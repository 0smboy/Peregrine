use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// One inventory host and the variables defined directly on its inventory line
/// or in `host_vars`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Host {
    pub name: String,
    pub vars: BTreeMap<String, Value>,
    pub direct_groups: BTreeSet<String>,
}

/// One inventory group before recursive child expansion.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Group {
    pub name: String,
    pub hosts: BTreeSet<String>,
    pub children: BTreeSet<String>,
    pub vars: BTreeMap<String, Value>,
}

/// Parsed Ansible-style INI inventory and its adjacent variable directories.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Inventory {
    pub hosts: BTreeMap<String, Host>,
    pub groups: BTreeMap<String, Group>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone)]
enum Section {
    Hosts(String),
    Children(String),
    Vars(String),
}

impl Inventory {
    /// Load an INI inventory plus sibling `group_vars` and `host_vars` folders.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let content = fs::read_to_string(path)
            .with_context(|| format!("read inventory {}", path.display()))?;
        let mut inventory = Self::default();
        inventory.ensure_group("all");
        inventory.ensure_group("ungrouped");
        inventory.parse_ini(path, &content)?;
        inventory.validate_children()?;

        let base = path.parent().unwrap_or_else(|| Path::new("."));
        inventory.load_group_vars(&base.join("group_vars"))?;
        inventory.load_host_vars(&base.join("host_vars"))?;
        inventory.compile_legacy_config(base)?;
        Ok(inventory)
    }

    /// Return host names in stable inventory order.
    #[must_use]
    pub fn host_names(&self) -> Vec<String> {
        self.hosts.keys().cloned().collect()
    }

    /// Resolve an exact host, a group, or an Ansible-style single index such as
    /// `proxyfs[0]`.
    pub fn hosts_for_pattern(&self, pattern: &str) -> Result<Vec<String>> {
        if self.hosts.contains_key(pattern) {
            return Ok(vec![pattern.to_owned()]);
        }

        let index_pattern = Regex::new(r"^([^\[]+)\[(-?\d+)\]$").expect("valid regex");
        if let Some(captures) = index_pattern.captures(pattern) {
            let group_name = &captures[1];
            let index = captures[2]
                .parse::<isize>()
                .with_context(|| format!("invalid host index in pattern {pattern}"))?;
            let hosts = self.group_hosts(group_name)?;
            let normalized = if index < 0 {
                isize::try_from(hosts.len()).unwrap_or(isize::MAX) + index
            } else {
                index
            };
            let selected = usize::try_from(normalized)
                .ok()
                .and_then(|position| hosts.get(position));
            return Ok(selected.cloned().into_iter().collect());
        }

        self.group_hosts(pattern)
    }

    /// Build the raw, deterministic variable context for one host. Jinja-valued
    /// variables remain unrendered until the template compatibility layer runs.
    pub fn host_context(&self, host_name: &str) -> Result<Value> {
        if !self.hosts.contains_key(host_name) {
            bail!("unknown inventory host: {host_name}");
        }

        let mut context = self.merged_host_vars(host_name)?;
        context.insert(
            "inventory_hostname".to_owned(),
            Value::String(host_name.to_owned()),
        );
        context.insert(
            "inventory_hostname_short".to_owned(),
            Value::String(host_name.split('.').next().unwrap_or(host_name).to_owned()),
        );

        let group_names = self.groups_for_host(host_name)?;
        context.insert(
            "group_names".to_owned(),
            Value::Array(group_names.iter().cloned().map(Value::String).collect()),
        );

        let mut groups = Map::new();
        for group_name in self.groups.keys() {
            groups.insert(
                group_name.clone(),
                Value::Array(
                    self.group_hosts(group_name)?
                        .into_iter()
                        .map(Value::String)
                        .collect(),
                ),
            );
        }
        context.insert("groups".to_owned(), Value::Object(groups));

        let mut hostvars = Map::new();
        for name in self.hosts.keys() {
            hostvars.insert(name.clone(), Value::Object(self.merged_host_vars(name)?));
        }
        context.insert("hostvars".to_owned(), Value::Object(hostvars));
        Ok(Value::Object(context))
    }

    fn parse_ini(&mut self, path: &Path, content: &str) -> Result<()> {
        let mut section = Section::Hosts("ungrouped".to_owned());
        for (zero_index, raw_line) in content.lines().enumerate() {
            let line_number = zero_index + 1;
            let line = strip_comment(raw_line).trim();
            if line.is_empty() {
                continue;
            }

            if let Some(header) = line
                .strip_prefix('[')
                .and_then(|value| value.strip_suffix(']'))
            {
                section = parse_section(header)?;
                match &section {
                    Section::Hosts(name) | Section::Children(name) | Section::Vars(name) => {
                        self.ensure_group(name);
                    }
                }
                continue;
            }

            match &section {
                Section::Hosts(group_name) => {
                    self.parse_host_line(group_name, line).with_context(|| {
                        format!("{}:{line_number}: invalid host line", path.display())
                    })?;
                }
                Section::Children(group_name) => {
                    let child = line
                        .split_whitespace()
                        .next()
                        .context("missing child group name")?;
                    self.ensure_group(child);
                    self.groups
                        .get_mut(group_name)
                        .expect("section group exists")
                        .children
                        .insert(child.to_owned());
                }
                Section::Vars(group_name) => {
                    let (key, raw_value) = line.split_once('=').with_context(|| {
                        format!(
                            "{}:{line_number}: group variable needs key=value",
                            path.display()
                        )
                    })?;
                    self.groups
                        .get_mut(group_name)
                        .expect("section group exists")
                        .vars
                        .insert(key.trim().to_owned(), parse_scalar(raw_value.trim())?);
                }
            }
        }
        Ok(())
    }

    fn parse_host_line(&mut self, group_name: &str, line: &str) -> Result<()> {
        let words = shell_words::split(line).context("parse shell-like inventory fields")?;
        let (pattern, assignments) = words.split_first().context("empty host line")?;
        let expanded = expand_host_pattern(pattern)?;
        let mut vars = BTreeMap::new();
        for assignment in assignments {
            let (key, raw_value) = assignment
                .split_once('=')
                .with_context(|| format!("host field is not key=value: {assignment}"))?;
            vars.insert(key.to_owned(), parse_scalar(raw_value)?);
        }

        for host_name in expanded {
            let host = self.hosts.entry(host_name.clone()).or_insert_with(|| Host {
                name: host_name.clone(),
                ..Host::default()
            });
            host.vars.extend(vars.clone());
            host.direct_groups.insert(group_name.to_owned());
            self.groups
                .get_mut(group_name)
                .expect("section group exists")
                .hosts
                .insert(host_name.clone());
            self.groups
                .get_mut("all")
                .expect("all group exists")
                .hosts
                .insert(host_name);
        }
        Ok(())
    }

    fn ensure_group(&mut self, name: &str) {
        self.groups.entry(name.to_owned()).or_insert_with(|| Group {
            name: name.to_owned(),
            ..Group::default()
        });
    }

    fn validate_children(&self) -> Result<()> {
        for group_name in self.groups.keys() {
            let mut visiting = BTreeSet::new();
            self.collect_group_hosts(group_name, &mut visiting)?;
        }
        Ok(())
    }

    fn group_hosts(&self, group_name: &str) -> Result<Vec<String>> {
        if !self.groups.contains_key(group_name) {
            bail!("unknown inventory host or group: {group_name}");
        }
        let mut visiting = BTreeSet::new();
        Ok(self
            .collect_group_hosts(group_name, &mut visiting)?
            .into_iter()
            .collect())
    }

    fn collect_group_hosts(
        &self,
        group_name: &str,
        visiting: &mut BTreeSet<String>,
    ) -> Result<BTreeSet<String>> {
        if !visiting.insert(group_name.to_owned()) {
            bail!("inventory group cycle contains {group_name}");
        }
        let group = self
            .groups
            .get(group_name)
            .with_context(|| format!("unknown child group: {group_name}"))?;
        let mut hosts = group.hosts.clone();
        for child in &group.children {
            hosts.extend(self.collect_group_hosts(child, visiting)?);
        }
        visiting.remove(group_name);
        Ok(hosts)
    }

    fn groups_for_host(&self, host_name: &str) -> Result<Vec<String>> {
        let mut names = Vec::new();
        for group_name in self.groups.keys() {
            if group_name != "all"
                && self
                    .group_hosts(group_name)?
                    .iter()
                    .any(|name| name == host_name)
            {
                names.push(group_name.clone());
            }
        }
        Ok(names)
    }

    fn merged_host_vars(&self, host_name: &str) -> Result<Map<String, Value>> {
        let mut merged = Map::new();
        if let Some(all) = self.groups.get("all") {
            extend_map(&mut merged, &all.vars);
        }

        let mut groups = self.groups_for_host(host_name)?;
        groups.sort_by_key(|name| (self.group_depth(name), name.clone()));
        for group_name in groups {
            if let Some(group) = self.groups.get(&group_name) {
                extend_map(&mut merged, &group.vars);
            }
        }
        extend_map(
            &mut merged,
            &self
                .hosts
                .get(host_name)
                .expect("host existence checked")
                .vars,
        );
        Ok(merged)
    }

    fn group_depth(&self, group_name: &str) -> usize {
        self.groups
            .values()
            .filter(|group| group.children.contains(group_name))
            .map(|group| 1 + self.group_depth(&group.name))
            .max()
            .unwrap_or(0)
    }

    fn load_group_vars(&mut self, directory: &Path) -> Result<()> {
        let has_compiled_all = directory.join("all").is_file();
        for path in variable_files(directory)? {
            if has_compiled_all
                && path
                    .file_name()
                    .and_then(|value| value.to_str())
                    .is_some_and(|name| name == "all.raw")
            {
                continue;
            }
            let group_name = variable_owner(&path)?;
            if matches!(group_name.as_str(), "security" | "ring_config") {
                continue;
            }
            let vars = load_variable_map(&path)?;
            if let Some(group) = self.groups.get_mut(&group_name) {
                group.vars.extend(vars);
            } else {
                self.warnings.push(format!(
                    "ignored group_vars file for absent group {group_name}: {}",
                    path.display()
                ));
            }
        }
        Ok(())
    }

    fn compile_legacy_config(&mut self, base: &Path) -> Result<()> {
        let group_vars = base.join("group_vars");
        if group_vars.join("all").is_file() {
            return Ok(());
        }
        self.compile_security(&group_vars.join("security"))?;
        self.compile_ring_config(&group_vars.join("ring_config.yml"))?;
        self.compile_network_addresses();
        Ok(())
    }

    fn compile_security(&mut self, path: &Path) -> Result<()> {
        if !path.is_file() {
            return Ok(());
        }
        let content = fs::read_to_string(path)
            .with_context(|| format!("read security variables {}", path.display()))?;
        let normalized = quote_bare_jinja_scalars(&content);
        let value: Value = serde_yaml_ng::from_str(&normalized)
            .with_context(|| format!("parse security variables {}", path.display()))?;
        let categories = value
            .as_object()
            .context("security variables must be a mapping")?;
        let all = self
            .groups
            .get("all")
            .expect("all group exists")
            .vars
            .clone();
        let mut compiled = BTreeMap::new();
        for (category, entries) in categories {
            let entries = entries
                .as_object()
                .with_context(|| format!("security category {category} must be a mapping"))?;
            let mut ports = Vec::new();
            for raw_ports in entries.values() {
                let resolved = resolve_simple_variable(raw_ports, &all)?;
                for port in match resolved {
                    Value::Array(values) => values,
                    value => vec![value],
                } {
                    let number = port
                        .as_u64()
                        .or_else(|| port.as_str().and_then(|text| text.parse().ok()))
                        .with_context(|| {
                            format!("security category {category} contains a non-numeric port")
                        })?;
                    ports.push(Value::from(number));
                }
            }
            compiled.insert(category.clone(), Value::Array(ports));
        }
        self.groups
            .get_mut("all")
            .expect("all group exists")
            .vars
            .extend(compiled);
        Ok(())
    }

    fn compile_ring_config(&mut self, path: &Path) -> Result<()> {
        if !path.is_file() {
            return Ok(());
        }
        let content = fs::read_to_string(path)
            .with_context(|| format!("read ring configuration {}", path.display()))?;
        let root: Value = serde_yaml_ng::from_str(&content)
            .with_context(|| format!("parse ring configuration {}", path.display()))?;
        let root = root
            .as_object()
            .context("ring configuration must be a mapping")?;
        let account = root.get("account_ring").context("missing account_ring")?;
        let container = root
            .get("container_ring")
            .context("missing container_ring")?;
        let object_rings = root
            .get("object_rings")
            .and_then(Value::as_array)
            .context("missing object_rings")?;

        let mut compiled = BTreeMap::new();
        compile_simple_ring(account, "account", &mut compiled)?;
        compile_simple_ring(container, "container", &mut compiled)?;
        let mut policies = Vec::new();
        let mut objects = Vec::new();
        for object in object_rings {
            let object = object
                .as_object()
                .context("object ring entry must be a mapping")?;
            let create = object
                .get("create_ring_info")
                .and_then(Value::as_object)
                .context("object ring missing create_ring_info")?;
            policies.push(
                object
                    .get("policy")
                    .cloned()
                    .context("object ring missing policy")?,
            );
            let content = object
                .get("ring_content")
                .and_then(Value::as_array)
                .context("object ring missing ring_content")?;
            objects.push(json_object([
                (
                    "name",
                    create
                        .get("builder_name")
                        .cloned()
                        .context("object ring missing builder_name")?,
                ),
                ("nodes", Value::Array(compile_ring_nodes(content)?)),
                (
                    "object_swift_partition_power",
                    create
                        .get("object_swift_partition_power")
                        .cloned()
                        .context("object ring missing partition power")?,
                ),
                (
                    "object_swift_replicas",
                    create
                        .get("object_swift_replicas")
                        .cloned()
                        .context("object ring missing replicas")?,
                ),
                (
                    "object_swift_minimum_time",
                    create
                        .get("object_swift_minimum_time")
                        .cloned()
                        .context("object ring missing minimum time")?,
                ),
            ]));
        }
        compiled.insert("policies".to_owned(), Value::Array(policies));
        compiled.insert("object_rings".to_owned(), Value::Array(objects));
        self.groups
            .get_mut("all")
            .expect("all group exists")
            .vars
            .extend(compiled);
        Ok(())
    }

    fn compile_network_addresses(&mut self) {
        let proxy_hosts = self
            .groups
            .get("proxy_servers")
            .map(|group| group.hosts.clone())
            .unwrap_or_default();
        let mut values: BTreeMap<&str, Vec<Value>> = BTreeMap::from([
            ("storage_network_addresses", Vec::new()),
            ("management_network_addresses", Vec::new()),
            ("business_network_addresses", Vec::new()),
            ("proxy_storage_network_addresses", Vec::new()),
            ("keystone_storage_network_addresses", Vec::new()),
            ("mariadb_storage_network_addresses", Vec::new()),
        ]);
        for (host_name, host) in &self.hosts {
            for (source, destination) in [
                ("storage_network_address", "storage_network_addresses"),
                ("management_network_address", "management_network_addresses"),
                ("business_network_address", "business_network_addresses"),
            ] {
                if let Some(address) = host.vars.get(source) {
                    values
                        .get_mut(destination)
                        .expect("network collection exists")
                        .push(address.clone());
                }
            }
            if proxy_hosts.contains(host_name)
                && let Some(address) = host.vars.get("storage_network_address")
            {
                values
                    .get_mut("proxy_storage_network_addresses")
                    .expect("network collection exists")
                    .push(address.clone());
            }
            if host
                .vars
                .get("keystone_node")
                .is_some_and(ansible_bool_value)
                && let Some(address) = host.vars.get("storage_network_address")
            {
                values
                    .get_mut("keystone_storage_network_addresses")
                    .expect("network collection exists")
                    .push(address.clone());
            }
            if host
                .vars
                .get("mariadb_node")
                .is_some_and(ansible_bool_value)
                && let Some(address) = host.vars.get("storage_network_address")
            {
                values
                    .get_mut("mariadb_storage_network_addresses")
                    .expect("network collection exists")
                    .push(address.clone());
            }
        }
        self.groups
            .get_mut("all")
            .expect("all group exists")
            .vars
            .extend(
                values
                    .into_iter()
                    .map(|(key, values)| (key.to_owned(), Value::Array(values))),
            );
    }

    fn load_host_vars(&mut self, directory: &Path) -> Result<()> {
        for path in variable_files(directory)? {
            let host_name = variable_owner(&path)?;
            let vars = load_variable_map(&path)?;
            if let Some(host) = self.hosts.get_mut(&host_name) {
                host.vars.extend(vars);
            } else {
                self.warnings.push(format!(
                    "ignored host_vars file for absent host {host_name}: {}",
                    path.display()
                ));
            }
        }
        Ok(())
    }
}

/// Fingerprint only runtime inventory inputs, excluding generated plans,
/// helper scripts, logs, and unrelated files in the same directory.
pub fn fingerprint_inventory_inputs(path: impl AsRef<Path>) -> Result<String> {
    let path = path.as_ref();
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    let mut files = vec![path.to_path_buf()];
    for directory_name in ["group_vars", "host_vars"] {
        let directory = base.join(directory_name);
        files.extend(variable_files(&directory)?);
    }
    files.sort();
    files.dedup();
    let mut digest = Sha256::new();
    for file in files {
        let relative = file.strip_prefix(base).unwrap_or(&file);
        digest.update(relative.to_string_lossy().as_bytes());
        digest.update([0]);
        digest.update(
            fs::read(&file).with_context(|| format!("read inventory input {}", file.display()))?,
        );
        digest.update([0]);
    }
    Ok(hex::encode(digest.finalize()))
}

fn parse_section(header: &str) -> Result<Section> {
    let (name, kind) = header
        .split_once(':')
        .map_or((header, None), |(name, kind)| (name, Some(kind)));
    if name.trim().is_empty() {
        bail!("inventory section name is empty");
    }
    match kind {
        None => Ok(Section::Hosts(name.trim().to_owned())),
        Some("children") => Ok(Section::Children(name.trim().to_owned())),
        Some("vars") => Ok(Section::Vars(name.trim().to_owned())),
        Some(other) => bail!("unsupported inventory section type: {other}"),
    }
}

fn expand_host_pattern(pattern: &str) -> Result<Vec<String>> {
    let range = Regex::new(r"^(.*)\[(-?\d+):(-?\d+)(?::(-?\d+))?\](.*)$").expect("valid regex");
    let Some(captures) = range.captures(pattern) else {
        return Ok(vec![pattern.to_owned()]);
    };
    let start_text = &captures[2];
    let end_text = &captures[3];
    let start = start_text.parse::<i64>().context("invalid range start")?;
    let end = end_text.parse::<i64>().context("invalid range end")?;
    let default_step = if start <= end { 1 } else { -1 };
    let step = captures
        .get(4)
        .map_or(Ok(default_step), |value| value.as_str().parse::<i64>())
        .context("invalid range step")?;
    if step == 0 || (end - start).signum() != step.signum() {
        bail!("host range does not progress toward its endpoint: {pattern}");
    }
    let width = start_text
        .trim_start_matches('-')
        .len()
        .max(end_text.trim_start_matches('-').len());
    let prefix = &captures[1];
    let suffix = &captures[5];
    let mut values = Vec::new();
    let mut current = start;
    loop {
        let number = if current < 0 {
            format!("-{:0width$}", current.unsigned_abs(), width = width)
        } else {
            format!("{current:0width$}")
        };
        values.push(format!("{prefix}{number}{suffix}"));
        if current == end {
            break;
        }
        current = current
            .checked_add(step)
            .context("host range integer overflow")?;
        if values.len() > 100_000 {
            bail!("host range is unreasonably large: {pattern}");
        }
    }
    Ok(values)
}

fn strip_comment(line: &str) -> &str {
    let mut single = false;
    let mut double = false;
    let mut escaped = false;
    for (index, character) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match character {
            '\\' if double => escaped = true,
            '\'' if !double => single = !single,
            '"' if !single => double = !double,
            '#' if !single && !double => return &line[..index],
            _ => {}
        }
    }
    line
}

fn parse_scalar(raw: &str) -> Result<Value> {
    serde_yaml_ng::from_str::<Value>(raw).with_context(|| format!("parse inventory scalar {raw:?}"))
}

fn variable_files(directory: &Path) -> Result<Vec<PathBuf>> {
    if !directory.exists() {
        return Ok(Vec::new());
    }
    let mut paths = Vec::new();
    for entry in fs::read_dir(directory)
        .with_context(|| format!("read variable directory {}", directory.display()))?
    {
        let entry = entry.with_context(|| format!("read entry in {}", directory.display()))?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let extension = path.extension().and_then(|value| value.to_str());
        if matches!(extension, Some("py" | "sh")) {
            continue;
        }
        if extension.is_none() || matches!(extension, Some("yml" | "yaml" | "raw")) {
            paths.push(path);
        }
    }
    paths.sort();
    Ok(paths)
}

fn variable_owner(path: &Path) -> Result<String> {
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .with_context(|| format!("variable filename is not UTF-8: {}", path.display()))?;
    let extension = path.extension().and_then(|value| value.to_str());
    if matches!(extension, Some("yml" | "yaml" | "raw")) {
        Ok(path
            .file_stem()
            .and_then(|value| value.to_str())
            .context("missing variable file stem")?
            .to_owned())
    } else {
        Ok(file_name.to_owned())
    }
}

fn load_variable_map(path: &Path) -> Result<BTreeMap<String, Value>> {
    let content =
        fs::read_to_string(path).with_context(|| format!("read variables {}", path.display()))?;
    let normalized = quote_bare_jinja_scalars(&content);
    let value: Value = serde_yaml_ng::from_str(&normalized)
        .with_context(|| format!("parse variables {}", path.display()))?;
    match value {
        Value::Null => Ok(BTreeMap::new()),
        Value::Object(map) => Ok(map.into_iter().collect()),
        _ => bail!("variable file root must be a mapping: {}", path.display()),
    }
}

fn quote_bare_jinja_scalars(content: &str) -> String {
    content
        .lines()
        .map(|line| {
            let Some(start) = line.find("{{") else {
                return line.to_owned();
            };
            let Some(end_start) = line.rfind("}}") else {
                return line.to_owned();
            };
            let end = end_start + 2;
            let prefix = &line[..start];
            let suffix = &line[end..];
            let suffix_without_comment = strip_comment(suffix).trim();
            let is_scalar_position = matches!(prefix.trim_end().chars().last(), Some(':' | '-'));
            if is_scalar_position && suffix_without_comment.is_empty() {
                let quoted =
                    serde_json::to_string(&line[start..end]).expect("string serialization");
                format!("{prefix}{quoted}{suffix}")
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn extend_map(target: &mut Map<String, Value>, source: &BTreeMap<String, Value>) {
    target.extend(
        source
            .iter()
            .map(|(key, value)| (key.clone(), value.clone())),
    );
}

fn resolve_simple_variable(value: &Value, variables: &BTreeMap<String, Value>) -> Result<Value> {
    match value {
        Value::String(expression) => {
            let trimmed = expression.trim();
            if let Some(name) = trimmed
                .strip_prefix("{{")
                .and_then(|inner| inner.strip_suffix("}}"))
                .map(str::trim)
            {
                return variables
                    .get(name)
                    .cloned()
                    .with_context(|| format!("undefined security variable: {name}"));
            }
        }
        Value::Array(values) => {
            return values
                .iter()
                .map(|value| resolve_simple_variable(value, variables))
                .collect::<Result<Vec<_>>>()
                .map(Value::Array);
        }
        Value::Object(values) => {
            return values
                .iter()
                .map(|(key, value)| Ok((key.clone(), resolve_simple_variable(value, variables)?)))
                .collect::<Result<Map<_, _>>>()
                .map(Value::Object);
        }
        _ => {}
    }
    Ok(value.clone())
}

fn compile_simple_ring(
    ring: &Value,
    prefix: &str,
    output: &mut BTreeMap<String, Value>,
) -> Result<()> {
    let ring = ring
        .as_object()
        .with_context(|| format!("{prefix}_ring must be a mapping"))?;
    let create = ring
        .get("create_ring_info")
        .and_then(Value::as_object)
        .with_context(|| format!("{prefix}_ring missing create_ring_info"))?;
    for suffix in ["partition_power", "replicas", "minimum_time"] {
        let source = format!("{prefix}_swift_{suffix}");
        output.insert(
            source.clone(),
            create
                .get(&source)
                .cloned()
                .with_context(|| format!("{prefix}_ring missing {source}"))?,
        );
    }
    let content = ring
        .get("ring_content")
        .and_then(Value::as_array)
        .with_context(|| format!("{prefix}_ring missing ring_content"))?;
    output.insert(
        format!("{prefix}_ring"),
        Value::Array(compile_ring_nodes(content)?),
    );
    Ok(())
}

fn compile_ring_nodes(content: &[Value]) -> Result<Vec<Value>> {
    let mut nodes = Vec::new();
    for entry in content {
        let entry = entry
            .as_object()
            .context("ring content entry must be a mapping")?;
        let region = entry
            .get("region")
            .cloned()
            .context("ring region missing")?;
        let zone = entry.get("zone").cloned().context("ring zone missing")?;
        if let Some(disks) = entry.get("common_disk_info").and_then(Value::as_array) {
            let storage = expand_ipv4_list(
                entry
                    .get("storage_ips")
                    .and_then(Value::as_str)
                    .context("common ring entry missing storage_ips")?,
            )?;
            let replication = expand_ipv4_list(
                entry
                    .get("replication_ips")
                    .and_then(Value::as_str)
                    .context("common ring entry missing replication_ips")?,
            )?;
            if storage.len() != replication.len() {
                bail!("storage and replication IP ranges have different lengths");
            }
            for (port, device, weight) in expand_common_disks(disks)? {
                for (storage_ip, replication_ip) in storage.iter().zip(&replication) {
                    nodes.push(json_object([
                        ("region", region.clone()),
                        ("zone", zone.clone()),
                        ("storage_ip", Value::String(storage_ip.clone())),
                        ("replication_ip", Value::String(replication_ip.clone())),
                        ("device", Value::String(device.clone())),
                        ("port", Value::from(port)),
                        ("weight", Value::from(weight)),
                    ]));
                }
            }
        }
        if let Some(disks) = entry.get("dedicated_disk_info").and_then(Value::as_array) {
            for (storage_ip, replication_ip, port, device, weight) in expand_dedicated_disks(disks)?
            {
                nodes.push(json_object([
                    ("region", region.clone()),
                    ("zone", zone.clone()),
                    ("storage_ip", Value::String(storage_ip)),
                    ("replication_ip", Value::String(replication_ip)),
                    ("device", Value::String(device)),
                    ("port", Value::from(port)),
                    ("weight", Value::from(weight)),
                ]));
            }
        }
    }
    Ok(nodes)
}

fn expand_common_disks(disks: &[Value]) -> Result<Vec<(u64, String, u64)>> {
    let mut expanded = Vec::new();
    for disk in disks {
        let disk = disk
            .as_str()
            .context("common disk specification must be a string")?;
        let fields = disk.split('_').collect::<Vec<_>>();
        if fields.len() != 3 {
            bail!("common disk specification needs port_devices_weight: {disk}");
        }
        let port = fields[0].parse().context("invalid disk port")?;
        let weight = fields[2].parse().context("invalid disk weight")?;
        for device in expand_devices(fields[1])? {
            expanded.push((port, device, weight));
        }
    }
    Ok(expanded)
}

type DedicatedDisk = (String, String, u64, String, u64);

fn expand_dedicated_disks(disks: &[Value]) -> Result<Vec<DedicatedDisk>> {
    let mut expanded = Vec::new();
    for disk in disks {
        let disk = disk
            .as_str()
            .context("dedicated disk specification must be a string")?;
        let fields = disk.split('_').collect::<Vec<_>>();
        if fields.len() != 5 {
            bail!(
                "dedicated disk specification needs storage_replication_port_devices_weight: {disk}"
            );
        }
        let port = fields[2].parse().context("invalid disk port")?;
        let weight = fields[4].parse().context("invalid disk weight")?;
        for device in expand_devices(fields[3])? {
            expanded.push((
                fields[0].to_owned(),
                fields[1].to_owned(),
                port,
                device,
                weight,
            ));
        }
    }
    Ok(expanded)
}

fn expand_devices(specification: &str) -> Result<Vec<String>> {
    let value: Value = serde_json::from_str(specification).context("invalid disk device JSON")?;
    let map = value
        .as_object()
        .context("disk device JSON must be a mapping")?;
    let mut devices = Vec::new();
    for kind in ["hdd", "ssd"] {
        let Some(range) = map.get(kind).and_then(Value::as_str) else {
            continue;
        };
        if range.is_empty() {
            continue;
        }
        let (start, end) = range
            .split_once('-')
            .map_or((range, range), |(start, end)| (start, end));
        let start = start.parse::<u32>().context("invalid disk range start")?;
        let end = end.parse::<u32>().context("invalid disk range end")?;
        if start > end || end - start > 100_000 {
            bail!("invalid or excessive disk range: {range}");
        }
        devices.extend((start..=end).map(|number| format!("{kind}{number:03}")));
    }
    Ok(devices)
}

fn expand_ipv4_list(specification: &str) -> Result<Vec<String>> {
    let mut addresses = Vec::new();
    for blob in specification
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
    {
        let (start, end) = blob
            .split_once('-')
            .map_or((blob, blob), |(start, end)| (start, end));
        let start = u32::from(
            start
                .parse::<Ipv4Addr>()
                .context("invalid IPv4 range start")?,
        );
        let end = u32::from(end.parse::<Ipv4Addr>().context("invalid IPv4 range end")?);
        if start > end || end - start > 1_000_000 {
            bail!("invalid or excessive IPv4 range: {blob}");
        }
        addresses.extend((start..=end).map(|address| Ipv4Addr::from(address).to_string()));
    }
    Ok(addresses)
}

fn json_object<const N: usize>(entries: [(&str, Value); N]) -> Value {
    Value::Object(
        entries
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}

fn ansible_bool_value(value: &Value) -> bool {
    match value {
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_i64().is_some_and(|number| number != 0),
        Value::String(value) => matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "true" | "yes" | "on" | "1"
        ),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn comments_inside_quotes_survive() {
        assert_eq!(strip_comment("a='x#y' # comment").trim(), "a='x#y'");
    }

    #[test]
    fn descending_ranges_are_supported() {
        assert_eq!(
            expand_host_pattern("node[03:01]").expect("range"),
            vec!["node03", "node02", "node01"]
        );
    }

    #[test]
    fn compiled_all_is_the_single_authoritative_workspace_source() {
        let directory = tempdir().expect("inventory directory");
        let group_vars = directory.path().join("group_vars");
        fs::create_dir(&group_vars).expect("group_vars");
        fs::write(directory.path().join("swift_hosts"), "[all]\n10.0.0.11\n").expect("inventory");
        fs::write(group_vars.join("all"), "source: compiled\n").expect("compiled all");
        fs::write(group_vars.join("all.raw"), "source: raw\n").expect("review source");
        fs::write(group_vars.join("ring_config.yml"), "not: [valid").expect("legacy helper source");

        let inventory =
            Inventory::load(directory.path().join("swift_hosts")).expect("load compiled workspace");

        assert_eq!(inventory.groups["all"].vars["source"], "compiled");
    }
}
