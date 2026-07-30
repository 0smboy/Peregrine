use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use regex::Regex;
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::bundle::audit_bundle;
use crate::inventory::Inventory;
use crate::model::{LoopSpec, PLAN_SCHEMA_VERSION, Plan, PlannedTask, SUPPORTED_MODULES};
use crate::safety::classify_task;

/// Deterministic planner for the bounded v3 playbook/task language.
pub struct Planner<'a> {
    bundle: &'a Path,
    inventory: &'a Inventory,
}

#[derive(Debug, Clone, Default)]
struct Inherited {
    when: Vec<String>,
    loops: Vec<LoopSpec>,
    vars: BTreeMap<String, Value>,
    run_once: bool,
    privilege_escalation: bool,
    become_user: Option<String>,
    delegate_to: Option<String>,
    notify: Vec<String>,
    ignore_errors: bool,
    failed_when: Vec<String>,
    changed_when: Vec<String>,
}

impl<'a> Planner<'a> {
    #[must_use]
    pub fn new(bundle: &'a Path, inventory: &'a Inventory) -> Self {
        Self { bundle, inventory }
    }

    /// Build and seal a plan. The caller supplies the fingerprint of inventory
    /// inputs so apply can bind the approval to the same configuration.
    pub fn build(
        &self,
        playbook: impl AsRef<Path>,
        inventory_fingerprint: impl Into<String>,
    ) -> Result<Plan> {
        let audit = audit_bundle(self.bundle)?;
        if !audit.is_compatible() {
            bail!(
                "bundle is incompatible: unsupported={:?}, parse_errors={:?}",
                audit.unsupported_modules,
                audit.parse_errors
            );
        }

        let playbook = playbook.as_ref();
        let content = fs::read_to_string(playbook)
            .with_context(|| format!("read playbook {}", playbook.display()))?;
        let root: Value = Value::deserialize(serde_yaml_ng::Deserializer::from_str(&content))
            .with_context(|| format!("parse playbook {}", playbook.display()))?;
        let plays = root
            .as_array()
            .with_context(|| format!("playbook root must be a list: {}", playbook.display()))?;

        let mut tasks = Vec::new();
        let mut handlers = Vec::new();
        let mut all_hosts = BTreeSet::new();
        for (play_index, play_value) in plays.iter().enumerate() {
            let play = play_value
                .as_object()
                .with_context(|| format!("play {} must be a mapping", play_index + 1))?;
            let host_pattern = required_string(play, "hosts")?;
            let hosts = self.inventory.hosts_for_pattern(&host_pattern)?;
            all_hosts.extend(hosts.iter().cloned());
            let Some(role_values) = play.get("roles") else {
                continue;
            };
            let roles = role_values
                .as_array()
                .with_context(|| format!("play {} roles must be a list", play_index + 1))?;

            for role_value in roles {
                let (role, role_context) = parse_role(role_value)?;
                let role_context = self.load_role_variables(&role, role_context)?;
                let task_path = self.bundle.join("roles").join(&role).join("tasks/main.yml");
                if !task_path.is_file() {
                    bail!("role {role} does not contain tasks/main.yml");
                }
                let mut stack = Vec::new();
                self.flatten_file(
                    &task_path,
                    &role,
                    &host_pattern,
                    &hosts,
                    &role_context,
                    &mut stack,
                    &mut tasks,
                )?;

                let handler_path = self
                    .bundle
                    .join("roles")
                    .join(&role)
                    .join("handlers/main.yml");
                if handler_path.is_file() {
                    let mut handler_stack = Vec::new();
                    self.flatten_file(
                        &handler_path,
                        &role,
                        &host_pattern,
                        &hosts,
                        &role_context,
                        &mut handler_stack,
                        &mut handlers,
                    )?;
                }
            }
        }

        for (index, task) in tasks.iter_mut().chain(handlers.iter_mut()).enumerate() {
            task.id = u64::try_from(index + 1).context("task id overflow")?;
        }
        Plan {
            schema_version: PLAN_SCHEMA_VERSION,
            bundle_fingerprint: audit.fingerprint,
            inventory_fingerprint: inventory_fingerprint.into(),
            playbook: relative(self.bundle, playbook)
                .to_string_lossy()
                .into_owned(),
            hosts: all_hosts.into_iter().collect(),
            tasks,
            handlers,
            digest: String::new(),
        }
        .seal()
    }

    fn load_role_variables(&self, role: &str, mut inherited: Inherited) -> Result<Inherited> {
        let role_root = self.bundle.join("roles").join(role);
        let mut variables = BTreeMap::new();
        for relative_path in ["defaults/main.yml", "vars/main.yml"] {
            let path = role_root.join(relative_path);
            if !path.is_file() {
                continue;
            }
            let content = fs::read_to_string(&path)
                .with_context(|| format!("read role variables {}", path.display()))?;
            let value: Value = Value::deserialize(serde_yaml_ng::Deserializer::from_str(&content))
                .with_context(|| format!("parse role variables {}", path.display()))?;
            let map = value
                .as_object()
                .with_context(|| format!("role variables must be a mapping: {}", path.display()))?;
            variables.extend(map.iter().map(|(key, value)| (key.clone(), value.clone())));
        }
        variables.extend(inherited.vars);
        inherited.vars = variables;
        Ok(inherited)
    }

    #[allow(clippy::too_many_arguments)]
    fn flatten_file(
        &self,
        path: &Path,
        role: &str,
        host_pattern: &str,
        hosts: &[String],
        inherited: &Inherited,
        stack: &mut Vec<PathBuf>,
        output: &mut Vec<PlannedTask>,
    ) -> Result<()> {
        let canonical = path
            .canonicalize()
            .with_context(|| format!("resolve task include {}", path.display()))?;
        if stack.contains(&canonical) {
            let chain = stack
                .iter()
                .chain(std::iter::once(&canonical))
                .map(|item| item.display().to_string())
                .collect::<Vec<_>>()
                .join(" -> ");
            bail!("task include cycle: {chain}");
        }
        stack.push(canonical);

        let content = fs::read_to_string(path)
            .with_context(|| format!("read task file {}", path.display()))?;
        let root: Value = Value::deserialize(serde_yaml_ng::Deserializer::from_str(&content))
            .with_context(|| format!("parse task file {}", path.display()))?;
        let result = self.flatten_task_list(
            path,
            &root,
            role,
            host_pattern,
            hosts,
            inherited,
            stack,
            output,
            "",
        );
        stack.pop();
        result
    }

    #[allow(clippy::too_many_arguments)]
    fn flatten_task_list(
        &self,
        path: &Path,
        value: &Value,
        role: &str,
        host_pattern: &str,
        hosts: &[String],
        inherited: &Inherited,
        stack: &mut Vec<PathBuf>,
        output: &mut Vec<PlannedTask>,
        position_prefix: &str,
    ) -> Result<()> {
        let items = value
            .as_array()
            .with_context(|| format!("task list must be an array: {}", path.display()))?;
        for (index, item) in items.iter().enumerate() {
            let position = if position_prefix.is_empty() {
                (index + 1).to_string()
            } else {
                format!("{position_prefix}.{}", index + 1)
            };
            let task = item.as_object().with_context(|| {
                format!("task {position} must be a mapping: {}", path.display())
            })?;
            let context = merge_context(inherited, task)?;

            if task.contains_key("block") {
                for section in ["block", "rescue", "always"] {
                    if let Some(children) = task.get(section) {
                        self.flatten_task_list(
                            path,
                            children,
                            role,
                            host_pattern,
                            hosts,
                            &context,
                            stack,
                            output,
                            &format!("{position}.{section}"),
                        )?;
                    }
                }
                continue;
            }

            if let Some(include_value) = task.get("include").or_else(|| task.get("include_tasks")) {
                let (file_name, parameters) = parse_include(include_value)?;
                let mut include_context = context;
                include_context.vars.extend(parameters);
                let include_path = path
                    .parent()
                    .unwrap_or_else(|| Path::new("."))
                    .join(file_name);
                self.flatten_file(
                    &include_path,
                    role,
                    host_pattern,
                    hosts,
                    &include_context,
                    stack,
                    output,
                )?;
                continue;
            }

            let (module, args) = task_module(task)?;
            let mut planned = PlannedTask {
                id: 0,
                source: format!(
                    "{}#{position}",
                    relative(self.bundle, path).to_string_lossy()
                ),
                role: role.to_owned(),
                name: task
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or(module)
                    .to_owned(),
                host_pattern: host_pattern.to_owned(),
                hosts: hosts.to_vec(),
                module: module.to_owned(),
                args,
                vars: context.vars,
                when: context.when,
                loops: context.loops,
                run_once: context.run_once,
                privilege_escalation: context.privilege_escalation,
                become_user: context.become_user,
                delegate_to: context.delegate_to,
                register: optional_string(task.get("register"))?,
                notify: context.notify,
                ignore_errors: context.ignore_errors,
                failed_when: context.failed_when,
                changed_when: context.changed_when,
                risk: Vec::new(),
            };
            planned.risk = classify_task(&planned);
            output.push(planned);
        }
        Ok(())
    }
}

fn parse_role(value: &Value) -> Result<(String, Inherited)> {
    match value {
        Value::String(role) => Ok((role.clone(), Inherited::default())),
        Value::Object(map) => {
            let role = required_string(map, "role")?;
            let context = merge_context(&Inherited::default(), map)?;
            Ok((role, context))
        }
        _ => bail!("role entry must be a string or mapping"),
    }
}

fn merge_context(inherited: &Inherited, task: &Map<String, Value>) -> Result<Inherited> {
    let mut merged = inherited.clone();
    if let Some(value) = task.get("when") {
        merged.when.extend(expression_strings(value));
    }
    merged.loops.extend(loop_specs(task)?);
    if let Some(Value::Object(vars)) = task.get("vars") {
        merged
            .vars
            .extend(vars.iter().map(|(key, value)| (key.clone(), value.clone())));
    }
    if task.get("run_once").is_some_and(ansible_bool) {
        merged.run_once = true;
    }
    if task.get("become").is_some_and(ansible_bool) {
        merged.privilege_escalation = true;
    }
    if let Some(value) = task.get("become_user") {
        merged.become_user = optional_string(Some(value))?;
    }
    if let Some(value) = task.get("delegate_to") {
        merged.delegate_to = optional_string(Some(value))?;
    }
    if let Some(value) = task.get("notify") {
        merged.notify.extend(string_list(value)?);
    }
    if task.get("ignore_errors").is_some_and(ansible_bool) {
        merged.ignore_errors = true;
    }
    if let Some(value) = task.get("failed_when") {
        merged.failed_when.extend(expression_strings(value));
    }
    if let Some(value) = task.get("changed_when") {
        merged.changed_when.extend(expression_strings(value));
    }
    Ok(merged)
}

fn loop_specs(task: &Map<String, Value>) -> Result<Vec<LoopSpec>> {
    let loop_var = task
        .get("loop_control")
        .and_then(Value::as_object)
        .and_then(|control| control.get("loop_var"))
        .and_then(Value::as_str)
        .unwrap_or("item")
        .to_owned();
    let mut loops = Vec::new();
    for key in [
        "loop",
        "with_items",
        "with_dict",
        "with_together",
        "with_inidata",
    ] {
        if let Some(expression) = task.get(key) {
            loops.push(LoopSpec {
                kind: key.to_owned(),
                expression: expression.clone(),
                loop_var: loop_var.clone(),
            });
        }
    }
    if loops.len() > 1 {
        bail!(
            "task defines multiple loops: {:?}",
            loops.iter().map(|item| &item.kind).collect::<Vec<_>>()
        );
    }
    Ok(loops)
}

fn task_module(task: &Map<String, Value>) -> Result<(&str, Value)> {
    let modules = SUPPORTED_MODULES
        .iter()
        .filter_map(|module| task.get(*module).map(|args| (*module, args)))
        .collect::<Vec<_>>();
    match modules.as_slice() {
        [(module, args)] => {
            let mut merged = match args {
                Value::Object(map) => map.clone(),
                Value::Null => Map::new(),
                value => Map::from_iter([("_raw_params".to_owned(), (*value).clone())]),
            };
            if let Some(extra) = task.get("args").and_then(Value::as_object) {
                merged.extend(extra.clone());
            }
            if merged.len() == 1 && merged.contains_key("_raw_params") && !task.contains_key("args")
            {
                Ok((
                    module,
                    merged.remove("_raw_params").expect("raw params exist"),
                ))
            } else {
                Ok((module, Value::Object(merged)))
            }
        }
        [] => bail!("task does not contain a supported executable module"),
        _ => bail!("task contains multiple executable modules"),
    }
}

fn parse_include(value: &Value) -> Result<(String, BTreeMap<String, Value>)> {
    match value {
        Value::String(specification) => parse_include_string(specification),
        Value::Object(map) => {
            let file = map
                .get("file")
                .or_else(|| map.get("_raw_params"))
                .and_then(Value::as_str)
                .context("include mapping requires file")?
                .to_owned();
            let vars = map
                .iter()
                .filter(|(key, _)| !matches!(key.as_str(), "file" | "_raw_params"))
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect();
            Ok((file, vars))
        }
        _ => bail!("include must be a string or mapping"),
    }
}

fn parse_include_string(specification: &str) -> Result<(String, BTreeMap<String, Value>)> {
    let trimmed = specification.trim();
    let split = trimmed.find(char::is_whitespace).unwrap_or(trimmed.len());
    let file = trimmed[..split].trim();
    if file.is_empty() {
        bail!("include filename is empty");
    }
    let remainder = trimmed[split..].trim();
    if remainder.is_empty() {
        return Ok((file.to_owned(), BTreeMap::new()));
    }

    let assignment = Regex::new(r"(?:^|\s)([A-Za-z_][A-Za-z0-9_]*)=").expect("valid regex");
    let captures = assignment.captures_iter(remainder).collect::<Vec<_>>();
    if captures.is_empty() {
        bail!("include parameters must use key=value: {remainder}");
    }
    let mut vars = BTreeMap::new();
    for (index, capture) in captures.iter().enumerate() {
        let key_match = capture.get(1).expect("assignment key");
        let value_start = key_match.end() + 1;
        let value_end = captures
            .get(index + 1)
            .and_then(|next| next.get(0))
            .map_or(remainder.len(), |next| next.start());
        let raw_value = remainder[value_start..value_end].trim();
        vars.insert(
            key_match.as_str().to_owned(),
            Value::String(unquote(raw_value).to_owned()),
        );
    }
    Ok((file.to_owned(), vars))
}

fn unquote(value: &str) -> &str {
    if value.len() >= 2 {
        let bytes = value.as_bytes();
        if matches!(
            (bytes[0], bytes[value.len() - 1]),
            (b'\'', b'\'') | (b'"', b'"')
        ) {
            return &value[1..value.len() - 1];
        }
    }
    value
}

fn expression_strings(value: &Value) -> Vec<String> {
    match value {
        Value::Array(items) => items.iter().flat_map(expression_strings).collect(),
        Value::String(expression) => vec![expression.clone()],
        _ => vec![serde_json::to_string(value).unwrap_or_else(|_| "null".to_owned())],
    }
}

fn string_list(value: &Value) -> Result<Vec<String>> {
    match value {
        Value::String(item) => Ok(vec![item.clone()]),
        Value::Array(items) => items
            .iter()
            .map(|item| {
                item.as_str()
                    .map(str::to_owned)
                    .context("list entry must be a string")
            })
            .collect(),
        _ => bail!("value must be a string or list of strings"),
    }
}

fn optional_string(value: Option<&Value>) -> Result<Option<String>> {
    value
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .context("value must be a string")
        })
        .transpose()
}

fn required_string(map: &Map<String, Value>, key: &str) -> Result<String> {
    map.get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .with_context(|| format!("required field {key} must be a string"))
}

fn ansible_bool(value: &Value) -> bool {
    match value {
        Value::Bool(boolean) => *boolean,
        Value::Number(number) => number.as_i64().is_some_and(|number| number != 0),
        Value::String(text) => matches!(
            text.trim().to_ascii_lowercase().as_str(),
            "true" | "yes" | "on" | "1"
        ),
        _ => false,
    }
}

fn relative<'a>(root: &'a Path, path: &'a Path) -> &'a Path {
    path.strip_prefix(root).unwrap_or(path)
}
