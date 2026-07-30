//! Read-only host checks that must pass before a sealed plan may mutate targets.

use std::collections::{BTreeSet, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::inventory::Inventory;
use crate::transport::{ConnectionSpec, Transport};

/// Read-only preflight result for the complete target inventory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreflightReport {
    pub ok: bool,
    pub hosts: Vec<HostPreflight>,
}

impl PreflightReport {
    /// Reject execution when any target failed a preflight check.
    pub fn ensure_safe(&self) -> Result<()> {
        if self.ok {
            return Ok(());
        }
        let failures = self
            .hosts
            .iter()
            .flat_map(|host| {
                host.errors
                    .iter()
                    .map(move |error| format!("{}: {error}", host.host))
            })
            .collect::<Vec<_>>();
        bail!(
            "deployment preflight failed before any mutation: {}",
            failures.join("; ")
        )
    }
}

/// Sanitized facts and blockers for one target host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostPreflight {
    pub host: String,
    pub ssh_host: String,
    pub os: String,
    pub addresses: Vec<String>,
    pub root_source: String,
    pub system_disk: String,
    pub data_disks: Vec<String>,
    pub repository_paths: Vec<String>,
    pub ok: bool,
    pub errors: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct LsblkOutput {
    #[serde(default)]
    blockdevices: Vec<BlockDevice>,
}

#[derive(Debug, Deserialize)]
struct BlockDevice {
    path: String,
    #[serde(rename = "type")]
    device_type: String,
    #[serde(default)]
    fstype: Option<String>,
    #[serde(default)]
    mountpoints: Value,
    #[serde(default)]
    children: Vec<BlockDevice>,
}

/// Contact every target through strict SSH and perform read-only OS, network,
/// repository, and block-device identity checks.
pub fn run_preflight<T: Transport>(
    inventory: &Inventory,
    known_hosts: Option<PathBuf>,
    transport: &mut T,
) -> Result<PreflightReport> {
    run_preflight_with_bundle(inventory, known_hosts, transport, None)
}

/// [`run_preflight`] plus controller-side bundle checks that need the active
/// bundle directory: every `roles/*_payload/files/bin` directory the bundle
/// declares must actually hold binaries (placeholders don't count), so an
/// unpopulated payload fails before any mutation regardless of which bundle
/// is being applied.
pub fn run_preflight_with_bundle<T: Transport>(
    inventory: &Inventory,
    known_hosts: Option<PathBuf>,
    transport: &mut T,
    bundle: Option<&Path>,
) -> Result<PreflightReport> {
    let payload_errors = bundle.map(bundle_payload_errors).unwrap_or_default();
    let mut hosts = Vec::new();
    for host in inventory.host_names() {
        let context = inventory.host_context(&host)?;
        let connection = ConnectionSpec::from_context(&host, &context, known_hosts.clone())?;
        let mut report = preflight_host(&host, &context, &connection, transport);
        if is_rust_stack(&context) && !payload_errors.is_empty() {
            report.errors.extend(payload_errors.iter().cloned());
            report.ok = false;
        }
        hosts.push(report);
    }
    Ok(PreflightReport {
        ok: hosts.iter().all(|host| host.ok),
        hosts,
    })
}

/// One error per `roles/*_payload/files/bin` directory in the bundle that
/// holds no real file (only `.keep` placeholders or nothing).
fn bundle_payload_errors(bundle: &Path) -> Vec<String> {
    let Ok(roles) = std::fs::read_dir(bundle.join("roles")) else {
        return Vec::new();
    };
    let mut errors = Vec::new();
    for role in roles.flatten() {
        let name = role.file_name().to_string_lossy().into_owned();
        if !name.ends_with("_payload") {
            continue;
        }
        let bin = role.path().join("files/bin");
        if !bin.is_dir() {
            continue;
        }
        let populated = std::fs::read_dir(&bin)
            .map(|entries| {
                entries
                    .flatten()
                    .any(|e| e.file_name().to_string_lossy() != ".keep")
            })
            .unwrap_or(false);
        if !populated {
            errors.push(format!(
                "bundle payload {} is unpopulated controller-side (see the role's PAYLOAD.md)",
                bin.display()
            ));
        }
    }
    errors
}

/// True when the host's merged variables mark the rust deployment stack.
fn is_rust_stack(context: &Value) -> bool {
    context
        .get("deploy_stack")
        .and_then(Value::as_str)
        .map(str::trim)
        == Some("rust")
}

fn preflight_host<T: Transport>(
    host: &str,
    context: &Value,
    connection: &ConnectionSpec,
    transport: &mut T,
) -> HostPreflight {
    let system_disk = string_array(context, "exclude_disks")
        .into_iter()
        .next()
        .map(|disk| normalize_device_path(&disk))
        .unwrap_or_default();
    let configured_data = string_array(context, "custom_disks");
    let mut report = HostPreflight {
        host: host.to_owned(),
        ssh_host: connection.host.clone(),
        os: String::new(),
        addresses: Vec::new(),
        root_source: String::new(),
        system_disk: system_disk.clone(),
        data_disks: configured_data.clone(),
        repository_paths: Vec::new(),
        ok: false,
        errors: Vec::new(),
    };

    let rust_stack = is_rust_stack(context);
    if connection.user != "root" {
        report
            .errors
            .push("v3 deployment requires an SSH root login".to_owned());
    }
    validate_controller_key(connection, &mut report.errors);
    if !validate_explicit_disk_contract(context, &configured_data, rust_stack, &mut report.errors) {
        return report;
    }

    let command = discovery_command(context, &system_disk, &configured_data, rust_stack);
    let output = match transport.run(connection, &command) {
        Ok(output) => output,
        Err(error) => {
            report
                .errors
                .push(format!("SSH transport failed: {error:#}"));
            return report;
        }
    };
    if output.status != 0 {
        report.errors.push(format!(
            "remote read-only discovery exited {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
        return report;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let Some((facts, lsblk_json)) = stdout.split_once("__LSBLK__\n") else {
        report
            .errors
            .push("remote discovery did not return lsblk JSON".to_owned());
        return report;
    };
    let facts = marker_map(facts);
    if facts.get("UID").map(String::as_str) != Some("0") {
        report
            .errors
            .push("remote SSH session is not uid 0".to_owned());
    }
    report.os = facts.get("OS").cloned().unwrap_or_default();
    if rust_stack {
        if !rust_os_supported(&report.os) {
            report.errors.push(format!(
                "rust-stack target must be Rocky/AlmaLinux/RHEL 9 or Debian 12/13, found {}",
                report.os
            ));
        }
    } else {
        let mut os_parts = report.os.split('|');
        if os_parts.next() != Some("rocky")
            || os_parts
                .next()
                .is_none_or(|version| !version.starts_with('9'))
        {
            report
                .errors
                .push(format!("target must be Rocky Linux 9, found {}", report.os));
        }
    }
    report.addresses = facts
        .get("ADDR")
        .map_or("", String::as_str)
        .split(',')
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect();
    report.root_source = facts.get("ROOT").cloned().unwrap_or_default();
    validate_addresses(context, &report.addresses, rust_stack, &mut report.errors);
    if let Some(interface) = context
        .get("keepalived_interface")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|interface| !interface.is_empty())
        && facts.get("KEEPALIVED_INTERFACE").map(String::as_str) != Some("ok")
    {
        report.errors.push(format!(
            "configured keepalived_interface {interface:?} does not exist on the target"
        ));
    }

    if !rust_stack {
        validate_repository_facts(&facts, &mut report);
    }

    match serde_json::from_str::<LsblkOutput>(lsblk_json.trim()) {
        Ok(lsblk) => validate_disks(&lsblk, &facts, &system_disk, &configured_data, &mut report),
        Err(error) => report
            .errors
            .push(format!("cannot parse remote lsblk JSON: {error}")),
    }
    report.ok = report.errors.is_empty();
    report
}

fn validate_repository_facts(
    facts: &std::collections::BTreeMap<String, String>,
    report: &mut HostPreflight,
) {
    for path in ["yum", "pip", "component"] {
        if facts.get(&format!("REPO_{path}")).map(String::as_str) == Some("ok") {
            report.repository_paths.push(path.to_owned());
        } else {
            report
                .errors
                .push(format!("local repository /{path}/ is not reachable"));
        }
    }
    for (marker, path, error) in [
        (
            "REPO_YUM_METADATA",
            "yum/repodata/repomd.xml",
            "local repository yum metadata /yum/repodata/repomd.xml is not readable",
        ),
        (
            "REPO_COMPONENT_SWIFT",
            "component/swift.tar.gz",
            "local repository /component/swift.tar.gz is not a valid gzip tar containing swift-2.31.1/",
        ),
        (
            "REPO_COMPONENT_SWIFTCLIENT",
            "component/python-swiftclient.tar.gz",
            "local repository /component/python-swiftclient.tar.gz is not a valid gzip tar containing python-swiftclient-4.2.0/",
        ),
    ] {
        if facts.get(marker).map(String::as_str) == Some("ok") {
            report.repository_paths.push(path.to_owned());
        } else {
            report.errors.push(error.to_owned());
        }
    }
}

fn validate_explicit_disk_contract(
    context: &Value,
    configured_data: &[String],
    rust_stack: bool,
    errors: &mut Vec<String>,
) -> bool {
    let mut safe = true;
    if !rust_stack && !context.get("use_custom_disks").is_some_and(ansible_bool) {
        errors.push(
            "use_custom_disks must be true; automatic disk discovery is not permitted".to_owned(),
        );
        safe = false;
    }
    let formats_disks = context
        .get("group_names")
        .and_then(Value::as_array)
        .is_some_and(|groups| {
            groups
                .iter()
                .any(|group| group.as_str() == Some("format_disk_servers"))
        });
    if formats_disks && configured_data.is_empty() {
        errors.push(
            "format_disk_servers hosts must declare at least one explicit custom_disks entry"
                .to_owned(),
        );
        safe = false;
    }
    safe
}

fn validate_controller_key(connection: &ConnectionSpec, errors: &mut Vec<String>) {
    let Some(path) = connection.key_path.as_deref() else {
        errors.push("an explicit controller-side SSH private key is required".to_owned());
        return;
    };
    let Ok(metadata) = fs::symlink_metadata(path) else {
        errors.push(format!(
            "SSH private key does not exist: {}",
            path.display()
        ));
        return;
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        errors.push(format!(
            "SSH private key must be a regular non-symlink file: {}",
            path.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            errors.push(format!(
                "SSH private key permissions are broader than 0600: {}",
                path.display()
            ));
        }
    }
}

fn discovery_command(
    context: &Value,
    system_disk: &str,
    data_disks: &[String],
    rust_stack: bool,
) -> String {
    let repository = context
        .get("local_repo_address")
        .and_then(Value::as_str)
        .filter(|value| valid_ipv4(value))
        .unwrap_or("0.0.0.0");
    let mut command = String::from("printf '__UID__=%s\\n' \"$(id -u)\"; ");
    command.push_str("if test -r /etc/os-release; then . /etc/os-release; printf '__OS__=%s|%s\\n' \"${ID:-}\" \"${VERSION_ID:-}\"; else printf '__OS__=|\\n'; fi; ");
    command.push_str("printf '__ADDR__='; ip -o -4 addr show scope global 2>/dev/null | awk '{split($4,a,\"/\"); print a[1]}' | paste -sd, -; ");
    command.push_str("printf '__ROOT__=%s\\n' \"$(findmnt -n -o SOURCE / 2>/dev/null)\"; ");
    command.push_str(&format!(
        "printf '__CANON_SYSTEM__=%s\\n' \"$(readlink -f -- {} 2>/dev/null)\"; ",
        shell_quote(system_disk)
    ));
    for (index, disk) in data_disks.iter().enumerate() {
        command.push_str(&format!(
            "printf '__CANON_DATA_{index}__=%s\\n' \"$(readlink -f -- {} 2>/dev/null)\"; ",
            shell_quote(disk)
        ));
    }
    if let Some(interface) = context
        .get("keepalived_interface")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|interface| !interface.is_empty())
    {
        command.push_str(&format!(
            "printf '__KEEPALIVED_INTERFACE__='; if ip link show -- {} >/dev/null 2>&1; then printf 'ok\\n'; else printf 'fail\\n'; fi; ",
            shell_quote(interface)
        ));
    }
    if !rust_stack {
        for path in ["yum", "pip", "component"] {
            command.push_str(&format!(
                "printf '__REPO_{path}__='; if curl -fsS --max-time 8 -o /dev/null {}; then printf 'ok\\n'; else printf 'fail\\n'; fi; ",
                shell_quote(&format!("http://{repository}/{path}/"))
            ));
        }
        command.push_str(&format!(
            "printf '__REPO_YUM_METADATA__='; if curl -fsS --max-time 15 -o /dev/null {}; then printf 'ok\\n'; else printf 'fail\\n'; fi; ",
            shell_quote(&format!("http://{repository}/yum/repodata/repomd.xml"))
        ));
        for (marker, archive, expected_root) in [
            ("REPO_COMPONENT_SWIFT", "swift.tar.gz", "swift-2.31.1"),
            (
                "REPO_COMPONENT_SWIFTCLIENT",
                "python-swiftclient.tar.gz",
                "python-swiftclient-4.2.0",
            ),
        ] {
            command.push_str(&format!(
                "printf '__{marker}__='; artifact=$(mktemp /tmp/swift-deploy-preflight.XXXXXX 2>/dev/null); if test -n \"$artifact\" && curl -fsS --max-time 120 -o \"$artifact\" {} && tar -tzf \"$artifact\" >/dev/null 2>&1 && tar -tzf \"$artifact\" 2>/dev/null | grep -Eq {}; then printf 'ok\\n'; else printf 'fail\\n'; fi; rm -f -- \"$artifact\"; ",
                shell_quote(&format!("http://{repository}/component/{archive}")),
                shell_quote(&format!(r"^{expected_root}(/|$)")),
            ));
        }
    }
    command.push_str(
        "printf '__LSBLK__\\n'; lsblk --json --paths --output PATH,TYPE,FSTYPE,MOUNTPOINTS",
    );
    command
}

fn normalize_device_path(value: &str) -> String {
    let value = value.trim();
    if value.is_empty() || value.starts_with('/') || value.contains('/') {
        value.to_owned()
    } else {
        format!("/dev/{value}")
    }
}

fn ansible_bool(value: &Value) -> bool {
    match value {
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_i64().is_some_and(|value| value != 0),
        Value::String(value) => matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "true" | "yes" | "on" | "1"
        ),
        _ => false,
    }
}

fn validate_addresses(
    context: &Value,
    actual: &[String],
    rust_stack: bool,
    errors: &mut Vec<String>,
) {
    let actual = actual.iter().map(String::as_str).collect::<HashSet<_>>();
    let fields: &[&str] = if rust_stack {
        // The rust stack may replicate over a dedicated network, so the
        // replication address must be proven assigned like every other one.
        &[
            "management_network_address",
            "storage_network_address",
            "replication_network_address",
            "business_network_address",
        ]
    } else {
        &[
            "management_network_address",
            "storage_network_address",
            "business_network_address",
        ]
    };
    for field in fields.iter().copied() {
        let expected = context
            .get(field)
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !actual.contains(expected) {
            errors.push(format!(
                "configured {field} {expected:?} is not assigned on the host"
            ));
        }
    }
    if !rust_stack {
        let storage = context
            .get("storage_network_address")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let replication = context
            .get("replication_network_address")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if storage != replication {
            errors.push(
                "replication_network_address must equal storage_network_address for v3".to_owned(),
            );
        }
    }
}

/// OS acceptance for rust-stack hosts: the EL 9 family (`rocky`, `almalinux`,
/// `rhel`) or Debian 12/13. `os` is the discovered `<ID>|<VERSION_ID>` pair.
fn rust_os_supported(os: &str) -> bool {
    let mut parts = os.split('|');
    let id = parts.next().unwrap_or("").trim();
    let major = parts
        .next()
        .unwrap_or("")
        .trim()
        .split(['.', '-'])
        .next()
        .unwrap_or("");
    match id {
        "rocky" | "almalinux" | "rhel" => major == "9",
        "debian" => matches!(major, "12" | "13"),
        _ => false,
    }
}

fn validate_disks(
    lsblk: &LsblkOutput,
    facts: &std::collections::BTreeMap<String, String>,
    system_disk: &str,
    configured_data: &[String],
    report: &mut HostPreflight,
) {
    if configured_data.is_empty() {
        return;
    }
    let protected = lsblk
        .blockdevices
        .iter()
        .filter(|device| subtree_contains_root(device, &report.root_source))
        .map(|device| device.path.as_str())
        .collect::<BTreeSet<_>>();
    if protected.is_empty() {
        report
            .errors
            .push("cannot identify the physical root disk from lsblk/findmnt".to_owned());
    }
    let canonical_system = facts.get("CANON_SYSTEM").map_or("", String::as_str);
    if canonical_system.is_empty() || !protected.contains(canonical_system) {
        report.errors.push(format!(
            "configured system disk {system_disk:?} resolves to {canonical_system:?}, not the detected root disk"
        ));
    }
    let mut seen = BTreeSet::new();
    let mut canonical_data = Vec::new();
    for (index, configured) in configured_data.iter().enumerate() {
        let canonical = facts
            .get(&format!("CANON_DATA_{index}"))
            .map_or("", String::as_str);
        canonical_data.push(canonical.to_owned());
        if canonical.is_empty() {
            report.errors.push(format!(
                "data disk {configured:?} does not resolve on the target"
            ));
            continue;
        }
        if !seen.insert(canonical.to_owned()) {
            report
                .errors
                .push(format!("multiple data disk entries resolve to {canonical}"));
        }
        if protected.contains(canonical) || canonical == canonical_system {
            report.errors.push(format!(
                "data disk {configured:?} resolves to protected root disk {canonical}"
            ));
            continue;
        }
        let Some(device) = find_device(&lsblk.blockdevices, canonical) else {
            report
                .errors
                .push(format!("data disk {configured:?} is absent from lsblk"));
            continue;
        };
        if device.device_type != "disk" {
            report.errors.push(format!(
                "data disk {configured:?} resolves to type {}, not a whole disk",
                device.device_type
            ));
        }
        if device_in_use(device) {
            report.errors.push(format!(
                "data disk {configured:?} already has partitions, a filesystem, or a mount"
            ));
        }
    }
    report.data_disks = canonical_data;
}

fn marker_map(text: &str) -> std::collections::BTreeMap<String, String> {
    text.lines()
        .filter_map(|line| line.strip_prefix("__")?.split_once("__="))
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect()
}

fn find_device<'a>(devices: &'a [BlockDevice], path: &str) -> Option<&'a BlockDevice> {
    for device in devices {
        if device.path == path {
            return Some(device);
        }
        if let Some(found) = find_device(&device.children, path) {
            return Some(found);
        }
    }
    None
}

fn subtree_contains_root(device: &BlockDevice, root_source: &str) -> bool {
    device.path == root_source
        || mountpoints(&device.mountpoints).contains(&"/")
        || device
            .children
            .iter()
            .any(|child| subtree_contains_root(child, root_source))
}

fn device_in_use(device: &BlockDevice) -> bool {
    device
        .fstype
        .as_deref()
        .is_some_and(|value| !value.is_empty())
        || !mountpoints(&device.mountpoints).is_empty()
        || !device.children.is_empty()
}

fn mountpoints(value: &Value) -> Vec<&str> {
    match value {
        Value::String(value) if !value.is_empty() => vec![value],
        Value::Array(values) => values.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    }
}

fn string_array(context: &Value, key: &str) -> Vec<String> {
    context
        .get(key)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .filter(|value| !value.is_empty())
        .collect()
}

fn valid_ipv4(value: &str) -> bool {
    value.parse::<std::net::Ipv4Addr>().is_ok()
}

fn shell_quote(value: &str) -> String {
    shell_words::quote(value).into_owned()
}
