use anyhow::{Result, bail};
use regex::Regex;
use serde_json::Value;

use crate::model::{Plan, PlannedTask, RiskClass};

/// Explicit, independent capabilities required before an approved plan can run.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct SafetyPolicy {
    pub allow_disk_wipe: bool,
    pub allow_firewall: bool,
    pub allow_ssh_reconfigure: bool,
    pub allow_host_reconfigure: bool,
}

impl SafetyPolicy {
    pub fn authorize(&self, plan: &Plan) -> Result<()> {
        let missing = plan
            .required_capabilities()
            .into_iter()
            .filter(|risk| match risk {
                RiskClass::DiskWipe => !self.allow_disk_wipe,
                RiskClass::Firewall => !self.allow_firewall,
                RiskClass::SshReconfigure => !self.allow_ssh_reconfigure,
                RiskClass::HostReconfigure => !self.allow_host_reconfigure,
            })
            .map(|risk| format!("{risk:?}"))
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            bail!(
                "missing independent safety capabilities: {}",
                missing.join(", ")
            );
        }
        Ok(())
    }
}

/// Classify a task from its audited source, module, and raw arguments.
#[must_use]
pub fn classify_task(task: &PlannedTask) -> Vec<RiskClass> {
    let evidence = format!(
        "{} {} {} {} {}",
        task.source,
        task.role,
        task.name,
        task.module,
        serde_json::to_string(&task.args).unwrap_or_default()
    )
    .to_lowercase();
    let mut risk = Vec::new();

    let disk_patterns = [
        "dd if=/dev/zero",
        "mkfs.",
        "mkfs ",
        "parted ",
        "wipefs",
        "sgdisk --zap",
    ];
    if disk_patterns
        .iter()
        .any(|pattern| evidence.contains(pattern))
    {
        risk.push(RiskClass::DiskWipe);
    }

    let firewall_patterns = [
        "iptables",
        "firewalld",
        "firewall.yml",
        "/etc/sysconfig/iptables",
    ];
    if firewall_patterns
        .iter()
        .any(|pattern| evidence.contains(pattern))
    {
        risk.push(RiskClass::Firewall);
    }

    let ssh_patterns = [
        "/etc/ssh/sshd_config",
        "ssh_bind_port",
        "listenaddress",
        "restart ssh service",
        "name=sshd",
        "\"name\":\"sshd\"",
    ];
    if ssh_patterns
        .iter()
        .any(|pattern| evidence.contains(pattern))
    {
        risk.push(RiskClass::SshReconfigure);
    }

    // The selected v3 playbook does substantially more than install Swift. It
    // replaces the host's package sources, performs a full yum upgrade, changes
    // OS identity/locale/time settings, and enables or restarts system services
    // and cron jobs. Keep those mutations behind a capability independent from
    // disk, firewall, and SSH authorization.
    let host_reconfigure_modules = [
        "cron", "package", "pip", "service", "systemd", "timezone", "user", "yum",
    ];
    let host_reconfigure_patterns = [
        "/etc/yum.conf",
        "/etc/yum.repos.d",
        "backup_repo.sh",
        "yum clean all",
        "yum repolist",
        "yum upgrade",
        "hostnamectl set-hostname",
        "/etc/hosts",
        "/etc/locale.conf",
        "/etc/profile",
        "/etc/bashrc",
        "/etc/selinux/config",
        "selinux=disabled",
        "/etc/systemd/system",
        "/lib/systemd/system",
        "/usr/lib/systemd/system",
        "/etc/systemd/journald.conf",
        "/etc/security/limits",
        "/etc/sysctl",
        "sysctl ",
        "kill_all_swift_services.sh",
        "restart crond",
        "name=crond",
        "\"name\":\"crond\"",
    ];
    if host_reconfigure_modules.contains(&task.module.as_str())
        || host_reconfigure_patterns
            .iter()
            .any(|pattern| evidence.contains(pattern))
    {
        risk.push(RiskClass::HostReconfigure);
    }

    risk.sort_unstable();
    risk.dedup();
    risk
}

/// Redact secrets in structured output while retaining non-sensitive evidence.
#[must_use]
pub fn redact(value: &Value) -> Value {
    redact_inner(value, None)
}

fn redact_inner(value: &Value, key: Option<&str>) -> Value {
    if key.is_some_and(sensitive_key) {
        return Value::String("<redacted>".to_owned());
    }
    match value {
        Value::Array(items) => {
            Value::Array(items.iter().map(|item| redact_inner(item, None)).collect())
        }
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(name, item)| (name.clone(), redact_inner(item, Some(name))))
                .collect(),
        ),
        Value::String(text) => Value::String(redact_fragments(text)),
        _ => value.clone(),
    }
}

fn sensitive_key(key: &str) -> bool {
    let key = key.to_lowercase();
    [
        "password",
        "passwd",
        "passphrase",
        "secret",
        "token",
        "access_key",
        "access-key",
        "private_key",
        "private-key",
    ]
    .iter()
    .any(|marker| key.contains(marker))
}

fn redact_fragments(text: &str) -> String {
    let pattern = Regex::new(
        r"(?i)(password|passwd|passphrase|secret|token|access[_-]?key|private[_-]?key)(\s*[=:]\s*)([^\s,;]+)",
    )
    .expect("valid redaction regex");
    pattern.replace_all(text, "$1$2<redacted>").into_owned()
}
