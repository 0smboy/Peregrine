use std::collections::BTreeMap;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Executable Ansible module surface observed in the selected v3 archive.
pub const SUPPORTED_MODULES: [&str; 28] = [
    "blockinfile",
    "command",
    "copy",
    "cron",
    "debug",
    "fail",
    "fetch",
    "file",
    "find",
    "get_url",
    "ini_file",
    "lineinfile",
    "mysql_db",
    "mysql_user",
    "package",
    "pip",
    "script",
    "service",
    "set_fact",
    "shell",
    "stat",
    "systemd",
    "template",
    "timezone",
    "unarchive",
    "uri",
    "user",
    "yum",
];

/// Current sealed-plan contract. Version 2 adds the mandatory `HostReconfigure`
/// capability; version 1 plans must be rebuilt so they cannot bypass it.
pub const PLAN_SCHEMA_VERSION: u32 = 2;

/// Result of a strict, read-only bundle audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleAudit {
    pub task_files: usize,
    pub tasks: usize,
    pub modules: BTreeMap<String, usize>,
    pub controls: BTreeMap<String, usize>,
    pub unsupported_modules: Vec<String>,
    pub parse_errors: Vec<String>,
    pub fingerprint: String,
}

impl BundleAudit {
    #[must_use]
    pub fn executable_module_count(&self) -> usize {
        self.modules
            .keys()
            .filter(|name| name.as_str() != "include" && name.as_str() != "include_tasks")
            .count()
    }

    #[must_use]
    pub fn is_compatible(&self) -> bool {
        self.unsupported_modules.is_empty() && self.parse_errors.is_empty()
    }
}

/// Independently authorized high-risk operation classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskClass {
    DiskWipe,
    Firewall,
    SshReconfigure,
    HostReconfigure,
}

/// Observed loop forms retained as raw expressions for runtime evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoopSpec {
    pub kind: String,
    pub expression: Value,
    pub loop_var: String,
}

/// One flattened, host-scoped task in an approved plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannedTask {
    pub id: u64,
    pub source: String,
    pub role: String,
    pub name: String,
    pub host_pattern: String,
    pub hosts: Vec<String>,
    pub module: String,
    pub args: Value,
    pub vars: BTreeMap<String, Value>,
    pub when: Vec<String>,
    pub loops: Vec<LoopSpec>,
    pub run_once: bool,
    #[serde(rename = "become")]
    pub privilege_escalation: bool,
    pub become_user: Option<String>,
    pub delegate_to: Option<String>,
    pub register: Option<String>,
    pub notify: Vec<String>,
    pub ignore_errors: bool,
    pub failed_when: Vec<String>,
    pub changed_when: Vec<String>,
    pub risk: Vec<RiskClass>,
}

/// Canonical plan sealed by a digest over every field except `digest` itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Plan {
    pub schema_version: u32,
    pub bundle_fingerprint: String,
    pub inventory_fingerprint: String,
    pub playbook: String,
    pub hosts: Vec<String>,
    pub tasks: Vec<PlannedTask>,
    pub handlers: Vec<PlannedTask>,
    pub digest: String,
}

/// Normalized result returned by every module adapter.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleResult {
    pub changed: bool,
    pub failed: bool,
    pub message: String,
    pub data: Value,
}

/// Aggregate, automation-friendly execution outcome.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionReport {
    pub changed: usize,
    pub unchanged: usize,
    pub skipped: usize,
    pub failed: usize,
    pub tasks: usize,
}

impl Plan {
    /// Seal this plan with deterministic SHA-256 canonical JSON.
    pub fn seal(mut self) -> Result<Self> {
        self.digest = self.expected_digest()?;
        Ok(self)
    }

    /// Fail if any plan field changed after sealing.
    pub fn verify(&self) -> Result<()> {
        if self.schema_version != PLAN_SCHEMA_VERSION {
            bail!(
                "unsupported plan schema {}; rebuild the plan with schema {PLAN_SCHEMA_VERSION}",
                self.schema_version
            );
        }
        let expected = self.expected_digest()?;
        if self.digest != expected {
            bail!(
                "plan digest mismatch: stored {}, calculated {expected}",
                self.digest
            );
        }
        Ok(())
    }

    /// Unique required capabilities in stable order.
    #[must_use]
    pub fn required_capabilities(&self) -> Vec<RiskClass> {
        self.tasks
            .iter()
            .chain(&self.handlers)
            .flat_map(|task| task.risk.iter().copied())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    fn expected_digest(&self) -> Result<String> {
        let mut canonical = self.clone();
        canonical.digest.clear();
        let bytes = serde_json::to_vec(&canonical)?;
        Ok(hex::encode(Sha256::digest(bytes)))
    }
}
