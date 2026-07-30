use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workload {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub storage: StorageConfig,
    #[serde(default)]
    pub auth: Option<AuthConfig>,
    pub stages: Vec<Stage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum StorageConfig {
    Mock {
        #[serde(default)]
        latency_us: u64,
    },
    S3 {
        endpoint: Option<String>,
        region: String,
        access_key: String,
        secret_key: String,
        #[serde(default)]
        path_style: bool,
        #[serde(default = "default_timeout_ms")]
        timeout_ms: u64,
        #[serde(default = "default_multipart_threshold")]
        multipart_threshold: u64,
        #[serde(default = "default_multipart_part_size")]
        multipart_part_size: u64,
    },
    /// OpenStack Swift (Keystone token applied at runtime if auth is keystone_v3).
    Swift {
        /// Base storage URL, e.g. http://swift:8080/v1/AUTH_{project}
        /// If empty and Keystone returns storage_url, that is used.
        endpoint: String,
        #[serde(default = "default_timeout_ms")]
        timeout_ms: u64,
        /// Optional static token (otherwise Keystone auth result).
        #[serde(default)]
        token: Option<String>,
    },
}

fn default_timeout_ms() -> u64 { 60_000 }
fn default_multipart_threshold() -> u64 { 8 * 1024 * 1024 }
fn default_multipart_part_size() -> u64 { 8 * 1024 * 1024 }

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuthConfig {
    KeystoneV3 {
        url: String,
        username: String,
        password: String,
        project_name: String,
        #[serde(default = "default_domain")]
        user_domain_name: String,
        #[serde(default = "default_domain")]
        project_domain_name: String,
        #[serde(default)]
        user_domain_id: Option<String>,
        #[serde(default)]
        project_domain_id: Option<String>,
        #[serde(default = "default_timeout_ms")]
        timeout_ms: u64,
    },
    /// Swift v1 auth (tempauth / swauth): GET the auth URL with
    /// X-Auth-User / X-Auth-Key; token and account storage URL come back
    /// in the X-Auth-Token / X-Storage-Url response headers.
    TempAuth {
        /// Auth endpoint, e.g. http://swift:8080/auth/v1.0
        url: String,
        /// account:user, e.g. test:tester
        user: String,
        key: String,
        #[serde(default = "default_timeout_ms")]
        timeout_ms: u64,
    },
    None,
}

fn default_domain() -> String { "Default".into() }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stage {
    pub name: String,
    #[serde(default = "default_stage_kind")]
    pub kind: String,
    pub workers: u32,
    #[serde(default)]
    pub runtime_secs: u64,
    #[serde(default)]
    pub total_ops: u64,
    pub operations: Vec<Operation>,
    pub objects: ObjectSpec,
    #[serde(default)]
    pub sequential: bool,
}

fn default_stage_kind() -> String { "main".into() }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Operation {
    #[serde(rename = "type")]
    pub op_type: String,
    pub ratio: u32,
    #[serde(default)]
    pub config: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectSpec {
    pub cprefix: String,
    pub containers: IdRange,
    pub oprefix: String,
    pub objects: IdRange,
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub size_min: u64,
    #[serde(default)]
    pub size_max: u64,
    #[serde(default)]
    pub hash_check: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct IdRange {
    pub start: u64,
    pub end: u64,
}

impl IdRange {
    pub fn count(self) -> u64 {
        self.end.saturating_sub(self.start).saturating_add(1)
    }
}

impl Workload {
    pub fn from_yaml_file(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        let wl: Self = serde_yaml::from_str(&text)?;
        wl.validate()?;
        Ok(wl)
    }

    pub fn to_yaml(&self) -> anyhow::Result<String> {
        Ok(serde_yaml::to_string(self)?)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.stages.is_empty() {
            anyhow::bail!("workload has no stages");
        }
        for st in &self.stages {
            if st.workers == 0 {
                anyhow::bail!("stage `{}`: workers must be > 0", st.name);
            }
            if st.runtime_secs == 0 && st.total_ops == 0 {
                anyhow::bail!("stage `{}`: set runtime_secs and/or total_ops", st.name);
            }
            if st.operations.is_empty() {
                anyhow::bail!("stage `{}`: no operations", st.name);
            }
            if st.operations.iter().map(|o| o.ratio as u64).sum::<u64>() == 0 {
                anyhow::bail!("stage `{}`: operation ratios sum to 0", st.name);
            }
            let sz = st.objects.effective_size_bounds();
            if sz.1 == 0 && st.operations.iter().any(|o| o.op_type == "write") {
                anyhow::bail!("stage `{}`: write ops need size or size_max > 0", st.name);
            }
        }
        Ok(())
    }
}

impl ObjectSpec {
    pub fn effective_size_bounds(&self) -> (u64, u64) {
        if self.size_max > 0 {
            let lo = if self.size_min > 0 {
                self.size_min
            } else if self.size > 0 {
                self.size
            } else {
                1
            };
            (lo.min(self.size_max), self.size_max)
        } else {
            (self.size, self.size)
        }
    }
    pub fn container_name(&self, id: u64) -> String {
        format!("{}{}", self.cprefix, id)
    }
    pub fn object_name(&self, id: u64) -> String {
        format!("{}{}", self.oprefix, id)
    }
}

impl Stage {
    pub fn duration(&self) -> Option<Duration> {
        if self.runtime_secs > 0 {
            Some(Duration::from_secs(self.runtime_secs))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_swift() {
        let yaml = r#"
name: t
storage:
  type: swift
  endpoint: http://127.0.0.1:8080/v1/AUTH_demo
auth:
  type: keystone_v3
  url: http://keystone:5000/v3
  username: u
  password: p
  project_name: demo
stages:
  - name: main
    workers: 1
    total_ops: 1
    operations:
      - type: write
        ratio: 100
    objects:
      cprefix: b
      containers: { start: 1, end: 1 }
      oprefix: o
      objects: { start: 1, end: 1 }
      size: 64
"#;
        let wl: Workload = serde_yaml::from_str(yaml).unwrap();
        wl.validate().unwrap();
        assert!(matches!(wl.storage, StorageConfig::Swift { .. }));
    }
}
