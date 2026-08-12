// Copyright (c) 2026 OpenStack Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Storage policies, ported from `swift/common/storage_policy.py`.
//!
//! Policies are parsed from `[storage-policy:N]` sections of `swift.conf`
//! (note Python reads that file with `strict=False`, so use
//! [`SwiftConfig::parse_lenient`]) and validated exactly as the Python
//! `StoragePolicyCollection` does.
//!
//! Deferred to later crates:
//! - actual PyECLib/liberasurecode driver initialisation and
//!   `fragment_size` computation (`swift-ec`); here EC parameters are
//!   validated structurally and quorum is computed from the scheme.
//! - ring loading (`swift-ring`); [`StoragePolicy::validate_ring_replica_count`]
//!   provides the EC validation hook.

use std::fmt;

use crate::config::{config_true_value, list_from_csv, SwiftConfig};

pub const LEGACY_POLICY_NAME: &str = "Policy-0";

pub const REPL_POLICY: &str = "replication";
pub const EC_POLICY: &str = "erasure_coding";
pub const DEFAULT_POLICY_TYPE: &str = REPL_POLICY;

pub const DEFAULT_EC_OBJECT_SEGMENT_SIZE: u64 = 1048576;

/// EC schemes recognised by PyECLib (`pyeclib.ec_iface.ALL_EC_TYPES`).
/// Runtime availability checking against liberasurecode is deferred to
/// the `swift-ec` crate.
pub const VALID_EC_TYPES: [&str; 9] = [
    "jerasure_rs_vand",
    "jerasure_rs_cauchy",
    "flat_xor_hd_3",
    "flat_xor_hd_4",
    "isa_l_rs_vand",
    "isa_l_rs_cauchy",
    "shss",
    "liberasurecode_rs_vand",
    "libphazr",
];

/// Error validating or parsing storage policies (Python `PolicyError`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyError(pub String);

impl PolicyError {
    fn new(msg: impl Into<String>) -> Self {
        PolicyError(msg.into())
    }

    /// Python `PolicyError(msg, index=idx)` appends `, for index 'idx'`.
    fn for_index(msg: impl Into<String>, index: impl fmt::Display) -> Self {
        PolicyError(format!("{}, for index '{}'", msg.into(), index))
    }
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for PolicyError {}

/// Quorum size for services that use replication for data integrity
/// (Python `utils.quorum_size`): `(n + 1) // 2`.
pub fn quorum_size(n: f64) -> u64 {
    ((n + 1.0) / 2.0).floor() as u64
}

/// Zero-indexed base string (Python `get_zero_indexed_base_string`):
/// index 0 yields the bare base, otherwise `base-index`.
pub fn get_zero_indexed_base_string(base: &str, index: u32) -> String {
    if index == 0 {
        base.to_string()
    } else {
        format!("{base}-{index}")
    }
}

fn valid_policy_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-'
}

/// Minimum number of parity fragments needed by an EC scheme, mirroring
/// PyECLib's `min_parity_fragments_needed()`. Will be replaced by a
/// liberasurecode driver query in the `swift-ec` crate.
fn min_parity_fragments_needed(ec_type: &str) -> u64 {
    match ec_type {
        "flat_xor_hd_3" => 2,
        "flat_xor_hd_4" => 3,
        _ => 1,
    }
}

/// EC-specific configuration of a policy of type `erasure_coding`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ECPolicyConfig {
    pub ec_type: String,
    pub ec_ndata: u64,
    pub ec_nparity: u64,
    pub ec_segment_size: u64,
    pub ec_duplication_factor: u64,
}

impl ECPolicyConfig {
    /// Total number of unique fragments (data + parity).
    pub fn ec_n_unique_fragments(&self) -> u64 {
        self.ec_ndata + self.ec_nparity
    }

    /// Short form of the EC schema stored in object system metadata on
    /// EC fragment archives for debugging.
    pub fn ec_scheme_description(&self) -> String {
        format!("{} {}+{}", self.ec_type, self.ec_ndata, self.ec_nparity)
    }
}

/// Type-specific part of a storage policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicySpecifics {
    Replication,
    ErasureCoding(ECPolicyConfig),
}

/// A storage policy (Python `StoragePolicy` / `ECStoragePolicy`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoragePolicy {
    idx: u32,
    alias_list: Vec<String>,
    pub is_default: bool,
    pub is_deprecated: bool,
    diskfile_module: String,
    ring_name: String,
    specifics: PolicySpecifics,
}

impl StoragePolicy {
    /// Create a replication policy (used directly only for the
    /// auto-created legacy `Policy-0`).
    pub fn new_replication(idx: u32, name: &str) -> Result<Self, PolicyError> {
        let mut policy = StoragePolicy {
            idx,
            alias_list: Vec::new(),
            is_default: false,
            is_deprecated: false,
            diskfile_module: "egg:swift#replication.fs".to_string(),
            ring_name: get_zero_indexed_base_string("object", idx),
            specifics: PolicySpecifics::Replication,
        };
        policy.add_name(name)?;
        Ok(policy)
    }

    /// Build a policy from a `[storage-policy:<index>]` section's options
    /// (Python `from_config` plus the `policy_type` dispatch done in
    /// `parse_storage_policies`).
    pub fn from_config(
        policy_index: &str,
        options: &[(String, String)],
    ) -> Result<Self, PolicyError> {
        let idx: i64 = policy_index
            .trim()
            .parse()
            .map_err(|_| PolicyError::new(format!("Invalid index {policy_index}")))?;
        if idx < 0 || idx > u32::MAX as i64 {
            return Err(PolicyError::new(format!("Invalid index {policy_index}")));
        }
        let idx = idx as u32;

        let get = |key: &str| -> Option<&str> {
            options
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.as_str())
        };
        let policy_type = get("policy_type").unwrap_or(DEFAULT_POLICY_TYPE);
        let is_ec = match policy_type {
            REPL_POLICY => false,
            EC_POLICY => true,
            other => return Err(PolicyError::new(format!("Invalid type {other}"))),
        };

        // validate option names against the type's config option map
        let base_options = [
            "name",
            "aliases",
            "policy_type",
            "default",
            "deprecated",
            "diskfile_module",
        ];
        let ec_options = [
            "ec_type",
            "ec_object_segment_size",
            "ec_num_data_fragments",
            "ec_num_parity_fragments",
            "ec_duplication_factor",
        ];
        for (key, _) in options {
            let known = base_options.contains(&key.as_str())
                || (is_ec && ec_options.contains(&key.as_str()));
            if !known {
                return Err(PolicyError::for_index(
                    format!("Invalid option '{key}' in storage-policy section"),
                    policy_index,
                ));
            }
        }

        let name = get("name").unwrap_or("");
        let default_diskfile = if is_ec {
            "egg:swift#erasure_coding.fs"
        } else {
            "egg:swift#replication.fs"
        };

        let specifics = if is_ec {
            // ec_type is one of the EC implementations supported by PyEClib
            let ec_type = get("ec_type")
                .ok_or_else(|| PolicyError::new("Missing ec_type"))?
                .to_string();
            if !VALID_EC_TYPES.contains(&ec_type.as_str()) {
                return Err(PolicyError::new(format!(
                    "Wrong ec_type {} for policy {}, should be one of \"{}\"",
                    ec_type,
                    name,
                    VALID_EC_TYPES.join(", ")
                )));
            }
            let parse_positive = |value: Option<&str>, what: &str| -> Result<u64, PolicyError> {
                let fail = || PolicyError::for_index(format!("Invalid {what} {value:?}"), idx);
                let v: i64 = value.ok_or_else(fail)?.trim().parse().map_err(|_| fail())?;
                if v <= 0 {
                    return Err(fail());
                }
                Ok(v as u64)
            };
            let ec_ndata = parse_positive(get("ec_num_data_fragments"), "ec_num_data_fragments")?;
            let ec_nparity =
                parse_positive(get("ec_num_parity_fragments"), "ec_num_parity_fragments")?;
            let ec_segment_size = match get("ec_object_segment_size") {
                None => DEFAULT_EC_OBJECT_SEGMENT_SIZE,
                some => parse_positive(some, "ec_object_segment_size")?,
            };
            let ec_duplication_factor = match get("ec_duplication_factor") {
                None => 1,
                Some(v) => v
                    .trim()
                    .parse::<i64>()
                    .ok()
                    .filter(|&n| n >= 1)
                    .ok_or_else(|| {
                        PolicyError::new(format!(
                            "Config option must be an positive int number, not \"{v}\"."
                        ))
                    })? as u64,
            };
            PolicySpecifics::ErasureCoding(ECPolicyConfig {
                ec_type,
                ec_ndata,
                ec_nparity,
                ec_segment_size,
                ec_duplication_factor,
            })
        } else {
            PolicySpecifics::Replication
        };

        let mut policy = StoragePolicy {
            idx,
            alias_list: Vec::new(),
            is_default: get("default").is_some_and(config_true_value),
            is_deprecated: get("deprecated").is_some_and(config_true_value),
            diskfile_module: get("diskfile_module")
                .unwrap_or(default_diskfile)
                .to_string(),
            ring_name: get_zero_indexed_base_string("object", idx),
            specifics,
        };

        policy.add_name(name)?;
        if let Some(aliases) = get("aliases") {
            for alias in list_from_csv(aliases) {
                if alias == name {
                    continue;
                }
                policy.add_name(&alias)?;
            }
        }

        if policy.is_deprecated && policy.is_default {
            return Err(PolicyError::new(format!(
                "Deprecated policy can not be default.  Invalid config, for index {}",
                policy.idx
            )));
        }

        // an isa_l_rs_vand scheme with nparity >= 5 harms data durability
        // and must be deprecated (https://bugs.launchpad.net/swift/+bug/1639691)
        if let PolicySpecifics::ErasureCoding(ec) = &policy.specifics {
            if ec.ec_type == "isa_l_rs_vand" && ec.ec_nparity >= 5 && !policy.is_deprecated {
                return Err(PolicyError::new(format!(
                    "Storage policy {} uses an EC configuration known to harm \
                     data durability. This policy MUST be deprecated.",
                    policy.name()
                )));
            }
        }

        Ok(policy)
    }

    pub fn idx(&self) -> u32 {
        self.idx
    }

    /// Primary name of the policy.
    pub fn name(&self) -> &str {
        &self.alias_list[0]
    }

    /// All names, comma-joined (Python `aliases` property).
    pub fn aliases(&self) -> String {
        self.alias_list.join(", ")
    }

    pub fn alias_list(&self) -> &[String] {
        &self.alias_list
    }

    /// Ring file base name: `object` for policy 0, `object-N` otherwise.
    pub fn ring_name(&self) -> &str {
        &self.ring_name
    }

    pub fn diskfile_module(&self) -> &str {
        &self.diskfile_module
    }

    pub fn policy_type(&self) -> &'static str {
        match self.specifics {
            PolicySpecifics::Replication => REPL_POLICY,
            PolicySpecifics::ErasureCoding(_) => EC_POLICY,
        }
    }

    /// The EC configuration, if this is an erasure-coding policy.
    pub fn ec(&self) -> Option<&ECPolicyConfig> {
        match &self.specifics {
            PolicySpecifics::Replication => None,
            PolicySpecifics::ErasureCoding(ec) => Some(ec),
        }
    }

    fn validate_policy_name(&self, name: &str) -> Result<(), PolicyError> {
        if name.is_empty() {
            return Err(PolicyError::for_index(
                format!("Invalid name {name:?}"),
                self.idx,
            ));
        }
        // defensively restrictive: names are used as HTTP headers
        if !name.chars().all(valid_policy_char) {
            return Err(PolicyError::for_index(
                format!(
                    "Names are used as HTTP headers, and can not reliably \
                     contain any characters not in letters, digits or a \
                     dash. Invalid name {name:?}"
                ),
                self.idx,
            ));
        }
        if name.eq_ignore_ascii_case(LEGACY_POLICY_NAME) && self.idx != 0 {
            return Err(PolicyError::for_index(
                format!(
                    "The name {LEGACY_POLICY_NAME} is reserved for policy \
                     index 0. Invalid name {name:?}"
                ),
                self.idx,
            ));
        }
        if self
            .alias_list
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(name))
        {
            return Err(PolicyError::for_index(
                format!("The name {name} is already assigned to this policy."),
                self.idx,
            ));
        }
        Ok(())
    }

    /// Add an alias name to the policy. Prefer going through
    /// [`StoragePolicyCollection::add_policy_alias`] so lookups stay
    /// consistent.
    pub fn add_name(&mut self, name: &str) -> Result<(), PolicyError> {
        self.validate_policy_name(name)?;
        self.alias_list.push(name.to_string());
        Ok(())
    }

    /// Remove an alias name; the policy must retain at least one name.
    pub fn remove_name(&mut self, name: &str) -> Result<(), PolicyError> {
        let Some(pos) = self.alias_list.iter().position(|n| n == name) else {
            return Err(PolicyError::new(format!(
                "{} is not a name assigned to policy {}",
                name, self.idx
            )));
        };
        if self.alias_list.len() == 1 {
            return Err(PolicyError::new(format!(
                "Cannot remove only name {} from policy {}. Policies must \
                 have at least one name.",
                name, self.idx
            )));
        }
        self.alias_list.remove(pos);
        Ok(())
    }

    /// Change the primary name of the policy.
    pub fn change_primary_name(&mut self, name: &str) -> Result<(), PolicyError> {
        if name == self.name() {
            return Ok(());
        }
        if let Some(pos) = self.alias_list.iter().position(|n| n == name) {
            self.alias_list.remove(pos);
        } else {
            self.validate_policy_name(name)?;
        }
        self.alias_list.insert(0, name.to_string());
        Ok(())
    }

    /// Number of successful backend requests needed for the proxy to
    /// consider a client request successful.
    ///
    /// For replication policies this depends on the ring's replica count;
    /// for EC policies it is derived from the scheme.
    pub fn quorum(&self, replica_count: f64) -> u64 {
        match &self.specifics {
            PolicySpecifics::Replication => quorum_size(replica_count),
            PolicySpecifics::ErasureCoding(ec) => {
                (ec.ec_ndata + min_parity_fragments_needed(&ec.ec_type)) * ec.ec_duplication_factor
            }
        }
    }

    /// EC-specific ring validation hook (Python `validate_ring_data`):
    /// the ring's replica count must equal exactly
    /// `(ndata + nparity) * duplication_factor`.
    pub fn validate_ring_replica_count(&self, replica_count: f64) -> Result<(), PolicyError> {
        if let PolicySpecifics::ErasureCoding(ec) = &self.specifics {
            let required = (ec.ec_n_unique_fragments() * ec.ec_duplication_factor) as f64;
            if replica_count != required {
                return Err(PolicyError::new(format!(
                    "EC ring for policy {} needs to be configured with \
                     exactly {} replicas. Got {}.",
                    self.name(),
                    required as u64,
                    replica_count
                )));
            }
        }
        Ok(())
    }

    /// Backend fragment index for a node index (Python
    /// `get_backend_index`); `None` for replication policies.
    pub fn get_backend_index(&self, node_index: u64) -> Option<u64> {
        self.ec().map(|ec| node_index % ec.ec_n_unique_fragments())
    }
}

/// The collection of valid storage policies for the cluster (Python
/// `StoragePolicyCollection`).
#[derive(Debug, Clone)]
pub struct StoragePolicyCollection {
    /// Policies in insertion order (parsed order, then any auto-created
    /// legacy Policy-0).
    policies: Vec<StoragePolicy>,
    default_idx: u32,
}

impl StoragePolicyCollection {
    /// Validate and build a collection (Python `_validate_policies`):
    ///
    /// * indexes and names (case-insensitive) must be unique
    /// * at most one default; deprecated policies can't be default
    /// * policy 0 is auto-created only when no policies are defined
    /// * at least one policy must not be deprecated
    /// * a lone policy becomes the default automatically
    pub fn new(policies: Vec<StoragePolicy>) -> Result<Self, PolicyError> {
        let mut validated: Vec<StoragePolicy> = Vec::new();
        let mut default_idx: Option<u32> = None;
        for policy in policies {
            if let Some(existing) = validated.iter().find(|p| p.idx == policy.idx) {
                return Err(PolicyError::new(format!(
                    "Duplicate index {} conflicts with {}",
                    policy.idx, existing.idx
                )));
            }
            for name in &policy.alias_list {
                if let Some(existing) = validated
                    .iter()
                    .find(|p| p.alias_list.iter().any(|n| n.eq_ignore_ascii_case(name)))
                {
                    return Err(PolicyError::new(format!(
                        "Duplicate name {} conflicts with policy {}",
                        name, existing.idx
                    )));
                }
            }
            if policy.is_default {
                if let Some(existing) = default_idx {
                    return Err(PolicyError::new(format!(
                        "Duplicate default {} conflicts with {}",
                        policy.idx, existing
                    )));
                }
                default_idx = Some(policy.idx);
            }
            validated.push(policy);
        }

        // if a 0 policy wasn't explicitly given, or nothing was provided,
        // create the 0 policy now
        if !validated.iter().any(|p| p.idx == 0) {
            if !validated.is_empty() {
                return Err(PolicyError::new(
                    "You must specify a storage policy section for policy \
                     index 0 in order to define multiple policies",
                ));
            }
            validated.push(StoragePolicy::new_replication(0, LEGACY_POLICY_NAME)?);
        }

        // at least one policy must be enabled
        if validated.iter().all(|p| p.is_deprecated) {
            return Err(PolicyError::new(
                "Unable to find policy that's not deprecated!",
            ));
        }

        // if needed, specify default
        let default_idx = match default_idx {
            Some(idx) => idx,
            None => {
                if validated.len() > 1 {
                    return Err(PolicyError::new("Unable to find default policy"));
                }
                validated[0].is_default = true;
                validated[0].idx
            }
        };

        Ok(StoragePolicyCollection {
            policies: validated,
            default_idx,
        })
    }

    pub fn len(&self) -> usize {
        self.policies.len()
    }

    pub fn is_empty(&self) -> bool {
        self.policies.is_empty()
    }

    /// Iterate policies in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = &StoragePolicy> {
        self.policies.iter()
    }

    /// The default policy.
    pub fn default_policy(&self) -> &StoragePolicy {
        self.get_by_index_num(self.default_idx).unwrap()
    }

    /// Find a policy by name or alias (case-insensitive).
    pub fn get_by_name(&self, name: &str) -> Option<&StoragePolicy> {
        self.policies
            .iter()
            .find(|p| p.alias_list.iter().any(|n| n.eq_ignore_ascii_case(name)))
    }

    /// Find a policy by numeric index.
    pub fn get_by_index_num(&self, idx: u32) -> Option<&StoragePolicy> {
        self.policies.iter().find(|p| p.idx == idx)
    }

    /// Find a policy by an index taken from a header value: `None` or an
    /// empty string means 0; an unparseable index yields `None`.
    pub fn get_by_index(&self, index: Option<&str>) -> Option<&StoragePolicy> {
        let idx = match index {
            None | Some("") => 0,
            Some(s) => s.trim().parse().ok()?,
        };
        self.get_by_index_num(idx)
    }

    /// Find a policy by a value that may be a name or an index; errors if
    /// both match but disagree (Python `get_by_name_or_index`).
    pub fn get_by_name_or_index(
        &self,
        name_or_index: &str,
    ) -> Result<Option<&StoragePolicy>, PolicyError> {
        let by_name = self.get_by_name(name_or_index);
        let by_index = self.get_by_index(Some(name_or_index));
        if let (Some(n), Some(i)) = (by_name, by_index) {
            if n.idx != i.idx {
                return Err(PolicyError::new(format!(
                    "Found different polices when searching by name ({}) \
                     and by index ({})",
                    n.idx, i.idx
                )));
            }
        }
        Ok(by_name.or(by_index))
    }

    /// The legacy policy (index 0).
    pub fn legacy(&self) -> Option<&StoragePolicy> {
        self.get_by_index(None)
    }

    /// Encode a policy index into a file/directory name (Python
    /// `get_policy_string`). `policy_or_index=None` means the legacy
    /// policy 0.
    pub fn get_policy_string(
        &self,
        base: &str,
        index: Option<&str>,
    ) -> Result<String, PolicyError> {
        let policy = self.get_by_index(index).ok_or_else(|| {
            PolicyError(format!(
                "Unknown policy, for index {:?}",
                index.unwrap_or("")
            ))
        })?;
        Ok(get_zero_indexed_base_string(base, policy.idx))
    }

    /// Decode a base name and policy from a file/directory name (Python
    /// `split_policy_string`).
    pub fn split_policy_string<'a>(
        &self,
        policy_string: &'a str,
    ) -> Result<(&'a str, &StoragePolicy), PolicyError> {
        let (base, policy_index) = match policy_string.rfind('-') {
            Some(pos) => (&policy_string[..pos], Some(&policy_string[pos + 1..])),
            None => (policy_string, None),
        };
        let unknown = || {
            PolicyError(format!(
                "Unknown policy, for index {:?}",
                policy_index.unwrap_or("")
            ))
        };
        let policy = self.get_by_index(policy_index);
        // round-trip check: the reconstructed string must match
        let reconstructed = get_zero_indexed_base_string(base, policy.map_or(0, |p| p.idx));
        if policy.is_none() || reconstructed != policy_string {
            return Err(unknown());
        }
        Ok((base, policy.unwrap()))
    }

    /// Add one or more alias names to a policy (Python
    /// `add_policy_alias`).
    pub fn add_policy_alias(
        &mut self,
        policy_index: u32,
        aliases: &[&str],
    ) -> Result<(), PolicyError> {
        for alias in aliases {
            if let Some(existing) = self.get_by_name(alias) {
                return Err(PolicyError::new(format!(
                    "Duplicate name {} in use by policy {}",
                    alias, existing.idx
                )));
            }
            let policy = self
                .policies
                .iter_mut()
                .find(|p| p.idx == policy_index)
                .ok_or_else(|| PolicyError::new(format!("No policy with index {policy_index}")))?;
            policy.add_name(alias)?;
        }
        Ok(())
    }

    /// Remove one or more alias names (Python `remove_policy_alias`). If
    /// a primary name is removed the next alias becomes primary.
    pub fn remove_policy_alias(&mut self, aliases: &[&str]) -> Result<(), PolicyError> {
        for alias in aliases {
            let Some(pos) = self
                .policies
                .iter()
                .position(|p| p.alias_list.iter().any(|n| n.eq_ignore_ascii_case(alias)))
            else {
                return Err(PolicyError::new(format!(
                    "No policy with name {alias} exists."
                )));
            };
            let policy = &mut self.policies[pos];
            if policy.alias_list.len() == 1 {
                return Err(PolicyError::new(format!(
                    "Policy {} with name {} has only one name. Policies \
                     must have at least one name.",
                    policy.idx, alias
                )));
            }
            policy.remove_name(alias)?;
        }
        Ok(())
    }

    /// Change the primary name of a policy (Python
    /// `change_policy_primary_name`).
    pub fn change_policy_primary_name(
        &mut self,
        policy_index: u32,
        new_name: &str,
    ) -> Result<(), PolicyError> {
        if let Some(taken) = self.get_by_name(new_name) {
            if taken.idx != policy_index {
                return Err(PolicyError::new(format!(
                    "Other policy {} with name {} exists.",
                    taken.idx, new_name
                )));
            }
        }
        let policy = self
            .policies
            .iter_mut()
            .find(|p| p.idx == policy_index)
            .ok_or_else(|| PolicyError::new(format!("No policy with index {policy_index}")))?;
        policy.change_primary_name(new_name)
    }
}

/// Parse storage policies from a parsed `swift.conf` (Python
/// `parse_storage_policies`). Remember that Python reads `swift.conf`
/// with `strict=False`; use [`SwiftConfig::parse_lenient`] /
/// [`SwiftConfig::read_path_lenient`] for full fidelity.
pub fn parse_storage_policies(conf: &SwiftConfig) -> Result<StoragePolicyCollection, PolicyError> {
    let mut policies = Vec::new();
    for section in conf.section_names() {
        let Some(policy_index) = section.strip_prefix("storage-policy:") else {
            continue;
        };
        let options = conf
            .items(section)
            .map_err(|e| PolicyError::new(e.to_string()))?;
        policies.push(StoragePolicy::from_config(policy_index, &options)?);
    }
    StoragePolicyCollection::new(policies)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn collection(conf: &str) -> Result<StoragePolicyCollection, PolicyError> {
        let config = SwiftConfig::parse_lenient(conf, &[], false).unwrap();
        parse_storage_policies(&config)
    }

    #[test]
    fn test_quorum_size() {
        assert_eq!(quorum_size(1.0), 1);
        assert_eq!(quorum_size(2.0), 1);
        assert_eq!(quorum_size(3.0), 2);
        assert_eq!(quorum_size(4.0), 2);
        assert_eq!(quorum_size(5.0), 3);
        // fractional replica counts
        assert_eq!(quorum_size(3.5), 2);
    }

    #[test]
    fn test_defaults_when_no_policies_defined() {
        let c = collection("[swift-hash]\nfoo = bar\n").unwrap();
        assert_eq!(c.len(), 1);
        let p = c.default_policy();
        assert_eq!(p.idx(), 0);
        assert_eq!(p.name(), "Policy-0");
        assert!(p.is_default);
        assert!(!p.is_deprecated);
        assert_eq!(p.ring_name(), "object");
        assert_eq!(p.policy_type(), REPL_POLICY);
        assert_eq!(c.legacy().unwrap().idx(), 0);
    }

    #[test]
    fn test_parse_multiple_policies() {
        let c = collection(
            "\
[storage-policy:0]
name = zero
aliases = one-for-all, Zed

[storage-policy:5]
name = five
default = yes
deprecated = no

[storage-policy:6]
name = six
deprecated = yes
",
        )
        .unwrap();
        assert_eq!(c.len(), 3);
        assert_eq!(c.default_policy().name(), "five");
        assert_eq!(c.get_by_name("zero").unwrap().idx(), 0);
        // aliases and case-insensitive lookup
        assert_eq!(c.get_by_name("ONE-FOR-ALL").unwrap().idx(), 0);
        assert_eq!(c.get_by_name("zed").unwrap().idx(), 0);
        assert_eq!(
            c.get_by_index_num(0).unwrap().aliases(),
            "zero, one-for-all, Zed"
        );
        // ring names
        assert_eq!(c.get_by_index_num(5).unwrap().ring_name(), "object-5");
        assert!(c.get_by_index_num(6).unwrap().is_deprecated);
        // header-style index lookups
        assert_eq!(c.get_by_index(Some("5")).unwrap().name(), "five");
        assert_eq!(c.get_by_index(Some("")).unwrap().idx(), 0);
        assert_eq!(c.get_by_index(None).unwrap().idx(), 0);
        assert!(c.get_by_index(Some("bad")).is_none());
        assert!(c.get_by_index(Some("7")).is_none());
    }

    #[test]
    fn test_ec_policy() {
        let c = collection(
            "\
[storage-policy:0]
name = zero

[storage-policy:1]
name = ec10-4
policy_type = erasure_coding
ec_type = liberasurecode_rs_vand
ec_num_data_fragments = 10
ec_num_parity_fragments = 4
default = yes
",
        )
        .unwrap();
        let p = c.get_by_index_num(1).unwrap();
        assert_eq!(p.policy_type(), EC_POLICY);
        let ec = p.ec().unwrap();
        assert_eq!(ec.ec_ndata, 10);
        assert_eq!(ec.ec_nparity, 4);
        assert_eq!(ec.ec_segment_size, DEFAULT_EC_OBJECT_SEGMENT_SIZE);
        assert_eq!(ec.ec_duplication_factor, 1);
        assert_eq!(ec.ec_n_unique_fragments(), 14);
        assert_eq!(ec.ec_scheme_description(), "liberasurecode_rs_vand 10+4");
        assert_eq!(p.diskfile_module(), "egg:swift#erasure_coding.fs");
        // RS quorum: ndata + 1
        assert_eq!(p.quorum(14.0), 11);
        // ring replica validation
        assert!(p.validate_ring_replica_count(14.0).is_ok());
        assert!(p.validate_ring_replica_count(15.0).is_err());
        // backend index wraps at unique fragment count
        assert_eq!(p.get_backend_index(3), Some(3));
        assert_eq!(p.get_backend_index(15), Some(1));
        assert_eq!(c.get_by_index_num(0).unwrap().get_backend_index(3), None);
    }

    #[test]
    fn test_ec_duplication_and_flat_xor_quorum() {
        let c = collection(
            "\
[storage-policy:0]
name = zero
default = yes

[storage-policy:1]
name = dup
policy_type = erasure_coding
ec_type = jerasure_rs_vand
ec_num_data_fragments = 4
ec_num_parity_fragments = 2
ec_duplication_factor = 2

[storage-policy:2]
name = xored
policy_type = erasure_coding
ec_type = flat_xor_hd_3
ec_num_data_fragments = 6
ec_num_parity_fragments = 3
",
        )
        .unwrap();
        let dup = c.get_by_index_num(1).unwrap();
        assert_eq!(dup.ec().unwrap().ec_duplication_factor, 2);
        // (4 + 1) * 2
        assert_eq!(dup.quorum(12.0), 10);
        assert!(dup.validate_ring_replica_count(12.0).is_ok());
        // flat_xor_hd_3 needs hd-1 = 2 parity fragments
        assert_eq!(c.get_by_index_num(2).unwrap().quorum(9.0), 8);
    }

    #[test]
    fn test_ec_validation_errors() {
        // missing ec_type
        assert!(collection(
            "[storage-policy:0]\nname = ec\npolicy_type = erasure_coding\n\
             ec_num_data_fragments = 10\nec_num_parity_fragments = 4\n"
        )
        .unwrap_err()
        .0
        .contains("Missing ec_type"));
        // bogus ec_type
        assert!(collection(
            "[storage-policy:0]\nname = ec\npolicy_type = erasure_coding\n\
             ec_type = bogus\nec_num_data_fragments = 10\n\
             ec_num_parity_fragments = 4\n"
        )
        .unwrap_err()
        .0
        .contains("Wrong ec_type"));
        // non-positive fragment counts
        assert!(collection(
            "[storage-policy:0]\nname = ec\npolicy_type = erasure_coding\n\
             ec_type = liberasurecode_rs_vand\nec_num_data_fragments = 0\n\
             ec_num_parity_fragments = 4\n"
        )
        .unwrap_err()
        .0
        .contains("Invalid ec_num_data_fragments"));
        // isa_l_rs_vand with >= 5 parity must be deprecated
        assert!(collection(
            "[storage-policy:0]\nname = zero\ndefault = yes\n\
             [storage-policy:1]\nname = unsafe\npolicy_type = erasure_coding\n\
             ec_type = isa_l_rs_vand\nec_num_data_fragments = 10\n\
             ec_num_parity_fragments = 5\n"
        )
        .unwrap_err()
        .0
        .contains("MUST be deprecated"));
        // ...deprecating it is accepted
        assert!(collection(
            "[storage-policy:0]\nname = zero\ndefault = yes\n\
             [storage-policy:1]\nname = unsafe\npolicy_type = erasure_coding\n\
             ec_type = isa_l_rs_vand\nec_num_data_fragments = 10\n\
             ec_num_parity_fragments = 5\ndeprecated = yes\n"
        )
        .is_ok());
    }

    #[test]
    fn test_collection_validation_errors() {
        // duplicate index
        assert!(collection(
            "[storage-policy:0]\nname = a\ndefault = yes\n\
             [storage-policy:00]\nname = b\n"
        )
        .unwrap_err()
        .0
        .contains("Duplicate index"));
        // duplicate name (case-insensitive)
        assert!(collection(
            "[storage-policy:0]\nname = dup\ndefault = yes\n\
             [storage-policy:1]\nname = DUP\n"
        )
        .unwrap_err()
        .0
        .contains("Duplicate name"));
        // multiple defaults
        assert!(collection(
            "[storage-policy:0]\nname = a\ndefault = yes\n\
             [storage-policy:1]\nname = b\ndefault = yes\n"
        )
        .unwrap_err()
        .0
        .contains("Duplicate default"));
        // no default among multiple policies
        assert!(
            collection("[storage-policy:0]\nname = a\n[storage-policy:1]\nname = b\n")
                .unwrap_err()
                .0
                .contains("Unable to find default")
        );
        // missing policy 0 with other policies defined
        assert!(
            collection("[storage-policy:1]\nname = one\ndefault = yes\n")
                .unwrap_err()
                .0
                .contains("policy index 0")
        );
        // all deprecated
        assert!(
            collection("[storage-policy:0]\nname = a\ndeprecated = yes\n")
                .unwrap_err()
                .0
                .contains("not deprecated")
        );
        // deprecated default
        assert!(
            collection("[storage-policy:0]\nname = a\ndefault = yes\ndeprecated = yes\n")
                .unwrap_err()
                .0
                .contains("Deprecated policy can not be default")
        );
        // bad name characters
        assert!(
            collection("[storage-policy:0]\nname = spaces not allowed\n")
                .unwrap_err()
                .0
                .contains("Invalid name")
        );
        // Policy-0 reserved for index 0
        assert!(collection(
            "[storage-policy:0]\nname = zero\ndefault = yes\n\
             [storage-policy:1]\nname = policy-0\n"
        )
        .unwrap_err()
        .0
        .contains("reserved"));
        // negative / bad index
        assert!(collection("[storage-policy:-1]\nname = a\n")
            .unwrap_err()
            .0
            .contains("Invalid index"));
        // unknown option
        assert!(collection("[storage-policy:0]\nname = a\nbert = ernie\n")
            .unwrap_err()
            .0
            .contains("Invalid option"));
        // unknown policy type
        assert!(
            collection("[storage-policy:0]\nname = a\npolicy_type = lazy\n")
                .unwrap_err()
                .0
                .contains("Invalid type")
        );
        // EC option on a replication policy is invalid
        assert!(collection("[storage-policy:0]\nname = a\nec_type = rs\n")
            .unwrap_err()
            .0
            .contains("Invalid option"));
    }

    #[test]
    fn test_policy_strings() {
        let c = collection(
            "[storage-policy:0]\nname = zero\n\
             [storage-policy:1]\nname = one\ndefault = yes\n",
        )
        .unwrap();
        assert_eq!(c.get_policy_string("objects", None).unwrap(), "objects");
        assert_eq!(
            c.get_policy_string("objects", Some("1")).unwrap(),
            "objects-1"
        );
        assert!(c.get_policy_string("objects", Some("7")).is_err());

        let (base, policy) = c.split_policy_string("objects").unwrap();
        assert_eq!((base, policy.idx()), ("objects", 0));
        let (base, policy) = c.split_policy_string("objects-1").unwrap();
        assert_eq!((base, policy.idx()), ("objects", 1));
        // index 0 is never spelled out
        assert!(c.split_policy_string("objects-0").is_err());
        // unknown index
        assert!(c.split_policy_string("objects-7").is_err());
        // non-numeric suffix that is not a policy
        assert!(c.split_policy_string("objects-foo").is_err());
        // round trip
        for s in ["async_pending", "async_pending-1", "tmp", "tmp-1"] {
            let (base, policy) = c.split_policy_string(s).unwrap();
            assert_eq!(
                c.get_policy_string(base, Some(&policy.idx().to_string()))
                    .unwrap(),
                s
            );
        }
    }

    #[test]
    fn test_alias_management() {
        let mut c = collection(
            "[storage-policy:0]\nname = zero\naliases = z\n\
             [storage-policy:1]\nname = one\ndefault = yes\n",
        )
        .unwrap();
        c.add_policy_alias(1, &["uno", "tahi"]).unwrap();
        assert_eq!(c.get_by_name("uno").unwrap().idx(), 1);
        // duplicate alias rejected
        assert!(c.add_policy_alias(1, &["zero"]).is_err());
        // remove alias; primary survives
        c.remove_policy_alias(&["tahi"]).unwrap();
        assert!(c.get_by_name("tahi").is_none());
        // removing a primary name promotes the next alias
        c.change_policy_primary_name(1, "uno").unwrap();
        assert_eq!(c.get_by_index_num(1).unwrap().name(), "uno");
        // can't take a name owned by another policy
        assert!(c.change_policy_primary_name(1, "zero").is_err());
        // can't remove the only name
        assert!(c.remove_policy_alias(&["z", "zero"]).is_err());
    }

    #[test]
    fn test_get_by_name_or_index() {
        let c = collection(
            "[storage-policy:0]\nname = zero\n\
             [storage-policy:1]\nname = one\ndefault = yes\n",
        )
        .unwrap();
        assert_eq!(c.get_by_name_or_index("one").unwrap().unwrap().idx(), 1);
        assert_eq!(c.get_by_name_or_index("0").unwrap().unwrap().idx(), 0);
        assert!(c.get_by_name_or_index("nope").unwrap().is_none());
        // a policy named "1" that is not policy 1 would conflict
        let c = collection(
            "[storage-policy:0]\nname = zero\n\
             [storage-policy:1]\nname = one\ndefault = yes\n\
             [storage-policy:2]\nname = 1\n",
        );
        // note: such a config is actually constructible; the conflict
        // surfaces on lookup
        let c = c.unwrap();
        assert!(c.get_by_name_or_index("1").is_err());
    }

    #[test]
    fn test_lenient_duplicate_sections() {
        // Python reads swift.conf with strict=False: duplicate options
        // take the last value
        let c =
            collection("[storage-policy:0]\nname = zero\nname = zilch\ndefault = yes\n").unwrap();
        assert_eq!(c.get_by_index_num(0).unwrap().name(), "zilch");
    }
}
