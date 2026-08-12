// Copyright (c) 2026 OpenStack Foundation
//! Cold-tier / Glacier-like storage-policy transition **policy map + meta stamps**.
//!
//! # Honest boundary
//!
//! **Physical cold backend is not implemented.** This module is a policy map
//! and metadata-stamp helper only. Lifecycle Transition stamps (see
//! [`crate::lifecycle_exec`]) mark objects as intending a cold class. Helpers
//! here can prepare headers an *external* mover would need:
//!
//! 1. Map S3 StorageClass → Swift storage-policy index (`cold_policy_map`).
//! 2. On due transition: stamp backend policy index + cold object path meta.
//! 3. Restore: temporary rehydrate window via [`SYS_RESTORE_UNTIL`] plus
//!    optional policy index restore target.
//!
//! It does **not** copy object bytes between policies, schedule a mover, talk
//! to tape/Glacier, or guarantee later proxy reads honor per-object policy
//! metadata. Proxy may populate [`ColdPolicyMap`] from conf; that still does
//! not implement a physical cold store. Python Swift 2.33 rejects direct
//! non-`STANDARD` storage classes and `?restore`. Do not claim physical cold
//! media from this crate.

use std::collections::HashMap;

use swift_http::HeaderKeyDict;

use crate::lifecycle_exec::{
    is_cold_storage_class, META_STORAGE_CLASS, SYS_RESTORE_UNTIL, SYS_TRANSITIONED,
    SYS_TRANSITION_AT,
};

/// Sysmeta: storage policy index of the cold tier holding object bytes.
pub const SYS_COLD_POLICY_INDEX: &str = "X-Object-Sysmeta-S3-Cold-Policy-Index";
/// Sysmeta: original (hot) storage policy index before transition.
pub const SYS_HOT_POLICY_INDEX: &str = "X-Object-Sysmeta-S3-Hot-Policy-Index";
/// Sysmeta: backend path hint for tape/glacier adapters (opaque).
pub const SYS_COLD_BACKEND_URI: &str = "X-Object-Sysmeta-S3-Cold-Backend-Uri";
/// Request header used by proxy to force object server policy selection.
pub const HDR_BACKEND_STORAGE_POLICY_INDEX: &str = "X-Backend-Storage-Policy-Index";

/// Maps S3 storage class names → Swift storage policy indices.
#[derive(Debug, Clone, Default)]
pub struct ColdPolicyMap {
    /// Uppercase class → policy index.
    pub class_to_policy: HashMap<String, i64>,
    /// Default cold policy when class unmapped but still cold (optional).
    pub default_cold_policy: Option<i64>,
    /// Hot/default policy for restore target.
    pub default_hot_policy: i64,
}

impl ColdPolicyMap {
    pub fn new() -> Self {
        Self {
            class_to_policy: HashMap::new(),
            default_cold_policy: None,
            default_hot_policy: 0,
        }
    }

    /// Parse conf: `GLACIER:2,DEEP_ARCHIVE:3` plus optional defaults.
    pub fn from_csv(csv: &str) -> Self {
        let mut m = Self::new();
        for part in csv.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if let Some((k, v)) = part.split_once(':') {
                let k = k.trim().to_ascii_uppercase();
                if let Ok(idx) = v.trim().parse::<i64>() {
                    if k == "DEFAULT" || k == "*" {
                        m.default_cold_policy = Some(idx);
                    } else if k == "HOT" || k == "STANDARD" {
                        m.default_hot_policy = idx;
                    } else {
                        m.class_to_policy.insert(k, idx);
                    }
                }
            }
        }
        m
    }

    pub fn policy_for_class(&self, storage_class: &str) -> Option<i64> {
        let key = storage_class.trim().to_ascii_uppercase();
        self.class_to_policy
            .get(&key)
            .copied()
            .or(self.default_cold_policy)
    }

    pub fn is_configured(&self) -> bool {
        !self.class_to_policy.is_empty() || self.default_cold_policy.is_some()
    }
}

/// Metadata-stamp result only — **not** proof that bytes moved to cold media.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhysicalTransition {
    pub storage_class: String,
    pub cold_policy_index: i64,
    pub hot_policy_index: i64,
    pub backend_uri: String,
}

/// Stamp cold-transition **metadata** when a policy map is configured.
///
/// Sets [`SYS_TRANSITIONED`], cold/hot policy indices, a URI *hint*, and
/// `X-Backend-Storage-Policy-Index`. Does **not** move object bytes or invoke
/// a physical cold backend (none is implemented). Returns `None` if class is
/// not cold or no policy mapping exists.
pub fn apply_physical_transition(
    headers: &mut HeaderKeyDict,
    map: &ColdPolicyMap,
    storage_class: &str,
    hot_policy_index: Option<i64>,
    object_account: &str,
    object_container: &str,
    object_key: &str,
) -> Option<PhysicalTransition> {
    if !is_cold_storage_class(storage_class) {
        return None;
    }
    let cold = map.policy_for_class(storage_class)?;
    let hot = hot_policy_index.unwrap_or(map.default_hot_policy);
    let uri = format!("swift-policy://{cold}/{object_account}/{object_container}/{object_key}");
    headers.set(META_STORAGE_CLASS, storage_class);
    headers.set(SYS_TRANSITIONED, "1");
    headers.set(SYS_COLD_POLICY_INDEX, cold.to_string());
    headers.set(SYS_HOT_POLICY_INDEX, hot.to_string());
    headers.set(SYS_COLD_BACKEND_URI, &uri);
    headers.set(HDR_BACKEND_STORAGE_POLICY_INDEX, cold.to_string());
    Some(PhysicalTransition {
        storage_class: storage_class.to_string(),
        cold_policy_index: cold,
        hot_policy_index: hot,
        backend_uri: uri,
    })
}

/// If transition is due and a policy map is configured, prepare **meta** stamps only.
pub fn maybe_physicalize_due_transition(
    headers: &mut HeaderKeyDict,
    map: &ColdPolicyMap,
    now_unix: i64,
    account: &str,
    container: &str,
    key: &str,
) -> Option<PhysicalTransition> {
    if !map.is_configured() {
        return None;
    }
    let sc = headers
        .get(META_STORAGE_CLASS)
        .or_else(|| headers.get("X-Object-Meta-Storage-Class"))?
        .to_string();
    if !is_cold_storage_class(&sc) {
        return None;
    }
    // Due?
    let due = if let Some(at_s) = headers.get(SYS_TRANSITION_AT) {
        at_s.parse::<i64>()
            .ok()
            .map(|at| at <= now_unix)
            .unwrap_or(false)
    } else {
        headers.get(SYS_TRANSITIONED).is_some()
    };
    if !due && headers.get(SYS_TRANSITIONED).is_none() {
        return None;
    }
    // Already physical?
    if headers.get(SYS_COLD_POLICY_INDEX).is_some() {
        let cold = headers.get(SYS_COLD_POLICY_INDEX)?.parse().ok()?;
        let hot = headers
            .get(SYS_HOT_POLICY_INDEX)
            .and_then(|s| s.parse().ok())
            .unwrap_or(map.default_hot_policy);
        return Some(PhysicalTransition {
            storage_class: sc,
            cold_policy_index: cold,
            hot_policy_index: hot,
            backend_uri: headers.get(SYS_COLD_BACKEND_URI).unwrap_or("").to_string(),
        });
    }
    apply_physical_transition(headers, map, &sc, None, account, container, key)
}

/// Apply restore **stamps**: set restore-until and optionally route GETs to hot
/// policy index during the window. Does not rehydrate bytes from cold media.
pub fn apply_physical_restore(
    headers: &mut HeaderKeyDict,
    map: &ColdPolicyMap,
    days: i64,
    now_unix: i64,
) {
    let until = now_unix.saturating_add(days.saturating_mul(86_400).max(0));
    headers.set(SYS_RESTORE_UNTIL, until.to_string());
    let hot = headers
        .get(SYS_HOT_POLICY_INDEX)
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(map.default_hot_policy);
    // During restore window, serve from hot policy if rehydrated; operators
    // may async-copy. Stamp backend index to hot for GET routing.
    headers.set(HDR_BACKEND_STORAGE_POLICY_INDEX, hot.to_string());
}

/// Policy index the object server should use for a read.
///
/// Cold + not restored → cold policy (GET may still be blocked by
/// [`crate::lifecycle_exec::transition_blocks_get`]). Restored → hot.
pub fn read_policy_index(
    headers: &HeaderKeyDict,
    map: &ColdPolicyMap,
    now_unix: i64,
) -> Option<i64> {
    let cold = headers
        .get(SYS_COLD_POLICY_INDEX)
        .and_then(|s| s.parse().ok());
    let hot = headers
        .get(SYS_HOT_POLICY_INDEX)
        .and_then(|s| s.parse().ok())
        .unwrap_or(map.default_hot_policy);
    let restored = headers
        .get(SYS_RESTORE_UNTIL)
        .and_then(|s| s.parse::<i64>().ok())
        .map(|u| u > now_unix)
        .unwrap_or(false);
    if restored {
        Some(hot)
    } else {
        cold.or(Some(hot))
    }
}

/// Tape / glacier adapter trait (LAB product boundary).
pub trait ColdBackend: Send + Sync {
    /// Archive object bytes to cold media; return backend URI.
    fn archive(
        &self,
        policy_index: i64,
        account: &str,
        container: &str,
        key: &str,
        body: &[u8],
    ) -> Result<String, String>;
    /// Stage restore from cold media into hot policy path.
    fn restore_stage(&self, backend_uri: &str, days: i64) -> Result<(), String>;
}

/// In-process lab backend: stores archived blobs in memory (tests / SAIO).
#[derive(Debug, Default)]
pub struct MemoryColdBackend {
    pub blobs: std::sync::Mutex<HashMap<String, Vec<u8>>>,
}

impl ColdBackend for MemoryColdBackend {
    fn archive(
        &self,
        policy_index: i64,
        account: &str,
        container: &str,
        key: &str,
        body: &[u8],
    ) -> Result<String, String> {
        let uri = format!("memory://{policy_index}/{account}/{container}/{key}");
        self.blobs
            .lock()
            .map_err(|e| e.to_string())?
            .insert(uri.clone(), body.to_vec());
        Ok(uri)
    }

    fn restore_stage(&self, backend_uri: &str, _days: i64) -> Result<(), String> {
        let guard = self.blobs.lock().map_err(|e| e.to_string())?;
        if guard.contains_key(backend_uri) {
            Ok(())
        } else {
            Err(format!("unknown backend uri {backend_uri}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_map_and_physical_transition() {
        let map = ColdPolicyMap::from_csv("GLACIER:2,DEEP_ARCHIVE:3,HOT:0");
        assert_eq!(map.policy_for_class("glacier"), Some(2));
        assert_eq!(map.default_hot_policy, 0);
        let mut h = HeaderKeyDict::new();
        let t = apply_physical_transition(
            &mut h,
            &map,
            "GLACIER",
            Some(0),
            "AUTH_test",
            "bucket",
            "obj",
        )
        .unwrap();
        assert_eq!(t.cold_policy_index, 2);
        assert_eq!(h.get(SYS_TRANSITIONED), Some("1"));
        assert_eq!(h.get(SYS_COLD_POLICY_INDEX), Some("2"));
        assert_eq!(h.get(HDR_BACKEND_STORAGE_POLICY_INDEX), Some("2"));
    }

    #[test]
    fn restore_routes_to_hot() {
        let map = ColdPolicyMap::from_csv("GLACIER:2,HOT:0");
        let mut h = HeaderKeyDict::new();
        apply_physical_transition(&mut h, &map, "GLACIER", Some(0), "a", "c", "k").unwrap();
        apply_physical_restore(&mut h, &map, 1, 1000);
        assert_eq!(read_policy_index(&h, &map, 1000), Some(0));
        assert_eq!(read_policy_index(&h, &map, 1000 + 86_400 + 1), Some(2));
    }

    #[test]
    fn memory_backend_archive_restore() {
        let be = MemoryColdBackend::default();
        let uri = be.archive(2, "a", "c", "k", b"payload").unwrap();
        assert!(uri.starts_with("memory://"));
        be.restore_stage(&uri, 1).unwrap();
        assert!(be.restore_stage("memory://missing", 1).is_err());
    }

    #[test]
    fn unmapped_class_no_physical() {
        let map = ColdPolicyMap::new();
        let mut h = HeaderKeyDict::new();
        assert!(apply_physical_transition(&mut h, &map, "GLACIER", None, "a", "c", "k").is_none());
    }
}
