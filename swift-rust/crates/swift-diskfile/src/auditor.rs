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

//! The object auditor core, ported from the audit path of
//! `swift/obj/auditor.py` + `object_audit_location_generator`: walk a
//! device's object tree, open each object, read it fully through the
//! reader (which verifies size and ETag and quarantines on mismatch),
//! and report the tally.
//!
//! The continuous daemon loop lives in `swift-object-auditor` (conf +
//! interval sleep, matching Python `ObjectAuditor.interval` default 30s).
//! Deferred: rate limiting, `hashes.pkl`-driven incremental audits, ZBF
//! (zero-byte-file) mode, and watcher plugins.

use std::path::{Path, PathBuf};

use swift_core::hashing::HashPathConfig;

use crate::diskfile::{DiskFile, DiskFileConfig};
use crate::error::DiskFileError;
use crate::layout::get_data_dir;
use crate::naming::PolicyKind;

/// Result of an audit pass over a device.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AuditReport {
    pub passed: u64,
    pub quarantined: u64,
    pub errors: u64,
    /// Hash-dir paths that were quarantined.
    pub quarantined_paths: Vec<PathBuf>,
}

/// `object_audit_location_generator`: yield every object hash directory
/// under `<device>/objects[-N]/<part>/<suffix>/<hash>`.
pub fn audit_locations(device_path: &Path, policy_index: u32) -> Vec<PathBuf> {
    let datadir = device_path.join(get_data_dir(policy_index));
    let mut out = Vec::new();
    let Ok(parts) = std::fs::read_dir(&datadir) else {
        return out;
    };
    for part in parts.flatten() {
        if !part.path().is_dir() {
            continue;
        }
        let Ok(suffixes) = std::fs::read_dir(part.path()) else {
            continue;
        };
        for suffix in suffixes.flatten() {
            let name = suffix.file_name();
            let name = name.to_string_lossy();
            if name.len() != 3 || !suffix.path().is_dir() {
                continue;
            }
            let Ok(hashes) = std::fs::read_dir(suffix.path()) else {
                continue;
            };
            for hash in hashes.flatten() {
                if hash.path().is_dir() {
                    out.push(hash.path());
                }
            }
        }
    }
    out.sort();
    out
}

/// Audit one object hash directory: open the diskfile, stream it through
/// the reader (which quarantines on size/ETag mismatch), and classify.
pub fn audit_object(
    device_path: &Path,
    hash_dir: &Path,
    policy: PolicyKind,
    policy_index: u32,
    hash_config: &HashPathConfig,
    cfg: &DiskFileConfig,
) -> AuditOutcome {
    let mut df = DiskFile::from_hash_dir(
        device_path,
        hash_dir,
        policy,
        policy_index,
        hash_config,
        cfg.clone(),
    );
    match df.open(None) {
        // no live object here (tombstone-only / empty) — nothing to audit
        Err(DiskFileError::NotExist) | Err(DiskFileError::Deleted { .. }) => AuditOutcome::Skipped,
        Err(DiskFileError::Quarantined(_)) => AuditOutcome::Quarantined,
        Err(_) => AuditOutcome::Error,
        Ok(_) => {
            let mut reader = match df.reader() {
                Ok(r) => r,
                Err(_) => return AuditOutcome::Error,
            };
            if reader.read_all().is_err() {
                return AuditOutcome::Error;
            }
            match reader.close() {
                Ok(()) => AuditOutcome::Passed,
                Err(DiskFileError::Quarantined(_)) => AuditOutcome::Quarantined,
                Err(_) => AuditOutcome::Error,
            }
        }
    }
}

/// Per-object audit result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditOutcome {
    Passed,
    Quarantined,
    Skipped,
    Error,
}

/// Audit every object on a device for one policy.
pub fn audit_device(
    device_path: &Path,
    policy: PolicyKind,
    policy_index: u32,
    hash_config: &HashPathConfig,
    cfg: &DiskFileConfig,
) -> AuditReport {
    let mut report = AuditReport::default();
    for hash_dir in audit_locations(device_path, policy_index) {
        match audit_object(
            device_path,
            &hash_dir,
            policy,
            policy_index,
            hash_config,
            cfg,
        ) {
            AuditOutcome::Passed => report.passed += 1,
            AuditOutcome::Quarantined => {
                report.quarantined += 1;
                report.quarantined_paths.push(hash_dir);
            }
            AuditOutcome::Error => report.errors += 1,
            AuditOutcome::Skipped => {}
        }
    }
    report
}

impl AuditReport {
    /// Merge another device/policy report into this one.
    pub fn merge(&mut self, other: AuditReport) {
        self.passed += other.passed;
        self.quarantined += other.quarantined;
        self.errors += other.errors;
        self.quarantined_paths.extend(other.quarantined_paths);
    }
}

/// List local storage devices under `devices_root` (Python `devices`).
/// When `mount_check` is true, only mountpoints are included.
pub fn list_devices(devices_root: &Path, mount_check: bool) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(devices_root) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        if mount_check && !is_mountpoint(&path) {
            continue;
        }
        out.push(path);
    }
    out.sort();
    out
}

fn is_mountpoint(path: &Path) -> bool {
    // Best-effort: compare st_dev with parent. Matches Python's common
    // `ismount` check without requiring the `mountpoint` binary.
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    let Some(parent) = path.parent() else {
        return true;
    };
    let Ok(parent_meta) = std::fs::metadata(parent) else {
        return false;
    };
    use std::os::unix::fs::MetadataExt;
    meta.dev() != parent_meta.dev()
}

/// One continuous-auditor pass: every local device × every policy index.
pub fn audit_devices(
    devices_root: &Path,
    mount_check: bool,
    policies: &[(u32, PolicyKind)],
    hash_config: &HashPathConfig,
    cfg: &DiskFileConfig,
) -> AuditReport {
    let mut report = AuditReport::default();
    for device in list_devices(devices_root, mount_check) {
        for &(policy_index, policy) in policies {
            report.merge(audit_device(
                &device,
                policy,
                policy_index,
                hash_config,
                cfg,
            ));
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::MetaValue;

    fn hc() -> HashPathConfig {
        HashPathConfig::new(b"".to_vec(), b"changeme".to_vec()).unwrap()
    }

    #[test]
    fn test_audit_passes_good_and_quarantines_corrupt() {
        let dir = std::env::temp_dir().join(format!("swift-audit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let device = dir.join("sda1");
        std::fs::create_dir_all(&device).unwrap();
        let cfg = DiskFileConfig::default();

        // write a good object
        let good = DiskFile::new(
            &device,
            0,
            "a",
            "c",
            "good",
            PolicyKind::Replication,
            0,
            &hc(),
            cfg.clone(),
        )
        .unwrap();
        let body = b"healthy object";
        let etag = {
            use md5::{Digest, Md5};
            format!("{:x}", Md5::digest(body))
        };
        let meta: crate::metadata::Metadata = vec![
            (
                "X-Timestamp".into(),
                MetaValue::Str("3286000000.00000".into()),
            ),
            ("Content-Type".into(), "text/plain".into()),
            ("ETag".into(), MetaValue::Str(etag)),
            (
                "Content-Length".into(),
                MetaValue::Str(body.len().to_string()),
            ),
        ];
        let mut w = good.create(".data").unwrap();
        w.write(body).unwrap();
        w.put(meta).unwrap();
        w.close();

        // write a corrupt object (etag won't match the on-disk bytes)
        let bad = DiskFile::new(
            &device,
            0,
            "a",
            "c",
            "bad",
            PolicyKind::Replication,
            0,
            &hc(),
            cfg.clone(),
        )
        .unwrap();
        let meta: crate::metadata::Metadata = vec![
            (
                "X-Timestamp".into(),
                MetaValue::Str("3286000000.00000".into()),
            ),
            ("Content-Type".into(), "text/plain".into()),
            (
                "ETag".into(),
                MetaValue::Str("00000000000000000000000000000000".into()),
            ),
            ("Content-Length".into(), MetaValue::Str("7".into())),
        ];
        let mut w = bad.create(".data").unwrap();
        w.write(b"corrupt").unwrap();
        w.put(meta).unwrap();
        w.close();

        let report = audit_device(&device, PolicyKind::Replication, 0, &hc(), &cfg);
        assert_eq!(report.passed, 1, "the good object passes: {report:?}");
        assert_eq!(report.quarantined, 1, "the corrupt object is quarantined");
        // the quarantined object is gone from the object tree
        assert_eq!(audit_locations(&device, 0).len(), 1);

        // Multi-device pass sees the same device under devices_root.
        let multi = audit_devices(&dir, false, &[(0, PolicyKind::Replication)], &hc(), &cfg);
        assert_eq!(multi.passed, 1);
        assert_eq!(list_devices(&dir, false), vec![device]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_list_devices_skips_files() {
        let dir = std::env::temp_dir().join(format!("swift-adev-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sda1")).unwrap();
        std::fs::write(dir.join("notes"), b"x").unwrap();
        let devices = list_devices(&dir, false);
        assert_eq!(devices.len(), 1);
        assert!(devices[0].ends_with("sda1"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
