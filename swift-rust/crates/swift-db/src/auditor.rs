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

//! The account/container DB auditor core, ported from the audit path of
//! `swift/{account,container}/auditor.py`: walk a device's DB tree, open
//! each broker, and confirm `get_info` succeeds (a broken DB fails to
//! open or query). Reports a tally; quarantining of corrupt DBs is left
//! to the daemon (we only classify).
//!
//! The continuous daemon loop lives in `swift-db-auditor` (conf +
//! interval sleep, matching Python `DatabaseAuditor.interval` default
//! 1800s). Deferred: per-row consistency checks and the actual
//! quarantine move.

use std::path::{Path, PathBuf};

use crate::{AccountBroker, ContainerBroker};

/// Result of a DB audit pass.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DbAuditReport {
    pub passed: u64,
    pub failed: u64,
    pub failed_paths: Vec<PathBuf>,
}

/// Find every `<hash>.db` under `<device>/<datadir>/<part>/<suffix>/<hash>/`.

/// Swift container/account hash dirs are MD5 hex (32 chars).
fn is_db_hash_dir(name: &str) -> bool {
    name.len() == 32 && name.bytes().all(|b| b.is_ascii_hexdigit())
}

pub fn db_locations(device_path: &Path, datadir: &str) -> Vec<PathBuf> {
    let root = device_path.join(datadir);
    let mut out = Vec::new();
    let Ok(parts) = std::fs::read_dir(&root) else {
        return out;
    };
    for part in parts.flatten() {
        let Ok(suffixes) = std::fs::read_dir(part.path()) else {
            continue;
        };
        for suffix in suffixes.flatten() {
            if suffix.file_name().to_string_lossy().len() != 3 {
                continue;
            }
            let Ok(hashes) = std::fs::read_dir(suffix.path()) else {
                continue;
            };
            for hash in hashes.flatten() {
                // Python `audit_location_generator` only yields 32-hex
                // hash dirs. `{hash}.tmp` is a renamed-aside replica
                // (deleted_child L4484–L4541) and must not be processed.
                let hash_name = hash.file_name();
                let hash_name = hash_name.to_string_lossy();
                if !is_db_hash_dir(&hash_name) {
                    continue;
                }
                let Ok(files) = std::fs::read_dir(hash.path()) else {
                    continue;
                };
                for f in files.flatten() {
                    let name = f.file_name();
                    if name.to_string_lossy().ends_with(".db") {
                        out.push(f.path());
                    }
                }
            }
        }
    }
    out.sort();
    out
}

/// Audit every container DB on a device.
pub fn audit_container_dbs(device_path: &Path) -> DbAuditReport {
    let mut report = DbAuditReport::default();
    for db in db_locations(device_path, "containers") {
        let mut broker = ContainerBroker::new(&db, "", "");
        match broker.get_info() {
            Ok(_) => report.passed += 1,
            Err(_) => {
                report.failed += 1;
                report.failed_paths.push(db);
            }
        }
    }
    report
}

/// Audit every account DB on a device.
pub fn audit_account_dbs(device_path: &Path) -> DbAuditReport {
    let mut report = DbAuditReport::default();
    for db in db_locations(device_path, "accounts") {
        let mut broker = AccountBroker::new(&db, "");
        match broker.get_info() {
            Ok(_) => report.passed += 1,
            Err(_) => {
                report.failed += 1;
                report.failed_paths.push(db);
            }
        }
    }
    report
}

impl DbAuditReport {
    /// Merge another device report into this one.
    pub fn merge(&mut self, other: DbAuditReport) {
        self.passed += other.passed;
        self.failed += other.failed;
        self.failed_paths.extend(other.failed_paths);
    }
}

/// List local storage devices under `devices_root`.
/// When `mount_check` is true, only mountpoints are included.
pub fn list_db_devices(devices_root: &Path, mount_check: bool) -> Vec<PathBuf> {
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

/// Audit account or container DBs on every local device.
pub fn audit_dbs_on_devices(devices_root: &Path, mount_check: bool, kind: &str) -> DbAuditReport {
    let mut report = DbAuditReport::default();
    for device in list_db_devices(devices_root, mount_check) {
        let one = match kind {
            "account" => audit_account_dbs(&device),
            _ => audit_container_dbs(&device),
        };
        report.merge(one);
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_container_db_audit() {
        let dir = std::env::temp_dir().join(format!("swift-dbaudit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let device = dir.join("sda1");
        // a healthy DB at a hash path
        let hd = device.join("containers/0/abc/00000000000000000000000000000abc");
        std::fs::create_dir_all(&hd).unwrap();
        let good = hd.join("00000000000000000000000000000abc.db");
        let mut b = ContainerBroker::new(&good, "a", "c");
        b.initialize("1751500000.00000", 0, "1751500000.00000", "id")
            .unwrap();
        b.get_info().unwrap();

        // a corrupt DB
        let hd2 = device.join("containers/0/def/00000000000000000000000000000def");
        std::fs::create_dir_all(&hd2).unwrap();
        std::fs::write(hd2.join("00000000000000000000000000000def.db"), b"not a db").unwrap();

        let report = audit_container_dbs(&device);
        assert_eq!(report.passed, 1, "{report:?}");
        assert_eq!(report.failed, 1, "{report:?}");

        let multi = audit_dbs_on_devices(&dir, false, "container");
        assert_eq!(multi.passed, 1);
        assert_eq!(multi.failed, 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_db_locations_skips_renamed_hash_tmp() {
        // deleted_child L4484: sharder/replicator must not see `{hash}.tmp`.
        let dir = std::env::temp_dir().join(format!(
            "swift-hash-tmp-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let device = dir.join("sda1");
        let hsh = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let live = device.join("containers/0").join(&hsh[29..]).join(hsh);
        std::fs::create_dir_all(&live).unwrap();
        let live_db = live.join(format!("{hsh}.db"));
        std::fs::write(&live_db, b"live").unwrap();
        let aside = device
            .join("containers/0")
            .join(&hsh[29..])
            .join(format!("{hsh}.tmp"));
        std::fs::create_dir_all(&aside).unwrap();
        let aside_db = aside.join(format!("{hsh}.db"));
        std::fs::write(&aside_db, b"aside").unwrap();
        let found = db_locations(&device, "containers");
        assert_eq!(found, vec![live_db], "{found:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
