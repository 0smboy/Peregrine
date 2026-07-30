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

//! The relinker core, ported from `swift/cli/relinker.py` +
//! `get_partition_for_hash`/`replace_partition_in_path`: when the
//! partition power increases, hard-link every object file from its old
//! partition directory to the directory for its partition at the new
//! power. Hard links share inodes, so this is cheap and reversible.
//!
//! Deferred: the two-phase relink/cleanup state machine, per-partition
//! progress files, and concurrency; this is the single-pass link step.

use std::path::Path;

use crate::layout::get_data_dir;

/// `get_partition_for_hash`: the partition a hash maps to at `part_power`
/// (the top 32 bits of the hash, big-endian, shifted).
pub fn partition_for_hash(hex_hash: &str, part_power: u32) -> Option<u32> {
    if hex_hash.len() < 8 {
        return None;
    }
    let mut raw = [0u8; 4];
    for i in 0..4 {
        raw[i] = u8::from_str_radix(&hex_hash[i * 2..i * 2 + 2], 16).ok()?;
    }
    let val = u32::from_be_bytes(raw);
    let part_shift = 32 - part_power;
    Some(((val as u64) >> part_shift) as u32)
}

/// Result of a relink pass.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RelinkReport {
    pub hash_dirs: u64,
    pub files_linked: u64,
    pub already_linked: u64,
}

/// Relink every object on a device from the old partition layout to the
/// new (`new_part_power`) layout. Existing links are left in place.
pub fn relink_device(
    device_path: &Path,
    policy_index: u32,
    new_part_power: u32,
) -> std::io::Result<RelinkReport> {
    let datadir = device_path.join(get_data_dir(policy_index));
    let mut report = RelinkReport::default();
    let Ok(parts) = std::fs::read_dir(&datadir) else {
        return Ok(report);
    };
    for part in parts.flatten() {
        if !part.path().is_dir() {
            continue;
        }
        let Ok(suffixes) = std::fs::read_dir(part.path()) else {
            continue;
        };
        for suffix in suffixes.flatten() {
            let suffix_name = suffix.file_name();
            let suffix_name = suffix_name.to_string_lossy();
            if suffix_name.len() != 3 || !suffix.path().is_dir() {
                continue;
            }
            let Ok(hashes) = std::fs::read_dir(suffix.path()) else {
                continue;
            };
            for hash in hashes.flatten() {
                if !hash.path().is_dir() {
                    continue;
                }
                let hash_name = hash.file_name();
                let hash_name = hash_name.to_string_lossy();
                let Some(new_part) = partition_for_hash(&hash_name, new_part_power) else {
                    continue;
                };
                report.hash_dirs += 1;
                // new location: <datadir>/<new_part>/<suffix>/<hash>/
                let new_hash_dir = datadir
                    .join(new_part.to_string())
                    .join(&*suffix_name)
                    .join(&*hash_name);
                std::fs::create_dir_all(&new_hash_dir)?;
                let Ok(files) = std::fs::read_dir(hash.path()) else {
                    continue;
                };
                for f in files.flatten() {
                    let name = f.file_name();
                    let dest = new_hash_dir.join(&name);
                    if dest.exists() {
                        report.already_linked += 1;
                        continue;
                    }
                    match std::fs::hard_link(f.path(), &dest) {
                        Ok(()) => report.files_linked += 1,
                        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                            report.already_linked += 1;
                        }
                        Err(e) => return Err(e),
                    }
                }
            }
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_partition_for_hash() {
        // top 4 bytes 00000abc... -> value, shifted
        let h = "abcdef0123456789abcdef0123456789";
        // at power 6, part_shift 26
        let p6 = partition_for_hash(h, 6).unwrap();
        // at power 7, the partition doubles-ish (one more bit of the hash)
        let p7 = partition_for_hash(h, 7).unwrap();
        assert_eq!(p7 >> 1, p6, "increasing power adds one low bit");
    }

    #[test]
    fn test_relink_hard_links_to_new_partition() {
        let dir = std::env::temp_dir().join(format!("swift-relink-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let device = dir.join("sda1");
        // an object at old part 5, suffix abc
        let hash = "ffffffff00000000000000000000aabc";
        let old_part = partition_for_hash(hash, 6).unwrap();
        let old_dir = device
            .join("objects")
            .join(old_part.to_string())
            .join("abc")
            .join(hash);
        std::fs::create_dir_all(&old_dir).unwrap();
        std::fs::write(old_dir.join("1751500000.00000.data"), b"body").unwrap();

        let report = relink_device(&device, 0, 7).unwrap();
        assert_eq!(report.files_linked, 1, "{report:?}");

        // the file now exists at the new partition, sharing an inode
        let new_part = partition_for_hash(hash, 7).unwrap();
        let new_file = device
            .join("objects")
            .join(new_part.to_string())
            .join("abc")
            .join(hash)
            .join("1751500000.00000.data");
        assert!(new_file.exists(), "linked to new partition {new_part}");
        assert_eq!(std::fs::read(&new_file).unwrap(), b"body");

        // a second pass is idempotent
        let report2 = relink_device(&device, 0, 7).unwrap();
        assert_eq!(report2.files_linked, 0);
        assert!(report2.already_linked >= 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
