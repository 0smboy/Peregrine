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

//! Node-local tombstone and SQLite space collectors for Prometheus textfile /
//! recon-style export (`swift_object_tombstones`, `swift_db_*`).

use std::path::{Path, PathBuf};

use swift_db::{sample_db_space, DbSpaceSample, DbSpaceTotals};

/// Per-policy / per-device tombstone tally.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TombstoneBucket {
    pub device: String,
    pub policy: String,
    pub count: u64,
    pub bytes: u64,
}

/// Scan result across one devices root (e.g. `/srv/node`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TombstoneReport {
    pub buckets: Vec<TombstoneBucket>,
    pub total_count: u64,
    pub total_bytes: u64,
}

fn policy_from_objects_dir(name: &str) -> Option<String> {
    if name == "objects" {
        return Some("0".to_string());
    }
    name.strip_prefix("objects-")
        .filter(|rest| !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()))
        .map(|rest| rest.to_string())
}

/// Walk `<devices_root>/<device>/objects*/**/*.ts` and tally count + bytes.
pub fn scan_tombstones(devices_root: &Path) -> TombstoneReport {
    let mut report = TombstoneReport::default();
    let Ok(devs) = std::fs::read_dir(devices_root) else {
        return report;
    };
    for dev in devs.flatten() {
        if !dev.path().is_dir() {
            continue;
        }
        let device = dev.file_name().to_string_lossy().to_string();
        let Ok(entries) = std::fs::read_dir(dev.path()) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            let Some(policy) = policy_from_objects_dir(&name) else {
                continue;
            };
            if !entry.path().is_dir() {
                continue;
            }
            let (count, bytes) = count_ts_tree(&entry.path());
            // Always emit a bucket (including zeros) so Prometheus keeps a
            // continuous series for alerts when tombstones reclaim to 0.
            report.total_count += count;
            report.total_bytes += bytes;
            report.buckets.push(TombstoneBucket {
                device: device.clone(),
                policy,
                count,
                bytes,
            });
        }
    }
    report
        .buckets
        .sort_by(|a, b| (&a.device, &a.policy).cmp(&(&b.device, &b.policy)));
    report
}

fn count_ts_tree(root: &Path) -> (u64, u64) {
    let mut count = 0u64;
    let mut bytes = 0u64;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in rd.flatten() {
            let path = e.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let name = e.file_name();
            let name = name.to_string_lossy();
            if name.ends_with(".ts") {
                count += 1;
                bytes += e.metadata().map(|m| m.len()).unwrap_or(0);
            }
        }
    }
    (count, bytes)
}

/// Render Prometheus textfile exposition for tombstones.
pub fn tombstones_prometheus(report: &TombstoneReport, node: &str) -> String {
    let mut out = String::new();
    out.push_str("# HELP swift_object_tombstones Count of on-disk .ts tombstone files\n");
    out.push_str("# TYPE swift_object_tombstones gauge\n");
    if report.buckets.is_empty() {
        // No objects* dirs yet — still expose a zero so scrape/alerts stay live.
        out.push_str(&format!(
            "swift_object_tombstones{{node=\"{}\",device=\"none\",policy=\"none\"}} 0\n",
            escape_label(node)
        ));
    } else {
        for b in &report.buckets {
            out.push_str(&format!(
                "swift_object_tombstones{{node=\"{}\",device=\"{}\",policy=\"{}\"}} {}\n",
                escape_label(node),
                escape_label(&b.device),
                escape_label(&b.policy),
                b.count
            ));
        }
    }
    out.push_str("# HELP swift_object_tombstone_bytes Total bytes of .ts tombstone files\n");
    out.push_str("# TYPE swift_object_tombstone_bytes gauge\n");
    if report.buckets.is_empty() {
        out.push_str(&format!(
            "swift_object_tombstone_bytes{{node=\"{}\",device=\"none\",policy=\"none\"}} 0\n",
            escape_label(node)
        ));
    } else {
        for b in &report.buckets {
            out.push_str(&format!(
                "swift_object_tombstone_bytes{{node=\"{}\",device=\"{}\",policy=\"{}\"}} {}\n",
                escape_label(node),
                escape_label(&b.device),
                escape_label(&b.policy),
                b.bytes
            ));
        }
    }
    out
}

fn escape_label(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Per-DB samples plus device aggregates.
#[derive(Debug, Clone, Default)]
pub struct DbSpaceReport {
    pub samples: Vec<DbSpaceSample>,
    pub by_kind: Vec<(String, DbSpaceTotals)>,
    pub errors: Vec<(PathBuf, String)>,
}

/// Sample account/container DBs under `<devices_root>/<device>/{accounts,containers}`.
pub fn scan_db_space(devices_root: &Path) -> DbSpaceReport {
    let mut report = DbSpaceReport::default();
    let mut account = DbSpaceTotals::default();
    let mut container = DbSpaceTotals::default();
    let Ok(devs) = std::fs::read_dir(devices_root) else {
        return report;
    };
    for dev in devs.flatten() {
        if !dev.path().is_dir() {
            continue;
        }
        for (datadir, kind, totals) in [
            ("accounts", "account", &mut account),
            ("containers", "container", &mut container),
        ] {
            let root = dev.path().join(datadir);
            walk_dbs(&root, kind, &mut report, totals);
        }
    }
    report.by_kind.push(("account".into(), account));
    report.by_kind.push(("container".into(), container));
    report
}

fn walk_dbs(
    root: &Path,
    kind: &'static str,
    report: &mut DbSpaceReport,
    totals: &mut DbSpaceTotals,
) {
    let Ok(parts) = std::fs::read_dir(root) else {
        return;
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
                let Ok(files) = std::fs::read_dir(hash.path()) else {
                    continue;
                };
                for f in files.flatten() {
                    let name = f.file_name();
                    if !name.to_string_lossy().ends_with(".db") {
                        continue;
                    }
                    match sample_db_space(&f.path(), kind) {
                        Ok(sample) => {
                            totals.absorb(&sample);
                            report.samples.push(sample);
                        }
                        Err(e) => {
                            totals.errors += 1;
                            report.errors.push((f.path(), e.to_string()));
                        }
                    }
                }
            }
        }
    }
}

/// Prometheus textfile for DB space aggregates (per kind).
pub fn db_space_prometheus(report: &DbSpaceReport, node: &str) -> String {
    let mut out = String::new();
    out.push_str("# HELP swift_db_file_bytes Sum of account/container SQLite file sizes\n");
    out.push_str("# TYPE swift_db_file_bytes gauge\n");
    out.push_str("# HELP swift_db_freelist_count Sum of PRAGMA freelist_count\n");
    out.push_str("# TYPE swift_db_freelist_count gauge\n");
    out.push_str("# HELP swift_db_freelist_bytes Approximate freelist bytes (pages * page_size)\n");
    out.push_str("# TYPE swift_db_freelist_bytes gauge\n");
    out.push_str("# HELP swift_db_files Count of sampled .db files\n");
    out.push_str("# TYPE swift_db_files gauge\n");
    for (kind, t) in &report.by_kind {
        let k = escape_label(kind);
        let n = escape_label(node);
        out.push_str(&format!(
            "swift_db_file_bytes{{node=\"{n}\",kind=\"{k}\"}} {}\n",
            t.file_bytes
        ));
        out.push_str(&format!(
            "swift_db_freelist_count{{node=\"{n}\",kind=\"{k}\"}} {}\n",
            t.freelist_count
        ));
        out.push_str(&format!(
            "swift_db_freelist_bytes{{node=\"{n}\",kind=\"{k}\"}} {}\n",
            t.freelist_bytes
        ));
        out.push_str(&format!(
            "swift_db_files{{node=\"{n}\",kind=\"{k}\"}} {}\n",
            t.files
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tombstone_scan_counts_policy_dirs() {
        let root = std::env::temp_dir().join(format!(
            "swift-ts-scan-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let h0 = root.join("d1/objects/1/abc/hash0");
        let h1 = root.join("d1/objects-1/2/def/hash1");
        std::fs::create_dir_all(&h0).unwrap();
        std::fs::create_dir_all(&h1).unwrap();
        std::fs::write(h0.join("1111111111.12345.ts"), b"").unwrap();
        std::fs::write(h0.join("1111111111.12345.data"), b"x").unwrap();
        std::fs::write(h1.join("2222222222.00000.ts"), b"yy").unwrap();

        let report = scan_tombstones(&root);
        assert_eq!(report.total_count, 2);
        assert_eq!(report.total_bytes, 2);
        assert_eq!(report.buckets.len(), 2);
        let prom = tombstones_prometheus(&report, "swift1");
        assert!(prom.contains("swift_object_tombstones"));
        assert!(prom.contains("policy=\"0\""));
        assert!(prom.contains("policy=\"1\""));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn db_space_prometheus_emits_gauges() {
        let report = DbSpaceReport {
            by_kind: vec![(
                "container".into(),
                DbSpaceTotals {
                    files: 2,
                    file_bytes: 4096,
                    freelist_count: 3,
                    freelist_bytes: 12288,
                    errors: 0,
                },
            )],
            ..Default::default()
        };
        let prom = db_space_prometheus(&report, "n1");
        assert!(prom.contains("swift_db_file_bytes{node=\"n1\",kind=\"container\"} 4096"));
        assert!(prom.contains("swift_db_freelist_count{node=\"n1\",kind=\"container\"} 3"));
    }
}
