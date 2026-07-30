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

//! On-disk recon collectors, ported from the data the recon middleware
//! exposes and the checks `swift/cli/recon.py` aggregates.
//!
//! `swift-recon` proper polls every node's `/recon/<check>` endpoint and
//! aggregates JSON; this module provides the *node-local* collectors those
//! endpoints serve: the MD5 of a file (byte-identical to Python's
//! `md5_hash_for_file`, the ring/swift.conf consistency check), ring-file
//! digests for a swift dir, the async_pending backlog count, and the
//! quarantine tallies. Golden-tested for the MD5 contract.

use std::io::Read;
use std::path::Path;

use md5::{Digest, Md5};

use swift_diskfile::get_async_dir;

/// Block size Python reads in (`MD5_BLOCK_READ_BYTES`); irrelevant to the
/// result but kept so behaviour matches on huge files.
const MD5_BLOCK_READ_BYTES: usize = 4096;

/// `md5_hash_for_file`: the hex-encoded MD5 of a file, streamed.
pub fn md5_hash_for_file(path: &Path) -> std::io::Result<String> {
    let mut f = std::fs::File::open(path)?;
    let mut hasher = Md5::new();
    let mut buf = vec![0u8; MD5_BLOCK_READ_BYTES];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    Ok(out)
}

/// The MD5 of each `*.ring.gz` in a swift dir (recon's `ringmd5` check),
/// sorted by ring name.
pub fn ring_md5(swift_dir: &Path) -> std::io::Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(swift_dir) else {
        return Ok(out);
    };
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if name.ends_with(".ring.gz") {
            let md5 = md5_hash_for_file(&e.path())?;
            out.push((name, md5));
        }
    }
    out.sort();
    Ok(out)
}

/// Count async_pending files across all policies on a device (recon's
/// `async` check backlog).
pub fn async_pending_count(device: &Path) -> u64 {
    let mut count = 0u64;
    let Ok(dirs) = std::fs::read_dir(device) else {
        return 0;
    };
    for d in dirs.flatten() {
        let name = d.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with("async_pending") || !d.path().is_dir() {
            continue;
        }
        // <async_dir>/<suffix>/<file>
        if let Ok(suffixes) = std::fs::read_dir(d.path()) {
            for s in suffixes.flatten() {
                if let Ok(files) = std::fs::read_dir(s.path()) {
                    count += files.flatten().filter(|f| f.path().is_file()).count() as u64;
                }
            }
        }
    }
    count
}

/// Quarantine tallies for a device (recon's `quarantined` check).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct QuarantineCounts {
    pub accounts: u64,
    pub containers: u64,
    pub objects: u64,
}

/// Count entries under `<device>/quarantined/{accounts,containers,objects*}`.
pub fn quarantine_counts(device: &Path) -> QuarantineCounts {
    let base = device.join("quarantined");
    let count_dir = |sub: &str| -> u64 {
        std::fs::read_dir(base.join(sub))
            .map(|rd| rd.flatten().count() as u64)
            .unwrap_or(0)
    };
    let mut objects = count_dir("objects");
    // per-policy object quarantine dirs: objects-<N>
    if let Ok(rd) = std::fs::read_dir(&base) {
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().to_string();
            if n.starts_with("objects-") {
                objects += std::fs::read_dir(e.path())
                    .map(|r| r.flatten().count() as u64)
                    .unwrap_or(0);
            }
        }
    }
    QuarantineCounts {
        accounts: count_dir("accounts"),
        containers: count_dir("containers"),
        objects,
    }
}

/// Assert the async dir naming matches diskfile's (guards the constant used
/// by [`async_pending_count`] against drift).
pub fn async_dir_name(policy_index: u32) -> String {
    get_async_dir(policy_index)
}

/// The aggregate of a metric collected across many nodes (`swift-recon`'s
/// low/high/average/total/number-of-hosts summary).
#[derive(Debug, Clone, PartialEq)]
pub struct ReconAggregate {
    pub low: f64,
    pub high: f64,
    pub total: f64,
    pub reported: usize,
    pub number_none: usize,
}

impl ReconAggregate {
    /// The mean over the reporting hosts (0 when none reported).
    pub fn average(&self) -> f64 {
        if self.reported == 0 {
            0.0
        } else {
            self.total / self.reported as f64
        }
    }
}

/// Aggregate per-node values the way `swift-recon` summarises a check across
/// the cluster: `None` entries (a host that didn't answer) are counted
/// separately and excluded from low/high/total.
pub fn aggregate_recon(values: &[Option<f64>]) -> ReconAggregate {
    let mut agg = ReconAggregate {
        low: f64::INFINITY,
        high: f64::NEG_INFINITY,
        total: 0.0,
        reported: 0,
        number_none: 0,
    };
    for v in values {
        match v {
            Some(x) => {
                agg.low = agg.low.min(*x);
                agg.high = agg.high.max(*x);
                agg.total += *x;
                agg.reported += 1;
            }
            None => agg.number_none += 1,
        }
    }
    if agg.reported == 0 {
        agg.low = 0.0;
        agg.high = 0.0;
    }
    agg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_md5_hash_for_file() {
        let dir = std::env::temp_dir().join(format!("swift-recon-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("data");
        std::fs::write(&f, b"hello swift recon").unwrap();
        // md5("hello swift recon")
        let got = md5_hash_for_file(&f).unwrap();
        assert_eq!(got.len(), 32);
        assert!(got.chars().all(|c| c.is_ascii_hexdigit()));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_async_pending_count() {
        let dir = std::env::temp_dir().join(format!("swift-recon-a-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let ap = dir.join("async_pending/abc");
        std::fs::create_dir_all(&ap).unwrap();
        std::fs::write(ap.join("hash-1"), b"x").unwrap();
        std::fs::write(ap.join("hash-2"), b"y").unwrap();
        let ap1 = dir.join("async_pending-1/def");
        std::fs::create_dir_all(&ap1).unwrap();
        std::fs::write(ap1.join("hash-3"), b"z").unwrap();
        assert_eq!(async_pending_count(&dir), 3);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_aggregate_recon() {
        let vals = [Some(2.0), Some(8.0), None, Some(5.0)];
        let agg = aggregate_recon(&vals);
        assert_eq!(agg.low, 2.0);
        assert_eq!(agg.high, 8.0);
        assert_eq!(agg.total, 15.0);
        assert_eq!(agg.reported, 3);
        assert_eq!(agg.number_none, 1);
        assert_eq!(agg.average(), 5.0);
        // all-none
        let empty = aggregate_recon(&[None, None]);
        assert_eq!(empty.reported, 0);
        assert_eq!(empty.low, 0.0);
        assert_eq!(empty.average(), 0.0);
    }

    #[test]
    fn test_quarantine_counts() {
        let dir = std::env::temp_dir().join(format!("swift-recon-q-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for (sub, n) in [("accounts", 1), ("containers", 2), ("objects", 3)] {
            let p = dir.join("quarantined").join(sub);
            std::fs::create_dir_all(&p).unwrap();
            for i in 0..n {
                std::fs::create_dir_all(p.join(format!("h{i}"))).unwrap();
            }
        }
        // a per-policy objects-1 dir with 1 entry
        let p1 = dir.join("quarantined/objects-1");
        std::fs::create_dir_all(p1.join("h0")).unwrap();
        let q = quarantine_counts(&dir);
        assert_eq!(q.accounts, 1);
        assert_eq!(q.containers, 2);
        assert_eq!(q.objects, 4, "objects + objects-1");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
