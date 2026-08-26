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

//! The db_replicator daemon *loop*, ported from the scan/peer-selection of
//! `swift/common/db_replicator.py` (`run_once` -> `_replicate_object`).
//!
//! The REPLICATE RPC (receive side) and the per-peer sync/usync push
//! (`replicate_container_db`) already live in [`crate::replicator`] and on the
//! account/container servers. This module adds what drives them: walk every
//! DB partition on a device, and for each DB compute the peer replicas from
//! the ring (all primaries other than the local node, rotated to start just
//! after self, exactly as Python's `nodes[i+1:] + nodes[:i]`) and push to each.
//!
//! The rsync full-DB fallback for a missing/divergent peer DB lives in the
//! client impl (see [`crate::rsync_db`] and swift-cli's db_replicator).
//! After a handoff DB replicates to every primary with no new local rows,
//! the hash dir is removed (Python `cleanup_post_replicate`) so sharders
//! do not report leftover object_count to root (probe L1426 / L1435).
//! Deferred: reclaim/delete of empty DBs, and per-partition failure backoff.

use std::path::{Path, PathBuf};

use swift_ring::{Ring, RingDevice};

use crate::db_locations;

/// One replicatable DB found on disk: its partition, hash dir, and file path.
#[derive(Debug, Clone, PartialEq)]
pub struct DbPartition {
    pub partition: u32,
    pub hash: String,
    pub path: PathBuf,
    /// Python `shouldbehere == False`: this node is not a primary for the
    /// (corrected) ring partition, or the DB sat in the wrong partition dir.
    pub is_handoff: bool,
}

/// Walk a device's DB tree, pairing each container with its partition number
/// (the top-level numeric dir) and hash (the hash dir name).
///
/// Python's replicator uses `broker.db_file` (the freshest epoch). Walking
/// both `<hash>.db` and `<hash>_<epoch>.db` as two objects would rsync the
/// epoch file onto the peer's unsuffixed name (probe L1347/L1375).
pub fn iter_db_partitions(device: &Path, datadir: &str) -> Vec<DbPartition> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for path in db_locations(device, datadir) {
        let Some(dir) = path.parent() else {
            continue;
        };
        if !seen.insert(dir.to_path_buf()) {
            continue;
        }
        // One broker per hash dir: freshest epoch, else the unsuffixed file.
        let cur = crate::get_db_files(&path)
            .into_iter()
            .last()
            .unwrap_or(path);
        // <device>/<datadir>/<part>/<suffix>/<hash>/<hash>[_epoch].db
        let hash = cur
            .parent()
            .and_then(|p| p.file_name())
            .map(|s| s.to_string_lossy().to_string());
        let partition = cur
            .parent()
            .and_then(|p| p.parent())
            .and_then(|p| p.parent())
            .and_then(|p| p.file_name())
            .and_then(|s| s.to_string_lossy().parse::<u32>().ok());
        if let (Some(hash), Some(partition)) = (hash, partition) {
            out.push(DbPartition {
                partition,
                hash,
                path: cur,
                is_handoff: false,
            });
        }
    }
    out
}

/// The peer replicas a local node should push a partition's DB to: every
/// primary node except the local one, rotated so the list starts with the
/// node right after `local_id` (Python's `repl_nodes = nodes[i+1:]+nodes[:i]`).
///
/// If the local node is not a primary for the partition (a handoff holding a
/// misplaced DB), all primaries are returned so the DB can be replicated out.
pub fn repl_peers(ring: &Ring, partition: u32, local_id: u64) -> Vec<&RingDevice> {
    let Ok(nodes) = ring.get_part_nodes(partition) else {
        return Vec::new();
    };
    let devs: Vec<&RingDevice> = nodes.iter().map(|n| n.dev).collect();
    match devs.iter().position(|d| d.id == local_id) {
        Some(i) if devs.len() > 1 => {
            let mut out = Vec::with_capacity(devs.len() - 1);
            out.extend_from_slice(&devs[i + 1..]);
            out.extend_from_slice(&devs[..i]);
            out
        }
        Some(_) => devs, // single replica: push to self set (Python special case)
        None => devs,    // handoff: replicate out to all primaries
    }
}

/// A pluggable "push this DB to this peer" action, so the loop is testable
/// without a live peer server. The real impl calls
/// [`crate::replicate_container_db`] / `replicate_account_db`.
pub trait DbReplicateClient {
    fn replicate(&self, db: &DbPartition, peer: &RingDevice) -> bool;
    /// Server-type post hook. Container replication uses this to feed rows
    /// whose policy differs from `container_stat` into the reconciler queue.
    fn post_replicate(&self, db: &DbPartition, ring: &Ring, responses: &[bool]) {
        let _ = (db, ring, responses);
    }
    /// `max_row` snapshot for Python `cleanup_post_replicate` (`max_row_delta`).
    fn db_max_row(&self, db: &DbPartition) -> i64 {
        let _ = db;
        0
    }
    /// Account (and container, if any) stored in this DB, so the loop can
    /// compare `ring.get_part` against the on-disk partition directory
    /// (Python `_replicate_object` `bpart != partition` → `shouldbehere=False`).
    fn db_account_container(&self, db: &DbPartition) -> Option<(String, Option<String>)> {
        let _ = db;
        None
    }
}

/// True when `local_id` is not a primary for `partition` (a handoff copy).
fn is_handoff_partition(ring: &Ring, partition: u32, local_id: u64) -> bool {
    match ring.get_part_nodes(partition) {
        Ok(nodes) => !nodes.iter().any(|n| n.dev.id == local_id),
        Err(_) => false,
    }
}

/// Python `Replicator.delete_db`: rmtree the hash dir, then rmdir empty
/// suffix and partition parents.
pub fn remove_replicated_handoff_db(db_path: &Path) -> bool {
    let Some(hash_dir) = db_path.parent() else {
        return false;
    };
    // Match Python `Replicator.delete_db`: serialize removal against broker
    // writers by taking the hash-directory parent lock before rmtree.  The
    // lock file itself is inside `hash_dir`; on Unix it remains a valid held
    // flock after unlink until this guard is dropped.
    let Ok(_lock) = crate::util::lock_parent_directory(db_path, 30.0) else {
        return false;
    };
    let suf_dir = hash_dir.parent().map(|p| p.to_path_buf());
    let part_dir = suf_dir
        .as_ref()
        .and_then(|s| s.parent().map(|p| p.to_path_buf()));
    let _ = std::fs::remove_dir_all(hash_dir);
    if let Some(suf) = suf_dir {
        let _ = std::fs::remove_dir(suf);
    }
    if let Some(part) = part_dir {
        let _ = std::fs::remove_dir(part);
    }
    !hash_dir.exists()
}

/// Loop stats (Python `stats`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ReplLoopStats {
    pub attempted: u64,
    pub successes: u64,
    pub failures: u64,
}

/// One replication pass over a device's DBs.
pub fn run_once(
    device: &Path,
    datadir: &str,
    ring: &Ring,
    local_id: u64,
    client: &dyn DbReplicateClient,
) -> ReplLoopStats {
    let mut stats = ReplLoopStats::default();
    for db in iter_db_partitions(device, datadir) {
        stats.attempted += 1;
        let orig_max_row = client.db_max_row(&db);
        // Python: if ring.get_part(account, container) != on-disk partition,
        // the DB is misplaced (nested shard created next to the donor). Push
        // to the *correct* partition's primaries, then always treat as a
        // handoff so cleanup_post_replicate can rmtree it (probe L1426).
        let mut target = db.clone();
        let mut wrong_part = false;
        if let Some((acct, cont)) = client.db_account_container(&db) {
            if let Ok(bpart) = ring.get_part(&acct, cont.as_deref(), None) {
                if bpart != db.partition {
                    eprintln!(
                        "db-replicator: Found db that should be on partition {bpart}; will replicate out and remove hsh={} disk_part={}",
                        db.hash, db.partition
                    );
                    target.partition = bpart;
                    wrong_part = true;
                }
            }
        }
        target.is_handoff = wrong_part || is_handoff_partition(ring, target.partition, local_id);
        let peers = repl_peers(ring, target.partition, local_id);
        let mut all_ok = !peers.is_empty();
        let mut responses: Vec<bool> = Vec::new();
        for peer in peers {
            if peer.id == local_id {
                continue;
            }
            let ok = client.replicate(&target, peer);
            responses.push(ok);
            if !ok {
                all_ok = false;
            }
        }
        client.post_replicate(&db, ring, &responses);
        if all_ok {
            stats.successes += 1;
            // Python `_replicate_object`: if this node is not a primary
            // (`shouldbehere` false), `cleanup_post_replicate` rmtree's the
            // hash dir after every peer succeeded and max_row did not grow.
            // Nested-shard handoffs leftover from a down CS still hold
            // pre-DELETE rows; sharders then UPDATE_ROOT with object_count
            // 50 each → HEAD 150 at probe L1435.
            if target.is_handoff && !responses.is_empty() && responses.iter().all(|&ok| ok) {
                let delta = client.db_max_row(&db) - orig_max_row;
                if delta == 0 {
                    eprintln!(
                        "db-replicator: deleted handoff hsh={} disk_part={} ring_part={} wrong_part={wrong_part}",
                        db.hash, db.partition, target.partition
                    );
                    let _ = remove_replicated_handoff_db(&db.path);
                } else {
                    eprintln!(
                        "db-replicator: keep handoff hsh={} max_row_delta={delta}",
                        db.hash
                    );
                }
            }
        } else {
            stats.failures += 1;
        }
    }
    stats
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use swift_core::hashing::HashPathConfig;
    use swift_ring::{RingData, RingDevice};

    fn dev(id: u64) -> RingDevice {
        RingDevice {
            id,
            region: 1,
            zone: 1,
            ip: format!("10.0.0.{id}"),
            port: 6201,
            replication_ip: None,
            replication_port: None,
            device: format!("sd{id}"),
            weight: 1.0,
            meta: String::new(),
            extra: Default::default(),
        }
    }

    /// One partition, 3 replicas over devices 0,1,2.
    fn ring3() -> Ring {
        let devs = vec![Some(dev(0)), Some(dev(1)), Some(dev(2))];
        let r2p2d = vec![vec![0u32], vec![1u32], vec![2u32]];
        let data = RingData::from_parts(devs, 32, r2p2d);
        Ring::new(data, HashPathConfig::new("", "changeme").unwrap())
    }

    #[test]
    fn test_repl_peers_rotation() {
        let ring = ring3();
        // local node 1 -> peers should be [2, 0] (nodes after self, then before)
        let peers = repl_peers(&ring, 0, 1);
        let ids: Vec<u64> = peers.iter().map(|d| d.id).collect();
        assert_eq!(ids, vec![2, 0]);
        // local node 0 -> [1, 2]
        let ids0: Vec<u64> = repl_peers(&ring, 0, 0).iter().map(|d| d.id).collect();
        assert_eq!(ids0, vec![1, 2]);
    }

    #[test]
    fn test_repl_peers_handoff_returns_all() {
        let ring = ring3();
        // node 99 isn't a primary -> replicate out to all primaries
        let ids: Vec<u64> = repl_peers(&ring, 0, 99).iter().map(|d| d.id).collect();
        assert_eq!(ids, vec![0, 1, 2]);
    }

    struct FakeRepl {
        pushes: Mutex<Vec<(u32, u64)>>,
        fail_peer: Option<u64>,
        ring_key: Option<(String, Option<String>)>,
    }
    impl DbReplicateClient for FakeRepl {
        fn replicate(&self, db: &DbPartition, peer: &RingDevice) -> bool {
            self.pushes.lock().unwrap().push((db.partition, peer.id));
            self.fail_peer != Some(peer.id)
        }
        fn db_account_container(&self, _db: &DbPartition) -> Option<(String, Option<String>)> {
            self.ring_key.clone()
        }
    }

    fn make_db(device: &Path, part: u32) -> String {
        let hash = "0000000000000000000000000000abcd";
        let hd = device.join(format!("containers/{part}/bcd/{hash}"));
        std::fs::create_dir_all(&hd).unwrap();
        std::fs::write(hd.join(format!("{hash}.db")), b"db").unwrap();
        hash.to_string()
    }

    #[test]
    fn test_iter_db_partitions_one_freshest_per_hash_dir() {
        // SHARDING dirs have <hash>.db + <hash>_<epoch>.db. Python walks
        // broker.db_file (freshest). Two entries would rsync the epoch
        // file onto the peer as <hash>.db (probe L1347).
        let dir = std::env::temp_dir().join(format!(
            "swift-repl-dedup-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let device = dir.join("sda1");
        let hash = make_db(&device, 0);
        let hd = device.join(format!("containers/0/bcd/{hash}"));
        std::fs::write(hd.join(format!("{hash}_1751500010.00000.db")), b"epoch").unwrap();
        let parts = iter_db_partitions(&device, "containers");
        assert_eq!(parts.len(), 1, "{parts:?}");
        let name = parts[0].path.file_name().unwrap().to_string_lossy();
        assert!(
            name.to_string().contains('_'),
            "must prefer epoch file, got {name}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_run_once_pushes_to_peers() {
        let dir = std::env::temp_dir().join(format!("swift-repl-loop-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let device = dir.join("sda1");
        make_db(&device, 0);

        let parts = iter_db_partitions(&device, "containers");
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].partition, 0);

        let client = FakeRepl {
            pushes: Mutex::new(Vec::new()),
            fail_peer: None,
            ring_key: None,
        };
        // local node 0 -> pushes to peers 1 and 2
        let stats = run_once(&device, "containers", &ring3(), 0, &client);
        assert_eq!(stats.attempted, 1);
        assert_eq!(stats.successes, 1);
        let pushed: Vec<u64> = client
            .pushes
            .lock()
            .unwrap()
            .iter()
            .map(|(_, id)| *id)
            .collect();
        assert_eq!(pushed, vec![1, 2]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_run_once_failure_when_peer_fails() {
        let dir = std::env::temp_dir().join(format!("swift-repl-loop-f-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let device = dir.join("sda1");
        make_db(&device, 0);
        let client = FakeRepl {
            pushes: Mutex::new(Vec::new()),
            fail_peer: Some(2),
            ring_key: None,
        };
        let stats = run_once(&device, "containers", &ring3(), 0, &client);
        assert_eq!(stats.failures, 1);
        assert_eq!(stats.successes, 0);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_run_once_removes_handoff_after_all_peers_ok() {
        let dir = std::env::temp_dir().join(format!(
            "swift-repl-handoff-rm-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let device = dir.join("sda1");
        let hash = make_db(&device, 0);
        let db_path = device.join(format!("containers/0/bcd/{hash}/{hash}.db"));
        assert!(db_path.exists());
        let client = FakeRepl {
            pushes: Mutex::new(Vec::new()),
            fail_peer: None,
            ring_key: None,
        };
        // node 99 is not a primary → handoff; all 3 primaries succeed.
        let stats = run_once(&device, "containers", &ring3(), 99, &client);
        assert_eq!(stats.successes, 1);
        assert!(
            !db_path.exists(),
            "handoff hash dir must be removed after successful replicate"
        );
        let pushed: Vec<u64> = client
            .pushes
            .lock()
            .unwrap()
            .iter()
            .map(|(_, id)| *id)
            .collect();
        assert_eq!(pushed, vec![0, 1, 2]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_run_once_keeps_handoff_when_a_peer_fails() {
        let dir = std::env::temp_dir().join(format!(
            "swift-repl-handoff-keep-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let device = dir.join("sda1");
        let hash = make_db(&device, 0);
        let db_path = device.join(format!("containers/0/bcd/{hash}/{hash}.db"));
        let client = FakeRepl {
            pushes: Mutex::new(Vec::new()),
            fail_peer: Some(1),
            ring_key: None,
        };
        let stats = run_once(&device, "containers", &ring3(), 99, &client);
        assert_eq!(stats.failures, 1);
        assert!(db_path.exists(), "failed handoff replicate must not rmtree");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_run_once_keeps_primary_db() {
        let dir = std::env::temp_dir().join(format!(
            "swift-repl-primary-keep-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let device = dir.join("sda1");
        let hash = make_db(&device, 0);
        let db_path = device.join(format!("containers/0/bcd/{hash}/{hash}.db"));
        let client = FakeRepl {
            pushes: Mutex::new(Vec::new()),
            fail_peer: None,
            ring_key: None,
        };
        let stats = run_once(&device, "containers", &ring3(), 0, &client);
        assert_eq!(stats.successes, 1);
        assert!(db_path.exists(), "primary DB must not be deleted");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn ring_two_parts() -> Ring {
        let devs = vec![Some(dev(0)), Some(dev(1)), Some(dev(2))];
        let r2p2d = vec![vec![0u32, 0], vec![1u32, 1], vec![2u32, 2]];
        let data = RingData::from_parts(devs, 31, r2p2d);
        Ring::new(data, HashPathConfig::new("", "changeme").unwrap())
    }

    #[test]
    fn test_run_once_wrong_partition_replicates_to_ring_part_then_rmtree() {
        // Python `_replicate_object`: bpart != on-disk partition → push to
        // the correct partition's primaries, then delete the misplaced copy.
        let dir = std::env::temp_dir().join(format!(
            "swift-repl-wrongpart-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let device = dir.join("sda1");
        let hash = make_db(&device, 0);
        let db_path = device.join(format!("containers/0/bcd/{hash}/{hash}.db"));
        let ring = ring_two_parts();
        let mut key = None;
        for name in ["c0", "c1", "c2", "c3", "c4", "c5", "c6", "c7", "c8", "c9"] {
            if ring.get_part("a", Some(name), None).unwrap() == 1 {
                key = Some((name.to_string(), name.to_string()));
                break;
            }
        }
        let (_, cname) = key.expect("need an account/container that hashes to part 1");
        let client = FakeRepl {
            pushes: Mutex::new(Vec::new()),
            fail_peer: None,
            ring_key: Some(("a".into(), Some(cname))),
        };
        // local node 0 *is* a primary of path partition 0, but the DB's
        // ring part is 1 → shouldbehere stays false (Python).
        let stats = run_once(&device, "containers", &ring, 0, &client);
        assert_eq!(stats.successes, 1);
        assert!(
            !db_path.exists(),
            "misplaced (wrong partition) DB must be removed"
        );
        let pushed = client.pushes.lock().unwrap().clone();
        assert!(
            pushed.iter().all(|(part, _)| *part == 1),
            "must push to ring part 1, got {pushed:?}"
        );
        assert!(!pushed.is_empty(), "must push to at least one peer");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
