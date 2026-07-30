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
//! Deferred: handoff-then-remove of misplaced DBs, reclaim/delete of empty
//! DBs, and per-partition failure backoff.

use std::path::{Path, PathBuf};

use swift_ring::{Ring, RingDevice};

use crate::db_locations;

/// One replicatable DB found on disk: its partition, hash dir, and file path.
#[derive(Debug, Clone, PartialEq)]
pub struct DbPartition {
    pub partition: u32,
    pub hash: String,
    pub path: PathBuf,
}

/// Walk a device's DB tree, pairing each `<hash>.db` with its partition number
/// (the top-level numeric dir) and hash (the hash dir name).
pub fn iter_db_partitions(device: &Path, datadir: &str) -> Vec<DbPartition> {
    let mut out = Vec::new();
    for path in db_locations(device, datadir) {
        // <device>/<datadir>/<part>/<suffix>/<hash>/<hash>.db
        let hash = path
            .parent()
            .and_then(|p| p.file_name())
            .map(|s| s.to_string_lossy().to_string());
        let partition = path
            .parent() // hash dir
            .and_then(|p| p.parent()) // suffix dir
            .and_then(|p| p.parent()) // partition dir
            .and_then(|p| p.file_name())
            .and_then(|s| s.to_string_lossy().parse::<u32>().ok());
        if let (Some(hash), Some(partition)) = (hash, partition) {
            out.push(DbPartition {
                partition,
                hash,
                path,
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
        let peers = repl_peers(ring, db.partition, local_id);
        let mut all_ok = !peers.is_empty();
        for peer in peers {
            if peer.id == local_id {
                continue;
            }
            if !client.replicate(&db, peer) {
                all_ok = false;
            }
        }
        if all_ok {
            stats.successes += 1;
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
    }
    impl DbReplicateClient for FakeRepl {
        fn replicate(&self, db: &DbPartition, peer: &RingDevice) -> bool {
            self.pushes.lock().unwrap().push((db.partition, peer.id));
            self.fail_peer != Some(peer.id)
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
        };
        // local node 0 -> pushes to peers 1 and 2
        let stats = run_once(&device, "containers", &ring3(), 0, &client);
        assert_eq!(stats.attempted, 1);
        assert_eq!(stats.successes, 1);
        let pushed: Vec<u64> = client.pushes.lock().unwrap().iter().map(|(_, id)| *id).collect();
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
        };
        let stats = run_once(&device, "containers", &ring3(), 0, &client);
        assert_eq!(stats.failures, 1);
        assert_eq!(stats.successes, 0);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
