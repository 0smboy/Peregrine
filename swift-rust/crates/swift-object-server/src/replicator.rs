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

//! The object replicator daemon *core*, ported from the rsync path of
//! `swift/obj/replicator.py` (`update` / `update_deleted`). It is deliberately
//! separate from the SSYNC receiver in [`crate::ssync`]: ssync is the other
//! consistency path and is not touched here.
//!
//! The loop walks every partition directory on a local device. For a partition
//! the local device is a *primary* for, it fetches each peer primary's suffix
//! hashes via the REPLICATE verb, rsyncs the suffix dirs whose hashes differ,
//! then asks the peer to invalidate+rehash them (Python `update`). For a
//! partition the local device is *not* a primary for (a handoff holding a
//! misplaced partition), it rsyncs every suffix to all primaries and, if all
//! succeed, deletes the local copy (Python `update_deleted`, "revert").
//!
//! The peer-hash RPC and the suffix transfer are pluggable traits so the
//! decision logic is unit-tested without a live cluster or a real rsync; the
//! HTTP/rsync adapters live in the `swift-object-replicator` binary.

use std::collections::HashMap;
use std::path::Path;

use swift_core::pickle::{self, Value};
use swift_diskfile::{get_data_dir, get_partition_hashes, get_tmp_dir, CleanupConfig, PolicyKind};
use swift_ring::{Ring, RingDevice};

/// Peer suffix-hash RPC (the object-server REPLICATE verb), pluggable so the
/// loop is testable without a live peer.
pub trait SuffixHashClient {
    /// REPLICATE `/<device>/<partition>` with no suffixes: fetch the peer's
    /// `{suffix: md5hex}` map. `None` on any transport/parse failure.
    fn peer_hashes(
        &self,
        peer: &RingDevice,
        device: &str,
        partition: u32,
        policy_index: u32,
    ) -> Option<HashMap<String, String>>;

    /// REPLICATE `/<device>/<partition>/<s1-s2-...>`: ask the peer to
    /// invalidate + rehash the named suffixes after a sync. Returns success.
    fn peer_rehash(
        &self,
        peer: &RingDevice,
        device: &str,
        partition: u32,
        suffixes: &[String],
        policy_index: u32,
    ) -> bool;
}

/// Suffix-directory transfer (rsync), pluggable so the loop is testable
/// without a real rsync.
pub trait SuffixSyncer {
    /// Push one suffix directory to the peer's partition directory. Returns
    /// success.
    fn sync_suffix(
        &self,
        local_suffix_dir: &Path,
        peer: &RingDevice,
        device: &str,
        partition: u32,
        suffix: &str,
        policy_index: u32,
    ) -> bool;
}

/// Per-pass stats (a subset of Python replicator `stats`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ReplicatorStats {
    /// Partition dirs examined.
    pub partitions: u64,
    /// Suffix directories rsynced (counted per peer).
    pub suffix_syncs: u64,
    /// Handoff partitions fully reverted (synced out then deleted locally).
    pub reverts: u64,
    /// Peers/partitions that failed a step.
    pub failures: u64,
}

/// Parse a pickled `{suffix: md5hex}` dict into a map, keeping only
/// string->string pairs (Python may store `None` for a suffix pending rehash).
pub fn hashes_from_pickle(body: &[u8]) -> Option<HashMap<String, String>> {
    dict_value_to_map(pickle::loads(body).ok()?)
}

fn dict_value_to_map(value: Value) -> Option<HashMap<String, String>> {
    match value {
        Value::Dict(pairs) => {
            let mut out = HashMap::new();
            for (k, v) in pairs {
                if let (Value::Str(k), Value::Str(v)) = (k, v) {
                    out.insert(k, v);
                }
            }
            Some(out)
        }
        _ => None,
    }
}

/// The suffixes present locally whose hash differs from — or is absent on —
/// the peer. Suffixes the peer has but we do not are the peer's job to push to
/// us on its own pass, so they are ignored here (Python compares in this same
/// local-drives-the-diff direction). Returned sorted for determinism.
pub fn divergent_suffixes(
    local: &HashMap<String, String>,
    remote: &HashMap<String, String>,
) -> Vec<String> {
    let mut out: Vec<String> = local
        .iter()
        .filter(|(suffix, hash)| remote.get(*suffix) != Some(*hash))
        .map(|(suffix, _)| suffix.clone())
        .collect();
    out.sort();
    out
}

/// The 3-hex suffix subdirectories of a partition, sorted.
fn suffix_dirs(partition_path: &Path) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(partition_path) {
        for entry in entries.flatten() {
            if !entry.path().is_dir() {
                continue;
            }
            if let Some(name) = entry.file_name().to_str() {
                if name.len() == 3 && name.bytes().all(|b| b.is_ascii_hexdigit()) {
                    out.push(name.to_string());
                }
            }
        }
    }
    out.sort();
    out
}

/// Local suffix hashes via the same `get_partition_hashes` the REPLICATE verb
/// uses, flattened to a `{suffix: md5hex}` map.
fn local_hashes(
    partition_path: &Path,
    policy: PolicyKind,
    cleanup: &CleanupConfig,
) -> HashMap<String, String> {
    match get_partition_hashes(partition_path, policy, &[], false, cleanup) {
        Ok((_hashed, hashes)) => dict_value_to_map(hashes.to_value()).unwrap_or_default(),
        Err(_) => HashMap::new(),
    }
}

/// Python `update`: the local device is a primary for this partition. Push the
/// divergent suffixes to every other primary and trigger a rehash there.
#[allow(clippy::too_many_arguments)]
pub fn replicate_partition(
    partition_path: &Path,
    device: &str,
    partition: u32,
    policy_index: u32,
    policy: PolicyKind,
    cleanup: &CleanupConfig,
    peers: &[&RingDevice],
    hash_client: &dyn SuffixHashClient,
    syncer: &dyn SuffixSyncer,
    stats: &mut ReplicatorStats,
) {
    let local = local_hashes(partition_path, policy, cleanup);
    for peer in peers {
        let Some(remote) = hash_client.peer_hashes(peer, device, partition, policy_index) else {
            stats.failures += 1;
            continue;
        };
        let diff = divergent_suffixes(&local, &remote);
        if diff.is_empty() {
            continue;
        }
        let mut ok = true;
        for suffix in &diff {
            if syncer.sync_suffix(
                &partition_path.join(suffix),
                peer,
                device,
                partition,
                suffix,
                policy_index,
            ) {
                stats.suffix_syncs += 1;
            } else {
                ok = false;
            }
        }
        // Only ask the peer to rehash once the pushes it depends on succeeded.
        if ok && !hash_client.peer_rehash(peer, device, partition, &diff, policy_index) {
            ok = false;
        }
        if !ok {
            stats.failures += 1;
        }
    }
}

/// Python `conf.replication_lock_timeout` default: seconds to wait for the
/// partition 'replication' lock before skipping a handoff revert.
const REPLICATION_LOCK_TIMEOUT: f64 = 15.0;

/// Python `update_deleted` (revert): the local device is NOT a primary for this
/// partition (it is a handoff). Push every suffix to every primary and, only if
/// all of them succeed, delete the local partition. Returns whether it was
/// reverted.
#[allow(clippy::too_many_arguments)]
pub fn revert_handoff(
    partition_path: &Path,
    device: &str,
    partition: u32,
    policy_index: u32,
    primaries: &[&RingDevice],
    hash_client: &dyn SuffixHashClient,
    syncer: &dyn SuffixSyncer,
    stats: &mut ReplicatorStats,
) -> bool {
    // Python `update_deleted` wraps the whole revert in the partition
    // 'replication' lock (`DiskFileManager.replication_lock`, default
    // `replication_lock_timeout` 15s) so an incoming SSYNC/receiver on the
    // same partition cannot race the delete. A timeout skips the handoff for
    // this pass — a lock-failure, not an error.
    let Ok(_lock) = swift_core::lockutil::lock_path(
        partition_path,
        REPLICATION_LOCK_TIMEOUT,
        Some("replication"),
    ) else {
        return false;
    };
    let suffixes = suffix_dirs(partition_path);
    let mut all_ok = !primaries.is_empty();
    for peer in primaries {
        let mut peer_ok = true;
        for suffix in &suffixes {
            if syncer.sync_suffix(
                &partition_path.join(suffix),
                peer,
                device,
                partition,
                suffix,
                policy_index,
            ) {
                stats.suffix_syncs += 1;
            } else {
                peer_ok = false;
            }
        }
        if peer_ok
            && !suffixes.is_empty()
            && !hash_client.peer_rehash(peer, device, partition, &suffixes, policy_index)
        {
            peer_ok = false;
        }
        if !peer_ok {
            all_ok = false;
        }
    }
    if all_ok && std::fs::remove_dir_all(partition_path).is_ok() {
        stats.reverts += 1;
        return true;
    }
    stats.failures += 1;
    false
}

/// Port of `swift.common.utils.unlink_older_than` as the replicator applies
/// it (replicator.py 855-857): remove every regular file directly in `path`
/// whose mtime is strictly older than `cutoff`. A missing directory and
/// per-file races are ignored, exactly as Python's ENOENT-swallowing
/// `listdir` / `unlink_paths_older_than` do; directories are left alone
/// (Python's `os.unlink` on one raises OSError, which is swallowed).
pub fn unlink_older_than(path: &Path, cutoff: std::time::SystemTime) {
    let Ok(entries) = std::fs::read_dir(path) else {
        return;
    };
    for entry in entries.flatten() {
        let fpath = entry.path();
        let Ok(meta) = std::fs::metadata(&fpath) else {
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        if let Ok(mtime) = meta.modified() {
            if mtime < cutoff {
                let _ = std::fs::remove_file(&fpath);
            }
        }
    }
}

/// One replication pass over a device directory for one replication policy.
#[allow(clippy::too_many_arguments)]
pub fn run_once(
    device_dir: &Path,
    device: &str,
    policy_index: u32,
    policy: PolicyKind,
    cleanup: &CleanupConfig,
    ring: &Ring,
    local_id: u64,
    hash_client: &dyn SuffixHashClient,
    syncer: &dyn SuffixSyncer,
) -> ReplicatorStats {
    let mut stats = ReplicatorStats::default();
    // replicator.py 855-857: before scanning partitions, each pass reaps the
    // temp files that crashed PUTs orphaned in the device tmp dir, once they
    // are older than reclaim_age.
    let reclaim_age = if cleanup.reclaim_age.is_finite() && cleanup.reclaim_age > 0.0 {
        cleanup.reclaim_age
    } else {
        0.0
    };
    if let Some(cutoff) = std::time::SystemTime::now()
        .checked_sub(std::time::Duration::from_secs_f64(reclaim_age))
    {
        unlink_older_than(&device_dir.join(get_tmp_dir(policy_index)), cutoff);
    }
    let part_root = device_dir.join(get_data_dir(policy_index));
    let Ok(entries) = std::fs::read_dir(&part_root) else {
        return stats;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let Some(partition) = path
            .file_name()
            .and_then(|s| s.to_str())
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        stats.partitions += 1;
        let Ok(nodes) = ring.get_part_nodes(partition) else {
            stats.failures += 1;
            continue;
        };
        let primaries: Vec<&RingDevice> = nodes.iter().map(|n| n.dev).collect();
        if primaries.iter().any(|d| d.id == local_id) {
            let peers: Vec<&RingDevice> =
                primaries.iter().copied().filter(|d| d.id != local_id).collect();
            replicate_partition(
                &path,
                device,
                partition,
                policy_index,
                policy,
                cleanup,
                &peers,
                hash_client,
                syncer,
                &mut stats,
            );
        } else {
            revert_handoff(
                &path,
                device,
                partition,
                policy_index,
                &primaries,
                hash_client,
                syncer,
                &mut stats,
            );
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
            port: 6010,
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

    #[derive(Default)]
    struct FakeHashClient {
        /// suffix->hash the peer reports (empty = peer has nothing).
        remote: HashMap<String, String>,
        hashed: Mutex<Vec<(u64, Vec<String>)>>,
        rehashed: Mutex<Vec<(u64, Vec<String>)>>,
    }
    impl SuffixHashClient for FakeHashClient {
        fn peer_hashes(
            &self,
            peer: &RingDevice,
            _device: &str,
            _partition: u32,
            _policy_index: u32,
        ) -> Option<HashMap<String, String>> {
            self.hashed.lock().unwrap().push((peer.id, vec![]));
            Some(self.remote.clone())
        }
        fn peer_rehash(
            &self,
            peer: &RingDevice,
            _device: &str,
            _partition: u32,
            suffixes: &[String],
            _policy_index: u32,
        ) -> bool {
            self.rehashed.lock().unwrap().push((peer.id, suffixes.to_vec()));
            true
        }
    }

    struct FakeSyncer {
        synced: Mutex<Vec<(u64, String)>>,
        fail_peer: Option<u64>,
    }
    impl SuffixSyncer for FakeSyncer {
        fn sync_suffix(
            &self,
            _local_suffix_dir: &Path,
            peer: &RingDevice,
            _device: &str,
            _partition: u32,
            suffix: &str,
            _policy_index: u32,
        ) -> bool {
            self.synced.lock().unwrap().push((peer.id, suffix.to_string()));
            self.fail_peer != Some(peer.id)
        }
    }

    #[test]
    fn test_divergent_suffixes() {
        let local = HashMap::from([
            ("abc".to_string(), "h1".to_string()),
            ("def".to_string(), "h2".to_string()),
        ]);
        // peer matches abc, missing def -> only def is divergent
        let remote = HashMap::from([("abc".to_string(), "h1".to_string())]);
        assert_eq!(divergent_suffixes(&local, &remote), vec!["def".to_string()]);
        // peer has a stale abc -> abc is divergent too
        let remote2 = HashMap::from([("abc".to_string(), "STALE".to_string())]);
        assert_eq!(
            divergent_suffixes(&local, &remote2),
            vec!["abc".to_string(), "def".to_string()]
        );
        // peer fully matches -> nothing to push
        assert!(divergent_suffixes(&local, &local).is_empty());
    }

    #[test]
    fn test_hashes_pickle_roundtrip() {
        let value = Value::Dict(vec![(
            Value::Str("abc".to_string()),
            Value::Str("0123456789abcdef0123456789abcdef".to_string()),
        )]);
        let body = pickle::dumps(&value).unwrap();
        let map = hashes_from_pickle(&body).unwrap();
        assert_eq!(map.get("abc").map(String::as_str), Some("0123456789abcdef0123456789abcdef"));
    }

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("swift-objrepl-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn test_run_once_primary_dispatch_queries_peers() {
        // A partition the local device (0) IS a primary for. Empty of suffixes,
        // so no sync happens, but each peer's hashes must be queried -> proves
        // the primary branch ran.
        let root = tmpdir("prim");
        let part = root.join("sdb1/objects/0");
        std::fs::create_dir_all(&part).unwrap();
        let hc = FakeHashClient::default();
        let sy = FakeSyncer { synced: Mutex::new(Vec::new()), fail_peer: None };
        let stats = run_once(
            &root.join("sdb1"),
            "sdb1",
            0,
            PolicyKind::Replication,
            &CleanupConfig::default(),
            &ring3(),
            0,
            &hc,
            &sy,
        );
        assert_eq!(stats.partitions, 1);
        assert_eq!(stats.reverts, 0);
        let queried: Vec<u64> = hc.hashed.lock().unwrap().iter().map(|(id, _)| *id).collect();
        assert_eq!(queried, vec![1, 2]); // both peer primaries, not self
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn test_run_once_handoff_reverts_and_deletes() {
        // Local device id 99 is NOT a primary -> handoff. One suffix present.
        let root = tmpdir("handoff");
        let part = root.join("sdb9/objects/0");
        let suffix = part.join("abc");
        std::fs::create_dir_all(&suffix).unwrap();
        std::fs::write(suffix.join("1700000000.00000.data"), b"x").unwrap();
        let hc = FakeHashClient::default();
        let sy = FakeSyncer { synced: Mutex::new(Vec::new()), fail_peer: None };
        let stats = run_once(
            &root.join("sdb9"),
            "sdb9",
            0,
            PolicyKind::Replication,
            &CleanupConfig::default(),
            &ring3(),
            99,
            &hc,
            &sy,
        );
        assert_eq!(stats.reverts, 1);
        // synced the suffix to all 3 primaries
        let peers: Vec<u64> = sy.synced.lock().unwrap().iter().map(|(id, _)| *id).collect();
        assert_eq!(peers, vec![0, 1, 2]);
        // local partition removed after a full revert
        assert!(!part.exists());
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// Age a file's mtime by `secs` seconds into the past.
    fn age_file(path: &Path, secs: u64) {
        let past = std::time::SystemTime::now() - std::time::Duration::from_secs(secs);
        let f = std::fs::OpenOptions::new().write(true).open(path).unwrap();
        f.set_times(std::fs::FileTimes::new().set_modified(past))
            .unwrap();
    }

    #[test]
    fn test_unlink_older_than_reaps_only_old_files() {
        let root = tmpdir("tmpreap");
        let tmp = root.join("sdb1/tmp");
        std::fs::create_dir_all(&tmp).unwrap();
        let old = tmp.join("tmpold");
        let fresh = tmp.join("tmpfresh");
        std::fs::write(&old, b"x").unwrap();
        std::fs::write(&fresh, b"y").unwrap();
        age_file(&old, 10_000);
        // subdirectories are never reaped
        std::fs::create_dir(tmp.join("subdir")).unwrap();

        let cutoff = std::time::SystemTime::now() - std::time::Duration::from_secs(5_000);
        unlink_older_than(&tmp, cutoff);
        assert!(!old.exists(), "old file reaped");
        assert!(fresh.exists(), "fresh file kept");
        assert!(tmp.join("subdir").exists(), "directories are left alone");
        // a missing dir is a no-op, as Python's listdir swallows ENOENT
        unlink_older_than(&root.join("sdb1/no-such-dir"), cutoff);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn test_run_once_reaps_orphaned_tmp_files() {
        // replicator.py 855-857: a pass removes tmp-dir files older than
        // reclaim_age (orphans of crashed PUTs) and keeps recent ones.
        let root = tmpdir("runreap");
        let device = root.join("sdb1");
        let tmp = device.join("tmp");
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::create_dir_all(device.join("objects")).unwrap();
        let old = tmp.join("tmporphan");
        let fresh = tmp.join("tmplive");
        std::fs::write(&old, b"x").unwrap();
        std::fs::write(&fresh, b"y").unwrap();
        age_file(&old, 10_000);

        let hc = FakeHashClient::default();
        let sy = FakeSyncer { synced: Mutex::new(Vec::new()), fail_peer: None };
        let cleanup = CleanupConfig {
            reclaim_age: 5_000.0,
            ..CleanupConfig::default()
        };
        run_once(
            &device,
            "sdb1",
            0,
            PolicyKind::Replication,
            &cleanup,
            &ring3(),
            0,
            &hc,
            &sy,
        );
        assert!(!old.exists(), "orphan older than reclaim_age is reaped");
        assert!(fresh.exists(), "recent tmp file survives the pass");
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn test_revert_keeps_partition_when_a_primary_fails() {
        let root = tmpdir("revert-fail");
        let part = root.join("sdb9/objects/0");
        let suffix = part.join("abc");
        std::fs::create_dir_all(&suffix).unwrap();
        std::fs::write(suffix.join("1700000000.00000.data"), b"x").unwrap();
        let hc = FakeHashClient::default();
        let sy = FakeSyncer { synced: Mutex::new(Vec::new()), fail_peer: Some(2) };
        let stats = run_once(
            &root.join("sdb9"),
            "sdb9",
            0,
            PolicyKind::Replication,
            &CleanupConfig::default(),
            &ring3(),
            99,
            &hc,
            &sy,
        );
        assert_eq!(stats.reverts, 0);
        assert_eq!(stats.failures, 1);
        assert!(part.exists()); // not deleted because peer 2's sync failed
        std::fs::remove_dir_all(&root).unwrap();
    }
}
