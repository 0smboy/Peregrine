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
//! hashes via the REPLICATE verb, then SSYNCs the suffix dirs whose hashes
//! differ (Python `update`). For a
//! partition the local device is *not* a primary for (a handoff holding a
//! misplaced partition), it SSYNCs every suffix to all primaries and deletes
//! only source generations that every primary confirms at identical logical
//! timestamps (Python `update_deleted`, "revert").
//!
//! The peer-hash RPC and the suffix transfer are pluggable traits so the
//! decision logic is unit-tested without a live cluster or a real rsync; the
//! HTTP/SSYNC adapters live in the `swift-object-replicator` binary.

use std::collections::{BTreeMap, HashMap};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use swift_core::pickle::{self, Value};
use swift_diskfile::{
    get_data_dir, get_partition_hashes, get_tmp_dir, invalidate_hash, CleanupConfig, PolicyKind,
};
use swift_ring::{Ring, RingDevice};

use crate::ssync_sender::{object_timestamps_from_hash_dir, ObjectTimestamps, SenderReport};

/// Replication suffix hashes. `None` is meaningful: the suffix exists but its
/// digest is invalidated or could not be recalculated. It must not collapse
/// into "suffix absent", because absence on both sides would silently suppress
/// the repair attempt.
pub type SuffixHashMap = HashMap<String, Option<String>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuffixHashError {
    /// HTTP 507: the target's device is unmounted, so the primary slot must be
    /// retried on a handoff node.
    InsufficientStorage,
    /// Transport, protocol, parse, or any other status failure.
    Failed,
}

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
    ) -> Result<SuffixHashMap, SuffixHashError>;
}

/// Partition suffix transfer (SSYNC), pluggable so the loop is testable
/// without a live peer.
pub trait SuffixSyncer {
    /// Reconcile the selected suffixes with one peer in a single SSYNC
    /// session. A successful report carries only object states confirmed
    /// present on the receiver. `None` means transport or protocol failure.
    fn sync_suffixes(
        &self,
        local_partition_dir: &Path,
        peer: &RingDevice,
        device: &str,
        partition: u32,
        suffixes: &[String],
        policy_index: u32,
    ) -> Option<SenderReport>;
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
    /// The pass stopped before another job because its ring file changed.
    /// Continuing with the old primary set could authorize an unsafe handoff
    /// purge after a rebalance.
    pub aborted_ring_change: bool,
    /// The pass stopped because the local device no longer satisfied the
    /// configured drive/mount contract.
    pub aborted_device: bool,
    /// Replication is deliberately disabled while a partition-power increase
    /// is in progress because both old and new layouts are hard-linked and a
    /// normal replication pass cannot safely distinguish them.
    pub skipped_next_part_power: bool,
}

/// Result of the daemon's safety checks immediately before each partition
/// job. Python performs these checks per job, not merely once per sweep.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplicationJobGuard {
    Continue,
    RingChanged,
    DeviceUnavailable,
}

/// Parse a pickled `{suffix: md5hex}` dict into a map, keeping only
/// string->string pairs (Python may store `None` for a suffix pending rehash).
pub fn hashes_from_pickle(body: &[u8]) -> Option<SuffixHashMap> {
    dict_value_to_map(pickle::loads(body).ok()?)
}

fn dict_value_to_map(value: Value) -> Option<SuffixHashMap> {
    match value {
        Value::Dict(pairs) => {
            let mut out = HashMap::new();
            for (k, v) in pairs {
                let Value::Str(k) = k else { return None };
                if !is_lower_hex(&k, 3) {
                    return None;
                }
                let value = match v {
                    Value::Str(value) => Some(value),
                    Value::None => None,
                    _ => return None,
                };
                if out.insert(k, value).is_some() {
                    return None;
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
pub fn divergent_suffixes(local: &SuffixHashMap, remote: &SuffixHashMap) -> Vec<String> {
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
) -> Option<SuffixHashMap> {
    match get_partition_hashes(partition_path, policy, &[], false, cleanup) {
        Ok((_hashed, hashes)) => dict_value_to_map(hashes.to_value()),
        Err(_) => None,
    }
}

/// Python `update`: the local device is a primary for this partition. SSYNC the
/// divergent suffixes to every other primary. The receiver's ordinary object
/// mutation path invalidates its suffix hash; a second REPLICATE rehash RPC is
/// an rsync-era operation and would race the SSYNC receiver's own updates.
#[allow(clippy::too_many_arguments)]
pub fn replicate_partition(
    partition_path: &Path,
    device: &str,
    partition: u32,
    policy_index: u32,
    policy: PolicyKind,
    cleanup: &CleanupConfig,
    peers: &[&RingDevice],
    handoffs: &[&RingDevice],
    hash_client: &dyn SuffixHashClient,
    syncer: &dyn SuffixSyncer,
    stats: &mut ReplicatorStats,
) {
    let Some(local) = ({
        let _scan =
            swift_core::stage::StageTimer::start("object-replicator", "replication", "scan");
        local_hashes(partition_path, policy, cleanup)
    }) else {
        stats.failures += 1;
        return;
    };
    let mut candidates = peers.iter().chain(handoffs.iter()).copied();
    let mut attempts_left = peers.len();
    while attempts_left > 0 {
        let Some(peer) = candidates.next() else {
            break;
        };
        attempts_left -= 1;
        let remote = match hash_client.peer_hashes(peer, device, partition, policy_index) {
            Ok(remote) => remote,
            Err(SuffixHashError::InsufficientStorage) => {
                stats.failures += 1;
                // Replace this unavailable primary with the next handoff.
                attempts_left += 1;
                continue;
            }
            Err(SuffixHashError::Failed) => {
                stats.failures += 1;
                continue;
            }
        };
        let diff = divergent_suffixes(&local, &remote);
        if diff.is_empty() {
            continue;
        }
        {
            let _sync =
                swift_core::stage::StageTimer::start("object-replicator", "replication", "sync");
            if syncer
                .sync_suffixes(partition_path, peer, device, partition, &diff, policy_index)
                .is_some()
            {
                stats.suffix_syncs += diff.len() as u64;
            } else {
                stats.failures += 1;
            }
        }
    }
}

/// Python's handoff revert lock budget: background replication must yield
/// quickly to an incoming SSYNC receiver or a foreground mutation.
const REPLICATION_LOCK_TIMEOUT: f64 = 0.2;

/// Handoff cleanup is background work. If a foreground request owns an object
/// stripe, leave that exact generation for the next pass rather than deleting
/// from a stale snapshot or stalling the whole partition.
const HANDOFF_OBJECT_LOCK_TIMEOUT: f64 = 0.2;

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileIdentity {
    name: String,
    device: u64,
    inode: u64,
    len: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HashDirIdentity {
    device: u64,
    inode: u64,
    files: Vec<FileIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PreObjectSnapshot {
    suffix: String,
    timestamps: Option<ObjectTimestamps>,
    identity: HashDirIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ObjectSnapshot {
    suffix: String,
    object_hash: String,
    timestamps: ObjectTimestamps,
    identity: HashDirIdentity,
}

/// Derive the same logical timestamp tuple that the SSYNC sender offers during
/// missing-check. A meta-only or otherwise invalid directory has no offerable
/// object state and must never become handoff-deletion authority.
fn current_object_timestamps(hash_dir: &Path) -> Option<ObjectTimestamps> {
    object_timestamps_from_hash_dir(hash_dir, PolicyKind::Replication, None, None)
}

fn snapshot_hash_dir(hash_dir: &Path) -> Option<HashDirIdentity> {
    let dir_metadata = hash_dir.symlink_metadata().ok()?;
    if !dir_metadata.file_type().is_dir() {
        return None;
    }
    let entries = std::fs::read_dir(hash_dir).ok()?;
    let mut files = Vec::new();
    for entry in entries {
        let entry = entry.ok()?;
        let metadata = entry.path().symlink_metadata().ok()?;
        if !metadata.file_type().is_file() {
            return None;
        }
        files.push(FileIdentity {
            name: entry.file_name().to_str()?.to_string(),
            device: metadata.dev(),
            inode: metadata.ino(),
            len: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        });
    }
    files.sort_by(|left, right| left.name.cmp(&right.name));
    Some(HashDirIdentity {
        device: dir_metadata.dev(),
        inode: dir_metadata.ino(),
        files,
    })
}

fn is_lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Strictly census every object directory before transfer. Unknown entries,
/// symlinks and malformed suffix/hash layouts make the pass retry rather than
/// silently treating an incompletely understood partition as empty.
fn snapshot_all_object_files(
    partition_path: &Path,
    policy_index: u32,
) -> Option<BTreeMap<String, PreObjectSnapshot>> {
    let device_path = partition_path.parent().and_then(Path::parent)?;
    let lock_dir = device_path
        .join(get_tmp_dir(policy_index))
        .join("object-mutation-locks");
    let mut snapshots = BTreeMap::new();
    for partition_entry in std::fs::read_dir(partition_path).ok()? {
        let partition_entry = partition_entry.ok()?;
        let name = partition_entry.file_name().to_str()?.to_string();
        let metadata = partition_entry.path().symlink_metadata().ok()?;
        if metadata.file_type().is_file()
            && matches!(
                name.as_str(),
                ".lock" | ".lock-replication" | "hashes.pkl" | "hashes.invalid"
            )
        {
            continue;
        }
        if !metadata.file_type().is_dir() || !is_lower_hex(&name, 3) {
            return None;
        }
        let _mutation_guard = swift_core::lockutil::lock_path(
            &lock_dir,
            HANDOFF_OBJECT_LOCK_TIMEOUT,
            Some(&format!("obj-{name}")),
        )
        .ok()?;
        for hash_entry in std::fs::read_dir(partition_entry.path()).ok()? {
            let hash_entry = hash_entry.ok()?;
            let object_hash = hash_entry.file_name().to_str()?.to_string();
            let hash_metadata = hash_entry.path().symlink_metadata().ok()?;
            if !hash_metadata.file_type().is_dir()
                || !is_lower_hex(&object_hash, 32)
                || !object_hash.ends_with(&name)
            {
                return None;
            }
            let snapshot = PreObjectSnapshot {
                suffix: name.clone(),
                timestamps: current_object_timestamps(&hash_entry.path()),
                identity: snapshot_hash_dir(&hash_entry.path())?,
            };
            if snapshots.insert(object_hash, snapshot).is_some() {
                return None;
            }
        }
    }
    Some(snapshots)
}

/// Freeze only source generations that SSYNC successfully confirmed on every
/// required primary. A generation changed after SSYNC is omitted here and will
/// remain for the next replicator pass.
fn snapshot_confirmed_objects(
    partition_path: &Path,
    confirmed: &BTreeMap<String, ObjectTimestamps>,
    before_transfer: &BTreeMap<String, PreObjectSnapshot>,
) -> Option<Vec<ObjectSnapshot>> {
    let mut snapshots = Vec::new();
    for (object_hash, expected_timestamps) in confirmed {
        if !is_lower_hex(object_hash, 32) {
            return None;
        }
        let suffix = object_hash[object_hash.len() - 3..].to_string();
        let Some(before) = before_transfer.get(object_hash) else {
            continue;
        };
        if before.suffix != suffix || before.timestamps.as_ref() != Some(expected_timestamps) {
            continue;
        }
        let hash_dir = partition_path.join(&suffix).join(object_hash);
        if current_object_timestamps(&hash_dir).as_ref() != Some(expected_timestamps) {
            continue;
        }
        let Some(files) = snapshot_hash_dir(&hash_dir) else {
            continue;
        };
        if files != before.identity {
            continue;
        }
        snapshots.push(ObjectSnapshot {
            suffix,
            object_hash: object_hash.clone(),
            timestamps: expected_timestamps.clone(),
            identity: files,
        });
    }
    Some(snapshots)
}

fn intersect_confirmations(
    peer_confirmations: &[BTreeMap<String, ObjectTimestamps>],
) -> BTreeMap<String, ObjectTimestamps> {
    let Some((first, rest)) = peer_confirmations.split_first() else {
        return BTreeMap::new();
    };
    let mut common = first.clone();
    for confirmations in rest {
        common.retain(|object_hash, timestamps| confirmations.get(object_hash) == Some(timestamps));
    }
    common
}

fn valid_confirmation_map(
    confirmations: &BTreeMap<String, ObjectTimestamps>,
    requested_suffixes: &[String],
) -> bool {
    confirmations.keys().all(|object_hash| {
        is_lower_hex(object_hash, 32)
            && requested_suffixes
                .iter()
                .any(|suffix| object_hash.ends_with(suffix))
    })
}

/// Purge only the exact source generations observed before SSYNC. The
/// partition directory and its persistent lock inode are intentionally kept;
/// recursive partition deletion would let a waiter lock a replacement inode
/// while an older holder still owns the unlinked one.
fn purge_handoff_snapshot(
    partition_path: &Path,
    policy_index: u32,
    snapshots: &[ObjectSnapshot],
) -> bool {
    let Some(device_path) = partition_path.parent().and_then(Path::parent) else {
        return false;
    };
    let lock_dir = device_path
        .join(get_tmp_dir(policy_index))
        .join("object-mutation-locks");
    let mut complete = true;
    for snapshot in snapshots {
        let stripe = &snapshot.object_hash[snapshot.object_hash.len() - 3..];
        let lock_name = format!("obj-{stripe}");
        let Ok(_mutation_guard) = swift_core::lockutil::lock_path(
            &lock_dir,
            HANDOFF_OBJECT_LOCK_TIMEOUT,
            Some(&lock_name),
        ) else {
            complete = false;
            continue;
        };
        let suffix_dir = partition_path.join(&snapshot.suffix);
        let hash_dir = suffix_dir.join(&snapshot.object_hash);
        if current_object_timestamps(&hash_dir).as_ref() != Some(&snapshot.timestamps) {
            complete = false;
            continue;
        }
        let Some(current) = snapshot_hash_dir(&hash_dir) else {
            if hash_dir.exists() {
                complete = false;
            }
            continue;
        };
        if current != snapshot.identity {
            complete = false;
            continue;
        }
        let mut object_removed = true;
        for file in &snapshot.identity.files {
            if let Err(error) = std::fs::remove_file(hash_dir.join(&file.name)) {
                if error.kind() != std::io::ErrorKind::NotFound {
                    object_removed = false;
                }
            }
        }
        if let Err(error) = std::fs::remove_dir(&hash_dir) {
            if error.kind() != std::io::ErrorKind::NotFound {
                object_removed = false;
            }
        }
        if invalidate_hash(&suffix_dir).is_err() {
            object_removed = false;
        }
        if object_removed {
            let _ = std::fs::remove_dir(&suffix_dir);
        } else {
            complete = false;
        }
    }
    match snapshot_all_object_files(partition_path, policy_index) {
        Some(remaining) if remaining.is_empty() => complete,
        _ => false,
    }
}

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
    syncer: &dyn SuffixSyncer,
    stats: &mut ReplicatorStats,
) -> bool {
    revert_handoff_guarded(
        partition_path,
        device,
        partition,
        policy_index,
        primaries,
        syncer,
        stats,
        &mut || true,
    )
}

/// Guarded handoff revert. The caller revalidates the ring generation and
/// local mount after the network phase but before any source deletion.
#[allow(clippy::too_many_arguments)]
pub fn revert_handoff_guarded(
    partition_path: &Path,
    device: &str,
    partition: u32,
    policy_index: u32,
    primaries: &[&RingDevice],
    syncer: &dyn SuffixSyncer,
    stats: &mut ReplicatorStats,
    before_purge: &mut dyn FnMut() -> bool,
) -> bool {
    // Python `update_deleted` wraps the whole revert in the partition
    // 'replication' lock (`DiskFileManager.replication_lock`, default
    // short replication lock timeout) so an incoming SSYNC/receiver on the
    // same partition cannot race the delete. A timeout skips the handoff for
    // this pass — a lock-failure, not an error.
    let Ok(_lock) = swift_core::lockutil::lock_path(
        partition_path,
        REPLICATION_LOCK_TIMEOUT,
        Some("replication"),
    ) else {
        return false;
    };
    let Some(before_transfer) = snapshot_all_object_files(partition_path, policy_index) else {
        stats.failures += 1;
        return false;
    };
    if before_transfer.is_empty() {
        // Keep the persistent partition lock inode, but do not count the same
        // lock-only directory as a newly reverted handoff on every pass.
        return false;
    }
    let suffixes = suffix_dirs(partition_path);
    let mut all_ok = !primaries.is_empty();
    let mut peer_confirmations = Vec::new();
    for peer in primaries {
        match syncer.sync_suffixes(
            partition_path,
            peer,
            device,
            partition,
            &suffixes,
            policy_index,
        ) {
            Some(report)
                if !report.limited_by_max_objects
                    && valid_confirmation_map(&report.can_delete_objs, &suffixes) =>
            {
                stats.suffix_syncs += suffixes.len() as u64;
                peer_confirmations.push(report.can_delete_objs);
            }
            Some(_) | None => all_ok = false,
        }
    }
    if all_ok {
        if !before_purge() {
            // Ring generation or mount ownership changed while SSYNC was in
            // flight. The remote copies may be useful, but none of that work
            // authorizes deletion under the old topology.
            return false;
        }
        let confirmed = intersect_confirmations(&peer_confirmations);
        let Some(snapshot) =
            snapshot_confirmed_objects(partition_path, &confirmed, &before_transfer)
        else {
            stats.failures += 1;
            return false;
        };
        if purge_handoff_snapshot(partition_path, policy_index, &snapshot) {
            stats.reverts += 1;
            return true;
        }
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
    run_once_guarded(
        device_dir,
        device,
        policy_index,
        policy,
        cleanup,
        ring,
        local_id,
        hash_client,
        syncer,
        &mut || ReplicationJobGuard::Continue,
    )
}

/// One replication pass with a fail-closed check immediately before every
/// partition job. The daemon uses this to abort on ring replacement or a lost
/// mount; the simpler [`run_once`] remains useful for deterministic library
/// tests and callers with an immutable in-memory ring.
#[allow(clippy::too_many_arguments)]
pub fn run_once_guarded(
    device_dir: &Path,
    device: &str,
    policy_index: u32,
    policy: PolicyKind,
    cleanup: &CleanupConfig,
    ring: &Ring,
    local_id: u64,
    hash_client: &dyn SuffixHashClient,
    syncer: &dyn SuffixSyncer,
    job_guard: &mut dyn FnMut() -> ReplicationJobGuard,
) -> ReplicatorStats {
    let mut stats = ReplicatorStats::default();
    if ring.next_part_power().is_some() {
        stats.skipped_next_part_power = true;
        return stats;
    }
    // replicator.py 855-857: before scanning partitions, each pass reaps the
    // temp files that crashed PUTs orphaned in the device tmp dir, once they
    // are older than reclaim_age.
    let reclaim_age = if cleanup.reclaim_age.is_finite() && cleanup.reclaim_age > 0.0 {
        cleanup.reclaim_age
    } else {
        0.0
    };
    if let Some(cutoff) =
        std::time::SystemTime::now().checked_sub(std::time::Duration::from_secs_f64(reclaim_age))
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
        match job_guard() {
            ReplicationJobGuard::Continue => {}
            ReplicationJobGuard::RingChanged => {
                stats.aborted_ring_change = true;
                return stats;
            }
            ReplicationJobGuard::DeviceUnavailable => {
                stats.aborted_device = true;
                stats.failures += 1;
                return stats;
            }
        }
        stats.partitions += 1;
        let Ok(nodes) = ring.get_part_nodes(partition) else {
            stats.failures += 1;
            continue;
        };
        let primaries: Vec<&RingDevice> = nodes.iter().map(|n| n.dev).collect();
        if primaries.iter().any(|d| d.id == local_id) {
            let peers: Vec<&RingDevice> = primaries
                .iter()
                .copied()
                .filter(|d| d.id != local_id)
                .collect();
            let handoffs: Vec<&RingDevice> = match ring.get_more_nodes(partition) {
                Ok(nodes) => nodes.into_iter().map(|node| node.dev).collect(),
                Err(_) => {
                    stats.failures += 1;
                    Vec::new()
                }
            };
            replicate_partition(
                &path,
                device,
                partition,
                policy_index,
                policy,
                cleanup,
                &peers,
                &handoffs,
                hash_client,
                syncer,
                &mut stats,
            );
        } else {
            let mut final_guard = ReplicationJobGuard::Continue;
            revert_handoff_guarded(
                &path,
                device,
                partition,
                policy_index,
                &primaries,
                syncer,
                &mut stats,
                &mut || {
                    final_guard = job_guard();
                    final_guard == ReplicationJobGuard::Continue
                },
            );
            match final_guard {
                ReplicationJobGuard::Continue => {}
                ReplicationJobGuard::RingChanged => {
                    stats.aborted_ring_change = true;
                    return stats;
                }
                ReplicationJobGuard::DeviceUnavailable => {
                    stats.aborted_device = true;
                    stats.failures += 1;
                    return stats;
                }
            }
        }
    }
    stats
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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

    fn ring3_with_next_part_power() -> Ring {
        let devs = vec![Some(dev(0)), Some(dev(1)), Some(dev(2))];
        let r2p2d = vec![vec![0u32], vec![1u32], vec![2u32]];
        let mut data = RingData::from_parts(devs, 32, r2p2d);
        data.next_part_power = Some(1);
        Ring::new(data, HashPathConfig::new("", "changeme").unwrap())
    }

    /// Partition 0 primaries are 0/1/2; device 3 is discoverable as a handoff
    /// through partition 1.
    fn ring4_with_handoff() -> Ring {
        let devs = vec![Some(dev(0)), Some(dev(1)), Some(dev(2)), Some(dev(3))];
        let r2p2d = vec![vec![0u32, 3], vec![1u32, 0], vec![2u32, 1]];
        Ring::new(
            RingData::from_parts(devs, 31, r2p2d),
            HashPathConfig::new("", "changeme").unwrap(),
        )
    }

    #[derive(Default)]
    struct FakeHashClient {
        /// suffix->hash the peer reports (empty = peer has nothing).
        remote: SuffixHashMap,
        hashed: Mutex<Vec<(u64, Vec<String>)>>,
        unmounted_peer: Option<u64>,
    }
    impl SuffixHashClient for FakeHashClient {
        fn peer_hashes(
            &self,
            peer: &RingDevice,
            _device: &str,
            _partition: u32,
            _policy_index: u32,
        ) -> Result<SuffixHashMap, SuffixHashError> {
            self.hashed.lock().unwrap().push((peer.id, vec![]));
            if self.unmounted_peer == Some(peer.id) {
                Err(SuffixHashError::InsufficientStorage)
            } else {
                Ok(self.remote.clone())
            }
        }
    }

    fn fake_report(local_partition_dir: &Path, suffixes: &[String]) -> Option<SenderReport> {
        let mut report = SenderReport::default();
        for suffix in suffixes {
            let suffix_dir = local_partition_dir.join(suffix);
            for entry in std::fs::read_dir(suffix_dir).ok()?.flatten() {
                let object_hash = entry.file_name().to_str()?.to_string();
                if is_lower_hex(&object_hash, 32) {
                    if let Some(timestamps) = current_object_timestamps(&entry.path()) {
                        report.can_delete_objs.insert(object_hash, timestamps);
                    }
                }
            }
        }
        Some(report)
    }

    struct FakeSyncer {
        synced: Mutex<Vec<(u64, String)>>,
        fail_peer: Option<u64>,
        omit_confirmations_peer: Option<u64>,
    }
    impl SuffixSyncer for FakeSyncer {
        fn sync_suffixes(
            &self,
            local_partition_dir: &Path,
            peer: &RingDevice,
            _device: &str,
            _partition: u32,
            suffixes: &[String],
            _policy_index: u32,
        ) -> Option<SenderReport> {
            self.synced
                .lock()
                .unwrap()
                .extend(suffixes.iter().cloned().map(|suffix| (peer.id, suffix)));
            if self.fail_peer == Some(peer.id) {
                return None;
            }
            if self.omit_confirmations_peer == Some(peer.id) {
                return Some(SenderReport::default());
            }
            fake_report(local_partition_dir, suffixes)
        }
    }

    #[test]
    fn test_divergent_suffixes() {
        let local = HashMap::from([
            ("abc".to_string(), Some("h1".to_string())),
            ("def".to_string(), Some("h2".to_string())),
        ]);
        // peer matches abc, missing def -> only def is divergent
        let remote = HashMap::from([("abc".to_string(), Some("h1".to_string()))]);
        assert_eq!(divergent_suffixes(&local, &remote), vec!["def".to_string()]);
        // peer has a stale abc -> abc is divergent too
        let remote2 = HashMap::from([("abc".to_string(), Some("STALE".to_string()))]);
        assert_eq!(
            divergent_suffixes(&local, &remote2),
            vec!["abc".to_string(), "def".to_string()]
        );
        // peer fully matches -> nothing to push
        assert!(divergent_suffixes(&local, &local).is_empty());

        // An invalidated local suffix remains present. A peer that omits it
        // must trigger SSYNC rather than looking like two empty maps.
        let invalid = HashMap::from([("abc".to_string(), None)]);
        assert_eq!(
            divergent_suffixes(&invalid, &HashMap::new()),
            vec!["abc".to_string()]
        );
    }

    #[test]
    fn test_hashes_pickle_roundtrip() {
        let value = Value::Dict(vec![(
            Value::Str("abc".to_string()),
            Value::Str("0123456789abcdef0123456789abcdef".to_string()),
        )]);
        let body = pickle::dumps(&value).unwrap();
        let map = hashes_from_pickle(&body).unwrap();
        assert_eq!(
            map.get("abc").and_then(Option::as_deref),
            Some("0123456789abcdef0123456789abcdef")
        );

        let invalid = Value::Dict(vec![(Value::Str("def".to_string()), Value::None)]);
        let invalid_map = hashes_from_pickle(&pickle::dumps(&invalid).unwrap()).unwrap();
        assert_eq!(invalid_map.get("def"), Some(&None));
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
        let sy = FakeSyncer {
            synced: Mutex::new(Vec::new()),
            fail_peer: None,
            omit_confirmations_peer: None,
        };
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
        let queried: Vec<u64> = hc
            .hashed
            .lock()
            .unwrap()
            .iter()
            .map(|(id, _)| *id)
            .collect();
        assert_eq!(queried, vec![1, 2]); // both peer primaries, not self
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn test_unmounted_primary_slot_retries_on_handoff_node() {
        let root = tmpdir("primary-handoff-fallback");
        let part = root.join("sdb1/objects/0");
        std::fs::create_dir_all(&part).unwrap();
        let hc = FakeHashClient {
            unmounted_peer: Some(1),
            ..FakeHashClient::default()
        };
        let sy = FakeSyncer {
            synced: Mutex::new(Vec::new()),
            fail_peer: None,
            omit_confirmations_peer: None,
        };
        let stats = run_once(
            &root.join("sdb1"),
            "sdb1",
            0,
            PolicyKind::Replication,
            &CleanupConfig::default(),
            &ring4_with_handoff(),
            0,
            &hc,
            &sy,
        );
        let queried: Vec<u64> = hc
            .hashed
            .lock()
            .unwrap()
            .iter()
            .map(|(id, _)| *id)
            .collect();
        assert_eq!(queried, vec![1, 2, 3]);
        assert_eq!(stats.failures, 1, "the unavailable primary is observable");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn test_ring_change_guard_aborts_before_handoff_network_or_purge() {
        let root = tmpdir("ring-change-handoff");
        let device = root.join("sdb9");
        let hash_dir = device
            .join("objects/0/abc")
            .join("00000000000000000000000000000abc");
        std::fs::create_dir_all(&hash_dir).unwrap();
        std::fs::write(hash_dir.join("1700000000.00000.data"), b"source").unwrap();
        let hc = FakeHashClient::default();
        let sy = FakeSyncer {
            synced: Mutex::new(Vec::new()),
            fail_peer: None,
            omit_confirmations_peer: None,
        };
        let stats = run_once_guarded(
            &device,
            "sdb9",
            0,
            PolicyKind::Replication,
            &CleanupConfig::default(),
            &ring3(),
            99,
            &hc,
            &sy,
            &mut || ReplicationJobGuard::RingChanged,
        );
        assert!(stats.aborted_ring_change);
        assert_eq!(stats.partitions, 0);
        assert_eq!(stats.reverts, 0);
        assert!(sy.synced.lock().unwrap().is_empty());
        assert!(hash_dir.exists(), "old-ring state must not authorize purge");
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn test_ring_change_after_ssync_aborts_before_handoff_purge() {
        let root = tmpdir("ring-change-after-ssync");
        let device = root.join("sdb9");
        let hash_dir = device
            .join("objects/0/abc")
            .join("00000000000000000000000000000abc");
        std::fs::create_dir_all(&hash_dir).unwrap();
        std::fs::write(hash_dir.join("1700000000.00000.data"), b"source").unwrap();
        let hc = FakeHashClient::default();
        let sy = FakeSyncer {
            synced: Mutex::new(Vec::new()),
            fail_peer: None,
            omit_confirmations_peer: None,
        };
        let guard_calls = AtomicUsize::new(0);
        let stats = run_once_guarded(
            &device,
            "sdb9",
            0,
            PolicyKind::Replication,
            &CleanupConfig::default(),
            &ring3(),
            99,
            &hc,
            &sy,
            &mut || {
                if guard_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    ReplicationJobGuard::Continue
                } else {
                    ReplicationJobGuard::RingChanged
                }
            },
        );
        assert!(stats.aborted_ring_change);
        assert_eq!(stats.reverts, 0);
        assert_eq!(sy.synced.lock().unwrap().len(), 3);
        assert!(
            hash_dir.exists(),
            "a ring replacement after transfer must revoke deletion authority"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn test_next_part_power_skips_before_handoff_network_or_purge() {
        let root = tmpdir("next-part-power-handoff");
        let device = root.join("sdb9");
        let hash_dir = device
            .join("objects/0/abc")
            .join("00000000000000000000000000000abc");
        std::fs::create_dir_all(&hash_dir).unwrap();
        std::fs::write(hash_dir.join("1700000000.00000.data"), b"source").unwrap();
        let hc = FakeHashClient::default();
        let sy = FakeSyncer {
            synced: Mutex::new(Vec::new()),
            fail_peer: None,
            omit_confirmations_peer: None,
        };
        let stats = run_once(
            &device,
            "sdb9",
            0,
            PolicyKind::Replication,
            &CleanupConfig::default(),
            &ring3_with_next_part_power(),
            99,
            &hc,
            &sy,
        );
        assert!(stats.skipped_next_part_power);
        assert_eq!(stats.partitions, 0);
        assert!(sy.synced.lock().unwrap().is_empty());
        assert!(hash_dir.exists());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn test_run_once_handoff_reverts_and_deletes() {
        // Local device id 99 is NOT a primary -> handoff. One suffix present.
        let root = tmpdir("handoff");
        let part = root.join("sdb9/objects/0");
        let suffix = part.join("abc");
        let hash_dir = suffix.join("00000000000000000000000000000abc");
        std::fs::create_dir_all(&hash_dir).unwrap();
        std::fs::write(hash_dir.join("1700000000.00000.data"), b"x").unwrap();
        std::fs::write(hash_dir.join(".1700000000.00000.data.6MbL6r"), b"partial").unwrap();
        drop(
            swift_core::lockutil::lock_path(&part, 1.0, Some("replication"))
                .expect("create the persistent partition lock inode"),
        );
        let lock_path = part.join(".lock-replication");
        let lock_inode_before = std::fs::metadata(&lock_path).unwrap().ino();
        let hc = FakeHashClient::default();
        let sy = FakeSyncer {
            synced: Mutex::new(Vec::new()),
            fail_peer: None,
            omit_confirmations_peer: None,
        };
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
        let peers: Vec<u64> = sy
            .synced
            .lock()
            .unwrap()
            .iter()
            .map(|(id, _)| *id)
            .collect();
        assert_eq!(peers, vec![0, 1, 2]);
        assert!(
            !hash_dir.exists(),
            "the exact transferred generation is purged"
        );
        assert!(
            part.exists(),
            "the partition remains as the home of its persistent lock inode"
        );
        assert_eq!(
            std::fs::metadata(&lock_path).unwrap().ino(),
            lock_inode_before,
            "handoff cleanup must never unlink and replace the active lock inode"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn test_lock_only_handoff_is_not_recounted_or_failed() {
        let root = tmpdir("handoff-lock-only");
        let part = root.join("sdb9/objects/0");
        std::fs::create_dir_all(&part).unwrap();
        drop(
            swift_core::lockutil::lock_path(&part, 1.0, Some("replication"))
                .expect("create the persistent partition lock inode"),
        );
        let lock_inode = std::fs::metadata(part.join(".lock-replication"))
            .unwrap()
            .ino();
        let hc = FakeHashClient::default();
        let sy = FakeSyncer {
            synced: Mutex::new(Vec::new()),
            fail_peer: None,
            omit_confirmations_peer: None,
        };
        for _ in 0..2 {
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
            assert_eq!(stats.failures, 0);
        }
        assert_eq!(
            std::fs::metadata(part.join(".lock-replication"))
                .unwrap()
                .ino(),
            lock_inode
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn test_handoff_busy_object_stripe_is_retryable_and_preserves_source() {
        let root = tmpdir("handoff-busy-stripe");
        let device = root.join("sdb9");
        let part = device.join("objects/0");
        let hash_dir = part.join("abc").join("00000000000000000000000000000abc");
        std::fs::create_dir_all(&hash_dir).unwrap();
        std::fs::write(hash_dir.join("1700000000.00000.data"), b"x").unwrap();
        let lock_dir = device.join("tmp/object-mutation-locks");
        let _busy = swift_core::lockutil::lock_path(&lock_dir, 1.0, Some("obj-abc"))
            .expect("hold foreground object stripe");
        let hc = FakeHashClient::default();
        let sy = FakeSyncer {
            synced: Mutex::new(Vec::new()),
            fail_peer: None,
            omit_confirmations_peer: None,
        };
        let stats = run_once(
            &device,
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
        assert!(hash_dir.exists());
        assert!(sy.synced.lock().unwrap().is_empty());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn test_handoff_malformed_or_symlink_entries_fail_closed() {
        let root = tmpdir("handoff-invalid-layout");
        let device = root.join("sdb9");
        let part = device.join("objects/0");
        let valid_hash = part.join("abc").join("00000000000000000000000000000abc");
        std::fs::create_dir_all(&valid_hash).unwrap();
        std::fs::write(valid_hash.join("1700000000.00000.data"), b"valid").unwrap();
        let target = root.join("outside-hash");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::create_dir_all(part.join("def")).unwrap();
        std::os::unix::fs::symlink(
            &target,
            part.join("def").join("00000000000000000000000000000def"),
        )
        .unwrap();
        std::fs::create_dir_all(part.join("ABC")).unwrap();
        let hc = FakeHashClient::default();
        let sy = FakeSyncer {
            synced: Mutex::new(Vec::new()),
            fail_peer: None,
            omit_confirmations_peer: None,
        };
        let stats = run_once(
            &device,
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
        assert!(valid_hash.exists());
        assert!(sy.synced.lock().unwrap().is_empty());
        std::fs::remove_dir_all(&root).unwrap();
    }

    struct InjectingSyncer {
        partition: std::path::PathBuf,
        injected: AtomicBool,
    }

    impl SuffixSyncer for InjectingSyncer {
        fn sync_suffixes(
            &self,
            local_partition_dir: &Path,
            peer: &RingDevice,
            _device: &str,
            _partition: u32,
            suffixes: &[String],
            _policy_index: u32,
        ) -> Option<SenderReport> {
            let report = fake_report(local_partition_dir, suffixes)?;
            if peer.id == 2 && !self.injected.swap(true, Ordering::SeqCst) {
                let new_hash = self
                    .partition
                    .join("def")
                    .join("00000000000000000000000000000def");
                std::fs::create_dir_all(&new_hash).unwrap();
                std::fs::write(new_hash.join("1700000001.00000.data"), b"new").unwrap();
            }
            Some(report)
        }
    }

    #[test]
    fn test_handoff_cleanup_preserves_object_created_after_sync_snapshot() {
        let root = tmpdir("handoff-race");
        let part = root.join("sdb9/objects/0");
        let old_hash = part.join("abc").join("00000000000000000000000000000abc");
        std::fs::create_dir_all(&old_hash).unwrap();
        std::fs::write(old_hash.join("1700000000.00000.data"), b"old").unwrap();
        let new_hash = part.join("def").join("00000000000000000000000000000def");
        let hc = FakeHashClient::default();
        let sy = InjectingSyncer {
            partition: part.clone(),
            injected: AtomicBool::new(false),
        };
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
        assert_eq!(stats.reverts, 0, "a changed handoff is not fully reverted");
        assert_eq!(stats.failures, 1, "the next pass must retry the handoff");
        assert!(!old_hash.exists(), "the transferred snapshot may be purged");
        assert!(
            new_hash.exists(),
            "an object created after the snapshot must never be recursively deleted"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn test_handoff_cleanup_requires_every_primary_confirmation() {
        let root = tmpdir("handoff-confirm-all");
        let part = root.join("sdb9/objects/0");
        let hash_dir = part.join("abc").join("00000000000000000000000000000abc");
        std::fs::create_dir_all(&hash_dir).unwrap();
        std::fs::write(hash_dir.join("1700000000.00000.data"), b"old").unwrap();
        let hc = FakeHashClient::default();
        let sy = FakeSyncer {
            synced: Mutex::new(Vec::new()),
            fail_peer: None,
            omit_confirmations_peer: Some(1),
        };
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
        assert!(
            hash_dir.exists(),
            "one primary omitting the exact timestamp must veto source deletion"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    struct MismatchingSyncer;

    impl SuffixSyncer for MismatchingSyncer {
        fn sync_suffixes(
            &self,
            local_partition_dir: &Path,
            peer: &RingDevice,
            _device: &str,
            _partition: u32,
            suffixes: &[String],
            _policy_index: u32,
        ) -> Option<SenderReport> {
            let mut report = fake_report(local_partition_dir, suffixes)?;
            if peer.id == 1 {
                for timestamps in report.can_delete_objs.values_mut() {
                    timestamps.ts_data = "1700000001.00000".parse().unwrap();
                }
            }
            Some(report)
        }
    }

    #[test]
    fn test_handoff_cleanup_rejects_cross_primary_timestamp_disagreement() {
        let root = tmpdir("handoff-timestamp-mismatch");
        let part = root.join("sdb9/objects/0");
        let hash_dir = part.join("abc").join("00000000000000000000000000000abc");
        std::fs::create_dir_all(&hash_dir).unwrap();
        std::fs::write(hash_dir.join("1700000000.00000.data"), b"old").unwrap();
        let stats = run_once(
            &root.join("sdb9"),
            "sdb9",
            0,
            PolicyKind::Replication,
            &CleanupConfig::default(),
            &ring3(),
            99,
            &FakeHashClient::default(),
            &MismatchingSyncer,
        );
        assert_eq!(stats.reverts, 0);
        assert_eq!(stats.failures, 1);
        assert!(hash_dir.exists());
        std::fs::remove_dir_all(&root).unwrap();
    }

    struct TruncatedSyncer;

    impl SuffixSyncer for TruncatedSyncer {
        fn sync_suffixes(
            &self,
            local_partition_dir: &Path,
            _peer: &RingDevice,
            _device: &str,
            _partition: u32,
            suffixes: &[String],
            _policy_index: u32,
        ) -> Option<SenderReport> {
            let mut report = fake_report(local_partition_dir, suffixes)?;
            report.limited_by_max_objects = true;
            Some(report)
        }
    }

    #[test]
    fn test_handoff_cleanup_rejects_truncated_sender_report() {
        let root = tmpdir("handoff-truncated");
        let part = root.join("sdb9/objects/0");
        let hash_dir = part.join("abc").join("00000000000000000000000000000abc");
        std::fs::create_dir_all(&hash_dir).unwrap();
        std::fs::write(hash_dir.join("1700000000.00000.data"), b"old").unwrap();
        let stats = run_once(
            &root.join("sdb9"),
            "sdb9",
            0,
            PolicyKind::Replication,
            &CleanupConfig::default(),
            &ring3(),
            99,
            &FakeHashClient::default(),
            &TruncatedSyncer,
        );
        assert_eq!(stats.reverts, 0);
        assert_eq!(stats.failures, 1);
        assert!(hash_dir.exists());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn test_handoff_cleanup_never_deletes_unoffered_meta_only_hash() {
        let root = tmpdir("handoff-meta-only");
        let part = root.join("sdb9/objects/0");
        let hash_dir = part.join("abc").join("00000000000000000000000000000abc");
        std::fs::create_dir_all(&hash_dir).unwrap();
        std::fs::write(hash_dir.join("1700000000.00000.meta"), b"meta-only").unwrap();
        let hc = FakeHashClient::default();
        let sy = FakeSyncer {
            synced: Mutex::new(Vec::new()),
            fail_peer: None,
            omit_confirmations_peer: None,
        };
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
        assert!(
            hash_dir.exists(),
            "a hash that SSYNC cannot offer is never deletion-authorized"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    struct ReplacingSyncer {
        data_file: std::path::PathBuf,
        replaced: AtomicBool,
    }

    impl SuffixSyncer for ReplacingSyncer {
        fn sync_suffixes(
            &self,
            local_partition_dir: &Path,
            peer: &RingDevice,
            _device: &str,
            _partition: u32,
            suffixes: &[String],
            _policy_index: u32,
        ) -> Option<SenderReport> {
            let report = fake_report(local_partition_dir, suffixes)?;
            if peer.id == 2 && !self.replaced.swap(true, Ordering::SeqCst) {
                std::fs::remove_file(&self.data_file).unwrap();
                std::fs::write(&self.data_file, b"replacement-at-the-same-timestamp").unwrap();
            }
            Some(report)
        }
    }

    #[test]
    fn test_handoff_cleanup_rejects_same_timestamp_inode_replacement() {
        let root = tmpdir("handoff-replaced-inode");
        let part = root.join("sdb9/objects/0");
        let hash_dir = part.join("abc").join("00000000000000000000000000000abc");
        std::fs::create_dir_all(&hash_dir).unwrap();
        let data_file = hash_dir.join("1700000000.00000.data");
        std::fs::write(&data_file, b"old").unwrap();
        let hc = FakeHashClient::default();
        let sy = ReplacingSyncer {
            data_file: data_file.clone(),
            replaced: AtomicBool::new(false),
        };
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
        assert_eq!(
            std::fs::read(&data_file).unwrap(),
            b"replacement-at-the-same-timestamp",
            "logical timestamp equality cannot authorize deleting a replaced inode"
        );
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
        let sy = FakeSyncer {
            synced: Mutex::new(Vec::new()),
            fail_peer: None,
            omit_confirmations_peer: None,
        };
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
        let hash_dir = part.join("abc").join("00000000000000000000000000000abc");
        std::fs::create_dir_all(&hash_dir).unwrap();
        std::fs::write(hash_dir.join("1700000000.00000.data"), b"x").unwrap();
        let hc = FakeHashClient::default();
        let sy = FakeSyncer {
            synced: Mutex::new(Vec::new()),
            fail_peer: Some(2),
            omit_confirmations_peer: None,
        };
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
