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

//! The db_replicator client (push side), ported from the DB-level path
//! of `swift/common/db_replicator.py`: contact a peer's REPLICATE
//! endpoint, negotiate with a `sync` RPC, then usync all local object
//! rows the peer has not yet seen via `merge_items`, falling back to a
//! staged full-DB rsync (`_rsync_db` -> `complete_rsync` /
//! `rsync_then_merge`) when the peer has no DB or has diverged too far.
//!
//! Deferred: the daemon loop (partition scan + ring-based peer
//! discovery) and outgoing-sync bookkeeping.

use std::cmp::Ordering;
use std::io::{Read, Write};

use crate::container::{DbState, DbValue, GetShardRangesArgs};
use crate::shard_state;
use crate::{py_json_parse_metadata, AccountBroker, ContainerBroker, DbError, ShardRange};
use swift_core::config::SwiftConfig;
use swift_core::hashing::HashPathConfig;
use swift_core::timestamp::Timestamp;
use swift_ring::{Ring, RingData, RingDevice};

const PER_DIFF: i64 = 1000;
const MAX_DIFFS: i64 = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ContainerPolicyInfo {
    put_timestamp: Timestamp,
    delete_timestamp: Timestamp,
    status_changed_at: Timestamp,
    count: i64,
    storage_policy_index: i64,
}

impl ContainerPolicyInfo {
    fn is_deleted(self) -> bool {
        self.delete_timestamp > self.put_timestamp && self.count == 0
    }

    fn has_been_recreated(self) -> bool {
        self.put_timestamp > self.delete_timestamp && self.delete_timestamp > Timestamp::zero()
    }
}

fn ordering_i8(ordering: Ordering) -> i8 {
    match ordering {
        Ordering::Less => -1,
        Ordering::Equal => 0,
        Ordering::Greater => 1,
    }
}

/// Exact port of `swift.container.reconciler.cmp_policy_info`.
///
/// A positive result means `local` is less authoritative than `remote`.
/// Ordinary live containers choose the oldest `status_changed_at`; deleted
/// containers choose the newest, while a genuine recreation takes precedence
/// over either rule.
fn cmp_policy_info(local: ContainerPolicyInfo, remote: ContainerPolicyInfo) -> i8 {
    let local_deleted = local.is_deleted();
    let remote_deleted = remote.is_deleted();
    if local_deleted || remote_deleted {
        if !local_deleted {
            return -1;
        }
        if !remote_deleted {
            return 1;
        }
        return ordering_i8(remote.status_changed_at.cmp(&local.status_changed_at));
    }

    let local_recreated = local.has_been_recreated();
    let remote_recreated = remote.has_been_recreated();
    if local_recreated || remote_recreated {
        if !local_recreated {
            return 1;
        }
        if !remote_recreated {
            return -1;
        }
        let most_recent_delete = local.delete_timestamp.max(remote.delete_timestamp);
        if local.put_timestamp < most_recent_delete {
            return 1;
        }
        if remote.put_timestamp < most_recent_delete {
            return -1;
        }
    }

    ordering_i8(local.status_changed_at.cmp(&remote.status_changed_at))
}

fn db_value_timestamp(info: &[(String, DbValue)], key: &str) -> Option<Timestamp> {
    info.iter().find(|(k, _)| k == key).and_then(|(_, value)| {
        let raw = value_str(value);
        raw.parse().ok()
    })
}

fn db_value_i64(info: &[(String, DbValue)], key: &str) -> Option<i64> {
    info.iter()
        .find(|(k, _)| k == key)
        .and_then(|(_, value)| match value {
            DbValue::Int(value) => Some(*value),
            DbValue::Text(value) => value.parse().ok(),
            DbValue::Null => None,
        })
}

fn json_i64(value: &serde_json::Value) -> Option<i64> {
    value.as_i64().or_else(|| value.as_str()?.parse().ok())
}

fn local_policy_info(info: &[(String, DbValue)]) -> Option<ContainerPolicyInfo> {
    Some(ContainerPolicyInfo {
        put_timestamp: db_value_timestamp(info, "put_timestamp")?,
        delete_timestamp: db_value_timestamp(info, "delete_timestamp")?,
        status_changed_at: db_value_timestamp(info, "status_changed_at")?,
        count: db_value_i64(info, "count").or_else(|| db_value_i64(info, "object_count"))?,
        storage_policy_index: db_value_i64(info, "storage_policy_index")?,
    })
}

fn remote_policy_info(info: &serde_json::Value) -> Option<ContainerPolicyInfo> {
    Some(ContainerPolicyInfo {
        put_timestamp: info.get("put_timestamp")?.as_str()?.parse().ok()?,
        delete_timestamp: info.get("delete_timestamp")?.as_str()?.parse().ok()?,
        status_changed_at: info.get("status_changed_at")?.as_str()?.parse().ok()?,
        count: info
            .get("count")
            .and_then(json_i64)
            .or_else(|| info.get("object_count").and_then(json_i64))?,
        storage_policy_index: json_i64(info.get("storage_policy_index")?)?,
    })
}

/// Return true when Python Swift's container policy reconciliation rules say
/// the local broker must adopt the peer's storage policy.
///
/// Missing extension fields deliberately return false so mixed-version peers
/// retain the pre-extension behavior instead of guessing a policy.
pub fn incorrect_policy_index(
    local_info: &[(String, DbValue)],
    remote_info: &serde_json::Value,
) -> bool {
    let Some(local) = local_policy_info(local_info) else {
        return false;
    };
    let Some(remote) = remote_policy_info(remote_info) else {
        return false;
    };
    local.storage_policy_index != remote.storage_policy_index && cmp_policy_info(local, remote) > 0
}

/// If we have no live objects left (tombstones/empty) but the peer still
/// lists some, and it already claims to be at our max_row, restart usync
/// from -1 so DELETE rows are pushed (probe L1435).
///
/// Do **not** treat any count mismatch as diverge: during nested cleave
/// (L1256) replicas intentionally differ (150 vs 50). `!=` on listing-w94
/// full-usynced an uncleaved donor and dropped obj-0000–0049 at L1321.
pub fn usync_start_point(
    point: i64,
    local_max_row: i64,
    local_count: i64,
    remote_count: i64,
) -> i64 {
    if local_count == 0 && remote_count > 0 && point >= local_max_row {
        -1
    } else {
        point
    }
}

/// Preserve the row timestamp exactly during usync.
///
/// `created_at` is part of the container DB hash and may encode independent
/// data/content-type/metadata timestamps. Re-stamping a tombstone on every
/// send makes replicas diverge forever and violates Python's `_usync_db`,
/// which forwards broker rows unchanged. A real delete already has a newer
/// data timestamp than the object it deletes; synthetic tombstones get their
/// timestamp once when they are constructed.
fn usync_created_at(rec: &crate::ObjectRecord) -> String {
    rec.created_at.clone()
}

fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            b => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn broker_account_container(local: &mut ContainerBroker) -> Option<(String, String)> {
    let info = local.get_info().ok()?;
    let get = |k: &str| -> Option<String> {
        info.iter()
            .find(|(key, _)| key == k)
            .and_then(|(_, v)| match v {
                DbValue::Text(s) if !s.is_empty() => Some(s.clone()),
                _ => None,
            })
    };
    Some((get("account")?, get("container")?))
}

fn fetch_peer_object_names(
    host: &str,
    device: &str,
    partition: &str,
    account: &str,
    container: &str,
) -> Result<Vec<String>, DbError> {
    let mut conn = std::net::TcpStream::connect(host)
        .map_err(|e| DbError::Connection(format!("connect {host}: {e}")))?;
    conn.set_nodelay(true).ok();
    conn.set_read_timeout(Some(std::time::Duration::from_secs(15)))
        .ok();
    let path = format!(
        "/{}/{}/{}/{}?format=json",
        url_encode(device),
        url_encode(partition),
        url_encode(account),
        url_encode(container)
    );
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nX-Backend-Allow-Reserved-Names: true\r\nConnection: close\r\n\r\n"
    );
    conn.write_all(req.as_bytes())
        .map_err(|e| DbError::Connection(format!("write {host}: {e}")))?;
    let mut raw = Vec::new();
    conn.read_to_end(&mut raw)
        .map_err(|e| DbError::Connection(format!("read {host}: {e}")))?;
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| DbError::Connection("bad listing response".into()))?;
    let status: u16 = String::from_utf8_lossy(&raw[..split])
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    if !(200..300).contains(&status) {
        return Err(DbError::Connection(format!("peer listing status {status}")));
    }
    let val: serde_json::Value = serde_json::from_slice(&raw[split + 4..])
        .map_err(|e| DbError::Connection(e.to_string()))?;
    let mut names = Vec::new();
    if let Some(arr) = val.as_array() {
        for obj in arr {
            if let Some(n) = obj.get("name").and_then(|v| v.as_str()) {
                if !n.is_empty() {
                    names.push(n.to_string());
                }
            }
        }
    }
    Ok(names)
}

fn url_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (
                (b[i + 1] as char).to_digit(16),
                (b[i + 2] as char).to_digit(16),
            ) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn object_namespace(local: &mut ContainerBroker) -> Option<(String, String)> {
    let md = local.metadata().ok()?;
    let get = |k: &str| -> Option<String> {
        md.iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(k))
            .map(|(_, (v, _))| v.clone())
            .filter(|v| !v.is_empty())
    };
    let root = get("X-Container-Sysmeta-Shard-Quoted-Root")
        .map(|s| url_decode(&s))
        .or_else(|| get("X-Container-Sysmeta-Shard-Root"));
    if let Some(rp) = root {
        if let Some((a, c)) = rp.split_once('/') {
            if !a.is_empty() && !c.is_empty() {
                return Some((a.to_string(), c.to_string()));
            }
        }
    }
    broker_account_container(local)
}

fn object_ring_path(swift_dir: &str, policy_index: i64) -> std::path::PathBuf {
    let filename = if policy_index == 0 {
        "object.ring.gz".to_string()
    } else {
        format!("object-{policy_index}.ring.gz")
    };
    std::path::Path::new(swift_dir).join(filename)
}

fn load_object_ring(policy_index: i64) -> Option<Ring> {
    let swift_dir = std::env::var("SWIFT_DIR").unwrap_or_else(|_| "/etc/swift".to_string());
    let swift_conf =
        std::env::var("SWIFT_CONF").unwrap_or_else(|_| format!("{swift_dir}/swift.conf"));
    let text = std::fs::read_to_string(swift_conf).ok()?;
    let conf = SwiftConfig::parse_lenient(&text, &[], false).ok()?;
    let hash = HashPathConfig::from_swift_conf(&conf).ok()?;
    let ring_path = object_ring_path(&swift_dir, policy_index);
    let data = RingData::load(&ring_path).ok()?;
    Some(Ring::new(data, hash))
}

fn head_object_request(
    host: &str,
    path: &str,
    policy_index: i64,
) -> String {
    // X-Backend-Open-Expired: an object past X-Delete-At still has a data
    // file. Probe test_expirer_object_split_brain L110 requires that name
    // to stay in the listing until the expirer reaps it. A plain HEAD 404s
    // and would look like a user DELETE.
    format!(
        "HEAD {path} HTTP/1.1\r\nHost: {host}\r\nX-Backend-Storage-Policy-Index: {policy_index}\r\nX-Backend-Open-Expired: true\r\nX-Backend-Replication: true\r\nConnection: close\r\n\r\n"
    )
}

fn head_object_status(
    dev: &RingDevice,
    part: u32,
    account: &str,
    container: &str,
    name: &str,
    policy_index: i64,
) -> Option<u16> {
    let host = format!("{}:{}", dev.ip, dev.port);
    let mut conn = std::net::TcpStream::connect(&host).ok()?;
    conn.set_nodelay(true).ok();
    conn.set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .ok();
    let path = format!(
        "/{}/{}/{}/{}/{}",
        url_encode(&dev.device),
        part,
        url_encode(account),
        url_encode(container),
        url_encode(name)
    );
    let req = head_object_request(&host, &path, policy_index);
    conn.write_all(req.as_bytes()).ok()?;
    let mut raw = Vec::new();
    conn.read_to_end(&mut raw).ok()?;
    let status: u16 = String::from_utf8_lossy(&raw)
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())?;
    Some(status)
}

/// `Some(true)` = every object replica is a tombstone / never existed
/// (404/410 even with open-expired); `Some(false)` = at least one data
/// file remains (including X-Delete-At expiry); `None` = could not tell.
fn object_is_gone(
    ring: &Ring,
    policy_index: i64,
    account: &str,
    container: &str,
    name: &str,
) -> Option<bool> {
    let (part, nodes) = ring.get_nodes(account, Some(container), Some(name)).ok()?;
    if nodes.is_empty() {
        return None;
    }
    let mut saw_404 = false;
    let mut saw_err = false;
    for n in nodes {
        match head_object_status(n.dev, part, account, container, name, policy_index) {
            Some(s) if (200..300).contains(&s) => return Some(false),
            Some(404) | Some(410) => saw_404 = true,
            _ => saw_err = true,
        }
    }
    if saw_404 && !saw_err {
        Some(true)
    } else {
        None
    }
}

/// After merging the peer's shard ranges: only a settled ACTIVE unsharded
/// shard may synthesize tombstones. `own_state=None` is not enough —
/// listing-w105 treated L1256 CREATED children (no own row yet) as leftover
/// and dropped alpha+beta at L1369. Do **not** default a missing own range
/// to ACTIVE (listing-w100).
pub(crate) fn synthetic_tombstones_allowed(
    db_state: Option<DbState>,
    own_state: Option<i64>,
    own_deleted: Option<i64>,
    mid_cleave: bool,
    from_handoff: bool,
) -> bool {
    if !matches!(db_state, Some(DbState::Unsharded)) {
        return false;
    }
    if mid_cleave {
        return false;
    }
    match (own_state, own_deleted) {
        (Some(shard_state::ACTIVE), Some(0)) => true,
        // listing-w108: empty handoff vs leftover primary (own=None even
        // after merging the peer's ranges). Do not allow own=None on a
        // primary — that tombstoned L1256 CREATED children (listing-w105).
        (None, None) if from_handoff => true,
        _ => false,
    }
}

fn shard_ranges_mid_cleave(local: &mut ContainerBroker) -> bool {
    let args = GetShardRangesArgs {
        include_own: true,
        include_deleted: false,
        ..Default::default()
    };
    match local.get_shard_ranges(&args) {
        Ok(rows) => rows.iter().any(|sr| {
            sr.state == shard_state::CREATED
                || sr.state == shard_state::CLEAVED
                || sr.state == shard_state::SHARDING
        }),
        Err(_) => true,
    }
}

fn synthetic_tombstone_items(
    names: &[String],
    policy_index: i64,
    created_at: &str,
) -> Vec<serde_json::Value> {
    names
        .iter()
        .enumerate()
        .map(|(i, name)| {
            serde_json::json!({
                "ROWID": i as i64 + 1,
                "name": name,
                "created_at": created_at,
                "size": 0,
                "content_type": "application/deleted",
                "etag": "noetag",
                "deleted": 1,
                "storage_policy_index": policy_index,
            })
        })
        .collect()
}

/// listing-w99: empty local replica vs leftover live rows on the peer.
/// Only for settled unsharded shards (post nested-complete / L1426).
fn push_synthetic_tombstones(
    local: &mut ContainerBroker,
    local_id: &str,
    peer_host: &str,
    peer_device: &str,
    partition: &str,
    hsh: &str,
    from_handoff: bool,
) -> Result<u64, DbError> {
    // Pull the peer's shard-range table first. listing-w104's empty replica
    // had own=None; the peer that still lists objects already knows the
    // range. After merge: CREATED/CLEAVED at L1256 → skip; ACTIVE at L1426
    // → synthesize.
    let _ = fetch_and_merge_remote_shard_ranges(local, peer_host, peer_device, partition, hsh);
    let db_state = local.get_db_state().ok();
    let own = local.get_own_shard_range(true).ok().flatten();
    let own_state = own.as_ref().map(|sr| sr.state);
    let own_del = own.as_ref().map(|sr| sr.deleted);
    let mid_cleave = shard_ranges_mid_cleave(local);
    if !synthetic_tombstones_allowed(db_state, own_state, own_del, mid_cleave, from_handoff) {
        eprintln!(
            "db-replicator: skip synthetic hsh={hsh} db_state={db_state:?} own_state={own_state:?} own_deleted={own_del:?} mid_cleave={mid_cleave} handoff={from_handoff}"
        );
        return Ok(0);
    }
    let Some((account, container)) = broker_account_container(local) else {
        eprintln!("db-replicator: skip synthetic hsh={hsh} no account/container");
        return Ok(0);
    };
    let names = fetch_peer_object_names(peer_host, peer_device, partition, &account, &container)?;
    if names.is_empty() {
        return Ok(0);
    }
    // L1256 vs L1426 have the same empty-handoff/lagging-primary shape.
    // Only tombstone names that are already gone from object storage
    // (user DELETE completed). Cleaved objects still on disk must live.
    let (obj_acct, obj_cont) =
        object_namespace(local).unwrap_or_else(|| (account.clone(), container.clone()));
    let Ok(policy_index) = local.storage_policy_index() else {
        eprintln!("db-replicator: skip synthetic hsh={hsh} no storage policy");
        return Ok(0);
    };
    let Some(ring) = load_object_ring(policy_index) else {
        eprintln!("db-replicator: skip synthetic hsh={hsh} no object ring policy={policy_index}");
        return Ok(0);
    };
    let gone: Vec<String> = names
        .iter()
        .filter(|n| object_is_gone(&ring, policy_index, &obj_acct, &obj_cont, n) == Some(true))
        .cloned()
        .collect();
    if gone.is_empty() {
        eprintln!(
            "db-replicator: skip synthetic hsh={hsh} n={} objects still live account={obj_acct} container={obj_cont}",
            names.len()
        );
        return Ok(0);
    }
    eprintln!(
        "db-replicator: synthetic gone hsh={hsh} gone={} listed={} account={obj_acct} container={obj_cont}",
        gone.len(),
        names.len()
    );
    let now = Timestamp::now().internal();
    let json_items = synthetic_tombstone_items(&gone, policy_index, &now);
    eprintln!(
        "db-replicator: synthetic tombstones hsh={hsh} n={} account={account} container={container}",
        json_items.len()
    );
    let body = serde_json::json!(["merge_items", json_items, local_id]);
    let (status, _) = replicate_rpc(
        peer_host,
        peer_device,
        partition,
        hsh,
        body.to_string().as_bytes(),
    )?;
    if status != 202 {
        return Err(DbError::Connection(format!(
            "synthetic merge_items status {status}"
        )));
    }
    Ok(json_items.len() as u64)
}

/// Outcome of a replication pass.
#[derive(Debug, Clone, PartialEq)]
pub struct ReplicateOutcome {
    /// Number of merge_items batches pushed.
    pub diffs: u64,
    /// Rows pushed in total.
    pub rows_pushed: u64,
    /// Final sync point after the pass.
    pub point: i64,
    /// The peer had no DB; the caller should fall back to a staged full-DB
    /// rsync + `complete_rsync` (db_replicator.py:553-557).
    pub needs_rsync: bool,
    /// usync could not (or would not) bring the peer up to date: either
    /// the remote-merge heuristic chose a full-DB transfer up front
    /// (`_choose_replication_mode`, db_replicator.py:579-591), or the
    /// usync loop stopped at `MAX_DIFFS` with rows still unsent
    /// ('diff_capped', db_replicator.py:462-470). The caller should fall
    /// back to a staged full-DB rsync + `rsync_then_merge`.
    pub usync_incomplete: bool,
}

/// Transport for the full-DB rsync fallback, abstracted so the fallback
/// orchestration is testable without a real rsync.
pub trait RsyncTransport {
    /// Stage the local DB file into the peer's `<device>/tmp/<stage_name>`
    /// receiving area (`_rsync_file` + `_rsync_db`'s
    /// `rsync_path = '%s/tmp/%s' % (device, local_id)`,
    /// db_replicator.py:345-377, 394-395). Returns success.
    fn rsync(
        &self,
        local_db: &std::path::Path,
        peer_host: &str,
        peer_device: &str,
        stage_name: &str,
    ) -> bool;
    /// POST the completion RPC `[op, stage_name, dest_db_name]` telling the
    /// peer to adopt (`complete_rsync`) or merge (`rsync_then_merge`) the
    /// staged DB (db_replicator.py:409-412). `dest_db_name` is Python
    /// `os.path.basename(broker.db_file)` and must keep any epoch suffix.
    fn complete(
        &self,
        peer_host: &str,
        peer_device: &str,
        partition: &str,
        hsh: &str,
        op: &str,
        stage_name: &str,
        dest_db_name: &str,
    ) -> bool;
}

/// Python `os.path.basename(broker.db_file)` for the complete_rsync third
/// argument. Epoch-suffixed DBs must keep the suffix so a SHARDED replica
/// does not recreate an unsuffixed retiring file (probe L1347/L1375).
pub fn rsync_dest_db_name(local_db: &std::path::Path, hsh: &str) -> String {
    match local_db.file_name().and_then(|s| s.to_str()) {
        Some(name) if name.ends_with(".db") => name.to_string(),
        _ => format!("{hsh}.db"),
    }
}

/// `_rsync_db` (db_replicator.py:379-412): stage the whole local DB file
/// into the peer's `<device>/tmp/<local_id>` — Python names the staged
/// file after the LOCAL db's id — then POST the completion RPC (`op` is
/// `complete_rsync` for a peer with no DB, `rsync_then_merge` for a
/// divergent one) so the peer adopts/merges the staged copy. Returns
/// whether the peer confirmed the op.
///
/// Deferred vs Python: the block-level re-sync when the DB was modified
/// during the first rsync (db_replicator.py:402-408) — the staged model
/// still converges on the next pass.
#[allow(clippy::too_many_arguments)] // mirrors the Python _rsync_db parameter set
pub fn rsync_db(
    local_db: &std::path::Path,
    local_id: &str,
    peer_host: &str,
    peer_device: &str,
    partition: &str,
    hsh: &str,
    op: &str,
    transport: &dyn RsyncTransport,
) -> bool {
    if !transport.rsync(local_db, peer_host, peer_device, local_id) {
        return false;
    }
    // Python `_rsync_db` dest is `os.path.basename(broker.db_file)`. An
    // epoch-suffixed source must complete onto `hash_<epoch>.db` so
    // shrink-to-root objects land in the live SHARDED file (probe L2088).
    // Staging an epoch file under `<hsh>.db` resurrects retiring (L1347).
    let dest = rsync_dest_db_name(local_db, hsh);
    transport.complete(peer_host, peer_device, partition, hsh, op, local_id, &dest)
}

/// True when `local_db` is an epoch-suffixed file (`<hash>_<epoch>.db`).
/// Full-file rsync dest is always `<hsh>.db`; staging an epoch file under
/// that name resurrects the retiring DB next to the peer's epoch file.
pub fn rsync_would_recreate_retiring(local_db: &std::path::Path) -> bool {
    crate::parse_db_filename(local_db).1.is_some()
}

/// The completion RPC at the end of `_rsync_db` (db_replicator.py:409-412):
/// POST `[op, stage_name, dest_db_name]` to the peer's REPLICATE endpoint and
/// report success on any 2xx (Python's `200 <= response.status < 300`).
/// Python sends `os.path.basename(broker.db_file)` as the third element.
pub fn replicate_completion_rpc(
    host: &str,
    device: &str,
    partition: &str,
    hsh: &str,
    op: &str,
    stage_name: &str,
    dest_db_name: &str,
) -> Result<bool, DbError> {
    let dest = if dest_db_name.is_empty() {
        format!("{hsh}.db")
    } else {
        dest_db_name.to_string()
    };
    let body = serde_json::json!([op, stage_name, dest]);
    let (status, _) = replicate_rpc(host, device, partition, hsh, body.to_string().as_bytes())?;
    Ok((200..300).contains(&status))
}

fn value_str(v: &DbValue) -> String {
    match v {
        DbValue::Text(s) => s.clone(),
        DbValue::Int(i) => i.to_string(),
        DbValue::Null => String::new(),
    }
}

/// A minimal HTTP POST of a JSON RPC body to a peer's REPLICATE endpoint.
/// Returns `(status, body)`.
fn replicate_rpc(
    host: &str,
    device: &str,
    partition: &str,
    hsh: &str,
    body: &[u8],
) -> Result<(u16, Vec<u8>), DbError> {
    let mut conn = std::net::TcpStream::connect(host)
        .map_err(|e| DbError::Connection(format!("connect {host}: {e}")))?;
    conn.set_nodelay(true).ok();
    conn.set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .ok();
    let path = format!("/{device}/{partition}/{hsh}");
    let req = format!(
        "REPLICATE {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    conn.write_all(req.as_bytes())
        .and_then(|_| conn.write_all(body))
        .map_err(|e| DbError::Connection(format!("write {host}: {e}")))?;
    let mut raw = Vec::new();
    conn.read_to_end(&mut raw)
        .map_err(|e| DbError::Connection(format!("read {host}: {e}")))?;
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| DbError::Connection("bad replicate response".into()))?;
    let status: u16 = String::from_utf8_lossy(&raw[..split])
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| DbError::Connection("bad status line".into()))?;
    Ok((status, raw[split + 4..].to_vec()))
}

/// Replicate the local container DB to a peer: negotiate the peer's
/// high-water mark for our id, then usync object rows past it.
pub fn replicate_container_db(
    local: &mut ContainerBroker,
    local_id: &str,
    peer_host: &str,
    peer_device: &str,
    partition: &str,
    hsh: &str,
) -> Result<ReplicateOutcome, DbError> {
    replicate_container_db_role(
        local,
        local_id,
        peer_host,
        peer_device,
        partition,
        hsh,
        false,
    )
}

fn peer_supports_shard_range_push(remote_info: &serde_json::Value) -> bool {
    // Python `_choose_replication_mode` uses field presence as the capability
    // signal, including `-1` on a fresh peer: we may push our ranges to it.
    remote_info.get("shard_max_row").is_some()
}

fn peer_has_shard_ranges_to_fetch(remote_info: &serde_json::Value) -> bool {
    // Python `_handle_sync_response` deliberately uses a stricter predicate:
    // only fetch when the peer reports a non-negative shard high-water mark.
    // Fetching from a fresh `-1` peer can merge its own range into a primary,
    // make `sharding_initiated()` spuriously true, and suppress object usync.
    remote_info
        .get("shard_max_row")
        .and_then(json_i64)
        .map(|max_row| max_row >= 0)
        .unwrap_or(false)
}

/// Python defers object replication only after this broker has initiated
/// sharding. Rust also needs to protect a newly-created *handoff* that has
/// learned shard ranges before its own range reflects that transition. That
/// exception must stay handoff-scoped: an under-populated primary can already
/// have shard ranges and still needs object usync before it cleaves.
fn defer_object_usync(local: &mut ContainerBroker, local_is_handoff: bool) -> bool {
    local.sharding_initiated().unwrap_or(false)
        || (local_is_handoff && local.has_other_shard_ranges().unwrap_or(false))
}

/// Like [`replicate_container_db`], but `local_is_handoff` lets an empty
/// handoff synthesize tombstones onto a leftover primary (probe L1435).
pub fn replicate_container_db_role(
    local: &mut ContainerBroker,
    local_id: &str,
    peer_host: &str,
    peer_device: &str,
    partition: &str,
    hsh: &str,
    local_is_handoff: bool,
) -> Result<ReplicateOutcome, DbError> {
    let info = local.get_replication_info()?;
    let get = |k: &str| {
        info.iter()
            .find(|(key, _)| key == k)
            .map(|(_, v)| value_str(v))
            .unwrap_or_default()
    };
    let local_max_row: i64 = get("max_row").parse().unwrap_or(-1);
    let local_count: i64 = get("count").parse().unwrap_or(-1);
    let local_policy_index: i64 = get("storage_policy_index").parse().unwrap_or(0);
    let local_created_at = get("created_at");
    let local_put_timestamp = get("put_timestamp");
    let local_delete_timestamp = get("delete_timestamp");
    let metadata = get("metadata");

    // ContainerReplicator._gather_sync_args extends the base DB RPC with
    // status_changed_at, count and storage_policy_index. Peers use those
    // fields to converge a container created under conflicting policies.
    let sync_body = serde_json::json!([
        "sync",
        local_max_row,
        get("hash"),
        local_id,
        local_created_at,
        local_put_timestamp,
        local_delete_timestamp,
        metadata,
        get("status_changed_at"),
        local_count,
        local_policy_index,
    ]);
    let (status, resp) = replicate_rpc(
        peer_host,
        peer_device,
        partition,
        hsh,
        sync_body.to_string().as_bytes(),
    )?;
    if status == 404 {
        // Peer has no DB yet (db_replicator.py:553-557); the caller must
        // fall back to a staged full-DB rsync + complete_rsync (see
        // rsync_db). `point: -1` + `needs_rsync: true` signals it.
        return Ok(ReplicateOutcome {
            diffs: 0,
            rows_pushed: 0,
            point: -1,
            needs_rsync: true,
            usync_incomplete: false,
        });
    }
    if status != 200 {
        return Err(DbError::Connection(format!("sync RPC status {status}")));
    }
    let remote_info: serde_json::Value =
        serde_json::from_slice(&resp).map_err(|e| DbError::Connection(e.to_string()))?;

    // ContainerReplicator._handle_sync_response: the more authoritative
    // policy wins before timestamps and metadata are merged.
    if incorrect_policy_index(&info, &remote_info) {
        let remote_policy_index = remote_info
            .get("storage_policy_index")
            .and_then(json_i64)
            .ok_or_else(|| DbError::Connection("peer omitted storage_policy_index".into()))?;
        local.set_storage_policy_index(remote_policy_index, &Timestamp::now().internal())?;
    }
    if let (Some(remote_created_at), Some(remote_put_timestamp), Some(remote_delete_timestamp)) = (
        remote_info.get("created_at").and_then(|v| v.as_str()),
        remote_info.get("put_timestamp").and_then(|v| v.as_str()),
        remote_info.get("delete_timestamp").and_then(|v| v.as_str()),
    ) {
        if remote_created_at != local_created_at
            || remote_put_timestamp != local_put_timestamp
            || remote_delete_timestamp != local_delete_timestamp
        {
            local.merge_timestamps(
                remote_created_at,
                remote_put_timestamp,
                remote_delete_timestamp,
            )?;
        }
    }
    // _handle_sync_response (db_replicator.py:561-564): a non-empty
    // `metadata` field in the peer's replication info is merged into the
    // local DB (timestamp-wins per key) before usyncing.
    if let Some(remote_md) = remote_info["metadata"].as_str() {
        if !remote_md.is_empty() {
            let md = py_json_parse_metadata(remote_md)?;
            local.update_metadata(&md)?;
        }
    }
    // 'point' is how much of US the remote already has
    let mut point = remote_info["point"].as_i64().unwrap_or(-1);
    let remote_count = remote_info
        .get("count")
        .and_then(|v| v.as_i64())
        .or_else(|| remote_info.get("object_count").and_then(|v| v.as_i64()))
        .unwrap_or(-1);
    // Hash/point can claim in-sync while object_count still diverges
    // (tombstones not applied on a lagging primary). Force a full usync
    // so DELETE rows converge before sharders UPDATE_ROOT (probe L1435).
    let new_point = usync_start_point(point, local_max_row, local_count, remote_count);
    if new_point != point {
        eprintln!(
            "db-replicator: count diverge hsh={hsh} local_count={local_count} remote_count={remote_count} point={point}->{new_point}"
        );
    }
    point = new_point;

    // Python has two distinct gates here. `_handle_sync_response` fetches
    // remote ranges only when `shard_max_row >= 0`; `_choose_replication_mode`
    // pushes local ranges whenever that field is present, including `-1` on a
    // fresh peer. Collapsing these predicates mutates a primary with the fresh
    // peer's own range before `sharding_initiated()` is evaluated.
    let remote_state = remote_info
        .get("db_state")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if peer_has_shard_ranges_to_fetch(&remote_info) {
        if let Err(e) =
            fetch_and_merge_remote_shard_ranges(local, peer_host, peer_device, partition, hsh)
        {
            eprintln!("db-replicator: fetch shard ranges hsh={hsh} err={e}");
        }
    }
    if peer_supports_shard_range_push(&remote_info) {
        if let Err(e) =
            sync_shard_ranges_to_peer(local, local_id, peer_host, peer_device, partition, hsh)
        {
            eprintln!("db-replicator: push shard ranges hsh={hsh} err={e}");
        }
    }

    // Python `_choose_replication_mode`: if *this* broker can shard,
    // refuse object rows and wait for cleaving (container/replicator.py:149).
    // Probe `test_replication_to_sharding_container` L2242: usync from an
    // unsharded replica must not merge rows into a SHARDING peer's fresh DB
    // (`get_objects()` on the epoch file stays empty). Python's small-db
    // path usyncs; aborting rsync_then_merge is not enough when
    // `max_row < per_diff`.
    if defer_object_usync(local, local_is_handoff) {
        // A handoff that has learned ranges waits for cleaving instead of
        // rsync_then_merge (probe L2964). Primaries are deliberately excluded
        // from that compatibility exception (listing probe L1517).
        eprintln!(
            "db-replicator: skip object usync (local sharding) hsh={hsh} handoff={local_is_handoff}"
        );
        return Ok(ReplicateOutcome {
            diffs: 0,
            rows_pushed: 0,
            point,
            needs_rsync: false,
            usync_incomplete: false,
        });
    }
    if remote_state == "sharding" || remote_state == "sharded" {
        eprintln!("db-replicator: skip object usync (remote {remote_state}) hsh={hsh}");
        return Ok(ReplicateOutcome {
            diffs: 0,
            rows_pushed: 0,
            point,
            needs_rsync: false,
            usync_incomplete: false,
        });
    }

    // _choose_replication_mode (db_replicator.py:571-591): when the peer
    // is not already in sync (its point does not cover our max_row,
    // _in_sync db_replicator.py:481-497) and its rowids differ from ours
    // by more than 50% with a gap greater than per_diff, do NOT usync:
    // the caller should rsync the whole DB and have the peer remote-merge
    // it ('rsync_then_merge'). The per_diff bound stops small containers
    // from dropping to rsync.
    let remote_max_row = remote_info["max_row"].as_i64().unwrap_or(-1);
    if point < local_max_row
        && local_max_row != 0
        && (remote_max_row as f64) / (local_max_row as f64) < 0.5
        && local_max_row - remote_max_row > PER_DIFF
    {
        return Ok(ReplicateOutcome {
            diffs: 0,
            rows_pushed: 0,
            point,
            needs_rsync: false,
            usync_incomplete: true,
        });
    }

    // usync: push object rows since `point` in ROWID order
    let mut diffs = 0u64;
    let mut rows_pushed = 0u64;
    let mut usync_incomplete = false;
    loop {
        if diffs as i64 >= MAX_DIFFS {
            // _usync_db (db_replicator.py:446, 462-470): stopping at
            // max_diffs with rows still unsent is a replication failure
            // ('diff_capped'); fall back to the staged rsync.
            usync_incomplete = !local.get_items_since(point, 1)?.is_empty();
            break;
        }
        let items = local.get_items_since(point, PER_DIFF)?;
        if diffs == 0 && local_count == 0 && remote_count > 0 {
            let n_del = items.iter().filter(|(_, r)| r.deleted == 1).count();
            eprintln!(
                "db-replicator: tombstone usync hsh={hsh} n={} deleted={n_del} point={point}",
                items.len()
            );
        }
        if items.is_empty() {
            // listing-w99: local_count=0 but no tombstone rows (n=0).
            // The leftover live objects sit on the peer. Only synthesize
            // tombstones for a settled ACTIVE unsharded shard (L1426), never
            // during nested cleave (L1256 CREATED/CLEAVED — that dropped
            // obj-0000–0049).
            if local_count == 0 && remote_count > 0 {
                match push_synthetic_tombstones(
                    local,
                    local_id,
                    peer_host,
                    peer_device,
                    partition,
                    hsh,
                    local_is_handoff,
                ) {
                    Ok(n) => rows_pushed += n,
                    Err(e) => {
                        eprintln!("db-replicator: synthetic tombstones failed hsh={hsh}: {e}")
                    }
                }
            }
            break;
        }
        let json_items: Vec<serde_json::Value> = items
            .iter()
            .map(|(rowid, rec)| {
                serde_json::json!({
                    "ROWID": rowid,
                    "name": rec.name,
                    "created_at": usync_created_at(rec),
                    "size": rec.size,
                    "content_type": rec.content_type,
                    "etag": rec.etag,
                    "deleted": rec.deleted,
                    "storage_policy_index": rec.storage_policy_index,
                })
            })
            .collect();
        let body = serde_json::json!(["merge_items", json_items, local_id]);
        let (status, _) = replicate_rpc(
            peer_host,
            peer_device,
            partition,
            hsh,
            body.to_string().as_bytes(),
        )?;
        if status != 202 {
            return Err(DbError::Connection(format!("merge_items status {status}")));
        }
        rows_pushed += items.len() as u64;
        point = *items.last().map(|(r, _)| r).unwrap();
        diffs += 1;
    }
    // Python ContainerReplicator._sync_shard_ranges: push every shard-range
    // row each cycle (no shard sync-points yet).
    let _ = sync_shard_ranges_to_peer(local, local_id, peer_host, peer_device, partition, hsh);
    Ok(ReplicateOutcome {
        diffs,
        rows_pushed,
        point,
        needs_rsync: false,
        usync_incomplete,
    })
}

fn fetch_and_merge_remote_shard_ranges(
    local: &mut ContainerBroker,
    peer_host: &str,
    peer_device: &str,
    partition: &str,
    hsh: &str,
) -> Result<(), DbError> {
    let body = serde_json::json!(["get_shard_ranges"]);
    let (status, resp) = replicate_rpc(
        peer_host,
        peer_device,
        partition,
        hsh,
        body.to_string().as_bytes(),
    )?;
    if status != 200 {
        return Ok(());
    }
    let arr: Vec<serde_json::Value> = serde_json::from_slice(&resp).unwrap_or_default();
    let mut ranges = Vec::new();
    for v in arr {
        if let Some(sr) = ShardRange::from_json(&v) {
            ranges.push(sr);
        }
    }
    if !ranges.is_empty() {
        let ranges = crate::container::check_merge_own_shard_range(ranges, local)?;
        if !ranges.is_empty() {
            local.merge_shard_ranges(ranges)?;
        }
    }
    Ok(())
}

/// `merge_shard_ranges` RPC: send this DB's shard-range table to the peer.
pub fn sync_shard_ranges_to_peer(
    local: &mut ContainerBroker,
    local_id: &str,
    peer_host: &str,
    peer_device: &str,
    partition: &str,
    hsh: &str,
) -> Result<(), DbError> {
    let ranges = local.get_all_shard_range_data()?;
    if ranges.is_empty() {
        return Ok(());
    }
    let json_ranges: Vec<serde_json::Value> = ranges.iter().map(|r| r.to_json()).collect();
    let body = serde_json::json!(["merge_shard_ranges", json_ranges, local_id]);
    let (status, _) = replicate_rpc(
        peer_host,
        peer_device,
        partition,
        hsh,
        body.to_string().as_bytes(),
    )?;
    if status != 202 && status != 200 {
        return Err(DbError::Connection(format!(
            "merge_shard_ranges status {status}"
        )));
    }
    Ok(())
}

/// A pickle stat value (`object_count`/`bytes_used`) as a JSON scalar for the
/// merge_items body: an integer stays a number, anything else becomes its
/// string form (the receiver accepts either).
fn stat_json(v: &swift_core::pickle::Value) -> serde_json::Value {
    match v {
        swift_core::pickle::Value::Int(i) => serde_json::Value::from(*i),
        swift_core::pickle::Value::Str(s) => serde_json::Value::from(s.clone()),
        _ => serde_json::Value::from(0),
    }
}

/// Replicate the local account DB to a peer: the account analogue of
/// [`replicate_container_db`], pushing container rows past the peer's
/// high-water mark for our id.
pub fn replicate_account_db(
    local: &mut AccountBroker,
    local_id: &str,
    peer_host: &str,
    peer_device: &str,
    partition: &str,
    hsh: &str,
) -> Result<ReplicateOutcome, DbError> {
    let info = local.get_replication_info()?;
    let get = |k: &str| {
        info.iter()
            .find(|(key, _)| key == k)
            .map(|(_, v)| value_str(v))
            .unwrap_or_default()
    };
    let local_max_row: i64 = get("max_row").parse().unwrap_or(-1);

    let sync_body = serde_json::json!([
        "sync",
        local_max_row,
        get("hash"),
        local_id,
        get("created_at"),
        get("put_timestamp"),
        get("delete_timestamp"),
        get("metadata"),
    ]);
    let (status, resp) = replicate_rpc(
        peer_host,
        peer_device,
        partition,
        hsh,
        sync_body.to_string().as_bytes(),
    )?;
    if status == 404 {
        // db_replicator.py:553-557: completely missing, rsync
        return Ok(ReplicateOutcome {
            diffs: 0,
            rows_pushed: 0,
            point: -1,
            needs_rsync: true,
            usync_incomplete: false,
        });
    }
    if status != 200 {
        return Err(DbError::Connection(format!("sync RPC status {status}")));
    }
    let remote_info: serde_json::Value =
        serde_json::from_slice(&resp).map_err(|e| DbError::Connection(e.to_string()))?;
    // _handle_sync_response (db_replicator.py:561-564): merge the peer's
    // non-empty metadata into the local DB before usyncing.
    if let Some(remote_md) = remote_info["metadata"].as_str() {
        if !remote_md.is_empty() {
            let md = py_json_parse_metadata(remote_md)?;
            local.update_metadata(&md)?;
        }
    }
    let mut point = remote_info["point"].as_i64().unwrap_or(-1);

    // _choose_replication_mode (db_replicator.py:571-591): a peer more
    // than 50% and per_diff rows behind is not usynced; the caller should
    // rsync the whole DB for a remote merge ('rsync_then_merge').
    let remote_max_row = remote_info["max_row"].as_i64().unwrap_or(-1);
    if point < local_max_row
        && local_max_row != 0
        && (remote_max_row as f64) / (local_max_row as f64) < 0.5
        && local_max_row - remote_max_row > PER_DIFF
    {
        return Ok(ReplicateOutcome {
            diffs: 0,
            rows_pushed: 0,
            point,
            needs_rsync: false,
            usync_incomplete: true,
        });
    }

    let mut diffs = 0u64;
    let mut rows_pushed = 0u64;
    let mut usync_incomplete = false;
    loop {
        if diffs as i64 >= MAX_DIFFS {
            // _usync_db (db_replicator.py:446, 462-470): rows left after
            // max_diffs batches means usync could not finish; fall back
            // to the staged rsync.
            usync_incomplete = !local.get_items_since(point, 1)?.is_empty();
            break;
        }
        let items = local.get_items_since(point, PER_DIFF)?;
        if items.is_empty() {
            break;
        }
        let json_items: Vec<serde_json::Value> = items
            .iter()
            .map(|(rowid, rec)| {
                serde_json::json!({
                    "ROWID": rowid,
                    "name": rec.name,
                    "put_timestamp": rec.put_timestamp,
                    "delete_timestamp": rec.delete_timestamp,
                    "object_count": stat_json(&rec.object_count),
                    "bytes_used": stat_json(&rec.bytes_used),
                    "deleted": rec.deleted,
                    "storage_policy_index": rec.storage_policy_index,
                })
            })
            .collect();
        let body = serde_json::json!(["merge_items", json_items, local_id]);
        let (status, _) = replicate_rpc(
            peer_host,
            peer_device,
            partition,
            hsh,
            body.to_string().as_bytes(),
        )?;
        if status != 202 {
            return Err(DbError::Connection(format!("merge_items status {status}")));
        }
        rows_pushed += items.len() as u64;
        point = *items.last().map(|(r, _)| r).unwrap();
        diffs += 1;
    }
    Ok(ReplicateOutcome {
        diffs,
        rows_pushed,
        point,
        needs_rsync: false,
        usync_incomplete,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn shard_range_fetch_and_push_gates_match_python() {
        let fresh = serde_json::json!({"shard_max_row": -1});
        assert!(peer_supports_shard_range_push(&fresh));
        assert!(!peer_has_shard_ranges_to_fetch(&fresh));

        let populated = serde_json::json!({"shard_max_row": 0});
        assert!(peer_supports_shard_range_push(&populated));
        assert!(peer_has_shard_ranges_to_fetch(&populated));

        let old_peer = serde_json::json!({"db_state": "sharding"});
        assert!(!peer_supports_shard_range_push(&old_peer));
        assert!(!peer_has_shard_ranges_to_fetch(&old_peer));
    }

    struct FakeRsync {
        /// (peer host, stage name) of every staging attempt.
        rsynced: Mutex<Vec<(String, String)>>,
        /// (op, stage name) of every completion RPC.
        completed: Mutex<Vec<(String, String)>>,
        rsync_ok: bool,
    }
    impl RsyncTransport for FakeRsync {
        fn rsync(&self, _db: &std::path::Path, host: &str, _dev: &str, stage: &str) -> bool {
            self.rsynced
                .lock()
                .unwrap()
                .push((host.to_string(), stage.to_string()));
            self.rsync_ok
        }
        fn complete(
            &self,
            _host: &str,
            _dev: &str,
            _p: &str,
            _h: &str,
            op: &str,
            stage: &str,
            _dest: &str,
        ) -> bool {
            self.completed
                .lock()
                .unwrap()
                .push((op.to_string(), stage.to_string()));
            true
        }
    }

    /// A one-shot fake peer: accepts one REPLICATE connection, reads the
    /// full request, then answers 200 with `body` and closes.
    fn spawn_recording_fake_peer(
        body: String,
    ) -> (
        std::net::SocketAddr,
        std::thread::JoinHandle<()>,
        Arc<Mutex<Vec<u8>>>,
    ) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let request = Arc::new(Mutex::new(Vec::new()));
        let captured = request.clone();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = Vec::new();
            let mut tmp = [0u8; 4096];
            let mut header_end = None;
            let mut content_length = 0usize;
            loop {
                if header_end.is_none() {
                    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        header_end = Some(pos + 4);
                        for line in String::from_utf8_lossy(&buf[..pos]).lines() {
                            if let Some((k, v)) = line.split_once(':') {
                                if k.eq_ignore_ascii_case("content-length") {
                                    content_length = v.trim().parse().unwrap_or(0);
                                }
                            }
                        }
                    }
                }
                if let Some(end) = header_end {
                    if buf.len() >= end + content_length {
                        break;
                    }
                }
                let n = stream.read(&mut tmp).unwrap();
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
            }
            *captured.lock().unwrap() = buf;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(resp.as_bytes()).unwrap();
        });
        (addr, handle, request)
    }

    fn spawn_fake_peer(body: String) -> (std::net::SocketAddr, std::thread::JoinHandle<()>) {
        let (addr, handle, _) = spawn_recording_fake_peer(body);
        (addr, handle)
    }

    #[test]
    fn synthetic_tombstone_object_lookup_uses_selected_policy() {
        assert_eq!(
            object_ring_path("/etc/swift", 0),
            std::path::Path::new("/etc/swift/object.ring.gz")
        );
        assert_eq!(
            object_ring_path("/etc/swift", 2),
            std::path::Path::new("/etc/swift/object-2.ring.gz")
        );

        let (addr, handle, request) = spawn_recording_fake_peer(String::new());
        let dev = RingDevice {
            id: 0,
            region: 1,
            zone: 1,
            ip: addr.ip().to_string(),
            port: addr.port() as u32,
            replication_ip: None,
            replication_port: None,
            device: "sda".to_string(),
            weight: 1.0,
            meta: String::new(),
            extra: Default::default(),
        };
        assert_eq!(
            head_object_status(&dev, 7, "AUTH_test", "c", "o", 2),
            Some(200)
        );
        handle.join().unwrap();
        let request = String::from_utf8(request.lock().unwrap().clone()).unwrap();
        assert!(
            request.contains("X-Backend-Storage-Policy-Index: 2\r\n"),
            "{request}"
        );

        let items = synthetic_tombstone_items(&["object-a".to_string()], 2, "123.00000");
        assert_eq!(items[0]["storage_policy_index"], 2);
        assert_eq!(items[0]["created_at"], "123.00000");
    }

    fn policy_info(
        put: &str,
        delete: &str,
        changed: &str,
        count: i64,
        policy: i64,
    ) -> ContainerPolicyInfo {
        ContainerPolicyInfo {
            put_timestamp: put.parse().unwrap(),
            delete_timestamp: delete.parse().unwrap(),
            status_changed_at: changed.parse().unwrap(),
            count,
            storage_policy_index: policy,
        }
    }

    #[test]
    fn test_cmp_policy_info_matches_python_reconciler_rules() {
        let ordinary_new = policy_info("20", "0", "20", 0, 2);
        let ordinary_old = policy_info("10", "0", "10", 0, 0);
        assert_eq!(cmp_policy_info(ordinary_new, ordinary_old), 1);
        assert_eq!(cmp_policy_info(ordinary_old, ordinary_new), -1);

        let deleted_old = policy_info("5", "10", "20", 0, 2);
        let deleted_new = policy_info("5", "10", "30", 0, 0);
        assert_eq!(cmp_policy_info(deleted_old, deleted_new), 1);
        assert_eq!(cmp_policy_info(deleted_new, deleted_old), -1);
        assert_eq!(cmp_policy_info(ordinary_new, deleted_new), -1);
        assert_eq!(cmp_policy_info(deleted_new, ordinary_new), 1);

        let recreated_old = policy_info("12", "10", "20", 0, 2);
        let recreated_new = policy_info("20", "15", "30", 0, 0);
        assert_eq!(cmp_policy_info(recreated_old, recreated_new), 1);
        assert_eq!(cmp_policy_info(recreated_new, recreated_old), -1);
    }

    #[test]
    fn test_container_sync_sends_policy_extension_and_adopts_older_policy() {
        let dir = std::env::temp_dir().join(format!("swift-repl-policy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("hash.db");
        let mut broker = ContainerBroker::new(&db_path, "a", "c");
        broker
            .initialize("0000000020.00000", 2, "0000000020.00000", "local-id")
            .unwrap();

        let body = serde_json::json!({
            "point": -1,
            "max_row": -1,
            "id": "peer-id",
            "created_at": "0000000010.00000",
            "put_timestamp": "0000000010.00000",
            "delete_timestamp": "0000000000.00000",
            "status_changed_at": "0000000010.00000",
            "count": 0,
            "storage_policy_index": 0,
            "metadata": "",
        })
        .to_string();
        let (addr, handle, request) = spawn_recording_fake_peer(body);
        let outcome = replicate_container_db(
            &mut broker,
            "local-id",
            &addr.to_string(),
            "sdb",
            "0",
            "hash",
        )
        .unwrap();
        handle.join().unwrap();
        assert!(!outcome.needs_rsync, "{outcome:?}");

        let request = request.lock().unwrap();
        let split = request.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
        let sent: serde_json::Value = serde_json::from_slice(&request[split + 4..]).unwrap();
        let sent = sent.as_array().unwrap();
        assert_eq!(sent.len(), 11, "{sent:?}");
        assert_eq!(sent[8], "0000000020.00000");
        assert_eq!(sent[9], 0);
        assert_eq!(sent[10], 2);

        assert_eq!(broker.storage_policy_index().unwrap(), 0);
        let info = broker.get_info().unwrap();
        let get = |key: &str| {
            info.iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value_str(value))
                .unwrap()
        };
        assert_eq!(get("created_at"), "0000000010.00000");
        assert_eq!(get("put_timestamp"), "0000000020.00000");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_sync_response_metadata_merged_into_local() {
        // db_replicator.py:561-564: the peer's metadata from the sync
        // response must be merged into the local DB.
        let dir = std::env::temp_dir().join(format!("swift-replmd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("hash.db");
        let mut broker = ContainerBroker::new(&db_path, "a", "c");
        broker
            .initialize("0000000001.00000", 0, "0000000001.00000", "local-id")
            .unwrap();

        let peer_md = "{\"X-Container-Meta-Color\": [\"blue\", \"0000000002.00000\"]}";
        let body = serde_json::json!({
            "point": 999,
            "id": "peer-id",
            "metadata": peer_md,
        })
        .to_string();
        let (addr, handle) = spawn_fake_peer(body);

        let outcome = replicate_container_db(
            &mut broker,
            "local-id",
            &addr.to_string(),
            "sdb",
            "0",
            "hash",
        )
        .unwrap();
        handle.join().unwrap();
        assert!(!outcome.needs_rsync);
        assert!(!outcome.usync_incomplete);
        // the peer's metadata landed in the local DB
        let md = broker.metadata().unwrap();
        assert_eq!(
            md.iter()
                .find(|(k, _)| k == "X-Container-Meta-Color")
                .map(|(_, v)| v.clone()),
            Some(("blue".to_string(), "0000000002.00000".to_string()))
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_skip_object_usync_when_remote_is_sharding() {
        // Probe L2242: unsharded replica must not merge_items into a
        // SHARDING peer's fresh DB.
        let dir = std::env::temp_dir().join(format!("swift-repl-skip-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("hash.db");
        let mut broker = ContainerBroker::new(&db_path, "a", "c");
        broker
            .initialize("0000000001.00000", 0, "0000000001.00000", "local-id")
            .unwrap();
        broker
            .put_object(
                "alpha",
                "0000000002.00000",
                0,
                "text/plain",
                "e",
                0,
                0,
                None,
                None,
            )
            .unwrap();
        let body = serde_json::json!({
            "point": -1,
            "id": "peer-id",
            "max_row": 0,
            "count": 0,
            "db_state": "sharding",
            "metadata": "",
        })
        .to_string();
        let (addr, handle) = spawn_fake_peer(body);
        let outcome = replicate_container_db(
            &mut broker,
            "local-id",
            &addr.to_string(),
            "sdb",
            "0",
            "hash",
        )
        .unwrap();
        handle.join().unwrap();
        assert_eq!(outcome.rows_pushed, 0, "{outcome:?}");
        assert!(!outcome.needs_rsync, "{outcome:?}");
        assert!(!outcome.usync_incomplete, "{outcome:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_skip_object_usync_when_handoff_has_shard_ranges() {
        // A fresh handoff may still report UNSHARDED after ranges replicate
        // into it. It must not accept object rows before the sharder cleaves.
        let dir = std::env::temp_dir().join(format!(
            "swift-repl-local-shard-ranges-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("hash.db");
        let mut broker = ContainerBroker::new(&db_path, "a", "c");
        broker
            .initialize("0000000001.00000", 0, "0000000001.00000", "local-id")
            .unwrap();
        broker
            .put_object(
                "alpha",
                "0000000002.00000",
                0,
                "text/plain",
                "e",
                0,
                0,
                None,
                None,
            )
            .unwrap();
        let mut shard = crate::shard::ShardRange::new(
            ".shards_a/c-0",
            "0000000003.00000",
            "",
            "",
        );
        shard.state = crate::shard::state::ACTIVE;
        broker.merge_shard_ranges(vec![shard]).unwrap();
        assert!(broker.has_other_shard_ranges().unwrap());

        assert!(
            !defer_object_usync(&mut broker, false),
            "a primary with ranges must still receive missing object rows"
        );
        assert!(defer_object_usync(&mut broker, true));

        let body = serde_json::json!({
            "point": -1,
            "id": "peer-id",
            "max_row": -1,
            "count": 0,
            "db_state": "unsharded",
            "metadata": "",
        })
        .to_string();
        let (addr, handle) = spawn_fake_peer(body);
        let outcome = replicate_container_db_role(
            &mut broker,
            "local-id",
            &addr.to_string(),
            "sdb",
            "0",
            "hash",
            true,
        )
        .unwrap();
        handle.join().unwrap();
        assert_eq!(outcome.rows_pushed, 0, "{outcome:?}");
        assert!(!outcome.needs_rsync, "{outcome:?}");
        assert!(!outcome.usync_incomplete, "{outcome:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_rsync_would_recreate_retiring_on_epoch_file() {
        assert!(rsync_would_recreate_retiring(std::path::Path::new(
            "/d/h/h_1751500010.00000.db"
        )));
        assert!(!rsync_would_recreate_retiring(std::path::Path::new(
            "/d/h/h.db"
        )));
    }

    #[test]
    fn test_rsync_db_keeps_epoch_suffix_on_dest() {
        // Probe L2088: sharder `_replicate_object` of a collapsed root must
        // complete onto `hash_<epoch>.db`, not recreate unsuffixed retiring.
        struct RecDest {
            dest: Mutex<String>,
        }
        impl RsyncTransport for RecDest {
            fn rsync(&self, _db: &std::path::Path, _host: &str, _dev: &str, _stage: &str) -> bool {
                true
            }
            fn complete(
                &self,
                _host: &str,
                _dev: &str,
                _p: &str,
                _h: &str,
                _op: &str,
                _stage: &str,
                dest: &str,
            ) -> bool {
                *self.dest.lock().unwrap() = dest.to_string();
                true
            }
        }
        let t = RecDest {
            dest: Mutex::new(String::new()),
        };
        assert!(rsync_db(
            std::path::Path::new("/d/h/h_1751500010.00000.db"),
            "id",
            "10.0.0.1:6201",
            "sdb",
            "0",
            "h",
            "rsync_then_merge",
            &t
        ));
        assert_eq!(t.dest.lock().unwrap().as_str(), "h_1751500010.00000.db");
        let t2 = RecDest {
            dest: Mutex::new(String::new()),
        };
        assert!(rsync_db(
            std::path::Path::new("/d/h/h.db"),
            "id",
            "10.0.0.1:6201",
            "sdb",
            "0",
            "h",
            "complete_rsync",
            &t2
        ));
        assert_eq!(t2.dest.lock().unwrap().as_str(), "h.db");
    }

    #[test]
    fn test_rsync_db_stages_under_local_id_then_completes() {
        let t = FakeRsync {
            rsynced: Mutex::new(Vec::new()),
            completed: Mutex::new(Vec::new()),
            rsync_ok: true,
        };
        assert!(rsync_db(
            std::path::Path::new("/x/db"),
            "local-uuid-id",
            "10.0.0.1:6201",
            "sdb",
            "5",
            "abc",
            "complete_rsync",
            &t
        ));
        // staged under the LOCAL db id (db_replicator.py:394-395), then the
        // completion RPC named the same staged file
        assert_eq!(
            t.rsynced.lock().unwrap().as_slice(),
            &[("10.0.0.1:6201".to_string(), "local-uuid-id".to_string())]
        );
        assert_eq!(
            t.completed.lock().unwrap().as_slice(),
            &[("complete_rsync".to_string(), "local-uuid-id".to_string())]
        );
    }

    #[test]
    fn test_rsync_failure_skips_complete() {
        let t = FakeRsync {
            rsynced: Mutex::new(Vec::new()),
            completed: Mutex::new(Vec::new()),
            rsync_ok: false,
        };
        assert!(!rsync_db(
            std::path::Path::new("/x/db"),
            "id",
            "h",
            "d",
            "1",
            "a",
            "rsync_then_merge",
            &t
        ));
        // complete is not attempted if the rsync failed
        assert!(t.completed.lock().unwrap().is_empty());
    }

    #[test]
    fn test_synthetic_tombstones_allowed_listing_w104_own_none() {
        use DbState::*;
        // listing-w105: missing own range on a primary must NOT synthesize.
        assert!(!synthetic_tombstones_allowed(
            Some(Unsharded),
            None,
            None,
            false,
            false
        ));
        // listing-w108: empty handoff vs leftover primary.
        assert!(synthetic_tombstones_allowed(
            Some(Unsharded),
            None,
            None,
            false,
            true
        ));
        // L1426 settled ACTIVE after merging the peer's own range.
        assert!(synthetic_tombstones_allowed(
            Some(Unsharded),
            Some(shard_state::ACTIVE),
            Some(0),
            false,
            false
        ));
        // listing-w100: default-ACTIVE during nested cleave must stay off.
        assert!(!synthetic_tombstones_allowed(
            Some(Unsharded),
            Some(shard_state::ACTIVE),
            Some(0),
            true,
            false
        ));
        assert!(!synthetic_tombstones_allowed(
            Some(Unsharded),
            None,
            None,
            true,
            true
        ));
        // L1256 CREATED/CLEAVED child after range merge.
        assert!(!synthetic_tombstones_allowed(
            Some(Unsharded),
            Some(shard_state::CREATED),
            Some(0),
            false,
            true
        ));
        assert!(!synthetic_tombstones_allowed(
            Some(Unsharded),
            Some(shard_state::CLEAVED),
            Some(0),
            false,
            false
        ));
        assert!(!synthetic_tombstones_allowed(
            Some(Sharded),
            Some(shard_state::ACTIVE),
            Some(0),
            false,
            true
        ));
        assert!(!synthetic_tombstones_allowed(
            Some(Unsharded),
            Some(shard_state::ACTIVE),
            Some(1),
            false,
            false
        ));
    }

    #[test]
    fn test_head_object_request_opens_expired() {
        let req = head_object_request("127.0.0.1:16210", "/sdb1/1/a/c/o", 0);
        assert!(
            req.contains("X-Backend-Open-Expired: true"),
            "{req}"
        );
        assert!(
            req.contains("X-Backend-Replication: true"),
            "{req}"
        );
        assert!(
            req.contains("X-Backend-Storage-Policy-Index: 0"),
            "{req}"
        );
    }

    #[test]
    fn test_usync_start_point_resets_when_counts_diverge() {
        assert_eq!(usync_start_point(100, 100, 0, 50), -1);
        assert_eq!(usync_start_point(100, 100, 0, 0), 100);
        assert_eq!(usync_start_point(40, 100, 0, 50), 40);
        // nested cleave: 50 vs 150 must NOT reset (listing-w94 L1321).
        assert_eq!(usync_start_point(150, 150, 50, 150), 150);
        assert_eq!(usync_start_point(150, 150, 150, 50), 150);
        let live = crate::ObjectRecord {
            name: "o".into(),
            created_at: "1751500001.00000".into(),
            size: 1,
            content_type: "text/plain".into(),
            etag: "e".into(),
            deleted: 0,
            storage_policy_index: 0,
            ctype_timestamp: None,
            meta_timestamp: None,
        };
        assert_eq!(usync_created_at(&live), "1751500001.00000");
        let tomb = crate::ObjectRecord {
            name: "o".into(),
            created_at: "1751500001.00000".into(),
            size: 0,
            content_type: "application/deleted".into(),
            etag: "noetag".into(),
            deleted: 1,
            storage_policy_index: 0,
            ctype_timestamp: None,
            meta_timestamp: None,
        };
        assert_eq!(usync_created_at(&tomb), "1751500001.00000");
    }

    #[test]
    fn test_remote_merge_heuristic_sets_usync_incomplete() {
        // _choose_replication_mode (db_replicator.py:579-591): a peer more
        // than 50% and per_diff rows behind is not usynced; the outcome
        // flags the staged rsync_then_merge fallback instead.
        let dir = std::env::temp_dir().join(format!("swift-replrm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut broker = ContainerBroker::new(&dir.join("hash.db"), "a", "c");
        broker
            .initialize("0000000001.00000", 0, "0000000001.00000", "local-id")
            .unwrap();
        // 1001 rows: the gap over an empty peer (max_row -1) exceeds
        // per_diff (1000), and -1/1001 < 0.5
        let records: Vec<crate::ObjectRecord> = (0..1001)
            .map(|i| crate::ObjectRecord {
                name: format!("o{i:04}"),
                created_at: format!("{:010}.00000", 1751500000 + i),
                size: 1,
                content_type: "text/plain".to_string(),
                etag: "e".to_string(),
                deleted: 0,
                storage_policy_index: 0,
                ctype_timestamp: None,
                meta_timestamp: None,
            })
            .collect();
        broker.merge_items(records).unwrap();

        let body = serde_json::json!({
            "point": -1,
            "max_row": -1,
            "id": "peer-id",
            "metadata": "",
        })
        .to_string();
        let (addr, handle) = spawn_fake_peer(body);
        let outcome = replicate_container_db(
            &mut broker,
            "local-id",
            &addr.to_string(),
            "sdb",
            "0",
            "hash",
        )
        .unwrap();
        handle.join().unwrap();
        assert!(outcome.usync_incomplete);
        assert!(!outcome.needs_rsync);
        // no merge_items batches were attempted
        assert_eq!(outcome.diffs, 0);
        assert_eq!(outcome.rows_pushed, 0);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
