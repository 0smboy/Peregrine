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

use std::io::{Read, Write};

use crate::container::DbValue;
use crate::{py_json_parse_metadata, AccountBroker, ContainerBroker, DbError};

const PER_DIFF: i64 = 1000;
const MAX_DIFFS: i64 = 100;

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
    /// POST the completion RPC `[op, stage_name, ...]` telling the peer to
    /// adopt (`complete_rsync`) or merge (`rsync_then_merge`) the staged
    /// DB (db_replicator.py:409-412). Returns success.
    fn complete(
        &self,
        peer_host: &str,
        peer_device: &str,
        partition: &str,
        hsh: &str,
        op: &str,
        stage_name: &str,
    ) -> bool;
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
    transport.complete(peer_host, peer_device, partition, hsh, op, local_id)
}

/// The completion RPC at the end of `_rsync_db` (db_replicator.py:409-412):
/// POST `[op, stage_name, <hsh>.db]` to the peer's REPLICATE endpoint and
/// report success on any 2xx (Python's `200 <= response.status < 300`).
/// Python sends `os.path.basename(broker.db_file)` as the third element;
/// this replicator only stages plain `<hsh>.db` DBs, so the basename is
/// derived from the URL hash.
pub fn replicate_completion_rpc(
    host: &str,
    device: &str,
    partition: &str,
    hsh: &str,
    op: &str,
    stage_name: &str,
) -> Result<bool, DbError> {
    let body = serde_json::json!([op, stage_name, format!("{hsh}.db")]);
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
    let info = local.get_replication_info()?;
    let get = |k: &str| {
        info.iter()
            .find(|(key, _)| key == k)
            .map(|(_, v)| value_str(v))
            .unwrap_or_default()
    };
    let local_max_row: i64 = get("max_row").parse().unwrap_or(-1);
    let metadata = get("metadata");

    // sync RPC: [op, remote_sync(max_row), hash, id, created_at,
    // put_timestamp, delete_timestamp, metadata]
    let sync_body = serde_json::json!([
        "sync",
        local_max_row,
        get("hash"),
        local_id,
        get("created_at"),
        get("put_timestamp"),
        get("delete_timestamp"),
        metadata,
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
        if items.is_empty() {
            break;
        }
        let json_items: Vec<serde_json::Value> = items
            .iter()
            .map(|(rowid, rec)| {
                serde_json::json!({
                    "ROWID": rowid,
                    "name": rec.name,
                    "created_at": rec.created_at,
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
    Ok(ReplicateOutcome {
        diffs,
        rows_pushed,
        point,
        needs_rsync: false,
        usync_incomplete,
    })
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
    use std::sync::Mutex;

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
    fn spawn_fake_peer(body: String) -> (std::net::SocketAddr, std::thread::JoinHandle<()>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
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
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(resp.as_bytes()).unwrap();
        });
        (addr, handle)
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

        let outcome =
            replicate_container_db(&mut broker, "local-id", &addr.to_string(), "sdb", "0", "hash")
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
        let outcome =
            replicate_container_db(&mut broker, "local-id", &addr.to_string(), "sdb", "0", "hash")
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
