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

//! The container reconciler core, ported from `swift/container/reconciler.py`.
//!
//! When an object is written under the wrong storage policy (e.g. during a
//! policy change race), the container server enqueues a *misplaced object*
//! entry into the hidden `.misplaced_objects` account. The reconciler daemon
//! later drains that queue, moving each object to the container's correct
//! policy (newest-timestamp wins) and removing the misplaced copy.
//!
//! The queue naming is the interoperability contract with the Python container
//! server that writes it, so it is golden-tested byte-for-byte:
//!
//! * queue container = `str(int(meta_ts) // 3600 * 3600)` (the object's
//!   last-modified hour bucket),
//! * queue object    = `"{policy_index}:/{account}/{container}/{object}"`,
//! * content-type    = `application/x-put` | `application/x-delete`.
//!
//! Production uses [`HttpReconcileClient`] (ring-direct GET/PUT/DELETE move)
//! and [`run_once`] over the `.misplaced_objects` queue. Deferred: the
//! `cmp_policy_info` container-recreation tie-break and the two-phase enqueue.
//! The move *decision* (which policy is authoritative, whether a queue entry
//! is still actionable) is ported and unit-tested over a pluggable client.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{SystemTime, UNIX_EPOCH};

use swift_core::timestamp::decode_timestamps;
use swift_http::split_path;
use swift_ring::Ring;

/// The hidden account holding the misplaced-object queue.
pub const MISPLACED_OBJECTS_ACCOUNT: &str = ".misplaced_objects";

/// Queue containers bucket objects by the hour of their last modification.
pub const MISPLACED_OBJECTS_CONTAINER_DIVISOR: i64 = 3600;

/// `get_reconciler_container_name`: the queue container an object's misplaced
/// entry belongs in — its meta timestamp floored to the hour, as a plain
/// (non-zero-padded) integer string.
pub fn reconciler_container_name(obj_timestamp: &str) -> Option<String> {
    let (data, _ctype, meta) = decode_timestamps(obj_timestamp, false).ok()?;
    // non-explicit decode yields Some(data) when the meta part is absent
    let meta = meta.unwrap_or(data);
    let secs = meta.as_secs_f64() as i64; // int(Timestamp)
    let bucket =
        secs.div_euclid(MISPLACED_OBJECTS_CONTAINER_DIVISOR) * MISPLACED_OBJECTS_CONTAINER_DIVISOR;
    Some(bucket.to_string())
}

/// `get_reconciler_obj_name`: the queue object name encoding the misplaced
/// object's (wrong) policy index and full path.
pub fn reconciler_obj_name(policy_index: i64, account: &str, container: &str, obj: &str) -> String {
    format!("{policy_index}:/{account}/{container}/{obj}")
}

/// `get_reconciler_content_type`: the content-type marking the queued op.
pub fn reconciler_content_type(op: &str) -> Option<&'static str> {
    match op.to_ascii_lowercase().as_str() {
        "put" => Some("application/x-put"),
        "delete" => Some("application/x-delete"),
        _ => None,
    }
}

/// A parsed misplaced-object queue entry.
#[derive(Debug, Clone, PartialEq)]
pub struct QueueEntry {
    pub policy_index: i64,
    pub account: String,
    pub container: String,
    pub obj: String,
}

/// `parse_raw_obj` (name portion): split `"{pi}:/{account}/{container}/{obj}"`
/// back into its parts.
pub fn parse_reconciler_obj_name(raw: &str) -> Option<QueueEntry> {
    let (pi, rest) = raw.split_once(':')?;
    let policy_index: i64 = pi.parse().ok()?;
    // rest is "/account/container/object"
    let parts = split_path(rest, 3, 3, true).ok()?;
    Some(QueueEntry {
        policy_index,
        account: parts[0].clone()?,
        container: parts[1].clone()?,
        obj: parts[2].clone()?,
    })
}

/// The op a queue entry represents.
#[derive(Debug, Clone, PartialEq)]
pub enum QueueOp {
    Put,
    Delete,
}

/// Recover the op from a queue entry's content-type.
pub fn op_from_content_type(content_type: &str) -> Option<QueueOp> {
    match content_type {
        "application/x-put" => Some(QueueOp::Put),
        "application/x-delete" => Some(QueueOp::Delete),
        _ => None,
    }
}

/// The reconcile decision for one queue entry, given the container's current
/// (authoritative) storage policy index.
#[derive(Debug, Clone, PartialEq)]
pub enum ReconcileDecision {
    /// The queued policy is already the authoritative one; the object is not
    /// misplaced (any more) — just clean up the queue entry.
    AlreadyCorrect,
    /// Move the object from `from_policy` to `to_policy`.
    Move { from_policy: i64, to_policy: i64 },
}

/// Decide what to do with a misplaced-object queue entry. If the queued
/// (wrong) policy equals the container's current policy, the object is no
/// longer misplaced; otherwise it must be moved to the current policy.
pub fn decide(entry: &QueueEntry, current_policy_index: i64) -> ReconcileDecision {
    if entry.policy_index == current_policy_index {
        ReconcileDecision::AlreadyCorrect
    } else {
        ReconcileDecision::Move {
            from_policy: entry.policy_index,
            to_policy: current_policy_index,
        }
    }
}

/// The outcome of reconciling one misplaced-object queue entry.
#[derive(Debug, Clone, PartialEq)]
pub enum ReconcileOutcome {
    /// The object was moved to the correct policy and the queue entry popped.
    Moved,
    /// The object was already in the correct policy; the queue entry popped.
    AlreadyCorrect,
    /// The move failed; the queue entry is left for a later pass.
    Failed,
}

/// The reconciler's backend actions, so the move orchestration is testable
/// without a live cluster. `move_object` performs the GET-from-wrong-policy →
/// PUT-to-right-policy → DELETE-from-wrong-policy sequence; `pop_queue` removes
/// the queue entry.
pub trait ReconcileClient {
    /// Move the object from `from_policy` to `to_policy`. Returns success.
    fn move_object(&self, entry: &QueueEntry, from_policy: i64, to_policy: i64) -> bool;
    /// Remove the misplaced-object queue entry.
    fn pop_queue(&self, entry: &QueueEntry) -> bool;
}

/// Reconcile one misplaced-object queue entry against the container's current
/// (authoritative) storage policy: move the object to the right policy if
/// needed, then pop the queue entry (Python `container/reconciler.py`
/// `process_queue_item`).
pub fn reconcile(
    entry: &QueueEntry,
    current_policy_index: i64,
    client: &dyn ReconcileClient,
) -> ReconcileOutcome {
    match decide(entry, current_policy_index) {
        ReconcileDecision::AlreadyCorrect => {
            client.pop_queue(entry);
            ReconcileOutcome::AlreadyCorrect
        }
        ReconcileDecision::Move {
            from_policy,
            to_policy,
        } => {
            if client.move_object(entry, from_policy, to_policy) {
                client.pop_queue(entry);
                ReconcileOutcome::Moved
            } else {
                ReconcileOutcome::Failed
            }
        }
    }
}

fn pe(s: &str) -> String {
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

fn http_status(buf: &[u8]) -> u16 {
    String::from_utf8_lossy(buf)
        .split("\r\n")
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or(500)
}

fn http_body(buf: &[u8]) -> &[u8] {
    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
        &buf[pos + 4..]
    } else {
        &[]
    }
}

fn header_value<'a>(buf: &'a [u8], name: &str) -> Option<&'a str> {
    let head = std::str::from_utf8(buf).ok()?;
    let end = head.find("\r\n\r\n").unwrap_or(head.len());
    for line in head[..end].split("\r\n").skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            if k.eq_ignore_ascii_case(name) {
                return Some(v.trim());
            }
        }
    }
    None
}

fn node_host(node: &swift_ring::RingDevice, replication: bool) -> String {
    if replication {
        let ip = node
            .replication_ip
            .clone()
            .unwrap_or_else(|| node.ip.clone());
        let port = node.replication_port.unwrap_or(node.port);
        format!("{ip}:{port}")
    } else {
        format!("{}:{}", node.ip, node.port)
    }
}

fn raw_request(
    host: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Option<(u16, Vec<u8>)> {
    let mut request = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\n");
    for (k, v) in headers {
        request.push_str(&format!("{k}: {v}\r\n"));
    }
    request.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    ));
    let Ok(mut conn) = TcpStream::connect(host) else {
        return None;
    };
    conn.set_nodelay(true).ok();
    let _ = conn.set_read_timeout(Some(std::time::Duration::from_secs(30)));
    if conn.write_all(request.as_bytes()).is_err() {
        return None;
    }
    if !body.is_empty() && conn.write_all(body).is_err() {
        return None;
    }
    let mut buf = Vec::new();
    if conn.read_to_end(&mut buf).is_err() {
        return None;
    }
    Some((http_status(&buf), buf))
}

/// List containers under an account (JSON names).
pub fn list_account_containers(account_ring: &Ring, account: &str) -> Option<Vec<String>> {
    let (part, nodes) = account_ring.get_nodes(account, None, None).ok()?;
    for node in &nodes {
        let host = node_host(node.dev, true);
        let path = format!(
            "/{}/{part}/{}?format=json&limit=10000",
            node.dev.device,
            pe(account)
        );
        let Some((status, buf)) = raw_request(
            &host,
            "GET",
            &path,
            &[
                ("Accept", "application/json"),
                ("X-Backend-Allow-Reserved-Names", "true"),
            ],
            &[],
        ) else {
            continue;
        };
        if status == 404 {
            return Some(Vec::new());
        }
        if !(200..300).contains(&status) {
            continue;
        }
        let body = http_body(&buf);
        let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) else {
            continue;
        };
        let Some(arr) = v.as_array() else {
            continue;
        };
        let mut names = Vec::new();
        for item in arr {
            if let Some(name) = item.get("name").and_then(|n| n.as_str()) {
                names.push(name.to_string());
            }
        }
        return Some(names);
    }
    None
}

/// List misplaced-object queue entries (name + content_type).
pub fn list_queue_objects(
    container_ring: &Ring,
    account: &str,
    container: &str,
) -> Option<Vec<(String, String)>> {
    let (part, nodes) = container_ring
        .get_nodes(account, Some(container), None)
        .ok()?;
    for node in &nodes {
        let host = node_host(node.dev, true);
        let path = format!(
            "/{}/{part}/{}/{}?format=json&limit=10000",
            node.dev.device,
            pe(account),
            pe(container)
        );
        let Some((status, buf)) = raw_request(
            &host,
            "GET",
            &path,
            &[
                ("Accept", "application/json"),
                ("X-Backend-Allow-Reserved-Names", "true"),
                ("X-Backend-Storage-Policy-Index", "0"),
            ],
            &[],
        ) else {
            continue;
        };
        if status == 404 {
            return Some(Vec::new());
        }
        if !(200..300).contains(&status) {
            continue;
        }
        let body = http_body(&buf);
        let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) else {
            continue;
        };
        let Some(arr) = v.as_array() else {
            continue;
        };
        let mut out = Vec::new();
        for item in arr {
            let Some(name) = item.get("name").and_then(|n| n.as_str()) else {
                continue;
            };
            let ctype = item
                .get("content_type")
                .and_then(|c| c.as_str())
                .unwrap_or("")
                .to_string();
            out.push((name.to_string(), ctype));
        }
        return Some(out);
    }
    None
}

/// Read a container's authoritative storage policy index (HEAD).
pub fn container_policy_index(
    container_ring: &Ring,
    account: &str,
    container: &str,
) -> Option<i64> {
    let (part, nodes) = container_ring
        .get_nodes(account, Some(container), None)
        .ok()?;
    for node in &nodes {
        let host = node_host(node.dev, true);
        let path = format!(
            "/{}/{part}/{}/{}",
            node.dev.device,
            pe(account),
            pe(container)
        );
        let Some((status, buf)) = raw_request(
            &host,
            "HEAD",
            &path,
            &[("X-Backend-Storage-Policy-Index", "0")],
            &[],
        ) else {
            continue;
        };
        if !(200..300).contains(&status) {
            continue;
        }
        if let Some(raw) = header_value(&buf, "X-Backend-Storage-Policy-Index") {
            if let Ok(pi) = raw.parse::<i64>() {
                return Some(pi);
            }
        }
        return Some(0);
    }
    None
}

/// Ring-direct reconcile client: GET from wrong policy → PUT to right →
/// DELETE from wrong; pop via container ring.
pub struct HttpReconcileClient<'a> {
    pub object_ring: &'a Ring,
    pub container_ring: &'a Ring,
    /// Queue container the entry was listed from (for pop_queue).
    pub queue_container: String,
}

impl ReconcileClient for HttpReconcileClient<'_> {
    fn move_object(&self, entry: &QueueEntry, from_policy: i64, to_policy: i64) -> bool {
        let Ok((part, nodes)) =
            self.object_ring
                .get_nodes(&entry.account, Some(&entry.container), Some(&entry.obj))
        else {
            return false;
        };
        let from_pi = from_policy.to_string();
        let to_pi = to_policy.to_string();
        // GET body from any primary that still has the misplaced object.
        let mut body: Option<Vec<u8>> = None;
        let mut etag = String::new();
        let mut content_type = String::from("application/octet-stream");
        let mut x_timestamp = String::new();
        for node in &nodes {
            let host = node_host(node.dev, false);
            let path = format!(
                "/{}/{part}/{}/{}/{}",
                node.dev.device,
                pe(&entry.account),
                pe(&entry.container),
                pe(&entry.obj)
            );
            let Some((status, buf)) = raw_request(
                &host,
                "GET",
                &path,
                &[("X-Backend-Storage-Policy-Index", from_pi.as_str())],
                &[],
            ) else {
                continue;
            };
            if !(200..300).contains(&status) {
                continue;
            }
            etag = header_value(&buf, "ETag")
                .unwrap_or("")
                .trim_matches('"')
                .to_string();
            content_type = header_value(&buf, "Content-Type")
                .unwrap_or("application/octet-stream")
                .to_string();
            x_timestamp = header_value(&buf, "X-Timestamp")
                .or_else(|| header_value(&buf, "X-Backend-Timestamp"))
                .unwrap_or("")
                .to_string();
            body = Some(http_body(&buf).to_vec());
            break;
        }
        let Some(body) = body else {
            // Already gone from the wrong policy — treat as success so the
            // queue entry can be popped (AlreadyCorrect-ish).
            return true;
        };
        if x_timestamp.is_empty() {
            x_timestamp = format!(
                "{:.5}",
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs_f64())
                    .unwrap_or(0.0)
            );
        }
        // PUT to the correct policy on a majority of primaries.
        let mut put_ok = 0usize;
        for node in &nodes {
            let host = node_host(node.dev, false);
            let path = format!(
                "/{}/{part}/{}/{}/{}",
                node.dev.device,
                pe(&entry.account),
                pe(&entry.container),
                pe(&entry.obj)
            );
            let Some((status, _)) = raw_request(
                &host,
                "PUT",
                &path,
                &[
                    ("X-Timestamp", x_timestamp.as_str()),
                    ("Content-Type", content_type.as_str()),
                    ("X-Backend-Storage-Policy-Index", to_pi.as_str()),
                    ("ETag", etag.as_str()),
                ],
                &body,
            ) else {
                continue;
            };
            if (200..300).contains(&status) {
                put_ok += 1;
            }
        }
        if put_ok * 2 <= nodes.len() {
            return false;
        }
        // DELETE the misplaced copy.
        let mut del_ok = 0usize;
        for node in &nodes {
            let host = node_host(node.dev, false);
            let path = format!(
                "/{}/{part}/{}/{}/{}",
                node.dev.device,
                pe(&entry.account),
                pe(&entry.container),
                pe(&entry.obj)
            );
            let Some((status, _)) = raw_request(
                &host,
                "DELETE",
                &path,
                &[
                    ("X-Timestamp", x_timestamp.as_str()),
                    ("X-Backend-Storage-Policy-Index", from_pi.as_str()),
                ],
                &[],
            ) else {
                continue;
            };
            if (200..300).contains(&status) || status == 404 {
                del_ok += 1;
            }
        }
        del_ok > 0
    }

    fn pop_queue(&self, entry: &QueueEntry) -> bool {
        let qname = reconciler_obj_name(
            entry.policy_index,
            &entry.account,
            &entry.container,
            &entry.obj,
        );
        let Ok((part, nodes)) = self.container_ring.get_nodes(
            MISPLACED_OBJECTS_ACCOUNT,
            Some(&self.queue_container),
            Some(&qname),
        ) else {
            return false;
        };
        let ts = format!(
            "{:.5}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs_f64())
                .unwrap_or(0.0)
        );
        let mut ok = 0usize;
        for node in &nodes {
            let host = node_host(node.dev, true);
            let path = format!(
                "/{}/{part}/{}/{}/{}",
                node.dev.device,
                pe(MISPLACED_OBJECTS_ACCOUNT),
                pe(&self.queue_container),
                pe(&qname)
            );
            let Some((status, _)) = raw_request(
                &host,
                "DELETE",
                &path,
                &[
                    ("X-Timestamp", ts.as_str()),
                    ("X-Backend-Storage-Policy-Index", "0"),
                    ("X-Backend-Allow-Reserved-Names", "true"),
                ],
                &[],
            ) else {
                continue;
            };
            if (200..300).contains(&status) || status == 404 {
                ok += 1;
            }
        }
        ok > 0
    }
}

/// Aggregated reconciler pass stats.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ReconcilerStats {
    pub moved: u64,
    pub already_correct: u64,
    pub failed: u64,
    pub errors: u64,
}

/// One full pass over `.misplaced_objects`.
pub fn run_once(account_ring: &Ring, container_ring: &Ring, object_ring: &Ring) -> ReconcilerStats {
    let mut stats = ReconcilerStats::default();
    let Some(containers) = list_account_containers(account_ring, MISPLACED_OBJECTS_ACCOUNT) else {
        stats.errors += 1;
        return stats;
    };
    for qcontainer in containers {
        let Some(objects) =
            list_queue_objects(container_ring, MISPLACED_OBJECTS_ACCOUNT, &qcontainer)
        else {
            stats.errors += 1;
            continue;
        };
        for (name, _ctype) in objects {
            let Some(entry) = parse_reconciler_obj_name(&name) else {
                continue;
            };
            let Some(current_pi) =
                container_policy_index(container_ring, &entry.account, &entry.container)
            else {
                stats.errors += 1;
                continue;
            };
            let client = HttpReconcileClient {
                object_ring,
                container_ring,
                queue_container: qcontainer.clone(),
            };
            match reconcile(&entry, current_pi, &client) {
                ReconcileOutcome::Moved => stats.moved += 1,
                ReconcileOutcome::AlreadyCorrect => stats.already_correct += 1,
                ReconcileOutcome::Failed => stats.failed += 1,
            }
        }
    }
    stats
}

/// Recon-cache update for the container reconciler.
pub fn recon_update(elapsed: std::time::Duration, stats: &ReconcilerStats) -> serde_json::Value {
    serde_json::json!({
        "container_reconciler_pass": elapsed.as_secs_f64(),
        "moved": stats.moved,
        "already_correct": stats.already_correct,
        "failed": stats.failed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct FakeReconcile {
        moves: Mutex<Vec<(i64, i64)>>,
        popped: Mutex<Vec<String>>,
        move_ok: bool,
    }
    impl ReconcileClient for FakeReconcile {
        fn move_object(&self, _e: &QueueEntry, from: i64, to: i64) -> bool {
            self.moves.lock().unwrap().push((from, to));
            self.move_ok
        }
        fn pop_queue(&self, e: &QueueEntry) -> bool {
            self.popped.lock().unwrap().push(e.obj.clone());
            true
        }
    }

    #[test]
    fn test_reconcile_moves_then_pops() {
        let e = QueueEntry {
            policy_index: 1,
            account: "a".into(),
            container: "c".into(),
            obj: "o".into(),
        };
        let client = FakeReconcile {
            moves: Mutex::new(Vec::new()),
            popped: Mutex::new(Vec::new()),
            move_ok: true,
        };
        assert_eq!(reconcile(&e, 0, &client), ReconcileOutcome::Moved);
        assert_eq!(*client.moves.lock().unwrap(), vec![(1, 0)]);
        assert_eq!(client.popped.lock().unwrap().len(), 1);
    }

    #[test]
    fn test_reconcile_already_correct_just_pops() {
        let e = QueueEntry {
            policy_index: 0,
            account: "a".into(),
            container: "c".into(),
            obj: "o".into(),
        };
        let client = FakeReconcile {
            moves: Mutex::new(Vec::new()),
            popped: Mutex::new(Vec::new()),
            move_ok: true,
        };
        assert_eq!(reconcile(&e, 0, &client), ReconcileOutcome::AlreadyCorrect);
        assert!(client.moves.lock().unwrap().is_empty());
        assert_eq!(client.popped.lock().unwrap().len(), 1);
    }

    #[test]
    fn test_reconcile_failed_move_keeps_entry() {
        let e = QueueEntry {
            policy_index: 2,
            account: "a".into(),
            container: "c".into(),
            obj: "o".into(),
        };
        let client = FakeReconcile {
            moves: Mutex::new(Vec::new()),
            popped: Mutex::new(Vec::new()),
            move_ok: false,
        };
        assert_eq!(reconcile(&e, 0, &client), ReconcileOutcome::Failed);
        assert!(client.popped.lock().unwrap().is_empty());
    }

    #[test]
    fn test_reconciler_obj_name_and_parse() {
        let name = reconciler_obj_name(1, "AUTH_test", "c", "o/deep");
        assert_eq!(name, "1:/AUTH_test/c/o/deep");
        let e = parse_reconciler_obj_name(&name).unwrap();
        assert_eq!(e.policy_index, 1);
        assert_eq!(e.account, "AUTH_test");
        assert_eq!(e.container, "c");
        assert_eq!(e.obj, "o/deep");
    }

    #[test]
    fn test_content_type_roundtrip() {
        assert_eq!(reconciler_content_type("put"), Some("application/x-put"));
        assert_eq!(
            reconciler_content_type("DELETE"),
            Some("application/x-delete")
        );
        assert_eq!(reconciler_content_type("bogus"), None);
        assert_eq!(
            op_from_content_type("application/x-put"),
            Some(QueueOp::Put)
        );
        assert_eq!(
            op_from_content_type("application/x-delete"),
            Some(QueueOp::Delete)
        );
    }

    #[test]
    fn test_container_name_hour_bucket() {
        // 1751500000 // 3600 * 3600 = 1751497200
        let name = reconciler_container_name("1751500000.00000").unwrap();
        assert_eq!(name, "1751497200");
        // not zero-padded (unlike the expirer's queue)
        assert!(!name.starts_with('0'));
    }

    #[test]
    fn test_decide_move_vs_correct() {
        let e = QueueEntry {
            policy_index: 1,
            account: "a".into(),
            container: "c".into(),
            obj: "o".into(),
        };
        assert_eq!(
            decide(&e, 0),
            ReconcileDecision::Move {
                from_policy: 1,
                to_policy: 0
            }
        );
        assert_eq!(decide(&e, 1), ReconcileDecision::AlreadyCorrect);
    }
}
