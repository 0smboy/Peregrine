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
//! Production uses [`HttpReconcileClient`] through an explicitly configured
//! internal proxy. The proxy is required: it selects the source/destination
//! policy rings and performs EC encoding on a replication-to-EC move.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{SystemTime, UNIX_EPOCH};

use swift_core::hashing::HashPathConfig;
use swift_core::timestamp::{decode_timestamps, Timestamp};
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

/// One fully parsed row from a `.misplaced_objects` queue listing.
///
/// `q_ts` is the timestamp encoded in the listing hash; `q_record` is the
/// timestamp of the queue row itself.  They differ when an operator forcibly
/// re-enqueues an older object, so both are needed to avoid popping a newer
/// queue record after processing a stale listing page.
#[derive(Debug, Clone, PartialEq)]
pub struct QueueRecord {
    pub entry: QueueEntry,
    pub op: QueueOp,
    pub q_ts: Timestamp,
    pub q_record: Timestamp,
}

/// Raw fields required from a JSON container-listing row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueListingEntry {
    pub name: String,
    pub content_type: String,
    pub hash: String,
    pub last_modified: String,
}

/// Recover the op from a queue entry's content-type.
pub fn op_from_content_type(content_type: &str) -> Option<QueueOp> {
    match content_type {
        "application/x-put" => Some(QueueOp::Put),
        "application/x-delete" => Some(QueueOp::Delete),
        _ => None,
    }
}

/// Port of Python `parse_raw_obj` for a reconciler queue listing row.
pub fn parse_queue_record(raw: &QueueListingEntry) -> Option<QueueRecord> {
    let entry = parse_reconciler_obj_name(&raw.name)?;
    let op = op_from_content_type(&raw.content_type)?;
    let (q_ts, _, _) = decode_timestamps(&raw.hash, false).ok()?;
    let q_record = Timestamp::from_isoformat(&raw.last_modified).ok()?;
    Some(QueueRecord {
        entry,
        op,
        q_ts,
        q_record,
    })
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
    fn move_object(&self, record: &QueueRecord, from_policy: i64, to_policy: i64) -> bool;
    /// Remove the misplaced-object queue entry.
    fn pop_queue(&self, record: &QueueRecord) -> bool;
}

/// Reconcile one misplaced-object queue entry against the container's current
/// (authoritative) storage policy: move the object to the right policy if
/// needed, then pop the queue entry (Python `container/reconciler.py`
/// `process_queue_item`).
pub fn reconcile(
    record: &QueueRecord,
    current_policy_index: i64,
    client: &dyn ReconcileClient,
) -> ReconcileOutcome {
    match decide(&record.entry, current_policy_index) {
        ReconcileDecision::AlreadyCorrect => {
            client.pop_queue(record);
            ReconcileOutcome::AlreadyCorrect
        }
        ReconcileDecision::Move {
            from_policy,
            to_policy,
        } => {
            if client.move_object(record, from_policy, to_policy) {
                client.pop_queue(record);
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

fn decoded_http_body(buf: &[u8]) -> Option<Vec<u8>> {
    let split = buf.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = std::str::from_utf8(&buf[..split]).ok()?;
    let chunked = head.lines().skip(1).any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("transfer-encoding")
                && value
                    .split(',')
                    .any(|coding| coding.trim().eq_ignore_ascii_case("chunked"))
        })
    });
    let body = &buf[split + 4..];
    if !chunked {
        return Some(body.to_vec());
    }

    let mut rest = body;
    let mut decoded = Vec::new();
    loop {
        let line_end = rest.windows(2).position(|w| w == b"\r\n")?;
        let size_token = std::str::from_utf8(&rest[..line_end])
            .ok()?
            .split(';')
            .next()?
            .trim();
        let size = usize::from_str_radix(size_token, 16).ok()?;
        rest = &rest[line_end + 2..];
        if size == 0 {
            return Some(decoded);
        }
        if rest.len() < size + 2 || &rest[size..size + 2] != b"\r\n" {
            return None;
        }
        decoded.extend_from_slice(&rest[..size]);
        rest = &rest[size + 2..];
    }
}

fn timestamp_with_offset(raw: &str, offset: u64) -> Option<String> {
    let mut timestamp: Timestamp = raw.parse().ok()?;
    timestamp.increment_offset(offset).ok()?;
    Some(timestamp.internal())
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

fn raw_request<K: AsRef<str>, V: AsRef<str>>(
    host: &str,
    method: &str,
    path: &str,
    headers: &[(K, V)],
    body: &[u8],
) -> Option<(u16, Vec<u8>)> {
    let mut request = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\n");
    for (k, v) in headers {
        request.push_str(&format!("{}: {}\r\n", k.as_ref(), v.as_ref()));
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

fn response_headers(buf: &[u8]) -> Option<Vec<(String, String)>> {
    let split = buf.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = std::str::from_utf8(&buf[..split]).ok()?;
    Some(
        head.split("\r\n")
            .skip(1)
            .filter_map(|line| {
                let (name, value) = line.split_once(':')?;
                Some((name.trim().to_string(), value.trim().to_string()))
            })
            .collect(),
    )
}

/// Headers copied by Python's reconciler from the source GET to the
/// destination PUT. Response framing, transaction, and backend-selection
/// headers must not be replayed; object metadata and middleware contracts
/// (SLO/DLO/symlink) must survive the move.
fn copied_source_headers(buf: &[u8]) -> Option<Vec<(String, String)>> {
    let mut copied = Vec::new();
    for (name, value) in response_headers(buf)? {
        let lower = name.to_ascii_lowercase();
        let keep = matches!(
            lower.as_str(),
            "content-type"
                | "content-encoding"
                | "content-disposition"
                | "content-language"
                | "cache-control"
                | "expires"
                | "x-robots-tag"
                | "x-delete-at"
                | "x-object-manifest"
                | "x-static-large-object"
        ) || lower.starts_with("x-object-meta-")
            || lower.starts_with("x-object-sysmeta-")
            || lower.starts_with("x-object-transient-sysmeta-")
            || lower.starts_with("x-symlink-");
        if keep {
            copied.push((name, value));
        }
    }
    Some(copied)
}

/// List containers under an account (JSON names).
pub fn list_account_containers(account_ring: &Ring, account: &str) -> Option<Vec<String>> {
    let (part, nodes) = account_ring.get_nodes(account, None, None).ok()?;
    let mut usable_response = false;
    let mut merged = BTreeSet::new();
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
            usable_response = true;
            continue;
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
        usable_response = true;
        for item in arr {
            if let Some(name) = item.get("name").and_then(|n| n.as_str()) {
                merged.insert(name.to_string());
            }
        }
    }
    let names: Vec<String> = merged.into_iter().collect();
    usable_response.then_some(names)
}

/// List misplaced-object queue entries with the timestamps required by
/// Python `parse_raw_obj`.
pub fn list_queue_objects(
    container_ring: &Ring,
    account: &str,
    container: &str,
) -> Option<Vec<QueueListingEntry>> {
    let (part, nodes) = container_ring
        .get_nodes(account, Some(container), None)
        .ok()?;
    let mut usable_response = false;
    let mut merged = BTreeMap::new();
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
            usable_response = true;
            continue;
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
        usable_response = true;
        for item in arr {
            let Some(name) = item.get("name").and_then(|n| n.as_str()) else {
                continue;
            };
            let content_type = item
                .get("content_type")
                .and_then(|c| c.as_str())
                .unwrap_or("")
                .to_string();
            let hash = item
                .get("hash")
                .and_then(|value| value.as_str())
                .unwrap_or("")
                .to_string();
            let last_modified = item
                .get("last_modified")
                .and_then(|value| value.as_str())
                .unwrap_or("")
                .to_string();
            let candidate = QueueListingEntry {
                name: name.to_string(),
                content_type,
                hash,
                last_modified,
            };
            merged
                .entry(name.to_string())
                .and_modify(|current: &mut QueueListingEntry| {
                    if candidate.last_modified > current.last_modified {
                        *current = candidate.clone();
                    }
                })
                .or_insert(candidate);
        }
    }
    let objects: Vec<QueueListingEntry> = merged.into_values().collect();
    usable_response.then_some(objects)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ContainerPolicyInfo {
    storage_policy_index: i64,
    put_timestamp: Timestamp,
    delete_timestamp: Timestamp,
    status_changed_at: Timestamp,
    object_count: i64,
}

fn policy_info_from_response(buf: &[u8]) -> Option<ContainerPolicyInfo> {
    let zero = Timestamp::zero();
    let parse_ts = |name: &str| {
        header_value(buf, name)
            .and_then(|value| value.parse().ok())
            .unwrap_or(zero)
    };
    Some(ContainerPolicyInfo {
        storage_policy_index: header_value(buf, "X-Backend-Storage-Policy-Index")
            .and_then(|value| value.parse().ok())?,
        put_timestamp: parse_ts("X-Backend-Put-Timestamp"),
        delete_timestamp: parse_ts("X-Backend-Delete-Timestamp"),
        status_changed_at: parse_ts("X-Backend-Status-Changed-At"),
        object_count: header_value(buf, "X-Container-Object-Count")
            .or_else(|| header_value(buf, "X-Backend-Object-Count"))
            .and_then(|value| value.parse().ok())
            .unwrap_or(0),
    })
}

fn timestamp_cmp(left: Timestamp, right: Timestamp) -> i8 {
    if left < right {
        -1
    } else if right < left {
        1
    } else {
        0
    }
}

/// Exact decision table from Python `cmp_policy_info`: positive means the
/// remote candidate is a better authority than the current choice.
fn cmp_policy_info(info: ContainerPolicyInfo, remote: ContainerPolicyInfo) -> i8 {
    let is_deleted = |candidate: ContainerPolicyInfo| {
        candidate.delete_timestamp > candidate.put_timestamp && candidate.object_count == 0
    };
    let deleted = is_deleted(info);
    let remote_deleted = is_deleted(remote);
    if deleted || remote_deleted {
        if !deleted {
            return -1;
        }
        if !remote_deleted {
            return 1;
        }
        return timestamp_cmp(remote.status_changed_at, info.status_changed_at);
    }

    let recreated = info.put_timestamp > info.delete_timestamp
        && info.delete_timestamp > Timestamp::zero();
    let remote_recreated = remote.put_timestamp > remote.delete_timestamp
        && remote.delete_timestamp > Timestamp::zero();
    if recreated || remote_recreated {
        if !recreated {
            return 1;
        }
        if !remote_recreated {
            return -1;
        }
        let most_recent_delete = info.delete_timestamp.max(remote.delete_timestamp);
        if info.put_timestamp < most_recent_delete {
            return 1;
        }
        if remote.put_timestamp < most_recent_delete {
            return -1;
        }
    }
    timestamp_cmp(info.status_changed_at, remote.status_changed_at)
}

/// Read a container's authoritative storage policy index (HEAD).  Swift must
/// hear from a majority of primaries and apply the deleted/recreated-container
/// comparison rules; returning the first 2xx races policy changes.
pub fn container_policy_index(
    container_ring: &Ring,
    account: &str,
    container: &str,
) -> Option<i64> {
    let (part, nodes) = container_ring
        .get_nodes(account, Some(container), None)
        .ok()?;
    let majority = nodes.len() / 2 + 1;
    let mut responses = Vec::new();
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
        if !(200..300).contains(&status) && status != 404 {
            continue;
        }
        if let Some(info) = policy_info_from_response(&buf) {
            responses.push(info);
        }
    }
    if responses.len() < majority {
        return None;
    }
    let mut best = responses[0];
    for candidate in responses.into_iter().skip(1) {
        if cmp_policy_info(best, candidate) > 0 {
            best = candidate;
        }
    }
    Some(best.storage_policy_index)
}

/// Internal-proxy reconcile client: GET from wrong policy → PUT to right →
/// DELETE from wrong; pop remains ring-direct to the queue container.
pub struct HttpReconcileClient<'a> {
    /// Explicit `host:port` of a loopback/internal proxy pipeline. It must
    /// preserve trusted X-Backend headers and must not be a public endpoint.
    pub proxy_host: &'a str,
    pub container_ring: &'a Ring,
    /// Queue container the entry was listed from (for pop_queue).
    pub queue_container: String,
}

impl HttpReconcileClient<'_> {
    fn object_path(entry: &QueueEntry) -> String {
        format!(
            "/v1/{}/{}/{}",
            pe(&entry.account),
            pe(&entry.container),
            pe(&entry.obj)
        )
    }

    fn delete_from_policy(&self, entry: &QueueEntry, policy: i64, ts: Timestamp) -> bool {
        let Some(timestamp) = timestamp_with_offset(&ts.internal(), 1) else {
            return false;
        };
        let headers = vec![
            ("X-Timestamp".to_string(), timestamp),
            (
                "X-Backend-Storage-Policy-Index".to_string(),
                policy.to_string(),
            ),
            (
                "X-Backend-Allow-Reserved-Names".to_string(),
                "true".to_string(),
            ),
            (
                "X-Backend-Use-Replication-Network".to_string(),
                "true".to_string(),
            ),
        ];
        raw_request(
            self.proxy_host,
            "DELETE",
            &Self::object_path(entry),
            &headers,
            &[],
        )
        .is_some_and(|(status, _)| (200..300).contains(&status) || status == 404)
    }

    fn ensure_destination_tombstone(
        &self,
        entry: &QueueEntry,
        policy: i64,
        q_ts: Timestamp,
    ) -> bool {
        let Some(timestamp) = timestamp_with_offset(&q_ts.internal(), 3) else {
            return false;
        };
        let headers = vec![
            ("X-Timestamp".to_string(), timestamp),
            (
                "X-Backend-Storage-Policy-Index".to_string(),
                policy.to_string(),
            ),
            (
                "X-Backend-Allow-Reserved-Names".to_string(),
                "true".to_string(),
            ),
            (
                "X-Backend-Use-Replication-Network".to_string(),
                "true".to_string(),
            ),
        ];
        raw_request(
            self.proxy_host,
            "DELETE",
            &Self::object_path(entry),
            &headers,
            &[],
        )
        .is_some_and(|(status, _)| (200..300).contains(&status) || status == 404)
    }
}

impl ReconcileClient for HttpReconcileClient<'_> {
    fn move_object(&self, record: &QueueRecord, from_policy: i64, to_policy: i64) -> bool {
        let entry = &record.entry;
        let from_pi = from_policy.to_string();
        let to_pi = to_policy.to_string();
        let path = Self::object_path(entry);
        let raw_path = format!("{path}?symlink=get");

        // If the destination already has a version at least as new as the
        // queue entry, only the misplaced source needs a tombstone.
        let destination_headers = [
            ("X-Backend-Storage-Policy-Index", to_pi.as_str()),
            ("X-Backend-Allow-Reserved-Names", "true"),
            ("X-Backend-Use-Replication-Network", "true"),
        ];
        let Some((destination_status, destination_response)) = raw_request(
            self.proxy_host,
            "HEAD",
            &raw_path,
            &destination_headers,
            &[],
        ) else {
            return false;
        };
        if (200..300).contains(&destination_status) {
            let destination_ts = header_value(&destination_response, "X-Backend-Timestamp")
                .or_else(|| header_value(&destination_response, "X-Timestamp"))
                .and_then(|value| value.parse::<Timestamp>().ok())
                .unwrap_or(Timestamp::zero());
            if destination_ts >= record.q_ts {
                return self.delete_from_policy(entry, from_policy, record.q_ts);
            }
        } else if destination_status / 100 != 4 {
            return false;
        }

        let Some((status, source_response)) = raw_request(
            self.proxy_host,
            "GET",
            &raw_path,
            &[
                ("X-Backend-Storage-Policy-Index", from_pi.as_str()),
                ("X-Backend-Allow-Reserved-Names", "true"),
                ("X-Backend-Use-Replication-Network", "true"),
            ],
            &[],
        ) else {
            return false;
        };
        if status == 404 && record.op == QueueOp::Delete {
            return self.ensure_destination_tombstone(entry, to_policy, record.q_ts)
                && self.delete_from_policy(entry, from_policy, record.q_ts);
        }
        // Python keeps an unavailable/missing PUT source queued until its
        // reclaim age; never pop it merely because one request saw a 404.
        if !(200..300).contains(&status) {
            return false;
        }
        let Some(body) = decoded_http_body(&source_response) else {
            return false;
        };
        let etag = header_value(&source_response, "ETag")
            .unwrap_or("")
            .trim_matches('"')
            .to_string();
        let Some(source_timestamp) = header_value(&source_response, "X-Backend-Timestamp")
            .or_else(|| header_value(&source_response, "X-Timestamp"))
        else {
            return false;
        };
        let Ok(source_timestamp) = source_timestamp.parse::<Timestamp>() else {
            return false;
        };
        if source_timestamp < record.q_ts {
            return false;
        }
        // `slightly_later_timestamp(ts, offset=3)`: retain the raw time and
        // add an internal offset so the destination supersedes the source.
        let copy_base = source_timestamp.max(record.q_ts);
        let Some(put_timestamp) = timestamp_with_offset(&copy_base.internal(), 3) else {
            return false;
        };
        let Some(mut put_headers) = copied_source_headers(&source_response) else {
            return false;
        };
        put_headers.push(("X-Timestamp".to_string(), put_timestamp));
        put_headers.push((
            "X-Backend-Storage-Policy-Index".to_string(),
            to_pi.clone(),
        ));
        put_headers.push((
            "X-Backend-Allow-Reserved-Names".to_string(),
            "true".to_string(),
        ));
        put_headers.push((
            "X-Backend-Use-Replication-Network".to_string(),
            "true".to_string(),
        ));
        put_headers.push(("ETag".to_string(), etag));

        let Some((put_status, _)) = raw_request(
            self.proxy_host,
            "PUT",
            &path,
            &put_headers,
            &body,
        ) else {
            return false;
        };
        if !(200..300).contains(&put_status) {
            return false;
        }

        self.delete_from_policy(entry, from_policy, record.q_ts)
    }

    fn pop_queue(&self, record: &QueueRecord) -> bool {
        let entry = &record.entry;
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
        let pop_base = record.q_record.max(record.q_ts);
        let Some(ts) = timestamp_with_offset(&pop_base.internal(), 2) else {
            return false;
        };
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

/// Match Python's `ContainerReconciler.should_process`: when multiple
/// reconciler daemons share a queue, exactly one process owns each object.
/// The canonical Swift path hash is interpreted as one big-endian integer
/// before taking the modulo.
pub fn should_process_entry(
    hash_config: &HashPathConfig,
    entry: &QueueEntry,
    processes: u64,
    process: u64,
) -> bool {
    if processes == 0 {
        return true;
    }
    let Ok(digest) =
        hash_config.hash_path_raw(&entry.account, Some(&entry.container), Some(&entry.obj))
    else {
        return false;
    };
    u128::from_be_bytes(digest) % u128::from(processes) == u128::from(process)
}

fn queue_containers_for_pass(now_secs: f64, mut listed: Vec<String>) -> Vec<String> {
    // Python `_iter_containers` always checks the current hour first. A queue
    // DB may have been created by the container-replicator after the last
    // container-updater pass, so it is not necessarily visible in the hidden
    // account listing yet.
    let current = ((now_secs as i64).div_euclid(MISPLACED_OBJECTS_CONTAINER_DIVISOR)
        * MISPLACED_OBJECTS_CONTAINER_DIVISOR)
        .to_string();
    let mut containers = vec![current.clone()];
    // Account listings are oldest-to-newest; Python walks each page in
    // reverse after the current-hour fast path.
    listed.reverse();
    containers.extend(listed.into_iter().filter(|name| name != &current));
    containers
}

/// One full pass over `.misplaced_objects`.
pub fn run_once(
    account_ring: &Ring,
    container_ring: &Ring,
    hash_config: &HashPathConfig,
    proxy_host: &str,
    processes: u64,
    process: u64,
) -> ReconcilerStats {
    let mut stats = ReconcilerStats::default();
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    let listed = match list_account_containers(account_ring, MISPLACED_OBJECTS_ACCOUNT) {
        Some(containers) => containers,
        None => {
            // The current-hour queue is still directly discoverable even if
            // the account listing is temporarily unavailable.
            stats.errors += 1;
            Vec::new()
        }
    };
    let containers = queue_containers_for_pass(now_secs, listed);
    for qcontainer in containers {
        let Some(objects) =
            list_queue_objects(container_ring, MISPLACED_OBJECTS_ACCOUNT, &qcontainer)
        else {
            stats.errors += 1;
            continue;
        };
        for raw in objects {
            let Some(record) = parse_queue_record(&raw) else {
                continue;
            };
            if !should_process_entry(hash_config, &record.entry, processes, process) {
                continue;
            }
            let Some(current_pi) =
                container_policy_index(
                    container_ring,
                    &record.entry.account,
                    &record.entry.container,
                )
            else {
                stats.errors += 1;
                continue;
            };
            let client = HttpReconcileClient {
                proxy_host,
                container_ring,
                queue_container: qcontainer.clone(),
            };
            match reconcile(&record, current_pi, &client) {
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

    #[test]
    fn internal_proxy_chunked_body_is_decoded_before_reupload() {
        let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n3;ext=x\r\n123\r\n0\r\n\r\n";
        assert_eq!(decoded_http_body(response).unwrap(), b"test123");
        assert!(decoded_http_body(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nbad"
        )
        .is_none());
    }

    #[test]
    fn reconciler_copy_keeps_object_contract_headers_only() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nContent-Type: text/plain\r\nX-Object-Meta-Test: custom-meta\r\nX-Static-Large-Object: True\r\nX-Symlink-Target: c/o\r\nX-Backend-Timestamp: 1751500001.00000\r\nX-Trans-Id: tx-test\r\n\r\ntest";
        let copied = copied_source_headers(response).unwrap();
        assert!(copied.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("x-object-meta-test") && value == "custom-meta"
        }));
        assert!(copied.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("x-static-large-object") && value == "True"
        }));
        assert!(copied.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("x-symlink-target") && value == "c/o"
        }));
        assert!(!copied.iter().any(|(name, _)| {
            name.eq_ignore_ascii_case("content-length")
                || name.eq_ignore_ascii_case("x-backend-timestamp")
                || name.eq_ignore_ascii_case("x-trans-id")
        }));
    }

    #[test]
    fn parse_queue_record_preserves_op_and_both_timestamps() {
        let raw = QueueListingEntry {
            name: "1:/AUTH_test/c/o".into(),
            content_type: "application/x-delete".into(),
            hash: "1751500001.00000".into(),
            last_modified: "2025-07-02T10:26:42.000000".into(),
        };
        let record = parse_queue_record(&raw).unwrap();
        assert_eq!(record.entry.policy_index, 1);
        assert_eq!(record.entry.obj, "o");
        assert_eq!(record.op, QueueOp::Delete);
        assert_eq!(record.q_ts.internal(), "1751500001.00000");
        assert_eq!(record.q_record.isoformat(), raw.last_modified);
    }

    #[test]
    fn policy_comparison_matches_deleted_and_recreated_rules() {
        let ts = |value: &str| value.parse::<Timestamp>().unwrap();
        let live = ContainerPolicyInfo {
            storage_policy_index: 0,
            put_timestamp: ts("1751500003.00000"),
            delete_timestamp: Timestamp::zero(),
            status_changed_at: ts("1751500003.00000"),
            object_count: 1,
        };
        let deleted = ContainerPolicyInfo {
            storage_policy_index: 1,
            put_timestamp: ts("1751500001.00000"),
            delete_timestamp: ts("1751500002.00000"),
            status_changed_at: ts("1751500002.00000"),
            object_count: 0,
        };
        assert!(cmp_policy_info(live, deleted) < 0);
        assert!(cmp_policy_info(deleted, live) > 0);

        let recreated = ContainerPolicyInfo {
            storage_policy_index: 2,
            put_timestamp: ts("1751500005.00000"),
            delete_timestamp: ts("1751500004.00000"),
            status_changed_at: ts("1751500005.00000"),
            object_count: 0,
        };
        assert!(cmp_policy_info(deleted, recreated) > 0);
    }

    #[test]
    fn reconciler_timestamp_adds_offset_three() {
        assert_eq!(
            timestamp_with_offset("1751500001.00000", 3).unwrap(),
            "1751500001.00000_0000000000000003"
        );
        assert_eq!(
            timestamp_with_offset("1751500001.00000_0000000000000002", 3).unwrap(),
            "1751500001.00000_0000000000000005"
        );
    }

    struct FakeReconcile {
        moves: Mutex<Vec<(i64, i64)>>,
        popped: Mutex<Vec<String>>,
        move_ok: bool,
    }
    impl ReconcileClient for FakeReconcile {
        fn move_object(&self, _record: &QueueRecord, from: i64, to: i64) -> bool {
            self.moves.lock().unwrap().push((from, to));
            self.move_ok
        }
        fn pop_queue(&self, record: &QueueRecord) -> bool {
            self.popped
                .lock()
                .unwrap()
                .push(record.entry.obj.clone());
            true
        }
    }

    fn queue_record(policy_index: i64) -> QueueRecord {
        QueueRecord {
            entry: QueueEntry {
                policy_index,
                account: "a".into(),
                container: "c".into(),
                obj: "o".into(),
            },
            op: QueueOp::Put,
            q_ts: "1751500001.00000".parse().unwrap(),
            q_record: "1751500001.00000".parse().unwrap(),
        }
    }

    #[test]
    fn test_reconcile_moves_then_pops() {
        let record = queue_record(1);
        let client = FakeReconcile {
            moves: Mutex::new(Vec::new()),
            popped: Mutex::new(Vec::new()),
            move_ok: true,
        };
        assert_eq!(reconcile(&record, 0, &client), ReconcileOutcome::Moved);
        assert_eq!(*client.moves.lock().unwrap(), vec![(1, 0)]);
        assert_eq!(client.popped.lock().unwrap().len(), 1);
    }

    #[test]
    fn test_reconcile_already_correct_just_pops() {
        let record = queue_record(0);
        let client = FakeReconcile {
            moves: Mutex::new(Vec::new()),
            popped: Mutex::new(Vec::new()),
            move_ok: true,
        };
        assert_eq!(
            reconcile(&record, 0, &client),
            ReconcileOutcome::AlreadyCorrect
        );
        assert!(client.moves.lock().unwrap().is_empty());
        assert_eq!(client.popped.lock().unwrap().len(), 1);
    }

    #[test]
    fn test_reconcile_failed_move_keeps_entry() {
        let record = queue_record(2);
        let client = FakeReconcile {
            moves: Mutex::new(Vec::new()),
            popped: Mutex::new(Vec::new()),
            move_ok: false,
        };
        assert_eq!(reconcile(&record, 0, &client), ReconcileOutcome::Failed);
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
    fn reconciler_process_partition_matches_python_hash_modulo() {
        let hash_config =
            HashPathConfig::new(b"testprefix".to_vec(), b"testsuffix".to_vec()).unwrap();
        let entry = QueueEntry {
            policy_index: 1,
            account: "AUTH_test".into(),
            container: "c".into(),
            obj: "o".into(),
        };
        // Python hash_path is 05c5055fb64b7219c5a436127559a5de;
        // int(hexdigest, 16) % 4 == 2.
        assert!(should_process_entry(&hash_config, &entry, 0, 0));
        for process in 0..4 {
            assert_eq!(
                should_process_entry(&hash_config, &entry, 4, process),
                process == 2
            );
        }
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
    fn current_queue_container_is_checked_before_account_listing() {
        let containers = queue_containers_for_pass(
            1_751_500_001.0,
            vec![
                "1751490000".to_string(),
                "1751497200".to_string(),
                "1751493600".to_string(),
            ],
        );
        assert_eq!(containers, vec!["1751497200", "1751493600", "1751490000"]);
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
