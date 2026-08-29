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

//! The object expirer daemon core, ported from `swift/obj/expirer.py`.
//!
//! Objects with an `X-Delete-At` are enqueued into the hidden
//! `.expiring_objects` account: a task object named
//! `"<delete_at>-<account>/<container>/<object>"` inside a task container
//! bucketed by `delete_at // divisor * divisor`. This daemon lists due task
//! containers, and for each task whose delete time has passed it DELETEs the
//! real object (guarded by `X-If-Delete-At`) and then pops the queue entry.
//!
//! This module ports the pure task-name / bucket arithmetic (byte-identical
//! to Python, golden-tested) plus the due-task iteration and the
//! delete-then-pop flow over a pluggable [`ExpiryClient`]. Real-object
//! DELETEs can use an internal proxy through [`ProxyExpiryClient`], matching
//! Python InternalClient policy/quorum/container-update semantics; queue pops
//! remain ring-direct. [`HttpExpiryClient`] preserves the legacy ring-direct
//! fallback. Deferred: process-sharding (`hash_mod`) and delay_reaping
//! per-account overrides.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{SystemTime, UNIX_EPOCH};

use swift_core::timestamp::Timestamp;
use swift_http::split_path;
use swift_ring::Ring;

/// Default `expiring_objects_container_divisor` (one bucket per day).
pub const EXPIRER_CONTAINER_DIVISOR: i64 = 86400;

/// Number of task-container names used within each divisor window. Modern
/// Swift spreads a day's tasks across the preceding 100 seconds by object
/// hash, avoiding a single hot queue container.
pub const EXPIRER_CONTAINER_PER_DIVISOR: i64 = 100;

/// The hidden account holding the expiry queue.
pub const EXPIRER_ACCOUNT_NAME: &str = ".expiring_objects";

/// Content-type marking an async (best-effort) delete task.
pub const ASYNC_DELETE_TYPE: &str = "application/async-deleted";

/// `normalize_delete_at_timestamp`: a delete-at time as Swift stores it, a
/// zero-padded 10-digit integer second count (or `%016.5f` high precision).
pub fn normalize_delete_at_timestamp(timestamp: i64) -> String {
    format!("{timestamp:010}")
}

/// High-precision form (`%016.5f`), used for sub-second task objects.
pub fn normalize_delete_at_timestamp_hp(timestamp: f64) -> String {
    format!("{timestamp:016.5}")
}

/// `build_task_obj`: the task object name for a queued expiry.
pub fn build_task_obj(delete_at: i64, account: &str, container: &str, obj: &str) -> String {
    format!(
        "{}-{}/{}/{}",
        normalize_delete_at_timestamp(delete_at),
        account,
        container,
        obj
    )
}

/// `parse_task_obj`: split `"<ts>-<account>/<container>/<object>"` back into
/// its parts. Returns `None` on a malformed name.
pub fn parse_task_obj(task_obj: &str) -> Option<(Timestamp, String, String, String)> {
    let (timestamp, target_path) = task_obj.split_once('-')?;
    let delete_at = timestamp.parse::<Timestamp>().ok()?;
    let parts = split_path(&format!("/{target_path}"), 3, 3, true).ok()?;
    let account = parts[0].clone()?;
    let container = parts[1].clone()?;
    let object = parts[2].clone()?;
    Some((delete_at, account, container, object))
}

/// `get_expirer_container`: the task container bucket a delete-at falls in.
pub fn get_expirer_container(x_delete_at: i64, divisor: i64) -> String {
    // Python: int(x_delete_at) // divisor * divisor, floor division
    let bucket = x_delete_at.div_euclid(divisor) * divisor;
    normalize_delete_at_timestamp(bucket)
}

/// `ExpirerConfig.get_expirer_container`: select the hash-sharded task
/// container for one object. `object_hash` is Swift's 32-hex-character
/// `hash_path(account, container, object)` result.
pub fn get_expirer_container_for_object_hash(
    x_delete_at: i64,
    object_hash: &str,
    divisor: i64,
    per_divisor: i64,
) -> String {
    let bucket = x_delete_at.div_euclid(divisor) * divisor;
    let offset = if per_divisor > 0 {
        u128::from_str_radix(object_hash, 16)
            .unwrap_or(0)
            .rem_euclid(per_divisor as u128) as i64
    } else {
        0
    };
    normalize_delete_at_timestamp(bucket.saturating_sub(offset))
}

/// `is_expected_task_container`: whether a bucket int is a legal task
/// container for this divisor (guards against stray containers).
pub fn is_expected_task_container(task_container_int: i64, divisor: i64, per_divisor: i64) -> bool {
    let r = (task_container_int - 1).rem_euclid(divisor);
    divisor - r <= per_divisor
}

/// A due expiry task.
#[derive(Debug, Clone, PartialEq)]
pub struct TaskInfo {
    pub task_account: String,
    pub task_container: String,
    pub task_object: String,
    pub target_account: String,
    pub target_container: String,
    pub target_object: String,
    /// Exact Swift task timestamp. Async SLO deletion uses a five-decimal
    /// timestamp that must survive parsing; truncating it can make the
    /// backend DELETE older than the segment PUT and turn a 409 into a
    /// falsely successful dequeue.
    pub delete_timestamp: Timestamp,
    pub is_async_delete: bool,
}

impl TaskInfo {
    /// `/<account>/<container>/<object>` of the real object to delete.
    pub fn target_path(&self) -> String {
        format!(
            "{}/{}/{}",
            self.target_account, self.target_container, self.target_object
        )
    }
}

/// X-Timestamp for the real-object DELETE. Prefer the task-name prefix so
/// high-precision SLO async jobs (`1751500000.12345-acct/c/o`) are not
/// truncated below the segment PUT timestamp (409 / ignored delete).
fn task_x_timestamp(task: &TaskInfo) -> String {
    task.task_object
        .split_once('-')
        .and_then(|(ts, _)| ts.parse::<Timestamp>().ok())
        .map(|ts| ts.normal())
        .unwrap_or_else(|| task.delete_timestamp.normal())
}

/// Iterate the task-container listing, yielding tasks whose delete time has
/// passed. Mirrors `_iter_task_container`: the listing is name-sorted (so
/// timestamp-ascending); the first not-yet-due task stops iteration.
///
/// `objects` is the container listing as `(name, content_type)` pairs.
pub fn iter_due_tasks(
    task_account: &str,
    task_container: &str,
    objects: &[(String, String)],
    now: Timestamp,
) -> Vec<TaskInfo> {
    let mut out = Vec::new();
    for (name, content_type) in objects {
        let Some((delete_timestamp, ta, tc, to)) = parse_task_obj(name) else {
            continue;
        };
        if delete_timestamp > now {
            // nothing later can be due yet
            break;
        }
        out.push(TaskInfo {
            task_account: task_account.to_string(),
            task_container: task_container.to_string(),
            task_object: name.clone(),
            target_account: ta,
            target_container: tc,
            target_object: to,
            delete_timestamp,
            is_async_delete: content_type == ASYNC_DELETE_TYPE,
        });
    }
    out
}

/// The result of attempting to delete the real object.
#[derive(Debug, Clone, PartialEq)]
pub enum DeleteResult {
    /// 2xx (or an accepted 409/404 for async) — the object is gone.
    Deleted,
    /// 404/412 for a non-async delete: the X-Delete-At no longer matches or
    /// the object vanished; only safe to pop once it is older than reclaim.
    Stale,
    /// Any other failure; retry on a later pass.
    Error,
}

/// Abstraction over the expirer's two backend actions.
pub trait ExpiryClient {
    /// DELETE the real object with `X-If-Delete-At: <ts>`.
    fn delete_actual_object(&self, task: &TaskInfo) -> DeleteResult;
    /// Remove the queue entry (DELETE the task object from its container).
    fn pop_queue(&self, task: &TaskInfo) -> bool;
}

/// Sweep stats.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ExpirerStats {
    pub objects: u64,
    pub errors: u64,
    pub skipped_retained: u64,
}

/// Process one due task: delete the object, then pop the queue on success
/// (or on a stale delete older than `reclaim_age`). `now` and `reclaim_age`
/// are seconds. Returns whether the queue entry was popped.
pub fn process_task(
    task: &TaskInfo,
    now: Timestamp,
    reclaim_age: i64,
    client: &dyn ExpiryClient,
    stats: &mut ExpirerStats,
) -> bool {
    match client.delete_actual_object(task) {
        DeleteResult::Deleted => {
            let popped = client.pop_queue(task);
            stats.objects += 1;
            popped
        }
        DeleteResult::Stale => {
            // Retry later unless the task is older than the reclaim age, in
            // which case the real object is presumed gone for good.
            let reclaim_cutoff = now
                .raw()
                .saturating_sub(reclaim_age.saturating_mul(100_000));
            if task.delete_timestamp.raw() <= reclaim_cutoff {
                let popped = client.pop_queue(task);
                stats.objects += 1;
                popped
            } else {
                stats.skipped_retained += 1;
                false
            }
        }
        DeleteResult::Error => {
            stats.errors += 1;
            false
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

fn delete_actual_object_via_proxy(proxy_host: &str, task: &TaskInfo) -> DeleteResult {
    let ts = task_x_timestamp(task);
    let path = format!(
        "/v1/{}/{}/{}",
        pe(&task.target_account),
        pe(&task.target_container),
        pe(&task.target_object)
    );
    let headers: Vec<(&str, &str)> = if task.is_async_delete {
        vec![
            ("X-Timestamp", ts.as_str()),
            ("X-Backend-Allow-Reserved-Names", "true"),
        ]
    } else {
        vec![
            ("X-Timestamp", ts.as_str()),
            ("X-If-Delete-At", ts.as_str()),
            ("X-Backend-Clean-Expiring-Object-Queue", "no"),
            ("X-Backend-Allow-Reserved-Names", "true"),
        ]
    };
    let Some((status, _)) = raw_request(proxy_host, "DELETE", &path, &headers) else {
        if std::env::var_os("PEREGRINE_EXPIRER_TRACE").is_some() {
            eprintln!(
                "EXPIRER_PROXY_DELETE target={} async={} result=transport-error",
                task.target_path(),
                task.is_async_delete
            );
        }
        return DeleteResult::Error;
    };
    if std::env::var_os("PEREGRINE_EXPIRER_TRACE").is_some() {
        eprintln!(
            "EXPIRER_PROXY_DELETE target={} async={} status={status}",
            task.target_path(),
            task.is_async_delete
        );
    }
    if task.is_async_delete {
        if (200..300).contains(&status) || status == 404 || status == 409 {
            DeleteResult::Deleted
        } else {
            DeleteResult::Error
        }
    } else if (200..300).contains(&status) || status == 409 {
        DeleteResult::Deleted
    } else if status == 404 || status == 412 {
        DeleteResult::Stale
    } else {
        DeleteResult::Error
    }
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
) -> Option<(u16, Vec<u8>)> {
    let mut request = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\n");
    for (k, v) in headers {
        request.push_str(&format!("{k}: {v}\r\n"));
    }
    request.push_str("Content-Length: 0\r\nConnection: close\r\n\r\n");
    let Ok(mut conn) = TcpStream::connect(host) else {
        return None;
    };
    conn.set_nodelay(true).ok();
    let _ = conn.set_read_timeout(Some(std::time::Duration::from_secs(15)));
    let _ = conn.set_write_timeout(Some(std::time::Duration::from_secs(15)));
    if conn.write_all(request.as_bytes()).is_err() {
        return None;
    }
    let mut buf = Vec::new();
    if conn.read_to_end(&mut buf).is_err() {
        return None;
    }
    Some((http_status(&buf), buf))
}

/// List containers under an account via the account ring (JSON).
pub fn list_account_containers(account_ring: &Ring, account: &str) -> Option<Vec<String>> {
    let (part, nodes) = account_ring.get_nodes(account, None, None).ok()?;
    let mut names = std::collections::BTreeSet::new();
    let mut saw_ok = false;
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
        ) else {
            continue;
        };
        if status == 404 {
            saw_ok = true;
            continue;
        }
        if !(200..300).contains(&status) {
            continue;
        }
        saw_ok = true;
        let body = http_body(&buf);
        let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) else {
            continue;
        };
        let Some(arr) = v.as_array() else {
            continue;
        };
        for item in arr {
            if let Some(name) = item.get("name").and_then(|n| n.as_str()) {
                names.insert(name.to_string());
            }
        }
    }
    if saw_ok {
        Some(names.into_iter().collect())
    } else {
        None
    }
}

/// List objects in a container via the container ring (name + content_type).
pub fn list_container_objects(
    container_ring: &Ring,
    account: &str,
    container: &str,
) -> Option<Vec<(String, String)>> {
    let (part, nodes) = container_ring
        .get_nodes(account, Some(container), None)
        .ok()?;
    let mut best: Vec<(String, String)> = Vec::new();
    let mut saw_ok = false;
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
        ) else {
            continue;
        };
        if status == 404 {
            saw_ok = true;
            continue;
        }
        if !(200..300).contains(&status) {
            continue;
        }
        saw_ok = true;
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
        if out.len() > best.len() {
            best = out;
        }
    }
    if saw_ok {
        Some(best)
    } else {
        None
    }
}

/// Ring-direct expiry client: DELETE the real object on the object ring,
/// then DELETE the queue entry on every container replica (Python
/// `direct_delete_container_entry`).
pub struct HttpExpiryClient<'a> {
    pub object_ring: &'a Ring,
    pub container_ring: &'a Ring,
}

/// Internal-proxy expiry client. Python's object expirer uses InternalClient
/// for the real-object DELETE so policy resolution, replica quorum, and
/// container updates all go through the proxy. Queue cleanup remains the
/// ring-direct `direct_delete_container_entry` operation.
pub struct ProxyExpiryClient<'a> {
    pub proxy_host: &'a str,
    pub container_ring: &'a Ring,
}

fn pop_queue_direct(container_ring: &Ring, task: &TaskInfo) -> bool {
    let Ok((part, nodes)) = container_ring.get_nodes(
        &task.task_account,
        Some(&task.task_container),
        Some(&task.task_object),
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
            pe(&task.task_account),
            pe(&task.task_container),
            pe(&task.task_object)
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
        ) else {
            continue;
        };
        if (200..300).contains(&status) || status == 404 {
            ok += 1;
        }
    }
    ok > 0
}

impl ExpiryClient for HttpExpiryClient<'_> {
    fn delete_actual_object(&self, task: &TaskInfo) -> DeleteResult {
        let Ok((part, nodes)) = self.object_ring.get_nodes(
            &task.target_account,
            Some(&task.target_container),
            Some(&task.target_object),
        ) else {
            return DeleteResult::Error;
        };
        let ts = task_x_timestamp(task);
        let mut saw_success = false;
        let mut saw_stale = false;
        let mut saw_error = false;
        for node in &nodes {
            let host = node_host(node.dev, false);
            let path = format!(
                "/{}/{part}/{}/{}/{}",
                node.dev.device,
                pe(&task.target_account),
                pe(&task.target_container),
                pe(&task.target_object)
            );
            let headers: Vec<(&str, &str)> = if task.is_async_delete {
                vec![
                    ("X-Timestamp", ts.as_str()),
                    ("X-Backend-Storage-Policy-Index", "0"),
                ]
            } else {
                vec![
                    ("X-Timestamp", ts.as_str()),
                    ("X-If-Delete-At", ts.as_str()),
                    ("X-Backend-Clean-Expiring-Object-Queue", "no"),
                    ("X-Backend-Storage-Policy-Index", "0"),
                ]
            };
            let Some((status, _)) = raw_request(&host, "DELETE", &path, &headers) else {
                saw_error = true;
                continue;
            };
            if task.is_async_delete {
                if (200..300).contains(&status) || status == 404 || status == 409 {
                    saw_success = true;
                } else {
                    saw_error = true;
                }
            } else if (200..300).contains(&status) || status == 409 {
                // 2xx or 409 (newer object) — Python acceptable_statuses
                saw_success = true;
            } else if status == 404 || status == 412 {
                saw_stale = true;
            } else {
                saw_error = true;
            }
        }
        if saw_success {
            DeleteResult::Deleted
        } else if saw_stale && !saw_error {
            DeleteResult::Stale
        } else {
            DeleteResult::Error
        }
    }

    fn pop_queue(&self, task: &TaskInfo) -> bool {
        pop_queue_direct(self.container_ring, task)
    }
}

impl ExpiryClient for ProxyExpiryClient<'_> {
    fn delete_actual_object(&self, task: &TaskInfo) -> DeleteResult {
        delete_actual_object_via_proxy(self.proxy_host, task)
    }

    fn pop_queue(&self, task: &TaskInfo) -> bool {
        pop_queue_direct(self.container_ring, task)
    }
}

/// One full expiry pass: list due task containers under `.expiring_objects`,
/// process each due task. Returns aggregated stats.
pub fn run_once(
    account_ring: &Ring,
    container_ring: &Ring,
    object_ring: &Ring,
    now: Timestamp,
    reclaim_age: i64,
) -> ExpirerStats {
    let client = HttpExpiryClient {
        object_ring,
        container_ring,
    };
    run_once_with_client(account_ring, container_ring, now, reclaim_age, &client)
}

/// One full expiry pass using the internal proxy for real-object DELETEs.
/// This is the production-equivalent transport: the proxy resolves the
/// current storage policy, enforces replica quorum, and emits container
/// updates. The expirer still removes successful queue entries directly.
pub fn run_once_via_proxy(
    account_ring: &Ring,
    container_ring: &Ring,
    proxy_host: &str,
    now: Timestamp,
    reclaim_age: i64,
) -> ExpirerStats {
    let client = ProxyExpiryClient {
        proxy_host,
        container_ring,
    };
    run_once_with_client(account_ring, container_ring, now, reclaim_age, &client)
}

fn run_once_with_client(
    account_ring: &Ring,
    container_ring: &Ring,
    now: Timestamp,
    reclaim_age: i64,
    client: &dyn ExpiryClient,
) -> ExpirerStats {
    let mut stats = ExpirerStats::default();
    let Some(containers) = list_account_containers(account_ring, EXPIRER_ACCOUNT_NAME) else {
        stats.errors += 1;
        return stats;
    };
    for cname in containers {
        let Ok(c_int) = cname.parse::<i64>() else {
            continue;
        };
        if c_int.saturating_mul(100_000) > now.raw() {
            // Name-sorted listings can break; unsorted leftovers must not
            // hide a due hash-sharded task container.
            continue;
        }
        // Zero-padded form used by the enqueue path.
        let task_container = normalize_delete_at_timestamp(c_int);
        let Some(objects) =
            list_container_objects(container_ring, EXPIRER_ACCOUNT_NAME, &task_container)
        else {
            // try the unpadded name Python listing may return
            let Some(objects) =
                list_container_objects(container_ring, EXPIRER_ACCOUNT_NAME, &cname)
            else {
                stats.errors += 1;
                continue;
            };
            let due = iter_due_tasks(EXPIRER_ACCOUNT_NAME, &cname, &objects, now);
            for task in due {
                process_task(&task, now, reclaim_age, client, &mut stats);
            }
            continue;
        };
        let due = iter_due_tasks(EXPIRER_ACCOUNT_NAME, &task_container, &objects, now);
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open("/tmp/g6-expirer.log")
        {
            use std::io::Write;
            let _ = writeln!(
                f,
                "container={task_container} objs={} due={} sample={:?}",
                objects.len(),
                due.len(),
                objects.iter().take(3).collect::<Vec<_>>()
            );
        }
        for task in due {
            process_task(&task, now, reclaim_age, client, &mut stats);
        }
    }
    stats
}

/// Recon-cache update for the object expirer (`object_expiration_pass` /
/// `expired_last_pass`).
pub fn recon_update(elapsed: std::time::Duration, expired: u64) -> serde_json::Value {
    serde_json::json!({
        "object_expiration_pass": elapsed.as_secs_f64(),
        "expired_last_pass": expired,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::Mutex;

    fn proxy_task(is_async_delete: bool) -> TaskInfo {
        TaskInfo {
            task_account: ".expiring_objects".into(),
            task_container: "1751414400".into(),
            task_object: "1751500000-AUTH_test/c/o/deep".into(),
            target_account: "AUTH_test".into(),
            target_container: "c".into(),
            target_object: "o/deep".into(),
            delete_timestamp: Timestamp::from_secs(1_751_500_000.0).unwrap(),
            is_async_delete,
        }
    }

    fn serve_proxy_status(status: &str) -> (String, std::thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let host = listener.local_addr().unwrap().to_string();
        let response =
            format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .unwrap();
            let mut buf = [0_u8; 8192];
            let n = stream.read(&mut buf).unwrap();
            stream.write_all(response.as_bytes()).unwrap();
            String::from_utf8_lossy(&buf[..n]).into_owned()
        });
        (host, handle)
    }

    #[test]
    fn test_proxy_delete_routes_through_proxy_with_internal_headers() {
        let (host, request) = serve_proxy_status("204 No Content");
        let result = delete_actual_object_via_proxy(&host, &proxy_task(false));
        assert_eq!(result, DeleteResult::Deleted);
        let request = request.join().unwrap();
        assert!(
            request.starts_with("DELETE /v1/AUTH_test/c/o%2Fdeep HTTP/1.1\r\n"),
            "{request}"
        );
        assert!(
            request.contains("X-Timestamp: 1751500000.00000\r\n"),
            "{request}"
        );
        assert!(
            request.contains("X-If-Delete-At: 1751500000.00000\r\n"),
            "{request}"
        );
        assert!(
            request.contains("X-Backend-Clean-Expiring-Object-Queue: no\r\n"),
            "{request}"
        );
        assert!(
            request.contains("X-Backend-Allow-Reserved-Names: true\r\n"),
            "{request}"
        );
        assert!(
            !request.contains("X-Backend-Storage-Policy-Index"),
            "the proxy, not the expirer, must resolve the current policy: {request}"
        );
    }

    #[test]
    fn test_proxy_delete_statuses_match_python_internal_client() {
        let (host, request) = serve_proxy_status("412 Precondition Failed");
        assert_eq!(
            delete_actual_object_via_proxy(&host, &proxy_task(false)),
            DeleteResult::Stale
        );
        request.join().unwrap();

        let (host, request) = serve_proxy_status("404 Not Found");
        assert_eq!(
            delete_actual_object_via_proxy(&host, &proxy_task(true)),
            DeleteResult::Deleted
        );
        let request = request.join().unwrap();
        assert!(!request.contains("X-If-Delete-At"), "{request}");
    }

    #[test]
    fn test_async_delete_preserves_high_precision_task_timestamp() {
        let task_object = "1788003752.62601-AUTH_test/segments/segment_1".to_string();
        let (delete_timestamp, target_account, target_container, target_object) =
            parse_task_obj(&task_object).unwrap();
        let task = TaskInfo {
            task_account: ".expiring_objects".into(),
            task_container: "1787961514".into(),
            task_object,
            target_account,
            target_container,
            target_object,
            delete_timestamp,
            is_async_delete: true,
        };
        let (host, request) = serve_proxy_status("204 No Content");
        assert_eq!(
            delete_actual_object_via_proxy(&host, &task),
            DeleteResult::Deleted
        );
        let request = request.join().unwrap();
        assert!(
            request.contains("X-Timestamp: 1788003752.62601\r\n"),
            "high-precision SLO timestamp was not preserved: {request}"
        );
    }

    #[test]
    fn test_build_and_parse_roundtrip() {
        let name = build_task_obj(1751500000, "AUTH_test", "c", "o/deep");
        assert_eq!(name, "1751500000-AUTH_test/c/o/deep");
        let (ts, a, c, o) = parse_task_obj(&name).unwrap();
        assert_eq!(ts, Timestamp::from_secs(1_751_500_000.0).unwrap());
        assert_eq!(a, "AUTH_test");
        assert_eq!(c, "c");
        assert_eq!(o, "o/deep", "object keeps its slashes");
    }

    #[test]
    fn test_normalize_matches_python_format() {
        assert_eq!(normalize_delete_at_timestamp(0), "0000000000");
        assert_eq!(normalize_delete_at_timestamp(1751500000), "1751500000");
    }

    #[test]
    fn test_expirer_container_bucket() {
        // divisor 86400: everything in the same day maps to the day's floor
        let day = 1751500000 / 86400 * 86400;
        assert_eq!(
            get_expirer_container(1751500000, 86400),
            normalize_delete_at_timestamp(day)
        );
        assert_eq!(
            get_expirer_container(1751500000 + 5, 86400),
            get_expirer_container(1751500000, 86400)
        );
    }

    #[test]
    fn test_expirer_container_is_sharded_backwards_by_object_hash() {
        let delete_at = 1_751_500_000;
        let day = delete_at / EXPIRER_CONTAINER_DIVISOR * EXPIRER_CONTAINER_DIVISOR;
        assert_eq!(
            get_expirer_container_for_object_hash(
                delete_at,
                "00000000000000000000000000000063",
                EXPIRER_CONTAINER_DIVISOR,
                EXPIRER_CONTAINER_PER_DIVISOR,
            ),
            normalize_delete_at_timestamp(day - 99)
        );
    }

    #[test]
    fn test_iter_due_stops_at_future() {
        let now_secs = 1_751_500_000;
        let now = Timestamp::from_secs(now_secs as f64).unwrap();
        let objs = vec![
            (
                build_task_obj(now_secs - 100, "a", "c", "past1"),
                String::new(),
            ),
            (build_task_obj(now_secs, "a", "c", "now"), String::new()),
            (
                build_task_obj(now_secs + 100, "a", "c", "future"),
                String::new(),
            ),
            (
                build_task_obj(now_secs + 200, "a", "c", "later"),
                String::new(),
            ),
        ];
        let due = iter_due_tasks(".expiring_objects", "0000000000", &objs, now);
        // the two <= now are due; iteration stops at the first future task
        assert_eq!(due.len(), 2);
        assert_eq!(due[0].target_object, "past1");
        assert_eq!(due[1].target_object, "now");
    }

    #[test]
    fn test_iter_due_uses_subsecond_current_time() {
        let objects = vec![(
            "1788004660.25140-AUTH_test/segments/segment_1".to_string(),
            ASYNC_DELETE_TYPE.to_string(),
        )];
        let before = Timestamp::from_secs(1_788_004_660.20).unwrap();
        let after = Timestamp::from_secs(1_788_004_660.30).unwrap();
        assert!(iter_due_tasks(".expiring_objects", "1787961505", &objects, before).is_empty());
        let due = iter_due_tasks(".expiring_objects", "1787961505", &objects, after);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].delete_timestamp.normal(), "1788004660.25140");
    }

    struct FakeExpiry {
        delete_result: DeleteResult,
        popped: Mutex<Vec<String>>,
    }
    impl ExpiryClient for FakeExpiry {
        fn delete_actual_object(&self, _task: &TaskInfo) -> DeleteResult {
            self.delete_result.clone()
        }
        fn pop_queue(&self, task: &TaskInfo) -> bool {
            self.popped.lock().unwrap().push(task.task_object.clone());
            true
        }
    }

    #[test]
    fn test_process_deletes_then_pops() {
        let now_secs = 1_751_500_000;
        let now = Timestamp::from_secs(now_secs as f64).unwrap();
        let objs = vec![(
            build_task_obj(now_secs - 10, "AUTH_x", "c", "o"),
            String::new(),
        )];
        let due = iter_due_tasks(".expiring_objects", "0000000000", &objs, now);
        let client = FakeExpiry {
            delete_result: DeleteResult::Deleted,
            popped: Mutex::new(Vec::new()),
        };
        let mut stats = ExpirerStats::default();
        let popped = process_task(&due[0], now, 604800, &client, &mut stats);
        assert!(popped);
        assert_eq!(stats.objects, 1);
        assert_eq!(client.popped.lock().unwrap().len(), 1);
    }

    #[test]
    fn test_async_delete_uses_high_precision_task_timestamp() {
        let task = TaskInfo {
            task_account: ".expiring_objects".into(),
            task_container: "1751414400".into(),
            task_object: "1787896797.36012-AUTH_test/c/segment_2".into(),
            target_account: "AUTH_test".into(),
            target_container: "c".into(),
            target_object: "segment_2".into(),
            delete_timestamp: Timestamp::from_secs(1_787_896_797.0).unwrap(),
            is_async_delete: true,
        };
        assert_eq!(task_x_timestamp(&task), "1787896797.36012");
        let integer = TaskInfo {
            task_object: "1751500000-AUTH_test/c/o".into(),
            delete_timestamp: Timestamp::from_secs(1_751_500_000.0).unwrap(),
            is_async_delete: false,
            ..task.clone()
        };
        assert_eq!(task_x_timestamp(&integer), "1751500000.00000");
    }

    #[test]
    fn test_stale_recent_retained_old_popped() {
        let now_secs = 1_751_500_000;
        let now = Timestamp::from_secs(now_secs as f64).unwrap();
        let reclaim = 604800;
        let client = FakeExpiry {
            delete_result: DeleteResult::Stale,
            popped: Mutex::new(Vec::new()),
        };
        // recent stale -> retained, not popped
        let recent = TaskInfo {
            task_account: ".expiring_objects".into(),
            task_container: "0".into(),
            task_object: "t1".into(),
            target_account: "a".into(),
            target_container: "c".into(),
            target_object: "o".into(),
            delete_timestamp: Timestamp::from_secs((now_secs - 10) as f64).unwrap(),
            is_async_delete: false,
        };
        let mut stats = ExpirerStats::default();
        assert!(!process_task(&recent, now, reclaim, &client, &mut stats));
        assert_eq!(stats.skipped_retained, 1);

        // old stale -> popped
        let old = TaskInfo {
            delete_timestamp: Timestamp::from_secs((now_secs - reclaim - 1) as f64).unwrap(),
            task_object: "t2".into(),
            ..recent.clone()
        };
        assert!(process_task(&old, now, reclaim, &client, &mut stats));
        assert_eq!(*client.popped.lock().unwrap(), vec!["t2".to_string()]);
    }
}
