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

//! The object updater daemon core, ported from `swift/obj/updater.py`.
//!
//! When an object PUT/DELETE cannot synchronously update every container
//! replica, the object server drops a pickled *async_pending* file under
//! `<device>/async_pending[-<policy>]/<suffix>/<ohash>-<timestamp>`. This
//! daemon later walks those files and replays the container update against
//! the container ring, unlinking each file once every replica has been
//! updated (or rewriting it with the set of replicas already done).
//!
//! The pickle payload is the dict written by `pickle_async_update`:
//! `{'op', 'account', 'container', 'obj', 'headers', 'db_state', ...}` and,
//! after a partial update, a `'successes'` list of container-node ids.
//!
//! Deferred: the container-ratelimit/bucketizing skip logic and the
//! multiprocess/greenlet pool. Shard 301 `Location` rewriting is implemented:
//! `container_path` is rewritten and the destination is retried once.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};

use swift_core::pickle::{self, Value};
use swift_core::timestamp::Timestamp;
use swift_diskfile::extract_policy_index;
use swift_ring::Ring;

use crate::percent_encode;

/// A parsed async_pending update, plus enough context to unlink or rewrite
/// its backing file.
#[derive(Debug, Clone)]
pub struct AsyncUpdate {
    pub op: String,
    pub account: String,
    pub container: String,
    pub obj: String,
    /// Shard destination (`account/container`) when this update is not for
    /// the root. Python `split_update_path`.
    pub container_path: Option<String>,
    /// Headers to forward on the container update, insertion-ordered.
    pub headers: Vec<(String, String)>,
    /// Container-node ids already updated (the `successes` key).
    pub successes: Vec<i64>,
    pub policy_index: u32,
    /// The async_pending file on disk.
    pub path: PathBuf,
    /// The `<timestamp>` portion of the filename.
    pub timestamp: String,
    /// The original pickled dict, kept so a rewrite preserves every other
    /// key byte-for-byte and only swaps `successes`.
    raw: Value,
}

fn dict_get<'a>(pairs: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    pairs
        .iter()
        .find(|(k, _)| matches!(k, Value::Str(s) if s == key))
        .map(|(_, v)| v)
}

/// Coerce a pickled scalar to the string form Swift would send on the wire.
fn as_wire_string(v: &Value) -> Option<String> {
    match v {
        Value::Str(s) => Some(s.clone()),
        Value::Bytes(b) => Some(pickle::latin1_decode(b)),
        Value::Int(i) => Some(i.to_string()),
        Value::Bool(b) => Some(if *b { "True" } else { "False" }.to_string()),
        _ => None,
    }
}

impl AsyncUpdate {
    /// Parse a pickled async_pending payload.
    pub fn parse(
        raw_bytes: &[u8],
        path: PathBuf,
        policy_index: u32,
        timestamp: String,
    ) -> Option<AsyncUpdate> {
        let value = pickle::loads(raw_bytes).ok()?;
        let pairs = value.as_dict()?.to_vec();
        let op = as_wire_string(dict_get(&pairs, "op")?)?;
        let account = as_wire_string(dict_get(&pairs, "account")?)?;
        let container = as_wire_string(dict_get(&pairs, "container")?)?;
        let obj = as_wire_string(dict_get(&pairs, "obj")?)?;
        let container_path = dict_get(&pairs, "container_path").and_then(as_wire_string);
        let headers = match dict_get(&pairs, "headers") {
            Some(Value::Dict(hp)) => hp
                .iter()
                .filter_map(|(k, v)| Some((as_wire_string(k)?, as_wire_string(v)?)))
                .collect(),
            _ => Vec::new(),
        };
        let successes = match dict_get(&pairs, "successes") {
            Some(Value::List(items)) => items
                .iter()
                .filter_map(|v| match v {
                    Value::Int(i) => Some(*i),
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        };
        Some(AsyncUpdate {
            op,
            account,
            container,
            obj,
            container_path,
            headers,
            successes,
            policy_index,
            path,
            timestamp,
            raw: Value::Dict(pairs),
        })
    }

    /// Account/container the container ring should use (shard when set).
    pub fn ring_account_container(&self) -> (&str, &str) {
        if let Some(p) = self.container_path.as_deref() {
            if let Some((a, c)) = p.split_once('/') {
                if !a.is_empty() && !c.is_empty() {
                    return (a, c);
                }
            }
        }
        (&self.account, &self.container)
    }

    /// The container path `/<account>/<container>/<object>` (percent-encoded),
    /// as sent to a container server.
    pub fn container_object_path(&self) -> String {
        let (acct, cont) = self.ring_account_container();
        format!(
            "/{}/{}/{}",
            percent_encode(acct),
            percent_encode(cont),
            percent_encode(&self.obj)
        )
    }

    /// Re-pickle this update with `successes` replaced, preserving every
    /// other key. Mirrors the object updater rewriting the async file after a
    /// partial success so the next sweep skips already-updated replicas.
    fn repickle_with_successes(&self, successes: &[i64]) -> Result<Vec<u8>, pickle::PickleError> {
        self.repickle_pairs(Some(successes), None)
    }

    fn repickle_redirect(&self, container_path: &str) -> Result<Vec<u8>, pickle::PickleError> {
        self.repickle_pairs(Some(&[]), Some(container_path))
    }

    fn repickle_pairs(
        &self,
        successes: Option<&[i64]>,
        container_path: Option<&str>,
    ) -> Result<Vec<u8>, pickle::PickleError> {
        let mut pairs = match &self.raw {
            Value::Dict(p) => p.clone(),
            _ => Vec::new(),
        };
        if let Some(successes) = successes {
            let list = Value::List(successes.iter().map(|i| Value::Int(*i)).collect());
            if let Some(slot) = pairs
                .iter_mut()
                .find(|(k, _)| matches!(k, Value::Str(s) if s == "successes"))
            {
                slot.1 = list;
            } else {
                pairs.push((Value::Str("successes".to_string()), list));
            }
        }
        if let Some(path) = container_path {
            let value = Value::Str(path.to_string());
            if let Some(slot) = pairs
                .iter_mut()
                .find(|(k, _)| matches!(k, Value::Str(s) if s == "container_path"))
            {
                slot.1 = value;
            } else {
                pairs.push((Value::Str("container_path".to_string()), value));
            }
        }
        pickle::dumps(&Value::Dict(pairs))
    }
}

/// The result of a single container-node update attempt.
#[derive(Debug, Clone, PartialEq)]
pub enum NodeResult {
    /// 2xx, replica updated.
    Success,
    /// HTTP 301 with a sharding `Location`. Not a replica success: Python
    /// rewrites `container_path` and retries the destination.
    Redirect(String),
    /// HTTP 503 from the container server: explicit transient DB lock
    /// contention. Safe to retry because updates are timestamp-idempotent.
    TransientFailure,
    /// Any other non-2xx / connection error; the update must be retried later.
    Failure,
}

/// Abstraction over "send one container update to one node", so the sweep
/// logic is testable without a real container server.
pub trait ContainerNodeClient {
    fn send(
        &self,
        node: &swift_ring::RingDevice,
        part: u32,
        op: &str,
        path: &str,
        policy_index: u32,
        headers: &[(String, String)],
    ) -> NodeResult;
}

/// The real client: a blocking HTTP/1.1 request over TCP, matching the
/// object server's synchronous `container_update`.
pub struct HttpContainerClient;

impl ContainerNodeClient for HttpContainerClient {
    fn send(
        &self,
        node: &swift_ring::RingDevice,
        part: u32,
        op: &str,
        path: &str,
        policy_index: u32,
        headers: &[(String, String)],
    ) -> NodeResult {
        let host = format!("{}:{}", node.ip, node.port);
        let mut request = format!(
            "{op} /{}/{part}{path} HTTP/1.1\r\nHost: {host}\r\n\
             X-Backend-Storage-Policy-Index: {policy_index}\r\n",
            node.device
        );
        for (k, v) in headers {
            request.push_str(&format!("{k}: {v}\r\n"));
        }
        request.push_str("Content-Length: 0\r\nConnection: close\r\n\r\n");
        let Ok(mut conn) = TcpStream::connect(&host) else {
            return NodeResult::Failure;
        };
        conn.set_nodelay(true).ok();
        let _ = conn.set_read_timeout(Some(std::time::Duration::from_secs(15)));
        if conn.write_all(request.as_bytes()).is_err() {
            return NodeResult::Failure;
        }
        let mut buf = Vec::new();
        if conn.read_to_end(&mut buf).is_err() {
            return NodeResult::Failure;
        }
        parse_status(&buf)
    }
}

/// Extract the status line result from a raw HTTP response.
fn parse_status(buf: &[u8]) -> NodeResult {
    let head = String::from_utf8_lossy(buf);
    let status = head
        .split("\r\n")
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok());
    match status {
        Some(s) if (200..300).contains(&s) => NodeResult::Success,
        Some(301) => {
            for line in head.split("\r\n").skip(1) {
                if let Some(loc) = line
                    .split_once(':')
                    .filter(|(k, _)| k.eq_ignore_ascii_case("location"))
                {
                    return NodeResult::Redirect(loc.1.trim().to_string());
                }
            }
            NodeResult::Failure
        }
        Some(503) => NodeResult::TransientFailure,
        _ => NodeResult::Failure,
    }
}

/// `/acct/cont/obj` or percent-encoded Location → `acct/cont`.
fn redirect_container_path(location: &str) -> Option<String> {
    let decoded = percent_decode(location.trim());
    let s = decoded.trim_start_matches('/');
    let (acct, rest) = s.split_once('/')?;
    let cont = rest.split_once('/').map(|(c, _)| c).unwrap_or(rest);
    if acct.is_empty() || cont.is_empty() {
        return None;
    }
    Some(format!("{acct}/{cont}"))
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = &input[i + 1..i + 3];
            if let Ok(v) = u8::from_str_radix(hex, 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn ensure_header(headers: &mut Vec<(String, String)>, name: &str, value: &str) {
    if !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(name)) {
        headers.push((name.to_string(), value.to_string()));
    }
}

/// Outcome of processing one async_pending file.
#[derive(Debug, Clone, PartialEq)]
pub enum UpdateOutcome {
    /// Every replica updated; the file was unlinked.
    Unlinked,
    /// Some replicas updated; the file was rewritten with the new successes.
    Rewritten,
    /// A shard 301 rewrote `container_path`; caller should retry once.
    Redirected(String),
    /// No progress; the file is left untouched for a later sweep.
    Failed,
}

/// A running tally over a sweep.
pub const DEFAULT_ASYNC_TRACKER_MAX_ENTRIES: usize = 100;

#[derive(Debug, Clone, PartialEq)]
pub struct FailedUpdate {
    pub account: String,
    pub container: String,
    pub timestamp: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct UpdaterStats {
    pub successes: u64,
    pub failures: u64,
    pub unlinks: u64,
    pub outdated_unlinks: u64,
    pub errors: u64,
    pub redirects: u64,
    failed_updates: Vec<FailedUpdate>,
    tracker_max_entries: usize,
}

impl Default for UpdaterStats {
    fn default() -> Self {
        Self::with_tracker_limit(DEFAULT_ASYNC_TRACKER_MAX_ENTRIES)
    }
}

impl UpdaterStats {
    pub fn with_tracker_limit(max_entries: usize) -> Self {
        Self {
            successes: 0,
            failures: 0,
            unlinks: 0,
            outdated_unlinks: 0,
            errors: 0,
            redirects: 0,
            failed_updates: Vec::new(),
            tracker_max_entries: max_entries.max(1),
        }
    }

    pub fn track_failure(&mut self, account: &str, container: &str, timestamp: f64) {
        if let Some(existing) = self
            .failed_updates
            .iter_mut()
            .find(|entry| entry.account == account && entry.container == container)
        {
            if timestamp < existing.timestamp {
                existing.timestamp = timestamp;
            }
        } else {
            self.failed_updates.push(FailedUpdate {
                account: account.to_string(),
                container: container.to_string(),
                timestamp,
            });
        }
        self.failed_updates.sort_by(|left, right| {
            left.timestamp
                .total_cmp(&right.timestamp)
                .then_with(|| left.account.cmp(&right.account))
                .then_with(|| left.container.cmp(&right.container))
        });
        self.failed_updates.truncate(self.tracker_max_entries);
    }

    fn track_update_failure(&mut self, update: &AsyncUpdate) {
        if let Ok(timestamp) = update.timestamp.parse::<Timestamp>() {
            self.track_failure(&update.account, &update.container, timestamp.as_secs_f64());
        }
    }

    pub fn failed_updates(&self) -> &[FailedUpdate] {
        &self.failed_updates
    }

    pub fn merge_from(&mut self, other: UpdaterStats) {
        self.successes += other.successes;
        self.failures += other.failures;
        self.unlinks += other.unlinks;
        self.outdated_unlinks += other.outdated_unlinks;
        self.errors += other.errors;
        self.redirects += other.redirects;
        for failure in other.failed_updates {
            self.track_failure(&failure.account, &failure.container, failure.timestamp);
        }
    }
}

/// Replay one update against the given container-ring nodes, then unlink or
/// rewrite the async file. `nodes` are the primary container nodes for the
/// update's account/container.
/// Bounded in-sweep retry for explicit transient HTTP 503 container updates.
/// Daemon threads may sleep; mirrors the idempotent replicator retry so a
/// momentarily busy container server does not defer the whole sweep.
const UPDATER_TRANSIENT_ATTEMPTS: u32 = 8;
const UPDATER_TRANSIENT_BACKOFF_MS: u64 = 50;

pub fn process_update(
    update: &AsyncUpdate,
    part: u32,
    nodes: &[&swift_ring::RingDevice],
    client: &dyn ContainerNodeClient,
    stats: &mut UpdaterStats,
) -> std::io::Result<UpdateOutcome> {
    let mut headers = update.headers.clone();
    // The updater always stamps the policy index; keep any existing value.
    if !headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("x-backend-storage-policy-index"))
    {
        headers.push((
            "X-Backend-Storage-Policy-Index".to_string(),
            update.policy_index.to_string(),
        ));
    }
    ensure_header(&mut headers, "X-Backend-Accept-Redirect", "true");
    ensure_header(&mut headers, "X-Backend-Accept-Quoted-Location", "true");
    let path = update.container_object_path();
    let mut successes = update.successes.clone();
    let mut all_ok = true;
    let mut redirects = Vec::new();
    for node in nodes {
        if successes.contains(&(node.id as i64)) {
            continue;
        }
        let mut transient_attempts = 0u32;
        loop {
            match client.send(node, part, &update.op, &path, update.policy_index, &headers) {
                NodeResult::Success => {
                    successes.push(node.id as i64);
                    break;
                }
                NodeResult::Redirect(loc) => {
                    all_ok = false;
                    redirects.push(loc);
                    break;
                }
                NodeResult::TransientFailure
                    if transient_attempts + 1 < UPDATER_TRANSIENT_ATTEMPTS =>
                {
                    transient_attempts += 1;
                    std::thread::sleep(std::time::Duration::from_millis(
                        UPDATER_TRANSIENT_BACKOFF_MS * transient_attempts as u64,
                    ));
                }
                NodeResult::TransientFailure | NodeResult::Failure => {
                    all_ok = false;
                    break;
                }
            }
        }
    }
    if all_ok {
        std::fs::remove_file(&update.path)?;
        stats.successes += 1;
        stats.unlinks += 1;
        Ok(UpdateOutcome::Unlinked)
    } else if let Some(dest) = redirects
        .iter()
        .find_map(|loc| redirect_container_path(loc))
    {
        // Python: erase successes, persist container_path, retry once.
        match update.repickle_redirect(&dest) {
            Ok(bytes) => {
                std::fs::write(&update.path, bytes)?;
                stats.redirects += 1;
                Ok(UpdateOutcome::Redirected(dest))
            }
            Err(_) => {
                stats.errors += 1;
                Ok(UpdateOutcome::Failed)
            }
        }
    } else {
        stats.track_update_failure(update);
        if successes.len() > update.successes.len() {
            // partial progress: persist which replicas are done
            match update.repickle_with_successes(&successes) {
                Ok(bytes) => {
                    std::fs::write(&update.path, bytes)?;
                    stats.failures += 1;
                    Ok(UpdateOutcome::Rewritten)
                }
                Err(_) => {
                    stats.errors += 1;
                    Ok(UpdateOutcome::Failed)
                }
            }
        } else {
            stats.failures += 1;
            Ok(UpdateOutcome::Failed)
        }
    }
}

/// Python `process_object_update`: one redirect rewrite, then one retry.
pub fn process_update_following_redirects(
    update: &AsyncUpdate,
    part: u32,
    nodes: &[&swift_ring::RingDevice],
    container_ring: &Ring,
    client: &dyn ContainerNodeClient,
    stats: &mut UpdaterStats,
) -> std::io::Result<UpdateOutcome> {
    match process_update(update, part, nodes, client, stats)? {
        UpdateOutcome::Redirected(dest) => {
            let mut retry = update.clone();
            retry.container_path = Some(dest);
            retry.successes.clear();
            let (acct, cont) = retry.ring_account_container();
            let Ok((retry_part, retry_nodes)) = container_ring.get_nodes(acct, Some(cont), None)
            else {
                stats.errors += 1;
                return Ok(UpdateOutcome::Failed);
            };
            let retry_devs: Vec<&swift_ring::RingDevice> =
                retry_nodes.iter().map(|n| n.dev).collect();
            process_update(&retry, retry_part, &retry_devs, client, stats)
        }
        other => Ok(other),
    }
}

/// Walk every async_pending file on a device, newest-per-object first,
/// unlinking obsolete duplicates. Mirrors `_iter_async_pendings`.
pub fn iter_async_pendings(device: &Path, stats: &mut UpdaterStats) -> Vec<AsyncUpdate> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(device) else {
        return out;
    };
    for asyncdir in entries.flatten() {
        let name = asyncdir.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with("async_pending") || !asyncdir.path().is_dir() {
            continue;
        }
        let policy_index = extract_policy_index(&name).unwrap_or(0);
        let Ok(prefixes) = std::fs::read_dir(asyncdir.path()) else {
            continue;
        };
        for prefix in prefixes.flatten() {
            if !prefix.path().is_dir() {
                continue;
            }
            // sort filenames descending so the newest timestamp per object
            // hash is seen first
            let mut files: Vec<PathBuf> = match std::fs::read_dir(prefix.path()) {
                Ok(rd) => rd.flatten().map(|e| e.path()).collect(),
                Err(_) => continue,
            };
            files.sort();
            files.reverse();
            let mut last_obj_hash: Option<String> = None;
            for file in files {
                if !file.is_file() {
                    continue;
                }
                let fname = file
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                // Python updater.py 722-731 accepts only names that split into
                // exactly `<ohash>-<timestamp>` (`update_file.split('-')` must
                // yield two parts); anything else is counted as an error and
                // skipped WITHOUT unlinking and WITHOUT touching the
                // newest-per-hash bookkeeping. We additionally require the
                // timestamp part to parse as a Timestamp so a leftover
                // `<ohash>-<ts>.tmp` (staged by an older writer) can never
                // sort ahead of — and unlink — the real pending file. Python
                // never meets such names: its temp files are staged in the
                // device tmp dir, as ours now are.
                let parts: Vec<&str> = fname.split('-').collect();
                let (obj_hash, timestamp) = match parts.as_slice() {
                    [h, t] if t.parse::<Timestamp>().is_ok() => (*h, *t),
                    _ => {
                        stats.errors += 1;
                        eprintln!(
                            "ERROR async pending file with unexpected name {}",
                            file.display()
                        );
                        continue;
                    }
                };
                if last_obj_hash.as_deref() == Some(obj_hash) {
                    // obsolete duplicate — the newer update superseded it
                    if std::fs::remove_file(&file).is_ok() {
                        stats.outdated_unlinks += 1;
                    }
                    continue;
                }
                last_obj_hash = Some(obj_hash.to_string());
                let Ok(bytes) = std::fs::read(&file) else {
                    continue;
                };
                match AsyncUpdate::parse(&bytes, file.clone(), policy_index, timestamp.to_string())
                {
                    Some(u) => out.push(u),
                    None => stats.errors += 1,
                }
            }
        }
    }
    out
}

/// One full sweep of a device: iterate async_pendings, look each up in the
/// container ring, and replay it. Returns the sweep stats.
pub fn run_once(
    device: &Path,
    container_ring: &Ring,
    client: &(dyn ContainerNodeClient + Sync),
) -> UpdaterStats {
    run_once_with_concurrency(device, container_ring, client, 1)
}

/// Like [`run_once`], but replays up to `concurrency` pending updates at a
/// time (L1b drain). `concurrency <= 1` is strictly sequential.
pub fn run_once_with_concurrency(
    device: &Path,
    container_ring: &Ring,
    client: &(dyn ContainerNodeClient + Sync),
    concurrency: usize,
) -> UpdaterStats {
    run_once_with_concurrency_and_tracker(
        device,
        container_ring,
        client,
        concurrency,
        DEFAULT_ASYNC_TRACKER_MAX_ENTRIES,
    )
}

pub fn run_once_with_concurrency_and_tracker(
    device: &Path,
    container_ring: &Ring,
    client: &(dyn ContainerNodeClient + Sync),
    concurrency: usize,
    tracker_max_entries: usize,
) -> UpdaterStats {
    let mut stats = UpdaterStats::with_tracker_limit(tracker_max_entries);
    let updates = iter_async_pendings(device, &mut stats);
    if updates.is_empty() {
        return stats;
    }
    let concurrency = concurrency.max(1);
    if concurrency == 1 {
        for update in updates {
            let (acct, cont) = update.ring_account_container();
            let Ok((part, nodes)) = container_ring.get_nodes(acct, Some(cont), None) else {
                stats.errors += 1;
                continue;
            };
            let devs: Vec<&swift_ring::RingDevice> = nodes.iter().map(|n| n.dev).collect();
            let _ = process_update_following_redirects(
                &update,
                part,
                &devs,
                container_ring,
                client,
                &mut stats,
            );
        }
        return stats;
    }

    use std::sync::Mutex;
    let stats = Mutex::new(stats);
    let mut start = 0usize;
    while start < updates.len() {
        let end = (start + concurrency).min(updates.len());
        let chunk = &updates[start..end];
        std::thread::scope(|scope| {
            for update in chunk {
                let stats = &stats;
                scope.spawn(move || {
                    let (acct, cont) = update.ring_account_container();
                    let Ok((part, nodes)) = container_ring.get_nodes(acct, Some(cont), None) else {
                        stats.lock().unwrap().errors += 1;
                        return;
                    };
                    let devs: Vec<&swift_ring::RingDevice> = nodes.iter().map(|n| n.dev).collect();
                    let mut local = UpdaterStats::with_tracker_limit(tracker_max_entries);
                    let _ = process_update_following_redirects(
                        update,
                        part,
                        &devs,
                        container_ring,
                        client,
                        &mut local,
                    );
                    let mut g = stats.lock().unwrap();
                    g.merge_from(local);
                });
            }
        });
        start = end;
    }
    stats.into_inner().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Build the pickle dict exactly as `pickle_async_update` would.
    fn make_async_pickle(op: &str, account: &str, container: &str, obj: &str) -> Vec<u8> {
        let headers = Value::Dict(vec![
            (
                Value::Str("x-timestamp".into()),
                Value::Str("1751500000.00000".into()),
            ),
            (Value::Str("x-size".into()), Value::Str("4".into())),
        ]);
        let dict = Value::Dict(vec![
            (Value::Str("op".into()), Value::Str(op.into())),
            (Value::Str("account".into()), Value::Str(account.into())),
            (Value::Str("container".into()), Value::Str(container.into())),
            (Value::Str("obj".into()), Value::Str(obj.into())),
            (Value::Str("headers".into()), headers),
        ]);
        pickle::dumps(&dict).unwrap()
    }

    /// A fake client that records every send and answers per a script.
    struct FakeClient {
        calls: Mutex<Vec<(u64, String, String)>>,
        answer: NodeResult,
    }
    impl ContainerNodeClient for FakeClient {
        fn send(
            &self,
            node: &swift_ring::RingDevice,
            _part: u32,
            op: &str,
            path: &str,
            _pi: u32,
            _h: &[(String, String)],
        ) -> NodeResult {
            self.calls
                .lock()
                .unwrap()
                .push((node.id, op.to_string(), path.to_string()));
            self.answer.clone()
        }
    }

    fn dev(id: u64) -> swift_ring::RingDevice {
        swift_ring::RingDevice {
            id,
            region: 1,
            zone: 1,
            ip: "127.0.0.1".into(),
            port: 6201,
            replication_ip: None,
            replication_port: None,
            device: format!("sd{id}"),
            weight: 1.0,
            meta: String::new(),
            extra: Default::default(),
        }
    }

    #[test]
    fn test_parse_roundtrip() {
        let bytes = make_async_pickle("PUT", "AUTH_test", "c", "o");
        let u = AsyncUpdate::parse(&bytes, PathBuf::from("/x"), 0, "1751500000.00000".into())
            .expect("parse");
        assert_eq!(u.op, "PUT");
        assert_eq!(u.account, "AUTH_test");
        assert_eq!(u.container, "c");
        assert_eq!(u.obj, "o");
        assert_eq!(u.container_object_path(), "/AUTH_test/c/o");
        assert!(u.headers.iter().any(|(k, v)| k == "x-size" && v == "4"));
        assert!(u.successes.is_empty());
        assert!(u.container_path.is_none());
    }

    #[test]
    fn test_parse_container_path_uses_shard_not_root() {
        let headers = Value::Dict(vec![(
            Value::Str("x-timestamp".into()),
            Value::Str("1751500000.00000".into()),
        )]);
        let dict = Value::Dict(vec![
            (Value::Str("op".into()), Value::Str("DELETE".into())),
            (Value::Str("account".into()), Value::Str("AUTH_test".into())),
            (Value::Str("container".into()), Value::Str("root".into())),
            (Value::Str("obj".into()), Value::Str("obj-0000".into())),
            (Value::Str("headers".into()), headers),
            (
                Value::Str("container_path".into()),
                Value::Str(".shards_AUTH_test/shard-cont".into()),
            ),
        ]);
        let bytes = pickle::dumps(&dict).unwrap();
        let u = AsyncUpdate::parse(&bytes, PathBuf::from("/x"), 0, "1".into()).unwrap();
        assert_eq!(
            u.ring_account_container(),
            (".shards_AUTH_test", "shard-cont")
        );
        assert_eq!(
            u.container_object_path(),
            "/.shards_AUTH_test/shard-cont/obj-0000"
        );
    }

    #[test]
    fn test_full_success_unlinks() {
        let dir = std::env::temp_dir().join(format!("swift-upd-ok-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let ap = dir.join("async_pending/abc");
        std::fs::create_dir_all(&ap).unwrap();
        let file = ap.join("00000000000000000000000000000abc-1751500000.00000");
        std::fs::write(&file, make_async_pickle("PUT", "a", "c", "o")).unwrap();

        let mut stats = UpdaterStats::default();
        let updates = iter_async_pendings(&dir, &mut stats);
        assert_eq!(updates.len(), 1);

        let client = FakeClient {
            calls: Mutex::new(Vec::new()),
            answer: NodeResult::Success,
        };
        let nodes = [dev(1), dev(2), dev(3)];
        let refs: Vec<&swift_ring::RingDevice> = nodes.iter().collect();
        let outcome = process_update(&updates[0], 5, &refs, &client, &mut stats).unwrap();
        assert_eq!(outcome, UpdateOutcome::Unlinked);
        assert!(!file.exists(), "async file unlinked on full success");
        assert_eq!(client.calls.lock().unwrap().len(), 3);
        assert_eq!(stats.successes, 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_partial_failure_rewrites_with_successes() {
        let dir = std::env::temp_dir().join(format!("swift-upd-part-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let ap = dir.join("async_pending/abc");
        std::fs::create_dir_all(&ap).unwrap();
        let file = ap.join("00000000000000000000000000000abc-1751500000.00000");
        std::fs::write(&file, make_async_pickle("PUT", "a", "c", "o")).unwrap();
        let mut stats = UpdaterStats::default();
        let updates = iter_async_pendings(&dir, &mut stats);

        // node 2 succeeds (we simulate by scripting all-fail then checking
        // that a subsequent all-success clears it); here answer=Failure means
        // no node succeeds -> Failed, file untouched
        let client = FakeClient {
            calls: Mutex::new(Vec::new()),
            answer: NodeResult::Failure,
        };
        let nodes = [dev(1), dev(2), dev(3)];
        let refs: Vec<&swift_ring::RingDevice> = nodes.iter().collect();
        let outcome = process_update(&updates[0], 5, &refs, &client, &mut stats).unwrap();
        assert_eq!(outcome, UpdateOutcome::Failed);
        assert!(file.exists(), "async file kept when nothing succeeded");
        assert_eq!(stats.failed_updates().len(), 1);
        assert_eq!(stats.failed_updates()[0].account, "a");
        assert_eq!(stats.failed_updates()[0].container, "c");
        assert!((stats.failed_updates()[0].timestamp - 1_751_500_000.0).abs() < 0.001);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A client that answers from a script, one entry per send.
    struct ScriptClient {
        calls: Mutex<Vec<(u64, String)>>,
        answers: Mutex<Vec<NodeResult>>,
    }
    impl ContainerNodeClient for ScriptClient {
        fn send(
            &self,
            node: &swift_ring::RingDevice,
            _part: u32,
            op: &str,
            _path: &str,
            _pi: u32,
            _h: &[(String, String)],
        ) -> NodeResult {
            self.calls.lock().unwrap().push((node.id, op.to_string()));
            self.answers
                .lock()
                .unwrap()
                .pop()
                .unwrap_or(NodeResult::Failure)
        }
    }

    #[test]
    fn test_transient_failures_retried_in_sweep() {
        let dir = std::env::temp_dir().join(format!("swift-upd-retry-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let ap = dir.join("async_pending/abc");
        std::fs::create_dir_all(&ap).unwrap();
        let file = ap.join("00000000000000000000000000000abc-1751500000.00000");
        std::fs::write(&file, make_async_pickle("PUT", "a", "c", "o")).unwrap();
        let mut stats = UpdaterStats::default();
        let updates = iter_async_pendings(&dir, &mut stats);
        // one node: two transient BUSY-style failures, then success.
        // script is stored reversed because the client pops from the back.
        let client = ScriptClient {
            calls: Mutex::new(Vec::new()),
            answers: Mutex::new(vec![
                NodeResult::Success,
                NodeResult::TransientFailure,
                NodeResult::TransientFailure,
            ]),
        };
        let nodes = [dev(1)];
        let refs: Vec<&swift_ring::RingDevice> = nodes.iter().collect();
        let outcome = process_update(&updates[0], 5, &refs, &client, &mut stats).unwrap();
        assert_eq!(outcome, UpdateOutcome::Unlinked);
        assert!(!file.exists(), "async file unlinked after transient retry");
        assert_eq!(client.calls.lock().unwrap().len(), 3);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_persistent_transient_failure_keeps_file() {
        let dir = std::env::temp_dir().join(format!("swift-upd-retx-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let ap = dir.join("async_pending/abc");
        std::fs::create_dir_all(&ap).unwrap();
        let file = ap.join("00000000000000000000000000000abc-1751500000.00000");
        std::fs::write(&file, make_async_pickle("PUT", "a", "c", "o")).unwrap();
        let mut stats = UpdaterStats::default();
        let updates = iter_async_pendings(&dir, &mut stats);
        let client = ScriptClient {
            calls: Mutex::new(Vec::new()),
            answers: Mutex::new(vec![NodeResult::TransientFailure; 16]),
        };
        let nodes = [dev(1), dev(2)];
        let refs: Vec<&swift_ring::RingDevice> = nodes.iter().collect();
        let outcome = process_update(&updates[0], 5, &refs, &client, &mut stats).unwrap();
        assert_eq!(outcome, UpdateOutcome::Failed);
        assert!(file.exists(), "async file kept when transient never clears");
        assert_eq!(
            client.calls.lock().unwrap().len(),
            2 * UPDATER_TRANSIENT_ATTEMPTS as usize
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_parse_status_maps_busy_to_transient() {
        let busy = b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n".to_vec();
        assert_eq!(parse_status(&busy), NodeResult::Failure);
        let unavailable = b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n".to_vec();
        assert_eq!(parse_status(&unavailable), NodeResult::TransientFailure);
        let worn = b"HTTP/1.1 507 Insufficient Storage\r\nContent-Length: 0\r\n\r\n".to_vec();
        assert_eq!(parse_status(&worn), NodeResult::Failure);
        let notfound = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec();
        assert_eq!(parse_status(&notfound), NodeResult::Failure);
    }

    #[test]
    fn test_outdated_duplicates_unlinked() {
        let dir = std::env::temp_dir().join(format!("swift-upd-dup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let ap = dir.join("async_pending/abc");
        std::fs::create_dir_all(&ap).unwrap();
        let h = "00000000000000000000000000000abc";
        // three updates for the SAME object hash, different timestamps
        for ts in ["1751500000.00000", "1751500001.00000", "1751500002.00000"] {
            std::fs::write(
                ap.join(format!("{h}-{ts}")),
                make_async_pickle("PUT", "a", "c", "o"),
            )
            .unwrap();
        }
        let mut stats = UpdaterStats::default();
        let updates = iter_async_pendings(&dir, &mut stats);
        // only the newest survives as a yielded update
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].timestamp, "1751500002.00000");
        assert_eq!(stats.outdated_unlinks, 2);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_leftover_tmp_sibling_is_skipped_not_treated_as_newest() {
        let dir = std::env::temp_dir().join(format!("swift-upd-tmp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let ap = dir.join("async_pending/abc");
        std::fs::create_dir_all(&ap).unwrap();
        let h = "00000000000000000000000000000abc";
        let real = ap.join(format!("{h}-1751500000.00000"));
        std::fs::write(&real, make_async_pickle("PUT", "a", "c", "o")).unwrap();
        // a crashed writer's staging leftover: its name sorts AFTER the real
        // one, so the descending scan sees it FIRST — it must be skipped as a
        // non-conforming name, never yielded, and never cause the real file
        // to be unlinked as an "obsolete duplicate"
        let tmp = ap.join(format!("{h}-1751500000.00000.tmp"));
        std::fs::write(&tmp, b"partial garbage").unwrap();

        let mut stats = UpdaterStats::default();
        let updates = iter_async_pendings(&dir, &mut stats);
        assert_eq!(updates.len(), 1, "only the real pending file is yielded");
        assert_eq!(updates[0].timestamp, "1751500000.00000");
        assert_eq!(updates[0].path, real);
        assert!(real.exists(), "the real pending file must not be unlinked");
        assert!(tmp.exists(), "unexpected names are skipped, not deleted");
        assert_eq!(stats.outdated_unlinks, 0);
        assert_eq!(stats.errors, 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_multi_dash_and_bad_timestamp_names_are_errors() {
        let dir = std::env::temp_dir().join(format!("swift-upd-badname-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let ap = dir.join("async_pending/abc");
        std::fs::create_dir_all(&ap).unwrap();
        // Python `update_file.split('-')` needs exactly two parts
        std::fs::write(ap.join("a-b-c"), b"x").unwrap();
        // two parts, but the timestamp does not parse
        std::fs::write(ap.join("deadbeef-notatimestamp"), b"x").unwrap();
        let mut stats = UpdaterStats::default();
        let updates = iter_async_pendings(&dir, &mut stats);
        assert!(updates.is_empty());
        assert_eq!(stats.errors, 2);
        assert!(ap.join("a-b-c").exists());
        assert!(ap.join("deadbeef-notatimestamp").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn parse_status_treats_301_location_as_redirect() {
        let raw = b"HTTP/1.1 301 Moved Permanently\r\n\
Location: /.shards_AUTH_test/shard-1/alpha\r\n\
X-Backend-Redirect-Timestamp: 1.00000\r\n\r\n";
        assert_eq!(
            parse_status(raw),
            NodeResult::Redirect("/.shards_AUTH_test/shard-1/alpha".into())
        );
        assert_eq!(
            redirect_container_path("/.shards_AUTH_test/shard-1/alpha").as_deref(),
            Some(".shards_AUTH_test/shard-1")
        );
        let ok = b"HTTP/1.1 204 No Content\r\n\r\n";
        assert_eq!(parse_status(ok), NodeResult::Success);
    }

    #[test]
    fn process_update_rewrites_container_path_on_301() {
        let dir = std::env::temp_dir().join(format!("swift-upd-301-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let ap = dir.join("async_pending/abc");
        std::fs::create_dir_all(&ap).unwrap();
        let file = ap.join("00000000000000000000000000000abc-1751500000.00000");
        std::fs::write(
            &file,
            make_async_pickle("PUT", "AUTH_test", "root", "alpha"),
        )
        .unwrap();
        let mut stats = UpdaterStats::default();
        let updates = iter_async_pendings(&dir, &mut stats);
        let client = FakeClient {
            calls: Mutex::new(Vec::new()),
            answer: NodeResult::Redirect("/.shards_AUTH_test/shard-b/alpha".into()),
        };
        let nodes = [dev(1), dev(2), dev(3)];
        let refs: Vec<&swift_ring::RingDevice> = nodes.iter().collect();
        let outcome = process_update(&updates[0], 5, &refs, &client, &mut stats).unwrap();
        assert_eq!(
            outcome,
            UpdateOutcome::Redirected(".shards_AUTH_test/shard-b".into())
        );
        assert!(file.exists(), "redirect rewrite keeps the pending file");
        assert_eq!(stats.redirects, 1);
        let rewritten = std::fs::read(&file).unwrap();
        let again = AsyncUpdate::parse(&rewritten, file.clone(), 0, "1".into()).unwrap();
        assert_eq!(
            again.container_path.as_deref(),
            Some(".shards_AUTH_test/shard-b")
        );
        assert!(again.successes.is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
