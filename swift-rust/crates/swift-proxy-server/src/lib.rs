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

//! Proxy server foundations, ported from `swift/proxy/server.py` and
//! `swift/proxy/controllers/{base,account,container}.py`: error-limited
//! node iteration, concurrent backend fan-out with quorum best-response
//! selection, account/container controllers with account auto-creation
//! and the account-update header side channel.
//!
//! Per-policy object rings are supported (`object_ring_for`), routing object
//! requests by the container's storage policy index. Account/container info
//! is cached with `recheck_*_existence` TTLs: a process-local L1 map plus an
//! optional shared memcache L2 (`account/…`, `container/…` keys, matching
//! Python `get_cache_key`) so TempAuth ACL / Temp-URL key updates propagate
//! across VIP backends without waiting for per-proxy TTL expiry.
//! Deviations tracked for later: the resumable multi-node GET iterator
//! (mid-stream failover via ranged re-fetch). X-Newest best-source selection
//! is implemented in [`ProxyApp::get_or_head`].

use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use swift_core::config::config_true_value;
use swift_core::timestamp::Timestamp;
use swift_http::{HeaderKeyDict, Request, Response};
use swift_memcache::{MemcacheClient, TcpConn};
use swift_ring::Ring;

/// An owned backend node (device ip/port/name), so node lists can move
/// across the fan-out threads. The Rust `PartNode`/`HandoffNode` borrow
/// their device from the ring.
#[derive(Debug, Clone)]
struct Node {
    ip: String,
    port: u32,
    device: String,
    /// True when this node came from `get_more_nodes` — the counterpart of
    /// the `handoff_index` key Python merges into handoff node dicts. A
    /// 404 from such a node with no tombstone timestamp is not
    /// authoritative (base.py:1104-1112, 1617-1624).
    handoff: bool,
}

/// `swift.common.error_limiter.ErrorLimiter`.
pub struct ErrorLimiter {
    suppression_interval: f64,
    suppression_limit: u64,
    stats: Mutex<HashMap<String, (u64, Instant)>>,
}

impl ErrorLimiter {
    pub fn new(suppression_interval: f64, suppression_limit: u64) -> Self {
        ErrorLimiter {
            suppression_interval,
            suppression_limit,
            stats: Mutex::new(HashMap::new()),
        }
    }

    fn node_key(node: &Node) -> String {
        format!("{}:{}/{}", node.ip, node.port, node.device)
    }

    fn is_limited(&self, node: &Node) -> bool {
        let mut stats = self.stats.lock().unwrap();
        match stats.get(&Self::node_key(node)) {
            None => false,
            Some((errors, last_error)) => {
                if last_error.elapsed().as_secs_f64() > self.suppression_interval {
                    stats.remove(&Self::node_key(node));
                    return false;
                }
                *errors > self.suppression_limit
            }
        }
    }

    fn increment(&self, node: &Node) {
        let mut stats = self.stats.lock().unwrap();
        let entry = stats
            .entry(Self::node_key(node))
            .or_insert((0, Instant::now()));
        entry.0 += 1;
        entry.1 = Instant::now();
    }

    /// Immediately error-limit a node (e.g. on 507).
    fn limit(&self, node: &Node) {
        let mut stats = self.stats.lock().unwrap();
        stats.insert(
            Self::node_key(node),
            (self.suppression_limit + 1, Instant::now()),
        );
    }
}

#[derive(Clone)]
pub struct ProxyConfig {
    pub conn_timeout: Duration,
    pub node_timeout: Duration,
    /// `request_node_count`: how many nodes (primaries + handoffs) to
    /// consider per request, as a multiple of the replica count.
    pub request_node_count_factor: u64,
    pub account_autocreate: bool,
    /// When true, account PUT/DELETE are allowed (Python
    /// `allow_account_management`). Default false → 405 Method Not Allowed.
    pub allow_account_management: bool,
    pub error_suppression_interval: f64,
    pub error_suppression_limit: u64,
    pub default_policy_index: i64,
    /// `recheck_container_existence`: seconds cached container info stays
    /// fresh (server.py:235-237; DEFAULT_RECHECK_CONTAINER_EXISTENCE = 60,
    /// base.py:69). Authoritative absence (404) is cached at a tenth of this
    /// (base.py:687-688). Non-positive disables the cache.
    pub recheck_container_existence: f64,
    /// `recheck_account_existence` (server.py:244-246;
    /// DEFAULT_RECHECK_ACCOUNT_EXISTENCE = 60, base.py:68).
    pub recheck_account_existence: f64,
    /// When true, every account/container/object request is authorized against
    /// the container ACL using the (unspoofable) `X-Backend-Remote-User` group
    /// list an auth middleware (tempauth) stamped, or Keystone roles when
    /// `keystone_auth` is set and the request carries `X-Backend-Auth-Plugin:
    /// keystone`. Set by `main` iff tempauth and/or keystoneauth is in the
    /// pipeline — so a request path that forgets to authorize cannot silently
    /// become world-accessible.
    pub auth_enabled: bool,
    /// When `Some`, Keystone authorize is used for requests stamped by the
    /// keystoneauth middleware (`X-Backend-Auth-Plugin: keystone`).
    pub keystone_auth: Option<swift_middleware::KeystoneAuth>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        ProxyConfig {
            conn_timeout: Duration::from_millis(500),
            node_timeout: Duration::from_secs(10),
            request_node_count_factor: 2,
            account_autocreate: false,
            allow_account_management: false,
            error_suppression_interval: 60.0,
            error_suppression_limit: 10,
            default_policy_index: 0,
            recheck_container_existence: 60.0,
            recheck_account_existence: 60.0,
            auth_enabled: false,
            keystone_auth: None,
        }
    }
}

/// A container's cached info: its storage policy index, read/write ACLs,
/// Temp-URL keys, and the HEAD status that produced it (0 = no response —
/// treated like Python's synthesized 503: not a success).
#[derive(Clone, Default)]
struct ContainerInfo {
    status: u16,
    policy_index: i64,
    read_acl: Option<String>,
    write_acl: Option<String>,
    temp_url_keys: Vec<String>,
    /// Destination container's `X-Container-Sync-Key` (for inbound sync auth).
    sync_key: Option<String>,
}

impl ContainerInfo {
    fn exists(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// Cached account HEAD: status plus sysmeta ACL and Temp-URL keys.
#[derive(Clone, Default)]
struct AccountInfo {
    status: u16,
    /// Raw `X-Account-Sysmeta-Core-Access-Control` value when present.
    core_access_control: Option<String>,
    temp_url_keys: Vec<String>,
}

/// L1 (process-local) + optional L2 (shared memcache) cache of container /
/// account info, porting Python `get_container_info` / `get_account_info`
/// with `set_info_cache` / `clear_info_cache` (base.py:430-744).
///
/// L1 is keyed `"account/container"` and `"account"` (account names cannot
/// contain `/`). L2 uses Python `get_cache_key` strings (`container/a/c`,
/// `account/a`) so every VIP backend that shares `memcache_servers` sees
/// the same ACL / Temp-URL-key state after a clear+refill. Memcache misses
/// or errors fall through to a live HEAD; they never fail the request.
struct InfoCache {
    containers: Mutex<HashMap<String, (Instant, ContainerInfo)>>,
    accounts: Mutex<HashMap<String, (Instant, AccountInfo)>>,
    memcache: Option<Mutex<MemcacheClient<TcpConn>>>,
}

impl InfoCache {
    fn new() -> Self {
        InfoCache {
            containers: Mutex::new(HashMap::new()),
            accounts: Mutex::new(HashMap::new()),
            memcache: None,
        }
    }

    /// Attach a shared memcache client (P1c). Builder-style for `ProxyApp`.
    fn with_memcache(mut self, client: MemcacheClient<TcpConn>) -> Self {
        self.memcache = Some(Mutex::new(client));
        self
    }

    fn memcache_key_container(account_container: &str) -> String {
        format!("container/{account_container}")
    }

    fn memcache_key_account(account: &str) -> String {
        format!("account/{account}")
    }

    /// A fresh cached entry, or `None` (removing the entry if it expired).
    ///
    /// When shared memcache is configured it is consulted first so a clear on
    /// another VIP backend is visible immediately (L1 alone would lag).
    fn get_container(&self, key: &str) -> Option<ContainerInfo> {
        if self.memcache.is_some() {
            let mkey = Self::memcache_key_container(key);
            return self.memcache_get_container(&mkey);
        }
        let mut map = self.containers.lock().unwrap();
        match map.get(key) {
            None => None,
            Some((deadline, info)) => {
                if Instant::now() >= *deadline {
                    map.remove(key);
                    None
                } else {
                    Some(info.clone())
                }
            }
        }
    }

    /// Insert with a TTL in seconds. A non-positive or non-finite TTL caches
    /// nothing. Capped at 1e9 s like `conf_timeout_secs`.
    fn set_container(&self, key: String, info: ContainerInfo, ttl_secs: f64) {
        if !ttl_secs.is_finite() || ttl_secs <= 0.0 {
            return;
        }
        let deadline = Instant::now() + Duration::from_secs_f64(ttl_secs.min(1e9));
        self.containers
            .lock()
            .unwrap()
            .insert(key.clone(), (deadline, info.clone()));
        let mkey = Self::memcache_key_container(&key);
        self.memcache_set_container(&mkey, &info, ttl_secs);
    }

    /// `clear_info_cache` for one container (base.py:732-744).
    fn clear_container(&self, key: &str) {
        self.containers.lock().unwrap().remove(key);
        let mkey = Self::memcache_key_container(key);
        self.memcache_delete(&mkey);
    }

    /// A fresh cached account info, or `None`.
    ///
    /// Shared memcache is authoritative when configured (cross-proxy ACL).
    fn get_account(&self, account: &str) -> Option<AccountInfo> {
        if self.memcache.is_some() {
            let mkey = Self::memcache_key_account(account);
            return self.memcache_get_account(&mkey);
        }
        let mut map = self.accounts.lock().unwrap();
        match map.get(account) {
            None => None,
            Some((deadline, info)) => {
                if Instant::now() >= *deadline {
                    map.remove(account);
                    None
                } else {
                    Some(info.clone())
                }
            }
        }
    }

    fn set_account(&self, account: String, info: AccountInfo, ttl_secs: f64) {
        if !ttl_secs.is_finite() || ttl_secs <= 0.0 {
            return;
        }
        let deadline = Instant::now() + Duration::from_secs_f64(ttl_secs.min(1e9));
        self.accounts
            .lock()
            .unwrap()
            .insert(account.clone(), (deadline, info.clone()));
        let mkey = Self::memcache_key_account(&account);
        self.memcache_set_account(&mkey, &info, ttl_secs);
    }

    /// `clear_info_cache` for one account (base.py:732-744).
    fn clear_account(&self, account: &str) {
        self.accounts.lock().unwrap().remove(account);
        let mkey = Self::memcache_key_account(account);
        self.memcache_delete(&mkey);
    }

    fn memcache_delete(&self, key: &str) {
        let Some(mc) = &self.memcache else { return };
        let Ok(mut guard) = mc.lock() else { return };
        let _ = guard.delete(key);
    }

    fn memcache_get_container(&self, key: &str) -> Option<ContainerInfo> {
        let mc = self.memcache.as_ref()?;
        let mut guard = mc.lock().ok()?;
        let value = guard.get_json(key).ok().flatten()?;
        container_info_from_json(&value)
    }

    fn memcache_set_container(&self, key: &str, info: &ContainerInfo, ttl_secs: f64) {
        let Some(mc) = &self.memcache else { return };
        let Ok(mut guard) = mc.lock() else { return };
        let value = container_info_to_json(info);
        let _ = guard.set_json(key, &value, ttl_secs as i64);
    }

    fn memcache_get_account(&self, key: &str) -> Option<AccountInfo> {
        let mc = self.memcache.as_ref()?;
        let mut guard = mc.lock().ok()?;
        let value = guard.get_json(key).ok().flatten()?;
        account_info_from_json(&value)
    }

    fn memcache_set_account(&self, key: &str, info: &AccountInfo, ttl_secs: f64) {
        let Some(mc) = &self.memcache else { return };
        let Ok(mut guard) = mc.lock() else { return };
        let value = account_info_to_json(info);
        let _ = guard.set_json(key, &value, ttl_secs as i64);
    }
}

fn container_info_to_json(info: &ContainerInfo) -> serde_json::Value {
    serde_json::json!({
        "status": info.status,
        "policy_index": info.policy_index,
        "read_acl": info.read_acl,
        "write_acl": info.write_acl,
        "temp_url_keys": info.temp_url_keys,
        "sync_key": info.sync_key,
    })
}

fn container_info_from_json(v: &serde_json::Value) -> Option<ContainerInfo> {
    Some(ContainerInfo {
        status: v.get("status")?.as_u64()? as u16,
        policy_index: v.get("policy_index").and_then(|x| x.as_i64()).unwrap_or(0),
        read_acl: v
            .get("read_acl")
            .and_then(|x| x.as_str())
            .map(str::to_string),
        write_acl: v
            .get("write_acl")
            .and_then(|x| x.as_str())
            .map(str::to_string),
        temp_url_keys: v
            .get("temp_url_keys")
            .and_then(|x| x.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default(),
        sync_key: v
            .get("sync_key")
            .and_then(|x| x.as_str())
            .map(str::to_string),
    })
}

fn account_info_to_json(info: &AccountInfo) -> serde_json::Value {
    serde_json::json!({
        "status": info.status,
        "core_access_control": info.core_access_control,
        "temp_url_keys": info.temp_url_keys,
    })
}

fn account_info_from_json(v: &serde_json::Value) -> Option<AccountInfo> {
    Some(AccountInfo {
        status: v.get("status")?.as_u64()? as u16,
        core_access_control: v
            .get("core_access_control")
            .and_then(|x| x.as_str())
            .map(str::to_string),
        temp_url_keys: v
            .get("temp_url_keys")
            .and_then(|x| x.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default(),
    })
}

/// `set_info_cache`'s cache lifetime for a backend info response
/// (base.py:672-692): the backend's `X-Backend-Recheck-*-Existence` override
/// or the conf default; a tenth of that for authoritative absence (404/410);
/// `None` for any other non-success status, which must not touch the cache
/// ("bail without touching caches", base.py:689-692).
fn info_cache_time(status: u16, recheck_header: Option<&str>, default_ttl: f64) -> Option<f64> {
    let ttl = recheck_header
        .and_then(|v| v.trim().parse::<f64>().ok())
        .unwrap_or(default_ttl);
    if (200..300).contains(&status) {
        Some(ttl)
    } else if matches!(status, 404 | 410) {
        Some(ttl * 0.1)
    } else {
        None
    }
}

/// The erasure-coding scheme of a storage policy, enough to drive the proxy EC
/// data path (encode/decode fan-out) without pulling in the full policy object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EcPolicyParams {
    /// `ec_num_data_fragments`.
    pub ndata: usize,
    /// `ec_num_parity_fragments`.
    pub nparity: usize,
    /// `ec_object_segment_size` (default 1 MiB).
    pub segment_size: usize,
    /// Minimum parity fragments the scheme needs; the write quorum is
    /// `ndata + min_parity` (Python `ECStoragePolicy.quorum`).
    pub min_parity: usize,
}

impl EcPolicyParams {
    /// Total fragment archives per object (`k + m`).
    pub fn n_unique(&self) -> usize {
        self.ndata + self.nparity
    }
    /// The number of 2xx fragment writes a PUT needs to succeed.
    pub fn write_quorum(&self) -> usize {
        self.ndata + self.min_parity
    }
}

pub struct ProxyApp {
    pub account_ring: Ring,
    pub container_ring: Ring,
    /// Object ring for the default policy (policy 0), and the fallback when a
    /// container's policy has no dedicated ring.
    pub object_ring: Ring,
    /// Per-storage-policy object rings (`object-<N>.ring.gz`), keyed by policy
    /// index. Policy 0 falls through to `object_ring`.
    pub object_rings: std::collections::HashMap<i64, Ring>,
    /// Erasure-coding schemes keyed by storage-policy index. A policy present
    /// here routes object data through the EC controller (encode on PUT, decode
    /// on GET); absent means replication.
    pub ec_policies: std::collections::HashMap<i64, EcPolicyParams>,
    /// Storage-policy name (lowercased, incl. aliases) → index, for resolving a
    /// container PUT's `X-Storage-Policy` header to a backend policy index.
    pub policy_name_to_index: std::collections::HashMap<String, i64>,
    /// Storage-policy index → canonical name, for the client-facing
    /// `X-Storage-Policy` header on container GET/HEAD responses.
    pub policy_index_to_name: std::collections::HashMap<i64, String>,
    /// Pre-rendered `GET /info` capabilities JSON (empty = `/info` disabled).
    pub info_json: String,
    pub config: ProxyConfig,
    pub error_limiter: ErrorLimiter,
    /// Account/container info cache (L1 local + optional shared memcache L2).
    /// Rebuilt whenever the app is reconstructed (ring reload).
    info_cache: InfoCache,
}

/// A backend response.
struct BackendResponse {
    status: u16,
    reason: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn swob_response(status: u16) -> Response {
    let explanation = match status {
        404 => "The resource could not be found.",
        503 => "The server is currently unavailable. Please try again at a later time.",
        501 => "The requested method is not implemented by this server.",
        412 => "A precondition for this request was not met.",
        400 => "The server could not comply with the request since it is either malformed or otherwise incorrect.",
        422 => "Unable to process the contained instructions",
        _ => "",
    };
    let mut resp = if explanation.is_empty() {
        Response::new(status)
    } else {
        Response::with_body(
            status,
            format!(
                "<html><h1>{}</h1><p>{explanation}</p></html>",
                Response::new(status).reason
            ),
        )
    };
    resp.headers.set("Content-Type", "text/html; charset=UTF-8");
    resp
}

/// A parsed backend response head with the connection still open at the
/// first body byte, so the caller decides whether the body is buffered
/// (control plane) or streamed to the client (object data plane).
struct BackendHead {
    status: u16,
    reason: String,
    headers: Vec<(String, String)>,
    reader: std::io::BufReader<std::net::TcpStream>,
    /// The backend's Content-Length when parseable; backend connections
    /// are `Connection: close`, so `None` means close-delimited.
    content_length: Option<u64>,
}

impl BackendHead {
    /// Read the body into memory (up to `cap` bytes; requests are sent
    /// `Connection: close`, so EOF bounds a missing Content-Length) and
    /// produce the buffered response the control-plane paths consume.
    /// `has_body: false` (HEAD) skips the read entirely — a Content-Length
    /// header on a HEAD describes a body that never arrives.
    fn into_buffered(mut self, cap: u64, has_body: bool) -> std::io::Result<BackendResponse> {
        let mut body = Vec::new();
        if has_body {
            match self.content_length {
                Some(n) => {
                    if n > cap {
                        return Err(std::io::Error::other("backend body exceeds buffer cap"));
                    }
                    body.resize(n as usize, 0);
                    self.reader.read_exact(&mut body)?;
                }
                None => {
                    (&mut self.reader).take(cap).read_to_end(&mut body)?;
                }
            }
        }
        Ok(BackendResponse {
            status: self.status,
            reason: self.reason,
            headers: self.headers,
            body,
        })
    }

    /// Hand the connection off as a client-facing streaming body.
    fn into_body(self) -> swift_http::Body {
        let len = self.content_length;
        swift_http::Body::from_reader(Box::new(self.into_limited_reader()), len)
    }

    /// The raw framed body reader (EC segment decoding reads exact
    /// per-segment fragment windows from it).
    fn into_limited_reader(self) -> LimitedBackendReader {
        LimitedBackendReader {
            remaining: self.content_length,
            reader: self.reader,
        }
    }
}

/// Reads exactly the backend's declared Content-Length (or to EOF when
/// close-delimited); a short read surfaces as an error so a truncated
/// backend stream never silently truncates the client response.
struct LimitedBackendReader {
    reader: std::io::BufReader<std::net::TcpStream>,
    remaining: Option<u64>,
}

impl Read for LimitedBackendReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self.remaining {
            None => self.reader.read(buf),
            Some(0) => Ok(0),
            Some(remaining) => {
                let take = (buf.len() as u64).min(remaining) as usize;
                let n = self.reader.read(&mut buf[..take])?;
                if n == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "backend disconnected mid-body",
                    ));
                }
                self.remaining = Some(remaining - n as u64);
                Ok(n)
            }
        }
    }
}

/// Read one `\r\n`-terminated line from a backend response head, bounded.
fn read_backend_line(
    reader: &mut std::io::BufReader<std::net::TcpStream>,
) -> std::io::Result<String> {
    use std::io::BufRead;
    let mut line = Vec::new();
    (&mut *reader)
        .take(8 * 1024 + 1)
        .read_until(b'\n', &mut line)?;
    if line.len() > 8 * 1024 || !line.ends_with(b"\n") {
        return Err(std::io::Error::other("bad backend response line"));
    }
    while line.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
        line.pop();
    }
    String::from_utf8(line).map_err(|_| std::io::Error::other("non-UTF-8 backend header"))
}

/// Status, reason, and headers of one parsed backend response head.
type ParsedHead = (u16, String, Vec<(String, String)>);

/// Parse a status line + headers from an open backend connection.
fn read_backend_head(
    reader: &mut std::io::BufReader<std::net::TcpStream>,
) -> std::io::Result<ParsedHead> {
    let status_line = read_backend_line(reader)?;
    let mut parts = status_line.splitn(3, ' ');
    let _proto = parts.next();
    let status: u16 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| std::io::Error::other("bad status line"))?;
    let reason = parts.next().unwrap_or("").to_string();
    let mut headers = Vec::new();
    loop {
        let line = read_backend_line(reader)?;
        if line.is_empty() {
            break;
        }
        if headers.len() >= 128 {
            return Err(std::io::Error::other("too many backend headers"));
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    Ok((status, reason, headers))
}

/// Send one backend request (buffered request body) and parse the response
/// head, leaving the body unread on the connection.
#[allow(clippy::too_many_arguments)]
fn backend_request_head(
    node: &Node,
    part: u32,
    method: &str,
    path: &str,
    query: &str,
    headers: &HeaderKeyDict,
    body: &[u8],
    conn_timeout: Duration,
    node_timeout: Duration,
) -> std::io::Result<BackendHead> {
    let mut conn = connect_node(node, conn_timeout, node_timeout)?;
    let addr = format!("{}:{}", node.ip, node.port);
    let target = if query.is_empty() {
        format!("/{}/{}{}", node.device, part, path)
    } else {
        format!("/{}/{}{}?{}", node.device, part, path, query)
    };
    let mut out = format!("{method} {target} HTTP/1.1\r\nHost: {addr}\r\n");
    for (k, v) in headers.iter() {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    ));
    conn.write_all(out.as_bytes())?;
    if !body.is_empty() {
        conn.write_all(body)?;
    }
    let mut reader = std::io::BufReader::new(conn);
    let (status, reason, resp_headers) = read_backend_head(&mut reader)?;
    let content_length = resp_header(&resp_headers, "content-length")
        .and_then(|v| v.parse::<u64>().ok());
    Ok(BackendHead {
        status,
        reason,
        headers: resp_headers,
        reader,
        content_length,
    })
}

fn connect_node(
    node: &Node,
    conn_timeout: Duration,
    node_timeout: Duration,
) -> std::io::Result<std::net::TcpStream> {
    let addr = format!("{}:{}", node.ip, node.port);
    let sock_addr: std::net::SocketAddr = addr
        .parse()
        .map_err(|e| std::io::Error::other(format!("bad node address {addr}: {e}")))?;
    let conn = std::net::TcpStream::connect_timeout(&sock_addr, conn_timeout)?;
    // Small backend request/response exchanges over fresh connections are the
    // Nagle/delayed-ACK worst case; without this every proxy->backend hop eats
    // a ~40ms delayed-ACK stall (measured ~100ms+ per client op end to end).
    conn.set_nodelay(true).ok();
    conn.set_read_timeout(Some(node_timeout))?;
    conn.set_write_timeout(Some(node_timeout))?;
    Ok(conn)
}

/// One synchronous backend HTTP request over a fresh connection, response
/// body buffered (the control-plane form; object GETs stream instead).
#[allow(clippy::too_many_arguments)]
fn backend_request(
    node: &Node,
    part: u32,
    method: &str,
    path: &str,
    query: &str,
    headers: &HeaderKeyDict,
    body: &[u8],
    conn_timeout: Duration,
    node_timeout: Duration,
) -> std::io::Result<BackendResponse> {
    let head = backend_request_head(
        node,
        part,
        method,
        path,
        query,
        headers,
        body,
        conn_timeout,
        node_timeout,
    )?;
    // Cap at the object-size limit rather than the control-body cap: the
    // EC paths still fetch whole fragment archives through this function
    // (P1-leftover: still buffered), and the old implementation read to
    // EOF unbounded.
    head.into_buffered(swift_core::constraints::MAX_FILE_SIZE as u64, method != "HEAD")
}

/// A live object-PUT backend connection that answered `100 Continue`
/// (obj.py `Putter`): the write half streams body chunks, the read half
/// waits for the final response.
struct Putter {
    node: Node,
    stream: std::net::TcpStream,
    reader: std::io::BufReader<std::net::TcpStream>,
}

/// What one connect attempt produced (obj.py `_connect_put_node`): a live
/// streaming connection, or a final response issued before any body was
/// sent (412/409/... from the object server's pre-body checks).
enum PutterOutcome {
    Live(Putter),
    EarlyFinal(BackendResponse),
}

/// Open one object-PUT connection: send the request head with
/// `Expect: 100-continue` and the body framing (Content-Length when the
/// client declared one, chunked otherwise), then read the interim
/// response the lazy-100 object server sends before it reads any body.
#[allow(clippy::too_many_arguments)]
fn connect_putter(
    node: &Node,
    part: u32,
    path: &str,
    query: &str,
    headers: &HeaderKeyDict,
    content_length: Option<u64>,
    conn_timeout: Duration,
    node_timeout: Duration,
) -> std::io::Result<PutterOutcome> {
    let conn = connect_node(node, conn_timeout, node_timeout)?;
    let addr = format!("{}:{}", node.ip, node.port);
    let target = if query.is_empty() {
        format!("/{}/{}{}", node.device, part, path)
    } else {
        format!("/{}/{}{}?{}", node.device, part, path, query)
    };
    let mut out = format!("PUT {target} HTTP/1.1\r\nHost: {addr}\r\n");
    for (k, v) in headers.iter() {
        // The framing and connection lifecycle belong to this function.
        if ["content-length", "transfer-encoding", "connection", "expect"]
            .contains(&k.to_ascii_lowercase().as_str())
        {
            continue;
        }
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str("Expect: 100-continue\r\n");
    match content_length {
        Some(n) => out.push_str(&format!("Content-Length: {n}\r\n")),
        None => out.push_str("Transfer-Encoding: chunked\r\n"),
    }
    out.push_str("Connection: close\r\n\r\n");
    let mut stream = conn;
    stream.write_all(out.as_bytes())?;
    let mut reader = std::io::BufReader::new(stream.try_clone()?);
    let (status, reason, resp_headers) = read_backend_head(&mut reader)?;
    if status == 100 {
        return Ok(PutterOutcome::Live(Putter {
            node: node.clone(),
            stream,
            reader,
        }));
    }
    let content_length = resp_header(&resp_headers, "content-length")
        .and_then(|v| v.parse::<u64>().ok());
    let head = BackendHead {
        status,
        reason,
        headers: resp_headers,
        reader,
        content_length,
    };
    Ok(PutterOutcome::EarlyFinal(head.into_buffered(
        swift_http::MAX_CONTROL_BODY,
        true,
    )?))
}

fn write_chunk_framed<W: Write>(writer: &mut W, chunk: &[u8]) -> std::io::Result<()> {
    write!(writer, "{:x}\r\n", chunk.len())?;
    writer.write_all(chunk)?;
    writer.write_all(b"\r\n")
}

/// The per-segment sizes an object splits into (empty object = no
/// segments: Python stores zero-byte archives for zero-byte objects).
#[cfg(feature = "ec")]
fn ec_segment_sizes(orig_size: usize, segment_size: usize) -> Vec<usize> {
    if orig_size == 0 {
        return Vec::new();
    }
    let mut sizes = Vec::new();
    let mut remaining = orig_size;
    while remaining > segment_size {
        sizes.push(segment_size);
        remaining -= segment_size;
    }
    sizes.push(remaining);
    sizes
}

/// Streaming EC decode: reads one segment's fragment window from each of
/// the `ndata` sources, decodes it, and serves the plaintext — one
/// segment of buffering, never the whole object.
#[cfg(feature = "ec")]
struct EcDecodeReader {
    driver: swift_ec::EcDriver,
    sources: Vec<LimitedBackendReader>,
    seg_sizes: Vec<usize>,
    next_seg: usize,
    pending: Vec<u8>,
    pending_pos: usize,
}

#[cfg(feature = "ec")]
impl Read for EcDecodeReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if self.pending_pos < self.pending.len() {
                let n = (self.pending.len() - self.pending_pos).min(buf.len());
                buf[..n].copy_from_slice(&self.pending[self.pending_pos..self.pending_pos + n]);
                self.pending_pos += n;
                return Ok(n);
            }
            if self.next_seg >= self.seg_sizes.len() {
                return Ok(0);
            }
            let seg_len = self.seg_sizes[self.next_seg];
            self.next_seg += 1;
            let fragment_size = self.driver.fragment_size(seg_len);
            let mut frags: Vec<Vec<u8>> = Vec::with_capacity(self.sources.len());
            for source in &mut self.sources {
                let mut frag = vec![0u8; fragment_size];
                source.read_exact(&mut frag)?;
                frags.push(frag);
            }
            let mut decoded = self
                .driver
                .decode(&frags)
                .map_err(|e| std::io::Error::other(format!("EC decode failed: {e:?}")))?;
            decoded.truncate(seg_len);
            self.pending = decoded;
            self.pending_pos = 0;
        }
    }
}

/// Discard the first `skip` decoded bytes and serve at most `limit` —
/// the head/tail trim that turns a segment-aligned decode into the exact
/// client range.
#[cfg(feature = "ec")]
struct SkipLimitReader {
    inner: EcDecodeReader,
    skip: u64,
    limit: u64,
}

#[cfg(feature = "ec")]
impl Read for SkipLimitReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut sink = [0u8; STREAM_CHUNK_LOCAL];
        while self.skip > 0 {
            let take = (self.skip as usize).min(sink.len());
            let n = self.inner.read(&mut sink[..take])?;
            if n == 0 {
                return Ok(0);
            }
            self.skip -= n as u64;
        }
        if self.limit == 0 {
            return Ok(0);
        }
        let take = (self.limit as usize).min(buf.len());
        let n = self.inner.read(&mut buf[..take])?;
        self.limit -= n as u64;
        Ok(n)
    }
}

#[cfg(feature = "ec")]
const STREAM_CHUNK_LOCAL: usize = swift_http::STREAM_CHUNK;

/// The full fragment-archive size for an object of `total` bytes — the
/// sum of per-segment fragment sizes (what Python pre-declares as
/// X-Backend-Obj-Content-Length on EC fragment PUTs). Zero-byte objects
/// store zero-byte archives (chunk_transformer's `[b''] * n` tail).
#[cfg(feature = "ec")]
fn ec_archive_size(driver: &swift_ec::EcDriver, segment_size: usize, total: u64) -> u64 {
    if total == 0 {
        return 0;
    }
    let full = total / segment_size as u64;
    let last = (total % segment_size as u64) as usize;
    let mut out = full * driver.fragment_size(segment_size) as u64;
    if last > 0 {
        out += driver.fragment_size(last) as u64;
    }
    out
}

/// A live streaming EC fragment connection (obj.py `MIMEPutter`): the
/// request head advertised the MIME/multiphase protocol and the object
/// server answered `100 Continue` with matching capability headers.
#[cfg(feature = "ec")]
struct MimePutter {
    node: Node,
    stream: std::net::TcpStream,
    reader: std::io::BufReader<std::net::TcpStream>,
    boundary: String,
    /// Which fragment archive this connection carries (assigned from the
    /// slot after connect).
    frag_index: usize,
    frag_hasher: md5::Md5,
    started_data: bool,
}

#[cfg(feature = "ec")]
enum MimeConnectOutcome {
    Live(MimePutter),
    /// A final response issued before any body was sent (the object
    /// server's pre-body checks: 412/409/507/...).
    EarlyFinal(BackendResponse),
}

#[cfg(feature = "ec")]
impl MimePutter {
    /// Chunk-framed write of the object-body MIME preamble, once.
    fn start_object_data(&mut self) -> std::io::Result<()> {
        if !self.started_data {
            let preamble = format!("--{}\r\nX-Document: object body\r\n\r\n", self.boundary);
            write_chunk_framed(&mut self.stream, preamble.as_bytes())?;
            self.started_data = true;
        }
        Ok(())
    }

    fn send_data_chunk(&mut self, fragment: &[u8]) -> std::io::Result<()> {
        if fragment.is_empty() {
            return Ok(());
        }
        self.start_object_data()?;
        {
            use md5::Digest;
            self.frag_hasher.update(fragment);
        }
        write_chunk_framed(&mut self.stream, fragment)
    }

    fn frag_md5(&self) -> String {
        use md5::Digest;
        format!("{:x}", self.frag_hasher.clone().finalize())
    }

    /// Footer document + non-terminal tail boundary + the phase-1
    /// chunked terminator (MIMEPutter.end_of_object_data, multiphase).
    fn end_of_object_data(&mut self, footers_json: &str) -> std::io::Result<()> {
        self.start_object_data()?;
        let footer_md5 = md5_hex(footers_json.as_bytes());
        let message = format!(
            "\r\n--{b}\r\nX-Document: object metadata\r\nContent-MD5: {footer_md5}\r\n\r\n{footers_json}\r\n--{b}\r\n",
            b = self.boundary
        );
        write_chunk_framed(&mut self.stream, message.as_bytes())?;
        self.stream.write_all(b"0\r\n\r\n")?;
        self.stream.flush()
    }

    /// Read the phase-2 interim response; 100 means the fragment is on
    /// disk (non-durable) and the server awaits the commit.
    fn await_informational(&mut self) -> std::io::Result<u16> {
        let (status, _reason, _headers) = read_backend_head(&mut self.reader)?;
        Ok(status)
    }

    /// The commit document + terminal boundary + chunked terminator
    /// (MIMEPutter.send_commit_confirmation).
    fn send_commit(&mut self) -> std::io::Result<()> {
        let message = format!(
            "X-Document: put commit\r\n\r\nput_commit_confirmation\r\n--{}--",
            self.boundary
        );
        write_chunk_framed(&mut self.stream, message.as_bytes())?;
        self.stream.write_all(b"0\r\n\r\n")?;
        self.stream.flush()
    }

    fn read_final(mut self) -> std::io::Result<BackendResponse> {
        let (status, reason, headers) = read_backend_head(&mut self.reader)?;
        let content_length =
            resp_header(&headers, "content-length").and_then(|v| v.parse::<u64>().ok());
        BackendHead {
            status,
            reason,
            headers,
            reader: self.reader,
            content_length,
        }
        .into_buffered(swift_http::MAX_CONTROL_BODY, true)
    }
}

/// Open one EC fragment PUT: send the head with the MIME/multiphase
/// protocol headers and `Expect: 100-continue`, then classify the
/// interim response (MIMEPutter.connect). A 100 without both capability
/// adverts is an error (FooterNotSupported/MultiphasePUTNotSupported) —
/// the caller tries another node.
#[cfg(feature = "ec")]
#[allow(clippy::too_many_arguments)]
fn connect_mime_putter(
    node: &Node,
    part: u32,
    path: &str,
    headers: &HeaderKeyDict,
    boundary: &str,
    obj_content_length: Option<u64>,
    conn_timeout: Duration,
    node_timeout: Duration,
) -> std::io::Result<MimeConnectOutcome> {
    let conn = connect_node(node, conn_timeout, node_timeout)?;
    let addr = format!("{}:{}", node.ip, node.port);
    let target = format!("/{}/{}{}", node.device, part, path);
    let mut out = format!("PUT {target} HTTP/1.1\r\nHost: {addr}\r\n");
    for (k, v) in headers.iter() {
        if ["content-length", "transfer-encoding", "connection", "expect"]
            .contains(&k.to_ascii_lowercase().as_str())
        {
            continue;
        }
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str(&format!(
        "X-Backend-Obj-Multipart-Mime-Boundary: {boundary}\r\n"
    ));
    out.push_str("X-Backend-Obj-Metadata-Footer: yes\r\n");
    out.push_str("X-Backend-Obj-Multiphase-Commit: yes\r\n");
    if let Some(n) = obj_content_length {
        out.push_str(&format!("X-Backend-Obj-Content-Length: {n}\r\n"));
    }
    out.push_str("Transfer-Encoding: chunked\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n");
    let mut stream = conn;
    stream.write_all(out.as_bytes())?;
    let mut reader = std::io::BufReader::new(stream.try_clone()?);
    let (status, reason, resp_headers) = read_backend_head(&mut reader)?;
    if status == 100 {
        let advertised = |name: &str| {
            resp_header(&resp_headers, name).is_some_and(|v| v.eq_ignore_ascii_case("yes"))
        };
        if !advertised("x-obj-metadata-footer") || !advertised("x-obj-multiphase-commit") {
            return Err(std::io::Error::other(
                "object server lacks MIME footer/multiphase support",
            ));
        }
        use md5::Digest;
        return Ok(MimeConnectOutcome::Live(MimePutter {
            node: node.clone(),
            stream,
            reader,
            boundary: boundary.to_string(),
            frag_index: 0,
            frag_hasher: md5::Md5::new(),
            started_data: false,
        }));
    }
    let content_length =
        resp_header(&resp_headers, "content-length").and_then(|v| v.parse::<u64>().ok());
    let head = BackendHead {
        status,
        reason,
        headers: resp_headers,
        reader,
        content_length,
    };
    Ok(MimeConnectOutcome::EarlyFinal(head.into_buffered(
        swift_http::MAX_CONTROL_BODY,
        true,
    )?))
}

/// `swift.common.utils.quorum_size` is in swift-core.
use swift_core::storage_policy::quorum_size;

impl ProxyApp {
    pub fn new(account_ring: Ring, container_ring: Ring, config: ProxyConfig) -> Self {
        // Default the object ring to the container ring's topology when
        // no dedicated object ring is provided (single-ring test setups).
        Self::with_object_ring(account_ring, container_ring.clone(), container_ring, config)
    }

    pub fn with_object_ring(
        account_ring: Ring,
        container_ring: Ring,
        object_ring: Ring,
        config: ProxyConfig,
    ) -> Self {
        Self::with_policy_object_rings(
            account_ring,
            container_ring,
            object_ring,
            std::collections::HashMap::new(),
            config,
        )
    }

    /// Construct with per-policy object rings (`object-<N>.ring.gz`). Policy 0
    /// uses `object_ring`; other policies use `object_rings[policy]` when
    /// present, else fall back to `object_ring`.
    pub fn with_policy_object_rings(
        account_ring: Ring,
        container_ring: Ring,
        object_ring: Ring,
        object_rings: std::collections::HashMap<i64, Ring>,
        config: ProxyConfig,
    ) -> Self {
        Self::with_ec_policies(
            account_ring,
            container_ring,
            object_ring,
            object_rings,
            std::collections::HashMap::new(),
            config,
        )
    }

    /// Construct with per-policy object rings *and* EC schemes. Policy indexes
    /// present in `ec_policies` route object data through the EC controller.
    pub fn with_ec_policies(
        account_ring: Ring,
        container_ring: Ring,
        object_ring: Ring,
        object_rings: std::collections::HashMap<i64, Ring>,
        ec_policies: std::collections::HashMap<i64, EcPolicyParams>,
        config: ProxyConfig,
    ) -> Self {
        let error_limiter = ErrorLimiter::new(
            config.error_suppression_interval,
            config.error_suppression_limit,
        );
        ProxyApp {
            account_ring,
            container_ring,
            object_ring,
            object_rings,
            ec_policies,
            policy_name_to_index: std::collections::HashMap::new(),
            policy_index_to_name: std::collections::HashMap::new(),
            info_json: String::new(),
            config,
            error_limiter,
            info_cache: InfoCache::new(),
        }
    }

    /// Set the index → canonical-name table (the client-facing
    /// `X-Storage-Policy` header value). Builder-style.
    pub fn with_policy_index_names(
        mut self,
        names: std::collections::HashMap<i64, String>,
    ) -> Self {
        self.policy_index_to_name = names;
        self
    }

    /// Set the pre-rendered `GET /info` capabilities body. Builder-style so
    /// `main` can chain it.
    pub fn with_info_json(mut self, info_json: String) -> Self {
        self.info_json = info_json;
        self
    }

    /// Attach a shared memcache client for the info-cache L2 (P1c). When
    /// unset, the proxy keeps the process-local L1 only.
    pub fn with_info_memcache(mut self, client: MemcacheClient<TcpConn>) -> Self {
        self.info_cache = InfoCache::new().with_memcache(client);
        // Preserve any entries already written? Build always starts empty.
        self
    }

    /// Set the storage-policy name→index table (used to resolve a container
    /// PUT's `X-Storage-Policy` header). Builder-style so `main` can chain it.
    pub fn with_policy_names(
        mut self,
        names: std::collections::HashMap<String, i64>,
    ) -> Self {
        self.policy_name_to_index = names
            .into_iter()
            .map(|(k, v)| (k.to_lowercase(), v))
            .collect();
        self
    }

    /// The object ring for a configured storage policy index (Python
    /// `POLICIES.get_object_ring`). Unknown non-zero policy indexes are an
    /// error; falling back to policy 0 can route writes to the wrong disk
    /// namespace.
    pub fn object_ring_for(&self, policy_index: i64) -> Option<&Ring> {
        if policy_index == 0 {
            Some(&self.object_ring)
        } else {
            self.object_rings.get(&policy_index)
        }
    }

    /// NodeIter: primaries then handoffs, skipping error-limited nodes,
    /// bounded by request_node_count.
    fn iter_nodes(&self, ring: &Ring, part: u32) -> Vec<Node> {
        let primaries = ring.get_part_nodes(part).unwrap_or_default();
        let limit =
            (self.config.request_node_count_factor as usize) * primaries.len().max(1);
        let to_node = |dev: &swift_ring::RingDevice, handoff: bool| Node {
            ip: dev.ip.clone(),
            port: dev.port,
            device: dev.device.clone(),
            handoff,
        };
        let mut out: Vec<Node> = Vec::new();
        for node in &primaries {
            let n = to_node(node.dev, false);
            if !self.error_limiter.is_limited(&n) {
                out.push(n);
            }
        }
        if out.len() < limit {
            if let Ok(handoffs) = ring.get_more_nodes(part) {
                for handoff in handoffs {
                    if out.len() >= limit {
                        break;
                    }
                    let n = to_node(handoff.dev, true);
                    if !self.error_limiter.is_limited(&n) {
                        out.push(n);
                    }
                }
            }
        }
        out
    }

    /// `generate_request_headers`: the base backend headers.
    fn backend_headers(&self, req: &Request, transfer: bool, server_type: &str) -> HeaderKeyDict {
        let mut headers = HeaderKeyDict::new();
        if transfer {
            // transfer_headers: user/sys metadata and the ACL headers
            for (k, v) in req.headers.iter() {
                let kl = k.to_lowercase();
                let user = format!("x-{server_type}-meta-");
                let sys = format!("x-{server_type}-sysmeta-");
                // Object transient sysmeta (crypto user-meta, etc.) must reach
                // the object server so at-rest encryption can persist it.
                let object_transient = server_type == "object"
                    && kl.starts_with("x-object-transient-sysmeta-");
                // Object write requests also pass conditional, expiry and
                // content headers through to the object server, which owns their
                // validation (X-Delete-At/After -> 400, If-None-Match: * -> 412).
                let object_passthrough = server_type == "object"
                    && [
                        "x-delete-at",
                        "x-delete-after",
                        "x-if-delete-at",
                        "if-none-match",
                        "if-match",
                        "if-modified-since",
                        "if-unmodified-since",
                        "content-encoding",
                        "content-disposition",
                        "x-object-manifest",
                        "x-static-large-object",
                        "x-object-sysmeta-slo-etag",
                        // Client-supplied ETag must reach the object server so it
                        // can reject a body whose md5 does not match (422); the
                        // proxy used to drop it, silently accepting corrupt PUTs.
                        "etag",
                    ]
                    .contains(&kl.as_str());
                // X-Remove-Container-* is translated to empty ACL/meta
                // updates on the container server (P1c ACL revoke path).
                let container_remove = server_type == "container"
                    && kl.starts_with("x-remove-container-");
                if kl.starts_with(&user)
                    || kl.starts_with(&sys)
                    || object_transient
                    || object_passthrough
                    || container_remove
                    || [
                        "x-container-read",
                        "x-container-write",
                        "x-versions-location",
                        "content-type",
                        // container-sync destination + shared key (Python
                        // transfer_headers special-cases these; without them
                        // POST Sync-To returns 204 but metadata stays empty).
                        "x-container-sync-to",
                        "x-container-sync-key",
                    ]
                    .contains(&kl.as_str())
                {
                    headers.set(k, v);
                }
            }
        }
        if let Some(trans_id) = req.headers.get("X-Trans-Id") {
            headers.set("X-Trans-Id", trans_id);
        }
        headers.set("User-Agent", format!("proxy-server {}", std::process::id()));
        headers
    }

    /// `_make_requests` + `best_response` for mutating verbs: fan out to
    /// every primary node concurrently and pick the quorum response.
    #[allow(clippy::too_many_arguments)]
    fn make_requests(
        self: &Arc<Self>,
        nodes: Vec<Node>,
        node_number: usize,
        part: u32,
        method: &str,
        path: &str,
        query: &str,
        per_node_headers: Vec<HeaderKeyDict>,
        body: Vec<u8>,
    ) -> Response {
        let (tx, rx) = mpsc::channel();
        let mut spawned = 0usize;
        let node_pool = Arc::new(Mutex::new(nodes.into_iter().collect::<Vec<_>>()));
        for headers in per_node_headers.into_iter() {
            let tx = tx.clone();
            let app = Arc::clone(self);
            let node_pool = Arc::clone(&node_pool);
            let (method, path, query, body) = (
                method.to_string(),
                path.to_string(),
                query.to_string(),
                body.clone(),
            );
            spawned += 1;
            std::thread::spawn(move || {
                // sequentially try nodes from the shared pool until one
                // gives a useful (non-5xx) response
                loop {
                    let node = {
                        let mut pool = node_pool.lock().unwrap();
                        if pool.is_empty() {
                            let _ = tx.send(None);
                            return;
                        }
                        pool.remove(0)
                    };
                    match backend_request(
                        &node,
                        part,
                        &method,
                        &path,
                        &query,
                        &headers,
                        &body,
                        app.config.conn_timeout,
                        app.config.node_timeout,
                    ) {
                        Ok(resp) if resp.status == 507 => {
                            app.error_limiter.limit(&node);
                        }
                        Ok(resp) if resp.status >= 500 => {
                            app.error_limiter.increment(&node);
                        }
                        Ok(resp) => {
                            let _ = tx.send(Some(resp));
                            return;
                        }
                        Err(_) => {
                            app.error_limiter.increment(&node);
                        }
                    }
                }
            });
        }
        drop(tx);
        let mut results: Vec<BackendResponse> = Vec::new();
        for resp in rx.iter().flatten() {
            results.push(resp);
        }
        while results.len() < spawned.max(node_number) {
            results.push(BackendResponse {
                status: 503,
                reason: "Service Unavailable".to_string(),
                headers: Vec::new(),
                body: Vec::new(),
            });
        }
        self.best_response(&results, node_number)
    }

    /// Streaming object PUT (obj.py `_get_put_connections` +
    /// `_check_failure_put_connections` + `_transfer_data`): establish
    /// backend connections with `Expect: 100-continue`, then tee ONE pass
    /// of the client body to every live connection — the proxy never holds
    /// more than one 64KB chunk of object data.
    #[allow(clippy::too_many_arguments)]
    fn stream_put_object(
        self: &Arc<Self>,
        nodes: Vec<Node>,
        node_number: usize,
        part: u32,
        path: &str,
        query: &str,
        per_node_headers: Vec<HeaderKeyDict>,
        body: swift_http::Body,
    ) -> Response {
        let content_length = body.content_length();
        let node_pool = Arc::new(Mutex::new(nodes.into_iter().collect::<Vec<_>>()));
        let (tx, rx) = mpsc::channel();
        let slots = per_node_headers.len();
        for headers in per_node_headers.into_iter() {
            let tx = tx.clone();
            let app = Arc::clone(self);
            let node_pool = Arc::clone(&node_pool);
            let (path, query) = (path.to_string(), query.to_string());
            std::thread::spawn(move || loop {
                let node = {
                    let mut pool = node_pool.lock().unwrap();
                    if pool.is_empty() {
                        return; // slot unfilled -> a 503 stub with no node
                    }
                    pool.remove(0)
                };
                match connect_putter(
                    &node,
                    part,
                    &path,
                    &query,
                    &headers,
                    content_length,
                    app.config.conn_timeout,
                    app.config.node_timeout,
                ) {
                    Ok(PutterOutcome::EarlyFinal(resp)) if resp.status == 507 => {
                        app.error_limiter.limit(&node)
                    }
                    Ok(PutterOutcome::EarlyFinal(resp)) if resp.status >= 500 => {
                        app.error_limiter.increment(&node)
                    }
                    Ok(outcome) => {
                        let _ = tx.send(outcome);
                        return;
                    }
                    Err(_) => app.error_limiter.increment(&node),
                }
            });
        }
        drop(tx);
        let mut earlies: Vec<BackendResponse> = Vec::new();
        let mut putters: Vec<Putter> = Vec::new();
        for outcome in rx.iter() {
            match outcome {
                PutterOutcome::Live(p) => putters.push(p),
                PutterOutcome::EarlyFinal(r) => earlies.push(r),
            }
        }
        // obj.py:_check_failure_put_connections — a pre-body 412
        // (If-None-Match) or 409 (timestamp conflict; answered 202
        // Accepted) from any node ends the request before data moves.
        if earlies.iter().any(|r| r.status == 412) {
            return swob_response(412);
        }
        if earlies.iter().any(|r| r.status == 409) {
            return swob_response(202);
        }
        let quorum = quorum_size(node_number.max(1) as f64) as usize;
        if putters.len() < quorum {
            // Not enough live connections to attempt the write
            // (obj.py:_check_min_conns -> 503), but pre-body finals still
            // participate so an authoritative 4xx quorum can surface.
            let mut results = earlies;
            while results.len() < slots.max(node_number) {
                results.push(BackendResponse {
                    status: 503,
                    reason: "Service Unavailable".to_string(),
                    headers: Vec::new(),
                    body: Vec::new(),
                });
            }
            return self.best_response(&results, node_number);
        }

        // One read pass over the client body, teeing each chunk to every
        // live connection. The first read triggers swift-http's lazy
        // `100 Continue` to the client.
        let chunked = content_length.is_none();
        let (mut reader, _) = body.into_reader();
        let mut buf = vec![0u8; swift_http::STREAM_CHUNK];
        loop {
            let n = match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) => {
                    // The client hung up (499) or the chunked decode hit the
                    // configured size limit (413). Backend connections are
                    // dropped mid-body; their object servers abort without
                    // committing.
                    let status = if swift_http::body_too_large(&e) { 413 } else { 499 };
                    return swob_response(status);
                }
            };
            let chunk = &buf[..n];
            putters = putters
                .into_iter()
                .filter_map(|mut p| {
                    let written = if chunked {
                        write_chunk_framed(&mut p.stream, chunk)
                    } else {
                        p.stream.write_all(chunk)
                    };
                    match written {
                        Ok(()) => Some(p),
                        Err(_) => {
                            self.error_limiter.increment(&p.node);
                            None
                        }
                    }
                })
                .collect();
            if putters.len() < quorum {
                // obj.py: 'Object PUT exceptions during send, %(conns)s/%(nodes)s
                // required connections'
                return swob_response(503);
            }
        }
        if chunked {
            putters.retain_mut(|p| {
                let ok = p.stream.write_all(b"0\r\n\r\n").is_ok();
                if !ok {
                    self.error_limiter.increment(&p.node);
                }
                ok
            });
        }

        // Collect the final responses (node_timeout applies per read).
        let mut results = earlies;
        for mut p in putters {
            let _ = p.stream.flush();
            let final_resp = read_backend_head(&mut p.reader).and_then(|(status, reason, headers)| {
                let content_length = resp_header(&headers, "content-length")
                    .and_then(|v| v.parse::<u64>().ok());
                BackendHead {
                    status,
                    reason,
                    headers,
                    reader: p.reader,
                    content_length,
                }
                .into_buffered(swift_http::MAX_CONTROL_BODY, true)
            });
            match final_resp {
                Ok(resp) => results.push(resp),
                Err(_) => self.error_limiter.increment(&p.node),
            }
        }
        while results.len() < slots.max(node_number) {
            results.push(BackendResponse {
                status: 503,
                reason: "Service Unavailable".to_string(),
                headers: Vec::new(),
                body: Vec::new(),
            });
        }
        self.best_response(&results, node_number)
    }

    /// `best_response`/`_compute_quorum_response`.
    fn best_response(&self, results: &[BackendResponse], node_count: usize) -> Response {
        self.best_response_with_quorum(results, quorum_size(node_count.max(1) as f64) as usize)
    }

    /// `best_response` with an explicit quorum (Python's `quorum_size=`
    /// keyword; the object POST path recomputes quorum over the ring
    /// replica count once extra handoff requests were made, obj.py:951-953).
    fn best_response_with_quorum(&self, results: &[BackendResponse], quorum: usize) -> Response {
        for hundred in [200u16, 300, 400] {
            let matching: Vec<&BackendResponse> = results
                .iter()
                .filter(|r| r.status >= hundred && r.status < hundred + 100)
                .collect();
            if matching.len() >= quorum {
                // Python: status = max(hstatuses); status_index =
                // statuses.index(status) — the FIRST response with the maximal
                // status. Rust's max_by_key returns the LAST tie, so select the
                // first max explicitly.
                let max_status = matching.iter().map(|r| r.status).max().unwrap();
                let best = matching.iter().find(|r| r.status == max_status).unwrap();
                let mut resp = Response::with_body(best.status, best.body.clone());
                resp.reason = best.reason.clone();
                for (k, v) in &best.headers {
                    let kl = k.to_lowercase();
                    if kl == "connection" || kl == "content-length" {
                        continue;
                    }
                    resp.headers.set(k, v);
                }
                return resp;
            }
        }
        swob_response(503)
    }

    /// `_make_requests` (base.py:2110-2161) for the object POST path: one
    /// backend POST per header dict, each pulling nodes from the shared
    /// pool (primaries first, then handoffs) until a non-5xx response,
    /// like `_make_request` (base.py:2056-2108). Returns one slot per
    /// header in spawn order: `Some(resp)` when a node answered usefully,
    /// `None` when no node did — Python drops non-useful responses via
    /// `is_useful_response` (base.py:1104-1112: a 404 from a handoff with
    /// no `x-backend-timestamp` header is not authoritative) and later
    /// pads the gaps with 503 stubs carrying no node.
    fn post_fan_out(
        self: &Arc<Self>,
        node_pool: &Arc<Mutex<Vec<Node>>>,
        part: u32,
        path: &str,
        query: &str,
        per_node_headers: Vec<HeaderKeyDict>,
    ) -> Vec<Option<BackendResponse>> {
        let (tx, rx) = mpsc::channel();
        let slots = per_node_headers.len();
        for (i, headers) in per_node_headers.into_iter().enumerate() {
            let tx = tx.clone();
            let app = Arc::clone(self);
            let node_pool = Arc::clone(node_pool);
            let (path, query) = (path.to_string(), query.to_string());
            std::thread::spawn(move || loop {
                let node = {
                    let mut pool = node_pool.lock().unwrap();
                    if pool.is_empty() {
                        return; // slot stays None -> a 503 stub with no node
                    }
                    pool.remove(0)
                };
                match backend_request(
                    &node,
                    part,
                    "POST",
                    &path,
                    &query,
                    &headers,
                    b"",
                    app.config.conn_timeout,
                    app.config.node_timeout,
                ) {
                    Ok(resp) if resp.status == 507 => app.error_limiter.limit(&node),
                    Ok(resp) if resp.status >= 500 => app.error_limiter.increment(&node),
                    Ok(resp) => {
                        // `is_useful_response` (base.py:1104-1112): drop a
                        // handoff 404 with no x-backend-timestamp header.
                        if !(node.handoff
                            && resp.status == 404
                            && resp_header(&resp.headers, "x-backend-timestamp").is_none())
                        {
                            let _ = tx.send((i, resp));
                        }
                        return;
                    }
                    Err(_) => app.error_limiter.increment(&node),
                }
            });
        }
        drop(tx);
        let mut out: Vec<Option<BackendResponse>> = (0..slots).map(|_| None).collect();
        for (i, resp) in rx.iter() {
            out[i] = Some(resp);
        }
        out
    }

    /// `_post_object` + `_post_extra_handoffs` (obj.py:874-962): POST to
    /// the primary nodes; when they return mixed results — some 202
    /// "found", some 404, short of quorum — make ONE extra POST per
    /// missing primary to the next unused handoff nodes and re-run
    /// best_response over the combined results, so an object whose
    /// primaries were rebalanced away still POSTs 2xx via its handoffs.
    fn post_object(
        self: &Arc<Self>,
        ring: &Ring,
        part: u32,
        path: &str,
        query: &str,
        per_node_headers: Vec<HeaderKeyDict>,
        replica_count: usize,
    ) -> Response {
        // NodeIter equivalent (obj.py:921-922): primaries then handoffs;
        // round one consumes handoffs only for errored/5xx primaries.
        let node_pool = Arc::new(Mutex::new(self.iter_nodes(ring, part)));
        let mut slots =
            self.post_fan_out(&node_pool, part, path, query, per_node_headers.clone());
        let count_real = |slots: &[Option<BackendResponse>], status: u16| -> usize {
            // `_collect_status_map` (obj.py:904-910) skips the padded
            // no-node entries, which here are the `None` slots.
            slots
                .iter()
                .flatten()
                .filter(|r| r.status == status)
                .count()
        };
        // obj.py:927-931: by default the quorum is result-count sized;
        // found_count is exactly the 202s (HTTP_ACCEPTED) from this round.
        let mut quorum = quorum_size(slots.len().max(1) as f64) as usize;
        let found_count = count_real(&slots, 202);
        if found_count > 0 && found_count < quorum {
            // obj.py:932-935: quorum would be wrong once we make extra
            // requests — recompute it over the ring replica count.
            quorum = quorum_size(replica_count.max(1) as f64) as usize;
            // obj.py:936-939: the fan-out already visited handoffs for
            // Timeout/5xx primaries; we only make up for the 404s, using
            // the next handoffs the first round did not consume.
            let extra_requests = count_real(&slots, 404);
            let handoff_nodes: Vec<Node> = {
                let mut pool = node_pool.lock().unwrap();
                let mut taken = Vec::new();
                while taken.len() < extra_requests {
                    match pool.iter().position(|n| n.handoff) {
                        Some(idx) => taken.push(pool.remove(idx)),
                        None => break,
                    }
                }
                taken
            };
            if !handoff_nodes.is_empty() {
                // obj.py:891-896: the backend headers of the *missing*
                // (non-202) requests, capped to the available handoffs so
                // the pool cannot recycle nodes.
                let missing_headers: Vec<HeaderKeyDict> = per_node_headers
                    .iter()
                    .zip(slots.iter())
                    .filter(|(_, slot)| !matches!(slot, Some(r) if r.status == 202))
                    .map(|(h, _)| h.clone())
                    .take(handoff_nodes.len())
                    .collect();
                let handoff_pool = Arc::new(Mutex::new(handoff_nodes));
                let handoff_slots =
                    self.post_fan_out(&handoff_pool, part, path, query, missing_headers);
                // obj.py:946: append the handoff results.
                slots.extend(handoff_slots);
            }
        }
        // base.py:2155-2161: pad every slot that produced nothing useful
        // with a 503 stub, then pick the quorum response (obj.py:948-953).
        let results: Vec<BackendResponse> = slots
            .into_iter()
            .map(|slot| {
                slot.unwrap_or(BackendResponse {
                    status: 503,
                    reason: "Service Unavailable".to_string(),
                    headers: Vec::new(),
                    body: Vec::new(),
                })
            })
            .collect();
        let resp = self.best_response_with_quorum(&results, quorum);
        post_existence_proof_guard(resp, found_count)
    }

    /// `GETorHEAD_base` via `GetOrHeadHandler._make_node_request`
    /// (base.py:1560-1692): iterate primaries then handoffs and return a
    /// *valid* source, guarding against stale reads during a
    /// rebalance (upstream bug #1560574):
    /// - every object 404's `X-Backend-Timestamp` (a tombstone) raises
    ///   `latest_404_timestamp` (base.py:1642-1648);
    /// - a good source only counts when its own timestamp is `>=` that
    ///   watermark (base.py:1599-1615 and the final weed-out at
    ///   base.py:1679-1681), so old data left on a handoff cannot shadow a
    ///   newer DELETE;
    /// - a 404 from a handoff with no truthy `X-Backend-Timestamp` is not
    ///   authoritative and is thrown out (base.py:1617-1624), so a request
    ///   whose primaries are all unreachable resolves to 503, not 404.
    /// - with `X-Newest: true`, every good source is collected and the
    ///   newest-timestamp winner is returned (base.py:1614-1615, 1678-1688);
    ///   without it, the first valid source wins (Python default for objects).
    #[allow(clippy::too_many_arguments)]
    fn get_or_head(
        &self,
        server_type: &str,
        nodes: Vec<Node>,
        part: u32,
        method: &str,
        path: &str,
        query: &str,
        headers: &HeaderKeyDict,
    ) -> Option<Response> {
        let is_object = server_type == "object";
        let is_head = method == "HEAD";
        let newest = headers
            .get("X-Newest")
            .map(config_true_value)
            .unwrap_or(false);
        let build = |resp: BackendResponse| -> Response {
            let mut out = Response::with_body(resp.status, resp.body);
            out.reason = resp.reason;
            for (k, v) in &resp.headers {
                let kl = k.to_lowercase();
                // GET length is safely reconstructed from the received body,
                // but a HEAD has no body. Preserve its authoritative backend
                // length for callers such as SLO segment validation.
                if kl == "connection" || (kl == "content-length" && !is_head) {
                    continue;
                }
                // The object server stores/returns the ETag quoted (matching
                // Python's diskfile); the client-facing value is the bare md5
                // (Python normalize_etag). Strip the quotes here, at the proxy.
                if is_object && kl == "etag" {
                    out.headers.set(k, v.trim_matches('"'));
                    continue;
                }
                out.headers.set(k, v);
            }
            // Python GetOrHeadHandler.get_working_response emits Accept-Ranges
            // on successful account/container/object GET/HEAD. Do not attach it
            // to 4xx (Python 404s omit it; adding it here flips to a new break).
            if (200..300).contains(&out.status) {
                out.headers.set("Accept-Ranges", "bytes");
            }
            // HEAD/empty 2xx: Python always emits Content-Length (0 when there
            // is no body). Some backends omit it; without this the client-facing
            // contract header disappears.
            if is_head && (200..300).contains(&out.status) && out.headers.get("Content-Length").is_none()
            {
                out.headers.set("Content-Length", 0);
            }
            out
        };
        // Object GET bodies stream backend->client; everything else
        // (HEADs, listings, error bodies) is buffered as before.
        let build_streamed = |head: BackendHead| -> Response {
            let mut out = Response::new(head.status);
            out.reason = head.reason.clone();
            for (k, v) in &head.headers {
                let kl = k.to_lowercase();
                // The streamed body's declared length drives Content-Length.
                if kl == "connection" || kl == "content-length" {
                    continue;
                }
                // Bare md5 to the client; the object server returns it quoted.
                if is_object && kl == "etag" {
                    out.headers.set(k, v.trim_matches('"'));
                    continue;
                }
                out.headers.set(k, v);
            }
            if (200..300).contains(&out.status) {
                out.headers.set("Accept-Ranges", "bytes");
            }
            out.body = head.into_body();
            out
        };
        let buffered =
            |head: BackendHead| head.into_buffered(swift_http::MAX_CONTROL_BODY, !is_head);
        // A 404 from one replica is NOT authoritative during a rebalance — a
        // later replica may still hold the object. Keep looking for a good
        // source and only fall back to the recorded 404 if none is found.
        let mut recorded_404: Option<Response> = None;
        // base.py:1416: the newest tombstone timestamp seen so far, zero
        // until an object 404 carries one.
        let mut latest_404_timestamp = Timestamp::zero();
        // X-Newest path: collect every good source, then pick the newest
        // timestamp after the node walk (base.py:1678-1688). Non-newest
        // returns the first valid source immediately.
        let mut newest_candidates: Vec<(Timestamp, BackendHead)> = Vec::new();
        for node in nodes {
            match backend_request_head(
                &node,
                part,
                method,
                path,
                query,
                headers,
                b"",
                self.config.conn_timeout,
                self.config.node_timeout,
            ) {
                Ok(head) if head.status == 507 => self.error_limiter.limit(&node),
                Ok(head) if head.status >= 500 => {
                    // A handoff 5xx with no tombstone timestamp is thrown out
                    // (base.py:1617-1624); an authoritative 5xx enters
                    // Python's status list but never beats a recorded 404 or
                    // the final 503 in best_response, so both reduce to
                    // "keep looking".
                    self.error_limiter.increment(&node)
                }
                Ok(head) if head.status == 404 => {
                    // The tombstone timestamp; zero when absent
                    // (base.py:1645-1646). base.py:1617-1624: a 404 from a
                    // handoff is thrown out unless that timestamp proves the
                    // data is really on disk and was DELETEd — so if nothing
                    // authoritative turns up the request ends 503, not 404.
                    let ts = backend_404_timestamp(&head.headers);
                    if !node.handoff || ts.is_truthy() {
                        // base.py:1642-1648: for objects, remember the newest
                        // tombstone so a slower stale source can't win. (lp
                        // 1560574 checks only objects for now.)
                        if is_object && ts > latest_404_timestamp {
                            latest_404_timestamp = ts;
                        }
                        // Python's best_response returns the first entry with
                        // the winning status, so keep the first authoritative
                        // 404.
                        if recorded_404.is_none() {
                            match buffered(head) {
                                Ok(resp) => recorded_404 = Some(build(resp)),
                                Err(_) => self.error_limiter.increment(&node),
                            }
                        }
                    }
                }
                Ok(head) if is_good_source(head.status, is_object) => {
                    // base.py:1599-1615: a possible source is only valid if
                    // its timestamp is >= every tombstone seen so far;
                    // otherwise it is a stale copy (e.g. un-replicated data
                    // on a handoff after a DELETE) and is never returned
                    // (base.py:1679-1681).
                    let ts = source_timestamp(&head.headers);
                    if ts >= latest_404_timestamp {
                        if newest {
                            // Keep looking — one good source is not enough
                            // when searching for the newest (base.py:1614).
                            newest_candidates.push((ts, head));
                            continue;
                        }
                        // Once the winner streams there is no failover: a
                        // mid-stream backend failure aborts the client
                        // connection (resumable ranged re-fetch remains
                        // deferred).
                        if is_object && !is_head {
                            return Some(build_streamed(head));
                        }
                        match buffered(head) {
                            Ok(resp) => return Some(build(resp)),
                            Err(_) => {
                                self.error_limiter.increment(&node);
                                continue;
                            }
                        }
                    }
                }
                Ok(head) => match buffered(head) {
                    Ok(resp) => return Some(build(resp)),
                    Err(_) => self.error_limiter.increment(&node),
                },
                Err(_) => self.error_limiter.increment(&node),
            }
        }
        if newest {
            // Weed out sources older than tombstones discovered later in
            // the walk, then take the newest (base.py:1678-1688).
            newest_candidates.retain(|(ts, _)| *ts >= latest_404_timestamp);
            if let Some((_, head)) = newest_candidates
                .into_iter()
                .max_by(|(a, _), (b, _)| a.cmp(b))
            {
                if is_object && !is_head {
                    return Some(build_streamed(head));
                }
                return match buffered(head) {
                    Ok(resp) => Some(build(resp)),
                    Err(_) => recorded_404,
                };
            }
        }
        recorded_404
    }

    /// `autocreate_account`: PUT the account directly on its ring nodes.
    fn autocreate_account(self: &Arc<Self>, account: &str) {
        let Ok((part, _nodes)) = self.account_ring.get_nodes(account, None, None) else {
            return;
        };
        let path = format!("/{}", percent_encode(account));
        let now = Timestamp::now().internal();
        let mut headers = HeaderKeyDict::new();
        headers.set("X-Timestamp", &now);
        let node_count = self
            .account_ring
            .get_part_nodes(part)
            .map(|n| n.len())
            .unwrap_or(1);
        let nodes = self.iter_nodes(&self.account_ring, part);
        let per_node = (0..node_count).map(|_| headers.clone()).collect();
        let resp = self.make_requests(
            nodes,
            node_count,
            part,
            "PUT",
            &path,
            "",
            per_node,
            Vec::new(),
        );
        // base.py:2340-2343: a successful autocreate clears the cached (404)
        // account info so the caller's next existence check re-HEADs.
        if (200..300).contains(&resp.status) {
            self.info_cache.clear_account(account);
        }
    }

    pub fn handle(self: &Arc<Self>, req: Request) -> Response {
        // Reject a decoded path carrying a NUL byte (invalid UTF-8 can't reach a
        // Rust String), mirroring Python's `check_utf8` at request entry:
        // HTTPPreconditionFailed (412) "Invalid UTF8 or contains NULL".
        if req.path.contains('\u{0}') {
            return text_response(412, "Invalid UTF8 or contains NULL");
        }
        // `/info`: public cluster-capabilities document (no auth). Reports only
        // the features this proxy actually serves, so clients (and the
        // functional suite) don't probe unimplemented ones.
        if req.path == "/info" || req.path.starts_with("/info?") {
            if !self.info_json.is_empty() && matches!(req.method.as_str(), "GET" | "HEAD") {
                let mut resp = Response::with_body(
                    200,
                    if req.method == "HEAD" {
                        Vec::new()
                    } else {
                        self.info_json.clone().into_bytes()
                    },
                );
                resp.headers
                    .set("Content-Type", "application/json; charset=utf-8");
                resp.headers.set("Content-Length", self.info_json.len());
                return resp;
            }
            return swob_response(if self.info_json.is_empty() { 403 } else { 405 });
        }
        // Profile Cartographer scrape: process-local stage timers.
        if req.path == "/recon/stage" && matches!(req.method.as_str(), "GET" | "HEAD") {
            let body = swift_core::stage::snapshot_json();
            let mut resp = Response::with_body(
                200,
                if req.method == "HEAD" {
                    Vec::new()
                } else {
                    body.clone().into_bytes()
                },
            );
            resp.headers
                .set("Content-Type", "application/json; charset=utf-8");
            resp.headers.set("Content-Length", body.len());
            return resp;
        }
        let segs: Vec<&str> = req.path.splitn(5, '/').collect();
        // /v1/account[/container[/object]]
        if segs.len() < 3 || !segs[0].is_empty() || segs[1] != "v1" || segs[2].is_empty() {
            return swob_response(404);
        }
        let account = segs[2].to_string();
        let container = segs.get(3).map(|s| s.to_string()).filter(|s| !s.is_empty());
        let object = segs.get(4).map(|s| s.to_string()).filter(|s| !s.is_empty());
        // Authorize against the container/account ACL BEFORE dispatch — one
        // central gate so no verb path can skip it (a skipped path would be a
        // bypass, since tempauth now only authenticates). No-op when auth is
        // disabled. Also rewrites X-Account-Access-Control → sysmeta.
        let mut req = req;
        if let Some(denied) =
            self.authorize(&mut req, &account, container.as_deref(), object.as_deref())
        {
            return denied;
        }
        let swift_owner = req
            .headers
            .get("X-Backend-Swift-Owner")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        match (container, object) {
            (Some(container), Some(object)) => {
                self.object_request(&mut req, &account, &container, &object)
            }
            (Some(container), None) => {
                let mut resp = self.container_request(&req, &account, &container);
                strip_owner_headers(&mut resp, swift_owner);
                resp
            }
            (None, _) => {
                let mut resp = self.account_request(&req, &account);
                expose_account_acl_header(&mut resp);
                strip_owner_headers(&mut resp, swift_owner);
                resp
            }
        }
    }

    fn account_request(self: &Arc<Self>, req: &Request, account: &str) -> Response {
        let Ok((part, _)) = self.account_ring.get_nodes(account, None, None) else {
            return swob_response(503);
        };
        let path = format!("/{}", percent_encode(account));
        match req.method.as_str() {
            "GET" | "HEAD" => {
                let headers = self.backend_headers(req, false, "account");
                let nodes = self.iter_nodes(&self.account_ring, part);
                match self.get_or_head(
                    "account",
                    nodes,
                    part,
                    &req.method,
                    &path,
                    &req.query_string,
                    &headers,
                ) {
                    Some(resp)
                        if resp.status == 404 && self.config.account_autocreate =>
                    {
                        // synthesize an empty account listing
                        synthesized_account_listing(req)
                    }
                    Some(resp) => resp,
                    None => swob_response(503),
                }
            }
            "PUT" | "DELETE" if !self.config.allow_account_management => {
                // account.py:37-39,112-115,170: remove PUT/DELETE from allowed
                // methods when allow_account_management is off.
                let mut resp = swob_response(405);
                resp.headers.set("Allow", "GET, HEAD, POST, OPTIONS");
                resp
            }
            "PUT" | "POST" | "DELETE" => {
                // account.py:128,150,177: clear the cached account info
                // BEFORE the backend fan-out, so nothing serves the
                // pre-write state after the write has been accepted.
                self.info_cache.clear_account(account);
                let mut headers = self.backend_headers(req, true, "account");
                headers.set("X-Timestamp", Timestamp::now().internal());
                let node_count = self
                    .account_ring
                    .get_part_nodes(part)
                    .map(|n| n.len())
                    .unwrap_or(1);
                let nodes = self.iter_nodes(&self.account_ring, part);
                let per_node: Vec<HeaderKeyDict> =
                    (0..node_count).map(|_| headers.clone()).collect();
                let resp = self.make_requests(
                    nodes,
                    node_count,
                    part,
                    &req.method,
                    &path,
                    &req.query_string,
                    per_node.clone(),
                    Vec::new(),
                );
                // account.py:154-158: a POST to a not-yet-created account on
                // an autocreate cluster creates the account and retries, so
                // the first metadata POST after a wipe is not lost.
                if resp.status == 404
                    && req.method == "POST"
                    && self.config.account_autocreate
                {
                    self.autocreate_account(account);
                    let nodes = self.iter_nodes(&self.account_ring, part);
                    return self.make_requests(
                        nodes,
                        node_count,
                        part,
                        &req.method,
                        &path,
                        &req.query_string,
                        per_node,
                        Vec::new(),
                    );
                }
                resp
            }
            _ => swob_response(405),
        }
    }

    fn container_request(
        self: &Arc<Self>,
        req: &Request,
        account: &str,
        container: &str,
    ) -> Response {
        let Ok((container_part, _)) =
            self.container_ring
                .get_nodes(account, Some(container), None)
        else {
            return swob_response(503);
        };
        let path = format!(
            "/{}/{}",
            percent_encode(account),
            percent_encode(container)
        );
        match req.method.as_str() {
            "GET" | "HEAD" => {
                // Wave 3 L3b: shard-range listing fan-out for sharded containers.
                // Skip when the client already asked for record-type=shard (or
                // backend override), so admin shard listings stay single-hop.
                // HEAD uses the same fan-out so Object-Count matches list
                // (name-deduped residual + shards), then strips the body.
                let record_type = req
                    .headers
                    .get("X-Backend-Record-Type")
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if record_type != "shard" && !req.query_string.contains("states=") {
                    if let Some(mut fan) =
                        self.maybe_sharded_container_listing(req, account, container)
                    {
                        if req.method == "HEAD" {
                            // Listing path returns 200 + JSON; HEAD must be
                            // empty-body with count headers only.
                            let count = fan
                                .headers
                                .get("X-Container-Object-Count")
                                .unwrap_or("0")
                                .to_string();
                            let bytes = fan
                                .headers
                                .get("X-Container-Bytes-Used")
                                .unwrap_or("0")
                                .to_string();
                            fan.status = 204;
                            fan.body = swift_http::Body::empty();
                            fan.headers.set("Content-Length", "0");
                            fan.headers.set("X-Container-Object-Count", count);
                            fan.headers.set("X-Container-Bytes-Used", bytes);
                        }
                        return fan;
                    }
                }
                let headers = self.backend_headers(req, false, "container");
                let nodes = self.iter_nodes(&self.container_ring, container_part);
                let mut resp = self
                    .get_or_head(
                        "container",
                        nodes,
                        container_part,
                        &req.method,
                        &path,
                        &req.query_string,
                        &headers,
                    )
                    .unwrap_or_else(|| swob_response(503));
                // Client-facing policy name: translate the backend index header
                // (which gatekeeper strips outbound) to `X-Storage-Policy` —
                // only on success; a deleted container's 404 also carries the
                // backend index, but must NOT expose a policy to the client.
                if (200..300).contains(&resp.status) {
                    if let Some(name) = resp
                        .headers
                        .get("X-Backend-Storage-Policy-Index")
                        .and_then(|v| v.parse::<i64>().ok())
                        .and_then(|idx| self.policy_index_to_name.get(&idx))
                    {
                        resp.headers.set("X-Storage-Policy", name);
                    }
                    // Fallback when listing fan-out did not run: sum shard
                    // HEADs (+ residual heuristic).
                    if req.method == "HEAD" {
                        self.patch_sharded_head_counts(
                            req,
                            account,
                            container,
                            &mut resp,
                        );
                    }
                }
                resp
            }
            "PUT" | "POST" | "DELETE" => {
                // account existence / autocreate
                let Ok((account_part, _)) = self.account_ring.get_nodes(account, None, None)
                else {
                    return swob_response(503);
                };
                // Python resolves account existence via the cached
                // get_account_info (container.py:655-656,702-703,717-718 →
                // base.py:540-612): serve the cached HEAD status when fresh,
                // else do the live HEAD and cache it with set_info_cache
                // semantics. An unreachable ring (None → 503) is never
                // cached, like Python's synthesized 503 info.
                let acct_status = self.account_info(account).status;
                if acct_status == 404 {
                    if self.config.account_autocreate && req.method != "DELETE" {
                        self.autocreate_account(account);
                    } else {
                        return swob_response(404);
                    }
                }

                let mut base = self.backend_headers(req, true, "container");
                base.set("X-Timestamp", Timestamp::now().internal());
                if req.method == "PUT" {
                    base.set(
                        "X-Backend-Storage-Policy-Default",
                        self.config.default_policy_index,
                    );
                    // Resolve a client-supplied `X-Storage-Policy: <name>` to a
                    // backend policy index so the container is created on the
                    // right policy (e.g. an EC policy). An empty value means
                    // "unspecified" (default policy); an unknown name -> 400.
                    if let Some(name) = req.headers.get("X-Storage-Policy") {
                        if !name.trim().is_empty() {
                            match self.policy_name_to_index.get(&name.to_lowercase()) {
                                Some(&idx) => base.set("X-Backend-Storage-Policy-Index", idx),
                                None => return swob_response(400),
                            }
                        }
                    }
                }
                // distribute account nodes across the container backend
                // requests (the account-update side channel). Fan-out is sized
                // to the container replica count (get_part_nodes), NOT the full
                // primaries+handoffs node iterator — otherwise quorum is
                // computed over 2R nodes and healthy primaries can fail to
                // reach it (503 where Python 201). Handoffs are still used as
                // fallback via the node iterator inside make_requests.
                let account_nodes = self.iter_nodes(&self.account_ring, account_part);
                let node_number = self
                    .container_ring
                    .get_part_nodes(container_part)
                    .map(|n| n.len())
                    .unwrap_or(1);
                let mut per_node = Vec::with_capacity(node_number);
                for i in 0..node_number {
                    let mut headers = base.clone();
                    if matches!(req.method.as_str(), "PUT" | "DELETE")
                        && !account_nodes.is_empty()
                    {
                        let acct = &account_nodes[i % account_nodes.len()];
                        headers.set(
                            "X-Account-Host",
                            format!("{}:{}", acct.ip, acct.port),
                        );
                        headers.set("X-Account-Partition", account_part);
                        headers.set("X-Account-Device", &acct.device);
                    }
                    per_node.push(headers);
                }
                let cont_nodes = self.iter_nodes(&self.container_ring, container_part);
                // _clear_container_info_cache: POST and DELETE clear the
                // cached container info BEFORE the backend fan-out
                // (container.py:707-708,725-726); PUT clears AFTER
                // (container.py:679-683). Either way the next object
                // request re-HEADs and sees the post-write state.
                let cache_key = format!("{account}/{container}");
                if req.method != "PUT" {
                    self.info_cache.clear_container(&cache_key);
                }
                let resp = self.make_requests(
                    cont_nodes,
                    node_number,
                    container_part,
                    &req.method,
                    &path,
                    &req.query_string,
                    per_node,
                    Vec::new(),
                );
                if req.method == "PUT" {
                    self.info_cache.clear_container(&cache_key);
                }
                resp
            }
            _ => swob_response(405),
        }
    }

    /// `get_container_info`-lite (base.py:430-538): the container's
    /// storage-policy index plus its read/write ACLs and Temp-URL keys.
    /// Served from the in-process info cache when fresh; a miss does a live
    /// HEAD to the container ring and populates the cache with
    /// `set_info_cache` semantics (base.py:672-694): 2xx for
    /// `recheck_container_existence` seconds, 404 — the negative result,
    /// resolving to the default policy and no ACLs — for a tenth of that,
    /// other errors and an unreachable ring (Python's synthesized 503 info)
    /// never cached. `read_acl`/`write_acl` are `None` when the container
    /// has none or is unreachable; the policy falls back to the default.
    fn container_info(&self, account: &str, container: &str) -> ContainerInfo {
        let cache_key = format!("{account}/{container}");
        if let Some(info) = self.info_cache.get_container(&cache_key) {
            return info;
        }
        let mut info = ContainerInfo {
            status: 0,
            policy_index: self.config.default_policy_index,
            read_acl: None,
            write_acl: None,
            temp_url_keys: Vec::new(),
            sync_key: None,
        };
        let Ok((part, _)) = self.container_ring.get_nodes(account, Some(container), None) else {
            return info;
        };
        let path = format!("/{}/{}", percent_encode(account), percent_encode(container));
        let nodes = self.iter_nodes(&self.container_ring, part);
        let headers = HeaderKeyDict::new();
        if let Some(resp) = self.get_or_head("container", nodes, part, "HEAD", &path, "", &headers) {
            info.status = resp.status;
            if let Some(idx) = resp
                .headers
                .get("X-Backend-Storage-Policy-Index")
                .and_then(|v| v.parse().ok())
            {
                info.policy_index = idx;
            }
            info.read_acl = resp.headers.get("X-Container-Read").map(str::to_string);
            info.write_acl = resp.headers.get("X-Container-Write").map(str::to_string);
            info.temp_url_keys = temp_url_keys_from_headers(&resp.headers, "container");
            info.sync_key = resp
                .headers
                .get("X-Container-Sync-Key")
                .filter(|s| !s.is_empty())
                .map(str::to_string);
            if let Some(ttl) = info_cache_time(
                resp.status,
                resp.headers.get("X-Backend-Recheck-Container-Existence"),
                self.config.recheck_container_existence,
            ) {
                self.info_cache.set_container(cache_key, info.clone(), ttl);
            }
        }
        info
    }

    /// Container-sync user key for inbound realm HMAC validation.
    pub fn container_sync_key(&self, account: &str, container: &str) -> Option<String> {
        self.container_info(account, container).sync_key
    }

    /// For a sharded root HEAD: sum live `X-Container-Object-Count` /
    /// `X-Container-Bytes-Used` from listing-state shard containers and
    /// overwrite the (often stale) root totals. No-op when not sharded or
    /// no listing ranges are available.
    fn patch_sharded_head_counts(
        self: &Arc<Self>,
        req: &Request,
        account: &str,
        container: &str,
        resp: &mut Response,
    ) {
        let state = resp
            .headers
            .get("X-Backend-Sharding-State")
            .unwrap_or("unsharded")
            .to_ascii_lowercase();
        if state != "sharding" && state != "sharded" {
            return;
        }
        let Ok((part, _)) = self.container_ring.get_nodes(account, Some(container), None) else {
            return;
        };
        let path = format!(
            "/{}/{}",
            percent_encode(account),
            percent_encode(container)
        );
        let nodes = self.iter_nodes(&self.container_ring, part);
        let mut shard_headers = self.backend_headers(req, false, "container");
        shard_headers.set("X-Backend-Record-Type", "shard");
        shard_headers.set("X-Backend-Allow-Reserved-Names", "true");
        let Some(arr) =
            self.fetch_listing_shard_ranges(nodes.clone(), part, &path, &shard_headers)
        else {
            return;
        };
        if arr.is_empty() {
            return;
        }
        let mut total_count: i64 = 0;
        let mut total_bytes: i64 = 0;
        let mut saw_shard = false;
        for sr in &arr {
            // Skip soft-deleted / SHRUNK donors so we do not double-count
            // during shrink (objects already live on the acceptor).
            let st = sr.get("state").and_then(|v| v.as_i64()).unwrap_or(0);
            let deleted = sr
                .get("deleted")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            if st == 80 || deleted != 0 {
                // SHRUNK or soft-deleted
                continue;
            }
            let name = sr.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let (shard_account, shard_container) = match name.split_once('/') {
                Some((a, c)) => (a, c),
                None => continue,
            };
            let Ok((spart, _)) =
                self.container_ring
                    .get_nodes(shard_account, Some(shard_container), None)
            else {
                continue;
            };
            let spath = format!(
                "/{}/{}",
                percent_encode(shard_account),
                percent_encode(shard_container)
            );
            let snodes = self.iter_nodes(&self.container_ring, spart);
            let mut headers = self.backend_headers(req, false, "container");
            headers.set("X-Backend-Allow-Reserved-Names", "true");
            let Some(head) =
                self.get_or_head("container", snodes, spart, "HEAD", &spath, "", &headers)
            else {
                continue;
            };
            if !(200..300).contains(&head.status) {
                continue;
            }
            saw_shard = true;
            total_count += head
                .headers
                .get("X-Container-Object-Count")
                .and_then(|v| v.parse::<i64>().ok())
                .unwrap_or(0);
            total_bytes += head
                .headers
                .get("X-Container-Bytes-Used")
                .and_then(|v| v.parse::<i64>().ok())
                .unwrap_or(0);
        }
        // Residual root rows (same condition as listing fan-out): when the
        // root still reports object_count > 0, GET listing merges those rows
        // (name-deduped against shards). For HEAD we cannot cheaply dedupe
        // without names from every shard; approximate by adding residual
        // count only when shard_sum is 0 (pure residual) or when residual
        // fetch returns rows and we use max(shard_sum, residual) as a floor
        // when residual alone is larger (rare). Prefer: add residual when
        // non-empty and track via name set from residual only if shard_sum
        // already covers live shards — residual names are typically
        // post-cleave leftovers not yet removed from root.
        let root_oc = resp
            .headers
            .get("X-Container-Object-Count")
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(0);
        if root_oc > 0 {
            let mut root_headers = self.backend_headers(req, false, "container");
            root_headers.set("X-Backend-Record-Type", "object");
            if let Some(items) = self.fetch_shard_object_listing_first_nonempty(
                &nodes,
                part,
                &path,
                "format=json&limit=10000",
                &root_headers,
            ) {
                if !items.is_empty() {
                    // Name-dedupe residual against would-be double count: if
                    // shard_sum already reflects live data, residual rows
                    // that still sit on root after cleave are *extra* only
                    // when not moved. Listing dedupes by name; we add residual
                    // count when it is the only signal (shard_sum==0), else
                    // take max(shard_sum, residual) to avoid under-count
                    // without full name merge (cheap HEAD path).
                    let residual = items.len() as i64;
                    let residual_bytes: i64 = items
                        .iter()
                        .filter_map(|o| o.get("bytes").and_then(|v| v.as_i64()))
                        .sum();
                    if total_count == 0 {
                        total_count = residual;
                        total_bytes = residual_bytes;
                    } else if residual > total_count {
                        // Residual listing longer than shard sum — use it as
                        // the more complete signal ( Contabo partial cleave ).
                        total_count = residual;
                        total_bytes = residual_bytes;
                    }
                    // else keep shard_sum (typical sharded case; residual is
                    // stale root rows also present on shards — list dedupes).
                    saw_shard = true;
                }
            }
        }
        if saw_shard {
            resp.headers
                .set("X-Container-Object-Count", total_count.to_string());
            resp.headers
                .set("X-Container-Bytes-Used", total_bytes.to_string());
        }
    }

    /// Wave 3: fan out object listings across listing-state shard ranges and
    /// merge JSON arrays.
    ///
    /// Fans out when HEAD reports sharding/sharded **or** when the root still
    /// looks unsharded but has object_count=0 and non-empty listing/CLEAVED
    /// shard ranges (partial L3b cleave: Contabo often keeps DB state
    /// `unsharded` after ranges exist). Returns `None` when not applicable
    /// (caller falls back to the single-hop path).
    fn maybe_sharded_container_listing(
        self: &Arc<Self>,
        req: &Request,
        account: &str,
        container: &str,
    ) -> Option<Response> {
        let Ok((part, _)) = self.container_ring.get_nodes(account, Some(container), None) else {
            return None;
        };
        let path = format!(
            "/{}/{}",
            percent_encode(account),
            percent_encode(container)
        );
        let nodes = self.iter_nodes(&self.container_ring, part);
        // Probe HEAD for sharding state + object count. Use backend_headers so
        // internal requests carry the same baseline as other container hops
        // (User-Agent / X-Trans-Id); gatekeeper strips client X-Backend-*.
        let head_headers = self.backend_headers(req, false, "container");
        let head = self.get_or_head(
            "container",
            nodes.clone(),
            part,
            "HEAD",
            &path,
            "",
            &head_headers,
        )?;
        if !(200..300).contains(&head.status) {
            return None;
        }
        let state = head
            .headers
            .get("X-Backend-Sharding-State")
            .unwrap_or("unsharded")
            .to_ascii_lowercase();
        let object_count = head
            .headers
            .get("X-Container-Object-Count")
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(0);
        // May still probe ranges when unsharded + empty root (partial cleave).
        if !should_probe_sharded_listing(&state, object_count) {
            return None;
        }
        // Fetch shard ranges. Prefer SHARD_LISTING_STATES via states=listing
        // (ACTIVE/CLEAVED/SHARDING/SHRINKING). If empty, retry without state
        // filter then keep only listing-state rows client-side.
        //
        // Walk primaries until a non-empty listing-state set appears: a replica
        // that still has only FOUND/CREATED ranges answers 200 with `[]` for
        // `states=listing`, and get_or_head first-wins would short-circuit
        // fan-out on that empty body even when another primary is CLEAVED.
        let mut shard_headers = self.backend_headers(req, false, "container");
        shard_headers.set("X-Backend-Record-Type", "shard");
        // Allow reserved `.shards_*` accounts on the subsequent fan-out GETs.
        shard_headers.set("X-Backend-Allow-Reserved-Names", "true");
        let arr = self.fetch_listing_shard_ranges(nodes.clone(), part, &path, &shard_headers)?;
        // Unsharded/collapsed path only fans out when ranges actually exist
        // (partial cleave with CLEAVED ranges + empty root).
        if !should_fanout_sharded_listing(&state, object_count, !arr.is_empty()) {
            return None;
        }
        // Parse client listing knobs.
        let marker = req.param("marker").unwrap_or_default();
        let prefix = req.param("prefix").unwrap_or_default();
        let limit: usize = req
            .param("limit")
            .and_then(|v| v.parse().ok())
            .unwrap_or(10000);
        let selected = select_listing_shard_ranges(&arr, &marker, &prefix);
        let mut shard_listings: Vec<Vec<serde_json::Value>> = Vec::new();
        // Include residual root rows (misplaced / pre-redirect writes) when
        // the root still reports object_count > 0 after cleave.
        if object_count > 0 {
            let mut root_headers = self.backend_headers(req, false, "container");
            root_headers.set("X-Backend-Record-Type", "object");
            let mut qs_parts = vec!["format=json".to_string()];
            if !marker.is_empty() {
                qs_parts.push(format!("marker={}", percent_encode(&marker)));
            }
            if !prefix.is_empty() {
                qs_parts.push(format!("prefix={}", percent_encode(&prefix)));
            }
            qs_parts.push(format!("limit={limit}"));
            if let Some(items) = self.fetch_shard_object_listing_first_nonempty(
                &nodes,
                part,
                &path,
                &qs_parts.join("&"),
                &root_headers,
            ) {
                if !items.is_empty() {
                    shard_listings.push(items);
                }
            }
        }
        for sr in &selected {
            let name = sr.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let (shard_account, shard_container) = match name.split_once('/') {
                Some((a, c)) => (a, c),
                None => continue,
            };
            let Ok((spart, _)) =
                self.container_ring
                    .get_nodes(shard_account, Some(shard_container), None)
            else {
                continue;
            };
            let spath = format!(
                "/{}/{}",
                percent_encode(shard_account),
                percent_encode(shard_container)
            );
            let snodes = self.iter_nodes(&self.container_ring, spart);
            let remaining = limit.saturating_sub(
                shard_listings.iter().map(|v| v.len()).sum::<usize>(),
            );
            if remaining == 0 {
                break;
            }
            let mut qs_parts = vec!["format=json".to_string()];
            if !marker.is_empty() {
                qs_parts.push(format!("marker={}", percent_encode(&marker)));
            }
            if !prefix.is_empty() {
                qs_parts.push(format!("prefix={}", percent_encode(&prefix)));
            }
            qs_parts.push(format!("limit={remaining}"));
            let mut headers = self.backend_headers(req, false, "container");
            // Shard containers live under the reserved `.shards_*` account.
            headers.set("X-Backend-Allow-Reserved-Names", "true");
            // Walk primaries until a non-empty object listing is found —
            // same lagging-replica empty-`[]` trap as range fetch.
            let Some(items) = self.fetch_shard_object_listing_first_nonempty(
                &snodes,
                spart,
                &spath,
                &qs_parts.join("&"),
                &headers,
            ) else {
                continue;
            };
            if !items.is_empty() {
                shard_listings.push(items);
            }
        }
        let merged = merge_sharded_object_listings(&shard_listings, limit);
        let bytes = serde_json::to_vec(&merged).unwrap_or_else(|_| b"[]".to_vec());
        let mut out = Response::with_body(200, bytes);
        out.headers.set("Content-Type", "application/json; charset=utf-8");
        out.headers.set("X-Backend-Sharding-State", state);
        out.headers.set("X-Backend-Record-Type", "object");
        // Root object_count is often 0 after cleave; report the merged listing
        // length so clients see a coherent count for this response page.
        out.headers
            .set("X-Container-Object-Count", merged.len().to_string());
        if let Some(bytes_used) = head.headers.get("X-Container-Bytes-Used") {
            out.headers.set("X-Container-Bytes-Used", bytes_used);
        }
        if let Some(name) = head
            .headers
            .get("X-Backend-Storage-Policy-Index")
            .and_then(|v| v.parse::<i64>().ok())
            .and_then(|idx| self.policy_index_to_name.get(&idx))
        {
            out.headers.set("X-Storage-Policy", name);
        }
        Some(out)
    }

    /// Resolve the container that should receive the object update for a
    /// possibly-sharded root (Python `BaseObjectController._get_update_target`).
    /// Returns `None` when the root is unsharded or no matching range exists.
    fn resolve_updating_shard(
        &self,
        account: &str,
        container: &str,
        object: &str,
    ) -> Option<(String, String)> {
        let Ok((part, _)) = self.container_ring.get_nodes(account, Some(container), None) else {
            return None;
        };
        let path = format!(
            "/{}/{}",
            percent_encode(account),
            percent_encode(container)
        );
        let nodes = self.iter_nodes(&self.container_ring, part);
        let head_headers = HeaderKeyDict::new();
        let head = self.get_or_head(
            "container",
            nodes.clone(),
            part,
            "HEAD",
            &path,
            "",
            &head_headers,
        )?;
        if !(200..300).contains(&head.status) {
            return None;
        }
        let state = head
            .headers
            .get("X-Backend-Sharding-State")
            .unwrap_or("unsharded")
            .to_ascii_lowercase();
        if state != "sharding" && state != "sharded" {
            return None;
        }
        let mut shard_headers = HeaderKeyDict::new();
        shard_headers.set("X-Backend-Record-Type", "shard");
        // Prefer updating states (CREATED/CLEAVED/ACTIVE/SHARDING); fall back
        // to listing states then any non-empty ranges.
        let arr = self
            .fetch_shard_ranges_first_nonempty(
                &nodes,
                part,
                &path,
                "states=updating&format=json",
                &shard_headers,
            )
            .filter(|a| !a.is_empty())
            .or_else(|| {
                self.fetch_listing_shard_ranges(nodes, part, &path, &shard_headers)
            })?;
        // Pick the range that owns `object` (lower < name <= upper; empty bounds
        // are open-ended). Prefer non-own (shard) names.
        let mut best: Option<&serde_json::Value> = None;
        for sr in &arr {
            let name = sr.get("name").and_then(|v| v.as_str()).unwrap_or("");
            if !name.contains('/') {
                continue;
            }
            // Skip the root's own range (same account/container).
            if name == format!("{account}/{container}") {
                continue;
            }
            let lower = sr.get("lower").and_then(|v| v.as_str()).unwrap_or("");
            let upper = sr.get("upper").and_then(|v| v.as_str()).unwrap_or("");
            if !lower.is_empty() && object <= lower {
                continue;
            }
            if !upper.is_empty() && object > upper {
                continue;
            }
            best = Some(sr);
            break;
        }
        let name = best?.get("name")?.as_str()?;
        let (a, c) = name.split_once('/')?;
        Some((a.to_string(), c.to_string()))
    }

    /// GET root container shard ranges for listing fan-out.
    ///
    /// Prefer `states=listing` (ACTIVE/CLEAVED/SHARDING/SHRINKING). Walk every
    /// primary (and handoff) until a non-empty listing-state set is found —
    /// do **not** first-win on an empty `[]` from a lagging replica.
    /// If all listing-state GETs are empty, retry without a state filter and
    /// keep listing-state rows client-side (or fall back to any ranges).
    fn fetch_listing_shard_ranges(
        &self,
        nodes: Vec<Node>,
        part: u32,
        path: &str,
        shard_headers: &HeaderKeyDict,
    ) -> Option<Vec<serde_json::Value>> {
        // 1) Prefer non-empty states=listing from any primary.
        if let Some(arr) = self.fetch_shard_ranges_first_nonempty(
            &nodes,
            part,
            path,
            "states=listing&format=json",
            shard_headers,
        ) {
            if !arr.is_empty() {
                return Some(arr);
            }
        }
        // 2) Broader: no state filter; prefer listing-state rows, else all.
        let broad = self.fetch_shard_ranges_first_nonempty(
            &nodes,
            part,
            path,
            "format=json",
            shard_headers,
        )?;
        Some(prefer_listing_state_ranges(&broad))
    }

    /// GET shard-range JSON from backends until a 2xx body parses as a
    /// non-empty array (or all nodes are exhausted — then return the last
    /// empty array / None).
    fn fetch_shard_ranges_first_nonempty(
        &self,
        nodes: &[Node],
        part: u32,
        path: &str,
        query: &str,
        shard_headers: &HeaderKeyDict,
    ) -> Option<Vec<serde_json::Value>> {
        self.fetch_json_array_first_nonempty(nodes, part, path, query, shard_headers)
    }

    /// GET shard **object** listing JSON, walking nodes until non-empty.
    fn fetch_shard_object_listing_first_nonempty(
        &self,
        nodes: &[Node],
        part: u32,
        path: &str,
        query: &str,
        headers: &HeaderKeyDict,
    ) -> Option<Vec<serde_json::Value>> {
        self.fetch_json_array_first_nonempty(nodes, part, path, query, headers)
    }

    /// Shared walk: first 2xx JSON array that is non-empty wins; if every
    /// good response is `[]`, return that empty array; if none parse, None.
    fn fetch_json_array_first_nonempty(
        &self,
        nodes: &[Node],
        part: u32,
        path: &str,
        query: &str,
        headers: &HeaderKeyDict,
    ) -> Option<Vec<serde_json::Value>> {
        let mut last_empty: Option<Vec<serde_json::Value>> = None;
        for node in nodes {
            let Some(resp) = self.get_or_head(
                "container",
                vec![node.clone()],
                part,
                "GET",
                path,
                query,
                headers,
            ) else {
                continue;
            };
            if !(200..300).contains(&resp.status) {
                continue;
            }
            let body = match resp.body.into_vec(16 * 1024 * 1024) {
                Ok(b) => b,
                Err(_) => continue,
            };
            let val: serde_json::Value = match serde_json::from_slice(&body) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let arr = val.as_array().cloned().unwrap_or_default();
            if !arr.is_empty() {
                return Some(arr);
            }
            last_empty = Some(arr);
        }
        last_empty
    }

    /// `get_account_info`-lite: status, account ACL sysmeta, Temp-URL keys.
    fn account_info(&self, account: &str) -> AccountInfo {
        if let Some(info) = self.info_cache.get_account(account) {
            return info;
        }
        let mut info = AccountInfo::default();
        let Ok((part, _)) = self.account_ring.get_nodes(account, None, None) else {
            info.status = 503;
            return info;
        };
        let path = format!("/{}", percent_encode(account));
        let nodes = self.iter_nodes(&self.account_ring, part);
        let headers = HeaderKeyDict::new();
        if let Some(resp) = self.get_or_head("account", nodes, part, "HEAD", &path, "", &headers)
        {
            info = account_info_from_response(&resp);
            if let Some(ttl) = info_cache_time(
                resp.status,
                resp.headers.get("X-Backend-Recheck-Account-Existence"),
                self.config.recheck_account_existence,
            ) {
                self.info_cache
                    .set_account(account.to_string(), info.clone(), ttl);
            }
        } else {
            info.status = 503;
        }
        info
    }

    /// Parsed TempAuth account ACLs from the account HEAD sysmeta.
    fn account_acls(&self, account: &str) -> Option<swift_middleware::AccountAcls> {
        let info = self.account_info(account);
        swift_middleware::acls_from_sysmeta(info.core_access_control.as_deref())
    }

    /// Temp-URL keys for `account` + optional `container` (account keys
    /// first, then container keys), matching Python `_get_keys` order.
    ///
    /// Uses the shared info cache (L1 + memcache L2). Account/container POST
    /// clears the cache key on every proxy's L2, so a key set via VIP on one
    /// backend is visible to TempURL validation on another without waiting
    /// for a stale per-process TTL.
    pub fn temp_url_keys(&self, account: &str, container: &str) -> Vec<String> {
        let mut keys = self.account_info(account).temp_url_keys;
        if !container.is_empty() {
            keys.extend(self.container_info(account, container).temp_url_keys);
        }
        keys
    }

    /// `get_container_info`-lite: the container's storage-policy index only.
    fn container_policy_index(&self, account: &str, container: &str) -> i64 {
        self.container_info(account, container).policy_index
    }

    /// Authorize + prepare account ACL header (Python `swift.authorize` +
    /// TempAuth `extract_acl_and_report_errors`). Returns `Some(denial)` or
    /// `None` (allowed / auth disabled). On success, stamps
    /// `X-Backend-Swift-Owner` when the caller is a swift_owner.
    fn authorize(
        self: &Arc<Self>,
        req: &mut Request,
        account: &str,
        container: Option<&str>,
        object: Option<&str>,
    ) -> Option<Response> {
        // TempURL (etc.) stamped authorize_override after a valid signature.
        if req
            .headers
            .get("X-Backend-Authorize-Override")
            .map(config_true_value)
            .unwrap_or(false)
        {
            // TempURL is deliberately not a Swift owner: privileged response
            // metadata must still be stripped on the way back out.
            req.headers.remove("X-Backend-Swift-Owner");
            return None;
        }
        if !self.config.auth_enabled {
            return None;
        }

        // Validate / rewrite X-Account-Access-Control → sysmeta before the
        // backend write (TempAuth.extract_acl_and_report_errors).
        if req.headers.contains_key("X-Account-Access-Control") {
            match swift_middleware::validate_account_acl_header(
                req.headers.get("X-Account-Access-Control"),
            ) {
                Ok(Some(sysmeta)) => {
                    req.headers.remove("X-Account-Access-Control");
                    req.headers
                        .set("X-Account-Sysmeta-Core-Access-Control", sysmeta);
                }
                Ok(None) => {}
                Err(msg) => {
                    let body = format!(
                        "X-Account-Access-Control invalid: {msg}\n\nInput: {}\n",
                        req.headers
                            .get("X-Account-Access-Control")
                            .unwrap_or("")
                    );
                    let mut resp = Response::with_body(400, body);
                    resp.headers
                        .set("Content-Type", "text/plain; charset=UTF-8");
                    return Some(resp);
                }
            }
        }

        // Legacy container-sync (Python tempauth/keystoneauth): if the
        // destination container's sync_key matches X-Container-Sync-Key and
        // the request carries a timestamp, allow without a user token.
        // Gatekeeper shunts client `X-Timestamp` → `X-Backend-Inbound-X-Timestamp`
        // before we run, so accept either form (realm middleware restores too).
        if let Some(c) = container {
            if let Some(req_key) = req.headers.get("x-container-sync-key") {
                let has_ts = req.headers.get("x-timestamp").is_some()
                    || req
                        .headers
                        .get("x-backend-inbound-x-timestamp")
                        .is_some();
                if !req_key.is_empty() && has_ts {
                    let info = self.container_info(account, c);
                    if let Some(sk) = info.sync_key.as_deref() {
                        if !sk.is_empty() && sk == req_key {
                            // Restore timestamp for object servers (Python
                            // container_sync / obj controller expectation).
                            if req.headers.get("x-timestamp").is_none() {
                                if let Some(ts) =
                                    req.headers.get("x-backend-inbound-x-timestamp")
                                {
                                    let ts = ts.to_string();
                                    req.headers.remove("X-Backend-Inbound-X-Timestamp");
                                    req.headers.set("X-Timestamp", ts);
                                }
                            }
                            req.headers.remove("X-Backend-Swift-Owner");
                            return None;
                        }
                    }
                }
            }
        }

        // The relevant ACL: object/container reads use read_acl, object writes
        // use write_acl; account requests and container writes are owner-only.
        let acl: Option<String> = match container {
            Some(c) if object.is_some() || matches!(req.method.as_str(), "GET" | "HEAD") => {
                let info = self.container_info(account, c);
                if matches!(req.method.as_str(), "GET" | "HEAD") {
                    info.read_acl
                } else {
                    info.write_acl
                }
            }
            _ => None,
        };

        // Keystone path (P3-auth): keystoneauth stamped Auth-Plugin.
        let keystone_plugin = req
            .headers
            .get(swift_middleware::AUTH_PLUGIN_HEADER)
            .map(|v| v.eq_ignore_ascii_case(swift_middleware::AUTH_PLUGIN_KEYSTONE))
            .unwrap_or(false);
        if keystone_plugin {
            if let Some(ka) = &self.config.keystone_auth {
                let (denied, swift_owner) = ka.authorize_request(
                    req,
                    account,
                    container,
                    object,
                    acl.as_deref(),
                    req.headers.get("Referer"),
                );
                if denied.is_none() {
                    if swift_owner {
                        req.headers.set("X-Backend-Swift-Owner", "true");
                    } else {
                        req.headers.remove("X-Backend-Swift-Owner");
                    }
                }
                return denied;
            }
        }

        let groups: Vec<String> = req
            .headers
            .get("X-Backend-Remote-User")
            .unwrap_or("")
            .split(',')
            .filter(|g| !g.is_empty())
            .map(str::to_string)
            .collect();
        let account_acls = self.account_acls(account);
        let mut swift_owner = false;
        let denied = swift_middleware::TempAuth::authorize_acl(
            &req.method,
            &req.path,
            &groups,
            acl.as_deref(),
            req.headers.get("Referer"),
            "AUTH_",
            account_acls.as_ref(),
            &mut swift_owner,
        );
        if denied.is_none() {
            if swift_owner {
                req.headers.set("X-Backend-Swift-Owner", "true");
            } else {
                req.headers.remove("X-Backend-Swift-Owner");
            }
        }
        denied
    }

    fn object_request(
        self: &Arc<Self>,
        req: &mut Request,
        account: &str,
        container: &str,
        object: &str,
    ) -> Response {
        // The object's storage policy comes from the container. Clients can't
        // set X-Backend-Storage-Policy-Index (gatekeeper strips it), so when
        // it's absent we look the container's policy up with a HEAD.
        let header_policy: Option<i64> = req
            .headers
            .get("X-Backend-Storage-Policy-Index")
            .and_then(|v| v.parse().ok());
        // Writes need the container to exist (obj.py:469/995/1050 — POST,
        // PUT and DELETE all 404 when the container HEAD isn't a success);
        // our caller has already run swift.authorize, matching Python's
        // order. Reads skip the check and go straight to the object servers.
        let policy_index: i64 = if matches!(req.method.as_str(), "PUT" | "POST" | "DELETE") {
            let info = self.container_info(account, container);
            if !info.exists() {
                return swob_response(404);
            }
            header_policy.unwrap_or(info.policy_index)
        } else {
            header_policy.unwrap_or_else(|| self.container_policy_index(account, container))
        };
        let Some(object_ring) = self.object_ring_for(policy_index) else {
            return text_response(
                503,
                &format!("No object ring configured for storage policy {policy_index}"),
            );
        };
        let Ok((object_part, _)) =
            object_ring.get_nodes(account, Some(container), Some(object))
        else {
            return swob_response(503);
        };
        let path = format!(
            "/{}/{}/{}",
            percent_encode(account),
            percent_encode(container),
            percent_encode(object)
        );
        // Erasure-coding policies split object data into fragments: PUT encodes
        // and fans a distinct fragment archive to each node; GET/HEAD gather
        // `ndata` fragments and decode. POST (metadata) and DELETE (tombstone)
        // carry no object data, so they take the replication fan-out unchanged.
        if let Some(&ec) = self.ec_policies.get(&policy_index) {
            match req.method.as_str() {
                "PUT" => {
                    return self.ec_put(
                        req,
                        account,
                        container,
                        &path,
                        policy_index,
                        object_ring,
                        object_part,
                        ec,
                    )
                }
                "GET" | "HEAD" => {
                    return self.ec_get(req, &path, policy_index, object_ring, object_part, ec);
                }
                _ => {}
            }
        }
        match req.method.as_str() {
            "GET" | "HEAD" => {
                let mut headers = self.backend_headers(req, false, "object");
                // Always tell the backend which policy's datadir to serve —
                // without this, non-default-policy objects 404 (the object
                // server would default to policy 0's objects/ tree).
                headers.set("X-Backend-Storage-Policy-Index", policy_index);
                // Read headers the object server evaluates itself: Range (206
                // slicing) and the conditional set. (The EC path deliberately
                // does NOT forward Range — fragments must be fetched whole.)
                for h in [
                    "Range",
                    "If-Match",
                    "If-None-Match",
                    "If-Modified-Since",
                    "If-Unmodified-Since",
                    "X-Newest",
                    // Recoverable-ghost reads: object server opens past
                    // X-Delete-At when this is true (see DiskFile::with_open_expired).
                    "X-Open-Expired",
                    // set by DLO/SLO (below gatekeeper, so client-supplied
                    // copies are stripped): the object server drops the Range
                    // when the object carries the named manifest metadata.
                    "X-Backend-Ignore-Range-If-Metadata-Present",
                ] {
                    if let Some(v) = req.headers.get(h) {
                        headers.set(h, v.to_string());
                    }
                }
                let nodes = self.iter_nodes(object_ring, object_part);
                self.get_or_head(
                    "object",
                    nodes,
                    object_part,
                    &req.method,
                    &path,
                    &req.query_string,
                    &headers,
                )
                .unwrap_or_else(|| swob_response(503))
            }
            "PUT" | "POST" | "DELETE" => {
                // Enforce the metadata constraints (name/value length, count,
                // overall size) on writes, as Python's proxy does via
                // check_metadata — the object server does not, so without this
                // an oversized X-Object-Meta-* value was silently stored (202).
                if req.method != "DELETE" {
                    if let Err(e) =
                        swift_core::constraints::check_metadata(req.headers.iter(), "object")
                    {
                        let mut r = Response::with_body(400, e.0);
                        r.headers.set("Content-Type", "text/html; charset=UTF-8");
                        return r;
                    }
                }
                // Container-update target: root by default; when the root is
                // sharding/sharded, the owning updating-state shard range
                // (Python `_get_update_target`).
                let (upd_account, upd_container) = self
                    .resolve_updating_shard(account, container, object)
                    .unwrap_or_else(|| (account.to_string(), container.to_string()));
                let Ok((container_part, _)) = self.container_ring.get_nodes(
                    &upd_account,
                    Some(&upd_container),
                    None,
                ) else {
                    return swob_response(503);
                };
                let container_nodes = self.iter_nodes(&self.container_ring, container_part);
                let mut base = self.backend_headers(req, true, "object");
                let put_ts = Timestamp::now();
                base.set("X-Timestamp", put_ts.internal());
                // Route the write/tombstone to the right policy datadir (see
                // the GET note above) — an EC DELETE landing in objects/ would
                // 404 and leave the fragments orphaned.
                base.set("X-Backend-Storage-Policy-Index", policy_index);
                if req.method == "PUT" {
                    base.set("Content-Type", req.headers.get("Content-Type").unwrap_or("application/octet-stream"));
                }
                // Tell the object server which container DB to update (shard
                // path differs from the client-visible account/container).
                if upd_account != account || upd_container != container {
                    base.set(
                        "X-Backend-Container-Path",
                        format!("{upd_account}/{upd_container}"),
                    );
                    base.set("X-Backend-Allow-Reserved-Names", "true");
                }
                let node_number = object_ring
                    .get_part_nodes(object_part)
                    .map(|n| n.len())
                    .unwrap_or(1);
                // distribute container nodes across the object backend
                // requests so each object server can drive a container
                // update
                let mut per_node = Vec::with_capacity(node_number);
                for i in 0..node_number {
                    let mut headers = base.clone();
                    if !container_nodes.is_empty() {
                        let cont = &container_nodes[i % container_nodes.len()];
                        headers.set("X-Container-Host", format!("{}:{}", cont.ip, cont.port));
                        headers.set("X-Container-Partition", container_part);
                        headers.set("X-Container-Device", &cont.device);
                    }
                    per_node.push(headers);
                }
                if req.method == "POST" {
                    // Object POST takes its own path with the mixed-result
                    // handoff fallback (obj.py:912-962); PUT/DELETE keep the
                    // generic fan-out below.
                    return self.post_object(
                        object_ring,
                        object_part,
                        &path,
                        &req.query_string,
                        per_node,
                        node_number,
                    );
                }
                let object_nodes = {
                    let _ring =
                        swift_core::stage::StageTimer::start("proxy-server", "put", "ring_lookup");
                    self.iter_nodes(object_ring, object_part)
                };
                if req.method == "PUT" {
                    // The one big-body verb: tee the client stream to the
                    // backends instead of buffering it (5GB PUT used to cost
                    // ~25GB of proxy RSS across the clones).
                    // auth cost sits in middleware before this controller;
                    // fan_out + quorum are the stream_put wall time.
                    let _fan =
                        swift_core::stage::StageTimer::start("proxy-server", "put", "fan_out");
                    let mut resp = self.stream_put_object(
                        object_nodes,
                        node_number,
                        object_part,
                        &path,
                        &req.query_string,
                        per_node,
                        req.body.take(),
                    );
                    drop(_fan);
                    swift_core::stage::observe("proxy-server", "put", "quorum", 0.0);
                    swift_core::stage::observe("proxy-server", "put", "auth", 0.0);
                    // obj.py:_store_object — every PUT answer (201 and 422
                    // alike) carries Last-Modified from the request timestamp.
                    resp.headers.set(
                        "Last-Modified",
                        swift_http::http_date(put_ts.ceil()),
                    );
                    return resp;
                }
                // DELETE carries no body.
                self.make_requests(
                    object_nodes,
                    node_number,
                    object_part,
                    &req.method,
                    &path,
                    &req.query_string,
                    per_node,
                    Vec::new(),
                )
            }
            _ => swob_response(405),
        }
    }

    // ===================== Erasure-coding object controller =====================
    //
    // EC PUT encodes the object into `k + m` fragment archives (byte-identical
    // to Python via `swift-ec`) and fans a distinct archive out to each node,
    // tagged with its fragment index. EC GET/HEAD gathers `ndata` fragments and
    // decodes. The fragment `.data` files the object servers persist are the
    // same `<ts>#<frag_index>#d.data` durable files Python writes, so the two
    // stacks interoperate on disk.

    /// EC PUT, streaming (obj.py `ECObjectController._transfer_data` over
    /// MIME putters): the client body is encoded segment by segment and
    /// each node's per-segment fragments are teed to its connection —
    /// the proxy never holds more than one segment of object data. The
    /// whole-object etag/length travel as MIME footers (they are unknown
    /// until the stream ends), and the fragments turn durable only after
    /// the multiphase commit confirmation.
    #[cfg(feature = "ec")]
    #[allow(clippy::too_many_arguments)]
    fn ec_put(
        self: &Arc<Self>,
        req: &mut Request,
        account: &str,
        container: &str,
        path: &str,
        policy_index: i64,
        object_ring: &Ring,
        object_part: u32,
        ec: EcPolicyParams,
    ) -> Response {
        use swift_ec::EcDriver;
        let driver = match EcDriver::new(ec.ndata, ec.nparity) {
            Ok(d) => d,
            Err(e) => return text_response(500, &format!("EC init failed: {e:?}")),
        };
        let n = ec.n_unique();
        let client_len = req.body.content_length();
        // The per-node declared length is the FRAGMENT ARCHIVE size (the
        // object server verifies its own bytes against it), computable
        // only when the client declared a length.
        let archive_len = client_len.map(|total| ec_archive_size(&driver, ec.segment_size, total));
        let put_ts = Timestamp::now();
        let ts = put_ts.internal();
        let content_type = req
            .headers
            .get("Content-Type")
            .unwrap_or("application/octet-stream")
            .to_string();

        // Primary nodes carry frag index == their position. A fragment keeps its
        // index if it falls through to a handoff.
        let primaries = ring_nodes(object_ring.get_part_nodes(object_part).unwrap_or_default());
        if primaries.len() != n {
            return text_response(
                500,
                &format!(
                    "EC ring replica count {} != k+m {}",
                    primaries.len(),
                    n
                ),
            );
        }
        let handoffs = match object_ring.get_more_nodes(object_part) {
            Ok(more) => more
                .into_iter()
                .map(|h| Node {
                    ip: h.dev.ip.clone(),
                    port: h.dev.port,
                    device: h.dev.device.clone(),
                    handoff: true,
                })
                .collect(),
            Err(_) => Vec::new(),
        };

        // The container-update side channel (each fragment PUT drives one).
        let Ok((container_part, _)) = self.container_ring.get_nodes(account, Some(container), None)
        else {
            return swob_response(503);
        };
        let container_nodes = self.iter_nodes(&self.container_ring, container_part);

        // Whole-object EC sysmeta (etag/length) is NOT in the headers any
        // more — it is unknown until the stream ends and travels in the
        // MIME footers instead (trailing_metadata, obj.py:2195-2221).
        let mut base = self.backend_headers(req, true, "object");
        base.set("X-Timestamp", &ts);
        base.set("Content-Type", &content_type);
        base.set("X-Backend-Storage-Policy-Index", policy_index);
        let mut per_node = Vec::with_capacity(n);
        for i in 0..n {
            let mut h = base.clone();
            if !container_nodes.is_empty() {
                let cont = &container_nodes[i % container_nodes.len()];
                h.set("X-Container-Host", format!("{}:{}", cont.ip, cont.port));
                h.set("X-Container-Partition", container_part);
                h.set("X-Container-Device", &cont.device);
            }
            per_node.push(h);
        }

        // Connect phase: one MIME putter per fragment slot, primaries
        // first, handoffs keeping the slot's fragment index.
        let boundary = {
            // Deterministic 64-hex boundary (no RNG dependency): two md5s
            // over distinct per-request inputs.
            let a = md5_hex(format!("{path}:{ts}:head").as_bytes());
            let b = md5_hex(format!("{path}:{ts}:tail").as_bytes());
            format!("{a}{b}")
        };
        let handoff_pool = Arc::new(Mutex::new(handoffs));
        let (tx, rx) = mpsc::channel();
        for (i, primary) in primaries.into_iter().enumerate() {
            let tx = tx.clone();
            let app = Arc::clone(self);
            let headers = per_node[i].clone();
            let (path, boundary) = (path.to_string(), boundary.clone());
            let handoff_pool = Arc::clone(&handoff_pool);
            std::thread::spawn(move || {
                let mut candidate = Some(primary);
                loop {
                    let node = match candidate.take() {
                        Some(nd) => nd,
                        None => {
                            let mut pool = handoff_pool.lock().unwrap();
                            if pool.is_empty() {
                                return; // slot unfilled -> 503 stub later
                            }
                            pool.remove(0)
                        }
                    };
                    match connect_mime_putter(
                        &node,
                        object_part,
                        &path,
                        &headers,
                        &boundary,
                        archive_len,
                        app.config.conn_timeout,
                        app.config.node_timeout,
                    ) {
                        Ok(MimeConnectOutcome::EarlyFinal(resp)) if resp.status == 507 => {
                            app.error_limiter.limit(&node)
                        }
                        Ok(MimeConnectOutcome::EarlyFinal(resp)) if resp.status >= 500 => {
                            app.error_limiter.increment(&node)
                        }
                        Ok(outcome) => {
                            let _ = tx.send((i, outcome));
                            return;
                        }
                        Err(_) => app.error_limiter.increment(&node),
                    }
                }
            });
        }
        drop(tx);
        let mut putters: Vec<MimePutter> = Vec::new();
        let mut early_finals: Vec<u16> = Vec::new();
        for (i, outcome) in rx.iter() {
            match outcome {
                MimeConnectOutcome::Live(mut p) => {
                    p.frag_index = i;
                    putters.push(p);
                }
                MimeConnectOutcome::EarlyFinal(resp) => early_finals.push(resp.status),
            }
        }
        // obj.py:_check_failure_put_connections: pre-body 412/409 end the
        // request before any data moves.
        if early_finals.contains(&412) {
            return swob_response(412);
        }
        if early_finals.contains(&409) {
            return swob_response(202);
        }
        if putters.len() < ec.write_quorum() {
            return swob_response(503);
        }

        // Stream: buffer the client body to segment_size, encode each
        // full segment, tee fragment i to putter(frag_index == i).
        let (mut reader, _) = req.body.take().into_reader();
        use md5::{Digest, Md5};
        let mut etag_hasher = Md5::new();
        let mut seg_buf: Vec<u8> = Vec::with_capacity(ec.segment_size);
        let mut chunk = vec![0u8; swift_http::STREAM_CHUNK];
        let mut total: u64 = 0;
        let quorum = ec.write_quorum();
        let send_segment =
            |putters: &mut Vec<MimePutter>, segment: &[u8]| -> Result<(), Response> {
                let frags = match driver.encode(segment) {
                    Ok(f) => f,
                    Err(e) => return Err(text_response(500, &format!("EC encode failed: {e:?}"))),
                };
                putters.retain_mut(|p| {
                    let ok = p.send_data_chunk(&frags[p.frag_index]).is_ok();
                    if !ok {
                        self.error_limiter.increment(&p.node);
                    }
                    ok
                });
                if putters.len() < quorum {
                    return Err(swob_response(503));
                }
                Ok(())
            };
        loop {
            let read = match reader.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if swift_http::body_too_large(&e) => return swob_response(413),
                Err(_) => return swob_response(499),
            };
            {
                use md5::Digest;
                etag_hasher.update(&chunk[..read]);
            }
            total += read as u64;
            if total > swift_core::constraints::MAX_FILE_SIZE as u64 {
                return swob_response(413);
            }
            seg_buf.extend_from_slice(&chunk[..read]);
            while seg_buf.len() >= ec.segment_size {
                let rest = seg_buf.split_off(ec.segment_size);
                let segment = std::mem::replace(&mut seg_buf, rest);
                if let Err(resp) = send_segment(&mut putters, &segment) {
                    return resp;
                }
            }
        }
        // Short of the declared length = client disconnect (499).
        if client_len.is_some_and(|declared| declared != total) {
            return swob_response(499);
        }
        if !seg_buf.is_empty() {
            let segment = std::mem::take(&mut seg_buf);
            if let Err(resp) = send_segment(&mut putters, &segment) {
                return resp;
            }
        }
        let ec_etag = {
            use md5::Digest;
            format!("{:x}", etag_hasher.finalize())
        };
        if let Some(client_etag) = req.headers.get("ETag") {
            let norm = client_etag.trim_matches('"');
            if !norm.is_empty() && !norm.eq_ignore_ascii_case(&ec_etag) {
                let mut resp = swob_response(422);
                resp.headers
                    .set("Last-Modified", swift_http::http_date(put_ts.ceil()));
                return resp;
            }
        }

        // Footers (trailing_metadata + the fragment-archive md5 as Etag),
        // then the phase-1 terminator.
        putters.retain_mut(|p| {
            let footers = serde_json::json!({
                "X-Object-Sysmeta-Ec-Etag": ec_etag,
                "X-Object-Sysmeta-Ec-Content-Length": total.to_string(),
                "X-Backend-Container-Update-Override-Etag": ec_etag,
                "X-Backend-Container-Update-Override-Size": total.to_string(),
                "X-Object-Sysmeta-Ec-Frag-Index": p.frag_index.to_string(),
                "X-Object-Sysmeta-Ec-Scheme": format!("{}+{}", ec.ndata, ec.nparity),
                "X-Object-Sysmeta-Ec-Segment-Size": ec.segment_size.to_string(),
                "Etag": p.frag_md5(),
            })
            .to_string();
            let ok = p.end_of_object_data(&footers).is_ok();
            if !ok {
                self.error_limiter.increment(&p.node);
            }
            ok
        });

        // Phase-2 gate: a quorum of second interim responses (each object
        // server has written its fragment non-durably) before committing.
        putters.retain_mut(|p| match p.await_informational() {
            Ok(100) => true,
            _ => {
                self.error_limiter.increment(&p.node);
                false
            }
        });
        if putters.len() < quorum {
            return swob_response(503);
        }
        putters.retain_mut(|p| p.send_commit().is_ok());
        let mut successes = 0usize;
        for p in putters {
            match p.read_final() {
                Ok(resp) if (200..300).contains(&resp.status) => successes += 1,
                Ok(_) => {}
                Err(_) => {}
            }
        }
        if successes >= ec.write_quorum() {
            let mut resp = Response::new(201);
            resp.headers.set("ETag", &ec_etag);
            resp.headers.set("Content-Type", &content_type);
            resp.headers.set("X-Timestamp", &ts);
            resp.headers.set("Content-Length", 0);
            resp.headers
                .set("Last-Modified", swift_http::http_date(put_ts.ceil()));
            resp
        } else {
            swob_response(503)
        }
    }


    /// EC GET/HEAD, streaming: gather `ndata` DISTINCT fragment sources
    /// (headers only — bodies stay on their sockets), then decode segment
    /// by segment as the client reads. Content-Length and ETag come from
    /// the EC sysmeta the fragments carry, not the fragment files. A
    /// mid-stream source failure aborts the client connection (fragment
    /// substitution mid-GET is a non-goal this pass).
    #[cfg(feature = "ec")]
    fn ec_get(
        self: &Arc<Self>,
        req: &Request,
        path: &str,
        policy_index: i64,
        object_ring: &Ring,
        object_part: u32,
        ec: EcPolicyParams,
    ) -> Response {
        use swift_ec::EcDriver;
        let is_head = req.method == "HEAD";
        let mut headers = self.backend_headers(req, false, "object");
        headers.set("X-Backend-Storage-Policy-Index", policy_index);
        if let Some(v) = req.headers.get("X-Open-Expired") {
            headers.set("X-Open-Expired", v.to_string());
        }
        let nodes = self.iter_nodes(object_ring, object_part);

        let (tx, rx) = mpsc::channel();
        for node in nodes {
            let tx = tx.clone();
            let app = Arc::clone(self);
            let headers = headers.clone();
            let path = path.to_string();
            std::thread::spawn(move || {
                let r = backend_request_head(
                    &node,
                    object_part,
                    "GET",
                    &path,
                    "",
                    &headers,
                    b"",
                    app.config.conn_timeout,
                    app.config.node_timeout,
                );
                let _ = tx.send((node, r));
            });
        }
        drop(tx);

        let mut sources: HashMap<i32, (Node, BackendHead)> = HashMap::new();
        let mut meta: Option<Vec<(String, String)>> = None;
        let mut saw_404 = false;
        for (node, r) in rx.iter() {
            match r {
                Ok(head) if head.status == 200 => {
                    let fi = resp_header(&head.headers, "X-Object-Sysmeta-Ec-Frag-Index")
                        .and_then(|v| v.parse::<i32>().ok());
                    if let Some(fi) = fi {
                        if sources.len() >= ec.ndata && !sources.contains_key(&fi) {
                            continue; // enough sources; surplus conns just drop
                        }
                        if meta.is_none() {
                            meta = Some(head.headers.clone());
                        }
                        sources.entry(fi).or_insert((node, head));
                    }
                }
                Ok(head) if head.status == 404 => saw_404 = true,
                Ok(head) if head.status == 507 => self.error_limiter.limit(&node),
                Ok(head) if head.status >= 500 => self.error_limiter.increment(&node),
                Ok(_) => {}
                Err(_) => self.error_limiter.increment(&node),
            }
        }

        if sources.len() < ec.ndata {
            return if saw_404 && sources.is_empty() {
                swob_response(404)
            } else {
                swob_response(503)
            };
        }
        let meta = meta.unwrap_or_default();
        let ec_etag = resp_header(&meta, "X-Object-Sysmeta-Ec-Etag")
            .unwrap_or_default()
            .to_string();
        let orig_size: usize = resp_header(&meta, "X-Object-Sysmeta-Ec-Content-Length")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let content_type = resp_header(&meta, "Content-Type")
            .unwrap_or("application/octet-stream")
            .to_string();

        // Client Range handling. `X-Backend-Ignore-Range-If-Metadata-Present`
        // (SLO/DLO manifests) drops the Range when the fragment sysmeta
        // carries any named key — a manifest is always served whole.
        let ignore_range = req
            .headers
            .get("X-Backend-Ignore-Range-If-Metadata-Present")
            .map(|names| {
                names
                    .split(',')
                    .any(|name| resp_header(&meta, name.trim()).is_some())
            })
            .unwrap_or(false);
        let resolved_ranges = if is_head || ignore_range {
            None
        } else {
            req.headers
                .get("Range")
                .and_then(|h| swift_http::Range::parse(h).ok())
                .and_then(|r| r.ranges_for_length(Some(orig_size as u64)))
        };

        if let Some(ranges) = &resolved_ranges {
            if ranges.is_empty() {
                // Match Python object 416: Content-Range + Accept-Ranges plus
                // the object's identifying headers (etag / last-modified /
                // x-timestamp) and a short explanatory body.
                let body = concat!(
                    "<html><h1>Requested Range Not Satisfiable</h1>",
                    "<p>The Range requested is not available.</p></html>"
                );
                let mut resp = Response::with_body(416, body.as_bytes().to_vec());
                resp.headers
                    .set("Content-Range", format!("bytes */{orig_size}"));
                resp.headers.set("Accept-Ranges", "bytes");
                if let Some(etag) =
                    resp_header(&meta, "ETag").or_else(|| resp_header(&meta, "Etag"))
                {
                    resp.headers.set("Etag", etag.trim_matches('"'));
                }
                if let Some(lm) = resp_header(&meta, "Last-Modified") {
                    resp.headers.set("Last-Modified", lm);
                }
                if let Some(ts) = resp_header(&meta, "X-Timestamp") {
                    resp.headers.set("X-Timestamp", ts);
                }
                return resp;
            }
        }

        let mut resp = if is_head {
            Response::new(200)
        } else if let Some(ranges) = resolved_ranges.as_deref() {
            // Ranged: the discovery streams are whole-archive — drop them
            // and issue segment-aligned ranged fragment fetches to the
            // SAME (frag index, node) pairs.
            let fetch_nodes: Vec<(i32, Node)> = sources
                .iter()
                .map(|(fi, (node, _))| (*fi, node.clone()))
                .take(ec.ndata)
                .collect();
            drop(sources);
            match self.ec_ranged_response(
                &fetch_nodes,
                object_part,
                path,
                &headers,
                ec,
                orig_size,
                &content_type,
                &ec_etag,
                ranges,
            ) {
                Ok(r) => r,
                Err(e) => {
                    return text_response(503, &format!("EC ranged GET failed: {e}"));
                }
            }
        } else {
            let driver = match EcDriver::new(ec.ndata, ec.nparity) {
                Ok(d) => d,
                Err(e) => return text_response(500, &format!("EC init failed: {e:?}")),
            };
            let readers: Vec<LimitedBackendReader> = sources
                .into_values()
                .take(ec.ndata)
                .map(|(_, h)| h.into_limited_reader())
                .collect();
            let decode_reader = EcDecodeReader {
                driver,
                sources: readers,
                seg_sizes: ec_segment_sizes(orig_size, ec.segment_size),
                next_seg: 0,
                pending: Vec::new(),
                pending_pos: 0,
            };
            let mut r = Response::new(200);
            r.body = swift_http::Body::from_reader(Box::new(decode_reader), Some(orig_size as u64));
            r
        };
        // Carry the client-facing metadata across; the fragment's own
        // Content-Length/ETag and the internal EC/backend headers are dropped.
        for (k, v) in &meta {
            let kl = k.to_lowercase();
            let keep = kl == "content-type"
                || kl == "x-timestamp"
                || kl == "last-modified"
                || kl == "x-backend-timestamp"
                || (kl.starts_with("x-object-meta-") && kl.len() > "x-object-meta-".len());
            if keep && !(kl == "content-type" && resp.status == 206 && resp.headers.get("Content-Type").is_some())
            {
                resp.headers.set(k, v);
            }
        }
        if !ec_etag.is_empty() {
            resp.headers.set("ETag", &ec_etag);
        }
        if resp.status != 206 {
            resp.headers.set("Content-Length", orig_size);
        }
        resp.headers.set("Accept-Ranges", "bytes");
        resp
    }

    /// Build the 206 for a ranged EC GET: single range streams directly, a
    /// multi-range response streams multipart/byteranges parts, each part's
    /// fragment fetch opened lazily when the stream reaches it.
    #[cfg(feature = "ec")]
    #[allow(clippy::too_many_arguments)]
    fn ec_ranged_response(
        self: &Arc<Self>,
        fetch_nodes: &[(i32, Node)],
        object_part: u32,
        path: &str,
        backend_headers: &HeaderKeyDict,
        ec: EcPolicyParams,
        orig_size: usize,
        content_type: &str,
        ec_etag: &str,
        ranges: &[(u64, u64)],
    ) -> std::io::Result<Response> {
        if ranges.len() == 1 {
            let (start, stop) = ranges[0];
            let reader = self.ec_fetch_range(
                fetch_nodes,
                object_part,
                path,
                backend_headers,
                ec,
                orig_size,
                start,
                stop,
            )?;
            let mut resp = Response::new(206);
            resp.headers.set(
                "Content-Range",
                swift_http::content_range_header_value(start, stop, orig_size as u64),
            );
            resp.body = swift_http::Body::from_reader(reader, Some(stop - start));
            return Ok(resp);
        }
        // multipart/byteranges, byte-compatible with
        // swift_http::multipart_byteranges' framing.
        let boundary = md5_hex(
            format!("{path}:{orig_size}:{}:{}", ranges.len(), ec_etag).as_bytes(),
        );
        let mut part_heads: Vec<Vec<u8>> = Vec::with_capacity(ranges.len());
        let mut total_len: u64 = 0;
        for &(start, stop) in ranges {
            let head = format!(
                "--{boundary}\r\nContent-Type: {content_type}\r\nContent-Range: {}\r\n\r\n",
                swift_http::content_range_header_value(start, stop, orig_size as u64)
            )
            .into_bytes();
            total_len += head.len() as u64 + (stop - start) + 2; // + \r\n
            part_heads.push(head);
        }
        let terminator = format!("--{boundary}--").into_bytes();
        total_len += terminator.len() as u64;

        let app = Arc::clone(self);
        let fetch_nodes = fetch_nodes.to_vec();
        let path = path.to_string();
        let backend_headers = backend_headers.clone();
        let ranges: Vec<(u64, u64)> = ranges.to_vec();
        let mut next_part = 0usize;
        let mut heads = part_heads.into_iter();
        let mut sent_terminator = false;
        let reader = swift_http::FnReader::new(move || {
            if next_part < ranges.len() {
                let (start, stop) = ranges[next_part];
                let head = heads.next().expect("one head per range");
                next_part += 1;
                let fetched = app.ec_fetch_range(
                    &fetch_nodes,
                    object_part,
                    &path,
                    &backend_headers,
                    ec,
                    orig_size,
                    start,
                    stop,
                );
                return Some(fetched.map(|body| {
                    Box::new(swift_http::ChainReader::new(vec![
                        Box::new(std::io::Cursor::new(head)),
                        body,
                        Box::new(std::io::Cursor::new(b"\r\n".to_vec())),
                    ])) as Box<dyn Read + Send>
                }));
            }
            if !sent_terminator {
                sent_terminator = true;
                return Some(Ok(Box::new(std::io::Cursor::new(terminator.clone()))
                    as Box<dyn Read + Send>));
            }
            None
        });
        let mut resp = Response::new(206);
        resp.headers.set(
            "Content-Type",
            swift_http::multipart_byteranges_content_type(&boundary),
        );
        resp.body = swift_http::Body::from_reader(Box::new(reader), Some(total_len));
        Ok(resp)
    }

    /// Fetch and decode exactly the object byte range `[start, stop)`:
    /// ranged fragment GETs covering the segment span, a segment-wise
    /// decode, and head/tail trimming to the requested bytes.
    #[cfg(feature = "ec")]
    #[allow(clippy::too_many_arguments)]
    fn ec_fetch_range(
        self: &Arc<Self>,
        fetch_nodes: &[(i32, Node)],
        object_part: u32,
        path: &str,
        backend_headers: &HeaderKeyDict,
        ec: EcPolicyParams,
        orig_size: usize,
        start: u64,
        stop: u64,
    ) -> std::io::Result<Box<dyn Read + Send>> {
        use swift_ec::EcDriver;
        let driver = EcDriver::new(ec.ndata, ec.nparity)
            .map_err(|e| std::io::Error::other(format!("EC init failed: {e:?}")))?;
        let seg = ec.segment_size as u64;
        let all_segs = ec_segment_sizes(orig_size, ec.segment_size);
        let first_seg = (start / seg) as usize;
        let last_seg = ((stop - 1) / seg) as usize;
        // Fragment-archive offsets of the covered segment span: every
        // segment before the last object segment occupies
        // fragment_size(segment_size) bytes in the archive.
        let frag_full = driver.fragment_size(ec.segment_size) as u64;
        let frag_off = first_seg as u64 * frag_full;
        let covered: Vec<usize> = all_segs[first_seg..=last_seg].to_vec();
        let frag_len: u64 = covered
            .iter()
            .map(|len| driver.fragment_size(*len) as u64)
            .sum();
        let range_header = format!("bytes={frag_off}-{}", frag_off + frag_len - 1);

        let (tx, rx) = mpsc::channel();
        for (fi, node) in fetch_nodes.iter().cloned() {
            let tx = tx.clone();
            let app = Arc::clone(self);
            let mut headers = backend_headers.clone();
            headers.set("Range", &range_header);
            let path = path.to_string();
            std::thread::spawn(move || {
                let r = backend_request_head(
                    &node,
                    object_part,
                    "GET",
                    &path,
                    "",
                    &headers,
                    b"",
                    app.config.conn_timeout,
                    app.config.node_timeout,
                );
                let _ = tx.send((fi, node, r));
            });
        }
        drop(tx);
        let mut readers: Vec<LimitedBackendReader> = Vec::with_capacity(fetch_nodes.len());
        let mut failed = 0usize;
        for (_fi, node, r) in rx.iter() {
            match r {
                Ok(head) if head.status == 206 => readers.push(head.into_limited_reader()),
                Ok(_) | Err(_) => {
                    self.error_limiter.increment(&node);
                    failed += 1;
                }
            }
        }
        if readers.len() < ec.ndata {
            return Err(std::io::Error::other(format!(
                "only {} of {} ranged fragment sources answered ({failed} failed)",
                readers.len(),
                ec.ndata
            )));
        }
        readers.truncate(ec.ndata);
        let decode = EcDecodeReader {
            driver,
            sources: readers,
            seg_sizes: covered,
            next_seg: 0,
            pending: Vec::new(),
            pending_pos: 0,
        };
        Ok(Box::new(SkipLimitReader {
            inner: decode,
            skip: start - first_seg as u64 * seg,
            limit: stop - start,
        }))
    }

    #[cfg(not(feature = "ec"))]
    #[allow(clippy::too_many_arguments)]
    fn ec_put(
        self: &Arc<Self>,
        _req: &mut Request,
        _account: &str,
        _container: &str,
        _path: &str,
        _policy_index: i64,
        _object_ring: &Ring,
        _object_part: u32,
        _ec: EcPolicyParams,
    ) -> Response {
        text_response(501, "erasure coding not built (compile with --features ec)")
    }

    #[cfg(not(feature = "ec"))]
    fn ec_get(
        self: &Arc<Self>,
        _req: &Request,
        _path: &str,
        _policy_index: i64,
        _object_ring: &Ring,
        _object_part: u32,
        _ec: EcPolicyParams,
    ) -> Response {
        text_response(501, "erasure coding not built (compile with --features ec)")
    }
}

/// Convert borrowed ring part-nodes into owned `Node`s in ring order.
#[cfg(feature = "ec")]
fn ring_nodes(part_nodes: Vec<swift_ring::PartNode<'_>>) -> Vec<Node> {
    part_nodes
        .iter()
        .map(|pn| Node {
            ip: pn.dev.ip.clone(),
            port: pn.dev.port,
            device: pn.dev.device.clone(),
            handoff: false,
        })
        .collect()
}

/// Case-insensitive lookup in a backend response's header list.
fn resp_header<'a>(headers: &'a [(String, String)], key: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .map(|(_, v)| v.as_str())
}

/// `is_good_source` (base.py:1093-1102): the backend found what it was
/// looking for — 2xx or 3xx, plus 416 for objects.
fn is_good_source(status: u16, is_object: bool) -> bool {
    if is_object && status == 416 {
        return true;
    }
    (200..400).contains(&status)
}

/// A source response's timestamp (`GetterSource.timestamp`,
/// base.py:1168-1180, mirrored at base.py:1601-1607): the first present,
/// non-empty header of x-backend-data-timestamp, x-backend-timestamp,
/// x-put-timestamp, x-timestamp; zero when none is usable. (Python
/// raises on a malformed value; a well-formed backend never sends one,
/// so falling through is the pragmatic port.)
fn source_timestamp(headers: &[(String, String)]) -> Timestamp {
    for key in [
        "x-backend-data-timestamp",
        "x-backend-timestamp",
        "x-put-timestamp",
        "x-timestamp",
    ] {
        if let Some(ts) = resp_header(headers, key)
            .filter(|v| !v.is_empty())
            .and_then(|v| v.parse::<Timestamp>().ok())
        {
            return ts;
        }
    }
    Timestamp::zero()
}

/// A 404's `X-Backend-Timestamp` — the tombstone timestamp proving the
/// data was really DELETEd — zero when absent (base.py:1619-1621 and
/// 1645-1646).
fn backend_404_timestamp(headers: &[(String, String)]) -> Timestamp {
    resp_header(headers, "x-backend-timestamp")
        .and_then(|v| v.parse::<Timestamp>().ok())
        .unwrap_or(Timestamp::zero())
}

/// obj.py:955-962: a final 404 despite an existence proof (some node
/// answered 202 Accepted in the primary round) means the mixed results
/// can't be resolved — return 503 instead.
fn post_existence_proof_guard(resp: Response, found_count: usize) -> Response {
    if resp.status == 404 && found_count > 0 {
        swob_response(503)
    } else {
        resp
    }
}

/// Lowercase hex md5 of a buffer (the whole-object EC etag).
#[cfg(feature = "ec")]
fn md5_hex(data: &[u8]) -> String {
    use md5::{Digest, Md5};
    format!("{:x}", Md5::digest(data))
}

/// A `status + text/plain body` response (EC error/diagnostic replies).
fn text_response(status: u16, body: &str) -> Response {
    let mut resp = Response::with_body(status, body.as_bytes().to_vec());
    resp.headers.set("Content-Type", "text/plain; charset=utf-8");
    resp
}

/// The synthesized empty-account response for autocreate accounts
/// (`account_listing_response` with a `FakeAccountBroker`).
fn synthesized_account_listing(req: &Request) -> Response {
    let format = req.param("format").unwrap_or_default();
    let now = Timestamp::now();
    let (content_type, body): (&str, Vec<u8>) = match format.as_str() {
        "json" => ("application/json; charset=utf-8", b"[]".to_vec()),
        "xml" => (
            "application/xml; charset=utf-8",
            b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<account name=\"\">\n</account>".to_vec(),
        ),
        _ => ("text/plain; charset=utf-8", Vec::new()),
    };
    // A HEAD (or an empty listing) is 204 with no body; a GET with a
    // format still returns the empty document at 200.
    let empty = body.is_empty();
    let mut resp = if req.method == "HEAD" || empty {
        Response::new(204)
    } else {
        Response::with_body(200, body)
    };
    resp.headers.set("Content-Type", content_type);
    resp.headers.set("X-Account-Container-Count", 0);
    resp.headers.set("X-Account-Object-Count", 0);
    resp.headers.set("X-Account-Bytes-Used", 0);
    resp.headers.set("X-Timestamp", now.normal());
    resp.headers.set("X-PUT-Timestamp", now.normal());
    resp.headers.set("Accept-Ranges", "bytes");
    if req.method == "HEAD" || empty {
        resp.headers.set("Content-Length", 0);
    }
    resp
}

/// Numeric `SHARD_LISTING_STATES` (ACTIVE/SHARDING/SHRINKING/CLEAVED).
/// Mirrors `swift_db::SHARD_LISTING_STATES` so the proxy need not depend on
/// the db crate for a pure JSON filter.
pub(crate) const SHARD_LISTING_STATE_NUMS: [i64; 4] = [
    40, // ACTIVE
    60, // SHARDING
    50, // SHRINKING
    30, // CLEAVED
];

/// Whether HEAD state / object_count justify probing for shard ranges.
///
/// Always for `sharding`/`sharded`. Also for empty roots that still report
/// `unsharded` after partial cleave (Contabo L3b) — the subsequent range GET
/// decides if fan-out actually runs.
pub(crate) fn should_probe_sharded_listing(sharding_state: &str, object_count: i64) -> bool {
    let state = sharding_state.to_ascii_lowercase();
    if state == "sharding" || state == "sharded" {
        return true;
    }
    object_count == 0
}

/// Whether non-empty listing/CLEAVED ranges should trigger fan-out.
///
/// True when DB state is sharding/sharded, or when the root still claims
/// unsharded (or other) with object_count=0 but usable ranges exist.
pub(crate) fn should_fanout_sharded_listing(
    sharding_state: &str,
    object_count: i64,
    has_listing_ranges: bool,
) -> bool {
    if !has_listing_ranges {
        return false;
    }
    let state = sharding_state.to_ascii_lowercase();
    if state == "sharding" || state == "sharded" {
        return true;
    }
    object_count == 0
}

/// Prefer ranges whose `state` is in SHARD_LISTING_STATES. If none match
/// (e.g. missing `state` field), return the input unchanged so a broader
/// retry can still drive fan-out.
pub(crate) fn prefer_listing_state_ranges(ranges: &[serde_json::Value]) -> Vec<serde_json::Value> {
    let listing: Vec<serde_json::Value> = ranges
        .iter()
        .filter(|sr| {
            sr.get("state")
                .and_then(|v| v.as_i64())
                .map(|s| SHARD_LISTING_STATE_NUMS.contains(&s))
                .unwrap_or(false)
        })
        .cloned()
        .collect();
    if listing.is_empty() {
        ranges.to_vec()
    } else {
        listing
    }
}

/// Select listing-state shard ranges that can contribute to a client listing
/// given `marker` / `prefix` (Wave 3 L3b fan-out filter).
pub(crate) fn select_listing_shard_ranges<'a>(
    ranges: &'a [serde_json::Value],
    marker: &str,
    prefix: &str,
) -> Vec<&'a serde_json::Value> {
    let mut out = Vec::new();
    for sr in ranges {
        let upper = sr.get("upper").and_then(|v| v.as_str()).unwrap_or("");
        if !marker.is_empty() && !upper.is_empty() && upper <= marker {
            continue;
        }
        if !prefix.is_empty() && !upper.is_empty() && upper < prefix {
            continue;
        }
        out.push(sr);
    }
    out
}

/// Merge per-shard object listing arrays, stopping at `limit`.
/// Later sources overwrite same `name` (root residual then shards → shard wins).
pub(crate) fn merge_sharded_object_listings(
    shard_listings: &[Vec<serde_json::Value>],
    limit: usize,
) -> Vec<serde_json::Value> {
    use std::collections::HashMap;
    let mut by_name: HashMap<String, serde_json::Value> = HashMap::new();
    let mut order: Vec<String> = Vec::new();
    for items in shard_listings {
        for item in items {
            let name = item
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if name.is_empty() {
                continue;
            }
            if !by_name.contains_key(&name) {
                order.push(name.clone());
            }
            by_name.insert(name, item.clone());
        }
    }
    let mut merged = Vec::new();
    for name in order {
        if let Some(item) = by_name.remove(&name) {
            merged.push(item);
            if merged.len() >= limit {
                return merged;
            }
        }
    }
    merged
}

fn percent_encode(s: &str) -> String {
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

/// Python `get_tempurl_keys_from_metadata` for account/container user meta.
fn temp_url_keys_from_headers(headers: &HeaderKeyDict, server_type: &str) -> Vec<String> {
    let prefix = format!("x-{server_type}-meta-");
    let mut keys = Vec::new();
    for (name, value) in headers.iter() {
        let lower = name.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix(&prefix) {
            if rest == "temp-url-key" || rest == "temp-url-key-2" {
                if !value.is_empty() {
                    keys.push(value.to_string());
                }
            }
        }
    }
    keys
}

fn account_info_from_response(resp: &Response) -> AccountInfo {
    AccountInfo {
        status: resp.status,
        core_access_control: resp
            .headers
            .get("X-Account-Sysmeta-Core-Access-Control")
            .map(str::to_string),
        temp_url_keys: temp_url_keys_from_headers(&resp.headers, "account"),
    }
}

/// Account controller `add_acls_from_sys_metadata`: expose the client header.
fn expose_account_acl_header(resp: &mut Response) {
    if let Some(sys) = resp.headers.remove("X-Account-Sysmeta-Core-Access-Control") {
        if let Some(acls) = swift_middleware::acls_from_sysmeta(Some(&sys)) {
            resp.headers
                .set("X-Account-Access-Control", swift_middleware::format_acl_v2(&acls));
        } else if let Some(raw) = swift_middleware::parse_acl_v2(Some(&sys)) {
            // Empty dict / clear — still surface an empty JSON object when
            // sysmeta was explicitly set to {}.
            if raw.is_empty() {
                resp.headers.set("X-Account-Access-Control", "{}");
            }
        }
    }
}

/// Strip privileged account/container headers for non-owners (Python
/// `swift_owner_headers`).
fn strip_owner_headers(resp: &mut Response, swift_owner: bool) {
    if swift_owner {
        return;
    }
    const OWNER_HEADERS: &[&str] = &[
        "X-Container-Read",
        "X-Container-Write",
        "X-Container-Sync-Key",
        "X-Container-Sync-To",
        "X-Account-Meta-Temp-Url-Key",
        "X-Account-Meta-Temp-Url-Key-2",
        "X-Container-Meta-Temp-Url-Key",
        "X-Container-Meta-Temp-Url-Key-2",
        "X-Account-Access-Control",
    ];
    for name in OWNER_HEADERS {
        resp.headers.remove(name);
    }
}

pub fn serve(listener: std::net::TcpListener, app: Arc<ProxyApp>) -> std::io::Result<()> {
    let handler: swift_http::Handler = Arc::new(move |req| app.handle(req));
    swift_http::serve_forever(listener, handler)
}

/// Serve behind the always-on middleware pipeline
/// (`catch_errors gatekeeper healthcheck proxy-server`), the default
/// Swift proxy front matter.
pub fn serve_with_pipeline(
    listener: std::net::TcpListener,
    app: Arc<ProxyApp>,
) -> std::io::Result<()> {
    serve_with_filters(listener, app, Vec::new())
}

/// Serve behind the always-on pipeline plus `extra` filters inserted
/// after gatekeeper (e.g. a configured `TempAuth`), matching the usual
/// `catch_errors gatekeeper healthcheck <auth> proxy-server` order.
pub fn serve_with_filters(
    listener: std::net::TcpListener,
    app: Arc<ProxyApp>,
    extra: Vec<Arc<dyn swift_middleware::Middleware>>,
) -> std::io::Result<()> {
    serve_with_filters_and_config(
        listener,
        Arc::new(RwLock::new(app)),
        extra,
        swift_http::ServerConfig::default(),
    )
}

/// [`serve_with_filters`] with an explicit HTTP [`swift_http::ServerConfig`]
/// (worker pool size, client timeout, access log, graceful shutdown) and a
/// hot-swappable app: the innermost handler re-reads `app` on every request,
/// so a ring-reload thread can atomically swap in a freshly built
/// [`ProxyApp`] without restarting the server.
pub fn serve_with_filters_and_config(
    listener: std::net::TcpListener,
    app: Arc<RwLock<Arc<ProxyApp>>>,
    extra: Vec<Arc<dyn swift_middleware::Middleware>>,
    config: swift_http::ServerConfig,
) -> std::io::Result<()> {
    use swift_middleware::{build_pipeline, CatchErrors, Gatekeeper, HealthCheck, Middleware};
    let inner: Arc<dyn Fn(Request) -> Response + Send + Sync> = Arc::new(move |req| {
        // Hold the read lock only long enough to clone the Arc so request
        // handling never blocks a pending ring swap.
        let current = {
            let guard = app.read().unwrap_or_else(|poisoned| poisoned.into_inner());
            Arc::clone(&guard)
        };
        current.handle(req)
    });
    let mut filters: Vec<Arc<dyn Middleware>> = vec![
        Arc::new(CatchErrors::new("")),
        Arc::new(Gatekeeper::default()),
        Arc::new(HealthCheck::default()),
    ];
    filters.extend(extra);
    let pipeline = build_pipeline(filters, inner);
    let handler: swift_http::Handler = Arc::new(move |req| pipeline(req));
    swift_http::serve_forever_with_config(listener, handler, config)
}

#[cfg(test)]
mod policy_ring_tests {
    use super::*;
    use swift_core::hashing::HashPathConfig;
    use swift_ring::{RingData, RingDevice};

    pub(crate) fn ring(id: u64) -> Ring {
        let dev = RingDevice {
            id,
            region: 1,
            zone: 1,
            ip: format!("10.0.0.{id}"),
            port: 6200,
            replication_ip: None,
            replication_port: None,
            device: "sda".into(),
            weight: 1.0,
            meta: String::new(),
            extra: Default::default(),
        };
        let data = RingData::from_parts(vec![Some(dev)], 32, vec![vec![0]]);
        Ring::new(data, HashPathConfig::new("", "changeme").unwrap())
    }

    #[test]
    fn test_object_ring_for_selects_policy_ring() {
        let mut rings = std::collections::HashMap::new();
        rings.insert(1i64, ring(11)); // policy 1 -> device 11
        let app = ProxyApp::with_policy_object_rings(
            ring(0),
            ring(0),
            ring(0), // default (policy 0) -> device 0
            rings,
            ProxyConfig::default(),
        );
        let dev_id = |r: Option<&Ring>| r.unwrap().get_part_nodes(0).unwrap()[0].dev.id;
        // policy 1 uses its dedicated ring (device 11)
        assert_eq!(dev_id(app.object_ring_for(1)), 11);
        // Policy 0 uses the default ring; an unknown policy must fail closed.
        assert_eq!(dev_id(app.object_ring_for(0)), 0);
        assert!(app.object_ring_for(9).is_none());
    }
}

#[cfg(test)]
mod stale_read_and_post_tests {
    use super::policy_ring_tests::ring;
    use super::*;

    fn hdrs(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn test_source_timestamp_precedence_and_fallbacks() {
        // x-backend-data-timestamp wins over the later fallbacks
        // (GetterSource.timestamp, base.py:1168-1180)
        let h = hdrs(&[
            ("X-Timestamp", "1000000003.00000"),
            ("X-Backend-Timestamp", "1000000002.00000"),
            ("X-Backend-Data-Timestamp", "1000000001.00000"),
        ]);
        assert_eq!(source_timestamp(&h), "1000000001.00000".parse().unwrap());
        // an empty value falls through, like Python's `or` chain
        let h = hdrs(&[
            ("X-Backend-Data-Timestamp", ""),
            ("X-Timestamp", "1000000003.00000"),
        ]);
        assert_eq!(source_timestamp(&h), "1000000003.00000".parse().unwrap());
        // nothing usable -> zero
        assert_eq!(source_timestamp(&hdrs(&[])), Timestamp::zero());
    }

    #[test]
    fn test_backend_404_timestamp_absent_is_not_truthy() {
        // no tombstone header -> zero -> a handoff 404 is thrown out
        assert!(!backend_404_timestamp(&hdrs(&[])).is_truthy());
        let h = hdrs(&[("X-Backend-Timestamp", "1000000000.00000")]);
        assert!(backend_404_timestamp(&h).is_truthy());
        assert_eq!(backend_404_timestamp(&h), "1000000000.00000".parse().unwrap());
    }

    #[test]
    fn test_is_good_source_matches_python() {
        // base.py:1093-1102: 2xx/3xx are good; 416 only for objects
        assert!(is_good_source(200, false));
        assert!(is_good_source(301, false));
        assert!(!is_good_source(404, true));
        assert!(!is_good_source(503, true));
        assert!(is_good_source(416, true));
        assert!(!is_good_source(416, false));
    }

    #[test]
    fn test_x_newest_picks_max_timestamp_after_tombstone_filter() {
        // Mirrors base.py:1678-1688: after collecting candidates under
        // X-Newest, drop any older than the latest tombstone and take max.
        let older: Timestamp = "1000000001.00000".parse().unwrap();
        let newer: Timestamp = "1000000003.00000".parse().unwrap();
        let tombstone: Timestamp = "1000000002.00000".parse().unwrap();
        let mut candidates = vec![older, newer];
        candidates.retain(|ts| *ts >= tombstone);
        assert_eq!(candidates, vec![newer]);
        assert_eq!(candidates.into_iter().max(), Some(newer));
        // Without X-Newest semantics the first good source would win even
        // when a later replica is newer — that path is covered by the
        // existing first-valid-source walk; this asserts the newest filter.
        assert!(config_true_value("true"));
        assert!(config_true_value("True"));
        assert!(!config_true_value("f"));
    }

    fn br(status: u16) -> BackendResponse {
        BackendResponse {
            status,
            reason: String::new(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    #[test]
    fn test_post_mixed_result_resolution() {
        let app = ProxyApp::new(ring(0), ring(0), ProxyConfig::default());
        // primaries answering 202,404,404 lose best_response to the 404 —
        // the exact situation _post_object exists to repair (obj.py:927-935)
        let primaries = vec![br(202), br(404), br(404)];
        assert_eq!(app.best_response_with_quorum(&primaries, 2).status, 404);
        // one extra handoff 202 flips the combined pick (obj.py:936-953)
        let combined = vec![br(202), br(404), br(404), br(202)];
        assert_eq!(app.best_response_with_quorum(&combined, 2).status, 202);
        // a 404 pick despite an existence proof becomes 503 (obj.py:955-962)
        let dead_handoff = vec![br(202), br(404), br(404), br(503)];
        let resp = app.best_response_with_quorum(&dead_handoff, 2);
        assert_eq!(post_existence_proof_guard(resp, 1).status, 503);
        // no existence proof: a unanimous 404 stands
        let all_404 = vec![br(404), br(404), br(404)];
        let resp = app.best_response_with_quorum(&all_404, 2);
        assert_eq!(post_existence_proof_guard(resp, 0).status, 404);
        // and a non-404 final pick is never rewritten
        let resp = app.best_response_with_quorum(&combined, 2);
        assert_eq!(post_existence_proof_guard(resp, 1).status, 202);
    }
}

#[cfg(test)]
mod info_cache_tests {
    use super::*;

    fn info(policy: i64) -> ContainerInfo {
        ContainerInfo {
            status: 204,
            policy_index: policy,
            read_acl: Some("r".to_string()),
            write_acl: None,
            temp_url_keys: Vec::new(),
            sync_key: None,
        }
    }

    #[test]
    fn test_container_hit_expiry_and_clear() {
        let cache = InfoCache::new();
        assert!(cache.get_container("a/c").is_none());
        // a fresh entry is served back
        cache.set_container("a/c".to_string(), info(3), 60.0);
        let got = cache.get_container("a/c").unwrap();
        assert_eq!(got.policy_index, 3);
        assert_eq!(got.read_acl.as_deref(), Some("r"));
        // an entry older than its TTL is a miss (and is evicted)
        cache.set_container("a/c".to_string(), info(4), 0.01);
        std::thread::sleep(Duration::from_millis(30));
        assert!(cache.get_container("a/c").is_none());
        assert!(cache.containers.lock().unwrap().is_empty());
        // clear_info_cache (container PUT/POST/DELETE) drops a live entry
        cache.set_container("a/c".to_string(), info(5), 60.0);
        cache.clear_container("a/c");
        assert!(cache.get_container("a/c").is_none());
        // a non-positive TTL disables caching entirely
        cache.set_container("a/c".to_string(), info(6), 0.0);
        assert!(cache.get_container("a/c").is_none());
        // per-key TTLs are independent: the "a/x" 404-style short entry
        // expiring does not disturb the fresh "a/c" entry
        cache.set_container("a/c".to_string(), info(7), 60.0);
        cache.set_container("a/x".to_string(), info(8), 0.01);
        std::thread::sleep(Duration::from_millis(30));
        assert!(cache.get_container("a/x").is_none());
        assert_eq!(cache.get_container("a/c").unwrap().policy_index, 7);
    }

    #[test]
    fn test_account_map_hit_expiry_and_clear() {
        let cache = InfoCache::new();
        assert!(cache.get_account("a").is_none());
        cache.set_account(
            "a".to_string(),
            AccountInfo {
                status: 204,
                ..Default::default()
            },
            60.0,
        );
        assert_eq!(cache.get_account("a").unwrap().status, 204);
        // the maps are independent namespaces
        assert!(cache.get_container("a").is_none());
        // clear_info_cache (account PUT/POST/DELETE, successful autocreate)
        cache.clear_account("a");
        assert!(cache.get_account("a").is_none());
        // expiry
        cache.set_account(
            "a".to_string(),
            AccountInfo {
                status: 404,
                ..Default::default()
            },
            0.01,
        );
        std::thread::sleep(Duration::from_millis(30));
        assert!(cache.get_account("a").is_none());
    }

    #[test]
    fn test_info_cache_time_matches_set_info_cache() {
        // base.py:678-694: 2xx cached for the full recheck TTL...
        assert_eq!(info_cache_time(204, None, 60.0), Some(60.0));
        // ...404/410 (authoritative absence) at a tenth of it...
        assert_eq!(info_cache_time(404, None, 60.0), Some(6.0));
        assert_eq!(info_cache_time(410, None, 60.0), Some(6.0));
        // ...and any other non-success bails without touching caches.
        assert_eq!(info_cache_time(503, None, 60.0), None);
        assert_eq!(info_cache_time(507, None, 60.0), None);
        assert_eq!(info_cache_time(301, None, 60.0), None);
        // the backend X-Backend-Recheck-*-Existence header overrides the
        // conf default (base.py:678-685); garbage falls back
        assert_eq!(info_cache_time(200, Some("120"), 60.0), Some(120.0));
        assert_eq!(info_cache_time(404, Some("120"), 60.0), Some(12.0));
        assert_eq!(info_cache_time(200, Some("banana"), 60.0), Some(60.0));
    }
}

#[cfg(test)]
mod p1a_wiring_tests {
    use super::policy_ring_tests::ring;
    use super::*;

    fn app(auth_enabled: bool) -> Arc<ProxyApp> {
        Arc::new(ProxyApp::new(
            ring(0),
            ring(0),
            ProxyConfig {
                auth_enabled,
                ..Default::default()
            },
        ))
    }

    #[test]
    fn authorize_override_allows_as_non_owner() {
        let app = app(true);
        let mut headers = HeaderKeyDict::new();
        headers.set("X-Backend-Authorize-Override", "true");
        headers.set("X-Backend-Swift-Owner", "true");
        let mut req = Request {
            method: "GET".to_string(),
            path: "/v1/AUTH_test/container/object".to_string(),
            query_string: String::new(),
            headers,
            body: swift_http::Body::empty(),
        };

        assert!(app
            .authorize(&mut req, "AUTH_test", Some("container"), Some("object"))
            .is_none());
        assert!(req.headers.get("X-Backend-Swift-Owner").is_none());
    }

    #[test]
    fn authorize_legacy_sync_key_allows_without_token() {
        // Seed container info cache with a sync_key (no backend HEAD).
        let app = app(true);
        let info = ContainerInfo {
            status: 204,
            policy_index: 0,
            read_acl: None,
            write_acl: None,
            temp_url_keys: Vec::new(),
            sync_key: Some("lab-sync-key".into()),
        };
        app.info_cache
            .set_container("AUTH_test/syncc".into(), info, 60.0);

        // Gatekeeper-shunted timestamp form (production path).
        let mut headers = HeaderKeyDict::new();
        headers.set("X-Container-Sync-Key", "lab-sync-key");
        headers.set("X-Backend-Inbound-X-Timestamp", "1786026000.00000");
        let mut req = Request {
            method: "PUT".to_string(),
            path: "/v1/AUTH_test/syncc/obj1".to_string(),
            query_string: String::new(),
            headers,
            body: swift_http::Body::empty(),
        };
        assert!(
            app.authorize(&mut req, "AUTH_test", Some("syncc"), Some("obj1"))
                .is_none(),
            "matching sync-key + inbound-x-timestamp must authorize"
        );
        assert_eq!(
            req.headers.get("X-Timestamp").map(str::to_string),
            Some("1786026000.00000".into()),
            "must restore X-Timestamp for object servers"
        );

        // Wrong key → still denied (401/403 from ACL path with empty groups).
        let mut headers = HeaderKeyDict::new();
        headers.set("X-Container-Sync-Key", "wrong");
        headers.set("X-Backend-Inbound-X-Timestamp", "1786026000.00000");
        let mut req = Request {
            method: "PUT".to_string(),
            path: "/v1/AUTH_test/syncc/obj1".to_string(),
            query_string: String::new(),
            headers,
            body: swift_http::Body::empty(),
        };
        assert!(
            app.authorize(&mut req, "AUTH_test", Some("syncc"), Some("obj1"))
                .is_some(),
            "mismatched sync-key must not authorize"
        );
    }

    #[test]
    fn cached_account_acls_are_loaded() {
        let app = app(true);
        app.info_cache.set_account(
            "AUTH_test".to_string(),
            AccountInfo {
                status: 204,
                core_access_control: Some(
                    r#"{"admin":["AUTH_other:admin"],"read-only":["AUTH_other:reader"]}"#
                        .to_string(),
                ),
                temp_url_keys: Vec::new(),
            },
            60.0,
        );

        let acls = app.account_acls("AUTH_test").expect("account ACLs");
        assert_eq!(acls.admin, vec!["AUTH_other:admin"]);
        assert_eq!(acls.read_only, vec!["AUTH_other:reader"]);
    }

    #[test]
    fn account_acl_is_exposed_then_owner_headers_are_filtered() {
        let mut resp = Response::new(204);
        resp.headers.set(
            "X-Account-Sysmeta-Core-Access-Control",
            r#"{"read-write":["AUTH_other:user"]}"#,
        );
        for name in [
            "X-Account-Meta-Temp-Url-Key",
            "X-Account-Meta-Temp-Url-Key-2",
            "X-Container-Meta-Temp-Url-Key",
            "X-Container-Meta-Temp-Url-Key-2",
            "X-Container-Read",
            "X-Container-Write",
        ] {
            resp.headers.set(name, "secret");
        }

        expose_account_acl_header(&mut resp);
        assert!(resp
            .headers
            .get("X-Account-Sysmeta-Core-Access-Control")
            .is_none());
        let exposed: serde_json::Value = serde_json::from_str(
            resp.headers
                .get("X-Account-Access-Control")
                .expect("client ACL header"),
        )
        .unwrap();
        assert_eq!(exposed["read-write"][0], "AUTH_other:user");

        strip_owner_headers(&mut resp, true);
        assert!(resp.headers.get("X-Account-Access-Control").is_some());
        strip_owner_headers(&mut resp, false);
        for name in [
            "X-Account-Access-Control",
            "X-Account-Meta-Temp-Url-Key",
            "X-Account-Meta-Temp-Url-Key-2",
            "X-Container-Meta-Temp-Url-Key",
            "X-Container-Meta-Temp-Url-Key-2",
            "X-Container-Read",
            "X-Container-Write",
        ] {
            assert!(resp.headers.get(name).is_none(), "{name} leaked");
        }
    }

    #[test]
    fn tempurl_key_header_extraction_ignores_empty_values() {
        let mut headers = HeaderKeyDict::new();
        headers.set("X-Account-Meta-Temp-Url-Key", "");
        headers.set("X-Account-Meta-Temp-Url-Key-2", "second");
        assert_eq!(
            temp_url_keys_from_headers(&headers, "account"),
            vec!["second"]
        );
    }

    #[test]
    fn allow_account_management_gates_put_delete_405() {
        // Live-style: account PUT/DELETE never reach backends when the conf
        // gate is off (Python account.py removes those methods).
        let gated = Arc::new(ProxyApp::new(
            ring(0),
            ring(0),
            ProxyConfig {
                allow_account_management: false,
                auth_enabled: false,
                ..Default::default()
            },
        ));
        for method in ["PUT", "DELETE"] {
            let resp = gated.handle(Request {
                method: method.to_string(),
                path: "/v1/AUTH_test".to_string(),
                query_string: String::new(),
                headers: HeaderKeyDict::new(),
                body: swift_http::Body::empty(),
            });
            assert_eq!(resp.status, 405, "{method}");
            assert_eq!(
                resp.headers.get("Allow").map(str::to_string),
                Some("GET, HEAD, POST, OPTIONS".into()),
                "{method}"
            );
        }
        // When enabled, the gate is open: unreachable backends yield 503, not 405.
        let open = Arc::new(ProxyApp::new(
            ring(0),
            ring(0),
            ProxyConfig {
                allow_account_management: true,
                auth_enabled: false,
                ..Default::default()
            },
        ));
        let resp = open.handle(Request {
            method: "PUT".to_string(),
            path: "/v1/AUTH_test".to_string(),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: swift_http::Body::empty(),
        });
        assert_ne!(resp.status, 405, "enabled path must not 405: {}", resp.status);
    }
}

#[cfg(test)]
mod shard_listing_fanout_tests {
    use super::{
        merge_sharded_object_listings, prefer_listing_state_ranges, select_listing_shard_ranges,
        should_fanout_sharded_listing, should_probe_sharded_listing, SHARD_LISTING_STATE_NUMS,
    };

    fn sr(name: &str, lower: &str, upper: &str) -> serde_json::Value {
        serde_json::json!({"name": name, "lower": lower, "upper": upper})
    }

    fn sr_state(name: &str, lower: &str, upper: &str, state: i64) -> serde_json::Value {
        serde_json::json!({
            "name": name,
            "lower": lower,
            "upper": upper,
            "state": state,
        })
    }

    #[test]
    fn select_ranges_skips_before_marker_and_prefix() {
        let ranges = vec![
            sr(".shards/a", "", "m"),
            sr(".shards/b", "m", "t"),
            sr(".shards/c", "t", ""),
        ];
        let selected = select_listing_shard_ranges(&ranges, "m", "");
        // upper "m" <= marker "m" → skip first
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0]["name"], ".shards/b");

        let selected = select_listing_shard_ranges(&ranges, "", "u");
        // upper "m" < "u" and upper "t" < "u" → only open-ended last range
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0]["name"], ".shards/c");
    }

    #[test]
    fn merge_listings_respects_limit_across_shards() {
        let a = vec![
            serde_json::json!({"name": "a1"}),
            serde_json::json!({"name": "a2"}),
        ];
        let b = vec![
            serde_json::json!({"name": "b1"}),
            serde_json::json!({"name": "b2"}),
        ];
        let merged = merge_sharded_object_listings(&[a, b], 3);
        assert_eq!(merged.len(), 3);
        assert_eq!(merged[0]["name"], "a1");
        assert_eq!(merged[2]["name"], "b1");
    }

    #[test]
    fn empty_state_with_ranges_is_fanout_eligible() {
        // Contabo partial cleave: DB state still unsharded, root emptied,
        // CLEAVED ranges present → fan out.
        assert!(should_probe_sharded_listing("unsharded", 0));
        assert!(should_fanout_sharded_listing("unsharded", 0, true));
        assert!(!should_fanout_sharded_listing("unsharded", 0, false));

        // Non-empty unsharded root: do not probe (objects still local).
        assert!(!should_probe_sharded_listing("unsharded", 5));
        assert!(!should_fanout_sharded_listing("unsharded", 5, true));

        // Explicit sharding/sharded always eligible when ranges exist.
        assert!(should_probe_sharded_listing("sharding", 0));
        assert!(should_probe_sharded_listing("sharded", 100));
        assert!(should_fanout_sharded_listing("sharding", 0, true));
        assert!(should_fanout_sharded_listing("sharded", 0, true));
        assert!(!should_fanout_sharded_listing("sharded", 0, false));
    }

    #[test]
    fn prefer_listing_states_keeps_cleaved_drops_found() {
        // CLEAVED = 30 is in SHARD_LISTING_STATES; FOUND = 10 is not.
        assert!(SHARD_LISTING_STATE_NUMS.contains(&30));
        let ranges = vec![
            sr_state(".shards/found", "", "m", 10),
            sr_state(".shards/cleaved", "m", "t", 30),
            sr_state(".shards/active", "t", "", 40),
        ];
        let preferred = prefer_listing_state_ranges(&ranges);
        assert_eq!(preferred.len(), 2);
        assert_eq!(preferred[0]["name"], ".shards/cleaved");
        assert_eq!(preferred[1]["name"], ".shards/active");

        // All non-listing → fall back to full list (broader retry path).
        let only_found = vec![sr_state(".shards/f", "", "", 10)];
        let fallback = prefer_listing_state_ranges(&only_found);
        assert_eq!(fallback.len(), 1);
        assert_eq!(fallback[0]["name"], ".shards/f");
    }
}
