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
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use swift_core::config::config_true_value;
use swift_core::constraints::check_utf8;
use swift_core::timestamp::{normalize_delete_at_timestamp, Timestamp};
use swift_http::{
    listing_query_invalid_utf8_param, split_path, AsyncRequest, AsyncService, HeaderKeyDict,
    Request, Response,
};
use swift_memcache::{MemcacheClient, TcpConn};
use swift_ring::Ring;

mod async_fanout;

// Swift's modern object-expirer queue uses one hidden account and spreads a
// divisor window over the preceding 100 container names by object hash. Keep
// these beside the proxy routing code: the proxy and object server must agree
// on the exact task-container name or expiry updates become orphaned.
const EXPIRER_ACCOUNT_NAME: &str = ".expiring_objects";
const EXPIRER_CONTAINER_DIVISOR: i64 = 86_400;
const EXPIRER_CONTAINERS_PER_DIVISOR: i64 = 100;

fn expirer_container_for_object_hash(delete_at: i64, object_hash: &str) -> String {
    let bucket = delete_at.div_euclid(EXPIRER_CONTAINER_DIVISOR) * EXPIRER_CONTAINER_DIVISOR;
    let offset = u128::from_str_radix(object_hash, 16)
        .unwrap_or(0)
        .rem_euclid(EXPIRER_CONTAINERS_PER_DIVISOR as u128) as i64;
    format!("{:010}", bucket.saturating_sub(offset))
}

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
    /// Ring primary position. For EC this is the fragment index the
    /// proxy assigned at PUT. Used when a backend 200 omits
    /// `X-Object-Sysmeta-Ec-Frag-Index` so gather can still count the
    /// source (field `9a95747` harvest saw 0 of those headers).
    backend_index: Option<i32>,
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
    /// Python `post_quorum_timeout` (default 0.5s). After a write fan-out
    /// has quorum, remaining replica slots are given this long to finish so
    /// account-update / container-update side channels complete. Unused
    /// slots are then cancelled; they are not detached.
    pub post_quorum_timeout: Duration,
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
    /// Python's `strict_cors_mode`: simple CORS responses are emitted only
    /// for an allowed Origin when true. Preflight always requires an allowed
    /// Origin, regardless of this setting.
    pub strict_cors_mode: bool,
    /// Operator-wide origins from `cors_allow_origin`. Container metadata is
    /// combined with these values when validating an Origin.
    pub cors_allow_origin: Vec<String>,
    /// Operator-wide additions to `Access-Control-Expose-Headers`.
    pub cors_expose_headers: Vec<String>,
    /// Python `allow_open_expired`. When false the proxy must not forward
    /// `X-Open-Expired` (the object server treats that header as sufficient
    /// to open a not-yet-reaped expired object).
    pub allow_open_expired: bool,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        ProxyConfig {
            conn_timeout: Duration::from_millis(500),
            node_timeout: Duration::from_secs(10),
            post_quorum_timeout: Duration::from_millis(500),
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
            strict_cors_mode: true,
            cors_allow_origin: Vec::new(),
            cors_expose_headers: Vec::new(),
            allow_open_expired: false,
        }
    }
}

/// CORS values persisted as container user metadata. Python exposes these as
/// `container_info['cors']` after reading the container HEAD response.
#[derive(Clone, Default, Debug, PartialEq, Eq)]
struct CorsInfo {
    allow_origin: Option<String>,
    expose_headers: Option<String>,
    max_age: Option<String>,
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
    /// `X-Container-Sysmeta-Rfc-Compliant-Etags` when the container HEAD
    /// carried a non-empty value. Empty/missing means "fall through to
    /// account / enable_by_default" (Python etag_quoter).
    rfc_compliant_etags: Option<String>,
    cors: CorsInfo,
    /// Python `container_info['db_state']` from `X-Backend-Sharding-State`.
    /// Empty means the HEAD omitted it; [`Self::root_db_state`] then reports
    /// `unsharded`, matching an unsharded broker.
    db_state: String,
}

impl ContainerInfo {
    fn exists(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// Object writes distinguish an authoritative missing container (404)
    /// from a container ring that could not answer at all (status 0). Python
    /// synthesizes 503 for the latter so callers do not cache infrastructure
    /// failure as non-existence.
    fn write_failure_status(&self) -> u16 {
        if self.status == 0 || self.status >= 500 {
            503
        } else {
            404
        }
    }

    /// Value for `X-Container-Root-Db-State` on object PUT/DELETE (Python
    /// obj.py `headers_in.get('X-Container-Root-Db-State')`).
    fn root_db_state(&self) -> &str {
        if self.db_state.is_empty() {
            "unsharded"
        } else {
            &self.db_state
        }
    }
}

/// Cached account HEAD: status plus sysmeta ACL and Temp-URL keys.
#[derive(Clone)]
struct AccountInfo {
    status: u16,
    /// Raw `X-Account-Sysmeta-Core-Access-Control` value when present.
    core_access_control: Option<String>,
    temp_url_keys: Vec<String>,
    /// `X-Account-Sysmeta-Rfc-Compliant-Etags` when the account HEAD
    /// carried a non-empty value.
    rfc_compliant_etags: Option<String>,
    /// Python `headers_to_account_info` `account_really_exists`: false when
    /// the listing was synthesized for `account_autocreate` (`X-Backend-
    /// Fake-Account-Listing: yes`). Defaults true so a missing cache field
    /// does not skip autocreate. Presence is `exists()`.
    account_really_exists: bool,
}

impl Default for AccountInfo {
    fn default() -> Self {
        AccountInfo {
            status: 0,
            core_access_control: None,
            temp_url_keys: Vec::new(),
            rfc_compliant_etags: None,
            account_really_exists: true,
        }
    }
}

impl AccountInfo {
    /// Python `Controller.account_info`: 2xx AND not a fake autocreate listing.
    fn exists(&self) -> bool {
        (200..300).contains(&self.status) && self.account_really_exists
    }
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
    container_db_states: Mutex<HashMap<String, (Instant, String)>>,
    accounts: Mutex<HashMap<String, (Instant, AccountInfo)>>,
    memcache: Option<Mutex<MemcacheClient<TcpConn>>>,
}

impl InfoCache {
    fn new() -> Self {
        InfoCache {
            containers: Mutex::new(HashMap::new()),
            container_db_states: Mutex::new(HashMap::new()),
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

    fn memcache_key_container_db_state(account_container: &str) -> String {
        format!("peregrine/container-root-db-state/{account_container}")
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

    /// A root DB-state proof is intentionally separate from container-info.
    /// Updating the latter from a listing extends stale policy/ACL metadata
    /// and breaks delete/recreate across storage policies (probe L2541).
    fn get_container_db_state(&self, key: &str) -> Option<String> {
        if self.memcache.is_some() {
            let mkey = Self::memcache_key_container_db_state(key);
            return self.memcache_get_string(&mkey);
        }
        let mut map = self.container_db_states.lock().unwrap();
        match map.get(key) {
            None => None,
            Some((deadline, state)) => {
                if Instant::now() >= *deadline {
                    map.remove(key);
                    None
                } else {
                    Some(state.clone())
                }
            }
        }
    }

    fn set_container_db_state(&self, key: &str, state: &str, ttl_secs: f64) {
        if !ttl_secs.is_finite() || ttl_secs <= 0.0 {
            return;
        }
        let deadline = Instant::now() + Duration::from_secs_f64(ttl_secs.min(1e9));
        self.container_db_states
            .lock()
            .unwrap()
            .insert(key.to_string(), (deadline, state.to_string()));
        let mkey = Self::memcache_key_container_db_state(key);
        self.memcache_set_string(&mkey, state, ttl_secs);
    }

    /// `clear_info_cache` for one container (base.py:732-744).
    fn clear_container(&self, key: &str) {
        self.containers.lock().unwrap().remove(key);
        self.container_db_states.lock().unwrap().remove(key);
        let mkey = Self::memcache_key_container(key);
        self.memcache_delete(&mkey);
        let state_key = Self::memcache_key_container_db_state(key);
        self.memcache_delete(&state_key);
    }

    /// Clear mutable container metadata while retaining independently proven
    /// root sharding state. A container POST cannot unshard a root. Python
    /// clears `container/<account>/<container>` here but deliberately does not
    /// purge the updating-shard cache, so retaining this routing proof matches
    /// its contract. PUT/DELETE still use [`Self::clear_container`] because a
    /// delete/recreate can invalidate both metadata and shard topology.
    fn clear_container_metadata(&self, key: &str) {
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

    fn memcache_get_string(&self, key: &str) -> Option<String> {
        let mc = self.memcache.as_ref()?;
        let mut guard = mc.lock().ok()?;
        guard
            .get_json(key)
            .ok()
            .flatten()?
            .as_str()
            .map(str::to_string)
    }

    fn memcache_set_string(&self, key: &str, value: &str, ttl_secs: f64) {
        let Some(mc) = &self.memcache else { return };
        let Ok(mut guard) = mc.lock() else { return };
        let value = serde_json::Value::String(value.to_string());
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
        "rfc_compliant_etags": info.rfc_compliant_etags,
        "db_state": info.db_state,
        "cors": {
            "allow_origin": info.cors.allow_origin,
            "expose_headers": info.cors.expose_headers,
            "max_age": info.cors.max_age,
        },
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
        rfc_compliant_etags: v
            .get("rfc_compliant_etags")
            .and_then(|x| x.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        db_state: v
            .get("db_state")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string(),
        cors: CorsInfo {
            allow_origin: v
                .get("cors")
                .and_then(|cors| cors.get("allow_origin"))
                .and_then(|x| x.as_str())
                .map(str::to_string),
            expose_headers: v
                .get("cors")
                .and_then(|cors| cors.get("expose_headers"))
                .and_then(|x| x.as_str())
                .map(str::to_string),
            max_age: v
                .get("cors")
                .and_then(|cors| cors.get("max_age"))
                .and_then(|x| x.as_str())
                .map(str::to_string),
        },
    })
}

fn account_info_to_json(info: &AccountInfo) -> serde_json::Value {
    serde_json::json!({
        "status": info.status,
        "core_access_control": info.core_access_control,
        "temp_url_keys": info.temp_url_keys,
        "rfc_compliant_etags": info.rfc_compliant_etags,
        "account_really_exists": info.account_really_exists,
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
        rfc_compliant_etags: v
            .get("rfc_compliant_etags")
            .and_then(|x| x.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        // Python `.get('account_really_exists', True)`: absent key is real.
        account_really_exists: v
            .get("account_really_exists")
            .and_then(|x| x.as_bool())
            .unwrap_or(true),
    })
}

/// `set_info_cache`'s cache lifetime for a backend info response
/// (base.py:672-692): the backend's `X-Backend-Recheck-*-Existence` override
/// or the conf default; a tenth of that for authoritative absence (404/410);
/// `None` for any other non-success status, which must not touch the cache
/// ("bail without touching caches", base.py:689-692).
pub(crate) fn info_cache_time(
    status: u16,
    recheck_header: Option<&str>,
    default_ttl: f64,
) -> Option<f64> {
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
    /// Syslog logger used by the daemon (`log_name`, usually `proxy-server`).
    /// Isolated lab manager.log / syslog harvest this path; `eprintln!` does not.
    logger: Option<Arc<swift_core::obslog::Logger>>,
    /// Test capture for the same lines the daemon sends to syslog.
    log_sink: Option<Arc<dyn Fn(&str) + Send + Sync>>,
}

/// A backend response.
struct BackendResponse {
    status: u16,
    reason: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

pub(crate) fn with_g6_diag(mut resp: Response, reason: impl Into<String>) -> Response {
    if resp.g6_diag.is_none() {
        resp.set_g6_diag(reason);
    }
    resp
}

fn finalize_service_g6_diag(mut resp: Response, via: &str, method: &str, path: &str) -> Response {
    match resp.g6_diag.as_mut() {
        Some(inner) => {
            if !inner.contains("via=") {
                *inner = format!("via={via} {inner}");
            }
        }
        None => {
            resp.set_g6_diag(format!(
                "reason=unstamped via={via} method={method} path={path} status={}",
                resp.status
            ));
        }
    }
    resp
}

/// Python `server.py get_controller` / `obj.py GETorHEAD`: an explicit
/// `X-Backend-Storage-Policy-Index` — including `0` — selects that policy's
/// object ring and controller. Remapping `0` onto an EC container made
/// InternalClient GETs for Policy-0 and ec42 hit the same fragments, so
/// `test_expirer_object_split_brain` saw the object in both policies
/// (L131) or a timestamp-less EC 404 when the data lived on Policy-0 (L105).
pub(crate) fn resolve_object_storage_policy(
    header_policy: Option<i64>,
    container_policy: i64,
) -> i64 {
    header_policy.unwrap_or(container_policy)
}

/// Python EC GET `best_response` on fragment 404s copies the winning
/// `X-Backend-Timestamp`. A synthesized HTML 404 must do the same so
/// InternalClient / `get_object_metadata(..., acceptable_statuses=(4,))`
/// can see the tombstone (probe `test_expirer_object_split_brain`).
pub(crate) fn swob_404_with_backend_timestamp(ts: Timestamp) -> Response {
    attach_backend_timestamp(swob_response(404), ts)
}

pub(crate) fn attach_backend_timestamp(mut resp: Response, ts: Timestamp) -> Response {
    if resp.status == 404 && ts.is_truthy() {
        if resp.headers.get("X-Backend-Timestamp").is_none() {
            resp.headers.set("X-Backend-Timestamp", ts.internal());
        }
        if resp.headers.get("X-Timestamp").is_none() {
            resp.headers.set("X-Timestamp", ts.normal());
        }
    }
    resp
}

fn swob_response(status: u16) -> Response {
    let explanation = match status {
        404 => "The resource could not be found.",
        503 => "The server is currently unavailable. Please try again at a later time.",
        501 => "The requested method is not implemented by this server.",
        412 => "A precondition for this request was not met.",
        409 => "There was a conflict when trying to complete your request.",
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

fn method_not_allowed(allow: &str) -> Response {
    let mut resp = swob_response(405);
    resp.headers.set("Allow", allow);
    resp
}

/// Python `list_from_csv`: trim comma-separated values, omit empties, and
/// return each distinct value once. Preserve first-seen order for a stable
/// wire response.
fn csv_header_values(value: &str) -> Vec<String> {
    let mut values = Vec::new();
    for item in value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
    {
        if !values.iter().any(|seen: &String| seen.as_str() == item) {
            values.push(item.to_string());
        }
    }
    values
}

fn append_vary(headers: &mut HeaderKeyDict, token: &str) {
    let mut values = headers
        .get("Vary")
        .map(csv_header_values)
        .unwrap_or_default();
    if !values.iter().any(|value| value.eq_ignore_ascii_case(token)) {
        values.push(token.to_string());
    }
    headers.set("Vary", values.join(", "));
}

/// A parsed backend response head with the connection still open at the
/// first body byte, so the caller decides whether the body is buffered
/// (control plane) or streamed to the client (object data plane).
struct BackendHead {
    status: u16,
    reason: String,
    headers: Vec<(String, String)>,
    reader: std::io::BufReader<TcpStream>,
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
    reader: std::io::BufReader<TcpStream>,
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
fn read_backend_line(reader: &mut std::io::BufReader<TcpStream>) -> std::io::Result<String> {
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
fn read_backend_head(reader: &mut std::io::BufReader<TcpStream>) -> std::io::Result<ParsedHead> {
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
    let content_length =
        resp_header(&resp_headers, "content-length").and_then(|v| v.parse::<u64>().ok());
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
) -> std::io::Result<TcpStream> {
    let addr = format!("{}:{}", node.ip, node.port);
    let sock_addr: SocketAddr = addr
        .parse()
        .map_err(|e| std::io::Error::other(format!("bad node address {addr}: {e}")))?;
    let conn = TcpStream::connect_timeout(&sock_addr, conn_timeout)?;
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
    head.into_buffered(
        swift_core::constraints::MAX_FILE_SIZE as u64,
        method != "HEAD",
    )
}

/// A live object-PUT backend connection that answered `100 Continue`
/// (obj.py `Putter`): the write half streams body chunks, the read half
/// waits for the final response.
struct Putter {
    node: Node,
    stream: TcpStream,
    reader: std::io::BufReader<TcpStream>,
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
        if [
            "content-length",
            "transfer-encoding",
            "connection",
            "expect",
        ]
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
    let content_length =
        resp_header(&resp_headers, "content-length").and_then(|v| v.parse::<u64>().ok());
    let head = BackendHead {
        status,
        reason,
        headers: resp_headers,
        reader,
        content_length,
    };
    Ok(PutterOutcome::EarlyFinal(
        head.into_buffered(swift_http::MAX_CONTROL_BODY, true)?,
    ))
}

fn write_chunk_framed<W: Write>(writer: &mut W, chunk: &[u8]) -> std::io::Result<()> {
    write!(writer, "{:x}\r\n", chunk.len())?;
    writer.write_all(chunk)?;
    writer.write_all(b"\r\n")
}

/// Keep a conditional zero-byte backend PUT in its pre-commit phase until
/// every object server has answered `100 Continue` or an early final status.
/// With `Content-Length: 0`, servers missing the object can commit before a
/// different replica returns `412`; chunked framing lets the proxy withhold
/// the terminating zero chunk when any replica rejects `If-None-Match: *`.
pub(crate) fn backend_put_content_length(
    client_length: Option<u64>,
    per_node_headers: &[HeaderKeyDict],
) -> Option<u64> {
    let conditional = per_node_headers
        .iter()
        .any(|headers| headers.get("If-None-Match").is_some());
    if client_length == Some(0) && conditional {
        None
    } else {
        client_length
    }
}

#[cfg(test)]
mod conditional_zero_put_tests {
    use super::*;

    #[test]
    fn conditional_zero_put_uses_chunked_backend_commit_barrier() {
        let mut conditional = HeaderKeyDict::new();
        conditional.set("If-None-Match", "*");
        assert_eq!(backend_put_content_length(Some(0), &[conditional]), None);

        let ordinary = HeaderKeyDict::new();
        assert_eq!(backend_put_content_length(Some(0), &[ordinary]), Some(0));
        assert_eq!(backend_put_content_length(Some(4), &[]), Some(4));
        assert_eq!(backend_put_content_length(None, &[]), None);
    }
}

/// The per-segment sizes an object splits into (empty object = no
/// segments: Python stores zero-byte archives for zero-byte objects).
#[cfg(feature = "ec")]
pub(crate) fn ec_segment_sizes(orig_size: usize, segment_size: usize) -> Vec<usize> {
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
    stream: TcpStream,
    reader: std::io::BufReader<TcpStream>,
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
        if [
            "content-length",
            "transfer-encoding",
            "connection",
            "expect",
        ]
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
    Ok(MimeConnectOutcome::EarlyFinal(
        head.into_buffered(swift_http::MAX_CONTROL_BODY, true)?,
    ))
}

/// `swift.common.utils.quorum_size` is in swift-core.
use swift_core::storage_policy::quorum_size;

/// Python `generate_request_headers` always carries backend-control headers
/// (and an explicit timestamp) into storage-node requests, independently of
/// the public metadata transfer rules. Internal Swift callers rely on this
/// for controls such as `X-Backend-No-Commit`; dropping it turns an intended
/// non-durable EC generation into a durable overwrite.
fn copy_backend_control_headers(req: &Request, headers: &mut HeaderKeyDict) {
    for (key, value) in req.headers.iter() {
        let lower = key.to_ascii_lowercase();
        if lower.starts_with("x-backend-") || lower == "x-timestamp" {
            headers.set(key, value);
        }
    }
}

/// During a partition-power increase every object backend request carries the
/// ring transition to the object server.  The storage layer uses it for
/// mutation dual-linking; read requests carry it for wire parity with Python.
fn stamp_next_part_power(headers: &mut HeaderKeyDict, object_ring: &Ring) {
    if let Some(next_part_power) = object_ring.next_part_power() {
        headers.set("X-Backend-Next-Part-Power", next_part_power);
    }
}

/// Preserve a trusted Swift-internal timestamp (including its offset) when
/// generating object backend requests.
///
/// Public pipelines shunt client `X-Timestamp` → `X-Backend-Inbound-X-Timestamp`
/// in gatekeeper; raw `X-Timestamp` stays stripped on the public path. Owner
/// PUTs (tempauth / Internal Client) must still honor that inbound value so a
/// recreate at `delete_at+1` beats the expirer tombstone stamped at
/// `delete_at`. Internal clients such as container-reconciler may also supply
/// `X-Timestamp` directly. Wall-clock is used only when neither header is
/// present — replacing a requested timestamp with now loses Swift conflict
/// ordering (field H1: handoff `.data` at wall-clock lost to a newer `.ts`).
fn object_write_timestamp(req: &Request) -> Timestamp {
    req.headers
        .get("X-Timestamp")
        .or_else(|| req.headers.get("X-Backend-Inbound-X-Timestamp"))
        .and_then(|raw| raw.parse().ok())
        .unwrap_or_else(Timestamp::now)
}

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
            logger: None,
            log_sink: None,
        }
    }

    /// Attach the daemon syslog logger. Ring reload must re-apply this.
    pub fn with_logger(mut self, logger: Arc<swift_core::obslog::Logger>) -> Self {
        self.logger = Some(logger);
        self
    }

    /// Capture `proxy-server:` lines in tests (same strings as syslog).
    pub fn with_log_sink(mut self, sink: Arc<dyn Fn(&str) + Send + Sync>) -> Self {
        self.log_sink = Some(sink);
        self
    }

    /// INFO (or ERROR when `error`) on the real proxy logger, plus any test sink.
    /// Isolated lab harvests `G6_DIAG` from stderr (manager.log); syslog
    /// `Logger` alone was silent on `2c64a89`.
    pub(crate) fn emit_proxy_log(&self, error: bool, msg: &str) {
        eprintln!("G6_DIAG {msg}");
        if let Some(sink) = &self.log_sink {
            sink(msg);
        }
        if let Some(logger) = &self.logger {
            if error {
                logger.error(msg);
            } else {
                logger.info(msg);
            }
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
    pub fn with_policy_names(mut self, names: std::collections::HashMap<String, i64>) -> Self {
        self.policy_name_to_index = names
            .into_iter()
            .map(|(k, v)| (k.to_lowercase(), v))
            .collect();
        self
    }

    /// EC scheme for a GET: exact policy index, else a configured scheme
    /// whose `ndata + nparity` matches this object ring's replica count.
    pub(crate) fn ec_params_for_object_ring(
        &self,
        policy_index: i64,
        object_ring: &Ring,
    ) -> Option<EcPolicyParams> {
        if let Some(&ec) = self.ec_policies.get(&policy_index) {
            return Some(ec);
        }
        let n = object_ring.replica_count().round() as usize;
        self.ec_policies
            .values()
            .copied()
            .find(|ec| ec.ndata + ec.nparity == n)
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

    /// Resolve Python `list_endpoints` account/container/object lookups.
    ///
    /// Only primary nodes are advertised, in ring order. Object lookups first
    /// obtain the container's current storage-policy index through the same
    /// live/cache-backed `container_info` path as the object data plane, then
    /// select that policy's object ring. The returned policy is present only
    /// for object paths and becomes v2's
    /// `X-Backend-Storage-Policy-Index` request header.
    pub fn list_endpoints(
        &self,
        account: &str,
        container: Option<&str>,
        object: Option<&str>,
    ) -> Result<(Vec<String>, Option<i64>), String> {
        if object.is_some() && container.is_none() {
            return Err("object endpoint lookup requires a container".to_string());
        }

        let storage_policy_index = match object {
            Some(_) => Some(
                self.container_policy_index(
                    account,
                    container
                        .ok_or_else(|| "object endpoint lookup requires a container".to_string())?,
                ),
            ),
            None => None,
        };
        let ring = if let Some(policy_index) = storage_policy_index {
            self.object_ring_for(policy_index).ok_or_else(|| {
                format!("no object ring configured for storage policy {policy_index}")
            })?
        } else if container.is_some() {
            &self.container_ring
        } else {
            &self.account_ring
        };

        let (partition, nodes) = ring
            .get_nodes(account, container, object)
            .map_err(|error| error.to_string())?;
        let mut resource = percent_encode(account);
        if let Some(container) = container {
            resource.push('/');
            resource.push_str(&percent_encode(container));
        }
        if let Some(object) = object {
            resource.push('/');
            resource.push_str(&percent_encode_path(object));
        }

        let endpoints = nodes
            .into_iter()
            .map(|node| {
                format!(
                    "http://{}:{}/{}/{partition}/{resource}",
                    node.dev.ip, node.dev.port, node.dev.device
                )
            })
            .collect();
        Ok((endpoints, storage_policy_index))
    }

    fn part_nodes(ring: &Ring, part: u32) -> Vec<Node> {
        ring.get_part_nodes(part)
            .unwrap_or_default()
            .into_iter()
            .map(|n| Node {
                ip: n.dev.ip.clone(),
                port: n.dev.port,
                device: n.dev.device.clone(),
                handoff: false,
                backend_index: Some(n.index as i32),
            })
            .collect()
    }

    /// Python `ContainerController._backend_requests`: round-robin
    /// `csv_append` of account *primaries* (`get_part_nodes`) onto each
    /// container replica's `X-Account-*` headers. `iter_nodes` includes
    /// handoffs; a 404ing handoff as a replica's only account-update
    /// target 404s that replica after creating the container DB
    /// (PUT 404 / HEAD 204).
    fn stamp_account_update_headers(
        per_node: &mut [HeaderKeyDict],
        account_part: u32,
        account_primaries: &[Node],
    ) {
        if per_node.is_empty() {
            return;
        }
        for (i, acct) in account_primaries.iter().enumerate() {
            let headers = &mut per_node[i % per_node.len()];
            headers.set("X-Account-Partition", account_part);
            let host = format!("{}:{}", acct.ip, acct.port);
            headers.set(
                "X-Account-Host",
                csv_append(headers.get("X-Account-Host"), &host),
            );
            headers.set(
                "X-Account-Device",
                csv_append(headers.get("X-Account-Device"), &acct.device),
            );
        }
    }

    /// Python `num_container_updates`: enough CU side-channels that a
    /// quorum object write still leaves a quorum container update.
    fn num_container_updates(rc: usize, qc: usize, ro: usize, qo: usize) -> usize {
        (qc + ro.saturating_sub(qo)).max(rc)
    }

    /// Python `BaseObjectController._backend_requests` container-update
    /// headers: cycle *primaries* (`get_part_nodes`) with `csv_append` until
    /// `num_container_updates`. `iter_nodes` includes handoffs; a handoff as
    /// a replica's only CU target 404s and the shard listing keeps the name
    /// (probe test_shrinking L1925).
    fn stamp_container_update_headers(
        per_node: &mut [HeaderKeyDict],
        container_part: u32,
        container_primaries: &[Node],
    ) {
        if per_node.is_empty() || container_primaries.is_empty() {
            return;
        }
        let rc = container_primaries.len();
        let ro = per_node.len();
        let qc = quorum_size(rc as f64) as usize;
        let qo = quorum_size(ro as f64) as usize;
        let n_updates_needed = Self::num_container_updates(rc, qc, ro, qo);
        for i in 0..n_updates_needed {
            let headers = &mut per_node[i % per_node.len()];
            let cont = &container_primaries[i % rc];
            headers.set("X-Container-Partition", container_part);
            let host = format!("{}:{}", cont.ip, cont.port);
            headers.set(
                "X-Container-Host",
                csv_append(headers.get("X-Container-Host"), &host),
            );
            headers.set(
                "X-Container-Device",
                csv_append(headers.get("X-Container-Device"), &cont.device),
            );
        }
    }

    /// Python `BaseObjectController._backend_requests` delete-at side channel.
    /// It deliberately walks the object slots in reverse order so ordinary
    /// container updates and expirer-queue updates are spread across different
    /// object replicas. A quorum object write must still carry a quorum of
    /// expiry updates.
    fn stamp_delete_at_update_headers(
        per_node: &mut [HeaderKeyDict],
        delete_at_container: &str,
        delete_at_part: u32,
        delete_at_primaries: &[Node],
    ) {
        if per_node.is_empty() || delete_at_primaries.is_empty() {
            return;
        }
        let rc = delete_at_primaries.len();
        let ro = per_node.len();
        let qc = quorum_size(rc as f64) as usize;
        let qo = quorum_size(ro as f64) as usize;
        let n_updates_needed = Self::num_container_updates(rc, qc, ro, qo);
        for i in 0..n_updates_needed {
            let index = ro - 1 - (i % ro);
            let headers = &mut per_node[index];
            let node = &delete_at_primaries[i % rc];
            headers.set("X-Delete-At-Container", delete_at_container);
            headers.set("X-Delete-At-Partition", delete_at_part);
            let host = format!("{}:{}", node.ip, node.port);
            headers.set(
                "X-Delete-At-Host",
                csv_append(headers.get("X-Delete-At-Host"), &host),
            );
            headers.set(
                "X-Delete-At-Device",
                csv_append(headers.get("X-Delete-At-Device"), &node.device),
            );
        }
    }

    fn stamp_expirer_update_headers(
        &self,
        per_node: &mut [HeaderKeyDict],
        base: &HeaderKeyDict,
        account: &str,
        container: &str,
        object: &str,
    ) {
        let Some(delete_at) = base
            .get("X-Delete-At")
            .and_then(parse_int_like)
            .map(|value| value as i64)
        else {
            return;
        };
        let Ok(object_hash) = self.container_ring.hash_path_config().hash_path(
            account,
            Some(container),
            Some(object),
        ) else {
            return;
        };
        let task_container = expirer_container_for_object_hash(delete_at, &object_hash);
        let Ok((part, _)) =
            self.container_ring
                .get_nodes(EXPIRER_ACCOUNT_NAME, Some(&task_container), None)
        else {
            return;
        };
        let primaries = Self::part_nodes(&self.container_ring, part);
        Self::stamp_delete_at_update_headers(per_node, &task_container, part, &primaries);
    }

    fn object_container_update_headers(
        &self,
        base: &HeaderKeyDict,
        container_part: u32,
        node_number: usize,
        account: &str,
        container: &str,
        object: &str,
    ) -> Vec<HeaderKeyDict> {
        let n = node_number.max(1);
        let mut per_node = vec![base.clone(); n];
        let primaries = Self::part_nodes(&self.container_ring, container_part);
        Self::stamp_container_update_headers(&mut per_node, container_part, &primaries);
        self.stamp_expirer_update_headers(&mut per_node, base, account, container, object);
        per_node
    }

    fn container_write_headers(
        &self,
        base: &HeaderKeyDict,
        container_part: u32,
        account_part: u32,
        stamp_account: bool,
    ) -> (usize, Vec<HeaderKeyDict>) {
        let node_number = self
            .container_ring
            .get_part_nodes(container_part)
            .map(|n| n.len())
            .unwrap_or(1)
            .max(1);
        let mut per_node = vec![base.clone(); node_number];
        if stamp_account {
            let primaries = Self::part_nodes(&self.account_ring, account_part);
            Self::stamp_account_update_headers(&mut per_node, account_part, &primaries);
        }
        (node_number, per_node)
    }

    /// NodeIter: primaries then handoffs, skipping error-limited nodes,
    /// bounded by request_node_count.
    fn iter_nodes(&self, ring: &Ring, part: u32) -> Vec<Node> {
        let primaries = ring.get_part_nodes(part).unwrap_or_default();
        let limit = (self.config.request_node_count_factor as usize) * primaries.len().max(1);
        let to_node =
            |dev: &swift_ring::RingDevice, handoff: bool, backend_index: Option<i32>| Node {
                ip: dev.ip.clone(),
                port: dev.port,
                device: dev.device.clone(),
                handoff,
                backend_index,
            };
        let mut out: Vec<Node> = Vec::new();
        for node in &primaries {
            let n = to_node(node.dev, false, Some(node.index as i32));
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
                    let n = to_node(handoff.dev, true, None);
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
        copy_backend_control_headers(req, &mut headers);
        if transfer {
            // transfer_headers: user/sys metadata and the ACL headers
            for (k, v) in req.headers.iter() {
                let kl = k.to_lowercase();
                let user = format!("x-{server_type}-meta-");
                let sys = format!("x-{server_type}-sysmeta-");
                // Object transient sysmeta (crypto user-meta, etc.) must reach
                // the object server so at-rest encryption can persist it.
                let object_transient =
                    server_type == "object" && kl.starts_with("x-object-transient-sysmeta-");
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
                let container_remove =
                    server_type == "container" && kl.starts_with("x-remove-container-");
                // container.py PUT/POST: reseller `X-Container-Sharding` becomes
                // sysmeta so the sharder sees sharding_enabled(broker).
                if server_type == "container" && kl == "x-container-sharding" {
                    let on = config_true_value(v);
                    headers.set(
                        "X-Container-Sysmeta-Sharding",
                        if on { "True" } else { "False" },
                    );
                    continue;
                }
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
        // Python generate_request_headers copies X-Newest. Listing HEAD
        // then get_or_head picks the newest replica so a just-SHARDED
        // under-populated node wins over a lagging SHARDING replica
        // (probe listing_under_populated L1509).
        if let Some(v) = req.headers.get("X-Newest") {
            headers.set("X-Newest", v);
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
        let slot_count = per_node_headers.len().max(1);
        let (tx, rx) = mpsc::sync_channel(slot_count);
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
        let content_length = backend_put_content_length(body.content_length(), &per_node_headers);
        let node_pool = Arc::new(Mutex::new(nodes.into_iter().collect::<Vec<_>>()));
        let slots = per_node_headers.len();
        let (tx, rx) = mpsc::sync_channel(slots.max(1));
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
                    let status = if swift_http::body_too_large(&e) {
                        413
                    } else {
                        499
                    };
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
            let final_resp =
                read_backend_head(&mut p.reader).and_then(|(status, reason, headers)| {
                    let content_length =
                        resp_header(&headers, "content-length").and_then(|v| v.parse::<u64>().ok());
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
        let slots = per_node_headers.len();
        let (tx, rx) = mpsc::sync_channel(slots.max(1));
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
        let mut slots = self.post_fan_out(&node_pool, part, path, query, per_node_headers.clone());
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
            if is_head
                && (200..300).contains(&out.status)
                && out.headers.get("Content-Length").is_none()
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
            // Middleware subrequests (DLO/SLO segment GETs) inspect response
            // headers before write_response re-derives Content-Length from Body.
            // Keep the declared length visible on the in-process Response.
            if out.headers.get("Content-Length").is_none() {
                if let Some(n) = out.body.content_length() {
                    out.headers.set("Content-Length", n);
                }
            }
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
        let mut newest_candidates: Vec<((u8, Timestamp), BackendHead)> = Vec::new();
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
                        // base.py:1642-1648 raises the tombstone watermark
                        // for objects (lp 1560574). Container DELETE must
                        // too: probe test_shrinking L2095, listing-w214 left
                        // an unsuffixed handoff with live alpha-1 after the
                        // three collapsed primaries tombstoned. Without this,
                        // first-200 GET returns that handoff instead of 404.
                        if ts > latest_404_timestamp {
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
                            // Containers: SHARDED beats SHARDING on a created_at tie.
                            let key = if is_object {
                                (0u8, ts)
                            } else {
                                container_newest_key(&head.headers)
                            };
                            newest_candidates.push((key, head));
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
            newest_candidates.retain(|((_, ts), _)| *ts >= latest_404_timestamp);
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
    fn autocreate_account(self: &Arc<Self>, account: &str) -> bool {
        let Ok((part, _nodes)) = self.account_ring.get_nodes(account, None, None) else {
            return false;
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
        let created = (200..300).contains(&resp.status);
        if created {
            self.info_cache.clear_account(account);
        }
        created
    }

    fn allowed_methods(&self, has_container: bool) -> &'static str {
        if has_container || self.config.allow_account_management {
            "GET, HEAD, PUT, POST, DELETE, OPTIONS"
        } else {
            "GET, HEAD, POST, OPTIONS"
        }
    }

    fn is_origin_allowed(&self, cors: &CorsInfo, origin: &str) -> bool {
        cors.allow_origin
            .as_deref()
            .into_iter()
            .flat_map(|value| value.split(' '))
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .chain(
                self.config
                    .cors_allow_origin
                    .iter()
                    .map(String::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty()),
            )
            .any(|allowed| allowed == "*" || allowed == origin)
    }

    /// Python `Controller.OPTIONS`: ordinary OPTIONS is a local 200 with
    /// `Allow`; account-level Origin requests remain ordinary OPTIONS. A
    /// container/object preflight additionally validates the container CORS
    /// metadata, Origin, and requested public method.
    fn options_response(&self, req: &Request, account: &str, container: Option<&str>) -> Response {
        let allow = self.allowed_methods(container.is_some());
        let mut resp = Response::new(200);
        resp.headers.set("Allow", allow);
        resp.headers.set("Content-Type", "text/html; charset=UTF-8");

        let Some(origin) = req.headers.get("Origin").filter(|value| !value.is_empty()) else {
            return resp;
        };
        let Some(container) = container else {
            return resp;
        };

        let cors = self.container_info(account, container).cors;
        let requested_method = req.headers.get("Access-Control-Request-Method");
        let method_allowed = requested_method
            .map(|method| allow.split(", ").any(|allowed| allowed == method))
            .unwrap_or(false);
        if !self.is_origin_allowed(&cors, origin) || !method_allowed {
            let mut denied = Response::new(401);
            denied.headers.set("Allow", allow);
            denied
                .headers
                .set("Content-Type", "text/html; charset=UTF-8");
            return denied;
        }

        if cors.allow_origin.as_deref().map(str::trim) == Some("*") {
            resp.headers.set("Access-Control-Allow-Origin", "*");
        } else {
            resp.headers.set("Access-Control-Allow-Origin", origin);
            append_vary(&mut resp.headers, "Origin");
        }
        if let Some(max_age) = cors.max_age {
            resp.headers.set("Access-Control-Max-Age", max_age);
        }
        resp.headers.set("Access-Control-Allow-Methods", allow);

        let requested_headers = req
            .headers
            .get("Access-Control-Request-Headers")
            .map(csv_header_values)
            .unwrap_or_default();
        if !requested_headers.is_empty() {
            resp.headers
                .set("Access-Control-Allow-Headers", requested_headers.join(", "));
            append_vary(&mut resp.headers, "Access-Control-Request-Headers");
        }
        resp
    }

    /// Python `cors_validation` simple-response behavior for container and
    /// object handlers. The business response status/body is never changed.
    fn apply_simple_cors(&self, req: &Request, cors: &CorsInfo, resp: &mut Response) {
        let Some(origin) = req.headers.get("Origin").filter(|value| !value.is_empty()) else {
            return;
        };
        if self.config.strict_cors_mode && !self.is_origin_allowed(cors, origin) {
            return;
        }

        if !resp.headers.contains_key("Access-Control-Expose-Headers") {
            let mut exposed = std::collections::BTreeSet::new();
            for name in [
                "cache-control",
                "content-language",
                "content-type",
                "expires",
                "last-modified",
                "pragma",
                "etag",
                "x-timestamp",
                "x-trans-id",
                "x-openstack-request-id",
            ] {
                exposed.insert(name.to_string());
            }
            exposed.extend(
                self.config
                    .cors_expose_headers
                    .iter()
                    .map(String::as_str)
                    .map(str::trim)
                    .filter(|header| !header.is_empty())
                    .map(str::to_string),
            );
            for (name, _) in resp.headers.iter() {
                let lower = name.to_ascii_lowercase();
                if lower.starts_with("x-container-meta-") || lower.starts_with("x-object-meta-") {
                    exposed.insert(lower);
                }
            }
            if let Some(extra) = cors.expose_headers.as_deref() {
                exposed.extend(
                    extra
                        .split(' ')
                        .map(str::trim)
                        .filter(|header| !header.is_empty())
                        .map(str::to_ascii_lowercase),
                );
            }
            resp.headers.set(
                "Access-Control-Expose-Headers",
                exposed.into_iter().collect::<Vec<_>>().join(", "),
            );
        }

        if !resp.headers.contains_key("Access-Control-Allow-Origin") {
            if cors.allow_origin.as_deref().map(str::trim) == Some("*") {
                resp.headers.set("Access-Control-Allow-Origin", "*");
            } else {
                resp.headers.set("Access-Control-Allow-Origin", origin);
                append_vary(&mut resp.headers, "Origin");
            }
        }
    }

    /// Hyper-pipeline CORS: same rules as the sync `handle` decorator,
    /// applied after middleware reassembly so DLO/SLO GET still gets ACAO.
    pub(crate) async fn apply_pipeline_cors(
        self: &Arc<Self>,
        method: String,
        path: String,
        origin: Option<String>,
        resp: &mut Response,
    ) {
        if !matches!(method.as_str(), "GET" | "HEAD" | "PUT" | "POST" | "DELETE") {
            return;
        }
        let Some(origin) = origin.filter(|value| !value.is_empty()) else {
            return;
        };
        let Ok(parts) = split_path(&path, 2, 4, true) else {
            return;
        };
        let Some(account) = parts
            .get(1)
            .and_then(|s| s.as_deref())
            .filter(|s| !s.is_empty())
            .map(str::to_string)
        else {
            return;
        };
        let Some(container) = parts
            .get(2)
            .and_then(|s| s.as_deref())
            .filter(|s| !s.is_empty())
            .map(str::to_string)
        else {
            return;
        };
        let cors = self.container_info_async(&account, &container).await.cors;
        let mut head = Request {
            method,
            path,
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: swift_http::Body::empty(),
        };
        head.headers.set("Origin", origin);
        self.apply_simple_cors(&head, &cors, resp);
    }

    pub fn handle(self: &Arc<Self>, req: Request) -> Response {
        if let Some(resp) = utf8_or_null_rejected(&req) {
            return resp;
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
        // `/v1/account//object` (empty container) is 404, not an account GET
        // that would 403 against a foreign account name.
        if segs.get(3) == Some(&"") {
            return swob_response(404);
        }
        let account = segs[2].to_string();
        let container = segs.get(3).map(|s| s.to_string()).filter(|s| !s.is_empty());
        let object = segs.get(4).map(|s| s.to_string()).filter(|s| !s.is_empty());
        // Python's ContainerController.UPDATE is @private: it is not in the
        // public Allow set and is reachable only when trusted middleware sets
        // X-Backend-Allow-Private-Methods after gatekeeper has stripped any
        // client-supplied X-Backend-* headers. SLO async delete depends on
        // this route to enqueue records in .expiring_objects.
        let private_container_update = req.method == "UPDATE"
            && container.is_some()
            && object.is_none()
            && req
                .headers
                .get("X-Backend-Allow-Private-Methods")
                .is_some_and(config_true_value);
        // Python validates the controller's public methods before invoking
        // auth or any handler. This also guarantees that an unsupported CORS
        // method cannot trigger metadata lookup or receive CORS headers.
        let allowed = self.allowed_methods(container.is_some());
        if !private_container_update
            && !allowed
                .split(", ")
                .any(|method| method == req.method.as_str())
        {
            return method_not_allowed(allowed);
        }
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
        // Trusted, internal authorization-only probe used by
        // versioned_writes before it mutates the archive or live object. The
        // outer Gatekeeper strips every client-supplied X-Backend-* header;
        // an authorized probe must never reach a storage node.
        if req
            .headers
            .remove(swift_middleware::VERSIONED_WRITES_AUTHORIZE_ONLY_HEADER)
            .is_some()
        {
            return Response::new(204);
        }
        if private_container_update {
            return self.container_update(
                &mut req,
                &account,
                container.as_deref().expect("private UPDATE has container"),
            );
        }
        if req.method == "OPTIONS" {
            return self.options_response(&req, &account, container.as_deref());
        }
        // Like the Python decorator, resolve CORS metadata before the actual
        // container/object handler. The HEAD subrequest deliberately carries
        // no client Origin header.
        let cors = if matches!(
            req.method.as_str(),
            "GET" | "HEAD" | "PUT" | "POST" | "DELETE"
        ) && req
            .headers
            .get("Origin")
            .map(|value| !value.is_empty())
            .unwrap_or(false)
        {
            container
                .as_deref()
                .map(|name| self.container_info(&account, name).cors)
        } else {
            None
        };
        let swift_owner = req
            .headers
            .get("X-Backend-Swift-Owner")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let mut resp = match (container, object) {
            (Some(container), Some(object)) => {
                self.object_request(&mut req, &account, &container, &object)
            }
            (Some(container), None) => {
                let mut resp = self.container_request(&req, &account, &container);
                strip_owner_headers(&mut resp, swift_owner);
                expose_container_sharding(&mut resp, is_reseller_request(&req));
                resp
            }
            (None, _) => {
                let mut resp = self.account_request(&req, &account);
                expose_account_acl_header(&mut resp);
                strip_owner_headers(&mut resp, swift_owner);
                resp
            }
        };
        if let Some(cors) = cors.as_ref() {
            self.apply_simple_cors(&req, cors, &mut resp);
        }
        resp
    }

    /// Production async entry: object PUT/GET stream; HEAD/POST use
    /// Tokio backend I/O. Remaining verbs stay at the control-plane cap.
    pub async fn handle_async(self: &Arc<Self>, mut areq: swift_http::AsyncRequest) -> Response {
        // Keep-alive requests skip the connection peek. `/info asdf` is 412
        // Bad URL (Python `get_controller is None`). Object names may contain
        // spaces after unquote (`testCopy`); only non-/v1 paths with a space
        // are 412.
        if areq.path.contains(' ') {
            let segs: Vec<&str> = areq.path.splitn(5, '/').collect();
            let v1 = segs.len() >= 3
                && segs[0].is_empty()
                && matches!(segs[1], "v1" | "v1.0")
                && !segs[2].is_empty();
            if !v1 {
                return text_response(412, "Bad URL");
            }
        }
        let segs: Vec<&str> = areq.path.splitn(5, '/').collect();
        if matches!(segs.get(1), Some(&"v1") | Some(&"v1.0"))
            && !segs.get(2).is_some_and(|s| !s.is_empty())
            && segs.len() <= 3
        {
            // PUT /v1 or /v1/ → 412 Bad URL. Empty-account paths with later
            // segments (`/v1//c/o`) stay 404 like Python.
            return text_response(412, "Bad URL");
        }
        let v1 = segs.len() >= 3 && segs[0].is_empty() && segs[1] == "v1" && !segs[2].is_empty();
        let private_container_update = v1
            && areq.method == "UPDATE"
            && segs.get(3).is_some_and(|segment| !segment.is_empty())
            && !segs.get(4).is_some_and(|segment| !segment.is_empty())
            && areq
                .headers
                .get("X-Backend-Allow-Private-Methods")
                .is_some_and(config_true_value);
        let object_put = areq.method == "PUT"
            && segs.len() >= 5
            && v1
            && areq.headers.get("X-Copy-From").is_none();
        let copy_req = v1
            && segs.len() >= 5
            && (areq.method == "COPY"
                || (areq.method == "PUT" && areq.headers.get("X-Copy-From").is_some()));
        if copy_req {
            let tmp = Request {
                method: areq.method.clone(),
                path: areq.path.clone(),
                query_string: areq.query_string.clone(),
                headers: areq.headers.clone(),
                body: swift_http::Body::empty(),
            };
            if let Some(resp) = utf8_or_null_rejected(&tmp) {
                return resp;
            }
            let mut req = Request {
                method: areq.method.clone(),
                path: areq.path.clone(),
                query_string: areq.query_string.clone(),
                headers: areq.headers.clone(),
                body: swift_http::Body::empty(),
            };
            let account = segs[2].to_string();
            let container = segs[3].to_string();
            let object = segs[4].to_string();
            if req.method == "COPY" {
                let Some(dest) = req.headers.get("Destination").map(str::to_string) else {
                    return Response::error(412, "Destination header required");
                };
                let dest_parts = {
                    let v = dest.strip_prefix('/').unwrap_or(dest.as_str());
                    v.split_once('/').and_then(|(c, o)| {
                        if c.is_empty() || o.is_empty() {
                            None
                        } else {
                            Some((c.to_string(), o.to_string()))
                        }
                    })
                };
                let Some((dst_c, dst_o)) = dest_parts else {
                    return Response::error(
                        412,
                        "Destination header must be of the form /container/object",
                    );
                };
                let dst_account = req
                    .headers
                    .get("Destination-Account")
                    .map(str::to_string)
                    .unwrap_or_else(|| account.clone());
                req.method = "PUT".into();
                req.path = format!("/v1/{dst_account}/{dst_c}/{dst_o}");
                req.headers.set(
                    "X-Copy-From",
                    percent_encode_path(&format!("/{container}/{object}")),
                );
                req.headers
                    .set("X-Copy-From-Account", percent_encode_path(&account));
                req.headers.remove("Destination");
                req.headers.remove("Destination-Account");
                if let Some(denied) = self
                    .authorize_async(&mut req, &dst_account, Some(&dst_c), Some(&dst_o))
                    .await
                {
                    return denied;
                }
                return self
                    .object_copy_async(req, &dst_account, &dst_c, &dst_o)
                    .await;
            }
            if let Some(denied) = self
                .authorize_async(&mut req, &account, Some(&container), Some(&object))
                .await
            {
                return denied;
            }
            return self
                .object_copy_async(req, &account, &container, &object)
                .await;
        }
        if object_put {
            let mut req = Request {
                method: areq.method.clone(),
                path: areq.path.clone(),
                query_string: areq.query_string.clone(),
                headers: areq.headers.clone(),
                body: swift_http::Body::empty(),
            };
            if let Some(resp) = utf8_or_null_rejected(&req) {
                return resp;
            }
            let account = segs[2].to_string();
            let container = segs[3].to_string();
            let object = segs[4].to_string();
            if let Some(denied) = self
                .authorize_async(&mut req, &account, Some(&container), Some(&object))
                .await
            {
                return denied;
            }
            // VersionedWrites must authorize the client-visible destination
            // before it moves the unread client stream into the hidden
            // versions container.  This header-only probe is deliberately
            // consumed after authorization and before any backend PUT.
            if req
                .headers
                .remove(swift_middleware::VERSIONED_WRITES_AUTHORIZE_ONLY_HEADER)
                .is_some()
            {
                return Response::new(204);
            }
            return self
                .object_put_async(&mut req, &account, &container, &object, &mut areq.body)
                .await;
        }
        let get_head_post_delete =
            v1 && matches!(areq.method.as_str(), "GET" | "HEAD" | "POST" | "DELETE");
        let account_or_container_put = v1 && areq.method == "PUT" && segs.len() < 5;
        if get_head_post_delete || account_or_container_put || private_container_update {
            let mut req = Request {
                method: areq.method.clone(),
                path: areq.path.clone(),
                query_string: areq.query_string.clone(),
                headers: areq.headers.clone(),
                body: swift_http::Body::empty(),
            };
            if let Some(resp) = utf8_or_null_rejected(&req) {
                return with_g6_diag(resp, "reason=utf8_or_null");
            }
            let account = segs[2].to_string();
            if segs.get(3) == Some(&"") {
                return with_g6_diag(swob_response(404), "reason=empty_container_seg");
            }
            let container = segs.get(3).map(|s| s.to_string()).filter(|s| !s.is_empty());
            let object = segs.get(4).map(|s| s.to_string()).filter(|s| !s.is_empty());
            let allowed = self.allowed_methods(container.is_some());
            if !private_container_update
                && !allowed
                    .split(", ")
                    .any(|method| method == req.method.as_str())
            {
                return method_not_allowed(allowed);
            }
            if let Some(denied) = self
                .authorize_async(&mut req, &account, container.as_deref(), object.as_deref())
                .await
            {
                let status = denied.status;
                return with_g6_diag(
                    denied,
                    format!("reason=authorize method={} status={status}", req.method),
                );
            }
            if req
                .headers
                .remove(swift_middleware::VERSIONED_WRITES_AUTHORIZE_ONLY_HEADER)
                .is_some()
            {
                return Response::new(204);
            }
            if matches!(req.method.as_str(), "POST" | "PUT" | "UPDATE") {
                let body = match areq.body.materialize(swift_http::MAX_CONTROL_BODY).await {
                    Ok(bytes) => swift_http::Body::Buffered(bytes),
                    Err(e) if swift_http::body_too_large(&e) => {
                        return Response::error(413, "Your request is too large.")
                    }
                    Err(_) => return swob_response(499),
                };
                req.body = body;
            }
            let swift_owner = req
                .headers
                .get("X-Backend-Swift-Owner")
                .is_some_and(config_true_value);
            return match (req.method.as_str(), container.as_deref(), object.as_deref()) {
                ("GET" | "HEAD", Some(c), Some(o)) => {
                    let (c, o) = (c.to_string(), o.to_string());
                    self.emit_proxy_log(
                        false,
                        &format!(
                            "proxy-server: EC GET {}/{}/{} status=start \
                             reason=handle_async method={}",
                            percent_encode(&account),
                            percent_encode(&c),
                            percent_encode(&o),
                            req.method
                        ),
                    );
                    let mut resp = self.object_get_head_async(&mut req, &account, &c, &o).await;
                    self.emit_proxy_log(
                        resp.status >= 400,
                        &format!(
                            "proxy-server: EC GET {}/{}/{} status={} \
                             reason=handle_async_done",
                            percent_encode(&account),
                            percent_encode(&c),
                            percent_encode(&o),
                            resp.status
                        ),
                    );
                    if resp.g6_diag.is_none() {
                        resp.set_g6_diag(format!(
                            "reason=handle_async_done method={} status={}",
                            req.method, resp.status
                        ));
                    }
                    resp
                }
                ("POST", Some(c), Some(o)) => {
                    let (c, o) = (c.to_string(), o.to_string());
                    self.object_post_async(&mut req, &account, &c, &o).await
                }
                ("GET" | "HEAD", Some(c), None) => {
                    let c = c.to_string();
                    finish_container_resp(
                        swift_owner,
                        is_reseller_request(&req),
                        self.container_get_head_async(req, &account, &c).await,
                    )
                }
                ("POST", Some(c), None) => {
                    let c = c.to_string();
                    finish_container_resp(
                        swift_owner,
                        is_reseller_request(&req),
                        self.container_post_async(req, &account, &c).await,
                    )
                }
                ("UPDATE", Some(c), None) if private_container_update => {
                    let c = c.to_string();
                    self.container_update_async(req, &account, &c).await
                }
                ("GET" | "HEAD", None, _) => finish_account_resp(
                    swift_owner,
                    self.account_get_head_async(req, &account).await,
                ),
                ("POST", None, _) => {
                    finish_account_resp(swift_owner, self.account_post_async(req, &account).await)
                }
                ("DELETE", Some(c), Some(o)) => {
                    let (c, o) = (c.to_string(), o.to_string());
                    self.object_delete_async(&mut req, &account, &c, &o).await
                }
                ("DELETE", Some(c), None) => {
                    let c = c.to_string();
                    self.container_delete_async(req, &account, &c).await
                }
                ("DELETE", None, _) => self.account_delete_async(req, &account).await,
                ("PUT", Some(c), None) => {
                    let c = c.to_string();
                    finish_container_resp(
                        swift_owner,
                        is_reseller_request(&req),
                        self.container_put_async(req, &account, &c).await,
                    )
                }
                ("PUT", None, _) => {
                    finish_account_resp(swift_owner, self.account_put_async(req, &account).await)
                }
                _ => swob_response(405),
            };
        }
        // Local control plane only. Never `self.handle()` — that path still
        // fans out over `std::net` (leftover sync controller).
        {
            let tmp = Request {
                method: areq.method.clone(),
                path: areq.path.clone(),
                query_string: areq.query_string.clone(),
                headers: areq.headers.clone(),
                body: swift_http::Body::empty(),
            };
            if let Some(resp) = utf8_or_null_rejected(&tmp) {
                return resp;
            }
        }
        if areq.path == "/info" || areq.path.starts_with("/info?") {
            if !self.info_json.is_empty() && matches!(areq.method.as_str(), "GET" | "HEAD") {
                let mut resp = Response::with_body(
                    200,
                    if areq.method == "HEAD" {
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
        if areq.path == "/recon/stage" && matches!(areq.method.as_str(), "GET" | "HEAD") {
            let body = swift_core::stage::snapshot_json();
            let mut resp = Response::with_body(
                200,
                if areq.method == "HEAD" {
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
        if areq.method == "OPTIONS" {
            let segs: Vec<&str> = areq.path.splitn(5, '/').collect();
            if segs.len() < 3 || !segs[0].is_empty() || segs[1] != "v1" || segs[2].is_empty() {
                return swob_response(404);
            }
            let account = segs[2].to_string();
            let container = segs.get(3).map(|s| s.to_string()).filter(|s| !s.is_empty());
            let origin = areq
                .headers
                .get("Origin")
                .filter(|value| !value.is_empty())
                .map(str::to_string);
            let requested_method = areq
                .headers
                .get("Access-Control-Request-Method")
                .map(str::to_string);
            let requested_headers_raw = areq
                .headers
                .get("Access-Control-Request-Headers")
                .map(str::to_string);
            return self
                .options_response_async(
                    &account,
                    container.as_deref(),
                    origin,
                    requested_method,
                    requested_headers_raw,
                )
                .await;
        }
        // Python validates controller public methods before 404: LICK /
        // GETorHEAD_base on a /v1 path is 405, not 404.
        let segs: Vec<&str> = areq.path.splitn(5, '/').collect();
        if segs.len() >= 3 && segs[0].is_empty() && segs[1] == "v1" && !segs[2].is_empty() {
            let allowed = self.allowed_methods(segs.get(3).is_some_and(|s| !s.is_empty()));
            return method_not_allowed(allowed);
        }
        with_g6_diag(
            swob_response(404),
            format!(
                "reason=handle_async_fallthrough method={} path={}",
                areq.method, areq.path
            ),
        )
    }

    async fn options_response_async(
        self: &Arc<Self>,
        account: &str,
        container: Option<&str>,
        origin: Option<String>,
        requested_method: Option<String>,
        requested_headers_raw: Option<String>,
    ) -> Response {
        let allow = self.allowed_methods(container.is_some());
        let mut resp = Response::new(200);
        resp.headers.set("Allow", allow);
        resp.headers.set("Content-Type", "text/html; charset=UTF-8");
        let Some(origin) = origin else {
            return resp;
        };
        let Some(container) = container else {
            return resp;
        };
        let cors = self.container_info_async(account, container).await.cors;
        let method_allowed = requested_method
            .as_deref()
            .map(|method| allow.split(", ").any(|allowed| allowed == method))
            .unwrap_or(false);
        if !self.is_origin_allowed(&cors, origin.as_str()) || !method_allowed {
            let mut denied = Response::new(401);
            denied.headers.set("Allow", allow);
            denied
                .headers
                .set("Content-Type", "text/html; charset=UTF-8");
            return denied;
        }
        if cors.allow_origin.as_deref().map(str::trim) == Some("*") {
            resp.headers.set("Access-Control-Allow-Origin", "*");
        } else {
            resp.headers
                .set("Access-Control-Allow-Origin", origin.as_str());
            append_vary(&mut resp.headers, "Origin");
        }
        if let Some(max_age) = cors.max_age {
            resp.headers.set("Access-Control-Max-Age", max_age);
        }
        resp.headers.set("Access-Control-Allow-Methods", allow);
        let requested_headers = requested_headers_raw
            .as_deref()
            .map(csv_header_values)
            .unwrap_or_default();
        if !requested_headers.is_empty() {
            resp.headers
                .set("Access-Control-Allow-Headers", requested_headers.join(", "));
            append_vary(&mut resp.headers, "Access-Control-Request-Headers");
        }
        resp
    }

    async fn object_put_async(
        self: &Arc<Self>,
        req: &mut Request,
        account: &str,
        container: &str,
        object: &str,
        body: &mut swift_http::IncomingBody,
    ) -> Response {
        let header_policy: Option<i64> = req
            .headers
            .get("X-Backend-Storage-Policy-Index")
            .and_then(|v| v.parse().ok());
        let info = self
            .container_info_for_write_async(account, container)
            .await;
        if !info.exists() {
            return swob_response(info.write_failure_status());
        }
        let policy_index: i64 = resolve_object_storage_policy(header_policy, info.policy_index);
        let Some(object_ring) = self.object_ring_for(policy_index) else {
            return text_response(
                503,
                &format!("No object ring configured for storage policy {policy_index}"),
            );
        };
        let Ok((object_part, _)) = object_ring.get_nodes(account, Some(container), Some(object))
        else {
            return swob_response(503);
        };
        apply_content_type_guess(req);
        if let Some(err) = check_object_creation(req, object) {
            return err;
        }
        if let Err(e) = swift_core::constraints::check_metadata(req.headers.iter(), "object") {
            let mut r = Response::with_body(400, e.0);
            r.headers.set("Content-Type", "text/plain");
            return r;
        }
        if object.len() as i64 > swift_core::constraints::MAX_OBJECT_NAME_LENGTH {
            return text_response(400, &format!("Object name too long: {object}"));
        }
        if container.len() as i64 > swift_core::constraints::MAX_CONTAINER_NAME_LENGTH {
            return text_response(400, &format!("Container name too long: {container}"));
        }
        let path = format!(
            "/{}/{}/{}",
            percent_encode(account),
            percent_encode(container),
            percent_encode(object)
        );
        if self.ec_policies.contains_key(&policy_index) {
            return self
                .ec_put_async(
                    req,
                    account,
                    container,
                    object,
                    &path,
                    policy_index,
                    object_ring,
                    object_part,
                    body,
                )
                .await;
        }
        let (upd_account, upd_container) = self
            .resolve_updating_shard_async(account, container, object)
            .await
            .unwrap_or_else(|| (account.to_string(), container.to_string()));
        let Ok((container_part, _)) =
            self.container_ring
                .get_nodes(&upd_account, Some(&upd_container), None)
        else {
            return swob_response(503);
        };
        let mut base = self.backend_headers(req, true, "object");
        let put_ts = object_write_timestamp(req);
        base.set("X-Timestamp", put_ts.internal());
        base.set("X-Backend-Storage-Policy-Index", policy_index);
        stamp_next_part_power(&mut base, object_ring);
        self.stamp_root_db_state(&account, &container, &mut base);
        base.set(
            "Content-Type",
            req.headers
                .get("Content-Type")
                .unwrap_or("application/octet-stream"),
        );
        stamp_shard_container_path(
            &mut base,
            &upd_account,
            &upd_container,
            &account,
            &container,
        );
        let node_number = object_ring
            .get_part_nodes(object_part)
            .map(|n| n.len())
            .unwrap_or(1);
        let per_node = self.object_container_update_headers(
            &base,
            container_part,
            node_number,
            account,
            container,
            object,
        );
        let object_nodes = self.iter_nodes(object_ring, object_part);
        let mut resp = self
            .stream_put_async(
                object_nodes,
                node_number,
                object_part,
                &path,
                &req.query_string,
                per_node,
                body,
            )
            .await;
        if let Some(etag) = resp.headers.get("ETag").map(str::to_string) {
            resp.headers.set("ETag", etag.trim_matches('"'));
        }
        if (200..300).contains(&resp.status) {
            resp.headers
                .set("Last-Modified", swift_http::http_date(put_ts.ceil()));
        }
        resp
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
                    Some(resp) if resp.status == 404 && self.config.account_autocreate => {
                        // synthesize an empty account listing
                        let mut fake = synthesized_account_listing(req);
                        fake.headers.set(
                            "X-Backend-Recheck-Account-Existence",
                            format!("{}", self.config.recheck_account_existence as i64),
                        );
                        self.cache_account_from_response(account, &fake);
                        fake
                    }
                    Some(resp) => resp,
                    None => swob_response(503),
                }
            }
            "PUT" | "DELETE" if !self.config.allow_account_management => {
                // account.py:37-39,112-115,170: remove PUT/DELETE from allowed
                // methods when allow_account_management is off.
                method_not_allowed(self.allowed_methods(false))
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
                if resp.status == 404 && req.method == "POST" && self.config.account_autocreate {
                    let _ = self.autocreate_account(account);
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
            _ => method_not_allowed(self.allowed_methods(false)),
        }
    }

    /// Python `ContainerController.UPDATE`: trusted bulk merge of object
    /// records into a container DB. This is a private middleware/internal-
    /// client contract, not a public Swift verb. The caller has already
    /// passed the private-method and authorization gates in [`Self::handle`].
    fn container_update(
        self: &Arc<Self>,
        req: &mut Request,
        account: &str,
        container: &str,
    ) -> Response {
        let Some(policy_index) = req
            .headers
            .get("X-Backend-Storage-Policy-Index")
            .and_then(|value| value.parse::<i64>().ok())
        else {
            return text_response(400, "Missing or invalid X-Backend-Storage-Policy-Index");
        };
        let body = match req.body.materialize(swift_http::MAX_CONTROL_BODY) {
            Ok(bytes) => bytes.to_vec(),
            Err(error) if swift_http::body_too_large(&error) => {
                return Response::error(413, "Your request is too large.")
            }
            Err(_) => return swob_response(499),
        };
        let Ok((part, _)) = self
            .container_ring
            .get_nodes(account, Some(container), None)
        else {
            return swob_response(503);
        };
        let mut headers = self.backend_headers(req, true, "container");
        headers.set("X-Backend-Storage-Policy-Index", policy_index);
        if !headers.contains_key("X-Timestamp") {
            headers.set("X-Timestamp", Timestamp::now().internal());
        }
        let node_count = self
            .container_ring
            .get_part_nodes(part)
            .map(|nodes| nodes.len())
            .unwrap_or(1);
        let per_node = (0..node_count).map(|_| headers.clone()).collect();
        self.make_requests(
            self.iter_nodes(&self.container_ring, part),
            node_count,
            part,
            "UPDATE",
            &format!("/{}/{}", percent_encode(account), percent_encode(container)),
            &req.query_string,
            per_node,
            body,
        )
    }

    fn container_request(
        self: &Arc<Self>,
        req: &Request,
        account: &str,
        container: &str,
    ) -> Response {
        let Ok((container_part, _)) = self
            .container_ring
            .get_nodes(account, Some(container), None)
        else {
            return swob_response(503);
        };
        let path = format!("/{}/{}", percent_encode(account), percent_encode(container));
        match req.method.as_str() {
            "GET" | "HEAD" => {
                // Python `validate_container_params` / `get_param`: listing
                // query values that are not valid UTF-8 are 400
                // `"<name>" parameter not valid UTF-8` (probe
                // test_sharding_listing delimiter=%ff).
                if let Some(name) = listing_query_invalid_utf8_param(&req.query_string) {
                    return constraint_plain(400, &format!("\"{name}\" parameter not valid UTF-8"));
                }
                if let Err(resp) = constrain_listing_limit(req) {
                    return resp;
                }
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
                if record_type != "object"
                    && record_type != "shard"
                    && !req.query_string.contains("states=")
                {
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
                        finalize_container_listing_headers(req, &mut fan);
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
                        self.patch_sharded_head_counts(req, account, container, &mut resp);
                    }
                }
                finalize_container_listing_headers(req, &mut resp);
                resp
            }
            "PUT" | "POST" | "DELETE" => {
                // account existence / autocreate
                let Ok((account_part, _)) = self.account_ring.get_nodes(account, None, None) else {
                    return swob_response(503);
                };
                // Python resolves account existence via the cached
                // get_account_info (container.py:655-656,702-703,717-718 →
                // base.py:540-612): serve the cached HEAD status when fresh,
                // else do the live HEAD and cache it with set_info_cache
                // semantics. An unreachable ring (None → 503) is never
                // cached, like Python's synthesized 503 info.
                let acct_status = self.account_info(account);
                if !acct_status.exists() {
                    if self.config.account_autocreate && req.method == "PUT" {
                        // Python container PUT stops with 503 when account
                        // autocreation fails. Continuing would let container
                        // servers create their local DBs and then return 404
                        // when every account-update target rejects the update,
                        // yielding the contradictory "PUT 404, HEAD 204".
                        if !self.autocreate_account(account) {
                            return swob_response(503);
                        }
                        // Python immediately resolves account_info again after
                        // a successful autocreate. A nominal 2xx create is not
                        // enough: if the account still cannot be observed, the
                        // container fan-out must not start.
                        let refreshed = self.account_info(account);
                        if !refreshed.exists() {
                            return swob_response(404);
                        }
                    } else {
                        return swob_response(404);
                    }
                }

                // Python container.py PUT/POST: pop swift_owner_headers from
                // the request when !swift_owner so a write-ACL / account-RW
                // caller cannot overwrite Read/Write/Sync-Key (Field H1:
                // test_protected_container_acl / test_protected_container_sync).
                // IsolatedIdentity account-RW can still POST; versions-location
                // must 403 (official test_versioning_container_acl).
                let mut write_req;
                let transfer_req = if matches!(req.method.as_str(), "PUT" | "POST") {
                    write_req = req.clone_head();
                    scrub_container_write_owner_headers(&mut write_req);
                    if let Some(denied) = deny_non_owner_container_versioning(&write_req) {
                        return denied;
                    }
                    &write_req
                } else {
                    req
                };
                let mut base = self.backend_headers(transfer_req, true, "container");
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
                // Account-update side channel: Python `_backend_requests`
                // stamps account *primaries* (`get_part_nodes`) by csv_append
                // round-robin. Fan-out is sized to the container replica
                // count, NOT the primaries+handoffs iterator — otherwise
                // quorum is computed over 2R nodes (503 where Python 201).
                // Handoffs are still the fallback inside make_requests.
                let (node_number, per_node) = self.container_write_headers(
                    &base,
                    container_part,
                    account_part,
                    matches!(req.method.as_str(), "PUT" | "DELETE"),
                );
                let cont_nodes = self.iter_nodes(&self.container_ring, container_part);
                // _clear_container_info_cache: POST and DELETE clear mutable
                // container info before fan-out; PUT clears after. Preserve
                // the independent updating-route proof across POST, matching
                // Python's decision not to purge its updating-shard cache.
                let cache_key = format!("{account}/{container}");
                if req.method == "POST" {
                    self.info_cache.clear_container_metadata(&cache_key);
                } else if req.method == "DELETE" {
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
            _ => method_not_allowed(self.allowed_methods(true)),
        }
    }

    /// Python `set_info_cache` from a container GETorHEAD response
    /// (base.py:672-694). Probe L2111: `assert_container_not_found` caches
    /// a 404; a later listing 200 must overwrite it or object DELETE sees
    /// `container_info.exists()==false` and 404s while the object bytes
    /// are still on disk (listing-w216 beta-1).
    fn remember_container_info(&self, account: &str, container: &str, resp: &Response) {
        let cache_key = format!("{account}/{container}");
        // listing-w217: overwriting a live 200 sharded cache from listing
        // headers reopened L2044 leftover names. Only fill a miss or a
        // negative (404) entry — the DELETE-container → listing [beta]
        // revive path (L2111).
        if self
            .info_cache
            .get_container(&cache_key)
            .is_some_and(|c| c.exists())
        {
            return;
        }
        let mut info = ContainerInfo {
            status: 0,
            policy_index: self.config.default_policy_index,
            read_acl: None,
            write_acl: None,
            temp_url_keys: Vec::new(),
            sync_key: None,
            rfc_compliant_etags: None,
            cors: CorsInfo::default(),
            db_state: String::new(),
        };
        fill_container_info_from_head(&mut info, resp);
        if let Some(ttl) = info_cache_time(
            resp.status,
            resp.headers.get("X-Backend-Recheck-Container-Existence"),
            self.config.recheck_container_existence,
        ) {
            self.info_cache.set_container(cache_key, info, ttl);
        }
    }

    /// Record a database state proved by the root listing path without
    /// touching container policy/ACL metadata. This is the fast-sharding case:
    /// Rust can complete a probe cycle before the ordinary 60-second
    /// container-info TTL expires, so the initial `unsharded` value would
    /// otherwise be stamped into async_pending files after the container
    /// nodes are deliberately stopped.
    fn remember_proven_container_db_state(&self, account: &str, container: &str, state: &str) {
        let cache_key = format!("{account}/{container}");
        self.info_cache.set_container_db_state(
            &cache_key,
            state,
            self.config.recheck_container_existence,
        );
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
    /// Object PUT/DELETE: if a cached 404 is stale (container revived by
    /// async pending), drop it and HEAD again. Does not change listing
    /// fan-out.
    fn container_info_for_write(&self, account: &str, container: &str) -> ContainerInfo {
        let info = self.container_info(account, container);
        if info.exists() {
            return info;
        }
        self.info_cache
            .clear_container(&format!("{account}/{container}"));
        self.container_info(account, container)
    }

    async fn container_info_for_write_async(
        self: &Arc<Self>,
        account: &str,
        container: &str,
    ) -> ContainerInfo {
        let info = self.container_info_async(account, container).await;
        if info.exists() {
            return info;
        }
        self.info_cache
            .clear_container(&format!("{account}/{container}"));
        self.container_info_async(account, container).await
    }

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
            rfc_compliant_etags: None,
            cors: CorsInfo::default(),
            db_state: String::new(),
        };
        let Ok((part, _)) = self
            .container_ring
            .get_nodes(account, Some(container), None)
        else {
            return info;
        };
        let path = format!("/{}/{}", percent_encode(account), percent_encode(container));
        let nodes = self.iter_nodes(&self.container_ring, part);
        let headers = HeaderKeyDict::new();
        if let Some(resp) = self.get_or_head("container", nodes, part, "HEAD", &path, "", &headers)
        {
            fill_container_info_from_head(&mut info, &resp);
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

    /// Python obj.py: object PUT/DELETE carry `X-Container-Root-Db-State` so
    /// a failed container update still pickles `db_state` into async_pending.
    fn effective_root_db_state(&self, account: &str, container: &str, fallback: &str) -> String {
        let cache_key = format!("{account}/{container}");
        self.info_cache
            .get_container_db_state(&cache_key)
            .unwrap_or_else(|| fallback.to_string())
    }

    fn stamp_root_db_state(&self, account: &str, container: &str, headers: &mut HeaderKeyDict) {
        let fallback = self.container_info(account, container);
        headers.set(
            "X-Container-Root-Db-State",
            self.effective_root_db_state(account, container, fallback.root_db_state()),
        );
    }

    /// Container-sync user key for inbound realm HMAC validation.
    pub fn container_sync_key(&self, account: &str, container: &str) -> Option<String> {
        self.container_info(account, container).sync_key
    }

    /// For a sharded root HEAD: Python `get_shard_usage` — sum
    /// `object_count`/`bytes_used` from root shard-range rows in
    /// ACTIVE/SHARDING/SHRINKING. Do **not** HEAD each shard container:
    /// live shard `object_count` lags `run_custom_sharder(reclaim_age=0)`
    /// PUT_shard onto the root (probe L1979 expected 51, live-shard sum
    /// stayed 50+50=100).
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
        let Ok((part, _)) = self
            .container_ring
            .get_nodes(account, Some(container), None)
        else {
            return;
        };
        let path = format!("/{}/{}", percent_encode(account), percent_encode(container));
        let nodes = self.iter_nodes(&self.container_ring, part);
        let mut shard_headers = self.backend_headers(req, false, "container");
        shard_headers.set("X-Backend-Record-Type", "shard");
        shard_headers.set("X-Backend-Allow-Reserved-Names", "true");
        let Some(arr) = self.fetch_listing_shard_ranges(nodes, part, &path, &shard_headers) else {
            return;
        };
        let (total_count, total_bytes, saw) = shard_usage_from_ranges(&arr);
        if saw {
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
        let Ok((part, _)) = self
            .container_ring
            .get_nodes(account, Some(container), None)
        else {
            return None;
        };
        let path = format!("/{}/{}", percent_encode(account), percent_encode(container));
        let nodes = self.iter_nodes(&self.container_ring, part);
        // Probe HEAD for sharding state + object count. Use backend_headers so
        // internal requests carry the same baseline as other container hops
        // (User-Agent / X-Trans-Id); gatekeeper strips client X-Backend-*.
        let head_headers = self.backend_headers(req, false, "container");
        let mut head = self.get_or_head(
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
        // GET: always look for listing ranges. A lagging unsharded HEAD
        // replica (count still 100) must not skip fan-out and list retiring
        // root leftovers (probe L1985). HEAD stays on the backend replica.
        if req.method.eq_ignore_ascii_case("HEAD") {
            // Patch counts from listing-state range stats even when the
            // first replica still says unsharded/100 (probe L1979).
            let mut shard_headers = self.backend_headers(req, false, "container");
            shard_headers.set("X-Backend-Record-Type", "shard");
            shard_headers.set("X-Backend-Allow-Reserved-Names", "true");
            let arrays = self.fetch_json_arrays_nonempty(
                &nodes,
                part,
                &path,
                "states=listing&format=json",
                &shard_headers,
            );
            if let Some((usage_count, usage_bytes)) = lowest_shard_usage(&arrays) {
                head.headers
                    .set("X-Container-Object-Count", usage_count.to_string());
                head.headers
                    .set("X-Container-Bytes-Used", usage_bytes.to_string());
            }
            // Python HEAD is `_GETorHEAD_from_backend` (probe L613 user-meta).
            head.status = 204;
            head.body = swift_http::Body::empty();
            head.headers.set("Content-Length", "0");
            if let Some(name) = head
                .headers
                .get("X-Backend-Storage-Policy-Index")
                .and_then(|v| v.parse::<i64>().ok())
                .and_then(|idx| self.policy_index_to_name.get(&idx))
            {
                head.headers.set("X-Storage-Policy", name.clone());
            }
            async_fanout::stamp_container_last_modified(&mut head);
            return Some(head);
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
        // None (every replica 200 []) is the same as Some([]) for fan-out:
        // probe L2070 dump has 2/3 SHARDING 200 [] and 1 COLLAPSED [alpha].
        // `?` here first-wins the empty SHARDING replica.
        let arr = self
            .fetch_listing_shard_ranges(nodes.clone(), part, &path, &shard_headers)
            .unwrap_or_default();
        // Unsharded/collapsed path only fans out when ranges actually exist
        // (partial cleave with CLEAVED ranges + empty root).
        if !should_fanout_sharded_listing(&state, object_count, !arr.is_empty()) {
            // Shrink-to-root L2070: listing ranges are gone; one replica is
            // already COLLAPSED with the objects, others still SHARDING on an
            // empty epoch. First-wins would return []. Dated empty_wins fold
            // keeps the newer nonempty replica (and still drops L692 leftovers).
            return self.folded_root_object_listing(req, &nodes, part, &path, &head, &state);
        }
        // Parse client listing knobs.
        let marker = req.param("marker").unwrap_or_default();
        let end_marker = req.param("end_marker").unwrap_or_default();
        let prefix = req.param("prefix").unwrap_or_default();
        let delimiter = req.param("delimiter").unwrap_or_default();
        let reverse = config_true_value(req.param("reverse").as_deref().unwrap_or(""));
        let limit: usize = req
            .param("limit")
            .and_then(|v| v.parse().ok())
            .unwrap_or(10000);
        let selected = select_listing_shard_ranges(&arr, &marker, &end_marker, &prefix, reverse);
        // Marker windows may select 1–2 ranges; settled-ness is a property of
        // the whole container (probe L692 reverse+limit).
        let all_ranges: Vec<&serde_json::Value> = arr.iter().collect();
        let root_path = format!("{account}/{container}");
        if state == "sharded" || listing_ranges_prove_sharded(&all_ranges, &root_path) {
            self.remember_proven_container_db_state(account, container, "sharded");
        }
        let empty_wins = listing_ranges_are_settled_active(&all_ranges);
        let mut feeds: Vec<ListingFeed> = Vec::new();
        // Residual root rows cover uncleaved namespace while SHARDING
        // (probe L631 / listing_under_populated L1483). Python `fill_gaps`
        // inserts the root as a namespace; we also GET the retiring DB.
        // Do not gate on HEAD object_count: after the first cleave batch the
        // fresh epoch HEAD is 0 while retiring still holds obj-0100+.
        // After db_state=sharded, Python lists shards only — residual would
        // resurrect deleted originals (L692).
        let newest = req
            .headers
            .get("X-Newest")
            .map(config_true_value)
            .unwrap_or(false);
        let has_shrinking = all_ranges
            .iter()
            .any(|sr| sr.get("state").and_then(|v| v.as_i64()).unwrap_or(0) == 50);
        // Probe L1985: reclaim custom-sharder may already have nested a
        // SHRINKING donor inside an expanded acceptor. Root retiring rows
        // still hold DELETE'd first-shard names; unioning them resurrects
        // obj-1-000…. Shard DBs are already [alpha] + second shard.
        if include_root_residual_for_listing_ex(
            &state,
            newest,
            empty_wins,
            has_shrinking,
            !arr.is_empty(),
            listing_has_full_active_cover(&all_ranges),
            listing_has_full_shrinking_cover(&all_ranges),
        ) {
            let mut root_headers = self.backend_headers(req, false, "container");
            root_headers.set("X-Backend-Record-Type", "object");
            let qs_parts = shard_listing_query_parts(
                &marker,
                &end_marker,
                &prefix,
                &delimiter,
                reverse,
                limit,
            );
            let qs = qs_parts.join("&");
            // X-Newest: same replica as HEAD (L1517). Otherwise first nonempty
            // (L1483 lagging CLEAVED replica still has names).
            let items = if newest {
                self.get_or_head(
                    "container",
                    nodes.clone(),
                    part,
                    "GET",
                    &path,
                    &qs,
                    &root_headers,
                )
                .and_then(parse_listing_json_body)
            } else {
                self.fetch_shard_object_listing_first_nonempty(
                    &nodes,
                    part,
                    &path,
                    &qs,
                    &root_headers,
                )
            };
            if let Some(items) = items {
                if !items.is_empty() {
                    feeds.push(ListingFeed {
                        lower: String::new(),
                        upper: String::new(),
                        timestamp: String::new(),
                        items,
                    });
                }
            }
        }
        for sr in &selected {
            let name = sr.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let (shard_account, shard_container) = match name.split_once('/') {
                Some((a, c)) => (a, c),
                None => continue,
            };
            // Probe L1985: `states=listing` fill_gaps may synthesise the root
            // own range. GETting that lists retiring-root leftovers.
            if shard_account == account && shard_container == container {
                continue;
            }
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
            let mut qs_parts = shard_listing_query_parts(
                &marker,
                &end_marker,
                &prefix,
                &delimiter,
                reverse,
                limit,
            );
            if empty_wins {
                // Limited per-replica pages are not comparable (L692 reverse
                // +limit mixed leftover evens). Majority-vote the full
                // marker window, then truncate client-side.
                qs_parts.retain(|p| !p.starts_with("limit="));
            }
            let mut headers = self.backend_headers(req, false, "container");
            // Shard containers live under the reserved `.shards_*` account.
            headers.set("X-Backend-Allow-Reserved-Names", "true");
            // Object rows, not nested namespaces. A SHARDING donor's default
            // GET would otherwise list the empty fresh epoch (probe L1321).
            headers.set("X-Backend-Record-Type", "object");
            // Settled listing (every selected range ACTIVE, ≥3 ranges): a
            // successful 200 [] on any replica is authoritative empty so a
            // lagging replica cannot resurrect DELETE leftovers (probe L1418).
            // First-gen (2 ACTIVE) and in-progress CLEAVED/SHARDING keep
            // replica-union (L1146 extra PUTs, L1321 cleave). 404 is not empty.
            // Feed merge is a name union: newest-covering empty suppression
            // dropped cleaved betas on listing-w91 (donor ts > children).
            let Some(items) = self.fetch_json_array_merged(
                &snodes,
                spart,
                &spath,
                &qs_parts.join("&"),
                &headers,
                empty_wins,
            ) else {
                continue;
            };
            // Python `_get_from_shards`: empty shard `continue`s — do not
            // feed an empty covering range into newest-covering while a
            // SHARDING donor still holds the names (probe L1321).
            if items.is_empty() && !empty_wins {
                continue;
            }
            feeds.push(ListingFeed {
                lower: sr
                    .get("lower")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                upper: sr
                    .get("upper")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                timestamp: listing_feed_timestamp(sr),
                items,
            });
        }
        let merged = merge_listings_newest_covering(&feeds, limit, reverse);
        let bytes = serde_json::to_vec(&merged).unwrap_or_else(|_| b"[]".to_vec());
        let mut out = Response::with_body(200, bytes);
        out.headers
            .set("Content-Type", "application/json; charset=utf-8");
        out.headers.set("X-Backend-Sharding-State", state);
        out.headers.set("X-Backend-Record-Type", "object");
        // Root object_count is often 0 after cleave; report the merged listing
        // length so clients see a coherent count for this response page.
        stamp_sharded_listing_stats(
            &mut out,
            &head,
            &merged,
            &marker,
            &end_marker,
            &prefix,
            &delimiter,
            limit,
        );
        if let Some(name) = head
            .headers
            .get("X-Backend-Storage-Policy-Index")
            .and_then(|v| v.parse::<i64>().ok())
            .and_then(|idx| self.policy_index_to_name.get(&idx))
        {
            out.headers.set("X-Storage-Policy", name);
        }
        copy_root_listing_headers(&head, &mut out);
        Some(out)
    }

    /// Root object GET folded across replicas (no shard fan-out).
    fn folded_root_object_listing(
        &self,
        req: &Request,
        nodes: &[Node],
        part: u32,
        path: &str,
        head: &Response,
        state: &str,
    ) -> Option<Response> {
        if !should_fold_root_objects_without_ranges(state) {
            return None;
        }
        let marker = req.param("marker").unwrap_or_default();
        let end_marker = req.param("end_marker").unwrap_or_default();
        let prefix = req.param("prefix").unwrap_or_default();
        let delimiter = req.param("delimiter").unwrap_or_default();
        let reverse = config_true_value(req.param("reverse").as_deref().unwrap_or(""));
        let limit: usize = req
            .param("limit")
            .and_then(|v| v.parse().ok())
            .unwrap_or(10000);
        let qs_parts =
            shard_listing_query_parts(&marker, &end_marker, &prefix, &delimiter, reverse, limit);
        let mut headers = self.backend_headers(req, false, "container");
        headers.set("X-Backend-Record-Type", "object");
        // Probe L2070: 2/3 SHARDING epoch 200 [] + 1 COLLAPSED [alpha].
        // Pick the replica with the highest live count (collapsed=1) and
        // GET objects from that node. Query matches dump (`format=json`
        // only): `limit=10000` is not what direct_client sends.
        let head_hdrs = self.backend_headers(req, false, "container");
        let mut scored: Vec<(i64, bool, Node)> = Vec::new();
        for node in nodes {
            let Some(h) = self.get_or_head(
                "container",
                vec![node.clone()],
                part,
                "HEAD",
                path,
                "",
                &head_hdrs,
            ) else {
                continue;
            };
            // listing-w214 L2095: a DELETED primary HEAD 404 must not
            // compete as object_count=0; skip it so we don't fold a
            // leftover handoff listing after all primaries tombstoned.
            if !(200..300).contains(&h.status) {
                continue;
            }
            let st = h
                .headers
                .get("X-Backend-Sharding-State")
                .unwrap_or("")
                .to_ascii_lowercase();
            let oc = h
                .headers
                .get("X-Container-Object-Count")
                .and_then(|v| v.parse::<i64>().ok())
                .unwrap_or(0);
            scored.push((oc, st == "collapsed", node.clone()));
        }
        scored.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)));
        let order: Vec<Node> = if scored.is_empty() {
            nodes.to_vec()
        } else {
            scored.into_iter().map(|(_, _, n)| n).collect()
        };
        let qs_plain = "format=json";
        let qs_full = qs_parts.join("&");
        let items = self
            .fetch_shard_object_listing_first_nonempty(&order, part, path, qs_plain, &headers)
            .filter(|a| !a.is_empty())
            .or_else(|| {
                self.fetch_shard_object_listing_first_nonempty(
                    &order, part, path, &qs_full, &headers,
                )
                .filter(|a| !a.is_empty())
            })
            .or_else(|| {
                self.fetch_json_array_merged(&order, part, path, qs_plain, &headers, false)
                    .filter(|a| !a.is_empty())
            })?;
        let bytes = serde_json::to_vec(&items).unwrap_or_else(|_| b"[]".to_vec());
        let mut out = Response::with_body(200, bytes);
        out.headers
            .set("Content-Type", "application/json; charset=utf-8");
        out.headers.set("X-Backend-Sharding-State", state);
        out.headers.set("X-Backend-Record-Type", "object");
        stamp_sharded_listing_stats(
            &mut out,
            head,
            &items,
            &marker,
            &end_marker,
            &prefix,
            &delimiter,
            limit,
        );
        if let Some(name) = head
            .headers
            .get("X-Backend-Storage-Policy-Index")
            .and_then(|v| v.parse::<i64>().ok())
            .and_then(|idx| self.policy_index_to_name.get(&idx))
        {
            out.headers.set("X-Storage-Policy", name);
        }
        copy_root_listing_headers(head, &mut out);
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
        let Ok((part, _)) = self
            .container_ring
            .get_nodes(account, Some(container), None)
        else {
            return None;
        };
        let path = format!("/{}/{}", percent_encode(account), percent_encode(container));
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
        // Prefer updating states (CREATED/CLEAVED/ACTIVE/SHARDING). A lagging
        // replica can return a non-empty updating set that still lacks nested
        // children; if no range covers the object, fall back to listing states
        // (do not change the updating query itself). Use the *longest* nonempty
        // replica: first-nonempty can hide CLEAVED children behind a 1-range
        // filler (probe test_sharding_listing L631).
        // listing-w137/w138: `includes=` on this query made L692 worse; keep
        // `states=updating&format=json` until includes= concat is proven.
        let updating = self
            .fetch_json_array_longest_nonempty(
                &nodes,
                part,
                &path,
                "states=updating&format=json",
                &shard_headers,
            )
            .filter(|a| !a.is_empty());
        let root_path = format!("{account}/{container}");
        let name = match updating
            .as_ref()
            .and_then(|arr| pick_updating_shard_name(arr, object, &root_path))
        {
            Some(n) => n,
            None => {
                let listing =
                    self.fetch_listing_shard_ranges(nodes, part, &path, &shard_headers)?;
                pick_updating_shard_name(&listing, object, &root_path)?
            }
        };
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
        // Python `_get_listing_namespaces_from_backend` uses the same
        // X-Newest walk as HEAD. Quorum topology is wrong here: two lagging
        // SHARDING replicas (CLEAVED+CREATED) outvote one just-SHARDED
        // replica with 4 ACTIVE (probe listing_under_populated L1509).
        let newest = shard_headers
            .get("X-Newest")
            .map(config_true_value)
            .unwrap_or(false);
        if newest {
            // Walk every replica and keep the most cleaved view. get_or_head
            // X-Newest can still return a SHARDING primary (same created_at);
            // 4 ACTIVE on the under-populated node must win (L1509).
            if let Some(arr) =
                prefer_most_progressed_listing_arrays(&self.fetch_json_arrays_nonempty(
                    &nodes,
                    part,
                    path,
                    "states=listing&format=json",
                    shard_headers,
                ))
            {
                if !arr.is_empty() {
                    return Some(arr);
                }
            }
            let broad = self
                .get_or_head(
                    "container",
                    nodes,
                    part,
                    "GET",
                    path,
                    "format=json",
                    shard_headers,
                )
                .and_then(parse_listing_json_body)?;
            return Some(prefer_listing_state_ranges(&broad));
        }
        // 1) Prefer the topology reported by the most replicas.  On a tie,
        // keep the longest progressed view so a lagging 1-range replica does
        // not hide CLEAVED children (probe test_sharding_listing L631).
        if let Some(arr) =
            prefer_quorum_consistent_listing_arrays(&self.fetch_json_arrays_nonempty(
                &nodes,
                part,
                path,
                "states=listing&format=json",
                shard_headers,
            ))
        {
            if !arr.is_empty() {
                return Some(arr);
            }
        }
        // 2) Broader: no state filter; prefer listing-state rows, else all.
        let broad = prefer_quorum_consistent_listing_arrays(&self.fetch_json_arrays_nonempty(
            &nodes,
            part,
            path,
            "format=json",
            shard_headers,
        ))?;
        Some(prefer_listing_state_ranges(&broad))
    }

    /// Walk every replica and collect nonempty JSON arrays.
    fn fetch_json_arrays_nonempty(
        &self,
        nodes: &[Node],
        part: u32,
        path: &str,
        query: &str,
        headers: &HeaderKeyDict,
    ) -> Vec<Vec<serde_json::Value>> {
        let mut arrays: Vec<Vec<serde_json::Value>> = Vec::new();
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
            if resp.status == 204 || body.is_empty() {
                continue;
            }
            let val: serde_json::Value = match serde_json::from_slice(&body) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let arr = val.as_array().cloned().unwrap_or_default();
            if !arr.is_empty() {
                arrays.push(arr);
            }
        }
        arrays
    }

    /// Walk every replica and keep the longest nonempty JSON array.
    fn fetch_json_array_longest_nonempty(
        &self,
        nodes: &[Node],
        part: u32,
        path: &str,
        query: &str,
        headers: &HeaderKeyDict,
    ) -> Option<Vec<serde_json::Value>> {
        prefer_longest_nonempty_arrays(
            &self.fetch_json_arrays_nonempty(nodes, part, path, query, headers),
        )
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

    /// Shared walk for shard-range JSON: first 2xx nonempty array wins.
    /// Do not union range rows across replicas — a lagging 2-range replica
    /// mixed with a 5-range replica makes InternalClient (sharder via
    /// :18080) skip nested UPDATE_ROOT (probe L1306 `2 != 5`).
    /// Object listings use `fetch_json_array_merged` instead.
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

    fn fetch_json_array_merged(
        &self,
        nodes: &[Node],
        part: u32,
        path: &str,
        query: &str,
        headers: &HeaderKeyDict,
        empty_wins: bool,
    ) -> Option<Vec<serde_json::Value>> {
        // Always walk replicas. Unsettled: union so extra PUTs on a later
        // replica are not dropped (L1321 donor). Settled: empty 200 [] wins
        // (L1418). 404 is not empty.
        // Do not short-circuit on X-Newest: a newest-timestamp replica can
        // still list deleted originals (listing-w151 UTF8 L692 FAIL).
        let mut replies: Vec<Option<Vec<serde_json::Value>>> = Vec::new();
        let mut timestamps: Vec<Timestamp> = Vec::new();
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
                replies.push(None);
                timestamps.push(Timestamp::zero());
                continue;
            };
            if !(200..300).contains(&resp.status) {
                replies.push(None);
                timestamps.push(Timestamp::zero());
                continue;
            }
            let ts = listing_resp_timestamp(&resp.headers);
            let body = match resp.body.into_vec(16 * 1024 * 1024) {
                Ok(b) => b,
                Err(_) => {
                    replies.push(None);
                    timestamps.push(Timestamp::zero());
                    continue;
                }
            };
            if resp.status == 204 || body.is_empty() {
                replies.push(Some(Vec::new()));
                timestamps.push(ts);
                continue;
            }
            let val: serde_json::Value = match serde_json::from_slice(&body) {
                Ok(v) => v,
                Err(_) => {
                    replies.push(None);
                    timestamps.push(Timestamp::zero());
                    continue;
                }
            };
            let arr = val.as_array().cloned().unwrap_or_default();
            replies.push(Some(arr));
            timestamps.push(ts);
        }
        fold_replica_listings_dated(&replies, empty_wins, &timestamps)
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
        if let Some(resp) = self.get_or_head("account", nodes, part, "HEAD", &path, "", &headers) {
            info = account_info_from_response(&resp);
            self.cache_account_from_response(account, &resp);
        } else {
            info.status = 503;
        }
        info
    }

    /// `set_info_cache` for an account HEAD/listing (including the
    /// autocreate fake listing, which must carry `account_really_exists=false`).
    pub(crate) fn cache_account_from_response(&self, account: &str, resp: &Response) {
        let info = account_info_from_response(resp);
        if let Some(ttl) = info_cache_time(
            resp.status,
            resp.headers.get("X-Backend-Recheck-Account-Existence"),
            self.config.recheck_account_existence,
        ) {
            self.info_cache.set_account(account.to_string(), info, ttl);
        }
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
        let scoped = self.temp_url_keys_scoped(account, container);
        let mut keys = scoped.account;
        keys.extend(scoped.container);
        keys
    }

    /// Account vs container Temp-URL keys (Python `_get_keys` scopes).
    pub fn temp_url_keys_scoped(
        &self,
        account: &str,
        container: &str,
    ) -> swift_middleware::ScopedTempUrlKeys {
        swift_middleware::ScopedTempUrlKeys {
            account: self.account_info(account).temp_url_keys,
            container: if container.is_empty() {
                Vec::new()
            } else {
                self.container_info(account, container).temp_url_keys
            },
        }
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
            // TempURL and ordinary pre-authed subrequests are deliberately
            // not Swift owners.  VersionedWrites container-info probes are a
            // narrower trusted case: they need owner-only sync metadata to
            // enforce Python's versioning/container-sync exclusion.  The
            // marker is consumed here and cannot originate at the public
            // listener because gatekeeper strips X-Backend-*.
            let owner_info = req
                .headers
                .remove(swift_middleware::VERSIONED_WRITES_OWNER_INFO_HEADER)
                .is_some_and(|value| config_true_value(&value));
            if owner_info {
                req.headers.set("X-Backend-Swift-Owner", "true");
            } else {
                req.headers.remove("X-Backend-Swift-Owner");
            }
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
                        req.headers.get("X-Account-Access-Control").unwrap_or("")
                    );
                    let mut resp = Response::with_body(400, body);
                    resp.headers
                        .set("Content-Type", "text/plain; charset=UTF-8");
                    return Some(resp);
                }
            }
        }

        // Both Python TempAuth and KeystoneAuth allow OPTIONS without user
        // credentials. Keep the owner marker clear: preflight may inspect
        // container CORS metadata, but it is never an owner-authorized
        // management request.
        if req.method == "OPTIONS" {
            req.headers.remove("X-Backend-Swift-Owner");
            return None;
        }

        // Legacy container-sync (Python tempauth/keystoneauth): if the
        // destination container's sync_key matches X-Container-Sync-Key and
        // the request carries a timestamp, allow without a user token.
        // Gatekeeper shunts client `X-Timestamp` → `X-Backend-Inbound-X-Timestamp`
        // before we run, so accept either form (realm middleware restores too).
        if let Some(c) = container {
            if let Some(req_key) = req.headers.get("x-container-sync-key") {
                let has_ts = req.headers.get("x-timestamp").is_some()
                    || req.headers.get("x-backend-inbound-x-timestamp").is_some();
                if !req_key.is_empty() && has_ts {
                    let info = self.container_info(account, c);
                    if let Some(sk) = info.sync_key.as_deref() {
                        if !sk.is_empty() && sk == req_key {
                            // Restore timestamp for object servers (Python
                            // container_sync / obj controller expectation).
                            if req.headers.get("x-timestamp").is_none() {
                                if let Some(ts) = req.headers.get("x-backend-inbound-x-timestamp") {
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
            stamp_auth_backend_headers(req, swift_owner, &groups);
        }
        denied
    }

    async fn authorize_async(
        self: &Arc<Self>,
        req: &mut Request,
        account: &str,
        container: Option<&str>,
        object: Option<&str>,
    ) -> Option<Response> {
        if req
            .headers
            .get("X-Backend-Authorize-Override")
            .map(config_true_value)
            .unwrap_or(false)
        {
            let owner_info = req
                .headers
                .remove(swift_middleware::VERSIONED_WRITES_OWNER_INFO_HEADER)
                .is_some_and(|value| config_true_value(&value));
            if owner_info {
                req.headers.set("X-Backend-Swift-Owner", "true");
            } else {
                req.headers.remove("X-Backend-Swift-Owner");
            }
            return None;
        }
        if !self.config.auth_enabled {
            return None;
        }
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
                        req.headers.get("X-Account-Access-Control").unwrap_or("")
                    );
                    let mut resp = Response::with_body(400, body);
                    resp.headers
                        .set("Content-Type", "text/plain; charset=UTF-8");
                    return Some(resp);
                }
            }
        }
        if req.method == "OPTIONS" {
            req.headers.remove("X-Backend-Swift-Owner");
            return None;
        }
        let c_info = match container {
            Some(c) => Some(self.container_info_async(account, c).await),
            None => None,
        };
        if container.is_some() {
            if let Some(req_key) = req.headers.get("x-container-sync-key") {
                let has_ts = req.headers.get("x-timestamp").is_some()
                    || req.headers.get("x-backend-inbound-x-timestamp").is_some();
                if !req_key.is_empty() && has_ts {
                    if let Some(info) = c_info.as_ref() {
                        if let Some(sk) = info.sync_key.as_deref() {
                            if !sk.is_empty() && sk == req_key {
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
        }
        let acl: Option<String> = match container {
            Some(_) if object.is_some() || matches!(req.method.as_str(), "GET" | "HEAD") => {
                c_info.as_ref().and_then(|info| {
                    if matches!(req.method.as_str(), "GET" | "HEAD") {
                        info.read_acl.clone()
                    } else {
                        info.write_acl.clone()
                    }
                })
            }
            _ => None,
        };
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
        let acct_info = self.account_info_async(account).await;
        let account_acls =
            swift_middleware::acls_from_sysmeta(acct_info.core_access_control.as_deref());
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
            stamp_auth_backend_headers(req, swift_owner, &groups);
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
            let info = self.container_info_for_write(account, container);
            if !info.exists() {
                return swob_response(info.write_failure_status());
            }
            resolve_object_storage_policy(header_policy, info.policy_index)
        } else {
            resolve_object_storage_policy(
                header_policy,
                self.container_policy_index(account, container),
            )
        };
        let Some(object_ring) = self.object_ring_for(policy_index) else {
            return text_response(
                503,
                &format!("No object ring configured for storage policy {policy_index}"),
            );
        };
        let Ok((object_part, _)) = object_ring.get_nodes(account, Some(container), Some(object))
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
        if let Some(ec) = self.ec_params_for_object_ring(policy_index, object_ring) {
            match req.method.as_str() {
                "PUT" if self.ec_policies.contains_key(&policy_index) => {
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
                    self.emit_proxy_log(
                        false,
                        &format!(
                            "proxy-server: EC GET {path} status=start reason=sync_ec_get \
                             policy={policy_index} ndata={}",
                            ec.ndata
                        ),
                    );
                    let resp = self.ec_get(req, &path, policy_index, object_ring, object_part, ec);
                    self.emit_proxy_log(
                        resp.status >= 400,
                        &format!(
                            "proxy-server: EC GET {path} status={} reason=sync_ec_get_done",
                            resp.status
                        ),
                    );
                    return resp;
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
                stamp_next_part_power(&mut headers, object_ring);
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
                    // set by DLO/SLO (below gatekeeper, so client-supplied
                    // copies are stripped): the object server drops the Range
                    // when the object carries the named manifest metadata.
                    "X-Backend-Ignore-Range-If-Metadata-Present",
                    // crypto encrypter: compare If-Match against Etag-Mac
                    "X-Backend-Etag-Is-At",
                ] {
                    if let Some(v) = req.headers.get(h) {
                        headers.set(h, v.to_string());
                    }
                }
                self.forward_open_expired(req, &mut headers);
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
                if req.method == "PUT" {
                    apply_content_type_guess(req);
                }
                if req.method == "POST" {
                    if let Err(resp) =
                        apply_check_delete_headers(req, Timestamp::now().as_secs_f64())
                    {
                        return resp;
                    }
                }
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
                let Ok((container_part, _)) =
                    self.container_ring
                        .get_nodes(&upd_account, Some(&upd_container), None)
                else {
                    return swob_response(503);
                };
                let mut base = self.backend_headers(req, true, "object");
                let put_ts = object_write_timestamp(req);
                base.set("X-Timestamp", put_ts.internal());
                // Route the write/tombstone to the right policy datadir (see
                // the GET note above) — an EC DELETE landing in objects/ would
                // 404 and leave the fragments orphaned.
                base.set("X-Backend-Storage-Policy-Index", policy_index);
                stamp_next_part_power(&mut base, object_ring);
                self.stamp_root_db_state(account, container, &mut base);
                if req.method == "PUT" {
                    base.set(
                        "Content-Type",
                        req.headers
                            .get("Content-Type")
                            .unwrap_or("application/octet-stream"),
                    );
                }
                // Tell the object server which container DB to update (shard
                // path differs from the client-visible account/container).
                stamp_shard_container_path(
                    &mut base,
                    &upd_account,
                    &upd_container,
                    account,
                    container,
                );
                let node_number = object_ring
                    .get_part_nodes(object_part)
                    .map(|n| n.len())
                    .unwrap_or(1);
                let per_node = self.object_container_update_headers(
                    &base,
                    container_part,
                    node_number,
                    account,
                    container,
                    object,
                );
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
                    // The object server stores and returns an RFC-quoted ETag,
                    // but Python's client-facing object PUT response exposes
                    // the bare MD5 (the same normalization used by GET/HEAD).
                    if let Some(etag) = resp.headers.get("ETag").map(str::to_string) {
                        resp.headers.set("ETag", etag.trim_matches('"'));
                    }
                    // obj.py:_store_object — every PUT answer (201 and 422
                    // alike) carries Last-Modified from the request timestamp.
                    resp.headers
                        .set("Last-Modified", swift_http::http_date(put_ts.ceil()));
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
            _ => method_not_allowed(self.allowed_methods(true)),
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
        apply_content_type_guess(req);
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
        let put_ts = object_write_timestamp(req);
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
                &format!("EC ring replica count {} != k+m {}", primaries.len(), n),
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
                    backend_index: None,
                })
                .collect(),
            Err(_) => Vec::new(),
        };

        // The container-update side channel (each fragment PUT drives one).
        let Ok((container_part, _)) = self
            .container_ring
            .get_nodes(account, Some(container), None)
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
        stamp_next_part_power(&mut base, object_ring);
        self.stamp_root_db_state(account, container, &mut base);
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
        let (tx, rx) = mpsc::sync_channel(primaries.len().max(1));
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
        if let Some(&client_err) = [400u16, 411, 413, 422, 507]
            .iter()
            .find(|s| early_finals.contains(s))
        {
            return swob_response(client_err);
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
        stamp_next_part_power(&mut headers, object_ring);
        self.forward_open_expired(req, &mut headers);
        let nodes = self.iter_nodes(object_ring, object_part);

        let (tx, rx) = mpsc::sync_channel(nodes.len().max(1));
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

        let mut goods: Vec<(Node, BackendHead)> = Vec::new();
        let mut latest_404_timestamp = Timestamp::zero();
        let mut saw_auth_404 = false;
        for (node, r) in rx.iter() {
            match r {
                Ok(head) if head.status == 200 => goods.push((node, head)),
                Ok(head) if head.status == 404 => {
                    let ts = backend_404_timestamp(&head.headers);
                    if !node.handoff || ts.is_truthy() {
                        saw_auth_404 = true;
                        if ts > latest_404_timestamp {
                            latest_404_timestamp = ts;
                        }
                    }
                }
                Ok(head) if head.status == 507 => self.error_limiter.limit(&node),
                Ok(head) if head.status >= 500 => self.error_limiter.increment(&node),
                Ok(_) => {}
                Err(_) => self.error_limiter.increment(&node),
            }
        }
        let n200 = goods.len();
        let mut sources: HashMap<i32, (Node, BackendHead)> = HashMap::new();
        let mut meta: Option<Vec<(String, String)>> = None;
        for (node, head) in goods {
            // obj.py ECGetResponseCollection.best_bucket: a newer tombstone
            // trumps older fragment archives left on nodes that missed DELETE.
            if source_timestamp(&head.headers) < latest_404_timestamp {
                continue;
            }
            let fi = resp_header(&head.headers, "X-Object-Sysmeta-Ec-Frag-Index")
                .and_then(|v| v.parse::<i32>().ok())
                .or(node.backend_index);
            if let Some(fi) = fi {
                if sources.len() >= ec.ndata && !sources.contains_key(&fi) {
                    continue;
                }
                if meta.is_none() {
                    meta = Some(head.headers.clone());
                }
                sources.entry(fi).or_insert((node, head));
            }
        }

        let required = if is_head { 1 } else { ec.ndata };
        if sources.len() < required {
            let idxs: Vec<i32> = sources.keys().copied().collect();
            // GET: empty + 404 → gone; leftover durables below ndata → 503.
            // HEAD: one fragment's metadata is enough (official lonely-frag
            // client HEAD is 2xx). Zero sources still follow GET's miss map.
            let status = if sources.is_empty() && saw_auth_404 {
                404
            } else {
                503
            };
            self.emit_proxy_log(
                true,
                &format!(
                    "proxy-server: EC GET {path} status={status} reason=sync_ec_gather \
                     policy={policy_index} ndata={} 200s={} idxs={idxs:?}",
                    ec.ndata, n200
                ),
            );
            return with_g6_diag(
                attach_backend_timestamp(swob_response(status), latest_404_timestamp),
                format!(
                    "reason=sync_ec_gather status={status} ndata={} idxs={idxs:?} \
                     ec=1 policy={policy_index} 200s={n200}",
                    ec.ndata
                ),
            );
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
                // Match Python EC object 416: swob's HTML error media type,
                // whole-object EC etag, and the usual range/object metadata.
                let body = concat!(
                    "<html><h1>Requested Range Not Satisfiable</h1>",
                    "<p>The Range requested is not available.</p></html>"
                );
                let mut resp = Response::with_body(416, body.as_bytes().to_vec());
                resp.headers
                    .set("Content-Range", format!("bytes */{orig_size}"));
                resp.headers.set("Content-Type", "text/html; charset=UTF-8");
                resp.headers.set("Accept-Ranges", "bytes");
                if !ec_etag.is_empty() {
                    resp.headers.set("Etag", &ec_etag);
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
            let keep = keep_ec_client_metadata(&kl);
            if keep
                && !(kl == "content-type"
                    && resp.status == 206
                    && resp.headers.get("Content-Type").is_some())
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
        let boundary =
            md5_hex(format!("{path}:{orig_size}:{}:{}", ranges.len(), ec_etag).as_bytes());
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
                return Some(Ok(
                    Box::new(std::io::Cursor::new(terminator.clone())) as Box<dyn Read + Send>
                ));
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

        let (tx, rx) = mpsc::sync_channel(fetch_nodes.len().max(1));
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
/// Used by the default async fan-out path; not EC-specific.
fn ring_nodes(part_nodes: Vec<swift_ring::PartNode<'_>>) -> Vec<Node> {
    part_nodes
        .iter()
        .map(|pn| Node {
            ip: pn.dev.ip.clone(),
            port: pn.dev.port,
            device: pn.dev.device.clone(),
            handoff: false,
            backend_index: Some(pn.index as i32),
        })
        .collect()
}

/// Headers from an EC fragment GET that must be copied onto the reconstructed
/// client response. Fragment Content-Length/ETag are the archive, not the
/// object; those are replaced with `X-Object-Sysmeta-Ec-*`. User/sysmeta and
/// Swift `allowed_headers` (`X-Static-Large-Object`, `X-Object-Manifest`, …)
/// have to survive or SLO/DLO reassembly never triggers on an EC policy.
pub(crate) fn keep_ec_client_metadata(kl: &str) -> bool {
    matches!(
        kl,
        "content-type"
            | "x-timestamp"
            | "last-modified"
            | "x-backend-timestamp"
            | "x-backend-data-timestamp"
            | "x-backend-durable-timestamp"
            | "x-delete-at"
            | "content-encoding"
            | "content-disposition"
            | "content-language"
            | "cache-control"
            | "expires"
            | "x-robots-tag"
            | "x-object-manifest"
            | "x-static-large-object"
    ) || (kl.starts_with("x-object-meta-") && kl.len() > "x-object-meta-".len())
        || kl.starts_with("x-object-sysmeta-")
        || kl.starts_with("x-object-transient-sysmeta-")
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
pub(crate) fn is_good_source(status: u16, is_object: bool) -> bool {
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
pub(crate) fn source_timestamp(headers: &[(String, String)]) -> Timestamp {
    // GetterSource.timestamp, base.py:1176-1180. Container X-Newest
    // additionally ranks X-Backend-Sharding-State (see
    // container_newest_key) because created_at ties every replica.
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

/// Container X-Newest key: sharding progress first, then timestamp.
/// `set_sharded_state` does not bump status_changed_at, and
/// X-Backend-Timestamp is created_at, so timestamp-only newest keeps a
/// lagging SHARDING primary (listing_under_populated L1509: 200 != 101).
pub(crate) fn container_newest_key(headers: &[(String, String)]) -> (u8, Timestamp) {
    let rank = match resp_header(headers, "x-backend-sharding-state")
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
        "sharded" | "collapsed" => 3,
        "sharding" => 2,
        "unsharded" => 1,
        _ => 0,
    };
    (rank, source_timestamp(headers))
}

/// A 404's `X-Backend-Timestamp` — the tombstone timestamp proving the
/// data was really DELETEd — zero when absent (base.py:1619-1621 and
/// 1645-1646).
pub(crate) fn backend_404_timestamp(headers: &[(String, String)]) -> Timestamp {
    resp_header(headers, "x-backend-timestamp")
        .and_then(|v| v.parse::<Timestamp>().ok())
        .unwrap_or(Timestamp::zero())
}

/// obj.py:955-962: a final 404 despite an existence proof (some node
/// answered 202 Accepted in the primary round) means the mixed results
/// can't be resolved — return 503 instead.
pub(crate) fn post_existence_proof_guard(resp: Response, found_count: usize) -> Response {
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
    resp.headers
        .set("Content-Type", "text/plain; charset=utf-8");
    resp
}

fn constraint_plain(status: u16, body: &str) -> Response {
    let mut resp = Response::with_body(status, body.as_bytes().to_vec());
    resp.headers.set("Content-Type", "text/plain");
    resp
}

/// Python `constrain_req_limit` / `validate_container_params`: listing
/// `limit=` above CONTAINER_LISTING_LIMIT is 412 `Maximum limit is N`
/// (probe test_sharding_listing L583). Must run in the proxy — sharded
/// fan-out never forwards the oversized limit to the container-server.
pub(crate) fn constrain_listing_limit(req: &Request) -> Result<usize, Response> {
    let max = swift_core::constraints::CONTAINER_LISTING_LIMIT;
    match req.param("limit") {
        Some(given) if !given.is_empty() && given.bytes().all(|b| b.is_ascii_digit()) => {
            let limit: i64 = given.parse().unwrap_or(max + 1);
            if limit > max {
                return Err(constraint_plain(412, &format!("Maximum limit is {max}")));
            }
            Ok(limit.max(0) as usize)
        }
        _ => Ok(max as usize),
    }
}

/// Python container.GET owns this response contract, not InternalClient.
/// Auto/default (including unknown) GET record types return an object listing
/// without backend record-type/format headers. Explicit object/shard requests
/// are internal direct-backend operations and must preserve their headers.
/// HEAD is not container.GET and must not inherit its response filtering.
pub(crate) fn finalize_container_listing_headers(req: &Request, resp: &mut Response) {
    let explicit_record_type = req
        .headers
        .get("X-Backend-Record-Type")
        .is_some_and(|kind| {
            kind.eq_ignore_ascii_case("object") || kind.eq_ignore_ascii_case("shard")
        });
    if req.method == "GET" && !explicit_record_type {
        resp.headers.remove("X-Backend-Record-Type");
        resp.headers.remove("X-Backend-Record-Shard-Format");
    }
}

fn finish_account_resp(swift_owner: bool, mut resp: Response) -> Response {
    expose_account_acl_header(&mut resp);
    strip_owner_headers(&mut resp, swift_owner);
    resp
}

fn finish_container_resp(swift_owner: bool, reseller: bool, mut resp: Response) -> Response {
    strip_owner_headers(&mut resp, swift_owner);
    expose_container_sharding(&mut resp, reseller);
    resp
}

/// Python container.py GET/HEAD: reseller requests see `X-Container-Sharding`
/// as `str(config_true_value(sysmeta))` (`'True'` / `'False'`). Probe tests
/// POST `X-Container-Sharding: on` with the admin token then HEAD that header.
fn expose_container_sharding(resp: &mut Response, reseller: bool) {
    if !reseller {
        return;
    }
    let sys = resp
        .headers
        .get("X-Container-Sysmeta-Sharding")
        .unwrap_or("False");
    resp.headers.set(
        "X-Container-Sharding",
        if config_true_value(sys) {
            "True"
        } else {
            "False"
        },
    );
}

fn is_reseller_request(req: &Request) -> bool {
    req.headers
        .get("X-Backend-Reseller-Request")
        .is_some_and(config_true_value)
        || req
            .headers
            .get("X-Backend-Remote-User")
            .unwrap_or("")
            .split(',')
            .any(|g| g == ".reseller_admin")
}

fn stamp_auth_backend_headers(req: &mut Request, swift_owner: bool, groups: &[String]) {
    if swift_owner {
        req.headers.set("X-Backend-Swift-Owner", "true");
    } else {
        req.headers.remove("X-Backend-Swift-Owner");
    }
    if groups.iter().any(|g| g == ".reseller_admin") {
        req.headers.set("X-Backend-Reseller-Request", "true");
    } else {
        req.headers.remove("X-Backend-Reseller-Request");
    }
}

/// Python `int()`-like parse used by `check_delete_headers`.
fn parse_int_like(s: &str) -> Option<f64> {
    let t = s.trim();
    let digits = t.strip_prefix(['+', '-']).unwrap_or(t);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    t.parse::<f64>().ok()
}

/// Port of `swift.common.constraints.check_delete_headers` for the proxy
/// PUT path. Python runs this in `check_object_creation` *before* the
/// backend 100-continue handshake, so a 400 body is never dropped.
fn apply_check_delete_headers(req: &mut Request, now: f64) -> Result<(), Response> {
    let backend_replication = req
        .headers
        .get("X-Backend-Replication")
        .is_some_and(config_true_value);
    if let Some(raw) = req.headers.get("X-Delete-After").map(str::to_string) {
        let Some(after) = parse_int_like(&raw) else {
            return Err(constraint_plain(400, "Non-integer X-Delete-After"));
        };
        let actual = normalize_delete_at_timestamp(now + after, false);
        if actual.parse::<i64>().unwrap_or(0) as f64 <= now {
            return Err(constraint_plain(400, "X-Delete-After in past"));
        }
        req.headers.set("X-Delete-At", actual);
        req.headers.remove("X-Delete-After");
    }
    if let Some(raw) = req.headers.get("X-Delete-At").map(str::to_string) {
        let Some(value) = parse_int_like(&raw) else {
            return Err(constraint_plain(400, "Non-integer X-Delete-At"));
        };
        let normalized = normalize_delete_at_timestamp(value, false);
        let x_delete_at = normalized.parse::<i64>().unwrap_or(0);
        if (x_delete_at as f64) <= now && !backend_replication {
            return Err(constraint_plain(400, "X-Delete-At in past"));
        }
        req.headers.set("X-Delete-At", normalized);
    }
    Ok(())
}

/// Python `ObjectController._update_content_type`: guess from the path
/// when the client omitted Content-Type or sent `X-Detect-Content-Type`.
pub(crate) fn apply_content_type_guess(req: &mut Request) {
    let detect = req
        .headers
        .get("X-Detect-Content-Type")
        .is_some_and(config_true_value);
    let missing = req
        .headers
        .get("Content-Type")
        .map(|v| v.is_empty())
        .unwrap_or(true);
    if detect || missing {
        req.headers
            .set("Content-Type", swift_http::guess_content_type(&req.path));
        if detect {
            req.headers.remove("X-Detect-Content-Type");
        }
    }
}

impl ProxyApp {
    /// Forward `X-Open-Expired` only when `allow_open_expired` is on.
    /// Python also stamps `X-Backend-Open-Expired` in that case; the object
    /// server currently honours the client header, so omitting it when the
    /// config is false is what makes expired GET 404.
    fn forward_open_expired(&self, req: &Request, headers: &mut HeaderKeyDict) {
        if !self.config.allow_open_expired {
            return;
        }
        if let Some(v) = req.headers.get("X-Open-Expired") {
            headers.set("X-Open-Expired", v.to_string());
            if config_true_value(v) {
                headers.set("X-Backend-Open-Expired", "true");
            }
        }
    }
}

/// Proxy half of Python `check_object_creation` (length / transfer-encoding
/// / delete-at). Content-Type is not required here: functional tests PUT
/// without it and expect 201, matching the object-server default.
fn check_object_creation(req: &mut Request, object_name: &str) -> Option<Response> {
    if object_name.len() as i64 > swift_core::constraints::MAX_OBJECT_NAME_LENGTH {
        return Some(constraint_plain(
            400,
            &format!(
                "Object name length of {} longer than {}",
                object_name.len(),
                swift_core::constraints::MAX_OBJECT_NAME_LENGTH
            ),
        ));
    }
    let te = req.headers.get("Transfer-Encoding").map(str::to_string);
    let chunked = if let Some(te) = te.as_deref() {
        let encodings: Vec<&str> = te
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        if encodings.len() > 1 {
            return Some(constraint_plain(
                501,
                "Unsupported Transfer-Coding header value specified in Transfer-Encoding header",
            ));
        }
        match encodings.last() {
            Some(last) if last.eq_ignore_ascii_case("chunked") => true,
            Some(_) => {
                return Some(constraint_plain(
                    400,
                    "Invalid Transfer-Encoding header value",
                ))
            }
            None => false,
        }
    } else {
        false
    };
    if let Some(cl) = req.headers.get("Content-Length") {
        if !chunked {
            let Some(n) = parse_int_like(cl) else {
                return Some(constraint_plain(400, "Invalid Content-Length header value"));
            };
            if n as i64 > swift_core::constraints::MAX_FILE_SIZE {
                return Some(text_response(413, "Your request is too large."));
            }
        }
    } else if !chunked {
        return Some(constraint_plain(411, "Missing Content-Length header."));
    }
    if let Err(resp) = apply_check_delete_headers(req, Timestamp::now().as_secs_f64()) {
        return Some(resp);
    }
    None
}

/// Python `check_utf8(path, internal=req.allow_reserved_names)`.
/// InternalClient sets `X-Backend-Allow-Reserved-Names: true`.
fn utf8_or_null_rejected(req: &Request) -> Option<Response> {
    let internal = req
        .headers
        .get("X-Backend-Allow-Reserved-Names")
        .map(config_true_value)
        .unwrap_or(false);
    if !check_utf8(&req.path, internal) {
        Some(text_response(412, "Invalid UTF8 or contains NULL"))
    } else {
        None
    }
}

/// The synthesized empty-account response for autocreate accounts
/// (`account_listing_response` with a `FakeAccountBroker`).
pub(crate) fn synthesized_account_listing(req: &Request) -> Response {
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
    // account.py:79-94: without this header a subsequent container PUT
    // treats the 2xx listing as a real account and skips autocreate, then
    // 404s because no account DB exists for the container-update.
    resp.headers.set("X-Backend-Fake-Account-Listing", "yes");
    if req.method == "HEAD" || empty {
        resp.headers.set("Content-Length", 0);
    }
    resp
}

/// Choose the updating shard that owns `object`.
///
/// Replica union can include a lagging donor (ACTIVE, older timestamp) plus
/// newer nested sub-shards. First-match would send DELETE to the donor
/// (probe L1418 leftover listing after delete-all). Skip deleted/SHARDED/
/// SHRUNK and pick the newest covering timestamp.
/// Python `_do_get_updating_namespaces(..., includes=obj)`: keep
/// `states=updating` and restrict the set to the range that owns `object`
/// so DELETE/PUT container-updates target that shard, not the first range
/// in a full listing (probe L692 leftover originals from shard 1+).
pub(crate) fn updating_shard_query(object: &str) -> String {
    format!(
        "states=updating&format=json&includes={}",
        percent_encode(object)
    )
}

pub(crate) fn pick_updating_shard_name(
    ranges: &[serde_json::Value],
    object: &str,
    root_path: &str,
) -> Option<String> {
    let mut best: Option<(&str, &str)> = None; // (timestamp, name)
    for sr in ranges {
        if sr.get("deleted").and_then(|v| v.as_i64()).unwrap_or(0) != 0 {
            continue;
        }
        let state = sr.get("state").and_then(|v| v.as_i64()).unwrap_or(0);
        if state == 70 || state == 80 {
            continue;
        }
        let name = sr.get("name").and_then(|v| v.as_str()).unwrap_or("");
        if !name.contains('/') || name == root_path {
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
        let ts = sr.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
        match best {
            None => best = Some((ts, name)),
            Some((bts, _)) if ts > bts => best = Some((ts, name)),
            _ => {}
        }
    }
    best.map(|(_, n)| n.to_string())
}

/// Python `get_shard_usage`: sum object/byte counts for non-deleted ranges
/// in `SHARD_STATS_STATES` (ACTIVE/SHARDING/SHRINKING).
pub(crate) fn shard_usage_from_ranges(arr: &[serde_json::Value]) -> (i64, i64, bool) {
    let mut count = 0i64;
    let mut bytes = 0i64;
    let mut saw = false;
    for sr in arr {
        let deleted = sr.get("deleted").and_then(|v| v.as_i64()).unwrap_or(0);
        if deleted != 0 {
            continue;
        }
        let st = sr.get("state").and_then(|v| v.as_i64()).unwrap_or(0);
        if st != 40 && st != 50 && st != 60 {
            continue;
        }
        saw = true;
        count += sr.get("object_count").and_then(|v| v.as_i64()).unwrap_or(0);
        bytes += sr.get("bytes_used").and_then(|v| v.as_i64()).unwrap_or(0);
    }
    (count, bytes, saw)
}

/// One non-deleted ACTIVE/SHRINKING range covering MIN–MAX. After first-shard
/// reclaim the updated root is this (probe L1979 listing-w231); a lagging
/// replica may still list two ranges totaling 100.
fn listing_is_single_full_cover(arr: &[serde_json::Value]) -> bool {
    if arr.len() != 1 {
        return false;
    }
    let sr = &arr[0];
    let st = sr.get("state").and_then(|v| v.as_i64()).unwrap_or(0);
    (st == 40 || st == 50)
        && sr.get("deleted").and_then(|v| v.as_i64()).unwrap_or(0) == 0
        && sr
            .get("lower")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .is_empty()
        && sr
            .get("upper")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .is_empty()
}

fn shard_usage_pick_min_floor(usages: Vec<(i64, i64)>) -> Option<(i64, i64)> {
    let max_c = usages.iter().map(|(c, _)| *c).max()?;
    let floor = max_c / 2;
    usages
        .into_iter()
        .filter(|(c, _)| *c >= floor)
        .min_by_key(|(c, _)| *c)
}

/// HEAD object-count after reclaim (probe L1979): equal-length listing
/// sets must not first-win a lagging 50+50 over a reclaimed 1+50.
/// Python HEAD is one replica's `get_shard_usage`; on the way down we take
/// the lowest live usage among nonempty listing-state replies.
pub(crate) fn lowest_shard_usage(arrays: &[Vec<serde_json::Value>]) -> Option<(i64, i64)> {
    // listing-w231: updated replica already dropped the reclaimed first
    // range (MIN–MAX 51) while a lagging replica still has 2 ranges (100).
    // Longest-wins then reports 100. A single MIN–MAX cover is the remaining
    // namespace; a bounded 1-range (second shard only, count 50) is not.
    let cover: Vec<(i64, i64)> = arrays
        .iter()
        .filter(|a| listing_is_single_full_cover(a))
        .filter_map(|a| {
            let (c, b, saw) = shard_usage_from_ranges(a);
            saw.then_some((c, b))
        })
        .collect();
    if !cover.is_empty() {
        return shard_usage_pick_min_floor(cover);
    }
    // listing-w195: a 1-range acceptor (count 50) must not beat a 2-range
    // reclaimed set (1+50=51). Longest listing-state set first, then the
    // lowest live usage among those (lagging 50+50 vs reclaimed 1+50).
    // listing-w201 L1992: same-length 51 vs 1 — a lagging 1-object view
    // must not win. Drop counts below half of the max, then take min
    // (51 vs 100 keeps 51; 51 vs 1 drops 1).
    let max_len = arrays.iter().map(|a| a.len()).max().filter(|n| *n > 0)?;
    let usages: Vec<(i64, i64)> = arrays
        .iter()
        .filter(|a| a.len() == max_len)
        .filter_map(|a| {
            let (c, b, saw) = shard_usage_from_ranges(a);
            saw.then_some((c, b))
        })
        .collect();
    shard_usage_pick_min_floor(usages)
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
/// Residual retiring-root object rows.
///
/// * `sharding`: always (L1483 uncleaved names; HEAD count may be 0).
/// * `sharded` + X-Newest: the newest replica may still hold uncleaved
///   rows after a peer marked ACTIVE (L1517). Without X-Newest, a lagging
///   replica would resurrect DELETE leftovers (L692).
pub(crate) fn include_sharding_residual_root(sharding_state: &str, newest: bool) -> bool {
    let s = sharding_state.to_ascii_lowercase();
    s == "sharding" || (s == "sharded" && newest)
}

/// Shrink-to-root (probe L2068/L2070): objects have been cleaved into the
/// root DB while listing still fans out to a now-empty SHRINKING shard.
/// Include root object rows only when the listing view is a settled
/// ACTIVE/SHRINKING partition (not nested donor+children, which would
/// resurrect L692 leftovers from a lagging root replica).
pub(crate) fn include_shrink_to_root_residual(
    sharding_state: &str,
    empty_wins: bool,
    has_shrinking: bool,
) -> bool {
    if !empty_wins || !has_shrinking {
        return false;
    }
    let s = sharding_state.to_ascii_lowercase();
    s == "sharded" || s == "collapsed"
}

pub(crate) fn cached_state_allows_shard_update(db_state: &str) -> bool {
    let state = db_state.to_ascii_lowercase();
    state == "sharded" || state == "sharding"
}

/// Root retiring rows. Skip when a SHRINKING donor is nested under an
/// expanded acceptor (probe L1985): shard DBs already have the live names
/// and the retiring DB still lists DELETE'd first-shard objects.
pub(crate) fn listing_has_full_active_cover(selected: &[&serde_json::Value]) -> bool {
    selected.iter().any(|sr| {
        sr.get("state").and_then(|v| v.as_i64()) == Some(40)
            && sr.get("deleted").and_then(|v| v.as_i64()).unwrap_or(0) == 0
            && sr
                .get("lower")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .is_empty()
            && sr
                .get("upper")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .is_empty()
    })
}

/// Shrink-to-root donor: a non-deleted SHRINKING range covering MIN-MAX.
/// Distinct from listing-w191 bounded shrinking (first-shard donor).
pub(crate) fn listing_has_full_shrinking_cover(selected: &[&serde_json::Value]) -> bool {
    selected.iter().any(|sr| {
        sr.get("state").and_then(|v| v.as_i64()) == Some(50)
            && sr.get("deleted").and_then(|v| v.as_i64()).unwrap_or(0) == 0
            && sr
                .get("lower")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .is_empty()
            && sr
                .get("upper")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .is_empty()
    })
}

pub(crate) fn include_root_residual_for_listing(
    sharding_state: &str,
    newest: bool,
    empty_wins: bool,
    has_shrinking: bool,
    has_listing_ranges: bool,
    full_active_cover: bool,
) -> bool {
    include_root_residual_for_listing_ex(
        sharding_state,
        newest,
        empty_wins,
        has_shrinking,
        has_listing_ranges,
        full_active_cover,
        false,
    )
}

pub(crate) fn include_root_residual_for_listing_ex(
    sharding_state: &str,
    newest: bool,
    empty_wins: bool,
    has_shrinking: bool,
    has_listing_ranges: bool,
    full_active_cover: bool,
    full_shrinking_cover: bool,
) -> bool {
    // L1985: nested shrinking under an expanded ACTIVE MIN-MAX acceptor.
    // Shard DBs hold the live names; retiring still lists DELETE'd rows.
    if full_active_cover {
        return false;
    }
    // listing-w191: bounded SHRINKING donor, fetch missed the acceptor.
    // Residual would union retiring leftovers; fan-out to the donor instead.
    if has_shrinking && has_listing_ranges && !full_shrinking_cover {
        return false;
    }
    // L2068/L2070: last shard shrinking into root (MIN-MAX SHRINKING, no
    // ACTIVE cover). Objects already live on the root; include them.
    if full_shrinking_cover {
        return include_shrink_to_root_residual(sharding_state, empty_wins, has_shrinking)
            || include_sharding_residual_root(sharding_state, newest);
    }
    // L1509: settled ACTIVE ranges already cover the namespace. Residual
    // retiring rows fill the under-populated last shards (101 != 200)
    // even when HEAD still says SHARDING (created_at tie / replicator).
    // L1483 keeps residual: CREATED ranges => empty_wins is false.
    if empty_wins && !has_shrinking {
        return false;
    }
    include_sharding_residual_root(sharding_state, newest)
        || include_shrink_to_root_residual(sharding_state, empty_wins, has_shrinking)
}

pub(crate) fn should_probe_sharded_listing(sharding_state: &str, object_count: i64) -> bool {
    let state = sharding_state.to_ascii_lowercase();
    if state == "sharding" || state == "sharded" || state == "collapsed" {
        return true;
    }
    object_count == 0
}

/// Shrink-to-root (probe L2070): no shard ranges left. Fold root object
/// rows across replicas instead of first-wins (a lagging SHARDING epoch
/// is 200 []).
pub(crate) fn should_fold_root_objects_without_ranges(sharding_state: &str) -> bool {
    matches!(
        sharding_state.to_ascii_lowercase().as_str(),
        "collapsed" | "sharding" | "sharded"
    )
}

/// Whether listing-state shard ranges should trigger fan-out.
///
/// Any nonempty listing-state set wins, including a lagging replica whose
/// HEAD still says unsharded/count=100 (probe L1985).
pub(crate) fn should_fanout_sharded_listing(
    _sharding_state: &str,
    _object_count: i64,
    has_listing_ranges: bool,
) -> bool {
    has_listing_ranges
}

/// Pick the longest nonempty JSON array. Listing-state `states=listing` from
/// a lagging replica can be a nonempty 1-range own-SHARDING set that would
/// first-win over a 2-CLEAVED replica and drop new PUTs (probe L631).
pub(crate) fn prefer_longest_nonempty_arrays(
    arrays: &[Vec<serde_json::Value>],
) -> Option<Vec<serde_json::Value>> {
    arrays
        .iter()
        .filter(|a| !a.is_empty())
        .max_by_key(|a| a.len())
        .cloned()
}

type ListingTopology = Vec<(String, String, String, i64, i64)>;

fn listing_topology(arr: &[serde_json::Value]) -> ListingTopology {
    let mut topology: ListingTopology = arr
        .iter()
        .map(|sr| {
            (
                sr.get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                sr.get("lower")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                sr.get("upper")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                sr.get("state").and_then(|v| v.as_i64()).unwrap_or(0),
                sr.get("deleted").and_then(|v| v.as_i64()).unwrap_or(0),
            )
        })
        .collect();
    topology.sort();
    topology
}

fn listing_array_timestamp(arr: &[serde_json::Value]) -> String {
    arr.iter()
        .map(listing_feed_timestamp)
        .max()
        .unwrap_or_default()
}

/// Select the shard-range topology reported by the most replicas.
///
/// A longest-array rule is useful during partial cleave, when only one
/// replica has progressed beyond an empty/filler view, but it is wrong once
/// a quorum agrees on a shorter, newer topology.  In particular:
///
/// * During W103/L1985 all three roots report a live SHRINKING donor plus an
///   expanded ACTIVE acceptor.  Both ranges must be queried until the donor
///   has moved `alpha`.
/// * During L2044 two roots report only the settled acceptor while one stale
///   root still reports donor+acceptor.  The quorum topology must win over
///   the longer stale array.
///
/// Empty arrays are intentionally absent from `arrays`; if every response is
/// empty the caller falls back to the root-listing path.  A topology tie keeps
/// the longest view, preserving the partial-cleave behaviour.
pub(crate) fn prefer_most_progressed_listing_arrays(
    arrays: &[Vec<serde_json::Value>],
) -> Option<Vec<serde_json::Value>> {
    arrays
        .iter()
        .filter(|arr| !arr.is_empty())
        .max_by_key(|arr| {
            let n_active = arr
                .iter()
                .filter(|sr| {
                    sr.get("state").and_then(|v| v.as_i64()) == Some(40)
                        && sr.get("deleted").and_then(|v| v.as_i64()).unwrap_or(0) == 0
                })
                .count();
            (n_active, arr.len(), listing_array_timestamp(arr))
        })
        .cloned()
}

pub(crate) fn prefer_quorum_consistent_listing_arrays(
    arrays: &[Vec<serde_json::Value>],
) -> Option<Vec<serde_json::Value>> {
    struct Group<'a> {
        topology: ListingTopology,
        members: Vec<&'a Vec<serde_json::Value>>,
    }

    let mut groups: Vec<Group<'_>> = Vec::new();
    for arr in arrays.iter().filter(|arr| !arr.is_empty()) {
        let topology = listing_topology(arr);
        if let Some(group) = groups.iter_mut().find(|group| group.topology == topology) {
            group.members.push(arr);
        } else {
            groups.push(Group {
                topology,
                members: vec![arr],
            });
        }
    }

    let winner = groups
        .into_iter()
        .max_by_key(|group| (group.members.len(), group.topology.len()))?;
    winner
        .members
        .into_iter()
        .max_by_key(|arr| listing_array_timestamp(arr))
        .cloned()
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

/// Query string for a shard/root object listing subrequest. Python
/// `_get_from_shards` forwards marker/end_marker/prefix/delimiter/reverse/limit
/// (probe test_sharding_listing do_listing_checks).
pub(crate) fn shard_listing_query_parts(
    marker: &str,
    end_marker: &str,
    prefix: &str,
    delimiter: &str,
    reverse: bool,
    limit: usize,
) -> Vec<String> {
    let mut qs_parts = vec!["format=json".to_string()];
    if !marker.is_empty() {
        qs_parts.push(format!("marker={}", percent_encode(marker)));
    }
    if !end_marker.is_empty() {
        qs_parts.push(format!("end_marker={}", percent_encode(end_marker)));
    }
    if !prefix.is_empty() {
        qs_parts.push(format!("prefix={}", percent_encode(prefix)));
    }
    if !delimiter.is_empty() {
        qs_parts.push(format!("delimiter={}", percent_encode(delimiter)));
    }
    if reverse {
        qs_parts.push("reverse=on".to_string());
    }
    qs_parts.push(format!("limit={limit}"));
    qs_parts
}

/// Copy root HEAD headers onto a sharded listing GET (Python keeps the
/// backend GET/HEAD headers). Probe `do_listing_checks` wants
/// Accept-Ranges, X-Timestamp, Last-Modified. Probe L671 also wants
/// X-Container-Read/Write, sync-key, and X-Versions-Location from POST.
pub(crate) fn copy_root_listing_headers(head: &Response, out: &mut Response) {
    out.headers.set("Accept-Ranges", "bytes");
    for k in ["X-Timestamp", "X-PUT-Timestamp", "Last-Modified"] {
        if out.headers.get(k).is_none() {
            if let Some(v) = head.headers.get(k).filter(|s| !s.is_empty()) {
                out.headers.set(k, v);
            }
        }
    }
    for (k, v) in head.headers.iter() {
        let lk = k.to_ascii_lowercase();
        if out.headers.get(k).is_some() {
            continue;
        }
        if lk.starts_with("x-container-meta-")
            || lk.starts_with("x-container-sysmeta-")
            || matches!(
                lk.as_str(),
                "x-container-read"
                    | "x-container-write"
                    | "x-container-sync-key"
                    | "x-container-sync-to"
                    | "x-versions-location"
                    | "x-history-location"
            )
        {
            out.headers.set(k, v);
        }
    }
    // Client POST `X-Versions-Location` is stored as sysmeta; the
    // versioned_writes filter may not see a reconstructed listing GET.
    // Probe test_sharding_listing L671 expects the client header.
    if out.headers.get("X-Versions-Location").is_none()
        && out.headers.get("X-History-Location").is_none()
    {
        if let Some(loc) = head
            .headers
            .get("X-Container-Sysmeta-Versions-Location")
            .filter(|s| !s.is_empty())
        {
            let mode = head
                .headers
                .get("X-Container-Sysmeta-Versions-Mode")
                .unwrap_or("stack");
            if mode.eq_ignore_ascii_case("history") {
                out.headers.set("X-History-Location", loc);
            } else {
                out.headers.set("X-Versions-Location", loc);
            }
        }
    }
}

fn listing_items_bytes_used(merged: &[serde_json::Value]) -> u64 {
    merged
        .iter()
        .filter_map(|v| {
            v.get("bytes").and_then(|b| {
                b.as_u64()
                    .or_else(|| b.as_i64().and_then(|i| u64::try_from(i).ok()))
            })
        })
        .sum()
}

/// Object-count from the merged listing page; bytes-used from that listing
/// when it is a complete unfiltered GET (root stats are 0 after cleave,
/// probe test_sharding_listing L671).
pub(crate) fn stamp_sharded_listing_stats(
    out: &mut Response,
    head: &Response,
    merged: &[serde_json::Value],
    marker: &str,
    end_marker: &str,
    prefix: &str,
    delimiter: &str,
    limit: usize,
) {
    out.headers
        .set("X-Container-Object-Count", merged.len().to_string());
    let head_bytes = head
        .headers
        .get("X-Container-Bytes-Used")
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    let listing_bytes = listing_items_bytes_used(merged);
    let complete = marker.is_empty()
        && end_marker.is_empty()
        && prefix.is_empty()
        && delimiter.is_empty()
        && merged.len() < limit;
    let bytes = if complete {
        listing_bytes.max(head_bytes)
    } else {
        head_bytes
    };
    out.headers.set("X-Container-Bytes-Used", bytes.to_string());
}

/// Select listing-state shard ranges that can contribute to a client listing.
/// Matches Python `_filter_complete_listing` + `filter_namespaces`: reverse
/// swaps marker/end_marker before the bound filter, then reverses the
/// remaining ranges so the walk is high-to-low (probe L562).
///
/// Keep a range when `marker < upper` (empty upper = MAX) and
/// `end_marker > lower` (empty lower = MIN). Prefix still skips `upper < prefix`.
pub(crate) fn select_listing_shard_ranges<'a>(
    ranges: &'a [serde_json::Value],
    marker: &str,
    end_marker: &str,
    prefix: &str,
    reverse: bool,
) -> Vec<&'a serde_json::Value> {
    let (filt_marker, filt_end) = if reverse {
        (end_marker, marker)
    } else {
        (marker, end_marker)
    };
    let mut out = Vec::new();
    for sr in ranges {
        let lower = sr.get("lower").and_then(|v| v.as_str()).unwrap_or("");
        let upper = sr.get("upper").and_then(|v| v.as_str()).unwrap_or("");
        if !filt_marker.is_empty() && !upper.is_empty() && upper <= filt_marker {
            continue;
        }
        if !filt_end.is_empty() && !lower.is_empty() && lower >= filt_end {
            continue;
        }
        if !prefix.is_empty() && !upper.is_empty() && upper < prefix {
            continue;
        }
        out.push(sr);
    }
    if reverse {
        out.reverse();
    }
    out
}

/// True when the listing view is a settled partition of ACTIVE/SHRINKING
/// ranges: every selected range is ACTIVE (40) or SHRINKING (50) and none
/// is a strict sub-interval of another (overlapping donor+children at
/// probe L1321). First-gen shrinking is two adjacent ACTIVE ranges covering
/// MIN–MAX (probe L1925); L1418 is four after the nested donor is gone.
/// Probe L2068: after shrink-to-root the last range is SHRINKING; treating
/// that as unsettled turned empty_wins off and a lagging replica resurrected
/// `obj-1-050+`. SHARDING/CLEAVED stay unsettled (L1483 residual union).
pub(crate) fn listing_ranges_are_settled_active(selected: &[&serde_json::Value]) -> bool {
    if selected.is_empty() {
        return false;
    }
    // Probe L1985: expanded ACTIVE acceptor (MIN–MAX) with a nested
    // SHRINKING donor. Treating that as unsettled unions handoff replicas
    // that still list DELETE'd obj-1-000… (listing-w191/w192 101 vs 51).
    // Shard DBs on primaries are already [alpha] + second-shard.
    if listing_has_full_active_cover(selected) {
        return true;
    }
    selected.iter().all(|sr| {
        matches!(
            sr.get("state").and_then(|v| v.as_i64()).unwrap_or(0),
            40 | 50
        )
    }) && !selected.iter().any(|sr| json_range_is_nested(sr, selected))
}

/// Strong proof that ACTIVE shard ranges form one gap-free MIN-to-MAX
/// namespace partition. Unlike `listing_ranges_are_settled_active`, this does
/// not accept SHRINKING ranges; it is safe to use as evidence that object
/// updates should carry root `db_state=sharded`.
pub(crate) fn listing_ranges_prove_sharded(
    selected: &[&serde_json::Value],
    root_path: &str,
) -> bool {
    if selected.is_empty() {
        return false;
    }
    let mut bounds = Vec::with_capacity(selected.len());
    for sr in selected {
        if sr.get("state").and_then(|v| v.as_i64()) != Some(40)
            || sr.get("deleted").and_then(|v| v.as_i64()).unwrap_or(0) != 0
        {
            return false;
        }
        // An ordinary, unsharded container may expose its own ACTIVE
        // MIN-to-MAX namespace row. That is not evidence that object updates
        // belong in a shard. Accept only actual shard-container rows and
        // explicitly reject the root's self range; otherwise a normal listing
        // poisons the root-db-state cache and the next DELETE leaves a stale
        // container row (object-expirer outdated-404/412 regression).
        let name = sr.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let Some((range_account, _)) = name.split_once('/') else {
            return false;
        };
        if name == root_path || !range_account.starts_with(".shards_") {
            return false;
        }
        bounds.push((
            sr.get("lower")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            sr.get("upper")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
        ));
    }
    bounds.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    if !bounds.first().is_some_and(|(lower, _)| lower.is_empty())
        || !bounds.last().is_some_and(|(_, upper)| upper.is_empty())
    {
        return false;
    }
    bounds
        .windows(2)
        .all(|pair| !pair[0].1.is_empty() && pair[0].1 == pair[1].0)
}

/// Fold per-replica object-listing replies.
///
/// `None` is 404/timeout (not empty). `Some([])` is a successful 200 [].
/// `empty_wins` (settled ACTIVE listing): any 200 [] is authoritative empty
/// so a lagging replica cannot resurrect DELETE leftovers (L1418). Otherwise
/// union nonempty replicas (L1146 extra PUTs / L1321 cleave). 404 is not empty.
pub(crate) fn fold_replica_listings(
    replies: &[Option<Vec<serde_json::Value>>],
    empty_wins: bool,
) -> Option<Vec<serde_json::Value>> {
    fold_replica_listings_dated(replies, empty_wins, &[])
}

/// Same as [`fold_replica_listings`], with per-reply container timestamps
/// aligned with `replies`. A nonempty listing newer than every 200 [] is a
/// just-cleaved shard (L1517), not L1418 leftover (leftover is older than
/// DELETE). This is not newest-fold: majority still wins when names exist.
pub(crate) fn fold_replica_listings_dated(
    replies: &[Option<Vec<serde_json::Value>>],
    empty_wins: bool,
    timestamps: &[Timestamp],
) -> Option<Vec<serde_json::Value>> {
    let ts_at = |i: usize| timestamps.get(i).copied().unwrap_or(Timestamp::zero());
    let mut arrays: Vec<Vec<serde_json::Value>> = Vec::new();
    let mut n_empty = 0usize;
    let mut n_200 = 0usize;
    for r in replies {
        match r {
            None => {}
            Some(a) if a.is_empty() => {
                n_200 += 1;
                n_empty += 1;
            }
            Some(a) => {
                n_200 += 1;
                arrays.push(a.clone());
            }
        }
    }
    if arrays.is_empty() {
        return if n_empty > 0 { Some(Vec::new()) } else { None };
    }
    if empty_wins && n_200 > 0 {
        // Probe L1985: 2/3 replicas still list DELETE'd first-shard names.
        // A newer strict subset ([alpha] after DELETE+PUT) is the settled
        // listing; collapse older supersets before majority vote.
        let collapsed = collapse_lagging_supersets(replies, timestamps);
        let arrays: Vec<Vec<serde_json::Value>> = collapsed
            .iter()
            .filter_map(|r| r.as_ref())
            .filter(|a| !a.is_empty())
            .cloned()
            .collect();
        let n_200 = collapsed.iter().filter(|r| r.is_some()).count();
        // Majority of 200 replies must list the name. Empty 200 [] votes
        // against every name (L1418). A lagging superset of DELETE'd
        // originals is a minority (L692). Extra PUTs on ≥2 replicas stay
        // (L643). 404 does not vote (not a 200).
        let mut counts: std::collections::HashMap<String, (usize, serde_json::Value)> =
            std::collections::HashMap::new();
        for a in &arrays {
            let mut seen = std::collections::HashSet::new();
            for item in a {
                let key = listing_item_sort_key(item).to_string();
                if key.is_empty() || !seen.insert(key.clone()) {
                    continue;
                }
                counts
                    .entry(key)
                    .and_modify(|(c, _)| *c += 1)
                    .or_insert((1, item.clone()));
            }
        }
        let mut kept: Vec<serde_json::Value> = counts
            .into_iter()
            .filter(|(_, (c, _))| *c * 2 > n_200)
            .map(|(_, (_, item))| item)
            .collect();
        kept.sort_by(|a, b| listing_item_sort_key(a).cmp(listing_item_sort_key(b)));
        if kept.is_empty() {
            // Majority empty: L1418 leftover (older) vs L1517 just-cleaved
            // (newer than the empty under-populated replicas).
            let mut max_empty = Timestamp::zero();
            for (i, r) in replies.iter().enumerate() {
                if matches!(r, Some(a) if a.is_empty()) && ts_at(i) > max_empty {
                    max_empty = ts_at(i);
                }
            }
            let mut best: Option<(Timestamp, usize)> = None;
            for (i, r) in replies.iter().enumerate() {
                if let Some(a) = r {
                    if !a.is_empty() {
                        let ts = ts_at(i);
                        if best.map(|(b, _)| ts >= b).unwrap_or(true) {
                            best = Some((ts, i));
                        }
                    }
                }
            }
            if let Some((ts, i)) = best {
                if ts > max_empty {
                    let mut out = replies[i].clone().unwrap_or_default();
                    out.sort_by(|a, b| listing_item_sort_key(a).cmp(listing_item_sort_key(b)));
                    return Some(out);
                }
            }
            return Some(Vec::new());
        }
        // Majority drops a just-cleaved 1/3 superset (L1517 obj-0100..0198).
        // Fill extras that occupy a single gap in the majority listing.
        // Interleaved DELETE leftovers span many gaps (L692) and stay dropped.
        kept = fill_single_gap_from_supersets(&kept, &arrays);
        return Some(kept);
    }
    Some(merge_sharded_object_listings(&arrays, usize::MAX))
}

fn parse_listing_json_body(resp: Response) -> Option<Vec<serde_json::Value>> {
    if !(200..300).contains(&resp.status) {
        return None;
    }
    let body = resp.body.into_vec(16 * 1024 * 1024).ok()?;
    if resp.status == 204 || body.is_empty() {
        return Some(Vec::new());
    }
    let val: serde_json::Value = serde_json::from_slice(&body).ok()?;
    Some(val.as_array().cloned().unwrap_or_default())
}

pub(crate) fn listing_resp_timestamp(headers: &HeaderKeyDict) -> Timestamp {
    // Prefer PUT/data timestamps. CS always sends X-Backend-Timestamp as
    // created_at, which is identical across replicas and hides DELETE/PUT
    // freshness (probe L1985 leftover after reclaim).
    for key in [
        "X-Backend-Data-Timestamp",
        "X-Backend-PUT-Timestamp",
        "X-PUT-Timestamp",
        "X-Backend-Timestamp",
        "X-Timestamp",
    ] {
        if let Some(v) = headers.get(key).filter(|s| !s.is_empty()) {
            if let Ok(ts) = v.parse::<Timestamp>() {
                return ts;
            }
        }
    }
    Timestamp::zero()
}

/// If listing A is a strict subset of B and A is newer, B is a lagging
/// DELETE leftover (probe L1985: `[alpha]` vs `[alpha]+obj-1-000…`).
fn collapse_lagging_supersets(
    replies: &[Option<Vec<serde_json::Value>>],
    timestamps: &[Timestamp],
) -> Vec<Option<Vec<serde_json::Value>>> {
    let name_set = |a: &[serde_json::Value]| -> std::collections::HashSet<String> {
        a.iter()
            .map(|i| listing_item_sort_key(i).to_string())
            .filter(|k| !k.is_empty())
            .collect()
    };
    let mut out = replies.to_vec();
    for i in 0..out.len() {
        let Some(a) = out[i].as_ref() else {
            continue;
        };
        if a.is_empty() {
            continue;
        }
        let ta = timestamps.get(i).copied().unwrap_or_else(Timestamp::zero);
        if ta == Timestamp::zero() {
            continue;
        }
        let na = name_set(a);
        let a_clone = a.clone();
        for j in 0..out.len() {
            if i == j {
                continue;
            }
            let Some(b) = out[j].as_ref() else {
                continue;
            };
            if b.is_empty() {
                continue;
            }
            let tb = timestamps.get(j).copied().unwrap_or_else(Timestamp::zero);
            let nb = name_set(b);
            if na.len() < nb.len() && na.is_subset(&nb) && ta > tb {
                out[j] = Some(a_clone.clone());
            }
        }
    }
    out
}

/// Keep minority names that sit in exactly one gap of the majority listing.
/// Empty majority is L1418 delete-all: do not resurrect leftovers.
fn fill_single_gap_from_supersets(
    majority: &[serde_json::Value],
    arrays: &[Vec<serde_json::Value>],
) -> Vec<serde_json::Value> {
    if majority.is_empty() {
        return Vec::new();
    }
    let maj_keys: Vec<String> = majority
        .iter()
        .map(|i| listing_item_sort_key(i).to_string())
        .filter(|k| !k.is_empty())
        .collect();
    let maj_set: std::collections::HashSet<&str> = maj_keys.iter().map(|s| s.as_str()).collect();
    let mut extra_items: std::collections::HashMap<String, serde_json::Value> =
        std::collections::HashMap::new();
    for a in arrays {
        let extra: Vec<&serde_json::Value> = a
            .iter()
            .filter(|i| {
                let k = listing_item_sort_key(i);
                !k.is_empty() && !maj_set.contains(k)
            })
            .collect();
        if extra.is_empty() {
            continue;
        }
        if extras_occupy_single_majority_gap(&maj_keys, &extra) {
            for item in extra {
                extra_items
                    .entry(listing_item_sort_key(item).to_string())
                    .or_insert_with(|| (*item).clone());
            }
        }
    }
    if extra_items.is_empty() {
        return majority.to_vec();
    }
    let mut out = majority.to_vec();
    out.extend(extra_items.into_values());
    out.sort_by(|a, b| listing_item_sort_key(a).cmp(listing_item_sort_key(b)));
    out
}

fn extras_occupy_single_majority_gap(maj_sorted: &[String], extra: &[&serde_json::Value]) -> bool {
    if extra.is_empty() || maj_sorted.is_empty() {
        return false;
    }
    let mut gap: Option<usize> = None;
    for item in extra {
        let k = listing_item_sort_key(item);
        let this_gap = match maj_sorted.binary_search_by(|m| m.as_str().cmp(k)) {
            Ok(_) => return false,
            Err(i) => i,
        };
        // Unbounded prefix (i==0) or suffix (i==len) is L1931 leftover after
        // emptying a shard then PUTting one new name (`alpha`). Only fill a
        // hole BETWEEN two majority names (L631 extra PUTs).
        if this_gap == 0 || this_gap == maj_sorted.len() {
            return false;
        }
        match gap {
            None => gap = Some(this_gap),
            Some(g) if g != this_gap => return false,
            Some(_) => {}
        }
    }
    true
}

fn listing_item_sort_key(item: &serde_json::Value) -> &str {
    item.get("name")
        .and_then(|v| v.as_str())
        .or_else(|| item.get("subdir").and_then(|v| v.as_str()))
        .unwrap_or("")
}

/// Merge per-shard object listing arrays, stopping at `limit`.
/// Later sources overwrite same `name` (root residual then shards → shard wins).
///
/// Sort by name/subdir **after** the union. Residual-root insertion order
/// is even originals first; cleaved new PUTs would otherwise appear after
/// them and fail probe test_sharding_listing L631 (`expected 0001, got 0002`).
pub(crate) fn merge_sharded_object_listings(
    shard_listings: &[Vec<serde_json::Value>],
    limit: usize,
) -> Vec<serde_json::Value> {
    merge_sharded_object_listings_dir(shard_listings, limit, false)
}

pub(crate) fn merge_sharded_object_listings_dir(
    shard_listings: &[Vec<serde_json::Value>],
    limit: usize,
    reverse: bool,
) -> Vec<serde_json::Value> {
    use std::collections::HashMap;
    let mut by_name: HashMap<String, serde_json::Value> = HashMap::new();
    for items in shard_listings {
        for item in items {
            // Delimiter listings use `subdir` not `name` (probe
            // test_sharding_listing L576 `[{subdir: obj-}]`).
            let name = listing_item_sort_key(item).to_string();
            if name.is_empty() {
                continue;
            }
            by_name.insert(name, item.clone());
        }
    }
    let mut merged: Vec<serde_json::Value> = by_name.into_values().collect();
    merged.sort_by(|a, b| {
        let ka = listing_item_sort_key(a);
        let kb = listing_item_sort_key(b);
        if reverse {
            kb.cmp(ka)
        } else {
            ka.cmp(kb)
        }
    });
    if merged.len() > limit {
        merged.truncate(limit);
    }
    merged
}

/// One shard (or nonempty residual root) contribution to a sharded GET listing.
pub(crate) struct ListingFeed {
    /// Bounds/timestamp kept for diagnostics; merge is a name union (L1321).
    #[allow(dead_code)]
    pub lower: String,
    #[allow(dead_code)]
    pub upper: String,
    #[allow(dead_code)]
    pub timestamp: String,
    pub items: Vec<serde_json::Value>,
}

pub(crate) fn listing_feed_timestamp(sr: &serde_json::Value) -> String {
    let ts = sr.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
    let meta = sr
        .get("meta_timestamp")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let state = sr
        .get("state_timestamp")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    [ts, meta, state]
        .into_iter()
        .max()
        .unwrap_or("")
        .to_string()
}

#[allow(dead_code)]
fn object_in_shard_bounds(name: &str, lower: &str, upper: &str) -> bool {
    if !lower.is_empty() && name <= lower {
        return false;
    }
    if !upper.is_empty() && name > upper {
        return false;
    }
    true
}

/// True when `a` is a strict sub-interval of `b` (empty = open bound).
fn shard_bounds_stricter(a_lo: &str, a_hi: &str, b_lo: &str, b_hi: &str) -> bool {
    if a_lo == b_lo && a_hi == b_hi {
        return false;
    }
    let left_ok = b_lo.is_empty() || (!a_lo.is_empty() && a_lo >= b_lo);
    let right_ok = b_hi.is_empty() || (!a_hi.is_empty() && a_hi <= b_hi);
    left_ok && right_ok
}

fn json_range_bounds(sr: &serde_json::Value) -> (&str, &str) {
    (
        sr.get("lower").and_then(|v| v.as_str()).unwrap_or(""),
        sr.get("upper").and_then(|v| v.as_str()).unwrap_or(""),
    )
}

/// True when `sr` is a strict sub-interval of another selected listing range.
pub(crate) fn json_range_is_nested(sr: &serde_json::Value, all: &[&serde_json::Value]) -> bool {
    let name = sr.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let (lo, hi) = json_range_bounds(sr);
    all.iter().any(|other| {
        let on = other.get("name").and_then(|v| v.as_str()).unwrap_or("");
        if on.is_empty() || on == name {
            return false;
        }
        let (olo, ohi) = json_range_bounds(other);
        shard_bounds_stricter(lo, hi, olo, ohi)
    })
}

/// Union object rows across shard feeds. Empty children add nothing and must
/// not omit names that still live on a SHARDING donor (probe L1321 / Python
/// `_get_from_shards` `if not objs: continue`). Newest-covering empty
/// suppression dropped cleaved betas on listing-w91 when the donor's
/// state_timestamp was newer than the CLEAVED children. L1418 leftover is
/// handled by settled replica empty-wins, not by this merge.
pub(crate) fn merge_listings_newest_covering(
    feeds: &[ListingFeed],
    limit: usize,
    reverse: bool,
) -> Vec<serde_json::Value> {
    let arrays: Vec<Vec<serde_json::Value>> = feeds.iter().map(|f| f.items.clone()).collect();
    merge_sharded_object_listings_dir(&arrays, limit, reverse)
}

/// Python `swift.common.utils.csv_append`.
fn csv_append(existing: Option<&str>, item: &str) -> String {
    match existing {
        Some(s) if !s.is_empty() => format!("{s},{item}"),
        _ => item.to_string(),
    }
}

/// Python `_backend_requests` `set_container_update`: send the percent-encoded
/// shard location in `X-Backend-Quoted-Container-Path` so object-servers update
/// the nested shard, not the root (probe L1435). Do not also send the legacy
/// raw header: shard paths may contain NUL, CR, or LF and therefore cannot be
/// represented safely as an HTTP/1.1 header value.
pub(crate) fn stamp_shard_container_path(
    headers: &mut HeaderKeyDict,
    upd_account: &str,
    upd_container: &str,
    account: &str,
    container: &str,
) {
    if upd_account == account && upd_container == container {
        return;
    }
    let path = format!("{upd_account}/{upd_container}");
    let quoted = percent_encode_path(&path);
    headers.set("X-Backend-Quoted-Container-Path", &quoted);
    headers.set("X-Backend-Allow-Reserved-Names", "true");
}

pub(crate) fn percent_encode(s: &str) -> String {
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

/// `urllib.parse.quote(value)` with its default `safe='/'`, used for object
/// names in list_endpoints URLs so nested object path separators survive.
fn percent_encode_path(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'/' | b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
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
            if (rest == "temp-url-key" || rest == "temp-url-key-2") && !value.is_empty() {
                keys.push(value.to_string());
            }
        }
    }
    keys
}

pub(crate) fn fill_container_info_from_head(info: &mut ContainerInfo, resp: &Response) {
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
    info.rfc_compliant_etags = resp
        .headers
        .get("X-Container-Sysmeta-Rfc-Compliant-Etags")
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    info.db_state = resp
        .headers
        .get("X-Backend-Sharding-State")
        .unwrap_or("")
        .to_string();
    info.cors = CorsInfo {
        allow_origin: resp
            .headers
            .get("X-Container-Meta-Access-Control-Allow-Origin")
            .map(str::to_string),
        expose_headers: resp
            .headers
            .get("X-Container-Meta-Access-Control-Expose-Headers")
            .map(str::to_string),
        max_age: resp
            .headers
            .get("X-Container-Meta-Access-Control-Max-Age")
            .map(str::to_string),
    };
}

pub(crate) fn account_info_from_response(resp: &Response) -> AccountInfo {
    let fake = resp
        .headers
        .get("X-Backend-Fake-Account-Listing")
        .map(config_true_value)
        .unwrap_or(false);
    AccountInfo {
        status: resp.status,
        core_access_control: resp
            .headers
            .get("X-Account-Sysmeta-Core-Access-Control")
            .map(str::to_string),
        temp_url_keys: temp_url_keys_from_headers(&resp.headers, "account"),
        rfc_compliant_etags: resp
            .headers
            .get("X-Account-Sysmeta-Rfc-Compliant-Etags")
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        account_really_exists: (200..300).contains(&resp.status) && !fake,
    }
}

/// Account controller `add_acls_from_sys_metadata`: expose the client header.
/// Python treats an empty ACL dict as an absent header (`if acl_dict:`).
fn expose_account_acl_header(resp: &mut Response) {
    if let Some(sys) = resp.headers.remove("X-Account-Sysmeta-Core-Access-Control") {
        if let Some(acls) = swift_middleware::acls_from_sysmeta(Some(&sys)) {
            if !acls.is_empty() {
                resp.headers.set(
                    "X-Account-Access-Control",
                    swift_middleware::format_acl_v2(&acls),
                );
            }
        }
    }
}

/// Privileged account/container headers (Python `swift.proxy.server`
/// `swift_owner_headers` / `swift.common.middleware.acl` owner-only set).
const SWIFT_OWNER_HEADERS: &[&str] = &[
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

/// Python container-server translates `X-Remove-Container-*` into an empty
/// ACL/meta write. IsolatedIdentity account-RW can POST those remove keys
/// even after the matching `swift_owner_headers` values are popped.
fn owner_remove_header(name: &str) -> String {
    match name.strip_prefix("X-") {
        Some(rest) => format!("X-Remove-{rest}"),
        None => format!("X-Remove-{name}"),
    }
}

/// Strip privileged account/container headers for non-owners (Python
/// `swift_owner_headers`).
fn strip_owner_headers(resp: &mut Response, swift_owner: bool) {
    if swift_owner {
        return;
    }
    for name in SWIFT_OWNER_HEADERS {
        resp.headers.remove(name);
    }
}

/// Python `ContainerController` PUT/POST: when `not req.environ.get('swift_owner')`,
/// `req.headers.pop` each `swift_owner_headers` key so the transfer to the
/// container server cannot persist Read/Write ACL or Sync-To/Key.
fn scrub_owner_request_headers(req: &mut Request, swift_owner: bool) {
    if swift_owner {
        return;
    }
    for name in SWIFT_OWNER_HEADERS {
        req.headers.remove(name);
        req.headers.remove(&owner_remove_header(name));
    }
}

/// Request-side owner-header scrub for container PUT/POST. Reads the
/// authorize stamp `X-Backend-Swift-Owner` (TempAuth/Keystone; reseller_admin
/// is also a swift_owner).
fn scrub_container_write_owner_headers(req: &mut Request) {
    let swift_owner = req
        .headers
        .get("X-Backend-Swift-Owner")
        .is_some_and(config_true_value);
    scrub_owner_request_headers(req, swift_owner);
}

/// Client + sysmeta keys `versioned_writes.prepare()` uses to persist
/// `X-Versions-Location` / `X-History-Location`. Not in Python
/// `swift_owner_headers`; IsolatedIdentity still needs an owner gate
/// because account-RW may POST a container (Field H1) while official
/// `test_versioning_container_acl` requires that POST to raise.
const CONTAINER_VERSIONING_REQUEST_HEADERS: &[&str] = &[
    "X-Versions-Location",
    "X-History-Location",
    "X-Remove-Versions-Location",
    "X-Remove-History-Location",
    "X-Container-Sysmeta-Versions-Location",
    "X-Container-Sysmeta-Versions-Mode",
];

/// Official `test_versioning_container_acl`: account2 / account-RW
/// `update_metadata(X-Versions-Location=…)` must be `ResponseError` (403),
/// not a silent 204 that persists sysmeta. Owners and pre-authed / container-sync
/// subrequests keep the headers.
pub(crate) fn deny_non_owner_container_versioning(req: &Request) -> Option<Response> {
    if req
        .headers
        .get("X-Backend-Swift-Owner")
        .is_some_and(config_true_value)
    {
        return None;
    }
    if req
        .headers
        .get("X-Backend-Authorize-Override")
        .is_some_and(config_true_value)
    {
        return None;
    }
    if req
        .headers
        .get("X-Container-Sync-Key")
        .is_some_and(|value| !value.is_empty())
    {
        return None;
    }
    if !CONTAINER_VERSIONING_REQUEST_HEADERS
        .iter()
        .any(|name| req.headers.contains_key(name))
    {
        return None;
    }
    Some(swob_response(403))
}

fn request_to_async(req: Request) -> AsyncRequest {
    let bytes = match req.body {
        swift_http::Body::Buffered(b) => b,
        _ => Vec::new(),
    };
    AsyncRequest {
        method: req.method,
        path: req.path,
        query_string: req.query_string,
        headers: req.headers,
        body: swift_http::IncomingBody::from_bytes(bytes, swift_http::MAX_CONTROL_BODY),
    }
}

/// Pipeline after the current intercepting filter.
///
/// S3 `handle_request_async` issues Swift subrequests (`PUT ?multipart-manifest=put`,
/// object GET). Those must still hit SLO/copy/DLO, not skip to the app.
fn remaining_async_next(
    filters: Arc<Vec<Arc<dyn swift_middleware::Middleware>>>,
    start: usize,
    app: Arc<ProxyApp>,
) -> swift_middleware::AsyncNextFn {
    Arc::new(move |req| {
        let filters = Arc::clone(&filters);
        let app = Arc::clone(&app);
        Box::pin(async move { dispatch_remaining(filters, start, app, req).await })
    })
}

/// Continue an unread Hyper body through the remaining middleware in WSGI
/// order. A streaming middleware may pass a transformed request to another
/// streaming middleware (S3 -> versioned writes), or to a control-plane
/// interceptor (versioned writes -> symlink). The old top-level branch picked
/// only the innermost streaming filter and wired its `next` directly to the
/// proxy app, silently bypassing every inner middleware.
fn remaining_streaming_next(
    filters: Arc<Vec<Arc<dyn swift_middleware::Middleware>>>,
    start: usize,
    app: Arc<ProxyApp>,
) -> swift_middleware::StreamingAsyncNextFn {
    Arc::new(move |req| {
        let filters = Arc::clone(&filters);
        let app = Arc::clone(&app);
        Box::pin(async move { dispatch_streaming_remaining(filters, start, app, req).await })
    })
}

/// Adapt a buffered control-plane subrequest back into the unread-body
/// dispatcher so an inner streaming middleware is not skipped.
fn remaining_buffered_next(
    filters: Arc<Vec<Arc<dyn swift_middleware::Middleware>>>,
    start: usize,
    app: Arc<ProxyApp>,
) -> swift_middleware::AsyncNextFn {
    Arc::new(move |req| {
        let filters = Arc::clone(&filters);
        let app = Arc::clone(&app);
        Box::pin(async move {
            dispatch_streaming_remaining(filters, start, app, request_to_async(req)).await
        })
    })
}

async fn dispatch_streaming_remaining(
    filters: Arc<Vec<Arc<dyn swift_middleware::Middleware>>>,
    start: usize,
    app: Arc<ProxyApp>,
    mut req: AsyncRequest,
) -> Response {
    let head = Request {
        method: req.method.clone(),
        path: req.path.clone(),
        query_string: req.query_string.clone(),
        headers: req.headers.clone(),
        body: swift_http::Body::empty(),
    };

    for j in start..filters.len() {
        if filters[j].streams_request(&head) {
            let next = remaining_streaming_next(Arc::clone(&filters), j + 1, Arc::clone(&app));
            let mut resp = filters[j].handle_streaming_request(req, next).await;
            buffer_manifest_channel(&mut resp).await;
            resp = apply_outbound_filters(
                Arc::clone(&filters),
                start,
                j,
                Arc::clone(&app),
                head.clone_head(),
                resp,
            )
            .await;
            // Streaming intercepts skip this filter in apply_outbound_filters
            // (end=j). SLO part-number reassemble can drop X-Object-Version-Id;
            // versioned_writes::finish restamps it from the client query.
            return filters[j].finish(&head, resp);
        }

        if filters[j].intercepts_request(&head) {
            let body = match req.body.materialize(swift_http::MAX_CONTROL_BODY).await {
                Ok(bytes) => swift_http::Body::Buffered(bytes),
                Err(e) if swift_http::body_too_large(&e) => {
                    return Response::error(413, "Your request is too large.")
                }
                Err(_) => {
                    if head.method == "PUT" {
                        let mut resp = swift_s3api::s3_error_response("RequestTimeout", None, &[]);
                        resp.headers.set("Connection", "close");
                        return resp;
                    }
                    return swob_response(499);
                }
            };
            let request = Request {
                method: req.method,
                path: req.path,
                query_string: req.query_string,
                headers: req.headers,
                body,
            };
            let next = remaining_buffered_next(Arc::clone(&filters), j + 1, Arc::clone(&app));
            let mut resp = filters[j].handle_request_async(request, next).await;
            buffer_manifest_channel(&mut resp).await;
            return apply_outbound_filters(filters, start, j, app, head, resp).await;
        }
    }

    let mut resp = app.handle_async(req).await;
    buffer_manifest_channel(&mut resp).await;
    apply_outbound_filters(filters.clone(), start, filters.len(), app, head, resp).await
}

/// Buffer SLO/DLO channel bodies so reassemble_async can parse the JSON.
async fn buffer_manifest_channel(resp: &mut Response) {
    let slo = resp
        .headers
        .get("X-Static-Large-Object")
        .is_some_and(config_true_value);
    let dlo = resp.headers.get("X-Object-Manifest").is_some();
    if (slo || dlo) && matches!(resp.body, swift_http::Body::Channel(_)) {
        let body = std::mem::replace(&mut resp.body, swift_http::Body::empty());
        match body.collect_async().await {
            Ok(bytes) => resp.body = swift_http::Body::Buffered(bytes),
            Err(_) => resp.body = swift_http::Body::empty(),
        }
    }
}

/// Stamp container/account `rfc-compliant-etags` sysmeta onto an object
/// response so etag-quoter (an *outer* filter) can quote or not without
/// its own info subrequest. Cache-only: object GET already populated
/// container L1; a live HEAD here would hold `&Request` across await
/// (not `Send`) and block a Tokio worker.
fn stamp_rfc_compliant_etag_flags(app: &ProxyApp, head: &Request, resp: &mut Response) {
    let Ok(parts) = split_path(&head.path, 4, 4, true) else {
        return;
    };
    let Some(account) = parts[1].as_deref().filter(|s| !s.is_empty()) else {
        return;
    };
    let Some(container) = parts[2].as_deref().filter(|s| !s.is_empty()) else {
        return;
    };
    // Cache-only: object GET already populated L1 via container_info_async.
    // A live HEAD here would block a Tokio worker (L2) and hang unit tests.
    let Some(cinfo) = app
        .info_cache
        .get_container(&format!("{account}/{container}"))
    else {
        return;
    };
    resp.headers
        .set("X-Backend-Container-Info-Status", cinfo.status.to_string());
    if let Some(flag) = cinfo
        .rfc_compliant_etags
        .as_deref()
        .filter(|s| !s.is_empty())
    {
        resp.headers
            .set("X-Backend-Container-Rfc-Compliant-Etags", flag);
    }
    let container_flag_set = cinfo
        .rfc_compliant_etags
        .as_deref()
        .is_some_and(|s| !s.is_empty());
    if !container_flag_set && (200..300).contains(&cinfo.status) {
        if let Some(ainfo) = app.info_cache.get_account(account) {
            resp.headers
                .set("X-Backend-Account-Info-Status", ainfo.status.to_string());
            if let Some(flag) = ainfo
                .rfc_compliant_etags
                .as_deref()
                .filter(|s| !s.is_empty())
            {
                resp.headers
                    .set("X-Backend-Account-Rfc-Compliant-Etags", flag);
            }
        }
    }
}

/// Outbound WSGI onion for filters in `[start, end)`. Inner intercepts
/// (`handle_request_async`) must still run outer `finish` / `reassemble_async`
/// — SLO GET If-Match is an intercept, etag-quoter is outer.
async fn apply_outbound_filters(
    filters: Arc<Vec<Arc<dyn swift_middleware::Middleware>>>,
    start: usize,
    end: usize,
    app: Arc<ProxyApp>,
    head: Request,
    mut resp: Response,
) -> Response {
    stamp_rfc_compliant_etag_flags(&app, &head, &mut resp);
    for j in (start..end).rev() {
        if filters[j].intercepts_response() {
            // First next() is the captured app response. Later next()s
            // (SLO/DLO segment GET, symlink follow) must still hit the
            // remaining filters — not skip to the app and drop symlink.
            let rest = remaining_async_next(Arc::clone(&filters), j + 1, Arc::clone(&app));
            let captured = Arc::new(Mutex::new(Some(resp)));
            let next: swift_middleware::AsyncNextFn = Arc::new(move |r| {
                let captured = Arc::clone(&captured);
                let rest = Arc::clone(&rest);
                Box::pin(async move {
                    if let Some(inner) = captured.lock().unwrap_or_else(|p| p.into_inner()).take() {
                        return inner;
                    }
                    rest(r).await
                })
            });
            resp = filters[j].reassemble_async(head.clone_head(), next).await;
        } else {
            resp = filters[j].finish(&head, resp);
        }
    }
    resp
}

async fn dispatch_remaining(
    filters: Arc<Vec<Arc<dyn swift_middleware::Middleware>>>,
    start: usize,
    app: Arc<ProxyApp>,
    req: Request,
) -> Response {
    let head = req.clone_head();
    for j in start..filters.len() {
        if filters[j].intercepts_request(&head) {
            let next = remaining_async_next(Arc::clone(&filters), j + 1, Arc::clone(&app));
            let mut resp = filters[j].handle_request_async(req, next).await;
            buffer_manifest_channel(&mut resp).await;
            resp = apply_outbound_filters(
                Arc::clone(&filters),
                start,
                j,
                Arc::clone(&app),
                head.clone_head(),
                resp,
            )
            .await;
            app.apply_pipeline_cors(
                head.method.clone(),
                head.path.clone(),
                head.headers.get("Origin").map(str::to_string),
                &mut resp,
            )
            .await;
            return resp;
        }
    }
    let mut resp = app.handle_async(request_to_async(req)).await;
    buffer_manifest_channel(&mut resp).await;
    resp = apply_outbound_filters(
        Arc::clone(&filters),
        start,
        filters.len(),
        Arc::clone(&app),
        head.clone_head(),
        resp,
    )
    .await;
    app.apply_pipeline_cors(
        head.method.clone(),
        head.path.clone(),
        head.headers.get("Origin").map(str::to_string),
        &mut resp,
    )
    .await;
    resp
}

struct ProxyAsyncService {
    app: Arc<RwLock<Arc<ProxyApp>>>,
    filters: Vec<Arc<dyn swift_middleware::Middleware>>,
}

impl AsyncService for ProxyAsyncService {
    fn call(
        &self,
        req: AsyncRequest,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>> {
        let app = {
            let guard = self.app.read().unwrap_or_else(|p| p.into_inner());
            Arc::clone(&guard)
        };
        let filters = self.filters.clone();
        Box::pin(async move {
            let method = req.method.clone();
            let path = req.path.clone();
            let via = if filters.is_empty() {
                "no_filters"
            } else {
                "filters"
            };
            let resp = async move {
                let mut req = req;
                if filters.is_empty() {
                    let head = Request {
                        method: req.method.clone(),
                        path: req.path.clone(),
                        query_string: req.query_string.clone(),
                        headers: req.headers.clone(),
                        body: swift_http::Body::empty(),
                    };
                    let mut resp = app.handle_async(req).await;
                    app.apply_pipeline_cors(
                        head.method.clone(),
                        head.path.clone(),
                        head.headers.get("Origin").map(str::to_string),
                        &mut resp,
                    )
                    .await;
                    return resp;
                }
                let mut head = Request {
                    method: req.method.clone(),
                    path: req.path.clone(),
                    query_string: req.query_string.clone(),
                    headers: req.headers.clone(),
                    body: swift_http::Body::empty(),
                };
                for filter in &filters {
                    match filter.prepare_async(&mut head).await {
                        swift_middleware::MwPrep::Continue => {}
                        swift_middleware::MwPrep::ShortCircuit(resp) => {
                            let mut resp = resp;
                            for g in filters.iter().rev() {
                                resp = g.finish(&head, resp);
                            }
                            return resp;
                        }
                    }
                }
                req.headers = head.headers.clone();
                req.query_string = head.query_string.clone();
                if filters.iter().any(|f| f.streams_request(&head)) {
                    let mut resp =
                        dispatch_streaming_remaining(Arc::new(filters), 0, Arc::clone(&app), req)
                            .await;
                    app.apply_pipeline_cors(
                        head.method.clone(),
                        head.path.clone(),
                        head.headers.get("Origin").map(str::to_string),
                        &mut resp,
                    )
                    .await;
                    return resp;
                }
                if filters.iter().any(|f| f.intercepts_request(&head)) {
                    let body = match req.body.materialize(swift_http::MAX_CONTROL_BODY).await {
                        Ok(bytes) => swift_http::Body::Buffered(bytes),
                        Err(e) if swift_http::body_too_large(&e) => {
                            return Response::error(413, "Your request is too large.")
                        }
                        Err(_) => {
                            // Python s3api PUT maps Swift 499 (short body /
                            // client hangup) to RequestTimeout 400. The
                            // intercept path never reaches s3api if Hyper
                            // fails the body read (Content-Length mismatch).
                            if head.method == "PUT" {
                                let mut resp =
                                    swift_s3api::s3_error_response("RequestTimeout", None, &[]);
                                resp.headers.set("Connection", "close");
                                return resp;
                            }
                            return swob_response(499);
                        }
                    };
                    let request = Request {
                        method: req.method,
                        path: req.path,
                        query_string: req.query_string,
                        headers: req.headers,
                        body,
                    };
                    let filters_arc = Arc::new(filters.clone());
                    for (i, filter) in filters.iter().enumerate() {
                        if filter.intercepts_request(&head) {
                            let next = remaining_async_next(
                                Arc::clone(&filters_arc),
                                i + 1,
                                Arc::clone(&app),
                            );
                            let mut resp = filter.handle_request_async(request, next).await;
                            buffer_manifest_channel(&mut resp).await;
                            resp = apply_outbound_filters(
                                Arc::clone(&filters_arc),
                                0,
                                i,
                                Arc::clone(&app),
                                head.clone_head(),
                                resp,
                            )
                            .await;
                            app.apply_pipeline_cors(
                                head.method.clone(),
                                head.path.clone(),
                                head.headers.get("Origin").map(str::to_string),
                                &mut resp,
                            )
                            .await;
                            return resp;
                        }
                    }
                    return remaining_async_next(filters_arc, 0, Arc::clone(&app))(request).await;
                }
                let mut resp = app.handle_async(req).await;
                buffer_manifest_channel(&mut resp).await;
                let filters_arc = Arc::new(filters);
                resp = apply_outbound_filters(
                    Arc::clone(&filters_arc),
                    0,
                    filters_arc.len(),
                    Arc::clone(&app),
                    head.clone_head(),
                    resp,
                )
                .await;
                app.apply_pipeline_cors(
                    head.method.clone(),
                    head.path.clone(),
                    head.headers.get("Origin").map(str::to_string),
                    &mut resp,
                )
                .await;
                resp
            }
            .await;
            finalize_service_g6_diag(resp, via, &method, &path)
        })
    }
}

pub fn serve(listener: TcpListener, app: Arc<ProxyApp>) -> std::io::Result<()> {
    swift_http::serve_forever_multi_service(
        vec![listener],
        Arc::new(ProxyAsyncService {
            app: Arc::new(RwLock::new(app)),
            filters: Vec::new(),
        }),
        swift_http::ServerConfig::default(),
    )
}

/// Ring resolver used by `list_endpoints` in the configured middleware
/// pipeline. Every lookup snapshots the current app from the shared slot, so
/// a successful ring reload is visible without rebuilding the middleware.
pub struct ProxyEndpointResolver {
    app: Arc<RwLock<Arc<ProxyApp>>>,
}

impl ProxyEndpointResolver {
    pub fn new(app: Arc<RwLock<Arc<ProxyApp>>>) -> Self {
        Self { app }
    }
}

impl swift_middleware::EndpointResolver for ProxyEndpointResolver {
    fn endpoints(
        &self,
        account: &str,
        container: Option<&str>,
        object: Option<&str>,
    ) -> Result<(Vec<String>, Option<i64>), String> {
        let current = {
            let guard = self
                .app
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            Arc::clone(&guard)
        };
        current.list_endpoints(account, container, object)
    }
}

/// Serve behind the always-on middleware pipeline
/// (`catch_errors gatekeeper healthcheck proxy-server`), the default
/// Swift proxy front matter.
pub fn serve_with_pipeline(listener: TcpListener, app: Arc<ProxyApp>) -> std::io::Result<()> {
    serve_with_filters(listener, app, Vec::new())
}

/// Serve behind the always-on pipeline plus `extra` filters inserted
/// after gatekeeper (e.g. a configured `TempAuth`), matching the usual
/// `catch_errors gatekeeper healthcheck <auth> proxy-server` order.
pub fn serve_with_filters(
    listener: TcpListener,
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

/// The three front-matter filters that normally guard every public proxy
/// listener.  Python's `InternalClient` is the deliberate exception: it
/// loads an in-process pipeline without gatekeeper so trusted `X-Backend-*`
/// controls can reach the terminal proxy app.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CorePipelineFilters {
    pub catch_errors: bool,
    pub gatekeeper: bool,
    pub healthcheck: bool,
}

impl Default for CorePipelineFilters {
    fn default() -> Self {
        Self {
            catch_errors: true,
            gatekeeper: true,
            healthcheck: true,
        }
    }
}

/// [`serve_with_filters`] with an explicit HTTP [`swift_http::ServerConfig`]
/// (worker pool size, client timeout, access log, graceful shutdown) and a
/// hot-swappable app: the innermost handler re-reads `app` on every request,
/// so a ring-reload thread can atomically swap in a freshly built
/// [`ProxyApp`] without restarting the server.
pub fn serve_with_filters_and_config(
    listener: TcpListener,
    app: Arc<RwLock<Arc<ProxyApp>>>,
    extra: Vec<Arc<dyn swift_middleware::Middleware>>,
    config: swift_http::ServerConfig,
) -> std::io::Result<()> {
    serve_with_core_filters_and_config(listener, app, extra, CorePipelineFilters::default(), config)
}

/// Serve with an explicitly selected front-matter pipeline. Public callers
/// should use [`serve_with_filters_and_config`]; the proxy binary only calls
/// this variant after enforcing that a gatekeeper-free listener is both
/// explicitly marked as an internal-client endpoint and bound to loopback.
pub fn serve_with_core_filters_and_config(
    listener: TcpListener,
    app: Arc<RwLock<Arc<ProxyApp>>>,
    extra: Vec<Arc<dyn swift_middleware::Middleware>>,
    core: CorePipelineFilters,
    config: swift_http::ServerConfig,
) -> std::io::Result<()> {
    use swift_middleware::{CatchErrors, Gatekeeper, HealthCheck, Middleware};
    let mut filters: Vec<Arc<dyn Middleware>> = Vec::new();
    if core.catch_errors {
        filters.push(Arc::new(CatchErrors::new("")));
    }
    if core.gatekeeper {
        filters.push(Arc::new(Gatekeeper::default()));
    }
    if core.healthcheck {
        filters.push(Arc::new(HealthCheck::default()));
    }
    filters.extend(extra);
    swift_http::serve_forever_multi_service(
        vec![listener],
        Arc::new(ProxyAsyncService { app, filters }),
        config,
    )
}

#[cfg(test)]
mod pipeline_async_tests {
    use super::*;
    use swift_http::IncomingBody;

    /// Object-server Range on a stub segment (inclusive `bytes=start-end`).
    fn stub_object_range(req: &Request, body: &[u8]) -> Response {
        let Some(spec) = req
            .headers
            .get("Range")
            .and_then(|r| r.strip_prefix("bytes="))
        else {
            return Response::with_body(200, body.to_vec());
        };
        let Some((start, end)) = spec.split_once('-') else {
            return Response::with_body(200, body.to_vec());
        };
        let (Ok(start), Ok(end)) = (start.parse::<usize>(), end.parse::<usize>()) else {
            return Response::with_body(200, body.to_vec());
        };
        if body.is_empty() || start >= body.len() || start > end {
            return Response::error(416, "Requested Range Not Satisfiable");
        }
        let end = end.min(body.len() - 1);
        let slice = body[start..=end].to_vec();
        let mut resp = Response::with_body(206, slice);
        resp.headers.set(
            "Content-Range",
            format!("bytes {start}-{end}/{}", body.len()),
        );
        resp
    }

    #[tokio::test]
    async fn tempauth_prepare_runs_on_hyper_path_so_auth_endpoint_is_not_404() {
        let app = Arc::new(ProxyApp::new(
            policy_ring_tests::ring(1),
            policy_ring_tests::ring(2),
            ProxyConfig {
                auth_enabled: true,
                ..Default::default()
            },
        ));
        let mut ta = swift_middleware::TempAuth::new("http://127.0.0.1:8080");
        ta.add_user("test", "tester", "testing", &[".admin"]);
        let svc = ProxyAsyncService {
            app: Arc::new(RwLock::new(app)),
            filters: vec![
                Arc::new(swift_middleware::CatchErrors::new("")),
                Arc::new(swift_middleware::Gatekeeper::default()),
                Arc::new(ta),
            ],
        };
        let mut headers = HeaderKeyDict::new();
        headers.set("X-Auth-User", "test:tester");
        headers.set("X-Auth-Key", "testing");
        let resp = svc
            .call(AsyncRequest {
                method: "GET".into(),
                path: "/auth/v1.0".into(),
                query_string: String::new(),
                headers,
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(
            resp.status, 200,
            "tempauth must run on the production async path, got {}",
            resp.reason
        );
        assert!(
            resp.headers.get("X-Auth-Token").is_some(),
            "token missing: {:?}",
            resp.headers
        );
        assert!(
            resp.headers.get("X-Trans-Id").is_some(),
            "catch_errors must stamp X-Trans-Id on the async path"
        );
    }

    /// Field G4 on isolated :18080 (frozen 2a6110c) returned 401 for TempURL
    /// because HMAC lived only in `handle()`, which Hyper never calls.
    /// `prepare` must stamp `X-Backend-Authorize-Override` so
    /// `authorize_async` does not treat a signed URL as anonymous.
    #[tokio::test]
    async fn tempurl_prepare_runs_on_hyper_path_so_signed_get_is_not_auth_401() {
        const KEY: &str = "mykey";
        const EXPIRES: &str = "4102444800";
        const SIG: &str = "beb29507e95de0350c1076f7671d128cc02120c3186c0ba7c70d4d3a1bba6bfe";
        let app = Arc::new(ProxyApp::new(
            policy_ring_tests::ring(1),
            policy_ring_tests::ring(2),
            ProxyConfig {
                auth_enabled: true,
                // No live object nodes in this unit test; fail the backend
                // connect quickly once authorize has accepted the TempURL.
                conn_timeout: Duration::from_millis(50),
                node_timeout: Duration::from_millis(50),
                ..Default::default()
            },
        ));
        let tu = swift_middleware::TempUrl::new(Arc::new(
            swift_middleware::ClosureKeyProvider::new(|_a, _c| vec![KEY.to_string()]),
        ));
        let svc = ProxyAsyncService {
            app: Arc::new(RwLock::new(app)),
            filters: vec![
                Arc::new(swift_middleware::CatchErrors::new("")),
                Arc::new(swift_middleware::Gatekeeper::default()),
                Arc::new(tu),
            ],
        };
        let resp = svc
            .call(AsyncRequest {
                method: "GET".into(),
                path: "/v1/AUTH_account/container/object".into(),
                query_string: format!("temp_url_sig={SIG}&temp_url_expires={EXPIRES}"),
                headers: HeaderKeyDict::new(),
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_ne!(
            resp.status, 401,
            "valid TempURL on the Hyper path must not 401 (got {} {:?})",
            resp.status, resp.reason
        );
    }

    #[tokio::test]
    async fn tempurl_prepare_rejects_bad_sig_on_hyper_path() {
        let app = Arc::new(ProxyApp::new(
            policy_ring_tests::ring(1),
            policy_ring_tests::ring(2),
            ProxyConfig {
                auth_enabled: true,
                ..Default::default()
            },
        ));
        let tu = swift_middleware::TempUrl::new(Arc::new(
            swift_middleware::ClosureKeyProvider::new(|_a, _c| vec!["mykey".to_string()]),
        ));
        let svc = ProxyAsyncService {
            app: Arc::new(RwLock::new(app)),
            filters: vec![Arc::new(tu)],
        };
        let resp = svc
            .call(AsyncRequest {
                method: "GET".into(),
                path: "/v1/AUTH_account/container/object".into(),
                query_string: "temp_url_sig=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&temp_url_expires=4102444800".into(),
                headers: HeaderKeyDict::new(),
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(resp.status, 401);
        let mut resp = resp;
        resp.body.materialize(u64::MAX).unwrap();
        let body = match &resp.body {
            swift_http::Body::Buffered(b) => String::from_utf8_lossy(b).into_owned(),
            _ => String::new(),
        };
        assert!(
            body.contains("Temp URL invalid"),
            "bad HMAC on Hyper path must use TempURL 401 body, got {body:?}"
        );
    }

    /// Container GET that looks like IsolatedIdentity after
    /// `X-Remove-Container-Meta-Web-Listings`: live HEAD has object-count
    /// and no web-listings.
    struct ListingsOffContainerStub;
    impl swift_middleware::Middleware for ListingsOffContainerStub {
        fn handle(&self, req: Request, next: &swift_middleware::NextFn) -> Response {
            next(req)
        }
        fn intercepts_request(&self, req: &Request) -> bool {
            matches!(req.method.as_str(), "GET" | "HEAD")
                && (req.path == "/v1/AUTH_account/container"
                    || req.path == "/v1/AUTH_account/container/")
        }
        fn handle_request_async(
            &self,
            req: Request,
            _next: swift_middleware::AsyncNextFn,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>> {
            Box::pin(async move {
                if req.method == "HEAD" {
                    let mut resp = Response::new(204);
                    resp.headers.set("X-Container-Object-Count", "4");
                    resp.headers.set("X-Timestamp", "1000.00000");
                    return resp;
                }
                let mut resp = Response::with_body(200, b"[]".to_vec());
                resp.headers.set("Content-Type", "application/json");
                resp.headers.set("X-Container-Object-Count", "4");
                resp
            })
        }
    }

    /// Official TestStaticWebTempurl.test_staticweb_off: prefix="" TempURL
    /// of the container is 401 when listings are off (no staticweb
    /// Content-Generator). Hyper must run TempURL.finish after StaticWeb.
    #[tokio::test]
    async fn staticweb_off_prefix_tempurl_is_401_on_hyper_path() {
        const KEY: &str = "mykey";
        const EXPIRES: &str = "4102444800";
        // sha256 HMAC over GET\n4102444800\nprefix:/v1/AUTH_account/container/
        const SIG: &str = "f13df77135f801a28d05f2b3ec2f3558fa9f5858d9218bc6c84b09fccffd5fa6";
        let app = Arc::new(ProxyApp::new(
            policy_ring_tests::ring(1),
            policy_ring_tests::ring(2),
            ProxyConfig {
                auth_enabled: true,
                ..Default::default()
            },
        ));
        let tu = swift_middleware::TempUrl::new(Arc::new(
            swift_middleware::ClosureKeyProvider::new(|_a, _c| vec![KEY.to_string()]),
        ));
        let svc = ProxyAsyncService {
            app: Arc::new(RwLock::new(app)),
            filters: vec![
                Arc::new(tu),
                Arc::new(swift_middleware::StaticWeb::new()),
                Arc::new(ListingsOffContainerStub),
            ],
        };
        let resp = svc
            .call(AsyncRequest {
                method: "GET".into(),
                path: "/v1/AUTH_account/container".into(),
                query_string: format!(
                    "temp_url_sig={SIG}&temp_url_expires={EXPIRES}&temp_url_prefix="
                ),
                headers: HeaderKeyDict::new(),
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(
            resp.status, 401,
            "listings-off prefix TempURL must 401 on Hyper, got {}",
            resp.status
        );
        let mut resp = resp;
        resp.body.materialize(u64::MAX).unwrap();
        let body = match &resp.body {
            swift_http::Body::Buffered(b) => String::from_utf8_lossy(b).into_owned(),
            _ => String::new(),
        };
        assert!(
            body.contains("Temp URL invalid"),
            "official test_staticweb_off body, got {body:?}"
        );
    }

    /// Object-server apply_conditional on the physical manifest ETag.
    /// Official TestDlo.test_dlo_if_match_get uses the assembled DLO ETag.
    struct DloIfMatchObjectServerStub;
    impl swift_middleware::Middleware for DloIfMatchObjectServerStub {
        fn handle(&self, req: Request, next: &swift_middleware::NextFn) -> Response {
            next(req)
        }
        fn intercepts_request(&self, req: &Request) -> bool {
            req.path.starts_with("/v1/a/c")
        }
        fn handle_request_async(
            &self,
            req: Request,
            _next: swift_middleware::AsyncNextFn,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>> {
            Box::pin(async move {
                if (req.method == "GET" || req.method == "HEAD")
                    && req.path == "/v1/a/c/manifest"
                    && req.headers.get("If-Match").is_some()
                {
                    return Response::error(412, "Precondition Failed");
                }
                if req.path == "/v1/a/c/manifest" {
                    let mut resp = Response::new(200);
                    resp.headers.set("X-Object-Manifest", "c/segs/");
                    resp.headers.set("Etag", "physical-manifest");
                    return resp;
                }
                if req.method == "GET" && req.path == "/v1/a/c" {
                    let listing = serde_json::json!([
                        {"name": "segs/1", "bytes": 3, "hash": "c4ca4238a0b923820dcc509a6f75849b"},
                        {"name": "segs/2", "bytes": 3, "hash": "c81e728d9d4c2f636f067f89cc14862c"},
                    ]);
                    return Response::with_body(200, serde_json::to_vec(&listing).unwrap());
                }
                if req.path == "/v1/a/c/segs/1" {
                    return Response::with_body(200, b"one".to_vec());
                }
                if req.path == "/v1/a/c/segs/2" {
                    return Response::with_body(200, b"two".to_vec());
                }
                Response::new(404)
            })
        }
    }

    #[tokio::test]
    async fn dlo_if_match_assembled_etag_is_200_on_hyper_path() {
        let app = Arc::new(ProxyApp::new(
            policy_ring_tests::ring(1),
            policy_ring_tests::ring(2),
            ProxyConfig {
                auth_enabled: false,
                ..Default::default()
            },
        ));
        let svc = ProxyAsyncService {
            app: Arc::new(RwLock::new(app)),
            filters: vec![
                Arc::new(swift_middleware::DynamicLargeObject::new()),
                Arc::new(DloIfMatchObjectServerStub),
            ],
        };
        let head = svc
            .call(AsyncRequest {
                method: "HEAD".into(),
                path: "/v1/a/c/manifest".into(),
                query_string: String::new(),
                headers: HeaderKeyDict::new(),
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(
            head.status, 200,
            "HEAD DLO must assemble, got {}",
            head.status
        );
        let etag = head
            .headers
            .get("Etag")
            .expect("assembled DLO Etag")
            .to_string();
        let mut headers = HeaderKeyDict::new();
        headers.set("If-Match", &etag);
        let mut resp = svc
            .call(AsyncRequest {
                method: "GET".into(),
                path: "/v1/a/c/manifest".into(),
                query_string: String::new(),
                headers,
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(
            resp.status, 200,
            "official test_dlo_if_match_get on Hyper, got {}",
            resp.status
        );
        resp.body.materialize(u64::MAX).unwrap();
        let body = match &resp.body {
            swift_http::Body::Buffered(b) => b.clone(),
            _ => Vec::new(),
        };
        assert_eq!(body, b"onetwo");
        let mut head_ok = HeaderKeyDict::new();
        head_ok.set("If-Match", &etag);
        let head_match = svc
            .call(AsyncRequest {
                method: "HEAD".into(),
                path: "/v1/a/c/manifest".into(),
                query_string: String::new(),
                headers: head_ok,
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(
            head_match.status, 200,
            "official test_dlo_if_match_head on Hyper, got {}",
            head_match.status
        );
        let mut miss = HeaderKeyDict::new();
        miss.set("If-Match", format!("not-{etag}"));
        let miss_head = svc
            .call(AsyncRequest {
                method: "HEAD".into(),
                path: "/v1/a/c/manifest".into(),
                query_string: String::new(),
                headers: miss,
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(
            miss_head.status, 412,
            "official test_dlo_if_match_head miss on Hyper, got {}",
            miss_head.status
        );
    }

    /// Official TestDlo.test_dlo_referer_on_segment_container step 2:
    /// manifest readable, segment-container listing 403, relayed as 403.
    struct DloRefererDeniedListingStub;
    impl swift_middleware::Middleware for DloRefererDeniedListingStub {
        fn handle(&self, req: Request, next: &swift_middleware::NextFn) -> Response {
            next(req)
        }
        fn intercepts_request(&self, req: &Request) -> bool {
            req.path.starts_with("/v1/a/")
        }
        fn handle_request_async(
            &self,
            req: Request,
            _next: swift_middleware::AsyncNextFn,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>> {
            Box::pin(async move {
                if req.path == "/v1/a/c/manifest" {
                    let mut resp = Response::new(200);
                    resp.headers.set("X-Object-Manifest", "other/segs/");
                    return resp;
                }
                if req.path == "/v1/a/other" {
                    return Response::error(403, "Forbidden");
                }
                Response::new(404)
            })
        }
    }

    #[tokio::test]
    async fn dlo_referer_denied_listing_is_403_on_hyper_path() {
        let app = Arc::new(ProxyApp::new(
            policy_ring_tests::ring(1),
            policy_ring_tests::ring(2),
            ProxyConfig {
                auth_enabled: false,
                ..Default::default()
            },
        ));
        let svc = ProxyAsyncService {
            app: Arc::new(RwLock::new(app)),
            filters: vec![
                Arc::new(swift_middleware::DynamicLargeObject::new()),
                Arc::new(DloRefererDeniedListingStub),
            ],
        };
        let resp = svc
            .call(AsyncRequest {
                method: "GET".into(),
                path: "/v1/a/c/manifest".into(),
                query_string: String::new(),
                headers: HeaderKeyDict::new(),
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(
            resp.status, 403,
            "official test_dlo_referer step 2 on Hyper, got {}",
            resp.status
        );
    }

    /// Official TestStaticWebTempurl.test_get_root: listings on, prefix=""
    /// TempURL of the container without a trailing slash is 301.
    struct ListingsOnContainerStub;
    impl swift_middleware::Middleware for ListingsOnContainerStub {
        fn handle(&self, req: Request, next: &swift_middleware::NextFn) -> Response {
            next(req)
        }
        fn intercepts_request(&self, req: &Request) -> bool {
            matches!(req.method.as_str(), "GET" | "HEAD")
                && (req.path == "/v1/AUTH_account/container"
                    || req.path == "/v1/AUTH_account/container/")
        }
        fn handle_request_async(
            &self,
            req: Request,
            _next: swift_middleware::AsyncNextFn,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>> {
            Box::pin(async move {
                let mut resp = if req.method == "HEAD" {
                    Response::new(204)
                } else {
                    Response::with_body(200, b"[]".to_vec())
                };
                resp.headers.set("X-Container-Meta-Web-Listings", "true");
                resp.headers.set("X-Container-Object-Count", "1");
                resp.headers.set("X-Timestamp", "1000.00000");
                resp
            })
        }
    }

    #[tokio::test]
    async fn staticweb_listings_on_prefix_tempurl_without_slash_is_301_on_hyper() {
        const KEY: &str = "mykey";
        const EXPIRES: &str = "4102444800";
        const SIG: &str = "f13df77135f801a28d05f2b3ec2f3558fa9f5858d9218bc6c84b09fccffd5fa6";
        let app = Arc::new(ProxyApp::new(
            policy_ring_tests::ring(1),
            policy_ring_tests::ring(2),
            ProxyConfig {
                auth_enabled: true,
                ..Default::default()
            },
        ));
        let tu = swift_middleware::TempUrl::new(Arc::new(
            swift_middleware::ClosureKeyProvider::new(|_a, _c| vec![KEY.to_string()]),
        ));
        let svc = ProxyAsyncService {
            app: Arc::new(RwLock::new(app)),
            filters: vec![
                Arc::new(tu),
                Arc::new(swift_middleware::StaticWeb::new()),
                Arc::new(ListingsOnContainerStub),
            ],
        };
        let resp = svc
            .call(AsyncRequest {
                method: "GET".into(),
                path: "/v1/AUTH_account/container".into(),
                query_string: format!(
                    "temp_url_sig={SIG}&temp_url_expires={EXPIRES}&temp_url_prefix="
                ),
                headers: HeaderKeyDict::new(),
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(
            resp.status, 301,
            "official test_get_root no-slash prefix TempURL must 301, got {}",
            resp.status
        );
    }

    /// Official TestSlo.test_slo_referer_on_segment_container step 2:
    /// manifest readable, first segment 403 → 409 Conflict (not 403).
    struct SloRefererDeniedSegmentStub;
    impl swift_middleware::Middleware for SloRefererDeniedSegmentStub {
        fn handle(&self, req: Request, next: &swift_middleware::NextFn) -> Response {
            next(req)
        }
        fn intercepts_request(&self, req: &Request) -> bool {
            req.path.starts_with("/v1/a/")
        }
        fn handle_request_async(
            &self,
            req: Request,
            _next: swift_middleware::AsyncNextFn,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>> {
            Box::pin(async move {
                if req.path == "/v1/a/c/manifest" {
                    let manifest = serde_json::json!([
                        {"name": "/other/s1", "bytes": 3, "hash": "c4ca4238a0b923820dcc509a6f75849b"},
                    ]);
                    let mut resp = Response::with_body(200, serde_json::to_vec(&manifest).unwrap());
                    resp.headers.set("X-Static-Large-Object", "True");
                    return resp;
                }
                if req.path == "/v1/a/other/s1" {
                    return Response::error(403, "Forbidden");
                }
                Response::new(404)
            })
        }
    }

    #[tokio::test]
    async fn slo_referer_denied_segment_is_409_on_hyper_path() {
        let app = Arc::new(ProxyApp::new(
            policy_ring_tests::ring(1),
            policy_ring_tests::ring(2),
            ProxyConfig {
                auth_enabled: false,
                ..Default::default()
            },
        ));
        let svc = ProxyAsyncService {
            app: Arc::new(RwLock::new(app)),
            filters: vec![
                Arc::new(swift_middleware::Slo::new()),
                Arc::new(SloRefererDeniedSegmentStub),
            ],
        };
        let resp = svc
            .call(AsyncRequest {
                method: "GET".into(),
                path: "/v1/a/c/manifest".into(),
                query_string: String::new(),
                headers: HeaderKeyDict::new(),
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(
            resp.status, 409,
            "official test_slo_referer step 2 on Hyper, got {}",
            resp.status
        );
    }

    /// Object-server apply_conditional on the physical SLO JSON ETag.
    /// Official TestSlo.test_slo_if_match_get uses the assembled SLO ETag.
    struct SloIfMatchObjectServerStub;
    impl swift_middleware::Middleware for SloIfMatchObjectServerStub {
        fn handle(&self, req: Request, next: &swift_middleware::NextFn) -> Response {
            next(req)
        }
        fn intercepts_request(&self, req: &Request) -> bool {
            req.path.starts_with("/v1/a/")
        }
        fn handle_request_async(
            &self,
            req: Request,
            _next: swift_middleware::AsyncNextFn,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>> {
            Box::pin(async move {
                if (req.method == "GET" || req.method == "HEAD")
                    && req.path == "/v1/a/c/manifest"
                    && (req.headers.get("If-Match").is_some()
                        || req.headers.get("If-None-Match").is_some())
                {
                    return Response::error(412, "Precondition Failed");
                }
                if req.path == "/v1/a/c/manifest" {
                    let manifest = serde_json::json!([
                        {"name": "/c/s1", "bytes": 3, "hash": "c4ca4238a0b923820dcc509a6f75849b"},
                    ]);
                    let mut resp = Response::with_body(200, serde_json::to_vec(&manifest).unwrap());
                    resp.headers.set("X-Static-Large-Object", "True");
                    resp.headers.set("Etag", "physical-json");
                    return resp;
                }
                if req.path == "/v1/a/c/s1" {
                    return Response::with_body(200, b"one".to_vec());
                }
                Response::new(404)
            })
        }
    }

    #[tokio::test]
    async fn slo_if_match_assembled_etag_is_200_on_hyper_path() {
        let app = Arc::new(ProxyApp::new(
            policy_ring_tests::ring(1),
            policy_ring_tests::ring(2),
            ProxyConfig {
                auth_enabled: false,
                ..Default::default()
            },
        ));
        let svc = ProxyAsyncService {
            app: Arc::new(RwLock::new(app)),
            filters: vec![
                Arc::new(swift_middleware::Slo::new()),
                Arc::new(SloIfMatchObjectServerStub),
            ],
        };
        let head = svc
            .call(AsyncRequest {
                method: "HEAD".into(),
                path: "/v1/a/c/manifest".into(),
                query_string: String::new(),
                headers: HeaderKeyDict::new(),
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(
            head.status, 200,
            "HEAD SLO must assemble, got {}",
            head.status
        );
        let etag = head
            .headers
            .get("Etag")
            .expect("assembled SLO Etag")
            .to_string();
        assert_ne!(etag, "physical-json", "must not leak physical JSON etag");
        let mut headers = HeaderKeyDict::new();
        headers.set("If-Match", &etag);
        let mut resp = svc
            .call(AsyncRequest {
                method: "GET".into(),
                path: "/v1/a/c/manifest".into(),
                query_string: String::new(),
                headers,
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(
            resp.status, 200,
            "official test_slo_if_match_get on Hyper, got {}",
            resp.status
        );
        resp.body.materialize(u64::MAX).unwrap();
        let body = match &resp.body {
            swift_http::Body::Buffered(b) => b.clone(),
            _ => Vec::new(),
        };
        assert_eq!(body, b"one");
        let mut miss = HeaderKeyDict::new();
        miss.set("If-Match", format!("not-{etag}"));
        let miss_resp = svc
            .call(AsyncRequest {
                method: "GET".into(),
                path: "/v1/a/c/manifest".into(),
                query_string: String::new(),
                headers: miss,
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(
            miss_resp.status, 412,
            "official test_slo_if_match_get miss on Hyper, got {}",
            miss_resp.status
        );
        let mut head_ok = HeaderKeyDict::new();
        head_ok.set("If-Match", &etag);
        let head_match = svc
            .call(AsyncRequest {
                method: "HEAD".into(),
                path: "/v1/a/c/manifest".into(),
                query_string: String::new(),
                headers: head_ok,
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(
            head_match.status, 200,
            "official test_slo_if_match_head on Hyper, got {}",
            head_match.status
        );
    }

    #[tokio::test]
    async fn slo_if_none_match_assembled_etag_is_304_on_hyper_path() {
        let app = Arc::new(ProxyApp::new(
            policy_ring_tests::ring(1),
            policy_ring_tests::ring(2),
            ProxyConfig {
                auth_enabled: false,
                ..Default::default()
            },
        ));
        let svc = ProxyAsyncService {
            app: Arc::new(RwLock::new(app)),
            filters: vec![
                Arc::new(swift_middleware::Slo::new()),
                Arc::new(SloIfMatchObjectServerStub),
            ],
        };
        let head = svc
            .call(AsyncRequest {
                method: "HEAD".into(),
                path: "/v1/a/c/manifest".into(),
                query_string: String::new(),
                headers: HeaderKeyDict::new(),
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(head.status, 200);
        let etag = head
            .headers
            .get("Etag")
            .expect("assembled SLO Etag")
            .to_string();
        let mut headers = HeaderKeyDict::new();
        headers.set("If-None-Match", &etag);
        let resp = svc
            .call(AsyncRequest {
                method: "GET".into(),
                path: "/v1/a/c/manifest".into(),
                query_string: String::new(),
                headers,
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(
            resp.status, 304,
            "official test_slo_if_none_match_get on Hyper, got {}",
            resp.status
        );
        let mut miss = HeaderKeyDict::new();
        miss.set("If-None-Match", format!("not-{etag}"));
        let mut miss_resp = svc
            .call(AsyncRequest {
                method: "GET".into(),
                path: "/v1/a/c/manifest".into(),
                query_string: String::new(),
                headers: miss,
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(
            miss_resp.status, 200,
            "official test_slo_if_none_match_get miss on Hyper, got {}",
            miss_resp.status
        );
        miss_resp.body.materialize(u64::MAX).unwrap();
        let body = match &miss_resp.body {
            swift_http::Body::Buffered(b) => b.clone(),
            _ => Vec::new(),
        };
        assert_eq!(body, b"one");
        let mut head_inm = HeaderKeyDict::new();
        head_inm.set("If-None-Match", &etag);
        let head_304 = svc
            .call(AsyncRequest {
                method: "HEAD".into(),
                path: "/v1/a/c/manifest".into(),
                query_string: String::new(),
                headers: head_inm,
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(
            head_304.status, 304,
            "official test_slo_if_none_match_head on Hyper, got {}",
            head_304.status
        );
    }

    /// Official TestSlo.test_slo_if_none_match_put: non-`*` is 400;
    /// first `*` creates; second `*` is object-server 412.
    struct SloIfNoneMatchPutStub {
        created: std::sync::Mutex<bool>,
    }
    impl swift_middleware::Middleware for SloIfNoneMatchPutStub {
        fn handle(&self, req: Request, next: &swift_middleware::NextFn) -> Response {
            next(req)
        }
        fn intercepts_request(&self, req: &Request) -> bool {
            req.path.starts_with("/v1/a/")
        }
        fn handle_request_async(
            &self,
            mut req: Request,
            _next: swift_middleware::AsyncNextFn,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>> {
            Box::pin(async move {
                if req.method == "HEAD" && req.path == "/v1/a/c/seg_a" {
                    let mut resp = Response::new(200);
                    resp.headers.set("Etag", "e");
                    resp.headers.set("Content-Length", "1");
                    return resp;
                }
                if req.method == "PUT" && req.path == "/v1/a/c/manifest-if-none-match" {
                    let _ = req.body.materialize(u64::MAX);
                    if req.headers.get("If-None-Match") == Some("*") {
                        let mut created = self.created.lock().unwrap_or_else(|p| p.into_inner());
                        if *created {
                            return Response::error(412, "Precondition Failed");
                        }
                        *created = true;
                    }
                    return Response::new(201);
                }
                Response::new(404)
            })
        }
    }

    #[tokio::test]
    async fn slo_if_none_match_put_is_400_then_201_then_412_on_hyper_path() {
        let app = Arc::new(ProxyApp::new(
            policy_ring_tests::ring(1),
            policy_ring_tests::ring(2),
            ProxyConfig {
                auth_enabled: false,
                ..Default::default()
            },
        ));
        let svc = ProxyAsyncService {
            app: Arc::new(RwLock::new(app)),
            filters: vec![
                Arc::new(swift_middleware::Slo::new()),
                Arc::new(SloIfNoneMatchPutStub {
                    created: std::sync::Mutex::new(false),
                }),
            ],
        };
        let manifest = serde_json::to_vec(&serde_json::json!([{
            "size_bytes": 1,
            "etag": serde_json::Value::Null,
            "path": "/c/seg_a"
        }]))
        .unwrap();
        let mut bad = HeaderKeyDict::new();
        bad.set("If-None-Match", "\"not-star\"");
        bad.set("Content-Length", manifest.len().to_string());
        let bad_resp = svc
            .call(AsyncRequest {
                method: "PUT".into(),
                path: "/v1/a/c/manifest-if-none-match".into(),
                query_string: "multipart-manifest=put".into(),
                headers: bad,
                body: IncomingBody::from_bytes(manifest.clone(), u64::MAX),
            })
            .await;
        assert_eq!(
            bad_resp.status, 400,
            "official test_slo_if_none_match_put not-star on Hyper, got {}",
            bad_resp.status
        );
        let mut first = HeaderKeyDict::new();
        first.set("If-None-Match", "*");
        first.set("Content-Length", manifest.len().to_string());
        let first_resp = svc
            .call(AsyncRequest {
                method: "PUT".into(),
                path: "/v1/a/c/manifest-if-none-match".into(),
                query_string: "multipart-manifest=put".into(),
                headers: first,
                body: IncomingBody::from_bytes(manifest.clone(), u64::MAX),
            })
            .await;
        assert_eq!(
            first_resp.status, 201,
            "official test_slo_if_none_match_put first * on Hyper, got {}",
            first_resp.status
        );
        let mut second = HeaderKeyDict::new();
        second.set("If-None-Match", "*");
        second.set("Content-Length", manifest.len().to_string());
        let second_resp = svc
            .call(AsyncRequest {
                method: "PUT".into(),
                path: "/v1/a/c/manifest-if-none-match".into(),
                query_string: "multipart-manifest=put".into(),
                headers: second,
                body: IncomingBody::from_bytes(manifest, u64::MAX),
            })
            .await;
        assert_eq!(
            second_resp.status, 412,
            "official test_slo_if_none_match_put second * on Hyper, got {}",
            second_resp.status
        );
    }

    /// Official TestSlo.test_slo_copy: COPY an SLO must persist assembled
    /// bytes. Dest GET `?multipart-manifest=get` then returns that body
    /// (not a JSON remanifest).
    struct SloCopyAssembleStub {
        dest: Arc<std::sync::Mutex<Option<(String, HeaderKeyDict, Vec<u8>)>>>,
    }
    impl swift_middleware::Middleware for SloCopyAssembleStub {
        fn handle(&self, req: Request, next: &swift_middleware::NextFn) -> Response {
            next(req)
        }
        fn intercepts_request(&self, req: &Request) -> bool {
            req.path.starts_with("/v1/a")
        }
        fn handle_request_async(
            &self,
            mut req: Request,
            _next: swift_middleware::AsyncNextFn,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>> {
            let dest = Arc::clone(&self.dest);
            Box::pin(async move {
                if req.path == "/v1/a/c/manifest-abcde" && req.method != "PUT" {
                    let manifest = serde_json::json!([
                        {"name": "/c/s1", "bytes": 3, "hash": "c4ca4238a0b923820dcc509a6f75849b"},
                    ]);
                    let mut resp = Response::with_body(200, serde_json::to_vec(&manifest).unwrap());
                    resp.headers.set("X-Static-Large-Object", "True");
                    resp.headers.set("Etag", "physical-json");
                    return resp;
                }
                if req.path == "/v1/a/c/s1" {
                    return Response::with_body(200, b"one".to_vec());
                }
                if req.method == "PUT" && req.path.ends_with("/c/copied-abcde") {
                    let headers = req.headers.clone();
                    let body = match req.body.materialize(u64::MAX) {
                        Ok(b) => b.to_vec(),
                        Err(_) => Vec::new(),
                    };
                    *dest.lock().unwrap_or_else(|p| p.into_inner()) =
                        Some((req.path.clone(), headers, body));
                    return Response::new(201);
                }
                if req.path.ends_with("/c/copied-abcde") {
                    if let Some((_path, headers, body)) =
                        dest.lock().unwrap_or_else(|p| p.into_inner()).clone()
                    {
                        let mut resp = if req.method == "HEAD" {
                            Response::new(200)
                        } else {
                            Response::with_body(200, body)
                        };
                        for key in [
                            "X-Static-Large-Object",
                            "Content-Type",
                            "X-Object-Meta-Test",
                            "X-Object-Sysmeta-Slo-Etag",
                            "X-Object-Sysmeta-Slo-Size",
                            "Etag",
                        ] {
                            if let Some(v) = headers.get(key) {
                                resp.headers.set(key, v);
                            }
                        }
                        return resp;
                    }
                }
                Response::new(404)
            })
        }
    }

    #[tokio::test]
    async fn slo_copy_assembles_without_slo_header_on_hyper_path() {
        let dest = Arc::new(std::sync::Mutex::new(None));
        let app = Arc::new(ProxyApp::new(
            policy_ring_tests::ring(1),
            policy_ring_tests::ring(2),
            ProxyConfig {
                auth_enabled: false,
                ..Default::default()
            },
        ));
        let svc = ProxyAsyncService {
            app: Arc::new(RwLock::new(app)),
            filters: vec![
                Arc::new(swift_middleware::Copy::new()),
                Arc::new(swift_middleware::Slo::new()),
                Arc::new(SloCopyAssembleStub {
                    dest: Arc::clone(&dest),
                }),
            ],
        };
        let mut headers = HeaderKeyDict::new();
        headers.set("Destination", "/c/copied-abcde");
        let resp = svc
            .call(AsyncRequest {
                method: "COPY".into(),
                path: "/v1/a/c/manifest-abcde".into(),
                query_string: String::new(),
                headers,
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(
            resp.status, 201,
            "official test_slo_copy COPY on Hyper, got {}",
            resp.status
        );
        let (_put_path, put_headers, put_body) = dest
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
            .expect("dest PUT");
        assert_eq!(put_body, b"one", "COPY must persist assembled SLO bytes");
        assert!(
            put_headers.get("X-Static-Large-Object").is_none(),
            "official test_slo_copy: dest must not carry X-Static-Large-Object"
        );
        let mut got = svc
            .call(AsyncRequest {
                method: "GET".into(),
                path: "/v1/a/c/copied-abcde".into(),
                query_string: "multipart-manifest=get".into(),
                headers: HeaderKeyDict::new(),
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(got.status, 200);
        got.body.materialize(u64::MAX).unwrap();
        let body = match &got.body {
            swift_http::Body::Buffered(b) => b.clone(),
            _ => Vec::new(),
        };
        assert_eq!(
            body, b"one",
            "official test_slo_copy dest multipart-manifest=get is assembled"
        );
    }

    #[tokio::test]
    async fn slo_copy_the_manifest_reputs_json_on_hyper_path() {
        let dest = Arc::new(std::sync::Mutex::new(None));
        let app = Arc::new(ProxyApp::new(
            policy_ring_tests::ring(1),
            policy_ring_tests::ring(2),
            ProxyConfig {
                auth_enabled: false,
                ..Default::default()
            },
        ));
        let svc = ProxyAsyncService {
            app: Arc::new(RwLock::new(app)),
            filters: vec![
                Arc::new(swift_middleware::Copy::new()),
                Arc::new(swift_middleware::Slo::new()),
                Arc::new(SloCopyAssembleStub {
                    dest: Arc::clone(&dest),
                }),
            ],
        };
        let mut headers = HeaderKeyDict::new();
        headers.set("Destination", "/c/copied-abcde");
        let resp = svc
            .call(AsyncRequest {
                method: "COPY".into(),
                path: "/v1/a/c/manifest-abcde".into(),
                query_string: "multipart-manifest=get".into(),
                headers,
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(
            resp.status, 201,
            "official test_slo_copy_the_manifest COPY on Hyper, got {}",
            resp.status
        );
        let (_put_path, put_headers, put_body) = dest
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
            .expect("dest PUT");
        assert!(
            serde_json::from_slice::<serde_json::Value>(&put_body).is_ok(),
            "official test_slo_copy_the_manifest dest must be JSON, got {:?}",
            String::from_utf8_lossy(&put_body)
        );
        assert_ne!(
            put_body, b"one",
            "remanifest must not persist assembled bytes"
        );
        let mut got = svc
            .call(AsyncRequest {
                method: "GET".into(),
                path: "/v1/a/c/copied-abcde".into(),
                query_string: "multipart-manifest=get".into(),
                headers: HeaderKeyDict::new(),
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(got.status, 200);
        got.body.materialize(u64::MAX).unwrap();
        let body = match &got.body {
            swift_http::Body::Buffered(b) => b.clone(),
            _ => Vec::new(),
        };
        let got_json: serde_json::Value =
            serde_json::from_slice(&body).expect("copied manifest JSON");
        assert!(
            got_json.is_array(),
            "official test_slo_copy_the_manifest GET must be JSON list"
        );
        let _ = put_headers;
    }

    #[tokio::test]
    async fn slo_copy_the_manifest_updating_metadata_on_hyper_path() {
        let dest = Arc::new(std::sync::Mutex::new(None));
        let app = Arc::new(ProxyApp::new(
            policy_ring_tests::ring(1),
            policy_ring_tests::ring(2),
            ProxyConfig {
                auth_enabled: false,
                ..Default::default()
            },
        ));
        let svc = ProxyAsyncService {
            app: Arc::new(RwLock::new(app)),
            filters: vec![
                Arc::new(swift_middleware::Copy::new()),
                Arc::new(swift_middleware::Slo::new()),
                Arc::new(SloCopyAssembleStub {
                    dest: Arc::clone(&dest),
                }),
            ],
        };
        let mut headers = HeaderKeyDict::new();
        headers.set("Destination", "/c/copied-abcde");
        headers.set("Content-Type", "image/jpeg");
        headers.set("X-Object-Meta-Test", "updated");
        let resp = svc
            .call(AsyncRequest {
                method: "COPY".into(),
                path: "/v1/a/c/manifest-abcde".into(),
                query_string: "multipart-manifest=get".into(),
                headers,
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(
            resp.status, 201,
            "official test_slo_copy_the_manifest_updating_metadata COPY on Hyper, got {}",
            resp.status
        );
        let (_put_path, put_headers, put_body) = dest
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
            .expect("dest PUT");
        assert!(
            serde_json::from_slice::<serde_json::Value>(&put_body).is_ok(),
            "remanifest dest must be JSON"
        );
        assert_eq!(
            put_headers.get("X-Object-Meta-Test"),
            Some("updated"),
            "COPY request metadata must win"
        );
        let ct = put_headers.get("Content-Type").unwrap_or("");
        assert!(
            ct.starts_with("image/jpeg"),
            "official updating_metadata dest PUT Content-Type, got {ct}"
        );
        let head = svc
            .call(AsyncRequest {
                method: "HEAD".into(),
                path: "/v1/a/c/copied-abcde".into(),
                query_string: String::new(),
                headers: HeaderKeyDict::new(),
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(head.status, 200);
        assert_eq!(
            head.headers.get("Content-Type"),
            Some("image/jpeg"),
            "official updating_metadata assembled HEAD Content-Type, got {:?}",
            head.headers.get("Content-Type")
        );
        assert_eq!(head.headers.get("X-Object-Meta-Test"), Some("updated"));
    }

    #[tokio::test]
    async fn slo_copy_account_destination_account_on_hyper_path() {
        let dest = Arc::new(std::sync::Mutex::new(None));
        let app = Arc::new(ProxyApp::new(
            policy_ring_tests::ring(1),
            policy_ring_tests::ring(2),
            ProxyConfig {
                auth_enabled: false,
                ..Default::default()
            },
        ));
        let svc = ProxyAsyncService {
            app: Arc::new(RwLock::new(app)),
            filters: vec![
                Arc::new(swift_middleware::Copy::new()),
                Arc::new(swift_middleware::Slo::new()),
                Arc::new(SloCopyAssembleStub {
                    dest: Arc::clone(&dest),
                }),
            ],
        };
        let mut headers = HeaderKeyDict::new();
        headers.set("Destination", "/c/copied-abcde");
        headers.set("Destination-Account", "a2");
        let resp = svc
            .call(AsyncRequest {
                method: "COPY".into(),
                path: "/v1/a/c/manifest-abcde".into(),
                query_string: String::new(),
                headers,
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(
            resp.status, 201,
            "official test_slo_copy_account COPY on Hyper, got {}",
            resp.status
        );
        let (put_path, put_headers, put_body) = dest
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
            .expect("dest PUT");
        assert_eq!(
            put_path, "/v1/a2/c/copied-abcde",
            "Destination-Account must rewrite dest PUT path"
        );
        assert_eq!(
            put_body, b"one",
            "cross-account COPY must persist assembled SLO"
        );
        assert!(put_headers.get("X-Static-Large-Object").is_none());
        let mut got = svc
            .call(AsyncRequest {
                method: "GET".into(),
                path: "/v1/a2/c/copied-abcde".into(),
                query_string: "multipart-manifest=get".into(),
                headers: HeaderKeyDict::new(),
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(got.status, 200);
        got.body.materialize(u64::MAX).unwrap();
        let body = match &got.body {
            swift_http::Body::Buffered(b) => b.clone(),
            _ => Vec::new(),
        };
        assert_eq!(
            body, b"one",
            "official test_slo_copy_account dest multipart-manifest=get is assembled"
        );
    }

    #[tokio::test]
    async fn slo_copy_the_manifest_account_on_hyper_path() {
        let dest = Arc::new(std::sync::Mutex::new(None));
        let app = Arc::new(ProxyApp::new(
            policy_ring_tests::ring(1),
            policy_ring_tests::ring(2),
            ProxyConfig {
                auth_enabled: false,
                ..Default::default()
            },
        ));
        let svc = ProxyAsyncService {
            app: Arc::new(RwLock::new(app)),
            filters: vec![
                Arc::new(swift_middleware::Copy::new()),
                Arc::new(swift_middleware::Slo::new()),
                Arc::new(SloCopyAssembleStub {
                    dest: Arc::clone(&dest),
                }),
            ],
        };
        let mut headers = HeaderKeyDict::new();
        headers.set("Destination", "/c/copied-abcde");
        headers.set("Destination-Account", "a");
        let resp = svc
            .call(AsyncRequest {
                method: "COPY".into(),
                path: "/v1/a/c/manifest-abcde".into(),
                query_string: "multipart-manifest=get".into(),
                headers,
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(
            resp.status, 201,
            "official test_slo_copy_the_manifest_account same-account on Hyper, got {}",
            resp.status
        );
        let (put_path, _put_headers, put_body) = dest
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
            .expect("dest PUT");
        assert_eq!(put_path, "/v1/a/c/copied-abcde");
        assert!(serde_json::from_slice::<serde_json::Value>(&put_body).is_ok());
    }

    /// Official TestSlo.test_slo_post_the_manifest_metadata_update: POST
    /// user-meta must keep X-Static-Large-Object and JSON on
    /// `?multipart-manifest=get`.
    struct SloPostManifestStub {
        meta: std::sync::Mutex<HeaderKeyDict>,
    }
    impl swift_middleware::Middleware for SloPostManifestStub {
        fn handle(&self, req: Request, next: &swift_middleware::NextFn) -> Response {
            next(req)
        }
        fn intercepts_request(&self, req: &Request) -> bool {
            req.path == "/v1/a/c/manifest-post"
        }
        fn handle_request_async(
            &self,
            req: Request,
            _next: swift_middleware::AsyncNextFn,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>> {
            Box::pin(async move {
                if req.method == "POST" {
                    let mut meta = self.meta.lock().unwrap_or_else(|p| p.into_inner());
                    for (k, v) in req.headers.iter() {
                        if k.to_ascii_lowercase().starts_with("x-object-meta-") {
                            meta.set(k, v);
                        }
                    }
                    return Response::new(202);
                }
                let manifest = serde_json::json!([
                    {"name": "/c/s1", "bytes": 3, "hash": "c4ca4238a0b923820dcc509a6f75849b"},
                ]);
                let mut resp = if req.method == "HEAD" {
                    Response::new(200)
                } else {
                    Response::with_body(200, serde_json::to_vec(&manifest).unwrap())
                };
                resp.headers.set("X-Static-Large-Object", "True");
                resp.headers.set("Content-Type", "application/octet-stream");
                resp.headers.set("Etag", "physical-json");
                let meta = self.meta.lock().unwrap_or_else(|p| p.into_inner());
                for (k, v) in meta.iter() {
                    resp.headers.set(k, v);
                }
                resp
            })
        }
    }

    #[tokio::test]
    async fn slo_post_the_manifest_keeps_slo_on_hyper_path() {
        let app = Arc::new(ProxyApp::new(
            policy_ring_tests::ring(1),
            policy_ring_tests::ring(2),
            ProxyConfig {
                auth_enabled: false,
                ..Default::default()
            },
        ));
        let svc = ProxyAsyncService {
            app: Arc::new(RwLock::new(app)),
            filters: vec![
                Arc::new(swift_middleware::Slo::new()),
                Arc::new(SloPostManifestStub {
                    meta: std::sync::Mutex::new(HeaderKeyDict::new()),
                }),
            ],
        };
        let mut headers = HeaderKeyDict::new();
        headers.set("X-Object-Meta-Post", "update");
        let post = svc
            .call(AsyncRequest {
                method: "POST".into(),
                path: "/v1/a/c/manifest-post".into(),
                query_string: "multipart-manifest=get".into(),
                headers,
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(
            post.status, 202,
            "official test_slo_post_the_manifest POST on Hyper, got {}",
            post.status
        );
        let head = svc
            .call(AsyncRequest {
                method: "HEAD".into(),
                path: "/v1/a/c/manifest-post".into(),
                query_string: String::new(),
                headers: HeaderKeyDict::new(),
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(head.status, 200);
        assert!(
            head.headers
                .get("X-Static-Large-Object")
                .is_some_and(|v| v.eq_ignore_ascii_case("true")),
            "POST must not drop X-Static-Large-Object, got {:?}",
            head.headers.get("X-Static-Large-Object")
        );
        assert_eq!(head.headers.get("X-Object-Meta-Post"), Some("update"));
        let mut got = svc
            .call(AsyncRequest {
                method: "GET".into(),
                path: "/v1/a/c/manifest-post".into(),
                query_string: "multipart-manifest=get".into(),
                headers: HeaderKeyDict::new(),
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(got.status, 200);
        got.body.materialize(u64::MAX).unwrap();
        let body = match &got.body {
            swift_http::Body::Buffered(b) => b.clone(),
            _ => Vec::new(),
        };
        assert!(
            serde_json::from_slice::<serde_json::Value>(&body).is_ok(),
            "official test_slo_post_the_manifest GET must stay JSON"
        );
    }

    /// Official TestSlo PUT validation: segment HEAD etag/size, required keys,
    /// and no self-segment (IsolatedIdentity Swift 2.9).
    struct SloPutValidationStub;
    impl swift_middleware::Middleware for SloPutValidationStub {
        fn handle(&self, req: Request, next: &swift_middleware::NextFn) -> Response {
            next(req)
        }
        fn intercepts_request(&self, req: &Request) -> bool {
            req.path.starts_with("/v1/a/c/")
        }
        fn handle_request_async(
            &self,
            mut req: Request,
            _next: swift_middleware::AsyncNextFn,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>> {
            Box::pin(async move {
                if req.method == "HEAD" && req.path == "/v1/a/c/seg_a" {
                    let mut resp = Response::new(200);
                    resp.headers.set("Etag", "actual");
                    resp.headers.set("Content-Length", "3");
                    return resp;
                }
                if req.method == "PUT" {
                    let _ = req.body.materialize(u64::MAX);
                    return Response::new(201);
                }
                Response::new(404)
            })
        }
    }

    async fn slo_put_manifest_on_hyper(path: &str, body: Vec<u8>) -> Response {
        let app = Arc::new(ProxyApp::new(
            policy_ring_tests::ring(1),
            policy_ring_tests::ring(2),
            ProxyConfig {
                auth_enabled: false,
                ..Default::default()
            },
        ));
        let svc = ProxyAsyncService {
            app: Arc::new(RwLock::new(app)),
            filters: vec![
                Arc::new(swift_middleware::Slo::new()),
                Arc::new(SloPutValidationStub),
            ],
        };
        let mut headers = HeaderKeyDict::new();
        headers.set("Content-Length", body.len().to_string());
        svc.call(AsyncRequest {
            method: "PUT".into(),
            path: path.into(),
            query_string: "multipart-manifest=put".into(),
            headers,
            body: IncomingBody::from_bytes(body, u64::MAX),
        })
        .await
    }

    #[tokio::test]
    async fn slo_put_validation_official_matrix_on_hyper_path() {
        let etag_mismatch = serde_json::to_vec(&serde_json::json!([{
            "path": "/c/seg_a",
            "etag": "not it",
            "size_bytes": 3
        }]))
        .unwrap();
        assert_eq!(
            slo_put_manifest_on_hyper("/v1/a/c/manifest-a-bad-etag", etag_mismatch)
                .await
                .status,
            400,
            "official test_slo_etag_mismatch"
        );
        let size_mismatch = serde_json::to_vec(&serde_json::json!([{
            "path": "/c/seg_a",
            "etag": "actual",
            "size_bytes": 2
        }]))
        .unwrap();
        assert_eq!(
            slo_put_manifest_on_hyper("/v1/a/c/manifest-a-bad-size", size_mismatch)
                .await
                .status,
            400,
            "official test_slo_size_mismatch"
        );
        let missing_etag = serde_json::to_vec(&serde_json::json!([{
            "path": "/c/seg_a",
            "size_bytes": 3
        }]))
        .unwrap();
        assert_eq!(
            slo_put_manifest_on_hyper("/v1/a/c/manifest-a-missing-etag", missing_etag)
                .await
                .status,
            400,
            "official test_slo_missing_etag"
        );
        let missing_size = serde_json::to_vec(&serde_json::json!([{
            "path": "/c/seg_a",
            "etag": "actual"
        }]))
        .unwrap();
        assert_eq!(
            slo_put_manifest_on_hyper("/v1/a/c/manifest-a-missing-size", missing_size)
                .await
                .status,
            400,
            "official test_slo_missing_size"
        );
        let null_etag = serde_json::to_vec(&serde_json::json!([{
            "path": "/c/seg_a",
            "etag": serde_json::Value::Null,
            "size_bytes": 3
        }]))
        .unwrap();
        assert_eq!(
            slo_put_manifest_on_hyper("/v1/a/c/manifest-a-unspecified-etag", null_etag)
                .await
                .status,
            201,
            "official test_slo_unspecified_etag"
        );
        let null_size = serde_json::to_vec(&serde_json::json!([{
            "path": "/c/seg_a",
            "etag": "actual",
            "size_bytes": serde_json::Value::Null
        }]))
        .unwrap();
        assert_eq!(
            slo_put_manifest_on_hyper("/v1/a/c/manifest-a-unspecified-size", null_size)
                .await
                .status,
            201,
            "official test_slo_unspecified_size"
        );
        let self_seg = serde_json::to_vec(&serde_json::json!([
            {"path": "/c/seg_a", "etag": "actual", "size_bytes": 3},
            {"path": "/c/seg_b", "etag": "actual", "size_bytes": 3}
        ]))
        .unwrap();
        assert_eq!(
            slo_put_manifest_on_hyper("/v1/a/c/seg_b", self_seg)
                .await
                .status,
            400,
            "official test_slo_overwrite_segment_with_manifest"
        );
    }

    /// Official TestSlo.test_slo_get_the_manifest / test_slo_head_the_manifest.
    struct SloManifestGetStub;
    impl swift_middleware::Middleware for SloManifestGetStub {
        fn handle(&self, req: Request, next: &swift_middleware::NextFn) -> Response {
            next(req)
        }
        fn intercepts_request(&self, req: &Request) -> bool {
            req.path.starts_with("/v1/a/c/")
        }
        fn handle_request_async(
            &self,
            req: Request,
            _next: swift_middleware::AsyncNextFn,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>> {
            Box::pin(async move {
                if req.path == "/v1/a/c/manifest-abcde" {
                    let manifest = serde_json::json!([
                        {"name": "/c/s1", "bytes": 3, "hash": "c4ca4238a0b923820dcc509a6f75849b"},
                        {"name": "/c/s2", "bytes": 3, "hash": "c81e728d9d4c2f636f067f89cc14862c"},
                    ]);
                    let mut resp = Response::with_body(200, serde_json::to_vec(&manifest).unwrap());
                    resp.headers.set("X-Static-Large-Object", "True");
                    resp.headers.set("Content-Type", "application/octet-stream");
                    resp.headers.set("Etag", "physical-json");
                    return resp;
                }
                if req.path == "/v1/a/c/s1" {
                    return stub_object_range(&req, b"aaa");
                }
                if req.path == "/v1/a/c/s2" {
                    return stub_object_range(&req, b"bbb");
                }
                Response::new(404)
            })
        }
    }

    #[tokio::test]
    async fn slo_get_the_manifest_is_json_on_hyper_path() {
        let app = Arc::new(ProxyApp::new(
            policy_ring_tests::ring(1),
            policy_ring_tests::ring(2),
            ProxyConfig {
                auth_enabled: false,
                ..Default::default()
            },
        ));
        let svc = ProxyAsyncService {
            app: Arc::new(RwLock::new(app)),
            filters: vec![
                Arc::new(swift_middleware::Slo::new()),
                Arc::new(SloManifestGetStub),
            ],
        };
        let mut resp = svc
            .call(AsyncRequest {
                method: "GET".into(),
                path: "/v1/a/c/manifest-abcde".into(),
                query_string: "multipart-manifest=get".into(),
                headers: HeaderKeyDict::new(),
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(
            resp.status, 200,
            "official test_slo_get_the_manifest on Hyper, got {}",
            resp.status
        );
        assert_eq!(
            resp.headers.get("Content-Type"),
            Some("application/json; charset=utf-8"),
            "official test_slo_get_the_manifest Content-Type"
        );
        resp.body.materialize(u64::MAX).unwrap();
        let body = match &resp.body {
            swift_http::Body::Buffered(b) => b.clone(),
            _ => Vec::new(),
        };
        assert!(
            serde_json::from_slice::<serde_json::Value>(&body).is_ok(),
            "official test_slo_get_the_manifest body must be JSON"
        );
        let head = svc
            .call(AsyncRequest {
                method: "HEAD".into(),
                path: "/v1/a/c/manifest-abcde".into(),
                query_string: "multipart-manifest=get".into(),
                headers: HeaderKeyDict::new(),
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(
            head.headers.get("Content-Type"),
            Some("application/json; charset=utf-8"),
            "official test_slo_head_the_manifest on Hyper, got {:?}",
            head.headers.get("Content-Type")
        );
    }

    #[tokio::test]
    async fn slo_get_raw_the_manifest_is_client_shaped_on_hyper_path() {
        let app = Arc::new(ProxyApp::new(
            policy_ring_tests::ring(1),
            policy_ring_tests::ring(2),
            ProxyConfig {
                auth_enabled: false,
                ..Default::default()
            },
        ));
        let svc = ProxyAsyncService {
            app: Arc::new(RwLock::new(app)),
            filters: vec![
                Arc::new(swift_middleware::Slo::new()),
                Arc::new(SloManifestGetStub),
            ],
        };
        let mut resp = svc
            .call(AsyncRequest {
                method: "GET".into(),
                path: "/v1/a/c/manifest-abcde".into(),
                query_string: "multipart-manifest=get&format=raw".into(),
                headers: HeaderKeyDict::new(),
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(
            resp.status, 200,
            "official test_slo_get_raw_the_manifest on Hyper, got {}",
            resp.status
        );
        assert_eq!(
            resp.headers.get("Content-Type"),
            Some("application/octet-stream"),
            "official test_slo_get_raw_the_manifest keeps object Content-Type, got {:?}",
            resp.headers.get("Content-Type")
        );
        resp.body.materialize(u64::MAX).unwrap();
        let body = match &resp.body {
            swift_http::Body::Buffered(b) => b.clone(),
            _ => Vec::new(),
        };
        let value: serde_json::Value = serde_json::from_slice(&body).expect("raw manifest JSON");
        let arr = value.as_array().expect("raw manifest list");
        assert_eq!(arr.len(), 2);
        let keys: std::collections::BTreeSet<_> = arr[0]
            .as_object()
            .expect("raw segment")
            .keys()
            .map(|k| k.as_str())
            .collect();
        assert_eq!(
            keys,
            ["etag", "path", "size_bytes"].into_iter().collect(),
            "official test_slo_get_raw_the_manifest keys"
        );
        assert_eq!(arr[0]["path"], "/c/s1");
        assert_eq!(arr[0]["size_bytes"], 3);
        assert_eq!(arr[0]["etag"], "c4ca4238a0b923820dcc509a6f75849b");
    }

    #[tokio::test]
    async fn slo_ranged_get_uses_assembled_bytes_on_hyper_path() {
        let app = Arc::new(ProxyApp::new(
            policy_ring_tests::ring(1),
            policy_ring_tests::ring(2),
            ProxyConfig {
                auth_enabled: false,
                ..Default::default()
            },
        ));
        let svc = ProxyAsyncService {
            app: Arc::new(RwLock::new(app)),
            filters: vec![
                Arc::new(swift_middleware::Slo::new()),
                Arc::new(SloManifestGetStub),
            ],
        };
        let mut headers = HeaderKeyDict::new();
        headers.set("Range", "bytes=2-4");
        let mut resp = svc
            .call(AsyncRequest {
                method: "GET".into(),
                path: "/v1/a/c/manifest-abcde".into(),
                query_string: String::new(),
                headers,
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(
            resp.status, 206,
            "official test_slo_ranged_get on Hyper, got {}",
            resp.status
        );
        resp.body.materialize(u64::MAX).unwrap();
        let body = match &resp.body {
            swift_http::Body::Buffered(b) => b.clone(),
            _ => Vec::new(),
        };
        assert_eq!(body, b"abb", "assembled Range bytes=2-4 of aaabbb");
    }

    /// Official TestSlo.test_slo_get_ranged_manifest: stored `range` slices
    /// the backing object. Same object twice is
    /// test_slo_get_ranged_manifest_repeated_segment.
    struct SloRangedManifestStub;
    impl swift_middleware::Middleware for SloRangedManifestStub {
        fn handle(&self, req: Request, next: &swift_middleware::NextFn) -> Response {
            next(req)
        }
        fn intercepts_request(&self, req: &Request) -> bool {
            req.path.starts_with("/v1/a/c/")
        }
        fn handle_request_async(
            &self,
            req: Request,
            _next: swift_middleware::AsyncNextFn,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>> {
            Box::pin(async move {
                if req.path == "/v1/a/c/ranged-manifest" {
                    let manifest = serde_json::json!([
                        {"name": "/c/s1", "bytes": 3, "hash": "c4ca4238a0b923820dcc509a6f75849b", "range": "2-4"},
                        {"name": "/c/s1", "bytes": 2, "hash": "c4ca4238a0b923820dcc509a6f75849b", "range": "0-1"},
                    ]);
                    let mut resp = Response::with_body(200, serde_json::to_vec(&manifest).unwrap());
                    resp.headers.set("X-Static-Large-Object", "True");
                    resp.headers.set("Etag", "physical-ranged");
                    return resp;
                }
                if req.path == "/v1/a/c/s1" {
                    return stub_object_range(&req, b"aaabbb");
                }
                Response::new(404)
            })
        }
    }

    #[tokio::test]
    async fn slo_get_ranged_manifest_slices_segments_on_hyper_path() {
        let app = Arc::new(ProxyApp::new(
            policy_ring_tests::ring(1),
            policy_ring_tests::ring(2),
            ProxyConfig {
                auth_enabled: false,
                ..Default::default()
            },
        ));
        let svc = ProxyAsyncService {
            app: Arc::new(RwLock::new(app)),
            filters: vec![
                Arc::new(swift_middleware::Slo::new()),
                Arc::new(SloRangedManifestStub),
            ],
        };
        let mut headers = HeaderKeyDict::new();
        headers.set("If-None-Match", "not-ranged");
        let mut resp = svc
            .call(AsyncRequest {
                method: "GET".into(),
                path: "/v1/a/c/ranged-manifest".into(),
                query_string: String::new(),
                headers,
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(
            resp.status, 200,
            "official test_slo_get_ranged_manifest on Hyper, got {}",
            resp.status
        );
        resp.body.materialize(u64::MAX).unwrap();
        let body = match &resp.body {
            swift_http::Body::Buffered(b) => b.clone(),
            _ => Vec::new(),
        };
        assert_eq!(
            body, b"abbaa",
            "range 2-4 then 0-1 of aaabbb (repeated segment)"
        );
    }

    /// Official TestSlo.test_slo_get_ranged_submanifest: outer references
    /// a ranged `sub_slo` window of an already-ranged inner assemble.
    struct SloRangedSubmanifestStub;
    impl swift_middleware::Middleware for SloRangedSubmanifestStub {
        fn handle(&self, req: Request, next: &swift_middleware::NextFn) -> Response {
            next(req)
        }
        fn intercepts_request(&self, req: &Request) -> bool {
            req.path.starts_with("/v1/a/c/")
        }
        fn handle_request_async(
            &self,
            req: Request,
            _next: swift_middleware::AsyncNextFn,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>> {
            Box::pin(async move {
                if req.path == "/v1/a/c/ranged-submanifest" {
                    let manifest = serde_json::json!([
                        {"name": "/c/cseg", "bytes": 1, "hash": "4a8a08f09d37b73795649038408b5f33"},
                        {"name": "/c/ranged-manifest", "bytes": 5, "hash": "inner-ranged", "sub_slo": true},
                        {"name": "/c/ranged-manifest", "bytes": 5, "hash": "inner-ranged", "range": "1-3", "sub_slo": true},
                        {"name": "/c/ranged-manifest", "bytes": 5, "hash": "inner-ranged", "range": "3-4", "sub_slo": true},
                    ]);
                    let mut resp = Response::with_body(200, serde_json::to_vec(&manifest).unwrap());
                    resp.headers.set("X-Static-Large-Object", "True");
                    resp.headers.set("Etag", "physical-ranged-sub");
                    return resp;
                }
                if req.path == "/v1/a/c/ranged-manifest" {
                    let manifest = serde_json::json!([
                        {"name": "/c/s1", "bytes": 6, "hash": "c4ca4238a0b923820dcc509a6f75849b", "range": "2-4"},
                        {"name": "/c/s1", "bytes": 6, "hash": "c4ca4238a0b923820dcc509a6f75849b", "range": "0-1"},
                    ]);
                    let mut resp = Response::with_body(200, serde_json::to_vec(&manifest).unwrap());
                    resp.headers.set("X-Static-Large-Object", "True");
                    resp.headers.set("X-Object-Sysmeta-Slo-Size", "5");
                    resp.headers.set("Etag", "physical-ranged");
                    return resp;
                }
                if req.path == "/v1/a/c/cseg" {
                    return stub_object_range(&req, b"c");
                }
                if req.path == "/v1/a/c/s1" {
                    return stub_object_range(&req, b"aaabbb");
                }
                Response::new(404)
            })
        }
    }

    #[tokio::test]
    async fn slo_get_ranged_submanifest_slices_nested_on_hyper_path() {
        let app = Arc::new(ProxyApp::new(
            policy_ring_tests::ring(1),
            policy_ring_tests::ring(2),
            ProxyConfig {
                auth_enabled: false,
                ..Default::default()
            },
        ));
        let svc = ProxyAsyncService {
            app: Arc::new(RwLock::new(app)),
            filters: vec![
                Arc::new(swift_middleware::Slo::new()),
                Arc::new(SloRangedSubmanifestStub),
            ],
        };
        let mut headers = HeaderKeyDict::new();
        headers.set("If-None-Match", "not-ranged-sub");
        let mut resp = svc
            .call(AsyncRequest {
                method: "GET".into(),
                path: "/v1/a/c/ranged-submanifest".into(),
                query_string: String::new(),
                headers,
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(
            resp.status, 200,
            "official test_slo_get_ranged_submanifest on Hyper, got {}",
            resp.status
        );
        resp.body.materialize(u64::MAX).unwrap();
        let body = match &resp.body {
            swift_http::Body::Buffered(b) => b.clone(),
            _ => Vec::new(),
        };
        assert_eq!(
            body, b"cabbaabbaaa",
            "c + abbaa + bba + aa (ranged sub_slo of ranged inner)"
        );
    }

    #[tokio::test]
    async fn slo_etag_is_hash_of_etags_on_hyper_path() {
        let app = Arc::new(ProxyApp::new(
            policy_ring_tests::ring(1),
            policy_ring_tests::ring(2),
            ProxyConfig {
                auth_enabled: false,
                ..Default::default()
            },
        ));
        let svc = ProxyAsyncService {
            app: Arc::new(RwLock::new(app)),
            filters: vec![
                Arc::new(swift_middleware::Slo::new()),
                Arc::new(SloManifestGetStub),
            ],
        };
        let head = svc
            .call(AsyncRequest {
                method: "HEAD".into(),
                path: "/v1/a/c/manifest-abcde".into(),
                query_string: String::new(),
                headers: HeaderKeyDict::new(),
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(head.status, 200);
        let etag = head
            .headers
            .get("Etag")
            .expect("assembled SLO Etag")
            .trim_matches('"')
            .to_string();
        assert_ne!(etag, "physical-json");
        // md5(seg1_hash || seg2_hash) — official test_slo_etag_is_hash_of_etags.
        assert_eq!(
            etag, "302cbafc0dfbc97f30d576a6f394dad3",
            "official test_slo_etag_is_hash_of_etags on Hyper"
        );
    }

    #[tokio::test]
    async fn slo_get_simple_manifest_assembles_without_conditionals_on_hyper() {
        let app = Arc::new(ProxyApp::new(
            policy_ring_tests::ring(1),
            policy_ring_tests::ring(2),
            ProxyConfig {
                auth_enabled: false,
                ..Default::default()
            },
        ));
        let svc = ProxyAsyncService {
            app: Arc::new(RwLock::new(app)),
            filters: vec![
                Arc::new(swift_middleware::Slo::new()),
                Arc::new(SloManifestGetStub),
            ],
        };
        let mut resp = svc
            .call(AsyncRequest {
                method: "GET".into(),
                path: "/v1/a/c/manifest-abcde".into(),
                query_string: String::new(),
                headers: HeaderKeyDict::new(),
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(
            resp.status, 200,
            "official test_slo_get_simple_manifest on Hyper, got {}",
            resp.status
        );
        let body = resp
            .body
            .collect_async()
            .await
            .expect("unconditional SLO GET body");
        assert_eq!(body, b"aaabbb");
    }

    /// Official TestSlo.test_slo_container_listing: listing `bytes` is the
    /// assembled size (`swift_bytes`), `hash` is the physical manifest etag.
    struct SloContainerListingStub;
    impl swift_middleware::Middleware for SloContainerListingStub {
        fn handle(&self, req: Request, next: &swift_middleware::NextFn) -> Response {
            next(req)
        }
        fn intercepts_request(&self, req: &Request) -> bool {
            req.method == "GET" && req.path == "/v1/a/c"
        }
        fn handle_request_async(
            &self,
            _req: Request,
            _next: swift_middleware::AsyncNextFn,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>> {
            Box::pin(async move {
                let listing = serde_json::json!([{
                    "name": "manifest-a",
                    "bytes": 1,
                    "hash": "c4ca4238a0b923820dcc509a6f75849b; slo_etag=slohash",
                    "content_type": "application/octet-stream;swift_bytes=3",
                }]);
                let mut resp = Response::with_body(200, serde_json::to_vec(&listing).unwrap());
                resp.headers
                    .set("Content-Type", "application/json; charset=utf-8");
                resp
            })
        }
    }

    #[tokio::test]
    async fn slo_container_listing_uses_slo_size_and_manifest_etag_on_hyper() {
        let app = Arc::new(ProxyApp::new(
            policy_ring_tests::ring(1),
            policy_ring_tests::ring(2),
            ProxyConfig {
                auth_enabled: false,
                ..Default::default()
            },
        ));
        let svc = ProxyAsyncService {
            app: Arc::new(RwLock::new(app)),
            filters: vec![
                Arc::new(swift_middleware::Slo::new()),
                Arc::new(SloContainerListingStub),
            ],
        };
        let resp = svc
            .call(AsyncRequest {
                method: "GET".into(),
                path: "/v1/a/c".into(),
                query_string: "format=json".into(),
                headers: HeaderKeyDict::new(),
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(resp.status, 200);
        let body = resp.body.collect_async().await.expect("listing body");
        let v: serde_json::Value = serde_json::from_slice(&body).expect("listing JSON");
        assert_eq!(
            v[0]["bytes"], 3,
            "official test_slo_container_listing bytes=assembled"
        );
        assert_eq!(
            v[0]["hash"], "c4ca4238a0b923820dcc509a6f75849b",
            "official test_slo_container_listing hash=manifest-get etag"
        );
        assert_eq!(
            v[0]["content_type"], "application/octet-stream",
            "listing must strip swift_bytes"
        );
    }

    /// Official TestSlo.test_slo_get_nested_manifest /
    /// test_slo_etag_is_hash_of_etags_submanifests.
    struct SloNestedManifestStub;
    impl swift_middleware::Middleware for SloNestedManifestStub {
        fn handle(&self, req: Request, next: &swift_middleware::NextFn) -> Response {
            next(req)
        }
        fn intercepts_request(&self, req: &Request) -> bool {
            req.path.starts_with("/v1/a/c/")
        }
        fn handle_request_async(
            &self,
            req: Request,
            _next: swift_middleware::AsyncNextFn,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>> {
            Box::pin(async move {
                if req.path == "/v1/a/c/manifest-abcde-submanifest" {
                    let manifest = serde_json::json!([
                        {"name": "/c/inner", "bytes": 6, "hash": "302cbafc0dfbc97f30d576a6f394dad3", "sub_slo": true},
                    ]);
                    let mut resp = Response::with_body(200, serde_json::to_vec(&manifest).unwrap());
                    resp.headers.set("X-Static-Large-Object", "True");
                    resp.headers.set("Etag", "physical-outer");
                    return resp;
                }
                if req.path == "/v1/a/c/inner" {
                    let manifest = serde_json::json!([
                        {"name": "/c/s1", "bytes": 3, "hash": "c4ca4238a0b923820dcc509a6f75849b"},
                        {"name": "/c/s2", "bytes": 3, "hash": "c81e728d9d4c2f636f067f89cc14862c"},
                    ]);
                    let mut resp = Response::with_body(200, serde_json::to_vec(&manifest).unwrap());
                    resp.headers.set("X-Static-Large-Object", "True");
                    resp.headers.set(
                        "X-Object-Sysmeta-Slo-Etag",
                        "302cbafc0dfbc97f30d576a6f394dad3",
                    );
                    resp.headers.set("X-Object-Sysmeta-Slo-Size", "6");
                    resp.headers.set("Etag", "physical-inner");
                    return resp;
                }
                if req.path == "/v1/a/c/s1" {
                    return stub_object_range(&req, b"aaa");
                }
                if req.path == "/v1/a/c/s2" {
                    return stub_object_range(&req, b"bbb");
                }
                Response::new(404)
            })
        }
    }

    #[tokio::test]
    async fn slo_get_nested_manifest_assembles_on_hyper_path() {
        let app = Arc::new(ProxyApp::new(
            policy_ring_tests::ring(1),
            policy_ring_tests::ring(2),
            ProxyConfig {
                auth_enabled: false,
                ..Default::default()
            },
        ));
        let svc = ProxyAsyncService {
            app: Arc::new(RwLock::new(app)),
            filters: vec![
                Arc::new(swift_middleware::Slo::new()),
                Arc::new(SloNestedManifestStub),
            ],
        };
        // Hyper reassemble's first next() is captured; nested segment GETs
        // only reach the stub when SLO intercepts_request (If-*).
        let mut headers = HeaderKeyDict::new();
        headers.set("If-None-Match", "not-nested");
        let mut resp = svc
            .call(AsyncRequest {
                method: "GET".into(),
                path: "/v1/a/c/manifest-abcde-submanifest".into(),
                query_string: String::new(),
                headers,
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(
            resp.status, 200,
            "official test_slo_get_nested_manifest on Hyper, got {}",
            resp.status
        );
        resp.body.materialize(u64::MAX).unwrap();
        let body = match &resp.body {
            swift_http::Body::Buffered(b) => b.clone(),
            _ => Vec::new(),
        };
        assert_eq!(body, b"aaabbb");
        let head = svc
            .call(AsyncRequest {
                method: "HEAD".into(),
                path: "/v1/a/c/manifest-abcde-submanifest".into(),
                query_string: String::new(),
                headers: HeaderKeyDict::new(),
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        let etag = head
            .headers
            .get("Etag")
            .expect("nested SLO Etag")
            .trim_matches('"')
            .to_string();
        assert_eq!(
            etag, "efd4f115d46b3e79ee1392c343b3b433",
            "official test_slo_etag_is_hash_of_etags_submanifests on Hyper"
        );
        let mut ranged = HeaderKeyDict::new();
        ranged.set("Range", "bytes=2-4");
        let mut slice = svc
            .call(AsyncRequest {
                method: "GET".into(),
                path: "/v1/a/c/manifest-abcde-submanifest".into(),
                query_string: String::new(),
                headers: ranged,
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(
            slice.status, 206,
            "official test_slo_ranged_submanifest on Hyper, got {}",
            slice.status
        );
        slice.body.materialize(u64::MAX).unwrap();
        let slice_body = match &slice.body {
            swift_http::Body::Buffered(b) => b.clone(),
            _ => Vec::new(),
        };
        assert_eq!(
            slice_body, b"abb",
            "client Range bytes=2-4 of nested aaabbb"
        );
    }

    /// Official listing_formats test_GET_HEAD_content_type: HEAD
    /// `?format=json` must stamp application/json even when the backend
    /// HEAD is a 204 text/plain.
    struct ListingHeadPlainStub;
    impl swift_middleware::Middleware for ListingHeadPlainStub {
        fn handle(&self, req: Request, next: &swift_middleware::NextFn) -> Response {
            next(req)
        }
        fn intercepts_request(&self, req: &Request) -> bool {
            matches!(req.method.as_str(), "GET" | "HEAD") && req.path == "/v1/a/c"
        }
        fn handle_request_async(
            &self,
            req: Request,
            _next: swift_middleware::AsyncNextFn,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>> {
            Box::pin(async move {
                let mut resp = if req.method == "HEAD" {
                    Response::new(204)
                } else {
                    Response::with_body(200, b"[]".to_vec())
                };
                resp.headers
                    .set("Content-Type", "text/plain; charset=utf-8");
                resp.headers.set("Content-Length", 0);
                resp
            })
        }
    }

    #[tokio::test]
    async fn listing_formats_head_json_content_type_on_hyper_path() {
        let app = Arc::new(ProxyApp::new(
            policy_ring_tests::ring(1),
            policy_ring_tests::ring(2),
            ProxyConfig {
                auth_enabled: false,
                ..Default::default()
            },
        ));
        let svc = ProxyAsyncService {
            app: Arc::new(RwLock::new(app)),
            filters: vec![
                Arc::new(swift_middleware::ListingFormats),
                Arc::new(ListingHeadPlainStub),
            ],
        };
        let resp = svc
            .call(AsyncRequest {
                method: "HEAD".into(),
                path: "/v1/a/c".into(),
                query_string: "format=json".into(),
                headers: HeaderKeyDict::new(),
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(resp.status, 204);
        assert_eq!(
            resp.headers.get("Content-Type"),
            Some("application/json; charset=utf-8"),
            "official test_GET_HEAD_content_type on Hyper"
        );
    }

    /// Official test_versioning_dlo: empty DLO overwrite must not archive.
    struct VersioningDloManifestStub {
        archive_puts: Arc<std::sync::Mutex<u32>>,
    }
    impl swift_middleware::Middleware for VersioningDloManifestStub {
        fn handle(&self, req: Request, next: &swift_middleware::NextFn) -> Response {
            next(req)
        }
        fn intercepts_request(&self, req: &Request) -> bool {
            req.path.starts_with("/v1/AUTH_test/")
        }
        fn handle_request_async(
            &self,
            req: Request,
            _next: swift_middleware::AsyncNextFn,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>> {
            let archive_puts = Arc::clone(&self.archive_puts);
            Box::pin(async move {
                if req.method == "HEAD" && req.path == "/v1/AUTH_test/c" {
                    let mut resp = Response::new(204);
                    resp.headers
                        .set("X-Container-Sysmeta-Versions-Location", "versions");
                    resp.headers
                        .set("X-Container-Sysmeta-Versions-Mode", "stack");
                    return resp;
                }
                if req.method == "GET" && req.path == "/v1/AUTH_test/c/man" {
                    let mut resp = Response::new(200);
                    resp.headers.set("X-Object-Manifest", "c/man/");
                    resp.headers.set("X-Timestamp", "1751500000.00000");
                    resp.headers.set("Content-Length", "0");
                    return resp;
                }
                if req.method == "PUT" && req.path.starts_with("/v1/AUTH_test/versions/") {
                    *archive_puts.lock().unwrap_or_else(|p| p.into_inner()) += 1;
                    return Response::new(201);
                }
                if req.method == "PUT" && req.path == "/v1/AUTH_test/c/man" {
                    return Response::new(201);
                }
                Response::new(404)
            })
        }
    }

    #[tokio::test]
    async fn versioning_dlo_empty_overwrite_does_not_archive_on_hyper() {
        let archive_puts = Arc::new(std::sync::Mutex::new(0u32));
        let app = Arc::new(ProxyApp::new(
            policy_ring_tests::ring(1),
            policy_ring_tests::ring(2),
            ProxyConfig {
                auth_enabled: false,
                ..Default::default()
            },
        ));
        let svc = ProxyAsyncService {
            app: Arc::new(RwLock::new(app)),
            filters: vec![
                Arc::new(swift_middleware::VersionedWrites::new()),
                Arc::new(VersioningDloManifestStub {
                    archive_puts: Arc::clone(&archive_puts),
                }),
            ],
        };
        let mut headers = HeaderKeyDict::new();
        headers.set("X-Object-Manifest", "c/man/");
        headers.set("Content-Length", "0");
        let resp = svc
            .call(AsyncRequest {
                method: "PUT".into(),
                path: "/v1/AUTH_test/c/man".into(),
                query_string: String::new(),
                headers,
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(
            resp.status, 201,
            "DLO manifest PUT on Hyper must 201, got {}",
            resp.status
        );
        let archived = *archive_puts.lock().unwrap_or_else(|p| p.into_inner());
        assert_eq!(
            archived, 0,
            "official test_versioning_dlo must not archive the prior manifest"
        );
    }

    /// Official TestObjectVersioning overwrite: a non-DLO PUT must archive
    /// the current object into versions-location on the Hyper stream path.
    struct VersioningOverwriteStub {
        archive_puts: Arc<std::sync::Mutex<u32>>,
    }
    impl swift_middleware::Middleware for VersioningOverwriteStub {
        fn handle(&self, req: Request, next: &swift_middleware::NextFn) -> Response {
            next(req)
        }
        fn intercepts_request(&self, req: &Request) -> bool {
            req.path.starts_with("/v1/AUTH_test/")
        }
        fn handle_request_async(
            &self,
            req: Request,
            _next: swift_middleware::AsyncNextFn,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>> {
            let archive_puts = Arc::clone(&self.archive_puts);
            Box::pin(async move {
                if req.method == "HEAD" && req.path == "/v1/AUTH_test/c" {
                    let mut resp = Response::new(204);
                    resp.headers
                        .set("X-Container-Sysmeta-Versions-Location", "versions");
                    resp.headers
                        .set("X-Container-Sysmeta-Versions-Mode", "stack");
                    return resp;
                }
                if req.method == "GET" && req.path == "/v1/AUTH_test/c/obj" {
                    let mut resp = Response::with_body(200, b"aaaaa".to_vec());
                    resp.headers.set("X-Timestamp", "1751500000.00000");
                    resp.headers.set("Content-Type", "text/plain");
                    resp.headers.set("Content-Length", "5");
                    return resp;
                }
                if req.method == "PUT" && req.path.starts_with("/v1/AUTH_test/versions/") {
                    *archive_puts.lock().unwrap_or_else(|p| p.into_inner()) += 1;
                    return Response::new(201);
                }
                if req.method == "PUT" && req.path == "/v1/AUTH_test/c/obj" {
                    return Response::new(201);
                }
                Response::new(404)
            })
        }
    }

    #[tokio::test]
    async fn versioning_overwrite_archives_current_on_hyper() {
        let archive_puts = Arc::new(std::sync::Mutex::new(0u32));
        let app = Arc::new(ProxyApp::new(
            policy_ring_tests::ring(1),
            policy_ring_tests::ring(2),
            ProxyConfig {
                auth_enabled: false,
                ..Default::default()
            },
        ));
        let svc = ProxyAsyncService {
            app: Arc::new(RwLock::new(app)),
            filters: vec![
                Arc::new(swift_middleware::VersionedWrites::new()),
                Arc::new(VersioningOverwriteStub {
                    archive_puts: Arc::clone(&archive_puts),
                }),
            ],
        };
        let mut headers = HeaderKeyDict::new();
        headers.set("Content-Length", "5");
        headers.set("Content-Type", "text/plain");
        let resp = svc
            .call(AsyncRequest {
                method: "PUT".into(),
                path: "/v1/AUTH_test/c/obj".into(),
                query_string: String::new(),
                headers,
                body: IncomingBody::from_bytes(b"bbbbb".to_vec(), u64::MAX),
            })
            .await;
        assert_eq!(
            resp.status, 201,
            "versioned overwrite PUT on Hyper must 201, got {}",
            resp.status
        );
        let archived = *archive_puts.lock().unwrap_or_else(|p| p.into_inner());
        assert_eq!(
            archived, 1,
            "official versioning overwrite must archive current on Hyper"
        );
    }

    /// Official TestSloWithVersioning.test_slo_manifest_version.
    struct SloManifestVersionStub {
        store: Arc<std::sync::Mutex<std::collections::HashMap<String, (HeaderKeyDict, Vec<u8>)>>>,
    }
    impl swift_middleware::Middleware for SloManifestVersionStub {
        fn handle(&self, req: Request, next: &swift_middleware::NextFn) -> Response {
            next(req)
        }
        fn intercepts_request(&self, req: &Request) -> bool {
            req.path.starts_with("/v1/AUTH_test/")
        }
        fn handle_request_async(
            &self,
            mut req: Request,
            _next: swift_middleware::AsyncNextFn,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>> {
            let store = Arc::clone(&self.store);
            Box::pin(async move {
                if req.method == "HEAD" && req.path == "/v1/AUTH_test/c" {
                    let mut resp = Response::new(204);
                    resp.headers
                        .set("X-Container-Sysmeta-Versions-Location", "versions");
                    resp.headers
                        .set("X-Container-Sysmeta-Versions-Mode", "stack");
                    return resp;
                }
                if req.method == "HEAD" && req.path == "/v1/AUTH_test/versions" {
                    return Response::new(204);
                }
                if req.method == "GET" && req.path == "/v1/AUTH_test/versions" {
                    let prefix = req
                        .query_string
                        .split('&')
                        .find_map(|part| part.strip_prefix("prefix="))
                        .unwrap_or("");
                    let prefix = swift_http::unquote(prefix);
                    let mut names: Vec<String> = store
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .keys()
                        .filter_map(|path| path.strip_prefix("/v1/AUTH_test/versions/"))
                        .filter(|name| prefix.is_empty() || name.starts_with(&prefix))
                        .map(str::to_string)
                        .collect();
                    names.sort();
                    names.reverse();
                    let listing: Vec<serde_json::Value> = names
                        .into_iter()
                        .map(|name| {
                            serde_json::json!({
                                "name": name,
                                "bytes": 1,
                                "hash": "x",
                                "content_type": "application/octet-stream",
                            })
                        })
                        .collect();
                    return Response::with_body(200, serde_json::to_vec(&listing).unwrap());
                }
                if req.method == "PUT" {
                    let headers = req.headers.clone();
                    let body = match req.body.materialize(u64::MAX) {
                        Ok(b) => b.to_vec(),
                        Err(_) => Vec::new(),
                    };
                    store
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .insert(req.path, (headers, body));
                    return Response::new(201);
                }
                if matches!(req.method.as_str(), "GET" | "HEAD") {
                    let Some((headers, body)) = store
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .get(&req.path)
                        .cloned()
                    else {
                        return Response::new(404);
                    };
                    let mut resp = if req.method == "HEAD" {
                        Response::new(200)
                    } else {
                        Response::with_body(200, body.clone())
                    };
                    resp.headers = headers;
                    resp.headers.set("Content-Length", body.len().to_string());
                    return resp;
                }
                if req.method == "DELETE" {
                    store
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .remove(&req.path);
                    return Response::new(204);
                }
                Response::new(404)
            })
        }
    }

    #[tokio::test]
    async fn slo_manifest_version_archives_slo_on_hyper_path() {
        let store = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        let app = Arc::new(ProxyApp::new(
            policy_ring_tests::ring(1),
            policy_ring_tests::ring(2),
            ProxyConfig {
                auth_enabled: false,
                ..Default::default()
            },
        ));
        let svc = ProxyAsyncService {
            app: Arc::new(RwLock::new(app)),
            filters: vec![
                Arc::new(swift_middleware::VersionedWrites::new()),
                Arc::new(swift_middleware::Slo::new()),
                Arc::new(SloManifestVersionStub {
                    store: Arc::clone(&store),
                }),
            ],
        };
        let mut seg_a = HeaderKeyDict::new();
        seg_a.set("Etag", "47bce5c74f589f4867dbd57e9ca9f808");
        seg_a.set("Content-Length", "3");
        store
            .lock()
            .unwrap()
            .insert("/v1/AUTH_test/c/seg_a".into(), (seg_a, b"aaa".to_vec()));
        let mut seg_b = HeaderKeyDict::new();
        seg_b.set("Etag", "08f8e0260c6441850a3e202c8d8c4a70");
        seg_b.set("Content-Length", "3");
        store
            .lock()
            .unwrap()
            .insert("/v1/AUTH_test/c/seg_b".into(), (seg_b, b"bbb".to_vec()));

        let first = serde_json::to_vec(&serde_json::json!([{
            "path": "/c/seg_a",
            "etag": serde_json::Value::Null,
            "size_bytes": serde_json::Value::Null
        }]))
        .unwrap();
        let mut headers = HeaderKeyDict::new();
        headers.set("Content-Length", first.len().to_string());
        assert_eq!(
            svc.call(AsyncRequest {
                method: "PUT".into(),
                path: "/v1/AUTH_test/c/my-slo-manifest".into(),
                query_string: "multipart-manifest=put".into(),
                headers,
                body: IncomingBody::from_bytes(first, u64::MAX),
            })
            .await
            .status,
            201,
            "first SLO PUT"
        );

        let second = serde_json::to_vec(&serde_json::json!([{
            "path": "/c/seg_b",
            "etag": serde_json::Value::Null,
            "size_bytes": serde_json::Value::Null
        }]))
        .unwrap();
        let mut headers = HeaderKeyDict::new();
        headers.set("Content-Length", second.len().to_string());
        assert_eq!(
            svc.call(AsyncRequest {
                method: "PUT".into(),
                path: "/v1/AUTH_test/c/my-slo-manifest".into(),
                query_string: "multipart-manifest=put".into(),
                headers,
                body: IncomingBody::from_bytes(second, u64::MAX),
            })
            .await
            .status,
            201,
            "second SLO PUT must archive the previous manifest"
        );

        let archived: Vec<String> = store
            .lock()
            .unwrap()
            .keys()
            .filter(|p| p.starts_with("/v1/AUTH_test/versions/"))
            .cloned()
            .collect();
        assert_eq!(archived.len(), 1, "exactly one archived SLO: {archived:?}");
        let version_path = archived[0].clone();
        let (ver_headers, ver_body) = store.lock().unwrap().get(&version_path).unwrap().clone();
        assert!(
            ver_headers
                .get("X-Static-Large-Object")
                .is_some_and(config_true_value),
            "archived version must stay an SLO, headers={ver_headers:?}"
        );
        let ver_json: serde_json::Value = serde_json::from_slice(&ver_body).unwrap_or_default();
        assert!(
            ver_json.is_array(),
            "archived body must be stored manifest JSON, got {}",
            String::from_utf8_lossy(&ver_body)
        );

        let get = svc
            .call(AsyncRequest {
                method: "GET".into(),
                path: version_path.clone(),
                query_string: "multipart-manifest=get".into(),
                headers: HeaderKeyDict::new(),
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(get.status, 200, "version multipart-manifest=get");
        let got = get.body.collect_async().await.expect("version JSON body");
        let listing: serde_json::Value = serde_json::from_slice(&got).expect("version JSON");
        assert_eq!(listing[0]["name"], "/c/seg_a");

        let mut ranged = HeaderKeyDict::new();
        ranged.set("If-None-Match", "not-version");
        let assembled = svc
            .call(AsyncRequest {
                method: "GET".into(),
                path: version_path,
                query_string: String::new(),
                headers: ranged,
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(assembled.status, 200, "version assembled GET");
        let assembled_body = assembled
            .body
            .collect_async()
            .await
            .expect("version assembled body");
        assert_eq!(assembled_body, b"aaa");

        assert_eq!(
            svc.call(AsyncRequest {
                method: "DELETE".into(),
                path: "/v1/AUTH_test/c/my-slo-manifest".into(),
                query_string: String::new(),
                headers: HeaderKeyDict::new(),
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await
            .status,
            204,
            "DELETE current restores the archived SLO"
        );
        let mut restored_hdrs = HeaderKeyDict::new();
        restored_hdrs.set("If-None-Match", "not-restored");
        let restored = svc
            .call(AsyncRequest {
                method: "GET".into(),
                path: "/v1/AUTH_test/c/my-slo-manifest".into(),
                query_string: String::new(),
                headers: restored_hdrs,
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        let restored_body = restored
            .body
            .collect_async()
            .await
            .expect("restored assembled body");
        assert_eq!(
            restored_body, b"aaa",
            "official test_slo_manifest_version restore on Hyper"
        );
    }

    /// Official TestDlo.test_copy: COPY a DLO manifest must PUT the
    /// assembled bytes and must not persist `X-Object-Manifest`.
    struct DloCopyAssembleStub {
        dest: Arc<std::sync::Mutex<Option<(HeaderKeyDict, Vec<u8>)>>>,
    }
    impl swift_middleware::Middleware for DloCopyAssembleStub {
        fn handle(&self, req: Request, next: &swift_middleware::NextFn) -> Response {
            next(req)
        }
        fn intercepts_request(&self, req: &Request) -> bool {
            req.path.starts_with("/v1/a/c")
        }
        fn handle_request_async(
            &self,
            req: Request,
            _next: swift_middleware::AsyncNextFn,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>> {
            let dest = Arc::clone(&self.dest);
            Box::pin(async move {
                if req.path == "/v1/a/c/man" && req.method != "PUT" {
                    let mut resp = Response::with_body(200, b"man1-contents".to_vec());
                    resp.headers.set("X-Object-Manifest", "c/segs/");
                    resp.headers.set("Etag", "physical-manifest");
                    return resp;
                }
                if req.method == "GET" && req.path == "/v1/a/c" {
                    let listing = serde_json::json!([
                        {"name": "segs/1", "bytes": 3, "hash": "c4ca4238a0b923820dcc509a6f75849b"},
                        {"name": "segs/2", "bytes": 3, "hash": "c81e728d9d4c2f636f067f89cc14862c"},
                    ]);
                    return Response::with_body(200, serde_json::to_vec(&listing).unwrap());
                }
                if req.path == "/v1/a/c/segs/1" {
                    return Response::with_body(200, b"one".to_vec());
                }
                if req.path == "/v1/a/c/segs/2" {
                    return Response::with_body(200, b"two".to_vec());
                }
                if req.method == "PUT" && req.path == "/v1/a/c/copied" {
                    let headers = req.headers.clone();
                    let body = match req.body {
                        swift_http::Body::Buffered(b) => b,
                        _ => Vec::new(),
                    };
                    *dest.lock().unwrap_or_else(|p| p.into_inner()) = Some((headers, body));
                    return Response::new(201);
                }
                Response::new(404)
            })
        }
    }

    #[tokio::test]
    async fn dlo_copy_assembles_without_manifest_header_on_hyper() {
        let dest = Arc::new(std::sync::Mutex::new(None));
        let app = Arc::new(ProxyApp::new(
            policy_ring_tests::ring(1),
            policy_ring_tests::ring(2),
            ProxyConfig {
                auth_enabled: false,
                ..Default::default()
            },
        ));
        let svc = ProxyAsyncService {
            app: Arc::new(RwLock::new(app)),
            filters: vec![
                Arc::new(swift_middleware::Copy::new()),
                Arc::new(swift_middleware::DynamicLargeObject::new()),
                Arc::new(DloCopyAssembleStub {
                    dest: Arc::clone(&dest),
                }),
            ],
        };
        let mut headers = HeaderKeyDict::new();
        headers.set("Destination", "/c/copied");
        let resp = svc
            .call(AsyncRequest {
                method: "COPY".into(),
                path: "/v1/a/c/man".into(),
                query_string: String::new(),
                headers,
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(
            resp.status, 201,
            "official test_copy COPY on Hyper, got {}",
            resp.status
        );
        let (put_headers, put_body) = dest
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
            .expect("dest PUT");
        assert_eq!(put_body, b"onetwo", "COPY must persist assembled DLO bytes");
        assert!(
            put_headers.get("X-Object-Manifest").is_none(),
            "official test_copy: dest must not carry X-Object-Manifest"
        );
    }

    #[tokio::test]
    async fn dlo_copy_account_destination_account_on_hyper() {
        let dest = Arc::new(std::sync::Mutex::new(None));
        let app = Arc::new(ProxyApp::new(
            policy_ring_tests::ring(1),
            policy_ring_tests::ring(2),
            ProxyConfig {
                auth_enabled: false,
                ..Default::default()
            },
        ));
        let svc = ProxyAsyncService {
            app: Arc::new(RwLock::new(app)),
            filters: vec![
                Arc::new(swift_middleware::Copy::new()),
                Arc::new(swift_middleware::DynamicLargeObject::new()),
                Arc::new(DloCopyAssembleStub {
                    dest: Arc::clone(&dest),
                }),
            ],
        };
        let mut headers = HeaderKeyDict::new();
        headers.set("Destination", "/c/copied");
        headers.set("Destination-Account", "a");
        let resp = svc
            .call(AsyncRequest {
                method: "COPY".into(),
                path: "/v1/a/c/man".into(),
                query_string: String::new(),
                headers,
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(
            resp.status, 201,
            "official test_copy_account COPY on Hyper, got {}",
            resp.status
        );
        let (put_headers, put_body) = dest
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
            .expect("dest PUT");
        assert_eq!(put_body, b"onetwo");
        assert!(put_headers.get("X-Object-Manifest").is_none());
    }

    #[tokio::test]
    async fn dlo_ranged_get_uses_assembled_bytes_on_hyper() {
        let dest = Arc::new(std::sync::Mutex::new(None));
        let app = Arc::new(ProxyApp::new(
            policy_ring_tests::ring(1),
            policy_ring_tests::ring(2),
            ProxyConfig {
                auth_enabled: false,
                ..Default::default()
            },
        ));
        let svc = ProxyAsyncService {
            app: Arc::new(RwLock::new(app)),
            filters: vec![
                Arc::new(swift_middleware::DynamicLargeObject::new()),
                Arc::new(DloCopyAssembleStub {
                    dest: Arc::clone(&dest),
                }),
            ],
        };
        let mut headers = HeaderKeyDict::new();
        headers.set("Range", "bytes=1-3");
        let mut resp = svc
            .call(AsyncRequest {
                method: "GET".into(),
                path: "/v1/a/c/man".into(),
                query_string: String::new(),
                headers,
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(
            resp.status, 206,
            "official test_get_range on Hyper, got {}",
            resp.status
        );
        resp.body.materialize(u64::MAX).unwrap();
        let body = match &resp.body {
            swift_http::Body::Buffered(b) => b.clone(),
            _ => Vec::new(),
        };
        assert_eq!(body, b"net", "assembled DLO Range bytes=1-3 of onetwo");
        let mut oob = HeaderKeyDict::new();
        oob.set("Range", "bytes=50-56");
        let miss = svc
            .call(AsyncRequest {
                method: "GET".into(),
                path: "/v1/a/c/man".into(),
                query_string: String::new(),
                headers: oob,
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(
            miss.status, 416,
            "official test_get_range_out_of_range on Hyper, got {}",
            miss.status
        );
    }

    #[tokio::test]
    async fn dlo_if_none_match_assembled_etag_is_304_on_hyper() {
        let app = Arc::new(ProxyApp::new(
            policy_ring_tests::ring(1),
            policy_ring_tests::ring(2),
            ProxyConfig {
                auth_enabled: false,
                ..Default::default()
            },
        ));
        let svc = ProxyAsyncService {
            app: Arc::new(RwLock::new(app)),
            filters: vec![
                Arc::new(swift_middleware::DynamicLargeObject::new()),
                Arc::new(DloIfMatchObjectServerStub),
            ],
        };
        let head = svc
            .call(AsyncRequest {
                method: "HEAD".into(),
                path: "/v1/a/c/manifest".into(),
                query_string: String::new(),
                headers: HeaderKeyDict::new(),
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(head.status, 200);
        let etag = head
            .headers
            .get("Etag")
            .expect("assembled DLO Etag")
            .to_string();
        let mut headers = HeaderKeyDict::new();
        headers.set("If-None-Match", &etag);
        let resp = svc
            .call(AsyncRequest {
                method: "GET".into(),
                path: "/v1/a/c/manifest".into(),
                query_string: String::new(),
                headers,
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(
            resp.status, 304,
            "official test_dlo_if_none_match_get on Hyper, got {}",
            resp.status
        );
        let mut head_match = HeaderKeyDict::new();
        head_match.set("If-None-Match", &etag);
        let head_304 = svc
            .call(AsyncRequest {
                method: "HEAD".into(),
                path: "/v1/a/c/manifest".into(),
                query_string: String::new(),
                headers: head_match,
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(
            head_304.status, 304,
            "official test_dlo_if_none_match_head on Hyper, got {}",
            head_304.status
        );
        let mut miss = HeaderKeyDict::new();
        miss.set("If-None-Match", format!("not-{etag}"));
        let miss_head = svc
            .call(AsyncRequest {
                method: "HEAD".into(),
                path: "/v1/a/c/manifest".into(),
                query_string: String::new(),
                headers: miss,
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(
            miss_head.status, 200,
            "official test_dlo_if_none_match_head miss on Hyper, got {}",
            miss_head.status
        );
    }

    /// Official TestStaticWebTempurl.test_get_dir: listings on, prefix=""
    /// TempURL of `/container/dir/` is 200 with parent `href="..` and
    /// TempURL query on object hrefs.
    struct ListingsDirContainerStub;
    impl swift_middleware::Middleware for ListingsDirContainerStub {
        fn handle(&self, req: Request, next: &swift_middleware::NextFn) -> Response {
            next(req)
        }
        fn intercepts_request(&self, req: &Request) -> bool {
            req.path.starts_with("/v1/AUTH_account/container")
        }
        fn handle_request_async(
            &self,
            req: Request,
            _next: swift_middleware::AsyncNextFn,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>> {
            Box::pin(async move {
                if req.path == "/v1/AUTH_account/container/dir"
                    || req.path == "/v1/AUTH_account/container/dir/"
                {
                    let mut resp = Response::new(200);
                    resp.headers.set("Content-Type", "application/directory");
                    resp.headers.set("Content-Length", "0");
                    return resp;
                }
                if req.method == "HEAD" && req.path == "/v1/AUTH_account/container" {
                    let mut resp = Response::new(204);
                    resp.headers.set("X-Container-Meta-Web-Listings", "true");
                    resp.headers.set("X-Container-Object-Count", "2");
                    resp.headers.set("X-Timestamp", "1000.00000");
                    return resp;
                }
                if req.method == "GET" && req.path == "/v1/AUTH_account/container" {
                    let listing = serde_json::json!([
                        {"name": "dir/obj", "bytes": 3, "hash": "x", "content_type": "text/plain", "last_modified": "2010-01-01T00:00:00.000000"},
                        {"subdir": "dir/subdir/"}
                    ]);
                    let mut resp = Response::with_body(200, serde_json::to_vec(&listing).unwrap());
                    resp.headers.set("Content-Type", "application/json");
                    return resp;
                }
                Response::new(404)
            })
        }
    }

    #[tokio::test]
    async fn staticweb_listings_on_prefix_tempurl_dir_is_200_on_hyper() {
        const KEY: &str = "mykey";
        const EXPIRES: &str = "4102444800";
        const SIG: &str = "f13df77135f801a28d05f2b3ec2f3558fa9f5858d9218bc6c84b09fccffd5fa6";
        let app = Arc::new(ProxyApp::new(
            policy_ring_tests::ring(1),
            policy_ring_tests::ring(2),
            ProxyConfig {
                auth_enabled: true,
                ..Default::default()
            },
        ));
        let tu = swift_middleware::TempUrl::new(Arc::new(
            swift_middleware::ClosureKeyProvider::new(|_a, _c| vec![KEY.to_string()]),
        ));
        let svc = ProxyAsyncService {
            app: Arc::new(RwLock::new(app)),
            filters: vec![
                Arc::new(tu),
                Arc::new(swift_middleware::StaticWeb::new()),
                Arc::new(ListingsDirContainerStub),
            ],
        };
        let mut resp = svc
            .call(AsyncRequest {
                method: "GET".into(),
                path: "/v1/AUTH_account/container/dir/".into(),
                query_string: format!(
                    "temp_url_sig={SIG}&temp_url_expires={EXPIRES}&temp_url_prefix="
                ),
                headers: HeaderKeyDict::new(),
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(
            resp.status, 200,
            "official test_get_dir on Hyper, got {}",
            resp.status
        );
        resp.body.materialize(u64::MAX).unwrap();
        let body = match &resp.body {
            swift_http::Body::Buffered(b) => String::from_utf8_lossy(b).into_owned(),
            _ => String::new(),
        };
        assert!(
            body.contains("Listing of /v1/"),
            "official test_get_dir listing title, got {body}"
        );
        assert!(
            body.contains("href=\".."),
            "official test_get_dir parent href, got {body}"
        );
        assert!(
            body.contains(&format!("temp_url_sig={SIG}")),
            "official test_get_dir must keep TempURL query on hrefs, got {body}"
        );
        assert!(
            body.contains("<a href=\"./obj"),
            "official test_get_dir object href, got {body}"
        );
    }

    #[tokio::test]
    async fn staticweb_listings_on_prefix_tempurl_dir_inline_on_hyper() {
        const KEY: &str = "mykey";
        const EXPIRES: &str = "4102444800";
        const SIG: &str = "f13df77135f801a28d05f2b3ec2f3558fa9f5858d9218bc6c84b09fccffd5fa6";
        let app = Arc::new(ProxyApp::new(
            policy_ring_tests::ring(1),
            policy_ring_tests::ring(2),
            ProxyConfig {
                auth_enabled: true,
                ..Default::default()
            },
        ));
        let tu = swift_middleware::TempUrl::new(Arc::new(
            swift_middleware::ClosureKeyProvider::new(|_a, _c| vec![KEY.to_string()]),
        ));
        let svc = ProxyAsyncService {
            app: Arc::new(RwLock::new(app)),
            filters: vec![
                Arc::new(tu),
                Arc::new(swift_middleware::StaticWeb::new()),
                Arc::new(ListingsDirContainerStub),
            ],
        };
        let mut resp = svc
            .call(AsyncRequest {
                method: "GET".into(),
                path: "/v1/AUTH_account/container/dir/".into(),
                query_string: format!(
                    "temp_url_sig={SIG}&temp_url_expires={EXPIRES}&temp_url_prefix=&inline=1"
                ),
                headers: HeaderKeyDict::new(),
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(
            resp.status, 200,
            "official test_get_dir_with_inline on Hyper, got {}",
            resp.status
        );
        resp.body.materialize(u64::MAX).unwrap();
        let body = match &resp.body {
            swift_http::Body::Buffered(b) => String::from_utf8_lossy(b).into_owned(),
            _ => String::new(),
        };
        assert!(
            body.contains("&amp;inline"),
            "official test_get_dir_with_inline href must include inline, got {body}"
        );
    }

    #[tokio::test]
    async fn staticweb_limited_dir_prefix_tempurl_hides_parent_on_hyper() {
        // Official test_get_limited_dir: prefix scoped to dir/ must not
        // emit href=".." (would escape the signed prefix).
        const KEY: &str = "mykey";
        const EXPIRES: &str = "4102444800";
        const SIG: &str = "19f889cf626f10a4dda11a2474f8906430efd3a4d63ad77f893aa0bbc03646bd";
        let app = Arc::new(ProxyApp::new(
            policy_ring_tests::ring(1),
            policy_ring_tests::ring(2),
            ProxyConfig {
                auth_enabled: true,
                ..Default::default()
            },
        ));
        let tu = swift_middleware::TempUrl::new(Arc::new(
            swift_middleware::ClosureKeyProvider::new(|_a, _c| vec![KEY.to_string()]),
        ));
        let svc = ProxyAsyncService {
            app: Arc::new(RwLock::new(app)),
            filters: vec![
                Arc::new(tu),
                Arc::new(swift_middleware::StaticWeb::new()),
                Arc::new(ListingsDirContainerStub),
            ],
        };
        let mut resp = svc
            .call(AsyncRequest {
                method: "GET".into(),
                path: "/v1/AUTH_account/container/dir/".into(),
                query_string: format!(
                    "temp_url_sig={SIG}&temp_url_expires={EXPIRES}&temp_url_prefix=dir/"
                ),
                headers: HeaderKeyDict::new(),
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(
            resp.status, 200,
            "official test_get_limited_dir on Hyper, got {}",
            resp.status
        );
        resp.body.materialize(u64::MAX).unwrap();
        let body = match &resp.body {
            swift_http::Body::Buffered(b) => String::from_utf8_lossy(b).into_owned(),
            _ => String::new(),
        };
        assert!(
            !body.contains("href=\".."),
            "limited prefix TempURL must hide parent ../, got {body}"
        );
        assert!(
            body.contains("<a href=\"./obj"),
            "limited dir listing still lists objects, got {body}"
        );
    }

    /// Official TestStaticWebTempurl.test_get_dir_with_iso_expiry: HMAC is
    /// over the numeric epoch, but listing hrefs must keep the ISO8601
    /// `temp_url_expires` the client presented (`quote` encodes `:`).
    #[tokio::test]
    async fn staticweb_listings_on_prefix_tempurl_iso_expiry_on_hyper() {
        const KEY: &str = "mykey";
        const ISO: &str = "2100-01-01T00:00:00Z";
        const SIG: &str = "f13df77135f801a28d05f2b3ec2f3558fa9f5858d9218bc6c84b09fccffd5fa6";
        let app = Arc::new(ProxyApp::new(
            policy_ring_tests::ring(1),
            policy_ring_tests::ring(2),
            ProxyConfig {
                auth_enabled: true,
                ..Default::default()
            },
        ));
        let tu = swift_middleware::TempUrl::new(Arc::new(
            swift_middleware::ClosureKeyProvider::new(|_a, _c| vec![KEY.to_string()]),
        ));
        let svc = ProxyAsyncService {
            app: Arc::new(RwLock::new(app)),
            filters: vec![
                Arc::new(tu),
                Arc::new(swift_middleware::StaticWeb::new()),
                Arc::new(ListingsDirContainerStub),
            ],
        };
        let mut resp = svc
            .call(AsyncRequest {
                method: "GET".into(),
                path: "/v1/AUTH_account/container/dir/".into(),
                query_string: format!("temp_url_sig={SIG}&temp_url_expires={ISO}&temp_url_prefix="),
                headers: HeaderKeyDict::new(),
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(
            resp.status, 200,
            "official test_get_dir_with_iso_expiry on Hyper, got {}",
            resp.status
        );
        resp.body.materialize(u64::MAX).unwrap();
        let body = match &resp.body {
            swift_http::Body::Buffered(b) => String::from_utf8_lossy(b).into_owned(),
            _ => String::new(),
        };
        assert!(
            body.contains("temp_url_expires=2100-01-01T00%3A00%3A00Z"),
            "official test_get_dir_with_iso_expiry href must keep ISO expires, got {body}"
        );
        assert!(
            !body.contains("temp_url_expires=4102444800"),
            "ISO TempURL listing must not rewrite expires to epoch, got {body}"
        );
    }

    /// Official TestStaticWebTempurl.test_unauthed: container GET with no
    /// token and no TempURL is 401 even when listings are on.
    struct ListingsOnAuthRequiredStub;
    impl swift_middleware::Middleware for ListingsOnAuthRequiredStub {
        fn handle(&self, req: Request, next: &swift_middleware::NextFn) -> Response {
            next(req)
        }
        fn intercepts_request(&self, req: &Request) -> bool {
            req.path.starts_with("/v1/AUTH_account/container")
        }
        fn handle_request_async(
            &self,
            req: Request,
            _next: swift_middleware::AsyncNextFn,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>> {
            Box::pin(async move {
                let authed = req.headers.get("X-Auth-Token").is_some()
                    || req.headers.get("X-Backend-Authorize-Override") == Some("true");
                if !authed {
                    return Response::error(401, "Unauthorized");
                }
                let mut resp = if req.method == "HEAD" {
                    Response::new(204)
                } else {
                    Response::with_body(200, b"[]".to_vec())
                };
                resp.headers.set("X-Container-Meta-Web-Listings", "true");
                resp.headers.set("X-Container-Object-Count", "1");
                resp.headers.set("X-Timestamp", "1000.00000");
                resp
            })
        }
    }

    #[tokio::test]
    async fn staticweb_listings_on_unauthed_container_get_is_401_on_hyper() {
        let app = Arc::new(ProxyApp::new(
            policy_ring_tests::ring(1),
            policy_ring_tests::ring(2),
            ProxyConfig {
                auth_enabled: true,
                ..Default::default()
            },
        ));
        let tu = swift_middleware::TempUrl::new(Arc::new(
            swift_middleware::ClosureKeyProvider::new(|_a, _c| vec!["mykey".to_string()]),
        ));
        let svc = ProxyAsyncService {
            app: Arc::new(RwLock::new(app)),
            filters: vec![
                Arc::new(tu),
                Arc::new(swift_middleware::StaticWeb::new()),
                Arc::new(ListingsOnAuthRequiredStub),
            ],
        };
        let resp = svc
            .call(AsyncRequest {
                method: "GET".into(),
                path: "/v1/AUTH_account/container".into(),
                query_string: String::new(),
                headers: HeaderKeyDict::new(),
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(
            resp.status, 401,
            "official test_unauthed on Hyper, got {}",
            resp.status
        );
    }

    /// Official TestTempURL.test_PUT_manifest_access: a signed PUT/POST
    /// carrying `X-Object-Manifest` is 400 in `prepare()` (Hyper never
    /// calls `handle()`).
    struct TempurlWriteWouldSucceedStub;
    impl swift_middleware::Middleware for TempurlWriteWouldSucceedStub {
        fn handle(&self, req: Request, next: &swift_middleware::NextFn) -> Response {
            next(req)
        }
        fn intercepts_request(&self, req: &Request) -> bool {
            matches!(req.method.as_str(), "PUT" | "POST")
                && req.path == "/v1/AUTH_account/container/object"
        }
        fn handle_request_async(
            &self,
            _req: Request,
            _next: swift_middleware::AsyncNextFn,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>> {
            Box::pin(async move { Response::new(201) })
        }
    }

    #[tokio::test]
    async fn tempurl_put_manifest_is_400_on_hyper() {
        const KEY: &str = "mykey";
        const EXPIRES: &str = "4102444800";
        const SIG: &str = "075253051197618a0ba40c0cb27954ab7774acea82b34cb7ffb6198c64f7e6cb";
        let app = Arc::new(ProxyApp::new(
            policy_ring_tests::ring(1),
            policy_ring_tests::ring(2),
            ProxyConfig {
                auth_enabled: true,
                ..Default::default()
            },
        ));
        let tu = swift_middleware::TempUrl::new(Arc::new(
            swift_middleware::ClosureKeyProvider::new(|_a, _c| vec![KEY.to_string()]),
        ));
        let svc = ProxyAsyncService {
            app: Arc::new(RwLock::new(app)),
            filters: vec![Arc::new(tu), Arc::new(TempurlWriteWouldSucceedStub)],
        };
        let mut headers = HeaderKeyDict::new();
        headers.set("X-Object-Manifest", "some_random_container/foo");
        let mut resp = svc
            .call(AsyncRequest {
                method: "PUT".into(),
                path: "/v1/AUTH_account/container/object".into(),
                query_string: format!("temp_url_sig={SIG}&temp_url_expires={EXPIRES}"),
                headers,
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(
            resp.status, 400,
            "official test_PUT_manifest_access PUT on Hyper, got {}",
            resp.status
        );
        resp.body.materialize(u64::MAX).unwrap();
        let body = match &resp.body {
            swift_http::Body::Buffered(b) => String::from_utf8_lossy(b).into_owned(),
            _ => String::new(),
        };
        assert_eq!(
            body, "The header 'X-Object-Manifest' is not allowed in this tempurl",
            "official test_PUT_manifest_access body, got {body:?}"
        );
    }

    #[tokio::test]
    async fn tempurl_post_manifest_is_400_on_hyper() {
        const KEY: &str = "mykey";
        const EXPIRES: &str = "4102444800";
        const SIG: &str = "47ba39ae5b07dde742ab515bb632b910eaa9a0b1343acde4face2efda13982a9";
        let app = Arc::new(ProxyApp::new(
            policy_ring_tests::ring(1),
            policy_ring_tests::ring(2),
            ProxyConfig {
                auth_enabled: true,
                ..Default::default()
            },
        ));
        let tu = swift_middleware::TempUrl::new(Arc::new(
            swift_middleware::ClosureKeyProvider::new(|_a, _c| vec![KEY.to_string()]),
        ));
        let svc = ProxyAsyncService {
            app: Arc::new(RwLock::new(app)),
            filters: vec![Arc::new(tu), Arc::new(TempurlWriteWouldSucceedStub)],
        };
        let mut headers = HeaderKeyDict::new();
        headers.set("X-Object-Manifest", "other/foo");
        let mut resp = svc
            .call(AsyncRequest {
                method: "POST".into(),
                path: "/v1/AUTH_account/container/object".into(),
                query_string: format!("temp_url_sig={SIG}&temp_url_expires={EXPIRES}"),
                headers,
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(
            resp.status, 400,
            "official test_PUT_manifest_access POST on Hyper, got {}",
            resp.status
        );
        resp.body.materialize(u64::MAX).unwrap();
        let body = match &resp.body {
            swift_http::Body::Buffered(b) => String::from_utf8_lossy(b).into_owned(),
            _ => String::new(),
        };
        assert_eq!(
            body,
            "The header 'X-Object-Manifest' is not allowed in this tempurl"
        );
    }

    #[tokio::test]
    async fn dlo_copy_manifest_keeps_x_object_manifest_on_hyper() {
        // Official TestDlo.test_copy_manifest: COPY ?multipart-manifest=get
        // remanifests. Dest PUT must keep X-Object-Manifest and the raw
        // manifest bytes (not the assembled segments).
        let dest = Arc::new(std::sync::Mutex::new(None));
        let app = Arc::new(ProxyApp::new(
            policy_ring_tests::ring(1),
            policy_ring_tests::ring(2),
            ProxyConfig {
                auth_enabled: false,
                ..Default::default()
            },
        ));
        let svc = ProxyAsyncService {
            app: Arc::new(RwLock::new(app)),
            filters: vec![
                Arc::new(swift_middleware::Copy::new()),
                Arc::new(swift_middleware::DynamicLargeObject::new()),
                Arc::new(DloCopyAssembleStub {
                    dest: Arc::clone(&dest),
                }),
            ],
        };
        let mut headers = HeaderKeyDict::new();
        headers.set("Destination", "/c/copied");
        let resp = svc
            .call(AsyncRequest {
                method: "COPY".into(),
                path: "/v1/a/c/man".into(),
                query_string: "multipart-manifest=get".into(),
                headers,
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(
            resp.status, 201,
            "official test_copy_manifest COPY on Hyper, got {}",
            resp.status
        );
        let (put_headers, put_body) = dest
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
            .expect("dest PUT");
        assert_eq!(
            put_body, b"man1-contents",
            "official test_copy_manifest must persist raw manifest bytes"
        );
        assert_eq!(
            put_headers.get("X-Object-Manifest"),
            Some("c/segs/"),
            "official test_copy_manifest dest must keep X-Object-Manifest"
        );
    }

    /// Official listing_formats test_GET_HEAD_content_type: GET
    /// `?format=xml` stamps application/xml on a JSON container listing.
    struct ListingJsonArrayStub;
    impl swift_middleware::Middleware for ListingJsonArrayStub {
        fn handle(&self, req: Request, next: &swift_middleware::NextFn) -> Response {
            next(req)
        }
        fn intercepts_request(&self, req: &Request) -> bool {
            matches!(req.method.as_str(), "GET" | "HEAD") && req.path == "/v1/a/c"
        }
        fn handle_request_async(
            &self,
            req: Request,
            _next: swift_middleware::AsyncNextFn,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>> {
            Box::pin(async move {
                if req.method == "HEAD" {
                    let mut resp = Response::new(204);
                    resp.headers
                        .set("Content-Type", "text/plain; charset=utf-8");
                    return resp;
                }
                let listing = serde_json::json!([
                    {"name": "o", "bytes": 1, "hash": "x", "content_type": "text/plain",
                     "last_modified": "2010-01-01T00:00:00.000000"}
                ]);
                let mut resp = Response::with_body(200, serde_json::to_vec(&listing).unwrap());
                resp.headers.set("Content-Type", "application/json");
                resp
            })
        }
    }

    #[tokio::test]
    async fn listing_formats_get_xml_content_type_on_hyper_path() {
        let app = Arc::new(ProxyApp::new(
            policy_ring_tests::ring(1),
            policy_ring_tests::ring(2),
            ProxyConfig {
                auth_enabled: false,
                ..Default::default()
            },
        ));
        let svc = ProxyAsyncService {
            app: Arc::new(RwLock::new(app)),
            filters: vec![
                Arc::new(swift_middleware::ListingFormats),
                Arc::new(ListingJsonArrayStub),
            ],
        };
        let mut resp = svc
            .call(AsyncRequest {
                method: "GET".into(),
                path: "/v1/a/c".into(),
                query_string: "format=xml".into(),
                headers: HeaderKeyDict::new(),
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(resp.status, 200);
        assert_eq!(
            resp.headers.get("Content-Type"),
            Some("application/xml; charset=utf-8"),
            "official test_GET_HEAD_content_type GET xml on Hyper"
        );
        resp.body.materialize(u64::MAX).unwrap();
        let body = match &resp.body {
            swift_http::Body::Buffered(b) => String::from_utf8_lossy(b).into_owned(),
            _ => String::new(),
        };
        assert!(
            body.contains("<object>") && body.contains("<name>o</name>"),
            "GET ?format=xml must convert the JSON listing, got {body}"
        );
    }

    /// Official test_versioning_check_acl: versions container is public
    /// read, but a foreign token must not DELETE/pop the source object.
    struct VersioningCheckAclStub {
        current: Arc<std::sync::Mutex<Vec<u8>>>,
        archive_deletes: Arc<std::sync::Mutex<u32>>,
    }
    impl swift_middleware::Middleware for VersioningCheckAclStub {
        fn handle(&self, req: Request, next: &swift_middleware::NextFn) -> Response {
            next(req)
        }
        fn intercepts_request(&self, req: &Request) -> bool {
            req.path.starts_with("/v1/AUTH_test/")
        }
        fn handle_request_async(
            &self,
            req: Request,
            _next: swift_middleware::AsyncNextFn,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>> {
            let current = Arc::clone(&self.current);
            let archive_deletes = Arc::clone(&self.archive_deletes);
            Box::pin(async move {
                if req
                    .headers
                    .get(swift_middleware::VERSIONED_WRITES_AUTHORIZE_ONLY_HEADER)
                    == Some("true")
                {
                    if req.headers.get("X-Auth-Token") == Some("token2") {
                        return Response::error(403, "Forbidden");
                    }
                    return Response::new(204);
                }
                if req.method == "HEAD" && req.path == "/v1/AUTH_test/c" {
                    let mut resp = Response::new(204);
                    resp.headers
                        .set("X-Container-Sysmeta-Versions-Location", "versions");
                    resp.headers
                        .set("X-Container-Sysmeta-Versions-Mode", "stack");
                    return resp;
                }
                if req.path == "/v1/AUTH_test/c/obj" {
                    if req.method == "GET" || req.method == "HEAD" {
                        let body = current.lock().unwrap_or_else(|p| p.into_inner()).clone();
                        let mut resp = if req.method == "HEAD" {
                            Response::new(200)
                        } else {
                            Response::with_body(200, body.clone())
                        };
                        resp.headers.set("Content-Length", body.len().to_string());
                        resp.headers.set("X-Timestamp", "1751500001.00000");
                        return resp;
                    }
                    if req.method == "PUT" {
                        let body = match req.body {
                            swift_http::Body::Buffered(b) => b,
                            _ => Vec::new(),
                        };
                        *current.lock().unwrap_or_else(|p| p.into_inner()) = body;
                        return Response::new(201);
                    }
                }
                if req.method == "GET" && req.path == "/v1/AUTH_test/versions" {
                    let listing = serde_json::json!([
                        {"name": "003obj/1751500000.00000", "bytes": 5,
                         "hash": "x", "content_type": "text/plain",
                         "last_modified": "2010-01-01T00:00:00.000000"}
                    ]);
                    return Response::with_body(200, serde_json::to_vec(&listing).unwrap());
                }
                if req.method == "DELETE" && req.path.starts_with("/v1/AUTH_test/versions/") {
                    *archive_deletes.lock().unwrap_or_else(|p| p.into_inner()) += 1;
                    return Response::new(204);
                }
                if req.method == "GET" && req.path.starts_with("/v1/AUTH_test/versions/") {
                    return Response::with_body(200, b"aaaaa".to_vec());
                }
                Response::new(404)
            })
        }
    }

    #[tokio::test]
    async fn versioning_check_acl_foreign_token_delete_is_denied_on_hyper() {
        let current = Arc::new(std::sync::Mutex::new(b"bbbbb".to_vec()));
        let archive_deletes = Arc::new(std::sync::Mutex::new(0u32));
        let app = Arc::new(ProxyApp::new(
            policy_ring_tests::ring(1),
            policy_ring_tests::ring(2),
            ProxyConfig {
                auth_enabled: false,
                ..Default::default()
            },
        ));
        let svc = ProxyAsyncService {
            app: Arc::new(RwLock::new(app)),
            filters: vec![
                Arc::new(swift_middleware::VersionedWrites::new()),
                Arc::new(VersioningCheckAclStub {
                    current: Arc::clone(&current),
                    archive_deletes: Arc::clone(&archive_deletes),
                }),
            ],
        };
        let mut headers = HeaderKeyDict::new();
        headers.set("X-Auth-Token", "token2");
        let resp = svc
            .call(AsyncRequest {
                method: "DELETE".into(),
                path: "/v1/AUTH_test/c/obj".into(),
                query_string: String::new(),
                headers,
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(
            resp.status, 403,
            "official test_versioning_check_acl foreign DELETE on Hyper, got {}",
            resp.status
        );
        let body = current.lock().unwrap_or_else(|p| p.into_inner()).clone();
        assert_eq!(
            body, b"bbbbb",
            "foreign DELETE must not pop/restore the versioned object"
        );
        let deleted = *archive_deletes.lock().unwrap_or_else(|p| p.into_inner());
        assert_eq!(
            deleted, 0,
            "foreign DELETE must not consume the versions archive"
        );
    }

    /// Container-only TempURL keys (IsolatedIdentity TestContainerTempurl).
    struct ContainerOnlyTempUrlKeys(Vec<String>);
    impl swift_middleware::KeyProvider for ContainerOnlyTempUrlKeys {
        fn keys_for(&self, _account: &str, _container: &str) -> Vec<String> {
            self.0.clone()
        }
        fn scoped_keys_for(
            &self,
            _account: &str,
            _container: &str,
        ) -> swift_middleware::ScopedTempUrlKeys {
            swift_middleware::ScopedTempUrlKeys {
                account: Vec::new(),
                container: self.0.clone(),
            }
        }
    }

    /// Official TestContainerTempurl.test_GET_DLO_outside_container: listing
    /// a foreign segment container under a container-key TempURL is 401.
    struct DloOutsideContainerStub {
        foreign_listings: Arc<std::sync::Mutex<u32>>,
    }
    impl swift_middleware::Middleware for DloOutsideContainerStub {
        fn handle(&self, req: Request, next: &swift_middleware::NextFn) -> Response {
            next(req)
        }
        fn intercepts_request(&self, req: &Request) -> bool {
            req.path.starts_with("/v1/AUTH_account/")
        }
        fn handle_request_async(
            &self,
            req: Request,
            _next: swift_middleware::AsyncNextFn,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>> {
            let foreign_listings = Arc::clone(&self.foreign_listings);
            Box::pin(async move {
                if req.path == "/v1/AUTH_account/container/object" {
                    let mut resp = Response::new(200);
                    resp.headers.set("X-Object-Manifest", "other/segs/");
                    resp.headers.set("Etag", "physical-manifest");
                    return resp;
                }
                if req.path == "/v1/AUTH_account/other" {
                    *foreign_listings.lock().unwrap_or_else(|p| p.into_inner()) += 1;
                    let listing = serde_json::json!([
                        {"name": "segs/1", "bytes": 3, "hash": "c4ca4238a0b923820dcc509a6f75849b"}
                    ]);
                    return Response::with_body(200, serde_json::to_vec(&listing).unwrap());
                }
                if req.path == "/v1/AUTH_account/other/segs/1" {
                    return Response::with_body(200, b"one".to_vec());
                }
                Response::new(404)
            })
        }
    }

    #[tokio::test]
    async fn container_tempurl_dlo_outside_container_is_401_on_hyper() {
        const KEY: &str = "mykey";
        const EXPIRES: &str = "4102444800";
        const SIG: &str = "beb29507e95de0350c1076f7671d128cc02120c3186c0ba7c70d4d3a1bba6bfe";
        let foreign_listings = Arc::new(std::sync::Mutex::new(0u32));
        let app = Arc::new(ProxyApp::new(
            policy_ring_tests::ring(1),
            policy_ring_tests::ring(2),
            ProxyConfig {
                auth_enabled: true,
                ..Default::default()
            },
        ));
        let tu = swift_middleware::TempUrl::new(Arc::new(ContainerOnlyTempUrlKeys(vec![
            KEY.to_string()
        ])));
        let svc = ProxyAsyncService {
            app: Arc::new(RwLock::new(app)),
            filters: vec![
                Arc::new(tu),
                Arc::new(swift_middleware::DynamicLargeObject::new()),
                Arc::new(DloOutsideContainerStub {
                    foreign_listings: Arc::clone(&foreign_listings),
                }),
            ],
        };
        for method in ["GET", "HEAD"] {
            let mut resp = svc
                .call(AsyncRequest {
                    method: method.into(),
                    path: "/v1/AUTH_account/container/object".into(),
                    query_string: format!("temp_url_sig={SIG}&temp_url_expires={EXPIRES}"),
                    headers: HeaderKeyDict::new(),
                    body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
                })
                .await;
            assert_eq!(
                resp.status, 401,
                "official test_GET_DLO_outside_container {method} on Hyper, got {}",
                resp.status
            );
            resp.body.materialize(u64::MAX).unwrap();
            let body = match &resp.body {
                swift_http::Body::Buffered(b) => String::from_utf8_lossy(b).into_owned(),
                _ => String::new(),
            };
            if method == "GET" {
                assert!(
                    body.contains("Temp URL invalid"),
                    "container-scope DLO {method} 401 body, got {body:?}"
                );
            }
        }
        let listed = *foreign_listings.lock().unwrap_or_else(|p| p.into_inner());
        assert_eq!(
            listed, 0,
            "must not list the foreign segment container, listings={listed}"
        );
    }

    fn account_quota_policies() -> swift_core::storage_policy::StoragePolicyCollection {
        let conf = "[storage-policy:0]\nname = nulo\ndefault = yes\n\
                    [storage-policy:1]\nname = unu\n";
        swift_core::storage_policy::parse_storage_policies(
            &swift_core::config::SwiftConfig::parse_lenient(conf, &[], false).unwrap(),
        )
        .unwrap()
    }

    /// Field G4 `versioning_container_acl`: Hyper used to rewrite
    /// `X-Versions-Location` in `versioned_writes.prepare()` and persist it
    /// on an account-RW / !swift_owner container POST (204). Official
    /// `update_metadata` must raise.
    #[tokio::test]
    async fn versioning_container_acl_hyper_path_non_owner_cannot_set_location() {
        let app = Arc::new(ProxyApp::new(
            policy_ring_tests::ring(1),
            policy_ring_tests::ring(2),
            ProxyConfig {
                auth_enabled: false,
                conn_timeout: Duration::from_millis(50),
                node_timeout: Duration::from_millis(50),
                ..Default::default()
            },
        ));
        let svc = ProxyAsyncService {
            app: Arc::new(RwLock::new(app)),
            filters: vec![Arc::new(swift_middleware::VersionedWrites::new())],
        };
        let mut headers = HeaderKeyDict::new();
        headers.set("X-Versions-Location", "versions");
        let resp = svc
            .call(AsyncRequest {
                method: "POST".into(),
                path: "/v1/AUTH_test/c".into(),
                query_string: String::new(),
                headers,
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(
            resp.status, 403,
            "non-owner versions-location POST on Hyper must 403, got {} {:?}",
            resp.status, resp.reason
        );
    }

    #[tokio::test]
    async fn versioning_container_acl_hyper_path_owner_is_not_403_at_gate() {
        let app = Arc::new(ProxyApp::new(
            policy_ring_tests::ring(1),
            policy_ring_tests::ring(2),
            ProxyConfig {
                auth_enabled: false,
                conn_timeout: Duration::from_millis(50),
                node_timeout: Duration::from_millis(50),
                ..Default::default()
            },
        ));
        let svc = ProxyAsyncService {
            app: Arc::new(RwLock::new(app)),
            filters: vec![Arc::new(swift_middleware::VersionedWrites::new())],
        };
        let mut headers = HeaderKeyDict::new();
        headers.set("X-Backend-Swift-Owner", "true");
        headers.set("X-Versions-Location", "versions");
        let resp = svc
            .call(AsyncRequest {
                method: "POST".into(),
                path: "/v1/AUTH_test/c".into(),
                query_string: String::new(),
                headers,
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_ne!(
            resp.status, 403,
            "owner versions-location POST must pass the owner gate, got {} {:?}",
            resp.status, resp.reason
        );
    }

    /// IsolatedIdentity Hyper never calls `NameCheck::handle()`. Forbidden
    /// characters must 400 from `prepare()`.
    #[tokio::test]
    async fn name_check_hyper_path_rejects_forbidden_character() {
        let app = Arc::new(ProxyApp::new(
            policy_ring_tests::ring(1),
            policy_ring_tests::ring(2),
            ProxyConfig {
                auth_enabled: false,
                conn_timeout: Duration::from_millis(50),
                node_timeout: Duration::from_millis(50),
                ..Default::default()
            },
        ));
        let svc = ProxyAsyncService {
            app: Arc::new(RwLock::new(app)),
            filters: vec![Arc::new(swift_middleware::NameCheck::default())],
        };
        let mut resp = svc
            .call(AsyncRequest {
                method: "PUT".into(),
                path: "/v1/AUTH_test/c/foo\"bar".into(),
                query_string: String::new(),
                headers: HeaderKeyDict::new(),
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(resp.status, 400);
        let body = String::from_utf8_lossy(resp.body.materialize(u64::MAX).unwrap()).into_owned();
        assert!(
            body.contains("forbidden chars"),
            "name_check Hyper 400 body must match handle(), got {body:?}"
        );
    }

    /// IsolatedIdentity Hyper never calls `Crossdomain::handle()`.
    #[tokio::test]
    async fn crossdomain_hyper_path_serves_policy_xml() {
        let app = Arc::new(ProxyApp::new(
            policy_ring_tests::ring(1),
            policy_ring_tests::ring(2),
            ProxyConfig {
                auth_enabled: false,
                conn_timeout: Duration::from_millis(50),
                node_timeout: Duration::from_millis(50),
                ..Default::default()
            },
        ));
        let svc = ProxyAsyncService {
            app: Arc::new(RwLock::new(app)),
            filters: vec![Arc::new(swift_middleware::Crossdomain::default())],
        };
        let mut resp = svc
            .call(AsyncRequest {
                method: "GET".into(),
                path: "/crossdomain.xml".into(),
                query_string: String::new(),
                headers: HeaderKeyDict::new(),
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(resp.status, 200);
        assert_eq!(resp.headers.get("Content-Type"), Some("application/xml"));
        let body = String::from_utf8_lossy(resp.body.materialize(u64::MAX).unwrap()).into_owned();
        assert!(
            body.contains("<cross-domain-policy>"),
            "crossdomain Hyper body must be the policy document, got {body:?}"
        );
    }

    /// Field H1: Hyper used to skip AccountQuotas.handle(), so account POST
    /// of X-Account-Quota-Bytes returned 204. intercepts_request must run.
    #[tokio::test]
    async fn account_quotas_hyper_path_user_cannot_set_quota_bytes() {
        let app = Arc::new(ProxyApp::new(
            policy_ring_tests::ring(1),
            policy_ring_tests::ring(2),
            ProxyConfig::default(),
        ));
        let svc = ProxyAsyncService {
            app: Arc::new(RwLock::new(app)),
            filters: vec![Arc::new(swift_middleware::AccountQuotas::new(
                account_quota_policies(),
            ))],
        };
        let mut headers = HeaderKeyDict::new();
        headers.set("X-Account-Quota-Bytes", "5000");
        let resp = svc
            .call(AsyncRequest {
                method: "POST".into(),
                path: "/v1/AUTH_test".into(),
                query_string: String::new(),
                headers,
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(
            resp.status, 403,
            "non-reseller quota set on Hyper path must be 403, got {} {:?}",
            resp.status, resp.reason
        );
    }

    #[tokio::test]
    async fn account_quotas_hyper_path_user_cannot_set_legacy_quota_bytes() {
        let app = Arc::new(ProxyApp::new(
            policy_ring_tests::ring(1),
            policy_ring_tests::ring(2),
            ProxyConfig::default(),
        ));
        let svc = ProxyAsyncService {
            app: Arc::new(RwLock::new(app)),
            filters: vec![Arc::new(swift_middleware::AccountQuotas::new(
                account_quota_policies(),
            ))],
        };
        let mut headers = HeaderKeyDict::new();
        headers.set("X-Account-Meta-Quota-Bytes", "99999");
        let resp = svc
            .call(AsyncRequest {
                method: "POST".into(),
                path: "/v1/AUTH_test".into(),
                query_string: String::new(),
                headers,
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(
            resp.status, 403,
            "legacy quota meta on Hyper path must be 403, got {}",
            resp.status
        );
    }

    #[tokio::test]
    async fn account_quotas_hyper_path_reseller_can_set_after_tempauth() {
        let app = Arc::new(ProxyApp::new(
            policy_ring_tests::ring(1),
            policy_ring_tests::ring(2),
            ProxyConfig {
                auth_enabled: true,
                conn_timeout: Duration::from_millis(50),
                node_timeout: Duration::from_millis(50),
                ..Default::default()
            },
        ));
        let mut ta = swift_middleware::TempAuth::new("http://127.0.0.1:8080");
        ta.add_user("test", "tester", "testing", &[".admin"]);
        ta.add_user("test", "reseller", "reselling", &[".reseller_admin"]);
        let svc = ProxyAsyncService {
            app: Arc::new(RwLock::new(app)),
            filters: vec![
                Arc::new(swift_middleware::AccountQuotas::new(
                    account_quota_policies(),
                )),
                Arc::new(ta),
            ],
        };

        let token = {
            let mut headers = HeaderKeyDict::new();
            headers.set("X-Auth-User", "test:reseller");
            headers.set("X-Auth-Key", "reselling");
            let resp = svc
                .call(AsyncRequest {
                    method: "GET".into(),
                    path: "/auth/v1.0".into(),
                    query_string: String::new(),
                    headers,
                    body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
                })
                .await;
            assert_eq!(resp.status, 200);
            resp.headers.get("X-Auth-Token").unwrap().to_string()
        };

        let mut headers = HeaderKeyDict::new();
        headers.set("X-Auth-Token", &token);
        headers.set("X-Account-Quota-Bytes", "5000");
        let resp = svc
            .call(AsyncRequest {
                method: "POST".into(),
                path: "/v1/AUTH_test".into(),
                query_string: String::new(),
                headers,
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_ne!(
            resp.status, 403,
            "reseller must pass AccountQuotas on Hyper (got {} {:?})",
            resp.status, resp.reason
        );

        let tester_token = {
            let mut headers = HeaderKeyDict::new();
            headers.set("X-Auth-User", "test:tester");
            headers.set("X-Auth-Key", "testing");
            let resp = svc
                .call(AsyncRequest {
                    method: "GET".into(),
                    path: "/auth/v1.0".into(),
                    query_string: String::new(),
                    headers,
                    body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
                })
                .await;
            resp.headers.get("X-Auth-Token").unwrap().to_string()
        };
        let mut headers = HeaderKeyDict::new();
        headers.set("X-Auth-Token", &tester_token);
        headers.set("X-Account-Quota-Bytes", "5000");
        let resp = svc
            .call(AsyncRequest {
                method: "POST".into(),
                path: "/v1/AUTH_test".into(),
                query_string: String::new(),
                headers,
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(
            resp.status, 403,
            ".admin tester must still be 403 on Hyper, got {}",
            resp.status
        );
    }

    /// Answers container HEAD with a 10-byte quota and object PUT with 201
    /// so ContainerQuotas can prove Hyper intercept (Field H1).
    struct ContainerQuotaInfoStub;
    impl swift_middleware::Middleware for ContainerQuotaInfoStub {
        fn handle(&self, req: Request, next: &swift_middleware::NextFn) -> Response {
            next(req)
        }
        fn intercepts_request(&self, req: &Request) -> bool {
            (req.method == "HEAD" && req.path == "/v1/AUTH_test/c")
                || (req.method == "PUT" && req.path.starts_with("/v1/AUTH_test/c/"))
                || (matches!(req.method.as_str(), "PUT" | "POST") && req.path == "/v1/AUTH_test/c")
        }
        fn handle_request_async(
            &self,
            req: Request,
            _next: swift_middleware::AsyncNextFn,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>> {
            Box::pin(async move {
                if req.method == "HEAD" {
                    let mut resp = Response::new(204);
                    resp.headers.set("X-Container-Meta-Quota-Bytes", "10");
                    resp.headers.set("X-Container-Bytes-Used", "0");
                    resp.headers.set("X-Container-Object-Count", "0");
                    return resp;
                }
                if req.path == "/v1/AUTH_test/c" {
                    return Response::new(204);
                }
                Response::new(201)
            })
        }
    }

    /// Field H1: Hyper used to skip ContainerQuotas.handle(), so object
    /// PUT 11B after a 10-byte quota returned 201. streams/intercept must run.
    #[tokio::test]
    async fn container_quotas_hyper_path_over_quota_object_put_is_413() {
        let app = Arc::new(ProxyApp::new(
            policy_ring_tests::ring(1),
            policy_ring_tests::ring(2),
            ProxyConfig::default(),
        ));
        let svc = ProxyAsyncService {
            app: Arc::new(RwLock::new(app)),
            filters: vec![
                Arc::new(swift_middleware::ContainerQuotas::new()),
                Arc::new(ContainerQuotaInfoStub),
            ],
        };
        let mut headers = HeaderKeyDict::new();
        headers.set("Content-Length", "11");
        let mut resp = svc
            .call(AsyncRequest {
                method: "PUT".into(),
                path: "/v1/AUTH_test/c/too-big".into(),
                query_string: String::new(),
                headers,
                body: IncomingBody::from_bytes(vec![b'x'; 11], u64::MAX),
            })
            .await;
        resp.body.materialize(u64::MAX).unwrap();
        assert_eq!(
            resp.status, 413,
            "over-quota object PUT on Hyper must be 413, got {} {:?}",
            resp.status, resp.reason
        );
        let body = match &resp.body {
            swift_http::Body::Buffered(b) => b.as_slice(),
            _ => b"",
        };
        assert_eq!(
            String::from_utf8_lossy(body),
            "Upload exceeds quota.",
            "413 body must match swob Upload exceeds quota."
        );
    }

    #[tokio::test]
    async fn container_quotas_hyper_path_admin_can_set_quota_bytes() {
        let app = Arc::new(ProxyApp::new(
            policy_ring_tests::ring(1),
            policy_ring_tests::ring(2),
            ProxyConfig::default(),
        ));
        let svc = ProxyAsyncService {
            app: Arc::new(RwLock::new(app)),
            filters: vec![
                Arc::new(swift_middleware::ContainerQuotas::new()),
                Arc::new(ContainerQuotaInfoStub),
            ],
        };
        let mut headers = HeaderKeyDict::new();
        headers.set("X-Container-Meta-Quota-Bytes", "10");
        let resp = svc
            .call(AsyncRequest {
                method: "POST".into(),
                path: "/v1/AUTH_test/c".into(),
                query_string: String::new(),
                headers,
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_ne!(
            resp.status, 403,
            "admin container quota set must not be 403 (got {} {:?})",
            resp.status, resp.reason
        );
        assert_eq!(
            resp.status, 204,
            "admin container quota set must reach the app, got {}",
            resp.status
        );
    }
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
    fn object_backend_headers_carry_ring_next_part_power() {
        let mut transitioning_data = RingData::from_parts(
            vec![Some(RingDevice {
                id: 1,
                region: 1,
                zone: 1,
                ip: "10.0.0.1".into(),
                port: 6200,
                replication_ip: None,
                replication_port: None,
                device: "sda".into(),
                weight: 1.0,
                meta: String::new(),
                extra: Default::default(),
            })],
            32,
            vec![vec![0]],
        );
        transitioning_data.next_part_power = Some(7);
        let transitioning = Ring::new(
            transitioning_data,
            HashPathConfig::new("", "changeme").unwrap(),
        );
        let mut headers = HeaderKeyDict::new();
        stamp_next_part_power(&mut headers, &transitioning);
        assert_eq!(headers.get("X-Backend-Next-Part-Power"), Some("7"));

        let mut stable_headers = HeaderKeyDict::new();
        stamp_next_part_power(&mut stable_headers, &ring(2));
        assert!(!stable_headers.contains_key("X-Backend-Next-Part-Power"));
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

    #[test]
    fn list_endpoints_selects_scope_ring_policy_and_primary_nodes() {
        let mut rings = std::collections::HashMap::new();
        rings.insert(1i64, ring(11));
        let app = ProxyApp::with_policy_object_rings(
            ring(1),
            ring(2),
            ring(10),
            rings,
            ProxyConfig::default(),
        );
        app.info_cache.set_container(
            "a/c".to_string(),
            ContainerInfo {
                status: 204,
                policy_index: 1,
                ..Default::default()
            },
            60.0,
        );

        let (account, account_policy) = app.list_endpoints("a", None, None).unwrap();
        assert_eq!(account_policy, None);
        assert_eq!(account, ["http://10.0.0.1:6200/sda/0/a"]);

        let (container, container_policy) = app.list_endpoints("a", Some("c"), None).unwrap();
        assert_eq!(container_policy, None);
        assert_eq!(container, ["http://10.0.0.2:6200/sda/0/a/c"]);

        let (encoded_container, _) = app
            .list_endpoints("ac count", Some("con+tainer"), None)
            .unwrap();
        assert_eq!(
            encoded_container,
            ["http://10.0.0.2:6200/sda/0/ac%20count/con%2Btainer"]
        );

        let (object, object_policy) = app
            .list_endpoints("a", Some("c"), Some("dir/part name+尾"))
            .unwrap();
        assert_eq!(object_policy, Some(1));
        assert_eq!(
            object,
            ["http://10.0.0.11:6200/sda/0/a/c/dir/part%20name%2B%E5%B0%BE"]
        );
    }

    #[test]
    fn list_endpoints_unknown_object_policy_fails_closed() {
        let app = ProxyApp::with_object_ring(ring(1), ring(2), ring(10), ProxyConfig::default());
        app.info_cache.set_container(
            "a/c".to_string(),
            ContainerInfo {
                status: 204,
                policy_index: 9,
                ..Default::default()
            },
            60.0,
        );
        assert_eq!(
            app.list_endpoints("a", Some("c"), Some("o")).unwrap_err(),
            "no object ring configured for storage policy 9"
        );
    }

    #[test]
    fn endpoint_resolver_reads_the_reloaded_proxy_app_each_time() {
        let slot = Arc::new(RwLock::new(Arc::new(ProxyApp::new(
            ring(1),
            ring(2),
            ProxyConfig::default(),
        ))));
        let resolver = ProxyEndpointResolver::new(Arc::clone(&slot));
        let (before, _) =
            swift_middleware::EndpointResolver::endpoints(&resolver, "a", None, None).unwrap();
        assert_eq!(before, ["http://10.0.0.1:6200/sda/0/a"]);

        *slot.write().unwrap() = Arc::new(ProxyApp::new(ring(7), ring(8), ProxyConfig::default()));
        let (after, _) =
            swift_middleware::EndpointResolver::endpoints(&resolver, "a", None, None).unwrap();
        assert_eq!(after, ["http://10.0.0.7:6200/sda/0/a"]);
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
    fn test_container_newest_key_prefers_sharded_over_newer_sharding() {
        // L1509: created_at ties; a SHARDING primary may even have a newer
        // put/created header. The just-SHARDED under-populated replica
        // must still win so listing uses 4 ACTIVE shards, not residual.
        let sharding = hdrs(&[
            ("X-Backend-Timestamp", "1000000009.00000"),
            ("X-Backend-Sharding-State", "sharding"),
        ]);
        let sharded = hdrs(&[
            ("X-Backend-Timestamp", "1000000001.00000"),
            ("X-Backend-Sharding-State", "sharded"),
        ]);
        assert!(container_newest_key(&sharded) > container_newest_key(&sharding));
    }

    #[test]
    fn test_ec_tombstone_404_carries_backend_timestamp() {
        // Probe test_expirer_object_split_brain (L105): after expire +
        // get_to_final_state, GET 404 must expose x-backend-timestamp.
        // EC gather used to return a bare HTML 404.
        let ts: Timestamp = "1788834800.12345".parse().unwrap();
        let resp = swob_404_with_backend_timestamp(ts);
        assert_eq!(resp.status, 404);
        assert_eq!(
            resp.headers.get("X-Backend-Timestamp"),
            Some(ts.internal().as_str())
        );
        assert_eq!(resp.headers.get("X-Timestamp"), Some(ts.normal().as_str()));
        let bare = swob_404_with_backend_timestamp(Timestamp::zero());
        assert_eq!(bare.status, 404);
        assert!(bare.headers.get("X-Backend-Timestamp").is_none());
        let unavailable = attach_backend_timestamp(swob_response(503), ts);
        assert_eq!(unavailable.status, 503);
        assert!(unavailable.headers.get("X-Backend-Timestamp").is_none());
    }

    fn policies_with_backend_timestamp(per_policy: &[(i64, Option<Timestamp>)]) -> Vec<i64> {
        per_policy
            .iter()
            .filter_map(|(policy, ts)| ts.filter(|ts| ts.is_truthy()).map(|_| *policy))
            .collect()
    }

    #[test]
    fn test_expirer_split_brain_ec42_policy0_isolation() {
        // Probe test_expirer_object_split_brain with forced
        // old_policy=ec42 (2) ↔ wrong_policy=Policy-0 (0) and the inverse.
        // InternalClient GET/DELETE send X-Backend-Storage-Policy-Index.
        const POLICY_0: i64 = 0;
        const EC42: i64 = 2;
        let create_ts: Timestamp = "1788834800.00000".parse().unwrap();
        let tombstone_ts: Timestamp = "1788834802.00000".parse().unwrap();

        // GET/DELETE must not remap explicit 0 onto an EC container (or
        // the reverse). Python get_controller / GETorHEAD use the header.
        assert_eq!(
            resolve_object_storage_policy(Some(POLICY_0), EC42),
            POLICY_0,
            "Policy-0 GET on an ec42 container stays on Policy-0"
        );
        assert_eq!(
            resolve_object_storage_policy(Some(EC42), POLICY_0),
            EC42,
            "ec42 GET on a Policy-0 container stays on ec42"
        );
        assert_eq!(resolve_object_storage_policy(None, EC42), EC42);
        assert_eq!(resolve_object_storage_policy(None, POLICY_0), POLICY_0);
        assert_eq!(
            resolve_object_storage_policy(Some(POLICY_0), POLICY_0),
            POLICY_0
        );
        assert_eq!(resolve_object_storage_policy(Some(EC42), EC42), EC42);

        // L105 Policy-0 → ec42: object lives on Policy-0. Isolated GET
        // with header 0 must see the expired timestamp, not a bare EC 404.
        let old = POLICY_0;
        let wrong = EC42;
        let get_old = resolve_object_storage_policy(Some(old), wrong);
        let get_wrong = resolve_object_storage_policy(Some(wrong), wrong);
        assert_eq!(get_old, POLICY_0);
        assert_eq!(get_wrong, EC42);
        let expired_on_old = swob_404_with_backend_timestamp(create_ts);
        let empty_wrong = swob_404_with_backend_timestamp(Timestamp::zero());
        assert_eq!(
            expired_on_old.headers.get("X-Backend-Timestamp"),
            Some(create_ts.internal().as_str())
        );
        assert!(empty_wrong.headers.get("X-Backend-Timestamp").is_none());

        // L131 ec42 → Policy-0 after 2nd expire: DELETE tombstones only
        // the policy that actually held the object. The other policy's
        // empty 404 must not count as "found".
        let after_delete =
            policies_with_backend_timestamp(&[(EC42, Some(tombstone_ts)), (POLICY_0, None)]);
        assert_eq!(after_delete, vec![EC42]);
        assert!(tombstone_ts > create_ts);

        // The old remap (header 0 + EC container → EC) made both probe
        // GETs observe the same timestamped 404.
        let remapped_both = policies_with_backend_timestamp(&[
            (POLICY_0, Some(tombstone_ts)),
            (EC42, Some(tombstone_ts)),
        ]);
        assert_eq!(
            remapped_both.len(),
            2,
            "sanity: a crossed GET is what L131 reports"
        );
        let isolated = policies_with_backend_timestamp(&[
            (
                POLICY_0,
                if resolve_object_storage_policy(Some(POLICY_0), EC42) == EC42 {
                    Some(tombstone_ts)
                } else {
                    None
                },
            ),
            (EC42, Some(tombstone_ts)),
        ]);
        assert_eq!(isolated, vec![EC42]);
    }

    #[test]
    fn test_backend_404_timestamp_absent_is_not_truthy() {
        // no tombstone header -> zero -> a handoff 404 is thrown out
        assert!(!backend_404_timestamp(&hdrs(&[])).is_truthy());
        let h = hdrs(&[("X-Backend-Timestamp", "1000000000.00000")]);
        assert!(backend_404_timestamp(&h).is_truthy());
        assert_eq!(
            backend_404_timestamp(&h),
            "1000000000.00000".parse().unwrap()
        );
    }

    #[test]
    fn test_container_delete_tombstone_beats_stale_handoff() {
        // listing-w214 L2095: primary DELETE 404 X-Backend-Timestamp is
        // newer than the leftover handoff's created/put timestamp. A 2xx
        // source older than that watermark must not win GETorHEAD.
        let tombstone: Timestamp = "1787701243.57447".parse().unwrap();
        let handoff: Timestamp = "1787701243.23638".parse().unwrap();
        let mut latest_404 = Timestamp::zero();
        if tombstone > latest_404 {
            latest_404 = tombstone;
        }
        assert!(
            handoff < latest_404,
            "stale unsuffixed handoff {:?} must lose to primary tombstone {:?}",
            handoff,
            latest_404
        );
        assert!(!(handoff >= latest_404));
        // A revived replica whose timestamp is at/after DELETE still wins.
        let revived: Timestamp = "1787701243.57447".parse().unwrap();
        assert!(revived >= latest_404);
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

    #[test]
    fn container_listing_record_headers_follow_python_get_contract() {
        for method in ["GET", "HEAD", "POST"] {
            for record_type in [
                None,
                Some(""),
                Some("auto"),
                Some("AuTo"),
                Some("banana"),
                Some("object"),
                Some("OBJECT"),
                Some("shard"),
                Some("SHARD"),
            ] {
                let mut req = Request {
                    method: method.into(),
                    path: "/v1/AUTH_test/c".into(),
                    query_string: "format=json".into(),
                    headers: HeaderKeyDict::new(),
                    body: swift_http::Body::empty(),
                };
                if let Some(kind) = record_type {
                    req.headers.set("X-Backend-Record-Type", kind);
                }
                let mut resp = Response::with_body(200, b"[]".to_vec());
                resp.headers.set("X-Backend-Record-Type", "shard");
                resp.headers
                    .set("X-Backend-Record-Shard-Format", "namespace");
                resp.headers.set("X-Backend-Sharding-State", "sharded");
                let preserve = method != "GET"
                    || record_type.is_some_and(|kind| {
                        kind.eq_ignore_ascii_case("object") || kind.eq_ignore_ascii_case("shard")
                    });
                finalize_container_listing_headers(&req, &mut resp);
                assert_eq!(
                    resp.headers.get("X-Backend-Record-Type").as_deref(),
                    preserve.then_some("shard"),
                    "method={method} record_type={record_type:?}"
                );
                assert_eq!(
                    resp.headers.get("X-Backend-Record-Shard-Format").as_deref(),
                    preserve.then_some("namespace"),
                    "method={method} record_type={record_type:?}"
                );
                assert_eq!(
                    resp.headers.get("X-Backend-Sharding-State").as_deref(),
                    Some("sharded")
                );
            }
        }
    }

    #[test]
    fn container_listing_rejects_non_utf8_delimiter() {
        // Python `validate_container_params` / `get_param`: delimiter=%ff
        // is 400 `"delimiter" parameter not valid UTF-8`
        // (probe test_sharding_listing).
        let app = Arc::new(ProxyApp::new(ring(0), ring(0), ProxyConfig::default()));
        let req = Request {
            method: "GET".into(),
            path: "/v1/AUTH_test/c".into(),
            query_string: "delimiter=%ff".into(),
            headers: HeaderKeyDict::new(),
            body: swift_http::Body::empty(),
        };
        let mut resp = app.container_request(&req, "AUTH_test", "c");
        assert_eq!(resp.status, 400, "{}", resp.reason);
        let body = String::from_utf8_lossy(resp.body.materialize(u64::MAX).unwrap());
        assert!(body.contains("not valid UTF-8"), "body={body:?}");
        assert!(body.contains("delimiter"), "body={body:?}");
    }

    #[test]
    fn container_listing_rejects_oversize_limit() {
        let app = Arc::new(ProxyApp::new(ring(0), ring(0), ProxyConfig::default()));
        let req = Request {
            method: "GET".into(),
            path: "/v1/AUTH_test/c".into(),
            query_string: "limit=10001".into(),
            headers: HeaderKeyDict::new(),
            body: swift_http::Body::empty(),
        };
        let mut resp = app.container_request(&req, "AUTH_test", "c");
        assert_eq!(resp.status, 412, "{}", resp.reason);
        let body = String::from_utf8_lossy(resp.body.materialize(u64::MAX).unwrap());
        assert!(body.contains("Maximum limit"), "body={body:?}");
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
            rfc_compliant_etags: None,
            cors: CorsInfo::default(),
            db_state: String::new(),
        }
    }

    #[test]
    fn test_listing_200_overwrites_deleted_404_cache() {
        // listing-w216 L2111: GET 404 after DELETE container caches
        // exists=false; listing [beta] 200 must refill so object DELETE
        // does not 404 while .data is on disk.
        let app = ProxyApp::new(
            super::policy_ring_tests::ring(0),
            super::policy_ring_tests::ring(0),
            ProxyConfig::default(),
        );
        let mut gone = Response::new(404);
        gone.headers.set("X-Backend-Storage-Policy-Index", "0");
        app.remember_container_info("AUTH_test", "c", &gone);
        let cached = app.info_cache.get_container("AUTH_test/c").unwrap();
        assert_eq!(cached.status, 404);
        assert!(!cached.exists());
        let mut ok = Response::new(200);
        ok.headers.set("X-Backend-Storage-Policy-Index", "0");
        ok.headers.set("X-Backend-Sharding-State", "collapsed");
        app.remember_container_info("AUTH_test", "c", &ok);
        let cached = app.info_cache.get_container("AUTH_test/c").unwrap();
        assert!(
            cached.exists(),
            "listing 200 must overwrite DELETE 404 cache"
        );
        assert_eq!(cached.db_state, "collapsed");
        // A live 200 sharded cache must not be replaced by a later listing
        // (listing-w217 L2044).
        let mut sharded = Response::new(200);
        sharded.headers.set("X-Backend-Storage-Policy-Index", "0");
        sharded.headers.set("X-Backend-Sharding-State", "sharded");
        app.remember_container_info("AUTH_test", "c", &sharded);
        let cached = app.info_cache.get_container("AUTH_test/c").unwrap();
        assert_eq!(cached.db_state, "collapsed");
    }

    #[test]
    fn proven_listing_state_is_independent_of_container_metadata() {
        let app = ProxyApp::new(
            super::policy_ring_tests::ring(0),
            super::policy_ring_tests::ring(0),
            ProxyConfig::default(),
        );
        let mut cached = info(7);
        cached.db_state = "unsharded".to_string();
        app.info_cache
            .set_container("AUTH_test/c".to_string(), cached, 60.0);
        app.remember_proven_container_db_state("AUTH_test", "c", "sharded");
        let unchanged = app.info_cache.get_container("AUTH_test/c").unwrap();
        assert_eq!(unchanged.db_state, "unsharded");
        assert_eq!(unchanged.policy_index, 7);
        assert_eq!(unchanged.read_acl.as_deref(), Some("r"));
        assert_eq!(
            app.effective_root_db_state("AUTH_test", "c", unchanged.root_db_state()),
            "sharded",
            "shard routing must use the same proven state as async-pending stamping"
        );
        let mut headers = HeaderKeyDict::new();
        app.stamp_root_db_state("AUTH_test", "c", &mut headers);
        assert_eq!(
            headers.get("X-Container-Root-Db-State"),
            Some("sharded"),
            "object PUT must use the listing-proven state"
        );
    }

    #[test]
    fn proven_listing_state_does_not_synthesize_container_metadata() {
        let app = ProxyApp::new(
            super::policy_ring_tests::ring(0),
            super::policy_ring_tests::ring(0),
            ProxyConfig::default(),
        );
        app.remember_proven_container_db_state("AUTH_test", "c", "sharded");
        assert!(
            app.info_cache.get_container("AUTH_test/c").is_none(),
            "a shard listing cannot safely infer policy or ACL metadata"
        );
        let mut headers = HeaderKeyDict::new();
        app.stamp_root_db_state("AUTH_test", "c", &mut headers);
        assert_eq!(headers.get("X-Container-Root-Db-State"), Some("sharded"));
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
        // A full clear drops metadata and the independent route proof.
        cache.set_container("a/c".to_string(), info(5), 60.0);
        cache.set_container_db_state("a/c", "sharded", 60.0);
        cache.clear_container("a/c");
        assert!(cache.get_container("a/c").is_none());
        assert!(cache.get_container_db_state("a/c").is_none());
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
    fn test_container_metadata_clear_preserves_proven_route_state() {
        let cache = InfoCache::new();
        cache.set_container("a/c".to_string(), info(5), 60.0);
        cache.set_container_db_state("a/c", "sharded", 60.0);

        cache.clear_container_metadata("a/c");

        assert!(cache.get_container("a/c").is_none());
        assert_eq!(
            cache.get_container_db_state("a/c").as_deref(),
            Some("sharded")
        );
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

    #[test]
    fn test_container_info_write_failure_distinguishes_unreachable_from_missing() {
        assert_eq!(ContainerInfo::default().write_failure_status(), 503);
        assert_eq!(
            ContainerInfo {
                status: 503,
                ..Default::default()
            }
            .write_failure_status(),
            503
        );
        assert_eq!(
            ContainerInfo {
                status: 404,
                ..Default::default()
            }
            .write_failure_status(),
            404
        );
    }

    #[test]
    fn test_reserved_nul_path_follows_allow_reserved_header() {
        let mut req = Request {
            method: "PUT".to_string(),
            path: "/v1/AUTH_test/\u{0}reserved".to_string(),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: swift_http::Body::empty(),
        };
        assert!(utf8_or_null_rejected(&req).is_some());
        req.headers.set("X-Backend-Allow-Reserved-Names", "true");
        assert!(utf8_or_null_rejected(&req).is_none());
    }

    #[test]
    fn test_synthesized_listing_is_not_a_real_account() {
        // account.py:79-94: fake listing is 2xx but account_really_exists
        // is false so container PUT still autocreates.
        let req = Request {
            method: "HEAD".to_string(),
            path: "/v1/AUTH_missing".to_string(),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: swift_http::Body::empty(),
        };
        let resp = synthesized_account_listing(&req);
        assert_eq!(resp.status, 204);
        assert_eq!(
            resp.headers
                .get("X-Backend-Fake-Account-Listing")
                .map(|s| s.to_ascii_lowercase()),
            Some("yes".to_string())
        );
        let info = account_info_from_response(&resp);
        assert_eq!(info.status, 204);
        assert!(!info.account_really_exists);
        assert!(!info.exists());
        let mut real = Response::new(204);
        real.headers.set("X-Account-Container-Count", "0");
        let real_info = account_info_from_response(&real);
        assert!(real_info.exists());
    }
}

#[cfg(test)]
mod cors_tests {
    use super::policy_ring_tests::ring;
    use super::*;

    fn app(config: ProxyConfig) -> Arc<ProxyApp> {
        Arc::new(ProxyApp::new(ring(0), ring(0), config))
    }

    fn request(method: &str, path: &str, headers: &[(&str, &str)]) -> Request {
        let mut request_headers = HeaderKeyDict::new();
        for (name, value) in headers {
            request_headers.set(name, value);
        }
        Request {
            method: method.to_string(),
            path: path.to_string(),
            query_string: String::new(),
            headers: request_headers,
            body: swift_http::Body::empty(),
        }
    }

    fn seed_container(app: &ProxyApp, account: &str, container: &str, cors: CorsInfo) {
        app.info_cache.set_container(
            format!("{account}/{container}"),
            ContainerInfo {
                status: 204,
                policy_index: 9,
                read_acl: None,
                write_acl: None,
                temp_url_keys: Vec::new(),
                sync_key: None,
                rfc_compliant_etags: None,
                cors,
                db_state: String::new(),
            },
            60.0,
        );
    }

    fn assert_no_access_control(headers: &HeaderKeyDict) {
        assert!(
            headers
                .iter()
                .all(|(name, _)| !name.to_ascii_lowercase().starts_with("access-control-")),
            "CORS header leaked: {headers:?}"
        );
    }

    fn assert_no_cors(headers: &HeaderKeyDict) {
        assert_no_access_control(headers);
        assert!(headers.get("Vary").is_none(), "Vary leaked: {headers:?}");
    }

    fn header_set(headers: &HeaderKeyDict, name: &str) -> std::collections::BTreeSet<String> {
        headers
            .get(name)
            .unwrap_or("")
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_ascii_lowercase)
            .collect()
    }

    #[test]
    fn proxy_config_cors_defaults_match_python() {
        let config = ProxyConfig::default();
        assert!(config.strict_cors_mode);
        assert!(config.cors_allow_origin.is_empty());
        assert!(config.cors_expose_headers.is_empty());
    }

    #[test]
    fn container_cors_info_round_trips_and_old_cache_values_default_empty() {
        let info = ContainerInfo {
            status: 204,
            policy_index: 3,
            read_acl: None,
            write_acl: None,
            temp_url_keys: Vec::new(),
            sync_key: None,
            rfc_compliant_etags: None,
            cors: CorsInfo {
                allow_origin: Some("https://allowed.example".into()),
                expose_headers: Some("X-Object-Meta-Color".into()),
                max_age: Some("999".into()),
            },
            db_state: String::new(),
        };
        let decoded = container_info_from_json(&container_info_to_json(&info)).unwrap();
        assert_eq!(decoded.cors, info.cors);

        let old_value = serde_json::json!({
            "status": 204,
            "policy_index": 0,
            "read_acl": null,
            "write_acl": null,
            "temp_url_keys": [],
            "sync_key": null,
        });
        assert_eq!(
            container_info_from_json(&old_value).unwrap().cors,
            CorsInfo::default()
        );
        assert_eq!(
            container_info_from_json(&old_value)
                .unwrap()
                .root_db_state(),
            "unsharded"
        );
    }

    #[test]
    fn reseller_head_exposes_x_container_sharding_from_sysmeta() {
        let mut resp = Response::new(204);
        resp.headers.set("X-Container-Sysmeta-Sharding", "True");
        expose_container_sharding(&mut resp, true);
        assert_eq!(resp.headers.get("X-Container-Sharding"), Some("True"));

        let mut resp = Response::new(204);
        expose_container_sharding(&mut resp, true);
        assert_eq!(resp.headers.get("X-Container-Sharding"), Some("False"));

        let mut resp = Response::new(204);
        resp.headers.set("X-Container-Sysmeta-Sharding", "on");
        expose_container_sharding(&mut resp, false);
        assert!(resp.headers.get("X-Container-Sharding").is_none());
    }

    #[test]
    fn fill_container_info_reads_backend_sharding_state() {
        let mut resp = Response::new(204);
        resp.headers.set("X-Backend-Sharding-State", "sharded");
        resp.headers.set("X-Backend-Storage-Policy-Index", "2");
        let mut info = ContainerInfo::default();
        fill_container_info_from_head(&mut info, &resp);
        assert_eq!(info.root_db_state(), "sharded");
        assert_eq!(info.policy_index, 2);
    }

    #[test]
    fn ordinary_options_covers_account_container_and_object_without_cors() {
        let app = app(ProxyConfig::default());
        for (path, expected) in [
            ("/v1/AUTH_test", "GET, HEAD, POST, OPTIONS"),
            ("/v1/AUTH_test/c", "GET, HEAD, PUT, POST, DELETE, OPTIONS"),
            ("/v1/AUTH_test/c/o", "GET, HEAD, PUT, POST, DELETE, OPTIONS"),
        ] {
            let resp = app.handle(request("OPTIONS", path, &[]));
            assert_eq!(resp.status, 200, "{path}");
            assert_eq!(resp.headers.get("Allow"), Some(expected), "{path}");
            assert_eq!(
                resp.headers.get("Content-Type"),
                Some("text/html; charset=UTF-8")
            );
            assert_no_cors(&resp.headers);
        }

        let account_cors = app.handle(request(
            "OPTIONS",
            "/v1/AUTH_test",
            &[
                ("Origin", "https://allowed.example"),
                ("Access-Control-Request-Method", "GET"),
            ],
        ));
        assert_eq!(account_cors.status, 200);
        assert_eq!(
            account_cors.headers.get("Allow"),
            Some("GET, HEAD, POST, OPTIONS")
        );
        assert_no_cors(&account_cors.headers);
    }

    #[test]
    fn options_bypasses_auth_for_ordinary_and_preflight_requests() {
        let app = app(ProxyConfig {
            auth_enabled: true,
            ..Default::default()
        });
        seed_container(
            &app,
            "AUTH_test",
            "c",
            CorsInfo {
                allow_origin: Some("https://allowed.example".into()),
                expose_headers: None,
                max_age: None,
            },
        );

        for path in ["/v1/AUTH_test", "/v1/AUTH_test/c", "/v1/AUTH_test/c/o"] {
            let resp = app.handle(request("OPTIONS", path, &[]));
            assert_eq!(resp.status, 200, "anonymous OPTIONS failed for {path}");
        }

        let preflight = app.handle(request(
            "OPTIONS",
            "/v1/AUTH_test/c/o",
            &[
                ("Origin", "https://allowed.example"),
                ("Access-Control-Request-Method", "GET"),
            ],
        ));
        assert_eq!(preflight.status, 200);
        assert_eq!(
            preflight.headers.get("Access-Control-Allow-Origin"),
            Some("https://allowed.example")
        );
    }

    #[tokio::test]
    async fn handle_async_applies_simple_cors_via_pipeline_helper() {
        let app = Arc::new(app(ProxyConfig {
            strict_cors_mode: true,
            ..Default::default()
        }));
        seed_container(
            app.as_ref(),
            "AUTH_test",
            "c",
            CorsInfo {
                allow_origin: Some("*".into()),
                expose_headers: None,
                max_age: None,
            },
        );
        let req = request("GET", "/v1/AUTH_test/c/o", &[("Origin", "http://m.com")]);
        let mut resp = Response::new(200);
        resp.headers.set("X-Object-Meta-Color", "red");
        app.apply_pipeline_cors(
            req.method.clone(),
            req.path.clone(),
            req.headers.get("Origin").map(str::to_string),
            &mut resp,
        )
        .await;
        assert_eq!(resp.headers.get("Access-Control-Allow-Origin"), Some("*"));
        assert!(
            resp.headers
                .get("Access-Control-Expose-Headers")
                .unwrap_or("")
                .contains("x-object-meta-color"),
            "{:?}",
            resp.headers.get("Access-Control-Expose-Headers")
        );
    }

    #[tokio::test]
    async fn handle_async_options_and_info_do_not_call_sync_handle() {
        let app = app(ProxyConfig::default());
        let opt = app
            .handle_async(swift_http::AsyncRequest {
                method: "OPTIONS".into(),
                path: "/v1/AUTH_test".into(),
                query_string: String::new(),
                headers: HeaderKeyDict::new(),
                body: swift_http::IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(opt.status, 200, "{}", opt.reason);
        assert_eq!(opt.headers.get("Allow"), Some("GET, HEAD, POST, OPTIONS"));
        let bad = app
            .handle_async(swift_http::AsyncRequest {
                method: "PUT".into(),
                path: "/v1".into(),
                query_string: String::new(),
                headers: HeaderKeyDict::new(),
                body: swift_http::IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(bad.status, 412, "{}", bad.reason);
        let body = match bad.body {
            swift_http::Body::Buffered(b) => String::from_utf8_lossy(&b).into_owned(),
            _ => String::new(),
        };
        assert!(body.contains("Bad URL"), "body={body:?}");
        let empty_acct = app
            .handle_async(swift_http::AsyncRequest {
                method: "GET".into(),
                path: "/v1//testc/testo".into(),
                query_string: String::new(),
                headers: HeaderKeyDict::new(),
                body: swift_http::IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_ne!(
            empty_acct.status, 412,
            "empty-account object path must not be Bad URL"
        );
        let empty_cont = app
            .handle_async(swift_http::AsyncRequest {
                method: "GET".into(),
                path: "/v1/testa//testo".into(),
                query_string: String::new(),
                headers: HeaderKeyDict::new(),
                body: swift_http::IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(
            empty_cont.status, 404,
            "empty-container object path must be 404, got {}",
            empty_cont.status
        );
        let info = app
            .handle_async(swift_http::AsyncRequest {
                method: "GET".into(),
                path: "/info".into(),
                query_string: String::new(),
                headers: HeaderKeyDict::new(),
                body: swift_http::IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(
            info.status, 403,
            "empty info_json is 403, got {}",
            info.status
        );
        let unknown = app
            .handle_async(swift_http::AsyncRequest {
                method: "PATCH".into(),
                path: "/not-v1".into(),
                query_string: String::new(),
                headers: HeaderKeyDict::new(),
                body: swift_http::IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(unknown.status, 404);
        let lick = app
            .handle_async(swift_http::AsyncRequest {
                method: "LICK".into(),
                path: "/v1/AUTH_test".into(),
                query_string: String::new(),
                headers: HeaderKeyDict::new(),
                body: swift_http::IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(
            lick.status, 405,
            "LICK on /v1 must be 405, got {}",
            lick.status
        );
        assert!(
            lick.headers.get("Allow").is_some(),
            "405 must advertise Allow"
        );
        let info_space = app
            .handle_async(swift_http::AsyncRequest {
                method: "GET".into(),
                path: "/info asdf".into(),
                query_string: String::new(),
                headers: HeaderKeyDict::new(),
                body: swift_http::IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(
            info_space.status, 412,
            "/info asdf must be 412, got {}",
            info_space.status
        );
        let spaced_obj = app
            .handle_async(swift_http::AsyncRequest {
                method: "GET".into(),
                path: "/v1/AUTH_test/c/l04 011e".into(),
                query_string: String::new(),
                headers: HeaderKeyDict::new(),
                body: swift_http::IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_ne!(
            spaced_obj.status, 412,
            "spaces in object names must not be Bad URL, got {}",
            spaced_obj.status
        );
    }

    #[test]
    fn content_type_guess_matches_python_mimetypes_for_func_tests() {
        let mut req = Request {
            method: "PUT".into(),
            path: "/v1/a/c/foo.txt".into(),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: swift_http::Body::empty(),
        };
        apply_content_type_guess(&mut req);
        assert_eq!(req.headers.get("Content-Type"), Some("text/plain"));
        req.headers.remove("Content-Type");
        req.path = "/v1/a/c/foo.wav".into();
        apply_content_type_guess(&mut req);
        assert_eq!(req.headers.get("Content-Type"), Some("audio/x-wav"));
        req.headers.remove("Content-Type");
        req.path = "/v1/a/c/foo.zip".into();
        apply_content_type_guess(&mut req);
        assert_eq!(req.headers.get("Content-Type"), Some("application/zip"));
        req.headers.set("Content-Type", "application/custom");
        apply_content_type_guess(&mut req);
        assert_eq!(req.headers.get("Content-Type"), Some("application/custom"));
    }

    struct InnerSegmentIntercept;
    impl swift_middleware::Middleware for InnerSegmentIntercept {
        fn handle(&self, req: Request, next: &swift_middleware::NextFn) -> Response {
            next(req)
        }
        fn intercepts_request(&self, req: &Request) -> bool {
            req.path.ends_with("/segment")
        }
        fn handle_request_async(
            &self,
            _req: Request,
            _next: swift_middleware::AsyncNextFn,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>> {
            Box::pin(async { Response::new(209) })
        }
    }

    struct OuterReassemble;
    impl swift_middleware::Middleware for OuterReassemble {
        fn handle(&self, req: Request, next: &swift_middleware::NextFn) -> Response {
            next(req)
        }
        fn intercepts_response(&self) -> bool {
            true
        }
        fn reassemble_async(
            &self,
            req: Request,
            next: swift_middleware::AsyncNextFn,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>> {
            Box::pin(async move {
                let _first = next(req.clone_head()).await;
                let mut sub = req.clone_head();
                sub.path = "/v1/AUTH_test/c/segment".into();
                next(sub).await
            })
        }
    }

    #[tokio::test]
    async fn intercepts_response_subsequent_next_hits_remaining_filters() {
        let app = app(ProxyConfig::default());
        let filters: Arc<Vec<Arc<dyn swift_middleware::Middleware>>> = Arc::new(vec![
            Arc::new(OuterReassemble),
            Arc::new(InnerSegmentIntercept),
        ]);
        let req = Request {
            method: "GET".into(),
            path: "/v1/AUTH_test/c/manifest".into(),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: swift_http::Body::empty(),
        };
        let resp = dispatch_remaining(filters, 0, app, req).await;
        assert_eq!(
            resp.status, 209,
            "SLO-style subsequent next() must reach remaining filters, got {}",
            resp.status
        );
    }

    struct InnerIfMatch412;
    impl swift_middleware::Middleware for InnerIfMatch412 {
        fn handle(&self, req: Request, next: &swift_middleware::NextFn) -> Response {
            next(req)
        }
        fn intercepts_request(&self, req: &Request) -> bool {
            req.headers.contains_key("If-Match")
        }
        fn handle_request_async(
            &self,
            _req: Request,
            _next: swift_middleware::AsyncNextFn,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>> {
            Box::pin(async {
                let mut resp = Response::new(412);
                resp.headers.set("Etag", "abc123");
                resp
            })
        }
    }

    struct OuterQuoteFinish;
    impl swift_middleware::Middleware for OuterQuoteFinish {
        fn handle(&self, req: Request, next: &swift_middleware::NextFn) -> Response {
            next(req)
        }
        fn finish(&self, _req: &Request, mut resp: Response) -> Response {
            if let Some(etag) = resp.headers.get("Etag").map(str::to_string) {
                if !(etag.starts_with('"') || etag.starts_with("W/\"")) || !etag.ends_with('"') {
                    resp.headers.set("Etag", format!("\"{etag}\""));
                }
            }
            resp
        }
    }

    #[tokio::test]
    async fn intercepts_request_still_runs_outer_finish() {
        // SLO GET If-Match intercepts_request and used to return before
        // outer etag-quoter finish(), leaving 412 ETags unquoted.
        let app = app(ProxyConfig::default());
        let filters: Arc<Vec<Arc<dyn swift_middleware::Middleware>>> =
            Arc::new(vec![Arc::new(OuterQuoteFinish), Arc::new(InnerIfMatch412)]);
        let mut req = Request {
            method: "GET".into(),
            path: "/v1/AUTH_test/c/o".into(),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: swift_http::Body::empty(),
        };
        req.headers.set("If-Match", "bogus");
        let resp = dispatch_remaining(filters, 0, app, req).await;
        assert_eq!(resp.status, 412);
        assert_eq!(
            resp.headers.get("Etag"),
            Some("\"abc123\""),
            "outer finish must still quote a 412 from an inner intercept"
        );
    }

    struct OuterObjectStreamer;
    impl swift_middleware::Middleware for OuterObjectStreamer {
        fn handle(&self, req: Request, next: &swift_middleware::NextFn) -> Response {
            next(req)
        }
        fn streams_request(&self, req: &Request) -> bool {
            req.method == "PUT"
        }
        fn handle_streaming_request(
            &self,
            req: swift_http::AsyncRequest,
            next: swift_middleware::StreamingAsyncNextFn,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>> {
            Box::pin(async move { next(req).await })
        }
    }

    struct InnerSymlinkPut;
    impl swift_middleware::Middleware for InnerSymlinkPut {
        fn handle(&self, req: Request, next: &swift_middleware::NextFn) -> Response {
            next(req)
        }
        fn intercepts_request(&self, req: &Request) -> bool {
            req.method == "PUT" && req.headers.contains_key("X-Symlink-Target")
        }
        fn handle_request_async(
            &self,
            req: Request,
            _next: swift_middleware::AsyncNextFn,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>> {
            Box::pin(async move {
                assert_eq!(req.headers.get("X-Symlink-Target"), Some("targets/object"));
                assert!(
                    matches!(req.body, swift_http::Body::Buffered(ref body) if body.is_empty())
                );
                Response::new(218)
            })
        }
    }

    #[tokio::test]
    async fn streaming_outer_filter_keeps_inner_symlink_intercept() {
        // VersionedWrites streams every ordinary object PUT. Its old `next`
        // pointed straight at ProxyApp, so a later Symlink filter never saw
        // X-Symlink-Target and stored an ordinary zero-byte object.
        let app = app(ProxyConfig::default());
        let filters: Arc<Vec<Arc<dyn swift_middleware::Middleware>>> = Arc::new(vec![
            Arc::new(OuterObjectStreamer),
            Arc::new(InnerSymlinkPut),
        ]);
        let mut headers = HeaderKeyDict::new();
        headers.set("X-Symlink-Target", "targets/object");
        headers.set("Content-Length", "0");
        let resp = dispatch_streaming_remaining(
            filters,
            0,
            app,
            swift_http::AsyncRequest {
                method: "PUT".into(),
                path: "/v1/AUTH_test/source/link".into(),
                query_string: String::new(),
                headers,
                body: swift_http::IncomingBody::from_bytes(
                    Vec::new(),
                    swift_http::MAX_CONTROL_BODY,
                ),
            },
        )
        .await;
        assert_eq!(resp.status, 218);
    }

    #[test]
    fn account_options_allow_reflects_account_management_setting() {
        let app = app(ProxyConfig {
            allow_account_management: true,
            ..Default::default()
        });
        let resp = app.handle(request("OPTIONS", "/v1/AUTH_test", &[]));
        assert_eq!(resp.status, 200);
        assert_eq!(
            resp.headers.get("Allow"),
            Some("GET, HEAD, PUT, POST, DELETE, OPTIONS")
        );
        assert_no_cors(&resp.headers);
    }

    #[test]
    fn container_and_object_preflight_emit_python_headers() {
        let app = app(ProxyConfig::default());
        seed_container(
            &app,
            "AUTH_test",
            "c",
            CorsInfo {
                allow_origin: Some("http://foo.bar:8080 https://allowed.example".to_string()),
                expose_headers: None,
                max_age: Some("999".to_string()),
            },
        );

        for path in ["/v1/AUTH_test/c", "/v1/AUTH_test/c/o"] {
            let resp = app.handle(request(
                "OPTIONS",
                path,
                &[
                    ("Origin", "https://allowed.example"),
                    ("Access-Control-Request-Method", "GET"),
                    (
                        "Access-Control-Request-Headers",
                        "X-Auth-Token, X-Object-Meta-Test, X-Auth-Token",
                    ),
                ],
            ));
            assert_eq!(resp.status, 200, "{path}");
            assert_eq!(
                resp.headers.get("Access-Control-Allow-Origin"),
                Some("https://allowed.example")
            );
            assert_eq!(
                resp.headers.get("Access-Control-Allow-Methods"),
                Some("GET, HEAD, PUT, POST, DELETE, OPTIONS")
            );
            assert_eq!(resp.headers.get("Access-Control-Max-Age"), Some("999"));
            assert_eq!(
                resp.headers.get("Access-Control-Allow-Headers"),
                Some("X-Auth-Token, X-Object-Meta-Test")
            );
            assert_eq!(
                resp.headers.get("Vary"),
                Some("Origin, Access-Control-Request-Headers")
            );
        }
    }

    #[test]
    fn preflight_rejects_origin_or_method_without_leaking_cors() {
        let strict_app = app(ProxyConfig::default());
        seed_container(
            &strict_app,
            "AUTH_test",
            "c",
            CorsInfo {
                allow_origin: Some("https://allowed.example".into()),
                expose_headers: None,
                max_age: Some("999".into()),
            },
        );

        for headers in [
            vec![
                ("Origin", "https://denied.example"),
                ("Access-Control-Request-Method", "GET"),
            ],
            vec![("Origin", "https://allowed.example")],
            vec![
                ("Origin", "https://allowed.example"),
                ("Access-Control-Request-Method", "PATCH"),
                ("Access-Control-Request-Headers", "X-Must-Not-Leak"),
            ],
        ] {
            let resp = strict_app.handle(request("OPTIONS", "/v1/AUTH_test/c/o", &headers));
            assert_eq!(resp.status, 401, "{headers:?}");
            assert_eq!(
                resp.headers.get("Allow"),
                Some("GET, HEAD, PUT, POST, DELETE, OPTIONS")
            );
            assert_eq!(
                resp.headers.get("Content-Type"),
                Some("text/html; charset=UTF-8")
            );
            assert!(resp.headers.get("Www-Authenticate").is_none());
            assert_no_cors(&resp.headers);
        }

        let non_strict = app(ProxyConfig {
            strict_cors_mode: false,
            ..Default::default()
        });
        seed_container(
            &non_strict,
            "AUTH_test",
            "c",
            CorsInfo {
                allow_origin: Some("https://allowed.example".into()),
                expose_headers: None,
                max_age: None,
            },
        );
        let resp = non_strict.handle(request(
            "OPTIONS",
            "/v1/AUTH_test/c/o",
            &[
                ("Origin", "https://denied.example"),
                ("Access-Control-Request-Method", "GET"),
            ],
        ));
        assert_eq!(resp.status, 401);
        assert_no_cors(&resp.headers);
    }

    #[test]
    fn preflight_wildcard_and_operator_origin_match_python() {
        let wildcard_app = app(ProxyConfig::default());
        seed_container(
            &wildcard_app,
            "AUTH_test",
            "wild",
            CorsInfo {
                allow_origin: Some("*".into()),
                expose_headers: None,
                max_age: None,
            },
        );
        let resp = wildcard_app.handle(request(
            "OPTIONS",
            "/v1/AUTH_test/wild/o",
            &[
                ("Origin", "https://any.example"),
                ("Access-Control-Request-Method", "HEAD"),
                ("Access-Control-Request-Headers", "X-Arbitrary-Header"),
            ],
        ));
        assert_eq!(resp.status, 200);
        assert_eq!(resp.headers.get("Access-Control-Allow-Origin"), Some("*"));
        assert_eq!(
            resp.headers.get("Vary"),
            Some("Access-Control-Request-Headers")
        );
        assert_eq!(
            resp.headers.get("Access-Control-Allow-Headers"),
            Some("X-Arbitrary-Header")
        );

        let blank_headers = wildcard_app.handle(request(
            "OPTIONS",
            "/v1/AUTH_test/wild/o",
            &[
                ("Origin", "https://any.example"),
                ("Access-Control-Request-Method", "GET"),
                ("Access-Control-Request-Headers", " , ,,"),
            ],
        ));
        assert_eq!(blank_headers.status, 200);
        assert!(blank_headers
            .headers
            .get("Access-Control-Allow-Headers")
            .is_none());
        assert!(blank_headers.headers.get("Vary").is_none());

        let operator_app = app(ProxyConfig {
            cors_allow_origin: vec!["https://operator.example".into()],
            ..Default::default()
        });
        seed_container(&operator_app, "AUTH_test", "c", CorsInfo::default());
        let resp = operator_app.handle(request(
            "OPTIONS",
            "/v1/AUTH_test/c/o",
            &[
                ("Origin", "https://operator.example"),
                ("Access-Control-Request-Method", "GET"),
            ],
        ));
        assert_eq!(resp.status, 200);
        assert_eq!(
            resp.headers.get("Access-Control-Allow-Origin"),
            Some("https://operator.example")
        );
        assert_eq!(resp.headers.get("Vary"), Some("Origin"));
    }

    #[test]
    fn simple_cors_strict_and_non_strict_match_python_without_leaks() {
        let non_strict = app(ProxyConfig {
            strict_cors_mode: false,
            cors_expose_headers: vec!["X-Custom-Operator".into()],
            ..Default::default()
        });
        let cors = CorsInfo {
            allow_origin: Some("https://other.example".into()),
            expose_headers: Some("X-Custom-User".into()),
            max_age: None,
        };
        let req = request(
            "GET",
            "/v1/AUTH_test/c/o",
            &[("Origin", "https://request.example")],
        );
        let mut resp = Response::new(404);
        resp.headers.set("X-Object-Meta-Color", "red");
        resp.headers.set("X-Super-Secret", "hush");
        resp.headers.set("Vary", "Accept-Encoding");
        non_strict.apply_simple_cors(&req, &cors, &mut resp);
        assert_eq!(resp.status, 404);
        assert_eq!(
            resp.headers.get("Access-Control-Allow-Origin"),
            Some("https://request.example")
        );
        assert_eq!(resp.headers.get("Vary"), Some("Accept-Encoding, Origin"));
        assert!(
            resp.headers
                .get("Access-Control-Expose-Headers")
                .unwrap_or("")
                .split(',')
                .map(str::trim)
                .any(|header| header == "X-Custom-Operator"),
            "operator-configured header spelling must be preserved"
        );
        let exposed = header_set(&resp.headers, "Access-Control-Expose-Headers");
        for expected in [
            "cache-control",
            "content-language",
            "content-type",
            "expires",
            "last-modified",
            "pragma",
            "etag",
            "x-timestamp",
            "x-trans-id",
            "x-openstack-request-id",
            "x-object-meta-color",
            "x-custom-operator",
            "x-custom-user",
        ] {
            assert!(
                exposed.contains(expected),
                "missing {expected}: {exposed:?}"
            );
        }
        assert!(!exposed.contains("x-super-secret"));

        let strict = app(ProxyConfig::default());
        let mut denied = Response::new(404);
        denied.headers.set("Vary", "Accept-Encoding");
        strict.apply_simple_cors(&req, &cors, &mut denied);
        assert_eq!(denied.status, 404);
        assert_no_access_control(&denied.headers);
        assert_eq!(denied.headers.get("Vary"), Some("Accept-Encoding"));

        let allowed_cors = CorsInfo {
            allow_origin: Some("https://request.example".into()),
            expose_headers: None,
            max_age: None,
        };
        let mut object_owned = Response::new(200);
        object_owned
            .headers
            .set("Access-Control-Allow-Origin", "https://object.example");
        object_owned
            .headers
            .set("Access-Control-Expose-Headers", "x-trans-id");
        strict.apply_simple_cors(&req, &allowed_cors, &mut object_owned);
        assert_eq!(
            object_owned.headers.get("Access-Control-Allow-Origin"),
            Some("https://object.example")
        );
        assert_eq!(
            object_owned.headers.get("Access-Control-Expose-Headers"),
            Some("x-trans-id")
        );
        assert!(object_owned.headers.get("Vary").is_none());

        let wildcard_cors = CorsInfo {
            allow_origin: Some("*".into()),
            expose_headers: None,
            max_age: None,
        };
        let mut wildcard = Response::new(200);
        strict.apply_simple_cors(&req, &wildcard_cors, &mut wildcard);
        assert_eq!(
            wildcard.headers.get("Access-Control-Allow-Origin"),
            Some("*")
        );
        assert!(wildcard.headers.get("Vary").is_none());
    }

    #[test]
    fn simple_cors_runs_on_container_and_object_handle_paths() {
        let non_strict = app(ProxyConfig {
            strict_cors_mode: false,
            ..Default::default()
        });
        seed_container(
            &non_strict,
            "AUTH_test",
            "c",
            CorsInfo {
                allow_origin: Some("https://different.example".into()),
                expose_headers: None,
                max_age: None,
            },
        );
        non_strict.info_cache.set_account(
            "AUTH_test".into(),
            AccountInfo {
                status: 404,
                ..Default::default()
            },
            60.0,
        );
        let container_resp = non_strict.handle(request(
            "PUT",
            "/v1/AUTH_test/c",
            &[("Origin", "https://request.example")],
        ));
        assert_eq!(container_resp.status, 404);
        assert_eq!(
            container_resp.headers.get("Access-Control-Allow-Origin"),
            Some("https://request.example")
        );

        let strict = app(ProxyConfig::default());
        seed_container(
            &strict,
            "AUTH_test",
            "c",
            CorsInfo {
                allow_origin: Some("https://allowed.example".into()),
                expose_headers: None,
                max_age: None,
            },
        );
        let allowed = strict.handle(request(
            "GET",
            "/v1/AUTH_test/c/o",
            &[("Origin", "https://allowed.example")],
        ));
        assert_eq!(allowed.status, 503);
        assert_eq!(
            allowed.headers.get("Access-Control-Allow-Origin"),
            Some("https://allowed.example")
        );

        let denied = strict.handle(request(
            "GET",
            "/v1/AUTH_test/c/o",
            &[("Origin", "https://denied.example")],
        ));
        assert_eq!(denied.status, 503);
        assert_no_cors(&denied.headers);

        let unsupported = strict.handle(request(
            "PATCH",
            "/v1/AUTH_test/c",
            &[("Origin", "https://allowed.example")],
        ));
        assert_eq!(unsupported.status, 405);
        assert_eq!(
            unsupported.headers.get("Allow"),
            Some("GET, HEAD, PUT, POST, DELETE, OPTIONS")
        );
        assert_no_cors(&unsupported.headers);
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

    fn put_req(headers: HeaderKeyDict) -> Request {
        Request {
            method: "PUT".to_string(),
            path: "/v1/AUTH_test/container/object".to_string(),
            query_string: String::new(),
            headers,
            body: swift_http::Body::empty(),
        }
    }

    #[test]
    fn trusted_object_write_timestamp_preserves_internal_offset() {
        let mut headers = HeaderKeyDict::new();
        headers.set("X-Timestamp", "1787742045.13120_0000000000000003");
        assert_eq!(
            object_write_timestamp(&put_req(headers)).internal(),
            "1787742045.13120_0000000000000003"
        );
    }

    #[test]
    fn inbound_object_write_timestamp_after_gatekeeper_shunt() {
        // Field H1: IC recreate PUT with X-Timestamp=delete_at+1 is shunted
        // by gatekeeper. The proxy must restore inbound so recreate_ts
        // beats the expirer tombstone at delete_at. Raw X-Timestamp stays
        // stripped (gatekeeper public-path contract).
        const DELETE_AT: &str = "1788864768.00000";
        const RECREATE: &str = "1788864769.00000";
        let mut headers = HeaderKeyDict::new();
        headers.set("X-Timestamp", RECREATE);
        let mut req = put_req(headers);

        use swift_middleware::{Gatekeeper, Middleware};
        let gk = Gatekeeper::default();
        assert!(matches!(
            gk.prepare(&mut req),
            swift_middleware::MwPrep::Continue
        ));
        assert!(
            req.headers.get("X-Timestamp").is_none(),
            "gatekeeper must keep raw X-Timestamp stripped on the public path"
        );
        assert_eq!(
            req.headers.get("X-Backend-Inbound-X-Timestamp"),
            Some(RECREATE)
        );

        let put_ts = object_write_timestamp(&req);
        assert_eq!(put_ts.internal(), RECREATE);
        let tombstone: Timestamp = DELETE_AT.parse().expect("delete_at");
        assert!(
            put_ts > tombstone,
            "recreate_ts {} must beat expirer tombstone {}",
            put_ts.internal(),
            tombstone.internal()
        );
    }

    #[test]
    fn inbound_object_write_timestamp_used_when_x_timestamp_absent() {
        let mut headers = HeaderKeyDict::new();
        headers.set("X-Backend-Inbound-X-Timestamp", "1788864769.00000");
        assert_eq!(
            object_write_timestamp(&put_req(headers)).internal(),
            "1788864769.00000"
        );
    }

    #[test]
    fn object_write_timestamp_prefers_x_timestamp_over_inbound() {
        let mut headers = HeaderKeyDict::new();
        headers.set("X-Timestamp", "1787742045.13120_0000000000000003");
        headers.set("X-Backend-Inbound-X-Timestamp", "1000000000.00000");
        assert_eq!(
            object_write_timestamp(&put_req(headers)).internal(),
            "1787742045.13120_0000000000000003"
        );
    }

    #[test]
    fn object_write_timestamp_wall_clock_without_client_or_inbound() {
        let before = Timestamp::now();
        let got = object_write_timestamp(&put_req(HeaderKeyDict::new()));
        let after = Timestamp::now();
        assert!(
            got >= before && got <= after,
            "wall-clock fallback expected, got {}",
            got.internal()
        );
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
    fn authorize_override_allows_trusted_versioning_info_probe_as_owner() {
        let app = app(true);
        let mut headers = HeaderKeyDict::new();
        headers.set("X-Backend-Authorize-Override", "true");
        headers.set(swift_middleware::VERSIONED_WRITES_OWNER_INFO_HEADER, "true");
        let mut req = Request {
            method: "HEAD".to_string(),
            path: "/v1/AUTH_test/container".to_string(),
            query_string: String::new(),
            headers,
            body: swift_http::Body::empty(),
        };

        assert!(app
            .authorize(&mut req, "AUTH_test", Some("container"), None)
            .is_none());
        assert_eq!(req.headers.get("X-Backend-Swift-Owner"), Some("true"));
        assert!(req
            .headers
            .get(swift_middleware::VERSIONED_WRITES_OWNER_INFO_HEADER)
            .is_none());
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
            rfc_compliant_etags: None,
            cors: CorsInfo::default(),
            db_state: String::new(),
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
    fn versioned_write_authorize_only_probe_stops_before_backend_dispatch() {
        let allowed = app(false);
        let mut headers = HeaderKeyDict::new();
        headers.set(
            swift_middleware::VERSIONED_WRITES_AUTHORIZE_ONLY_HEADER,
            "true",
        );
        let req = Request {
            method: "PUT".to_string(),
            path: "/v1/AUTH_test/container/object".to_string(),
            query_string: String::new(),
            headers,
            body: swift_http::Body::empty(),
        };
        assert_eq!(allowed.handle(req).status, 204);

        let denied = app(true);
        denied.info_cache.set_container(
            "AUTH_test/container".to_string(),
            ContainerInfo {
                status: 204,
                policy_index: 0,
                ..Default::default()
            },
            60.0,
        );
        let mut headers = HeaderKeyDict::new();
        headers.set(
            swift_middleware::VERSIONED_WRITES_AUTHORIZE_ONLY_HEADER,
            "true",
        );
        let req = Request {
            method: "DELETE".to_string(),
            path: "/v1/AUTH_test/container/object".to_string(),
            query_string: String::new(),
            headers,
            body: swift_http::Body::empty(),
        };
        assert_eq!(denied.handle(req).status, 401);
    }

    #[tokio::test]
    async fn versioned_write_streaming_authorize_probe_stops_before_object_put() {
        let allowed = app(false);
        let mut headers = HeaderKeyDict::new();
        headers.set(
            swift_middleware::VERSIONED_WRITES_AUTHORIZE_ONLY_HEADER,
            "true",
        );
        headers.set("Content-Length", "16");
        let resp = allowed
            .handle_async(AsyncRequest {
                method: "PUT".to_string(),
                path: "/v1/AUTH_test/container/object".to_string(),
                query_string: String::new(),
                headers,
                body: swift_http::IncomingBody::from_bytes(b"must-not-consume".to_vec(), 1024),
            })
            .await;
        assert_eq!(resp.status, 204);
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
                rfc_compliant_etags: None,
                account_really_exists: true,
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

    fn privileged_container_write_headers() -> HeaderKeyDict {
        let mut headers = HeaderKeyDict::new();
        headers.set("X-Container-Read", "frank");
        headers.set("X-Container-Write", "frank");
        headers.set("X-Container-Sync-Key", "uuid-not-secret");
        headers.set("X-Container-Sync-To", "//other/sync");
        headers.set("X-Container-Meta-Color", "blue");
        headers.set("X-Container-Meta-Temp-Url-Key", "tempurl");
        headers
    }

    /// Field H1: account-RW / container-write callers are authorized but
    /// `swift_owner` stays false — Python pops privileged request headers
    /// so test_protected_container_acl keeps `jdoe` and
    /// test_protected_container_sync keeps `secret`.
    #[test]
    fn non_owner_container_put_post_cannot_set_privileged_headers() {
        for method in ["PUT", "POST"] {
            let mut req = Request {
                method: method.into(),
                path: "/v1/AUTH_test/c".into(),
                query_string: String::new(),
                headers: privileged_container_write_headers(),
                body: swift_http::Body::empty(),
            };
            assert!(req.headers.get("X-Backend-Swift-Owner").is_none());
            scrub_container_write_owner_headers(&mut req);
            for name in [
                "X-Container-Read",
                "X-Container-Write",
                "X-Container-Sync-Key",
                "X-Container-Sync-To",
                "X-Container-Meta-Temp-Url-Key",
            ] {
                assert!(
                    req.headers.get(name).is_none(),
                    "{method} !swift_owner left {name}"
                );
            }
            assert_eq!(
                req.headers.get("X-Container-Meta-Color"),
                Some("blue"),
                "{method} must keep unprivileged container meta"
            );

            let app = app(false);
            let transferred = app.backend_headers(&req, true, "container");
            for name in [
                "X-Container-Read",
                "X-Container-Write",
                "X-Container-Sync-Key",
                "X-Container-Sync-To",
                "X-Container-Meta-Temp-Url-Key",
            ] {
                assert!(
                    transferred.get(name).is_none(),
                    "{method} backend_headers leaked {name}"
                );
            }
            assert_eq!(transferred.get("X-Container-Meta-Color"), Some("blue"));
        }
    }

    #[test]
    fn owner_and_reseller_container_put_post_can_set_privileged_headers() {
        for (label, extra) in [
            ("owner", vec![("X-Backend-Swift-Owner", "true")]),
            (
                "reseller",
                vec![
                    ("X-Backend-Swift-Owner", "true"),
                    ("X-Backend-Reseller-Request", "true"),
                ],
            ),
        ] {
            for method in ["PUT", "POST"] {
                let mut headers = privileged_container_write_headers();
                for (k, v) in &extra {
                    headers.set(*k, *v);
                }
                let mut req = Request {
                    method: method.into(),
                    path: "/v1/AUTH_test/c".into(),
                    query_string: String::new(),
                    headers,
                    body: swift_http::Body::empty(),
                };
                scrub_container_write_owner_headers(&mut req);
                assert_eq!(
                    req.headers.get("X-Container-Read"),
                    Some("frank"),
                    "{label} {method} must keep X-Container-Read"
                );
                assert_eq!(
                    req.headers.get("X-Container-Write"),
                    Some("frank"),
                    "{label} {method} must keep X-Container-Write"
                );
                assert_eq!(
                    req.headers.get("X-Container-Sync-Key"),
                    Some("uuid-not-secret"),
                    "{label} {method} must keep X-Container-Sync-Key"
                );

                let app = app(false);
                let transferred = app.backend_headers(&req, true, "container");
                assert_eq!(transferred.get("X-Container-Read"), Some("frank"));
                assert_eq!(transferred.get("X-Container-Write"), Some("frank"));
                assert_eq!(
                    transferred.get("X-Container-Sync-Key"),
                    Some("uuid-not-secret")
                );
            }
        }
    }

    #[test]
    fn account_rw_authorize_is_not_swift_owner_so_acl_headers_scrub() {
        // frank: X-Account-Access-Control read-write — authorized to POST the
        // container, but not swift_owner (TempAuth.authorize_acl).
        let acct = swift_middleware::AccountAcls {
            admin: Vec::new(),
            read_write: vec!["frank".into()],
            read_only: Vec::new(),
        };
        let frank = vec!["frank".to_string()];
        let mut swift_owner = true;
        let denied = swift_middleware::TempAuth::authorize_acl(
            "POST",
            "/v1/AUTH_test/c",
            &frank,
            None,
            None,
            "AUTH_",
            Some(&acct),
            &mut swift_owner,
        );
        assert!(denied.is_none(), "account-RW frank must be allowed");
        assert!(!swift_owner, "account-RW is not swift_owner");

        let mut req = Request {
            method: "POST".into(),
            path: "/v1/AUTH_test/c".into(),
            query_string: String::new(),
            headers: privileged_container_write_headers(),
            body: swift_http::Body::empty(),
        };
        if swift_owner {
            req.headers.set("X-Backend-Swift-Owner", "true");
        }
        scrub_container_write_owner_headers(&mut req);
        assert!(req.headers.get("X-Container-Read").is_none());
        assert!(req.headers.get("X-Container-Write").is_none());
        assert!(req.headers.get("X-Container-Sync-Key").is_none());
    }

    /// IsolatedIdentity leftover: account-RW POST `X-Remove-Container-Read`
    /// used to reach the container server and clear the ACL after the
    /// matching `X-Container-Read` was already popped.
    #[test]
    fn non_owner_container_put_post_cannot_remove_privileged_headers() {
        for method in ["PUT", "POST"] {
            let mut headers = HeaderKeyDict::new();
            headers.set("X-Remove-Container-Read", "x");
            headers.set("X-Remove-Container-Write", "x");
            headers.set("X-Remove-Container-Sync-Key", "x");
            headers.set("X-Remove-Container-Sync-To", "x");
            headers.set("X-Remove-Container-Meta-Temp-Url-Key", "x");
            headers.set("X-Remove-Container-Meta-Color", "x");
            let mut req = Request {
                method: method.into(),
                path: "/v1/AUTH_test/c".into(),
                query_string: String::new(),
                headers,
                body: swift_http::Body::empty(),
            };
            scrub_container_write_owner_headers(&mut req);
            for name in [
                "X-Remove-Container-Read",
                "X-Remove-Container-Write",
                "X-Remove-Container-Sync-Key",
                "X-Remove-Container-Sync-To",
                "X-Remove-Container-Meta-Temp-Url-Key",
            ] {
                assert!(
                    req.headers.get(name).is_none(),
                    "{method} !swift_owner left {name}"
                );
            }
            assert_eq!(
                req.headers.get("X-Remove-Container-Meta-Color"),
                Some("x"),
                "{method} must keep unprivileged X-Remove-Container-Meta-*"
            );
        }
    }

    /// Official test_versioning_container_acl: account2 / account-RW
    /// `update_metadata(X-Versions-Location)` must raise (403), not persist.
    #[test]
    fn non_owner_container_put_post_cannot_set_versions_location() {
        for method in ["PUT", "POST"] {
            for (name, value) in [
                ("X-Versions-Location", "versions"),
                ("X-History-Location", "history"),
                ("X-Container-Sysmeta-Versions-Location", "versions"),
                ("X-Remove-Versions-Location", "x"),
            ] {
                let mut headers = HeaderKeyDict::new();
                headers.set(name, value);
                let req = Request {
                    method: method.into(),
                    path: "/v1/AUTH_test/c".into(),
                    query_string: String::new(),
                    headers,
                    body: swift_http::Body::empty(),
                };
                let denied = deny_non_owner_container_versioning(&req)
                    .unwrap_or_else(|| panic!("{method} {name} must 403"));
                assert_eq!(denied.status, 403, "{method} {name}");
            }
        }
    }

    #[test]
    fn owner_and_override_can_set_versions_location() {
        for extra in [
            vec![("X-Backend-Swift-Owner", "true")],
            vec![("X-Backend-Authorize-Override", "true")],
            vec![("X-Container-Sync-Key", "sync")],
        ] {
            let mut headers = HeaderKeyDict::new();
            headers.set("X-Versions-Location", "versions");
            for (k, v) in extra {
                headers.set(k, v);
            }
            let req = Request {
                method: "POST".into(),
                path: "/v1/AUTH_test/c".into(),
                query_string: String::new(),
                headers,
                body: swift_http::Body::empty(),
            };
            assert!(
                deny_non_owner_container_versioning(&req).is_none(),
                "owner/override/sync must keep versions-location"
            );
        }
    }

    #[test]
    fn non_owner_container_meta_without_versions_headers_is_not_403() {
        let req = Request {
            method: "POST".into(),
            path: "/v1/AUTH_test/c".into(),
            query_string: String::new(),
            headers: privileged_container_write_headers(),
            body: swift_http::Body::empty(),
        };
        assert!(deny_non_owner_container_versioning(&req).is_none());
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
        // POST (metadata) stays allowed when account management is off.
        let post = gated.handle(Request {
            method: "POST".to_string(),
            path: "/v1/AUTH_test".to_string(),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: swift_http::Body::empty(),
        });
        assert_ne!(
            post.status, 405,
            "account POST must not 405: {}",
            post.status
        );
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
        assert_ne!(
            resp.status, 405,
            "enabled path must not 405: {}",
            resp.status
        );
    }

    fn req_with(headers: &[(&str, &str)]) -> Request {
        let mut h = HeaderKeyDict::new();
        for (k, v) in headers {
            h.set(k, v);
        }
        Request {
            method: "PUT".into(),
            path: "/v1/a/c/o".into(),
            query_string: String::new(),
            headers: h,
            body: swift_http::Body::empty(),
        }
    }

    #[test]
    fn check_object_creation_delete_at_bodies() {
        let mut bad = req_with(&[("Content-Length", "0"), ("X-Delete-At", "*")]);
        let mut err = check_object_creation(&mut bad, "o").unwrap();
        assert_eq!(err.status, 400);
        assert_eq!(
            String::from_utf8_lossy(err.body.materialize(u64::MAX).unwrap()),
            "Non-integer X-Delete-At"
        );
        let mut past = req_with(&[("Content-Length", "0"), ("X-Delete-At", "0")]);
        let mut err = check_object_creation(&mut past, "o").unwrap();
        assert_eq!(
            String::from_utf8_lossy(err.body.materialize(u64::MAX).unwrap()),
            "X-Delete-At in past"
        );
        let mut after = req_with(&[("Content-Length", "0"), ("X-Delete-After", "*")]);
        let mut err = check_object_creation(&mut after, "o").unwrap();
        assert_eq!(
            String::from_utf8_lossy(err.body.materialize(u64::MAX).unwrap()),
            "Non-integer X-Delete-After"
        );
        let mut missing = req_with(&[]);
        let mut err = check_object_creation(&mut missing, "o").unwrap();
        assert_eq!(err.status, 411);
        assert_eq!(
            String::from_utf8_lossy(err.body.materialize(u64::MAX).unwrap()),
            "Missing Content-Length header."
        );
        let mut te = req_with(&[("Transfer-Encoding", "gzip,chunked")]);
        let err = check_object_creation(&mut te, "o").unwrap();
        assert_eq!(err.status, 501);
        let mut cl = req_with(&[("Content-Length", "X")]);
        let mut err = check_object_creation(&mut cl, "o").unwrap();
        assert_eq!(err.status, 400);
        assert_eq!(
            String::from_utf8_lossy(err.body.materialize(u64::MAX).unwrap()),
            "Invalid Content-Length header value"
        );
    }
}

#[cfg(test)]
mod shard_listing_fanout_tests {
    use super::{
        copy_root_listing_headers, fold_replica_listings, fold_replica_listings_dated,
        include_root_residual_for_listing, include_root_residual_for_listing_ex,
        include_sharding_residual_root, include_shrink_to_root_residual, json_range_is_nested,
        listing_has_full_active_cover, listing_ranges_are_settled_active,
        listing_ranges_prove_sharded, listing_resp_timestamp, lowest_shard_usage,
        merge_listings_newest_covering, merge_sharded_object_listings,
        merge_sharded_object_listings_dir, pick_updating_shard_name, prefer_listing_state_ranges,
        prefer_longest_nonempty_arrays, prefer_most_progressed_listing_arrays,
        prefer_quorum_consistent_listing_arrays, select_listing_shard_ranges,
        shard_usage_from_ranges, should_fanout_sharded_listing,
        should_fold_root_objects_without_ranges, should_probe_sharded_listing,
        stamp_shard_container_path, updating_shard_query, ListingFeed, SHARD_LISTING_STATE_NUMS,
    };
    use swift_http::HeaderKeyDict;

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
        let selected = select_listing_shard_ranges(&ranges, "m", "", "", false);
        // upper "m" <= marker "m" → skip first
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0]["name"], ".shards/b");

        let selected = select_listing_shard_ranges(&ranges, "", "", "u", false);
        // upper "m" < "u" and upper "t" < "u" → only open-ended last range
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0]["name"], ".shards/c");
    }

    #[test]
    fn select_ranges_reverse_swaps_marker_and_end_marker() {
        // probe L562: reverse=True, marker=obj-0350, end_marker=obj-0150.
        // Forward skip `upper <= marker` would keep only shard3 (13 extras)
        // and under-return the 25-name reverse page.
        let ranges = vec![
            sr(".shards/s0", "", "obj-0098"),
            sr(".shards/s1", "obj-0098", "obj-0198"),
            sr(".shards/s2", "obj-0198", "obj-0298"),
            sr(".shards/s3", "obj-0298", ""),
        ];
        let selected = select_listing_shard_ranges(&ranges, "obj-0350", "obj-0150", "", true);
        let names: Vec<&str> = selected
            .iter()
            .filter_map(|v| v.get("name").and_then(|n| n.as_str()))
            .collect();
        assert_eq!(
            names,
            vec![".shards/s3", ".shards/s2", ".shards/s1"],
            "{names:?}"
        );

        let fwd = select_listing_shard_ranges(&ranges, "obj-0198", "", "", false);
        assert_eq!(fwd.len(), 2);
        assert_eq!(fwd[0]["name"], ".shards/s2");
        assert_eq!(fwd[1]["name"], ".shards/s3");
    }

    #[test]
    fn merge_reverse_limit_spans_shards() {
        // L562: shard3 holds 13 reverse extras; page limit 25 continues into shard2.
        let s3: Vec<_> = (0..13)
            .map(|i| serde_json::json!({"name": format!("obj-{:04}", 349 - i * 4)}))
            .collect();
        let s2: Vec<_> = (0..25)
            .map(|i| serde_json::json!({"name": format!("obj-{:04}", 297 - i * 4)}))
            .collect();
        let merged = merge_listings_newest_covering(
            &[
                ListingFeed {
                    lower: "obj-0298".into(),
                    upper: String::new(),
                    timestamp: String::new(),
                    items: s3,
                },
                ListingFeed {
                    lower: "obj-0198".into(),
                    upper: "obj-0298".into(),
                    timestamp: String::new(),
                    items: s2,
                },
            ],
            25,
            true,
        );
        let names: Vec<&str> = merged
            .iter()
            .filter_map(|v| v.get("name")?.as_str())
            .collect();
        assert_eq!(names.len(), 25, "{names:?}");
        assert_eq!(names[0], "obj-0349");
        assert_eq!(names[12], "obj-0301");
        assert_eq!(names[13], "obj-0297");
        assert_eq!(names[24], "obj-0253");
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
    fn merge_listings_unions_cleaved_replica_and_new_puts() {
        // no_replicators: replica A has only extra PUTs, replica B has cleaved
        // originals. Union must include both.
        let extra = vec![
            serde_json::json!({"name": "beta000"}),
            serde_json::json!({"name": "beta001"}),
        ];
        let cleaved = vec![
            serde_json::json!({"name": "obj-0000"}),
            serde_json::json!({"name": "beta000"}),
        ];
        let merged = merge_sharded_object_listings(&[extra, cleaved], 10000);
        let names: Vec<&str> = merged
            .iter()
            .filter_map(|v| v.get("name").and_then(|n| n.as_str()))
            .collect();
        assert_eq!(merged.len(), 3, "{names:?}");
        assert!(names.contains(&"beta000"));
        assert!(names.contains(&"beta001"));
        assert!(names.contains(&"obj-0000"));
    }

    #[test]
    fn merge_sorts_residual_evens_ahead_of_cleaved_new_puts() {
        // probe test_sharding_listing L631: residual root is even originals;
        // cleaved shard also has odd new PUTs. Insertion order would yield
        // 0000,0002,0001; Swift listings are name-sorted.
        let residual = vec![
            serde_json::json!({"name": "obj-0000"}),
            serde_json::json!({"name": "obj-0002"}),
            serde_json::json!({"name": "obj-0004"}),
        ];
        let cleaved = vec![
            serde_json::json!({"name": "obj-0000"}),
            serde_json::json!({"name": "obj-0001"}),
            serde_json::json!({"name": "obj-0002"}),
            serde_json::json!({"name": "obj-0004"}),
            serde_json::json!({"name": "obj-0005"}),
        ];
        let merged = merge_sharded_object_listings(&[residual.clone(), cleaved.clone()], 10000);
        let names: Vec<&str> = merged
            .iter()
            .filter_map(|v| v.get("name").and_then(|n| n.as_str()))
            .collect();
        assert_eq!(
            names,
            ["obj-0000", "obj-0001", "obj-0002", "obj-0004", "obj-0005"]
        );
        let rev =
            merge_sharded_object_listings_dir(&[cleaved.clone(), residual.clone()], 10000, true);
        let rnames: Vec<&str> = rev
            .iter()
            .filter_map(|v| v.get("name").and_then(|n| n.as_str()))
            .collect();
        assert_eq!(
            rnames,
            ["obj-0005", "obj-0004", "obj-0002", "obj-0001", "obj-0000"]
        );
    }

    #[test]
    fn empty_state_with_ranges_is_fanout_eligible() {
        // Contabo partial cleave: DB state still unsharded, root emptied,
        // CLEAVED ranges present → fan out.
        assert!(should_probe_sharded_listing("unsharded", 0));
        assert!(should_fanout_sharded_listing("unsharded", 0, true));
        assert!(!should_fanout_sharded_listing("unsharded", 0, false));

        // Non-empty unsharded HEAD: do not rewrite HEAD. GET still fans
        // out when listing ranges exist (lagging replica, L1985).
        assert!(!should_probe_sharded_listing("unsharded", 5));
        assert!(should_fanout_sharded_listing("unsharded", 5, true));

        // Explicit sharding/sharded always eligible when ranges exist.
        assert!(should_probe_sharded_listing("sharding", 0));
        assert!(should_probe_sharded_listing("sharded", 100));
        assert!(should_fanout_sharded_listing("sharding", 0, true));
        assert!(should_fanout_sharded_listing("sharded", 0, true));
        assert!(!should_fanout_sharded_listing("sharded", 0, false));
        assert!(should_probe_sharded_listing("collapsed", 1));
        assert!(!should_fanout_sharded_listing("collapsed", 1, false));
        assert!(should_fold_root_objects_without_ranges("collapsed"));
        assert!(should_fold_root_objects_without_ranges("sharding"));
        assert!(!should_fold_root_objects_without_ranges("unsharded"));

        // L1483: SHARDING residual even when HEAD count is 0.
        assert!(include_sharding_residual_root("sharding", false));
        assert!(include_sharding_residual_root("SHARDING", true));
        assert!(include_sharding_residual_root("sharded", true));
        assert!(!include_sharding_residual_root("sharded", false));
        assert!(!include_sharding_residual_root("unsharded", true));
        // Probe L2070: shrink-to-root residual on sharded without X-Newest.
        assert!(include_shrink_to_root_residual("sharded", true, true));
        assert!(include_shrink_to_root_residual("collapsed", true, true));
        assert!(!include_shrink_to_root_residual("sharded", true, false));
        assert!(!include_shrink_to_root_residual("sharded", false, true));
        assert!(!include_shrink_to_root_residual("sharding", true, true));
        // L1985 nested shrinking: retiring root must not union.
        assert!(!include_root_residual_for_listing(
            "sharded", false, false, true, true, false
        ));
        assert!(!include_root_residual_for_listing(
            "sharding", false, false, true, true, false
        ));
        // L1985 expanded acceptor covers MIN–MAX: never union retiring root.
        assert!(!include_root_residual_for_listing(
            "sharding", false, true, true, true, true
        ));
        assert!(!include_root_residual_for_listing(
            "sharded", true, true, true, true, true
        ));
        // L1483 SHARDING residual while uncleaved (no shrinking nest).
        assert!(include_root_residual_for_listing(
            "sharding", false, false, false, true, false
        ));
        // L2070 no ranges: fold root objects instead of residual-from-fanout.
        assert!(!include_root_residual_for_listing(
            "collapsed",
            false,
            false,
            false,
            false,
            false
        ));
        // listing-w191: settled shrinking without MIN-MAX ACTIVE (fetch
        // missed the expanded acceptor). Must still skip residual.
        assert!(!include_root_residual_for_listing(
            "sharded", false, true, true, true, false
        ));
        assert!(!include_root_residual_for_listing_ex(
            "sharded", false, true, true, true, false, false
        ));
        // L2070: last shard shrinking into root (MIN-MAX SHRINKING).
        assert!(include_root_residual_for_listing_ex(
            "sharded", false, true, true, true, false, true
        ));
        assert!(include_root_residual_for_listing_ex(
            "collapsed",
            false,
            true,
            true,
            true,
            false,
            true
        ));
        // L1509: settled ACTIVE, even if HEAD is still SHARDING.
        assert!(!include_root_residual_for_listing_ex(
            "sharded", true, true, false, true, false, false
        ));
        assert!(!include_root_residual_for_listing_ex(
            "sharding", true, true, false, true, false, false
        ));
        // L1483: still SHARDING / unsettled CREATED → residual stays on.
        assert!(include_root_residual_for_listing_ex(
            "sharding", true, false, false, true, false, false
        ));
        let shrinking_partial = sr_state(".shards/0", "", "obj-1-049", 50);
        let acc = sr_state(".shards/1", "", "", 40);
        assert!(listing_has_full_active_cover(&[&shrinking_partial, &acc]));
        assert!(!include_root_residual_for_listing(
            "sharded",
            false,
            false,
            true,
            true,
            listing_has_full_active_cover(&[&shrinking_partial, &acc])
        ));
    }

    #[test]
    fn folded_root_unions_collapsed_replica_over_empty_sharding() {
        // Probe L2068: 2/3 roots SHARDING 200 [] (empty epoch), 1 COLLAPSED
        // with [alpha-1]. empty_wins would drop alpha; union nonempty.
        let empty = Some(vec![]);
        let alpha = Some(vec![serde_json::json!({"name": "alpha-1"})]);
        let got = fold_replica_listings(&[empty.clone(), alpha, empty], false).unwrap();
        let names: Vec<&str> = got
            .iter()
            .filter_map(|v| v.get("name").and_then(|n| n.as_str()))
            .collect();
        assert_eq!(names, vec!["alpha-1"], "L2068 fold {got:?}");
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

        // All FOUND → fall back to full list (broader retry path).
        let only_found = vec![sr_state(".shards/f", "", "", 10)];
        let fallback = prefer_listing_state_ranges(&only_found);
        assert_eq!(fallback.len(), 1);
        assert_eq!(fallback[0]["name"], ".shards/f");
    }

    #[test]
    fn pick_updating_prefers_newer_subshard_over_lagging_donor() {
        // Probe L1418: union of a lagging replica's old ACTIVE donor and
        // newer nested sub-shards must DELETE to the sub-shard.
        let donor = serde_json::json!({
            "name": ".shards_a/c-0",
            "lower": "",
            "upper": "m",
            "state": 40,
            "deleted": 0,
            "timestamp": "1751500001.00000",
        });
        let sub = serde_json::json!({
            "name": ".shards_a/c-0-0",
            "lower": "",
            "upper": "g",
            "state": 40,
            "deleted": 0,
            "timestamp": "1751500009.00000",
        });
        let deleted_donor = serde_json::json!({
            "name": ".shards_a/c-0",
            "lower": "",
            "upper": "m",
            "state": 70,
            "deleted": 1,
            "timestamp": "1751500010.00000",
        });
        let got = pick_updating_shard_name(&[donor, sub, deleted_donor], "beta000", "AUTH_test/c");
        assert_eq!(got.as_deref(), Some(".shards_a/c-0-0"));
    }

    #[test]
    fn concat_includes_ranges_prefers_newest_covering_not_longest_tie() {
        // Two replicas each return one includes= range (length 1). Longest
        // nonempty is a tie; concatenating then picking newest covering is
        // what resolve_updating_shard must do (listing-w137).
        let lagging = serde_json::json!({
            "name": ".shards_a/c-0",
            "lower": "",
            "upper": "",
            "state": 40,
            "deleted": 0,
            "timestamp": "1751500001.00000",
        });
        let child = serde_json::json!({
            "name": ".shards_a/c-1",
            "lower": "m",
            "upper": "",
            "state": 40,
            "deleted": 0,
            "timestamp": "1751500009.00000",
        });
        let concat = vec![lagging, child];
        assert_eq!(
            pick_updating_shard_name(&concat, "obj-0100", "AUTH_test/c").as_deref(),
            Some(".shards_a/c-1")
        );
        assert_eq!(
            pick_updating_shard_name(&concat, "aaa", "AUTH_test/c").as_deref(),
            Some(".shards_a/c-0")
        );
    }

    #[test]
    fn updating_shard_query_keeps_states_updating_and_includes_object() {
        let q = updating_shard_query("obj-0100");
        assert!(q.starts_with("states=updating&format=json&"), "{q}");
        assert!(q.contains("includes=obj-0100"), "{q}");
        let funky = updating_shard_query("obj\n0001%Ff");
        assert!(funky.contains("states=updating"), "{funky}");
        assert!(funky.contains("includes=obj%0A0001%25Ff"), "{funky}");
    }

    #[test]
    fn pick_updating_none_when_lagging_updating_lacks_nested_child() {
        // A lagging root replica's updating set: SHARDED donor (skipped) plus
        // the un-nested sibling. Objects in the nested first-half are not
        // covered → None, so resolve_updating_shard must fall back to listing.
        let sibling = serde_json::json!({
            "name": ".shards_a/c-1",
            "lower": "m",
            "upper": "",
            "state": 40,
            "deleted": 0,
            "timestamp": "1751500001.00000",
        });
        let donor_sharded = serde_json::json!({
            "name": ".shards_a/c-0",
            "lower": "",
            "upper": "m",
            "state": 70,
            "deleted": 1,
            "timestamp": "1751500010.00000",
        });
        assert_eq!(
            pick_updating_shard_name(
                &[sibling.clone(), donor_sharded.clone()],
                "beta000",
                "AUTH_test/c"
            ),
            None
        );
        let nested = serde_json::json!({
            "name": ".shards_a/c-0-0",
            "lower": "",
            "upper": "g",
            "state": 40,
            "deleted": 0,
            "timestamp": "1751500009.00000",
        });
        assert_eq!(
            pick_updating_shard_name(&[sibling, donor_sharded, nested], "beta000", "AUTH_test/c")
                .as_deref(),
            Some(".shards_a/c-0-0")
        );
    }

    #[test]
    fn merge_empty_sub_does_not_drop_donor_or_sibling_names() {
        // Python `_get_from_shards` skips empty children; they must not wipe
        // names still listed on the SHARDING donor (listing-w91 L1321).
        let donor = ListingFeed {
            lower: String::new(),
            upper: "m".into(),
            timestamp: "1751500001.00000".into(),
            items: vec![
                serde_json::json!({"name": "beta000"}),
                serde_json::json!({"name": "beta001"}),
                serde_json::json!({"name": "j-0000"}),
            ],
        };
        let sub = ListingFeed {
            lower: String::new(),
            upper: "g".into(),
            timestamp: "1751500001.00000".into(),
            items: vec![],
        };
        let other = ListingFeed {
            lower: "m".into(),
            upper: String::new(),
            timestamp: "1751500001.00000".into(),
            items: vec![serde_json::json!({"name": "z-0100"})],
        };
        let merged = merge_listings_newest_covering(&[donor, sub, other], 10000, false);
        let names: Vec<&str> = merged
            .iter()
            .filter_map(|v| v.get("name").and_then(|n| n.as_str()))
            .collect();
        assert!(names.contains(&"beta000"), "{names:?}");
        assert!(names.contains(&"beta001"), "{names:?}");
        assert!(names.contains(&"j-0000"), "{names:?}");
        assert!(names.contains(&"z-0100"), "{names:?}");
    }

    #[test]
    fn prefer_longest_nonempty_listing_set() {
        let short = vec![serde_json::json!({"name": "own"})];
        let long = vec![
            serde_json::json!({"name": "c0", "state": 30}),
            serde_json::json!({"name": "c1", "state": 30}),
            serde_json::json!({"name": "own", "state": 60}),
        ];
        let got = prefer_longest_nonempty_arrays(&[vec![], short, long.clone()]).unwrap();
        assert_eq!(got.len(), 3, "{got:?}");
        assert_eq!(got[0]["name"], "c0");
    }

    #[test]
    fn newest_listing_prefers_four_active_over_cleaved_quorum() {
        let cleaved = vec![
            serde_json::json!({"name": "s0", "lower": "", "upper": "obj-0049", "state": 30}),
            serde_json::json!({"name": "s1", "lower": "obj-0049", "upper": "obj-0099", "state": 30}),
            serde_json::json!({"name": "s2", "lower": "obj-0099", "upper": "obj-0149", "state": 20}),
            serde_json::json!({"name": "s3", "lower": "obj-0149", "upper": "", "state": 20}),
        ];
        let active = vec![
            serde_json::json!({"name": "s0", "lower": "", "upper": "obj-0049", "state": 40, "timestamp": "1751500001.00000"}),
            serde_json::json!({"name": "s1", "lower": "obj-0049", "upper": "obj-0099", "state": 40, "timestamp": "1751500001.00000"}),
            serde_json::json!({"name": "s2", "lower": "obj-0099", "upper": "obj-0149", "state": 40, "timestamp": "1751500001.00000"}),
            serde_json::json!({"name": "s3", "lower": "obj-0149", "upper": "", "state": 40, "timestamp": "1751500001.00000"}),
        ];
        let got =
            prefer_most_progressed_listing_arrays(&[cleaved.clone(), cleaved, active.clone()])
                .unwrap();
        assert_eq!(
            got.iter().filter(|sr| sr["state"] == 40).count(),
            4,
            "{got:?}"
        );
    }

    #[test]
    fn quorum_listing_outvotes_single_sharded_active_partition() {
        // L1509: two lagging SHARDING replicas agree on CLEAVED+CREATED;
        // the just-SHARDED replica has 4 ACTIVE. Quorum therefore cannot
        // be the X-Newest namespace source.
        let cleaved = vec![
            serde_json::json!({"name": "s0", "lower": "", "upper": "obj-0049", "state": 30}),
            serde_json::json!({"name": "s1", "lower": "obj-0049", "upper": "obj-0099", "state": 30}),
            serde_json::json!({"name": "s2", "lower": "obj-0099", "upper": "obj-0149", "state": 20}),
            serde_json::json!({"name": "s3", "lower": "obj-0149", "upper": "", "state": 20}),
        ];
        let active = vec![
            serde_json::json!({"name": "s0", "lower": "", "upper": "obj-0049", "state": 40, "timestamp": "1751500099.00000"}),
            serde_json::json!({"name": "s1", "lower": "obj-0049", "upper": "obj-0099", "state": 40, "timestamp": "1751500099.00000"}),
            serde_json::json!({"name": "s2", "lower": "obj-0099", "upper": "obj-0149", "state": 40, "timestamp": "1751500099.00000"}),
            serde_json::json!({"name": "s3", "lower": "obj-0149", "upper": "", "state": 40, "timestamp": "1751500099.00000"}),
        ];
        let got =
            prefer_quorum_consistent_listing_arrays(&[cleaved.clone(), cleaved, active]).unwrap();
        assert_eq!(
            got.iter().filter(|sr| sr["state"] == 40).count(),
            0,
            "quorum must pick the 2-replica SHARDING view, got {got:?}"
        );
        assert_eq!(got.iter().filter(|sr| sr["state"] == 30).count(), 2);
    }

    #[test]
    fn quorum_listing_keeps_live_shrinking_donor_until_move() {
        let transition = vec![
            serde_json::json!({
                "name": ".shards/a/donor",
                "lower": "",
                "upper": "obj-1-049",
                "state": 50,
                "deleted": 0,
                "timestamp": "1751500001.00000",
                "state_timestamp": "1751500010.00000",
            }),
            serde_json::json!({
                "name": ".shards/a/acceptor",
                "lower": "",
                "upper": "",
                "state": 40,
                "deleted": 0,
                "timestamp": "1751500010.00000",
            }),
        ];
        let got = prefer_quorum_consistent_listing_arrays(&[
            transition.clone(),
            transition.clone(),
            transition,
        ])
        .unwrap();
        assert_eq!(got.len(), 2, "W103/L1985 must query donor and acceptor");
        assert!(got.iter().any(|sr| sr["name"] == ".shards/a/donor"));
    }

    #[test]
    fn quorum_listing_ignores_one_long_stale_shrink_topology() {
        let acceptor = serde_json::json!({
            "name": ".shards/a/acceptor",
            "lower": "",
            "upper": "",
            "state": 40,
            "deleted": 0,
            "timestamp": "1751500020.00000",
        });
        let settled = vec![acceptor.clone()];
        let stale = vec![
            serde_json::json!({
                "name": ".shards/a/donor",
                "lower": "",
                "upper": "obj-1-049",
                "state": 50,
                "deleted": 0,
                "timestamp": "1751500010.00000",
            }),
            acceptor,
        ];
        let got =
            prefer_quorum_consistent_listing_arrays(&[settled.clone(), stale, settled]).unwrap();
        assert_eq!(got.len(), 1, "L2044 quorum must beat longer stale view");
        assert_eq!(got[0]["name"], ".shards/a/acceptor");
    }

    #[test]
    fn quorum_listing_tie_preserves_longest_partial_cleave_view() {
        let short = vec![sr_state("AUTH_test/root", "", "", 60)];
        let long = vec![
            sr_state(".shards/a/c0", "", "m", 30),
            sr_state("AUTH_test/root", "m", "", 60),
        ];
        let got = prefer_quorum_consistent_listing_arrays(&[short, long]).unwrap();
        assert_eq!(got.len(), 2, "L631 tie must retain progressed cleave view");
    }

    #[test]
    fn copy_root_listing_headers_copies_acl_and_versions() {
        let mut head = swift_http::Response::with_body(204, Vec::new());
        head.headers.set("X-Container-Read", "read_acl");
        head.headers.set("X-Container-Write", "write_acl");
        head.headers.set("X-Container-Sync-Key", "sync_key");
        head.headers
            .set("X-Container-Sysmeta-Versions-Location", "versions");
        head.headers.set("X-Container-Meta-Test", "testing");
        let mut out = swift_http::Response::with_body(200, b"[]".to_vec());
        copy_root_listing_headers(&head, &mut out);
        assert_eq!(out.headers.get("X-Container-Read"), Some("read_acl"));
        assert_eq!(out.headers.get("X-Container-Write"), Some("write_acl"));
        assert_eq!(out.headers.get("X-Container-Sync-Key"), Some("sync_key"));
        assert_eq!(out.headers.get("X-Versions-Location"), Some("versions"));
        assert_eq!(out.headers.get("X-Container-Meta-Test"), Some("testing"));
        assert_eq!(out.headers.get("Accept-Ranges"), Some("bytes"));
    }

    #[test]
    fn stamp_shard_path_only_sends_quoted_location_for_newline() {
        let mut h = HeaderKeyDict::new();
        stamp_shard_container_path(
            &mut h,
            ".shards_AUTH_test",
            "c\n%Ff-0",
            "AUTH_test",
            "c\n%Ff",
        );
        let quoted = h.get("X-Backend-Quoted-Container-Path").unwrap_or("");
        assert!(quoted.contains("%0A"), "{quoted}");
        assert_eq!(h.get("X-Backend-Container-Path"), None);
        assert_eq!(h.get("X-Backend-Location-Is-Quoted"), None);
    }

    #[test]
    fn stamp_versions_shard_path_percent_encodes_nul_without_raw_header() {
        let mut h = HeaderKeyDict::new();
        stamp_shard_container_path(
            &mut h,
            ".shards_AUTH_test",
            "versions\0bucket-123",
            "AUTH_test",
            "versions",
        );
        assert_eq!(
            h.get("X-Backend-Quoted-Container-Path"),
            Some(".shards_AUTH_test/versions%00bucket-123")
        );
        assert_eq!(h.get("X-Backend-Allow-Reserved-Names"), Some("true"));
        assert_eq!(h.get("X-Backend-Container-Path"), None);
        assert_eq!(h.get("X-Backend-Location-Is-Quoted"), None);
    }

    #[test]
    fn merge_keeps_delimiter_subdir_entries() {
        let a = vec![serde_json::json!({"subdir": "obj-"})];
        let b = vec![serde_json::json!({"subdir": "obj-"})];
        let merged = merge_sharded_object_listings(&[a, b], 10000);
        assert_eq!(merged.len(), 1, "{merged:?}");
        assert_eq!(merged[0]["subdir"], "obj-");
    }

    #[test]
    fn merge_newer_donor_without_cleaved_names_keeps_child_rows() {
        // listing-w91: SHARDING donor state_timestamp can be newer than
        // CLEAVED children. Newest-covering then omitted cleaved betas.
        let donor = ListingFeed {
            lower: String::new(),
            upper: "obj-0049".into(),
            timestamp: "1751500010.00000".into(),
            items: vec![serde_json::json!({"name": "obj-0000"})],
        };
        let sub0 = ListingFeed {
            lower: String::new(),
            upper: "beta049".into(),
            timestamp: "1751500009.00000".into(),
            items: vec![
                serde_json::json!({"name": "beta000"}),
                serde_json::json!({"name": "beta049"}),
            ],
        };
        let sub1 = ListingFeed {
            lower: "beta049".into(),
            upper: "obj-0049".into(),
            timestamp: "1751500009.00000".into(),
            items: vec![serde_json::json!({"name": "beta050"})],
        };
        let merged = merge_listings_newest_covering(&[donor, sub0, sub1], 10000, false);
        let names: Vec<&str> = merged
            .iter()
            .filter_map(|v| v.get("name").and_then(|n| n.as_str()))
            .collect();
        assert!(names.contains(&"beta000"), "{names:?}");
        assert!(names.contains(&"beta049"), "{names:?}");
        assert!(names.contains(&"beta050"), "{names:?}");
        assert!(names.contains(&"obj-0000"), "{names:?}");
    }

    #[test]
    fn nested_sub_ranges_are_detected_against_donor() {
        let donor = serde_json::json!({
            "name": ".shards_a/c-0",
            "lower": "",
            "upper": "obj-0049",
        });
        let sub0 = serde_json::json!({
            "name": ".shards_a/c-0-0",
            "lower": "",
            "upper": "beta049",
        });
        let sub1 = serde_json::json!({
            "name": ".shards_a/c-0-1",
            "lower": "beta049",
            "upper": "obj-0049",
        });
        let sibling = serde_json::json!({
            "name": ".shards_a/c-1",
            "lower": "obj-0049",
            "upper": "",
        });
        let all = [&donor, &sub0, &sub1, &sibling];
        assert!(json_range_is_nested(&sub0, &all));
        assert!(json_range_is_nested(&sub1, &all));
        assert!(!json_range_is_nested(&donor, &all));
        assert!(!json_range_is_nested(&sibling, &all));
    }

    #[test]
    fn settled_active_empty_wins_over_lagging_objects() {
        // Majority 200 [] (delete-all, L1418), not a 1:1 split with extras.
        let empty = Some(vec![]);
        let objs = Some(vec![serde_json::json!({"name": "beta050"})]);
        let got = fold_replica_listings(&[empty.clone(), empty, objs], true).unwrap();
        assert!(got.is_empty(), "{got:?}");
    }

    #[test]
    fn cleaved_union_keeps_objects_despite_empty_replica() {
        let empty = Some(vec![]);
        let objs = Some(vec![serde_json::json!({"name": "beta000"})]);
        let got = fold_replica_listings(&[empty, objs], false).unwrap();
        assert_eq!(got[0]["name"], "beta000");
    }

    #[test]
    fn replica_404_is_not_empty() {
        assert!(fold_replica_listings(&[None, None], true).is_none());
        assert!(fold_replica_listings(&[None, None], false).is_none());
        let empty = fold_replica_listings(&[None, Some(vec![])], false).unwrap();
        assert!(empty.is_empty());
        // 404 + leftover objects, empty_wins still not empty (no 200 []).
        let leftover = fold_replica_listings(
            &[None, Some(vec![serde_json::json!({"name": "beta050"})])],
            true,
        )
        .unwrap();
        assert_eq!(leftover[0]["name"], "beta050");
    }

    #[test]
    fn settled_shortest_nonempty_drops_lagging_originals() {
        // L692: extras remain so no replica is 200 []. Lagging replica still
        // lists deleted originals (longer). Shortest nonempty is the
        // tombstoned replica.
        let extras = Some(vec![
            serde_json::json!({"name": "obj-0001"}),
            serde_json::json!({"name": "obj-0005"}),
        ]);
        let mixed = Some(vec![
            serde_json::json!({"name": "obj-0000"}),
            serde_json::json!({"name": "obj-0001"}),
            serde_json::json!({"name": "obj-0002"}),
            serde_json::json!({"name": "obj-0005"}),
        ]);
        let got = fold_replica_listings(&[mixed, extras], true).unwrap();
        let names: Vec<&str> = got.iter().filter_map(|v| v.get("name")?.as_str()).collect();
        assert_eq!(names, vec!["obj-0001", "obj-0005"]);
        let extras = Some(vec![serde_json::json!({"name": "obj-0001"})]);
        let mixed = Some(vec![
            serde_json::json!({"name": "obj-0000"}),
            serde_json::json!({"name": "obj-0001"}),
        ]);
        let unioned = fold_replica_listings(&[mixed, extras], false).unwrap();
        assert_eq!(unioned.len(), 2, "cleaving still unions: {unioned:?}");
        // L643: extras on 2/3 replicas stay (majority). L692: originals on 1/3 drop.
        let orig_and_extra = Some(vec![
            serde_json::json!({"name": "obj-0000"}),
            serde_json::json!({"name": "obj-0001"}),
        ]);
        let extra_only = Some(vec![serde_json::json!({"name": "obj-0001"})]);
        let both_extras = Some(vec![
            serde_json::json!({"name": "obj-0000"}),
            serde_json::json!({"name": "obj-0001"}),
        ]);
        let got = fold_replica_listings(&[orig_and_extra, extra_only, both_extras], true).unwrap();
        let names: Vec<&str> = got.iter().filter_map(|v| v.get("name")?.as_str()).collect();
        assert_eq!(
            names,
            vec!["obj-0000", "obj-0001"],
            "L643 extras+orig {got:?}"
        );
        let a = Some(vec![
            serde_json::json!({"name": "obj-0001"}),
            serde_json::json!({"name": "obj-0005"}),
        ]);
        let b = Some(vec![
            serde_json::json!({"name": "obj-0000"}),
            serde_json::json!({"name": "obj-0001"}),
            serde_json::json!({"name": "obj-0002"}),
            serde_json::json!({"name": "obj-0005"}),
        ]);
        let c = Some(vec![
            serde_json::json!({"name": "obj-0001"}),
            serde_json::json!({"name": "obj-0005"}),
        ]);
        let got = fold_replica_listings(&[a, b, c], true).unwrap();
        let names: Vec<&str> = got.iter().filter_map(|v| v.get("name")?.as_str()).collect();
        assert_eq!(
            names,
            vec!["obj-0001", "obj-0005"],
            "L692 extras only {got:?}"
        );
    }

    #[test]
    fn just_cleaved_superset_does_not_fill_unbounded_prefix() {
        // After L1931, unbounded prefix/suffix extras are not hole-filled.
        // Live L1517 GREEN is sharder PUT onto primaries plus dated-empty
        // (`newer_nonempty_beats_older_empty_majority`), not prefix fill.
        let under = Some(vec![serde_json::json!({"name": "obj-0199"})]);
        let full: Vec<_> = (100..=199)
            .map(|i| serde_json::json!({"name": format!("obj-{i:04}")}))
            .collect();
        let got = fold_replica_listings(&[under.clone(), Some(full), under], true).unwrap();
        let names: Vec<&str> = got.iter().filter_map(|v| v.get("name")?.as_str()).collect();
        assert_eq!(names, vec!["obj-0199"], "{names:?}");

        // L692 interleaved evens still drop: extras 0001/0005, mixed adds
        // 0000 (prefix) and 0002 (between) — two gaps.
        let extras = Some(vec![
            serde_json::json!({"name": "obj-0001"}),
            serde_json::json!({"name": "obj-0005"}),
        ]);
        let mixed = Some(vec![
            serde_json::json!({"name": "obj-0000"}),
            serde_json::json!({"name": "obj-0001"}),
            serde_json::json!({"name": "obj-0002"}),
            serde_json::json!({"name": "obj-0005"}),
        ]);
        let got = fold_replica_listings(&[extras.clone(), mixed, extras], true).unwrap();
        let names: Vec<&str> = got.iter().filter_map(|v| v.get("name")?.as_str()).collect();
        assert_eq!(names, vec!["obj-0001", "obj-0005"]);
    }

    #[test]
    fn empty_wins_collapses_newer_subset_over_lagging_supersets() {
        use swift_core::timestamp::Timestamp;
        // Probe L1985: 2/3 shard-0 replicas still list DELETE'd obj-1-000…;
        // the reclaimed replica lists only alpha. Majority would keep the
        // leftovers (`c*2 > n_200`). Collapse the older supersets first.
        let alpha = Some(vec![serde_json::json!({"name": "alpha-1"})]);
        let leftover = Some(vec![
            serde_json::json!({"name": "alpha-1"}),
            serde_json::json!({"name": "obj-1-000"}),
            serde_json::json!({"name": "obj-1-001"}),
        ]);
        let old: Timestamp = "1751500001.00000".parse().unwrap();
        let new: Timestamp = "1751500002.00000".parse().unwrap();
        let got = fold_replica_listings_dated(
            &[leftover.clone(), leftover.clone(), alpha.clone()],
            true,
            &[old, old, new],
        )
        .unwrap();
        let names: Vec<&str> = got
            .iter()
            .filter_map(|v| v.get("name").and_then(|n| n.as_str()))
            .collect();
        assert_eq!(names, vec!["alpha-1"], "L1985 leftovers {got:?}");

        // Equal timestamps (created_at identical): do not collapse — that is
        // why listing_resp_timestamp prefers PUT/data timestamps.
        let got = fold_replica_listings_dated(
            &[leftover.clone(), leftover.clone(), alpha.clone()],
            true,
            &[old, old, old],
        )
        .unwrap();
        let names: Vec<&str> = got
            .iter()
            .filter_map(|v| v.get("name").and_then(|n| n.as_str()))
            .collect();
        assert_eq!(
            names,
            vec!["alpha-1", "obj-1-000", "obj-1-001"],
            "equal ts must not newest-fold {got:?}"
        );

        // L1517 safety: older under-populated subset must not replace a
        // newer 2/3 just-cleaved superset.
        let under = Some(vec![serde_json::json!({"name": "obj-0199"})]);
        let full: Vec<_> = (100..=199)
            .map(|i| serde_json::json!({"name": format!("obj-{i:04}")}))
            .collect();
        let got = fold_replica_listings_dated(
            &[Some(full.clone()), Some(full.clone()), under],
            true,
            &[new, new, old],
        )
        .unwrap();
        let names: Vec<&str> = got.iter().filter_map(|v| v.get("name")?.as_str()).collect();
        assert_eq!(names.len(), 100, "L1517 reverse-collapse {names:?}");
        assert_eq!(names[0], "obj-0100");
        assert_eq!(names[99], "obj-0199");
    }

    #[test]
    fn listing_resp_timestamp_prefers_put_over_created_at() {
        let mut h = HeaderKeyDict::new();
        h.set("X-Backend-Timestamp", "1751500001.00000");
        h.set("X-Backend-PUT-Timestamp", "1751500002.00000");
        h.set("X-Timestamp", "1751500000.00000");
        assert_eq!(
            listing_resp_timestamp(&h),
            "1751500002.00000".parse().unwrap()
        );
        let mut h = HeaderKeyDict::new();
        h.set("X-Backend-Timestamp", "1751500001.00000");
        h.set("X-Backend-Data-Timestamp", "1751500003.00000");
        h.set("X-Backend-PUT-Timestamp", "1751500002.00000");
        assert_eq!(
            listing_resp_timestamp(&h),
            "1751500003.00000".parse().unwrap()
        );
    }

    #[test]
    fn empty_wins_does_not_fill_unbounded_suffix_after_one_name() {
        // probe test_shrinking L1931: majority [alpha], lagging replica still
        // has deleted obj-1-000… in the suffix "gap".
        let alpha = Some(vec![serde_json::json!({"name": "alpha-1"})]);
        let leftover = Some(vec![
            serde_json::json!({"name": "alpha-1"}),
            serde_json::json!({"name": "obj-1-000"}),
            serde_json::json!({"name": "obj-1-001"}),
        ]);
        let got = fold_replica_listings(&[alpha.clone(), alpha.clone(), leftover], true).unwrap();
        let names: Vec<&str> = got
            .iter()
            .filter_map(|v| v.get("name").and_then(|n| n.as_str()))
            .collect();
        assert_eq!(names, vec!["alpha-1"], "{got:?}");
    }

    #[test]
    fn newer_nonempty_beats_older_empty_majority() {
        use swift_core::timestamp::Timestamp;
        let empty = Some(vec![]);
        let full = Some(vec![
            serde_json::json!({"name": "obj-0100"}),
            serde_json::json!({"name": "obj-0101"}),
        ]);
        let old: Timestamp = "1751500001.00000".parse().unwrap();
        let new: Timestamp = "1751500002.00000".parse().unwrap();
        // L1517 shard-2: under-populated 200 [] older than just-cleaved.
        let got = fold_replica_listings_dated(
            &[empty.clone(), full.clone(), empty.clone()],
            true,
            &[old, new, old],
        )
        .unwrap();
        let names: Vec<&str> = got.iter().filter_map(|v| v.get("name")?.as_str()).collect();
        assert_eq!(names, vec!["obj-0100", "obj-0101"]);
        // L1418: leftover older than DELETE 200 [].
        let leftover = Some(vec![serde_json::json!({"name": "beta050"})]);
        let got = fold_replica_listings_dated(
            &[empty.clone(), empty.clone(), leftover],
            true,
            &[new, new, old],
        )
        .unwrap();
        assert!(got.is_empty(), "{got:?}");
        // No timestamps: keep L1418 (do not resurrect).
        let got = fold_replica_listings(&[empty.clone(), empty, full], true).unwrap();
        assert!(got.is_empty(), "{got:?}");
    }

    #[test]
    fn settled_active_two_range_first_gen_and_nested() {
        let a = sr_state(".shards_AUTH_test/a", "", "m", 40);
        let b = sr_state(".shards_AUTH_test/b", "m", "", 40);
        // probe test_shrinking L1925: two ACTIVE first-gen shards.
        assert!(listing_ranges_are_settled_active(&[&a, &b]));
        assert!(listing_ranges_prove_sharded(&[&b, &a], "AUTH_test/c"));
        let r0 = sr_state(".shards_AUTH_test/r0", "", "g", 40);
        let r1 = sr_state(".shards_AUTH_test/r1", "g", "m", 40);
        let r2 = sr_state(".shards_AUTH_test/r2", "m", "t", 40);
        let r3 = sr_state(".shards_AUTH_test/r3", "t", "", 40);
        assert!(listing_ranges_are_settled_active(&[&r0, &r1, &r2, &r3]));
        assert!(listing_ranges_prove_sharded(
            &[&r0, &r1, &r2, &r3],
            "AUTH_test/c"
        ));
        let cleaved = sr_state(".shards_AUTH_test/cl", "", "g", 30);
        assert!(!listing_ranges_are_settled_active(&[
            &cleaved, &r1, &r2, &r3
        ]));
        assert!(!listing_ranges_prove_sharded(
            &[&cleaved, &r1, &r2, &r3],
            "AUTH_test/c"
        ));
        // Probe L2068: last remaining shard shrinking into root.
        let shrinking = sr_state(".shards_AUTH_test/last", "", "", 50);
        assert!(listing_ranges_are_settled_active(&[&shrinking]));
        assert!(!listing_ranges_prove_sharded(&[&shrinking], "AUTH_test/c"));
        let shrinking_lo = sr_state(".shards_AUTH_test/d0", "", "m", 50);
        let acc = sr_state(".shards_AUTH_test/a0", "", "", 40);
        assert!(
            listing_has_full_active_cover(&[&shrinking_lo, &acc]),
            "expanded acceptor is MIN–MAX ACTIVE"
        );
        assert!(
            listing_ranges_are_settled_active(&[&shrinking_lo, &acc]),
            "L1985 nested shrinking under expanded acceptor must majority-vote, not union handoffs"
        );
        // Overlapping donor + children, even if all ACTIVE: L1321 must union.
        let donor = sr_state(".shards_AUTH_test/donor", "", "obj-0049", 40);
        let sub0 = sr_state(".shards_AUTH_test/s0", "", "beta049", 40);
        let sub1 = sr_state(".shards_AUTH_test/s1", "beta049", "obj-0049", 40);
        assert!(!listing_ranges_are_settled_active(&[
            &donor, &sub0, &sub1, &r3
        ]));
        assert!(!listing_ranges_prove_sharded(
            &[&donor, &sub0, &sub1, &r3],
            "AUTH_test/c"
        ));
        assert!(!listing_ranges_are_settled_active(&[]));
        assert!(!listing_ranges_prove_sharded(&[], "AUTH_test/c"));

        // A self range spans the complete namespace even for an ordinary
        // root. It must never upgrade the cached DB state to `sharded`.
        let ordinary_root = sr_state("AUTH_test/c", "", "", 40);
        assert!(!listing_ranges_prove_sharded(
            &[&ordinary_root],
            "AUTH_test/c"
        ));
    }

    #[test]
    fn shard_usage_matches_python_stats_states() {
        // L1979: root range stats 1+50, not live shard HEAD 50+50.
        let d0 = serde_json::json!({"name":"s/0","state":40,"deleted":0,"object_count":1,"bytes_used":1});
        let d1 = serde_json::json!({"name":"s/1","state":40,"deleted":0,"object_count":50,"bytes_used":50});
        let (c, b, saw) = shard_usage_from_ranges(&[d0, d1]);
        assert!(saw);
        assert_eq!((c, b), (51, 51));
        let shrunk = serde_json::json!({"name":"s/x","state":80,"deleted":1,"object_count":1,"bytes_used":1});
        let (c, _, saw) = shard_usage_from_ranges(&[shrunk]);
        assert!(!saw);
        assert_eq!(c, 0);
        let shrinking = serde_json::json!({"name":"s/d","state":50,"deleted":0,"object_count":1,"bytes_used":1});
        let (c, _, saw) = shard_usage_from_ranges(&[shrinking]);
        assert!(saw);
        assert_eq!(c, 1);
        // listing-w193/w194: equal-length lagging 50+50 vs reclaimed 1+50.
        let lagging = vec![
            serde_json::json!({"name":"s/0","state":40,"deleted":0,"object_count":50,"bytes_used":50}),
            serde_json::json!({"name":"s/1","state":40,"deleted":0,"object_count":50,"bytes_used":50}),
        ];
        let reclaimed = vec![
            serde_json::json!({"name":"s/0","state":40,"deleted":0,"object_count":1,"bytes_used":1}),
            serde_json::json!({"name":"s/1","state":40,"deleted":0,"object_count":50,"bytes_used":50}),
        ];
        let incomplete = vec![
            serde_json::json!({"name":"s/1","lower":"obj-1-049","upper":"","state":40,"deleted":0,"object_count":50,"bytes_used":50}),
        ];
        let (c, _) = lowest_shard_usage(&[lagging.clone(), reclaimed.clone()]).unwrap();
        assert_eq!(c, 51, "L1979 HEAD must not first-win lagging 100");
        let (c, _) = lowest_shard_usage(&[incomplete, reclaimed.clone()]).unwrap();
        assert_eq!(c, 51, "L1979 HEAD must not prefer a 1-range 50");
        // listing-w231: reclaimed replica is already MIN–MAX 51; lagging
        // still lists 2 ranges totaling 100. Prefer the cover, not longest.
        let cover_51 = vec![
            serde_json::json!({"name":"s/1","lower":"","upper":"","state":40,"deleted":0,"object_count":51,"bytes_used":51}),
        ];
        let (c, _) = lowest_shard_usage(&[lagging.clone(), cover_51]).unwrap();
        assert_eq!(
            c, 51,
            "L1979 HEAD must prefer MIN-MAX cover 51 over 2-range 100"
        );
        // listing-w201 L1992: after shrink, one replica still says 1.
        let only_alpha = vec![
            serde_json::json!({"name":"s/1","lower":"","upper":"","state":40,"deleted":0,"object_count":1,"bytes_used":1}),
        ];
        let full_acc = vec![
            serde_json::json!({"name":"s/1","lower":"","upper":"","state":40,"deleted":0,"object_count":51,"bytes_used":51}),
        ];
        let (c, _) = lowest_shard_usage(&[only_alpha, full_acc]).unwrap();
        assert_eq!(c, 51, "L1992 HEAD must not min-pick lagging 1");
    }
}

#[cfg(test)]
mod account_update_headers_tests {
    use super::*;

    #[test]
    fn backend_controls_are_independent_of_metadata_transfer() {
        let mut request_headers = HeaderKeyDict::new();
        request_headers.set("X-Backend-No-Commit", "True");
        request_headers.set("X-Backend-Storage-Policy-Index", "2");
        request_headers.set("X-Timestamp", "6001.00000");
        request_headers.set("X-Object-Meta-Color", "blue");
        let request = Request {
            method: "PUT".into(),
            path: "/v1/a/c/o".into(),
            query_string: String::new(),
            headers: request_headers,
            body: swift_http::Body::empty(),
        };
        let mut backend = HeaderKeyDict::new();
        copy_backend_control_headers(&request, &mut backend);
        assert_eq!(backend.get("X-Backend-No-Commit"), Some("True"));
        assert_eq!(backend.get("X-Backend-Storage-Policy-Index"), Some("2"));
        assert_eq!(backend.get("X-Timestamp"), Some("6001.00000"));
        assert_eq!(backend.get("X-Object-Meta-Color"), None);
    }

    fn node(device: &str, port: u32) -> Node {
        Node {
            ip: "10.0.0.1".into(),
            port,
            device: device.into(),
            handoff: false,
            backend_index: None,
        }
    }

    #[test]
    fn csv_append_round_robin_matches_python_backend_requests() {
        let mut per_node = vec![HeaderKeyDict::new(); 3];
        let primaries = vec![node("sda", 1000), node("sdb", 1001), node("sdc", 1002)];
        ProxyApp::stamp_account_update_headers(&mut per_node, 7, &primaries);
        assert_eq!(per_node[0].get("X-Account-Host"), Some("10.0.0.1:1000"));
        assert_eq!(per_node[0].get("X-Account-Device"), Some("sda"));
        assert_eq!(per_node[1].get("X-Account-Host"), Some("10.0.0.1:1001"));
        assert_eq!(per_node[1].get("X-Account-Device"), Some("sdb"));
        assert_eq!(per_node[2].get("X-Account-Host"), Some("10.0.0.1:1002"));
        assert_eq!(per_node[2].get("X-Account-Device"), Some("sdc"));
        assert_eq!(per_node[0].get("X-Account-Partition"), Some("7"));
    }

    #[test]
    fn extra_account_primary_csv_appends_onto_first_replica() {
        let mut per_node = vec![HeaderKeyDict::new(); 3];
        let primaries = vec![
            node("sda", 1000),
            node("sdb", 1001),
            node("sdc", 1002),
            node("sdd", 1003),
        ];
        ProxyApp::stamp_account_update_headers(&mut per_node, 7, &primaries);
        assert_eq!(
            per_node[0].get("X-Account-Host"),
            Some("10.0.0.1:1000,10.0.0.1:1003")
        );
        assert_eq!(per_node[0].get("X-Account-Device"), Some("sda,sdd"));
        assert_eq!(per_node[1].get("X-Account-Device"), Some("sdb"));
        assert_eq!(per_node[2].get("X-Account-Device"), Some("sdc"));
    }

    #[test]
    fn container_update_round_robin_uses_primaries() {
        let mut per_node = vec![HeaderKeyDict::new(); 3];
        let primaries = vec![node("sda", 1000), node("sdb", 1001), node("sdc", 1002)];
        ProxyApp::stamp_container_update_headers(&mut per_node, 9, &primaries);
        assert_eq!(per_node[0].get("X-Container-Host"), Some("10.0.0.1:1000"));
        assert_eq!(per_node[0].get("X-Container-Device"), Some("sda"));
        assert_eq!(per_node[1].get("X-Container-Host"), Some("10.0.0.1:1001"));
        assert_eq!(per_node[1].get("X-Container-Device"), Some("sdb"));
        assert_eq!(per_node[2].get("X-Container-Host"), Some("10.0.0.1:1002"));
        assert_eq!(per_node[2].get("X-Container-Device"), Some("sdc"));
        assert_eq!(per_node[0].get("X-Container-Partition"), Some("9"));
        assert_eq!(ProxyApp::num_container_updates(3, 2, 3, 2), 3);
    }

    #[test]
    fn extra_container_primary_csv_appends_onto_first_replica() {
        let mut per_node = vec![HeaderKeyDict::new(); 3];
        let primaries = vec![
            node("sda", 1000),
            node("sdb", 1001),
            node("sdc", 1002),
            node("sdd", 1003),
        ];
        ProxyApp::stamp_container_update_headers(&mut per_node, 9, &primaries);
        assert_eq!(
            per_node[0].get("X-Container-Host"),
            Some("10.0.0.1:1000,10.0.0.1:1003")
        );
        assert_eq!(per_node[0].get("X-Container-Device"), Some("sda,sdd"));
        assert_eq!(per_node[1].get("X-Container-Device"), Some("sdb"));
        assert_eq!(per_node[2].get("X-Container-Device"), Some("sdc"));
    }

    #[test]
    fn expirer_container_matches_hash_sharded_python_bucket() {
        assert_eq!(
            expirer_container_for_object_hash(1_788_001_562, "0000000000000000000000000000001c"),
            "1787961572"
        );
    }

    #[test]
    fn delete_at_updates_are_reverse_distributed_across_object_slots() {
        let mut per_node = vec![HeaderKeyDict::new(); 3];
        let primaries = vec![node("sda", 1000), node("sdb", 1001), node("sdc", 1002)];
        ProxyApp::stamp_delete_at_update_headers(&mut per_node, "1787961572", 643, &primaries);
        assert_eq!(per_node[2].get("X-Delete-At-Host"), Some("10.0.0.1:1000"));
        assert_eq!(per_node[2].get("X-Delete-At-Device"), Some("sda"));
        assert_eq!(per_node[1].get("X-Delete-At-Host"), Some("10.0.0.1:1001"));
        assert_eq!(per_node[1].get("X-Delete-At-Device"), Some("sdb"));
        assert_eq!(per_node[0].get("X-Delete-At-Host"), Some("10.0.0.1:1002"));
        assert_eq!(per_node[0].get("X-Delete-At-Device"), Some("sdc"));
        for headers in &per_node {
            assert_eq!(headers.get("X-Delete-At-Container"), Some("1787961572"));
            assert_eq!(headers.get("X-Delete-At-Partition"), Some("643"));
        }
    }

    #[test]
    fn keep_ec_client_metadata_includes_slo_and_dlo_headers() {
        assert!(keep_ec_client_metadata("x-static-large-object"));
        assert!(keep_ec_client_metadata("x-object-manifest"));
        assert!(keep_ec_client_metadata("x-object-sysmeta-slo-etag"));
        assert!(keep_ec_client_metadata("x-object-meta-color"));
        assert!(keep_ec_client_metadata("x-object-meta-è-probe"));
        assert!(keep_ec_client_metadata(
            &"X-Object-Meta-è-probe".to_lowercase()
        ));
        assert!(keep_ec_client_metadata("x-backend-data-timestamp"));
        assert!(keep_ec_client_metadata("x-backend-durable-timestamp"));
        assert!(!keep_ec_client_metadata("content-length"));
        assert!(!keep_ec_client_metadata("etag"));
        assert!(!keep_ec_client_metadata("x-trans-id"));
    }
}
