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

//! The container-sync daemon core, ported from `swift/container/sync.py`,
//! `swift/container/sync_store.py`, and realm signing in
//! `swift/common/container_sync_realms.py`.
//!
//! A container with `X-Container-Sync-To` and `X-Container-Sync-Key` mirrors
//! its object rows to another container. Two ROWID watermarks
//! (`x_container_sync_point1` / `point2`) drive a two-pass schedule: pass A
//! backfills rows between point2 and point1 (all replicas), pass B ships a
//! hash-shard of rows newer than point1 (primary-node share). Each remote
//! request is authenticated with either realm HMAC (`X-Container-Sync-Auth`)
//! or the legacy `X-Container-Sync-Key` header.
//!
//! Deployable surface:
//! - [`run_once`] / binary `swift-container-sync` walks the sync store
//! - [`HttpSyncClient`] issues signed PUT/DELETE over HTTP/1.1
//! - [`SyncClient`] trait is mockable for unit tests
//!
//! Residual vs Python: remote HEAD-before-PUT short-circuit, InternalClient
//! object GET (PUT body is supplied by [`ObjectSource`]), ring ordinal
//! locality filter (caller can pass `ordinal`/`replica_count`), and live
//! multi-cluster soak. HTTPS remotes use `native-tls` with system roots by
//! default; optional `[container-sync] ssl_ca_file` and
//! `insecure_skip_verify` (default **false**) tune verification.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use hmac::{Hmac, Mac};
use sha1::Sha1;
use swift_core::config::config_true_value;
use swift_core::hashing::HashPathConfig;
use swift_core::timestamp::Timestamp;
use swift_db::{db_locations, ContainerBroker, DbError, DbValue};
use swift_http::normalize_etag;

type HmacSha1 = Hmac<Sha1>;

// ---------------------------------------------------------------------------
// Realm signing (Python ContainerSyncRealms.get_sig)
// ---------------------------------------------------------------------------

/// `ContainerSyncRealms.get_sig`: HMAC-SHA1 hexdigest authenticating a
/// container-sync request. Message is
/// `"{method}\n{path}\n{x_timestamp}\n{nonce}\n{user_key}"` keyed by the
/// realm key.
pub fn get_sig(
    request_method: &str,
    path: &str,
    x_timestamp: &str,
    nonce: &str,
    realm_key: &str,
    user_key: &str,
) -> String {
    let mut mac =
        HmacSha1::new_from_slice(realm_key.as_bytes()).expect("HMAC accepts a key of any length");
    let msg = format!("{request_method}\n{path}\n{x_timestamp}\n{nonce}\n{user_key}");
    mac.update(msg.as_bytes());
    let digest = mac.finalize().into_bytes();
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// The `X-Container-Sync-Auth` header value: `"{realm} {nonce} {sig}"`.
pub fn sync_auth_header(realm: &str, nonce: &str, sig: &str) -> String {
    format!("{realm} {nonce} {sig}")
}

// ---------------------------------------------------------------------------
// Realms conf
// ---------------------------------------------------------------------------

/// One realm section from `container-sync-realms.conf`.
#[derive(Debug, Clone, Default)]
pub struct RealmData {
    pub key: Option<String>,
    pub key2: Option<String>,
    /// cluster name (upper) → endpoint URL
    pub clusters: HashMap<String, String>,
}

/// Parsed `container-sync-realms.conf` (Python `ContainerSyncRealms`).
#[derive(Debug, Clone, Default)]
pub struct ContainerSyncRealms {
    pub realms: HashMap<String, RealmData>,
}

impl ContainerSyncRealms {
    /// Parse an INI-style realms conf body.
    pub fn parse(content: &str) -> Self {
        let mut realms: HashMap<String, RealmData> = HashMap::new();
        let mut current: Option<String> = None;
        for raw in content.lines() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            if line.starts_with('[') && line.ends_with(']') {
                let name = line[1..line.len() - 1].trim();
                if name.eq_ignore_ascii_case("DEFAULT") {
                    current = None;
                    continue;
                }
                let upper = name.to_ascii_uppercase();
                realms.entry(upper.clone()).or_default();
                current = Some(upper);
                continue;
            }
            let Some(section) = current.as_ref() else {
                continue;
            };
            let Some((k, v)) = line.split_once('=') else {
                continue;
            };
            let (k, v) = (k.trim().to_ascii_lowercase(), v.trim().to_string());
            let entry = realms.entry(section.clone()).or_default();
            if k == "key" {
                entry.key = Some(v);
            } else if k == "key2" {
                entry.key2 = Some(v);
            } else if let Some(cluster) = k.strip_prefix("cluster_") {
                entry.clusters.insert(cluster.to_ascii_uppercase(), v);
            }
        }
        ContainerSyncRealms { realms }
    }

    pub fn load(path: &Path) -> Self {
        let content = std::fs::read_to_string(path).unwrap_or_default();
        Self::parse(&content)
    }

    pub fn realm_names(&self) -> Vec<String> {
        self.realms.keys().cloned().collect()
    }

    pub fn key(&self, realm: &str) -> Option<&str> {
        self.realms
            .get(&realm.to_ascii_uppercase())
            .and_then(|r| r.key.as_deref())
    }

    pub fn key2(&self, realm: &str) -> Option<&str> {
        self.realms
            .get(&realm.to_ascii_uppercase())
            .and_then(|r| r.key2.as_deref())
    }

    pub fn clusters(&self, realm: &str) -> Vec<String> {
        self.realms
            .get(&realm.to_ascii_uppercase())
            .map(|r| r.clusters.keys().cloned().collect())
            .unwrap_or_default()
    }

    pub fn endpoint(&self, realm: &str, cluster: &str) -> Option<&str> {
        self.realms
            .get(&realm.to_ascii_uppercase())
            .and_then(|r| r.clusters.get(&cluster.to_ascii_uppercase()))
            .map(|s| s.as_str())
    }

    /// Shape for proxy `/info` → `container_sync.realms`.
    pub fn info_realms(&self, current: Option<(&str, &str)>) -> serde_json::Value {
        let mut dct = serde_json::Map::new();
        for (realm, data) in &self.realms {
            if data.clusters.is_empty() {
                continue;
            }
            let mut clusters = serde_json::Map::new();
            for c in data.clusters.keys() {
                let mut entry = serde_json::Map::new();
                if let Some((cr, cc)) = current {
                    if realm.eq_ignore_ascii_case(cr) && c.eq_ignore_ascii_case(cc) {
                        entry.insert("current".into(), serde_json::Value::Bool(true));
                    }
                }
                clusters.insert(c.clone(), serde_json::Value::Object(entry));
            }
            dct.insert(realm.clone(), serde_json::json!({ "clusters": clusters }));
        }
        serde_json::Value::Object(dct)
    }
}

// ---------------------------------------------------------------------------
// validate_sync_to
// ---------------------------------------------------------------------------

/// Result of validating `X-Container-Sync-To`.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidatedSyncTo {
    pub endpoint: String,
    pub realm: Option<String>,
    pub realm_key: Option<String>,
}

/// `validate_sync_to` from `swift/common/utils`.
pub fn validate_sync_to(
    value: &str,
    allowed_sync_hosts: &[String],
    realms: &ContainerSyncRealms,
) -> Result<Option<ValidatedSyncTo>, String> {
    let orig = value;
    let value = value.trim_end_matches('/');
    if value.is_empty() {
        return Ok(None);
    }
    if let Some(rest) = value.strip_prefix("//") {
        let data: Vec<&str> = rest.split('/').collect();
        if data.len() != 4 {
            return Err(format!("Invalid X-Container-Sync-To format {orig:?}"));
        }
        let (realm, cluster, account, container) = (data[0], data[1], data[2], data[3]);
        let realm_key = realms
            .key(realm)
            .ok_or_else(|| format!("No realm key for {realm:?}"))?
            .to_string();
        let endpoint = realms
            .endpoint(realm, cluster)
            .ok_or_else(|| format!("No cluster endpoint for {realm:?} {cluster:?}"))?;
        return Ok(Some(ValidatedSyncTo {
            endpoint: format!(
                "{}/{}/{}",
                endpoint.trim_end_matches('/'),
                account,
                container
            ),
            realm: Some(realm.to_ascii_uppercase()),
            realm_key: Some(realm_key),
        }));
    }
    // Full URL path: scheme://host[:port]/path
    let rest = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))
        .ok_or_else(|| {
            "Invalid scheme in X-Container-Sync-To, must be \"//\",                  \"http\", or \"https\".".to_string()
        })?;
    let scheme = if value.starts_with("https://") {
        "https"
    } else {
        "http"
    };
    let (hostport, path) = rest
        .split_once('/')
        .map(|(h, p)| (h, format!("/{p}")))
        .ok_or_else(|| "Path required in X-Container-Sync-To".to_string())?;
    if path.contains('?') || path.contains('#') || path.contains(';') {
        return Err("Params, queries, and fragments not allowed in X-Container-Sync-To".into());
    }
    let hostname = hostport
        .split(':')
        .next()
        .unwrap_or(hostport)
        .trim_start_matches('[')
        .trim_end_matches(']');
    if !allowed_sync_hosts.iter().any(|h| h == hostname) {
        return Err(format!("Invalid host {hostname:?} in X-Container-Sync-To"));
    }
    Ok(Some(ValidatedSyncTo {
        endpoint: format!("{scheme}://{hostport}{path}"),
        realm: None,
        realm_key: None,
    }))
}

// ---------------------------------------------------------------------------
// Sync store (symlink index under sync_containers/)
// ---------------------------------------------------------------------------

pub const SYNC_DATADIR: &str = "sync_containers";
const CONTAINERS_DATADIR: &str = "containers";

/// Filesystem store of containers that need syncing (Python `ContainerSyncStore`).
#[derive(Debug, Clone)]
pub struct ContainerSyncStore {
    pub devices: PathBuf,
}

impl ContainerSyncStore {
    pub fn new(devices: impl Into<PathBuf>) -> Self {
        ContainerSyncStore {
            devices: devices.into(),
        }
    }

    fn container_to_synced_path(&self, db_file: &Path) -> Option<PathBuf> {
        let db_str = db_file.to_string_lossy();
        let marker = format!("/{CONTAINERS_DATADIR}/");
        let idx = db_str.find(&marker)?;
        let devices_and_device = &db_str[..idx];
        let rest = &db_str[idx + marker.len()..];
        Some(PathBuf::from(format!(
            "{devices_and_device}/{SYNC_DATADIR}/{rest}"
        )))
    }

    fn synced_to_container_path(&self, sync_file: &Path) -> Option<PathBuf> {
        let s = sync_file.to_string_lossy();
        let marker = format!("/{SYNC_DATADIR}/");
        let idx = s.find(&marker)?;
        let devices_and_device = &s[..idx];
        let rest = &s[idx + marker.len()..];
        Some(PathBuf::from(format!(
            "{devices_and_device}/{CONTAINERS_DATADIR}/{rest}"
        )))
    }

    /// Add a symlink for `db_file` under `sync_containers/`.
    pub fn add_synced_container(&self, db_file: &Path) -> std::io::Result<()> {
        let Some(sync_file) = self.container_to_synced_path(db_file) else {
            return Ok(());
        };
        if sync_file.exists() || sync_file.symlink_metadata().is_ok() {
            return Ok(());
        }
        if let Some(parent) = sync_file.parent() {
            std::fs::create_dir_all(parent)?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            match symlink(db_file, &sync_file) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
                Err(e) => Err(e),
            }
        }
        #[cfg(not(unix))]
        {
            // Non-unix: hardlink or copy is not ideal; record a stub file with
            // the real path for the generator to resolve.
            std::fs::write(&sync_file, db_file.to_string_lossy().as_bytes())
        }
    }

    pub fn remove_synced_container(&self, db_file: &Path) -> std::io::Result<()> {
        let Some(sync_file) = self.container_to_synced_path(db_file) else {
            return Ok(());
        };
        match std::fs::remove_file(&sync_file) {
            Ok(()) => {
                if let Some(parent) = sync_file.parent() {
                    let _ = std::fs::remove_dir(parent);
                }
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Add or remove based on broker metadata (Python `update_sync_store`).
    pub fn update_sync_store(&self, broker: &mut ContainerBroker) -> Result<(), DbError> {
        let md = broker.metadata()?;
        let has_to = md
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("X-Container-Sync-To"));
        let has_key = md
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("X-Container-Sync-Key"));
        if !has_to && !has_key {
            return Ok(());
        }
        if broker.is_deleted()? {
            let _ = self.remove_synced_container(broker.db_file());
            return Ok(());
        }
        let sync_to = md
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("X-Container-Sync-To"))
            .map(|(_, (v, _))| v.as_str())
            .unwrap_or("");
        let sync_key = md
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("X-Container-Sync-Key"))
            .map(|(_, (v, _))| v.as_str())
            .unwrap_or("");
        if !sync_to.is_empty() && !sync_key.is_empty() {
            let _ = self.add_synced_container(broker.db_file());
        } else {
            let _ = self.remove_synced_container(broker.db_file());
        }
        Ok(())
    }

    /// Yield real container DB paths linked from every device's sync store.
    pub fn synced_containers(&self) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let Ok(entries) = std::fs::read_dir(&self.devices) else {
            return out;
        };
        for e in entries.flatten() {
            let device = e.path();
            if !device.is_dir() {
                continue;
            }
            for link in db_locations(&device, SYNC_DATADIR) {
                if let Some(real) = self.synced_to_container_path(&link) {
                    if real.exists() {
                        out.push(real);
                    } else {
                        // Stale symlink: drop it.
                        let _ = std::fs::remove_file(&link);
                    }
                }
            }
        }
        out.sort();
        out
    }
}

// ---------------------------------------------------------------------------
// Row model + SyncClient
// ---------------------------------------------------------------------------

/// One object row to mirror to the remote container.
#[derive(Debug, Clone, PartialEq)]
pub struct SyncRow {
    pub row_id: i64,
    pub name: String,
    pub created_at: String,
    pub deleted: bool,
    pub size: i64,
    pub content_type: String,
    pub etag: String,
}

/// The action taken for a synced row.
#[derive(Debug, Clone, PartialEq)]
pub enum SyncAction {
    /// A live row -> PUT the object to the remote.
    Put,
    /// A tombstone row -> DELETE the object on the remote.
    Delete,
}

impl SyncRow {
    pub fn action(&self) -> SyncAction {
        if self.deleted {
            SyncAction::Delete
        } else {
            SyncAction::Put
        }
    }

    /// Data timestamp for DELETE (first component of Swift's compact
    /// `encode_timestamps` representation).
    pub fn ts_data(&self) -> Option<Timestamp> {
        decode_row_timestamps(&self.created_at).map(|(data, _, _)| data)
    }

    /// Meta timestamp for PUT (third decoded component, defaulting through
    /// content-type to data when the compact deltas are absent).
    pub fn ts_meta(&self) -> Option<Timestamp> {
        decode_row_timestamps(&self.created_at).map(|(_, _, meta)| meta)
    }
}

/// Decode Python Swift's `encode_timestamps` form:
/// `<t1>[<+/-><t2-t1>[<+/-><t3-t2>]]`, where deltas are hexadecimal counts
/// of [`swift_core::timestamp::PRECISION`]. This is distinct from a
/// `Timestamp`'s optional `_hexoffset`; container rows use `+`/`-` deltas.
fn decode_row_timestamps(encoded: &str) -> Option<(Timestamp, Timestamp, Timestamp)> {
    let first_sign = encoded.find(['+', '-']).unwrap_or(encoded.len());
    let data: Timestamp = encoded.get(..first_sign)?.parse().ok()?;
    let mut deltas = Vec::new();
    let mut cursor = first_sign;
    while cursor < encoded.len() {
        let sign = match encoded.as_bytes().get(cursor)? {
            b'+' => 1i64,
            b'-' => -1i64,
            _ => return None,
        };
        let start = cursor + 1;
        let rest = encoded.get(start..)?;
        let next = rest.find(['+', '-']).map(|offset| start + offset);
        let end = next.unwrap_or(encoded.len());
        let raw = encoded.get(start..end)?;
        if raw.is_empty() {
            return None;
        }
        let magnitude = i64::from_str_radix(raw, 16).ok()?;
        deltas.push(sign.checked_mul(magnitude)?);
        if deltas.len() > 2 {
            return None;
        }
        cursor = end;
    }

    let content_type = match deltas.first().copied().unwrap_or(0) {
        0 => data,
        delta => data.normalized().apply_delta(delta).ok()?,
    };
    let metadata = match deltas.get(1).copied().unwrap_or(0) {
        0 => content_type,
        delta => content_type.normalized().apply_delta(delta).ok()?,
    };
    Some((data, content_type, metadata))
}

/// Context for one remote sync operation (auth material + destination).
#[derive(Debug, Clone)]
pub struct SyncContext {
    pub sync_to: String,
    pub user_key: String,
    pub realm: Option<String>,
    pub realm_key: Option<String>,
    pub account: String,
    pub container: String,
    /// Storage policy index of the source container (for local object GET).
    pub storage_policy_index: i64,
}

/// Abstraction over "mirror one row to the remote container".
pub trait SyncClient {
    /// Send the row (PUT or DELETE) to the remote. Returns `true` on success.
    fn sync_row(&self, row: &SyncRow, action: &SyncAction, ctx: &SyncContext) -> bool;
}

/// Optional local object body source for PUT (Python InternalClient.get_object).
pub trait ObjectSource: Send + Sync {
    /// Returns (headers as key/value pairs, body bytes) for a live object.
    fn get_object(
        &self,
        account: &str,
        container: &str,
        name: &str,
        storage_policy_index: i64,
    ) -> Option<(Vec<(String, String)>, Vec<u8>)>;
}

/// No-op object source (DELETE-only / tests that do not exercise PUT body).
pub struct EmptyObjectSource;
impl ObjectSource for EmptyObjectSource {
    fn get_object(
        &self,
        _account: &str,
        _container: &str,
        _name: &str,
        _storage_policy_index: i64,
    ) -> Option<(Vec<(String, String)>, Vec<u8>)> {
        None
    }
}

/// Map-backed object source for unit tests.
pub struct MapObjectSource {
    pub objects: HashMap<String, (Vec<(String, String)>, Vec<u8>)>,
}
impl ObjectSource for MapObjectSource {
    fn get_object(
        &self,
        account: &str,
        container: &str,
        name: &str,
        _storage_policy_index: i64,
    ) -> Option<(Vec<(String, String)>, Vec<u8>)> {
        self.objects
            .get(&format!("{account}/{container}/{name}"))
            .cloned()
    }
}

// ---------------------------------------------------------------------------
// Auth header builder + HTTP remote client
// ---------------------------------------------------------------------------

/// Build remote request headers for a sync operation.
pub fn build_sync_headers(
    method: &str,
    object_name: &str,
    sync_to: &str,
    user_key: &str,
    realm: Option<&str>,
    realm_key: Option<&str>,
    x_timestamp: &str,
    nonce: &str,
    extra: &[(String, String)],
) -> Vec<(String, String)> {
    let mut headers: Vec<(String, String)> = vec![("x-timestamp".into(), x_timestamp.into())];
    headers.extend(extra.iter().cloned());
    if let (Some(realm), Some(realm_key)) = (realm, realm_key) {
        let path = format!("{}/{}", url_path(sync_to), percent_encode_path(object_name));
        let sig = get_sig(method, &path, x_timestamp, nonce, realm_key, user_key);
        headers.push((
            "x-container-sync-auth".into(),
            sync_auth_header(realm, nonce, &sig),
        ));
    } else {
        headers.push(("x-container-sync-key".into(), user_key.into()));
    }
    headers
}

fn url_path(sync_to: &str) -> String {
    // strip scheme://host[:port]
    if let Some(rest) = sync_to
        .strip_prefix("https://")
        .or_else(|| sync_to.strip_prefix("http://"))
    {
        if let Some(idx) = rest.find('/') {
            return rest[idx..].trim_end_matches('/').to_string();
        }
    }
    sync_to.trim_end_matches('/').to_string()
}

fn percent_encode_path(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Parse `http[s]://host[:port]/path` into (host, port, path, use_tls).
/// Public for unit tests of scheme / default-port selection.
pub fn parse_http_url(url: &str) -> Option<(String, u16, String, bool)> {
    let (rest, tls) = if let Some(r) = url.strip_prefix("https://") {
        (r, true)
    } else {
        let r = url.strip_prefix("http://")?;
        (r, false)
    };
    let (hostport, path) = match rest.split_once('/') {
        Some((h, p)) => (h, format!("/{p}")),
        None => (rest, "/".to_string()),
    };
    let (host, port) = if let Some((h, p)) = hostport.rsplit_once(':') {
        if h.starts_with('[') {
            // IPv6 literal — keep simple: no bracketed support beyond default
            (hostport.to_string(), if tls { 443 } else { 80 })
        } else if let Ok(port) = p.parse::<u16>() {
            (h.to_string(), port)
        } else {
            (hostport.to_string(), if tls { 443 } else { 80 })
        }
    } else {
        (hostport.to_string(), if tls { 443 } else { 80 })
    };
    Some((host, port, path, tls))
}

/// Read the HTTP status line from a raw response buffer.
fn status_from_response_buf(buf: &[u8]) -> u16 {
    let head = String::from_utf8_lossy(buf);
    let line = head.lines().next().unwrap_or("");
    line.split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

/// TLS verification knobs for outbound HTTPS sync (and optional CA pin).
///
/// Defaults are **secure**: system trust store, certificate verification on.
/// `insecure_skip_verify` is only for lab / self-signed remotes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TlsOptions {
    /// Optional PEM bundle of extra root CAs (`ssl_ca_file`).
    pub ssl_ca_file: Option<PathBuf>,
    /// When true, accept invalid certs/hostnames (default **false**).
    pub insecure_skip_verify: bool,
}

/// Build a `native-tls` connector from [`TlsOptions`].
///
/// Returns `Err` if the CA file is missing/unreadable or PEM is invalid.
pub fn build_tls_connector(opts: &TlsOptions) -> Result<native_tls::TlsConnector, String> {
    let mut builder = native_tls::TlsConnector::builder();
    if opts.insecure_skip_verify {
        builder.danger_accept_invalid_certs(true);
        builder.danger_accept_invalid_hostnames(true);
    }
    if let Some(path) = &opts.ssl_ca_file {
        let pem =
            std::fs::read(path).map_err(|e| format!("ssl_ca_file read {}: {e}", path.display()))?;
        let cert = native_tls::Certificate::from_pem(&pem)
            .map_err(|e| format!("ssl_ca_file parse {}: {e}", path.display()))?;
        builder.add_root_certificate(cert);
    }
    builder
        .build()
        .map_err(|e| format!("tls connector build: {e}"))
}

/// Issue a bare HTTP/1.1 request; returns status code (0 on transport error).
///
/// HTTPS uses `native-tls` (system trust store by default). Pass
/// [`TlsOptions`] for custom CA (`ssl_ca_file`) or lab-only
/// `insecure_skip_verify` (defaults secure).
pub fn http_request(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: &[u8],
    timeout: Duration,
) -> u16 {
    http_request_with_tls(method, url, headers, body, timeout, &TlsOptions::default())
}

/// Like [`http_request`] with explicit TLS options.
pub fn http_request_with_tls(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: &[u8],
    timeout: Duration,
    tls_opts: &TlsOptions,
) -> u16 {
    let Some((host, port, path, tls)) = parse_http_url(url) else {
        return 0;
    };
    // Omit default ports from Host (RFC 7230).
    let host_header = if (!tls && port == 80) || (tls && port == 443) {
        host.clone()
    } else {
        format!("{host}:{port}")
    };
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    let Ok(mut conn) = TcpStream::connect(format!("{host}:{port}")) else {
        return 0;
    };
    let _ = conn.set_read_timeout(Some(timeout));
    let _ = conn.set_write_timeout(Some(timeout));
    let _ = conn.set_nodelay(true);

    if tls {
        let Ok(connector) = build_tls_connector(tls_opts) else {
            return 0;
        };
        // SNI / cert CN uses the hostname (not host:port).
        let Ok(mut tls_stream) = connector.connect(&host, conn) else {
            return 0;
        };
        if tls_stream.write_all(req.as_bytes()).is_err() {
            return 0;
        }
        if !body.is_empty() && tls_stream.write_all(body).is_err() {
            return 0;
        }
        let mut buf = Vec::new();
        let _ = tls_stream.read_to_end(&mut buf);
        return status_from_response_buf(&buf);
    }

    if conn.write_all(req.as_bytes()).is_err() {
        return 0;
    }
    if !body.is_empty() && conn.write_all(body).is_err() {
        return 0;
    }
    let mut buf = Vec::new();
    let _ = conn.read_to_end(&mut buf);
    status_from_response_buf(&buf)
}

/// Production remote client: signs requests and issues HTTP PUT/DELETE.
/// PUT bodies come from [`ObjectSource`].
pub struct HttpSyncClient {
    pub object_source: Box<dyn ObjectSource>,
    pub timeout: Duration,
    pub tls: TlsOptions,
    nonce_counter: AtomicU64,
}

impl HttpSyncClient {
    pub fn new(object_source: Box<dyn ObjectSource>, timeout_secs: f64) -> Self {
        Self::with_tls(object_source, timeout_secs, TlsOptions::default())
    }

    pub fn with_tls(
        object_source: Box<dyn ObjectSource>,
        timeout_secs: f64,
        tls: TlsOptions,
    ) -> Self {
        HttpSyncClient {
            object_source,
            timeout: Duration::from_secs_f64(timeout_secs.max(0.1)),
            tls,
            nonce_counter: AtomicU64::new(1),
        }
    }

    fn next_nonce(&self) -> String {
        let n = self.nonce_counter.fetch_add(1, Ordering::Relaxed);
        format!("{n:032x}")
    }
}

fn newest_source_timestamp(row: &SyncRow, headers: &[(String, String)]) -> Option<String> {
    let source_raw = headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("x-timestamp"))
        .map(|(_, value)| value.as_str())?;
    let source = source_raw.parse::<Timestamp>().ok()?;
    let row_meta = row.ts_meta()?;
    (source >= row_meta).then(|| source.internal())
}

/// Match Python container-sync's response-header normalization before a
/// source object is replayed to the destination.  Public proxy responses may
/// quote ETags, while object PUT expects the bare digest.  Container listings
/// may also append an internal `swift_bytes` content-type parameter that must
/// not escape onto the destination object.
fn normalize_source_put_header(name: &str, value: String) -> String {
    if name.eq_ignore_ascii_case("etag") {
        return normalize_etag(&value).to_string();
    }
    if name.eq_ignore_ascii_case("content-type") {
        if let Some((content_type, parameter)) = value.rsplit_once(';') {
            if parameter.trim_start().starts_with("swift_bytes=") {
                return content_type.to_string();
            }
        }
    }
    value
}

impl SyncClient for HttpSyncClient {
    fn sync_row(&self, row: &SyncRow, action: &SyncAction, ctx: &SyncContext) -> bool {
        let url = format!(
            "{}/{}",
            ctx.sync_to.trim_end_matches('/'),
            percent_encode_path(&row.name)
        );
        let nonce = self.next_nonce();
        match action {
            SyncAction::Delete => {
                let Some(data_timestamp) = row.ts_data() else {
                    return false;
                };
                let headers = build_sync_headers(
                    "DELETE",
                    &row.name,
                    &ctx.sync_to,
                    &ctx.user_key,
                    ctx.realm.as_deref(),
                    ctx.realm_key.as_deref(),
                    &data_timestamp.internal(),
                    &nonce,
                    &[],
                );
                let status =
                    http_request_with_tls("DELETE", &url, &headers, &[], self.timeout, &self.tls);
                if !matches!(status, 200..=299 | 404 | 409) {
                    eprintln!("container-sync: destination DELETE status={status}");
                }
                // Python treats 404/409 as success for DELETE.
                matches!(status, 200..=299 | 404 | 409)
            }
            SyncAction::Put => {
                let Some((obj_headers, body)) = self.object_source.get_object(
                    &ctx.account,
                    &ctx.container,
                    &row.name,
                    ctx.storage_policy_index,
                ) else {
                    return false;
                };
                // The container row may be stale when an object-server PUT
                // could not update any container replica.  Python uses the
                // X-Newest object GET's X-Timestamp for the destination PUT,
                // and refuses to advance the sync point if that object is
                // older than the row's metadata timestamp.
                let Some(ts) = newest_source_timestamp(row, &obj_headers) else {
                    return false;
                };
                // Strip hop-by-hop / framing headers from the proxy GET.
                // Forwarding Transfer-Encoding / Content-Length (we recompute
                // CL from body) makes the remote PUT fail with 4xx/5xx and
                // every row lands as a sync failure.
                let mut extra: Vec<(String, String)> = obj_headers
                    .into_iter()
                    .filter(|(k, _)| {
                        let l = k.to_ascii_lowercase();
                        !matches!(
                            l.as_str(),
                            "date"
                                | "last-modified"
                                | "x-timestamp"
                                | "transfer-encoding"
                                | "content-length"
                                | "connection"
                                | "keep-alive"
                                | "proxy-connection"
                                | "te"
                                | "trailer"
                                | "upgrade"
                                | "server"
                                | "www-authenticate"
                                | "x-trans-id"
                                | "x-openstack-request-id"
                                | "accept-ranges"
                        )
                    })
                    .map(|(name, value)| {
                        let value = normalize_source_put_header(&name, value);
                        (name, value)
                    })
                    .collect();
                if !extra.iter().any(|(k, _)| k.eq_ignore_ascii_case("etag"))
                    && !row.etag.is_empty()
                {
                    extra.push(("etag".into(), row.etag.clone()));
                }
                if !extra
                    .iter()
                    .any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                    && !row.content_type.is_empty()
                {
                    extra.push(("content-type".into(), row.content_type.clone()));
                }
                let headers = build_sync_headers(
                    "PUT",
                    &row.name,
                    &ctx.sync_to,
                    &ctx.user_key,
                    ctx.realm.as_deref(),
                    ctx.realm_key.as_deref(),
                    &ts,
                    &nonce,
                    &extra,
                );
                let status =
                    http_request_with_tls("PUT", &url, &headers, &body, self.timeout, &self.tls);
                if !(200..300).contains(&status) {
                    eprintln!("container-sync: destination PUT status={status}");
                }
                (200..300).contains(&status)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Two-pass row processing + stats
// ---------------------------------------------------------------------------

/// Sweep stats for one container or a whole pass.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SyncStats {
    pub deletes: u64,
    pub puts: u64,
    pub failures: u64,
    pub skips: u64,
    pub syncs: u64,
    /// Highest fully-synced row id after a simple batch (test helper).
    pub sync_point: i64,
    /// Final point1 / point2 after a container pass.
    pub sync_point1: i64,
    pub sync_point2: i64,
}

/// Sync a batch of rows (already ordered by row id ascending). Advances the
/// sync point past each successful row; a failure stops the advance so the
/// row is retried next pass.
pub fn sync_rows(rows: &[SyncRow], start_point: i64, client: &dyn SyncClient) -> SyncStats {
    let ctx = SyncContext {
        sync_to: String::new(),
        user_key: String::new(),
        realm: None,
        realm_key: None,
        account: String::new(),
        container: String::new(),
        storage_policy_index: 0,
    };
    let mut stats = SyncStats {
        sync_point: start_point,
        sync_point1: start_point,
        sync_point2: start_point,
        ..Default::default()
    };
    for row in rows {
        let action = row.action();
        if client.sync_row(row, &action, &ctx) {
            match action {
                SyncAction::Put => stats.puts += 1,
                SyncAction::Delete => stats.deletes += 1,
            }
            stats.sync_point = row.row_id;
        } else {
            stats.failures += 1;
            break;
        }
    }
    stats
}

/// Whether this primary ordinal owns `object_name` for the initial pass
/// (`unpack_from('>I', hash_path(..., raw_digest=True))[0] % replica_count`).
pub fn owns_object(
    hash_config: &HashPathConfig,
    account: &str,
    container: &str,
    object_name: &str,
    ordinal: usize,
    replica_count: usize,
) -> bool {
    if replica_count == 0 {
        return true;
    }
    let Ok(raw) = hash_config.hash_path_raw(account, Some(container), Some(object_name)) else {
        return true;
    };
    let n = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize;
    n % replica_count == ordinal
}

/// Process one container DB: two-pass sync and advance watermarks.
///
/// `ordinal` / `replica_count` control the point1 hash-shard (pass 0/1 for
/// single-node tests that ship every new row).
pub fn process_container_db(
    db_path: &Path,
    client: &dyn SyncClient,
    realms: &ContainerSyncRealms,
    allowed_sync_hosts: &[String],
    hash_config: &HashPathConfig,
    ordinal: usize,
    replica_count: usize,
    container_time_secs: u64,
) -> SyncStats {
    let mut stats = SyncStats::default();
    let mut broker = ContainerBroker::new(db_path, "", "");
    let info = match broker.get_info() {
        Ok(i) => i,
        Err(_) => {
            stats.failures += 1;
            return stats;
        }
    };
    let get = |k: &str| -> String {
        info.iter()
            .find(|(n, _)| n == k)
            .map(|(_, v)| match v {
                DbValue::Text(s) => s.clone(),
                DbValue::Int(i) => i.to_string(),
                DbValue::Null => String::new(),
            })
            .unwrap_or_default()
    };
    let account = get("account");
    let container = get("container");
    // Rebind broker with real account/container for metadata path.
    let mut broker = ContainerBroker::new(db_path, &account, &container);
    if broker.is_deleted().unwrap_or(true) {
        stats.skips += 1;
        return stats;
    }
    let md = broker.metadata().unwrap_or_default();
    let versions_enabled = md
        .iter()
        .find(|(key, _)| {
            key.eq_ignore_ascii_case("X-Container-Sysmeta-Versions-Enabled")
        })
        .map(|(_, (value, _))| value.as_str())
        .unwrap_or("");
    // Python object-versioning and container-sync deliberately do not share
    // a source container: container-sync cannot preserve prior versions.
    // Fail closed if an internal pipeline bypass produced both metadata
    // families on one DB.
    if config_true_value(versions_enabled) {
        stats.skips += 1;
        return stats;
    }
    let sync_to = md
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("X-Container-Sync-To"))
        .map(|(_, (v, _))| v.clone())
        .unwrap_or_default();
    let user_key = md
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("X-Container-Sync-Key"))
        .map(|(_, (v, _))| v.clone())
        .unwrap_or_default();
    if sync_to.is_empty() || user_key.is_empty() {
        stats.skips += 1;
        return stats;
    }
    let validated = match validate_sync_to(&sync_to, allowed_sync_hosts, realms) {
        Ok(Some(v)) => v,
        Ok(None) => {
            stats.skips += 1;
            return stats;
        }
        Err(_) => {
            stats.failures += 1;
            return stats;
        }
    };
    let mut sync_point1: i64 = info
        .iter()
        .find(|(n, _)| n == "x_container_sync_point1")
        .and_then(|(_, v)| v.as_i64())
        .unwrap_or(-1);
    let mut sync_point2: i64 = info
        .iter()
        .find(|(n, _)| n == "x_container_sync_point2")
        .and_then(|(_, v)| v.as_i64())
        .unwrap_or(-1);
    let storage_policy_index: i64 = info
        .iter()
        .find(|(n, _)| n == "storage_policy_index")
        .and_then(|(_, v)| v.as_i64())
        .unwrap_or(0);

    let ctx = SyncContext {
        sync_to: validated.endpoint,
        user_key,
        realm: validated.realm,
        realm_key: validated.realm_key,
        account: account.clone(),
        container: container.clone(),
        storage_policy_index,
    };

    let deadline = std::time::Instant::now() + Duration::from_secs(container_time_secs.max(1));
    let mut next_sync_point: Option<i64> = None;

    // Pass A: backfill rows with point2 < ROWID <= point1 (all replicas).
    while std::time::Instant::now() < deadline && sync_point2 < sync_point1 {
        let rows = match broker.get_items_since(sync_point2, 1) {
            Ok(r) => r,
            Err(_) => {
                stats.failures += 1;
                break;
            }
        };
        let Some((row_id, rec)) = rows.into_iter().next() else {
            break;
        };
        if row_id > sync_point1 {
            break;
        }
        let row = SyncRow {
            row_id,
            name: rec.name,
            created_at: rec.created_at,
            deleted: rec.deleted != 0,
            size: rec.size,
            content_type: rec.content_type,
            etag: rec.etag,
        };
        let action = row.action();
        if !client.sync_row(&row, &action, &ctx) {
            if next_sync_point.is_none() {
                next_sync_point = Some(sync_point2);
            }
            stats.failures += 1;
        } else {
            match action {
                SyncAction::Put => stats.puts += 1,
                SyncAction::Delete => stats.deletes += 1,
            }
        }
        sync_point2 = row_id;
        let _ = broker.set_x_container_sync_points(None, Some(sync_point2));
    }
    if let Some(p) = next_sync_point {
        let _ = broker.set_x_container_sync_points(None, Some(p));
        sync_point2 = p;
    }

    // Pass B: new rows above point1, hash-sharded by ordinal.
    while std::time::Instant::now() < deadline {
        let rows = match broker.get_items_since(sync_point1, 1) {
            Ok(r) => r,
            Err(_) => {
                stats.failures += 1;
                break;
            }
        };
        let Some((row_id, rec)) = rows.into_iter().next() else {
            break;
        };
        let row = SyncRow {
            row_id,
            name: rec.name.clone(),
            created_at: rec.created_at,
            deleted: rec.deleted != 0,
            size: rec.size,
            content_type: rec.content_type,
            etag: rec.etag,
        };
        if owns_object(
            hash_config,
            &account,
            &container,
            &rec.name,
            ordinal,
            replica_count,
        ) {
            let action = row.action();
            if client.sync_row(&row, &action, &ctx) {
                match action {
                    SyncAction::Put => stats.puts += 1,
                    SyncAction::Delete => stats.deletes += 1,
                }
            } else {
                stats.failures += 1;
            }
        }
        sync_point1 = row_id;
        let _ = broker.set_x_container_sync_points(Some(sync_point1), None);
    }

    stats.syncs += 1;
    stats.sync_point1 = sync_point1;
    stats.sync_point2 = sync_point2;
    stats.sync_point = sync_point1;
    stats
}

/// Walk every synced container under `devices` once.
pub fn run_once(
    devices: &Path,
    client: &dyn SyncClient,
    realms: &ContainerSyncRealms,
    allowed_sync_hosts: &[String],
    hash_config: &HashPathConfig,
    ordinal: usize,
    replica_count: usize,
    container_time_secs: u64,
) -> SyncStats {
    let store = ContainerSyncStore::new(devices);
    let mut total = SyncStats::default();
    for path in store.synced_containers() {
        let s = process_container_db(
            &path,
            client,
            realms,
            allowed_sync_hosts,
            hash_config,
            ordinal,
            replica_count,
            container_time_secs,
        );
        total.deletes += s.deletes;
        total.puts += s.puts;
        total.failures += s.failures;
        total.skips += s.skips;
        total.syncs += s.syncs;
    }
    total
}

/// Config knobs from `[container-sync]`.
#[derive(Debug, Clone)]
pub struct ContainerSyncConfig {
    pub devices: PathBuf,
    pub interval: u64,
    pub container_time: u64,
    pub allowed_sync_hosts: Vec<String>,
    pub conn_timeout: f64,
    pub realms_conf_path: PathBuf,
    pub mount_check: bool,
    /// Extra PEM CA file for HTTPS remotes (`ssl_ca_file`). Empty → none.
    pub ssl_ca_file: Option<PathBuf>,
    /// Skip TLS cert/hostname verify (default **false** / secure).
    pub insecure_skip_verify: bool,
}

impl Default for ContainerSyncConfig {
    fn default() -> Self {
        ContainerSyncConfig {
            devices: PathBuf::from("/srv/node"),
            interval: 300,
            container_time: 60,
            allowed_sync_hosts: vec!["127.0.0.1".into()],
            conn_timeout: 5.0,
            realms_conf_path: PathBuf::from("/etc/swift/container-sync-realms.conf"),
            mount_check: true,
            ssl_ca_file: None,
            insecure_skip_verify: false,
        }
    }
}

impl ContainerSyncConfig {
    /// Load from a parsed conf: `[container-sync]` with DEFAULT fallbacks.
    pub fn from_swift_conf(conf: &swift_core::config::SwiftConfig, swift_dir: &str) -> Self {
        let get = |section: &str, key: &str, default: &str| -> String {
            conf.get(section, key)
                .ok()
                .flatten()
                .or_else(|| conf.get("DEFAULT", key).ok().flatten())
                .or_else(|| conf.get("app:container-server", key).ok().flatten())
                .unwrap_or_else(|| default.to_string())
        };
        let hosts = get("container-sync", "allowed_sync_hosts", "127.0.0.1");
        let ca_raw = get("container-sync", "ssl_ca_file", "");
        let ssl_ca_file = {
            let t = ca_raw.trim();
            if t.is_empty() {
                None
            } else {
                Some(PathBuf::from(t))
            }
        };
        // Secure default: only explicit true-values enable skip-verify.
        let insecure_skip_verify =
            config_true_value(&get("container-sync", "insecure_skip_verify", "false"));
        ContainerSyncConfig {
            devices: PathBuf::from(get("container-sync", "devices", "/srv/node")),
            interval: get("container-sync", "interval", "300")
                .parse()
                .unwrap_or(300),
            container_time: get("container-sync", "container_time", "60")
                .parse()
                .unwrap_or(60),
            allowed_sync_hosts: hosts
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            conn_timeout: get("container-sync", "conn_timeout", "5")
                .parse()
                .unwrap_or(5.0),
            realms_conf_path: PathBuf::from(format!("{swift_dir}/container-sync-realms.conf")),
            mount_check: config_true_value(&get("container-sync", "mount_check", "true")),
            ssl_ca_file,
            insecure_skip_verify,
        }
    }

    /// TLS options for [`HttpSyncClient`] / [`http_request_with_tls`].
    pub fn tls_options(&self) -> TlsOptions {
        TlsOptions {
            ssl_ca_file: self.ssl_ca_file.clone(),
            insecure_skip_verify: self.insecure_skip_verify,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn test_get_sig_matches_python() {
        let sig = get_sig(
            "PUT",
            "/v1/AUTH_dst/dstcont/obj",
            "1751500000.00000",
            "deadbeefdeadbeefdeadbeefdeadbeef",
            "realmkey",
            "userkey",
        );
        assert_eq!(sig, "21f83a6e560fea0436cafaa95c1042449b45f4e6");
    }

    #[test]
    fn test_sync_auth_header() {
        assert_eq!(sync_auth_header("US", "nonce", "sig"), "US nonce sig");
    }

    #[test]
    fn test_source_put_headers_match_python_normalization() {
        assert_eq!(
            normalize_source_put_header("ETag", "\"7008d51685b171535a9114d25d60d18e\"".into()),
            "7008d51685b171535a9114d25d60d18e"
        );
        assert_eq!(
            normalize_source_put_header(
                "Content-Type",
                "application/octet-stream; swift_bytes=12".into(),
            ),
            "application/octet-stream"
        );
        assert_eq!(
            normalize_source_put_header(
                "Content-Type",
                "text/plain; charset=utf-8; swift_bytes=7".into(),
            ),
            "text/plain; charset=utf-8"
        );
        assert_eq!(
            normalize_source_put_header("X-Object-Meta-Test", "keep".into()),
            "keep"
        );
    }

    #[test]
    fn test_realms_parse_and_validate() {
        let conf = r#"
[realm1]
key = realm1key
cluster_c1 = http://127.0.0.1:8080/v1/
"#;
        let realms = ContainerSyncRealms::parse(conf);
        assert_eq!(realms.key("realm1"), Some("realm1key"));
        assert_eq!(
            realms.endpoint("REALM1", "C1"),
            Some("http://127.0.0.1:8080/v1/")
        );
        let v = validate_sync_to("//realm1/c1/a/c", &[], &realms)
            .unwrap()
            .unwrap();
        assert_eq!(v.endpoint, "http://127.0.0.1:8080/v1/a/c");
        assert_eq!(v.realm.as_deref(), Some("REALM1"));
        assert_eq!(v.realm_key.as_deref(), Some("realm1key"));

        let hosts = vec!["sync.example.com".into()];
        let v2 = validate_sync_to("http://sync.example.com/v1/a/c", &hosts, &realms)
            .unwrap()
            .unwrap();
        assert_eq!(v2.endpoint, "http://sync.example.com/v1/a/c");
        assert!(v2.realm.is_none());

        assert!(validate_sync_to("http://evil.com/v1/a/c", &hosts, &realms).is_err());
    }

    #[test]
    fn test_row_action() {
        assert_eq!(
            SyncRow {
                row_id: 1,
                name: "o".into(),
                created_at: "1".into(),
                deleted: false,
                size: 0,
                content_type: String::new(),
                etag: String::new(),
            }
            .action(),
            SyncAction::Put
        );
        assert_eq!(
            SyncRow {
                row_id: 2,
                name: "o".into(),
                created_at: "1".into(),
                deleted: true,
                size: 0,
                content_type: String::new(),
                etag: String::new(),
            }
            .action(),
            SyncAction::Delete
        );
    }

    struct FakeSync {
        sent: Mutex<Vec<(i64, SyncAction)>>,
        fail_at: Option<i64>,
    }
    impl SyncClient for FakeSync {
        fn sync_row(&self, row: &SyncRow, action: &SyncAction, _ctx: &SyncContext) -> bool {
            self.sent.lock().unwrap().push((row.row_id, action.clone()));
            self.fail_at != Some(row.row_id)
        }
    }

    #[test]
    fn test_sync_rows_advances_point() {
        let rows = vec![
            SyncRow {
                row_id: 1,
                name: "a".into(),
                created_at: "1".into(),
                deleted: false,
                size: 1,
                content_type: "t".into(),
                etag: "e".into(),
            },
            SyncRow {
                row_id: 2,
                name: "b".into(),
                created_at: "2".into(),
                deleted: true,
                size: 0,
                content_type: String::new(),
                etag: String::new(),
            },
            SyncRow {
                row_id: 3,
                name: "c".into(),
                created_at: "3".into(),
                deleted: false,
                size: 1,
                content_type: "t".into(),
                etag: "e".into(),
            },
        ];
        let client = FakeSync {
            sent: Mutex::new(Vec::new()),
            fail_at: None,
        };
        let stats = sync_rows(&rows, 0, &client);
        assert_eq!(stats.puts, 2);
        assert_eq!(stats.deletes, 1);
        assert_eq!(stats.sync_point, 3);
    }

    #[test]
    fn test_sync_rows_stops_on_failure() {
        let rows = vec![
            SyncRow {
                row_id: 1,
                name: "a".into(),
                created_at: "1".into(),
                deleted: false,
                size: 0,
                content_type: String::new(),
                etag: String::new(),
            },
            SyncRow {
                row_id: 2,
                name: "b".into(),
                created_at: "2".into(),
                deleted: false,
                size: 0,
                content_type: String::new(),
                etag: String::new(),
            },
            SyncRow {
                row_id: 3,
                name: "c".into(),
                created_at: "3".into(),
                deleted: false,
                size: 0,
                content_type: String::new(),
                etag: String::new(),
            },
        ];
        let client = FakeSync {
            sent: Mutex::new(Vec::new()),
            fail_at: Some(2),
        };
        let stats = sync_rows(&rows, 0, &client);
        assert_eq!(stats.sync_point, 1);
        assert_eq!(stats.failures, 1);
        assert_eq!(client.sent.lock().unwrap().len(), 2);
    }

    #[test]
    fn test_build_sync_headers_realm_and_legacy() {
        let h = build_sync_headers(
            "PUT",
            "obj",
            "http://127.0.0.1/v1/a/c",
            "uk",
            Some("R1"),
            Some("rk"),
            "1.0",
            "nonce",
            &[],
        );
        let auth = h
            .iter()
            .find(|(k, _)| k == "x-container-sync-auth")
            .map(|(_, v)| v.as_str())
            .unwrap();
        assert!(auth.starts_with("R1 nonce "));
        let path = "/v1/a/c/obj";
        let expected = get_sig("PUT", path, "1.0", "nonce", "rk", "uk");
        assert!(auth.ends_with(&expected));

        let h2 = build_sync_headers(
            "DELETE",
            "obj",
            "http://127.0.0.1/v1/a/c",
            "uk",
            None,
            None,
            "1.0",
            "n",
            &[],
        );
        assert!(h2
            .iter()
            .any(|(k, v)| k == "x-container-sync-key" && v == "uk"));
    }

    #[test]
    fn test_newest_source_timestamp_supersedes_stale_container_row() {
        let row = SyncRow {
            row_id: 1,
            name: "o".into(),
            created_at: "1751500000.00000".into(),
            deleted: false,
            size: 1,
            content_type: "text/plain".into(),
            etag: "old".into(),
        };
        let headers = vec![("X-Timestamp".into(), "1751500001.25000".into())];
        assert_eq!(
            newest_source_timestamp(&row, &headers).as_deref(),
            Some("1751500001.25000")
        );
    }

    #[test]
    fn test_decode_row_timestamps_matches_python_compact_deltas() {
        let (data, content_type, metadata) =
            decode_row_timestamps("1787757710.91367+3bf3+0").unwrap();
        assert_eq!(data.internal(), "1787757710.91367");
        assert_eq!(content_type.internal(), "1787757711.06714");
        assert_eq!(metadata.internal(), "1787757711.06714");

        let (data, content_type, metadata) =
            decode_row_timestamps("1751500003.00000-186a0+30d40").unwrap();
        assert_eq!(data.internal(), "1751500003.00000");
        assert_eq!(content_type.internal(), "1751500002.00000");
        assert_eq!(metadata.internal(), "1751500004.00000");

        let (data, content_type, metadata) =
            decode_row_timestamps("1751500000.00000_0000000000000002+0+0").unwrap();
        assert_eq!(data.offset(), 2);
        assert_eq!(content_type, data);
        assert_eq!(metadata, data);
    }

    #[test]
    fn test_sync_row_uses_decoded_meta_and_data_timestamps() {
        let row = SyncRow {
            row_id: 2,
            name: "o".into(),
            created_at: "1787757710.91367+3bf3+0".into(),
            deleted: false,
            size: 9,
            content_type: "image/jpeg".into(),
            etag: "etag".into(),
        };
        assert_eq!(
            row.ts_data().map(|timestamp| timestamp.internal()).as_deref(),
            Some("1787757710.91367")
        );
        assert_eq!(
            row.ts_meta().map(|timestamp| timestamp.internal()).as_deref(),
            Some("1787757711.06714")
        );
    }

    #[test]
    fn test_newest_source_timestamp_rejects_missing_or_older_object() {
        let row = SyncRow {
            row_id: 1,
            name: "o".into(),
            created_at: "1751500001.00000".into(),
            deleted: false,
            size: 1,
            content_type: "text/plain".into(),
            etag: "row".into(),
        };
        assert!(newest_source_timestamp(&row, &[]).is_none());
        assert!(newest_source_timestamp(
            &row,
            &[("x-timestamp".into(), "1751500000.00000".into())]
        )
        .is_none());
    }

    #[test]
    fn test_sync_store_add_remove_and_list() {
        let root = std::env::temp_dir().join(format!(
            "swift-sync-store-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let device = root.join("sdb");
        let db = device
            .join("containers")
            .join("0")
            .join("abc")
            .join("hash")
            .join("hash.db");
        std::fs::create_dir_all(db.parent().unwrap()).unwrap();
        std::fs::write(&db, b"x").unwrap();
        let store = ContainerSyncStore::new(&root);
        store.add_synced_container(&db).unwrap();
        let listed = store.synced_containers();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0], db);
        store.remove_synced_container(&db).unwrap();
        assert!(store.synced_containers().is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_process_container_db_two_pass_with_mock() {
        let root = std::env::temp_dir().join(format!(
            "swift-sync-proc-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let db = root.join("c.db");
        std::fs::create_dir_all(&root).unwrap();
        let ts = "1751500000.00000";
        let mut broker = ContainerBroker::new(&db, "a", "c");
        broker.initialize(ts, 0, ts, "dbid").unwrap();
        broker
            .update_metadata(&vec![
                (
                    "X-Container-Sync-To".into(),
                    ("http://127.0.0.1:9/v1/dst/c".into(), ts.into()),
                ),
                ("X-Container-Sync-Key".into(), ("secret".into(), ts.into())),
            ])
            .unwrap();
        for (i, name) in ["o1", "o2", "o3"].iter().enumerate() {
            broker
                .put_object(
                    name,
                    &format!("175150000{i}.00000"),
                    3,
                    "text/plain",
                    "abc",
                    0,
                    0,
                    None,
                    None,
                )
                .unwrap();
        }

        let client = FakeSync {
            sent: Mutex::new(Vec::new()),
            fail_at: None,
        };
        let realms = ContainerSyncRealms::default();
        let hosts = vec!["127.0.0.1".into()];
        let hash = HashPathConfig::new("changeme", "changeme").unwrap();
        // ordinal 0, replica_count 1 → owns every object
        let stats = process_container_db(&db, &client, &realms, &hosts, &hash, 0, 1, 60);
        assert_eq!(stats.puts, 3, "sent={:?}", client.sent.lock().unwrap());
        assert_eq!(stats.sync_point1, 3);
        assert_eq!(stats.failures, 0);
        let mut b = ContainerBroker::new(&db, "a", "c");
        let info = b.get_info().unwrap();
        let p1 = info
            .iter()
            .find(|(n, _)| n == "x_container_sync_point1")
            .and_then(|(_, v)| v.as_i64())
            .unwrap();
        assert_eq!(p1, 3);
        // Second pass: no new rows above point1; backfill may re-send.
        let client2 = FakeSync {
            sent: Mutex::new(Vec::new()),
            fail_at: None,
        };
        let stats2 = process_container_db(&db, &client2, &realms, &hosts, &hash, 0, 1, 60);
        assert_eq!(stats2.sync_point1, 3);
        // point2 should have advanced through the backfill window.
        assert!(stats2.sync_point2 >= 0);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_process_container_db_skips_object_versioning_source() {
        let root = std::env::temp_dir().join(format!(
            "swift-sync-versioned-skip-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let db = root.join("c.db");
        std::fs::create_dir_all(&root).unwrap();
        let ts = "1751500000.00000";
        let mut broker = ContainerBroker::new(&db, "a", "c");
        broker.initialize(ts, 0, ts, "dbid").unwrap();
        broker
            .update_metadata(&vec![
                (
                    "X-Container-Sync-To".into(),
                    ("http://127.0.0.1:9/v1/dst/c".into(), ts.into()),
                ),
                ("X-Container-Sync-Key".into(), ("secret".into(), ts.into())),
                (
                    "X-Container-Sysmeta-Versions-Enabled".into(),
                    ("True".into(), ts.into()),
                ),
            ])
            .unwrap();
        broker
            .put_object(
                "o1",
                ts,
                3,
                "text/plain",
                "abc",
                0,
                0,
                None,
                None,
            )
            .unwrap();

        let client = FakeSync {
            sent: Mutex::new(Vec::new()),
            fail_at: None,
        };
        let realms = ContainerSyncRealms::default();
        let hosts = vec!["127.0.0.1".into()];
        let hash = HashPathConfig::new("changeme", "changeme").unwrap();
        let stats = process_container_db(&db, &client, &realms, &hosts, &hash, 0, 1, 60);
        assert_eq!(stats.skips, 1);
        assert!(client.sent.lock().unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_info_realms_current() {
        let conf = r#"
[US]
key = k
cluster_east = http://east/v1/
cluster_west = http://west/v1/
"#;
        let realms = ContainerSyncRealms::parse(conf);
        let info = realms.info_realms(Some(("US", "EAST")));
        assert_eq!(info["US"]["clusters"]["EAST"]["current"], true);
        assert!(info["US"]["clusters"]["WEST"].get("current").is_none());
    }

    #[test]
    fn test_parse_http_url_scheme_and_ports() {
        let (h, p, path, tls) = parse_http_url("https://sync.example.com/v1/a/c/obj").unwrap();
        assert_eq!(h, "sync.example.com");
        assert_eq!(p, 443);
        assert_eq!(path, "/v1/a/c/obj");
        assert!(tls);

        let (h, p, path, tls) = parse_http_url("http://sync.example.com/v1/a/c").unwrap();
        assert_eq!(h, "sync.example.com");
        assert_eq!(p, 80);
        assert_eq!(path, "/v1/a/c");
        assert!(!tls);

        let (h, p, _, tls) = parse_http_url("https://sync.example.com:8443/v1/a").unwrap();
        assert_eq!(h, "sync.example.com");
        assert_eq!(p, 8443);
        assert!(tls);

        let (h, p, _, tls) = parse_http_url("http://127.0.0.1:8080/v1").unwrap();
        assert_eq!(h, "127.0.0.1");
        assert_eq!(p, 8080);
        assert!(!tls);

        assert!(parse_http_url("ftp://bad/path").is_none());
        assert!(parse_http_url("//no-scheme").is_none());
    }

    #[test]
    fn test_validate_sync_to_https_allowed_host() {
        let realms = ContainerSyncRealms::default();
        let hosts = vec!["secure.example.com".into()];
        let v = validate_sync_to("https://secure.example.com/v1/a/c", &hosts, &realms)
            .unwrap()
            .unwrap();
        assert_eq!(v.endpoint, "https://secure.example.com/v1/a/c");
        assert!(v.realm.is_none());
    }

    #[test]
    fn test_tls_options_default_is_secure() {
        let opts = TlsOptions::default();
        assert!(!opts.insecure_skip_verify);
        assert!(opts.ssl_ca_file.is_none());
        // Default connector must build (system roots).
        assert!(build_tls_connector(&opts).is_ok());
    }

    #[test]
    fn test_container_sync_config_tls_defaults_secure() {
        let conf = swift_core::config::SwiftConfig::parse_lenient(
            r#"
[container-sync]
devices = /tmp/node
"#,
            &[],
            false,
        )
        .unwrap();
        let cfg = ContainerSyncConfig::from_swift_conf(&conf, "/etc/swift");
        assert!(!cfg.insecure_skip_verify, "insecure must default false");
        assert!(cfg.ssl_ca_file.is_none());
        let tls = cfg.tls_options();
        assert!(!tls.insecure_skip_verify);
        assert!(tls.ssl_ca_file.is_none());
    }

    #[test]
    fn test_container_sync_config_tls_knobs_parsed() {
        let conf = swift_core::config::SwiftConfig::parse_lenient(
            r#"
[container-sync]
ssl_ca_file = /etc/swift/ca.pem
insecure_skip_verify = true
"#,
            &[],
            false,
        )
        .unwrap();
        let cfg = ContainerSyncConfig::from_swift_conf(&conf, "/etc/swift");
        assert_eq!(
            cfg.ssl_ca_file.as_deref(),
            Some(Path::new("/etc/swift/ca.pem"))
        );
        assert!(cfg.insecure_skip_verify);
        let tls = cfg.tls_options();
        assert_eq!(tls.ssl_ca_file, cfg.ssl_ca_file);
        assert!(tls.insecure_skip_verify);
        // Explicit false / empty must stay secure.
        let conf2 = swift_core::config::SwiftConfig::parse_lenient(
            r#"
[container-sync]
ssl_ca_file =
insecure_skip_verify = false
"#,
            &[],
            false,
        )
        .unwrap();
        let cfg2 = ContainerSyncConfig::from_swift_conf(&conf2, "/etc/swift");
        assert!(cfg2.ssl_ca_file.is_none());
        assert!(!cfg2.insecure_skip_verify);
    }

    #[test]
    fn test_build_tls_connector_missing_ca_errors() {
        let opts = TlsOptions {
            ssl_ca_file: Some(PathBuf::from("/nonexistent/path/no-ca.pem")),
            insecure_skip_verify: false,
        };
        assert!(build_tls_connector(&opts).is_err());
    }

    #[test]
    fn test_https_scheme_selects_tls_flag() {
        // Scheme drives use_tls; default ports 443 vs 80.
        let (_, p, _, tls) = parse_http_url("https://r.example/v1/a/c").unwrap();
        assert!(tls);
        assert_eq!(p, 443);
        let (_, p, _, tls) = parse_http_url("http://r.example/v1/a/c").unwrap();
        assert!(!tls);
        assert_eq!(p, 80);
    }
}
