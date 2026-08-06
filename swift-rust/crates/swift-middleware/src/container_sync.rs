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

//! Proxy middleware for container-sync request authentication, ported from
//! `swift/common/middleware/container_sync.py`.
//!
//! On an inbound request carrying `X-Container-Sync-Auth` (realm HMAC style),
//! validates the signature against `container-sync-realms.conf` keys and the
//! destination container's `X-Container-Sync-Key` (via [`SyncKeyProvider`]).
//! A valid signature stamps `X-Backend-Authorize-Override` so TempAuth /
//! proxy ACLs pass the request through.
//!
//! Also rejects full-URL `X-Container-Sync-To` values when `allow_full_urls`
//! is false (realm `//realm/cluster/account/container` form only).
//!
//! `/info` advertising of realms is done by the proxy from the same conf
//! (Python registers via `register_swift_info('container_sync', realms=...)`).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use hmac::{Hmac, Mac};
use sha1::Sha1;
use swift_core::constraints::VALID_API_VERSIONS;
use swift_http::{split_path, Request, Response};

use crate::{Middleware, NextFn};

type HmacSha1 = Hmac<Sha1>;

/// HMAC-SHA1 hexdigest (same contract as container-server `get_sig`).
pub fn get_sig(
    request_method: &str,
    path: &str,
    x_timestamp: &str,
    nonce: &str,
    realm_key: &str,
    user_key: &str,
) -> String {
    let mut mac = HmacSha1::new_from_slice(realm_key.as_bytes())
        .expect("HMAC accepts a key of any length");
    let msg = format!("{request_method}\n{path}\n{x_timestamp}\n{nonce}\n{user_key}");
    mac.update(msg.as_bytes());
    let digest = mac.finalize().into_bytes();
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn streq_const_time(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Supplies the destination container's `X-Container-Sync-Key`.
pub trait SyncKeyProvider: Send + Sync {
    fn sync_key(&self, account: &str, container: &str) -> Option<String>;
}

/// Map-backed provider for unit tests.
pub struct MapSyncKeyProvider {
    pub keys: HashMap<String, String>,
}

impl SyncKeyProvider for MapSyncKeyProvider {
    fn sync_key(&self, account: &str, container: &str) -> Option<String> {
        self.keys
            .get(&format!("{account}/{container}"))
            .cloned()
    }
}

/// Closure-backed provider (proxy wires container HEAD lookups).
pub struct ClosureSyncKeyProvider {
    inner: Arc<dyn Fn(&str, &str) -> Option<String> + Send + Sync>,
}

impl ClosureSyncKeyProvider {
    pub fn new<F>(f: F) -> Self
    where
        F: Fn(&str, &str) -> Option<String> + Send + Sync + 'static,
    {
        ClosureSyncKeyProvider {
            inner: Arc::new(f),
        }
    }
}

impl SyncKeyProvider for ClosureSyncKeyProvider {
    fn sync_key(&self, account: &str, container: &str) -> Option<String> {
        (self.inner)(account, container)
    }
}

/// One realm from `container-sync-realms.conf`.
#[derive(Debug, Clone, Default)]
pub struct RealmInfo {
    pub key: Option<String>,
    pub key2: Option<String>,
    pub clusters: HashMap<String, String>,
}

/// Parsed realms conf used by the middleware (and `/info` helper).
#[derive(Debug, Clone, Default)]
pub struct RealmsConf {
    pub realms: HashMap<String, RealmInfo>,
}

impl RealmsConf {
    pub fn parse(content: &str) -> Self {
        let mut realms: HashMap<String, RealmInfo> = HashMap::new();
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
                entry
                    .clusters
                    .insert(cluster.to_ascii_uppercase(), v);
            }
        }
        RealmsConf { realms }
    }

    pub fn load(path: &Path) -> Self {
        let content = std::fs::read_to_string(path).unwrap_or_default();
        Self::parse(&content)
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

    /// `/info` payload for `container_sync.realms`.
    pub fn info_dict(&self, current: Option<(&str, &str)>) -> serde_json::Value {
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
            dct.insert(
                realm.clone(),
                serde_json::json!({ "clusters": clusters }),
            );
        }
        serde_json::Value::Object(dct)
    }
}

/// WSGI-style container_sync middleware.
pub struct ContainerSync {
    pub realms: RealmsConf,
    pub allow_full_urls: bool,
    pub current_realm: Option<String>,
    pub current_cluster: Option<String>,
    pub sync_keys: Arc<dyn SyncKeyProvider>,
    pub realms_path: Option<PathBuf>,
}

impl ContainerSync {
    pub fn new(sync_keys: Arc<dyn SyncKeyProvider>) -> Self {
        ContainerSync {
            realms: RealmsConf::default(),
            allow_full_urls: true,
            current_realm: None,
            current_cluster: None,
            sync_keys,
            realms_path: None,
        }
    }

    pub fn with_realms(mut self, realms: RealmsConf) -> Self {
        self.realms = realms;
        self
    }

    pub fn with_realms_path(mut self, path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        self.realms = RealmsConf::load(&path);
        self.realms_path = Some(path);
        self
    }

    pub fn with_allow_full_urls(mut self, allow: bool) -> Self {
        self.allow_full_urls = allow;
        self
    }

    pub fn with_current(mut self, current: Option<&str>) -> Self {
        if let Some(cur) = current {
            let parts: Vec<&str> = cur.trim_matches('/').split('/').collect();
            if parts.len() == 2 {
                self.current_realm = Some(parts[0].to_ascii_uppercase());
                self.current_cluster = Some(parts[1].to_ascii_uppercase());
            }
        }
        self
    }

    /// Shape for proxy `/info` when this filter is in the pipeline.
    pub fn info_json(&self) -> serde_json::Value {
        let current = match (&self.current_realm, &self.current_cluster) {
            (Some(r), Some(c)) => Some((r.as_str(), c.as_str())),
            _ => None,
        };
        serde_json::json!({
            "realms": self.realms.info_dict(current),
        })
    }

    fn unauthorized() -> Response {
        let mut resp = Response::with_body(
            401,
            b"X-Container-Sync-Auth header not valid; \
              contact cluster operator for support."
                .to_vec(),
        );
        resp.headers.set("Content-Type", "text/plain");
        resp.headers.set(
            "Www-Authenticate",
            "SwiftContainerSync realm=\"unknown\"",
        );
        resp
    }

    fn bad_request(body: &str) -> Response {
        let mut resp = Response::with_body(400, body.as_bytes().to_vec());
        resp.headers.set("Content-Type", "text/plain");
        resp
    }
}

impl Middleware for ContainerSync {
    fn handle(&self, mut req: Request, next: &NextFn) -> Response {
        // Fresh realms on /info is Python behaviour; proxy rebuilds info at
        // startup — middleware still reloads from disk if a path is set.
        if req.path == "/info" || req.path.starts_with("/info?") {
            return next(req);
        }

        let segs = match split_path(&req.path, 3, 4, true) {
            Ok(s) => s,
            Err(_) => return next(req),
        };
        let version = segs[0].as_deref().unwrap_or("");
        if !VALID_API_VERSIONS
            .iter()
            .any(|v| v.eq_ignore_ascii_case(version))
        {
            return next(req);
        }
        let account = segs[1].clone().unwrap_or_default();
        let container = segs[2].clone().unwrap_or_default();
        let object = segs.get(3).cloned().flatten().filter(|o| !o.is_empty());

        // Validate sync-to form on container metadata updates.
        if matches!(req.method.as_str(), "PUT" | "POST")
            && !container.is_empty()
            && object.is_none()
        {
            if let Some(sync_to) = req.headers.get("x-container-sync-to") {
                if !self.allow_full_urls && !sync_to.starts_with("//") {
                    return Self::bad_request(
                        "Full URLs are not allowed for X-Container-Sync-To \
                         values. Only realm values of the format \
                         //realm/cluster/account/container are allowed.\n",
                    );
                }
            }
        }

        let auth = match req.headers.get("x-container-sync-auth") {
            Some(a) if !a.is_empty() => a.to_string(),
            _ => return next(req),
        };
        let parts: Vec<&str> = auth.split_whitespace().collect();
        if parts.len() != 3 {
            return Self::unauthorized();
        }
        let (realm, nonce, sig) = (parts[0], parts[1], parts[2]);
        let realm_key = self.realms.key(realm);
        let realm_key2 = self.realms.key2(realm);
        let Some(realm_key) = realm_key else {
            return Self::unauthorized();
        };
        let Some(user_key) = self.sync_keys.sync_key(&account, &container) else {
            return Self::unauthorized();
        };

        // Gatekeeper shunts x-timestamp → x-backend-inbound-x-timestamp.
        if let Some(ts) = req
            .headers
            .get("x-backend-inbound-x-timestamp")
            .map(str::to_string)
        {
            req.headers.remove("X-Backend-Inbound-X-Timestamp");
            req.headers.set("X-Timestamp", ts);
        }
        let x_timestamp = req.headers.get("x-timestamp").unwrap_or("0").to_string();

        let expected = get_sig(
            &req.method,
            &req.path,
            &x_timestamp,
            nonce,
            realm_key,
            &user_key,
        );
        let expected2 = realm_key2
            .map(|k2| get_sig(&req.method, &req.path, &x_timestamp, nonce, k2, &user_key))
            .unwrap_or_else(|| expected.clone());

        if !streq_const_time(sig, &expected) && !streq_const_time(sig, &expected2) {
            return Self::unauthorized();
        }

        // Valid: authorize override + SLO/symlink overrides (header stamps).
        req.headers.set("X-Backend-Authorize-Override", "true");
        req.headers.set("X-Backend-Remote-User", ".wsgi.container_sync");
        req.headers.set("X-Backend-Slo-Override", "true");
        req.headers.set("X-Backend-Symlink-Override", "true");
        next(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use swift_http::HeaderKeyDict;

    fn req(method: &str, path: &str) -> Request {
        Request {
            method: method.into(),
            path: path.into(),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: swift_http::Body::empty(),
        }
    }

    fn app_ok() -> NextFn {
        Arc::new(|_r| Response::new(204))
    }

    #[test]
    fn test_valid_auth_sets_override() {
        let mut keys = HashMap::new();
        keys.insert("AUTH_a/c".into(), "userkey".into());
        let mut realms = RealmsConf::default();
        realms.realms.insert(
            "US".into(),
            RealmInfo {
                key: Some("realmkey".into()),
                key2: None,
                clusters: HashMap::new(),
            },
        );
        let mw = ContainerSync::new(Arc::new(MapSyncKeyProvider { keys })).with_realms(realms);
        let path = "/v1/AUTH_a/c/obj";
        let ts = "1751500000.00000";
        let nonce = "deadbeefdeadbeefdeadbeefdeadbeef";
        let sig = get_sig("PUT", path, ts, nonce, "realmkey", "userkey");
        let mut r = req("PUT", path);
        r.headers.set("X-Timestamp", ts);
        r.headers
            .set("X-Container-Sync-Auth", format!("US {nonce} {sig}"));
        let resp = mw.handle(r, &app_ok());
        assert_eq!(resp.status, 204);
    }

    #[test]
    fn test_invalid_sig_401() {
        let mut keys = HashMap::new();
        keys.insert("AUTH_a/c".into(), "userkey".into());
        let mut realms = RealmsConf::default();
        realms.realms.insert(
            "US".into(),
            RealmInfo {
                key: Some("realmkey".into()),
                key2: None,
                clusters: HashMap::new(),
            },
        );
        let mw = ContainerSync::new(Arc::new(MapSyncKeyProvider { keys })).with_realms(realms);
        let mut r = req("PUT", "/v1/AUTH_a/c/obj");
        r.headers.set("X-Timestamp", "1");
        r.headers
            .set("X-Container-Sync-Auth", "US nonce badbadbad");
        let resp = mw.handle(r, &app_ok());
        assert_eq!(resp.status, 401);
    }

    #[test]
    fn test_full_url_rejected_when_disallowed() {
        let mw = ContainerSync::new(Arc::new(MapSyncKeyProvider {
            keys: HashMap::new(),
        }))
        .with_allow_full_urls(false);
        let mut r = req("POST", "/v1/AUTH_a/c");
        r.headers
            .set("X-Container-Sync-To", "http://other/v1/a/c");
        let resp = mw.handle(r, &app_ok());
        assert_eq!(resp.status, 400);
    }

    #[test]
    fn test_no_auth_passthrough() {
        let mw = ContainerSync::new(Arc::new(MapSyncKeyProvider {
            keys: HashMap::new(),
        }));
        let resp = mw.handle(req("GET", "/v1/AUTH_a/c/obj"), &app_ok());
        assert_eq!(resp.status, 204);
    }

    #[test]
    fn test_get_sig_python_vector() {
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
}
