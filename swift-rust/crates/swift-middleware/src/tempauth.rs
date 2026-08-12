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

//! `tempauth`: token-based authentication and account-group
//! authorization, a functional subset of
//! `swift/common/middleware/tempauth.py`.
//!
//! Covered: the `user_<account>_<user> = <key> [groups...] [url]` config,
//! token issuance at `/auth/v1.0` (and `/auth/`, `/auth/v1/<a>/auth`),
//! `X-Auth-Token` validation, and inline authorization — a request is
//! allowed when the path account (e.g. `AUTH_test`) is one of the token
//! user's groups, when the user is `.reseller_admin`, or (for GET/HEAD)
//! `.reseller_reader`; account PUT/DELETE requires reseller admin.
//!
//! Container ACLs (`X-Container-Read`/`Write`) and account ACLs
//! (`X-Account-Access-Control`) are enforced via [`TempAuth::authorize_acl`]
//! (proxy supplies the ACL data after info lookups). With shared memcache
//! info-cache L2 (P1c), ACL updates clear across VIP backends. Residual
//! (wontfix P1c / P3): S3 auth, Python memcache/fernet token wire
//! formats, service tokens, and the deferred `swift.authorize` callback
//! shape (we authorize inline).
//!
//! When [`TempAuth::with_shared_secret`] is set (cluster deploy: derived
//! from `swift.conf` hash prefix/suffix), issued tokens are HMAC-signed
//! and valid on every proxy that shares the secret — required for
//! HAProxy to load-balance across nodes without per-process 401s.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use swift_http::{Request, Response};

use crate::acl::{parse_acl_v1, referrer_allowed, AccountAcls};
use crate::{Middleware, NextFn};

type HmacSha256 = Hmac<Sha256>;

/// One configured user identity.
#[derive(Debug, Clone)]
pub struct UserRecord {
    pub key: String,
    /// Extra groups beyond the implicit `<account>:<user>` and
    /// `<reseller_prefix><account>` (e.g. `.admin`, `.reseller_admin`).
    pub groups: Vec<String>,
    /// Storage URL override; when absent, `<default_url>/<reseller><acct>`.
    pub url: Option<String>,
}

struct CachedToken {
    groups: Vec<String>,
    expires: Instant,
}

pub struct TempAuth {
    reseller_prefix: String,
    auth_prefix: String,
    default_storage_url: String,
    token_life: Duration,
    /// keyed by `"<account>:<user>"`.
    users: HashMap<String, UserRecord>,
    tokens: Mutex<HashMap<String, CachedToken>>,
    token_counter: AtomicU64,
    /// Cluster-shared HMAC key. `None` keeps legacy in-process tokens (tests).
    shared_secret: Option<Vec<u8>>,
}

impl TempAuth {
    /// `default_storage_url` is the base the issued X-Storage-Url is
    /// built from, e.g. `http://127.0.0.1:8080`.
    pub fn new(default_storage_url: impl Into<String>) -> Self {
        TempAuth {
            reseller_prefix: "AUTH_".to_string(),
            auth_prefix: "/auth/".to_string(),
            default_storage_url: default_storage_url.into(),
            token_life: Duration::from_secs(86400),
            users: HashMap::new(),
            tokens: Mutex::new(HashMap::new()),
            token_counter: AtomicU64::new(0),
            shared_secret: None,
        }
    }

    /// Enable HMAC tokens that any proxy with the same secret can validate.
    pub fn with_shared_secret(mut self, secret: impl AsRef<[u8]>) -> Self {
        self.shared_secret = Some(secret.as_ref().to_vec());
        self
    }

    /// Same as [`with_shared_secret`] on `&mut Self` for builder-style setup.
    pub fn set_shared_secret(&mut self, secret: impl AsRef<[u8]>) -> &mut Self {
        self.shared_secret = Some(secret.as_ref().to_vec());
        self
    }

    /// Add a `user_<account>_<user>` record.
    pub fn add_user(
        &mut self,
        account: &str,
        user: &str,
        key: &str,
        groups: &[&str],
    ) -> &mut Self {
        self.users.insert(
            format!("{account}:{user}"),
            UserRecord {
                key: key.to_string(),
                groups: groups.iter().map(|s| s.to_string()).collect(),
                url: None,
            },
        );
        self
    }

    /// The full group list for an authenticated `account:user`, ported from
    /// Python `TempAuth._get_user_groups`: `[account, account:user, ...groups]`,
    /// and — crucially — the storage account id (`AUTH_<account>`) is added ONLY
    /// for a `.admin` user (which also consumes the `.admin` token). So a
    /// non-admin user is NOT an account owner and can reach resources only via
    /// ACLs, exactly as Swift does.
    fn user_groups(&self, account_user: &str, record: &UserRecord) -> Vec<String> {
        let account = account_user.split(':').next().unwrap_or("");
        let mut groups = vec![account.to_string(), account_user.to_string()];
        let mut is_admin = false;
        for g in &record.groups {
            if g == ".admin" {
                is_admin = true;
            } else {
                groups.push(g.clone());
            }
        }
        if is_admin {
            groups.push(format!("{}{}", self.reseller_prefix, account));
        }
        groups
    }

    fn issue_token(&self, groups: Vec<String>) -> String {
        if let Some(secret) = &self.shared_secret {
            return self.issue_shared_token(secret, groups);
        }
        let n = self.token_counter.fetch_add(1, Ordering::Relaxed);
        let mut x = (std::process::id() as u64)
            .wrapping_mul(0x9e3779b97f4a7c15)
            .wrapping_add(n);
        x ^= x >> 29;
        x = x.wrapping_mul(0xbf58476d1ce4e5b9);
        let token = format!("{}tk{:016x}{:08x}", self.reseller_prefix, x, n);
        self.tokens.lock().unwrap().insert(
            token.clone(),
            CachedToken {
                groups,
                expires: Instant::now() + self.token_life,
            },
        );
        token
    }

    fn issue_shared_token(&self, secret: &[u8], groups: Vec<String>) -> String {
        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
            .saturating_add(self.token_life.as_secs());
        // groups joined with RS (0x1e) — account names in practice lack this byte
        let payload = format!("{exp}\x1e{}", groups.join("\x1e"));
        let mac = {
            let mut h = HmacSha256::new_from_slice(secret).expect("HMAC key");
            h.update(payload.as_bytes());
            h.finalize().into_bytes()
        };
        format!(
            "{}tkv1.{}.{}",
            self.reseller_prefix,
            hex_encode(payload.as_bytes()),
            hex_encode(&mac)
        )
    }

    fn validate_token(&self, token: &str) -> Option<Vec<String>> {
        if let Some(secret) = &self.shared_secret {
            if let Some(groups) = self.validate_shared_token(secret, token) {
                return Some(groups);
            }
            // Fall through: allow in-process tokens during mixed rollout.
        }
        let mut tokens = self.tokens.lock().unwrap();
        match tokens.get(token) {
            Some(cached) if cached.expires > Instant::now() => Some(cached.groups.clone()),
            Some(_) => {
                tokens.remove(token);
                None
            }
            None => None,
        }
    }

    fn validate_shared_token(&self, secret: &[u8], token: &str) -> Option<Vec<String>> {
        let prefix = format!("{}tkv1.", self.reseller_prefix);
        let rest = token.strip_prefix(&prefix)?;
        let (payload_hex, mac_hex) = rest.split_once('.')?;
        let payload = hex_decode(payload_hex)?;
        let mac = hex_decode(mac_hex)?;
        let mut h = HmacSha256::new_from_slice(secret).ok()?;
        h.update(&payload);
        h.verify_slice(&mac).ok()?;
        let text = String::from_utf8(payload).ok()?;
        let mut parts = text.split('\x1e');
        let exp: u64 = parts.next()?.parse().ok()?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if now > exp {
            return None;
        }
        Some(parts.map(|s| s.to_string()).collect())
    }

    fn unauthorized(realm: &str) -> Response {
        let mut resp = Response::error(
            401,
            "This server could not verify that you are authorized to access the document you requested.",
        );
        resp.headers
            .set("Www-Authenticate", format!("Swift realm=\"{realm}\""));
        resp
    }
}

fn hex_encode(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(data.len() * 2);
    for &b in data {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_nibble(bytes[i])?;
        let lo = hex_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

impl TempAuth {
    fn forbidden() -> Response {
        let mut resp = Response::with_body(403, b"403 Forbidden".to_vec());
        resp.headers.set("Content-Type", "text/plain");
        resp
    }

    /// `handle_get_token`: authenticate credentials and issue a token.
    fn handle_get_token(&self, req: &Request) -> Response {
        let segs: Vec<&str> = req.path.trim_start_matches('/').split('/').collect();
        // support /auth/v1.0, /auth/, /auth/v1/<act>/auth: only the last
        // form carries an account in the path that must match creds
        let account: Option<String> =
            if segs.len() >= 4 && segs[1] == "v1" && segs[3] == "auth" {
                Some(segs[2].to_string())
            } else {
                None
            };

        let x_auth_user = req
            .headers
            .get("X-Auth-User")
            .or_else(|| req.headers.get("X-Storage-User"));
        let key = req
            .headers
            .get("X-Auth-Key")
            .or_else(|| req.headers.get("X-Storage-Pass"));
        let Some(x_auth_user) = x_auth_user else {
            return Self::unauthorized("unknown");
        };
        let Some((cred_account, user)) = x_auth_user.split_once(':') else {
            return Self::unauthorized("unknown");
        };
        if let Some(path_account) = &account {
            if path_account != cred_account {
                return Self::unauthorized(path_account);
            }
        }
        let account_user = format!("{cred_account}:{user}");
        let Some(record) = self.users.get(&account_user) else {
            return Self::unauthorized(cred_account);
        };
        if key != Some(record.key.as_str()) {
            return Self::unauthorized(cred_account);
        }

        let groups = self.user_groups(&account_user, record);
        let token = self.issue_token(groups);
        let storage_url = record.url.clone().unwrap_or_else(|| {
            format!(
                "{}/v1/{}{}",
                self.default_storage_url, self.reseller_prefix, cred_account
            )
        });
        let mut resp = Response::new(200);
        resp.headers.set("X-Auth-Token", &token);
        resp.headers.set("X-Storage-Token", &token);
        resp.headers.set("X-Storage-Url", storage_url);
        resp.headers.set("Content-Type", "text/plain");
        resp.headers.set("Content-Length", 0);
        resp
    }

    /// `authorize`: ACL-aware account/container authorization, ported from
    /// Python `TempAuth.authorize`. The proxy calls this AFTER it has learned
    /// the container ACL and account ACL sysmeta (tempauth itself only
    /// authenticates and stamps the group list). `user_groups` is the
    /// authenticated user's groups (empty = anonymous); `acl` is the relevant
    /// container read/write ACL (or `None` for owner-only resources like
    /// account requests or container PUT/POST/DELETE); `account_acls` is the
    /// parsed `X-Account-Access-Control` sysmeta when set; `referer` is the
    /// request Referer. Returns `Some(denial)` (401 anonymous / 403
    /// authenticated) or `None` (authorized). When authorized as account
    /// owner / account-ACL admin, `swift_owner` is set to `true`.
    pub fn authorize_acl(
        method: &str,
        path: &str,
        user_groups: &[String],
        acl: Option<&str>,
        referer: Option<&str>,
        reseller_prefix: &str,
        account_acls: Option<&AccountAcls>,
        swift_owner: &mut bool,
    ) -> Option<Response> {
        // path is /v1/<account>[/container[/object]]
        let segs: Vec<&str> = path.trim_start_matches('/').splitn(4, '/').collect();
        let Some(account) = segs.get(1).copied().filter(|a| !a.is_empty()) else {
            return Some(Self::forbidden());
        };
        let container = segs.get(2).copied().filter(|c| !c.is_empty());
        let obj = segs.get(3).copied().filter(|o| !o.is_empty());
        *swift_owner = false;

        // reseller admin has full access; reseller reader has read access.
        if user_groups.iter().any(|g| g == ".reseller_admin") {
            *swift_owner = true;
            return None;
        }
        if user_groups.iter().any(|g| g == ".reseller_reader")
            && matches!(method, "GET" | "HEAD")
        {
            return None;
        }
        // account owner (the reseller-prefixed account name is one of the user's
        // groups), barred only from account-level PUT/DELETE.
        if user_groups.iter().any(|g| g == account)
            && (!matches!(method, "PUT" | "DELETE") || container.is_some())
        {
            *swift_owner = true;
            return None;
        }
        // container/object ACL: public/referrer read, .rlistings, and account or
        // user groups granted by the ACL (cross-account access).
        if let Some(acl) = acl {
            let (referrers, groups) = parse_acl_v1(acl);
            if referrer_allowed(referer, &referrers)
                && (obj.is_some() || groups.iter().any(|g| g == ".rlistings"))
            {
                return None;
            }
            for ug in user_groups {
                if groups.iter().any(|g| g == ug) {
                    return None;
                }
            }
        }
        // X-Account-Access-Control (admin / read-write / read-only).
        if let Some(acct) = account_acls {
            if acct.is_admin(user_groups) {
                *swift_owner = true;
                return None;
            }
            if acct.is_read_write(user_groups)
                && (container.is_some() || matches!(method, "GET" | "HEAD"))
            {
                return None;
            }
            if acct.is_read_only(user_groups) && matches!(method, "GET" | "HEAD") {
                return None;
            }
        }
        let _ = reseller_prefix;
        // Deny: 401 for an anonymous request (so a client can authenticate),
        // 403 for an authenticated user who simply lacks access.
        if user_groups.is_empty() {
            Some(Self::unauthorized(account))
        } else {
            Some(Self::forbidden())
        }
    }
}

impl Middleware for TempAuth {
    fn handle(&self, req: Request, next: &NextFn) -> Response {
        // auth endpoint: issue tokens
        if req.path.starts_with(&self.auth_prefix) {
            return self.handle_get_token(&req);
        }
        // TempURL (and peers) set authorize_override after validating a
        // signature; skip re-auth so we do not wipe their Remote-User stamp.
        if req
            .headers
            .get("X-Backend-Authorize-Override")
            .map(|v| {
                matches!(
                    v.to_ascii_lowercase().as_str(),
                    "true" | "1" | "yes" | "on"
                )
            })
            .unwrap_or(false)
        {
            return next(req);
        }

        let token = req
            .headers
            .get("X-Auth-Token")
            .or_else(|| req.headers.get("X-Storage-Token"));
        // Authenticate only. A valid token yields the user's groups; an invalid
        // one of ours is a hard 401; anything else (incl. no token) is
        // anonymous. Authorization is deferred to the proxy, which knows the
        // container/account ACL.
        let groups: Vec<String> = match token {
            Some(token) if token.starts_with(&self.reseller_prefix) => {
                match self.validate_token(token) {
                    Some(groups) => groups,
                    None => {
                        let realm = req
                            .path
                            .trim_start_matches('/')
                            .split('/')
                            .nth(1)
                            .unwrap_or("unknown");
                        return Self::unauthorized(realm);
                    }
                }
            }
            _ => Vec::new(),
        };
        let mut req = req;
        // Translate client X-Account-Access-Control → sysmeta (TempAuth
        // extract_acl_and_report_errors). Invalid syntax → 400 before the app.
        if req.headers.contains_key("X-Account-Access-Control") {
            match crate::acl::validate_account_acl_header(
                req.headers.get("X-Account-Access-Control"),
            ) {
                Ok(Some(json)) => {
                    req.headers.remove("X-Account-Access-Control");
                    req.headers
                        .set("X-Account-Sysmeta-Core-Access-Control", json);
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
                    return resp;
                }
            }
        }
        // Stamp the group list for the proxy's authorize. gatekeeper strips
        // inbound x-backend* headers, so a client cannot forge this.
        req.headers.set("X-Backend-Remote-User", groups.join(","));
        next(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use swift_http::HeaderKeyDict;

    fn mk(method: &str, path: &str, headers: &[(&str, &str)]) -> Request {
        let mut h = HeaderKeyDict::new();
        for (k, v) in headers {
            h.set(k, v);
        }
        Request {
            method: method.into(),
            path: path.into(),
            query_string: String::new(),
            headers: h,
            body: swift_http::Body::empty(),
        }
    }

    // An app that records the (unspoofable) X-Backend-Remote-User it received.
    #[allow(clippy::type_complexity)]
    fn recording_app() -> (
        Arc<Mutex<Option<String>>>,
        Arc<dyn Fn(Request) -> Response + Send + Sync>,
    ) {
        let seen = Arc::new(Mutex::new(None));
        let s2 = seen.clone();
        let app: Arc<dyn Fn(Request) -> Response + Send + Sync> = Arc::new(move |r: Request| {
            *s2.lock().unwrap() = r.headers.get("X-Backend-Remote-User").map(|s| s.to_string());
            Response::new(204)
        });
        (seen, app)
    }

    #[test]
    fn test_unauthorized_matches_swob_response() {
        let mut resp = TempAuth::unauthorized("AUTH_test");
        assert_eq!(resp.status, 401);
        assert_eq!(
            resp.headers.get("Content-Type"),
            Some("text/html; charset=UTF-8")
        );
        assert_eq!(
            resp.headers.get("Www-Authenticate"),
            Some("Swift realm=\"AUTH_test\"")
        );
        assert_eq!(
            resp.body.materialize(u64::MAX).unwrap(),
            b"<html><h1>Unauthorized</h1><p>This server could not verify that you are authorized to access the document you requested.</p></html>"
        );
    }

    #[test]
    fn test_token_issue_and_stamp() {
        let mut ta = TempAuth::new("http://h:8080");
        ta.add_user("test", "tester", "testing", &[".admin"]);

        // wrong key -> 401
        assert_eq!(
            ta.handle(
                mk("GET", "/auth/v1.0", &[("X-Auth-User", "test:tester"), ("X-Auth-Key", "wrong")]),
                &(std::sync::Arc::new(|_r| Response::new(500)) as crate::NextFn),
            )
            .status,
            401
        );
        // right key -> token + storage url
        let resp = ta.handle(
            mk("GET", "/auth/v1.0", &[("X-Auth-User", "test:tester"), ("X-Auth-Key", "testing")]),
            &(std::sync::Arc::new(|_r| Response::new(500)) as crate::NextFn),
        );
        assert_eq!(resp.status, 200);
        let token = resp.headers.get("X-Auth-Token").unwrap().to_string();
        assert!(token.starts_with("AUTH_tk"), "{token}");
        assert_eq!(resp.headers.get("X-Storage-Url"), Some("http://h:8080/v1/AUTH_test"));

        // valid token: handle forwards, stamping the user's groups
        let (seen, app) = recording_app();
        let resp = ta.handle(mk("GET", "/v1/AUTH_test/c", &[("X-Auth-Token", &token)]), &app);
        assert_eq!(resp.status, 204);
        // a .admin user owns AUTH_test (storage account added, .admin consumed)
        let groups = seen.lock().unwrap().clone().unwrap();
        assert!(groups.contains("AUTH_test") && !groups.contains(".admin"), "{groups}");

        // a forged inbound X-Backend-Remote-User is overwritten by the real one
        let (seen, app) = recording_app();
        ta.handle(
            mk(
                "GET",
                "/v1/AUTH_test/c",
                &[("X-Auth-Token", &token), ("X-Backend-Remote-User", ".reseller_admin")],
            ),
            &app,
        );
        assert!(
            !seen.lock().unwrap().clone().unwrap().contains(".reseller_admin"),
            "forged group must be dropped"
        );

        // bad token -> 401 (not anonymous)
        assert_eq!(
            ta.handle(
                mk("GET", "/v1/AUTH_test/c", &[("X-Auth-Token", "AUTH_tkbogus")]),
                &(std::sync::Arc::new(|_r| Response::new(500)) as crate::NextFn),
            )
            .status,
            401
        );

        // no token -> anonymous: forwards with an empty group stamp
        let (seen, app) = recording_app();
        assert_eq!(
            ta.handle(mk("GET", "/v1/AUTH_test/c", &[]), &app).status,
            204
        );
        assert_eq!(seen.lock().unwrap().clone().unwrap(), "");
    }

    #[test]
    fn test_shared_secret_token_cross_instance() {
        let secret = b"lab-shared-tempauth-secret";
        let mut a = TempAuth::new("http://vip:8085").with_shared_secret(secret);
        a.add_user("test", "tester", "testing", &[".admin"]);
        let mut b = TempAuth::new("http://vip:8085").with_shared_secret(secret);
        b.add_user("test", "tester", "testing", &[".admin"]);

        let resp = a.handle(
            mk(
                "GET",
                "/auth/v1.0",
                &[("X-Auth-User", "test:tester"), ("X-Auth-Key", "testing")],
            ),
            &(std::sync::Arc::new(|_r| Response::new(500)) as crate::NextFn),
        );
        assert_eq!(resp.status, 200);
        let token = resp.headers.get("X-Auth-Token").unwrap().to_string();
        assert!(token.contains("tkv1."), "{token}");

        let (seen, app) = recording_app();
        let resp = b.handle(mk("GET", "/v1/AUTH_test/c", &[("X-Auth-Token", &token)]), &app);
        assert_eq!(resp.status, 204, "peer proxy must accept HMAC token");
        assert!(seen.lock().unwrap().clone().unwrap().contains("AUTH_test"));
    }

    #[test]
    fn test_authorize_acl() {
        let owner = vec!["test:tester".into(), ".admin".into(), "AUTH_test".to_string()];
        let other = vec!["other:u".into(), "AUTH_other".to_string()];
        let admin = vec!["a:b".into(), ".reseller_admin".to_string()];
        let anon: Vec<String> = vec![];
        let az = |m: &str,
                  p: &str,
                  g: &[String],
                  acl: Option<&str>,
                  rf: Option<&str>,
                  acct: Option<&AccountAcls>| {
            let mut owner_flag = false;
            let denied =
                TempAuth::authorize_acl(m, p, g, acl, rf, "AUTH_", acct, &mut owner_flag);
            (denied, owner_flag)
        };

        // owner: allowed on their objects/containers
        let (d, own) = az("GET", "/v1/AUTH_test/c/o", &owner, None, None, None);
        assert!(d.is_none() && own);
        assert!(az("PUT", "/v1/AUTH_test/c/o", &owner, None, None, None)
            .0
            .is_none());
        // owner barred from account-level PUT/DELETE
        assert_eq!(
            az("PUT", "/v1/AUTH_test", &owner, None, None, None)
                .0
                .unwrap()
                .status,
            403
        );
        // cross-account without ACL -> 403; anonymous without ACL -> 401
        assert_eq!(
            az("GET", "/v1/AUTH_test/c/o", &other, None, None, None)
                .0
                .unwrap()
                .status,
            403
        );
        assert_eq!(
            az("GET", "/v1/AUTH_test/c/o", &anon, None, None, None)
                .0
                .unwrap()
                .status,
            401
        );
        // reseller admin: allowed anywhere
        let (d, own) = az("DELETE", "/v1/AUTH_test/c/o", &admin, None, None, None);
        assert!(d.is_none() && own);
        // public read (.r:*) allows anonymous OBJECT GET
        assert!(az("GET", "/v1/AUTH_test/c/o", &anon, Some(".r:*"), None, None)
            .0
            .is_none());
        // .r:* on a container LISTING needs .rlistings
        assert_eq!(
            az("GET", "/v1/AUTH_test/c", &anon, Some(".r:*"), None, None)
                .0
                .unwrap()
                .status,
            401
        );
        assert!(az(
            "GET",
            "/v1/AUTH_test/c",
            &anon,
            Some(".r:*,.rlistings"),
            None,
            None
        )
        .0
        .is_none());
        // cross-account granted by an ACL group (read + write)
        assert!(az(
            "GET",
            "/v1/AUTH_test/c/o",
            &other,
            Some("AUTH_other"),
            None,
            None
        )
        .0
        .is_none());
        assert!(az(
            "PUT",
            "/v1/AUTH_test/c/o",
            &other,
            Some("AUTH_other"),
            None,
            None
        )
        .0
        .is_none());
        // a container with only a read ACL: another user's write (write_acl=None) -> 403
        assert_eq!(
            az("PUT", "/v1/AUTH_test/c/o", &other, None, None, None)
                .0
                .unwrap()
                .status,
            403
        );

        // Account ACL: admin is swift_owner; read-write can mutate containers;
        // read-only is GET/HEAD only.
        let acct = AccountAcls {
            admin: vec!["AUTH_other".into()],
            read_write: vec!["rw:user".into()],
            read_only: vec!["ro:user".into()],
        };
        let (d, own) = az("POST", "/v1/AUTH_test", &other, None, None, Some(&acct));
        assert!(d.is_none() && own);
        let rw = vec!["rw:user".into()];
        assert!(az("PUT", "/v1/AUTH_test/c", &rw, None, None, Some(&acct))
            .0
            .is_none());
        assert_eq!(
            az("POST", "/v1/AUTH_test", &rw, None, None, Some(&acct))
                .0
                .unwrap()
                .status,
            403
        );
        let ro = vec!["ro:user".into()];
        assert!(az("GET", "/v1/AUTH_test", &ro, None, None, Some(&acct))
            .0
            .is_none());
        assert_eq!(
            az("PUT", "/v1/AUTH_test/c/o", &ro, None, None, Some(&acct))
                .0
                .unwrap()
                .status,
            403
        );
    }
}
