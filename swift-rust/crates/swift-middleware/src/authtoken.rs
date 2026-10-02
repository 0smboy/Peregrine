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

//! Minimal Keystone `authtoken` filter for the Rust proxy.
//!
//! Mirrors the security-critical contract of `keystonemiddleware.auth_token`:
//! validate `X-Auth-Token` (and optional `X-Service-Token`) against a Keystone
//! v3 Identity API, then stamp the identity headers that
//! [`crate::keystoneauth::KeystoneAuth`] consumes (`X-Identity-Status`,
//! `X-User-*`, `X-Project-*`, `X-Roles`, …).
//!
//! Token validation is pluggable via [`TokenValidator`]:
//! - [`StaticTokenMap`] for unit / threat tests (no network)
//! - [`HttpKeystoneValidator`] for production (GET `/v3/auth/tokens` with a
//!   cached service credential token)
//!
//! `delay_auth_decision=true` (default) matches keystonemiddleware: missing
//! **or invalid** tokens are deferred (`X-Identity-Status: Invalid`) so a
//! downstream auth filter (TempAuth in `keystone_coexist`) can accept its own
//! tokens. Presented-but-invalid tokens hard-fail with 401 only when
//! `delay_auth_decision=false`.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::Value;
use swift_http::{Request, Response};

use crate::keystoneauth::Identity;
use crate::{Middleware, MwPrep, NextFn};

/// Headers keystonemiddleware sets; always cleared before stamping so a
/// client cannot forge identity past authtoken (gatekeeper also strips
/// these inbound as defense in depth).
const IDENTITY_HEADERS: &[&str] = &[
    "X-Identity-Status",
    "X-Service-Identity-Status",
    "X-Roles",
    "X-Service-Roles",
    "X-User-Id",
    "X-User-Name",
    "X-Project-Id",
    "X-Project-Name",
    "X-Tenant-Id",
    "X-Tenant-Name",
    "X-User-Domain-Id",
    "X-User-Domain-Name",
    "X-Project-Domain-Id",
    "X-Project-Domain-Name",
];

/// Outcome of validating one token.
#[derive(Debug, Clone)]
pub enum TokenOutcome {
    /// Token valid; identity fields lowercased roles already.
    Confirmed(Box<ValidatedToken>),
    /// Token present but rejected (unknown, expired, revoked).
    Invalid,
    /// No token / network skip when delay is allowed.
    Indeterminate,
}

/// Validated Keystone v3 token payload.
#[derive(Debug, Clone)]
pub struct ValidatedToken {
    pub identity: Identity,
    pub user_domain_id: String,
    pub user_domain_name: String,
    pub project_domain_id: String,
    pub project_domain_name: String,
}

/// Pluggable token validator (static map or live Keystone).
pub trait TokenValidator: Send + Sync {
    fn validate(&self, token: &str) -> TokenOutcome;

    /// Keystone HTTP validation must not run on a Tokio worker (`std::net`).
    fn needs_network(&self) -> bool {
        false
    }

    fn validate_async<'a>(
        &'a self,
        token: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = TokenOutcome> + Send + 'a>> {
        Box::pin(async move { self.validate(token) })
    }
}

/// In-memory token → identity map for tests and SAIO-less evidence.
#[derive(Debug, Default)]
pub struct MapTokenValidator {
    tokens: HashMap<String, ValidatedToken>,
}

/// Alias for [`MapTokenValidator`].
pub type StaticTokenMap = MapTokenValidator;

impl MapTokenValidator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, token: impl Into<String>, validated: ValidatedToken) {
        self.tokens.insert(token.into(), validated);
    }
}

impl TokenValidator for MapTokenValidator {
    fn validate(&self, token: &str) -> TokenOutcome {
        match self.tokens.get(token) {
            Some(v) => TokenOutcome::Confirmed(Box::new(v.clone())),
            None => TokenOutcome::Invalid,
        }
    }
}

/// Live Keystone v3 validator using a service user password to obtain an
/// admin/service token, then `GET {auth_url}/auth/tokens` with
/// `X-Subject-Token`.
pub struct HttpTokenValidator {
    auth_url: String,
    username: String,
    password: String,
    project_name: String,
    user_domain_name: String,
    project_domain_name: String,
    timeout: Duration,
    cached: Mutex<Option<(Instant, String)>>,
    cache_ttl: Duration,
}

/// Alias for [`HttpTokenValidator`].
pub type HttpKeystoneValidator = HttpTokenValidator;

impl HttpTokenValidator {
    pub fn new(
        auth_url: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
        project_name: impl Into<String>,
    ) -> Self {
        Self {
            auth_url: auth_url.into().trim_end_matches('/').to_string(),
            username: username.into(),
            password: password.into(),
            project_name: project_name.into(),
            user_domain_name: "Default".into(),
            project_domain_name: "Default".into(),
            timeout: Duration::from_secs(5),
            cached: Mutex::new(None),
            cache_ttl: Duration::from_secs(300),
        }
    }

    pub fn with_domains(
        mut self,
        user_domain: impl Into<String>,
        project_domain: impl Into<String>,
    ) -> Self {
        self.user_domain_name = user_domain.into();
        self.project_domain_name = project_domain.into();
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    fn service_token(&self) -> Result<String, String> {
        if let Ok(guard) = self.cached.lock() {
            if let Some((at, tok)) = guard.as_ref() {
                if at.elapsed() < self.cache_ttl {
                    return Ok(tok.clone());
                }
            }
        }
        let body = serde_json::json!({
            "auth": {
                "identity": {
                    "methods": ["password"],
                    "password": {
                        "user": {
                            "name": self.username,
                            "domain": { "name": self.user_domain_name },
                            "password": self.password
                        }
                    }
                },
                "scope": {
                    "project": {
                        "name": self.project_name,
                        "domain": { "name": self.project_domain_name }
                    }
                }
            }
        });
        let url = format!("{}/auth/tokens", self.auth_url);
        let (status, headers, _body) = http_json(
            "POST",
            &url,
            &[("Content-Type", "application/json")],
            Some(body.to_string().as_bytes()),
            self.timeout,
        )?;
        if !(200..300).contains(&status) {
            return Err(format!("keystone password auth HTTP {status}"));
        }
        let token = headers
            .get("x-subject-token")
            .cloned()
            .ok_or_else(|| "keystone response missing X-Subject-Token".to_string())?;
        if let Ok(mut guard) = self.cached.lock() {
            *guard = Some((Instant::now(), token.clone()));
        }
        Ok(token)
    }
}

impl TokenValidator for HttpTokenValidator {
    fn needs_network(&self) -> bool {
        true
    }

    fn validate_async<'a>(
        &'a self,
        token: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = TokenOutcome> + Send + 'a>> {
        Box::pin(async move {
            let token = token.to_string();
            let v = HttpTokenValidator::new(
                self.auth_url.clone(),
                self.username.clone(),
                self.password.clone(),
                self.project_name.clone(),
            )
            .with_domains(
                self.user_domain_name.clone(),
                self.project_domain_name.clone(),
            )
            .with_timeout(self.timeout);
            let (tx, rx) = tokio::sync::oneshot::channel();
            std::thread::spawn(move || {
                let outcome = v.validate(&token);
                let _ = tx.send(outcome);
            });
            rx.await.unwrap_or(TokenOutcome::Invalid)
        })
    }

    fn validate(&self, token: &str) -> TokenOutcome {
        let admin = match self.service_token() {
            Ok(t) => t,
            Err(_) => return TokenOutcome::Invalid,
        };
        let url = format!("{}/auth/tokens", self.auth_url);
        let result = http_json(
            "GET",
            &url,
            &[("X-Auth-Token", admin.as_str()), ("X-Subject-Token", token)],
            None,
            self.timeout,
        );
        let (status, _hdrs, body) = match result {
            Ok(r) => r,
            Err(_) => return TokenOutcome::Invalid,
        };
        if status == 404 || status == 401 || status == 403 {
            return TokenOutcome::Invalid;
        }
        if !(200..300).contains(&status) {
            return TokenOutcome::Invalid;
        }
        match parse_token_body(&body) {
            Some(v) => TokenOutcome::Confirmed(Box::new(v)),
            None => TokenOutcome::Invalid,
        }
    }
}

fn parse_token_body(body: &[u8]) -> Option<ValidatedToken> {
    let v: Value = serde_json::from_slice(body).ok()?;
    let token = v.get("token")?;
    let user = token.get("user")?;
    let project = token.get("project")?;
    let roles = token
        .get("roles")
        .and_then(|r| r.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|r| r.get("name").and_then(|n| n.as_str()))
                .map(|s| s.to_ascii_lowercase())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let identity = Identity {
        user_id: user.get("id")?.as_str()?.to_string(),
        user_name: user
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("")
            .to_string(),
        tenant_id: project.get("id")?.as_str()?.to_string(),
        tenant_name: project
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("")
            .to_string(),
        roles,
        service_roles: Vec::new(),
    };
    let user_domain = user.get("domain");
    let project_domain = project.get("domain");
    Some(ValidatedToken {
        identity,
        user_domain_id: user_domain
            .and_then(|d| d.get("id"))
            .and_then(|x| x.as_str())
            .unwrap_or("default")
            .to_string(),
        user_domain_name: user_domain
            .and_then(|d| d.get("name"))
            .and_then(|x| x.as_str())
            .unwrap_or("Default")
            .to_string(),
        project_domain_id: project_domain
            .and_then(|d| d.get("id"))
            .and_then(|x| x.as_str())
            .unwrap_or("default")
            .to_string(),
        project_domain_name: project_domain
            .and_then(|d| d.get("name"))
            .and_then(|x| x.as_str())
            .unwrap_or("Default")
            .to_string(),
    })
}

/// Tiny sync HTTP/1.1 client. Supports `http://` and `https://` (via
/// `native-tls`). Returns status, lowercased response headers, and body bytes.
fn http_json(
    method: &str,
    url: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
    timeout: Duration,
) -> Result<(u16, HashMap<String, String>, Vec<u8>), String> {
    let (https, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        return Err(format!("auth_url must be http:// or https:// (got {url})"));
    };
    let (hostport, path) = match rest.split_once('/') {
        Some((hp, p)) => (hp.to_string(), format!("/{p}")),
        None => (rest.to_string(), "/".to_string()),
    };
    let host = hostport
        .split(':')
        .next()
        .unwrap_or(hostport.as_str())
        .to_string();
    // Default ports when omitted (Keystone public is usually :5000, but
    // https://host/v3 without a port is valid behind a TLS terminator).
    let connect_hostport = if hostport.contains(':') {
        hostport.clone()
    } else if https {
        format!("{host}:443")
    } else {
        format!("{host}:80")
    };
    let addr = connect_hostport
        .to_socket_addrs()
        .map_err(|e| e.to_string())?
        .next()
        .ok_or_else(|| format!("cannot resolve {connect_hostport}"))?;
    let stream = TcpStream::connect_timeout(&addr, timeout).map_err(|e| e.to_string())?;
    stream.set_read_timeout(Some(timeout)).ok();
    stream.set_write_timeout(Some(timeout)).ok();

    let body_len = body.map(|b| b.len()).unwrap_or(0);
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
    if body.is_some() {
        req.push_str(&format!("Content-Length: {body_len}\r\n"));
    }
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");

    let mut buf = Vec::new();
    if https {
        let connector = native_tls::TlsConnector::builder()
            .build()
            .map_err(|e| format!("tls connector: {e}"))?;
        let mut tls = connector
            .connect(&host, stream)
            .map_err(|e| format!("tls handshake to {host}: {e}"))?;
        tls.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
        if let Some(b) = body {
            tls.write_all(b).map_err(|e| e.to_string())?;
        }
        tls.read_to_end(&mut buf).map_err(|e| e.to_string())?;
    } else {
        let mut stream = stream;
        stream
            .write_all(req.as_bytes())
            .map_err(|e| e.to_string())?;
        if let Some(b) = body {
            stream.write_all(b).map_err(|e| e.to_string())?;
        }
        stream.read_to_end(&mut buf).map_err(|e| e.to_string())?;
    }

    let text = String::from_utf8_lossy(&buf);
    let (head, rest) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| "malformed HTTP response".to_string())?;
    let mut lines = head.lines();
    let status_line = lines.next().unwrap_or("");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let mut hdrs = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            hdrs.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    Ok((status, hdrs, rest.as_bytes().to_vec()))
}

/// The `authtoken` middleware.
pub struct AuthToken {
    validator: Arc<dyn TokenValidator>,
    /// When true (default), missing token → Indeterminate (anonymous).
    pub delay_auth_decision: bool,
    /// `WWW-Authenticate` realm URI (Keystone public endpoint).
    pub www_authenticate_uri: String,
}

impl AuthToken {
    pub fn new(validator: Arc<dyn TokenValidator>) -> Self {
        Self {
            validator,
            delay_auth_decision: true,
            www_authenticate_uri: String::new(),
        }
    }

    pub fn with_delay(mut self, delay: bool) -> Self {
        self.delay_auth_decision = delay;
        self
    }

    pub fn with_www_authenticate_uri(mut self, uri: impl Into<String>) -> Self {
        self.www_authenticate_uri = uri.into();
        self
    }

    fn clear_identity(req: &mut Request) {
        for h in IDENTITY_HEADERS {
            req.headers.remove(h);
        }
    }

    fn stamp(req: &mut Request, token: &ValidatedToken, service: Option<&ValidatedToken>) {
        // Unspoofable marker (gatekeeper strips inbound X-Backend-*): keystoneauth
        // must not trust client-forged X-Identity-Status without this.
        req.headers.set("X-Backend-Authtoken-Status", "Confirmed");
        req.headers.set("X-Identity-Status", "Confirmed");
        req.headers.set("X-User-Id", &token.identity.user_id);
        req.headers.set("X-User-Name", &token.identity.user_name);
        req.headers.set("X-Project-Id", &token.identity.tenant_id);
        req.headers
            .set("X-Project-Name", &token.identity.tenant_name);
        req.headers.set("X-Tenant-Id", &token.identity.tenant_id);
        req.headers
            .set("X-Tenant-Name", &token.identity.tenant_name);
        req.headers.set("X-Roles", token.identity.roles.join(","));
        req.headers.set("X-User-Domain-Id", &token.user_domain_id);
        req.headers
            .set("X-User-Domain-Name", &token.user_domain_name);
        req.headers
            .set("X-Project-Domain-Id", &token.project_domain_id);
        req.headers
            .set("X-Project-Domain-Name", &token.project_domain_name);
        if let Some(svc) = service {
            req.headers.set("X-Service-Identity-Status", "Confirmed");
            req.headers
                .set("X-Service-Roles", svc.identity.roles.join(","));
        }
    }

    fn unauthorized(&self) -> Response {
        let mut resp = Response::with_body(401, "Unauthorized\n");
        resp.headers
            .set("Content-Type", "text/plain; charset=UTF-8");
        let uri = if self.www_authenticate_uri.is_empty() {
            "Keystone".to_string()
        } else {
            self.www_authenticate_uri.clone()
        };
        resp.headers
            .set("Www-Authenticate", format!("Keystone uri=\"{uri}\""));
        resp
    }
}

impl Middleware for AuthToken {
    fn prepare(&self, req: &mut Request) -> MwPrep {
        Self::clear_identity(req);
        if req
            .headers
            .get("X-Backend-Authorize-Override")
            .map(|v| matches!(v.to_ascii_lowercase().as_str(), "true" | "1" | "yes" | "on"))
            .unwrap_or(false)
        {
            return MwPrep::Continue;
        }

        let user_token = req
            .headers
            .get("X-Auth-Token")
            .or_else(|| req.headers.get("X-Storage-Token"))
            .map(|s| s.to_string());
        let service_token = req.headers.get("X-Service-Token").map(|s| s.to_string());

        let user_check = match user_token.as_deref() {
            Some(t) if !t.is_empty() => self.validator.validate(t),
            _ => TokenOutcome::Indeterminate,
        };

        match user_check {
            TokenOutcome::Invalid | TokenOutcome::Indeterminate => {
                if !self.delay_auth_decision {
                    return MwPrep::ShortCircuit(self.unauthorized());
                }
                req.headers.set("X-Identity-Status", "Invalid");
            }
            TokenOutcome::Confirmed(mut validated) => {
                let service = match service_token.as_deref() {
                    Some(t) if !t.is_empty() => match self.validator.validate(t) {
                        TokenOutcome::Confirmed(svc) => {
                            validated.identity.service_roles = svc.identity.roles.clone();
                            Some(svc)
                        }
                        TokenOutcome::Invalid => return MwPrep::ShortCircuit(self.unauthorized()),
                        TokenOutcome::Indeterminate => None,
                    },
                    _ => None,
                };
                Self::stamp(req, &validated, service.as_deref());
            }
        }
        MwPrep::Continue
    }

    fn prepare_async<'a>(
        &'a self,
        req: &'a mut Request,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = MwPrep> + Send + 'a>> {
        Box::pin(async move {
            if !self.validator.needs_network() {
                return self.prepare(req);
            }
            Self::clear_identity(req);
            if req
                .headers
                .get("X-Backend-Authorize-Override")
                .map(|v| matches!(v.to_ascii_lowercase().as_str(), "true" | "1" | "yes" | "on"))
                .unwrap_or(false)
            {
                return MwPrep::Continue;
            }
            let user_token = req
                .headers
                .get("X-Auth-Token")
                .or_else(|| req.headers.get("X-Storage-Token"))
                .map(|s| s.to_string());
            let service_token = req.headers.get("X-Service-Token").map(|s| s.to_string());
            let user_check = match user_token.as_deref() {
                Some(t) if !t.is_empty() => self.validator.validate_async(t).await,
                _ => TokenOutcome::Indeterminate,
            };
            match user_check {
                TokenOutcome::Invalid | TokenOutcome::Indeterminate => {
                    if !self.delay_auth_decision {
                        return MwPrep::ShortCircuit(self.unauthorized());
                    }
                    req.headers.set("X-Identity-Status", "Invalid");
                }
                TokenOutcome::Confirmed(mut validated) => {
                    let service = match service_token.as_deref() {
                        Some(t) if !t.is_empty() => match self.validator.validate_async(t).await {
                            TokenOutcome::Confirmed(svc) => {
                                validated.identity.service_roles = svc.identity.roles.clone();
                                Some(svc)
                            }
                            TokenOutcome::Invalid => {
                                return MwPrep::ShortCircuit(self.unauthorized())
                            }
                            TokenOutcome::Indeterminate => None,
                        },
                        _ => None,
                    };
                    Self::stamp(req, &validated, service.as_deref());
                }
            }
            MwPrep::Continue
        })
    }

    fn handle(&self, mut req: Request, next: &NextFn) -> Response {
        match self.prepare(&mut req) {
            MwPrep::ShortCircuit(resp) => resp,
            MwPrep::Continue => next(req),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use swift_http::HeaderKeyDict;

    fn mk(headers: &[(&str, &str)]) -> Request {
        let mut h = HeaderKeyDict::new();
        for (k, v) in headers {
            h.set(k, *v);
        }
        Request {
            method: "GET".into(),
            path: "/v1/AUTH_t1/c/o".into(),
            query_string: String::new(),
            headers: h,
            body: swift_http::Body::empty(),
        }
    }

    fn sample_token(roles: &[&str]) -> ValidatedToken {
        ValidatedToken {
            identity: Identity {
                user_id: "u1".into(),
                user_name: "alice".into(),
                tenant_id: "t1".into(),
                tenant_name: "proj".into(),
                roles: roles.iter().map(|s| s.to_ascii_lowercase()).collect(),
                service_roles: vec![],
            },
            user_domain_id: "default".into(),
            user_domain_name: "Default".into(),
            project_domain_id: "default".into(),
            project_domain_name: "Default".into(),
        }
    }

    #[test]
    fn stamps_confirmed_identity() {
        let mut map = StaticTokenMap::new();
        map.insert("good", sample_token(&["admin"]));
        let at = AuthToken::new(Arc::new(map));
        let seen = Arc::new(Mutex::new(None::<String>));
        let s2 = seen.clone();
        let app: NextFn = Arc::new(move |r: Request| {
            *s2.lock().unwrap() = r.headers.get("X-Identity-Status").map(|s| s.to_string());
            assert_eq!(r.headers.get("X-User-Id"), Some("u1"));
            assert_eq!(r.headers.get("X-Project-Id"), Some("t1"));
            assert_eq!(r.headers.get("X-Roles"), Some("admin"));
            Response::new(204)
        });
        let resp = at.handle(mk(&[("X-Auth-Token", "good")]), &app);
        assert_eq!(resp.status, 204);
        assert_eq!(seen.lock().unwrap().as_deref(), Some("Confirmed"));
    }

    #[test]
    fn stamps_backend_authtoken_marker() {
        let mut map = StaticTokenMap::new();
        map.insert("good", sample_token(&["admin"]));
        let at = AuthToken::new(Arc::new(map));
        let app: NextFn = Arc::new(|r: Request| {
            assert_eq!(
                r.headers.get("X-Backend-Authtoken-Status"),
                Some("Confirmed")
            );
            Response::new(204)
        });
        assert_eq!(at.handle(mk(&[("X-Auth-Token", "good")]), &app).status, 204);
    }

    #[test]
    fn invalid_token_deferred_when_delay() {
        // keystone_coexist: TempAuth tokens fail Keystone validate but must
        // reach the next filter (TempAuth) — same as keystonemiddleware delay.
        let at = AuthToken::new(Arc::new(StaticTokenMap::new()));
        let seen = Arc::new(Mutex::new(None::<String>));
        let s2 = seen.clone();
        let app: NextFn = Arc::new(move |r: Request| {
            *s2.lock().unwrap() = r.headers.get("X-Identity-Status").map(|s| s.to_string());
            Response::new(204)
        });
        let resp = at.handle(mk(&[("X-Auth-Token", "AUTH_tkbogus")]), &app);
        assert_eq!(resp.status, 204);
        assert_eq!(seen.lock().unwrap().as_deref(), Some("Invalid"));
    }

    #[test]
    fn invalid_token_is_401_without_delay() {
        let at = AuthToken::new(Arc::new(StaticTokenMap::new())).with_delay(false);
        let app: NextFn = Arc::new(|_r| Response::new(204));
        let resp = at.handle(mk(&[("X-Auth-Token", "bogus")]), &app);
        assert_eq!(resp.status, 401);
        assert!(resp.headers.get("Www-Authenticate").is_some());
    }

    #[test]
    fn forged_client_identity_cleared_without_token() {
        let at = AuthToken::new(Arc::new(StaticTokenMap::new()));
        let seen = Arc::new(Mutex::new(None::<String>));
        let s2 = seen.clone();
        let app: NextFn = Arc::new(move |r: Request| {
            *s2.lock().unwrap() = r.headers.get("X-Identity-Status").map(|s| s.to_string());
            assert!(r.headers.get("X-Roles").is_none());
            Response::new(204)
        });
        let resp = at.handle(
            mk(&[
                ("X-Identity-Status", "Confirmed"),
                ("X-Roles", "admin"),
                ("X-Project-Id", "evil"),
            ]),
            &app,
        );
        assert_eq!(resp.status, 204);
        assert_eq!(seen.lock().unwrap().as_deref(), Some("Invalid"));
    }

    #[test]
    fn no_delay_missing_token_401() {
        let at = AuthToken::new(Arc::new(StaticTokenMap::new())).with_delay(false);
        let app: NextFn = Arc::new(|_r| Response::new(204));
        let resp = at.handle(mk(&[]), &app);
        assert_eq!(resp.status, 401);
    }

    #[test]
    fn http_json_accepts_http_and_https_schemes_only() {
        let err = http_json(
            "GET",
            "ftp://keystone.example/v3",
            &[],
            None,
            Duration::from_millis(50),
        )
        .unwrap_err();
        assert!(
            err.contains("http://") && err.contains("https://"),
            "unexpected err: {err}"
        );
        // https:// with unresolvable/closed host must fail at connect/TLS, not
        // at scheme parse — proves https:// is accepted as a scheme.
        let https_err = http_json(
            "GET",
            "https://127.0.0.1:1/v3",
            &[],
            None,
            Duration::from_millis(200),
        )
        .unwrap_err();
        assert!(
            !https_err.contains("must be http:// or https://"),
            "https scheme rejected early: {https_err}"
        );
    }

    #[test]
    fn parse_keystone_token_json() {
        let body = br#"{
          "token": {
            "user": {"id":"u9","name":"bob","domain":{"id":"default","name":"Default"}},
            "project": {"id":"p9","name":"demo","domain":{"id":"default","name":"Default"}},
            "roles": [{"name":"admin"},{"name":"member"}]
          }
        }"#;
        let v = parse_token_body(body).unwrap();
        assert_eq!(v.identity.user_id, "u9");
        assert_eq!(v.identity.tenant_id, "p9");
        assert!(v.identity.roles.contains(&"admin".to_string()));
    }
}
