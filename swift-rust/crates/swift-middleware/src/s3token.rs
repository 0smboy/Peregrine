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

//! `s3token` — exchange S3 SigV4 credentials for a Keystone token.
//!
//! Port of `swift/common/middleware/s3token.py` (Wave 3 / production stop-line):
//! when a request already carries S3 auth details (stamped by `s3api` as
//! `X-Backend-S3-*` headers, or when `s3api` calls [`S3TokenClient`] inline),
//! POST `{auth_uri}/v3/s3tokens` with access key / signature / **urlsafe-base64
//! string-to-sign** and stamp the returned Keystone token headers so
//! `keystoneauth` can authorize.
//!
//! Keystone `credentials.token` must be urlsafe-base64 of the raw SigV4
//! string-to-sign (Python `base64.urlsafe_b64encode`). Never post `X-Amz-Date`
//! as the token — that is not valid base64 of a SigV4 STS and yields 401.
//!
//! [`HttpS3TokenClient`] performs a real HTTP(S) exchange (same transport
//! style as `authtoken`). Without a reachable Keystone, exchange returns
//! `None` and the filter passthroughs (honest ON-BY-CONFIG). Unit tests use
//! [`MapS3TokenClient`].

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE;
use base64::Engine;
use swift_http::{Request, Response};

use crate::{Middleware, NextFn};

/// Backend headers stamped by `s3api` (Python `s3api.auth_details` environ).
pub const HDR_S3_ACCESS_KEY: &str = "X-Backend-S3-Access-Key";
pub const HDR_S3_SIGNATURE: &str = "X-Backend-S3-Signature";
/// Raw UTF-8 SigV4 string-to-sign (not base64). Client encodes for Keystone.
pub const HDR_S3_STRING_TO_SIGN: &str = "X-Backend-S3-String-To-Sign";

/// Urlsafe-base64 encode (with padding), matching Python
/// `base64.urlsafe_b64encode(...).decode('ascii')`.
pub fn encode_s3tokens_token(string_to_sign: &[u8]) -> String {
    URL_SAFE.encode(string_to_sign)
}

/// Outcome of an s3tokens exchange.
#[derive(Debug, Clone)]
pub struct S3TokenResult {
    pub token_id: String,
    pub project_id: String,
    pub project_name: String,
    pub user_id: String,
    pub user_name: String,
    pub roles: Vec<String>,
}

/// Pluggable Keystone `/v3/s3tokens` client.
pub trait S3TokenClient: Send + Sync {
    fn exchange(&self, access_key: &str, signature: &str, string_to_sign: &str) -> Option<S3TokenResult>;
}

/// In-memory map for unit tests (access_key → result).
#[derive(Debug, Default)]
pub struct MapS3TokenClient {
    map: HashMap<String, S3TokenResult>,
}

impl MapS3TokenClient {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, access_key: impl Into<String>, result: S3TokenResult) {
        self.map.insert(access_key.into(), result);
    }
}

impl S3TokenClient for MapS3TokenClient {
    fn exchange(&self, access_key: &str, _signature: &str, _string_to_sign: &str) -> Option<S3TokenResult> {
        self.map.get(access_key).cloned()
    }
}

/// HTTP Keystone s3tokens client (live-ready). Failures → `None` (passthrough).
pub struct HttpS3TokenClient {
    auth_uri: String,
    timeout: Duration,
}

impl HttpS3TokenClient {
    pub fn new(auth_uri: impl Into<String>) -> Self {
        Self {
            auth_uri: auth_uri.into().trim_end_matches('/').to_string(),
            timeout: Duration::from_secs(5),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Exposed for unit tests against a local listener.
    pub fn auth_uri(&self) -> &str {
        &self.auth_uri
    }
}

impl S3TokenClient for HttpS3TokenClient {
    fn exchange(&self, access_key: &str, signature: &str, string_to_sign: &str) -> Option<S3TokenResult> {
        // Body matches Python s3token (`credentials.access/token/signature`).
        // `token` is urlsafe-base64 of the raw SigV4 string-to-sign bytes.
        let token = encode_s3tokens_token(string_to_sign.as_bytes());
        let body = format!(
            "{{\"credentials\":{{\"access\":\"{}\",\"token\":\"{}\",\"signature\":\"{}\"}}}}",
            json_escape(access_key),
            json_escape(&token),
            json_escape(signature),
        );
        // auth_uri may be `http://host:5001` or `http://host:5000/v3` (Python style).
        let url = if self.auth_uri.ends_with("/v3") {
            format!("{}/s3tokens", self.auth_uri)
        } else {
            format!("{}/v3/s3tokens", self.auth_uri)
        };
        let (status, headers, resp_body) = http_post_json(&url, &body, self.timeout).ok()?;
        if !(200..300).contains(&status) {
            return None;
        }
        let mut result = parse_s3tokens_response(&String::from_utf8_lossy(&resp_body))?;
        // Keystone often returns the token id only in X-Subject-Token.
        if result.token_id.is_empty() {
            if let Some(subj) = headers.get("x-subject-token") {
                result.token_id = subj.clone();
            }
        }
        Some(result)
    }
}

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Tiny sync HTTP/1.1 POST (http + https via native-tls), matching authtoken.
fn http_post_json(
    url: &str,
    body: &str,
    timeout: Duration,
) -> Result<(u16, HashMap<String, String>, Vec<u8>), String> {
    let (https, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        return Err(format!("auth_uri must be http:// or https:// (got {url})"));
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

    let mut req = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    req.push_str(body);

    let mut buf = Vec::new();
    if https {
        let connector = native_tls::TlsConnector::builder()
            .build()
            .map_err(|e| format!("tls connector: {e}"))?;
        let mut tls = connector
            .connect(&host, stream)
            .map_err(|e| format!("tls handshake to {host}: {e}"))?;
        tls.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
        tls.read_to_end(&mut buf).map_err(|e| e.to_string())?;
    } else {
        let mut stream = stream;
        stream.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
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

fn parse_s3tokens_response(body: &str) -> Option<S3TokenResult> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    let token = v.get("token")?;
    let project = token.get("project")?;
    let user = token.get("user")?;
    let roles = token
        .get("roles")
        .and_then(|r| r.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|r| r.get("name").and_then(|n| n.as_str()).map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    Some(S3TokenResult {
        token_id: token
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        project_id: project.get("id")?.as_str()?.to_string(),
        project_name: project
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        user_id: user.get("id")?.as_str()?.to_string(),
        user_name: user
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        roles,
    })
}

/// Extract access key from an AWS4 Authorization header (Credential=…).
pub fn access_key_from_authorization(auth: &str) -> Option<String> {
    let cred = auth.split("Credential=").nth(1)?;
    let token = cred.split(',').next()?.trim();
    let access = token.split('/').next()?.trim();
    if access.is_empty() {
        None
    } else {
        Some(access.to_string())
    }
}

/// `s3token` middleware.
pub struct S3Token {
    client: Arc<dyn S3TokenClient>,
    /// Reseller prefix stamped into storage-account helper (default AUTH_).
    pub reseller_prefix: String,
}

impl S3Token {
    pub fn new(client: Arc<dyn S3TokenClient>) -> Self {
        Self {
            client,
            reseller_prefix: "AUTH_".into(),
        }
    }

    pub fn with_reseller_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.reseller_prefix = prefix.into();
        self
    }
}

/// Pull access/signature/raw-STS from s3api-stamped backend headers, falling
/// back to Authorization for access+signature only. Without a raw string-to-sign
/// header we passthrough (never invent a token from `X-Amz-Date`).
fn auth_details_from_request(req: &Request) -> Option<(String, String, String)> {
    let string_to_sign = req.headers.get(HDR_S3_STRING_TO_SIGN)?.to_string();
    if string_to_sign.is_empty() {
        return None;
    }
    let access_key = req
        .headers
        .get(HDR_S3_ACCESS_KEY)
        .map(str::to_string)
        .or_else(|| {
            req.headers
                .get("Authorization")
                .and_then(access_key_from_authorization)
        })?;
    let signature = req
        .headers
        .get(HDR_S3_SIGNATURE)
        .map(str::to_string)
        .or_else(|| {
            req.headers.get("Authorization").and_then(|auth| {
                auth.split("Signature=")
                    .nth(1)
                    .map(|s| s.trim().to_string())
            })
        })
        .unwrap_or_default();
    Some((access_key, signature, string_to_sign))
}

fn strip_s3_auth_detail_headers(req: &mut Request) {
    req.headers.remove(HDR_S3_ACCESS_KEY);
    req.headers.remove(HDR_S3_SIGNATURE);
    req.headers.remove(HDR_S3_STRING_TO_SIGN);
}

impl Middleware for S3Token {
    fn handle(&self, mut req: Request, next: &NextFn) -> Response {
        let Some((access_key, signature, string_to_sign)) = auth_details_from_request(&req) else {
            return next(req);
        };
        let Some(result) = self.client.exchange(&access_key, &signature, &string_to_sign) else {
            return next(req);
        };
        strip_s3_auth_detail_headers(&mut req);
        req.headers.set("X-Identity-Status", "Confirmed");
        req.headers.set("X-Project-Id", &result.project_id);
        req.headers.set("X-Project-Name", &result.project_name);
        req.headers.set("X-User-Id", &result.user_id);
        req.headers.set("X-User-Name", &result.user_name);
        req.headers.set("X-Roles", result.roles.join(","));
        if !result.token_id.is_empty() {
            req.headers.set("X-Auth-Token", &result.token_id);
        }
        req.headers.set(
            "X-Backend-Storage-Account",
            format!("{}{}", self.reseller_prefix, result.project_id),
        );
        next(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;
    use swift_http::{Body, HeaderKeyDict};

    #[test]
    fn access_key_parse() {
        let a = "AWS4-HMAC-SHA256 Credential=AKIA/20130524/us-east-1/s3/aws4_request, \
                 SignedHeaders=host, Signature=abc";
        assert_eq!(access_key_from_authorization(a).as_deref(), Some("AKIA"));
    }

    #[test]
    fn stamps_headers_on_exchange() {
        let mut map = MapS3TokenClient::new();
        map.insert(
            "AKIA",
            S3TokenResult {
                token_id: "tok".into(),
                project_id: "pid".into(),
                project_name: "demo".into(),
                user_id: "uid".into(),
                user_name: "alice".into(),
                roles: vec!["admin".into()],
            },
        );
        let mw = S3Token::new(Arc::new(map));
        let mut headers = HeaderKeyDict::new();
        headers.set(
            "Authorization",
            "AWS4-HMAC-SHA256 Credential=AKIA/20130524/us-east-1/s3/aws4_request, \
             SignedHeaders=host, Signature=deadbeef",
        );
        headers.set(HDR_S3_STRING_TO_SIGN, "AWS4-HMAC-SHA256\n20130524T000000Z\nscope\nhash");
        headers.set(HDR_S3_ACCESS_KEY, "AKIA");
        headers.set(HDR_S3_SIGNATURE, "deadbeef");
        let req = Request {
            method: "GET".into(),
            path: "/".into(),
            query_string: String::new(),
            headers,
            body: Body::empty(),
        };
        let next: NextFn = Arc::new(|r| {
            assert_eq!(r.headers.get("X-Identity-Status"), Some("Confirmed"));
            assert_eq!(r.headers.get("X-Project-Id"), Some("pid"));
            assert_eq!(r.headers.get("X-Roles"), Some("admin"));
            // Auth-detail headers must not leak downstream.
            assert!(r.headers.get(HDR_S3_STRING_TO_SIGN).is_none());
            Response::new(200)
        });
        assert_eq!(mw.handle(req, &next).status, 200);
    }

    #[test]
    fn passthrough_without_s3_auth() {
        let mw = S3Token::new(Arc::new(MapS3TokenClient::new()));
        let req = Request {
            method: "GET".into(),
            path: "/v1/AUTH_test".into(),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: Body::empty(),
        };
        let next: NextFn = Arc::new(|r| {
            assert!(r.headers.get("X-Identity-Status").is_none());
            Response::new(204)
        });
        assert_eq!(mw.handle(req, &next).status, 204);
    }

    #[test]
    fn passthrough_when_only_amz_date_no_sts_header() {
        // Regression: never treat X-Amz-Date as Keystone credentials.token.
        let mut map = MapS3TokenClient::new();
        map.insert(
            "AKIA",
            S3TokenResult {
                token_id: "tok".into(),
                project_id: "pid".into(),
                project_name: "demo".into(),
                user_id: "uid".into(),
                user_name: "alice".into(),
                roles: vec!["admin".into()],
            },
        );
        let mw = S3Token::new(Arc::new(map));
        let mut headers = HeaderKeyDict::new();
        headers.set(
            "Authorization",
            "AWS4-HMAC-SHA256 Credential=AKIA/20130524/us-east-1/s3/aws4_request, \
             SignedHeaders=host, Signature=deadbeef",
        );
        headers.set("X-Amz-Date", "20130524T000000Z");
        let req = Request {
            method: "GET".into(),
            path: "/".into(),
            query_string: String::new(),
            headers,
            body: Body::empty(),
        };
        let next: NextFn = Arc::new(|r| {
            assert!(r.headers.get("X-Identity-Status").is_none());
            Response::new(204)
        });
        assert_eq!(mw.handle(req, &next).status, 204);
    }

    #[test]
    fn encode_s3tokens_token_urlsafe_b64() {
        let sts = b"AWS4-HMAC-SHA256\n20130524T000000Z\nscope\nhash";
        let enc = encode_s3tokens_token(sts);
        assert_eq!(enc, URL_SAFE.encode(sts));
        // Round-trip.
        let decoded = URL_SAFE.decode(enc.as_bytes()).unwrap();
        assert_eq!(decoded, sts);
    }

    #[test]
    fn parse_s3tokens_json_body() {
        let body = r#"{
          "token": {
            "id": "t1",
            "project": {"id": "p1", "name": "demo"},
            "user": {"id": "u1", "name": "alice"},
            "roles": [{"name": "admin"}, {"name": "member"}]
          }
        }"#;
        let r = parse_s3tokens_response(body).unwrap();
        assert_eq!(r.token_id, "t1");
        assert_eq!(r.project_id, "p1");
        assert_eq!(r.roles, vec!["admin", "member"]);
    }

    #[test]
    fn http_s3token_client_live_against_local_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let raw_sts = "AWS4-HMAC-SHA256\n20130524T000000Z\nscope\nhash";
        let expect_token = encode_s3tokens_token(raw_sts.as_bytes());
        let handle = thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut buf = [0u8; 8192];
            let n = sock.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]);
            assert!(req.contains("POST /v3/s3tokens"));
            assert!(req.contains("\"access\":\"AKIA\""));
            // Must post base64 STS, never the raw date alone.
            assert!(req.contains(&format!("\"token\":\"{expect_token}\"")));
            assert!(!req.contains("\"token\":\"20130524T000000Z\""));
            let body = r#"{"token":{"project":{"id":"pid","name":"demo"},"user":{"id":"uid","name":"alice"},"roles":[{"name":"admin"}]}}"#;
            let resp = format!(
                "HTTP/1.1 201 Created\r\nContent-Length: {}\r\nX-Subject-Token: subj-tok\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            sock.write_all(resp.as_bytes()).unwrap();
        });
        let client = HttpS3TokenClient::new(format!("http://127.0.0.1:{port}"));
        let result = client
            .exchange("AKIA", "sig", raw_sts)
            .expect("live HTTP exchange");
        assert_eq!(result.project_id, "pid");
        assert_eq!(result.token_id, "subj-tok");
        handle.join().unwrap();
    }
}
