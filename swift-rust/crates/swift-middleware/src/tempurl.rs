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

//! `tempurl`: grants temporary, signed access to Swift resources, a
//! faithful port of `swift/common/middleware/tempurl.py`. A client presents
//! `temp_url_sig` and `temp_url_expires` query parameters; the signature is
//! an HMAC (RFC 2104) over the message `"<method>\n<expires>\n<path>"` keyed
//! by an account- or container-level Temp-URL key. On a valid, unexpired
//! signature for one of the configured methods the request is let through
//! (its query string rewritten to only the tempurl-relevant parameters, and
//! configured incoming headers scrubbed); on any failure a `401
//! Unauthorized` is returned. For a successful `GET`/`HEAD` a
//! `Content-Disposition` and `Expires` header are added to the response, and
//! configured outgoing headers are scrubbed.
//!
//! Supported signature encodings match the Python: a bare lowercase hex
//! digest (length selects `sha1`/`sha256`/`sha512`) or an
//! `"<algorithm>:<base64 digest>"` form (standard or url-safe base64). A
//! `HEAD` matches signatures minted for `HEAD`, `GET`, `POST`, or `PUT`.
//! Prefix (`temp_url_prefix`), `filename`, and `inline` are all honored,
//! including the staticweb container-root carve-out.
//!
//! Keys are supplied through the injectable [`KeyProvider`] trait rather than
//! the Python `get_account_info`/`get_container_info` subrequests: the
//! provider returns every candidate key (account and container) for the
//! request's account/container.
//!
//! On a valid signature this middleware stamps
//! `X-Backend-Authorize-Override: true` and
//! `X-Backend-Remote-User: .wsgi.tempurl` (Python `authorize_override` +
//! `REMOTE_USER`). Account-vs-container key *scope* is not tracked: the
//! [`KeyProvider`] returns a flat key list.
//!
//! `temp_url_ip_range` is supported: client address is taken from
//! `X-Backend-Remote-Addr` (stamped by the HTTP server from the TCP peer),
//! then `X-Forwarded-For` / `X-Real-IP`. The HMAC body becomes
//! `ip={range}\n{method}\n{expires}\n{path}` (Python `get_hmac`).
//!
//! Deferrals: `logger.increment('tempurl.digests.*')` metrics.
//!
//! Wiring: the proxy supplies a [`KeyProvider`] that HEADs account/container
//! metadata for `Temp-URL-Key[-2]`. `/info` advertising is done by the proxy
//! when the filter is enabled (not inside this crate).

use std::sync::Arc;

use sha1::{Digest, Sha1};
use sha2::{Sha256, Sha512};

use swift_http::{http_date, split_path, title_case, HeaderKeyDict, Request, Response};

use crate::{Middleware, MwPrep, NextFn};

/// Header names that may never accompany an "unsafe" (write) tempurl
/// request, mirroring `DISALLOWED_INCOMING_HEADERS`. Blocking these prevents
/// a PUT tempurl from uploading a pointer (dynamic large object manifest or
/// symlink) to data the tempurl would not otherwise grant access to.
const DISALLOWED_INCOMING_HEADERS: [&str; 2] = ["X-Object-Manifest", "X-Symlink-Target"];

/// Default `incoming_remove_headers` (`DEFAULT_INCOMING_REMOVE_HEADERS`).
const DEFAULT_INCOMING_REMOVE_HEADERS: [&str; 2] = ["x-timestamp", "x-open-expired"];
/// Default `outgoing_remove_headers` (`DEFAULT_OUTGOING_REMOVE_HEADERS`).
const DEFAULT_OUTGOING_REMOVE_HEADERS: [&str; 1] = ["x-object-meta-*"];
/// Default `outgoing_allow_headers` (`DEFAULT_OUTGOING_ALLOW_HEADERS`).
const DEFAULT_OUTGOING_ALLOW_HEADERS: [&str; 1] = ["x-object-meta-public-*"];
/// Default `methods`.
const DEFAULT_METHODS: [&str; 5] = ["GET", "HEAD", "PUT", "POST", "DELETE"];
/// Default `allowed_digests` (`DEFAULT_ALLOWED_DIGESTS` from
/// `swift/common/digest.py`).
const DEFAULT_ALLOWED_DIGESTS: [&str; 3] = ["sha1", "sha256", "sha512"];

/// Supplies the Temp-URL keys for a request's account and container.
///
/// This replaces the Python `_get_keys` helper, which reads the
/// `X-[Account|Container]-Meta-Temp-URL-Key[-2]` metadata via
/// `get_account_info`/`get_container_info` subrequests. Implementations
/// return every candidate key (up to two account keys and two container
/// keys); the signature is checked against all of them.
pub trait KeyProvider: Send + Sync {
    /// All Temp-URL keys configured for `account`/`container`, in any order.
    fn keys_for(&self, account: &str, container: &str) -> Vec<String>;
}

/// [`KeyProvider`] backed by an injectable closure (proxy wires account /
/// container meta HEAD lookups).
pub struct ClosureKeyProvider {
    inner: Arc<dyn Fn(&str, &str) -> Vec<String> + Send + Sync>,
}

impl ClosureKeyProvider {
    pub fn new<F>(f: F) -> Self
    where
        F: Fn(&str, &str) -> Vec<String> + Send + Sync + 'static,
    {
        ClosureKeyProvider { inner: Arc::new(f) }
    }
}

impl KeyProvider for ClosureKeyProvider {
    fn keys_for(&self, account: &str, container: &str) -> Vec<String> {
        (self.inner)(account, container)
    }
}

/// Exact-name plus prefix-match rules parsed from a header configuration
/// list (tokens ending in `*` are prefix rules). All comparisons are done on
/// lowercased names.
struct HeaderRules {
    exact: Vec<String>,
    prefix: Vec<String>,
}

impl HeaderRules {
    fn from_tokens<I, S>(tokens: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut exact = Vec::new();
        let mut prefix = Vec::new();
        for token in tokens {
            let token = token.as_ref().to_lowercase();
            if let Some(p) = token.strip_suffix('*') {
                prefix.push(p.to_string());
            } else {
                exact.push(token);
            }
        }
        HeaderRules { exact, prefix }
    }

    fn matches(&self, name_lower: &str) -> bool {
        self.exact.iter().any(|e| e == name_lower)
            || self
                .prefix
                .iter()
                .any(|p| name_lower.starts_with(p.as_str()))
    }
}

/// WSGI middleware granting temporary URLs specific access to Swift
/// resources.
pub struct TempUrl {
    /// Request methods allowed to be used with a temporary URL (config
    /// `methods`).
    pub methods: Vec<String>,
    /// Headers removed from incoming requests (config
    /// `incoming_remove_headers`; tokens ending in `*` are prefix rules).
    pub incoming_remove_headers: Vec<String>,
    /// Exceptions to `incoming_remove_headers` (config
    /// `incoming_allow_headers`).
    pub incoming_allow_headers: Vec<String>,
    /// Headers removed from outgoing responses (config
    /// `outgoing_remove_headers`).
    pub outgoing_remove_headers: Vec<String>,
    /// Exceptions to `outgoing_remove_headers` (config
    /// `outgoing_allow_headers`).
    pub outgoing_allow_headers: Vec<String>,
    /// Digest algorithms accepted in a signature (config `allowed_digests`).
    pub allowed_digests: Vec<String>,
    /// Source of the account/container Temp-URL keys.
    pub key_provider: Arc<dyn KeyProvider>,
}

impl TempUrl {
    /// Construct with Swift's default configuration around a key provider.
    pub fn new(key_provider: Arc<dyn KeyProvider>) -> Self {
        TempUrl {
            methods: DEFAULT_METHODS.iter().map(|s| s.to_string()).collect(),
            incoming_remove_headers: DEFAULT_INCOMING_REMOVE_HEADERS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            incoming_allow_headers: Vec::new(),
            outgoing_remove_headers: DEFAULT_OUTGOING_REMOVE_HEADERS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            outgoing_allow_headers: DEFAULT_OUTGOING_ALLOW_HEADERS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            allowed_digests: DEFAULT_ALLOWED_DIGESTS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            key_provider,
        }
    }

    /// Build from a `[filter:tempurl]` conf map around a key provider.
    pub fn from_conf(
        options: &std::collections::HashMap<String, String>,
        key_provider: Arc<dyn KeyProvider>,
    ) -> Self {
        let mut tu = TempUrl::new(key_provider);
        if let Some(v) = options.get("methods") {
            let methods: Vec<String> = v.split_whitespace().map(|s| s.to_string()).collect();
            if !methods.is_empty() {
                tu.methods = methods;
            }
        }
        if let Some(v) = options.get("allowed_digests") {
            let digests: Vec<String> = v
                .split_whitespace()
                .map(|s| s.to_ascii_lowercase())
                .collect();
            if !digests.is_empty() {
                tu.allowed_digests = digests;
            }
        }
        if let Some(v) = options.get("incoming_remove_headers") {
            tu.incoming_remove_headers = v.split_whitespace().map(|s| s.to_string()).collect();
        }
        if let Some(v) = options.get("incoming_allow_headers") {
            tu.incoming_allow_headers = v.split_whitespace().map(|s| s.to_string()).collect();
        }
        if let Some(v) = options.get("outgoing_remove_headers") {
            tu.outgoing_remove_headers = v.split_whitespace().map(|s| s.to_string()).collect();
        }
        if let Some(v) = options.get("outgoing_allow_headers") {
            tu.outgoing_allow_headers = v.split_whitespace().map(|s| s.to_string()).collect();
        }
        tu
    }

    /// `/info` fragment for an enabled tempurl filter (Python
    /// `register_swift_info('tempurl', ...)`).
    pub fn info_dict(&self) -> serde_json::Value {
        let mut digests = self.allowed_digests.clone();
        digests.sort();
        serde_json::json!({
            "methods": self.methods,
            "incoming_remove_headers": self.incoming_remove_headers,
            "incoming_allow_headers": self.incoming_allow_headers,
            "outgoing_remove_headers": self.outgoing_remove_headers,
            "outgoing_allow_headers": self.outgoing_allow_headers,
            "allowed_digests": digests,
        })
    }

    /// `401 Unauthorized`, matching `_invalid`: a `HEAD` gets an empty body,
    /// everything else the plain-text `"401 Unauthorized: Temp URL
    /// invalid\n"`. swob renders both with a `text/html` content type.
    fn invalid(&self, method: &str) -> Response {
        let mut resp = if method == "HEAD" {
            Response::new(401)
        } else {
            Response::with_body(401, "401 Unauthorized: Temp URL invalid\n")
        };
        resp.headers.set("Content-Type", "text/html; charset=UTF-8");
        resp
    }

    /// Port of `_get_path_parts`. Returns `(account, container, object)` when
    /// the request targets a `v1` object (or, when `allow_container_root`,
    /// the container root, giving an empty object) under one of the
    /// configured methods; `None` otherwise.
    fn get_path_parts(
        &self,
        path: &str,
        method: &str,
        allow_container_root: bool,
    ) -> Option<(String, String, String)> {
        if !self.methods.iter().any(|m| m == method) {
            return None;
        }
        let minsegs = if allow_container_root { 3 } else { 4 };
        let parts = split_path(path, minsegs, 4, true).ok()?;
        let ver = parts[0].as_deref().unwrap_or("");
        let acc = parts[1].clone().unwrap_or_default();
        let cont = parts[2].clone().unwrap_or_default();
        let obj_opt = parts[3].clone();
        let obj_nonroot = obj_opt
            .as_deref()
            .map(|o| !o.trim_matches('/').is_empty())
            .unwrap_or(false);
        if ver == "v1" && (allow_container_root || obj_nonroot) {
            return Some((acc, cont, obj_opt.unwrap_or_default()));
        }
        None
    }

    /// Port of `_clean_disallowed_headers`: reject an unsafe (non
    /// `GET`/`HEAD`/`OPTIONS`) request carrying a disallowed header with
    /// `400 Bad Request`.
    fn clean_disallowed_headers(&self, req: &Request) -> Option<Response> {
        if matches!(req.method.as_str(), "GET" | "HEAD" | "OPTIONS") {
            return None;
        }
        for name in DISALLOWED_INCOMING_HEADERS {
            if req.headers.contains_key(name) {
                let body = format!(
                    "The header '{}' is not allowed in this tempurl",
                    title_case(name)
                );
                let mut resp = Response::with_body(400, body);
                resp.headers.set("Content-Type", "text/html; charset=UTF-8");
                return Some(resp);
            }
        }
        None
    }

    /// Port of `_clean_incoming_headers`: drop configured headers from the
    /// request, honoring the allow list as an exception.
    fn clean_incoming_headers(&self, req: &mut Request) {
        let remove = HeaderRules::from_tokens(&self.incoming_remove_headers);
        let allow = HeaderRules::from_tokens(&self.incoming_allow_headers);
        let names: Vec<String> = req.headers.iter().map(|(k, _)| k.to_string()).collect();
        for name in names {
            let lower = name.to_lowercase();
            if allow.matches(&lower) {
                continue;
            }
            if remove.matches(&lower) {
                req.headers.remove(&name);
            }
        }
    }

    /// Port of `_clean_outgoing_headers`: drop configured headers from the
    /// response, honoring the allow list as an exception.
    fn clean_outgoing_headers(&self, headers: &mut HeaderKeyDict) {
        let remove = HeaderRules::from_tokens(&self.outgoing_remove_headers);
        let allow = HeaderRules::from_tokens(&self.outgoing_allow_headers);
        let names: Vec<String> = headers.iter().map(|(k, _)| k.to_string()).collect();
        for name in names {
            let lower = name.to_lowercase();
            if allow.matches(&lower) {
                continue;
            }
            if remove.matches(&lower) {
                headers.remove(&name);
            }
        }
    }

    /// True when `prepare` accepted a TempURL (Python `REMOTE_USER =
    /// .wsgi.tempurl`). Used by `finish` so Hyper outbound decoration
    /// does not run on ordinary authenticated responses.
    fn is_validated_tempurl(req: &Request) -> bool {
        req.headers.get("X-Backend-Remote-User") == Some(".wsgi.tempurl")
    }
}

impl Middleware for TempUrl {
    /// Production Hyper serve never calls `handle()`: HMAC, incoming
    /// scrub, query rewrite, and `X-Backend-Authorize-Override` live
    /// here so `ProxyAsyncService` copies them onto the async request
    /// before `authorize_async`.
    fn prepare(&self, req: &mut Request) -> MwPrep {
        // OPTIONS is never a tempurl request.
        if req.method == "OPTIONS" {
            return MwPrep::Continue;
        }

        // --- parse the tempurl query parameters (get_temp_url_info) ---
        let params = req.params();
        let first = |key: &str| -> Option<String> {
            params
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.clone())
        };
        let raw_sig = first("temp_url_sig");
        let raw_expires = first("temp_url_expires");
        let prefix = first("temp_url_prefix");
        let filename = first("filename");
        let ip_range = first("temp_url_ip_range");
        let inline = params.iter().any(|(k, _)| k == "inline");

        let expires = normalize_temp_url_expires(raw_expires.as_deref(), now_epoch());

        // No signature and no expires at all: not a tempurl request.
        if raw_sig.is_none() && expires.is_none() {
            return MwPrep::Continue;
        }
        // A tempurl attempt with a missing/empty signature or a
        // missing/expired (falsy) timestamp is invalid.
        let raw_sig = match raw_sig {
            Some(s) if !s.is_empty() => s,
            _ => return MwPrep::ShortCircuit(self.invalid(&req.method)),
        };
        let expires = match expires {
            Some(e) if e != 0 => e,
            _ => return MwPrep::ShortCircuit(self.invalid(&req.method)),
        };

        // --- decode the signature encoding (extract_digest_and_algorithm) ---
        let (algo, sig_hex) = match extract_digest_and_algorithm(&raw_sig) {
            Ok(pair) => pair,
            Err(()) => return MwPrep::ShortCircuit(self.invalid(&req.method)),
        };
        if !self.allowed_digests.contains(&algo) {
            return MwPrep::ShortCircuit(self.invalid(&req.method));
        }

        // --- resolve the path (get_path_parts) ---
        let allow_container_root =
            matches!(req.method.as_str(), "GET" | "HEAD") && prefix.as_deref() == Some("");
        let (account, container, obj) =
            match self.get_path_parts(&req.path, &req.method, allow_container_root) {
                Some(parts) => parts,
                None => return MwPrep::ShortCircuit(self.invalid(&req.method)),
            };

        // --- ip range gate (Python: REMOTE_ADDR ∈ temp_url_ip_range) ---
        if let Some(ref range) = ip_range {
            let client = client_remote_addr(req);
            if !client
                .as_deref()
                .map(|c| ip_in_range(c, range))
                .unwrap_or(false)
            {
                return MwPrep::ShortCircuit(self.invalid(&req.method));
            }
        }

        // --- fetch keys and build the signed message path ---
        let keys = self.key_provider.keys_for(&account, &container);
        if keys.is_empty() {
            return MwPrep::ShortCircuit(self.invalid(&req.method));
        }
        let path = match &prefix {
            None => format!("/v1/{account}/{container}/{obj}"),
            Some(pfx) => {
                if !obj.starts_with(pfx.as_str()) {
                    return MwPrep::ShortCircuit(self.invalid(&req.method));
                }
                format!("prefix:/v1/{account}/{container}/{pfx}")
            }
        };

        // A HEAD may satisfy a signature minted for HEAD/GET/POST/PUT.
        let candidate_methods: Vec<&str> = if req.method == "HEAD" {
            vec!["HEAD", "GET", "POST", "PUT"]
        } else {
            vec![req.method.as_str()]
        };
        let mut is_valid = false;
        'search: for m in &candidate_methods {
            let message = match &ip_range {
                Some(r) => format!("ip={r}\n{m}\n{expires}\n{path}"),
                None => format!("{m}\n{expires}\n{path}"),
            };
            for key in &keys {
                if let Some(candidate) = hmac_hex(&algo, key.as_bytes(), message.as_bytes()) {
                    if streq_const_time(&sig_hex, &candidate) {
                        is_valid = true;
                        break 'search;
                    }
                }
            }
        }
        if !is_valid {
            return MwPrep::ShortCircuit(self.invalid(&req.method));
        }

        // --- signature is valid: scrub headers and rewrite the query ---
        if let Some(resp) = self.clean_disallowed_headers(req) {
            return MwPrep::ShortCircuit(resp);
        }
        self.clean_incoming_headers(req);

        let mut qs_pairs: Vec<(String, String)> = vec![
            ("temp_url_sig".to_string(), sig_hex.clone()),
            ("temp_url_expires".to_string(), raw_expires_string(&params)),
        ];
        if let Some(r) = &ip_range {
            qs_pairs.push(("temp_url_ip_range".to_string(), r.clone()));
        }
        if let Some(pfx) = &prefix {
            qs_pairs.push(("temp_url_prefix".to_string(), pfx.clone()));
        }
        let filename_nonempty = filename.as_deref().filter(|f| !f.is_empty());
        if let Some(f) = filename_nonempty {
            qs_pairs.push(("filename".to_string(), f.to_string()));
        }
        if inline {
            qs_pairs.push(("inline".to_string(), String::new()));
        }
        req.query_string = urlencode(&qs_pairs);

        // Bypass TempAuth + proxy ACL checks (Python authorize_override).
        req.headers.set("X-Backend-Authorize-Override", "true");
        req.headers.set("X-Backend-Remote-User", ".wsgi.tempurl");
        // Numeric expires for finish() Content-Disposition / Expires so
        // Hyper outbound does not re-parse ISO8601 vs epoch.
        req.headers
            .set("X-Backend-Tempurl-Expires", expires.to_string());
        // Empty object marks the staticweb container-root carve-out.
        req.headers.set("X-Backend-Tempurl-Object", &obj);

        MwPrep::Continue
    }

    fn handle(&self, mut req: Request, next: &NextFn) -> Response {
        match self.prepare(&mut req) {
            MwPrep::ShortCircuit(resp) => resp,
            MwPrep::Continue => {
                let head = req.clone_head();
                self.finish(&head, next(req))
            }
        }
    }

    fn finish(&self, req: &Request, mut resp: Response) -> Response {
        if !Self::is_validated_tempurl(req) {
            return resp;
        }

        self.clean_outgoing_headers(&mut resp.headers);

        if !matches!(req.method.as_str(), "GET" | "HEAD") || !(200..=299).contains(&resp.status) {
            return resp;
        }

        let params = req.params();
        let filename = params
            .iter()
            .find(|(k, _)| k == "filename")
            .map(|(_, v)| v.clone())
            .filter(|f| !f.is_empty());
        let inline = params.iter().any(|(k, _)| k == "inline");
        let expires = req
            .headers
            .get("X-Backend-Tempurl-Expires")
            .and_then(|s| s.parse::<i64>().ok())
            .or_else(|| {
                normalize_temp_url_expires(
                    params
                        .iter()
                        .find(|(k, _)| k == "temp_url_expires")
                        .map(|(_, v)| v.as_str()),
                    now_epoch(),
                )
                .filter(|&e| e != 0)
            });
        let obj = req
            .headers
            .get("X-Backend-Tempurl-Object")
            .unwrap_or("")
            .to_string();

        let mut inline_disposition = inline;
        let content_generator = resp
            .headers
            .get("X-Backend-Content-Generator")
            .map(|s| s.to_string());
        let existing_disposition = resp
            .headers
            .get("Content-Disposition")
            .map(|s| s.to_string());

        if content_generator.as_deref() == Some("staticweb") {
            inline_disposition = true;
        } else if obj.is_empty() {
            // The container-root carve-out only stands for a staticweb
            // response; otherwise a rootless tempurl is invalid.
            return self.invalid(&req.method);
        }

        let filename_ref = filename.as_deref();
        let disposition_value = if inline_disposition {
            match filename_ref {
                Some(f) => disposition_format("inline", f),
                None => "inline".to_string(),
            }
        } else if let Some(f) = filename_ref {
            disposition_format("attachment", f)
        } else if let Some(existing) = existing_disposition {
            existing
        } else {
            let name = basename(req.path.trim_end_matches('/'));
            disposition_format("attachment", &name)
        };
        let value = disposition_value.replace('\n', "%0A");
        resp.headers.set("Content-Disposition", value);
        if let Some(expires) = expires {
            resp.headers.set("Expires", http_date(expires));
        }
        resp
    }
}

/// The original (undecoded-int) `temp_url_expires` string, preserved verbatim
/// in the rewritten query as Python does with `client_temp_url_expires`.
fn raw_expires_string(params: &[(String, String)]) -> String {
    params
        .iter()
        .find(|(k, _)| k == "temp_url_expires")
        .map(|(_, v)| v.clone())
        .unwrap_or_default()
}

/// Seconds since the Unix epoch, or 0 if the clock is before 1970.
fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Port of `normalize_temp_url_expires`. `None` in => `None` out; otherwise an
/// int (or 0 if unparseable), coerced to 0 when already expired.
fn normalize_temp_url_expires(value: Option<&str>, now: i64) -> Option<i64> {
    let value = value?;
    let mut expires = match value.trim().parse::<i64>() {
        Ok(n) => n,
        Err(_) => iso8601_to_epoch(value).unwrap_or(0),
    };
    if expires < now {
        expires = 0;
    }
    Some(expires)
}

/// Parse an `EXPIRES_ISO8601_FORMAT` (`"%Y-%m-%dT%H:%M:%SZ"`) UTC timestamp to
/// epoch seconds, `None` on any deviation (matching `strptime` + `timegm`).
fn iso8601_to_epoch(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() != 20 || !s.is_ascii() {
        return None;
    }
    if b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'Z'
    {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let part = &s[r];
        if part.bytes().all(|c| c.is_ascii_digit()) {
            part.parse::<i64>().ok()
        } else {
            None
        }
    };
    let year = num(0..4)?;
    let month = num(5..7)?;
    let day = num(8..10)?;
    let hour = num(11..13)?;
    let minute = num(14..16)?;
    let second = num(17..19)?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    if hour > 23 || minute > 59 || second > 61 {
        return None;
    }
    Some(
        days_from_civil(year, month as u32, day as u32) * 86400
            + hour * 3600
            + minute * 60
            + second,
    )
}

/// Days since 1970-01-01 for a proleptic-Gregorian date (Howard Hinnant's
/// algorithm; the same one `swift-http::dates` uses internally).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 } as i64;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// Port of `extract_digest_and_algorithm`. Returns `(algorithm, lowercase-hex
/// digest)`. The hex form leaves the digest string untouched (so an
/// upper-case hex signature will fail the later comparison exactly as it does
/// in Python); the base64 form is decoded and re-hex-encoded.
pub(crate) fn extract_digest_and_algorithm(value: &str) -> Result<(String, String), ()> {
    if let Some(idx) = value.find(':') {
        let algo = value[..idx].to_string();
        let mut body = value[idx + 1..].to_string();
        let has_urlsafe = body.contains('-') || body.contains('_');
        let has_standard = body.contains('+') || body.contains('/');
        if has_urlsafe && !has_standard {
            body = body.replace('-', "+").replace('_', "/");
        }
        let decoded = strict_b64decode(&format!("{body}=="))?;
        Ok((algo, hex_encode(&decoded)))
    } else {
        if !is_valid_hex(value) {
            return Err(());
        }
        let algo = match value.len() {
            40 => "sha1",
            64 => "sha256",
            128 => "sha512",
            _ => return Err(()),
        };
        Ok((algo.to_string(), value.to_string()))
    }
}

/// Even-length string of hex digits, matching what `binascii.unhexlify`
/// accepts.
fn is_valid_hex(value: &str) -> bool {
    !value.is_empty()
        && value.len().is_multiple_of(2)
        && value.bytes().all(|c| c.is_ascii_hexdigit())
}

/// Lowercase hex encoding of `bytes`.
fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Port of `swift.common.utils.strict_b64decode` (default arguments):
/// validate that every non-padding character is in the standard base64
/// alphabet, then decode. Extra trailing `=` padding (as produced by
/// appending `"=="`) is tolerated.
fn strict_b64decode(value: &str) -> Result<Vec<u8>, ()> {
    // `value.strip('=')` then reject any non-alphabet character. A `=` in the
    // interior survives the strip and thus fails here, as in Python.
    let stripped = value.trim_matches('=');
    for c in stripped.bytes() {
        if b64_value(c).is_none() {
            return Err(());
        }
    }
    let chars: Vec<u8> = value.bytes().filter(|&c| c != b'=').collect();
    let mut out = Vec::with_capacity(chars.len() / 4 * 3 + 2);
    for chunk in chars.chunks(4) {
        // A lone trailing character cannot encode any byte.
        if chunk.len() == 1 {
            return Err(());
        }
        let mut buf = [0u8; 4];
        for (i, &c) in chunk.iter().enumerate() {
            buf[i] = b64_value(c).ok_or(())?;
        }
        out.push((buf[0] << 2) | (buf[1] >> 4));
        if chunk.len() >= 3 {
            out.push((buf[1] << 4) | (buf[2] >> 2));
        }
        if chunk.len() == 4 {
            out.push((buf[2] << 6) | buf[3]);
        }
    }
    Ok(out)
}

fn b64_value(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Client IP for TempURL range checks (Python `REMOTE_ADDR`).
fn client_remote_addr(req: &Request) -> Option<String> {
    if let Some(v) = req.headers.get("X-Backend-Remote-Addr") {
        let t = v.trim();
        if !t.is_empty() {
            return Some(t.to_string());
        }
    }
    if let Some(v) = req.headers.get("X-Forwarded-For") {
        // First hop is the original client.
        if let Some(first) = v.split(',').next() {
            let t = first.trim();
            if !t.is_empty() {
                return Some(t.to_string());
            }
        }
    }
    if let Some(v) = req.headers.get("X-Real-IP") {
        let t = v.trim();
        if !t.is_empty() {
            return Some(t.to_string());
        }
    }
    None
}

/// IPv4 address/CIDR membership (Python `ipaddress.ip_network`).
fn ip_in_range(client: &str, range: &str) -> bool {
    let client = client.trim();
    let range = range.trim();
    if range.is_empty() {
        return false;
    }
    // Exact host match (also covers single-IP "network").
    if !range.contains('/') {
        return client == range;
    }
    let Some((net_s, pref_s)) = range.split_once('/') else {
        return false;
    };
    let Ok(prefix) = pref_s.parse::<u32>() else {
        return false;
    };
    if prefix > 32 {
        return false;
    }
    let Some(client_u) = parse_ipv4(client) else {
        return false;
    };
    let Some(net_u) = parse_ipv4(net_s.trim()) else {
        return false;
    };
    if prefix == 0 {
        return true;
    }
    let mask = u32::MAX << (32 - prefix);
    (client_u & mask) == (net_u & mask)
}

fn parse_ipv4(s: &str) -> Option<u32> {
    let mut parts = [0u32; 4];
    let mut i = 0;
    for p in s.split('.') {
        if i >= 4 {
            return None;
        }
        let n: u32 = p.parse().ok()?;
        if n > 255 {
            return None;
        }
        parts[i] = n;
        i += 1;
    }
    if i != 4 {
        return None;
    }
    Some((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3])
}

/// HMAC-`algo` of `msg` under `key`, hex-encoded; `None` for an unsupported
/// algorithm name.
pub(crate) fn hmac_hex(algo: &str, key: &[u8], msg: &[u8]) -> Option<String> {
    let digest = match algo {
        "sha1" => hmac::<Sha1>(64, key, msg),
        "sha256" => hmac::<Sha256>(64, key, msg),
        "sha512" => hmac::<Sha512>(128, key, msg),
        _ => return None,
    };
    Some(hex_encode(&digest))
}

/// RFC 2104 HMAC over any RustCrypto `Digest`, given its block size.
fn hmac<D: Digest>(block_size: usize, key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut key = key.to_vec();
    if key.len() > block_size {
        let mut hasher = D::new();
        hasher.update(&key);
        key = hasher.finalize().to_vec();
    }
    if key.len() < block_size {
        key.resize(block_size, 0);
    }
    let ipad: Vec<u8> = key.iter().map(|b| b ^ 0x36).collect();
    let opad: Vec<u8> = key.iter().map(|b| b ^ 0x5c).collect();

    let mut inner = D::new();
    inner.update(&ipad);
    inner.update(msg);
    let inner_digest = inner.finalize().to_vec();

    let mut outer = D::new();
    outer.update(&opad);
    outer.update(&inner_digest);
    outer.finalize().to_vec()
}

/// Constant-time string comparison, port of `streq_const_time`.
fn streq_const_time(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        result |= x ^ y;
    }
    result == 0
}

/// `urllib.parse.urlencode` over ordered pairs (each key and value
/// `quote_plus`-encoded).
fn urlencode(pairs: &[(String, String)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", quote_plus(k), quote_plus(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// `urllib.parse.quote_plus`: unreserved characters pass through, space
/// becomes `+`, everything else is `%XX` over the UTF-8 bytes.
fn quote_plus(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        if b == b' ' {
            out.push('+');
        } else if is_unreserved(b, b"") {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// `swift.common.utils.quote` == `urllib.parse.quote(value, safe)`:
/// unreserved-or-safe characters pass through, everything else `%XX`.
fn quote(s: &str, safe: &[u8]) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        if is_unreserved(b, safe) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// `urllib`'s always-safe set (`A-Za-z0-9_.-~`) plus any extra `safe` bytes.
fn is_unreserved(b: u8, safe: &[u8]) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-' | b'~') || safe.contains(&b)
}

/// Port of `disposition_format`: an RFC 6266 `Content-Disposition` value with
/// both a plain `filename=` and an RFC 5987 `filename*=UTF-8''` form.
fn disposition_format(disposition_type: &str, filename: &str) -> String {
    format!(
        "{}; filename=\"{}\"; filename*=UTF-8''{}",
        disposition_type,
        quote(filename, b" /"),
        quote(filename, b"")
    )
}

/// `os.path.basename`: the final path component (empty if the path ends in a
/// separator).
fn basename(path: &str) -> String {
    match path.rsplit_once('/') {
        Some((_, last)) => last.to_string(),
        None => path.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Golden vectors were computed with the real Python `get_hmac`
    // (KEY="mykey", EXPIRES=4102444800 => 2100-01-01, so unexpired for
    // decades) over PATH="/v1/AUTH_account/container/object".
    const KEY: &str = "mykey";
    const KEY2: &str = "otherkey";
    const EXPIRES: &str = "4102444800";
    const ACCT: &str = "AUTH_account";
    const CONT: &str = "container";

    const SIG_GET_SHA1: &str = "dcc8453074ac52d0d2c3edba7d543b96f194e8d7";
    const SIG_GET_SHA256: &str = "beb29507e95de0350c1076f7671d128cc02120c3186c0ba7c70d4d3a1bba6bfe";
    const SIG_GET_SHA512: &str = "1cdf6d963eab46dd1634a3bd02ea5f4092fb79491425a6a030c44fd1da14e76002afe0e46cb6f639aaa8a4b1f49f2f70b8207972e26525de15a5f6516e1c854f";
    const SIG_GET_SHA512_B64: &str =
        "sha512:HN9tlj6rRt0WNKO9AupfQJL7eUkUJaagMMRP0doU52ACr-DkbLb2OaqopLH0ny9wuCB5cuJlJd4VpfZRbhyFTw==";
    const SIG_GET_SHA256_B64: &str = "sha256:vrKVB-ld4DUMEHb3Zx0SjMAhIMMYbAunxw1NOhu6a_4=";
    const SIG_PUT_SHA256: &str = "075253051197618a0ba40c0cb27954ab7774acea82b34cb7ffb6198c64f7e6cb";
    const SIG_POST_SHA256: &str =
        "47ba39ae5b07dde742ab515bb632b910eaa9a0b1343acde4face2efda13982a9";
    const SIG_PREFIX_SHA256: &str =
        "baa50ebfd744600c5c957654a289920477824a392a8977c74fd8dfa75dfced2b";
    const SIG_GET_SHA256_KEY2: &str =
        "e0e563761d385fd5fb26cc47c932343e2cccb28da6597a7872fdc43fd1de590e";

    struct StaticKeys(Vec<String>);
    impl KeyProvider for StaticKeys {
        fn keys_for(&self, _account: &str, _container: &str) -> Vec<String> {
            self.0.clone()
        }
    }

    struct NoKeys;
    impl KeyProvider for NoKeys {
        fn keys_for(&self, _account: &str, _container: &str) -> Vec<String> {
            Vec::new()
        }
    }

    fn tempurl(keys: &[&str]) -> TempUrl {
        TempUrl::new(Arc::new(StaticKeys(
            keys.iter().map(|k| k.to_string()).collect(),
        )))
    }

    fn mk(method: &str, path: &str, query: &str, headers: &[(&str, &str)]) -> Request {
        let mut h = HeaderKeyDict::new();
        for (k, v) in headers {
            h.set(k, v);
        }
        Request {
            method: method.into(),
            path: path.into(),
            query_string: query.into(),
            headers: h,
            body: swift_http::Body::empty(),
        }
    }

    // Innermost app: reflects the (rewritten) query and surviving request
    // headers into the response so tests can inspect what reached the app,
    // plus a couple of headers to prove the outbound scrub. Extra response
    // headers requested by the test are added on top.
    fn echo_app(extra: Vec<(&'static str, &'static str)>) -> crate::NextFn {
        std::sync::Arc::new(move |req: Request| {
            let mut resp = Response::with_body(200, b"BODY".to_vec());
            resp.headers.set("Echo-Query", &req.query_string);
            for (k, v) in req.headers.iter() {
                resp.headers.set(&format!("Echo-{k}"), v);
            }
            resp.headers.set("X-Object-Meta-Secret", "leak");
            resp.headers.set("X-Object-Meta-Public-Ok", "kept");
            for (k, v) in &extra {
                resp.headers.set(k, *v);
            }
            resp
        })
    }

    /// The returned body is materialized so assertions can read it in place.
    fn run(tu: &TempUrl, req: Request) -> Response {
        let mut resp = tu.handle(req, &echo_app(Vec::new()));
        resp.body.materialize(u64::MAX).unwrap();
        resp
    }

    fn run_with(tu: &TempUrl, req: Request, extra: Vec<(&'static str, &'static str)>) -> Response {
        let mut resp = tu.handle(req, &echo_app(extra));
        resp.body.materialize(u64::MAX).unwrap();
        resp
    }

    /// Test bodies are always buffered once `run` has materialized them.
    fn body_bytes(resp: &Response) -> &[u8] {
        match &resp.body {
            swift_http::Body::Buffered(b) => b,
            swift_http::Body::Streamed(_) | swift_http::Body::Channel(_) => unreachable!(),
        }
    }

    fn query(sig: &str) -> String {
        format!("temp_url_sig={sig}&temp_url_expires={EXPIRES}")
    }

    // ---- happy paths ----

    #[test]
    fn test_valid_get_sha256() {
        let tu = tempurl(&[KEY]);
        let resp = run(
            &tu,
            mk(
                "GET",
                "/v1/AUTH_account/container/object",
                &query(SIG_GET_SHA256),
                &[],
            ),
        );
        assert_eq!(resp.status, 200);
        assert_eq!(body_bytes(&resp), b"BODY");
        // Query was rewritten to the extracted sig + original expires only.
        assert_eq!(
            resp.headers.get("Echo-Query"),
            Some(format!("temp_url_sig={SIG_GET_SHA256}&temp_url_expires={EXPIRES}").as_str())
        );
        assert_eq!(
            resp.headers.get("Echo-X-Backend-Authorize-Override"),
            Some("true")
        );
        assert_eq!(
            resp.headers.get("Echo-X-Backend-Remote-User"),
            Some(".wsgi.tempurl")
        );
        // GET success gets a Content-Disposition (default attachment named
        // after the object) and an Expires header.
        assert_eq!(
            resp.headers.get("Content-Disposition"),
            Some("attachment; filename=\"object\"; filename*=UTF-8''object")
        );
        assert_eq!(
            resp.headers.get("Expires"),
            Some(http_date(4102444800).as_str())
        );
    }

    #[test]
    fn test_valid_get_sha1() {
        let tu = tempurl(&[KEY]);
        let resp = run(
            &tu,
            mk(
                "GET",
                "/v1/AUTH_account/container/object",
                &query(SIG_GET_SHA1),
                &[],
            ),
        );
        assert_eq!(resp.status, 200);
    }

    #[test]
    fn test_valid_get_sha512_hex() {
        let tu = tempurl(&[KEY]);
        let resp = run(
            &tu,
            mk(
                "GET",
                "/v1/AUTH_account/container/object",
                &query(SIG_GET_SHA512),
                &[],
            ),
        );
        assert_eq!(resp.status, 200);
    }

    #[test]
    fn test_valid_get_sha512_base64() {
        let tu = tempurl(&[KEY]);
        let resp = run(
            &tu,
            mk(
                "GET",
                "/v1/AUTH_account/container/object",
                &query(SIG_GET_SHA512_B64),
                &[],
            ),
        );
        assert_eq!(resp.status, 200);
        // The rewritten query carries the re-hex-encoded signature, matching
        // the hex sha512 golden vector.
        assert_eq!(
            resp.headers.get("Echo-Query"),
            Some(format!("temp_url_sig={SIG_GET_SHA512}&temp_url_expires={EXPIRES}").as_str())
        );
    }

    #[test]
    fn test_valid_get_sha256_base64_urlsafe() {
        let tu = tempurl(&[KEY]);
        let resp = run(
            &tu,
            mk(
                "GET",
                "/v1/AUTH_account/container/object",
                &query(SIG_GET_SHA256_B64),
                &[],
            ),
        );
        assert_eq!(resp.status, 200);
        assert_eq!(
            resp.headers.get("Echo-Query"),
            Some(format!("temp_url_sig={SIG_GET_SHA256}&temp_url_expires={EXPIRES}").as_str())
        );
    }

    #[test]
    fn test_valid_put() {
        let tu = tempurl(&[KEY]);
        let resp = run(
            &tu,
            mk(
                "PUT",
                "/v1/AUTH_account/container/object",
                &query(SIG_PUT_SHA256),
                &[],
            ),
        );
        assert_eq!(resp.status, 200);
        // PUT (not GET/HEAD) gets no Content-Disposition.
        assert!(resp.headers.get("Content-Disposition").is_none());
        assert!(resp.headers.get("Expires").is_none());
    }

    #[test]
    fn test_head_matches_get_signature() {
        // A HEAD is valid against a signature minted for GET.
        let tu = tempurl(&[KEY]);
        let resp = run(
            &tu,
            mk(
                "HEAD",
                "/v1/AUTH_account/container/object",
                &query(SIG_GET_SHA256),
                &[],
            ),
        );
        assert_eq!(resp.status, 200);
    }

    #[test]
    fn test_head_matches_post_signature() {
        let tu = tempurl(&[KEY]);
        let resp = run(
            &tu,
            mk(
                "HEAD",
                "/v1/AUTH_account/container/object",
                &query(SIG_POST_SHA256),
                &[],
            ),
        );
        assert_eq!(resp.status, 200);
    }

    #[test]
    fn test_get_does_not_match_put_signature() {
        // The reverse of HEAD's leniency: a GET is NOT valid against a PUT
        // signature.
        let tu = tempurl(&[KEY]);
        let resp = run(
            &tu,
            mk(
                "GET",
                "/v1/AUTH_account/container/object",
                &query(SIG_PUT_SHA256),
                &[],
            ),
        );
        assert_eq!(resp.status, 401);
    }

    #[test]
    fn test_second_key_matches() {
        // Signature made with the account's second key still validates.
        let tu = tempurl(&[KEY, KEY2]);
        let resp = run(
            &tu,
            mk(
                "GET",
                "/v1/AUTH_account/container/object",
                &query(SIG_GET_SHA256_KEY2),
                &[],
            ),
        );
        assert_eq!(resp.status, 200);
    }

    #[test]
    fn test_valid_prefix() {
        // Prefix signature valid for any object under the prefix.
        let tu = tempurl(&[KEY]);
        let q = format!(
            "temp_url_sig={SIG_PREFIX_SHA256}&temp_url_expires={EXPIRES}&temp_url_prefix=pre"
        );
        let resp = run(
            &tu,
            mk("GET", "/v1/AUTH_account/container/pre/sub/obj", &q, &[]),
        );
        assert_eq!(resp.status, 200);
        // The prefix parameter is preserved in the rewritten query.
        assert_eq!(
            resp.headers.get("Echo-Query"),
            Some(
                format!(
                    "temp_url_sig={SIG_PREFIX_SHA256}&temp_url_expires={EXPIRES}&temp_url_prefix=pre"
                )
                .as_str()
            )
        );
    }

    #[test]
    fn test_prefix_object_not_under_prefix() {
        // Object does not start with the prefix => 401.
        let tu = tempurl(&[KEY]);
        let q = format!(
            "temp_url_sig={SIG_PREFIX_SHA256}&temp_url_expires={EXPIRES}&temp_url_prefix=pre"
        );
        let resp = run(&tu, mk("GET", "/v1/AUTH_account/container/other", &q, &[]));
        assert_eq!(resp.status, 401);
    }

    // ---- pass-through (not a tempurl request) ----

    #[test]
    fn test_options_passthrough() {
        let tu = tempurl(&[KEY]);
        let resp = run(
            &tu,
            mk("OPTIONS", "/v1/AUTH_account/container/object", "", &[]),
        );
        assert_eq!(resp.status, 200);
        // No query rewrite happened.
        assert_eq!(resp.headers.get("Echo-Query"), Some(""));
    }

    #[test]
    fn test_no_tempurl_params_passthrough() {
        let tu = tempurl(&[KEY]);
        let resp = run(
            &tu,
            mk(
                "GET",
                "/v1/AUTH_account/container/object",
                "format=json",
                &[],
            ),
        );
        assert_eq!(resp.status, 200);
        // Untouched query reaches the app.
        assert_eq!(resp.headers.get("Echo-Query"), Some("format=json"));
    }

    // ---- rejections / edge cases ----

    #[test]
    fn test_missing_signature_is_invalid() {
        // expires present but no sig => 401 (not a pass-through).
        let tu = tempurl(&[KEY]);
        let resp = run(
            &tu,
            mk(
                "GET",
                "/v1/AUTH_account/container/object",
                &format!("temp_url_expires={EXPIRES}"),
                &[],
            ),
        );
        assert_eq!(resp.status, 401);
        assert_eq!(
            String::from_utf8_lossy(body_bytes(&resp)),
            "401 Unauthorized: Temp URL invalid\n"
        );
    }

    #[test]
    fn test_empty_signature_is_invalid() {
        let tu = tempurl(&[KEY]);
        let resp = run(
            &tu,
            mk(
                "GET",
                "/v1/AUTH_account/container/object",
                &format!("temp_url_sig=&temp_url_expires={EXPIRES}"),
                &[],
            ),
        );
        assert_eq!(resp.status, 401);
    }

    #[test]
    fn test_missing_expires_is_invalid() {
        let tu = tempurl(&[KEY]);
        let resp = run(
            &tu,
            mk(
                "GET",
                "/v1/AUTH_account/container/object",
                &format!("temp_url_sig={SIG_GET_SHA256}"),
                &[],
            ),
        );
        assert_eq!(resp.status, 401);
    }

    #[test]
    fn test_expired_is_invalid() {
        // A past timestamp normalizes to 0 (falsy) => 401.
        let tu = tempurl(&[KEY]);
        let resp = run(
            &tu,
            mk(
                "GET",
                "/v1/AUTH_account/container/object",
                &format!("temp_url_sig={SIG_GET_SHA256}&temp_url_expires=1"),
                &[],
            ),
        );
        assert_eq!(resp.status, 401);
    }

    #[test]
    fn test_head_invalid_has_empty_body() {
        // A rejected HEAD returns an empty body, unlike other methods.
        let tu = tempurl(&[KEY]);
        let resp = run(
            &tu,
            mk(
                "HEAD",
                "/v1/AUTH_account/container/object",
                &format!("temp_url_sig=deadbeef&temp_url_expires={EXPIRES}"),
                &[],
            ),
        );
        assert_eq!(resp.status, 401);
        assert!(body_bytes(&resp).is_empty());
    }

    #[test]
    fn test_tampered_signature_is_invalid() {
        // Flip the last hex digit.
        let tu = tempurl(&[KEY]);
        let mut sig = SIG_GET_SHA256.to_string();
        sig.pop();
        sig.push('0');
        let bad = if sig == SIG_GET_SHA256 {
            format!("{}1", &SIG_GET_SHA256[..SIG_GET_SHA256.len() - 1])
        } else {
            sig
        };
        let resp = run(
            &tu,
            mk(
                "GET",
                "/v1/AUTH_account/container/object",
                &query(&bad),
                &[],
            ),
        );
        assert_eq!(resp.status, 401);
    }

    #[test]
    fn test_uppercase_hex_signature_is_invalid() {
        // The hex form is compared verbatim; upper-case never matches the
        // lower-case hexdigest (faithful to Python).
        let tu = tempurl(&[KEY]);
        let resp = run(
            &tu,
            mk(
                "GET",
                "/v1/AUTH_account/container/object",
                &query(&SIG_GET_SHA256.to_uppercase()),
                &[],
            ),
        );
        assert_eq!(resp.status, 401);
    }

    #[test]
    fn test_bad_hex_length_is_invalid() {
        // Valid hex but not a recognized digest length => 401.
        let tu = tempurl(&[KEY]);
        let resp = run(
            &tu,
            mk(
                "GET",
                "/v1/AUTH_account/container/object",
                &query("abcdef"),
                &[],
            ),
        );
        assert_eq!(resp.status, 401);
    }

    #[test]
    fn test_disallowed_digest_is_invalid() {
        // sha1 is a valid length/algorithm, but if it is not in
        // allowed_digests it is rejected.
        let mut tu = tempurl(&[KEY]);
        tu.allowed_digests = vec!["sha256".to_string(), "sha512".to_string()];
        let resp = run(
            &tu,
            mk(
                "GET",
                "/v1/AUTH_account/container/object",
                &query(SIG_GET_SHA1),
                &[],
            ),
        );
        assert_eq!(resp.status, 401);
    }

    #[test]
    fn test_no_keys_is_invalid() {
        let tu = TempUrl::new(Arc::new(NoKeys));
        let resp = run(
            &tu,
            mk(
                "GET",
                "/v1/AUTH_account/container/object",
                &query(SIG_GET_SHA256),
                &[],
            ),
        );
        assert_eq!(resp.status, 401);
    }

    #[test]
    fn test_method_not_in_allowed_methods() {
        // DELETE excluded from methods => path-parts returns nothing => 401,
        // even though the DELETE signature would otherwise be right.
        let mut tu = tempurl(&[KEY]);
        tu.methods = vec!["GET".to_string(), "HEAD".to_string()];
        let resp = run(
            &tu,
            mk(
                "DELETE",
                "/v1/AUTH_account/container/object",
                &format!(
                    "temp_url_sig=16edc82a9c89f71f721f360f2bd6917f3d9bfcb1dcd8dc804e8020fba8b37ef8&temp_url_expires={EXPIRES}"
                ),
                &[],
            ),
        );
        assert_eq!(resp.status, 401);
    }

    #[test]
    fn test_container_request_is_invalid() {
        // No object and no container-root carve-out (no prefix="") => 401.
        let tu = tempurl(&[KEY]);
        let resp = run(
            &tu,
            mk(
                "GET",
                "/v1/AUTH_account/container",
                &query(SIG_GET_SHA256),
                &[],
            ),
        );
        assert_eq!(resp.status, 401);
    }

    #[test]
    fn test_altered_path_is_invalid() {
        // Same signature, different object path => 401.
        let tu = tempurl(&[KEY]);
        let resp = run(
            &tu,
            mk(
                "GET",
                "/v1/AUTH_account/container/other-object",
                &query(SIG_GET_SHA256),
                &[],
            ),
        );
        assert_eq!(resp.status, 401);
    }

    // ---- header scrubbing ----

    #[test]
    fn test_incoming_headers_scrubbed() {
        // X-Timestamp is removed by default; other headers survive.
        let tu = tempurl(&[KEY]);
        let resp = run(
            &tu,
            mk(
                "GET",
                "/v1/AUTH_account/container/object",
                &query(SIG_GET_SHA256),
                &[("X-Timestamp", "12345"), ("X-Object-Meta-Keep", "yes")],
            ),
        );
        assert_eq!(resp.status, 200);
        assert!(resp.headers.get("Echo-X-Timestamp").is_none());
        assert_eq!(resp.headers.get("Echo-X-Object-Meta-Keep"), Some("yes"));
    }

    #[test]
    fn test_outgoing_headers_scrubbed() {
        // x-object-meta-* removed, x-object-meta-public-* kept.
        let tu = tempurl(&[KEY]);
        let resp = run(
            &tu,
            mk(
                "GET",
                "/v1/AUTH_account/container/object",
                &query(SIG_GET_SHA256),
                &[],
            ),
        );
        assert_eq!(resp.status, 200);
        assert!(resp.headers.get("X-Object-Meta-Secret").is_none());
        assert_eq!(resp.headers.get("X-Object-Meta-Public-Ok"), Some("kept"));
    }

    #[test]
    fn test_disallowed_header_on_put_is_bad_request() {
        // A PUT tempurl carrying X-Object-Manifest is a 400.
        let tu = tempurl(&[KEY]);
        let resp = run(
            &tu,
            mk(
                "PUT",
                "/v1/AUTH_account/container/object",
                &query(SIG_PUT_SHA256),
                &[("X-Object-Manifest", "c/o")],
            ),
        );
        assert_eq!(resp.status, 400);
        assert_eq!(
            String::from_utf8_lossy(body_bytes(&resp)),
            "The header 'X-Object-Manifest' is not allowed in this tempurl"
        );
    }

    #[test]
    fn test_disallowed_header_on_get_is_allowed() {
        // The same header on a GET is fine (safe method).
        let tu = tempurl(&[KEY]);
        let resp = run(
            &tu,
            mk(
                "GET",
                "/v1/AUTH_account/container/object",
                &query(SIG_GET_SHA256),
                &[("X-Symlink-Target", "c/o")],
            ),
        );
        assert_eq!(resp.status, 200);
    }

    // ---- content-disposition variants ----

    #[test]
    fn test_filename_override_attachment() {
        let tu = tempurl(&[KEY]);
        let q = format!(
            "temp_url_sig={SIG_GET_SHA256}&temp_url_expires={EXPIRES}&filename=My+Test+File.pdf"
        );
        let resp = run(&tu, mk("GET", "/v1/AUTH_account/container/object", &q, &[]));
        assert_eq!(resp.status, 200);
        assert_eq!(
            resp.headers.get("Content-Disposition"),
            Some(
                "attachment; filename=\"My Test File.pdf\"; filename*=UTF-8''My%20Test%20File.pdf"
            )
        );
        // filename is preserved (quote_plus) in the rewritten query.
        assert_eq!(
            resp.headers.get("Echo-Query"),
            Some(
                format!(
                    "temp_url_sig={SIG_GET_SHA256}&temp_url_expires={EXPIRES}&filename=My+Test+File.pdf"
                )
                .as_str()
            )
        );
    }

    #[test]
    fn test_inline_disposition() {
        let tu = tempurl(&[KEY]);
        let q = format!("temp_url_sig={SIG_GET_SHA256}&temp_url_expires={EXPIRES}&inline");
        let resp = run(&tu, mk("GET", "/v1/AUTH_account/container/object", &q, &[]));
        assert_eq!(resp.status, 200);
        assert_eq!(resp.headers.get("Content-Disposition"), Some("inline"));
        assert_eq!(
            resp.headers.get("Echo-Query"),
            Some(
                format!("temp_url_sig={SIG_GET_SHA256}&temp_url_expires={EXPIRES}&inline=")
                    .as_str()
            )
        );
    }

    #[test]
    fn test_inline_with_filename() {
        let tu = tempurl(&[KEY]);
        let q = format!(
            "temp_url_sig={SIG_GET_SHA256}&temp_url_expires={EXPIRES}&inline&filename=doc.pdf"
        );
        let resp = run(&tu, mk("GET", "/v1/AUTH_account/container/object", &q, &[]));
        assert_eq!(resp.status, 200);
        assert_eq!(
            resp.headers.get("Content-Disposition"),
            Some("inline; filename=\"doc.pdf\"; filename*=UTF-8''doc.pdf")
        );
    }

    #[test]
    fn test_existing_disposition_preserved() {
        // With neither inline nor filename, an existing Content-Disposition
        // from the app is kept.
        let tu = tempurl(&[KEY]);
        let resp = run_with(
            &tu,
            mk(
                "GET",
                "/v1/AUTH_account/container/object",
                &query(SIG_GET_SHA256),
                &[],
            ),
            vec![("Content-Disposition", "attachment; filename=\"from-meta\"")],
        );
        assert_eq!(resp.status, 200);
        assert_eq!(
            resp.headers.get("Content-Disposition"),
            Some("attachment; filename=\"from-meta\"")
        );
    }

    // ---- container-root carve-out (staticweb) ----

    #[test]
    fn test_container_root_requires_staticweb() {
        // GET at the container root with prefix="" is allowed past the
        // signature check, but without a staticweb response it is a 401.
        let tu = tempurl(&[KEY]);
        // sha256 sig over "prefix:/v1/AUTH_account/container/" is required.
        let sig = hmac_hex(
            "sha256",
            KEY.as_bytes(),
            format!("GET\n{EXPIRES}\nprefix:/v1/{ACCT}/{CONT}/").as_bytes(),
        )
        .unwrap();
        let q = format!("temp_url_sig={sig}&temp_url_expires={EXPIRES}&temp_url_prefix=");
        let resp = run(&tu, mk("GET", "/v1/AUTH_account/container", &q, &[]));
        assert_eq!(resp.status, 401);
    }

    #[test]
    fn test_container_root_with_staticweb() {
        // The same request, but the app declares a staticweb response, is
        // allowed and gets an inline disposition.
        let tu = tempurl(&[KEY]);
        let sig = hmac_hex(
            "sha256",
            KEY.as_bytes(),
            format!("GET\n{EXPIRES}\nprefix:/v1/{ACCT}/{CONT}/").as_bytes(),
        )
        .unwrap();
        let q = format!("temp_url_sig={sig}&temp_url_expires={EXPIRES}&temp_url_prefix=");
        let resp = run_with(
            &tu,
            mk("GET", "/v1/AUTH_account/container", &q, &[]),
            vec![("X-Backend-Content-Generator", "staticweb")],
        );
        assert_eq!(resp.status, 200);
        assert_eq!(resp.headers.get("Content-Disposition"), Some("inline"));
    }

    // ---- ISO 8601 expires ----

    #[test]
    fn test_iso8601_expires_accepted() {
        // The signature is over the *numeric* expires; the URL may carry the
        // equivalent ISO8601 string. 1512508563 == 2017-12-05T21:16:03Z, but
        // that is in the past, so pick a far-future instant instead.
        let future_epoch: i64 = 4102444800; // 2100-01-01T00:00:00Z
        let iso = "2100-01-01T00:00:00Z";
        assert_eq!(iso8601_to_epoch(iso), Some(future_epoch));
        let tu = tempurl(&[KEY]);
        // sig is computed over the numeric form, exactly as SIG_GET_SHA256.
        let q = format!("temp_url_sig={SIG_GET_SHA256}&temp_url_expires={iso}");
        let resp = run(&tu, mk("GET", "/v1/AUTH_account/container/object", &q, &[]));
        assert_eq!(resp.status, 200);
        // The original ISO string is preserved (quote_plus-encoded) in the
        // rewritten query.
        assert_eq!(
            resp.headers.get("Echo-Query"),
            Some(
                format!("temp_url_sig={SIG_GET_SHA256}&temp_url_expires=2100-01-01T00%3A00%3A00Z")
                    .as_str()
            )
        );
    }

    // ---- pure-helper unit tests ----

    #[test]
    fn test_iso8601_docstring_value() {
        assert_eq!(iso8601_to_epoch("2017-12-05T21:16:03Z"), Some(1512508563));
        assert_eq!(iso8601_to_epoch("2017-12-05 21:16:03Z"), None); // wrong sep
        assert_eq!(iso8601_to_epoch("2017-13-05T21:16:03Z"), None); // bad month
        assert_eq!(iso8601_to_epoch("not-a-date"), None);
    }

    #[test]
    fn test_normalize_expires() {
        // None in => None out.
        assert_eq!(normalize_temp_url_expires(None, 1000), None);
        // Future int passes through.
        assert_eq!(normalize_temp_url_expires(Some("5000"), 1000), Some(5000));
        // Past int coerces to 0.
        assert_eq!(normalize_temp_url_expires(Some("500"), 1000), Some(0));
        // Garbage coerces to 0.
        assert_eq!(normalize_temp_url_expires(Some("xyz"), 1000), Some(0));
        // ISO string in the future.
        assert_eq!(
            normalize_temp_url_expires(Some("2100-01-01T00:00:00Z"), 1000),
            Some(4102444800)
        );
    }

    #[test]
    fn test_extract_digest_and_algorithm() {
        assert_eq!(
            extract_digest_and_algorithm(SIG_GET_SHA1).unwrap(),
            ("sha1".to_string(), SIG_GET_SHA1.to_string())
        );
        assert_eq!(
            extract_digest_and_algorithm(SIG_GET_SHA256).unwrap(),
            ("sha256".to_string(), SIG_GET_SHA256.to_string())
        );
        // url-safe base64 sha512 decodes to the hex sha512 golden vector.
        assert_eq!(
            extract_digest_and_algorithm(SIG_GET_SHA512_B64).unwrap(),
            ("sha512".to_string(), SIG_GET_SHA512.to_string())
        );
        assert_eq!(
            extract_digest_and_algorithm(SIG_GET_SHA256_B64).unwrap(),
            ("sha256".to_string(), SIG_GET_SHA256.to_string())
        );
        // Odd-length / bad-length hex.
        assert!(extract_digest_and_algorithm("abc").is_err());
        assert!(extract_digest_and_algorithm("abcd").is_err());
        // Non-hex characters.
        assert!(extract_digest_and_algorithm(&"z".repeat(64)).is_err());
    }

    #[test]
    fn test_hmac_vectors() {
        assert_eq!(
            hmac_hex(
                "sha1",
                KEY.as_bytes(),
                format!("GET\n{EXPIRES}\n/v1/{ACCT}/{CONT}/object").as_bytes()
            )
            .unwrap(),
            SIG_GET_SHA1
        );
        assert_eq!(
            hmac_hex(
                "sha256",
                KEY.as_bytes(),
                format!("GET\n{EXPIRES}\n/v1/{ACCT}/{CONT}/object").as_bytes()
            )
            .unwrap(),
            SIG_GET_SHA256
        );
        assert_eq!(
            hmac_hex(
                "sha512",
                KEY.as_bytes(),
                format!("GET\n{EXPIRES}\n/v1/{ACCT}/{CONT}/object").as_bytes()
            )
            .unwrap(),
            SIG_GET_SHA512
        );
        assert!(hmac_hex("md5", b"k", b"m").is_none());
    }

    #[test]
    fn test_streq_const_time() {
        assert!(streq_const_time("abc", "abc"));
        assert!(!streq_const_time("abc", "abd"));
        assert!(!streq_const_time("abc", "abcd"));
    }

    #[test]
    fn test_quote_helpers() {
        assert_eq!(quote_plus("My File.pdf"), "My+File.pdf");
        assert_eq!(quote("My Test File.pdf", b" /"), "My Test File.pdf");
        assert_eq!(quote("My Test File.pdf", b""), "My%20Test%20File.pdf");
        assert_eq!(quote("a/b c", b" /"), "a/b c");
        assert_eq!(quote("a/b c", b""), "a%2Fb%20c");
        assert_eq!(
            disposition_format("attachment", "My Test File.pdf"),
            "attachment; filename=\"My Test File.pdf\"; filename*=UTF-8''My%20Test%20File.pdf"
        );
    }

    #[test]
    fn test_basename() {
        assert_eq!(basename("/v1/a/c/o"), "o");
        assert_eq!(basename("/v1/a/c/o".trim_end_matches('/')), "o");
        assert_eq!(basename("/v1/a/c/".trim_end_matches('/')), "c");
        assert_eq!(basename("solo"), "solo");
    }

    #[test]
    fn test_ip_in_range_ipv4() {
        assert!(ip_in_range("1.2.3.4", "1.2.3.4"));
        assert!(!ip_in_range("1.2.3.5", "1.2.3.4"));
        assert!(ip_in_range("1.2.3.50", "1.2.3.0/24"));
        assert!(!ip_in_range("1.2.4.1", "1.2.3.0/24"));
        assert!(ip_in_range("10.0.0.1", "0.0.0.0/0"));
    }

    #[test]
    fn test_temp_url_ip_range_accepts_matching_client() {
        let tu = tempurl(&[KEY]);
        let message = format!("ip=1.2.3.0/24\nGET\n{EXPIRES}\n/v1/AUTH_account/container/object");
        let sig = hmac_hex("sha256", KEY.as_bytes(), message.as_bytes()).unwrap();
        let q =
            format!("temp_url_sig={sig}&temp_url_expires={EXPIRES}&temp_url_ip_range=1.2.3.0/24");
        let resp = run(
            &tu,
            mk(
                "GET",
                "/v1/AUTH_account/container/object",
                &q,
                &[("X-Backend-Remote-Addr", "1.2.3.9")],
            ),
        );
        assert_eq!(resp.status, 200, "body={:?}", body_bytes(&resp));
    }

    #[test]
    fn test_temp_url_ip_range_rejects_outside() {
        let tu = tempurl(&[KEY]);
        let message = format!("ip=1.2.3.0/24\nGET\n{EXPIRES}\n/v1/AUTH_account/container/object");
        let sig = hmac_hex("sha256", KEY.as_bytes(), message.as_bytes()).unwrap();
        let q =
            format!("temp_url_sig={sig}&temp_url_expires={EXPIRES}&temp_url_ip_range=1.2.3.0/24");
        let resp = run(
            &tu,
            mk(
                "GET",
                "/v1/AUTH_account/container/object",
                &q,
                &[("X-Backend-Remote-Addr", "9.9.9.9")],
            ),
        );
        assert_eq!(resp.status, 401);
    }

    // ---- Hyper prepare/finish split (production ProxyAsyncService) ----
    //
    // Isolated :18080 never calls Middleware::handle(). HMAC and
    // X-Backend-Authorize-Override must happen in prepare(); Content-
    // Disposition / outgoing scrub must happen in finish().

    #[test]
    fn test_prepare_stamps_override_on_valid_signature() {
        let tu = tempurl(&[KEY]);
        let mut req = mk(
            "GET",
            "/v1/AUTH_account/container/object",
            &query(SIG_GET_SHA256),
            &[("X-Timestamp", "12345")],
        );
        match tu.prepare(&mut req) {
            MwPrep::Continue => {}
            MwPrep::ShortCircuit(resp) => {
                panic!(
                    "valid TempURL must Continue on prepare, got {}",
                    resp.status
                )
            }
        }
        assert_eq!(
            req.headers.get("X-Backend-Authorize-Override"),
            Some("true")
        );
        assert_eq!(
            req.headers.get("X-Backend-Remote-User"),
            Some(".wsgi.tempurl")
        );
        assert!(
            req.headers.get("X-Timestamp").is_none(),
            "incoming scrub must run in prepare so Hyper copies the cleaned head"
        );
        assert_eq!(
            req.query_string,
            format!("temp_url_sig={SIG_GET_SHA256}&temp_url_expires={EXPIRES}")
        );
    }

    #[test]
    fn test_prepare_short_circuits_bad_hmac() {
        let tu = tempurl(&[KEY]);
        let mut req = mk(
            "GET",
            "/v1/AUTH_account/container/object",
            &query("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            &[],
        );
        match tu.prepare(&mut req) {
            MwPrep::ShortCircuit(resp) => {
                assert_eq!(resp.status, 401);
                assert!(req.headers.get("X-Backend-Authorize-Override").is_none());
            }
            MwPrep::Continue => panic!("bad HMAC must ShortCircuit 401, not Continue"),
        }
    }

    #[test]
    fn test_prepare_passthrough_without_tempurl_params() {
        let tu = tempurl(&[KEY]);
        let mut req = mk(
            "GET",
            "/v1/AUTH_account/container/object",
            "format=json",
            &[],
        );
        match tu.prepare(&mut req) {
            MwPrep::Continue => {}
            MwPrep::ShortCircuit(resp) => {
                panic!("non-tempurl GET must Continue, got {}", resp.status)
            }
        }
        assert!(req.headers.get("X-Backend-Authorize-Override").is_none());
        assert_eq!(req.query_string, "format=json");
    }

    #[test]
    fn test_finish_scrubs_and_sets_disposition_after_prepare() {
        let tu = tempurl(&[KEY]);
        let mut req = mk(
            "GET",
            "/v1/AUTH_account/container/object",
            &query(SIG_GET_SHA256),
            &[],
        );
        assert!(matches!(tu.prepare(&mut req), MwPrep::Continue));
        let mut resp = Response::with_body(200, b"BODY".to_vec());
        resp.headers.set("X-Object-Meta-Secret", "leak");
        resp.headers.set("X-Object-Meta-Public-Ok", "kept");
        let resp = tu.finish(&req, resp);
        assert_eq!(
            resp.headers.get("Content-Disposition"),
            Some("attachment; filename=\"object\"; filename*=UTF-8''object")
        );
        assert_eq!(
            resp.headers.get("Expires"),
            Some(http_date(4102444800).as_str())
        );
        assert!(resp.headers.get("X-Object-Meta-Secret").is_none());
        assert_eq!(resp.headers.get("X-Object-Meta-Public-Ok"), Some("kept"));
    }

    #[test]
    fn test_prepare_accepts_decoded_object_path() {
        // Hyper unquotes PATH_INFO before prepare; HMAC is over the decoded
        // `/v1/{acct}/{cont}/{obj}` (Python: do not encode the path).
        let tu = tempurl(&[KEY]);
        let obj = "dir/a b.txt";
        let path = format!("/v1/{ACCT}/{CONT}/{obj}");
        let message = format!("GET\n{EXPIRES}\n{path}");
        let sig = hmac_hex("sha256", KEY.as_bytes(), message.as_bytes()).unwrap();
        let mut req = mk("GET", &path, &query(&sig), &[]);
        match tu.prepare(&mut req) {
            MwPrep::Continue => {}
            MwPrep::ShortCircuit(resp) => {
                panic!("decoded-path HMAC must Continue, got {}", resp.status)
            }
        }
        assert_eq!(
            req.headers.get("X-Backend-Remote-User"),
            Some(".wsgi.tempurl")
        );
    }
}
