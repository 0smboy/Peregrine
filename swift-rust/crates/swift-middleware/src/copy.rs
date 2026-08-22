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

//! `copy`: server-side object copy, ported from
//! `swift/common/middleware/copy.py`.
//!
//! Two entry points, both resolved into a GET of the source object followed
//! by a PUT of the destination, all as backend subrequests:
//!
//! * `COPY /v1/a/c/o` with a `Destination: /dstc/dsto` header, and
//! * `PUT /v1/a/dstc/dsto` with an `X-Copy-From: /c/o` header.
//!
//! The source account defaults to the request account and may be overridden
//! with `X-Copy-From-Account` (or `Destination-Account` on a COPY). On a copy
//! the destination object inherits the source's `Content-Type` and other
//! object metadata unless `X-Fresh-Metadata: true` is set, in which case only
//! the request's own metadata is used.
//!
//! Manifest-aware copy (`?multipart-manifest=get`) fetches the raw SLO/DLO
//! manifest and re-PUTs it as a manifest (`multipart-manifest=put` for SLO;
//! `X-Object-Manifest` for DLO). `Range` partial copy is supported via the
//! source GET. Residual vs. `copy.py` (wontfix P1c): container/account
//! sync-key propagation.

use std::future::Future;
use std::pin::Pin;

use swift_http::{split_path, Body, HeaderKeyDict, Request, Response};

use crate::{AsyncNextFn, Middleware, NextFn};

/// The `copy` middleware.
#[derive(Default, Debug, Clone)]
pub struct Copy {
    /// Seconds between cooperative yield points during large copies
    /// (`[filter:copy] yield_frequency`, default 10).
    pub yield_frequency: f64,
}

impl Copy {
    pub fn new() -> Self {
        Copy {
            yield_frequency: 10.0,
        }
    }

    pub fn with_yield_frequency(mut self, seconds: f64) -> Self {
        self.yield_frequency = if seconds.is_finite() && seconds >= 0.0 {
            seconds
        } else {
            10.0
        };
        self
    }
}

/// Python `urllib.parse.unquote` for a single path/header component.
/// Invalid `%` sequences are left intact (`%-sign` stays `%-sign`).
fn percent_decode_component(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(hex) = std::str::from_utf8(&bytes[i + 1..i + 3]) {
                if let Ok(value) = u8::from_str_radix(hex, 16) {
                    out.push(value);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `urllib.parse.quote(s, safe='/')` / Python `wsgi_quote` with default
/// `safe='/'`. COPY rewrites `X-Copy-From` through this so a later unquote
/// keeps a literal `%2F` in the object name instead of turning it into `/`.
fn wsgi_quote(s: &str) -> String {
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

/// Parse a `/<container>/<object>` header value into its two parts.
///
/// Python `copy.py` does `split_path(unquote(copy_from), 1, 2, True)`.
/// `X-Copy-From` is stored `wsgi_quote`d so `%` in the object name survives
/// the unquote (`%2F` stays the three characters `%2F`, not a slash).
fn parse_container_object(value: &str) -> Option<(String, String)> {
    let decoded = percent_decode_component(value);
    let v = decoded.strip_prefix('/').unwrap_or(decoded.as_str());
    let (container, object) = v.split_once('/')?;
    if container.is_empty() || object.is_empty() {
        return None;
    }
    Some((container.to_string(), object.to_string()))
}

/// Object metadata headers copied from the source when metadata is preserved.
fn is_copied_source_header(name: &str) -> bool {
    let lname = name.to_ascii_lowercase();
    // Python excludes x-static-large-object / x-object-manifest from the
    // generic copy set; those are handled by the multipart-manifest path.
    if lname == "x-static-large-object" || lname == "x-object-manifest" {
        return false;
    }
    lname == "content-type"
        || lname == "content-encoding"
        || lname == "content-disposition"
        || lname == "x-delete-at"
        || lname.starts_with("x-object-meta-")
        || lname.starts_with("x-object-sysmeta-")
        // After `?symlink=get`, sysmeta is converted to X-Symlink-*; Python
        // copy_header_subset still carries those onto the dest PUT so the
        // dest is a symlink, not a 0-byte regular object.
        || lname.starts_with("x-symlink-")
}

/// True when the client asked for a raw-manifest copy
/// (`?multipart-manifest=get`).
fn is_manifest_get(req: &Request) -> bool {
    req.param("multipart-manifest").as_deref() == Some("get")
}

/// Rewrite `query_string`, setting or clearing `multipart-manifest`.
fn set_multipart_manifest_param(query: &str, value: Option<&str>) -> String {
    let mut parts: Vec<(String, String)> = Vec::new();
    if !query.is_empty() {
        for pair in query.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (k, v) = match pair.split_once('=') {
                Some((k, v)) => (k, v),
                None => (pair, ""),
            };
            if k.eq_ignore_ascii_case("multipart-manifest") {
                continue;
            }
            parts.push((k.to_string(), v.to_string()));
        }
    }
    if let Some(v) = value {
        parts.push(("multipart-manifest".to_string(), v.to_string()));
    }
    parts
        .into_iter()
        .map(|(k, v)| if v.is_empty() { k } else { format!("{k}={v}") })
        .collect::<Vec<_>>()
        .join("&")
}

impl Copy {
    /// Run the GET-source / PUT-dest sequence for a request already shaped as
    /// a PUT carrying `X-Copy-From` (+ optional `X-Copy-From-Account`).
    fn do_copy(&self, mut req: Request, next: &NextFn) -> Response {
        let parts = match split_path(&req.path, 4, 4, true) {
            Ok(p) => p,
            Err(_) => return Response::error(412, "Invalid destination path"),
        };
        let version = parts[0].clone().unwrap_or_default();
        let dst_account = parts[1].clone().unwrap_or_default();

        let copy_from = req.headers.get("X-Copy-From").unwrap_or("").to_string();
        let Some((src_container, src_object)) = parse_container_object(&copy_from) else {
            return Response::error(
                412,
                "X-Copy-From header must be of the form /container/object",
            );
        };
        let src_account = req
            .headers
            .get("X-Copy-From-Account")
            .map(|s| s.to_string())
            .unwrap_or_else(|| dst_account.clone());
        let fresh_metadata = req
            .headers
            .get("X-Fresh-Metadata")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        let manifest_get = is_manifest_get(&req);

        // 1) GET the source object.
        let mut get_req = Request {
            method: "GET".to_string(),
            path: format!("/{version}/{src_account}/{src_container}/{src_object}"),
            query_string: if manifest_get {
                // Python: multipart-manifest=get&format=raw so SLO/DLO return
                // the stored manifest body, not the reassembled object.
                "multipart-manifest=get&format=raw".to_string()
            } else {
                String::new()
            },
            headers: HeaderKeyDict::new(),
            body: Body::empty(),
        };
        get_req.headers.set("X-Newest", "true");
        // Carry the authenticated identity onto the source GET so it is
        // authorized as the same user (the proxy authorizes every subrequest
        // via the unspoofable X-Backend-Remote-User); without this a copy from
        // a private container would be denied.
        if let Some(ru) = req.headers.get("X-Backend-Remote-User") {
            get_req.headers.set("X-Backend-Remote-User", ru.to_string());
        }
        if let Some(rf) = req.headers.get("Referer") {
            get_req.headers.set("Referer", rf.to_string());
        }
        // Python's `_get_source_object` does `req.copy_get()`, preserving the
        // client's conditional headers on the source GET. In particular a
        // `Range` (or `If-*`) header must reach the source so a PUT+Range or
        // COPY+Range makes a partial copy.
        for cond in [
            "Range",
            "If-Match",
            "If-None-Match",
            "If-Modified-Since",
            "If-Unmodified-Since",
        ] {
            if let Some(v) = req.headers.get(cond) {
                get_req.headers.set(cond, v.to_string());
            }
        }
        let source = next(get_req);
        if !(200..300).contains(&source.status) {
            // propagate the source failure (e.g. 404) to the client
            return source;
        }

        let source_is_slo = source
            .headers
            .get("X-Static-Large-Object")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let source_dlo_manifest = source.headers.get("X-Object-Manifest").map(str::to_string);

        // 2) build the destination PUT: source body, merged headers.
        let mut put_headers = HeaderKeyDict::new();
        if !fresh_metadata {
            for (k, v) in source.headers.iter() {
                if is_copied_source_header(k) {
                    put_headers.set(k, v);
                }
            }
        }
        // the request's own metadata wins over the source's
        for (k, v) in req.headers.iter() {
            let lk = k.to_ascii_lowercase();
            if lk == "x-copy-from"
                || lk == "x-copy-from-account"
                || lk == "x-fresh-metadata"
                || lk == "content-length"
            {
                continue;
            }
            put_headers.set(k, v);
        }

        // Manifest-aware copy: re-PUT as SLO put or DLO header, matching
        // Python copy.py handle_PUT multipart-manifest=get branch.
        if manifest_get {
            if source_is_slo {
                req.query_string = set_multipart_manifest_param(&req.query_string, Some("put"));
            } else if let Some(dlo) = &source_dlo_manifest {
                req.query_string = set_multipart_manifest_param(&req.query_string, None);
                put_headers.set("X-Object-Manifest", dlo);
            } else {
                req.query_string = set_multipart_manifest_param(&req.query_string, None);
            }
        }

        // The source body is plumbed straight through to the destination PUT
        // as a stream — an object copy never materializes the object.
        let (source_reader, source_len) = source.body.into_reader();
        if let Some(len) = source_len {
            put_headers.set("Content-Length", len.to_string());
        }
        put_headers.set("X-Copied-From", format!("{src_container}/{src_object}"));
        put_headers.set("X-Copied-From-Account", src_account.clone());

        req.method = "PUT".to_string();
        req.headers = put_headers;
        req.body = Body::from_reader(source_reader, source_len);
        let mut resp = next(req);
        // surface the copy provenance on the response, as Python does
        resp.headers
            .set("X-Copied-From", format!("{src_container}/{src_object}"));
        resp.headers
            .set("X-Copied-From-Account", src_account.clone());
        resp
    }

    fn rewrite_copy_as_put(&self, mut req: Request) -> Result<Request, Response> {
        let parts = match split_path(&req.path, 4, 4, true) {
            Ok(p) => p,
            Err(_) => return Err(Response::error(412, "Invalid destination path")),
        };
        let version = parts[0].clone().unwrap_or_default();
        let account = parts[1].clone().unwrap_or_default();
        let container = parts[2].clone().unwrap_or_default();
        let object = parts[3].clone().unwrap_or_default();
        let Some(dest) = req.headers.get("Destination").map(|s| s.to_string()) else {
            return Err(Response::error(412, "Destination header required"));
        };
        let Some((dst_container, dst_object)) = parse_container_object(&dest) else {
            return Err(Response::error(
                412,
                "Destination header must be of the form /container/object",
            ));
        };
        let dst_account = req
            .headers
            .get("Destination-Account")
            .map(|s| s.to_string())
            .unwrap_or_else(|| account.clone());
        req.method = "PUT".to_string();
        req.path = format!("/{version}/{dst_account}/{dst_container}/{dst_object}");
        // Python `handle_COPY`: `req.headers['X-Copy-From'] = wsgi_quote(source)`
        // so a later `unquote` + `split_path(..., rest_with_last=True)` keeps
        // a literal `%2F` in the object name (`TestFile.testCopy`).
        req.headers
            .set("X-Copy-From", wsgi_quote(&format!("/{container}/{object}")));
        req.headers.set("X-Copy-From-Account", wsgi_quote(&account));
        req.headers.remove("Destination");
        req.headers.remove("Destination-Account");
        Ok(req)
    }

    async fn do_copy_async(&self, mut req: Request, next: AsyncNextFn) -> Response {
        let parts = match split_path(&req.path, 4, 4, true) {
            Ok(p) => p,
            Err(_) => return Response::error(412, "Invalid destination path"),
        };
        let version = parts[0].clone().unwrap_or_default();
        let dst_account = parts[1].clone().unwrap_or_default();
        let copy_from = req.headers.get("X-Copy-From").unwrap_or("").to_string();
        let Some((src_container, src_object)) = parse_container_object(&copy_from) else {
            return Response::error(
                412,
                "X-Copy-From header must be of the form /container/object",
            );
        };
        let src_account = req
            .headers
            .get("X-Copy-From-Account")
            .map(|s| s.to_string())
            .unwrap_or_else(|| dst_account.clone());
        let fresh_metadata = req
            .headers
            .get("X-Fresh-Metadata")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let manifest_get = is_manifest_get(&req);

        let mut get_req = Request {
            method: "GET".to_string(),
            path: format!("/{version}/{src_account}/{src_container}/{src_object}"),
            query_string: if manifest_get {
                "multipart-manifest=get&format=raw".to_string()
            } else {
                String::new()
            },
            headers: HeaderKeyDict::new(),
            body: Body::empty(),
        };
        get_req.headers.set("X-Newest", "true");
        if let Some(ru) = req.headers.get("X-Backend-Remote-User") {
            get_req.headers.set("X-Backend-Remote-User", ru.to_string());
        }
        if let Some(rf) = req.headers.get("Referer") {
            get_req.headers.set("Referer", rf.to_string());
        }
        for cond in [
            "Range",
            "If-Match",
            "If-None-Match",
            "If-Modified-Since",
            "If-Unmodified-Since",
        ] {
            if let Some(v) = req.headers.get(cond) {
                get_req.headers.set(cond, v.to_string());
            }
        }
        let source = next(get_req).await;
        if !(200..300).contains(&source.status) {
            return source;
        }
        let source_is_slo = source
            .headers
            .get("X-Static-Large-Object")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let source_dlo_manifest = source.headers.get("X-Object-Manifest").map(str::to_string);

        let mut put_headers = HeaderKeyDict::new();
        if !fresh_metadata {
            for (k, v) in source.headers.iter() {
                if is_copied_source_header(k) {
                    put_headers.set(k, v);
                }
            }
        }
        for (k, v) in req.headers.iter() {
            let lk = k.to_ascii_lowercase();
            if lk == "x-copy-from"
                || lk == "x-copy-from-account"
                || lk == "x-fresh-metadata"
                || lk == "content-length"
            {
                continue;
            }
            put_headers.set(k, v);
        }
        if manifest_get {
            if source_is_slo {
                req.query_string = set_multipart_manifest_param(&req.query_string, Some("put"));
            } else if let Some(dlo) = &source_dlo_manifest {
                req.query_string = set_multipart_manifest_param(&req.query_string, None);
                put_headers.set("X-Object-Manifest", dlo);
            } else {
                req.query_string = set_multipart_manifest_param(&req.query_string, None);
            }
        }
        let bytes = match source.body.collect_async().await {
            Ok(b) => b,
            Err(_) => return Response::error(499, "Client Disconnect"),
        };
        put_headers.set("Content-Length", bytes.len().to_string());
        put_headers.set("X-Copied-From", format!("{src_container}/{src_object}"));
        put_headers.set("X-Copied-From-Account", src_account.clone());
        req.method = "PUT".to_string();
        req.headers = put_headers;
        req.body = Body::Buffered(bytes);
        let mut resp = next(req).await;
        resp.headers
            .set("X-Copied-From", format!("{src_container}/{src_object}"));
        resp.headers
            .set("X-Copied-From-Account", src_account);
        resp
    }
}

impl Middleware for Copy {
    fn handle(&self, req: Request, next: &NextFn) -> Response {
        // Only object requests (4 path segments) are candidates.
        let _parts = match split_path(&req.path, 4, 4, true) {
            Ok(p) => p,
            Err(_) => return next(req),
        };

        if req.method == "PUT" && req.headers.get("X-Copy-From").is_some() {
            return self.do_copy(req, next);
        }

        if req.method == "COPY" {
            match self.rewrite_copy_as_put(req) {
                Ok(req) => return self.do_copy(req, next),
                Err(resp) => return resp,
            }
        }

        next(req)
    }

    fn intercepts_request(&self, req: &Request) -> bool {
        split_path(&req.path, 4, 4, true).is_ok()
            && (req.method == "COPY"
                || (req.method == "PUT" && req.headers.get("X-Copy-From").is_some()))
    }

    fn handle_request_async(
        &self,
        req: Request,
        next: AsyncNextFn,
    ) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        Box::pin(async move {
            if req.method == "COPY" {
                match self.rewrite_copy_as_put(req) {
                    Ok(req) => self.do_copy_async(req, next).await,
                    Err(resp) => resp,
                }
            } else {
                self.do_copy_async(req, next).await
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    fn req(method: &str, path: &str, headers: &[(&str, &str)]) -> Request {
        let mut h = HeaderKeyDict::new();
        for (k, v) in headers {
            h.set(k, v);
        }
        Request {
            method: method.to_string(),
            path: path.to_string(),
            query_string: String::new(),
            headers: h,
            body: Body::empty(),
        }
    }

    /// A fake backend that answers a scripted source GET and records the PUT
    /// (with its body drained into a buffered copy for the assertions).
    fn backend(
        source_body: &'static [u8],
        source_ct: &'static str,
    ) -> (Arc<Mutex<Vec<Request>>>, NextFn) {
        let log = Arc::new(Mutex::new(Vec::new()));
        let log2 = log.clone();
        let app: NextFn = Arc::new(move |mut r: Request| {
            let is_get = r.method == "GET";
            r.body.materialize(u64::MAX).unwrap();
            log2.lock().unwrap().push(r);
            if is_get {
                let mut resp = Response::with_body(200, source_body.to_vec());
                resp.headers.set("Content-Type", source_ct);
                resp.headers.set("X-Object-Meta-Color", "red");
                resp
            } else {
                Response::new(201)
            }
        });
        (log, app)
    }

    #[test]
    fn test_put_x_copy_from_copies_body_and_metadata() {
        let (log, app) = backend(b"hello", "text/plain");
        let c = Copy::new();
        let r = req(
            "PUT",
            "/v1/AUTH_test/dstc/dsto",
            &[("X-Copy-From", "/srcc/srco")],
        );
        let resp = c.handle(r, &app);
        assert_eq!(resp.status, 201);
        let mut calls = log.lock().unwrap();
        assert_eq!(calls.len(), 2, "GET source then PUT dest");
        assert_eq!(calls[0].method, "GET");
        assert_eq!(calls[0].path, "/v1/AUTH_test/srcc/srco");
        let put = &mut calls[1];
        assert_eq!(put.method, "PUT");
        assert_eq!(put.path, "/v1/AUTH_test/dstc/dsto");
        assert_eq!(put.body.materialize(u64::MAX).unwrap(), b"hello");
        // source content-type + meta preserved
        assert_eq!(put.headers.get("Content-Type"), Some("text/plain"));
        assert_eq!(put.headers.get("X-Object-Meta-Color"), Some("red"));
        assert_eq!(put.headers.get("Content-Length"), Some("5"));
        assert_eq!(resp.headers.get("X-Copied-From"), Some("srcc/srco"));
    }

    #[test]
    fn test_put_x_copy_from_unquotes_percent_encoded_object() {
        let (log, app) = backend(b"hello", "text/plain");
        let c = Copy::new();
        let r = req(
            "PUT",
            "/v1/AUTH_test/dstc/dsto",
            &[(
                "X-Copy-From",
                "/srcc/object%20name%20with%20%25-sign%20%F0%9F%99%82",
            )],
        );
        let resp = c.handle(r, &app);
        assert_eq!(resp.status, 201);
        let calls = log.lock().unwrap();
        assert_eq!(
            calls[0].path,
            "/v1/AUTH_test/srcc/object name with %-sign 🙂"
        );
    }

    #[test]
    fn test_copy_carries_symlink_user_headers() {
        // COPY ?symlink=get: source GET returns X-Symlink-Target (sysmeta
        // already converted). Dest PUT must keep that header.
        let log = Arc::new(Mutex::new(Vec::new()));
        let log2 = log.clone();
        let app: NextFn = Arc::new(move |mut r: Request| {
            let is_get = r.method == "GET";
            r.body.materialize(u64::MAX).unwrap();
            log2.lock().unwrap().push(r);
            if is_get {
                let mut resp = Response::with_body(200, Vec::new());
                resp.headers.set("Content-Type", "application/symlink");
                resp.headers.set("X-Symlink-Target", "tgtc/tgto");
                resp
            } else {
                Response::new(201)
            }
        });
        let c = Copy::new();
        let r = req(
            "PUT",
            "/v1/AUTH_test/dstc/link2",
            &[("X-Copy-From", "/srcc/link")],
        );
        let resp = c.handle(r, &app);
        assert_eq!(resp.status, 201);
        let calls = log.lock().unwrap();
        let dest_put = calls.iter().find(|c| c.method == "PUT").unwrap();
        assert_eq!(
            dest_put.headers.get("X-Symlink-Target"),
            Some("tgtc/tgto")
        );
    }

    #[test]
    fn test_copy_method_keeps_percent_encoded_slash_in_object_name() {
        // TestFile.testCopy source: 'dealde%2Fl04 011e%204c8df/flash.png'
        // Python wsgi_quote's X-Copy-From so unquote does not turn %2F into /.
        let (log, app) = backend(b"png", "image/png");
        let c = Copy::new();
        let r = req(
            "COPY",
            "/v1/AUTH_test/srcc/dealde%2Fl04 011e%204c8df/flash.png",
            &[("Destination", "/dstc/dsto")],
        );
        let resp = c.handle(r, &app);
        assert_eq!(resp.status, 201);
        let calls = log.lock().unwrap();
        assert_eq!(
            calls[0].path,
            "/v1/AUTH_test/srcc/dealde%2Fl04 011e%204c8df/flash.png",
            "GET source must keep literal %2F and the real slash"
        );
        assert_eq!(calls[1].path, "/v1/AUTH_test/dstc/dsto");
    }

    #[test]
    fn test_copy_method_uses_destination() {
        let (log, app) = backend(b"data", "application/json");
        let c = Copy::new();
        let r = req(
            "COPY",
            "/v1/AUTH_test/srcc/srco",
            &[("Destination", "/dstc/dsto")],
        );
        let resp = c.handle(r, &app);
        assert_eq!(resp.status, 201);
        let calls = log.lock().unwrap();
        assert_eq!(calls[0].path, "/v1/AUTH_test/srcc/srco", "GET the source");
        assert_eq!(
            calls[1].path, "/v1/AUTH_test/dstc/dsto",
            "PUT the destination"
        );
    }

    #[test]
    fn test_fresh_metadata_drops_source_meta() {
        let (log, app) = backend(b"x", "text/plain");
        let c = Copy::new();
        let r = req(
            "PUT",
            "/v1/AUTH_test/dstc/dsto",
            &[
                ("X-Copy-From", "/srcc/srco"),
                ("X-Fresh-Metadata", "true"),
                ("Content-Type", "image/png"),
            ],
        );
        let resp = c.handle(r, &app);
        assert_eq!(resp.status, 201);
        let calls = log.lock().unwrap();
        let put = &calls[1];
        // source meta NOT carried; request's own content-type wins
        assert_eq!(put.headers.get("X-Object-Meta-Color"), None);
        assert_eq!(put.headers.get("Content-Type"), Some("image/png"));
    }

    #[test]
    fn test_missing_destination_is_412() {
        let c = Copy::new();
        let app: NextFn = Arc::new(|_r: Request| Response::new(201));
        let r = req("COPY", "/v1/AUTH_test/srcc/srco", &[]);
        let resp = c.handle(r, &app);
        assert_eq!(resp.status, 412);
    }

    #[test]
    fn test_source_404_propagates() {
        let app: NextFn = Arc::new(|r: Request| {
            if r.method == "GET" {
                Response::new(404)
            } else {
                Response::new(201)
            }
        });
        let c = Copy::new();
        let r = req(
            "PUT",
            "/v1/AUTH_test/dstc/dsto",
            &[("X-Copy-From", "/srcc/missing")],
        );
        let resp = c.handle(r, &app);
        assert_eq!(resp.status, 404, "source failure surfaces, no PUT");
    }

    #[test]
    fn test_range_header_forwarded_to_source_get() {
        // A COPY (or PUT+X-Copy-From) carrying a Range must make a partial
        // copy: the Range header has to reach the source GET.
        let (log, app) = backend(b"test", "text/plain");
        let c = Copy::new();
        let r = req(
            "COPY",
            "/v1/AUTH_test/srcc/srco",
            &[("Destination", "/dstc/dsto"), ("Range", "bytes=1-2")],
        );
        let resp = c.handle(r, &app);
        assert_eq!(resp.status, 201);
        let calls = log.lock().unwrap();
        assert_eq!(calls[0].method, "GET");
        assert_eq!(calls[0].headers.get("Range"), Some("bytes=1-2"));
    }

    #[test]
    fn test_non_object_passes_through() {
        let c = Copy::new();
        let app: NextFn = Arc::new(|_r: Request| Response::new(204));
        let r = req("PUT", "/v1/AUTH_test/c", &[("X-Copy-From", "/x/y")]);
        assert_eq!(c.handle(r, &app).status, 204);
    }

    #[test]
    fn test_manifest_get_copy_slo_rewrites_to_put() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let log2 = log.clone();
        let app: NextFn = Arc::new(move |mut r: Request| {
            let is_get = r.method == "GET";
            let qs = r.query_string.clone();
            r.body.materialize(u64::MAX).unwrap();
            log2.lock().unwrap().push(r);
            if is_get {
                let mut resp = Response::with_body(
                    200,
                    br#"[{"path":"/c/s","etag":"e","size_bytes":1}]"#.to_vec(),
                );
                resp.headers.set("X-Static-Large-Object", "True");
                resp.headers.set("Content-Type", "application/json");
                // Source GET must ask for the raw manifest.
                assert!(qs.contains("multipart-manifest=get"), "source GET qs={qs}");
                resp
            } else {
                Response::new(201)
            }
        });
        let mut r = req(
            "PUT",
            "/v1/AUTH_test/dstc/dsto",
            &[("X-Copy-From", "/srcc/srco")],
        );
        r.query_string = "multipart-manifest=get".to_string();
        let resp = Copy::new().handle(r, &app);
        assert_eq!(resp.status, 201);
        let calls = log.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert!(
            calls[1].query_string.contains("multipart-manifest=put"),
            "dest PUT qs={}",
            calls[1].query_string
        );
        assert!(calls[1].headers.get("X-Static-Large-Object").is_none());
    }

    #[test]
    fn test_manifest_get_copy_dlo_sets_x_object_manifest() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let log2 = log.clone();
        let app: NextFn = Arc::new(move |mut r: Request| {
            let is_get = r.method == "GET";
            r.body.materialize(u64::MAX).unwrap();
            log2.lock().unwrap().push(r);
            if is_get {
                let mut resp = Response::with_body(200, Vec::new());
                resp.headers.set("X-Object-Manifest", "c/segs/");
                resp.headers.set("Content-Type", "text/plain");
                resp
            } else {
                Response::new(201)
            }
        });
        let mut r = req(
            "PUT",
            "/v1/AUTH_test/dstc/dsto",
            &[("X-Copy-From", "/srcc/srco")],
        );
        r.query_string = "multipart-manifest=get".to_string();
        let resp = Copy::new().handle(r, &app);
        assert_eq!(resp.status, 201);
        let calls = log.lock().unwrap();
        assert!(!calls[1].query_string.contains("multipart-manifest"));
        assert_eq!(calls[1].headers.get("X-Object-Manifest"), Some("c/segs/"));
    }

    #[test]
    fn test_intercepts_copy_and_x_copy_from() {
        let c = Copy::new();
        let copy = req("COPY", "/v1/a/c/o", &[("Destination", "/d/o2")]);
        assert!(c.intercepts_request(&copy));
        let put = req("PUT", "/v1/a/d/o2", &[("X-Copy-From", "/c/o")]);
        assert!(c.intercepts_request(&put));
        let plain = req("PUT", "/v1/a/c/o", &[]);
        assert!(!c.intercepts_request(&plain));
        let acc = req("COPY", "/v1/a", &[]);
        assert!(!c.intercepts_request(&acc));
    }

    #[tokio::test]
    async fn test_async_x_copy_from_goes_through_next() {
        let (log, app) = backend(b"hello", "text/plain");
        let next: AsyncNextFn = std::sync::Arc::new(move |r: Request| {
            let app = app.clone();
            Box::pin(async move { app(r) })
        });
        let r = req(
            "PUT",
            "/v1/AUTH_test/dstc/dsto",
            &[("X-Copy-From", "/srcc/srco")],
        );
        let resp = Copy::new().do_copy_async(r, next).await;
        assert_eq!(resp.status, 201);
        let calls = log.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].method, "GET");
        assert_eq!(calls[1].method, "PUT");
    }
}
