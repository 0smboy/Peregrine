// Copyright (c) 2013 OpenStack Foundation
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

//! `dlo`: Dynamic Large Object support, a port of the GET/HEAD reassembly and
//! PUT validation in `swift/common/middleware/dlo.py`.
//!
//! A DLO manifest is an object carrying an `X-Object-Manifest:
//! <container>/<prefix>` header. On GET/HEAD of that object the middleware:
//!
//! 1. issues a container-listing **subrequest**
//!    (`GET /<v>/<a>/<container>?prefix=<prefix>`) to enumerate the segments
//!    (sorted lexicographically by the container DB),
//! 2. computes the aggregate `Content-Length` (sum of segment `bytes`) and, for
//!    a complete listing, the DLO `Etag` (`md5` of the concatenated,
//!    quote-normalized segment hashes, wrapped in quotes),
//! 3. for a GET, fetches each segment with its own subrequest and streams the
//!    concatenation as the body — honouring a single `Range` header by slicing
//!    the concatenation.
//!
//! A HEAD returns the aggregate metadata with no body. `multipart-manifest=get`
//! bypasses reassembly (returns the raw manifest object).
//!
//! Simplifications vs. Python: the container listing is fetched as a single
//! page (the `CONTAINER_LISTING_LIMIT` marker-pagination loop and the
//! `RateLimitedIterator`/`SegmentedIterable` streaming machinery are not
//! ported), and a ranged GET fetches whole segments and slices the
//! concatenation rather than issuing per-segment ranged subrequests. The
//! observable result (status, headers, body bytes) matches Python for any
//! listing under the limit.

use std::io::Read;
use std::sync::Arc;

use swift_http::{
    split_path, unquote, Body, FnReader, HeaderKeyDict, Range, Request, Response,
    MAX_CONTROL_BODY,
};

use crate::slo::dlo_etag_and_size;
use crate::{Middleware, NextFn};

/// `swift.common.constraints.CONTAINER_LISTING_LIMIT`.
const CONTAINER_LISTING_LIMIT: usize = 10000;
const X_OBJECT_MANIFEST: &str = "X-Object-Manifest";
const IGNORE_RANGE_HDR: &str = "X-Backend-Ignore-Range-If-Metadata-Present";

/// Dynamic Large Object middleware.
#[derive(Debug, Default, Clone)]
pub struct DynamicLargeObject;

impl DynamicLargeObject {
    pub fn new() -> Self {
        DynamicLargeObject
    }
}

/// One enumerated segment from the container listing.
#[derive(Debug, Clone)]
struct Segment {
    name: String,
    bytes: i64,
    hash: String,
}

/// `urllib.parse.quote` with the default safe set, for query-string values.
fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-' | b'~' | b'/' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// `request_helpers.update_ignore_range_header`: signal the backend to serve
/// the whole object (ignore `Range`) when `name` metadata is present, so the
/// manifest object itself is returned with its `X-Object-Manifest` header
/// intact even when the client sent a `Range`.
fn update_ignore_range_header(headers: &mut HeaderKeyDict, name: &str) {
    let val = match headers.get(IGNORE_RANGE_HDR) {
        Some(s) if !s.is_empty() => format!("{s},{name}"),
        _ => name.to_string(),
    };
    headers.set(IGNORE_RANGE_HDR, val);
}

/// Build a backend subrequest that preserves the original request's auth
/// context (headers/env) while overriding the method/path/query and dropping
/// the body plus any range/length/conditional headers.
fn make_subreq(orig: &Request, method: &str, path: String, query_string: String) -> Request {
    let mut headers = orig.headers.clone();
    headers.remove("Range");
    headers.remove("Content-Length");
    headers.remove("If-Match");
    headers.remove("If-None-Match");
    headers.remove("If-Modified-Since");
    headers.remove("If-Unmodified-Since");
    headers.remove(IGNORE_RANGE_HDR);
    Request {
        method: method.to_string(),
        path,
        query_string,
        headers,
        body: Body::empty(),
    }
}

fn parse_segments(json: &[u8]) -> Vec<Segment> {
    let value: serde_json::Value = match serde_json::from_slice(json) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    if let Some(arr) = value.as_array() {
        for it in arr {
            // subdir rows have no "name"; skip them.
            let Some(name) = it.get("name").and_then(|v| v.as_str()) else {
                continue;
            };
            out.push(Segment {
                name: name.to_string(),
                bytes: it.get("bytes").and_then(|v| v.as_i64()).unwrap_or(0),
                hash: it
                    .get("hash")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            });
        }
    }
    out
}

impl DynamicLargeObject {
    /// GET or HEAD: detect a manifest object and, if present, reassemble it.
    fn handle_get_head(&self, mut req: Request, next: &NextFn) -> Response {
        update_ignore_range_header(&mut req.headers, X_OBJECT_MANIFEST);
        let orig_req = req.clone_head();
        let resp = next(req);

        match resp.headers.get(X_OBJECT_MANIFEST).map(str::to_string) {
            Some(x_object_manifest) => {
                self.get_or_head_response(&orig_req, &resp, &x_object_manifest, next)
            }
            // Not a DLO manifest; pass the response through unchanged.
            None => resp,
        }
    }

    /// Fetch the container listing for the manifest's `<container>/<prefix>`.
    /// On a non-2xx listing, returns the error response to relay.
    fn get_container_listing(
        &self,
        orig: &Request,
        version: &str,
        account: &str,
        container: &str,
        prefix: &str,
        next: &NextFn,
    ) -> Result<Vec<Segment>, Response> {
        let path = format!("/{version}/{account}/{container}");
        let query_string = format!("prefix={}&format=json", quote(prefix));
        let con_req = make_subreq(orig, "GET", path, query_string);
        let mut con_resp = next(con_req);
        if !(200..300).contains(&con_resp.status) {
            let mut err = con_resp;
            if orig.method == "HEAD" {
                err.body = Body::empty();
            }
            return Err(err);
        }
        // A container listing is bounded by the listing limit; anything
        // larger cannot be one, so treat it as an empty listing.
        Ok(match con_resp.body.materialize(MAX_CONTROL_BODY) {
            Ok(bytes) => parse_segments(bytes),
            Err(_) => Vec::new(),
        })
    }

    fn get_or_head_response(
        &self,
        req: &Request,
        manifest_resp: &Response,
        x_object_manifest: &str,
        next: &NextFn,
    ) -> Response {
        // Match Python Swift's wsgi_unquote before splitting. The listing
        // subrequest quotes the decoded prefix exactly once below.
        let decoded_manifest = unquote(x_object_manifest);
        let (container, obj_prefix) = decoded_manifest
            .split_once('/')
            .unwrap_or((decoded_manifest.as_str(), ""));

        // version, account from the manifest object's path.
        let parts = match split_path(&req.path, 2, 3, true) {
            Ok(p) => p,
            Err(_) => return Response::error(400, "Invalid path"),
        };
        let version = parts[0].clone().unwrap_or_default();
        let account = parts[1].clone().unwrap_or_default();

        let segments = match self.get_container_listing(
            req, &version, &account, container, obj_prefix, next,
        ) {
            Ok(s) => s,
            Err(resp) => return resp,
        };
        let have_complete_listing = segments.len() < CONTAINER_LISTING_LIMIT;

        // Aggregate size and (for a complete listing) the DLO Etag.
        let pairs: Vec<(String, i64)> = segments
            .iter()
            .map(|s| (s.hash.clone(), s.bytes))
            .collect();
        let (dlo_etag, total_len) = dlo_etag_and_size(&pairs);

        // Resolve a single Range header against the aggregate length.
        // (first_byte, last_byte_exclusive)
        let mut byte_range: Option<(u64, u64)> = None;
        let mut unsatisfiable = false;
        let range = req
            .headers
            .get("Range")
            .and_then(|h| Range::parse(h).ok())
            .filter(|r| r.ranges.len() == 1);
        if let Some(range) = range {
            let total_u = total_len.max(0) as u64;
            match range.ranges_for_length(Some(total_u)) {
                Some(ranges) if ranges.is_empty() => {
                    // Only definitively unsatisfiable with a complete listing.
                    if have_complete_listing {
                        unsatisfiable = true;
                    }
                }
                // With a complete listing, honour the range; otherwise we can't
                // be sure of the aggregate length, so ignore it.
                Some(ranges) if have_complete_listing => {
                    byte_range = Some(ranges[0]);
                }
                Some(_) => {}
                None => {}
            }
        }

        if unsatisfiable {
            let mut resp = Response::error(416, "Requested Range Not Satisfiable");
            resp.headers.set("Accept-Ranges", "bytes");
            if have_complete_listing {
                resp.headers
                    .set("Content-Range", format!("bytes */{}", total_len.max(0)));
            }
            return resp;
        }

        // Assemble the response headers from the manifest object's headers,
        // dropping the ones we recompute.
        let mut headers = manifest_resp.headers.clone();
        headers.remove("Content-Length");
        headers.remove("Content-Range");
        headers.remove("Transfer-Encoding");
        if have_complete_listing {
            headers.remove("Etag");
            headers.set("Etag", &dlo_etag);
        }
        headers.set("Accept-Ranges", "bytes");

        let is_get = req.method == "GET";

        let (status, body, content_len) = if let Some((first, last_excl)) = byte_range {
            // Ranged (206): fetch the whole object then slice.
            // P1-leftover: still buffered — a ranged DLO GET assembles the
            // whole concatenation and slices it (per-segment ranged
            // subrequests are a later pass).
            let full = if is_get {
                match self.fetch_segments(req, &version, &account, container, &segments, next) {
                    Ok(b) => b,
                    Err(resp) => return resp,
                }
            } else {
                Vec::new()
            };
            let first_us = first as usize;
            let last_us = (last_excl as usize).min(full.len().max(first_us));
            let slice = if is_get {
                full.get(first_us..last_us).unwrap_or(&[]).to_vec()
            } else {
                Vec::new()
            };
            headers.set(
                "Content-Range",
                format!("bytes {}-{}/{}", first, last_excl - 1, total_len.max(0)),
            );
            (206u16, Body::from(slice), (last_excl - first) as i64)
        } else if is_get {
            // Whole object (200): lazy segment streaming — each subrequest
            // is issued only when the client stream reaches that segment; a
            // mid-stream failure aborts the connection (Python parity — the
            // status is already sent). The declared length is only known
            // with a complete listing.
            let body = Self::segment_stream_body(
                req.clone_head(),
                version.clone(),
                account.clone(),
                container.to_string(),
                segments,
                Arc::clone(next),
                have_complete_listing.then_some(total_len.max(0) as u64),
            );
            (200u16, body, total_len)
        } else {
            (200u16, Body::empty(), total_len)
        };

        if have_complete_listing || byte_range.is_some() {
            headers.set("Content-Length", content_len.to_string());
        }

        let mut resp = Response::new(status);
        resp.headers = headers;
        resp.body = body;
        resp
    }

    /// The lazy DLO reassembly body: a [`FnReader`] that pulls one segment
    /// subrequest at a time through a cloned `NextFn`. Segment failures
    /// surface as `io::Error` (the transport aborts the response).
    fn segment_stream_body(
        orig: Request,
        version: String,
        account: String,
        container: String,
        segments: Vec<Segment>,
        next: NextFn,
        content_length: Option<u64>,
    ) -> Body {
        let mut queue = segments.into_iter();
        let reader = FnReader::new(move || {
            let seg = queue.next()?;
            let path = format!("/{version}/{account}/{container}/{}", seg.name);
            let sub = make_subreq(&orig, "GET", path.clone(), String::new());
            let sresp = next(sub);
            if !(200..300).contains(&sresp.status) {
                return Some(Err(std::io::Error::other(format!(
                    "DLO segment {path} returned {}",
                    sresp.status
                ))));
            }
            let (reader, _len): (Box<dyn Read + Send>, _) = sresp.body.into_reader();
            Some(Ok(reader))
        });
        Body::from_reader(Box::new(reader), content_length)
    }

    /// Fetch every segment in order and return the concatenated bytes. On a
    /// segment fetch failure, returns a 409 (the client has to be told the
    /// large object is broken).
    fn fetch_segments(
        &self,
        orig: &Request,
        version: &str,
        account: &str,
        container: &str,
        segments: &[Segment],
        next: &NextFn,
    ) -> Result<Vec<u8>, Response> {
        let mut body = Vec::new();
        for seg in segments {
            let path = format!("/{version}/{account}/{container}/{}", seg.name);
            let sub = make_subreq(orig, "GET", path, String::new());
            let sresp = next(sub);
            if !(200..300).contains(&sresp.status) {
                return Err(Response::error(409, "Conflict"));
            }
            // P1-leftover: still buffered (ranged-GET assembly only).
            match sresp
                .body
                .into_vec(swift_core::constraints::MAX_FILE_SIZE as u64)
            {
                Ok(b) => body.extend_from_slice(&b),
                Err(_) => return Err(Response::error(409, "Conflict")),
            }
        }
        Ok(body)
    }
}

/// `_validate_x_object_manifest_header`: reject a malformed manifest header on
/// PUT with a 400 whose body Python sets verbatim.
fn validate_x_object_manifest_header(req: &Request) -> Option<Response> {
    let value = req.headers.get(X_OBJECT_MANIFEST)?;
    let (container, prefix) = match value.split_once('/') {
        Some((c, p)) => (c, p),
        None => ("", ""),
    };
    if container.is_empty()
        || prefix.is_empty()
        || value.contains('?')
        || value.contains('&')
        || prefix.starts_with('/')
    {
        let mut resp = Response::with_body(
            400,
            "X-Object-Manifest must be in the format container/prefix"
                .as_bytes()
                .to_vec(),
        );
        resp.headers.set("Content-Type", "text/html; charset=UTF-8");
        return Some(resp);
    }
    None
}

impl Middleware for DynamicLargeObject {
    fn handle(&self, req: Request, next: &NextFn) -> Response {
        // Only object requests (v/a/c/o) are candidates.
        if split_path(&req.path, 4, 4, true).is_err() {
            return next(req);
        }

        let is_get_head = req.method == "GET" || req.method == "HEAD";
        let mpm_get = req.param("multipart-manifest").as_deref() == Some("get");
        if is_get_head && !mpm_get {
            return self.handle_get_head(req, next);
        } else if req.method == "PUT" {
            if let Some(err) = validate_x_object_manifest_header(&req) {
                return err;
            }
        }
        next(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use md5::{Digest, Md5};

    /// A programmable backend: matches (method, path) to responses. Canned
    /// responses are torn into Sync parts (a `Body` reader is only `Send`)
    /// and re-issued per request, so one route can serve many subrequests.
    #[allow(clippy::type_complexity)]
    fn backend(routes: Vec<(&'static str, &'static str, Response)>) -> NextFn {
        let routes: Vec<(String, String, u16, HeaderKeyDict, Vec<u8>)> = routes
            .into_iter()
            .map(|(m, p, mut r)| {
                let body = r.body.materialize(u64::MAX).unwrap().to_vec();
                (m.to_string(), p.to_string(), r.status, r.headers, body)
            })
            .collect();
        Arc::new(move |req: Request| {
            for (m, p, status, headers, body) in routes.iter() {
                if &req.method == m && &req.path == p {
                    let mut out = Response::new(*status);
                    out.headers = headers.clone();
                    out.body = body.clone().into();
                    return out;
                }
            }
            Response::new(404)
        })
    }

    fn body_of(resp: &mut Response) -> Vec<u8> {
        resp.body.materialize(u64::MAX).unwrap().to_vec()
    }

    fn md5_hex(data: &[u8]) -> String {
        let d = Md5::digest(data);
        let mut s = String::new();
        for b in d {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    fn listing_json(entries: &[(&str, i64, &str)]) -> Vec<u8> {
        let items: Vec<serde_json::Value> = entries
            .iter()
            .map(|(name, bytes, hash)| {
                serde_json::json!({"name": name, "bytes": bytes, "hash": hash})
            })
            .collect();
        serde_json::to_vec(&items).unwrap()
    }

    fn get_req(path: &str, range: Option<&str>) -> Request {
        let mut headers = HeaderKeyDict::new();
        if let Some(r) = range {
            headers.set("Range", r);
        }
        Request {
            method: "GET".to_string(),
            path: path.to_string(),
            query_string: String::new(),
            headers,
            body: Body::empty(),
        }
    }

    fn manifest_backend() -> NextFn {
        // manifest object -> zero body with X-Object-Manifest + Content-Type
        let mk_manifest = || {
            let mut manifest = Response::with_body(200, Vec::new());
            manifest.headers.set("X-Object-Manifest", "c/segs/");
            manifest.headers.set("Content-Type", "text/jibberish");
            manifest.headers.set("Content-Length", "0");
            manifest.headers.set("Etag", md5_hex(b""));
            manifest
        };
        let manifest = mk_manifest();
        let manifest_head = mk_manifest();

        let listing = Response::with_body(
            200,
            listing_json(&[
                ("segs/1", 3, &md5_hex(b"one")),
                ("segs/2", 3, &md5_hex(b"two")),
                ("segs/3", 5, &md5_hex(b"three")),
            ]),
        );

        backend(vec![
            ("GET", "/v1/a/c/manifest", manifest),
            ("HEAD", "/v1/a/c/manifest", manifest_head),
            ("GET", "/v1/a/c", listing),
            ("GET", "/v1/a/c/segs/1", Response::with_body(200, b"one".to_vec())),
            ("GET", "/v1/a/c/segs/2", Response::with_body(200, b"two".to_vec())),
            (
                "GET",
                "/v1/a/c/segs/3",
                Response::with_body(200, b"three".to_vec()),
            ),
        ])
    }

    #[test]
    fn test_full_get_reassembles() {
        let dlo = DynamicLargeObject::new();
        let be = manifest_backend();
        let mut resp = dlo.handle(get_req("/v1/a/c/manifest", None), &be);
        assert_eq!(resp.status, 200);
        assert_eq!(body_of(&mut resp), b"onetwothree");
        assert_eq!(resp.headers.get("Content-Type"), Some("text/jibberish"));
        assert_eq!(resp.headers.get("Content-Length"), Some("11"));
    }

    #[test]
    fn test_head_no_body() {
        let dlo = DynamicLargeObject::new();
        let be = manifest_backend();
        let mut req = get_req("/v1/a/c/manifest", None);
        req.method = "HEAD".to_string();
        let resp = dlo.handle(req, &be);
        assert_eq!(resp.status, 200);
        assert!(resp.body.is_definitely_empty());
        assert_eq!(resp.headers.get("Content-Length"), Some("11"));
    }

    #[test]
    fn test_range_from_start_of_second_segment() {
        // "onetwothree", bytes=3- -> "twothree", 206
        let dlo = DynamicLargeObject::new();
        let be = manifest_backend();
        let mut resp = dlo.handle(get_req("/v1/a/c/manifest", Some("bytes=3-")), &be);
        assert_eq!(resp.status, 206);
        assert_eq!(body_of(&mut resp), b"twothree");
        assert_eq!(resp.headers.get("Content-Range"), Some("bytes 3-10/11"));
    }

    #[test]
    fn test_range_middle() {
        // bytes=5-10 -> "onetwothree"[5..11] = "othree"
        let dlo = DynamicLargeObject::new();
        let be = manifest_backend();
        let mut resp = dlo.handle(
            get_req("/v1/a/c/manifest", Some("bytes=5-10")),
            &be,
        );
        assert_eq!(resp.status, 206);
        assert_eq!(body_of(&mut resp), b"othree");
    }

    #[test]
    fn test_non_manifest_passthrough() {
        let dlo = DynamicLargeObject::new();
        let be = backend(vec![(
            "GET",
            "/v1/a/c/plain",
            Response::with_body(200, b"hello".to_vec()),
        )]);
        let mut resp = dlo.handle(get_req("/v1/a/c/plain", None), &be);
        assert_eq!(resp.status, 200);
        assert_eq!(body_of(&mut resp), b"hello");
    }

    #[test]
    fn test_listing_error_relayed() {
        let dlo = DynamicLargeObject::new();
        let mut manifest = Response::with_body(200, Vec::new());
        manifest.headers.set("X-Object-Manifest", "c/segs/");
        let be = backend(vec![
            ("GET", "/v1/a/c/manifest", manifest),
            ("GET", "/v1/a/c", Response::new(403)),
        ]);
        let resp = dlo.handle(get_req("/v1/a/c/manifest", None), &be);
        assert_eq!(resp.status, 403);
    }

    #[test]
    fn test_put_validation() {
        let dlo = DynamicLargeObject::new();
        let mut req = Request {
            method: "PUT".to_string(),
            path: "/v1/a/c/manifest".to_string(),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: Body::empty(),
        };
        req.headers.set("X-Object-Manifest", "badformat");
        let be = backend(vec![]);
        let resp = dlo.handle(req, &be);
        assert_eq!(resp.status, 400);
    }
}
