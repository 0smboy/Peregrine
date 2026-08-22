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

//! `container_quotas`: enforces per-container byte/object quotas, a port of
//! `swift/common/middleware/container_quotas.py`. A container administrator
//! sets `X-Container-Meta-Quota-Bytes` and/or `X-Container-Meta-Quota-Count`
//! on the container; this middleware then rejects any object `PUT` that would
//! push the container past those limits with `413 Request Entity Too Large`
//! and the body `Upload exceeds quota.`. When those quota headers are *set*
//! (a container `PUT`/`POST`) they are validated to be all-digit, and a
//! malformed value is rejected with `400 Bad Request`.
//!
//! To read the container's current usage the Python middleware calls
//! `get_container_info(req.environ, self.app, swift_source='CQ')`, which
//! consults the container-info cache or issues a backend subrequest. This
//! port makes that subrequest explicit: it constructs a fresh `HEAD` of the
//! container path and calls `next` with it, then reads the usage and quota
//! from the response headers (`X-Container-Bytes-Used`,
//! `X-Container-Object-Count`, `X-Container-Meta-Quota-Bytes`,
//! `X-Container-Meta-Quota-Count`) before calling `next` again with the real
//! object `PUT`. `content_length` is taken from the request's
//! `Content-Length` header.
//!
//! Deferrals:
//! * The container-info *cache* is not modelled; every policed object `PUT`
//!   costs one real backend `HEAD` subrequest here.
//! * `bad_response`'s `swift.authorize` branch — which returns the auth
//!   middleware's own response (typically `401`) instead of `413` so the
//!   container's existence is not leaked to a caller who could not have
//!   written the object anyway — needs the pipeline's `swift.authorize`
//!   callback and the container `write_acl`; it is not ported, so an
//!   over-quota `PUT` always returns `413`.
//! * `filter_factory` and `register_swift_info('container_quotas')` are not
//!   ported (registration is handled elsewhere).
//! * Python's `req.method in ('PUT')` (a substring test against the string
//!   `'PUT'`, not a tuple) is faithfully rendered as `method == "PUT"`, the
//!   only real HTTP method it can match.

use swift_http::{split_path, Request, Response};

use crate::{Middleware, NextFn};

/// Resolve the request's byte size for quota math. Prefer `Content-Length`,
/// then a declared streamed length. When the body is chunked / unknown
/// (common behind HAProxy), materialize up to `cap` bytes — overflowing
/// `cap` means the upload already exceeds the remaining quota.
fn request_content_length(req: &mut Request, cap: u64) -> Result<i64, ()> {
    if let Some(v) = req
        .headers
        .get("Content-Length")
        .and_then(|v| v.parse::<i64>().ok())
    {
        return Ok(v);
    }
    if let Some(n) = req.body.content_length() {
        return Ok(n as i64);
    }
    match req.body.materialize(cap) {
        Ok(b) => Ok(b.len() as i64),
        Err(_) => Err(()),
    }
}

/// Port of `swift.common.http.is_success`: a 2xx status.
fn is_success(status: u16) -> bool {
    (200..300).contains(&status)
}

/// Port of Python `str.isdigit()` for the ASCII case: a non-empty string
/// whose characters are all decimal digits. (Python also accepts a handful
/// of Unicode digit code points; quota values are ASCII in practice.)
fn is_digit_str(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// `400 Bad Request` with swob's `HTTPBadRequest(body=...)` shape: the body
/// is exactly the message, content-type `text/html`.
fn bad_request(message: &str) -> Response {
    let mut resp = Response::with_body(400, message);
    resp.headers.set("Content-Type", "text/html; charset=UTF-8");
    resp
}

/// `413 Request Entity Too Large` with swob's
/// `HTTPRequestEntityTooLarge(body='Upload exceeds quota.')` shape.
fn upload_exceeds_quota() -> Response {
    let mut resp = Response::with_body(413, "Upload exceeds quota.");
    resp.headers.set("Content-Type", "text/html; charset=UTF-8");
    resp
}

/// Middleware that enforces `X-Container-Meta-Quota-Bytes` /
/// `X-Container-Meta-Quota-Count` on object `PUT`s.
#[derive(Default)]
pub struct ContainerQuotas;

impl ContainerQuotas {
    pub fn new() -> Self {
        ContainerQuotas
    }
}

impl Middleware for ContainerQuotas {
    fn handle(&self, mut req: Request, next: &NextFn) -> Response {
        // req.split_path(3, 4, True); a ValueError (bad/short path) means
        // this is not an object or container request we police -> pass through.
        let parts = match split_path(&req.path, 3, 4, true) {
            Ok(p) => p,
            Err(_) => return next(req),
        };
        // [version, account, container, obj]; obj is None (padded) or "" for
        // a container-level path.
        let version = parts[0].clone().unwrap_or_default();
        let account = parts[1].clone().unwrap_or_default();
        let container = parts[2].clone().unwrap_or_default();
        let obj = parts[3].clone().unwrap_or_default();

        if obj.is_empty() && (req.method == "PUT" || req.method == "POST") {
            // Setting quotas on the container: verify the new values are
            // properly formatted (Python: `if val and not val.isdigit()`).
            if let Some(val) = req.headers.get("X-Container-Meta-Quota-Bytes") {
                if !val.is_empty() && !is_digit_str(val) {
                    return bad_request("Invalid bytes quota.");
                }
            }
            if let Some(val) = req.headers.get("X-Container-Meta-Quota-Count") {
                if !val.is_empty() && !is_digit_str(val) {
                    return bad_request("Invalid count quota.");
                }
            }
        } else if !obj.is_empty() && req.method == "PUT" {
            // Uploading an object: check it against the container's quotas.
            // HEAD the container with the caller's auth headers (clone_head),
            // standing in for `get_container_info` / make_subrequest.
            let info = {
                let mut sub = req.clone_head();
                sub.method = "HEAD".into();
                sub.path = format!("/{version}/{account}/{container}");
                sub.query_string = String::new();
                sub.headers.remove("Content-Length");
                next(sub)
            };
            if !is_success(info.status) {
                // No usable container info; let the real request 404 later.
                return next(req);
            }

            // Byte quota: enforced only when the container carries a digit
            // `quota-bytes` meta value and a usable `bytes` figure.
            if let (Some(quota), Some(used)) = (
                info.headers.get("X-Container-Meta-Quota-Bytes"),
                info.headers.get("X-Container-Bytes-Used"),
            ) {
                if is_digit_str(quota) {
                    if let (Ok(quota), Ok(used)) = (quota.parse::<i64>(), used.parse::<i64>()) {
                        let remaining = (quota - used).max(0) as u64;
                        // Cap materialize at remaining+1 so an oversize
                        // chunked body (e.g. HAProxy) trips Err → 413.
                        let cap = remaining.saturating_add(1).max(1);
                        let content_length = match request_content_length(&mut req, cap) {
                            Ok(n) => n,
                            Err(()) => return upload_exceeds_quota(),
                        };
                        let new_size = used + content_length;
                        if quota < new_size {
                            return upload_exceeds_quota();
                        }
                    }
                }
            }

            // Object-count quota: enforced only when the container carries a
            // digit `quota-count` meta value and a usable `object_count`.
            if let (Some(quota), Some(count)) = (
                info.headers.get("X-Container-Meta-Quota-Count"),
                info.headers.get("X-Container-Object-Count"),
            ) {
                if is_digit_str(quota) {
                    if let (Ok(quota), Ok(count)) = (quota.parse::<i64>(), count.parse::<i64>()) {
                        let new_count = count + 1;
                        if quota < new_count {
                            return upload_exceeds_quota();
                        }
                    }
                }
            }
        }

        next(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use swift_http::HeaderKeyDict;

    /// Records every `(method, path)` that reaches the fake backend, so a
    /// test can prove whether the container HEAD subrequest was issued.
    type Log = Arc<Mutex<Vec<(String, String)>>>;

    /// A canned container HEAD response with the given status and headers.
    fn container_head(status: u16, headers: &[(&str, &str)]) -> Response {
        let mut resp = Response::new(status);
        for (k, v) in headers {
            resp.headers.set(k, v);
        }
        resp
    }

    /// Build a fake `next`: it logs each call, answers a `HEAD` (the quota
    /// subrequest) with `head`, and answers anything else (the real request
    /// reaching the app) with `201 Created`. The canned head is torn into
    /// Sync parts (a `Body` reader is only `Send`) and re-issued per call.
    fn backend(head: Response) -> (Log, crate::NextFn) {
        let log: Log = Arc::new(Mutex::new(Vec::new()));
        let log2 = log.clone();
        let (head_status, head_headers) = (head.status, head.headers);
        let next: crate::NextFn = Arc::new(move |req: Request| {
            log2.lock()
                .unwrap()
                .push((req.method.clone(), req.path.clone()));
            if req.method == "HEAD" {
                let mut resp = Response::new(head_status);
                resp.headers = head_headers.clone();
                resp
            } else {
                Response::with_body(201, b"Created".to_vec())
            }
        });
        (log, next)
    }

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

    /// The returned body is materialized so assertions can read it in place.
    fn run(req: Request, head: Response) -> (Response, Log) {
        let cq = ContainerQuotas::new();
        let (log, next) = backend(head);
        let mut resp = cq.handle(req, &next);
        resp.body.materialize(u64::MAX).unwrap();
        (resp, log)
    }

    /// Test bodies are always buffered once `run` has materialized them.
    fn body_bytes(resp: &Response) -> &[u8] {
        match &resp.body {
            swift_http::Body::Buffered(b) => b,
            swift_http::Body::Streamed(_) | swift_http::Body::Channel(_) => unreachable!(),
        }
    }

    fn assert_created(resp: &Response) {
        assert_eq!(resp.status, 201);
        assert_eq!(body_bytes(resp), b"Created");
    }

    // ---- container PUT/POST: quota-header validation ----------------------

    #[test]
    fn test_set_valid_quota_passes() {
        // A well-formed quota value on a container PUT passes straight through
        // with no subrequest.
        let (resp, log) = run(
            mk(
                "PUT",
                "/v1/a/c",
                &[
                    ("X-Container-Meta-Quota-Bytes", "1000"),
                    ("X-Container-Meta-Quota-Count", "5"),
                ],
            ),
            container_head(204, &[]),
        );
        assert_created(&resp);
        assert_eq!(
            log.lock().unwrap().as_slice(),
            &[("PUT".into(), "/v1/a/c".into())]
        );
    }

    #[test]
    fn test_set_invalid_bytes_quota_rejected() {
        let (resp, log) = run(
            mk("PUT", "/v1/a/c", &[("X-Container-Meta-Quota-Bytes", "1TB")]),
            container_head(204, &[]),
        );
        assert_eq!(resp.status, 400);
        assert_eq!(
            String::from_utf8_lossy(body_bytes(&resp)),
            "Invalid bytes quota."
        );
        // rejected before ever reaching the backend
        assert!(log.lock().unwrap().is_empty());
    }

    #[test]
    fn test_set_invalid_count_quota_rejected_on_post() {
        let (resp, _log) = run(
            mk("POST", "/v1/a/c", &[("X-Container-Meta-Quota-Count", "-1")]),
            container_head(204, &[]),
        );
        assert_eq!(resp.status, 400);
        assert_eq!(
            String::from_utf8_lossy(body_bytes(&resp)),
            "Invalid count quota."
        );
    }

    #[test]
    fn test_empty_quota_header_is_not_validated() {
        // An empty value is falsy in Python (`if val and ...`), so it is
        // allowed through (it clears the quota).
        let (resp, _log) = run(
            mk("PUT", "/v1/a/c", &[("X-Container-Meta-Quota-Bytes", "")]),
            container_head(204, &[]),
        );
        assert_created(&resp);
    }

    // ---- object PUT: quota enforcement -----------------------------------

    #[test]
    fn test_object_put_under_bytes_quota_passes() {
        // quota 1000, used 8, +5 = 13 <= 1000 -> allowed.
        let (resp, log) = run(
            mk("PUT", "/v1/a/c/o", &[("Content-Length", "5")]),
            container_head(
                204,
                &[
                    ("X-Container-Meta-Quota-Bytes", "1000"),
                    ("X-Container-Bytes-Used", "8"),
                ],
            ),
        );
        assert_created(&resp);
        // the HEAD subrequest was made, then the real PUT
        assert_eq!(
            log.lock().unwrap().as_slice(),
            &[
                ("HEAD".into(), "/v1/a/c".into()),
                ("PUT".into(), "/v1/a/c/o".into()),
            ]
        );
    }

    #[test]
    fn test_object_put_over_bytes_quota_rejected() {
        // quota 10, used 8, +5 = 13 > 10 -> 413, and the real PUT never runs.
        let (resp, log) = run(
            mk("PUT", "/v1/a/c/o", &[("Content-Length", "5")]),
            container_head(
                204,
                &[
                    ("X-Container-Meta-Quota-Bytes", "10"),
                    ("X-Container-Bytes-Used", "8"),
                ],
            ),
        );
        assert_eq!(resp.status, 413);
        assert_eq!(
            String::from_utf8_lossy(body_bytes(&resp)),
            "Upload exceeds quota."
        );
        // only the HEAD subrequest happened; the object PUT was blocked
        assert_eq!(
            log.lock().unwrap().as_slice(),
            &[("HEAD".into(), "/v1/a/c".into())]
        );
    }

    #[test]
    fn test_object_put_at_bytes_quota_boundary_passes() {
        // quota 13, used 8, +5 = 13; rejection is strict `<`, so equal passes.
        let (resp, _log) = run(
            mk("PUT", "/v1/a/c/o", &[("Content-Length", "5")]),
            container_head(
                204,
                &[
                    ("X-Container-Meta-Quota-Bytes", "13"),
                    ("X-Container-Bytes-Used", "8"),
                ],
            ),
        );
        assert_created(&resp);
    }

    #[test]
    fn test_object_put_no_content_length_defaults_zero() {
        // No Content-Length -> counts as 0 bytes; used 8 <= quota 8 passes.
        let (resp, _log) = run(
            mk("PUT", "/v1/a/c/o", &[]),
            container_head(
                204,
                &[
                    ("X-Container-Meta-Quota-Bytes", "8"),
                    ("X-Container-Bytes-Used", "8"),
                ],
            ),
        );
        assert_created(&resp);
    }

    #[test]
    fn test_object_put_over_count_quota_rejected() {
        // quota-count 1, object_count 1, +1 = 2 > 1 -> 413.
        let (resp, _log) = run(
            mk("PUT", "/v1/a/c/o", &[("Content-Length", "1")]),
            container_head(
                204,
                &[
                    ("X-Container-Meta-Quota-Count", "1"),
                    ("X-Container-Object-Count", "1"),
                ],
            ),
        );
        assert_eq!(resp.status, 413);
        assert_eq!(
            String::from_utf8_lossy(body_bytes(&resp)),
            "Upload exceeds quota."
        );
    }

    #[test]
    fn test_object_put_under_count_quota_passes() {
        // quota-count 5, object_count 1, +1 = 2 <= 5 -> allowed.
        let (resp, _log) = run(
            mk("PUT", "/v1/a/c/o", &[("Content-Length", "1")]),
            container_head(
                204,
                &[
                    ("X-Container-Meta-Quota-Count", "5"),
                    ("X-Container-Object-Count", "1"),
                ],
            ),
        );
        assert_created(&resp);
    }

    #[test]
    fn test_non_digit_quota_meta_not_enforced() {
        // A stored quota that is not all-digits is ignored (matches the
        // `.isdigit()` guard), so the upload is allowed.
        let (resp, _log) = run(
            mk("PUT", "/v1/a/c/o", &[("Content-Length", "9999")]),
            container_head(
                204,
                &[
                    ("X-Container-Meta-Quota-Bytes", "unlimited"),
                    ("X-Container-Bytes-Used", "8"),
                ],
            ),
        );
        assert_created(&resp);
    }

    #[test]
    fn test_no_quota_set_passes() {
        // Container has no quota meta at all -> object PUT allowed.
        let (resp, log) = run(
            mk("PUT", "/v1/a/c/o", &[("Content-Length", "9999")]),
            container_head(204, &[("X-Container-Bytes-Used", "8")]),
        );
        assert_created(&resp);
        // the HEAD subrequest still ran (to learn there was no quota)
        assert_eq!(
            log.lock().unwrap().first(),
            Some(&("HEAD".into(), "/v1/a/c".into()))
        );
    }

    #[test]
    fn test_container_head_failure_passes_through() {
        // The container HEAD is a 404 -> no usable info -> let the real
        // request proceed (it will 404 downstream).
        let (resp, log) = run(
            mk("PUT", "/v1/a/c/o", &[("Content-Length", "9999")]),
            container_head(
                404,
                &[
                    ("X-Container-Meta-Quota-Bytes", "10"),
                    ("X-Container-Bytes-Used", "0"),
                ],
            ),
        );
        assert_created(&resp);
        assert_eq!(
            log.lock().unwrap().as_slice(),
            &[
                ("HEAD".into(), "/v1/a/c".into()),
                ("PUT".into(), "/v1/a/c/o".into()),
            ]
        );
    }

    #[test]
    fn test_object_get_makes_no_subrequest() {
        // A non-PUT method is not policed: no HEAD subrequest, straight pass.
        let (resp, log) = run(
            mk("GET", "/v1/a/c/o", &[]),
            container_head(
                204,
                &[
                    ("X-Container-Meta-Quota-Bytes", "1"),
                    ("X-Container-Bytes-Used", "9999"),
                ],
            ),
        );
        assert_created(&resp);
        assert_eq!(
            log.lock().unwrap().as_slice(),
            &[("GET".into(), "/v1/a/c/o".into())]
        );
    }

    #[test]
    fn test_bad_path_passes_through() {
        // Too few segments for split_path(3, 4) (account-only path) -> the
        // ValueError branch -> pass through untouched, no subrequest.
        let (resp, log) = run(mk("PUT", "/v1/a", &[]), container_head(204, &[]));
        assert_created(&resp);
        assert_eq!(
            log.lock().unwrap().as_slice(),
            &[("PUT".into(), "/v1/a".into())]
        );
    }
}
