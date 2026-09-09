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
//! Hyper path: production serve is `prepare` → app and never calls
//! `handle()`. Container `PUT`/`POST` quota-header validation is
//! `prepare` (invalid → `ShortCircuit` 400) so admin/reseller set still
//! reaches the app. Object `PUT` enforcement is a streaming intercept
//! (`streams_request` + `handle_streaming_request`) so Hyper does not
//! materialize `MAX_CONTROL_BODY` on every upload. `intercepts_request` +
//! `handle_request_async` cover the same object `PUT` when
//! `dispatch_remaining` (COPY dest) never consults `streams_request`.
//! Over-quota object `PUT` is `413` with body `Upload exceeds quota.` —
//! the `test_container_quota_bytes` shape (PUT 11B after a 10-byte quota).
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

use std::future::Future;
use std::pin::Pin;

use swift_http::{split_path, AsyncRequest, IncomingBody, Request, Response};

use crate::{AsyncNextFn, Middleware, MwPrep, NextFn, StreamingAsyncNextFn};

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

/// `(version, account, container, obj)` from `split_path(3, 4, True)`.
fn request_parts(req: &Request) -> Option<(String, String, String, String)> {
    let parts = split_path(&req.path, 3, 4, true).ok()?;
    Some((
        parts[0].clone().unwrap_or_default(),
        parts[1].clone().unwrap_or_default(),
        parts[2].clone().unwrap_or_default(),
        parts[3].clone().unwrap_or_default(),
    ))
}

fn is_container_write(req: &Request) -> bool {
    matches!(req.method.as_str(), "PUT" | "POST")
        && matches!(request_parts(req), Some((_, _, container, obj))
            if !container.is_empty() && obj.is_empty())
}

fn is_object_put(req: &Request) -> bool {
    req.method == "PUT"
        && matches!(request_parts(req), Some((_, _, container, obj))
            if !container.is_empty() && !obj.is_empty())
}

/// Setting quotas on the container: verify the new values are
/// properly formatted (Python: `if val and not val.isdigit()`).
fn validate_quota_headers(req: &Request) -> Result<(), Response> {
    if let Some(val) = req.headers.get("X-Container-Meta-Quota-Bytes") {
        if !val.is_empty() && !is_digit_str(val) {
            return Err(bad_request("Invalid bytes quota."));
        }
    }
    if let Some(val) = req.headers.get("X-Container-Meta-Quota-Count") {
        if !val.is_empty() && !is_digit_str(val) {
            return Err(bad_request("Invalid count quota."));
        }
    }
    Ok(())
}

fn container_head_request(req: &Request, version: &str, account: &str, container: &str) -> Request {
    let mut sub = req.clone_head();
    sub.method = "HEAD".into();
    sub.path = format!("/{version}/{account}/{container}");
    sub.query_string = String::new();
    sub.headers.remove("Content-Length");
    sub
}

fn container_head_async(
    req: &AsyncRequest,
    version: &str,
    account: &str,
    container: &str,
) -> AsyncRequest {
    let mut headers = req.headers.clone();
    headers.remove("Content-Length");
    AsyncRequest {
        method: "HEAD".into(),
        path: format!("/{version}/{account}/{container}"),
        query_string: String::new(),
        headers,
        body: IncomingBody::from_bytes(Vec::new(), 1),
    }
}

/// Materialize cap for a chunked / unknown-length PUT: remaining quota
/// bytes + 1 so an oversize body trips `Err` → 413.
fn bytes_quota_materialize_cap(info: &Response) -> Option<u64> {
    let quota = info.headers.get("X-Container-Meta-Quota-Bytes")?;
    let used = info.headers.get("X-Container-Bytes-Used")?;
    if !is_digit_str(quota) {
        return None;
    }
    let quota = quota.parse::<i64>().ok()?;
    let used = used.parse::<i64>().ok()?;
    let remaining = (quota - used).max(0) as u64;
    Some(remaining.saturating_add(1).max(1))
}

/// `413` when the upload would breach a digit byte or count quota.
/// `None` means no enforceable quota or still under the limit.
fn reject_if_over_quota(info: &Response, content_length: i64) -> Option<Response> {
    if let (Some(quota), Some(used)) = (
        info.headers.get("X-Container-Meta-Quota-Bytes"),
        info.headers.get("X-Container-Bytes-Used"),
    ) {
        if is_digit_str(quota) {
            if let (Ok(quota), Ok(used)) = (quota.parse::<i64>(), used.parse::<i64>()) {
                if quota < used + content_length {
                    return Some(upload_exceeds_quota());
                }
            }
        }
    }
    if let (Some(quota), Some(count)) = (
        info.headers.get("X-Container-Meta-Quota-Count"),
        info.headers.get("X-Container-Object-Count"),
    ) {
        if is_digit_str(quota) {
            if let (Ok(quota), Ok(count)) = (quota.parse::<i64>(), count.parse::<i64>()) {
                if quota < count + 1 {
                    return Some(upload_exceeds_quota());
                }
            }
        }
    }
    None
}

fn header_content_length(headers: &swift_http::HeaderKeyDict) -> Option<i64> {
    headers
        .get("Content-Length")
        .and_then(|v| v.parse::<i64>().ok())
}

/// Middleware that enforces `X-Container-Meta-Quota-Bytes` /
/// `X-Container-Meta-Quota-Count` on object `PUT`s.
#[derive(Default)]
pub struct ContainerQuotas;

impl ContainerQuotas {
    pub fn new() -> Self {
        ContainerQuotas
    }

    async fn enforce_object_put_async(&self, mut req: Request, next: AsyncNextFn) -> Response {
        let Some((version, account, container, obj)) = request_parts(&req) else {
            return next(req).await;
        };
        if obj.is_empty() {
            return next(req).await;
        }
        let info = next(container_head_request(&req, &version, &account, &container)).await;
        if !is_success(info.status) {
            return next(req).await;
        }
        let cap = bytes_quota_materialize_cap(&info).unwrap_or(1);
        let content_length = match request_content_length(&mut req, cap) {
            Ok(n) => n,
            Err(()) => return upload_exceeds_quota(),
        };
        if let Some(resp) = reject_if_over_quota(&info, content_length) {
            return resp;
        }
        next(req).await
    }

    async fn enforce_object_put_streaming(
        &self,
        mut req: AsyncRequest,
        next: StreamingAsyncNextFn,
    ) -> Response {
        let head = Request {
            method: req.method.clone(),
            path: req.path.clone(),
            query_string: req.query_string.clone(),
            headers: req.headers.clone(),
            body: swift_http::Body::empty(),
        };
        let Some((version, account, container, obj)) = request_parts(&head) else {
            return next(req).await;
        };
        if obj.is_empty() {
            return next(req).await;
        }
        let info = next(container_head_async(&req, &version, &account, &container)).await;
        if !is_success(info.status) {
            return next(req).await;
        }
        let content_length = if let Some(n) = header_content_length(&req.headers) {
            n
        } else if let Some(n) = req.body.content_length() {
            n as i64
        } else if let Some(cap) = bytes_quota_materialize_cap(&info) {
            match req.body.materialize(cap).await {
                Ok(bytes) => {
                    let n = bytes.len() as i64;
                    req.body = IncomingBody::from_bytes(bytes, cap.max(n as u64).max(1));
                    n
                }
                Err(_) => return upload_exceeds_quota(),
            }
        } else {
            0
        };
        if let Some(resp) = reject_if_over_quota(&info, content_length) {
            return resp;
        }
        next(req).await
    }
}

impl Middleware for ContainerQuotas {
    /// Hyper never calls `handle()`. Invalid container quota-set headers
    /// short-circuit here; valid admin/reseller set Continues to the app.
    fn prepare(&self, req: &mut Request) -> MwPrep {
        if is_container_write(req) {
            if let Err(resp) = validate_quota_headers(req) {
                return MwPrep::ShortCircuit(resp);
            }
        }
        MwPrep::Continue
    }

    /// Object PUT so `dispatch_remaining` (COPY dest) still enforces.
    /// Container PUT/POST so Hyper validation matches sync `handle`.
    fn intercepts_request(&self, req: &Request) -> bool {
        is_container_write(req) || is_object_put(req)
    }

    /// Object-sized PUT must not `materialize(MAX_CONTROL_BODY)`.
    fn streams_request(&self, req: &Request) -> bool {
        is_object_put(req)
    }

    fn handle_streaming_request(
        &self,
        req: AsyncRequest,
        next: StreamingAsyncNextFn,
    ) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        Box::pin(async move { self.enforce_object_put_streaming(req, next).await })
    }

    fn handle_request_async(
        &self,
        req: Request,
        next: AsyncNextFn,
    ) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        Box::pin(async move {
            if is_container_write(&req) {
                if let Err(resp) = validate_quota_headers(&req) {
                    return resp;
                }
                return next(req).await;
            }
            if is_object_put(&req) {
                return self.enforce_object_put_async(req, next).await;
            }
            next(req).await
        })
    }

    fn handle(&self, mut req: Request, next: &NextFn) -> Response {
        // req.split_path(3, 4, True); a ValueError (bad/short path) means
        // this is not an object or container request we police -> pass through.
        let Some((version, account, container, obj)) = request_parts(&req) else {
            return next(req);
        };

        if obj.is_empty() && (req.method == "PUT" || req.method == "POST") {
            if let Err(resp) = validate_quota_headers(&req) {
                return resp;
            }
        } else if !obj.is_empty() && req.method == "PUT" {
            // Uploading an object: check it against the container's quotas.
            // HEAD the container with the caller's auth headers (clone_head),
            // standing in for `get_container_info` / make_subrequest.
            let info = next(container_head_request(&req, &version, &account, &container));
            if !is_success(info.status) {
                // No usable container info; let the real request 404 later.
                return next(req);
            }

            if let Some(cap) = bytes_quota_materialize_cap(&info) {
                let content_length = match request_content_length(&mut req, cap) {
                    Ok(n) => n,
                    Err(()) => return upload_exceeds_quota(),
                };
                if let Some(resp) = reject_if_over_quota(&info, content_length) {
                    return resp;
                }
            } else if let Some(resp) = reject_if_over_quota(&info, 0) {
                // Count quota only (no usable bytes quota / Content-Length).
                return resp;
            }
        }

        next(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use swift_http::{HeaderKeyDict, IncomingBody};

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

    fn async_backend(head: Response) -> (Log, crate::AsyncNextFn) {
        let log: Log = Arc::new(Mutex::new(Vec::new()));
        let log2 = log.clone();
        let (head_status, head_headers) = (head.status, head.headers);
        let next: crate::AsyncNextFn = Arc::new(move |req: Request| {
            log2.lock()
                .unwrap()
                .push((req.method.clone(), req.path.clone()));
            let (head_status, head_headers) = (head_status, head_headers.clone());
            Box::pin(async move {
                if req.method == "HEAD" {
                    let mut resp = Response::new(head_status);
                    resp.headers = head_headers;
                    resp
                } else {
                    Response::with_body(201, b"Created".to_vec())
                }
            })
        });
        (log, next)
    }

    fn streaming_backend(head: Response) -> (Log, crate::StreamingAsyncNextFn) {
        let log: Log = Arc::new(Mutex::new(Vec::new()));
        let log2 = log.clone();
        let (head_status, head_headers) = (head.status, head.headers);
        let next: crate::StreamingAsyncNextFn = Arc::new(move |req: AsyncRequest| {
            log2.lock()
                .unwrap()
                .push((req.method.clone(), req.path.clone()));
            let (head_status, head_headers) = (head_status, head_headers.clone());
            Box::pin(async move {
                if req.method == "HEAD" {
                    let mut resp = Response::new(head_status);
                    resp.headers = head_headers;
                    resp
                } else {
                    Response::with_body(201, b"Created".to_vec())
                }
            })
        });
        (log, next)
    }

    fn mk_async(method: &str, path: &str, headers: &[(&str, &str)], body: Vec<u8>) -> AsyncRequest {
        let mut h = HeaderKeyDict::new();
        for (k, v) in headers {
            h.set(k, v);
        }
        AsyncRequest {
            method: method.into(),
            path: path.into(),
            query_string: String::new(),
            headers: h,
            body: IncomingBody::from_bytes(body, u64::MAX),
        }
    }

    async fn run_hyper(req: Request, head: Response) -> (Response, Log) {
        let cq = ContainerQuotas::new();
        let (log, next) = async_backend(head);
        let mut resp = cq.handle_request_async(req, next).await;
        resp.body.materialize(u64::MAX).unwrap();
        (resp, log)
    }

    async fn run_hyper_stream(req: AsyncRequest, head: Response) -> (Response, Log) {
        let cq = ContainerQuotas::new();
        let (log, next) = streaming_backend(head);
        let mut resp = cq.handle_streaming_request(req, next).await;
        resp.body.materialize(u64::MAX).unwrap();
        (resp, log)
    }

    // ---- Hyper path (Field H1: object PUT was 201 because handle()
    // never ran). Shapes match TestContainer.test_container_quota_bytes.

    #[test]
    fn hyper_intercepts_container_write_and_object_put() {
        let cq = ContainerQuotas::new();
        assert!(cq.intercepts_request(&mk("POST", "/v1/a/c", &[])));
        assert!(cq.intercepts_request(&mk("PUT", "/v1/a/c", &[])));
        assert!(cq.intercepts_request(&mk("PUT", "/v1/a/c/o", &[("Content-Length", "11")])));
        assert!(cq.streams_request(&mk("PUT", "/v1/a/c/o", &[("Content-Length", "11")])));
        assert!(!cq.intercepts_request(&mk("GET", "/v1/a/c", &[])));
        assert!(!cq.intercepts_request(&mk("GET", "/v1/a/c/o", &[])));
        assert!(!cq.streams_request(&mk("POST", "/v1/a/c", &[])));
        assert!(
            !cq.intercepts_request(&mk("PUT", "/v1/a", &[])),
            "account PUT is AccountQuotas, not ContainerQuotas"
        );
        assert!(!cq.streams_request(&mk("PUT", "/v1/a/c", &[])));
    }

    #[test]
    fn prepare_rejects_invalid_quota_set_on_hyper() {
        let cq = ContainerQuotas::new();
        let mut req = mk(
            "POST",
            "/v1/a/c",
            &[("X-Container-Meta-Quota-Bytes", "1TB")],
        );
        match cq.prepare(&mut req) {
            crate::MwPrep::ShortCircuit(resp) => {
                assert_eq!(resp.status, 400);
            }
            crate::MwPrep::Continue => panic!("invalid quota set must ShortCircuit 400"),
        }
    }

    #[test]
    fn prepare_allows_admin_quota_set() {
        let cq = ContainerQuotas::new();
        let mut req = mk("POST", "/v1/a/c", &[("X-Container-Meta-Quota-Bytes", "10")]);
        assert!(matches!(cq.prepare(&mut req), crate::MwPrep::Continue));
    }

    #[tokio::test]
    async fn hyper_object_put_over_quota_bytes_is_413() {
        // test_container_quota_bytes: quota 10, PUT 11B → 413 not 201.
        let (resp, log) = run_hyper(
            mk("PUT", "/v1/a/c/o", &[("Content-Length", "11")]),
            container_head(
                204,
                &[
                    ("X-Container-Meta-Quota-Bytes", "10"),
                    ("X-Container-Bytes-Used", "0"),
                ],
            ),
        )
        .await;
        assert_eq!(
            resp.status, 413,
            "over-quota object PUT must be 413, got {}",
            resp.status
        );
        assert_eq!(
            String::from_utf8_lossy(body_bytes(&resp)),
            "Upload exceeds quota."
        );
        assert_eq!(
            log.lock().unwrap().as_slice(),
            &[("HEAD".into(), "/v1/a/c".into())]
        );
    }

    #[tokio::test]
    async fn hyper_stream_object_put_over_quota_bytes_is_413() {
        let body = vec![b'x'; 11];
        let (resp, log) = run_hyper_stream(
            mk_async("PUT", "/v1/a/c/o", &[("Content-Length", "11")], body),
            container_head(
                204,
                &[
                    ("X-Container-Meta-Quota-Bytes", "10"),
                    ("X-Container-Bytes-Used", "0"),
                ],
            ),
        )
        .await;
        assert_eq!(resp.status, 413);
        assert_eq!(
            String::from_utf8_lossy(body_bytes(&resp)),
            "Upload exceeds quota."
        );
        assert_eq!(
            log.lock().unwrap().as_slice(),
            &[("HEAD".into(), "/v1/a/c".into())]
        );
    }

    #[tokio::test]
    async fn hyper_object_put_at_quota_bytes_passes() {
        let (resp, log) = run_hyper(
            mk("PUT", "/v1/a/c/o", &[("Content-Length", "10")]),
            container_head(
                204,
                &[
                    ("X-Container-Meta-Quota-Bytes", "10"),
                    ("X-Container-Bytes-Used", "0"),
                ],
            ),
        )
        .await;
        assert_created(&resp);
        assert_eq!(
            log.lock().unwrap().as_slice(),
            &[
                ("HEAD".into(), "/v1/a/c".into()),
                ("PUT".into(), "/v1/a/c/o".into()),
            ]
        );
    }

    #[tokio::test]
    async fn hyper_admin_can_set_container_quota_bytes() {
        let (resp, log) = run_hyper(
            mk("POST", "/v1/a/c", &[("X-Container-Meta-Quota-Bytes", "10")]),
            container_head(204, &[]),
        )
        .await;
        assert_created(&resp);
        assert_eq!(
            log.lock().unwrap().as_slice(),
            &[("POST".into(), "/v1/a/c".into())]
        );
    }

    #[tokio::test]
    async fn hyper_invalid_quota_set_is_400() {
        let (resp, log) = run_hyper(
            mk("PUT", "/v1/a/c", &[("X-Container-Meta-Quota-Bytes", "1TB")]),
            container_head(204, &[]),
        )
        .await;
        assert_eq!(resp.status, 400);
        assert_eq!(
            String::from_utf8_lossy(body_bytes(&resp)),
            "Invalid bytes quota."
        );
        assert!(log.lock().unwrap().is_empty());
    }
}
