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

//! `account_quotas`: blocks write requests (`PUT`/`POST`) that would push an
//! account over a configured byte or object-count quota, a port of
//! `swift/common/middleware/account_quotas.py`. `DELETE` is always allowed.
//!
//! Quotas live in account (sys)metadata, populated by resellers:
//! `X-Account-Quota-Bytes` / `-Count` (and the obsolete
//! `X-Account-Meta-Quota-Bytes`) for the whole account, and
//! `X-Account-Quota-Bytes-Policy-<name>` / `-Count-Policy-<name>` per storage
//! policy. These are stored as `X-Account-Sysmeta-...` and only resellers may
//! set them.
//!
//! On an object `PUT` the middleware HEADs the account (and, for the
//! per-policy checks, the container) as **backend subrequests** to read the
//! current usage, then rejects with `413 Request Entity Too Large` and the
//! body `Upload exceeds quota.` (or `Upload exceeds policy quota.`) when the
//! new object would breach a quota. This is the Rust stand-in for Swift's
//! `get_account_info` / `get_container_info`: instead of a cached
//! `make_subrequest(env)`, the effective `next` handler is called with a
//! freshly-built `HEAD` `Request` and the returned `Response`'s headers are
//! parsed exactly as `headers_to_account_info` / `headers_to_container_info`
//! would parse a backend HEAD.
//!
//! Deferrals (faithful in behaviour, different in mechanism):
//! - `reseller_request` is sourced from the `X-Backend-Reseller-Request`
//!   request header (coerced by `config_true_value`) rather than the WSGI
//!   `environ['reseller_request']` flag. This mirrors `read_only`'s header
//!   stand-in; `gatekeeper` forbids clients from forging any `X-Backend-*`
//!   header, so the boundary is preserved.
//! - `quota_exceeded`'s `swift.authorize` delayed-denial wrapping (which lets
//!   a container-ACL check run first) is not ported: there is no authorize
//!   hook in this pipeline, so an over-quota write is rejected immediately
//!   with the 413 -- the equivalent of swob's `else: return resp` branch.
//! - account/container info caching (memcache + `swift.infocache`) is not
//!   modelled; every enforcement issues live HEAD subrequests. The account
//!   info `status` / `account_really_exists` fields and the
//!   valid-API-version short-circuit are likewise not modelled: absent usage
//!   or quota headers default to `0` / "no quota", which yields the same
//!   "no quota enforced" outcome a 0/503 info dict would.
//! - swob raises `400` on a malformed `Content-Length`; here it defaults to
//!   `0` (`request.content_length or 0`).
//! - `filter_factory` / `register_swift_info` are not ported.

use swift_core::config::config_true_value;
use swift_core::storage_policy::StoragePolicyCollection;

use swift_http::{split_path, Request, Response};

use crate::{Middleware, NextFn};

/// Account quota middleware. Holds the cluster's storage policies (Swift's
/// global `POLICIES`) so per-policy usage headers, which are keyed by policy
/// *name*, can be resolved from a policy *index*.
pub struct AccountQuotas {
    policies: StoragePolicyCollection,
}

impl AccountQuotas {
    pub fn new(policies: StoragePolicyCollection) -> Self {
        AccountQuotas { policies }
    }

    /// Whether this is a reseller request. See the module deferral note: the
    /// value is taken from the backend header `X-Backend-Reseller-Request`
    /// rather than `environ['reseller_request']`.
    fn is_reseller(&self, req: &Request) -> bool {
        req.headers
            .get("X-Backend-Reseller-Request")
            .map(config_true_value)
            .unwrap_or(false)
    }

    /// `413 Request Entity Too Large` with swob's `body=...` shape: the body
    /// is exactly the message, content-type `text/html`.
    fn quota_exceeded(body: &str) -> Response {
        let mut resp = Response::with_body(413, body);
        resp.headers.set("Content-Type", "text/html; charset=UTF-8");
        resp
    }

    /// Handle a bare account request (no container). On `POST`/`PUT` migrate
    /// the legacy `-Meta-` headers and validate/translate any quota-set
    /// headers (resellers only); then, on the response, expose the stored
    /// `X-Account-Sysmeta-*` quotas as public `X-Account-*` headers.
    fn handle_account(&self, mut req: Request, next: &NextFn) -> Response {
        if req.method == "POST" || req.method == "PUT" {
            // Support old meta format: copy `X-Account-Meta-Quota-Bytes`
            // (and its X-Remove twin) into the modern header when the modern
            // header is not already set.
            for (legacy, modern) in [
                ("X-Account-Meta-Quota-Bytes", "X-Account-Quota-Bytes"),
                (
                    "X-Remove-Account-Meta-Quota-Bytes",
                    "X-Remove-Account-Quota-Bytes",
                ),
            ] {
                if let Some(value) = req.headers.get(legacy).map(str::to_string) {
                    let modern_falsy = req.headers.get(modern).is_none_or(str::is_empty);
                    if modern_falsy {
                        req.headers.set(modern, value);
                    }
                }
            }
            if let Err(resp) = self.validate_and_translate_quotas(&mut req, "Quota-Bytes") {
                return resp;
            }
            if let Err(resp) = self.validate_and_translate_quotas(&mut req, "Quota-Count") {
                return resp;
            }
        }

        let mut resp = next(req);

        // Non-resellers can't update quotas, but they *can* see them. Global
        // quotas first.
        for postfix in ["Quota-Bytes", "Quota-Count"] {
            let value = resp
                .headers
                .get(&format!("X-Account-Sysmeta-{postfix}"))
                .filter(|v| !v.is_empty())
                .map(str::to_string);
            if let Some(value) = value {
                resp.headers.set(&format!("X-Account-{postfix}"), value);
            }
        }
        // Per-policy quotas: sysmeta keyed by index, exposed keyed by name.
        for policy in self.policies.iter() {
            for infix in ["Quota-Bytes-Policy", "Quota-Count-Policy"] {
                let value = resp
                    .headers
                    .get(&format!("X-Account-Sysmeta-{infix}-{}", policy.idx()))
                    .filter(|v| !v.is_empty())
                    .map(str::to_string);
                if let Some(value) = value {
                    resp.headers
                        .set(&format!("X-Account-{infix}-{}", policy.name()), value);
                }
            }
        }
        resp
    }

    /// Port of `validate_and_translate_quotas`. Reads the public quota-set
    /// headers off `req`, and for resellers rewrites them into
    /// `X-Account-Sysmeta-*`; for non-resellers any attempt to set a quota is
    /// rejected. `Err(resp)` carries the rejection (`400`/`403`).
    fn validate_and_translate_quotas(
        &self,
        req: &mut Request,
        quota_type: &str,
    ) -> Result<(), Response> {
        // (policy index or None for the global quota, requested value).
        // `None` value == header absent; `Some("")` == explicit removal.
        let mut new_quotas: Vec<(Option<u32>, Option<String>)> = Vec::new();

        let mut global = req
            .headers
            .get(&format!("X-Account-{quota_type}"))
            .map(str::to_string);
        if req
            .headers
            .get(&format!("X-Remove-Account-{quota_type}"))
            .is_some_and(|v| !v.is_empty())
        {
            global = Some(String::new()); // X-Remove dominates if both are present
        }
        new_quotas.push((None, global));

        // Collect policy names first to avoid borrowing self while mutating
        // req.headers below.
        let policies: Vec<(u32, String)> = self
            .policies
            .iter()
            .map(|p| (p.idx(), p.name().to_string()))
            .collect();
        for (idx, name) in &policies {
            let tail = format!("Account-{quota_type}-Policy-{name}");
            if req
                .headers
                .get(&format!("X-Remove-{tail}"))
                .is_some_and(|v| !v.is_empty())
            {
                new_quotas.push((Some(*idx), Some(String::new())));
            } else {
                let quota = req.headers.remove(&format!("X-{tail}"));
                new_quotas.push((Some(*idx), quota));
            }
        }

        if self.is_reseller(req) {
            // A set (non-empty) quota must be all digits.
            let bad = new_quotas.iter().any(|(_, quota)| {
                quota
                    .as_deref()
                    .is_some_and(|q| !q.is_empty() && !q.bytes().all(|b| b.is_ascii_digit()))
            });
            if bad {
                return Err(Self::bad_request());
            }
            for (idx, quota) in &new_quotas {
                let hdr = match idx {
                    None => format!("X-Account-Sysmeta-{quota_type}"),
                    Some(i) => format!("X-Account-Sysmeta-{quota_type}-Policy-{i}"),
                };
                match quota {
                    // Python `headers[hdr] = quota` where `quota is None`
                    // deletes the header.
                    Some(value) => req.headers.set(&hdr, value),
                    None => {
                        req.headers.remove(&hdr);
                    }
                }
            }
        } else if new_quotas.iter().any(|(_, quota)| quota.is_some()) {
            // deny quota set for non-reseller
            return Err(Self::forbidden());
        }
        Ok(())
    }

    /// swob `HTTPBadRequest()` (no explicit body).
    fn bad_request() -> Response {
        Response::error(
            400,
            "The server could not comply with the request since it is either \
             malformed or otherwise incorrect.",
        )
    }

    /// swob `HTTPForbidden()` (no explicit body).
    fn forbidden() -> Response {
        Response::error(403, "Access was denied to this resource.")
    }

    /// Per-policy usage from the account HEAD response. `suffix` is
    /// `"Bytes-Used"` or `"Object-Count"`. Unknown policy index -> `0`, as
    /// `storage_policies.get(idx, {})` would yield an empty dict.
    fn policy_usage(&self, acct: &Response, policy_idx: i64, suffix: &str) -> i64 {
        let name = match u32::try_from(policy_idx)
            .ok()
            .and_then(|i| self.policies.get_by_index_num(i))
        {
            Some(p) => p.name().to_string(),
            None => return 0,
        };
        header_int(
            acct,
            &format!("X-Account-Storage-Policy-{name}-{suffix}"),
            0,
        )
    }
}

/// Parse an integer header value the way `int(headers.get(k, default))`
/// would: whitespace-trimmed, `default` when the header is absent or the
/// value does not parse.
fn header_int(resp: &Response, name: &str, default: i64) -> i64 {
    resp.headers
        .get(name)
        .and_then(|v| v.trim().parse::<i64>().ok())
        .unwrap_or(default)
}

impl Middleware for AccountQuotas {
    fn handle(&self, req: Request, next: &NextFn) -> Response {
        // split_path(2, 4, rest_with_last=True); a ValueError just passes the
        // request through untouched.
        let parts = match split_path(&req.path, 2, 4, true) {
            Ok(parts) => parts,
            Err(_) => return next(req),
        };
        let version = parts[0].clone().unwrap_or_default();
        let account = parts[1].clone().unwrap_or_default();
        let container = parts[2].clone().unwrap_or_default();
        let obj = parts[3].clone().unwrap_or_default();

        if container.is_empty() {
            return self.handle_account(req, next);
        }
        // container or object request; even if the quota headers are set in
        // the request, they're meaningless

        if req.method != "PUT" || obj.is_empty() {
            return next(req);
        }
        // OK, object PUT

        if self.is_reseller(&req) {
            // but resellers aren't constrained by quotas :-)
            return next(req);
        }

        let content_length = header_int_from_req(&req, "Content-Length", 0);

        // ---- Subrequest 1: HEAD the account for current usage/quotas. ----
        let acct_resp = {
            let mut sub = req.clone_head();
            sub.method = "HEAD".into();
            sub.path = format!("/{version}/{account}");
            sub.query_string = String::new();
            sub.headers.remove("Content-Length");
            sub.headers.set("X-Backend-Allow-Reserved-Names", "true");
            next(sub)
        };

        // Check for quota byte violation. sysmeta wins over legacy meta; a
        // present-but-unparseable value is treated as "no quota" (-1).
        let quota = acct_resp
            .headers
            .get("X-Account-Sysmeta-Quota-Bytes")
            .or_else(|| acct_resp.headers.get("X-Account-Meta-Quota-Bytes"))
            .and_then(|v| v.trim().parse::<i64>().ok())
            .unwrap_or(-1);
        if quota >= 0 {
            let new_size = header_int(&acct_resp, "X-Account-Bytes-Used", 0) + content_length;
            if quota < new_size {
                return Self::quota_exceeded("Upload exceeds quota.");
            }
        }

        // Check for quota count violation.
        let quota = header_int(&acct_resp, "X-Account-Sysmeta-Quota-Count", -1);
        if quota >= 0 {
            let new_count = header_int(&acct_resp, "X-Account-Object-Count", 0) + 1;
            if quota < new_count {
                return Self::quota_exceeded("Upload exceeds quota.");
            }
        }

        // ---- Subrequest 2: HEAD the container for its storage policy. ----
        let cont_resp = {
            let mut sub = req.clone_head();
            sub.method = "HEAD".into();
            sub.path = format!("/{version}/{account}/{container}");
            sub.query_string = String::new();
            sub.headers.remove("Content-Length");
            sub.headers.set("X-Backend-Allow-Reserved-Names", "true");
            next(sub)
        };
        let policy_idx = header_int(&cont_resp, "X-Backend-Storage-Policy-Index", 0);

        // Check quota-byte per policy.
        let policy_quota = header_int(
            &acct_resp,
            &format!("X-Account-Sysmeta-Quota-Bytes-Policy-{policy_idx}"),
            -1,
        );
        if policy_quota >= 0 {
            let new_size = self.policy_usage(&acct_resp, policy_idx, "Bytes-Used") + content_length;
            if policy_quota < new_size {
                return Self::quota_exceeded("Upload exceeds policy quota.");
            }
        }

        // Check quota-count per policy.
        let policy_quota = header_int(
            &acct_resp,
            &format!("X-Account-Sysmeta-Quota-Count-Policy-{policy_idx}"),
            -1,
        );
        if policy_quota >= 0 {
            let new_count = self.policy_usage(&acct_resp, policy_idx, "Object-Count") + 1;
            if policy_quota < new_count {
                return Self::quota_exceeded("Upload exceeds policy quota.");
            }
        }

        next(req)
    }
}

/// `header_int` for a [`Request`] (the account HEAD reads a [`Response`]; the
/// client's `Content-Length` is read off the request).
fn header_int_from_req(req: &Request, name: &str, default: i64) -> i64 {
    req.headers
        .get(name)
        .and_then(|v| v.trim().parse::<i64>().ok())
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use swift_core::config::SwiftConfig;
    use swift_core::storage_policy::parse_storage_policies;
    use swift_http::HeaderKeyDict;

    // patch_policies default fixture: nulo(0, default), unu(1).
    fn policies() -> StoragePolicyCollection {
        let conf = "[storage-policy:0]\nname = nulo\ndefault = yes\n\
                    [storage-policy:1]\nname = unu\n";
        parse_storage_policies(&SwiftConfig::parse_lenient(conf, &[], false).unwrap()).unwrap()
    }

    fn mw() -> AccountQuotas {
        AccountQuotas::new(policies())
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

    fn resp(status: u16, headers: &[(&str, &str)]) -> Response {
        let mut r = Response::new(status);
        for (k, v) in headers {
            r.headers.set(k, v);
        }
        r
    }

    /// A fake backend: matches a subrequest on `(method, path)` and replays a
    /// canned response; unmatched routes return `200` with body `backend-ok`
    /// (the real PUT/POST landing on the app). Canned responses are torn
    /// into Sync parts (a `Body` reader is only `Send`) and re-issued per
    /// request, so one route can serve many subrequests.
    fn backend(routes: Vec<(&'static str, &'static str, Response)>) -> crate::NextFn {
        let routes: Vec<(&'static str, &'static str, u16, HeaderKeyDict)> = routes
            .into_iter()
            .map(|(m, p, r)| (m, p, r.status, r.headers))
            .collect();
        Arc::new(move |req: Request| {
            for (m, p, status, headers) in &routes {
                if req.method == *m && req.path == *p {
                    let mut out = Response::new(*status);
                    out.headers = headers.clone();
                    return out;
                }
            }
            Response::with_body(200, b"backend-ok".to_vec())
        })
    }

    /// The returned body is materialized so assertions can read it in place.
    fn run(req: Request, next: crate::NextFn) -> Response {
        let mut resp = mw().handle(req, &next);
        resp.body.materialize(u64::MAX).unwrap();
        resp
    }

    /// Test bodies are always buffered once `run` has materialized them.
    fn body_bytes(resp: &Response) -> &[u8] {
        match &resp.body {
            swift_http::Body::Buffered(b) => b,
            swift_http::Body::Streamed(_) => unreachable!(),
        }
    }

    fn assert_passthrough(r: &Response) {
        assert_eq!(r.status, 200);
        assert_eq!(body_bytes(r), b"backend-ok");
    }

    fn assert_over_quota(r: &Response, body: &str) {
        assert_eq!(r.status, 413);
        assert_eq!(String::from_utf8_lossy(body_bytes(r)), body);
    }

    // ---- happy path -------------------------------------------------------

    #[test]
    fn test_no_quota_passes() {
        // Account has usage but no quota metadata: the object PUT sails
        // through after both HEAD subrequests.
        let next = backend(vec![
            ("HEAD", "/v1/a", resp(200, &[("x-account-bytes-used", "1000")])),
            (
                "HEAD",
                "/v1/a/c",
                resp(200, &[("x-backend-storage-policy-index", "1")]),
            ),
        ]);
        assert_passthrough(&run(mk("PUT", "/v1/a/c/o", &[]), next));
    }

    #[test]
    fn test_bogus_quota_ignored() {
        // A non-integer sysmeta quota (e.g. set before the middleware
        // existed) is treated as no quota at all.
        let next = backend(vec![(
            "HEAD",
            "/v1/a",
            resp(
                200,
                &[
                    ("x-account-bytes-used", "1000"),
                    ("x-account-sysmeta-quota-bytes", "pasty-plastogene"),
                ],
            ),
        )]);
        assert_passthrough(&run(mk("PUT", "/v1/a/c/o", &[]), next));
    }

    #[test]
    fn test_under_quota_with_content_length() {
        // 0 used + 1000 quota, uploading 901 bytes: still under.
        let next = backend(vec![(
            "HEAD",
            "/v1/a",
            resp(
                200,
                &[
                    ("x-account-bytes-used", "0"),
                    ("x-account-sysmeta-quota-bytes", "1000"),
                ],
            ),
        )]);
        let req = mk("PUT", "/v1/a/c/o", &[("Content-Length", "901")]);
        assert_passthrough(&run(req, next));
    }

    // ---- account byte quota ----------------------------------------------

    #[test]
    fn test_exceed_bytes_quota() {
        let next = backend(vec![(
            "HEAD",
            "/v1/a",
            resp(
                200,
                &[
                    ("x-account-bytes-used", "1000"),
                    ("x-account-sysmeta-quota-bytes", "0"),
                ],
            ),
        )]);
        assert_over_quota(&run(mk("PUT", "/v1/a/c/o", &[]), next), "Upload exceeds quota.");
    }

    #[test]
    fn test_exceed_bytes_quota_legacy_meta() {
        // The obsolete X-Account-Meta-Quota-Bytes is honoured when no sysmeta
        // quota is present.
        let next = backend(vec![(
            "HEAD",
            "/v1/a",
            resp(
                200,
                &[
                    ("x-account-bytes-used", "1000"),
                    ("x-account-meta-quota-bytes", "0"),
                ],
            ),
        )]);
        assert_over_quota(&run(mk("PUT", "/v1/a/c/o", &[]), next), "Upload exceeds quota.");
    }

    #[test]
    fn test_content_length_counts_against_bytes_quota() {
        // 0 used, quota 10, uploading 100 bytes -> over.
        let next = backend(vec![(
            "HEAD",
            "/v1/a",
            resp(
                200,
                &[
                    ("x-account-bytes-used", "0"),
                    ("x-account-sysmeta-quota-bytes", "10"),
                ],
            ),
        )]);
        let req = mk("PUT", "/v1/a/c/o", &[("Content-Length", "100")]);
        assert_over_quota(&run(req, next), "Upload exceeds quota.");
    }

    // ---- account object-count quota --------------------------------------

    #[test]
    fn test_exceed_count_quota() {
        // 10 objects used, count quota 10: one more would make 11.
        let next = backend(vec![(
            "HEAD",
            "/v1/a",
            resp(
                200,
                &[
                    ("x-account-bytes-used", "100"),
                    ("x-account-object-count", "10"),
                    ("x-account-sysmeta-quota-count", "10"),
                ],
            ),
        )]);
        assert_over_quota(&run(mk("PUT", "/v1/a/c/o", &[]), next), "Upload exceeds quota.");
    }

    // ---- per-policy quotas (needs the policy-name mapping) ----------------

    #[test]
    fn test_exceed_per_policy_bytes_quota() {
        // Container is on policy 1 ("unu"); that policy already holds 100
        // bytes with a per-policy quota of 10. The *global* quota (1000) is
        // fine, so only the policy check trips.
        let next = backend(vec![
            (
                "HEAD",
                "/v1/a",
                resp(
                    200,
                    &[
                        ("x-account-bytes-used", "100"),
                        ("x-account-storage-policy-unu-bytes-used", "100"),
                        ("x-account-sysmeta-quota-bytes-policy-1", "10"),
                        ("x-account-sysmeta-quota-bytes", "1000"),
                    ],
                ),
            ),
            (
                "HEAD",
                "/v1/a/c",
                resp(200, &[("x-backend-storage-policy-index", "1")]),
            ),
        ]);
        assert_over_quota(
            &run(mk("PUT", "/v1/a/c/o", &[]), next),
            "Upload exceeds policy quota.",
        );
    }

    #[test]
    fn test_exceed_per_policy_count_quota() {
        // Policy 1 already holds 5 objects with a per-policy count quota of 5.
        let next = backend(vec![
            (
                "HEAD",
                "/v1/a",
                resp(
                    200,
                    &[
                        ("x-account-bytes-used", "100"),
                        ("x-account-storage-policy-unu-object-count", "5"),
                        ("x-account-sysmeta-quota-count-policy-1", "5"),
                    ],
                ),
            ),
            (
                "HEAD",
                "/v1/a/c",
                resp(200, &[("x-backend-storage-policy-index", "1")]),
            ),
        ]);
        assert_over_quota(
            &run(mk("PUT", "/v1/a/c/o", &[]), next),
            "Upload exceeds policy quota.",
        );
    }

    // ---- pass-through cases ----------------------------------------------

    #[test]
    fn test_reseller_bypasses_quota() {
        // A reseller PUT is never constrained -- no HEAD subrequest is even
        // made (the account HEAD route is absent to prove it is not hit).
        let next = backend(vec![]);
        let req = mk(
            "PUT",
            "/v1/a/c/o",
            &[("X-Backend-Reseller-Request", "true")],
        );
        assert_passthrough(&run(req, next));
    }

    #[test]
    fn test_container_put_ignored() {
        // A container PUT (no object) is not an object write; pass through
        // without HEADing anything.
        let next = backend(vec![]);
        let req = mk("PUT", "/v1/a/c", &[("X-Account-Meta-Quota-Bytes", "99999")]);
        assert_passthrough(&run(req, next));
    }

    #[test]
    fn test_object_get_ignored() {
        // Only PUT is policed; a GET passes straight through.
        let next = backend(vec![]);
        assert_passthrough(&run(mk("GET", "/v1/a/c/o", &[]), next));
    }

    #[test]
    fn test_object_delete_allowed() {
        let next = backend(vec![]);
        assert_passthrough(&run(mk("DELETE", "/v1/a/c/o", &[]), next));
    }

    #[test]
    fn test_bad_path_passes_through() {
        let next = backend(vec![]);
        assert_passthrough(&run(mk("PUT", "/v1", &[]), next));
    }

    // ---- account handling (quota display + reseller set) ------------------

    #[test]
    fn test_account_response_exposes_sysmeta_quotas() {
        // A GET of the account: the stored sysmeta quotas are surfaced as
        // public X-Account-* headers, per-policy ones keyed by policy name.
        let next = backend(vec![(
            "GET",
            "/v1/a",
            resp(
                200,
                &[
                    ("x-account-bytes-used", "100"),
                    ("x-account-sysmeta-quota-bytes", "1000"),
                    ("x-account-sysmeta-quota-bytes-policy-1", "10"),
                ],
            ),
        )]);
        let r = run(mk("GET", "/v1/a", &[]), next);
        assert_eq!(r.status, 200);
        assert_eq!(r.headers.get("X-Account-Quota-Bytes"), Some("1000"));
        assert_eq!(r.headers.get("X-Account-Quota-Bytes-Policy-Unu"), Some("10"));
        // sysmeta is preserved alongside the exposed public header
        assert_eq!(r.headers.get("X-Account-Sysmeta-Quota-Bytes"), Some("1000"));
    }

    #[test]
    fn test_reseller_can_set_quota() {
        // A reseller POST that sets X-Account-Quota-Bytes has it rewritten to
        // the sysmeta header before it reaches the backend. The fake next
        // echoes the request headers it received so we can prove the rewrite.
        let next: Arc<dyn Fn(Request) -> Response + Send + Sync> = Arc::new(|req: Request| {
            let mut r = Response::new(200);
            for (k, v) in req.headers.iter() {
                r.headers.set(&format!("Echo-{k}"), v);
            }
            r
        });
        let req = mk(
            "POST",
            "/v1/a",
            &[
                ("X-Backend-Reseller-Request", "true"),
                ("X-Account-Quota-Bytes", "5000"),
            ],
        );
        let r = run(req, next);
        assert_eq!(r.status, 200);
        assert_eq!(
            r.headers.get("Echo-X-Account-Sysmeta-Quota-Bytes"),
            Some("5000")
        );
    }

    #[test]
    fn test_nonreseller_cannot_set_quota() {
        // A non-reseller attempting to set a quota on the account is 403'd.
        let next = backend(vec![]);
        let req = mk("POST", "/v1/a", &[("X-Account-Quota-Bytes", "5000")]);
        let r = run(req, next);
        assert_eq!(r.status, 403);
    }

    #[test]
    fn test_reseller_rejects_non_numeric_quota() {
        // A reseller sending a non-digit quota value is 400'd.
        let next = backend(vec![]);
        let req = mk(
            "POST",
            "/v1/a",
            &[
                ("X-Backend-Reseller-Request", "true"),
                ("X-Account-Quota-Bytes", "abc"),
            ],
        );
        let r = run(req, next);
        assert_eq!(r.status, 400);
    }

    #[test]
    fn test_object_write_ignores_attempt_to_set_quota() {
        // Setting X-Account-Meta-* on an *object* PUT is meaningless and must
        // not trip the non-reseller guard: it just passes through.
        let next = backend(vec![
            ("HEAD", "/v1/a", resp(200, &[("x-account-bytes-used", "0")])),
            (
                "HEAD",
                "/v1/a/c",
                resp(200, &[("x-backend-storage-policy-index", "0")]),
            ),
        ]);
        let req = mk(
            "PUT",
            "/v1/a/c/o",
            &[("X-Account-Meta-Quota-Bytes", "99999")],
        );
        assert_passthrough(&run(req, next));
    }
}
