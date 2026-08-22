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

//! `read_only`: makes an entire cluster or individual accounts read only,
//! a faithful port of `swift/common/middleware/read_only.py`. When
//! read-only mode is in effect the write methods (`COPY`, `POST`, `PUT`,
//! and `DELETE` unless `allow_deletes` is set) are rejected with `405
//! Method Not Allowed` and the body `Writes are disabled for this
//! account.`. Non-write methods and requests to non-Swift paths (bad
//! path or unknown API version) always pass through.
//!
//! An operator can mark a single account read-only (or, when the cluster
//! is read-only, mark one account writable) with the account sysmeta
//! `X-Account-Sysmeta-Read-Only` (values coerced by `config_true_value`):
//! a non-empty value overrides the cluster-wide `read_only` setting.
//!
//! Deferral: the Python middleware reads that per-account override via
//! `get_info(self.app, ...)`, which consults the account-info cache or
//! issues a backend subrequest. This port sources the override from the
//! request's own `X-Account-Sysmeta-Read-Only` header instead — the value
//! the account-info resolution step populates in the full pipeline, and a
//! header `gatekeeper` forbids clients from forging. Consequently the
//! `COPY` `Destination-Account` branch still resolves and *validates* the
//! destination account (returning `412 Precondition Failed` on a
//! malformed value, as `check_account_format` does), but selecting a
//! *different* account's cached sysmeta for a cross-account COPY is the
//! part that needs `get_info` and is deferred; the effective account's
//! read-only value is taken from the request header. `filter_factory`,
//! `register_swift_info`, and the logger are also not ported.

use swift_core::config::config_true_value;
use swift_core::constraints::{check_account_format, VALID_API_VERSIONS};

use swift_http::{split_path, Request, Response};

use crate::{Middleware, NextFn};

/// Middleware that makes an entire cluster or individual accounts read
/// only.
#[derive(Default)]
pub struct ReadOnly {
    /// When true the whole cluster is read only (config `read_only`).
    pub read_only: bool,
    /// When true, `DELETE` is not treated as a write (config
    /// `allow_deletes`).
    pub allow_deletes: bool,
}

impl ReadOnly {
    pub fn new(read_only: bool, allow_deletes: bool) -> Self {
        ReadOnly {
            read_only,
            allow_deletes,
        }
    }

    /// Build from raw config strings, mirroring `ReadOnlyMiddleware.__init__`:
    /// both values pass through `config_true_value`, and a missing option
    /// is false.
    pub fn from_conf(read_only: Option<&str>, allow_deletes: Option<&str>) -> Self {
        ReadOnly {
            read_only: read_only.map(config_true_value).unwrap_or(false),
            allow_deletes: allow_deletes.map(config_true_value).unwrap_or(false),
        }
    }

    /// Whether `method` counts as a write. `write_methods` is `{COPY,
    /// POST, PUT}`, plus `DELETE` unless `allow_deletes` is set.
    fn is_write_method(&self, method: &str) -> bool {
        matches!(method, "COPY" | "POST" | "PUT") || (!self.allow_deletes && method == "DELETE")
    }

    /// Whether the effective account should be read-only. Considers both
    /// the cluster-wide config value and the per-account override in
    /// `X-Account-Sysmeta-Read-Only`. An empty/absent override falls back
    /// to the cluster value; a non-empty override is coerced by
    /// `config_true_value`.
    ///
    /// `_account` is retained to mirror the Python signature; the override
    /// is sourced from the request header (see the module deferral note)
    /// rather than a per-account `get_info` lookup.
    fn account_read_only(&self, req: &Request, _account: &str) -> bool {
        let read_only = req.headers.get("X-Account-Sysmeta-Read-Only").unwrap_or("");
        if read_only.is_empty() {
            return self.read_only;
        }
        config_true_value(read_only)
    }

    /// `405 Method Not Allowed` with swob's `HTTPMethodNotAllowed(body=...)`
    /// shape: the body is exactly the message, content-type `text/html`.
    fn writes_disabled() -> Response {
        let mut resp = Response::with_body(405, "Writes are disabled for this account.");
        resp.headers.set("Content-Type", "text/html; charset=UTF-8");
        resp
    }
}

impl Middleware for ReadOnly {
    fn handle(&self, req: Request, next: &NextFn) -> Response {
        if !self.is_write_method(&req.method) {
            return next(req);
        }

        // A malformed path or unknown API version is not a Swift write we
        // police -- pass it through (Python catches the ValueError).
        let parts = match split_path(&req.path, 2, 4, true) {
            Ok(parts) => parts,
            Err(_) => return next(req),
        };
        let version = parts[0].as_deref().unwrap_or("");
        if !VALID_API_VERSIONS.contains(&version) {
            return next(req);
        }
        // parts[1] (account) is guaranteed present for minsegs == 2.
        let mut account = parts[1].clone().unwrap_or_default();

        if req.method == "COPY" {
            if let Some(dest_account) = req.headers.get("Destination-Account") {
                match check_account_format(dest_account) {
                    Ok(a) => account = a.to_string(),
                    Err(e) => {
                        // check_account_format raises HTTPPreconditionFailed.
                        let mut resp = Response::with_body(412, e.0);
                        resp.headers.set("Content-Type", "text/html; charset=UTF-8");
                        return resp;
                    }
                }
            }
        }

        if self.account_read_only(&req, &account) {
            return Self::writes_disabled();
        }

        next(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use swift_http::HeaderKeyDict;

    const READ_METHODS: [&str; 2] = ["GET", "HEAD"];
    const WRITE_METHODS: [&str; 4] = ["COPY", "DELETE", "POST", "PUT"];
    const RO_MSG: &str = "Writes are disabled for this account.";

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

    // Innermost app: echoes a fixed body so we can tell a pass-through
    // (200 "Some Content") from a middleware rejection.
    fn content_app() -> Arc<dyn Fn(Request) -> Response + Send + Sync> {
        Arc::new(|_r| Response::with_body(200, b"Some Content".to_vec()))
    }

    /// The returned body is materialized so assertions can read it in place.
    fn run(ro: &ReadOnly, req: Request) -> Response {
        let mut resp = ro.handle(req, &content_app());
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

    fn assert_passthrough(resp: &Response) {
        assert_eq!(resp.status, 200);
        assert_eq!(body_bytes(resp), b"Some Content");
    }

    fn assert_blocked(resp: &Response) {
        assert_eq!(resp.status, 405);
        assert_eq!(String::from_utf8_lossy(body_bytes(resp)), RO_MSG);
    }

    #[test]
    fn test_global_read_only_off() {
        // Cluster off, no per-account override: everything passes.
        let ro = ReadOnly::new(false, false);
        for method in READ_METHODS.iter().chain(WRITE_METHODS.iter()) {
            let resp = run(&ro, mk(method, "/v1/a", &[]));
            assert_passthrough(&resp);
        }
    }

    #[test]
    fn test_global_read_only_on() {
        // Cluster on: reads pass, writes are rejected.
        let ro = ReadOnly::new(true, false);
        for method in READ_METHODS {
            assert_passthrough(&run(&ro, mk(method, "/v1/a", &[])));
        }
        for method in WRITE_METHODS {
            assert_blocked(&run(&ro, mk(method, "/v1/a", &[])));
        }
    }

    #[test]
    fn test_account_read_only_on() {
        // Cluster off, account override 'true': reads pass, writes reject.
        let ro = ReadOnly::new(false, false);
        let hdr = [("X-Account-Sysmeta-Read-Only", "true")];
        for method in READ_METHODS {
            assert_passthrough(&run(&ro, mk(method, "/v1/a", &hdr)));
        }
        for method in WRITE_METHODS {
            assert_blocked(&run(&ro, mk(method, "/v1/a", &hdr)));
        }
    }

    #[test]
    fn test_account_read_only_off() {
        // Cluster off, account override 'false': everything passes.
        let ro = ReadOnly::new(false, false);
        let hdr = [("X-Account-Sysmeta-Read-Only", "false")];
        for method in READ_METHODS.iter().chain(WRITE_METHODS.iter()) {
            assert_passthrough(&run(&ro, mk(method, "/v1/a", &hdr)));
        }
    }

    #[test]
    fn test_global_read_only_on_account_off() {
        // Cluster on but the account is explicitly writable: everything
        // passes (the non-empty override wins over the cluster value).
        let ro = ReadOnly::new(true, false);
        let hdr = [("X-Account-Sysmeta-Read-Only", "false")];
        for method in READ_METHODS.iter().chain(WRITE_METHODS.iter()) {
            assert_passthrough(&run(&ro, mk(method, "/v1/a", &hdr)));
        }
    }

    #[test]
    fn test_global_read_only_on_allow_deletes() {
        // allow_deletes removes DELETE from the write set, so it passes
        // even with the cluster read-only; the other writes still reject.
        let ro = ReadOnly::new(true, true);
        assert_passthrough(&run(&ro, mk("DELETE", "/v1/a", &[])));
        for method in ["COPY", "POST", "PUT"] {
            assert_blocked(&run(&ro, mk(method, "/v1/a", &[])));
        }
    }

    #[test]
    fn test_account_read_only_on_allow_deletes() {
        // Account is read-only ('on'), but allow_deletes means DELETE is
        // never a policed write, so it still passes; a PUT is rejected.
        let ro = ReadOnly::new(false, true);
        let hdr = [("X-Account-Sysmeta-Read-Only", "on")];
        assert_passthrough(&run(&ro, mk("DELETE", "/v1/a", &hdr)));
        assert_blocked(&run(&ro, mk("PUT", "/v1/a", &hdr)));
    }

    #[test]
    fn test_copy_destination_account_writable() {
        // Cluster on, COPY to a destination account marked writable: the
        // effective (destination) account's override allows the write.
        let ro = ReadOnly::new(true, false);
        let resp = run(
            &ro,
            mk(
                "COPY",
                "/v1/a",
                &[
                    ("Destination-Account", "b"),
                    ("X-Account-Sysmeta-Read-Only", "false"),
                ],
            ),
        );
        assert_passthrough(&resp);
    }

    #[test]
    fn test_copy_destination_account_read_only() {
        // Cluster off, COPY to a destination account marked read-only:
        // rejected.
        let ro = ReadOnly::new(false, false);
        let resp = run(
            &ro,
            mk(
                "COPY",
                "/v1/a",
                &[
                    ("Destination-Account", "b"),
                    ("X-Account-Sysmeta-Read-Only", "true"),
                ],
            ),
        );
        assert_blocked(&resp);
    }

    #[test]
    fn test_copy_bad_destination_account() {
        // A malformed Destination-Account is rejected with 412 before any
        // read-only decision, regardless of the cluster setting.
        let ro = ReadOnly::new(false, false);
        let resp = run(&ro, mk("COPY", "/v1/a", &[("Destination-Account", "b/c")]));
        assert_eq!(resp.status, 412);
        assert_eq!(
            String::from_utf8_lossy(body_bytes(&resp)),
            "Account name cannot contain slashes"
        );

        // An empty Destination-Account is likewise a 412.
        let resp = run(&ro, mk("COPY", "/v1/a", &[("Destination-Account", "")]));
        assert_eq!(resp.status, 412);
        assert_eq!(
            String::from_utf8_lossy(body_bytes(&resp)),
            "Account name cannot be empty"
        );
    }

    #[test]
    fn test_non_swift_paths_pass_through() {
        // Even with the cluster read-only AND the account marked read-only,
        // a request whose path is not a valid Swift API path is not a write
        // this middleware polices, so it passes through untouched.
        let ro = ReadOnly::new(true, false);
        let hdr = [("X-Account-Sysmeta-Read-Only", "on")];
        // unknown API version
        assert_passthrough(&run(&ro, mk("POST", "/auth/v3.14", &hdr)));
        // too few segments (no account)
        assert_passthrough(&run(&ro, mk("PUT", "/v1", &hdr)));
        // empty account segment
        assert_passthrough(&run(&ro, mk("DELETE", "/v1.0/", &hdr)));
    }

    #[test]
    fn test_from_conf_coercion() {
        // Missing options are false; values pass through config_true_value.
        let ro = ReadOnly::from_conf(None, None);
        assert!(!ro.read_only && !ro.allow_deletes);
        let ro = ReadOnly::from_conf(Some("true"), Some("YES"));
        assert!(ro.read_only && ro.allow_deletes);
        let ro = ReadOnly::from_conf(Some("false"), Some("0"));
        assert!(!ro.read_only && !ro.allow_deletes);
    }
}
