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

//! `etag_quoter`: makes object ETags RFC-compliant by wrapping the
//! response `Etag` value in double quotes, and translates the
//! account/container `X-...-Rfc-Compliant-Etags` client header to and from
//! its `X-...-Sysmeta-Rfc-Compliant-Etags` backend form. Port of
//! `swift/common/middleware/etag_quoter.py`.
//!
//! `RFC 7232 §2.3` requires the `Etag` header value to be double quoted;
//! Swift stores bare MD5s, so this filter re-quotes them when enabled.
//!
//! Per-container / per-account `rfc-compliant-etags` sysmeta is resolved
//! from `X-Backend-*-Rfc-Compliant-Etags` stamps the proxy copies off
//! `get_container_info` / `get_account_info` before this filter's
//! outbound pass. Missing stamps keep the Python terminal fallback
//! (`enable_by_default`). Empty sysmeta is treated as unset (fall through)
//! so a container POST of `X-Container-Rfc-Compliant-Etags: ` clears
//! the override.

use std::future::Future;
use std::pin::Pin;

use swift_core::config::config_true_value;
use swift_core::constraints::VALID_API_VERSIONS;
use swift_http::{split_path, Request, Response};

use crate::{AsyncNextFn, Middleware, NextFn};

#[derive(Default)]
pub struct EtagQuoter {
    /// Quote object ETags cluster-wide (Python `enable_by_default`). This
    /// is the terminal fallback; per-account/per-container sysmeta
    /// overrides are deferred (see the module docs).
    pub enable_by_default: bool,
}

impl Middleware for EtagQuoter {
    fn handle(&self, mut req: Request, next: &NextFn) -> Response {
        // Parse `/<version>/<account>/<container>/<object>`. A path that
        // does not split, or whose version is not a valid API version, is
        // not a "swifty" request and passes straight through untouched.
        let parts = match split_path(&req.path, 2, 4, true) {
            Ok(p) => p,
            Err(_) => return next(req),
        };
        let version = parts[0].as_deref().unwrap_or("");
        if !VALID_API_VERSIONS.contains(&version) {
            return next(req);
        }
        // In Python `not container` / `not obj` treat both a missing
        // segment (None) and an empty trailing segment ("") as absent.
        let container_present = parts[2].as_deref().is_some_and(|s| !s.is_empty());
        let obj_present = parts[3].as_deref().is_some_and(|s| !s.is_empty());

        if !obj_present {
            // Account or container request: translate the client-facing
            // `X-...-Rfc-Compliant-Etags` header into its sysmeta form on
            // the way in, and translate the stored sysmeta back to the
            // friendly name on the way out.
            let typ = if container_present {
                "Container"
            } else {
                "Account"
            };
            let client_header = format!("X-{typ}-Rfc-Compliant-Etags");
            let sysmeta_header = format!("X-{typ}-Sysmeta-Rfc-Compliant-Etags");
            let remove_header = format!("X-Remove-{typ}-Rfc-Compliant-Etags");

            if req.headers.contains_key(&client_header) {
                let value = req.headers.get(&client_header).unwrap_or("").to_string();
                if !value.is_empty() {
                    // `config_true_value(...)` yields a Python bool, which
                    // swob stringifies as "True"/"False" when it is stored
                    // as a request header value.
                    let normalized = if config_true_value(&value) {
                        "True"
                    } else {
                        "False"
                    };
                    req.headers.set(&sysmeta_header, normalized);
                } else {
                    req.headers.set(&sysmeta_header, "");
                }
            }
            // An `X-Remove-...` request (present and non-empty) clears the
            // sysmeta.
            if req
                .headers
                .get(&remove_header)
                .is_some_and(|v| !v.is_empty())
            {
                req.headers.set(&sysmeta_header, "");
            }

            let mut resp = next(req);
            // Present the stored sysmeta back to the client under the
            // friendly header name.
            if let Some(value) = resp.headers.remove(&sysmeta_header) {
                resp.headers.set(&client_header, value);
            }
            return resp;
        }

        // Object request: quote the response ETag when the container /
        // account sysmeta (or `enable_by_default`) says to.
        let head = req.clone_head();
        let resp = next(req);
        self.finish(&head, resp)
    }

    fn intercepts_response(&self) -> bool {
        self.enable_by_default
    }

    fn reassemble_async(
        &self,
        req: Request,
        next: AsyncNextFn,
    ) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        Box::pin(async move {
            let resp = next(req.clone_head()).await;
            self.finish(&req, resp)
        })
    }

    fn finish(&self, req: &Request, mut resp: Response) -> Response {
        let parts = match split_path(&req.path, 2, 4, true) {
            Ok(p) => p,
            Err(_) => return resp,
        };
        let version = parts[0].as_deref().unwrap_or("");
        if !VALID_API_VERSIONS.contains(&version) {
            return resp;
        }
        let obj_present = parts[3].as_deref().is_some_and(|s| !s.is_empty());
        if !obj_present {
            return resp;
        }
        if !self.should_quote_object(&mut resp) {
            return resp;
        }
        self.quote_object_etag(resp)
    }
}

impl EtagQuoter {
    /// Python `EtagQuoterMiddleware.__call__` object-path flag:
    /// container sysmeta, else account sysmeta, else `enable_by_default`.
    /// A non-2xx container/account info status skips quoting. The proxy
    /// stamps these as `X-Backend-*` so this filter does not issue its
    /// own info subrequest; absent stamps mean "unit-test / no proxy".
    fn should_quote_object(&self, resp: &mut Response) -> bool {
        let container_status = resp.headers.remove("X-Backend-Container-Info-Status");
        let container_flag = resp
            .headers
            .remove("X-Backend-Container-Rfc-Compliant-Etags");
        let account_status = resp.headers.remove("X-Backend-Account-Info-Status");
        let account_flag = resp
            .headers
            .remove("X-Backend-Account-Rfc-Compliant-Etags");
        let Some(cs) = container_status else {
            return self.enable_by_default;
        };
        let cs: u16 = cs.parse().unwrap_or(0);
        if !(200..300).contains(&cs) {
            return false;
        }
        if let Some(flag) = container_flag.filter(|s| !s.is_empty()) {
            return config_true_value(&flag);
        }
        let Some(as_) = account_status else {
            return self.enable_by_default;
        };
        let as_: u16 = as_.parse().unwrap_or(0);
        if !(200..300).contains(&as_) {
            return false;
        }
        if let Some(flag) = account_flag.filter(|s| !s.is_empty()) {
            return config_true_value(&flag);
        }
        self.enable_by_default
    }

    fn quote_object_etag(&self, mut resp: Response) -> Response {
        if let Some(etag) = resp.headers.get("Etag").map(str::to_string) {
            // Keep it as-is only if it is already a (strong or weak)
            // quoted validator: starts with `"` or `W/"` AND ends with `"`.
            let already_quoted =
                (etag.starts_with('"') || etag.starts_with("W/\"")) && etag.ends_with('"');
            if !already_quoted {
                resp.headers.set("Etag", format!("\"{etag}\""));
            }
        }
        resp
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use swift_http::HeaderKeyDict;

    fn req(path: &str) -> Request {
        Request {
            method: "GET".into(),
            path: path.into(),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: swift_http::Body::empty(),
        }
    }

    /// An app that returns a fixed `Etag` response header.
    fn etag_app(etag: &'static str) -> Arc<dyn Fn(Request) -> Response + Send + Sync> {
        Arc::new(move |_req: Request| {
            let mut resp = Response::new(200);
            resp.headers.set("Etag", etag);
            resp
        })
    }

    /// An app that reflects the surviving *request* headers into the
    /// response as `Echo-<name>` so a test can inspect what reached it.
    fn echo_app() -> Arc<dyn Fn(Request) -> Response + Send + Sync> {
        Arc::new(|req: Request| {
            let mut resp = Response::new(204);
            for (k, v) in req.headers.iter() {
                resp.headers.set(&format!("Echo-{k}"), v);
            }
            resp
        })
    }

    // ---- object path: ETag quoting ------------------------------------

    #[test]
    fn test_bare_etag_is_quoted_when_enabled() {
        let eq = EtagQuoter {
            enable_by_default: true,
        };
        let app = etag_app("d41d8cd98f00b204e9800998ecf8427e");
        let resp = eq.handle(req("/v1/a/c/o"), &app);
        assert_eq!(
            resp.headers.get("Etag"),
            Some("\"d41d8cd98f00b204e9800998ecf8427e\"")
        );
    }

    #[test]
    fn test_finish_quotes_on_async_outbound_path() {
        let eq = EtagQuoter {
            enable_by_default: true,
        };
        let mut resp = Response::new(200);
        resp.headers.set("Etag", "d41d8cd98f00b204e9800998ecf8427e");
        let resp = eq.finish(&req("/v1/a/c/o"), resp);
        assert_eq!(
            resp.headers.get("Etag"),
            Some("\"d41d8cd98f00b204e9800998ecf8427e\"")
        );
    }

    #[test]
    fn test_finish_quotes_412_when_enabled() {
        let eq = EtagQuoter {
            enable_by_default: true,
        };
        let mut resp = Response::new(412);
        resp.headers.set("Etag", "d41d8cd98f00b204e9800998ecf8427e");
        let resp = eq.finish(&req("/v1/a/c/o"), resp);
        assert_eq!(
            resp.headers.get("Etag"),
            Some("\"d41d8cd98f00b204e9800998ecf8427e\"")
        );
    }

    #[test]
    fn test_finish_container_false_overrides_enable_by_default() {
        let eq = EtagQuoter {
            enable_by_default: true,
        };
        let mut resp = Response::new(200);
        resp.headers.set("Etag", "098f6bcd4621d373cade4e832627b4f6");
        resp.headers.set("X-Backend-Container-Info-Status", "204");
        resp.headers
            .set("X-Backend-Container-Rfc-Compliant-Etags", "False");
        let resp = eq.finish(&req("/v1/a/c/o"), resp);
        assert_eq!(
            resp.headers.get("Etag"),
            Some("098f6bcd4621d373cade4e832627b4f6")
        );
        assert!(resp
            .headers
            .get("X-Backend-Container-Rfc-Compliant-Etags")
            .is_none());
    }

    #[test]
    fn test_finish_account_true_when_container_flag_cleared() {
        let eq = EtagQuoter {
            enable_by_default: false,
        };
        let mut resp = Response::new(200);
        resp.headers.set("Etag", "098f6bcd4621d373cade4e832627b4f6");
        resp.headers.set("X-Backend-Container-Info-Status", "204");
        resp.headers.set("X-Backend-Account-Info-Status", "204");
        resp.headers
            .set("X-Backend-Account-Rfc-Compliant-Etags", "True");
        let resp = eq.finish(&req("/v1/a/c/o"), resp);
        assert_eq!(
            resp.headers.get("Etag"),
            Some("\"098f6bcd4621d373cade4e832627b4f6\"")
        );
    }

    #[test]
    fn test_already_quoted_etag_is_untouched() {
        let eq = EtagQuoter {
            enable_by_default: true,
        };
        let app = etag_app("\"d41d8cd98f00b204e9800998ecf8427e\"");
        let resp = eq.handle(req("/v1/a/c/o"), &app);
        assert_eq!(
            resp.headers.get("Etag"),
            Some("\"d41d8cd98f00b204e9800998ecf8427e\"")
        );
    }

    #[test]
    fn test_weak_validator_is_untouched() {
        let eq = EtagQuoter {
            enable_by_default: true,
        };
        let app = etag_app("W/\"d41d8cd98f00b204e9800998ecf8427e\"");
        let resp = eq.handle(req("/v1/a/c/o"), &app);
        assert_eq!(
            resp.headers.get("Etag"),
            Some("W/\"d41d8cd98f00b204e9800998ecf8427e\"")
        );
    }

    #[test]
    fn test_open_quote_without_close_is_still_quoted() {
        // Faithful to Python: startswith('"') but not endswith('"') is not
        // "already quoted", so it gets wrapped again -> `""abc`".
        let eq = EtagQuoter {
            enable_by_default: true,
        };
        let app = etag_app("\"abc");
        let resp = eq.handle(req("/v1/a/c/o"), &app);
        assert_eq!(resp.headers.get("Etag"), Some("\"\"abc\""));
    }

    #[test]
    fn test_bare_etag_not_quoted_when_disabled() {
        let eq = EtagQuoter {
            enable_by_default: false,
        };
        let app = etag_app("d41d8cd98f00b204e9800998ecf8427e");
        let resp = eq.handle(req("/v1/a/c/o"), &app);
        assert_eq!(
            resp.headers.get("Etag"),
            Some("d41d8cd98f00b204e9800998ecf8427e")
        );
    }

    #[test]
    fn test_default_is_disabled() {
        assert!(!EtagQuoter::default().enable_by_default);
    }

    #[test]
    fn test_object_without_etag_header() {
        let eq = EtagQuoter {
            enable_by_default: true,
        };
        let app: Arc<dyn Fn(Request) -> Response + Send + Sync> = Arc::new(|_r| Response::new(204));
        let resp = eq.handle(req("/v1/a/c/o"), &app);
        assert!(resp.headers.get("Etag").is_none());
        assert_eq!(resp.status, 204);
    }

    #[test]
    fn test_pseudo_dir_object_with_trailing_slash_is_object() {
        // `/v1/a/c/o/` -> obj = "o/" (rest_with_last), so it is an object
        // request and the ETag is quoted.
        let eq = EtagQuoter {
            enable_by_default: true,
        };
        let app = etag_app("abc");
        let resp = eq.handle(req("/v1/a/c/o/"), &app);
        assert_eq!(resp.headers.get("Etag"), Some("\"abc\""));
    }

    // ---- non-swifty pass-through --------------------------------------

    #[test]
    fn test_non_swifty_path_passes_through() {
        let eq = EtagQuoter {
            enable_by_default: true,
        };
        let app = etag_app("d41d8cd98f00b204e9800998ecf8427e");
        // Not enough segments to split -> ValueError in Python.
        let resp = eq.handle(req("/healthcheck"), &app);
        assert_eq!(
            resp.headers.get("Etag"),
            Some("d41d8cd98f00b204e9800998ecf8427e")
        );
    }

    #[test]
    fn test_bad_api_version_passes_through() {
        let eq = EtagQuoter {
            enable_by_default: true,
        };
        let app = etag_app("d41d8cd98f00b204e9800998ecf8427e");
        let resp = eq.handle(req("/v2/a/c/o"), &app);
        assert_eq!(
            resp.headers.get("Etag"),
            Some("d41d8cd98f00b204e9800998ecf8427e")
        );
    }

    // ---- container/account request: inbound header translation --------

    #[test]
    fn test_container_true_header_becomes_sysmeta() {
        let eq = EtagQuoter::default();
        let mut r = req("/v1/a/c");
        r.headers.set("X-Container-Rfc-Compliant-Etags", "true");
        let app = echo_app();
        let resp = eq.handle(r, &app);
        assert_eq!(
            resp.headers
                .get("Echo-X-Container-Sysmeta-Rfc-Compliant-Etags"),
            Some("True")
        );
    }

    #[test]
    fn test_container_falsey_header_becomes_false_sysmeta() {
        let eq = EtagQuoter::default();
        let mut r = req("/v1/a/c");
        // A non-empty, non-true value normalizes to "False".
        r.headers.set("X-Container-Rfc-Compliant-Etags", "no");
        let app = echo_app();
        let resp = eq.handle(r, &app);
        assert_eq!(
            resp.headers
                .get("Echo-X-Container-Sysmeta-Rfc-Compliant-Etags"),
            Some("False")
        );
    }

    #[test]
    fn test_container_empty_header_clears_sysmeta() {
        let eq = EtagQuoter::default();
        let mut r = req("/v1/a/c");
        r.headers.set("X-Container-Rfc-Compliant-Etags", "");
        let app = echo_app();
        let resp = eq.handle(r, &app);
        assert_eq!(
            resp.headers
                .get("Echo-X-Container-Sysmeta-Rfc-Compliant-Etags"),
            Some("")
        );
    }

    #[test]
    fn test_container_remove_header_clears_sysmeta() {
        let eq = EtagQuoter::default();
        let mut r = req("/v1/a/c");
        r.headers
            .set("X-Remove-Container-Rfc-Compliant-Etags", "on");
        let app = echo_app();
        let resp = eq.handle(r, &app);
        assert_eq!(
            resp.headers
                .get("Echo-X-Container-Sysmeta-Rfc-Compliant-Etags"),
            Some("")
        );
    }

    #[test]
    fn test_account_true_header_becomes_sysmeta() {
        // No container segment -> Account variant of the header names.
        let eq = EtagQuoter::default();
        let mut r = req("/v1/a");
        r.headers.set("X-Account-Rfc-Compliant-Etags", "1");
        let app = echo_app();
        let resp = eq.handle(r, &app);
        assert_eq!(
            resp.headers
                .get("Echo-X-Account-Sysmeta-Rfc-Compliant-Etags"),
            Some("True")
        );
    }

    #[test]
    fn test_no_client_header_leaves_no_sysmeta() {
        let eq = EtagQuoter::default();
        let app = echo_app();
        let resp = eq.handle(req("/v1/a/c"), &app);
        assert!(resp
            .headers
            .get("Echo-X-Container-Sysmeta-Rfc-Compliant-Etags")
            .is_none());
    }

    // ---- container/account request: outbound header translation -------

    #[test]
    fn test_response_sysmeta_translated_to_client_header() {
        let eq = EtagQuoter::default();
        // App returns the stored sysmeta; the middleware renames it to the
        // friendly client header and drops the sysmeta.
        let app: Arc<dyn Fn(Request) -> Response + Send + Sync> = Arc::new(|_r| {
            let mut resp = Response::new(204);
            resp.headers
                .set("X-Container-Sysmeta-Rfc-Compliant-Etags", "True");
            resp
        });
        let resp = eq.handle(req("/v1/a/c"), &app);
        assert_eq!(
            resp.headers.get("X-Container-Rfc-Compliant-Etags"),
            Some("True")
        );
        assert!(resp
            .headers
            .get("X-Container-Sysmeta-Rfc-Compliant-Etags")
            .is_none());
    }

    #[test]
    fn test_account_response_sysmeta_translated() {
        let eq = EtagQuoter::default();
        let app: Arc<dyn Fn(Request) -> Response + Send + Sync> = Arc::new(|_r| {
            let mut resp = Response::new(204);
            resp.headers
                .set("X-Account-Sysmeta-Rfc-Compliant-Etags", "False");
            resp
        });
        let resp = eq.handle(req("/v1/a"), &app);
        assert_eq!(
            resp.headers.get("X-Account-Rfc-Compliant-Etags"),
            Some("False")
        );
        assert!(resp
            .headers
            .get("X-Account-Sysmeta-Rfc-Compliant-Etags")
            .is_none());
    }

    #[test]
    fn test_container_request_does_not_quote_etag() {
        // The obj-less path never touches an ETag header, even when
        // quoting is enabled globally.
        let eq = EtagQuoter {
            enable_by_default: true,
        };
        let app = etag_app("d41d8cd98f00b204e9800998ecf8427e");
        let resp = eq.handle(req("/v1/a/c"), &app);
        assert_eq!(
            resp.headers.get("Etag"),
            Some("d41d8cd98f00b204e9800998ecf8427e")
        );
    }
}
