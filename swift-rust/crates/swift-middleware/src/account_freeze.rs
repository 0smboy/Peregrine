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

//! `account_freeze`: deny every method for accounts listed in
//! `[filter:account_freeze] frozen_accounts` (CSV).
//!
//! Opt-in only. This filter is not inserted into the default proxy pipeline
//! and is not registered in [`crate::plugin_registry`] (that map only holds
//! passthrough factories; fail-closed load cannot be expressed there).
//! Operators add it to `pipeline =` later.
//!
//! An empty `frozen_accounts` list with the filter present is a load error
//! (fail closed). Paths that do not carry an account (`/healthcheck`,
//! `/info`, S3 `ListBuckets` `/`) are not blocked. After s3api rewrite,
//! S3 traffic is `/v1/{account}/...` and is classified by the same extractor;
//! this crate has no separate S3-account helper.

use std::collections::{HashMap, HashSet};

use swift_core::config::list_from_csv;
use swift_core::constraints::VALID_API_VERSIONS;
use swift_http::{split_path, Request, Response};

use crate::{Middleware, NextFn};

/// Body for a frozen-account 403. Must not resemble a successful payload.
const FROZEN_BODY: &str = "Account is frozen.";

/// Deny all methods for configured Swift accounts.
#[derive(Debug)]
pub struct AccountFreeze {
    frozen_accounts: HashSet<String>,
}

impl AccountFreeze {
    /// Build from `[filter:account_freeze]` items.
    ///
    /// `frozen_accounts` is a comma-separated list. Missing, blank, or
    /// comma-only values are a load error.
    pub fn from_conf(conf: &HashMap<String, String>) -> Result<Self, String> {
        let raw = conf
            .get("frozen_accounts")
            .map(String::as_str)
            .unwrap_or("");
        let accounts = list_from_csv(raw);
        if accounts.is_empty() {
            return Err(
                "[filter:account_freeze] frozen_accounts is empty; refusing to load (fail closed)"
                    .into(),
            );
        }
        Ok(AccountFreeze {
            frozen_accounts: accounts.into_iter().collect(),
        })
    }

    /// Account from `/v1/{account}/...` or `/v1.0/{account}/...`.
    /// Rewritten S3 paths use the same shape. No account → `None`.
    fn account_from_path(path: &str) -> Option<String> {
        let parts = split_path(path, 2, 4, true).ok()?;
        let version = parts.first().and_then(|v| v.as_deref()).unwrap_or("");
        if !VALID_API_VERSIONS.contains(&version) {
            return None;
        }
        let account = parts.get(1).and_then(|v| v.as_deref()).unwrap_or("");
        if account.is_empty() {
            None
        } else {
            Some(account.to_string())
        }
    }

    fn forbidden() -> Response {
        let mut resp = Response::with_body(403, FROZEN_BODY);
        resp.headers.set("Content-Type", "text/plain; charset=UTF-8");
        resp
    }
}

impl Middleware for AccountFreeze {
    fn handle(&self, req: Request, next: &NextFn) -> Response {
        if let Some(account) = Self::account_from_path(&req.path) {
            if self.frozen_accounts.contains(&account) {
                return Self::forbidden();
            }
        }
        next(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use swift_http::HeaderKeyDict;

    const METHODS: [&str; 6] = ["GET", "HEAD", "PUT", "POST", "DELETE", "COPY"];

    fn freeze_auth_test() -> AccountFreeze {
        let mut conf = HashMap::new();
        conf.insert("frozen_accounts".into(), "AUTH_test".into());
        AccountFreeze::from_conf(&conf).unwrap()
    }

    fn mk(method: &str, path: &str) -> Request {
        Request {
            method: method.into(),
            path: path.into(),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: swift_http::Body::empty(),
        }
    }

    fn content_app() -> crate::NextFn {
        Arc::new(|_r| Response::with_body(200, b"Some Content".to_vec()))
    }

    fn run(freeze: &AccountFreeze, req: Request) -> Response {
        let mut resp = freeze.handle(req, &content_app());
        resp.body.materialize(u64::MAX).unwrap();
        resp
    }

    fn body_bytes(resp: &Response) -> &[u8] {
        match &resp.body {
            swift_http::Body::Buffered(b) => b,
            swift_http::Body::Streamed(_) | swift_http::Body::Channel(_) => unreachable!(),
        }
    }

    fn assert_forbidden(resp: &Response) {
        assert_eq!(resp.status, 403);
        assert_eq!(body_bytes(resp), FROZEN_BODY.as_bytes());
        assert_ne!(body_bytes(resp), b"Some Content");
        assert_ne!(body_bytes(resp), b"OK");
        assert!(!body_bytes(resp).is_empty());
    }

    fn assert_passthrough(resp: &Response) {
        assert_eq!(resp.status, 200);
        assert_eq!(body_bytes(resp), b"Some Content");
    }

    #[test]
    fn frozen_account_denies_get_head_put_post_delete_copy() {
        let freeze = freeze_auth_test();
        for method in METHODS {
            let resp = run(&freeze, mk(method, "/v1/AUTH_test/c/o"));
            assert_eq!(resp.status, 403, "{method} /v1/AUTH_test/c/o");
            assert_forbidden(&resp);
        }
        assert_forbidden(&run(&freeze, mk("GET", "/v1/AUTH_test")));
        assert_forbidden(&run(&freeze, mk("GET", "/v1.0/AUTH_test/c")));
    }

    #[test]
    fn auth_s3test_is_allowed() {
        let freeze = freeze_auth_test();
        for method in METHODS {
            let resp = run(&freeze, mk(method, "/v1/AUTH_s3test/c/o"));
            assert_eq!(resp.status, 200, "{method} /v1/AUTH_s3test/c/o");
            assert_passthrough(&resp);
        }
    }

    #[test]
    fn empty_frozen_accounts_fails_closed_at_load() {
        let err = AccountFreeze::from_conf(&HashMap::new()).unwrap_err();
        assert!(err.contains("empty"), "{err}");
        assert!(err.contains("fail closed"), "{err}");

        let mut blank = HashMap::new();
        blank.insert("frozen_accounts".into(), String::new());
        assert!(AccountFreeze::from_conf(&blank).is_err());

        let mut commas = HashMap::new();
        commas.insert("frozen_accounts".into(), "  ,  , ".into());
        assert!(AccountFreeze::from_conf(&commas).is_err());
    }

    #[test]
    fn healthcheck_path_is_allowed() {
        let freeze = freeze_auth_test();
        assert_passthrough(&run(&freeze, mk("GET", "/healthcheck")));
        assert_passthrough(&run(&freeze, mk("GET", "/info")));
        assert_passthrough(&run(&freeze, mk("GET", "/")));
        assert_passthrough(&run(&freeze, mk("GET", "/v1")));
    }
}
