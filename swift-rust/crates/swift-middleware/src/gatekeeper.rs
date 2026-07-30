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

//! `gatekeeper`: strips client-supplied backend/sysmeta headers from the
//! inbound request and the outbound response. This is a security
//! boundary — without it a client could inject `X-Backend-*` or
//! `X-Object-Sysmeta-*` headers straight through to the storage nodes.

use swift_http::{Request, Response};

use crate::{Middleware, NextFn};

/// The header-name prefixes/exact-matches gatekeeper removes, matching
/// `gatekeeper.inbound_exclusions` (which equals `outbound_exclusions`).
/// All comparisons are case-insensitive on the lowercased name.
fn is_excluded(name_lower: &str) -> bool {
    const PREFIXES: [&str; 6] = [
        "x-account-sysmeta-",
        "x-container-sysmeta-",
        "x-object-sysmeta-",
        "x-object-transient-sysmeta-",
        "x-backend",
        // the exact-match rules below are handled separately
        "",
    ];
    for prefix in PREFIXES.iter().filter(|p| !p.is_empty()) {
        if name_lower.starts_with(prefix) {
            return true;
        }
    }
    // exact-match rules (regex anchored with `$` in Python)
    matches!(
        name_lower,
        "x-account-host"
            | "x-account-device"
            | "x-account-partition"
            | "x-container-host"
            | "x-container-device"
            | "x-container-partition"
            | "x-container-root-db-state"
            | "x-delete-at-host"
            | "x-delete-at-device"
            | "x-delete-at-partition"
            | "x-delete-at-container"
    )
}

pub struct Gatekeeper {
    pub shunt_x_timestamp: bool,
    pub allow_reserved_names_header: bool,
}

impl Default for Gatekeeper {
    fn default() -> Self {
        Gatekeeper {
            shunt_x_timestamp: true,
            allow_reserved_names_header: false,
        }
    }
}

impl Middleware for Gatekeeper {
    fn handle(&self, mut req: Request, next: &NextFn) -> Response {
        // strip excluded inbound headers
        let to_remove: Vec<String> = req
            .headers
            .iter()
            .filter(|(k, _)| is_excluded(&k.to_lowercase()))
            .map(|(k, _)| k.to_string())
            .collect();
        for name in to_remove {
            req.headers.remove(&name);
        }
        // shunt an inbound X-Timestamp into a backend header so clients
        // cannot forge the storage timestamp
        if self.shunt_x_timestamp {
            if let Some(ts) = req.headers.remove("X-Timestamp") {
                req.headers.set("X-Backend-Inbound-X-Timestamp", ts);
            }
        }
        if self.allow_reserved_names_header {
            if let Some(v) = req.headers.remove("X-Allow-Reserved-Names") {
                req.headers.set("X-Backend-Allow-Reserved-Names", v);
            }
        }

        let mut resp = next(req);

        // strip excluded outbound headers
        let to_remove: Vec<String> = resp
            .headers
            .iter()
            .filter(|(k, _)| is_excluded(&k.to_lowercase()))
            .map(|(k, _)| k.to_string())
            .collect();
        for name in to_remove {
            resp.headers.remove(&name);
        }
        resp
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use swift_http::HeaderKeyDict;

    fn echo_headers() -> Arc<dyn Fn(Request) -> Response + Send + Sync> {
        Arc::new(|req: Request| {
            // reflect the surviving request headers into the response so
            // the test can inspect what reached the app
            let mut resp = Response::new(200);
            for (k, v) in req.headers.iter() {
                resp.headers.set(&format!("Echo-{k}"), v);
            }
            // also emit a backend header to prove the outbound scrub
            resp.headers.set("X-Backend-Secret", "leak");
            resp.headers.set("X-Object-Meta-Public", "ok");
            resp
        })
    }

    #[test]
    fn test_strips_inbound_and_outbound() {
        let gk = Gatekeeper::default();
        let mut req = Request {
            method: "GET".into(),
            path: "/v1/a/c/o".into(),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: swift_http::Body::empty(),
        };
        req.headers.set("X-Backend-Storage-Policy-Index", "9");
        req.headers.set("X-Object-Sysmeta-Evil", "1");
        req.headers.set("X-Container-Host", "evil:1");
        req.headers.set("X-Object-Meta-Fine", "keep");
        req.headers.set("X-Timestamp", "1751500000.00000");

        let resp = gk.handle(req, &echo_headers());

        // backend/sysmeta/host inbound headers must NOT have reached the app
        assert!(resp.headers.get("Echo-X-Backend-Storage-Policy-Index").is_none());
        assert!(resp.headers.get("Echo-X-Object-Sysmeta-Evil").is_none());
        assert!(resp.headers.get("Echo-X-Container-Host").is_none());
        // user meta survives
        assert_eq!(resp.headers.get("Echo-X-Object-Meta-Fine"), Some("keep"));
        // X-Timestamp was shunted
        assert!(resp.headers.get("Echo-X-Timestamp").is_none());
        assert_eq!(
            resp.headers.get("Echo-X-Backend-Inbound-X-Timestamp"),
            Some("1751500000.00000")
        );
        // outbound backend header stripped, user meta kept
        assert!(resp.headers.get("X-Backend-Secret").is_none());
        assert_eq!(resp.headers.get("X-Object-Meta-Public"), Some("ok"));
    }
}
