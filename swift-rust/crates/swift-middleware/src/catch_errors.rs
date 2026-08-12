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

//! `catch_errors`: the outermost pipeline filter. It stamps every
//! request with a transaction id, exposes it as `X-Trans-Id` /
//! `X-Openstack-Request-Id` on the response, and would convert a panic
//! in the pipeline into a 500 (Rust panics unwind per-connection in the
//! threaded server; here we guarantee the trans-id contract).

use std::sync::atomic::{AtomicU64, Ordering};

use swift_http::{Request, Response};

use crate::{Middleware, NextFn};

/// A trans-id generator. Python: `tx<21 hex>-<10 hex unix time><suffix>`.
/// We keep the same shape; the random part is a per-process counter mixed
/// with the pid (no `rand` dependency, deterministic within a run).
pub struct CatchErrors {
    pub trans_id_suffix: String,
    counter: AtomicU64,
    seed: u64,
}

impl CatchErrors {
    pub fn new(trans_id_suffix: impl Into<String>) -> Self {
        let seed = std::process::id() as u64;
        CatchErrors {
            trans_id_suffix: trans_id_suffix.into(),
            counter: AtomicU64::new(0),
            seed,
        }
    }

    fn generate_trans_id(&self, extra: Option<&str>) -> String {
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        // 21 hex chars of "randomness" (pid-seeded counter, xorshifted)
        let mut x = self.seed.wrapping_mul(0x9e3779b97f4a7c15).wrapping_add(n);
        x ^= x >> 30;
        x = x.wrapping_mul(0xbf58476d1ce4e5b9);
        x ^= x >> 27;
        let rand21 = format!("{:016x}{:05x}", x, (n & 0xfffff));
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut suffix = self.trans_id_suffix.clone();
        if let Some(extra) = extra {
            suffix.push('-');
            suffix.push_str(&extra.chars().take(32).collect::<String>());
        }
        format!("tx{}-{:010x}{}", &rand21[..21], now, suffix)
    }
}

impl Middleware for CatchErrors {
    fn handle(&self, mut req: Request, next: &NextFn) -> Response {
        let extra = req.headers.get("X-Trans-Id-Extra").map(str::to_string);
        let trans_id = self.generate_trans_id(extra.as_deref());
        req.headers.set("X-Trans-Id", &trans_id);
        let mut resp = next(req);
        resp.headers.set("X-Trans-Id", &trans_id);
        resp.headers.set("X-Openstack-Request-Id", &trans_id);
        resp
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use swift_http::HeaderKeyDict;

    #[test]
    fn test_stamps_trans_id() {
        let ce = CatchErrors::new("-suffix");
        let app: Arc<dyn Fn(Request) -> Response + Send + Sync> = Arc::new(|_r| Response::new(204));
        let req = Request {
            method: "GET".into(),
            path: "/v1/a".into(),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: swift_http::Body::empty(),
        };
        let resp = ce.handle(req, &app);
        let tx = resp.headers.get("X-Trans-Id").unwrap();
        assert!(tx.starts_with("tx"), "{tx}");
        assert!(tx.ends_with("-suffix"), "{tx}");
        assert_eq!(resp.headers.get("X-Openstack-Request-Id"), Some(tx));
        // trans ids are unique per request
        let ce2 = CatchErrors::new("");
        let app2: Arc<dyn Fn(Request) -> Response + Send + Sync> =
            Arc::new(|_r| Response::new(200));
        let mk = || {
            ce2.handle(
                Request {
                    method: "GET".into(),
                    path: "/".into(),
                    query_string: String::new(),
                    headers: HeaderKeyDict::new(),
                    body: swift_http::Body::empty(),
                },
                &app2,
            )
            .headers
            .get("X-Trans-Id")
            .unwrap()
            .to_string()
        };
        assert_ne!(mk(), mk());
    }
}
