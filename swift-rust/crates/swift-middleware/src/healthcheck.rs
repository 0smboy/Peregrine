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

//! `healthcheck`: answers `/healthcheck` with `200 OK`, or `503 DISABLED
//! BY FILE` when the configured `disable_path` exists.

use std::path::PathBuf;

use swift_http::{Request, Response};

use crate::{Middleware, NextFn};

#[derive(Default)]
pub struct HealthCheck {
    pub disable_path: Option<PathBuf>,
}

impl Middleware for HealthCheck {
    fn handle(&self, req: Request, next: &NextFn) -> Response {
        if req.path == "/healthcheck" {
            let disabled = self.disable_path.as_ref().is_some_and(|p| p.exists());
            let mut resp = if disabled {
                Response::with_body(503, b"DISABLED BY FILE".to_vec())
            } else {
                Response::with_body(200, b"OK".to_vec())
            };
            resp.headers.set("Content-Type", "text/plain");
            return resp;
        }
        next(req)
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

    #[test]
    fn test_healthcheck() {
        let hc = HealthCheck::default();
        let app: Arc<dyn Fn(Request) -> Response + Send + Sync> = Arc::new(|_r| Response::new(404));
        let mut resp = hc.handle(req("/healthcheck"), &app);
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body.materialize(u64::MAX).unwrap(), b"OK");
        assert_eq!(resp.headers.get("Content-Type"), Some("text/plain"));

        // non-healthcheck passes through
        let app: Arc<dyn Fn(Request) -> Response + Send + Sync> = Arc::new(|_r| Response::new(204));
        let resp = hc.handle(req("/v1/a"), &app);
        assert_eq!(resp.status, 204);
    }

    #[test]
    fn test_disabled() {
        let dir = std::env::temp_dir().join(format!("swift-hc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let flag = dir.join("disabled");
        std::fs::write(&flag, b"").unwrap();
        let hc = HealthCheck {
            disable_path: Some(flag),
        };
        let app: Arc<dyn Fn(Request) -> Response + Send + Sync> = Arc::new(|_r| Response::new(404));
        let mut resp = hc.handle(req("/healthcheck"), &app);
        assert_eq!(resp.status, 503);
        assert_eq!(
            resp.body.materialize(u64::MAX).unwrap(),
            b"DISABLED BY FILE"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
