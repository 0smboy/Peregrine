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

//! `crossdomain`: answers `GET /crossdomain.xml` with the configured
//! Flash/Silverlight cross-domain policy document
//! (`swift/common/middleware/crossdomain.py`).

use swift_http::{Request, Response};

use crate::{Middleware, MwPrep, NextFn};

const DEFAULT_POLICY: &str = "<allow-access-from domain=\"*\" secure=\"false\" />";

pub struct Crossdomain {
    /// The `<cross-domain-policy>` inner content.
    pub policy: String,
}

impl Default for Crossdomain {
    fn default() -> Self {
        Crossdomain {
            policy: DEFAULT_POLICY.to_string(),
        }
    }
}

impl Crossdomain {
    fn policy_response(&self) -> Response {
        let body = format!(
            "<?xml version=\"1.0\"?>\n\
             <!DOCTYPE cross-domain-policy SYSTEM \
             \"http://www.adobe.com/xml/dtds/cross-domain-policy.dtd\" >\n\
             <cross-domain-policy>\n{}\n</cross-domain-policy>",
            self.policy
        );
        let mut resp = Response::with_body(200, body.into_bytes());
        resp.headers.set("Content-Type", "application/xml");
        resp
    }
}

impl Middleware for Crossdomain {
    fn prepare(&self, req: &mut Request) -> MwPrep {
        if req.path == "/crossdomain.xml" {
            MwPrep::ShortCircuit(self.policy_response())
        } else {
            MwPrep::Continue
        }
    }

    fn handle(&self, mut req: Request, next: &NextFn) -> Response {
        match self.prepare(&mut req) {
            MwPrep::ShortCircuit(resp) => resp,
            MwPrep::Continue => next(req),
        }
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
    fn test_crossdomain() {
        let cd = Crossdomain::default();
        let app: Arc<dyn Fn(Request) -> Response + Send + Sync> = Arc::new(|_r| Response::new(404));
        let mut resp = cd.handle(req("/crossdomain.xml"), &app);
        assert_eq!(resp.status, 200);
        let body = String::from_utf8_lossy(resp.body.materialize(u64::MAX).unwrap()).into_owned();
        assert!(body.contains("<cross-domain-policy>"), "{body}");
        assert!(body.contains("allow-access-from"), "{body}");
        assert_eq!(resp.headers.get("Content-Type"), Some("application/xml"));

        // other paths pass through
        let app: Arc<dyn Fn(Request) -> Response + Send + Sync> = Arc::new(|_r| Response::new(204));
        assert_eq!(cd.handle(req("/v1/a"), &app).status, 204);
    }

    #[test]
    fn test_prepare_short_circuits_crossdomain_xml() {
        let cd = Crossdomain::default();
        let mut request = req("/crossdomain.xml");
        match cd.prepare(&mut request) {
            MwPrep::ShortCircuit(mut resp) => {
                assert_eq!(resp.status, 200);
                let body =
                    String::from_utf8_lossy(resp.body.materialize(u64::MAX).unwrap()).into_owned();
                assert!(body.contains("<cross-domain-policy>"), "{body}");
                assert_eq!(resp.headers.get("Content-Type"), Some("application/xml"));
            }
            MwPrep::Continue => panic!("GET /crossdomain.xml must short-circuit on Hyper prepare"),
        }
        let mut other = req("/v1/a");
        assert!(matches!(cd.prepare(&mut other), MwPrep::Continue));
    }
}
