// Copyright (c) 2026 OpenStack Foundation
//! `list_endpoints` middleware — advertise ring endpoints for a path.
//!
//! Python: `swift.common.middleware.list_endpoints`. On `GET
//! /endpoints/<account>/<container>/<object>` (or configured path root),
//! returns a JSON list of primary backend URLs from a provided resolver.
//!
//! Without a ring resolver, returns `501 Not Implemented` with a clear body
//! when the path matches the endpoints prefix; other paths pass through.
//! Tests inject a fixed resolver.
//!
//! The [`EndpointResolver`] signature matches the proxy tip (`Option` container
//! / object + policy index) so `ProxyEndpointResolver` can implement it.

use std::sync::Arc;

use swift_http::{Request, Response};

use crate::{Middleware, NextFn};

/// Resolve account/container/object → backend endpoint URL strings.
///
/// The optional integer is the container storage-policy index (object paths).
pub trait EndpointResolver: Send + Sync {
    fn endpoints(
        &self,
        account: &str,
        container: Option<&str>,
        object: Option<&str>,
    ) -> Result<(Vec<String>, Option<i64>), String>;
}

/// Fixed list for tests / offline.
pub struct StaticEndpoints(pub Vec<String>);

impl EndpointResolver for StaticEndpoints {
    fn endpoints(
        &self,
        _account: &str,
        _container: Option<&str>,
        _object: Option<&str>,
    ) -> Result<(Vec<String>, Option<i64>), String> {
        Ok((self.0.clone(), None))
    }
}

/// list_endpoints filter.
pub struct ListEndpoints {
    /// Path prefix including leading slash, default `/endpoints/`.
    pub path_root: String,
    pub resolver: Option<Arc<dyn EndpointResolver>>,
}

impl Default for ListEndpoints {
    fn default() -> Self {
        Self {
            path_root: "/endpoints/".into(),
            resolver: None,
        }
    }
}

impl ListEndpoints {
    pub fn new(resolver: Arc<dyn EndpointResolver>) -> Self {
        Self {
            path_root: "/endpoints/".into(),
            resolver: Some(resolver),
        }
    }

    pub fn with_path_root(mut self, path_root: impl Into<String>) -> Self {
        let path_root = path_root.into();
        self.path_root = format!("{}/", path_root.trim_end_matches('/'));
        self
    }

    pub fn with_resolver(mut self, r: Arc<dyn EndpointResolver>) -> Self {
        self.resolver = Some(r);
        self
    }
}

impl Middleware for ListEndpoints {
    fn handle(&self, req: Request, next: &NextFn) -> Response {
        let root = if self.path_root.ends_with('/') {
            self.path_root.clone()
        } else {
            format!("{}/", self.path_root)
        };
        if !req.path.starts_with(&root) {
            return next(req);
        }
        if req.method != "GET" && req.method != "HEAD" {
            return Response::error(405, "Method Not Allowed");
        }
        let rest = &req.path[root.len()..];
        let parts: Vec<&str> = rest.split('/').filter(|s| !s.is_empty()).collect();
        let (version, offset) = match parts.first().copied() {
            Some("1" | "v1" | "1.0" | "v1.0") => (1, 1),
            Some("2" | "v2" | "2.0" | "v2.0") => (2, 1),
            Some(candidate) if candidate.starts_with('v') && !candidate.contains('_') => {
                return Response::error(400, &format!("Unsupported version {candidate:?}"));
            }
            Some(_) => (1, 0),
            None => return Response::error(400, "No account specified"),
        };
        let Some(account) = parts.get(offset).copied() else {
            return Response::error(400, "No account specified");
        };
        let container = parts.get(offset + 1).copied();
        let object = if parts.len() > offset + 2 {
            Some(parts[offset + 2..].join("/"))
        } else {
            None
        };
        let Some(resolver) = &self.resolver else {
            return Response::error(
                501,
                "list_endpoints: no ring resolver configured on this proxy",
            );
        };
        let (eps, policy) = match resolver.endpoints(account, container, object.as_deref()) {
            Ok(result) => result,
            Err(err) => return Response::error(400, &err),
        };
        let body = if version == 2 {
            let mut response = serde_json::json!({
                "endpoints": eps,
                "headers": {},
            });
            if let Some(policy) = policy {
                response["headers"]["X-Backend-Storage-Policy-Index"] =
                    serde_json::json!(policy.to_string());
            }
            serde_json::to_vec(&response).unwrap_or_else(|_| b"{}".to_vec())
        } else {
            serde_json::to_vec(&eps).unwrap_or_else(|_| b"[]".to_vec())
        };
        let mut r = Response::with_body(200, body);
        r.headers.set("Content-Type", "application/json");
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn returns_json_endpoints() {
        let le = ListEndpoints::new(Arc::new(StaticEndpoints(vec![
            "http://127.0.0.1:6200/sdb1".into(),
            "http://127.0.0.1:6200/sdb2".into(),
        ])));
        let next: NextFn = Arc::new(|_r| Response::new(500));
        let req = Request {
            method: "GET".into(),
            path: "/endpoints/a/c/o".into(),
            query_string: String::new(),
            headers: swift_http::HeaderKeyDict::new(),
            body: swift_http::Body::empty(),
        };
        let mut resp = le.handle(req, &next);
        assert_eq!(resp.status, 200);
        let b = resp.body.materialize(u64::MAX).unwrap();
        let v: Vec<String> = serde_json::from_slice(b).unwrap();
        assert_eq!(v.len(), 2);
    }

    #[test]
    fn passthrough_other_paths() {
        let le = ListEndpoints::default();
        let next: NextFn = Arc::new(|_r| Response::new(204));
        let req = Request {
            method: "GET".into(),
            path: "/v1/a/c".into(),
            query_string: String::new(),
            headers: swift_http::HeaderKeyDict::new(),
            body: swift_http::Body::empty(),
        };
        assert_eq!(le.handle(req, &next).status, 204);
    }

    #[test]
    fn configured_path_root_is_canonical_and_routes() {
        let le = ListEndpoints::new(Arc::new(StaticEndpoints(vec![
            "http://127.0.0.1:6200/sdb1".into(),
        ])))
        .with_path_root("/where//");
        assert_eq!(le.path_root, "/where/");

        let next: NextFn = Arc::new(|_r| Response::new(500));
        let req = Request {
            method: "GET".into(),
            path: "/where/a/c/o".into(),
            query_string: String::new(),
            headers: swift_http::HeaderKeyDict::new(),
            body: swift_http::Body::empty(),
        };
        assert_eq!(le.handle(req, &next).status, 200);
    }

    #[test]
    fn v2_account_response_has_endpoints_and_headers_shape() {
        let le = ListEndpoints::new(Arc::new(StaticEndpoints(vec![
            "http://127.0.0.1:6200/sdb1".into(),
        ])))
        .with_path_root("/where");
        let next: NextFn = Arc::new(|_r| Response::new(500));
        let req = Request {
            method: "GET".into(),
            path: "/where/v2/a".into(),
            query_string: String::new(),
            headers: swift_http::HeaderKeyDict::new(),
            body: swift_http::Body::empty(),
        };
        let mut response = le.handle(req, &next);
        assert_eq!(response.status, 200);
        let body: serde_json::Value =
            serde_json::from_slice(response.body.materialize(u64::MAX).unwrap()).unwrap();
        assert_eq!(
            body,
            serde_json::json!({
                "endpoints": ["http://127.0.0.1:6200/sdb1"],
                "headers": {},
            })
        );
    }
}
