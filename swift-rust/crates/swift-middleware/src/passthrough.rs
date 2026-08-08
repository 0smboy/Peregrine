// Copyright (c) 2026 OpenStack Foundation
//! Named no-op middleware for Paste pipeline names that are registered and
//! claimable as "wired" without changing request semantics.
//!
//! Used so OpenStack-standard pipeline filter names are **not** "unknown /
//! not implemented" — they occupy a pipeline slot and pass through. Real
//! behaviour may live elsewhere (e.g. always-on filters, ops tools).

use swift_http::{Request, Response};

use crate::{Middleware, NextFn};

/// Identity middleware with a stable name for logs/tests.
#[derive(Debug, Clone)]
pub struct NamedPassthrough {
    pub name: String,
}

impl NamedPassthrough {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

impl Middleware for NamedPassthrough {
    fn handle(&self, req: Request, next: &NextFn) -> Response {
        next(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn passes_through() {
        let p = NamedPassthrough::new("slo");
        let next: NextFn = Arc::new(|_r| Response::new(201));
        let req = Request {
            method: "GET".into(),
            path: "/".into(),
            query_string: String::new(),
            headers: swift_http::HeaderKeyDict::new(),
            body: swift_http::Body::empty(),
        };
        assert_eq!(p.handle(req, &next).status, 201);
    }
}
