// Copyright (c) 2026 OpenStack Foundation
//! Named no-op middleware for **known** pipeline filter names that should
//! occupy a slot without changing request semantics.
//!
//! # Honesty
//!
//! [`NamedPassthrough`] is **not** a third-party PasteDeploy / egg / shared-library
//! ABI. Unknown filter names are skipped (or fail closed under
//! `strict_pipeline=true` + `plugin_default=skip`). Deliberate no-op for a
//! *configured* alias requires an explicit passthrough path — it is still an
//! in-process Rust stub, not Python Paste plugin loading.
//!
//! Used so selected OpenStack-standard names can sit in `pipeline=` without
//! being reported as unknown. Real behaviour may live elsewhere (always-on
//! filters, ops tools).

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
