// Copyright (c) 2026 OpenStack Foundation
//! Lightweight `xprofile` Paste filter — request timing / profiling hooks.
//!
//! Python Swift ships `swift.common.middleware.xprofile` for developer
//! profiling. This port records per-request wall time and optional path
//! prefix match, then injects response headers:
//!
//! * `X-Profile-Duration-Ms` — handler wall time in milliseconds
//! * `X-Profile-Path` — request path (when enabled)
//!
//! Configuration (`[filter:xprofile]`):
//! * `enabled` (default true when filter is in pipeline)
//! * `log_filename` optional path; if set, append one JSON line per request
//! * `profile_path` optional prefix; only profile paths starting with it
//!
//! Always passes the request through — never blocks. Safe for production
//! when duration headers alone are used (log_filename empty).

use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Mutex;
use std::time::Instant;

use swift_http::{Request, Response};

use crate::{Middleware, NextFn};

/// xprofile middleware (always pass-through with timing headers).
pub struct XProfile {
    pub enabled: bool,
    pub profile_path: Option<String>,
    log: Option<Mutex<std::fs::File>>,
    pub add_path_header: bool,
}

impl Default for XProfile {
    fn default() -> Self {
        Self {
            enabled: true,
            profile_path: None,
            log: None,
            add_path_header: true,
        }
    }
}

impl XProfile {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_log_file(mut self, path: &str) -> std::io::Result<Self> {
        let f = OpenOptions::new().create(true).append(true).open(path)?;
        self.log = Some(Mutex::new(f));
        Ok(self)
    }

    fn should_profile(&self, path: &str) -> bool {
        if !self.enabled {
            return false;
        }
        match &self.profile_path {
            None => true,
            Some(p) if p.is_empty() => true,
            Some(p) => path.starts_with(p.as_str()),
        }
    }
}

impl Middleware for XProfile {
    fn handle(&self, req: Request, next: &NextFn) -> Response {
        if !self.should_profile(&req.path) {
            return next(req);
        }
        let method = req.method.clone();
        let path = req.path.clone();
        let start = Instant::now();
        let mut resp = next(req);
        let ms = start.elapsed().as_secs_f64() * 1000.0;
        resp.headers
            .set("X-Profile-Duration-Ms", format!("{ms:.3}"));
        if self.add_path_header {
            resp.headers.set("X-Profile-Path", &path);
        }
        if let Some(log) = &self.log {
            if let Ok(mut f) = log.lock() {
                let line = format!(
                    "{{\"method\":\"{method}\",\"path\":\"{path}\",\"status\":{},\"duration_ms\":{ms:.3}}}\n",
                    resp.status
                );
                let _ = f.write_all(line.as_bytes());
            }
        }
        resp
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn adds_duration_header() {
        let xp = XProfile::new();
        let next: NextFn = Arc::new(|_r| Response::new(200));
        let req = Request {
            method: "GET".into(),
            path: "/v1/a/c/o".into(),
            query_string: String::new(),
            headers: swift_http::HeaderKeyDict::new(),
            body: swift_http::Body::empty(),
        };
        let resp = xp.handle(req, &next);
        assert_eq!(resp.status, 200);
        assert!(resp.headers.get("X-Profile-Duration-Ms").is_some());
        assert_eq!(
            resp.headers.get("X-Profile-Path"),
            Some("/v1/a/c/o")
        );
    }

    #[test]
    fn profile_path_prefix_filters() {
        let mut xp = XProfile::new();
        xp.profile_path = Some("/v1/AUTH_".into());
        let next: NextFn = Arc::new(|_r| Response::new(204));
        let skip = Request {
            method: "GET".into(),
            path: "/healthcheck".into(),
            query_string: String::new(),
            headers: swift_http::HeaderKeyDict::new(),
            body: swift_http::Body::empty(),
        };
        let r = xp.handle(skip, &next);
        assert!(r.headers.get("X-Profile-Duration-Ms").is_none());
        let hit = Request {
            method: "GET".into(),
            path: "/v1/AUTH_test/c".into(),
            query_string: String::new(),
            headers: swift_http::HeaderKeyDict::new(),
            body: swift_http::Body::empty(),
        };
        let r2 = xp.handle(hit, &next);
        assert!(r2.headers.get("X-Profile-Duration-Ms").is_some());
    }
}
