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

//! `bulk` delete, ported from `swift/common/middleware/bulk.py`.
//!
//! A `POST`/`DELETE` with `?bulk-delete` and a newline-separated body of
//! `/<container>/<object>` paths deletes each one via a backend subrequest,
//! returning a JSON (or plain-text) summary: how many were deleted, how many
//! were already gone, and any per-path errors. Objects are processed before
//! containers so a container empties before it is removed.
//!
//! P1a delivers **bulk-delete only**. Honest deferrals / wont-fix-for-P1a:
//! - `?extract-archive` (bulk upload / tar extraction) — not wired; `/info`
//!   must NOT advertise `bulk_upload` until that lands (P1b+).
//! - Periodic whitespace heartbeat on long deletes.
//! - `version_id` handling for versioned objects.

use swift_http::{split_path, Body, HeaderKeyDict, Request, Response};

use crate::{Middleware, NextFn};

/// The `bulk` middleware (delete half).
pub struct Bulk {
    pub max_deletes_per_request: usize,
}

impl Default for Bulk {
    fn default() -> Self {
        Bulk {
            max_deletes_per_request: 10000,
        }
    }
}

/// The tally of a bulk-delete pass.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct BulkDeleteResult {
    pub number_deleted: u64,
    pub number_not_found: u64,
    /// `[path, error-status]` pairs.
    pub errors: Vec<(String, String)>,
}

/// Percent-decode a single path line (`urllib.parse.unquote`).
fn unquote(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (
                (bytes[i + 1] as char).to_digit(16),
                (bytes[i + 2] as char).to_digit(16),
            ) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse the delete body into object names, in the order Python processes
/// them: objects (a name with an internal `/`) first, then containers.
pub fn parse_delete_body(body: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(body);
    let names: Vec<String> = text
        .lines()
        .map(|l| unquote(l.trim()))
        .filter(|l| !l.is_empty())
        .collect();
    let is_object = |name: &str| name.trim_matches('/').contains('/');
    let mut objects: Vec<String> = names.iter().filter(|n| is_object(n)).cloned().collect();
    let containers: Vec<String> = names.iter().filter(|n| !is_object(n)).cloned().collect();
    objects.extend(containers);
    objects
}

impl Bulk {
    pub fn new() -> Self {
        Bulk::default()
    }

    /// Build from a `[filter:bulk]` conf map (`max_deletes_per_request`).
    pub fn from_conf(options: &std::collections::HashMap<String, String>) -> Self {
        let mut b = Bulk::new();
        if let Some(v) = options.get("max_deletes_per_request") {
            if let Ok(n) = v.trim().parse::<usize>() {
                b.max_deletes_per_request = n.max(1);
            }
        }
        b
    }

    fn handle_delete(&self, mut req: Request, next: &NextFn) -> Response {
        let parts = match split_path(&req.path, 2, 3, true) {
            Ok(p) => p,
            Err(_) => return Response::error(404, "Not Found"),
        };
        let version = parts[0].clone().unwrap_or_default();
        let account = parts[1].clone().unwrap_or_default();

        // only newline-separated plain text is accepted
        if let Some(ct) = req.headers.get("Content-Type") {
            if !ct.starts_with("text/plain") {
                return Response::error(406, "Invalid Content-Type");
            }
        }

        // P1-leftover: still buffered — the delete list is read whole (the
        // streaming line-by-line reader is a later pass).
        let names = match req
            .body
            .materialize(swift_core::constraints::MAX_FILE_SIZE as u64)
        {
            Ok(bytes) => parse_delete_body(bytes),
            Err(_) => return Response::error(413, "Request Entity Too Large"),
        };
        if names.len() > self.max_deletes_per_request {
            return Response::error(413, "Maximum Bulk Deletes exceeded");
        }

        // Propagate auth / authorize stamps (Python make_subrequest keeps
        // X-Auth-Token; our pipeline also needs the unspoofable backend stamps).
        let mut sub_headers = HeaderKeyDict::new();
        for key in [
            "X-Auth-Token",
            "X-Storage-Token",
            "X-Backend-Remote-User",
            "X-Backend-Authorize-Override",
            "X-Backend-Swift-Owner",
            "X-Trans-Id",
        ] {
            if let Some(v) = req.headers.get(key) {
                sub_headers.set(key, v);
            }
        }

        let mut result = BulkDeleteResult::default();
        for name in &names {
            let delete_path = format!("/{version}/{account}/{}", name.trim_start_matches('/'));
            let subreq = Request {
                method: "DELETE".to_string(),
                path: delete_path,
                query_string: String::new(),
                headers: sub_headers.clone(),
                body: Body::empty(),
            };
            let resp = next(subreq);
            match resp.status {
                s if (200..300).contains(&s) => result.number_deleted += 1,
                404 => result.number_not_found += 1,
                s => result
                    .errors
                    .push((name.clone(), format!("{s} {}", resp.reason))),
            }
        }

        // final status, matching Python
        let (status, body_note) = if !result.errors.is_empty() {
            (400, "")
        } else if result.number_deleted == 0 && result.number_not_found == 0 {
            (400, "Invalid bulk delete.")
        } else {
            (200, "")
        };

        let summary = serde_json::json!({
            "Number Deleted": result.number_deleted,
            "Number Not Found": result.number_not_found,
            "Response Status": status_line(status),
            "Response Body": body_note,
            "Errors": result.errors.iter().map(|(p, e)| vec![p.clone(), e.clone()]).collect::<Vec<_>>(),
        });
        let mut out = Response::with_body(200, summary.to_string().into_bytes());
        out.headers.set("Content-Type", "application/json");
        out
    }
}

fn status_line(code: u16) -> String {
    format!("{code} {}", swift_http::reason_phrase(code))
}

impl Middleware for Bulk {
    fn handle(&self, req: Request, next: &NextFn) -> Response {
        let is_bulk_delete = req.param("bulk-delete").is_some()
            && (req.method == "POST" || req.method == "DELETE");
        if is_bulk_delete {
            self.handle_delete(req, next)
        } else {
            next(req)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    fn req(body: &str) -> Request {
        let mut h = HeaderKeyDict::new();
        h.set("Content-Type", "text/plain");
        Request {
            method: "POST".into(),
            path: "/v1/AUTH_test".into(),
            query_string: "bulk-delete=1".into(),
            headers: h,
            body: body.as_bytes().to_vec().into(),
        }
    }

    #[test]
    fn test_parse_orders_objects_before_containers() {
        let names = parse_delete_body(b"/c1/obj1\n/c2\n/c1/obj2\n/c3\n");
        assert_eq!(names, vec!["/c1/obj1", "/c1/obj2", "/c2", "/c3"]);
    }

    #[test]
    fn test_bulk_delete_counts() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let calls2 = calls.clone();
        let app = move |r: Request| {
            calls2.lock().unwrap().push(r.path.clone());
            if r.path.ends_with("missing") {
                Response::new(404)
            } else {
                Response::new(204)
            }
        };
        let b = Bulk::new();
        let app: crate::NextFn = Arc::new(app);
        let mut resp = b.handle(req("/c/a\n/c/b\n/c/missing\n"), &app);
        assert_eq!(resp.status, 200);
        let summary: serde_json::Value =
            serde_json::from_slice(resp.body.materialize(u64::MAX).unwrap()).unwrap();
        assert_eq!(summary["Number Deleted"], 2);
        assert_eq!(summary["Number Not Found"], 1);
        assert_eq!(summary["Response Status"], "200 OK");
        // subrequests hit the full paths
        assert_eq!(calls.lock().unwrap()[0], "/v1/AUTH_test/c/a");
    }

    #[test]
    fn test_bulk_delete_copies_auth_headers_to_subrequests() {
        let b = Bulk::new();
        let app: crate::NextFn = Arc::new(|r: Request| {
            assert_eq!(r.headers.get("X-Auth-Token"), Some("auth-token"));
            assert_eq!(r.headers.get("X-Storage-Token"), Some("storage-token"));
            assert_eq!(
                r.headers.get("X-Backend-Remote-User"),
                Some("AUTH_test,AUTH_test:user")
            );
            assert_eq!(
                r.headers.get("X-Backend-Authorize-Override"),
                Some("true")
            );
            Response::new(204)
        });
        let mut request = req("/c/a\n");
        request.headers.set("X-Auth-Token", "auth-token");
        request.headers.set("X-Storage-Token", "storage-token");
        request
            .headers
            .set("X-Backend-Remote-User", "AUTH_test,AUTH_test:user");
        request
            .headers
            .set("X-Backend-Authorize-Override", "true");

        assert_eq!(b.handle(request, &app).status, 200);
    }

    #[test]
    fn test_bulk_delete_errors_yield_400() {
        let app = |r: Request| {
            if r.path.ends_with("boom") {
                Response::new(500)
            } else {
                Response::new(204)
            }
        };
        let b = Bulk::new();
        let app: crate::NextFn = Arc::new(app);
        let mut resp = b.handle(req("/c/ok\n/c/boom\n"), &app);
        let summary: serde_json::Value =
            serde_json::from_slice(resp.body.materialize(u64::MAX).unwrap()).unwrap();
        assert_eq!(summary["Response Status"], "400 Bad Request");
        assert_eq!(summary["Errors"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_empty_body_is_invalid() {
        let b = Bulk::new();
        let app: crate::NextFn = Arc::new(|_r: Request| Response::new(204));
        let mut resp = b.handle(req(""), &app);
        let summary: serde_json::Value =
            serde_json::from_slice(resp.body.materialize(u64::MAX).unwrap()).unwrap();
        assert_eq!(summary["Response Status"], "400 Bad Request");
        assert_eq!(summary["Response Body"], "Invalid bulk delete.");
    }

    #[test]
    fn test_non_bulk_passes_through() {
        let b = Bulk::new();
        let app: crate::NextFn = Arc::new(|_r: Request| Response::new(202));
        let mut r = req("/c/a\n");
        r.query_string = String::new(); // no bulk-delete param
        assert_eq!(b.handle(r, &app).status, 202);
    }
}
