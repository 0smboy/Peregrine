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

//! `bulk` delete + extract-archive, ported from `swift/common/middleware/bulk.py`.
//!
//! * **Delete:** `POST`/`DELETE` with `?bulk-delete` and a newline-separated body of
//!   `/<container>/<object>` paths.
//! * **Upload:** `PUT` with `?extract-archive={tar|tar.gz|tar.bz2}` expands the
//!   request body archive into object PUTs under the target account/container.
//!
//! Heartbeat whitespace on long runs and version_id-aware delete remain deferred.

use std::collections::HashSet;
use std::io::{Cursor, Read};

use flate2::read::GzDecoder;
use tar::Archive;

use swift_core::constraints::MAX_FILE_SIZE;
use swift_http::{split_path, Body, HeaderKeyDict, Request, Response};

use crate::{Middleware, NextFn};

/// The `bulk` middleware (delete + extract-archive).
pub struct Bulk {
    pub max_deletes_per_request: usize,
    pub max_containers_per_extraction: usize,
    pub max_failed_extractions: usize,
}

impl Default for Bulk {
    fn default() -> Self {
        Bulk {
            max_deletes_per_request: 10000,
            max_containers_per_extraction: 10000,
            max_failed_extractions: 1000,
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

    /// Build from a `[filter:bulk]` conf map.
    pub fn from_conf(options: &std::collections::HashMap<String, String>) -> Self {
        let mut b = Bulk::new();
        if let Some(v) = options.get("max_deletes_per_request") {
            if let Ok(n) = v.trim().parse::<usize>() {
                b.max_deletes_per_request = n.max(1);
            }
        }
        if let Some(v) = options.get("max_containers_per_extraction") {
            if let Ok(n) = v.trim().parse::<usize>() {
                b.max_containers_per_extraction = n.max(1);
            }
        }
        if let Some(v) = options.get("max_failed_extractions") {
            if let Ok(n) = v.trim().parse::<usize>() {
                b.max_failed_extractions = n.max(1);
            }
        }
        b
    }

    /// `/info` fragment for bulk_upload when extract-archive is available.
    pub fn upload_info_dict(&self) -> serde_json::Value {
        serde_json::json!({
            "max_containers_per_extraction": self.max_containers_per_extraction,
            "max_failed_extractions": self.max_failed_extractions,
        })
    }

    fn auth_sub_headers(req: &Request) -> HeaderKeyDict {
        let mut sub_headers = HeaderKeyDict::new();
        for key in [
            "X-Auth-Token",
            "X-Storage-Token",
            "X-Backend-Remote-User",
            "X-Backend-Authorize-Override",
            "X-Backend-Swift-Owner",
            "X-Trans-Id",
            "X-Delete-At",
            "X-Delete-After",
        ] {
            if let Some(v) = req.headers.get(key) {
                sub_headers.set(key, v);
            }
        }
        // User object metadata from the outer extract request.
        for (k, v) in req.headers.iter() {
            let lower = k.to_ascii_lowercase();
            if lower.starts_with("x-object-meta-") {
                sub_headers.set(k, v);
            }
        }
        sub_headers
    }

    fn create_container_if_needed(
        &self,
        cont_path: &str,
        sub_headers: &HeaderKeyDict,
        next: &NextFn,
    ) -> Result<bool, (u16, String)> {
        let head = Request {
            method: "HEAD".into(),
            path: cont_path.to_string(),
            query_string: String::new(),
            headers: sub_headers.clone(),
            body: Body::empty(),
        };
        let resp = next(head);
        if (200..300).contains(&resp.status) {
            return Ok(false);
        }
        if resp.status != 404 {
            return Err((resp.status, resp.reason.clone()));
        }
        let put = Request {
            method: "PUT".into(),
            path: cont_path.to_string(),
            query_string: String::new(),
            headers: sub_headers.clone(),
            body: Body::empty(),
        };
        let resp = next(put);
        if (200..300).contains(&resp.status) {
            return Ok(true);
        }
        Err((resp.status, resp.reason.clone()))
    }

    fn handle_extract(&self, mut req: Request, next: &NextFn, compress: &str) -> Response {
        let parts = match split_path(&req.path, 2, 3, true) {
            Ok(p) => p,
            Err(_) => return Response::error(404, "Not Found"),
        };
        let version = parts[0].clone().unwrap_or_default();
        let account = parts[1].clone().unwrap_or_default();
        let extract_base = parts[2]
            .clone()
            .unwrap_or_default()
            .trim_matches('/')
            .to_string();

        let archive_bytes = match req
            .body
            .materialize(MAX_FILE_SIZE as u64)
        {
            Ok(b) => b.to_vec(),
            Err(_) => return Response::error(413, "Request Entity Too Large"),
        };

        let decoded: Result<Vec<u8>, String> = match compress {
            "" => Ok(archive_bytes),
            "gz" => {
                let mut d = GzDecoder::new(Cursor::new(archive_bytes));
                let mut out = Vec::new();
                d.read_to_end(&mut out)
                    .map_err(|e| format!("Invalid Tar File: {e}"))
                    .map(|_| out)
            }
            "bz2" => {
                let mut d = bzip2::read::BzDecoder::new(Cursor::new(archive_bytes));
                let mut out = Vec::new();
                d.read_to_end(&mut out)
                    .map_err(|e| format!("Invalid Tar File: {e}"))
                    .map(|_| out)
            }
            _ => Err("Unsupported extract-archive format".into()),
        };

        let tar_bytes = match decoded {
            Ok(b) => b,
            Err(msg) => {
                let summary = serde_json::json!({
                    "Number Files Created": 0,
                    "Response Status": "400 Bad Request",
                    "Response Body": msg,
                    "Errors": [],
                });
                let mut out = Response::with_body(200, summary.to_string().into_bytes());
                out.headers.set("Content-Type", "application/json");
                return out;
            }
        };

        let mut archive = Archive::new(Cursor::new(tar_bytes));
        let sub_headers = Self::auth_sub_headers(&req);
        let mut number_created: u64 = 0;
        let mut errors: Vec<(String, String)> = Vec::new();
        let mut containers_accessed: HashSet<String> = HashSet::new();
        let mut containers_created: usize = 0;
        let mut failed_status_line = String::from("400 Bad Request");

        let entries = match archive.entries() {
            Ok(e) => e,
            Err(e) => {
                let summary = serde_json::json!({
                    "Number Files Created": 0,
                    "Response Status": "400 Bad Request",
                    "Response Body": format!("Invalid Tar File: {e}"),
                    "Errors": [],
                });
                let mut out = Response::with_body(200, summary.to_string().into_bytes());
                out.headers.set("Content-Type", "application/json");
                return out;
            }
        };

        for entry in entries {
            if errors.len() >= self.max_failed_extractions {
                break;
            }
            let mut entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    errors.push((String::new(), format!("Invalid Tar File: {e}")));
                    continue;
                }
            };
            if !entry.header().entry_type().is_file() {
                continue;
            }
            let path = match entry.path() {
                Ok(p) => p.to_string_lossy().into_owned(),
                Err(_) => {
                    errors.push((String::new(), "400 Bad Request".into()));
                    continue;
                }
            };
            let mut obj_path = path;
            if let Some(rest) = obj_path.strip_prefix("./") {
                obj_path = rest.to_string();
            }
            obj_path = obj_path.trim_start_matches('/').to_string();
            if !extract_base.is_empty() {
                obj_path = format!("{extract_base}/{obj_path}");
            }
            if !obj_path.contains('/') {
                continue; // base-level file without container — ignore (Python)
            }
            let size = entry.header().size().unwrap_or(0);
            if size as i64 > MAX_FILE_SIZE {
                errors.push((obj_path, "413 Request Entity Too Large".into()));
                continue;
            }
            let container = obj_path.split('/').next().unwrap_or("").to_string();
            let cont_path = format!("/{version}/{account}/{container}");
            if !containers_accessed.contains(&container) {
                match self.create_container_if_needed(&cont_path, &sub_headers, next) {
                    Ok(true) => {
                        containers_created += 1;
                        if containers_created > self.max_containers_per_extraction {
                            let summary = serde_json::json!({
                                "Number Files Created": number_created,
                                "Response Status": "400 Bad Request",
                                "Response Body": format!(
                                    "More than {} containers to create from tar.",
                                    self.max_containers_per_extraction
                                ),
                                "Errors": errors.iter().map(|(p,e)| vec![p.clone(), e.clone()]).collect::<Vec<_>>(),
                            });
                            let mut out = Response::with_body(200, summary.to_string().into_bytes());
                            out.headers.set("Content-Type", "application/json");
                            return out;
                        }
                    }
                    Ok(false) => {}
                    Err((401, _)) => {
                        return Response::error(401, "Unauthorized");
                    }
                    Err((st, reason)) => {
                        // Python still tries the object PUT; record container failure.
                        errors.push((cont_path.clone(), format!("{st} {reason}")));
                    }
                }
                containers_accessed.insert(container);
            }

            let mut file_bytes = Vec::new();
            if let Err(e) = entry.read_to_end(&mut file_bytes) {
                errors.push((obj_path, format!("Invalid Tar File: {e}")));
                continue;
            }
            let destination = format!("/{version}/{account}/{obj_path}");
            let mut put_headers = sub_headers.clone();
            put_headers.set("Content-Length", file_bytes.len().to_string());
            let put = Request {
                method: "PUT".into(),
                path: destination,
                query_string: String::new(),
                headers: put_headers,
                body: file_bytes.into(),
            };
            let resp = next(put);
            if (200..300).contains(&resp.status) {
                number_created += 1;
            } else {
                if resp.status == 401 {
                    return Response::error(401, "Unauthorized");
                }
                if (500..600).contains(&resp.status) {
                    failed_status_line = status_line(resp.status);
                }
                errors.push((obj_path, format!("{} {}", resp.status, resp.reason)));
            }
        }

        let (status_line_s, body_note) = if !errors.is_empty() {
            (failed_status_line, String::new())
        } else if number_created == 0 {
            (
                "400 Bad Request".to_string(),
                "Invalid Tar File: No Valid Files".to_string(),
            )
        } else {
            ("201 Created".to_string(), String::new())
        };

        let summary = serde_json::json!({
            "Number Files Created": number_created,
            "Response Status": status_line_s,
            "Response Body": body_note,
            "Errors": errors.iter().map(|(p, e)| vec![p.clone(), e.clone()]).collect::<Vec<_>>(),
        });
        let mut out = Response::with_body(200, summary.to_string().into_bytes());
        out.headers.set("Content-Type", "application/json");
        out
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

        let sub_headers = Self::auth_sub_headers(&req);

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

/// Map `?extract-archive=` value to tar compress mode (`""`, `"gz"`, `"bz2"`).
fn extract_compress_type(raw: &str) -> Option<&'static str> {
    match raw.trim().trim_start_matches('.').to_ascii_lowercase().as_str() {
        "tar" => Some(""),
        "tar.gz" | "tgz" => Some("gz"),
        "tar.bz2" | "tbz2" | "tbz" => Some("bz2"),
        _ => None,
    }
}

impl Middleware for Bulk {
    fn handle(&self, req: Request, next: &NextFn) -> Response {
        if req.method == "PUT" {
            if let Some(fmt) = req.param("extract-archive") {
                return match extract_compress_type(&fmt) {
                    Some(compress) => self.handle_extract(req, next, compress),
                    None => Response::error(400, "Unsupported extract-archive format"),
                };
            }
        }
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

    fn make_tar_with_file(name: &str, data: &[u8]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_path(name).unwrap();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append(&header, data).unwrap();
        builder.into_inner().unwrap()
    }

    #[test]
    fn test_extract_archive_tar_puts_objects() {
        let tar_bytes = make_tar_with_file("cont/obj1.txt", b"hello-bulk");
        let calls = Arc::new(Mutex::new(Vec::new()));
        let calls2 = calls.clone();
        let app: crate::NextFn = Arc::new(move |r: Request| {
            calls2
                .lock()
                .unwrap()
                .push((r.method.clone(), r.path.clone()));
            if r.method == "HEAD" {
                Response::new(404)
            } else if r.method == "PUT" && r.path.ends_with("/cont") {
                Response::new(201)
            } else if r.method == "PUT" {
                Response::new(201)
            } else {
                Response::new(404)
            }
        });
        let b = Bulk::new();
        let mut r = Request {
            method: "PUT".into(),
            path: "/v1/AUTH_test".into(),
            query_string: "extract-archive=tar".into(),
            headers: HeaderKeyDict::new(),
            body: tar_bytes.into(),
        };
        r.headers.set("X-Auth-Token", "t");
        let mut resp = b.handle(r, &app);
        assert_eq!(resp.status, 200);
        let summary: serde_json::Value =
            serde_json::from_slice(resp.body.materialize(u64::MAX).unwrap()).unwrap();
        assert_eq!(summary["Number Files Created"], 1);
        assert_eq!(summary["Response Status"], "201 Created");
        let paths: Vec<_> = calls
            .lock()
            .unwrap()
            .iter()
            .map(|(_, p)| p.clone())
            .collect();
        assert!(
            paths.iter().any(|p| p == "/v1/AUTH_test/cont/obj1.txt"),
            "paths={paths:?}"
        );
    }

    #[test]
    fn test_extract_archive_tar_gz() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;
        let tar_bytes = make_tar_with_file("c/a", b"z");
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(&tar_bytes).unwrap();
        let gz = enc.finish().unwrap();
        let app: crate::NextFn = Arc::new(|r: Request| {
            if r.method == "HEAD" {
                Response::new(204)
            } else {
                Response::new(201)
            }
        });
        let b = Bulk::new();
        let r = Request {
            method: "PUT".into(),
            path: "/v1/AUTH_test".into(),
            query_string: "extract-archive=tar.gz".into(),
            headers: HeaderKeyDict::new(),
            body: gz.into(),
        };
        let mut resp = b.handle(r, &app);
        let summary: serde_json::Value =
            serde_json::from_slice(resp.body.materialize(u64::MAX).unwrap()).unwrap();
        assert_eq!(summary["Number Files Created"], 1);
    }

    #[test]
    fn test_extract_unsupported_format() {
        let b = Bulk::new();
        let app: crate::NextFn = Arc::new(|_r: Request| Response::new(201));
        let r = Request {
            method: "PUT".into(),
            path: "/v1/AUTH_test".into(),
            query_string: "extract-archive=zip".into(),
            headers: HeaderKeyDict::new(),
            body: b"x".to_vec().into(),
        };
        assert_eq!(b.handle(r, &app).status, 400);
    }
}
