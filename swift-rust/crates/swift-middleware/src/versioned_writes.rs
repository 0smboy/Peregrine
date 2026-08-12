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

//! `versioned_writes` (legacy stack + history modes), ported from
//! `swift/common/middleware/versioned_writes/legacy.py`.
//!
//! A container flagged with `X-Versions-Location` (stack) or
//! `X-History-Location` (history) keeps prior object contents in a versions
//! container. Stack mode restores the newest archive on `DELETE`; history
//! mode archives the current object and writes a delete-marker before the
//! delete proceeds.
//!
//! Archive name interoperability contract (golden-tested):
//! `"{len(object):03x}{object}/{Timestamp(ts).internal}"`.
//!
//! Container `PUT`/`POST` translates client `X-Versions-Location` /
//! `X-History-Location` into sysmeta when `allow_versioned_writes` is true.
//!
//! Deferred / wontfix:
//! * `swift.authorize` write-ACL recheck before archive (no authorize hook).
//! * In-proxy reverse-listing fallback for pre-2.6.0 container servers
//!   (listing uses `reverse=on` only).

use swift_core::config::config_true_value;
use swift_core::constraints::check_container_format;
use swift_core::timestamp::Timestamp;
use swift_http::{split_path, Body, Request, Response, MAX_CONTROL_BODY};

use crate::{Middleware, NextFn};

const DELETE_MARKER_CONTENT_TYPE: &str = "application/x-deleted;swift_versions_deleted=1";
const SYSMETA_VERSIONS_LOC: &str = "X-Container-Sysmeta-Versions-Location";
const SYSMETA_VERSIONS_MODE: &str = "X-Container-Sysmeta-Versions-Mode";

/// Trusted, internal authorization probe understood by the terminal proxy.
///
/// Gatekeeper must strip this header from client requests. The terminal app
/// authorizes then returns without backend I/O (normally 204).
pub const AUTHORIZE_ONLY_HEADER: &str = "X-Backend-Versioned-Writes-Authorize-Only";

/// The `versioned_writes` middleware.
pub struct VersionedWrites {
    /// When set (true/false), this middleware owns enablement. When `None`,
    /// object versioning still runs if the container already has a location
    /// (legacy container-server `allow_versions` compatibility).
    pub allow_versioned_writes: Option<bool>,
    /// Whether the terminal proxy implements [`AUTHORIZE_ONLY_HEADER`].
    /// False is the only safe default.
    authorization_probe_supported: bool,
}

impl Default for VersionedWrites {
    fn default() -> Self {
        VersionedWrites {
            allow_versioned_writes: Some(true),
            authorization_probe_supported: false,
        }
    }
}

impl VersionedWrites {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_conf(allow: Option<&str>) -> Self {
        VersionedWrites {
            allow_versioned_writes: allow.map(config_true_value),
            authorization_probe_supported: false,
        }
    }

    pub fn with_authorization_probe(mut self, supported: bool) -> Self {
        self.authorization_probe_supported = supported;
        self
    }
}

/// Archive object name for a prior version.
pub fn versions_object_name(object_name: &str, ts: &str) -> Option<String> {
    let internal = ts.parse::<Timestamp>().ok()?.internal();
    let len = object_name.chars().count();
    Some(format!("{len:03x}{object_name}/{internal}"))
}

/// Listing prefix for an object's archives.
pub fn versions_object_prefix(object_name: &str) -> String {
    let len = object_name.chars().count();
    format!("{len:03x}{object_name}/")
}

struct VersionCfg {
    location: String,
    mode: String, // "stack" | "history"
}

/// Build an internal subrequest that carries the caller's auth and bypasses
/// TempAuth re-checks (`make_pre_authed_request` stand-in).
fn pre_authed(method: &str, path: &str, from: &Request) -> Request {
    let mut sub = from.clone_head();
    sub.method = method.to_string();
    sub.path = path.to_string();
    sub.query_string = String::new();
    sub.headers.remove("Content-Length");
    sub.headers.remove("X-If-Delete-At");
    sub.headers.set("X-Backend-Authorize-Override", "true");
    sub.headers.set("X-Backend-Source", "VW");
    sub
}

impl VersionedWrites {
    fn is_enabled(&self, has_legacy_versions: bool) -> bool {
        match self.allow_versioned_writes {
            Some(v) => v,
            None => has_legacy_versions,
        }
    }

    fn copy_current_then_continue(
        &self,
        req: Request,
        version: &str,
        account: &str,
        object: &str,
        versions_cont: &str,
        next: &NextFn,
    ) -> Result<Request, Response> {
        let get_req = pre_authed("GET", &req.path, &req);
        let current = next(get_req);
        if current.status == 404 {
            return Ok(req);
        }
        if !(200..300).contains(&current.status) {
            return Err(current);
        }
        let ts_source = current
            .headers
            .get("X-Timestamp")
            .map(|s| s.to_string())
            .unwrap_or_else(|| "0".to_string());
        let Some(vers_name) = versions_object_name(object, &ts_source) else {
            return Ok(req);
        };
        let (current_reader, current_len) = current.body.into_reader();
        let mut archive = pre_authed(
            "PUT",
            &format!("/{version}/{account}/{versions_cont}/{vers_name}"),
            &req,
        );
        archive.body = Body::from_reader(current_reader, current_len);
        if let Some(ct) = current.headers.get("Content-Type") {
            archive.headers.set("Content-Type", ct);
        }
        if let Some(len) = current_len {
            archive.headers.set("Content-Length", len.to_string());
        }
        let archive_resp = next(archive);
        if !(200..300).contains(&archive_resp.status) {
            return Err(archive_resp);
        }
        Ok(req)
    }

    fn handle_put(
        &self,
        req: Request,
        version: &str,
        account: &str,
        object: &str,
        versions_cont: &str,
        next: &NextFn,
    ) -> Response {
        match self.copy_current_then_continue(req, version, account, object, versions_cont, next) {
            Ok(req) => next(req),
            Err(resp) => resp,
        }
    }

    fn handle_delete_history(
        &self,
        req: Request,
        version: &str,
        account: &str,
        object: &str,
        versions_cont: &str,
        next: &NextFn,
    ) -> Response {
        let req = match self
            .copy_current_then_continue(req, version, account, object, versions_cont, next)
        {
            Ok(r) => r,
            Err(resp) => return resp,
        };
        let marker_name = versions_object_name(object, &Timestamp::now().internal())
            .unwrap_or_else(|| format!("{}marker", versions_object_prefix(object)));
        let mut marker = pre_authed(
            "PUT",
            &format!("/{version}/{account}/{versions_cont}/{marker_name}"),
            &req,
        );
        marker
            .headers
            .set("Content-Type", DELETE_MARKER_CONTENT_TYPE);
        marker.headers.set("Content-Length", "0");
        let marker_resp = next(marker);
        if !(200..300).contains(&marker_resp.status) {
            return marker_resp;
        }
        next(req)
    }

    fn handle_delete_stack(
        &self,
        mut req: Request,
        version: &str,
        account: &str,
        container: &str,
        object: &str,
        versions_cont: &str,
        next: &NextFn,
    ) -> Response {
        let prefix = versions_object_prefix(object);
        let mut list_req = pre_authed(
            "GET",
            &format!("/{version}/{account}/{versions_cont}"),
            &req,
        );
        list_req.query_string =
            format!("prefix={}&reverse=on&format=json", quote_path(&prefix));
        let mut list_resp = next(list_req);
        if list_resp.status == 404 {
            return next(req);
        }
        if !(200..300).contains(&list_resp.status) {
            return list_resp;
        }
        let listing = match list_resp.body.materialize(MAX_CONTROL_BODY) {
            Ok(b) => b.to_vec(),
            Err(_) => return Response::error(500, "Internal Error"),
        };
        let items = parse_listing_json(&listing);
        if items.is_empty() {
            return next(req);
        }

        // Walk newest-first (reverse=on). Skip missing archives.
        let mut idx = 0;
        while idx < items.len() {
            let item = &items[idx];
            idx += 1;
            if item.content_type == DELETE_MARKER_CONTENT_TYPE {
                // If current object exists, just delete it (restore to marker).
                let mut head = pre_authed("HEAD", &req.path, &req);
                head.headers.set("X-Newest", "True");
                let hresp = next(head);
                if hresp.status != 404 {
                    if !(200..300).contains(&hresp.status) {
                        return hresp;
                    }
                    break;
                }
                // No current data — find next non-marker to restore.
                let mut restored_path: Option<String> = None;
                while idx < items.len() {
                    let restore = &items[idx];
                    idx += 1;
                    if restore.content_type == DELETE_MARKER_CONTENT_TYPE {
                        break;
                    }
                    if let Some(path) = self.restore_data(
                        &req,
                        version,
                        account,
                        container,
                        object,
                        versions_cont,
                        &restore.name,
                        next,
                    ) {
                        // Delete the archive we restored from.
                        let del = pre_authed("DELETE", &path, &req);
                        let del_resp = next(del);
                        if del_resp.status != 404 && !(200..300).contains(&del_resp.status) {
                            return del_resp;
                        }
                        restored_path = Some(path);
                        break;
                    }
                }
                let _ = restored_path;
                // Redirect original DELETE to the delete-marker archive.
                req = pre_authed(
                    "DELETE",
                    &format!("/{version}/{account}/{versions_cont}/{}", item.name),
                    &req,
                );
                break;
            } else {
                // Restore previous version into place, then DELETE the archive.
                if let Some(restored_path) = self.restore_data(
                    &req,
                    version,
                    account,
                    container,
                    object,
                    versions_cont,
                    &item.name,
                    next,
                ) {
                    req = pre_authed("DELETE", &restored_path, &req);
                    break;
                }
                // Archive vanished — try next.
                continue;
            }
        }
        req.headers.remove("X-If-Delete-At");
        next(req)
    }

    fn restore_data(
        &self,
        auth_from: &Request,
        version: &str,
        account: &str,
        container: &str,
        object: &str,
        versions_cont: &str,
        prev_obj_name: &str,
        next: &NextFn,
    ) -> Option<String> {
        let get_path = format!("/{version}/{account}/{versions_cont}/{prev_obj_name}");
        let get_req = pre_authed("GET", &get_path, auth_from);
        let get_resp = next(get_req);
        if get_resp.status == 404 {
            return None;
        }
        if !(200..300).contains(&get_resp.status) {
            return None;
        }
        let (reader, len) = get_resp.body.into_reader();
        let mut put = pre_authed(
            "PUT",
            &format!("/{version}/{account}/{container}/{object}"),
            auth_from,
        );
        put.body = Body::from_reader(reader, len);
        if let Some(ct) = get_resp.headers.get("Content-Type") {
            put.headers.set("Content-Type", ct);
        }
        if let Some(l) = len {
            put.headers.set("Content-Length", l.to_string());
        }
        let put_resp = next(put);
        if !(200..300).contains(&put_resp.status) {
            return None;
        }
        Some(get_path)
    }

    fn handle_container(&self, mut req: Request, next: &NextFn) -> Response {
        let enabled = self.allow_versioned_writes;
        let has_versions = req.headers.contains_key("X-Versions-Location");
        let has_history = req.headers.contains_key("X-History-Location");

        if has_versions && has_history {
            let hist = req.headers.get("X-History-Location").unwrap_or("");
            let vers = req.headers.get("X-Versions-Location").unwrap_or("");
            if hist.is_empty() {
                req.headers.remove("X-History-Location");
            } else if !vers.is_empty() {
                let mut resp = Response::with_body(
                    400,
                    "Only one of x-versions-location or x-history-location may be specified",
                );
                resp.headers.set("Content-Type", "text/plain");
                return resp;
            } else {
                req.headers.remove("X-Versions-Location");
            }
        }

        let has_versions = req.headers.contains_key("X-Versions-Location");
        let has_history = req.headers.contains_key("X-History-Location");
        if has_versions || has_history {
            let (val, mode) = if has_versions {
                (
                    req.headers
                        .get("X-Versions-Location")
                        .unwrap_or("")
                        .to_string(),
                    "stack",
                )
            } else {
                (
                    req.headers
                        .get("X-History-Location")
                        .unwrap_or("")
                        .to_string(),
                    "history",
                )
            };
            if val.is_empty() {
                req.headers.set("X-Remove-Versions-Location", "x");
            } else if matches!(enabled, Some(false))
                && (req.method == "PUT" || req.method == "POST")
            {
                let mut resp = Response::with_body(412, "Versioned Writes is disabled");
                resp.headers.set("Content-Type", "text/plain");
                return resp;
            } else {
                match check_container_format(&val) {
                    Ok(location) => {
                        req.headers.set(SYSMETA_VERSIONS_LOC, location);
                        req.headers.set(SYSMETA_VERSIONS_MODE, mode);
                        req.headers.set("X-Versions-Location", "");
                        req.headers.remove("X-Remove-Versions-Location");
                        req.headers.remove("X-Remove-History-Location");
                    }
                    Err(e) => {
                        let mut resp = Response::with_body(400, e.0);
                        resp.headers.set("Content-Type", "text/plain");
                        return resp;
                    }
                }
            }
        }

        if req.headers.get("X-Remove-Versions-Location").is_some_and(|v| !v.is_empty())
            || req
                .headers
                .get("X-Remove-History-Location")
                .is_some_and(|v| !v.is_empty())
        {
            req.headers.set("X-Versions-Location", "");
            req.headers.set(SYSMETA_VERSIONS_LOC, "");
            req.headers.set(SYSMETA_VERSIONS_MODE, "");
            req.headers.remove("X-Remove-Versions-Location");
            req.headers.remove("X-Remove-History-Location");
        }

        let mut resp = next(req);
        let location = resp
            .headers
            .get(SYSMETA_VERSIONS_LOC)
            .filter(|v| !v.is_empty())
            .map(|s| s.to_string());
        let mode = resp
            .headers
            .get(SYSMETA_VERSIONS_MODE)
            .unwrap_or("stack")
            .to_string();
        if let Some(loc) = location {
            if mode == "history" {
                resp.headers.set("X-History-Location", loc);
            } else {
                resp.headers.set("X-Versions-Location", loc);
            }
        }
        resp
    }

    fn read_version_cfg(&self, cinfo: &Response) -> Option<VersionCfg> {
        let mut location = cinfo
            .headers
            .get(SYSMETA_VERSIONS_LOC)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());
        let mut mode = cinfo
            .headers
            .get(SYSMETA_VERSIONS_MODE)
            .unwrap_or("stack")
            .to_string();
        let mut legacy = false;
        if location.is_none() {
            if let Some(v) = cinfo
                .headers
                .get("X-Versions-Location")
                .filter(|s| !s.is_empty())
            {
                location = Some(v.split('/').next().unwrap_or(v).to_string());
                mode = "stack".into();
                legacy = true;
            }
        }
        let location = location?;
        if !self.is_enabled(legacy) {
            return None;
        }
        let location = location.split('/').next().unwrap_or(&location).to_string();
        Some(VersionCfg { location, mode })
    }
}

fn quote_path(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

struct ListingItem {
    name: String,
    content_type: String,
}

fn parse_listing_json(bytes: &[u8]) -> Vec<ListingItem> {
    let value: serde_json::Value = match serde_json::from_slice(bytes) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    if let Some(arr) = value.as_array() {
        for it in arr {
            if let Some(name) = it.get("name").and_then(|v| v.as_str()) {
                out.push(ListingItem {
                    name: name.to_string(),
                    content_type: it
                        .get("content_type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("application/octet-stream")
                        .to_string(),
                });
            }
        }
    }
    out
}

impl Middleware for VersionedWrites {
    fn handle(&self, req: Request, next: &NextFn) -> Response {
        let parts = match split_path(&req.path, 2, 4, true) {
            Ok(p) => p,
            Err(_) => return next(req),
        };
        let version = parts[0].clone().unwrap_or_default();
        let account = parts[1].clone().unwrap_or_default();
        let container = parts[2].clone().unwrap_or_default();
        let object = parts[3].clone().unwrap_or_default();

        // Container request (no object).
        if !container.is_empty()
            && object.is_empty()
            && self.allow_versioned_writes.is_some()
            && (req.method == "PUT" || req.method == "POST" || req.method == "GET" || req.method == "HEAD")
        {
            return self.handle_container(req, next);
        }

        if object.is_empty() || (req.method != "PUT" && req.method != "DELETE") {
            return next(req);
        }

        let head = pre_authed(
            "HEAD",
            &format!("/{version}/{account}/{container}"),
            &req,
        );
        let cinfo = next(head);
        let Some(cfg) = self.read_version_cfg(&cinfo) else {
            return next(req);
        };

        if req.method == "PUT" {
            return self.handle_put(req, &version, &account, &object, &cfg.location, next);
        }
        // DELETE
        if cfg.mode == "history" {
            self.handle_delete_history(req, &version, &account, &object, &cfg.location, next)
        } else {
            self.handle_delete_stack(
                req,
                &version,
                &account,
                &container,
                &object,
                &cfg.location,
                next,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use swift_http::HeaderKeyDict;

    #[test]
    fn test_versions_object_name_format() {
        let name = versions_object_name("obj", "1751500000.00000").unwrap();
        assert!(name.starts_with("003obj/"), "{name}");
        let long = "x".repeat(16);
        let n2 = versions_object_name(&long, "1751500000.00000").unwrap();
        assert!(n2.starts_with("010"), "{n2}");
        assert_eq!(versions_object_prefix("obj"), "003obj/");
    }

    fn req(method: &str, path: &str) -> Request {
        Request {
            method: method.to_string(),
            path: path.to_string(),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: b"newdata".to_vec().into(),
        }
    }

    #[allow(clippy::type_complexity)]
    fn backend(
        versioned: bool,
        current_exists: bool,
    ) -> (Arc<Mutex<Vec<(String, String)>>>, NextFn) {
        let log = Arc::new(Mutex::new(Vec::new()));
        let log2 = log.clone();
        let app: NextFn = Arc::new(move |r: Request| {
            log2.lock().unwrap().push((r.method.clone(), r.path.clone()));
            match r.method.as_str() {
                "HEAD" if r.path.ends_with("/c") || r.path.contains("/c?") => {
                    let mut resp = Response::new(204);
                    if versioned {
                        resp.headers
                            .set(SYSMETA_VERSIONS_LOC, "versions");
                        resp.headers.set(SYSMETA_VERSIONS_MODE, "stack");
                    }
                    resp
                }
                "HEAD" => {
                    if current_exists {
                        Response::new(200)
                    } else {
                        Response::new(404)
                    }
                }
                "GET" if r.path.contains("/versions") && r.query_string.contains("prefix=") => {
                    // Empty listing by default
                    Response::with_body(200, b"[]".to_vec())
                }
                "GET" => {
                    if current_exists {
                        let mut resp = Response::with_body(200, b"olddata".to_vec());
                        resp.headers.set("X-Timestamp", "1751500000.00000");
                        resp.headers.set("Content-Type", "text/plain");
                        resp
                    } else {
                        Response::new(404)
                    }
                }
                _ => Response::new(201),
            }
        });
        (log, app)
    }

    #[test]
    fn test_put_archives_current_version() {
        let (log, app) = backend(true, true);
        let vw = VersionedWrites::new();
        let resp = vw.handle(req("PUT", "/v1/AUTH_test/c/obj"), &app);
        assert_eq!(resp.status, 201);
        let calls = log.lock().unwrap();
        assert!(calls.len() >= 4, "{calls:?}");
        assert_eq!(calls[0].0, "HEAD");
        assert!(calls.iter().any(|(m, p)| m == "PUT" && p.contains("/versions/003obj/")));
    }

    #[test]
    fn test_put_no_current_skips_archive() {
        let (log, app) = backend(true, false);
        let vw = VersionedWrites::new();
        let resp = vw.handle(req("PUT", "/v1/AUTH_test/c/obj"), &app);
        assert_eq!(resp.status, 201);
        let calls = log.lock().unwrap();
        assert!(calls.iter().all(|(_, p)| !p.contains("/versions/") || p.ends_with("/versions")));
    }

    #[test]
    fn test_unversioned_container_passes_through() {
        let (log, app) = backend(false, true);
        let vw = VersionedWrites::new();
        let resp = vw.handle(req("PUT", "/v1/AUTH_test/c/obj"), &app);
        assert_eq!(resp.status, 201);
        let calls = log.lock().unwrap();
        assert_eq!(calls.len(), 2, "{calls:?}");
        assert_eq!(calls[1], ("PUT".into(), "/v1/AUTH_test/c/obj".into()));
    }

    #[test]
    fn test_delete_stack_restores_previous() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let log2 = log.clone();
        let archive_name = "003obj/1751500000.00000";
        let app: NextFn = Arc::new(move |r: Request| {
            log2.lock().unwrap().push((r.method.clone(), r.path.clone()));
            match (r.method.as_str(), r.path.as_str()) {
                ("HEAD", p) if p.ends_with("/c") => {
                    let mut resp = Response::new(204);
                    resp.headers.set(SYSMETA_VERSIONS_LOC, "versions");
                    resp.headers.set(SYSMETA_VERSIONS_MODE, "stack");
                    resp
                }
                ("GET", p) if p.contains("/versions") && r.query_string.contains("prefix=") => {
                    let body = format!(
                        r#"[{{"name":"{archive_name}","content_type":"text/plain","bytes":7}}]"#
                    );
                    Response::with_body(200, body.into_bytes())
                }
                ("GET", p) if p.contains("/versions/") => {
                    let mut resp = Response::with_body(200, b"olddata".to_vec());
                    resp.headers.set("Content-Type", "text/plain");
                    resp
                }
                ("PUT", _) => Response::new(201),
                ("DELETE", _) => Response::new(204),
                _ => Response::new(200),
            }
        });
        let vw = VersionedWrites::new();
        let mut dreq = req("DELETE", "/v1/AUTH_test/c/obj");
        dreq.body = Body::empty();
        let resp = vw.handle(dreq, &app);
        assert_eq!(resp.status, 204);
        let calls = log.lock().unwrap();
        // Must restore (PUT current) then DELETE archive.
        assert!(
            calls
                .iter()
                .any(|(m, p)| m == "PUT" && p == "/v1/AUTH_test/c/obj"),
            "{calls:?}"
        );
        assert!(
            calls
                .iter()
                .any(|(m, p)| m == "DELETE" && p.contains("/versions/003obj/")),
            "{calls:?}"
        );
    }

    #[test]
    fn test_container_sets_sysmeta_from_versions_location() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let log2 = log.clone();
        let app: NextFn = Arc::new(move |r: Request| {
            log2.lock().unwrap().push((
                r.method.clone(),
                r.headers
                    .get(SYSMETA_VERSIONS_LOC)
                    .unwrap_or("")
                    .to_string(),
            ));
            let mut resp = Response::new(204);
            if let Some(v) = r.headers.get(SYSMETA_VERSIONS_LOC) {
                resp.headers.set(SYSMETA_VERSIONS_LOC, v);
                resp.headers.set(
                    SYSMETA_VERSIONS_MODE,
                    r.headers.get(SYSMETA_VERSIONS_MODE).unwrap_or("stack"),
                );
            }
            resp
        });
        let vw = VersionedWrites::new();
        let mut r = req("POST", "/v1/AUTH_test/c");
        r.body = Body::empty();
        r.headers.set("X-Versions-Location", "versions");
        let resp = vw.handle(r, &app);
        assert_eq!(resp.status, 204);
        assert_eq!(
            resp.headers.get("X-Versions-Location"),
            Some("versions")
        );
        let calls = log.lock().unwrap();
        assert_eq!(calls[0].1, "versions");
    }

    #[test]
    fn test_container_mutual_exclusion() {
        let app: NextFn = Arc::new(|_r| Response::new(204));
        let vw = VersionedWrites::new();
        let mut r = req("POST", "/v1/AUTH_test/c");
        r.body = Body::empty();
        r.headers.set("X-Versions-Location", "v1");
        r.headers.set("X-History-Location", "v2");
        assert_eq!(vw.handle(r, &app).status, 400);
    }

    #[test]
    fn test_delete_history_archives_and_marker() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let log2 = log.clone();
        let app: NextFn = Arc::new(move |r: Request| {
            let ct = r.headers.get("Content-Type").unwrap_or("").to_string();
            log2.lock()
                .unwrap()
                .push((r.method.clone(), r.path.clone(), ct));
            match (r.method.as_str(), r.path.as_str()) {
                ("HEAD", p) if p.ends_with("/c") => {
                    let mut resp = Response::new(204);
                    resp.headers.set(SYSMETA_VERSIONS_LOC, "versions");
                    resp.headers.set(SYSMETA_VERSIONS_MODE, "history");
                    resp
                }
                ("GET", p) if p == "/v1/AUTH_test/c/obj" => {
                    let mut resp = Response::with_body(200, b"cur".to_vec());
                    resp.headers.set("X-Timestamp", "1751500000.00000");
                    resp.headers.set("Content-Type", "text/plain");
                    resp
                }
                ("PUT", _) => Response::new(201),
                ("DELETE", _) => Response::new(204),
                _ => Response::new(200),
            }
        });
        let vw = VersionedWrites::new();
        let mut dreq = req("DELETE", "/v1/AUTH_test/c/obj");
        dreq.body = Body::empty();
        let resp = vw.handle(dreq, &app);
        assert_eq!(resp.status, 204);
        let calls = log.lock().unwrap();
        // Archive current, write delete-marker, then DELETE current.
        assert!(
            calls
                .iter()
                .any(|(m, p, _)| m == "PUT" && p.contains("/versions/003obj/")),
            "archive missing: {calls:?}"
        );
        assert!(
            calls.iter().any(|(m, p, ct)| {
                m == "PUT"
                    && p.contains("/versions/")
                    && ct == DELETE_MARKER_CONTENT_TYPE
            }),
            "delete marker missing: {calls:?}"
        );
        assert!(
            calls
                .iter()
                .any(|(m, p, _)| m == "DELETE" && p == "/v1/AUTH_test/c/obj"),
            "original delete missing: {calls:?}"
        );
    }
}
