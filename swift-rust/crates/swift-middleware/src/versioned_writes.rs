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

//! `versioned_writes` (legacy/stack mode), ported from
//! `swift/common/middleware/versioned_writes/legacy.py`.
//!
//! A container flagged with `X-Versions-Location: <versions_cont>` keeps a
//! copy of each object's prior contents: before an overwriting `PUT`, the
//! current object is archived into the versions container under a name that
//! sorts by object then timestamp, so `DELETE` can later restore the most
//! recent prior version.
//!
//! The archived name is the interoperability contract and is golden-tested:
//! `"{len(object):03x}{object}/{Timestamp(ts).internal}"`.
//!
//! This module ports the copy-current-on-PUT flow over the Next framework
//! (HEAD container -> if versioned, GET current -> archive -> proceed with the
//! PUT). Deferred: the DELETE-restore listing walk, history mode
//! (`X-History-Location`, which archives deletes too), and the
//! `swift.authorize` write-ACL recheck.

use swift_core::timestamp::Timestamp;
use swift_http::{split_path, Body, HeaderKeyDict, Request, Response};

use crate::{Middleware, NextFn};

/// The `versioned_writes` middleware.
#[derive(Default)]
pub struct VersionedWrites;

impl VersionedWrites {
    pub fn new() -> Self {
        VersionedWrites
    }
}

/// `_build_versions_object_name`: the archive object name for a prior version.
/// `object_name` length is prefixed as 3 hex digits so archives sort together,
/// then the object name, then the source version's internal timestamp.
pub fn versions_object_name(object_name: &str, ts: &str) -> Option<String> {
    let internal = ts.parse::<Timestamp>().ok()?.internal();
    // Python uses len(object_name): the code-point count.
    let len = object_name.chars().count();
    Some(format!("{len:03x}{object_name}/{internal}"))
}

impl VersionedWrites {
    fn copy_current_then_put(
        &self,
        req: Request,
        version: &str,
        account: &str,
        object: &str,
        versions_cont: &str,
        next: &NextFn,
    ) -> Response {
        // GET the current object; if absent, nothing to archive.
        let get_req = Request {
            method: "GET".to_string(),
            path: req.path.clone(),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: Body::empty(),
        };
        let current = next(get_req);
        if current.status == 404 {
            return next(req);
        }
        if !(200..300).contains(&current.status) {
            // an error reading the current object aborts the write
            return current;
        }
        // Determine the source timestamp (x-timestamp preferred).
        let ts_source = current
            .headers
            .get("X-Timestamp")
            .map(|s| s.to_string())
            .unwrap_or_else(|| "0".to_string());
        let Some(vers_name) = versions_object_name(object, &ts_source) else {
            return next(req);
        };

        // Archive the current contents into the versions container. The
        // current object's body is plumbed straight into the archive PUT as
        // a stream — the copy never materializes the object.
        let (current_reader, current_len) = current.body.into_reader();
        let mut archive = Request {
            method: "PUT".to_string(),
            path: format!("/{version}/{account}/{versions_cont}/{vers_name}"),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: Body::from_reader(current_reader, current_len),
        };
        if let Some(ct) = current.headers.get("Content-Type") {
            archive.headers.set("Content-Type", ct);
        }
        if let Some(len) = current_len {
            archive.headers.set("Content-Length", len.to_string());
        }
        let archive_resp = next(archive);
        if !(200..300).contains(&archive_resp.status) {
            // could not archive -> refuse the overwrite, as Python does
            return archive_resp;
        }

        // Proceed with the original PUT.
        next(req)
    }
}

impl Middleware for VersionedWrites {
    fn handle(&self, req: Request, next: &NextFn) -> Response {
        // Only object PUTs are candidates.
        if req.method != "PUT" {
            return next(req);
        }
        let parts = match split_path(&req.path, 4, 4, true) {
            Ok(p) => p,
            Err(_) => return next(req),
        };
        let version = parts[0].clone().unwrap_or_default();
        let account = parts[1].clone().unwrap_or_default();
        let container = parts[2].clone().unwrap_or_default();
        let object = parts[3].clone().unwrap_or_default();

        // HEAD the container to learn its versioning config.
        let head = Request {
            method: "HEAD".to_string(),
            path: format!("/{version}/{account}/{container}"),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: Body::empty(),
        };
        let cinfo = next(head);
        let versions_cont = cinfo
            .headers
            .get("X-Container-Sysmeta-Versions-Location")
            .or_else(|| cinfo.headers.get("X-Versions-Location"))
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty());

        match versions_cont {
            Some(vc) => self.copy_current_then_put(req, &version, &account, &object, &vc, next),
            None => next(req),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn test_versions_object_name_format() {
        // len("obj") == 3 -> "003", then name, then internal timestamp
        let name = versions_object_name("obj", "1751500000.00000").unwrap();
        assert!(name.starts_with("003obj/"), "{name}");
        // 16-char name -> 0x10 -> "010"
        let long = "x".repeat(16);
        let n2 = versions_object_name(&long, "1751500000.00000").unwrap();
        assert!(n2.starts_with("010"), "{n2}");
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

    /// Backend: HEAD container reports versioning; GET current returns a body;
    /// records the archive PUT and the final PUT.
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
                "HEAD" => {
                    let mut resp = Response::new(204);
                    if versioned {
                        resp.headers
                            .set("X-Container-Sysmeta-Versions-Location", "versions");
                    }
                    resp
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
        // HEAD container, GET current, PUT archive, PUT original
        assert_eq!(calls.len(), 4, "{calls:?}");
        assert_eq!(calls[0].0, "HEAD");
        assert_eq!(calls[1], ("GET".into(), "/v1/AUTH_test/c/obj".into()));
        // archive lands in the versions container with the 003obj/ prefix
        assert_eq!(calls[2].0, "PUT");
        assert!(
            calls[2].1.starts_with("/v1/AUTH_test/versions/003obj/"),
            "{}",
            calls[2].1
        );
        assert_eq!(calls[3], ("PUT".into(), "/v1/AUTH_test/c/obj".into()));
    }

    #[test]
    fn test_put_no_current_skips_archive() {
        let (log, app) = backend(true, false);
        let vw = VersionedWrites::new();
        let resp = vw.handle(req("PUT", "/v1/AUTH_test/c/obj"), &app);
        assert_eq!(resp.status, 201);
        let calls = log.lock().unwrap();
        // HEAD, GET (404), PUT original — no archive PUT
        assert_eq!(calls.len(), 3, "{calls:?}");
        assert!(calls.iter().all(|(_, p)| !p.contains("/versions/")));
    }

    #[test]
    fn test_unversioned_container_passes_through() {
        let (log, app) = backend(false, true);
        let vw = VersionedWrites::new();
        let resp = vw.handle(req("PUT", "/v1/AUTH_test/c/obj"), &app);
        assert_eq!(resp.status, 201);
        let calls = log.lock().unwrap();
        // HEAD container, then the PUT — no GET/archive
        assert_eq!(calls.len(), 2, "{calls:?}");
        assert_eq!(calls[1], ("PUT".into(), "/v1/AUTH_test/c/obj".into()));
    }
}
