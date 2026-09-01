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

//! Characterization tests for modern object versioning:
//! * PUT `?version-id=` restore-old-as-latest (Python `handle_put_version`)
//! * POST must not create a new archive (Python `handle_post`)
//!
//! A07 owns `versioned_writes.rs`. These tests live in a sibling module so
//! they do not collide with that file. They encode Python oracle status
//! codes, not the current 501 stub.

#![cfg(test)]

use std::sync::{Arc, Mutex};

use swift_http::{
    AsyncRequest, Body, HeaderKeyDict, IncomingBody, Request, Response, MAX_CONTROL_BODY,
};

use crate::versioned_writes::{VersionedWrites, AUTHORIZE_ONLY_HEADER};
use crate::{Middleware, StreamingAsyncNextFn};

const SYSMETA_VERSIONS_ENABLED: &str = "X-Container-Sysmeta-Versions-Enabled";
const SYSMETA_VERSIONS_CONTAINER: &str = "X-Container-Sysmeta-Versions-Container";
const SYSMETA_VERSIONS_SYMLINK: &str = "X-Object-Sysmeta-Versions-Symlink";
const VERSION_ID: &str = "1787766177.51067";
const MISSING_VERSION_ID: &str = "1234567890.12345";

type Call = (String, String, String, HeaderKeyDict);

fn vw() -> VersionedWrites {
    VersionedWrites::new().with_object_versioning(true)
}

fn enabled_container() -> Response {
    let mut resp = Response::new(204);
    resp.headers.set(SYSMETA_VERSIONS_ENABLED, "True");
    resp.headers
        .set(SYSMETA_VERSIONS_CONTAINER, "%00versions%00c");
    resp
}

fn put_version_id_request(version_id: &str, body: Vec<u8>) -> AsyncRequest {
    AsyncRequest {
        method: "PUT".to_string(),
        path: "/v1/AUTH_test/c/o".to_string(),
        query_string: format!("version-id={version_id}"),
        headers: HeaderKeyDict::new(),
        body: IncomingBody::from_bytes(body, MAX_CONTROL_BODY),
    }
}

fn record(calls: &Arc<Mutex<Vec<Call>>>, req: &AsyncRequest) {
    calls.lock().unwrap().push((
        req.method.clone(),
        req.path.clone(),
        req.query_string.clone(),
        req.headers.clone(),
    ));
}

/// Python `handle_put_version`: `version-id=null` is 400, never a restore.
#[tokio::test]
async fn test_put_version_id_null_is_400() {
    let next: StreamingAsyncNextFn = Arc::new(move |req: AsyncRequest| {
        Box::pin(async move {
            if req.headers.contains_key(AUTHORIZE_ONLY_HEADER) {
                return Response::new(204);
            }
            if req.method == "HEAD" && req.path == "/v1/AUTH_test/c" {
                return enabled_container();
            }
            panic!(
                "null version-id must not reach the archive: {} {}",
                req.method, req.path
            );
        })
    });
    let resp = vw()
        .handle_streaming_request(put_version_id_request("null", Vec::new()), next)
        .await;
    assert_eq!(resp.status, 400, "Python: PUT version-id=null is 400");
}

/// Python `handle_put_version`: missing archive → 404, not 501.
///
/// This currently fails: `handle_modern_object_streaming` returns
/// `501 PUT version-id is not implemented` before HEADing the archive.
#[tokio::test]
async fn test_put_version_id_missing_archive_is_404_not_501() {
    let calls: Arc<Mutex<Vec<Call>>> = Arc::new(Mutex::new(Vec::new()));
    let calls2 = Arc::clone(&calls);
    let next: StreamingAsyncNextFn = Arc::new(move |req: AsyncRequest| {
        let calls = Arc::clone(&calls2);
        Box::pin(async move {
            record(&calls, &req);
            if req.headers.contains_key(AUTHORIZE_ONLY_HEADER) {
                return Response::new(204);
            }
            if req.method == "HEAD" && req.path == "/v1/AUTH_test/c" {
                return enabled_container();
            }
            if req.method == "HEAD" && req.path == "/v1/AUTH_test/\0versions\0c" {
                return Response::new(204);
            }
            if req.method == "HEAD" && req.path.starts_with("/v1/AUTH_test/\0versions\0c/") {
                return Response::new(404);
            }
            Response::new(500)
        })
    });
    let resp = vw()
        .handle_streaming_request(put_version_id_request(MISSING_VERSION_ID, Vec::new()), next)
        .await;
    assert_ne!(
        resp.status,
        501,
        "PUT ?version-id= of a missing archive must not be 501; calls={:?}",
        calls
            .lock()
            .unwrap()
            .iter()
            .map(|(m, p, q, _)| (m, p, q))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        resp.status,
        404,
        "Python handle_put_version: missing version is 404; calls={:?}",
        calls
            .lock()
            .unwrap()
            .iter()
            .map(|(m, p, q, _)| (m, p, q))
            .collect::<Vec<_>>()
    );
}

/// Python `handle_put_version`: HEAD archive, then `_put_symlink_to_version`.
/// Zero-byte body. Does not write a new hidden object. Version-id unchanged.
///
/// This currently fails with 501.
#[tokio::test]
async fn test_put_version_id_repoints_current_without_new_archive() {
    let calls: Arc<Mutex<Vec<Call>>> = Arc::new(Mutex::new(Vec::new()));
    let calls2 = Arc::clone(&calls);
    let next: StreamingAsyncNextFn = Arc::new(move |req: AsyncRequest| {
        let calls = Arc::clone(&calls2);
        Box::pin(async move {
            record(&calls, &req);
            if req.headers.contains_key(AUTHORIZE_ONLY_HEADER) {
                return Response::new(204);
            }
            if req.method == "HEAD" && req.path == "/v1/AUTH_test/c" {
                return enabled_container();
            }
            if req.method == "HEAD" && req.path.starts_with("/v1/AUTH_test/\0versions\0c/") {
                let mut resp = Response::new(200);
                resp.headers.set("ETag", "966634ebf2fc135707d6753692bf4b1e");
                resp.headers.set("Content-Length", "8");
                resp.headers.set("Content-Type", "text/jibberish02");
                return resp;
            }
            if req.method == "PUT" && req.path == "/v1/AUTH_test/c/o" {
                assert!(
                    req.headers
                        .get("X-Symlink-Target")
                        .or_else(|| req.headers.get("X-Object-Sysmeta-Symlink-Target"))
                        .is_some_and(|value| value.contains("versions") || value.contains("%00")),
                    "marker PUT must target the hidden archive, not a client body; headers={:?}",
                    req.headers
                );
                let mut resp = Response::new(201);
                resp.headers.set("ETag", "d41d8cd98f00b204e9800998ecf8427e");
                return resp;
            }
            if req.method == "PUT" && req.path.starts_with("/v1/AUTH_test/\0versions\0c/") {
                panic!(
                    "PUT ?version-id= must not write a new archive (Python only repoints the marker): {} {}",
                    req.method, req.path
                );
            }
            panic!("unexpected subrequest {} {}", req.method, req.path);
        })
    });
    let resp = vw()
        .handle_streaming_request(put_version_id_request(VERSION_ID, Vec::new()), next)
        .await;
    assert_ne!(
        resp.status, 501,
        "PUT ?version-id= restore is implemented in Python"
    );
    assert!(
        (200..300).contains(&resp.status),
        "restore should succeed, got {}; calls={:?}",
        resp.status,
        calls
            .lock()
            .unwrap()
            .iter()
            .map(|(m, p, q, _)| (m, p, q))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        resp.headers.get("X-Object-Version-Id"),
        Some(VERSION_ID),
        "restore keeps the requested version-id; it does not mint a new one"
    );
    let hidden_puts = calls
        .lock()
        .unwrap()
        .iter()
        .filter(|(method, path, _, _)| method == "PUT" && path.contains('\0'))
        .count();
    assert_eq!(hidden_puts, 0, "restore must not PUT a new hidden object");
}

/// Python rejects a PUT ?version-id= with a non-empty body (400), not 501.
#[tokio::test]
async fn test_put_version_id_nonzero_body_is_400_not_501() {
    let next: StreamingAsyncNextFn = Arc::new(move |req: AsyncRequest| {
        Box::pin(async move {
            if req.headers.contains_key(AUTHORIZE_ONLY_HEADER) {
                return Response::new(204);
            }
            if req.method == "HEAD" && req.path == "/v1/AUTH_test/c" {
                return enabled_container();
            }
            Response::new(500)
        })
    });
    let resp = vw()
        .handle_streaming_request(put_version_id_request(VERSION_ID, b"nope".to_vec()), next)
        .await;
    assert_ne!(
        resp.status, 501,
        "non-empty PUT version-id is 400 in Python, not 501"
    );
    assert_eq!(resp.status, 400);
}

/// POST to the current object must not archive a new hidden object.
/// Crate-level follow-307 is already covered in versioned_writes.rs; this
/// pins "no hidden PUT" as the POST contract for A07/listing merge.
#[tokio::test]
async fn test_post_does_not_put_a_new_hidden_archive() {
    let calls: Arc<Mutex<Vec<Call>>> = Arc::new(Mutex::new(Vec::new()));
    let calls2 = Arc::clone(&calls);
    let next: StreamingAsyncNextFn = Arc::new(move |req: AsyncRequest| {
        let calls = Arc::clone(&calls2);
        Box::pin(async move {
            record(&calls, &req);
            if req.headers.contains_key(AUTHORIZE_ONLY_HEADER) {
                return Response::new(204);
            }
            if req.method == "HEAD" && req.path == "/v1/AUTH_test/c" {
                return enabled_container();
            }
            if req.method == "POST" && req.path == "/v1/AUTH_test/c/o" {
                let mut resp = Response::new(307);
                resp.headers.set(
                    "Location",
                    "/v1/AUTH_test/%00versions%00c/%00o%008211892386.68781",
                );
                resp.headers.set(SYSMETA_VERSIONS_SYMLINK, "true");
                return resp;
            }
            if req.method == "POST" && req.path.starts_with("/v1/AUTH_test/\0versions\0c/") {
                return Response::new(202);
            }
            if req.method == "PUT" {
                panic!(
                    "POST must not archive: PUT {} {}",
                    req.path, req.query_string
                );
            }
            Response::new(500)
        })
    });
    let request = AsyncRequest {
        method: "POST".to_string(),
        path: "/v1/AUTH_test/c/o".to_string(),
        query_string: String::new(),
        headers: {
            let mut headers = HeaderKeyDict::new();
            headers.set("Content-Type", "text/updated20");
            headers
        },
        body: IncomingBody::from_bytes(Vec::new(), MAX_CONTROL_BODY),
    };
    let route = Request {
        method: "POST".to_string(),
        path: "/v1/AUTH_test/c/o".to_string(),
        query_string: String::new(),
        headers: HeaderKeyDict::new(),
        body: Body::empty(),
    };
    assert!(vw().streams_request(&route));
    let resp = vw().handle_streaming_request(request, next).await;
    assert_eq!(
        resp.status,
        202,
        "calls={:?}",
        calls
            .lock()
            .unwrap()
            .iter()
            .map(|(m, p, _, _)| (m, p))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        calls
            .lock()
            .unwrap()
            .iter()
            .filter(|(method, _, _, _)| method == "PUT")
            .count(),
        0,
        "POST must not create a new version archive"
    );
}
