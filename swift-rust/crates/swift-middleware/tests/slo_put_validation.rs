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
// implied. See the License for the specific language governing permissions
// and limitations under the License.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use md5::{Digest, Md5};
use serde_json::{json, Value};
use swift_http::{HeaderKeyDict, Request, Response};
use swift_middleware::{Middleware, NextFn, Slo};

fn md5_hex(data: &[u8]) -> String {
    let digest = Md5::digest(data);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn head_response(etag: &str, size: i64) -> Response {
    let mut response = Response::new(200);
    response.headers.set("Etag", etag);
    response.headers.set("Content-Length", size.to_string());
    response
        .headers
        .set("Content-Type", "application/octet-stream");
    response
}

fn sub_slo_head_response(
    physical_etag: &str,
    physical_size: i64,
    slo_etag: &str,
    slo_size: i64,
) -> Response {
    let mut response = head_response(physical_etag, physical_size);
    response.headers.set("X-Static-Large-Object", "True");
    response.headers.set("X-Object-Sysmeta-Slo-Etag", slo_etag);
    response
        .headers
        .set("X-Object-Sysmeta-Slo-Size", slo_size.to_string());
    response
}

/// The stored-manifest PUT the middleware issued, captured as Sync parts
/// (a `Request` is not Clone and its `Body` reader is only `Send`).
#[derive(Clone)]
struct CapturedPut {
    headers: HeaderKeyDict,
    body: Vec<u8>,
}

fn run_manifest_put(manifest: Value, heads: Vec<(&str, Response)>) -> (Response, Vec<CapturedPut>) {
    // Canned HEAD responses likewise torn into Sync parts.
    let heads: Arc<HashMap<String, (u16, HeaderKeyDict)>> = Arc::new(
        heads
            .into_iter()
            .map(|(path, response)| (path.to_string(), (response.status, response.headers)))
            .collect(),
    );
    let writes: Arc<Mutex<Vec<CapturedPut>>> = Arc::new(Mutex::new(Vec::new()));
    let writes_for_backend = Arc::clone(&writes);
    let backend: NextFn = Arc::new(move |mut request: Request| {
        if request.method == "HEAD" {
            return match heads.get(&request.path) {
                Some((status, headers)) => {
                    let mut response = Response::new(*status);
                    response.headers = headers.clone();
                    response
                }
                None => Response::new(404),
            };
        }
        if request.method == "PUT"
            && request.path == "/v1/a/c/manifest"
            && request.query_string.is_empty()
        {
            let body = request.body.materialize(u64::MAX).unwrap().to_vec();
            writes_for_backend.lock().unwrap().push(CapturedPut {
                headers: request.headers,
                body,
            });
            return Response::new(201);
        }
        Response::new(404)
    });

    let body = serde_json::to_vec(&manifest).unwrap();
    let mut headers = HeaderKeyDict::new();
    headers.set("Content-Type", "application/json");
    headers.set("Content-Length", body.len().to_string());
    let request = Request {
        method: "PUT".to_string(),
        path: "/v1/a/c/manifest".to_string(),
        query_string: "multipart-manifest=put".to_string(),
        headers,
        body: body.into(),
    };

    let mut response = Slo::new().handle(request, &backend);
    response.body.materialize(u64::MAX).unwrap();
    let captured_writes = writes.lock().unwrap().clone();
    (response, captured_writes)
}

fn stored_manifest(writes: &[CapturedPut]) -> Value {
    assert_eq!(writes.len(), 1, "validated manifest must be stored once");
    serde_json::from_slice(&writes[0].body).unwrap()
}

/// Test bodies are always buffered once `run_manifest_put` has
/// materialized them.
fn body_string(resp: &Response) -> String {
    match &resp.body {
        swift_http::Body::Buffered(b) => String::from_utf8_lossy(b).into_owned(),
        swift_http::Body::Streamed(_) => unreachable!(),
    }
}

#[test]
fn ordinary_segment_uses_head_metadata() {
    let segment_etag = md5_hex(b"abc");
    let (response, writes) = run_manifest_put(
        json!([{
            "path": "/c/segment",
            "etag": segment_etag,
            "size_bytes": 3
        }]),
        vec![("/v1/a/c/segment", head_response(&segment_etag, 3))],
    );

    assert_eq!(response.status, 201);
    assert_eq!(
        stored_manifest(&writes),
        json!([{"name": "/c/segment", "bytes": 3, "hash": segment_etag}])
    );
    assert_eq!(
        writes[0].headers.get("X-Object-Sysmeta-Slo-Etag"),
        Some(md5_hex(segment_etag.as_bytes()).as_str())
    );
    assert_eq!(
        writes[0].headers.get("X-Object-Sysmeta-Slo-Size"),
        Some("3")
    );
    let aggregate_etag = md5_hex(segment_etag.as_bytes());
    let physical_manifest_etag = md5_hex(&writes[0].body);
    assert_eq!(
        writes[0].headers.get("Etag"),
        Some(physical_manifest_etag.as_str()),
        "the object server must validate the stored JSON digest"
    );
    assert_eq!(
        response.headers.get("Etag"),
        Some(aggregate_etag.as_str()),
        "the client-facing PUT ETag is the aggregate segment ETag"
    );
}

#[test]
fn nested_submanifest_uses_slo_metadata_not_physical_object_metadata() {
    let b_etag = md5_hex(b"bbb");
    let c_etag = md5_hex(b"ccc");
    let d_etag = md5_hex(b"ddd");
    let cd_slo_etag = md5_hex(format!("{c_etag}{d_etag}").as_bytes());
    let (response, writes) = run_manifest_put(
        json!([
            {"path": "/c/b", "etag": b_etag, "size_bytes": 3},
            {"path": "/c/manifest-cd", "etag": cd_slo_etag, "size_bytes": 6}
        ]),
        vec![
            ("/v1/a/c/b", head_response(&b_etag, 3)),
            (
                "/v1/a/c/manifest-cd",
                sub_slo_head_response("physical-json-etag", 197, &cd_slo_etag, 6),
            ),
        ],
    );

    assert_eq!(response.status, 201);
    assert_eq!(
        stored_manifest(&writes),
        json!([
            {"name": "/c/b", "bytes": 3, "hash": b_etag},
            {
                "name": "/c/manifest-cd",
                "bytes": 6,
                "hash": cd_slo_etag,
                "sub_slo": true
            }
        ])
    );
    assert_eq!(
        writes[0].headers.get("X-Object-Sysmeta-Slo-Etag"),
        Some(md5_hex(format!("{b_etag}{cd_slo_etag}").as_bytes()).as_str())
    );
    assert_eq!(
        writes[0].headers.get("X-Object-Sysmeta-Slo-Size"),
        Some("9")
    );
}

#[test]
fn submanifest_suffix_range_is_normalized_and_counted() {
    let sub_slo_etag = md5_hex(b"sub-slo");
    let (response, writes) = run_manifest_put(
        json!([{
            "path": "/c/submanifest",
            "etag": sub_slo_etag,
            "size_bytes": 10,
            "range": "-4"
        }]),
        vec![(
            "/v1/a/c/submanifest",
            sub_slo_head_response("physical-json-etag", 149, &sub_slo_etag, 10),
        )],
    );

    assert_eq!(response.status, 201);
    assert_eq!(
        stored_manifest(&writes),
        json!([{
            "name": "/c/submanifest",
            "bytes": 10,
            "hash": sub_slo_etag,
            "range": "6-9",
            "sub_slo": true
        }])
    );
    assert_eq!(
        writes[0].headers.get("X-Object-Sysmeta-Slo-Etag"),
        Some(md5_hex(format!("{sub_slo_etag}:6-9;").as_bytes()).as_str())
    );
    assert_eq!(
        writes[0].headers.get("X-Object-Sysmeta-Slo-Size"),
        Some("4")
    );
}

#[test]
fn wrong_etag_is_rejected() {
    let (response, writes) = run_manifest_put(
        json!([{"path": "/c/segment", "etag": "wrong", "size_bytes": 3}]),
        vec![("/v1/a/c/segment", head_response("actual", 3))],
    );

    assert_eq!(response.status, 400);
    assert!(body_string(&response).contains("Etag Mismatch"));
    assert!(writes.is_empty());
}

#[test]
fn wrong_size_is_rejected() {
    let (response, writes) = run_manifest_put(
        json!([{"path": "/c/segment", "etag": "actual", "size_bytes": 4}]),
        vec![("/v1/a/c/segment", head_response("actual", 3))],
    );

    assert_eq!(response.status, 400);
    assert!(body_string(&response).contains("Size Mismatch"));
    assert!(writes.is_empty());
}

#[test]
fn path_must_identify_a_container_and_object() {
    let (response, writes) = run_manifest_put(
        json!([{"path": "object-only", "etag": "actual", "size_bytes": 3}]),
        Vec::new(),
    );

    assert_eq!(response.status, 400);
    assert!(body_string(&response).contains("path does not refer to an object"));
    assert!(writes.is_empty());
}
