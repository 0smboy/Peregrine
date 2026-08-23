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
use swift_middleware::{AsyncNextFn, Middleware, NextFn, Slo};

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
    run_manifest_put_with_client_etag(manifest, heads, None)
}

fn run_manifest_put_with_client_etag(
    manifest: Value,
    heads: Vec<(&str, Response)>,
    client_etag: Option<&str>,
) -> (Response, Vec<CapturedPut>) {
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
            let physical_etag = request.headers.get("Etag").map(str::to_string);
            writes_for_backend.lock().unwrap().push(CapturedPut {
                headers: request.headers,
                body,
            });
            let mut response = Response::new(201);
            if let Some(physical_etag) = physical_etag {
                response.headers.set("Etag", physical_etag);
            }
            return response;
        }
        Response::new(404)
    });

    let body = serde_json::to_vec(&manifest).unwrap();
    let mut headers = HeaderKeyDict::new();
    headers.set("Content-Type", "application/json");
    headers.set("Content-Length", body.len().to_string());
    if let Some(client_etag) = client_etag {
        headers.set("Etag", client_etag);
    }
    let request = Request {
        method: "PUT".to_string(),
        path: "/v1/a/c/manifest".to_string(),
        query_string: "multipart-manifest=put".to_string(),
        headers,
        body: body.into(),
    };

    // Keep these contract tests deterministic and avoid the optional warm-up
    // HEAD pile. The production default still validates with concurrency 10.
    let mut response = Slo::new().with_concurrency(1).handle(request, &backend);
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
        swift_http::Body::Streamed(_) | swift_http::Body::Channel(_) => unreachable!(),
    }
}

#[test]
fn ordinary_segment_uses_head_metadata() {
    let segment_etag = md5_hex(b"abc");
    let slo_etag = md5_hex(segment_etag.as_bytes());
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
        response.headers.get("Etag"),
        Some(format!("\"{slo_etag}\"").as_str())
    );
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
    let physical_etag = md5_hex(&writes[0].body);
    assert_eq!(writes[0].headers.get("Etag"), Some(physical_etag.as_str()));
    assert_ne!(physical_etag, slo_etag);
    let ct = writes[0].headers.get("Content-Type").unwrap_or("");
    assert!(ct.contains("swift_bytes=3"), "{ct}");
    assert_eq!(
        writes[0]
            .headers
            .get("X-Object-Sysmeta-Container-Update-Override-Etag"),
        Some(format!("{physical_etag}; slo_etag={slo_etag}").as_str())
    );
}

#[test]
fn matching_client_aggregate_etag_is_accepted_and_replaced_for_backend() {
    let segment_etag = md5_hex(b"abc");
    let slo_etag = md5_hex(segment_etag.as_bytes());
    let (response, writes) = run_manifest_put_with_client_etag(
        json!([{
            "path": "/c/segment",
            "etag": segment_etag,
            "size_bytes": 3
        }]),
        vec![("/v1/a/c/segment", head_response(&segment_etag, 3))],
        Some(&slo_etag),
    );

    assert_eq!(response.status, 201);
    assert_eq!(writes.len(), 1);
    let physical_etag = md5_hex(&writes[0].body);
    assert_eq!(writes[0].headers.get("Etag"), Some(physical_etag.as_str()));
    assert_ne!(writes[0].headers.get("Etag"), Some(slo_etag.as_str()));
    assert_eq!(
        response.headers.get("Etag"),
        Some(format!("\"{slo_etag}\"").as_str())
    );
}

#[test]
fn quoted_matching_client_aggregate_etag_is_accepted() {
    let segment_etag = md5_hex(b"abc");
    let slo_etag = md5_hex(segment_etag.as_bytes());
    let quoted = format!("\"{slo_etag}\"");
    let (response, writes) = run_manifest_put_with_client_etag(
        json!([{
            "path": "/c/segment",
            "etag": segment_etag,
            "size_bytes": 3
        }]),
        vec![("/v1/a/c/segment", head_response(&segment_etag, 3))],
        Some(&quoted),
    );

    assert_eq!(response.status, 201);
    assert_eq!(writes.len(), 1);
    assert_eq!(response.headers.get("Etag"), Some(quoted.as_str()));
}

#[test]
fn mismatching_client_aggregate_etag_is_rejected_before_backend_put() {
    let segment_etag = md5_hex(b"abc");
    let (response, writes) = run_manifest_put_with_client_etag(
        json!([{
            "path": "/c/segment",
            "etag": segment_etag,
            "size_bytes": 3
        }]),
        vec![("/v1/a/c/segment", head_response(&segment_etag, 3))],
        Some("00000000000000000000000000000000"),
    );

    assert_eq!(response.status, 422);
    assert_eq!(
        body_string(&response),
        concat!(
            "<html><h1>Unprocessable Entity</h1><p>",
            "Unable to process the contained instructions</p></html>"
        )
    );
    assert_eq!(
        response.headers.get("Content-Type"),
        Some("text/html; charset=UTF-8")
    );
    assert!(writes.is_empty());
}

#[test]
fn one_thousand_object_segments_plus_inline_data_is_accepted() {
    let segment_etag = md5_hex(b"abc");
    let mut entries = vec![
        json!({
            "path": "/c/segment",
            "etag": segment_etag,
            "size_bytes": 3
        });
        1000
    ];
    // Python's max_manifest_segments counts only entries with `path`.
    entries.push(json!({"data": "eA=="}));

    let (response, writes) = run_manifest_put(
        Value::Array(entries),
        vec![("/v1/a/c/segment", head_response(&segment_etag, 3))],
    );

    assert_eq!(response.status, 201);
    assert_eq!(writes.len(), 1);
    assert_eq!(stored_manifest(&writes).as_array().unwrap().len(), 1001);
}

#[test]
fn one_thousand_and_one_object_segments_are_rejected_before_backend_calls() {
    let entries = vec![
        json!({
            "path": "/c/segment",
            "etag": "unused",
            "size_bytes": 3
        });
        1001
    ];

    let backend_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let backend_calls_observer = Arc::clone(&backend_calls);
    let backend: NextFn = Arc::new(move |_request: Request| {
        backend_calls_observer.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Response::new(500)
    });
    let body = serde_json::to_vec(&Value::Array(entries)).unwrap();
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

    assert_eq!(response.status, 413);
    assert_eq!(
        body_string(&response),
        "Number of object-backed segments must be <= 1000"
    );
    assert_eq!(
        response.headers.get("Content-Type"),
        Some("text/html; charset=UTF-8")
    );
    assert_eq!(response.headers.get("Content-Length"), Some("48"));
    assert_eq!(backend_calls.load(std::sync::atomic::Ordering::SeqCst), 0);
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

/// Production Hyper uses `handle_put_async`, which prefetches segment HEADs
/// into a path-keyed cache. A ranged manifest (Python `TestSloEnv`) names
/// the same sub-SLO three times; the cache must not be consumed on first use.
#[tokio::test]
async fn async_put_reuses_head_for_duplicate_ranged_paths() {
    let sub_slo_etag = md5_hex(b"sub-slo");
    let writes: Arc<Mutex<Vec<CapturedPut>>> = Arc::new(Mutex::new(Vec::new()));
    let writes_for_backend = Arc::clone(&writes);
    let etag_for_backend = sub_slo_etag.clone();
    let backend: AsyncNextFn = Arc::new(move |mut request: Request| {
        let writes_for_backend = Arc::clone(&writes_for_backend);
        let etag_for_backend = etag_for_backend.clone();
        Box::pin(async move {
            if request.method == "HEAD" && request.path == "/v1/a/c/submanifest" {
                return sub_slo_head_response("physical-json-etag", 149, &etag_for_backend, 10);
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
        })
    });

    let manifest = json!([
        {"path": "/c/submanifest", "etag": sub_slo_etag, "size_bytes": 10, "range": "-4"},
        {"path": "/c/submanifest", "etag": sub_slo_etag, "size_bytes": 10, "range": "0-3"},
        {"path": "/c/submanifest", "etag": sub_slo_etag, "size_bytes": 10, "range": "6-9"}
    ]);
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

    let mut response = Slo::new()
        .handle_request_async(request, backend)
        .await;
    response.body.materialize(u64::MAX).unwrap();
    assert_eq!(response.status, 201, "{}", body_string(&response));
    let captured = writes.lock().unwrap().clone();
    assert_eq!(
        stored_manifest(&captured),
        json!([
            {"name": "/c/submanifest", "bytes": 10, "hash": sub_slo_etag, "range": "6-9", "sub_slo": true},
            {"name": "/c/submanifest", "bytes": 10, "hash": sub_slo_etag, "range": "0-3", "sub_slo": true},
            {"name": "/c/submanifest", "bytes": 10, "hash": sub_slo_etag, "range": "6-9", "sub_slo": true}
        ])
    );
}

#[test]
fn typo_etag_key_is_rejected_as_extraneous() {
    let (response, writes) = run_manifest_put(
        json!([{
            "path": "/c/segment",
            "teag": "deadbeef",
            "size_bytes": 3
        }]),
        vec![("/v1/a/c/segment", head_response("actual", 3))],
    );
    assert_eq!(response.status, 400);
    assert!(body_string(&response).contains("extraneous keys"));
    assert!(writes.is_empty());
}

/// Production Hyper GET `?multipart-manifest=get` must not reassemble; Python
/// forces `application/json; charset=utf-8` on the stored listing.
#[tokio::test]
async fn async_manifest_get_sets_json_content_type() {
    let stored = serde_json::to_vec(&json!([{"name": "/c/segment", "bytes": 3, "hash": "abc"}])).unwrap();
    let backend: AsyncNextFn = Arc::new(move |request: Request| {
        let stored = stored.clone();
        Box::pin(async move {
            if request.method == "GET" && request.path == "/v1/a/c/manifest" {
                let mut resp = Response::with_body(200, stored);
                resp.headers.set("X-Static-Large-Object", "True");
                resp.headers.set("Content-Type", "application/octet-stream");
                return resp;
            }
            Response::new(404)
        })
    });
    let request = Request {
        method: "GET".to_string(),
        path: "/v1/a/c/manifest".to_string(),
        query_string: "multipart-manifest=get".to_string(),
        headers: HeaderKeyDict::new(),
        body: Vec::<u8>::new().into(),
    };
    let response = Slo::new().reassemble_async(request, backend).await;
    assert_eq!(response.status, 200);
    assert_eq!(
        response.headers.get("Content-Type"),
        Some("application/json; charset=utf-8")
    );
}

#[test]
fn container_listing_splits_slo_etag_from_hash() {
    let listing = serde_json::to_vec(&json!([
        {"name": "o", "bytes": 3, "hash": "deadbeef; slo_etag=slohash", "content_type": "application/octet-stream", "last_modified": "2020-01-01T00:00:00.000000"},
        {"subdir": "p/"}
    ])).unwrap();
    let backend_body = listing.clone();
    let backend: NextFn = Arc::new(move |_r: Request| {
        let mut resp = Response::with_body(200, backend_body.clone());
        resp.headers.set("Content-Type", "application/json; charset=utf-8");
        resp
    });
    let req = Request {
        method: "GET".into(),
        path: "/v1/a/c".into(),
        query_string: "format=json".into(),
        headers: HeaderKeyDict::new(),
        body: Vec::<u8>::new().into(),
    };
    let mut resp = Slo::new().handle(req, &backend);
    resp.body.materialize(u64::MAX).unwrap();
    let v: Value = serde_json::from_slice(match &resp.body {
        swift_http::Body::Buffered(b) => b,
        _ => panic!("expected buffered"),
    }).unwrap();
    assert_eq!(v[0]["hash"], "deadbeef");
    assert_eq!(v[0]["slo_etag"], "\"slohash\"");
    assert_eq!(v[1]["subdir"], "p/");
    let _ = listing;
}

#[test]
fn prepare_sets_etag_is_at_for_object_get() {
    let mut req = Request {
        method: "GET".into(),
        path: "/v1/a/c/o".into(),
        query_string: String::new(),
        headers: HeaderKeyDict::new(),
        body: Vec::<u8>::new().into(),
    };
    let _ = Slo::new().prepare(&mut req);
    assert_eq!(
        req.headers.get("X-Backend-Etag-Is-At"),
        Some("X-Object-Sysmeta-Slo-Etag")
    );
}

#[tokio::test]
async fn async_heartbeat_put_is_202_chunked() {
    let backend: AsyncNextFn = Arc::new(|mut request: Request| {
        Box::pin(async move {
            if request.method == "HEAD" {
                let mut r = Response::new(200);
                r.headers.set("Etag", "e");
                r.headers.set("Content-Length", "1");
                return r;
            }
            if request.method == "PUT" {
                let _ = request.body.materialize(u64::MAX);
                let mut r = Response::new(201);
                r.headers.set("Etag", "\"slo\"");
                r.headers.set("Last-Modified", "Mon, 01 Jan 2020 00:00:00 GMT");
                return r;
            }
            Response::new(404)
        })
    });
    let body = serde_json::to_vec(&json!([{"path": "/c/s1", "etag": "e", "size_bytes": 1}])).unwrap();
    let mut headers = HeaderKeyDict::new();
    headers.set("Content-Type", "application/json");
    headers.set("Content-Length", body.len().to_string());
    let request = Request {
        method: "PUT".into(),
        path: "/v1/a/c/manifest".into(),
        query_string: "multipart-manifest=put&heartbeat=on".into(),
        headers,
        body: body.into(),
    };
    let mut resp = Slo::new().handle_request_async(request, backend).await;
    assert_eq!(resp.status, 202);
    assert_eq!(resp.body.content_length(), None);
    let bytes = resp.body.materialize(u64::MAX).unwrap();
    assert!(bytes.starts_with(b" "), "{bytes:?}");
    assert!(bytes.windows(4).any(|w| w == b"\r\n\r\n"));
    let text = String::from_utf8_lossy(bytes);
    assert!(text.contains("201 Created"), "{text}");
    assert!(text.contains("Etag"), "{text}");
}

#[test]
fn if_none_match_not_star_is_400() {
    let backend: NextFn = Arc::new(|_r: Request| Response::new(500));
    let body = serde_json::to_vec(&json!([{"path": "/c/s1", "etag": "e", "size_bytes": 1}])).unwrap();
    let mut headers = HeaderKeyDict::new();
    headers.set("If-None-Match", "\"not-star\"");
    let req = Request {
        method: "PUT".into(),
        path: "/v1/a/c/manifest".into(),
        query_string: "multipart-manifest=put".into(),
        headers,
        body: body.into(),
    };
    let resp = Slo::new().handle(req, &backend);
    assert_eq!(resp.status, 400);
}

#[tokio::test]
async fn if_none_match_star_does_not_412_segment_heads() {
    let saw_inm = Arc::new(Mutex::new(false));
    let flag = Arc::clone(&saw_inm);
    let backend: AsyncNextFn = Arc::new(move |mut request: Request| {
        let flag = Arc::clone(&flag);
        Box::pin(async move {
            if request.method == "HEAD" {
                if request.headers.get("If-None-Match").is_some() {
                    *flag.lock().unwrap() = true;
                    return Response::new(412);
                }
                let mut r = Response::new(200);
                r.headers.set("Etag", "e");
                r.headers.set("Content-Length", "1");
                return r;
            }
            if request.method == "PUT" {
                let _ = request.body.materialize(u64::MAX);
                return Response::new(201);
            }
            Response::new(404)
        })
    });
    let body = serde_json::to_vec(&json!([{"path": "/c/s1", "etag": "e", "size_bytes": 1}])).unwrap();
    let mut headers = HeaderKeyDict::new();
    headers.set("If-None-Match", "*");
    headers.set("Content-Length", body.len().to_string());
    let request = Request {
        method: "PUT".into(),
        path: "/v1/a/c/manifest".into(),
        query_string: "multipart-manifest=put".into(),
        headers,
        body: body.into(),
    };
    let resp = Slo::new().handle_request_async(request, backend).await;
    assert_eq!(resp.status, 201, "first If-None-Match:* PUT must create");
    assert!(
        !*saw_inm.lock().unwrap(),
        "segment HEAD must not forward If-None-Match"
    );
}

#[tokio::test]
async fn heartbeat_missing_segment_lists_404_error() {
    let backend: AsyncNextFn = Arc::new(|request: Request| {
        Box::pin(async move {
            if request.method == "HEAD" && request.path.contains("s1") {
                let mut r = Response::new(200);
                r.headers.set("Etag", "e");
                r.headers.set("Content-Length", "1");
                return r;
            }
            if request.method == "HEAD" {
                return Response::new(404);
            }
            Response::new(404)
        })
    });
    let body = serde_json::to_vec(&json!([
        {"path": "/c/s1", "etag": "e", "size_bytes": 1},
        {"path": "non-existent/segment"}
    ]))
    .unwrap();
    let mut headers = HeaderKeyDict::new();
    headers.set("Content-Length", body.len().to_string());
    let request = Request {
        method: "PUT".into(),
        path: "/v1/a/c/manifest".into(),
        query_string: "multipart-manifest=put&heartbeat=on".into(),
        headers,
        body: body.into(),
    };
    let mut resp = Slo::new().handle_request_async(request, backend).await;
    assert_eq!(resp.status, 202);
    let text = String::from_utf8_lossy(resp.body.materialize(u64::MAX).unwrap());
    assert!(text.contains("Response Status: 400 Bad Request"), "{text}");
    assert!(text.contains("Response Body: Bad Request"), "{text}");
    assert!(
        text.contains("non-existent/segment, 404 Not Found"),
        "{text}"
    );
}

#[tokio::test]
async fn heartbeat_bad_etag_json_uses_webob_422_body() {
    let backend: AsyncNextFn = Arc::new(|mut request: Request| {
        Box::pin(async move {
            if request.method == "HEAD" {
                let mut r = Response::new(200);
                r.headers.set("Etag", "e");
                r.headers.set("Content-Length", "1");
                return r;
            }
            let _ = request.body.materialize(u64::MAX);
            Response::new(201)
        })
    });
    let body = serde_json::to_vec(&json!([{"path": "/c/s1", "etag": "e", "size_bytes": 1}])).unwrap();
    let mut headers = HeaderKeyDict::new();
    headers.set("Accept", "application/json");
    headers.set("Etag", "bad etag");
    headers.set("Content-Length", body.len().to_string());
    let request = Request {
        method: "PUT".into(),
        path: "/v1/a/c/manifest".into(),
        query_string: "multipart-manifest=put&heartbeat=on".into(),
        headers,
        body: body.into(),
    };
    let mut resp = Slo::new().handle_request_async(request, backend).await;
    assert_eq!(resp.status, 202);
    let text = String::from_utf8_lossy(resp.body.materialize(u64::MAX).unwrap());
    let json_start = text.find('{').expect(&text);
    let v: Value = serde_json::from_str(&text[json_start..]).unwrap();
    assert_eq!(v["Response Status"], "422 Unprocessable Entity");
    assert_eq!(
        v["Response Body"],
        "Unprocessable Entity\nUnable to process the contained instructions"
    );
    assert_eq!(v["Errors"], json!([]));
}

#[tokio::test]
async fn if_match_get_uses_slo_etag_not_physical() {
    let stored = serde_json::to_vec(&json!([{"name": "/c/s1", "bytes": 1, "hash": "e"}])).unwrap();
    let backend: AsyncNextFn = Arc::new(move |request: Request| {
        let stored = stored.clone();
        Box::pin(async move {
            if request.headers.get("If-Match").is_some() {
                return Response::new(412);
            }
            if request.method == "GET" && request.path == "/v1/a/c/manifest" {
                let mut resp = Response::with_body(200, stored);
                resp.headers.set("X-Static-Large-Object", "True");
                resp.headers.set("Etag", "physicaljson");
                resp.headers.set("X-Object-Sysmeta-Slo-Etag", "slohash");
                resp.headers.set("X-Object-Sysmeta-Slo-Size", "1");
                resp.headers
                    .set("Content-Type", "application/octet-stream;swift_bytes=1");
                return resp;
            }
            if request.method == "GET" && request.path == "/v1/a/c/s1" {
                let mut r = Response::with_body(200, b"x".to_vec());
                r.headers.set("Etag", "e");
                return r;
            }
            Response::new(404)
        })
    });
    let mut headers = HeaderKeyDict::new();
    headers.set("If-Match", "\"slohash\"");
    let request = Request {
        method: "GET".into(),
        path: "/v1/a/c/manifest".into(),
        query_string: String::new(),
        headers,
        body: Vec::<u8>::new().into(),
    };
    assert!(Slo::new().intercepts_request(&request));
    let mut resp = Slo::new().handle_request_async(request, backend).await;
    assert_eq!(resp.status, 200);
    assert_eq!(resp.headers.get("Etag"), Some("\"slohash\""));
    assert_eq!(
        resp.headers.get("Content-Type"),
        Some("application/octet-stream")
    );
    let body = std::mem::replace(&mut resp.body, swift_http::Body::empty());
    assert_eq!(body.collect_async().await.unwrap(), b"x");
}

#[tokio::test]
async fn head_part_number_refetches_manifest() {
    let stored = serde_json::to_vec(&json!([
        {"name": "/c/s1", "bytes": 3, "hash": "aaa"},
        {"name": "/c/s2", "bytes": 3, "hash": "bbb"}
    ]))
    .unwrap();
    let backend: AsyncNextFn = Arc::new(move |request: Request| {
        let stored = stored.clone();
        Box::pin(async move {
            if request.path == "/v1/a/c/manifest" {
                let mut resp = if request.method == "HEAD" {
                    Response::new(200)
                } else {
                    Response::with_body(200, stored)
                };
                resp.headers.set("X-Static-Large-Object", "True");
                resp.headers.set("X-Object-Sysmeta-Slo-Etag", "slohash");
                resp.headers.set("X-Object-Sysmeta-Slo-Size", "6");
                resp.headers.set("Etag", "physical");
                return resp;
            }
            Response::new(404)
        })
    });
    let request = Request {
        method: "HEAD".into(),
        path: "/v1/a/c/manifest".into(),
        query_string: "part-number=2".into(),
        headers: HeaderKeyDict::new(),
        body: Vec::<u8>::new().into(),
    };
    let resp = Slo::new().reassemble_async(request, backend).await;
    assert_eq!(resp.status, 206);
    assert_eq!(resp.headers.get("X-Parts-Count"), Some("2"));
    assert_eq!(resp.headers.get("Content-Length"), Some("3"));
    assert_eq!(resp.headers.get("Content-Range"), Some("bytes 3-5/6"));
}

#[tokio::test]
async fn part_number_out_of_range_is_plain_416() {
    let stored = serde_json::to_vec(&json!([{"name": "/c/s1", "bytes": 3, "hash": "aaa"}])).unwrap();
    let backend: AsyncNextFn = Arc::new(move |request: Request| {
        let stored = stored.clone();
        Box::pin(async move {
            if request.path == "/v1/a/c/manifest" {
                let mut resp = Response::with_body(200, stored);
                resp.headers.set("X-Static-Large-Object", "True");
                resp.headers.set("X-Object-Sysmeta-Slo-Etag", "slohash");
                resp.headers.set("X-Object-Sysmeta-Slo-Size", "3");
                return resp;
            }
            Response::new(404)
        })
    });
    let request = Request {
        method: "GET".into(),
        path: "/v1/a/c/manifest".into(),
        query_string: "part-number=9".into(),
        headers: HeaderKeyDict::new(),
        body: Vec::<u8>::new().into(),
    };
    let mut resp = Slo::new().reassemble_async(request, backend).await;
    assert_eq!(resp.status, 416);
    let body = resp.body.materialize(u64::MAX).unwrap();
    assert_eq!(body, b"The requested part number is not satisfiable".as_slice());
    assert_eq!(resp.headers.get("X-Parts-Count"), Some("1"));
    assert_eq!(resp.headers.get("Content-Range"), Some("bytes */3"));
}

#[test]
fn container_listing_strips_swift_bytes_from_content_type() {
    let listing = serde_json::to_vec(&json!([{
        "name": "o",
        "bytes": 1,
        "hash": "deadbeef; slo_etag=slohash",
        "content_type": "application/octet-stream;swift_bytes=99"
    }]))
    .unwrap();
    let backend_body = listing.clone();
    let backend: NextFn = Arc::new(move |_r: Request| {
        let mut resp = Response::with_body(200, backend_body.clone());
        resp.headers
            .set("Content-Type", "application/json; charset=utf-8");
        resp
    });
    let req = Request {
        method: "GET".into(),
        path: "/v1/a/c".into(),
        query_string: "format=json".into(),
        headers: HeaderKeyDict::new(),
        body: Vec::<u8>::new().into(),
    };
    let mut resp = Slo::new().handle(req, &backend);
    resp.body.materialize(u64::MAX).unwrap();
    let v: Value = serde_json::from_slice(match &resp.body {
        swift_http::Body::Buffered(b) => b,
        _ => panic!("expected buffered"),
    })
    .unwrap();
    assert_eq!(v[0]["content_type"], "application/octet-stream");
    assert_eq!(v[0]["bytes"], 99);
    let _ = listing;
}
