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

use std::sync::{Arc, Mutex};

use swift_http::{HeaderKeyDict, Request, Response};
use swift_middleware::{DynamicLargeObject, Middleware, NextFn};

fn get_req() -> Request {
    Request {
        method: "GET".to_string(),
        path: "/v1/a/c/manifest".to_string(),
        query_string: String::new(),
        headers: HeaderKeyDict::new(),
        body: swift_http::Body::empty(),
    }
}

fn manifest_response(value: &str) -> Response {
    let mut response = Response::with_body(200, Vec::new());
    response.headers.set("X-Object-Manifest", value);
    response
}

// The manifest header is re-issued per request: a Response is not Clone
// (its body may be a stream), so canned routes rebuild it each call.
fn manifest_value(resp: &Response) -> String {
    resp.headers.get("X-Object-Manifest").unwrap().to_string()
}

fn observed_listing_query(x_object_manifest: &str) -> String {
    let manifest = manifest_value(&manifest_response(x_object_manifest));
    let observed = Arc::new(Mutex::new(None));
    let observed_for_backend = Arc::clone(&observed);
    let backend: NextFn = Arc::new(move |req: Request| match req.path.as_str() {
        "/v1/a/c/manifest" => manifest_response(&manifest),
        "/v1/a/c" => {
            *observed_for_backend.lock().unwrap() = Some(req.query_string);
            Response::with_body(200, b"[]".to_vec())
        }
        _ => Response::new(404),
    });

    let response = DynamicLargeObject::new().handle(get_req(), &backend);
    assert_eq!(response.status, 200);

    let query = observed
        .lock()
        .unwrap()
        .take()
        .expect("DLO must issue a container-listing subrequest");
    query
}

#[test]
fn manifest_prefix_is_unquoted_once_then_quoted_for_the_listing() {
    let cases = [
        ("c/ascii", "prefix=ascii&format=json"),
        ("c/literal_%25ff", "prefix=literal_%25ff&format=json"),
        ("c/existing_%25", "prefix=existing_%25&format=json"),
        (
            "c/single_decode_%2525",
            "prefix=single_decode_%2525&format=json",
        ),
        ("c/malformed_%", "prefix=malformed_%25&format=json"),
        ("c/malformed_%2", "prefix=malformed_%252&format=json"),
        ("c/malformed_%GG", "prefix=malformed_%25GG&format=json"),
        ("c/non_utf8_%FF", "prefix=non_utf8_%EF%BF%BD&format=json"),
    ];

    for (manifest, expected_query) in cases {
        assert_eq!(
            observed_listing_query(manifest),
            expected_query,
            "wrong listing query for {manifest:?}"
        );
    }
}

#[test]
fn percent_named_segments_are_reassembled() {
    let manifest = manifest_value(&manifest_response("c/segs_%25ff"));
    let observed = Arc::new(Mutex::new(None));
    let observed_for_backend = Arc::clone(&observed);
    let backend: NextFn = Arc::new(move |req: Request| match req.path.as_str() {
        "/v1/a/c/manifest" => manifest_response(&manifest),
        "/v1/a/c" => {
            *observed_for_backend.lock().unwrap() = Some(req.query_string.clone());
            if req.query_string == "prefix=segs_%25ff&format=json" {
                Response::with_body(
                    200,
                    br#"[{"name":"segs_%ffa","bytes":10,"hash":"16c52c6e8326c071da771e66dc6e9e57"}]"#
                        .to_vec(),
                )
            } else {
                Response::with_body(200, b"[]".to_vec())
            }
        }
        "/v1/a/c/segs_%ffa" => Response::with_body(200, b"AAAAAAAAAA".to_vec()),
        _ => Response::new(404),
    });

    let mut response = DynamicLargeObject::new().handle(get_req(), &backend);

    assert_eq!(response.status, 200);
    assert_eq!(response.body.materialize(u64::MAX).unwrap(), b"AAAAAAAAAA");
    assert_eq!(
        observed.lock().unwrap().as_deref(),
        Some("prefix=segs_%25ff&format=json")
    );
}
