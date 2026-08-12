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

//! Differential tests against golden swob fixtures.

use std::path::PathBuf;

use serde_json::Value as Json;
use swift_http::*;

fn expectations() -> Json {
    let raw = std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/expectations.json"),
    )
    .expect("missing fixtures; run rust/crates/swift-http/tests/fixtures/generate.py");
    serde_json::from_slice(&raw).unwrap()
}

#[test]
fn test_range_semantics_match_swob() {
    let exp = expectations();
    for case in exp["ranges"].as_array().unwrap() {
        let header = case["header"].as_str().unwrap();
        let parsed = Range::parse(header);
        if !case["valid"].as_bool().unwrap() {
            assert!(parsed.is_err(), "{header}: swob rejects this");
            continue;
        }
        let parsed = parsed.unwrap_or_else(|e| panic!("{header}: {e}"));
        let want_ranges: Vec<(Option<u64>, Option<u64>)> = case["ranges"]
            .as_array()
            .unwrap()
            .iter()
            .map(|pair| (pair[0].as_u64(), pair[1].as_u64()))
            .collect();
        assert_eq!(parsed.ranges, want_ranges, "{header}: parsed ranges");
        assert_eq!(
            parsed.to_header(),
            case["str"].as_str().unwrap(),
            "{header}: str()"
        );
        for (key, want) in case["for_length"].as_object().unwrap() {
            let length = if key == "null" {
                None
            } else {
                Some(key.parse::<u64>().unwrap())
            };
            let got = parsed.ranges_for_length(length);
            match want {
                Json::Null => assert!(got.is_none(), "{header} @ {key}: expected ignore"),
                Json::Array(items) => {
                    let want: Vec<(u64, u64)> = items
                        .iter()
                        .map(|p| (p[0].as_u64().unwrap(), p[1].as_u64().unwrap()))
                        .collect();
                    assert_eq!(got, Some(want), "{header} @ {key}");
                }
                other => panic!("{other:?}"),
            }
        }
    }
}

#[test]
fn test_match_semantics_match_swob() {
    let exp = expectations();
    for case in exp["matches"].as_array().unwrap() {
        let m = Match::parse(case["header"].as_str().unwrap());
        for (val, want) in case["checks"].as_object().unwrap() {
            assert_eq!(
                m.matches(val),
                want.as_bool().unwrap(),
                "{:?} contains {val:?}",
                case["header"]
            );
        }
    }
}

#[test]
fn test_title_case_matches_python() {
    let exp = expectations();
    for (key, want) in exp["titles"].as_object().unwrap() {
        assert_eq!(
            title_case(key),
            want.as_str().unwrap(),
            "title case of {key:?}"
        );
    }
}

#[test]
fn test_http_dates_match_python() {
    let exp = expectations();
    for case in exp["dates"].as_array().unwrap() {
        let secs = case["secs"].as_i64().unwrap();
        let want = case["formatted"].as_str().unwrap();
        assert_eq!(http_date(secs), want, "http_date({secs})");
        assert_eq!(parse_http_date(want), Some(secs), "parse of {want:?}");
    }
}

#[test]
fn test_server_round_trip() {
    use std::io::{Read, Write};
    use std::sync::Arc;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handler: Handler = Arc::new(|mut req: Request| {
        let body = req.body.materialize(u64::MAX).unwrap().to_vec();
        let mut resp = Response::with_body(
            200,
            format!(
                "{} {} q={} body={}",
                req.method,
                req.path,
                req.query_string,
                String::from_utf8_lossy(&body)
            ),
        );
        resp.headers
            .set("X-Echo", req.headers.get("x-test").unwrap_or(""));
        resp
    });
    std::thread::spawn(move || serve_forever(listener, handler));

    let mut conn = std::net::TcpStream::connect(addr).unwrap();
    // two pipelined keep-alive requests, the second with a body
    conn.write_all(
        b"GET /v1/a/%E4%B8%AD?marker=x HTTP/1.1\r\nX-Test: hi\r\n\r\n\
          PUT /v1/a/c/o HTTP/1.1\r\nContent-Length: 5\r\nX-Test: two\r\n\r\nhello",
    )
    .unwrap();
    let mut buf = Vec::new();
    conn.set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    // read until both responses arrive
    let mut tmp = [0u8; 4096];
    while buf.windows(4).filter(|w| w == b"\r\n\r\n").count() < 2
        || !String::from_utf8_lossy(&buf).contains("body=hello")
    {
        let n = conn.read(&mut tmp).unwrap();
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    let text = String::from_utf8_lossy(&buf);
    assert!(text.contains("HTTP/1.1 200 OK"), "{text}");
    assert!(text.contains("X-Echo: hi"), "{text}");
    assert!(text.contains("GET /v1/a/中 q=marker=x"), "{text}");
    assert!(text.contains("PUT /v1/a/c/o"), "{text}");
    assert!(text.contains("body=hello"), "{text}");
}
