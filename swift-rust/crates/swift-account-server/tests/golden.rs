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

//! Replay the Python AccountController oracle sequence against the Rust
//! server over real HTTP: statuses, interesting headers and bodies must
//! match.

use std::io::{Read, Write};
use std::path::PathBuf;

use serde_json::Value as Json;
use swift_account_server::{serve, AccountServerConfig};

fn expectations() -> Json {
    let raw = std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/expectations.json"),
    )
    .expect("missing fixtures; run rust/crates/swift-account-server/tests/fixtures/generate.py");
    serde_json::from_slice(&raw).unwrap()
}

fn http_request(
    addr: std::net::SocketAddr,
    method: &str,
    path: &str,
    query: &str,
    headers: &Json,
) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let mut conn = std::net::TcpStream::connect(addr).unwrap();
    let target = if query.is_empty() {
        path.to_string()
    } else {
        format!("{path}?{query}")
    };
    let mut req = format!("{method} {target} HTTP/1.1\r\nHost: t\r\n");
    for (k, v) in headers.as_object().unwrap() {
        req.push_str(&format!("{k}: {}\r\n", v.as_str().unwrap()));
    }
    req.push_str("Content-Length: 0\r\nConnection: close\r\n\r\n");
    conn.write_all(req.as_bytes()).unwrap();
    let mut raw = Vec::new();
    conn.read_to_end(&mut raw).unwrap();
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let body = raw[split + 4..].to_vec();
    let mut lines = head.lines();
    let status: u16 = lines
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    (status, headers, body)
}

#[test]
fn test_account_server_matches_python_oracle() {
    let exp = expectations();
    let tmp = std::env::temp_dir().join(format!("swift-account-golden-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(tmp.join("sda1")).unwrap();

    let config = AccountServerConfig {
        devices: tmp.clone(),
        mount_check: false,
        hash_config: swift_core::hashing::HashPathConfig::new(
            b"".to_vec(),
            exp["hash_suffix"].as_str().unwrap().as_bytes().to_vec(),
        )
        .unwrap(),
        policies: vec![(0, "Policy-0".to_string())],
        fixed_created_at: Some("1751500000.00000".to_string()),
    };
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || serve(listener, config));

    for case in exp["requests"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let (status, headers, body) = http_request(
            addr,
            case["method"].as_str().unwrap(),
            case["path"].as_str().unwrap(),
            case["query"].as_str().unwrap(),
            &case["headers"],
        );
        assert_eq!(
            status,
            case["status"].as_u64().unwrap() as u16,
            "{label}: status (body: {})",
            String::from_utf8_lossy(&body)
        );
        // interesting headers must match exactly
        for (k, want) in case["response_headers"].as_object().unwrap() {
            let got = headers
                .iter()
                .find(|(hk, _)| hk.eq_ignore_ascii_case(k))
                .map(|(_, v)| v.as_str());
            assert_eq!(
                got,
                want.as_str(),
                "{label}: header {k}"
            );
        }
        // no stray x-account-* headers the oracle didn't produce
        for (k, _) in &headers {
            if k.to_lowercase().starts_with("x-account-") {
                assert!(
                    case["response_headers"]
                        .as_object()
                        .unwrap()
                        .keys()
                        .any(|wk| wk.eq_ignore_ascii_case(k)),
                    "{label}: unexpected header {k}"
                );
            }
        }
        // HEAD responses have no body on the wire
        if case["method"] == "HEAD" {
            continue;
        }
        assert_eq!(
            String::from_utf8_lossy(&body),
            case["body"].as_str().unwrap(),
            "{label}: body"
        );
    }
    std::fs::remove_dir_all(&tmp).unwrap();
}
