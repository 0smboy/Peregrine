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

//! Replay the Python ObjectController oracle against the Rust object
//! server, plus a Rust object→container update integration check.

use std::io::{Read, Write};
use std::path::PathBuf;

use serde_json::Value as Json;
use swift_object_server::{serve, ContainerUpdateMode, ObjectServerConfig};

fn expectations() -> Json {
    let raw = std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/expectations.json"),
    )
    .expect("missing fixtures; run rust/crates/swift-object-server/tests/fixtures/generate.py");
    serde_json::from_slice(&raw).unwrap()
}

fn http_request(
    addr: std::net::SocketAddr,
    method: &str,
    path: &str,
    headers: &Json,
    body: &[u8],
) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let mut conn = std::net::TcpStream::connect(addr).unwrap();
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: t\r\n");
    let mut has_clen = false;
    let mut has_ctype = false;
    for (k, v) in headers.as_object().unwrap() {
        if k.eq_ignore_ascii_case("content-length") {
            has_clen = true;
        }
        if k.eq_ignore_ascii_case("content-type") {
            has_ctype = true;
        }
        req.push_str(&format!("{k}: {}\r\n", v.as_str().unwrap()));
    }
    if !has_clen {
        req.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    let _ = has_ctype;
    req.push_str("Connection: close\r\n\r\n");
    conn.write_all(req.as_bytes()).unwrap();
    conn.write_all(body).unwrap();
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

fn object_config(devices: &std::path::Path, hash_suffix: &str) -> ObjectServerConfig {
    ObjectServerConfig {
        devices: devices.to_path_buf(),
        mount_check: false,
        hash_config: swift_core::hashing::HashPathConfig::new(
            b"".to_vec(),
            hash_suffix.as_bytes().to_vec(),
        )
        .unwrap(),
        diskfile: swift_diskfile::DiskFileConfig::default(),
        policies: std::collections::HashMap::from([(0, swift_diskfile::PolicyKind::Replication)]),
        container_update_timeout: std::time::Duration::from_secs(1),
        container_update_mode: ContainerUpdateMode::Sync,
    }
}

#[test]
fn test_object_server_matches_python_oracle() {
    let exp = expectations();
    let tmp = std::env::temp_dir().join(format!("swift-obj-golden-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(tmp.join("sda1")).unwrap();

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let config = object_config(&tmp, exp["hash_suffix"].as_str().unwrap());
    std::thread::spawn(move || serve(listener, config));

    for case in exp["requests"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let body = case["body"].as_str().unwrap().as_bytes();
        let (status, headers, resp_body) = http_request(
            addr,
            case["method"].as_str().unwrap(),
            case["path"].as_str().unwrap(),
            &case["headers"],
            body,
        );
        assert_eq!(
            status,
            case["status"].as_u64().unwrap() as u16,
            "{label}: status (body: {})",
            String::from_utf8_lossy(&resp_body)
        );
        // On 2xx, all content metadata must match; on errors only the
        // status is contractual (bodies are swob boilerplate).
        let keys: &[&str] = if status < 300 {
            &[
                "Content-Range",
                "Content-Type",
                "Content-Length",
                "Etag",
                "X-Object-Meta-Color",
                "X-Timestamp",
                "X-Backend-Timestamp",
            ]
        } else {
            &["Content-Range"]
        };
        for key in keys {
            if let Some(want) = case["response_headers"]
                .as_object()
                .unwrap()
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(key))
                .map(|(_, v)| v.as_str().unwrap())
            {
                let got = headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case(key))
                    .map(|(_, v)| v.as_str());
                assert_eq!(got, Some(want), "{label}: header {key}");
            }
        }
        if case["method"] == "HEAD" {
            continue;
        }
        // 2xx bodies (object payloads) must match exactly; error bodies
        // only need the status
        if status < 300 {
            assert_eq!(
                resp_body,
                case["response_body"].as_str().unwrap().as_bytes(),
                "{label}: body"
            );
        }
    }
    std::fs::remove_dir_all(&tmp).unwrap();
}

#[test]
fn test_object_put_updates_container_server() {
    let tmp = std::env::temp_dir().join(format!("swift-o2c-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(tmp.join("sda1")).unwrap();
    let hash_cfg =
        || swift_core::hashing::HashPathConfig::new(b"".to_vec(), b"changeme".to_vec()).unwrap();

    // container server
    let cont_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let cont_addr = cont_listener.local_addr().unwrap();
    let cont_config = swift_container_server::ContainerServerConfig {
        devices: tmp.clone(),
        mount_check: false,
        hash_config: hash_cfg(),
        policies: vec![(0, "Policy-0".to_string())],
        default_policy_index: 0,
        fixed_created_at: None,
    };
    std::thread::spawn(move || swift_container_server::serve(cont_listener, cont_config));

    // object server
    let obj_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let obj_addr = obj_listener.local_addr().unwrap();
    let obj_tmp = tmp.clone();
    std::thread::spawn(move || serve(obj_listener, object_config(&obj_tmp, "changeme")));
    std::thread::sleep(std::time::Duration::from_millis(150));

    // create the container
    let (status, _, _) = http_request(
        cont_addr,
        "PUT",
        "/sda1/0/AUTH_o2c/box",
        &serde_json::json!({"X-Timestamp": "1751500000.00000"}),
        b"",
    );
    assert_eq!(status, 201);

    // PUT an object with container-update headers pointing at the
    // container server
    let (status, _, _) = http_request(
        obj_addr,
        "PUT",
        "/sda1/0/AUTH_o2c/box/thing",
        &serde_json::json!({
            "X-Timestamp": "1751500001.00000",
            "Content-Type": "text/plain",
            "Content-Length": "5",
            "X-Container-Host": cont_addr.to_string(),
            "X-Container-Partition": "0",
            "X-Container-Device": "sda1",
        }),
        b"hello",
    );
    assert_eq!(status, 201, "object PUT");

    // the container listing must show the object
    let (status, _, body) = http_request(
        cont_addr,
        "GET",
        "/sda1/0/AUTH_o2c/box?format=json",
        &serde_json::json!({}),
        b"",
    );
    assert_eq!(status, 200);
    let listing: Json = serde_json::from_slice(&body).unwrap();
    assert_eq!(listing[0]["name"], "thing", "{listing}");
    assert_eq!(listing[0]["bytes"], 5);
    std::fs::remove_dir_all(&tmp).unwrap();
}
