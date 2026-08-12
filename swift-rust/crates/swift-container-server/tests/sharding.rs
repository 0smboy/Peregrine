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

//! The container-server shard request paths: record-type=shard PUT (merge
//! shard ranges), record-type=shard GET (shard-range listing), and the
//! _redirect_to_shard 301 on an object PUT.

use swift_container_server::{ContainerServer, ContainerServerConfig};
use swift_db::{shard_state, ShardRange};
use swift_http::{HeaderKeyDict, Request};

fn config(devices: &std::path::Path) -> ContainerServerConfig {
    ContainerServerConfig {
        devices: devices.to_path_buf(),
        mount_check: false,
        hash_config: swift_core::hashing::HashPathConfig::new(b"".to_vec(), b"changeme".to_vec())
            .unwrap(),
        policies: vec![(0, "Policy-0".to_string())],
        default_policy_index: 0,
        fixed_created_at: Some("1751500000.00000".to_string()),
    }
}

fn req(method: &str, path: &str, headers: &[(&str, &str)], body: &[u8]) -> Request {
    let mut h = HeaderKeyDict::new();
    for (k, v) in headers {
        h.set(k, v);
    }
    Request {
        method: method.into(),
        path: path.into(),
        query_string: String::new(),
        headers: h,
        body: body.into(),
    }
}

#[test]
fn test_shard_put_get_and_redirect() {
    let dir = std::env::temp_dir().join(format!("swift-cs-shard-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("sda1")).unwrap();
    let server = ContainerServer::new(config(&dir));

    // create the container
    let r = req(
        "PUT",
        "/sda1/0/AUTH_test/c",
        &[("X-Timestamp", "1751500000.00000")],
        b"",
    );
    assert!(matches!(server.handle(r).status, 201 | 202));

    // PUT record-type=shard: two ACTIVE shard ranges
    let ranges = serde_json::Value::Array(vec![
        ShardRange {
            state: shard_state::ACTIVE,
            ..ShardRange::new(".shards_AUTH_test/c-1", "1751500010.00000", "", "m")
        }
        .to_json(),
        ShardRange {
            state: shard_state::ACTIVE,
            ..ShardRange::new(".shards_AUTH_test/c-2", "1751500010.00000", "m", "")
        }
        .to_json(),
    ]);
    let r = req(
        "PUT",
        "/sda1/0/AUTH_test/c",
        &[
            ("X-Timestamp", "1751500011.00000"),
            ("X-Backend-Record-Type", "shard"),
        ],
        serde_json::to_vec(&ranges).unwrap().as_slice(),
    );
    assert!(matches!(server.handle(r).status, 201 | 202));

    // GET record-type=shard: the two ranges come back as JSON
    let r = req(
        "GET",
        "/sda1/0/AUTH_test/c",
        &[("X-Backend-Record-Type", "shard")],
        b"",
    );
    let resp = server.handle(r);
    assert_eq!(resp.status, 200);
    assert_eq!(resp.headers.get("X-Backend-Record-Type"), Some("shard"));
    let body = resp.body.into_vec(u64::MAX).unwrap();
    let got: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let arr = got.as_array().unwrap();
    assert_eq!(arr.len(), 2, "{got}");
    assert_eq!(arr[0]["name"], ".shards_AUTH_test/c-1");
    assert_eq!(arr[1]["name"], ".shards_AUTH_test/c-2");

    // an object PUT with accept-redirect is 301'd to the shard that owns it
    let r = req(
        "PUT",
        "/sda1/0/AUTH_test/c/p",
        &[
            ("X-Timestamp", "1751500012.00000"),
            ("X-Backend-Accept-Redirect", "true"),
            ("x-size", "0"),
            ("x-content-type", "text/plain"),
            ("x-etag", "d41d8cd98f00b204e9800998ecf8427e"),
        ],
        b"",
    );
    let resp = server.handle(r);
    assert_eq!(resp.status, 301, "object update redirected to its shard");
    // "p" is in (m, +inf] -> c-2
    assert_eq!(
        resp.headers.get("Location"),
        Some("/.shards_AUTH_test/c-2/p")
    );
    assert_eq!(
        resp.headers.get("X-Backend-Redirect-Timestamp"),
        Some("1751500010.00000")
    );

    // without accept-redirect, the object PUT is applied normally (201)
    let r = req(
        "PUT",
        "/sda1/0/AUTH_test/c/p",
        &[
            ("X-Timestamp", "1751500012.00000"),
            ("x-size", "0"),
            ("x-content-type", "text/plain"),
            ("x-etag", "d41d8cd98f00b204e9800998ecf8427e"),
        ],
        b"",
    );
    assert_eq!(server.handle(r).status, 201);
    std::fs::remove_dir_all(&dir).unwrap();
}
