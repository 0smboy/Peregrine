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
//! _redirect_to_shard 301 on an object PUT and DELETE.

use std::path::PathBuf;
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
        recon_cache_path: PathBuf::from("/var/cache/swift"),
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
    assert_eq!(
        resp.headers.get("X-Backend-Record-Shard-Format"),
        Some("full")
    );
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

    // Python DELETE_object: accept-redirect → 301 to the owning shard
    // (probe L1435). Must not tombstone the root.
    let r = req(
        "DELETE",
        "/sda1/0/AUTH_test/c/p",
        &[
            ("X-Timestamp", "1751500013.00000"),
            ("X-Backend-Accept-Redirect", "true"),
            ("X-Backend-Accept-Quoted-Location", "true"),
        ],
        b"",
    );
    let resp = server.handle(r);
    assert_eq!(resp.status, 301, "object DELETE redirected to its shard");
    assert_eq!(
        resp.headers.get("Location"),
        Some("/.shards_AUTH_test/c-2/p")
    );
    assert_eq!(
        resp.headers.get("X-Backend-Redirect-Timestamp"),
        Some("1751500010.00000")
    );

    // without accept-redirect, DELETE is applied on this DB (204)
    let r = req(
        "DELETE",
        "/sda1/0/AUTH_test/c/p",
        &[("X-Timestamp", "1751500013.00000")],
        b"",
    );
    assert_eq!(server.handle(r).status, 204);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn test_put_object_without_spi_uses_container_policy_for_object_count() {
    // Python PUT_object uses the container SPI when the request omits
    // X-Backend-Storage-Policy-Index. A hardcoded 0 left policy_stat empty
    // and get_info()['object_count'] == 0, so auto-shard skipped.
    use swift_db::ContainerBroker;
    let dir = std::env::temp_dir().join(format!("swift-cs-spi-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("sda1")).unwrap();
    let mut cfg = config(&dir);
    cfg.policies = vec![(0, "Policy-0".into()), (1, "silver".into())];
    cfg.default_policy_index = 1;
    let server = ContainerServer::new(cfg);
    let r = req(
        "PUT",
        "/sda1/0/AUTH_test/c",
        &[
            ("X-Timestamp", "1751500000.00000"),
            ("X-Backend-Storage-Policy-Index", "1"),
        ],
        b"",
    );
    assert!(matches!(server.handle(r).status, 201 | 202));
    let r = req(
        "PUT",
        "/sda1/0/AUTH_test/c/obj1",
        &[
            ("X-Timestamp", "1751500001.00000"),
            ("x-size", "3"),
            ("x-content-type", "text/plain"),
            ("x-etag", "etag"),
        ],
        b"",
    );
    assert_eq!(server.handle(r).status, 201);
    let db = server
        .db_file_for_request(&req("HEAD", "/sda1/0/AUTH_test/c", &[], b""))
        .unwrap();
    let mut broker = ContainerBroker::new(&db, "AUTH_test", "c");
    let info = broker.get_info().unwrap();
    let spi = info
        .iter()
        .find(|(k, _)| k == "storage_policy_index")
        .and_then(|(_, v)| v.as_i64())
        .unwrap();
    let oc = info
        .iter()
        .find(|(k, _)| k == "object_count")
        .and_then(|(_, v)| v.as_i64())
        .unwrap();
    assert_eq!(spi, 1, "{info:?}");
    assert_eq!(
        oc, 1,
        "object_count must follow container SPI, got {info:?}"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn test_put_shard_persists_quoted_root_sysmeta() {
    // Python PUT_shard calls `_update_metadata` so Quoted-Root sticks.
    let dir = std::env::temp_dir().join(format!("swift-cs-quoted-root-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("sda1")).unwrap();
    let server = ContainerServer::new(config(&dir));
    let mut sr = ShardRange::new(".shards_AUTH_test/c-0", "1751500010.00000", "", "");
    sr.state = shard_state::CREATED;
    let body = serde_json::to_vec(&vec![sr.to_json()]).unwrap();
    let r = req(
        "PUT",
        "/sda1/0/.shards_AUTH_test/c-0",
        &[
            ("X-Timestamp", "1751500010.00000"),
            ("X-Backend-Record-Type", "shard"),
            ("X-Backend-Auto-Create", "True"),
            ("X-Backend-Allow-Reserved-Names", "true"),
            ("X-Container-Sysmeta-Shard-Quoted-Root", "AUTH_test/rootc"),
            ("X-Container-Sysmeta-Sharding", "True"),
        ],
        &body,
    );
    assert!(matches!(server.handle(r).status, 201 | 202));
    let db = server
        .db_file_for_request(&req(
            "HEAD",
            "/sda1/0/.shards_AUTH_test/c-0",
            &[("X-Backend-Allow-Reserved-Names", "true")],
            b"",
        ))
        .unwrap();
    let mut broker = swift_db::ContainerBroker::new(&db, ".shards_AUTH_test", "c-0");
    assert!(
        !broker.is_root_container().unwrap(),
        "Quoted-Root must make this a shard"
    );
    let own = broker.get_own_shard_range(true).unwrap();
    assert!(own.is_some(), "PUT_shard body is the own range");
    let resp = server.handle(req(
        "GET",
        "/sda1/0/.shards_AUTH_test/c-0",
        &[
            ("X-Backend-Record-Type", "shard"),
            ("X-Backend-Allow-Reserved-Names", "true"),
        ],
        b"",
    ));
    assert_eq!(resp.status, 200);
    assert_eq!(
        resp.headers.get("X-Container-Sysmeta-Shard-Quoted-Root"),
        Some("AUTH_test/rootc"),
        "GET_shard must emit Quoted-Root (probe test_shrinking L1808)"
    );
    assert_eq!(
        resp.headers.get("X-Container-Sysmeta-Sharding"),
        Some("True")
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn test_sharded_root_head_count_rolls_up_after_shard_stats_put() {
    // Probe `_test_sharded_listing` after extra PUTs + run_sharders:
    // HEAD object-count must follow newer shard-range stats (100 → 200).
    let dir = std::env::temp_dir().join(format!("swift-cs-head-count-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("sda1")).unwrap();
    let server = ContainerServer::new(config(&dir));
    let r = req(
        "PUT",
        "/sda1/0/AUTH_test/c",
        &[("X-Timestamp", "1751500000.00000")],
        b"",
    );
    assert!(matches!(server.handle(r).status, 201 | 202));

    let epoch = "1751500010.00000";
    let mut s1 = ShardRange::new(".shards_AUTH_test/c-0", epoch, "", "m");
    s1.state = shard_state::ACTIVE;
    s1.object_count = 50;
    let mut s2 = ShardRange::new(".shards_AUTH_test/c-1", epoch, "m", "");
    s2.state = shard_state::ACTIVE;
    s2.object_count = 50;
    let ranges = serde_json::Value::Array(vec![s1.to_json(), s2.to_json()]);
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

    let db = server
        .db_file_for_request(&req("HEAD", "/sda1/0/AUTH_test/c", &[], b""))
        .unwrap();
    {
        let mut broker = swift_db::ContainerBroker::new(&db, "AUTH_test", "c");
        broker.enable_sharding(epoch).unwrap();
        assert!(broker.set_sharding_state().unwrap(), "UNSHARDED → SHARDING");
        assert!(broker.set_sharded_state().unwrap(), "SHARDING → SHARDED");
        assert_eq!(broker.get_shard_usage().unwrap(), (0, 100));
    }

    let head = server.handle(req("HEAD", "/sda1/0/AUTH_test/c", &[], b""));
    assert_eq!(head.status, 204);
    assert_eq!(
        head.headers.get("X-Container-Object-Count").as_deref(),
        Some("100"),
        "{:?}",
        head.headers
    );

    let mut s1b = ShardRange::new(".shards_AUTH_test/c-0", epoch, "", "m");
    s1b.state = shard_state::ACTIVE;
    s1b.object_count = 150;
    s1b.bytes_used = 150;
    s1b.meta_timestamp = "1751500099.00000".into();
    s1b.reported = 0;
    let r = req(
        "PUT",
        "/sda1/0/AUTH_test/c",
        &[
            ("X-Timestamp", "1751500099.00000"),
            ("X-Backend-Record-Type", "shard"),
        ],
        serde_json::to_vec(&vec![s1b.to_json()]).unwrap().as_slice(),
    );
    assert!(matches!(server.handle(r).status, 201 | 202));

    let head = server.handle(req("HEAD", "/sda1/0/AUTH_test/c", &[], b""));
    assert_eq!(
        head.headers.get("X-Container-Object-Count").as_deref(),
        Some("200"),
        "HEAD must roll up newer shard stats, {:?}",
        head.headers
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn test_get_object_listing_uses_retiring_db_while_sharding() {
    // Python GET_object lists broker.get_brokers()[0] (retiring). Fresh
    // epoch has no object rows. Probe L1321 obj-0000-0049.
    let dir = std::env::temp_dir().join(format!("swift-cs-retiring-list-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("sda1")).unwrap();
    let server = ContainerServer::new(config(&dir));
    let r = req(
        "PUT",
        "/sda1/0/AUTH_test/c",
        &[("X-Timestamp", "1751500000.00000")],
        b"",
    );
    assert!(matches!(server.handle(r).status, 201 | 202));
    let r = req(
        "PUT",
        "/sda1/0/AUTH_test/c/obj-0000",
        &[
            ("X-Timestamp", "1751500001.00000"),
            ("x-size", "0"),
            ("x-content-type", "text/plain"),
            ("x-etag", "d41d8cd98f00b204e9800998ecf8427e"),
        ],
        b"",
    );
    assert_eq!(server.handle(r).status, 201);

    let db = server
        .db_file_for_request(&req("HEAD", "/sda1/0/AUTH_test/c", &[], b""))
        .unwrap();
    let mut broker = swift_db::ContainerBroker::new(&db, "AUTH_test", "c");
    broker.enable_sharding("1751500010.00000").unwrap();
    assert!(broker.set_sharding_state().unwrap());
    assert!(
        broker.retiring_broker().is_some(),
        "epoch DB must leave a retiring unsuffixed file"
    );

    let mut get = req("GET", "/sda1/0/AUTH_test/c", &[], b"");
    get.query_string = "format=json".into();
    let resp = server.handle(get);
    assert_eq!(resp.status, 200, "{}", resp.reason);
    let body = resp.body.into_vec(u64::MAX).unwrap();
    let listing: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let names: Vec<&str> = listing
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.get("name").and_then(|n| n.as_str()))
        .collect();
    assert!(
        names.contains(&"obj-0000"),
        "sharding GET must list retiring rows, got {names:?}"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}
