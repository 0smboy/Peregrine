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

//! Replay the Python ContainerController oracle against the Rust
//! container server, plus a Rust↔Rust container→account update
//! integration check.

use std::io::{Read, Write};
use std::path::PathBuf;

use serde_json::Value as Json;
use swift_container_server::{serve, ContainerServerConfig};
use swift_db::{replicate_container_db, ContainerBroker, DbValue};

fn tmpdir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("swift-cont-golden-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("sda1")).unwrap();
    dir
}

fn assert_objects_match(desc: &str, got: &[Vec<DbValue>], want: &Json) {
    let want = want.as_array().unwrap();
    assert_eq!(got.len(), want.len(), "{desc}: row count {got:?}");
    for (i, (row, wrow)) in got.iter().zip(want).enumerate() {
        let wrow = wrow.as_array().unwrap();
        for (c, (g, w)) in row.iter().zip(wrow).enumerate() {
            match (w, g) {
                (Json::String(s), DbValue::Text(t)) => assert_eq!(t, s, "{desc} r{i}c{c}"),
                (Json::Number(n), DbValue::Int(x)) => {
                    assert_eq!(*x, n.as_i64().unwrap(), "{desc} r{i}c{c}")
                }
                (Json::Null, DbValue::Null) => {}
                other => panic!("{desc} r{i}c{c}: {other:?}"),
            }
        }
    }
}

fn expectations() -> Json {
    let raw = std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/expectations.json"),
    )
    .expect("missing fixtures; run rust/crates/swift-container-server/tests/fixtures/generate.py");
    serde_json::from_slice(&raw).unwrap()
}

fn http_request(
    addr: std::net::SocketAddr,
    method: &str,
    path: &str,
    query: &str,
    headers: &Json,
    body: &str,
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
    req.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    ));
    conn.write_all(req.as_bytes()).unwrap();
    conn.write_all(body.as_bytes()).unwrap();
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

fn container_config(devices: &std::path::Path, hash_suffix: &str) -> ContainerServerConfig {
    ContainerServerConfig {
        devices: devices.to_path_buf(),
        mount_check: false,
        hash_config: swift_core::hashing::HashPathConfig::new(
            b"".to_vec(),
            hash_suffix.as_bytes().to_vec(),
        )
        .unwrap(),
        policies: vec![(0, "Policy-0".to_string())],
        default_policy_index: 0,
        fixed_created_at: Some("1751500000.00000".to_string()),
    }
}

#[test]
fn test_container_server_matches_python_oracle() {
    let exp = expectations();
    let tmp = std::env::temp_dir().join(format!("swift-container-golden-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(tmp.join("sda1")).unwrap();

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let config = container_config(&tmp, exp["hash_suffix"].as_str().unwrap());
    std::thread::spawn(move || serve(listener, config));

    for case in exp["requests"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let (status, headers, body) = http_request(
            addr,
            case["method"].as_str().unwrap(),
            case["path"].as_str().unwrap(),
            case["query"].as_str().unwrap(),
            &case["headers"],
            case["body"].as_str().unwrap(),
        );
        assert_eq!(
            status,
            case["status"].as_u64().unwrap() as u16,
            "{label}: status (body: {})",
            String::from_utf8_lossy(&body)
        );
        for (k, want) in case["response_headers"].as_object().unwrap() {
            let got = headers
                .iter()
                .find(|(hk, _)| hk.eq_ignore_ascii_case(k))
                .map(|(_, v)| v.as_str());
            assert_eq!(got, want.as_str(), "{label}: header {k}");
        }
        for (k, _) in &headers {
            let kl = k.to_lowercase();
            if kl.starts_with("x-container-") || kl.starts_with("x-backend-") {
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
        if case["method"] == "HEAD" {
            continue;
        }
        assert_eq!(
            String::from_utf8_lossy(&body),
            case["response_body"].as_str().unwrap(),
            "{label}: body"
        );
    }
    std::fs::remove_dir_all(&tmp).unwrap();
}

#[test]
fn test_container_put_updates_account_server() {
    // Rust container server drives a Rust account server through the
    // X-Account-* update side channel, like a real cluster does.
    let tmp = std::env::temp_dir().join(format!("swift-c2a-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(tmp.join("sda1")).unwrap();
    let hash_cfg =
        || swift_core::hashing::HashPathConfig::new(b"".to_vec(), b"changeme".to_vec()).unwrap();

    // account server
    let acct_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let acct_addr = acct_listener.local_addr().unwrap();
    let acct_config = swift_account_server::AccountServerConfig {
        devices: tmp.clone(),
        mount_check: false,
        hash_config: hash_cfg(),
        policies: vec![(0, "Policy-0".to_string())],
        fixed_created_at: Some("1751500000.00000".to_string()),
    };
    std::thread::spawn(move || swift_account_server::serve(acct_listener, acct_config));

    // container server
    let cont_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let cont_addr = cont_listener.local_addr().unwrap();
    let cont_config = container_config(&tmp, "changeme");
    std::thread::spawn(move || serve(cont_listener, cont_config));

    // create the account
    let (status, _, _) = http_request(
        acct_addr,
        "PUT",
        "/sda1/0/AUTH_link",
        "",
        &serde_json::json!({"X-Timestamp": "1751500000.00000"}),
        "",
    );
    assert_eq!(status, 201);

    // PUT the container with account-update headers pointing at the
    // live Rust account server
    let (status, _, _) = http_request(
        cont_addr,
        "PUT",
        "/sda1/0/AUTH_link/c1",
        "",
        &serde_json::json!({
            "X-Timestamp": "1751500001.00000",
            "X-Account-Host": acct_addr.to_string(),
            "X-Account-Partition": "0",
            "X-Account-Device": "sda1",
        }),
        "",
    );
    assert_eq!(status, 201);

    // the account listing must now show the container
    let (status, _, body) = http_request(
        acct_addr,
        "GET",
        "/sda1/0/AUTH_link",
        "format=json",
        &serde_json::json!({}),
        "",
    );
    assert_eq!(status, 200);
    let listing: Json = serde_json::from_slice(&body).unwrap();
    assert_eq!(listing[0]["name"], "c1", "{listing}");
    std::fs::remove_dir_all(&tmp).unwrap();
}

#[test]
fn test_replicate_rpc_matches_python() {
    // Drive the Rust REPLICATE handler with the same merge_items /
    // merge_syncs RPCs the Python ReplicatorRpc received, and check the
    // resulting object + incoming_sync rows match.
    let root = expectations();
    let exp = &root["replicate"];
    let tmp = tmpdir("replicate");
    let account = exp["account"].as_str().unwrap();
    let container = exp["container"].as_str().unwrap();
    let partition = exp["partition"].as_str().unwrap();
    let hsh = exp["hash"].as_str().unwrap();

    let suffix = &hsh[hsh.len() - 3..];
    let db_path = tmp
        .join("sda1")
        .join("containers")
        .join(partition)
        .join(suffix)
        .join(hsh)
        .join(format!("{hsh}.db"));
    let mut init = ContainerBroker::new(&db_path, account, container);
    init.initialize(
        "1751500000.00000",
        0,
        "1751500000.00000",
        "fixed-db-id-0001",
    )
    .unwrap();
    init.get_info().unwrap();

    let config = container_config(&tmp, root["hash_suffix"].as_str().unwrap());
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || serve(listener, config));
    std::thread::sleep(std::time::Duration::from_millis(100));

    let rpc_path = format!("/sda1/{partition}/{hsh}");

    let body = serde_json::to_string(&exp["merge_items"]["op"]).unwrap();
    let (status, _, _) = http_request(
        addr,
        "REPLICATE",
        &rpc_path,
        "",
        &serde_json::json!({}),
        &body,
    );
    assert_eq!(
        status,
        exp["merge_items"]["status"].as_u64().unwrap() as u16,
        "merge_items status"
    );
    let mut broker = ContainerBroker::new(&db_path, account, container);
    assert_objects_match(
        "replicate merge_items rows",
        &broker.object_rows().unwrap(),
        &exp["merge_items"]["rows"],
    );

    let syncs = serde_json::json!(["merge_syncs", [{"sync_point": 42, "remote_id": "peer-2"}]]);
    let (status, _, _) = http_request(
        addr,
        "REPLICATE",
        &rpc_path,
        "",
        &serde_json::json!({}),
        &syncs.to_string(),
    );
    assert_eq!(
        status,
        exp["merge_syncs"]["status"].as_u64().unwrap() as u16,
        "merge_syncs status"
    );
    std::fs::remove_dir_all(&tmp).unwrap();
}

#[test]
fn test_usync_push_replication_between_two_servers() {
    // The push side of db replication: a local broker with rows usyncs
    // them (via the REPLICATE merge_items RPC) to a second container
    // server, which ends up with the same objects.
    let tmp = tmpdir("usync");
    let account = "a";
    let container = "repl2";
    // both DBs live under the same hash path, on two "devices"
    let hash_cfg =
        swift_core::hashing::HashPathConfig::new(b"".to_vec(), b"changeme".to_vec()).unwrap();
    let hsh = hash_cfg.hash_path(account, Some(container), None).unwrap();
    let suffix = &hsh[hsh.len() - 3..];
    let db_rel = format!("containers/0/{suffix}/{hsh}/{hsh}.db");

    // local (source) broker, populated with two objects
    let local_db = tmp.join("sda1").join(&db_rel);
    let mut local = ContainerBroker::new(&local_db, account, container);
    local
        .initialize("1751500000.00000", 0, "1751500000.00000", "src-db-id")
        .unwrap();
    local
        .put_object(
            "obj-a",
            "1751500002.00000",
            5,
            "text/a",
            "ea",
            0,
            0,
            None,
            None,
        )
        .unwrap();
    local
        .put_object(
            "obj-b",
            "1751500003.00000",
            7,
            "text/b",
            "eb",
            0,
            0,
            None,
            None,
        )
        .unwrap();
    local.get_info().unwrap();

    // remote (destination) container server, with an empty DB at the
    // same hash path on device sdb1
    std::fs::create_dir_all(tmp.join("sdb1")).unwrap();
    let remote_db = tmp.join("sdb1").join(&db_rel);
    let mut remote = ContainerBroker::new(&remote_db, account, container);
    remote
        .initialize("1751500000.00000", 0, "1751500000.00000", "dst-db-id")
        .unwrap();
    remote.get_info().unwrap();

    let config = container_config(&tmp, "changeme");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || serve(listener, config));
    std::thread::sleep(std::time::Duration::from_millis(100));

    // usync loop: read local items since -1, push a merge_items RPC
    let items = local.get_items_since(-1, 1000).unwrap();
    let json_items: Vec<serde_json::Value> = items
        .iter()
        .map(|(rowid, rec)| {
            serde_json::json!({
                "ROWID": rowid,
                "name": rec.name,
                "created_at": rec.created_at,
                "size": rec.size,
                "content_type": rec.content_type,
                "etag": rec.etag,
                "deleted": rec.deleted,
                "storage_policy_index": rec.storage_policy_index,
            })
        })
        .collect();
    let rpc = serde_json::json!(["merge_items", json_items, "src-db-id"]);
    let (status, _, _) = http_request(
        addr,
        "REPLICATE",
        &format!("/sdb1/0/{hsh}"),
        "",
        &serde_json::json!({}),
        &rpc.to_string(),
    );
    assert_eq!(status, 202, "usync merge_items push");

    // the remote DB now has both objects
    let mut remote2 = ContainerBroker::new(&remote_db, account, container);
    let rows = remote2.object_rows().unwrap();
    let names: Vec<String> = rows
        .iter()
        .map(|r| match &r[1] {
            DbValue::Text(s) => s.clone(),
            _ => String::new(),
        })
        .collect();
    assert_eq!(
        names,
        vec!["obj-a".to_string(), "obj-b".to_string()],
        "replicated names"
    );
    // and the source sync point was recorded
    assert_eq!(remote2.get_sync("src-db-id", true).unwrap(), 2);
    std::fs::remove_dir_all(&tmp).unwrap();
}

fn info_count(b: &mut ContainerBroker) -> i64 {
    b.get_info()
        .unwrap()
        .into_iter()
        .find(|(k, _)| k == "object_count")
        .and_then(|(_, v)| match v {
            DbValue::Int(i) => Some(i),
            DbValue::Text(s) => s.parse().ok(),
            _ => None,
        })
        .unwrap_or(-1)
}

#[test]
fn test_replicate_tombstones_zero_peer_object_count() {
    // listing-w95: local_count=0 vs remote_count=50, point reset to -1,
    // but peer object_count stayed 50. The shipped replicate_container_db
    // path must actually merge deleted=1 rows onto the peer.
    let tmp = tmpdir("tombstone-repl");
    let account = "a";
    let container = "shard50";
    let hash_cfg =
        swift_core::hashing::HashPathConfig::new(b"".to_vec(), b"changeme".to_vec()).unwrap();
    let hsh = hash_cfg.hash_path(account, Some(container), None).unwrap();
    let suffix = &hsh[hsh.len() - 3..];
    let db_rel = format!("containers/0/{suffix}/{hsh}/{hsh}.db");

    let local_db = tmp.join("sda1").join(&db_rel);
    let mut local = ContainerBroker::new(&local_db, account, container);
    local
        .initialize("1751500000.00000", 0, "1751500000.00000", "src-db-id")
        .unwrap();
    let remote_db = tmp.join("sdb1").join(&db_rel);
    let mut remote = ContainerBroker::new(&remote_db, account, container);
    remote
        .initialize("1751500000.00000", 0, "1751500000.00000", "dst-db-id")
        .unwrap();
    for i in 0..50 {
        let name = format!("o{i:03}");
        local
            .put_object(&name, "1751500001.00000", 1, "text/plain", "e", 0, 0, None, None)
            .unwrap();
        remote
            .put_object(&name, "1751500001.00000", 1, "text/plain", "e", 0, 0, None, None)
            .unwrap();
    }
    local.commit_pending().unwrap();
    remote.commit_pending().unwrap();
    // Peer already received our live rows (sync point == pre-delete max_row).
    let pre = local.get_max_row().unwrap().unwrap_or(-1);
    remote.merge_syncs(&[(pre, "src-db-id".to_string())], true).unwrap();
    assert_eq!(info_count(&mut local), 50);
    assert_eq!(info_count(&mut remote), 50);

    for i in 0..50 {
        local
            .delete_object(&format!("o{i:03}"), "1751500099.00000", 0)
            .unwrap();
    }
    local.commit_pending().unwrap();
    assert_eq!(info_count(&mut local), 0);

    let config = container_config(&tmp, "changeme");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || serve(listener, config));
    std::thread::sleep(std::time::Duration::from_millis(100));

    let outcome = replicate_container_db(
        &mut local,
        "src-db-id",
        &addr.to_string(),
        "sdb1",
        "0",
        &hsh,
    )
    .expect("replicate_container_db");
    assert!(!outcome.needs_rsync, "{outcome:?}");
    assert!(
        outcome.rows_pushed > 0,
        "must push tombstone rows, got {outcome:?}"
    );

    let mut remote2 = ContainerBroker::new(&remote_db, account, container);
    assert_eq!(
        info_count(&mut remote2),
        0,
        "peer object_count must be 0 after tombstone usync; rows={:?}",
        remote2.object_rows().unwrap()
    );
    std::fs::remove_dir_all(&tmp).unwrap();
}
