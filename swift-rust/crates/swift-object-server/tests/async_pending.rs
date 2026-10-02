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

//! When a container update can't be applied synchronously, the object server
//! must drop an async_pending pickle that the object-updater daemon later
//! replays. A missing side-channel is not a failure (Python `updates = []`);
//! a named container host that cannot be reached is.

use swift_http::{AsyncRequest, HeaderKeyDict, Request};
use swift_object_server::{
    iter_async_pendings, ContainerUpdateMode, ObjectServer, ObjectServerConfig, UpdaterStats,
};

fn config(devices: &std::path::Path) -> ObjectServerConfig {
    ObjectServerConfig {
        devices: devices.to_path_buf(),
        mount_check: false,
        hash_config: swift_core::hashing::HashPathConfig::new(b"".to_vec(), b"changeme".to_vec())
            .unwrap(),
        diskfile: swift_diskfile::DiskFileConfig::default(),
        policies: std::collections::HashMap::from([(0, swift_diskfile::PolicyKind::Replication)]),
        // Closed CU ports refuse immediately; keep the bound tight so a hang
        // cannot masquerade as a successful sync update.
        container_update_timeout: std::time::Duration::from_millis(50),
        container_update_mode: swift_object_server::ContainerUpdateMode::Sync,
    }
}

fn stamp_cu(headers: &mut HeaderKeyDict, host: &str) {
    headers.set("X-Container-Host", host);
    headers.set("X-Container-Device", "sda1");
    headers.set("X-Container-Partition", "0");
}

fn count_pendings(devices_root: &std::path::Path) -> usize {
    let mut total = 0;
    if let Ok(entries) = std::fs::read_dir(devices_root) {
        for entry in entries.flatten() {
            if !entry.path().is_dir() {
                continue;
            }
            let mut stats = UpdaterStats::default();
            total += iter_async_pendings(&entry.path(), &mut stats).len();
        }
    }
    total
}

#[test]
fn test_put_without_container_hosts_does_not_write_async_pending() {
    let dir = std::env::temp_dir().join(format!("swift-os-async-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let device = dir.join("sda1");
    std::fs::create_dir_all(&device).unwrap();

    let server = ObjectServer::new(config(&dir));
    // Python: no X-Container-Partition → updates=[] → no pickle. EC fragments
    // not selected by num_container_updates look like this.
    let mut headers = HeaderKeyDict::new();
    headers.set("X-Timestamp", "1751500000.00000");
    headers.set("Content-Length", "5");
    headers.set("Content-Type", "text/plain");
    let req = Request {
        method: "PUT".into(),
        path: "/sda1/0/AUTH_test/c/o".into(),
        query_string: String::new(),
        headers,
        body: b"hello".to_vec().into(),
    };
    let resp = server.handle(req);
    assert_eq!(resp.status, 201, "PUT should still succeed");

    let mut stats = UpdaterStats::default();
    let updates = iter_async_pendings(&device, &mut stats);
    assert!(
        updates.is_empty(),
        "missing CU side-channel must not enqueue async_pending: {updates:?}"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn test_put_with_unreachable_container_host_writes_async_pending() {
    let dir = std::env::temp_dir().join(format!("swift-os-async-down-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let device = dir.join("sda1");
    std::fs::create_dir_all(&device).unwrap();

    let server = ObjectServer::new(config(&dir));
    let mut headers = HeaderKeyDict::new();
    headers.set("X-Timestamp", "1751500000.00000");
    headers.set("Content-Length", "5");
    headers.set("Content-Type", "text/plain");
    stamp_cu(&mut headers, "127.0.0.1:1");
    let req = Request {
        method: "PUT".into(),
        path: "/sda1/0/AUTH_test/c/o".into(),
        query_string: String::new(),
        headers,
        body: b"hello".to_vec().into(),
    };
    let resp = server.handle(req);
    assert_eq!(resp.status, 201, "object PUT stays 2xx when CU is down");

    let mut stats = UpdaterStats::default();
    let updates = iter_async_pendings(&device, &mut stats);
    assert_eq!(updates.len(), 1, "one async_pending expected");
    let u = &updates[0];
    assert_eq!(u.op, "PUT");
    assert_eq!(u.account, "AUTH_test");
    assert_eq!(u.container, "c");
    assert_eq!(u.obj, "o");
    assert!(u
        .headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("x-size")));
    assert!(u
        .headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("x-timestamp") && v == "1751500000.00000"));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn test_partial_container_outage_pending_count_stays_under_2x() {
    // Probe UpdaterStatsMixIn._create_lots_of_asyncs: 2 of 4 container
    // servers down, then assertGreater(count, N) and assertLess(count, 2N).
    // Each object is three device-local PUTs (object replicas / EC
    // fragments) plus one extra no-side-channel PUT (fragment the proxy did
    // not pick for num_container_updates).
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let dir = std::env::temp_dir().join(format!("swift-os-async-card-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    for name in ["sda1", "sdb1", "sdc1", "sdd1"] {
        std::fs::create_dir_all(dir.join(name)).unwrap();
    }

    let live = TcpListener::bind("127.0.0.1:0").unwrap();
    live.set_nonblocking(true).unwrap();
    let live_addr = live.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_t = Arc::clone(&stop);
    std::thread::spawn(move || {
        while !stop_t.load(Ordering::Relaxed) {
            match live.accept() {
                Ok((mut stream, _)) => {
                    let mut buf = [0u8; 1024];
                    let _ = stream.read(&mut buf);
                    let _ = stream.write_all(
                        b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    );
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
                Err(_) => break,
            }
        }
    });

    let server = ObjectServer::new(config(&dir));
    let live_host = live_addr.to_string();
    let down_host = "127.0.0.1:1";
    let total_objs = 12;
    for i in 0..total_objs {
        let obj = format!("o-{i:03}");
        let ts = format!("{}", 1_751_500_000 + i);
        // Replica / fragment 0: assigned a live container replica → no pending.
        let mut h0 = HeaderKeyDict::new();
        h0.set("X-Timestamp", &ts);
        h0.set("Content-Length", "1");
        h0.set("Content-Type", "text/plain");
        stamp_cu(&mut h0, &live_host);
        assert_eq!(
            server
                .handle(Request {
                    method: "PUT".into(),
                    path: format!("/sda1/0/AUTH_test/c/{obj}"),
                    query_string: String::new(),
                    headers: h0,
                    body: b"x".to_vec().into(),
                })
                .status,
            201
        );
        // Replica / fragment 1: assigned a down container replica → pending.
        let mut h1 = HeaderKeyDict::new();
        h1.set("X-Timestamp", &ts);
        h1.set("Content-Length", "1");
        h1.set("Content-Type", "text/plain");
        stamp_cu(&mut h1, down_host);
        assert_eq!(
            server
                .handle(Request {
                    method: "PUT".into(),
                    path: format!("/sdb1/0/AUTH_test/c/{obj}"),
                    query_string: String::new(),
                    headers: h1,
                    body: b"x".to_vec().into(),
                })
                .status,
            201
        );
        // Half the objects also lose a second assigned replica (2 of 3 CS
        // down on that partition) so the total sits strictly above N.
        if i % 2 == 0 {
            let mut h2 = HeaderKeyDict::new();
            h2.set("X-Timestamp", &ts);
            h2.set("Content-Length", "1");
            h2.set("Content-Type", "text/plain");
            stamp_cu(&mut h2, down_host);
            assert_eq!(
                server
                    .handle(Request {
                        method: "PUT".into(),
                        path: format!("/sdc1/0/AUTH_test/c/{obj}"),
                        query_string: String::new(),
                        headers: h2,
                        body: b"x".to_vec().into(),
                    })
                    .status,
                201
            );
        } else {
            let mut h2 = HeaderKeyDict::new();
            h2.set("X-Timestamp", &ts);
            h2.set("Content-Length", "1");
            h2.set("Content-Type", "text/plain");
            stamp_cu(&mut h2, &live_host);
            assert_eq!(
                server
                    .handle(Request {
                        method: "PUT".into(),
                        path: format!("/sdc1/0/AUTH_test/c/{obj}"),
                        query_string: String::new(),
                        headers: h2,
                        body: b"x".to_vec().into(),
                    })
                    .status,
                201
            );
        }
        // Extra fragment with no CU headers (EC num_container_updates leftover).
        // Must not emit a pending or the probe's 2N ceiling is breached.
        let mut h3 = HeaderKeyDict::new();
        h3.set("X-Timestamp", &ts);
        h3.set("Content-Length", "1");
        h3.set("Content-Type", "text/plain");
        assert_eq!(
            server
                .handle(Request {
                    method: "PUT".into(),
                    path: format!("/sdd1/0/AUTH_test/c/{obj}"),
                    query_string: String::new(),
                    headers: h3,
                    body: b"x".to_vec().into(),
                })
                .status,
            201
        );
    }
    stop.store(true, Ordering::Relaxed);

    let count = count_pendings(&dir);
    assert!(
        count > total_objs,
        "pending count {count} should exceed object count {total_objs}"
    );
    assert!(
        count < total_objs * 2,
        "pending count {count} must stay under 2× object count {}",
        total_objs * 2
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn test_async_mode_always_writes_pending_even_with_hosts() {
    let dir = std::env::temp_dir().join(format!("swift-os-async-mode-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let device = dir.join("sda1");
    std::fs::create_dir_all(&device).unwrap();

    let mut cfg = config(&dir);
    cfg.container_update_mode = ContainerUpdateMode::Async;
    let server = ObjectServer::new(cfg);
    let mut headers = HeaderKeyDict::new();
    headers.set("X-Timestamp", "1751500000.00000");
    headers.set("Content-Length", "5");
    headers.set("Content-Type", "text/plain");
    // Well-formed side channel that would normally be contacted synchronously.
    // In async mode we must still enqueue and never dial these hosts.
    headers.set("X-Container-Host", "127.0.0.1:1");
    headers.set("X-Container-Device", "sda1");
    headers.set("X-Container-Partition", "0");
    let req = Request {
        method: "PUT".into(),
        path: "/sda1/0/AUTH_test/c/o-async".into(),
        query_string: String::new(),
        headers,
        body: b"hello".to_vec().into(),
    };
    assert_eq!(server.handle(req).status, 201);
    let mut stats = UpdaterStats::default();
    let updates = iter_async_pendings(&device, &mut stats);
    assert_eq!(updates.len(), 1, "async mode must always write pending");
    assert_eq!(updates[0].obj, "o-async");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn test_async_pending_pickle_includes_root_db_state() {
    let dir = std::env::temp_dir().join(format!("swift-os-async-dbstate-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let device = dir.join("sda1");
    std::fs::create_dir_all(&device).unwrap();

    let server = ObjectServer::new(config(&dir));
    let mut headers = HeaderKeyDict::new();
    headers.set("X-Timestamp", "1751500000.00000");
    headers.set("Content-Length", "5");
    headers.set("Content-Type", "text/plain");
    headers.set("X-Container-Root-Db-State", "unsharded");
    stamp_cu(&mut headers, "127.0.0.1:1");
    let req = Request {
        method: "PUT".into(),
        path: "/sda1/0/AUTH_test/c/o-state".into(),
        query_string: String::new(),
        headers,
        body: b"hello".to_vec().into(),
    };
    assert_eq!(server.handle(req).status, 201);
    let mut stats = UpdaterStats::default();
    let updates = iter_async_pendings(&device, &mut stats);
    assert_eq!(updates.len(), 1);
    let bytes = std::fs::read(&updates[0].path).expect("read pending pickle");
    let pairs = match swift_core::pickle::loads(&bytes).expect("unpickle") {
        swift_core::pickle::Value::Dict(p) => p,
        other => panic!("expected dict pickle, got {other:?}"),
    };
    let state = pairs.iter().find_map(|(k, v)| match (k, v) {
        (swift_core::pickle::Value::Str(k), swift_core::pickle::Value::Str(v))
            if k == "db_state" =>
        {
            Some(v.as_str())
        }
        _ => None,
    });
    assert_eq!(state, Some("unsharded"), "pickle keys: {pairs:?}");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn test_put_with_x_delete_at_enqueues_expiry_task() {
    let dir = std::env::temp_dir().join(format!("swift-os-exp-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let device = dir.join("sda1");
    std::fs::create_dir_all(&device).unwrap();

    let server = ObjectServer::new(config(&dir));
    let mut headers = HeaderKeyDict::new();
    headers.set("X-Timestamp", "1751500000.00000");
    headers.set("Content-Length", "5");
    headers.set("Content-Type", "text/plain");
    headers.set("X-Delete-At", "1751600000"); // no X-Delete-At-Host -> async
    let req = Request {
        method: "PUT".into(),
        path: "/sda1/0/AUTH_test/c/o".into(),
        query_string: String::new(),
        headers,
        body: b"hello".to_vec().into(),
    };
    assert_eq!(server.handle(req).status, 201);

    // among the async_pendings, one enqueues the expiry task into
    // .expiring_objects with the task-object name <delete_at>-<a>/<c>/<o>
    let mut stats = UpdaterStats::default();
    let updates = iter_async_pendings(&device, &mut stats);
    let expiry = updates
        .iter()
        .find(|u| u.account == ".expiring_objects")
        .expect("an expiry-queue async_pending was written");
    assert_eq!(expiry.op, "PUT");
    assert_eq!(expiry.obj, "1751600000-AUTH_test/c/o");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn test_handle_async_put_without_container_hosts_does_not_write_pending() {
    let dir = std::env::temp_dir().join(format!("swift-os-async-hy-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let device = dir.join("sda1");
    std::fs::create_dir_all(&device).unwrap();
    let server = ObjectServer::new(config(&dir));
    let mut headers = HeaderKeyDict::new();
    headers.set("X-Timestamp", "1751500000.00000");
    headers.set("Content-Length", "5");
    headers.set("Content-Type", "text/plain");
    let resp = server
        .handle_async(AsyncRequest {
            method: "PUT".into(),
            path: "/sda1/0/AUTH_test/c/o-hy".into(),
            query_string: String::new(),
            headers,
            body: swift_http::IncomingBody::from_bytes(b"hello".to_vec(), u64::MAX),
        })
        .await;
    assert_eq!(resp.status, 201, "{}", resp.reason);
    let mut stats = UpdaterStats::default();
    assert!(
        iter_async_pendings(&device, &mut stats).is_empty(),
        "Hyper PUT without CU headers must not enqueue"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn test_handle_async_put_unreachable_container_still_201_and_pending() {
    let dir = std::env::temp_dir().join(format!("swift-os-async-hy-down-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let device = dir.join("sda1");
    std::fs::create_dir_all(&device).unwrap();
    let server = ObjectServer::new(config(&dir));
    let mut headers = HeaderKeyDict::new();
    headers.set("X-Timestamp", "1751500000.00000");
    headers.set("Content-Length", "5");
    headers.set("Content-Type", "text/plain");
    stamp_cu(&mut headers, "127.0.0.1:1");
    let resp = server
        .handle_async(AsyncRequest {
            method: "PUT".into(),
            path: "/sda1/0/AUTH_test/c/o-hy-down".into(),
            query_string: String::new(),
            headers,
            body: swift_http::IncomingBody::from_bytes(b"hello".to_vec(), u64::MAX),
        })
        .await;
    assert_eq!(resp.status, 201, "object PUT stays 2xx when CU is down");
    let mut stats = UpdaterStats::default();
    assert_eq!(iter_async_pendings(&device, &mut stats).len(), 1);
    std::fs::remove_dir_all(&dir).unwrap();
}
