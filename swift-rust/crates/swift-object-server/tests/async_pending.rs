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
//! replays. This drives a PUT with no container side-channel and checks the
//! file lands in the expected format (round-tripped through the updater's
//! own parser).

use swift_http::{HeaderKeyDict, Request};
use swift_object_server::{ContainerUpdateMode, iter_async_pendings, ObjectServer, ObjectServerConfig, UpdaterStats};

fn config(devices: &std::path::Path) -> ObjectServerConfig {
    ObjectServerConfig {
        devices: devices.to_path_buf(),
        mount_check: false,
        hash_config: swift_core::hashing::HashPathConfig::new(b"".to_vec(), b"changeme".to_vec())
            .unwrap(),
        diskfile: swift_diskfile::DiskFileConfig::default(),
        policies: std::collections::HashMap::from([(
            0,
            swift_diskfile::PolicyKind::Replication,
        )]),
        container_update_timeout: std::time::Duration::from_secs(1),
        container_update_mode: swift_object_server::ContainerUpdateMode::Sync,
    }
}

#[test]
fn test_put_without_container_hosts_writes_async_pending() {
    let dir = std::env::temp_dir().join(format!("swift-os-async-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let device = dir.join("sda1");
    std::fs::create_dir_all(&device).unwrap();

    let server = ObjectServer::new(config(&dir));
    // PUT with NO X-Container-Host side channel -> the container update can't
    // be applied synchronously and must go to async_pending.
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

    // an async_pending must have been written; the updater parses it back
    let mut stats = UpdaterStats::default();
    let updates = iter_async_pendings(&device, &mut stats);
    assert_eq!(updates.len(), 1, "one async_pending expected");
    let u = &updates[0];
    assert_eq!(u.op, "PUT");
    assert_eq!(u.account, "AUTH_test");
    assert_eq!(u.container, "c");
    assert_eq!(u.obj, "o");
    // the update headers were carried (x-size / x-timestamp), case-insensitively
    // (HeaderKeyDict title-cases keys, as Python's does)
    assert!(u.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("x-size")));
    assert!(u
        .headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("x-timestamp") && v == "1751500000.00000"));
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
