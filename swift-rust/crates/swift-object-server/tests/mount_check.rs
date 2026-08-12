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

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use swift_http::{HeaderKeyDict, Request};
use swift_object_server::{ContainerUpdateMode, ObjectServer, ObjectServerConfig};

static NEXT_TEST_ROOT: AtomicU64 = AtomicU64::new(0);

struct TestDevices(PathBuf);

impl TestDevices {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "swift-object-mount-check-{label}-{}-{}",
            std::process::id(),
            NEXT_TEST_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(path.join("sda1")).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDevices {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn server(devices: &Path, mount_check: bool) -> ObjectServer {
    ObjectServer::new(ObjectServerConfig {
        devices: devices.to_path_buf(),
        mount_check,
        hash_config: swift_core::hashing::HashPathConfig::new(
            Vec::new(),
            b"mount-check-tests".to_vec(),
        )
        .unwrap(),
        diskfile: swift_diskfile::DiskFileConfig::default(),
        policies: std::collections::HashMap::from([(0, swift_diskfile::PolicyKind::Replication)]),
        container_update_timeout: std::time::Duration::from_secs(1),
        container_update_mode: ContainerUpdateMode::Sync,
    })
}

fn request(method: &str, timestamp: &str, body: &[u8]) -> Request {
    let mut headers = HeaderKeyDict::new();
    headers.set("X-Timestamp", timestamp);
    headers.set("Content-Type", "application/octet-stream");
    headers.set("Content-Length", body.len());
    Request {
        method: method.to_string(),
        path: "/sda1/0/AUTH_test/container/object".to_string(),
        query_string: String::new(),
        headers,
        body: body.to_vec().into(),
    }
}

#[test]
fn mount_check_returns_507_for_every_object_data_verb_after_unmount() {
    let devices = TestDevices::new("required");
    let marker = devices.path().join("sda1/.ismount");
    std::fs::write(&marker, b"").unwrap();
    let server = server(devices.path(), true);

    assert_eq!(server.handle(request("GET", "1", b"")).status, 404);
    std::fs::remove_file(marker).unwrap();

    for method in ["GET", "HEAD", "PUT", "POST", "DELETE"] {
        let response = server.handle(request(method, "2", b"payload"));
        assert_eq!(
            response.status, 507,
            "{method} must reject an unmounted drive"
        );
    }
}

#[test]
fn mount_check_false_allows_a_plain_saio_device_directory() {
    let devices = TestDevices::new("disabled");
    let server = server(devices.path(), false);

    let put = server.handle(request("PUT", "1", b"payload"));
    assert_eq!(put.status, 201);

    let mut get = server.handle(request("GET", "1", b""));
    assert_eq!(get.status, 200);
    assert_eq!(get.body.materialize(u64::MAX).unwrap(), b"payload");

    let head = server.handle(request("HEAD", "1", b""));
    assert_eq!(head.status, 200);
    assert!(head.body.is_definitely_empty());

    let post = server.handle(request("POST", "2", b""));
    assert_eq!(post.status, 202);

    let delete = server.handle(request("DELETE", "3", b""));
    assert_eq!(delete.status, 204);
}
