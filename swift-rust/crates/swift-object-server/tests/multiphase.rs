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

//! Backend multipart-MIME PUT coverage for both shipped execution paths:
//! the production async server's streaming two-phase wire protocol and the
//! synchronous compatibility handler's two-phase commit state machine.

use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use swift_object_server::{ContainerUpdateMode, ObjectServer, ObjectServerConfig};

static NEXT_TEST_ROOT: AtomicU64 = AtomicU64::new(0);

struct TestDevices(PathBuf);

impl TestDevices {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "swift-object-multiphase-{label}-{}-{}",
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

fn object_server(devices: &Path) -> ObjectServer {
    ObjectServer::new(ObjectServerConfig {
        devices: devices.to_path_buf(),
        mount_check: false,
        hash_config: swift_core::hashing::HashPathConfig::new(
            Vec::new(),
            b"multiphase-tests".to_vec(),
        )
        .unwrap(),
        diskfile: swift_diskfile::DiskFileConfig::default(),
        policies: std::collections::HashMap::from([
            (0, swift_diskfile::PolicyKind::Replication),
            (
                1,
                swift_diskfile::PolicyKind::Ec {
                    n_unique_fragments: Some(6),
                },
            ),
        ]),
        container_update_timeout: std::time::Duration::from_secs(1),
        container_update_mode: ContainerUpdateMode::Sync,
    })
}

/// Serve the production async object service (policy 0 replication + policy
/// 1 EC-ish) on an ephemeral port; process exit reaps the detached thread.
fn spawn_server(devices: &Path) -> std::net::SocketAddr {
    spawn_server_with_config(devices, swift_http::ServerConfig::default())
}

fn spawn_server_with_config(
    devices: &Path,
    config: swift_http::ServerConfig,
) -> std::net::SocketAddr {
    let server = object_server(devices);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let _ = swift_object_server::serve_with_config(listener, server, config);
    });
    address
}

fn md5_hex(data: &[u8]) -> String {
    use md5::{Digest, Md5};
    format!("{:x}", Md5::digest(data))
}

fn chunked(payload: &[u8]) -> Vec<u8> {
    let mut out = format!("{:x}\r\n", payload.len()).into_bytes();
    out.extend_from_slice(payload);
    out.extend_from_slice(b"\r\n");
    out
}

const TERMINATOR: &[u8] = b"0\r\n\r\n";

/// Phase-1 body: object-body doc + metadata-footer doc, ending at a
/// NON-terminal boundary (exactly MIMEPutter::end_of_object_data).
fn phase1(boundary: &str, data: &[u8], footer_json: &str) -> Vec<u8> {
    let mut body = format!("--{boundary}\r\nX-Document: object body\r\n\r\n").into_bytes();
    body.extend_from_slice(data);
    body.extend_from_slice(
        format!(
            "\r\n--{boundary}\r\nX-Document: object metadata\r\nContent-MD5: {}\r\n\r\n{}\r\n--{boundary}\r\n",
            md5_hex(footer_json.as_bytes()),
            footer_json
        )
        .as_bytes(),
    );
    body
}

/// Phase-2 body: the commit doc + terminal boundary
/// (MIMEPutter::send_commit_confirmation).
fn phase2(boundary: &str) -> Vec<u8> {
    format!("X-Document: put commit\r\n\r\nput_commit_confirmation\r\n--{boundary}--").into_bytes()
}

fn read_interim(client: &mut TcpStream) -> String {
    let mut seen = Vec::new();
    let mut byte = [0u8; 1];
    while !seen.ends_with(b"\r\n\r\n") {
        client.read_exact(&mut byte).unwrap();
        seen.push(byte[0]);
    }
    String::from_utf8_lossy(&seen).into_owned()
}

fn begin_native_multiphase(
    address: std::net::SocketAddr,
    path: &str,
    boundary: &str,
    data: &[u8],
    footer_json: &str,
) -> TcpStream {
    let mut client = TcpStream::connect(address).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    client
        .write_all(
            format!(
                "PUT {path} HTTP/1.1\r\nHost: t\r\nX-Timestamp: {}\r\n\
                 Content-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n\
                 Expect: 100-continue\r\nX-Backend-Storage-Policy-Index: 1\r\n\
                 X-Backend-Obj-Multipart-Mime-Boundary: {boundary}\r\n\
                 X-Backend-Obj-Metadata-Footer: yes\r\n\
                 X-Backend-Obj-Multiphase-Commit: yes\r\n\
                 X-Backend-Obj-Content-Length: {}\r\nConnection: close\r\n\r\n",
                swift_core::timestamp::Timestamp::now().internal(),
                data.len()
            )
            .as_bytes(),
        )
        .unwrap();
    let first = read_interim(&mut client);
    assert_eq!(status_of(&first), 100, "{first}");
    assert!(first.contains("X-Obj-Metadata-Footer: yes"), "{first}");
    assert!(first.contains("X-Obj-Multiphase-Commit: yes"), "{first}");
    client
        .write_all(&chunked(&phase1(boundary, data, footer_json)))
        .unwrap();
    client.write_all(TERMINATOR).unwrap();
    let second = read_interim(&mut client);
    assert_eq!(status_of(&second), 100, "{second}");
    client
}

fn status_of(response: &str) -> u16 {
    response
        .lines()
        .next()
        .unwrap_or_else(|| panic!("empty HTTP response"))
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap()
}

#[derive(Clone)]
struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

impl Write for CaptureWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn sync_multiphase_put(
    server: &ObjectServer,
    path: &str,
    data: &[u8],
    footer_json: &str,
    commit_doc: &[u8],
    captured: Arc<Mutex<Vec<u8>>>,
) -> swift_http::Response {
    let boundary = "sync-two-phase-boundary";
    let mut decoded = phase1(boundary, data, footer_json);
    decoded.extend_from_slice(commit_doc);
    let mut body = swift_http::Body::from_reader(Box::new(std::io::Cursor::new(decoded)), None);
    body.attach_interim(swift_http::InterimResponder::new(Some(Box::new(
        CaptureWriter(captured),
    ))));
    let mut headers = swift_http::HeaderKeyDict::new();
    headers.set(
        "X-Timestamp",
        swift_core::timestamp::Timestamp::now().internal(),
    );
    headers.set("Content-Type", "application/octet-stream");
    headers.set("Transfer-Encoding", "chunked");
    headers.set("Expect", "100-continue");
    headers.set("X-Backend-Obj-Multipart-Mime-Boundary", boundary);
    headers.set("X-Backend-Obj-Metadata-Footer", "yes");
    headers.set("X-Backend-Obj-Multiphase-Commit", "yes");
    headers.set("X-Backend-Obj-Content-Length", data.len());
    server.handle(swift_http::Request {
        method: "PUT".into(),
        path: path.into(),
        query_string: String::new(),
        headers,
        body,
    })
}

#[allow(clippy::too_many_arguments)]
fn async_mime_put(
    address: std::net::SocketAddr,
    path: &str,
    policy_index: Option<i64>,
    data: &[u8],
    footer_json: &str,
    extra_headers: &[(&str, &str)],
) -> (u16, String) {
    let boundary = "deadbeefcafe";
    let mut client = TcpStream::connect(address).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut head = format!(
        "PUT {path} HTTP/1.1\r\nHost: test\r\nX-Timestamp: {}\r\nContent-Type: application/octet-stream\r\n\
         Transfer-Encoding: chunked\r\nExpect: 100-continue\r\n\
         X-Backend-Obj-Multipart-Mime-Boundary: {boundary}\r\n\
         X-Backend-Obj-Metadata-Footer: yes\r\n\
         X-Backend-Obj-Content-Length: {}\r\n",
        swift_core::timestamp::Timestamp::now().internal(),
        data.len()
    );
    if let Some(p) = policy_index {
        head.push_str(&format!("X-Backend-Storage-Policy-Index: {p}\r\n"));
    }
    for (k, v) in extra_headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("Connection: close\r\n\r\n");
    client.write_all(head.as_bytes()).unwrap();

    let first = read_interim(&mut client);
    if status_of(&first) != 100 {
        let mut rest = String::new();
        let _ = client.read_to_string(&mut rest);
        return (status_of(&first), first + &rest);
    }
    assert!(first.contains("X-Obj-Metadata-Footer: yes"), "{first}");
    client
        .write_all(&chunked(&phase1(boundary, data, footer_json)))
        .unwrap();
    client.write_all(TERMINATOR).unwrap();
    let mut rest = String::new();
    client.read_to_string(&mut rest).unwrap();
    assert!(
        !rest.is_empty(),
        "server closed without a final response after {first:?}"
    );
    (status_of(&rest), rest)
}

#[test]
fn sync_compatibility_handler_keeps_two_phase_commit_contract() {
    let devices = TestDevices::new("sync-two-phase");
    let server = object_server(devices.path());
    let data = b"two phase fragment";
    let footers = format!("{{\"Etag\": \"{}\"}}", md5_hex(data));
    let captured = Arc::new(Mutex::new(Vec::new()));
    let response = sync_multiphase_put(
        &server,
        "/sda1/0/a/c/committed",
        data,
        &footers,
        &phase2("sync-two-phase-boundary"),
        Arc::clone(&captured),
    );
    assert_eq!(response.status, 201);
    let interim = String::from_utf8_lossy(
        &captured
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()),
    )
    .into_owned();
    assert_eq!(
        interim.matches("HTTP/1.1 100 Continue").count(),
        2,
        "{interim}"
    );
    assert!(
        interim.contains("X-Obj-Multiphase-Commit: yes"),
        "{interim}"
    );
    assert!(interim.contains("X-Obj-Metadata-Footer: yes"), "{interim}");

    let bad_doc = b"X-Document: not a commit\r\n\r\nnope\r\n--sync-two-phase-boundary--";
    let rejected = sync_multiphase_put(
        &server,
        "/sda1/0/a/c/rejected",
        data,
        &footers,
        bad_doc,
        Arc::new(Mutex::new(Vec::new())),
    );
    assert_eq!(rejected.status, 500);
}

#[test]
fn native_async_multiphase_put_advertises_and_commits_after_confirmation() {
    let devices = TestDevices::new("native-two-phase");
    let address = spawn_server(devices.path());
    let boundary = "native-two-phase-boundary";
    let data = b"native async fragment";
    let footers = format!(
        "{{\"Etag\": \"{}\", \"X-Object-Sysmeta-Ec-Frag-Index\": \"3\"}}",
        md5_hex(data)
    );
    let mut client = TcpStream::connect(address).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    client
        .write_all(
            format!(
                "PUT /sda1/0/a/c/native HTTP/1.1\r\nHost: t\r\nX-Timestamp: {}\r\n\
                 Content-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n\
                 Expect: 100-continue\r\nX-Backend-Storage-Policy-Index: 1\r\n\
                 X-Backend-Obj-Multipart-Mime-Boundary: {boundary}\r\n\
                 X-Backend-Obj-Metadata-Footer: yes\r\n\
                 X-Backend-Obj-Multiphase-Commit: yes\r\n\
                 X-Backend-Obj-Content-Length: {}\r\nConnection: close\r\n\r\n",
                swift_core::timestamp::Timestamp::now().internal(),
                data.len()
            )
            .as_bytes(),
        )
        .unwrap();

    let first = read_interim(&mut client);
    assert_eq!(status_of(&first), 100, "{first}");
    assert!(first.contains("X-Obj-Metadata-Footer: yes"), "{first}");
    assert!(first.contains("X-Obj-Multiphase-Commit: yes"), "{first}");
    client
        .write_all(&chunked(&phase1(boundary, data, &footers)))
        .unwrap();
    client.write_all(TERMINATOR).unwrap();

    let second = read_interim(&mut client);
    assert_eq!(status_of(&second), 100, "{second}");
    let before_commit = find_files(devices.path(), "data");
    assert!(
        before_commit
            .iter()
            .any(|path| path.to_string_lossy().contains("#3.data")),
        "second 100 must follow a persisted non-durable fragment: {before_commit:?}"
    );
    assert!(
        !before_commit
            .iter()
            .any(|path| path.to_string_lossy().contains("#3#d.data")),
        "fragment became durable before commit confirmation: {before_commit:?}"
    );

    client.write_all(&chunked(&phase2(boundary))).unwrap();
    client.write_all(TERMINATOR).unwrap();
    let mut final_response = String::new();
    client.read_to_string(&mut final_response).unwrap();
    assert_eq!(status_of(&final_response), 201, "{final_response}");
    let after_commit = find_files(devices.path(), "data");
    assert!(
        after_commit
            .iter()
            .any(|path| path.to_string_lossy().contains("#3#d.data")),
        "commit confirmation did not make the fragment durable: {after_commit:?}"
    );
}

#[test]
fn native_async_multiphase_disconnect_never_marks_fragment_durable() {
    let devices = TestDevices::new("native-two-phase-disconnect");
    let address = spawn_server(devices.path());
    let boundary = "native-disconnect-boundary";
    let data = b"non durable fragment";
    let footers = format!(
        "{{\"Etag\": \"{}\", \"X-Object-Sysmeta-Ec-Frag-Index\": \"2\"}}",
        md5_hex(data)
    );
    let mut client = TcpStream::connect(address).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    client
        .write_all(
            format!(
                "PUT /sda1/0/a/c/disconnect HTTP/1.1\r\nHost: t\r\nX-Timestamp: {}\r\n\
                 Content-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n\
                 Expect: 100-continue\r\nX-Backend-Storage-Policy-Index: 1\r\n\
                 X-Backend-Obj-Multipart-Mime-Boundary: {boundary}\r\n\
                 X-Backend-Obj-Metadata-Footer: yes\r\n\
                 X-Backend-Obj-Multiphase-Commit: yes\r\n\
                 X-Backend-Obj-Content-Length: {}\r\nConnection: close\r\n\r\n",
                swift_core::timestamp::Timestamp::now().internal(),
                data.len()
            )
            .as_bytes(),
        )
        .unwrap();
    assert_eq!(status_of(&read_interim(&mut client)), 100);
    client
        .write_all(&chunked(&phase1(boundary, data, &footers)))
        .unwrap();
    client.write_all(TERMINATOR).unwrap();
    assert_eq!(status_of(&read_interim(&mut client)), 100);
    client.shutdown(Shutdown::Write).unwrap();
    let mut final_response = String::new();
    let _ = client.read_to_string(&mut final_response);
    if !final_response.is_empty() {
        assert_eq!(status_of(&final_response), 499, "{final_response}");
    }
    let data_files = find_files(devices.path(), "data");
    assert!(
        !data_files
            .iter()
            .any(|path| path.to_string_lossy().contains("#2#d.data")),
        "disconnect marked an unconfirmed fragment durable: {data_files:?}"
    );
}

#[test]
fn native_async_multiphase_body_idle_returns_408_without_waiting_for_socket_eof() {
    let devices = TestDevices::new("native-two-phase-idle");
    let mut config = swift_http::ServerConfig::default();
    config.body_idle_timeout_secs = 1;
    let address = spawn_server_with_config(devices.path(), config);
    let boundary = "native-idle-boundary";
    let mut client = TcpStream::connect(address).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    client
        .write_all(
            format!(
                "PUT /sda1/0/a/c/idle HTTP/1.1\r\nHost: t\r\nX-Timestamp: {}\r\n\
                 Content-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n\
                 Expect: 100-continue\r\nX-Backend-Storage-Policy-Index: 1\r\n\
                 X-Backend-Obj-Multipart-Mime-Boundary: {boundary}\r\n\
                 X-Backend-Obj-Metadata-Footer: yes\r\n\
                 X-Backend-Obj-Multiphase-Commit: yes\r\n\
                 X-Backend-Obj-Content-Length: 1\r\nConnection: close\r\n\r\n",
                swift_core::timestamp::Timestamp::now().internal()
            )
            .as_bytes(),
        )
        .unwrap();

    assert_eq!(status_of(&read_interim(&mut client)), 100);
    let started = Instant::now();
    let mut final_response = String::new();
    client.read_to_string(&mut final_response).unwrap();
    assert_eq!(status_of(&final_response), 408, "{final_response}");
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "body-idle response waited for the stalled client: {:?}",
        started.elapsed()
    );
    assert!(
        find_files(devices.path(), "data").is_empty(),
        "a body-idle timeout must not persist a fragment"
    );
}

#[test]
fn native_async_multiphase_accepts_opaque_commit_body_and_drains_extra_docs() {
    let devices = TestDevices::new("native-two-phase-opaque-commit");
    let address = spawn_server(devices.path());
    let boundary = "native-opaque-boundary";
    let data = b"opaque commit fragment";
    let footers = format!(
        "{{\"Etag\": \"{}\", \"X-Object-Sysmeta-Ec-Frag-Index\": \"4\"}}",
        md5_hex(data)
    );
    let mut client =
        begin_native_multiphase(address, "/sda1/0/a/c/opaque", boundary, data, &footers);
    let commit_and_junk = format!(
        "X-Document: put commit\r\n\r\ncommit_confirmation\r\n\
         --{boundary}\r\nX-Document: extra\r\n\r\njunk\r\n--{boundary}--"
    );
    client
        .write_all(&chunked(commit_and_junk.as_bytes()))
        .unwrap();
    client.write_all(TERMINATOR).unwrap();
    let mut final_response = String::new();
    client.read_to_string(&mut final_response).unwrap();
    assert_eq!(status_of(&final_response), 201, "{final_response}");
    let data_files = find_files(devices.path(), "data");
    assert!(
        data_files
            .iter()
            .any(|path| path.to_string_lossy().contains("#4#d.data")),
        "opaque commit body was not accepted like Python Swift: {data_files:?}"
    );
}

#[test]
fn native_async_multiphase_invalid_commit_header_is_500_and_not_durable() {
    let devices = TestDevices::new("native-two-phase-invalid-commit");
    let address = spawn_server(devices.path());
    let boundary = "native-invalid-boundary";
    let data = b"invalid commit fragment";
    let footers = format!(
        "{{\"Etag\": \"{}\", \"X-Object-Sysmeta-Ec-Frag-Index\": \"5\"}}",
        md5_hex(data)
    );
    let mut client =
        begin_native_multiphase(address, "/sda1/0/a/c/invalid", boundary, data, &footers);
    let invalid = format!("X-Document: not a commit\r\n\r\nnope\r\n--{boundary}--");
    client.write_all(&chunked(invalid.as_bytes())).unwrap();
    client.write_all(TERMINATOR).unwrap();
    let mut final_response = String::new();
    client.read_to_string(&mut final_response).unwrap();
    assert_eq!(status_of(&final_response), 500, "{final_response}");
    let data_files = find_files(devices.path(), "data");
    assert!(
        !data_files
            .iter()
            .any(|path| path.to_string_lossy().contains("#5#d.data")),
        "invalid commit header marked a fragment durable: {data_files:?}"
    );
}

#[test]
fn native_async_multiphase_without_metadata_footer_matches_replication_contract() {
    let devices = TestDevices::new("native-two-phase-no-footer");
    let address = spawn_server(devices.path());
    let boundary = "native-no-footer-boundary";
    let data = b"replicated multiphase bytes";
    let mut client = TcpStream::connect(address).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    client
        .write_all(
            format!(
                "PUT /sda1/0/a/c/no-footer HTTP/1.1\r\nHost: t\r\nX-Timestamp: {}\r\n\
                 Content-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n\
                 Expect: 100-continue\r\n\
                 X-Backend-Obj-Multipart-Mime-Boundary: {boundary}\r\n\
                 X-Backend-Obj-Multiphase-Commit: yes\r\n\
                 X-Backend-Obj-Content-Length: {}\r\nConnection: close\r\n\r\n",
                swift_core::timestamp::Timestamp::now().internal(),
                data.len()
            )
            .as_bytes(),
        )
        .unwrap();
    let first = read_interim(&mut client);
    assert_eq!(status_of(&first), 100, "{first}");
    assert!(first.contains("X-Obj-Multiphase-Commit: yes"), "{first}");
    assert!(!first.contains("X-Obj-Metadata-Footer"), "{first}");

    let mut object_doc = format!("--{boundary}\r\nX-Document: object body\r\n\r\n").into_bytes();
    object_doc.extend_from_slice(data);
    object_doc.extend_from_slice(format!("\r\n--{boundary}\r\n").as_bytes());
    client.write_all(&chunked(&object_doc)).unwrap();
    client.write_all(TERMINATOR).unwrap();
    assert_eq!(status_of(&read_interim(&mut client)), 100);

    let opaque_commit =
        format!("X-Document: put commit\r\n\r\ncommit_confirmation\r\n--{boundary}--");
    client
        .write_all(&chunked(opaque_commit.as_bytes()))
        .unwrap();
    client.write_all(TERMINATOR).unwrap();
    let mut final_response = String::new();
    client.read_to_string(&mut final_response).unwrap();
    assert_eq!(status_of(&final_response), 201, "{final_response}");

    let mut get = TcpStream::connect(address).unwrap();
    get.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    get.write_all(b"GET /sda1/0/a/c/no-footer HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut response = Vec::new();
    get.read_to_end(&mut response).unwrap();
    assert!(
        response.starts_with(b"HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&response)
    );
    assert!(response.ends_with(data), "replicated body mismatch");
}

#[test]
fn native_async_complete_commit_doc_then_disconnect_remains_durable() {
    let devices = TestDevices::new("native-two-phase-post-commit-disconnect");
    let address = spawn_server(devices.path());
    let boundary = "native-post-commit-disconnect-boundary";
    let data = b"commit before drain fragment";
    let footers = format!(
        "{{\"Etag\": \"{}\", \"X-Object-Sysmeta-Ec-Frag-Index\": \"0\"}}",
        md5_hex(data)
    );
    let mut client = begin_native_multiphase(
        address,
        "/sda1/0/a/c/post-commit-disconnect",
        boundary,
        data,
        &footers,
    );
    let commit_doc = format!("X-Document: put commit\r\n\r\ncommit_confirmation\r\n--{boundary}--");
    client.write_all(&chunked(commit_doc.as_bytes())).unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let mut final_response = String::new();
    let _ = client.read_to_string(&mut final_response);
    if !final_response.is_empty() {
        assert_eq!(status_of(&final_response), 499, "{final_response}");
    }
    let data_files = find_files(devices.path(), "data");
    assert!(
        data_files
            .iter()
            .any(|path| path.to_string_lossy().contains("#0#d.data")),
        "a complete commit document must authorize durability before post-commit drain: {data_files:?}"
    );
}

fn find_files(root: &Path, extension: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == extension) {
                out.push(path);
            }
        }
    }
    out
}

#[test]
fn async_mime_put_stores_data_footers_and_overrides() {
    let devices = TestDevices::new("full");
    let address = spawn_server(devices.path());
    let data = b"async MIME object payload";
    let footers = format!(
        "{{\"Etag\": \"{}\", \"X-Object-Sysmeta-From-Footer\": \"yes-indeed\", \
          \"X-Backend-Container-Update-Override-Etag\": \"whole-object-etag\"}}",
        md5_hex(data)
    );
    // An unreachable container host forces the update onto the
    // async_pending side channel, where the override etag must appear.
    let (status, _resp) = async_mime_put(
        address,
        "/sda1/0/a/c/o",
        None,
        data,
        &footers,
        &[
            ("X-Container-Host", "127.0.0.1:1"),
            ("X-Container-Partition", "0"),
            ("X-Container-Device", "sda1"),
        ],
    );
    assert_eq!(status, 201);

    // GET round-trips the data and the footer-supplied sysmeta.
    let mut client = TcpStream::connect(address).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    client
        .write_all(b"GET /sda1/0/a/c/o HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut resp = Vec::new();
    client.read_to_end(&mut resp).unwrap();
    let text = String::from_utf8_lossy(&resp);
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
    assert!(
        text.contains("X-Object-Sysmeta-From-Footer: yes-indeed"),
        "{text}"
    );
    assert!(resp.ends_with(data), "body mismatch");

    // The async_pending carries the override etag, not the fragment md5.
    // (Pending files live under async_pending/<suffix>/<hash>-<ts>, no
    // extension — scan every file below any async_pending dir.)
    let mut found_override = false;
    let mut saw_pending = false;
    let mut stack = vec![devices.path().to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.to_string_lossy().contains("async_pending") {
                saw_pending = true;
                let bytes = std::fs::read(&path).unwrap();
                if bytes
                    .windows(b"whole-object-etag".len())
                    .any(|w| w == b"whole-object-etag")
                {
                    found_override = true;
                }
            }
        }
    }
    assert!(saw_pending, "an async_pending should have been written");
    assert!(
        found_override,
        "async_pending should carry the override etag"
    );
}

#[test]
fn async_ec_policy_put_commits_only_after_complete_mime_body() {
    let devices = TestDevices::new("durable");
    let address = spawn_server(devices.path());
    let data = b"fragment archive bytes";
    let footers = format!(
        "{{\"Etag\": \"{}\", \"X-Object-Sysmeta-Ec-Frag-Index\": \"3\"}}",
        md5_hex(data)
    );

    // Committed: the fragment lands as a durable #3#d.data.
    let (status, _r) = async_mime_put(
        address,
        "/sda1/0/a/c/committed",
        Some(1),
        data,
        &footers,
        &[],
    );
    assert_eq!(status, 201);
    let durable: Vec<_> = find_files(devices.path(), "data")
        .into_iter()
        .filter(|p| p.to_string_lossy().contains("#3#d.data"))
        .collect();
    assert_eq!(
        durable.len(),
        1,
        "expected one durable fragment: {durable:?}"
    );

    // A truncated chunked MIME stream must not create either a durable or a
    // non-durable fragment. This is the production async equivalent of the
    // legacy two-phase handler refusing a missing commit document.
    let boundary = "disconnect-boundary";
    let mut client = TcpStream::connect(address).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    client
        .write_all(
            format!(
                "PUT /sda1/0/a/c/uncommitted HTTP/1.1\r\nHost: t\r\nX-Timestamp: {}\r\n\
                 Content-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n\
                 Expect: 100-continue\r\nX-Backend-Storage-Policy-Index: 1\r\n\
                 X-Backend-Obj-Multipart-Mime-Boundary: {boundary}\r\n\
                 X-Backend-Obj-Metadata-Footer: yes\r\n\
                 X-Backend-Obj-Content-Length: {}\r\nConnection: close\r\n\r\n",
                swift_core::timestamp::Timestamp::now().internal(),
                data.len()
            )
            .as_bytes(),
        )
        .unwrap();
    assert_eq!(status_of(&read_interim(&mut client)), 100);
    let partial = format!("--{boundary}\r\nX-Document: object body\r\n\r\n");
    client
        .write_all(format!("{:x}\r\n", partial.len() + data.len() + 1024).as_bytes())
        .unwrap();
    client.write_all(partial.as_bytes()).unwrap();
    client.write_all(data).unwrap();
    let _ = client.shutdown(Shutdown::Write);
    let mut aborted = String::new();
    let _ = client.read_to_string(&mut aborted);
    if !aborted.is_empty() {
        assert_eq!(status_of(&aborted), 499, "{aborted}");
    }
    let all: Vec<_> = find_files(devices.path(), "data");
    let non_durable: Vec<_> = all
        .iter()
        .filter(|p| {
            let s = p.to_string_lossy().into_owned();
            s.contains("#3.data") && !s.contains("#d")
        })
        .collect();
    assert_eq!(
        non_durable.len(),
        0,
        "truncated MIME PUT left a non-durable fragment: {all:?}"
    );
}

#[test]
fn footer_etag_mismatch_is_422() {
    let devices = TestDevices::new("etag");
    let address = spawn_server(devices.path());
    let footers = "{\"Etag\": \"0000deadbeef0000deadbeef00000000\"}".to_string();
    let (status, _r) = async_mime_put(
        address,
        "/sda1/0/a/c/bad",
        None,
        b"real data",
        &footers,
        &[],
    );
    assert_eq!(status, 422);
    assert!(find_files(devices.path(), "data").is_empty());
}

#[test]
fn corrupt_footer_md5_is_422() {
    let devices = TestDevices::new("footermd5");
    let address = spawn_server(devices.path());
    let boundary = "b0undary";
    let data = b"x";
    let mut client = TcpStream::connect(address).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    client
        .write_all(
            format!(
                "PUT /sda1/0/a/c/o HTTP/1.1\r\nHost: t\r\nX-Timestamp: {}\r\n\
                 Content-Type: text/plain\r\nTransfer-Encoding: chunked\r\nExpect: 100-continue\r\n\
                 X-Backend-Obj-Multipart-Mime-Boundary: {boundary}\r\n\
                 X-Backend-Obj-Metadata-Footer: yes\r\nConnection: close\r\n\r\n",
                swift_core::timestamp::Timestamp::now().internal()
            )
            .as_bytes(),
        )
        .unwrap();
    assert_eq!(status_of(&read_interim(&mut client)), 100);
    let mut body = format!("--{boundary}\r\nX-Document: object body\r\n\r\n").into_bytes();
    body.extend_from_slice(data);
    body.extend_from_slice(
        format!(
            "\r\n--{boundary}\r\nX-Document: object metadata\r\nContent-MD5: wrongmd5\r\n\r\n{{}}\r\n--{boundary}--"
        )
        .as_bytes(),
    );
    client.write_all(&chunked(&body)).unwrap();
    client.write_all(TERMINATOR).unwrap();
    let mut rest = String::new();
    client.read_to_string(&mut rest).unwrap();
    assert_eq!(status_of(&rest), 422, "{rest}");
}
