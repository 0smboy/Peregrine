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

//! The multipart-MIME / multiphase-commit backend PUT, over a real
//! connection (both 100 Continue interim responses and both chunked
//! sequences on the wire) — the protocol the EC proxy PUT path speaks
//! (obj.py MIMEPutter <-> obj/server.py mime_documents flow).

use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use swift_object_server::{ObjectServer, ObjectServerConfig};

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

/// Serve an object server (policy 0 replication + policy 1 EC-ish) on an
/// ephemeral port; the accept thread is detached (process exit reaps it).
fn spawn_server(devices: &Path) -> std::net::SocketAddr {
    let server = Arc::new(ObjectServer::new(ObjectServerConfig {
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
    }));
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let handler: swift_http::Handler = Arc::new(move |req| server.handle(req));
    std::thread::spawn(move || swift_http::serve_forever(listener, handler));
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

fn status_of(response: &str) -> u16 {
    response
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap()
}

#[allow(clippy::too_many_arguments)]
fn mime_put(
    address: std::net::SocketAddr,
    path: &str,
    policy_index: Option<i64>,
    data: &[u8],
    footer_json: &str,
    send_commit: bool,
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
         X-Backend-Obj-Metadata-Footer: yes\r\nX-Backend-Obj-Multiphase-Commit: yes\r\n\
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
    assert!(first.contains("X-Obj-Multiphase-Commit: yes"), "{first}");
    assert!(first.contains("X-Obj-Metadata-Footer: yes"), "{first}");

    client
        .write_all(&chunked(&phase1(boundary, data, footer_json)))
        .unwrap();
    client.write_all(TERMINATOR).unwrap();

    let second = read_interim(&mut client);
    if status_of(&second) != 100 {
        let mut rest = String::new();
        let _ = client.read_to_string(&mut rest);
        return (status_of(&second), second + &rest);
    }

    if send_commit {
        client.write_all(&chunked(&phase2(boundary))).unwrap();
    } else {
        // terminal boundary with no commit doc
        client
            .write_all(&chunked(
                format!("X-Document: not a commit\r\n\r\nnope\r\n--{boundary}--").as_bytes(),
            ))
            .unwrap();
    }
    client.write_all(TERMINATOR).unwrap();
    let _ = client.shutdown(Shutdown::Write);
    let mut rest = String::new();
    client.read_to_string(&mut rest).unwrap();
    (status_of(&rest), rest)
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
fn full_multiphase_put_stores_data_footers_and_overrides() {
    let devices = TestDevices::new("full");
    let address = spawn_server(devices.path());
    let data = b"multiphase object payload";
    let footers = format!(
        "{{\"Etag\": \"{}\", \"X-Object-Sysmeta-From-Footer\": \"yes-indeed\", \
          \"X-Backend-Container-Update-Override-Etag\": \"whole-object-etag\"}}",
        md5_hex(data)
    );
    // An unreachable container host forces the update onto the
    // async_pending side channel, where the override etag must appear.
    let (status, _resp) = mime_put(
        address,
        "/sda1/0/a/c/o",
        None,
        data,
        &footers,
        true,
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
    assert!(text.contains("X-Object-Sysmeta-From-Footer: yes-indeed"), "{text}");
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
    assert!(found_override, "async_pending should carry the override etag");
}

#[test]
fn ec_policy_put_is_durable_only_after_commit() {
    let devices = TestDevices::new("durable");
    let address = spawn_server(devices.path());
    let data = b"fragment archive bytes";
    let footers = format!(
        "{{\"Etag\": \"{}\", \"X-Object-Sysmeta-Ec-Frag-Index\": \"3\"}}",
        md5_hex(data)
    );

    // Committed: the fragment lands as a durable #3#d.data.
    let (status, _r) = mime_put(
        address,
        "/sda1/0/a/c/committed",
        Some(1),
        data,
        &footers,
        true,
        &[],
    );
    assert_eq!(status, 201);
    let durable: Vec<_> = find_files(devices.path(), "data")
        .into_iter()
        .filter(|p| p.to_string_lossy().contains("#3#d.data"))
        .collect();
    assert_eq!(durable.len(), 1, "expected one durable fragment: {durable:?}");

    // No commit doc: 500 per server.py:1020-1021, and the fragment stays
    // NON-durable (#3.data without the #d marker).
    let (status, resp) = mime_put(
        address,
        "/sda1/0/a/c/uncommitted",
        Some(1),
        data,
        &footers,
        false,
        &[],
    );
    assert_eq!(status, 500, "{resp}");
    let all: Vec<_> = find_files(devices.path(), "data");
    let uncommitted: Vec<_> = all
        .iter()
        .filter(|p| !p.to_string_lossy().contains("committed"))
        .collect();
    let _ = uncommitted;
    let non_durable: Vec<_> = all
        .iter()
        .filter(|p| {
            let s = p.to_string_lossy().into_owned();
            s.contains("#3.data") && !s.contains("#d")
        })
        .collect();
    assert_eq!(
        non_durable.len(),
        1,
        "expected one non-durable fragment: {all:?}"
    );
}

#[test]
fn footer_etag_mismatch_is_422() {
    let devices = TestDevices::new("etag");
    let address = spawn_server(devices.path());
    let footers = "{\"Etag\": \"0000deadbeef0000deadbeef00000000\"}".to_string();
    let (status, _r) = mime_put(
        address,
        "/sda1/0/a/c/bad",
        None,
        b"real data",
        &footers,
        true,
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
    let _ = client.shutdown(Shutdown::Write);
    let mut rest = String::new();
    client.read_to_string(&mut rest).unwrap();
    assert_eq!(status_of(&rest), 422, "{rest}");
}
