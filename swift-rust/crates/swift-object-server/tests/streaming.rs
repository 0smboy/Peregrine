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

//! The P1 streaming contracts: a PUT consumes its body as a stream and
//! commits exactly the bytes read; a short body never commits; GET
//! streams with the metadata length declared; HEAD never touches the
//! data file's contents; ranged responses are byte-identical to the
//! buffered oracle.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use swift_http::{Body, HeaderKeyDict, Request};
use swift_object_server::{ContainerUpdateMode, ObjectServer, ObjectServerConfig};

static NEXT_TEST_ROOT: AtomicU64 = AtomicU64::new(0);

struct TestDevices(PathBuf);

impl TestDevices {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "swift-object-streaming-{label}-{}-{}",
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

fn server(devices: &Path) -> ObjectServer {
    ObjectServer::new(ObjectServerConfig {
        devices: devices.to_path_buf(),
        mount_check: false,
        hash_config: swift_core::hashing::HashPathConfig::new(
            Vec::new(),
            b"streaming-tests".to_vec(),
        )
        .unwrap(),
        diskfile: swift_diskfile::DiskFileConfig::default(),
        policies: std::collections::HashMap::from([(0, swift_diskfile::PolicyKind::Replication)]),
        container_update_timeout: std::time::Duration::from_secs(1),
        container_update_mode: ContainerUpdateMode::Sync,
    })
}

fn request(method: &str, timestamp: &str, body: Body) -> Request {
    let mut headers = HeaderKeyDict::new();
    headers.set("X-Timestamp", timestamp);
    headers.set("Content-Type", "application/octet-stream");
    if let Some(n) = body.content_length() {
        headers.set("Content-Length", n);
    }
    Request {
        method: method.to_string(),
        path: "/sda1/0/AUTH_test/container/object".to_string(),
        query_string: String::new(),
        headers,
        body,
    }
}

/// A reader that yields its payload in deliberately small pieces, so the
/// PUT loop must iterate (a Cursor would hand everything over at once).
struct Dribble {
    payload: Vec<u8>,
    pos: usize,
    step: usize,
}

impl Read for Dribble {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let remaining = &self.payload[self.pos..];
        let n = remaining.len().min(self.step).min(buf.len());
        buf[..n].copy_from_slice(&remaining[..n]);
        self.pos += n;
        Ok(n)
    }
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

fn md5_hex(data: &[u8]) -> String {
    use md5::{Digest, Md5};
    format!("{:x}", Md5::digest(data))
}

fn committed_data_file(devices: &Path) -> PathBuf {
    let mut data_file = None;
    let mut stack = vec![devices.join("sda1")];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "data") {
                data_file = Some(path);
            }
        }
    }
    data_file.expect("a committed .data file")
}

#[test]
fn streamed_put_commits_exactly_the_streamed_bytes_and_etag() {
    let devices = TestDevices::new("put");
    let server = server(devices.path());
    // 200KB across 7KB reads: the loop runs many times and crosses the
    // 64KB chunk boundary repeatedly.
    let payload = pattern(200 * 1024);
    let body = Body::from_reader(
        Box::new(Dribble {
            payload: payload.clone(),
            pos: 0,
            step: 7 * 1024,
        }),
        Some(payload.len() as u64),
    );
    let put = server.handle(request("PUT", "1", body));
    assert_eq!(put.status, 201);
    assert_eq!(
        put.headers.get("ETag").unwrap().trim_matches('"'),
        md5_hex(&payload)
    );

    let mut get = server.handle(request("GET", "1", Body::empty()));
    assert_eq!(get.status, 200);
    // The GET body is a stream with the metadata length declared.
    assert!(matches!(get.body, Body::Streamed(_)));
    assert_eq!(get.body.content_length(), Some(payload.len() as u64));
    assert_eq!(get.body.materialize(u64::MAX).unwrap(), &payload[..]);
}

#[test]
fn short_body_is_a_499_and_commits_nothing() {
    let devices = TestDevices::new("short");
    let server = server(devices.path());
    // Declares 1000 bytes but the stream ends after 400.
    let body = Body::from_reader(Box::new(std::io::Cursor::new(pattern(400))), Some(1000));
    let put = server.handle(request("PUT", "1", body));
    assert_eq!(put.status, 499);
    // Nothing was committed: no data file anywhere under objects/, and
    // the aborted temp file was removed with the writer.
    let mut data_files = Vec::new();
    let mut stack = vec![devices.path().join("sda1")];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "data") {
                data_files.push(path);
            }
        }
    }
    assert!(data_files.is_empty(), "leaked data files: {data_files:?}");
    let get = server.handle(request("GET", "1", Body::empty()));
    assert_eq!(get.status, 404);
}

#[test]
fn head_serves_metadata_without_reading_a_corrupt_data_file() {
    let devices = TestDevices::new("head");
    let server = server(devices.path());
    let payload = pattern(4096);
    let put = server.handle(request("PUT", "1", payload.clone().into()));
    assert_eq!(put.status, 201);

    // Corrupt the stored data file's CONTENTS without touching its size
    // or xattrs: a HEAD must still answer 200 from metadata alone.
    let data_file = committed_data_file(devices.path());
    // Flip bytes in place (same length) via read-modify-write.
    let mut contents = std::fs::read(&data_file).unwrap();
    for b in contents.iter_mut() {
        *b ^= 0xFF;
    }
    // Preserve xattr metadata: write through the SAME inode.
    use std::io::{Seek, SeekFrom, Write};
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .open(&data_file)
        .unwrap();
    f.seek(SeekFrom::Start(0)).unwrap();
    f.write_all(&contents).unwrap();
    drop(f);

    let head = server.handle(request("HEAD", "1", Body::empty()));
    assert_eq!(head.status, 200);
    assert_eq!(
        head.headers.get("Content-Length").unwrap(),
        payload.len().to_string()
    );
    assert!(head.body.is_definitely_empty());
    // The file was not quarantined by the HEAD.
    assert!(data_file.exists());
}

#[test]
fn complete_stream_quarantines_bad_etag_before_consumer_drop() {
    use swift_diskfile::{
        read_metadata, write_metadata, MetaValue, DEFAULT_XATTR_SIZE,
    };

    let devices = TestDevices::new("quarantine-before-drop");
    let server = server(devices.path());
    let payload = pattern(64 * 1024);
    assert_eq!(
        server
            .handle(request("PUT", "1", payload.clone().into()))
            .status,
        201
    );
    let data_file = committed_data_file(devices.path());
    let mut metadata = read_metadata(&data_file).unwrap();
    let (_, etag) = metadata
        .iter_mut()
        .find(|(key, _)| matches!(key, MetaValue::Str(name) if name == "ETag"))
        .expect("stored object ETag metadata");
    *etag = MetaValue::Str("badetag".into());
    write_metadata(&data_file, &metadata, DEFAULT_XATTR_SIZE).unwrap();

    let resp = server.handle(request("GET", "1", Body::empty()));
    assert_eq!(resp.status, 200);
    let (mut reader, length) = resp.body.into_reader();
    assert_eq!(length, Some(payload.len() as u64));
    let mut got = vec![0; payload.len()];
    reader.read_exact(&mut got).unwrap();
    assert_eq!(got, payload);

    // Keep `reader` alive here. The quarantine must be the side effect of
    // reading the final byte, not a later Drop that can race the next request.
    assert!(
        !data_file.exists(),
        "bad ETag remained readable until response-reader drop"
    );
    assert_eq!(server.handle(request("GET", "1", Body::empty())).status, 404);
}

#[test]
fn single_range_get_streams_the_window() {
    let devices = TestDevices::new("range1");
    let server = server(devices.path());
    let payload = pattern(100_000);
    assert_eq!(
        server
            .handle(request("PUT", "1", payload.clone().into()))
            .status,
        201
    );

    let mut req = request("GET", "1", Body::empty());
    req.headers.set("Range", "bytes=500-70000");
    let mut resp = server.handle(req);
    assert_eq!(resp.status, 206);
    assert_eq!(
        resp.headers.get("Content-Range").unwrap(),
        format!("bytes 500-70000/{}", payload.len())
    );
    assert_eq!(resp.body.content_length(), Some(70_000 - 500 + 1));
    assert_eq!(
        resp.body.materialize(u64::MAX).unwrap(),
        &payload[500..=70_000]
    );
}

#[test]
fn full_covering_range_quarantines_bad_etag() {
    use swift_diskfile::{
        read_metadata, write_metadata, MetaValue, DEFAULT_XATTR_SIZE,
    };

    let devices = TestDevices::new("range-full-quarantine");
    let server = server(devices.path());
    let payload = b"RANGE".to_vec();
    assert_eq!(
        server
            .handle(request("PUT", "1", payload.clone().into()))
            .status,
        201
    );
    let data_file = committed_data_file(devices.path());
    let mut metadata = read_metadata(&data_file).unwrap();
    let (_, etag) = metadata
        .iter_mut()
        .find(|(key, _)| matches!(key, MetaValue::Str(name) if name == "ETag"))
        .expect("stored object ETag metadata");
    *etag = MetaValue::Str("badetag".into());
    write_metadata(&data_file, &metadata, DEFAULT_XATTR_SIZE).unwrap();

    // The requested end extends past EOF, so the normalized range covers the
    // complete object. Swift serves the bytes as 206 and quarantines at the
    // stream boundary; a following request must already observe the 404.
    let mut req = request("GET", "1", Body::empty());
    req.headers.set("Range", "bytes=0-11");
    let mut resp = server.handle(req);
    assert_eq!(resp.status, 206);
    assert_eq!(resp.body.materialize(u64::MAX).unwrap(), payload);
    assert!(
        !data_file.exists(),
        "full-covering range left a bad ETag object readable"
    );
    assert_eq!(server.handle(request("GET", "1", Body::empty())).status, 404);
}

#[test]
fn unsatisfiable_range_preserves_object_content_type() {
    let devices = TestDevices::new("range416");
    let server = server(devices.path());
    let payload = pattern(64);
    assert_eq!(
        server
            .handle(request("PUT", "1", payload.clone().into()))
            .status,
        201
    );

    let mut req = request("GET", "1", Body::empty());
    req.headers.set("Range", "bytes=999-1000");
    let resp = server.handle(req);
    assert_eq!(resp.status, 416);
    assert_eq!(resp.headers.get("Content-Range"), Some("bytes */64"));
    assert_eq!(
        resp.headers.get("Content-Type"),
        Some("application/octet-stream")
    );
}

#[test]
fn multi_range_get_matches_the_buffered_oracle() {
    let devices = TestDevices::new("rangen");
    let server = server(devices.path());
    let payload = pattern(50_000);
    assert_eq!(
        server
            .handle(request("PUT", "1", payload.clone().into()))
            .status,
        201
    );

    let ranges: [(u64, u64); 3] = [(0, 1000), (10_000, 10_500), (49_000, 50_000)];
    let mut req = request("GET", "1", Body::empty());
    req.headers
        .set("Range", "bytes=0-999,10000-10499,49000-49999");
    let mut resp = server.handle(req);
    assert_eq!(resp.status, 206);
    let content_type = resp.headers.get("Content-Type").unwrap().to_string();
    let boundary = content_type
        .split_once("boundary=")
        .expect("multipart content type")
        .1
        .to_string();
    let expected = swift_http::multipart_byteranges(
        &boundary,
        &ranges,
        &payload,
        "application/octet-stream",
        payload.len() as u64,
    );
    let got = resp.body.materialize(u64::MAX).unwrap();
    assert_eq!(
        resp.headers.get("Content-Length").unwrap(),
        expected.len().to_string()
    );
    assert_eq!(
        got,
        &expected[..],
        "multipart body diverged from the oracle"
    );
}
