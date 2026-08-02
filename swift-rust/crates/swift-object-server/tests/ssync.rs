// Copyright (c) 2026 OpenStack Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0

//! SSYNC receiver compatibility and safety tests over the duplex wire.
//!
//! The receiver hijacks the connection, so these tests attach an
//! `InterimResponder::with_hijack` sink to a synthetic streamed body and read
//! the raw wire (response head plus chunked frames) that the handler wrote.

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use swift_core::hashing::HashPathConfig;
use swift_http::{Body, HeaderKeyDict, InterimResponder, Request, Response};
use swift_object_server::ssync::{encode_missing, SsyncEvent, SsyncParser};
use swift_object_server::{ContainerUpdateMode, ObjectServer, ObjectServerConfig};

static NEXT_TMP: AtomicU64 = AtomicU64::new(0);

struct TestTree {
    root: PathBuf,
}

impl TestTree {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "swift-object-ssync-{}-{}",
            std::process::id(),
            NEXT_TMP.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("sda1")).unwrap();
        Self { root }
    }
}

impl Drop for TestTree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn hash_config() -> HashPathConfig {
    HashPathConfig::new(b"startcap".to_vec(), b"endcap".to_vec()).unwrap()
}

fn server(devices: &Path, mount_check: bool) -> ObjectServer {
    let policies = HashMap::from([
        (0, swift_diskfile::PolicyKind::Replication),
        (
            2,
            swift_diskfile::PolicyKind::Ec {
                n_unique_fragments: Some(6),
            },
        ),
    ]);
    ObjectServer::new(ObjectServerConfig {
        devices: devices.to_path_buf(),
        mount_check,
        hash_config: hash_config(),
        diskfile: swift_diskfile::DiskFileConfig::default(),
        policies,
        container_update_timeout: std::time::Duration::from_secs(1),
        container_update_mode: ContainerUpdateMode::Sync,
    })
}

fn request(method: &str, path: &str, headers: &[(&str, &str)], body: &[u8]) -> Request {
    let mut header_dict = HeaderKeyDict::new();
    for (key, value) in headers {
        header_dict.set(key, value);
    }
    Request {
        method: method.into(),
        path: path.into(),
        query_string: String::new(),
        headers: header_dict,
        body: body.to_vec().into(),
    }
}

fn put(server: &ObjectServer, object: &str, timestamp: &str, body: &[u8]) {
    let content_length = body.len().to_string();
    let response = server.handle(request(
        "PUT",
        &format!("/sda1/0/a/c/{object}"),
        &[
            ("X-Timestamp", timestamp),
            ("Content-Type", "text/plain"),
            ("Content-Length", &content_length),
        ],
        body,
    ));
    assert_eq!(response.status, 201, "PUT failed: {response:?}");
}

fn get(server: &ObjectServer, object: &str) -> Response {
    server.handle(request("GET", &format!("/sda1/0/a/c/{object}"), &[], &[]))
}

fn session(missing: &[String], updates: &[u8]) -> Vec<u8> {
    let mut body = b":MISSING_CHECK: START\r\n".to_vec();
    for line in missing {
        body.extend_from_slice(line.as_bytes());
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(b":MISSING_CHECK: END\r\n:UPDATES: START\r\n");
    body.extend_from_slice(updates);
    body.extend_from_slice(b":UPDATES: END\r\n");
    body
}

/// The captured connection write half handed to a hijacking handler.
#[derive(Clone)]
struct WireSink(Arc<Mutex<Vec<u8>>>);

impl Write for WireSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// What an SSYNC request produced: either an ordinary HTTP error response
/// (validation failed before the hijack) or the hijacked wire (response head
/// plus the de-chunked protocol body).
enum SsyncReply {
    Http(Response),
    Wire { head: String, body: Vec<u8> },
}

impl SsyncReply {
    fn status(&self) -> u16 {
        match self {
            SsyncReply::Http(response) => response.status,
            SsyncReply::Wire { head, .. } => head
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse().ok())
                .unwrap_or(0),
        }
    }

    fn wire_body(&self) -> &[u8] {
        match self {
            SsyncReply::Http(_) => panic!("expected a hijacked wire reply"),
            SsyncReply::Wire { body, .. } => body,
        }
    }

    fn lines(&self) -> Vec<Vec<u8>> {
        self.wire_body()
            .split(|byte| *byte == b'\n')
            .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
            .filter(|line| !line.is_empty())
            .map(<[u8]>::to_vec)
            .collect()
    }
}

/// De-chunk a `Transfer-Encoding: chunked` body. Tolerates a missing
/// terminal chunk (a dropped connection) by returning what arrived.
fn dechunk(mut raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let Some(line_end) = raw.windows(2).position(|w| w == b"\r\n") else {
            assert!(raw.is_empty(), "trailing garbage after chunks: {raw:?}");
            return out;
        };
        let size = usize::from_str_radix(
            std::str::from_utf8(&raw[..line_end]).unwrap().trim(),
            16,
        )
        .expect("chunk size hex");
        raw = &raw[line_end + 2..];
        if size == 0 {
            return out;
        }
        out.extend_from_slice(&raw[..size]);
        assert_eq!(&raw[size..size + 2], b"\r\n", "chunk terminator");
        raw = &raw[size + 2..];
    }
}

fn ssync_request(
    server: &ObjectServer,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> SsyncReply {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let mut req = request("SSYNC", path, headers, &[]);
    req.body = Body::from_reader(Box::new(std::io::Cursor::new(body.to_vec())), None);
    req.body.attach_interim(InterimResponder::with_hijack(
        None,
        Some(Box::new(WireSink(captured.clone()))),
    ));
    let response = server.handle(req);
    let raw = captured.lock().unwrap().clone();
    if raw.is_empty() {
        return SsyncReply::Http(response);
    }
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("response head");
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    assert!(
        head.to_ascii_lowercase().contains("transfer-encoding: chunked"),
        "duplex response must be chunked: {head}"
    );
    SsyncReply::Wire {
        head,
        body: dechunk(&raw[split + 4..]),
    }
}

fn ssync(server: &ObjectServer, body: &[u8]) -> SsyncReply {
    ssync_request(server, "/sda1/0", &[], body)
}

fn body_bytes(response: &mut Response) -> Vec<u8> {
    response.body.materialize(u64::MAX).unwrap().to_vec()
}

/// Protocol-phase errors are conveyed in-band inside the 200 body as
/// `:ERROR: 0 '<message>'` (Python's generic-exception translation).
fn assert_protocol_error(reply: &SsyncReply, message: &str) {
    assert_eq!(reply.status(), 200, "SSYNC phase errors stay in-band");
    let body = String::from_utf8_lossy(reply.wire_body()).into_owned();
    assert!(body.contains(":ERROR: 0"), "unexpected error body: {body}");
    assert!(body.contains(message), "unexpected error body: {body}");
}

fn python_stdout(code: &str) -> Vec<u8> {
    let output = Command::new("python3")
        .arg("-c")
        .arg(code)
        .output()
        .expect("python3 is required for interoperability tests");
    assert!(
        output.status.success(),
        "Python fixture failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

fn python_asserts_response(body: &[u8], code: &str) {
    let mut child = Command::new("python3")
        .arg("-c")
        .arg(code)
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("python3 is required for interoperability tests");
    child.stdin.as_mut().unwrap().write_all(body).unwrap();
    drop(child.stdin.take());
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "Python rejected Rust SSYNC response: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn ssync_incremental_parser_pauses_between_missing_check_and_updates() {
    let body = session(
        &["33333333333333333333333333333333 1751500000.00000".into()],
        b"PUT /a/c/o\r\nContent-Length: 1\r\n\r\nx",
    );
    let mut parser = SsyncParser::new();

    let first_events = parser.push(&body).unwrap();
    assert_eq!(first_events.len(), 2);
    assert!(matches!(
        &first_events[0],
        SsyncEvent::Missing(offer)
            if offer.object_hash == "33333333333333333333333333333333"
    ));
    assert!(matches!(first_events[1], SsyncEvent::MissingEnd));

    let update_events = parser.start_updates().unwrap();
    assert_eq!(update_events.len(), 2);
    assert!(matches!(
        &update_events[0],
        SsyncEvent::Update(update)
            if update.method == "PUT" && update.path == "/a/c/o" && update.body == b"x"
    ));
    assert!(matches!(update_events[1], SsyncEvent::UpdatesEnd));
    parser.finish().unwrap();
}

#[test]
fn ssync_incremental_parser_accepts_one_byte_feeds() {
    let body = session(
        &["44444444444444444444444444444444 1751500000.00000".into()],
        b"DELETE /a/c/o\r\nX-Timestamp: 1751500001.00000\r\n\r\n",
    );
    let missing_end = body
        .windows(b":MISSING_CHECK: END\r\n".len())
        .position(|window| window == b":MISSING_CHECK: END\r\n")
        .unwrap()
        + b":MISSING_CHECK: END\r\n".len();
    let mut parser = SsyncParser::new();
    let mut events = Vec::new();

    for byte in &body[..missing_end] {
        events.extend(parser.push(std::slice::from_ref(byte)).unwrap());
    }
    assert!(matches!(events.last(), Some(SsyncEvent::MissingEnd)));
    events.extend(parser.start_updates().unwrap());
    for byte in &body[missing_end..] {
        events.extend(parser.push(std::slice::from_ref(byte)).unwrap());
    }
    parser.finish().unwrap();

    assert!(events.iter().any(|event| matches!(
        event,
        SsyncEvent::Update(update)
            if update.method == "DELETE" && update.path == "/a/c/o" && update.body.is_empty()
    )));
    assert!(matches!(events.last(), Some(SsyncEvent::UpdatesEnd)));
}

#[test]
fn ssync_encode_missing_matches_python_wire_format() {
    let ts = |s: &str| s.parse::<swift_core::timestamp::Timestamp>().unwrap();
    let hash = "55555555555555555555555555555555";
    let t0 = ts("1751500000.00000");
    // plain data
    assert_eq!(
        encode_missing(hash, t0, None, None, None),
        format!("{hash} 1751500000.00000")
    );
    // meta delta, one second newer (0x186a0 deca-microseconds)
    assert_eq!(
        encode_missing(hash, t0, Some(ts("1751500001.00000")), None, None),
        format!("{hash} 1751500000.00000 m:186a0")
    );
    // meta + ctype deltas with a meta offset
    assert_eq!(
        encode_missing(
            hash,
            t0,
            Some(ts("1751500001.00000_000000000000000a")),
            Some(ts("1751500000.50000")),
            None
        ),
        format!("{hash} 1751500000.00000 m:186a0__a,t:c350")
    );
    // non-durable marker
    assert_eq!(
        encode_missing(hash, t0, None, None, Some(false)),
        format!("{hash} 1751500000.00000 durable:False")
    );
    // ts_meta equal to ts_data suppresses the deltas (including ctype, as in
    // Python where t: is nested under the m: branch) but not durable
    assert_eq!(
        encode_missing(hash, t0, Some(t0), Some(ts("1751500009.00000")), Some(false)),
        format!("{hash} 1751500000.00000 durable:False")
    );
}

#[test]
fn ssync_missing_check_compares_local_data_and_metadata_timestamps() {
    let tree = TestTree::new();
    let server = server(&tree.root, false);
    put(&server, "o1", "1751500000.00000", b"one");
    put(&server, "o2", "1751500000.00000", b"two");

    let hash1 = hash_config().hash_path("a", Some("c"), Some("o1")).unwrap();
    let hash2 = hash_config().hash_path("a", Some("c"), Some("o2")).unwrap();
    let missing_hash = "11111111111111111111111111111111";
    let body = session(
        &[
            format!("{missing_hash} 1751500000.00000"),
            // 0x186a0 deca-microseconds is exactly one second newer metadata.
            format!("{hash1} 1751500000.00000 m:186a0"),
            format!("{hash2} 1751500000.00000"),
        ],
        &[],
    );

    let reply = ssync(&server, &body);
    assert_eq!(reply.status(), 200);
    assert_eq!(
        reply.wire_body(),
        format!(
            "\r\n:MISSING_CHECK: START\r\n{missing_hash} dm\r\n{hash1} m\r\n\
             :MISSING_CHECK: END\r\n:UPDATES: START\r\n:UPDATES: END\r\n"
        )
        .into_bytes()
    );
    assert_eq!(
        reply.lines(),
        vec![
            b":MISSING_CHECK: START".to_vec(),
            format!("{missing_hash} dm").into_bytes(),
            format!("{hash1} m").into_bytes(),
            b":MISSING_CHECK: END".to_vec(),
            b":UPDATES: START".to_vec(),
            b":UPDATES: END".to_vec(),
        ]
    );
}

#[test]
fn ssync_advertises_accept_no_commit_in_the_response_head() {
    let tree = TestTree::new();
    let server = server(&tree.root, false);
    let reply = ssync(&server, &session(&[], &[]));
    let SsyncReply::Wire { head, .. } = &reply else {
        panic!("expected a hijacked reply");
    };
    assert!(
        head.contains("X-Backend-Accept-No-Commit: True"),
        "sender needs the no-commit capability header: {head}"
    );
}

#[test]
fn ssync_updates_apply_put_post_and_delete_subrequests() {
    let tree = TestTree::new();
    let server = server(&tree.root, false);
    put(&server, "gone", "1751500000.00000", b"old");

    let updates = b"PUT /a/c/new\r\n\
Content-Length: 5\r\n\
Content-Type: text/plain\r\n\
X-Timestamp: 1751500001.00000\r\n\
X-Object-Meta-Origin: ssync\r\n\
\r\n\
helloPOST /a/c/new\r\n\
X-Timestamp: 1751500002.00000\r\n\
X-Object-Meta-Color: blue\r\n\
\r\n\
DELETE /a/c/gone\r\n\
X-Timestamp: 1751500003.00000\r\n\
\r\n";
    let reply = ssync(&server, &session(&[], updates));
    assert_eq!(reply.status(), 200);
    assert_eq!(
        reply.lines(),
        vec![
            b":MISSING_CHECK: START".to_vec(),
            b":MISSING_CHECK: END".to_vec(),
            b":UPDATES: START".to_vec(),
            b":UPDATES: END".to_vec(),
        ]
    );

    let mut new_object = get(&server, "new");
    assert_eq!(new_object.status, 200);
    assert_eq!(body_bytes(&mut new_object), b"hello");
    // Swift POST replaces the object's user metadata set; unspecified values
    // from the earlier PUT are intentionally removed.
    assert_eq!(new_object.headers.get("X-Object-Meta-Origin"), None);
    assert_eq!(new_object.headers.get("X-Object-Meta-Color"), Some("blue"));
    assert_eq!(get(&server, "gone").status, 404);
}

#[test]
fn ssync_applies_updates_sequentially_like_python_then_reports_the_error() {
    // Python's receiver routes each subrequest as it arrives; a later
    // protocol error aborts the session in-band but earlier writes stand.
    let tree = TestTree::new();
    let server = server(&tree.root, false);
    let updates = b"PUT /a/c/already-written\r\n\
Content-Length: 1\r\n\
Content-Type: text/plain\r\n\
X-Timestamp: 1751500001.00000\r\n\
\r\n\
xGET /a/c/invalid\r\n\r\n";
    let reply = ssync(&server, &session(&[], updates));
    assert_protocol_error(&reply, "invalid subrequest method");
    assert_eq!(get(&server, "already-written").status, 200);
}

#[test]
fn ssync_rejects_oversized_lines_headers_and_bodies_without_panicking() {
    let tree = TestTree::new();
    let server = server(&tree.root, false);

    let huge_line = "a".repeat(65_537);
    let reply = ssync(
        &server,
        &session(&[format!("{huge_line} 1751500000.00000")], &[]),
    );
    assert_protocol_error(&reply, "line too long");

    let mut too_many_headers = b"PUT /a/c/o\r\nContent-Length: 0\r\n".to_vec();
    for index in 0..129 {
        too_many_headers.extend_from_slice(format!("X-Test-{index}: value\r\n").as_bytes());
    }
    too_many_headers.extend_from_slice(b"\r\n");
    let reply = ssync(&server, &session(&[], &too_many_headers));
    assert_protocol_error(&reply, "too many headers");

    let huge_body = b"PUT /a/c/o\r\n\
Content-Length: 67108865\r\n\
Content-Type: application/octet-stream\r\n\
X-Timestamp: 1751500001.00000\r\n\
\r\n";
    let reply = ssync(&server, &session(&[], huge_body));
    assert_protocol_error(&reply, "subrequest body too large");
}

#[test]
fn ssync_rejects_bad_framing_and_invalid_headers() {
    let tree = TestTree::new();
    let server = server(&tree.root, false);

    let reply = ssync(
        &server,
        &session(&["not-a-swift-hash 1751500000.00000".into()], &[]),
    );
    assert_protocol_error(&reply, "invalid object hash");

    let bad_length = b"PUT /a/c/o\r\n\
Content-Length: -1\r\n\
Content-Type: text/plain\r\n\
X-Timestamp: 1751500001.00000\r\n\
\r\n";
    let reply = ssync(&server, &session(&[], bad_length));
    assert_protocol_error(&reply, "invalid content-length");

    let malformed_header = b"PUT /a/c/o\r\n\
Content-Length: 0\r\n\
This-Is-Not-A-Header\r\n\
\r\n";
    let reply = ssync(&server, &session(&[], malformed_header));
    assert_protocol_error(&reply, "malformed header");

    let mut trailing = session(&[], &[]);
    trailing.extend_from_slice(b"unexpected");
    let reply = ssync(&server, &trailing);
    assert_protocol_error(&reply, "trailing data after updates end");
}

#[test]
fn ssync_truncated_sessions_drop_the_connection_like_python() {
    // Python's receiver treats EOF mid-session as a client disconnect: no
    // in-band error, nothing written after the frames already sent, and no
    // partial subrequest applied.
    let tree = TestTree::new();
    let server = server(&tree.root, false);

    let reply = ssync(&server, b":MISSING_CHECK: START\r\n");
    assert_eq!(reply.status(), 200);
    let body = String::from_utf8_lossy(reply.wire_body()).into_owned();
    assert!(
        !body.contains(":ERROR:") && !body.contains(":MISSING_CHECK:"),
        "a hangup mid-missing-check writes no frames: {body:?}"
    );

    let truncated_update = b"PUT /a/c/o\r\n\
Content-Length: 5\r\n\
Content-Type: text/plain\r\n\
X-Timestamp: 1751500001.00000\r\n\
\r\n\
abc";
    let mut truncated_session =
        b":MISSING_CHECK: START\r\n:MISSING_CHECK: END\r\n:UPDATES: START\r\n".to_vec();
    truncated_session.extend_from_slice(truncated_update);
    let _ = ssync(&server, &truncated_session);
    assert_eq!(get(&server, "o").status, 404);
}

#[test]
fn ssync_enforces_path_device_and_mount_contract() {
    let tree = TestTree::new();
    let unmounted = server(&tree.root, true);
    assert_eq!(ssync(&unmounted, &session(&[], &[])).status(), 507);

    std::fs::write(tree.root.join("sda1/.ismount"), b"").unwrap();
    let mounted = server(&tree.root, true);
    assert_eq!(ssync(&mounted, &session(&[], &[])).status(), 200);
    assert_eq!(
        ssync_request(&mounted, "/sda1", &[], &session(&[], &[])).status(),
        400
    );
    // EC SSYNC with a frag index is accepted on the duplex receiver.
    assert_eq!(
        ssync_request(
            &mounted,
            "/sda1/0",
            &[
                ("X-Backend-Storage-Policy-Index", "2"),
                ("X-Backend-Ssync-Frag-Index", "0"),
            ],
            &session(&[], &[]),
        )
        .status(),
        200
    );
    // ...but a malformed frag index is still a 400 before the exchange.
    assert_eq!(
        ssync_request(
            &mounted,
            "/sda1/0",
            &[("X-Backend-Ssync-Frag-Index", "not-a-number")],
            &session(&[], &[]),
        )
        .status(),
        400
    );

    let options = mounted.handle(request("OPTIONS", "/sda1/0", &[], &[]));
    assert!(options.headers.get("Allow").unwrap().contains("SSYNC"));
}

#[test]
fn unknown_policy_put_fails_closed_without_creating_policy_directory() {
    let tree = TestTree::new();
    let server = server(&tree.root, false);
    let mut response = server.handle(request(
        "PUT",
        "/sda1/0/a/c/o",
        &[
            ("X-Backend-Storage-Policy-Index", "999"),
            ("X-Timestamp", "1751500001.00000"),
            ("Content-Type", "text/plain"),
            ("Content-Length", "1"),
        ],
        b"x",
    ));

    assert_eq!(response.status, 503);
    assert_eq!(body_bytes(&mut response), b"No policy with index 999");
    assert!(!tree.root.join("sda1/objects-999").exists());
}

#[test]
fn unknown_policy_get_post_and_delete_fail_closed() {
    let tree = TestTree::new();
    let server = server(&tree.root, false);

    for method in ["GET", "POST", "DELETE"] {
        let mut response = server.handle(request(
            method,
            "/sda1/0/a/c/o",
            &[("X-Backend-Storage-Policy-Index", "999")],
            &[],
        ));
        assert_eq!(response.status, 503, "{method}");
        assert_eq!(body_bytes(&mut response), b"No policy with index 999", "{method}");
    }

    assert!(!tree.root.join("sda1/objects-999").exists());
}

#[test]
fn unknown_policy_ssync_fails_closed_without_creating_policy_directory() {
    let tree = TestTree::new();
    let server = server(&tree.root, false);
    let updates = b"PUT /a/c/o\r\n\
Content-Length: 1\r\n\
Content-Type: text/plain\r\n\
X-Timestamp: 1751500001.00000\r\n\
\r\n\
x";
    let reply = ssync_request(
        &server,
        "/sda1/0",
        &[("X-Backend-Storage-Policy-Index", "999")],
        &session(&[], updates),
    );

    let SsyncReply::Http(mut response) = reply else {
        panic!("policy validation must fail before the hijack");
    };
    assert_eq!(response.status, 503);
    assert_eq!(body_bytes(&mut response), b"No policy with index 999");
    assert!(!tree.root.join("sda1/objects-999").exists());
}

#[test]
fn python_stdlib_batch_fixture_can_generate_request_and_parse_response() {
    let tree = TestTree::new();
    let server = server(&tree.root, false);
    let offered_hash = "22222222222222222222222222222222";
    let request_body = python_stdout(concat!(
        "import sys, urllib.parse\n",
        "offered = urllib.parse.quote('22222222222222222222222222222222')\n",
        "path = urllib.parse.quote('/a/c/雪')\n",
        "wire = (':MISSING_CHECK: START\\r\\n' + offered + ' 1751500000.00000\\r\\n'",
        "        ':MISSING_CHECK: END\\r\\n:UPDATES: START\\r\\n'",
        "        'PUT ' + path + '\\r\\nContent-Length: 5\\r\\n'",
        "        'Content-Type: text/plain\\r\\nX-Timestamp: 1751500001.00000\\r\\n\\r\\n').encode('ascii')",
        "        + b'hello' + b':UPDATES: END\\r\\n'\n",
        "sys.stdout.buffer.write(wire)"
    ));

    let reply = ssync(&server, &request_body);
    assert_eq!(reply.status(), 200);
    python_asserts_response(
        reply.wire_body(),
        concat!(
            "import sys\n",
            "lines=[line.strip() for line in sys.stdin.buffer.read().splitlines() if line.strip()]\n",
            "assert lines == [b':MISSING_CHECK: START',",
            " b'22222222222222222222222222222222 dm',",
            " b':MISSING_CHECK: END', b':UPDATES: START', b':UPDATES: END'], lines"
        ),
    );
    let mut unicode_object = get(&server, "雪");
    assert_eq!(unicode_object.status, 200);
    assert_eq!(body_bytes(&mut unicode_object), b"hello");
    assert!(
        !tree.root.join("sda1/async_pending").exists(),
        "backend replication must not enqueue a container update"
    );
    assert_eq!(
        reply.lines()[1],
        format!("{offered_hash} dm").into_bytes()
    );
}
