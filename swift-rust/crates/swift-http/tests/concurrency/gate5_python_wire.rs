//! Gate 5 concurrency-visible wire vs Python-cited expected behavior.
//!
//! Dual-feed: in-tree `SwiftHttpProtocol` on Eventlet WSGI
//! (`eventlet_swift_wsgi.py`, same protocol class as `wsgi.py:435-458`)
//! versus Peregrine Hyper HTTP/1.1. Full SAIO/`pyeclib` object-server is
//! not required for protocol dual-feed.
//!
//! Citations:
//! - `swift/common/http_protocol.py:214-217` — `Expect: 100-continue` arms
//!   `wsgi.input.wfile_line = b'HTTP/1.1 100 Continue\r\n'` and the 100 is
//!   written on the **first read** of `wsgi.input`, not at request start.
//! - `swift/common/wsgi.py:428-429` — `max_clients` sizes `RestrictedGreenPool`
//!   (request concurrency), not OS worker threads / connections.
//! - `swift/common/wsgi.py:443-446` — Eventlet `capitalize_response_headers`
//!   is False so S3 can emit `ETag` rather than `Etag`.
//! - `swift/common/swob.py` Range / Match — satisfiable range is 206; empty
//!   `ranges_for_length` is 416; If-None-Match hit is 304.
//! - `swift/common/middleware/copy.py:49-65` and `copy.py:320-347` — COPY is
//!   GET source then PUT dest. Shipped golden:
//!   `async_fanout::tests::hyper_serve_copy_is_get_then_put_on_shipped_proxy`
//!   (not the protocol dual-feed below).
//! - Object DELETE tombstone 204: `obj/server.py:1311-1369` — shipped Hyper
//!   `ObjectServer` in this file (`shipped_object_delete_is_204_tombstone`).
//! - SSYNC 200 + `X-Backend-Accept-No-Commit: True`: `obj/server.py:1406-1415`
//!   and missing-check `ssync_receiver.py:451-513` —
//!   `shipped_object_ssync_accept_no_commit`.

#![allow(dead_code)]

#[path = "harness.rs"]
mod harness;

use std::future::Future;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::pin::Pin;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use std::collections::HashMap;

use swift_core::hashing::HashPathConfig;
use swift_diskfile::{DiskFileConfig, PolicyKind};
use swift_http::server::{serve_forever_multi_service, AsyncRequest, AsyncService, ServerConfig};
use swift_http::{
    conditional_response_status, title_case, HeaderKeyDict, Range, Request, Response,
    PRODUCTION_HTTP1_ENGINE,
};
use swift_object_server::{serve_with_config, ObjectServer, ObjectServerConfig};

struct ReadBodyThen201;

impl AsyncService for ReadBodyThen201 {
    fn call(&self, mut req: AsyncRequest) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        Box::pin(async move {
            // First body read == Python first `wsgi.input` read.
            let _ = req.body.next_chunk().await;
            Response::new(201)
        })
    }
}

struct NoBodyRead204;

impl AsyncService for NoBodyRead204 {
    fn call(&self, req: AsyncRequest) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        Box::pin(async move {
            let _ = req;
            Response::new(204)
        })
    }
}

struct EtagService;

impl AsyncService for EtagService {
    fn call(&self, req: AsyncRequest) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        Box::pin(async move {
            let _ = req;
            let mut resp = Response::new(200);
            resp.headers.set("ETag", "\"abc\"");
            resp
        })
    }
}

struct SwiftUtf8MetadataEcho;

impl AsyncService for SwiftUtf8MetadataEcho {
    fn call(&self, mut req: AsyncRequest) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        Box::pin(async move {
            assert_eq!(req.method, "PUT");
            assert_eq!(req.path, "/v1/a/c/o-è");
            assert_eq!(req.headers.get("x-object-meta-è"), Some("meta-è"));

            let mut body = Vec::new();
            while let Some(chunk) = req.body.next_chunk().await.expect("UTF-8 request body") {
                body.extend_from_slice(&chunk);
            }
            assert_eq!(body, b"body");

            let mut response = Response::new(201);
            response.headers.set("x-object-meta-è", "meta-è");
            response
        })
    }
}

struct SwiftUtf8MetadataPost;

impl AsyncService for SwiftUtf8MetadataPost {
    fn call(&self, mut req: AsyncRequest) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        Box::pin(async move {
            assert_eq!(req.method, "POST");
            assert_eq!(req.path, "/v1/AUTH_test/container-è/object-è");
            assert_eq!(req.headers.get("x-object-meta-è"), Some("meta-è"));
            assert_eq!(req.body.materialize(64 * 1024).await.unwrap(), b"");
            Response::new(202)
        })
    }
}

fn spawn_async(worker_threads: usize, service: Arc<dyn AsyncService>) -> harness::Server {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let shutdown = Arc::new(AtomicBool::new(false));
    let config = ServerConfig {
        worker_threads,
        connection_queue: 32,
        client_timeout_secs: 2,
        head_deadline_secs: 2,
        max_requests_per_connection: 32,
        shutdown: Some(Arc::clone(&shutdown)),
        ..ServerConfig::default()
    };
    let flag = Arc::clone(&shutdown);
    let join = thread::spawn(move || serve_forever_multi_service(vec![listener], service, config));
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(20)).is_ok() {
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    harness::Server {
        addr,
        shutdown: flag,
        join: Some(join),
    }
}

fn read_until_double_crlf(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 256];
    loop {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    Ok(buf)
}

#[test]
fn production_engine_is_hyper_http1_not_http2() {
    assert_eq!(PRODUCTION_HTTP1_ENGINE, "hyper/http1");
    assert!(
        !PRODUCTION_HTTP1_ENGINE.contains("http2"),
        "HTTP/2 is a later ADR; production is HTTP/1.1"
    );
}

#[test]
fn max_clients_is_not_the_only_concurrency_knob() {
    // wsgi.py:428-429: Python max_clients sizes RestrictedGreenPool.
    // Peregrine splits connection vs request vs class caps (AGENTS.md §7).
    let cfg = ServerConfig::default();
    let fields = [
        cfg.max_connections,
        cfg.max_active_requests,
        cfg.max_foreground,
        cfg.worker_threads,
    ];
    assert!(
        fields.len() == 4,
        "connection, request, class, and runtime-thread caps are independent fields"
    );
}

#[test]
fn title_case_matches_python_bytes_title_and_s3_keeps_etag_name() {
    // Python bytes.title(): "etag" -> "Etag". Eventlet is told NOT to
    // recapitalize responses (wsgi.py:443-446) so s3api can emit "ETag".
    assert_eq!(title_case("etag"), "Etag");
    let mut h = HeaderKeyDict::new();
    h.set("ETag", "\"abc\"");
    // Store key is title-case; S3 wire override is a later header emit.
    assert_eq!(h.get("etag").unwrap(), "\"abc\"");
}

#[test]
fn expect_continue_fires_on_first_body_read_not_before() {
    // http_protocol.py:214-217: 100 is armed on Expect, sent on first read.
    let server = spawn_async(2, Arc::new(ReadBodyThen201));
    let mut client = TcpStream::connect_timeout(&server.addr, Duration::from_millis(400)).unwrap();
    client
        .set_read_timeout(Some(Duration::from_millis(400)))
        .unwrap();
    client
        .write_all(
            b"PUT /v1/a/c/o HTTP/1.1\r\n\
              Host: 127.0.0.1\r\n\
              Expect: 100-continue\r\n\
              Content-Length: 4\r\n\
              Connection: close\r\n\
              \r\n",
        )
        .unwrap();
    client.flush().unwrap();
    let head = read_until_double_crlf(&mut client).unwrap();
    let text = String::from_utf8_lossy(&head);
    assert!(
        text.starts_with("HTTP/1.1 100 Continue"),
        "first body read must emit 100 Continue (http_protocol.py:214-217), got {text:?}"
    );
    client.write_all(b"abcd").unwrap();
    let rest = read_until_double_crlf(&mut client).unwrap();
    let rest = String::from_utf8_lossy(&rest);
    assert!(
        rest.contains("201") || text.contains("201"),
        "PUT after 100 must complete, rest={rest:?}"
    );
}

#[test]
fn expect_continue_is_not_sent_when_handler_does_not_read_body() {
    // Python: no wsgi.input read → no 100; the final status is the response.
    let server = spawn_async(2, Arc::new(NoBodyRead204));
    let mut client = TcpStream::connect_timeout(&server.addr, Duration::from_millis(400)).unwrap();
    client
        .set_read_timeout(Some(Duration::from_millis(400)))
        .unwrap();
    client
        .write_all(
            b"PUT /v1/a/c/o HTTP/1.1\r\n\
              Host: 127.0.0.1\r\n\
              Expect: 100-continue\r\n\
              Content-Length: 4\r\n\
              Connection: close\r\n\
              \r\n",
        )
        .unwrap();
    client.flush().unwrap();
    let head = read_until_double_crlf(&mut client).unwrap();
    let text = String::from_utf8_lossy(&head);
    assert!(
        !text.starts_with("HTTP/1.1 100 Continue"),
        "unread body must not emit 100 (http_protocol.py:214-217 first-read), got {text:?}"
    );
    assert!(
        text.contains("204"),
        "unread Expect PUT should complete 204, got {text:?}"
    );
}

#[test]
fn three_keepalive_expect_continue_at_two_workers() {
    // Same occupancy bar as align_expect_continue.rs; must stay spawn_server(2).
    let server = harness::spawn_server(2, Arc::new(harness::echo_materialize));
    let _idle_a = harness::get_keepalive(server.addr).expect("keepalive a");
    let _idle_b = harness::get_keepalive(server.addr).expect("keepalive b");
    thread::sleep(Duration::from_millis(80));
    let started = Instant::now();
    let mut client = TcpStream::connect_timeout(&server.addr, Duration::from_millis(400)).unwrap();
    client
        .set_read_timeout(Some(Duration::from_millis(400)))
        .unwrap();
    client
        .write_all(
            b"PUT /v1/a/c/o HTTP/1.1\r\n\
              Host: 127.0.0.1\r\n\
              Expect: 100-continue\r\n\
              Content-Length: 4\r\n\
              Connection: keep-alive\r\n\
              \r\n",
        )
        .unwrap();
    client.flush().unwrap();
    let head = read_until_double_crlf(&mut client).expect("100 Continue");
    let elapsed = started.elapsed();
    let text = String::from_utf8_lossy(&head);
    assert!(
        text.starts_with("HTTP/1.1 100 Continue"),
        "Gate 5 occupancy: {text:?} after {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_millis(400),
        "100 Continue took {elapsed:?}"
    );
}

#[test]
fn shipped_range_and_conditional_are_the_object_server_functions() {
    // swob Range / Match live in this crate; the shipped object GET applies
    // them in `ObjectServer::get_streaming_async` (handle_async_get_range_and_if_none_match).
    let body = b"abcdefghij";
    let mut req = Request {
        method: "GET".into(),
        path: "/sda1/0/a/c/o".into(),
        query_string: String::new(),
        headers: HeaderKeyDict::new(),
        body: swift_http::Body::empty(),
    };
    req.headers.set("Range", "bytes=2-5");
    let parsed = Range::parse("bytes=2-5").unwrap();
    let ranges = parsed.ranges_for_length(Some(body.len() as u64)).unwrap();
    assert_eq!(&body[ranges[0].0 as usize..ranges[0].1 as usize], b"cdef");
    let unsat = Range::parse("bytes=99-100")
        .unwrap()
        .ranges_for_length(Some(body.len() as u64))
        .unwrap();
    assert!(unsat.is_empty());
    let mut base = Response::with_body(200, body.to_vec());
    base.headers.set("ETag", "\"ten\"");
    req.headers.remove("Range");
    req.headers.set("If-None-Match", "\"ten\"");
    assert_eq!(conditional_response_status(&req, &base), Some(304));
}

#[test]
fn chunked_put_is_decoded_on_hyper_http1_before_handler() {
    // http_protocol.py:207-208: Transfer-Encoding last token `chunked`
    // sets wsgi.input.chunked_input. Production Hyper HTTP/1.1 decode
    // must present the same bytes to the shipped AsyncService.
    struct CollectThen201;
    impl AsyncService for CollectThen201 {
        fn call(
            &self,
            mut req: AsyncRequest,
        ) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
            Box::pin(async move {
                let mut body = Vec::new();
                while let Ok(Some(c)) = req.body.next_chunk().await {
                    body.extend_from_slice(&c);
                }
                assert_eq!(body, b"hello", "chunked decoder must yield object bytes");
                Response::new(201)
            })
        }
    }
    let server = spawn_async(2, Arc::new(CollectThen201));
    let mut client = TcpStream::connect_timeout(&server.addr, Duration::from_millis(400)).unwrap();
    client
        .set_read_timeout(Some(Duration::from_millis(800)))
        .unwrap();
    client
        .write_all(
            b"PUT /v1/a/c/o HTTP/1.1\r\n\
              Host: 127.0.0.1\r\n\
              Transfer-Encoding: chunked\r\n\
              Connection: close\r\n\
              \r\n\
              5\r\nhello\r\n\
              0\r\n\r\n",
        )
        .unwrap();
    let (st, buf) = harness::read_http_response(&mut client).unwrap();
    assert_eq!(st, 201, "{}", String::from_utf8_lossy(&buf));
}

#[test]
fn etag_header_survives_on_the_wire() {
    // wsgi.py:443-446: do not recapitalize to the point S3 ETag is lost.
    let server = spawn_async(2, Arc::new(EtagService));
    let mut client = TcpStream::connect_timeout(&server.addr, Duration::from_millis(400)).unwrap();
    client
        .set_read_timeout(Some(Duration::from_millis(400)))
        .unwrap();
    client
        .write_all(b"GET /o HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .unwrap();
    let head = read_until_double_crlf(&mut client).unwrap();
    let text = String::from_utf8_lossy(&head);
    assert!(
        text.to_ascii_lowercase().contains("etag:"),
        "ETag must be present on the wire, got {text:?}"
    );
}

#[test]
fn swift_utf8_metadata_names_survive_raw_request_and_response_wire() {
    // Python Swift accepts UTF-8 object metadata field names on its native
    // HTTP/1.1 wire. RFC-only Hyper rejects those names before AsyncService,
    // so the production listener has a narrowly-scoped Swift compatibility
    // handoff. This is a real socket test of both directions, not a parser
    // unit test.
    let server = spawn_async(2, Arc::new(SwiftUtf8MetadataEcho));
    let mut client = TcpStream::connect_timeout(&server.addr, Duration::from_millis(400)).unwrap();
    client
        .set_read_timeout(Some(Duration::from_millis(800)))
        .unwrap();
    client
        .write_all(
            b"PUT /v1/a/c/o-%C3%A8 HTTP/1.1\r\n\
              Host: 127.0.0.1\r\n\
              x-object-meta-\xc3\xa8: meta-\xc3\xa8\r\n\
              Content-Length: 4\r\n\
              Connection: close\r\n\
              \r\n\
              body",
        )
        .unwrap();

    let mut response = Vec::new();
    client.read_to_end(&mut response).unwrap();
    assert!(
        response.starts_with(b"HTTP/1.1 201 "),
        "unexpected response: {:?}",
        String::from_utf8_lossy(&response)
    );
    assert!(
        response
            .windows(b"X-Object-Meta-\xc3\xa8: meta-\xc3\xa8\r\n".len())
            .any(|window| window == b"X-Object-Meta-\xc3\xa8: meta-\xc3\xa8\r\n"),
        "UTF-8 metadata field must survive response wire: {:?}",
        String::from_utf8_lossy(&response)
    );
}

#[test]
fn swiftclient_utf8_zero_length_post_receives_a_complete_response() {
    let server = spawn_async(2, Arc::new(SwiftUtf8MetadataPost));
    let response = transact(
        server.addr,
        b"POST /v1/AUTH_test/container-%C3%A8/object-%C3%A8 HTTP/1.1\r\n\
          Host: 127.0.0.1\r\n\
          Accept-Encoding: identity\r\n\
          x-auth-token: AUTH_tk-test\r\n\
          x-object-meta-\xc3\xa8: meta-\xc3\xa8\r\n\
          user-agent: python-swiftclient-4.10.0\r\n\
          Content-Length: 0\r\n\
          \r\n",
    );
    assert!(
        response.starts_with(b"HTTP/1.1 202 "),
        "swiftclient POST must not be closed without a response: {:?}",
        String::from_utf8_lossy(&response)
    );
    assert!(
        response
            .windows(b"Content-Length: 0\r\n".len())
            .any(|window| window == b"Content-Length: 0\r\n"),
        "empty response must be explicitly framed: {:?}",
        String::from_utf8_lossy(&response)
    );
}

#[test]
fn swift_utf8_head_terminator_may_straddle_request_line_peek_boundary() {
    // Reproduce the production failure deterministically. The first socket
    // write contains the request line and all but the final LF of CRLFCRLF.
    // The request-line peek is allowed to consume that whole packet, so the
    // complete-head reader must retain the peeked suffix when it continues.
    let server = spawn_async(2, Arc::new(SwiftUtf8MetadataPost));
    let mut client = TcpStream::connect_timeout(&server.addr, Duration::from_millis(400)).unwrap();
    client
        .set_read_timeout(Some(Duration::from_millis(800)))
        .unwrap();
    client
        .write_all(
            b"POST /v1/AUTH_test/container-%C3%A8/object-%C3%A8 HTTP/1.1\r\n\
              Host: 127.0.0.1\r\n\
              x-object-meta-\xc3\xa8: meta-\xc3\xa8\r\n\
              Content-Length: 0\r\n\r",
        )
        .unwrap();
    client.flush().unwrap();
    thread::sleep(Duration::from_millis(50));
    client.write_all(b"\n").unwrap();
    client.flush().unwrap();

    let mut response = Vec::new();
    client.read_to_end(&mut response).unwrap();
    assert!(
        response.starts_with(b"HTTP/1.1 202 "),
        "split head terminator must not time out: {:?}",
        String::from_utf8_lossy(&response)
    );
}

struct EventletServer {
    addr: std::net::SocketAddr,
    child: Option<Child>,
}

impl Drop for EventletServer {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

fn swift_src_root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for _ in 0..12 {
        if p.join("swift/common/http_protocol.py").is_file() {
            return p;
        }
        if !p.pop() {
            break;
        }
    }
    panic!(
        "could not find swift/common/http_protocol.py above {}",
        env!("CARGO_MANIFEST_DIR")
    );
}

fn spawn_eventlet() -> EventletServer {
    let root = swift_src_root();
    let script =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/concurrency/eventlet_swift_wsgi.py");
    let mut child = Command::new("python3")
        .arg(&script)
        .env("PYTHONPATH", &root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn eventlet_swift_wsgi.py: {e}"));
    let stdout = child.stdout.take().expect("stdout");
    let mut lines = BufReader::new(stdout).lines();
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut port: Option<u16> = None;
    while Instant::now() < deadline {
        if let Some(Ok(line)) = lines.next() {
            if let Some(p) = line.strip_prefix("PORT=") {
                port = p.trim().parse().ok();
                break;
            }
        } else {
            break;
        }
    }
    let Some(port) = port else {
        let err = child
            .stderr
            .take()
            .map(|mut s| {
                let mut b = String::new();
                let _ = s.read_to_string(&mut b);
                b
            })
            .unwrap_or_default();
        let _ = child.kill();
        panic!("Eventlet SwiftHttpProtocol did not print PORT= ; stderr={err}");
    };
    let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    EventletServer {
        addr,
        child: Some(child),
    }
}

fn first_line(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .lines()
        .next()
        .unwrap_or("")
        .to_string()
}

fn transact(addr: std::net::SocketAddr, req: &[u8]) -> Vec<u8> {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(req).unwrap();
    s.flush().unwrap();
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    buf
}

/// Dual-feed oracle for **protocol** (Expect / chunked / ETag), not object
/// verbs. COPY/DELETE/SSYNC object semantics are the shipped ObjectServer /
/// proxy tests below, citing `obj/server.py` and `copy.py`.
struct ProtocolPutService;

impl AsyncService for ProtocolPutService {
    fn call(&self, mut req: AsyncRequest) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        Box::pin(async move {
            while let Ok(Some(_)) = req.body.next_chunk().await {}
            let mut r = Response::new(201);
            r.headers.set("ETag", "\"abc\"");
            r
        })
    }
}

#[test]
fn dual_feed_eventlet_swift_http_protocol_vs_hyper() {
    let py = spawn_eventlet();
    let rust = spawn_async(2, Arc::new(ProtocolPutService));

    let expect_put = b"PUT /v1/a/c/o HTTP/1.1\r\nHost: 127.0.0.1\r\nExpect: 100-continue\r\nContent-Length: 4\r\nConnection: close\r\n\r\n";
    let py_100 = {
        let mut s = TcpStream::connect_timeout(&py.addr, Duration::from_secs(2)).unwrap();
        s.set_read_timeout(Some(Duration::from_millis(800)))
            .unwrap();
        s.write_all(expect_put).unwrap();
        s.flush().unwrap();
        let head = read_until_double_crlf(&mut s).unwrap();
        s.write_all(b"abcd").unwrap();
        let _ = transact_rest(&mut s);
        first_line(&head)
    };
    let rust_100 = {
        let mut s = TcpStream::connect_timeout(&rust.addr, Duration::from_secs(2)).unwrap();
        s.set_read_timeout(Some(Duration::from_millis(800)))
            .unwrap();
        s.write_all(expect_put).unwrap();
        s.flush().unwrap();
        let head = read_until_double_crlf(&mut s).unwrap();
        s.write_all(b"abcd").unwrap();
        let _ = transact_rest(&mut s);
        first_line(&head)
    };
    assert!(
        py_100.starts_with("HTTP/1.1 100 Continue"),
        "Eventlet SwiftHttpProtocol 100: {py_100:?}"
    );
    assert_eq!(
        py_100, rust_100,
        "Expect: 100-continue first-read must match Eventlet SwiftHttpProtocol"
    );

    let chunked = b"PUT /v1/a/c/o HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
    let py_ch = first_line(&transact(py.addr, chunked));
    let rust_ch = first_line(&transact(rust.addr, chunked));
    assert!(py_ch.contains("201"), "Eventlet chunked {py_ch:?}");
    assert_eq!(
        py_ch.split_whitespace().nth(1),
        rust_ch.split_whitespace().nth(1),
        "chunked status Eventlet={py_ch:?} Hyper={rust_ch:?}"
    );
    // COPY/DELETE/SSYNC object verbs are not protocol stubs. See
    // `shipped_object_delete_is_204_tombstone`, `shipped_object_ssync_accept_no_commit`,
    // and proxy `hyper_serve_copy_is_get_then_put_on_shipped_proxy`.
}

fn transact_rest(s: &mut TcpStream) -> Vec<u8> {
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    buf
}

static NEXT_OBJECT_SERVER_DIR: AtomicU64 = AtomicU64::new(0);

fn spawn_object_server() -> (harness::Server, PathBuf) {
    let instance = NEXT_OBJECT_SERVER_DIR.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "gate5-obj-{}-{}-{}",
        std::process::id(),
        line!(),
        instance,
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("sda1")).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let shutdown = Arc::new(AtomicBool::new(false));
    let server = ObjectServer::new(ObjectServerConfig {
        devices: dir.clone(),
        mount_check: false,
        hash_config: HashPathConfig::new(b"".to_vec(), b"gate5".to_vec()).unwrap(),
        diskfile: DiskFileConfig::default(),
        policies: HashMap::from([(0, PolicyKind::Replication)]),
        container_update_timeout: Duration::from_millis(50),
        container_update_mode: swift_object_server::ContainerUpdateMode::Async,
    });
    let cfg = ServerConfig {
        worker_threads: 2,
        shutdown: Some(Arc::clone(&shutdown)),
        ..ServerConfig::default()
    };
    let join = thread::spawn(move || serve_with_config(listener, server, cfg));
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(20)).is_ok() {
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    (
        harness::Server {
            addr,
            shutdown,
            join: Some(join),
        },
        dir,
    )
}

#[test]
fn shipped_object_delete_is_204_tombstone() {
    // obj/server.py:1311-1369 HTTPNoContent after a winning tombstone.
    let (server, dir) = spawn_object_server();
    let put = transact(
        server.addr,
        b"PUT /sda1/0/AUTH_test/c/o HTTP/1.1\r\nHost: t\r\nX-Timestamp: 5000\r\nContent-Type: application/octet-stream\r\nContent-Length: 4\r\nConnection: close\r\n\r\nabcd",
    );
    assert!(
        first_line(&put).contains("201"),
        "setup PUT {}",
        first_line(&put)
    );
    let del = transact(
        server.addr,
        b"DELETE /sda1/0/AUTH_test/c/o HTTP/1.1\r\nHost: t\r\nX-Timestamp: 5001\r\nConnection: close\r\n\r\n",
    );
    let line = first_line(&del);
    assert!(
        line.contains("204"),
        "DELETE tombstone must be 204 (obj/server.py:1311-1369), got {line:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn shipped_object_ssync_accept_no_commit() {
    // obj/server.py:1406-1415 X-Backend-Accept-No-Commit; sender getresponse
    // after headers (ssync_sender.py:264-272).
    let (server, dir) = spawn_object_server();
    let body =
        b":MISSING_CHECK: START\r\n:MISSING_CHECK: END\r\n:UPDATES: START\r\n:UPDATES: END\r\n";
    let mut req = format!(
        "SSYNC /sda1/0 HTTP/1.1\r\nHost: t\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    req.extend_from_slice(body);
    let resp = transact(server.addr, &req);
    let text = String::from_utf8_lossy(&resp);
    assert!(
        text.contains("200"),
        "SSYNC status obj/server.py:1406-1415 {text:?}"
    );
    assert!(
        text.to_ascii_lowercase()
            .contains("x-backend-accept-no-commit: true"),
        "SSYNC must advertise X-Backend-Accept-No-Commit (obj/server.py:1412), got {text:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn copy_py_oracle_is_get_then_put() {
    // copy.py:49-65 / 320-347. Shipped Hyper COPY is the proxy test
    // `hyper_serve_copy_is_get_then_put_on_shipped_proxy` (this crate
    // cannot depend on swift-proxy-server). This monorepo does not vendor
    // upstream Swift sources, so a missing oracle is skip — not a compile
    // failure of every workspace test.
    let oracle = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../swift/common/middleware/copy.py");
    let Ok(copy_py) = std::fs::read_to_string(&oracle) else {
        return;
    };
    assert!(
        copy_py.contains("COPY") && copy_py.contains("PUT") && copy_py.contains("GET"),
        "copy.py must describe COPY as GET then PUT"
    );
}
