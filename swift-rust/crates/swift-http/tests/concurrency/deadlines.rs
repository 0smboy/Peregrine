//! Body-idle vs upload-lifetime: distinct budgets (AGENTS.md §19).
//!
//! Python: `wsgi.py:442` `socket_timeout = client_timeout` (default 60s) is
//! Eventlet's per-socket idle. Peregrine splits that into progress-aware
//! `body_idle_timeout_secs` vs total `max_upload_time_secs`.
#![allow(dead_code)]

#[path = "harness.rs"]
mod harness;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use swift_http::server::{serve_forever_with_config, Handler, ServerConfig};

fn spawn_with(config: impl FnOnce(&mut ServerConfig), handler: Handler) -> harness::Server {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut cfg = ServerConfig {
        worker_threads: 2,
        connection_queue: 32,
        client_timeout_secs: 2,
        head_deadline_secs: 2,
        max_requests_per_connection: 32,
        shutdown: Some(Arc::clone(&shutdown)),
        ..ServerConfig::default()
    };
    config(&mut cfg);
    let flag = Arc::clone(&shutdown);
    let join = std::thread::spawn(move || serve_forever_with_config(listener, handler, cfg));
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while std::time::Instant::now() < deadline {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(20)).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    harness::Server {
        addr,
        shutdown: flag,
        join: Some(join),
    }
}

#[test]
fn body_idle_fires_on_stalled_chunk_while_upload_lifetime_is_separate() {
    let server = spawn_with(
        |c| {
            c.body_idle_timeout_secs = 1;
            c.max_upload_time_secs = 30;
            c.client_timeout_secs = 30;
        },
        Arc::new(harness::echo_materialize),
    );
    let mut client = TcpStream::connect_timeout(&server.addr, Duration::from_secs(1)).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    client
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let started = std::time::Instant::now();
    client
        .write_all(
            b"PUT /o HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 8\r\nConnection: close\r\n\r\nab",
        )
        .unwrap();
    client.flush().unwrap();
    let mut buf = Vec::new();
    let _ = client.read_to_end(&mut buf);
    let elapsed = started.elapsed();
    let text = String::from_utf8_lossy(&buf);
    let status_line = text.lines().next().unwrap_or("");
    assert!(
        status_line.contains("408") || status_line.contains("499"),
        "stalled body must close on body-idle (408/499), not upload-lifetime; got {text:?}"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "body-idle is 1s; must not wait the 30s upload lifetime: {elapsed:?}"
    );
}

#[test]
fn production_engine_is_hyper_http1() {
    assert_eq!(swift_http::PRODUCTION_HTTP1_ENGINE, "hyper/http1");
}

#[test]
fn idle_keepalive_outlives_header_deadline() {
    // HeaderDeadline (1s) must not kill an idle keep-alive. Idle wait is
    // client_timeout (8s). A second request after 2s must still 200, and a
    // new health HEAD while that conn is held must complete quickly.
    let server = spawn_with(
        |c| {
            c.head_deadline_secs = 1;
            c.client_timeout_secs = 8;
            c.max_connections = 32;
            c.max_active_requests = 8;
        },
        Arc::new(harness::tiny_ok),
    );
    let mut held = harness::get_keepalive(server.addr).expect("first keep-alive");
    std::thread::sleep(Duration::from_millis(2100));
    held.write_all(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\n\r\n")
        .expect("second request on idle conn");
    held.flush().unwrap();
    let (status, _) = harness::read_http_response(&mut held).expect("second response");
    assert_eq!(
        status, 200,
        "idle keep-alive must survive past head_deadline_secs"
    );
    let (health, elapsed) =
        harness::get_close_timed(server.addr, Duration::from_millis(400)).expect("health");
    assert_eq!(health, 200);
    assert!(
        elapsed < Duration::from_millis(250),
        "health HEAD with one idle keep-alive took {elapsed:?}"
    );
}

#[test]
fn new_connection_idle_outlives_header_deadline() {
    // HeaderDeadline must not start until the first request-line byte.
    // Connect, wait past head_deadline, then send a full GET → 200.
    let server = spawn_with(
        |c| {
            c.head_deadline_secs = 1;
            c.client_timeout_secs = 8;
            c.max_connections = 32;
            c.max_active_requests = 8;
        },
        Arc::new(harness::tiny_ok),
    );
    let mut held = TcpStream::connect_timeout(&server.addr, Duration::from_secs(1)).unwrap();
    held.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    held.set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    std::thread::sleep(Duration::from_millis(2100));
    held.write_all(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\n\r\n")
        .expect("first request after silent accept");
    held.flush().unwrap();
    let (status, _) = harness::read_http_response(&mut held).expect("first response");
    assert_eq!(
        status, 200,
        "silent new connection must survive past head_deadline_secs"
    );
}

#[test]
fn first_line_drip_still_hits_header_deadline() {
    // Once the client drips a request-line byte, HeaderDeadline applies.
    let server = spawn_with(
        |c| {
            c.head_deadline_secs = 1;
            c.client_timeout_secs = 8;
            c.max_connections = 32;
            c.max_active_requests = 8;
        },
        Arc::new(harness::tiny_ok),
    );
    let mut slow = TcpStream::connect_timeout(&server.addr, Duration::from_secs(1)).unwrap();
    slow.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    slow.set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let started = std::time::Instant::now();
    slow.write_all(b"GET / HT").unwrap();
    slow.flush().unwrap();
    let mut buf = Vec::new();
    let _ = slow.read_to_end(&mut buf);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "dripping request line must hit HeaderDeadline; held {:?}",
        started.elapsed()
    );
}

#[test]
fn idle_keepalives_do_not_delay_health_head() {
    // Per-conn shutdown wait_flag (1ms Sleep × N idle) drowned G7 100k
    // health p99. Idle wait is a pending read + one process-wide watch.
    let server = spawn_with(
        |c| {
            c.head_deadline_secs = 1;
            c.client_timeout_secs = 8;
            c.max_connections = 256;
            c.max_active_requests = 256;
            c.max_requests_per_connection = 1024;
        },
        Arc::new(harness::tiny_ok),
    );
    let mut held = Vec::new();
    for _ in 0..128 {
        held.push(harness::get_keepalive(server.addr).expect("idle keep-alive"));
    }
    let mut samples = Vec::new();
    for _ in 0..40 {
        let (status, elapsed) =
            harness::get_close_timed(server.addr, Duration::from_millis(400)).expect("health");
        assert_eq!(status, 200);
        samples.push(elapsed.as_secs_f64() * 1000.0);
    }
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let p99 = samples[(samples.len() - 1) * 99 / 100];
    assert!(
        p99 < 50.0,
        "health HEAD p99 {p99:.1} ms with 128 idle keep-alives"
    );
    let _ = held;
}
