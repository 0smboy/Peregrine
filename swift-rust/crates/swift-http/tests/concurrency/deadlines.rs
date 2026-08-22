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
