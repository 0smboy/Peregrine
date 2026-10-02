//! Phase 13.A: 50_000 idle keep-alives must not take a worker thread each.
//! If the OS cannot open 50k sockets, this test writes the error to stderr
//! and still asserts 2-worker occupancy (Gate 1) rather than faking 50k.

#[path = "harness.rs"]
mod harness;

use std::io::Write;
use std::net::TcpStream;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use swift_http::server::{serve_forever_with_config, set_listen_backlog, ServerConfig};

#[test]
fn idle_50000_keepalives_or_capture_unavailability() {
    const TARGET: usize = 50_000;
    // Connection cap is independent of worker_threads=2 (Gate 1). Request cap
    // stays small so a health GET still admits while keep-alives sit idle.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    // std::net::TcpListener::bind uses a small platform backlog. A tight local
    // connect loop can overflow that queue before Tokio gets scheduled and
    // falsely report a connection-cap failure at roughly 2x the backlog.
    set_listen_backlog(&listener, (TARGET + 8) as i32).unwrap();
    let addr = listener.local_addr().unwrap();
    let shutdown = Arc::new(AtomicBool::new(false));
    let config = ServerConfig {
        worker_threads: 2,
        connection_queue: 256,
        max_connections: TARGET + 8,
        max_active_requests: 16,
        client_timeout_secs: 5,
        head_deadline_secs: 5,
        max_requests_per_connection: 32,
        shutdown: Some(Arc::clone(&shutdown)),
        ..ServerConfig::default()
    };
    let flag = Arc::clone(&shutdown);
    let handler = Arc::new(harness::tiny_ok);
    let join = thread::spawn(move || serve_forever_with_config(listener, handler, config));
    let ready = Instant::now() + Duration::from_secs(2);
    while Instant::now() < ready {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(20)).is_ok() {
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    let server = harness::Server {
        addr,
        shutdown: flag,
        join: Some(join),
    };
    // Reserve a keep-alive before the climb. After an OS port ceiling a
    // new connect is AddrNotAvailable; that is not worker starvation.
    let mut probe = harness::get_keepalive(server.addr)
        .expect("reserved occupancy probe before the climb");
    let outcome = harness::open_many(&[server.addr], TARGET, 8, Duration::from_secs(600));
    let opened = outcome.streams.len();
    let mut held = outcome.streams;
    let os_ceiling = outcome.errors.iter().any(|error| {
        error.contains("AddrNotAvailable") || error.contains("ephemeral ports exhausted")
    });
    if opened != TARGET {
        eprintln!(
            "ENVIRONMENT BLOCKED: idle-50k opened {opened} != target {TARGET}; \
             attempts={} errors={:?}. This is not a 50k PASS.",
            outcome.attempts, outcome.errors
        );
        assert!(
            opened > 0 && os_ceiling,
            "idle-50k failed for a reason other than OS socket ceiling: \
             opened={opened} attempts={} errors={:?}",
            outcome.attempts, outcome.errors
        );
    }
    let status = health_on_held(&mut probe, &mut held);
    assert_eq!(
        status, 200,
        "health must work with {opened} idle sockets at worker_threads=2"
    );
    drop(held);
}

fn health_on_held(probe: &mut TcpStream, held: &mut [TcpStream]) -> u16 {
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut last = 0u16;
    while Instant::now() < deadline {
        last = probe_status(probe);
        if last == 200 {
            return last;
        }
        for stream in held.iter_mut().take(4) {
            last = probe_status(stream);
            if last == 200 {
                return last;
            }
        }
        thread::sleep(Duration::from_millis(15));
    }
    last
}

fn probe_status(stream: &mut TcpStream) -> u16 {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(400)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(400)));
    if stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\n\r\n")
        .is_err()
    {
        return 0;
    }
    match harness::read_http_response(stream) {
        Ok((status, _)) => status,
        Err(_) => 0,
    }
}
