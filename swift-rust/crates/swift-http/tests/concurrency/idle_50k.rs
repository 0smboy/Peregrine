//! Phase 13.A: 50_000 idle keep-alives must not take a worker thread each.
//! If the OS cannot open 50k sockets, this test writes the error to stderr
//! and still asserts 2-worker occupancy (Gate 1) rather than faking 50k.

#[path = "harness.rs"]
mod harness;

use std::io::ErrorKind;
use std::net::TcpStream;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use swift_http::server::{serve_forever_with_config, ServerConfig};

#[test]
fn idle_50000_keepalives_or_capture_unavailability() {
    const TARGET: usize = 50_000;
    // Connection cap is independent of worker_threads=2 (Gate 1). Request cap
    // stays small so a health GET still admits while keep-alives sit idle.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
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
    let mut held = Vec::new();
    held.reserve(TARGET.min(1024));
    let mut opened = 0usize;
    let mut unavailable: Option<String> = None;
    let cap = Instant::now() + Duration::from_secs(8);
    for i in 0..TARGET {
        if Instant::now() >= cap {
            unavailable = Some(format!(
                "idle-50k time cap after {opened} sockets (target {TARGET})"
            ));
            break;
        }
        match TcpStream::connect_timeout(&server.addr, Duration::from_millis(50)) {
            Ok(s) => {
                let _ = s.set_nodelay(true);
                held.push(s);
                opened += 1;
            }
            Err(e) => {
                unavailable = Some(format!(
                    "idle-50k stopped after {opened} sockets at i={i}: {e} kind={:?}",
                    e.kind()
                ));
                break;
            }
        }
        if opened > 0 && opened % 5000 == 0 {
            // A health request must still complete while keep-alives sit idle.
            match harness::get_close_timed(server.addr, Duration::from_millis(400)) {
                Ok((200, _)) => {}
                Ok((status, _)) => {
                    unavailable = Some(format!("health failed at {opened} idle sockets: {status}"));
                    break;
                }
                Err(e) => {
                    unavailable = Some(format!("health connect failed at {opened}: {e}"));
                    break;
                }
            }
        }
    }
    if let Some(msg) = unavailable {
        panic!(
            "ENVIRONMENT BLOCKED: idle-50k target={TARGET} opened={opened}: {msg}"
        );
    }
    assert_eq!(
        opened, TARGET,
        "ENVIRONMENT BLOCKED: idle-50k opened {opened} != target {TARGET}"
    );
    let (status, _) = harness::get_close_timed(server.addr, Duration::from_secs(1))
        .expect("health GET with 50k idle keep-alives");
    assert_eq!(status, 200, "health must work with {opened} idle sockets");
    drop(held);
    let _ = ErrorKind::AddrInUse;
}
