//! Gate 4: overload is fail-closed 503 on the shipped Hyper accept loop.
//!
//! `AdmissionController::try_acquire_connection` never waits and never
//! grows a queue. Overflow writes `HTTP/1.1 503` via `reject_overloaded`.

#[path = "harness.rs"]
mod harness;

use std::io::Write;
use std::net::{Shutdown, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use swift_http::server::{serve_forever_with_config, ServerConfig};

fn spawn_max_connections(max_connections: usize) -> harness::Server {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let config = ServerConfig {
        worker_threads: 2,
        connection_queue: 32,
        max_connections,
        client_timeout_secs: 2,
        head_deadline_secs: 2,
        max_requests_per_connection: 32,
        shutdown: Some(Arc::clone(&shutdown)),
        ..ServerConfig::default()
    };
    let flag = Arc::clone(&shutdown);
    let handler = Arc::new(harness::tiny_ok);
    let join = std::thread::spawn(move || serve_forever_with_config(listener, handler, config));
    // Readiness must use Connection: close so the single admission slot is
    // released before the test holds a keepalive. A bare TCP probe would sit
    // in header-read and occupy max_connections=1.
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let mut ready = false;
    while std::time::Instant::now() < deadline {
        if let Ok((200, _)) =
            harness::get_close_timed(addr, Duration::from_millis(50))
        {
            ready = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(ready, "Hyper serve did not accept a close-probe GET");
    harness::Server {
        addr,
        shutdown: flag,
        join: Some(join),
    }
}

#[test]
fn extra_connection_is_503_when_max_connections_is_full() {
    let server = spawn_max_connections(1);
    let held = harness::get_keepalive(server.addr).expect("held keepalive occupies the one slot");

    let mut extra = TcpStream::connect_timeout(&server.addr, Duration::from_millis(400))
        .expect("overflow connect");
    extra
        .set_read_timeout(Some(Duration::from_millis(800)))
        .unwrap();
    extra
        .set_write_timeout(Some(Duration::from_millis(800)))
        .unwrap();
    let _ = extra.write_all(
        b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
    );
    let _ = extra.flush();
    let _ = extra.shutdown(Shutdown::Write);
    let (status, buf) = harness::read_http_response(&mut extra).expect("overflow response");
    assert_eq!(
        status, 503,
        "shipped Hyper must fail-closed at max_connections, got {status} {}",
        String::from_utf8_lossy(&buf)
    );
    drop(held);
}
