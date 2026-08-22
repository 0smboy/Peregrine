//! Gate 1 / §26.B: slow header drip must not pin every worker.

#[path = "harness.rs"]
mod harness;

use std::io::Write;
use std::net::TcpStream;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[test]
fn slow_headers_do_not_starve_healthy_requests() {
    let server = harness::spawn_server(2, Arc::new(harness::tiny_ok));

    let mut slow_a = TcpStream::connect(server.addr).unwrap();
    slow_a
        .write_all(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nX-A: ")
        .unwrap();
    let mut slow_b = TcpStream::connect(server.addr).unwrap();
    slow_b
        .write_all(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nX-B: ")
        .unwrap();
    thread::sleep(Duration::from_millis(80));

    let (status, elapsed) = harness::get_close_timed(server.addr, Duration::from_millis(400))
        .expect("healthy request must not wait on slowloris clients");
    assert_eq!(status, 200);
    assert!(
        elapsed < Duration::from_millis(400),
        "healthy request took {elapsed:?}; slowloris pinned workers"
    );
}
