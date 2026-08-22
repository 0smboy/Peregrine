//! Gate 2 / §26.D: a slow GET client must not pin the worker in write_response.

#[path = "harness.rs"]
mod harness;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[test]
fn slow_get_reader_does_not_starve_a_health_get() {
    let server = harness::spawn_server(2, Arc::new(harness::big_body));

    fn start_slow_get(addr: std::net::SocketAddr) -> TcpStream {
        let mut s = TcpStream::connect(addr).unwrap();
        s.write_all(b"GET /big HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\n\r\n")
            .unwrap();
        s.flush().unwrap();
        let mut one = [0u8; 1];
        let _ = s.read(&mut one);
        s
    }

    let _a = start_slow_get(server.addr);
    let _b = start_slow_get(server.addr);
    thread::sleep(Duration::from_millis(80));

    let (status, elapsed) = harness::get_close_timed(server.addr, Duration::from_millis(400))
        .expect("health GET must not wait on slow readers");
    assert_eq!(status, 200);
    assert!(
        elapsed < Duration::from_millis(400),
        "health GET took {elapsed:?}; slow reader pinned workers (Gate 2)"
    );
}
