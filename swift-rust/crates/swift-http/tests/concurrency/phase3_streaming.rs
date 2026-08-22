//! Production serve consumes a multi-chunk body without requiring the
//! handler to see a single materialized buffer first.
#![allow(dead_code)]

#[path = "harness.rs"]
mod harness;

use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use swift_http::{Request, Response};

#[test]
fn echo_handler_sees_body_in_chunks_on_hyper_serve() {
    let chunks = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&chunks);
    let handler: swift_http::Handler = Arc::new(move |mut request: Request| {
        let n = request.body.content_length().unwrap_or(0);
        seen.fetch_add(n as usize, Ordering::SeqCst);
        match request.body.materialize(u64::MAX) {
            Ok(bytes) => Response::with_body(200, bytes.to_vec()),
            Err(_) => Response::error(500, "body"),
        }
    });
    let server = harness::spawn_server(2, handler);
    let payload = vec![b'x'; 128 * 1024];
    let mut client =
        std::net::TcpStream::connect_timeout(&server.addr, std::time::Duration::from_secs(1))
            .unwrap();
    let head = format!(
        "PUT /o HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    );
    client.write_all(head.as_bytes()).unwrap();
    client.write_all(&payload).unwrap();
    client.flush().unwrap();
    let (status, _) = harness::read_http_response(&mut client).unwrap();
    assert_eq!(status, 200, "chunked-size PUT must complete on Hyper serve");
    assert_eq!(chunks.load(Ordering::SeqCst), payload.len());
}

#[test]
fn occupancy_still_pinned_at_two_workers() {
    assert_eq!(swift_http::PRODUCTION_HTTP1_ENGINE, "hyper/http1");
    let server = harness::spawn_server(2, Arc::new(harness::tiny_ok));
    let _a = harness::get_keepalive(server.addr).expect("ka a");
    let _b = harness::get_keepalive(server.addr).expect("ka b");
    let (status, elapsed) =
        harness::get_close_timed(server.addr, std::time::Duration::from_millis(400)).unwrap();
    assert_eq!(status, 200);
    assert!(
        elapsed < std::time::Duration::from_millis(400),
        "third request starved: {elapsed:?}"
    );
}
