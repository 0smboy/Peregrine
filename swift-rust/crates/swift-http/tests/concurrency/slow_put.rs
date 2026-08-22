//! Gate 2 / §26.C: a slow request body must not pin a storage/HTTP worker
//! for the entire upload. Phase 0: RED on the sync `materialize` handler.

#[path = "harness.rs"]
mod harness;

use std::io::Write;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[test]
fn slow_put_body_does_not_starve_a_health_get() {
    let server = harness::spawn_server(2, Arc::new(harness::echo_materialize));

    const TARGET: usize = 1_000;
    let mut held = Vec::with_capacity(TARGET);
    for i in 0..TARGET {
        match std::net::TcpStream::connect(server.addr) {
            Ok(s) => {
                let mut s = s;
                if s.write_all(
                    b"PUT /v1/a/c/o HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 64\r\nConnection: keep-alive\r\n\r\nX",
                )
                .is_err()
                {
                    panic!("ENVIRONMENT BLOCKED: slow PUT write failed at {i}/{TARGET}");
                }
                held.push(s);
            }
            Err(e) => {
                panic!(
                    "ENVIRONMENT BLOCKED: slow PUT target={TARGET} opened={i}: {e}"
                );
            }
        }
    }
    thread::sleep(Duration::from_millis(80));

    let (status, elapsed) = harness::get_close_timed(server.addr, Duration::from_millis(400))
        .expect("GET must not wait on slow PUT bodies");
    assert_eq!(status, 200);
    assert!(
        elapsed < Duration::from_millis(400),
        "GET took {elapsed:?}; {TARGET} slow PUTs pinned workers (Gate 2)"
    );
    drop(held);
}
