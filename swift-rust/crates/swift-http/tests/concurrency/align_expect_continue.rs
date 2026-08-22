//! Gate 5 / AGENTS.md §28: `Expect: 100-continue` under connection keep-alive.
//!
//! `src/server.rs` already unit-tests the protocol when a worker is free
//! (lazy 100 on first body read, withhold on unread reject, 417, multiphase
//! re-arm). This file does not repeat those.
//!
//! Python Eventlet: `workers=2` are processes; each has ~1024 greenlets.
//! Three keep-alive clients (the s3-tests / boto pattern) still get a
//! prompt `100 Continue` on a PUT that reads the body.
//!
//! Current Peregrine: `workers=2` are blocking OS threads. Two idle
//! keep-alives occupy both workers; the continue PUT never reaches a
//! handler until `head_deadline`. This test encodes that Gate 5 gap and
//! MUST remain RED until L1 is fixed.
//!
//! Do not raise `worker_threads` to make this pass (hides L1).
//! `worker_starvation.rs` owns the GET form of the same 3-keep-alive /
//! 2-worker occupancy — do not change that test to pass.

#[path = "harness.rs"]
mod harness;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

#[test]
fn three_keepalive_clients_with_two_workers_expect_continue_is_not_starved() {
    // echo_materialize reads the body, which is what triggers the lazy 100
    // (Python `wsgi.input` first-read / Peregrine `maybe_send_continue`).
    let server = harness::spawn_server(2, Arc::new(harness::echo_materialize));
    let _idle_a = harness::get_keepalive(server.addr).expect("keepalive a");
    let _idle_b = harness::get_keepalive(server.addr).expect("keepalive b");
    thread::sleep(Duration::from_millis(80));

    let started = Instant::now();
    let mut client = TcpStream::connect_timeout(&server.addr, Duration::from_millis(400))
        .expect("third keep-alive client connects");
    client
        .set_read_timeout(Some(Duration::from_millis(400)))
        .unwrap();
    client
        .set_write_timeout(Some(Duration::from_millis(400)))
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

    let head = read_until_double_crlf(&mut client).expect(
        "100 Continue must arrive without waiting for an idle keep-alive deadline \
         (Python Eventlet would not pin 2 workers on 2 keep-alive clients)",
    );
    let elapsed = started.elapsed();
    let text = String::from_utf8_lossy(&head);
    assert!(
        text.starts_with("HTTP/1.1 100 Continue"),
        "Gate 5: third keep-alive Expect: 100-continue client saw {text:?} after {elapsed:?} (L1)"
    );
    assert!(
        elapsed < Duration::from_millis(400),
        "100 Continue took {elapsed:?}; idle keep-alive is occupying workers (L1)"
    );
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
            return Ok(buf);
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::UnexpectedEof,
        "connection closed before header terminator",
    ))
}
