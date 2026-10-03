//! Gate 1 (AGENTS.md §26.A / §35): idle keep-alive must not occupy a worker.
//!
//! Phase 0: this test encodes the *target* property and is expected **RED**
//! on the current sync server (`workers=2` + two idle keep-alives starve a
//! third request until `head_deadline`).

#[path = "harness.rs"]
mod harness;

use std::io::Write;
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use swift_http::server::{serve_forever_with_config, ServerConfig};
use swift_http::{Request, Response};

#[test]
fn idle_keepalive_does_not_starve_a_third_request() {
    let server = harness::spawn_server(2, Arc::new(harness::tiny_ok));
    let _idle_a = harness::get_keepalive(server.addr).expect("keepalive a");
    let _idle_b = harness::get_keepalive(server.addr).expect("keepalive b");
    thread::sleep(Duration::from_millis(80));

    let (status, elapsed) = harness::get_close_timed(server.addr, Duration::from_millis(400))
        .expect("third request must complete without waiting for an idle keep-alive deadline");
    assert_eq!(status, 200, "third request status");
    assert!(
        elapsed < Duration::from_millis(400),
        "third request took {elapsed:?}; idle keep-alive is occupying workers (L1)"
    );
}

#[test]
fn health_head_answers_while_workers_are_blocked() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let entered = Arc::new(AtomicUsize::new(0));
    let release = Arc::new(AtomicBool::new(false));
    let entered_h = Arc::clone(&entered);
    let release_h = Arc::clone(&release);
    let handler = Arc::new(move |req: Request| {
        if req.path == "/block" {
            entered_h.fetch_add(1, Ordering::SeqCst);
            while !release_h.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(20));
            }
        }
        Response::with_body(200, "ok")
    });
    let shutdown = Arc::new(AtomicBool::new(false));
    let config = ServerConfig {
        worker_threads: 2,
        max_connections: 32,
        max_active_requests: 32,
        client_timeout_secs: 5,
        head_deadline_secs: 5,
        shutdown: Some(Arc::clone(&shutdown)),
        dedicated_accept: true,
        ..ServerConfig::default()
    };
    let flag = Arc::clone(&shutdown);
    let join = thread::spawn(move || serve_forever_with_config(listener, handler, config));
    let ready = Instant::now() + Duration::from_secs(2);
    while Instant::now() < ready {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(20)).is_ok() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    for _ in 0..2 {
        let addr = addr;
        thread::spawn(move || {
            let mut sock = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(5))).ok();
            let _ = sock.write_all(b"GET /block HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n");
            let _ = sock.flush();
            let _ = harness::read_http_response(&mut sock);
        });
    }
    let wait = Instant::now() + Duration::from_secs(2);
    while entered.load(Ordering::SeqCst) < 2 && Instant::now() < wait {
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        entered.load(Ordering::SeqCst),
        2,
        "workers did not enter /block"
    );

    let started = Instant::now();
    let mut health = TcpStream::connect_timeout(&addr, Duration::from_millis(250)).unwrap();
    health
        .set_read_timeout(Some(Duration::from_millis(250)))
        .unwrap();
    health
        .set_write_timeout(Some(Duration::from_millis(250)))
        .unwrap();
    health
        .write_all(b"HEAD /healthcheck HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")
        .unwrap();
    let (status, _) = harness::read_http_response(&mut health).expect("health head");
    let elapsed = started.elapsed();
    release.store(true, Ordering::SeqCst);
    flag.store(true, Ordering::SeqCst);
    let _ = TcpStream::connect_timeout(&addr, Duration::from_millis(50));
    let _ = join.join();
    assert_eq!(status, 200);
    assert!(
        elapsed < Duration::from_millis(250),
        "HEAD /healthcheck took {elapsed:?} while workers were blocked"
    );
}
