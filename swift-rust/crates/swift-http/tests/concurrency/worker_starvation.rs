//! Gate 1 (AGENTS.md §26.A / §35): idle keep-alive must not occupy a worker.
//!
//! Phase 0: this test encodes the *target* property and is expected **RED**
//! on the current sync server (`workers=2` + two idle keep-alives starve a
//! third request until `head_deadline`).

#[path = "harness.rs"]
mod harness;

use std::io::{Read, Write};
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

fn scheduler_lag_ns(text: &str) -> Option<u64> {
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("runtime_scheduler_lag ") {
            return value.trim().parse().ok();
        }
    }
    None
}

/// Handlers that run for a long time must not make the accept-to-worker
/// handoff itself wait. Lag is recorded when a body worker dequeues the
/// socket, before the handler runs.
#[test]
fn accept_handoff_lag_stays_under_bound_while_handlers_run() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handler = Arc::new(|req: Request| {
        if req.path == "/spin" {
            let start = Instant::now();
            while start.elapsed() < Duration::from_millis(180) {
                std::thread::yield_now();
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
    let paths = ["/spin", "/spin", "/recon/concurrency"];
    let mut threads = Vec::new();
    for path in paths {
        let addr = addr;
        threads.push(thread::spawn(move || {
            let mut sock = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(3))).ok();
            let req = format!("GET {path} HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n");
            sock.write_all(req.as_bytes()).unwrap();
            harness::read_http_response(&mut sock).expect("response")
        }));
    }
    let mut recon = None;
    for thread in threads {
        let (status, body) = thread.join().unwrap();
        assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
        let text = String::from_utf8_lossy(&body);
        if scheduler_lag_ns(&text).is_some() {
            recon = Some(text.into_owned());
        }
    }
    flag.store(true, Ordering::SeqCst);
    let _ = TcpStream::connect_timeout(&addr, Duration::from_millis(50));
    let _ = join.join();
    let body = recon.expect("recon response");
    let lag_ns = scheduler_lag_ns(&body).unwrap();
    assert!(
        lag_ns < 100_000_000,
        "accept handoff lag {lag_ns} ns exceeded 100 ms\n{body}"
    );
}

/// A short Hyper header timer must not close the socket while a slow
/// client is still reading a response body.
#[test]
fn slow_reader_receives_the_full_body() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    // Larger than a shrunk receive window, so the write is still in
    // progress across the pause.
    let payload = vec![b'B'; 2 * 1024 * 1024];
    let payload_h = payload.clone();
    let handler = Arc::new(move |_req: Request| Response::with_body(200, payload_h.clone()));
    let shutdown = Arc::new(AtomicBool::new(false));
    let config = ServerConfig {
        worker_threads: 2,
        max_connections: 8,
        max_active_requests: 8,
        client_timeout_secs: 5,
        head_deadline_secs: 5,
        shutdown: Some(Arc::clone(&shutdown)),
        dedicated_accept: true,
        header_read_timeout: Some(Duration::from_millis(200)),
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
    let mut sock = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).unwrap();
    shrink_recv_buf(&sock);
    sock.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    sock.write_all(b"GET /obj HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut buf = Vec::new();
    let mut tmp = [0u8; 256];
    let n = sock.read(&mut tmp).expect("first bytes");
    assert!(n > 0, "response did not start");
    buf.extend_from_slice(&tmp[..n]);
    // Longer than Hyper's default 30s header timer. The client has not
    // finished the body, so that timer must not close the socket.
    thread::sleep(Duration::from_secs(32));
    let drain_deadline = Instant::now() + Duration::from_secs(15);
    let mut tmp = [0u8; 8192];
    while Instant::now() < drain_deadline {
        match sock.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => break,
            Err(error) => panic!("slow reader failed after the header timer: {error}"),
        }
    }
    flag.store(true, Ordering::SeqCst);
    let _ = TcpStream::connect_timeout(&addr, Duration::from_millis(50));
    let _ = join.join();
    let marker = buf.windows(4).position(|w| w == b"\r\n\r\n").expect("headers");
    let body = &buf[marker + 4..];
    assert_eq!(
        body.len(),
        payload.len(),
        "slow reader got {} of {} body bytes",
        body.len(),
        payload.len()
    );
    assert!(body.iter().all(|b| *b == b'B'));
}

fn shrink_recv_buf(sock: &TcpStream) {
    use std::os::fd::AsRawFd;
    let small: libc::c_int = 1024;
    unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &small as *const libc::c_int as *const libc::c_void,
            std::mem::size_of_val(&small) as libc::socklen_t,
        );
    }
}
