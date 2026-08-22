//! AGENTS.md §29 idle density: attempt 10k, 50k and 100k keep-alives
//! at `worker_threads=2`. One climb to 100k; the OS ceiling is reported
//! for every larger target. A held keep-alive must get health=200.
//! HTTP 503 is not occupancy.

#[path = "harness.rs"]
mod harness;

use std::io::Write;
use std::net::TcpStream;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use swift_http::server::{serve_forever_with_config, ServerConfig};

fn probe_once(stream: &mut TcpStream) -> String {
    stream.set_read_timeout(Some(Duration::from_millis(400))).ok();
    stream.set_write_timeout(Some(Duration::from_millis(400))).ok();
    if stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\n\r\n")
        .is_err()
    {
        return "health_err=write".into();
    }
    match harness::read_http_response(stream) {
        Ok((200, _)) => "health=200".into(),
        Ok((status, _)) => format!("health={status}"),
        Err(e) => format!("health_err={e}"),
    }
}

fn occupancy_health(probe: &mut TcpStream, held: &mut [TcpStream]) -> String {
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut last = "health_err=untried".to_string();
    while Instant::now() < deadline {
        last = probe_once(probe);
        if last == "health=200" {
            return last;
        }
        for s in held.iter_mut().take(4) {
            let alt = probe_once(s);
            if alt == "health=200" {
                return alt;
            }
            last = alt;
        }
        thread::sleep(Duration::from_millis(15));
    }
    last
}

struct IdleOutcome {
    opened: usize,
    health: String,
    err: Option<String>,
}

fn try_idle(target: usize) -> IdleOutcome {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let shutdown = Arc::new(AtomicBool::new(false));
    let config = ServerConfig {
        worker_threads: 2,
        connection_queue: 1024,
        max_connections: target.saturating_add(64),
        max_active_requests: target.saturating_add(64),
        client_timeout_secs: 5,
        head_deadline_secs: 5,
        max_requests_per_connection: 1024,
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
    let mut probe = match harness::get_keepalive(server.addr) {
        Ok(p) => p,
        Err(e) => {
            return IdleOutcome {
                opened: 0,
                health: String::new(),
                err: Some(format!("could not open occupancy probe keep-alive: {e}")),
            };
        }
    };
    let mut held = Vec::new();
    let mut opened = 0usize;
    let cap = Instant::now() + Duration::from_secs(12);
    for i in 0..target {
        if Instant::now() >= cap {
            let health = occupancy_health(&mut probe, &mut held);
            return IdleOutcome {
                opened,
                health: health.clone(),
                err: Some(format!(
                    "time cap after {opened} sockets (i={i}) {health} worker_threads=2"
                )),
            };
        }
        match TcpStream::connect_timeout(&server.addr, Duration::from_millis(50)) {
            Ok(s) => {
                let _ = s.set_nodelay(true);
                held.push(s);
                opened += 1;
            }
            Err(e) => {
                let health = occupancy_health(&mut probe, &mut held);
                return IdleOutcome {
                    opened,
                    health: health.clone(),
                    err: Some(format!(
                        "stopped after {opened} sockets at i={i}: {e} kind={:?} {health} worker_threads=2",
                        e.kind()
                    )),
                };
            }
        }
        if opened > 0 && opened % 2000 == 0 {
            let health = occupancy_health(&mut probe, &mut held);
            if health != "health=200" {
                return IdleOutcome {
                    opened,
                    health: health.clone(),
                    err: Some(format!(
                        "health failed at {opened} idle sockets: {health} worker_threads=2"
                    )),
                };
            }
        }
    }
    let health = occupancy_health(&mut probe, &mut held);
    if health != "health=200" {
        return IdleOutcome {
            opened,
            health: health.clone(),
            err: Some(format!(
                "health must work with {opened} idle sockets, got {health} worker_threads=2"
            )),
        };
    }
    IdleOutcome {
        opened,
        health,
        err: None,
    }
}

#[test]
fn idle_density_10k_50k_100k_at_two_workers() {
    // One climb to 100k. Stacking 10k then 50k then 100k in-process
    // exhausts FDs and turns the occupancy probe into 503 theater.
    let out = try_idle(100_000);
    assert_eq!(
        out.health, "health=200",
        "held keep-alive must get health=200 at worker_threads=2 (503 is not occupancy): opened={} err={:?}",
        out.opened, out.err
    );
    assert!(
        out.opened > 0,
        "could not open even one idle socket: {:?}",
        out.err
    );
    for target in [10_000usize, 50_000, 100_000] {
        if out.err.is_none() && out.opened >= target {
            eprintln!(
                "idle-{target}: opened {} keep-alives at worker_threads=2 health=200",
                out.opened
            );
        } else {
            let detail = out.err.clone().unwrap_or_else(|| {
                format!(
                    "opened {} < {target} health={} worker_threads=2",
                    out.opened, out.health
                )
            });
            panic!(
                "ENVIRONMENT BLOCKED: idle-{target} opened={} (need {target}): {detail}",
                out.opened
            );
        }
    }
}
