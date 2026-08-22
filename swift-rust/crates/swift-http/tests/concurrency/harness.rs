//! Shared Phase 0 concurrency-gate helpers. Not a standalone test.
#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use swift_http::server::{serve_forever_with_config, Handler, ServerConfig};
use swift_http::{Request, Response};

pub struct Server {
    pub addr: std::net::SocketAddr,
    pub shutdown: Arc<AtomicBool>,
    pub join: Option<thread::JoinHandle<std::io::Result<()>>>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Ok(poke) = TcpStream::connect_timeout(&self.addr, Duration::from_millis(50)) {
            let _ = poke.shutdown(Shutdown::Both);
        }
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

pub fn tiny_ok(_: Request) -> Response {
    Response::with_body(200, "ok")
}

pub fn echo_materialize(mut request: Request) -> Response {
    match request.body.materialize(u64::MAX) {
        Ok(_) => {
            let bytes = request.body.into_vec(u64::MAX).unwrap_or_default();
            Response::with_body(200, bytes)
        }
        Err(_) => Response::error(500, "body"),
    }
}

pub fn big_body(_: Request) -> Response {
    Response::with_body(200, vec![b'x'; 256 * 1024])
}

pub fn spawn_server(worker_threads: usize, handler: Handler) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let shutdown = Arc::new(AtomicBool::new(false));
    let config = ServerConfig {
        worker_threads,
        connection_queue: 32,
        client_timeout_secs: 2,
        head_deadline_secs: 2,
        max_requests_per_connection: 32,
        shutdown: Some(Arc::clone(&shutdown)),
        ..ServerConfig::default()
    };
    let flag = Arc::clone(&shutdown);
    let join = thread::spawn(move || serve_forever_with_config(listener, handler, config));
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(20)).is_ok() {
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    Server {
        addr,
        shutdown: flag,
        join: Some(join),
    }
}

pub fn get_keepalive(addr: std::net::SocketAddr) -> std::io::Result<TcpStream> {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(1))?;
    s.set_read_timeout(Some(Duration::from_secs(2)))?;
    s.set_write_timeout(Some(Duration::from_secs(2)))?;
    s.write_all(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\n\r\n")?;
    s.flush()?;
    read_http_response(&mut s)?;
    Ok(s)
}

pub fn get_close_timed(
    addr: std::net::SocketAddr,
    timeout: Duration,
) -> std::io::Result<(u16, Duration)> {
    let started = Instant::now();
    let mut s = TcpStream::connect_timeout(&addr, timeout)?;
    s.set_read_timeout(Some(timeout))?;
    s.set_write_timeout(Some(timeout))?;
    s.write_all(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")?;
    s.flush()?;
    let (status, _) = read_http_response(&mut s)?;
    Ok((status, started.elapsed()))
}

pub fn read_http_response(stream: &mut TcpStream) -> std::io::Result<(u16, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let status = parse_status(&buf[..pos]).unwrap_or(0);
            if let Some(need) = content_length(&buf[..pos]) {
                while buf.len() < pos + 4 + need {
                    let n = stream.read(&mut tmp)?;
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                }
            }
            return Ok((status, buf));
        }
    }
    let status = parse_status(&buf).unwrap_or(0);
    Ok((status, buf))
}

fn parse_status(head: &[u8]) -> Option<u16> {
    let line = std::str::from_utf8(head).ok()?.lines().next()?;
    line.split_whitespace().nth(1)?.parse().ok()
}

fn content_length(head: &[u8]) -> Option<usize> {
    let text = std::str::from_utf8(head).ok()?;
    for line in text.lines() {
        if let Some(rest) = line
            .split_once(':')
            .filter(|(k, _)| k.eq_ignore_ascii_case("content-length"))
            .map(|(_, v)| v)
        {
            return rest.trim().parse().ok();
        }
    }
    None
}
