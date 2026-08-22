//! AGENTS.md TEST LAB G3: architecture activation is proven by counters
//! on a real HTTP request, not by `/recon/concurrency` returning 200.

#[path = "harness.rs"]
mod harness;

use std::future::Future;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::pin::Pin;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use swift_http::server::{
    serve_forever_multi_service, serve_forever_with_config, AsyncRequest, AsyncService, Handler,
    ServerConfig,
};
use swift_http::{Request, Response};
use swift_runtime::ConcurrencyMetrics;

fn get_path(addr: std::net::SocketAddr, path: &str) -> (u16, String) {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(1)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
    let req = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes()).unwrap();
    s.flush().unwrap();
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    (status, text)
}

fn wait_bind(addr: std::net::SocketAddr) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(20)).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn spawn_legacy(metrics: ConcurrencyMetrics, handler: Handler) -> harness::Server {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let shutdown = Arc::new(AtomicBool::new(false));
    let config = ServerConfig {
        worker_threads: 2,
        connection_queue: 32,
        client_timeout_secs: 2,
        head_deadline_secs: 2,
        max_requests_per_connection: 32,
        shutdown: Some(Arc::clone(&shutdown)),
        metrics: Some(metrics),
        ..ServerConfig::default()
    };
    let flag = Arc::clone(&shutdown);
    let join = thread::spawn(move || serve_forever_with_config(listener, handler, config));
    wait_bind(addr);
    harness::Server {
        addr,
        shutdown: flag,
        join: Some(join),
    }
}

fn spawn_native(metrics: ConcurrencyMetrics, service: Arc<dyn AsyncService>) -> harness::Server {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let shutdown = Arc::new(AtomicBool::new(false));
    let config = ServerConfig {
        worker_threads: 2,
        connection_queue: 32,
        client_timeout_secs: 2,
        head_deadline_secs: 2,
        max_requests_per_connection: 32,
        shutdown: Some(Arc::clone(&shutdown)),
        metrics: Some(metrics),
        ..ServerConfig::default()
    };
    let flag = Arc::clone(&shutdown);
    let join = thread::spawn(move || serve_forever_multi_service(vec![listener], service, config));
    wait_bind(addr);
    harness::Server {
        addr,
        shutdown: flag,
        join: Some(join),
    }
}

struct NativeOk;

impl AsyncService for NativeOk {
    fn call(&self, _req: AsyncRequest) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        Box::pin(async { Response::with_body(200, "native") })
    }
}

#[test]
fn recon_200_alone_does_not_count_as_activation() {
    let metrics = ConcurrencyMetrics::new();
    let server = spawn_native(metrics.clone(), Arc::new(NativeOk));
    let (status, body) = get_path(server.addr, "/recon/concurrency");
    assert_eq!(status, 200, "{body}");
    assert!(
        body.contains("native_async_requests_total 0"),
        "recon must not increment native_async:\n{body}"
    );
    assert!(
        body.contains("http_requests_total{engine=\"hyper\"} 0"),
        "recon must not increment http_requests_total:\n{body}"
    );
    assert_eq!(metrics.snapshot().native_async_requests_total, 0);
    assert_eq!(metrics.snapshot().http_requests_total_hyper, 0);
}

#[test]
fn legacy_handler_path_increments_legacy_not_native() {
    let metrics = ConcurrencyMetrics::new();
    let handler: Handler = Arc::new(|_req: Request| Response::with_body(200, "legacy"));
    let server = spawn_legacy(metrics.clone(), handler);
    let (status, _) = get_path(server.addr, "/g3-legacy");
    assert_eq!(status, 200);
    let snap = metrics.snapshot();
    assert!(
        snap.http_requests_total_hyper >= 1,
        "hyper={}",
        snap.http_requests_total_hyper
    );
    assert!(
        snap.legacy_sync_handler_requests_total >= 1,
        "legacy={}",
        snap.legacy_sync_handler_requests_total
    );
    assert_eq!(
        snap.native_async_requests_total, 0,
        "legacy Handler must not count as native async"
    );
    let (status, body) = get_path(server.addr, "/recon/concurrency");
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("legacy_sync_handler_requests_total"));
    assert!(body.contains("native_async_requests_total 0") || body.contains("native_async_requests_total 0\n"));
}

#[test]
fn native_async_service_increments_native_not_legacy() {
    let metrics = ConcurrencyMetrics::new();
    let server = spawn_native(metrics.clone(), Arc::new(NativeOk));
    let (status, body) = get_path(server.addr, "/g3-native");
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("native"), "{body}");
    let snap = metrics.snapshot();
    assert!(
        snap.http_requests_total_hyper >= 1,
        "hyper={}",
        snap.http_requests_total_hyper
    );
    assert!(
        snap.native_async_requests_total >= 1,
        "native_async={}",
        snap.native_async_requests_total
    );
    assert_eq!(
        snap.legacy_sync_handler_requests_total, 0,
        "native AsyncService must not count as legacy"
    );
    assert_eq!(snap.block_in_place_total, 0);
    assert_eq!(snap.blocking_network_wait_total, 0);
    let (status, recon) = get_path(server.addr, "/recon/concurrency");
    assert_eq!(status, 200, "{recon}");
    assert!(
        recon.contains("native_async_requests_total 1")
            || recon.contains("native_async_requests_total 2"),
        "expected native_async >= 1 in recon:\n{recon}"
    );
}

#[test]
fn block_in_place_counter_is_observable() {
    let metrics = ConcurrencyMetrics::new();
    metrics.record_block_in_place();
    assert_eq!(metrics.snapshot().block_in_place_total, 1);
    let text = metrics.render();
    assert!(text.contains("block_in_place_total 1"), "{text}");
}
