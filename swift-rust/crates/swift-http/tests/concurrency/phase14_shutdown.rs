//! Phase 14: SIGTERM flag runs StopAccepting → close idle → stop admit →
//! cancel cancellable → wait durability barrier → deadline → force.

#[path = "harness.rs"]
mod harness;

use std::collections::HashMap;
use std::future::Future;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use swift_core::hashing::HashPathConfig;
use swift_diskfile::{DiskFileConfig, PolicyKind};
use swift_http::server::{
    serve_forever_multi_service, serve_forever_with_config, AsyncRequest, AsyncService, Handler,
    ServerConfig,
};
use swift_http::Response;
use swift_object_server::{serve_with_config, ObjectServer, ObjectServerConfig};
use swift_runtime::{
    CancelReason, ConcurrencyMetrics, DeadlineKind, DeviceIoLimits, StorageExecutor,
    StorageExecutorConfig,
};

fn spawn_metrics(metrics: ConcurrencyMetrics, handler: Handler) -> harness::Server {
    spawn_metrics_cfg(metrics, handler, |_| {})
}

fn spawn_metrics_cfg(
    metrics: ConcurrencyMetrics,
    handler: Handler,
    tweak: impl FnOnce(&mut ServerConfig),
) -> harness::Server {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let shutdown = Arc::new(AtomicBool::new(false));
    let mut config = ServerConfig {
        worker_threads: 2,
        connection_queue: 32,
        client_timeout_secs: 5,
        head_deadline_secs: 2,
        max_requests_per_connection: 32,
        shutdown: Some(Arc::clone(&shutdown)),
        metrics: Some(metrics),
        shutdown_deadline_secs: 5,
        ..ServerConfig::default()
    };
    tweak(&mut config);
    let flag = Arc::clone(&shutdown);
    let join = thread::spawn(move || serve_forever_with_config(listener, handler, config));
    wait_bind(addr);
    harness::Server {
        addr,
        shutdown: flag,
        join: Some(join),
    }
}

fn spawn_async_service(
    metrics: ConcurrencyMetrics,
    service: Arc<dyn AsyncService>,
    tweak: impl FnOnce(&mut ServerConfig),
) -> harness::Server {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let shutdown = Arc::new(AtomicBool::new(false));
    let mut config = ServerConfig {
        worker_threads: 2,
        connection_queue: 32,
        client_timeout_secs: 5,
        head_deadline_secs: 2,
        max_requests_per_connection: 32,
        shutdown: Some(Arc::clone(&shutdown)),
        metrics: Some(metrics),
        shutdown_deadline_secs: 5,
        ..ServerConfig::default()
    };
    tweak(&mut config);
    let flag = Arc::clone(&shutdown);
    let join = thread::spawn(move || serve_forever_multi_service(vec![listener], service, config));
    wait_bind(addr);
    harness::Server {
        addr,
        shutdown: flag,
        join: Some(join),
    }
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

struct YieldingPark {
    parked: Arc<AtomicBool>,
    finished: Arc<AtomicBool>,
}

impl AsyncService for YieldingPark {
    fn call(&self, _req: AsyncRequest) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        let parked = Arc::clone(&self.parked);
        let finished = Arc::clone(&self.finished);
        Box::pin(async move {
            parked.store(true, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_secs(30)).await;
            finished.store(true, Ordering::SeqCst);
            Response::with_body(200, "late")
        })
    }
}

fn shutdown_reason_count(metrics: &ConcurrencyMetrics) -> u64 {
    let snap = metrics.snapshot();
    snap.cancellations_total[CancelReason::Shutdown as usize]
}

#[test]
fn stop_accept_does_not_admit_a_new_request() {
    let metrics = ConcurrencyMetrics::new();
    let server = spawn_metrics(metrics.clone(), Arc::new(harness::tiny_ok));
    server.shutdown.store(true, Ordering::SeqCst);
    thread::sleep(Duration::from_millis(30));
    let result = harness::get_close_timed(server.addr, Duration::from_millis(400));
    match result {
        Ok((status, _)) => {
            assert!(
                status == 503 || status == 0,
                "after stop-accept, new work must not be a normal admitted 200, got {status}"
            );
        }
        Err(_) => {}
    }
}

#[test]
fn idle_keepalive_is_closed_on_shutdown() {
    let metrics = ConcurrencyMetrics::new();
    let server = spawn_metrics(metrics.clone(), Arc::new(harness::tiny_ok));
    let mut ka = harness::get_keepalive(server.addr).expect("keepalive");
    ka.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    server.shutdown.store(true, Ordering::SeqCst);
    let mut buf = [0u8; 8];
    let n = ka.read(&mut buf);
    assert!(
        matches!(n, Ok(0) | Err(_)),
        "idle keep-alive must close on shutdown, read={n:?}"
    );
}

#[test]
fn cancellable_inflight_is_cancelled_when_not_in_commit_shield() {
    let metrics = ConcurrencyMetrics::new();
    let parked = Arc::new(AtomicBool::new(false));
    let finished = Arc::new(AtomicBool::new(false));
    let service = Arc::new(YieldingPark {
        parked: Arc::clone(&parked),
        finished: Arc::clone(&finished),
    });
    let server = spawn_async_service(metrics.clone(), service, |_| {});
    let addr = server.addr;
    let (tx, rx) = mpsc::sync_channel::<(u16, Duration)>(1);
    let started = Instant::now();
    thread::spawn(move || {
        let result = harness::get_close_timed(addr, Duration::from_secs(2));
        let (status, elapsed) = result.unwrap_or((0, started.elapsed()));
        let _ = tx.send((status, elapsed));
    });
    let deadline = Instant::now() + Duration::from_secs(2);
    while !parked.load(Ordering::SeqCst) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    assert!(
        parked.load(Ordering::SeqCst),
        "yielding handler never started"
    );
    let before = Instant::now();
    server.shutdown.store(true, Ordering::SeqCst);
    let (status, _) = rx
        .recv_timeout(Duration::from_secs(2))
        .unwrap_or((0, Duration::ZERO));
    let after = before.elapsed();
    assert!(
        !finished.load(Ordering::SeqCst),
        "30s sleep must not complete; shutdown must cancel the async request"
    );
    assert_ne!(
        status, 200,
        "cancellable request must not return 200 after shutdown, got {status}"
    );
    assert!(
        after < Duration::from_secs(5),
        "cancel must not wait out the handler sleep, took {after:?}"
    );
    let cancelled = shutdown_reason_count(&metrics);
    assert!(
        cancelled >= 1,
        "cancellations_total{{reason=shutdown}} must increment on the shipped path, got {cancelled} status={status}"
    );
}

fn object_fixture(dir: &std::path::Path, stall: Arc<dyn Fn() + Send + Sync>) -> ObjectServer {
    let exec = StorageExecutor::new(
        StorageExecutorConfig::new(1, 8, DeviceIoLimits::new(8, 8, 8, 8, 8)).unwrap(),
    )
    .unwrap();
    ObjectServer::new(ObjectServerConfig {
        devices: dir.to_path_buf(),
        mount_check: false,
        hash_config: HashPathConfig::new(b"".to_vec(), b"phase14".to_vec()).unwrap(),
        diskfile: DiskFileConfig::default(),
        policies: HashMap::from([(0, PolicyKind::Replication)]),
        container_update_timeout: Duration::from_millis(50),
        container_update_mode: swift_object_server::ContainerUpdateMode::Async,
    })
    .with_storage(exec)
    .with_commit_stall(stall)
}

fn put_object(addr: std::net::SocketAddr, timeout: Duration) -> u16 {
    let mut c = match TcpStream::connect_timeout(&addr, Duration::from_millis(400)) {
        Ok(c) => c,
        Err(_) => return 0,
    };
    c.set_read_timeout(Some(timeout)).ok();
    let _ = c.write_all(
        b"PUT /sda1/0/AUTH_test/c/o HTTP/1.1\r\nHost: t\r\nX-Timestamp: 5000\r\nContent-Type: application/octet-stream\r\nContent-Length: 4\r\nConnection: close\r\n\r\nabcd",
    );
    let mut buf = Vec::new();
    let _ = c.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf);
    text.split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

fn any_data_file(root: &std::path::Path) -> bool {
    fn walk(p: &std::path::Path) -> bool {
        let Ok(rd) = std::fs::read_dir(p) else {
            return false;
        };
        for e in rd.flatten() {
            let path = e.path();
            if path.is_dir() && walk(&path) {
                return true;
            }
            let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if name.contains(".data") {
                return true;
            }
        }
        false
    }
    walk(root)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn commit_shield_survives_shutdown_and_gauges_are_readable() {
    let dir = std::env::temp_dir().join(format!(
        "phase14-shutdown-{}-{}",
        std::process::id(),
        line!()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("sda1")).unwrap();
    let entered = Arc::new(AtomicBool::new(false));
    let release = Arc::new(AtomicBool::new(false));
    let stall = {
        let entered = Arc::clone(&entered);
        let release = Arc::clone(&release);
        Arc::new(move || {
            entered.store(true, Ordering::SeqCst);
            while !release.load(Ordering::SeqCst) {
                thread::park_timeout(Duration::from_millis(5));
            }
        }) as Arc<dyn Fn() + Send + Sync>
    };
    let metrics = ConcurrencyMetrics::new();
    let server = object_fixture(&dir, stall);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let shutdown = Arc::new(AtomicBool::new(false));
    let cfg = ServerConfig {
        worker_threads: 2,
        shutdown: Some(Arc::clone(&shutdown)),
        metrics: Some(metrics.clone()),
        shutdown_deadline_secs: 5,
        ..ServerConfig::default()
    };
    thread::spawn(move || serve_with_config(listener, server, cfg));
    wait_bind(addr);

    let (put_tx, put_rx) = mpsc::sync_channel::<u16>(1);
    thread::spawn(move || {
        let _ = put_tx.send(put_object(addr, Duration::from_secs(8)));
    });

    let entered_deadline = Instant::now() + Duration::from_secs(3);
    while !entered.load(Ordering::SeqCst) && Instant::now() < entered_deadline {
        thread::sleep(Duration::from_millis(5));
    }
    assert!(entered.load(Ordering::SeqCst));
    assert!(metrics.snapshot().commit_shield_active >= 1);
    shutdown.store(true, Ordering::SeqCst);
    let wait_deadline = Instant::now() + Duration::from_secs(1);
    let mut saw_waiting = false;
    while Instant::now() < wait_deadline {
        let snap = metrics.snapshot();
        if snap.shutdown_waiting_commits >= 1 || snap.commit_shield_active >= 1 {
            saw_waiting = true;
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    assert!(
        saw_waiting,
        "shutdown_waiting_commits / commit_shield_active must be readable while waiting"
    );
    release.store(true, Ordering::SeqCst);
    let put_status = put_rx.recv_timeout(Duration::from_secs(3)).unwrap_or(0);
    assert_eq!(
        put_status, 201,
        "durability barrier PUT must finish commit after shutdown, got {put_status}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_deadline_forces_http_without_ambiguous_commit() {
    let dir =
        std::env::temp_dir().join(format!("phase14-force-{}-{}", std::process::id(), line!()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("sda1")).unwrap();
    let entered = Arc::new(AtomicBool::new(false));
    let release = Arc::new(AtomicBool::new(false));
    let stall = {
        let entered = Arc::clone(&entered);
        let release = Arc::clone(&release);
        Arc::new(move || {
            entered.store(true, Ordering::SeqCst);
            while !release.load(Ordering::SeqCst) {
                thread::park_timeout(Duration::from_millis(5));
            }
        }) as Arc<dyn Fn() + Send + Sync>
    };
    let metrics = ConcurrencyMetrics::new();
    let server = object_fixture(&dir, stall);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let shutdown = Arc::new(AtomicBool::new(false));
    let cfg = ServerConfig {
        worker_threads: 2,
        shutdown: Some(Arc::clone(&shutdown)),
        metrics: Some(metrics.clone()),
        shutdown_deadline_secs: 1,
        client_timeout_secs: 10,
        head_deadline_secs: 10,
        ..ServerConfig::default()
    };
    thread::spawn(move || serve_with_config(listener, server, cfg));
    wait_bind(addr);

    let (put_tx, put_rx) = mpsc::sync_channel::<u16>(1);
    thread::spawn(move || {
        // Client read timeout is >> ShutdownDeadline (10s vs 1s). A no-op
        // force would sit until this timeout (~10s), not ~1s.
        let _ = put_tx.send(put_object(addr, Duration::from_secs(10)));
    });

    let entered_deadline = Instant::now() + Duration::from_secs(3);
    while !entered.load(Ordering::SeqCst) && Instant::now() < entered_deadline {
        thread::sleep(Duration::from_millis(5));
    }
    assert!(
        entered.load(Ordering::SeqCst),
        "PUT never entered commit stall"
    );
    shutdown.store(true, Ordering::SeqCst);
    let forced_at = Instant::now();
    let put_status = put_rx.recv_timeout(Duration::from_secs(12)).unwrap_or(0);
    let forced_after = forced_at.elapsed();
    assert_ne!(
        put_status, 201,
        "HTTP must be forced off at shutdown deadline while commit is still stalled"
    );
    assert!(
        forced_after < Duration::from_millis(1500),
        "force must fire on ShutdownDeadline (1s), not client timeout (10s); took {forced_after:?}"
    );
    let shutdown_idx = DeadlineKind::ALL
        .iter()
        .position(|k| *k == DeadlineKind::Shutdown)
        .expect("DeadlineKind::Shutdown");
    let snap = metrics.snapshot();
    assert!(
        snap.timeouts_total[shutdown_idx] >= 1,
        "timeouts_total{{phase=shutdown}} must increment on the shipped Hyper force path, snap timeouts={:?}",
        snap.timeouts_total
    );
    assert!(
        snap.commit_shield_active >= 1,
        "commit-shield must still be running after HTTP force, active={}",
        snap.commit_shield_active
    );
    assert!(
        snap.render().contains("timeouts_total{phase=\"shutdown\"}"),
        "serialized snapshot must name the shutdown phase"
    );
    release.store(true, Ordering::SeqCst);
    let drain = Instant::now() + Duration::from_secs(3);
    while metrics.snapshot().commit_shield_active != 0 && Instant::now() < drain {
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        metrics.snapshot().commit_shield_active,
        0,
        "shielded commit must finish after stall release; durability must not be ambiguous"
    );
    assert!(
        any_data_file(&dir),
        "object must exist on disk after shielded commit (HTTP was forced, commit was not aborted)"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
