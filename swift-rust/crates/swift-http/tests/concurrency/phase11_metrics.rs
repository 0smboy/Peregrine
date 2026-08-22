//! Phase 11: shipped ConcurrencyMetrics snapshot moves under real load.
//! Reads the same registry the Hyper accept loop attaches — not a stub.

#[path = "harness.rs"]
mod harness;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use swift_core::hashing::HashPathConfig;
use swift_diskfile::{DiskFileConfig, PolicyKind};
use swift_http::server::{serve_forever_with_config, Handler, IncomingBody, ServerConfig};
use swift_http::{Request, Response};
use swift_object_server::{serve_with_config, ObjectServer, ObjectServerConfig};
use swift_runtime::{
    text_has_forbidden_labels, ConcurrencyMetrics, DeviceIoLimits, StorageExecutor,
    StorageExecutorConfig, REQUIRED_METRIC_NAMES,
};

fn spawn_with_metrics(
    metrics: ConcurrencyMetrics,
    worker_threads: usize,
    handler: Handler,
    tweak: impl FnOnce(&mut ServerConfig),
) -> harness::Server {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let shutdown = Arc::new(AtomicBool::new(false));
    let mut config = ServerConfig {
        worker_threads,
        connection_queue: 32,
        client_timeout_secs: 2,
        head_deadline_secs: 2,
        max_requests_per_connection: 32,
        shutdown: Some(Arc::clone(&shutdown)),
        metrics: Some(metrics),
        ..ServerConfig::default()
    };
    tweak(&mut config);
    let flag = Arc::clone(&shutdown);
    let join = thread::spawn(move || serve_forever_with_config(listener, handler, config));
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(20)).is_ok() {
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    harness::Server {
        addr,
        shutdown: flag,
        join: Some(join),
    }
}

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

#[test]
fn snapshot_moves_on_admitted_request_and_recon_endpoint() {
    let metrics = ConcurrencyMetrics::new();
    let parked = Arc::new(AtomicBool::new(false));
    let release = Arc::new(AtomicBool::new(false));
    let handler: Handler = {
        let parked = Arc::clone(&parked);
        let release = Arc::clone(&release);
        Arc::new(move |_req: Request| {
            parked.store(true, Ordering::SeqCst);
            while !release.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(5));
            }
            Response::with_body(200, "ok")
        })
    };
    let server = spawn_with_metrics(metrics.clone(), 2, handler, |_| {});

    let addr = server.addr;
    let join = thread::spawn(move || get_path(addr, "/held"));
    let deadline = Instant::now() + Duration::from_secs(2);
    while !parked.load(Ordering::SeqCst) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    assert!(parked.load(Ordering::SeqCst), "handler never ran");
    let snap = metrics.snapshot();
    assert!(
        snap.connections_open >= 1,
        "connections_open={}",
        snap.connections_open
    );
    assert!(
        snap.requests_active >= 1,
        "requests_active={}",
        snap.requests_active
    );
    assert!(snap.runtime_tasks >= 1, "runtime_tasks={}", snap.runtime_tasks);
    assert!(snap.process_threads >= 1);
    assert!(snap.open_fds >= 1);
    release.store(true, Ordering::SeqCst);
    let (status, _) = join.join().unwrap();
    assert_eq!(status, 200);

    let ka = harness::get_keepalive(server.addr).expect("keepalive");
    let snap = metrics.snapshot();
    assert!(
        snap.connections_open >= 1,
        "keepalive connections_open={}",
        snap.connections_open
    );
    assert!(
        snap.connections_idle >= 1,
        "keepalive connections_idle={}",
        snap.connections_idle
    );
    drop(ka);

    let (status, body) = get_path(server.addr, "/recon/concurrency");
    assert_eq!(status, 200, "{body}");
    for name in REQUIRED_METRIC_NAMES {
        assert!(body.contains(name), "recon missing {name}\n{body}");
    }
    assert!(
        !text_has_forbidden_labels(&body),
        "forbidden labels in recon body"
    );
    assert!(body.contains("timeouts_total{phase=\"body_idle\"}"));
    assert!(body.contains("cancellations_total{reason=\"timeout\"}"));
}

#[test]
fn admission_reject_increments_snapshot() {
    let metrics = ConcurrencyMetrics::new();
    let server = spawn_with_metrics(metrics.clone(), 2, Arc::new(harness::tiny_ok), |c| {
        c.max_connections = 1;
        c.max_active_requests = 8;
        c.connection_queue = 1;
    });
    let _hold = harness::get_keepalive(server.addr).expect("hold the only connection");
    let mut probe = TcpStream::connect_timeout(&server.addr, Duration::from_secs(1)).unwrap();
    probe.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    probe
        .write_all(b"GET /health HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut buf = Vec::new();
    let _ = probe.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf);
    assert!(
        text.contains("503") || metrics.snapshot().admission_rejected_total >= 1,
        "expected 503 or rejected counter, got {text:?} snap={:?}",
        metrics.snapshot().admission_rejected_total
    );
    assert!(
        metrics.snapshot().admission_rejected_total >= 1,
        "admission_rejected_total stayed 0"
    );
}

#[test]
fn body_idle_timeout_increments_labeled_counter() {
    let metrics = ConcurrencyMetrics::new();
    let server = spawn_with_metrics(
        metrics.clone(),
        2,
        Arc::new(harness::echo_materialize),
        |c| {
            c.body_idle_timeout_secs = 1;
            c.max_upload_time_secs = 30;
            c.client_timeout_secs = 30;
        },
    );
    let mut client = TcpStream::connect_timeout(&server.addr, Duration::from_secs(1)).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    client
        .write_all(
            b"PUT /o HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 8\r\nConnection: close\r\n\r\nab",
        )
        .unwrap();
    let mut buf = Vec::new();
    let _ = client.read_to_end(&mut buf);
    let snap = metrics.snapshot();
    let text = snap.render();
    assert!(
        text.contains("timeouts_total{phase=\"body_idle\"}")
            && snap.timeouts_total.iter().any(|n| *n >= 1),
        "body idle timeout did not increment timeouts_total: {text}"
    );
    assert!(
        text.contains("cancellations_total{reason=\"timeout\"}"),
        "{text}"
    );
    assert!(!text_has_forbidden_labels(&text));
}

#[tokio::test]
async fn incoming_body_buffer_bytes_move_on_from_bytes() {
    let metrics = ConcurrencyMetrics::new();
    metrics
        .bind(async {
            let body = IncomingBody::from_bytes(vec![0u8; 4096], 1 << 20);
            assert!(
                metrics.snapshot().request_body_buffer_bytes >= 4096,
                "{}",
                metrics.snapshot().request_body_buffer_bytes
            );
            drop(body);
            assert_eq!(metrics.snapshot().request_body_buffer_bytes, 0);
        })
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn commit_shield_and_device_gauges_during_put_finalize() {
    let dir = std::env::temp_dir().join(format!(
        "phase11-metrics-{}-{}",
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

    let exec = StorageExecutor::new(
        StorageExecutorConfig::new(1, 8, DeviceIoLimits::new(8, 8, 8, 8, 8))
            .expect("storage config"),
    )
    .expect("storage executor");
    let metrics = ConcurrencyMetrics::new();
    let server = ObjectServer::new(ObjectServerConfig {
        devices: dir.clone(),
        mount_check: false,
        hash_config: HashPathConfig::new(b"".to_vec(), b"phase11-metrics".to_vec()).unwrap(),
        diskfile: DiskFileConfig::default(),
        policies: HashMap::from([(0, PolicyKind::Replication)]),
        container_update_timeout: Duration::from_millis(50),
        container_update_mode: swift_object_server::ContainerUpdateMode::Async,
    })
    .with_storage(exec)
    .with_commit_stall(stall);

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let shutdown = Arc::new(AtomicBool::new(false));
    let cfg = ServerConfig {
        worker_threads: 2,
        shutdown: Some(Arc::clone(&shutdown)),
        metrics: Some(metrics.clone()),
        ..ServerConfig::default()
    };
    thread::spawn(move || serve_with_config(listener, server, cfg));
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(20)).is_ok() {
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }

    let (put_tx, put_rx) = mpsc::sync_channel::<u16>(1);
    thread::spawn(move || {
        let mut c = TcpStream::connect_timeout(&addr, Duration::from_millis(400)).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(8))).ok();
        let _ = c.write_all(
            b"PUT /sda1/0/AUTH_test/c/o HTTP/1.1\r\nHost: t\r\nX-Timestamp: 5000\r\nContent-Type: application/octet-stream\r\nContent-Length: 4\r\nConnection: close\r\n\r\nabcd",
        );
        let mut buf = Vec::new();
        let _ = c.read_to_end(&mut buf);
        let text = String::from_utf8_lossy(&buf);
        let status = text
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let _ = put_tx.send(status);
    });

    let entered_deadline = Instant::now() + Duration::from_secs(3);
    while !entered.load(Ordering::SeqCst) && Instant::now() < entered_deadline {
        thread::sleep(Duration::from_millis(5));
    }
    assert!(entered.load(Ordering::SeqCst), "PUT never reached commit stall");
    let snap = metrics.snapshot();
    assert!(
        snap.commit_shield_active >= 1,
        "commit_shield_active={}",
        snap.commit_shield_active
    );
    assert!(
        snap.device_ops_active >= 1,
        "device_ops_active={}",
        snap.device_ops_active
    );
    let text = snap.render();
    assert!(!text_has_forbidden_labels(&text));

    release.store(true, Ordering::SeqCst);
    let put_status = put_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    assert_eq!(put_status, 201);
    let idle = Instant::now() + Duration::from_secs(2);
    while Instant::now() < idle {
        if metrics.snapshot().commit_shield_active == 0
            && metrics.snapshot().device_ops_active == 0
        {
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(metrics.snapshot().commit_shield_active, 0);
    assert_eq!(metrics.snapshot().device_ops_active, 0);
    shutdown.store(true, Ordering::SeqCst);
    let _ = std::fs::remove_dir_all(&dir);
}
