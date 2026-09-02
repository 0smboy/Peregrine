//! Gate 3 / AGENTS.md §26.E: a real ObjectServer PUT whose finalize/fsync is
//! stalled on StorageExecutor must not pin Hyper HTTP workers on the same
//! listener. Health GET is the concurrent probe (it must not wait on that
//! storage thread).

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
use swift_http::ServerConfig;
use swift_object_server::{serve_with_config, ObjectServer, ObjectServerConfig};
use swift_runtime::{DeviceIoLimits, StorageExecutor, StorageExecutorConfig};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fsync_storm_does_not_starve_a_health_get() {
    let dir = std::env::temp_dir().join(format!("fsync-storm-{}-{}", std::process::id(), line!()));
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

    // One blocking storage worker: the stalled commit occupies it. Health
    // GET must still complete without that worker.
    let exec = StorageExecutor::new(
        StorageExecutorConfig::new(1, 8, DeviceIoLimits::new(8, 8, 8, 8, 8))
            .expect("storage config"),
    )
    .expect("storage executor");

    let server = ObjectServer::new(ObjectServerConfig {
        devices: dir.clone(),
        mount_check: false,
        hash_config: HashPathConfig::new(b"".to_vec(), b"fsync-storm".to_vec()).unwrap(),
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

    let (put_tx, put_rx) = mpsc::sync_channel::<(u16, String)>(1);
    thread::spawn(move || {
        let mut c = TcpStream::connect_timeout(&addr, Duration::from_millis(400)).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(8))).ok();
        c.set_write_timeout(Some(Duration::from_secs(2))).ok();
        let _ = c.write_all(
            b"PUT /sda1/0/AUTH_test/c/o HTTP/1.1\r\nHost: t\r\nX-Timestamp: 5000\r\nContent-Type: application/octet-stream\r\nContent-Length: 4\r\nConnection: close\r\n\r\nabcd",
        );
        let mut buf = Vec::new();
        let _ = c.read_to_end(&mut buf);
        let text = String::from_utf8_lossy(&buf).into_owned();
        let status = text
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let _ = put_tx.send((status, text));
    });

    let entered_deadline = Instant::now() + Duration::from_secs(3);
    while !entered.load(Ordering::SeqCst) && Instant::now() < entered_deadline {
        thread::sleep(Duration::from_millis(5));
    }
    assert!(
        entered.load(Ordering::SeqCst),
        "shipped PUT never entered StorageExecutor commit/fsync (finish_pending_put)"
    );
    assert!(
        put_rx.try_recv().is_err(),
        "PUT must still be in finalize; response arrived before the commit stall released"
    );

    let (status, elapsed) = harness::get_close_timed(addr, Duration::from_millis(400))
        .expect("health GET on the ObjectServer Hyper listener while PUT commit is parked");
    assert_ne!(status, 0, "health GET produced no HTTP status");
    assert!(
        elapsed < Duration::from_millis(400),
        "GET took {elapsed:?}; object PUT fsync occupied HTTP workers (Gate 3)"
    );

    release.store(true, Ordering::SeqCst);
    let (put_status, put_text) = put_rx
        .recv_timeout(Duration::from_secs(3))
        .expect("PUT should finish after commit stall releases");
    assert_eq!(
        put_status, 201,
        "stalled PUT must commit after release, got {put_status} {put_text}"
    );

    shutdown.store(true, Ordering::SeqCst);
    let _ = std::fs::remove_dir_all(&dir);
}
