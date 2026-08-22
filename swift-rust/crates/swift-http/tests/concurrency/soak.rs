//! AGENTS.md §29 mixed-workload soak on the shipped Hyper object-server path.
//!
//! The soak **program** is 24h (`SOAK_PROGRAM_SECS`). Override with
//! `PEREGRINE_SOAK_SECS` for a session run of the **same** driver (same
//! injections, same leak/durability assertions). Do not substitute a toy soak.

#[path = "harness.rs"]
mod harness;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use swift_core::hashing::HashPathConfig;
use swift_diskfile::{DiskFileConfig, PolicyKind};
use swift_http::ServerConfig;
use swift_object_server::{serve_with_config, ObjectServer, ObjectServerConfig};
use swift_runtime::{
    ConcurrencyMetrics, DeviceIoLimits, StorageExecutor, StorageExecutorConfig,
};

/// AGENTS.md §29 soak program length.
const SOAK_PROGRAM_SECS: u64 = 24 * 60 * 60;

fn claiming_g8() -> bool {
    matches!(
        std::env::var("PEREGRINE_CLAIM_G8").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

fn soak_secs() -> u64 {
    if claiming_g8() {
        let secs = std::env::var("PEREGRINE_SOAK_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(SOAK_PROGRAM_SECS);
        if secs < SOAK_PROGRAM_SECS {
            panic!(
                "ENVIRONMENT BLOCKED: G8 soak requires {SOAK_PROGRAM_SECS}s, got {secs} (unset PEREGRINE_CLAIM_G8 for developer soak)"
            );
        }
        return SOAK_PROGRAM_SECS;
    }
    std::env::var("PEREGRINE_SOAK_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(30)
}

fn object_server(
    dir: &std::path::Path,
    stall: Arc<dyn Fn() + Send + Sync>,
) -> ObjectServer {
    let exec = StorageExecutor::new(
        StorageExecutorConfig::new(1, 8, DeviceIoLimits::new(8, 8, 8, 8, 8)).unwrap(),
    )
    .unwrap();
    ObjectServer::new(ObjectServerConfig {
        devices: dir.to_path_buf(),
        mount_check: false,
        hash_config: HashPathConfig::new(b"".to_vec(), b"soak".to_vec()).unwrap(),
        diskfile: DiskFileConfig::default(),
        policies: HashMap::from([(0, PolicyKind::Replication)]),
        container_update_timeout: Duration::from_millis(50),
        container_update_mode: swift_object_server::ContainerUpdateMode::Async,
    })
    .with_storage(exec)
    .with_commit_stall(stall)
}

fn spawn_object(
    dir: &std::path::Path,
    stall: Arc<dyn Fn() + Send + Sync>,
    metrics: ConcurrencyMetrics,
    shutdown: Arc<AtomicBool>,
) -> (std::net::SocketAddr, thread::JoinHandle<std::io::Result<()>>) {
    let server = object_server(dir, stall);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let cfg = ServerConfig {
        worker_threads: 2,
        shutdown: Some(Arc::clone(&shutdown)),
        metrics: Some(metrics),
        client_timeout_secs: 5,
        head_deadline_secs: 5,
        ..ServerConfig::default()
    };
    let join = thread::spawn(move || serve_with_config(listener, server, cfg));
    wait_bind(addr);
    (addr, join)
}

fn wait_bind(addr: std::net::SocketAddr) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(20)).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(5));
    }
    panic!("object server did not bind {addr}");
}

fn transact(addr: std::net::SocketAddr, bytes: &[u8], timeout: Duration) -> (u16, String) {
    let mut c = match TcpStream::connect_timeout(&addr, Duration::from_millis(400)) {
        Ok(c) => c,
        Err(e) => return (0, e.to_string()),
    };
    c.set_read_timeout(Some(timeout)).ok();
    c.set_write_timeout(Some(timeout)).ok();
    let _ = c.write_all(bytes);
    let _ = c.flush();
    let mut buf = Vec::new();
    let _ = c.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    (status, text)
}

fn put(addr: std::net::SocketAddr, name: &str, ts: u64, body: &[u8]) -> u16 {
    let mut req = format!(
        "PUT /sda1/0/AUTH_test/c/{name} HTTP/1.1\r\nHost: t\r\nX-Timestamp: {ts}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    req.extend_from_slice(body);
    transact(addr, &req, Duration::from_secs(8)).0
}

fn get_obj(addr: std::net::SocketAddr, name: &str) -> u16 {
    let req = format!(
        "GET /sda1/0/AUTH_test/c/{name} HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n"
    );
    transact(addr, req.as_bytes(), Duration::from_secs(4)).0
}

fn recon(addr: std::net::SocketAddr) -> String {
    transact(
        addr,
        b"GET /recon/concurrency HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n",
        Duration::from_secs(2),
    )
    .1
}

fn sample_rss_kb() -> Option<u64> {
    let pid = std::process::id();
    let out = Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout).trim().parse().ok()
}

fn slow_put(addr: std::net::SocketAddr, name: &str, ts: u64) -> u16 {
    let mut c = match TcpStream::connect_timeout(&addr, Duration::from_millis(400)) {
        Ok(c) => c,
        Err(_) => return 0,
    };
    c.set_read_timeout(Some(Duration::from_secs(8))).ok();
    c.set_write_timeout(Some(Duration::from_secs(8))).ok();
    let head = format!(
        "PUT /sda1/0/AUTH_test/c/{name} HTTP/1.1\r\nHost: t\r\nX-Timestamp: {ts}\r\nContent-Type: application/octet-stream\r\nContent-Length: 8\r\nConnection: close\r\n\r\n"
    );
    let _ = c.write_all(head.as_bytes());
    let _ = c.write_all(b"abcd");
    thread::sleep(Duration::from_millis(40));
    let _ = c.write_all(b"efgh");
    let mut buf = Vec::new();
    let _ = c.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf);
    text.split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mixed_workload_soak_on_shipped_hyper_object_server() {
    let secs = soak_secs();
    let kind = if claiming_g8() {
        "g8_24h"
    } else {
        "developer_soak"
    };
    eprintln!("SOAK_KIND={kind} ran_secs_budget={secs} program_secs={SOAK_PROGRAM_SECS}");
    if kind == "developer_soak" {
        assert!(
            secs < SOAK_PROGRAM_SECS,
            "developer soak must not silently equal G8 duration without PEREGRINE_CLAIM_G8=1"
        );
    }
    let dir = std::env::temp_dir().join(format!(
        "peregrine-soak-{}-{}",
        std::process::id(),
        line!()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("sda1")).unwrap();

    let stall_on = Arc::new(AtomicBool::new(false));
    let stall_entered = Arc::new(AtomicBool::new(false));
    let stall = {
        let stall_on = Arc::clone(&stall_on);
        let stall_entered = Arc::clone(&stall_entered);
        Arc::new(move || {
            if stall_on.load(Ordering::SeqCst) {
                stall_entered.store(true, Ordering::SeqCst);
                while stall_on.load(Ordering::SeqCst) {
                    thread::park_timeout(Duration::from_millis(5));
                }
            }
        }) as Arc<dyn Fn() + Send + Sync>
    };

    let metrics = ConcurrencyMetrics::new();
    let shutdown = Arc::new(AtomicBool::new(false));
    let (mut addr, mut join) = spawn_object(&dir, Arc::clone(&stall), metrics.clone(), Arc::clone(&shutdown));

    let saw_backend_fail = Arc::new(AtomicBool::new(false));
    let saw_slow = Arc::new(AtomicBool::new(false));
    let saw_fsync = Arc::new(AtomicBool::new(false));
    let saw_restart = Arc::new(AtomicBool::new(false));
    let ts = Arc::new(AtomicU64::new(7000));

    let mut fds: Vec<u64> = Vec::new();
    let mut threads: Vec<u64> = Vec::new();
    let mut tasks: Vec<u64> = Vec::new();
    let mut rss: Vec<u64> = Vec::new();

    let deadline = Instant::now() + Duration::from_secs(secs.max(1));
    let mut cycle = 0u64;
    while Instant::now() < deadline {
        cycle += 1;
        let n = ts.fetch_add(1, Ordering::SeqCst);
        let name = format!("o{n}");
        match cycle % 4 {
            1 => {
                let st = put(addr, &name, n, b"soak");
                assert_eq!(st, 201, "normal PUT must commit on shipped serve, got {st}");
                let g = get_obj(addr, &name);
                assert_eq!(g, 200, "GET after PUT must be 200, got {g}");
                let _ = harness::get_keepalive(addr);
            }
            2 => {
                let st = slow_put(addr, &name, n);
                assert_eq!(st, 201, "slow PUT must still commit, got {st}");
                saw_slow.store(true, Ordering::SeqCst);
                let health = harness::get_close_timed(addr, Duration::from_millis(400));
                assert!(
                    health.map(|(s, _)| s != 0).unwrap_or(false),
                    "slow PUT must not starve health GET"
                );
            }
            3 => {
                stall_entered.store(false, Ordering::SeqCst);
                stall_on.store(true, Ordering::SeqCst);
                let put_addr = addr;
                let put_name = name.clone();
                let h = thread::spawn(move || put(put_addr, &put_name, n, b"fsnc"));
                let enter_deadline = Instant::now() + Duration::from_secs(2);
                while !stall_entered.load(Ordering::SeqCst) && Instant::now() < enter_deadline {
                    thread::sleep(Duration::from_millis(5));
                }
                assert!(
                    stall_entered.load(Ordering::SeqCst),
                    "fsync stall must enter StorageExecutor commit on shipped PUT"
                );
                saw_fsync.store(true, Ordering::SeqCst);
                let health = harness::get_close_timed(addr, Duration::from_millis(400));
                assert!(
                    health.map(|(s, _)| s != 0).unwrap_or(false),
                    "fsync stall must not starve health GET"
                );
                stall_on.store(false, Ordering::SeqCst);
                let stalled = h.join().expect("stalled PUT thread");
                assert_eq!(stalled, 201, "PUT after fsync stall release must be 201");
            }
            _ => {
                let (st, _) = transact(
                    addr,
                    b"PUT /no-such-device/0/AUTH_test/c/x HTTP/1.1\r\nHost: t\r\nX-Timestamp: 1\r\nContent-Type: application/octet-stream\r\nContent-Length: 1\r\nConnection: close\r\n\r\nZ",
                    Duration::from_secs(4),
                );
                assert!(
                    st >= 400 && st != 201,
                    "missing-device PUT must fail closed with HTTP error, got {st}"
                );
                saw_backend_fail.store(true, Ordering::SeqCst);
                if cycle >= 4 {
                    shutdown.store(true, Ordering::SeqCst);
                    let _ = TcpStream::connect_timeout(&addr, Duration::from_millis(50));
                    let _ = join.join();
                    shutdown.store(false, Ordering::SeqCst);
                    let spawned = spawn_object(
                        &dir,
                        Arc::clone(&stall),
                        metrics.clone(),
                        Arc::clone(&shutdown),
                    );
                    addr = spawned.0;
                    join = spawned.1;
                    saw_restart.store(true, Ordering::SeqCst);
                    let st = put(addr, &format!("post-restart-{n}"), n + 50_000, b"rst");
                    assert_eq!(st, 201, "PUT after worker restart must work, got {st}");
                }
            }
        }
        let snap = metrics.snapshot();
        fds.push(snap.open_fds);
        threads.push(snap.process_threads);
        tasks.push(snap.runtime_tasks);
        if let Some(kb) = sample_rss_kb() {
            rss.push(kb);
        }
        let body = recon(addr);
        assert!(
            body.contains("commit_shield_active") || body.contains("connections_open"),
            "recon snapshot missing, got {}",
            &body[..body.len().min(200)]
        );
    }

    stall_on.store(false, Ordering::SeqCst);
    let drain = Instant::now() + Duration::from_secs(3);
    while metrics.snapshot().commit_shield_active != 0 && Instant::now() < drain {
        thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        metrics.snapshot().commit_shield_active,
        0,
        "stuck durability transaction after soak"
    );

    assert!(
        saw_slow.load(Ordering::SeqCst),
        "slow-client injection never fired"
    );
    assert!(
        saw_fsync.load(Ordering::SeqCst),
        "fsync-stall injection never fired"
    );
    assert!(
        saw_backend_fail.load(Ordering::SeqCst),
        "backend-failure injection never fired"
    );
    if secs >= 4 {
        assert!(
            saw_restart.load(Ordering::SeqCst),
            "worker-restart injection never fired (need enough soak time for cycle%8==0)"
        );
    }

    fn not_unbounded(samples: &[u64], label: &str) {
        if samples.len() < 4 {
            return;
        }
        let mid = samples.len() / 2;
        let early = samples[..mid].iter().copied().max().unwrap_or(0);
        let late = *samples.last().unwrap_or(&0);
        assert!(
            late <= early.saturating_mul(4).saturating_add(64),
            "{label} grew without bound: early_max={early} late={late} samples={samples:?}"
        );
    }
    not_unbounded(&fds, "open_fds");
    not_unbounded(&threads, "process_threads");
    not_unbounded(&tasks, "runtime_tasks");
    if rss.len() >= 4 {
        let mut mono = true;
        for w in rss.windows(2) {
            if w[1] <= w[0] {
                mono = false;
                break;
            }
        }
        assert!(
            !mono,
            "RSS grew on every sample (monotonic leak): {rss:?}"
        );
    }

    shutdown.store(true, Ordering::SeqCst);
    let _ = TcpStream::connect_timeout(&addr, Duration::from_millis(50));
    let _ = join.join();
    let _ = std::fs::remove_dir_all(&dir);
    eprintln!(
        "soak kind={kind} program_secs={SOAK_PROGRAM_SECS} ran_secs={secs} cycles={cycle} \
         slow={} fsync={} backend_fail={} restart={} commit_shield={}",
        saw_slow.load(Ordering::SeqCst),
        saw_fsync.load(Ordering::SeqCst),
        saw_backend_fail.load(Ordering::SeqCst),
        saw_restart.load(Ordering::SeqCst),
        metrics.snapshot().commit_shield_active
    );
}
