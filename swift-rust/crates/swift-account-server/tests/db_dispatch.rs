//! Gate 3: shipped `AccountServer::handle_async` rusqlite runs on DbExecutor.
//! Park the shard; handle_async must not finish; a health GET on the same
//! Hyper listener must.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

use swift_account_server::{serve_instance, AccountServer, AccountServerConfig};
use swift_core::hashing::HashPathConfig;
use swift_http::{AsyncRequest, HeaderKeyDict, IncomingBody, Request, ServerConfig};

fn tmpdir() -> PathBuf {
    static NEXT_ID: AtomicU64 = AtomicU64::new(0);
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "acct-dispatch-{}-{id}",
        std::process::id(),
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("sda1")).unwrap();
    dir
}

fn cfg(devices: PathBuf) -> AccountServerConfig {
    AccountServerConfig {
        devices,
        mount_check: false,
        hash_config: HashPathConfig::new(b"".to_vec(), b"dispatch".to_vec()).unwrap(),
        policies: vec![(0, "Policy-0".into())],
        fixed_created_at: Some("3286000000.00000".into()),
    }
}

fn put_account(account: &str) -> AsyncRequest {
    let mut headers = HeaderKeyDict::new();
    headers.set("X-Timestamp", "3286000000.00000");
    AsyncRequest {
        method: "PUT".into(),
        path: format!("/sda1/0/{account}"),
        query_string: String::new(),
        headers,
        body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
    }
}

fn probe_get(addr: std::net::SocketAddr) -> (u16, Duration) {
    let started = std::time::Instant::now();
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_millis(400)).unwrap();
    s.set_read_timeout(Some(Duration::from_millis(400))).unwrap();
    s.write_all(b"GET /health HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    let status = std::str::from_utf8(&buf)
        .unwrap_or("")
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    (status, started.elapsed())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handle_async_account_put_waits_on_parked_shard() {
    let dir = tmpdir();
    let server = AccountServer::new(cfg(dir.clone()));
    let probe = Request {
        method: "PUT".into(),
        path: "/sda1/0/AUTH_test".into(),
        query_string: String::new(),
        headers: HeaderKeyDict::new(),
        body: swift_http::Body::empty(),
    };
    let db_file = server.db_file_for_request(&probe).unwrap();

    let (entered_tx, entered_rx) = mpsc::sync_channel::<()>(1);
    let (release_tx, release_rx) = mpsc::sync_channel::<()>(1);
    let db = server.db().clone();
    let park: tokio::task::JoinHandle<Result<(), _>> = tokio::spawn({
        let db_file = db_file.clone();
        async move {
            db.run_on_shard(db_file, move || {
                entered_tx.send(()).ok();
                let _ = release_rx.recv();
            })
            .await
        }
    });
    entered_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("shard park entered");

    let put = tokio::spawn({
        async move { server.handle_async(put_account("AUTH_test")).await }
    });
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert!(
        !put.is_finished(),
        "handle_async PUT must wait on the parked DbExecutor shard"
    );

    release_tx.send(()).ok();
    park.await.unwrap().unwrap();
    let resp = put.await.unwrap();
    assert!(
        resp.status == 201 || resp.status == 202,
        "account PUT after shard release, got {}",
        resp.status
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handle_async_account_get_post_delete_use_shard() {
    let dir = tmpdir();
    let server = AccountServer::new(cfg(dir.clone()));
    assert_eq!(server.handle_async(put_account("AUTH_test")).await.status, 201);

    for method in ["GET", "HEAD", "POST", "DELETE"] {
        let mut headers = HeaderKeyDict::new();
        headers.set("X-Timestamp", "3286000001.00000");
        let resp = server
            .handle_async(AsyncRequest {
                method: method.into(),
                path: "/sda1/0/AUTH_test".into(),
                query_string: String::new(),
                headers,
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert!(
            (200..500).contains(&resp.status),
            "{method} status {}",
            resp.status
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hyper_health_get_while_account_shard_parked() {
    let dir = tmpdir();
    let config = cfg(dir.clone());
    let server = Arc::new(AccountServer::new(config));
    let probe = Request {
        method: "PUT".into(),
        path: "/sda1/0/AUTH_park".into(),
        query_string: String::new(),
        headers: HeaderKeyDict::new(),
        body: swift_http::Body::empty(),
    };
    let db_file = server.db_file_for_request(&probe).unwrap();
    let (entered_tx, entered_rx) = mpsc::sync_channel::<()>(1);
    let (release_tx, release_rx) = mpsc::sync_channel::<()>(1);
    let db = server.db().clone();
    let park = tokio::spawn(async move {
        db.run_on_shard(db_file, move || {
            entered_tx.send(()).ok();
            let _ = release_rx.recv();
        })
        .await
    });
    entered_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("park");

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let shutdown = Arc::new(AtomicBool::new(false));
    let http_cfg = ServerConfig {
        worker_threads: 2,
        shutdown: Some(Arc::clone(&shutdown)),
        ..ServerConfig::default()
    };
    let served = Arc::clone(&server);
    std::thread::spawn(move || serve_instance(listener, served, http_cfg));
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while std::time::Instant::now() < deadline {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(20)).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let (status, elapsed) = probe_get(addr);
    assert_ne!(status, 0, "health GET must get an HTTP status");
    assert!(
        elapsed < Duration::from_millis(400),
        "health GET took {elapsed:?} while account shard parked"
    );
    release_tx.send(()).ok();
    let _ = park.await;
    shutdown.store(true, Ordering::SeqCst);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handle_async_replicate_uses_hash_db_not_account_name() {
    let dir = tmpdir();
    let server = AccountServer::new(cfg(dir.clone()));
    assert_eq!(server.handle_async(put_account("AUTH_test")).await.status, 201);
    let probe = Request {
        method: "PUT".into(),
        path: "/sda1/0/AUTH_test".into(),
        query_string: String::new(),
        headers: HeaderKeyDict::new(),
        body: swift_http::Body::empty(),
    };
    let db_file = server.db_file_for_request(&probe).unwrap();
    let hsh = db_file
        .file_stem()
        .and_then(|s| s.to_str())
        .expect("hash.db stem")
        .to_string();
    let rpc_path = format!("/sda1/0/{hsh}");
    let via_helper = server
        .replicate_db_file_for_request(&Request {
            method: "REPLICATE".into(),
            path: rpc_path.clone(),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: swift_http::Body::empty(),
        })
        .unwrap();
    assert_eq!(via_helper, db_file);
    let body = serde_json::json!([
        "sync",
        -1,
        "hash",
        "peer-id",
        "3286000000.00000",
        "3286000000.00000",
        "0",
        "{}"
    ]);
    let resp = server
        .handle_async(AsyncRequest {
            method: "REPLICATE".into(),
            path: rpc_path,
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: IncomingBody::from_bytes(body.to_string().into_bytes(), u64::MAX),
        })
        .await;
    assert_eq!(
        resp.status, 200,
        "account REPLICATE sync over handle_async got {}",
        resp.status
    );
    let _ = std::fs::remove_dir_all(&dir);
}
