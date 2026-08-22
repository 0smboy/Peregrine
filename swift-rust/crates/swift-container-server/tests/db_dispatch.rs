//! Gate 3: shipped `ContainerServer::handle_async` rusqlite on DbExecutor.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

use swift_container_server::{serve_instance, ContainerServer, ContainerServerConfig};
use swift_core::hashing::HashPathConfig;
use swift_http::{AsyncRequest, HeaderKeyDict, IncomingBody, Request, ServerConfig};

fn tmpdir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "cont-dispatch-{}-{}",
        std::process::id(),
        line!()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("sda1")).unwrap();
    dir
}

fn cfg(devices: PathBuf) -> ContainerServerConfig {
    ContainerServerConfig {
        devices,
        mount_check: false,
        hash_config: HashPathConfig::new(b"".to_vec(), b"dispatch".to_vec()).unwrap(),
        policies: vec![(0, "Policy-0".into())],
        default_policy_index: 0,
        fixed_created_at: Some("3286000000.00000".into()),
    }
}

fn put_container() -> AsyncRequest {
    let mut headers = HeaderKeyDict::new();
    headers.set("X-Timestamp", "3286000000.00000");
    AsyncRequest {
        method: "PUT".into(),
        path: "/sda1/0/AUTH_test/c".into(),
        query_string: String::new(),
        headers,
        body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handle_async_container_put_and_listing_wait_on_parked_shard() {
    let dir = tmpdir();
    let server = ContainerServer::new(cfg(dir.clone()));
    let probe = Request {
        method: "PUT".into(),
        path: "/sda1/0/AUTH_test/c".into(),
        query_string: String::new(),
        headers: HeaderKeyDict::new(),
        body: swift_http::Body::empty(),
    };
    let db_file = server.db_file_for_request(&probe).unwrap();
    let (entered_tx, entered_rx) = mpsc::sync_channel::<()>(1);
    let (release_tx, release_rx) = mpsc::sync_channel::<()>(1);
    let db = server.db().clone();
    let park = tokio::spawn({
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
        async move { server.handle_async(put_container()).await }
    });
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert!(
        !put.is_finished(),
        "container PUT-create must wait on the parked shard"
    );
    release_tx.send(()).ok();
    park.await.unwrap().unwrap();
    let resp = put.await.unwrap();
    assert!(
        resp.status == 201 || resp.status == 202,
        "container PUT-create got {}",
        resp.status
    );

    let server = ContainerServer::new(cfg(dir.clone()));
    for method in ["GET", "HEAD", "POST", "DELETE"] {
        let mut headers = HeaderKeyDict::new();
        headers.set("X-Timestamp", "3286000001.00000");
        let status = server
            .handle_async(AsyncRequest {
                method: method.into(),
                path: "/sda1/0/AUTH_test/c".into(),
                query_string: String::new(),
                headers,
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await
            .status;
        assert!(
            (200..500).contains(&status),
            "{method} status {status}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hyper_health_get_while_container_shard_parked() {
    let dir = tmpdir();
    let config = cfg(dir.clone());
    let server = Arc::new(ContainerServer::new(config));
    let probe = Request {
        method: "PUT".into(),
        path: "/sda1/0/AUTH_park/c".into(),
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
    let started = std::time::Instant::now();
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_millis(400)).unwrap();
    s.set_read_timeout(Some(Duration::from_millis(400))).unwrap();
    s.write_all(b"GET /health HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    let elapsed = started.elapsed();
    assert!(!buf.is_empty(), "health GET produced no bytes");
    assert!(
        elapsed < Duration::from_millis(400),
        "health GET took {elapsed:?} while container shard parked"
    );
    release_tx.send(()).ok();
    let _ = park.await;
    shutdown.store(true, Ordering::SeqCst);
    let _ = std::fs::remove_dir_all(&dir);
}
