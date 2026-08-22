//! Gate 3 substrate: `AccountBroker::put_container` and
//! `ContainerBroker::put_object` (rusqlite) run on [`DbExecutor`].
//! Production `handle_async` isolation is `swift-account-server` /
//! `swift-container-server` `tests/db_dispatch.rs`.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use swift_core::pickle::Value;
use swift_db::{AccountBroker, ContainerBroker};
use swift_runtime::{DbExecutor, DbExecutorConfig};

fn tmpdir() -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "peregrine-db-iso-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

const TS: &str = "3286000000.00000";

#[tokio::test]
async fn account_broker_put_container_runs_on_db_executor() {
    let exec = DbExecutor::new(DbExecutorConfig::new(2, 8, 8).unwrap()).unwrap();
    let dir = tmpdir();
    let path = dir.join("acct.db");
    let caller = std::thread::current().id();
    let db_path = path.clone();

    let worker_tid = exec
        .run_on_shard(path.clone(), move || {
            let mut broker = AccountBroker::new(&db_path, "AUTH_test");
            broker.initialize(TS, TS, "iso-db-id").unwrap();
            broker
                .put_container("c", TS, "0", Value::Int(1), Value::Int(2), 0)
                .unwrap();
            std::thread::current().id()
        })
        .await
        .unwrap();

    assert_ne!(
        worker_tid, caller,
        "AccountBroker rusqlite must not run on the HTTP/reactor task"
    );

    let mut broker = AccountBroker::new(&path, "AUTH_test");
    let info = broker.get_info().unwrap();
    let count = info
        .iter()
        .find(|(k, _)| k == "container_count")
        .and_then(|(_, v)| v.as_i64());
    assert_eq!(
        count,
        Some(1),
        "put_container must have committed, got {info:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn container_broker_put_object_runs_on_db_executor() {
    let exec = DbExecutor::new(DbExecutorConfig::new(2, 8, 8).unwrap()).unwrap();
    let dir = tmpdir();
    let path = dir.join("cont.db");
    let caller = std::thread::current().id();
    let db_path = path.clone();

    let worker_tid = exec
        .run_on_shard(path.clone(), move || {
            let mut broker = ContainerBroker::new(&db_path, "AUTH_test", "c");
            broker.initialize(TS, 0, TS, "iso-cont-id").unwrap();
            broker
                .put_object("o", TS, 13, "text/plain", "etag-iso", 0, 0, None, None)
                .unwrap();
            std::thread::current().id()
        })
        .await
        .unwrap();

    assert_ne!(
        worker_tid, caller,
        "ContainerBroker rusqlite must not run on the HTTP/reactor task"
    );

    let mut broker = ContainerBroker::new(&path, "AUTH_test", "c");
    let info = broker.get_info().unwrap();
    let count = info
        .iter()
        .find(|(k, _)| k == "object_count")
        .and_then(|(_, v)| v.as_i64());
    assert_eq!(
        count,
        Some(1),
        "put_object must have committed, got {info:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn account_broker_does_not_block_reactor() {
    let exec = DbExecutor::new(DbExecutorConfig::new(1, 4, 4).unwrap()).unwrap();
    let dir = tmpdir();
    let path = dir.join("acct.db");
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel::<()>(1);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel::<()>(1);

    let job = tokio::spawn({
        let exec = exec.clone();
        let path = path.clone();
        async move {
            exec.run_on_shard(path.clone(), move || {
                let mut broker = AccountBroker::new(&path, "AUTH_test");
                broker.initialize(TS, TS, "iso-db-id-2").unwrap();
                broker
                    .put_container("parked", TS, "0", Value::Int(0), Value::Int(0), 0)
                    .unwrap();
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
            })
            .await
        }
    });

    let start = Instant::now();
    loop {
        if entered_rx.try_recv().is_ok() {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "AccountBroker did not enter DbExecutor"
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    }

    let started = std::sync::Arc::new(AtomicBool::new(false));
    let started_flag = std::sync::Arc::clone(&started);
    let job2 = tokio::spawn({
        let exec = exec.clone();
        let path = path.clone();
        async move {
            exec.run_on_shard(path, move || {
                started_flag.store(true, Ordering::SeqCst);
                1u8
            })
            .await
        }
    });

    tokio::time::timeout(
        Duration::from_millis(200),
        tokio::time::sleep(Duration::from_millis(5)),
    )
    .await
    .expect("reactor must progress while rusqlite occupies the DB shard");
    assert!(
        !started.load(Ordering::SeqCst),
        "same-shard job must wait in the mailbox, not run on the caller"
    );

    release_tx.send(()).unwrap();
    job.await.unwrap().unwrap();
    assert_eq!(job2.await.unwrap().unwrap(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn container_broker_does_not_block_reactor() {
    let exec = DbExecutor::new(DbExecutorConfig::new(1, 4, 4).unwrap()).unwrap();
    let dir = tmpdir();
    let path = dir.join("cont.db");
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel::<()>(1);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel::<()>(1);

    let job = tokio::spawn({
        let exec = exec.clone();
        let path = path.clone();
        async move {
            exec.run_on_shard(path.clone(), move || {
                let mut broker = ContainerBroker::new(&path, "AUTH_test", "c");
                broker.initialize(TS, 0, TS, "iso-cont-id-2").unwrap();
                broker
                    .put_object("parked", TS, 0, "text/plain", "e", 0, 0, None, None)
                    .unwrap();
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
            })
            .await
        }
    });

    let start = Instant::now();
    loop {
        if entered_rx.try_recv().is_ok() {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "ContainerBroker did not enter DbExecutor"
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    tokio::time::timeout(
        Duration::from_millis(200),
        tokio::time::sleep(Duration::from_millis(5)),
    )
    .await
    .expect("reactor must progress while ContainerBroker occupies the DB shard");
    release_tx.send(()).unwrap();
    job.await.unwrap().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
