//! Gate 3 substrate: real `DiskFileWriter::put` (`finalize_put`: xattr +
//! `sync_all` + rename) runs on [`StorageExecutor`] / `BlockingDomain`,
//! not on the caller task. Production object PUT is `ObjectServer::handle_async`
//! → `put_streaming_async` → this executor. GET isolation is
//! `handle_async_get_does_not_pin_storage_on_slow_client` in swift-object-server.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use swift_core::hashing::HashPathConfig;
use swift_diskfile::{read_metadata, DiskFile, DiskFileConfig, MetaValue, PolicyKind};
use swift_runtime::{
    DeviceId, DeviceIoLimits, StorageError, StorageExecutor, StorageExecutorConfig, TrafficClass,
};

fn tmpdir() -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "peregrine-df-iso-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn hc() -> HashPathConfig {
    HashPathConfig::new(b"p".to_vec(), b"s".to_vec()).unwrap()
}

fn put_metadata(etag: &str, len: usize) -> Vec<(MetaValue, MetaValue)> {
    vec![
        (
            MetaValue::Str("X-Timestamp".into()),
            MetaValue::Str("3286000000.00000".into()),
        ),
        (
            MetaValue::Str("Content-Type".into()),
            MetaValue::Str("text/plain".into()),
        ),
        (MetaValue::Str("ETag".into()), MetaValue::Str(etag.into())),
        (
            MetaValue::Str("Content-Length".into()),
            MetaValue::Str(len.to_string()),
        ),
    ]
}

fn durable_data_file(datadir: &Path) -> PathBuf {
    let entries: Vec<_> = std::fs::read_dir(datadir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .collect();
    entries
        .iter()
        .find(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(".data"))
        })
        .cloned()
        .unwrap_or_else(|| panic!("durable .data missing in {datadir:?}: {entries:?}"))
}

fn finalize_put_on_device(device: PathBuf, name: &str, body: &[u8]) -> PathBuf {
    let mut cfg = DiskFileConfig::default();
    cfg.fsync_on_close = true;
    let df = DiskFile::new(
        &device,
        0,
        "AUTH_test",
        "c",
        name,
        PolicyKind::Replication,
        0,
        &hc(),
        cfg,
    )
    .unwrap();
    let etag = {
        use md5::{Digest, Md5};
        format!("{:x}", Md5::digest(body))
    };
    let mut w = df.create(".data").unwrap();
    w.write(body).unwrap();
    // DiskFileWriter::put → finalize_put: write_file_metadata (xattr),
    // File::sync_all, invalidate_hash, renamer(+ dir sync_all).
    w.put(put_metadata(&etag, body.len())).unwrap();
    w.close();
    df.datadir().to_path_buf()
}

#[tokio::test]
async fn diskfile_put_finalize_runs_on_storage_executor() {
    let exec = StorageExecutor::new(
        StorageExecutorConfig::new(1, 4, DeviceIoLimits::new(4, 4, 4, 4, 4)).unwrap(),
    )
    .unwrap();
    let dir = tmpdir();
    let device = dir.join("sda1");
    std::fs::create_dir_all(&device).unwrap();
    let caller = std::thread::current().id();
    let body = b"isolation-put";

    let (worker_tid, datadir) = exec
        .run_finite(DeviceId::new("sda1"), TrafficClass::Foreground, move || {
            let datadir = finalize_put_on_device(device, "o", body);
            (std::thread::current().id(), datadir)
        })
        .await
        .unwrap();

    assert_ne!(
        worker_tid, caller,
        "DiskFileWriter::put/finalize_put must not run on the HTTP/reactor task"
    );
    let data = durable_data_file(&datadir);
    assert_eq!(std::fs::read(&data).unwrap(), body);
    let expected_etag = {
        use md5::{Digest, Md5};
        format!("{:x}", Md5::digest(body))
    };
    let meta = read_metadata(&data).expect("finalize_put must persist xattr metadata");
    let etag = meta
        .iter()
        .find_map(|(k, v)| matches!(k, MetaValue::Str(s) if s == "ETag").then_some(v));
    assert!(
        matches!(etag, Some(MetaValue::Str(s)) if s == &expected_etag),
        "ETag xattr missing or mismatched: {meta:?}"
    );
    assert_eq!(exec.stats().blocking.completed_total, 1);
    assert_eq!(exec.stats().device_ops_active, 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn diskfile_put_does_not_block_reactor_or_try_acquire() {
    let exec = StorageExecutor::new(
        StorageExecutorConfig::new(1, 4, DeviceIoLimits::new(1, 1, 1, 1, 1)).unwrap(),
    )
    .unwrap();
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel::<()>(1);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel::<()>(1);
    let dir = tmpdir();
    let device = dir.join("sda1");
    std::fs::create_dir_all(&device).unwrap();
    let sda = DeviceId::new("sda1");

    let job = tokio::spawn({
        let exec = exec.clone();
        let sda = sda.clone();
        async move {
            exec.run_finite(sda, TrafficClass::Foreground, move || {
                let datadir = finalize_put_on_device(device, "slow", b"");
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                datadir
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
            "DiskFile put did not enter storage executor"
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    }

    let busy = exec
        .try_acquire_device(sda.clone(), TrafficClass::Foreground)
        .unwrap_err();
    assert!(
        matches!(
            busy,
            StorageError::DeviceClassBusy {
                class: TrafficClass::Foreground,
                cap: 1,
                ..
            }
        ),
        "second try-acquire must fail closed, not block: {busy:?}"
    );
    tokio::time::timeout(
        Duration::from_millis(200),
        tokio::time::sleep(Duration::from_millis(5)),
    )
    .await
    .expect("reactor must progress while DiskFileWriter::put occupies storage");

    release_tx.send(()).unwrap();
    let datadir = job.await.unwrap().unwrap();
    let _ = durable_data_file(&datadir);
    assert_eq!(exec.stats().device_ops_active, 0);
    let _ = std::fs::remove_dir_all(&dir);
}
