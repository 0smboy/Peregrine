use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use swift_core::hashing::HashPathConfig;
use swift_diskfile::{DiskFile, DiskFileConfig, DiskFileError, PolicyKind};

static NEXT_TMP: AtomicU64 = AtomicU64::new(0);

fn tmp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "swift-object-mutation-{tag}-{}-{}",
        std::process::id(),
        NEXT_TMP.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn diskfile(device: &PathBuf, object: &str) -> DiskFile {
    let hash = HashPathConfig::new(Vec::new(), b"mutation-lock-tests".to_vec()).unwrap();
    DiskFile::new(
        device,
        0,
        "AUTH_test",
        "container",
        object,
        PolicyKind::Replication,
        0,
        &hash,
        DiskFileConfig::default(),
    )
    .unwrap()
}

#[test]
fn same_object_contends_on_one_persistent_stripe() {
    let device = tmp_dir("same");
    let first = diskfile(&device, "object");
    let second = diskfile(&device, "object");
    let hash = first.datadir().file_name().unwrap().to_str().unwrap();
    let expected = device
        .join("tmp/object-mutation-locks")
        .join(format!(".lock-obj-{}", &hash[hash.len() - 3..]));

    let held = first.acquire_mutation_lock(1.0).unwrap();
    assert!(expected.exists(), "lock inode must persist at {expected:?}");
    assert!(matches!(
        second.acquire_mutation_lock(0.05),
        Err(DiskFileError::LockTimeout(_))
    ));
    drop(held);
    second.acquire_mutation_lock(0.2).unwrap();

    let _ = std::fs::remove_dir_all(device);
}

#[test]
fn mutation_lock_inode_count_is_bounded_by_hash_suffix_space() {
    let device = tmp_dir("bounded");
    for index in 0..5000 {
        let df = diskfile(&device, &format!("object-{index}"));
        drop(df.acquire_mutation_lock(1.0).unwrap());
    }
    let count = std::fs::read_dir(device.join("tmp/object-mutation-locks"))
        .unwrap()
        .count();
    assert!(count <= 4096, "fixed stripe space exceeded: {count}");
    assert!(
        count > 1000,
        "test did not exercise enough distinct stripes: {count}"
    );

    let _ = std::fs::remove_dir_all(device);
}
