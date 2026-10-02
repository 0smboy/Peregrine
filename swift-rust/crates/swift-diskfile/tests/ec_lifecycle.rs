// Copyright (c) 2026 OpenStack Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! EC diskfile PUT+commit lifecycle, exercising the *proxy* path where the
//! fragment index arrives only in the PUT metadata
//! (`X-Object-Sysmeta-Ec-Frag-Index`), not via `with_frag_index` at
//! construction. This is the regression guard for the durability bug where
//! `put()` computed the frag index but never stored `self.frag_index`, so the
//! subsequent `commit()` failed with `BadFragmentIndex` and the fragment never
//! became durable.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use swift_core::hashing::HashPathConfig;
use swift_core::timestamp::Timestamp;
use swift_diskfile::{
    read_metadata, DiskFile, DiskFileConfig, DiskFileError, MetaValue, Metadata, PolicyKind,
};

fn ec_meta(ts: &str, frag_index: i64) -> Metadata {
    vec![
        (
            MetaValue::Str("name".into()),
            MetaValue::Str("/AUTH_test/c/o".into()),
        ),
        (
            MetaValue::Str("X-Timestamp".into()),
            MetaValue::Str(ts.into()),
        ),
        (
            MetaValue::Str("Content-Length".into()),
            MetaValue::Str("5".into()),
        ),
        (
            MetaValue::Str("ETag".into()),
            MetaValue::Str("5d41402abc4b2a76b9719d911017c592".into()),
        ),
        (
            MetaValue::Str("X-Object-Sysmeta-Ec-Frag-Index".into()),
            MetaValue::Int(frag_index),
        ),
    ]
}

#[test]
fn test_ec_put_then_commit_becomes_durable_via_metadata_frag_index() {
    let dir = std::env::temp_dir().join(format!("swift-ec-life-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let device = dir.join("sda1");
    std::fs::create_dir_all(&device).unwrap();
    let hc = HashPathConfig::new("", "changeme").unwrap();

    // EC diskfile with NO frag index at construction — the proxy supplies it
    // through the PUT metadata only.
    let df = DiskFile::new(
        &device,
        0,
        "AUTH_test",
        "c",
        "o",
        PolicyKind::Ec {
            n_unique_fragments: Some(6),
        },
        0,
        &hc,
        DiskFileConfig::default(),
    )
    .unwrap();
    let datadir = df.datadir().to_path_buf();
    let suffix = datadir
        .parent()
        .and_then(Path::file_name)
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let invalidations = datadir
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("hashes.invalid");

    let ts = "1751500001.00000";
    let mut writer = df.create(".data").unwrap();
    writer.write(b"hello").unwrap();
    // put() must persist the frag index (3) from the metadata so commit() works
    writer.put(ec_meta(ts, 3)).unwrap();
    let invalidations_after_put = std::fs::read_to_string(&invalidations)
        .unwrap_or_default()
        .lines()
        .filter(|line| *line == suffix)
        .count();
    let tsp = ts.parse::<Timestamp>().unwrap();
    writer
        .commit(&tsp)
        .expect("commit must succeed and make the fragment durable");
    writer.close();
    let invalidations_after_commit = std::fs::read_to_string(&invalidations)
        .unwrap_or_default()
        .lines()
        .filter(|line| *line == suffix)
        .count();
    assert_eq!(
        invalidations_after_commit,
        invalidations_after_put + 1,
        "the EC durable transition must invalidate the suffix independently"
    );

    // the durable fragment file <ts>#3#d.data must now exist
    let datadir = find_hash_dir(&device);
    let files: Vec<String> = std::fs::read_dir(&datadir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        files.iter().any(|f| f.contains("#3#d.data")),
        "durable fragment not written; files = {files:?}"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn test_ec_into_durable_commit_uses_metadata_frag_index() {
    let dir = std::env::temp_dir().join(format!("swift-ec-durable-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let device = dir.join("sda1");
    std::fs::create_dir_all(&device).unwrap();
    let hc = HashPathConfig::new("", "changeme").unwrap();
    let df = DiskFile::new(
        &device,
        0,
        "AUTH_test",
        "c",
        "o",
        PolicyKind::Ec {
            n_unique_fragments: Some(6),
        },
        0,
        &hc,
        DiskFileConfig::default(),
    )
    .unwrap();
    let ts = "1751500002.00000";
    let mut writer = df.create(".data").unwrap();
    writer.write(b"hello").unwrap();
    let durable = writer.into_durable().unwrap();
    durable
        .commit(ec_meta(ts, 4))
        .expect("DurablePut::commit must stamp ts#N#d.data from footer sysmeta");
    let datadir = find_hash_dir(&device);
    let files: Vec<String> = std::fs::read_dir(&datadir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        files.iter().any(|f| f.contains("#4#d.data")),
        "durable fragment not written; files = {files:?}"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Descend `<device>/objects/<part>/<suffix>/<hash>/` to the hash dir.
fn find_hash_dir(device: &Path) -> std::path::PathBuf {
    let objects = device.join("objects");
    for part in std::fs::read_dir(&objects).unwrap().flatten() {
        if !part.path().is_dir() {
            continue;
        }
        for suffix in std::fs::read_dir(part.path()).unwrap().flatten() {
            if !suffix.path().is_dir() {
                continue;
            }
            for hash in std::fs::read_dir(suffix.path()).unwrap().flatten() {
                if hash.path().is_dir() {
                    return hash.path();
                }
            }
        }
    }
    panic!("no hash dir under {}", objects.display());
}

const FRAGMENT_KEY: &str = "X-Object-Sysmeta-Ec-Frag-Index";
const OLD_TS: &str = "1751500100.00000";
const NEW_TS: &str = "1751500101.00000";

#[derive(Clone, Copy, Debug)]
enum PersistMode {
    TwoPhase,
    Durable,
    NoCommit,
}
const PERSIST_MODES: [PersistMode; 3] = [
    PersistMode::TwoPhase,
    PersistMode::Durable,
    PersistMode::NoCommit,
];

struct ValidationTree {
    root: PathBuf,
    device: PathBuf,
}
impl ValidationTree {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "swift-ec-index-validation-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        let device = root.join("sda1");
        std::fs::create_dir(&device).unwrap();
        Self { root, device }
    }

    fn diskfile(&self, index: Option<i64>) -> DiskFile {
        DiskFile::new(
            &self.device,
            0,
            "AUTH_test",
            "c",
            "o",
            PolicyKind::Ec {
                n_unique_fragments: Some(6),
            },
            0,
            &HashPathConfig::new("", "changeme").unwrap(),
            DiskFileConfig::default(),
        )
        .unwrap()
        .with_frag_index(index)
    }
}
impl Drop for ValidationTree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn files(path: &Path) -> Vec<std::ffi::OsString> {
    let entries = match std::fs::read_dir(path) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(error) => panic!("read {}: {error}", path.display()),
    };
    let mut names: Vec<_> = entries.map(|entry| entry.unwrap().file_name()).collect();
    names.sort();
    names
}

fn metadata_with_index(value: Option<MetaValue>) -> Metadata {
    let mut metadata = ec_meta(NEW_TS, 5);
    metadata.retain(|(key, _)| !matches!(key, MetaValue::Str(key) if key == FRAGMENT_KEY));
    if let Some(value) = value {
        metadata.push((MetaValue::Str(FRAGMENT_KEY.into()), value));
    }
    metadata
}

fn persist_data(df: &DiskFile, mode: PersistMode, metadata: Metadata) -> Result<(), DiskFileError> {
    let mut writer = df.create(".data").unwrap();
    writer.write(b"hello").unwrap();
    match mode {
        PersistMode::TwoPhase => {
            let result = writer
                .put(metadata)
                .and_then(|()| writer.commit(&NEW_TS.parse::<Timestamp>().unwrap()));
            writer.close();
            result
        }
        PersistMode::Durable => writer.into_durable().unwrap().commit(metadata),
        PersistMode::NoCommit => writer.into_durable().unwrap().commit_nondurable(metadata),
    }
}

fn assert_index_rejected(value: Option<MetaValue>, writer_index: Option<i64>) {
    for mode in PERSIST_MODES {
        let tree = ValidationTree::new();
        let df = tree.diskfile(None);
        let mut original = df.create(".data").unwrap();
        original.write(b"hello").unwrap();
        original.put(ec_meta(OLD_TS, 5)).unwrap();
        original.commit(&OLD_TS.parse().unwrap()).unwrap();
        original.close();
        let source = df.datadir().join(format!("{OLD_TS}#5#d.data"));
        let old_metadata = read_metadata(&source).unwrap();
        let old_files = files(df.datadir());
        let candidate = tree.diskfile(writer_index);

        let result = persist_data(&candidate, mode, metadata_with_index(value.clone()));
        assert!(
            matches!(result, Err(DiskFileError::BadFragmentIndex(_))),
            "{mode:?}: {result:?}"
        );
        assert_eq!(
            files(df.datadir()),
            old_files,
            "{mode:?}: rejected index published or removed a generation"
        );
        assert_eq!(
            std::fs::read(&source).unwrap(),
            b"hello",
            "{mode:?}: existing source changed"
        );
        assert_eq!(
            read_metadata(&source).unwrap(),
            old_metadata,
            "{mode:?}: source sysmeta changed"
        );
        assert!(
            files(&tree.device.join("tmp")).is_empty(),
            "{mode:?}: unpublished temp leaked"
        );
        assert!(
            !df.datadir().join(format!("{NEW_TS}.data")).exists(),
            "{mode:?}: EC data fell back to replication filename"
        );
    }
}

#[test]
fn ec_index_missing_rejects_in_all_persist_modes() {
    assert_index_rejected(None, None);
}

#[test]
fn ec_index_nonnumeric_rejects_in_all_persist_modes() {
    assert_index_rejected(Some(MetaValue::Str("not-an-index".into())), None);
}

#[test]
fn ec_index_equal_to_fragment_count_rejects_in_all_persist_modes() {
    assert_index_rejected(Some(MetaValue::Int(6)), None);
}

#[test]
fn ec_index_negative_rejects_in_all_persist_modes() {
    assert_index_rejected(Some(MetaValue::Int(-1)), None);
}

#[test]
fn ec_index_invalid_metadata_does_not_use_valid_writer_fallback() {
    assert_index_rejected(Some(MetaValue::Str("invalid".into())), Some(5));
    assert_index_rejected(Some(MetaValue::Int(6)), Some(5));
}

#[test]
fn ec_index_writer_fallback_is_also_range_checked() {
    assert_index_rejected(None, Some(6));
    assert_index_rejected(None, Some(-1));
}

fn assert_index_accepted(
    value: Option<MetaValue>,
    writer_index: Option<i64>,
    persisted_value: MetaValue,
) {
    for mode in PERSIST_MODES {
        let tree = ValidationTree::new();
        let df = tree.diskfile(writer_index);
        persist_data(&df, mode, metadata_with_index(value.clone())).unwrap();
        let suffix = if matches!(mode, PersistMode::NoCommit) {
            "#5.data"
        } else {
            "#5#d.data"
        };
        let expected = format!("{NEW_TS}{suffix}");
        assert_eq!(
            files(df.datadir()),
            vec![std::ffi::OsString::from(&expected)],
            "{mode:?}"
        );
        let path = df.datadir().join(expected);
        assert_eq!(std::fs::read(&path).unwrap(), b"hello", "{mode:?}");
        let stored = read_metadata(&path).unwrap();
        let index = stored.iter().find_map(|(key, value)| {
            matches!(key, MetaValue::Str(key) if key == FRAGMENT_KEY).then_some(value)
        });
        assert_eq!(
            index,
            Some(&persisted_value),
            "{mode:?}: missing or changed fragment sysmeta"
        );
        assert!(
            files(&tree.device.join("tmp")).is_empty(),
            "{mode:?}: successful publication leaked temp"
        );
    }
}

#[test]
fn ec_index_n_minus_one_is_valid_in_all_persist_modes() {
    assert_index_accepted(Some(MetaValue::Int(5)), None, MetaValue::Int(5));
    assert_index_accepted(
        Some(MetaValue::Str(" +5 ".into())),
        None,
        MetaValue::Str(" +5 ".into()),
    );
}

#[test]
fn ec_index_missing_metadata_is_backfilled_from_valid_writer_index() {
    assert_index_accepted(None, Some(5), MetaValue::Int(5));
}

#[test]
fn ec_index_explicit_metadata_precedes_writer_index() {
    assert_index_accepted(Some(MetaValue::Int(5)), Some(1), MetaValue::Int(5));
}

#[test]
fn ec_durable_metadata_and_tombstone_keep_non_data_filenames() {
    // A valid tombstone must not already be older than reclaim_age; this
    // tests filename selection, not the independent age-based cleanup.
    let timestamp = format!(
        "{:.5}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64()
    )
    .parse::<Timestamp>()
    .unwrap()
    .internal();
    for mode in [PersistMode::Durable, PersistMode::NoCommit] {
        for extension in [".meta", ".ts"] {
            let tree = ValidationTree::new();
            let df = tree.diskfile(Some(5));
            let owned = df.create(extension).unwrap().into_durable().unwrap();
            let metadata = vec![(
                MetaValue::Str("X-Timestamp".into()),
                MetaValue::Str(timestamp.clone()),
            )];
            match mode {
                PersistMode::Durable => owned.commit(metadata),
                PersistMode::NoCommit => owned.commit_nondurable(metadata),
                PersistMode::TwoPhase => unreachable!(),
            }
            .unwrap();
            assert_eq!(
                files(df.datadir()),
                vec![std::ffi::OsString::from(format!("{timestamp}{extension}"))],
                "{mode:?} {extension}"
            );
            assert!(
                files(&tree.device.join("tmp")).is_empty(),
                "{mode:?} {extension}"
            );
        }
    }
}
