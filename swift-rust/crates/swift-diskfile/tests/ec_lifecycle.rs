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

use std::path::Path;

use swift_core::hashing::HashPathConfig;
use swift_core::timestamp::Timestamp;
use swift_diskfile::{DiskFile, DiskFileConfig, MetaValue, Metadata, PolicyKind};

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
