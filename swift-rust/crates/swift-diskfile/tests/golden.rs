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

//! Differential tests against golden fixtures produced by the real
//! Python implementation (see `fixtures/generate.py`). Metadata pickles
//! must match Python *byte for byte*; file selection, suffix hashing and
//! reclaim behavior must match result for result.

use std::path::{Path, PathBuf};

use serde_json::Value as Json;
use swift_core::pickle::Value;
use swift_diskfile::*;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn expectations() -> Json {
    let raw = std::fs::read(fixture("expectations.json")).expect(
        "missing fixtures; run rust/crates/swift-diskfile/tests/fixtures/generate.py",
    );
    serde_json::from_slice(&raw).unwrap()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn tmpdir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "swift-diskfile-golden-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Build the logical metadata from a fixture case's `pairs` +
/// `raw_values`.
fn meta_from_case(case: &Json) -> Metadata {
    let raw_values = &case["raw_values"];
    case["pairs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|pair| {
            let key = pair[0].as_str().unwrap();
            let value = match &pair[1] {
                Json::Null => MetaValue::Bytes(unhex(raw_values[key].as_str().unwrap())),
                Json::String(s) => MetaValue::Str(s.clone()),
                Json::Number(n) => MetaValue::Int(n.as_i64().unwrap()),
                other => panic!("unexpected pair value {other:?}"),
            };
            (MetaValue::Str(key.to_string()), value)
        })
        .collect()
}

#[test]
fn test_metadata_pickles_match_python() {
    let exp = expectations();
    for case in exp["pickles"].as_array().unwrap() {
        let desc = case["desc"].as_str().unwrap();
        let blob = unhex(case["blob"].as_str().unwrap());
        let expected_meta = meta_from_case(case);

        // decoding Python's pickle yields the logical dict, in order
        let decoded = metadata_from_pickle(&blob)
            .unwrap_or_else(|e| panic!("{desc}: decode failed: {e}"));
        assert_eq!(decoded, expected_meta, "{desc}: decoded metadata");

        // encoding is byte-identical with pickle.dumps(..., 2)
        let encoded = metadata_to_pickle(&expected_meta).unwrap();
        assert_eq!(
            encoded, blob,
            "{desc}: canonical pickle bytes (lens {} vs {})",
            encoded.len(),
            blob.len()
        );

        // checksum matches what Python stores alongside
        use md5::{Digest, Md5};
        assert_eq!(
            format!("{:x}", Md5::digest(&blob)),
            case["checksum"].as_str().unwrap(),
            "{desc}: checksum"
        );
    }
}

#[test]
fn test_legacy_py2_pickles() {
    let exp = expectations();
    for case in exp["legacy_pickles"].as_array().unwrap() {
        let desc = case["desc"].as_str().unwrap();
        let blob = unhex(case["blob"].as_str().unwrap());
        let decoded = metadata_from_pickle(&blob).unwrap();
        let expected: Metadata = case["pairs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|pair| {
                (
                    MetaValue::Str(pair[0].as_str().unwrap().to_string()),
                    MetaValue::Str(pair[1].as_str().unwrap().to_string()),
                )
            })
            .collect();
        assert_eq!(decoded, expected, "{desc}");
    }
}

fn policy_for(case: &Json) -> PolicyKind {
    match case["policy"].as_str().unwrap() {
        "repl" => PolicyKind::Replication,
        "ec" => PolicyKind::Ec {
            n_unique_fragments: None,
        },
        other => panic!("unknown policy {other}"),
    }
}

fn opt_basename(path: &Option<PathBuf>) -> Option<String> {
    path.as_ref()
        .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
}

fn sorted_filenames(infos: &[FileInfo]) -> Vec<String> {
    let mut names: Vec<String> = infos.iter().map(|i| i.filename.clone()).collect();
    names.sort();
    names
}

fn json_str_list(value: &Json) -> Vec<String> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect()
}

#[test]
fn test_ondisk_selection_matches_python() {
    let exp = expectations();
    for case in exp["ondisk"].as_array().unwrap() {
        let desc = case["desc"].as_str().unwrap();
        let files: Vec<String> = json_str_list(&case["files"]);
        let frag_index = case["frag_index"].as_i64();
        let frag_prefs: Option<Vec<FragPref>> = case["frag_prefs"].as_array().map(|prefs| {
            prefs
                .iter()
                .map(|p| FragPref {
                    timestamp: p["timestamp"].as_str().unwrap().parse().unwrap(),
                    exclude: p["exclude"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|v| v.as_i64().unwrap())
                        .collect(),
                })
                .collect()
        });

        let results = get_ondisk_files(
            &files,
            Path::new("/dd"),
            true,
            policy_for(case),
            frag_index,
            frag_prefs.as_deref(),
        )
        .unwrap_or_else(|e| panic!("{desc}: {e}"));

        let want = &case["result"];
        for (key, got) in [
            ("data_file", opt_basename(&results.data_file)),
            ("meta_file", opt_basename(&results.meta_file)),
            ("ts_file", opt_basename(&results.ts_file)),
            ("ctype_file", opt_basename(&results.ctype_file)),
        ] {
            assert_eq!(
                got,
                want[key].as_str().map(str::to_string),
                "{desc}: {key}"
            );
        }
        assert_eq!(
            sorted_filenames(&results.obsolete),
            json_str_list(&want["obsolete"]),
            "{desc}: obsolete"
        );
        assert_eq!(
            sorted_filenames(&results.possible_reclaim),
            json_str_list(&want["possible_reclaim"]),
            "{desc}: possible_reclaim"
        );
        let mut unexpected: Vec<String> = results
            .unexpected
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        unexpected.sort();
        assert_eq!(
            unexpected,
            json_str_list(&want["unexpected"]),
            "{desc}: unexpected"
        );
        if let Some(durable) = want["data_durable"].as_bool() {
            // the generator records `.get('durable', False)`
            assert_eq!(
                results.data_info.as_ref().unwrap().durable.unwrap_or(false),
                durable,
                "{desc}: data_durable"
            );
        }
        if let Some(ts) = want["durable_timestamp"].as_str() {
            assert_eq!(
                results.durable_frag_set_ts.map(|t| t.internal()),
                Some(ts.to_string()),
                "{desc}: durable_timestamp"
            );
        }
    }
}

/// Build a `pickle::Value` for a suffix-hash value from its JSON form.
fn hash_value_from_json(v: &Json) -> Value {
    match v {
        Json::Null => Value::None,
        Json::Bool(b) => Value::Bool(*b),
        Json::String(s) => Value::Str(s.clone()),
        Json::Number(n) if n.is_i64() => Value::Int(n.as_i64().unwrap()),
        Json::Number(n) => Value::Float(n.as_f64().unwrap()),
        Json::Object(map) => Value::Dict(
            map.iter()
                .map(|(k, v)| {
                    let key = if k == "null" {
                        Value::None
                    } else {
                        Value::Int(k.parse().unwrap())
                    };
                    (key, Value::Str(v.as_str().unwrap().to_string()))
                })
                .collect(),
        ),
        other => panic!("unexpected hash value {other:?}"),
    }
}

#[test]
fn test_hashes_pkl_write_matches_python() {
    let exp = expectations();
    let frozen = exp["hashes_pkl"]["frozen_time"].as_f64().unwrap();
    for case in exp["hashes_pkl"]["write_cases"].as_array().unwrap() {
        let desc = case["desc"].as_str().unwrap();
        let mut hashes = Hashes::default();
        for pair in case["pairs"].as_array().unwrap() {
            let key = pair[0].as_str().unwrap();
            if key == "updated" {
                continue; // stamped by hashes_to_pickle
            }
            hashes.set(key, hash_value_from_json(&pair[1]));
        }
        let blob = hashes_to_pickle(&mut hashes, frozen).unwrap();
        assert_eq!(
            blob,
            unhex(case["blob"].as_str().unwrap()),
            "{desc}: hashes.pkl bytes"
        );
    }
}

#[test]
fn test_hashes_pkl_read_matches_python() {
    let exp = expectations();
    for case in exp["hashes_pkl"]["read_cases"].as_array().unwrap() {
        let desc = case["desc"].as_str().unwrap();
        let part = tmpdir(&format!("read-{desc}"));
        if let Some(blob) = case["blob"].as_str() {
            std::fs::write(part.join(HASH_FILE), unhex(blob)).unwrap();
        }
        let got = read_hashes(&part);
        let want = case["expected"].as_object().unwrap();
        assert_eq!(got.pairs.len(), want.len(), "{desc}: key count {got:?}");
        for (key, value) in want {
            let got_value = got
                .get(key)
                .unwrap_or_else(|| panic!("{desc}: missing key {key}"));
            let want_value = hash_value_from_json(value);
            assert_eq!(got_value, &want_value, "{desc}: {key}");
        }
        std::fs::remove_dir_all(&part).unwrap();
    }
}

fn build_tree(datadir_root: &Path, tree: &Json) {
    for (hashdir_rel, files) in tree.as_object().unwrap() {
        let hd = datadir_root.join(hashdir_rel);
        std::fs::create_dir_all(&hd).unwrap();
        for f in files.as_array().unwrap() {
            std::fs::write(hd.join(f.as_str().unwrap()), b"").unwrap();
        }
    }
}

fn snapshot_tree(partition_path: &Path) -> Vec<(String, Vec<String>)> {
    let mut out = Vec::new();
    let mut suffixes: Vec<String> = std::fs::read_dir(partition_path)
        .unwrap()
        .filter_map(|e| {
            let e = e.unwrap();
            let name = e.file_name().to_string_lossy().into_owned();
            (e.path().is_dir() && name.len() == 3).then_some(name)
        })
        .collect();
    suffixes.sort();
    for suffix in suffixes {
        let sdir = partition_path.join(&suffix);
        let mut hashdirs: Vec<String> = std::fs::read_dir(&sdir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        hashdirs.sort();
        for hd in hashdirs {
            let mut files: Vec<String> = std::fs::read_dir(sdir.join(&hd))
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            files.sort();
            out.push((format!("{suffix}/{hd}"), files));
        }
    }
    out
}

fn assert_partition_case(
    desc: &str,
    case: &Json,
    partition_path: &Path,
    hashed: u64,
    hashes: &Hashes,
) {
    assert_eq!(
        hashed,
        case["hashed"].as_u64().unwrap(),
        "{desc}: hashed count"
    );
    let want_hashes = case["hashes"].as_object().unwrap();
    assert_eq!(
        hashes.pairs.len(),
        want_hashes.len(),
        "{desc}: suffix count in {hashes:?}"
    );
    for (suffix, value) in want_hashes {
        let got = hashes
            .get(suffix)
            .unwrap_or_else(|| panic!("{desc}: missing suffix {suffix}"));
        let want = hash_value_from_json(value);
        // EC nested dicts: compare as unordered maps
        match (&want, got) {
            (Value::Dict(w), Value::Dict(g)) => {
                assert_eq!(w.len(), g.len(), "{desc}: {suffix} frag count");
                for (k, v) in w {
                    let found = g.iter().find(|(gk, _)| gk == k);
                    assert_eq!(
                        found.map(|(_, gv)| gv),
                        Some(v),
                        "{desc}: {suffix} frag {k:?}"
                    );
                }
            }
            _ => assert_eq!(got, &want, "{desc}: suffix {suffix}"),
        }
    }
    let survivors = snapshot_tree(partition_path);
    let want_survivors = case["survivors"].as_object().unwrap();
    assert_eq!(
        survivors.len(),
        want_survivors.len(),
        "{desc}: hashdir count {survivors:?}"
    );
    for (rel, files) in &survivors {
        assert_eq!(
            files,
            &json_str_list(&want_survivors[rel]),
            "{desc}: survivors of {rel}"
        );
    }
}

#[test]
fn test_partition_hashing_matches_python() {
    let exp = expectations();
    let cfg = CleanupConfig {
        commit_window: 0.0,
        ..Default::default()
    };
    let cases = exp["partitions"].as_array().unwrap();

    // repl-basic and repl-invalidate-rehash share one evolving tree
    let dev = tmpdir("partition-repl");
    {
        let case = &cases[0];
        assert_eq!(case["desc"], "repl-basic");
        build_tree(&dev.join("objects"), &case["tree"]);
        let partition_path = dev.join("objects/1234");
        let (hashed, hashes) = get_partition_hashes(
            &partition_path,
            PolicyKind::Replication,
            &[],
            false,
            &cfg,
        )
        .unwrap();
        assert_partition_case("repl-basic", case, &partition_path, hashed, &hashes);
    }
    {
        let case = &cases[1];
        assert_eq!(case["desc"], "repl-invalidate-rehash");
        let partition_path = dev.join("objects/1234");
        for (hashdir_rel, files) in case["added"].as_object().unwrap() {
            let hd = dev.join("objects").join(hashdir_rel);
            for f in files.as_array().unwrap() {
                std::fs::write(hd.join(f.as_str().unwrap()), b"").unwrap();
            }
            invalidate_hash(hd.parent().unwrap()).unwrap();
        }
        let (hashed, hashes) = get_partition_hashes(
            &partition_path,
            PolicyKind::Replication,
            &[],
            false,
            &cfg,
        )
        .unwrap();
        assert_partition_case(
            "repl-invalidate-rehash",
            case,
            &partition_path,
            hashed,
            &hashes,
        );
    }
    std::fs::remove_dir_all(&dev).unwrap();

    {
        let case = &cases[2];
        assert_eq!(case["desc"], "ec-basic");
        let dev = tmpdir("partition-ec");
        build_tree(&dev.join("objects-2"), &case["tree"]);
        let partition_path = dev.join("objects-2/99");
        let (hashed, hashes) = get_partition_hashes(
            &partition_path,
            PolicyKind::Ec {
                n_unique_fragments: Some(6),
            },
            &[],
            false,
            &cfg,
        )
        .unwrap();
        assert_partition_case("ec-basic", case, &partition_path, hashed, &hashes);
        std::fs::remove_dir_all(&dev).unwrap();
    }
}

#[test]
fn test_xattr_chunk_layout_matches_python() {
    let exp = expectations();
    let layout = &exp["xattr_layout"];
    let blob = unhex(layout["blob"].as_str().unwrap());
    let meta = metadata_from_pickle(&blob).unwrap();

    let dir = tmpdir("xattr");
    let path = dir.join("obj.data");
    std::fs::write(&path, b"body").unwrap();
    write_metadata(&path, &meta, 254).unwrap();

    // chunk sizes must equal what Python's write_metadata produced
    let want_sizes: Vec<usize> = layout["chunk_sizes_254"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap() as usize)
        .collect();
    let mut reassembled = Vec::new();
    let mut got_sizes = Vec::new();
    for i in 0.. {
        let key = if i == 0 {
            METADATA_KEY.to_string()
        } else {
            format!("{METADATA_KEY}{i}")
        };
        match xattr::get(&path, &key).unwrap() {
            Some(chunk) => {
                got_sizes.push(chunk.len());
                reassembled.extend_from_slice(&chunk);
            }
            None => break,
        }
    }
    assert_eq!(got_sizes, want_sizes, "chunk sizes");
    assert_eq!(reassembled, blob, "reassembled blob");
    assert_eq!(
        xattr::get(&path, METADATA_CHECKSUM_KEY).unwrap().unwrap(),
        layout["checksum"].as_str().unwrap().as_bytes(),
        "checksum attr"
    );
    // and our reader agrees end to end
    assert_eq!(read_metadata(&path).unwrap(), meta);
    std::fs::remove_dir_all(&dir).unwrap();
}

// ---------------------------------------------------------------------------
// DiskFile lifecycle replay: Rust performs the same put/post/delete/commit
// operations the Python DiskFile performed at fixture-generation time and
// must produce identical trees, xattr pickle blobs, and open() results.
// ---------------------------------------------------------------------------

fn lifecycle_hash_config() -> swift_core::hashing::HashPathConfig {
    swift_core::hashing::HashPathConfig::new(b"".to_vec(), b"changeme".to_vec()).unwrap()
}

fn lifecycle_config() -> DiskFileConfig {
    DiskFileConfig {
        cleanup: CleanupConfig {
            commit_window: 0.0,
            ..Default::default()
        },
        ..Default::default()
    }
}

fn scenario_policy(case: &Json) -> (PolicyKind, u32) {
    match case["policy"].as_str().unwrap() {
        "repl" => (PolicyKind::Replication, 0),
        _ => (
            PolicyKind::Ec {
                n_unique_fragments: Some(6),
            },
            2,
        ),
    }
}

fn metadata_from_pairs(pairs: &Json) -> Metadata {
    pairs
        .as_array()
        .unwrap()
        .iter()
        .map(|pair| {
            let value = match &pair[1] {
                Json::String(s) => MetaValue::Str(s.clone()),
                Json::Number(n) => MetaValue::Int(n.as_i64().unwrap()),
                other => panic!("unexpected metadata value {other:?}"),
            };
            (MetaValue::Str(pair[0].as_str().unwrap().to_string()), value)
        })
        .collect()
}

fn build_lifecycle_diskfile(
    device: &Path,
    case: &Json,
    acco_key: &str,
) -> DiskFile {
    let (policy, policy_index) = scenario_policy(case);
    let acco = json_str_list(&case[acco_key]);
    let df = DiskFile::new(
        device,
        1234,
        &acco[0],
        &acco[1],
        &acco[2],
        policy,
        policy_index,
        &lifecycle_hash_config(),
        lifecycle_config(),
    )
    .unwrap();
    df.with_frag_index(case["frag_index"].as_i64())
}

fn tree_snapshot(datadir: &Path) -> Option<Vec<String>> {
    match std::fs::read_dir(datadir) {
        Ok(entries) => {
            let mut names: Vec<String> = entries
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();
            Some(names)
        }
        Err(_) => None,
    }
}

fn expected_tree(value: &Json) -> Option<Vec<String>> {
    value.as_array().map(|_| json_str_list(value))
}

fn read_raw_xattr_blob(path: &Path) -> String {
    let mut blob = Vec::new();
    for i in 0.. {
        let key = if i == 0 {
            METADATA_KEY.to_string()
        } else {
            format!("{METADATA_KEY}{i}")
        };
        match xattr::get(path, &key) {
            Ok(Some(chunk)) => blob.extend_from_slice(&chunk),
            _ => break,
        }
    }
    blob.iter().map(|b| format!("{b:02x}")).collect()
}

fn assert_metadata_matches(desc: &str, field: &str, got: &Metadata, want: &Json) {
    let want = want.as_object().unwrap();
    assert_eq!(got.len(), want.len(), "{desc}: {field} key count: {got:?}");
    for (key, value) in want {
        let got_value = got
            .iter()
            .find(|(k, _)| matches!(k, MetaValue::Str(s) if s == key))
            .map(|(_, v)| v)
            .unwrap_or_else(|| panic!("{desc}: {field} missing key {key}"));
        match (value, got_value) {
            (Json::String(s), MetaValue::Str(g)) => {
                assert_eq!(g, s, "{desc}: {field}[{key}]")
            }
            (Json::Number(n), MetaValue::Int(g)) => {
                assert_eq!(*g, n.as_i64().unwrap(), "{desc}: {field}[{key}]")
            }
            other => panic!("{desc}: {field}[{key}] type mismatch {other:?}"),
        }
    }
}

fn assert_open_result(
    desc: &str,
    df: &mut DiskFile,
    current_time: f64,
    want: &Json,
) {
    match df.open(Some(current_time)) {
        Err(e) => {
            let got = match e {
                DiskFileError::Deleted { .. } => "deleted",
                DiskFileError::Expired { .. } => "expired",
                DiskFileError::NotExist => "not_exist",
                DiskFileError::Collision => "collision",
                DiskFileError::Quarantined(_) => "quarantined",
                other => panic!("{desc}: unexpected open error {other}"),
            };
            assert_eq!(Some(got), want["error"].as_str(), "{desc}: open error");
            if let DiskFileError::Deleted {
                metadata,
                timestamp,
            } = e
            {
                assert_eq!(
                    timestamp.internal(),
                    want["timestamp"].as_str().unwrap(),
                    "{desc}: tombstone timestamp"
                );
                assert_metadata_matches(desc, "tombstone metadata", &metadata, &want["metadata"]);
            }
        }
        Ok(df) => {
            assert!(
                want["error"].is_null(),
                "{desc}: expected error {:?}, opened fine",
                want["error"]
            );
            assert_metadata_matches(desc, "metadata", df.get_metadata().unwrap(), &want["metadata"]);
            assert_metadata_matches(
                desc,
                "datafile_metadata",
                df.get_datafile_metadata().unwrap(),
                &want["datafile_metadata"],
            );
            match df.get_metafile_metadata().unwrap() {
                Some(mf) => assert_metadata_matches(
                    desc,
                    "metafile_metadata",
                    mf,
                    &want["metafile_metadata"],
                ),
                None => assert!(
                    want["metafile_metadata"].is_null(),
                    "{desc}: expected metafile metadata"
                ),
            }
            assert_eq!(
                df.content_length().unwrap(),
                want["content_length"].as_u64().unwrap(),
                "{desc}: content_length"
            );
            assert_eq!(
                df.timestamp().unwrap().internal(),
                want["timestamp"].as_str().unwrap(),
                "{desc}: timestamp"
            );
            assert_eq!(
                df.data_timestamp().unwrap().internal(),
                want["data_timestamp"].as_str().unwrap(),
                "{desc}: data_timestamp"
            );
            assert_eq!(
                df.content_type().unwrap(),
                want["content_type"].as_str(),
                "{desc}: content_type"
            );
            assert_eq!(
                df.content_type_timestamp().unwrap().internal(),
                want["content_type_timestamp"].as_str().unwrap(),
                "{desc}: content_type_timestamp"
            );
            assert_eq!(
                df.durable_timestamp().unwrap().map(|t| t.internal()),
                want["durable_timestamp"].as_str().map(str::to_string),
                "{desc}: durable_timestamp"
            );
        }
    }
}

#[test]
fn test_diskfile_lifecycle_matches_python() {
    let exp = expectations();
    let lifecycle = &exp["lifecycle"];
    let frozen = lifecycle["frozen_time"].as_f64().unwrap();

    for case in lifecycle["scenarios"].as_array().unwrap() {
        let desc = case["desc"].as_str().unwrap();
        let device = tmpdir(&format!("lifecycle-{desc}"));

        // replay the recorded operations with the Rust implementation
        let df = build_lifecycle_diskfile(&device, case, "acco");
        for op in case["ops"].as_array().unwrap() {
            match op["op"].as_str().unwrap() {
                "put" => {
                    let mut writer = df.create(".data").unwrap();
                    writer.write(op["body"].as_str().unwrap().as_bytes()).unwrap();
                    writer.put(metadata_from_pairs(&op["metadata"])).unwrap();
                    if op["commit"].as_bool() == Some(true) {
                        let ts: swift_core::Timestamp =
                            op["commit_timestamp"].as_str().unwrap().parse().unwrap();
                        writer.commit(&ts).unwrap();
                    }
                    writer.close();
                }
                "post" => {
                    df.write_metadata(&metadata_from_pairs(&op["metadata"])).unwrap();
                }
                "delete" => {
                    let ts: swift_core::Timestamp =
                        op["timestamp"].as_str().unwrap().parse().unwrap();
                    df.delete(&ts).unwrap();
                }
                other => panic!("{desc}: unknown op {other}"),
            }
        }

        // the resulting tree must match Python's
        assert_eq!(
            tree_snapshot(df.datadir()),
            expected_tree(&case["tree"]),
            "{desc}: tree after ops"
        );

        // where recorded, the raw pickled xattr blob must match Python's
        // byte for byte
        for blob_key in ["data_xattr_blob", "ts_xattr_blob"] {
            if let Some(want_blob) = case[blob_key].as_str() {
                if want_blob.is_empty() {
                    continue; // file was reclaimed at generation time too
                }
                let fname = expected_tree(&case["tree"])
                    .unwrap()
                    .into_iter()
                    .find(|f| {
                        f.ends_with(if blob_key == "data_xattr_blob" {
                            ".data"
                        } else {
                            ".ts"
                        })
                    })
                    .unwrap();
                assert_eq!(
                    read_raw_xattr_blob(&df.datadir().join(&fname)),
                    want_blob,
                    "{desc}: {blob_key} of {fname}"
                );
            }
        }

        // open() must behave exactly like Python's
        let acco_key = if case["collide_acco"].is_null() {
            "acco"
        } else {
            "collide_acco"
        };
        let mut opener = build_lifecycle_diskfile(&device, case, acco_key);
        if acco_key == "collide_acco" {
            opener = opener.with_datadir_override(df.datadir());
        }
        assert_open_result(desc, &mut opener, frozen, &case["open"]);

        if let Some(want) = case.get("open_before_expiry").filter(|v| !v.is_null()) {
            let mut opener = build_lifecycle_diskfile(&device, case, "acco");
            assert_open_result(&format!("{desc}/before-expiry"), &mut opener, 999999999.0, want);
        }
        if let Some(want) = case.get("open_with_prefs").filter(|v| !v.is_null()) {
            let mut opener =
                build_lifecycle_diskfile(&device, case, "acco").with_frag_prefs(Some(vec![]));
            assert_open_result(&format!("{desc}/with-prefs"), &mut opener, frozen, want);
        }

        // quarantine scenarios also record the after-state of both trees
        if !case["post_open_tree"].is_null() || case["quarantined_tree"].is_array() {
            assert_eq!(
                tree_snapshot(df.datadir()),
                expected_tree(&case["post_open_tree"]),
                "{desc}: datadir after quarantine"
            );
            let quarantined = device
                .join("quarantined")
                .join("objects")
                .join(df.datadir().file_name().unwrap());
            assert_eq!(
                tree_snapshot(&quarantined),
                expected_tree(&case["quarantined_tree"]),
                "{desc}: quarantined tree"
            );
        }

        std::fs::remove_dir_all(&device).unwrap();
    }
}

#[test]
fn test_reader_verifies_etag_and_size() {
    let device = tmpdir("reader");
    let hash_cfg = lifecycle_hash_config();
    let df = DiskFile::new(
        &device,
        7,
        "a",
        "c",
        "reader-o",
        PolicyKind::Replication,
        0,
        &hash_cfg,
        lifecycle_config(),
    )
    .unwrap();
    let body = b"read me back";
    let etag = {
        use md5::{Digest, Md5};
        format!("{:x}", Md5::digest(body))
    };
    let meta: Metadata = vec![
        ("X-Timestamp".into(), MetaValue::Str("3286000000.00000".into())),
        ("Content-Type".into(), "text/plain".into()),
        ("ETag".into(), MetaValue::Str(etag)),
        ("Content-Length".into(), MetaValue::Str(body.len().to_string())),
    ];
    let mut writer = df.create(".data").unwrap();
    writer.write(body).unwrap();
    writer.put(meta).unwrap();
    writer.close();

    let mut df2 = DiskFile::new(
        &device,
        7,
        "a",
        "c",
        "reader-o",
        PolicyKind::Replication,
        0,
        &hash_cfg,
        lifecycle_config(),
    )
    .unwrap();
    df2.open(Some(3286000001.0)).unwrap();
    let mut reader = df2.reader().unwrap();
    assert_eq!(reader.read_all().unwrap(), body);
    reader.close().unwrap();

    // corrupt the body: read must quarantine on close
    let mut df3 = DiskFile::new(
        &device,
        7,
        "a",
        "c",
        "reader-o",
        PolicyKind::Replication,
        0,
        &hash_cfg,
        lifecycle_config(),
    )
    .unwrap();
    df3.open(Some(3286000001.0)).unwrap();
    let data_file = df3.get_metadata().unwrap().len(); // force open state use
    let _ = data_file;
    std::fs::write(
        df3.datadir().join("3286000000.00000.data"),
        b"corrupt body",
    )
    .unwrap();
    let mut df4 = DiskFile::new(
        &device,
        7,
        "a",
        "c",
        "reader-o",
        PolicyKind::Replication,
        0,
        &hash_cfg,
        lifecycle_config(),
    )
    .unwrap();
    df4.open(Some(3286000001.0)).unwrap();
    let mut reader = df4.reader().unwrap();
    reader.read_all().unwrap();
    assert!(matches!(
        reader.close(),
        Err(DiskFileError::Quarantined(_))
    ));
    std::fs::remove_dir_all(&device).unwrap();
}
