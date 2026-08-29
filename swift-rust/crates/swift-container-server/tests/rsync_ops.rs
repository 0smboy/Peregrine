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

//! The REPLICATE rsync-staged full-DB ops (`complete_rsync` /
//! `rsync_then_merge`, db_replicator.py:1085-1130): a DB staged into
//! `<device>/tmp/` is re-id'd, optionally merged with the live DB, and
//! renamed into the partition's hash dir — the live db path is never
//! written directly.

use std::path::{Path, PathBuf};

use swift_container_server::{ContainerServer, ContainerServerConfig};
use swift_db::{shard_state, ContainerBroker, ShardRange};
use swift_http::{HeaderKeyDict, Request};

const HSH: &str = "00000000000000000000000000000abc";

fn config(devices: &Path) -> ContainerServerConfig {
    ContainerServerConfig {
        devices: devices.to_path_buf(),
        mount_check: false,
        hash_config: swift_core::hashing::HashPathConfig::new(b"".to_vec(), b"changeme".to_vec())
            .unwrap(),
        policies: vec![(0, "Policy-0".to_string())],
        default_policy_index: 0,
        fixed_created_at: Some("1751500000.00000".to_string()),
        recon_cache_path: PathBuf::from("/var/cache/swift"),
    }
}

fn replicate_req(path: &str, body: serde_json::Value) -> Request {
    Request {
        method: "REPLICATE".into(),
        path: path.into(),
        query_string: String::new(),
        headers: HeaderKeyDict::new(),
        body: body.to_string().into(),
    }
}

fn final_db_path(dir: &Path) -> PathBuf {
    dir.join("sda1")
        .join("containers")
        .join("0")
        .join("abc")
        .join(HSH)
        .join(format!("{HSH}.db"))
}

/// Build a committed container DB at `path` with `names` object rows and
/// optional metadata, then close it.
fn make_db(path: &Path, db_id: &str, names: &[&str], meta: &[(&str, &str, &str)]) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    // A received rsync file is staged under the sender id without a `.db`
    // suffix. Build it through a normal broker path first, then close and
    // rename it to the exact wire/staging name the RPC consumes.
    let broker_path = if path.extension().and_then(|v| v.to_str()) == Some("db") {
        path.to_path_buf()
    } else {
        path.with_extension("db")
    };
    let mut b = ContainerBroker::new(&broker_path, "a", "c");
    b.initialize("1751500000.00000", 0, "1751500000.00000", db_id)
        .unwrap();
    for (i, name) in names.iter().enumerate() {
        b.put_object(
            name,
            &format!("175150000{i}.00000"),
            1,
            "text/plain",
            "etag",
            0,
            0,
            None,
            None,
        )
        .unwrap();
    }
    b.commit_pending().unwrap();
    let md: swift_db::BrokerMetadata = meta
        .iter()
        .map(|(k, v, ts)| (k.to_string(), (v.to_string(), ts.to_string())))
        .collect();
    if !md.is_empty() {
        b.update_metadata(&md).unwrap();
    }
    drop(b);
    if broker_path != path {
        std::fs::rename(broker_path, path).unwrap();
    }
}

fn broker_id(b: &mut ContainerBroker) -> String {
    b.get_replication_info()
        .unwrap()
        .into_iter()
        .find(|(k, _)| k == "id")
        .and_then(|(_, v)| v.as_text())
        .unwrap()
}

fn row_names(b: &mut ContainerBroker) -> Vec<String> {
    b.get_items_since(-1, 1000)
        .unwrap()
        .into_iter()
        .map(|(_, rec)| rec.name)
        .collect()
}

#[test]
fn test_complete_rsync_adopts_staged_db() {
    let dir = std::env::temp_dir().join(format!("swift-cs-crsync-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("sda1")).unwrap();
    let server = ContainerServer::new(config(&dir));

    // a staged file that doesn't exist -> 404 (db_replicator.py:1091-1092)
    let r = replicate_req(
        &format!("/sda1/0/{HSH}"),
        serde_json::json!(["complete_rsync", "no-such-stage"]),
    );
    assert_eq!(server.handle(r).status, 404);

    // stage a real DB in <device>/tmp/<sender-db-id>
    let staged = dir.join("sda1").join("tmp").join("sender-db-id");
    make_db(&staged, "sender-db-id", &["o1", "o2"], &[]);

    let r = replicate_req(
        &format!("/sda1/0/{HSH}"),
        serde_json::json!(["complete_rsync", "sender-db-id", format!("{HSH}.db")]),
    );
    assert_eq!(server.handle(r).status, 204);

    // the staged file was renamed into the final hash-dir path...
    let final_db = final_db_path(&dir);
    assert!(final_db.exists());
    assert!(!staged.exists());
    let mut b = ContainerBroker::new(&final_db, "a", "c");
    // ...with its rows intact, a fresh id (db.py:608-617)...
    assert_eq!(row_names(&mut b), vec!["o1".to_string(), "o2".to_string()]);
    assert_ne!(broker_id(&mut b), "sender-db-id");
    // ...and the sender's incoming sync point at max row (db.py:618-622)
    assert_eq!(b.get_sync("sender-db-id", true).unwrap(), 2);

    // with the final DB present, another complete_rsync is refused
    // (db_replicator.py:1089-1090)
    let staged2 = dir.join("sda1").join("tmp").join("second-stage");
    make_db(&staged2, "second-stage", &["x"], &[]);
    let r = replicate_req(
        &format!("/sda1/0/{HSH}"),
        serde_json::json!(["complete_rsync", "second-stage"]),
    );
    assert_eq!(server.handle(r).status, 404);
    assert!(staged2.exists(), "staged file must be left untouched");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn test_complete_rsync_keeps_epoch_suffix() {
    // Python `os.path.basename(broker.db_file)` for a SHARDED replica is
    // `<hash>_<epoch>.db`. Completing as `<hash>.db` recreates the retiring
    // file next to the epoch DB (probe L1347/L1375).
    let dir = std::env::temp_dir().join(format!("swift-cs-crsync-epoch-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("sda1")).unwrap();
    let server = ContainerServer::new(config(&dir));
    let staged = dir.join("sda1").join("tmp").join("sender-epoch-id");
    make_db(&staged, "sender-epoch-id", &["o1"], &[]);
    let epoch_name = format!("{HSH}_1751500010.00000.db");
    let r = replicate_req(
        &format!("/sda1/0/{HSH}"),
        serde_json::json!(["complete_rsync", "sender-epoch-id", epoch_name]),
    );
    assert_eq!(server.handle(r).status, 204);
    let hash_dir = dir
        .join("sda1")
        .join("containers")
        .join("0")
        .join("abc")
        .join(HSH);
    let epoch_db = hash_dir.join(&epoch_name);
    let unsuffixed = hash_dir.join(format!("{HSH}.db"));
    assert!(epoch_db.exists(), "epoch dest must exist: {epoch_db:?}");
    assert!(
        !unsuffixed.exists(),
        "must not recreate retiring unsuffixed db: {unsuffixed:?}"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn test_complete_rsync_refuses_unsuffixed_next_to_epoch() {
    let dir = std::env::temp_dir().join(format!("swift-cs-crsync-guard-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("sda1")).unwrap();
    let server = ContainerServer::new(config(&dir));
    let hash_dir = dir
        .join("sda1")
        .join("containers")
        .join("0")
        .join("abc")
        .join(HSH);
    let epoch_db = hash_dir.join(format!("{HSH}_1751500010.00000.db"));
    make_db(&epoch_db, "epoch-id", &["keep"], &[]);
    let staged = dir.join("sda1").join("tmp").join("sender-plain");
    make_db(&staged, "sender-plain", &["x"], &[]);
    let r = replicate_req(
        &format!("/sda1/0/{HSH}"),
        serde_json::json!(["complete_rsync", "sender-plain", format!("{HSH}.db")]),
    );
    assert_eq!(
        server.handle(r).status,
        404,
        "must not recreate retiring file"
    );
    let unsuffixed = hash_dir.join(format!("{HSH}.db"));
    assert!(!unsuffixed.exists(), "{unsuffixed:?}");
    assert!(epoch_db.exists());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn test_rsync_then_merge_merges_existing_into_staged() {
    let dir = std::env::temp_dir().join(format!("swift-cs-rtm-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("sda1")).unwrap();
    let server = ContainerServer::new(config(&dir));

    // both the live DB and the staged file must exist
    // (db_replicator.py:1098-1100, 1107-1109)
    let r = replicate_req(
        &format!("/sda1/0/{HSH}"),
        serde_json::json!(["rsync_then_merge", "stage-xyz"]),
    );
    assert_eq!(server.handle(r).status, 404);

    // live DB: two rows the sender doesn't have, plus local metadata
    let final_db = final_db_path(&dir);
    make_db(
        &final_db,
        "peer-db-id",
        &["e1", "e2"],
        &[("X-Container-Meta-Old", "1", "0000000010.00000")],
    );
    // tmp missing while the live DB exists -> still 404
    let r = replicate_req(
        &format!("/sda1/0/{HSH}"),
        serde_json::json!(["rsync_then_merge", "stage-xyz"]),
    );
    assert_eq!(server.handle(r).status, 404);

    // staged (sender's) DB: three other rows and its own metadata
    let staged = dir.join("sda1").join("tmp").join("stage-xyz");
    make_db(
        &staged,
        "sender-db-id",
        &["n1", "n2", "n3"],
        &[("X-Container-Meta-New", "2", "0000000011.00000")],
    );

    let r = replicate_req(
        &format!("/sda1/0/{HSH}"),
        serde_json::json!(["rsync_then_merge", "stage-xyz"]),
    );
    assert_eq!(server.handle(r).status, 204);
    assert!(!staged.exists());

    // the final DB now holds BOTH row sets (db_replicator.py:1112-1119)...
    let mut b = ContainerBroker::new(&final_db, "a", "c");
    let mut names = row_names(&mut b);
    names.sort();
    assert_eq!(names, vec!["e1", "e2", "n1", "n2", "n3"]);
    // ...the existing DB's metadata merged over (db_replicator.py:1124)...
    let md = b.metadata().unwrap();
    let get = |k: &str| {
        md.iter()
            .find(|(key, _)| key == k)
            .map(|(_, (v, _))| v.clone())
    };
    assert_eq!(get("X-Container-Meta-Old"), Some("1".to_string()));
    assert_eq!(get("X-Container-Meta-New"), Some("2".to_string()));
    // ...a fresh id, and the staged name's sync point at the merged max
    // row (db_replicator.py:1123, db.py:608-622)
    assert_ne!(broker_id(&mut b), "sender-db-id");
    assert_ne!(broker_id(&mut b), "peer-db-id");
    assert_eq!(b.get_sync("stage-xyz", true).unwrap(), 5);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn test_replicate_sync_uses_epoch_db_when_hash_db_unlinked() {
    // Python `_db_file_exists` is `bool(get_db_files(path))`. After
    // set_sharded_state the retiring unsuffixed file is gone. Probe L2321:
    // unsharded→sharded REPLICATE sync must not 404, so the third replica
    // can pull shard ranges (object rows stay skipped).
    let dir = std::env::temp_dir().join(format!("swift-cs-sync-epoch-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("sda1")).unwrap();
    let db = final_db_path(&dir);
    make_db(&db, "retiring-id", &["o1"], &[]);
    let epoch = "1751500010.00000";
    let mut b = ContainerBroker::new(&db, "a", "c");
    let mut own = ShardRange::new("a/c", epoch, "", "");
    own.state = shard_state::SHARDING;
    own.epoch = Some(epoch.into());
    let mut r0 = ShardRange::new(".shards_a/c-0", epoch, "", "m");
    r0.state = shard_state::ACTIVE;
    let mut r1 = ShardRange::new(".shards_a/c-1", epoch, "m", "");
    r1.state = shard_state::ACTIVE;
    b.merge_shard_ranges(vec![own, r0, r1]).unwrap();
    b.enable_sharding(epoch).unwrap();
    assert!(b.set_sharding_state().unwrap());
    assert!(b.set_sharded_state().unwrap());
    drop(b);
    assert!(!db.exists(), "retiring {db:?} must be unlinked");
    let files = swift_db::get_db_files(&db);
    assert_eq!(files.len(), 1, "{files:?}");
    assert!(
        files[0]
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .contains('_'),
        "remaining file must be epoch-suffixed: {files:?}"
    );

    let server = ContainerServer::new(config(&dir));
    let sync = replicate_req(
        &format!("/sda1/0/{HSH}"),
        serde_json::json!([
            "sync",
            -1,
            "h",
            "peer-id",
            "1751500000.00000",
            "1751500000.00000",
            "0",
            "{}"
        ]),
    );
    let resp = server.handle(sync);
    assert_eq!(
        resp.status, 200,
        "REPLICATE sync against epoch-only SHARDED db must not 404, got {}",
        resp.status
    );
    if let swift_http::Body::Buffered(bytes) = &resp.body {
        let v: serde_json::Value = serde_json::from_slice(bytes).unwrap_or_default();
        assert_eq!(
            v.get("db_state").and_then(|x| x.as_str()),
            Some("sharded"),
            "sync info must advertise sharded so the sender skips object usync: {v}"
        );
    } else {
        panic!("sync body was not buffered");
    }

    let get = replicate_req(
        &format!("/sda1/0/{HSH}"),
        serde_json::json!(["get_shard_ranges"]),
    );
    let resp = server.handle(get);
    assert_eq!(resp.status, 200, "get_shard_ranges got {}", resp.status);
    let mut check = ContainerBroker::new(&files[0], "a", "c");
    let got = check.get_all_shard_range_data().unwrap();
    assert!(
        got.iter().filter(|r| r.deleted == 0).count() >= 2,
        "SHARDED epoch db must still have shard ranges for the third replica to pull: {got:?}"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}
