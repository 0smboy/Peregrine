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
use swift_db::ContainerBroker;
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
    let mut b = ContainerBroker::new(path, "a", "c");
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
