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

//! Automatic DB replication: replicate_container_db drives the full
//! sync+usync protocol against a live peer container server; the peer
//! converges to the source's object rows.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use swift_container_server::{serve, ContainerServerConfig};
use swift_db::{replicate_container_db, ContainerBroker};

fn hash_cfg() -> swift_core::hashing::HashPathConfig {
    swift_core::hashing::HashPathConfig::new(b"".to_vec(), b"changeme".to_vec()).unwrap()
}

fn tmpdir() -> PathBuf {
    static NEXT_TMPDIR: AtomicU64 = AtomicU64::new(0);
    let unique = NEXT_TMPDIR.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("swift-dbrepl-{}-{unique}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

#[test]
fn test_replicate_container_db_converges() {
    let tmp = tmpdir();
    let account = "a";
    let container = "sync";
    let hsh = hash_cfg()
        .hash_path(account, Some(container), None)
        .unwrap();
    let suffix = &hsh[hsh.len() - 3..];
    let db_rel = format!("containers/0/{suffix}/{hsh}/{hsh}.db");

    // source on sda1 with three objects (one a delete marker)
    std::fs::create_dir_all(tmp.join("sda1")).unwrap();
    let src_db = tmp.join("sda1").join(&db_rel);
    let mut src = ContainerBroker::new(&src_db, account, container);
    src.initialize("1751500000.00000", 0, "1751500000.00000", "src-id-xyz")
        .unwrap();
    src.put_object(
        "a1",
        "1751500002.00000",
        5,
        "text/a",
        "ea",
        0,
        0,
        None,
        None,
    )
    .unwrap();
    src.put_object(
        "a2",
        "1751500003.00000",
        7,
        "text/b",
        "eb",
        0,
        0,
        None,
        None,
    )
    .unwrap();
    src.delete_object("gone", "1751500004.00000", 0).unwrap();
    src.get_info().unwrap();

    // empty peer DB on sdb1, served by a live container server
    std::fs::create_dir_all(tmp.join("sdb1")).unwrap();
    let peer_db = tmp.join("sdb1").join(&db_rel);
    let mut peer = ContainerBroker::new(&peer_db, account, container);
    peer.initialize("1751500000.00000", 0, "1751500000.00000", "peer-id-xyz")
        .unwrap();
    peer.get_info().unwrap();

    let config = ContainerServerConfig {
        devices: tmp.clone(),
        mount_check: false,
        hash_config: hash_cfg(),
        policies: vec![(0, "Policy-0".to_string())],
        default_policy_index: 0,
        fixed_created_at: None,
    };
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || serve(listener, config));
    std::thread::sleep(std::time::Duration::from_millis(120));

    // run the replication pass source -> peer
    let outcome =
        replicate_container_db(&mut src, "src-id-xyz", &addr.to_string(), "sdb1", "0", &hsh)
            .unwrap();
    assert_eq!(outcome.rows_pushed, 3, "all three rows pushed");
    assert_eq!(outcome.diffs, 1);

    // the peer now has the same three object rows...
    let mut peer2 = ContainerBroker::new(&peer_db, account, container);
    let mut names: Vec<String> = peer2
        .object_rows()
        .unwrap()
        .iter()
        .map(|r| match &r[1] {
            swift_db::DbValue::Text(s) => s.clone(),
            _ => String::new(),
        })
        .collect();
    names.sort();
    assert_eq!(
        names,
        vec!["a1".to_string(), "a2".to_string(), "gone".to_string()]
    );
    // ...and recorded the source's high-water mark
    assert_eq!(peer2.get_sync("src-id-xyz", true).unwrap(), 3);

    // a second pass is a no-op (nothing new to push)
    let outcome2 =
        replicate_container_db(&mut src, "src-id-xyz", &addr.to_string(), "sdb1", "0", &hsh)
            .unwrap();
    assert_eq!(outcome2.rows_pushed, 0, "idempotent second pass");
    assert_eq!(outcome2.diffs, 0);
    std::fs::remove_dir_all(&tmp).unwrap();
}

#[test]
fn test_replicate_container_db_copies_shard_ranges() {
    // G6 test_sharder: Python ContainerReplicator._sync_shard_ranges.
    // Without merge_shard_ranges RPC, node 0 had ranges and nodes 1/2 had 0
    // (AssertionError 3 != 0).
    use swift_db::{shard_state, GetShardRangesArgs, ShardRange};

    let tmp = tmpdir();
    let account = "AUTH_test";
    let container = "sharded";
    let hsh = hash_cfg()
        .hash_path(account, Some(container), None)
        .unwrap();
    let suffix = &hsh[hsh.len() - 3..];
    let db_rel = format!("containers/0/{suffix}/{hsh}/{hsh}.db");

    std::fs::create_dir_all(tmp.join("sda1")).unwrap();
    let src_db = tmp.join("sda1").join(&db_rel);
    let mut src = ContainerBroker::new(&src_db, account, container);
    src.initialize("1751500000.00000", 0, "1751500000.00000", "src-id-xyz")
        .unwrap();
    for i in 0..4 {
        src.put_object(
            &format!("o{i}"),
            "1751500002.00000",
            1,
            "text/plain",
            "e",
            0,
            0,
            None,
            None,
        )
        .unwrap();
    }
    let sr0 = ShardRange {
        state: shard_state::FOUND,
        object_count: 2,
        ..ShardRange::new(".shards_AUTH_test/c-0", "1751500010.00000", "", "o1")
    };
    let sr1 = ShardRange {
        state: shard_state::FOUND,
        object_count: 2,
        ..ShardRange::new(".shards_AUTH_test/c-1", "1751500010.00000", "o1", "")
    };
    src.merge_shard_ranges(vec![sr0, sr1]).unwrap();

    std::fs::create_dir_all(tmp.join("sdb1")).unwrap();
    let peer_db = tmp.join("sdb1").join(&db_rel);
    let mut peer = ContainerBroker::new(&peer_db, account, container);
    peer.initialize("1751500000.00000", 0, "1751500000.00000", "peer-id-xyz")
        .unwrap();

    let config = ContainerServerConfig {
        devices: tmp.clone(),
        mount_check: false,
        hash_config: hash_cfg(),
        policies: vec![(0, "Policy-0".to_string())],
        default_policy_index: 0,
        fixed_created_at: None,
    };
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || serve(listener, config));
    std::thread::sleep(std::time::Duration::from_millis(120));

    replicate_container_db(&mut src, "src-id-xyz", &addr.to_string(), "sdb1", "0", &hsh).unwrap();

    let mut peer2 = ContainerBroker::new(&peer_db, account, container);
    let got = peer2
        .get_shard_ranges(&GetShardRangesArgs::default())
        .unwrap();
    assert_eq!(
        got.len(),
        2,
        "peer must receive both shard ranges, got {got:?}"
    );
    std::fs::remove_dir_all(&tmp).unwrap();
}
