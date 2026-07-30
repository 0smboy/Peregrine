// Copyright (c) 2026 OpenStack Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0

//! EC SSYNC end-to-end tests over real TCP sockets: duplex exchanges against
//! a live `swift-http` server, the rust sender against the rust receiver, and
//! the reconstructor's revert job moving a handoff fragment.

use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use swift_core::hashing::HashPathConfig;
use swift_diskfile::{get_data_dir, storage_directory, DiskFileConfig, PolicyKind};
use swift_http::{HeaderKeyDict, Request};
use swift_object_server::reconstructor::{
    build_part_jobs, process_part_job, EcJobType, EcSsyncStats, HttpSuffixHashFetcher,
    TcpSsyncPusher,
};
use swift_object_server::ssync_sender::{
    Sender, SsyncJob, SsyncNode, SsyncWire, TcpSsyncWire,
};
use swift_object_server::{ObjectServer, ObjectServerConfig};
use swift_ring::{Ring, RingData, RingDevice};

static NEXT_TMP: AtomicU64 = AtomicU64::new(0);

struct TestTree {
    root: PathBuf,
}

impl TestTree {
    fn new(tag: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "swift-ssync-ec-{tag}-{}-{}",
            std::process::id(),
            NEXT_TMP.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("sda1")).unwrap();
        Self { root }
    }
}

impl Drop for TestTree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn hash_config() -> HashPathConfig {
    HashPathConfig::new(b"startcap".to_vec(), b"endcap".to_vec()).unwrap()
}

const EC_POLICY: u32 = 2;

fn ec_kind() -> PolicyKind {
    PolicyKind::Ec {
        n_unique_fragments: Some(6),
    }
}

fn object_server(devices: &Path) -> ObjectServer {
    let policies = HashMap::from([
        (0, PolicyKind::Replication),
        (EC_POLICY, ec_kind()),
    ]);
    ObjectServer::new(ObjectServerConfig {
        devices: devices.to_path_buf(),
        mount_check: false,
        hash_config: hash_config(),
        diskfile: DiskFileConfig::default(),
        policies,
    })
}

/// Serve an object server on an ephemeral port; the thread lives for the
/// rest of the test process.
fn spawn_server(devices: &Path) -> SocketAddr {
    let server = Arc::new(object_server(devices));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let handler: swift_http::Handler = Arc::new(move |req| server.handle(req));
    std::thread::spawn(move || {
        let _ = swift_http::serve_forever(listener, handler);
    });
    address
}

fn request(method: &str, path: &str, headers: &[(&str, &str)], body: &[u8]) -> Request {
    let mut header_dict = HeaderKeyDict::new();
    for (key, value) in headers {
        header_dict.set(key, value);
    }
    Request {
        method: method.into(),
        path: path.into(),
        query_string: String::new(),
        headers: header_dict,
        body: body.to_vec().into(),
    }
}

/// PUT one EC fragment (durable) through a local object server instance.
fn put_fragment(
    server: &ObjectServer,
    partition: u64,
    object: &str,
    timestamp: &str,
    frag_index: i64,
    body: &[u8],
) {
    let content_length = body.len().to_string();
    let frag = frag_index.to_string();
    let policy = EC_POLICY.to_string();
    let response = server.handle(request(
        "PUT",
        &format!("/sda1/{partition}/a/c/{object}"),
        &[
            ("X-Timestamp", timestamp),
            ("Content-Type", "application/octet-stream"),
            ("Content-Length", &content_length),
            ("X-Backend-Storage-Policy-Index", &policy),
            ("X-Object-Sysmeta-Ec-Frag-Index", &frag),
            ("X-Object-Sysmeta-Ec-Etag", "deadbeef"),
        ],
        body,
    ));
    assert_eq!(response.status, 201, "fragment PUT failed: {response:?}");
}

/// The object's hash dir under a device tree.
fn hash_dir(devices: &Path, partition: u64, object: &str) -> PathBuf {
    let object_hash = hash_config()
        .hash_path("a", Some("c"), Some(object))
        .unwrap();
    devices.join("sda1").join(storage_directory(
        Path::new(&get_data_dir(EC_POLICY)),
        partition,
        &object_hash,
    ))
}

fn dir_files(dir: &Path) -> Vec<String> {
    let mut files: Vec<String> = std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    files.sort();
    files
}

fn chunk(payload: &[u8]) -> Vec<u8> {
    let mut out = format!("{:x}\r\n", payload.len()).into_bytes();
    out.extend_from_slice(payload);
    out.extend_from_slice(b"\r\n");
    out
}

/// Read protocol lines off the wire until (and including) `end`.
fn read_until(wire: &mut TcpSsyncWire, end: &[u8]) -> Vec<Vec<u8>> {
    let mut lines = Vec::new();
    loop {
        let line = wire.readline().expect("readline");
        assert!(!line.is_empty(), "receiver hung up early: {lines:?}");
        let trimmed: Vec<u8> = {
            let mut l = line.clone();
            while l.last().is_some_and(|b| b.is_ascii_whitespace()) {
                l.pop();
            }
            l
        };
        let done = trimmed == end;
        if !trimmed.is_empty() {
            lines.push(trimmed);
        }
        if done {
            return lines;
        }
    }
}

fn connect(address: SocketAddr, partition: u64, frag_index: Option<i64>) -> TcpSsyncWire {
    let node = SsyncNode {
        replication_ip: address.ip().to_string(),
        replication_port: address.port() as u32,
        device: "sda1".to_string(),
        backend_index: frag_index,
    };
    let job = SsyncJob {
        device: "unused-local".to_string(),
        partition,
        policy_index: EC_POLICY,
        policy: ec_kind(),
        frag_index,
    };
    TcpSsyncWire::connect(&node, &job, std::time::Duration::from_secs(5),
        std::time::Duration::from_secs(10)).expect("connect")
}

#[test]
fn duplex_replication_round_trip_over_a_real_socket() {
    // True duplex against a live server: read the full missing-check reply
    // BEFORE the updates section is sent.
    let tree = TestTree::new("repl");
    let address = spawn_server(&tree.root);
    let node = SsyncNode {
        replication_ip: address.ip().to_string(),
        replication_port: address.port() as u32,
        device: "sda1".to_string(),
        backend_index: None,
    };
    let job = SsyncJob {
        device: "unused".into(),
        partition: 0,
        policy_index: 0,
        policy: PolicyKind::Replication,
        frag_index: None,
    };
    let mut wire = TcpSsyncWire::connect(
        &node,
        &job,
        std::time::Duration::from_secs(5),
        std::time::Duration::from_secs(10),
    )
    .expect("connect");

    let offered = "77777777777777777777777777777777";
    wire.send(&chunk(b":MISSING_CHECK: START\r\n")).unwrap();
    wire.send(&chunk(format!("{offered} 1751500000.00000\r\n").as_bytes()))
        .unwrap();
    wire.send(&chunk(b":MISSING_CHECK: END\r\n")).unwrap();
    let lines = read_until(&mut wire, b":MISSING_CHECK: END");
    assert!(
        lines.contains(&format!("{offered} dm").into_bytes()),
        "receiver must want the offered object: {lines:?}"
    );

    // Only now send the updates section (the response arrived mid-request).
    wire.send(&chunk(b":UPDATES: START\r\n")).unwrap();
    let put = b"PUT /a/c/sock\r\n\
Content-Length: 4\r\n\
Content-Type: text/plain\r\n\
X-Timestamp: 1751500001.00000\r\n\
\r\n";
    wire.send(&chunk(put)).unwrap();
    wire.send(&chunk(b"wire")).unwrap();
    wire.send(&chunk(b":UPDATES: END\r\n")).unwrap();
    let lines = read_until(&mut wire, b":UPDATES: END");
    assert!(lines.contains(&b":UPDATES: START".to_vec()), "{lines:?}");
    wire.disconnect();

    let server = object_server(&tree.root);
    let mut got = server.handle(request("GET", "/sda1/0/a/c/sock", &[], &[]));
    assert_eq!(got.status, 200);
    assert_eq!(got.body.materialize(u64::MAX).unwrap(), b"wire");
}

#[test]
fn duplex_ec_frag_index_missing_check_and_fragment_puts_over_a_real_socket() {
    let tree = TestTree::new("ec");
    let address = spawn_server(&tree.root);
    let partition = 5u64;
    let ts = "1751500001.00000";
    let object_hash = hash_config().hash_path("a", Some("c"), Some("o1")).unwrap();

    // 1. Updates PUT with frag index 3, non-durable (X-Backend-No-Commit):
    //    must land as <ts>#3.data.
    let mut wire = connect(address, partition, Some(3));
    wire.send(&chunk(b":MISSING_CHECK: START\r\n")).unwrap();
    wire.send(&chunk(format!("{object_hash} {ts} durable:False\r\n").as_bytes()))
        .unwrap();
    wire.send(&chunk(b":MISSING_CHECK: END\r\n")).unwrap();
    let lines = read_until(&mut wire, b":MISSING_CHECK: END");
    assert!(
        lines.contains(&format!("{object_hash} dm").into_bytes()),
        "empty receiver wants the fragment: {lines:?}"
    );
    wire.send(&chunk(b":UPDATES: START\r\n")).unwrap();
    let put = format!(
        "PUT /a/c/o1\r\n\
         Content-Length: 8\r\n\
         Content-Type: application/octet-stream\r\n\
         ETag: e551cfbf2aff4e31d3682e661fa2d2f2\r\n\
         X-Backend-No-Commit: True\r\n\
         X-Object-Sysmeta-Ec-Etag: deadbeef\r\n\
         X-Object-Sysmeta-Ec-Frag-Index: 3\r\n\
         X-Timestamp: {ts}\r\n\r\n"
    );
    wire.send(&chunk(put.as_bytes())).unwrap();
    wire.send(&chunk(b"frag-3!!")).unwrap();
    wire.send(&chunk(b":UPDATES: END\r\n")).unwrap();
    read_until(&mut wire, b":UPDATES: END");
    wire.disconnect();
    let dir = hash_dir(&tree.root, partition, "o1");
    assert_eq!(
        dir_files(&dir),
        vec![format!("{ts}#3.data")],
        "non-durable fragment file"
    );

    // 2. Offering the same fragment as DURABLE makes the receiver commit its
    //    local non-durable copy instead of re-requesting the data
    //    (ssync_receiver._check_local).
    let mut wire = connect(address, partition, Some(3));
    wire.send(&chunk(b":MISSING_CHECK: START\r\n")).unwrap();
    wire.send(&chunk(format!("{object_hash} {ts}\r\n").as_bytes()))
        .unwrap();
    wire.send(&chunk(b":MISSING_CHECK: END\r\n")).unwrap();
    let lines = read_until(&mut wire, b":MISSING_CHECK: END");
    assert!(
        !lines.iter().any(|l| l.starts_with(object_hash.as_bytes())),
        "nothing wanted once the local frag can be committed: {lines:?}"
    );
    wire.send(&chunk(b":UPDATES: START\r\n")).unwrap();
    wire.send(&chunk(b":UPDATES: END\r\n")).unwrap();
    read_until(&mut wire, b":UPDATES: END");
    wire.disconnect();
    assert_eq!(
        dir_files(&dir),
        vec![format!("{ts}#3#d.data")],
        "the offer made the local fragment durable"
    );

    // 3. Frag-index-aware missing check: the same object offered under a
    //    DIFFERENT frag index is wanted (no local frag 5 diskfile).
    let mut wire = connect(address, partition, Some(5));
    wire.send(&chunk(b":MISSING_CHECK: START\r\n")).unwrap();
    wire.send(&chunk(format!("{object_hash} {ts}\r\n").as_bytes()))
        .unwrap();
    wire.send(&chunk(b":MISSING_CHECK: END\r\n")).unwrap();
    let lines = read_until(&mut wire, b":MISSING_CHECK: END");
    assert!(
        lines.contains(&format!("{object_hash} dm").into_bytes()),
        "frag 5 is missing even though frag 3 exists: {lines:?}"
    );
    wire.send(&chunk(b":UPDATES: START\r\n")).unwrap();
    // A durable PUT for frag 5 lands as <ts>#5#d.data alongside frag 3.
    let put = format!(
        "PUT /a/c/o1\r\n\
         Content-Length: 8\r\n\
         Content-Type: application/octet-stream\r\n\
         ETag: 17f91c5cde8e820492d6fb45a14776f6\r\n\
         X-Object-Sysmeta-Ec-Etag: deadbeef\r\n\
         X-Object-Sysmeta-Ec-Frag-Index: 5\r\n\
         X-Timestamp: {ts}\r\n\r\n"
    );
    wire.send(&chunk(put.as_bytes())).unwrap();
    wire.send(&chunk(b"frag-5!!")).unwrap();
    wire.send(&chunk(b":UPDATES: END\r\n")).unwrap();
    let lines = read_until(&mut wire, b":UPDATES: END");
    assert!(lines.contains(&b":UPDATES: START".to_vec()), "{lines:?}");
    wire.disconnect();
    assert_eq!(
        dir_files(&dir),
        vec![format!("{ts}#3#d.data"), format!("{ts}#5#d.data")],
        "durable subrequest PUT with a same-timestamp sibling frag index"
    );
}

#[test]
fn rust_sender_moves_a_fragment_to_the_rust_receiver() {
    let source = TestTree::new("send-src");
    let dest = TestTree::new("send-dst");
    let partition = 7u64;
    let ts = "1751500002.00000";
    let source_server = object_server(&source.root);
    put_fragment(&source_server, partition, "obj", ts, 3, b"fragment-bytes");

    let address = spawn_server(&dest.root);
    let hc = hash_config();
    let cfg = DiskFileConfig::default();
    let job = SsyncJob {
        device: "sda1".to_string(),
        partition,
        policy_index: EC_POLICY,
        policy: ec_kind(),
        frag_index: Some(3),
    };
    let node = SsyncNode {
        replication_ip: address.ip().to_string(),
        replication_port: address.port() as u32,
        device: "sda1".to_string(),
        backend_index: Some(3),
    };
    let sender = Sender {
        devices: &source.root,
        hash_config: &hc,
        diskfile_config: &cfg,
        job: &job,
        suffixes: None,
        include_non_durable: true,
        max_objects: 0,
        sync_frag_target: None,
        diskfile_builder: None,
    };
    let mut wire = TcpSsyncWire::connect(
        &node,
        &job,
        std::time::Duration::from_secs(5),
        std::time::Duration::from_secs(10),
    )
    .expect("connect");
    let report = sender.run(&mut wire).expect("ssync run");
    wire.disconnect();

    let object_hash = hc.hash_path("a", Some("c"), Some("obj")).unwrap();
    assert!(report.can_delete_objs.contains_key(&object_hash));
    assert_eq!(
        report.send_map,
        vec![(object_hash, swift_object_server::ssync_sender::Wanted { data: true, meta: true })]
    );
    // The fragment arrived durable and byte-identical.
    let dir = hash_dir(&dest.root, partition, "obj");
    assert_eq!(dir_files(&dir), vec![format!("{ts}#3#d.data")]);
    assert_eq!(
        std::fs::read(dir.join(format!("{ts}#3#d.data"))).unwrap(),
        b"fragment-bytes"
    );

    // A second run offers everything and gets nothing back: in sync.
    let sender = Sender {
        devices: &source.root,
        hash_config: &hc,
        diskfile_config: &cfg,
        job: &job,
        suffixes: None,
        include_non_durable: true,
        max_objects: 0,
        sync_frag_target: None,
        diskfile_builder: None,
    };
    let mut wire = TcpSsyncWire::connect(
        &node,
        &job,
        std::time::Duration::from_secs(5),
        std::time::Duration::from_secs(10),
    )
    .expect("reconnect");
    let report = sender.run(&mut wire).expect("second run");
    wire.disconnect();
    assert!(report.send_map.is_empty(), "{:?}", report.send_map);
}

#[test]
fn reconstructor_revert_moves_a_handoff_fragment_and_purges_it() {
    let handoff = TestTree::new("revert-src");
    let primary = TestTree::new("revert-dst");
    let partition = 0u64;
    let ts = "1751500003.00000";
    // The handoff holds a durable fragment at frag index 2 whose proper
    // primary is node 2 of the ring.
    let handoff_server = object_server(&handoff.root);
    put_fragment(&handoff_server, partition, "stray", ts, 2, b"handoff-frag");

    let address = spawn_server(&primary.root);
    let dev = |id: u64, port: u32| RingDevice {
        id,
        region: 1,
        zone: 1,
        ip: "127.0.0.1".to_string(),
        port,
        replication_ip: None,
        replication_port: None,
        device: "sda1".to_string(),
        weight: 1.0,
        meta: String::new(),
        extra: Default::default(),
    };
    // 6 "replicas" (frag indexes); node 2 is the live server.
    let devs: Vec<Option<RingDevice>> = (0..6u64)
        .map(|i| {
            Some(dev(
                i,
                if i == 2 { address.port() as u32 } else { 1 + i as u32 },
            ))
        })
        .collect();
    let r2p2d = (0..6u32).map(|i| vec![i]).collect();
    let ring = Ring::new(RingData::from_parts(devs, 32, r2p2d), hash_config());
    let part_nodes = ring.get_part_nodes(partition as u32).unwrap();

    let hc = hash_config();
    let cfg = DiskFileConfig::default();
    let cleanup = swift_diskfile::CleanupConfig::default();
    // local_dev_id 99: not a primary -> pure handoff, REVERT jobs only.
    let part_path = handoff
        .root
        .join("sda1")
        .join(get_data_dir(EC_POLICY))
        .join(partition.to_string());
    let jobs = build_part_jobs(
        &part_path,
        partition,
        "sda1",
        ec_kind(),
        &cleanup,
        &part_nodes,
        99,
        None,
    );
    assert_eq!(jobs.len(), 1, "{jobs:?}");
    assert_eq!(jobs[0].job_type, EcJobType::Revert);
    assert_eq!(jobs[0].frag_index, Some(2));
    assert_eq!(jobs[0].sync_to.len(), 1);
    assert_eq!(jobs[0].sync_to[0].replication_port, address.port() as u32);
    assert_eq!(jobs[0].primary_frag_index, None);

    let pusher = TcpSsyncPusher {
        conn_timeout: std::time::Duration::from_secs(5),
        node_timeout: std::time::Duration::from_secs(10),
    };
    let mut stats = EcSsyncStats::default();
    process_part_job(
        &handoff.root,
        &hc,
        &cfg,
        EC_POLICY,
        ec_kind(),
        &jobs[0],
        &pusher,
        &HttpSuffixHashFetcher::default(),
        None,
        &mut stats,
    );
    assert_eq!(stats.reverts, 1, "{stats:?}");
    assert_eq!(stats.failures, 0, "{stats:?}");

    // The fragment now lives durably on the primary...
    let dest_dir = hash_dir(&primary.root, partition, "stray");
    assert_eq!(dir_files(&dest_dir), vec![format!("{ts}#2#d.data")]);
    assert_eq!(
        std::fs::read(dest_dir.join(format!("{ts}#2#d.data"))).unwrap(),
        b"handoff-frag"
    );
    // ...and the handoff's copy (hash dir and suffix dir) is purged.
    let src_dir = hash_dir(&handoff.root, partition, "stray");
    assert!(!src_dir.exists(), "reverted fragment must be deleted");
    assert!(
        !src_dir.parent().unwrap().exists(),
        "emptied suffix dir is removed"
    );
}

/// A SYNC job whose local fragment index differs from the receiver's
/// backend index: the diskfile builder rebuilds the fragment at the
/// target index (obj.py reconstruct_fa / sync_diskfile_builder), and the
/// receiver stores the REBUILT bytes under the target index with a
/// recomputed etag. Without a builder the object is skipped.
#[test]
fn sync_job_rebuilds_the_fragment_at_the_receivers_index() {
    use swift_diskfile::{MetaValue, Metadata};
    use swift_object_server::ssync_sender::SyncDiskfileBuilder;

    struct FakeRebuilder;
    impl SyncDiskfileBuilder for FakeRebuilder {
        fn rebuild(
            &self,
            _object_hash: &str,
            datafile_metadata: &Metadata,
            target_frag_index: i64,
        ) -> Result<(Metadata, Vec<u8>), String> {
            // The real EcSyncRebuilder contract: local datafile metadata
            // with the frag index swapped and ETag removed.
            let mut metadata: Metadata = Vec::new();
            for (k, v) in datafile_metadata {
                if let MetaValue::Str(key) = k {
                    if key.eq_ignore_ascii_case("ETag") {
                        continue;
                    }
                    if key == "X-Object-Sysmeta-Ec-Frag-Index" {
                        metadata.push((k.clone(), MetaValue::Int(target_frag_index)));
                        continue;
                    }
                }
                metadata.push((k.clone(), v.clone()));
            }
            Ok((metadata, b"rebuilt-at-target-index".to_vec()))
        }
    }

    let source = TestTree::new("rebuild-src");
    let dest = TestTree::new("rebuild-dst");
    let partition = 9;
    let ts = "1700000600.00000";
    // The local participating fragment is index 1; the receiver wants 4.
    put_fragment(&object_server(&source.root), partition, "obj", ts, 1, b"local-frag-index-1");
    let address = spawn_server(&dest.root);
    let hc = hash_config();
    let cfg = DiskFileConfig::default();
    let job = SsyncJob {
        device: "sda1".to_string(),
        partition,
        policy_index: EC_POLICY,
        policy: ec_kind(),
        frag_index: Some(1),
    };
    let node = SsyncNode {
        replication_ip: address.ip().to_string(),
        replication_port: address.port() as u32,
        device: "sda1".to_string(),
        backend_index: Some(4),
    };

    // Without a builder: the mismatched object is skipped entirely.
    let sender = Sender {
        devices: &source.root,
        hash_config: &hc,
        diskfile_config: &cfg,
        job: &job,
        suffixes: None,
        include_non_durable: false,
        max_objects: 0,
        sync_frag_target: Some(4),
        diskfile_builder: None,
    };
    let mut wire = TcpSsyncWire::connect(
        &node,
        &job,
        std::time::Duration::from_secs(5),
        std::time::Duration::from_secs(10),
    )
    .expect("connect");
    sender.run(&mut wire).expect("ssync run");
    wire.disconnect();
    let dir = hash_dir(&dest.root, partition, "obj");
    assert!(
        !dir.exists() || dir_files(&dir).is_empty(),
        "no builder -> nothing stored"
    );

    // With the builder: the rebuilt fragment lands durable at index 4.
    let sender = Sender {
        devices: &source.root,
        hash_config: &hc,
        diskfile_config: &cfg,
        job: &job,
        suffixes: None,
        include_non_durable: false,
        max_objects: 0,
        sync_frag_target: Some(4),
        diskfile_builder: Some(&FakeRebuilder),
    };
    let mut wire = TcpSsyncWire::connect(
        &node,
        &job,
        std::time::Duration::from_secs(5),
        std::time::Duration::from_secs(10),
    )
    .expect("connect");
    sender.run(&mut wire).expect("ssync run");
    wire.disconnect();
    assert_eq!(dir_files(&dir), vec![format!("{ts}#4#d.data")]);
    assert_eq!(
        std::fs::read(dir.join(format!("{ts}#4#d.data"))).unwrap(),
        b"rebuilt-at-target-index"
    );
}

/// Live-shape repro: a partner holding one fragment vs a victim whose
/// partition is EMPTY (fragment lost, hashes invalidated) — the delta must
/// flag the suffix through the REAL REPLICATE fetch path.
#[test]
fn suffix_delta_fires_against_an_emptied_victim_partition() {
    use swift_object_server::reconstructor::{get_suffixes_to_sync, HttpSuffixHashFetcher};
    use swift_object_server::ssync_sender::SsyncNode;

    let partner = TestTree::new("delta-partner");
    let victim = TestTree::new("delta-victim");
    let partition = 89;
    let ts = "1700000700.00000";
    put_fragment(&object_server(&partner.root), partition, "obj", ts, 3, b"partner frag 3");
    // Victim: same object existed and was lost — partition dir exists with
    // empty suffix remains after invalidation/cleanup.
    let vict_server = object_server(&victim.root);
    put_fragment(&vict_server, partition, "obj", ts, 2, b"victim frag 2");
    let dir = hash_dir(&victim.root, partition, "obj");
    for f in dir_files(&dir) {
        std::fs::remove_file(dir.join(f)).unwrap();
    }
    let part_dir = victim
        .root
        .join("sda1")
        .join(get_data_dir(EC_POLICY))
        .join(partition.to_string());
    let _ = std::fs::remove_file(part_dir.join("hashes.pkl"));
    let _ = std::fs::remove_file(part_dir.join("hashes.invalid"));
    let address = spawn_server(&victim.root);

    let node = SsyncNode {
        replication_ip: address.ip().to_string(),
        replication_port: address.port() as u32,
        device: "sda1".to_string(),
        backend_index: Some(2),
    };
    let partner_part = partner
        .root
        .join("sda1")
        .join(get_data_dir(EC_POLICY))
        .join(partition.to_string());
    let suffixes = get_suffixes_to_sync(
        &partner_part,
        partition,
        ec_kind(),
        EC_POLICY,
        &DiskFileConfig::default().cleanup,
        Some(3),
        &node,
        &HttpSuffixHashFetcher::default(),
    )
    .expect("delta must not error");
    let object_hash = hash_config().hash_path("a", Some("c"), Some("obj")).unwrap();
    let suffix = object_hash[object_hash.len() - 3..].to_string();
    assert_eq!(suffixes, vec![suffix], "the lost fragment's suffix must be flagged");
}
