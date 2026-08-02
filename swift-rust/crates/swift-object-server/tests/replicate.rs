// Copyright (c) 2026 OpenStack Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0

//! Object-server REPLICATE receiver compatibility tests.

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use swift_core::pickle::{self, Value};
use swift_http::{Body, HeaderKeyDict, Request, Response};
use swift_object_server::{ContainerUpdateMode, ObjectServer, ObjectServerConfig};

const REPL_HASH: &str = "db57fb79699b56d0b801140d67a1caa1";
const EC_FRAG_HASH: &str = "8d8bc42a67759705bb3a3e1e625d3175";
const EC_DURABLE_HASH: &str = "60e9a804d2f52dc41b371046650366f4";

static NEXT_TMP: AtomicU64 = AtomicU64::new(0);

struct TestTree {
    root: PathBuf,
}

impl TestTree {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "swift-object-replicate-{}-{}",
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

fn server(devices: &Path, mount_check: bool) -> ObjectServer {
    let policies = HashMap::from([
        (0, swift_diskfile::PolicyKind::Replication),
        (
            2,
            swift_diskfile::PolicyKind::Ec {
                n_unique_fragments: Some(6),
            },
        ),
    ]);
    ObjectServer::new(ObjectServerConfig {
        devices: devices.to_path_buf(),
        mount_check,
        hash_config: swift_core::hashing::HashPathConfig::new(b"".to_vec(), b"changeme".to_vec())
            .unwrap(),
        diskfile: swift_diskfile::DiskFileConfig::default(),
        policies,
        container_update_timeout: std::time::Duration::from_secs(1),
        container_update_mode: ContainerUpdateMode::Sync,
    })
}

fn replicate(path: &str, policy: Option<&str>) -> Request {
    let mut headers = HeaderKeyDict::new();
    if let Some(policy) = policy {
        headers.set("X-Backend-Storage-Policy-Index", policy);
    }
    Request {
        method: "REPLICATE".into(),
        path: path.into(),
        query_string: String::new(),
        headers,
        body: Body::empty(),
    }
}

fn write_ondisk_file(root: &Path, data_dir: &str, partition: &str, suffix: &str, filename: &str) {
    let hash = format!("{}{}", "0".repeat(29), suffix);
    let hash_dir = root
        .join("sda1")
        .join(data_dir)
        .join(partition)
        .join(suffix)
        .join(hash);
    std::fs::create_dir_all(&hash_dir).unwrap();
    std::fs::write(hash_dir.join(filename), b"").unwrap();
}

fn body_bytes(resp: &mut Response) -> Vec<u8> {
    resp.body.materialize(u64::MAX).unwrap().to_vec()
}

fn decoded(mut resp: Response) -> Value {
    let body = body_bytes(&mut resp);
    assert_eq!(resp.status, 200, "response body: {body:?}");
    assert_eq!(&body[..2], b"\x80\x02", "must use pickle protocol 2");
    pickle::loads(&body).unwrap()
}

fn dict_get<'a>(value: &'a Value, key: &str) -> &'a Value {
    value
        .as_dict()
        .unwrap()
        .iter()
        .find_map(|(candidate, value)| match candidate {
            Value::Str(candidate) if candidate == key => Some(value),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing key {key:?} in {value:?}"))
}

fn python_asserts_pickle(body: &[u8], code: &str) {
    let mut child = Command::new("python3")
        .arg("-c")
        .arg(code)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("python3 is required for Swift interoperability tests");
    child.stdin.as_mut().unwrap().write_all(body).unwrap();
    drop(child.stdin.take());
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "Python rejected Rust pickle: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn replicate_validates_path_policy_device_and_mount() {
    let tree = TestTree::new();
    let unmounted = server(&tree.root, true);
    assert_eq!(unmounted.handle(replicate("/sda1/p", None)).status, 507);

    std::fs::write(tree.root.join("sda1/.ismount"), b"").unwrap();
    let mounted = server(&tree.root, true);
    let empty = mounted.handle(replicate("/sda1/p", None));
    assert_eq!(decoded(empty), Value::Dict(Vec::new()));
    assert!(!tree.root.join("sda1/objects/p").exists());

    let normal = server(&tree.root, false);
    assert_eq!(normal.handle(replicate("/sda1", None)).status, 400);
    assert_eq!(normal.handle(replicate("/../p", None)).status, 400);
    assert_eq!(normal.handle(replicate("/sda1/..", None)).status, 400);
    assert_eq!(normal.handle(replicate("/missing/p", None)).status, 507);

    let mut bad_policy = normal.handle(replicate("/sda1/p", Some("bogus")));
    assert_eq!(bad_policy.status, 503);
    assert_eq!(body_bytes(&mut bad_policy), b"No policy with index bogus");

    let mut unknown_policy = normal.handle(replicate("/sda1/p", Some("999")));
    assert_eq!(unknown_policy.status, 503);
    assert_eq!(body_bytes(&mut unknown_policy), b"No policy with index 999");
    assert!(!tree.root.join("sda1/objects-999").exists());
}

#[test]
fn replicate_returns_replication_hashes() {
    let tree = TestTree::new();
    write_ondisk_file(&tree.root, "objects", "p", "abc", "1751500000.00000.data");

    let value = decoded(server(&tree.root, false).handle(replicate("/sda1/p", None)));
    assert_eq!(value.as_dict().unwrap().len(), 1);
    assert_eq!(dict_get(&value, "abc"), &Value::Str(REPL_HASH.into()));
}

#[test]
fn replicate_returns_ec_fragment_and_durable_hashes() {
    let tree = TestTree::new();
    write_ondisk_file(
        &tree.root,
        "objects-2",
        "p",
        "def",
        "1751500000.00000#1#d.data",
    );

    let value = decoded(server(&tree.root, false).handle(replicate("/sda1/p", Some("2"))));
    let ec = dict_get(&value, "def").as_dict().unwrap();
    assert_eq!(ec.len(), 2);
    assert!(ec.contains(&(Value::Int(1), Value::Str(EC_FRAG_HASH.to_string()))));
    assert!(ec.contains(&(Value::None, Value::Str(EC_DURABLE_HASH.to_string()))));
}

#[test]
fn replicate_with_suffixes_only_invalidates_and_returns_none() {
    let tree = TestTree::new();
    for suffix in ["abc", "def"] {
        write_ondisk_file(&tree.root, "objects", "p", suffix, "1751500000.00000.data");
    }
    let srv = server(&tree.root, false);
    assert_eq!(
        decoded(srv.handle(replicate("/sda1/p", None)))
            .as_dict()
            .unwrap()
            .len(),
        2
    );
    let partition = tree.root.join("sda1/objects/p");
    let hashes_before = std::fs::read(partition.join("hashes.pkl")).unwrap();

    let mut response = srv.handle(replicate("/sda1/p/abc-def-not-a-suffix", None));
    let body = body_bytes(&mut response);
    assert_eq!(body, b"\x80\x02N.");
    assert_eq!(pickle::loads(&body).unwrap(), Value::None);
    assert_eq!(
        std::fs::read(partition.join("hashes.pkl")).unwrap(),
        hashes_before,
        "suffix REPLICATE must not rehash"
    );
    assert_eq!(
        std::fs::read_to_string(partition.join("hashes.invalid")).unwrap(),
        "abc\ndef\n"
    );
}

#[test]
fn rust_replicate_pickles_are_loadable_by_python() {
    let tree = TestTree::new();
    write_ondisk_file(&tree.root, "objects", "p", "abc", "1751500000.00000.data");
    write_ondisk_file(
        &tree.root,
        "objects-2",
        "p",
        "def",
        "1751500000.00000#1#d.data",
    );
    let srv = server(&tree.root, false);

    let mut repl = srv.handle(replicate("/sda1/p", None));
    python_asserts_pickle(
        &body_bytes(&mut repl),
        "import pickle, sys; raw=sys.stdin.buffer.read(); assert raw[:2] == b'\\x80\\x02'; value=pickle.loads(raw); assert value == {'abc': 'db57fb79699b56d0b801140d67a1caa1'}",
    );

    let mut ec = srv.handle(replicate("/sda1/p", Some("2")));
    python_asserts_pickle(
        &body_bytes(&mut ec),
        "import pickle, sys; raw=sys.stdin.buffer.read(); assert raw[:2] == b'\\x80\\x02'; value=pickle.loads(raw); assert value == {'def': {1: '8d8bc42a67759705bb3a3e1e625d3175', None: '60e9a804d2f52dc41b371046650366f4'}}",
    );
}
