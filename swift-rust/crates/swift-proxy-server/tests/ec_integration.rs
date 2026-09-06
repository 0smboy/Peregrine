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

//! End-to-end erasure coding: a real Rust proxy fronting real Rust account,
//! container, and `k + m` object servers. The proxy encodes the object into
//! fragment archives (via `swift-ec`/liberasurecode), fans one to each object
//! server, and later gathers `ndata` fragments and decodes them back. Also
//! proves EC redundancy: the object still reads after `nparity` fragments are
//! destroyed on disk.
//!
//! Requires the `ec` feature (liberasurecode); the whole module is gated on it.
#![cfg(feature = "ec")]

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use swift_proxy_server::{EcPolicyParams, ProxyApp, ProxyConfig};
use swift_ring::{Ring, RingData, RingDevice};

const K: usize = 4;
const M: usize = 2;
const N: usize = K + M;
const EC_POLICY: i64 = 1;
const SEGMENT_SIZE: usize = 1024; // small, to force a multi-segment archive

/// liberasurecode is process-global; two Hyper EC clusters in one test
/// binary SIGSEGV if they encode at the same time.
static EC_CLUSTER_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn hash_cfg() -> swift_core::hashing::HashPathConfig {
    swift_core::hashing::HashPathConfig::new(b"".to_vec(), b"changeme".to_vec()).unwrap()
}

fn dev(id: u32, port: u32) -> RingDevice {
    RingDevice {
        id: id as u64,
        region: 1,
        zone: 1,
        ip: "127.0.0.1".to_string(),
        port,
        replication_ip: None,
        replication_port: None,
        device: "sda1".to_string(),
        weight: 100.0,
        meta: String::new(),
        extra: serde_json::Map::new(),
    }
}

fn single_device_ring(port: u32) -> Ring {
    let data = RingData::from_parts(
        vec![Some(dev(0, port))],
        32,
        vec![vec![0], vec![0], vec![0]],
    );
    Ring::new(data, hash_cfg())
}

/// One partition, `ports.len()` replicas: replica `i`, part 0 -> device `i`.
fn multi_device_ring(ports: &[u32]) -> Ring {
    let devs: Vec<Option<RingDevice>> = ports
        .iter()
        .enumerate()
        .map(|(i, &p)| Some(dev(i as u32, p)))
        .collect();
    let r2p2d: Vec<Vec<u32>> = (0..ports.len() as u32).map(|i| vec![i]).collect();
    let data = RingData::from_parts(devs, 32, r2p2d);
    Ring::new(data, hash_cfg())
}

fn http(
    addr: std::net::SocketAddr,
    method: &str,
    target: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let mut conn = std::net::TcpStream::connect(addr).unwrap();
    let mut req = format!("{method} {target} HTTP/1.1\r\nHost: t\r\n");
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    ));
    conn.write_all(req.as_bytes()).unwrap();
    conn.write_all(body).unwrap();
    let mut raw = Vec::new();
    conn.read_to_end(&mut raw).unwrap();
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let out_body = raw[split + 4..].to_vec();
    let mut lines = head.lines();
    let status: u16 = lines
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let hdrs = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    (status, hdrs, out_body)
}

/// Recursively collect files under `dir` whose name matches `pred`.
fn find_files(dir: &Path, pred: &dyn Fn(&str) -> bool) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(find_files(&p, pred));
        } else if p.file_name().and_then(|n| n.to_str()).is_some_and(pred) {
            out.push(p);
        }
    }
    out
}

/// Chunked-transfer PUT (no Content-Length): one chunk + terminator.
fn http_chunked(
    addr: std::net::SocketAddr,
    target: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let mut conn = std::net::TcpStream::connect(addr).unwrap();
    let mut req = format!("PUT {target} HTTP/1.1\r\nHost: t\r\n");
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n");
    conn.write_all(req.as_bytes()).unwrap();
    if !body.is_empty() {
        conn.write_all(format!("{:x}\r\n", body.len()).as_bytes())
            .unwrap();
        conn.write_all(body).unwrap();
        conn.write_all(b"\r\n").unwrap();
    }
    conn.write_all(b"0\r\n\r\n").unwrap();
    let mut raw = Vec::new();
    conn.read_to_end(&mut raw).unwrap();
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let out_body = raw[split + 4..].to_vec();
    let mut lines = head.lines();
    let status: u16 = lines
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let hdrs = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    (status, hdrs, out_body)
}

fn md5_hex(data: &[u8]) -> String {
    use md5::{Digest, Md5};
    format!("{:x}", Md5::digest(data))
}

/// Policy 0 is replication (`objects/`). Policy 1 is EC (`objects-1/`).
/// InternalClient GET omits `X-Backend-Storage-Policy-Index`; if the proxy
/// falls through to policy 0 it 404s even when every fragment is on disk.
///
/// `serve()` is Hyper `handle_async` — the same path isolated `:18080` hits.
fn boot_ec_cluster(tmp: &Path) -> (std::net::SocketAddr, Vec<PathBuf>) {
    boot_ec_cluster_inner(tmp, None)
}

fn boot_ec_cluster_logged(
    tmp: &Path,
) -> (std::net::SocketAddr, Vec<PathBuf>, Arc<Mutex<Vec<String>>>) {
    let lines = Arc::new(Mutex::new(Vec::new()));
    let sink_lines = Arc::clone(&lines);
    let sink: Arc<dyn Fn(&str) + Send + Sync> = Arc::new(move |msg: &str| {
        sink_lines.lock().unwrap().push(msg.to_string());
    });
    let (addr, dirs) = boot_ec_cluster_inner(tmp, Some(sink));
    (addr, dirs, lines)
}

fn boot_ec_cluster_inner(
    tmp: &Path,
    log_sink: Option<Arc<dyn Fn(&str) + Send + Sync>>,
) -> (std::net::SocketAddr, Vec<PathBuf>) {
    let acct_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let acct_addr = acct_listener.local_addr().unwrap();
    std::fs::create_dir_all(tmp.join("acct/sda1")).unwrap();
    let acct_config = swift_account_server::AccountServerConfig {
        devices: tmp.join("acct"),
        mount_check: false,
        hash_config: hash_cfg(),
        policies: vec![(0, "Policy-0".to_string()), (1, "Policy-1".to_string())],
        fixed_created_at: None,
    };
    std::thread::spawn(move || swift_account_server::serve(acct_listener, acct_config));

    let cont_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let cont_addr = cont_listener.local_addr().unwrap();
    std::fs::create_dir_all(tmp.join("cont/sda1")).unwrap();
    let cont_config = swift_container_server::ContainerServerConfig {
        devices: tmp.join("cont"),
        mount_check: false,
        hash_config: hash_cfg(),
        policies: vec![(0, "Policy-0".to_string()), (1, "Policy-1".to_string())],
        default_policy_index: 0,
        recon_cache_path: tmp.join("recon"),
        fixed_created_at: None,
    };
    std::thread::spawn(move || swift_container_server::serve(cont_listener, cont_config));

    let mut obj_ports = Vec::new();
    let mut obj_dirs = Vec::new();
    for i in 0..N {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        obj_ports.push(addr.port() as u32);
        let dir = tmp.join(format!("obj{i}"));
        std::fs::create_dir_all(dir.join("sda1")).unwrap();
        obj_dirs.push(dir.clone());
        let policies = std::collections::HashMap::from([
            (0, swift_diskfile::PolicyKind::Replication),
            (
                EC_POLICY as u32,
                swift_diskfile::PolicyKind::Ec {
                    n_unique_fragments: Some(N as u32),
                },
            ),
        ]);
        let config = swift_object_server::ObjectServerConfig {
            devices: dir,
            mount_check: false,
            hash_config: hash_cfg(),
            diskfile: swift_diskfile::DiskFileConfig::default(),
            policies,
            container_update_timeout: std::time::Duration::from_secs(1),
            container_update_mode: swift_object_server::ContainerUpdateMode::Sync,
        };
        std::thread::spawn(move || swift_object_server::serve(listener, config));
    }

    let ec_ring = multi_device_ring(&obj_ports);
    let mut object_rings = std::collections::HashMap::new();
    object_rings.insert(EC_POLICY, ec_ring.clone());
    let mut ec_policies = std::collections::HashMap::new();
    ec_policies.insert(
        EC_POLICY,
        EcPolicyParams {
            ndata: K,
            nparity: M,
            segment_size: SEGMENT_SIZE,
            min_parity: 1,
        },
    );
    let proxy_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let mut app = ProxyApp::with_ec_policies(
        single_device_ring(acct_addr.port() as u32),
        single_device_ring(cont_addr.port() as u32),
        ec_ring,
        object_rings,
        ec_policies,
        ProxyConfig {
            account_autocreate: true,
            ..Default::default()
        },
    );
    app.policy_name_to_index.insert("policy-1".to_string(), 1);
    let app = if let Some(sink) = log_sink {
        app.with_log_sink(sink)
    } else {
        app
    };
    let app = Arc::new(app);
    std::thread::spawn(move || swift_proxy_server::serve(proxy_listener, app));
    std::thread::sleep(std::time::Duration::from_millis(300));
    (proxy_addr, obj_dirs)
}

fn rmtree_one_durable_hash_dir(obj_dirs: &[PathBuf]) -> PathBuf {
    let victim = obj_dirs
        .iter()
        .find_map(|d| {
            let frags = find_files(d, &|n| n.ends_with("#d.data"));
            frags.into_iter().next()
        })
        .expect("a durable fragment to delete");
    let hash_dir = victim.parent().expect("hash dir").to_path_buf();
    std::fs::remove_dir_all(&hash_dir).unwrap();
    hash_dir
}

#[test]
fn test_ec_object_put_get_round_trip_and_fragment_loss() {
    let _ec = EC_CLUSTER_LOCK.lock().unwrap();
    let tmp = std::env::temp_dir().join(format!("swift-ec-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    let (proxy_addr, obj_dirs) = boot_ec_cluster(&tmp);

    // create the container ON THE EC POLICY (autocreates the account) —
    // updates for policy-1 objects are filtered out of a policy-0
    // container's listings as misplaced rows.
    let (status, _, _) = http(
        proxy_addr,
        "PUT",
        "/v1/AUTH_ec/ecbox",
        &[("X-Storage-Policy", "Policy-1")],
        b"",
    );
    assert_eq!(status, 201, "container PUT");

    // a multi-segment payload (deterministic, spans several 1 KiB segments)
    let payload: Vec<u8> = (0..3500u32)
        .map(|i| (i.wrapping_mul(31) % 251) as u8)
        .collect();

    // EC PUT through the proxy: encode -> fan k+m fragments out to the nodes
    let (status, _, _) = http(
        proxy_addr,
        "PUT",
        "/v1/AUTH_ec/ecbox/big.bin",
        &[
            ("Content-Type", "text/plain"),
            ("X-Backend-Storage-Policy-Index", "1"),
        ],
        &payload,
    );
    assert_eq!(status, 201, "EC object PUT");

    // every object server holds exactly one durable fragment (<ts>#<fi>#d.data)
    let mut durable = 0;
    for d in &obj_dirs {
        let frags = find_files(d, &|n| n.ends_with("#d.data"));
        assert!(
            frags.len() <= 1,
            "one durable fragment per node, got {frags:?}"
        );
        durable += frags.len();
    }
    assert_eq!(
        durable, N,
        "all {N} fragments landed durable, got {durable}"
    );

    // The normal PUT's container update records the WHOLE OBJECT's etag/size
    // (the footers' overrides), not the fragment archive's. Check this before
    // staging a newer non-durable generation: Python still emits a container
    // update for that internal PUT, while object GET durability is independent.
    let (status, _, listing) = http(proxy_addr, "GET", "/v1/AUTH_ec/ecbox?format=json", &[], b"");
    assert_eq!(status, 200, "container listing");
    let entries: serde_json::Value = serde_json::from_slice(&listing).unwrap();
    let entry = entries
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["name"] == "big.bin")
        .expect("big.bin listed");
    assert_eq!(entry["bytes"], serde_json::json!(payload.len()));
    assert_eq!(entry["hash"], serde_json::json!(md5_hex(&payload)));

    // An internal caller may stage a newer EC generation without committing
    // it.  The proxy must carry X-Backend-No-Commit to every object node; the
    // old durable generation remains the client-visible object while the new
    // fragments coexist on disk without #d.
    let staged_payload: Vec<u8> = (0..4200u32)
        .map(|i| (i.wrapping_mul(47).wrapping_add(3) % 251) as u8)
        .collect();
    let (status, _, _) = http(
        proxy_addr,
        "PUT",
        "/v1/AUTH_ec/ecbox/big.bin",
        &[
            ("Content-Type", "text/plain"),
            ("X-Backend-Storage-Policy-Index", "1"),
            ("X-Backend-No-Commit", "True"),
        ],
        &staged_payload,
    );
    assert_eq!(status, 201, "non-durable EC object PUT");
    let mut nondurable = 0;
    for d in &obj_dirs {
        nondurable += find_files(d, &|n| n.ends_with(".data") && !n.ends_with("#d.data")).len();
    }
    assert_eq!(
        nondurable, N,
        "all {N} staged fragments must remain non-durable"
    );

    // EC GET through the proxy: gather ndata fragments and decode
    let (status, headers, body) = http(
        proxy_addr,
        "GET",
        "/v1/AUTH_ec/ecbox/big.bin",
        &[("X-Backend-Storage-Policy-Index", "1")],
        b"",
    );
    assert_eq!(status, 200, "EC object GET");
    assert_eq!(body, payload, "EC object body round-trips after decode");
    let backend_data_timestamp = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("X-Backend-Data-Timestamp"))
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    let backend_durable_timestamp = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("X-Backend-Durable-Timestamp"))
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    assert!(!backend_data_timestamp.is_empty(), "backend data timestamp");
    assert_eq!(
        backend_data_timestamp, backend_durable_timestamp,
        "a normal EC GET must expose its selected durable generation to InternalClient"
    );
    let cl = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("Content-Length"))
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    assert_eq!(
        cl,
        payload.len().to_string(),
        "Content-Length is the object size"
    );

    // Official probe POSTs after PUT. Field `9a95747` still 404'd proxy_get
    // after once when remaining ndata 200s had data_ts=PUT and
    // durable_ts=POST — gather keyed durable set membership by data_ts.
    let (status, _, _) = http(
        proxy_addr,
        "POST",
        "/v1/AUTH_ec/ecbox/big.bin",
        &[
            ("X-Object-Meta-Color", "red"),
            ("X-Backend-Storage-Policy-Index", "1"),
        ],
        b"",
    );
    assert_eq!(status, 202, "EC object POST-after-PUT");
    let (status, _, body) = http(
        proxy_addr,
        "GET",
        "/v1/AUTH_ec/ecbox/big.bin",
        &[("X-Backend-Storage-Policy-Index", "1")],
        b"",
    );
    assert_eq!(status, 200, "EC GET after POST-after-PUT");
    assert_eq!(
        body, payload,
        "POST must not split the durable EC generation"
    );
    // Official proxy_get is InternalClient: no policy index header.
    let (status, _, body) = http(proxy_addr, "GET", "/v1/AUTH_ec/ecbox/big.bin", &[], b"");
    assert_eq!(
        status, 200,
        "InternalClient-shaped GET after POST must use the container EC policy"
    );
    assert_eq!(body, payload);

    // EC redundancy: destroy nparity fragments and confirm the object still
    // decodes from the surviving ndata.
    for d in obj_dirs.iter().take(M) {
        for f in find_files(d, &|n| n.ends_with(".data")) {
            std::fs::remove_file(&f).unwrap();
        }
    }
    let (status, _, body) = http(
        proxy_addr,
        "GET",
        "/v1/AUTH_ec/ecbox/big.bin",
        &[("X-Backend-Storage-Policy-Index", "1")],
        b"",
    );
    assert_eq!(status, 200, "EC GET survives loss of {M} fragments");
    assert_eq!(body, payload, "EC decode from ndata surviving fragments");

    // The client-facing ETag is the whole-object md5 too.
    let (status, headers, _) = http(
        proxy_addr,
        "HEAD",
        "/v1/AUTH_ec/ecbox/big.bin",
        &[("X-Backend-Storage-Policy-Index", "1")],
        b"",
    );
    assert_eq!(status, 200);
    let etag = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("ETag"))
        .map(|(_, v)| v.trim_matches('"').to_string())
        .unwrap_or_default();
    assert_eq!(etag, md5_hex(&payload), "ETag is the whole-object md5");

    // ---- streaming edge cases on the same cluster ----

    // Empty object: python-parity zero-byte fragment archives, empty GET.
    let (status, _, _) = http(
        proxy_addr,
        "PUT",
        "/v1/AUTH_ec/ecbox/empty.bin",
        &[
            ("Content-Type", "application/octet-stream"),
            ("X-Backend-Storage-Policy-Index", "1"),
        ],
        b"",
    );
    assert_eq!(status, 201, "empty EC PUT");
    let mut empty_archives = 0;
    for d in &obj_dirs {
        for f in find_files(d, &|n| n.ends_with("#d.data")) {
            // only the new object's fragments are zero-length
            if std::fs::metadata(&f).unwrap().len() == 0 {
                empty_archives += 1;
            }
        }
    }
    assert_eq!(
        empty_archives, N,
        "zero-byte object stores zero-byte archives on every node"
    );
    let (status, headers, body) = http(
        proxy_addr,
        "GET",
        "/v1/AUTH_ec/ecbox/empty.bin",
        &[("X-Backend-Storage-Policy-Index", "1")],
        b"",
    );
    assert_eq!(status, 200, "empty EC GET");
    assert!(body.is_empty());
    assert!(headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("Content-Length") && v == "0"));

    // Chunked (unknown-length) client PUT streams through the same path.
    let chunked_payload: Vec<u8> = (0..2600u32).map(|i| (i % 251) as u8).collect();
    let (status, _, _) = http_chunked(
        proxy_addr,
        "/v1/AUTH_ec/ecbox/chunked.bin",
        &[
            ("Content-Type", "application/octet-stream"),
            ("X-Backend-Storage-Policy-Index", "1"),
        ],
        &chunked_payload,
    );
    assert_eq!(status, 201, "chunked EC PUT");
    let (status, _, body) = http(
        proxy_addr,
        "GET",
        "/v1/AUTH_ec/ecbox/chunked.bin",
        &[("X-Backend-Storage-Policy-Index", "1")],
        b"",
    );
    assert_eq!(status, 200);
    assert_eq!(body, chunked_payload, "chunked EC PUT round-trips");

    // ---- ranged EC GET (segment-aligned fragment fetches) ----

    // Single range crossing a segment boundary (1 KiB segments).
    let (status, headers, body) = http(
        proxy_addr,
        "GET",
        "/v1/AUTH_ec/ecbox/big.bin",
        &[
            ("X-Backend-Storage-Policy-Index", "1"),
            ("Range", "bytes=1500-2500"),
        ],
        b"",
    );
    assert_eq!(status, 206, "single-range EC GET");
    assert_eq!(body, payload[1500..=2500], "range bytes exact");
    let content_range = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("Content-Range"))
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    assert_eq!(content_range, format!("bytes 1500-2500/{}", payload.len()));

    // Suffix range.
    let (status, _, body) = http(
        proxy_addr,
        "GET",
        "/v1/AUTH_ec/ecbox/big.bin",
        &[
            ("X-Backend-Storage-Policy-Index", "1"),
            ("Range", "bytes=-700"),
        ],
        b"",
    );
    assert_eq!(status, 206, "suffix-range EC GET");
    assert_eq!(body, payload[payload.len() - 700..], "suffix bytes exact");

    // Multi-range: multipart/byteranges, byte-compatible with the
    // swift_http::multipart_byteranges framing.
    let (status, headers, body) = http(
        proxy_addr,
        "GET",
        "/v1/AUTH_ec/ecbox/big.bin",
        &[
            ("X-Backend-Storage-Policy-Index", "1"),
            ("Range", "bytes=0-99,1200-1299,3400-3499"),
        ],
        b"",
    );
    assert_eq!(status, 206, "multi-range EC GET");
    let content_type_hdr = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("Content-Type"))
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    let boundary = content_type_hdr
        .split_once("boundary=")
        .expect("multipart content type")
        .1
        .to_string();
    let expected = swift_http::multipart_byteranges(
        &boundary,
        &[(0, 100), (1200, 1300), (3400, 3500)],
        &payload,
        "text/plain",
        payload.len() as u64,
    );
    assert_eq!(body, expected, "multipart body matches the oracle framing");

    // Unsatisfiable range -> Python-compatible swob HTML plus the total
    // length and the whole-object EC etag (never a fragment etag).
    let (status, headers, body) = http(
        proxy_addr,
        "GET",
        "/v1/AUTH_ec/ecbox/big.bin",
        &[
            ("X-Backend-Storage-Policy-Index", "1"),
            ("Range", "bytes=99999-100000"),
        ],
        b"",
    );
    assert_eq!(status, 416, "unsatisfiable EC range");
    let header = |name: &str| {
        headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    };
    let expected_body = concat!(
        "<html><h1>Requested Range Not Satisfiable</h1>",
        "<p>The Range requested is not available.</p></html>"
    );
    let expected_content_range = format!("bytes */{}", payload.len());
    let expected_length = expected_body.len().to_string();
    let expected_etag = md5_hex(&payload);
    assert_eq!(body, expected_body.as_bytes());
    assert_eq!(
        header("Content-Range"),
        Some(expected_content_range.as_str())
    );
    assert_eq!(header("Content-Type"), Some("text/html; charset=UTF-8"));
    assert_eq!(header("Content-Length"), Some(expected_length.as_str()));
    assert_eq!(header("Accept-Ranges"), Some("bytes"));
    assert_eq!(
        header("ETag").map(|value| value.trim_matches('"')),
        Some(expected_etag.as_str()),
        "416 ETag is the whole-object md5"
    );

    // A client ETag that doesn't match the streamed md5 -> 422.
    let (status, _, _) = http(
        proxy_addr,
        "PUT",
        "/v1/AUTH_ec/ecbox/badetag.bin",
        &[
            ("Content-Type", "application/octet-stream"),
            ("X-Backend-Storage-Policy-Index", "1"),
            ("ETag", "00000000000000000000000000000000"),
        ],
        b"some bytes",
    );
    assert_eq!(status, 422, "client etag mismatch");

    std::fs::remove_dir_all(&tmp).unwrap();
}

/// Field `4f7a82c` `test_rebuild_missing_frags`: official probe is
/// PUT + POST, `break_nodes` rmtree of 1–2 primaries, then InternalClient
/// GET (no `X-Backend-Storage-Policy-Index`). Single-frag loss must 200
/// because ndata=4 and five archives remain — including before once.
#[test]
fn test_internal_client_get_after_post_and_single_frag_rmtree() {
    let _ec = EC_CLUSTER_LOCK.lock().unwrap();
    let tmp = std::env::temp_dir().join(format!(
        "swift-ec-rebuild-once-{}-{}",
        std::process::id(),
        line!()
    ));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    let (proxy_addr, obj_dirs, logs) = boot_ec_cluster_logged(&tmp);

    let (status, _, _) = http(
        proxy_addr,
        "PUT",
        "/v1/AUTH_ec/probe",
        &[("X-Storage-Policy", "Policy-1")],
        b"",
    );
    assert_eq!(status, 201, "container PUT");

    let payload: Vec<u8> = (0..1800u32).map(|i| (i % 251) as u8).collect();
    let (status, _, _) = http(
        proxy_addr,
        "PUT",
        "/v1/AUTH_ec/probe/obj",
        &[
            ("Content-Type", "application/octet-stream"),
            ("X-Backend-Storage-Policy-Index", "1"),
        ],
        &payload,
    );
    assert_eq!(status, 201, "EC PUT");
    let (status, _, _) = http(
        proxy_addr,
        "POST",
        "/v1/AUTH_ec/probe/obj",
        &[
            ("X-Object-Meta-Color", "red"),
            ("X-Backend-Storage-Policy-Index", "1"),
        ],
        b"",
    );
    assert_eq!(status, 202, "POST-after-PUT");

    let (status, _, body) = http(proxy_addr, "GET", "/v1/AUTH_ec/probe/obj", &[], b"");
    assert_eq!(status, 200, "InternalClient GET after POST");
    assert_eq!(body, payload);

    let deleted = rmtree_one_durable_hash_dir(&obj_dirs);
    assert!(
        !deleted.exists(),
        "break_nodes-shaped rmtree must remove the hash dir: {deleted:?}"
    );
    let remaining: usize = obj_dirs
        .iter()
        .map(|d| find_files(d, &|n| n.ends_with("#d.data")).len())
        .sum();
    assert_eq!(remaining, N - 1, "exactly one durable fragment removed");

    // Leaked client Fragment-Preferences must not hide remaining durables
    // (`copy_backend_control_headers` forwards X-Backend-*).
    let leaked_prefs = r#"[{"timestamp":"0","exclude":[0,1,2,3,4,5]}]"#;
    let (status, headers, body) = http(
        proxy_addr,
        "GET",
        "/v1/AUTH_ec/probe/obj",
        &[("X-Backend-Fragment-Preferences", leaked_prefs)],
        b"",
    );
    assert_eq!(
        status,
        200,
        "InternalClient GET after single-frag rmtree must decode remaining ndata: {}",
        String::from_utf8_lossy(&body)
    );
    assert_eq!(body, payload);
    let color = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("X-Object-Meta-Color"))
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    assert_eq!(color, "red", "POST metadata must survive single-frag loss");
    let captured = logs.lock().unwrap().clone();
    assert!(
        captured.iter().any(|line| {
            line.contains("proxy-server: EC GET")
                && line.contains("status=200")
                && line.contains("reason=ok")
        }),
        "Hyper handle_async must log EC GET ok via the proxy logger sink: {captured:?}"
    );

    // Adjacent second hole (official 0+5 / 0+4). Still ndata=4 of 6.
    let _ = rmtree_one_durable_hash_dir(&obj_dirs);
    let (status, _, body) = http(proxy_addr, "GET", "/v1/AUTH_ec/probe/obj", &[], b"");
    assert_eq!(
        status,
        200,
        "InternalClient GET after two-frag rmtree must still decode: {}",
        String::from_utf8_lossy(&body)
    );
    assert_eq!(body, payload);

    // Below ndata: the miss line must use the same logger sink field greps.
    let _ = rmtree_one_durable_hash_dir(&obj_dirs);
    let _ = rmtree_one_durable_hash_dir(&obj_dirs);
    logs.lock().unwrap().clear();
    let (status, _, _) = http(proxy_addr, "GET", "/v1/AUTH_ec/probe/obj", &[], b"");
    assert_eq!(status, 404, "GET with only 2/6 fragments must 404");
    let captured = logs.lock().unwrap().clone();
    assert!(
        captured.iter().any(|line| {
            line.contains("proxy-server: EC GET")
                && line.contains("reason=")
                && line.contains("200s=")
                && line.contains("idxs=")
        }),
        "gather miss must log via the real proxy logger path: {captured:?}"
    );

    std::fs::remove_dir_all(&tmp).unwrap();
}
