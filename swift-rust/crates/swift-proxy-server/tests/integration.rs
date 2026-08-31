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

//! End-to-end: a real Rust proxy fronting real Rust account and
//! container servers over loopback HTTP, wired by a single-device
//! in-memory ring.

use std::io::{Read, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use serde_json::Value as Json;
use swift_proxy_server::{ProxyApp, ProxyConfig};
use swift_ring::{Ring, RingData, RingDevice};

fn body_http(
    addr: std::net::SocketAddr,
    method: &str,
    target: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> (u16, Vec<u8>) {
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
    let status: u16 = String::from_utf8_lossy(&raw[..split])
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    (status, raw[split + 4..].to_vec())
}

fn hash_cfg() -> swift_core::hashing::HashPathConfig {
    swift_core::hashing::HashPathConfig::new(b"".to_vec(), b"changeme".to_vec()).unwrap()
}

fn single_device_ring(port: u32) -> Ring {
    let dev = RingDevice {
        id: 0,
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
    };
    let data = RingData::from_parts(vec![Some(dev)], 32, vec![vec![0], vec![0], vec![0]]);
    Ring::new(data, hash_cfg())
}

fn replica_ring(ports: &[u32], devices: &[&str]) -> Ring {
    let devs: Vec<Option<RingDevice>> = ports
        .iter()
        .zip(devices.iter())
        .enumerate()
        .map(|(i, (port, device))| {
            Some(RingDevice {
                id: i as u64,
                region: 1,
                zone: (i as u64) + 1,
                ip: "127.0.0.1".to_string(),
                port: *port,
                replication_ip: None,
                replication_port: None,
                device: (*device).to_string(),
                weight: 100.0,
                meta: String::new(),
                extra: serde_json::Map::new(),
            })
        })
        .collect();
    let replica2part2dev_id: Vec<Vec<u32>> = (0..ports.len() as u32).map(|i| vec![i]).collect();
    let data = RingData::from_parts(devs, 32, replica2part2dev_id);
    Ring::new(data, hash_cfg())
}

fn http(
    addr: std::net::SocketAddr,
    method: &str,
    target: &str,
    body: &str,
) -> (u16, Vec<(String, String)>, Vec<u8>) {
    http_with_headers(addr, method, target, &[], body)
}

fn http_with_headers(
    addr: std::net::SocketAddr,
    method: &str,
    target: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let mut conn = std::net::TcpStream::connect(addr).unwrap();
    let mut req = format!("{method} {target} HTTP/1.1\r\nHost: t\r\n");
    for (key, value) in headers {
        req.push_str(&format!("{key}: {value}\r\n"));
    }
    req.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    ));
    conn.write_all(req.as_bytes()).unwrap();
    conn.write_all(body.as_bytes()).unwrap();
    let mut raw = Vec::new();
    conn.read_to_end(&mut raw).unwrap();
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let body = raw[split + 4..].to_vec();
    let mut lines = head.lines();
    let status: u16 = lines
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    (status, headers, body)
}

#[derive(Default)]
struct BackendRequestCounts {
    head: AtomicUsize,
    put: AtomicUsize,
    post: AtomicUsize,
    delete: AtomicUsize,
}

/// Minimal HTTP backend whose status is selected by method. It records every
/// request so account-gate tests can prove the container ring saw zero fan-out.
fn spawn_counting_backend(
    head_status: u16,
    put_status: u16,
) -> (std::net::SocketAddr, Arc<BackendRequestCounts>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let counts = Arc::new(BackendRequestCounts::default());
    let thread_counts = Arc::clone(&counts);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buf = [0u8; 8192];
            let Ok(n) = stream.read(&mut buf) else {
                continue;
            };
            let first = String::from_utf8_lossy(&buf[..n]);
            let method = first.split_whitespace().next().unwrap_or("");
            let status = match method {
                "HEAD" => {
                    thread_counts.head.fetch_add(1, Ordering::SeqCst);
                    head_status
                }
                "PUT" => {
                    thread_counts.put.fetch_add(1, Ordering::SeqCst);
                    put_status
                }
                "POST" => {
                    thread_counts.post.fetch_add(1, Ordering::SeqCst);
                    204
                }
                "DELETE" => {
                    thread_counts.delete.fetch_add(1, Ordering::SeqCst);
                    204
                }
                _ => 405,
            };
            let reason = match status {
                201 => "Created",
                204 => "No Content",
                404 => "Not Found",
                503 => "Service Unavailable",
                _ => "Response",
            };
            let response = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    (addr, counts)
}

#[test]
fn test_proxy_end_to_end_account_and_container() {
    let tmp = std::env::temp_dir().join(format!("swift-proxy-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(tmp.join("sda1")).unwrap();

    let acct_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let acct_addr = acct_listener.local_addr().unwrap();
    let acct_config = swift_account_server::AccountServerConfig {
        devices: tmp.clone(),
        mount_check: false,
        hash_config: hash_cfg(),
        policies: vec![(0, "Policy-0".to_string())],
        fixed_created_at: None,
    };
    std::thread::spawn(move || swift_account_server::serve(acct_listener, acct_config));

    let cont_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let cont_addr = cont_listener.local_addr().unwrap();
    let cont_config = swift_container_server::ContainerServerConfig {
        devices: tmp.clone(),
        mount_check: false,
        hash_config: hash_cfg(),
        policies: vec![(0, "Policy-0".to_string())],
        default_policy_index: 0,
        recon_cache_path: tmp.join("recon"),
        fixed_created_at: None,
    };
    std::thread::spawn(move || swift_container_server::serve(cont_listener, cont_config));

    let proxy_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let app = Arc::new(ProxyApp::new(
        single_device_ring(acct_addr.port() as u32),
        single_device_ring(cont_addr.port() as u32),
        ProxyConfig {
            account_autocreate: true,
            ..Default::default()
        },
    ));
    std::thread::spawn(move || swift_proxy_server::serve(proxy_listener, app));
    std::thread::sleep(std::time::Duration::from_millis(200));

    // PUT a container through the proxy: account autocreated, container
    // recorded, and the account-update side channel registers it back
    let (status, _, _) = http(proxy_addr, "PUT", "/v1/AUTH_e2e/box", "");
    assert_eq!(status, 201, "container PUT via proxy");

    // account listing through the proxy shows the container
    let (status, _, body) = http(proxy_addr, "GET", "/v1/AUTH_e2e?format=json", "");
    assert_eq!(status, 200, "account GET via proxy");
    let listing: Json = serde_json::from_slice(&body).unwrap();
    assert_eq!(listing[0]["name"], "box", "account listing: {listing}");

    // container HEAD through the proxy
    let (status, headers, _) = http(proxy_addr, "HEAD", "/v1/AUTH_e2e/box", "");
    assert_eq!(status, 204, "container HEAD via proxy");
    assert!(
        headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("X-Container-Object-Count")),
        "container HEAD headers: {headers:?}"
    );

    // missing account: autocreate synthesizes an empty listing
    let (status, headers, body) = http(proxy_addr, "GET", "/v1/AUTH_missing?format=json", "");
    assert_eq!(status, 200);
    assert_eq!(String::from_utf8_lossy(&body), "[]");
    assert!(
        headers.iter().any(|(k, v)| k.eq_ignore_ascii_case(
            "X-Backend-Fake-Account-Listing"
        ) && v.eq_ignore_ascii_case("yes")),
        "fake listing must carry X-Backend-Fake-Account-Listing: {headers:?}"
    );

    // Probe check_server HEADs the account (fake 204) then PUTs a container.
    // Without account_really_exists=false the proxy skips autocreate and 404s.
    let (status, _, _) = http(proxy_addr, "HEAD", "/v1/AUTH_after_head", "");
    assert_eq!(status, 204, "HEAD missing autocreate account");
    let (status, _, _) = http(proxy_addr, "PUT", "/v1/AUTH_after_head/box2", "");
    assert_eq!(
        status, 201,
        "container PUT after fake HEAD must autocreate the account"
    );

    std::fs::remove_dir_all(&tmp).unwrap();
}

#[test]
fn test_container_put_does_not_mutate_when_account_autocreate_fails() {
    let tmp = std::env::temp_dir().join(format!(
        "swift-proxy-autocreate-fail-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(tmp.join("sda1")).unwrap();

    let acct_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let acct_addr = acct_listener.local_addr().unwrap();
    let acct_config = swift_account_server::AccountServerConfig {
        devices: tmp.clone(),
        mount_check: false,
        hash_config: hash_cfg(),
        policies: vec![(0, "Policy-0".to_string())],
        fixed_created_at: None,
    };
    std::thread::spawn(move || swift_account_server::serve(acct_listener, acct_config));

    let cont_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let cont_addr = cont_listener.local_addr().unwrap();
    let cont_config = swift_container_server::ContainerServerConfig {
        devices: tmp.clone(),
        mount_check: false,
        hash_config: hash_cfg(),
        policies: vec![(0, "Policy-0".to_string())],
        default_policy_index: 0,
        recon_cache_path: tmp.join("recon"),
        fixed_created_at: None,
    };
    std::thread::spawn(move || swift_container_server::serve(cont_listener, cont_config));

    let account_ring = single_device_ring(acct_addr.port() as u32);
    let (account_part, _) = account_ring
        .get_nodes("AUTH_deleted", None, None)
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(100));
    let account_path = format!("/sda1/{account_part}/AUTH_deleted");
    let (status, _, _) = http_with_headers(
        acct_addr,
        "PUT",
        &account_path,
        &[("X-Timestamp", "1751500000.00000")],
        "",
    );
    assert_eq!(status, 201, "account setup PUT");
    let (status, _, _) = http_with_headers(
        acct_addr,
        "DELETE",
        &account_path,
        &[("X-Timestamp", "1751500001.00000")],
        "",
    );
    assert_eq!(status, 204, "account setup DELETE");

    let proxy_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let app = Arc::new(ProxyApp::new(
        account_ring,
        single_device_ring(cont_addr.port() as u32),
        ProxyConfig {
            account_autocreate: true,
            ..Default::default()
        },
    ));
    std::thread::spawn(move || swift_proxy_server::serve(proxy_listener, app));
    std::thread::sleep(std::time::Duration::from_millis(150));

    // A recently-deleted account rejects autocreate with 403. Python's
    // container controller converts that failure to 503 and never fans out
    // the container PUT; the old Rust path ignored it, returned 404 from the
    // account-update side channel, but had already created the container DB.
    let (status, _, _) = http(proxy_addr, "PUT", "/v1/AUTH_deleted/ghost", "");
    assert_eq!(status, 503, "failed account autocreate must stop container PUT");
    let (status, _, _) = http(proxy_addr, "HEAD", "/v1/AUTH_deleted/ghost", "");
    assert_eq!(status, 404, "failed PUT must not leave a container behind");

    std::fs::remove_dir_all(&tmp).unwrap();
}

#[test]
fn test_container_account_gate_handles_all_non_success_and_only_put_autocreates() {
    let (account_addr, account_counts) = spawn_counting_backend(503, 503);
    let (container_addr, container_counts) = spawn_counting_backend(204, 201);
    let proxy_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let app = Arc::new(ProxyApp::new(
        single_device_ring(account_addr.port() as u32),
        single_device_ring(container_addr.port() as u32),
        ProxyConfig {
            account_autocreate: true,
            ..Default::default()
        },
    ));
    std::thread::spawn(move || swift_proxy_server::serve(proxy_listener, app));
    std::thread::sleep(std::time::Duration::from_millis(100));

    let (status, _, _) = http(proxy_addr, "POST", "/v1/AUTH_down/c", "");
    assert_eq!(status, 404, "POST must not autocreate an unavailable account");
    let (status, _, _) = http(proxy_addr, "DELETE", "/v1/AUTH_down/c", "");
    assert_eq!(status, 404, "DELETE must not autocreate an unavailable account");
    assert_eq!(
        account_counts.put.load(Ordering::SeqCst),
        0,
        "POST/DELETE must not send account PUT"
    );
    assert_eq!(
        container_counts.post.load(Ordering::SeqCst)
            + container_counts.delete.load(Ordering::SeqCst),
        0,
        "non-2xx account_info must stop container fan-out"
    );

    let (status, _, _) = http(proxy_addr, "PUT", "/v1/AUTH_down/c", "");
    assert_eq!(status, 503, "failed PUT autocreate is service unavailable");
    assert!(
        account_counts.put.load(Ordering::SeqCst) > 0,
        "only PUT attempts account autocreate"
    );
    assert_eq!(
        container_counts.put.load(Ordering::SeqCst),
        0,
        "failed autocreate must stop container fan-out"
    );
}

#[test]
fn test_container_put_rechecks_account_after_successful_autocreate() {
    // Account PUT reports success, but every HEAD remains 404. Python retries
    // account_info and returns 404 without touching the container ring.
    let (account_addr, account_counts) = spawn_counting_backend(404, 201);
    let (container_addr, container_counts) = spawn_counting_backend(204, 201);
    let proxy_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let app = Arc::new(ProxyApp::new(
        single_device_ring(account_addr.port() as u32),
        single_device_ring(container_addr.port() as u32),
        ProxyConfig {
            account_autocreate: true,
            ..Default::default()
        },
    ));
    std::thread::spawn(move || swift_proxy_server::serve(proxy_listener, app));
    std::thread::sleep(std::time::Duration::from_millis(100));

    let (status, _, _) = http(proxy_addr, "PUT", "/v1/AUTH_invisible/c", "");
    assert_eq!(status, 404, "unobservable account after autocreate");
    assert!(
        account_counts.put.load(Ordering::SeqCst) > 0,
        "account autocreate must have run"
    );
    assert!(
        account_counts.head.load(Ordering::SeqCst) >= 2,
        "account_info must be checked before and after autocreate"
    );
    assert_eq!(
        container_counts.put.load(Ordering::SeqCst),
        0,
        "failed refreshed account_info must stop container fan-out"
    );
}

#[test]
fn test_container_put_succeeds_when_one_account_replica_404s() {
    // RSAIO-style replica=3: AUTH exists on two devices, the third 404s.
    // Python `_backend_requests` still reaches write quorum (201).
    let tmp = std::env::temp_dir().join(format!(
        "swift-proxy-acct-partial-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&tmp);
    for dev in ["sda1", "sda2", "sda3"] {
        std::fs::create_dir_all(tmp.join(dev)).unwrap();
    }

    let acct_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let acct_addr = acct_listener.local_addr().unwrap();
    let acct_config = swift_account_server::AccountServerConfig {
        devices: tmp.clone(),
        mount_check: false,
        hash_config: hash_cfg(),
        policies: vec![(0, "Policy-0".to_string())],
        fixed_created_at: None,
    };
    std::thread::spawn(move || swift_account_server::serve(acct_listener, acct_config));

    let cont_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let cont_addr = cont_listener.local_addr().unwrap();
    let cont_config = swift_container_server::ContainerServerConfig {
        devices: tmp.clone(),
        mount_check: false,
        hash_config: hash_cfg(),
        policies: vec![(0, "Policy-0".to_string())],
        default_policy_index: 0,
        recon_cache_path: tmp.join("recon"),
        fixed_created_at: None,
    };
    std::thread::spawn(move || swift_container_server::serve(cont_listener, cont_config));

    let account_ring = replica_ring(
        &[
            u32::from(acct_addr.port()),
            u32::from(acct_addr.port()),
            u32::from(acct_addr.port()),
        ],
        &["sda1", "sda2", "sda3"],
    );
    let (account_part, _) = account_ring.get_nodes("AUTH_e2e", None, None).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(120));
    for device in ["sda1", "sda2"] {
        let (status, _, _) = http_with_headers(
            acct_addr,
            "PUT",
            &format!("/{device}/{account_part}/AUTH_e2e"),
            &[("X-Timestamp", "1751500000.00000")],
            "",
        );
        assert_eq!(status, 201, "account setup on {device}");
    }

    let proxy_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let app = Arc::new(ProxyApp::new(
        account_ring,
        replica_ring(
            &[
                u32::from(cont_addr.port()),
                u32::from(cont_addr.port()),
                u32::from(cont_addr.port()),
            ],
            &["sda1", "sda2", "sda3"],
        ),
        ProxyConfig {
            account_autocreate: false,
            ..Default::default()
        },
    ));
    std::thread::spawn(move || swift_proxy_server::serve(proxy_listener, app));
    std::thread::sleep(std::time::Duration::from_millis(150));

    let (status, _, _) = http(proxy_addr, "PUT", "/v1/AUTH_e2e/box", "");
    assert_eq!(
        status, 201,
        "one account replica 404 must not fail container PUT"
    );
    let (status, _, _) = http(proxy_addr, "HEAD", "/v1/AUTH_e2e/box", "");
    assert_eq!(status, 204);

    std::fs::remove_dir_all(&tmp).unwrap();
}

#[test]
fn test_proxy_object_round_trip() {
    let tmp = std::env::temp_dir().join(format!("swift-proxy-obj-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(tmp.join("sda1")).unwrap();

    // account server
    let acct_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let acct_addr = acct_listener.local_addr().unwrap();
    let acct_config = swift_account_server::AccountServerConfig {
        devices: tmp.clone(),
        mount_check: false,
        hash_config: hash_cfg(),
        policies: vec![(0, "Policy-0".to_string())],
        fixed_created_at: None,
    };
    std::thread::spawn(move || swift_account_server::serve(acct_listener, acct_config));

    // container server
    let cont_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let cont_addr = cont_listener.local_addr().unwrap();
    let cont_config = swift_container_server::ContainerServerConfig {
        devices: tmp.clone(),
        mount_check: false,
        hash_config: hash_cfg(),
        policies: vec![(0, "Policy-0".to_string())],
        default_policy_index: 0,
        recon_cache_path: tmp.join("recon"),
        fixed_created_at: None,
    };
    std::thread::spawn(move || swift_container_server::serve(cont_listener, cont_config));

    // object server
    let obj_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let obj_addr = obj_listener.local_addr().unwrap();
    let obj_tmp = tmp.clone();
    std::thread::spawn(move || {
        swift_object_server::serve(
            obj_listener,
            swift_object_server::ObjectServerConfig {
                devices: obj_tmp,
                mount_check: false,
                hash_config: hash_cfg(),
                diskfile: swift_diskfile::DiskFileConfig::default(),
                policies: std::collections::HashMap::from([(
                    0,
                    swift_diskfile::PolicyKind::Replication,
                )]),
                container_update_timeout: std::time::Duration::from_secs(1),
                container_update_mode: swift_object_server::ContainerUpdateMode::Sync,
            },
        )
    });

    // proxy fronting all three
    let proxy_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let app = Arc::new(ProxyApp::with_object_ring(
        single_device_ring(acct_addr.port() as u32),
        single_device_ring(cont_addr.port() as u32),
        single_device_ring(obj_addr.port() as u32),
        ProxyConfig {
            account_autocreate: true,
            ..Default::default()
        },
    ));
    std::thread::spawn(move || {
        swift_proxy_server::serve_with_filters(
            proxy_listener,
            app,
            vec![Arc::new(swift_middleware::Slo::new())],
        )
    });
    std::thread::sleep(std::time::Duration::from_millis(250));

    // create the container (autocreates the account)
    let (status, _) = body_http(proxy_addr, "PUT", "/v1/AUTH_full/docs", &[], b"");
    assert_eq!(status, 201, "container PUT");

    // object writes into a container that doesn't exist 404 like Python
    // (obj.py checks container_info status on POST/PUT/DELETE)
    let (status, _) = body_http(proxy_addr, "PUT", "/v1/AUTH_full/missing/o", &[], b"x");
    assert_eq!(status, 404, "object PUT to missing container");
    let (status, _) = body_http(proxy_addr, "POST", "/v1/AUTH_full/missing/o", &[], b"");
    assert_eq!(status, 404, "object POST to missing container");
    let (status, _) = body_http(proxy_addr, "DELETE", "/v1/AUTH_full/missing/o", &[], b"");
    assert_eq!(status, 404, "object DELETE to missing container");

    // PUT an object through the proxy: proxy -> object server -> writes
    // to disk and updates the container via the side channel
    let payload = b"the quick brown fox";
    let (status, put_headers, _) = http_with_headers(
        proxy_addr,
        "PUT",
        "/v1/AUTH_full/docs/fox.txt",
        &[("Content-Type", "text/plain")],
        std::str::from_utf8(payload).unwrap(),
    );
    assert_eq!(status, 201, "object PUT");
    let put_etag = put_headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("Etag"))
        .map(|(_, value)| value.as_str());
    assert_eq!(
        put_etag,
        Some("30f3c93e46436deb58ba70816a8ec124"),
        "client-facing PUT ETag must match Python's bare MD5"
    );

    // A multipart PUT with null etag/size relies entirely on the internal
    // proxy HEAD. Both copies are intentional: the first segment is not the
    // final segment, so losing its backend Content-Length turns it into a
    // false zero-byte segment and SLO rejects the manifest as too small.
    let manifest = serde_json::to_vec(&serde_json::json!([
        {"path": "/docs/fox.txt", "etag": null, "size_bytes": null},
        {"path": "/docs/fox.txt", "etag": null, "size_bytes": null}
    ]))
    .unwrap();
    let (status, body) = body_http(
        proxy_addr,
        "PUT",
        "/v1/AUTH_full/docs/manifest?multipart-manifest=put",
        &[("Content-Type", "application/json")],
        &manifest,
    );
    assert_eq!(
        status,
        201,
        "SLO PUT must receive HEAD metadata: {}",
        String::from_utf8_lossy(&body)
    );

    // Inspect the raw normalized manifest. Null client values must be filled
    // from the real object HEAD, including the backend ETag.
    let (status, body) = body_http(
        proxy_addr,
        "GET",
        "/v1/AUTH_full/docs/manifest?multipart-manifest=get",
        &[],
        b"",
    );
    assert_eq!(status, 200, "raw SLO GET");
    let stored: Json = serde_json::from_slice(&body).unwrap();
    assert_eq!(stored.as_array().unwrap().len(), 2);
    for segment in stored.as_array().unwrap() {
        assert_eq!(segment["bytes"], payload.len());
        assert_eq!(segment["hash"], "30f3c93e46436deb58ba70816a8ec124");
    }

    // The same metadata must survive a client-facing HEAD. The HTTP writer
    // must not replace the backend object length with the empty HEAD body size.
    let (status, headers, body) = http(proxy_addr, "HEAD", "/v1/AUTH_full/docs/fox.txt", "");
    assert_eq!(status, 200, "object HEAD");
    assert!(body.is_empty(), "HEAD has no response body");
    let header = |name: &str| {
        headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    };
    assert_eq!(header("Content-Length"), Some("19"));
    // Client-facing ETag is the bare md5 (proxy strips the object server's
    // quotes, matching Python normalize_etag).
    assert_eq!(header("Etag"), Some("30f3c93e46436deb58ba70816a8ec124"));

    // GET the object back through the proxy
    let (status, body) = body_http(proxy_addr, "GET", "/v1/AUTH_full/docs/fox.txt", &[], b"");
    assert_eq!(status, 200, "object GET");
    assert_eq!(body, payload, "object body round-trips");

    // the container listing shows the object
    let (status, body) = body_http(
        proxy_addr,
        "GET",
        "/v1/AUTH_full/docs?format=json",
        &[],
        b"",
    );
    assert_eq!(status, 200);
    let listing: Json = serde_json::from_slice(&body).unwrap();
    assert_eq!(listing[0]["name"], "fox.txt", "{listing}");
    assert_eq!(listing[0]["bytes"], payload.len(), "listing size");

    // DELETE the object through the proxy
    let (status, _) = body_http(proxy_addr, "DELETE", "/v1/AUTH_full/docs/fox.txt", &[], b"");
    assert_eq!(status, 204, "object DELETE");
    let (status, _) = body_http(proxy_addr, "GET", "/v1/AUTH_full/docs/fox.txt", &[], b"");
    assert_eq!(status, 404, "object gone after delete");

    std::fs::remove_dir_all(&tmp).unwrap();
}

/// Spin one object server on its own devices dir (so each "node" has
/// independent on-disk state) and return its address plus the dir.
fn spawn_object_server(tag: &str) -> (std::net::SocketAddr, std::path::PathBuf) {
    let tmp = std::env::temp_dir().join(format!("swift-proxy-ho-{}-{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(tmp.join("sda1")).unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let devices = tmp.clone();
    std::thread::spawn(move || {
        swift_object_server::serve(
            listener,
            swift_object_server::ObjectServerConfig {
                devices,
                mount_check: false,
                hash_config: hash_cfg(),
                diskfile: swift_diskfile::DiskFileConfig::default(),
                policies: std::collections::HashMap::from([(
                    0,
                    swift_diskfile::PolicyKind::Replication,
                )]),
                container_update_timeout: std::time::Duration::from_secs(1),
                container_update_mode: swift_object_server::ContainerUpdateMode::Sync,
            },
        )
    });
    (addr, tmp)
}

/// A two-partition object ring: partition 0's primaries are the first
/// three ports and the fourth port is its only handoff. (`get_more_nodes`
/// only yields devices assigned to *some* partition, so the handoff
/// device is made partition 1's primary.)
fn three_primary_one_handoff_ring(ports: [u32; 4]) -> Ring {
    let dev = |id: u64, port: u32| RingDevice {
        id,
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
    };
    let devs = vec![
        Some(dev(0, ports[0])),
        Some(dev(1, ports[1])),
        Some(dev(2, ports[2])),
        Some(dev(3, ports[3])),
    ];
    // part_shift 31 -> two partitions; partition 0 -> devices 0,1,2 and
    // partition 1 -> device 3 (so device 3 is partition 0's handoff).
    let data = RingData::from_parts(devs, 31, vec![vec![0, 3], vec![1, 3], vec![2, 3]]);
    Ring::new(data, hash_cfg())
}

/// An object name that hashes to partition 0 of `ring` (deterministic
/// given the fixed test hash prefix/suffix).
fn object_on_partition_zero(ring: &Ring, account: &str, container: &str) -> String {
    (0..1000)
        .map(|i| format!("obj{i}"))
        .find(|o| ring.get_part(account, Some(container), Some(o)).unwrap() == 0)
        .expect("some object name lands on partition 0")
}

fn internal_ts(secs: f64) -> String {
    swift_core::timestamp::Timestamp::from_secs(secs)
        .unwrap()
        .internal()
}

/// A recent timestamp `back` seconds in the past. Timestamps must be
/// near-now: a tombstone older than `reclaim_age` (7 days) is reclaimed
/// the moment cleanup runs, so an ancient DELETE leaves no tombstone and
/// its 404 carries no X-Backend-Timestamp.
fn recent_ts(back: f64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();
    internal_ts(now - back)
}

#[test]
fn test_get_stale_handoff_data_loses_to_newer_tombstones() {
    // Upstream bug #1560574: after a DELETE lands on the primaries (newer
    // tombstones), old data still sitting on a handoff must NOT be served
    // — the proxy GET compares the source timestamp against the largest
    // 404 X-Backend-Timestamp and returns 404, not the stale 200.
    let (a, ta) = spawn_object_server("stale-p1");
    let (b, tb) = spawn_object_server("stale-p2");
    let (c, tc) = spawn_object_server("stale-p3");
    let (d, td) = spawn_object_server("stale-h");
    let ring = three_primary_one_handoff_ring([
        a.port() as u32,
        b.port() as u32,
        c.port() as u32,
        d.port() as u32,
    ]);

    // account/container rings point at a closed port (nothing binds port
    // 1): the policy lookup falls back to the default policy 0.
    let proxy_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let app = Arc::new(ProxyApp::with_object_ring(
        single_device_ring(1),
        single_device_ring(1),
        ring.clone(),
        ProxyConfig::default(),
    ));
    std::thread::spawn(move || swift_proxy_server::serve(proxy_listener, app));
    std::thread::sleep(std::time::Duration::from_millis(250));

    let obj = object_on_partition_zero(&ring, "AUTH_stale", "c");
    let target = format!("/sda1/0/AUTH_stale/c/{obj}");
    let t1 = recent_ts(100.0);
    let t2 = recent_ts(10.0);

    // the object lands everywhere (including the handoff) at t1 ...
    for addr in [a, b, c, d] {
        let (status, _) = body_http(
            addr,
            "PUT",
            &target,
            &[("X-Timestamp", &t1), ("Content-Type", "text/plain")],
            b"stale body",
        );
        assert_eq!(status, 201, "direct backend PUT");
    }
    // ... then a newer DELETE reaches only the primaries, leaving the
    // stale .data on the handoff
    for addr in [a, b, c] {
        let (status, _) = body_http(addr, "DELETE", &target, &[("X-Timestamp", &t2)], b"");
        assert_eq!(status, 204, "direct backend DELETE");
    }
    // precondition: the handoff really would serve the stale copy
    let (status, body) = body_http(d, "GET", &target, &[], b"");
    assert_eq!(status, 200, "handoff still has the old data");
    assert_eq!(body, b"stale body");

    // the proxy must prefer the newer tombstones over the stale source
    let (status, body) = body_http(
        proxy_addr,
        "GET",
        &format!("/v1/AUTH_stale/c/{obj}"),
        &[],
        b"",
    );
    assert_eq!(
        status,
        404,
        "stale handoff data must not shadow newer tombstones: {}",
        String::from_utf8_lossy(&body)
    );

    for tmp in [ta, tb, tc, td] {
        let _ = std::fs::remove_dir_all(tmp);
    }
}

#[test]
fn test_get_unreachable_primaries_and_empty_handoff_is_503() {
    // With every primary unreachable, an empty handoff's plain 404 (no
    // X-Backend-Timestamp tombstone) is not authoritative
    // (base.py:1617-1624) — the proxy must answer 503, not 404.
    let (d, td) = spawn_object_server("unreach-h");
    // ports 1-3 are privileged and unbound: connections are refused
    let ring = three_primary_one_handoff_ring([1, 2, 3, d.port() as u32]);

    let proxy_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let app = Arc::new(ProxyApp::with_object_ring(
        single_device_ring(1),
        single_device_ring(1),
        ring.clone(),
        ProxyConfig::default(),
    ));
    std::thread::spawn(move || swift_proxy_server::serve(proxy_listener, app));
    std::thread::sleep(std::time::Duration::from_millis(250));

    let obj = object_on_partition_zero(&ring, "AUTH_unreach", "c");
    let (status, body) = body_http(
        proxy_addr,
        "GET",
        &format!("/v1/AUTH_unreach/c/{obj}"),
        &[],
        b"",
    );
    assert_eq!(
        status,
        503,
        "a non-authoritative handoff 404 must not become the final status: {}",
        String::from_utf8_lossy(&body)
    );

    let _ = std::fs::remove_dir_all(td);
}

#[test]
fn test_post_mixed_results_falls_back_to_handoff() {
    // obj.py:912-962: primaries answering 202,404,404 would lose
    // best_response to the 404; the proxy must make one extra POST per
    // missing primary to the next handoffs and combine the results.
    let (a, ta) = spawn_object_server("post-p1");
    let (b, tb) = spawn_object_server("post-p2");
    let (c, tc) = spawn_object_server("post-p3");
    let (d, td) = spawn_object_server("post-h");
    let ring = three_primary_one_handoff_ring([
        a.port() as u32,
        b.port() as u32,
        c.port() as u32,
        d.port() as u32,
    ]);

    // a real container server: object POST requires the container to exist
    // (obj.py:469), so the proxy's container HEAD must succeed
    let cont_tmp =
        std::env::temp_dir().join(format!("swift-proxy-postmix-c-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&cont_tmp);
    std::fs::create_dir_all(cont_tmp.join("sda1")).unwrap();
    let cont_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let cont_addr = cont_listener.local_addr().unwrap();
    let cont_config = swift_container_server::ContainerServerConfig {
        devices: cont_tmp.clone(),
        mount_check: false,
        hash_config: hash_cfg(),
        policies: vec![(0, "Policy-0".to_string())],
        default_policy_index: 0,
        recon_cache_path: cont_tmp.join("recon"),
        fixed_created_at: None,
    };
    std::thread::spawn(move || swift_container_server::serve(cont_listener, cont_config));

    let proxy_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let app = Arc::new(ProxyApp::with_object_ring(
        single_device_ring(1),
        single_device_ring(cont_addr.port() as u32),
        ring.clone(),
        ProxyConfig::default(),
    ));
    std::thread::spawn(move || swift_proxy_server::serve(proxy_listener, app));
    std::thread::sleep(std::time::Duration::from_millis(250));

    let obj = object_on_partition_zero(&ring, "AUTH_post", "c");
    let tc0 = recent_ts(200.0);
    let (status, _) = body_http(
        cont_addr,
        "PUT",
        "/sda1/0/AUTH_post/c",
        &[
            ("X-Timestamp", &tc0),
            ("X-Backend-Storage-Policy-Index", "0"),
        ],
        b"",
    );
    assert_eq!(status, 201, "direct backend container PUT");
    let target = format!("/sda1/0/AUTH_post/c/{obj}");
    let t1 = recent_ts(100.0);

    // the object exists on one primary and one handoff only (as after a
    // partial rebalance); two primaries have never seen it
    for addr in [a, d] {
        let (status, _) = body_http(
            addr,
            "PUT",
            &target,
            &[("X-Timestamp", &t1), ("Content-Type", "text/plain")],
            b"posted body",
        );
        assert_eq!(status, 201, "direct backend PUT");
    }

    let (status, body) = body_http(
        proxy_addr,
        "POST",
        &format!("/v1/AUTH_post/c/{obj}"),
        &[("X-Object-Meta-Color", "teal")],
        b"",
    );
    assert_eq!(
        status,
        202,
        "mixed primary results must fall back to the handoff: {}",
        String::from_utf8_lossy(&body)
    );

    // the metadata reached both live copies (primary + the one extra
    // handoff POST); the empty primaries still know nothing
    for addr in [a, d] {
        let (status, headers, _) = http(addr, "HEAD", &target, "");
        assert_eq!(status, 200);
        assert!(
            headers
                .iter()
                .any(|(k, v)| { k.eq_ignore_ascii_case("X-Object-Meta-Color") && v == "teal" }),
            "POST metadata visible on {addr}: {headers:?}"
        );
    }
    for addr in [b, c] {
        let (status, _, _) = http(addr, "HEAD", &target, "");
        assert_eq!(status, 404);
    }

    for tmp in [ta, tb, tc, td] {
        let _ = std::fs::remove_dir_all(tmp);
    }
}

#[test]
fn test_pipeline_healthcheck_gatekeeper_transid() {
    // a proxy behind the default pipeline: healthcheck answers locally,
    // gatekeeper blocks a client-injected backend header, catch_errors
    // stamps a trans id
    let app = Arc::new(ProxyApp::new(
        single_device_ring(1),
        single_device_ring(1),
        ProxyConfig::default(),
    ));
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || swift_proxy_server::serve_with_pipeline(listener, app));
    std::thread::sleep(std::time::Duration::from_millis(150));

    // healthcheck short-circuits before the proxy app
    let (status, headers, body) = http(addr, "GET", "/healthcheck", "");
    assert_eq!(status, 200);
    assert_eq!(body, b"OK");
    // catch_errors stamped a trans id even on the healthcheck path
    assert!(headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("X-Trans-Id")));

    // an object GET to a dead backend still returns (503) with a trans id,
    // and the response carries no leaked backend headers
    let (_status, headers, _) = http(addr, "GET", "/v1/AUTH_x/c/o", "");
    assert!(
        headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("X-Trans-Id")),
        "trans id present: {headers:?}"
    );
    assert!(
        !headers
            .iter()
            .any(|(k, _)| k.to_lowercase().starts_with("x-backend")),
        "no backend headers leak to the client: {headers:?}"
    );
}

#[test]
fn test_tempauth_end_to_end() {
    // full cluster behind tempauth: get a token, then use it to create a
    // container and store an object; an unauthenticated request is 401.
    let tmp = std::env::temp_dir().join(format!("swift-auth-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(tmp.join("sda1")).unwrap();

    let acct_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let acct_addr = acct_listener.local_addr().unwrap();
    std::thread::spawn(move || {
        swift_account_server::serve(
            acct_listener,
            swift_account_server::AccountServerConfig {
                devices: tmp.clone(),
                mount_check: false,
                hash_config: hash_cfg(),
                policies: vec![(0, "Policy-0".to_string())],
                fixed_created_at: None,
            },
        )
    });
    let tmp2 = std::env::temp_dir().join(format!("swift-auth-{}", std::process::id()));
    let cont_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let cont_addr = cont_listener.local_addr().unwrap();
    std::thread::spawn(move || {
        swift_container_server::serve(
            cont_listener,
            swift_container_server::ContainerServerConfig {
                devices: tmp2.clone(),
                mount_check: false,
                hash_config: hash_cfg(),
                policies: vec![(0, "Policy-0".to_string())],
                default_policy_index: 0,
                recon_cache_path: tmp2.join("recon"),
                fixed_created_at: None,
            },
        )
    });

    let app = Arc::new(ProxyApp::new(
        single_device_ring(acct_addr.port() as u32),
        single_device_ring(cont_addr.port() as u32),
        ProxyConfig {
            account_autocreate: true,
            auth_enabled: true,
            ..Default::default()
        },
    ));
    let proxy_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let mut ta = swift_middleware::TempAuth::new(format!("http://{proxy_addr}"));
    ta.add_user("test", "tester", "testing", &[".admin"]);
    std::thread::spawn(move || {
        swift_proxy_server::serve_with_filters(proxy_listener, app, vec![Arc::new(ta)])
    });
    std::thread::sleep(std::time::Duration::from_millis(250));

    // Unauthenticated container GET -> Python TempAuth's exact 401 wire shape.
    let (status, headers, body) = http(proxy_addr, "GET", "/v1/AUTH_test/box", "");
    assert_eq!(status, 401, "no token");
    let header = |name: &str| {
        headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    };
    let expected_body = concat!(
        "<html><h1>Unauthorized</h1>",
        "<p>This server could not verify that you are authorized to access ",
        "the document you requested.</p></html>"
    );
    assert_eq!(body, expected_body.as_bytes());
    assert_eq!(header("Content-Type"), Some("text/html; charset=UTF-8"));
    assert_eq!(header("Content-Length"), Some("131"));
    assert_eq!(
        header("Www-Authenticate"),
        Some("Swift realm=\"AUTH_test\"")
    );

    // get a token
    let mut conn = std::net::TcpStream::connect(proxy_addr).unwrap();
    conn.write_all(
        b"GET /auth/v1.0 HTTP/1.1\r\nHost: t\r\nX-Auth-User: test:tester\r\nX-Auth-Key: testing\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    )
    .unwrap();
    let mut raw = Vec::new();
    conn.read_to_end(&mut raw).unwrap();
    let head = String::from_utf8_lossy(&raw);
    let token = head
        .lines()
        .find_map(|l| l.strip_prefix("X-Auth-Token: "))
        .expect("token issued")
        .trim()
        .to_string();
    assert!(token.starts_with("AUTH_tk"), "{token}");

    // create the container with the token
    let mut conn = std::net::TcpStream::connect(proxy_addr).unwrap();
    conn.write_all(
        format!(
            "PUT /v1/AUTH_test/box HTTP/1.1\r\nHost: t\r\nX-Auth-Token: {token}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .as_bytes(),
    )
    .unwrap();
    let mut raw = Vec::new();
    conn.read_to_end(&mut raw).unwrap();
    let status: u16 = String::from_utf8_lossy(&raw)
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(
        status,
        201,
        "authenticated container PUT: {}",
        String::from_utf8_lossy(&raw)
    );

    std::fs::remove_dir_all(
        std::env::temp_dir().join(format!("swift-auth-{}", std::process::id())),
    )
    .ok();
}
