//! AGENTS.md §31: production serve is async HTTP/1.1 only.
//! These tests fail if a second production engine (LegacyService on the
//! object/proxy/account/container data plane, or blocking handle_connection
//! accept loop) comes back.

#[path = "harness.rs"]
mod harness;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use swift_core::hashing::HashPathConfig;
use swift_diskfile::{DiskFileConfig, PolicyKind};
use swift_http::{reject_legacy_server_runtime, ServerConfig, PRODUCTION_HTTP1_ENGINE};
use swift_object_server::{serve_with_config, ObjectServer, ObjectServerConfig};

#[test]
fn production_engine_constant_is_hyper_http1_only() {
    assert_eq!(PRODUCTION_HTTP1_ENGINE, "hyper/http1");
    assert!(!PRODUCTION_HTTP1_ENGINE.contains("http2"));
    assert!(!PRODUCTION_HTTP1_ENGINE.contains("legacy"));
}

#[test]
fn legacy_runtime_flag_is_rejected() {
    assert!(reject_legacy_server_runtime(None).is_ok());
    assert!(reject_legacy_server_runtime(Some("async")).is_ok());
    let err = reject_legacy_server_runtime(Some("legacy")).expect_err("legacy must die");
    assert!(err.contains("removed"), "{err}");
}

#[test]
fn object_proxy_account_container_serve_is_not_legacy_service() {
    let object = include_str!("../../../swift-object-server/src/lib.rs");
    let proxy = include_str!("../../../swift-proxy-server/src/lib.rs");
    let account = include_str!("../../../swift-account-server/src/lib.rs");
    let container = include_str!("../../../swift-container-server/src/lib.rs");
    for (name, src) in [
        ("object", object),
        ("proxy", proxy),
        ("account", account),
        ("container", container),
    ] {
        assert!(
            src.contains("serve_forever_multi_service"),
            "{name} production serve must call serve_forever_multi_service"
        );
        let prod = src.split("#[cfg(test)]").next().unwrap_or(src);
        assert!(
            !prod.contains("LegacyService"),
            "{name} production src must not construct LegacyService"
        );
        assert!(
            !prod.contains("handle_connection("),
            "{name} production src must not call sync handle_connection"
        );
    }
}

#[test]
fn occupancy_harness_stays_spawn_server_two() {
    let starvation = include_str!("worker_starvation.rs");
    let slow_put = include_str!("slow_put.rs");
    let slow_reader = include_str!("slow_reader.rs");
    let slowloris = include_str!("slowloris.rs");
    let expect = include_str!("align_expect_continue.rs");
    for (name, src) in [
        ("worker_starvation", starvation),
        ("slow_put", slow_put),
        ("slow_reader", slow_reader),
        ("slowloris", slowloris),
        ("align_expect_continue", expect),
    ] {
        assert!(
            src.contains("spawn_server(2"),
            "{name} must stay spawn_server(2)"
        );
    }
}

#[test]
fn shipped_object_put_get_uses_async_serve_not_legacy_adapter() {
    let dir =
        std::env::temp_dir().join(format!("legacy-removed-{}-{}", std::process::id(), line!()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("sda1")).unwrap();
    let server = ObjectServer::new(ObjectServerConfig {
        devices: dir.clone(),
        mount_check: false,
        hash_config: HashPathConfig::new(b"".to_vec(), b"legacy-removed".to_vec()).unwrap(),
        diskfile: DiskFileConfig::default(),
        policies: HashMap::from([(0, PolicyKind::Replication)]),
        container_update_timeout: Duration::from_millis(50),
        container_update_mode: swift_object_server::ContainerUpdateMode::Async,
    });
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let shutdown = Arc::new(AtomicBool::new(false));
    let cfg = ServerConfig {
        worker_threads: 2,
        shutdown: Some(Arc::clone(&shutdown)),
        ..ServerConfig::default()
    };
    thread::spawn(move || serve_with_config(listener, server, cfg));
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(20)).is_ok() {
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    let mut c = TcpStream::connect_timeout(&addr, Duration::from_millis(400)).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(4))).ok();
    c.write_all(
        b"PUT /sda1/0/AUTH_test/c/o HTTP/1.1\r\nHost: t\r\nX-Timestamp: 9000\r\nContent-Type: application/octet-stream\r\nContent-Length: 4\r\nConnection: close\r\n\r\nabcd",
    )
    .unwrap();
    let mut buf = Vec::new();
    let _ = c.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf);
    assert!(
        text.contains("201"),
        "object PUT on serve_with_config (AsyncService) must be 201, got {text:?}"
    );
    let mut g = TcpStream::connect_timeout(&addr, Duration::from_millis(400)).unwrap();
    g.set_read_timeout(Some(Duration::from_secs(4))).ok();
    g.write_all(b"GET /sda1/0/AUTH_test/c/o HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut gbuf = Vec::new();
    let _ = g.read_to_end(&mut gbuf);
    let gtext = String::from_utf8_lossy(&gbuf);
    assert!(
        gtext.contains("200") && gtext.contains("abcd"),
        "object GET on AsyncService path must return body, got {gtext:?}"
    );
    shutdown.store(true, Ordering::SeqCst);
    let _ = std::fs::remove_dir_all(&dir);
}
