//! Launch the real `swift-object-server` binary with no `server_runtime`
//! flag. Production default must be async HTTP/1.1 (AGENTS.md §31).

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn wait_port(addr: std::net::SocketAddr) -> bool {
    let deadline = Instant::now() + Duration::from_secs(8);
    while Instant::now() < deadline {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(50)).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

fn http(addr: std::net::SocketAddr, req: &[u8]) -> String {
    let mut c = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(4))).ok();
    c.write_all(req).unwrap();
    let mut buf = Vec::new();
    let _ = c.read_to_end(&mut buf);
    String::from_utf8_lossy(&buf).into_owned()
}

#[test]
fn production_binary_starts_async_without_legacy_flag() {
    let bin = env!("CARGO_BIN_EXE_swift-object-server");
    let root =
        std::env::temp_dir().join(format!("async-default-{}-{}", std::process::id(), line!()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("devices/sda1")).unwrap();
    let swift_conf = root.join("swift.conf");
    std::fs::write(
        &swift_conf,
        "[swift-hash]\nswift_hash_path_prefix = p\nswift_hash_path_suffix = s\n",
    )
    .unwrap();
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);
    let obj_conf = root.join("object-server.conf");
    std::fs::write(
        &obj_conf,
        format!(
            "[DEFAULT]\n\
             bind_ip = 127.0.0.1\n\
             bind_port = {}\n\
             workers = 0\n\
             devices = {}\n\
             mount_check = false\n\
             client_timeout = 5\n\
             [app:object-server]\n\
             mount_check = false\n",
            addr.port(),
            root.join("devices").display()
        ),
    )
    .unwrap();

    let mut child = Command::new(bin)
        .arg(&obj_conf)
        .env("SWIFT_CONF", &swift_conf)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn swift-object-server");
    assert!(
        wait_port(addr),
        "swift-object-server did not listen on {addr}"
    );

    let recon = http(
        addr,
        b"GET /recon/concurrency HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n",
    );
    assert!(
        recon.contains("connections_open") && recon.contains("commit_shield_active"),
        "recon must be a real snapshot, got {}",
        &recon[..recon.len().min(400)]
    );
    assert!(
        !recon.contains("server_runtime=legacy") && !recon.contains("engine=\"legacy\""),
        "snapshot must not advertise a legacy engine, got {recon}"
    );

    let put = http(
        addr,
        b"PUT /sda1/0/AUTH_test/c/o HTTP/1.1\r\nHost: t\r\nX-Timestamp: 8000\r\nContent-Type: application/octet-stream\r\nContent-Length: 4\r\nConnection: close\r\n\r\nabcd",
    );
    assert!(
        put.contains("201"),
        "PUT on production binary must be 201, got {put}"
    );
    let get = http(
        addr,
        b"GET /sda1/0/AUTH_test/c/o HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n",
    );
    assert!(
        get.contains("200") && get.contains("abcd"),
        "GET must return the object, got {get}"
    );

    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn production_binary_exits_on_server_runtime_legacy() {
    let bin = env!("CARGO_BIN_EXE_swift-object-server");
    let root = std::env::temp_dir().join(format!(
        "async-legacy-flag-{}-{}",
        std::process::id(),
        line!()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("devices/sda1")).unwrap();
    let swift_conf = root.join("swift.conf");
    std::fs::write(
        &swift_conf,
        "[swift-hash]\nswift_hash_path_prefix = p\nswift_hash_path_suffix = s\n",
    )
    .unwrap();
    let obj_conf = root.join("object-server.conf");
    std::fs::write(
        &obj_conf,
        "[DEFAULT]\n\
         bind_ip = 127.0.0.1\n\
         bind_port = 1\n\
         workers = 0\n\
         devices = /tmp\n\
         mount_check = false\n\
         server_runtime = legacy\n\
         [app:object-server]\n",
    )
    .unwrap();
    let out = Command::new(bin)
        .arg(&obj_conf)
        .env("SWIFT_CONF", &swift_conf)
        .output()
        .expect("run binary");
    assert!(
        !out.status.success(),
        "server_runtime=legacy must refuse to start"
    );
    let err = String::from_utf8_lossy(&out.stderr);
    let all = format!("{err}{}", String::from_utf8_lossy(&out.stdout));
    assert!(
        all.contains("removed") || all.contains("legacy"),
        "legacy refusal must mention removal, got {all}"
    );
    let _ = std::fs::remove_dir_all(&root);
}
