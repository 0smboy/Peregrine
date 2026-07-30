use std::fs;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

use serde_json::Value;
use tempfile::tempdir;

#[test]
fn ui_subcommand_documents_safe_local_defaults() {
    let output = Command::new(env!("CARGO_BIN_EXE_swift-deploy"))
        .args(["ui", "--help"])
        .output()
        .expect("run swift-deploy ui help");

    assert!(output.status.success());
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(help.contains("127.0.0.1"));
    assert!(help.contains("8788"));
    assert!(help.contains("--inventory"));
    assert!(help.contains("--known-hosts"));
}

#[test]
fn ui_refuses_a_public_bind_address() {
    let output = Command::new(env!("CARGO_BIN_EXE_swift-deploy"))
        .args(["ui", "--bind", "0.0.0.0", "--port", "0"])
        .output()
        .expect("run swift-deploy ui with public bind");

    assert!(!output.status.success());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("loopback"), "unexpected error: {error}");
}

#[test]
fn ui_serves_the_real_control_surface_and_health_check() {
    let server = TestServer::start();

    let page = server.get("/");
    assert!(page.starts_with("HTTP/1.1 200 OK"));
    assert!(page.contains("<title>Swift 集群部署工作区</title>"));
    assert!(page.contains("id=\"audit-action\""));
    assert!(page.contains("id=\"validate-action\""));
    assert!(page.contains("id=\"plan-action\""));
    assert!(page.contains("id=\"apply-action\""));
    assert!(page.contains("id=\"allow-host-reconfigure\""));
    assert!(page.contains("仅用于专用、全新安装的 Rocky 9 主机"));
    assert!(page.contains("完整 yum upgrade"));

    let health = server.get("/healthz");
    assert!(health.starts_with("HTTP/1.1 200 OK"));
    assert!(health.contains("\"ok\":true"));
}

#[test]
fn ui_serves_embedded_assets_with_a_locked_down_browser_policy() {
    let server = TestServer::start();
    let page = server.get("/");
    assert!(page.contains("Content-Security-Policy: default-src 'self'"));
    assert!(page.contains("href=\"/app.css\""));
    assert!(page.contains("src=\"/app.js\""));

    let css = server.get("/app.css");
    assert!(css.starts_with("HTTP/1.1 200 OK"));
    assert!(css.contains("--copper:"));
    assert!(css.contains("prefers-reduced-motion"));

    let javascript = server.get("/app.js");
    assert!(javascript.starts_with("HTTP/1.1 200 OK"));
    assert!(javascript.contains("/api/validate"));
    assert!(javascript.contains("/api/plan"));
    assert!(javascript.contains("/api/apply"));
    assert!(javascript.contains("localStorage"));

    let favicon = server.get("/favicon.ico");
    assert!(favicon.starts_with("HTTP/1.1 204 No Content"));
}

#[test]
fn ui_denies_mutations_without_its_same_origin_token() {
    let server = TestServer::start();
    let response = server.post("/api/audit", "{}", &[]);

    assert!(response.starts_with("HTTP/1.1 403 Forbidden"));
    assert!(response.contains("anti-CSRF token"));
}

#[test]
fn ui_runs_a_real_audit_job_and_exposes_its_state() {
    let server = TestServer::start();
    let page = server.get("/");
    let token = extract_between(&page, "name=\"ui-token\" content=\"", "\"")
        .expect("same-origin token in UI page");
    let config = config_body("/tmp/swift-deploy-ui-test-plan.json");
    let response = server.post("/api/audit", &config, &[("X-Swift-Deploy-Token", token)]);
    assert!(response.starts_with("HTTP/1.1 202 Accepted"), "{response}");

    for _ in 0..120 {
        let state: Value =
            serde_json::from_str(response_body(&server.get("/api/state"))).expect("UI state JSON");
        if state["job"]["state"] == "succeeded" {
            assert_eq!(state["audit"]["task_files"], 57);
            assert_eq!(state["audit"]["tasks"], 422);
            return;
        }
        assert_ne!(state["job"]["state"], "failed", "{state:#}");
        thread::sleep(Duration::from_millis(25));
    }
    panic!("audit job did not finish");
}

#[test]
fn ui_validates_inventory_and_builds_a_sealed_plan_without_contacting_hosts() {
    let server = TestServer::start();
    let page = server.get("/");
    let token = extract_between(&page, "name=\"ui-token\" content=\"", "\"")
        .expect("same-origin token in UI page");
    let directory = tempdir().expect("UI plan tempdir");
    let plan_path = directory.path().join("swift-plan.json");
    let config = config_body(plan_path.to_str().expect("UTF-8 plan path"));

    let validate = server.post("/api/validate", &config, &[("X-Swift-Deploy-Token", token)]);
    assert!(validate.starts_with("HTTP/1.1 202 Accepted"), "{validate}");
    let state = wait_for_job(&server, "validate");
    assert_eq!(state["inventory"]["hosts"], 2);
    assert!(
        state["inventory"]["placeholders"]
            .as_array()
            .is_some_and(|items| !items.is_empty())
    );

    let plan = server.post("/api/plan", &config, &[("X-Swift-Deploy-Token", token)]);
    assert!(plan.starts_with("HTTP/1.1 202 Accepted"), "{plan}");
    let state = wait_for_job(&server, "plan");
    assert_eq!(state["plan"]["hosts"], 2);
    assert_eq!(state["plan"]["tasks"], 336);
    assert_eq!(state["plan"]["digest"].as_str().map(str::len), Some(64));
    assert_eq!(state["plan"]["risks"].as_array().map(Vec::len), Some(4));
}

#[test]
fn ui_never_allows_apply_against_the_bundled_sample_inventory() {
    let server = TestServer::start();
    let page = server.get("/");
    let token = extract_between(&page, "name=\"ui-token\" content=\"", "\"")
        .expect("same-origin token in UI page");
    let directory = tempdir().expect("UI sample plan tempdir");
    let plan_path = directory.path().join("swift-plan.json");
    let config = config_body(plan_path.to_str().expect("UTF-8 plan path"));
    let plan = server.post("/api/plan", &config, &[("X-Swift-Deploy-Token", token)]);
    assert!(plan.starts_with("HTTP/1.1 202 Accepted"), "{plan}");
    let state = wait_for_job(&server, "plan");
    let digest = state["plan"]["digest"].as_str().expect("plan digest");
    let mut request: Value = serde_json::from_str(&config).expect("UI config JSON");
    let request = request.as_object_mut().expect("UI config object");
    request.insert(
        "confirm_digest".to_owned(),
        Value::String(digest.to_owned()),
    );
    request.insert("approval".to_owned(), Value::String("APPLY".to_owned()));
    request.insert("allow_disk_wipe".to_owned(), Value::Bool(true));
    request.insert("allow_firewall".to_owned(), Value::Bool(true));
    request.insert("allow_ssh_reconfigure".to_owned(), Value::Bool(true));
    request.insert("allow_host_reconfigure".to_owned(), Value::Bool(true));
    let body = serde_json::to_string(request).expect("serialize Apply request");

    let response = server.post("/api/apply", &body, &[("X-Swift-Deploy-Token", token)]);
    assert!(
        response.starts_with("HTTP/1.1 400 Bad Request"),
        "{response}"
    );
    assert!(response.contains("sample inventory"), "{response}");
}

#[test]
fn ui_rejects_a_copied_sample_before_contacting_hosts() {
    let server = TestServer::start();
    let page = server.get("/");
    let token = extract_between(&page, "name=\"ui-token\" content=\"", "\"")
        .expect("same-origin token in UI page");
    let directory = tempdir().expect("UI Apply tempdir");
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("bundle/config_sample");
    let config_root = directory.path().join("real-config");
    copy_tree(&source, &config_root);
    let inventory = config_root.join("swift_hosts");
    let plan_path = directory.path().join("swift-plan.json");
    let config = config_body_for(
        inventory.to_str().expect("UTF-8 inventory path"),
        plan_path.to_str().expect("UTF-8 plan path"),
    );
    let plan = server.post("/api/plan", &config, &[("X-Swift-Deploy-Token", token)]);
    assert!(plan.starts_with("HTTP/1.1 202 Accepted"), "{plan}");
    let state = wait_for_job(&server, "plan");
    let digest = state["plan"]["digest"].as_str().expect("plan digest");
    let mut request: Value = serde_json::from_str(&config).expect("UI config JSON");
    let request = request.as_object_mut().expect("UI config object");
    request.insert(
        "confirm_digest".to_owned(),
        Value::String(digest.to_owned()),
    );
    request.insert("approval".to_owned(), Value::String("APPLY".to_owned()));
    request.insert("allow_disk_wipe".to_owned(), Value::Bool(true));
    request.insert("allow_firewall".to_owned(), Value::Bool(true));
    request.insert("allow_ssh_reconfigure".to_owned(), Value::Bool(true));
    request.insert("allow_host_reconfigure".to_owned(), Value::Bool(true));
    let body = serde_json::to_string(request).expect("serialize Apply request");

    let response = server.post("/api/apply", &body, &[("X-Swift-Deploy-Token", token)]);
    assert!(
        response.starts_with("HTTP/1.1 400 Bad Request"),
        "{response}"
    );
    assert!(
        response.to_ascii_lowercase().contains("sample"),
        "{response}"
    );
}

fn wait_for_job(server: &TestServer, kind: &str) -> Value {
    for _ in 0..160 {
        let state: Value =
            serde_json::from_str(response_body(&server.get("/api/state"))).expect("UI state JSON");
        if state["job"]["kind"] == kind && state["job"]["state"] == "succeeded" {
            return state;
        }
        assert_ne!(state["job"]["state"], "failed", "{state:#}");
        thread::sleep(Duration::from_millis(25));
    }
    panic!("{kind} job did not finish");
}

fn config_body(plan: &str) -> String {
    config_body_for("bundle/config_sample/swift_hosts", plan)
}

fn config_body_for(inventory: &str, plan: &str) -> String {
    serde_json::to_string(&serde_json::json!({
        "bundle": "bundle",
        "inventory": inventory,
        "playbook": "bundle/swift.yml",
        "plan": plan,
        "known_hosts": ""
    }))
    .expect("serialize UI config")
}

fn copy_tree(source: &std::path::Path, destination: &std::path::Path) {
    fs::create_dir_all(destination).expect("create copied config directory");
    for entry in fs::read_dir(source).expect("read config source") {
        let entry = entry.expect("config source entry");
        let target = destination.join(entry.file_name());
        if entry.file_type().expect("config entry type").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).expect("copy config file");
        }
    }
}

fn response_body(response: &str) -> &str {
    response
        .split_once("\r\n\r\n")
        .map_or(response, |(_, body)| body)
}

fn extract_between<'a>(text: &'a str, prefix: &str, suffix: &str) -> Option<&'a str> {
    let start = text.find(prefix)? + prefix.len();
    let remaining = &text[start..];
    let end = remaining.find(suffix)?;
    Some(&remaining[..end])
}

struct TestServer {
    port: u16,
    child: Child,
}

impl TestServer {
    fn start() -> Self {
        let reservation = TcpListener::bind("127.0.0.1:0").expect("reserve UI test port");
        let port = reservation.local_addr().expect("test address").port();
        drop(reservation);
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let child = Command::new(env!("CARGO_BIN_EXE_swift-deploy"))
            .current_dir(&manifest)
            .args([
                "ui",
                "--port",
                &port.to_string(),
                "--bundle",
                "bundle",
                "--inventory",
                "bundle/config_sample/swift_hosts",
                "--playbook",
                "bundle/swift.yml",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start UI test server");
        let server = Self { port, child };
        for _ in 0..240 {
            if server.try_get("/healthz").is_some() {
                return server;
            }
            thread::sleep(Duration::from_millis(25));
        }
        panic!("UI test server never became ready");
    }

    fn get(&self, path: &str) -> String {
        self.try_get(path).expect("UI HTTP response")
    }

    fn post(&self, path: &str, body: &str, headers: &[(&str, &str)]) -> String {
        let mut request = format!(
            "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        );
        for (name, value) in headers {
            request.push_str(&format!("{name}: {value}\r\n"));
        }
        request.push_str("Connection: close\r\n\r\n");
        request.push_str(body);
        self.request(&request).expect("UI POST response")
    }

    fn try_get(&self, path: &str) -> Option<String> {
        self.request(&format!(
            "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
        ))
    }

    fn request(&self, request: &str) -> Option<String> {
        let mut stream = TcpStream::connect(("127.0.0.1", self.port)).ok()?;
        stream.write_all(request.as_bytes()).ok()?;
        stream.shutdown(Shutdown::Write).ok()?;
        let mut response = String::new();
        stream.read_to_string(&mut response).ok()?;
        Some(response)
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
