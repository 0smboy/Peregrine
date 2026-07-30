use std::fs;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

use serde_json::{Value, json};
use tempfile::{TempDir, tempdir};

const TEMPAUTH_KEY: &str = "Tempauth-Key-9xQ4";

#[test]
fn rust_workspace_generates_validates_and_carries_no_keystone_apply_blockers() {
    let server = TestServer::start();

    let response = server.authorized_post("/api/workspace/generate", &rust_workspace_request());
    assert!(
        response.starts_with("HTTP/1.1 201 Created"),
        "generate failed: {response}"
    );
    assert!(
        !response.contains(TEMPAUTH_KEY),
        "workspace API leaked the tempauth key: {response}"
    );
    let generated = response_json(&response);
    assert_eq!(generated["ok"], true, "{generated:#}");
    assert_eq!(generated["summary"]["auth_method"], "tempauth");
    assert_eq!(generated["summary"]["ingress_mode"], "direct");
    let files = generated["files"].as_array().expect("generated files");
    let all = files
        .iter()
        .find(|file| file["path"] == "group_vars/all")
        .and_then(|file| file["content"].as_str())
        .expect("generated group_vars/all");
    assert!(all.contains("deploy_stack: rust"), "{all}");
    assert!(all.contains("auth_method: tempauth"), "{all}");
    assert!(all.contains("swift_policies"), "{all}");
    assert!(
        all.contains("ring_fetch_dir: /var/lib/swift-deploy/rings/rocky9-rust-tempauth"),
        "{all}"
    );
    assert!(
        !files
            .iter()
            .any(|file| file["path"] == "group_vars/keystones"
                || file["path"] == "group_vars/mariadb_servers"),
        "rust workspace must not render keystone/mariadb group_vars files: {files:#?}"
    );

    let inventory = PathBuf::from(generated["inventory"].as_str().expect("inventory path"));
    let playbook = PathBuf::from(generated["playbook"].as_str().expect("playbook path"));
    let plan = PathBuf::from(generated["plan"].as_str().expect("plan path"));
    let config = json!({
        "bundle": server.bundle(),
        "inventory": inventory,
        "playbook": playbook,
        "plan": plan,
        "known_hosts": ""
    });
    let validate = server.authorized_post("/api/validate", &config);
    assert!(
        validate.starts_with("HTTP/1.1 202 Accepted"),
        "validate rejected: {validate}"
    );
    let state = wait_for_job(&server, "validate");
    assert_eq!(state["inventory"]["hosts"], 3, "{state:#}");
    assert_eq!(
        state["inventory"]["sample"], false,
        "rust workspace with empty mariadb_servers/keystones groups must not be blocked: {state:#}"
    );
    assert_eq!(
        state["inventory"]["apply_blockers"]
            .as_array()
            .map(Vec::len),
        Some(0),
        "unexpected apply blockers for the rust workspace: {state:#}"
    );
}

fn rust_workspace_request() -> Value {
    json!({
        "project_name": "rocky9-rust-tempauth",
        "stack": "rust",
        "deployment_mode": "production",
        "saio": false,
        "use_wwid": false,
        "hostname_modifiable": false,
        "hostname_prefix": "swift",
        "timezone": "Asia/Shanghai",
        "ntp_internet_server": "time.cloudflare.com",
        "local_repo_address": "",
        "admin_ips": ["10.88.0.10"],
        "ssh_bind_port": 2222,
        "nodes": [
            rust_node("rust-a", "10.88.0.11", 1, json!([]), "ntp_server"),
            rust_node("rust-b", "10.88.0.12", 2, json!([]), "ntp_client"),
            rust_node("rust-c", "10.88.0.13", 3, json!([]), "ntp_client")
        ],
        "ring": {
            "partition_power": 10,
            "replicas": 3,
            "minimum_time": 1,
            "object_policy_name": "Policy-0",
            "object_policy_type": "replication",
            "ec_data_fragments": null,
            "ec_parity_fragments": null,
            "ec_segment_size": 1_048_576,
            "device_weight": 100
        },
        "auth": {
            "method": "tempauth",
            "interface": "swift",
            "account_name": "",
            "admin_user": "",
            "admin_password": "",
            "mariadb_root_password": "",
            "mariadb_keystone_password": "",
            "mariadb_clustercheck_password": "",
            "keystone_admin_password": "",
            "keystone_swift_password": "",
            "keystone_controller_hostname": "",
            "haproxy_stats_user": "",
            "haproxy_stats_password": ""
        },
        "tempauth_accounts": [
            { "account": "test", "user": "tester", "key": TEMPAUTH_KEY }
        ],
        "ingress": {
            "mode": "direct",
            "http_mode": "http",
            "auth_url_ip": "10.88.20.11",
            "swift_port": 8080,
            "vip_prefix": 24,
            "virtual_router_id": 51,
            "vrrp_auth_pass": ""
        }
    })
}

fn rust_node(name: &str, management_ip: &str, zone: u16, disks: Value, ntp_role: &str) -> Value {
    let storage_ip = management_ip.replacen("10.88.0.", "10.88.10.", 1);
    let business_ip = management_ip.replacen("10.88.0.", "10.88.20.", 1);
    let system_disk = if disks.as_array().is_some_and(Vec::is_empty) {
        ""
    } else {
        "/dev/sda"
    };
    json!({
        "name": name,
        "address": management_ip,
        "ssh_user": "root",
        "ssh_port": 22,
        "ssh_key_file": "/root/.ssh/id_ed25519",
        "management_ip": management_ip,
        "storage_ip": storage_ip.clone(),
        "replication_ip": storage_ip,
        "business_ip": business_ip,
        "region": 1,
        "zone": zone,
        "roles": ["proxy", "account", "container", "object", ntp_role],
        "disk_type": "hdd",
        "system_disk": system_disk,
        "disks": disks,
        "keepalived_interface": "",
        "keepalived_priority": null
    })
}

fn write_rust_fixture_bundle(root: &Path) -> PathBuf {
    let bundle = root.join("bundle-rust");
    fs::create_dir_all(bundle.join("config_sample/group_vars")).expect("fixture group_vars");
    fs::write(
        bundle.join("swift.yml"),
        "---\n- hosts: all\n  roles:\n    - rust_common\n",
    )
    .expect("fixture swift.yml");
    fs::write(
        bundle.join("config_sample/group_vars/all.raw"),
        "---\ndeploy_stack: rust\nsrv_node_root: /srv/node\n",
    )
    .expect("fixture all.raw");
    fs::write(
        bundle.join("config_sample/swift_hosts"),
        "[all]\n\n[proxy_servers]\n",
    )
    .expect("fixture sample inventory");
    bundle
}

fn wait_for_job(server: &TestServer, kind: &str) -> Value {
    for _ in 0..240 {
        let state = response_json(&server.get("/api/state"));
        if state["job"]["kind"] == kind && state["job"]["state"] == "succeeded" {
            return state;
        }
        assert_ne!(state["job"]["state"], "failed", "{state:#}");
        thread::sleep(Duration::from_millis(25));
    }
    panic!("{kind} job did not finish");
}

fn response_json(response: &str) -> Value {
    let body = response
        .split_once("\r\n\r\n")
        .map_or(response, |(_, body)| body);
    serde_json::from_str(body).unwrap_or_else(|error| {
        panic!("parse HTTP JSON response: {error}; response was: {response}")
    })
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
    root: TempDir,
}

impl TestServer {
    fn start() -> Self {
        let reservation = TcpListener::bind("127.0.0.1:0").expect("reserve UI test port");
        let port = reservation.local_addr().expect("test address").port();
        drop(reservation);
        let root = tempdir().expect("UI rust test root");
        let bundle = write_rust_fixture_bundle(root.path());
        let workspace_root = root.path().join("projects");
        fs::create_dir_all(&workspace_root).expect("workspace root");
        let child = Command::new(env!("CARGO_BIN_EXE_swift-deploy"))
            .current_dir(root.path())
            .args(["ui", "--port", &port.to_string(), "--bundle"])
            .arg(&bundle)
            .arg("--inventory")
            .arg(bundle.join("config_sample/swift_hosts"))
            .arg("--playbook")
            .arg(bundle.join("swift.yml"))
            .arg("--plan")
            .arg(workspace_root.join("default-plan.json"))
            .arg("--workspace-root")
            .arg(&workspace_root)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start UI rust test server");
        let server = Self { port, child, root };
        for _ in 0..120 {
            if server.try_get("/healthz").is_some() {
                return server;
            }
            thread::sleep(Duration::from_millis(25));
        }
        panic!("UI rust test server never became ready");
    }

    fn bundle(&self) -> PathBuf {
        self.root.path().join("bundle-rust")
    }

    fn token(&self) -> String {
        extract_between(&self.get("/"), "name=\"ui-token\" content=\"", "\"")
            .expect("same-origin token in UI page")
            .to_owned()
    }

    fn get(&self, path: &str) -> String {
        self.try_get(path).expect("UI HTTP response")
    }

    fn authorized_post(&self, path: &str, body: &Value) -> String {
        let token = self.token();
        let body = serde_json::to_string(body).expect("serialize UI request");
        let request = format!(
            "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nX-Swift-Deploy-Token: {token}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
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
