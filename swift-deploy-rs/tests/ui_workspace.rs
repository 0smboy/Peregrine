use std::fs;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

use serde_json::{Value, json};
use tempfile::{TempDir, tempdir};

const ADMIN_PASSWORD: &str = "Admin-Prod-9sQ4";
const MARIADB_ROOT_PASSWORD: &str = "Maria-Root-8cK2";
const MARIADB_KEYSTONE_PASSWORD: &str = "Maria-Keystone-7mP3";
const KEYSTONE_ADMIN_PASSWORD: &str = "Keystone-Admin-6hR5";
const KEYSTONE_SWIFT_PASSWORD: &str = "Keystone-Swift-5vN7";
const VRRP_AUTH_PASS: &str = "Vr9Pass";

#[test]
fn workspace_mutations_require_the_same_origin_token() {
    let server = TestServer::start();
    let body = production_workspace_request();

    for endpoint in ["/api/workspace/preview", "/api/workspace/generate"] {
        let response = server.post(endpoint, &body, &[]);
        assert_status(&response, "403 Forbidden");
        assert!(response.contains("anti-CSRF token"), "{response}");
    }
}

#[test]
fn workspace_generation_rejects_invalid_configuration_without_writing_files() {
    let server = TestServer::start();
    let mut body = production_workspace_request();
    body["nodes"] = json!([]);

    let response = server.authorized_post("/api/workspace/generate", &body);
    assert_status(&response, "422 Unprocessable Entity");
    assert_no_secret_is_returned(&response);
    let rejection = response_json(&response);
    assert_eq!(rejection["valid"], false, "{rejection:#}");
    assert!(
        rejection["errors"]
            .as_array()
            .is_some_and(|errors| !errors.is_empty()),
        "{rejection:#}"
    );
    assert_eq!(
        fs::read_dir(server.workspace_root())
            .expect("read workspace root after rejected generation")
            .count(),
        0,
        "invalid configuration must not create a deployment project"
    );
}

#[test]
fn workspace_preview_is_complete_read_only_and_redacts_every_secret() {
    let server = TestServer::start();
    let response =
        server.authorized_post("/api/workspace/preview", &production_workspace_request());
    assert_status(&response, "200 OK");
    assert_secrets_are_redacted(&response);

    let preview = response_json(&response);
    assert_eq!(preview["valid"], true, "{preview:#}");
    assert_eq!(preview["errors"].as_array().map(Vec::len), Some(0));
    assert_eq!(preview["summary"]["project_name"], "rocky9-keystone-http");
    assert_eq!(preview["summary"]["deployment_mode"], "production");
    assert_eq!(preview["summary"]["node_count"], 3);
    assert_eq!(preview["summary"]["storage_node_count"], 3);
    assert_eq!(preview["summary"]["disk_count"], 6);
    assert_eq!(preview["summary"]["replicas"], 3);
    assert_eq!(preview["summary"]["auth_method"], "keystone");
    assert_eq!(preview["summary"]["http_mode"], "http");
    assert_eq!(preview["summary"]["ingress_mode"], "keepalived");
    assert_eq!(preview["summary"]["regions"], json!([1]));
    assert_eq!(preview["summary"]["zones"], json!([1, 2, 3]));

    let files = workspace_files(&preview);
    assert!(
        files.iter().any(|file| file["path"] == "swift_hosts"),
        "{files:#?}"
    );
    assert!(
        files
            .iter()
            .any(|file| file["path"] == "group_vars/all.raw"),
        "{files:#?}"
    );
    assert!(
        files
            .iter()
            .any(|file| file["path"] == "group_vars/ring_config.yml"),
        "{files:#?}"
    );
    for host in ["10.77.0.11", "10.77.0.12", "10.77.0.13"] {
        let host_vars = format!("host_vars/{host}.yml");
        assert!(
            files.iter().any(|file| file["path"] == host_vars),
            "missing {host_vars}: {files:#?}"
        );
    }
    for file in files {
        assert!(file["path"].is_string(), "{file:#}");
        assert!(file["content"].is_string(), "{file:#}");
    }

    let inventory = workspace_file_content(&preview, "swift_hosts");
    for host in ["10.77.0.11", "10.77.0.12", "10.77.0.13"] {
        assert!(inventory.contains(host), "{inventory}");
    }
    for label in ["swift-a", "swift-b", "swift-c"] {
        assert!(
            !inventory.contains(label),
            "UI labels must not become Ansible inventory hostnames: {inventory}"
        );
    }
    let metadata = workspace_file_content(&preview, ".swift-deploy-workspace.json");
    for label in ["swift-a", "swift-b", "swift-c"] {
        assert!(
            metadata.contains(label),
            "missing UI label metadata: {metadata}"
        );
    }

    assert_eq!(
        fs::read_dir(server.workspace_root())
            .expect("read workspace root after preview")
            .count(),
        0,
        "preview must not create a deployment project"
    );
}

#[test]
fn compiled_workspace_uses_the_selected_port_and_proxy_only_storage_addresses() {
    let server = TestServer::start();
    let mut body = production_workspace_request();
    body["ingress"]["swift_port"] = json!(6060);
    let roles = body["nodes"][2]["roles"]
        .as_array_mut()
        .expect("node roles");
    roles.retain(|role| role != "proxy");

    let response = server.authorized_post("/api/workspace/preview", &body);
    assert_status(&response, "200 OK");
    let preview = response_json(&response);
    assert_eq!(preview["valid"], true, "{preview:#}");

    let raw: Value =
        serde_yaml_ng::from_str(workspace_file_content(&preview, "group_vars/all.raw"))
            .expect("parse generated all.raw");
    assert_eq!(raw["haproxy_storage_port"], 6060);
    assert_eq!(raw["swift_lb_port"], 6060);

    let compiled: Value =
        serde_yaml_ng::from_str(workspace_file_content(&preview, "group_vars/all"))
            .expect("parse generated compiled all");
    assert_eq!(
        compiled["proxy_storage_network_addresses"],
        json!(["10.77.10.11", "10.77.10.12"])
    );
    assert!(
        compiled["business_network_public_ports"]
            .as_array()
            .is_some_and(|ports| ports.contains(&json!(6060)))
    );
    assert!(
        !compiled["business_network_public_ports"]
            .as_array()
            .is_some_and(|ports| ports.contains(&json!(5050)))
    );
}

#[test]
fn unsupported_or_unsafe_workspace_choices_fail_closed() {
    let server = TestServer::start();

    let mut direct = production_workspace_request();
    direct["ingress"]["mode"] = json!("direct");
    direct["ingress"]["auth_url_ip"] = json!("10.77.20.11");
    assert_preview_error(&server, &direct, "ingress.mode", "Keystone");

    let mut non_storage_disk = production_workspace_request();
    non_storage_disk["nodes"][0]["roles"] = json!(["proxy", "ntp_server"]);
    assert_preview_error(&server, &non_storage_disk, "nodes[0].disks", "非存储节点");

    let mut extra_keepalived = production_workspace_request();
    extra_keepalived["ingress"]["mode"] = json!("haproxy");
    extra_keepalived["ingress"]["auth_url_ip"] = json!("10.77.20.11");
    assert_preview_error(
        &server,
        &extra_keepalived,
        "nodes.roles",
        "不能包含 Keepalived",
    );

    let mut tempauth = production_workspace_request();
    tempauth["auth"]["method"] = json!("tempauth");
    assert_preview_error(&server, &tempauth, "auth.method", "TempAuth");

    let mut ec = production_workspace_request();
    ec["ring"]["object_policy_type"] = json!("erasure_coding");
    ec["ring"]["ec_data_fragments"] = json!(2);
    ec["ring"]["ec_parity_fragments"] = json!(1);
    assert_preview_error(&server, &ec, "ring.object_policy_type", "暂不允许 EC");

    let mut unsafe_password = production_workspace_request();
    unsafe_password["auth"]["admin_password"] = json!("Unsafe!Password");
    assert_preview_error(
        &server,
        &unsafe_password,
        "auth.admin_password",
        "只允许 ASCII",
    );
}

#[test]
fn generated_workspace_validates_and_builds_a_sealed_three_node_plan() {
    let server = TestServer::start();
    let response =
        server.authorized_post("/api/workspace/generate", &production_workspace_request());
    assert_status(&response, "201 Created");
    assert_secrets_are_redacted(&response);

    let generated = response_json(&response);
    assert_eq!(generated["ok"], true, "{generated:#}");
    assert_eq!(generated["summary"]["node_count"], 3);
    assert_eq!(generated["summary"]["auth_method"], "keystone");
    assert_eq!(generated["summary"]["http_mode"], "http");
    let files = workspace_files(&generated);
    assert!(!files.is_empty(), "{generated:#}");
    for file in files {
        assert!(file["path"].is_string(), "{file:#}");
        assert!(file["content"].is_string(), "{file:#}");
    }

    let project_root = response_path(&generated, "project_root");
    let inventory = response_path(&generated, "inventory");
    let playbook = response_path(&generated, "playbook");
    let plan = response_path(&generated, "plan");
    assert!(project_root.is_dir(), "{}", project_root.display());
    assert!(inventory.is_file(), "{}", inventory.display());
    assert!(playbook.is_file(), "{}", playbook.display());
    assert!(inventory.starts_with(&project_root));
    assert!(plan.starts_with(&project_root));
    assert!(
        project_root
            .canonicalize()
            .expect("canonical project root")
            .starts_with(
                server
                    .workspace_root()
                    .canonicalize()
                    .expect("canonical workspace root")
            )
    );

    let inventory_text = fs::read_to_string(&inventory).expect("read generated inventory");
    for address in ["10.77.0.11", "10.77.0.12", "10.77.0.13"] {
        assert!(inventory_text.contains(address), "{inventory_text}");
    }
    assert!(!inventory_text.contains("192.168.2.51"));
    assert!(!inventory_text.contains("/path/to/id_ed25519"));

    let config = ui_config(&inventory, &playbook, &plan);
    let validate = server.authorized_post("/api/validate", &config);
    assert_status(&validate, "202 Accepted");
    let state = wait_for_job(&server, "validate");
    assert_eq!(state["inventory"]["hosts"], 3, "{state:#}");
    assert_eq!(
        state["inventory"]["placeholders"].as_array().map(Vec::len),
        Some(0),
        "generated production configuration contains placeholders: {state:#}"
    );
    assert_eq!(state["inventory"]["sample"], false, "{state:#}");

    let plan_response = server.authorized_post("/api/plan", &config);
    assert_status(&plan_response, "202 Accepted");
    let state = wait_for_job(&server, "plan");
    assert_eq!(state["plan"]["hosts"], 3, "{state:#}");
    assert!(
        state["plan"]["tasks"]
            .as_u64()
            .is_some_and(|tasks| tasks > 0),
        "{state:#}"
    );
    assert_eq!(state["plan"]["digest"].as_str().map(str::len), Some(64));
    assert!(
        plan.is_file(),
        "sealed plan was not written: {}",
        plan.display()
    );

    let digest = state["plan"]["digest"]
        .as_str()
        .expect("generated plan digest");
    let mut wrong_digest = config.clone();
    let request = wrong_digest.as_object_mut().expect("UI config object");
    request.insert("confirm_digest".to_owned(), json!("0".repeat(64)));
    request.insert("approval".to_owned(), json!("APPLY"));
    request.insert("allow_disk_wipe".to_owned(), json!(true));
    request.insert("allow_firewall".to_owned(), json!(true));
    request.insert("allow_ssh_reconfigure".to_owned(), json!(true));
    request.insert("allow_host_reconfigure".to_owned(), json!(true));
    let response = server.authorized_post("/api/apply", &wrong_digest);
    assert_status(&response, "400 Bad Request");
    assert!(
        response.contains("does not match sealed digest"),
        "{response}"
    );

    let mut missing_risks = config;
    let request = missing_risks.as_object_mut().expect("UI config object");
    request.insert("confirm_digest".to_owned(), json!(digest));
    request.insert("approval".to_owned(), json!("APPLY"));
    let response = server.authorized_post("/api/apply", &missing_risks);
    assert_status(&response, "400 Bad Request");
    for risk in ["DiskWipe", "Firewall", "SshReconfigure", "HostReconfigure"] {
        assert!(response.contains(risk), "missing {risk}: {response}");
    }
}

#[test]
fn copied_bundled_sample_is_still_rejected_before_apply() {
    let server = TestServer::start();
    let copied_root = server.workspace_root().join("copied-deployment");
    copy_tree(
        &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("bundle/config_sample"),
        &copied_root,
    );
    let inventory = copied_root.join("swift_hosts");
    let playbook = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("bundle/swift.yml");
    let plan = copied_root.join("swift-plan.json");
    let config = ui_config(&inventory, &playbook, &plan);

    let plan_response = server.authorized_post("/api/plan", &config);
    assert_status(&plan_response, "202 Accepted");
    let state = wait_for_job(&server, "plan");
    let digest = state["plan"]["digest"]
        .as_str()
        .expect("sample plan digest");
    let mut apply = config;
    let object = apply.as_object_mut().expect("UI config object");
    object.insert("confirm_digest".to_owned(), json!(digest));
    object.insert("approval".to_owned(), json!("APPLY"));
    object.insert("allow_disk_wipe".to_owned(), json!(true));
    object.insert("allow_firewall".to_owned(), json!(true));
    object.insert("allow_ssh_reconfigure".to_owned(), json!(true));
    object.insert("allow_host_reconfigure".to_owned(), json!(true));

    let response = server.authorized_post("/api/apply", &apply);
    assert_status(&response, "400 Bad Request");
    assert!(
        response.to_ascii_lowercase().contains("sample"),
        "copied sample must be rejected by content, not only by path: {response}"
    );
}

fn production_workspace_request() -> Value {
    json!({
        "project_name": "rocky9-keystone-http",
        "deployment_mode": "production",
        "saio": false,
        "use_wwid": false,
        "hostname_modifiable": true,
        "hostname_prefix": "swift",
        "timezone": "Asia/Shanghai",
        "ntp_internet_server": "time.cloudflare.com",
        "local_repo_address": "10.77.0.10",
        "admin_ips": ["10.77.0.10"],
        "ssh_bind_port": 2222,
        "nodes": [
            production_node("swift-a", "10.77.0.11", "10.77.10.11", "10.77.10.11", "10.77.20.11", 1, 160),
            production_node("swift-b", "10.77.0.12", "10.77.10.12", "10.77.10.12", "10.77.20.12", 2, 150),
            production_node("swift-c", "10.77.0.13", "10.77.10.13", "10.77.10.13", "10.77.20.13", 3, 140)
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
            "method": "keystone",
            "interface": "swift",
            "account_name": "production",
            "admin_user": "cluster_admin",
            "admin_password": ADMIN_PASSWORD,
            "mariadb_root_password": MARIADB_ROOT_PASSWORD,
            "mariadb_keystone_password": MARIADB_KEYSTONE_PASSWORD,
            "mariadb_clustercheck_password": "Maria-Check-4dL8",
            "keystone_admin_password": KEYSTONE_ADMIN_PASSWORD,
            "keystone_swift_password": KEYSTONE_SWIFT_PASSWORD,
            "keystone_controller_hostname": "swift-vip",
            "haproxy_stats_user": "haproxy_observer",
            "haproxy_stats_password": "HAProxy-Stats-3qT9"
        },
        "ingress": {
            "mode": "keepalived",
            "http_mode": "http",
            "auth_url_ip": "10.77.20.100",
            "swift_port": 5050,
            "vip_prefix": 24,
            "virtual_router_id": 51,
            "vrrp_auth_pass": VRRP_AUTH_PASS
        }
    })
}

fn production_node(
    name: &str,
    management_ip: &str,
    storage_ip: &str,
    replication_ip: &str,
    business_ip: &str,
    zone: u16,
    keepalived_priority: u16,
) -> Value {
    let ntp_role = if zone == 1 {
        "ntp_server"
    } else {
        "ntp_client"
    };
    json!({
        "name": name,
        "address": management_ip,
        "ssh_user": "root",
        "ssh_port": 22,
        "ssh_key_file": "/root/.ssh/id_ed25519",
        "management_ip": management_ip,
        "storage_ip": storage_ip,
        "replication_ip": replication_ip,
        "business_ip": business_ip,
        "region": 1,
        "zone": zone,
        "roles": [
            "proxy",
            "account",
            "container",
            "object",
            "keystone",
            "mariadb",
            "haproxy",
            "keepalived",
            ntp_role
        ],
        "disk_type": "hdd",
        "system_disk": "/dev/sda",
        "disks": ["/dev/sdb", "/dev/sdc"],
        "keepalived_interface": "eth2",
        "keepalived_priority": keepalived_priority
    })
}

fn ui_config(inventory: &Path, playbook: &Path, plan: &Path) -> Value {
    json!({
        "bundle": PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("bundle"),
        "inventory": inventory,
        "playbook": playbook,
        "plan": plan,
        "known_hosts": ""
    })
}

fn workspace_files(response: &Value) -> &[Value] {
    response["files"]
        .as_array()
        .expect("files must be [{path, content}] so the UI can render an exact redacted preview")
}

fn workspace_file_content<'a>(response: &'a Value, path: &str) -> &'a str {
    workspace_files(response)
        .iter()
        .find(|file| file["path"] == path)
        .and_then(|file| file["content"].as_str())
        .unwrap_or_else(|| panic!("missing generated file {path}: {response:#}"))
}

fn assert_preview_error(server: &TestServer, body: &Value, field: &str, message: &str) {
    let response = server.authorized_post("/api/workspace/preview", body);
    assert_status(&response, "200 OK");
    assert_no_secret_is_returned(&response);
    let preview = response_json(&response);
    assert_eq!(preview["valid"], false, "{preview:#}");
    assert!(
        preview["errors"]
            .as_array()
            .is_some_and(|errors| errors.iter().any(|issue| issue["field"] == field
                && issue["message"]
                    .as_str()
                    .is_some_and(|text| text.contains(message)))),
        "missing validation error {field} containing {message}: {preview:#}"
    );
    assert_eq!(
        preview["files"].as_array().map(Vec::len),
        Some(0),
        "invalid preview must not render workspace files: {preview:#}"
    );
}

fn response_path(response: &Value, field: &str) -> PathBuf {
    PathBuf::from(
        response[field]
            .as_str()
            .unwrap_or_else(|| panic!("missing {field} path: {response:#}")),
    )
}

fn assert_secrets_are_redacted(response: &str) {
    assert_no_secret_is_returned(response);
    assert!(response.contains("<redacted>"), "{response}");
}

fn assert_no_secret_is_returned(response: &str) {
    for secret in [
        ADMIN_PASSWORD,
        MARIADB_ROOT_PASSWORD,
        MARIADB_KEYSTONE_PASSWORD,
        KEYSTONE_ADMIN_PASSWORD,
        KEYSTONE_SWIFT_PASSWORD,
        VRRP_AUTH_PASS,
    ] {
        assert!(
            !response.contains(secret),
            "workspace API leaked a secret value: {response}"
        );
    }
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

fn copy_tree(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).expect("create copied sample directory");
    for entry in fs::read_dir(source).expect("read sample directory") {
        let entry = entry.expect("sample entry");
        let target = destination.join(entry.file_name());
        if entry.file_type().expect("sample entry type").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).expect("copy sample file");
        }
    }
}

fn assert_status(response: &str, expected: &str) {
    assert!(
        response.starts_with(&format!("HTTP/1.1 {expected}")),
        "expected {expected}, received: {response}"
    );
}

fn response_json(response: &str) -> Value {
    serde_json::from_str(response_body(response)).unwrap_or_else(|error| {
        panic!("parse HTTP JSON response: {error}; response was: {response}")
    })
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
    workspace_root: TempDir,
}

impl TestServer {
    fn start() -> Self {
        let reservation = TcpListener::bind("127.0.0.1:0").expect("reserve UI test port");
        let port = reservation.local_addr().expect("test address").port();
        drop(reservation);
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = tempdir().expect("UI workspace root");
        let child = Command::new(env!("CARGO_BIN_EXE_swift-deploy"))
            .current_dir(&manifest)
            .args(["ui", "--port", &port.to_string(), "--bundle"])
            .arg(manifest.join("bundle"))
            .arg("--inventory")
            .arg(manifest.join("bundle/config_sample/swift_hosts"))
            .arg("--playbook")
            .arg(manifest.join("bundle/swift.yml"))
            .arg("--plan")
            .arg(workspace_root.path().join("default-plan.json"))
            .arg("--workspace-root")
            .arg(workspace_root.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start UI workspace test server");
        let server = Self {
            port,
            child,
            workspace_root,
        };
        for _ in 0..120 {
            if server.try_get("/healthz").is_some() {
                return server;
            }
            thread::sleep(Duration::from_millis(25));
        }
        panic!("UI workspace test server never became ready");
    }

    fn workspace_root(&self) -> &Path {
        self.workspace_root.path()
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
        self.post(path, body, &[("X-Swift-Deploy-Token", &token)])
    }

    fn post(&self, path: &str, body: &Value, headers: &[(&str, &str)]) -> String {
        let body = serde_json::to_string(body).expect("serialize UI request");
        let mut request = format!(
            "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        );
        for (name, value) in headers {
            request.push_str(&format!("{name}: {value}\r\n"));
        }
        request.push_str("Connection: close\r\n\r\n");
        request.push_str(&body);
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
