use std::fs;
use std::path::{Path, PathBuf};

use swift_deploy_rs::Inventory;
use swift_deploy_rs::workspace::{Auth, Ingress, Node, Ring, TempauthAccount, WorkspaceRequest};
use tempfile::tempdir;

const TEMPAUTH_KEY: &str = "Tempauth-Key-9xQ4";

#[test]
fn rust_stack_workspace_generates_tempauth_group_vars_without_keystone_files() {
    let root = tempdir().expect("workspace root");
    let bundle = rust_fixture_bundle(root.path());
    let request = rust_request();

    let report = request.validate();
    assert!(report.valid, "{:#?}", report.errors);

    let generated = request
        .generate(&bundle, root.path().join("projects"))
        .expect("generate rust workspace");

    let all = fs::read_to_string(generated.project_root.join("group_vars/all"))
        .expect("read generated rust group_vars/all");
    let compiled: serde_json::Value =
        serde_yaml_ng::from_str(&all).expect("parse rust group_vars/all");
    assert_eq!(compiled["deploy_stack"], "rust");
    assert_eq!(compiled["auth_method"], "tempauth");
    assert_eq!(compiled["swift_tempauth_users"][0]["account"], "test");
    assert_eq!(compiled["swift_tempauth_users"][0]["user"], "tester");
    assert_eq!(compiled["swift_tempauth_users"][0]["key"], TEMPAUTH_KEY);
    assert_eq!(compiled["swift_tempauth_users"][0]["admin"], true);
    assert_eq!(compiled["proxy_bind_port"], 8080);
    assert_eq!(compiled["object_bind_port"], 6200);
    assert_eq!(compiled["srv_node_root"], "/srv/node");
    assert_eq!(
        compiled["ring_fetch_dir"], "/var/lib/swift-deploy/rings/rocky9-rust-tempauth",
        "ring_fetch_dir must be a per-project controller-side staging directory"
    );
    assert_eq!(compiled["swift_policies"][0]["index"], 0);
    assert_eq!(compiled["swift_policies"][0]["name"], "Policy-0");
    assert_eq!(compiled["swift_policies"][0]["type"], "replication");
    assert_eq!(compiled["swift_policies"][0]["default"], true);
    assert_eq!(compiled["swift_device_weight"], 100);
    assert_eq!(compiled["use_lb"], false);
    assert_eq!(compiled["auth_url_ip"], "10.88.20.11");
    assert_eq!(compiled["swift_lb_port"], 8080);
    let keys = compiled
        .as_object()
        .expect("rust group_vars/all mapping")
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    assert!(
        !keys
            .iter()
            .any(|key| key.to_ascii_lowercase().contains("mariadb")
                || key.to_ascii_lowercase().contains("keystone")),
        "rust group_vars/all leaked keystone/mariadb variables: {keys:?}"
    );

    for name in ["keystones", "mariadb_servers"] {
        assert!(
            !generated
                .project_root
                .join("group_vars")
                .join(name)
                .exists(),
            "rust workspace must not carry a group_vars/{name} file"
        );
    }

    let inventory = Inventory::load(&generated.inventory).expect("load generated rust inventory");
    for group in [
        "proxy_servers",
        "account_servers",
        "container_servers",
        "object_servers",
        "mariadb_servers",
        "keystones",
        "haproxy_servers",
        "keepalived_servers",
    ] {
        assert!(
            inventory.groups.contains_key(group),
            "missing shared inventory group {group}"
        );
    }
    for group in ["mariadb_servers", "keystones", "haproxy_servers"] {
        assert!(
            inventory.groups[group].hosts.is_empty(),
            "rust inventory group {group} must stay empty"
        );
    }
    let diskless = inventory
        .host_context("10.88.0.13")
        .expect("diskless host context");
    assert_eq!(
        diskless["custom_disks"],
        serde_json::json!([]),
        "rust nodes may carry zero data disks"
    );
    assert_eq!(diskless["deploy_stack"], "rust");
}

#[test]
fn rust_stack_allows_a_dedicated_replication_network() {
    // Dedicated WireGuard-style storage (172.18.1.0/24) and replication
    // (172.19.1.0/24) networks: replication may differ from storage for rust.
    let mut request = rust_request();
    for (index, node) in request.nodes.iter_mut().enumerate() {
        node.storage_ip = format!("172.18.1.{}", 11 + index);
        node.replication_ip = format!("172.19.1.{}", 11 + index);
    }

    let report = request.validate();
    assert!(report.valid, "{:#?}", report.errors);

    let root = tempdir().expect("workspace root");
    let bundle = rust_fixture_bundle(root.path());
    let generated = request
        .generate(&bundle, root.path().join("projects"))
        .expect("generate rust workspace with split replication");
    let host_vars = fs::read_to_string(generated.project_root.join("host_vars/10.88.0.11.yml"))
        .expect("read split-replication host vars");
    assert!(
        host_vars.contains("storage_network_address: 172.18.1.11"),
        "{host_vars}"
    );
    assert!(
        host_vars.contains("replication_network_address: 172.19.1.11"),
        "{host_vars}"
    );

    // An empty replication address falls back to the storage network.
    let mut fallback = rust_request();
    for node in &mut fallback.nodes {
        node.replication_ip = String::new();
    }
    let report = fallback.validate();
    assert!(report.valid, "{:#?}", report.errors);
    let generated = fallback
        .generate(&bundle, root.path().join("projects-fallback"))
        .expect("generate rust workspace with defaulted replication");
    let host_vars = fs::read_to_string(generated.project_root.join("host_vars/10.88.0.11.yml"))
        .expect("read fallback host vars");
    assert!(
        host_vars.contains("replication_network_address: 10.88.10.11"),
        "{host_vars}"
    );

    // python-v3 keeps the replication==storage pin (also covered by
    // workspace_config::upstream_v3_rejects_a_split_replication_address).
    let mut python = rust_request();
    python.stack = "python-v3".to_owned();
    python.nodes[0].replication_ip = "172.19.1.11".to_owned();
    let report = python.validate();
    assert!(report.errors.iter().any(|issue| {
        issue.field == "nodes[0].replication_ip"
            && issue.message.contains("storage_network_address")
    }));
}

#[test]
fn rust_stack_preview_redacts_tempauth_keys() {
    let root = tempdir().expect("workspace root");
    let bundle = rust_fixture_bundle(root.path());
    let preview = rust_request()
        .preview(&bundle)
        .expect("preview rust workspace");
    assert!(preview.valid, "{:#?}", preview.errors);
    let serialized = serde_json::to_string(&preview).expect("serialize rust preview");
    assert!(
        !serialized.contains(TEMPAUTH_KEY),
        "preview leaked the tempauth key"
    );
    assert!(serialized.contains("<redacted>"));
}

#[test]
fn rust_stack_rejects_keystone_or_mariadb_roles() {
    let mut request = rust_request();
    request.nodes[0].roles.push("keystone".to_owned());

    let report = request.validate();

    assert!(!report.valid);
    assert!(report.errors.iter().any(|issue| {
        issue.field == "nodes[0].roles" && issue.message.contains("mariadb/keystone")
    }));

    let mut mariadb = rust_request();
    mariadb.nodes[1].roles.push("mariadb".to_owned());
    let report = mariadb.validate();
    assert!(report.errors.iter().any(|issue| {
        issue.field == "nodes[1].roles" && issue.message.contains("mariadb/keystone")
    }));
}

#[test]
fn rust_stack_rejects_keepalived_ingress_and_unknown_stacks() {
    let mut keepalived = rust_request();
    keepalived.ingress.mode = "keepalived".to_owned();
    let report = keepalived.validate();
    assert!(!report.valid);
    assert!(
        report
            .errors
            .iter()
            .any(|issue| { issue.field == "ingress.mode" && issue.message.contains("Keepalived") })
    );

    let mut unknown = rust_request();
    unknown.stack = "go".to_owned();
    let report = unknown.validate();
    assert!(
        report
            .errors
            .iter()
            .any(|issue| issue.field == "stack" && issue.message.contains("python-v3"))
    );
}

#[test]
fn rust_stack_requires_a_valid_tempauth_account() {
    let mut request = rust_request();
    request.tempauth_accounts.clear();
    let report = request.validate();
    assert!(!report.valid);
    assert!(
        report
            .errors
            .iter()
            .any(|issue| issue.field == "tempauth_accounts")
    );

    let mut weak = rust_request();
    weak.tempauth_accounts[0].key = "short".to_owned();
    let report = weak.validate();
    assert!(report.errors.iter().any(|issue| {
        issue.field == "tempauth_accounts[0].key" && issue.message.contains("12")
    }));
}

#[test]
fn rust_stack_erasure_coding_requires_enough_object_devices() {
    // devices: 2 + 1 + 1 (diskless node counts as one directory device) = 4 < 4 + 2
    let mut request = rust_request();
    request.ring.object_policy_type = "erasure_coding".to_owned();
    request.ring.ec_data_fragments = Some(4);
    request.ring.ec_parity_fragments = Some(2);

    let report = request.validate();

    assert!(!report.valid);
    assert!(report.errors.iter().any(|issue| {
        issue.field == "ring.ec_data_fragments" && issue.message.contains("object")
    }));

    // rust v1 is directory-device-only (one device per node), so EC must fit
    // the node count: 2+1 across three nodes satisfies data + parity = 3.
    let mut satisfied = request.clone();
    satisfied.ring.ec_data_fragments = Some(2);
    satisfied.ring.ec_parity_fragments = Some(1);
    let report = satisfied.validate();
    assert!(report.valid, "{:#?}", report.errors);

    let root = tempdir().expect("workspace root");
    let bundle = rust_fixture_bundle(root.path());
    let generated = satisfied
        .generate(&bundle, root.path().join("projects"))
        .expect("generate rust EC workspace");
    let all = fs::read_to_string(generated.project_root.join("group_vars/all"))
        .expect("read rust EC group_vars/all");
    let compiled: serde_json::Value =
        serde_yaml_ng::from_str(&all).expect("parse rust EC group_vars/all");
    assert_eq!(compiled["swift_policies"][1]["name"], "EC-2-1");
    assert_eq!(compiled["swift_policies"][1]["type"], "erasure_coding");
    assert_eq!(
        compiled["swift_policies"][1]["ec_type"],
        "liberasurecode_rs_vand"
    );
    assert_eq!(compiled["swift_policies"][1]["ec_data"], 2);
    assert_eq!(compiled["swift_policies"][1]["ec_parity"], 1);
    assert_eq!(compiled["swift_policies"][1]["ec_segment_size"], 1_048_576);
    assert_eq!(compiled["swift_policies"][1]["replicas"], 3);
    assert_eq!(compiled["swift_policies"][0]["default"], true);
}

#[test]
fn rust_stack_rejects_custom_disks() {
    // rust v1 deploys directory devices only; a data-disk list must fail
    // closed so no rust plan ever carries the disk_wipe capability.
    let mut request = rust_request();
    request.nodes[0].disks = vec!["/dev/sdb".to_owned()];
    request.nodes[0].system_disk = "/dev/sda".to_owned();
    let report = request.validate();
    assert!(!report.valid);
    assert!(
        report
            .errors
            .iter()
            .any(|issue| issue.field == "nodes[0].disks" && issue.message.contains("目录设备"))
    );
}

#[test]
fn stack_defaults_to_python_v3_and_python_rules_still_apply() {
    let value = serde_json::json!({
        "project_name": "default-stack",
        "deployment_mode": "development",
        "saio": false,
        "use_wwid": false,
        "hostname_modifiable": false,
        "hostname_prefix": "swift",
        "timezone": "UTC",
        "ntp_internet_server": "time.cloudflare.com",
        "local_repo_address": "10.88.0.9",
        "admin_ips": ["10.88.0.9"],
        "ssh_bind_port": 22,
        "nodes": [],
        "ring": {
            "partition_power": 10,
            "replicas": 1,
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
            "account_name": "testing",
            "admin_user": "cluster_admin",
            "admin_password": "Admin-Valid-9sQ4",
            "mariadb_root_password": "Maria-Root-8cK2",
            "mariadb_keystone_password": "Maria-Keystone-7mP3",
            "mariadb_clustercheck_password": "Maria-Check-4dL8",
            "keystone_admin_password": "Keystone-Admin-6hR5",
            "keystone_swift_password": "Keystone-Swift-5vN7",
            "keystone_controller_hostname": "controller",
            "haproxy_stats_user": "haproxy_observer",
            "haproxy_stats_password": "HAProxy-Stats-3qT9"
        },
        "ingress": {
            "mode": "haproxy",
            "http_mode": "http",
            "auth_url_ip": "10.88.20.11",
            "swift_port": 5050,
            "vip_prefix": 24,
            "virtual_router_id": 51,
            "vrrp_auth_pass": "Vr9Pass"
        }
    });
    let request: WorkspaceRequest =
        serde_json::from_value(value).expect("deserialize request without a stack field");
    assert_eq!(request.stack, "python-v3");
    assert!(request.tempauth_accounts.is_empty());
    assert!(!request.is_rust());
}

fn rust_fixture_bundle(root: &Path) -> PathBuf {
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
    bundle
}

fn rust_request() -> WorkspaceRequest {
    WorkspaceRequest {
        project_name: "rocky9-rust-tempauth".to_owned(),
        stack: "rust".to_owned(),
        deployment_mode: "production".to_owned(),
        saio: false,
        use_wwid: false,
        hostname_modifiable: false,
        hostname_prefix: "swift".to_owned(),
        timezone: "Asia/Shanghai".to_owned(),
        ntp_internet_server: "time.cloudflare.com".to_owned(),
        local_repo_address: String::new(),
        admin_ips: vec!["10.88.0.10".to_owned()],
        ssh_bind_port: 2222,
        nodes: vec![
            rust_node("rust-a", "10.88.0.11", 1, Vec::new(), true),
            rust_node("rust-b", "10.88.0.12", 2, Vec::new(), false),
            rust_node("rust-c", "10.88.0.13", 3, Vec::new(), false),
        ],
        ring: Ring {
            partition_power: 10,
            replicas: 3,
            minimum_time: 1,
            object_policy_name: "Policy-0".to_owned(),
            object_policy_type: "replication".to_owned(),
            ec_data_fragments: None,
            ec_parity_fragments: None,
            ec_segment_size: 1_048_576,
            device_weight: 100,
        },
        auth: Auth {
            method: "tempauth".to_owned(),
            interface: "swift".to_owned(),
            account_name: String::new(),
            admin_user: String::new(),
            admin_password: String::new(),
            mariadb_root_password: String::new(),
            mariadb_keystone_password: String::new(),
            mariadb_clustercheck_password: String::new(),
            keystone_admin_password: String::new(),
            keystone_swift_password: String::new(),
            keystone_controller_hostname: String::new(),
            haproxy_stats_user: String::new(),
            haproxy_stats_password: String::new(),
        },
        tempauth_accounts: vec![TempauthAccount {
            account: "test".to_owned(),
            user: "tester".to_owned(),
            key: TEMPAUTH_KEY.to_owned(),
        }],
        ingress: Ingress {
            mode: "direct".to_owned(),
            http_mode: "http".to_owned(),
            auth_url_ip: "10.88.20.11".to_owned(),
            swift_port: 8080,
            vip_prefix: 24,
            virtual_router_id: 51,
            vrrp_auth_pass: String::new(),
        },
    }
}

fn rust_node(
    name: &str,
    management_ip: &str,
    zone: u16,
    disks: Vec<&str>,
    ntp_server: bool,
) -> Node {
    let storage_ip = management_ip.replacen("10.88.0.", "10.88.10.", 1);
    let business_ip = management_ip.replacen("10.88.0.", "10.88.20.", 1);
    let system_disk = if disks.is_empty() {
        String::new()
    } else {
        "sda".to_owned()
    };
    Node {
        name: name.to_owned(),
        address: management_ip.to_owned(),
        ssh_user: "root".to_owned(),
        ssh_port: 22,
        ssh_key_file: "/root/.ssh/id_ed25519".to_owned(),
        management_ip: management_ip.to_owned(),
        storage_ip: storage_ip.clone(),
        replication_ip: storage_ip,
        business_ip,
        region: 1,
        zone,
        roles: vec![
            "proxy".to_owned(),
            "storage".to_owned(),
            if ntp_server {
                "ntp_server".to_owned()
            } else {
                "ntp_client".to_owned()
            },
        ],
        disk_type: "hdd".to_owned(),
        system_disk,
        disks: disks.into_iter().map(str::to_owned).collect(),
        keepalived_interface: String::new(),
        keepalived_priority: None,
    }
}
