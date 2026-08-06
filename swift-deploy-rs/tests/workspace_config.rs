use std::fs;
use std::path::PathBuf;

use swift_deploy_rs::Inventory;
use swift_deploy_rs::workspace::{Auth, Ingress, Node, Ring, WorkspaceRequest};
use tempfile::tempdir;

const ADMIN_PASSWORD: &str = "Admin-Prod-9sQ4";
const MARIADB_ROOT_PASSWORD: &str = "Maria-Root-8cK2";
const MARIADB_KEYSTONE_PASSWORD: &str = "Maria-Keystone-7mP3";
const MARIADB_CLUSTERCHECK_PASSWORD: &str = "Maria-Check-4dL8";
const KEYSTONE_ADMIN_PASSWORD: &str = "Keystone-Admin-6hR5";
const KEYSTONE_SWIFT_PASSWORD: &str = "Keystone-Swift-5vN7";
const HAPROXY_STATS_PASSWORD: &str = "HAProxy-Stats-3qT9";
const VRRP_AUTH_PASS: &str = "Vr9Pass";

#[test]
fn valid_three_node_workspace_generates_inventory_and_compatible_variables() {
    let root = tempdir().expect("workspace root");
    let request = production_request();

    let generated = request
        .generate(bundle(), root.path())
        .expect("generate valid workspace");

    assert_eq!(generated.summary.node_count, 3);
    assert_eq!(generated.summary.storage_node_count, 3);
    assert_eq!(generated.summary.disk_count, 6);
    assert!(generated.inventory.is_file());
    assert!(generated.playbook.is_file());
    assert!(generated.plan.starts_with(&generated.project_root));

    let inventory = Inventory::load(&generated.inventory).expect("load generated inventory");
    assert_eq!(
        inventory.host_names(),
        ["10.77.0.11", "10.77.0.12", "10.77.0.13"]
    );
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
            "missing group {group}"
        );
    }

    let first = inventory
        .host_context("10.77.0.11")
        .expect("render first host context");
    assert_eq!(first["management_network_address"], "10.77.0.11");
    assert_eq!(first["storage_network_address"], "10.77.10.11");
    assert_eq!(first["business_network_address"], "10.77.20.11");
    assert_eq!(first["mariadb_node"], true);
    assert_eq!(first["keystone_node"], true);
    assert_eq!(first["INSTALL_MODE"], "production");
    assert_eq!(first["firewall_type"], "iptables");
    assert_eq!(first["data_encryption"], false);
    assert_eq!(
        first["mariadb_clustercheck_password"],
        MARIADB_CLUSTERCHECK_PASSWORD
    );
    assert_eq!(first["haproxy_stats_user"], "haproxy_observer");
    assert_eq!(first["haproxy_stats_password"], HAPROXY_STATS_PASSWORD);
    assert_eq!(first["object_rings"][0]["object_swift_replicas"], 3);
    assert_eq!(
        first["object_rings"][0]["nodes"].as_array().map(Vec::len),
        Some(6)
    );

    let all_raw = fs::read_to_string(generated.project_root.join("group_vars/all.raw"))
        .expect("read generated all.raw");
    assert!(!all_raw.contains("45.30.16.x"));
    assert!(!all_raw.contains("192.168.101.x"));
    assert!(!all_raw.contains("xxxxx"));
    assert!(all_raw.contains(ADMIN_PASSWORD));

    let compiled_all = fs::read_to_string(generated.project_root.join("group_vars/all"))
        .expect("read Ansible-loadable compiled group_vars/all");
    let compiled: serde_json::Value =
        serde_yaml_ng::from_str(&compiled_all).expect("parse compiled group_vars/all");
    assert_eq!(compiled["account_ring"].as_array().map(Vec::len), Some(6));
    assert_eq!(compiled["container_ring"].as_array().map(Vec::len), Some(6));
    assert_eq!(
        compiled["object_rings"][0]["nodes"]
            .as_array()
            .map(Vec::len),
        Some(6)
    );
    assert_eq!(
        compiled["storage_network_addresses"]
            .as_array()
            .map(Vec::len),
        Some(3)
    );
    assert_eq!(
        compiled["proxy_storage_network_addresses"]
            .as_array()
            .map(Vec::len),
        Some(3)
    );
    assert_eq!(
        compiled["keystone_storage_network_addresses"]
            .as_array()
            .map(Vec::len),
        Some(3)
    );
}

#[test]
fn topology_without_roles_is_rejected() {
    let mut request = production_request();
    for node in &mut request.nodes {
        node.roles.clear();
    }

    let report = request.validate();

    assert!(!report.valid);
    assert!(
        report
            .errors
            .iter()
            .any(|issue| issue.field == "nodes[0].roles")
    );
    assert!(
        report
            .errors
            .iter()
            .any(|issue| issue.message.contains("proxy"))
    );
}

#[test]
fn system_disk_may_never_appear_in_data_disks() {
    let mut request = production_request();
    request.nodes[0].system_disk = "sda".to_owned();
    request.nodes[0].disks = vec!["/dev/sda".to_owned(), "/dev/sdb".to_owned()];

    let report = request.validate();

    assert!(!report.valid);
    assert!(report.errors.iter().any(|issue| {
        issue.field == "nodes[0].disks[0]" && issue.message.contains("系统盘冲突")
    }));
}

#[test]
fn erasure_coding_is_disabled_until_ring_replica_semantics_are_split() {
    let mut request = production_request();
    request.ring.object_policy_type = "erasure_coding".to_owned();
    request.ring.replicas = 5;
    request.ring.ec_data_fragments = Some(3);
    request.ring.ec_parity_fragments = Some(1);

    let report = request.validate();

    assert!(!report.valid);
    assert!(report.errors.iter().any(|issue| {
        issue.field == "ring.object_policy_type" && issue.message.contains("暂不允许 EC")
    }));
}

#[test]
fn upstream_v3_rejects_a_split_replication_address() {
    let mut request = production_request();
    request.nodes[0].replication_ip = "10.77.11.11".to_owned();

    let report = request.validate();

    assert!(!report.valid);
    assert!(report.errors.iter().any(|issue| {
        issue.field == "nodes[0].replication_ip"
            && issue.message.contains("只监听 storage_network_address")
    }));
}

#[test]
fn unsupported_auth_ingress_storage_and_secret_choices_fail_closed() {
    let mut repository_url = production_request();
    repository_url.local_repo_address = "http://10.77.0.10:8080/repo".to_owned();
    let report = repository_url.validate();
    assert!(report.errors.iter().any(|issue| {
        issue.field == "local_repo_address" && issue.message.contains("单个 IPv4")
    }));

    let mut direct = production_request();
    direct.ingress.mode = "direct".to_owned();
    direct.ingress.auth_url_ip = direct.nodes[0].business_ip.clone();
    let report = direct.validate();
    assert!(
        report
            .errors
            .iter()
            .any(|issue| { issue.field == "ingress.mode" && issue.message.contains("Keystone") })
    );

    let mut tempauth = production_request();
    tempauth.auth.method = "tempauth".to_owned();
    let report = tempauth.validate();
    assert!(
        report
            .errors
            .iter()
            .any(|issue| issue.field == "auth.method" && issue.message.contains("TempAuth"))
    );

    let mut non_storage_disk = production_request();
    non_storage_disk.nodes[0].roles = vec!["proxy".to_owned(), "ntp_server".to_owned()];
    let report = non_storage_disk.validate();
    assert!(report.errors.iter().any(|issue| {
        issue.field == "nodes[0].disks" && issue.message.contains("非存储节点")
    }));

    let mut mismatched_ha = production_request();
    mismatched_ha.ingress.mode = "haproxy".to_owned();
    mismatched_ha.ingress.auth_url_ip = mismatched_ha.nodes[0].business_ip.clone();
    let report = mismatched_ha.validate();
    assert!(report.errors.iter().any(|issue| {
        issue.field == "nodes.roles" && issue.message.contains("不能包含 Keepalived")
    }));

    let mut unsafe_secret = production_request();
    unsafe_secret.auth.admin_password = "Unsafe!Password".to_owned();
    let report = unsafe_secret.validate();
    assert!(report.errors.iter().any(|issue| {
        issue.field == "auth.admin_password" && issue.message.contains("只允许 ASCII")
    }));
}

#[test]
fn preview_redacts_all_credentials_and_writes_nothing() {
    let request = production_request();
    let preview = request.preview(bundle()).expect("render preview");

    assert!(preview.valid, "{:#?}", preview.errors);
    assert!(!preview.files.is_empty());
    let serialized = serde_json::to_string(&preview).expect("serialize preview");
    for secret in [
        ADMIN_PASSWORD,
        MARIADB_ROOT_PASSWORD,
        MARIADB_KEYSTONE_PASSWORD,
        MARIADB_CLUSTERCHECK_PASSWORD,
        KEYSTONE_ADMIN_PASSWORD,
        KEYSTONE_SWIFT_PASSWORD,
        HAPROXY_STATS_PASSWORD,
        VRRP_AUTH_PASS,
    ] {
        assert!(!serialized.contains(secret), "preview leaked {secret}");
    }
    assert!(serialized.contains("<redacted>"));
}

#[test]
fn explicit_disks_and_wwid_are_blocked_as_an_upstream_v3_conflict() {
    let mut request = production_request();
    request.use_wwid = true;

    let report = request.validate();

    assert!(!report.valid);
    assert!(
        report
            .errors
            .iter()
            .any(|issue| { issue.field == "use_wwid" && issue.message.contains("custom_disks") })
    );
}

fn bundle() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("bundle")
}

fn production_request() -> WorkspaceRequest {
    WorkspaceRequest {
        project_name: "rocky9-keystone-http".to_owned(),
        stack: "python-v3".to_owned(),
        deployment_mode: "production".to_owned(),
        saio: false,
        use_wwid: false,
        hostname_modifiable: true,
        hostname_prefix: "swift".to_owned(),
        timezone: "Asia/Shanghai".to_owned(),
        ntp_internet_server: "time.cloudflare.com".to_owned(),
        local_repo_address: "10.77.0.10".to_owned(),
        admin_ips: vec!["10.77.0.10".to_owned()],
        ssh_bind_port: 2222,
        nodes: vec![
            production_node(
                "swift-a",
                "10.77.0.11",
                "10.77.10.11",
                "10.77.10.11",
                "10.77.20.11",
                1,
                160,
            ),
            production_node(
                "swift-b",
                "10.77.0.12",
                "10.77.10.12",
                "10.77.10.12",
                "10.77.20.12",
                2,
                150,
            ),
            production_node(
                "swift-c",
                "10.77.0.13",
                "10.77.10.13",
                "10.77.10.13",
                "10.77.20.13",
                3,
                140,
            ),
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
            method: "keystone".to_owned(),
            interface: "swift".to_owned(),
            account_name: "production".to_owned(),
            admin_user: "cluster_admin".to_owned(),
            admin_password: ADMIN_PASSWORD.to_owned(),
            mariadb_root_password: MARIADB_ROOT_PASSWORD.to_owned(),
            mariadb_keystone_password: MARIADB_KEYSTONE_PASSWORD.to_owned(),
            mariadb_clustercheck_password: MARIADB_CLUSTERCHECK_PASSWORD.to_owned(),
            keystone_admin_password: KEYSTONE_ADMIN_PASSWORD.to_owned(),
            keystone_swift_password: KEYSTONE_SWIFT_PASSWORD.to_owned(),
            keystone_controller_hostname: "swift-vip".to_owned(),
            haproxy_stats_user: "haproxy_observer".to_owned(),
            haproxy_stats_password: HAPROXY_STATS_PASSWORD.to_owned(),
        },
        tempauth_accounts: Vec::new(),
        ingress: Ingress {
            mode: "keepalived".to_owned(),
            http_mode: "http".to_owned(),
            auth_url_ip: "10.77.20.100".to_owned(),
            swift_port: 5050,
            vip_prefix: 24,
            virtual_router_id: 51,
            vrrp_auth_pass: VRRP_AUTH_PASS.to_owned(),
        },
    }
}

fn production_node(
    name: &str,
    management_ip: &str,
    storage_ip: &str,
    replication_ip: &str,
    business_ip: &str,
    zone: u16,
    keepalived_priority: u16,
) -> Node {
    Node {
        name: name.to_owned(),
        address: management_ip.to_owned(),
        ssh_user: "root".to_owned(),
        ssh_port: 22,
        ssh_key_file: "/root/.ssh/id_ed25519".to_owned(),
        management_ip: management_ip.to_owned(),
        storage_ip: storage_ip.to_owned(),
        replication_ip: replication_ip.to_owned(),
        business_ip: business_ip.to_owned(),
        region: 1,
        zone,
        roles: vec![
            "proxy".to_owned(),
            "storage".to_owned(),
            "keystone".to_owned(),
            "mariadb".to_owned(),
            "haproxy".to_owned(),
            "keepalived".to_owned(),
            if zone == 1 {
                "ntp_server".to_owned()
            } else {
                "ntp_client".to_owned()
            },
        ],
        disk_type: "hdd".to_owned(),
        system_disk: "sda".to_owned(),
        disks: vec!["/dev/sdb".to_owned(), "/dev/sdc".to_owned()],
        swift_devices: Vec::new(),
        keepalived_interface: "eth2".to_owned(),
        keepalived_priority: Some(keepalived_priority),
    }
}
