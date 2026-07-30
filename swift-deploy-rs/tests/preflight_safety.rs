use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use swift_deploy_rs::{
    Auth, CommandOutput, Ingress, Inventory, Node, RecordingTransport, Ring, TransportAction,
    WorkspaceRequest, run_preflight,
};
use tempfile::{TempDir, tempdir};

#[test]
fn rocky9_preflight_accepts_only_an_unpartitioned_unused_data_disk() {
    let (directory, inventory_path) = fixture();
    let inventory = Inventory::load(&inventory_path).expect("load preflight inventory");
    let mut transport = RecordingTransport::default();
    transport.outputs.push_back(CommandOutput {
        status: 0,
        stdout: safe_discovery("/dev/nvme1n1").into_bytes(),
        stderr: Vec::new(),
    });

    let report = run_preflight(&inventory, None, &mut transport).expect("run preflight");

    assert!(report.ok, "{:#?}", report.hosts);
    assert_eq!(report.hosts[0].system_disk, "/dev/nvme0n1");
    assert_eq!(report.hosts[0].data_disks, ["/dev/nvme1n1"]);
    drop(directory);
}

#[test]
fn preflight_blocks_a_data_disk_with_existing_content() {
    let (_directory, inventory_path) = fixture();
    let inventory = Inventory::load(&inventory_path).expect("load preflight inventory");
    let mut transport = RecordingTransport::default();
    transport.outputs.push_back(CommandOutput {
        status: 0,
        stdout: used_data_discovery().into_bytes(),
        stderr: Vec::new(),
    });

    let report = run_preflight(&inventory, None, &mut transport).expect("run preflight");

    assert!(!report.ok);
    assert!(
        report.hosts[0]
            .errors
            .iter()
            .any(|error| { error.contains("already has partitions, a filesystem, or a mount") })
    );
    assert!(report.ensure_safe().is_err());
}

#[test]
fn preflight_blocks_missing_keepalived_interface() {
    let (directory, inventory_path) = fixture();
    let host_vars = directory.path().join("host_vars/10.0.0.11.yml");
    let variables = fs::read_to_string(&host_vars).expect("read host vars");
    fs::write(
        &host_vars,
        format!("{variables}keepalived_interface: eth9\n"),
    )
    .expect("set keepalived interface");
    let inventory = Inventory::load(&inventory_path).expect("load preflight inventory");
    let mut transport = RecordingTransport::default();
    transport.outputs.push_back(CommandOutput {
        status: 0,
        stdout: safe_discovery("/dev/nvme1n1")
            .replace("__LSBLK__\n", "__KEEPALIVED_INTERFACE__=fail\n__LSBLK__\n")
            .into_bytes(),
        stderr: Vec::new(),
    });

    let report = run_preflight(&inventory, None, &mut transport).expect("run preflight");

    assert!(!report.ok);
    assert!(
        report.hosts[0]
            .errors
            .iter()
            .any(|error| { error.contains("keepalived_interface \"eth9\" does not exist") })
    );
    assert!(transport.actions.iter().any(|action| matches!(
        action,
        TransportAction::Run { command, .. }
            if command.contains("ip link show -- eth9")
    )));
}

#[test]
fn preflight_blocks_invalid_component_archives() {
    let (_directory, inventory_path) = fixture();
    let inventory = Inventory::load(&inventory_path).expect("load preflight inventory");
    let mut transport = RecordingTransport::default();
    transport.outputs.push_back(CommandOutput {
        status: 0,
        stdout: safe_discovery("/dev/nvme1n1")
            .replace(
                "__REPO_COMPONENT_SWIFT__=ok",
                "__REPO_COMPONENT_SWIFT__=fail",
            )
            .into_bytes(),
        stderr: Vec::new(),
    });

    let report = run_preflight(&inventory, None, &mut transport).expect("run preflight");

    assert!(!report.ok);
    assert!(
        report.hosts[0]
            .errors
            .iter()
            .any(|error| { error.contains("swift.tar.gz") && error.contains("swift-2.31.1/") })
    );
}

#[test]
fn preflight_rejects_standard_disk_discovery_before_contacting_hosts() {
    let (_directory, inventory_path) = fixture();
    let inventory_text = fs::read_to_string(&inventory_path).expect("read inventory");
    fs::write(
        &inventory_path,
        inventory_text.replace("use_custom_disks=true", "use_custom_disks=false"),
    )
    .expect("disable explicit disks");
    let inventory = Inventory::load(&inventory_path).expect("load preflight inventory");
    let mut transport = RecordingTransport::default();

    let report = run_preflight(&inventory, None, &mut transport).expect("run preflight");

    assert!(!report.ok);
    assert!(
        report.hosts[0]
            .errors
            .iter()
            .any(|error| { error.contains("use_custom_disks must be true") })
    );
    assert!(transport.actions.is_empty());
}

#[test]
fn preflight_requires_explicit_disks_for_format_disk_servers() {
    let (directory, inventory_path) = fixture();
    fs::write(
        directory.path().join("host_vars/10.0.0.11.yml"),
        "management_network_address: 10.0.0.11\nstorage_network_address: 10.0.10.11\nreplication_network_address: 10.0.10.11\nbusiness_network_address: 10.0.20.11\ncustom_disks: []\nexclude_disks:\n  - /dev/nvme0n1\n",
    )
    .expect("remove explicit disks");
    let inventory = Inventory::load(&inventory_path).expect("load preflight inventory");
    let mut transport = RecordingTransport::default();

    let report = run_preflight(&inventory, None, &mut transport).expect("run preflight");

    assert!(!report.ok);
    assert!(
        report.hosts[0]
            .errors
            .iter()
            .any(|error| { error.contains("format_disk_servers hosts must declare") })
    );
    assert!(transport.actions.is_empty());
}

#[test]
fn generated_workspace_normalizes_a_bare_system_disk_for_preflight() {
    let workspace_root = tempdir().expect("workspace root");
    let key = workspace_root.path().join("id_ed25519");
    fs::write(&key, "test key").expect("write test key");
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).expect("secure test key");
    let generated = generated_request(&key)
        .generate(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("bundle"),
            workspace_root.path(),
        )
        .expect("generate workspace");
    let inventory = Inventory::load(&generated.inventory).expect("load generated inventory");
    let context = inventory
        .host_context("10.0.0.11")
        .expect("generated host context");
    assert_eq!(context["exclude_disks"][0], "/dev/nvme0n1");
    assert_eq!(context["use_custom_disks"], true);

    let mut transport = RecordingTransport::default();
    transport.outputs.push_back(CommandOutput {
        status: 0,
        stdout: safe_discovery("/dev/nvme1n1").into_bytes(),
        stderr: Vec::new(),
    });
    let report = run_preflight(&inventory, None, &mut transport).expect("run preflight");

    assert!(report.ok, "{:#?}", report.hosts);
    assert_eq!(report.hosts[0].system_disk, "/dev/nvme0n1");
    assert!(transport.actions.iter().any(|action| matches!(
        action,
        TransportAction::Run { command, .. }
            if command.contains("readlink -f -- /dev/nvme0n1")
                && command.contains("/yum/repodata/repomd.xml")
                && command.contains("/component/swift.tar.gz")
                && command.contains("swift-2.31.1")
                && command.contains("/component/python-swiftclient.tar.gz")
                && command.contains("python-swiftclient-4.2.0")
    )));
}

fn fixture() -> (TempDir, PathBuf) {
    let directory = tempdir().expect("fixture directory");
    let key = directory.path().join("id_ed25519");
    fs::write(&key, "test key").expect("write test key");
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).expect("secure test key");
    let inventory = directory.path().join("swift_hosts");
    fs::write(
        &inventory,
        format!(
            "[all]\n10.0.0.11 ansible_host=10.0.0.11 ansible_user=root ansible_port=22 ansible_ssh_private_key_file={}\n\n[proxy_servers]\n10.0.0.11\n\n[account_servers]\n10.0.0.11\n\n[container_servers]\n10.0.0.11\n\n[object_servers]\n10.0.0.11\n\n[format_disk_servers]\n10.0.0.11\n\n[all:vars]\nlocal_repo_address=10.0.0.9\nuse_custom_disks=true\n",
            key.display()
        ),
    )
    .expect("write inventory");
    let host_vars = directory.path().join("host_vars");
    fs::create_dir_all(&host_vars).expect("host vars directory");
    fs::write(
        host_vars.join("10.0.0.11.yml"),
        "management_network_address: 10.0.0.11\nstorage_network_address: 10.0.10.11\nreplication_network_address: 10.0.10.11\nbusiness_network_address: 10.0.20.11\ncustom_disks:\n  - /dev/nvme1n1\nexclude_disks:\n  - /dev/nvme0n1\n",
    )
    .expect("write host vars");
    assert!(Path::new(&inventory).is_file());
    (directory, inventory)
}

fn generated_request(key: &Path) -> WorkspaceRequest {
    WorkspaceRequest {
        project_name: "generated-preflight".to_owned(),
        stack: "python-v3".to_owned(),
        deployment_mode: "development".to_owned(),
        saio: true,
        use_wwid: false,
        hostname_modifiable: true,
        hostname_prefix: "swift".to_owned(),
        timezone: "UTC".to_owned(),
        ntp_internet_server: "time.cloudflare.com".to_owned(),
        local_repo_address: "10.0.0.9".to_owned(),
        admin_ips: vec!["10.0.0.9".to_owned()],
        ssh_bind_port: 22,
        nodes: vec![Node {
            name: "swift-a".to_owned(),
            address: "10.0.0.11".to_owned(),
            ssh_user: "root".to_owned(),
            ssh_port: 22,
            ssh_key_file: key.to_string_lossy().into_owned(),
            management_ip: "10.0.0.11".to_owned(),
            storage_ip: "10.0.10.11".to_owned(),
            replication_ip: "10.0.10.11".to_owned(),
            business_ip: "10.0.20.11".to_owned(),
            region: 1,
            zone: 1,
            roles: vec![
                "proxy".to_owned(),
                "account".to_owned(),
                "container".to_owned(),
                "object".to_owned(),
                "mariadb".to_owned(),
                "keystone".to_owned(),
                "haproxy".to_owned(),
                "ntp_server".to_owned(),
            ],
            disk_type: "hdd".to_owned(),
            system_disk: "nvme0n1".to_owned(),
            disks: vec!["/dev/nvme1n1".to_owned()],
            keepalived_interface: String::new(),
            keepalived_priority: None,
        }],
        ring: Ring {
            partition_power: 10,
            replicas: 1,
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
            account_name: "testing".to_owned(),
            admin_user: "cluster_admin".to_owned(),
            admin_password: "Admin-Valid-9sQ4".to_owned(),
            mariadb_root_password: "Maria-Root-8cK2".to_owned(),
            mariadb_keystone_password: "Maria-Keystone-7mP3".to_owned(),
            mariadb_clustercheck_password: "Maria-Check-4dL8".to_owned(),
            keystone_admin_password: "Keystone-Admin-6hR5".to_owned(),
            keystone_swift_password: "Keystone-Swift-5vN7".to_owned(),
            keystone_controller_hostname: "swift-a".to_owned(),
            haproxy_stats_user: "haproxy_observer".to_owned(),
            haproxy_stats_password: "HAProxy-Stats-3qT9".to_owned(),
        },
        tempauth_accounts: Vec::new(),
        ingress: Ingress {
            mode: "haproxy".to_owned(),
            http_mode: "http".to_owned(),
            auth_url_ip: "10.0.20.11".to_owned(),
            swift_port: 5050,
            vip_prefix: 24,
            virtual_router_id: 51,
            vrrp_auth_pass: "Vr9Pass".to_owned(),
        },
    }
}

fn safe_discovery(data_disk: &str) -> String {
    format!(
        "__UID__=0\n__OS__=rocky|9.4\n__ADDR__=10.0.0.11,10.0.10.11,10.0.20.11\n__ROOT__=/dev/nvme0n1p3\n__CANON_SYSTEM__=/dev/nvme0n1\n__CANON_DATA_0__={data_disk}\n__REPO_yum__=ok\n__REPO_pip__=ok\n__REPO_component__=ok\n__REPO_YUM_METADATA__=ok\n__REPO_COMPONENT_SWIFT__=ok\n__REPO_COMPONENT_SWIFTCLIENT__=ok\n__LSBLK__\n{{\"blockdevices\":[{{\"path\":\"/dev/nvme0n1\",\"type\":\"disk\",\"fstype\":null,\"mountpoints\":[null],\"children\":[{{\"path\":\"/dev/nvme0n1p3\",\"type\":\"part\",\"fstype\":\"xfs\",\"mountpoints\":[\"/\"]}}]}},{{\"path\":\"{data_disk}\",\"type\":\"disk\",\"fstype\":null,\"mountpoints\":[null]}}]}}\n"
    )
}

fn used_data_discovery() -> String {
    safe_discovery("/dev/nvme1n1").replace(
        "{\"path\":\"/dev/nvme1n1\",\"type\":\"disk\",\"fstype\":null,\"mountpoints\":[null]}",
        "{\"path\":\"/dev/nvme1n1\",\"type\":\"disk\",\"fstype\":\"xfs\",\"mountpoints\":[\"/data\"]}",
    )
}
