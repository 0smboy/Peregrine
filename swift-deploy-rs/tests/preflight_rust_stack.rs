use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use swift_deploy_rs::{
    CommandOutput, Inventory, RecordingTransport, TransportAction, run_preflight,
    run_preflight_with_bundle,
};
use tempfile::{TempDir, tempdir};

#[test]
fn rust_stack_preflight_skips_repo_checks_and_allows_a_diskless_host() {
    let (directory, inventory_path) = rust_fixture();
    let inventory = Inventory::load(&inventory_path).expect("load rust preflight inventory");
    let mut transport = RecordingTransport::default();
    transport.outputs.push_back(CommandOutput {
        status: 0,
        stdout: rust_discovery("rocky|9.4").into_bytes(),
        stderr: Vec::new(),
    });

    let report = run_preflight(&inventory, None, &mut transport).expect("run rust preflight");

    assert!(report.ok, "{:#?}", report.hosts);
    assert!(
        report.hosts[0].repository_paths.is_empty(),
        "rust preflight must not report repository paths"
    );
    let command = transport
        .actions
        .iter()
        .find_map(|action| match action {
            TransportAction::Run { command, .. } => Some(command.clone()),
            _ => None,
        })
        .expect("rust preflight contacted the host");
    assert!(
        !command.contains("__REPO_") && !command.contains("http://"),
        "rust preflight must not probe the local repository: {command}"
    );
    assert!(
        command.contains("os-release") && command.contains("lsblk"),
        "rust preflight keeps OS and disk discovery: {command}"
    );
    drop(directory);
}

#[test]
fn rust_stack_preflight_accepts_el9_and_debian_12_13_only() {
    let (_directory, inventory_path) = rust_fixture();
    let inventory = Inventory::load(&inventory_path).expect("load rust preflight inventory");
    for (os, accepted) in [
        ("rocky|9.4", true),
        ("almalinux|9.7", true),
        ("rhel|9.8", true),
        ("debian|13", true),
        ("debian|12", true),
        ("debian|11", false),
        ("rocky|8.9", false),
        ("ubuntu|22.04", false),
    ] {
        let mut transport = RecordingTransport::default();
        transport.outputs.push_back(CommandOutput {
            status: 0,
            stdout: rust_discovery(os).into_bytes(),
            stderr: Vec::new(),
        });
        let report = run_preflight(&inventory, None, &mut transport).expect("run rust preflight");
        assert_eq!(report.ok, accepted, "{os}: {:#?}", report.hosts);
        if !accepted {
            assert!(
                report.hosts[0]
                    .errors
                    .iter()
                    .any(|error| error.contains("Rocky/AlmaLinux/RHEL 9 or Debian 12/13")),
                "{os}: {:#?}",
                report.hosts
            );
        }
    }
}

#[test]
fn python_stack_keeps_the_strict_rocky_pin() {
    let (directory, inventory_path) = rust_fixture();
    switch_fixture_to_python(&directory, &inventory_path);
    let inventory = Inventory::load(&inventory_path).expect("load python preflight inventory");
    let mut transport = RecordingTransport::default();
    transport.outputs.push_back(CommandOutput {
        status: 0,
        stdout: python_discovery()
            .replace("__OS__=rocky|9.4", "__OS__=almalinux|9.7")
            .into_bytes(),
        stderr: Vec::new(),
    });

    let report = run_preflight(&inventory, None, &mut transport).expect("run python preflight");

    assert!(!report.ok);
    assert!(
        report.hosts[0]
            .errors
            .iter()
            .any(|error| error.contains("Rocky Linux 9"))
    );
}

#[test]
fn rust_stack_preflight_verifies_a_dedicated_replication_address_is_assigned() {
    let (directory, inventory_path) = rust_fixture();
    fs::write(
        directory.path().join("host_vars/10.0.0.11.yml"),
        "management_network_address: 10.0.0.11\nstorage_network_address: 172.18.1.11\nreplication_network_address: 172.19.1.11\nbusiness_network_address: 10.0.20.11\ncustom_disks: []\n",
    )
    .expect("write split-replication host vars");
    let inventory = Inventory::load(&inventory_path).expect("load rust preflight inventory");

    // Replication address assigned on the host: accepted.
    let assigned = rust_discovery("rocky|9.4").replace(
        "__ADDR__=10.0.0.11,10.0.10.11,10.0.20.11",
        "__ADDR__=10.0.0.11,172.18.1.11,172.19.1.11,10.0.20.11",
    );
    let mut transport = RecordingTransport::default();
    transport.outputs.push_back(CommandOutput {
        status: 0,
        stdout: assigned.into_bytes(),
        stderr: Vec::new(),
    });
    let report = run_preflight(&inventory, None, &mut transport).expect("run rust preflight");
    assert!(report.ok, "{:#?}", report.hosts);

    // Replication address missing from the host: blocked.
    let missing = rust_discovery("rocky|9.4").replace(
        "__ADDR__=10.0.0.11,10.0.10.11,10.0.20.11",
        "__ADDR__=10.0.0.11,172.18.1.11,10.0.20.11",
    );
    let mut transport = RecordingTransport::default();
    transport.outputs.push_back(CommandOutput {
        status: 0,
        stdout: missing.into_bytes(),
        stderr: Vec::new(),
    });
    let report = run_preflight(&inventory, None, &mut transport).expect("run rust preflight");
    assert!(!report.ok);
    assert!(
        report.hosts[0].errors.iter().any(|error| {
            error.contains("replication_network_address") && error.contains("not assigned")
        }),
        "{:#?}",
        report.hosts
    );
}

#[test]
fn rust_stack_preflight_requires_the_controller_side_payload() {
    let (directory, inventory_path) = rust_fixture();
    let inventory = Inventory::load(&inventory_path).expect("load rust preflight inventory");
    let bundle = directory.path().join("bundle-rust");
    // a declared payload dir holding only a placeholder is unpopulated
    let payload_dir = bundle.join("roles/rust_payload/files/bin");
    fs::create_dir_all(&payload_dir).expect("payload directory");
    fs::write(payload_dir.join(".keep"), b"").expect("placeholder");

    let mut transport = RecordingTransport::default();
    transport.outputs.push_back(CommandOutput {
        status: 0,
        stdout: rust_discovery("rocky|9.4").into_bytes(),
        stderr: Vec::new(),
    });
    let report = run_preflight_with_bundle(&inventory, None, &mut transport, Some(&bundle))
        .expect("run rust preflight without payload");
    assert!(!report.ok);
    assert!(
        report.hosts[0]
            .errors
            .iter()
            .any(|error| error.contains("payload") && error.contains("unpopulated"))
    );

    fs::write(payload_dir.join("swift-proxy-server"), b"payload").expect("payload binary");
    let mut transport = RecordingTransport::default();
    transport.outputs.push_back(CommandOutput {
        status: 0,
        stdout: rust_discovery("rocky|9.4").into_bytes(),
        stderr: Vec::new(),
    });
    let report = run_preflight_with_bundle(&inventory, None, &mut transport, Some(&bundle))
        .expect("run rust preflight with payload");
    assert!(report.ok, "{:#?}", report.hosts);
}

#[test]
fn python_stack_preflight_ignores_the_rust_payload_gate() {
    // A python-v3 host (no deploy_stack marker) must not be blocked by a
    // bundle that lacks the rust payload.
    let (directory, inventory_path) = rust_fixture();
    switch_fixture_to_python(&directory, &inventory_path);
    let inventory = Inventory::load(&inventory_path).expect("load python preflight inventory");
    let bundle = directory.path().join("bundle");
    fs::create_dir_all(&bundle).expect("fixture bundle directory");
    let mut transport = RecordingTransport::default();
    transport.outputs.push_back(CommandOutput {
        status: 0,
        stdout: python_discovery().into_bytes(),
        stderr: Vec::new(),
    });

    let report = run_preflight_with_bundle(&inventory, None, &mut transport, Some(&bundle))
        .expect("run python preflight");

    assert!(report.ok, "{:#?}", report.hosts);
}

fn switch_fixture_to_python(directory: &TempDir, inventory_path: &Path) {
    let inventory_text = fs::read_to_string(inventory_path).expect("read inventory");
    fs::write(
        inventory_path,
        inventory_text.replace(
            "deploy_stack=rust\n",
            "use_custom_disks=true\nlocal_repo_address=10.0.0.9\n",
        ),
    )
    .expect("switch fixture to python-v3");
    fs::write(
        directory.path().join("host_vars/10.0.0.11.yml"),
        "management_network_address: 10.0.0.11\nstorage_network_address: 10.0.10.11\nreplication_network_address: 10.0.10.11\nbusiness_network_address: 10.0.20.11\ncustom_disks:\n  - /dev/nvme1n1\nexclude_disks:\n  - /dev/nvme0n1\n",
    )
    .expect("write python host vars");
}

fn rust_fixture() -> (TempDir, PathBuf) {
    let directory = tempdir().expect("fixture directory");
    let key = directory.path().join("id_ed25519");
    fs::write(&key, "test key").expect("write test key");
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).expect("secure test key");
    let inventory = directory.path().join("swift_hosts");
    fs::write(
        &inventory,
        format!(
            "[all]\n10.0.0.11 ansible_host=10.0.0.11 ansible_user=root ansible_port=22 ansible_ssh_private_key_file={}\n\n[proxy_servers]\n10.0.0.11\n\n[account_servers]\n10.0.0.11\n\n[container_servers]\n10.0.0.11\n\n[object_servers]\n10.0.0.11\n\n[format_disk_servers]\n\n[all:vars]\ndeploy_stack=rust\n",
            key.display()
        ),
    )
    .expect("write inventory");
    let host_vars = directory.path().join("host_vars");
    fs::create_dir_all(&host_vars).expect("host vars directory");
    fs::write(
        host_vars.join("10.0.0.11.yml"),
        "management_network_address: 10.0.0.11\nstorage_network_address: 10.0.10.11\nreplication_network_address: 10.0.10.11\nbusiness_network_address: 10.0.20.11\ncustom_disks: []\n",
    )
    .expect("write host vars");
    (directory, inventory)
}

fn rust_discovery(os: &str) -> String {
    format!(
        "__UID__=0\n__OS__={os}\n__ADDR__=10.0.0.11,10.0.10.11,10.0.20.11\n__ROOT__=/dev/nvme0n1p3\n__CANON_SYSTEM__=\n__LSBLK__\n{{\"blockdevices\":[{{\"path\":\"/dev/nvme0n1\",\"type\":\"disk\",\"fstype\":null,\"mountpoints\":[null],\"children\":[{{\"path\":\"/dev/nvme0n1p3\",\"type\":\"part\",\"fstype\":\"xfs\",\"mountpoints\":[\"/\"]}}]}}]}}\n"
    )
}

fn python_discovery() -> String {
    "__UID__=0\n__OS__=rocky|9.4\n__ADDR__=10.0.0.11,10.0.10.11,10.0.20.11\n__ROOT__=/dev/nvme0n1p3\n__CANON_SYSTEM__=/dev/nvme0n1\n__CANON_DATA_0__=/dev/nvme1n1\n__REPO_yum__=ok\n__REPO_pip__=ok\n__REPO_component__=ok\n__REPO_YUM_METADATA__=ok\n__REPO_COMPONENT_SWIFT__=ok\n__REPO_COMPONENT_SWIFTCLIENT__=ok\n__LSBLK__\n{\"blockdevices\":[{\"path\":\"/dev/nvme0n1\",\"type\":\"disk\",\"fstype\":null,\"mountpoints\":[null],\"children\":[{\"path\":\"/dev/nvme0n1p3\",\"type\":\"part\",\"fstype\":\"xfs\",\"mountpoints\":[\"/\"]}]},{\"path\":\"/dev/nvme1n1\",\"type\":\"disk\",\"fstype\":null,\"mountpoints\":[null]}]}\n".to_owned()
}
