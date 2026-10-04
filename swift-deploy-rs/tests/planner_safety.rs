use std::fs;
use std::path::PathBuf;

use pretty_assertions::assert_eq;
use serde_json::json;
use swift_deploy_rs::{Inventory, Planner, RiskClass, SafetyPolicy, fingerprint_path, redact};
use tempfile::tempdir;

#[test]
fn planner_flattens_includes_blocks_and_inherited_controls() {
    let directory = tempdir().expect("temporary project");
    let bundle = directory.path().join("bundle");
    fs::create_dir_all(bundle.join("roles/demo/tasks")).expect("task directory");
    fs::create_dir_all(bundle.join("roles/demo/handlers")).expect("handler directory");
    fs::create_dir_all(bundle.join("roles/demo/vars")).expect("role vars directory");
    fs::write(
        bundle.join("demo.yml"),
        r#"
- hosts: all
  roles:
    - role: demo
      when: role_enabled
"#,
    )
    .expect("playbook");
    fs::write(
        bundle.join("roles/demo/tasks/main.yml"),
        r#"
- name: include nested work
  include: child.yml inherited_value={{ parent_value }}
  when: include_enabled
  with_items: "{{ outer_items }}"
  run_once: true
"#,
    )
    .expect("main tasks");
    fs::write(
        bundle.join("roles/demo/tasks/child.yml"),
        r#"
- block:
    - name: nested command
      shell: "echo {{ inherited_value }} {{ item }} {{ db_password }}"
      when: child_enabled
      with_items: "{{ inner_items }}"
      notify: restart demo
  when: block_enabled
"#,
    )
    .expect("child tasks");
    fs::write(
        bundle.join("roles/demo/handlers/main.yml"),
        r#"
- name: restart demo
  service:
    name: demo
    state: restarted
"#,
    )
    .expect("handlers");
    fs::write(
        bundle.join("roles/demo/vars/main.yml"),
        "role_value: from-role-vars\n",
    )
    .expect("role vars");
    let inventory_path = directory.path().join("hosts");
    fs::write(&inventory_path, "127.0.0.1 ansible_user=root\n").expect("inventory");
    let inventory = Inventory::load(&inventory_path).expect("load inventory");

    let first = Planner::new(&bundle, &inventory)
        .build(
            bundle.join("demo.yml"),
            fingerprint_path(&inventory_path).expect("inventory hash"),
        )
        .expect("first plan");
    let second = Planner::new(&bundle, &inventory)
        .build(
            bundle.join("demo.yml"),
            fingerprint_path(&inventory_path).expect("inventory hash"),
        )
        .expect("second plan");

    assert_eq!(first.digest, second.digest);
    first.verify().expect("sealed plan verifies");
    assert_eq!(first.tasks.len(), 1);
    assert_eq!(first.handlers.len(), 1);
    let task = &first.tasks[0];
    assert_eq!(task.module, "shell");
    assert_eq!(
        task.when,
        vec![
            "role_enabled",
            "include_enabled",
            "block_enabled",
            "child_enabled"
        ]
    );
    assert_eq!(task.loops.len(), 2);
    assert!(task.run_once);
    assert!(!task.privilege_escalation);
    assert_eq!(task.vars["inherited_value"], "{{ parent_value }}");
    assert_eq!(task.vars["role_value"], "from-role-vars");
    assert_eq!(task.notify, vec!["restart demo"]);
    assert_eq!(
        task.args,
        json!("echo {{ inherited_value }} {{ item }} {{ db_password }}")
    );
}

#[test]
fn independent_capabilities_are_required_for_each_high_risk_class() {
    let directory = tempdir().expect("temporary project");
    let bundle = directory.path().join("bundle");
    fs::create_dir_all(bundle.join("roles/risky/tasks")).expect("task directory");
    fs::write(bundle.join("risky.yml"), "- hosts: all\n  roles: [risky]\n").expect("playbook");
    fs::write(
        bundle.join("roles/risky/tasks/main.yml"),
        r#"
- name: wipe disk header
  shell: dd if=/dev/zero of=/dev/sdb bs=512 count=4
- name: load firewall
  shell: iptables-restore < /opt/rules
- name: change ssh port
  lineinfile:
    dest: /etc/ssh/sshd_config
    line: Port 2222
- name: replace repositories and upgrade the host
  command: yum upgrade --best --allowerasing -y
- name: replace yum configuration
  ini_file:
    dest: /etc/yum.conf
    section: main
    option: keepcache
    value: 1
- name: change hostname
  command: hostnamectl set-hostname swift-01
- name: change locale profile
  lineinfile:
    dest: /etc/profile
    line: export LANG=en_US.UTF-8
- name: disable selinux
  lineinfile:
    dest: /etc/selinux/config
    line: SELINUX=disabled
- name: restart base service
  service:
    name: crond
    state: restarted
- name: install host cron
  cron:
    name: swift permission check
    minute: "*/5"
    job: /usr/local/bin/check-swift
"#,
    )
    .expect("tasks");
    let inventory_path = directory.path().join("hosts");
    fs::write(&inventory_path, "127.0.0.1\n").expect("inventory");
    let inventory = Inventory::load(&inventory_path).expect("load inventory");
    let plan = Planner::new(&bundle, &inventory)
        .build(bundle.join("risky.yml"), "inventory-fingerprint")
        .expect("plan");

    let mut stale_plan = plan.clone();
    stale_plan.schema_version = 1;
    let stale_plan = stale_plan.seal().expect("seal stale schema plan");
    assert!(
        stale_plan
            .verify()
            .expect_err("schema 1 must be rejected")
            .to_string()
            .contains("rebuild the plan")
    );

    assert_eq!(
        plan.required_capabilities(),
        vec![
            RiskClass::DiskWipe,
            RiskClass::Firewall,
            RiskClass::SshReconfigure,
            RiskClass::HostReconfigure
        ]
    );
    for task_name in [
        "replace repositories and upgrade the host",
        "replace yum configuration",
        "change hostname",
        "change locale profile",
        "disable selinux",
        "restart base service",
        "install host cron",
    ] {
        let task = plan
            .tasks
            .iter()
            .find(|task| task.name == task_name)
            .unwrap_or_else(|| panic!("missing planned task {task_name}"));
        assert!(
            task.risk.contains(&RiskClass::HostReconfigure),
            "{task_name} must require HostReconfigure: {:?}",
            task.risk
        );
    }
    assert!(SafetyPolicy::default().authorize(&plan).is_err());
    assert!(
        SafetyPolicy {
            allow_disk_wipe: true,
            ..SafetyPolicy::default()
        }
        .authorize(&plan)
        .is_err()
    );
    assert!(
        SafetyPolicy {
            allow_disk_wipe: true,
            allow_firewall: true,
            allow_ssh_reconfigure: true,
            allow_host_reconfigure: true,
        }
        .authorize(&plan)
        .is_ok()
    );
}

#[test]
fn redaction_hides_sensitive_values_without_damaging_normal_fields() {
    let redacted = redact(&json!({
        "password": "super-secret",
        "api_token": "token-value",
        "nested": {"private_key": "key-material", "port": 22},
        "normal": "visible"
    }));

    assert_eq!(redacted["password"], "<redacted>");
    assert_eq!(redacted["api_token"], "<redacted>");
    assert_eq!(redacted["nested"]["private_key"], "<redacted>");
    assert_eq!(redacted["nested"]["port"], 22);
    assert_eq!(redacted["normal"], "visible");
}

#[test]
fn selected_v3_swift_playbook_builds_a_sealed_safety_classified_plan() {
    let bundle = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("bundle");
    let inventory_path = bundle.join("config_sample/swift_hosts");
    let inventory = Inventory::load(&inventory_path).expect("load sample inventory");
    let plan = Planner::new(&bundle, &inventory)
        .build(
            bundle.join("swift.yml"),
            fingerprint_path(bundle.join("config_sample")).expect("config fingerprint"),
        )
        .expect("build full v3 Swift plan");

    plan.verify().expect("full plan digest");
    assert!(
        plan.tasks.len() > 300,
        "expected the full Swift deployment surface"
    );
    assert_eq!(
        plan.required_capabilities(),
        vec![
            RiskClass::DiskWipe,
            RiskClass::Firewall,
            RiskClass::SshReconfigure,
            RiskClass::HostReconfigure
        ]
    );
    assert!(plan.tasks.iter().any(|task| {
        task.args
            .as_str()
            .is_some_and(|args| args.contains("{{ mariadb_root_password }}"))
    }));
}

fn seal_swift_plan(inventory_rel: &str) -> swift_deploy_rs::Plan {
    let bundle = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("bundle");
    let inventory_path = bundle.join(inventory_rel);
    let inventory = Inventory::load(&inventory_path).expect("load inventory");
    let plan = Planner::new(&bundle, &inventory)
        .build(
            bundle.join("swift.yml"),
            fingerprint_path(&inventory_path).expect("inventory fingerprint"),
        )
        .expect("seal swift.yml");
    plan.verify().expect("sealed plan digest");
    plan
}

fn args_text(task: &swift_deploy_rs::PlannedTask) -> String {
    serde_json::to_string(&task.args).unwrap_or_default()
}

#[test]
fn sample_swift_plan_seals_and_mkfs_hosts_are_the_sample_pair() {
    let plan = seal_swift_plan("config_sample/swift_hosts");
    let mkfs: Vec<_> = plan
        .tasks
        .iter()
        .filter(|task| args_text(task).to_lowercase().contains("mkfs"))
        .collect();
    assert!(!mkfs.is_empty(), "sample plan must include mkfs tasks");
    for task in mkfs {
        let mut hosts = task.hosts.clone();
        hosts.sort();
        assert_eq!(
            hosts,
            vec!["192.168.2.51".to_owned(), "192.168.2.52".to_owned()],
            "sample mkfs task {} hosts",
            task.name
        );
    }
}

fn is_destructive_live_task(task: &swift_deploy_rs::PlannedTask) -> bool {
    let name = task.name.to_lowercase();
    let args = args_text(task).to_lowercase();
    let disk = args.contains("mkfs")
        || name.contains("dd before")
        || args.contains("dd if=")
        || name.contains("partition table")
        || args.contains("parted ")
        || args.contains("sfdisk");
    let yum_upgrade = name.contains("yum upgrade") || args.contains("yum upgrade");
    let restart_sshd = name.contains("restart ssh")
        || (args.contains("sshd") && (args.contains("restarted") || args.contains("restart")));
    let install_identity = (name.contains("mariadb") || name.contains("keystone"))
        && name.contains("install");
    disk || yum_upgrade || restart_sshd || install_identity
}

#[test]
fn identity_swift_plan_seals_with_empty_disk_wipe_hosts() {
    let plan = seal_swift_plan("config_contabo_identity/swift_hosts");
    let disk_wipe: Vec<_> = plan
        .tasks
        .iter()
        .filter(|task| task.risk.contains(&RiskClass::DiskWipe))
        .collect();
    assert!(
        !disk_wipe.is_empty(),
        "identity plan still classifies mkfs tasks; only their host lists are empty"
    );
    for task in disk_wipe {
        assert!(
            task.hosts.is_empty(),
            "identity disk_wipe task {} must have an empty host list, got {:?}",
            task.name,
            task.hosts
        );
    }

    let destructive: Vec<_> = plan
        .tasks
        .iter()
        .filter(|task| is_destructive_live_task(task))
        .collect();
    assert!(
        !destructive.is_empty(),
        "identity plan must still list mkfs, dd, yum upgrade, sshd restart, and MariaDB/Keystone install tasks"
    );
    for task in destructive {
        assert!(
            task.hosts.is_empty(),
            "identity destructive task {} must have an empty host list, got {:?}",
            task.name,
            task.hosts
        );
    }
}
