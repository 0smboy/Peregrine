use std::fs;
use std::path::PathBuf;

use serde_json::Value;

fn bundle() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("bundle")
}

fn read(relative: &str) -> String {
    let path = bundle().join(relative);
    fs::read_to_string(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

fn task_named<'a>(tasks: &'a [Value], name: &str) -> &'a serde_json::Map<String, Value> {
    tasks
        .iter()
        .filter_map(Value::as_object)
        .find(|task| task.get("name").and_then(Value::as_str) == Some(name))
        .unwrap_or_else(|| panic!("missing task {name}"))
}

#[test]
fn keystone_bootstrap_keys_round_trip_through_the_control_node() {
    let path = bundle().join("roles/keystones/tasks/bootstrap.yml");
    let tasks: Value = serde_yaml_ng::from_str(
        &fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display())),
    )
    .expect("parse Keystone bootstrap tasks");
    let tasks = tasks.as_array().expect("Keystone task list");

    let controller_block = tasks[0].as_object().expect("controller block");
    assert_eq!(
        controller_block.get("when").and_then(Value::as_str),
        Some("inventory_hostname == groups['mariadb_servers'][0]")
    );
    let controller_tasks = controller_block["block"]
        .as_array()
        .expect("controller block tasks");
    let archive = task_named(
        controller_tasks,
        "Archive Keystone bootstrap keys on the controller",
    );
    assert!(
        archive["shell"]
            .as_str()
            .is_some_and(|command| command.contains("fernet-keys credential-keys"))
    );
    let fetch = task_named(
        controller_tasks,
        "Fetch Keystone bootstrap keys to the control node",
    );
    assert_eq!(
        fetch["fetch"]["src"],
        "/tmp/swift-deploy-keystone-bootstrap-keys.tar.gz"
    );
    assert_eq!(
        fetch["fetch"]["dest"],
        "/tmp/swift-deploy-control-keystone-bootstrap-keys.tar.gz"
    );
    assert_ne!(fetch["fetch"]["src"], fetch["fetch"]["dest"]);
    assert_eq!(fetch["fetch"]["flat"], true);
    let restrict = task_named(
        controller_tasks,
        "Restrict the control-node Keystone bootstrap archive",
    );
    assert_eq!(restrict["file"]["path"], fetch["fetch"]["dest"]);
    assert_eq!(restrict["file"]["mode"], "0600");
    assert_eq!(restrict["delegate_to"], "localhost");

    let stage = task_named(
        tasks,
        "Stage the Keystone bootstrap archive on every Keystone node",
    );
    assert_eq!(stage["copy"]["src"], fetch["fetch"]["dest"]);
    assert_eq!(
        stage["copy"]["dest"],
        "/tmp/swift-deploy-node-keystone-bootstrap-keys.tar.gz"
    );
    assert_eq!(stage["copy"]["owner"], "root");
    assert_eq!(stage["copy"]["group"], "root");
    assert_eq!(stage["copy"]["mode"], "0600");

    let distribute = task_named(
        tasks,
        "Distribute Keystone bootstrap keys to every Keystone node",
    );
    assert_eq!(distribute["unarchive"]["src"], stage["copy"]["dest"]);
    assert_eq!(distribute["unarchive"]["dest"], "/etc/keystone");
    assert_eq!(distribute["unarchive"]["remote_src"], true);
    assert!(distribute.get("when").is_none());

    let permissions = task_named(tasks, "Secure distributed Keystone bootstrap keys");
    let command = permissions["shell"].as_str().expect("permission command");
    for evidence in [
        "chown -R keystone:keystone",
        "-type d -exec chmod 0700",
        "-type f -exec chmod 0600",
    ] {
        assert!(command.contains(evidence), "missing permission: {evidence}");
    }

    let cleanup = task_named(tasks, "Remove the node-side Keystone bootstrap archive");
    assert_eq!(cleanup["file"]["path"], stage["copy"]["dest"]);
    assert_eq!(cleanup["file"]["state"], "absent");
    assert!(cleanup.get("when").is_none());
}

#[test]
fn service_templates_use_only_their_role_scoped_storage_addresses() {
    let mariadb = read("roles/mariadb_servers/templates/etc/my.cnf.d/server.cnf.j2");
    assert!(mariadb.contains(
        "wsrep_cluster_address=\"gcomm://{{ mariadb_storage_network_addresses|join(',') }}\""
    ));
    assert!(!mariadb.contains(
        "wsrep_cluster_address=\"gcomm://{{ keystone_storage_network_addresses|join(',') }}\""
    ));

    let proxy = read("roles/swift_proxy/templates/proxy-server.conf.j2");
    let configured_memcache_lines = proxy
        .lines()
        .map(str::trim)
        .filter(|line| {
            line.starts_with("memcache_servers=") || line.starts_with("memcached_servers =")
        })
        .collect::<Vec<_>>();
    assert_eq!(configured_memcache_lines.len(), 2);
    assert!(
        configured_memcache_lines
            .iter()
            .all(|line| line.contains("proxy_storage_network_addresses"))
    );
    assert!(proxy.contains("keystone_endpoint_controller_hostname"));

    let keystone = read("roles/keystone_install/vars/main.yml");
    assert!(keystone.contains("keystone_storage_network_addresses|join(':11211,')"));
    assert!(!keystone.contains("proxy_storage_network_addresses"));
}

#[test]
fn generated_credentials_replace_upstream_fixed_health_and_stats_passwords() {
    let defaults = read("roles/mariadb_servers/defaults/main.yml");
    assert!(!defaults.contains("clustercheckpassword"));

    let clustercheck = read("roles/mariadb_servers/files/usr/bin/clustercheck");
    assert!(!clustercheck.contains("clustercheckpassword"));
    assert!(clustercheck.contains("MYSQL_PASSWORD:?MYSQL_PASSWORD must be set"));

    let mysqlchk = read("roles/mariadb_servers/templates/etc/mysqlchk@.service.j2");
    assert!(mysqlchk.contains("MYSQL_USERNAME={{ mariadb_clustercheck_user }}"));
    assert!(mysqlchk.contains("MYSQL_PASSWORD={{ mariadb_clustercheck_password }}"));

    let haproxy = read("roles/haproxy_servers/templates/haproxy.cfg.j2");
    assert!(
        haproxy.contains("stats auth    {{ haproxy_stats_user }}:{{ haproxy_stats_password }}")
    );
    assert!(!haproxy.contains("stats auth    admin:admin"));
}
