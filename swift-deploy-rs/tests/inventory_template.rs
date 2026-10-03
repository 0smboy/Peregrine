use std::fs;
use std::path::PathBuf;

use pretty_assertions::assert_eq;
use serde_json::json;
use swift_deploy_rs::{Inventory, Renderer};
use tempfile::tempdir;

#[test]
fn inventory_expands_ranges_children_and_variable_layers() {
    let directory = tempdir().expect("temporary inventory directory");
    let inventory_path = directory.path().join("swift_hosts");
    fs::write(
        &inventory_path,
        r#"
10.0.0.[01:02] ansible_user=root ansible_port=2222

[proxy_servers]
10.0.0.01 proxy_mode=https

[storage_nodes]
10.0.0.02

[swift_nodes:children]
proxy_servers
storage_nodes

[swift_nodes:vars]
cluster_name=swift-lab
"#,
    )
    .expect("write inventory");

    fs::create_dir(directory.path().join("group_vars")).expect("create group vars");
    fs::write(
        directory.path().join("group_vars/all.raw"),
        "INSTALL_MODE: production\nproxy_server_bind_port: 8080\n",
    )
    .expect("write all vars");
    fs::write(
        directory.path().join("group_vars/proxy_servers"),
        "public_port: {{ proxy_server_bind_port }}\n",
    )
    .expect("write group vars containing bare Jinja");

    fs::create_dir(directory.path().join("host_vars")).expect("create host vars");
    fs::write(
        directory.path().join("host_vars/10.0.0.01.yml"),
        "rack: rack-a\nstorage_network_address: 10.1.0.1\n",
    )
    .expect("write host vars");

    let inventory = Inventory::load(&inventory_path).expect("load inventory");

    assert_eq!(inventory.host_names(), vec!["10.0.0.01", "10.0.0.02"]);
    assert_eq!(
        inventory
            .hosts_for_pattern("swift_nodes")
            .expect("host pattern"),
        vec!["10.0.0.01", "10.0.0.02"]
    );

    let first = inventory.host_context("10.0.0.01").expect("host context");
    assert_eq!(first["ansible_user"], "root");
    assert_eq!(first["ansible_port"], 2222);
    assert_eq!(first["cluster_name"], "swift-lab");
    assert_eq!(first["rack"], "rack-a");
    assert_eq!(first["public_port"], "{{ proxy_server_bind_port }}");
    assert_eq!(
        first["proxy_storage_network_addresses"],
        json!(["10.1.0.1"])
    );
    assert_eq!(
        first["groups"]["swift_nodes"],
        json!(["10.0.0.01", "10.0.0.02"])
    );
}

#[test]
fn renderer_supports_the_v3_jinja_compatibility_surface() {
    let renderer = Renderer::new();
    let context = json!({
        "inventory_hostname": "192.168.2.51",
        "left": ["proxy", "object"],
        "right": ["object", "container"],
        "result": {"failed": true}
    });

    assert_eq!(
        renderer
            .render_str("node-{{ inventory_hostname.split('.')[-1] }}", &context)
            .expect("split method"),
        "node-51"
    );
    assert_eq!(
        renderer
            .render_str("{{ left | intersect(right) | join(',') }}", &context)
            .expect("intersect filter"),
        "object"
    );
    assert!(
        renderer
            .eval_bool("result is failed", &context)
            .expect("failed test")
    );
    assert!(
        renderer
            .eval_bool("inventory_hostname.find('192.') == 0", &context)
            .expect("find method")
    );
    assert_eq!(
        renderer
            .render_str(
                "{{ '.'.join(inventory_hostname.split('.')[:-1]) }}",
                &context,
            )
            .expect("Python-style join method"),
        "192.168.2"
    );
    assert!(
        renderer
            .eval_bool(
                "result and {{ inventory_hostname.find('192.') == 0 }}",
                &json!({
                    "result": true,
                    "inventory_hostname": "192.168.2.51"
                }),
            )
            .expect("embedded expression in legacy when")
    );

    let resolved = renderer
        .resolve_context(&json!({
            "proxy_server_bind_port": 8080,
            "public_port": "{{ proxy_server_bind_port }}",
            "endpoint": "http://127.0.0.1:{{ public_port }}"
        }))
        .expect("recursive variable resolution");
    assert_eq!(resolved["public_port"], 8080);
    assert_eq!(resolved["endpoint"], "http://127.0.0.1:8080");
}

#[test]
fn selected_v3_sample_inventory_loads_without_ansible() {
    let bundle = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("bundle/config_sample");
    let inventory = Inventory::load(bundle.join("swift_hosts")).expect("load v3 sample inventory");

    assert_eq!(inventory.host_names(), vec!["192.168.2.51", "192.168.2.52"]);
    assert_eq!(
        inventory
            .hosts_for_pattern("storage_nodes")
            .expect("storage hosts"),
        vec!["192.168.2.51", "192.168.2.52"]
    );
    let proxy = inventory
        .host_context("192.168.2.51")
        .expect("sample host context");
    assert_eq!(proxy["INSTALL_MODE"], "production");
    assert_eq!(proxy["proxy_mode"], "http");
    assert_eq!(proxy["proxy_server_bind_port"], 8080);
    assert_eq!(
        proxy["business_network_public_ports"],
        json!([5000, 35357, 5050, 443])
    );
    assert!(
        proxy["account_ring"]
            .as_array()
            .is_some_and(|nodes| !nodes.is_empty())
    );
}

#[test]
fn contabo_keepalived_script_renders_timeout_and_fall() {
    let renderer = Renderer::new();
    // Contabo live: VIP 10.0.0.10/22 on eth1, VRID 51, swift1 priority 140,
    // chk_http_port interval 1 weight -10, use_lb so the check is haproxy.
    // Group vars still omit timeout and fall; the template must emit them.
    let context = json!({
        "use_lb": true,
        "keepalived_interface": "eth1",
        "keepalived_priority": 140,
        "keepalived_mode": "nopreempt",
        "auth_url_ip": "10.0.0.10",
        "vip_prefix": 22,
        "keepalived_vrrp_script": {
            "name": "chk_http_port",
            "interval": 1,
            "weight": -10
        },
        "keepalived_servers": {
            "vrrp_instance": {
                "virtual_router_id": 51,
                "advert_int": 1,
                "auth_pass": "fixture-auth"
            }
        }
    });
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for relative in [
        "bundle-rust/roles/rust_keepalived/templates/keepalived.conf.j2",
        "bundle/roles/keepalived_servers/templates/keepalived.conf.j2",
    ] {
        let source = fs::read_to_string(root.join(relative))
            .unwrap_or_else(|error| panic!("read {relative}: {error}"));
        let rendered = renderer
            .render_str(&source, &context)
            .unwrap_or_else(|error| panic!("render {relative}: {error}"));
        let script = rendered
            .split_once("# Peregrine_vrrp_script BEGIN")
            .and_then(|(_, rest)| rest.split_once("# Peregrine_vrrp_script END"))
            .map(|(block, _)| block)
            .unwrap_or_else(|| panic!("{relative} missing vrrp_script markers"));
        let interval = script.find("interval 1").expect("interval");
        let timeout = script.find("timeout 4").expect("timeout");
        let fall = script.find("fall 3").expect("fall");
        let weight = script.find("weight -10").expect("weight");
        assert!(
            interval < timeout && timeout < fall && fall < weight,
            "{relative} script block order:\n{script}"
        );
        assert!(
            script.contains("script   \"/etc/keepalived/check_haproxy.sh\""),
            "{relative} check command changed:\n{script}"
        );
        assert!(rendered.contains("virtual_router_id  51"));
        assert!(rendered.contains("priority   140"));
        assert!(rendered.contains("auth_pass fixture-auth"));
        assert!(rendered.contains("nopreempt"));
    }
}
