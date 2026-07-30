use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs;

use pretty_assertions::assert_eq;
use serde_json::json;
use swift_deploy_rs::{
    CommandOutput, ConnectionSpec, Executor, Inventory, LoopSpec, ModuleDispatcher,
    OpenSshTransport, Plan, PlannedTask, RecordingTransport, Renderer, SUPPORTED_MODULES,
    TransportAction,
};
use tempfile::tempdir;

#[test]
fn openssh_argv_keeps_host_key_checking_and_rejects_passwords_by_default() {
    let connection = ConnectionSpec {
        host: "10.0.0.8".to_owned(),
        user: "root".to_owned(),
        port: 2222,
        key_path: Some("/keys/swift key".into()),
        password: None,
        known_hosts: Some("/tmp/known_hosts".into()),
        become_user: None,
    };
    let argv = OpenSshTransport::ssh_argv(&connection, "printf ok").expect("SSH argv");

    assert_eq!(argv[0], OsString::from("ssh"));
    assert!(argv.contains(&OsString::from("StrictHostKeyChecking=yes")));
    assert!(argv.contains(&OsString::from("UserKnownHostsFile=/tmp/known_hosts")));
    assert!(argv.contains(&OsString::from("/keys/swift key")));
    let separator = argv.iter().position(|value| value == "--").expect("SSH --");
    let target = argv
        .iter()
        .position(|value| value == "root@10.0.0.8")
        .expect("SSH target");
    assert!(
        separator < target,
        "option parsing must end before the target"
    );
    assert_eq!(argv.last(), Some(&OsString::from("printf ok")));

    let password_connection = ConnectionSpec {
        password: Some("not-allowed".to_owned()),
        ..connection
    };
    assert!(OpenSshTransport::ssh_argv(&password_connection, "true").is_err());
}

#[test]
fn inventory_connection_rejects_ssh_option_injection() {
    let malicious_user = json!({"ansible_user": "-oProxyCommand=bad", "ansible_host": "10.0.0.8"});
    assert!(ConnectionSpec::from_context("node", &malicious_user, None).is_err());

    let malicious_host = json!({"ansible_user": "root", "ansible_host": "-oProxyCommand=bad"});
    assert!(ConnectionSpec::from_context("node", &malicious_host, None).is_err());
}

#[test]
fn dispatcher_covers_all_28_modules_and_edits_files_in_rust() {
    let directory = tempdir().expect("temporary bundle");
    let bundle = directory.path().join("bundle");
    fs::create_dir_all(bundle.join("roles/demo/templates")).expect("template directory");
    fs::create_dir_all(bundle.join("roles/demo/files")).expect("files directory");
    fs::write(
        bundle.join("roles/demo/templates/demo.conf.j2"),
        "port={{ port }}\n",
    )
    .expect("template");
    fs::write(bundle.join("roles/demo/files/payload"), "payload\n").expect("payload");

    assert_eq!(ModuleDispatcher::supported_modules(), SUPPORTED_MODULES);

    let renderer = Renderer::new();
    let dispatcher = ModuleDispatcher::new(&bundle, &renderer);
    let connection = ConnectionSpec::local("node-a");
    let mut transport = RecordingTransport::default();
    transport.set_file("node-a", "/etc/demo.conf", b"mode=old\n".to_vec());

    let line = dispatcher
        .execute(
            &mut transport,
            &connection,
            "demo",
            "lineinfile",
            &json!({
                "dest": "/etc/demo.conf",
                "regexp": "^mode=",
                "line": "mode=new"
            }),
            &json!({}),
        )
        .expect("lineinfile");
    assert!(line.changed);
    assert_eq!(
        transport.file("node-a", "/etc/demo.conf"),
        Some(&b"mode=new\n"[..])
    );

    let template = dispatcher
        .execute(
            &mut transport,
            &connection,
            "demo",
            "template",
            &json!({"src": "demo.conf.j2", "dest": "/etc/rendered.conf"}),
            &json!({"port": 8080}),
        )
        .expect("template");
    assert!(template.changed);
    assert_eq!(
        transport.file("node-a", "/etc/rendered.conf"),
        Some(&b"port=8080\n"[..])
    );

    let shell = dispatcher
        .execute(
            &mut transport,
            &connection,
            "demo",
            "shell",
            &json!("echo safe"),
            &json!({}),
        )
        .expect("shell");
    assert!(shell.changed);
    assert!(transport.actions.iter().any(|action| matches!(
        action,
        TransportAction::Run { command, .. } if command == "echo safe"
    )));

    let facts = dispatcher
        .execute(
            &mut transport,
            &connection,
            "demo",
            "set_fact",
            &json!({"ready": true}),
            &json!({}),
        )
        .expect("set_fact");
    assert_eq!(facts.data["facts"]["ready"], true);

    transport.set_file("node-a", "/tmp/source", b"source".to_vec());
    transport.set_file("node-a", "/etc/block.conf", b"head\n".to_vec());
    transport.set_file("node-a", "/etc/demo.ini", b"[main]\nold = 1\n".to_vec());
    let remaining = [
        (
            "blockinfile",
            json!({"path": "/etc/block.conf", "block": "managed", "create": true}),
        ),
        ("command", json!("printf command")),
        ("copy", json!({"src": "payload", "dest": "/tmp/copied"})),
        (
            "cron",
            json!({"name": "demo", "minute": "5", "job": "/bin/true"}),
        ),
        ("debug", json!({"msg": "debug"})),
        ("fail", json!({"msg": "expected"})),
        (
            "fetch",
            json!({"src": "/tmp/source", "dest": directory.path().join("fetch"), "flat": true}),
        ),
        (
            "file",
            json!({"path": "/tmp/demo-dir", "state": "directory"}),
        ),
        ("find", json!({"paths": ["/tmp"], "recurse": false})),
        (
            "get_url",
            json!({"url": "https://example.invalid/file", "dest": "/tmp/file"}),
        ),
        (
            "ini_file",
            json!({"path": "/etc/demo.ini", "section": "main", "option": "new", "value": "2"}),
        ),
        ("mysql_db", json!({"name": "demo", "state": "present"})),
        (
            "mysql_user",
            json!({"name": "demo", "host": "localhost", "password": "secret"}),
        ),
        ("package", json!({"name": "rsync", "state": "present"})),
        ("pip", json!({"name": "sample", "state": "present"})),
        ("script", json!("payload --check")),
        ("service", json!({"name": "demo", "state": "restarted"})),
        ("stat", json!({"path": "/tmp/source"})),
        (
            "systemd",
            json!({"name": "demo", "state": "started", "daemon_reload": true}),
        ),
        ("timezone", json!({"name": "UTC"})),
        (
            "unarchive",
            json!({"src": "payload", "dest": "/tmp/unpacked"}),
        ),
        (
            "uri",
            json!({"url": "https://example.invalid/health", "method": "HEAD", "status_code": 200}),
        ),
        ("user", json!({"name": "swift", "state": "present"})),
        ("yum", json!({"name": "chrony", "state": "present"})),
    ];
    let mut exercised = BTreeSet::from(["lineinfile", "set_fact", "shell", "template"]);
    for (module, args) in remaining {
        let result = dispatcher
            .execute(
                &mut transport,
                &connection,
                "demo",
                module,
                &args,
                &json!({}),
            )
            .unwrap_or_else(|error| panic!("{module} adapter failed: {error:#}"));
        if module == "fail" {
            assert!(result.failed);
        }
        exercised.insert(module);
    }
    assert_eq!(
        exercised,
        SUPPORTED_MODULES.into_iter().collect::<BTreeSet<_>>()
    );
}

#[test]
fn explicit_metadata_is_enforced_even_when_file_content_matches() {
    let directory = tempdir().expect("temporary bundle");
    let renderer = Renderer::new();
    let dispatcher = ModuleDispatcher::new(directory.path(), &renderer);
    let connection = ConnectionSpec::local("node-a");
    let mut transport = RecordingTransport::default();
    transport.set_file("node-a", "/etc/swift/same.conf", b"same\n".to_vec());

    let result = dispatcher
        .execute(
            &mut transport,
            &connection,
            "demo",
            "copy",
            &json!({
                "content": "same\n",
                "dest": "/etc/swift/same.conf",
                "mode": "0640",
                "owner": "swift",
                "group": "swift"
            }),
            &json!({}),
        )
        .expect("copy with explicit metadata");

    assert!(result.changed);
    assert!(transport.actions.iter().any(|action| matches!(
        action,
        TransportAction::WriteFile { path, options, .. }
            if path == "/etc/swift/same.conf"
                && options.mode.as_deref() == Some("0640")
                && options.owner.as_deref() == Some("swift")
                && options.group.as_deref() == Some("swift")
    )));
}

#[test]
fn executor_handles_nested_loops_run_once_register_and_handlers() {
    let directory = tempdir().expect("temporary project");
    let inventory_path = directory.path().join("hosts");
    fs::write(
        &inventory_path,
        "node-a ansible_user=root\nnode-b ansible_user=root\n",
    )
    .expect("inventory");
    let inventory = Inventory::load(&inventory_path).expect("inventory");
    let task = PlannedTask {
        id: 1,
        source: "roles/demo/tasks/main.yml#1".to_owned(),
        role: "demo".to_owned(),
        name: "loop command".to_owned(),
        host_pattern: "all".to_owned(),
        hosts: vec!["node-a".to_owned(), "node-b".to_owned()],
        module: "shell".to_owned(),
        args: json!("echo {{ outer }}-{{ inner }}"),
        vars: BTreeMap::from([("enabled".to_owned(), json!(true))]),
        when: vec!["enabled".to_owned()],
        loops: vec![
            LoopSpec {
                kind: "with_items".to_owned(),
                expression: json!(["a", "b"]),
                loop_var: "outer".to_owned(),
            },
            LoopSpec {
                kind: "with_items".to_owned(),
                expression: json!([1, 2]),
                loop_var: "inner".to_owned(),
            },
        ],
        run_once: true,
        privilege_escalation: false,
        become_user: None,
        delegate_to: None,
        register: Some("loop_result".to_owned()),
        notify: vec!["restart demo".to_owned()],
        ignore_errors: false,
        failed_when: Vec::new(),
        changed_when: Vec::new(),
        risk: Vec::new(),
    };
    let handler = PlannedTask {
        id: 2,
        source: "roles/demo/handlers/main.yml#1".to_owned(),
        role: "demo".to_owned(),
        name: "restart demo".to_owned(),
        host_pattern: "all".to_owned(),
        hosts: vec!["node-a".to_owned(), "node-b".to_owned()],
        module: "service".to_owned(),
        args: json!({"name": "demo", "state": "restarted"}),
        vars: BTreeMap::new(),
        when: Vec::new(),
        loops: Vec::new(),
        run_once: false,
        privilege_escalation: false,
        become_user: None,
        delegate_to: None,
        register: None,
        notify: Vec::new(),
        ignore_errors: false,
        failed_when: Vec::new(),
        changed_when: Vec::new(),
        risk: Vec::new(),
    };
    let plan = Plan {
        schema_version: 2,
        bundle_fingerprint: "bundle".to_owned(),
        inventory_fingerprint: "inventory".to_owned(),
        playbook: "demo.yml".to_owned(),
        hosts: vec!["node-a".to_owned(), "node-b".to_owned()],
        tasks: vec![task],
        handlers: vec![handler],
        digest: String::new(),
    }
    .seal()
    .expect("seal plan");

    let renderer = Renderer::new();
    let mut transport = RecordingTransport::default();
    let report = Executor::new(directory.path(), &inventory, &renderer)
        .execute(&plan, &mut transport)
        .expect("execute plan");

    assert_eq!(report.failed, 0);
    assert_eq!(report.changed, 5);
    assert_eq!(report.skipped, 1);
    let commands = transport
        .actions
        .iter()
        .filter_map(|action| match action {
            TransportAction::Run { command, .. } => Some(command.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(commands.contains(&"echo a-1"));
    assert!(commands.contains(&"echo b-2"));
    assert!(
        commands
            .iter()
            .any(|command| command.contains("systemctl restart demo"))
    );
}

#[test]
fn run_once_register_and_set_fact_are_available_on_every_target_host() {
    let directory = tempdir().expect("temporary project");
    let inventory_path = directory.path().join("hosts");
    fs::write(
        &inventory_path,
        "node-a ansible_user=root\nnode-b ansible_user=root\n",
    )
    .expect("inventory");
    let inventory = Inventory::load(&inventory_path).expect("inventory");
    let hosts = vec!["node-a".to_owned(), "node-b".to_owned()];
    let task = |id: u64,
                name: &str,
                module: &str,
                args: serde_json::Value,
                run_once: bool,
                register: Option<&str>| PlannedTask {
        id,
        source: format!("roles/demo/tasks/main.yml#{id}"),
        role: "demo".to_owned(),
        name: name.to_owned(),
        host_pattern: "all".to_owned(),
        hosts: hosts.clone(),
        module: module.to_owned(),
        args,
        vars: BTreeMap::new(),
        when: Vec::new(),
        loops: Vec::new(),
        run_once,
        privilege_escalation: false,
        become_user: None,
        delegate_to: None,
        register: register.map(str::to_owned),
        notify: Vec::new(),
        ignore_errors: false,
        failed_when: Vec::new(),
        changed_when: Vec::new(),
        risk: Vec::new(),
    };
    let plan = Plan {
        schema_version: 2,
        bundle_fingerprint: "bundle".to_owned(),
        inventory_fingerprint: "inventory".to_owned(),
        playbook: "demo.yml".to_owned(),
        hosts: hosts.clone(),
        tasks: vec![
            task(
                1,
                "seed once",
                "shell",
                json!("printf seed"),
                true,
                Some("seed_result"),
            ),
            task(
                2,
                "share fact once",
                "set_fact",
                json!({"shared_value": "{{ seed_result.stdout }}"}),
                true,
                None,
            ),
            task(
                3,
                "consume shared fact everywhere",
                "shell",
                json!("echo {{ shared_value }}"),
                false,
                None,
            ),
        ],
        handlers: Vec::new(),
        digest: String::new(),
    }
    .seal()
    .expect("seal plan");
    let mut transport = RecordingTransport::default();
    for host in ["node-a", "node-b"] {
        transport.outputs.push_back(CommandOutput {
            status: 0,
            stdout: format!("HOSTNAME={host}\nDEFAULT={host}\nALL={host}\n").into_bytes(),
            stderr: Vec::new(),
        });
    }
    transport.outputs.push_back(CommandOutput {
        status: 0,
        stdout: b"seed".to_vec(),
        stderr: Vec::new(),
    });

    let report = Executor::new(directory.path(), &inventory, &Renderer::new())
        .execute(&plan, &mut transport)
        .expect("execute plan");

    assert_eq!(report.failed, 0);
    for host in ["node-a", "node-b"] {
        assert!(transport.actions.iter().any(|action| matches!(
            action,
            TransportAction::Run {
                host: action_host,
                command
            } if action_host == host && command == "echo seed"
        )));
    }
}
