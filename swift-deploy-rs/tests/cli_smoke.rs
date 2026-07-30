use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;
use swift_deploy_rs::Plan;
use tempfile::tempdir;

#[test]
fn audit_validate_plan_and_safety_rejections_work_end_to_end() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let bundle = manifest.join("bundle");
    let inventory = bundle.join("config_sample/swift_hosts");

    let audit = run(&["audit", "--bundle", path(&bundle), "--json"]);
    assert_success(&audit);
    let audit_json: Value = serde_json::from_slice(&audit.stdout).expect("audit JSON");
    assert_eq!(audit_json["task_files"], 57);
    assert_eq!(audit_json["tasks"], 422);

    let validate = run(&["validate", "--inventory", path(&inventory), "--json"]);
    assert_success(&validate);
    let validate_json: Value = serde_json::from_slice(&validate.stdout).expect("validate JSON");
    assert_eq!(validate_json["hosts"], 2);
    assert!(
        validate_json["placeholders"]
            .as_array()
            .is_some_and(|items| !items.is_empty())
    );

    let directory = tempdir().expect("temporary CLI output");
    let plan_path = directory.path().join("swift-plan.json");
    let plan_output = run(&[
        "plan",
        "--bundle",
        path(&bundle),
        "--inventory",
        path(&inventory),
        "--playbook",
        path(&bundle.join("swift.yml")),
        "--output",
        path(&plan_path),
        "--json",
    ]);
    assert_success(&plan_output);
    let plan: Plan =
        serde_json::from_slice(&fs::read(&plan_path).expect("read plan")).expect("plan JSON");
    plan.verify().expect("CLI plan digest");

    let wrong_digest = run(&[
        "apply",
        "--bundle",
        path(&bundle),
        "--inventory",
        path(&inventory),
        "--plan",
        path(&plan_path),
        "--confirm-digest",
        "wrong",
    ]);
    assert!(!wrong_digest.status.success());
    assert!(String::from_utf8_lossy(&wrong_digest.stderr).contains("confirmation"));

    let missing_gates = run(&[
        "apply",
        "--bundle",
        path(&bundle),
        "--inventory",
        path(&inventory),
        "--plan",
        path(&plan_path),
        "--confirm-digest",
        &plan.digest,
    ]);
    assert!(!missing_gates.status.success());
    let missing_gates_error = String::from_utf8_lossy(&missing_gates.stderr);
    assert!(missing_gates_error.contains("safety capabilities"));
    assert!(missing_gates_error.contains("HostReconfigure"));

    let apply_help = run(&["apply", "--help"]);
    assert_success(&apply_help);
    assert!(String::from_utf8_lossy(&apply_help.stdout).contains("--allow-host-reconfigure"));

    let modules = run(&["modules", "--json"]);
    assert_success(&modules);
    let modules_json: Value = serde_json::from_slice(&modules.stdout).expect("modules JSON");
    assert_eq!(modules_json.as_array().map(Vec::len), Some(28));
}

fn run(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_swift-deploy"))
        .args(arguments)
        .output()
        .expect("run swift-deploy")
}

fn path(path: &Path) -> &str {
    path.to_str().expect("UTF-8 test path")
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "command failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
