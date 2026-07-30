use std::path::PathBuf;

use pretty_assertions::assert_eq;
use swift_deploy_rs::{SUPPORTED_MODULES, audit_bundle};

fn bundle() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("bundle")
}

#[test]
fn selected_v3_bundle_is_fully_covered() {
    let audit = audit_bundle(bundle()).expect("audit selected bundle");

    assert_eq!(audit.task_files, 57);
    assert_eq!(audit.tasks, 422);
    assert_eq!(audit.executable_module_count(), SUPPORTED_MODULES.len());
    assert_eq!(audit.unsupported_modules, Vec::<String>::new());
    assert_eq!(audit.parse_errors, Vec::<String>::new());

    for module in SUPPORTED_MODULES {
        assert!(
            audit.modules.contains_key(module),
            "selected bundle did not exercise {module}"
        );
    }
}

#[test]
fn audit_fingerprint_is_stable() {
    let first = audit_bundle(bundle()).expect("first audit");
    let second = audit_bundle(bundle()).expect("second audit");
    assert_eq!(first.fingerprint, second.fingerprint);
    assert_eq!(first.fingerprint.len(), 64);
}
