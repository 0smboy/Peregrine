use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use crate::model::{BundleAudit, SUPPORTED_MODULES};

const TASK_METADATA: &[&str] = &[
    "always",
    "any_errors_fatal",
    "args",
    "async",
    "become",
    "become_flags",
    "become_method",
    "become_user",
    "block",
    "changed_when",
    "check_mode",
    "collections",
    "connection",
    "delay",
    "delegate_facts",
    "delegate_to",
    "environment",
    "failed_when",
    "ignore_errors",
    "ignore_unreachable",
    "loop",
    "loop_control",
    "module_defaults",
    "name",
    "no_log",
    "notify",
    "poll",
    "register",
    "rescue",
    "retries",
    "run_once",
    "tags",
    "throttle",
    "until",
    "vars",
    "when",
];

const CONTROL_KEYS: &[&str] = &[
    "always",
    "block",
    "changed_when",
    "delegate_to",
    "failed_when",
    "ignore_errors",
    "loop",
    "notify",
    "register",
    "rescue",
    "run_once",
    "when",
    "with_dict",
    "with_inidata",
    "with_items",
    "with_together",
];

#[derive(Default)]
struct AuditAccumulator {
    tasks: usize,
    modules: BTreeMap<String, usize>,
    controls: BTreeMap<String, usize>,
    unsupported: BTreeSet<String>,
    parse_errors: Vec<String>,
}

/// Audit every role task and handler file without executing bundle content.
pub fn audit_bundle(root: impl AsRef<Path>) -> Result<BundleAudit> {
    let root = root.as_ref();
    if !root.is_dir() {
        bail!("bundle path is not a directory: {}", root.display());
    }

    let task_files = task_files(root)?;
    let mut accumulator = AuditAccumulator::default();
    for path in &task_files {
        let content = fs::read_to_string(path)
            .with_context(|| format!("read task file {}", path.display()))?;
        let mut saw_document = false;
        for document in serde_yaml_ng::Deserializer::from_str(&content) {
            saw_document = true;
            match Value::deserialize(document) {
                Ok(value) => walk_task_value(&value, &mut accumulator),
                Err(error) => accumulator
                    .parse_errors
                    .push(format!("{}: {error}", relative(root, path).display())),
            }
        }
        if !saw_document && !content.trim().is_empty() {
            accumulator.parse_errors.push(format!(
                "{}: no YAML document found",
                relative(root, path).display()
            ));
        }
    }

    Ok(BundleAudit {
        task_files: task_files.len(),
        tasks: accumulator.tasks,
        modules: accumulator.modules,
        controls: accumulator.controls,
        unsupported_modules: accumulator.unsupported.into_iter().collect(),
        parse_errors: accumulator.parse_errors,
        fingerprint: fingerprint_path(root)?,
    })
}

fn walk_task_value(value: &Value, accumulator: &mut AuditAccumulator) {
    match value {
        Value::Array(items) => {
            for item in items {
                walk_task_value(item, accumulator);
            }
        }
        Value::Object(task) => {
            let has_block = task.contains_key("block")
                || task.contains_key("rescue")
                || task.contains_key("always");
            if has_block {
                for section in ["block", "rescue", "always"] {
                    if let Some(children) = task.get(section) {
                        walk_task_value(children, accumulator);
                    }
                }
                return;
            }

            accumulator.tasks += 1;
            for key in task.keys() {
                if CONTROL_KEYS.contains(&key.as_str()) || key.starts_with("with_") {
                    *accumulator.controls.entry(key.clone()).or_default() += 1;
                }
            }

            let mut module_count = 0;
            for key in task.keys() {
                if is_module(key) {
                    module_count += 1;
                    *accumulator.modules.entry(key.clone()).or_default() += 1;
                } else if !is_metadata(key) && !key.starts_with("with_") {
                    accumulator.unsupported.insert(key.clone());
                }
            }
            if module_count == 0 {
                accumulator
                    .unsupported
                    .insert("<missing-module>".to_owned());
            } else if module_count > 1 {
                accumulator
                    .unsupported
                    .insert("<multiple-modules>".to_owned());
            }
        }
        _ => {}
    }
}

fn is_module(key: &str) -> bool {
    SUPPORTED_MODULES.contains(&key) || matches!(key, "include" | "include_tasks")
}

fn is_metadata(key: &str) -> bool {
    TASK_METADATA.contains(&key)
}

fn task_files(root: &Path) -> Result<Vec<PathBuf>> {
    let roles = root.join("roles");
    if !roles.is_dir() {
        bail!("bundle does not contain roles/: {}", root.display());
    }
    let mut files = Vec::new();
    for entry in WalkDir::new(&roles).follow_links(false) {
        let entry = entry.with_context(|| format!("walk {}", roles.display()))?;
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let is_yaml = matches!(
            path.extension().and_then(|value| value.to_str()),
            Some("yml" | "yaml")
        );
        let in_task_directory = path
            .components()
            .any(|component| matches!(component.as_os_str().to_str(), Some("tasks" | "handlers")));
        if is_yaml && in_task_directory {
            files.push(path.to_path_buf());
        }
    }
    files.sort();
    Ok(files)
}

/// Calculate a deterministic SHA-256 over relative paths and file bytes.
pub fn fingerprint_path(root: impl AsRef<Path>) -> Result<String> {
    let root = root.as_ref();
    let mut paths = Vec::new();
    for entry in WalkDir::new(root).follow_links(false) {
        let entry = entry.with_context(|| format!("walk {}", root.display()))?;
        if entry.file_type().is_file() {
            paths.push(entry.path().to_path_buf());
        }
    }
    paths.sort();

    let mut digest = Sha256::new();
    for path in paths {
        let relative_path = relative(root, &path);
        digest.update(relative_path.to_string_lossy().as_bytes());
        digest.update([0]);
        digest.update(fs::read(&path).with_context(|| format!("read {}", path.display()))?);
        digest.update([0]);
    }
    Ok(hex::encode(digest.finalize()))
}

fn relative<'a>(root: &'a Path, path: &'a Path) -> &'a Path {
    path.strip_prefix(root).unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn fingerprint_is_path_and_content_sensitive() {
        let directory = tempdir().expect("temp directory");
        fs::write(directory.path().join("a"), "one").expect("write fixture");
        let first = fingerprint_path(directory.path()).expect("first fingerprint");
        fs::write(directory.path().join("a"), "two").expect("update fixture");
        let second = fingerprint_path(directory.path()).expect("second fingerprint");
        assert_ne!(first, second);
    }
}
