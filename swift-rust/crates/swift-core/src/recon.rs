// Copyright (c) 2026 OpenStack Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Recon cache maintenance, the Rust counterpart of
//! `swift.common.utils.dump_recon_cache` / `put_recon_cache_entry`.
//!
//! The recon cache is a single-line JSON object read by swift-recon and
//! the recon middleware. Updates are merged into whatever is already on
//! disk and written back atomically (temp file + rename in the same
//! directory), so readers always see a complete document.
//!
//! Merge semantics, following the Python implementation with one
//! contract-mandated extension:
//! - a `null` update value deletes the key (top level and nested);
//! - an empty-object update value (`{}`) also deletes the key, as in
//!   Python's `put_recon_cache_entry`;
//! - an object update value merges one level deep into an existing
//!   object (replacing it entirely when the existing value is not an
//!   object);
//! - any other value replaces the existing one.
//!
//! Like the Python version, a missing, unreadable, or corrupt cache file
//! is treated as `{}` and recreated. Unlike Python there is no advisory
//! flock; last-writer-wins on the rename, which still never corrupts the
//! file.

use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value};

/// Read the existing cache entry, tolerating a missing or corrupt file.
/// Python reads only the first line of the file, so mirror that.
fn read_existing_entry(cache_file: &Path) -> Map<String, Value> {
    let Ok(contents) = std::fs::read_to_string(cache_file) else {
        return Map::new();
    };
    let first_line = contents.lines().next().unwrap_or("");
    match serde_json::from_str::<Value>(first_line) {
        Ok(Value::Object(entry)) => entry,
        _ => Map::new(),
    }
}

/// Merge one `key: item` update into the cache entry
/// (`swift.common.utils.put_recon_cache_entry`).
fn put_recon_cache_entry(cache_entry: &mut Map<String, Value>, key: &str, item: &Value) {
    match item {
        Value::Null => {
            cache_entry.remove(key);
        }
        Value::Object(updates) => {
            if updates.is_empty() {
                cache_entry.remove(key);
                return;
            }
            let slot = cache_entry
                .entry(key.to_string())
                .or_insert_with(|| Value::Object(Map::new()));
            if !slot.is_object() {
                *slot = Value::Object(Map::new());
            }
            if let Value::Object(existing) = slot {
                for (nested_key, nested_value) in updates {
                    let delete = nested_value.is_null()
                        || nested_value
                            .as_object()
                            .is_some_and(|nested| nested.is_empty());
                    if delete {
                        existing.remove(nested_key);
                    } else {
                        existing.insert(nested_key.clone(), nested_value.clone());
                    }
                }
            }
        }
        other => {
            cache_entry.insert(key.to_string(), other.clone());
        }
    }
}

/// Merge `updates` (which must be a JSON object) into `cache_file` and
/// write the result atomically, creating parent directories as needed.
pub fn dump_recon_cache(cache_file: &Path, updates: &Value) -> std::io::Result<()> {
    let Some(update_entries) = updates.as_object() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "recon cache updates must be a JSON object",
        ));
    };

    let parent = cache_file
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)?;

    let mut cache_entry = read_existing_entry(cache_file);
    for (key, value) in update_entries {
        put_recon_cache_entry(&mut cache_entry, key, value);
    }

    // serde_json's default map is BTreeMap-backed, so keys serialize
    // sorted, matching Python's `json.dumps(..., sort_keys=True)`.
    let mut serialized = Value::Object(cache_entry).to_string();
    serialized.push('\n');

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.subsec_nanos())
        .unwrap_or(0);
    let tmp_path = parent.join(format!(".recon.{}.{}.tmp", std::process::id(), nanos));
    let mut tmp_file = std::fs::File::create(&tmp_path)?;
    if let Err(error) = tmp_file
        .write_all(serialized.as_bytes())
        .and_then(|()| tmp_file.flush())
    {
        drop(tmp_file);
        let _ = std::fs::remove_file(&tmp_path);
        return Err(error);
    }
    drop(tmp_file);
    if let Err(error) = std::fs::rename(&tmp_path, cache_file) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::path::PathBuf;

    fn scratch_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("swift-recon-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn read_cache(cache_file: &Path) -> Value {
        let contents = std::fs::read_to_string(cache_file).unwrap();
        assert!(contents.ends_with('\n'), "cache line ends with newline");
        serde_json::from_str(contents.trim_end()).unwrap()
    }

    #[test]
    fn creates_the_cache_file_and_parent_directories() {
        let dir = scratch_dir("create");
        let cache_file = dir.join("nested/object.recon");
        dump_recon_cache(&cache_file, &json!({"object_replication_time": 1.5})).unwrap();
        assert_eq!(
            read_cache(&cache_file),
            json!({"object_replication_time": 1.5})
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn merges_updates_into_the_existing_entry() {
        let dir = scratch_dir("merge");
        let cache_file = dir.join("object.recon");
        dump_recon_cache(&cache_file, &json!({"a": 1, "b": "old"})).unwrap();
        dump_recon_cache(&cache_file, &json!({"b": "new", "c": [1, 2]})).unwrap();
        assert_eq!(
            read_cache(&cache_file),
            json!({"a": 1, "b": "new", "c": [1, 2]})
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn null_and_empty_object_values_delete_keys() {
        let dir = scratch_dir("delete");
        let cache_file = dir.join("object.recon");
        dump_recon_cache(&cache_file, &json!({"a": 1, "b": 2, "c": 3})).unwrap();
        dump_recon_cache(&cache_file, &json!({"a": null, "b": {}})).unwrap();
        assert_eq!(read_cache(&cache_file), json!({"c": 3}));
        // Deleting a missing key is a no-op, as in Python's dict.pop(key, None).
        dump_recon_cache(&cache_file, &json!({"never-there": null})).unwrap();
        assert_eq!(read_cache(&cache_file), json!({"c": 3}));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn object_values_merge_one_level_deep() {
        let dir = scratch_dir("nested");
        let cache_file = dir.join("object.recon");
        dump_recon_cache(&cache_file, &json!({"stats": {"x": 1, "y": 2}, "plain": 5})).unwrap();
        dump_recon_cache(&cache_file, &json!({"stats": {"y": null, "z": 3}})).unwrap();
        assert_eq!(
            read_cache(&cache_file),
            json!({"plain": 5, "stats": {"x": 1, "z": 3}})
        );
        // A dict update over a non-dict value replaces it.
        dump_recon_cache(&cache_file, &json!({"plain": {"inner": true}})).unwrap();
        assert_eq!(
            read_cache(&cache_file),
            json!({"plain": {"inner": true}, "stats": {"x": 1, "z": 3}})
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_cache_files_are_recreated() {
        let dir = scratch_dir("corrupt");
        std::fs::create_dir_all(&dir).unwrap();
        let cache_file = dir.join("object.recon");
        for corrupt in ["not json at all\n", "[1, 2, 3]\n", ""] {
            std::fs::write(&cache_file, corrupt).unwrap();
            dump_recon_cache(&cache_file, &json!({"a": 1})).unwrap();
            assert_eq!(read_cache(&cache_file), json!({"a": 1}), "from {corrupt:?}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn non_object_updates_are_rejected() {
        let dir = scratch_dir("reject");
        let cache_file = dir.join("object.recon");
        let error = dump_recon_cache(&cache_file, &json!([1, 2])).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(!cache_file.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn output_is_a_single_sorted_json_line() {
        let dir = scratch_dir("sorted");
        let cache_file = dir.join("object.recon");
        dump_recon_cache(&cache_file, &json!({"zebra": 1, "apple": 2, "mango": 3})).unwrap();
        let contents = std::fs::read_to_string(&cache_file).unwrap();
        assert_eq!(contents, "{\"apple\":2,\"mango\":3,\"zebra\":1}\n");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
