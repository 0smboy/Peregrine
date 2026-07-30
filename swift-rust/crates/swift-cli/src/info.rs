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

//! `swift-container-info` / `swift-account-info` / `swift-object-info`,
//! ported from `swift/cli/info.py`'s `print_db_info_metadata` and
//! `print_obj_metadata`.

use std::path::Path;

use swift_db::{AccountBroker, ContainerBroker, DbValue};
use swift_diskfile::{read_metadata, MetaValue};

fn v(row: &[(String, DbValue)], key: &str) -> String {
    row.iter()
        .find(|(k, _)| k == key)
        .map(|(_, val)| match val {
            DbValue::Text(s) => s.clone(),
            DbValue::Int(i) => i.to_string(),
            DbValue::Null => String::new(),
        })
        .unwrap_or_default()
}

/// Render `swift-container-info` for a container `.db`.
pub fn container_info(db_file: &Path) -> Result<String, String> {
    let mut broker = ContainerBroker::new(db_file, "", "");
    let info = broker.get_info().map_err(|e| e.to_string())?;
    let deleted = broker.is_deleted().map_err(|e| e.to_string())?;
    let mut out = String::new();
    let account = v(&info, "account");
    let container = v(&info, "container");
    out.push_str(&format!("Path: /{account}/{container}\n"));
    out.push_str(&format!("  Account: {account}\n"));
    out.push_str(&format!("  Container: {container}\n"));
    out.push_str(&format!("  Deleted: {deleted}\n"));
    out.push_str(&format!(
        "  Object Count: {}\n",
        v(&info, "object_count")
    ));
    out.push_str(&format!("  Bytes Used: {}\n", v(&info, "bytes_used")));
    out.push_str(&format!(
        "  Storage Policy Index: {}\n",
        v(&info, "storage_policy_index")
    ));
    out.push_str(&format!("  Put Timestamp: {}\n", v(&info, "put_timestamp")));
    out.push_str(&format!(
        "  Delete Timestamp: {}\n",
        v(&info, "delete_timestamp")
    ));
    out.push_str(&format!("  Hash: {}\n", v(&info, "hash")));
    out.push_str(&format!("  ID: {}\n", v(&info, "id")));
    push_metadata(&mut out, &broker.metadata().map_err(|e| e.to_string())?);
    Ok(out)
}

/// Render `swift-account-info` for an account `.db`.
pub fn account_info(db_file: &Path) -> Result<String, String> {
    let mut broker = AccountBroker::new(db_file, "");
    let info = broker.get_info().map_err(|e| e.to_string())?;
    let deleted = broker.is_deleted().map_err(|e| e.to_string())?;
    let mut out = String::new();
    let account = v(&info, "account");
    out.push_str(&format!("Path: /{account}\n"));
    out.push_str(&format!("  Account: {account}\n"));
    out.push_str(&format!("  Deleted: {deleted}\n"));
    out.push_str(&format!(
        "  Container Count: {}\n",
        v(&info, "container_count")
    ));
    out.push_str(&format!(
        "  Object Count: {}\n",
        v(&info, "object_count")
    ));
    out.push_str(&format!("  Bytes Used: {}\n", v(&info, "bytes_used")));
    out.push_str(&format!("  Put Timestamp: {}\n", v(&info, "put_timestamp")));
    out.push_str(&format!("  Hash: {}\n", v(&info, "hash")));
    out.push_str(&format!("  ID: {}\n", v(&info, "id")));
    push_metadata(&mut out, &broker.metadata().map_err(|e| e.to_string())?);
    Ok(out)
}

fn push_metadata(out: &mut String, md: &swift_db::BrokerMetadata) {
    let mut user = Vec::new();
    let mut sys = Vec::new();
    for (key, (value, _ts)) in md {
        if value.is_empty() {
            continue;
        }
        let lower = key.to_lowercase();
        if lower.contains("-meta-") {
            user.push((key.clone(), value.clone()));
        } else if lower.contains("-sysmeta-") {
            sys.push((key.clone(), value.clone()));
        }
    }
    out.push_str("  User Metadata:\n");
    for (k, val) in &user {
        out.push_str(&format!("    {k}: {val}\n"));
    }
    out.push_str("  System Metadata:\n");
    for (k, val) in &sys {
        out.push_str(&format!("    {k}: {val}\n"));
    }
}

/// Render `swift-object-info` for a `.data`/`.meta`/`.ts` file's xattr
/// metadata.
pub fn object_info(data_file: &Path) -> Result<String, String> {
    let meta = read_metadata(data_file).map_err(|e| e.to_string())?;
    let get = |key: &str| -> Option<String> {
        meta.iter()
            .find(|(k, _)| matches!(k, MetaValue::Str(s) if s.eq_ignore_ascii_case(key)))
            .and_then(|(_, val)| match val {
                MetaValue::Str(s) => Some(s.clone()),
                MetaValue::Int(i) => Some(i.to_string()),
                MetaValue::Bytes(_) => None,
            })
    };
    let mut out = String::new();
    if let Some(name) = get("name") {
        out.push_str(&format!("Path: {name}\n"));
    }
    out.push_str(&format!(
        "Content-Type: {}\n",
        get("Content-Type").unwrap_or_default()
    ));
    out.push_str(&format!(
        "Timestamp: {}\n",
        get("X-Timestamp").unwrap_or_default()
    ));
    out.push_str(&format!(
        "Content-Length: {}\n",
        get("Content-Length").unwrap_or_default()
    ));
    out.push_str(&format!("ETag: {}\n", get("ETag").unwrap_or_default()));
    out.push_str("Metadata:\n");
    for (k, val) in &meta {
        if let (MetaValue::Str(key), value) = (k, val) {
            let lower = key.to_lowercase();
            if lower.starts_with("x-object-meta-") || lower.starts_with("x-object-sysmeta-") {
                let vs = match value {
                    MetaValue::Str(s) => s.clone(),
                    MetaValue::Int(i) => i.to_string(),
                    MetaValue::Bytes(_) => "<binary>".to_string(),
                };
                out.push_str(&format!("  {key}: {vs}\n"));
            }
        }
    }
    Ok(out)
}


#[cfg(test)]
mod tests {
    use super::*;
    use swift_db::ContainerBroker;

    #[test]
    fn test_container_info_renders() {
        let dir = std::env::temp_dir().join(format!("swift-cli-info-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("c.db");
        let mut b = ContainerBroker::new(&db, "AUTH_x", "box");
        b.initialize("1751500000.00000", 0, "1751500000.00000", "id-1").unwrap();
        b.put_object("o1", "1751500001.00000", 5, "text/plain", "e", 0, 0, None, None)
            .unwrap();
        b.update_metadata(&vec![(
            "X-Container-Meta-Color".to_string(),
            ("blue".to_string(), "1751500001.00000".to_string()),
        )])
        .unwrap();
        b.get_info().unwrap();
        let out = container_info(&db).unwrap();
        assert!(out.contains("Path: /AUTH_x/box"), "{out}");
        assert!(out.contains("Object Count: 1"), "{out}");
        assert!(out.contains("X-Container-Meta-Color: blue"), "{out}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
