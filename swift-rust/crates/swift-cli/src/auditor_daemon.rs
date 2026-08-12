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

//! Shared helpers for continuous auditor daemons (P2b).
//!
//! Pass implementations live in `swift-diskfile::audit_devices` and
//! `swift-db::audit_dbs_on_devices`. This module owns mode detection and
//! recon payload shapes used by the CLI binaries.

use std::path::Path;

/// True when `arg` should be treated as a conf path (daemon mode), not a
/// device directory (legacy one-shot).
pub fn looks_like_conf_arg(arg: &str) -> bool {
    let path = Path::new(arg);
    if path.is_dir() {
        return false;
    }
    if path.is_file() {
        return true;
    }
    arg.ends_with(".conf")
}

/// Recon cache payload for object auditor (seconds + tallies).
pub fn object_auditor_recon_update(
    elapsed_secs: f64,
    passed: u64,
    quarantined: u64,
    errors: u64,
    start_epoch_secs: f64,
) -> serde_json::Value {
    serde_json::json!({
        "object_auditor_stats_ALL": {
            "passes": passed,
            "errors": errors,
            "quarantined": quarantined,
            "audit_time": elapsed_secs,
            "start_time": start_epoch_secs,
        }
    })
}

/// Recon cache payload for account/container DB auditor.
pub fn db_auditor_recon_update(
    kind: &str,
    elapsed_secs: f64,
    passed: u64,
    failed: u64,
    end_epoch_secs: f64,
) -> serde_json::Value {
    let key_stats = format!("{kind}_auditor_stats");
    let key_time = format!("{kind}_auditor_pass_time");
    let key_last = format!("{kind}_auditor_last");
    serde_json::json!({
        key_stats: {
            "passes": passed,
            "failures": failed,
        },
        key_time: elapsed_secs,
        key_last: end_epoch_secs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn looks_like_conf_arg_distinguishes_dir_and_conf() {
        let dir =
            std::env::temp_dir().join(format!("swift-aud-mode-{}-{}", std::process::id(), line!()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert!(!looks_like_conf_arg(dir.to_str().unwrap()));
        assert!(looks_like_conf_arg("/etc/swift/object-server.conf"));
        assert!(looks_like_conf_arg("object-server.conf"));
        let conf = dir.join("x.conf");
        std::fs::write(&conf, "[DEFAULT]\n").unwrap();
        assert!(looks_like_conf_arg(conf.to_str().unwrap()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn recon_updates_carry_pass_keys() {
        let o = object_auditor_recon_update(1.5, 2, 0, 0, 100.0);
        assert_eq!(o["object_auditor_stats_ALL"]["passes"], 2);
        assert!(
            (o["object_auditor_stats_ALL"]["audit_time"]
                .as_f64()
                .unwrap()
                - 1.5)
                .abs()
                < 1e-9
        );

        let d = db_auditor_recon_update("account", 0.25, 3, 1, 200.0);
        assert_eq!(d["account_auditor_stats"]["failures"], 1);
        assert_eq!(d["account_auditor_last"], 200.0);
    }
}
