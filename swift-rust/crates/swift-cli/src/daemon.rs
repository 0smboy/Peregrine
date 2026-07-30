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

//! Shared plumbing for the CLI-hosted daemons (the account/container DB
//! replicator): SIGTERM-aware interval sleeps and Python-recon-compatible
//! cache dumps.

// The generic daemon plumbing now lives in one place; re-exported so this
// crate's binaries keep their familiar `daemonutil::` / `daemon::` spelling.
pub use swift_core::daemon::{dump_recon, epoch_secs_now, sleep_unless_stopped, statsd_prefix};

/// The recon-cache update the Python account/container DB replicator dumps
/// after a pass (`swift/common/db_replicator.py _report_stats`):
/// `replication_time` is the pass duration in SECONDS, `replication_last` the
/// pass end as epoch seconds, and `replication_stats` the `_zero_stats()`
/// dict shape. Counters the Rust replicator does not track are zero.
pub fn db_replicator_recon_update(
    attempted: u64,
    successes: u64,
    failures: u64,
    start_epoch_secs: f64,
    end_epoch_secs: f64,
) -> serde_json::Value {
    serde_json::json!({
        "replication_stats": {
            "attempted": attempted,
            "success": successes,
            "failure": failures,
            "diff": 0,
            "diff_capped": 0,
            "empty": 0,
            "hashmatch": 0,
            "no_change": 0,
            "remote_merge": 0,
            "remove": 0,
            "rsync": 0,
            "ts_repl": 0,
            "deferred": 0,
            "start": start_epoch_secs,
            "failure_nodes": {},
        },
        "replication_time": end_epoch_secs - start_epoch_secs,
        "replication_last": end_epoch_secs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use std::time::Duration;
    use std::time::Instant;

    #[test]
    fn sleep_unless_stopped_returns_immediately_when_flag_is_set() {
        let stop = AtomicBool::new(true);
        let start = Instant::now();
        assert!(sleep_unless_stopped(3600, &stop));
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn sleep_unless_stopped_completes_a_zero_interval_without_stop() {
        let stop = AtomicBool::new(false);
        assert!(!sleep_unless_stopped(0, &stop));
    }

    #[test]
    fn statsd_prefix_prepends_only_when_configured() {
        assert_eq!(
            statsd_prefix("", "container-replicator"),
            "container-replicator"
        );
        assert_eq!(
            statsd_prefix("node1", "account-replicator"),
            "node1.account-replicator"
        );
    }

    #[test]
    fn db_replicator_recon_update_dumps_python_recon_keys() {
        let update = db_replicator_recon_update(5, 4, 1, 1_700_000_000.0, 1_700_000_012.5);
        let obj = update.as_object().unwrap();
        for key in ["replication_stats", "replication_time", "replication_last"] {
            assert!(obj.contains_key(key), "missing {key}");
        }
        // replication_time is seconds for the DB replicators
        assert!((update["replication_time"].as_f64().unwrap() - 12.5).abs() < 1e-9);
        assert_eq!(
            update["replication_last"].as_f64().unwrap(),
            1_700_000_012.5
        );
        let stats = update["replication_stats"].as_object().unwrap();
        for key in [
            "attempted",
            "success",
            "failure",
            "diff",
            "diff_capped",
            "empty",
            "hashmatch",
            "no_change",
            "remote_merge",
            "remove",
            "rsync",
            "ts_repl",
            "start",
            "failure_nodes",
        ] {
            assert!(stats.contains_key(key), "missing replication_stats.{key}");
        }
        assert_eq!(update["replication_stats"]["attempted"], 5);
        assert_eq!(update["replication_stats"]["success"], 4);
        assert_eq!(update["replication_stats"]["failure"], 1);

        // round-trip through the dump helper into a temp cache path
        let dir = std::env::temp_dir().join(format!(
            "swift-cli-daemon-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let cache_path = dir.join("cache");
        dump_recon(cache_path.to_str().unwrap(), "container.recon", &update).unwrap();
        let read: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(cache_path.join("container.recon")).unwrap(),
        )
        .unwrap();
        assert!(read.get("replication_stats").is_some());
        assert!(read.get("replication_time").is_some());
        assert!(read.get("replication_last").is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
