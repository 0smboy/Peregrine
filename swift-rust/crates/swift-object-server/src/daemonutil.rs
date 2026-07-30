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

//! Shared plumbing for the object daemon binaries (replicator/updater):
//! SIGTERM-aware interval sleeps and Python-recon-compatible cache dumps.

// The generic daemon plumbing now lives in one place; re-exported so this
// crate's binaries keep their familiar `daemonutil::` / `daemon::` spelling.
pub use swift_core::daemon::{dump_recon, epoch_secs_now, sleep_unless_stopped, statsd_prefix};

use std::time::Duration;

use crate::replicator::ReplicatorStats;

/// The recon-cache update the Python object replicator dumps after a pass
/// (`swift/obj/replicator.py update_recon`): `replication_time` /
/// `object_replication_time` are the pass duration in MINUTES,
/// `replication_last` / `object_replication_last` the pass end as epoch
/// seconds, and `replication_stats` a `Stats.to_recon()`-shaped object.
/// Counters the Rust replicator does not track are reported as zero.
pub fn replicator_recon_update(
    stats: &ReplicatorStats,
    elapsed: Duration,
    end_epoch_secs: f64,
) -> serde_json::Value {
    let minutes = elapsed.as_secs_f64() / 60.0;
    serde_json::json!({
        "replication_stats": {
            "attempted": stats.partitions,
            "failure": stats.failures,
            "hashmatch": 0,
            "remove": stats.reverts,
            "rsync": stats.suffix_syncs,
            "success": stats.partitions.saturating_sub(stats.failures),
            "suffix_count": 0,
            "suffix_hash": 0,
            "suffix_sync": stats.suffix_syncs,
            "failure_nodes": {},
        },
        "replication_time": minutes,
        "replication_last": end_epoch_secs,
        "object_replication_time": minutes,
        "object_replication_last": end_epoch_secs,
    })
}

/// The recon-cache update the Python object updater dumps after a sweep
/// (`swift/obj/updater.py aggregate_and_dump_recon`, the keys `swift-recon`
/// reads): the sweep duration in seconds and the sweep end as epoch seconds.
pub fn updater_recon_update(elapsed: Duration, end_epoch_secs: f64) -> serde_json::Value {
    serde_json::json!({
        "object_updater_sweep": elapsed.as_secs_f64(),
        "object_updater_last": end_epoch_secs,
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
        assert_eq!(statsd_prefix("", "object-replicator"), "object-replicator");
        assert_eq!(
            statsd_prefix("node1", "object-replicator"),
            "node1.object-replicator"
        );
    }

    #[test]
    fn replicator_recon_update_has_python_recon_keys() {
        let stats = ReplicatorStats {
            partitions: 4,
            suffix_syncs: 3,
            reverts: 2,
            failures: 1,
        };
        let update = replicator_recon_update(&stats, Duration::from_secs(90), 1_700_000_000.0);
        let obj = update.as_object().unwrap();
        for key in [
            "replication_stats",
            "replication_time",
            "replication_last",
            "object_replication_time",
            "object_replication_last",
        ] {
            assert!(obj.contains_key(key), "missing {key}");
        }
        // durations are minutes, timestamps epoch seconds
        assert!((update["object_replication_time"].as_f64().unwrap() - 1.5).abs() < 1e-9);
        assert!((update["replication_time"].as_f64().unwrap() - 1.5).abs() < 1e-9);
        assert_eq!(
            update["object_replication_last"].as_f64().unwrap(),
            1_700_000_000.0
        );
        let stats_obj = update["replication_stats"].as_object().unwrap();
        for key in [
            "attempted",
            "failure",
            "hashmatch",
            "remove",
            "rsync",
            "success",
            "suffix_count",
            "suffix_hash",
            "suffix_sync",
            "failure_nodes",
        ] {
            assert!(stats_obj.contains_key(key), "missing replication_stats.{key}");
        }
        assert_eq!(update["replication_stats"]["attempted"], 4);
        assert_eq!(update["replication_stats"]["failure"], 1);
        assert_eq!(update["replication_stats"]["remove"], 2);
        assert_eq!(update["replication_stats"]["suffix_sync"], 3);
    }

    #[test]
    fn updater_recon_update_dumps_python_recon_keys() {
        let update = updater_recon_update(Duration::from_secs(7), 1_700_000_100.0);
        assert_eq!(update["object_updater_sweep"].as_f64().unwrap(), 7.0);
        assert_eq!(update["object_updater_last"].as_f64().unwrap(), 1_700_000_100.0);

        // round-trip through the dump helper into a temp cache path
        let dir = std::env::temp_dir().join(format!(
            "swift-obj-daemonutil-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let cache_path = dir.join("cache");
        dump_recon(cache_path.to_str().unwrap(), "object.recon", &update).unwrap();
        let read: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(cache_path.join("object.recon")).unwrap(),
        )
        .unwrap();
        assert!(read.get("object_updater_sweep").is_some());
        assert!(read.get("object_updater_last").is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
