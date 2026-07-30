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

//! Plumbing every background daemon needs: a SIGTERM-aware interval sleep, the
//! statsd prefix Python's `get_logger` computes, wall-clock epoch seconds, and
//! a recon-cache dump.
//!
//! These live here rather than beside any one daemon because all of them are
//! policy-free and every daemon crate already depends on `swift-core`. They had
//! been copied into `swift-cli` and `swift-object-server`, and a third copy was
//! about to land in `swift-container-server` — at which point a fix to one
//! would silently miss the others.
//!
//! What stays with each daemon is the *shape of its recon update*, since that
//! is a statement about the counters that daemon keeps.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde_json::Value;

/// Sleep for `secs` seconds in one-second slices, returning early as soon as
/// `stop` is set. Returns whether `stop` was set by the time the sleep ended,
/// so a daemon loop can `break` and shut down promptly on SIGTERM instead of
/// finishing a full interval.
pub fn sleep_unless_stopped(secs: u64, stop: &AtomicBool) -> bool {
    for _ in 0..secs {
        if stop.load(Ordering::Relaxed) {
            return true;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    stop.load(Ordering::Relaxed)
}

/// The statsd metric prefix Python's `get_logger` computes:
/// `log_statsd_metric_prefix` prepended to the daemon name when configured,
/// else the daemon name alone.
pub fn statsd_prefix(metric_prefix: &str, name: &str) -> String {
    if metric_prefix.is_empty() {
        name.to_string()
    } else {
        format!("{metric_prefix}.{name}")
    }
}

/// Current wall-clock time as float epoch seconds (Python `time.time()`).
pub fn epoch_secs_now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Merge a recon update into `<recon_cache_path>/<file>` (Python
/// `dump_recon_cache`). Callers log a failure and keep running: a broken recon
/// cache must never kill a daemon.
pub fn dump_recon(recon_cache_path: &str, file: &str, update: &Value) -> std::io::Result<()> {
    crate::recon::dump_recon_cache(&Path::new(recon_cache_path).join(file), update)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn sleep_returns_immediately_when_already_stopped() {
        let stop = AtomicBool::new(true);
        let started = Instant::now();
        assert!(sleep_unless_stopped(30, &stop));
        assert!(started.elapsed() < Duration::from_secs(1), "did not wait out the interval");
    }

    #[test]
    fn sleep_reports_a_clean_interval() {
        let stop = AtomicBool::new(false);
        assert!(!sleep_unless_stopped(0, &stop));
    }

    #[test]
    fn statsd_prefix_matches_python_get_logger() {
        assert_eq!(statsd_prefix("", "container-updater"), "container-updater");
        assert_eq!(statsd_prefix("swift", "container-updater"), "swift.container-updater");
    }

    #[test]
    fn dump_recon_merges_rather_than_replaces() {
        let dir = std::env::temp_dir().join(format!("swift-core-daemon-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.to_str().unwrap();
        dump_recon(path, "x.recon", &serde_json::json!({"a": 1})).unwrap();
        dump_recon(path, "x.recon", &serde_json::json!({"b": 2})).unwrap();
        let read: Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("x.recon")).unwrap()).unwrap();
        assert_eq!(read["a"], 1, "the earlier key survived the second dump");
        assert_eq!(read["b"], 2);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
