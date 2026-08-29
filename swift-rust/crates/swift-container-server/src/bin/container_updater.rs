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

//! `swift-container-updater <config.conf> [once]`: the container updater daemon.
//! Walks every container DB on every device and PUTs the container's
//! object/byte totals to its account replicas whenever the live stats have
//! moved past the `reported_*` copy, sweeping on an interval (or a single pass
//! with the `once` argument). Reads the ACCOUNT ring from SWIFT_DIR, because
//! the reports go to account servers.

use std::path::Path;

use swift_container_server::updater::{self, run_once, HttpAccountClient};
use swift_core::config::SwiftConfig;
use swift_core::daemon;
use swift_core::hashing::HashPathConfig;
use swift_core::obslog::{LogLevel, Logger};
use swift_core::statsd::StatsdClient;
use swift_ring::{Ring, RingData};

fn parse_conf_file(path: &str) -> Result<SwiftConfig, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|error| format!("could not read {path}: {error}"))?;
    SwiftConfig::parse_lenient(&content, &[], false)
        .map_err(|error| format!("could not parse {path}: {error}"))
}

fn main() {
    let conf_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/etc/swift/container-server.conf".to_string());
    let run_once_only = std::env::args().nth(2).as_deref() == Some("once");
    let conf = parse_conf_file(&conf_path).unwrap_or_else(|error| {
        eprintln!("{error}");
        std::process::exit(1);
    });
    let get = |section: &str, key: &str, default: &str| -> String {
        conf.get(section, key)
            .ok()
            .flatten()
            .or_else(|| conf.get("DEFAULT", key).ok().flatten())
            .unwrap_or_else(|| default.to_string())
    };
    let devices = get("app:container-server", "devices", "/srv/node");
    // Python parity: swift/container/updater.py defaults interval to 300 seconds.
    let interval: u64 = get("container-updater", "interval", "300")
        .parse()
        .unwrap_or(300);
    let log_name = get("container-updater", "log_name", "container-updater");
    let log_level = get("container-updater", "log_level", "INFO")
        .parse::<LogLevel>()
        .unwrap_or(LogLevel::Info);
    let logger = Logger::with_syslog(&log_name, log_level);
    let statsd = StatsdClient::new(
        &get("container-updater", "log_statsd_host", ""),
        get("container-updater", "log_statsd_port", "8125")
            .parse()
            .unwrap_or(8125),
        &daemon::statsd_prefix(
            &get("container-updater", "log_statsd_metric_prefix", ""),
            "container-updater",
        ),
    );
    let recon_cache_path = get("container-updater", "recon_cache_path", "/var/cache/swift");

    let swift_conf_path =
        std::env::var("SWIFT_CONF").unwrap_or_else(|_| "/etc/swift/swift.conf".to_string());
    let swift_conf = parse_conf_file(&swift_conf_path).unwrap_or_else(|error| {
        eprintln!("{error}");
        std::process::exit(1);
    });
    let hash_config = HashPathConfig::from_swift_conf(&swift_conf).unwrap_or_else(|e| {
        logger.error(&format!("bad swift.conf hash config: {e}"));
        std::process::exit(1);
    });
    let swift_dir = std::env::var("SWIFT_DIR").unwrap_or_else(|_| "/etc/swift".to_string());
    // The account ring: a container's stats are reported to its ACCOUNT's
    // replicas, not to container nodes.
    let ring_path = format!("{swift_dir}/account.ring.gz");
    // A missing ring at startup is fatal; per-pass reloads below fall back to
    // the previous ring.
    let mut account_ring = Ring::new(
        RingData::load(Path::new(&ring_path)).unwrap_or_else(|e| {
            logger.error(&format!("could not load {ring_path}: {e}"));
            std::process::exit(1);
        }),
        hash_config.clone(),
    );
    let client = HttpAccountClient;
    let stop = swift_http::install_sigterm_flag();

    logger.info(&format!(
        "swift-container-updater: devices={devices} interval={interval}s once={run_once_only}"
    ));
    loop {
        let sweep_start = std::time::Instant::now();
        let (mut ok, mut fail, mut no_change) = (0u64, 0, 0);
        if let Ok(entries) = std::fs::read_dir(&devices) {
            for e in entries.flatten() {
                if e.path().is_dir() {
                    let s = run_once(&e.path(), &account_ring, &client);
                    ok += s.successes;
                    fail += s.failures;
                    no_change += s.no_changes;
                }
            }
        }
        logger.info(&format!(
            "container-updater pass: successes={ok} failures={fail} no_changes={no_change}"
        ));
        statsd.update_stats("successes", ok as i64);
        statsd.update_stats("failures", fail as i64);
        statsd.update_stats("no_changes", no_change as i64);
        let update = updater::recon_update(sweep_start.elapsed(), daemon::epoch_secs_now());
        if let Err(e) = daemon::dump_recon(&recon_cache_path, "container.recon", &update) {
            logger.warning(&format!(
                "could not dump recon cache to {recon_cache_path}/container.recon: {e}"
            ));
        }
        if run_once_only {
            break;
        }
        if daemon::sleep_unless_stopped(interval, &stop) {
            logger.info("exiting on SIGTERM");
            break;
        }
        // Reload the account ring every pass; on failure keep the previous.
        match RingData::load(Path::new(&ring_path)) {
            Ok(data) => account_ring = Ring::new(data, hash_config.clone()),
            Err(e) => logger.warning(&format!(
                "could not reload {ring_path}: {e}; reusing previous ring"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_config_is_an_error() {
        let missing = std::env::temp_dir().join(format!(
            "swift-container-updater-missing-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&missing);
        let error = parse_conf_file(missing.to_str().unwrap()).unwrap_err();
        assert!(error.contains("could not read"), "{error}");
    }
}
