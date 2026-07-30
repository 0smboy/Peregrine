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

//! `swift-object-updater <config.conf> [once]`: the object updater daemon.
//! Replays `async_pending` container updates that a PUT/DELETE couldn't deliver
//! synchronously, sweeping every device on an interval (or a single pass with
//! the `once` argument). Reads the container ring from SWIFT_DIR.

use std::path::Path;

use swift_core::config::SwiftConfig;
use swift_core::hashing::HashPathConfig;
use swift_core::obslog::{LogLevel, Logger};
use swift_core::statsd::StatsdClient;
use swift_object_server::daemonutil;
use swift_object_server::updater::{run_once, HttpContainerClient};
use swift_ring::{Ring, RingData};

fn parse_conf_file(path: &str) -> SwiftConfig {
    let content = std::fs::read_to_string(path).unwrap_or_default();
    SwiftConfig::parse_lenient(&content, &[], false).unwrap_or_else(|e| {
        eprintln!("could not parse {path}: {e}");
        std::process::exit(1);
    })
}

fn main() {
    let conf_path =
        std::env::args().nth(1).unwrap_or_else(|| "/etc/swift/object-server.conf".to_string());
    let run_once_only = std::env::args().nth(2).as_deref() == Some("once");
    let conf = parse_conf_file(&conf_path);
    let get = |section: &str, key: &str, default: &str| -> String {
        conf.get(section, key)
            .ok()
            .flatten()
            .or_else(|| conf.get("DEFAULT", key).ok().flatten())
            .unwrap_or_else(|| default.to_string())
    };
    let devices = get("app:object-server", "devices", "/srv/node");
    // Python parity: swift/obj/updater.py defaults interval to 300 seconds.
    let interval: u64 = get("object-updater", "interval", "300").parse().unwrap_or(300);
    let log_name = get("object-updater", "log_name", "object-updater");
    let log_level = get("object-updater", "log_level", "INFO")
        .parse::<LogLevel>()
        .unwrap_or(LogLevel::Info);
    let logger = Logger::with_syslog(&log_name, log_level);
    let statsd = StatsdClient::new(
        &get("object-updater", "log_statsd_host", ""),
        get("object-updater", "log_statsd_port", "8125")
            .parse()
            .unwrap_or(8125),
        &daemonutil::statsd_prefix(
            &get("object-updater", "log_statsd_metric_prefix", ""),
            "object-updater",
        ),
    );
    let recon_cache_path = get("object-updater", "recon_cache_path", "/var/cache/swift");

    let swift_conf_path =
        std::env::var("SWIFT_CONF").unwrap_or_else(|_| "/etc/swift/swift.conf".to_string());
    let swift_conf = parse_conf_file(&swift_conf_path);
    let hash_config = HashPathConfig::from_swift_conf(&swift_conf).unwrap_or_else(|e| {
        logger.error(&format!("bad swift.conf hash config: {e}"));
        std::process::exit(1);
    });
    let swift_dir = std::env::var("SWIFT_DIR").unwrap_or_else(|_| "/etc/swift".to_string());
    let ring_path = format!("{swift_dir}/container.ring.gz");
    // A missing ring at startup is fatal; per-pass reloads below fall back to
    // the previous ring.
    let mut container_ring = Ring::new(
        RingData::load(Path::new(&ring_path)).unwrap_or_else(|e| {
            logger.error(&format!("could not load {ring_path}: {e}"));
            std::process::exit(1);
        }),
        hash_config.clone(),
    );
    let client = HttpContainerClient;
    let stop = swift_http::install_sigterm_flag();

    logger.info(&format!(
        "swift-object-updater: devices={devices} interval={interval}s once={run_once_only}"
    ));
    loop {
        let sweep_start = std::time::Instant::now();
        let (mut ok, mut fail, mut unlink, mut errors, mut redirects) = (0u64, 0, 0, 0, 0);
        if let Ok(entries) = std::fs::read_dir(&devices) {
            for e in entries.flatten() {
                if e.path().is_dir() {
                    let s = run_once(&e.path(), &container_ring, &client);
                    ok += s.successes;
                    fail += s.failures;
                    unlink += s.unlinks + s.outdated_unlinks;
                    errors += s.errors;
                    redirects += s.redirects;
                }
            }
        }
        logger.info(&format!(
            "object-updater pass: successes={ok} failures={fail} unlinks={unlink} \
             errors={errors} redirects={redirects}"
        ));
        statsd.update_stats("successes", ok as i64);
        statsd.update_stats("failures", fail as i64);
        statsd.update_stats("unlinks", unlink as i64);
        let update = daemonutil::updater_recon_update(
            sweep_start.elapsed(),
            daemonutil::epoch_secs_now(),
        );
        if let Err(e) = daemonutil::dump_recon(&recon_cache_path, "object.recon", &update) {
            logger.warning(&format!(
                "could not dump recon cache to {recon_cache_path}/object.recon: {e}"
            ));
        }
        if run_once_only {
            break;
        }
        if daemonutil::sleep_unless_stopped(interval, &stop) {
            logger.info("exiting on SIGTERM");
            break;
        }
        // Reload the container ring every pass; on failure keep the previous.
        match RingData::load(Path::new(&ring_path)) {
            Ok(data) => container_ring = Ring::new(data, hash_config.clone()),
            Err(e) => logger.warning(&format!(
                "could not reload {ring_path}: {e}; reusing previous ring"
            )),
        }
    }
}
