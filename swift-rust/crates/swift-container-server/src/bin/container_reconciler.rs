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

//! `swift-container-reconciler <config.conf> [once]`: drain the
//! `.misplaced_objects` queue, moving objects to the container's current
//! storage policy. Reads account/container/object rings from SWIFT_DIR.

use std::path::Path;

use swift_container_server::reconciler::{recon_update, run_once};
use swift_core::daemon;
use swift_core::config::SwiftConfig;
use swift_core::hashing::HashPathConfig;
use swift_core::obslog::{LogLevel, Logger};
use swift_core::statsd::StatsdClient;
use swift_ring::{Ring, RingData};

fn parse_conf_file(path: &str) -> SwiftConfig {
    let content = std::fs::read_to_string(path).unwrap_or_default();
    SwiftConfig::parse_lenient(&content, &[], false).unwrap_or_else(|e| {
        eprintln!("could not parse {path}: {e}");
        std::process::exit(1);
    })
}

fn load_ring(path: &str, hash_config: &HashPathConfig, logger: &Logger) -> Ring {
    Ring::new(
        RingData::load(Path::new(path)).unwrap_or_else(|e| {
            logger.error(&format!("could not load {path}: {e}"));
            std::process::exit(1);
        }),
        hash_config.clone(),
    )
}

fn main() {
    let conf_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/etc/swift/container-reconciler.conf".to_string());
    let conf_path = if Path::new(&conf_path).exists() {
        conf_path
    } else {
        "/etc/swift/container-server.conf".to_string()
    };
    let run_once_only = std::env::args().nth(2).as_deref() == Some("once");
    let conf = parse_conf_file(&conf_path);
    let get = |section: &str, key: &str, default: &str| -> String {
        conf.get(section, key)
            .ok()
            .flatten()
            .or_else(|| conf.get("DEFAULT", key).ok().flatten())
            .unwrap_or_else(|| default.to_string())
    };
    let interval: u64 = get("container-reconciler", "interval", "30")
        .parse()
        .unwrap_or(30);
    let log_name = get("container-reconciler", "log_name", "container-reconciler");
    let log_level = get("container-reconciler", "log_level", "INFO")
        .parse::<LogLevel>()
        .unwrap_or(LogLevel::Info);
    let logger = Logger::with_syslog(&log_name, log_level);
    let statsd = StatsdClient::new(
        &get("container-reconciler", "log_statsd_host", ""),
        get("container-reconciler", "log_statsd_port", "8125")
            .parse()
            .unwrap_or(8125),
        &daemon::statsd_prefix(
            &get("container-reconciler", "log_statsd_metric_prefix", ""),
            "container-reconciler",
        ),
    );
    let recon_cache_path = get("container-reconciler", "recon_cache_path", "/var/cache/swift");

    let swift_conf_path =
        std::env::var("SWIFT_CONF").unwrap_or_else(|_| "/etc/swift/swift.conf".to_string());
    let swift_conf = parse_conf_file(&swift_conf_path);
    let hash_config = HashPathConfig::from_swift_conf(&swift_conf).unwrap_or_else(|e| {
        logger.error(&format!("bad swift.conf hash config: {e}"));
        std::process::exit(1);
    });
    let swift_dir = std::env::var("SWIFT_DIR").unwrap_or_else(|_| "/etc/swift".to_string());
    let account_ring_path = format!("{swift_dir}/account.ring.gz");
    let container_ring_path = format!("{swift_dir}/container.ring.gz");
    let object_ring_path = format!("{swift_dir}/object.ring.gz");
    let mut account_ring = load_ring(&account_ring_path, &hash_config, &logger);
    let mut container_ring = load_ring(&container_ring_path, &hash_config, &logger);
    let mut object_ring = load_ring(&object_ring_path, &hash_config, &logger);
    let stop = swift_http::install_sigterm_flag();

    logger.info(&format!(
        "swift-container-reconciler: interval={interval}s once={run_once_only}"
    ));
    loop {
        let sweep_start = std::time::Instant::now();
        let stats = run_once(&account_ring, &container_ring, &object_ring);
        logger.info(&format!(
            "container-reconciler pass: moved={} already_correct={} failed={} errors={}",
            stats.moved, stats.already_correct, stats.failed, stats.errors
        ));
        statsd.update_stats("moved", stats.moved as i64);
        statsd.update_stats("failed", stats.failed as i64);
        let update = recon_update(sweep_start.elapsed(), &stats);
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
        for (path, ring) in [
            (&account_ring_path, &mut account_ring),
            (&container_ring_path, &mut container_ring),
            (&object_ring_path, &mut object_ring),
        ] {
            match RingData::load(Path::new(path)) {
                Ok(data) => *ring = Ring::new(data, hash_config.clone()),
                Err(e) => logger.warning(&format!(
                    "could not reload {path}: {e}; reusing previous ring"
                )),
            }
        }
    }
}
