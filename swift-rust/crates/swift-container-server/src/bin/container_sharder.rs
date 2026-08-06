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

//! `swift-container-sharder <config.conf> [once]`: cleave SHARDING containers;
//! when `auto_shard=true`, also transition oversized unsharded containers.
//! See `sharder.rs` module docs for residuals vs full Python L3b.

use swift_container_server::sharder::{self, run_once_with_opts, SharderRunOpts};
use swift_core::daemon;
use swift_core::config::SwiftConfig;
use swift_core::hashing::HashPathConfig;
use swift_core::obslog::{LogLevel, Logger};
use swift_core::statsd::StatsdClient;

fn parse_conf_file(path: &str) -> SwiftConfig {
    let content = std::fs::read_to_string(path).unwrap_or_default();
    SwiftConfig::parse_lenient(&content, &[], false).unwrap_or_else(|e| {
        eprintln!("could not parse {path}: {e}");
        std::process::exit(1);
    })
}

fn main() {
    let conf_path =
        std::env::args().nth(1).unwrap_or_else(|| "/etc/swift/container-server.conf".to_string());
    let run_once_only = std::env::args().nth(2).as_deref() == Some("once");
    let conf = parse_conf_file(&conf_path);
    let get = |section: &str, key: &str, default: &str| -> String {
        conf.get(section, key)
            .ok()
            .flatten()
            .or_else(|| conf.get("DEFAULT", key).ok().flatten())
            .unwrap_or_else(|| default.to_string())
    };
    let devices = get("app:container-server", "devices", "/srv/node");
    // Python container/sharder.py defaults interval to 30s.
    let interval: u64 = get("container-sharder", "interval", "30").parse().unwrap_or(30);
    let cleave_batch_size: usize = get("container-sharder", "cleave_batch_size", "2")
        .parse()
        .unwrap_or(2);
    let auto_shard = matches!(
        get("container-sharder", "auto_shard", "false")
            .to_lowercase()
            .as_str(),
        "true" | "1" | "yes" | "on" | "t" | "y"
    );
    let shard_size: i64 = get("container-sharder", "shard_container_threshold", "1000000")
        .parse()
        .unwrap_or(1_000_000);
    let minimum_shard_size: i64 = get("container-sharder", "minimum_shard_size", "100000")
        .parse()
        .unwrap_or(100_000);
    let log_name = get("container-sharder", "log_name", "container-sharder");
    let log_level = get("container-sharder", "log_level", "INFO")
        .parse::<LogLevel>()
        .unwrap_or(LogLevel::Info);
    let logger = Logger::with_syslog(&log_name, log_level);
    let statsd = StatsdClient::new(
        &get("container-sharder", "log_statsd_host", ""),
        get("container-sharder", "log_statsd_port", "8125")
            .parse()
            .unwrap_or(8125),
        &daemon::statsd_prefix(
            &get("container-sharder", "log_statsd_metric_prefix", ""),
            "container-sharder",
        ),
    );
    let recon_cache_path = get("container-sharder", "recon_cache_path", "/var/cache/swift");

    let swift_conf_path =
        std::env::var("SWIFT_CONF").unwrap_or_else(|_| "/etc/swift/swift.conf".to_string());
    let swift_conf = parse_conf_file(&swift_conf_path);
    let hash_config = HashPathConfig::from_swift_conf(&swift_conf).unwrap_or_else(|e| {
        logger.error(&format!("bad swift.conf hash config: {e}"));
        std::process::exit(1);
    });
    let opts = SharderRunOpts {
        cleave_batch_size,
        auto_shard,
        shard_size,
        minimum_shard_size,
    };
    let stop = swift_http::install_sigterm_flag();

    logger.info(&format!(
        "swift-container-sharder: devices={devices} interval={interval}s \
         cleave_batch_size={cleave_batch_size} auto_shard={auto_shard} \
         shard_size={shard_size} once={run_once_only} \
         mode=wave3-local-cleave+auto_shard-gate"
    ));
    loop {
        let sweep_start = std::time::Instant::now();
        let mut agg = sharder::SharderStats::default();
        if let Ok(entries) = std::fs::read_dir(&devices) {
            for e in entries.flatten() {
                if e.path().is_dir() {
                    let s = run_once_with_opts(&e.path(), &hash_config, &opts);
                    agg.containers_seen += s.containers_seen;
                    agg.sharding += s.sharding;
                    agg.cleaved_batches += s.cleaved_batches;
                    agg.finished += s.finished;
                    agg.skipped += s.skipped;
                    agg.failures += s.failures;
                }
            }
        }
        logger.info(&format!(
            "container-sharder pass: seen={} sharding={} cleaved_batches={} \
             finished={} skipped={} failures={}",
            agg.containers_seen,
            agg.sharding,
            agg.cleaved_batches,
            agg.finished,
            agg.skipped,
            agg.failures
        ));
        statsd.update_stats("containers_seen", agg.containers_seen as i64);
        statsd.update_stats("sharding", agg.sharding as i64);
        statsd.update_stats("finished", agg.finished as i64);
        statsd.update_stats("failures", agg.failures as i64);
        let update = sharder::recon_update(sweep_start.elapsed(), daemon::epoch_secs_now(), &agg);
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
    }
}
