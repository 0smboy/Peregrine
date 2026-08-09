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
//! When `container.ring.gz` loads, uncleaved shard containers are HTTP-created
//! on ring primaries (quorum) before local cleave. See `sharder.rs` module docs
//! for claimable path vs Contabo KEEP residuals.

use std::path::Path;

use swift_container_server::sharder::{self, run_once_with_opts_and_ring, SharderRunOpts};
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
    let auto_shrink = matches!(
        get("container-sharder", "auto_shrink", "false")
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
        auto_shrink,
        shard_size,
        minimum_shard_size,
    };
    let swift_dir = std::env::var("SWIFT_DIR").unwrap_or_else(|_| "/etc/swift".to_string());
    let ring_path = format!("{swift_dir}/container.ring.gz");
    // Optional ring: missing → local SAIO path (LocalShardReplicator). Present →
    // LookupHttpShardReplicator creates uncleaved shards on ring primaries.
    let mut container_ring: Option<Ring> = match RingData::load(Path::new(&ring_path)) {
        Ok(data) => {
            logger.info(&format!("loaded container ring {ring_path}"));
            Some(Ring::new(data, hash_config.clone()))
        }
        Err(e) => {
            logger.warning(&format!(
                "no container ring at {ring_path} ({e}); multi-node shard create disabled \
                 (local cleave only — SAIO-safe)"
            ));
            None
        }
    };
    let stop = swift_http::install_sigterm_flag();

    let mode = if container_ring.is_some() {
        "ring-primaries+local-cleave"
    } else {
        "local-cleave-only"
    };
    logger.info(&format!(
        "swift-container-sharder: devices={devices} interval={interval}s \
         cleave_batch_size={cleave_batch_size} auto_shard={auto_shard} \
         auto_shrink={auto_shrink} \
         shard_size={shard_size} once={run_once_only} mode={mode} \
         (no Contabo KEEP claim without live quorum evidence)"
    ));
    loop {
        let sweep_start = std::time::Instant::now();
        let mut agg = sharder::SharderStats::default();
        if let Ok(entries) = std::fs::read_dir(&devices) {
            for e in entries.flatten() {
                if e.path().is_dir() {
                    let s = run_once_with_opts_and_ring(
                        &e.path(),
                        &hash_config,
                        &opts,
                        container_ring.as_ref(),
                    );
                    agg.containers_seen += s.containers_seen;
                    agg.sharding += s.sharding;
                    agg.cleaved_batches += s.cleaved_batches;
                    agg.finished += s.finished;
                    agg.skipped += s.skipped;
                    agg.failures += s.failures;
                    agg.replicate_errors += s.replicate_errors;
                    agg.shrinking_donors += s.shrinking_donors;
                }
            }
        }
        logger.info(&format!(
            "container-sharder pass: seen={} sharding={} cleaved_batches={} \
             finished={} skipped={} failures={} replicate_errors={} shrinking_donors={}",
            agg.containers_seen,
            agg.sharding,
            agg.cleaved_batches,
            agg.finished,
            agg.skipped,
            agg.failures,
            agg.replicate_errors,
            agg.shrinking_donors
        ));
        statsd.update_stats("containers_seen", agg.containers_seen as i64);
        statsd.update_stats("sharding", agg.sharding as i64);
        statsd.update_stats("finished", agg.finished as i64);
        statsd.update_stats("failures", agg.failures as i64);
        statsd.update_stats("replicate_errors", agg.replicate_errors as i64);
        statsd.update_stats("shrinking_donors", agg.shrinking_donors as i64);
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
        // Reload container ring each pass; on failure keep previous (or None).
        match RingData::load(Path::new(&ring_path)) {
            Ok(data) => container_ring = Some(Ring::new(data, hash_config.clone())),
            Err(e) => {
                if container_ring.is_some() {
                    logger.warning(&format!(
                        "could not reload {ring_path}: {e}; reusing previous ring"
                    ));
                }
            }
        }
    }
}
