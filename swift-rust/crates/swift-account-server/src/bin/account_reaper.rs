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

//! `swift-account-reaper <config.conf> [once]`: purge containers/objects of
//! accounts marked status=DELETED after `delay_reaping`. Reads object and
//! container rings from SWIFT_DIR.

use std::collections::HashMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use swift_account_server::reaper::{recon_update, run_once};
use swift_core::config::SwiftConfig;
use swift_core::daemon;
use swift_core::hashing::HashPathConfig;
use swift_core::obslog::{LogLevel, Logger};
use swift_core::statsd::StatsdClient;
use swift_core::storage_policy::parse_storage_policies;
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
        .unwrap_or_else(|| "/etc/swift/account-server.conf".to_string());
    let run_once_only = std::env::args().nth(2).as_deref() == Some("once");
    let conf = parse_conf_file(&conf_path);
    let get = |section: &str, key: &str, default: &str| -> String {
        conf.get(section, key)
            .ok()
            .flatten()
            .or_else(|| conf.get("DEFAULT", key).ok().flatten())
            .unwrap_or_else(|| default.to_string())
    };
    let devices = get("app:account-server", "devices", "/srv/node");
    let interval: u64 = get("account-reaper", "interval", "3600")
        .parse()
        .unwrap_or(3600);
    let delay_reaping: f64 = get("account-reaper", "delay_reaping", "0")
        .parse()
        .unwrap_or(0.0);
    let log_name = get("account-reaper", "log_name", "account-reaper");
    let log_level = get("account-reaper", "log_level", "INFO")
        .parse::<LogLevel>()
        .unwrap_or(LogLevel::Info);
    let logger = Logger::with_syslog(&log_name, log_level);
    let statsd = StatsdClient::new(
        &get("account-reaper", "log_statsd_host", ""),
        get("account-reaper", "log_statsd_port", "8125")
            .parse()
            .unwrap_or(8125),
        &daemon::statsd_prefix(
            &get("account-reaper", "log_statsd_metric_prefix", ""),
            "account-reaper",
        ),
    );
    let recon_cache_path = get("account-reaper", "recon_cache_path", "/var/cache/swift");

    let swift_conf_path =
        std::env::var("SWIFT_CONF").unwrap_or_else(|_| "/etc/swift/swift.conf".to_string());
    let swift_conf = parse_conf_file(&swift_conf_path);
    let hash_config = HashPathConfig::from_swift_conf(&swift_conf).unwrap_or_else(|e| {
        logger.error(&format!("bad swift.conf hash config: {e}"));
        std::process::exit(1);
    });
    let swift_dir = std::env::var("SWIFT_DIR").unwrap_or_else(|_| "/etc/swift".to_string());
    let policies = parse_storage_policies(&swift_conf).unwrap_or_else(|e| {
        logger.error(&format!("bad storage policies in {swift_conf_path}: {e}"));
        std::process::exit(1);
    });
    let object_ring_paths: Vec<(i64, String)> = policies
        .iter()
        .map(|policy| {
            (
                i64::from(policy.idx()),
                format!("{swift_dir}/{}.ring.gz", policy.ring_name()),
            )
        })
        .collect();
    let container_ring_path = format!("{swift_dir}/container.ring.gz");
    let account_ring_path = format!("{swift_dir}/account.ring.gz");
    let mut object_rings: HashMap<i64, Ring> = object_ring_paths
        .iter()
        .map(|(index, path)| (*index, load_ring(path, &hash_config, &logger)))
        .collect();
    let mut container_ring = load_ring(&container_ring_path, &hash_config, &logger);
    let mut account_ring = load_ring(&account_ring_path, &hash_config, &logger);
    let stop = swift_http::install_sigterm_flag();

    logger.info(&format!(
        "swift-account-reaper: devices={devices} interval={interval}s \
         delay_reaping={delay_reaping}s once={run_once_only}"
    ));
    loop {
        let sweep_start = std::time::Instant::now();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);
        let mut pass = swift_account_server::reaper::ReaperPassStats::default();
        if let Ok(entries) = std::fs::read_dir(&devices) {
            for e in entries.flatten() {
                if e.path().is_dir() {
                    let s = run_once(
                        &e.path(),
                        now,
                        delay_reaping,
                        &object_rings,
                        &container_ring,
                        &account_ring,
                    );
                    pass.accounts_reaped += s.accounts_reaped;
                    pass.accounts_skipped += s.accounts_skipped;
                    pass.containers_deleted += s.containers_deleted;
                    pass.containers_remaining += s.containers_remaining;
                    pass.objects_deleted += s.objects_deleted;
                    pass.objects_remaining += s.objects_remaining;
                    pass.errors += s.errors;
                }
            }
        }
        logger.info(&format!(
            "account-reaper pass: accounts_reaped={} containers_deleted={} \
             objects_deleted={} errors={}",
            pass.accounts_reaped, pass.containers_deleted, pass.objects_deleted, pass.errors
        ));
        statsd.update_stats("accounts_reaped", pass.accounts_reaped as i64);
        statsd.update_stats("containers_deleted", pass.containers_deleted as i64);
        statsd.update_stats("objects_deleted", pass.objects_deleted as i64);
        let update = recon_update(sweep_start.elapsed(), &pass);
        if let Err(e) = daemon::dump_recon(&recon_cache_path, "account.recon", &update) {
            logger.warning(&format!(
                "could not dump recon cache to {recon_cache_path}/account.recon: {e}"
            ));
        }
        if run_once_only {
            break;
        }
        if daemon::sleep_unless_stopped(interval, &stop) {
            logger.info("exiting on SIGTERM");
            break;
        }
        for (index, path) in &object_ring_paths {
            match RingData::load(Path::new(path)) {
                Ok(data) => {
                    object_rings.insert(*index, Ring::new(data, hash_config.clone()));
                }
                Err(e) => logger.warning(&format!(
                    "could not reload {path}: {e}; reusing previous ring"
                )),
            }
        }
        for (path, ring) in [
            (&container_ring_path, &mut container_ring),
            (&account_ring_path, &mut account_ring),
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
