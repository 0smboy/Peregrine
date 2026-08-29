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

//! `swift-object-expirer <config.conf> [once]`: drain the `.expiring_objects`
//! queue and DELETE objects whose `X-Delete-At` has passed (guarded by
//! `X-If-Delete-At`). Reads account/container/object rings from SWIFT_DIR.

use std::path::Path;

use swift_core::config::SwiftConfig;
use swift_core::hashing::HashPathConfig;
use swift_core::obslog::{LogLevel, Logger};
use swift_core::statsd::StatsdClient;
use swift_core::timestamp::Timestamp;
use swift_object_server::daemonutil;
use swift_object_server::expirer::{recon_update, run_once, run_once_via_proxy};
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

fn parse_internal_client_host(url: &str) -> Result<Option<String>, String> {
    let url = url.trim();
    if url.is_empty() {
        return Ok(None);
    }
    let Some(rest) = url.strip_prefix("http://") else {
        return Err("internal_client_url must use plain http:// on a protected listener".into());
    };
    let host = rest.split('/').next().unwrap_or("").trim();
    if host.is_empty() || !host.contains(':') {
        return Err("internal_client_url must include host:port".into());
    }
    Ok(Some(host.to_string()))
}

fn main() {
    let conf_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/etc/swift/object-expirer.conf".to_string());
    // Also accept object-server.conf (section [object-expirer]) for single-file
    // deployments that fold the expirer into the object conf.
    let conf_path = if Path::new(&conf_path).exists() {
        conf_path
    } else {
        "/etc/swift/object-server.conf".to_string()
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
    let interval: u64 = get("object-expirer", "interval", "300")
        .parse()
        .unwrap_or(300);
    let reclaim_age: i64 = get("object-expirer", "reclaim_age", "604800")
        .parse()
        .unwrap_or(604800);
    let internal_client_host =
        parse_internal_client_host(&get("object-expirer", "internal_client_url", ""))
            .unwrap_or_else(|e| {
                eprintln!("invalid object-expirer internal client endpoint: {e}");
                std::process::exit(1);
            });
    let log_name = get("object-expirer", "log_name", "object-expirer");
    let log_level = get("object-expirer", "log_level", "INFO")
        .parse::<LogLevel>()
        .unwrap_or(LogLevel::Info);
    let logger = Logger::with_syslog(&log_name, log_level);
    let statsd = StatsdClient::new(
        &get("object-expirer", "log_statsd_host", ""),
        get("object-expirer", "log_statsd_port", "8125")
            .parse()
            .unwrap_or(8125),
        &daemonutil::statsd_prefix(
            &get("object-expirer", "log_statsd_metric_prefix", ""),
            "object-expirer",
        ),
    );
    let recon_cache_path = get("object-expirer", "recon_cache_path", "/var/cache/swift");

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

    let delete_transport = internal_client_host
        .as_deref()
        .map(|host| format!("internal-proxy:{host}"))
        .unwrap_or_else(|| "legacy-ring-direct".to_string());
    logger.info(&format!(
        "swift-object-expirer: interval={interval}s reclaim_age={reclaim_age}s once={run_once_only} delete_transport={delete_transport}"
    ));
    loop {
        let sweep_start = std::time::Instant::now();
        // Async SLO delete jobs use five-decimal timestamps. Keep the current
        // time at Swift's native precision too; whole-second `now` defers a
        // job created earlier in the same second until the next pass.
        let now = Timestamp::now();
        let stats = if let Some(host) = internal_client_host.as_deref() {
            run_once_via_proxy(&account_ring, &container_ring, host, now, reclaim_age)
        } else {
            run_once(
                &account_ring,
                &container_ring,
                &object_ring,
                now,
                reclaim_age,
            )
        };
        logger.info(&format!(
            "object-expirer pass: expired={} errors={} retained={}",
            stats.objects, stats.errors, stats.skipped_retained
        ));
        statsd.update_stats("objects", stats.objects as i64);
        statsd.update_stats("errors", stats.errors as i64);
        let update = recon_update(sweep_start.elapsed(), stats.objects);
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

#[cfg(test)]
mod tests {
    use super::parse_internal_client_host;

    #[test]
    fn internal_client_url_requires_protected_plain_http_host_port() {
        assert_eq!(
            parse_internal_client_host("http://127.0.0.1:18082").unwrap(),
            Some("127.0.0.1:18082".to_string())
        );
        assert_eq!(parse_internal_client_host("  ").unwrap(), None);
        assert!(parse_internal_client_host("https://127.0.0.1:18082").is_err());
        assert!(parse_internal_client_host("http://127.0.0.1").is_err());
    }
}
