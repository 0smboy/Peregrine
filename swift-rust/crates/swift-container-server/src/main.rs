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

//! `swift-container-server <config.conf>` (see the account server for
//! the configuration conventions).

use std::sync::Arc;

use swift_container_server::{serve_with_config, ContainerServerConfig};
use swift_core::config::SwiftConfig;
use swift_core::hashing::HashPathConfig;
use swift_core::obslog::{LogLevel, Logger};
use swift_core::statsd::StatsdClient;
use swift_core::storage_policy::parse_storage_policies;

fn parse_conf_file(path: &str) -> Result<SwiftConfig, String> {
    let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    SwiftConfig::parse_lenient(&content, &[], false).map_err(|e| e.to_string())
}

fn policies_and_default(swift_conf: &SwiftConfig) -> Result<(Vec<(i64, String)>, i64), String> {
    parse_storage_policies(swift_conf)
        .map_err(|e| e.to_string())
        .map(|policies| {
            let default = policies.default_policy().idx() as i64;
            let names = policies
                .iter()
                .map(|p| (p.idx() as i64, p.name().to_string()))
                .collect();
            (names, default)
        })
}

fn main() {
    let conf_path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: swift-container-server <config.conf>");
        std::process::exit(1);
    });
    let conf = parse_conf_file(&conf_path).unwrap_or_else(|e| {
        eprintln!("could not read {conf_path}: {e}");
        std::process::exit(1);
    });
    let section = "app:container-server";
    let get = |key: &str, default: &str| -> String {
        conf.get(section, key)
            .ok()
            .flatten()
            .or_else(|| conf.get("DEFAULT", key).ok().flatten())
            .unwrap_or_else(|| default.to_string())
    };
    swift_http::reject_legacy_server_runtime(Some(&get("server_runtime", ""))).unwrap_or_else(
        |e| {
            eprintln!("{e}");
            std::process::exit(1);
        },
    );

    // Observability: syslog-or-stderr logger plus a fire-and-forget statsd
    // client (a no-op when log_statsd_host is unset).
    let log_name = get("log_name", "container-server");
    let log_level = get("log_level", "INFO")
        .parse::<LogLevel>()
        .unwrap_or(LogLevel::Info);
    let logger = Logger::with_syslog(&log_name, log_level);
    let statsd_prefix = {
        let metric_prefix = get("log_statsd_metric_prefix", "");
        if metric_prefix.is_empty() {
            log_name.clone()
        } else {
            format!("{metric_prefix}.{log_name}")
        }
    };
    let statsd = StatsdClient::new(
        &get("log_statsd_host", ""),
        get("log_statsd_port", "8125").parse().unwrap_or(8125),
        &statsd_prefix,
    );

    let swift_conf_path = std::env::var("SWIFT_CONF").unwrap_or_else(|_| {
        format!(
            "{}/swift.conf",
            std::env::var("SWIFT_DIR").unwrap_or_else(|_| "/etc/swift".to_string())
        )
    });
    let swift_conf = parse_conf_file(&swift_conf_path).unwrap_or_else(|e| {
        logger.error(&format!("could not read {swift_conf_path}: {e}"));
        std::process::exit(1);
    });
    let hash_config = HashPathConfig::from_swift_conf(&swift_conf).unwrap_or_else(|e| {
        logger.error(&format!("bad swift.conf hash config: {e}"));
        std::process::exit(1);
    });
    let (policies, default_policy_index) = policies_and_default(&swift_conf).unwrap_or_else(|e| {
        logger.error(&format!("bad swift.conf storage policies: {e}"));
        std::process::exit(1);
    });

    let config = ContainerServerConfig {
        devices: get("devices", "/srv/node").into(),
        mount_check: matches!(
            get("mount_check", "true").to_lowercase().as_str(),
            "true" | "1" | "yes" | "on" | "t" | "y"
        ),
        hash_config,
        policies,
        default_policy_index,
        fixed_created_at: None,
    };

    // eventlet parity: `workers` × `max_clients` becomes one bounded thread
    // pool (capped like the built-in default) plus a connection queue.
    let workers: usize = get("workers", "0").parse().unwrap_or(0);
    let max_clients: usize = get("max_clients", "1024").parse().unwrap_or(1024);
    let client_timeout_secs: u64 = get("client_timeout", "60").parse().unwrap_or(60);
    let access_logger = Arc::clone(&logger);
    let access_statsd = Arc::clone(&statsd);
    let access_log: swift_http::AccessLog = Arc::new(move |req, status, elapsed| {
        access_statsd.increment(&format!("{}.{status}", req.method));
        access_statsd.timing(
            &format!("{}.timing", req.method),
            elapsed.as_secs_f64() * 1000.0,
        );
        access_logger.info(&format!(
            "{} {} {} {:.4}s",
            req.method,
            req.path,
            status,
            elapsed.as_secs_f64()
        ));
    });
    let mut http_config = swift_http::ServerConfig {
        client_timeout_secs,
        access_log: Some(access_log),
        // SIGTERM/SIGINT: stop accepting, drain in-flight requests, return.
        shutdown: Some(swift_http::install_sigterm_flag()),
        ..Default::default()
    };
    if workers > 0 {
        http_config.worker_threads = workers.saturating_mul(max_clients).clamp(1, 128);
    }
    http_config.connection_queue = max_clients.max(1);

    let bind = format!("{}:{}", get("bind_ip", "0.0.0.0"), get("bind_port", "6201"));
    let listener = std::net::TcpListener::bind(&bind).unwrap_or_else(|e| {
        logger.error(&format!("could not bind {bind}: {e}"));
        std::process::exit(1);
    });
    logger.info(&format!("swift-container-server listening on {bind}"));
    match serve_with_config(listener, config, http_config) {
        Ok(()) => logger.info("exiting"),
        Err(e) => {
            logger.error(&format!("server error: {e}"));
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod startup_policy_tests {
    use super::*;

    #[test]
    fn invalid_storage_policy_is_not_silently_replaced_with_policy_zero() {
        let conf = SwiftConfig::parse_lenient(
            "[storage-policy:0]\nname = zero\n\
             [storage-policy:1]\nname = one\n",
            &[],
            false,
        )
        .unwrap();
        assert!(policies_and_default(&conf).is_err());
    }
}
