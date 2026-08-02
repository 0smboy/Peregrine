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

//! `swift-object-server <config.conf>` (see the account server for the
//! configuration conventions; SWIFT_CONF supplies the hash prefix/suffix).

use std::sync::Arc;

use swift_core::config::{config_fallocate_value, SwiftConfig};
use swift_core::hashing::HashPathConfig;
use swift_core::obslog::{LogLevel, Logger};
use swift_core::statsd::StatsdClient;
use swift_core::storage_policy::parse_storage_policies;
use swift_diskfile::{DiskFileConfig, PolicyKind};
use swift_object_server::{
    serve_with_config, ContainerUpdateMode, ObjectServer, ObjectServerConfig,
};

fn parse_conf_file(path: &str) -> Result<SwiftConfig, String> {
    let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    SwiftConfig::parse_lenient(&content, &[], false).map_err(|e| e.to_string())
}

fn storage_policy_kinds(
    swift_conf: &SwiftConfig,
) -> Result<std::collections::HashMap<u32, PolicyKind>, String> {
    parse_storage_policies(swift_conf)
        .map_err(|e| e.to_string())
        .map(|policies| {
            policies
                .iter()
                .map(|policy| {
                    let kind = match policy.ec() {
                        Some(ec) => PolicyKind::Ec {
                            n_unique_fragments: Some(ec.ec_n_unique_fragments() as u32),
                        },
                        None => PolicyKind::Replication,
                    };
                    (policy.idx(), kind)
                })
                .collect()
        })
}

fn main() {
    let conf_path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: swift-object-server <config.conf>");
        std::process::exit(1);
    });
    let conf = parse_conf_file(&conf_path).unwrap_or_else(|e| {
        eprintln!("could not read {conf_path}: {e}");
        std::process::exit(1);
    });
    let section = "app:object-server";
    let get = |key: &str, default: &str| -> String {
        conf.get(section, key)
            .ok()
            .flatten()
            .or_else(|| conf.get("DEFAULT", key).ok().flatten())
            .unwrap_or_else(|| default.to_string())
    };

    // Observability: syslog-or-stderr logger plus a fire-and-forget statsd
    // client (a no-op when log_statsd_host is unset), named as Python's
    // get_logger would name them.
    let log_name = get("log_name", "object-server");
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

    let swift_conf_path =
        std::env::var("SWIFT_CONF").unwrap_or_else(|_| {
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
    let policies = storage_policy_kinds(&swift_conf).unwrap_or_else(|e| {
        logger.error(&format!("bad swift.conf storage policies: {e}"));
        std::process::exit(1);
    });
    let fallocate_reserve = config_fallocate_value(&get("fallocate_reserve", "1%"))
        .unwrap_or_else(|e| {
            logger.error(&e.to_string());
            std::process::exit(1);
        });
    let config = ObjectServerConfig {
        devices: get("devices", "/srv/node").into(),
        mount_check: matches!(
            get("mount_check", "true").to_lowercase().as_str(),
            "true" | "1" | "yes" | "on" | "t" | "y"
        ),
        hash_config,
        diskfile: DiskFileConfig {
            // L2 A/B knob: fsync_on_close = false skips put/rename fsync.
            fsync_on_close: matches!(
                get("fsync_on_close", "true").to_lowercase().as_str(),
                "true" | "1" | "yes" | "on" | "t" | "y"
            ),
            ..DiskFileConfig::default()
        },
        policies,
        container_update_timeout: std::time::Duration::from_secs_f64(
            get("container_update_timeout", "1.0")
                .parse::<f64>()
                .unwrap_or(1.0)
                .max(0.001),
        ),
        container_update_mode: match get("container_update_mode", "sync")
            .to_ascii_lowercase()
            .as_str()
        {
            "async" | "asynchronous" | "pending" => ContainerUpdateMode::Async,
            _ => ContainerUpdateMode::Sync,
        },
    };

    // eventlet parity: `workers` processes each serving `max_clients`
    // concurrent clients becomes one bounded thread pool (capped like the
    // built-in default) plus a connection queue of max_clients.
    let workers: usize = get("workers", "0").parse().unwrap_or(0);
    let max_clients: usize = get("max_clients", "1024").parse().unwrap_or(1024);
    let client_timeout_secs: u64 = get("client_timeout", "60").parse().unwrap_or(60);
    let access_logger = Arc::clone(&logger);
    let access_statsd = Arc::clone(&statsd);
    let access_log: swift_http::AccessLog =
        Arc::new(move |req, status, elapsed| {
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
    let reuse_port = matches!(
        get("reuse_port", "false").to_lowercase().as_str(),
        "true" | "1" | "yes" | "on" | "t" | "y"
    );
    let mut http_config = swift_http::ServerConfig {
        client_timeout_secs,
        access_log: Some(access_log),
        // SIGTERM/SIGINT: stop accepting, drain in-flight requests, return.
        shutdown: Some(swift_http::install_sigterm_flag()),
        reuse_port,
        ..Default::default()
    };
    if workers > 0 {
        http_config.worker_threads = workers.saturating_mul(max_clients).clamp(1, 128);
    }
    http_config.connection_queue = max_clients.max(1);

    let bind = format!("{}:{}", get("bind_ip", "0.0.0.0"), get("bind_port", "6200"));
    let listener = swift_http::bind_listener(&bind, reuse_port).unwrap_or_else(|e| {
        logger.error(&format!("could not bind {bind} (reuse_port={reuse_port}): {e}"));
        std::process::exit(1);
    });
    logger.info(&format!("swift-object-server listening on {bind}"));
    let server = ObjectServer::new(config).with_fallocate_reserve(fallocate_reserve);
    match serve_with_config(listener, server, http_config) {
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
    fn invalid_storage_policy_is_not_silently_treated_as_replication() {
        let conf = SwiftConfig::parse_lenient(
            "[storage-policy:0]\nname = broken\npolicy_type = erasure_coding\n",
            &[],
            false,
        )
        .unwrap();
        assert!(storage_policy_kinds(&conf).is_err());
    }

    #[test]
    fn configured_policy_kinds_preserve_replication_and_ec() {
        let conf = SwiftConfig::parse_lenient(
            "[storage-policy:0]\n\
             name = replicated\n\
             [storage-policy:1]\n\
             name = encoded\n\
             policy_type = erasure_coding\n\
             ec_type = liberasurecode_rs_vand\n\
             ec_num_data_fragments = 10\n\
             ec_num_parity_fragments = 4\n\
             default = yes\n",
            &[],
            false,
        )
        .unwrap();

        let policies = storage_policy_kinds(&conf).unwrap();
        assert_eq!(
            policies.get(&0),
            Some(&swift_diskfile::PolicyKind::Replication)
        );
        assert_eq!(
            policies.get(&1),
            Some(&swift_diskfile::PolicyKind::Ec {
                n_unique_fragments: Some(14),
            })
        );
    }
}
