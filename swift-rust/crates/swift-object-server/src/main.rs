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

use swift_core::config::{config_fallocate_value, config_true_value, SwiftConfig};
use swift_core::hashing::HashPathConfig;
use swift_core::obslog::{LogLevel, Logger};
use swift_core::statsd::StatsdClient;
use swift_core::storage_policy::parse_storage_policies;
use swift_diskfile::{DiskFileConfig, PolicyKind};
use swift_object_server::servers_per_port::{
    bind_acceptors_with_reuse, child_bind_port_from_env, default_swift_dir, effective_concurrency,
    listen_ports, maybe_supervise_port_workers, ConcurrencyInputs,
};
use swift_object_server::{
    serve_with_config_multi, ContainerUpdateMode, ObjectServer, ObjectServerConfig,
};

/// Disk admission for one object-server process: thread cap, queue, device ops.
///
/// The HTTP server already accepted the connection under `max_clients`.
/// The storage executor's lazy default (8 threads, queue 32, 32 in-flight
/// ops per device) is smaller than that, and it fails closed. A 1000-PUT
/// burst then gets 500 from the object server, which the proxy reports as
/// 503 once write quorum is lost.
fn object_storage_admission(
    worker_threads: usize,
    connection_queue: usize,
    max_clients: usize,
) -> Result<(usize, usize, usize), String> {
    let threads = worker_threads.max(1);
    let queue = connection_queue.max(1);
    let admitted = max_clients.max(1);
    if threads.saturating_add(queue) < admitted {
        return Err(format!(
            "storage executor cannot hold {admitted} admitted PUTs (threads={threads} queue={queue})"
        ));
    }
    Ok((threads, queue, admitted))
}

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
    swift_http::reject_legacy_server_runtime(Some(&get("server_runtime", ""))).unwrap_or_else(
        |e| {
            eprintln!("{e}");
            std::process::exit(1);
        },
    );

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
    let policies = storage_policy_kinds(&swift_conf).unwrap_or_else(|e| {
        logger.error(&format!("bad swift.conf storage policies: {e}"));
        std::process::exit(1);
    });
    let fallocate_reserve =
        config_fallocate_value(&get("fallocate_reserve", "1%")).unwrap_or_else(|e| {
            logger.error(&e.to_string());
            std::process::exit(1);
        });
    // WORM clock-health knob for the native lock gate. 0 (default) =
    // disabled: clock_ok stays the historical constant `true`. >0 = enabled
    // fail-closed against chrony tracking. Invalid values refuse startup
    // rather than silently disabling a safety signal.
    let worm_clock_max_offset_ms = {
        let raw = get("worm_clock_max_offset_ms", "0");
        raw.trim().parse::<u64>().unwrap_or_else(|_| {
            logger.error(&format!("invalid worm_clock_max_offset_ms {raw:?}"));
            std::process::exit(1);
        })
    };
    let config = ObjectServerConfig {
        devices: get("devices", "/srv/node").into(),
        mount_check: matches!(
            get("mount_check", "true").to_lowercase().as_str(),
            "true" | "1" | "yes" | "on" | "t" | "y"
        ),
        hash_config,
        diskfile: DiskFileConfig {
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

    // Topology / concurrency — docs/fairness-lab/WORKERS-SEMANTICS.md
    let workers: usize = get("workers", "0").parse().unwrap_or(0);
    let max_clients: usize = get("max_clients", "1024").parse().unwrap_or(1024);
    let servers_per_port: usize = get("servers_per_port", "0").parse().unwrap_or(0);
    let client_timeout_secs: u64 = get("client_timeout", "60").parse().unwrap_or(60);
    let bind_ip = get("bind_ip", "0.0.0.0");
    let bind_port: u16 = get("bind_port", "6200").parse().unwrap_or(6200);
    let ring_ip = {
        let rip = get("ring_ip", "");
        if rip.is_empty() {
            bind_ip.clone()
        } else {
            rip
        }
    };
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

    // Wave 2: discover ring ports; parent supervises one OS child per
    // (port, worker_index); child binds a single port (REUSEPORT when spp>1).
    let discovered = if servers_per_port > 0 {
        let p = listen_ports(&default_swift_dir(), &ring_ip, bind_port);
        logger.info(&format!(
            "servers_per_port={servers_per_port}: listen_ports={p:?} ring_ip={ring_ip}"
        ));
        p
    } else {
        vec![bind_port]
    };

    if servers_per_port > 0 {
        let conf_argv = std::env::args().skip(1).collect::<Vec<_>>();
        match maybe_supervise_port_workers(servers_per_port, &discovered, &conf_argv) {
            Ok(Some(code)) => {
                logger.info(&format!(
                    "servers_per_port supervisor: {} child process(es) exited (code={code})",
                    discovered.len().saturating_mul(servers_per_port.max(1))
                ));
                std::process::exit(code);
            }
            Ok(None) => {}
            Err(e) => {
                logger.error(&format!("servers_per_port supervise failed: {e}"));
                std::process::exit(1);
            }
        }
    }

    let ports = if let Some(child_port) = child_bind_port_from_env() {
        logger.info(&format!(
            "servers_per_port child: bind_port={child_port} (process-isolated)"
        ));
        vec![child_port]
    } else {
        discovered
    };

    // Children always bind one acceptor; REUSEPORT when spp>1 (siblings share port).
    let n_per_port = 1usize;
    let reuse_port = config_true_value(&get("reuse_port", "false"))
        || (servers_per_port > 1 && child_bind_port_from_env().is_some());

    // Child process: size the local pool as one acceptor; parent already exited.
    let eff_spp = if child_bind_port_from_env().is_some() {
        1
    } else {
        servers_per_port
    };
    let eff = effective_concurrency(ConcurrencyInputs {
        workers,
        max_clients,
        servers_per_port: eff_spp,
        bind_ports: ports.len().max(1),
    });
    logger.info(&format!(
        "concurrency: {} → worker_threads={} queue={} acceptors={} notes={:?}",
        eff.formula, eff.worker_threads, eff.connection_queue, eff.acceptors, eff.notes
    ));

    let http_config = swift_http::ServerConfig {
        client_timeout_secs,
        access_log: Some(access_log),
        shutdown: Some(swift_http::install_sigterm_flag()),
        reuse_port,
        worker_threads: eff.worker_threads,
        connection_queue: eff.connection_queue,
        // Slow PUTs pin body workers. Accept has to stay on its own thread
        // or the listen queue fills and the proxy's connect times out as 503.
        dedicated_accept: true,
        ..Default::default()
    };

    let listeners = bind_acceptors_with_reuse(&bind_ip, &ports, n_per_port, reuse_port)
        .unwrap_or_else(|e| {
            logger.error(&format!(
                "could not bind {bind_ip} ports={ports:?} n_per_port={n_per_port} \
             reuse_port={reuse_port}: {e}"
            ));
            std::process::exit(1);
        });
    for lis in &listeners {
        if let Err(e) = swift_http::set_listen_backlog(lis, 65535) {
            logger.error(&format!("listen backlog: {e}"));
            std::process::exit(1);
        }
    }
    for (i, lis) in listeners.iter().enumerate() {
        let addr = lis
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "?".into());
        logger.info(&format!(
            "swift-object-server listening on {addr} (socket {i}/{})",
            listeners.len()
        ));
    }

    let (storage_threads, storage_queue, storage_devices) =
        object_storage_admission(eff.worker_threads, eff.connection_queue, max_clients)
            .unwrap_or_else(|e| {
                logger.error(&format!("storage executor: {e}"));
                std::process::exit(1);
            });
    logger.info(&format!(
        "storage executor: threads={storage_threads} queue={storage_queue} device_ops={storage_devices}"
    ));

    let mut server = ObjectServer::new(config)
        .with_fallocate_reserve(fallocate_reserve)
        .with_recon_cache_path(get("recon_cache_path", "/var/cache/swift").into())
        .with_storage_admission(storage_threads, storage_queue, storage_devices);
    if worm_clock_max_offset_ms > 0 {
        server = server.with_worm_clock(std::sync::Arc::new(swift_http::ClockHealth::chrony(
            worm_clock_max_offset_ms,
        )));
    }
    match serve_with_config_multi(listeners, server, http_config) {
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
    fn server_runtime_legacy_is_rejected_at_startup_helper() {
        assert!(swift_http::reject_legacy_server_runtime(Some("legacy")).is_err());
        assert!(swift_http::reject_legacy_server_runtime(Some("")).is_ok());
    }

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
    fn admitted_puts_fit_in_the_storage_executor() {
        let (threads, queue, device_ops) =
            super::object_storage_admission(128, 1024, 1024).expect("admission");
        assert!(threads.saturating_add(queue) >= 1024);
        assert!(device_ops >= 1024);
        assert!(super::object_storage_admission(8, 32, 1024).is_err());
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
