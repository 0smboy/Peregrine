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
// implied. See the License for the specific language governing permissions
// and limitations under the License.

//! `swift-object-reconstructor <object-server.conf> [once]`: the EC
//! reconstructor daemon (`swift/obj/reconstructor.py`), ssync-driven half.
//! For every EC policy it sweeps each local device's partitions, builds SYNC
//! jobs (push this primary's fragment state to its ring partners) and REVERT
//! jobs (push misplaced fragments to their proper primary, then purge them
//! locally), and runs them over SSYNC. The fragment REBUILD path
//! (liberasurecode) stays behind the `ec` cargo feature as a library API.

use std::path::Path;

use swift_core::config::SwiftConfig;
use swift_core::hashing::HashPathConfig;
use swift_core::obslog::{LogLevel, Logger};
use swift_core::statsd::StatsdClient;
use swift_core::storage_policy::parse_storage_policies;
use swift_diskfile::{get_data_dir, CleanupConfig, DiskFileConfig, PolicyKind};
use swift_object_server::daemonutil;
use swift_object_server::reconstructor::{
    build_part_jobs, process_part_job, EcScheme, EcSsyncStats, HttpSuffixHashFetcher,
    TcpSsyncPusher,
};
use swift_ring::{Ring, RingData};

fn parse_conf_file(path: &str) -> SwiftConfig {
    let content = std::fs::read_to_string(path).unwrap_or_default();
    SwiftConfig::parse_lenient(&content, &[], false).unwrap_or_else(|e| {
        eprintln!("could not parse {path}: {e}");
        std::process::exit(1);
    })
}

/// One EC policy this daemon covers.
struct EcPolicy {
    index: u32,
    kind: PolicyKind,
    scheme: EcScheme,
    ring_path: String,
    ring: Ring,
}

fn main() {
    let conf_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/etc/swift/object-server.conf".to_string());
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
    let bind_port: u32 = get("app:object-server", "bind_port", "6010")
        .parse()
        .unwrap_or(6010);
    // When >0 the object server discovers per-device ring ports; conf
    // bind_port is only a base and must not be used for ring identity.
    let servers_per_port: u32 = get("app:object-server", "servers_per_port", "0")
        .parse()
        .unwrap_or(0);
    let interval: u64 = get("object-reconstructor", "interval", "30")
        .parse()
        .unwrap_or(30);
    let rebuild_handoff_node_count: i64 =
        get("object-reconstructor", "rebuild_handoff_node_count", "2")
            .parse()
            .unwrap_or(2);
    let log_name = get("object-reconstructor", "log_name", "object-reconstructor");
    let log_level = get("object-reconstructor", "log_level", "INFO")
        .parse::<LogLevel>()
        .unwrap_or(LogLevel::Info);
    let logger = Logger::with_syslog(&log_name, log_level);
    let statsd = StatsdClient::new(
        &get("object-reconstructor", "log_statsd_host", ""),
        get("object-reconstructor", "log_statsd_port", "8125")
            .parse()
            .unwrap_or(8125),
        &daemonutil::statsd_prefix(
            &get("object-reconstructor", "log_statsd_metric_prefix", ""),
            "object-reconstructor",
        ),
    );
    let recon_cache_path = get(
        "object-reconstructor",
        "recon_cache_path",
        "/var/cache/swift",
    );

    let swift_dir = std::env::var("SWIFT_DIR").unwrap_or_else(|_| "/etc/swift".to_string());
    let swift_conf_path =
        std::env::var("SWIFT_CONF").unwrap_or_else(|_| format!("{swift_dir}/swift.conf"));
    let swift_conf = parse_conf_file(&swift_conf_path);
    let hash_config = HashPathConfig::from_swift_conf(&swift_conf).unwrap_or_else(|e| {
        logger.error(&format!("bad swift.conf hash config: {e}"));
        std::process::exit(1);
    });
    let policies = parse_storage_policies(&swift_conf).unwrap_or_else(|e| {
        logger.error(&format!("bad swift.conf storage policies: {e}"));
        std::process::exit(1);
    });
    let constraints = swift_core::constraints::Constraints::from_swift_conf(&swift_conf)
        .unwrap_or_else(|e| {
            logger.error(&format!("bad swift.conf constraints: {e}"));
            std::process::exit(1);
        });
    let max_original_size = usize::try_from(constraints.max_file_size)
        .ok()
        .filter(|value| *value > 0)
        .unwrap_or_else(|| {
            logger.error("max_file_size must be a positive usize");
            std::process::exit(1);
        });
    // Every EC policy with a loadable ring; a missing ring at startup is
    // fatal, like the replicator.
    let mut ec_policies: Vec<EcPolicy> = Vec::new();
    for policy in policies.iter() {
        let Some(ec) = policy.ec() else { continue };
        let scheme = EcScheme {
            ndata: ec.ec_ndata as usize,
            nparity: ec.ec_nparity as usize,
            segment_size: ec.ec_segment_size as usize,
        };
        let ring_path = format!("{swift_dir}/{}.ring.gz", policy.ring_name());
        let ring = Ring::new(
            RingData::load(Path::new(&ring_path)).unwrap_or_else(|e| {
                logger.error(&format!("could not load {ring_path}: {e}"));
                std::process::exit(1);
            }),
            hash_config.clone(),
        );
        ec_policies.push(EcPolicy {
            index: policy.idx(),
            kind: PolicyKind::Ec {
                n_unique_fragments: Some(ec.ec_n_unique_fragments() as u32),
            },
            scheme,
            ring_path,
            ring,
        });
    }
    if ec_policies.is_empty() {
        logger.info("swift-object-reconstructor: no EC storage policies configured; exiting");
        return;
    }

    let diskfile_config = DiskFileConfig::default();
    let reclaim_age: f64 = get("object-reconstructor", "reclaim_age", "604800")
        .parse()
        .unwrap_or(604800.0);
    let commit_window: f64 = get("object-reconstructor", "commit_window", "60")
        .parse()
        .unwrap_or(60.0);
    let cleanup = CleanupConfig {
        reclaim_age,
        commit_window,
    };
    let pusher = TcpSsyncPusher::default();
    let hash_fetcher = HttpSuffixHashFetcher::default();
    let stop = swift_http::install_sigterm_flag();
    let devices_path = std::path::PathBuf::from(&devices);

    logger.info(&format!(
        "swift-object-reconstructor: devices={devices} bind_port={bind_port} \
         servers_per_port={servers_per_port} interval={interval}s once={run_once_only} policies={}",
        ec_policies.len()
    ));
    loop {
        let pass_start = std::time::Instant::now();
        let mut total = EcSsyncStats::default();
        for policy in &ec_policies {
            sweep_policy(
                &devices_path,
                bind_port,
                servers_per_port,
                policy,
                &hash_config,
                &diskfile_config,
                &cleanup,
                rebuild_handoff_node_count,
                max_original_size,
                &pusher,
                &hash_fetcher,
                &mut total,
            );
        }
        logger.info(&format!(
            "object-reconstructor pass: suffix_syncs={} reverts={} failures={}",
            total.suffix_syncs, total.reverts, total.failures
        ));
        if let Some(err) = &total.last_error {
            // A pass that keeps failing is the one an operator has to act on,
            // so say what went wrong rather than only how often.
            logger.error(&format!("object-reconstructor last failure: {err}"));
        }
        statsd.update_stats("suffix_syncs", total.suffix_syncs as i64);
        statsd.update_stats("reverts", total.reverts as i64);
        statsd.update_stats("failures", total.failures as i64);
        let update = serde_json::json!({
            "object_reconstruction_time": pass_start.elapsed().as_secs_f64() / 60.0,
            "object_reconstruction_last": daemonutil::epoch_secs_now(),
        });
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
        // Reload the rings every pass so a rebalance is picked up without a
        // restart; on failure keep the previous ring.
        for policy in &mut ec_policies {
            match RingData::load(Path::new(&policy.ring_path)) {
                Ok(data) => policy.ring = Ring::new(data, hash_config.clone()),
                Err(e) => logger.warning(&format!(
                    "could not reload {}: {e}; reusing previous ring",
                    policy.ring_path
                )),
            }
        }
    }
}

/// One pass over every local device's partitions for one EC policy
/// (`collect_parts` + `build_reconstruction_jobs` + `process_job`).
#[allow(clippy::too_many_arguments)]
fn sweep_policy(
    devices_path: &Path,
    bind_port: u32,
    servers_per_port: u32,
    policy: &EcPolicy,
    hash_config: &HashPathConfig,
    diskfile_config: &DiskFileConfig,
    cleanup: &CleanupConfig,
    rebuild_handoff_node_count: i64,
    max_original_size: usize,
    pusher: &TcpSsyncPusher,
    hash_fetcher: &HttpSuffixHashFetcher,
    total: &mut EcSsyncStats,
) {
    #[cfg(not(feature = "ec"))]
    let _ = max_original_size;
    let Ok(entries) = std::fs::read_dir(devices_path) else {
        return;
    };
    for entry in entries.flatten() {
        let device_path = entry.path();
        if !device_path.is_dir() {
            continue;
        }
        let Some(dev_name) = device_path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        // Identify self: the ring device on this port owning this dir.
        // Address-aware: (port, device) alone is ambiguous across nodes and
        // made every node but the first act as swift1. See `localdev`.
        // With servers_per_port>0 conf bind_port is only a base (e.g. 6210)
        // while ring ports are 6211/6212 — match by local IP + device name.
        let local_id = if servers_per_port > 0 {
            swift_object_server::localdev::ring_device_id_local_name(&policy.ring, dev_name)
        } else {
            swift_object_server::localdev::ring_device_id(&policy.ring, bind_port, dev_name)
        };
        let Some(local_id) = local_id else {
            continue; // device not in this policy's ring
        };
        let part_root = device_path.join(get_data_dir(policy.index));
        let Ok(parts) = std::fs::read_dir(&part_root) else {
            continue;
        };
        for part_entry in parts.flatten() {
            let part_path = part_entry.path();
            if !part_path.is_dir() {
                continue;
            }
            let Some(partition) = part_path
                .file_name()
                .and_then(|s| s.to_str())
                .and_then(|s| s.parse::<u64>().ok())
            else {
                continue;
            };
            let Ok(part_nodes) = policy.ring.get_part_nodes(partition as u32) else {
                total.failures += 1;
                continue;
            };
            let Ok(handoff_nodes) = policy.ring.get_more_nodes(partition as u32) else {
                total.failures += 1;
                continue;
            };
            let jobs = build_part_jobs(
                &part_path,
                partition,
                dev_name,
                policy.kind,
                cleanup,
                &part_nodes,
                &handoff_nodes,
                rebuild_handoff_node_count,
                local_id,
                Some(policy.scheme),
            );
            // SYNC jobs rebuild fragments on the fly at the partner's
            // backend index (reconstruct_fa): sources are this partition's
            // primaries — the coherence + local-timestamp checks discard a
            // stale/absent target's response. Without the `ec` feature
            // (no codec) there is no rebuilder and mismatched fragments
            // are skipped, as before.
            #[cfg(feature = "ec")]
            let peers: Vec<swift_ring::RingDevice> =
                part_nodes.iter().map(|pn| pn.dev.clone()).collect();
            #[cfg(feature = "ec")]
            let frag_fetcher = swift_object_server::reconstructor::HttpFragmentFetcher {
                policy_index: policy.index,
                max_response_bytes:
                    swift_object_server::reconstructor::fragment_archive_size_bound(
                        policy.scheme,
                        max_original_size,
                    )
                    .unwrap_or(0),
                max_original_size,
                scheme: Some(policy.scheme),
                ..Default::default()
            };
            for job in &jobs {
                #[cfg(feature = "ec")]
                let rebuilder = swift_object_server::reconstructor::EcSyncRebuilder {
                    scheme: policy.scheme,
                    partition,
                    peers: peers.clone(),
                    fetcher: &frag_fetcher,
                };
                #[cfg(feature = "ec")]
                let diskfile_builder: Option<
                    &dyn swift_object_server::ssync_sender::SyncDiskfileBuilder,
                > = Some(&rebuilder);
                #[cfg(not(feature = "ec"))]
                let diskfile_builder: Option<
                    &dyn swift_object_server::ssync_sender::SyncDiskfileBuilder,
                > = None;
                process_part_job(
                    devices_path,
                    hash_config,
                    diskfile_config,
                    policy.index,
                    policy.kind,
                    job,
                    pusher,
                    hash_fetcher,
                    diskfile_builder,
                    total,
                );
            }
        }
    }
}
