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

//! `swift-object-replicator <object-server.conf> [once]`: the rsync-based
//! object replicator daemon. Sweeps every local device, and for each partition
//! either pushes divergent suffixes to the peer primaries (primary) or reverts
//! a misplaced handoff partition (see [`swift_object_server::replicator`]).
//!
//! Single-host SAIO model: peers are reached at `127.0.0.1:<ring-port>` for the
//! REPLICATE RPC, and their on-disk device roots come from a
//! `[object-replicator] peer_map = <port>:<devices-root>,...` conf option
//! (keyed by the ring device port), so the suffix rsync targets a local path
//! instead of an rsyncd module. Only the default replication policy (index 0)
//! is handled here; EC policies replicate via the reconstructor.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use swift_core::config::SwiftConfig;
use swift_core::hashing::HashPathConfig;
use swift_core::obslog::{LogLevel, Logger};
use swift_core::statsd::StatsdClient;
use swift_diskfile::{get_data_dir, CleanupConfig, PolicyKind};
use swift_object_server::daemonutil;
use swift_object_server::replicator::{run_once, SuffixHashClient, SuffixSyncer};
use swift_ring::{Ring, RingData, RingDevice};

fn parse_conf_file(path: &str) -> SwiftConfig {
    let content = std::fs::read_to_string(path).unwrap_or_default();
    SwiftConfig::parse_lenient(&content, &[], false).unwrap_or_else(|e| {
        eprintln!("could not parse {path}: {e}");
        std::process::exit(1);
    })
}

/// Parse `port:path,port:path,...` into a port->devices-root map.
fn parse_peer_map(spec: &str) -> HashMap<u32, PathBuf> {
    let mut out = HashMap::new();
    for entry in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        if let Some((port, path)) = entry.split_once(':') {
            if let Ok(port) = port.trim().parse::<u32>() {
                out.insert(port, PathBuf::from(path.trim()));
            }
        }
    }
    out
}

/// A minimal REPLICATE request to a peer object server, returning `(status,
/// body)`. Connection is closed after the response.
fn replicate_rpc(peer_host: &str, path: &str, policy_index: u32) -> Option<(u16, Vec<u8>)> {
    let mut conn = TcpStream::connect(peer_host).ok()?;
    conn.set_read_timeout(Some(Duration::from_secs(30))).ok();
    conn.set_write_timeout(Some(Duration::from_secs(30))).ok();
    let req = format!(
        "REPLICATE {path} HTTP/1.1\r\nHost: {peer_host}\r\n\
         X-Backend-Storage-Policy-Index: {policy_index}\r\n\
         Content-Length: 0\r\nConnection: close\r\n\r\n"
    );
    conn.write_all(req.as_bytes()).ok()?;
    let mut raw = Vec::new();
    conn.read_to_end(&mut raw).ok()?;
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    let status: u16 = String::from_utf8_lossy(&raw[..split])
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())?;
    Some((status, raw[split + 4..].to_vec()))
}

/// Real REPLICATE-verb client.
struct HttpSuffixHashClient;

impl HttpSuffixHashClient {
    fn peer_host(peer: &RingDevice) -> String {
        format!("{}:{}", peer.ip, peer.port)
    }
}

impl SuffixHashClient for HttpSuffixHashClient {
    fn peer_hashes(
        &self,
        peer: &RingDevice,
        device: &str,
        partition: u32,
        policy_index: u32,
    ) -> Option<HashMap<String, String>> {
        let path = format!("/{}/{partition}", peer.device);
        let _ = device; // the peer's own device name identifies the target
        let (status, body) = replicate_rpc(&Self::peer_host(peer), &path, policy_index)?;
        if status != 200 {
            return None;
        }
        swift_object_server::replicator::hashes_from_pickle(&body)
    }

    fn peer_rehash(
        &self,
        peer: &RingDevice,
        _device: &str,
        partition: u32,
        suffixes: &[String],
        policy_index: u32,
    ) -> bool {
        if suffixes.is_empty() {
            return true;
        }
        let path = format!("/{}/{partition}/{}", peer.device, suffixes.join("-"));
        matches!(
            replicate_rpc(&Self::peer_host(peer), &path, policy_index),
            Some((200, _))
        )
    }
}

/// Where the rsync push lands. `Local` (single-host SAIO) targets a filesystem
/// path from the port->root peer map; `Ssh` (cross-machine) targets
/// `root@<peer-ip>:<devices-root>` and rsyncs over ssh.
enum RsyncDest {
    Local(HashMap<u32, PathBuf>),
    Ssh {
        devices_root: String,
        ssh_opts: String,
    },
}

/// Real rsync-over-Command syncer (local path or ssh).
struct RsyncSuffixSyncer {
    dest: RsyncDest,
}

impl SuffixSyncer for RsyncSuffixSyncer {
    fn sync_suffix(
        &self,
        local_suffix_dir: &Path,
        peer: &RingDevice,
        _device: &str,
        partition: u32,
        _suffix: &str,
        policy_index: u32,
    ) -> bool {
        let datadir = get_data_dir(policy_index);
        // Destination partition dir with a trailing slash: rsyncing the suffix
        // dir (no trailing slash on the source) INTO it yields
        // <dest>/<suffix>/..., and --mkpath creates the parents on either side.
        let (dest, ssh): (String, Option<&str>) = match &self.dest {
            RsyncDest::Local(map) => {
                let Some(root) = map.get(&peer.port) else {
                    eprintln!(
                        "object-replicator: no peer_map entry for port {}",
                        peer.port
                    );
                    return false;
                };
                (
                    format!("{}/{}/{datadir}/{partition}/", root.display(), peer.device),
                    None,
                )
            }
            RsyncDest::Ssh {
                devices_root,
                ssh_opts,
            } => (
                format!(
                    "root@{}:{devices_root}/{}/{datadir}/{partition}/",
                    peer.ip, peer.device
                ),
                Some(ssh_opts.as_str()),
            ),
        };
        // Object files are immutable (timestamp in the name), so --ignore-existing
        // is safe and avoids churn, matching the object replicator's intent.
        // --exclude the rsync temp-file pattern (`.<name>.<6 alnum>`) exactly as
        // swift/obj/replicator.py does, so a handoff's stray rsync dropping is
        // never propagated to a primary.
        let mut cmd = std::process::Command::new("rsync");
        cmd.args([
            "--recursive",
            "--links",
            "--perms",
            "--times",
            "--xattrs",
            "--whole-file",
            "--ignore-existing",
            "--mkpath",
            "--exclude=.*.[0-9a-zA-Z][0-9a-zA-Z][0-9a-zA-Z][0-9a-zA-Z][0-9a-zA-Z][0-9a-zA-Z]",
        ]);
        if let Some(opts) = ssh {
            cmd.arg("-e").arg(opts);
        }
        cmd.arg(local_suffix_dir).arg(dest);
        matches!(cmd.status(), Ok(s) if s.success())
    }
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
    let interval: u64 = get("object-replicator", "interval", "30")
        .parse()
        .unwrap_or(30);
    let log_name = get("object-replicator", "log_name", "object-replicator");
    let log_level = get("object-replicator", "log_level", "INFO")
        .parse::<LogLevel>()
        .unwrap_or(LogLevel::Info);
    let logger = Logger::with_syslog(&log_name, log_level);
    let statsd = StatsdClient::new(
        &get("object-replicator", "log_statsd_host", ""),
        get("object-replicator", "log_statsd_port", "8125")
            .parse()
            .unwrap_or(8125),
        &daemonutil::statsd_prefix(
            &get("object-replicator", "log_statsd_metric_prefix", ""),
            "object-replicator",
        ),
    );
    let recon_cache_path = get("object-replicator", "recon_cache_path", "/var/cache/swift");
    // Cross-machine rsync-over-ssh when `rsync_ssh_opts` is set (the peer's
    // devices root is `rsync_devices_root`, same path on every node); otherwise
    // the single-host local `peer_map = port:/local/root` model.
    let rsync_ssh_opts = get("object-replicator", "rsync_ssh_opts", "");
    let dest = if rsync_ssh_opts.is_empty() {
        RsyncDest::Local(parse_peer_map(&get("object-replicator", "peer_map", "")))
    } else {
        RsyncDest::Ssh {
            devices_root: get("object-replicator", "rsync_devices_root", "/srv/node"),
            ssh_opts: rsync_ssh_opts,
        }
    };

    let swift_conf_path =
        std::env::var("SWIFT_CONF").unwrap_or_else(|_| "/etc/swift/swift.conf".to_string());
    let swift_conf = parse_conf_file(&swift_conf_path);
    let hash_config = HashPathConfig::from_swift_conf(&swift_conf).unwrap_or_else(|e| {
        logger.error(&format!("bad swift.conf hash config: {e}"));
        std::process::exit(1);
    });
    let swift_dir = std::env::var("SWIFT_DIR").unwrap_or_else(|_| "/etc/swift".to_string());
    let ring_path = format!("{swift_dir}/object.ring.gz");
    // A missing ring at startup is fatal; per-pass reloads below fall back to
    // the previous ring.
    let mut ring = Ring::new(
        RingData::load(Path::new(&ring_path)).unwrap_or_else(|e| {
            logger.error(&format!("could not load {ring_path}: {e}"));
            std::process::exit(1);
        }),
        hash_config.clone(),
    );

    let hash_client = HttpSuffixHashClient;
    let syncer = RsyncSuffixSyncer { dest };
    // Honor conf `reclaim_age` / `commit_window` (DEFAULT or [object-replicator]).
    // Previously always CleanupConfig::default() (604800s), so lab reclaim_age=600
    // had no effect — Wave 0 residual until this wire-up.
    let reclaim_age: f64 = get("object-replicator", "reclaim_age", "604800")
        .parse()
        .unwrap_or(604800.0);
    let commit_window: f64 = get("object-replicator", "commit_window", "60")
        .parse()
        .unwrap_or(60.0);
    let cleanup = CleanupConfig {
        reclaim_age,
        commit_window,
    };
    let stop = swift_http::install_sigterm_flag();

    logger.info(&format!(
        "swift-object-replicator: devices={devices} bind_port={bind_port} \
         interval={interval}s reclaim_age={reclaim_age}s once={run_once_only}"
    ));
    loop {
        let pass_start = std::time::Instant::now();
        let mut total = swift_object_server::replicator::ReplicatorStats::default();
        if let Ok(entries) = std::fs::read_dir(&devices) {
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_dir() {
                    continue;
                }
                let Some(dev_name) = path.file_name().and_then(|s| s.to_str()) else {
                    continue;
                };
                // Identify self: the ring device on this port owning this dir.
                let Some(local_id) = ring_device_id(&ring, bind_port, dev_name) else {
                    continue; // device not in the ring; nothing to replicate
                };
                let stats = run_once(
                    &path,
                    dev_name,
                    0,
                    PolicyKind::Replication,
                    &cleanup,
                    &ring,
                    local_id,
                    &hash_client,
                    &syncer,
                );
                total.partitions += stats.partitions;
                total.suffix_syncs += stats.suffix_syncs;
                total.reverts += stats.reverts;
                total.failures += stats.failures;
            }
        }
        logger.info(&format!(
            "object-replicator pass: partitions={} suffix_syncs={} reverts={} failures={}",
            total.partitions, total.suffix_syncs, total.reverts, total.failures
        ));
        statsd.update_stats("suffix_syncs", total.suffix_syncs as i64);
        statsd.update_stats("reverts", total.reverts as i64);
        statsd.update_stats("failures", total.failures as i64);
        let update = daemonutil::replicator_recon_update(
            &total,
            pass_start.elapsed(),
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
        // Reload the ring every pass so a rebalance is picked up without a
        // restart; on failure keep replicating with the previous ring.
        match RingData::load(Path::new(&ring_path)) {
            Ok(data) => ring = Ring::new(data, hash_config.clone()),
            Err(e) => logger.warning(&format!(
                "could not reload {ring_path}: {e}; reusing previous ring"
            )),
        }
    }
}

/// The ring device id for the local device dir, matched by (port, device name).
fn ring_device_id(ring: &Ring, bind_port: u32, dev_name: &str) -> Option<u64> {
    // Delegated: matching on (port, device) alone makes every node but the
    // first adopt another node's ring identity, because every node calls its
    // first disk d1. See `localdev`.
    swift_object_server::localdev::ring_device_id(ring, bind_port, dev_name)
}
