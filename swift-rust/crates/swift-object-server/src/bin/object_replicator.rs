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

//! `swift-object-replicator <object-server.conf> [once]`: the SSYNC-based
//! object replicator daemon. Sweeps every local device, and for each partition
//! either pushes divergent suffixes to the peer primaries (primary) or reverts
//! a misplaced handoff partition (see [`swift_object_server::replicator`]).
//! Both hash comparison and object transfer go through the peer object server;
//! no sender writes directly into a peer's live `objects*` tree. Only the
//! default replication policy (index 0) is handled here; EC policies replicate
//! via the reconstructor.

use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use swift_core::config::{config_true_value, SwiftConfig};
use swift_core::hashing::HashPathConfig;
use swift_core::obslog::{LogLevel, Logger};
use swift_core::statsd::StatsdClient;
use swift_core::storage_policy::{parse_storage_policies, REPL_POLICY};
use swift_diskfile::{CleanupConfig, DiskFileConfig, PolicyKind};
use swift_object_server::daemonutil;
use swift_object_server::replicator::{
    run_once_guarded, ReplicationJobGuard, SuffixHashClient, SuffixHashError, SuffixHashMap,
    SuffixSyncer,
};
use swift_object_server::ssync_sender::{Sender, SsyncJob, SsyncNode, TcpSsyncWire};
use swift_ring::{Ring, RingData, RingDevice};

fn load_conf_file(path: &str) -> Result<SwiftConfig, String> {
    let content =
        std::fs::read_to_string(path).map_err(|error| format!("could not read {path}: {error}"))?;
    SwiftConfig::parse_lenient(&content, &[], false)
        .map_err(|error| format!("could not parse {path}: {error}"))
}

fn parse_conf_file(path: &str) -> SwiftConfig {
    load_conf_file(path).unwrap_or_else(|error| {
        eprintln!("{error}");
        std::process::exit(1);
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    len: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

fn file_identity(path: &Path) -> std::io::Result<FileIdentity> {
    let metadata = std::fs::metadata(path)?;
    Ok(FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        len: metadata.len(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    })
}

fn load_ring_snapshot(
    path: &Path,
    hash_config: &HashPathConfig,
) -> Result<(Ring, FileIdentity), String> {
    let before = file_identity(path)
        .map_err(|error| format!("could not stat {}: {error}", path.display()))?;
    let data = RingData::load(path)
        .map_err(|error| format!("could not load {}: {error}", path.display()))?;
    let after = file_identity(path)
        .map_err(|error| format!("could not restat {}: {error}", path.display()))?;
    if before != after {
        return Err(format!(
            "ring {} changed while it was being loaded",
            path.display()
        ));
    }
    Ok((Ring::new(data, hash_config.clone()), after))
}

struct ReplicationPolicyState {
    index: u32,
    name: String,
    ring_path: PathBuf,
    ring: Ring,
    ring_identity: FileIdentity,
}

const MAX_REPLICATE_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

fn ring_device_socket(peer: &RingDevice) -> Option<SocketAddr> {
    let ip = peer
        .replication_ip
        .as_deref()
        .unwrap_or(&peer.ip)
        .parse::<IpAddr>()
        .ok()?;
    let port = u16::try_from(peer.replication_port.unwrap_or(peer.port)).ok()?;
    Some(SocketAddr::new(ip, port))
}

/// A bounded REPLICATE request to a peer object server, returning `(status,
/// body)`. Both the byte budget and wall-clock budget are finite.
fn replicate_rpc(
    peer: &RingDevice,
    path: &str,
    policy_index: u32,
    conn_timeout: Duration,
    http_timeout: Duration,
) -> Option<(u16, Vec<u8>)> {
    let peer_addr = ring_device_socket(peer)?;
    swift_object_server::reconstructor::bounded_replicate_rpc(
        peer_addr,
        path,
        policy_index,
        conn_timeout,
        http_timeout,
        http_timeout,
        MAX_REPLICATE_RESPONSE_BYTES,
    )
    .ok()
}

/// Real REPLICATE-verb client.
struct HttpSuffixHashClient {
    conn_timeout: Duration,
    http_timeout: Duration,
}

impl SuffixHashClient for HttpSuffixHashClient {
    fn peer_hashes(
        &self,
        peer: &RingDevice,
        device: &str,
        partition: u32,
        policy_index: u32,
    ) -> Result<SuffixHashMap, SuffixHashError> {
        let path = format!("/{}/{partition}", peer.device);
        let _ = device; // the peer's own device name identifies the target
        let (status, body) = replicate_rpc(
            peer,
            &path,
            policy_index,
            self.conn_timeout,
            self.http_timeout,
        )
        .ok_or(SuffixHashError::Failed)?;
        if status == 507 {
            return Err(SuffixHashError::InsufficientStorage);
        }
        if status != 200 {
            return Err(SuffixHashError::Failed);
        }
        swift_object_server::replicator::hashes_from_pickle(&body).ok_or(SuffixHashError::Failed)
    }
}

/// Replication-policy suffix transfer through the peer's SSYNC receiver.
///
/// The receiver owns the partition replication lock for the session and each
/// subrequest enters the same object mutation/durability path as foreground
/// traffic. This deliberately replaces raw local/SSH rsync into live storage.
struct SsyncSuffixSyncer {
    devices: PathBuf,
    hash_config: HashPathConfig,
    diskfile_config: DiskFileConfig,
    conn_timeout: Duration,
    node_timeout: Duration,
    max_objects_per_session: usize,
    max_objects_per_partition: usize,
}

impl SuffixSyncer for SsyncSuffixSyncer {
    fn sync_suffixes(
        &self,
        local_partition_dir: &Path,
        peer: &RingDevice,
        device: &str,
        partition: u32,
        suffixes: &[String],
        policy_index: u32,
    ) -> Option<swift_object_server::ssync_sender::SenderReport> {
        if !local_partition_dir.is_dir() {
            return None;
        }
        let job = SsyncJob {
            device: device.to_string(),
            partition: u64::from(partition),
            policy_index,
            policy: PolicyKind::Replication,
            frag_index: None,
        };
        let node = SsyncNode {
            replication_ip: peer
                .replication_ip
                .clone()
                .unwrap_or_else(|| peer.ip.clone()),
            replication_port: peer.replication_port.unwrap_or(peer.port),
            device: peer.device.clone(),
            backend_index: None,
        };
        let mut aggregate = swift_object_server::ssync_sender::SenderReport::default();
        let mut cursor: Option<(String, String)> = None;
        loop {
            let sender = Sender {
                devices: &self.devices,
                hash_config: &self.hash_config,
                diskfile_config: &self.diskfile_config,
                job: &job,
                suffixes: Some(suffixes),
                include_non_durable: false,
                max_objects: self.max_objects_per_session,
                start_after: cursor.clone(),
                sync_frag_target: None,
                diskfile_builder: None,
            };
            let Ok(mut wire) =
                TcpSsyncWire::connect(&node, &job, self.conn_timeout, self.node_timeout)
            else {
                return None;
            };
            let page = sender.run(&mut wire);
            wire.disconnect();
            let page = page.ok()?;
            aggregate.offered_count = aggregate.offered_count.checked_add(page.offered_count)?;
            if aggregate.offered_count > self.max_objects_per_partition {
                return None;
            }
            for (object_hash, timestamps) in page.can_delete_objs {
                if aggregate
                    .can_delete_objs
                    .insert(object_hash, timestamps)
                    .is_some()
                {
                    return None;
                }
            }
            aggregate.send_map.extend(page.send_map);
            aggregate.last_offered = page.last_offered.clone();
            if !page.limited_by_max_objects {
                aggregate.limited_by_max_objects = false;
                return Some(aggregate);
            }
            let next = page.last_offered?;
            if cursor.as_ref().is_some_and(|current| {
                (next.0.as_str(), next.1.as_str()) <= (current.0.as_str(), current.1.as_str())
            }) {
                return None;
            }
            cursor = Some(next);
        }
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
    let servers_per_port: u32 = get("app:object-server", "servers_per_port", "0")
        .parse()
        .unwrap_or(0);
    let mount_check = config_true_value(&get("object-replicator", "mount_check", "true"));
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

    let swift_conf_path =
        std::env::var("SWIFT_CONF").unwrap_or_else(|_| "/etc/swift/swift.conf".to_string());
    let swift_conf = parse_conf_file(&swift_conf_path);
    let hash_config = HashPathConfig::from_swift_conf(&swift_conf).unwrap_or_else(|e| {
        logger.error(&format!("bad swift.conf hash config: {e}"));
        std::process::exit(1);
    });
    let swift_dir = std::env::var("SWIFT_DIR").unwrap_or_else(|_| "/etc/swift".to_string());
    let policies = parse_storage_policies(&swift_conf).unwrap_or_else(|error| {
        logger.error(&format!("bad storage policies: {error}"));
        std::process::exit(1);
    });
    let mut replication_policies = Vec::new();
    for policy in policies
        .iter()
        .filter(|policy| policy.policy_type() == REPL_POLICY)
    {
        let ring_path = PathBuf::from(format!("{swift_dir}/{}.ring.gz", policy.ring_name()));
        let (ring, ring_identity) =
            load_ring_snapshot(&ring_path, &hash_config).unwrap_or_else(|error| {
                logger.error(&error);
                std::process::exit(1);
            });
        replication_policies.push(ReplicationPolicyState {
            index: policy.idx(),
            name: policy.name().to_string(),
            ring_path,
            ring,
            ring_identity,
        });
    }
    if replication_policies.is_empty() {
        logger.info("swift-object-replicator: no replication policies configured; exiting");
        return;
    }

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
    let conn_timeout = get("object-replicator", "conn_timeout", "0.5")
        .parse::<f64>()
        .ok()
        .filter(|value| value.is_finite() && *value >= 0.0)
        .map(Duration::from_secs_f64)
        .unwrap_or_else(|| Duration::from_millis(500));
    let node_timeout = get("object-replicator", "node_timeout", "30")
        .parse::<f64>()
        .ok()
        .filter(|value| value.is_finite() && *value > 0.0)
        .map(Duration::from_secs_f64)
        .unwrap_or_else(|| Duration::from_secs(30));
    let http_timeout = get("object-replicator", "http_timeout", "60")
        .parse::<f64>()
        .ok()
        .filter(|value| value.is_finite() && *value > 0.0)
        .map(Duration::from_secs_f64)
        .unwrap_or_else(|| Duration::from_secs(60));
    let max_objects_per_session = get(
        "object-replicator",
        "max_objects_per_ssync_session",
        "10000",
    )
    .parse::<usize>()
    .ok()
    .filter(|value| *value > 0)
    .unwrap_or(10_000);
    let max_objects_per_partition = get(
        "object-replicator",
        "max_objects_per_partition_sync",
        "100000",
    )
    .parse::<usize>()
    .ok()
    .filter(|value| *value >= max_objects_per_session)
    .unwrap_or(100_000usize.max(max_objects_per_session));
    let hash_client = HttpSuffixHashClient {
        conn_timeout,
        http_timeout,
    };
    let syncer = SsyncSuffixSyncer {
        devices: PathBuf::from(&devices),
        hash_config: hash_config.clone(),
        diskfile_config: DiskFileConfig {
            cleanup: cleanup.clone(),
            ..DiskFileConfig::default()
        },
        conn_timeout,
        node_timeout,
        max_objects_per_session,
        max_objects_per_partition,
    };
    let stop = swift_http::install_sigterm_flag();

    logger.info(&format!(
        "swift-object-replicator: devices={devices} bind_port={bind_port} \
         servers_per_port={servers_per_port} mount_check={mount_check} sync_method=ssync \
         interval={interval}s reclaim_age={reclaim_age}s once={run_once_only} policies={} ",
        replication_policies.len()
    ));
    loop {
        let pass_start = std::time::Instant::now();
        let mut total = swift_object_server::replicator::ReplicatorStats::default();
        let mut abort_pass = false;
        for policy in &mut replication_policies {
            match load_ring_snapshot(&policy.ring_path, &hash_config) {
                Ok((ring, identity)) => {
                    policy.ring = ring;
                    policy.ring_identity = identity;
                }
                Err(error) => {
                    logger.error(&format!(
                        "policy {} ring unavailable; skipping this pass: {error}",
                        policy.name
                    ));
                    total.failures += 1;
                    continue;
                }
            }
            if policy.ring.next_part_power().is_some() {
                logger.warning(&format!(
                    "next_part_power set in replication policy '{}'; skipping",
                    policy.name
                ));
                total.skipped_next_part_power = true;
                continue;
            }
            let entries = match std::fs::read_dir(&devices) {
                Ok(entries) => entries,
                Err(error) => {
                    logger.error(&format!("could not list devices root {devices}: {error}"));
                    total.failures += 1;
                    break;
                }
            };
            for entry in entries.flatten() {
                let Some(dev_name) = entry.file_name().to_str().map(str::to_string) else {
                    continue;
                };
                let path = match checked_device_path(Path::new(&devices), &dev_name, mount_check) {
                    Ok(path) => path,
                    Err(error) => {
                        logger.warning(&format!("skipping device {dev_name}: {error}"));
                        total.failures += 1;
                        continue;
                    }
                };
                let Some(local_id) =
                    ring_device_id(&policy.ring, bind_port, servers_per_port, &dev_name)
                else {
                    logger.warning(&format!(
                        "device {dev_name} is not a confirmed local member of policy {}",
                        policy.name
                    ));
                    total.failures += 1;
                    continue;
                };
                let expected_ring = policy.ring_identity;
                let ring_path = policy.ring_path.clone();
                let devices_root = PathBuf::from(&devices);
                let guarded_device = dev_name.clone();
                let mut job_guard = || {
                    if file_identity(&ring_path).ok() != Some(expected_ring) {
                        return ReplicationJobGuard::RingChanged;
                    }
                    if swift_core::constraints::check_drive(
                        &devices_root,
                        &guarded_device,
                        mount_check,
                    )
                    .is_err()
                    {
                        return ReplicationJobGuard::DeviceUnavailable;
                    }
                    ReplicationJobGuard::Continue
                };
                let stats = run_once_guarded(
                    &path,
                    &dev_name,
                    policy.index,
                    PolicyKind::Replication,
                    &cleanup,
                    &policy.ring,
                    local_id,
                    &hash_client,
                    &syncer,
                    &mut job_guard,
                );
                total.partitions += stats.partitions;
                total.suffix_syncs += stats.suffix_syncs;
                total.reverts += stats.reverts;
                total.failures += stats.failures;
                total.aborted_device |= stats.aborted_device;
                total.aborted_ring_change |= stats.aborted_ring_change;
                total.skipped_next_part_power |= stats.skipped_next_part_power;
                if stats.aborted_ring_change {
                    logger.warning(&format!(
                        "policy {} ring changed; aborting the current replication pass",
                        policy.name
                    ));
                    abort_pass = true;
                    break;
                }
                if stats.aborted_device {
                    logger.warning(&format!(
                        "device {dev_name} became unavailable; remaining jobs on it were skipped"
                    ));
                }
            }
            if abort_pass {
                break;
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
            if abort_pass || total.aborted_device {
                std::process::exit(1);
            }
            break;
        }
        if daemonutil::sleep_unless_stopped(interval, &stop) {
            logger.info("exiting on SIGTERM");
            break;
        }
    }
}

fn checked_device_path(root: &Path, device: &str, mount_check: bool) -> Result<PathBuf, String> {
    swift_core::constraints::check_drive(root, device, mount_check)
        .map_err(|error| error.to_string())
}

/// The ring device id for the local device dir, matched by (port, device name).
fn ring_device_id(
    ring: &Ring,
    bind_port: u32,
    servers_per_port: u32,
    dev_name: &str,
) -> Option<u64> {
    // Delegated: matching on (port, device) alone makes every node but the
    // first adopt another node's ring identity, because every node calls its
    // first disk d1. See `localdev`.
    if servers_per_port > 0 {
        swift_object_server::localdev::ring_device_id_local_name(ring, dev_name)
    } else {
        swift_object_server::localdev::ring_device_id(ring, bind_port, dev_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicU64, Ordering};
    use swift_http::{HeaderKeyDict, Request};
    use swift_object_server::{ContainerUpdateMode, ObjectServer, ObjectServerConfig};

    static NEXT_TMP: AtomicU64 = AtomicU64::new(0);

    fn test_root(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "swift-object-replicator-{tag}-{}-{}",
            std::process::id(),
            NEXT_TMP.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn server(root: &Path, hash_config: &HashPathConfig) -> ObjectServer {
        ObjectServer::new(ObjectServerConfig {
            devices: root.to_path_buf(),
            mount_check: false,
            hash_config: hash_config.clone(),
            diskfile: DiskFileConfig::default(),
            policies: HashMap::from([(0, PolicyKind::Replication)]),
            container_update_timeout: Duration::from_secs(1),
            container_update_mode: ContainerUpdateMode::Sync,
        })
    }

    fn request(method: &str, path: &str, body: &[u8]) -> Request {
        let mut headers = HeaderKeyDict::new();
        headers.set("X-Timestamp", "1751500001.00000");
        headers.set("Content-Type", "application/octet-stream");
        headers.set("Content-Length", &body.len().to_string());
        Request {
            method: method.to_string(),
            path: path.to_string(),
            query_string: String::new(),
            headers,
            body: body.to_vec().into(),
        }
    }

    #[test]
    fn suffix_hash_rpc_uses_replication_plane_address() {
        let peer = RingDevice {
            id: 1,
            region: 1,
            zone: 1,
            ip: "192.0.2.10".to_string(),
            port: 6200,
            replication_ip: Some("198.51.100.20".to_string()),
            replication_port: Some(16200),
            device: "sdb1".to_string(),
            weight: 1.0,
            meta: String::new(),
            extra: Default::default(),
        };
        assert_eq!(
            ring_device_socket(&peer).unwrap().to_string(),
            "198.51.100.20:16200"
        );

        let mut ipv6 = peer;
        ipv6.replication_ip = Some("2001:db8::20".to_string());
        assert_eq!(
            ring_device_socket(&ipv6).unwrap().to_string(),
            "[2001:db8::20]:16200"
        );
    }

    #[test]
    fn missing_config_and_unmounted_device_fail_closed() {
        let root = test_root("startup-safety");
        std::fs::create_dir_all(root.join("sda1")).unwrap();
        let missing = root.join("does-not-exist.conf");
        let error = load_conf_file(missing.to_str().unwrap()).unwrap_err();
        assert!(error.contains("could not read"));
        assert!(checked_device_path(&root, "sda1", false).is_ok());
        assert!(
            checked_device_path(&root, "sda1", true).is_err(),
            "an ordinary rootfs directory is not an eligible mounted device"
        );
        std::fs::write(root.join("sda1/.ismount"), b"").unwrap();
        assert!(checked_device_path(&root, "sda1", true).is_ok());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn servers_per_port_identity_uses_local_device_name_not_base_port() {
        let mut devs = vec![None; 8];
        devs[7] = Some(RingDevice {
            id: 7,
            region: 1,
            zone: 1,
            ip: "127.0.0.1".to_string(),
            port: 6217,
            replication_ip: None,
            replication_port: None,
            device: "sda1".to_string(),
            weight: 1.0,
            meta: String::new(),
            extra: Default::default(),
        });
        let data = RingData::from_parts(devs, 32, vec![vec![7u32]]);
        let ring = Ring::new(data, HashPathConfig::new("", "changeme").unwrap());
        assert_eq!(ring_device_id(&ring, 6210, 1, "sda1"), Some(7));
        assert_eq!(ring_device_id(&ring, 6210, 0, "sda1"), None);
    }

    #[test]
    fn ssync_syncer_transfers_via_object_server() {
        let source = test_root("source");
        let destination = test_root("destination");
        std::fs::create_dir_all(source.join("sda1")).unwrap();
        std::fs::create_dir_all(destination.join("sdb1")).unwrap();
        let hash_config = HashPathConfig::new("", "changeme").unwrap();
        let source_server = server(&source, &hash_config);
        let put = source_server.handle(request("PUT", "/sda1/0/a/c/o", b"through-ssync"));
        assert_eq!(put.status, 201, "source PUT failed: {put:?}");
        let put_two =
            source_server.handle(request("PUT", "/sda1/0/a/c/o-two", b"through-second-page"));
        assert_eq!(put_two.status, 201, "second source PUT failed: {put_two:?}");

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let destination_for_server = destination.clone();
        let hash_for_server = hash_config.clone();
        std::thread::spawn(move || {
            let _ = swift_object_server::serve_with_config(
                listener,
                server(&destination_for_server, &hash_for_server),
                swift_http::ServerConfig::default(),
            );
        });

        let object_hash = hash_config.hash_path("a", Some("c"), Some("o")).unwrap();
        let object_hash_two = hash_config
            .hash_path("a", Some("c"), Some("o-two"))
            .unwrap();
        let mut suffixes = vec![
            object_hash[object_hash.len() - 3..].to_string(),
            object_hash_two[object_hash_two.len() - 3..].to_string(),
        ];
        suffixes.sort();
        suffixes.dedup();
        let local_partition = source
            .join("sda1")
            .join(swift_diskfile::get_data_dir(0))
            .join("0");
        let syncer = SsyncSuffixSyncer {
            devices: source.clone(),
            hash_config: hash_config.clone(),
            diskfile_config: DiskFileConfig::default(),
            conn_timeout: Duration::from_secs(2),
            node_timeout: Duration::from_secs(5),
            max_objects_per_session: 1,
            max_objects_per_partition: 100_000,
        };
        let peer = RingDevice {
            id: 1,
            region: 1,
            zone: 1,
            ip: address.ip().to_string(),
            port: u32::from(address.port()),
            replication_ip: None,
            replication_port: None,
            device: "sdb1".to_string(),
            weight: 1.0,
            meta: String::new(),
            extra: Default::default(),
        };
        let report = syncer
            .sync_suffixes(&local_partition, &peer, "sda1", 0, &suffixes, 0)
            .expect("SSYNC transfer must complete");
        assert_eq!(report.offered_count, 2, "both bounded pages completed");
        assert!(!report.limited_by_max_objects);
        assert_eq!(
            report
                .can_delete_objs
                .get(&object_hash)
                .map(|state| state.ts_data),
            Some("1751500001.00000".parse().unwrap()),
            "a successful session must explicitly confirm the source generation"
        );
        assert!(report.can_delete_objs.contains_key(&object_hash_two));
        let mut get =
            server(&destination, &hash_config).handle(request("GET", "/sdb1/0/a/c/o", b""));
        assert_eq!(get.status, 200);
        assert_eq!(get.body.materialize(u64::MAX).unwrap(), b"through-ssync");
        let mut get_two =
            server(&destination, &hash_config).handle(request("GET", "/sdb1/0/a/c/o-two", b""));
        assert_eq!(get_two.status, 200);
        assert_eq!(
            get_two.body.materialize(u64::MAX).unwrap(),
            b"through-second-page"
        );

        let _ = std::fs::remove_dir_all(&source);
        let _ = std::fs::remove_dir_all(&destination);
    }

    #[test]
    fn handoff_purge_requires_three_real_ssync_receiver_confirmations() {
        let source = test_root("handoff-source");
        std::fs::create_dir_all(source.join("sda1")).unwrap();
        let hash_config = HashPathConfig::new("", "changeme").unwrap();
        let put = server(&source, &hash_config).handle(request(
            "PUT",
            "/sda1/0/a/c/three-primary-object",
            b"confirmed-three-times",
        ));
        assert_eq!(put.status, 201, "source PUT failed: {put:?}");

        let mut destinations = Vec::new();
        let mut peers = Vec::new();
        for id in 1..=3u64 {
            let destination = test_root(&format!("handoff-destination-{id}"));
            std::fs::create_dir_all(destination.join("sdb1")).unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let destination_for_server = destination.clone();
            let hash_for_server = hash_config.clone();
            std::thread::spawn(move || {
                let _ = swift_object_server::serve_with_config(
                    listener,
                    server(&destination_for_server, &hash_for_server),
                    swift_http::ServerConfig::default(),
                );
            });
            peers.push(RingDevice {
                id,
                region: 1,
                zone: id,
                ip: address.ip().to_string(),
                port: u32::from(address.port()),
                replication_ip: None,
                replication_port: None,
                device: "sdb1".to_string(),
                weight: 1.0,
                meta: String::new(),
                extra: Default::default(),
            });
            destinations.push(destination);
        }

        let syncer = SsyncSuffixSyncer {
            devices: source.clone(),
            hash_config: hash_config.clone(),
            diskfile_config: DiskFileConfig::default(),
            conn_timeout: Duration::from_secs(2),
            node_timeout: Duration::from_secs(5),
            max_objects_per_session: 10_000,
            max_objects_per_partition: 100_000,
        };
        let partition = source
            .join("sda1")
            .join(swift_diskfile::get_data_dir(0))
            .join("0");
        let peer_refs: Vec<&RingDevice> = peers.iter().collect();
        let mut stats = swift_object_server::replicator::ReplicatorStats::default();
        assert!(swift_object_server::replicator::revert_handoff(
            &partition, "sda1", 0, 0, &peer_refs, &syncer, &mut stats,
        ));
        assert_eq!(stats.reverts, 1);
        assert_eq!(stats.failures, 0);
        assert_eq!(
            stats.suffix_syncs, 3,
            "one suffix confirmed by each primary"
        );

        let source_get = server(&source, &hash_config).handle(request(
            "GET",
            "/sda1/0/a/c/three-primary-object",
            b"",
        ));
        assert_eq!(source_get.status, 404, "confirmed handoff must be purged");
        for destination in &destinations {
            let mut get = server(destination, &hash_config).handle(request(
                "GET",
                "/sdb1/0/a/c/three-primary-object",
                b"",
            ));
            assert_eq!(get.status, 200);
            assert_eq!(
                get.body.materialize(u64::MAX).unwrap(),
                b"confirmed-three-times"
            );
        }

        let _ = std::fs::remove_dir_all(source);
        for destination in destinations {
            let _ = std::fs::remove_dir_all(destination);
        }
    }

    #[test]
    fn handoff_source_survives_one_real_primary_transport_failure() {
        let source = test_root("handoff-failure-source");
        let destination = test_root("handoff-failure-destination");
        std::fs::create_dir_all(source.join("sda1")).unwrap();
        std::fs::create_dir_all(destination.join("sdb1")).unwrap();
        let hash_config = HashPathConfig::new("", "changeme").unwrap();
        assert_eq!(
            server(&source, &hash_config)
                .handle(request(
                    "PUT",
                    "/sda1/0/a/c/must-survive",
                    b"source-authority",
                ))
                .status,
            201
        );

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let live_address = listener.local_addr().unwrap();
        let destination_for_server = destination.clone();
        let hash_for_server = hash_config.clone();
        std::thread::spawn(move || {
            let _ = swift_object_server::serve_with_config(
                listener,
                server(&destination_for_server, &hash_for_server),
                swift_http::ServerConfig::default(),
            );
        });
        let closed_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let closed_address = closed_listener.local_addr().unwrap();
        drop(closed_listener);

        let peer = |id: u64, address: std::net::SocketAddr| RingDevice {
            id,
            region: 1,
            zone: id,
            ip: address.ip().to_string(),
            port: u32::from(address.port()),
            replication_ip: None,
            replication_port: None,
            device: "sdb1".to_string(),
            weight: 1.0,
            meta: String::new(),
            extra: Default::default(),
        };
        let peers = vec![
            peer(1, live_address),
            peer(2, live_address),
            peer(3, closed_address),
        ];
        let peer_refs: Vec<&RingDevice> = peers.iter().collect();
        let syncer = SsyncSuffixSyncer {
            devices: source.clone(),
            hash_config: hash_config.clone(),
            diskfile_config: DiskFileConfig::default(),
            conn_timeout: Duration::from_millis(200),
            node_timeout: Duration::from_secs(2),
            max_objects_per_session: 10_000,
            max_objects_per_partition: 100_000,
        };
        let partition = source
            .join("sda1")
            .join(swift_diskfile::get_data_dir(0))
            .join("0");
        let mut stats = swift_object_server::replicator::ReplicatorStats::default();
        assert!(!swift_object_server::replicator::revert_handoff(
            &partition, "sda1", 0, 0, &peer_refs, &syncer, &mut stats,
        ));
        assert_eq!(stats.reverts, 0);
        assert_eq!(stats.failures, 1);
        let mut get =
            server(&source, &hash_config).handle(request("GET", "/sda1/0/a/c/must-survive", b""));
        assert_eq!(get.status, 200, "one failed primary must retain source");
        assert_eq!(get.body.materialize(u64::MAX).unwrap(), b"source-authority");

        let _ = std::fs::remove_dir_all(source);
        let _ = std::fs::remove_dir_all(destination);
    }
}
