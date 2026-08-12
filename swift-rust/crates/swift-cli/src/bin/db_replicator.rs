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

//! `swift-db-replicator <account|container> <server.conf> [once]`: the account
//! and container DB replicator daemon. Python ships these as two commands
//! (`swift-account-replicator` / `swift-container-replicator`); this one binary
//! selects the server type from its first argument.
//!
//! The partition sweep + ring-based peer rotation already live in swift-db's
//! `repl_loop` (`replicator_run_once`); this binary supplies a real
//! `DbReplicateClient` that opens the local broker and
//! pushes to the peer via the sync/usync RPC ([`swift_db::replicate_container_db`]
//! / [`swift_db::replicate_account_db`]), falling back to a staged full-DB
//! rsync when the peer has no DB yet (`complete_rsync`) or usync cannot
//! converge it (`rsync_then_merge`): the DB file is staged into the peer's
//! `<device>/tmp/<local-db-id>` and a REPLICATE RPC tells the peer to
//! adopt/merge it (Python `_rsync_db`, db_replicator.py:379-412).
//! Single-host SAIO reaches peers at `127.0.0.1:<ring-port>` for the RPC,
//! and takes their device roots from a
//! `[<type>-replicator] peer_map = <port>:<devices-root>,...` conf option.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use swift_cli::daemon;
use swift_core::config::SwiftConfig;
use swift_core::hashing::HashPathConfig;
use swift_core::obslog::{LogLevel, Logger};
use swift_core::statsd::StatsdClient;
use swift_db::{
    replicate_account_db, replicate_completion_rpc, replicate_container_db,
    replicator_run_once as run_once, rsync_db, AccountBroker, ContainerBroker, DbPartition,
    DbReplicateClient, RsyncTransport,
};
use swift_ring::{Ring, RingData, RingDevice};

#[derive(Clone, Copy, PartialEq)]
enum ServerType {
    Account,
    Container,
}

impl ServerType {
    fn datadir(self) -> &'static str {
        match self {
            ServerType::Account => "accounts",
            ServerType::Container => "containers",
        }
    }
    fn section(self) -> &'static str {
        match self {
            ServerType::Account => "app:account-server",
            ServerType::Container => "app:container-server",
        }
    }
    fn repl_section(self) -> &'static str {
        match self {
            ServerType::Account => "account-replicator",
            ServerType::Container => "container-replicator",
        }
    }
    fn ring_name(self) -> &'static str {
        match self {
            ServerType::Account => "account.ring.gz",
            ServerType::Container => "container.ring.gz",
        }
    }
    /// The recon cache file Python's recon middleware and `swift-recon` read
    /// for this server type.
    fn recon_file(self) -> &'static str {
        match self {
            ServerType::Account => "account.recon",
            ServerType::Container => "container.recon",
        }
    }
}

fn parse_conf_file(path: &str) -> SwiftConfig {
    let content = std::fs::read_to_string(path).unwrap_or_default();
    SwiftConfig::parse_lenient(&content, &[], false).unwrap_or_else(|e| {
        eprintln!("could not parse {path}: {e}");
        std::process::exit(1);
    })
}

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

/// Full-DB rsync fallback: the DB is STAGED into the peer's
/// `<device>/tmp/<stage>` (never written onto its live db path; the peer
/// adopts it via the complete_rsync / rsync_then_merge RPC). `Local`
/// (single-host SAIO) targets a filesystem path from the port->root peer
/// map; `Ssh` (cross-machine) targets `root@<peer-ip>:<devices-root>`
/// over ssh.
enum DbRsyncDest {
    Local {
        peer_map: HashMap<u32, PathBuf>,
        port_of: HashMap<String, u32>,
    },
    Ssh {
        devices_root: String,
        ssh_opts: String,
    },
}

struct DbRsync {
    dest: DbRsyncDest,
}

impl DbRsync {
    /// The rsync destination for staging a DB into the peer's
    /// `<device>/tmp/<stage_name>` receiving area (`_rsync_db`'s
    /// `rsync_path = '%s/tmp/%s' % (device['device'], local_id)`,
    /// db_replicator.py:394-395), plus the `-e` ssh options in Ssh mode.
    /// `None` when the peer is not in the Local peer map.
    fn rsync_dest(
        &self,
        peer_host: &str,
        peer_device: &str,
        stage_name: &str,
    ) -> Option<(String, Option<&str>)> {
        let rel = format!("{peer_device}/tmp/{stage_name}");
        match &self.dest {
            DbRsyncDest::Local { peer_map, port_of } => {
                let port = port_of.get(peer_host).copied()?;
                let root = peer_map.get(&port)?;
                Some((format!("{}/{rel}", root.display()), None))
            }
            DbRsyncDest::Ssh {
                devices_root,
                ssh_opts,
            } => {
                // peer_host is "ip:port"; the rsync target is root@ip:<root>/<rel>.
                let ip = peer_host.split(':').next().unwrap_or(peer_host);
                Some((
                    format!("root@{ip}:{devices_root}/{rel}"),
                    Some(ssh_opts.as_str()),
                ))
            }
        }
    }
}

impl RsyncTransport for DbRsync {
    fn rsync(&self, local_db: &Path, peer_host: &str, peer_device: &str, stage_name: &str) -> bool {
        let Some((dest, ssh)) = self.rsync_dest(peer_host, peer_device, stage_name) else {
            return false;
        };
        let mut cmd = std::process::Command::new("rsync");
        cmd.args(["--whole-file", "--ignore-times", "--mkpath"]);
        if let Some(opts) = ssh {
            cmd.arg("-e").arg(opts);
        }
        cmd.arg(local_db).arg(dest);
        matches!(cmd.status(), Ok(s) if s.success())
    }

    fn complete(
        &self,
        peer_host: &str,
        peer_device: &str,
        partition: &str,
        hsh: &str,
        op: &str,
        stage_name: &str,
    ) -> bool {
        // The receive-side op that adopts (complete_rsync) or merges
        // (rsync_then_merge) the staged DB (db_replicator.py:409-412).
        matches!(
            replicate_completion_rpc(peer_host, peer_device, partition, hsh, op, stage_name),
            Ok(true)
        )
    }
}

/// Opens the local broker for a found DB and pushes it to a peer.
struct DbClient {
    server: ServerType,
    rsync: DbRsync,
}

impl DbReplicateClient for DbClient {
    fn replicate(&self, db: &DbPartition, peer: &RingDevice) -> bool {
        let peer_host = format!("{}:{}", peer.ip, peer.port);
        let partition = db.partition.to_string();
        match self.server {
            ServerType::Container => {
                let mut broker = ContainerBroker::new(&db.path, "", "");
                let local_id = broker_id(broker.get_replication_info().ok());
                match replicate_container_db(
                    &mut broker,
                    &local_id,
                    &peer_host,
                    &peer.device,
                    &partition,
                    &db.hash,
                ) {
                    // peer had no DB at all: stage the whole DB into the
                    // peer's tmp dir and have it adopted (complete_rsync,
                    // db_replicator.py:553-557)
                    Ok(outcome) if outcome.needs_rsync => rsync_db(
                        &db.path,
                        &local_id,
                        &peer_host,
                        &peer.device,
                        &partition,
                        &db.hash,
                        "complete_rsync",
                        &self.rsync,
                    ),
                    // usync can't converge the peer: stage the DB and have
                    // the peer merge its own rows into it before adopting
                    // (rsync_then_merge, db_replicator.py:579-591)
                    Ok(outcome) if outcome.usync_incomplete => rsync_db(
                        &db.path,
                        &local_id,
                        &peer_host,
                        &peer.device,
                        &partition,
                        &db.hash,
                        "rsync_then_merge",
                        &self.rsync,
                    ),
                    Ok(_) => true,
                    Err(e) => {
                        eprintln!("db-replicator: container push to {peer_host} failed: {e}");
                        false
                    }
                }
            }
            ServerType::Account => {
                let mut broker = AccountBroker::new(&db.path, "");
                let local_id = broker_id(broker.get_replication_info().ok());
                match replicate_account_db(
                    &mut broker,
                    &local_id,
                    &peer_host,
                    &peer.device,
                    &partition,
                    &db.hash,
                ) {
                    Ok(outcome) if outcome.needs_rsync => rsync_db(
                        &db.path,
                        &local_id,
                        &peer_host,
                        &peer.device,
                        &partition,
                        &db.hash,
                        "complete_rsync",
                        &self.rsync,
                    ),
                    Ok(outcome) if outcome.usync_incomplete => rsync_db(
                        &db.path,
                        &local_id,
                        &peer_host,
                        &peer.device,
                        &partition,
                        &db.hash,
                        "rsync_then_merge",
                        &self.rsync,
                    ),
                    Ok(_) => true,
                    Err(e) => {
                        eprintln!("db-replicator: account push to {peer_host} failed: {e}");
                        false
                    }
                }
            }
        }
    }
}

/// The local DB's own id (the stable sync source), read from replication info.
fn broker_id(info: Option<Vec<(String, swift_db::DbValue)>>) -> String {
    info.and_then(|i| {
        i.iter().find(|(k, _)| k == "id").map(|(_, v)| match v {
            swift_db::DbValue::Text(s) => s.clone(),
            swift_db::DbValue::Int(n) => n.to_string(),
            swift_db::DbValue::Null => String::new(),
        })
    })
    .unwrap_or_default()
}

fn ring_device_id(ring: &Ring, bind_port: u32, dev_name: &str) -> Option<u64> {
    ring.devs()
        .iter()
        .flatten()
        .find(|d| d.port == bind_port && d.device == dev_name)
        .map(|d| d.id)
}

fn main() {
    // Support two invocation styles so Python swift-init/Manager can drive us:
    //   swift-db-replicator <account|container> <conf> [once]   (native)
    //   swift-account-replicator <conf> [once]                  (argv[0] picks mode)
    //   swift-container-replicator <conf> [once]
    let argv0 = std::env::args().next().unwrap_or_default();
    let base = argv0.rsplit('/').next().unwrap_or("");
    let (server, arg_shift) = if base.contains("account-replicator") {
        (ServerType::Account, 0) // conf at argv[1]
    } else if base.contains("container-replicator") {
        (ServerType::Container, 0)
    } else {
        // native form: mode is argv[1], conf/once shifted by one
        let mode = std::env::args().nth(1).unwrap_or_default();
        let s = match mode.as_str() {
            "account" => ServerType::Account,
            "container" => ServerType::Container,
            _ => {
                eprintln!(
                    "usage: swift-db-replicator <account|container> <server.conf> [once]\n\
                     (or invoke as swift-account-replicator / swift-container-replicator)"
                );
                std::process::exit(2);
            }
        };
        (s, 1)
    };
    let conf_path = std::env::args().nth(1 + arg_shift).unwrap_or_else(|| {
        format!(
            "/etc/swift/{}-server.conf",
            match server {
                ServerType::Account => "account",
                ServerType::Container => "container",
            }
        )
    });
    let run_once_only = std::env::args().nth(2 + arg_shift).as_deref() == Some("once");
    let conf = parse_conf_file(&conf_path);
    let get = |section: &str, key: &str, default: &str| -> String {
        conf.get(section, key)
            .ok()
            .flatten()
            .or_else(|| conf.get("DEFAULT", key).ok().flatten())
            .unwrap_or_else(|| default.to_string())
    };
    let devices = get(server.section(), "devices", "/srv/node");
    let default_port = match server {
        ServerType::Account => "6012",
        ServerType::Container => "6011",
    };
    let bind_port: u32 = get(server.section(), "bind_port", default_port)
        .parse()
        .unwrap_or(0);
    let interval: u64 = get(server.repl_section(), "interval", "30")
        .parse()
        .unwrap_or(30);
    let log_name = get(server.repl_section(), "log_name", server.repl_section());
    let log_level = get(server.repl_section(), "log_level", "INFO")
        .parse::<LogLevel>()
        .unwrap_or(LogLevel::Info);
    let logger = Logger::with_syslog(&log_name, log_level);
    let statsd = StatsdClient::new(
        &get(server.repl_section(), "log_statsd_host", ""),
        get(server.repl_section(), "log_statsd_port", "8125")
            .parse()
            .unwrap_or(8125),
        &daemon::statsd_prefix(
            &get(server.repl_section(), "log_statsd_metric_prefix", ""),
            server.repl_section(),
        ),
    );
    let recon_cache_path = get(
        server.repl_section(),
        "recon_cache_path",
        "/var/cache/swift",
    );
    // Cross-machine rsync-over-ssh when `rsync_ssh_opts` is set; otherwise the
    // single-host local `peer_map = port:/local/root` model.
    let rsync_ssh_opts = get(server.repl_section(), "rsync_ssh_opts", "");
    let rsync_dest = if rsync_ssh_opts.is_empty() {
        let peer_map = parse_peer_map(&get(server.repl_section(), "peer_map", ""));
        let port_of: HashMap<String, u32> = peer_map
            .keys()
            .map(|p| (format!("127.0.0.1:{p}"), *p))
            .collect();
        DbRsyncDest::Local { peer_map, port_of }
    } else {
        DbRsyncDest::Ssh {
            devices_root: get(server.repl_section(), "rsync_devices_root", "/srv/node"),
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
    let ring_path = format!("{swift_dir}/{}", server.ring_name());
    // A missing ring at startup is fatal; per-pass reloads below fall back to
    // the previous ring.
    let mut ring = Ring::new(
        RingData::load(Path::new(&ring_path)).unwrap_or_else(|e| {
            logger.error(&format!("could not load {ring_path}: {e}"));
            std::process::exit(1);
        }),
        hash_config.clone(),
    );

    let client = DbClient {
        server,
        rsync: DbRsync { dest: rsync_dest },
    };
    let stop = swift_http::install_sigterm_flag();

    logger.info(&format!(
        "swift-db-replicator[{}]: devices={devices} bind_port={bind_port} \
         interval={interval}s once={run_once_only}",
        server.datadir()
    ));
    loop {
        let pass_start_epoch = daemon::epoch_secs_now();
        let (mut attempted, mut successes, mut failures) = (0u64, 0u64, 0u64);
        if let Ok(entries) = std::fs::read_dir(&devices) {
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_dir() {
                    continue;
                }
                let Some(dev_name) = path.file_name().and_then(|s| s.to_str()) else {
                    continue;
                };
                let Some(local_id) = ring_device_id(&ring, bind_port, dev_name) else {
                    continue;
                };
                let stats = run_once(&path, server.datadir(), &ring, local_id, &client);
                attempted += stats.attempted;
                successes += stats.successes;
                failures += stats.failures;
            }
        }
        logger.info(&format!(
            "db-replicator[{}] pass: attempted={attempted} successes={successes} failures={failures}",
            server.datadir()
        ));
        statsd.update_stats("successes", successes as i64);
        statsd.update_stats("failures", failures as i64);
        let update = daemon::db_replicator_recon_update(
            attempted,
            successes,
            failures,
            pass_start_epoch,
            daemon::epoch_secs_now(),
        );
        if let Err(e) = daemon::dump_recon(&recon_cache_path, server.recon_file(), &update) {
            logger.warning(&format!(
                "could not dump recon cache to {recon_cache_path}/{}: {e}",
                server.recon_file()
            ));
        }
        if run_once_only {
            break;
        }
        if daemon::sleep_unless_stopped(interval, &stop) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rsync_dest_local_stages_into_peer_tmp() {
        // Local mode stages into <peer root>/<device>/tmp/<stage_name>
        // (_rsync_db's rsync_path, db_replicator.py:394-395), never onto
        // the peer's live db path.
        let peer_map: HashMap<u32, PathBuf> = [(6011u32, PathBuf::from("/srv/node2"))]
            .into_iter()
            .collect();
        let port_of: HashMap<String, u32> = [("127.0.0.1:6011".to_string(), 6011u32)]
            .into_iter()
            .collect();
        let rsync = DbRsync {
            dest: DbRsyncDest::Local { peer_map, port_of },
        };
        let (dest, ssh) = rsync
            .rsync_dest("127.0.0.1:6011", "sdb1", "local-uuid-id")
            .unwrap();
        assert_eq!(dest, "/srv/node2/sdb1/tmp/local-uuid-id");
        assert!(ssh.is_none());
        // a peer missing from the map has no destination
        assert!(rsync.rsync_dest("127.0.0.1:9999", "sdb1", "x").is_none());
    }

    #[test]
    fn test_rsync_dest_ssh_stages_into_remote_tmp() {
        let rsync = DbRsync {
            dest: DbRsyncDest::Ssh {
                devices_root: "/srv/node".to_string(),
                ssh_opts: "ssh -i /root/.ssh/id".to_string(),
            },
        };
        let (dest, ssh) = rsync
            .rsync_dest("10.0.0.7:6011", "sdb7", "some-db-id")
            .unwrap();
        assert_eq!(dest, "root@10.0.0.7:/srv/node/sdb7/tmp/some-db-id");
        assert_eq!(ssh, Some("ssh -i /root/.ssh/id"));
    }
}
