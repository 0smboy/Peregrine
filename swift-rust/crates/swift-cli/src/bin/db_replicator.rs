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
use swift_core::timestamp::{decode_timestamps, Timestamp};
use swift_db::{
    replicate_account_db, replicate_completion_rpc, replicate_container_db_role,
    replicator_run_once as run_once, rsync_db, AccountBroker, ContainerBroker, DbError,
    DbPartition, DbReplicateClient, DbState, DbValue, ObjectRecord, RsyncTransport,
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
                // Probe/SAIO rings bind 127.0.0.1:16211,
                // 127.0.0.2:16221, and so on. `port_of` is keyed by the
                // local listener address, so an exact lookup can miss a
                // primary whose ring host uses another loopback address.
                // The port uniquely identifies that local server root;
                // otherwise the handoff is never staged (probe L2938/L3024).
                let port = port_of.get(peer_host).copied().or_else(|| {
                    peer_host
                        .rsplit_once(':')
                        .and_then(|(_, port)| port.parse().ok())
                        .filter(|port| peer_map.contains_key(port))
                })?;
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
            eprintln!("db-replicator: rsync dest missing peer={peer_host} device={peer_device}");
            return false;
        };
        let mut cmd = std::process::Command::new("rsync");
        cmd.args(["--whole-file", "--ignore-times", "--mkpath"]);
        if let Some(opts) = ssh {
            cmd.arg("-e").arg(opts);
        }
        cmd.arg(local_db).arg(&dest);
        let ok = matches!(cmd.status(), Ok(s) if s.success());
        if !ok {
            eprintln!("db-replicator: rsync failed peer={peer_host} dest={dest}");
        }
        ok
    }

    fn complete(
        &self,
        peer_host: &str,
        peer_device: &str,
        partition: &str,
        hsh: &str,
        op: &str,
        stage_name: &str,
        dest_db_name: &str,
    ) -> bool {
        // The receive-side op that adopts (complete_rsync) or merges
        // (rsync_then_merge) the staged DB (db_replicator.py:409-412).
        matches!(
            replicate_completion_rpc(
                peer_host,
                peer_device,
                partition,
                hsh,
                op,
                stage_name,
                dest_db_name,
            ),
            Ok(true)
        )
    }
}

/// Probe L1356: `CleavingContext.load_all` / `done()` on every replica.
/// Skip-epoch full-file rsync no longer copies Context-* sysmeta, so a
/// SHARDED container must rewrite every stored context as done before usync.
fn mark_sharded_cleaving_contexts_done(broker: &mut ContainerBroker) {
    match broker.get_db_state() {
        Ok(DbState::Sharded) => {}
        _ => return,
    }
    let ts = Timestamp::now().internal();
    let Ok(md) = broker.metadata() else {
        return;
    };
    let mut updates = Vec::new();
    for (k, (v, _)) in md {
        if v.is_empty() {
            continue;
        }
        let lk = k.to_ascii_lowercase();
        if !lk.starts_with("x-container-sysmeta-shard-context-")
            && lk != "x-container-sysmeta-shard-cleaving-context"
        {
            continue;
        }
        let Ok(mut val) = serde_json::from_str::<serde_json::Value>(&v) else {
            continue;
        };
        let Some(obj) = val.as_object_mut() else {
            continue;
        };
        obj.insert("cleaving_done".into(), serde_json::Value::Bool(true));
        obj.insert("misplaced_done".into(), serde_json::Value::Bool(true));
        let to = obj
            .get("cleave_to_row")
            .and_then(|x| x.as_i64())
            .or_else(|| obj.get("max_row").and_then(|x| x.as_i64()))
            .unwrap_or(0);
        obj.insert("max_row".into(), serde_json::json!(to));
        updates.push((k, (val.to_string(), ts.clone())));
    }
    if !updates.is_empty() {
        let _ = broker.update_metadata(&updates);
    }
}

/// Opens the local broker for a found DB and pushes it to a peer.
struct DbClient {
    server: ServerType,
    rsync: DbRsync,
    hash_config: HashPathConfig,
}

const MISPLACED_OBJECTS_ACCOUNT: &str = ".misplaced_objects";
const RECONCILER_BATCH_SIZE: i64 = 1000;

fn reconciler_container_name(created_at: &str) -> Option<String> {
    let (data, _ctype, meta) = decode_timestamps(created_at, false).ok()?;
    let timestamp = meta.unwrap_or(data).as_secs_f64() as i64;
    Some((timestamp.div_euclid(3600) * 3600).to_string())
}

fn reconciler_object_name(
    policy_index: i64,
    account: &str,
    container: &str,
    object: &str,
) -> String {
    format!("{policy_index}:/{account}/{container}/{object}")
}

fn source_device_path(db: &DbPartition) -> Option<&Path> {
    // <device>/containers/<part>/<suffix>/<hash>/<hash>.db
    db.path.ancestors().nth(5)
}

impl DbClient {
    fn feed_reconciler(
        &self,
        source_db: &DbPartition,
        ring: &Ring,
        account: &str,
        container: &str,
        row: &ObjectRecord,
    ) -> bool {
        let Some(queue_container) = reconciler_container_name(&row.created_at) else {
            return false;
        };
        let Ok(partition) = ring.get_part(MISPLACED_OBJECTS_ACCOUNT, Some(&queue_container), None)
        else {
            return false;
        };
        let Some(device) = source_device_path(source_db) else {
            return false;
        };
        let Ok(hash) =
            self.hash_config
                .hash_path(MISPLACED_OBJECTS_ACCOUNT, Some(&queue_container), None)
        else {
            return false;
        };
        let suffix = &hash[hash.len().saturating_sub(3)..];
        let db_path = device
            .join("containers")
            .join(partition.to_string())
            .join(suffix)
            .join(&hash)
            .join(format!("{hash}.db"));
        if std::fs::create_dir_all(db_path.parent().unwrap_or(device)).is_err() {
            return false;
        }

        let mut queue = ContainerBroker::new(&db_path, MISPLACED_OBJECTS_ACCOUNT, &queue_container);
        if !queue.db_exists() {
            let id = format!(
                "reconciler-{}-{}",
                std::process::id(),
                Timestamp::now().internal()
            );
            match queue.initialize(&queue_container, 0, &queue_container, &id) {
                Ok(()) | Err(DbError::AlreadyExists(_)) => {}
                Err(e) => {
                    eprintln!("db-replicator: create reconciler DB failed: {e}");
                    return false;
                }
            }
        }

        let queue_row = ObjectRecord {
            name: reconciler_object_name(row.storage_policy_index, account, container, &row.name),
            created_at: row.created_at.clone(),
            size: 0,
            content_type: if row.deleted == 0 {
                "application/x-put".to_string()
            } else {
                "application/x-delete".to_string()
            },
            etag: row.created_at.clone(),
            deleted: 0,
            storage_policy_index: 0,
            ctype_timestamp: None,
            meta_timestamp: None,
        };
        match queue.merge_items(vec![queue_row]) {
            Ok(()) => {
                eprintln!(
                    "db-replicator: reconciler enqueue account={account} container={container} object={} source_policy={} bucket={queue_container}",
                    row.name, row.storage_policy_index
                );
                true
            }
            Err(e) => {
                eprintln!("db-replicator: reconciler enqueue failed: {e}");
                false
            }
        }
    }
}

fn info_text(info: &[(String, DbValue)], key: &str) -> Option<String> {
    info.iter()
        .find(|(k, _)| k == key)
        .and_then(|(_, v)| match v {
            DbValue::Text(s) if !s.is_empty() => Some(s.clone()),
            _ => None,
        })
}

impl DbReplicateClient for DbClient {
    fn keep_handoff(&self, db: &DbPartition) -> bool {
        if self.server != ServerType::Container {
            return false;
        }
        // Must read account/container from container_stat. A blank path
        // synthesizes an ACTIVE own, so sharding_initiated() is false even
        // when the on-disk own is SHARDED (probe L2972).
        let mut probe = ContainerBroker::new(&db.path, "", "");
        let info = match probe.get_info() {
            Ok(info) => info,
            Err(_) => return probe.sharding_required().unwrap_or(false),
        };
        let account = info
            .iter()
            .find(|(key, _)| key == "account")
            .and_then(|(_, value)| value.as_text())
            .unwrap_or_default();
        let container = info
            .iter()
            .find(|(key, _)| key == "container")
            .and_then(|(_, value)| value.as_text())
            .unwrap_or_default();
        let mut broker = if account.is_empty() {
            probe
        } else {
            ContainerBroker::new(&db.path, &account, &container)
        };
        broker.sharding_required().unwrap_or(false)
    }

    fn db_max_row(&self, db: &DbPartition) -> i64 {
        match self.server {
            ServerType::Container => {
                let mut broker = ContainerBroker::new(&db.path, "", "");
                broker.get_max_row().ok().flatten().unwrap_or(-1)
            }
            ServerType::Account => {
                let mut broker = AccountBroker::new(&db.path, "");
                broker.get_max_row().ok().flatten().unwrap_or(-1)
            }
        }
    }

    fn db_account_container(&self, db: &DbPartition) -> Option<(String, Option<String>)> {
        match self.server {
            ServerType::Container => {
                let mut broker = ContainerBroker::new(&db.path, "", "");
                let info = broker.get_info().ok()?;
                Some((info_text(&info, "account")?, info_text(&info, "container")))
            }
            ServerType::Account => {
                let mut broker = AccountBroker::new(&db.path, "");
                let info = broker.get_info().ok()?;
                Some((info_text(&info, "account")?, None))
            }
        }
    }

    fn replicate(&self, db: &DbPartition, peer: &RingDevice) -> bool {
        let peer_host = format!("{}:{}", peer.ip, peer.port);
        let partition = db.partition.to_string();
        match self.server {
            ServerType::Container => {
                let mut broker = ContainerBroker::new(&db.path, "", "");
                // Skip-epoch rsync no longer copies sysmeta. After nested
                // complete the local Context-* is done but peer keys stay
                // False (probe L1356). Force them done on SHARDED DBs so
                // usync/metadata merge matches Python whole-file rsync.
                mark_sharded_cleaving_contexts_done(&mut broker);
                let local_id = broker_id(broker.get_replication_info().ok());
                match replicate_container_db_role(
                    &mut broker,
                    &local_id,
                    &peer_host,
                    &peer.device,
                    &partition,
                    &db.hash,
                    db.is_handoff,
                ) {
                    // peer had no DB at all: stage the whole DB into the
                    // peer's tmp dir and have it adopted (complete_rsync,
                    // db_replicator.py:553-557)
                    Ok(outcome) if outcome.needs_rsync => {
                        // `rsync_db` preserves an epoch suffix in the
                        // completion destination. The older guard assumed
                        // every destination was `<hash>.db`; keeping it here
                        // suppresses the only whole-DB transfer to an empty
                        // new primary (probe L3024/L2938). The receive side,
                        // not this staging guard, enforces L1347.
                        rsync_db(
                            &db.path,
                            &local_id,
                            &peer_host,
                            &peer.device,
                            &partition,
                            &db.hash,
                            "complete_rsync",
                            &self.rsync,
                        )
                    }
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

    fn post_replicate(&self, db: &DbPartition, ring: &Ring, responses: &[bool]) {
        if self.server != ServerType::Container {
            return;
        }
        let mut broker = ContainerBroker::new(&db.path, "", "");
        if broker.hydrate_account_container().is_err() {
            return;
        }
        let Ok(info) = broker.get_replication_info() else {
            return;
        };
        let Some(account) = info_text(&info, "account") else {
            return;
        };
        let Some(container) = info_text(&info, "container") else {
            return;
        };
        if account == MISPLACED_OBJECTS_ACCOUNT {
            return;
        }
        let Ok(point) = broker.get_reconciler_sync() else {
            return;
        };
        let max_row = broker.get_max_row().ok().flatten().unwrap_or(-1);
        if !broker.has_multiple_policies().unwrap_or(false) {
            if max_row != point {
                let _ = broker.update_reconciler_sync(max_row);
            }
            return;
        }

        let mut cursor = point;
        let mut durable_point = point;
        let mut errors = false;
        let mut first_batch = true;
        loop {
            let Ok(rows) = broker.get_misplaced_since(cursor, RECONCILER_BATCH_SIZE) else {
                return;
            };
            if rows.is_empty() {
                // Python `dump_to_reconciler`: when there was no misplaced
                // row at all after `point`, the whole DB through max_row is
                // known clean and may be checkpointed after the peer quorum.
                if first_batch {
                    durable_point = max_row;
                }
                break;
            }
            first_batch = false;
            for (_, row) in &rows {
                if !self.feed_reconciler(db, ring, &account, &container, row) {
                    errors = true;
                }
            }
            cursor = rows.last().map(|(rowid, _)| *rowid).unwrap_or(cursor);
            // Once any queue write fails, never checkpoint beyond the gap,
            // even if later batches succeed. Otherwise a restart could skip
            // the failed row forever.
            if !errors {
                durable_point = cursor;
            }
            if rows.len() < RECONCILER_BATCH_SIZE as usize {
                break;
            }
        }

        let successes = responses.iter().filter(|&&ok| ok).count();
        let majority = responses.len() / 2 + 1;
        if durable_point > point && !responses.is_empty() && successes >= majority {
            if let Err(e) = broker.update_reconciler_sync(durable_point) {
                eprintln!("db-replicator: update reconciler sync failed: {e}");
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
        hash_config: hash_config.clone(),
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

    fn one_partition_ring(hash_config: HashPathConfig) -> Ring {
        let device = RingDevice {
            id: 0,
            region: 1,
            zone: 1,
            ip: "127.0.0.1".to_string(),
            port: 6011,
            replication_ip: None,
            replication_port: None,
            device: "sda".to_string(),
            weight: 1.0,
            meta: String::new(),
            extra: Default::default(),
        };
        Ring::new(
            RingData::from_parts(vec![Some(device)], 32, vec![vec![0]]),
            hash_config,
        )
    }

    fn test_db_client(hash_config: HashPathConfig) -> DbClient {
        DbClient {
            server: ServerType::Container,
            rsync: DbRsync {
                dest: DbRsyncDest::Local {
                    peer_map: HashMap::new(),
                    port_of: HashMap::new(),
                },
            },
            hash_config,
        }
    }

    #[test]
    fn test_feed_reconciler_creates_resumable_queue_entry() {
        let root = std::env::temp_dir().join(format!(
            "swift-reconciler-feed-{}-{}",
            std::process::id(),
            Timestamp::now().raw()
        ));
        let source_hash = "11111111111111111111111111111111";
        let source_path = root
            .join("sda/containers/0/111")
            .join(source_hash)
            .join(format!("{source_hash}.db"));
        std::fs::create_dir_all(source_path.parent().unwrap()).unwrap();
        let source = DbPartition {
            partition: 0,
            hash: source_hash.to_string(),
            path: source_path,
            is_handoff: false,
        };
        let hash_config = HashPathConfig::new("test-prefix", "test-suffix").unwrap();
        let ring = one_partition_ring(hash_config.clone());
        let client = test_db_client(hash_config.clone());
        let created_at = "1700000000.12345";
        let row = ObjectRecord {
            name: "nested/object".to_string(),
            created_at: created_at.to_string(),
            size: 99,
            content_type: "application/octet-stream".to_string(),
            etag: "source-etag".to_string(),
            deleted: 0,
            storage_policy_index: 2,
            ctype_timestamp: None,
            meta_timestamp: None,
        };

        assert!(client.feed_reconciler(&source, &ring, "AUTH_test", "ec", &row));

        let bucket = reconciler_container_name(created_at).unwrap();
        let queue_hash = hash_config
            .hash_path(MISPLACED_OBJECTS_ACCOUNT, Some(&bucket), None)
            .unwrap();
        let queue_path = root
            .join("sda/containers/0")
            .join(&queue_hash[queue_hash.len() - 3..])
            .join(&queue_hash)
            .join(format!("{queue_hash}.db"));
        let mut queue = ContainerBroker::new(&queue_path, MISPLACED_OBJECTS_ACCOUNT, &bucket);
        let queued = queue.get_items_since(-1, 10).unwrap();
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].1.name, "2:/AUTH_test/ec/nested/object");
        assert_eq!(queued[0].1.created_at, created_at);
        assert_eq!(queued[0].1.etag, created_at);
        assert_eq!(queued[0].1.content_type, "application/x-put");
        assert_eq!(queued[0].1.deleted, 0);
        assert_eq!(queued[0].1.storage_policy_index, 0);
        std::fs::remove_dir_all(root).unwrap();
    }

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
    fn test_rsync_dest_local_matches_ring_ip_by_port() {
        // G6 probe ring: 127.0.0.1:16211 .. 127.0.0.4:16241. Lookup must
        // not require the host to be 127.0.0.1.
        let peer_map: HashMap<u32, PathBuf> = [
            (16211u32, PathBuf::from("/srv/1/node")),
            (16231u32, PathBuf::from("/srv/3/node")),
        ]
        .into_iter()
        .collect();
        let rsync = DbRsync {
            dest: DbRsyncDest::Local {
                peer_map,
                port_of: HashMap::new(),
            },
        };
        let (dest, ssh) = rsync
            .rsync_dest("127.0.0.3:16231", "sdb3", "handoff-id")
            .unwrap();
        assert_eq!(dest, "/srv/3/node/sdb3/tmp/handoff-id");
        assert!(ssh.is_none());
        assert!(rsync.rsync_dest("127.0.0.2:16221", "sdb2", "x").is_none());
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
