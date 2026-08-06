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

//! The container sharder daemon core, ported from `swift/container/sharder.py`.
//!
//! The sharder drives a large container through sharding: it finds shard
//! ranges, creates the shard containers, moves this container into the
//! `sharding` state, then *cleaves* — copies each shard range's objects out of
//! the retiring DB into that shard's container — advancing a cleave cursor,
//! and finally moves to the `sharded` state. This module ports the cleave
//! orchestration on top of the sharding primitives already in `swift-db`
//! (`find_shard_ranges`, `merge_shard_ranges`, `make_shard_name`,
//! `set_sharding_state`/`set_sharded_state`).
//!
//! [`run_once`] walks a device's container DBs and continues cleave for
//! containers already in the `sharding` state, writing shard DBs onto the
//! **same device** under the normal `containers/<part>/<suf>/<hash>/` layout
//! (local cleave). Wave 3 adds CleavingContext persistence, optional
//! `auto_shard`, a local misplaced-object pass, and an HTTP shard-replicate
//! hook. Proxy listing fan-out lives in `swift-proxy-server`.
//!
//! Residuals vs full Python L3b / multi-node KEEP claim blockers:
//! - shrink / expand / compactible-sequence of shard ranges
//! - live Contabo multi-node quorum drill (unit [`HttpShardReplicator`] only;
//!   ring → primary nodes wiring in daemon loop not driven end-to-end on VIP)
//! - sharder HTTP create+replicate of shard DBs on *all* primary replicas with
//!   durable cleave under concurrent load (local same-device cleave is KEEP-
//!   insufficient for product claim)
//! - manage-shard-ranges compact/repair/analyze (CLI deferred; find/show/info/
//!   enable/delete/merge/find_and_replace ship)
//! - WAN / async container-sync (wontfix)

use std::path::Path;

use swift_core::hashing::HashPathConfig;
use swift_db::{
    db_locations, make_shard_name, shard_state, shards_account_name, ContainerBroker, DbError,
    DbState, GetShardRangesArgs, ShardRange,
};

/// Sysmeta key for persisted [`CleavingContext`] JSON.
pub const CLEAVING_CONTEXT_KEY: &str = "X-Container-Sysmeta-Shard-Cleaving-Context";

/// `CleavingContext`: the sharder's progress through a container's shard
/// ranges (Python's stored context; persisted in container sysmeta).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CleavingContext {
    /// The upper bound of the last shard range cleaved (`""` = not started /
    /// namespace minimum).
    pub cursor: String,
    pub ranges_done: usize,
    pub ranges_todo: usize,
    /// True once the cursor reaches the namespace maximum (all ranges cleaved).
    pub cleaving_done: bool,
}

impl CleavingContext {
    /// Serialize to a compact JSON object.
    pub fn to_json(&self) -> String {
        format!(
            "{{\"cursor\":{},\"ranges_done\":{},\"ranges_todo\":{},\"cleaving_done\":{}}}",
            json_str(&self.cursor),
            self.ranges_done,
            self.ranges_todo,
            if self.cleaving_done { "true" } else { "false" },
        )
    }

    /// Parse from JSON (tolerant of whitespace).
    pub fn from_json(s: &str) -> Option<Self> {
        let cursor = json_get_str(s, "cursor")?;
        let ranges_done = json_get_usize(s, "ranges_done")?;
        let ranges_todo = json_get_usize(s, "ranges_todo").unwrap_or(0);
        let cleaving_done = s.contains("\"cleaving_done\":true")
            || s.contains("\"cleaving_done\": true");
        Some(Self {
            cursor,
            ranges_done,
            ranges_todo,
            cleaving_done,
        })
    }
}

fn json_str(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

fn json_get_str(s: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\":");
    let rest = s.split(&needle).nth(1)?.trim_start();
    if !rest.starts_with('"') {
        return None;
    }
    let mut out = String::new();
    let mut chars = rest[1..].chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                if let Some(n) = chars.next() {
                    out.push(n);
                }
            }
            '"' => break,
            other => out.push(other),
        }
    }
    Some(out)
}

fn json_get_usize(s: &str, key: &str) -> Option<usize> {
    let needle = format!("\"{key}\":");
    let rest = s.split(&needle).nth(1)?.trim_start();
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

/// Load persisted cleaving context from container sysmeta.
pub fn load_cleaving_context(broker: &mut ContainerBroker) -> Result<CleavingContext, DbError> {
    let md = broker.metadata()?;
    for (k, (v, _)) in md {
        if k.eq_ignore_ascii_case(CLEAVING_CONTEXT_KEY) {
            if let Some(ctx) = CleavingContext::from_json(&v) {
                return Ok(ctx);
            }
        }
    }
    Ok(CleavingContext::default())
}

/// Persist cleaving context into container sysmeta.
pub fn save_cleaving_context(
    broker: &mut ContainerBroker,
    ctx: &CleavingContext,
    timestamp: &str,
) -> Result<(), DbError> {
    broker.update_metadata(&vec![(
        CLEAVING_CONTEXT_KEY.to_string(),
        (ctx.to_json(), timestamp.to_string()),
    )])
}

/// Hook for multi-node shard DB create/replicate (Python sharder HTTP path).
/// Local lab uses [`LocalShardReplicator`] (no-op success). Multi-node uses
/// [`HttpShardReplicator`] with a quorum of container-server PUTs.
pub trait ShardReplicator: Send {
    /// Ensure the shard container exists on primary replicas; return Ok when
    /// a quorum has the empty/created shard DB.
    fn replicate_shard(&mut self, shard_name: &str, part: &str) -> Result<(), String>;
}

/// No-op replicator (local cleave already wrote the shard DB on-device).
#[derive(Debug, Default)]
pub struct LocalShardReplicator;

impl ShardReplicator for LocalShardReplicator {
    fn replicate_shard(&mut self, _shard_name: &str, _part: &str) -> Result<(), String> {
        Ok(())
    }
}

/// One container-server primary for HTTP shard create.
#[derive(Debug, Clone)]
pub struct ShardReplicaNode {
    pub ip: String,
    pub port: u16,
    pub device: String,
}

/// Transport for container PUT used by [`HttpShardReplicator`].
/// Production uses [`TcpShardHttpTransport`]; unit tests inject maps.
pub trait ShardHttpTransport: Send {
    /// PUT empty container at `/{device}/{part}/{account}/{container}`.
    /// Returns HTTP status.
    fn put_container(
        &mut self,
        node: &ShardReplicaNode,
        part: &str,
        account: &str,
        container: &str,
        timestamp: &str,
    ) -> Result<u16, String>;
}

/// Multi-node HTTP shard create with quorum (replica_count/2 + 1 by default).
pub struct HttpShardReplicator<T: ShardHttpTransport> {
    pub nodes: Vec<ShardReplicaNode>,
    pub quorum: usize,
    pub transport: T,
}

impl<T: ShardHttpTransport> HttpShardReplicator<T> {
    pub fn new(nodes: Vec<ShardReplicaNode>, transport: T) -> Self {
        let n = nodes.len();
        let quorum = (n / 2) + 1;
        Self {
            nodes,
            quorum: quorum.max(1),
            transport,
        }
    }

    pub fn with_quorum(mut self, quorum: usize) -> Self {
        self.quorum = quorum.max(1);
        self
    }
}

impl<T: ShardHttpTransport> ShardReplicator for HttpShardReplicator<T> {
    fn replicate_shard(&mut self, shard_name: &str, part: &str) -> Result<(), String> {
        let (account, container) = split_shard_name(shard_name);
        if account.is_empty() || container.is_empty() {
            return Err(format!("invalid shard name: {shard_name}"));
        }
        let ts = swift_core::timestamp::Timestamp::now().internal();
        let mut ok = 0usize;
        let mut errors = Vec::new();
        // Clone node list so we can mutably borrow transport while iterating.
        let nodes = self.nodes.clone();
        for node in &nodes {
            match self
                .transport
                .put_container(node, part, &account, &container, &ts)
            {
                Ok(status) if (200..300).contains(&status) || status == 202 => ok += 1,
                Ok(status) => errors.push(format!("{}:{} → {status}", node.ip, node.port)),
                Err(e) => errors.push(format!("{}:{} → {e}", node.ip, node.port)),
            }
        }
        if ok >= self.quorum {
            Ok(())
        } else {
            Err(format!(
                "shard create quorum failed for {shard_name}: ok={ok}/{} need={}; {}",
                self.nodes.len(),
                self.quorum,
                errors.join("; ")
            ))
        }
    }
}

/// Std TCP transport: `PUT /{device}/{part}/{account}/{container}` with
/// `X-Timestamp` (container-server create path).
#[derive(Debug, Default)]
pub struct TcpShardHttpTransport {
    pub timeout: std::time::Duration,
}

impl TcpShardHttpTransport {
    pub fn new() -> Self {
        Self {
            timeout: std::time::Duration::from_secs(5),
        }
    }
}

impl ShardHttpTransport for TcpShardHttpTransport {
    fn put_container(
        &mut self,
        node: &ShardReplicaNode,
        part: &str,
        account: &str,
        container: &str,
        timestamp: &str,
    ) -> Result<u16, String> {
        use std::io::{Read, Write};
        use std::net::{TcpStream, ToSocketAddrs};
        let path = format!(
            "/{}/{}/{}/{}",
            node.device, part, account, container
        );
        let hostport = format!("{}:{}", node.ip, node.port);
        let addr = hostport
            .to_socket_addrs()
            .map_err(|e| e.to_string())?
            .next()
            .ok_or_else(|| format!("cannot resolve {hostport}"))?;
        let mut stream =
            TcpStream::connect_timeout(&addr, self.timeout).map_err(|e| e.to_string())?;
        stream.set_read_timeout(Some(self.timeout)).ok();
        stream.set_write_timeout(Some(self.timeout)).ok();
        let req = format!(
            "PUT {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\
             X-Timestamp: {timestamp}\r\nContent-Length: 0\r\n\r\n",
            node.ip
        );
        stream.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).map_err(|e| e.to_string())?;
        let text = String::from_utf8_lossy(&buf);
        let status = text
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        Ok(status)
    }
}

/// In-memory transport for quorum unit tests.
#[derive(Debug, Default)]
pub struct MapShardHttpTransport {
    /// Key `"ip:port/device"` → status to return (missing → connection error).
    pub responses: std::collections::HashMap<String, u16>,
    pub calls: Vec<(String, String, String, String)>,
}

impl MapShardHttpTransport {
    pub fn new() -> Self {
        Self::default()
    }

    fn key(node: &ShardReplicaNode) -> String {
        format!("{}:{}/{}", node.ip, node.port, node.device)
    }
}

impl ShardHttpTransport for MapShardHttpTransport {
    fn put_container(
        &mut self,
        node: &ShardReplicaNode,
        part: &str,
        account: &str,
        container: &str,
        _timestamp: &str,
    ) -> Result<u16, String> {
        self.calls.push((
            Self::key(node),
            part.to_string(),
            account.to_string(),
            container.to_string(),
        ));
        self.responses
            .get(&Self::key(node))
            .copied()
            .ok_or_else(|| format!("connection refused {}", Self::key(node)))
    }
}

/// `_find_shard_ranges` + `_create_shard_containers` (naming part): scan the
/// container for shard ranges, build FOUND `ShardRange` records named with
/// `make_shard_name`, and merge them into the container's shard-range table.
/// Returns the found ranges (ascending by upper).
pub fn find_and_merge_found_ranges(
    broker: &mut ContainerBroker,
    account: &str,
    container: &str,
    shard_size: i64,
    minimum_shard_size: i64,
    timestamp: &str,
) -> Result<Vec<ShardRange>, DbError> {
    let (found, _done) = broker.find_shard_ranges(shard_size, minimum_shard_size)?;
    let shards_account = shards_account_name(account);
    let mut ranges = Vec::with_capacity(found.len());
    for f in &found {
        // first-generation shards: parent == root == this container
        let name = make_shard_name(&shards_account, container, container, timestamp, f.index as u64);
        let mut sr = ShardRange::new(&name, timestamp, &f.lower, &f.upper);
        sr.object_count = f.object_count;
        ranges.push(sr);
    }
    if !ranges.is_empty() {
        broker.merge_shard_ranges(ranges.clone())?;
    }
    Ok(ranges)
}

/// `_cleave_shard_range`: copy `range`'s objects out of the `retiring` DB into
/// its `shard` container, update the range's stats from the shard, and mark it
/// CLEAVED. The updated range is persisted into both the shard container (as
/// its own range) and the `source` container (so the root records progress).
pub fn cleave_shard_range(
    retiring: &mut ContainerBroker,
    shard: &mut ContainerBroker,
    source: &mut ContainerBroker,
    range: &mut ShardRange,
) -> Result<(), DbError> {
    let records = retiring.object_records_in_range(&range.lower, &range.upper)?;
    if !records.is_empty() {
        shard.merge_items(records)?;
    }
    // Update the range's object/byte counts from the cleaved shard.
    let info = shard.get_info()?;
    let get = |k: &str| {
        info.iter()
            .find(|(n, _)| n == k)
            .and_then(|(_, v)| v.as_i64())
            .unwrap_or(0)
    };
    range.object_count = get("object_count");
    range.bytes_used = get("bytes_used");
    range.state = shard_state::CLEAVED;
    // bump the meta timestamp so the CLEAVED/count update wins on merge
    range.meta_timestamp = range.timestamp.clone();
    shard.merge_shard_ranges(vec![range.clone()])?;
    source.merge_shard_ranges(vec![range.clone()])?;
    Ok(())
}

/// `_cleave`: cleave up to `batch_size` not-yet-cleaved ranges, advancing the
/// cleave cursor. Objects are read from the container's retiring DB (the
/// broker must be in the SHARDING state, i.e. have a separate retiring DB).
/// `shard_for` yields a (local) broker for a shard range's container. When the
/// cursor reaches the namespace maximum the context is marked `cleaving_done`.
pub fn cleave(
    source: &mut ContainerBroker,
    ranges: &mut [ShardRange],
    shard_for: &mut dyn FnMut(&ShardRange) -> ContainerBroker,
    ctx: &mut CleavingContext,
    batch_size: usize,
) -> Result<(), DbError> {
    let Some(mut retiring) = source.retiring_broker() else {
        // not in the sharding state; nothing to cleave from a retiring DB
        return Ok(());
    };
    ctx.ranges_todo = ranges
        .iter()
        .filter(|r| r.upper.is_empty() || r.upper.as_str() > ctx.cursor.as_str())
        .count();
    let mut done_this_batch = 0usize;
    for range in ranges.iter_mut() {
        if ctx.cleaving_done || done_this_batch >= batch_size {
            break;
        }
        // skip ranges already behind the cursor
        if !range.upper.is_empty() && range.upper.as_str() <= ctx.cursor.as_str() {
            continue;
        }
        let mut shard = shard_for(range);
        cleave_shard_range(&mut retiring, &mut shard, source, range)?;
        ctx.cursor = range.upper.clone();
        ctx.ranges_done += 1;
        done_this_batch += 1;
        if range.upper.is_empty() {
            // reached the namespace maximum -> all ranges cleaved
            ctx.cleaving_done = true;
        }
    }
    Ok(())
}

/// Sweep counters for one device pass.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SharderStats {
    pub containers_seen: u64,
    pub sharding: u64,
    pub cleaved_batches: u64,
    pub finished: u64,
    pub skipped: u64,
    pub failures: u64,
}

/// Recon-cache update dumped after a sharder sweep.
pub fn recon_update(elapsed: std::time::Duration, end_epoch_secs: f64, stats: &SharderStats) -> serde_json::Value {
    serde_json::json!({
        "container_sharder_sweep": elapsed.as_secs_f64(),
        "container_sharder_last": end_epoch_secs,
        "container_sharder_containers_seen": stats.containers_seen,
        "container_sharder_sharding": stats.sharding,
        "container_sharder_cleaved_batches": stats.cleaved_batches,
        "container_sharder_finished": stats.finished,
        "container_sharder_failures": stats.failures,
    })
}

/// Parse a shard-range `name` (`account/container`) into parts.
fn split_shard_name(name: &str) -> (String, String) {
    match name.split_once('/') {
        Some((a, c)) => (a.to_string(), c.to_string()),
        None => (String::new(), name.to_string()),
    }
}

/// Place a local shard broker under `device/containers/…` using the hash path.
fn local_shard_broker(
    device: &Path,
    hash_config: &HashPathConfig,
    part: &str,
    shard_name: &str,
) -> ContainerBroker {
    let (account, container) = split_shard_name(shard_name);
    let hsh = hash_config
        .hash_path(&account, Some(&container), None)
        .unwrap_or_else(|_| "0".repeat(32));
    let suffix = &hsh[hsh.len().saturating_sub(3)..];
    let hd = device
        .join("containers")
        .join(part)
        .join(suffix)
        .join(&hsh);
    let _ = std::fs::create_dir_all(&hd);
    let db = hd.join(format!("{hsh}.db"));
    let mut b = ContainerBroker::new(&db, &account, &container);
    if !db.exists() {
        let ts = swift_core::timestamp::Timestamp::now().internal();
        let _ = b.initialize(&ts, 0, &ts, "shard");
    }
    b
}

/// Continue cleave for one container already in the SHARDING state.
/// Returns whether the container reached SHARDED this pass.
pub fn process_sharding_container(
    broker: &mut ContainerBroker,
    device: &Path,
    hash_config: &HashPathConfig,
    part: &str,
    cleave_batch_size: usize,
) -> Result<bool, DbError> {
    process_sharding_container_with_replicator(
        broker,
        device,
        hash_config,
        part,
        cleave_batch_size,
        &mut LocalShardReplicator,
    )
}

/// Same as [`process_sharding_container`] but with an injectable replicator.
pub fn process_sharding_container_with_replicator(
    broker: &mut ContainerBroker,
    device: &Path,
    hash_config: &HashPathConfig,
    part: &str,
    cleave_batch_size: usize,
    replicator: &mut dyn ShardReplicator,
) -> Result<bool, DbError> {
    let info = broker.get_info()?;
    let account = info
        .iter()
        .find(|(k, _)| k == "account")
        .and_then(|(_, v)| v.as_text())
        .unwrap_or_default();
    let container = info
        .iter()
        .find(|(k, _)| k == "container")
        .and_then(|(_, v)| v.as_text())
        .unwrap_or_default();
    if account.is_empty() || container.is_empty() {
        return Ok(false);
    }
    let mut ranges = broker.get_shard_ranges(&GetShardRangesArgs {
        include_own: false,
        ..GetShardRangesArgs::default()
    })?;
    if ranges.is_empty() {
        return Ok(false);
    }
    // Prefer persisted context; fall back to CLEAVED-range scan.
    let mut ctx = load_cleaving_context(broker)?;
    if ctx.cursor.is_empty() {
        if let Some(last) = ranges
            .iter()
            .filter(|r| r.state >= shard_state::CLEAVED && !r.upper.is_empty())
            .max_by(|a, b| a.upper.cmp(&b.upper))
        {
            ctx.cursor = last.upper.clone();
            ctx.ranges_done = ranges
                .iter()
                .filter(|r| r.state >= shard_state::CLEAVED)
                .count();
        }
    }
    // Ensure shard DBs exist remotely (hook; local no-op).
    for sr in &ranges {
        if sr.state < shard_state::CLEAVED {
            let _ = replicator.replicate_shard(&sr.name, part);
        }
    }
    let mut shard_for = |sr: &ShardRange| local_shard_broker(device, hash_config, part, &sr.name);
    cleave(broker, &mut ranges, &mut shard_for, &mut ctx, cleave_batch_size)?;
    let ts = swift_core::timestamp::Timestamp::now().internal();
    save_cleaving_context(broker, &ctx, &ts)?;
    // Misplaced pass: objects still in retiring DB outside cleaved ranges.
    let _ = move_misplaced_from_retiring(broker, device, hash_config, part, &ranges);
    if ctx.cleaving_done || ranges.iter().all(|r| r.state >= shard_state::CLEAVED) {
        return broker.set_sharded_state();
    }
    Ok(false)
}

/// Move objects left in the retiring DB that fall outside CLEAVED/ACTIVE
/// shard ranges into the owning shard (local device). Returns count moved.
pub fn move_misplaced_from_retiring(
    source: &mut ContainerBroker,
    device: &Path,
    hash_config: &HashPathConfig,
    part: &str,
    ranges: &[ShardRange],
) -> Result<usize, DbError> {
    let Some(mut retiring) = source.retiring_broker() else {
        return Ok(0);
    };
    let records = retiring.object_records_in_range("", "")?;
    let mut moved = 0usize;
    for rec in records {
        let name = rec.name.clone();
        let Some(owner) = ranges.iter().find(|r| {
            r.state >= shard_state::CLEAVED
                && (r.lower.is_empty() || name.as_str() > r.lower.as_str())
                && (r.upper.is_empty() || name.as_str() <= r.upper.as_str())
        }) else {
            continue;
        };
        let mut shard = local_shard_broker(device, hash_config, part, &owner.name);
        shard.merge_items(vec![rec])?;
        // Tombstone in retiring so a later reclaim can drop it.
        let ts = swift_core::timestamp::Timestamp::now().internal();
        let _ = retiring.delete_object(&name, &ts, 0);
        moved += 1;
    }
    Ok(moved)
}

/// Options for one sharder device sweep.
#[derive(Debug, Clone)]
pub struct SharderRunOpts {
    pub cleave_batch_size: usize,
    /// When true, unsharded containers with `object_count >= shard_size`
    /// are transitioned into SHARDING.
    pub auto_shard: bool,
    pub shard_size: i64,
    pub minimum_shard_size: i64,
}

impl Default for SharderRunOpts {
    fn default() -> Self {
        Self {
            cleave_batch_size: 2,
            auto_shard: false,
            shard_size: 1_000_000,
            minimum_shard_size: 100_000,
        }
    }
}

/// One full sweep of a device's container DBs.
pub fn run_once(
    device: &Path,
    hash_config: &HashPathConfig,
    cleave_batch_size: usize,
) -> SharderStats {
    run_once_with_opts(
        device,
        hash_config,
        &SharderRunOpts {
            cleave_batch_size,
            ..SharderRunOpts::default()
        },
    )
}

/// Sweep with full Wave 3 options (`auto_shard`, shard sizes).
pub fn run_once_with_opts(
    device: &Path,
    hash_config: &HashPathConfig,
    opts: &SharderRunOpts,
) -> SharderStats {
    let mut stats = SharderStats::default();
    for db in db_locations(device, "containers") {
        stats.containers_seen += 1;
        let mut broker = ContainerBroker::new(&db, "", "");
        let state = match broker.get_db_state() {
            Ok(s) => s,
            Err(_) => {
                stats.failures += 1;
                continue;
            }
        };
        let part = db
            .components()
            .rev()
            .nth(3)
            .and_then(|c| c.as_os_str().to_str())
            .unwrap_or("0")
            .to_string();
        match state {
            DbState::Sharding => {
                stats.sharding += 1;
                match process_sharding_container(
                    &mut broker,
                    device,
                    hash_config,
                    &part,
                    opts.cleave_batch_size,
                ) {
                    Ok(true) => {
                        stats.cleaved_batches += 1;
                        stats.finished += 1;
                    }
                    Ok(false) => stats.cleaved_batches += 1,
                    Err(_) => stats.failures += 1,
                }
            }
            DbState::Unsharded if opts.auto_shard => {
                match maybe_auto_shard(&mut broker, opts) {
                    Ok(true) => {
                        stats.sharding += 1;
                        match process_sharding_container(
                            &mut broker,
                            device,
                            hash_config,
                            &part,
                            opts.cleave_batch_size,
                        ) {
                            Ok(true) => {
                                stats.cleaved_batches += 1;
                                stats.finished += 1;
                            }
                            Ok(false) => stats.cleaved_batches += 1,
                            Err(_) => stats.failures += 1,
                        }
                    }
                    Ok(false) => stats.skipped += 1,
                    Err(_) => stats.failures += 1,
                }
            }
            DbState::Sharded | DbState::Unsharded | DbState::Collapsed | DbState::NotFound => {
                stats.skipped += 1;
            }
        }
    }
    stats
}

/// If object_count ≥ shard_size, find ranges + enter SHARDING. Returns true
/// when the container is now ready to cleave.
pub fn maybe_auto_shard(broker: &mut ContainerBroker, opts: &SharderRunOpts) -> Result<bool, DbError> {
    let info = broker.get_info()?;
    let object_count = info
        .iter()
        .find(|(k, _)| k == "object_count")
        .and_then(|(_, v)| v.as_i64())
        .unwrap_or(0);
    if object_count < opts.shard_size {
        return Ok(false);
    }
    let account = info
        .iter()
        .find(|(k, _)| k == "account")
        .and_then(|(_, v)| v.as_text())
        .unwrap_or_default();
    let container = info
        .iter()
        .find(|(k, _)| k == "container")
        .and_then(|(_, v)| v.as_text())
        .unwrap_or_default();
    if account.is_empty() || container.is_empty() {
        return Ok(false);
    }
    let epoch = swift_core::timestamp::Timestamp::now().internal();
    find_and_merge_found_ranges(
        broker,
        &account,
        &container,
        opts.shard_size,
        opts.minimum_shard_size,
        &epoch,
    )?;
    broker.enable_sharding(&epoch)?;
    Ok(broker.set_sharding_state()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use swift_core::hashing::HashPathConfig;

    fn container_broker(dir: &std::path::Path, name: &str, n: usize) -> ContainerBroker {
        let h = format!("{:0>32}", name.replace(['/', '.'], ""));
        let h = &h[h.len() - 32..];
        let hd = dir.join(format!("c/0/{}/{h}", &h[h.len() - 3..]));
        std::fs::create_dir_all(&hd).unwrap();
        let db = hd.join(format!("{h}.db"));
        let mut b = ContainerBroker::new(&db, "AUTH_test", name);
        b.initialize("1751500000.00000", 0, "1751500000.00000", "id")
            .unwrap();
        for i in 0..n {
            b.put_object(&format!("o{i:04}"), "1751500001.00000", 1, "text/plain", "e", 0, 0, None, None)
                .unwrap();
        }
        b
    }

    #[test]
    fn test_find_create_and_cleave() {
        let dir = std::env::temp_dir().join(format!("swift-sharder-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // a source container with 10 objects
        let mut source = container_broker(&dir, "c", 10);

        // find + merge shard ranges (shard_size 3, min 1 -> 4 ranges)
        let epoch = "1751500010.00000";
        let mut ranges =
            find_and_merge_found_ranges(&mut source, "AUTH_test", "c", 3, 1, epoch).unwrap();
        assert_eq!(ranges.len(), 4, "{ranges:?}");
        assert!(ranges.iter().all(|r| r.state == shard_state::FOUND));

        // move to sharding state
        source.enable_sharding(epoch).unwrap();
        assert!(source.set_sharding_state().unwrap());

        // cleave all ranges (batch big enough to finish)
        let shard_dir = dir.join("shards");
        let mut shard_for = |sr: &ShardRange| {
            let safe = sr.name.replace(['/', '.', '-'], "_");
            let hd = shard_dir.join(&safe);
            std::fs::create_dir_all(&hd).unwrap();
            let db = hd.join("shard.db");
            let mut b = ContainerBroker::new(&db, ".shards_AUTH_test", &sr.name);
            let _ = b.initialize("1751500010.00000", 0, "1751500010.00000", "sid");
            b
        };
        let mut ctx = CleavingContext::default();
        cleave(&mut source, &mut ranges, &mut shard_for, &mut ctx, 10).unwrap();

        assert!(ctx.cleaving_done, "reached namespace max");
        assert_eq!(ctx.ranges_done, 4);
        assert!(ranges.iter().all(|r| r.state == shard_state::CLEAVED));
        // every object accounted for across the shards
        let total: i64 = ranges.iter().map(|r| r.object_count).sum();
        assert_eq!(total, 10, "{ranges:?}");
        // the first shard (upper o0002) got exactly its 3 objects
        assert_eq!(ranges[0].object_count, 3);

        // finish: move to sharded state
        assert!(source.set_sharded_state().unwrap());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_cleave_is_batched() {
        let dir = std::env::temp_dir().join(format!("swift-sharder-b-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut source = container_broker(&dir, "c", 10);
        let epoch = "1751500010.00000";
        let mut ranges =
            find_and_merge_found_ranges(&mut source, "AUTH_test", "c", 3, 1, epoch).unwrap();
        source.enable_sharding(epoch).unwrap();
        source.set_sharding_state().unwrap();

        let shard_dir = dir.join("shards");
        let mut shard_for = |sr: &ShardRange| {
            let safe = sr.name.replace(['/', '.', '-'], "_");
            let hd = shard_dir.join(&safe);
            std::fs::create_dir_all(&hd).unwrap();
            let mut b = ContainerBroker::new(&hd.join("s.db"), ".shards_AUTH_test", &sr.name);
            let _ = b.initialize("1751500010.00000", 0, "1751500010.00000", "sid");
            b
        };
        // first batch of 2
        let mut ctx = CleavingContext::default();
        cleave(&mut source, &mut ranges, &mut shard_for, &mut ctx, 2).unwrap();
        assert_eq!(ctx.ranges_done, 2);
        assert!(!ctx.cleaving_done);
        assert_eq!(ctx.cursor, ranges[1].upper);
        // second batch finishes
        cleave(&mut source, &mut ranges, &mut shard_for, &mut ctx, 2).unwrap();
        assert_eq!(ctx.ranges_done, 4);
        assert!(ctx.cleaving_done);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_run_once_cleaves_sharding_container_on_device() {
        let hash_config = HashPathConfig::new("", "changeme").unwrap();
        let dir = std::env::temp_dir().join(format!("swift-sharder-run-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let device = dir.join("d1");
        // Place the source DB on a normal containers/ path.
        let account = "AUTH_test";
        let container = "big";
        let hsh = hash_config
            .hash_path(account, Some(container), None)
            .unwrap();
        let suf = &hsh[hsh.len() - 3..];
        let hd = device.join("containers/0").join(suf).join(&hsh);
        std::fs::create_dir_all(&hd).unwrap();
        let db = hd.join(format!("{hsh}.db"));
        let mut source = ContainerBroker::new(&db, account, container);
        source
            .initialize("1751500000.00000", 0, "1751500000.00000", "id")
            .unwrap();
        for i in 0..10 {
            source
                .put_object(
                    &format!("o{i:04}"),
                    "1751500001.00000",
                    1,
                    "text/plain",
                    "e",
                    0,
                    0,
                    None,
                    None,
                )
                .unwrap();
        }
        let epoch = "1751500010.00000";
        find_and_merge_found_ranges(&mut source, account, container, 3, 1, epoch).unwrap();
        source.enable_sharding(epoch).unwrap();
        assert!(source.set_sharding_state().unwrap());
        drop(source);

        let stats = run_once(&device, &hash_config, 10);
        assert_eq!(stats.sharding, 1, "{stats:?}");
        assert!(stats.finished >= 1, "{stats:?}");
        assert_eq!(stats.failures, 0, "{stats:?}");

        let mut check = ContainerBroker::new(&db, account, container);
        assert_eq!(check.get_db_state().unwrap(), DbState::Sharded);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_cleaving_context_roundtrip() {
        let ctx = CleavingContext {
            cursor: "o0002".into(),
            ranges_done: 2,
            ranges_todo: 4,
            cleaving_done: false,
        };
        let json = ctx.to_json();
        let back = CleavingContext::from_json(&json).unwrap();
        assert_eq!(back, ctx);
    }

    #[test]
    fn test_cleaving_context_persists_on_broker() {
        let dir = std::env::temp_dir().join(format!("swift-sharder-ctx-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut source = container_broker(&dir, "c", 2);
        let ctx = CleavingContext {
            cursor: "o0000".into(),
            ranges_done: 1,
            ranges_todo: 2,
            cleaving_done: false,
        };
        save_cleaving_context(&mut source, &ctx, "1751500010.00000").unwrap();
        let loaded = load_cleaving_context(&mut source).unwrap();
        assert_eq!(loaded.cursor, "o0000");
        assert_eq!(loaded.ranges_done, 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_auto_shard_triggers_above_threshold() {
        let dir = std::env::temp_dir().join(format!("swift-sharder-auto-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut source = container_broker(&dir, "c", 10);
        let opts = SharderRunOpts {
            cleave_batch_size: 10,
            auto_shard: true,
            shard_size: 5,
            minimum_shard_size: 1,
        };
        assert!(maybe_auto_shard(&mut source, &opts).unwrap());
        assert_eq!(source.get_db_state().unwrap(), DbState::Sharding);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_run_once_skips_unsharded() {
        let hash_config = HashPathConfig::new("", "changeme").unwrap();
        let dir = std::env::temp_dir().join(format!("swift-sharder-skip-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let device = dir.join("d1");
        let hsh = "0000000000000000000000000000abcd";
        let hd = device.join("containers/0/bcd").join(hsh);
        std::fs::create_dir_all(&hd).unwrap();
        let db = hd.join(format!("{hsh}.db"));
        let mut b = ContainerBroker::new(&db, "a", "c");
        b.initialize("1751500000.00000", 0, "1751500000.00000", "id")
            .unwrap();
        drop(b);
        let stats = run_once(&device, &hash_config, 10);
        assert_eq!(stats.containers_seen, 1);
        assert_eq!(stats.sharding, 0);
        assert_eq!(stats.skipped, 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_http_shard_replicator_quorum_pass_and_fail() {
        let nodes = vec![
            ShardReplicaNode {
                ip: "10.0.0.1".into(),
                port: 6201,
                device: "sda".into(),
            },
            ShardReplicaNode {
                ip: "10.0.0.2".into(),
                port: 6201,
                device: "sda".into(),
            },
            ShardReplicaNode {
                ip: "10.0.0.3".into(),
                port: 6201,
                device: "sda".into(),
            },
        ];
        let mut map = MapShardHttpTransport::new();
        map.responses
            .insert("10.0.0.1:6201/sda".into(), 201);
        map.responses
            .insert("10.0.0.2:6201/sda".into(), 201);
        map.responses
            .insert("10.0.0.3:6201/sda".into(), 503);
        let mut ok_rep = HttpShardReplicator::new(nodes.clone(), map);
        assert!(ok_rep
            .replicate_shard(".shards_AUTH_test/c-0", "0")
            .is_ok());
        assert_eq!(ok_rep.quorum, 2);

        let mut fail_map = MapShardHttpTransport::new();
        fail_map
            .responses
            .insert("10.0.0.1:6201/sda".into(), 201);
        // only 1 of 3 → below quorum 2
        let mut bad = HttpShardReplicator::new(nodes, fail_map);
        let err = bad
            .replicate_shard(".shards_AUTH_test/c-0", "0")
            .unwrap_err();
        assert!(err.contains("quorum failed"), "{err}");
    }

    #[test]
    fn test_move_misplaced_from_retiring_into_owner_shard() {
        let hash_config = HashPathConfig::new("", "changeme").unwrap();
        let dir = std::env::temp_dir().join(format!("swift-sharder-mis-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let device = dir.join("d1");
        let account = "AUTH_test";
        let container = "root";
        let hsh = hash_config
            .hash_path(account, Some(container), None)
            .unwrap();
        let suf = &hsh[hsh.len() - 3..];
        let hd = device.join("containers/0").join(suf).join(&hsh);
        std::fs::create_dir_all(&hd).unwrap();
        let db = hd.join(format!("{hsh}.db"));
        let mut source = ContainerBroker::new(&db, account, container);
        source
            .initialize("1751500000.00000", 0, "1751500000.00000", "id")
            .unwrap();
        for name in ["a1", "m1", "z1"] {
            source
                .put_object(name, "1751500001.00000", 1, "text/plain", "e", 0, 0, None, None)
                .unwrap();
        }
        let epoch = "1751500010.00000";
        let ranges = vec![
            {
                let mut sr = ShardRange::new(".shards_AUTH_test/c-lo", epoch, "", "m");
                sr.state = shard_state::CLEAVED;
                sr
            },
            {
                let mut sr = ShardRange::new(".shards_AUTH_test/c-hi", epoch, "m", "");
                sr.state = shard_state::CLEAVED;
                sr
            },
        ];
        source.merge_shard_ranges(ranges.clone()).unwrap();
        source.enable_sharding(epoch).unwrap();
        assert!(source.set_sharding_state().unwrap());
        // Simulate a leftover object still in retiring after a partial cleave.
        let mut retiring = source.retiring_broker().expect("retiring db");
        retiring
            .put_object("m2", "1751500002.00000", 1, "text/plain", "e", 0, 0, None, None)
            .unwrap();
        drop(retiring);
        let moved = move_misplaced_from_retiring(&mut source, &device, &hash_config, "0", &ranges)
            .unwrap();
        assert!(moved >= 1, "expected misplaced move, got {moved}");
        // Owner of "m2" is the hi shard (lower=m, upper="").
        let mut hi = local_shard_broker(&device, &hash_config, "0", &ranges[1].name);
        let objs = hi
            .object_records_in_range("", "")
            .unwrap()
            .into_iter()
            .map(|r| r.name)
            .collect::<Vec<_>>();
        assert!(objs.iter().any(|n| n == "m2"), "{objs:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_auto_shard_gate_skips_below_threshold() {
        let dir = std::env::temp_dir().join(format!("swift-sharder-gate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut source = container_broker(&dir, "c", 3);
        let opts = SharderRunOpts {
            cleave_batch_size: 10,
            auto_shard: true,
            shard_size: 100,
            minimum_shard_size: 1,
        };
        assert!(!maybe_auto_shard(&mut source, &opts).unwrap());
        assert_eq!(source.get_db_state().unwrap(), DbState::Unsharded);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_run_once_with_opts_auto_shard_path() {
        let hash_config = HashPathConfig::new("", "changeme").unwrap();
        let dir = std::env::temp_dir().join(format!(
            "swift-sharder-auto-run-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let device = dir.join("d1");
        let account = "AUTH_test";
        let container = "auto";
        let hsh = hash_config
            .hash_path(account, Some(container), None)
            .unwrap();
        let suf = &hsh[hsh.len() - 3..];
        let hd = device.join("containers/0").join(suf).join(&hsh);
        std::fs::create_dir_all(&hd).unwrap();
        let db = hd.join(format!("{hsh}.db"));
        let mut source = ContainerBroker::new(&db, account, container);
        source
            .initialize("1751500000.00000", 0, "1751500000.00000", "id")
            .unwrap();
        for i in 0..10 {
            source
                .put_object(
                    &format!("o{i:04}"),
                    "1751500001.00000",
                    1,
                    "text/plain",
                    "e",
                    0,
                    0,
                    None,
                    None,
                )
                .unwrap();
        }
        drop(source);
        let opts = SharderRunOpts {
            cleave_batch_size: 10,
            auto_shard: true,
            shard_size: 5,
            minimum_shard_size: 1,
        };
        let stats = run_once_with_opts(&device, &hash_config, &opts);
        assert_eq!(stats.failures, 0, "{stats:?}");
        assert!(stats.sharding >= 1 || stats.finished >= 1, "{stats:?}");
        let mut check = ContainerBroker::new(&db, account, container);
        let st = check.get_db_state().unwrap();
        assert!(
            matches!(st, DbState::Sharding | DbState::Sharded),
            "expected sharding/sharded, got {st:?}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_http_shard_replicator_with_quorum_override() {
        let nodes = vec![
            ShardReplicaNode {
                ip: "10.0.0.1".into(),
                port: 6201,
                device: "sdb".into(),
            },
            ShardReplicaNode {
                ip: "10.0.0.2".into(),
                port: 6201,
                device: "sdb".into(),
            },
            ShardReplicaNode {
                ip: "10.0.0.3".into(),
                port: 6201,
                device: "sdb".into(),
            },
        ];
        let mut map = MapShardHttpTransport::new();
        map.responses.insert("10.0.0.1:6201/sdb".into(), 201);
        // only 1 ok; default quorum=2 fails, with_quorum(1) passes
        let mut strict = HttpShardReplicator::new(nodes.clone(), MapShardHttpTransport {
            responses: map.responses.clone(),
            calls: Vec::new(),
        });
        assert!(strict
            .replicate_shard(".shards_a/c-0", "1")
            .unwrap_err()
            .contains("quorum failed"));
        let mut loose = HttpShardReplicator::new(nodes, map).with_quorum(1);
        assert!(loose.replicate_shard(".shards_a/c-0", "1").is_ok());
        assert_eq!(loose.transport.calls.len(), 3);
        assert_eq!(loose.transport.calls[0].2, ".shards_a");
        assert_eq!(loose.transport.calls[0].3, "c-0");
    }

    #[test]
    fn test_split_shard_name_and_local_replicator() {
        assert_eq!(
            split_shard_name(".shards_AUTH/c-x"),
            (".shards_AUTH".into(), "c-x".into())
        );
        assert_eq!(
            split_shard_name("nopath"),
            (String::new(), "nopath".into())
        );
        let mut local = LocalShardReplicator;
        assert!(local.replicate_shard("a/c", "0").is_ok());
    }
}
