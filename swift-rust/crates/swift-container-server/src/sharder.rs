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
//! [`run_once`] / [`run_once_with_opts`] walk a device's container DBs and
//! continue cleave for containers in the `sharding` state. Object rows are
//! still written under the **same device** layout (local cleave). When a
//! container ring is available, [`run_once_with_opts_and_replicator`] (and the
//! `swift-container-sharder` binary) also **HTTP-creates** each uncleaved
//! shard container on ring primaries via [`LookupHttpShardReplicator`] /
//! [`HttpShardReplicator`] before cleaving. Wave 3 adds CleavingContext
//! persistence, optional `auto_shard`, a local misplaced-object pass, and a
//! SHRINKING-donor detection stub. Proxy listing fan-out lives in
//! `swift-proxy-server`.
//!
//! ## Claimable vs residual (no Contabo KEEP claim without live evidence)
//!
//! **Claimable (unit-tested code path in this module / binary):**
//! - [`HttpShardReplicator`] quorum create (`replica_count/2+1`, overrideable)
//! - [`LookupHttpShardReplicator`]: per-shard primary resolve + quorum PUT
//! - [`primary_shard_replica_nodes`] / [`shard_replicas_from_ring_devices`] /
//!   [`ring_get_nodes_for_shard`]: ring devices → [`ShardReplicaNode`]
//! - Daemon loop: optional container.ring.gz → inject lookup replicator into
//!   [`process_sharding_container_with_replicator`] for uncleaved ranges
//! - [`find_shrinking_donors`] / [`process_shrinking_donors`]: detect donors
//!   marked SHRINKING by CLI compact and move their objects into a covering
//!   ACTIVE acceptor, then mark the donor SHRUNK
//! - [`LocalShardReplicator`] + same-device lab cleave (SAIO-safe default when
//!   no ring is loaded)
//!
//! **Still not KEEP (residuals):**
//! 1. **Live Contabo/VIP quorum drill** — create shard containers on ≥ quorum
//!    of real container-servers under the production ring; synthetic unit
//!    tests alone never count as KEEP.
//! 2. **Durable multi-primary object cleave under concurrent load** — local
//!    same-device row write is not a multi-node product claim; remote object
//!    push / rsync of cleaved shard DBs remains open.
//! 3. **Cross-node shrink over HTTP** — when the donor DB lives only on a
//!    remote primary, this process skips (never fabricates empty donors).
//!    Multi-device **same host** shrink has unit coverage (see
//!    [`process_shrinking_donors`] + `auto_shrink`) but is disabled by default.
//!    It is not a multi-primary product claim. Optional lab harness:
//!    `tools/soak/multi-primary-shrink-soak.sh`.
//! 4. WAN / async container-sync (wontfix).

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
        let cleaving_done =
            s.contains("\"cleaving_done\":true") || s.contains("\"cleaving_done\": true");
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

/// Default quorum for a replica set size: `n/2 + 1` (at least 1).
pub fn default_shard_quorum(replica_count: usize) -> usize {
    ((replica_count / 2) + 1).max(1)
}

/// Build ordered primary [`ShardReplicaNode`]s from ring device fields
/// (`ip`, `port`, `device`). Preserves ring primary order so HTTP create
/// targets match proxy/container placement.
///
/// Callers obtain the device list via `Ring::get_nodes(account, Some(container), None)`
/// or `Ring::get_part_nodes(part)` and map each `PartNode.dev`.
pub fn shard_replicas_from_ring_devices<'a, I>(devices: I) -> Vec<ShardReplicaNode>
where
    I: IntoIterator<Item = (&'a str, u16, &'a str)>,
{
    devices
        .into_iter()
        .map(|(ip, port, device)| ShardReplicaNode {
            ip: ip.to_string(),
            port,
            device: device.to_string(),
        })
        .collect()
}

/// Select primary shard replica nodes for `shard_name` using a ring lookup
/// callback. The callback receives `(account, container)` from the shard
/// path and must return `(partition, Vec<(ip, port, device)>)` — typically
/// wrapping `Ring::get_nodes`.
///
/// Returns `(part, nodes)` ready for [`HttpShardReplicator::new`].
pub fn primary_shard_replica_nodes<F>(
    shard_name: &str,
    mut get_nodes: F,
) -> Result<(String, Vec<ShardReplicaNode>), String>
where
    F: FnMut(&str, &str) -> Result<(u32, Vec<(String, u16, String)>), String>,
{
    let (account, container) = split_shard_name(shard_name);
    if account.is_empty() || container.is_empty() {
        return Err(format!("invalid shard name: {shard_name}"));
    }
    let (part, devices) = get_nodes(&account, &container)?;
    let nodes = shard_replicas_from_ring_devices(
        devices
            .iter()
            .map(|(ip, port, dev)| (ip.as_str(), *port, dev.as_str())),
    );
    if nodes.is_empty() {
        return Err(format!(
            "no primary nodes for shard {shard_name} part={part}"
        ));
    }
    Ok((part.to_string(), nodes))
}

/// Convenience: build [`HttpShardReplicator`] with default quorum from primary nodes.
pub fn http_replicator_for_primaries<T: ShardHttpTransport>(
    nodes: Vec<ShardReplicaNode>,
    transport: T,
) -> HttpShardReplicator<T> {
    HttpShardReplicator::new(nodes, transport)
}

/// Quorum PUT of an empty shard container to a fixed primary list.
/// Shared by [`HttpShardReplicator`] and [`LookupHttpShardReplicator`].
pub fn put_shard_quorum<T: ShardHttpTransport>(
    transport: &mut T,
    nodes: &[ShardReplicaNode],
    quorum: usize,
    shard_name: &str,
    part: &str,
) -> Result<(), String> {
    let (account, container) = split_shard_name(shard_name);
    if account.is_empty() || container.is_empty() {
        return Err(format!("invalid shard name: {shard_name}"));
    }
    let need = quorum.max(1);
    let ts = swift_core::timestamp::Timestamp::now().internal();
    let mut ok = 0usize;
    let mut errors = Vec::new();
    for node in nodes {
        match transport.put_container(node, part, &account, &container, &ts) {
            Ok(status) if (200..300).contains(&status) || status == 202 => ok += 1,
            Ok(status) => errors.push(format!("{}:{} → {status}", node.ip, node.port)),
            Err(e) => errors.push(format!("{}:{} → {e}", node.ip, node.port)),
        }
    }
    if ok >= need {
        Ok(())
    } else {
        Err(format!(
            "shard create quorum failed for {shard_name}: ok={ok}/{} need={need}; {}",
            nodes.len(),
            errors.join("; ")
        ))
    }
}

impl<T: ShardHttpTransport> ShardReplicator for HttpShardReplicator<T> {
    fn replicate_shard(&mut self, shard_name: &str, part: &str) -> Result<(), String> {
        // Clone node list so we can mutably borrow transport while iterating.
        let nodes = self.nodes.clone();
        let quorum = self.quorum;
        put_shard_quorum(&mut self.transport, &nodes, quorum, shard_name, part)
    }
}

/// HTTP shard create that **resolves primaries per shard name** via a ring
/// (or mock) lookup callback, then applies quorum PUT.
///
/// Use this from the daemon loop: each uncleaved range may hash to a different
/// partition/primary set than the root container.
pub struct LookupHttpShardReplicator<T, F>
where
    T: ShardHttpTransport,
    F: FnMut(&str, &str) -> Result<(u32, Vec<(String, u16, String)>), String>,
{
    pub transport: T,
    pub get_nodes: F,
    /// Override quorum; `None` → [`default_shard_quorum`] for that shard's nodes.
    pub quorum: Option<usize>,
}

impl<T, F> LookupHttpShardReplicator<T, F>
where
    T: ShardHttpTransport,
    F: FnMut(&str, &str) -> Result<(u32, Vec<(String, u16, String)>), String>,
{
    pub fn new(transport: T, get_nodes: F) -> Self {
        Self {
            transport,
            get_nodes,
            quorum: None,
        }
    }

    pub fn with_quorum(mut self, quorum: usize) -> Self {
        self.quorum = Some(quorum.max(1));
        self
    }
}

impl<T, F> ShardReplicator for LookupHttpShardReplicator<T, F>
where
    T: ShardHttpTransport + Send,
    F: FnMut(&str, &str) -> Result<(u32, Vec<(String, u16, String)>), String> + Send,
{
    fn replicate_shard(&mut self, shard_name: &str, _fallback_part: &str) -> Result<(), String> {
        let (part, nodes) = primary_shard_replica_nodes(shard_name, &mut self.get_nodes)?;
        let quorum = self
            .quorum
            .unwrap_or_else(|| default_shard_quorum(nodes.len()));
        put_shard_quorum(&mut self.transport, &nodes, quorum, shard_name, &part)
    }
}

/// Map `Ring::get_nodes(account, Some(container), None)` into the tuple shape
/// expected by [`primary_shard_replica_nodes`] / [`LookupHttpShardReplicator`].
pub fn ring_get_nodes_for_shard(
    ring: &swift_ring::Ring,
    account: &str,
    container: &str,
) -> Result<(u32, Vec<(String, u16, String)>), String> {
    let (part, nodes) = ring
        .get_nodes(account, Some(container), None)
        .map_err(|e| e.to_string())?;
    Ok((
        part,
        nodes
            .iter()
            .map(|n| (n.dev.ip.clone(), n.dev.port as u16, n.dev.device.clone()))
            .collect(),
    ))
}

/// Build a [`LookupHttpShardReplicator`] backed by a live [`swift_ring::Ring`]
/// and TCP transport (daemon default multi-node path).
#[allow(clippy::type_complexity)]
pub fn lookup_replicator_for_ring(
    ring: &swift_ring::Ring,
) -> LookupHttpShardReplicator<
    TcpShardHttpTransport,
    impl FnMut(&str, &str) -> Result<(u32, Vec<(String, u16, String)>), String> + '_,
> {
    LookupHttpShardReplicator::new(TcpShardHttpTransport::new(), move |account, container| {
        ring_get_nodes_for_shard(ring, account, container)
    })
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
        let path = format!("/{}/{}/{}/{}", node.device, part, account, container);
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
        stream
            .write_all(req.as_bytes())
            .map_err(|e| e.to_string())?;
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
        let name = make_shard_name(
            &shards_account,
            container,
            container,
            timestamp,
            f.index as u64,
        );
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
///
/// Both live and deleted rows are copied (Python `yield_objects` order), but
/// object_count / bytes_used always come from the shard's live stats after
/// merge (policy_stat triggers ignore deleted=1).
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
    // Refresh range stats from live rows only (triggers keep object_count =
    // count of deleted=0; tombstones contribute 0).
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
    /// HTTP/ring shard-create attempts that failed quorum (multi-node path).
    pub replicate_errors: u64,
    /// SHRINKING donor ranges observed (stub compact pass; no object move).
    pub shrinking_donors: u64,
}

/// Recon-cache update dumped after a sharder sweep.
pub fn recon_update(
    elapsed: std::time::Duration,
    end_epoch_secs: f64,
    stats: &SharderStats,
) -> serde_json::Value {
    serde_json::json!({
        "container_sharder_sweep": elapsed.as_secs_f64(),
        "container_sharder_last": end_epoch_secs,
        "container_sharder_containers_seen": stats.containers_seen,
        "container_sharder_sharding": stats.sharding,
        "container_sharder_cleaved_batches": stats.cleaved_batches,
        "container_sharder_finished": stats.finished,
        "container_sharder_failures": stats.failures,
        "container_sharder_replicate_errors": stats.replicate_errors,
        "container_sharder_shrinking_donors": stats.shrinking_donors,
    })
}

/// Parse a shard-range `name` (`account/container`) into parts.
fn split_shard_name(name: &str) -> (String, String) {
    match name.split_once('/') {
        Some((a, c)) => (a.to_string(), c.to_string()),
        None => (String::new(), name.to_string()),
    }
}

/// Place a local shard broker under `device/containers/{part}/…`.
///
/// `part` **must** be the container-ring partition for `shard_name` (not the
/// root container's part). Writing under the root part is SAIO-convenient but
/// makes proxy listing fan-out (which ring-looks up the shard) always miss.
/// Path of the local shard container DB (may not exist yet).
fn shard_db_path(
    device: &Path,
    hash_config: &HashPathConfig,
    part: &str,
    shard_name: &str,
) -> (std::path::PathBuf, String, String) {
    let (account, container) = split_shard_name(shard_name);
    let hsh = hash_config
        .hash_path(&account, Some(&container), None)
        .unwrap_or_else(|_| "0".repeat(32));
    let suffix = &hsh[hsh.len().saturating_sub(3)..];
    let hd = device.join("containers").join(part).join(suffix).join(&hsh);
    let db = hd.join(format!("{hsh}.db"));
    (db, account, container)
}

/// Open a shard broker only if its DB file already exists (no auto-create).
fn open_existing_shard_broker(
    device: &Path,
    hash_config: &HashPathConfig,
    part: &str,
    shard_name: &str,
) -> Option<ContainerBroker> {
    let (db, account, container) = shard_db_path(device, hash_config, part, shard_name);
    if !db.exists() {
        return None;
    }
    Some(ContainerBroker::new(&db, &account, &container))
}

/// Sibling device directories under the same parent as `device` (e.g. all of
/// `/srv/node/d*`), including `device` itself. Used so shrink can find a
/// donor DB that landed on another local device.
fn local_device_siblings(device: &Path) -> Vec<std::path::PathBuf> {
    let mut out = vec![device.to_path_buf()];
    let Some(parent) = device.parent() else {
        return out;
    };
    let Ok(entries) = std::fs::read_dir(parent) else {
        return out;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() && p != device {
            out.push(p);
        }
    }
    out
}

/// Find an existing shard DB on any of `devices` (ring part preferred).
fn open_existing_shard_on_devices(
    devices: &[std::path::PathBuf],
    hash_config: &HashPathConfig,
    part: &str,
    shard_name: &str,
) -> Option<(std::path::PathBuf, ContainerBroker)> {
    for dev in devices {
        if let Some(b) = open_existing_shard_broker(dev, hash_config, part, shard_name) {
            return Some((dev.clone(), b));
        }
        // Also try common part layouts if ring part is wrong (lab handoffs).
        // Walk device/containers/*/suffix/hash only when part miss.
    }
    // Fallback: scan each device for the hash path under any part.
    let (account, container) = split_shard_name(shard_name);
    let hsh = hash_config
        .hash_path(&account, Some(&container), None)
        .ok()?;
    let suffix = &hsh[hsh.len().saturating_sub(3)..];
    for dev in devices {
        let cont_root = dev.join("containers");
        let Ok(parts) = std::fs::read_dir(&cont_root) else {
            continue;
        };
        for part_ent in parts.flatten() {
            let db = part_ent
                .path()
                .join(suffix)
                .join(&hsh)
                .join(format!("{hsh}.db"));
            if db.exists() {
                return Some((dev.clone(), ContainerBroker::new(&db, &account, &container)));
            }
        }
    }
    None
}

fn local_shard_broker(
    device: &Path,
    hash_config: &HashPathConfig,
    part: &str,
    shard_name: &str,
) -> ContainerBroker {
    let (db, account, container) = shard_db_path(device, hash_config, part, shard_name);
    let _ = std::fs::create_dir_all(db.parent().unwrap_or(device));
    let mut b = ContainerBroker::new(&db, &account, &container);
    if !db.exists() {
        let ts = swift_core::timestamp::Timestamp::now().internal();
        let _ = b.initialize(&ts, 0, &ts, "shard");
    }
    b
}

/// Resolve the container-ring partition for a shard range name.
/// Falls back to `fallback_part` (root part) when the ring is unavailable —
/// that path is SAIO-only and will not fan out correctly multi-node.
fn shard_part_for(
    shard_name: &str,
    ring: Option<&swift_ring::Ring>,
    fallback_part: &str,
) -> String {
    let Some(ring) = ring else {
        return fallback_part.to_string();
    };
    let (account, container) = split_shard_name(shard_name);
    match ring.get_nodes(&account, Some(&container), None) {
        Ok((part, _)) => part.to_string(),
        Err(_) => fallback_part.to_string(),
    }
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

/// Outcome of one SHARDING container process pass.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ProcessShardingOutcome {
    /// True when the container reached SHARDED this pass.
    pub finished: bool,
    /// Uncleaved ranges for which remote create failed quorum (or lookup).
    pub replicate_errors: u64,
}

/// Same as [`process_sharding_container`] but with an injectable replicator.
///
/// For each uncleaved range, calls [`ShardReplicator::replicate_shard`] so
/// multi-node backends ([`LookupHttpShardReplicator`]) can create the shard
/// container on ring primaries. Cleave still writes objects to the **local**
/// device path (SAIO-safe); remote object placement remains a residual.
pub fn process_sharding_container_with_replicator(
    broker: &mut ContainerBroker,
    device: &Path,
    hash_config: &HashPathConfig,
    part: &str,
    cleave_batch_size: usize,
    replicator: &mut dyn ShardReplicator,
) -> Result<bool, DbError> {
    Ok(process_sharding_container_detailed(
        broker,
        device,
        hash_config,
        part,
        cleave_batch_size,
        replicator,
    )?
    .finished)
}

/// Like [`process_sharding_container_with_replicator`] but returns replicate
/// error counts for daemon stats.
pub fn process_sharding_container_detailed(
    broker: &mut ContainerBroker,
    device: &Path,
    hash_config: &HashPathConfig,
    part: &str,
    cleave_batch_size: usize,
    replicator: &mut dyn ShardReplicator,
) -> Result<ProcessShardingOutcome, DbError> {
    process_sharding_container_detailed_with_ring(
        broker,
        device,
        hash_config,
        part,
        cleave_batch_size,
        replicator,
        None,
    )
}

/// Same as [`process_sharding_container_detailed`] but places local shard DBs
/// under each shard's **own** container-ring partition when `ring` is set.
/// Multi-node listing fan-out requires this; root-part placement is SAIO-only.
pub fn process_sharding_container_detailed_with_ring(
    broker: &mut ContainerBroker,
    device: &Path,
    hash_config: &HashPathConfig,
    part: &str,
    cleave_batch_size: usize,
    replicator: &mut dyn ShardReplicator,
    ring: Option<&swift_ring::Ring>,
) -> Result<ProcessShardingOutcome, DbError> {
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
        return Ok(ProcessShardingOutcome::default());
    }
    let mut ranges = broker.get_shard_ranges(&GetShardRangesArgs {
        include_own: false,
        ..GetShardRangesArgs::default()
    })?;
    if ranges.is_empty() {
        return Ok(ProcessShardingOutcome::default());
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
    // Ensure shard containers exist on primary replicas (local = no-op;
    // LookupHttpShardReplicator resolves ring primaries per shard name).
    let mut replicate_errors = 0u64;
    for sr in &ranges {
        if sr.state < shard_state::CLEAVED {
            let spart = shard_part_for(&sr.name, ring, part);
            if replicator.replicate_shard(&sr.name, &spart).is_err() {
                replicate_errors += 1;
            }
        }
    }
    let mut shard_for = |sr: &ShardRange| {
        let spart = shard_part_for(&sr.name, ring, part);
        local_shard_broker(device, hash_config, &spart, &sr.name)
    };
    cleave(
        broker,
        &mut ranges,
        &mut shard_for,
        &mut ctx,
        cleave_batch_size,
    )?;
    let ts = swift_core::timestamp::Timestamp::now().internal();
    save_cleaving_context(broker, &ctx, &ts)?;
    // Misplaced pass: objects still in retiring DB outside cleaved ranges.
    // Owner shards must also be under their ring part.
    let _ =
        move_misplaced_from_retiring_with_ring(broker, device, hash_config, part, &ranges, ring);
    let finished = if ctx.cleaving_done || ranges.iter().all(|r| r.state >= shard_state::CLEAVED) {
        broker.set_sharded_state()?
    } else {
        false
    };
    Ok(ProcessShardingOutcome {
        finished,
        replicate_errors,
    })
}

/// Collect non-deleted shard ranges in SHRINKING state (CLI compact/repair
/// marks these as donors for the daemon).
pub fn find_shrinking_donors(broker: &mut ContainerBroker) -> Result<Vec<ShardRange>, DbError> {
    let ranges = broker.get_shard_ranges(&GetShardRangesArgs {
        include_own: false,
        ..GetShardRangesArgs::default()
    })?;
    Ok(ranges
        .into_iter()
        .filter(|r| r.deleted == 0 && r.state == shard_state::SHRINKING)
        .collect())
}

/// Whether `acceptor` fully covers `donor`'s namespace (inclusive bounds
/// matching shard-range convention: (lower, upper]).
pub fn range_covers(acceptor: &ShardRange, donor: &ShardRange) -> bool {
    // lower: acceptor.lower <= donor.lower (empty lower = MIN)
    let lower_ok = acceptor.lower.is_empty()
        || (!donor.lower.is_empty()
            && ShardRange::lower_cmp(&acceptor.lower, &donor.lower) != std::cmp::Ordering::Greater);
    // upper: acceptor.upper >= donor.upper (empty upper = MAX)
    let upper_ok = acceptor.upper.is_empty()
        || (!donor.upper.is_empty()
            && ShardRange::lower_cmp(&donor.upper, &acceptor.upper) != std::cmp::Ordering::Greater);
    lower_ok && upper_ok
}

/// Find an ACTIVE non-deleted range on the root that covers `donor` and is
/// not the donor itself (compact expands the acceptor to cover donors).
pub fn find_shrink_acceptor<'a>(
    ranges: &'a [ShardRange],
    donor: &ShardRange,
) -> Option<&'a ShardRange> {
    ranges.iter().find(|r| {
        r.deleted == 0
            && r.state == shard_state::ACTIVE
            && r.name != donor.name
            && range_covers(r, donor)
    })
}

/// Process SHRINKING donors on a SHARDED root: move live objects from each
/// donor shard container into a covering ACTIVE acceptor, zero donor stats,
/// and mark the donor **SHRUNK** on the root.
///
/// Searches **all sibling devices** under the parent of `device` (e.g. every
/// `/srv/node/d*` on this host) for the donor DB so multi-device nodes still
/// shrink when the root and donor land on different local devices.
///
/// Multi-node KEEP still needs the root range table replicated to the node
/// that holds the donor (container-replicator); this function never creates
/// empty donor DBs.
///
/// Returns the number of donors successfully marked SHRUNK.
pub fn process_shrinking_donors(
    root: &mut ContainerBroker,
    device: &Path,
    hash_config: &HashPathConfig,
    root_part: &str,
    ring: Option<&swift_ring::Ring>,
) -> Result<usize, DbError> {
    let donors = find_shrinking_donors(root)?;
    if donors.is_empty() {
        return Ok(0);
    }
    let ranges = root.get_shard_ranges(&GetShardRangesArgs {
        include_own: false,
        include_deleted: false,
        ..GetShardRangesArgs::default()
    })?;
    let ts = swift_core::timestamp::Timestamp::now().internal();
    let mut finished = 0usize;
    let search_devices = local_device_siblings(device);
    for donor in donors {
        let Some(acceptor) = find_shrink_acceptor(&ranges, &donor) else {
            continue;
        };
        let donor_part = shard_part_for(&donor.name, ring, root_part);
        let acc_part = shard_part_for(&acceptor.name, ring, root_part);
        // Only shrink when the donor shard DB already lives on this host.
        // `local_shard_broker` auto-creates empty DBs — that would mark SHRUNK
        // without moving real objects (Contabo multi-primary hazard).
        let Some((donor_dev, mut donor_b)) =
            open_existing_shard_on_devices(&search_devices, hash_config, &donor_part, &donor.name)
        else {
            continue;
        };
        // Prefer acceptor on same device as donor; else create under donor device.
        let mut acc_b =
            open_existing_shard_broker(&donor_dev, hash_config, &acc_part, &acceptor.name)
                .unwrap_or_else(|| {
                    local_shard_broker(&donor_dev, hash_config, &acc_part, &acceptor.name)
                });

        // Copy all rows in the donor's original bounds into the acceptor.
        let records = donor_b.object_records_in_range(&donor.lower, &donor.upper)?;
        let names: Vec<String> = records.iter().map(|r| r.name.clone()).collect();
        if !records.is_empty() {
            acc_b.merge_items(records)?;
        }
        // Remove from donor so listing does not double-count if both still list.
        for name in &names {
            let _ = donor_b.remove_object_named(name);
        }

        // Refresh acceptor stats from live DB.
        let mut acc_updated = acceptor.clone();
        if let Ok(info) = acc_b.get_info() {
            let get = |k: &str| {
                info.iter()
                    .find(|(n, _)| n == k)
                    .and_then(|(_, v)| v.as_i64())
                    .unwrap_or(0)
            };
            acc_updated.object_count = get("object_count");
            acc_updated.bytes_used = get("bytes_used");
            acc_updated.meta_timestamp = ts.clone();
        }

        let mut donor_updated = donor.clone();
        // Bump created timestamp so merge_shards takes the full new row
        // (same timestamp would preserve existing deleted=0).
        donor_updated.timestamp = ts.clone();
        donor_updated.object_count = 0;
        donor_updated.bytes_used = 0;
        donor_updated.meta_timestamp = ts.clone();
        let _ = donor_updated.update_state(shard_state::SHRUNK, Some(&ts));
        // SHRUNK donors are soft-deleted from the namespace (Python).
        donor_updated.deleted = 1;

        // Acceptor bounds/stats: bump timestamp so meta wins cleanly.
        acc_updated.timestamp = ts.clone();

        // Persist own-range view on the acceptor shard (optional consistency).
        let _ = acc_b.merge_shard_ranges(vec![acc_updated.clone()]);
        root.merge_shard_ranges(vec![donor_updated, acc_updated])?;
        finished += 1;
    }
    Ok(finished)
}

/// Back-compat name used by older call sites / tests.
pub fn process_shrinking_donors_stub(broker: &mut ContainerBroker) -> Result<usize, DbError> {
    Ok(find_shrinking_donors(broker)?.len())
}

/// Move misplaced objects out of the **retiring** DB (Python `_cleave` →
/// `_move_misplaced_objects` with `src_broker=get_brokers()[0]` and
/// `src_bounds=_make_default_misplaced_object_bounds`).
///
/// Only objects **outside the own shard range** are misplaced on the retiring
/// DB. A root container (empty lower/upper) therefore yields a no-op: rows
/// that still sit in retiring after a normal cleave are *expected* and stay
/// until [`ContainerBroker::set_sharded_state`] unlinks the retiring file.
///
/// ## Contabo bug (fixed)
/// An earlier implementation re-merged every object that fell *inside* a
/// CLEAVED range into its shard, then wrote a **newer** tombstone
/// (`delete_object` → `deleted=1, etag=noetag`) into retiring. On the next
/// sharder pass those tombstones were merged into the shards (newest-wins)
/// and overwrote the live rows — listings went empty while object GET still
/// 200'd. Match Python: do not re-process already-cleaved retiring rows, and
/// when a real misplaced move succeeds use hard `remove_object_named` (not a
/// tombstone write).
pub fn move_misplaced_from_retiring(
    source: &mut ContainerBroker,
    device: &Path,
    hash_config: &HashPathConfig,
    part: &str,
    ranges: &[ShardRange],
) -> Result<usize, DbError> {
    move_misplaced_from_retiring_with_ring(source, device, hash_config, part, ranges, None)
}

/// Same as [`move_misplaced_from_retiring`] but places owner shards under
/// their ring partition when `ring` is provided.
pub fn move_misplaced_from_retiring_with_ring(
    source: &mut ContainerBroker,
    device: &Path,
    hash_config: &HashPathConfig,
    part: &str,
    ranges: &[ShardRange],
    ring: Option<&swift_ring::Ring>,
) -> Result<usize, DbError> {
    let Some(mut retiring) = source.retiring_broker() else {
        return Ok(0);
    };
    let own = match source.get_own_shard_range(false)? {
        Some(o) => o,
        None => return Ok(0),
    };
    // `_make_default_misplaced_object_bounds`: only outside own range.
    let mut bounds: Vec<(String, String)> = Vec::new();
    if !own.lower.is_empty() {
        bounds.push((String::new(), own.lower.clone()));
    }
    if !own.upper.is_empty() {
        bounds.push((own.upper.clone(), String::new()));
    }
    if bounds.is_empty() {
        return Ok(0);
    }
    let source_path = source.path();
    let mut moved = 0usize;
    for (lower, upper) in &bounds {
        let records = retiring.object_records_in_range(lower, upper)?;
        for rec in records {
            let name = rec.name.clone();
            let Some(owner) = ranges.iter().find(|r| {
                r.deleted == 0
                    && (r.lower.is_empty() || name.as_str() > r.lower.as_str())
                    && (r.upper.is_empty() || name.as_str() <= r.upper.as_str())
            }) else {
                continue;
            };
            if owner.name == source_path {
                continue;
            }
            let spart = shard_part_for(&owner.name, ring, part);
            let mut shard = local_shard_broker(device, hash_config, &spart, &owner.name);
            shard.merge_items(vec![rec])?;
            // Hard-delete from retiring (Python `remove_objects`), not tombstone.
            retiring.remove_object_named(&name)?;
            moved += 1;
        }
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
    /// When true, SHARDED roots run
    /// [`process_shrinking_donors`] for multi-primary/local multi-device
    /// auto-shrink. This is opt-in because cross-node donor discovery and
    /// crash-safe handoff are not yet product-proven.
    pub auto_shrink: bool,
    pub shard_size: i64,
    pub minimum_shard_size: i64,
}

impl Default for SharderRunOpts {
    fn default() -> Self {
        Self {
            cleave_batch_size: 2,
            auto_shard: false,
            auto_shrink: false,
            shard_size: 1_000_000,
            minimum_shard_size: 100_000,
        }
    }
}

/// One full sweep of a device's container DBs (local replicator / SAIO path).
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

/// Sweep with full Wave 3 options (`auto_shard`, shard sizes) using
/// [`LocalShardReplicator`] (same-device; does not break SAIO).
pub fn run_once_with_opts(
    device: &Path,
    hash_config: &HashPathConfig,
    opts: &SharderRunOpts,
) -> SharderStats {
    let mut local = LocalShardReplicator;
    run_once_with_opts_and_replicator(device, hash_config, opts, &mut local)
}

/// Re-open a broker with account/container from `container_stat` so
/// [`ContainerBroker::get_db_state`] can compare the own-range epoch (needed
/// for SHARDED detection and own-range filters).
fn broker_with_path_from_db(db: &Path) -> Result<ContainerBroker, DbError> {
    let mut probe = ContainerBroker::new(db, "", "");
    let info = probe.get_info()?;
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
    if account.is_empty() {
        Ok(probe)
    } else {
        Ok(ContainerBroker::new(db, &account, &container))
    }
}

/// Sweep with an injectable [`ShardReplicator`] for multi-node shard create.
///
/// Pass [`LookupHttpShardReplicator`] (ring callback + transport) so each
/// uncleaved range is created on its ring primaries before local cleave.
/// Pass [`LocalShardReplicator`] for lab/SAIO.
pub fn run_once_with_opts_and_replicator(
    device: &Path,
    hash_config: &HashPathConfig,
    opts: &SharderRunOpts,
    replicator: &mut dyn ShardReplicator,
) -> SharderStats {
    run_once_with_opts_replicator_and_ring(device, hash_config, opts, replicator, None)
}

/// Sweep with replicator + optional ring so local shard DBs land on the
/// correct partition for listing fan-out.
pub fn run_once_with_opts_replicator_and_ring(
    device: &Path,
    hash_config: &HashPathConfig,
    opts: &SharderRunOpts,
    replicator: &mut dyn ShardReplicator,
    ring: Option<&swift_ring::Ring>,
) -> SharderStats {
    let mut stats = SharderStats::default();
    for db in db_locations(device, "containers") {
        stats.containers_seen += 1;
        let mut broker = match broker_with_path_from_db(&db) {
            Ok(b) => b,
            Err(_) => {
                stats.failures += 1;
                continue;
            }
        };
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
                match process_sharding_container_detailed_with_ring(
                    &mut broker,
                    device,
                    hash_config,
                    &part,
                    opts.cleave_batch_size,
                    replicator,
                    ring,
                ) {
                    Ok(out) => {
                        stats.cleaved_batches += 1;
                        stats.replicate_errors += out.replicate_errors;
                        if out.finished {
                            stats.finished += 1;
                        }
                    }
                    Err(_) => stats.failures += 1,
                }
            }
            DbState::Unsharded if opts.auto_shard => match maybe_auto_shard(&mut broker, opts) {
                Ok(true) => {
                    stats.sharding += 1;
                    match process_sharding_container_detailed_with_ring(
                        &mut broker,
                        device,
                        hash_config,
                        &part,
                        opts.cleave_batch_size,
                        replicator,
                        ring,
                    ) {
                        Ok(out) => {
                            stats.cleaved_batches += 1;
                            stats.replicate_errors += out.replicate_errors;
                            if out.finished {
                                stats.finished += 1;
                            }
                        }
                        Err(_) => stats.failures += 1,
                    }
                }
                Ok(false) => stats.skipped += 1,
                Err(_) => stats.failures += 1,
            },
            DbState::Sharded => {
                // Multi-primary auto-shrink product: move objects from
                // SHRINKING donors into acceptors across local device
                // siblings; mark donors SHRUNK. Skip when auto_shrink=false.
                if !opts.auto_shrink {
                    stats.skipped += 1;
                    continue;
                }
                match process_shrinking_donors(&mut broker, device, hash_config, &part, ring) {
                    Ok(n) if n > 0 => {
                        stats.shrinking_donors += n as u64;
                        stats.finished += n as u64;
                    }
                    Ok(_) => stats.skipped += 1,
                    Err(_) => stats.failures += 1,
                }
            }
            DbState::Unsharded | DbState::Collapsed | DbState::NotFound => {
                stats.skipped += 1;
            }
        }
    }
    stats
}

/// Convenience: ring-backed multi-node sweep (TCP PUT to primaries).
///
/// Equivalent to building [`lookup_replicator_for_ring`] and calling
/// [`run_once_with_opts_and_replicator`]. When `container_ring` is `None`,
/// falls back to local SAIO path.
pub fn run_once_with_opts_and_ring(
    device: &Path,
    hash_config: &HashPathConfig,
    opts: &SharderRunOpts,
    container_ring: Option<&swift_ring::Ring>,
) -> SharderStats {
    match container_ring {
        Some(ring) => {
            let mut rep = lookup_replicator_for_ring(ring);
            run_once_with_opts_replicator_and_ring(device, hash_config, opts, &mut rep, Some(ring))
        }
        None => run_once_with_opts(device, hash_config, opts),
    }
}

/// If object_count ≥ shard_size, find ranges + enter SHARDING. Returns true
/// when the container is now ready to cleave.
pub fn maybe_auto_shard(
    broker: &mut ContainerBroker,
    opts: &SharderRunOpts,
) -> Result<bool, DbError> {
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
    broker.set_sharding_state()
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
            b.put_object(
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
            auto_shrink: true,
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
        map.responses.insert("10.0.0.1:6201/sda".into(), 201);
        map.responses.insert("10.0.0.2:6201/sda".into(), 201);
        map.responses.insert("10.0.0.3:6201/sda".into(), 503);
        let mut ok_rep = HttpShardReplicator::new(nodes.clone(), map);
        assert!(ok_rep.replicate_shard(".shards_AUTH_test/c-0", "0").is_ok());
        assert_eq!(ok_rep.quorum, 2);

        let mut fail_map = MapShardHttpTransport::new();
        fail_map.responses.insert("10.0.0.1:6201/sda".into(), 201);
        // only 1 of 3 → below quorum 2
        let mut bad = HttpShardReplicator::new(nodes, fail_map);
        let err = bad
            .replicate_shard(".shards_AUTH_test/c-0", "0")
            .unwrap_err();
        assert!(err.contains("quorum failed"), "{err}");
    }

    #[test]
    fn test_move_misplaced_from_retiring_is_noop_for_root_namespace() {
        // Root own range spans ("", ""): default misplaced bounds are empty,
        // so retiring rows (including post-cleave leftovers) are not re-moved.
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
                .put_object(
                    name,
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
        let mut retiring = source.retiring_broker().expect("retiring db");
        retiring
            .put_object(
                "m2",
                "1751500002.00000",
                1,
                "text/plain",
                "e",
                0,
                0,
                None,
                None,
            )
            .unwrap();
        drop(retiring);
        let moved =
            move_misplaced_from_retiring(&mut source, &device, &hash_config, "0", &ranges).unwrap();
        assert_eq!(
            moved, 0,
            "root whole-namespace must not re-move retiring rows"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_move_misplaced_outside_own_range_into_owner_shard() {
        // Shrunk own range (lower=m): objects ≤ m are outside and must move.
        let hash_config = HashPathConfig::new("", "changeme").unwrap();
        let dir = std::env::temp_dir().join(format!("swift-sharder-mis2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let device = dir.join("d1");
        let account = "AUTH_test";
        let container = "shardlike";
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
                .put_object(
                    name,
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
        // Own range only covers (m, +inf]; a1 is outside and misplaced.
        let mut own = source.get_own_shard_range(false).unwrap().unwrap();
        own.lower = "m".into();
        own.upper = String::new();
        own.epoch = Some(epoch.into());
        own.state = shard_state::SHARDING;
        own.timestamp = epoch.into();
        own.state_timestamp = epoch.into();
        source.merge_shard_ranges(vec![own]).unwrap();
        let ranges = vec![{
            let mut sr = ShardRange::new(".shards_AUTH_test/c-lo", epoch, "", "m");
            sr.state = shard_state::ACTIVE;
            sr
        }];
        source.merge_shard_ranges(ranges.clone()).unwrap();
        assert!(source.set_sharding_state().unwrap());
        let moved =
            move_misplaced_from_retiring(&mut source, &device, &hash_config, "0", &ranges).unwrap();
        assert!(
            moved >= 1,
            "expected a1 (and possibly more) moved, got {moved}"
        );
        let mut lo = local_shard_broker(&device, &hash_config, "0", &ranges[0].name);
        let objs = lo
            .object_records_in_range("", "")
            .unwrap()
            .into_iter()
            .map(|r| (r.name, r.deleted, r.etag))
            .collect::<Vec<_>>();
        assert!(
            objs.iter()
                .any(|(n, d, e)| n == "a1" && *d == 0 && e == "e"),
            "misplaced live object must stay live, got {objs:?}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Contabo regression: multi-pass cleave (batch_size=1) must not leave
    /// shard rows as tombstones (deleted=1, etag=noetag, size=0).
    #[test]
    fn test_multipass_cleave_keeps_live_objects_not_tombstones() {
        let hash_config = HashPathConfig::new("", "changeme").unwrap();
        let dir = std::env::temp_dir().join(format!("swift-sharder-live-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let device = dir.join("d1");
        let account = "AUTH_test";
        let container = "livec";
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
                    10 + i as i64,
                    "text/plain",
                    &format!("etag{i:04}"),
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
        // own range + epoch must survive set_sharding_state (db_state path)
        let own = source.get_own_shard_range(true).unwrap();
        assert!(own.is_some(), "own range must persist into fresh epoch DB");
        assert!(own.unwrap().epoch.is_some());

        // Multi-pass with batch_size=1 (mirrors daemon sweeps + Contabo load).
        for _ in 0..8 {
            let finished =
                process_sharding_container(&mut source, &device, &hash_config, "0", 1).unwrap();
            if finished {
                break;
            }
        }

        let ranges = source
            .get_shard_ranges(&GetShardRangesArgs {
                include_own: false,
                ..GetShardRangesArgs::default()
            })
            .unwrap();
        assert!(!ranges.is_empty());
        let mut live_total = 0i64;
        for sr in &ranges {
            let mut shard = local_shard_broker(&device, &hash_config, "0", &sr.name);
            let rows = shard.object_records_in_range("", "").unwrap();
            for r in &rows {
                assert_eq!(
                    r.deleted, 0,
                    "cleaved object {} became tombstone (deleted=1 etag={})",
                    r.name, r.etag
                );
                assert_ne!(r.etag, "noetag", "tombstone etag on {}", r.name);
                assert!(r.size > 0, "zero size on live object {}", r.name);
                live_total += 1;
            }
            // object_count must reflect live only
            let oc = shard
                .get_info()
                .unwrap()
                .into_iter()
                .find(|(k, _)| k == "object_count")
                .and_then(|(_, v)| v.as_i64())
                .unwrap_or(-1);
            assert_eq!(oc, rows.len() as i64, "shard {} object_count", sr.name);
        }
        assert_eq!(live_total, 10, "all 10 objects must be live across shards");
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
            auto_shrink: true,
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
        let dir =
            std::env::temp_dir().join(format!("swift-sharder-auto-run-{}", std::process::id()));
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
            auto_shrink: true,
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
        let mut strict = HttpShardReplicator::new(
            nodes.clone(),
            MapShardHttpTransport {
                responses: map.responses.clone(),
                calls: Vec::new(),
            },
        );
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
        assert_eq!(split_shard_name("nopath"), (String::new(), "nopath".into()));
        let mut local = LocalShardReplicator;
        assert!(local.replicate_shard("a/c", "0").is_ok());
    }

    #[test]
    fn test_primary_shard_replica_nodes_selection() {
        assert_eq!(default_shard_quorum(0), 1);
        assert_eq!(default_shard_quorum(1), 1);
        assert_eq!(default_shard_quorum(2), 2);
        assert_eq!(default_shard_quorum(3), 2);
        assert_eq!(default_shard_quorum(4), 3);

        let from_devs = shard_replicas_from_ring_devices([
            ("10.0.0.1", 6201u16, "sda"),
            ("10.0.0.2", 6201u16, "sdb"),
            ("10.0.0.3", 6201u16, "sdc"),
        ]);
        assert_eq!(from_devs.len(), 3);
        assert_eq!(from_devs[0].ip, "10.0.0.1");
        assert_eq!(from_devs[0].device, "sda");
        assert_eq!(from_devs[2].port, 6201);

        // Simulated ring: get_nodes for account/container returns fixed primaries.
        let (part, nodes) =
            primary_shard_replica_nodes(".shards_AUTH_test/c-epoch-0", |account, container| {
                assert_eq!(account, ".shards_AUTH_test");
                assert_eq!(container, "c-epoch-0");
                Ok((
                    7u32,
                    vec![
                        ("10.1.0.1".into(), 6201, "d1".into()),
                        ("10.1.0.2".into(), 6201, "d1".into()),
                        ("10.1.0.3".into(), 6201, "d1".into()),
                    ],
                ))
            })
            .unwrap();
        assert_eq!(part, "7");
        assert_eq!(nodes.len(), 3);
        assert_eq!(nodes[1].ip, "10.1.0.2");

        // Invalid name
        assert!(primary_shard_replica_nodes("nopath", |_, _| Ok((0, vec![]))).is_err());

        // Empty primaries rejected
        let err = primary_shard_replica_nodes(".shards_a/c", |_, _| Ok((1, vec![]))).unwrap_err();
        assert!(err.contains("no primary"), "{err}");

        // Wire into HttpShardReplicator and hit quorum
        let mut map = MapShardHttpTransport::new();
        for n in &nodes {
            map.responses
                .insert(format!("{}:{}/{}", n.ip, n.port, n.device), 201);
        }
        let mut rep = http_replicator_for_primaries(nodes, map);
        assert_eq!(rep.quorum, 2);
        assert!(rep
            .replicate_shard(".shards_AUTH_test/c-epoch-0", &part)
            .is_ok());
        assert_eq!(rep.transport.calls.len(), 3);
    }

    /// Mock ring callback: different shards → different primary sets/parts.
    #[test]
    fn test_lookup_http_shard_replicator_per_shard_primaries() {
        let mut map = MapShardHttpTransport::new();
        // shard-0 → part 3, nodes a,b,c
        for host in ["10.0.0.1", "10.0.0.2", "10.0.0.3"] {
            map.responses.insert(format!("{host}:6201/sda"), 201);
        }
        // shard-1 → part 9, nodes d,e,f
        for host in ["10.0.1.1", "10.0.1.2", "10.0.1.3"] {
            map.responses.insert(format!("{host}:6201/sdb"), 201);
        }

        let mut lookup = LookupHttpShardReplicator::new(map, |account, container| {
            assert_eq!(account, ".shards_a");
            match container {
                "c-0" => Ok((
                    3u32,
                    vec![
                        ("10.0.0.1".into(), 6201, "sda".into()),
                        ("10.0.0.2".into(), 6201, "sda".into()),
                        ("10.0.0.3".into(), 6201, "sda".into()),
                    ],
                )),
                "c-1" => Ok((
                    9u32,
                    vec![
                        ("10.0.1.1".into(), 6201, "sdb".into()),
                        ("10.0.1.2".into(), 6201, "sdb".into()),
                        ("10.0.1.3".into(), 6201, "sdb".into()),
                    ],
                )),
                other => Err(format!("unexpected container {other}")),
            }
        });

        // fallback_part ignored — ring part is used
        assert!(lookup.replicate_shard(".shards_a/c-0", "999").is_ok());
        assert!(lookup.replicate_shard(".shards_a/c-1", "999").is_ok());
        let calls = &lookup.transport.calls;
        assert_eq!(calls.len(), 6);
        assert!(calls.iter().any(|c| c.1 == "3" && c.3 == "c-0"));
        assert!(calls.iter().any(|c| c.1 == "9" && c.3 == "c-1"));
        // Missing primaries → error
        let mut bad =
            LookupHttpShardReplicator::new(MapShardHttpTransport::new(), |_, _| Ok((1, vec![])));
        assert!(bad.replicate_shard(".shards_a/c-x", "0").is_err());
    }

    #[test]
    fn test_run_once_with_replicator_invokes_create_for_uncleaved() {
        let hash_config = HashPathConfig::new("", "changeme").unwrap();
        let dir = std::env::temp_dir().join(format!("swift-sharder-mn-run-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let device = dir.join("d1");
        let account = "AUTH_test";
        let container = "mn";
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
        for i in 0..6 {
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
        let ranges = source
            .get_shard_ranges(&GetShardRangesArgs {
                include_own: false,
                ..GetShardRangesArgs::default()
            })
            .unwrap();
        assert!(!ranges.is_empty());
        drop(source);

        // Recording replicator: counts ensure_shard calls, always ok.
        struct RecordingRep {
            names: Vec<String>,
        }
        impl ShardReplicator for RecordingRep {
            fn replicate_shard(&mut self, shard_name: &str, _part: &str) -> Result<(), String> {
                self.names.push(shard_name.to_string());
                Ok(())
            }
        }
        let mut rep = RecordingRep { names: Vec::new() };
        let opts = SharderRunOpts {
            cleave_batch_size: 10,
            auto_shard: false,
            auto_shrink: true,
            shard_size: 1_000_000,
            minimum_shard_size: 1,
        };
        let stats = run_once_with_opts_and_replicator(&device, &hash_config, &opts, &mut rep);
        assert_eq!(stats.failures, 0, "{stats:?}");
        assert_eq!(stats.sharding, 1);
        assert!(stats.finished >= 1, "{stats:?}");
        assert_eq!(stats.replicate_errors, 0);
        // One create call per uncleaved range
        assert_eq!(rep.names.len(), ranges.len(), "{:?}", rep.names);
        for r in &ranges {
            assert!(rep.names.contains(&r.name), "missing {}", r.name);
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_run_once_with_lookup_replicator_mock_ring_and_errors() {
        let hash_config = HashPathConfig::new("", "changeme").unwrap();
        let dir =
            std::env::temp_dir().join(format!("swift-sharder-lookup-run-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let device = dir.join("d1");
        let account = "AUTH_test";
        let container = "lk";
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
        for i in 0..4 {
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
        find_and_merge_found_ranges(&mut source, account, container, 2, 1, epoch).unwrap();
        source.enable_sharding(epoch).unwrap();
        assert!(source.set_sharding_state().unwrap());
        drop(source);

        // Only 1/3 nodes ok → quorum fail; local cleave must still finish.
        let mut map = MapShardHttpTransport::new();
        map.responses.insert("10.9.0.1:6201/d".into(), 201);
        let mut lookup = LookupHttpShardReplicator::new(map, |_a, _c| {
            Ok((
                0u32,
                vec![
                    ("10.9.0.1".into(), 6201, "d".into()),
                    ("10.9.0.2".into(), 6201, "d".into()),
                    ("10.9.0.3".into(), 6201, "d".into()),
                ],
            ))
        });
        let opts = SharderRunOpts {
            cleave_batch_size: 10,
            ..SharderRunOpts::default()
        };
        let stats = run_once_with_opts_and_replicator(&device, &hash_config, &opts, &mut lookup);
        // Local cleave still works despite remote quorum fails
        assert_eq!(stats.failures, 0, "{stats:?}");
        assert!(stats.finished >= 1, "{stats:?}");
        assert!(stats.replicate_errors >= 1, "{stats:?}");
        let mut check = ContainerBroker::new(&db, account, container);
        assert_eq!(check.get_db_state().unwrap(), DbState::Sharded);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_ring_get_nodes_for_shard_and_run_with_ring() {
        use swift_ring::{Ring, RingData, RingDevice};

        fn dev(id: u64) -> RingDevice {
            RingDevice {
                id,
                region: 1,
                zone: 1,
                ip: format!("10.0.0.{}", id + 1),
                port: 6201,
                replication_ip: None,
                replication_port: None,
                device: format!("sd{id}"),
                weight: 1.0,
                meta: String::new(),
                extra: Default::default(),
            }
        }
        let data = RingData::from_parts(
            vec![Some(dev(0)), Some(dev(1)), Some(dev(2))],
            32, // part_power 0 → single partition
            vec![vec![0u32], vec![1u32], vec![2u32]],
        );
        let ring = Ring::new(data, HashPathConfig::new("", "changeme").unwrap());
        let (part, nodes) =
            ring_get_nodes_for_shard(&ring, ".shards_AUTH_test", "c-epoch-0").unwrap();
        assert_eq!(part, 0);
        assert_eq!(nodes.len(), 3);
        assert_eq!(nodes[0].0, "10.0.0.1");
        assert_eq!(nodes[0].2, "sd0");

        // run_once_with_opts_and_ring(None) == local path
        let hash_config = HashPathConfig::new("", "changeme").unwrap();
        let dir =
            std::env::temp_dir().join(format!("swift-sharder-ring-none-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let device = dir.join("d1");
        std::fs::create_dir_all(device.join("containers")).unwrap();
        let stats =
            run_once_with_opts_and_ring(&device, &hash_config, &SharderRunOpts::default(), None);
        assert_eq!(stats.containers_seen, 0);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_range_covers_and_find_acceptor() {
        let mut donor = ShardRange::new("d", "1", "", "m");
        donor.state = shard_state::SHRINKING;
        let mut acc = ShardRange::new("a", "1", "", "");
        acc.state = shard_state::ACTIVE;
        assert!(range_covers(&acc, &donor));
        let ranges = vec![donor.clone(), acc.clone()];
        assert_eq!(
            find_shrink_acceptor(&ranges, &donor).map(|r| r.name.as_str()),
            Some("a")
        );
    }

    #[test]
    fn test_process_shrinking_donors_moves_objects_and_marks_shrunk() {
        let hash_config = HashPathConfig::new("", "changeme").unwrap();
        let dir =
            std::env::temp_dir().join(format!("swift-sharder-shrink-move-{}", std::process::id()));
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
        let epoch = "1751500010.00000";
        let mut donor = ShardRange::new(".shards_AUTH_test/c-d0", epoch, "", "m");
        donor.state = shard_state::SHRINKING;
        donor.object_count = 1;
        // Acceptor covers full namespace (compact expand).
        let mut acceptor = ShardRange::new(".shards_AUTH_test/c-a0", epoch, "", "");
        acceptor.state = shard_state::ACTIVE;
        source
            .merge_shard_ranges(vec![donor.clone(), acceptor.clone()])
            .unwrap();
        // Seed one object into the donor shard DB under part "0".
        let mut donor_b = local_shard_broker(&device, &hash_config, "0", &donor.name);
        donor_b
            .merge_items(vec![swift_db::ObjectRecord {
                name: "aaa".into(),
                created_at: "1751500011.00000".into(),
                size: 3,
                content_type: "text/plain".into(),
                etag: "d41d8cd98f00b204e9800998ecf8427e".into(),
                deleted: 0,
                storage_policy_index: 0,
                ctype_timestamp: None,
                meta_timestamp: None,
            }])
            .unwrap();
        assert_eq!(donor_b.object_records_in_range("", "m").unwrap().len(), 1);

        let donors = find_shrinking_donors(&mut source).unwrap();
        assert_eq!(
            donors.len(),
            1,
            "expected one SHRINKING donor, got {donors:?}"
        );
        let all = source
            .get_shard_ranges(&GetShardRangesArgs {
                include_own: false,
                include_deleted: false,
                ..Default::default()
            })
            .unwrap();
        assert!(
            find_shrink_acceptor(&all, &donors[0]).is_some(),
            "no acceptor covering donor among {all:?}"
        );
        let n = process_shrinking_donors(&mut source, &device, &hash_config, "0", None).unwrap();
        assert_eq!(n, 1, "process_shrinking_donors returned {n}");

        let after = source
            .get_shard_ranges(&GetShardRangesArgs {
                include_deleted: true,
                include_own: false,
                ..Default::default()
            })
            .unwrap();
        let d = after.iter().find(|r| r.name == donor.name).unwrap();
        assert_eq!(d.state, shard_state::SHRUNK, "{d:?}");
        assert_eq!(d.deleted, 1);
        assert_eq!(d.object_count, 0);

        let mut acc_b = local_shard_broker(&device, &hash_config, "0", &acceptor.name);
        let moved = acc_b.object_records_in_range("", "").unwrap();
        assert!(
            moved.iter().any(|r| r.name == "aaa" && r.deleted == 0),
            "{moved:?}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Multi-device (same host) auto-shrink: donor DB on d2, root on d1.
    #[test]
    fn test_multi_device_auto_shrink_finds_donor_sibling() {
        let hash_config = HashPathConfig::new("", "changeme").unwrap();
        let dir = std::env::temp_dir().join(format!(
            "swift-sharder-multidev-shrink-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let d1 = dir.join("d1");
        let d2 = dir.join("d2");
        let account = "AUTH_test";
        let container = "root";
        let hsh = hash_config
            .hash_path(account, Some(container), None)
            .unwrap();
        let suf = &hsh[hsh.len() - 3..];
        let hd = d1.join("containers/0").join(suf).join(&hsh);
        std::fs::create_dir_all(&hd).unwrap();
        let db = hd.join(format!("{hsh}.db"));
        let mut source = ContainerBroker::new(&db, account, container);
        source
            .initialize("1751500000.00000", 0, "1751500000.00000", "id")
            .unwrap();
        let epoch = "1751500010.00000";
        let mut donor = ShardRange::new(".shards_AUTH_test/c-d0", epoch, "", "m");
        donor.state = shard_state::SHRINKING;
        donor.object_count = 1;
        let mut acceptor = ShardRange::new(".shards_AUTH_test/c-a0", epoch, "", "");
        acceptor.state = shard_state::ACTIVE;
        source
            .merge_shard_ranges(vec![donor.clone(), acceptor.clone()])
            .unwrap();
        // Donor lives on sibling device d2 (multi-primary local topology).
        let mut donor_b = local_shard_broker(&d2, &hash_config, "0", &donor.name);
        donor_b
            .merge_items(vec![swift_db::ObjectRecord {
                name: "bbb".into(),
                created_at: "1751500011.00000".into(),
                size: 3,
                content_type: "text/plain".into(),
                etag: "d41d8cd98f00b204e9800998ecf8427e".into(),
                deleted: 0,
                storage_policy_index: 0,
                ctype_timestamp: None,
                meta_timestamp: None,
            }])
            .unwrap();

        let n = process_shrinking_donors(&mut source, &d1, &hash_config, "0", None).unwrap();
        assert_eq!(n, 1, "multi-device shrink should finish donor on sibling");

        let after = source
            .get_shard_ranges(&GetShardRangesArgs {
                include_deleted: true,
                include_own: false,
                ..Default::default()
            })
            .unwrap();
        let d = after.iter().find(|r| r.name == donor.name).unwrap();
        assert_eq!(d.state, shard_state::SHRUNK);

        // Acceptor got the row (created under donor device d2 path).
        let mut acc_b = local_shard_broker(&d2, &hash_config, "0", &acceptor.name);
        let moved = acc_b.object_records_in_range("", "").unwrap();
        assert!(
            moved.iter().any(|r| r.name == "bbb" && r.deleted == 0),
            "{moved:?}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_auto_shrink_opt_default_false() {
        assert!(!SharderRunOpts::default().auto_shrink);
    }
}
