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
//! - [`find_compactible_shard_sequences`] / [`find_and_enable_shrinking_candidates`]:
//!   Python `_find_and_enable_shrinking_candidates` on a SHARDED root when
//!   `auto_shard` (not `auto_shrink`): mark small donors SHRINKING, expand the
//!   acceptor, HTTP PUT the pair onto donor/acceptor containers
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
//! 2. **Durable multi-primary object cleave under concurrent load** — after
//!    local cleave, [`replicate_broker_to_ring_peers`] usyncs (or rsyncs)
//!    the shard DB onto ring primaries. Live G6/Contabo unexpected=0 is
//!    still required before KEEP.
//! 3. **Cross-node shrink over HTTP** — when the donor DB lives only on a
//!    remote primary, this process skips (never fabricates empty donors).
//!    Multi-device **same host** shrink has unit coverage (see
//!    [`process_shrinking_donors`] + `auto_shrink`) but is disabled by default.
//!    It is not a multi-primary product claim. Optional lab harness:
//!    `tools/soak/multi-primary-shrink-soak.sh`.
//! 4. WAN / async container-sync (wontfix).

use std::path::{Path, PathBuf};

use swift_core::hashing::HashPathConfig;
use swift_db::{
    db_locations, get_db_files, make_db_file_path, make_shard_name, remove_replicated_handoff_db,
    replicate_container_db, shard_state, shards_account_name, ContainerBroker, DbError, DbState,
    GetShardRangesArgs, ObjectRecord, ShardRange,
};

/// Legacy single-key persist (pre Python `Context-{db_id}` namespace).
/// Still accepted on load so already-written lab DBs remain readable.
pub const CLEAVING_CONTEXT_KEY: &str = "X-Container-Sysmeta-Shard-Cleaving-Context";

/// Python `set_sharding_sysmeta('Context-' + ref)` → this header prefix plus
/// the retiring/fresh DB id. Probe `CleavingContext.load_all` only accepts
/// keys that strip to `Context-*`.
pub const CLEAVING_CONTEXT_KEY_PREFIX: &str = "X-Container-Sysmeta-Shard-Context-";

/// Sysmeta header Python stores for one cleaving context.
pub fn cleaving_context_sysmeta_key(ref_id: &str) -> String {
    format!("{CLEAVING_CONTEXT_KEY_PREFIX}{ref_id}")
}

fn is_cleaving_context_key(k: &str) -> bool {
    let kl = k.to_ascii_lowercase();
    kl == CLEAVING_CONTEXT_KEY.to_ascii_lowercase()
        || kl.starts_with(&CLEAVING_CONTEXT_KEY_PREFIX.to_ascii_lowercase())
}

fn broker_db_id(broker: &mut ContainerBroker) -> String {
    broker
        .get_info()
        .ok()
        .and_then(|info| {
            info.into_iter()
                .find(|(k, _)| k == "id")
                .and_then(|(_, v)| v.as_text())
        })
        .unwrap_or_default()
}

/// Python `CleavingContext._make_ref(brokers[0])`: the *retiring* DB id
/// while sharding. Fresh epoch DBs each get a new id; using that as `ref`
/// makes every replica write `Context-shardid` and replicator merge keeps
/// one key (probe L1261 `len(contexts)==3`).
fn broker_cleaving_ref(broker: &mut ContainerBroker) -> String {
    if let Some(mut retiring) = broker.retiring_broker() {
        let id = broker_db_id(&mut retiring);
        if !id.is_empty() {
            return id;
        }
    }
    broker_db_id(broker)
}

fn broker_max_row(broker: &mut ContainerBroker) -> i64 {
    broker.get_max_row().ok().flatten().unwrap_or(-1)
}

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
    /// Python `CleavingContext.misplaced_done`. Probe `load_all`/`done()`
    /// requires this plus `cleaving_done` and `max_row == cleave_to_row`.
    pub misplaced_done: bool,
    pub max_row: i64,
    pub cleave_to_row: i64,
    /// Python `last_cleave_to_row` (`null` until a reset).
    pub last_cleave_to_row: Option<i64>,
    /// Python `replication_time` (seconds; unused locally).
    pub replication_time: i64,
    /// Broker DB id (`Context-{ref}` sysmeta namespace).
    pub ref_id: String,
}

impl CleavingContext {
    /// Python `CleavingContext.done()`.
    pub fn done(&self) -> bool {
        self.misplaced_done && self.cleaving_done && self.max_row == self.cleave_to_row
    }

    /// Serialize to a compact JSON object (Python `dict(CleavingContext)` keys).
    /// Python `json.dumps(dict(self))` is loaded via `CleavingContext(**data)`,
    /// so extra keys would TypeError; keep this set aligned with
    /// `swift/container/sharder.py`.
    pub fn to_json(&self) -> String {
        let last = match self.last_cleave_to_row {
            Some(n) => n.to_string(),
            None => "null".to_string(),
        };
        format!(
            "{{\"ref\":{},\"cursor\":{},\"max_row\":{},\"cleave_to_row\":{},\
             \"last_cleave_to_row\":{},\"cleaving_done\":{},\"misplaced_done\":{},\
             \"ranges_done\":{},\"ranges_todo\":{},\"replication_time\":{}}}",
            json_str(&self.ref_id),
            json_str(&self.cursor),
            self.max_row,
            self.cleave_to_row,
            last,
            if self.cleaving_done { "true" } else { "false" },
            if self.misplaced_done { "true" } else { "false" },
            self.ranges_done,
            self.ranges_todo,
            self.replication_time,
        )
    }

    /// Parse from JSON (tolerant of whitespace).
    pub fn from_json(s: &str) -> Option<Self> {
        let cursor = json_get_str(s, "cursor").unwrap_or_default();
        let ranges_done = json_get_usize(s, "ranges_done").unwrap_or(0);
        let ranges_todo = json_get_usize(s, "ranges_todo").unwrap_or(0);
        let cleaving_done =
            s.contains("\"cleaving_done\":true") || s.contains("\"cleaving_done\": true");
        let misplaced_done =
            s.contains("\"misplaced_done\":true") || s.contains("\"misplaced_done\": true");
        let max_row = json_get_i64(s, "max_row").unwrap_or(0);
        let cleave_to_row = json_get_i64(s, "cleave_to_row").unwrap_or(max_row);
        let last_cleave_to_row = json_get_i64(s, "last_cleave_to_row");
        let replication_time = json_get_i64(s, "replication_time").unwrap_or(0);
        let ref_id = json_get_str(s, "ref").unwrap_or_default();
        Some(Self {
            cursor,
            ranges_done,
            ranges_todo,
            cleaving_done,
            misplaced_done,
            max_row,
            cleave_to_row,
            last_cleave_to_row,
            replication_time,
            ref_id,
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
    json_get_i64(s, key).and_then(|v| usize::try_from(v).ok())
}

fn json_get_i64(s: &str, key: &str) -> Option<i64> {
    let needle = format!("\"{key}\":");
    let rest = s.split(&needle).nth(1)?.trim_start();
    let raw: String = rest
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '-')
        .collect();
    raw.parse().ok()
}

/// Load persisted cleaving context from container sysmeta.
///
/// Python `CleavingContext.load` reads only `Context-{brokers[0].id}` (the
/// retiring DB while SHARDING; the remaining DB after SHARDED). A peer
/// replica's done `Context-*` must not skip local remaining cleave (probe
/// `listing_under_populated_replica` L1517). Legacy single key is the only
/// fallback while SHARDING/unsharded. After SHARDED the retiring file is
/// gone so `Context-{fresh_id}` misses; fall back to a remaining Context-*
/// (saved under the old retiring id) so unit `load().done()` still holds.
pub fn load_cleaving_context(broker: &mut ContainerBroker) -> Result<CleavingContext, DbError> {
    let id = broker_cleaving_ref(broker);
    let md = broker.metadata()?;
    let preferred = if !id.is_empty() {
        Some(cleaving_context_sysmeta_key(&id))
    } else {
        None
    };
    let mut found: Option<CleavingContext> = None;
    let mut other_done: Option<CleavingContext> = None;
    let mut other_context: Option<CleavingContext> = None;
    let mut legacy: Option<CleavingContext> = None;
    for (k, (v, _)) in md {
        if v.is_empty() {
            continue;
        }
        let Some(parsed) = CleavingContext::from_json(&v) else {
            continue;
        };
        if let Some(pref) = &preferred {
            if k.eq_ignore_ascii_case(pref) {
                found = Some(parsed);
                break;
            }
        }
        if k.eq_ignore_ascii_case(CLEAVING_CONTEXT_KEY) {
            legacy = Some(parsed);
        } else if k
            .to_ascii_lowercase()
            .starts_with(&CLEAVING_CONTEXT_KEY_PREFIX.to_ascii_lowercase())
        {
            if parsed.done() && other_done.is_none() {
                other_done = Some(parsed.clone());
            }
            other_context = Some(parsed);
        }
    }
    let state = broker.get_db_state().ok();
    // SHARDING / unsharded: never adopt another replica's Context-* (L1517).
    // SHARDED: retiring file is gone; Context-{old id} is the local finished
    // context — prefer a done() leftover so `load().done()` still holds.
    let picked = if state == Some(DbState::Sharded) {
        found.or(other_done).or(other_context).or(legacy)
    } else {
        found.or(legacy)
    };
    let mut ctx = fill_ref(picked.unwrap_or_default(), &id);
    // Python `CleavingContext.load`: `data['max_row'] = brokers[0].get_max_row()`.
    if state == Some(DbState::Sharding) {
        ctx.max_row = broker_max_row_retiring(broker);
    }
    Ok(ctx)
}

fn broker_max_row_retiring(broker: &mut ContainerBroker) -> i64 {
    if let Some(mut retiring) = broker.retiring_broker() {
        let n = broker_max_row(&mut retiring);
        if n >= 0 {
            return n;
        }
    }
    broker_max_row(broker)
}

/// Python `CleavingContext.load_all`: every non-empty `Context-*` sysmeta
/// on the freshest DB (probe L1261 after `replicators.once()`).
pub fn load_all_cleaving_contexts(
    broker: &mut ContainerBroker,
) -> Result<Vec<(CleavingContext, String)>, DbError> {
    let md = broker.metadata()?;
    let prefix = CLEAVING_CONTEXT_KEY_PREFIX.to_ascii_lowercase();
    let mut out = Vec::new();
    for (k, (v, ts)) in md {
        if v.is_empty() {
            continue;
        }
        if !k.to_ascii_lowercase().starts_with(&prefix) {
            continue;
        }
        if let Some(parsed) = CleavingContext::from_json(&v) {
            out.push((parsed, ts));
        }
    }
    Ok(out)
}

fn fill_ref(mut ctx: CleavingContext, id: &str) -> CleavingContext {
    if ctx.ref_id.is_empty() {
        ctx.ref_id = id.to_string();
    }
    ctx
}

/// Persist cleaving context into container sysmeta under Python's
/// `X-Container-Sysmeta-Shard-Context-{ref}` key so probe
/// `CleavingContext.load_all` sees it.
pub fn save_cleaving_context(
    broker: &mut ContainerBroker,
    ctx: &CleavingContext,
    timestamp: &str,
) -> Result<(), DbError> {
    let mut stored = ctx.clone();
    if stored.ref_id.is_empty() {
        stored.ref_id = broker_cleaving_ref(broker);
    }
    if stored.ref_id.is_empty() {
        stored.ref_id = "unknown".to_string();
    }
    broker.update_metadata(&vec![(
        cleaving_context_sysmeta_key(&stored.ref_id),
        (stored.to_json(), timestamp.to_string()),
    )])
}

/// After a nested replica finishes cleaving, rewrite every stored Context-* so
/// Python `CleavingContext.load_all` / `done()` is True (probe L1356).
fn mark_all_cleaving_contexts_done(
    broker: &mut ContainerBroker,
    done: &CleavingContext,
    timestamp: &str,
) -> Result<(), DbError> {
    let mut local = done.clone();
    if local.ref_id.is_empty() {
        local.ref_id = broker_cleaving_ref(broker);
    }
    if local.ref_id.is_empty() {
        local.ref_id = "unknown".to_string();
    }
    local.misplaced_done = true;
    local.cleaving_done = true;
    local.max_row = local.cleave_to_row;
    let mut updates = vec![(
        cleaving_context_sysmeta_key(&local.ref_id),
        (local.to_json(), timestamp.to_string()),
    )];
    for (mut other, _) in load_all_cleaving_contexts(broker).unwrap_or_default() {
        if other.ref_id == local.ref_id || other.ref_id.is_empty() {
            continue;
        }
        other.misplaced_done = true;
        other.cleaving_done = true;
        other.max_row = other.cleave_to_row;
        updates.push((
            cleaving_context_sysmeta_key(&other.ref_id),
            (other.to_json(), timestamp.to_string()),
        ));
    }
    broker.update_metadata(&updates)
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

    /// Python `_create_shard_containers` PUT, including Quoted-Root sysmeta.
    fn put_container_with_meta(
        &mut self,
        node: &ShardReplicaNode,
        part: &str,
        account: &str,
        container: &str,
        timestamp: &str,
        extra_headers: &[(&str, &str)],
    ) -> Result<u16, String> {
        use std::io::{Read, Write};
        use std::net::{TcpStream, ToSocketAddrs};
        let path = format!(
            "/{}/{}/{}/{}",
            http_path_seg(&node.device),
            http_path_seg(part),
            http_path_seg(account),
            http_path_seg(container)
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
        let mut extra = String::new();
        for (k, v) in extra_headers {
            extra.push_str(k);
            extra.push_str(": ");
            extra.push_str(v);
            extra.push_str("\r\n");
        }
        let req = format!(
            "PUT {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\
             X-Timestamp: {timestamp}\r\n{extra}Content-Length: 0\r\n\r\n",
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

impl ShardHttpTransport for TcpShardHttpTransport {
    fn put_container(
        &mut self,
        node: &ShardReplicaNode,
        part: &str,
        account: &str,
        container: &str,
        timestamp: &str,
    ) -> Result<u16, String> {
        self.put_container_with_meta(node, part, account, container, timestamp, &[])
    }
}

/// Python `_create_shard_containers`: `PUT_shard` the range onto ring
/// primaries with Quoted-Root / Sharding sysmeta so later sharder passes
/// on those replicas treat the DB as a shard (`get_own_shard_range`) and
/// `_update_root_container`.
fn create_shard_on_primaries(
    ring: &swift_ring::Ring,
    shard: &ShardRange,
    root_account: &str,
    root_container: &str,
) -> Result<(), String> {
    let (part, nodes) =
        primary_shard_replica_nodes(&shard.name, |a, c| ring_get_nodes_for_shard(ring, a, c))?;
    let quoted = http_quote(&format!("{root_account}/{root_container}"));
    let extra = [
        ("X-Backend-Auto-Create", "True"),
        ("X-Backend-Allow-Reserved-Names", "true"),
        ("X-Container-Sysmeta-Shard-Quoted-Root", quoted.as_str()),
        ("X-Container-Sysmeta-Sharding", "True"),
        ("X-Backend-Storage-Policy-Index", "0"),
    ];
    let body = shard_ranges_json(std::slice::from_ref(shard));
    let need = default_shard_quorum(nodes.len());
    let ts = swift_core::timestamp::Timestamp::now().internal();
    let (account, container) = split_shard_name(&shard.name);
    let part = part.to_string();
    let mut ok = 0usize;
    let mut errors = Vec::new();
    for node in &nodes {
        match put_shard_ranges_body(node, &part, &account, &container, &ts, &body, &extra) {
            Ok(status) if (200..300).contains(&status) || status == 202 => ok += 1,
            Ok(status) => errors.push(format!("{}:{} → {status}", node.ip, node.port)),
            Err(e) => errors.push(format!("{}:{} → {e}", node.ip, node.port)),
        }
    }
    if ok >= need {
        Ok(())
    } else {
        Err(format!(
            "shard create quorum failed for {}: ok={ok}/{} need={need}; {}",
            shard.name,
            nodes.len(),
            errors.join("; ")
        ))
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
    find_and_merge_found_ranges_named(
        broker,
        account,
        container,
        container,
        shard_size,
        minimum_shard_size,
        timestamp,
    )
}

/// Python `make_shard_ranges`: `shards_account_prefix + root_account`,
/// `root_container`, `parent_container` (the sharding container itself).
fn find_and_merge_found_ranges_named(
    broker: &mut ContainerBroker,
    root_account: &str,
    root_container: &str,
    parent_container: &str,
    shard_size: i64,
    minimum_shard_size: i64,
    timestamp: &str,
) -> Result<Vec<ShardRange>, DbError> {
    let (found, _done) = broker.find_shard_ranges(shard_size, minimum_shard_size)?;
    let shards_account = shards_account_name(root_account);
    let mut ranges = Vec::with_capacity(found.len());
    for f in &found {
        let name = make_shard_name(
            &shards_account,
            root_container,
            parent_container,
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

/// `_cleave_shard_range`: copy the not-yet-synced rows for `range` out of the
/// `retiring` DB into its `shard` container.  A target's incoming sync point
/// and the cleaving context's previous high-water mark jointly prevent an old
/// retiring replica from replaying rows after a reset.
///
/// Both live and deleted rows are copied (Python `yield_objects` order), but
/// object_count / bytes_used are refreshed and CREATED is promoted to CLEAVED
/// only while sharding.  A SHRINKING donor copies into an existing ACTIVE
/// acceptor without changing the acceptor state, matching Python Swift.
pub fn cleave_shard_range(
    retiring: &mut ContainerBroker,
    shard: &mut ContainerBroker,
    source: &mut ContainerBroker,
    range: &mut ShardRange,
    last_cleave_to_row: Option<i64>,
    own_shrinking: bool,
) -> Result<bool, DbError> {
    let initial_state = range.state;
    // The daemon converts FOUND to CREATED before cleaving.  Local/unit
    // callers intentionally allow FOUND as the same first-cleave state.
    let first_cleave = initial_state == shard_state::FOUND || initial_state == shard_state::CREATED;
    let source_db_id = broker_db_id(retiring);
    let source_max_row = broker_max_row(retiring);
    let sync_point = if source_db_id.is_empty() {
        -1
    } else {
        shard.get_sync(&source_db_id, true)?
    };
    let sync_from_row = std::cmp::max(last_cleave_to_row.unwrap_or(-1), sync_point);
    let should_sync = source_max_row == -1 || sync_point < source_max_row;
    let prior_object_count = shard
        .get_info()
        .ok()
        .and_then(|info| {
            info.iter()
                .find(|(n, _)| *n == "object_count")
                .and_then(|(_, v)| v.as_i64())
        })
        .unwrap_or(0);
    let records = if should_sync {
        retiring.object_records_in_range_since(&range.lower, &range.upper, sync_from_row)?
    } else {
        Vec::new()
    };
    let had_objects = !records.is_empty();
    if had_objects {
        shard.merge_items(records)?;
    }

    if should_sync && !source_db_id.is_empty() {
        let mut syncs = vec![(source_max_row, source_db_id)];
        syncs.extend(retiring.get_syncs(true)?);
        shard.merge_syncs(&syncs, true)?;
    }

    if !own_shrinking && first_cleave {
        // Refresh range stats from live rows only (triggers keep object_count
        // equal to deleted=0 rows; tombstones contribute zero).
        let info = shard.get_info()?;
        let get = |k: &str| {
            info.iter()
                .find(|(n, _)| n == k)
                .and_then(|(_, v)| v.as_i64())
                .unwrap_or(0)
        };
        let object_count = get("object_count");
        let bytes_used = get("bytes_used");
        // Advance only one normal-timestamp tick past the FOUND estimate.
        // ShardRange metadata is a Python `NormalTimestamp`, so an internal
        // offset (`_<hex>`) is not wire-compatible. Using wall
        // clock time here can make this stale first-cleave snapshot newer
        // than an authoritative shard report processed earlier in the same
        // device sweep (for example, 50 objects overwriting a later 51 after
        // misplaced-object movement). One 10-microsecond tick is enough to
        // make the copied byte count win over the original estimate, while
        // every real later shard report still wins by normal timestamp.
        let meta_timestamp = range
            .meta_timestamp
            .parse::<swift_core::timestamp::Timestamp>()
            .ok()
            .and_then(|timestamp| timestamp.apply_delta(1).ok())
            .map(|timestamp| timestamp.normal())
            .unwrap_or_else(|| swift_core::timestamp::Timestamp::now().normal());
        range.update_meta(object_count, bytes_used, &meta_timestamp);
        range.state = shard_state::CLEAVED;
        shard.merge_shard_ranges(vec![range.clone()])?;
    }
    source.merge_shard_ranges(vec![range.clone()])?;

    // Python `_cleave_shard_broker`: CLEAVE_EMPTY does not consume
    // `cleave_batch_size` only when yield_objects found nothing AND the
    // shard broker was just created this pass. An already-CLEAVED range
    // with a newly-created empty local shard and no retiring rows is
    // therefore CLEAVE_EMPTY (probe listing_under_populated L1494). The
    // same already-CLEAVED range with retiring rows is CLEAVE_SUCCESS and
    // still consumes the batch (probe L1191 / L1204).
    let newly_created_empty = prior_object_count == 0 && sync_point < 0;
    let consume_batch = if !should_sync {
        true
    } else if had_objects {
        true
    } else {
        !newly_created_empty
    };
    Ok(consume_batch)
}

/// Python `shard_range.upper >= own_shard_range.upper` with empty = MAX.
fn namespace_upper_covers(range_upper: &str, own_upper: &str) -> bool {
    ShardRange::upper_cmp(range_upper, own_upper) != std::cmp::Ordering::Less
}

/// `_cleave`: cleave up to `batch_size` not-yet-cleaved ranges, advancing the
/// cleave cursor. Objects are read from the container's retiring DB (the
/// broker must be in the SHARDING state, i.e. have a separate retiring DB).
/// `shard_for` yields a (local) broker for a shard range's container.
///
/// Python `_cleave_shard_broker`: `cleaving_done` is set when
/// `shard_range.upper >= own_shard_range.upper` (empty upper = namespace MAX),
/// not only when the last range is MAX. `CLEAVE_EMPTY` still advances the
/// cursor but does not count against `cleave_batch_size`.
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
    let own = source.get_own_shard_range(false)?;
    let own_upper = own.as_ref().map(|o| o.upper.clone()).unwrap_or_default();
    let own_shrinking = own
        .as_ref()
        .is_some_and(|o| o.state == shard_state::SHRINKING || o.state == shard_state::SHRUNK);
    ctx.ranges_todo = ranges
        .iter()
        .filter(|r| r.state != shard_state::SHRINKING)
        .filter(|r| r.upper.is_empty() || r.upper.as_str() > ctx.cursor.as_str())
        .count();
    let mut done_this_batch = 0usize;
    for range in ranges.iter_mut() {
        if ctx.cleaving_done || done_this_batch >= batch_size {
            break;
        }
        if range.state == shard_state::SHRINKING {
            continue;
        }
        // skip ranges already behind the cursor
        if !range.upper.is_empty() && range.upper.as_str() <= ctx.cursor.as_str() {
            continue;
        }
        // Python `_cleave` stops at a range not in CREATED/CLEAVED/ACTIVE.
        // FOUND is included here because local `cleave()` tests drive the
        // copy step without `_create_shard_containers`; the daemon converts
        // FOUND → CREATED before calling `cleave`.
        if range.state != shard_state::FOUND
            && range.state != shard_state::CREATED
            && range.state != shard_state::CLEAVED
            && range.state != shard_state::ACTIVE
        {
            break;
        }
        // A stale, full-namespace ACTIVE acceptor may remain beside a
        // SHARDING epoch after shrink completion.  With no usable context,
        // replaying the retiring DB would resurrect reclaimed rows.  Do not
        // generalize this guard to bounded ACTIVE ranges: Python cleaves those
        // during replication-to-sharded recovery, using context and incoming
        // sync points to avoid duplicate rows.
        if range.state == shard_state::ACTIVE
            && range.lower.is_empty()
            && range.upper.is_empty()
            && !own_shrinking
        {
            ctx.cursor = range.upper.clone();
            ctx.ranges_done += 1;
            if ctx.ranges_todo > 0 {
                ctx.ranges_todo -= 1;
            }
            ctx.cleaving_done = true;
            continue;
        }
        let mut shard = shard_for(range);
        let had_objects = cleave_shard_range(
            &mut retiring,
            &mut shard,
            source,
            range,
            ctx.last_cleave_to_row,
            own_shrinking,
        )?;
        ctx.cursor = range.upper.clone();
        ctx.ranges_done += 1;
        // Python `range_done`: todo shrinks as each range is cleaved.
        if ctx.ranges_todo > 0 {
            ctx.ranges_todo -= 1;
        }
        // Python CLEAVE_EMPTY does not consume cleave_batch_size.
        if had_objects {
            done_this_batch += 1;
        }
        if namespace_upper_covers(&range.upper, &own_upper) {
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
/// Percent-encode one URL path segment (UTF-8 bytes). Slash is encoded so
/// container names stay a single segment.
fn http_path_seg(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            b => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Python `urllib.parse.quote` with default `safe='/'` (UTF-8 bytes).
/// Used for `X-Container-Sysmeta-Shard-Quoted-Root` (HTTP headers are ASCII).
fn http_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' => {
                out.push(b as char)
            }
            b => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn shard_ranges_json(ranges: &[ShardRange]) -> Vec<u8> {
    let arr: Vec<serde_json::Value> = ranges
        .iter()
        .map(|r| {
            let mut j = r.to_json();
            if let Some(obj) = j.as_object_mut() {
                obj.insert("reported".into(), serde_json::json!(0));
            }
            j
        })
        .collect();
    serde_json::to_vec(&arr).unwrap_or_else(|_| b"[]".to_vec())
}

/// G6 SAIO: device `sdb2` for `127.0.0.2` lives under `/srv/2/node`, not
/// under the local sharder’s `/srv/1/node`.
fn peer_devices_root(local_device: &Path, peer_ip: &str) -> std::path::PathBuf {
    // G6 SAIO layout: `/srv/<n>/node/<device>`. `parent()` of the device is
    // `/srv/<n>/node`, so the loopback octet maps at `/srv/<octet>/node`.
    let node_dir = local_device.parent();
    let is_node = node_dir
        .and_then(|p| p.file_name())
        .is_some_and(|n| n == "node");
    if is_node {
        if let (Some(n_dir), Some(octet)) = (
            node_dir.and_then(|p| p.parent()),
            peer_ip.strip_prefix("127.0.0."),
        ) {
            if !octet.is_empty() && octet.bytes().all(|c| c.is_ascii_digit()) {
                if let Some(srv) = n_dir.parent() {
                    return srv.join(octet).join("node");
                }
            }
        }
    }
    node_dir.unwrap_or(local_device).to_path_buf()
}

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
/// Looks for any `<hash>[_<epoch>].db` in the hash dir (Python opens the
/// freshest file); unsuffixed-only used to miss a SHARDED acceptor.
fn open_existing_shard_broker(
    device: &Path,
    hash_config: &HashPathConfig,
    part: &str,
    shard_name: &str,
) -> Option<ContainerBroker> {
    let (db, account, container) = shard_db_path(device, hash_config, part, shard_name);
    if get_db_files(&db).is_empty() {
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
            if !get_db_files(&db).is_empty() {
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
    open_or_create_shard_broker(device, hash_config, part, shard_name, None)
}

/// Python `_get_shard_broker` / `ContainerBroker.create_broker(..., epoch=)`.
fn local_shard_broker_for_range(
    device: &Path,
    hash_config: &HashPathConfig,
    part: &str,
    sr: &ShardRange,
) -> ContainerBroker {
    open_or_create_shard_broker(device, hash_config, part, &sr.name, sr.epoch.as_deref())
}

/// Open the existing hash-dir DB, or create one. Never initialize an
/// unsuffixed `<hash>.db` beside an existing epoch file: that makes
/// `get_db_state()==SHARDING` with empty retiring (probe L2088 count 0).
fn open_or_create_shard_broker(
    device: &Path,
    hash_config: &HashPathConfig,
    part: &str,
    shard_name: &str,
    epoch: Option<&str>,
) -> ContainerBroker {
    let (unsuffixed, account, container) = shard_db_path(device, hash_config, part, shard_name);
    let existing = get_db_files(&unsuffixed);
    // Open an existing epoch file when the range has that epoch (shrink-to-root
    // acceptor = SHARDED root). Do not create a *new* epoch-suffixed DB for a
    // handoff of an unsuffixed shard — that split listing-w204 L1992 51≠50.
    let db = if let Some(e) = epoch.filter(|s| !s.is_empty()) {
        let named = make_db_file_path(&unsuffixed, Some(e)).unwrap_or_else(|_| unsuffixed.clone());
        if named.exists() {
            named
        } else if let Some(freshest) = existing.last() {
            freshest.clone()
        } else {
            unsuffixed.clone()
        }
    } else if let Some(freshest) = existing.last() {
        freshest.clone()
    } else {
        unsuffixed.clone()
    };
    let _ = std::fs::create_dir_all(db.parent().unwrap_or(device));
    let mut b = ContainerBroker::new(&db, &account, &container);
    if existing.is_empty() && !db.exists() {
        let ts = swift_core::timestamp::Timestamp::now().internal();
        let id = format!("{ts}-{}", std::process::id());
        let _ = b.initialize(&ts, 0, &ts, &id);
    }
    b
}

/// Python `_get_shard_broker`: stamp Quoted-Root so later sharder passes
/// treat this DB as a shard and `_update_root_container`.
fn ensure_shard_root_sysmeta(
    broker: &mut ContainerBroker,
    root_account: &str,
    root_container: &str,
    own: &ShardRange,
) {
    let ts = swift_core::timestamp::Timestamp::now().internal();
    // The header name is deliberately *Quoted*-Root.  Python stores
    // `urllib.parse.quote(root_path)` here so the metadata value remains
    // ASCII-safe when it is later copied back into an HTTP response header.
    // Storing the raw UTF-8 path causes the HTTP/1 parser to reinterpret its
    // bytes as Latin-1 (probe MoreUTF8 test_shrinking).
    let root_path = http_quote(&format!("{root_account}/{root_container}"));
    let _ = broker.update_metadata(&vec![
        (
            "X-Container-Sysmeta-Shard-Quoted-Root".to_string(),
            (root_path, ts.clone()),
        ),
        (
            "X-Container-Sysmeta-Sharding".to_string(),
            ("True".to_string(), ts),
        ),
    ]);
    let _ = broker.merge_shard_ranges(vec![own.clone()]);
}

fn root_account_container(broker: &mut ContainerBroker) -> Option<(String, String)> {
    if broker.is_root_container().ok()? {
        return None;
    }
    let md = broker.metadata().ok()?;
    let get = |k: &str| {
        md.iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(k))
            .map(|(_, (v, _))| v.clone())
            .filter(|v| !v.is_empty())
    };
    let path = get("X-Container-Sysmeta-Shard-Quoted-Root")
        .map(|p| swift_http::unquote(&p))
        .or_else(|| get("X-Container-Sysmeta-Shard-Root"))?;
    let path = path.trim_start_matches('/');
    let (acct, cont) = path.split_once('/')?;
    if acct.is_empty() || cont.is_empty() {
        return None;
    }
    Some((acct.to_string(), cont.to_string()))
}

/// Python `broker.root_account` / `root_container`. Nested children must
/// stamp *this* on Quoted-Root so `_update_root_container` updates the
/// listing HEAD (probe L1435), not the immediate parent shard.
fn true_root_account_container(
    broker: &mut ContainerBroker,
    fallback_account: &str,
    fallback_container: &str,
) -> (String, String) {
    root_account_container(broker)
        .unwrap_or_else(|| (fallback_account.to_string(), fallback_container.to_string()))
}

/// Python `update_own_shard_range_stats` + persist when counts change.
pub fn refresh_own_shard_range_stats(
    broker: &mut ContainerBroker,
) -> Result<Option<ShardRange>, DbError> {
    let Some(mut own) = broker.get_own_shard_range(true)? else {
        return Ok(None);
    };
    let info = broker.get_info()?;
    let get = |k: &str| {
        info.iter()
            .find(|(n, _)| n == k)
            .and_then(|(_, v)| v.as_i64())
            .unwrap_or(0)
    };
    let oc = get("object_count");
    let bu = get("bytes_used");
    let tombs = broker.tombstone_count().unwrap_or(-1);
    // Python `ShardRange.update_meta`: leave `reported` set when live stats
    // match. Lagging replicas that still have the pre-PUT count must not
    // re-send 50 with a newer meta_timestamp and stomp 150 on the root
    // (probe L1157 HEAD 200!=100).
    if own.object_count == oc && own.bytes_used == bu && own.tombstones.max(0) == tombs.max(0) {
        return Ok(Some(own));
    }
    let ts = swift_core::timestamp::Timestamp::now().internal();
    own.update_meta(oc, bu, &ts);
    if tombs >= 0 {
        own.tombstones = tombs;
        own.reported = 0;
    }
    broker.merge_shard_ranges(vec![own.clone()])?;
    Ok(Some(own))
}

fn put_shard_ranges_body(
    node: &ShardReplicaNode,
    part: &str,
    account: &str,
    container: &str,
    timestamp: &str,
    body: &[u8],
    extra_headers: &[(&str, &str)],
) -> Result<u16, String> {
    use std::io::{Read, Write};
    use std::net::{TcpStream, ToSocketAddrs};
    let path = format!(
        "/{}/{}/{}/{}",
        http_path_seg(&node.device),
        http_path_seg(part),
        http_path_seg(account),
        http_path_seg(container)
    );
    let hostport = format!("{}:{}", node.ip, node.port);
    let addr = hostport
        .to_socket_addrs()
        .map_err(|e| e.to_string())?
        .next()
        .ok_or_else(|| format!("cannot resolve {hostport}"))?;
    let mut stream = TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(5))
        .map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .ok();
    stream
        .set_write_timeout(Some(std::time::Duration::from_secs(5)))
        .ok();
    let mut extra = String::new();
    for (k, v) in extra_headers {
        extra.push_str(k);
        extra.push_str(": ");
        extra.push_str(v);
        extra.push_str("\r\n");
    }
    let req = format!(
        "PUT {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\
         X-Timestamp: {timestamp}\r\nX-Backend-Record-Type: shard\r\n\
         X-Backend-Allow-Reserved-Names: true\r\n{extra}\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        node.ip,
        body.len()
    );
    stream
        .write_all(req.as_bytes())
        .map_err(|e| e.to_string())?;
    stream.write_all(body).map_err(|e| e.to_string())?;
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

/// HTTP UPDATE (merge_items) cleaved object rows onto each shard primary.
/// Only the rows already in the local cleaved shard — not the whole retiring
/// namespace, which would populate leftover CREATED shards too early (L1509).
fn update_objects_on_primaries(
    ring: &swift_ring::Ring,
    shard_name: &str,
    records: &[ObjectRecord],
) -> Result<(), String> {
    if records.is_empty() {
        return Ok(());
    }
    let (part, nodes) =
        primary_shard_replica_nodes(shard_name, |a, c| ring_get_nodes_for_shard(ring, a, c))?;
    let (account, container) = split_shard_name(shard_name);
    let part = part.to_string();
    let ts = swift_core::timestamp::Timestamp::now().internal();
    let body = object_records_update_json(records);
    let dest_is_shard = account.starts_with(".shards_");
    let extra = if dest_is_shard {
        [
            ("X-Backend-Allow-Reserved-Names", "true"),
            ("X-Backend-Auto-Create", "True"),
        ]
    } else {
        [
            ("X-Backend-Allow-Reserved-Names", "true"),
            ("X-Backend-Auto-Create", "False"),
        ]
    };
    let mut ok = 0usize;
    for node in &nodes {
        match update_objects_body(node, &part, &account, &container, &ts, &body, &extra) {
            Ok(status) if (200..300).contains(&status) || status == 202 => ok += 1,
            _ => {}
        }
    }
    if ok == 0 {
        Err(format!(
            "UPDATE objects onto {} primaries failed (0/{})",
            shard_name,
            nodes.len()
        ))
    } else {
        Ok(())
    }
}

fn object_records_update_json(records: &[ObjectRecord]) -> Vec<u8> {
    let arr: Vec<serde_json::Value> = records
        .iter()
        .map(|r| {
            serde_json::json!({
                "name": r.name,
                "created_at": r.created_at,
                "size": r.size,
                "content_type": r.content_type,
                "etag": r.etag,
                "deleted": r.deleted,
                "storage_policy_index": r.storage_policy_index,
                "ctype_timestamp": r.ctype_timestamp,
                "meta_timestamp": r.meta_timestamp,
            })
        })
        .collect();
    serde_json::to_vec(&arr).unwrap_or_else(|_| b"[]".to_vec())
}

fn update_objects_body(
    node: &ShardReplicaNode,
    part: &str,
    account: &str,
    container: &str,
    timestamp: &str,
    body: &[u8],
    extra_headers: &[(&str, &str)],
) -> Result<u16, String> {
    use std::io::{Read, Write};
    use std::net::{TcpStream, ToSocketAddrs};
    let path = format!(
        "/{}/{}/{}/{}",
        http_path_seg(&node.device),
        http_path_seg(part),
        http_path_seg(account),
        http_path_seg(container)
    );
    let hostport = format!("{}:{}", node.ip, node.port);
    let addr = hostport
        .to_socket_addrs()
        .map_err(|e| e.to_string())?
        .next()
        .ok_or_else(|| format!("cannot resolve {hostport}"))?;
    let mut stream = TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(5))
        .map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .ok();
    stream
        .set_write_timeout(Some(std::time::Duration::from_secs(5)))
        .ok();
    let mut extra = String::new();
    for (k, v) in extra_headers {
        extra.push_str(k);
        extra.push_str(": ");
        extra.push_str(v);
        extra.push_str("\r\n");
    }
    let req = format!(
        "UPDATE {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\
         X-Timestamp: {timestamp}\r\n\
         X-Backend-Allow-Reserved-Names: true\r\n{extra}\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        node.ip,
        body.len()
    );
    stream
        .write_all(req.as_bytes())
        .map_err(|e| e.to_string())?;
    stream.write_all(body).map_err(|e| e.to_string())?;
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

/// Python `_send_shard_ranges` to `account/container` ring primaries.
fn push_shard_ranges_to_ring(
    ring: &swift_ring::Ring,
    account: &str,
    container: &str,
    ranges: &[ShardRange],
) -> bool {
    let Ok((part, nodes)) = ring.get_nodes(account, Some(container), None) else {
        return false;
    };
    let ts = swift_core::timestamp::Timestamp::now().internal();
    let body = shard_ranges_json(ranges);
    let need = default_shard_quorum(nodes.len());
    let part = part.to_string();
    let mut ok = 0usize;
    for n in &nodes {
        let node = ShardReplicaNode {
            ip: n.dev.ip.clone(),
            port: n.dev.port as u16,
            device: n.dev.device.clone(),
        };
        match put_shard_ranges_body(&node, &part, account, container, &ts, &body, &[]) {
            Ok(status) if (200..300).contains(&status) || status == 202 => ok += 1,
            _ => {}
        }
    }
    ok >= need
}

/// Direct GET of shard-range JSON from one container-server replica.
fn get_shard_ranges_body(
    node: &ShardReplicaNode,
    part: &str,
    account: &str,
    container: &str,
    query: &str,
) -> Result<(u16, Vec<u8>), String> {
    use std::io::{Read, Write};
    use std::net::{TcpStream, ToSocketAddrs};
    let path = format!(
        "/{}/{}/{}/{}",
        http_path_seg(&node.device),
        http_path_seg(part),
        http_path_seg(account),
        http_path_seg(container)
    );
    let uri = if query.is_empty() {
        path
    } else {
        format!("{path}?{query}")
    };
    let hostport = format!("{}:{}", node.ip, node.port);
    let addr = hostport
        .to_socket_addrs()
        .map_err(|e| e.to_string())?
        .next()
        .ok_or_else(|| format!("cannot resolve {hostport}"))?;
    let mut stream = TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(5))
        .map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .ok();
    stream
        .set_write_timeout(Some(std::time::Duration::from_secs(5)))
        .ok();
    let req = format!(
        "GET {uri} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\
         X-Backend-Record-Type: shard\r\nX-Backend-Record-Shard-Format: full\r\n\
         X-Backend-Override-Deleted: true\r\nX-Backend-Include-Deleted: true\r\n\
         X-Backend-Allow-Reserved-Names: true\r\n\r\n",
        node.ip
    );
    stream
        .write_all(req.as_bytes())
        .map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).map_err(|e| e.to_string())?;
    let status = buf
        .split(|&b| b == b'\n')
        .next()
        .and_then(|l| std::str::from_utf8(l).ok())
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = match buf.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(i) => buf[i + 4..].to_vec(),
        None => Vec::new(),
    };
    Ok((status, body))
}

fn parse_shard_ranges_json(body: &[u8]) -> Vec<ShardRange> {
    match serde_json::from_slice::<serde_json::Value>(body) {
        Ok(serde_json::Value::Array(arr)) => arr.iter().filter_map(ShardRange::from_json).collect(),
        _ => Vec::new(),
    }
}

/// Python `_fetch_shard_ranges`: GET every root primary and keep all
/// parsed ranges (newest-wins happens in `merge_shards`).
fn fetch_shard_ranges_from_root(
    ring: &swift_ring::Ring,
    root_acct: &str,
    root_cont: &str,
    marker: &str,
    end_marker: &str,
) -> Vec<ShardRange> {
    fetch_shard_ranges_from_root_states(
        ring, root_acct, root_cont, marker, end_marker, "auditing",
    )
}

fn fetch_shard_ranges_from_root_states(
    ring: &swift_ring::Ring,
    root_acct: &str,
    root_cont: &str,
    marker: &str,
    end_marker: &str,
    states: &str,
) -> Vec<ShardRange> {
    let Ok((part, nodes)) = ring.get_nodes(root_acct, Some(root_cont), None) else {
        return Vec::new();
    };
    let mut q = format!("format=json&states={states}");
    if !marker.is_empty() {
        q.push_str("&marker=");
        q.push_str(&http_path_seg(marker));
    }
    if !end_marker.is_empty() {
        q.push_str("&end_marker=");
        q.push_str(&http_path_seg(end_marker));
    }
    let part = part.to_string();
    let mut out = Vec::new();
    for n in &nodes {
        let node = ShardReplicaNode {
            ip: n.dev.ip.clone(),
            port: n.dev.port as u16,
            device: n.dev.device.clone(),
        };
        match get_shard_ranges_body(&node, &part, root_acct, root_cont, &q) {
            Ok((status, body)) if (200..300).contains(&status) => {
                out.extend(parse_shard_ranges_json(&body));
            }
            _ => {}
        }
    }
    out
}

/// Python `_merge_shard_ranges_from_root` (probe L1245): own range by name
/// plus namespace children. Newest-wins is `merge_shard_ranges`.
fn merge_shard_ranges_from_root(
    broker: &mut ContainerBroker,
    fetched: &[ShardRange],
    own: &ShardRange,
) {
    let mut own_from_root = None;
    let mut children = Vec::new();
    for sr in fetched {
        if sr.name == own.name {
            own_from_root = Some(sr.clone());
        } else if own.includes_range(sr) {
            children.push(sr.clone());
        } else if (own.state == shard_state::SHRINKING || own.state == shard_state::SHRUNK)
            && sr.includes_range(own)
        {
            // Shrinking acceptor is an expanded neighbor, not a child.
            children.push(sr.clone());
        }
    }
    if let Some(from_root) = own_from_root {
        let _ = broker.merge_shard_ranges(vec![from_root]);
    }
    let sharded = matches!(broker.get_db_state(), Ok(DbState::Sharded));
    // SHARDED+SHRUNK donors still need the covering acceptor so the
    // live misplaced pass can find a destination (probe L2761).
    if !children.is_empty() {
        let shrinking_own =
            own.state == shard_state::SHRINKING || own.state == shard_state::SHRUNK;
        if !sharded || shrinking_own {
            let _ = broker.merge_shard_ranges(children);
        }
    }
}

/// Python `_do_audit_shard_container`: pull the root's view of this shard
/// (own state + sub-shards) so a replica that missed the SHARDING PUT
/// still `set_sharding_state`.
fn audit_shard_from_root(broker: &mut ContainerBroker, ring: Option<&swift_ring::Ring>) {
    let Some((root_acct, root_cont)) = root_account_container(broker) else {
        return;
    };
    let Some(own) = broker.get_own_shard_range(true).ok().flatten() else {
        return;
    };
    let Some(ring) = ring else {
        return;
    };
    let fetched =
        fetch_shard_ranges_from_root(ring, &root_acct, &root_cont, &own.lower, &own.upper);
    if fetched.is_empty() {
        return;
    }
    merge_shard_ranges_from_root(broker, &fetched, &own);
}

/// Python `_update_root_container`: push this shard's own range stats to root.
pub fn update_root_container(
    broker: &mut ContainerBroker,
    ring: Option<&swift_ring::Ring>,
) -> Result<bool, DbError> {
    let Some((root_acct, root_cont)) = root_account_container(broker) else {
        return Ok(false);
    };
    let Some(own) = refresh_own_shard_range_stats(broker)? else {
        return Ok(false);
    };
    // Python `_update_root_container`: if the latch is set, do not send.
    if own.reported != 0 {
        return Ok(true);
    }
    let Some(ring) = ring else {
        return Ok(true);
    };
    let Ok((part, nodes)) = ring.get_nodes(&root_acct, Some(&root_cont), None) else {
        return Ok(false);
    };
    let ts = swift_core::timestamp::Timestamp::now().internal();
    // Python `_send_shard_ranges`: include own + others, `reported=0`.
    let mut ranges = broker
        .get_shard_ranges(&GetShardRangesArgs {
            include_own: true,
            include_deleted: true,
            ..GetShardRangesArgs::default()
        })
        .unwrap_or_else(|_| vec![own.clone()]);
    if ranges.is_empty() {
        ranges.push(own.clone());
    }
    for r in &mut ranges {
        r.reported = 0;
        if r.name == own.name {
            r.object_count = own.object_count;
            r.bytes_used = own.bytes_used;
            r.meta_timestamp = own.meta_timestamp.clone();
        }
    }
    let referer = http_quote(&broker.path());
    eprintln!(
        "G6_UPDATE_ROOT shard={} root={}/{} n={} states={:?} deleted={:?} oc={:?} names={:?}",
        broker.path(),
        root_acct,
        root_cont,
        ranges.len(),
        ranges.iter().map(|r| r.state).collect::<Vec<_>>(),
        ranges.iter().map(|r| r.deleted).collect::<Vec<_>>(),
        ranges.iter().map(|r| r.object_count).collect::<Vec<_>>(),
        ranges.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(),
    );
    let body = shard_ranges_json(&ranges);
    let need = default_shard_quorum(nodes.len());
    let mut ok = 0usize;
    let extra = [("Referer", referer.as_str())];
    for n in &nodes {
        let node = ShardReplicaNode {
            ip: n.dev.ip.clone(),
            port: n.dev.port as u16,
            device: n.dev.device.clone(),
        };
        match put_shard_ranges_body(
            &node,
            &part.to_string(),
            &root_acct,
            &root_cont,
            &ts,
            &body,
            &extra,
        ) {
            Ok(status) if (200..300).contains(&status) || status == 202 => ok += 1,
            _ => {}
        }
    }
    let sent = ok >= need;
    if sent {
        // Python: mark own.reported so the next cycle does not re-send.
        let mut done = own.clone();
        done.reported = 1;
        let _ = broker.merge_shard_ranges(vec![done]);
    }
    Ok(sent)
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
    // Python `_create_shard_containers` uses `broker.root_path`, not the
    // container being cleaved. A nested first-gen parent would otherwise
    // stamp Quoted-Root as itself; L1435 HEAD then stays at the pre-delete
    // shard-range object_count (listing-w116 leftover 150).
    let (root_acct, root_cont) = true_root_account_container(broker, &account, &container);
    let mut ranges = broker.get_shard_ranges(&GetShardRangesArgs {
        include_own: false,
        ..GetShardRangesArgs::default()
    })?;
    // Nested shard: only cleave namespace children. An audit-merged sibling
    // with upper=MAX would otherwise satisfy `upper >= own.upper` and
    // complete_sharding in one batch=2 pass (probe L1204/L1228).
    //
    // Shrinking is the opposite geometry: the acceptor was expanded to
    // *cover* this donor (`acceptor.includes(own)`), so `own.includes(acceptor)`
    // is false. Probe L2001 `G6_CLEAVE skip-empty` while UPDATE_ROOT already
    // listed the expanded acceptor on the donor.
    if let Some(own) = broker.get_own_shard_range(true).ok().flatten() {
        if own.state == shard_state::SHRINKING || own.state == shard_state::SHRUNK {
            ranges.retain(|r| r.includes_range(&own) || own.includes_range(r));
        } else if !own.lower.is_empty() || !own.upper.is_empty() {
            ranges.retain(|r| own.includes_range(r));
        }
    }
    if ranges.is_empty() {
        eprintln!(
            "G6_CLEAVE skip-empty account={account} container={container} own={:?}",
            broker
                .get_own_shard_range(true)
                .ok()
                .flatten()
                .map(|o| (o.lower, o.upper, o.state))
        );
        return Ok(ProcessShardingOutcome::default());
    }
    // Prefer persisted context; fall back to CLEAVED-range scan.
    let mut ctx = load_cleaving_context(broker)?;
    if ctx.ref_id.is_empty() {
        ctx.ref_id = broker_cleaving_ref(broker);
    }
    // Python `_complete_sharding` else: if cleaving_done but `done()` is
    // false (`max_row != cleave_to_row`, typically a peer's finished
    // context), reset and cleave remaining retiring rows (L1517).
    if ctx.cleaving_done && !ctx.done() {
        ctx.cursor.clear();
        ctx.ranges_done = 0;
        ctx.ranges_todo = 0;
        ctx.cleaving_done = false;
        ctx.misplaced_done = false;
        ctx.last_cleave_to_row = Some(ctx.cleave_to_row);
    }
    // Python `CleavingContext.start()`: snapshot retiring max_row so
    // `done()` (`max_row == cleave_to_row`) holds when no new rows arrived.
    if ctx.cursor.is_empty() && !ctx.cleaving_done {
        let max_row = broker_max_row_retiring(broker);
        ctx.max_row = max_row;
        ctx.cleave_to_row = max_row;
        // Python `CleavingContext.start()`: cursor = own.lower, then
        // `_cleave` still visits already-CLEAVED ranges and counts
        // CLEAVE_SUCCESS against `cleave_batch_size`. Inferring the cursor
        // from CLEAVED uppers skips those and lets a second replica finish
        // the leftover CREATED range in the same once() (probe L1204).
        if let Some(own) = broker.get_own_shard_range(true).ok().flatten() {
            ctx.cursor = own.lower;
        }
    }
    // Python `_create_shard_containers`: FOUND → PUT shard container →
    // CREATED, merge, then `_replicate_object` *before* cleave. Probe
    // `_test_sharded_listing` expects non-leader replicas at CREATED (20).
    let mut replicate_errors = 0u64;
    let ts_created = swift_core::timestamp::Timestamp::now().internal();
    let local_device = device
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_string();
    let devices_root = device.parent().map(|p| p.to_path_buf());
    let mut created = Vec::new();
    for sr in &mut ranges {
        if sr.state != shard_state::FOUND {
            continue;
        }
        let spart = shard_part_for(&sr.name, ring, part);
        // Python updates CREATED before `_send_shard_ranges` so the PUT body
        // carries state=20 (probe other-replicas `[CREATED, CREATED]`).
        let _ = sr.update_state(shard_state::CREATED, Some(&ts_created));
        let created_ok = if let Some(ring) = ring {
            create_shard_on_primaries(ring, sr, &root_acct, &root_cont)
        } else {
            replicator.replicate_shard(&sr.name, &spart)
        };
        if created_ok.is_err() {
            replicate_errors += 1;
            break;
        }
        created.push(sr.clone());
    }
    if !created.is_empty() {
        broker.merge_shard_ranges(created.clone())?;
        // HTTP PUT CREATED ranges onto other root primaries. Python
        // `_replicate_object` of the root; rsync of the DB can miss UTF-8
        // names, leaving replica shard_ranges `[]` (probe L1072).
        if let Some(ring) = ring {
            let _ = push_shard_ranges_to_ring(ring, &account, &container, &created);
        }
        replicate_errors += replicate_broker_to_ring_peers(
            broker,
            hash_config,
            ring,
            &local_device,
            devices_root.as_deref(),
            false,
        );
        // Python `_create_shard_containers` Auto-Creates the shard DB on
        // every primary. A down primary misses the PUT; `replicators.once()`
        // later copies from a node that has the file. We only used to
        // materialize DBs during cleave, so the leftover CREATED range had
        // no file for replicators to push (probe L1290 FileNotFoundError).
        for sr in &created {
            let spart = shard_part_for(&sr.name, ring, part);
            let mut shard = local_shard_broker_for_range(device, hash_config, &spart, sr);
            ensure_shard_root_sysmeta(&mut shard, &root_acct, &root_cont, sr);
            let _ = shard.merge_shard_ranges(vec![sr.clone()]);
            replicate_errors += replicate_broker_to_ring_peers(
                &mut shard,
                hash_config,
                ring,
                &local_device,
                devices_root.as_deref(),
                true,
            );
        }
    }
    // Python `_cleave`: misplaced pass first, then range cleave. Root
    // containers covering MIN–MAX have empty misplaced bounds; the Python
    // helper still returns True, so probe `done()` requires this flag.
    if !ctx.misplaced_done {
        let _ = move_misplaced_from_retiring_with_ring(
            broker,
            device,
            hash_config,
            part,
            &ranges,
            ring,
        );
        ctx.misplaced_done = true;
    }
    // Python `_cleave`: `if cleaving_context.cleaving_done: return`.
    // Probe L2044: a leftover empty epoch keeps db_state=SHARDING, so the
    // next `sharders.once()` re-entered cleave and copied retiring live
    // rows (obj-1-000…, never tombstoned on the root) onto the ACTIVE
    // expanded acceptor. Python uses retiring-id context + sync_point;
    // we skip the object copy and finish `set_sharded_state` (unlink).
    if ctx.cleaving_done {
        eprintln!(
            "G6_CLEAVE already-done account={account} container={container} misplaced={}",
            ctx.misplaced_done
        );
        let finished = if ctx.misplaced_done {
            complete_sharding(broker)?
        } else {
            false
        };
        return Ok(ProcessShardingOutcome {
            finished,
            replicate_errors: 0,
        });
    }
    let mut shard_for = |sr: &ShardRange| {
        let spart = shard_part_for(&sr.name, ring, part);
        let mut b = local_shard_broker_for_range(device, hash_config, &spart, sr);
        ensure_shard_root_sysmeta(&mut b, &root_acct, &root_cont, sr);
        b
    };
    cleave(
        broker,
        &mut ranges,
        &mut shard_for,
        &mut ctx,
        cleave_batch_size,
    )?;
    // Python `_cleave_shard_broker` `_replicate_object`: push the cleaved
    // shard DB onto that shard's ring primaries. Also push leftover CREATED
    // DBs so `replicators.once()` can fill a primary that missed Auto-Create.
    let own_shrinking = broker
        .get_own_shard_range(true)
        .ok()
        .flatten()
        .is_some_and(|o| o.state == shard_state::SHRINKING || o.state == shard_state::SHRUNK);
    for sr in ranges.iter().filter(|r| r.state >= shard_state::CREATED) {
        // listing-w207: HTTP UPDATE of a leftover local ACTIVE MIN–MAX
        // DB resurrected obj-1-000 after client DELETEs. First-gen UPDATE
        // is CLEAVED (not ACTIVE) so this does not skip it. listing-w219:
        // skipping the whole loop also skipped `replicate_broker` of the
        // expanded acceptor → HEAD 1 instead of 51 (L1992). Only skip the
        // object-row UPDATE; still rsync the shard DB.
        let skip_leftover_object_update = ctx.cleaving_done
            && !own_shrinking
            && sr.state == shard_state::ACTIVE
            && sr.lower.is_empty()
            && sr.upper.is_empty();
        let spart = shard_part_for(&sr.name, ring, part);
        let mut shard = local_shard_broker_for_range(device, hash_config, &spart, sr);
        // Python `_cleave_shard_broker` `_replicate_object` only after that
        // range is cleaved. Pushing retiring rows onto leftover CREATED
        // shards during node-0/1's first batch populates them too early
        // (listing-w155 L1509 expected 101, got 200). UPDATE only the
        // objects already merged into a CLEAVED/ACTIVE local shard.
        if let Some(ring) = ring {
            if sr.state >= shard_state::CLEAVED && !skip_leftover_object_update {
                if let Ok(records) = shard.object_records_in_range(&sr.lower, &sr.upper) {
                    if !records.is_empty() {
                        match update_objects_on_primaries(ring, &sr.name, &records) {
                            Ok(()) => eprintln!(
                                "G6_UPDATE_OBJECTS shard={} n={} state={} ok",
                                sr.name,
                                records.len(),
                                sr.state
                            ),
                            Err(e) => eprintln!(
                                "G6_UPDATE_OBJECTS shard={} n={} state={} err={}",
                                sr.name,
                                records.len(),
                                sr.state,
                                e
                            ),
                        }
                    }
                }
            }
        }
        replicate_errors += replicate_broker_to_ring_peers(
            &mut shard,
            hash_config,
            ring,
            &local_device,
            devices_root.as_deref(),
            true,
        );
    }
    // Python `_cleave` returns `misplaced_done and cleaving_done`. The
    // `all >= CLEAVED` shortcut is wrong for a nested shard: a batch of
    // two sub-ranges can all be CLEAVED while `own.upper` is still ahead,
    // and `_complete_sharding` must not unlink the retiring DB.
    let finished_cleave = ctx.cleaving_done;
    {
        let own = broker.get_own_shard_range(true).ok().flatten();
        eprintln!(
            "G6_CLEAVE account={account} container={container} own_bounds={:?} n={} states={:?} uppers={:?} cursor={:?} done={} todo={} cleaving_done={} finished_cleave={} batch={}",
            own.as_ref().map(|o| (o.lower.as_str(), o.upper.as_str(), o.state)),
            ranges.len(),
            ranges.iter().map(|r| r.state).collect::<Vec<_>>(),
            ranges.iter().map(|r| r.upper.as_str()).collect::<Vec<_>>(),
            ctx.cursor,
            ctx.ranges_done,
            ctx.ranges_todo,
            ctx.cleaving_done,
            finished_cleave,
            cleave_batch_size,
        );
    }
    if finished_cleave {
        ctx.misplaced_done = true;
        // `load_all` uses the *stored* max_row (unlike `load()`, which
        // refreshes from the retiring DB). Keep them equal so `done()` is True.
        ctx.max_row = ctx.cleave_to_row;
    }
    let ts = swift_core::timestamp::Timestamp::now().internal();
    // Nested donor only (probe L1356). First-gen root complete must keep
    // a single save_cleaving_context — listing-w41/w42 L1157 `200!=100`.
    let nested_done = finished_cleave && !broker.is_root_container().unwrap_or(true);
    if nested_done {
        mark_all_cleaving_contexts_done(broker, &ctx, &ts)?;
    } else {
        save_cleaving_context(broker, &ctx, &ts)?;
    }
    let finished = if finished_cleave {
        complete_sharding(broker)?
    } else {
        false
    };
    // Python `_complete_sharding` promotes CLEAVED→ACTIVE on the root, then
    // shard DBs must have ACTIVE own ranges so a later SHARDING send that
    // misses a down replica leaves ACTIVE (probe L1183 `[60,60,40]`).
    if finished {
        if let Some(ring) = ring {
            if let Ok(actives) = broker.get_shard_ranges(&GetShardRangesArgs {
                include_own: false,
                states: Some(vec![shard_state::ACTIVE]),
                ..GetShardRangesArgs::default()
            }) {
                for sr in &actives {
                    let (acct, cont) = split_shard_name(&sr.name);
                    if !acct.is_empty() && !cont.is_empty() {
                        let _ =
                            push_shard_ranges_to_ring(ring, &acct, &cont, std::slice::from_ref(sr));
                    }
                }
            }
        }
    }
    Ok(ProcessShardingOutcome {
        finished,
        replicate_errors,
    })
}

/// Python `is_shrinking_candidate`: row_count (objects + tombstones) is below
/// `shrink_threshold` and not above `expansion_limit`.
pub fn is_shrinking_candidate(
    shard_range: &ShardRange,
    shrink_threshold: i64,
    expansion_limit: i64,
    states: &[i64],
) -> bool {
    states.contains(&shard_range.state)
        && shard_range.row_count() < shrink_threshold
        && shard_range.row_count() <= expansion_limit
}

/// `sequence.upper < next.lower` with empty upper = MAX, empty lower = MIN.
fn namespace_upper_lt_lower(upper: &str, lower: &str) -> bool {
    if upper.is_empty() || lower.is_empty() {
        return false;
    }
    upper < lower
}

/// Python `ShardRangeList.includes`: sequence bounds enclose `other`.
fn sequence_includes(sequence: &[ShardRange], other: &ShardRange) -> bool {
    if sequence.is_empty() {
        return false;
    }
    let lo = &sequence[0].lower;
    let hi = &sequence[sequence.len() - 1].upper;
    ShardRange::lower_cmp(lo, &other.lower) != std::cmp::Ordering::Greater
        && ShardRange::upper_cmp(hi, &other.upper) != std::cmp::Ordering::Less
}

fn sequence_row_count(sequence: &[ShardRange]) -> i64 {
    sequence.iter().map(|r| r.row_count()).sum()
}

fn sequence_complete(
    sequence: &[ShardRange],
    shrink_threshold: i64,
    expansion_limit: i64,
    max_shrinking: i64,
) -> bool {
    if sequence.is_empty() {
        return false;
    }
    let last = sequence.last().unwrap();
    let shrinking_states = [shard_state::ACTIVE, shard_state::SHRINKING];
    !is_shrinking_candidate(last, shrink_threshold, expansion_limit, &shrinking_states)
        || (max_shrinking > 0 && (max_shrinking as usize) < sequence.len())
        || sequence_row_count(sequence) >= expansion_limit
}

/// Python `find_compactible_shard_sequences`.
///
/// Neighbouring ACTIVE/SHRINKING ranges whose combined row_count fits under
/// `expansion_limit` and whose donors are below `shrink_threshold`. The last
/// range in each sequence is the acceptor. `max_shrinking` is donors-per-
/// acceptor (Python default 1); `max_expanding` caps the number of sequences
/// (`-1` = unlimited). Probe L2001: oc=1 donor + oc=50 acceptor with
/// threshold=10 (10% of shard_size 100) yields one sequence; 50+50 does not.
pub fn find_compactible_shard_sequences(
    broker: &mut ContainerBroker,
    shrink_threshold: i64,
    expansion_limit: i64,
    max_shrinking: i64,
    max_expanding: i64,
    include_shrinking: bool,
) -> Result<Vec<Vec<ShardRange>>, DbError> {
    let shard_ranges = broker.get_shard_ranges(&GetShardRangesArgs {
        include_own: false,
        include_deleted: false,
        ..GetShardRangesArgs::default()
    })?;
    // Persist own only. A synthesized default has no epoch; merging it as
    // the shrink-to-root acceptor overwrites own.epoch and get_db_state()
    // becomes Unsharded (probe test_shrinking L2088).
    let own = broker.get_own_shard_range(true)?;
    let shrinking_states = [shard_state::ACTIVE, shard_state::SHRINKING];
    let mut compactible = Vec::new();
    let mut index = 0usize;
    let mut expanding = 0i64;
    while (max_expanding < 0 || expanding < max_expanding) && index < shard_ranges.len() {
        if !is_shrinking_candidate(
            &shard_ranges[index],
            shrink_threshold,
            expansion_limit,
            &shrinking_states,
        ) {
            index += 1;
            continue;
        }
        let mut sequence = vec![shard_ranges[index].clone()];
        for shard_range in shard_ranges.iter().skip(index + 1) {
            if namespace_upper_lt_lower(&sequence.last().unwrap().upper, &shard_range.lower) {
                break;
            }
            if shard_range.state != shard_state::ACTIVE
                && shard_range.state != shard_state::SHRINKING
            {
                break;
            }
            if shard_range.state == shard_state::SHRINKING {
                sequence.push(shard_range.clone());
            } else if sequence_row_count(&sequence) + shard_range.row_count() <= expansion_limit {
                sequence.push(shard_range.clone());
                if sequence_complete(&sequence, shrink_threshold, expansion_limit, max_shrinking) {
                    break;
                }
            } else {
                break;
            }
        }
        index += sequence.len();
        if index == shard_ranges.len()
            && shard_ranges.len() == sequence.len()
            && !sequence_complete(&sequence, shrink_threshold, expansion_limit, max_shrinking)
            && own
                .as_ref()
                .is_some_and(|o| sequence_includes(&sequence, o))
        {
            sequence.push(own.clone().expect("own checked above"));
        }
        let last_state = sequence.last().map(|r| r.state).unwrap_or(-1);
        if sequence.len() < 2
            || (last_state != shard_state::ACTIVE && last_state != shard_state::SHARDED)
        {
            continue;
        }
        expanding += 1;
        let already_shrinking = sequence.iter().any(|r| r.state == shard_state::SHRINKING);
        if !already_shrinking || include_shrinking {
            compactible.push(sequence);
        }
    }
    Ok(compactible)
}

/// Python `process_compactible_shard_sequences` + `finalize_shrinking`:
/// expand each acceptor over its donors, mark donors SHRINKING with a new
/// epoch, merge into the root broker. Does not move object rows.
pub fn process_compactible_shard_sequences(
    broker: &mut ContainerBroker,
    sequences: &mut [Vec<ShardRange>],
) -> Result<(), DbError> {
    let timestamp = swift_core::timestamp::Timestamp::now().internal();
    let own_path = broker.path();
    let persisted_own_epoch = broker
        .get_own_shard_range(true)
        .ok()
        .flatten()
        .and_then(|o| o.epoch);
    let mut to_merge = Vec::new();
    for sequence in sequences.iter_mut() {
        if sequence.len() < 2 {
            continue;
        }
        let acceptor_idx = sequence.len() - 1;
        let donors: Vec<ShardRange> = sequence[..acceptor_idx].to_vec();
        if sequence[acceptor_idx].expand(&donors) {
            sequence[acceptor_idx].timestamp = timestamp.clone();
        }
        if sequence[acceptor_idx].update_state(shard_state::ACTIVE, None) {
            sequence[acceptor_idx].state_timestamp = timestamp.clone();
        }
        // Expand/timestamp-bump must not drop the root own epoch. A no-epoch
        // own on an epoch-suffixed DB is Unsharded (L2088).
        if sequence[acceptor_idx].name == own_path {
            if sequence[acceptor_idx].epoch.is_none() {
                sequence[acceptor_idx].epoch = persisted_own_epoch.clone();
            }
        }
        for donor in sequence[..acceptor_idx].iter_mut() {
            if donor.update_state(shard_state::SHRINKING, None) {
                donor.state_timestamp = timestamp.clone();
                donor.epoch = Some(timestamp.clone());
            }
        }
        to_merge.push(sequence[acceptor_idx].clone());
        to_merge.extend(sequence[..acceptor_idx].iter().cloned());
    }
    if !to_merge.is_empty() {
        broker.merge_shard_ranges(to_merge)?;
    }
    Ok(())
}

/// Python `_find_and_enable_shrinking_candidates`: compactible sequences on a
/// SHARDED root, then HTTP PUT expanded acceptor to the acceptor container and
/// `[donor, acceptor]` to each donor. Gated by the caller on `auto_shard`
/// (Python `is_leader`); does **not** require `auto_shrink` and does not move
/// object rows locally (`process_shrinking_donors` stays opt-in).
pub fn find_and_enable_shrinking_candidates(
    broker: &mut ContainerBroker,
    shrink_threshold: i64,
    expansion_limit: i64,
    max_shrinking: i64,
    max_expanding: i64,
    ring: Option<&swift_ring::Ring>,
) {
    if !matches!(broker.get_db_state(), Ok(DbState::Sharded)) {
        return;
    }
    let Ok(mut sequences) = find_compactible_shard_sequences(
        broker,
        shrink_threshold,
        expansion_limit,
        max_shrinking,
        max_expanding,
        true,
    ) else {
        return;
    };
    eprintln!(
        "G6_SHRINK_CANDIDATES n={} lengths={:?}",
        sequences.len(),
        sequences.iter().map(|s| s.len()).collect::<Vec<_>>()
    );
    if sequences.is_empty() {
        return;
    }
    if process_compactible_shard_sequences(broker, &mut sequences).is_err() {
        return;
    }
    let own_name = broker
        .get_own_shard_range(false)
        .ok()
        .flatten()
        .map(|o| o.name)
        .unwrap_or_default();
    let Some(ring) = ring else {
        return;
    };
    let send_ts = swift_core::timestamp::Timestamp::now().internal();
    for sequence in &mut sequences {
        if sequence.len() < 2 {
            continue;
        }
        let split_at = sequence.len() - 1;
        let donor_ocs: i64 = sequence[..split_at].iter().map(|d| d.object_count).sum();
        let donor_bytes: i64 = sequence[..split_at].iter().map(|d| d.bytes_used).sum();
        {
            let acceptor = &sequence[split_at];
            if acceptor.name != own_name {
                let (acct, cont) = split_shard_name(&acceptor.name);
                if !acct.is_empty() && !cont.is_empty() {
                    let _ = push_shard_ranges_to_ring(
                        ring,
                        &acct,
                        &cont,
                        std::slice::from_ref(acceptor),
                    );
                }
            }
        }
        if sequence[split_at].name != own_name {
            sequence[split_at].increment_meta(donor_ocs, donor_bytes, &send_ts);
        }
        let acceptor = sequence[split_at].clone();
        for donor in &sequence[..split_at] {
            let (acct, cont) = split_shard_name(&donor.name);
            if acct.is_empty() || cont.is_empty() {
                continue;
            }
            let payload = [donor.clone(), acceptor.clone()];
            let _ = push_shard_ranges_to_ring(ring, &acct, &cont, &payload);
        }
    }
}

/// Python `shard_shrink_point` default 10% of `shard_container_threshold`.
fn python_shrink_threshold(opts: &SharderRunOpts) -> i64 {
    (opts.shard_size * 10 / 100).max(0)
}

/// Python `shard_shrink_merge_point` default 75% of `shard_container_threshold`.
fn python_expansion_limit(opts: &SharderRunOpts) -> i64 {
    (opts.shard_size * 75 / 100).max(0)
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
    // Last-shard shrink-to-root: the covering acceptor is the root own,
    // which `include_own: false` hides from `find_shrink_acceptor`.
    let own = root.get_own_shard_range(true)?;
    let ts = swift_core::timestamp::Timestamp::now().internal();
    let mut finished = 0usize;
    let search_devices = local_device_siblings(device);
    for donor in donors {
        let acceptor = find_shrink_acceptor(&ranges, &donor)
            .cloned()
            .or_else(|| {
                own.clone().filter(|o| {
                    o.deleted == 0
                        && (o.state == shard_state::ACTIVE || o.state == shard_state::SHARDED)
                        && o.name != donor.name
                        && range_covers(o, &donor)
                })
            });
        let Some(acceptor) = acceptor else {
            continue;
        };
        let acceptor_is_this_root = acceptor.name == root.path();
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
        // Search every local device for the real acceptor before creating
        // an empty one. Creating empty on the donor device and then publishing
        // that DB's object_count overwrites the root with 1 (alpha only)
        // while listing still reads the real acceptor (probe MoreUTF8
        // test_shrinking L1992: 51 != 1).
        // Copy all rows in the donor's original bounds into the acceptor.
        let records = donor_b.object_records_in_range(&donor.lower, &donor.upper)?;
        let live_copied = records.iter().filter(|r| r.deleted == 0).count() as i64;
        let bytes_copied: i64 = records
            .iter()
            .filter(|r| r.deleted == 0)
            .map(|r| r.size)
            .sum();
        let names: Vec<String> = records.iter().map(|r| r.name.clone()).collect();

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

        if acceptor_is_this_root {
            // Shrink-to-root: write into this root broker (epoch file).
            // Do not open_or_create a second unsuffixed hash.db (L2088
            // unsharded + object_count 1). Do not timestamp-bump own:
            // a newer no-epoch own would wipe own.epoch.
            if !records.is_empty() {
                root.merge_items(records)?;
            }
            for name in &names {
                let _ = donor_b.remove_object_named(name);
            }
            root.merge_shard_ranges(vec![donor_updated])?;
            finished += 1;
            continue;
        }

        let (acc_existing, mut acc_b) = match open_existing_shard_on_devices(
            &search_devices,
            hash_config,
            &acc_part,
            &acceptor.name,
        ) {
            Some((_acc_dev, broker)) => (true, broker),
            None => (
                false,
                local_shard_broker_for_range(&donor_dev, hash_config, &acc_part, &acceptor),
            ),
        };

        if !records.is_empty() {
            acc_b.merge_items(records)?;
        }
        // Remove from donor so listing does not double-count if both still list.
        for name in &names {
            let _ = donor_b.remove_object_named(name);
        }

        // Refresh acceptor stats from the live acceptor DB only when that
        // DB already existed. A newly created empty acceptor only has the
        // just-copied donor rows; publishing get_info() would stomp the
        // real acceptor's 50 down to 1 on the root.
        let mut acc_updated = acceptor.clone();
        if acc_existing {
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
        } else {
            acc_updated.object_count = acceptor.object_count + live_copied;
            acc_updated.bytes_used = acceptor.bytes_used + bytes_copied;
            acc_updated.meta_timestamp = ts.clone();
        }

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
            let mut shard = local_shard_broker_for_range(device, hash_config, &spart, owner);
            shard.merge_items(vec![rec])?;
            // Hard-delete from retiring (Python `remove_objects`), not tombstone.
            retiring.remove_object_named(&name)?;
            moved += 1;
        }
    }
    Ok(moved)
}


/// Python `_process_broker` -> `_move_misplaced_objects` on the **live** broker.
///
/// Probe `test_misplaced_object_movement` L2761: after a shard shrinks, its
/// DB is SHARDED and a late in-flight PUT can land in that live table. Python
/// treats every remaining object row as misplaced (`_make_misplaced_object_bounds`
/// for SHARDED = `("", "")`) and moves it to a covering
/// CREATED/CLEAVED/ACTIVE/SHARDING destination. Rust previously only moved
/// rows out of the *retiring* file during `_cleave`, so `alpha` stayed on the
/// SHRUNK donor and listing missed it.
fn range_contains_object_name(r: &ShardRange, name: &str) -> bool {
    (r.lower.is_empty() || name > r.lower.as_str())
        && (r.upper.is_empty() || name <= r.upper.as_str())
}

fn is_shard_update_state(state: i64) -> bool {
    matches!(
        state,
        shard_state::CREATED
            | shard_state::CLEAVED
            | shard_state::ACTIVE
            | shard_state::SHARDING
    )
}

fn misplaced_dest_ranges(
    source: &mut ContainerBroker,
    ring: Option<&swift_ring::Ring>,
) -> Vec<ShardRange> {
    if source.is_root_container().unwrap_or(true) {
        return source
            .get_shard_ranges(&GetShardRangesArgs {
                include_own: false,
                include_deleted: false,
                states: Some(vec![
                    shard_state::CREATED,
                    shard_state::CLEAVED,
                    shard_state::ACTIVE,
                    shard_state::SHARDING,
                ]),
                ..GetShardRangesArgs::default()
            })
            .unwrap_or_default();
    }
    let mut ranges = Vec::new();
    if let (Some(ring), Some((root_acct, root_cont))) = (ring, root_account_container(source)) {
        ranges = fetch_shard_ranges_from_root_states(
            ring, &root_acct, &root_cont, "", "", "updating",
        );
    }
    if ranges.is_empty() {
        ranges = source
            .get_shard_ranges(&GetShardRangesArgs {
                include_own: false,
                include_deleted: false,
                ..GetShardRangesArgs::default()
            })
            .unwrap_or_default();
    }
    ranges
}

pub fn move_misplaced_from_live(
    source: &mut ContainerBroker,
    device: &Path,
    hash_config: &HashPathConfig,
    part: &str,
    ring: Option<&swift_ring::Ring>,
) -> Result<usize, DbError> {
    if !matches!(source.get_db_state()?, DbState::Sharded) {
        return Ok(0);
    }
    let dest_ranges = misplaced_dest_ranges(source, ring);
    let source_path = source.path();
    let root_path = root_account_container(source).map(|(acct, cont)| format!("{acct}/{cont}"));
    // Python fill_gaps appends the root own range (often SHARDED). That
    // range is a valid dest after shrink-to-root (probe L2798). Do not
    // synthesize an ACTIVE MIN-MAX fallback for uncovered names: a
    // mid-shrink leading gap must stay unplaced (probe test_shrinking).
    let has_updating_dest = dest_ranges.iter().any(|r| {
        r.deleted == 0
            && r.name != source_path
            && (is_shard_update_state(r.state)
                || root_path.as_deref() == Some(r.name.as_str()))
    });
    let root_fallback = if !has_updating_dest && !source.is_root_container().unwrap_or(true)
    {
        root_path.as_ref().map(|path| {
            let ts = source
                .get_own_shard_range(false)
                .ok()
                .flatten()
                .map(|o| o.timestamp.clone())
                .unwrap_or_else(|| swift_core::timestamp::Timestamp::now().internal());
            let mut sr = ShardRange::new(path, &ts, "", "");
            sr.state = shard_state::ACTIVE;
            sr
        })
    } else {
        None
    };
    if dest_ranges.is_empty() && root_fallback.is_none() {
        return Ok(0);
    }
    let records = source.object_records_in_range("", "")?;
    if records.is_empty() {
        return Ok(0);
    }
    let search = local_device_siblings(device);
    let mut moved = 0usize;
    for rec in records {
        let name = rec.name.clone();
        let owner_from_ranges = dest_ranges.iter().find(|r| {
            r.deleted == 0
                && range_contains_object_name(r, &name)
                && r.name != source_path
                && (is_shard_update_state(r.state)
                    || root_path.as_deref() == Some(r.name.as_str()))
        });
        let Some(owner) = owner_from_ranges.or(root_fallback.as_ref()) else {
            continue;
        };
        if owner.name == source_path {
            continue;
        }
        let dest_part = shard_part_for(&owner.name, ring, part);
        let local_ok = match open_existing_shard_on_devices(
            &search,
            hash_config,
            &dest_part,
            &owner.name,
        ) {
            Some((_dev, mut dest)) => dest.merge_items(vec![rec.clone()]).is_ok(),
            None if ring.is_none() => {
                // Unit tests / no-ring SAIO: create dest on this device.
                let mut dest =
                    local_shard_broker_for_range(device, hash_config, &dest_part, owner);
                dest.merge_items(vec![rec.clone()]).is_ok()
            }
            None => false,
        };
        // Python `_replicate_and_delete`: the dest primary set must receive
        // the row. A local merge on the donor device is invisible to listing
        // when dest primaries live on other /srv/N/node trees (probe L2761).
        let remote_ok = match ring {
            Some(ring) => {
                update_objects_on_primaries(ring, &owner.name, std::slice::from_ref(&rec)).is_ok()
            }
            None => false,
        };
        eprintln!(
            "G6_MISPLACED name={name} dest={} local={local_ok} remote={remote_ok}",
            owner.name
        );
        if local_ok || remote_ok {
            source.remove_object_named(&name)?;
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
    /// `shard_container_threshold`: auto-shard when `object_count >=` this.
    pub shard_size: i64,
    /// Python `rows_per_shard` (default `threshold // 2`). `0` means derive
    /// from `shard_size / 2` so existing struct literals keep working.
    pub rows_per_shard: i64,
    pub minimum_shard_size: i64,
    /// Python `--partitions`. Empty = all partitions.
    pub partitions: Vec<String>,
}

/// Identity of the container-server instance whose device is being swept.
///
/// Python Swift only lets ring primary index 0 discover new root shard or
/// shrink candidates.  The identity must therefore include the service IP
/// and port as well as the device name supplied to the leader check; device
/// names alone are commonly repeated on different hosts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharderNodeIdentity {
    pub bind_ip: String,
    pub bind_port: u32,
}

impl SharderNodeIdentity {
    pub fn new(bind_ip: impl Into<String>, bind_port: u32) -> Self {
        Self {
            bind_ip: bind_ip.into(),
            bind_port,
        }
    }
}

impl Default for SharderRunOpts {
    fn default() -> Self {
        Self {
            cleave_batch_size: 2,
            auto_shard: false,
            auto_shrink: false,
            shard_size: 1_000_000,
            rows_per_shard: 500_000,
            minimum_shard_size: 100_000,
            partitions: Vec::new(),
        }
    }
}

fn effective_rows_per_shard(opts: &SharderRunOpts) -> i64 {
    if opts.rows_per_shard > 0 {
        opts.rows_per_shard
    } else {
        (opts.shard_size / 2).max(1)
    }
}

fn effective_minimum_shard_size(opts: &SharderRunOpts) -> i64 {
    let rows = effective_rows_per_shard(opts);
    if opts.minimum_shard_size > 0 && opts.minimum_shard_size <= rows {
        opts.minimum_shard_size
    } else {
        (rows / 5).max(1)
    }
}

/// Python `sharding_enabled(broker)`: sysmeta or existing shard ranges.
pub fn sharding_enabled(broker: &mut ContainerBroker) -> bool {
    if broker
        .metadata()
        .ok()
        .and_then(|md| {
            md.into_iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("X-Container-Sysmeta-Sharding"))
        })
        .map(|(_, (v, _))| {
            matches!(
                v.to_ascii_lowercase().as_str(),
                "true" | "yes" | "1" | "on" | "t" | "y"
            )
        })
        .unwrap_or(false)
    {
        return true;
    }
    broker.has_other_shard_ranges().unwrap_or(false)
}

/// Stage a DB into `{devices_root}/{peer_device}/tmp/{stage}` then complete
/// the REPLICATE rsync RPC. SAIO (all devices on one host) does not need ssh.
struct DevicesRootRsync {
    /// Local device dir (e.g. `/srv/1/node/sdb1`) used to resolve peers.
    local_device: std::path::PathBuf,
}

impl swift_db::RsyncTransport for DevicesRootRsync {
    fn rsync(
        &self,
        local_db: &std::path::Path,
        peer_host: &str,
        peer_device: &str,
        stage_name: &str,
    ) -> bool {
        let ip = peer_host.split(':').next().unwrap_or(peer_host);
        let dest = peer_devices_root(&self.local_device, ip)
            .join(peer_device)
            .join("tmp")
            .join(stage_name);
        if let Some(parent) = dest.parent() {
            if std::fs::create_dir_all(parent).is_err() {
                return false;
            }
        }
        std::fs::copy(local_db, &dest).is_ok()
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
        swift_db::replicate_completion_rpc(
            peer_host,
            peer_device,
            partition,
            hsh,
            op,
            stage_name,
            dest_db_name,
        )
        .unwrap_or(false)
    }
}

/// Exact safety predicate for Python `cleanup_post_replicate` on a temporary
/// shard handoff. Device-name ambiguity is deliberately conservative: if a
/// primary has the same device name, the source is treated as primary and is
/// never removed. A future caller with ring device ids may make that identity
/// more precise without weakening these data-safety conditions.
fn should_cleanup_replicated_handoff(
    cleanup_requested: bool,
    source_is_primary: bool,
    target_count: usize,
    attempted_count: usize,
    errors: u64,
    max_row_before: Option<i64>,
    max_row_after: Option<i64>,
    sharding_required: bool,
) -> bool {
    cleanup_requested
        && !source_is_primary
        && target_count > 0
        && attempted_count == target_count
        && errors == 0
        && max_row_before.is_some()
        && max_row_before == max_row_after
        && !sharding_required
}

/// Python sharder `_replicate_object`: push this container DB (objects +
/// shard ranges) to the other ring primaries. Returns the number of peers or
/// cleanup operations that failed. Uses the broker's own ring partition, not
/// the caller's. When `cleanup_handoff` is true, a non-primary temporary shard
/// DB is removed only after all Python `cleanup_post_replicate` guards hold.
fn replicate_broker_to_ring_peers(
    broker: &mut ContainerBroker,
    hash_config: &HashPathConfig,
    ring: Option<&swift_ring::Ring>,
    local_device: &str,
    devices_root: Option<&std::path::Path>,
    cleanup_handoff: bool,
) -> u64 {
    let Some(ring) = ring else {
        return 0;
    };
    let Ok(info) = broker.get_info() else {
        return 0;
    };
    let get = |k: &str| {
        info.iter()
            .find(|(n, _)| n == k)
            .and_then(|(_, v)| v.as_text())
            .unwrap_or_default()
    };
    let account = get("account");
    let container = get("container");
    let id = get("id");
    if account.is_empty() || container.is_empty() || id.is_empty() {
        return 0;
    }
    let Ok(hsh) = hash_config.hash_path(&account, Some(&container), None) else {
        return 0;
    };
    let Ok((part, nodes)) = ring.get_nodes(&account, Some(&container), None) else {
        return 0;
    };
    let part = part.to_string();
    // G6 uses unique device names (`sdb1`..`sdb4`). In a production ring
    // where names are duplicated across hosts this intentionally suppresses
    // cleanup rather than guessing local identity and risking data loss.
    let source_is_primary = nodes.iter().any(|n| n.dev.device == local_device);
    let target_count = if source_is_primary {
        nodes
            .iter()
            .filter(|n| n.dev.device != local_device)
            .count()
    } else {
        nodes.len()
    };
    let max_row_before = broker.get_max_row().ok().map(|v| v.unwrap_or(-1));
    // Constructor path: `open_or_create_shard_broker` already points at the
    // epoch file when `sr.epoch` is set. rsync dest is basename of this
    // file (Python `_rsync_db`), so an epoch source completes onto
    // `hash_<epoch>.db` (probe L2088) instead of resurrecting retiring.
    let db_path = broker.db_file().to_path_buf();
    let rsync = devices_root.map(|root| DevicesRootRsync {
        // `root` is the node dir (`/srv/1/node`); join local device name.
        local_device: root.join(local_device),
    });
    let mut errors = 0u64;
    let mut attempted_count = 0usize;
    for n in &nodes {
        if n.dev.device == local_device {
            continue;
        }
        attempted_count += 1;
        let ip = n
            .dev
            .replication_ip
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or(n.dev.ip.as_str());
        let port = n.dev.replication_port.unwrap_or(n.dev.port);
        let host = format!("{ip}:{port}");
        match replicate_container_db(broker, &id, &host, &n.dev.device, &part, &hsh) {
            Ok(outcome) => {
                let op = if outcome.needs_rsync {
                    "complete_rsync"
                } else {
                    // Always rsync_then_merge after usync so shard-range
                    // rows (own range) land; merge_items alone omits them
                    // when the peer never advertised shard_max_row.
                    "rsync_then_merge"
                };
                let ok = match rsync.as_ref() {
                    Some(t) => {
                        swift_db::rsync_db(&db_path, &id, &host, &n.dev.device, &part, &hsh, op, t)
                    }
                    None => !outcome.needs_rsync && !outcome.usync_incomplete,
                };
                if !ok {
                    errors += 1;
                }
            }
            Err(_) => errors += 1,
        }
    }
    let max_row_after = broker.get_max_row().ok().map(|v| v.unwrap_or(-1));
    // Python ContainerReplicator refuses handoff cleanup while the DB still
    // requires sharding, so a nested cleave cannot lose its local source.
    let sharding_required = match broker.get_db_state() {
        Ok(DbState::Sharding) => true,
        Ok(DbState::Unsharded) => broker.sharding_initiated().unwrap_or(true),
        Ok(_) => false,
        Err(_) => true,
    };
    if should_cleanup_replicated_handoff(
        cleanup_handoff,
        source_is_primary,
        target_count,
        attempted_count,
        errors,
        max_row_before,
        max_row_after,
        sharding_required,
    ) {
        if remove_replicated_handoff_db(&db_path) {
            eprintln!(
                "G6_HANDOFF_CLEANUP account={account} container={container} part={part} device={local_device} db={}",
                db_path.display()
            );
        } else {
            // Cleanup failure is a replication failure: the stale handoff is
            // still able to report old object_count to root on a later pass.
            errors += 1;
        }
    }
    errors
}

/// Python `roundrobin_datadirs` yields each container directory once;
/// `ContainerBroker` then opens the freshest epoch file. Walking every
/// `<hash>.db` *and* `<hash>_<epoch>.db` as separate brokers would run
/// `_cleave` twice in one `once()` and finish a `cleave_batch_size=2`
/// nested shard in a single cycle (probe L1204/L1228).
fn current_container_db_files(device: &Path) -> Vec<PathBuf> {
    let all = db_locations(device, "containers");
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for p in all {
        let Some(dir) = p.parent() else {
            continue;
        };
        if !seen.insert(dir.to_path_buf()) {
            continue;
        }
        let files = get_db_files(&p);
        if let Some(cur) = files.last() {
            out.push(cur.clone());
        } else if p.exists() {
            out.push(p);
        }
    }
    out
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

/// Whether this local device is ring primary index 0 for a container.
///
/// A wildcard bind address cannot be compared with the ring IP, so in that
/// case the configured port plus the on-disk device name are used.  With a
/// concrete bind address all three values must match.
fn local_node_is_primary_leader(
    ring: &swift_ring::Ring,
    account: &str,
    container: &str,
    device: &Path,
    local: &SharderNodeIdentity,
) -> bool {
    let Ok((_part, nodes)) = ring.get_nodes(account, Some(container), None) else {
        return false;
    };
    let Some(primary) = nodes.first() else {
        return false;
    };
    let local_device = device
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    let wildcard = matches!(local.bind_ip.as_str(), "0.0.0.0" | "::" | "[::]");
    (wildcard || primary.dev.ip == local.bind_ip)
        && primary.dev.port == local.bind_port
        && primary.dev.device == local_device
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
    run_once_with_opts_replicator_ring_and_node(
        device,
        hash_config,
        opts,
        replicator,
        ring,
        None,
    )
}

fn run_once_with_opts_replicator_ring_and_node(
    device: &Path,
    hash_config: &HashPathConfig,
    opts: &SharderRunOpts,
    replicator: &mut dyn ShardReplicator,
    ring: Option<&swift_ring::Ring>,
    local_node: Option<&SharderNodeIdentity>,
) -> SharderStats {
    let mut stats = SharderStats::default();
    for db in current_container_db_files(device) {
        let part = db
            .components()
            .rev()
            .nth(3)
            .and_then(|c| c.as_os_str().to_str())
            .unwrap_or("0")
            .to_string();
        if !opts.partitions.is_empty() && !opts.partitions.iter().any(|p| p == &part) {
            continue;
        }
        stats.containers_seen += 1;
        let mut broker = match broker_with_path_from_db(&db) {
            Ok(b) => b,
            Err(_) => {
                stats.failures += 1;
                continue;
            }
        };
        // Python `_process_broker` starts with `_audit_container`. A shard
        // replica that missed the SHARDING PUT (server was down) learns
        // own=SHARDING and sub-shards from the root here (probe L1245).
        if !broker.is_root_container().unwrap_or(true) {
            audit_shard_from_root(&mut broker, ring);
        }
        // Python `_process_broker`: misplaced pass after audit. SHARDED
        // live-table rows (post-shrink in-flight PUTs) never sit in retiring,
        // so `_cleave`'s retiring helper cannot see them (probe L2761).
        if matches!(broker.get_db_state().ok(), Some(DbState::Sharded)) {
            if let Err(_) = move_misplaced_from_live(&mut broker, device, hash_config, &part, ring)
            {
                stats.failures += 1;
            }
        }
        let broker_path = broker.path();
        let (broker_account, broker_container) =
            broker_path.split_once('/').unwrap_or((broker_path.as_str(), ""));
        // Local/single-node callers without a ring identity keep their
        // historical behavior. The daemon always supplies an identity when
        // a ring is loaded, matching Python's `node['index'] == 0` gate.
        let is_leader = match (ring, local_node) {
            (Some(ring), Some(local)) => local_node_is_primary_leader(
                ring,
                broker_account,
                broker_container,
                device,
                local,
            ),
            _ => true,
        };
        let state = match broker.get_db_state() {
            Ok(s) => s,
            Err(_) => {
                stats.failures += 1;
                continue;
            }
        };
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
            // Python `_process_broker`:
            // - only a *root* leader bootstraps auto-shard from object_count
            // - a *shard* whose own range is already SHARDING (root sent it)
            //   must `set_sharding_state` + cleave (probe L1199: 2 epoch DBs)
            DbState::Unsharded | DbState::Collapsed
                if {
                    let is_root = broker.is_root_container().unwrap_or(true);
                    let own_cleaving = broker
                        .get_own_shard_range(true)
                        .ok()
                        .flatten()
                        .is_some_and(|r| swift_db::CLEAVING_STATES.contains(&r.state));
                    let has_other_ranges = own_cleaving
                        && broker.has_other_shard_ranges().unwrap_or(false);
                    (is_root
                        && (has_other_ranges
                            || (is_leader
                                && (opts.auto_shard || sharding_enabled(&mut broker)))))
                        || (!is_root && own_cleaving)
                } =>
            {
                let is_root = broker.is_root_container().unwrap_or(true);
                if !is_root {
                    let own = broker.get_own_shard_range(true).ok().flatten();
                    let has_children = own.as_ref().is_some_and(|o| {
                        broker
                            .get_shard_ranges(&GetShardRangesArgs {
                                include_own: false,
                                ..GetShardRangesArgs::default()
                            })
                            .ok()
                            .is_some_and(|rs| rs.iter().any(|r| o.includes_range(r)))
                    });
                    eprintln!(
                        "G6_UNSHARDED_SHARD own={:?} has_children={has_children}",
                        own.as_ref().map(|o| (
                            o.lower.as_str(),
                            o.upper.as_str(),
                            o.state,
                            o.name.as_str()
                        ))
                    );
                    if own
                        .as_ref()
                        .is_some_and(|r| r.state == shard_state::SHARDING)
                        && !has_children
                    {
                        let _ = maybe_auto_shard(&mut broker, opts);
                    }
                    let _ = broker.set_sharding_state();
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
                } else {
                    match maybe_start_sharding(&mut broker, opts) {
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
                    }
                }
            }
            DbState::Sharded => {
                // Multi-primary auto-shrink product: move objects from
                // SHRINKING donors into acceptors across local device
                // siblings; mark donors SHRUNK. Skip when auto_shrink=false.
                // Python does **not** gate shrinking-candidate discovery on
                // this flag — that is `auto_shard` + leader on a SHARDED root.
                if opts.auto_shrink {
                    match process_shrinking_donors(&mut broker, device, hash_config, &part, ring) {
                        Ok(n) if n > 0 => {
                            stats.shrinking_donors += n as u64;
                            stats.finished += n as u64;
                        }
                        Ok(_) => stats.skipped += 1,
                        Err(_) => stats.failures += 1,
                    }
                } else {
                    stats.skipped += 1;
                }
                // Python `_process_broker` on a SHARDED root leader:
                // shrinking candidates first, then sharding candidates.
                if broker.is_root_container().unwrap_or(false) && opts.auto_shard && is_leader {
                    find_and_enable_shrinking_candidates(
                        &mut broker,
                        python_shrink_threshold(opts),
                        python_expansion_limit(opts),
                        1,
                        -1,
                        ring,
                    );
                    find_and_enable_sharding_candidates(&mut broker, opts.shard_size, ring);
                }
            }
            DbState::Unsharded | DbState::Collapsed | DbState::NotFound => {
                stats.skipped += 1;
            }
        }
        // Python `_update_root_container`: shard DBs (not roots) push live
        // object_count to the root so HEAD after `run_sharders` is current.
        if let Err(_) = update_root_container(&mut broker, ring) {
            stats.failures += 1;
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

/// Ring-backed sweep with the local service identity needed for Python's
/// primary-index-zero leader semantics.
pub fn run_once_with_opts_and_ring_for_node(
    device: &Path,
    hash_config: &HashPathConfig,
    opts: &SharderRunOpts,
    container_ring: Option<&swift_ring::Ring>,
    local_node: &SharderNodeIdentity,
) -> SharderStats {
    match container_ring {
        Some(ring) => {
            let mut rep = lookup_replicator_for_ring(ring);
            run_once_with_opts_replicator_ring_and_node(
                device,
                hash_config,
                opts,
                &mut rep,
                Some(ring),
                Some(local_node),
            )
        }
        None => run_once_with_opts(device, hash_config, opts),
    }
}

/// Python `_complete_sharding`: promote every CLEAVED other-range to ACTIVE,
/// mark own SHARDED (and `deleted=1` with a new timestamp if this is a nested
/// shard), then unlink the retiring DB (`set_sharded_state`).
///
/// Probe `_test_sharded_listing` L1362 lists 4 live ranges because the donor
/// own range is deleted on the root; L1396 asserts `old_shard_range.deleted`.
fn complete_sharding(broker: &mut ContainerBroker) -> Result<bool, DbError> {
    let ts = swift_core::timestamp::Timestamp::now().internal();
    let Some(mut own) = broker.get_own_shard_range(true)? else {
        return Ok(false);
    };
    own.update_meta(0, 0, &ts);
    let shrinking = own.state == shard_state::SHRINKING || own.state == shard_state::SHRUNK;
    let mut to_merge = Vec::new();
    if shrinking {
        let _ = own.update_state(shard_state::SHRUNK, Some(&ts));
    } else {
        let _ = own.update_state(shard_state::SHARDED, Some(&ts));
        let cleaved = broker.get_shard_ranges(&GetShardRangesArgs {
            include_own: false,
            ..GetShardRangesArgs::default()
        })?;
        for mut sr in cleaved {
            if sr.state == shard_state::CLEAVED && sr.update_state(shard_state::ACTIVE, Some(&ts)) {
                to_merge.push(sr);
            }
        }
    }
    // Python: non-root `own.copy(timestamp=now, deleted=1)` so merge at root
    // replaces the live SHARDING donor. Same timestamp + deleted=1 loses
    // (`merge_shards` preserves existing deleted on a timestamp tie).
    if !broker.is_root_container().unwrap_or(true) && own.deleted == 0 {
        own.deleted = 1;
        own.timestamp = ts.clone();
        own.meta_timestamp = ts.clone();
        own.state_timestamp = ts;
    }
    to_merge.push(own);
    broker.merge_shard_ranges(to_merge)?;
    broker.set_sharded_state()
}

/// Python `find_sharding_candidates` + `_find_and_enable_sharding_candidates`:
/// ACTIVE other-ranges with `object_count >= threshold` become SHARDING, then
/// that range is PUT onto the shard container primaries.
fn find_and_enable_sharding_candidates(
    broker: &mut ContainerBroker,
    threshold: i64,
    ring: Option<&swift_ring::Ring>,
) {
    let Ok(ranges) = broker.get_shard_ranges(&GetShardRangesArgs {
        include_own: false,
        states: Some(vec![shard_state::ACTIVE]),
        ..GetShardRangesArgs::default()
    }) else {
        return;
    };
    let ts = swift_core::timestamp::Timestamp::now().internal();
    let mut candidates = Vec::new();
    for mut sr in ranges {
        if sr.state == shard_state::ACTIVE && sr.object_count >= threshold {
            if sr.update_state(shard_state::SHARDING, Some(&ts)) {
                sr.epoch = Some(ts.clone());
                candidates.push(sr);
            }
        }
    }
    if candidates.is_empty() {
        return;
    }
    let _ = broker.merge_shard_ranges(candidates.clone());
    let Some(ring) = ring else {
        return;
    };
    for sr in &candidates {
        let (acct, cont) = split_shard_name(&sr.name);
        if acct.is_empty() || cont.is_empty() {
            continue;
        }
        let _ = push_shard_ranges_to_ring(ring, &acct, &cont, std::slice::from_ref(sr));
    }
}

/// Enter SHARDING when ranges already exist (`swift-manage-shard-ranges
/// find_and_replace --enable`) even if `object_count < shard_size`. Auto-find
/// still requires the threshold.
fn maybe_start_sharding(
    broker: &mut ContainerBroker,
    opts: &SharderRunOpts,
) -> Result<bool, DbError> {
    // A replica may receive a SHARDED own range plus its ACTIVE children
    // while its local DB is still UNSHARDED. Reuse those exact ranges; calling
    // auto-find would create a second epoch and four overlapping ranges.
    //
    // Shrink-to-root is the exception: an ACTIVE/SHARDED root own range plus
    // a SHRINKING donor describes an acceptor, not a new cleave. Starting a
    // fresh epoch there creates an empty DB and drops the listing.
    let other_ranges = broker.get_shard_ranges(&GetShardRangesArgs {
        include_own: false,
        include_deleted: false,
        ..GetShardRangesArgs::default()
    })?;
    // Last shrink-to-root: other_ranges is empty (donor SHRUNK/deleted) but
    // compactible may have persisted own without epoch onto the epoch file.
    // get_db_state() is then Unsharded with object_count 1 (probe L2088).
    // Heal only when own is an acceptor — a SHARDING own must keep cleaving.
    if let Some(db_epoch) = broker.db_epoch() {
        if let Some(mut own) = broker.get_own_shard_range(true)? {
            let cleaving = own.state == shard_state::SHARDING
                || own.state == shard_state::SHRINKING;
            if !cleaving {
                let own_norm = own
                    .epoch
                    .as_deref()
                    .and_then(|e| e.parse::<swift_core::timestamp::Timestamp>().ok())
                    .map(|ts| ts.normal());
                let db_norm = db_epoch
                    .parse::<swift_core::timestamp::Timestamp>()
                    .ok()
                    .map(|ts| ts.normal());
                if own_norm != db_norm {
                    own.epoch = Some(db_epoch);
                    own.timestamp = swift_core::timestamp::Timestamp::now().internal();
                    broker.merge_shard_ranges(vec![own])?;
                }
            }
        }
    }

    if !other_ranges.is_empty() {
        let has_shrinking_donor = other_ranges
            .iter()
            .any(|range| range.state == shard_state::SHRINKING);
        let own_is_donor = broker.get_own_shard_range(true)?.is_some_and(|range| {
            range.state == shard_state::SHARDING || range.state == shard_state::SHRINKING
        });
        if has_shrinking_donor && !own_is_donor {
            return Ok(false);
        }
        // An epoch-suffixed DB whose own range is already an acceptor
        // (ACTIVE/SHARDED), not a cleaving donor. Leftover ACTIVE siblings
        // after the first shrink are mid-shrink children. Calling
        // set_sharding_state() here creates a second epoch, own.epoch
        // diverges, and HEAD reports unsharded with object_count 1 (L2088).
        //
        // If own is still SHARDING, this is the first cleave (maybe_auto_shard
        // just created the epoch file). Must continue into set_sharding_state
        // so objects actually leave the root (probe expected count 0).
        if broker.db_epoch().is_some() && !own_is_donor {
            if let Some(db_epoch) = broker.db_epoch() {
                if let Some(mut own) = broker.get_own_shard_range(true)? {
                    let own_norm = own
                        .epoch
                        .as_deref()
                        .and_then(|e| e.parse::<swift_core::timestamp::Timestamp>().ok())
                        .map(|ts| ts.normal());
                    let db_norm = db_epoch
                        .parse::<swift_core::timestamp::Timestamp>()
                        .ok()
                        .map(|ts| ts.normal());
                    if own_norm != db_norm {
                        own.epoch = Some(db_epoch);
                        let ts = swift_core::timestamp::Timestamp::now().internal();
                        own.timestamp = ts;
                        broker.merge_shard_ranges(vec![own])?;
                    }
                }
            }
            return Ok(false);
        }
        return broker.set_sharding_state();
    }
    maybe_auto_shard(broker, opts)
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
    let rows_per_shard = effective_rows_per_shard(opts);
    let minimum_shard_size = effective_minimum_shard_size(opts);
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
    // Python `make_shard_ranges`: shards_account_prefix + root_account,
    // root_container, parent=this container. Nested shards must not
    // prefix `.shards_` onto an already-hidden account.
    let (name_acct, name_root, name_parent) = match root_account_container(broker) {
        Some((ra, rc)) => (ra, rc, container),
        None => (account.clone(), container.clone(), container),
    };
    let epoch = swift_core::timestamp::Timestamp::now().internal();
    find_and_merge_found_ranges_named(
        broker,
        &name_acct,
        &name_root,
        &name_parent,
        rows_per_shard,
        minimum_shard_size,
        &epoch,
    )?;
    broker.enable_sharding(&epoch)?;
    broker.set_sharding_state()
}

#[cfg(test)]
mod tests {
    use super::*;
    use swift_core::hashing::HashPathConfig;
    use swift_db::RsyncTransport;

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
        let total_bytes: i64 = ranges.iter().map(|r| r.bytes_used).sum();
        assert_eq!(total_bytes, 10, "in-memory cleave stats: {ranges:?}");
        let persisted = source
            .get_shard_ranges(&GetShardRangesArgs {
                include_own: false,
                ..GetShardRangesArgs::default()
            })
            .unwrap();
        let persisted_bytes: i64 = persisted.iter().map(|r| r.bytes_used).sum();
        assert_eq!(
            persisted_bytes, 10,
            "root DB must persist cleaved shard bytes: {persisted:?}"
        );
        assert!(
            persisted.iter().all(|range| {
                let meta = range
                    .meta_timestamp
                    .parse::<swift_core::timestamp::Timestamp>()
                    .unwrap();
                let created = range
                    .timestamp
                    .parse::<swift_core::timestamp::Timestamp>()
                    .unwrap();
                !range.meta_timestamp.contains('_')
                    && meta.offset() == 0
                    && meta.raw() == created.raw() + 1
            }),
            "first-cleave metadata must be a one-tick NormalTimestamp: {persisted:?}"
        );
        // A shard may report a newer live count before another root replica
        // finishes its first cleave. Replaying the stale cleave snapshot must
        // not overwrite that authoritative report.
        let mut authoritative = persisted[0].clone();
        authoritative.update_meta(4, 4, "1751500011.00000");
        source
            .merge_shard_ranges(vec![authoritative.clone()])
            .unwrap();
        source
            .merge_shard_ranges(vec![ranges[0].clone()])
            .unwrap();
        let after_replay = source
            .get_shard_ranges(&GetShardRangesArgs {
                include_own: false,
                ..GetShardRangesArgs::default()
            })
            .unwrap()
            .into_iter()
            .find(|range| range.name == authoritative.name)
            .unwrap();
        assert_eq!(after_replay.object_count, 4, "{after_replay:?}");
        assert_eq!(after_replay.bytes_used, 4, "{after_replay:?}");
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
        assert_eq!(
            ctx.ranges_todo, 2,
            "Python leftover ranges_todo after batch"
        );
        assert!(!ctx.cleaving_done);
        assert_eq!(ctx.cursor, ranges[1].upper);
        // second batch finishes
        cleave(&mut source, &mut ranges, &mut shard_for, &mut ctx, 2).unwrap();
        assert_eq!(ctx.ranges_done, 4);
        assert_eq!(ctx.ranges_todo, 0);
        assert!(ctx.cleaving_done);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_nested_cleave_batch_two_keeps_sharding() {
        // Probe `_test_sharded_listing` L1191–L1228: a shard-of-a-shard with
        // own.upper != MAX, three sub-ranges, cleave_batch_size=2. One
        // process_sharding pass must leave db_state=sharding, the retiring
        // unsuffixed .db, and [CLEAVED, CLEAVED, CREATED].
        let hash_config = HashPathConfig::new("", "changeme").unwrap();
        let dir = std::env::temp_dir().join(format!("swift-nested-cleave-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let device = dir.join("d1");
        let account = "AUTH_test";
        let container = "c-0";
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
        for i in 0..150 {
            source
                .put_object(
                    &format!("j{i:04}"),
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
        let mut own = ShardRange::new(&source.path(), epoch, "", "m");
        own.state = shard_state::SHARDING;
        own.epoch = Some(epoch.into());
        ensure_shard_root_sysmeta(&mut source, account, "rootc", &own);
        let ranges =
            find_and_merge_found_ranges(&mut source, account, container, 50, 1, epoch).unwrap();
        assert_eq!(
            ranges.len(),
            3,
            "150 objects / 50 rows under own.upper=m: {ranges:?}"
        );
        assert_eq!(ranges.last().unwrap().upper, "m", "{ranges:?}");
        source.enable_sharding(epoch).unwrap();
        assert!(source.set_sharding_state().unwrap());
        assert!(
            db.exists(),
            "retiring unsuffixed .db must exist after set_sharding_state"
        );

        let finished =
            process_sharding_container(&mut source, &device, &hash_config, "0", 2).unwrap();
        assert!(!finished, "batch=2 of 3 must not complete_sharding");
        assert_eq!(source.get_db_state().unwrap(), DbState::Sharding);
        assert!(
            db.exists(),
            "retiring unsuffixed .db must survive a partial nested cleave"
        );
        let got = source
            .get_shard_ranges(&GetShardRangesArgs {
                include_own: false,
                ..GetShardRangesArgs::default()
            })
            .unwrap();
        let states: Vec<i64> = got.iter().map(|r| r.state).collect();
        assert_eq!(
            states,
            vec![
                shard_state::CLEAVED,
                shard_state::CLEAVED,
                shard_state::CREATED
            ],
            "{got:?}"
        );
        let ctx = load_cleaving_context(&mut source).unwrap();
        assert!(!ctx.cleaving_done, "{ctx:?}");
        assert_eq!(ctx.ranges_done, 2, "{ctx:?}");
        assert_eq!(ctx.ranges_todo, 1, "{ctx:?}");
        let created = got
            .iter()
            .find(|r| r.state == shard_state::CREATED)
            .expect("leftover CREATED range");
        let (created_db, _, _) = shard_db_path(&device, &hash_config, "0", &created.name);
        assert!(
            created_db.exists(),
            "CREATED sub-shard must have a local db for replicators.once() \
             to copy onto a missing primary (probe L1290): {created_db:?}"
        );
        let with_own = source
            .get_shard_ranges(&GetShardRangesArgs {
                include_own: true,
                include_deleted: true,
                ..GetShardRangesArgs::default()
            })
            .unwrap();
        assert!(
            with_own.len() >= 4,
            "nested shard must report own+3 sub-ranges to root, got {with_own:?}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_nested_second_once_deletes_own_and_promotes_active() {
        // Probe L1338–L1366: a later once() finishes the leftover CREATED
        // range, promotes children ACTIVE, marks own SHARDED+deleted so the
        // root listing drops the donor (4 live ranges, not 5).
        let hash_config = HashPathConfig::new("", "changeme").unwrap();
        let dir = std::env::temp_dir().join(format!("swift-nested-finish-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let device = dir.join("d1");
        let account = "AUTH_test";
        let container = "c-0";
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
        for i in 0..150 {
            source
                .put_object(
                    &format!("j{i:04}"),
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
        let mut own = ShardRange::new(&source.path(), epoch, "", "m");
        own.state = shard_state::SHARDING;
        own.epoch = Some(epoch.into());
        ensure_shard_root_sysmeta(&mut source, account, "rootc", &own);
        let ranges =
            find_and_merge_found_ranges(&mut source, account, container, 50, 1, epoch).unwrap();
        assert_eq!(ranges.len(), 3, "{ranges:?}");
        source.enable_sharding(epoch).unwrap();
        assert!(source.set_sharding_state().unwrap());

        let finished =
            process_sharding_container(&mut source, &device, &hash_config, "0", 2).unwrap();
        assert!(!finished, "batch=2 of 3 must not complete_sharding");
        drop(source);

        let mut source = ContainerBroker::new(&db, account, container);
        let finished =
            process_sharding_container(&mut source, &device, &hash_config, "0", 2).unwrap();
        assert!(finished, "second once() must finish leftover CREATED");
        assert_eq!(source.get_db_state().unwrap(), DbState::Sharded);
        assert!(
            !db.exists(),
            "retiring unsuffixed .db must be unlinked after complete_sharding"
        );
        let children = source
            .get_shard_ranges(&GetShardRangesArgs {
                include_own: false,
                ..GetShardRangesArgs::default()
            })
            .unwrap();
        assert_eq!(children.len(), 3, "{children:?}");
        assert!(
            children.iter().all(|r| r.state == shard_state::ACTIVE),
            "children must be ACTIVE, got {children:?}"
        );
        let own = source
            .get_own_shard_range(true)
            .unwrap()
            .expect("own range");
        assert_eq!(own.state, shard_state::SHARDED, "{own:?}");
        assert_eq!(own.deleted, 1, "nested donor must be deleted: {own:?}");
        let live = source
            .get_shard_ranges(&GetShardRangesArgs {
                include_own: true,
                include_deleted: false,
                ..GetShardRangesArgs::default()
            })
            .unwrap();
        assert_eq!(
            live.len(),
            3,
            "deleted own must not appear in live listing, got {live:?}"
        );
        let ctx = load_cleaving_context(&mut source).unwrap();
        assert!(
            ctx.done(),
            "probe L1356 load_all/done() must be True: {ctx:?}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_two_cleaved_ranges_short_of_own_upper_do_not_finish() {
        // `all >= CLEAVED` used to call complete_sharding even when the
        // last cleaved upper was still below own.upper.
        let hash_config = HashPathConfig::new("", "changeme").unwrap();
        let dir = std::env::temp_dir().join(format!("swift-cleave-gap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let device = dir.join("d1");
        let account = "AUTH_test";
        let container = "c-0";
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
        for i in 0..80 {
            source
                .put_object(
                    &format!("j{i:04}"),
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
        let mut own = ShardRange::new(&source.path(), epoch, "", "m");
        own.state = shard_state::SHARDING;
        own.epoch = Some(epoch.into());
        ensure_shard_root_sysmeta(&mut source, account, "rootc", &own);
        let mut a = ShardRange::new(".shards_AUTH_test/c-0-0", epoch, "", "g");
        a.state = shard_state::CREATED;
        let mut b = ShardRange::new(".shards_AUTH_test/c-0-1", epoch, "g", "k");
        b.state = shard_state::CREATED;
        source.merge_shard_ranges(vec![a, b]).unwrap();
        source.enable_sharding(epoch).unwrap();
        assert!(source.set_sharding_state().unwrap());

        let finished =
            process_sharding_container(&mut source, &device, &hash_config, "0", 2).unwrap();
        assert!(!finished, "last.upper=k < own.upper=m must not finish");
        assert_eq!(source.get_db_state().unwrap(), DbState::Sharding);
        assert!(db.exists(), "retiring .db must remain");
        let ctx = load_cleaving_context(&mut source).unwrap();
        assert!(!ctx.cleaving_done, "{ctx:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_run_once_does_not_double_cleave_epoch_and_retiring() {
        // Both <hash>.db and <hash>_<epoch>.db exist. One once() with
        // batch=2 must not walk them as two containers and finish 3 ranges.
        let hash_config = HashPathConfig::new("", "changeme").unwrap();
        let dir = std::env::temp_dir().join(format!("swift-once-dedup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let device = dir.join("d1");
        let account = "AUTH_test";
        let container = "c-0";
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
        for i in 0..150 {
            source
                .put_object(
                    &format!("j{i:04}"),
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
        let mut own = ShardRange::new(&source.path(), epoch, "", "m");
        own.state = shard_state::SHARDING;
        own.epoch = Some(epoch.into());
        ensure_shard_root_sysmeta(&mut source, account, "rootc", &own);
        find_and_merge_found_ranges(&mut source, account, container, 50, 1, epoch).unwrap();
        source.enable_sharding(epoch).unwrap();
        assert!(source.set_sharding_state().unwrap());
        drop(source);

        let stats = run_once(&device, &hash_config, 2);
        assert_eq!(stats.failures, 0, "{stats:?}");
        assert_eq!(
            stats.finished, 0,
            "must not complete in one once(): {stats:?}"
        );
        let mut check = ContainerBroker::new(&db, account, container);
        assert_eq!(check.get_db_state().unwrap(), DbState::Sharding);
        assert!(db.exists(), "retiring .db unlinked by a double once() walk");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_nested_once_ignores_audit_sibling_and_keeps_sharding() {
        // Live G6: audit may merge a sibling range with upper=MAX. That must
        // not skip find or complete_sharding; one once()+batch=2 still
        // leaves db_state=sharding and the retiring file.
        let hash_config = HashPathConfig::new("", "changeme").unwrap();
        let dir = std::env::temp_dir().join(format!("swift-nested-sibling-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let device = dir.join("d1");
        let account = "AUTH_test";
        let container = "c-0";
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
        for i in 0..150 {
            source
                .put_object(
                    &format!("j{i:04}"),
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
        let mut own = ShardRange::new(&source.path(), epoch, "", "m");
        own.state = shard_state::SHARDING;
        own.epoch = Some(epoch.into());
        ensure_shard_root_sysmeta(&mut source, account, "rootc", &own);
        let mut sibling = ShardRange::new(".shards_AUTH_test/c-1", epoch, "m", "");
        sibling.state = shard_state::ACTIVE;
        source.merge_shard_ranges(vec![sibling]).unwrap();
        assert!(source.has_other_shard_ranges().unwrap());
        drop(source);

        let opts = SharderRunOpts {
            cleave_batch_size: 2,
            auto_shard: true,
            auto_shrink: false,
            shard_size: 100,
            rows_per_shard: 50,
            minimum_shard_size: 10,
            partitions: Vec::new(),
        };
        let stats = run_once_with_opts(&device, &hash_config, &opts);
        assert_eq!(stats.failures, 0, "{stats:?}");
        assert_eq!(
            stats.finished, 0,
            "sibling MAX must not finish nested cleave: {stats:?}"
        );
        let mut check = ContainerBroker::new(&db, account, container);
        assert_eq!(check.get_db_state().unwrap(), DbState::Sharding);
        assert!(db.exists(), "retiring unsuffixed .db must remain");
        let own = check.get_own_shard_range(true).unwrap().unwrap();
        let kids: Vec<_> = check
            .get_shard_ranges(&GetShardRangesArgs {
                include_own: false,
                ..GetShardRangesArgs::default()
            })
            .unwrap()
            .into_iter()
            .filter(|r| own.includes_range(r))
            .collect();
        let child_states: Vec<i64> = kids.iter().map(|r| r.state).collect();
        assert_eq!(
            child_states,
            vec![
                shard_state::CLEAVED,
                shard_state::CLEAVED,
                shard_state::CREATED
            ],
            "expected 3 nested children after once(), got {kids:?}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_second_replica_counts_already_cleaved_against_batch() {
        // Probe L1191: replica 2 audits [CLEAVED, CLEAVED, CREATED] from the
        // root with an empty cleaving context. Python still visits the two
        // CLEAVED ranges (they consume cleave_batch_size=2) and must not
        // finish the leftover CREATED range in that once().
        let hash_config = HashPathConfig::new("", "changeme").unwrap();
        let dir = std::env::temp_dir().join(format!("swift-cleave-recount-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let device = dir.join("d1");
        let account = "AUTH_test";
        let container = "c-0";
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
        for i in 0..150 {
            source
                .put_object(
                    &format!("j{i:04}"),
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
        let mut own = ShardRange::new(&source.path(), epoch, "", "m");
        own.state = shard_state::SHARDING;
        own.epoch = Some(epoch.into());
        ensure_shard_root_sysmeta(&mut source, account, "rootc", &own);
        let mut r0 = ShardRange::new(".shards_AUTH_test/c-0-0", epoch, "", "j0049");
        r0.state = shard_state::CLEAVED;
        let mut r1 = ShardRange::new(".shards_AUTH_test/c-0-1", epoch, "j0049", "j0099");
        r1.state = shard_state::CLEAVED;
        let mut r2 = ShardRange::new(".shards_AUTH_test/c-0-2", epoch, "j0099", "m");
        r2.state = shard_state::CREATED;
        source.merge_shard_ranges(vec![r0, r1, r2]).unwrap();
        source.enable_sharding(epoch).unwrap();
        assert!(source.set_sharding_state().unwrap());

        let finished =
            process_sharding_container(&mut source, &device, &hash_config, "0", 2).unwrap();
        assert!(!finished, "second replica must not finish leftover CREATED");
        assert_eq!(source.get_db_state().unwrap(), DbState::Sharding);
        assert!(db.exists(), "retiring .db must remain");
        let got = source
            .get_shard_ranges(&GetShardRangesArgs {
                include_own: false,
                ..GetShardRangesArgs::default()
            })
            .unwrap();
        let states: Vec<i64> = got.iter().map(|r| r.state).collect();
        assert_eq!(
            states,
            vec![
                shard_state::CLEAVED,
                shard_state::CLEAVED,
                shard_state::CREATED
            ],
            "{got:?}"
        );
        let ctx = load_cleaving_context(&mut source).unwrap();
        assert!(!ctx.cleaving_done, "{ctx:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_underpopulated_replica_finishes_empty_cleaved_prefix() {
        // Probe listing_under_populated L1494: under-populated replica has
        // one object in the last range and an empty cleaving context. The
        // two already-CLEAVED prefix ranges have no local rows, so Python
        // treats them as CLEAVE_EMPTY and does not spend cleave_batch_size
        // on them. One once() must finish the leftover CREATED ranges and
        // reach SHARDED.
        let hash_config = HashPathConfig::new("", "changeme").unwrap();
        let dir = std::env::temp_dir().join(format!(
            "swift-cleave-underpop-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let device = dir.join("d1");
        let account = "AUTH_test";
        let container = "c-under";
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
        source
            .put_object(
                "zzz",
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
        let epoch = "1751500010.00000";
        let mut own = ShardRange::new(&source.path(), epoch, "", "");
        own.state = shard_state::SHARDING;
        own.epoch = Some(epoch.into());
        ensure_shard_root_sysmeta(&mut source, account, "rootc", &own);
        let mut r0 = ShardRange::new(".shards_AUTH_test/c-u-0", epoch, "", "m");
        r0.state = shard_state::CLEAVED;
        let mut r1 = ShardRange::new(".shards_AUTH_test/c-u-1", epoch, "m", "y");
        r1.state = shard_state::CLEAVED;
        let mut r2 = ShardRange::new(".shards_AUTH_test/c-u-2", epoch, "y", "zzz");
        r2.state = shard_state::CREATED;
        let mut r3 = ShardRange::new(".shards_AUTH_test/c-u-3", epoch, "zzz", "");
        r3.state = shard_state::CREATED;
        source
            .merge_shard_ranges(vec![r0, r1, r2, r3])
            .unwrap();
        source.enable_sharding(epoch).unwrap();
        assert!(source.set_sharding_state().unwrap());

        let finished =
            process_sharding_container(&mut source, &device, &hash_config, "0", 2).unwrap();
        assert!(
            finished,
            "under-populated replica must finish leftover CREATED ranges"
        );
        assert_eq!(source.get_db_state().unwrap(), DbState::Sharded);
        let got = source
            .get_shard_ranges(&GetShardRangesArgs {
                include_own: false,
                ..Default::default()
            })
            .unwrap();
        let states: Vec<i64> = got.iter().map(|r| r.state).collect();
        assert_eq!(
            states,
            vec![
                shard_state::ACTIVE,
                shard_state::ACTIVE,
                shard_state::ACTIVE,
                shard_state::ACTIVE
            ],
            "{got:?}"
        );
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
        let ranges = check
            .get_shard_ranges(&GetShardRangesArgs {
                include_own: false,
                ..GetShardRangesArgs::default()
            })
            .unwrap();
        assert!(
            !ranges.is_empty() && ranges.iter().all(|r| r.state == shard_state::ACTIVE),
            "complete_sharding must promote CLEAVED→ACTIVE, got {ranges:?}"
        );
        let loaded = load_cleaving_context(&mut check).unwrap();
        assert!(
            loaded.done(),
            "probe CleavingContext.load_all/done() requires misplaced_done \
             && cleaving_done && max_row==cleave_to_row, got {loaded:?}"
        );
        let md = check.metadata().unwrap();
        assert!(
            md.iter().any(|(k, (v, _))| {
                k.to_ascii_lowercase()
                    .starts_with("x-container-sysmeta-shard-context-")
                    && !v.is_empty()
            }),
            "expected X-Container-Sysmeta-Shard-Context-{{id}}, got {md:?}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_injected_ranges_start_sharding_below_threshold() {
        // manage-shard-ranges injects ranges with 10 objects; G6 conf
        // shard_container_threshold=100. Python still set_sharding_state.
        let dir = std::env::temp_dir().join(format!("swift-sharder-inject-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut source = container_broker(&dir, "c", 10);
        let epoch = "1751500010.00000";
        find_and_merge_found_ranges(&mut source, "AUTH_test", "c", 5, 1, epoch).unwrap();
        source.enable_sharding(epoch).unwrap();
        assert!(source.has_other_shard_ranges().unwrap());
        let opts = SharderRunOpts {
            cleave_batch_size: 10,
            auto_shard: false,
            auto_shrink: false,
            shard_size: 100,
            rows_per_shard: 0,
            minimum_shard_size: 1,
            partitions: Vec::new(),
        };
        assert!(
            !maybe_auto_shard(&mut source, &opts).unwrap(),
            "threshold 100 must skip auto-find with 10 objects"
        );
        assert!(maybe_start_sharding(&mut source, &opts).unwrap());
        assert_eq!(source.get_db_state().unwrap(), DbState::Sharding);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_replicated_sharded_own_reuses_active_ranges() {
        // Probe test_replication_to_sharded_container L2323: the third node
        // has an UNSHARDED local DB, but replication supplied a SHARDED own
        // range and two ACTIVE children. Reuse those ranges. Auto-finding a
        // new epoch produces four overlapping ranges.
        let dir = std::env::temp_dir().join(format!(
            "swift-sharder-replicated-ranges-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let mut source = container_broker(&dir, "c", 101);
        let epoch = "1751500010.00000";
        let mut own = source.get_own_shard_range(false).unwrap().unwrap();
        own.state = shard_state::SHARDED;
        own.state_timestamp = epoch.into();
        own.epoch = Some(epoch.into());
        let mut first = ShardRange::new(".shards_AUTH_test/c-0", epoch, "", "o0049");
        first.state = shard_state::ACTIVE;
        first.object_count = 50;
        let mut second = ShardRange::new(".shards_AUTH_test/c-1", epoch, "o0049", "");
        second.state = shard_state::ACTIVE;
        second.object_count = 51;
        source
            .merge_shard_ranges(vec![own, first.clone(), second.clone()])
            .unwrap();
        assert_eq!(source.get_db_state().unwrap(), DbState::Unsharded);

        let opts = SharderRunOpts {
            cleave_batch_size: 10,
            auto_shard: true,
            auto_shrink: false,
            shard_size: 100,
            rows_per_shard: 0,
            minimum_shard_size: 1,
            partitions: Vec::new(),
        };
        assert!(maybe_start_sharding(&mut source, &opts).unwrap());
        assert_eq!(source.get_db_state().unwrap(), DbState::Sharding);
        let ranges = source
            .get_shard_ranges(&GetShardRangesArgs {
                include_own: false,
                include_deleted: false,
                ..GetShardRangesArgs::default()
            })
            .unwrap();
        assert_eq!(
            ranges.len(),
            2,
            "must not auto-find a second epoch: {ranges:?}"
        );
        assert_eq!(
            ranges
                .iter()
                .map(|range| range.name.as_str())
                .collect::<Vec<_>>(),
            vec![first.name.as_str(), second.name.as_str()]
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_maybe_start_sharding_skips_epoch_db_with_active_sibling() {
        // After the first shard shrinks away, the leftover sibling is still
        // ACTIVE (tombstones). The root is epoch-backed. Must not create a
        // second epoch (L2088 unsharded / own.epoch mismatch).
        let hash_config = HashPathConfig::new("", "changeme").unwrap();
        let dir = std::env::temp_dir().join(format!(
            "swift-s2r-active-sib-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let device = dir.join("d1");
        let account = "AUTH_test";
        let container = "c";
        let hsh = hash_config
            .hash_path(account, Some(container), None)
            .unwrap();
        let suf = &hsh[hsh.len() - 3..];
        let hd = device.join("containers/0").join(suf).join(&hsh);
        std::fs::create_dir_all(&hd).unwrap();
        let unsuffixed = hd.join(format!("{hsh}.db"));
        let epoch = "1751500010.00000";
        let epoch_path = make_db_file_path(&unsuffixed, Some(epoch)).unwrap();
        let mut root = ContainerBroker::new(&epoch_path, account, container);
        root.initialize("1751500000.00000", 0, "1751500000.00000", "id")
            .unwrap();
        root.put_object(
            "alpha-1",
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
        let mut own = root.get_own_shard_range(false).unwrap().unwrap();
        own.epoch = Some(epoch.to_string());
        own.state = shard_state::SHARDED;
        let mut sibling = ShardRange::new(".shards_AUTH_test/c-1", epoch, "m", "");
        sibling.state = shard_state::ACTIVE;
        sibling.object_count = 1;
        root.merge_shard_ranges(vec![own, sibling]).unwrap();
        assert_eq!(root.get_db_state().unwrap(), DbState::Sharded);
        let files_before = swift_db::get_db_files(&unsuffixed).len();

        let opts = SharderRunOpts {
            cleave_batch_size: 10,
            auto_shard: true,
            auto_shrink: false,
            shard_size: 100,
            rows_per_shard: 0,
            minimum_shard_size: 1,
            partitions: Vec::new(),
        };
        assert!(!maybe_start_sharding(&mut root, &opts).unwrap());
        assert_eq!(root.get_db_state().unwrap(), DbState::Sharded);
        assert_eq!(
            swift_db::get_db_files(&unsuffixed).len(),
            files_before,
            "must not create a second epoch file"
        );
        let after = root.get_own_shard_range(true).unwrap().unwrap();
        assert_eq!(after.epoch.as_deref(), Some(epoch), "{after:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_maybe_start_sharding_preserves_collapsed_root_without_siblings() {
        // Probe L2088 after the last donor is SHRUNK: no other ranges,
        // epoch file, own.epoch wiped, object_count 1. get_db_state already
        // recognizes the collapsed root; maybe_start_sharding must not restart
        // it or create another epoch.
        let hash_config = HashPathConfig::new("", "changeme").unwrap();
        let dir = std::env::temp_dir().join(format!(
            "swift-s2r-heal-collapsed-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let device = dir.join("d1");
        let account = "AUTH_test";
        let container = "c";
        let hsh = hash_config
            .hash_path(account, Some(container), None)
            .unwrap();
        let suf = &hsh[hsh.len() - 3..];
        let hd = device.join("containers/0").join(suf).join(&hsh);
        std::fs::create_dir_all(&hd).unwrap();
        let unsuffixed = hd.join(format!("{hsh}.db"));
        let epoch = "1751500010.00000";
        let epoch_path = make_db_file_path(&unsuffixed, Some(epoch)).unwrap();
        let mut root = ContainerBroker::new(&epoch_path, account, container);
        root.initialize("1751500000.00000", 0, "1751500000.00000", "id")
            .unwrap();
        root.put_object(
            "alpha-1",
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
        let mut own = root.get_own_shard_range(false).unwrap().unwrap();
        own.epoch = None;
        own.state = shard_state::ACTIVE;
        root.merge_shard_ranges(vec![own]).unwrap();
        assert_eq!(root.get_db_state().unwrap(), DbState::Collapsed);

        let opts = SharderRunOpts {
            cleave_batch_size: 10,
            auto_shard: true,
            auto_shrink: false,
            shard_size: 100,
            rows_per_shard: 0,
            minimum_shard_size: 1,
            partitions: Vec::new(),
        };
        assert!(!maybe_start_sharding(&mut root, &opts).unwrap());
        assert_eq!(
            root.get_db_state().unwrap(),
            DbState::Collapsed,
            "L2088: empty-others root must remain collapsed"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_maybe_start_sharding_restores_wiped_own_epoch() {
        // Compactible/merge can persist own without epoch onto an epoch file.
        // get_db_state() recognizes the sibling-backed root as Sharded; the
        // repair still has to restore own.epoch from the DB filename.
        let hash_config = HashPathConfig::new("", "changeme").unwrap();
        let dir = std::env::temp_dir().join(format!(
            "swift-s2r-heal-epoch-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let device = dir.join("d1");
        let account = "AUTH_test";
        let container = "c";
        let hsh = hash_config
            .hash_path(account, Some(container), None)
            .unwrap();
        let suf = &hsh[hsh.len() - 3..];
        let hd = device.join("containers/0").join(suf).join(&hsh);
        std::fs::create_dir_all(&hd).unwrap();
        let unsuffixed = hd.join(format!("{hsh}.db"));
        let epoch = "1751500010.00000";
        let epoch_path = make_db_file_path(&unsuffixed, Some(epoch)).unwrap();
        let mut root = ContainerBroker::new(&epoch_path, account, container);
        root.initialize("1751500000.00000", 0, "1751500000.00000", "id")
            .unwrap();
        root.put_object(
            "alpha-1",
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
        let mut own = root.get_own_shard_range(false).unwrap().unwrap();
        own.epoch = None;
        own.state = shard_state::ACTIVE;
        let mut sibling = ShardRange::new(".shards_AUTH_test/c-1", epoch, "m", "");
        sibling.state = shard_state::ACTIVE;
        root.merge_shard_ranges(vec![own, sibling]).unwrap();
        assert_eq!(root.get_db_state().unwrap(), DbState::Sharded);

        let opts = SharderRunOpts {
            cleave_batch_size: 10,
            auto_shard: true,
            auto_shrink: false,
            shard_size: 100,
            rows_per_shard: 0,
            minimum_shard_size: 1,
            partitions: Vec::new(),
        };
        assert!(!maybe_start_sharding(&mut root, &opts).unwrap());
        let after = root.get_own_shard_range(true).unwrap().unwrap();
        let own_norm = after
            .epoch
            .as_deref()
            .and_then(|e| e.parse::<swift_core::timestamp::Timestamp>().ok())
            .map(|ts| ts.normal());
        let db_norm = epoch
            .parse::<swift_core::timestamp::Timestamp>()
            .ok()
            .map(|ts| ts.normal());
        assert_eq!(own_norm, db_norm, "{after:?}");
        assert_eq!(root.get_db_state().unwrap(), DbState::Sharded);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_shrink_to_root_acceptor_does_not_set_sharding_state() {
        // Probe L2068: root own is the ACTIVE expanded acceptor with a
        // remaining SHRINKING donor range. Must not create an empty epoch DB.
        let dir = std::env::temp_dir().join(format!("swift-sharder-s2r-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut source = container_broker(&dir, "c", 1);
        let ts = swift_core::timestamp::Timestamp::now().internal();
        let mut donor = ShardRange::new(".shards_a/c-0", &ts, "", "m");
        donor.state = shard_state::SHRINKING;
        source.merge_shard_ranges(vec![donor]).unwrap();
        let own = source.get_own_shard_range(false).unwrap().unwrap();
        assert!(
            !swift_db::CLEAVING_STATES.contains(&own.state),
            "acceptor own must not be cleaving, got {}",
            own.state
        );
        assert!(source.has_other_shard_ranges().unwrap());
        let opts = SharderRunOpts {
            cleave_batch_size: 10,
            auto_shard: true,
            auto_shrink: false,
            shard_size: 100,
            rows_per_shard: 0,
            minimum_shard_size: 1,
            partitions: Vec::new(),
        };
        assert!(!maybe_start_sharding(&mut source, &opts).unwrap());
        assert_ne!(source.get_db_state().unwrap(), DbState::Sharding);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_sharded_own_with_donor_does_not_create_empty_epoch() {
        // Probe L2088: SHARDED root own + remaining SHRINKING donor.
        // Epoch on own would let set_sharding_state succeed and leave
        // db_state=sharding / object_count=0.
        let dir =
            std::env::temp_dir().join(format!("swift-sharder-s2r-sharded-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut source = container_broker(&dir, "c", 1);
        let ts = swift_core::timestamp::Timestamp::now().internal();
        let mut own = source.get_own_shard_range(false).unwrap().unwrap();
        own.state = shard_state::SHARDED;
        own.epoch = Some(ts.clone());
        source.merge_shard_ranges(vec![own]).unwrap();
        let mut donor = ShardRange::new(".shards_a/c-0", &ts, "", "m");
        donor.state = shard_state::SHRINKING;
        source.merge_shard_ranges(vec![donor]).unwrap();
        let opts = SharderRunOpts {
            cleave_batch_size: 10,
            auto_shard: true,
            auto_shrink: false,
            shard_size: 100,
            rows_per_shard: 0,
            minimum_shard_size: 1,
            partitions: Vec::new(),
        };
        assert!(!maybe_start_sharding(&mut source, &opts).unwrap());
        assert_ne!(source.get_db_state().unwrap(), DbState::Sharding);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_local_shard_broker_does_not_create_unsuffixed_beside_epoch() {
        // Probe L2088: shrink-to-root acceptor is the SHARDED root
        // (`hash_<epoch>.db`). Python `create_broker(epoch=own.epoch)` opens
        // that file. Initializing unsuffixed `hash.db` makes db_state=SHARDING
        // with empty retiring (HEAD 0, GET []).
        let hash_config = HashPathConfig::new("", "changeme").unwrap();
        let dir = std::env::temp_dir().join(format!("swift-s2r-epoch-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let device = dir.join("d1");
        let account = "AUTH_test";
        let container = "c";
        let hsh = hash_config
            .hash_path(account, Some(container), None)
            .unwrap();
        let suf = &hsh[hsh.len() - 3..];
        let hd = device.join("containers/0").join(suf).join(&hsh);
        std::fs::create_dir_all(&hd).unwrap();
        let unsuffixed = hd.join(format!("{hsh}.db"));
        let epoch = "1751500010.00000";
        // Objects live in the epoch file (Python create_broker(epoch=)).
        // set_sharding_state copies metadata only — putting rows on the
        // unsuffixed file then unlinking it would leave an empty epoch.
        let epoch_path = make_db_file_path(&unsuffixed, Some(epoch)).unwrap();
        let mut root = ContainerBroker::new(&epoch_path, account, container);
        root.initialize("1751500000.00000", 0, "1751500000.00000", "id")
            .unwrap();
        root.put_object(
            "alpha-1",
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
        let mut own = root.get_own_shard_range(false).unwrap().unwrap();
        own.epoch = Some(epoch.to_string());
        own.state = shard_state::SHARDED;
        root.merge_shard_ranges(vec![own]).unwrap();
        assert!(
            !unsuffixed.exists(),
            "collapsed root has no unsuffixed file"
        );
        assert_eq!(root.get_db_state().unwrap(), DbState::Collapsed);
        drop(root);

        let name = format!("{account}/{container}");
        let mut opened =
            open_or_create_shard_broker(&device, &hash_config, "0", &name, Some(epoch));
        assert!(
            !unsuffixed.exists(),
            "must not create unsuffixed sidecar beside epoch"
        );
        assert_eq!(opened.get_db_state().unwrap(), DbState::Collapsed);
        assert_eq!(get_db_files(&unsuffixed).len(), 1);
        let names: Vec<String> = opened
            .object_records_in_range("", "")
            .unwrap()
            .into_iter()
            .filter(|r| r.deleted == 0)
            .map(|r| r.name)
            .collect();
        assert_eq!(names, vec!["alpha-1".to_string()]);
        // epoch=None must still open the freshest file, not initialize hash.db
        let mut opened_none = open_or_create_shard_broker(&device, &hash_config, "0", &name, None);
        assert!(
            !unsuffixed.exists(),
            "epoch=None must not initialize unsuffixed beside epoch"
        );
        assert_eq!(opened_none.get_db_state().unwrap(), DbState::Collapsed);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_cleaving_done_does_not_recopy_retiring_onto_active_acceptor() {
        // Probe L2044: leftover SHARDING epoch + retiring still holding
        // first-shard PUT rows must not merge them onto the ACTIVE acceptor.
        let hash_config = HashPathConfig::new("", "changeme").unwrap();
        let dir = std::env::temp_dir().join(format!("swift-cleave-done-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let device = dir.join("d1");
        let account = "AUTH_test";
        let container = "c";
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
        source
            .put_object(
                "obj-1-000",
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
        source
            .put_object(
                "alpha-1",
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
        let epoch = "1751500010.00000";
        source.enable_sharding(epoch).unwrap();
        assert!(source.set_sharding_state().unwrap());
        let ts = "1751500011.00000";
        let mut acc = ShardRange::new(".shards_a/c-1", ts, "", "");
        acc.state = shard_state::ACTIVE;
        acc.object_count = 1;
        source.merge_shard_ranges(vec![acc.clone()]).unwrap();
        let spart = "0";
        let mut shard = local_shard_broker(&device, &hash_config, spart, &acc.name);
        shard
            .put_object(
                "alpha-1",
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
        let mut ctx = CleavingContext::default();
        ctx.cleaving_done = true;
        ctx.misplaced_done = true;
        ctx.max_row = broker_max_row_retiring(&mut source);
        ctx.cleave_to_row = ctx.max_row;
        ctx.ref_id = broker_cleaving_ref(&mut source);
        save_cleaving_context(&mut source, &ctx, "1751500012.00000").unwrap();
        let _ = process_sharding_container(&mut source, &device, &hash_config, "0", 10).unwrap();
        let names: Vec<String> = shard
            .object_records_in_range("", "")
            .unwrap()
            .into_iter()
            .filter(|r| r.deleted == 0)
            .map(|r| r.name)
            .collect();
        assert_eq!(
            names,
            vec!["alpha-1".to_string()],
            "L2044 recopy resurrected {names:?}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_active_full_cover_does_not_recopy_without_cleaving_done() {
        // listing-w207: leftover SHARDING root with no done() context
        // recopied retiring obj-1-000 onto the expanded ACTIVE acceptor.
        let hash_config = HashPathConfig::new("", "changeme").unwrap();
        let dir = std::env::temp_dir().join(format!("swift-cleave-active-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let device = dir.join("d1");
        let account = "AUTH_test";
        let container = "c";
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
        source
            .put_object(
                "obj-1-000",
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
        let epoch = "1751500010.00000";
        source.enable_sharding(epoch).unwrap();
        assert!(source.set_sharding_state().unwrap());
        let ts = "1751500011.00000";
        let mut acc = ShardRange::new(".shards_a/c-1", ts, "", "");
        acc.state = shard_state::ACTIVE;
        acc.object_count = 1;
        source.merge_shard_ranges(vec![acc.clone()]).unwrap();
        let mut shard = local_shard_broker(&device, &hash_config, "0", &acc.name);
        shard
            .put_object(
                "alpha-1",
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
        let _ = process_sharding_container(&mut source, &device, &hash_config, "0", 10).unwrap();
        let names: Vec<String> = shard
            .object_records_in_range("", "")
            .unwrap()
            .into_iter()
            .filter(|r| r.deleted == 0)
            .map(|r| r.name)
            .collect();
        assert_eq!(
            names,
            vec!["alpha-1".to_string()],
            "L2044 recopy without context resurrected {names:?}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_cleaving_context_roundtrip() {
        let ctx = CleavingContext {
            cursor: "o0002".into(),
            ranges_done: 2,
            ranges_todo: 4,
            cleaving_done: false,
            ..CleavingContext::default()
        };
        let json = ctx.to_json();
        assert!(json.contains("\"misplaced_done\":false"));
        assert!(json.contains("\"last_cleave_to_row\":null"));
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
            misplaced_done: true,
            max_row: 2,
            cleave_to_row: 2,
            ..CleavingContext::default()
        };
        save_cleaving_context(&mut source, &ctx, "1751500010.00000").unwrap();
        let loaded = load_cleaving_context(&mut source).unwrap();
        assert_eq!(loaded.cursor, "o0000");
        assert_eq!(loaded.ranges_done, 1);
        assert_eq!(loaded.misplaced_done, true);
        assert_eq!(loaded.max_row, loaded.cleave_to_row);
        assert!(
            !loaded.done(),
            "cleaving_done still false so done() must be false: {loaded:?}"
        );
        let md = source.metadata().unwrap();
        let id = source
            .get_info()
            .unwrap()
            .into_iter()
            .find(|(k, _)| k == "id")
            .and_then(|(_, v)| v.as_text())
            .unwrap_or_default();
        assert!(
            md.iter().any(|(k, (v, _))| {
                is_cleaving_context_key(k)
                    && k.eq_ignore_ascii_case(&cleaving_context_sysmeta_key(&id))
                    && !v.is_empty()
            }),
            "expected Python Context-{{id}} sysmeta, got {md:?}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_load_all_merges_three_retiring_context_keys() {
        // Probe L1261: after replicators.once() the third replica's
        // CleavingContext.load_all must see one Context-{retiring_id} per
        // replica. Using the fresh DB id (was hardcoded "shardid") collapsed
        // all three writes onto one sysmeta key.
        let dir = std::env::temp_dir().join(format!("swift-ctx-merge-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let epoch = "1751500010.00000";
        let mut retiring_ids = Vec::new();
        let mut contexts_md = Vec::new();
        for (i, id) in ["id-a", "id-b", "id-c"].iter().enumerate() {
            let hd = dir.join(format!("r{i}"));
            std::fs::create_dir_all(&hd).unwrap();
            let db = hd.join(format!("{:0>32}.db", i));
            let mut b = ContainerBroker::new(&db, "AUTH_test", "c");
            b.initialize("1751500000.00000", 0, "1751500000.00000", id)
                .unwrap();
            let mut own = ShardRange::new("AUTH_test/c", epoch, "", "");
            own.state = shard_state::SHARDING;
            own.epoch = Some(epoch.into());
            b.merge_shard_ranges(vec![own]).unwrap();
            assert!(b.set_sharding_state().unwrap());
            let retiring = broker_cleaving_ref(&mut b);
            assert_eq!(retiring, *id, "ref must be retiring id, not fresh");
            let fresh = broker_db_id(&mut b);
            assert_ne!(fresh, retiring, "fresh epoch DB must get a new id");
            let ctx = CleavingContext {
                ref_id: retiring.clone(),
                cursor: format!("c{i}"),
                ranges_done: i + 1,
                ranges_todo: 3 - (i + 1),
                misplaced_done: true,
                max_row: 150,
                cleave_to_row: 150,
                ..CleavingContext::default()
            };
            save_cleaving_context(&mut b, &ctx, &format!("175150001{i}.00000")).unwrap();
            retiring_ids.push(retiring);
            contexts_md.extend(
                b.metadata()
                    .unwrap()
                    .into_iter()
                    .filter(|(k, (v, _))| is_cleaving_context_key(k) && !v.is_empty()),
            );
        }
        // Replicator merge: timestamp-wins per key, never drop a distinct
        // Context-* key (probe third replica after replicators.once()).
        let hd = dir.join("merged");
        std::fs::create_dir_all(&hd).unwrap();
        let db = hd.join(format!("{:0>32}.db", 9));
        let mut merged = ContainerBroker::new(&db, "AUTH_test", "c");
        merged
            .initialize("1751500000.00000", 0, "1751500000.00000", "id-c")
            .unwrap();
        merged.update_metadata(&contexts_md).unwrap();
        let loaded = load_all_cleaving_contexts(&mut merged).unwrap();
        assert_eq!(
            loaded.len(),
            3,
            "replicator merge must keep 3 Context keys, got {loaded:?}"
        );
        let refs: Vec<_> = loaded.iter().map(|(c, _)| c.ref_id.as_str()).collect();
        for id in &retiring_ids {
            assert!(
                refs.contains(&id.as_str()),
                "missing Context-{id}: {refs:?}"
            );
        }

        // Python `CleavingContext.load` uses only Context-{retiring_id}.
        // A peer's done context must not skip local remaining cleave (L1517).
        let mut peer_done = CleavingContext {
            ref_id: retiring_ids[0].clone(),
            cursor: "".into(),
            ranges_done: 4,
            ranges_todo: 0,
            cleaving_done: true,
            misplaced_done: true,
            max_row: 1,
            cleave_to_row: 1,
            ..CleavingContext::default()
        };
        peer_done.cursor = "obj-0398".into();
        save_cleaving_context(&mut merged, &peer_done, "1751500099.00000").unwrap();
        // Own retiring id is id-c; its in-progress context must win.
        let own = CleavingContext {
            ref_id: "id-c".into(),
            cursor: "obj-0098".into(),
            ranges_done: 2,
            ranges_todo: 2,
            cleaving_done: false,
            misplaced_done: true,
            max_row: 200,
            cleave_to_row: 200,
            ..CleavingContext::default()
        };
        save_cleaving_context(&mut merged, &own, "1751500020.00000").unwrap();
        let loaded = load_cleaving_context(&mut merged).unwrap();
        assert_eq!(loaded.ref_id, "id-c", "{loaded:?}");
        assert!(
            !loaded.cleaving_done,
            "must not adopt peer done context: {loaded:?}"
        );
        assert_eq!(loaded.cursor, "obj-0098", "{loaded:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_load_cleaving_context_ignores_peer_done_without_own_key() {
        // L1517: node 1 is still SHARDING; only a peer's finished Context-*
        // is present. Start fresh — do not skip remaining retiring rows.
        let dir = std::env::temp_dir().join(format!("swift-ctx-peer-only-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join(format!("{:0>32}.db", 1));
        let mut b = ContainerBroker::new(&db, "AUTH_test", "c");
        b.initialize("1751500000.00000", 0, "1751500000.00000", "id-local")
            .unwrap();
        let epoch = "1751500010.00000";
        let mut own = ShardRange::new("AUTH_test/c", epoch, "", "");
        own.state = shard_state::SHARDING;
        own.epoch = Some(epoch.into());
        b.merge_shard_ranges(vec![own]).unwrap();
        b.enable_sharding(epoch).unwrap();
        assert!(b.set_sharding_state().unwrap());
        assert_eq!(b.get_db_state().unwrap(), DbState::Sharding);
        let peer = CleavingContext {
            ref_id: "id-peer".into(),
            cursor: "obj-0398".into(),
            ranges_done: 4,
            ranges_todo: 0,
            cleaving_done: true,
            misplaced_done: true,
            max_row: 1,
            cleave_to_row: 1,
            ..CleavingContext::default()
        };
        save_cleaving_context(&mut b, &peer, "1751500099.00000").unwrap();
        let loaded = load_cleaving_context(&mut b).unwrap();
        assert!(
            !loaded.cleaving_done,
            "peer-only done context must not load while SHARDING: {loaded:?}"
        );
        assert!(loaded.cursor.is_empty(), "{loaded:?}");
        // Unsharded (no retiring file) must also ignore a peer Context-*.
        let db2 = dir.join(format!("{:0>32}.db", 2));
        let mut fresh = ContainerBroker::new(&db2, "AUTH_test", "c");
        fresh
            .initialize("1751500000.00000", 0, "1751500000.00000", "id-unsharded")
            .unwrap();
        save_cleaving_context(&mut fresh, &peer, "1751500099.00000").unwrap();
        let loaded = load_cleaving_context(&mut fresh).unwrap();
        assert!(
            !loaded.cleaving_done,
            "unsharded must not adopt peer done: {loaded:?}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_refresh_own_shard_range_stats_from_live_objects() {
        let dir =
            std::env::temp_dir().join(format!("swift-sharder-rootupd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut shard = container_broker(&dir, "c", 10);
        let ts = "1751500010.00000";
        let mut own = ShardRange::new("AUTH_test/c", ts, "", "");
        own.state = shard_state::ACTIVE;
        ensure_shard_root_sysmeta(&mut shard, "AUTH_test", "rootc", &own);
        let refreshed = refresh_own_shard_range_stats(&mut shard)
            .unwrap()
            .expect("own range");
        assert_eq!(refreshed.object_count, 10, "{refreshed:?}");
        assert!(!shard.is_root_container().unwrap());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn refresh_own_keeps_reported_when_counts_unchanged() {
        // Probe L1157: lagging replica still at 10 objects, already reported.
        // Must not clear the latch or bump meta (that would stomp a newer
        // 20-object report already on the root).
        let dir =
            std::env::temp_dir().join(format!("swift-sharder-reported-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut shard = container_broker(&dir, "c", 10);
        let ts = "1751500010.00000";
        let mut own = ShardRange::new("AUTH_test/c", ts, "", "");
        own.state = shard_state::ACTIVE;
        own.object_count = 10;
        own.bytes_used = 10;
        own.reported = 1;
        own.meta_timestamp = ts.to_string();
        ensure_shard_root_sysmeta(&mut shard, "AUTH_test", "rootc", &own);
        shard.merge_shard_ranges(vec![own.clone()]).unwrap();
        let refreshed = refresh_own_shard_range_stats(&mut shard)
            .unwrap()
            .expect("own range");
        assert_eq!(refreshed.object_count, 10, "{refreshed:?}");
        assert_eq!(refreshed.reported, 1, "latch must stay set: {refreshed:?}");
        assert_eq!(
            refreshed.meta_timestamp, ts,
            "unchanged stats must not bump meta_timestamp"
        );
        assert_eq!(
            update_root_container(&mut shard, None).unwrap(),
            true,
            "reported latch skips send"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn refresh_own_clears_reported_when_counts_grow() {
        let dir = std::env::temp_dir().join(format!(
            "swift-sharder-reported-grow-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let mut shard = container_broker(&dir, "c", 10);
        let ts = "1751500010.00000";
        let mut own = ShardRange::new("AUTH_test/c", ts, "", "");
        own.state = shard_state::ACTIVE;
        own.object_count = 5;
        own.bytes_used = 5;
        own.reported = 1;
        own.meta_timestamp = ts.to_string();
        ensure_shard_root_sysmeta(&mut shard, "AUTH_test", "rootc", &own);
        shard.merge_shard_ranges(vec![own]).unwrap();
        let refreshed = refresh_own_shard_range_stats(&mut shard)
            .unwrap()
            .expect("own range");
        assert_eq!(refreshed.object_count, 10, "{refreshed:?}");
        assert_eq!(refreshed.reported, 0, "growth must clear latch");
        assert_ne!(refreshed.meta_timestamp, ts);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn nested_child_quoted_root_is_true_root_not_parent() {
        // Probe L1435: first-gen parent is itself a shard of AUTH_test/rootc.
        // Nested children must stamp Quoted-Root as AUTH_test/rootc, not the
        // parent `.shards_AUTH_test/c-0`, so update_root_container hits the
        // listing HEAD.
        let dir =
            std::env::temp_dir().join(format!("swift-sharder-nested-root-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut parent = container_broker(&dir, "c-0", 0);
        let ts = "1751500010.00000";
        let mut own = ShardRange::new(".shards_AUTH_test/c-0", ts, "", "m");
        own.state = shard_state::SHARDING;
        ensure_shard_root_sysmeta(&mut parent, "AUTH_test", "rootc", &own);
        let (ra, rc) = true_root_account_container(&mut parent, ".shards_AUTH_test", "c-0");
        assert_eq!(
            (ra.as_str(), rc.as_str()),
            ("AUTH_test", "rootc"),
            "parent root_path must be the true root"
        );
        let mut child = container_broker(&dir.join("child"), "c-0-0", 0);
        let mut child_own = ShardRange::new(".shards_AUTH_test/c-0-0", ts, "", "g");
        child_own.state = shard_state::ACTIVE;
        ensure_shard_root_sysmeta(&mut child, &ra, &rc, &child_own);
        assert_eq!(
            root_account_container(&mut child),
            Some(("AUTH_test".into(), "rootc".into())),
            "nested child Quoted-Root must be AUTH_test/rootc"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_find_and_enable_sharding_candidates_marks_oversized_active() {
        let dir =
            std::env::temp_dir().join(format!("swift-sharder-candidates-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut b = container_broker(&dir, "c", 0);
        let epoch = "1751500010.00000";
        b.enable_sharding(epoch).unwrap();
        let mut s1 = ShardRange::new(".shards_AUTH_test/c-0", epoch, "", "m");
        s1.state = shard_state::ACTIVE;
        s1.object_count = 150;
        let mut s2 = ShardRange::new(".shards_AUTH_test/c-1", epoch, "m", "");
        s2.state = shard_state::ACTIVE;
        s2.object_count = 50;
        b.merge_shard_ranges(vec![s1, s2]).unwrap();
        assert!(b.set_sharding_state().unwrap());
        assert!(b.set_sharded_state().unwrap());
        find_and_enable_sharding_candidates(&mut b, 100, None);
        let got = b.get_shard_ranges(&GetShardRangesArgs::default()).unwrap();
        assert_eq!(got.len(), 2, "{got:?}");
        assert_eq!(got[0].state, shard_state::SHARDING, "{got:?}");
        assert_eq!(got[1].state, shard_state::ACTIVE, "{got:?}");
        assert!(got[0].epoch.is_some(), "{got:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_merge_shard_ranges_from_root_promotes_own_and_children() {
        // Probe L1245: third replica still ACTIVE locally; root has SHARDING
        // plus three sub-shards. Audit merge must land all of that.
        let dir = std::env::temp_dir().join(format!("swift-sharder-audit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut shard = container_broker(&dir, "c-0", 0);
        let ts = "1751500010.00000";
        let mut own = ShardRange::new("AUTH_test/c-0", ts, "", "m");
        own.state = shard_state::ACTIVE;
        own.object_count = 150;
        ensure_shard_root_sysmeta(&mut shard, "AUTH_test", "rootc", &own);
        assert_eq!(
            shard.get_own_shard_range(true).unwrap().unwrap().state,
            shard_state::ACTIVE
        );

        let mut from_root = own.clone();
        from_root.state = shard_state::SHARDING;
        from_root.state_timestamp = "1751500099.00000".into();
        from_root.epoch = Some("1751500099.00000".into());
        let mut c0 = ShardRange::new(".shards_AUTH_test/c-0-0", ts, "", "g");
        c0.state = shard_state::CLEAVED;
        let mut c1 = ShardRange::new(".shards_AUTH_test/c-0-1", ts, "g", "m");
        c1.state = shard_state::CLEAVED;
        let mut sibling = ShardRange::new(".shards_AUTH_test/c-1", ts, "m", "");
        sibling.state = shard_state::ACTIVE;
        merge_shard_ranges_from_root(&mut shard, &[from_root, c0, c1, sibling], &own);
        let got_own = shard.get_own_shard_range(true).unwrap().unwrap();
        assert_eq!(got_own.state, shard_state::SHARDING, "{got_own:?}");
        let others = shard
            .get_shard_ranges(&GetShardRangesArgs::default())
            .unwrap();
        let names: Vec<_> = others.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&".shards_AUTH_test/c-0-0"), "{names:?}");
        assert!(names.contains(&".shards_AUTH_test/c-0-1"), "{names:?}");
        assert!(
            !names.contains(&".shards_AUTH_test/c-1"),
            "sibling must not merge into this shard: {names:?}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_get_shard_ranges_sends_auditing_query() {
        use std::io::Read;
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .ok();
            let mut buf = Vec::new();
            let mut tmp = [0u8; 512];
            loop {
                match stream.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => {
                        buf.extend_from_slice(&tmp[..n]);
                        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            String::from_utf8_lossy(&buf).into_owned()
        });
        let node = ShardReplicaNode {
            ip: "127.0.0.1".into(),
            port: addr.port(),
            device: "sdb1".into(),
        };
        let _ = get_shard_ranges_body(
            &node,
            "42",
            "AUTH_test",
            "rootc",
            "format=json&states=auditing&marker=a&end_marker=m",
        );
        let req = handle.join().unwrap();
        assert!(req.starts_with("GET /sdb1/42/AUTH_test/rootc?"), "{req}");
        assert!(req.contains("states=auditing"), "{req}");
        assert!(req.contains("X-Backend-Record-Type: shard"), "{req}");
        assert!(req.contains("X-Backend-Include-Deleted: true"), "{req}");
    }

    #[test]
    fn test_put_container_with_meta_sends_quoted_root() {
        use std::io::Read;
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .ok();
            let mut buf = Vec::new();
            let mut tmp = [0u8; 512];
            loop {
                match stream.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => {
                        buf.extend_from_slice(&tmp[..n]);
                        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            String::from_utf8_lossy(&buf).into_owned()
        });
        let mut t = TcpShardHttpTransport::new();
        let node = ShardReplicaNode {
            ip: "127.0.0.1".into(),
            port: addr.port(),
            device: "sdb1".into(),
        };
        let extra = [
            ("X-Backend-Auto-Create", "True"),
            ("X-Container-Sysmeta-Shard-Quoted-Root", "AUTH_test%2Frootc"),
            ("X-Container-Sysmeta-Sharding", "True"),
        ];
        let _ = t.put_container_with_meta(
            &node,
            "42",
            ".shards_AUTH_test",
            "c-0",
            "1751500010.00000",
            &extra,
        );
        let req = handle.join().unwrap();
        assert!(
            req.contains("X-Container-Sysmeta-Shard-Quoted-Root: AUTH_test%2Frootc"),
            "{req}"
        );
        assert!(req.contains("X-Container-Sysmeta-Sharding: True"), "{req}");
        assert!(req.contains("X-Backend-Auto-Create: True"), "{req}");
        assert!(req.contains("PUT /sdb1/42/.shards_AUTH_test/c-0 "), "{req}");
    }

    #[test]
    fn test_devices_root_rsync_stages_into_peer_tmp() {
        let dir = std::env::temp_dir().join(format!("swift-sharder-rsync-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let src = dir.join("src.db");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&src, b"cleaved-shard-db").unwrap();
        let t = DevicesRootRsync {
            local_device: dir.join("sdb1"),
        };
        assert!(t.rsync(&src, "192.168.0.2:6201", "sdb2", "local-id"));
        let staged = dir.join("sdb2/tmp/local-id");
        assert_eq!(std::fs::read(&staged).unwrap(), b"cleaved-shard-db");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_replicate_broker_to_ring_peers_noop_without_ring() {
        let dir =
            std::env::temp_dir().join(format!("swift-sharder-replnone-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut shard = container_broker(&dir, "c", 2);
        let hash_config = HashPathConfig::new("", "changeme").unwrap();
        assert_eq!(
            replicate_broker_to_ring_peers(&mut shard, &hash_config, None, "sdb1", None, false,),
            0
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_handoff_cleanup_requires_complete_stable_non_sharding_copy() {
        assert!(should_cleanup_replicated_handoff(
            true,
            false,
            3,
            3,
            0,
            Some(50),
            Some(50),
            false,
        ));
        for unsafe_case in [
            should_cleanup_replicated_handoff(true, true, 2, 2, 0, Some(50), Some(50), false),
            should_cleanup_replicated_handoff(true, false, 3, 2, 0, Some(50), Some(50), false),
            should_cleanup_replicated_handoff(true, false, 3, 3, 1, Some(50), Some(50), false),
            should_cleanup_replicated_handoff(true, false, 3, 3, 0, Some(50), Some(51), false),
            should_cleanup_replicated_handoff(true, false, 3, 3, 0, Some(50), Some(50), true),
        ] {
            assert!(!unsafe_case);
        }
    }

    #[test]
    fn test_peer_devices_root_maps_saio_loopback() {
        let local = std::path::Path::new("/srv/1/node/sdb1");
        assert_eq!(
            peer_devices_root(local, "127.0.0.2"),
            std::path::PathBuf::from("/srv/2/node")
        );
        assert_eq!(
            peer_devices_root(local, "127.0.0.4"),
            std::path::PathBuf::from("/srv/4/node")
        );
        assert_eq!(
            peer_devices_root(local, "10.0.0.9"),
            std::path::PathBuf::from("/srv/1/node")
        );
    }

    #[test]
    fn test_http_path_seg_encodes_utf8() {
        let s = http_path_seg("caf\u{e9}");
        assert!(s.contains('%'), "{s}");
        assert!(!s.contains('\u{e9}'), "{s}");
        assert_eq!(http_path_seg("sdb1"), "sdb1");
    }

    #[test]
    fn test_http_quote_encodes_utf8_keeps_slash() {
        assert_eq!(http_quote("AUTH_test/caf\u{e9}"), "AUTH_test/caf%C3%A9");
        assert_eq!(http_quote("AUTH_test/rootc"), "AUTH_test/rootc");
        assert!(!http_quote("AUTH_test/caf\u{e9}").contains('\u{e9}'));
    }

    #[test]
    fn test_ensure_shard_root_sysmeta_stores_utf8_root_quoted() {
        let dir = std::env::temp_dir().join(format!(
            "swift-sharder-quoted-root-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let mut shard = container_broker(&dir, "shard-0", 0);
        let own = ShardRange::new(
            ".shards_AUTH_test/shard-0",
            "1751500010.00000",
            "",
            "",
        );

        ensure_shard_root_sysmeta(&mut shard, "AUTH_test", "café-ሴ", &own);

        let metadata = shard.metadata().unwrap();
        let quoted = metadata
            .iter()
            .find(|(key, _)| {
                key.eq_ignore_ascii_case("X-Container-Sysmeta-Shard-Quoted-Root")
            })
            .map(|(_, (value, _))| value.as_str());
        assert_eq!(quoted, Some("AUTH_test/caf%C3%A9-%E1%88%B4"));
        assert_eq!(
            root_account_container(&mut shard),
            Some(("AUTH_test".into(), "café-ሴ".into()))
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_put_shard_ranges_sends_json_and_quoted_root() {
        use std::io::Read;
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .ok();
            let mut buf = Vec::new();
            let mut tmp = [0u8; 1024];
            loop {
                match stream.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => {
                        buf.extend_from_slice(&tmp[..n]);
                        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                            // wait for body
                            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                                let head = String::from_utf8_lossy(&buf[..pos]);
                                if let Some(cl) = head
                                    .lines()
                                    .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
                                    .and_then(|l| l.split(':').nth(1))
                                    .and_then(|s| s.trim().parse::<usize>().ok())
                                {
                                    let body_start = pos + 4;
                                    if buf.len() >= body_start + cl {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
            String::from_utf8_lossy(&buf).into_owned()
        });
        let node = ShardReplicaNode {
            ip: "127.0.0.1".into(),
            port: addr.port(),
            device: "sdb1".into(),
        };
        let mut sr = ShardRange::new(".shards_AUTH_test/caf\u{e9}-0", "1751500010.00000", "", "m");
        sr.state = shard_state::CREATED;
        let quoted = http_quote("AUTH_test/caf\u{e9}");
        let extra = [
            ("X-Backend-Auto-Create", "True"),
            ("X-Container-Sysmeta-Shard-Quoted-Root", quoted.as_str()),
            ("X-Container-Sysmeta-Sharding", "True"),
        ];
        let body = shard_ranges_json(std::slice::from_ref(&sr));
        let _ = put_shard_ranges_body(
            &node,
            "42",
            ".shards_AUTH_test",
            "caf\u{e9}-0",
            "1751500010.00000",
            &body,
            &extra,
        );
        let req = handle.join().unwrap();
        let head = req.split("\r\n\r\n").next().unwrap_or(&req);
        assert!(head.contains("X-Backend-Record-Type: shard"), "{req}");
        assert!(
            head.contains("X-Container-Sysmeta-Shard-Quoted-Root: AUTH_test/caf%C3%A9"),
            "{req}"
        );
        assert!(
            !head.contains('\u{e9}'),
            "raw UTF-8 must not appear in headers: {head}"
        );
        assert!(
            req.contains("\"state\":20") || req.contains("\"state\": 20"),
            "{req}"
        );
        assert!(
            req.contains("PUT /sdb1/42/.shards_AUTH_test/caf%C3%A9-0 "),
            "{req}"
        );
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
            rows_per_shard: 0,
            minimum_shard_size: 1,
            partitions: Vec::new(),
        };
        assert!(maybe_auto_shard(&mut source, &opts).unwrap());
        assert_eq!(source.get_db_state().unwrap(), DbState::Sharding);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_probe_threshold_100_persists_two_shard_ranges() {
        // G6 probe: shard_container_threshold=100, rows_per_shard=50,
        // minimum_shard_size=10, 100 objects → 2 ranges (was 0 with
        // hardcoded minimum 100000).
        let dir = std::env::temp_dir().join(format!("swift-sharder-g6-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut source = container_broker(&dir, "c", 100);
        let opts = SharderRunOpts {
            cleave_batch_size: 2,
            auto_shard: true,
            auto_shrink: false,
            shard_size: 100,
            rows_per_shard: 50,
            minimum_shard_size: 10,
            partitions: Vec::new(),
        };
        assert!(maybe_auto_shard(&mut source, &opts).unwrap());
        let ranges = source
            .get_shard_ranges(&GetShardRangesArgs::default())
            .unwrap();
        assert_eq!(
            ranges.len(),
            2,
            "expected 2 shard ranges for 100 objects / 50 rows: {ranges:?}"
        );
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

    #[test]
    fn test_move_misplaced_from_sharded_live_table_into_owner() {
        // Probe L2761: SHARDED donor live table holds a late "alpha"; the
        // covering ACTIVE acceptor must receive it and the donor must drop it.
        let hash_config = HashPathConfig::new("", "changeme").unwrap();
        let dir = std::env::temp_dir().join(format!(
            "swift-sharder-mis-live-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let device = dir.join("d1");
        let account = "AUTH_test";
        let container = "shrunk-donor";
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
        source
            .put_object(
                "seed",
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
        let epoch = "1751500010.00000";
        let dest = {
            let mut sr = ShardRange::new(".shards_AUTH_test/c-hi", epoch, "", "");
            sr.state = shard_state::ACTIVE;
            sr
        };
        source.merge_shard_ranges(vec![dest.clone()]).unwrap();
        source.enable_sharding(epoch).unwrap();
        assert!(source.set_sharding_state().unwrap());
        assert!(source.set_sharded_state().unwrap());
        assert_eq!(source.get_db_state().unwrap(), DbState::Sharded);
        source
            .put_object(
                "alpha",
                "1751500020.00000",
                0,
                "text/plain",
                "misplaced",
                0,
                0,
                None,
                None,
            )
            .unwrap();
        let moved =
            move_misplaced_from_live(&mut source, &device, &hash_config, "0", None).unwrap();
        assert_eq!(moved, 1, "expected alpha moved from SHARDED live table");
        let leftover = source
            .object_records_in_range("", "")
            .unwrap()
            .into_iter()
            .map(|r| r.name)
            .collect::<Vec<_>>();
        assert!(
            !leftover.iter().any(|n| n == "alpha"),
            "donor must drop alpha, leftover={leftover:?}"
        );
        let mut dest_b = local_shard_broker(&device, &hash_config, "0", &dest.name);
        let dest_names = dest_b
            .object_records_in_range("", "")
            .unwrap()
            .into_iter()
            .map(|r| (r.name, r.deleted, r.etag))
            .collect::<Vec<_>>();
        assert!(
            dest_names
                .iter()
                .any(|(n, d, e)| n == "alpha" && *d == 0 && e == "misplaced"),
            "acceptor must have live alpha, got {dest_names:?}"
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
            rows_per_shard: 0,
            minimum_shard_size: 1,
            partitions: Vec::new(),
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
            rows_per_shard: 0,
            minimum_shard_size: 1,
            partitions: Vec::new(),
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
    fn test_run_once_restarts_sharding_from_collapsed_root() {
        // Official probe test_shrinking runs the entire shard/shrink cycle a
        // second time from a deleted, revived COLLAPSED root. Python handles
        // COLLAPSED beside UNSHARDED: enabling the new own-range epoch makes
        // the old epoch DB the retiring file, then set_sharding_state creates
        // the new fresh DB. Skipping COLLAPSED left replicas permanently in
        // `X-Backend-Sharding-State: collapsed` at probe L1854.
        let hash_config = HashPathConfig::new("", "changeme").unwrap();
        let dir = std::env::temp_dir().join(format!(
            "swift-sharder-collapsed-restart-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let device = dir.join("d1");
        let account = "AUTH_test";
        let container = "collapsed-root";
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
        source.enable_sharding("1751500010.00000").unwrap();
        assert!(source.set_sharding_state().unwrap());
        for i in 0..10 {
            source
                .put_object(
                    &format!("o{i:04}"),
                    "1751500011.00000",
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
        assert!(source.set_sharded_state().unwrap());
        assert_eq!(source.get_db_state().unwrap(), DbState::Collapsed);
        drop(source);

        let opts = SharderRunOpts {
            cleave_batch_size: 10,
            auto_shard: true,
            auto_shrink: true,
            shard_size: 5,
            rows_per_shard: 0,
            minimum_shard_size: 1,
            partitions: Vec::new(),
        };
        let stats = run_once_with_opts(&device, &hash_config, &opts);
        assert_eq!(stats.failures, 0, "{stats:?}");
        assert!(stats.sharding >= 1 || stats.finished >= 1, "{stats:?}");
        let mut check = ContainerBroker::new(&db, account, container);
        assert!(
            matches!(
                check.get_db_state().unwrap(),
                DbState::Sharding | DbState::Sharded
            ),
            "collapsed root was skipped: {stats:?}"
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
            rows_per_shard: 0,
            minimum_shard_size: 1,
            partitions: Vec::new(),
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
    fn test_only_ring_index_zero_is_local_sharder_leader() {
        use swift_ring::{Ring, RingData, RingDevice};

        fn dev(id: u64) -> RingDevice {
            RingDevice {
                id,
                region: 1,
                zone: id + 1,
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
            32,
            vec![vec![0u32], vec![1u32], vec![2u32]],
        );
        let ring = Ring::new(data, HashPathConfig::new("", "changeme").unwrap());
        let leader = SharderNodeIdentity::new("10.0.0.1", 6201);
        let follower = SharderNodeIdentity::new("10.0.0.2", 6201);

        assert!(local_node_is_primary_leader(
            &ring,
            "AUTH_test",
            "root",
            Path::new("/srv/1/node/sd0"),
            &leader,
        ));
        assert!(!local_node_is_primary_leader(
            &ring,
            "AUTH_test",
            "root",
            Path::new("/srv/2/node/sd1"),
            &follower,
        ));
        assert!(!local_node_is_primary_leader(
            &ring,
            "AUTH_test",
            "root",
            Path::new("/srv/1/node/sd0"),
            &SharderNodeIdentity::new("10.0.0.1", 6202),
        ));
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
    fn test_process_shrinking_donors_shrink_to_root_collapses() {
        // Probe L2088: last SHRINKING donor is covered only by the root own
        // (`include_own: false` hides it from find_shrink_acceptor). Must copy
        // alpha onto the epoch DB and leave collapsed, not unsharded.
        let hash_config = HashPathConfig::new("", "changeme").unwrap();
        let dir = std::env::temp_dir().join(format!(
            "swift-s2r-collapse-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let device = dir.join("d1");
        let account = "AUTH_test";
        let container = "c";
        let hsh = hash_config
            .hash_path(account, Some(container), None)
            .unwrap();
        let suf = &hsh[hsh.len() - 3..];
        let hd = device.join("containers/0").join(suf).join(&hsh);
        std::fs::create_dir_all(&hd).unwrap();
        let unsuffixed = hd.join(format!("{hsh}.db"));
        let epoch = "1751500010.00000";
        let epoch_path = make_db_file_path(&unsuffixed, Some(epoch)).unwrap();
        let mut root = ContainerBroker::new(&epoch_path, account, container);
        root.initialize("1751500000.00000", 0, "1751500000.00000", "id")
            .unwrap();
        let mut own = root.get_own_shard_range(false).unwrap().unwrap();
        own.epoch = Some(epoch.to_string());
        own.state = shard_state::SHARDED;
        let mut donor = ShardRange::new(".shards_AUTH_test/c-0", epoch, "", "");
        donor.state = shard_state::SHRINKING;
        donor.object_count = 1;
        root.merge_shard_ranges(vec![own, donor.clone()]).unwrap();
        assert_eq!(root.get_db_state().unwrap(), DbState::Sharded);

        let mut donor_b = local_shard_broker(&device, &hash_config, "0", &donor.name);
        donor_b
            .merge_items(vec![swift_db::ObjectRecord {
                name: "alpha-1".into(),
                created_at: "1751500011.00000".into(),
                size: 1,
                content_type: "text/plain".into(),
                etag: "e".into(),
                deleted: 0,
                storage_policy_index: 0,
                ctype_timestamp: None,
                meta_timestamp: None,
            }])
            .unwrap();

        let n = process_shrinking_donors(&mut root, &device, &hash_config, "0", None).unwrap();
        assert_eq!(n, 1, "shrink-to-root must finish the last donor, got {n}");
        assert!(
            !unsuffixed.exists(),
            "must not create unsuffixed sidecar beside epoch"
        );
        assert_eq!(
            root.get_db_state().unwrap(),
            DbState::Collapsed,
            "L2088: last shrink must collapse, not unsharded"
        );
        let names: Vec<String> = root
            .object_records_in_range("", "")
            .unwrap()
            .into_iter()
            .filter(|r| r.deleted == 0)
            .map(|r| r.name)
            .collect();
        assert_eq!(names, vec!["alpha-1".to_string()], "{names:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_compactible_shrink_to_root_preserves_own_epoch() {
        // A synthesized default own has no epoch. Merging it as acceptor
        // would make get_db_state()==unsharded on the epoch file (L2088).
        let dir = std::env::temp_dir().join(format!(
            "swift-s2r-epoch-keep-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let mut root = container_broker(&dir, "c", 1);
        let epoch = "1751500010.00000";
        let mut own = root.get_own_shard_range(false).unwrap().unwrap();
        own.epoch = Some(epoch.to_string());
        own.state = shard_state::SHARDED;
        let mut donor = ShardRange::new(".shards_AUTH_test/c-0", epoch, "", "");
        donor.state = shard_state::ACTIVE;
        donor.object_count = 1;
        root.merge_shard_ranges(vec![own, donor]).unwrap();

        let mut sequences = find_compactible_shard_sequences(
            &mut root, 10, 100, 1, 1, true,
        )
        .unwrap();
        assert!(
            !sequences.is_empty(),
            "last shard must form a shrink-to-root sequence"
        );
        process_compactible_shard_sequences(&mut root, &mut sequences).unwrap();
        let after = root.get_own_shard_range(true).unwrap().unwrap();
        assert_eq!(
            after.epoch.as_deref(),
            Some(epoch),
            "own.epoch must survive compactible expand: {after:?}"
        );
        // container_broker is unsuffixed, so db_state stays Unsharded;
        // the invariant is that own.epoch survived the merge.
        std::fs::remove_dir_all(&dir).unwrap();
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
    fn test_shrink_does_not_publish_empty_local_acceptor_stats() {
        // Probe MoreUTF8 test_shrinking L1992: donor+root on d1, real
        // acceptor (50 objects) only on d2. Shrinking must not create an
        // empty acceptor on d1 and write object_count=1 to the root.
        let hash_config = HashPathConfig::new("", "changeme").unwrap();
        let dir = std::env::temp_dir().join(format!(
            "swift-sharder-shrink-empty-acc-{}",
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
        acceptor.object_count = 50;
        acceptor.bytes_used = 150;
        source
            .merge_shard_ranges(vec![donor.clone(), acceptor.clone()])
            .unwrap();

        let mut donor_b = local_shard_broker(&d1, &hash_config, "0", &donor.name);
        donor_b
            .merge_items(vec![swift_db::ObjectRecord {
                name: "alpha-1".into(),
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

        let mut acc_b = local_shard_broker(&d2, &hash_config, "0", &acceptor.name);
        let records: Vec<_> = (0..50)
            .map(|i| swift_db::ObjectRecord {
                name: format!("obj-{i:03}"),
                created_at: "1751500011.00000".into(),
                size: 3,
                content_type: "text/plain".into(),
                etag: "d41d8cd98f00b204e9800998ecf8427e".into(),
                deleted: 0,
                storage_policy_index: 0,
                ctype_timestamp: None,
                meta_timestamp: None,
            })
            .collect();
        acc_b.merge_items(records).unwrap();

        let n = process_shrinking_donors(&mut source, &d1, &hash_config, "0", None).unwrap();
        assert_eq!(n, 1);

        let after = source
            .get_shard_ranges(&GetShardRangesArgs {
                include_deleted: true,
                include_own: false,
                ..Default::default()
            })
            .unwrap();
        let a = after.iter().find(|r| r.name == acceptor.name).unwrap();
        assert_eq!(
            a.object_count, 51,
            "root acceptor stats must keep the real 50 plus copied alpha, got {a:?}"
        );
        assert_eq!(a.bytes_used, 153, "{a:?}");
        let d = after.iter().find(|r| r.name == donor.name).unwrap();
        assert_eq!(d.state, shard_state::SHRUNK);
        assert_eq!(d.deleted, 1);

        let mut acc_after = open_existing_shard_broker(&d2, &hash_config, "0", &acceptor.name)
            .expect("real acceptor must still exist on d2");
        let moved = acc_after.object_records_in_range("", "").unwrap();
        assert!(
            moved.iter().any(|r| r.name == "alpha-1" && r.deleted == 0),
            "{moved:?}"
        );
        assert_eq!(moved.iter().filter(|r| r.deleted == 0).count(), 51);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_auto_shrink_opt_default_false() {
        assert!(!SharderRunOpts::default().auto_shrink);
    }

    fn shrinking_root_broker(dir: &std::path::Path, name: &str) -> ContainerBroker {
        let h = format!("{:0>32}", name.replace(['/', '.'], ""));
        let h = &h[h.len() - 32..];
        let hd = dir.join(format!("c/0/{}/{h}", &h[h.len() - 3..]));
        std::fs::create_dir_all(&hd).unwrap();
        let db = hd.join(format!("{h}.db"));
        let mut b = ContainerBroker::new(&db, "AUTH_test", name);
        b.initialize("1751500000.00000", 0, "1751500000.00000", "id")
            .unwrap();
        b
    }

    #[test]
    fn test_find_compactible_1_plus_50_not_50_plus_50() {
        // Probe L2001: after DELETE of first-shard objects, donor row_count=1
        // is below shrink_threshold=10 (10% of shard_size 100) so it compact
        // into the oc=50 neighbor. The original 50+50 pair must not compact.
        let dir = std::env::temp_dir().join(format!(
            "swift-compactible-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let mut broker = shrinking_root_broker(&dir, "c");
        let ts = "1751500010.00000";
        let mut donor = ShardRange::new(".shards_AUTH_test/c-0", ts, "", "m");
        donor.state = shard_state::ACTIVE;
        donor.object_count = 1;
        donor.tombstones = 0;
        let mut acceptor = ShardRange::new(".shards_AUTH_test/c-1", ts, "m", "");
        acceptor.state = shard_state::ACTIVE;
        acceptor.object_count = 50;
        acceptor.tombstones = 0;
        broker
            .merge_shard_ranges(vec![donor.clone(), acceptor.clone()])
            .unwrap();

        let seqs = find_compactible_shard_sequences(&mut broker, 10, 75, 1, -1, false).unwrap();
        assert_eq!(seqs.len(), 1, "{seqs:?}");
        assert_eq!(seqs[0].len(), 2);
        assert_eq!(seqs[0][0].name, donor.name);
        assert_eq!(seqs[0][1].name, acceptor.name);

        let mut seqs = seqs;
        process_compactible_shard_sequences(&mut broker, &mut seqs).unwrap();
        let after = broker
            .get_shard_ranges(&GetShardRangesArgs {
                include_own: false,
                include_deleted: false,
                ..GetShardRangesArgs::default()
            })
            .unwrap();
        let d = after.iter().find(|r| r.name == donor.name).unwrap();
        let a = after.iter().find(|r| r.name == acceptor.name).unwrap();
        assert_eq!(d.state, shard_state::SHRINKING, "{d:?}");
        assert_eq!(a.state, shard_state::ACTIVE, "{a:?}");
        assert_eq!(a.lower, "", "acceptor expands over donor: {a:?}");
        assert_eq!(a.upper, "");

        // 50+50: neither range is below threshold 10.
        let dir2 = dir.join("fifty");
        let mut broker2 = shrinking_root_broker(&dir2, "c2");
        let mut d50 = donor.clone();
        d50.object_count = 50;
        d50.name = ".shards_AUTH_test/c2-0".into();
        let mut a50 = acceptor.clone();
        a50.object_count = 50;
        a50.name = ".shards_AUTH_test/c2-1".into();
        broker2.merge_shard_ranges(vec![d50, a50]).unwrap();
        let seqs = find_compactible_shard_sequences(&mut broker2, 10, 75, 1, -1, false).unwrap();
        assert!(
            seqs.is_empty(),
            "50+50 must not compact under threshold 10: {seqs:?}"
        );

        // Unreclaimed tombstones keep row_count above threshold (L1979 reclaim).
        let dir3 = dir.join("tombs");
        let mut broker3 = shrinking_root_broker(&dir3, "c3");
        let mut d_tombs = donor.clone();
        d_tombs.object_count = 1;
        d_tombs.tombstones = 50;
        d_tombs.name = ".shards_AUTH_test/c3-0".into();
        let mut a_tombs = acceptor.clone();
        a_tombs.name = ".shards_AUTH_test/c3-1".into();
        broker3.merge_shard_ranges(vec![d_tombs, a_tombs]).unwrap();
        let seqs = find_compactible_shard_sequences(&mut broker3, 10, 75, 1, -1, false).unwrap();
        assert!(
            seqs.is_empty(),
            "row_count=51 (1+50 tombs) must not compact: {seqs:?}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_run_once_sharded_root_auto_shard_enables_shrinking() {
        // Python `_process_broker`: SHARDED root + auto_shard finds the 1+50
        // pair even with auto_shrink=false. process_shrinking_donors must not
        // run (would skip because donor is still ACTIVE until this pass).
        let hash_config = HashPathConfig::new("", "changeme").unwrap();
        let dir = std::env::temp_dir().join(format!(
            "swift-run-once-shrink-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
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
        let mut donor = ShardRange::new(".shards_AUTH_test/c-0", epoch, "", "m");
        donor.state = shard_state::ACTIVE;
        donor.object_count = 1;
        donor.tombstones = 0;
        let mut acceptor = ShardRange::new(".shards_AUTH_test/c-1", epoch, "m", "");
        acceptor.state = shard_state::ACTIVE;
        acceptor.object_count = 50;
        acceptor.tombstones = 0;
        source
            .merge_shard_ranges(vec![donor.clone(), acceptor.clone()])
            .unwrap();
        source.enable_sharding(epoch).unwrap();
        assert!(source.set_sharding_state().unwrap());
        assert!(source.set_sharded_state().unwrap());
        assert_eq!(source.get_db_state().unwrap(), DbState::Sharded);
        drop(source);

        let opts = SharderRunOpts {
            cleave_batch_size: 2,
            auto_shard: true,
            auto_shrink: false,
            shard_size: 100,
            rows_per_shard: 50,
            minimum_shard_size: 10,
            partitions: Vec::new(),
        };
        let stats = run_once_with_opts(&device, &hash_config, &opts);
        assert_eq!(stats.failures, 0, "{stats:?}");
        let mut check = ContainerBroker::new(&db, account, container);
        // set_sharded_state unlinks retiring; reopen the remaining epoch file.
        if !db.exists() {
            let files: Vec<_> = std::fs::read_dir(&hd)
                .unwrap()
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|x| x == "db"))
                .collect();
            assert_eq!(files.len(), 1, "{files:?}");
            check = ContainerBroker::new(&files[0], account, container);
        }
        assert_eq!(check.get_db_state().unwrap(), DbState::Sharded);
        let after = check
            .get_shard_ranges(&GetShardRangesArgs {
                include_own: false,
                include_deleted: false,
                ..GetShardRangesArgs::default()
            })
            .unwrap();
        let d = after
            .iter()
            .find(|r| r.name == donor.name)
            .expect(&format!("{after:?}"));
        let a = after
            .iter()
            .find(|r| r.name == acceptor.name)
            .expect(&format!("{after:?}"));
        assert_eq!(d.state, shard_state::SHRINKING, "{d:?}");
        assert_eq!(a.lower, "", "{a:?}");
        assert_eq!(a.upper, "");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_shrinking_cleave_does_not_drop_expanded_acceptor() {
        // Probe L2001: donor own is (Min, obj-1-049] SHRINKING and the
        // acceptor was expanded to (Min, Max]. Nested-child retain must not
        // drop the acceptor (`G6_CLEAVE skip-empty`).
        let hash_config = HashPathConfig::new("", "changeme").unwrap();
        let dir = std::env::temp_dir().join(format!(
            "swift-shrink-cleave-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let device = dir.join("d1");
        let account = ".shards_AUTH_test";
        let container = "c-d0";
        let hsh = hash_config
            .hash_path(account, Some(container), None)
            .unwrap();
        let suf = &hsh[hsh.len() - 3..];
        let hd = device.join("containers/0").join(suf).join(&hsh);
        std::fs::create_dir_all(&hd).unwrap();
        let db = hd.join(format!("{hsh}.db"));
        let mut donor = ContainerBroker::new(&db, account, container);
        donor
            .initialize("1751500000.00000", 0, "1751500000.00000", "id")
            .unwrap();
        donor
            .put_object(
                "aaa",
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
        let epoch = "1751500010.00000";
        let mut own = ShardRange::new(&donor.path(), epoch, "", "m");
        own.state = shard_state::SHRINKING;
        own.epoch = Some(epoch.into());
        ensure_shard_root_sysmeta(&mut donor, "AUTH_test", "rootc", &own);
        let mut acceptor = ShardRange::new(".shards_AUTH_test/c-a0", epoch, "", "");
        acceptor.state = shard_state::ACTIVE;
        donor
            .merge_shard_ranges(vec![own.clone(), acceptor.clone()])
            .unwrap();
        assert!(donor.set_sharding_state().unwrap());
        let out = process_sharding_container_detailed(
            &mut donor,
            &device,
            &hash_config,
            "0",
            2,
            &mut LocalShardReplicator,
        )
        .unwrap();
        assert!(
            out.finished,
            "shrinking donor must cleave into expanded acceptor, not skip-empty: {out:?}"
        );
        let own_after = donor.get_own_shard_range(true).unwrap().unwrap();
        assert_eq!(
            own_after.state,
            shard_state::SHRUNK,
            "set_sharded_state must not clobber SHRUNK: {own_after:?}"
        );
        assert_eq!(own_after.deleted, 1, "{own_after:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_recleave_uses_context_and_sync_high_water_marks() {
        // Probe test_shrinking L2044: after a completed shrink, a changed
        // retiring max-row resets the cleaving context.  Only rows newer than
        // last_cleave_to_row may be copied, and a subsequent retry must also
        // honor the acceptor's incoming sync point.  Replaying from row zero
        // resurrects reclaimed objects from an old donor replica.
        let hash_config = HashPathConfig::new("", "changeme").unwrap();
        let dir = std::env::temp_dir().join(format!(
            "swift-shrink-recleave-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let device = dir.join("d1");
        let account = ".shards_AUTH_test";
        let container = "c-donor";
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
        source
            .put_object(
                "aaa",
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

        let epoch = "1751500010.00000";
        let mut own = ShardRange::new(&source.path(), epoch, "", "m");
        own.state = shard_state::SHRINKING;
        own.epoch = Some(epoch.into());
        ensure_shard_root_sysmeta(&mut source, "AUTH_test", "rootc", &own);
        let mut acceptor = ShardRange::new(".shards_AUTH_test/c-acceptor", epoch, "", "");
        acceptor.state = shard_state::ACTIVE;
        source
            .merge_shard_ranges(vec![own.clone(), acceptor.clone()])
            .unwrap();
        assert!(source.set_sharding_state().unwrap());

        let first_max = broker_max_row_retiring(&mut source);
        let source_id = {
            let mut retiring = source.retiring_broker().unwrap();
            broker_db_id(&mut retiring)
        };
        let mut ranges = vec![acceptor];
        let mut ctx = CleavingContext {
            max_row: first_max,
            cleave_to_row: first_max,
            ..CleavingContext::default()
        };
        let mut shard_for =
            |sr: &ShardRange| local_shard_broker(&device, &hash_config, "0", &sr.name);
        cleave(&mut source, &mut ranges, &mut shard_for, &mut ctx, 2).unwrap();
        assert!(ctx.cleaving_done, "{ctx:?}");
        assert_eq!(ranges[0].state, shard_state::ACTIVE);

        let mut shard = local_shard_broker(&device, &hash_config, "0", &ranges[0].name);
        assert_eq!(shard.get_sync(&source_id, true).unwrap(), first_max);
        assert_eq!(
            shard
                .object_records_in_range("", "")
                .unwrap()
                .into_iter()
                .map(|r| r.name)
                .collect::<Vec<_>>(),
            vec!["aaa".to_string()]
        );

        // Simulate a reclaimed target row, then append one genuinely new row
        // to the retiring DB.  A reset must copy only the latter.
        shard.remove_object_named("aaa").unwrap();
        {
            let mut retiring = source.retiring_broker().unwrap();
            retiring
                .put_object(
                    "bbb",
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
            retiring.commit_pending().unwrap();
        }
        let second_max = broker_max_row_retiring(&mut source);
        assert!(second_max > first_max);
        ctx.cursor.clear();
        ctx.ranges_done = 0;
        ctx.ranges_todo = 0;
        ctx.cleaving_done = false;
        ctx.last_cleave_to_row = Some(first_max);
        ctx.max_row = second_max;
        ctx.cleave_to_row = second_max;
        cleave(&mut source, &mut ranges, &mut shard_for, &mut ctx, 2).unwrap();
        assert_eq!(
            shard
                .object_records_in_range("", "")
                .unwrap()
                .into_iter()
                .map(|r| r.name)
                .collect::<Vec<_>>(),
            vec!["bbb".to_string()],
            "old row was replayed across last_cleave_to_row"
        );
        assert_eq!(shard.get_sync(&source_id, true).unwrap(), second_max);

        // Even without the context floor, the target sync point prevents a
        // retry against the unchanged source from replaying either old row.
        shard.remove_object_named("bbb").unwrap();
        ctx.cursor.clear();
        ctx.ranges_done = 0;
        ctx.ranges_todo = 0;
        ctx.cleaving_done = false;
        ctx.last_cleave_to_row = None;
        cleave(&mut source, &mut ranges, &mut shard_for, &mut ctx, 2).unwrap();
        assert!(
            shard.object_records_in_range("", "").unwrap().is_empty(),
            "incoming sync point did not suppress an unchanged-source retry"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
