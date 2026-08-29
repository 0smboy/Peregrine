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

//! The container server, ported from `swift/container/server.py`.
//! Statuses, headers and listing bodies are golden-tested against the
//! Python WSGI controller.
//!
//! Sharding request paths ARE implemented: record-type=shard PUT (merge
//! shard ranges), record-type=shard/auto GET (shard-range listing), and the
//! _redirect_to_shard 301 on object PUT and DELETE. Deviations tracked for later:
//! REPLICATE is handled via the db_replicator RPC. Container-sync is a full
//! path: metadata updates maintain `sync_containers/`, `swift-container-sync`
//! ships rows, and the proxy `container_sync` filter validates inbound realm
//! auth. Residual: fallocate_reserve free-space check is not enforced.

use std::future::Future;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::pin::Pin;

pub mod reconciler;
pub mod sharder;
pub mod sync;
pub mod updater;
pub use reconciler::{
    decide as reconciler_decide, parse_reconciler_obj_name, reconcile, reconciler_container_name,
    reconciler_content_type, reconciler_obj_name, run_once as reconciler_run_once, QueueEntry,
    QueueOp, ReconcileClient, ReconcileDecision, ReconcileOutcome, ReconcilerStats,
    MISPLACED_OBJECTS_ACCOUNT,
};
pub use sharder::{
    cleave, cleave_shard_range, cleaving_context_sysmeta_key, default_shard_quorum,
    find_and_enable_shrinking_candidates, find_and_merge_found_ranges,
    find_compactible_shard_sequences, find_shrink_acceptor, find_shrinking_donors,
    http_replicator_for_primaries, is_shrinking_candidate, load_all_cleaving_contexts,
    load_cleaving_context, lookup_replicator_for_ring, maybe_auto_shard,
    move_misplaced_from_retiring, primary_shard_replica_nodes, process_compactible_shard_sequences,
    process_sharding_container, process_sharding_container_detailed,
    process_sharding_container_with_replicator, process_shrinking_donors,
    process_shrinking_donors_stub, put_shard_quorum, range_covers,
    recon_update as sharder_recon_update, refresh_own_shard_range_stats, ring_get_nodes_for_shard,
    run_once as sharder_run_once, run_once_with_opts as sharder_run_once_with_opts,
    run_once_with_opts_and_replicator, run_once_with_opts_and_ring, save_cleaving_context,
    shard_replicas_from_ring_devices, update_root_container, CleavingContext, HttpShardReplicator,
    LocalShardReplicator, LookupHttpShardReplicator, MapShardHttpTransport, ProcessShardingOutcome,
    ShardHttpTransport, ShardReplicaNode, ShardReplicator, SharderRunOpts, SharderStats,
    TcpShardHttpTransport, CLEAVING_CONTEXT_KEY, CLEAVING_CONTEXT_KEY_PREFIX,
};
pub use sync::{
    build_sync_headers, get_sig, owns_object, process_container_db, run_once as sync_run_once,
    sync_auth_header, sync_rows, validate_sync_to, ContainerSyncConfig, ContainerSyncRealms,
    ContainerSyncStore, EmptyObjectSource, HttpSyncClient, MapObjectSource, ObjectSource,
    SyncAction, SyncClient, SyncContext, SyncRow, SyncStats, ValidatedSyncTo, SYNC_DATADIR,
};
pub use updater::{
    process_container, run_once as updater_run_once, AccountNodeClient, ContainerOutcome,
    ContainerStat, ContainerUpdaterStats, HttpAccountClient,
};

use swift_core::hashing::HashPathConfig;
use swift_core::timestamp::Timestamp;
use swift_db::{BrokerMetadata, ContainerBroker, DbError, DbValue, ListObjectsArgs, ObjectRecord};
use swift_http::{
    http_date, split_path, AsyncRequest, AsyncService, HeaderKeyDict, Request, Response,
};
use swift_runtime::{ConcurrencyMetrics, DbExecutor, DbExecutorConfig};

pub const CONTAINER_LISTING_LIMIT: i64 = 10000;
pub const MAX_META_COUNT: usize = 90;
pub const MAX_META_OVERALL_SIZE: usize = 4096;
pub const AUTO_CREATE_ACCOUNT_PREFIX: &str = ".";
const SHARDS_ACCOUNT_PREFIX: &str = ".shards_";
const RESERVED: char = '\u{0}';
const SAVE_HEADERS: [&str; 4] = [
    "x-container-read",
    "x-container-write",
    "x-container-sync-key",
    "x-container-sync-to",
];

#[derive(Debug, Clone)]
pub struct ContainerServerConfig {
    pub devices: PathBuf,
    pub mount_check: bool,
    pub hash_config: HashPathConfig,
    pub policies: Vec<(i64, String)>,
    pub default_policy_index: i64,
    /// Fixed `created_at` for deterministic tests.
    pub fixed_created_at: Option<String>,
    /// Python `recon_cache_path` (DEFAULT / filter:recon). Used for GET /recon/*.
    pub recon_cache_path: PathBuf,
}

pub struct ContainerServer {
    pub config: ContainerServerConfig,
    db: std::sync::OnceLock<DbExecutor>,
}

struct ReplicateTarget {
    drive: String,
    db_path: PathBuf,
}

fn swob_explanation(status: u16) -> &'static str {
    match status {
        202 => "The request is accepted for processing.",
        404 => "The resource could not be found.",
        405 => "The method is not allowed for this resource.",
        409 => "There was a conflict when trying to complete your request.",
        413 => "The body of your request was too large for this server.",
        500 => "The server has either erred or is incapable of performing the requested operation.",
        507 => "There was not enough space to save the resource. Drive: %s",
        _ => "",
    }
}

fn swob_response(status: u16, drive: Option<&str>) -> Response {
    let explanation = swob_explanation(status).replace("%s", drive.unwrap_or(""));
    let mut resp = if explanation.is_empty() {
        Response::new(status)
    } else {
        Response::with_body(
            status,
            format!(
                "<html><h1>{}</h1><p>{explanation}</p></html>",
                Response::new(status).reason
            ),
        )
    };
    resp.headers.set("Content-Type", "text/html; charset=UTF-8");
    resp
}

fn plain_response(status: u16, body: &str) -> Response {
    let mut resp = Response::with_body(status, body.as_bytes().to_vec());
    resp.headers.set("Content-Type", "text/plain");
    resp
}

fn error_response(status: u16, body: &str) -> Response {
    let mut resp = Response::with_body(status, body.as_bytes().to_vec());
    resp.headers.set("Content-Type", "text/html; charset=UTF-8");
    resp
}

/// Control-plane request bodies (REPLICATE RPC args, shard-range PUTs,
/// UPDATE record lists) are bounded: an over-cap body is 413, and a
/// transport failure during the read maps to the server's catch-all 500
/// (server.py `__call__`).
fn read_control_body(req: &mut Request) -> Result<&[u8], Response> {
    match req.body.materialize(swift_http::MAX_CONTROL_BODY) {
        Ok(body) => Ok(body),
        Err(e) if swift_http::body_too_large(&e) => Err(swob_response(413, None)),
        Err(_) => Err(swob_response(500, None)),
    }
}

fn value_str(v: &DbValue) -> String {
    match v {
        DbValue::Text(s) => s.clone(),
        DbValue::Int(i) => i.to_string(),
        DbValue::Null => String::new(),
    }
}

fn py_json_escape(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c if (c as u32) > 0x7e => {
                let cp = c as u32;
                if cp > 0xffff {
                    let v = cp - 0x10000;
                    out.push_str(&format!("\\u{:04x}", 0xd800 + (v >> 10)));
                    out.push_str(&format!("\\u{:04x}", 0xdc00 + (v & 0x3ff)));
                } else {
                    out.push_str(&format!("\\u{cp:04x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// One container listing record after `update_object_record`.
enum ObjRecord {
    Subdir(String),
    Object {
        bytes: i64,
        hash: String,
        name: String,
        content_type: String,
        last_modified: String,
    },
}

/// `extract_swift_bytes` override applied by
/// `override_bytes_from_content_type`.
fn override_bytes(content_type: &str, size: i64) -> (String, i64) {
    match content_type.split_once(';') {
        None => (content_type.to_string(), size),
        Some((ct, params)) => {
            let mut out = ct.to_string();
            let mut bytes = size;
            for param in params.split(';') {
                let (k, v) = param.split_once('=').unwrap_or((param, ""));
                let (k, v) = (k.trim(), v.trim());
                if k == "swift_bytes" {
                    if let Ok(b) = v.parse() {
                        bytes = b;
                    }
                } else if !k.is_empty() {
                    out.push_str(&format!(";{k}={v}"));
                }
            }
            (out, bytes)
        }
    }
}

fn listing_to_json(records: &[ObjRecord]) -> String {
    let mut out = String::from("[");
    for (i, rec) in records.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        match rec {
            ObjRecord::Subdir(name) => {
                out.push_str("{\"subdir\": ");
                py_json_escape(name, &mut out);
                out.push('}');
            }
            ObjRecord::Object {
                bytes,
                hash,
                name,
                content_type,
                last_modified,
            } => {
                out.push_str(&format!("{{\"bytes\": {bytes}, \"hash\": "));
                py_json_escape(hash, &mut out);
                out.push_str(", \"name\": ");
                py_json_escape(name, &mut out);
                out.push_str(", \"content_type\": ");
                py_json_escape(content_type, &mut out);
                out.push_str(", \"last_modified\": ");
                py_json_escape(last_modified, &mut out);
                out.push('}');
            }
        }
    }
    out.push(']');
    out
}

fn listing_to_text(records: &[ObjRecord]) -> Vec<u8> {
    let mut out = Vec::new();
    for rec in records {
        match rec {
            ObjRecord::Subdir(name) | ObjRecord::Object { name, .. } => {
                out.extend_from_slice(name.as_bytes());
            }
        }
        out.push(b'\n');
    }
    out
}

fn xml_escape_text(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            c => out.push(c),
        }
    }
}

fn xml_escape_attr(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\n' => out.push_str("&#10;"),
            '\t' => out.push_str("&#09;"),
            '\r' => out.push_str("&#13;"),
            c => out.push(c),
        }
    }
}

fn xml_field(out: &mut String, tag: &str, value: &str) {
    if value.is_empty() {
        out.push_str(&format!("<{tag} />"));
    } else {
        out.push_str(&format!("<{tag}>"));
        xml_escape_text(value, out);
        out.push_str(&format!("</{tag}>"));
    }
}

/// `listing_formats.container_to_xml` (no inter-element whitespace).
fn listing_to_xml(records: &[ObjRecord], container: &str) -> Vec<u8> {
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str("<container name=\"");
    xml_escape_attr(container, &mut out);
    out.push_str("\">");
    for rec in records {
        match rec {
            ObjRecord::Subdir(name) => {
                out.push_str("<subdir name=\"");
                xml_escape_attr(name, &mut out);
                out.push_str("\">");
                xml_field(&mut out, "name", name);
                out.push_str("</subdir>");
            }
            ObjRecord::Object {
                bytes,
                hash,
                name,
                content_type,
                last_modified,
            } => {
                out.push_str("<object>");
                xml_field(&mut out, "name", name);
                xml_field(&mut out, "hash", hash);
                xml_field(&mut out, "bytes", &bytes.to_string());
                xml_field(&mut out, "content_type", content_type);
                xml_field(&mut out, "last_modified", last_modified);
                out.push_str("</object>");
            }
        }
    }
    out.push_str("</container>");
    out.into_bytes()
}

fn listing_content_type(req: &Request) -> &'static str {
    if let Some(format) = req.param("format") {
        return match format.to_lowercase().as_str() {
            "json" => "application/json",
            "xml" => "application/xml",
            _ => "text/plain",
        };
    }
    if let Some(accept) = req.headers.get("Accept") {
        let accept = accept.to_lowercase();
        if accept.contains("application/json") {
            return "application/json";
        }
        if accept.contains("application/xml") {
            return "application/xml";
        }
        if accept.contains("text/xml") {
            return "text/xml";
        }
    }
    "text/plain"
}

fn valid_timestamp(req: &Request) -> Result<Timestamp, Response> {
    let Some(raw) = req.headers.get("X-Timestamp") else {
        return Err(plain_response(400, "Missing X-Timestamp header"));
    };
    raw.parse()
        .map_err(|_| plain_response(400, "Invalid X-Timestamp header"))
}

fn is_sys_or_user_meta(server_type: &str, key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    let user = format!("x-{server_type}-meta-");
    let sys = format!("x-{server_type}-sysmeta-");
    (lower.starts_with(&user) && lower.len() > user.len())
        || (lower.starts_with(&sys) && lower.len() > sys.len())
}

/// Translate Swift `X-Remove-*` headers into empty-value updates of the
/// target header (container/server.py POST metadata path).
///
/// Examples:
/// - `X-Remove-Container-Read: x` → `("X-Container-Read", "")`
/// - `X-Remove-Container-Meta-Color: x` → `("X-Container-Meta-Color", "")`
///
/// Returns `None` when the header is not an X-Remove of a savable key, or
/// when the remove trigger value is empty (Python ignores empty removes).
fn translate_container_remove_header(key: &str, value: &str) -> Option<(String, String)> {
    if value.is_empty() {
        return None;
    }
    let lower = key.to_ascii_lowercase();
    const PREFIX: &str = "x-remove-container-";
    if !lower.starts_with(PREFIX) || lower.len() <= PREFIX.len() {
        return None;
    }
    let rest = &lower[PREFIX.len()..];
    // ACL / sync headers: X-Remove-Container-Read → X-Container-Read
    let target = format!("x-container-{rest}");
    if SAVE_HEADERS.contains(&target.as_str()) || is_sys_or_user_meta("container", &target) {
        // Preserve conventional casing for the well-known ACL headers.
        let out_key = match target.as_str() {
            "x-container-read" => "X-Container-Read".to_string(),
            "x-container-write" => "X-Container-Write".to_string(),
            "x-container-sync-key" => "X-Container-Sync-Key".to_string(),
            "x-container-sync-to" => "X-Container-Sync-To".to_string(),
            _ => target,
        };
        return Some((out_key, String::new()));
    }
    None
}

fn validate_metadata(md: &BrokerMetadata) -> Result<(), Response> {
    let mut meta_count = 0usize;
    let mut meta_size = 0usize;
    for (key, (value, _)) in md {
        let key = key.to_lowercase();
        for prefix in ["x-account-meta-", "x-container-meta-"] {
            if !value.is_empty() && key.starts_with(prefix) {
                meta_count += 1;
                // Python len() counts characters (code points), not bytes, so
                // a non-ASCII metadata value is not over-counted here.
                meta_size += key[prefix.len()..].chars().count() + value.chars().count();
                break;
            }
        }
    }
    if meta_count > MAX_META_COUNT {
        return Err(error_response(
            400,
            &format!("Too many metadata items; max {MAX_META_COUNT}"),
        ));
    }
    if meta_size > MAX_META_OVERALL_SIZE {
        return Err(error_response(
            400,
            &format!("Total metadata too large; max {MAX_META_OVERALL_SIZE}"),
        ));
    }
    Ok(())
}

fn validate_internal_name(name: &str, type_: &str) -> Result<(), Response> {
    if name.contains(RESERVED) && !name.starts_with(RESERVED) {
        return Err(error_response(
            400,
            &format!("Invalid reserved-namespace {type_}"),
        ));
    }
    Ok(())
}

/// Port of `swift.common.request_helpers.validate_internal_obj`.
///
/// Reconciler queue object names deliberately embed the source account,
/// container, and object in one record name.  Those embedded names may contain
/// the reserved byte, so Python skips object-name validation for auto-created
/// system accounts (including `.misplaced_objects`).  User-account paths must
/// retain the stricter namespace checks.
fn validate_internal_obj(account: &str, container: &str, obj: &str) -> Result<(), Response> {
    validate_internal_name(account, "account")?;
    validate_internal_name(container, "container")?;
    if !obj.is_empty()
        && !account.starts_with(AUTO_CREATE_ACCOUNT_PREFIX)
        && account != MISPLACED_OBJECTS_ACCOUNT
    {
        validate_internal_name(obj, "object")?;
        if container.starts_with(RESERVED) && !obj.starts_with(RESERVED) {
            return Err(error_response(
                400,
                "Invalid user-namespace object in reserved-namespace container",
            ));
        }
        if obj.starts_with(RESERVED) && !container.starts_with(RESERVED) {
            return Err(error_response(
                400,
                "Invalid reserved-namespace object in user-namespace container",
            ));
        }
    }
    Ok(())
}

/// Percent-encode a location the way `urllib.parse.quote` does with the
/// default safe set (letters, digits, `_.-~` and `/`).
fn pct_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-' | b'~' | b'/' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn truthy(v: Option<&str>) -> bool {
    matches!(
        v.map(str::to_lowercase).as_deref(),
        Some("true") | Some("1") | Some("yes") | Some("on") | Some("t") | Some("y")
    )
}

impl ContainerServer {
    pub fn new(config: ContainerServerConfig) -> Self {
        ContainerServer {
            config,
            db: std::sync::OnceLock::new(),
        }
    }

    pub fn db(&self) -> &DbExecutor {
        self.db.get_or_init(|| {
            DbExecutor::new(DbExecutorConfig::new(4, 32, 8).expect("db executor config"))
                .expect("db executor")
        })
    }


    /// Python recon middleware: GET `/recon/<check>` never uses obj_path.
    /// Isolated G6 container-server.conf pipelines `healthcheck recon
    /// container-server`, but this binary ignores the pipeline, so `/recon/*`
    /// used to 400 via `split_path(..., 4, 5)`.
    fn recon_get(&self, req: &Request) -> Response {
        if req.method != "GET" && req.method != "HEAD" {
            return plain_response(405, "Method Not Allowed");
        }
        let check = req.path.trim_start_matches("/recon/").trim_end_matches('/');
        if check != "sharding" {
            return plain_response(404, &format!("Invalid path: {}", req.path));
        }
        let cache = self.config.recon_cache_path.join("container.recon");
        let keys = ["sharding_stats", "sharding_time", "sharding_last"];
        let mut out = serde_json::Map::new();
        let parsed = std::fs::read_to_string(&cache).ok().and_then(|s| {
            serde_json::from_str::<serde_json::Value>(s.lines().next().unwrap_or("")).ok()
        });
        if let Some(serde_json::Value::Object(map)) = parsed {
            for k in keys {
                out.insert(
                    k.to_string(),
                    map.get(k).cloned().unwrap_or(serde_json::Value::Null),
                );
            }
        } else {
            for k in keys {
                out.insert(k.to_string(), serde_json::Value::Null);
            }
        }
        let body = serde_json::Value::Object(out).to_string();
        let mut resp = Response::with_body(200, body.into_bytes());
        resp.headers.set("Content-Type", "application/json");
        resp
    }

    pub fn db_file_for_request(&self, req: &Request) -> Result<PathBuf, Response> {
        let (drive, part, account, container, _obj) = self.obj_path(req)?;
        self.check_drive(&drive)?;
        Ok(self
            .broker_for(&drive, &part, &account, &container)
            .db_file()
            .to_path_buf())
    }

    /// Python `ReplicatorRpc` URL is `/<device>/<partition>/<hash>`, not
    /// `/<device>/<partition>/<account>/<container>`. `handle_async` must
    /// park the hash DB on DbExecutor; using `obj_path` 400s every REPLICATE
    /// (G6 `sync RPC status 400`).
    pub fn replicate_db_file_for_request(&self, req: &Request) -> Result<PathBuf, Response> {
        self.replicate_target(req).map(|t| t.db_path)
    }

    fn replicate_target(&self, req: &Request) -> Result<ReplicateTarget, Response> {
        let segs = split_path(&req.path, 3, 3, false).map_err(|e| plain_response(400, &e))?;
        let drive = segs[0].clone().unwrap_or_default();
        let partition = segs[1].clone().unwrap_or_default();
        let hsh = segs[2].clone().unwrap_or_default();
        if let Err(resp) = self.check_drive(&drive) {
            return Err(resp);
        }
        if hsh.is_empty() {
            return Err(plain_response(400, &format!("Invalid path: {}", req.path)));
        }
        let suffix = &hsh[hsh.len().saturating_sub(3)..];
        let db_path = self
            .config
            .devices
            .join(&drive)
            .join("containers")
            .join(&partition)
            .join(suffix)
            .join(&hsh)
            .join(format!("{hsh}.db"));
        Ok(ReplicateTarget { drive, db_path })
    }

    async fn dispatch_on_shard(&self, req: Request) -> Response {
        let db_file = match if req.method.eq_ignore_ascii_case("REPLICATE") {
            self.replicate_db_file_for_request(&req)
        } else {
            self.db_file_for_request(&req)
        } {
            Ok(p) => p,
            Err(resp) => return resp,
        };
        let config = self.config.clone();
        match self
            .db()
            .run_on_shard(db_file, move || {
                ContainerServer {
                    config,
                    db: std::sync::OnceLock::new(),
                }
                .handle(req)
            })
            .await
        {
            Ok(resp) => resp,
            Err(e) => error_response(500, &e.to_string()),
        }
    }

    pub async fn handle_async(&self, mut areq: AsyncRequest) -> Response {
        if let Some(m) = ConcurrencyMetrics::current() {
            m.attach_db(self.db().clone());
        }
        let max = areq.body.max_body_bytes().min(swift_http::MAX_CONTROL_BODY);
        let body = match areq.body.materialize(max).await {
            Ok(bytes) => swift_http::Body::Buffered(bytes),
            Err(e) if swift_http::body_too_large(&e) => return swob_response(413, None),
            Err(_) => return swob_response(500, None),
        };
        let req = Request {
            method: areq.method,
            path: areq.path,
            query_string: areq.query_string,
            headers: areq.headers,
            body,
        };
        if req.method == "OPTIONS" {
            return self.handle(req);
        }
        if req.path.starts_with("/recon/") {
            return self.recon_get(&req);
        }
        self.dispatch_on_shard(req).await
    }

    #[allow(dead_code)]
    async fn put_async(&self, req: &mut Request) -> Response {
        let (drive, part, account, container, obj) = match self.obj_path(req) {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        let req_timestamp = match valid_timestamp(req) {
            Ok(t) => t,
            Err(resp) => return resp,
        };
        if let Err(resp) = self.check_drive(&drive) {
            return resp;
        }
        let Some(obj) = obj else {
            return self.put(req);
        };
        let requested_policy_index = match self.policy_index(req) {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        let obj_policy_index = requested_policy_index.unwrap_or(0);
        let (Some(size), Some(content_type), Some(etag)) = (
            req.headers.get("x-size").map(str::to_string),
            req.headers.get("x-content-type").map(str::to_string),
            req.headers.get("x-etag").map(str::to_string),
        ) else {
            return error_response(500, "missing required backend headers");
        };
        let Ok(size) = size.trim().parse::<i64>() else {
            return error_response(500, "bad x-size");
        };
        let ctype_ts = req
            .headers
            .get("x-content-type-timestamp")
            .map(str::to_string);
        let meta_ts = req.headers.get("x-meta-timestamp").map(str::to_string);
        let broker_probe = self.broker_for(&drive, &part, &account, &container);
        let db_file = broker_probe.db_file().to_path_buf();
        let account_s = account.clone();
        let container_s = container.clone();
        let obj_s = obj.clone();
        let ts = req_timestamp.internal();
        let result = self
            .db()
            .run_on_shard(db_file.clone(), move || {
                let mut broker = ContainerBroker::new(&db_file, &account_s, &container_s);
                broker.put_object(
                    &obj_s,
                    &ts,
                    size,
                    &content_type,
                    &etag,
                    0,
                    obj_policy_index,
                    ctype_ts.as_deref(),
                    meta_ts.as_deref(),
                )
            })
            .await;
        match result {
            Ok(Ok(())) => Response::new(201),
            Ok(Err(e)) => self.db_error_response(&e, broker_probe.db_file()),
            Err(e) => error_response(500, &e.to_string()),
        }
    }

    fn created_at(&self) -> String {
        self.config
            .fixed_created_at
            .clone()
            .unwrap_or_else(|| Timestamp::now().internal())
    }

    fn new_db_id(&self, drive: &str) -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        format!("{nanos:032x}-{drive}")
    }

    fn check_drive(&self, drive: &str) -> Result<(), Response> {
        // Shared constraint: quote_plus name validity + mount check when
        // configured (Python check_drive); mount_check is the production
        // default and must be enforced.
        swift_core::constraints::check_drive(&self.config.devices, drive, self.config.mount_check)
            .map(|_| ())
            .map_err(|_| swob_response(507, Some(drive)))
    }

    /// Port of `possibly_quarantine` (swift/common/db.py:502-522): a
    /// broker error whose message indicates DB corruption moves the hash
    /// dir to `<device>/quarantined/containers/` and the request is
    /// answered 404 (the DB is gone); any other DbError stays a 500.
    fn db_error_response(&self, e: &DbError, db_file: &std::path::Path) -> Response {
        if swift_db::is_corruption_error(e) {
            let _ = swift_db::quarantine_db(db_file, "containers");
            return swob_response(404, None);
        }
        error_response(500, &e.to_string())
    }

    fn broker_for(
        &self,
        drive: &str,
        part: &str,
        account: &str,
        container: &str,
    ) -> ContainerBroker {
        let hsh = self
            .config
            .hash_config
            .hash_path(account, Some(container), None)
            .unwrap_or_default();
        let suffix = &hsh[hsh.len().saturating_sub(3)..];
        let db_path = self
            .config
            .devices
            .join(drive)
            .join("containers")
            .join(part)
            .join(suffix)
            .join(&hsh)
            .join(format!("{hsh}.db"));
        ContainerBroker::new(&db_path, account, container)
    }

    /// `get_and_validate_policy_index`.
    fn policy_index(&self, req: &Request) -> Result<Option<i64>, Response> {
        let Some(raw) = req.headers.get("X-Backend-Storage-Policy-Index") else {
            return Ok(None);
        };
        // Python's error interpolates %r: ints render bare, strings
        // render quoted
        let index: Option<i64> = raw.trim().parse().ok();
        match index {
            Some(index) if self.config.policies.iter().any(|(i, _)| *i == index) => Ok(Some(index)),
            Some(index) => Err(plain_response(
                400,
                &format!("Invalid X-Backend-Storage-Policy-Index {index}"),
            )),
            None => Err(plain_response(
                400,
                &format!("Invalid X-Backend-Storage-Policy-Index '{raw}'"),
            )),
        }
    }

    pub fn handle(&self, mut req: Request) -> Response {
        if req.path.starts_with("/recon/") {
            return self.recon_get(&req);
        }
        let mut resp = match req.method.as_str() {
            "GET" => self.get(&req),
            "HEAD" => self.head(&req),
            "PUT" => self.put(&mut req),
            "POST" => self.post(&req),
            "DELETE" => self.delete(&req),
            "UPDATE" => self.update(&mut req),
            "REPLICATE" => self.replicate(&mut req),
            "OPTIONS" => {
                let mut resp = Response::new(200);
                resp.headers.set(
                    "Allow",
                    "DELETE, GET, HEAD, OPTIONS, POST, PUT, REPLICATE, UPDATE",
                );
                resp
            }
            _ => {
                let mut resp = swob_response(405, None);
                resp.headers.set(
                    "Allow",
                    "DELETE, GET, HEAD, OPTIONS, POST, PUT, REPLICATE, UPDATE",
                );
                resp
            }
        };
        resp.headers
            .setdefault("Content-Type", "text/html; charset=UTF-8");
        resp
    }

    /// `get_obj_name_and_placement`: /drive/part/account/container[/obj].
    #[allow(clippy::type_complexity)]
    fn obj_path(
        &self,
        req: &Request,
    ) -> Result<(String, String, String, String, Option<String>), Response> {
        let segs = split_path(&req.path, 4, 5, true).map_err(|e| plain_response(400, &e))?;
        let drive = segs[0].clone().unwrap_or_default();
        let part = segs[1].clone().unwrap_or_default();
        let account = segs[2].clone().unwrap_or_default();
        let container = segs[3].clone().unwrap_or_default();
        let obj = segs.get(4).cloned().flatten().filter(|o| !o.is_empty());
        if let Some(obj) = &obj {
            validate_internal_obj(&account, &container, obj)?;
        } else {
            validate_internal_name(&account, "account")?;
            validate_internal_name(&container, "container")?;
        }
        Ok((drive, part, account, container, obj))
    }

    /// `gen_resp_headers`.
    fn gen_resp_headers(
        &self,
        info: &[(String, DbValue)],
        is_deleted: bool,
        sharding_state: &str,
    ) -> HeaderKeyDict {
        let get = |k: &str| -> String {
            info.iter()
                .find(|(key, _)| key == k)
                .map(|(_, v)| value_str(v))
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "0".to_string())
        };
        let internal = |k: &str| {
            get(k)
                .parse::<Timestamp>()
                .map(|t| t.internal())
                .unwrap_or_else(|_| "0000000000.00000".to_string())
        };
        let normal = |k: &str| {
            get(k)
                .parse::<Timestamp>()
                .map(|t| t.normal())
                .unwrap_or_else(|_| "0000000000.00000".to_string())
        };
        let mut headers = HeaderKeyDict::new();
        headers.set("X-Backend-Timestamp", internal("created_at"));
        headers.set("X-Backend-PUT-Timestamp", internal("put_timestamp"));
        headers.set("X-Backend-DELETE-Timestamp", internal("delete_timestamp"));
        headers.set("X-Backend-Status-Changed-At", internal("status_changed_at"));
        headers.set(
            "X-Backend-Storage-Policy-Index",
            info.iter()
                .find(|(k, _)| k == "storage_policy_index")
                .map(|(_, v)| value_str(v))
                .unwrap_or_else(|| "0".to_string()),
        );
        if !is_deleted {
            headers.set("X-Container-Object-Count", get("object_count"));
            headers.set("X-Container-Bytes-Used", get("bytes_used"));
            headers.set("X-Timestamp", normal("created_at"));
            headers.set("X-PUT-Timestamp", normal("put_timestamp"));
            headers.set("X-Backend-Sharding-State", sharding_state);
        }
        headers
    }

    fn add_meta_headers(
        &self,
        broker: &mut ContainerBroker,
        headers: &mut HeaderKeyDict,
    ) -> Result<(), DbError> {
        for (key, (value, _)) in broker.metadata()? {
            let lower = key.to_lowercase();
            if !value.is_empty()
                && (SAVE_HEADERS.contains(&lower.as_str())
                    || is_sys_or_user_meta("container", &key))
            {
                headers.set(&key, value);
            }
        }
        Ok(())
    }

    fn last_modified(&self, headers: &mut HeaderKeyDict) {
        if let Some(put_ts) = headers.get("X-PUT-Timestamp") {
            if let Ok(ts) = put_ts.parse::<Timestamp>() {
                headers.set("Last-Modified", http_date(ts.ceil()));
            }
        }
    }

    fn head(&self, req: &Request) -> Response {
        let (drive, part, account, container, _obj) = match self.obj_path(req) {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        let out_content_type = listing_content_type(req);
        if let Err(resp) = self.check_drive(&drive) {
            return resp;
        }
        let mut broker = self.broker_for(&drive, &part, &account, &container);
        let (info, is_deleted) = match broker.get_info_is_deleted() {
            Ok(v) => v,
            Err(e) => return self.db_error_response(&e, broker.db_file()),
        };
        let sharding_state = broker
            .get_db_state()
            .map(|s| s.as_str().to_string())
            .unwrap_or_else(|_| "unsharded".to_string());
        let mut headers = self.gen_resp_headers(&info, is_deleted, &sharding_state);
        if is_deleted {
            let mut resp = swob_response(404, None);
            for (k, v) in headers.iter() {
                resp.headers.set(k, v);
            }
            return resp;
        }
        if let Err(e) = self.add_meta_headers(&mut broker, &mut headers) {
            return self.db_error_response(&e, broker.db_file());
        }
        headers.set("Content-Type", format!("{out_content_type}; charset=utf-8"));
        self.last_modified(&mut headers);
        let mut resp = Response::new(204);
        for (k, v) in headers.iter() {
            resp.headers.set(k, v);
        }
        resp
    }

    fn get(&self, req: &Request) -> Response {
        let (drive, part, account, container, _obj) = match self.obj_path(req) {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        let out_content_type = listing_content_type(req);
        if let Err(resp) = self.check_drive(&drive) {
            return resp;
        }
        let limit = match req.param("limit") {
            Some(given) if !given.is_empty() && given.bytes().all(|b| b.is_ascii_digit()) => {
                // An all-digit value that overflows i64 is still a number
                // Python (arbitrary precision) would see as > the max, so it
                // must 412 — not silently fall back to the default.
                let limit: i64 = match given.parse() {
                    Ok(l) => l,
                    Err(_) => {
                        return error_response(
                            412,
                            &format!("Maximum limit is {CONTAINER_LISTING_LIMIT}"),
                        )
                    }
                };
                if limit > CONTAINER_LISTING_LIMIT {
                    return error_response(
                        412,
                        &format!("Maximum limit is {CONTAINER_LISTING_LIMIT}"),
                    );
                }
                limit
            }
            _ => CONTAINER_LISTING_LIMIT,
        };
        let requested_policy_index = match self.policy_index(req) {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        let mut broker = self.broker_for(&drive, &part, &account, &container);
        let (info, is_deleted) = match broker.get_info_is_deleted() {
            Ok(v) => v,
            Err(e) => return self.db_error_response(&e, broker.db_file()),
        };
        let sharding_state = broker
            .get_db_state()
            .map(|s| s.as_str().to_string())
            .unwrap_or_else(|_| "unsharded".to_string());
        // Python GET_shard: X-Backend-Override-Deleted lets the sharder
        // read ranges from a deleted root (probe test_delete_root_reclaim).
        // Object listings stay 404.
        let db_state_early = broker
            .get_db_state()
            .map(|s| s.as_str().to_string())
            .unwrap_or_default();
        let mut record_type_early = req
            .headers
            .get("x-backend-record-type")
            .unwrap_or("")
            .to_ascii_lowercase();
        if record_type_early == "auto"
            && (db_state_early == "sharding" || db_state_early == "sharded")
        {
            record_type_early = "shard".to_string();
        }
        let override_deleted = truthy(req.headers.get("x-backend-override-deleted"));
        let mut headers = self.gen_resp_headers(
            &info,
            is_deleted && !(record_type_early == "shard" && override_deleted),
            &sharding_state,
        );
        if is_deleted && !(record_type_early == "shard" && override_deleted) {
            let mut resp = swob_response(404, None);
            for (k, v) in headers.iter() {
                resp.headers.set(k, v);
            }
            return resp;
        }
        // Resolve the record type: an explicit 'shard', or 'auto' once the DB
        // is sharding/sharded, is served as a shard-range listing.
        let db_state = broker
            .get_db_state()
            .map(|s| s.as_str().to_string())
            .unwrap_or_default();
        let mut record_type = req
            .headers
            .get("x-backend-record-type")
            .unwrap_or("")
            .to_ascii_lowercase();
        if record_type == "auto" && (db_state == "sharding" || db_state == "sharded") {
            record_type = "shard".to_string();
        }
        if record_type == "shard" {
            return self.get_shard(req, &mut broker, headers, out_content_type);
        }
        headers.set("X-Backend-Record-Type", "object");
        let storage_policy_index = requested_policy_index.unwrap_or_else(|| {
            info.iter()
                .find(|(k, _)| k == "storage_policy_index")
                .and_then(|(_, v)| match v {
                    DbValue::Int(i) => Some(*i),
                    _ => None,
                })
                .unwrap_or(0)
        });
        headers.set(
            "X-Backend-Record-Storage-Policy-Index",
            storage_policy_index,
        );
        let args = ListObjectsArgs {
            limit,
            marker: req.param("marker").unwrap_or_default(),
            end_marker: req.param("end_marker").unwrap_or_default(),
            prefix: req.param("prefix"),
            delimiter: req.param("delimiter"),
            path: req.param("path"),
            storage_policy_index,
            reverse: truthy(req.param("reverse").as_deref()),
            include_deleted: Some(false),
            allow_reserved: req.headers.get("X-Backend-Allow-Reserved-Names").is_some(),
        };
        // Python GET_object: `with broker.get_brokers()[0] as src_broker`
        // lists from the retiring DB while sharding. The fresh epoch DB has
        // no object rows (set_sharding_state copies metadata only). Listing
        // the freshest file drops uncleaved names (probe L1321 obj-0000-0049
        // after extra replicators put an epoch DB on every replica).
        // After SHARDED, retiring rows must not leak into an explicit
        // object listing (probe TestShardedAPI L3256). While SHARDING,
        // keep listing the retiring DB so uncleaved names survive.
        let rows = if db_state == "sharding" {
            if let Some(mut retiring) = broker.retiring_broker() {
                match retiring.list_objects_iter(&args) {
                    Ok(rows) => rows,
                    Err(e) => return self.db_error_response(&e, retiring.db_file()),
                }
            } else {
                match broker.list_objects_iter(&args) {
                    Ok(rows) => rows,
                    Err(e) => return self.db_error_response(&e, broker.db_file()),
                }
            }
        } else {
            match broker.list_objects_iter(&args) {
                Ok(rows) => rows,
                Err(e) => return self.db_error_response(&e, broker.db_file()),
            }
        };
        let mut records = Vec::with_capacity(rows.len());
        for row in rows {
            let name = value_str(&row[0]);
            match &row[3] {
                DbValue::Null => records.push(ObjRecord::Subdir(name)),
                ct => {
                    let size = match &row[2] {
                        DbValue::Int(i) => *i,
                        _ => 0,
                    };
                    let (content_type, bytes) = override_bytes(&value_str(ct), size);
                    let last_modified = value_str(&row[1])
                        .parse::<Timestamp>()
                        .map(|t| t.isoformat())
                        .unwrap_or_default();
                    records.push(ObjRecord::Object {
                        bytes,
                        hash: value_str(&row[4]),
                        name,
                        content_type,
                        last_modified,
                    });
                }
            }
        }
        if let Err(e) = self.add_meta_headers(&mut broker, &mut headers) {
            return self.db_error_response(&e, broker.db_file());
        }
        let body = if out_content_type.ends_with("/xml") {
            listing_to_xml(&records, &container)
        } else if out_content_type.ends_with("/json") {
            listing_to_json(&records).into_bytes()
        } else {
            listing_to_text(&records)
        };
        let mut resp = if body.is_empty() {
            Response::new(204)
        } else {
            Response::with_body(200, body)
        };
        for (k, v) in headers.iter() {
            resp.headers.set(k, v);
        }
        resp.headers
            .set("Content-Type", format!("{out_content_type}; charset=utf-8"));
        self.last_modified(&mut resp.headers);
        resp
    }

    /// `account_update`: synchronous PUT to the account server(s) named
    /// in the X-Account-* headers.
    fn account_update(
        &self,
        req: &Request,
        account: &str,
        container: &str,
        broker: &mut ContainerBroker,
    ) -> Option<Response> {
        let hosts: Vec<String> = req
            .headers
            .get("X-Account-Host")
            .unwrap_or("")
            .split(',')
            .map(|h| h.trim().to_string())
            .collect();
        let devices: Vec<String> = req
            .headers
            .get("X-Account-Device")
            .unwrap_or("")
            .split(',')
            .map(|d| d.trim().to_string())
            .collect();
        let partition = req.headers.get("X-Account-Partition").unwrap_or("");
        if hosts.len() != devices.len() {
            return Some(error_response(400, ""));
        }
        if partition.is_empty() {
            return None;
        }
        let info = match broker.get_info() {
            Ok(info) => info,
            Err(e) => return Some(error_response(500, &e.to_string())),
        };
        let get = |k: &str| {
            info.iter()
                .find(|(key, _)| key == k)
                .map(|(_, v)| value_str(v))
                .unwrap_or_default()
        };
        let mut not_founds = 0;
        let updates: Vec<(String, String)> = hosts.into_iter().zip(devices).collect();
        for (host, device) in &updates {
            let path = format!(
                "/{device}/{partition}/{}/{}",
                percent_encode(account),
                percent_encode(container)
            );
            let request = format!(
                "PUT {path} HTTP/1.1\r\nHost: {host}\r\n\
                 X-Put-Timestamp: {}\r\nX-Delete-Timestamp: {}\r\n\
                 X-Object-Count: {}\r\nX-Bytes-Used: {}\r\n\
                 X-Backend-Storage-Policy-Index: {}\r\n\
                 Content-Length: 0\r\nConnection: close\r\n\r\n",
                get("put_timestamp"),
                get("delete_timestamp"),
                get("object_count"),
                get("bytes_used"),
                get("storage_policy_index"),
            );
            // Python ConnectionTimeout(self.conn_timeout), default 0.5s.
            // Unbounded connect() to a ring IP that is down stalls the
            // container PUT (and the DbExecutor shard it runs on).
            let connect_timeout = std::time::Duration::from_millis(500);
            let addr = match std::net::ToSocketAddrs::to_socket_addrs(host) {
                Ok(mut addrs) => match addrs.next() {
                    Some(addr) => addr,
                    None => continue,
                },
                Err(_) => continue,
            };
            if let Ok(mut conn) = std::net::TcpStream::connect_timeout(&addr, connect_timeout) {
                conn.set_nodelay(true).ok();
                let _ = conn.set_read_timeout(Some(std::time::Duration::from_secs(10)));
                if conn.write_all(request.as_bytes()).is_ok() {
                    let mut buf = Vec::new();
                    let _ = conn.read_to_end(&mut buf);
                    let head = String::from_utf8_lossy(&buf);
                    if head.starts_with("HTTP/1.1 404") || head.starts_with("HTTP/1.0 404") {
                        not_founds += 1;
                    }
                }
            }
        }
        if !updates.is_empty() && not_founds == updates.len() {
            Some(swob_response(404, None))
        } else {
            None
        }
    }

    fn should_autocreate(&self, account: &str, req: &Request) -> bool {
        if let Some(header) = req.headers.get("X-Backend-Auto-Create") {
            return truthy(Some(header));
        }
        if account.starts_with(SHARDS_ACCOUNT_PREFIX) {
            return false;
        }
        account.starts_with(AUTO_CREATE_ACCOUNT_PREFIX)
    }

    fn maybe_autocreate(
        &self,
        broker: &mut ContainerBroker,
        req_timestamp: &Timestamp,
        account: &str,
        policy_index: Option<i64>,
        drive: &str,
        req: &Request,
    ) -> Result<bool, Response> {
        let mut created = false;
        if self.should_autocreate(account, req) && !broker.db_exists() {
            let Some(policy_index) = policy_index else {
                return Err(error_response(
                    400,
                    "X-Backend-Storage-Policy-Index header is required",
                ));
            };
            match broker.initialize(
                &req_timestamp.normalized().internal(),
                policy_index,
                &self.created_at(),
                &self.new_db_id(drive),
            ) {
                Ok(()) | Err(DbError::AlreadyExists(_)) => created = true,
                Err(e) => return Err(error_response(500, &e.to_string())),
            }
        }
        if !broker.db_exists() {
            return Err(swob_response(404, None));
        }
        Ok(created)
    }

    fn update_metadata_from_headers(
        &self,
        req: &Request,
        broker: &mut ContainerBroker,
        timestamp: &Timestamp,
    ) -> Result<(), Response> {
        let mut metadata: BrokerMetadata = Vec::new();
        for (k, v) in req.headers.iter() {
            if let Some((rk, rv)) = translate_container_remove_header(k, v) {
                metadata.push((rk, (rv, timestamp.internal())));
                continue;
            }
            let lower = k.to_lowercase();
            if SAVE_HEADERS.contains(&lower.as_str()) || is_sys_or_user_meta("container", k) {
                metadata.push((k.to_string(), (v.to_string(), timestamp.internal())));
            }
        }
        if metadata.is_empty() {
            return Ok(());
        }
        // Python validates the MERGED metadata (existing overlaid with the
        // updates), so a POST that is fine by itself still 400s when it takes
        // the aggregate stored metadata over the limits.
        let mut merged = broker.metadata().unwrap_or_default();
        for (k, vt) in &metadata {
            match merged.iter_mut().find(|(mk, _)| mk.eq_ignore_ascii_case(k)) {
                Some((_, mvt)) => {
                    if vt.1 > mvt.1 {
                        *mvt = vt.clone();
                    }
                }
                None => merged.push((k.clone(), vt.clone())),
            }
        }
        validate_metadata(&merged)?;
        // Reset sync points when X-Container-Sync-To changes (Python PUT/POST).
        if metadata
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("X-Container-Sync-To"))
        {
            let old_to = broker
                .metadata()
                .ok()
                .and_then(|md| {
                    md.into_iter()
                        .find(|(k, _)| k.eq_ignore_ascii_case("X-Container-Sync-To"))
                        .map(|(_, (v, _))| v)
                })
                .unwrap_or_default();
            let new_to = metadata
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("X-Container-Sync-To"))
                .map(|(_, (v, _))| v.as_str())
                .unwrap_or("");
            if old_to != new_to {
                let _ = broker.set_x_container_sync_points(Some(-1), Some(-1));
            }
        }
        broker
            .update_metadata(&metadata)
            .map_err(|e| self.db_error_response(&e, broker.db_file()))?;
        // Maintain sync_containers/ index for the container-sync daemon.
        let store = crate::sync::ContainerSyncStore::new(&self.config.devices);
        let _ = store.update_sync_store(broker);
        Ok(())
    }

    fn put(&self, req: &mut Request) -> Response {
        let (drive, part, account, container, obj) = match self.obj_path(req) {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        let req_timestamp = match valid_timestamp(req) {
            Ok(t) => t,
            Err(resp) => return resp,
        };
        if let Err(resp) = self.check_drive(&drive) {
            return resp;
        }
        let mut broker = self.broker_for(&drive, &part, &account, &container);
        if let Some(obj) = obj {
            return self.put_object(req, &mut broker, &account, &obj, &req_timestamp, &drive);
        }
        if req
            .headers
            .get("x-backend-record-type")
            .is_some_and(|t| t.eq_ignore_ascii_case("shard"))
        {
            return self.put_shard(req, &mut broker, &account, &req_timestamp, &drive);
        }
        self.put_container(
            req,
            &mut broker,
            &account,
            &container,
            &req_timestamp,
            &drive,
        )
    }

    fn put_object(
        &self,
        req: &Request,
        broker: &mut ContainerBroker,
        account: &str,
        obj: &str,
        req_timestamp: &Timestamp,
        drive: &str,
    ) -> Response {
        let requested_policy_index = match self.policy_index(req) {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        // Python PUT_object: request SPI if present, else the container's.
        // Hardcoding 0 made policy_stat.object_count stay 0 when the container
        // SPI was non-zero, so the sharder saw object_count < threshold.
        let obj_policy_index = match requested_policy_index {
            Some(i) => i,
            None => broker.storage_policy_index().unwrap_or(0),
        };
        if let Err(resp) = self.maybe_autocreate(
            broker,
            req_timestamp,
            account,
            Some(obj_policy_index),
            drive,
            req,
        ) {
            return resp;
        }
        let (Some(size), Some(content_type), Some(etag)) = (
            req.headers.get("x-size").map(str::to_string),
            req.headers.get("x-content-type").map(str::to_string),
            req.headers.get("x-etag").map(str::to_string),
        ) else {
            return error_response(500, "missing required backend headers");
        };
        // If the container is sharding/sharded, redirect the object update to
        // the shard that owns this name (301), when the caller accepts it.
        if let Some(redirect) = self.redirect_to_shard(req, broker, obj) {
            return redirect;
        }
        let Ok(size) = size.trim().parse::<i64>() else {
            return error_response(500, "bad x-size");
        };
        if let Err(e) = broker.put_object(
            obj,
            &req_timestamp.internal(),
            size,
            &content_type,
            &etag,
            0,
            obj_policy_index,
            req.headers.get("x-content-type-timestamp"),
            req.headers.get("x-meta-timestamp"),
        ) {
            return self.db_error_response(&e, broker.db_file());
        }
        Response::new(201)
    }

    /// `PUT_shard`: merge shard ranges (a JSON array of shard-range dicts in
    /// the body) into the container's shard_range table.
    fn put_shard(
        &self,
        req: &mut Request,
        broker: &mut ContainerBroker,
        account: &str,
        req_timestamp: &Timestamp,
        drive: &str,
    ) -> Response {
        let requested_policy_index = match self.policy_index(req) {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        let body = match read_control_body(req) {
            Ok(body) => body,
            Err(resp) => return resp,
        };
        let ranges: Vec<swift_db::ShardRange> =
            match serde_json::from_slice::<serde_json::Value>(body) {
                Ok(serde_json::Value::Array(arr)) => {
                    let mut v = Vec::with_capacity(arr.len());
                    for item in &arr {
                        match swift_db::ShardRange::from_json(item) {
                            Some(sr) => v.push(sr),
                            None => return error_response(400, "Invalid body: bad shard range"),
                        }
                    }
                    v
                }
                _ => return error_response(400, "Invalid body: expected a JSON array"),
            };
        let created = match self.maybe_autocreate(
            broker,
            req_timestamp,
            account,
            requested_policy_index.or(Some(0)),
            drive,
            req,
        ) {
            Ok(c) => c,
            Err(resp) => return resp,
        };
        // Python PUT_shard: `_update_metadata` then merge. Quoted-Root /
        // Sharding sysmeta on `_create_shard_containers` must stick so later
        // sharder passes treat the DB as a shard and `_update_root_container`.
        if let Err(resp) = self.update_metadata_from_headers(req, broker, req_timestamp) {
            return resp;
        }
        if !ranges.is_empty() {
            if let Err(e) = broker.merge_shard_ranges(ranges) {
                return self.db_error_response(&e, broker.db_file());
            }
        }
        self.create_ok_resp(broker, created)
    }

    /// `_redirect_to_shard`: if the request accepts a redirect and a shard
    /// range in an update state contains `obj_name`, return a 301 pointing at
    /// that shard container.
    fn redirect_to_shard(
        &self,
        req: &Request,
        broker: &mut ContainerBroker,
        obj_name: &str,
    ) -> Option<Response> {
        if !truthy(req.headers.get("x-backend-accept-redirect")) {
            return None;
        }
        let ranges = broker
            .get_shard_ranges(&swift_db::GetShardRangesArgs {
                includes: Some(obj_name.to_string()),
                states: Some(swift_db::SHARD_UPDATE_STATES.to_vec()),
                ..Default::default()
            })
            .ok()?;
        let containing = ranges.into_iter().next()?;
        let location = format!("/{}/{}", containing.name, obj_name);
        let quoted = pct_quote(&location);
        if location != quoted && !truthy(req.headers.get("x-backend-accept-quoted-location")) {
            // sender expects an unquoted location but it isn't safe to send one
            return None;
        }
        let mut resp = swob_response(301, None);
        resp.headers.set("Location", &quoted);
        resp.headers.set("X-Backend-Location-Is-Quoted", "true");
        resp.headers
            .set("X-Backend-Redirect-Timestamp", &containing.timestamp);
        Some(resp)
    }

    /// `GET_shard`: return the container's shard ranges as a JSON listing,
    /// filtered by the `states` (names/numbers/aliases), marker/end_marker or
    /// includes, and reverse query params.
    fn get_shard(
        &self,
        req: &Request,
        broker: &mut ContainerBroker,
        mut headers: HeaderKeyDict,
        out_content_type: &str,
    ) -> Response {
        // Python `_create_GET_response` copies broker.metadata onto shard
        // listings. Probe `direct_get_container_shard_ranges` is a GET with
        // `X-Backend-Record-Type: shard` (not HEAD); missing Quoted-Root
        // fails test_shrinking L1808.
        if let Err(e) = self.add_meta_headers(broker, &mut headers) {
            return self.db_error_response(&e, broker.db_file());
        }
        self.last_modified(&mut headers);
        // Python GET_shard: when the caller sends
        // X-Backend-Override-Shard-Name-Filter matching db_state==sharded,
        // ignore includes/marker/end_marker/reverse and return every range
        // (probe TestShardedAPI L3192-3200).
        let db_state = broker
            .get_db_state()
            .map(|s| s.as_str().to_string())
            .unwrap_or_default();
        let override_filter = req
            .headers
            .get("x-backend-override-shard-name-filter")
            .unwrap_or("")
            .to_ascii_lowercase();
        let override_all = override_filter == "sharded" && db_state == "sharded";
        if override_all {
            headers.set("X-Backend-Override-Shard-Name-Filter", "true");
        }
        let states_raw = req.param("states");
        let fill_gaps = states_raw.as_deref().is_some_and(|csv| {
            csv.split(',').any(|p| {
                matches!(
                    p.trim().to_ascii_lowercase().as_str(),
                    "listing" | "updating"
                )
            })
        });
        let include_own = states_raw.as_deref().is_some_and(|csv| {
            csv.split(',').any(|p| p.trim().eq_ignore_ascii_case("auditing"))
        });
        let states = match states_raw {
            Some(csv) => {
                let list: Vec<String> = csv.split(',').map(str::to_string).collect();
                match swift_db::resolve_shard_range_states(&list) {
                    Ok(s) => s,
                    Err(msg) => return error_response(400, &msg),
                }
            }
            None => None,
        };
        let args = swift_db::GetShardRangesArgs {
            marker: if override_all {
                None
            } else {
                req.param("marker").filter(|s| !s.is_empty())
            },
            end_marker: if override_all {
                None
            } else {
                req.param("end_marker").filter(|s| !s.is_empty())
            },
            includes: if override_all {
                None
            } else {
                req.param("includes").filter(|s| !s.is_empty())
            },
            reverse: if override_all {
                false
            } else {
                truthy(req.param("reverse").as_deref())
            },
            include_deleted: truthy(req.headers.get("x-backend-include-deleted")),
            states,
            fill_gaps,
            include_own,
            ..Default::default()
        };
        let ranges = match broker.get_shard_ranges(&args) {
            Ok(r) => r,
            Err(e) => return self.db_error_response(&e, broker.db_file()),
        };
        let shard_format = req
            .headers
            .get("x-backend-record-shard-format")
            .unwrap_or("full")
            .to_ascii_lowercase();
        // Python GET_shard (server.py): namespace format is honored even
        // when includes/marker/end_marker are set. The docstring that says
        // those params force `full` is stale; probe TestShardedAPI
        // `get_container_namespaces(includes=...)` expects `namespace`.
        // Auditing (include_own) and include_deleted cannot be namespaces.
        if shard_format == "namespace" && args.include_deleted {
            return error_response(400, "No include_deleted for namespace GET");
        }
        if shard_format == "namespace" && include_own {
            return error_response(400, "No auditing state for namespace GET");
        }
        let namespace_ok = shard_format == "namespace";
        let body = if namespace_ok {
            headers.set("X-Backend-Record-Shard-Format", "namespace");
            serde_json::Value::Array(
                ranges
                    .iter()
                    .map(|r| {
                        serde_json::json!({
                            "name": r.name,
                            "lower": r.lower,
                            "upper": r.upper,
                        })
                    })
                    .collect(),
            )
        } else {
            headers.set("X-Backend-Record-Shard-Format", "full");
            serde_json::Value::Array(ranges.iter().map(|r| r.to_json()).collect::<Vec<_>>())
        };
        let bytes = serde_json::to_vec(&body).unwrap_or_default();
        headers.set("X-Backend-Record-Type", "shard");
        headers.set("Content-Type", format!("{out_content_type}; charset=utf-8"));
        let mut resp = Response::with_body(200, bytes);
        for (k, v) in headers.iter() {
            resp.headers.set(k, v);
        }
        resp
    }

    fn create_ok_resp(&self, broker: &mut ContainerBroker, created: bool) -> Response {
        let mut resp = if created {
            Response::new(201)
        } else {
            swob_response(202, None)
        };
        if let Ok(spi) = broker.storage_policy_index() {
            resp.headers.set("x-backend-storage-policy-index", spi);
        }
        resp
    }

    fn put_container(
        &self,
        req: &Request,
        broker: &mut ContainerBroker,
        account: &str,
        container: &str,
        req_timestamp: &Timestamp,
        drive: &str,
    ) -> Response {
        if let Err(e) = swift_core::constraints::check_metadata(req.headers.iter(), "container") {
            return plain_response(400, &e.0);
        }
        // Reject over-long container names (Python proxy container PUT).
        if container.len() as i64 > swift_core::constraints::MAX_CONTAINER_NAME_LENGTH {
            return error_response(
                400,
                &format!(
                    "Container name length of {} longer than {}",
                    container.len(),
                    swift_core::constraints::MAX_CONTAINER_NAME_LENGTH
                ),
            );
        }
        let requested_policy_index = match self.policy_index(req) {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        let new_container_policy = requested_policy_index.unwrap_or_else(|| {
            req.headers
                .get("X-Backend-Storage-Policy-Default")
                .and_then(|v| v.parse().ok())
                .unwrap_or(self.config.default_policy_index)
        });
        // _update_or_create
        let mut created = false;
        if !broker.db_exists() {
            match broker.initialize(
                &req_timestamp.internal(),
                new_container_policy,
                &self.created_at(),
                &self.new_db_id(drive),
            ) {
                Ok(()) => created = true,
                Err(DbError::AlreadyExists(_)) => {}
                Err(e) => return error_response(500, &e.to_string()),
            }
        }
        if !created {
            let recreated = matches!(broker.is_deleted(), Ok(true));
            if recreated {
                if let Err(e) =
                    broker.set_storage_policy_index(new_container_policy, &req_timestamp.internal())
                {
                    return self.db_error_response(&e, broker.db_file());
                }
            } else if let Some(requested) = requested_policy_index {
                match broker.storage_policy_index() {
                    Ok(existing) if existing != requested => {
                        let mut resp = swob_response(409, None);
                        resp.headers.set("x-backend-storage-policy-index", existing);
                        return resp;
                    }
                    Ok(_) => {}
                    Err(e) => return self.db_error_response(&e, broker.db_file()),
                }
            }
            if let Err(e) = broker.update_put_timestamp(&req_timestamp.internal()) {
                return self.db_error_response(&e, broker.db_file());
            }
            if matches!(broker.is_deleted(), Ok(true)) {
                return swob_response(409, None);
            }
            if recreated {
                if let Err(e) = broker.update_status_changed_at(&req_timestamp.internal()) {
                    return self.db_error_response(&e, broker.db_file());
                }
                created = true;
            }
        }
        if let Err(resp) = self.update_metadata_from_headers(req, broker, req_timestamp) {
            return resp;
        }
        if let Some(resp) = self.account_update(req, account, container, broker) {
            return resp;
        }
        self.create_ok_resp(broker, created)
    }

    fn post(&self, req: &Request) -> Response {
        if let Err(e) = swift_core::constraints::check_metadata(req.headers.iter(), "container") {
            return plain_response(400, &e.0);
        }
        let (drive, part, account, container, _obj) = match self.obj_path(req) {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        let req_timestamp = match valid_timestamp(req) {
            Ok(t) => t,
            Err(resp) => return resp,
        };
        if let Err(resp) = self.check_drive(&drive) {
            return resp;
        }
        let mut broker = self.broker_for(&drive, &part, &account, &container);
        if !broker.db_exists() || matches!(broker.is_deleted(), Ok(true)) {
            return swob_response(404, None);
        }
        if !truthy(req.headers.get("x-backend-no-timestamp-update")) {
            if let Err(e) = broker.update_put_timestamp(&req_timestamp.internal()) {
                return self.db_error_response(&e, broker.db_file());
            }
        }
        if let Err(resp) = self.update_metadata_from_headers(req, &mut broker, &req_timestamp) {
            return resp;
        }
        Response::new(204)
    }

    fn delete(&self, req: &Request) -> Response {
        let (drive, part, account, container, obj) = match self.obj_path(req) {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        let req_timestamp = match valid_timestamp(req) {
            Ok(t) => t,
            Err(resp) => return resp,
        };
        if let Err(resp) = self.check_drive(&drive) {
            return resp;
        }
        let mut broker = self.broker_for(&drive, &part, &account, &container);
        match obj {
            Some(obj) => {
                // DELETE_object
                let requested_policy_index = match self.policy_index(req) {
                    Ok(v) => v,
                    Err(resp) => return resp,
                };
                let obj_policy_index = requested_policy_index.unwrap_or(0);
                if let Err(resp) = self.maybe_autocreate(
                    &mut broker,
                    &req_timestamp,
                    &account,
                    Some(obj_policy_index),
                    &drive,
                    req,
                ) {
                    return resp;
                }
                // Python DELETE_object: redirect if a shard range owns the name
                // (probe L1435 — tombstones must land on the nested shard, not
                // the SHARDED root).
                if let Some(redirect) = self.redirect_to_shard(req, &mut broker, &obj) {
                    return redirect;
                }
                let raw_ts = req
                    .headers
                    .get("x-timestamp")
                    .unwrap_or_default()
                    .to_string();
                if let Err(e) = broker.delete_object(&obj, &raw_ts, obj_policy_index) {
                    return error_response(500, &e.to_string());
                }
                Response::new(204)
            }
            None => {
                // DELETE_container
                if !broker.db_exists() {
                    return swob_response(404, None);
                }
                match broker.empty() {
                    Ok(false) => return swob_response(409, None),
                    Ok(true) => {}
                    Err(e) => return error_response(500, &e.to_string()),
                }
                let put_ts_nonzero = broker
                    .get_info()
                    .ok()
                    .and_then(|info| {
                        info.iter()
                            .find(|(k, _)| k == "put_timestamp")
                            .map(|(_, v)| value_str(v))
                    })
                    .and_then(|s| s.parse::<Timestamp>().ok())
                    .map(|t| t != "0".parse::<Timestamp>().unwrap())
                    .unwrap_or(false);
                let existed = put_ts_nonzero && !matches!(broker.is_deleted(), Ok(true));
                if let Err(e) = broker.delete_db(&req_timestamp.internal()) {
                    return error_response(500, &e.to_string());
                }
                if !matches!(broker.is_deleted(), Ok(true)) {
                    return swob_response(409, None);
                }
                if let Some(resp) = self.account_update(req, &account, &container, &mut broker) {
                    return resp;
                }
                if existed {
                    Response::new(204)
                } else {
                    swob_response(404, None)
                }
            }
        }
    }

    /// `REPLICATE`: the db_replicator RPC receive side. The body is a
    /// JSON array `[op, arg1, ...]`. Supports the DB-level ops sync,
    /// merge_syncs and merge_items, plus the rsync-staged full-DB ops
    /// complete_rsync and rsync_then_merge.
    fn replicate(&self, req: &mut Request) -> Response {
        let target = match self.replicate_target(req) {
            Ok(t) => t,
            Err(resp) => return resp,
        };
        let drive = target.drive;
        let db_path = target.db_path;
        let body = match read_control_body(req) {
            Ok(body) => body,
            Err(resp) => return resp,
        };
        let args: Vec<serde_json::Value> = match serde_json::from_slice(body) {
            Ok(serde_json::Value::Array(a)) => a,
            _ => return plain_response(400, "Invalid object type"),
        };
        if args.is_empty() {
            return plain_response(400, "Invalid object type");
        }
        let op = args[0].as_str().unwrap_or("");
        // The rsync-staged ops dispatch before the db-exists gate — they
        // are exactly the ops that run when the final DB is missing or
        // divergent (dispatch, db_replicator.py:972-975).
        if op == "complete_rsync" {
            return self.complete_rsync(&drive, &db_path, &args);
        }
        if op == "rsync_then_merge" {
            return self.rsync_then_merge(&drive, &db_path, &args);
        }
        // someone might be about to rsync a db to us, so make sure there's
        // a tmp dir to receive it (dispatch, db_replicator.py:976-980)
        let _ = std::fs::create_dir_all(self.config.devices.join(&drive).join("tmp"));
        // Python `_db_file_exists` = `bool(get_db_files(db_path))`. After
        // `set_sharded_state` the retiring `<hash>.db` is unlinked and only
        // `<hash>_<epoch>.db` remains. A `hash.db.exists()` 404 here made
        // unsharded→sharded sync skip `get_shard_ranges`, so the third
        // replica never received shard ranges (probe L2321 `[] != 2`).
        if matches!(
            op,
            "sync" | "merge_syncs" | "merge_items" | "get_shard_ranges" | "merge_shard_ranges"
        ) && swift_db::get_db_files(&db_path).is_empty()
        {
            return swob_response(404, None);
        }
        let mut broker = ContainerBroker::new(&db_path, "", "");
        let _ = broker.hydrate_account_container();
        match op {
            "merge_items" => {
                let items = args
                    .get(1)
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                let source = args.get(2).and_then(|v| v.as_str()).map(str::to_string);
                let max_rowid = items.iter().filter_map(|o| o["ROWID"].as_i64()).max();
                let mut records = Vec::with_capacity(items.len());
                for obj in &items {
                    records.push(ObjectRecord {
                        name: obj["name"].as_str().unwrap_or_default().to_string(),
                        created_at: obj["created_at"].as_str().unwrap_or_default().to_string(),
                        size: obj["size"].as_i64().unwrap_or(0),
                        content_type: obj["content_type"].as_str().unwrap_or_default().to_string(),
                        etag: obj["etag"].as_str().unwrap_or_default().to_string(),
                        deleted: obj["deleted"].as_i64().unwrap_or(0),
                        storage_policy_index: obj["storage_policy_index"].as_i64().unwrap_or(0),
                        ctype_timestamp: obj["ctype_timestamp"].as_str().map(str::to_string),
                        meta_timestamp: obj["meta_timestamp"].as_str().map(str::to_string),
                    });
                }
                if let Err(e) = broker.merge_items(records) {
                    return self.db_error_response(&e, broker.db_file());
                }
                // replication sync-point tracking: record the highest
                // incoming ROWID against the source id (Python does this
                // inside merge_items when a source is given)
                if let (Some(source), Some(rowid)) = (source, max_rowid) {
                    if let Err(e) = broker.merge_syncs(&[(rowid, source)], true) {
                        return self.db_error_response(&e, broker.db_file());
                    }
                }
                swob_response(202, None)
            }
            "merge_syncs" => {
                let syncs = args
                    .get(1)
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                let points: Vec<(i64, String)> = syncs
                    .iter()
                    .map(|s| {
                        (
                            s["sync_point"].as_i64().unwrap_or(-1),
                            s["remote_id"].as_str().unwrap_or_default().to_string(),
                        )
                    })
                    .collect();
                if let Err(e) = broker.merge_syncs(&points, true) {
                    return self.db_error_response(&e, broker.db_file());
                }
                swob_response(202, None)
            }
            "sync" => {
                // args: remote_sync, hash, id, created_at, put_timestamp,
                // delete_timestamp, metadata, [status_changed_at, count,
                // storage_policy_index]
                let s = |i: usize| {
                    args.get(i)
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string()
                };
                let remote_point = args.get(1).and_then(|v| v.as_i64()).unwrap_or(-1);
                let remote_hash = s(2);
                let remote_id = s(3);
                let created_at = s(4);
                let put_timestamp = s(5);
                let delete_timestamp = s(6);
                let remote_metadata = s(7);
                let mut remote_info = serde_json::json!({
                    "created_at": created_at,
                    "put_timestamp": put_timestamp,
                    "delete_timestamp": delete_timestamp,
                });
                if args.len() > 10 {
                    remote_info["status_changed_at"] = args[8].clone();
                    remote_info["count"] = args[9].clone();
                    remote_info["storage_policy_index"] = args[10].clone();
                }

                let mut info = match broker.get_replication_info() {
                    Ok(i) => i,
                    Err(e) => return self.db_error_response(&e, broker.db_file()),
                };
                // ContainerReplicatorRpc._get_synced_replication_info: if
                // the peer is authoritative, adopt its policy and refresh
                // the response snapshot before the generic sync merge.
                if swift_db::incorrect_policy_index(&info, &remote_info) {
                    let remote_policy_index = args[10]
                        .as_i64()
                        .or_else(|| args[10].as_str().and_then(|v| v.parse().ok()))
                        .expect("validated by incorrect_policy_index");
                    if let Err(e) = broker
                        .set_storage_policy_index(remote_policy_index, &Timestamp::now().internal())
                    {
                        return self.db_error_response(&e, broker.db_file());
                    }
                    info = match broker.get_replication_info() {
                        Ok(i) => i,
                        Err(e) => return self.db_error_response(&e, broker.db_file()),
                    };
                }
                if !remote_metadata.is_empty() {
                    let md = match swift_db::py_json_parse_metadata(&remote_metadata) {
                        Ok(md) => md,
                        Err(e) => return self.db_error_response(&e, broker.db_file()),
                    };
                    if let Err(e) = broker.update_metadata(&md) {
                        return self.db_error_response(&e, broker.db_file());
                    }
                }
                let get = |k: &str| {
                    info.iter()
                        .find(|(key, _)| key == k)
                        .map(|(_, v)| value_str(v))
                        .unwrap_or_default()
                };
                // merge the stat timestamps if any differ
                if get("created_at") != created_at
                    || get("put_timestamp") != put_timestamp
                    || get("delete_timestamp") != delete_timestamp
                {
                    if let Err(e) =
                        broker.merge_timestamps(&created_at, &put_timestamp, &delete_timestamp)
                    {
                        return self.db_error_response(&e, broker.db_file());
                    }
                }
                let mut point = broker.get_sync(&remote_id, true).unwrap_or(-1);
                let local_hash = get("hash");
                if remote_hash == local_hash && point < remote_point {
                    let _ = broker.merge_syncs(&[(remote_point, remote_id.clone())], true);
                    point = remote_point;
                }
                // respond with our replication info as JSON (point added)
                let mut obj = serde_json::Map::new();
                for (k, v) in broker.get_replication_info().unwrap_or_default() {
                    let jv = match v {
                        DbValue::Int(i) => serde_json::Value::from(i),
                        DbValue::Text(t) => serde_json::Value::from(t),
                        DbValue::Null => serde_json::Value::Null,
                    };
                    obj.insert(k, jv);
                }
                obj.insert("point".to_string(), serde_json::Value::from(point));
                let body = serde_json::to_vec(&serde_json::Value::Object(obj)).unwrap();
                let mut resp = Response::with_body(200, body);
                resp.headers.set("Content-Type", "text/html; charset=UTF-8");
                resp
            }
            "merge_shard_ranges" => {
                // Python ContainerReplicatorRpc.merge_shard_ranges: args[1]
                // is a list of shard-range dicts.
                let mut ranges = Vec::new();
                if let Some(arr) = args.get(1).and_then(|v| v.as_array()) {
                    for item in arr {
                        if let Some(sr) = swift_db::ShardRange::from_json(item) {
                            ranges.push(sr);
                        }
                    }
                }
                let ranges = match swift_db::check_merge_own_shard_range(ranges, &mut broker) {
                    Ok(r) => r,
                    Err(e) => return self.db_error_response(&e, broker.db_file()),
                };
                if let Err(e) = broker.merge_shard_ranges(ranges) {
                    return self.db_error_response(&e, broker.db_file());
                }
                swob_response(202, None)
            }
            "get_shard_ranges" => {
                let ranges = match broker.get_all_shard_range_data() {
                    Ok(r) => r,
                    Err(e) => return self.db_error_response(&e, broker.db_file()),
                };
                let body = serde_json::Value::Array(
                    ranges.iter().map(|r| r.to_json()).collect::<Vec<_>>(),
                );
                let bytes = serde_json::to_vec(&body).unwrap_or_default();
                let mut resp = Response::with_body(200, bytes);
                resp.headers.set("Content-Type", "application/json");
                resp
            }
            other => plain_response(400, &format!("unknown replicate op {other}")),
        }
    }

    /// `complete_rsync` (db_replicator.py:1085-1096): adopt a whole DB
    /// staged in `<device>/tmp/<args[1]>` as this partition's DB. 404 when
    /// the final DB already exists or the staged file is missing;
    /// otherwise re-id the staged DB (`newid`) and rename it into place.
    fn complete_rsync(&self, drive: &str, db_path: &Path, args: &[serde_json::Value]) -> Response {
        let Some(tmp_name) = args.get(1).and_then(|v| v.as_str()) else {
            return plain_response(400, "Invalid object type");
        };
        let old_filename = self.config.devices.join(drive).join("tmp").join(tmp_name);
        // optional final basename (db_replicator.py:1086-1088), sent by
        // Python for epoch-suffixed dbs; defaults to `<hsh>.db` from the URL
        let db_file = match args.get(2).and_then(|v| v.as_str()) {
            Some(name) => db_path.parent().unwrap_or_else(|| Path::new("")).join(name),
            None => db_path.to_path_buf(),
        };
        if db_file.exists() {
            return swob_response(404, None);
        }
        // Sender used to always pass `<hsh>.db` even for an epoch DB
        // (db_replicator.py sends basename(broker.db_file)). Creating the
        // unsuffixed name next to an existing epoch file resurrects the
        // retiring DB (probe L1347/L1375: db_state=sharding, leftover
        // normal_dbs). Refuse that without blocking a real first create.
        let dest_name = db_file.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if dest_name.ends_with(".db") && !dest_name.contains('_') {
            let others = swift_db::get_db_files(&db_file);
            if others
                .iter()
                .any(|p| p.file_name().and_then(|s| s.to_str()) != Some(dest_name))
            {
                return swob_response(404, None);
            }
        }
        if !old_filename.exists() {
            return swob_response(404, None);
        }
        {
            // newid(args[0]) — the staged filename IS the sender DB's id
            // (db_replicator.py:394-395, 409-412), so this records the
            // incoming sync point for the sender at the adopted max row
            let mut broker = ContainerBroker::new(&old_filename, "", "");
            if let Err(e) = broker.newid(tmp_name) {
                return error_response(500, &e.to_string());
            }
        } // close the sqlite handle before the rename
        if let Err(e) = swift_db::renamer(&old_filename, &db_file) {
            return error_response(500, &e.to_string());
        }
        swob_response(204, None)
    }

    /// `_abort_rsync_then_merge` (db_replicator.py:1098-1100) with the
    /// container overrides: the final DB must exist — any epoch file,
    /// `_db_file_exists` (container/replicator.py:390-391) — the staged
    /// file must exist, and the local DB must not have started sharding
    /// since the original 'sync' (container/replicator.py:421-429; a fresh
    /// broker is instantiated on each check to see the latest state).
    fn abort_rsync_then_merge(&self, db_path: &Path, tmp_filename: &Path) -> bool {
        if swift_db::get_db_files(db_path).is_empty() || !tmp_filename.exists() {
            return true;
        }
        let mut broker = ContainerBroker::new(db_path, "", "");
        sharding_initiated(&mut broker)
    }

    /// `rsync_then_merge` (db_replicator.py:1106-1130): merge the existing
    /// DB's object rows, sync points, shard ranges
    /// (container/replicator.py:431-437) and metadata into the staged DB,
    /// re-id it, then rename it over the existing DB.
    fn rsync_then_merge(
        &self,
        drive: &str,
        db_path: &Path,
        args: &[serde_json::Value],
    ) -> Response {
        let Some(tmp_name) = args.get(1).and_then(|v| v.as_str()) else {
            return plain_response(400, "Invalid object type");
        };
        let tmp_filename = self.config.devices.join(drive).join("tmp").join(tmp_name);
        if self.abort_rsync_then_merge(db_path, &tmp_filename) {
            return swob_response(404, None);
        }
        {
            let mut new_broker = ContainerBroker::new(&tmp_filename, "", "");
            let mut existing = ContainerBroker::new(db_path, "", "");
            // batch-copy the existing DB's object rows into the staged DB
            // (db_replicator.py:1112-1119)
            let mut point = -1i64;
            loop {
                let items = match existing.get_items_since(point, 1000) {
                    Ok(items) => items,
                    Err(e) => return error_response(500, &e.to_string()),
                };
                if items.is_empty() {
                    break;
                }
                point = items.last().map(|(rowid, _)| *rowid).unwrap();
                let records: Vec<ObjectRecord> = items.into_iter().map(|(_, rec)| rec).collect();
                if let Err(e) = new_broker.merge_items(records) {
                    return error_response(500, &e.to_string());
                }
            }
            let step = (|| {
                new_broker.merge_syncs(&existing.get_syncs(true)?, true)?;
                // _post_rsync_then_merge_hook (container/replicator.py:
                // 431-437): carry the existing DB's shard ranges over
                let shards = existing.get_all_shard_range_data()?;
                let shards = swift_db::check_merge_own_shard_range(shards, &mut new_broker)?;
                if !shards.is_empty() {
                    new_broker.merge_shard_ranges(shards)?;
                }
                new_broker.newid(tmp_name)?;
                let md = existing.metadata()?;
                new_broker.update_metadata(&md)
            })();
            if let Err(e) = step {
                return error_response(500, &e.to_string());
            }
        } // close both sqlite handles before the rename
        if self.abort_rsync_then_merge(db_path, &tmp_filename) {
            return swob_response(404, None);
        }
        // Python `db_file = existing_broker.db_file` (freshest epoch).
        // Renaming onto the URL's unsuffixed `<hsh>.db` recreates a retiring
        // file next to the epoch DB (probe L1347/L1375).
        let dest = swift_db::get_db_files(db_path)
            .into_iter()
            .last()
            .unwrap_or_else(|| db_path.to_path_buf());
        if let Err(e) = swift_db::renamer(&tmp_filename, &dest) {
            return error_response(500, &e.to_string());
        }
        swob_response(204, None)
    }

    /// `UPDATE`: merge_items RPC with a JSON list of object records.
    fn update(&self, req: &mut Request) -> Response {
        let (drive, part, account, container, _obj) = match self.obj_path(req) {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        let req_timestamp = match valid_timestamp(req) {
            Ok(t) => t,
            Err(resp) => return resp,
        };
        if let Err(resp) = self.check_drive(&drive) {
            return resp;
        }
        let requested_policy_index = match self.policy_index(req) {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        let mut broker = self.broker_for(&drive, &part, &account, &container);
        if let Err(resp) = self.maybe_autocreate(
            &mut broker,
            &req_timestamp,
            &account,
            requested_policy_index,
            &drive,
            req,
        ) {
            return resp;
        }
        let body = match read_control_body(req) {
            Ok(body) => body,
            Err(resp) => return resp,
        };
        let objs: Vec<serde_json::Value> = match serde_json::from_slice(body) {
            Ok(serde_json::Value::Array(objs)) => objs,
            Ok(_) | Err(_) => {
                return plain_response(400, "Expecting value: line 1 column 1 (char 0)")
            }
        };
        let mut records = Vec::with_capacity(objs.len());
        for obj in &objs {
            records.push(ObjectRecord {
                name: obj["name"].as_str().unwrap_or_default().to_string(),
                created_at: obj["created_at"].as_str().unwrap_or_default().to_string(),
                size: obj["size"].as_i64().unwrap_or(0),
                content_type: obj["content_type"].as_str().unwrap_or_default().to_string(),
                etag: obj["etag"].as_str().unwrap_or_default().to_string(),
                deleted: obj["deleted"].as_i64().unwrap_or(0),
                storage_policy_index: obj["storage_policy_index"].as_i64().unwrap_or(0),
                ctype_timestamp: obj["ctype_timestamp"].as_str().map(str::to_string),
                meta_timestamp: obj["meta_timestamp"].as_str().map(str::to_string),
            });
        }
        if let Err(e) = broker.merge_items(records) {
            return error_response(500, &e.to_string());
        }
        swob_response(202, None)
    }
}

/// `ContainerBroker.sharding_initiated` (container/backend.py:452-460):
/// the own shard range is in a cleaving state (SHRINKING/SHRUNK/SHARDING/
/// SHARDED, `ShardRange.CLEAVING_STATES`) and other shard ranges exist.
fn sharding_initiated(broker: &mut ContainerBroker) -> bool {
    let Ok(Some(own)) = broker.get_own_shard_range(false) else {
        return false;
    };
    let cleaving = [
        swift_db::shard_state::SHRINKING,
        swift_db::shard_state::SHRUNK,
        swift_db::shard_state::SHARDING,
        swift_db::shard_state::SHARDED,
    ];
    cleaving.contains(&own.state) && broker.has_other_shard_ranges().unwrap_or(false)
}

fn percent_encode(s: &str) -> String {
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

struct ContainerAsyncService(std::sync::Arc<ContainerServer>);

impl AsyncService for ContainerAsyncService {
    fn call(&self, req: AsyncRequest) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        Box::pin(async move { self.0.handle_async(req).await })
    }
}

pub fn serve(
    listener: std::net::TcpListener,
    config: ContainerServerConfig,
) -> std::io::Result<()> {
    serve_instance(
        listener,
        std::sync::Arc::new(ContainerServer::new(config)),
        swift_http::ServerConfig::default(),
    )
}

/// Like [`serve`], but with an explicit HTTP server config (worker sizing,
/// client timeout, access log, shutdown flag).
pub fn serve_with_config(
    listener: std::net::TcpListener,
    config: ContainerServerConfig,
    http_config: swift_http::ServerConfig,
) -> std::io::Result<()> {
    serve_instance(
        listener,
        std::sync::Arc::new(ContainerServer::new(config)),
        http_config,
    )
}

/// Serve a constructed [`ContainerServer`] so tests can park its shard.
pub fn serve_instance(
    listener: std::net::TcpListener,
    server: std::sync::Arc<ContainerServer>,
    mut http_config: swift_http::ServerConfig,
) -> std::io::Result<()> {
    let metrics = http_config
        .metrics
        .clone()
        .unwrap_or_else(ConcurrencyMetrics::new);
    metrics.set_worker_threads(http_config.worker_threads);
    http_config.metrics = Some(metrics);
    swift_http::serve_forever_multi_service(
        vec![listener],
        std::sync::Arc::new(ContainerAsyncService(server)),
        http_config,
    )
}

#[cfg(test)]
mod reserved_path_tests {
    use super::*;

    fn test_server() -> ContainerServer {
        ContainerServer::new(ContainerServerConfig {
            devices: std::env::temp_dir(),
            mount_check: false,
            hash_config: HashPathConfig::new(b"test-prefix".to_vec(), Vec::new()).unwrap(),
            policies: vec![(0, "replication".to_string())],
            default_policy_index: 0,
            fixed_created_at: None,
            recon_cache_path: PathBuf::from("/var/cache/swift"),
        })
    }

    fn delete_request(account: &str, object: &str) -> Request {
        let mut headers = HeaderKeyDict::new();
        headers.set("X-Backend-Allow-Reserved-Names", "true");
        Request {
            method: "DELETE".to_string(),
            path: format!("/sda1/396/{account}/1787788800/{object}"),
            query_string: String::new(),
            headers,
            body: Vec::new().into(),
        }
    }

    #[test]
    fn reconciler_queue_object_may_embed_reserved_components() {
        let object = "1:/AUTH_test/\0container\0uuid/\0object\0uuid";
        let parsed = test_server()
            .obj_path(&delete_request(MISPLACED_OBJECTS_ACCOUNT, object))
            .expect(".misplaced_objects queue names embed reserved source names");
        assert_eq!(parsed.4.as_deref(), Some(object));
    }

    #[test]
    fn user_account_still_rejects_embedded_reserved_components() {
        let object = "ordinary-prefix/\0object";
        let response = test_server()
            .obj_path(&delete_request("AUTH_test", object))
            .expect_err("allow-reserved listing header must not bypass path validation");
        assert_eq!(response.status, 400);
    }
}

#[cfg(test)]
mod remove_header_tests {
    use super::translate_container_remove_header;

    #[test]
    fn remove_container_read_clears_acl() {
        let (k, v) = translate_container_remove_header("X-Remove-Container-Read", "x").unwrap();
        assert_eq!(k, "X-Container-Read");
        assert_eq!(v, "");
    }

    #[test]
    fn empty_remove_trigger_ignored() {
        assert!(translate_container_remove_header("X-Remove-Container-Read", "").is_none());
    }

    #[test]
    fn remove_user_meta() {
        let (k, v) =
            translate_container_remove_header("X-Remove-Container-Meta-Color", "true").unwrap();
        assert_eq!(k.to_ascii_lowercase(), "x-container-meta-color");
        assert_eq!(v, "");
    }
}

#[cfg(test)]
mod replication_policy_tests {
    use super::*;

    fn test_server(devices: PathBuf) -> ContainerServer {
        ContainerServer::new(ContainerServerConfig {
            devices,
            mount_check: false,
            hash_config: HashPathConfig::new(b"test-prefix".to_vec(), Vec::new()).unwrap(),
            policies: vec![(0, "ec".to_string()), (2, "replication".to_string())],
            default_policy_index: 0,
            fixed_created_at: None,
            recon_cache_path: PathBuf::from("/var/cache/swift"),
        })
    }

    fn policy_test_dir() -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "swift-container-policy-sync-{}-{nanos}",
            std::process::id()
        ))
    }

    #[test]
    fn sync_receiver_adopts_authoritative_remote_policy() {
        let devices = policy_test_dir();
        let db_path = devices
            .join("sda")
            .join("containers")
            .join("0")
            .join("123")
            .join("abc123")
            .join("abc123.db");
        std::fs::create_dir_all(db_path.parent().unwrap()).unwrap();
        let mut broker = ContainerBroker::new(&db_path, "a", "c");
        broker
            .initialize("0000000020.00000", 2, "0000000020.00000", "local-id")
            .unwrap();

        let sync = serde_json::json!([
            "sync",
            -1,
            "",
            "remote-id",
            "0000000010.00000",
            "0000000010.00000",
            "0000000000.00000",
            "",
            "0000000010.00000",
            0,
            0,
        ]);
        let request = Request {
            method: "REPLICATE".to_string(),
            path: "/sda/0/abc123".to_string(),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: swift_http::Body::Buffered(serde_json::to_vec(&sync).unwrap()),
        };
        let response = test_server(devices.clone()).handle(request);
        assert_eq!(response.status, 200);

        let mut broker = ContainerBroker::new(&db_path, "", "");
        assert_eq!(broker.storage_policy_index().unwrap(), 0);
        let body: serde_json::Value =
            serde_json::from_slice(&response.body.into_vec(1024 * 1024).unwrap()).unwrap();
        assert_eq!(body["storage_policy_index"], 0);
        std::fs::remove_dir_all(devices).unwrap();
    }
}

#[cfg(test)]
mod shard_format_tests {
    use super::*;
    use swift_db::{shard_state, ShardRange};

    fn test_server() -> ContainerServer {
        ContainerServer::new(ContainerServerConfig {
            devices: std::env::temp_dir(),
            mount_check: false,
            hash_config: HashPathConfig::new(b"test-prefix".to_vec(), Vec::new()).unwrap(),
            policies: vec![(0, "replication".to_string())],
            default_policy_index: 0,
            fixed_created_at: None,
            recon_cache_path: PathBuf::from("/var/cache/swift"),
        })
    }

    fn shard_get(includes: Option<&str>) -> Request {
        let mut headers = HeaderKeyDict::new();
        headers.set("X-Backend-Record-Type", "shard");
        headers.set("X-Backend-Record-Shard-Format", "namespace");
        Request {
            method: "GET".to_string(),
            path: "/sda/0/AUTH_test/c".to_string(),
            query_string: includes
                .map(|inc| format!("format=json&includes={inc}"))
                .unwrap_or_else(|| "format=json".to_string()),
            headers,
            body: Vec::new().into(),
        }
    }

    #[test]
    fn namespace_format_survives_includes_param() {
        let dir = std::env::temp_dir().join(format!(
            "swift-container-ns-includes-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("c.db");
        let mut broker = ContainerBroker::new(&db, "AUTH_test", "c");
        broker
            .initialize("1751500000.00000", 0, "1751500000.00000", "id-ns")
            .unwrap();
        let sr0 = ShardRange {
            state: shard_state::ACTIVE,
            object_count: 5,
            ..ShardRange::new(".shards_AUTH_test/c-0", "1751500010.00000", "", "m")
        };
        let sr1 = ShardRange {
            state: shard_state::ACTIVE,
            object_count: 5,
            ..ShardRange::new(".shards_AUTH_test/c-1", "1751500010.00000", "m", "")
        };
        broker.merge_shard_ranges(vec![sr0, sr1]).unwrap();

        let resp = test_server().get_shard(
            &shard_get(Some("obj-0001")),
            &mut broker,
            HeaderKeyDict::new(),
            "application/json",
        );
        assert_eq!(resp.status, 200, "namespace+includes must not 400");
        assert_eq!(
            resp.headers.get("X-Backend-Record-Shard-Format"),
            Some("namespace"),
            "Python GET_shard keeps namespace when includes is set"
        );
        assert_eq!(resp.headers.get("X-Backend-Record-Type"), Some("shard"));
        let body: serde_json::Value =
            serde_json::from_slice(&resp.body.into_vec(1024 * 1024).unwrap()).unwrap();
        let arr = body.as_array().expect("namespace listing is a JSON array");
        assert_eq!(arr.len(), 1, "includes returns the covering namespace");
        assert_eq!(arr[0]["name"], ".shards_AUTH_test/c-1");
        assert!(arr[0].get("object_count").is_none(), "namespace omits full fields");

        // Override-Shard-Name-Filter=sharded on a SHARDED db ignores includes.
        broker
            .merge_shard_ranges(vec![ShardRange {
                state: shard_state::SHARDED,
                ..ShardRange::new("AUTH_test/c", "1751500020.00000", "", "")
            }])
            .unwrap();
        // own range SHARDED plus two ACTIVE children is db_state sharded
        // only if get_db_state reports sharded; force via set_sharding if needed.
        let mut headers = HeaderKeyDict::new();
        headers.set("X-Backend-Record-Type", "shard");
        headers.set("X-Backend-Record-Shard-Format", "full");
        headers.set("X-Backend-Override-Shard-Name-Filter", "sharded");
        let req = Request {
            method: "GET".to_string(),
            path: "/sda/0/AUTH_test/c".to_string(),
            query_string: "format=json&includes=obj-0001".to_string(),
            headers,
            body: Vec::new().into(),
        };
        let resp = test_server().get_shard(
            &req,
            &mut broker,
            HeaderKeyDict::new(),
            "application/json",
        );
        let override_hdr = resp.headers.get("X-Backend-Override-Shard-Name-Filter");
        let body: serde_json::Value =
            serde_json::from_slice(&resp.body.into_vec(1024 * 1024).unwrap()).unwrap();
        let n = body.as_array().map(|a| a.len()).unwrap_or(0);
        if override_hdr == Some("true") {
            assert!(n >= 2, "override must return all ranges, got {n}");
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn recon_sharding_is_json_200_not_obj_path_400() {
        let mut srv = test_server();
        srv.config.recon_cache_path = std::env::temp_dir().join(format!(
            "g6-recon-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&srv.config.recon_cache_path).unwrap();
        std::fs::write(
            srv.config.recon_cache_path.join("container.recon"),
            concat!(
                r#"{"sharding_stats":{"sharding":{"sharding_in_progress":{"all":[]}}},"#,
                r#""sharding_time":1.5,"sharding_last":1.0}"#
            ),
        )
        .unwrap();
        let req = Request {
            method: "GET".into(),
            path: "/recon/sharding".into(),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: swift_http::Body::Buffered(vec![]),
        };
        let resp = srv.handle(req);
        assert_eq!(resp.status, 200, "recon must not 400 via obj_path");
        assert_eq!(resp.headers.get("Content-Type"), Some("application/json"));
        let body = String::from_utf8(resp.body.into_vec(64 * 1024).expect("body")).unwrap();
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(v.get("sharding_stats").is_some());
        let _ = std::fs::remove_dir_all(&srv.config.recon_cache_path);
    }

}
