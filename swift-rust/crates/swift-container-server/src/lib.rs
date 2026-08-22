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
//! _redirect_to_shard 301 on object PUT. Deviations tracked for later:
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
    cleave, cleave_shard_range, default_shard_quorum, find_and_merge_found_ranges,
    find_shrink_acceptor, find_shrinking_donors, http_replicator_for_primaries,
    load_cleaving_context, lookup_replicator_for_ring, maybe_auto_shard,
    move_misplaced_from_retiring, primary_shard_replica_nodes, process_sharding_container,
    process_sharding_container_detailed, process_sharding_container_with_replicator,
    process_shrinking_donors, process_shrinking_donors_stub, put_shard_quorum, range_covers,
    recon_update as sharder_recon_update, ring_get_nodes_for_shard, run_once as sharder_run_once,
    run_once_with_opts as sharder_run_once_with_opts, run_once_with_opts_and_replicator,
    run_once_with_opts_and_ring, save_cleaving_context, shard_replicas_from_ring_devices,
    CleavingContext, HttpShardReplicator, LocalShardReplicator, LookupHttpShardReplicator,
    MapShardHttpTransport, ProcessShardingOutcome, ShardHttpTransport, ShardReplicaNode,
    ShardReplicator, SharderRunOpts, SharderStats, TcpShardHttpTransport, CLEAVING_CONTEXT_KEY,
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
}

pub struct ContainerServer {
    pub config: ContainerServerConfig,
    db: std::sync::OnceLock<DbExecutor>,
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

    pub fn db_file_for_request(&self, req: &Request) -> Result<PathBuf, Response> {
        let (drive, part, account, container, _obj) = self.obj_path(req)?;
        self.check_drive(&drive)?;
        Ok(self
            .broker_for(&drive, &part, &account, &container)
            .db_file()
            .to_path_buf())
    }

    async fn dispatch_on_shard(&self, req: Request) -> Response {
        let db_file = match self.db_file_for_request(&req) {
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
        let ctype_ts = req.headers.get("x-content-type-timestamp").map(str::to_string);
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
        validate_internal_name(&account, "account")?;
        validate_internal_name(&container, "container")?;
        if let Some(obj) = &obj {
            validate_internal_name(obj, "object")?;
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
        let mut headers = self.gen_resp_headers(&info, is_deleted, &sharding_state);
        if is_deleted {
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
        let rows = match broker.list_objects_iter(&args) {
            Ok(rows) => rows,
            Err(e) => return self.db_error_response(&e, broker.db_file()),
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
            if let Ok(mut conn) = std::net::TcpStream::connect(host) {
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
        if self.should_autocreate(account, req) && !broker.db_file().exists() {
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
        if !broker.db_file().exists() {
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
        let obj_policy_index = requested_policy_index.unwrap_or(0);
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
        let states = match req.param("states") {
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
            marker: req.param("marker").filter(|s| !s.is_empty()),
            end_marker: req.param("end_marker").filter(|s| !s.is_empty()),
            includes: req.param("includes").filter(|s| !s.is_empty()),
            reverse: truthy(req.param("reverse").as_deref()),
            include_deleted: truthy(req.headers.get("x-backend-include-deleted")),
            states,
            ..Default::default()
        };
        let ranges = match broker.get_shard_ranges(&args) {
            Ok(r) => r,
            Err(e) => return self.db_error_response(&e, broker.db_file()),
        };
        let body = serde_json::Value::Array(ranges.iter().map(|r| r.to_json()).collect::<Vec<_>>());
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
        if !broker.db_file().exists() {
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
        if !broker.db_file().exists() || matches!(broker.is_deleted(), Ok(true)) {
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
                if !broker.db_file().exists() {
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
        let segs = match split_path(&req.path, 3, 3, false) {
            Ok(segs) => segs,
            Err(e) => return plain_response(400, &e),
        };
        let drive = segs[0].clone().unwrap_or_default();
        let partition = segs[1].clone().unwrap_or_default();
        let hsh = segs[2].clone().unwrap_or_default();
        if let Err(resp) = self.check_drive(&drive) {
            return resp;
        }
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
        // db path: <device>/containers/<part>/<hsh[-3:]>/<hsh>/<hsh>.db
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
        if matches!(op, "sync" | "merge_syncs" | "merge_items") && !db_path.exists() {
            return swob_response(404, None);
        }
        let mut broker = ContainerBroker::new(&db_path, "", "");
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
                // delete_timestamp, metadata
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
                if !remote_metadata.is_empty() {
                    if let Ok(md) = swift_db::py_json_parse_metadata(&remote_metadata) {
                        let _ = broker.update_metadata(&md);
                    }
                }
                let info = match broker.get_replication_info() {
                    Ok(i) => i,
                    Err(e) => return self.db_error_response(&e, broker.db_file()),
                };
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
                    let _ = broker.merge_timestamps(&created_at, &put_timestamp, &delete_timestamp);
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
        if let Err(e) = swift_db::renamer(&tmp_filename, db_path) {
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
