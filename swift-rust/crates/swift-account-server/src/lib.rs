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

//! The account server, ported from `swift/account/server.py` and
//! `swift/account/utils.py`. Response statuses, headers and listing
//! bodies (json/plain/xml) are golden-tested against the Python WSGI
//! controller.
//!
//! Deviations tracked for later: the fallocate_reserve free-space check
//! is not yet enforced.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;

pub mod reaper;
pub use reaper::{
    is_reapable, reap_account, reap_container, recon_update as reaper_recon_update,
    run_once as reaper_run_once, HttpReaperClient, ReaperClient, ReaperPassStats, ReaperStats,
};

use swift_core::hashing::HashPathConfig;
use swift_core::timestamp::Timestamp;
use swift_db::{
    AccountBroker, BrokerMetadata, ContainerRecord, DbError, DbValue, ListContainersArgs,
};
use swift_http::{split_path, AsyncRequest, AsyncService, Body, HeaderKeyDict, Request, Response};
use swift_runtime::{ConcurrencyMetrics, DbExecutor, DbExecutorConfig};

pub const ACCOUNT_LISTING_LIMIT: i64 = 10000;
pub const MAX_META_COUNT: usize = 90;
pub const MAX_META_OVERALL_SIZE: usize = 4096;
pub const AUTO_CREATE_ACCOUNT_PREFIX: &str = ".";
const RESERVED: char = '\u{0}';

/// Server configuration (the interesting subset of account-server.conf).
#[derive(Debug, Clone)]
pub struct AccountServerConfig {
    pub devices: PathBuf,
    pub mount_check: bool,
    pub hash_config: HashPathConfig,
    /// `(index, name)` pairs from swift.conf storage policies.
    pub policies: Vec<(i64, String)>,
    /// Fixed `created_at` for deterministic tests; `None` uses the
    /// clock (production).
    pub fixed_created_at: Option<String>,
}

pub struct AccountServer {
    pub config: AccountServerConfig,
    db: std::sync::OnceLock<DbExecutor>,
}

/// swob explanations for the statuses these servers emit; a default
/// HTML body is generated only when the explanation is non-empty.
fn swob_explanation(status: u16) -> &'static str {
    match status {
        202 => "The request is accepted for processing.",
        403 => "Access was denied to this resource.",
        404 => "The resource could not be found.",
        405 => "The method is not allowed for this resource.",
        406 => "The resource is not available in a format acceptable to your browser.",
        409 => "There was a conflict when trying to complete your request.",
        412 => "A precondition for this request was not met.",
        413 => "The body of your request was too large for this server.",
        500 => "The server has either erred or is incapable of performing the requested operation.",
        501 => "The requested method is not implemented by this server.",
        503 => "The server is currently unavailable. Please try again at a later time.",
        507 => "There was not enough space to save the resource. Drive: %s",
        _ => "",
    }
}

/// A swob response with its default body (used when Python passes no
/// explicit body).
fn swob_response(status: u16, drive: Option<&str>) -> Response {
    let explanation = swob_explanation(status).replace("%s", drive.unwrap_or(""));
    let mut resp = if explanation.is_empty() {
        Response::new(status)
    } else {
        Response::with_body(
            status,
            format!(
                "<html><h1>{}</h1><p>{explanation}</p></html>",
                swift_http::Response::new(status).reason
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

/// The values swob's error responses carry.
fn error_response(status: u16, body: &str) -> Response {
    let mut resp = Response::with_body(status, body.as_bytes().to_vec());
    resp.headers.set("Content-Type", "text/html; charset=UTF-8");
    resp
}

/// Control-plane request bodies (REPLICATE RPC args) are bounded: an
/// over-cap body is 413, and a transport failure during the read maps to
/// the server's catch-all 500 (server.py `__call__`).
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

fn info_get<'i>(info: &'i [(String, DbValue)], key: &str) -> Option<&'i DbValue> {
    info.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

/// Python `json.dumps` string escaping (ensure_ascii).
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

/// One listing record, ordered as the Python dicts are built.
pub enum ListingRecord {
    Subdir(String),
    Container {
        name: String,
        count: i64,
        bytes: i64,
        last_modified: String,
        storage_policy: Option<String>,
    },
}

fn listing_to_json(records: &[ListingRecord]) -> String {
    let mut out = String::from("[");
    for (i, rec) in records.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        match rec {
            ListingRecord::Subdir(name) => {
                out.push_str("{\"subdir\": ");
                py_json_escape(name, &mut out);
                out.push('}');
            }
            ListingRecord::Container {
                name,
                count,
                bytes,
                last_modified,
                storage_policy,
            } => {
                out.push_str("{\"name\": ");
                py_json_escape(name, &mut out);
                out.push_str(&format!(", \"count\": {count}, \"bytes\": {bytes}"));
                out.push_str(", \"last_modified\": ");
                py_json_escape(last_modified, &mut out);
                if let Some(policy) = storage_policy {
                    out.push_str(", \"storage_policy\": ");
                    py_json_escape(policy, &mut out);
                }
                out.push('}');
            }
        }
    }
    out.push(']');
    out
}

fn listing_to_text(records: &[ListingRecord]) -> Vec<u8> {
    let mut out = Vec::new();
    for rec in records {
        match rec {
            ListingRecord::Subdir(name) => out.extend_from_slice(name.as_bytes()),
            ListingRecord::Container { name, .. } => out.extend_from_slice(name.as_bytes()),
        }
        out.push(b'\n');
    }
    out
}

/// ElementTree-style escaping.
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

fn account_listing_to_xml(records: &[ListingRecord], account: &str) -> Vec<u8> {
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str("<account name=\"");
    xml_escape_attr(account, &mut out);
    out.push_str("\">\n");
    for rec in records {
        match rec {
            ListingRecord::Subdir(name) => {
                out.push_str("<subdir name=\"");
                xml_escape_attr(name, &mut out);
                out.push_str("\" />\n");
            }
            ListingRecord::Container {
                name,
                count,
                bytes,
                last_modified,
                storage_policy,
            } => {
                out.push_str("<container>");
                xml_field(&mut out, "name", name);
                xml_field(&mut out, "count", &count.to_string());
                xml_field(&mut out, "bytes", &bytes.to_string());
                xml_field(&mut out, "last_modified", last_modified);
                if let Some(policy) = storage_policy {
                    xml_field(&mut out, "storage_policy", policy);
                }
                out.push_str("</container>\n");
            }
        }
    }
    out.push_str("</account>");
    out.into_bytes()
}

/// `listing_formats.get_listing_content_type` (format param only; full
/// Accept negotiation is a proxy concern).
fn listing_content_type(req: &Request) -> Result<&'static str, Response> {
    if let Some(format) = req.param("format") {
        return Ok(match format.to_lowercase().as_str() {
            "json" => "application/json",
            "xml" => "application/xml",
            _ => "text/plain",
        });
    }
    if let Some(accept) = req.headers.get("Accept") {
        let accept = accept.to_lowercase();
        if accept.contains("application/json") {
            return Ok("application/json");
        }
        if accept.contains("application/xml") {
            return Ok("application/xml");
        }
        if accept.contains("text/xml") {
            return Ok("text/xml");
        }
    }
    Ok("text/plain")
}

/// `valid_timestamp`: X-Timestamp required and parseable.
fn valid_timestamp(req: &Request) -> Result<Timestamp, Response> {
    let Some(raw) = req.headers.get("X-Timestamp") else {
        let mut resp = Response::with_body(400, "Missing X-Timestamp header".as_bytes().to_vec());
        resp.headers.set("Content-Type", "text/plain");
        return Err(resp);
    };
    raw.parse().map_err(|_| {
        let mut resp = Response::with_body(400, "Invalid X-Timestamp header".as_bytes().to_vec());
        resp.headers.set("Content-Type", "text/plain");
        resp
    })
}

fn is_sys_or_user_meta(server_type: &str, key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    lower.starts_with(&format!("x-{server_type}-meta-"))
        && lower.len() > format!("x-{server_type}-meta-").len()
        || lower.starts_with(&format!("x-{server_type}-sysmeta-"))
            && lower.len() > format!("x-{server_type}-sysmeta-").len()
}

/// `DatabaseBroker.validate_metadata` (count/size limits).
fn validate_metadata(md: &BrokerMetadata) -> Result<(), Response> {
    let mut meta_count = 0usize;
    let mut meta_size = 0usize;
    for (key, (value, _)) in md {
        let key = key.to_lowercase();
        for prefix in ["x-account-meta-", "x-container-meta-"] {
            if !value.is_empty() && key.starts_with(prefix) {
                let short = &key[prefix.len()..];
                meta_count += 1;
                meta_size += short.len() + value.len();
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

impl AccountServer {
    pub fn new(config: AccountServerConfig) -> Self {
        AccountServer {
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
        let segs = split_path(&req.path, 3, 4, false).map_err(|e| plain_response(400, &e))?;
        let drive = segs[0].clone().unwrap_or_default();
        let part = segs[1].clone().unwrap_or_default();
        let account = segs[2].clone().unwrap_or_default();
        validate_internal_name(&account, "account")?;
        if let Some(container) = segs.get(3).cloned().flatten() {
            if !container.is_empty() {
                validate_internal_name(&container, "container")?;
            }
        }
        self.check_drive(&drive)?;
        Ok(self
            .broker_for(&drive, &part, &account)
            .db_file()
            .to_path_buf())
    }

    /// Python `ReplicatorRpc` URL is `/<device>/<partition>/<hash>`. Parking
    /// that hash as if it were an account name serializes the wrong DB.
    pub fn replicate_db_file_for_request(&self, req: &Request) -> Result<PathBuf, Response> {
        let segs = split_path(&req.path, 3, 3, false).map_err(|e| plain_response(400, &e))?;
        let drive = segs[0].clone().unwrap_or_default();
        let partition = segs[1].clone().unwrap_or_default();
        let hsh = segs[2].clone().unwrap_or_default();
        self.check_drive(&drive)?;
        if hsh.is_empty() {
            return Err(plain_response(400, &format!("Invalid path: {}", req.path)));
        }
        let suffix = &hsh[hsh.len().saturating_sub(3)..];
        Ok(self
            .config
            .devices
            .join(&drive)
            .join("accounts")
            .join(&partition)
            .join(suffix)
            .join(&hsh)
            .join(format!("{hsh}.db")))
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
                AccountServer {
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
        let max = areq.body.max_body_bytes();
        let body = match areq.body.materialize(max).await {
            Ok(bytes) => Body::Buffered(bytes),
            Err(_) => return error_response(499, "Client Disconnect"),
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
    async fn put_async(&self, req: Request) -> Response {
        let segs = match split_path(&req.path, 3, 4, false) {
            Ok(segs) => segs,
            Err(e) => return plain_response(400, &e),
        };
        let drive = segs[0].clone().unwrap_or_default();
        let part = segs[1].clone().unwrap_or_default();
        let account = segs[2].clone().unwrap_or_default();
        let container = segs[3].clone();
        if let Err(resp) = validate_internal_name(&account, "account") {
            return resp;
        }
        if let Some(container) = &container {
            if let Err(resp) = validate_internal_name(container, "container") {
                return resp;
            }
        }
        if let Err(resp) = self.check_drive(&drive) {
            return resp;
        }
        match container {
            Some(container) if !container.is_empty() => {
                self.put_container_async(req, drive, part, account, container)
                    .await
            }
            _ => self.put_account(&req, &drive, &part, &account),
        }
    }

    #[allow(dead_code)]
    async fn put_container_async(
        &self,
        req: Request,
        drive: String,
        part: String,
        account: String,
        container: String,
    ) -> Response {
        let timestamp = match req.headers.get("x-timestamp") {
            Some(_) => match valid_timestamp(&req) {
                Ok(t) => t,
                Err(resp) => return resp,
            },
            None => Timestamp::now(),
        };
        let policy_index: i64 = req
            .headers
            .get("X-Backend-Storage-Policy-Index")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let (Some(put_ts), Some(delete_ts), Some(obj_count), Some(bytes_used)) = (
            req.headers.get("x-put-timestamp").map(str::to_string),
            req.headers.get("x-delete-timestamp").map(str::to_string),
            req.headers.get("x-object-count").map(str::to_string),
            req.headers.get("x-bytes-used").map(str::to_string),
        ) else {
            return error_response(500, "missing required backend headers");
        };
        let override_deleted = req
            .headers
            .get("x-account-override-deleted")
            .map(|v| v.to_lowercase() == "yes")
            .unwrap_or(false);
        let broker_probe = self.broker_for(&drive, &part, &account);
        let db_file = broker_probe.db_file().to_path_buf();
        let account_s = account.clone();
        let container_s = container.clone();
        let ts_internal = timestamp.internal();
        let created_at = self.created_at();
        let db_id = new_db_id(&drive);
        let auto = account.starts_with(AUTO_CREATE_ACCOUNT_PREFIX);
        let result = self
            .db()
            .run_on_shard(db_file.clone(), move || {
                let mut broker = AccountBroker::new(&db_file, &account_s);
                if auto && !broker.db_file().exists() {
                    match broker.initialize(&ts_internal, &created_at, &db_id) {
                        Ok(()) | Err(DbError::AlreadyExists(_)) => {}
                        Err(e) => return Err(e),
                    }
                }
                let deleted = broker.db_file().exists() && matches!(broker.is_deleted(), Ok(true));
                if (!override_deleted && deleted) || !broker.db_file().exists() {
                    return Ok(None);
                }
                broker.put_container(
                    &container_s,
                    &put_ts,
                    &delete_ts,
                    swift_core::pickle::Value::Str(obj_count),
                    swift_core::pickle::Value::Str(bytes_used),
                    policy_index,
                )?;
                Ok(Some(delete_ts > put_ts))
            })
            .await;
        match result {
            Ok(Ok(None)) => swob_response(404, None),
            Ok(Ok(Some(true))) => Response::new(204),
            Ok(Ok(Some(false))) => Response::new(201),
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

    fn check_drive(&self, drive: &str) -> Result<PathBuf, Response> {
        // Delegate to the shared constraint: quote_plus name validity plus a
        // mount check when configured (Python check_drive). Enforcing
        // mount_check (the production default) prevents reading/writing DBs on
        // an unmounted-but-existing device dir where Python would 507.
        swift_core::constraints::check_drive(&self.config.devices, drive, self.config.mount_check)
            .map_err(|_| swob_response(507, Some(drive)))
    }

    /// Port of `possibly_quarantine` (swift/common/db.py:502-522): a
    /// broker error whose message indicates DB corruption moves the hash
    /// dir to `<device>/quarantined/accounts/` and the request is
    /// answered 404 (the DB is gone); any other DbError stays a 500.
    fn db_error_response(&self, e: &DbError, db_file: &std::path::Path) -> Response {
        if swift_db::is_corruption_error(e) {
            let _ = swift_db::quarantine_db(db_file, "accounts");
            return swob_response(404, None);
        }
        if swift_db::is_lock_contention(e) {
            return error_response(503, &e.to_string());
        }
        error_response(500, &e.to_string())
    }

    fn broker_for(&self, drive: &str, part: &str, account: &str) -> AccountBroker {
        let hsh = self
            .config
            .hash_config
            .hash_path(account, None, None)
            .unwrap_or_default();
        let suffix = &hsh[hsh.len().saturating_sub(3)..];
        let db_path = self
            .config
            .devices
            .join(drive)
            .join("accounts")
            .join(part)
            .join(suffix)
            .join(&hsh)
            .join(format!("{hsh}.db"));
        AccountBroker::new(&db_path, account)
    }

    /// `_deleted_response`: 404/204/403 with X-Account-Status when the
    /// database exists but is marked deleted.
    fn deleted_response(&self, broker: &mut AccountBroker, status: u16, body: &str) -> Response {
        let mut resp = Response::with_body(status, body.as_bytes().to_vec());
        // Python passes charset='utf-8' here (lowercase)
        resp.headers.set("Content-Type", "text/html; charset=utf-8");
        if broker.db_file().exists() {
            if let Ok(true) = broker.is_status_deleted() {
                resp.headers.set("X-Account-Status", "Deleted");
            }
        }
        resp
    }

    /// `REPLICATE`: db_replicator RPC receive side (sync / merge_items /
    /// merge_syncs, plus the rsync-staged full-DB ops complete_rsync and
    /// rsync_then_merge). Body is JSON `[op, ...]`.
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
        let suffix = &hsh[hsh.len().saturating_sub(3)..];
        let db_path = self
            .config
            .devices
            .join(&drive)
            .join("accounts")
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
        if !db_path.exists() {
            return swob_response(404, None);
        }
        let mut broker = AccountBroker::new(&db_path, "");
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
                for c in &items {
                    let count_val = |k: &str| match &c[k] {
                        serde_json::Value::Number(n) if n.is_i64() => {
                            swift_core::pickle::Value::Int(n.as_i64().unwrap())
                        }
                        serde_json::Value::String(s) => swift_core::pickle::Value::Str(s.clone()),
                        _ => swift_core::pickle::Value::Int(0),
                    };
                    records.push(ContainerRecord {
                        name: c["name"].as_str().unwrap_or_default().to_string(),
                        put_timestamp: c["put_timestamp"].as_str().unwrap_or_default().to_string(),
                        delete_timestamp: c["delete_timestamp"]
                            .as_str()
                            .unwrap_or_default()
                            .to_string(),
                        object_count: count_val("object_count"),
                        bytes_used: count_val("bytes_used"),
                        deleted: c["deleted"].as_i64().unwrap_or(0),
                        storage_policy_index: c["storage_policy_index"].as_i64().unwrap_or(0),
                    });
                }
                if let Err(e) = broker.merge_items(records) {
                    return self.db_error_response(&e, broker.db_file());
                }
                if let (Some(source), Some(rowid)) = (source, max_rowid) {
                    if let Err(e) = broker.merge_syncs(&[(rowid, source)], true) {
                        return self.db_error_response(&e, broker.db_file());
                    }
                }
                swob_response(202, None)
            }
            "sync" => {
                // args: remote_sync, hash, id, created_at, put_timestamp,
                // delete_timestamp, metadata (the db_replicator negotiation;
                // mirrors the container-server `sync` op).
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
        // optional final basename (db_replicator.py:1086-1088); defaults
        // to `<hsh>.db` from the URL
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
            let mut broker = AccountBroker::new(&old_filename, "");
            if let Err(e) = broker.newid(tmp_name) {
                return error_response(500, &e.to_string());
            }
        } // close the sqlite handle before the rename
        if let Err(e) = swift_db::renamer(&old_filename, &db_file) {
            return error_response(500, &e.to_string());
        }
        swob_response(204, None)
    }

    /// `rsync_then_merge` (db_replicator.py:1106-1130): merge the existing
    /// DB's container rows, sync points and metadata into the staged DB,
    /// re-id it, then rename it over the existing DB. 404 unless both the
    /// existing DB and the staged file exist (`_abort_rsync_then_merge`,
    /// db_replicator.py:1098-1100).
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
        if !db_path.exists() || !tmp_filename.exists() {
            return swob_response(404, None);
        }
        {
            let mut new_broker = AccountBroker::new(&tmp_filename, "");
            let mut existing = AccountBroker::new(db_path, "");
            // batch-copy the existing DB's container rows into the staged
            // DB (db_replicator.py:1112-1119)
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
                let records: Vec<ContainerRecord> = items.into_iter().map(|(_, rec)| rec).collect();
                if let Err(e) = new_broker.merge_items(records) {
                    return error_response(500, &e.to_string());
                }
            }
            let step = (|| {
                new_broker.merge_syncs(&existing.get_syncs(true)?, true)?;
                new_broker.newid(tmp_name)?;
                let md = existing.metadata()?;
                new_broker.update_metadata(&md)
            })();
            if let Err(e) = step {
                return error_response(500, &e.to_string());
            }
        } // close both sqlite handles before the rename
        if !db_path.exists() || !tmp_filename.exists() {
            return swob_response(404, None);
        }
        if let Err(e) = swift_db::renamer(&tmp_filename, db_path) {
            return error_response(500, &e.to_string());
        }
        swob_response(204, None)
    }

    pub fn handle(&self, mut req: Request) -> Response {
        // path validity: null bytes are allowed internally, but the path
        // must be valid UTF-8 (unquote already replaced bad sequences)
        if req.path.is_empty() {
            return error_response(412, "Invalid UTF8 or contains NULL");
        }
        let mut resp = match req.method.as_str() {
            "GET" => self.get(&req),
            "HEAD" => self.head(&req),
            "PUT" => self.put(&req),
            "POST" => self.post(&req),
            "DELETE" => self.delete(&req),
            "REPLICATE" => self.replicate(&mut req),
            "OPTIONS" => {
                let mut resp = Response::new(200);
                resp.headers
                    .set("Allow", "DELETE, GET, HEAD, OPTIONS, POST, PUT, REPLICATE");
                resp
            }
            _ => {
                let mut resp = swob_response(405, None);
                resp.headers
                    .set("Allow", "DELETE, GET, HEAD, OPTIONS, POST, PUT, REPLICATE");
                resp
            }
        };
        // swob gives every response a default content type
        resp.headers
            .setdefault("Content-Type", "text/html; charset=UTF-8");
        resp
    }

    fn account_path(&self, req: &Request) -> Result<(String, String, String), Response> {
        let segs = split_path(&req.path, 3, 3, false).map_err(|e| plain_response(400, &e))?;
        let (drive, part, account) = (
            segs[0].clone().unwrap_or_default(),
            segs[1].clone().unwrap_or_default(),
            segs[2].clone().unwrap_or_default(),
        );
        validate_internal_name(&account, "account")?;
        Ok((drive, part, account))
    }

    fn get(&self, req: &Request) -> Response {
        let (drive, _part, account) = match self.account_path(req) {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        let out_content_type = match listing_content_type(req) {
            Ok(ct) => ct,
            Err(resp) => return resp,
        };
        if let Err(resp) = self.check_drive(&drive) {
            return resp;
        }
        // limit constraint
        let limit = match req.param("limit") {
            Some(given) if given.bytes().all(|b| b.is_ascii_digit()) && !given.is_empty() => {
                // An all-digit value overflowing i64 is > the max in Python's
                // arbitrary-precision int -> 412, not a silent default.
                let limit: i64 = match given.parse() {
                    Ok(l) => l,
                    Err(_) => {
                        return error_response(
                            412,
                            &format!("Maximum limit is {ACCOUNT_LISTING_LIMIT}"),
                        )
                    }
                };
                if limit > ACCOUNT_LISTING_LIMIT {
                    return error_response(
                        412,
                        &format!("Maximum limit is {ACCOUNT_LISTING_LIMIT}"),
                    );
                }
                limit
            }
            _ => ACCOUNT_LISTING_LIMIT,
        };
        let mut broker = self.broker_for(&drive, &_part, &account);
        match broker.is_deleted() {
            Ok(true) | Err(_) => return self.deleted_response(&mut broker, 404, ""),
            Ok(false) => {}
        }
        let args = ListContainersArgs {
            limit,
            marker: req.param("marker").unwrap_or_default(),
            end_marker: req.param("end_marker").unwrap_or_default(),
            prefix: req.param("prefix"),
            delimiter: req.param("delimiter"),
            // config_true_value is case-insensitive (Python lowercases first),
            // so "True"/"YES" must count too.
            reverse: matches!(
                req.param("reverse").map(|s| s.to_lowercase()).as_deref(),
                Some("true") | Some("1") | Some("yes") | Some("on") | Some("t") | Some("y")
            ),
            allow_reserved: req.headers.get("X-Backend-Allow-Reserved-Names").is_some(),
        };
        let rows = match broker.list_containers_iter(&args) {
            Ok(rows) => rows,
            Err(e) => return self.db_error_response(&e, broker.db_file()),
        };
        let mut records = Vec::with_capacity(rows.len());
        for row in rows {
            let name = value_str(&row[0]);
            let is_subdir = matches!(&row[5], DbValue::Int(1));
            if is_subdir {
                records.push(ListingRecord::Subdir(name));
            } else {
                let put_ts = value_str(&row[3]);
                let last_modified = put_ts
                    .parse::<Timestamp>()
                    .map(|t| t.isoformat())
                    .unwrap_or_default();
                let spi = match &row[4] {
                    DbValue::Int(i) => *i,
                    _ => 0,
                };
                let storage_policy = self
                    .config
                    .policies
                    .iter()
                    .find(|(idx, _)| *idx == spi)
                    .map(|(_, name)| name.clone());
                records.push(ListingRecord::Container {
                    name,
                    count: match &row[1] {
                        DbValue::Int(i) => *i,
                        _ => 0,
                    },
                    bytes: match &row[2] {
                        DbValue::Int(i) => *i,
                        _ => 0,
                    },
                    last_modified,
                    storage_policy,
                });
            }
        }
        let mut resp = if out_content_type.ends_with("/xml") {
            Response::with_body(200, account_listing_to_xml(&records, &account))
        } else if out_content_type.ends_with("/json") {
            Response::with_body(200, listing_to_json(&records).into_bytes())
        } else if !records.is_empty() {
            Response::with_body(200, listing_to_text(&records))
        } else {
            Response::new(204)
        };
        match self.response_headers(&mut broker) {
            Ok(headers) => {
                for (k, v) in headers.iter() {
                    resp.headers.set(k, v);
                }
            }
            Err(e) => return self.db_error_response(&e, broker.db_file()),
        }
        resp.headers
            .set("Content-Type", format!("{out_content_type}; charset=utf-8"));
        resp
    }

    fn head(&self, req: &Request) -> Response {
        let (drive, part, account) = match self.account_path(req) {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        let out_content_type = match listing_content_type(req) {
            Ok(ct) => ct,
            Err(resp) => return resp,
        };
        if let Err(resp) = self.check_drive(&drive) {
            return resp;
        }
        let mut broker = self.broker_for(&drive, &part, &account);
        match broker.is_deleted() {
            Ok(true) | Err(_) => return self.deleted_response(&mut broker, 404, ""),
            Ok(false) => {}
        }
        let mut resp = Response::new(204);
        match self.response_headers(&mut broker) {
            Ok(headers) => {
                for (k, v) in headers.iter() {
                    resp.headers.set(k, v);
                }
            }
            Err(e) => return self.db_error_response(&e, broker.db_file()),
        }
        resp.headers
            .set("Content-Type", format!("{out_content_type}; charset=utf-8"));
        resp
    }

    /// `get_response_headers`.
    fn response_headers(&self, broker: &mut AccountBroker) -> Result<HeaderKeyDict, DbError> {
        let info = broker.get_info()?;
        let mut headers = HeaderKeyDict::new();
        headers.set(
            "X-Account-Container-Count",
            value_str(info_get(&info, "container_count").unwrap_or(&DbValue::Int(0))),
        );
        headers.set(
            "X-Account-Object-Count",
            value_str(info_get(&info, "object_count").unwrap_or(&DbValue::Int(0))),
        );
        headers.set(
            "X-Account-Bytes-Used",
            value_str(info_get(&info, "bytes_used").unwrap_or(&DbValue::Int(0))),
        );
        let normal = |key: &str| {
            info_get(&info, key)
                .map(value_str)
                .and_then(|s| s.parse::<Timestamp>().ok())
                .map(|t| t.normal())
                .unwrap_or_default()
        };
        headers.set("X-Timestamp", normal("created_at"));
        headers.set("X-PUT-Timestamp", normal("put_timestamp"));
        for (idx, name) in &self.config.policies {
            let stats = broker.policy_stat_rows()?;
            for row in stats {
                if matches!(&row[0], DbValue::Int(i) if i == idx) {
                    let prefix = format!("X-Account-Storage-Policy-{name}");
                    headers.set(&format!("{prefix}-Container-Count"), value_str(&row[1]));
                    headers.set(&format!("{prefix}-Object-Count"), value_str(&row[2]));
                    headers.set(&format!("{prefix}-Bytes-Used"), value_str(&row[3]));
                }
            }
        }
        for (key, (value, _)) in broker.metadata()? {
            if !value.is_empty() {
                headers.set(&key, value);
            }
        }
        Ok(headers)
    }

    fn put(&self, req: &Request) -> Response {
        let segs = match split_path(&req.path, 3, 4, false) {
            Ok(segs) => segs,
            Err(e) => return plain_response(400, &e),
        };
        let drive = segs[0].clone().unwrap_or_default();
        let part = segs[1].clone().unwrap_or_default();
        let account = segs[2].clone().unwrap_or_default();
        let container = segs[3].clone();
        if let Err(resp) = validate_internal_name(&account, "account") {
            return resp;
        }
        if let Some(container) = &container {
            if let Err(resp) = validate_internal_name(container, "container") {
                return resp;
            }
        }
        if let Err(resp) = self.check_drive(&drive) {
            return resp;
        }
        match container {
            Some(container) if !container.is_empty() => {
                self.put_container(req, &drive, &part, &account, &container)
            }
            _ => self.put_account(req, &drive, &part, &account),
        }
    }

    fn put_container(
        &self,
        req: &Request,
        drive: &str,
        part: &str,
        account: &str,
        container: &str,
    ) -> Response {
        let timestamp = match req.headers.get("x-timestamp") {
            Some(_) => match valid_timestamp(req) {
                Ok(t) => t,
                Err(resp) => return resp,
            },
            None => Timestamp::now(),
        };
        let policy_index: i64 = req
            .headers
            .get("X-Backend-Storage-Policy-Index")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let mut broker = self.broker_for(drive, part, account);
        if account.starts_with(AUTO_CREATE_ACCOUNT_PREFIX) && !broker.db_file().exists() {
            match broker.initialize(&timestamp.internal(), &self.created_at(), &new_db_id(drive)) {
                Ok(()) | Err(DbError::AlreadyExists(_)) => {}
                Err(e) => return error_response(500, &e.to_string()),
            }
        }
        let override_deleted = req
            .headers
            .get("x-account-override-deleted")
            .map(|v| v.to_lowercase() == "yes")
            .unwrap_or(false);
        let deleted = broker.db_file().exists() && matches!(broker.is_deleted(), Ok(true));
        if (!override_deleted && deleted) || !broker.db_file().exists() {
            return swob_response(404, None);
        }
        let (Some(put_ts), Some(delete_ts), Some(obj_count), Some(bytes_used)) = (
            req.headers.get("x-put-timestamp").map(str::to_string),
            req.headers.get("x-delete-timestamp").map(str::to_string),
            req.headers.get("x-object-count").map(str::to_string),
            req.headers.get("x-bytes-used").map(str::to_string),
        ) else {
            // Python raises KeyError out of the handler -> 500
            return error_response(500, "missing required backend headers");
        };
        if let Err(e) = broker.put_container(
            container,
            &put_ts,
            &delete_ts,
            swift_core::pickle::Value::Str(obj_count),
            swift_core::pickle::Value::Str(bytes_used),
            policy_index,
        ) {
            return self.db_error_response(&e, broker.db_file());
        }
        if delete_ts > put_ts {
            Response::new(204)
        } else {
            Response::new(201)
        }
    }

    fn put_account(&self, req: &Request, drive: &str, part: &str, account: &str) -> Response {
        if let Err(e) = swift_core::constraints::check_metadata(req.headers.iter(), "account") {
            return plain_response(400, &e.0);
        }
        let timestamp = match valid_timestamp(req) {
            Ok(t) => t,
            Err(resp) => return resp,
        };
        let mut broker = self.broker_for(drive, part, account);
        let created;
        if !broker.db_file().exists() {
            created = match broker.initialize(
                &timestamp.internal(),
                &self.created_at(),
                &new_db_id(drive),
            ) {
                Ok(()) => true,
                Err(DbError::AlreadyExists(_)) => false,
                Err(e) => return error_response(500, &e.to_string()),
            };
        } else if matches!(broker.is_status_deleted(), Ok(true)) {
            return self.deleted_response(&mut broker, 403, "Recently deleted");
        } else {
            created = matches!(broker.is_deleted(), Ok(true));
            if let Err(e) = broker.update_put_timestamp(&timestamp.internal()) {
                return self.db_error_response(&e, broker.db_file());
            }
            if matches!(broker.is_deleted(), Ok(true)) {
                return swob_response(409, None);
            }
        }
        if let Err(resp) = self.update_metadata_from_headers(req, &mut broker, &timestamp) {
            return resp;
        }
        if created {
            Response::new(201)
        } else {
            swob_response(202, None)
        }
    }

    fn update_metadata_from_headers(
        &self,
        req: &Request,
        broker: &mut AccountBroker,
        timestamp: &Timestamp,
    ) -> Result<(), Response> {
        let metadata: BrokerMetadata = req
            .headers
            .iter()
            .filter(|(k, _)| is_sys_or_user_meta("account", k))
            .map(|(k, v)| (k.to_string(), (v.to_string(), timestamp.internal())))
            .collect();
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
        broker
            .update_metadata(&metadata)
            .map_err(|e| self.db_error_response(&e, broker.db_file()))
    }

    fn post(&self, req: &Request) -> Response {
        if let Err(e) = swift_core::constraints::check_metadata(req.headers.iter(), "account") {
            return plain_response(400, &e.0);
        }
        let (drive, part, account) = match self.account_path(req) {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        let timestamp = match valid_timestamp(req) {
            Ok(t) => t,
            Err(resp) => return resp,
        };
        if let Err(resp) = self.check_drive(&drive) {
            return resp;
        }
        let mut broker = self.broker_for(&drive, &part, &account);
        match broker.is_deleted() {
            Ok(true) | Err(_) => return self.deleted_response(&mut broker, 404, ""),
            Ok(false) => {}
        }
        if let Err(resp) = self.update_metadata_from_headers(req, &mut broker, &timestamp) {
            return resp;
        }
        Response::new(204)
    }

    fn delete(&self, req: &Request) -> Response {
        let (drive, part, account) = match self.account_path(req) {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        if let Err(resp) = self.check_drive(&drive) {
            return resp;
        }
        let timestamp = match valid_timestamp(req) {
            Ok(t) => t,
            Err(resp) => return resp,
        };
        let mut broker = self.broker_for(&drive, &part, &account);
        match broker.is_deleted() {
            Ok(true) | Err(_) => return self.deleted_response(&mut broker, 404, ""),
            Ok(false) => {}
        }
        if let Err(e) = broker.delete_db(&timestamp.internal()) {
            return error_response(500, &e.to_string());
        }
        self.deleted_response(&mut broker, 204, "")
    }
}

/// Runtime db id: `<random>-<device>` like Python's `str(uuid4())-dev`.
fn new_db_id(device: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{nanos:032x}-{device}")
}

struct AccountAsyncService(std::sync::Arc<AccountServer>);

impl AsyncService for AccountAsyncService {
    fn call(&self, req: AsyncRequest) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        Box::pin(async move { self.0.handle_async(req).await })
    }
}

/// Serve on the given listener (used by main and by tests).
pub fn serve(listener: std::net::TcpListener, config: AccountServerConfig) -> std::io::Result<()> {
    serve_instance(
        listener,
        std::sync::Arc::new(AccountServer::new(config)),
        swift_http::ServerConfig::default(),
    )
}

/// Like [`serve`], but with an explicit HTTP server config (worker sizing,
/// client timeout, access log, shutdown flag).
pub fn serve_with_config(
    listener: std::net::TcpListener,
    config: AccountServerConfig,
    http_config: swift_http::ServerConfig,
) -> std::io::Result<()> {
    serve_instance(
        listener,
        std::sync::Arc::new(AccountServer::new(config)),
        http_config,
    )
}

/// Serve a constructed [`AccountServer`] (tests share the instance to park
/// its [`DbExecutor`] shard while Hyper still accepts).
pub fn serve_instance(
    listener: std::net::TcpListener,
    server: std::sync::Arc<AccountServer>,
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
        std::sync::Arc::new(AccountAsyncService(server)),
        http_config,
    )
}
