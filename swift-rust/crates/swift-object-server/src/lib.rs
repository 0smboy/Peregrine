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

//! The object server, ported from `swift/obj/server.py` for the
//! replication policy: PUT (write + commit), GET/HEAD (with Range),
//! POST (fast-POST metadata + content-type merge), DELETE (tombstone),
//! each driving `swift-diskfile` and the container-update side channel.
//!
//! Deviations tracked for later: EC policy paths (frag index, ssync),
//! multi-stage MIME PUT (SLO
//! footers), delete-at reaping (X-Delete-At enqueue), keep-cache/zero-copy.
//! The async_pending fallback (writing a pickle the object-updater replays
//! when a container update can't be applied synchronously) IS implemented.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub mod daemonutil;
pub mod expirer;
pub mod localdev;
/// The EC object reconstructor: ssync-driven SYNC/REVERT partition jobs
/// (feature-independent) plus the fragment rebuild path, which links
/// liberasurecode and is behind the `ec` feature.
pub mod reconstructor;
pub mod replicator;
pub mod servers_per_port;
pub mod ssync;
pub mod ssync_sender;
pub mod updater;
/// Experimental native `/v1` lock gate. Wired on PUT/POST/DELETE of an
/// existing object (not REPLICATE/SSYNC). Not live-proven, not deployed,
/// not a compliance claim.
pub mod worm_native_gate;
pub use worm_native_gate::{
    is_s3_lock_control_plane_post, native_mutation_allowed, native_mutation_allowed_for,
    NativeGovernanceBypass,
};
pub use expirer::{
    build_task_obj, get_expirer_container, iter_due_tasks, parse_task_obj, process_task,
    recon_update as expirer_recon_update, run_once as expirer_run_once, DeleteResult, ExpirerStats,
    ExpiryClient, HttpExpiryClient, TaskInfo, ASYNC_DELETE_TYPE, EXPIRER_ACCOUNT_NAME,
    EXPIRER_CONTAINER_DIVISOR,
};
pub use updater::{
    iter_async_pendings, process_update, run_once, run_once_with_concurrency, AsyncUpdate,
    ContainerNodeClient, HttpContainerClient, NodeResult, UpdateOutcome, UpdaterStats,
};

use swift_core::config::{config_true_value, FallocateReserve};
use swift_core::hashing::HashPathConfig;
use swift_core::pickle::{self, Value as PickleValue};
use swift_core::timestamp::{normalize_delete_at_timestamp, Timestamp};
use swift_diskfile::{
    get_data_dir, get_partition_hashes, invalidate_hash, make_ec_ondisk_filename,
    storage_directory, valid_suffix, DiskFile, DiskFileConfig, DiskFileError, MetaValue, Metadata,
    PolicyKind,
};
use swift_http::{
    http_date, split_path, unquote, Body, ChainReader, HeaderKeyDict, Match, MimeDocs, Range,
    Request, Response, STREAM_CHUNK,
};

use crate::ssync::{MissingOffer, SsyncEvent, SsyncParser, SsyncSubrequest};

pub const MAX_FILE_SIZE: i64 = 5_368_709_122;

/// How the object server applies the container-listing side channel after a
/// durable object PUT/DELETE.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ContainerUpdateMode {
    /// Contact container replicas in parallel under `container_update_timeout`;
    /// fall back to `async_pending` on any miss (L1a / Python default).
    #[default]
    Sync,
    /// Always enqueue `async_pending` and return; the object-updater drains
    /// the listing update off the write path (L1b).
    Async,
}

pub struct ObjectServerConfig {
    pub devices: PathBuf,
    pub mount_check: bool,
    pub hash_config: HashPathConfig,
    pub diskfile: DiskFileConfig,
    /// Every configured storage-policy index and its diskfile kind. Keeping the
    /// complete registry lets request handling distinguish a replication policy
    /// from an unknown index instead of treating every map miss as replication.
    pub policies: std::collections::HashMap<u32, PolicyKind>,
    /// Per-replica budget for the synchronous container update on the object
    /// PUT/DELETE path (Python `container_update_timeout`, default 1.0s).
    /// Replicas are contacted in parallel; any that miss this budget fall
    /// through to `async_pending`.
    pub container_update_timeout: std::time::Duration,
    /// `sync` (default) or `async` — see [`ContainerUpdateMode`].
    pub container_update_mode: ContainerUpdateMode,
}

pub struct ObjectServer {
    pub config: ObjectServerConfig,
    /// `fallocate_reserve`: the free-space floor a PUT may not take the
    /// device below. Python enforces it inside `fallocate()`
    /// (`swift/common/utils`), surfacing as DiskFileNoSpace -> 507; the
    /// config default is `1%`.
    pub fallocate_reserve: FallocateReserve,
}

fn meta_get<'m>(meta: &'m Metadata, key: &str) -> Option<&'m str> {
    meta.iter()
        .find(|(k, _)| matches!(k, MetaValue::Str(s) if s.eq_ignore_ascii_case(key)))
        .and_then(|(_, v)| v.as_str())
}

/// Stored object ETag used by GET/HEAD and PUT `If-Match`.
fn object_etag(meta: &Metadata) -> &str {
    meta_get(meta, "ETag").unwrap_or("")
}

/// Python `dict.update` semantics on the ordered metadata pairs: replace the
/// value in place when the key already exists (matched case-insensitively,
/// as [`meta_get`] does), else append.
fn meta_upsert(meta: &mut Metadata, key: &str, value: String) {
    match meta
        .iter_mut()
        .find(|(k, _)| matches!(k, MetaValue::Str(s) if s.eq_ignore_ascii_case(key)))
    {
        Some(slot) => slot.1 = MetaValue::Str(value),
        None => meta.push((MetaValue::Str(key.to_string()), MetaValue::Str(value))),
    }
}

/// Simplified `swift.common.utils.extract_swift_bytes`, sufficient for the
/// unquoted parameter tokens Swift itself writes (`;swift_bytes=N`): return
/// the content-type minus any `swift_bytes` param, plus that param's value.
fn extract_swift_bytes(content_type: &str) -> (String, Option<String>) {
    match content_type.split_once(';') {
        None => (content_type.to_string(), None),
        Some((ct, params)) => {
            let mut out = ct.to_string();
            let mut swift_bytes = None;
            for param in params.split(';') {
                let (k, v) = param.split_once('=').unwrap_or((param, ""));
                let (k, v) = (k.trim(), v.trim());
                if k == "swift_bytes" {
                    swift_bytes = Some(v.to_string());
                } else if !k.is_empty() {
                    out.push_str(&format!(";{k}={v}"));
                }
            }
            (out, swift_bytes)
        }
    }
}

fn swob_response(status: u16) -> Response {
    let explanation = match status {
        404 => "The resource could not be found.",
        409 => "There was a conflict when trying to complete your request.",
        422 => "Unable to process the contained instructions",
        503 => "The server is currently unavailable. Please try again at a later time.",
        507 => "There was not enough space to save the resource. Drive: ",
        _ => "",
    };
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

/// Map a MIME-stream read error to the response Python's exception
/// translation produces: decoder over-cap -> 413, malformed multipart ->
/// 400, disconnect/timeout -> 499.
fn mime_read_error(e: &std::io::Error) -> Response {
    if swift_http::body_too_large(e) {
        plain_response(413, "Your request is too large.")
    } else if e.kind() == std::io::ErrorKind::InvalidData {
        plain_response(400, &e.to_string())
    } else {
        swob_response(499)
    }
}

/// Parse the metadata-footer document (server.py `_read_metadata_footer` +
/// `_parse_footer`): headers must carry `Content-MD5` over the JSON body.
fn read_footer_metadata(docs: &mut MimeDocs) -> Result<Vec<(String, String)>, Response> {
    let headers = match docs.next_document() {
        Ok(Some(h)) => h,
        Ok(None) => return Err(plain_response(400, "couldn't find footer MIME doc")),
        Err(e) => return Err(mime_read_error(&e)),
    };
    let Some(expected_md5) = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("Content-MD5"))
        .map(|(_, v)| v.clone())
    else {
        return Err(plain_response(400, "no Content-MD5 in footer"));
    };
    let mut body = Vec::new();
    if let Err(e) = std::io::Read::take(&mut *docs, 1024 * 1024).read_to_end(&mut body) {
        return Err(mime_read_error(&e));
    }
    let computed = {
        use md5::{Digest, Md5};
        format!("{:x}", Md5::digest(&body))
    };
    if computed != expected_md5 {
        return Err(plain_response(422, "footer MD5 mismatch"));
    }
    let Ok(serde_json::Value::Object(map)) = serde_json::from_slice::<serde_json::Value>(&body)
    else {
        return Err(plain_response(400, "invalid JSON for footer doc"));
    };
    let mut out = Vec::with_capacity(map.len());
    for (k, v) in map {
        let value = match v {
            serde_json::Value::String(s) => s,
            serde_json::Value::Number(n) => n.to_string(),
            serde_json::Value::Bool(b) => b.to_string(),
            _ => return Err(plain_response(400, "invalid JSON for footer doc")),
        };
        out.push((k, value));
    }
    Ok(out)
}

/// `_check_container_override` (server.py:606-645): rewrite container
/// update headers from `*-container-update-override-*` request headers
/// and footers. Prefix order is significant (sysmeta overrides backend);
/// within each prefix, footers override headers.
fn apply_container_override(
    update: &mut HeaderKeyDict,
    headers: &HeaderKeyDict,
    footers: &[(String, String)],
) {
    for prefix in [
        "x-backend-container-update-override-",
        "x-object-sysmeta-container-update-override-",
    ] {
        for (k, v) in headers.iter() {
            let kl = k.to_ascii_lowercase();
            if let Some(rest) = kl.strip_prefix(prefix) {
                update.set(&format!("x-{rest}"), v);
            }
        }
        for (k, v) in footers {
            let kl = k.to_ascii_lowercase();
            if let Some(rest) = kl.strip_prefix(prefix) {
                update.set(&format!("x-{rest}"), v);
            }
        }
    }
}

fn is_sys_or_user_meta(key: &str) -> bool {
    let l = key.to_ascii_lowercase();
    (l.starts_with("x-object-meta-") && l.len() > "x-object-meta-".len())
        || (l.starts_with("x-object-sysmeta-") && l.len() > "x-object-sysmeta-".len())
}

fn is_object_transient_sysmeta(key: &str) -> bool {
    let l = key.to_ascii_lowercase();
    l.starts_with("x-object-transient-sysmeta-") && l.len() > "x-object-transient-sysmeta-".len()
}

/// Swift's default object-server `allowed_headers` (plus the always-persisted
/// large-object headers): non-meta request headers the object server stores
/// with the object and echoes on GET/HEAD — notably `X-Object-Manifest` (DLO)
/// and `X-Static-Large-Object` (SLO), without which manifest reassembly can
/// never trigger.
fn is_allowed_header(key: &str) -> bool {
    matches!(
        key.to_ascii_lowercase().as_str(),
        "x-object-manifest"
            | "x-static-large-object"
            | "content-disposition"
            | "content-encoding"
            | "content-language"
            | "cache-control"
            | "expires"
            | "x-robots-tag"
    )
}

fn is_replication_header(req: &Request, key: &str) -> bool {
    req.headers
        .get("X-Backend-Replication-Headers")
        .is_some_and(|headers| {
            headers
                .split_ascii_whitespace()
                .any(|header| header.eq_ignore_ascii_case(key))
        })
}

fn should_persist_header(req: &Request, key: &str) -> bool {
    is_sys_or_user_meta(key)
        || is_object_transient_sysmeta(key)
        || is_allowed_header(key)
        || is_replication_header(req, key)
}

#[derive(Debug, Default)]
struct LocalSsyncTimestamps {
    data: Option<Timestamp>,
    meta: Option<Timestamp>,
    ctype: Option<Timestamp>,
}

/// True if a header value parses the way Python's `int()` accepts a base-10
/// integer: optional surrounding whitespace, an optional sign, then one or
/// more ASCII digits. Used to reproduce the `Non-integer X-Delete-*`
/// distinction (`'*'` is rejected, `'1' * 100` is accepted even though it
/// overflows i64).
fn parse_int_like(s: &str) -> Option<f64> {
    let t = s.trim();
    let digits = t.strip_prefix(['+', '-']).unwrap_or(t);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    // f64 has ample range for any realistic X-Delete-At; overflow past f64 is
    // clamped by normalize_delete_at_timestamp anyway.
    t.parse::<f64>().ok()
}

/// Whether an `If-None-Match` header value carries the `*` wildcard token.
fn if_none_match_has_star(value: &str) -> bool {
    value.split(',').any(|tok| tok.trim() == "*")
}

/// Port of `swift.common.constraints.check_delete_headers`: validate the
/// `X-Delete-After` / `X-Delete-At` headers against the request timestamp
/// `now` (float seconds) and return the resolved, normalized `X-Delete-At`
/// string (or `None` when neither header is present). `X-Delete-After` takes
/// precedence and is converted to an `X-Delete-At`. On any invalid value the
/// error carries the exact 400 response Python would emit.
fn check_delete_headers(req: &Request, now: f64) -> Result<Option<String>, Response> {
    // X-Delete-After is converted into an X-Delete-At and takes precedence.
    let raw_delete_at: Option<String> = if let Some(raw) = req.headers.get("X-Delete-After") {
        let Some(after) = parse_int_like(raw) else {
            return Err(plain_response(400, "Non-integer X-Delete-After"));
        };
        let actual = normalize_delete_at_timestamp(now + after, false);
        if actual.parse::<i64>().unwrap_or(0) as f64 <= now {
            return Err(plain_response(400, "X-Delete-After in past"));
        }
        Some(actual)
    } else {
        req.headers.get("X-Delete-At").map(str::to_string)
    };

    let Some(raw) = raw_delete_at else {
        return Ok(None);
    };

    let Some(value) = parse_int_like(&raw) else {
        return Err(plain_response(400, "Non-integer X-Delete-At"));
    };
    let normalized = normalize_delete_at_timestamp(value, false);
    let x_delete_at = normalized.parse::<i64>().unwrap_or(0);
    let backend_replication = req
        .headers
        .get("X-Backend-Replication")
        .is_some_and(config_true_value);
    if (x_delete_at as f64) <= now && !backend_replication {
        return Err(plain_response(400, "X-Delete-At in past"));
    }
    Ok(Some(normalized))
}

/// Copy on-disk object metadata into request-style headers for the native
/// lock gate. Only string pairs are needed (lock sysmeta is stored as text).
fn metadata_as_headers(meta: &Metadata) -> HeaderKeyDict {
    let mut headers = HeaderKeyDict::new();
    for (k, v) in meta {
        if let (Some(key), Some(value)) = (k.as_str(), v.as_str()) {
            headers.set(key, value);
        }
    }
    headers
}

/// Experimental native lock gate on PUT/POST/DELETE of an existing object.
/// Not live-proven, not deployed, not a compliance claim.
///
/// Missing object → allow (PUT create). Replicate/ssync
/// (`X-Backend-Replication`) skip this gate. Lock-sysmeta-only POST is not
/// a data overwrite and is not denied. Malformed lock headers deny
/// inside [`native_mutation_allowed`]. A live object whose metadata cannot
/// be read fails closed (500) instead of treating the object as unlocked.
fn deny_locked_native_mutation(
    req: &Request,
    existing: Option<Result<&Metadata, DiskFileError>>,
) -> Option<Response> {
    if req
        .headers
        .get("X-Backend-Replication")
        .is_some_and(config_true_value)
    {
        return None;
    }
    let meta = match existing {
        None => return None,
        Some(Ok(meta)) => meta,
        Some(Err(e)) => return Some(plain_response(500, &e.to_string())),
    };
    let headers = metadata_as_headers(meta);
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    // clock_ok stays true until a clock-health signal exists.
    if native_mutation_allowed_for(
        &req.method,
        &headers,
        Some(&req.headers),
        now_unix,
        true,
        NativeGovernanceBypass::NONE,
    ) {
        None
    } else {
        Some(plain_response(403, "object is locked"))
    }
}

/// PUT `If-Match` against the current object ETag (same value GET emits).
/// Missing object or mismatch → 412. Header absent → no precondition.
fn put_if_match_precondition(
    req: &Request,
    orig_exists: bool,
    orig_metadata: Option<&Metadata>,
) -> Option<Response> {
    let Some(if_match) = req.headers.get("If-Match") else {
        return None;
    };
    if !orig_exists {
        return Some(swob_response(412));
    }
    let etag = orig_metadata.map(object_etag).unwrap_or("");
    if Match::parse(if_match).matches(etag) {
        None
    } else {
        Some(swob_response(412))
    }
}

/// Python `fallocate()`'s FALLOCATE_RESERVE check, absolute-bytes mode: would
/// writing `size` bytes leave the device's filesystem with `free` bytes
/// available at or below the reserve? Zero-length writes never trip the
/// reserve (Python skips the check when `size` is falsy) and a non-positive
/// reserve disables it. Percent reserves compare against the device's TOTAL
/// capacity, which the shared `fsutil` contract does not expose, so percent
/// mode is not enforced here yet.
fn fallocate_reserve_breached(free: u64, size: u64, reserve: &FallocateReserve) -> bool {
    if size == 0 {
        return false;
    }
    match reserve {
        FallocateReserve::Bytes(reserve) if *reserve > 0 => {
            (free as i128) - (size as i128) <= (*reserve as i128)
        }
        _ => false,
    }
}

impl ObjectServer {
    pub fn new(config: ObjectServerConfig) -> Self {
        ObjectServer {
            config,
            // swift.common.utils: fallocate_reserve defaults to "1%".
            fallocate_reserve: FallocateReserve::Percent(1.0),
        }
    }

    /// Builder-style override for the `fallocate_reserve` parsed by
    /// `swift_core::config::config_fallocate_value`.
    pub fn with_fallocate_reserve(mut self, reserve: FallocateReserve) -> Self {
        self.fallocate_reserve = reserve;
        self
    }

    fn check_drive(&self, drive: &str) -> Result<(), Response> {
        // Use the same drive-name and mount semantics as the account and
        // container servers. In production, mount_check prevents a lost mount
        // from redirecting object I/O into the underlying root filesystem;
        // SAIO may explicitly disable it and use a plain device directory.
        swift_core::constraints::check_drive(&self.config.devices, drive, self.config.mount_check)
            .map(|_| ())
            .map_err(|_| swob_response(507))
    }

    #[allow(clippy::type_complexity)]
    fn obj_path(
        &self,
        req: &Request,
    ) -> Result<(String, u64, String, String, String, u32, PolicyKind), Response> {
        let (policy_index, policy) = self.storage_policy(req)?;
        let segs = split_path(&req.path, 5, 5, true).map_err(|e| plain_response(400, &e))?;
        let drive = segs[0].clone().unwrap_or_default();
        let part: u64 = segs[1]
            .clone()
            .unwrap_or_default()
            .parse()
            .map_err(|_| plain_response(400, "bad partition"))?;
        let account = segs[2].clone().unwrap_or_default();
        let container = segs[3].clone().unwrap_or_default();
        let obj = segs[4].clone().unwrap_or_default();
        Ok((drive, part, account, container, obj, policy_index, policy))
    }

    fn diskfile_for(
        &self,
        drive: &str,
        part: u64,
        account: &str,
        container: &str,
        obj: &str,
        policy: (u32, PolicyKind),
    ) -> Result<DiskFile, DiskFileError> {
        let (policy_index, policy) = policy;
        DiskFile::new(
            &self.config.devices.join(drive),
            part,
            account,
            container,
            obj,
            policy,
            policy_index,
            &self.config.hash_config,
            self.config.diskfile.clone(),
        )
    }

    fn storage_policy(&self, req: &Request) -> Result<(u32, PolicyKind), Response> {
        let raw = req.headers.get("X-Backend-Storage-Policy-Index");
        let policy_index = match raw {
            None => 0,
            Some(raw) => {
                let trimmed = raw.trim();
                let digits = trimmed.strip_prefix('+').unwrap_or(trimmed);
                if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err(plain_response(503, &format!("No policy with index {raw}")));
                }
                match digits.parse::<u32>() {
                    Ok(index) => index,
                    Err(_) => {
                        return Err(plain_response(503, &format!("No policy with index {raw}")))
                    }
                }
            }
        };
        let Some(policy) = self.config.policies.get(&policy_index).copied() else {
            return Err(plain_response(
                503,
                &format!("No policy with index {}", raw.unwrap_or("0")),
            ));
        };
        Ok((policy_index, policy))
    }

    /// Python-compatible object-server REPLICATE hash endpoint.
    ///
    /// A request without suffixes returns the partition's replication or EC
    /// suffix-hash dictionary. A request carrying suffixes only marks valid
    /// three-hex suffixes dirty and returns pickled `None`; the following
    /// no-suffix request performs the rehash. Both forms use pickle protocol 2
    /// for compatibility with older Swift nodes.
    fn replicate(&self, req: &Request) -> Response {
        let segments = match split_path(&req.path, 2, 3, true) {
            Ok(segments) => segments,
            Err(error) => return plain_response(400, &error),
        };
        let device = segments[0].clone().unwrap_or_default();
        let partition = segments[1].clone().unwrap_or_default();
        if device.is_empty() || matches!(device.as_str(), "." | "..") {
            return plain_response(400, &format!("Invalid device: {device}"));
        }
        if partition.is_empty() || matches!(partition.as_str(), "." | "..") {
            return plain_response(400, &format!("Invalid partition: {partition}"));
        }
        let (policy_index, policy) = match self.storage_policy(req) {
            Ok(policy) => policy,
            Err(response) => return response,
        };
        if let Err(response) = self.check_drive(&device) {
            return response;
        }

        let partition_path = self
            .config
            .devices
            .join(&device)
            .join(get_data_dir(policy_index))
            .join(&partition);
        let suffix_parts = segments[2]
            .as_deref()
            .filter(|suffixes| !suffixes.is_empty());
        let value = if let Some(suffix_parts) = suffix_parts {
            for suffix in suffix_parts
                .split('-')
                .filter(|suffix| valid_suffix(suffix))
            {
                if let Err(error) = invalidate_hash(&partition_path.join(suffix)) {
                    return plain_response(500, &error.to_string());
                }
            }
            PickleValue::None
        } else if !partition_path.exists() {
            PickleValue::Dict(Vec::new())
        } else {
            match get_partition_hashes(
                &partition_path,
                policy,
                &[],
                false,
                &self.config.diskfile.cleanup,
            ) {
                Ok((_hashed, hashes)) => hashes.to_value(),
                Err(error) => return plain_response(500, &error.to_string()),
            }
        };

        match pickle::dumps(&value) {
            Ok(body) => Response::with_body(200, body),
            Err(error) => plain_response(500, &error.to_string()),
        }
    }

    /// SSYNC receiver (`ssync_receiver.Receiver`), replication and EC.
    ///
    /// Validation failures before the exchange begins return ordinary HTTP
    /// error responses (Python raises them from `initialize_request`). Once
    /// validation passes, the handler hijacks the connection and speaks the
    /// full-duplex protocol itself: it writes the `200 OK` head (declaring
    /// `Transfer-Encoding: chunked` and framing every payload by hand, as
    /// eventlet does), reads the sender's missing-check section, answers with
    /// the wanted list, applies each updates-phase subrequest as it arrives,
    /// and reports the final `:UPDATES:` frame. In-session errors are conveyed
    /// in-band as Python does: an `:ERROR: <status> <repr>\n` line inside the
    /// 200 body.
    /// `DiskFileManager.replication_lock_timeout` default (seconds).
    const REPLICATION_LOCK_TIMEOUT: f64 = 15.0;

    fn ssync(&self, req: &mut Request) -> Response {
        let segments = match split_path(&req.path, 2, 2, false) {
            Ok(segments) => segments,
            Err(error) => return plain_response(400, &error),
        };
        let device = segments[0].clone().unwrap_or_default();
        let raw_partition = segments[1].clone().unwrap_or_default();
        if device.is_empty() || matches!(device.as_str(), "." | "..") {
            return plain_response(400, &format!("Invalid device: {device}"));
        }
        if raw_partition.parse::<u64>().is_err() {
            return plain_response(400, &format!("Invalid partition: {raw_partition}"));
        }
        let (policy_index, policy) = match self.storage_policy(req) {
            Ok(policy) => policy,
            Err(response) => return response,
        };
        // Python parses X-Backend-Ssync-Frag-Index for any policy; it only
        // has an effect on EC diskfiles.
        let frag_index: Option<i64> = match req.headers.get("X-Backend-Ssync-Frag-Index") {
            None | Some("") => None,
            Some(raw) => match raw.trim().parse::<i64>() {
                Ok(frag_index) => Some(frag_index),
                Err(_) => {
                    return plain_response(
                        400,
                        &format!("Invalid X-Backend-Ssync-Frag-Index {raw:?}"),
                    )
                }
            },
        };
        if let Err(response) = self.check_drive(&device) {
            return response;
        }
        // Python's receiver holds the partition 'replication' lock for the
        // whole exchange (Receiver.__call__ via DiskFileManager
        // .replication_lock) — the same flock the reconstructor's revert and
        // the replicator take, so cross-replication (Rust OR Python daemons
        // on this node) cannot race this session. Timeout -> 503, before the
        // connection is hijacked.
        let part_path = self
            .config
            .devices
            .join(&device)
            .join(get_data_dir(policy_index))
            .join(&raw_partition);
        let Ok(_replication_lock) = swift_core::lockutil::lock_path(
            &part_path,
            Self::REPLICATION_LOCK_TIMEOUT,
            Some("replication"),
        ) else {
            return swob_response(503);
        };

        let Some(mut wire) = req.body.hijack() else {
            // Should not happen on a real connection; refuse rather than
            // half-speak the protocol.
            return plain_response(500, "SSYNC requires a hijackable connection");
        };
        let (mut reader, _) = req.body.take().into_reader();
        let session = SsyncSession {
            server: self,
            device,
            partition: raw_partition,
            policy_index,
            policy,
            frag_index,
        };
        // The sender may see a broken pipe rather than this sentinel; every
        // write after the hijack belongs to the handler and IO errors simply
        // end the exchange (the server closes the connection afterwards).
        let head = b"HTTP/1.1 200 OK\r\n\
             X-Backend-Accept-No-Commit: True\r\n\
             Content-Type: text/plain\r\n\
             Transfer-Encoding: chunked\r\n\r\n";
        if wire.write_all(head).is_ok() {
            let _ = session.run(&mut *reader, &mut *wire);
        }
        // The connection was hijacked: this response never reaches the wire.
        Response::new(499)
    }

    fn apply_ssync_update(
        &self,
        device: &str,
        partition: &str,
        policy_index: u32,
        frag_index: Option<i64>,
        update: SsyncSubrequest,
    ) -> Response {
        let mut headers = update.headers;
        headers.set("X-Backend-Storage-Policy-Index", policy_index);
        headers.set("X-Backend-Replication", "True");
        if let Some(frag_index) = frag_index {
            // primary node should not 409 if it has a non-primary fragment
            headers.set("X-Backend-Ssync-Frag-Index", frag_index);
        }
        if !update.replication_headers.is_empty() {
            headers.set(
                "X-Backend-Replication-Headers",
                update.replication_headers.join(" "),
            );
        }
        let decoded_path = unquote(&update.path);
        self.handle(Request {
            method: update.method,
            path: format!("/{device}/{partition}{decoded_path}"),
            query_string: String::new(),
            headers,
            body: update.body.into(),
        })
    }

    fn valid_timestamp(req: &Request) -> Result<Timestamp, Response> {
        req.headers
            .get("X-Timestamp")
            .ok_or_else(|| plain_response(400, "Missing X-Timestamp header"))
            .and_then(|raw| {
                raw.parse()
                    .map_err(|_| plain_response(400, "Invalid X-Timestamp header"))
            })
    }

    pub fn handle(&self, mut req: Request) -> Response {
        // Reject object names carrying a NUL byte before dispatch, as the
        // proxy does with `check_utf8`. Matches the functional-test contract
        // of 412 "Invalid UTF8 or contains NULL".
        if req.path.contains('\u{0}') {
            return plain_response(412, "Invalid UTF8 or contains NULL");
        }
        if req.path == "/recon/stage" && matches!(req.method.as_str(), "GET" | "HEAD") {
            let body = swift_core::stage::snapshot_json();
            let mut resp = Response::with_body(
                200,
                if req.method == "HEAD" {
                    Vec::new()
                } else {
                    body.clone().into_bytes()
                },
            );
            resp.headers
                .set("Content-Type", "application/json; charset=utf-8");
            resp.headers.set("Content-Length", body.len());
            return resp;
        }
        let mut resp = match req.method.as_str() {
            // GET/HEAD are conditional responses: an otherwise-2xx result may be
            // reduced to a 304/412 by If-[None-]Match / If-[Un]Modified-Since.
            "GET" => swift_http::apply_conditional(&req, self.get(&req, true)),
            "HEAD" => swift_http::apply_conditional(&req, self.get(&req, false)),
            "PUT" => self.put(&mut req),
            "POST" => self.post(&req),
            "DELETE" => self.delete(&req),
            "REPLICATE" => self.replicate(&req),
            "SSYNC" => self.ssync(&mut req),
            "OPTIONS" => {
                let mut resp = Response::new(200);
                resp.headers.set(
                    "Allow",
                    "DELETE, GET, HEAD, OPTIONS, POST, PUT, REPLICATE, SSYNC",
                );
                resp
            }
            _ => {
                let mut resp = swob_response(405);
                resp.headers.set(
                    "Allow",
                    "DELETE, GET, HEAD, OPTIONS, POST, PUT, REPLICATE, SSYNC",
                );
                resp
            }
        };
        resp.headers
            .setdefault("Content-Type", "text/html; charset=UTF-8");
        resp
    }

    fn put(&self, req: &mut Request) -> Response {
        let _meta_stage =
            swift_core::stage::StageTimer::start("object-server", "put", "metadata_parse");
        let (drive, part, account, container, obj, policy_index, policy) = match self.obj_path(req)
        {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        let req_timestamp = match Self::valid_timestamp(req) {
            Ok(t) => t,
            Err(resp) => return resp,
        };
        if let Err(resp) = self.check_drive(&drive) {
            return resp;
        }
        // check_object_creation: content-type + content-length required
        let Some(content_type) = req.headers.get("Content-Type") else {
            return plain_response(400, "No content type");
        };
        let content_type = content_type.to_string();
        if req.headers.get("Content-Length").is_none()
            && !req
                .headers
                .get("Transfer-Encoding")
                .is_some_and(|te| te.eq_ignore_ascii_case("chunked"))
        {
            return plain_response(411, "Missing Content-Length header.");
        }
        // The multipart-MIME backend PUT (X-Backend-Obj-* headers): the
        // request body is MIME documents — object data, then a metadata
        // footer, then (multiphase) a commit confirmation after a second
        // 100 Continue. server.py:881-918.
        use swift_core::config::config_true_value;
        let have_footer = req
            .headers
            .get("X-Backend-Obj-Metadata-Footer")
            .is_some_and(config_true_value);
        let multiphase = req
            .headers
            .get("X-Backend-Obj-Multiphase-Commit")
            .is_some_and(config_true_value);
        let mime_mode = have_footer || multiphase;
        // The declared object length (None when unknown) drives the
        // MAX_FILE_SIZE pre-check and the fallocate reserve; the streamed
        // byte count is verified against it at EOF. In MIME mode the
        // request Content-Length describes the whole MIME body, so the
        // object length travels in X-Backend-Obj-Content-Length.
        let declared_len: Option<u64> = if mime_mode {
            req.headers
                .get("X-Backend-Obj-Content-Length")
                .and_then(|s| s.trim().parse::<u64>().ok())
        } else {
            req.headers
                .get("Content-Length")
                .and_then(|s| s.trim().parse::<u64>().ok())
                .or_else(|| req.body.content_length())
        };
        if declared_len.is_some_and(|len| len > MAX_FILE_SIZE as u64) {
            return plain_response(413, "Your request is too large.");
        }
        // Only `If-None-Match: *` is supported on a write; anything else is a
        // 400 (the proxy's `If-None-Match only supports *`).
        if let Some(inm) = req.headers.get("If-None-Match") {
            if !if_none_match_has_star(inm) {
                return plain_response(400, "If-None-Match only supports *");
            }
        }
        // Validate/normalize X-Delete-After / X-Delete-At (check_delete_headers).
        let resolved_delete_at = match check_delete_headers(req, req_timestamp.as_secs_f64()) {
            Ok(v) => v,
            Err(resp) => return resp,
        };

        // Pre-create checks against any existing object: If-None-Match,
        // If-Match, the timestamp-conflict guard, and the experimental native
        // lock gate. A live object yields its metadata (sysmeta included); an
        // expired object is absent for If-* but still carries lock sysmeta.
        // A tombstone/missing object yields no metadata but still carries a
        // timestamp for the conflict guard.
        // SSYNC subrequests carry a Frag-Index header, in which case the
        // pre-open ignores non-matching on-disk data files so a primary
        // holding a different fragment does not 409 (server.py:833).
        let ssync_frag_index: Option<i64> = req
            .headers
            .get("X-Backend-Ssync-Frag-Index")
            .and_then(|raw| raw.trim().parse().ok());
        let (orig_exists, orig_timestamp, orig_metadata) = match self
            .diskfile_for(
                &drive,
                part,
                &account,
                &container,
                &obj,
                (policy_index, policy),
            )
            .map(|df| df.with_frag_index(ssync_frag_index))
        {
            Ok(mut pre) => match pre.open(None) {
                Ok(opened) => {
                    let ts = opened
                        .data_timestamp()
                        .unwrap_or_else(|_| "0".parse().unwrap());
                    // Live object: metadata read failure is not "unlocked".
                    match opened.get_metadata() {
                        Ok(meta) => (true, ts, Some(meta.clone())),
                        Err(e) => return plain_response(500, &e.to_string()),
                    }
                }
                Err(DiskFileError::Deleted { timestamp, .. }) => (false, timestamp, None),
                // An expired object counts as absent for If-None-Match / If-Match,
                // but its timestamp still guards against an out-of-order
                // overwrite and its lock sysmeta still feeds the lock gate.
                Err(DiskFileError::Expired { metadata }) => {
                    let ts = meta_get(&metadata, "X-Timestamp")
                        .and_then(|s| s.parse::<Timestamp>().ok())
                        .unwrap_or_else(|| "0".parse().unwrap());
                    (false, ts, Some(metadata))
                }
                Err(DiskFileError::NotExist) | Err(DiskFileError::Quarantined(_)) => {
                    (false, "0".parse().unwrap(), None)
                }
                Err(e) => return plain_response(500, &e.to_string()),
            },
            Err(e) => return plain_response(500, &e.to_string()),
        };
        // If-None-Match only reaches here as `*` (non-`*` rejected above): a
        // wildcard match against an existing object is a 412.
        if orig_exists && req.headers.get("If-None-Match").is_some() {
            return swob_response(412);
        }
        if orig_timestamp >= req_timestamp {
            let mut resp = swob_response(409);
            resp.headers
                .set("X-Backend-Timestamp", orig_timestamp.internal());
            return resp;
        }
        if let Some(resp) = put_if_match_precondition(req, orig_exists, orig_metadata.as_ref()) {
            return resp;
        }
        // Experimental native lock: live or expired metadata bag. No object →
        // allow PUT. Replicate/ssync skip inside the helper. Not live-proven.
        if orig_exists || orig_metadata.is_some() {
            if let Some(resp) = deny_locked_native_mutation(
                req,
                orig_metadata
                    .as_ref()
                    .map(|meta| Ok::<_, DiskFileError>(meta)),
            ) {
                return resp;
            }
        }

        // fallocate_reserve: refuse the write before any data lands when it
        // would drop the device's free space to or below the configured
        // reserve — the point where Python's DiskFileWriter raises
        // DiskFileNoSpace out of fallocate() and server.py answers 507. A
        // statvfs failure fails open; the write itself still ENOSPCs.
        // Chunked transfers declare no length, so (as in Python, which
        // fallocates only when a size is known) they cannot pre-reserve.
        if let Ok(free) = swift_core::fsutil::free_bytes(&self.config.devices.join(&drive)) {
            if fallocate_reserve_breached(free, declared_len.unwrap_or(0), &self.fallocate_reserve)
            {
                return swob_response(507);
            }
        }

        let df = match self.diskfile_for(
            &drive,
            part,
            &account,
            &container,
            &obj,
            (policy_index, policy),
        ) {
            Ok(df) => df,
            Err(e) => return plain_response(500, &e.to_string()),
        };

        let mut writer = match df.create(".data") {
            Ok(w) => w,
            Err(DiskFileError::NoSpace) => return swob_response(507),
            Err(e) => return plain_response(500, &e.to_string()),
        };
        // MIME mode: advertise the capabilities on the first 100 Continue
        // (server.py:884-900) and position the parser at the object-body
        // document. The interim handle is a no-op when the proxy did not
        // send Expect (eventlet parity).
        let interim = req.body.interim_responder();
        let mut mime_docs: Option<MimeDocs> = if mime_mode {
            let Some(boundary) = req
                .headers
                .get("X-Backend-Obj-Multipart-Mime-Boundary")
                .map(str::to_string)
            else {
                return plain_response(400, "no MIME boundary");
            };
            let mut adverts: Vec<(&str, &str)> = Vec::new();
            if multiphase {
                adverts.push(("X-Obj-Multiphase-Commit", "yes"));
            }
            if have_footer {
                adverts.push(("X-Obj-Metadata-Footer", "yes"));
            }
            if let Some(i) = &interim {
                if i.send_continue(&adverts).is_err() {
                    return swob_response(499);
                }
            }
            let (reader, _) = req.body.take().into_reader();
            let mut docs = MimeDocs::new(reader, boundary.as_bytes());
            match docs.next_document() {
                Ok(Some(_object_body_headers)) => {}
                Ok(None) => return plain_response(400, "no object body MIME doc"),
                Err(e) => return mime_read_error(&e),
            }
            Some(docs)
        } else {
            None
        };
        let mut plain_reader = if mime_docs.is_none() {
            Some(req.body.take().into_reader().0)
        } else {
            None
        };
        // Consume the object data as a stream: 64KB chunks into the
        // writer, which keeps the incremental md5 and byte count. All
        // abort paths below return without `put()`, so the writer's drop
        // removes the temp file (Python: the `with diskfile.create()`
        // block unwinding without a put).
        drop(_meta_stage);
        let _write_stage =
            swift_core::stage::StageTimer::start("object-server", "put", "disk_write");
        let mut buf = [0u8; STREAM_CHUNK];
        let mut upload_size: u64 = 0;
        loop {
            let read = match (&mut mime_docs, &mut plain_reader) {
                (Some(docs), _) => docs.read(&mut buf),
                (None, Some(reader)) => reader.read(&mut buf),
                (None, None) => unreachable!(),
            };
            let n = match read {
                Ok(0) => break,
                Ok(n) => n,
                // The chunked decoder's body cap surfaces mid-read as the
                // too-large error (Python: wsgi input raising on an
                // oversized chunked body -> 413).
                Err(e) if swift_http::body_too_large(&e) => {
                    return plain_response(413, "Your request is too large.")
                }
                // ChunkReadError: client hung up / short body -> 499, no
                // commit.
                Err(_) => return swob_response(499),
            };
            upload_size += n as u64;
            if upload_size > MAX_FILE_SIZE as u64 {
                return plain_response(413, "Your request is too large.");
            }
            if let Err(e) = writer.write(&buf[..n]) {
                return plain_response(500, &e.to_string());
            }
        }
        // Python raises ChunkReadError when the body ends short of the
        // declared Content-Length: 499, nothing committed.
        if declared_len.is_some_and(|declared| declared != upload_size) {
            return swob_response(499);
        }
        // The metadata footer document (server.py:571-604, 979-994).
        let footers: Vec<(String, String)> = match (&mut mime_docs, have_footer) {
            (Some(docs), true) => match read_footer_metadata(docs) {
                Ok(f) => f,
                Err(resp) => return resp,
            },
            _ => Vec::new(),
        };
        let footer_get = |name: &str| {
            footers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str())
        };
        drop(_write_stage);
        let (upload_size, etag) = {
            let _hash = swift_core::stage::StageTimer::start("object-server", "put", "hash");
            writer.chunks_finished()
        };
        // The received etag — footer first, else the request header — must
        // match the streamed md5 (server.py:996-1007; the body is already
        // consumed at this point, as in Python).
        let received_etag = footer_get("etag")
            .or_else(|| req.headers.get("ETag"))
            .unwrap_or("");
        let normalized = received_etag.trim_matches('"');
        if !normalized.is_empty() && !normalized.eq_ignore_ascii_case(&etag) {
            return swob_response(422);
        }
        let mut metadata: Metadata = vec![
            (
                "X-Timestamp".into(),
                MetaValue::Str(req_timestamp.internal()),
            ),
            ("Content-Type".into(), MetaValue::Str(content_type.clone())),
            (
                "Content-Length".into(),
                MetaValue::Str(upload_size.to_string()),
            ),
            ("ETag".into(), MetaValue::Str(etag.clone())),
        ];
        // user/sysmeta and transient sysmeta from the request headers
        for (k, v) in req.headers.iter() {
            let lower = k.to_ascii_lowercase();
            let is_core = matches!(
                lower.as_str(),
                "x-timestamp"
                    | "content-type"
                    | "content-length"
                    | "etag"
                    | "x-delete-at"
                    | "x-delete-after"
            );
            if should_persist_header(req, k) && !is_core {
                metadata.push((MetaValue::Str(k.to_string()), MetaValue::Str(v.to_string())));
            }
        }
        // Footer sysmeta/user-meta overrides header-sourced entries
        // (server.py:996-1002: metadata.update(footers sys/user meta)).
        for (k, v) in &footers {
            if is_sys_or_user_meta(k) || is_object_transient_sysmeta(k) {
                meta_upsert(&mut metadata, k, v.clone());
            }
        }
        // Persist the normalized X-Delete-At as datafile metadata (Python
        // stores it via `allowed_headers`); this is what HEAD/GET echoes and
        // the expirer reads.
        if let Some(delete_at) = &resolved_delete_at {
            metadata.push((
                MetaValue::Str("X-Delete-At".into()),
                MetaValue::Str(delete_at.clone()),
            ));
        }

        let _commit_stage = swift_core::stage::StageTimer::start("object-server", "put", "commit");
        if let Err(e) = writer.put(metadata) {
            writer.close();
            return match e {
                DiskFileError::NoSpace | DiskFileError::XattrNotSupported => swob_response(507),
                other => plain_response(500, &other.to_string()),
            };
        }
        drop(_commit_stage);
        // Two-phase commit (server.py:1009-1021): the fragment is on disk
        // but NOT durable; tell the proxy with a second 100 Continue (which
        // also re-arms the chunked body for the commit sequence), then
        // require the commit confirmation document before making it
        // durable.
        if multiphase {
            let Some(docs) = &mut mime_docs else {
                writer.close();
                return plain_response(400, "multiphase commit requires a MIME body");
            };
            if let Some(i) = &interim {
                if i.send_continue(&[]).is_err() {
                    writer.close();
                    return swob_response(499);
                }
            }
            match docs.next_document() {
                Ok(Some(headers)) => {
                    let is_commit = headers
                        .iter()
                        .any(|(k, v)| k.eq_ignore_ascii_case("X-Document") && v == "put commit");
                    if !is_commit {
                        writer.close();
                        return plain_response(500, "expected put commit MIME doc");
                    }
                }
                Ok(None) => {
                    writer.close();
                    return plain_response(400, "couldn't find PUT commit MIME doc");
                }
                Err(_) => {
                    writer.close();
                    return swob_response(499);
                }
            }
        }
        // The ssync sender marks a non-durable EC fragment PUT with
        // X-Backend-No-Commit; legacy default is to commit (server.py:1095).
        if !req
            .headers
            .get("X-Backend-No-Commit")
            .is_some_and(config_true_value)
        {
            if let Err(e) = writer.commit(&req_timestamp) {
                writer.close();
                return plain_response(500, &e.to_string());
            }
        }
        writer.close();
        // Drain any remaining MIME docs (there should be none, but the
        // whole request body must be read; server.py:1023-1033, bounded).
        if let Some(docs) = &mut mime_docs {
            for _ in 0..16 {
                match docs.next_document() {
                    Ok(Some(_)) => continue,
                    _ => break,
                }
            }
        }

        // container update side channel: the actually-written byte count
        // and streamed md5, not the declared header values — unless the
        // request/footers carry container-update overrides (EC PUTs
        // override with the whole-object etag/size so listings show the
        // object, not the fragment archive; server.py:606-645).
        let mut update = HeaderKeyDict::new();
        update.set("x-size", upload_size);
        update.set("x-content-type", &content_type);
        update.set("x-timestamp", req_timestamp.internal());
        update.set("x-etag", &etag);
        apply_container_override(&mut update, &req.headers, &footers);
        self.container_update(
            "PUT",
            &drive,
            &account,
            &container,
            &obj,
            req,
            &update,
            policy_index,
        );
        // enqueue expiry if the object has an X-Delete-At
        if let Some(delete_at) = resolved_delete_at
            .as_deref()
            .and_then(|v| v.parse::<i64>().ok())
        {
            self.delete_at_update(
                delete_at,
                &drive,
                &account,
                &container,
                &obj,
                req,
                policy_index,
            );
        }

        let mut resp = Response::new(201);
        resp.headers.set("ETag", format!("\"{etag}\""));
        resp
    }

    fn post(&self, req: &Request) -> Response {
        let (drive, part, account, container, obj, policy_index, policy) = match self.obj_path(req)
        {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        let req_timestamp = match Self::valid_timestamp(req) {
            Ok(t) => t,
            Err(resp) => return resp,
        };
        if let Err(resp) = self.check_drive(&drive) {
            return resp;
        }
        // POST rejects an X-Delete-At already in the past (Python server.py POST
        // uses a plain `new_delete_at < req_timestamp` guard, not the normalizing
        // check_delete_headers used on PUT).
        if let Some(raw) = req.headers.get("X-Delete-At") {
            if let Some(v) = parse_int_like(raw) {
                if v != 0.0 && v < req_timestamp.as_secs_f64() {
                    return plain_response(400, "X-Delete-At in past");
                }
            }
        }
        let mut df = match self.diskfile_for(
            &drive,
            part,
            &account,
            &container,
            &obj,
            (policy_index, policy),
        ) {
            Ok(df) => df,
            Err(e) => return plain_response(500, &e.to_string()),
        };
        let orig = match df.open(None) {
            Ok(df) => df,
            Err(DiskFileError::NotExist) | Err(DiskFileError::Deleted { .. }) => {
                return swob_response(404)
            }
            // Python DiskFileExpired subclasses DiskFileNotExist, so
            // server.py POST (690-691) turns an expired object into the
            // same 404.
            Err(DiskFileError::Expired { .. }) => return swob_response(404),
            Err(DiskFileError::Quarantined(_)) => return swob_response(404),
            Err(e) => return plain_response(500, &e.to_string()),
        };
        let orig_timestamp = orig
            .get_metadata()
            .ok()
            .and_then(|m| meta_get(m, "X-Timestamp"))
            .and_then(|s| s.parse::<Timestamp>().ok())
            .unwrap_or_else(|| "0".parse().unwrap());
        // server.py 696: the timestamp the current content-type carries — the
        // one encoded in the newest .meta, else the datafile's X-Timestamp.
        let orig_ctype_timestamp = orig
            .content_type_timestamp()
            .unwrap_or_else(|_| "0".parse().unwrap());
        // server.py 697-702: a request Content-Type is stamped with the
        // explicit Content-Type-Timestamp header when one is supplied
        // (replication), else with the request timestamp; a POST carrying NO
        // Content-Type gets Timestamp zero so it can never displace the
        // on-disk content-type. (Python truthiness: an empty Content-Type
        // counts as absent.)
        let req_ctype_timestamp: Timestamp = if req
            .headers
            .get("Content-Type")
            .is_some_and(|c| !c.is_empty())
        {
            match req.headers.get("Content-Type-Timestamp") {
                Some(raw) => match raw.parse() {
                    Ok(t) => t,
                    // Python's Timestamp() raises out of the handler: 500.
                    Err(_) => return plain_response(500, "invalid Content-Type-Timestamp"),
                },
                None => req_timestamp,
            }
        } else {
            "0".parse().unwrap()
        };
        // server.py 703-707: conflict only when BOTH the metadata timestamp
        // and the content-type timestamp are older-or-equal; a POST that lost
        // the metadata race may still deliver a newer content-type.
        if orig_timestamp >= req_timestamp && orig_ctype_timestamp >= req_ctype_timestamp {
            let mut resp = swob_response(409);
            resp.headers
                .set("X-Backend-Timestamp", orig_timestamp.internal());
            return resp;
        }
        // Experimental native lock on existing-object POST. Replicate/ssync
        // skip. Lock-sysmeta-only POST is not denied. Unreadable metadata
        // fails closed (500).
        if let Some(resp) = deny_locked_native_mutation(req, Some(orig.get_metadata())) {
            return resp;
        }
        let content_length = orig
            .get_metadata()
            .ok()
            .and_then(|m| meta_get(m, "Content-Length"))
            .unwrap_or("0")
            .to_string();
        let etag = orig
            .get_metadata()
            .ok()
            .and_then(|m| meta_get(m, "ETag"))
            .unwrap_or("")
            .to_string();
        let data_timestamp = orig
            .data_timestamp()
            .unwrap_or_else(|_| "0".parse().unwrap());
        // the merged current content-type (from the newest .meta carrying one,
        // else the datafile)
        let orig_content_type = orig.content_type().ok().flatten().unwrap_or("").to_string();
        // the datafile's own content-type, for the swift_bytes carry-over on
        // the container update below
        let datafile_content_type = orig
            .get_datafile_metadata()
            .ok()
            .and_then(|m| meta_get(m, "Content-Type"))
            .unwrap_or("")
            .to_string();
        let metafile_metadata: Option<Metadata> =
            orig.get_metafile_metadata().ok().flatten().cloned();

        // server.py 709-732: a POST newer than the current metadata replaces
        // the whole .meta with fresh user meta from the request; an older POST
        // (alive only because its content-type is newer) preserves the
        // existing .meta metadata verbatim — only the content-type may change.
        let mut metadata: Metadata = if req_timestamp > orig_timestamp {
            let mut m: Metadata = vec![(
                "X-Timestamp".into(),
                MetaValue::Str(req_timestamp.internal()),
            )];
            for (k, v) in req.headers.iter() {
                let is_core = matches!(
                    k.to_ascii_lowercase().as_str(),
                    "x-timestamp" | "content-type" | "content-type-timestamp"
                );
                if should_persist_header(req, k) && !is_core {
                    m.push((MetaValue::Str(k.to_string()), MetaValue::Str(v.to_string())));
                }
            }
            m
        } else {
            // server.py 731-732: `metadata = dict(disk_file.get_metafile_metadata())`.
            // With no .meta on disk Python raises (dict(None)) into a 500; no
            // well-formed request reaches this, since a request content-type
            // timestamp never exceeds a metadata timestamp that itself does
            // not exceed the datafile timestamp.
            match metafile_metadata {
                Some(m) => m,
                None => return plain_response(500, "POST preserving absent .meta metadata"),
            }
        };
        // Deferred, as elsewhere: _conditional_delete_at_update (delete-at
        // queue maintenance on POST) is not yet ported.

        // server.py 733-748: resolve which content-type wins. A newer request
        // content-type goes into the .meta stamped with its own timestamp;
        // otherwise the ORIGINAL content-type keeps its ORIGINAL timestamp and
        // is written into the .meta only when it did not come from the .data
        // file (a datafile content-type is implicit in any .meta without one).
        let (resolved_ctype, resolved_ctype_timestamp) =
            if req_ctype_timestamp > orig_ctype_timestamp {
                let new_ctype = req.headers.get("Content-Type").unwrap_or("").to_string();
                meta_upsert(&mut metadata, "Content-Type", new_ctype.clone());
                meta_upsert(
                    &mut metadata,
                    "Content-Type-Timestamp",
                    req_ctype_timestamp.internal(),
                );
                (new_ctype, req_ctype_timestamp)
            } else {
                if orig_ctype_timestamp != data_timestamp {
                    meta_upsert(&mut metadata, "Content-Type", orig_content_type.clone());
                    meta_upsert(
                        &mut metadata,
                        "Content-Type-Timestamp",
                        orig_ctype_timestamp.internal(),
                    );
                }
                (orig_content_type.clone(), orig_ctype_timestamp)
            };
        // server.py 775-776: x-meta-timestamp is metadata['X-Timestamp'] — the
        // PRESERVED original .meta timestamp when this POST lost the meta race.
        let meta_timestamp = meta_get(&metadata, "X-Timestamp")
            .unwrap_or("0")
            .to_string();

        // The .meta filename encodes (metadata timestamp, content-type
        // timestamp): write_metadata → finalize_put → make_ondisk_filename
        // appends the ctype delta exactly when Content-Type-Timestamp is
        // present in the metadata, as decided above.
        if let Err(e) = df.write_metadata(&metadata) {
            return match e {
                DiskFileError::NoSpace | DiskFileError::XattrNotSupported => swob_response(507),
                other => plain_response(500, &other.to_string()),
            };
        }

        // server.py 755-768: when the winning content-type is not the
        // datafile's, the datafile content-type may carry a swift_bytes param
        // (appended by SLO) that must continue to ride the container update.
        let mut update_ctype = resolved_ctype;
        if resolved_ctype_timestamp != data_timestamp {
            let (_, swift_bytes) = extract_swift_bytes(&datafile_content_type);
            if let Some(swift_bytes) = swift_bytes {
                update_ctype.push_str(&format!(";swift_bytes={swift_bytes}"));
            }
        }

        // server.py 770-777: the container update carries the object's
        // ORIGINAL data timestamp as x-timestamp (so the container row's
        // created_at stays at the PUT time), the RESOLVED content-type and
        // content-type timestamp (orig or new, whichever won), and the .meta
        // timestamp as x-meta-timestamp. Object POST updates are PUT to the
        // container.
        let mut update = HeaderKeyDict::new();
        update.set("x-size", content_length);
        update.set("x-content-type", &update_ctype);
        update.set("x-timestamp", data_timestamp.internal());
        update.set(
            "x-content-type-timestamp",
            resolved_ctype_timestamp.internal(),
        );
        update.set("x-meta-timestamp", &meta_timestamp);
        update.set("x-etag", &etag);
        self.container_update(
            "PUT",
            &drive,
            &account,
            &container,
            &obj,
            req,
            &update,
            policy_index,
        );

        // swob HTTPAccepted default body
        let mut resp = Response::with_body(
            202,
            b"<html><h1>Accepted</h1><p>The request is accepted for processing.</p></html>"
                .to_vec(),
        );
        resp.headers.set("Content-Type", "text/html; charset=UTF-8");
        resp
    }

    fn delete(&self, req: &Request) -> Response {
        let (drive, part, account, container, obj, policy_index, policy) = match self.obj_path(req)
        {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        let req_timestamp = match Self::valid_timestamp(req) {
            Ok(t) => t,
            Err(resp) => return resp,
        };
        if let Err(resp) = self.check_drive(&drive) {
            return resp;
        }
        // Parse X-If-Delete-At up front (Python server.py DELETE): bad value
        // → 400; when present we must verify it against the object's
        // X-Delete-At before writing a tombstone (412 on mismatch).
        let if_delete_at: Option<Timestamp> = match req.headers.get("X-If-Delete-At") {
            None => None,
            Some(raw) => match raw.parse::<Timestamp>() {
                Ok(t) => Some(t),
                Err(_) => return plain_response(400, "Bad X-If-Delete-At header value"),
            },
        };
        let mut df = match self.diskfile_for(
            &drive,
            part,
            &account,
            &container,
            &obj,
            (policy_index, policy),
        ) {
            Ok(df) => df,
            Err(e) => return plain_response(500, &e.to_string()),
        };
        // Expirer deletes already-past X-Delete-At objects; open them.
        if if_delete_at.is_some() {
            df = df.with_open_expired(true);
        }
        // A live object yields 204 (if we win the timestamp race) or 409;
        // a missing or already-deleted object always yields 404 even
        // though a fresh tombstone is still written when we win.
        let (orig_timestamp, was_live, orig_delete_at, orig_metadata) = match df.open(None) {
            Ok(_) => {
                let ts = df.data_timestamp().unwrap_or_else(|_| "0".parse().unwrap());
                let metadata = match df.get_metadata() {
                    Ok(m) => Some(m.clone()),
                    Err(e) => return plain_response(500, &e.to_string()),
                };
                let delete_at = metadata
                    .as_ref()
                    .and_then(|m| {
                        m.iter().find_map(|(k, v)| {
                            if k.as_str() != Some("X-Delete-At") {
                                return None;
                            }
                            match v {
                                MetaValue::Str(s) => s.parse::<Timestamp>().ok(),
                                MetaValue::Int(i) => i.to_string().parse::<Timestamp>().ok(),
                                _ => None,
                            }
                        })
                    })
                    .unwrap_or_else(|| "0".parse().unwrap());
                (ts, true, delete_at, metadata)
            }
            Err(DiskFileError::Deleted { timestamp, .. }) => {
                (timestamp, false, "0".parse().unwrap(), None)
            }
            Err(DiskFileError::NotExist) | Err(DiskFileError::Quarantined(_)) => {
                ("0".parse().unwrap(), false, "0".parse().unwrap(), None)
            }
            Err(DiskFileError::Expired { metadata }) => {
                // open_expired=false path; treat as live-but-expired for
                // X-If-Delete-At verification.
                let ts = metadata
                    .iter()
                    .find_map(|(k, v)| {
                        if k.as_str() == Some("X-Timestamp") {
                            v.as_str().and_then(|s| s.parse().ok())
                        } else {
                            None
                        }
                    })
                    .unwrap_or_else(|| "0".parse().unwrap());
                let delete_at = metadata
                    .iter()
                    .find_map(|(k, v)| {
                        if k.as_str() != Some("X-Delete-At") {
                            return None;
                        }
                        match v {
                            MetaValue::Str(s) => s.parse::<Timestamp>().ok(),
                            MetaValue::Int(i) => i.to_string().parse::<Timestamp>().ok(),
                            _ => None,
                        }
                    })
                    .unwrap_or_else(|| "0".parse().unwrap());
                (ts, true, delete_at, Some(metadata))
            }
            Err(e) => return plain_response(500, &e.to_string()),
        };
        // Python: when X-If-Delete-At is set, refuse to tombstone unless the
        // object's X-Delete-At matches (412) / object exists (404) / not
        // newer (409).
        if let Some(req_if) = if_delete_at {
            if !was_live {
                let mut resp = swob_response(404);
                resp.headers.set(
                    "X-Backend-Timestamp",
                    orig_timestamp.max(req_timestamp).internal(),
                );
                return resp;
            }
            if orig_timestamp >= req_timestamp {
                let mut resp = swob_response(409);
                resp.headers.set(
                    "X-Backend-Timestamp",
                    orig_timestamp.max(req_timestamp).internal(),
                );
                return resp;
            }
            if orig_delete_at != req_if {
                return plain_response(412, "X-If-Delete-At and X-Delete-At do not match");
            }
        }
        let response_timestamp = orig_timestamp.max(req_timestamp);
        let response_class = if !was_live {
            404
        } else if orig_timestamp < req_timestamp {
            204
        } else {
            409
        };
        // Experimental native lock: existing object only. Replicate/ssync skip.
        // Not live-proven, not deployed. Live metadata read failure is 500.
        if was_live && orig_timestamp < req_timestamp {
            if let Some(resp) = deny_locked_native_mutation(
                req,
                orig_metadata
                    .as_ref()
                    .map(|meta| Ok::<_, DiskFileError>(meta)),
            ) {
                return resp;
            }
        }
        if orig_timestamp < req_timestamp {
            let fresh = match self.diskfile_for(
                &drive,
                part,
                &account,
                &container,
                &obj,
                (policy_index, policy),
            ) {
                Ok(df) => df,
                Err(e) => return plain_response(500, &e.to_string()),
            };
            if let Err(e) = fresh.delete(&req_timestamp) {
                return match e {
                    DiskFileError::NoSpace => swob_response(507),
                    other => plain_response(500, &other.to_string()),
                };
            }
            let mut update = HeaderKeyDict::new();
            update.set("x-timestamp", req_timestamp.internal());
            self.container_update(
                "DELETE",
                &drive,
                &account,
                &container,
                &obj,
                req,
                &update,
                policy_index,
            );
        }
        let mut resp = match response_class {
            204 => Response::new(204),
            404 => swob_response(404),
            _ => swob_response(409),
        };
        resp.headers
            .set("X-Backend-Timestamp", response_timestamp.internal());
        resp
    }

    fn get(&self, req: &Request, include_body: bool) -> Response {
        let (drive, part, account, container, obj, policy_index, policy) = match self.obj_path(req)
        {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        if let Err(resp) = self.check_drive(&drive) {
            return resp;
        }
        let mut df = match self.diskfile_for(
            &drive,
            part,
            &account,
            &container,
            &obj,
            (policy_index, policy),
        ) {
            Ok(df) => df,
            Err(e) => return plain_response(500, &e.to_string()),
        };
        // Python `allow_open_expired` / `X-Open-Expired: true`: open a file that
        // is past X-Delete-At but has not been reaped yet. Default remains 404.
        let open_expired = req
            .headers
            .get("X-Open-Expired")
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or(false);
        df = df.with_open_expired(open_expired);
        let opened = match df.open(None) {
            Ok(df) => df,
            Err(DiskFileError::Deleted { timestamp, .. }) => {
                let mut resp = swob_response(404);
                resp.headers
                    .set("X-Backend-Timestamp", timestamp.internal());
                return resp;
            }
            // An object past its X-Delete-At reads as expired: Python treats
            // DiskFileExpired as a DiskFileNotExist -> 404 with the object's
            // timestamp echoed back.
            Err(DiskFileError::Expired { metadata }) => {
                let mut resp = swob_response(404);
                if let Some(ts) =
                    meta_get(&metadata, "X-Timestamp").and_then(|s| s.parse::<Timestamp>().ok())
                {
                    resp.headers.set("X-Backend-Timestamp", ts.internal());
                }
                return resp;
            }
            Err(DiskFileError::NotExist) | Err(DiskFileError::Quarantined(_)) => {
                return swob_response(404)
            }
            Err(e) => return plain_response(500, &e.to_string()),
        };

        let metadata = opened.get_metadata().unwrap().clone();
        let obj_size: u64 = meta_get(&metadata, "Content-Length")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let x_ts: Timestamp = meta_get(&metadata, "X-Timestamp")
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| "0".parse().unwrap());
        let etag = object_etag(&metadata).to_string();
        let content_type = meta_get(&metadata, "Content-Type")
            .unwrap_or("application/octet-stream")
            .to_string();
        let data_ts = opened
            .data_timestamp()
            .map(|t| t.internal())
            .unwrap_or_default();
        let durable_ts = opened.durable_timestamp().ok().flatten();

        // Range handling
        // `X-Backend-Ignore-Range-If-Metadata-Present` (set by the SLO/DLO
        // middlewares): drop the Range when the object carries any of the named
        // metadata — a manifest must always be served whole so the middleware
        // can reassemble, applying the client Range to the assembled object.
        let ignore_range = req
            .headers
            .get("X-Backend-Ignore-Range-If-Metadata-Present")
            .map(|names| {
                names
                    .split(',')
                    .any(|name| meta_get(&metadata, name.trim()).is_some())
            })
            .unwrap_or(false);
        let range_header = if ignore_range {
            None
        } else {
            req.headers.get("Range").map(str::to_string)
        };
        // The response is served from metadata alone; the data file's
        // contents are only opened for a body that will actually stream, so
        // HEAD never reads object data. A GET streams from disk, meaning a
        // corrupt file is detected during/after the stream (quarantine on
        // the reader's EOF/drop) rather than before the response — Python
        // parity.
        let open_reader = |df: &mut DiskFile| match df.reader() {
            Ok(r) => Ok(r),
            Err(e) => Err(plain_response(500, &e.to_string())),
        };
        let (status, body, content_range): (u16, Body, Option<String>) = match range_header
            .as_deref()
            .and_then(|h| Range::parse(h).ok())
            .map(|range| range.ranges_for_length(Some(obj_size)))
        {
            Some(Some(ranges)) if ranges.is_empty() => {
                // Python object 416 keeps identifying headers + Accept-Ranges
                // and returns a short HTML body (swob).
                let body = concat!(
                    "<html><h1>Requested Range Not Satisfiable</h1>",
                    "<p>The Range requested is not available.</p></html>"
                );
                let mut resp = Response::with_body(416, body.as_bytes().to_vec());
                resp.headers
                    .set("Content-Range", format!("bytes */{obj_size}"));
                resp.headers.set("Content-Type", &content_type);
                resp.headers.set("Accept-Ranges", "bytes");
                resp.headers.set("ETag", format!("\"{etag}\""));
                resp.headers.set("Last-Modified", http_date(x_ts.ceil()));
                resp.headers.set("X-Timestamp", x_ts.normal());
                return resp;
            }
            Some(Some(ranges)) if ranges.len() == 1 => {
                let (start, stop) = ranges[0];
                let body = if include_body {
                    let reader = match open_reader(&mut df) {
                        Ok(r) => r,
                        Err(resp) => return resp,
                    };
                    Body::from_reader(
                        Box::new(reader.range_window(start, stop)),
                        Some(stop - start),
                    )
                } else {
                    Body::empty()
                };
                (
                    206,
                    body,
                    Some(swift_http::content_range_header_value(
                        start, stop, obj_size,
                    )),
                )
            }
            // multiple ranges -> a multipart/byteranges 206 body
            Some(Some(ranges)) => {
                // deterministic 32-hex boundary derived from the object's
                // etag + the requested ranges (unique per response, stable)
                let boundary = {
                    use md5::{Digest, Md5};
                    let mut h = Md5::new();
                    h.update(etag.as_bytes());
                    for (s, e) in &ranges {
                        h.update(s.to_le_bytes());
                        h.update(e.to_le_bytes());
                    }
                    h.finalize()
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>()
                };
                // per-part headers byte-identical to
                // swift_http::multipart_byteranges; the exact body length is
                // computed up front from the part sizes so the multipart
                // stream carries a Content-Length
                let part_head = |start: u64, stop: u64| {
                    format!(
                        "--{boundary}\r\nContent-Type: {content_type}\r\nContent-Range: {}\r\n\r\n",
                        swift_http::content_range_header_value(start, stop, obj_size)
                    )
                };
                let terminator = format!("--{boundary}--");
                let total: u64 = ranges
                    .iter()
                    .map(|&(start, stop)| part_head(start, stop).len() as u64 + (stop - start) + 2)
                    .sum::<u64>()
                    + terminator.len() as u64;
                let body = if include_body {
                    let reader = match open_reader(&mut df) {
                        Ok(r) => r,
                        Err(resp) => return resp,
                    };
                    let mut parts: Vec<Box<dyn Read + Send>> = Vec::new();
                    for &(start, stop) in &ranges {
                        parts.push(Box::new(std::io::Cursor::new(
                            part_head(start, stop).into_bytes(),
                        )));
                        parts.push(Box::new(reader.range_window(start, stop)));
                        parts.push(Box::new(std::io::Cursor::new(b"\r\n".to_vec())));
                    }
                    parts.push(Box::new(std::io::Cursor::new(terminator.into_bytes())));
                    Body::from_reader(Box::new(ChainReader::new(parts)), Some(total))
                } else {
                    Body::empty()
                };
                let mut resp = Response::new(206);
                resp.body = body;
                resp.headers.set(
                    "Content-Type",
                    swift_http::multipart_byteranges_content_type(&boundary),
                );
                resp.headers.set("Content-Length", total);
                resp.headers.set("ETag", format!("\"{etag}\""));
                resp.headers.set("Last-Modified", http_date(x_ts.ceil()));
                resp.headers.set("X-Timestamp", x_ts.normal());
                resp.headers.set("Accept-Ranges", "bytes");
                return resp;
            }
            // an unparseable/unsatisfiable-for-length Range is ignored
            _ => {
                let body = if include_body {
                    let reader = match open_reader(&mut df) {
                        Ok(r) => r,
                        Err(resp) => return resp,
                    };
                    Body::from_reader(Box::new(reader.into_stream()), Some(obj_size))
                } else {
                    Body::empty()
                };
                (200, body, None)
            }
        };

        let mut resp = Response::new(status);
        resp.body = body;
        resp.headers.set("Content-Type", &content_type);
        for (k, v) in &metadata {
            if let (MetaValue::Str(key), MetaValue::Str(value)) = (k, v) {
                if is_sys_or_user_meta(key)
                    || is_object_transient_sysmeta(key)
                    || is_allowed_header(key)
                    || key.eq_ignore_ascii_case("X-Delete-At")
                {
                    resp.headers.set(key, value);
                }
            }
        }
        resp.headers.set("ETag", format!("\"{etag}\""));
        resp.headers.set("Last-Modified", http_date(x_ts.ceil()));
        resp.headers.set("X-Timestamp", x_ts.normal());
        resp.headers.set("X-Backend-Timestamp", x_ts.internal());
        resp.headers.set("X-Backend-Data-Timestamp", &data_ts);
        if let Some(durable) = durable_ts {
            resp.headers
                .set("X-Backend-Durable-Timestamp", durable.internal());
        }
        resp.headers.set("Accept-Ranges", "bytes");
        if let Some(cr) = content_range {
            resp.headers.set("Content-Range", cr);
            resp.headers
                .set("Content-Length", resp.body.content_length().unwrap_or(0));
        } else {
            resp.headers.set("Content-Length", obj_size);
        }
        resp
    }

    /// `container_update`: synchronous PUT/DELETE to the container servers
    /// named by X-Container-Host/Partition/Device. Replicas are contacted in
    /// parallel under `container_update_timeout`; any node that cannot be
    /// updated synchronously (unreachable, non-2xx, timeout, or none supplied)
    /// causes an async_pending write so the object-updater daemon replays the
    /// update later — without this, a container listing permanently misses the
    /// object when a container node is down.
    #[allow(clippy::too_many_arguments)]
    fn container_update(
        &self,
        op: &str,
        drive: &str,
        account: &str,
        container: &str,
        obj: &str,
        req: &Request,
        update: &HeaderKeyDict,
        policy_index: u32,
    ) {
        if req
            .headers
            .get("X-Backend-Replication")
            .is_some_and(config_true_value)
        {
            return;
        }
        // L1b: take the container update fully off the PUT/DELETE critical
        // path. Listing lag is bounded by object-updater drain.
        if self.config.container_update_mode == ContainerUpdateMode::Async {
            self.write_async_pending(op, drive, account, container, obj, update, policy_index);
            return;
        }
        let hosts: Vec<&str> = req
            .headers
            .get("X-Container-Host")
            .unwrap_or("")
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        let devices: Vec<&str> = req
            .headers
            .get("X-Container-Device")
            .unwrap_or("")
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        let partition = req.headers.get("X-Container-Partition").unwrap_or("");
        // Sharded roots: proxy sets X-Backend-Container-Path to the owning
        // shard's account/container so the update hits the shard DB, not the
        // root (Python object-server container_update + Container-Path).
        let (upd_account, upd_container) =
            parse_backend_container_path(req.headers.get("X-Backend-Container-Path"))
                .unwrap_or((account, container));
        let path = format!(
            "/{}/{}/{}",
            percent_encode(upd_account),
            percent_encode(upd_container),
            percent_encode(obj)
        );
        // A well-formed side channel gives matching host/device lists and a
        // partition; otherwise there is nothing to update synchronously and the
        // whole update goes async.
        let well_formed =
            !hosts.is_empty() && hosts.len() == devices.len() && !partition.is_empty();
        let all_ok = if well_formed {
            fanout_container_http(
                op,
                &hosts,
                &devices,
                partition,
                &path,
                update,
                policy_index,
                self.config.container_update_timeout,
            )
        } else {
            false
        };
        if !all_ok {
            self.write_async_pending(op, drive, account, container, obj, update, policy_index);
        }
    }

    /// `delete_at_update`: on a PUT carrying `X-Delete-At`, enqueue a task
    /// object into the hidden `.expiring_objects` account so the object-expirer
    /// deletes the object at that time. The task object is
    /// `build_task_obj(delete_at, account, container, obj)` in the hour-bucket
    /// container `get_expirer_container(delete_at)`; it is sent to the expirer
    /// container replicas named by `X-Delete-At-Host/Partition/Device`, falling
    /// back to an async_pending like any other container update.
    #[allow(clippy::too_many_arguments)]
    fn delete_at_update(
        &self,
        delete_at: i64,
        drive: &str,
        account: &str,
        container: &str,
        obj: &str,
        req: &Request,
        _policy_index: u32,
    ) {
        if req
            .headers
            .get("X-Backend-Replication")
            .is_some_and(config_true_value)
        {
            return;
        }
        let task_account = crate::expirer::EXPIRER_ACCOUNT_NAME;
        let task_container = crate::expirer::get_expirer_container(
            delete_at,
            crate::expirer::EXPIRER_CONTAINER_DIVISOR,
        );
        let task_obj = crate::expirer::build_task_obj(delete_at, account, container, obj);

        // the expiry queue entry: an empty object marking the deletion
        let mut update = HeaderKeyDict::new();
        update.set("x-size", "0");
        update.set("x-content-type", "text/plain"); // X_DELETE_TYPE
        update.set("x-etag", "d41d8cd98f00b204e9800998ecf8427e"); // md5("")
        update.set("x-timestamp", req.headers.get("X-Timestamp").unwrap_or("0"));

        let hosts: Vec<&str> = req
            .headers
            .get("X-Delete-At-Host")
            .unwrap_or("")
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        let devices: Vec<&str> = req
            .headers
            .get("X-Delete-At-Device")
            .unwrap_or("")
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        let partition = req.headers.get("X-Delete-At-Partition").unwrap_or("");
        let path = format!(
            "/{}/{}/{}",
            percent_encode(task_account),
            percent_encode(&task_container),
            percent_encode(&task_obj)
        );
        let well_formed =
            !hosts.is_empty() && hosts.len() == devices.len() && !partition.is_empty();
        let all_ok = if well_formed {
            fanout_container_http(
                "PUT",
                &hosts,
                &devices,
                partition,
                &path,
                &update,
                0,
                self.config.container_update_timeout,
            )
        } else {
            false
        };
        if !all_ok {
            // enqueue via async_pending against the object's own device;
            // storage policy 0 is the expirer account's policy.
            self.write_async_pending(
                "PUT",
                drive,
                task_account,
                &task_container,
                &task_obj,
                &update,
                0,
            );
        }
    }

    /// Write an async_pending pickle for a container update that could not be
    /// applied synchronously, byte-compatible with Python `pickle_async_update`
    /// and with what `updater::AsyncUpdate::parse` consumes:
    /// `{'op','account','container','obj','headers'}` at
    /// `<device>/async_pending[-<policy>]/<suffix>/<ohash>-<timestamp>`.
    ///
    /// Durability mirrors `diskfile.pickle_async_update` (diskfile.py
    /// 1468-1492) + `swift.common.utils.pickle.write_pickle`: the pickle is
    /// staged in the DEVICE tmp dir (the same tmp dir diskfile `create` uses,
    /// never inside the scanned async dir), fsynced before the rename, and the
    /// rename fsyncs the destination's parent dir. Failures are never silent:
    /// a dropped async_pending permanently desyncs the container listing.
    #[allow(clippy::too_many_arguments)]
    fn write_async_pending(
        &self,
        op: &str,
        drive: &str,
        account: &str,
        container: &str,
        obj: &str,
        update: &HeaderKeyDict,
        policy_index: u32,
    ) {
        use swift_core::pickle::{dumps, Value};
        let ohash = match self
            .config
            .hash_config
            .hash_path(account, Some(container), Some(obj))
        {
            Ok(ohash) => ohash,
            Err(e) => {
                eprintln!(
                    "ERROR async_pending: hash_path failed for /{account}/{container}/{obj}: {e}"
                );
                return;
            }
        };
        // Python normalizes the filename timestamp: Timestamp(timestamp).internal
        let timestamp = match update
            .get("x-timestamp")
            .unwrap_or("0")
            .parse::<Timestamp>()
        {
            Ok(t) => t.internal(),
            Err(_) => {
                eprintln!(
                    "ERROR async_pending: bad x-timestamp {:?}, dropping update for \
                     /{account}/{container}/{obj}",
                    update.get("x-timestamp")
                );
                return;
            }
        };
        let mut headers: Vec<(Value, Value)> = update
            .iter()
            .map(|(k, v)| (Value::Str(k.to_string()), Value::Str(v.to_string())))
            .collect();
        headers.push((
            Value::Str("X-Backend-Storage-Policy-Index".into()),
            Value::Str(policy_index.to_string()),
        ));
        let data = Value::Dict(vec![
            (Value::Str("op".into()), Value::Str(op.to_string())),
            (
                Value::Str("account".into()),
                Value::Str(account.to_string()),
            ),
            (
                Value::Str("container".into()),
                Value::Str(container.to_string()),
            ),
            (Value::Str("obj".into()), Value::Str(obj.to_string())),
            (Value::Str("headers".into()), Value::Dict(headers)),
        ]);
        let bytes = match dumps(&data) {
            Ok(bytes) => bytes,
            Err(e) => {
                eprintln!(
                    "ERROR async_pending: pickle failed for /{account}/{container}/{obj}: {e}"
                );
                return;
            }
        };
        let device_path = self.config.devices.join(drive);
        let async_dir = device_path.join(swift_diskfile::get_async_dir(policy_index));
        let tmp_dir = device_path.join(swift_diskfile::get_tmp_dir(policy_index));
        let suffix = &ohash[ohash.len().saturating_sub(3)..];
        let dest = async_dir.join(suffix).join(format!("{ohash}-{timestamp}"));
        // write_pickle stages in tmp_dir, fsyncs the file, then renames into
        // place (creating the suffix dir and fsyncing it).
        if let Err(e) = swift_diskfile::write_pickle(&bytes, &dest, &tmp_dir) {
            eprintln!(
                "ERROR async_pending: write failed for {}: {e}",
                dest.display()
            );
        }
    }
}

/// Parse `X-Backend-Container-Path` as `account/container` or `/account/container`.
fn parse_backend_container_path(raw: Option<&str>) -> Option<(&str, &str)> {
    let s = raw?.trim().trim_start_matches('/');
    if s.is_empty() {
        return None;
    }
    let (a, c) = s.split_once('/')?;
    if a.is_empty() || c.is_empty() {
        return None;
    }
    Some((a, c))
}

/// Fire one container-server update over a fresh TCP connection, honouring
/// `timeout` for connect + read (Python `container_update_timeout`).
#[allow(clippy::too_many_arguments)]
fn sync_container_http(
    op: &str,
    host: &str,
    device: &str,
    partition: &str,
    path: &str,
    update: &HeaderKeyDict,
    policy_index: u32,
    timeout: std::time::Duration,
) -> bool {
    let Ok(addr) = host.parse::<std::net::SocketAddr>() else {
        return false;
    };
    let mut request = format!(
        "{op} /{device}/{partition}{path} HTTP/1.1\r\nHost: {host}\r\n\
         X-Backend-Storage-Policy-Index: {policy_index}\r\n"
    );
    for (k, v) in update.iter() {
        request.push_str(&format!("{k}: {v}\r\n"));
    }
    request.push_str("Content-Length: 0\r\nConnection: close\r\n\r\n");
    match std::net::TcpStream::connect_timeout(&addr, timeout) {
        Ok(mut conn) => {
            conn.set_nodelay(true).ok();
            let _ = conn.set_read_timeout(Some(timeout));
            let _ = conn.set_write_timeout(Some(timeout));
            let mut buf = Vec::new();
            conn.write_all(request.as_bytes()).is_ok()
                && conn.read_to_end(&mut buf).is_ok()
                && response_is_success(&buf)
        }
        Err(_) => false,
    }
}

/// Contact every container replica in parallel. Returns true only when every
/// replica accepts the update inside `timeout`.
#[allow(clippy::too_many_arguments)]
fn fanout_container_http(
    op: &str,
    hosts: &[&str],
    devices: &[&str],
    partition: &str,
    path: &str,
    update: &HeaderKeyDict,
    policy_index: u32,
    timeout: std::time::Duration,
) -> bool {
    if hosts.is_empty() || hosts.len() != devices.len() {
        return false;
    }
    // Owned copies so worker threads do not borrow the request-scoped strs
    // across a join that outlives the loop body.
    let jobs: Vec<(String, String)> = hosts
        .iter()
        .zip(devices.iter())
        .map(|(h, d)| ((*h).to_string(), (*d).to_string()))
        .collect();
    let op = op.to_string();
    let partition = partition.to_string();
    let path = path.to_string();
    // HeaderKeyDict is not Sync-cloned cheaply; rebuild the wire headers once
    // and share the rendered pairs.
    let header_pairs: Vec<(String, String)> = update
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(jobs.len());
        for (host, device) in &jobs {
            let op = op.as_str();
            let partition = partition.as_str();
            let path = path.as_str();
            let header_pairs = &header_pairs;
            handles.push(scope.spawn(move || {
                let mut hdrs = HeaderKeyDict::new();
                for (k, v) in header_pairs {
                    hdrs.set(k, v);
                }
                sync_container_http(
                    op,
                    host,
                    device,
                    partition,
                    path,
                    &hdrs,
                    policy_index,
                    timeout,
                )
            }));
        }
        handles.into_iter().all(|h| h.join().unwrap_or(false))
    })
}

/// Whether a raw HTTP response's status line is 2xx.
fn response_is_success(buf: &[u8]) -> bool {
    String::from_utf8_lossy(buf)
        .split("\r\n")
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .map(|s| (200..300).contains(&s))
        .unwrap_or(false)
}

pub(crate) fn percent_encode(s: &str) -> String {
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

/// Python object-server defaults `replication_failure_threshold` /
/// `replication_failure_ratio`: hang up the updates phase early once failures
/// pass the threshold and the failure:success ratio.
const REPLICATION_FAILURE_THRESHOLD: usize = 100;
const REPLICATION_FAILURE_RATIO: f64 = 1.0;

/// One HTTP chunk (`<len hex>\r\n<payload>\r\n`), flushed — the receiver
/// declares `Transfer-Encoding: chunked` and eventlet frames every yield as
/// its own chunk. An empty payload writes the `0\r\n\r\n` terminator.
fn write_chunk(wire: &mut dyn Write, payload: &[u8]) -> std::io::Result<()> {
    write!(wire, "{:x}\r\n", payload.len())?;
    wire.write_all(payload)?;
    wire.write_all(b"\r\n")?;
    wire.flush()
}

/// Close enough to Python `repr()` of an ASCII str for the ssync `:ERROR:`
/// lines: single-quoted, backslash escapes for the quote, backslash and
/// control bytes.
fn python_repr(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('\'');
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32))
            }
            c => out.push(c),
        }
    }
    out.push('\'');
    out
}

/// `ssync_receiver.encode_wanted`: compare the remote offer against the
/// local diskfile state and produce the `<hash> <parts>` wanted line
/// (`parts` from 'd'/'m', sorted), or `None` when in sync.
fn encode_wanted(remote: &MissingOffer, local: &LocalSsyncTimestamps) -> Option<String> {
    let mut want_data = false;
    let mut want_meta = false;
    match local.data {
        Some(local_data) => {
            // we have something, let's get just the right stuff
            if remote.ts_data > local_data {
                want_data = true;
            }
            if local
                .meta
                .is_some_and(|local_meta| remote.ts_meta > local_meta)
            {
                want_meta = true;
            }
            if local.ctype.is_some_and(|local_ctype| {
                remote.ts_ctype > local_ctype && remote.ts_ctype > remote.ts_data
            }) {
                want_meta = true;
            }
        }
        None => {
            // we got nothing, so we'll take whatever the remote has
            want_data = true;
            want_meta = true;
        }
    }
    let parts = match (want_data, want_meta) {
        (true, true) => "dm",
        (true, false) => "d",
        (false, true) => "m",
        (false, false) => return None,
    };
    Some(format!("{} {parts}", remote.object_hash))
}

/// One hijacked SSYNC exchange (`ssync_receiver.Receiver.__call__` after
/// `initialize_request`): all validation already passed, the response head is
/// on the wire, and this drives the chunked body in both directions.
struct SsyncSession<'a> {
    server: &'a ObjectServer,
    device: String,
    /// Partition path segment (already validated as an integer).
    partition: String,
    policy_index: u32,
    policy: PolicyKind,
    frag_index: Option<i64>,
}

impl SsyncSession<'_> {
    fn run(&self, reader: &mut dyn Read, wire: &mut dyn Write) -> std::io::Result<()> {
        // Python's first yield: a bare b'\r\n' to kick wsgi into sending the
        // response head before the exchange starts.
        write_chunk(wire, b"\r\n")?;
        let mut parser = SsyncParser::new();
        let mut wanted: Vec<String> = Vec::new();
        let mut buf = vec![0u8; STREAM_CHUNK];
        // ---- missing check: read offers, compare against local state ----
        let mut missing_done = false;
        while !missing_done {
            let n = match reader.read(&mut buf) {
                // The client hung up mid-request: drop the connection without
                // an in-band error, like Python's SsyncClientDisconnected /
                // ChunkReadError paths.
                Ok(0) | Err(_) => return Ok(()),
                Ok(n) => n,
            };
            let events = match parser.push(&buf[..n]) {
                Ok(events) => events,
                Err(error) => return self.in_band_error(wire, 0, error.message()),
            };
            for event in events {
                match event {
                    SsyncEvent::Missing(offer) => {
                        if let Some(line) = self.check_missing(&offer) {
                            wanted.push(line);
                        }
                    }
                    SsyncEvent::MissingEnd => missing_done = true,
                    // The parser pauses at MissingEnd until start_updates().
                    _ => unreachable!("update event before start_updates"),
                }
            }
            if let Some(error) = parser.failure() {
                let message = error.message().to_string();
                return self.in_band_error(wire, 0, &message);
            }
        }
        // The exact frames Python yields from missing_check().
        write_chunk(wire, b":MISSING_CHECK: START\r\n")?;
        if !wanted.is_empty() {
            write_chunk(wire, wanted.join("\r\n").as_bytes())?;
        }
        write_chunk(wire, b"\r\n")?;
        write_chunk(wire, b":MISSING_CHECK: END\r\n")?;
        // ---- updates: apply each subrequest as it arrives ----
        let mut successes = 0usize;
        let mut failures = 0usize;
        let mut updates_done = false;
        let mut events = match parser.start_updates() {
            Ok(events) => events,
            Err(error) => return self.in_band_error(wire, 0, error.message()),
        };
        loop {
            for event in events {
                match event {
                    SsyncEvent::Update(update) => {
                        let response = self.server.apply_ssync_update(
                            &self.device,
                            &self.partition,
                            self.policy_index,
                            self.frag_index,
                            update,
                        );
                        if (200..300).contains(&response.status) || response.status == 404 {
                            successes += 1;
                        } else {
                            failures += 1;
                        }
                        if failures >= REPLICATION_FAILURE_THRESHOLD
                            && (successes == 0
                                || failures as f64 / successes as f64 > REPLICATION_FAILURE_RATIO)
                        {
                            return self.in_band_error(
                                wire,
                                0,
                                &format!("Too many {failures} failures to {successes} successes"),
                            );
                        }
                    }
                    SsyncEvent::UpdatesEnd => updates_done = true,
                    _ => unreachable!("missing event after start_updates"),
                }
            }
            if let Some(error) = parser.failure() {
                // Subrequests parsed before the bad line were already applied
                // (Python routes each as it arrives); now convey the error.
                let message = error.message().to_string();
                return self.in_band_error(wire, 0, &message);
            }
            if updates_done {
                break;
            }
            let n = match reader.read(&mut buf) {
                Ok(0) | Err(_) => return Ok(()),
                Ok(n) => n,
            };
            events = match parser.push(&buf[..n]) {
                Ok(events) => events,
                Err(error) => return self.in_band_error(wire, 0, error.message()),
            };
        }
        if failures != 0 {
            // Python raises HTTPInternalServerError; __call__ formats the
            // response's *byte* body with %r, hence the b'...' repr.
            let body =
                format!("ERROR: With :UPDATES: {failures} failures to {successes} successes");
            write_chunk(
                wire,
                format!(":ERROR: 500 b{}\n", python_repr(&body)).as_bytes(),
            )?;
            write_chunk(wire, b"")?;
            return Ok(());
        }
        write_chunk(wire, b":UPDATES: START\r\n")?;
        write_chunk(wire, b":UPDATES: END\r\n")?;
        write_chunk(wire, b"")?;
        // Read out what remains of the request body (normally just the
        // sender's terminal chunk, sent after it reads the frames above), so
        // closing does not RST the final frames off the sender's socket.
        let mut drained = 0usize;
        while let Ok(n) = reader.read(&mut buf) {
            if n == 0 {
                break;
            }
            drained += n;
            if drained > 64 * 1024 {
                break;
            }
        }
        Ok(())
    }

    /// `Receiver._check_missing`: decode was done by the parser; compare and
    /// encode the wanted line.
    fn check_missing(&self, remote: &MissingOffer) -> Option<String> {
        let local = self.check_local(remote, true);
        encode_wanted(remote, &local)
    }

    /// `Receiver._check_local`: local diskfile state for one offer, with the
    /// EC non-durable fix-ups (commit a local non-durable frag the remote has
    /// durably, or mask an offer we already hold non-durably).
    fn check_local(&self, remote: &MissingOffer, make_durable: bool) -> LocalSsyncTimestamps {
        let device_path = self.server.config.devices.join(&self.device);
        let partition: u64 = self.partition.parse().unwrap_or(0);
        let hash_dir = device_path.join(storage_directory(
            Path::new(&get_data_dir(self.policy_index)),
            partition,
            &remote.object_hash,
        ));
        let mut diskfile = DiskFile::from_hash_dir(
            &device_path,
            &hash_dir,
            self.policy,
            self.policy_index,
            &self.server.config.hash_config,
            self.server.config.diskfile.clone(),
        )
        .with_frag_index(self.frag_index)
        .with_open_expired(true);
        let mut result = match diskfile.open(None) {
            Ok(opened) => LocalSsyncTimestamps {
                data: opened.data_timestamp().ok(),
                meta: opened.timestamp().ok(),
                ctype: opened.content_type_timestamp().ok(),
            },
            Err(DiskFileError::Deleted { timestamp, .. }) => LocalSsyncTimestamps {
                data: Some(timestamp),
                ..LocalSsyncTimestamps::default()
            },
            // e.g. a non-durable EC frag; Python treats any other diskfile
            // error as an absent local object.
            Err(_) => LocalSsyncTimestamps::default(),
        };
        // The EC durable fix-up. Python evaluates this via df.fragments /
        // df.durable_timestamp, which survive an open() exception; Rust's
        // DiskFile drops its state on failure, so recompute the on-disk info
        // directly. Replication diskfiles have no fragment sets (df.fragments
        // is None in Python), so this is EC-only either way.
        let Some(frag_index) = self.frag_index else {
            return result;
        };
        if !matches!(self.policy, PolicyKind::Ec { .. }) {
            return result;
        }
        let files: Vec<String> = match std::fs::read_dir(&hash_dir) {
            Ok(entries) => entries
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect(),
            Err(_) => return result,
        };
        let Ok(ondisk) = swift_diskfile::get_ondisk_files(
            &files,
            &hash_dir,
            true,
            self.policy,
            Some(frag_index),
            None,
        ) else {
            return result;
        };
        let durable_older = match ondisk.durable_frag_set_ts {
            None => true,
            Some(durable_ts) => durable_ts < remote.ts_data,
        };
        let have_offered_frag = ondisk.frag_sets.iter().any(|(ts, set)| {
            *ts == remote.ts_data && set.iter().any(|info| info.frag_index == Some(frag_index))
        });
        if durable_older && have_offered_frag {
            // The remote is offering a fragment that we already have but is
            // *newer* than anything *durable* that we have
            if remote.durable {
                // We have the frag, just missing durable state, so make the
                // frag durable now. Try this just once to avoid looping.
                if make_durable && self.commit_frag(&hash_dir, &remote.ts_data, frag_index) {
                    return self.check_local(remote, false);
                }
                // commit failed: fall back to wanting a full update
            } else {
                // We have the non-durable frag that is on offer, but our
                // ts_data may currently be an older durable frag; bump it so
                // the remote frag is not wanted.
                result.data = Some(remote.ts_data);
            }
        }
        result
    }

    /// `ECDiskFileWriter.commit` for a fragment that is already on disk:
    /// rename `<ts>#<fi>.data` to its durable `#d` name, fsync the hash dir,
    /// clean up obsolete files.
    fn commit_frag(&self, hash_dir: &Path, timestamp: &Timestamp, frag_index: i64) -> bool {
        let (Ok(src), Ok(dst)) = (
            make_ec_ondisk_filename(timestamp, frag_index, false),
            make_ec_ondisk_filename(timestamp, frag_index, true),
        ) else {
            return false;
        };
        if std::fs::rename(hash_dir.join(&src), hash_dir.join(&dst)).is_err() {
            return false;
        }
        if let Ok(dir) = std::fs::File::open(hash_dir) {
            let _ = dir.sync_all();
        }
        let _ = swift_diskfile::cleanup_ondisk_files(
            hash_dir,
            self.policy,
            &self.server.config.diskfile.cleanup,
        );
        true
    }

    /// Python `Receiver.__call__`'s exception-to-body translation: an
    /// `:ERROR: <status> <repr>\n` line inside the 200 body, then the chunked
    /// terminator.
    fn in_band_error(
        &self,
        wire: &mut dyn Write,
        status: u16,
        message: &str,
    ) -> std::io::Result<()> {
        write_chunk(
            wire,
            format!(":ERROR: {status} {}\n", python_repr(message)).as_bytes(),
        )?;
        write_chunk(wire, b"")
    }
}

pub fn serve(listener: std::net::TcpListener, config: ObjectServerConfig) -> std::io::Result<()> {
    let server = std::sync::Arc::new(ObjectServer::new(config));
    let handler: swift_http::Handler = std::sync::Arc::new(move |req| server.handle(req));
    swift_http::serve_forever(listener, handler)
}

/// Like [`serve`], but with a caller-built server (carrying e.g. a
/// `fallocate_reserve`) and an explicit HTTP server config (worker sizing,
/// client timeout, access log, shutdown flag).
pub fn serve_with_config(
    listener: std::net::TcpListener,
    server: ObjectServer,
    http_config: swift_http::ServerConfig,
) -> std::io::Result<()> {
    serve_with_config_multi(vec![listener], server, http_config)
}

/// Serve across multiple listen sockets (`servers_per_port` topology).
/// All listeners share one worker pool ([`swift_http::serve_forever_multi`]).
pub fn serve_with_config_multi(
    listeners: Vec<std::net::TcpListener>,
    server: ObjectServer,
    http_config: swift_http::ServerConfig,
) -> std::io::Result<()> {
    let server = std::sync::Arc::new(server);
    let handler: swift_http::Handler = std::sync::Arc::new(move |req| server.handle(req));
    swift_http::server::serve_forever_multi(listeners, handler, http_config)
}

#[cfg(test)]
mod delete_header_tests {
    use super::*;

    fn req_with(headers: &[(&str, &str)]) -> Request {
        let mut h = HeaderKeyDict::new();
        for (k, v) in headers {
            h.set(k, *v);
        }
        Request {
            method: "PUT".into(),
            path: "/sda1/0/a/c/o".into(),
            query_string: String::new(),
            headers: h,
            body: Body::empty(),
        }
    }

    #[test]
    fn test_parse_int_like() {
        assert!(parse_int_like("*").is_none());
        assert!(parse_int_like("").is_none());
        assert!(parse_int_like(" 12 ").is_some());
        assert_eq!(parse_int_like("-5"), Some(-5.0));
        // a 100-digit integer overflows i64 but is still a valid int string
        assert!(parse_int_like(&"1".repeat(100)).is_some());
    }

    #[test]
    fn test_if_none_match_has_star() {
        assert!(if_none_match_has_star("*"));
        assert!(if_none_match_has_star("\"abc\", *"));
        assert!(!if_none_match_has_star("\"abc\""));
    }

    #[test]
    fn test_check_delete_headers() {
        let now = 1_000_000.0_f64;
        // no headers -> None
        assert_eq!(check_delete_headers(&req_with(&[]), now).unwrap(), None);
        // non-integer X-Delete-At -> 400 with exact body
        let mut err = check_delete_headers(&req_with(&[("X-Delete-At", "*")]), now).unwrap_err();
        assert_eq!(err.status, 400);
        assert_eq!(
            String::from_utf8_lossy(err.body.materialize(u64::MAX).unwrap()),
            "Non-integer X-Delete-At"
        );
        // past X-Delete-At -> 400
        let mut err = check_delete_headers(&req_with(&[("X-Delete-At", "0")]), now).unwrap_err();
        assert_eq!(
            String::from_utf8_lossy(err.body.materialize(u64::MAX).unwrap()),
            "X-Delete-At in past"
        );
        // far-future X-Delete-At clamps to 9999999999
        let val = check_delete_headers(&req_with(&[("X-Delete-At", &"1".repeat(100))]), now)
            .unwrap()
            .unwrap();
        assert_eq!(val, "9999999999");
        // non-integer X-Delete-After -> 400 with exact body
        let mut err = check_delete_headers(&req_with(&[("X-Delete-After", "*")]), now).unwrap_err();
        assert_eq!(
            String::from_utf8_lossy(err.body.materialize(u64::MAX).unwrap()),
            "Non-integer X-Delete-After"
        );
        // valid X-Delete-After -> now + after
        let val = check_delete_headers(&req_with(&[("X-Delete-After", "2")]), now)
            .unwrap()
            .unwrap();
        assert_eq!(val, format!("{:010}", 1_000_002));
    }
}

#[cfg(test)]
mod fast_post_helper_tests {
    use super::*;

    #[test]
    fn test_extract_swift_bytes() {
        assert_eq!(
            extract_swift_bytes("text/plain"),
            ("text/plain".into(), None)
        );
        assert_eq!(
            extract_swift_bytes("text/plain;swift_bytes=123"),
            ("text/plain".into(), Some("123".into()))
        );
        // other params are preserved, in order, minus swift_bytes
        assert_eq!(
            extract_swift_bytes("text/plain;charset=utf-8;swift_bytes=9;a=b"),
            ("text/plain;charset=utf-8;a=b".into(), Some("9".into()))
        );
    }

    #[test]
    fn test_meta_upsert_replaces_in_place_or_appends() {
        let mut meta: Metadata = vec![
            ("X-Timestamp".into(), MetaValue::Str("1".into())),
            ("Content-Type".into(), MetaValue::Str("a/b".into())),
        ];
        meta_upsert(&mut meta, "content-type", "c/d".into());
        assert_eq!(meta.len(), 2, "existing key replaced, not duplicated");
        assert_eq!(meta_get(&meta, "Content-Type"), Some("c/d"));
        meta_upsert(&mut meta, "Content-Type-Timestamp", "2".into());
        assert_eq!(meta.len(), 3);
        assert_eq!(meta_get(&meta, "Content-Type-Timestamp"), Some("2"));
    }
}

#[cfg(test)]
mod fallocate_reserve_tests {
    use super::*;

    #[test]
    fn breach_math_matches_python_fallocate_reserve() {
        let reserve = FallocateReserve::Bytes(100);
        assert!(
            fallocate_reserve_breached(150, 50, &reserve),
            "free-after-write equal to the reserve fails (Python: free <= reserve)"
        );
        assert!(fallocate_reserve_breached(120, 50, &reserve));
        assert!(
            fallocate_reserve_breached(10, 50, &reserve),
            "write larger than free"
        );
        assert!(!fallocate_reserve_breached(151, 50, &reserve));
        assert!(
            !fallocate_reserve_breached(0, 0, &reserve),
            "zero-length writes skip the check"
        );
        assert!(!fallocate_reserve_breached(
            0,
            10,
            &FallocateReserve::Bytes(0)
        ));
        // percent mode needs the device's total capacity; not enforced yet
        assert!(!fallocate_reserve_breached(
            1,
            1,
            &FallocateReserve::Percent(99.0)
        ));
    }

    fn tiny_server(devices: &Path, reserve: FallocateReserve) -> ObjectServer {
        ObjectServer::new(ObjectServerConfig {
            devices: devices.to_path_buf(),
            mount_check: false,
            hash_config: HashPathConfig::new(Vec::new(), b"reserve-tests".to_vec()).unwrap(),
            diskfile: DiskFileConfig::default(),
            policies: std::collections::HashMap::from([(0, PolicyKind::Replication)]),
            container_update_timeout: std::time::Duration::from_secs(1),
            container_update_mode: ContainerUpdateMode::Sync,
        })
        .with_fallocate_reserve(reserve)
    }

    fn put_request(body: &[u8]) -> Request {
        let mut headers = HeaderKeyDict::new();
        headers.set("X-Timestamp", "1");
        headers.set("Content-Type", "application/octet-stream");
        headers.set("Content-Length", body.len());
        Request {
            method: "PUT".into(),
            path: "/sda1/0/AUTH_test/c/o".into(),
            query_string: String::new(),
            headers,
            body: body.to_vec().into(),
        }
    }

    #[test]
    fn put_honors_the_fallocate_reserve_against_a_temp_device() {
        let dir = std::env::temp_dir().join(format!(
            "swift-obj-reserve-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sda1")).unwrap();
        // an unsatisfiable reserve: any write leaves free <= reserve -> 507
        let full = tiny_server(&dir, FallocateReserve::Bytes(i64::MAX));
        assert_eq!(full.handle(put_request(b"body")).status, 507);
        // a tiny reserve passes and the object lands
        let ok = tiny_server(&dir, FallocateReserve::Bytes(1));
        assert_eq!(ok.handle(put_request(b"body")).status, 201);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod native_worm_gate_wiring_tests {
    use super::*;
    use crate::worm_native_gate::{
        SYS_LEGAL_HOLD, SYS_LOCK_MODE, SYS_LOCK_REVISION, SYS_RETAIN_UNTIL,
    };

    fn server(devices: &Path) -> ObjectServer {
        ObjectServer::new(ObjectServerConfig {
            devices: devices.to_path_buf(),
            mount_check: false,
            hash_config: HashPathConfig::new(Vec::new(), b"worm-gate-tests".to_vec()).unwrap(),
            diskfile: DiskFileConfig::default(),
            policies: std::collections::HashMap::from([(0, PolicyKind::Replication)]),
            container_update_timeout: std::time::Duration::from_secs(1),
            container_update_mode: ContainerUpdateMode::Sync,
        })
    }

    fn temp_devices() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "swift-obj-worm-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sda1")).unwrap();
        dir
    }

    fn put_req(ts: &str, extra: &[(&str, &str)], body: &[u8]) -> Request {
        let mut headers = HeaderKeyDict::new();
        headers.set("X-Timestamp", ts);
        headers.set("Content-Type", "application/octet-stream");
        headers.set("Content-Length", body.len());
        for (k, v) in extra {
            headers.set(k, *v);
        }
        Request {
            method: "PUT".into(),
            path: "/sda1/0/AUTH_test/c/o".into(),
            query_string: String::new(),
            headers,
            body: body.to_vec().into(),
        }
    }

    fn method_req(method: &str, ts: &str) -> Request {
        method_req_headers(method, ts, &[])
    }

    fn method_req_headers(method: &str, ts: &str, extra: &[(&str, &str)]) -> Request {
        let mut headers = HeaderKeyDict::new();
        headers.set("X-Timestamp", ts);
        for (k, v) in extra {
            headers.set(k, *v);
        }
        Request {
            method: method.into(),
            path: "/sda1/0/AUTH_test/c/o".into(),
            query_string: String::new(),
            headers,
            body: Body::empty(),
        }
    }

    #[test]
    fn unlocked_put_and_missing_headers_allow() {
        let dir = temp_devices();
        let srv = server(&dir);
        assert_eq!(srv.handle(put_req("1", &[], b"a")).status, 201);
        assert_eq!(srv.handle(put_req("2", &[], b"b")).status, 201);
        assert_eq!(srv.handle(method_req("DELETE", "3")).status, 204);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn legal_hold_and_compliance_deny_existing_mutations() {
        let dir = temp_devices();
        let srv = server(&dir);
        assert_eq!(
            srv.handle(put_req("1", &[(SYS_LEGAL_HOLD, "ON")], b"held"))
                .status,
            201
        );
        let mut overwrite = srv.handle(put_req("2", &[], b"nope"));
        assert_eq!(overwrite.status, 403);
        assert_eq!(
            String::from_utf8_lossy(overwrite.body.materialize(u64::MAX).unwrap()),
            "object is locked"
        );
        assert_eq!(srv.handle(method_req("POST", "3")).status, 403);
        assert_eq!(srv.handle(method_req("DELETE", "4")).status, 403);
        assert_eq!(srv.handle(method_req("GET", "5")).status, 200);

        let dir2 = temp_devices();
        let srv2 = server(&dir2);
        assert_eq!(
            srv2.handle(put_req(
                "1",
                &[
                    (SYS_LOCK_MODE, "COMPLIANCE"),
                    (SYS_RETAIN_UNTIL, "2033-05-18T03:33:20Z"),
                ],
                b"locked"
            ))
            .status,
            201
        );
        assert_eq!(srv2.handle(method_req("DELETE", "2")).status, 403);
        let mut repl = put_req("3", &[], b"replica");
        repl.headers.set("X-Backend-Replication", "True");
        assert_eq!(srv2.handle(repl).status, 201);
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&dir2);
    }

    #[test]
    fn lock_sysmeta_post_allowed_overwrite_put_still_403() {
        let dir = temp_devices();
        let srv = server(&dir);
        assert_eq!(srv.handle(put_req("1", &[], b"plain")).status, 201);
        let lock_post = method_req_headers(
            "POST",
            "2",
            &[
                (SYS_LEGAL_HOLD, "ON"),
                (SYS_LOCK_MODE, "COMPLIANCE"),
                (SYS_RETAIN_UNTIL, "2033-05-18T03:33:20Z"),
                (SYS_LOCK_REVISION, "1"),
            ],
        );
        assert_eq!(srv.handle(lock_post).status, 202);
        assert_eq!(srv.handle(put_req("3", &[], b"nope")).status, 403);
        assert_eq!(srv.handle(method_req("POST", "4")).status, 403);
        assert_eq!(
            srv.handle(method_req_headers(
                "POST",
                "5",
                &[(SYS_LEGAL_HOLD, "ON"), ("X-Object-Meta-Color", "blue")]
            ))
            .status,
            403
        );
        let mut repl = put_req("6", &[], b"replica");
        repl.headers.set("X-Backend-Replication", "True");
        assert_eq!(srv.handle(repl).status, 201);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn put_if_match_mismatch_412_match_allows() {
        let dir = temp_devices();
        let srv = server(&dir);
        let mut missing = put_req("1", &[], b"abc");
        missing.headers.set("If-Match", "\"deadbeef\"");
        assert_eq!(srv.handle(missing).status, 412);

        let created = srv.handle(put_req("1", &[], b"abc"));
        assert_eq!(created.status, 201);
        let etag = created
            .headers
            .get("ETag")
            .expect("PUT 201 carries ETag")
            .to_string();

        let mut star = put_req("2", &[], b"star");
        star.headers.set("If-None-Match", "*");
        assert_eq!(srv.handle(star).status, 412);

        let mut mismatch = put_req("2", &[], b"nope");
        mismatch.headers.set("If-Match", "\"deadbeef\"");
        assert_eq!(srv.handle(mismatch).status, 412);

        let mut matched = put_req("2", &[], b"ok");
        matched.headers.set("If-Match", &etag);
        assert_eq!(srv.handle(matched).status, 201);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn expired_locked_put_overwrite_still_denied() {
        let dir = temp_devices();
        let srv = server(&dir);
        assert_eq!(
            srv.handle(put_req(
                "1",
                &[
                    (SYS_LEGAL_HOLD, "ON"),
                    ("X-Delete-At", "1"),
                    ("X-Backend-Replication", "True"),
                ],
                b"held"
            ))
            .status,
            201
        );
        assert_eq!(srv.handle(put_req("2", &[], b"nope")).status, 403);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
