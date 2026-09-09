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

//! `versioned_writes` (legacy stack + history modes), ported from
//! `swift/common/middleware/versioned_writes/legacy.py`.
//!
//! A container flagged with `X-Versions-Location` (stack) or
//! `X-History-Location` (history) keeps prior object contents in a versions
//! container. Stack mode restores the newest archive on `DELETE`; history
//! mode archives the current object and writes a delete-marker before the
//! delete proceeds.
//!
//! Archive name interoperability contract (golden-tested):
//! `"{len(object):03x}{object}/{Timestamp(ts).internal}"`.
//!
//! Container `PUT`/`POST` translates client `X-Versions-Location` /
//! `X-History-Location` into sysmeta when `allow_versioned_writes` is true.
//!
//! IsolatedIdentity (Swift 2.9 `versioned_writes.py`) skips copy-current
//! when the client PUT or the current object carries `X-Object-Manifest`
//! (`test_versioning_dlo`: empty DLO overwrite must not bump the archive
//! `object_count`). Master `legacy.py` dropped that skip; keep the 2.9
//! behavior here.
//!
//! Deferred / wontfix:
//! * `swift.authorize` write-ACL recheck before archive (no authorize hook).
//! * In-proxy reverse-listing fallback for pre-2.6.0 container servers
//!   (listing uses `reverse=on` only).

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use swift_core::config::config_true_value;
use swift_core::constraints::check_container_format;
use swift_core::timestamp::Timestamp;
use swift_http::{
    parse_query, percent_decode_bytes, split_path, AsyncRequest, Body, BodyTransform, IncomingBody,
    Request, Response, MAX_CONTROL_BODY,
};

use crate::{AsyncNextFn, Middleware, MwPrep, NextFn, StreamingAsyncNextFn};

const DELETE_MARKER_CONTENT_TYPE: &str = "application/x-deleted;swift_versions_deleted=1";
const SYSMETA_VERSIONS_LOC: &str = "X-Container-Sysmeta-Versions-Location";
const SYSMETA_VERSIONS_MODE: &str = "X-Container-Sysmeta-Versions-Mode";
const CLIENT_VERSIONS_ENABLED: &str = "X-Versions-Enabled";
const SYSMETA_OBJECT_VERSIONS_ENABLED: &str = "X-Container-Sysmeta-Versions-Enabled";
const SYSMETA_OBJECT_VERSIONS_CONTAINER: &str = "X-Container-Sysmeta-Versions-Container";
const SYSMETA_OBJECT_VERSIONS_SYMLINK: &str = "X-Object-Sysmeta-Versions-Symlink";
const SYSMETA_SYMLINK_TARGET: &str = "X-Object-Sysmeta-Symlink-Target";
const SYSMETA_SYMLINK_TARGET_ETAG: &str = "X-Object-Sysmeta-Symlink-Target-Etag";
const SYSMETA_SYMLINK_TARGET_BYTES: &str = "X-Object-Sysmeta-Symlink-Target-Bytes";
const SYSMETA_SYMLOOP_EXTEND: &str = "X-Object-Sysmeta-Symloop-Extend";
const SYSMETA_ALLOW_RESERVED_NAMES: &str = "X-Object-Sysmeta-Allow-Reserved-Names";
const SYSMETA_CONTAINER_UPDATE_OVERRIDE_ETAG: &str =
    "X-Object-Sysmeta-Container-Update-Override-Etag";
const MD5_OF_EMPTY_STRING: &str = "d41d8cd98f00b204e9800998ecf8427e";

/// Trusted, internal authorization probe understood by the terminal proxy.
///
/// Gatekeeper must strip this header from client requests. The terminal app
/// authorizes then returns without backend I/O (normally 204).
pub const AUTHORIZE_ONLY_HEADER: &str = "X-Backend-Versioned-Writes-Authorize-Only";

/// Trusted marker for the container-info HEADs issued by this middleware.
///
/// Modern object versioning needs owner-only container metadata such as
/// `X-Container-Sync-To` to enforce its mutual-exclusion rules.  The public
/// request cannot supply this header because gatekeeper strips every
/// `X-Backend-*` header before `versioned_writes` runs.
pub const OWNER_INFO_HEADER: &str = "X-Backend-Versioned-Writes-Owner-Info";

/// The `versioned_writes` middleware.
pub struct VersionedWrites {
    /// When set (true/false), this middleware owns enablement. When `None`,
    /// object versioning still runs if the container already has a location
    /// (legacy container-server `allow_versions` compatibility).
    pub allow_versioned_writes: Option<bool>,
    /// Modern Swift object versioning (`X-Versions-Enabled`). Kept separate
    /// from legacy stack/history versioning, matching Python's two config
    /// switches.
    pub allow_object_versioning: bool,
    /// Whether the terminal proxy implements [`AUTHORIZE_ONLY_HEADER`].
    /// False is the only safe default.
    authorization_probe_supported: bool,
}

impl Default for VersionedWrites {
    fn default() -> Self {
        VersionedWrites {
            allow_versioned_writes: Some(true),
            allow_object_versioning: false,
            authorization_probe_supported: false,
        }
    }
}

impl VersionedWrites {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_conf(allow: Option<&str>) -> Self {
        VersionedWrites {
            allow_versioned_writes: allow.map(config_true_value),
            allow_object_versioning: false,
            authorization_probe_supported: false,
        }
    }

    pub fn with_object_versioning(mut self, enabled: bool) -> Self {
        self.allow_object_versioning = enabled;
        self
    }

    pub fn with_authorization_probe(mut self, supported: bool) -> Self {
        self.authorization_probe_supported = supported;
        self
    }
}

fn modern_versions_container(container: &str) -> String {
    // `Request.path` and `Request::param` are already percent-decoded.
    // Decoding a second time would corrupt a legitimate literal `%00` in a
    // user container name and select the wrong ring partition.
    format!("\0versions\0{container}")
}

fn split_modern_versions_container(name: &str) -> Option<String> {
    name.strip_prefix("\0versions\0").map(str::to_string)
}

fn modern_bad_request(body: &str) -> Response {
    let mut resp = Response::with_body(400, body.as_bytes().to_vec());
    resp.headers.set("Content-Type", "text/plain");
    resp
}

fn modern_enabled(headers: &swift_http::HeaderKeyDict) -> bool {
    headers
        .get(SYSMETA_OBJECT_VERSIONS_ENABLED)
        .is_some_and(config_true_value)
}

fn modern_versions_object_name(object: &str, version: Timestamp) -> Option<String> {
    if object.contains('\0') {
        return None;
    }
    Some(format!(
        "\0{object}\0{}",
        version.normalized().invert().internal()
    ))
}

fn split_modern_versions_object_name(name: &str) -> Option<(String, Timestamp)> {
    let rest = name.strip_prefix('\0')?;
    let (object, inverse) = rest.split_once('\0')?;
    let version = inverse.parse::<Timestamp>().ok()?.invert().normalized();
    Some((object.to_string(), version))
}

/// Python `split_reserved_name(name)[0]`. Versions-container delimiter
/// subdirs are `\0del-` (no second reserved char). Requiring `split_once('\0')`
/// dropped delete-marker prefixes from `?versions&delimiter=`.
fn split_reserved_name_first(name: &str) -> Option<&str> {
    let rest = name.strip_prefix('\0')?;
    rest.split('\0').next().filter(|part| !part.is_empty())
}

/// Leftover `hash` params after the etag (Python `parse_header`).
fn listing_hash_params(hash: &str) -> String {
    hash.split(';')
        .skip(1)
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("; ")
}

/// Python `ContainerContext` listing translation for a versions-symlink:
/// `bytes` from `symlink_bytes`, `hash` from `symlink_etag` plus leftover
/// params (`slo_etag`) so SLO listing rewrite can promote `slo_etag`.
fn apply_version_symlink_listing(
    map: &mut serde_json::Map<String, serde_json::Value>,
    version: &str,
    account: &str,
    container: &str,
    version_id: Timestamp,
    wants_versions: bool,
) {
    if let Some(bytes) = map.remove("symlink_bytes") {
        map.insert("bytes".to_string(), bytes);
    }
    let leftover = map
        .get("hash")
        .and_then(|value| value.as_str())
        .map(listing_hash_params)
        .unwrap_or_default();
    let slo_param = leftover.split(';').map(str::trim).find_map(|part| {
        part.strip_prefix("slo_etag=")
            .map(|value| value.to_string())
    });
    if let Some(etag) = map.remove("symlink_etag") {
        let etag = match etag {
            serde_json::Value::String(value) => value,
            other => other.to_string(),
        };
        let hash = match slo_param {
            Some(slo) => format!("{etag}; slo_etag={slo}"),
            None => etag,
        };
        map.insert("hash".to_string(), serde_json::Value::String(hash));
    }
    map.insert("version_symlink".to_string(), serde_json::Value::Bool(true));
    if !wants_versions {
        map.insert(
            "symlink_path".to_string(),
            serde_json::Value::String(format!(
                "/{version}/{account}/{container}/{}?version-id={}",
                quote_path(map.get("name").and_then(|v| v.as_str()).unwrap_or("")),
                version_id.internal()
            )),
        );
    }
}

fn query_param(query: &str, name: &str) -> Option<String> {
    parse_query(query)
        .into_iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value)
}

/// Python `handle_versioned_request` rewrites the path to the hidden archive
/// and keeps the rest of the query. `?symlink=get` must still reach symlink
/// middleware so HEAD/GET of a versioned symlink returns the link itself.
fn query_without_param(query: &str, name: &str) -> String {
    let mut parts = Vec::new();
    for (key, value) in parse_query(query) {
        if key == name {
            continue;
        }
        if value.is_empty() {
            parts.push(key);
        } else {
            parts.push(format!("{key}={value}"));
        }
    }
    parts.join("&")
}

fn modern_versions_listing_query(req: &Request) -> Result<String, Response> {
    let marker = req.param("marker");
    let version_marker = req.param("version_marker");
    if marker.is_none() && version_marker.is_some() {
        return Err(modern_bad_request("version_marker param requires marker"));
    }

    let mut query = vec!["format=json".to_string()];
    if let Some(prefix) = req.param("prefix") {
        if prefix.contains('\0') {
            return Err(modern_bad_request("invalid prefix param"));
        }
        query.push(format!("prefix={}", quote_path(&format!("\0{prefix}"))));
    }

    if let Some(marker) = marker {
        if marker.contains('\0') {
            return Err(modern_bad_request("invalid marker param"));
        }
        let marker = match version_marker.as_deref() {
            None => format!("\0{marker}\0:"),
            Some("null") => format!("\0{marker}\0"),
            Some(raw) => {
                let version = raw
                    .parse::<Timestamp>()
                    .map_err(|_| modern_bad_request("invalid version_marker param"))?;
                modern_versions_object_name(&marker, version)
                    .ok_or_else(|| modern_bad_request("invalid marker param"))?
            }
        };
        query.push(format!("marker={}", quote_path(&marker)));
    }

    if let Some(delimiter) = req.param("delimiter") {
        if delimiter
            .chars()
            .any(|ch| ch == '\0' || ch == '.' || ch.is_ascii_digit())
        {
            return Err(modern_bad_request("invalid delimiter param"));
        }
        query.push(format!("delimiter={}", quote_path(&delimiter)));
    }
    for name in ["limit", "reverse"] {
        if let Some(value) = req.param(name) {
            query.push(format!("{name}={}", quote_path(&value)));
        }
    }
    Ok(query.join("&"))
}

fn decoded_header_path(value: &str) -> String {
    String::from_utf8_lossy(&percent_decode_bytes(value.as_bytes())).into_owned()
}

/// Hidden-container listing names may quote reserved NULs as `%00` without
/// quoting other `%` bytes in the user object name (`%25ff`). Full percent-decode
/// turns `%25ff` into `%ff` and version-id DELETE 404s, leaving versions behind.
fn reserved_listing_name(raw: &str) -> String {
    if raw.contains('\0') {
        return raw.to_string();
    }
    raw.replace("%00", "\0")
}

fn validated_modern_post_target(location: &str, account: &str, hidden: &str) -> Option<String> {
    let decoded = decoded_header_path(location);
    // Pre-authorized internal requests may only target an origin-relative
    // Swift path.  Reject absolute and scheme-relative redirects before path
    // parsing so a backend 307 cannot become an internal open redirect.
    if !decoded.starts_with('/') || decoded.starts_with("//") {
        return None;
    }
    let parts = split_path(&decoded, 4, 4, true).ok()?;
    if parts[1].as_deref() != Some(account) || parts[2].as_deref() != Some(hidden) {
        return None;
    }
    Some(decoded)
}

fn empty_async_request(req: Request) -> AsyncRequest {
    AsyncRequest {
        method: req.method,
        path: req.path,
        query_string: req.query_string,
        headers: req.headers,
        body: IncomingBody::from_bytes(Vec::new(), MAX_CONTROL_BODY),
    }
}

fn buffered_to_async(req: Request) -> AsyncRequest {
    let max_body = req.body.content_length().unwrap_or(MAX_CONTROL_BODY).max(1);
    let bytes = match req.body {
        Body::Buffered(bytes) => bytes,
        _ => Vec::new(),
    };
    let max_body = max_body.max(bytes.len() as u64).max(1);
    AsyncRequest {
        method: req.method,
        path: req.path,
        query_string: req.query_string,
        headers: req.headers,
        body: IncomingBody::from_bytes(bytes, max_body),
    }
}

/// `dispatch_remaining` (COPY dest PUT) only honors `intercepts_request`,
/// not `streams_request`. Wrap the buffered inner next so the streaming
/// PUT handler can still copy-current.
fn streaming_next_from_async(next: AsyncNextFn) -> StreamingAsyncNextFn {
    Arc::new(move |mut req: AsyncRequest| {
        let next = Arc::clone(&next);
        Box::pin(async move {
            let max_body = req.body.max_body_bytes();
            let bytes = match req.body.materialize(max_body).await {
                Ok(bytes) => bytes,
                Err(_) => return Response::error(499, "Client Disconnect"),
            };
            next(Request {
                method: req.method,
                path: req.path,
                query_string: req.query_string,
                headers: req.headers,
                body: Body::Buffered(bytes),
            })
            .await
        })
    })
}

struct ByteCounterTransform {
    bytes: Arc<AtomicU64>,
}

impl BodyTransform for ByteCounterTransform {
    fn push(&mut self, input: Option<&[u8]>) -> std::io::Result<Vec<u8>> {
        let chunk = input.unwrap_or_default();
        self.bytes.fetch_add(chunk.len() as u64, Ordering::Relaxed);
        Ok(chunk.to_vec())
    }
}

fn response_body_as_incoming(body: Body, max_body: u64) -> Result<IncomingBody, Response> {
    match body {
        Body::Buffered(bytes) => Ok(IncomingBody::from_bytes(bytes, max_body)),
        Body::Channel(channel) => {
            let (rx, scope, content_length) = channel.into_rx();
            Ok(IncomingBody::from_channel(
                rx,
                content_length,
                scope,
                max_body,
            ))
        }
        Body::Streamed(_) => Err(Response::error(
            500,
            "async object copy returned a blocking response body",
        )),
    }
}

/// Archive object name for a prior version.
pub fn versions_object_name(object_name: &str, ts: &str) -> Option<String> {
    let internal = ts.parse::<Timestamp>().ok()?.internal();
    // Python `len(name.encode('utf8'))` is UTF-8 bytes, not Unicode scalars.
    let len = object_name.len();
    Some(format!("{len:03x}{object_name}/{internal}"))
}

/// Listing prefix for an object's archives.
pub fn versions_object_prefix(object_name: &str) -> String {
    let len = object_name.len();
    format!("{len:03x}{object_name}/")
}

struct VersionCfg {
    location: String,
    mode: String, // "stack" | "history"
}

/// Build an internal subrequest that carries the caller's auth and bypasses
/// TempAuth re-checks (`make_pre_authed_request` stand-in).
fn put_has_version_id(query: &str) -> bool {
    query_param(query, "version-id").is_some_and(|value| !value.is_empty())
}

/// Python `_get_source_object`: GET `?symlink=get` with X-Newest only.
/// Do not clone the incoming PUT's X-Symlink-Target / body headers onto the
/// GET — that makes symlink middleware follow the *new* target (or the
/// stored target) and archives md5(target) instead of md5('').
fn legacy_source_get(path: &str, from: &swift_http::HeaderKeyDict) -> Request {
    let mut get = Request {
        method: "GET".to_string(),
        path: path.to_string(),
        query_string: "symlink=get".to_string(),
        headers: swift_http::HeaderKeyDict::new(),
        body: Body::empty(),
    };
    for name in [
        "X-Auth-Token",
        "X-Backend-Remote-User",
        "Referer",
        "X-Trans-Id",
        "X-Timestamp",
    ] {
        if let Some(value) = from.get(name) {
            get.headers.set(name, value);
        }
    }
    get.headers.set("X-Newest", "True");
    get.headers.set("X-Backend-Authorize-Override", "true");
    get.headers.set("X-Backend-Source", "VW");
    get
}

fn pre_authed(method: &str, path: &str, from: &Request) -> Request {
    let mut sub = from.clone_head();
    sub.method = method.to_string();
    sub.path = path.to_string();
    sub.query_string = String::new();
    sub.headers.remove("Content-Length");
    sub.headers.remove("X-If-Delete-At");
    sub.headers.set("X-Backend-Authorize-Override", "true");
    sub.headers.set("X-Backend-Source", "VW");
    sub
}

/// Build the reserved versions-container PUT with the same deliberately
/// small header set as Python object_versioning.  In particular, do not copy
/// the primary container's versioning, sync, ACL, quota, or user metadata to
/// the hidden container.
fn hidden_container_put(path: &str, policy_index: Option<&str>) -> Request {
    let mut req = Request {
        method: "PUT".to_string(),
        path: path.to_string(),
        query_string: String::new(),
        headers: swift_http::HeaderKeyDict::new(),
        body: Body::empty(),
    };
    req.headers.set("X-Backend-Authorize-Override", "true");
    req.headers.set("X-Backend-Source", "VW");
    req.headers.set("X-Backend-Allow-Reserved-Names", "true");
    if let Some(policy) = policy_index.filter(|value| !value.is_empty()) {
        req.headers.set("X-Backend-Storage-Policy-Index", policy);
    }
    req.headers.set("Content-Length", "0");
    req
}

/// Official Swift 2.9 `handle_obj_versions_put`: do not version a DLO
/// manifest (`X-Object-Manifest` on the PUT or on the current object).
fn is_dlo_manifest(headers: &swift_http::HeaderKeyDict) -> bool {
    headers.contains_key("X-Object-Manifest")
}

impl VersionedWrites {
    fn is_enabled(&self, has_legacy_versions: bool) -> bool {
        match self.allow_versioned_writes {
            Some(v) => v,
            None => has_legacy_versions,
        }
    }

    fn copy_current_then_continue(
        &self,
        req: Request,
        version: &str,
        account: &str,
        object: &str,
        versions_cont: &str,
        next: &NextFn,
    ) -> Result<Request, Response> {
        if is_dlo_manifest(&req.headers) {
            return Ok(req);
        }
        let get_req = pre_authed("GET", &req.path, &req);
        let current = next(get_req);
        if current.status == 404 {
            return Ok(req);
        }
        if !(200..300).contains(&current.status) {
            return Err(current);
        }
        if is_dlo_manifest(&current.headers) {
            return Ok(req);
        }
        let ts_source = current
            .headers
            .get("X-Timestamp")
            .map(|s| s.to_string())
            .unwrap_or_else(|| "0".to_string());
        let Some(vers_name) = versions_object_name(object, &ts_source) else {
            return Ok(req);
        };
        let (current_reader, current_len) = current.body.into_reader();
        let mut archive = pre_authed(
            "PUT",
            &format!("/{version}/{account}/{versions_cont}/{vers_name}"),
            &req,
        );
        archive.body = Body::from_reader(current_reader, current_len);
        if let Some(ct) = current.headers.get("Content-Type") {
            archive.headers.set("Content-Type", ct);
        }
        if let Some(len) = current_len {
            archive.headers.set("Content-Length", len.to_string());
        }
        let archive_resp = next(archive);
        if !(200..300).contains(&archive_resp.status) {
            return Err(archive_resp);
        }
        Ok(req)
    }

    fn handle_put(
        &self,
        req: Request,
        version: &str,
        account: &str,
        object: &str,
        versions_cont: &str,
        next: &NextFn,
    ) -> Response {
        match self.copy_current_then_continue(req, version, account, object, versions_cont, next) {
            Ok(req) => next(req),
            Err(resp) => resp,
        }
    }

    fn handle_delete_history(
        &self,
        req: Request,
        version: &str,
        account: &str,
        object: &str,
        versions_cont: &str,
        next: &NextFn,
    ) -> Response {
        let req = match self.copy_current_then_continue(
            req,
            version,
            account,
            object,
            versions_cont,
            next,
        ) {
            Ok(r) => r,
            Err(resp) => return resp,
        };
        let marker_name = versions_object_name(object, &Timestamp::now().internal())
            .unwrap_or_else(|| format!("{}marker", versions_object_prefix(object)));
        let mut marker = pre_authed(
            "PUT",
            &format!("/{version}/{account}/{versions_cont}/{marker_name}"),
            &req,
        );
        marker
            .headers
            .set("Content-Type", DELETE_MARKER_CONTENT_TYPE);
        marker.headers.set("Content-Length", "0");
        let marker_resp = next(marker);
        if !(200..300).contains(&marker_resp.status) {
            return marker_resp;
        }
        next(req)
    }

    fn handle_delete_stack(
        &self,
        mut req: Request,
        version: &str,
        account: &str,
        container: &str,
        object: &str,
        versions_cont: &str,
        next: &NextFn,
    ) -> Response {
        let prefix = versions_object_prefix(object);
        let mut list_req = pre_authed(
            "GET",
            &format!("/{version}/{account}/{versions_cont}"),
            &req,
        );
        list_req.query_string = format!("prefix={}&reverse=on&format=json", quote_path(&prefix));
        let mut list_resp = next(list_req);
        if list_resp.status == 404 {
            return next(req);
        }
        if !(200..300).contains(&list_resp.status) {
            return list_resp;
        }
        let listing = match list_resp.body.materialize(MAX_CONTROL_BODY) {
            Ok(b) => b.to_vec(),
            Err(_) => return Response::error(500, "Internal Error"),
        };
        let items = parse_listing_json(&listing);
        if items.is_empty() {
            return next(req);
        }

        // Walk newest-first (reverse=on). Skip missing archives.
        let mut idx = 0;
        while idx < items.len() {
            let item = &items[idx];
            idx += 1;
            if item.content_type == DELETE_MARKER_CONTENT_TYPE {
                // If current object exists, just delete it (restore to marker).
                let mut head = pre_authed("HEAD", &req.path, &req);
                head.headers.set("X-Newest", "True");
                let hresp = next(head);
                if hresp.status != 404 {
                    if !(200..300).contains(&hresp.status) {
                        return hresp;
                    }
                    break;
                }
                // No current data — find next non-marker to restore.
                let mut restored_path: Option<String> = None;
                while idx < items.len() {
                    let restore = &items[idx];
                    idx += 1;
                    if restore.content_type == DELETE_MARKER_CONTENT_TYPE {
                        break;
                    }
                    if let Some(path) = self.restore_data(
                        &req,
                        version,
                        account,
                        container,
                        object,
                        versions_cont,
                        &restore.name,
                        next,
                    ) {
                        // Delete the archive we restored from.
                        let del = pre_authed("DELETE", &path, &req);
                        let del_resp = next(del);
                        if del_resp.status != 404 && !(200..300).contains(&del_resp.status) {
                            return del_resp;
                        }
                        restored_path = Some(path);
                        break;
                    }
                }
                let _ = restored_path;
                // Redirect original DELETE to the delete-marker archive.
                req = pre_authed(
                    "DELETE",
                    &format!("/{version}/{account}/{versions_cont}/{}", item.name),
                    &req,
                );
                break;
            } else {
                // Restore previous version into place, then DELETE the archive.
                if let Some(restored_path) = self.restore_data(
                    &req,
                    version,
                    account,
                    container,
                    object,
                    versions_cont,
                    &item.name,
                    next,
                ) {
                    req = pre_authed("DELETE", &restored_path, &req);
                    break;
                }
                // Archive vanished — try next.
                continue;
            }
        }
        req.headers.remove("X-If-Delete-At");
        next(req)
    }

    fn restore_data(
        &self,
        auth_from: &Request,
        version: &str,
        account: &str,
        container: &str,
        object: &str,
        versions_cont: &str,
        prev_obj_name: &str,
        next: &NextFn,
    ) -> Option<String> {
        let get_path = format!("/{version}/{account}/{versions_cont}/{prev_obj_name}");
        let get_req = pre_authed("GET", &get_path, auth_from);
        let get_resp = next(get_req);
        if get_resp.status == 404 {
            return None;
        }
        if !(200..300).contains(&get_resp.status) {
            return None;
        }
        let (reader, len) = get_resp.body.into_reader();
        let mut put = pre_authed(
            "PUT",
            &format!("/{version}/{account}/{container}/{object}"),
            auth_from,
        );
        put.body = Body::from_reader(reader, len);
        if let Some(ct) = get_resp.headers.get("Content-Type") {
            put.headers.set("Content-Type", ct);
        }
        if let Some(l) = len {
            put.headers.set("Content-Length", l.to_string());
        }
        let put_resp = next(put);
        if !(200..300).contains(&put_resp.status) {
            return None;
        }
        Some(get_path)
    }

    fn expose_object_versioning_on_response(&self, mut resp: Response) -> Response {
        if let Some(enabled) = resp
            .headers
            .get(SYSMETA_OBJECT_VERSIONS_ENABLED)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
        {
            resp.headers.set(CLIENT_VERSIONS_ENABLED, enabled);
        }
        resp
    }

    fn prepare_object_versioning_container(
        &self,
        req: &mut Request,
        cinfo: &Response,
        version: &str,
        account: &str,
        container: &str,
        next: &NextFn,
    ) -> Result<(), Response> {
        let requested = req
            .headers
            .get(CLIENT_VERSIONS_ENABLED)
            .map(config_true_value);
        let enabling = requested == Some(true);
        if enabling
            && cinfo
                .headers
                .get("X-Container-Sync-To")
                .is_some_and(|value| !value.is_empty())
        {
            return Err(modern_bad_request(
                "Cannot enable object versioning on a container configured as source of container syncing.",
            ));
        }

        if requested.is_none() {
            return Ok(());
        }
        if !self.allow_object_versioning {
            return Err(Response::error(412, "Object versioning is disabled"));
        }

        req.headers.remove(CLIENT_VERSIONS_ENABLED);
        req.headers.set(
            SYSMETA_OBJECT_VERSIONS_ENABLED,
            if enabling { "True" } else { "False" },
        );
        if !enabling {
            return Ok(());
        }

        if cinfo
            .headers
            .get(SYSMETA_VERSIONS_LOC)
            .is_some_and(|value| !value.is_empty())
            || cinfo
                .headers
                .get("X-Versions-Location")
                .is_some_and(|value| !value.is_empty())
        {
            return Err(modern_bad_request(
                "Cannot enable object versioning on a container that is already using the legacy versioned writes feature.",
            ));
        }

        // Python Swift always derives the hidden container from the primary
        // container name when enabling versioning.  Reusing the already
        // quoted sysmeta value here would quote `%00` a second time on a
        // re-enable and persist `%2500versions%2500...`.
        let hidden = modern_versions_container(container);
        let hidden_path = format!("/{version}/{account}/{hidden}");
        let policy_index = cinfo
            .headers
            .get("X-Backend-Storage-Policy-Index")
            .filter(|value| !value.is_empty());
        let create = hidden_container_put(&hidden_path, policy_index);
        let created = next(create);
        if !(200..300).contains(&created.status) && created.status != 409 {
            return Err(Response::error(500, "Error enabling object versioning"));
        }
        req.headers
            .set(SYSMETA_OBJECT_VERSIONS_CONTAINER, quote_path(&hidden));
        Ok(())
    }

    async fn prepare_object_versioning_container_async(
        &self,
        req: &mut Request,
        source_sync_configured: bool,
        _configured: Option<String>,
        legacy_configured: bool,
        policy_index: Option<String>,
        version: &str,
        account: &str,
        container: &str,
        next: AsyncNextFn,
    ) -> Result<(), Response> {
        let requested = req
            .headers
            .get(CLIENT_VERSIONS_ENABLED)
            .map(config_true_value);
        let enabling = requested == Some(true);
        if enabling && source_sync_configured {
            return Err(modern_bad_request(
                "Cannot enable object versioning on a container configured as source of container syncing.",
            ));
        }
        if requested.is_none() {
            return Ok(());
        }
        if !self.allow_object_versioning {
            return Err(Response::error(412, "Object versioning is disabled"));
        }

        req.headers.remove(CLIENT_VERSIONS_ENABLED);
        req.headers.set(
            SYSMETA_OBJECT_VERSIONS_ENABLED,
            if enabling { "True" } else { "False" },
        );
        if !enabling {
            return Ok(());
        }
        if legacy_configured {
            return Err(modern_bad_request(
                "Cannot enable object versioning on a container that is already using the legacy versioned writes feature.",
            ));
        }

        // See the synchronous path above: the configured value came from a
        // response header and is percent-quoted.  Enabling is deterministic,
        // so rebuild the reserved name from the primary container instead of
        // double-quoting old sysmeta on re-enable.
        let hidden = modern_versions_container(container);
        let hidden_path = format!("/{version}/{account}/{hidden}");
        let create = hidden_container_put(&hidden_path, policy_index.as_deref());
        let created = next(create).await;
        if !(200..300).contains(&created.status) && created.status != 409 {
            return Err(Response::error(500, "Error enabling object versioning"));
        }
        req.headers
            .set(SYSMETA_OBJECT_VERSIONS_CONTAINER, quote_path(&hidden));
        Ok(())
    }

    fn handle_object_versioning_container(&self, mut req: Request, next: &NextFn) -> Response {
        let parts = match split_path(&req.path, 3, 3, true) {
            Ok(parts) => parts,
            Err(_) => return next(req),
        };
        let version = parts[0].clone().unwrap_or_default();
        let account = parts[1].clone().unwrap_or_default();
        let container = parts[2].clone().unwrap_or_default();
        let mut head = pre_authed("HEAD", &req.path, &req);
        head.headers.remove(CLIENT_VERSIONS_ENABLED);
        head.headers.set(OWNER_INFO_HEADER, "true");
        let cinfo = next(head);
        if let Err(resp) = self.prepare_object_versioning_container(
            &mut req, &cinfo, &version, &account, &container, next,
        ) {
            return resp;
        }
        self.expose_object_versioning_on_response(next(req))
    }

    async fn handle_object_versioning_container_async(
        &self,
        mut req: Request,
        next: AsyncNextFn,
    ) -> Response {
        let parts = match split_path(&req.path, 3, 3, true) {
            Ok(parts) => parts,
            Err(_) => return next(req).await,
        };
        let version = parts[0].clone().unwrap_or_default();
        let account = parts[1].clone().unwrap_or_default();
        let container = parts[2].clone().unwrap_or_default();
        let mut head = pre_authed("HEAD", &req.path, &req);
        head.headers.remove(CLIENT_VERSIONS_ENABLED);
        head.headers.set(OWNER_INFO_HEADER, "true");
        let cinfo = next(head).await;
        let source_sync_configured = cinfo
            .headers
            .get("X-Container-Sync-To")
            .is_some_and(|value| !value.is_empty());
        let configured = cinfo
            .headers
            .get(SYSMETA_OBJECT_VERSIONS_CONTAINER)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        let legacy_configured = cinfo
            .headers
            .get(SYSMETA_VERSIONS_LOC)
            .is_some_and(|value| !value.is_empty())
            || cinfo
                .headers
                .get("X-Versions-Location")
                .is_some_and(|value| !value.is_empty());
        let policy_index = cinfo
            .headers
            .get("X-Backend-Storage-Policy-Index")
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        if let Err(resp) = self
            .prepare_object_versioning_container_async(
                &mut req,
                source_sync_configured,
                configured.clone(),
                legacy_configured,
                policy_index,
                &version,
                &account,
                &container,
                next.clone(),
            )
            .await
        {
            return resp;
        }
        // Python ContainerContext.handle_delete: HEAD hidden, 409 if it still
        // has versions, else DELETE hidden, then DELETE the user container.
        if req.method == "DELETE" {
            if let Err(resp) = self
                .delete_hidden_versions_container_if_empty_async(
                    req.headers.clone(),
                    &version,
                    &account,
                    &container,
                    configured.as_deref(),
                    next.clone(),
                )
                .await
            {
                return resp;
            }
        }
        self.expose_object_versioning_on_response(next(req).await)
    }

    /// Python: delete the reserved versions container only after it is empty.
    async fn delete_hidden_versions_container_if_empty_async(
        &self,
        headers: swift_http::HeaderKeyDict,
        version: &str,
        account: &str,
        container: &str,
        configured: Option<&str>,
        next: AsyncNextFn,
    ) -> Result<(), Response> {
        if configured.is_none() {
            return Ok(());
        }
        let hidden = modern_versions_container(container);
        let hidden_path = format!("/{version}/{account}/{hidden}");
        let head = Self::modern_internal_request("HEAD", hidden_path.clone(), "", &headers);
        let vresp = next(head).await;
        if (200..300).contains(&vresp.status) {
            let count = vresp
                .headers
                .get("X-Container-Object-Count")
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(0);
            if count > 0 {
                let mut resp =
                    Response::error(409, "Delete all versions before deleting container.");
                resp.headers.set("Content-Type", "text/plain");
                return Err(resp);
            }
            let del = Self::modern_internal_request("DELETE", hidden_path, "", &headers);
            let dresp = next(del).await;
            if dresp.status == 409 {
                let mut resp =
                    Response::error(409, "Delete all versions before deleting container.");
                resp.headers.set("Content-Type", "text/plain");
                return Err(resp);
            }
            if !(200..300).contains(&dresp.status) && dresp.status != 404 {
                return Err(Response::error(500, "Error deleting versioned container"));
            }
        } else if vresp.status != 404 {
            return Err(Response::error(500, "Error deleting versioned container"));
        }
        Ok(())
    }

    fn modern_internal_request(
        method: &str,
        path: String,
        query_string: &str,
        source_headers: &swift_http::HeaderKeyDict,
    ) -> Request {
        let mut req = Request {
            method: method.to_string(),
            path,
            query_string: query_string.to_string(),
            headers: source_headers.clone(),
            body: Body::empty(),
        };
        req.headers.remove("Content-Length");
        req.headers.remove("Transfer-Encoding");
        req.headers.set("X-Backend-Authorize-Override", "true");
        req.headers.set("X-Backend-Source", "OV");
        if req.path.contains('\0') {
            // All raw-NUL paths produced by object versioning are internal
            // reserved containers/objects. Keep this invariant in the
            // constructor so version-id GET/HEAD/DELETE cannot accidentally
            // omit the terminal controller's reserved-name capability.
            req.headers.set("X-Backend-Allow-Reserved-Names", "true");
        }
        req
    }

    fn modern_authorization_probe(req: &AsyncRequest) -> Request {
        let mut authorize = Request {
            method: req.method.clone(),
            path: req.path.clone(),
            query_string: req.query_string.clone(),
            headers: req.headers.clone(),
            body: Body::empty(),
        };
        authorize.headers.remove("Content-Length");
        authorize.headers.remove("Transfer-Encoding");
        authorize.headers.set(AUTHORIZE_ONLY_HEADER, "true");
        authorize
    }

    async fn copy_current_modern_version(
        &self,
        version: &str,
        account: &str,
        hidden: &str,
        object: &str,
        original_path: &str,
        source_headers: &swift_http::HeaderKeyDict,
        next: &StreamingAsyncNextFn,
    ) -> Result<(), Response> {
        let mut get = Self::modern_internal_request(
            "GET",
            original_path.to_string(),
            "symlink=get",
            source_headers,
        );
        get.headers.set("X-Newest", "True");
        let current = next(empty_async_request(get)).await;
        if current.status == 404 {
            return Ok(());
        }
        if !(200..300).contains(&current.status) {
            return Err(current);
        }
        if current
            .headers
            .get(SYSMETA_OBJECT_VERSIONS_SYMLINK)
            .is_some_and(config_true_value)
        {
            return Ok(());
        }

        let source_timestamp = current
            .headers
            .get("X-Backend-Timestamp")
            .or_else(|| current.headers.get("X-Timestamp"))
            .and_then(|value| value.parse::<Timestamp>().ok())
            .unwrap_or_else(Timestamp::now)
            .normalized();
        let Some(archive_name) = modern_versions_object_name(object, source_timestamp) else {
            return Err(Response::error(400, "Invalid object name"));
        };
        let archive_path = format!("/{version}/{account}/{hidden}/{archive_name}");
        let content_length = current
            .headers
            .get("Content-Length")
            .and_then(|value| value.parse::<u64>().ok())
            .or_else(|| current.body.content_length());
        let max_body = content_length.unwrap_or(u64::MAX);
        let body = response_body_as_incoming(current.body, max_body)?;
        let mut archive_headers = current.headers;
        archive_headers.remove("X-Timestamp");
        archive_headers.remove("X-Backend-Timestamp");
        archive_headers.remove("Transfer-Encoding");
        archive_headers.set("X-Backend-Authorize-Override", "true");
        archive_headers.set("X-Backend-Source", "OV");
        archive_headers.set("X-Backend-Allow-Reserved-Names", "true");
        if let Some(length) = content_length {
            archive_headers.set("Content-Length", length.to_string());
        }
        let copied = next(AsyncRequest {
            method: "PUT".to_string(),
            path: archive_path,
            query_string: String::new(),
            headers: archive_headers,
            body,
        })
        .await;
        if copied.status == 404 {
            return Err(Response::error(
                500,
                "The versions container does not exist. You may want to re-enable object versioning.",
            ));
        }
        if !(200..300).contains(&copied.status) {
            return Err(copied);
        }
        Ok(())
    }

    /// Legacy `X-Versions-Location` / `X-History-Location` copy-current.
    ///
    /// Python `_copy_current` skips the archive PUT when GET current is 404
    /// (first write). Modern `X-Versions-Enabled` still archives the first
    /// PUT into the hidden `%00versions%00` container; this helper must not
    /// be used for that path.
    async fn copy_current_legacy_streaming(
        &self,
        version: &str,
        account: &str,
        object: &str,
        versions_cont: &str,
        original_path: &str,
        source_headers: &swift_http::HeaderKeyDict,
        next: &StreamingAsyncNextFn,
    ) -> Result<(), Response> {
        if is_dlo_manifest(source_headers) {
            return Ok(());
        }
        let get = legacy_source_get(original_path, source_headers);
        let current = next(empty_async_request(get)).await;
        if current.status == 404 {
            return Ok(());
        }
        if !(200..300).contains(&current.status) {
            return Err(current);
        }
        if is_dlo_manifest(&current.headers) {
            return Ok(());
        }
        let ts_source = current
            .headers
            .get("X-Timestamp")
            .or_else(|| current.headers.get("X-Backend-Timestamp"))
            .map(|s| s.to_string())
            .unwrap_or_else(|| "0".to_string());
        let Some(vers_name) = versions_object_name(object, &ts_source) else {
            return Ok(());
        };
        let content_length = current
            .headers
            .get("Content-Length")
            .and_then(|value| value.parse::<u64>().ok())
            .or_else(|| current.body.content_length());
        let max_body = content_length.unwrap_or(u64::MAX);
        let body = response_body_as_incoming(current.body, max_body)?;
        let mut archive_headers = current.headers;
        archive_headers.remove("X-Timestamp");
        archive_headers.remove("X-Backend-Timestamp");
        archive_headers.remove("Transfer-Encoding");
        archive_headers.set("X-Backend-Authorize-Override", "true");
        archive_headers.set("X-Backend-Source", "VW");
        if let Some(length) = content_length {
            archive_headers.set("Content-Length", length.to_string());
        }
        // Object ETag must be md5 of the archived bytes. A followed GET
        // would copy the target ETag; drop it so the object server hashes
        // the (symlink) body.
        archive_headers.remove("ETag");
        let copied = next(AsyncRequest {
            method: "PUT".to_string(),
            path: format!("/{version}/{account}/{versions_cont}/{vers_name}"),
            query_string: String::new(),
            headers: archive_headers,
            body,
        })
        .await;
        if !(200..300).contains(&copied.status) {
            return Err(copied);
        }
        Ok(())
    }

    async fn restore_data_streaming(
        &self,
        version: &str,
        account: &str,
        container: &str,
        object: &str,
        versions_cont: &str,
        prev_obj_name: &str,
        source_headers: &swift_http::HeaderKeyDict,
        next: &StreamingAsyncNextFn,
    ) -> Option<String> {
        let get_path = format!("/{version}/{account}/{versions_cont}/{prev_obj_name}");
        let get = legacy_source_get(&get_path, source_headers);
        let current = next(empty_async_request(get)).await;
        if current.status == 404 {
            return None;
        }
        if !(200..300).contains(&current.status) {
            return None;
        }
        let content_length = current
            .headers
            .get("Content-Length")
            .and_then(|value| value.parse::<u64>().ok())
            .or_else(|| current.body.content_length());
        let max_body = content_length.unwrap_or(u64::MAX);
        let body = response_body_as_incoming(current.body, max_body).ok()?;
        let mut put_headers = current.headers;
        put_headers.remove("X-Timestamp");
        put_headers.remove("X-Backend-Timestamp");
        put_headers.remove("Transfer-Encoding");
        put_headers.set("X-Backend-Authorize-Override", "true");
        put_headers.set("X-Backend-Source", "VW");
        if let Some(length) = content_length {
            put_headers.set("Content-Length", length.to_string());
        }
        let put_path = format!("/{version}/{account}/{container}/{object}");
        let copied = next(AsyncRequest {
            method: "PUT".to_string(),
            path: put_path,
            query_string: String::new(),
            headers: put_headers,
            body,
        })
        .await;
        if !(200..300).contains(&copied.status) {
            return None;
        }
        Some(get_path)
    }

    async fn handle_delete_stack_streaming(
        &self,
        mut req: AsyncRequest,
        version: &str,
        account: &str,
        container: &str,
        object: &str,
        versions_cont: &str,
        next: StreamingAsyncNextFn,
    ) -> Response {
        let prefix = versions_object_prefix(object);
        let list_query = format!("prefix={}&reverse=on&format=json", quote_path(&prefix));
        let mut list = Self::modern_internal_request(
            "GET",
            format!("/{version}/{account}/{versions_cont}"),
            &list_query,
            &req.headers,
        );
        list.headers.set("X-Backend-Source", "VW");
        let mut list_resp = next(empty_async_request(list)).await;
        if list_resp.status == 404 {
            return next(req).await;
        }
        if !(200..300).contains(&list_resp.status) {
            return list_resp;
        }
        let listing = match std::mem::replace(&mut list_resp.body, Body::empty())
            .collect_async()
            .await
        {
            Ok(bytes) => bytes,
            Err(_) => return Response::error(500, "Internal Error"),
        };
        let items = parse_listing_json(&listing);
        if items.is_empty() {
            return next(req).await;
        }

        let mut idx = 0;
        while idx < items.len() {
            let item_name = items[idx].name.clone();
            let item_ct = items[idx].content_type.clone();
            idx += 1;
            if item_ct == DELETE_MARKER_CONTENT_TYPE {
                let mut head =
                    Self::modern_internal_request("HEAD", req.path.clone(), "", &req.headers);
                head.headers.set("X-Newest", "True");
                head.headers.set("X-Backend-Source", "VW");
                let hresp = next(empty_async_request(head)).await;
                if hresp.status != 404 {
                    if !(200..300).contains(&hresp.status) {
                        return hresp;
                    }
                    break;
                }
                while idx < items.len() {
                    let restore_name = items[idx].name.clone();
                    let restore_ct = items[idx].content_type.clone();
                    idx += 1;
                    if restore_ct == DELETE_MARKER_CONTENT_TYPE {
                        break;
                    }
                    if let Some(path) = self
                        .restore_data_streaming(
                            version,
                            account,
                            container,
                            object,
                            versions_cont,
                            &restore_name,
                            &req.headers,
                            &next,
                        )
                        .await
                    {
                        let del = Self::modern_internal_request("DELETE", path, "", &req.headers);
                        let del_resp = next(empty_async_request(del)).await;
                        if del_resp.status != 404 && !(200..300).contains(&del_resp.status) {
                            return del_resp;
                        }
                        break;
                    }
                }
                req.method = "DELETE".to_string();
                req.path = format!("/{version}/{account}/{versions_cont}/{item_name}");
                req.query_string.clear();
                req.headers.remove("X-If-Delete-At");
                req.headers.set("X-Backend-Authorize-Override", "true");
                req.headers.set("X-Backend-Source", "VW");
                return next(req).await;
            } else if let Some(restored_path) = self
                .restore_data_streaming(
                    version,
                    account,
                    container,
                    object,
                    versions_cont,
                    &item_name,
                    &req.headers,
                    &next,
                )
                .await
            {
                req.method = "DELETE".to_string();
                req.path = restored_path;
                req.query_string.clear();
                req.headers.remove("X-If-Delete-At");
                req.headers.set("X-Backend-Authorize-Override", "true");
                req.headers.set("X-Backend-Source", "VW");
                return next(req).await;
            }
        }
        req.headers.remove("X-If-Delete-At");
        next(req).await
    }

    async fn handle_delete_history_streaming(
        &self,
        mut req: AsyncRequest,
        version: &str,
        account: &str,
        object: &str,
        versions_cont: &str,
        next: StreamingAsyncNextFn,
    ) -> Response {
        if let Err(resp) = self
            .copy_current_legacy_streaming(
                version,
                account,
                object,
                versions_cont,
                &req.path,
                &req.headers,
                &next,
            )
            .await
        {
            return resp;
        }
        let marker_name = versions_object_name(object, &Timestamp::now().internal())
            .unwrap_or_else(|| format!("{}marker", versions_object_prefix(object)));
        let mut marker = Self::modern_internal_request(
            "PUT",
            format!("/{version}/{account}/{versions_cont}/{marker_name}"),
            "",
            &req.headers,
        );
        marker.headers.set("X-Backend-Source", "VW");
        marker
            .headers
            .set("Content-Type", DELETE_MARKER_CONTENT_TYPE);
        marker.headers.set("Content-Length", "0");
        let marker_resp = next(empty_async_request(marker)).await;
        if !(200..300).contains(&marker_resp.status) {
            return marker_resp;
        }
        req.headers.remove("X-If-Delete-At");
        req.headers.set("X-Backend-Authorize-Override", "true");
        next(req).await
    }

    async fn handle_modern_put_streaming(
        &self,
        req: AsyncRequest,
        next: StreamingAsyncNextFn,
    ) -> Response {
        let parts = match split_path(&req.path, 4, 4, true) {
            Ok(parts) => parts,
            Err(_) => return next(req).await,
        };
        let version = parts[0].clone().unwrap_or_default();
        let account = parts[1].clone().unwrap_or_default();
        let container = parts[2].clone().unwrap_or_default();
        let object = parts[3].clone().unwrap_or_default();
        if version.is_empty() || account.is_empty() || container.is_empty() || object.is_empty() {
            return next(req).await;
        }

        let container_path = format!("/{version}/{account}/{container}");
        let mut info = Self::modern_internal_request("HEAD", container_path, "", &req.headers);
        info.headers.set(OWNER_INFO_HEADER, "true");
        let cinfo = next(empty_async_request(info)).await;
        let configured = cinfo
            .headers
            .get(SYSMETA_OBJECT_VERSIONS_CONTAINER)
            .filter(|value| !value.is_empty())
            .map(decoded_header_path);
        if !modern_enabled(&cinfo.headers) || configured.is_none() {
            // Hyper never calls sync `handle_put`. Legacy stack/history
            // copy-current has to run here. First PUT: GET current 404
            // → pass through, do not archive.
            if let Some(cfg) = self.read_version_cfg(&cinfo) {
                if let Err(resp) = self
                    .copy_current_legacy_streaming(
                        &version,
                        &account,
                        &object,
                        &cfg.location,
                        &req.path,
                        &req.headers,
                        &next,
                    )
                    .await
                {
                    return resp;
                }
            }
            return next(req).await;
        }
        let hidden = configured.unwrap();

        // The public object path has not reached the terminal controller yet.
        // Authorize it before moving the unread client body into an internal
        // reserved-name request.
        let authorized = next(empty_async_request(Self::modern_authorization_probe(&req))).await;
        if !(200..300).contains(&authorized.status) {
            return authorized;
        }

        // Fail before reading client data if the hidden container has gone
        // missing. This leaves the current/null version untouched.
        let hidden_path = format!("/{version}/{account}/{hidden}");
        let mut hidden_head = Self::modern_internal_request("HEAD", hidden_path, "", &req.headers);
        hidden_head
            .headers
            .set("X-Backend-Allow-Reserved-Names", "true");
        let hidden_info = next(empty_async_request(hidden_head)).await;
        if hidden_info.status == 404 {
            return Response::error(
                500,
                "The versions container does not exist. You may want to re-enable object versioning.",
            );
        }
        if !(200..300).contains(&hidden_info.status) {
            return hidden_info;
        }

        if let Err(resp) = self
            .copy_current_modern_version(
                &version,
                &account,
                &hidden,
                &object,
                &req.path,
                &req.headers,
                &next,
            )
            .await
        {
            return resp;
        }

        let put_timestamp = req
            .headers
            .get("X-Timestamp")
            .or_else(|| req.headers.get("X-Backend-Inbound-X-Timestamp"))
            .and_then(|value| value.parse::<Timestamp>().ok())
            .unwrap_or_else(Timestamp::now);
        let version_id = put_timestamp.normalized();
        let Some(archive_name) = modern_versions_object_name(&object, version_id) else {
            return Response::error(400, "Invalid object name");
        };
        let archive_path = format!("/{version}/{account}/{hidden}/{archive_name}");
        let declared_length = req.body.content_length().or_else(|| {
            req.headers
                .get("Content-Length")
                .and_then(|value| value.parse::<u64>().ok())
        });
        let counter = Arc::new(AtomicU64::new(0));
        let max_body = req.body.max_body_bytes();
        let client_body = req.body.with_transform(
            Box::new(ByteCounterTransform {
                bytes: Arc::clone(&counter),
            }),
            declared_length,
        );
        let mut archive_headers = req.headers.clone();
        archive_headers.remove("X-Delete-At");
        archive_headers.remove("X-Delete-After");
        archive_headers.set("X-Timestamp", put_timestamp.internal());
        archive_headers.set("X-Backend-Authorize-Override", "true");
        archive_headers.set("X-Backend-Allow-Reserved-Names", "true");
        // Do not set X-Backend-Symlink-Override on the *archive* PUT.
        // Python lets symlink inherit target Content-Type onto the archived
        // user-staticlink; versions listing reads that type. Override remains
        // on the versions-symlink marker PUT below (COPY dest 412).
        if let Some(length) = declared_length {
            archive_headers.set("Content-Length", length.to_string());
            archive_headers.remove("Transfer-Encoding");
        }
        let archived = next(AsyncRequest {
            method: "PUT".to_string(),
            path: archive_path,
            query_string: String::new(),
            headers: archive_headers,
            body: client_body,
        })
        .await;
        if archived.status == 404 {
            return Response::error(
                500,
                "The versions container does not exist. You may want to re-enable object versioning.",
            );
        }
        if !(200..300).contains(&archived.status) {
            return archived;
        }
        let target_etag = archived
            .headers
            .get("ETag")
            .map(|value| value.trim_matches('"').to_string())
            .unwrap_or_default();
        // Python `_put_symlink_to_version`: marker TGT_BYTES is slo_size when
        // the archived object is an SLO, not the manifest JSON length. Listing
        // then uses symlink_bytes; SLO promotes slo_etag from hash params.
        let slo_size = req
            .headers
            .get("X-Object-Sysmeta-Slo-Size")
            .and_then(|value| value.parse::<u64>().ok());
        let slo_etag = req
            .headers
            .get("X-Object-Sysmeta-Slo-Etag")
            .map(|value| value.trim_matches('"').to_string())
            .filter(|value| !value.is_empty());
        let target_bytes = slo_size
            .unwrap_or_else(|| declared_length.unwrap_or_else(|| counter.load(Ordering::Relaxed)));
        // Listing slo_etag is leftover hash params on the marker
        // (apply_version_symlink_listing), not TGT_ETAG. Stuffing slo_etag
        // into TGT_ETAG 409s symlink follow (archive ETag is manifest md5).
        //
        // Nested static user-symlink GET: hop 2 `found_etag` is the archived
        // object's TGT_ETAG sysmeta (client X-Symlink-Target-Etag), not the
        // zero-byte archive ETag. Marker TGT_ETAG must match that or symlink
        // middleware 409s "X-Symlink-Target-Etag headers do not match".
        // Marker PUT still sets X-Backend-Symlink-Override so COPY dest does
        // not HEAD-validate the hidden archive against this etag (412).
        let follow_etag = req
            .headers
            .get("X-Symlink-Target-Etag")
            .or_else(|| req.headers.get(SYSMETA_SYMLINK_TARGET_ETAG))
            .or_else(|| archived.headers.get(SYSMETA_SYMLINK_TARGET_ETAG))
            .or_else(|| archived.headers.get("X-Symlink-Target-Etag"))
            .map(|value| value.trim_matches('"').to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| target_etag.clone());
        let listing_etag = follow_etag.clone();
        // Python symlink `_validate_etag_and_update_sysmeta` copies the
        // target Content-Type when the client omitted it. VW runs *before*
        // symlink and archives with X-Backend-Symlink-Override, so inherit
        // here from a HEAD of X-Symlink-Target (test_versioned_staticlink).
        let mut content_type = req
            .headers
            .get("Content-Type")
            .filter(|value| !value.is_empty())
            .or_else(|| {
                archived.headers.get("Content-Type").filter(|value| {
                    !value.is_empty() && !value.to_ascii_lowercase().starts_with("text/html")
                })
            })
            .unwrap_or("")
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_string();
        if content_type.is_empty() {
            if let Some(tgt) = req.headers.get("X-Symlink-Target") {
                let decoded = decoded_header_path(tgt);
                let head_path = if decoded.starts_with('/') {
                    format!("/{version}/{account}{decoded}")
                } else {
                    format!("/{version}/{account}/{decoded}")
                };
                let head = Self::modern_internal_request("HEAD", head_path, "", &req.headers);
                let href = next(empty_async_request(head)).await;
                if (200..300).contains(&href.status) {
                    if let Some(ct) = href.headers.get("Content-Type") {
                        content_type = ct.split(';').next().unwrap_or(ct).trim().to_string();
                    }
                }
            }
        }
        if content_type.is_empty() {
            content_type = "application/octet-stream".to_string();
        }

        let mut marker_timestamp = put_timestamp;
        if marker_timestamp.increment_offset(1).is_err() {
            return Response::error(500, "Object version timestamp overflow");
        }
        let quoted_target = format!("{}/{}", quote_path(&hidden), quote_path(&archive_name));
        let mut marker_headers = req.headers;
        for name in [
            "ETag",
            "Transfer-Encoding",
            "X-If-Delete-At",
            "X-Object-Manifest",
            "X-Static-Large-Object",
            "X-Object-Sysmeta-Slo-Etag",
            "X-Object-Sysmeta-Slo-Size",
        ] {
            marker_headers.remove(name);
        }
        // Python `_put_symlink_to_version` overwrites X-Symlink-Target with the
        // hidden archive path and pops X-Symlink-Target-Account. Do not pop
        // client X-Symlink-Target-Etag (static user-symlinks still HEAD-validate).
        marker_headers.remove("X-Symlink-Target-Account");
        marker_headers.set("X-Symlink-Target", &quoted_target);
        marker_headers.set("X-Symlink-Target-Etag", &follow_etag);
        marker_headers.set("Content-Length", "0");
        marker_headers.set("Content-Type", content_type);
        marker_headers.set("X-Timestamp", marker_timestamp.internal());
        marker_headers.set("X-Backend-Authorize-Override", "true");
        marker_headers.set("X-Backend-Source", "OV");
        marker_headers.set("X-Backend-Allow-Reserved-Names", "true");
        marker_headers.set("X-Backend-Symlink-Override", "true");
        marker_headers.set(SYSMETA_SYMLINK_TARGET, &quoted_target);
        marker_headers.set(SYSMETA_SYMLINK_TARGET_ETAG, &listing_etag);
        marker_headers.set(SYSMETA_SYMLINK_TARGET_BYTES, target_bytes.to_string());
        marker_headers.set(SYSMETA_OBJECT_VERSIONS_SYMLINK, "true");
        marker_headers.set(SYSMETA_SYMLOOP_EXTEND, "true");
        marker_headers.set(SYSMETA_ALLOW_RESERVED_NAMES, "true");
        let mut override_etag = format!(
            "{MD5_OF_EMPTY_STRING}; symlink_target={quoted_target}; symlink_target_etag={listing_etag}; symlink_target_bytes={target_bytes}"
        );
        if let Some(slo) = slo_etag.as_deref() {
            override_etag.push_str(&format!("; slo_etag={slo}"));
        }
        marker_headers.set(SYSMETA_CONTAINER_UPDATE_OVERRIDE_ETAG, override_etag);
        let mut marker = next(AsyncRequest {
            method: "PUT".to_string(),
            path: req.path,
            query_string: String::new(),
            headers: marker_headers,
            body: IncomingBody::from_bytes(Vec::new(), max_body),
        })
        .await;
        if (200..300).contains(&marker.status) {
            marker.headers.set("ETag", target_etag);
            marker
                .headers
                .set("X-Object-Version-Id", version_id.internal());
        }
        marker
    }

    /// Python `ObjectContext.handle_put_version`: zero-byte PUT ?version-id=
    /// HEADs the hidden archive and repoints the public versions-symlink.
    /// Does not copy-current and does not write a new hidden object.
    async fn handle_put_version_streaming(
        &self,
        mut req: AsyncRequest,
        next: StreamingAsyncNextFn,
        version: &str,
        account: &str,
        hidden: &str,
        archive_name: &str,
        archive_path: String,
        requested: Timestamp,
    ) -> Response {
        let max_body = req.body.max_body_bytes();
        let declared = req.body.content_length().or_else(|| {
            req.headers
                .get("Content-Length")
                .and_then(|value| value.parse::<u64>().ok())
        });
        let has_body = match declared {
            Some(0) => false,
            Some(_) => true,
            None => match req.body.materialize(max_body).await {
                Ok(bytes) => !bytes.is_empty(),
                Err(_) => true,
            },
        };
        if has_body {
            return modern_bad_request("PUT version-id requests require a zero byte body");
        }

        let mut archive_head =
            Self::modern_internal_request("HEAD", archive_path, "symlink=get", &req.headers);
        archive_head
            .headers
            .set("X-Backend-Allow-Reserved-Names", "true");
        let head_resp = next(empty_async_request(archive_head)).await;
        if head_resp.status == 404 {
            let hidden_path = format!("/{version}/{account}/{hidden}");
            let mut hidden_head =
                Self::modern_internal_request("HEAD", hidden_path, "", &req.headers);
            hidden_head
                .headers
                .set("X-Backend-Allow-Reserved-Names", "true");
            let hidden_info = next(empty_async_request(hidden_head)).await;
            if (200..300).contains(&hidden_info.status) {
                return Response::error(404, "The specified version does not exist");
            }
            return Response::error(
                500,
                "The versions container does not exist. You may want to re-enable object versioning.",
            );
        }
        if !(200..300).contains(&head_resp.status) {
            return head_resp;
        }

        let target_etag = head_resp
            .headers
            .get("ETag")
            .map(|value| value.trim_matches('"').to_string())
            .unwrap_or_default();
        let target_bytes = head_resp
            .headers
            .get("Content-Length")
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);
        let content_type = head_resp
            .headers
            .get("Content-Type")
            .unwrap_or("application/octet-stream")
            .split(';')
            .next()
            .unwrap_or("application/octet-stream")
            .trim()
            .to_string();

        let mut marker_timestamp = req
            .headers
            .get("X-Timestamp")
            .or_else(|| req.headers.get("X-Backend-Inbound-X-Timestamp"))
            .and_then(|value| value.parse::<Timestamp>().ok())
            .unwrap_or_else(Timestamp::now);
        if marker_timestamp.increment_offset(1).is_err() {
            return Response::error(500, "Object version timestamp overflow");
        }
        let quoted_target = format!("{}/{}", quote_path(hidden), quote_path(archive_name));
        let mut marker_headers = req.headers;
        for name in [
            "ETag",
            "Transfer-Encoding",
            "X-If-Delete-At",
            "X-Object-Manifest",
            "X-Static-Large-Object",
            "X-Object-Sysmeta-Slo-Etag",
            "X-Object-Sysmeta-Slo-Size",
        ] {
            marker_headers.remove(name);
        }
        // Same 5e2d84a marker contract as ordinary versioned PUT.
        marker_headers.remove("X-Symlink-Target-Account");
        marker_headers.set("X-Symlink-Target", &quoted_target);
        marker_headers.set("Content-Length", "0");
        marker_headers.set("Content-Type", content_type);
        marker_headers.set("X-Timestamp", marker_timestamp.internal());
        marker_headers.set("X-Backend-Authorize-Override", "true");
        marker_headers.set("X-Backend-Source", "OV");
        marker_headers.set("X-Backend-Allow-Reserved-Names", "true");
        marker_headers.set("X-Backend-Symlink-Override", "true");
        marker_headers.set(SYSMETA_SYMLINK_TARGET, &quoted_target);
        marker_headers.set(SYSMETA_SYMLINK_TARGET_ETAG, &target_etag);
        marker_headers.set(SYSMETA_SYMLINK_TARGET_BYTES, target_bytes.to_string());
        marker_headers.set(SYSMETA_OBJECT_VERSIONS_SYMLINK, "true");
        marker_headers.set(SYSMETA_SYMLOOP_EXTEND, "true");
        marker_headers.set(SYSMETA_ALLOW_RESERVED_NAMES, "true");
        marker_headers.set(
            SYSMETA_CONTAINER_UPDATE_OVERRIDE_ETAG,
            format!(
                "{MD5_OF_EMPTY_STRING}; symlink_target={quoted_target}; symlink_target_etag={target_etag}; symlink_target_bytes={target_bytes}"
            ),
        );
        req.query_string.clear();
        let mut marker = next(AsyncRequest {
            method: "PUT".to_string(),
            path: req.path,
            query_string: String::new(),
            headers: marker_headers,
            body: IncomingBody::from_bytes(Vec::new(), max_body),
        })
        .await;
        if (200..300).contains(&marker.status) {
            marker.headers.set("ETag", target_etag);
            marker
                .headers
                .set("X-Object-Version-Id", requested.internal());
        }
        marker
    }

    async fn handle_modern_object_streaming(
        &self,
        mut req: AsyncRequest,
        next: StreamingAsyncNextFn,
    ) -> Response {
        let parts = match split_path(&req.path, 4, 4, true) {
            Ok(parts) => parts,
            Err(_) => return next(req).await,
        };
        let version = parts[0].clone().unwrap_or_default();
        let account = parts[1].clone().unwrap_or_default();
        let container = parts[2].clone().unwrap_or_default();
        let object = parts[3].clone().unwrap_or_default();
        if version.is_empty() || account.is_empty() || container.is_empty() || object.is_empty() {
            return next(req).await;
        }

        let authorized = next(empty_async_request(Self::modern_authorization_probe(&req))).await;
        if !(200..300).contains(&authorized.status) {
            return authorized;
        }

        let container_path = format!("/{version}/{account}/{container}");
        let mut info = Self::modern_internal_request("HEAD", container_path, "", &req.headers);
        info.headers.set(OWNER_INFO_HEADER, "true");
        let cinfo = next(empty_async_request(info)).await;
        let configured = cinfo
            .headers
            .get(SYSMETA_OBJECT_VERSIONS_CONTAINER)
            .filter(|value| !value.is_empty())
            .map(decoded_header_path);
        let is_enabled = modern_enabled(&cinfo.headers);
        let requested_version =
            query_param(&req.query_string, "version-id").filter(|value| !value.is_empty());

        if let Some(requested) = requested_version {
            if req.method == "POST" {
                return modern_bad_request("POST to a specific version is not allowed");
            }
            if requested == "null" {
                let modern_null = is_enabled && configured.is_some();
                if !modern_null {
                    // Legacy X-Versions-Location: version-id=null is the current
                    // object. DELETE restores the previous archive (stack) or
                    // writes a history marker — not a bare current DELETE.
                    if req.method == "DELETE" {
                        if let Some(cfg) = self.read_version_cfg(&cinfo) {
                            if cfg.mode == "history" {
                                return self
                                    .handle_delete_history_streaming(
                                        req,
                                        &version,
                                        &account,
                                        &object,
                                        &cfg.location,
                                        next,
                                    )
                                    .await;
                            }
                            return self
                                .handle_delete_stack_streaming(
                                    req,
                                    &version,
                                    &account,
                                    &container,
                                    &object,
                                    &cfg.location,
                                    next,
                                )
                                .await;
                        }
                    }
                }
                match req.method.as_str() {
                    "GET" | "HEAD" => {
                        let mut source = Self::modern_internal_request(
                            &req.method,
                            req.path.clone(),
                            "symlink=get",
                            &req.headers,
                        );
                        source.headers.set("X-Newest", "True");
                        let mut resp = next(empty_async_request(source)).await;
                        if (200..300).contains(&resp.status)
                            && resp
                                .headers
                                .get(SYSMETA_OBJECT_VERSIONS_SYMLINK)
                                .is_some_and(config_true_value)
                        {
                            return Response::new(404);
                        }
                        if (200..300).contains(&resp.status) {
                            resp.headers.set("X-Object-Version-Id", "null");
                        }
                        return resp;
                    }
                    "DELETE" => {
                        let delete =
                            Self::modern_internal_request("DELETE", req.path, "", &req.headers);
                        let mut resp = next(empty_async_request(delete)).await;
                        if (200..300).contains(&resp.status) || resp.status == 404 {
                            resp.headers.set("X-Object-Version-Id", "null");
                            resp.headers.set("X-Object-Current-Version-Id", "null");
                        }
                        return resp;
                    }
                    "PUT" => {
                        return modern_bad_request(
                            "PUT version-id requests cannot target the null version",
                        );
                    }
                    _ => return next(req).await,
                }
            }

            let parsed = match requested.parse::<Timestamp>() {
                Ok(timestamp) => timestamp.normalized(),
                Err(_) => return modern_bad_request("Invalid version parameter"),
            };
            let Some(hidden) = configured else {
                return modern_bad_request(
                    "version-aware operations require that the container is versioned",
                );
            };
            let Some(archive_name) = modern_versions_object_name(&object, parsed) else {
                return modern_bad_request("Invalid object name");
            };
            let archive_path = format!("/{version}/{account}/{hidden}/{archive_name}");

            match req.method.as_str() {
                "GET" | "HEAD" => {
                    // Keep `symlink=get` / `multipart-manifest` etc. Python
                    // rewrites path_info and leaves QUERY_STRING intact minus
                    // the consumed version-id semantics (still present on the
                    // public request; archive subrequest must not drop
                    // symlink=get or the archive user-symlink is followed).
                    let rest = query_without_param(&req.query_string, "version-id");
                    let archive = Self::modern_internal_request(
                        &req.method,
                        archive_path,
                        &rest,
                        &req.headers,
                    );
                    let mut resp = next(empty_async_request(archive)).await;
                    let is_delete_marker = resp
                        .headers
                        .get("X-Backend-Content-Type")
                        .or_else(|| resp.headers.get("Content-Type"))
                        == Some(DELETE_MARKER_CONTENT_TYPE);
                    if is_delete_marker {
                        let mut missing = Response::new(404);
                        missing
                            .headers
                            .set("X-Object-Version-Id", parsed.internal());
                        missing
                            .headers
                            .set("Content-Type", DELETE_MARKER_CONTENT_TYPE);
                        return missing;
                    }
                    if (200..300).contains(&resp.status) {
                        resp.headers.set("X-Object-Version-Id", parsed.internal());
                    }
                    resp
                }
                "DELETE" => {
                    let mut current_id = "null".to_string();
                    let current_head = Self::modern_internal_request(
                        "HEAD",
                        req.path.clone(),
                        "symlink=get",
                        &req.headers,
                    );
                    let current = next(empty_async_request(current_head)).await;
                    let expected_target = format!("{hidden}/{archive_name}");
                    let current_target = current
                        .headers
                        .get(SYSMETA_SYMLINK_TARGET)
                        .map(decoded_header_path);
                    if let Some(target) = current_target.as_deref() {
                        if let Some(target_name) = target.split_once('/').map(|(_, name)| name) {
                            if let Some((_name, timestamp)) =
                                split_modern_versions_object_name(target_name)
                            {
                                current_id = timestamp.internal();
                            }
                        }
                    }
                    if current_target.as_deref() == Some(expected_target.as_str()) {
                        let delete_link = Self::modern_internal_request(
                            "DELETE",
                            req.path.clone(),
                            "",
                            &req.headers,
                        );
                        let deleted = next(empty_async_request(delete_link)).await;
                        if !(200..300).contains(&deleted.status) && deleted.status != 404 {
                            return deleted;
                        }
                        current_id = "null".to_string();
                    }
                    let archive =
                        Self::modern_internal_request("DELETE", archive_path, "", &req.headers);
                    let mut resp = next(empty_async_request(archive)).await;
                    resp.headers.set("X-Object-Version-Id", parsed.internal());
                    resp.headers.set("X-Object-Current-Version-Id", current_id);
                    resp
                }
                "PUT" => {
                    self.handle_put_version_streaming(
                        req,
                        next,
                        &version,
                        &account,
                        &hidden,
                        &archive_name,
                        archive_path,
                        parsed,
                    )
                    .await
                }
                _ => next(req).await,
            }
        } else if req.method == "POST" && configured.is_some() {
            // Python object_versioning.handle_post sends the public POST first.
            // Symlink middleware returns 307 for the current-version marker;
            // only that trusted version symlink may redirect metadata to the
            // reserved hidden object.  Build the eventual request before the
            // public call consumes `req`, and never follow an arbitrary 307.
            let hidden = configured.unwrap();
            let source_headers = req.headers.clone();
            let resp = next(req).await;
            if resp.status != 307
                || !resp
                    .headers
                    .get(SYSMETA_OBJECT_VERSIONS_SYMLINK)
                    .is_some_and(config_true_value)
            {
                return resp;
            }
            let Some(location) = resp.headers.get("Location") else {
                return resp;
            };
            let Some(target_path) = validated_modern_post_target(location, &account, &hidden)
            else {
                return resp;
            };

            let mut post = Self::modern_internal_request("POST", target_path, "", &source_headers);
            // Python copies non-expiry POST metadata to the eventual request.
            post.headers.remove("X-Delete-At");
            post.headers.remove("X-Delete-After");
            post.headers.set("X-Backend-Allow-Reserved-Names", "true");
            next(empty_async_request(post)).await
        } else if req.method == "DELETE" && configured.is_some() && is_enabled {
            let hidden = configured.unwrap();
            let hidden_path = format!("/{version}/{account}/{hidden}");
            let mut hidden_head =
                Self::modern_internal_request("HEAD", hidden_path, "", &req.headers);
            hidden_head
                .headers
                .set("X-Backend-Allow-Reserved-Names", "true");
            let hidden_info = next(empty_async_request(hidden_head)).await;
            if hidden_info.status == 404 {
                return Response::error(
                    500,
                    "The versions container does not exist. You may want to re-enable object versioning.",
                );
            }
            if !(200..300).contains(&hidden_info.status) {
                return hidden_info;
            }

            if let Err(resp) = self
                .copy_current_modern_version(
                    &version,
                    &account,
                    &hidden,
                    &object,
                    &req.path,
                    &req.headers,
                    &next,
                )
                .await
            {
                return resp;
            }

            let marker_timestamp = req
                .headers
                .get("X-Timestamp")
                .or_else(|| req.headers.get("X-Backend-Inbound-X-Timestamp"))
                .and_then(|value| value.parse::<Timestamp>().ok())
                .unwrap_or_else(Timestamp::now)
                .normalized();
            let Some(marker_name) = modern_versions_object_name(&object, marker_timestamp) else {
                return modern_bad_request("Invalid object name");
            };
            let marker_path = format!("/{version}/{account}/{hidden}/{marker_name}");
            let mut marker_headers = req.headers.clone();
            marker_headers.remove("Transfer-Encoding");
            marker_headers.set("Content-Length", "0");
            marker_headers.set("Content-Type", DELETE_MARKER_CONTENT_TYPE);
            marker_headers.set("X-Timestamp", marker_timestamp.internal());
            marker_headers.set("X-Backend-Authorize-Override", "true");
            marker_headers.set("X-Backend-Source", "OV");
            marker_headers.set("X-Backend-Allow-Reserved-Names", "true");
            let marker = next(AsyncRequest {
                method: "PUT".to_string(),
                path: marker_path,
                query_string: String::new(),
                headers: marker_headers,
                body: IncomingBody::from_bytes(Vec::new(), req.body.max_body_bytes()),
            })
            .await;
            if marker.status == 404 {
                return Response::error(
                    500,
                    "The versions container does not exist. You may want to re-enable object versioning.",
                );
            }
            if !(200..300).contains(&marker.status) {
                return marker;
            }

            req.query_string.clear();
            req.headers.set("X-Backend-Authorize-Override", "true");
            let mut resp = next(req).await;
            if (200..300).contains(&resp.status) || resp.status == 404 {
                resp.headers
                    .set("X-Object-Version-Id", marker_timestamp.internal());
                resp.headers
                    .set("X-Backend-Content-Type", DELETE_MARKER_CONTENT_TYPE);
            }
            resp
        } else if req.method == "DELETE" {
            // Hyper streams DELETE when object_versioning is on. Legacy
            // X-Versions-Location / X-History-Location must not fall through
            // to a bare current-object DELETE.
            if let Some(cfg) = self.read_version_cfg(&cinfo) {
                if cfg.mode == "history" {
                    return self
                        .handle_delete_history_streaming(
                            req,
                            &version,
                            &account,
                            &object,
                            &cfg.location,
                            next,
                        )
                        .await;
                }
                return self
                    .handle_delete_stack_streaming(
                        req,
                        &version,
                        &account,
                        &container,
                        &object,
                        &cfg.location,
                        next,
                    )
                    .await;
            }
            next(req).await
        } else {
            next(req).await
        }
    }

    fn modern_target_from_listing_item(
        item: &serde_json::Value,
        hidden: &str,
    ) -> Option<(String, String, Timestamp)> {
        let raw_path = item.get("symlink_path")?.as_str()?;
        let decoded = decoded_header_path(raw_path);
        let parts = split_path(&decoded, 4, 4, true).ok()?;
        let target_container = parts[2].as_deref()?;
        if target_container != hidden {
            return None;
        }
        let target_name = parts[3].as_deref()?;
        let (object, version) = split_modern_versions_object_name(target_name)?;
        Some((format!("{target_container}/{target_name}"), object, version))
    }

    async fn rewrite_modern_account_response(&self, req: Request, next: AsyncNextFn) -> Response {
        let mut primary = next(req.clone_head()).await;
        if req.method != "GET" || !(200..300).contains(&primary.status) {
            return self.finish(&req, primary);
        }
        let parts = match split_path(&req.path, 2, 2, false) {
            Ok(parts) => parts,
            Err(_) => return self.finish(&req, primary),
        };
        let version = parts[0].clone().unwrap_or_default();
        let account = parts[1].clone().unwrap_or_default();
        if version.is_empty() || account.is_empty() {
            return self.finish(&req, primary);
        }

        let taken = std::mem::replace(&mut primary.body, Body::empty());
        let primary_body = match taken.collect_async().await {
            Ok(body) => body,
            Err(_) => return Response::error(500, "Error reading account listing"),
        };
        let primary_items: Vec<serde_json::Value> = match serde_json::from_slice(&primary_body) {
            Ok(items) => items,
            Err(_) => {
                primary.body = Body::Buffered(primary_body);
                return self.finish(&req, primary);
            }
        };

        // Keep reserved implementation containers out of the user listing,
        // even when an inner listing formatter supplied them. Retain their
        // rows as a fallback if the dedicated reserved-name query is empty.
        let mut visible = Vec::new();
        let mut hidden_by_primary: HashMap<String, serde_json::Value> = HashMap::new();
        for item in primary_items {
            let hidden_name = item
                .get("name")
                .and_then(|value| value.as_str())
                .and_then(split_modern_versions_container);
            if let Some(name) = hidden_name {
                hidden_by_primary.insert(name, item);
            } else {
                visible.push(item);
            }
        }

        let mut query = vec!["format=json".to_string()];
        let hidden_prefix = req
            .param("prefix")
            .map(|prefix| modern_versions_container(&prefix))
            .unwrap_or_else(|| "\0versions\0".to_string());
        query.push(format!("prefix={}", quote_path(&hidden_prefix)));
        for name in ["marker", "end_marker"] {
            if let Some(value) = req.param(name) {
                query.push(format!(
                    "{name}={}",
                    quote_path(&modern_versions_container(&value))
                ));
            }
        }
        for name in ["limit", "reverse"] {
            if let Some(value) = req.param(name) {
                query.push(format!("{name}={}", quote_path(&value)));
            }
        }
        let mut hidden_get = Self::modern_internal_request(
            "GET",
            format!("/{version}/{account}"),
            &query.join("&"),
            &req.headers,
        );
        hidden_get
            .headers
            .set("X-Backend-Allow-Reserved-Names", "true");
        let mut hidden_resp = next(hidden_get).await;
        if (200..300).contains(&hidden_resp.status) {
            let body = std::mem::replace(&mut hidden_resp.body, Body::empty());
            if let Ok(bytes) = body.collect_async().await {
                if let Ok(items) = serde_json::from_slice::<Vec<serde_json::Value>>(&bytes) {
                    for item in items {
                        let Some(logical_name) = item
                            .get("name")
                            .and_then(|value| value.as_str())
                            .and_then(split_modern_versions_container)
                        else {
                            continue;
                        };
                        hidden_by_primary.insert(logical_name, item);
                    }
                }
            }
        }

        for item in &mut visible {
            let Some(name) = item
                .get("name")
                .and_then(|value| value.as_str())
                .map(str::to_string)
            else {
                continue;
            };
            let Some(hidden) = hidden_by_primary.remove(&name) else {
                continue;
            };
            let hidden_bytes = hidden
                .get("bytes")
                .and_then(|value| value.as_u64())
                .unwrap_or(0);
            let Some(map) = item.as_object_mut() else {
                continue;
            };
            let primary_bytes = map
                .get("bytes")
                .and_then(|value| value.as_u64())
                .unwrap_or(0);
            map.insert(
                "bytes".to_string(),
                serde_json::Value::from(primary_bytes.saturating_add(hidden_bytes)),
            );
        }

        // Python AccountContext.list_containers: leftover hidden versions
        // containers after a direct-deleted primary are surfaced under the
        // user container name with count=0 so clients can see the orphan
        // storage (probe test_account_listing). Names already merged into a
        // live primary were popped above. Client DELETE of the user
        // container still removes the hidden container.
        for (key, mut item) in hidden_by_primary {
            if let Some(map) = item.as_object_mut() {
                map.insert("name".to_string(), serde_json::Value::String(key));
                map.insert("count".to_string(), serde_json::json!(0));
            }
            visible.push(item);
        }

        visible.sort_by(|left, right| {
            left.get("name")
                .and_then(|value| value.as_str())
                .unwrap_or("")
                .cmp(
                    right
                        .get("name")
                        .and_then(|value| value.as_str())
                        .unwrap_or(""),
                )
        });
        if req
            .param("reverse")
            .as_deref()
            .is_some_and(config_true_value)
        {
            visible.reverse();
        }
        let limit = req
            .param("limit")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(10_000);
        visible.truncate(limit);
        let body = serde_json::to_vec(&visible).unwrap_or_else(|_| b"[]".to_vec());
        primary
            .headers
            .set("Content-Length", body.len().to_string());
        primary.body = Body::Buffered(body);
        self.finish(&req, primary)
    }

    async fn add_hidden_container_bytes(
        headers: swift_http::HeaderKeyDict,
        primary: &mut Response,
        version: &str,
        account: &str,
        hidden: &str,
        next: AsyncNextFn,
    ) {
        let hidden_path = format!("/{version}/{account}/{hidden}");
        let mut hidden_head = Self::modern_internal_request("HEAD", hidden_path, "", &headers);
        hidden_head
            .headers
            .set("X-Backend-Allow-Reserved-Names", "true");
        let hidden_resp = next(hidden_head).await;
        if !(200..300).contains(&hidden_resp.status) {
            return;
        }
        let ver_bytes = hidden_resp
            .headers
            .get("X-Container-Bytes-Used")
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);
        let primary_bytes = primary
            .headers
            .get("X-Container-Bytes-Used")
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);
        primary.headers.set(
            "X-Container-Bytes-Used",
            primary_bytes.saturating_add(ver_bytes).to_string(),
        );
    }

    async fn rewrite_modern_container_response(&self, req: Request, next: AsyncNextFn) -> Response {
        let mut primary = next(req.clone_head()).await;
        if !(200..300).contains(&primary.status) {
            return self.finish(&req, primary);
        }
        if !matches!(req.method.as_str(), "GET" | "HEAD") {
            return self.finish(&req, primary);
        }
        let parts = match split_path(&req.path, 3, 3, false) {
            Ok(parts) => parts,
            Err(_) => return self.finish(&req, primary),
        };
        let version = parts[0].clone().unwrap_or_default();
        let account = parts[1].clone().unwrap_or_default();
        let container = parts[2].clone().unwrap_or_default();
        if version.is_empty() || account.is_empty() || container.is_empty() {
            return self.finish(&req, primary);
        }

        let configured = primary
            .headers
            .get(SYSMETA_OBJECT_VERSIONS_CONTAINER)
            .filter(|value| !value.is_empty())
            .map(decoded_header_path);
        let hidden = configured
            .clone()
            .unwrap_or_else(|| modern_versions_container(&container));
        let wants_versions_early = req.param("versions").is_some();
        // Python ContainerContext HEADs the versions container on every
        // successful primary GET/HEAD and adds X-Container-Bytes-Used.
        // `?versions` GET already reads the hidden listing below.
        if req.method == "HEAD" || (req.method == "GET" && !wants_versions_early) {
            if let Some(ref hidden_name) = configured {
                Self::add_hidden_container_bytes(
                    req.headers.clone(),
                    &mut primary,
                    &version,
                    &account,
                    hidden_name,
                    next.clone(),
                )
                .await;
            }
        }
        if req.method == "HEAD" {
            return self.finish(&req, primary);
        }
        let taken = std::mem::replace(&mut primary.body, Body::empty());
        let primary_body = match taken.collect_async().await {
            Ok(body) => body,
            Err(_) => return Response::error(500, "Error reading container listing"),
        };
        let mut primary_items: Vec<serde_json::Value> = match serde_json::from_slice(&primary_body)
        {
            Ok(items) => items,
            Err(_) => {
                primary.body = Body::Buffered(primary_body);
                return self.finish(&req, primary);
            }
        };

        // Ordinary listings expose the target size and etag rather than the
        // zero-byte implementation symlink.  The richer merge below is only
        // needed for an explicit `?versions` request.
        let wants_versions = req.param("versions").is_some();
        for item in &mut primary_items {
            let Some((_target, _object, version_id)) =
                Self::modern_target_from_listing_item(item, &hidden)
            else {
                continue;
            };
            let Some(map) = item.as_object_mut() else {
                continue;
            };
            apply_version_symlink_listing(
                map,
                &version,
                &account,
                &container,
                version_id,
                wants_versions,
            );
        }

        if !wants_versions {
            let body = serde_json::to_vec(&primary_items).unwrap_or(primary_body);
            primary
                .headers
                .set("Content-Length", body.len().to_string());
            primary.body = Body::Buffered(body);
            return self.finish(&req, primary);
        }

        let mut null_versions = Vec::new();
        let mut current: HashMap<String, (String, Timestamp, serde_json::Value)> = HashMap::new();
        let mut subdirs = Vec::new();
        for item in primary_items {
            if item.get("subdir").is_some() {
                subdirs.push(item);
                continue;
            }
            if let Some((target, object, version_id)) =
                Self::modern_target_from_listing_item(&item, &hidden)
            {
                current.insert(target, (object, version_id, item));
            } else {
                let mut item = item;
                if let Some(map) = item.as_object_mut() {
                    map.insert(
                        "version_id".to_string(),
                        serde_json::Value::String("null".to_string()),
                    );
                    map.insert("is_latest".to_string(), serde_json::Value::Bool(true));
                }
                null_versions.push(item);
            }
        }

        let hidden_query = match modern_versions_listing_query(&req) {
            Ok(query) => query,
            Err(resp) => return resp,
        };
        let hidden_path = format!("/{version}/{account}/{hidden}");
        let mut hidden_get =
            Self::modern_internal_request("GET", hidden_path, &hidden_query, &req.headers);
        hidden_get
            .headers
            .set("X-Backend-Allow-Reserved-Names", "true");
        let mut hidden_resp = next(hidden_get).await;
        let hidden_bytes = hidden_resp
            .headers
            .get("X-Container-Bytes-Used")
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);
        let hidden_missing = hidden_resp.status == 404;
        let hidden_listing = if (200..300).contains(&hidden_resp.status) {
            let body = std::mem::replace(&mut hidden_resp.body, Body::empty());
            match body.collect_async().await {
                Ok(bytes) => {
                    serde_json::from_slice::<Vec<serde_json::Value>>(&bytes).unwrap_or_default()
                }
                Err(_) => Vec::new(),
            }
        } else if hidden_missing {
            Vec::new()
        } else {
            return hidden_resp;
        };

        if hidden_bytes > 0 {
            let primary_bytes = primary
                .headers
                .get("X-Container-Bytes-Used")
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(0);
            primary.headers.set(
                "X-Container-Bytes-Used",
                primary_bytes.saturating_add(hidden_bytes).to_string(),
            );
        }

        let mut seen_latest: HashSet<String> = null_versions
            .iter()
            .filter_map(|item| item.get("name").and_then(|value| value.as_str()))
            .map(str::to_string)
            .collect();
        let mut versions = Vec::new();
        for mut item in hidden_listing {
            let Some(raw_name) = item
                .get("name")
                .and_then(|value| value.as_str())
                .map(str::to_string)
            else {
                if let Some(raw_subdir) = item.get("subdir").and_then(|value| value.as_str()) {
                    let decoded = reserved_listing_name(raw_subdir);
                    if let Some(object) = split_reserved_name_first(&decoded) {
                        let already = subdirs.iter().any(|existing| {
                            existing.get("subdir").and_then(|value| value.as_str()) == Some(object)
                        });
                        if !already {
                            subdirs.push(serde_json::json!({"subdir": object}));
                        }
                    }
                }
                continue;
            };
            let decoded_name = reserved_listing_name(&raw_name);
            let Some((object, version_id)) = split_modern_versions_object_name(&decoded_name)
            else {
                continue;
            };
            let target_key = format!("{hidden}/{decoded_name}");
            let is_current = current.remove(&target_key).is_some();
            let is_delete_marker = item.get("content_type").and_then(|value| value.as_str())
                == Some(DELETE_MARKER_CONTENT_TYPE);
            let is_latest = if is_current {
                seen_latest.insert(object.clone());
                true
            } else if is_delete_marker && !seen_latest.contains(&object) {
                seen_latest.insert(object.clone());
                true
            } else {
                false
            };
            if let Some(map) = item.as_object_mut() {
                map.insert("name".to_string(), serde_json::Value::String(object));
                map.insert(
                    "version_id".to_string(),
                    serde_json::Value::String(version_id.internal()),
                );
                map.insert("is_latest".to_string(), serde_json::Value::Bool(is_latest));
            }
            versions.push(item);
        }

        // Match Python's externally visible contract: a successful hidden
        // listing is authoritative even when sharding makes it partial. Only
        // restore current symlinks when the hidden container itself is absent.
        if hidden_missing {
            for (_target, (object, version_id, mut item)) in current {
                if let Some(map) = item.as_object_mut() {
                    map.insert("name".to_string(), serde_json::Value::String(object));
                    map.insert(
                        "version_id".to_string(),
                        serde_json::Value::String(version_id.internal()),
                    );
                    map.insert("is_latest".to_string(), serde_json::Value::Bool(true));
                    map.remove("version_symlink");
                    map.remove("symlink_path");
                }
                versions.push(item);
            }
        }

        versions.extend(null_versions);
        versions.extend(subdirs);
        versions.sort_by(|left, right| {
            let left_name = left
                .get("name")
                .or_else(|| left.get("subdir"))
                .and_then(|value| value.as_str())
                .unwrap_or("");
            let right_name = right
                .get("name")
                .or_else(|| right.get("subdir"))
                .and_then(|value| value.as_str())
                .unwrap_or("");
            left_name.cmp(right_name).then_with(|| {
                let left_version = left
                    .get("version_id")
                    .and_then(|value| value.as_str())
                    .unwrap_or("");
                let right_version = right
                    .get("version_id")
                    .and_then(|value| value.as_str())
                    .unwrap_or("");
                right_version.cmp(left_version)
            })
        });
        if req
            .param("reverse")
            .as_deref()
            .is_some_and(config_true_value)
        {
            versions.reverse();
        }
        let limit = req
            .param("limit")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(10_000);
        versions.truncate(limit);
        let body = serde_json::to_vec(&versions).unwrap_or_else(|_| b"[]".to_vec());
        primary
            .headers
            .set("Content-Length", body.len().to_string());
        primary.body = Body::Buffered(body);
        self.finish(&req, primary)
    }

    /// Translate client `X-Versions-Location` / `X-History-Location` into
    /// sysmeta on container PUT/POST. Returns a 4xx response to short-circuit.
    fn rewrite_container_version_headers(&self, req: &mut Request) -> Option<Response> {
        let enabled = self.allow_versioned_writes;
        let has_versions = req.headers.contains_key("X-Versions-Location");
        let has_history = req.headers.contains_key("X-History-Location");

        if has_versions && has_history {
            let hist = req.headers.get("X-History-Location").unwrap_or("");
            let vers = req.headers.get("X-Versions-Location").unwrap_or("");
            if hist.is_empty() {
                req.headers.remove("X-History-Location");
            } else if !vers.is_empty() {
                let mut resp = Response::with_body(
                    400,
                    "Only one of x-versions-location or x-history-location may be specified",
                );
                resp.headers.set("Content-Type", "text/plain");
                return Some(resp);
            } else {
                req.headers.remove("X-Versions-Location");
            }
        }

        let has_versions = req.headers.contains_key("X-Versions-Location");
        let has_history = req.headers.contains_key("X-History-Location");
        if has_versions || has_history {
            let (val, mode) = if has_versions {
                (
                    req.headers
                        .get("X-Versions-Location")
                        .unwrap_or("")
                        .to_string(),
                    "stack",
                )
            } else {
                (
                    req.headers
                        .get("X-History-Location")
                        .unwrap_or("")
                        .to_string(),
                    "history",
                )
            };
            if val.is_empty() {
                req.headers.set("X-Remove-Versions-Location", "x");
            } else if matches!(enabled, Some(false))
                && (req.method == "PUT" || req.method == "POST")
            {
                let mut resp = Response::with_body(412, "Versioned Writes is disabled");
                resp.headers.set("Content-Type", "text/plain");
                return Some(resp);
            } else {
                match check_container_format(&val) {
                    Ok(location) => {
                        req.headers.set(SYSMETA_VERSIONS_LOC, location);
                        req.headers.set(SYSMETA_VERSIONS_MODE, mode);
                        req.headers.set("X-Versions-Location", "");
                        req.headers.remove("X-Remove-Versions-Location");
                        req.headers.remove("X-Remove-History-Location");
                    }
                    Err(e) => {
                        let mut resp = Response::with_body(400, e.0);
                        resp.headers.set("Content-Type", "text/plain");
                        return Some(resp);
                    }
                }
            }
        }

        if req
            .headers
            .get("X-Remove-Versions-Location")
            .is_some_and(|v| !v.is_empty())
            || req
                .headers
                .get("X-Remove-History-Location")
                .is_some_and(|v| !v.is_empty())
        {
            req.headers.set("X-Versions-Location", "");
            req.headers.set(SYSMETA_VERSIONS_LOC, "");
            req.headers.set(SYSMETA_VERSIONS_MODE, "");
            req.headers.remove("X-Remove-Versions-Location");
            req.headers.remove("X-Remove-History-Location");
        }
        None
    }

    fn expose_versions_on_response(&self, mut resp: Response) -> Response {
        let location = resp
            .headers
            .get(SYSMETA_VERSIONS_LOC)
            .filter(|v| !v.is_empty())
            .map(|s| s.to_string());
        let mode = resp
            .headers
            .get(SYSMETA_VERSIONS_MODE)
            .unwrap_or("stack")
            .to_string();
        if let Some(loc) = location {
            if mode == "history" {
                resp.headers.set("X-History-Location", loc);
            } else {
                resp.headers.set("X-Versions-Location", loc);
            }
        }
        resp
    }

    fn handle_container(&self, mut req: Request, next: &NextFn) -> Response {
        if let Some(resp) = self.rewrite_container_version_headers(&mut req) {
            return resp;
        }
        let resp = next(req);
        self.expose_versions_on_response(resp)
    }

    fn read_version_cfg(&self, cinfo: &Response) -> Option<VersionCfg> {
        let mut location = cinfo
            .headers
            .get(SYSMETA_VERSIONS_LOC)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());
        let mut mode = cinfo
            .headers
            .get(SYSMETA_VERSIONS_MODE)
            .unwrap_or("stack")
            .to_string();
        let mut legacy = false;
        if location.is_none() {
            if let Some(v) = cinfo
                .headers
                .get("X-Versions-Location")
                .filter(|s| !s.is_empty())
            {
                location = Some(v.split('/').next().unwrap_or(v).to_string());
                mode = "stack".into();
                legacy = true;
            }
        }
        let location = location?;
        if !self.is_enabled(legacy) {
            return None;
        }
        // HEAD/sysmeta expose Python `quote()` of UTF-8 names. Internal
        // copy-current paths are already decoded; using the quoted value
        // looks up a container named `%EF%84%...` and 404s the overwrite.
        let location = decoded_header_path(&location);
        let location = location.split('/').next().unwrap_or(&location).to_string();
        Some(VersionCfg { location, mode })
    }
}

fn quote_path(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn public_version_path(api_version: &str, account: &str, container: &str, object: &str) -> String {
    format!(
        "/{}/{}/{}/{}",
        quote_path(api_version),
        quote_path(account),
        quote_path(container),
        quote_path(object),
    )
}

fn public_symlink_target(container: &str, object: &str) -> String {
    format!("{}/{}", quote_path(container), quote_path(object))
}

/// Python SLO part-number responses keep the version-id from the inner
/// versioned GET. Outbound SLO reassemble builds a new 206 and can drop
/// `X-Object-Version-Id`. Re-stamp from the client query after that.
fn stamp_version_id_from_query(req: &Request, mut resp: Response) -> Response {
    if !matches!(req.method.as_str(), "GET" | "HEAD") {
        return resp;
    }
    let Some(raw) = query_param(&req.query_string, "version-id") else {
        return resp;
    };
    if raw.is_empty() {
        return resp;
    }
    if raw == "null" {
        if resp.headers.get("X-Object-Version-Id").is_none() {
            resp.headers.set("X-Object-Version-Id", "null");
        }
        return resp;
    }
    if let Ok(ts) = raw.parse::<Timestamp>() {
        resp.headers.set("X-Object-Version-Id", ts.internal());
    }
    resp
}

/// Python `object_versioning.handle_request` rewrites symlink-follow headers
/// so clients never see the reserved versions container. Hidden
/// `Content-Location` / `X-Symlink-Target` become the public object path
/// plus `?version-id=`.
fn rewrite_hidden_version_client_headers(
    req: &Request,
    mut resp: Response,
    api_version: &str,
    account: &str,
    container: &str,
    object: &str,
) -> Response {
    if !matches!(req.method.as_str(), "GET" | "HEAD") {
        return resp;
    }
    if query_param(&req.query_string, "version-id").is_some_and(|value| !value.is_empty()) {
        return resp;
    }
    if api_version.is_empty() || account.is_empty() || container.is_empty() || object.is_empty() {
        return resp;
    }

    let expected_hidden = modern_versions_container(container);

    if let Some(loc) = resp.headers.get("Content-Location") {
        let decoded = decoded_header_path(loc);
        if let Ok(parts) = split_path(&decoded, 4, 4, true) {
            if parts[1].as_deref() == Some(account)
                && parts[2].as_deref() == Some(expected_hidden.as_str())
            {
                if let Some((_name, version)) = parts[3]
                    .as_deref()
                    .and_then(split_modern_versions_object_name)
                {
                    let version_id = version.internal();
                    resp.headers.set("X-Object-Version-Id", version_id.clone());
                    resp.headers.set(
                        "Content-Location",
                        format!(
                            "{}?version-id={version_id}",
                            public_version_path(api_version, account, container, object)
                        ),
                    );
                }
            }
        }
    }

    if let Some(target) = resp.headers.get("X-Symlink-Target") {
        let decoded = decoded_header_path(target);
        let with_slash = if decoded.starts_with('/') {
            decoded
        } else {
            format!("/{decoded}")
        };
        if let Ok(parts) = split_path(&with_slash, 2, 2, true) {
            if parts[0].as_deref() == Some(expected_hidden.as_str()) {
                if let Some((_name, version)) = parts[1]
                    .as_deref()
                    .and_then(split_modern_versions_object_name)
                {
                    let version_id = version.internal();
                    resp.headers.set("X-Object-Version-Id", version_id.clone());
                    resp.headers.set(
                        "X-Symlink-Target",
                        format!(
                            "{}?version-id={version_id}",
                            public_symlink_target(container, object)
                        ),
                    );
                }
            }
        }
    }

    resp
}

struct ListingItem {
    name: String,
    content_type: String,
}

fn parse_listing_json(bytes: &[u8]) -> Vec<ListingItem> {
    let value: serde_json::Value = match serde_json::from_slice(bytes) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    if let Some(arr) = value.as_array() {
        for it in arr {
            if let Some(name) = it.get("name").and_then(|v| v.as_str()) {
                out.push(ListingItem {
                    name: name.to_string(),
                    content_type: it
                        .get("content_type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("application/octet-stream")
                        .to_string(),
                });
            }
        }
    }
    out
}

impl Middleware for VersionedWrites {
    fn prepare(&self, req: &mut Request) -> MwPrep {
        // Hyper path: handle() is not called. Translate client
        // X-Versions-Location onto sysmeta before container POST (probe
        // test_sharding_listing L671).
        if self.allow_versioned_writes.is_none() {
            return MwPrep::Continue;
        }
        let parts = match split_path(&req.path, 2, 4, true) {
            Ok(p) => p,
            Err(_) => return MwPrep::Continue,
        };
        let container = parts[2].clone().unwrap_or_default();
        let object = parts[3].clone().unwrap_or_default();
        if container.is_empty() || !object.is_empty() {
            return MwPrep::Continue;
        }
        if matches!(req.method.as_str(), "PUT" | "POST") {
            if let Some(resp) = self.rewrite_container_version_headers(req) {
                return MwPrep::ShortCircuit(resp);
            }
        }
        MwPrep::Continue
    }

    fn finish(&self, req: &Request, resp: Response) -> Response {
        let parts = match split_path(&req.path, 2, 4, true) {
            Ok(p) => p,
            Err(_) => return resp,
        };
        let version = parts[0].clone().unwrap_or_default();
        let account = parts[1].clone().unwrap_or_default();
        let container = parts[2].clone().unwrap_or_default();
        let object = parts[3].clone().unwrap_or_default();
        if !object.is_empty() {
            let resp = if self.allow_object_versioning {
                rewrite_hidden_version_client_headers(
                    req, resp, &version, &account, &container, &object,
                )
            } else {
                resp
            };
            return stamp_version_id_from_query(req, resp);
        }
        if container.is_empty() {
            return resp;
        }
        if matches!(req.method.as_str(), "PUT" | "POST" | "GET" | "HEAD") {
            let resp = if self.allow_versioned_writes.is_some() {
                self.expose_versions_on_response(resp)
            } else {
                resp
            };
            if self.allow_object_versioning {
                return self.expose_object_versioning_on_response(resp);
            }
            return resp;
        }
        resp
    }

    fn intercepts_request(&self, req: &Request) -> bool {
        if self.allow_object_versioning
            && matches!(req.method.as_str(), "PUT" | "POST")
            && req.headers.contains_key(CLIENT_VERSIONS_ENABLED)
            && matches!(split_path(&req.path, 3, 3, true), Ok(parts) if parts[2].as_deref().is_some_and(|container| !container.is_empty()))
        {
            return true;
        }
        // Python ContainerContext.handle_delete runs on every user-container
        // DELETE so the hidden versions container is removed. dispatch_remaining
        // only honors intercepts_request; streaming is object-only.
        if self.allow_object_versioning
            && req.method == "DELETE"
            && matches!(split_path(&req.path, 3, 4, true), Ok(parts)
                if parts[2].as_deref().is_some_and(|container| !container.is_empty())
                    && parts.get(3).and_then(|part| part.as_deref()).unwrap_or("").is_empty())
        {
            return true;
        }
        // COPY dest PUT is rewritten by `copy` then dispatched through
        // `dispatch_remaining`, which never consults `streams_request`.
        // Intercept the dest PUT so legacy copy-current still runs.
        let is_object = matches!(split_path(&req.path, 4, 4, true), Ok(parts)
            if parts[2].as_deref().is_some_and(|container| !container.is_empty())
                && parts[3].as_deref().is_some_and(|object| !object.is_empty()));
        let version_id_object = is_object
            && self.allow_object_versioning
            && matches!(req.method.as_str(), "GET" | "HEAD" | "DELETE")
            && query_param(&req.query_string, "version-id").is_some_and(|value| !value.is_empty());
        // COPY source GET is intercept next(), not Hyper streaming.
        (is_object
            && req.method == "PUT"
            && !put_has_version_id(&req.query_string)
            && !req.headers.contains_key("X-Copy-From")
            && (self.allow_object_versioning || self.allow_versioned_writes != Some(false)))
            || version_id_object
    }

    fn intercepts_response(&self) -> bool {
        self.allow_object_versioning
    }

    fn streams_request(&self, req: &Request) -> bool {
        let is_object = matches!(split_path(&req.path, 4, 4, true), Ok(parts)
            if parts[2].as_deref().is_some_and(|container| !container.is_empty())
                && parts[3].as_deref().is_some_and(|object| !object.is_empty()));
        if !is_object {
            return false;
        }
        let ordinary_put = req.method == "PUT"
            && !req.headers.contains_key("X-Copy-From")
            && !put_has_version_id(&req.query_string);
        // Legacy X-Versions-Location PUTs and stack/history DELETEs must
        // stream: G3 Hyper never calls sync `handle()`, so copy-current /
        // restore would otherwise be skipped when `allow_object_versioning`
        // is off (IsolatedIdentity default).
        let legacy_or_modern =
            self.allow_object_versioning || self.allow_versioned_writes != Some(false);
        if ordinary_put && legacy_or_modern {
            return true;
        }
        if req.method == "DELETE" && legacy_or_modern {
            return true;
        }
        if !self.allow_object_versioning {
            return false;
        }
        if req.method == "POST" {
            return true;
        }
        query_param(&req.query_string, "version-id").is_some_and(|value| !value.is_empty())
            && matches!(req.method.as_str(), "GET" | "HEAD" | "PUT" | "POST")
    }

    fn handle_streaming_request(
        &self,
        req: AsyncRequest,
        next: StreamingAsyncNextFn,
    ) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        Box::pin(async move {
            if req.method == "PUT" && !put_has_version_id(&req.query_string) {
                self.handle_modern_put_streaming(req, next).await
            } else {
                self.handle_modern_object_streaming(req, next).await
            }
        })
    }

    fn handle_request_async(
        &self,
        req: Request,
        next: AsyncNextFn,
    ) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        Box::pin(async move {
            let is_object = matches!(split_path(&req.path, 4, 4, true), Ok(parts)
                if parts[2].as_deref().is_some_and(|container| !container.is_empty())
                    && parts[3].as_deref().is_some_and(|object| !object.is_empty()));
            if is_object && req.method == "PUT" && !put_has_version_id(&req.query_string) {
                let streaming_next = streaming_next_from_async(next);
                return self
                    .handle_modern_put_streaming(buffered_to_async(req), streaming_next)
                    .await;
            }
            if is_object
                && self.allow_object_versioning
                && matches!(req.method.as_str(), "GET" | "HEAD" | "DELETE")
                && query_param(&req.query_string, "version-id").is_some_and(|v| !v.is_empty())
            {
                let streaming_next = streaming_next_from_async(next);
                return self
                    .handle_modern_object_streaming(buffered_to_async(req), streaming_next)
                    .await;
            }
            self.handle_object_versioning_container_async(req, next)
                .await
        })
    }

    fn reassemble_async(
        &self,
        req: Request,
        next: AsyncNextFn,
    ) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        Box::pin(async move {
            let is_account_get = req.method == "GET"
                && matches!(split_path(&req.path, 2, 2, false), Ok(parts)
                    if parts[1]
                        .as_deref()
                        .is_some_and(|account| !account.is_empty()));
            if is_account_get {
                return self.rewrite_modern_account_response(req, next).await;
            }

            let is_container = matches!(req.method.as_str(), "GET" | "HEAD")
                && matches!(split_path(&req.path, 3, 3, false), Ok(parts)
                    if parts[2]
                        .as_deref()
                        .is_some_and(|container| !container.is_empty()));
            if is_container {
                return self.rewrite_modern_container_response(req, next).await;
            }

            let resp = next(req.clone_head()).await;
            self.finish(&req, resp)
        })
    }

    fn handle(&self, req: Request, next: &NextFn) -> Response {
        let parts = match split_path(&req.path, 2, 4, true) {
            Ok(p) => p,
            Err(_) => return next(req),
        };
        let version = parts[0].clone().unwrap_or_default();
        let account = parts[1].clone().unwrap_or_default();
        let container = parts[2].clone().unwrap_or_default();
        let object = parts[3].clone().unwrap_or_default();

        if self.allow_object_versioning
            && !container.is_empty()
            && object.is_empty()
            && matches!(req.method.as_str(), "PUT" | "POST")
            && req.headers.contains_key(CLIENT_VERSIONS_ENABLED)
        {
            return self.handle_object_versioning_container(req, next);
        }

        // Container request (no object).
        if !container.is_empty()
            && object.is_empty()
            && self.allow_versioned_writes.is_some()
            && (req.method == "PUT"
                || req.method == "POST"
                || req.method == "GET"
                || req.method == "HEAD")
        {
            return self.handle_container(req, next);
        }

        if object.is_empty() || (req.method != "PUT" && req.method != "DELETE") {
            return next(req);
        }

        let head = pre_authed("HEAD", &format!("/{version}/{account}/{container}"), &req);
        let cinfo = next(head);
        let Some(cfg) = self.read_version_cfg(&cinfo) else {
            return next(req);
        };

        if req.method == "PUT" {
            return self.handle_put(req, &version, &account, &object, &cfg.location, next);
        }
        // DELETE
        if cfg.mode == "history" {
            self.handle_delete_history(req, &version, &account, &object, &cfg.location, next)
        } else {
            self.handle_delete_stack(
                req,
                &version,
                &account,
                &container,
                &object,
                &cfg.location,
                next,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use swift_http::HeaderKeyDict;

    #[test]
    fn test_versions_object_name_format() {
        let name = versions_object_name("obj", "1751500000.00000").unwrap();
        assert!(name.starts_with("003obj/"), "{name}");
        let long = "x".repeat(16);
        let n2 = versions_object_name(&long, "1751500000.00000").unwrap();
        assert!(n2.starts_with("010"), "{n2}");
        assert_eq!(versions_object_prefix("obj"), "003obj/");
        let utf8 = "\u{03a9}"; // U+03A9 OMEGA, UTF-8 length 2
        let n3 = versions_object_name(utf8, "1751500000.00000").unwrap();
        assert!(
            n3.starts_with("002"),
            "utf8 prefix must be byte length, got {n3}"
        );
    }

    #[test]
    fn test_query_without_param_keeps_symlink_get() {
        assert_eq!(
            query_without_param("version-id=1787766177.51067&symlink=get", "version-id"),
            "symlink=get"
        );
        assert_eq!(
            query_without_param("version-id=1787766177.51067", "version-id"),
            ""
        );
        assert_eq!(
            query_without_param(
                "symlink=get&version-id=1.0&multipart-manifest=get",
                "version-id"
            ),
            "symlink=get&multipart-manifest=get"
        );
    }

    #[test]
    fn test_modern_post_target_is_origin_relative_and_version_container_scoped() {
        assert_eq!(
            validated_modern_post_target(
                "/v1/AUTH_test/%00versions%00c/%00o%008211892386.68781",
                "AUTH_test",
                "\0versions\0c",
            )
            .as_deref(),
            Some("/v1/AUTH_test/\0versions\0c/\0o\08211892386.68781")
        );
        assert!(validated_modern_post_target(
            "/v1/AUTH_other/%00versions%00c/%00o%008211892386.68781",
            "AUTH_test",
            "\0versions\0c",
        )
        .is_none());
        assert!(validated_modern_post_target(
            "/v1/AUTH_test/%00versions%00other/%00o%008211892386.68781",
            "AUTH_test",
            "\0versions\0c",
        )
        .is_none());
        assert!(validated_modern_post_target(
            "https://example.test/v1/AUTH_test/%00versions%00c/o",
            "AUTH_test",
            "\0versions\0c",
        )
        .is_none());
        assert!(validated_modern_post_target(
            "//example.test/v1/AUTH_test/%00versions%00c/o",
            "AUTH_test",
            "\0versions\0c",
        )
        .is_none());
        assert!(validated_modern_post_target(
            "/v1/AUTH_test/%00versions%00c",
            "AUTH_test",
            "\0versions\0c",
        )
        .is_none());
    }

    fn req(method: &str, path: &str) -> Request {
        Request {
            method: method.to_string(),
            path: path.to_string(),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: b"newdata".to_vec().into(),
        }
    }

    #[allow(clippy::type_complexity)]
    fn backend(
        versioned: bool,
        current_exists: bool,
    ) -> (Arc<Mutex<Vec<(String, String)>>>, NextFn) {
        let log = Arc::new(Mutex::new(Vec::new()));
        let log2 = log.clone();
        let app: NextFn = Arc::new(move |r: Request| {
            log2.lock()
                .unwrap()
                .push((r.method.clone(), r.path.clone()));
            match r.method.as_str() {
                "HEAD" if r.path.ends_with("/c") || r.path.contains("/c?") => {
                    let mut resp = Response::new(204);
                    if versioned {
                        resp.headers.set(SYSMETA_VERSIONS_LOC, "versions");
                        resp.headers.set(SYSMETA_VERSIONS_MODE, "stack");
                    }
                    resp
                }
                "HEAD" => {
                    if current_exists {
                        Response::new(200)
                    } else {
                        Response::new(404)
                    }
                }
                "GET" if r.path.contains("/versions") && r.query_string.contains("prefix=") => {
                    // Empty listing by default
                    Response::with_body(200, b"[]".to_vec())
                }
                "GET" => {
                    if current_exists {
                        let mut resp = Response::with_body(200, b"olddata".to_vec());
                        resp.headers.set("X-Timestamp", "1751500000.00000");
                        resp.headers.set("Content-Type", "text/plain");
                        resp
                    } else {
                        Response::new(404)
                    }
                }
                _ => Response::new(201),
            }
        });
        (log, app)
    }

    #[test]
    fn test_put_archives_current_version() {
        let (log, app) = backend(true, true);
        let vw = VersionedWrites::new();
        let resp = vw.handle(req("PUT", "/v1/AUTH_test/c/obj"), &app);
        assert_eq!(resp.status, 201);
        let calls = log.lock().unwrap();
        assert!(calls.len() >= 4, "{calls:?}");
        assert_eq!(calls[0].0, "HEAD");
        assert!(calls
            .iter()
            .any(|(m, p)| m == "PUT" && p.contains("/versions/003obj/")));
    }

    #[test]
    fn test_put_no_current_skips_archive() {
        let (log, app) = backend(true, false);
        let vw = VersionedWrites::new();
        let resp = vw.handle(req("PUT", "/v1/AUTH_test/c/obj"), &app);
        assert_eq!(resp.status, 201);
        let calls = log.lock().unwrap();
        assert!(calls
            .iter()
            .all(|(_, p)| !p.contains("/versions/") || p.ends_with("/versions")));
    }

    #[test]
    fn test_put_dlo_manifest_skips_archive() {
        // Official test_versioning_dlo / Swift 2.9 handle_obj_versions_put:
        // a PUT with X-Object-Manifest must not copy-current.
        let (log, app) = backend(true, true);
        let vw = VersionedWrites::new();
        let mut put = req("PUT", "/v1/AUTH_test/c/obj");
        put.body = Body::empty();
        put.headers.set("X-Object-Manifest", "c/obj/");
        let resp = vw.handle(put, &app);
        assert_eq!(resp.status, 201);
        let calls = log.lock().unwrap();
        assert!(
            calls
                .iter()
                .all(|(m, p)| !(m == "PUT" && p.contains("/versions/"))),
            "DLO manifest PUT must not archive: {calls:?}"
        );
        assert!(
            calls
                .iter()
                .all(|(m, p)| !(m == "GET" && p == "/v1/AUTH_test/c/obj")),
            "DLO PUT must skip GET current: {calls:?}"
        );
    }

    fn streaming_legacy_backend(
        current_exists: bool,
    ) -> (
        Arc<Mutex<Vec<(String, String, String)>>>,
        StreamingAsyncNextFn,
    ) {
        type Call = (String, String, String);
        let calls: Arc<Mutex<Vec<Call>>> = Arc::new(Mutex::new(Vec::new()));
        let calls2 = Arc::clone(&calls);
        let next: StreamingAsyncNextFn = Arc::new(move |mut req: AsyncRequest| {
            let calls = Arc::clone(&calls2);
            Box::pin(async move {
                let _body = req.body.materialize(u64::MAX).await.unwrap();
                calls.lock().unwrap().push((
                    req.method.clone(),
                    req.path.clone(),
                    req.query_string.clone(),
                ));
                if req.method == "HEAD" && req.path == "/v1/AUTH_test/c" {
                    let mut resp = Response::new(204);
                    resp.headers.set(SYSMETA_VERSIONS_LOC, "versions");
                    resp.headers.set(SYSMETA_VERSIONS_MODE, "stack");
                    return resp;
                }
                if req.method == "GET" && req.path == "/v1/AUTH_test/c/obj" {
                    if current_exists {
                        let mut resp = Response::with_body(200, b"aaaaa".to_vec());
                        resp.headers.set("X-Timestamp", "1751500000.00000");
                        resp.headers.set("Content-Type", "text/jibberish01");
                        resp.headers.set("Content-Length", "5");
                        return resp;
                    }
                    return Response::new(404);
                }
                Response::new(201)
            })
        });
        (calls, next)
    }

    fn streaming_legacy_put() -> AsyncRequest {
        let mut headers = HeaderKeyDict::new();
        headers.set("Content-Length", "5");
        headers.set("Content-Type", "text/jibberish01");
        AsyncRequest {
            method: "PUT".to_string(),
            path: "/v1/AUTH_test/c/obj".to_string(),
            query_string: String::new(),
            headers,
            body: IncomingBody::from_bytes(b"aaaaa".to_vec(), 1024),
        }
    }

    #[test]
    fn test_legacy_first_put_streams_on_hyper_path() {
        let vw = VersionedWrites::new();
        assert!(vw.streams_request(&req("PUT", "/v1/AUTH_test/c/obj")));
        let vw = VersionedWrites::new().with_object_versioning(true);
        assert!(vw.streams_request(&req("PUT", "/v1/AUTH_test/c/obj")));
    }

    #[test]
    fn test_legacy_delete_streams_when_object_versioning_is_off() {
        // IsolatedIdentity `[filter:versioned_writes]` often sets only
        // `allow_versioned_writes=true`. Hyper must still restore on DELETE
        // (official test_versioning_container_acl last step + stack pop).
        let vw = VersionedWrites::new();
        assert!(!vw.allow_object_versioning, "default must stay legacy-only");
        assert!(
            vw.streams_request(&req("DELETE", "/v1/AUTH_test/c/obj")),
            "legacy stack DELETE must stream on Hyper"
        );
        assert!(!vw.streams_request(&req("DELETE", "/v1/AUTH_test/c")));
        let vw = VersionedWrites::new().with_object_versioning(true);
        assert!(vw.streams_request(&req("DELETE", "/v1/AUTH_test/c/obj")));
    }

    #[tokio::test]
    async fn test_streaming_legacy_first_put_does_not_archive() {
        // Python `_copy_current`: GET current 404 → skip archive PUT.
        // X-Versions-Location versions container stays empty until overwrite.
        let (calls, next) = streaming_legacy_backend(false);
        let vw = VersionedWrites::new().with_object_versioning(true);
        let resp = vw
            .handle_streaming_request(streaming_legacy_put(), next)
            .await;
        assert_eq!(resp.status, 201);
        let calls = calls.lock().unwrap();
        assert!(
            calls
                .iter()
                .any(|(m, p, _)| m == "PUT" && p == "/v1/AUTH_test/c/obj"),
            "client PUT must proceed: {calls:?}"
        );
        assert!(
            calls
                .iter()
                .all(|(m, p, _)| !(m == "PUT" && p.contains("/versions/"))),
            "first PUT must not archive: {calls:?}"
        );
        assert!(
            calls.iter().any(|(m, p, q)| m == "GET"
                && p == "/v1/AUTH_test/c/obj"
                && q.contains("symlink=get")),
            "missing current must be probed: {calls:?}"
        );
    }

    #[tokio::test]
    async fn test_streaming_legacy_overwrite_symlink_archives_empty_body() {
        // GET ?symlink=get must archive the 0-byte link, not the target
        // body (md5('aaaaa')).
        type Call = (String, String, String, Vec<u8>, Option<String>);
        let calls: Arc<Mutex<Vec<Call>>> = Arc::new(Mutex::new(Vec::new()));
        let calls2 = Arc::clone(&calls);
        let next: StreamingAsyncNextFn = Arc::new(move |mut req: AsyncRequest| {
            let calls = Arc::clone(&calls2);
            Box::pin(async move {
                let body = req.body.materialize(u64::MAX).await.unwrap();
                calls.lock().unwrap().push((
                    req.method.clone(),
                    req.path.clone(),
                    req.query_string.clone(),
                    body,
                    req.headers.get("X-Symlink-Target").map(str::to_string),
                ));
                if req.method == "HEAD" && req.path == "/v1/AUTH_test/c" {
                    let mut resp = Response::new(204);
                    resp.headers.set(SYSMETA_VERSIONS_LOC, "versions");
                    resp.headers.set(SYSMETA_VERSIONS_MODE, "stack");
                    return resp;
                }
                if req.method == "GET" && req.path == "/v1/AUTH_test/c/obj" {
                    if req.query_string.contains("symlink=get") {
                        let mut resp = Response::with_body(200, Vec::new());
                        resp.headers.set("X-Timestamp", "1751500000.00000");
                        resp.headers.set("Content-Type", "application/symlink");
                        resp.headers.set("Content-Length", "0");
                        resp.headers.set("ETag", "d41d8cd98f00b204e9800998ecf8427e");
                        resp.headers.set("X-Symlink-Target", "c/tgt_a");
                        return resp;
                    }
                    let mut resp = Response::with_body(200, b"aaaaa".to_vec());
                    resp.headers.set("ETag", "594f803b380a41396ed63dca39503542");
                    resp.headers.set("Content-Length", "5");
                    return resp;
                }
                Response::new(201)
            })
        });
        let mut headers = HeaderKeyDict::new();
        headers.set("Content-Length", "0");
        headers.set("X-Symlink-Target", "c/tgt_b");
        let req = AsyncRequest {
            method: "PUT".to_string(),
            path: "/v1/AUTH_test/c/obj".to_string(),
            query_string: String::new(),
            headers,
            body: IncomingBody::from_bytes(Vec::new(), 1024),
        };
        let vw = VersionedWrites::new().with_object_versioning(true);
        let resp = vw.handle_streaming_request(req, next).await;
        assert_eq!(resp.status, 201);
        let calls = calls.lock().unwrap();
        let get = calls
            .iter()
            .find(|(m, p, _, _, _)| m == "GET" && p == "/v1/AUTH_test/c/obj")
            .expect("GET current");
        assert!(
            get.2.contains("symlink=get"),
            "copy-current must GET ?symlink=get: {calls:?}"
        );
        assert!(
            get.4.is_none(),
            "GET must not carry the new PUT X-Symlink-Target: {calls:?}"
        );
        let archive = calls
            .iter()
            .find(|(m, p, _, _, _)| m == "PUT" && p.contains("/versions/"))
            .expect("archive PUT");
        assert_eq!(
            archive.3, b"",
            "archived symlink body must be empty: {calls:?}"
        );
        assert_eq!(
            archive.4.as_deref(),
            Some("c/tgt_a"),
            "archive must keep the old symlink target: {calls:?}"
        );
    }

    #[tokio::test]
    async fn test_streaming_legacy_overwrite_archives_current() {
        let (calls, next) = streaming_legacy_backend(true);
        let vw = VersionedWrites::new().with_object_versioning(true);
        let resp = vw
            .handle_streaming_request(streaming_legacy_put(), next)
            .await;
        assert_eq!(resp.status, 201);
        let calls = calls.lock().unwrap();
        assert!(
            calls
                .iter()
                .any(|(m, p, _)| m == "PUT" && p.starts_with("/v1/AUTH_test/versions/003obj/")),
            "overwrite must archive: {calls:?}"
        );
        assert!(
            calls
                .iter()
                .any(|(m, p, _)| m == "PUT" && p == "/v1/AUTH_test/c/obj"),
            "client PUT must proceed: {calls:?}"
        );
    }

    #[tokio::test]
    async fn test_streaming_legacy_dlo_manifest_put_does_not_archive() {
        // Official test_versioning_dlo: empty DLO overwrite stays
        // versions object_count == 3 (no archive of the prior manifest).
        let (calls, next) = streaming_legacy_backend(true);
        let vw = VersionedWrites::new();
        let mut headers = HeaderKeyDict::new();
        headers.set("Content-Length", "0");
        headers.set("X-Object-Manifest", "c/obj/");
        let req = AsyncRequest {
            method: "PUT".to_string(),
            path: "/v1/AUTH_test/c/obj".to_string(),
            query_string: String::new(),
            headers,
            body: IncomingBody::from_bytes(Vec::new(), 1024),
        };
        let resp = vw.handle_streaming_request(req, next).await;
        assert_eq!(resp.status, 201);
        let calls = calls.lock().unwrap();
        assert!(
            calls
                .iter()
                .any(|(m, p, _)| m == "PUT" && p == "/v1/AUTH_test/c/obj"),
            "client DLO PUT must proceed: {calls:?}"
        );
        assert!(
            calls
                .iter()
                .all(|(m, p, _)| !(m == "PUT" && p.contains("/versions/"))),
            "DLO manifest PUT must not archive: {calls:?}"
        );
        assert!(
            calls
                .iter()
                .all(|(m, p, _)| !(m == "GET" && p == "/v1/AUTH_test/c/obj")),
            "DLO PUT must skip GET current: {calls:?}"
        );
    }

    #[tokio::test]
    async fn test_streaming_legacy_overwrite_skips_existing_dlo_manifest() {
        // Swift 2.9: current object already a DLO → do not archive it.
        type Call = (String, String, String);
        let calls: Arc<Mutex<Vec<Call>>> = Arc::new(Mutex::new(Vec::new()));
        let calls2 = Arc::clone(&calls);
        let next: StreamingAsyncNextFn = Arc::new(move |mut req: AsyncRequest| {
            let calls = Arc::clone(&calls2);
            Box::pin(async move {
                let _body = req.body.materialize(u64::MAX).await.unwrap();
                calls.lock().unwrap().push((
                    req.method.clone(),
                    req.path.clone(),
                    req.query_string.clone(),
                ));
                if req.method == "HEAD" && req.path == "/v1/AUTH_test/c" {
                    let mut resp = Response::new(204);
                    resp.headers.set(SYSMETA_VERSIONS_LOC, "versions");
                    resp.headers.set(SYSMETA_VERSIONS_MODE, "stack");
                    return resp;
                }
                if req.method == "GET" && req.path == "/v1/AUTH_test/c/obj" {
                    let mut resp = Response::with_body(200, Vec::new());
                    resp.headers.set("X-Timestamp", "1751500000.00000");
                    resp.headers.set("X-Object-Manifest", "c/obj/");
                    resp.headers.set("Content-Length", "0");
                    return resp;
                }
                Response::new(201)
            })
        });
        let vw = VersionedWrites::new();
        let resp = vw
            .handle_streaming_request(streaming_legacy_put(), next)
            .await;
        assert_eq!(resp.status, 201);
        let calls = calls.lock().unwrap();
        assert!(
            calls
                .iter()
                .any(|(m, p, _)| m == "GET" && p == "/v1/AUTH_test/c/obj"),
            "non-DLO PUT must still probe current: {calls:?}"
        );
        assert!(
            calls
                .iter()
                .all(|(m, p, _)| !(m == "PUT" && p.contains("/versions/"))),
            "existing DLO current must not be archived: {calls:?}"
        );
    }

    #[tokio::test]
    async fn test_acl_writer_overwrite_preauths_archive_into_write_denied_versions() {
        // Official test_versioning_container_acl: account2 has source write
        // ACL and X-Container-Write: '' on the versions container. Archive
        // PUT must carry authorize-override (Python make_pre_authed_request).
        type Call = (String, String, HeaderKeyDict);
        let calls: Arc<Mutex<Vec<Call>>> = Arc::new(Mutex::new(Vec::new()));
        let calls2 = Arc::clone(&calls);
        let next: StreamingAsyncNextFn = Arc::new(move |mut req: AsyncRequest| {
            let calls = Arc::clone(&calls2);
            Box::pin(async move {
                let _ = req.body.materialize(u64::MAX).await.unwrap();
                calls.lock().unwrap().push((
                    req.method.clone(),
                    req.path.clone(),
                    req.headers.clone(),
                ));
                if req.method == "HEAD" && req.path == "/v1/AUTH_test/c" {
                    let mut resp = Response::new(204);
                    resp.headers.set(SYSMETA_VERSIONS_LOC, "versions");
                    resp.headers.set(SYSMETA_VERSIONS_MODE, "stack");
                    resp.headers.set("X-Container-Write", "AUTH_other");
                    return resp;
                }
                if req.method == "GET" && req.path == "/v1/AUTH_test/c/obj" {
                    let mut resp = Response::with_body(200, b"aaaaa".to_vec());
                    resp.headers.set("X-Timestamp", "1751500000.00000");
                    resp.headers.set("Content-Type", "text/plain");
                    resp.headers.set("Content-Length", "5");
                    return resp;
                }
                Response::new(201)
            })
        });
        let mut headers = HeaderKeyDict::new();
        headers.set("Content-Length", "5");
        headers.set("X-Auth-Token", "account2");
        let req = AsyncRequest {
            method: "PUT".to_string(),
            path: "/v1/AUTH_test/c/obj".to_string(),
            query_string: String::new(),
            headers,
            body: IncomingBody::from_bytes(b"bbbbb".to_vec(), 1024),
        };
        let vw = VersionedWrites::new();
        let resp = vw.handle_streaming_request(req, next).await;
        assert_eq!(resp.status, 201);
        let calls = calls.lock().unwrap();
        let archive = calls
            .iter()
            .find(|(m, p, _)| m == "PUT" && p.starts_with("/v1/AUTH_test/versions/"))
            .expect("ACL writer overwrite must archive");
        assert_eq!(
            archive.2.get("X-Backend-Authorize-Override"),
            Some("true"),
            "archive PUT must be pre-authed: {calls:?}"
        );
        assert_eq!(archive.2.get("X-Backend-Source"), Some("VW"));
    }

    fn intercept_legacy_backend(
        current_exists: bool,
    ) -> (Arc<Mutex<Vec<(String, String, String)>>>, AsyncNextFn) {
        type Call = (String, String, String);
        let calls: Arc<Mutex<Vec<Call>>> = Arc::new(Mutex::new(Vec::new()));
        let calls2 = Arc::clone(&calls);
        let next: AsyncNextFn = Arc::new(move |r: Request| {
            let calls = Arc::clone(&calls2);
            Box::pin(async move {
                calls.lock().unwrap().push((
                    r.method.clone(),
                    r.path.clone(),
                    r.query_string.clone(),
                ));
                if r.method == "HEAD" && r.path == "/v1/AUTH_test/c" {
                    let mut resp = Response::new(204);
                    resp.headers.set(SYSMETA_VERSIONS_LOC, "versions");
                    resp.headers.set(SYSMETA_VERSIONS_MODE, "stack");
                    return resp;
                }
                if r.method == "GET" && r.path == "/v1/AUTH_test/c/obj" {
                    if current_exists {
                        let mut resp = Response::with_body(200, b"ccccc".to_vec());
                        resp.headers.set("X-Timestamp", "1751500001.00000");
                        resp.headers.set("Content-Type", "text/jibberish02");
                        resp.headers.set("Content-Length", "5");
                        return resp;
                    }
                    return Response::new(404);
                }
                Response::new(201)
            })
        });
        (calls, next)
    }

    fn copy_dest_put() -> Request {
        let mut headers = HeaderKeyDict::new();
        headers.set("Content-Length", "5");
        headers.set("Content-Type", "text/jibberish04");
        headers.set("X-Copied-From", "src/srcobj");
        Request {
            method: "PUT".to_string(),
            path: "/v1/AUTH_test/c/obj".to_string(),
            query_string: String::new(),
            headers,
            body: Body::Buffered(b"ddddd".to_vec()),
        }
    }

    #[test]
    fn test_copy_dest_put_intercepts_on_dispatch_remaining() {
        let vw = VersionedWrites::new().with_object_versioning(true);
        assert!(vw.intercepts_request(&copy_dest_put()));
        let mut leftover = copy_dest_put();
        leftover.query_string = "symlink=get".to_string();
        assert!(
            vw.intercepts_request(&leftover),
            "COPY dest PUT leftover ?symlink=get must still copy-current"
        );
        assert!(vw.streams_request(&leftover));
        let mut x_copy = copy_dest_put();
        x_copy.headers.set("X-Copy-From", "/src/srcobj");
        assert!(
            !vw.intercepts_request(&x_copy),
            "copy middleware must own X-Copy-From"
        );
        let copy_method = req("COPY", "/v1/AUTH_test/src/srcobj");
        assert!(!vw.intercepts_request(&copy_method));
    }

    #[tokio::test]
    async fn test_copy_dest_put_with_symlink_query_archives_current() {
        let (calls, next) = intercept_legacy_backend(true);
        let vw = VersionedWrites::new().with_object_versioning(true);
        let mut dest = copy_dest_put();
        dest.query_string = "symlink=get".to_string();
        dest.headers.set("X-Symlink-Target", "c/target-object");
        dest.body = Body::Buffered(Vec::new());
        let resp = vw.handle_request_async(dest, next).await;
        assert_eq!(resp.status, 201);
        let calls = calls.lock().unwrap();
        assert!(
            calls
                .iter()
                .any(|(m, p, _)| m == "PUT" && p.starts_with("/v1/AUTH_test/versions/003obj/")),
            "COPY dest PUT ?symlink=get must archive current: {calls:?}"
        );
    }

    #[tokio::test]
    async fn test_copy_dest_put_archives_current_via_handle_request_async() {
        // Hyper COPY: copy.rs pops X-Copy-From and next()s a dest PUT through
        // dispatch_remaining, which never calls handle_streaming_request.
        let (calls, next) = intercept_legacy_backend(true);
        let vw = VersionedWrites::new().with_object_versioning(true);
        let resp = vw.handle_request_async(copy_dest_put(), next).await;
        assert_eq!(resp.status, 201);
        let calls = calls.lock().unwrap();
        assert!(
            calls
                .iter()
                .any(|(m, p, _)| m == "PUT" && p.starts_with("/v1/AUTH_test/versions/003obj/")),
            "COPY dest must archive current: {calls:?}"
        );
        assert!(
            calls
                .iter()
                .any(|(m, p, _)| m == "PUT" && p == "/v1/AUTH_test/c/obj"),
            "dest PUT must proceed: {calls:?}"
        );
    }

    #[tokio::test]
    async fn test_copy_dest_put_first_object_does_not_archive() {
        let (calls, next) = intercept_legacy_backend(false);
        let vw = VersionedWrites::new().with_object_versioning(true);
        let resp = vw.handle_request_async(copy_dest_put(), next).await;
        assert_eq!(resp.status, 201);
        let calls = calls.lock().unwrap();
        assert!(
            calls
                .iter()
                .all(|(m, p, _)| !(m == "PUT" && p.contains("/versions/"))),
            "first COPY dest must not archive: {calls:?}"
        );
    }

    #[test]
    fn test_unversioned_container_passes_through() {
        let (log, app) = backend(false, true);
        let vw = VersionedWrites::new();
        let resp = vw.handle(req("PUT", "/v1/AUTH_test/c/obj"), &app);
        assert_eq!(resp.status, 201);
        let calls = log.lock().unwrap();
        assert_eq!(calls.len(), 2, "{calls:?}");
        assert_eq!(calls[1], ("PUT".into(), "/v1/AUTH_test/c/obj".into()));
    }

    #[test]
    fn test_delete_stack_restores_previous() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let log2 = log.clone();
        let archive_name = "003obj/1751500000.00000";
        let app: NextFn = Arc::new(move |r: Request| {
            log2.lock()
                .unwrap()
                .push((r.method.clone(), r.path.clone()));
            match (r.method.as_str(), r.path.as_str()) {
                ("HEAD", p) if p.ends_with("/c") => {
                    let mut resp = Response::new(204);
                    resp.headers.set(SYSMETA_VERSIONS_LOC, "versions");
                    resp.headers.set(SYSMETA_VERSIONS_MODE, "stack");
                    resp
                }
                ("GET", p) if p.contains("/versions") && r.query_string.contains("prefix=") => {
                    let body = format!(
                        r#"[{{"name":"{archive_name}","content_type":"text/plain","bytes":7}}]"#
                    );
                    Response::with_body(200, body.into_bytes())
                }
                ("GET", p) if p.contains("/versions/") => {
                    let mut resp = Response::with_body(200, b"olddata".to_vec());
                    resp.headers.set("Content-Type", "text/plain");
                    resp
                }
                ("PUT", _) => Response::new(201),
                ("DELETE", _) => Response::new(204),
                _ => Response::new(200),
            }
        });
        let vw = VersionedWrites::new();
        let mut dreq = req("DELETE", "/v1/AUTH_test/c/obj");
        dreq.body = Body::empty();
        let resp = vw.handle(dreq, &app);
        assert_eq!(resp.status, 204);
        let calls = log.lock().unwrap();
        // Must restore (PUT current) then DELETE archive.
        assert!(
            calls
                .iter()
                .any(|(m, p)| m == "PUT" && p == "/v1/AUTH_test/c/obj"),
            "{calls:?}"
        );
        assert!(
            calls
                .iter()
                .any(|(m, p)| m == "DELETE" && p.contains("/versions/003obj/")),
            "{calls:?}"
        );
    }

    fn streaming_delete_req() -> AsyncRequest {
        AsyncRequest {
            method: "DELETE".to_string(),
            path: "/v1/AUTH_test/c/obj".to_string(),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: IncomingBody::from_bytes(Vec::new(), 1024),
        }
    }

    #[tokio::test]
    async fn test_streaming_legacy_delete_stack_restores_archive() {
        type Call = (String, String, String, Vec<u8>);
        let calls: Arc<Mutex<Vec<Call>>> = Arc::new(Mutex::new(Vec::new()));
        let calls2 = Arc::clone(&calls);
        let archive_name = "003obj/1751500000.00000";
        let next: StreamingAsyncNextFn = Arc::new(move |mut req: AsyncRequest| {
            let calls = Arc::clone(&calls2);
            let archive_name = archive_name.to_string();
            Box::pin(async move {
                let body = req.body.materialize(u64::MAX).await.unwrap();
                calls.lock().unwrap().push((
                    req.method.clone(),
                    req.path.clone(),
                    req.query_string.clone(),
                    body.clone(),
                ));
                if req.headers.contains_key(AUTHORIZE_ONLY_HEADER) {
                    return Response::new(204);
                }
                if req.method == "HEAD" && req.path == "/v1/AUTH_test/c" {
                    let mut resp = Response::new(204);
                    resp.headers.set(SYSMETA_VERSIONS_LOC, "versions");
                    resp.headers.set(SYSMETA_VERSIONS_MODE, "stack");
                    return resp;
                }
                if req.method == "GET"
                    && req.path == "/v1/AUTH_test/versions"
                    && req.query_string.contains("prefix=")
                {
                    let listing = format!(
                        r#"[{{"name":"{archive_name}","content_type":"text/plain","bytes":5}}]"#
                    );
                    return Response::with_body(200, listing.into_bytes());
                }
                if req.method == "GET" && req.path.contains("/versions/003obj/") {
                    let mut resp = Response::with_body(200, b"ccccc".to_vec());
                    resp.headers.set("Content-Type", "text/jibberish02");
                    resp.headers.set("Content-Length", "5");
                    return resp;
                }
                if req.method == "PUT" && req.path == "/v1/AUTH_test/c/obj" {
                    return Response::new(201);
                }
                if req.method == "DELETE" {
                    return Response::new(204);
                }
                Response::new(200)
            })
        });
        // IsolatedIdentity default: allow_versioned_writes only.
        let vw = VersionedWrites::new();
        assert!(!vw.allow_object_versioning);
        let resp = vw
            .handle_streaming_request(streaming_delete_req(), next)
            .await;
        assert_eq!(resp.status, 204);
        let calls = calls.lock().unwrap();
        let restore = calls
            .iter()
            .find(|(m, p, _, _)| m == "PUT" && p == "/v1/AUTH_test/c/obj");
        assert!(
            restore.is_some(),
            "must restore current from archive: {calls:?}"
        );
        assert_eq!(restore.unwrap().3, b"ccccc", "restored body: {calls:?}");
        assert!(
            calls.iter().any(
                |(m, p, _, _)| m == "DELETE" && p.starts_with("/v1/AUTH_test/versions/003obj/")
            ),
            "must DELETE the popped archive: {calls:?}"
        );
    }

    #[tokio::test]
    async fn test_streaming_legacy_delete_empty_versions_passthrough() {
        type Call = (String, String);
        let calls: Arc<Mutex<Vec<Call>>> = Arc::new(Mutex::new(Vec::new()));
        let calls2 = Arc::clone(&calls);
        let next: StreamingAsyncNextFn = Arc::new(move |mut req: AsyncRequest| {
            let calls = Arc::clone(&calls2);
            Box::pin(async move {
                let _ = req.body.materialize(u64::MAX).await.unwrap();
                calls
                    .lock()
                    .unwrap()
                    .push((req.method.clone(), req.path.clone()));
                if req.headers.contains_key(AUTHORIZE_ONLY_HEADER) {
                    return Response::new(204);
                }
                if req.method == "HEAD" && req.path == "/v1/AUTH_test/c" {
                    let mut resp = Response::new(204);
                    resp.headers.set(SYSMETA_VERSIONS_LOC, "versions");
                    resp.headers.set(SYSMETA_VERSIONS_MODE, "stack");
                    return resp;
                }
                if req.method == "GET" && req.path == "/v1/AUTH_test/versions" {
                    return Response::with_body(200, b"[]".to_vec());
                }
                if req.method == "DELETE" {
                    return Response::new(204);
                }
                Response::new(200)
            })
        });
        let vw = VersionedWrites::new().with_object_versioning(true);
        let resp = vw
            .handle_streaming_request(streaming_delete_req(), next)
            .await;
        assert_eq!(resp.status, 204);
        let calls = calls.lock().unwrap();
        assert!(
            calls
                .iter()
                .any(|(m, p)| m == "DELETE" && p == "/v1/AUTH_test/c/obj"),
            "empty archive list must DELETE current: {calls:?}"
        );
        assert!(
            calls
                .iter()
                .all(|(m, p)| !(m == "PUT" && p == "/v1/AUTH_test/c/obj")),
            "empty archive list must not restore: {calls:?}"
        );
        assert!(
            calls
                .iter()
                .all(|(m, p)| !(m == "DELETE" && p.contains("/versions/"))),
            "empty archive list must not DELETE archive: {calls:?}"
        );
    }

    #[tokio::test]
    async fn test_streaming_legacy_delete_history_archives_and_marker() {
        type Call = (String, String, String);
        let calls: Arc<Mutex<Vec<Call>>> = Arc::new(Mutex::new(Vec::new()));
        let calls2 = Arc::clone(&calls);
        let next: StreamingAsyncNextFn = Arc::new(move |mut req: AsyncRequest| {
            let calls = Arc::clone(&calls2);
            Box::pin(async move {
                let _ = req.body.materialize(u64::MAX).await.unwrap();
                calls.lock().unwrap().push((
                    req.method.clone(),
                    req.path.clone(),
                    req.headers.get("Content-Type").unwrap_or("").to_string(),
                ));
                if req.headers.contains_key(AUTHORIZE_ONLY_HEADER) {
                    return Response::new(204);
                }
                if req.method == "HEAD" && req.path == "/v1/AUTH_test/c" {
                    let mut resp = Response::new(204);
                    resp.headers.set(SYSMETA_VERSIONS_LOC, "versions");
                    resp.headers.set(SYSMETA_VERSIONS_MODE, "history");
                    return resp;
                }
                if req.method == "GET" && req.path == "/v1/AUTH_test/c/obj" {
                    let mut resp = Response::with_body(200, b"cur".to_vec());
                    resp.headers.set("X-Timestamp", "1751500000.00000");
                    resp.headers.set("Content-Type", "text/plain");
                    resp.headers.set("Content-Length", "3");
                    return resp;
                }
                if req.method == "PUT" {
                    return Response::new(201);
                }
                if req.method == "DELETE" {
                    return Response::new(204);
                }
                Response::new(200)
            })
        });
        let vw = VersionedWrites::new().with_object_versioning(true);
        let resp = vw
            .handle_streaming_request(streaming_delete_req(), next)
            .await;
        assert_eq!(resp.status, 204);
        let calls = calls.lock().unwrap();
        assert!(
            calls
                .iter()
                .any(|(m, p, _)| m == "PUT" && p.contains("/versions/003obj/")),
            "history DELETE must archive current: {calls:?}"
        );
        assert!(
            calls
                .iter()
                .any(|(m, _, ct)| m == "PUT" && ct == DELETE_MARKER_CONTENT_TYPE),
            "history DELETE must write marker: {calls:?}"
        );
        assert!(
            calls
                .iter()
                .any(|(m, p, _)| m == "DELETE" && p == "/v1/AUTH_test/c/obj"),
            "history DELETE must delete current: {calls:?}"
        );
    }

    #[test]
    fn test_container_sets_sysmeta_from_versions_location() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let log2 = log.clone();
        let app: NextFn = Arc::new(move |r: Request| {
            log2.lock().unwrap().push((
                r.method.clone(),
                r.headers
                    .get(SYSMETA_VERSIONS_LOC)
                    .unwrap_or("")
                    .to_string(),
            ));
            let mut resp = Response::new(204);
            if let Some(v) = r.headers.get(SYSMETA_VERSIONS_LOC) {
                resp.headers.set(SYSMETA_VERSIONS_LOC, v);
                resp.headers.set(
                    SYSMETA_VERSIONS_MODE,
                    r.headers.get(SYSMETA_VERSIONS_MODE).unwrap_or("stack"),
                );
            }
            resp
        });
        let vw = VersionedWrites::new();
        let mut r = req("POST", "/v1/AUTH_test/c");
        r.body = Body::empty();
        r.headers.set("X-Versions-Location", "versions");
        let resp = vw.handle(r, &app);
        assert_eq!(resp.status, 204);
        assert_eq!(resp.headers.get("X-Versions-Location"), Some("versions"));
        let calls = log.lock().unwrap();
        assert_eq!(calls[0].1, "versions");
    }

    #[test]
    fn test_finish_restamps_version_id_on_slo_part_number_response() {
        let vw = VersionedWrites::new().with_object_versioning(true);
        let mut req = req("GET", "/v1/AUTH_test/c/o");
        req.query_string = "part-number=1&version-id=1787766177.51067".to_string();
        let mut resp = Response::new(206);
        resp.headers.set("X-Parts-Count", "2");
        resp.headers.set("Content-Range", "bytes 0-2/6");
        let out = vw.finish(&req, resp);
        assert_eq!(
            out.headers.get("X-Object-Version-Id"),
            Some("1787766177.51067"),
            "SLO part-number 206 must still advertise the requested version-id"
        );
        assert_eq!(out.headers.get("X-Parts-Count"), Some("2"));
    }

    #[test]
    fn test_finish_rewrites_hidden_content_location_to_version_id_query() {
        let vw = VersionedWrites::new().with_object_versioning(true);
        let version: Timestamp = "1788249092.75587".parse().unwrap();
        let hidden = modern_versions_container("c");
        let archive = modern_versions_object_name("o", version).unwrap();
        let mut resp = Response::new(200);
        resp.headers.set(
            "Content-Location",
            format!(
                "/v1/AUTH_test/{}/{}",
                quote_path(&hidden),
                quote_path(&archive)
            ),
        );
        let out = vw.finish(&req("HEAD", "/v1/AUTH_test/c/o"), resp);
        let version_id = version.internal();
        let expected = format!("/v1/AUTH_test/c/o?version-id={version_id}");
        assert_eq!(out.headers.get("Content-Location"), Some(expected.as_str()));
        assert_eq!(
            out.headers.get("X-Object-Version-Id"),
            Some(version_id.as_str())
        );
    }

    #[test]
    fn test_finish_rewrites_hidden_symlink_target_to_version_id_query() {
        let vw = VersionedWrites::new().with_object_versioning(true);
        let version: Timestamp = "1788249092.75587".parse().unwrap();
        let hidden = modern_versions_container("c");
        let archive = modern_versions_object_name("o", version).unwrap();
        let mut resp = Response::new(200);
        resp.headers.set(
            "X-Symlink-Target",
            format!("{}/{}", quote_path(&hidden), quote_path(&archive)),
        );
        let mut request = req("GET", "/v1/AUTH_test/c/o");
        request.query_string = "symlink=get".to_string();
        let out = vw.finish(&request, resp);
        let version_id = version.internal();
        let expected = format!("c/o?version-id={version_id}");
        assert_eq!(out.headers.get("X-Symlink-Target"), Some(expected.as_str()));
        assert_eq!(
            out.headers.get("X-Object-Version-Id"),
            Some(version_id.as_str())
        );
    }

    #[test]
    fn test_finish_leaves_foreign_content_location_alone() {
        let vw = VersionedWrites::new().with_object_versioning(true);
        let mut resp = Response::new(200);
        resp.headers
            .set("Content-Location", "/v1/AUTH_test/other/obj");
        let out = vw.finish(&req("GET", "/v1/AUTH_test/c/o"), resp);
        assert_eq!(
            out.headers.get("Content-Location"),
            Some("/v1/AUTH_test/other/obj")
        );
        assert!(out.headers.get("X-Object-Version-Id").is_none());
    }

    #[test]
    fn test_finish_does_not_rewrite_version_id_request_content_location() {
        let vw = VersionedWrites::new().with_object_versioning(true);
        let version: Timestamp = "1788249092.75587".parse().unwrap();
        let hidden = modern_versions_container("c");
        let archive = modern_versions_object_name("o", version).unwrap();
        let mut resp = Response::new(200);
        let hidden_loc = format!(
            "/v1/AUTH_test/{}/{}",
            quote_path(&hidden),
            quote_path(&archive)
        );
        resp.headers.set("Content-Location", &hidden_loc);
        let mut request = req("GET", "/v1/AUTH_test/c/o");
        request.query_string = format!("version-id={}", version.internal());
        let out = vw.finish(&request, resp);
        assert_eq!(
            out.headers.get("Content-Location"),
            Some(hidden_loc.as_str())
        );
        let version_id = version.internal();
        assert_eq!(
            out.headers.get("X-Object-Version-Id"),
            Some(version_id.as_str())
        );
    }

    #[test]
    fn test_reserved_listing_name_preserves_percent_twenty_five() {
        assert_eq!(
            super::reserved_listing_name("%00obj%25ff%001234"),
            "\0obj%25ff\01234"
        );
        assert_eq!(
            super::reserved_listing_name("\0obj%25ff\01234"),
            "\0obj%25ff\01234"
        );
    }

    #[test]
    fn test_read_version_cfg_decodes_quoted_utf8_location() {
        let vw = VersionedWrites::new();
        let mut cinfo = Response::new(204);
        cinfo
            .headers
            .set("X-Versions-Location", "%EF%84%8F%ED%88%8D-versions");
        let cfg = vw.read_version_cfg(&cinfo).expect("legacy cfg");
        assert_eq!(cfg.mode, "stack");
        assert_ne!(cfg.location, "%EF%84%8F%ED%88%8D-versions");
        assert!(
            cfg.location.ends_with("-versions"),
            "decoded location {}",
            cfg.location
        );
        assert!(
            !cfg.location.contains('%'),
            "must not keep percent-encoding: {}",
            cfg.location
        );
    }

    #[test]
    fn test_prepare_rewrites_versions_location_to_sysmeta() {
        let vw = VersionedWrites::new();
        let mut r = req("POST", "/v1/AUTH_test/c");
        r.headers.set("X-Versions-Location", "versions");
        assert!(matches!(vw.prepare(&mut r), MwPrep::Continue));
        assert_eq!(r.headers.get(SYSMETA_VERSIONS_LOC), Some("versions"));
        assert_eq!(r.headers.get(SYSMETA_VERSIONS_MODE), Some("stack"));
        let mut resp = Response::new(204);
        resp.headers.set(SYSMETA_VERSIONS_LOC, "versions");
        resp.headers.set(SYSMETA_VERSIONS_MODE, "stack");
        let out = vw.finish(&r, resp);
        assert_eq!(out.headers.get("X-Versions-Location"), Some("versions"));
    }

    #[test]
    fn test_prepare_mutual_exclusion_short_circuits() {
        let vw = VersionedWrites::new();
        let mut r = req("POST", "/v1/AUTH_test/c");
        r.headers.set("X-Versions-Location", "v1");
        r.headers.set("X-History-Location", "v2");
        match vw.prepare(&mut r) {
            MwPrep::ShortCircuit(resp) => assert_eq!(resp.status, 400),
            MwPrep::Continue => panic!("expected 400 short-circuit"),
        }
    }

    #[test]
    fn test_container_mutual_exclusion() {
        let app: NextFn = Arc::new(|_r| Response::new(204));
        let vw = VersionedWrites::new();
        let mut r = req("POST", "/v1/AUTH_test/c");
        r.body = Body::empty();
        r.headers.set("X-Versions-Location", "v1");
        r.headers.set("X-History-Location", "v2");
        assert_eq!(vw.handle(r, &app).status, 400);
    }

    #[test]
    fn test_modern_object_versioning_enable_creates_reserved_container() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let log2 = log.clone();
        let app: NextFn = Arc::new(move |r: Request| {
            log2.lock()
                .unwrap()
                .push((r.method.clone(), r.path.clone()));
            if r.method == "HEAD" && r.path == "/v1/AUTH_test/c" {
                return Response::new(204);
            }
            if r.method == "POST" && r.path == "/v1/AUTH_test/c" {
                let mut resp = Response::new(204);
                if let Some(value) = r.headers.get(SYSMETA_OBJECT_VERSIONS_ENABLED) {
                    resp.headers.set(SYSMETA_OBJECT_VERSIONS_ENABLED, value);
                }
                if let Some(value) = r.headers.get(SYSMETA_OBJECT_VERSIONS_CONTAINER) {
                    resp.headers.set(SYSMETA_OBJECT_VERSIONS_CONTAINER, value);
                }
                return resp;
            }
            Response::new(201)
        });
        let vw = VersionedWrites::new().with_object_versioning(true);
        let mut r = req("POST", "/v1/AUTH_test/c");
        r.body = Body::empty();
        r.headers.set(CLIENT_VERSIONS_ENABLED, "true");
        let resp = vw.handle(r, &app);
        assert_eq!(resp.status, 204);
        assert_eq!(resp.headers.get(CLIENT_VERSIONS_ENABLED), Some("True"));
        let calls = log.lock().unwrap();
        assert!(
            calls
                .iter()
                .any(|(method, path)| { method == "PUT" && path == "/v1/AUTH_test/\0versions\0c" }),
            "{calls:?}"
        );
    }

    #[test]
    fn test_modern_container_delete_intercepts_request() {
        let vw = VersionedWrites::new().with_object_versioning(true);
        assert!(vw.intercepts_request(&req("DELETE", "/v1/AUTH_test/c")));
        assert!(!vw.intercepts_request(&req("DELETE", "/v1/AUTH_test/c/obj")));
        assert!(!VersionedWrites::new().intercepts_request(&req("DELETE", "/v1/AUTH_test/c")));
    }

    #[tokio::test]
    async fn test_modern_container_delete_removes_empty_hidden_container() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let log2 = log.clone();
        let vw = VersionedWrites::new().with_object_versioning(true);
        let app: AsyncNextFn = Arc::new(move |r: Request| {
            log2.lock()
                .unwrap()
                .push((r.method.clone(), r.path.clone()));
            let mut resp = Response::new(204);
            if r.method == "HEAD" && r.path == "/v1/AUTH_test/c" {
                resp.headers.set(
                    SYSMETA_OBJECT_VERSIONS_CONTAINER,
                    quote_path(&modern_versions_container("c")),
                );
                resp.headers.set(SYSMETA_OBJECT_VERSIONS_ENABLED, "True");
                return Box::pin(async move { resp });
            }
            if r.method == "HEAD" && r.path == "/v1/AUTH_test/\0versions\0c" {
                resp.headers.set("X-Container-Object-Count", "0");
                return Box::pin(async move { resp });
            }
            Box::pin(async move { resp })
        });
        let r = req("DELETE", "/v1/AUTH_test/c");
        let resp = vw.handle_request_async(r, app).await;
        assert_eq!(resp.status, 204, "{resp:?}");
        let calls = log.lock().unwrap().clone();
        assert!(
            calls
                .iter()
                .any(|(m, p)| m == "DELETE" && p == "/v1/AUTH_test/\0versions\0c"),
            "must DELETE hidden versions container: {calls:?}"
        );
        assert!(
            calls
                .iter()
                .any(|(m, p)| m == "DELETE" && p == "/v1/AUTH_test/c"),
            "must DELETE user container: {calls:?}"
        );
    }

    #[tokio::test]
    async fn test_modern_container_delete_conflict_when_hidden_not_empty() {
        let vw = VersionedWrites::new().with_object_versioning(true);
        let app: AsyncNextFn = Arc::new(move |r: Request| {
            let mut resp = Response::new(204);
            if r.method == "HEAD" && r.path == "/v1/AUTH_test/c" {
                resp.headers.set(
                    SYSMETA_OBJECT_VERSIONS_CONTAINER,
                    quote_path(&modern_versions_container("c")),
                );
                return Box::pin(async move { resp });
            }
            if r.method == "HEAD" && r.path == "/v1/AUTH_test/\0versions\0c" {
                resp.headers.set("X-Container-Object-Count", "3");
                return Box::pin(async move { resp });
            }
            panic!(
                "must not DELETE while hidden versions remain: {} {}",
                r.method, r.path
            );
        });
        let r = req("DELETE", "/v1/AUTH_test/c");
        let resp = vw.handle_request_async(r, app).await;
        assert_eq!(resp.status, 409);
    }

    #[test]
    fn test_modern_object_versioning_reenable_does_not_double_quote_hidden_container() {
        let call_count = Arc::new(AtomicU64::new(0));
        let call_count2 = Arc::clone(&call_count);
        let app: NextFn =
            Arc::new(
                move |r: Request| match call_count2.fetch_add(1, Ordering::SeqCst) {
                    0 => {
                        assert_eq!(r.method, "HEAD");
                        let mut resp = Response::new(204);
                        resp.headers
                            .set(SYSMETA_OBJECT_VERSIONS_CONTAINER, "%00versions%00c");
                        resp
                    }
                    1 => {
                        assert_eq!(r.method, "PUT");
                        assert_eq!(r.path, "/v1/AUTH_test/\0versions\0c");
                        Response::new(201)
                    }
                    2 => {
                        assert_eq!(r.method, "POST");
                        assert_eq!(
                            r.headers.get(SYSMETA_OBJECT_VERSIONS_CONTAINER),
                            Some("%00versions%00c")
                        );
                        let mut resp = Response::new(204);
                        resp.headers.set(SYSMETA_OBJECT_VERSIONS_ENABLED, "True");
                        resp.headers
                            .set(SYSMETA_OBJECT_VERSIONS_CONTAINER, "%00versions%00c");
                        resp
                    }
                    n => panic!("unexpected re-enable subrequest {n}"),
                },
            );
        let vw = VersionedWrites::new().with_object_versioning(true);
        let mut request = req("POST", "/v1/AUTH_test/c");
        request.headers.set(CLIENT_VERSIONS_ENABLED, "true");
        let resp = vw.handle(request, &app);
        assert_eq!(resp.status, 204);
        assert_eq!(call_count.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_modern_object_versioning_async_reenable_does_not_double_quote_hidden_container() {
        let call_count = Arc::new(AtomicU64::new(0));
        let call_count2 = Arc::clone(&call_count);
        let next: AsyncNextFn = Arc::new(move |r: Request| {
            let call_count = Arc::clone(&call_count2);
            Box::pin(async move {
                match call_count.fetch_add(1, Ordering::SeqCst) {
                    0 => {
                        assert_eq!(r.method, "HEAD");
                        let mut resp = Response::new(204);
                        resp.headers
                            .set(SYSMETA_OBJECT_VERSIONS_CONTAINER, "%00versions%00c");
                        resp
                    }
                    1 => {
                        assert_eq!(r.method, "PUT");
                        assert_eq!(r.path, "/v1/AUTH_test/\0versions\0c");
                        Response::new(201)
                    }
                    2 => {
                        assert_eq!(r.method, "POST");
                        assert_eq!(
                            r.headers.get(SYSMETA_OBJECT_VERSIONS_CONTAINER),
                            Some("%00versions%00c")
                        );
                        let mut resp = Response::new(204);
                        resp.headers.set(SYSMETA_OBJECT_VERSIONS_ENABLED, "True");
                        resp.headers
                            .set(SYSMETA_OBJECT_VERSIONS_CONTAINER, "%00versions%00c");
                        resp
                    }
                    n => panic!("unexpected async re-enable subrequest {n}"),
                }
            })
        });
        let vw = VersionedWrites::new().with_object_versioning(true);
        let mut request = req("POST", "/v1/AUTH_test/c");
        request.headers.set(CLIENT_VERSIONS_ENABLED, "true");
        let resp = vw.handle_request_async(request, next).await;
        assert_eq!(resp.status, 204);
        assert_eq!(call_count.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn test_modern_hidden_container_put_does_not_clone_primary_metadata() {
        let create = hidden_container_put("/v1/AUTH_test/\0versions\0c", Some("2"));
        assert_eq!(create.method, "PUT");
        assert_eq!(create.headers.get("Content-Length"), Some("0"));
        assert_eq!(
            create.headers.get("X-Backend-Allow-Reserved-Names"),
            Some("true")
        );
        assert_eq!(
            create.headers.get("X-Backend-Storage-Policy-Index"),
            Some("2")
        );
        assert!(create.headers.get(CLIENT_VERSIONS_ENABLED).is_none());
        assert!(create
            .headers
            .get(SYSMETA_OBJECT_VERSIONS_ENABLED)
            .is_none());
        assert!(create
            .headers
            .get(SYSMETA_OBJECT_VERSIONS_CONTAINER)
            .is_none());
        assert!(create.headers.get("X-Container-Sync-To").is_none());
    }

    #[tokio::test]
    async fn test_modern_streaming_put_archives_body_then_commits_symlink() {
        type Call = (String, String, String, HeaderKeyDict, Vec<u8>);
        let calls: Arc<Mutex<Vec<Call>>> = Arc::new(Mutex::new(Vec::new()));
        let calls2 = Arc::clone(&calls);
        let next: StreamingAsyncNextFn = Arc::new(move |mut req: AsyncRequest| {
            let calls = Arc::clone(&calls2);
            Box::pin(async move {
                let body = req.body.materialize(u64::MAX).await.unwrap();
                calls.lock().unwrap().push((
                    req.method.clone(),
                    req.path.clone(),
                    req.query_string.clone(),
                    req.headers.clone(),
                    body,
                ));
                if req.method == "HEAD" && req.path == "/v1/AUTH_test/c" {
                    let mut resp = Response::new(204);
                    resp.headers.set(SYSMETA_OBJECT_VERSIONS_ENABLED, "True");
                    resp.headers
                        .set(SYSMETA_OBJECT_VERSIONS_CONTAINER, "%00versions%00c");
                    return resp;
                }
                if req.method == "PUT"
                    && req.path == "/v1/AUTH_test/c/o"
                    && req.headers.contains_key(AUTHORIZE_ONLY_HEADER)
                {
                    return Response::new(204);
                }
                if req.method == "HEAD" && req.path == "/v1/AUTH_test/\0versions\0c" {
                    return Response::new(204);
                }
                if req.method == "GET" && req.path == "/v1/AUTH_test/c/o" {
                    return Response::new(404);
                }
                if req.method == "PUT" && req.path.starts_with("/v1/AUTH_test/\0versions\0c/\0o\0")
                {
                    let mut resp = Response::new(201);
                    resp.headers.set("ETag", "966634ebf2fc135707d6753692bf4b1e");
                    return resp;
                }
                Response::new(201)
            })
        });

        let mut headers = HeaderKeyDict::new();
        headers.set("Content-Length", "8");
        headers.set("Content-Type", "text/plain");
        headers.set("X-Timestamp", "1787770000.00000");
        let req = AsyncRequest {
            method: "PUT".to_string(),
            path: "/v1/AUTH_test/c/o".to_string(),
            query_string: String::new(),
            headers,
            body: IncomingBody::from_bytes(b"version1".to_vec(), 1024),
        };
        let vw = VersionedWrites::new().with_object_versioning(true);
        let resp = vw.handle_streaming_request(req, next).await;
        assert_eq!(resp.status, 201);
        assert_eq!(
            resp.headers.get("ETag"),
            Some("966634ebf2fc135707d6753692bf4b1e")
        );
        assert_eq!(
            resp.headers.get("X-Object-Version-Id"),
            Some("1787770000.00000")
        );

        let calls = calls.lock().unwrap();
        let archive = calls
            .iter()
            .find(|(method, path, _, _, _)| {
                method == "PUT" && path.starts_with("/v1/AUTH_test/\0versions\0c/\0o\0")
            })
            .expect("hidden version PUT");
        assert_eq!(archive.4, b"version1");
        let marker = calls
            .iter()
            .find(|(method, path, _, headers, _)| {
                method == "PUT"
                    && path == "/v1/AUTH_test/c/o"
                    && headers.contains_key(SYSMETA_OBJECT_VERSIONS_SYMLINK)
            })
            .expect("primary symlink PUT");
        assert_eq!(marker.4, b"");
        assert_eq!(marker.3.get(SYSMETA_SYMLINK_TARGET_BYTES), Some("8"));
        assert_eq!(marker.3.get(SYSMETA_ALLOW_RESERVED_NAMES), Some("true"));
        assert!(marker
            .3
            .get(SYSMETA_SYMLINK_TARGET)
            .is_some_and(|value| value.starts_with("%00versions%00c/%00o%00")));
    }

    #[tokio::test]
    async fn test_modern_streaming_put_overwrites_client_symlink_target_on_marker() {
        type Call = (String, String, String, HeaderKeyDict, Vec<u8>);
        let calls: Arc<Mutex<Vec<Call>>> = Arc::new(Mutex::new(Vec::new()));
        let calls2 = Arc::clone(&calls);
        let next: StreamingAsyncNextFn = Arc::new(move |mut req: AsyncRequest| {
            let calls = Arc::clone(&calls2);
            Box::pin(async move {
                let body = req.body.materialize(u64::MAX).await.unwrap();
                calls.lock().unwrap().push((
                    req.method.clone(),
                    req.path.clone(),
                    req.query_string.clone(),
                    req.headers.clone(),
                    body,
                ));
                if req.method == "HEAD" && req.path == "/v1/AUTH_test/c" {
                    let mut resp = Response::new(204);
                    resp.headers.set(SYSMETA_OBJECT_VERSIONS_ENABLED, "True");
                    resp.headers
                        .set(SYSMETA_OBJECT_VERSIONS_CONTAINER, "%00versions%00c");
                    return resp;
                }
                if req.method == "PUT"
                    && req.path == "/v1/AUTH_test/c/o"
                    && req.headers.contains_key(AUTHORIZE_ONLY_HEADER)
                {
                    return Response::new(204);
                }
                if req.method == "HEAD" && req.path == "/v1/AUTH_test/\0versions\0c" {
                    return Response::new(204);
                }
                if req.method == "GET" && req.path == "/v1/AUTH_test/c/o" {
                    return Response::new(404);
                }
                if req.method == "PUT" && req.path.starts_with("/v1/AUTH_test/\0versions\0c/\0o\0")
                {
                    let mut resp = Response::new(201);
                    resp.headers.set("ETag", "d41d8cd98f00b204e9800998ecf8427e");
                    return resp;
                }
                Response::new(201)
            })
        });

        let mut headers = HeaderKeyDict::new();
        headers.set("Content-Length", "0");
        headers.set("Content-Type", "application/octet-stream");
        headers.set("X-Timestamp", "1787770000.00000");
        headers.set("X-Symlink-Target", "c/tgt");
        headers.set("X-Symlink-Target-Account", "other");
        headers.set("X-Symlink-Target-Etag", "abc123");
        let req = AsyncRequest {
            method: "PUT".to_string(),
            path: "/v1/AUTH_test/c/o".to_string(),
            query_string: String::new(),
            headers,
            body: IncomingBody::from_bytes(Vec::new(), 1024),
        };
        let vw = VersionedWrites::new().with_object_versioning(true);
        let resp = vw.handle_streaming_request(req, next).await;
        assert_eq!(resp.status, 201);

        let calls = calls.lock().unwrap();
        let archive = calls
            .iter()
            .find(|(method, path, _, _, _)| {
                method == "PUT" && path.starts_with("/v1/AUTH_test/\0versions\0c/\0o\0")
            })
            .expect("hidden version PUT");
        assert_eq!(archive.3.get("X-Symlink-Target"), Some("c/tgt"));
        let marker = calls
            .iter()
            .find(|(method, path, _, headers, _)| {
                method == "PUT"
                    && path == "/v1/AUTH_test/c/o"
                    && headers.contains_key(SYSMETA_OBJECT_VERSIONS_SYMLINK)
            })
            .expect("primary symlink PUT");
        assert_eq!(marker.4, b"");
        assert!(
            marker
                .3
                .get("X-Symlink-Target")
                .is_some_and(|value| value.starts_with("%00versions%00c/%00o%00")),
            "marker X-Symlink-Target={:?}",
            marker.3.get("X-Symlink-Target")
        );
        assert_ne!(marker.3.get("X-Symlink-Target"), Some("c/tgt"));
        assert!(marker.3.get("X-Symlink-Target-Account").is_none());
        assert_eq!(
            marker.3.get("X-Symlink-Target-Etag"),
            Some("abc123"),
            "marker TGT_ETAG must equal archived static-symlink TGT_ETAG so GET follow matches"
        );
        assert_eq!(
            marker.3.get("X-Backend-Symlink-Override"),
            Some("true"),
            "override skips HEAD-validate of hidden archive against the user-target etag"
        );
        assert!(marker
            .3
            .get(SYSMETA_SYMLINK_TARGET)
            .is_some_and(|value| value.starts_with("%00versions%00c/%00o%00")));
        assert_eq!(marker.3.get(SYSMETA_SYMLOOP_EXTEND), Some("true"));
        assert_eq!(marker.3.get(SYSMETA_ALLOW_RESERVED_NAMES), Some("true"));
    }

    #[tokio::test]
    async fn test_modern_version_id_get_uses_reserved_internal_request() {
        type Call = (String, String, String, HeaderKeyDict);
        let calls: Arc<Mutex<Vec<Call>>> = Arc::new(Mutex::new(Vec::new()));
        let calls2 = Arc::clone(&calls);
        let next: StreamingAsyncNextFn = Arc::new(move |req: AsyncRequest| {
            let calls = Arc::clone(&calls2);
            Box::pin(async move {
                calls.lock().unwrap().push((
                    req.method.clone(),
                    req.path.clone(),
                    req.query_string.clone(),
                    req.headers.clone(),
                ));
                if req.headers.contains_key(AUTHORIZE_ONLY_HEADER) {
                    return Response::new(204);
                }
                if req.method == "HEAD" && req.path == "/v1/AUTH_test/c" {
                    let mut resp = Response::new(204);
                    resp.headers.set(SYSMETA_OBJECT_VERSIONS_ENABLED, "True");
                    resp.headers
                        .set(SYSMETA_OBJECT_VERSIONS_CONTAINER, "%00versions%00c");
                    return resp;
                }
                if req.method == "GET" && req.path.starts_with("/v1/AUTH_test/\0versions\0c/") {
                    return Response::with_body(200, b"version-body".to_vec());
                }
                Response::new(404)
            })
        });

        let request = AsyncRequest {
            method: "GET".to_string(),
            path: "/v1/AUTH_test/c/o".to_string(),
            query_string: "version-id=1787766177.51067".to_string(),
            headers: HeaderKeyDict::new(),
            body: IncomingBody::from_bytes(Vec::new(), 1024),
        };
        let vw = VersionedWrites::new().with_object_versioning(true);
        let mut resp = vw.handle_streaming_request(request, next).await;
        assert_eq!(resp.status, 200, "calls={:?}", calls.lock().unwrap());
        assert_eq!(
            resp.headers.get("X-Object-Version-Id"),
            Some("1787766177.51067")
        );
        assert_eq!(
            resp.body.materialize(1024).unwrap().as_ref(),
            b"version-body"
        );

        let calls = calls.lock().unwrap();
        let archive = calls
            .iter()
            .find(|(method, path, _, _)| {
                method == "GET" && path.starts_with("/v1/AUTH_test/\0versions\0c/")
            })
            .expect("version-id archive GET");
        assert_eq!(
            archive.3.get("X-Backend-Allow-Reserved-Names"),
            Some("true")
        );
        assert_eq!(archive.3.get("X-Backend-Authorize-Override"), Some("true"));
        assert_eq!(
            archive.2, "",
            "version-id-only GET must not invent symlink=get: {calls:?}"
        );
    }

    #[tokio::test]
    async fn test_modern_version_id_head_keeps_symlink_get_on_archive() {
        type Call = (String, String, String, HeaderKeyDict);
        let calls: Arc<Mutex<Vec<Call>>> = Arc::new(Mutex::new(Vec::new()));
        let calls2 = Arc::clone(&calls);
        let next: StreamingAsyncNextFn = Arc::new(move |req: AsyncRequest| {
            let calls = Arc::clone(&calls2);
            Box::pin(async move {
                calls.lock().unwrap().push((
                    req.method.clone(),
                    req.path.clone(),
                    req.query_string.clone(),
                    req.headers.clone(),
                ));
                if req.headers.contains_key(AUTHORIZE_ONLY_HEADER) {
                    return Response::new(204);
                }
                if req.method == "HEAD" && req.path == "/v1/AUTH_test/c" {
                    let mut resp = Response::new(204);
                    resp.headers.set(SYSMETA_OBJECT_VERSIONS_ENABLED, "True");
                    resp.headers
                        .set(SYSMETA_OBJECT_VERSIONS_CONTAINER, "%00versions%00c");
                    return resp;
                }
                if req.method == "HEAD" && req.path.starts_with("/v1/AUTH_test/\0versions\0c/") {
                    let mut resp = Response::new(200);
                    if req.query_string.contains("symlink=get") {
                        resp.headers.set("Content-Type", "application/symlink");
                        resp.headers.set("X-Symlink-Target", "c/target");
                    } else {
                        resp.headers.set("Content-Type", "text/jibberish01");
                    }
                    return resp;
                }
                Response::new(404)
            })
        });

        let request = AsyncRequest {
            method: "HEAD".to_string(),
            path: "/v1/AUTH_test/c/symlink".to_string(),
            query_string: "version-id=1787766177.51067&symlink=get".to_string(),
            headers: HeaderKeyDict::new(),
            body: IncomingBody::from_bytes(Vec::new(), 1024),
        };
        let vw = VersionedWrites::new().with_object_versioning(true);
        let resp = vw.handle_streaming_request(request, next).await;
        assert_eq!(resp.status, 200, "calls={:?}", calls.lock().unwrap());
        assert_eq!(
            resp.headers.get("Content-Type"),
            Some("application/symlink"),
            "symlink=get must not follow the archived user-symlink"
        );

        let calls = calls.lock().unwrap();
        let archive = calls
            .iter()
            .find(|(method, path, _, _)| {
                method == "HEAD" && path.starts_with("/v1/AUTH_test/\0versions\0c/")
            })
            .expect("version-id archive HEAD");
        assert!(
            archive.2.contains("symlink=get"),
            "archive HEAD must keep symlink=get: {calls:?}"
        );
        assert!(
            !archive.2.contains("version-id="),
            "archive HEAD must drop version-id: {calls:?}"
        );
    }

    #[tokio::test]
    async fn test_modern_version_id_get_follows_archived_symlink_unless_symlink_get() {
        // assert_previous_version GETs ?version-id= and expects the target
        // body/type. info(version-id, symlink=get) must not follow.
        // next() is symlink sitting after versioned_writes (18080 pipeline).
        type Call = (String, String, String);
        let calls: Arc<Mutex<Vec<Call>>> = Arc::new(Mutex::new(Vec::new()));
        let calls2 = Arc::clone(&calls);
        let next: StreamingAsyncNextFn = Arc::new(move |req: AsyncRequest| {
            let calls = Arc::clone(&calls2);
            Box::pin(async move {
                calls.lock().unwrap().push((
                    req.method.clone(),
                    req.path.clone(),
                    req.query_string.clone(),
                ));
                if req.headers.contains_key(AUTHORIZE_ONLY_HEADER) {
                    return Response::new(204);
                }
                if req.method == "HEAD" && req.path == "/v1/AUTH_test/c" {
                    let mut resp = Response::new(204);
                    resp.headers.set(SYSMETA_OBJECT_VERSIONS_ENABLED, "True");
                    resp.headers
                        .set(SYSMETA_OBJECT_VERSIONS_CONTAINER, "%00versions%00c");
                    return resp;
                }
                if matches!(req.method.as_str(), "GET" | "HEAD")
                    && req.path.starts_with("/v1/AUTH_test/\0versions\0c/")
                {
                    if query_param(&req.query_string, "symlink").as_deref() == Some("get") {
                        let mut resp = Response::new(200);
                        resp.headers.set("Content-Type", "application/symlink");
                        resp.headers.set(SYSMETA_SYMLINK_TARGET, "c/tgt");
                        return resp;
                    }
                    let mut resp = Response::with_body(200, b"target object data".to_vec());
                    resp.headers.set("Content-Type", "text/jibberish01");
                    return resp;
                }
                Response::new(404)
            })
        });

        let vw = VersionedWrites::new().with_object_versioning(true);
        let follow = AsyncRequest {
            method: "GET".to_string(),
            path: "/v1/AUTH_test/c/symlink".to_string(),
            query_string: "version-id=1787766177.51067".to_string(),
            headers: HeaderKeyDict::new(),
            body: IncomingBody::from_bytes(Vec::new(), 1024),
        };
        let mut followed = vw.handle_streaming_request(follow, Arc::clone(&next)).await;
        assert_eq!(
            followed.status,
            200,
            "follow GET: {:?}",
            calls.lock().unwrap()
        );
        assert_eq!(
            followed.headers.get("Content-Type"),
            Some("text/jibberish01")
        );
        assert_eq!(
            followed.body.materialize(1024).unwrap().as_ref(),
            b"target object data"
        );

        let no_follow = AsyncRequest {
            method: "GET".to_string(),
            path: "/v1/AUTH_test/c/symlink".to_string(),
            query_string: "version-id=1787766177.51067&symlink=get".to_string(),
            headers: HeaderKeyDict::new(),
            body: IncomingBody::from_bytes(Vec::new(), 1024),
        };
        let mut link = vw.handle_streaming_request(no_follow, next).await;
        assert_eq!(
            link.status,
            200,
            "symlink=get GET: {:?}",
            calls.lock().unwrap()
        );
        assert_eq!(
            link.headers.get("Content-Type"),
            Some("application/symlink"),
            "GET ?version-id=&symlink=get must return the archived user-symlink"
        );
        assert_eq!(link.body.materialize(1024).unwrap().as_ref(), b"");

        let calls = calls.lock().unwrap();
        assert!(
            calls.iter().any(|(method, path, qs)| {
                method == "GET"
                    && path.starts_with("/v1/AUTH_test/\0versions\0c/")
                    && !qs.contains("symlink=get")
            }),
            "follow archive GET missing: {calls:?}"
        );
        assert!(
            calls.iter().any(|(method, path, qs)| {
                method == "GET"
                    && path.starts_with("/v1/AUTH_test/\0versions\0c/")
                    && qs.contains("symlink=get")
            }),
            "symlink=get archive GET missing: {calls:?}"
        );
    }

    #[tokio::test]
    async fn test_modern_version_id_head_follows_archived_symlink_without_symlink_get() {
        // assert_previous_version.initialize() is HEAD ?version-id= (no
        // symlink=get) and stores content_type from that response.
        type Call = (String, String, String);
        let calls: Arc<Mutex<Vec<Call>>> = Arc::new(Mutex::new(Vec::new()));
        let calls2 = Arc::clone(&calls);
        let next: StreamingAsyncNextFn = Arc::new(move |req: AsyncRequest| {
            let calls = Arc::clone(&calls2);
            Box::pin(async move {
                calls.lock().unwrap().push((
                    req.method.clone(),
                    req.path.clone(),
                    req.query_string.clone(),
                ));
                if req.headers.contains_key(AUTHORIZE_ONLY_HEADER) {
                    return Response::new(204);
                }
                if req.method == "HEAD" && req.path == "/v1/AUTH_test/c" {
                    let mut resp = Response::new(204);
                    resp.headers.set(SYSMETA_OBJECT_VERSIONS_ENABLED, "True");
                    resp.headers
                        .set(SYSMETA_OBJECT_VERSIONS_CONTAINER, "%00versions%00c");
                    return resp;
                }
                if req.method == "HEAD" && req.path.starts_with("/v1/AUTH_test/\0versions\0c/") {
                    let mut resp = Response::new(200);
                    if query_param(&req.query_string, "symlink").as_deref() == Some("get") {
                        resp.headers.set("Content-Type", "application/symlink");
                    } else {
                        resp.headers.set("Content-Type", "text/jibberish01");
                    }
                    return resp;
                }
                Response::new(404)
            })
        });

        let request = AsyncRequest {
            method: "HEAD".to_string(),
            path: "/v1/AUTH_test/c/symlink".to_string(),
            query_string: "version-id=1787766177.51067".to_string(),
            headers: HeaderKeyDict::new(),
            body: IncomingBody::from_bytes(Vec::new(), 1024),
        };
        let vw = VersionedWrites::new().with_object_versioning(true);
        let resp = vw.handle_streaming_request(request, next).await;
        assert_eq!(resp.status, 200, "calls={:?}", calls.lock().unwrap());
        assert_eq!(
            resp.headers.get("Content-Type"),
            Some("text/jibberish01"),
            "HEAD ?version-id= must follow the archived user-symlink"
        );
        let calls = calls.lock().unwrap();
        let archive = calls
            .iter()
            .find(|(method, path, _)| {
                method == "HEAD" && path.starts_with("/v1/AUTH_test/\0versions\0c/")
            })
            .expect("version-id archive HEAD");
        assert!(
            !archive.2.contains("symlink=get"),
            "HEAD ?version-id= must not force symlink=get: {}",
            archive.2
        );
    }

    #[tokio::test]
    async fn test_modern_post_follows_its_version_symlink_with_reserved_capability() {
        type Call = (String, String, HeaderKeyDict);
        let calls: Arc<Mutex<Vec<Call>>> = Arc::new(Mutex::new(Vec::new()));
        let calls2 = Arc::clone(&calls);
        let next: StreamingAsyncNextFn = Arc::new(move |req: AsyncRequest| {
            let calls = Arc::clone(&calls2);
            Box::pin(async move {
                calls.lock().unwrap().push((
                    req.method.clone(),
                    req.path.clone(),
                    req.headers.clone(),
                ));
                if req.headers.contains_key(AUTHORIZE_ONLY_HEADER) {
                    return Response::new(204);
                }
                if req.method == "HEAD" && req.path == "/v1/AUTH_test/c" {
                    let mut resp = Response::new(204);
                    resp.headers.set(SYSMETA_OBJECT_VERSIONS_ENABLED, "True");
                    resp.headers
                        .set(SYSMETA_OBJECT_VERSIONS_CONTAINER, "%00versions%00c");
                    return resp;
                }
                if req.method == "POST" && req.path == "/v1/AUTH_test/c/o" {
                    let mut resp = Response::new(307);
                    resp.headers.set(
                        "Location",
                        "/v1/AUTH_test/%00versions%00c/%00o%008211892386.68781",
                    );
                    resp.headers.set(SYSMETA_OBJECT_VERSIONS_SYMLINK, "true");
                    return resp;
                }
                if req.method == "POST"
                    && req.path == "/v1/AUTH_test/\0versions\0c/\0o\08211892386.68781"
                {
                    assert_eq!(
                        req.headers.get("X-Backend-Allow-Reserved-Names"),
                        Some("true")
                    );
                    assert_eq!(
                        req.headers.get("X-Backend-Authorize-Override"),
                        Some("true")
                    );
                    assert_eq!(req.headers.get("X-Backend-Source"), Some("OV"));
                    assert_eq!(req.headers.get("X-Object-Meta-Fruit"), Some("Tomato"));
                    assert!(!req.headers.contains_key("X-Delete-After"));
                    assert_eq!(req.body.content_length(), Some(0));
                    return Response::new(202);
                }
                panic!(
                    "unexpected modern POST subrequest {} {}",
                    req.method, req.path
                );
            })
        });

        let vw = VersionedWrites::new().with_object_versioning(true);
        let mut route_probe = req("POST", "/v1/AUTH_test/c/o");
        route_probe.body = Body::empty();
        assert!(vw.streams_request(&route_probe));

        let mut headers = HeaderKeyDict::new();
        headers.set("X-Object-Meta-Fruit", "Tomato");
        headers.set("X-Delete-After", "60");
        let request = AsyncRequest {
            method: "POST".to_string(),
            path: "/v1/AUTH_test/c/o".to_string(),
            query_string: String::new(),
            headers,
            body: IncomingBody::from_bytes(Vec::new(), MAX_CONTROL_BODY),
        };
        let resp = vw.handle_streaming_request(request, next).await;
        assert_eq!(resp.status, 202, "calls={:?}", calls.lock().unwrap());
        assert_eq!(calls.lock().unwrap().len(), 4);
        assert_eq!(
            calls
                .lock()
                .unwrap()
                .iter()
                .filter(|(method, _, _)| method == "POST")
                .count(),
            3,
            "authorization probe, public POST, then trusted hidden POST"
        );
    }

    #[tokio::test]
    async fn test_modern_post_does_not_follow_untrusted_redirect() {
        let calls: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(Vec::new()));
        let calls2 = Arc::clone(&calls);
        let next: StreamingAsyncNextFn = Arc::new(move |req: AsyncRequest| {
            let calls = Arc::clone(&calls2);
            Box::pin(async move {
                calls
                    .lock()
                    .unwrap()
                    .push((req.method.clone(), req.path.clone()));
                if req.headers.contains_key(AUTHORIZE_ONLY_HEADER) {
                    return Response::new(204);
                }
                if req.method == "HEAD" && req.path == "/v1/AUTH_test/c" {
                    let mut resp = Response::new(204);
                    resp.headers.set(SYSMETA_OBJECT_VERSIONS_ENABLED, "True");
                    resp.headers
                        .set(SYSMETA_OBJECT_VERSIONS_CONTAINER, "%00versions%00c");
                    return resp;
                }
                if req.method == "POST" && req.path == "/v1/AUTH_test/c/o" {
                    let mut resp = Response::new(307);
                    resp.headers.set(
                        "Location",
                        "/v1/AUTH_test/%00versions%00other/%00o%008211892386.68781",
                    );
                    resp.headers.set(SYSMETA_OBJECT_VERSIONS_SYMLINK, "true");
                    return resp;
                }
                panic!(
                    "untrusted redirect must not be followed: {} {}",
                    req.method, req.path
                );
            })
        });

        let request = AsyncRequest {
            method: "POST".to_string(),
            path: "/v1/AUTH_test/c/o".to_string(),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: IncomingBody::from_bytes(Vec::new(), MAX_CONTROL_BODY),
        };
        let vw = VersionedWrites::new().with_object_versioning(true);
        let resp = vw.handle_streaming_request(request, next).await;
        assert_eq!(resp.status, 307);
        assert_eq!(calls.lock().unwrap().len(), 3);
        assert_eq!(
            calls
                .lock()
                .unwrap()
                .iter()
                .filter(|(method, _)| method == "POST")
                .count(),
            2,
            "authorization probe and public POST only"
        );
    }

    #[tokio::test]
    async fn test_modern_delete_missing_versions_container_fails_before_delete() {
        let calls: Arc<Mutex<Vec<(String, String, HeaderKeyDict)>>> =
            Arc::new(Mutex::new(Vec::new()));
        let calls2 = Arc::clone(&calls);
        let next: StreamingAsyncNextFn = Arc::new(move |req: AsyncRequest| {
            let calls = Arc::clone(&calls2);
            Box::pin(async move {
                calls.lock().unwrap().push((
                    req.method.clone(),
                    req.path.clone(),
                    req.headers.clone(),
                ));
                if req.headers.contains_key(AUTHORIZE_ONLY_HEADER) {
                    return Response::new(204);
                }
                if req.method == "HEAD" && req.path == "/v1/AUTH_test/c" {
                    let mut resp = Response::new(204);
                    resp.headers.set(SYSMETA_OBJECT_VERSIONS_ENABLED, "True");
                    resp.headers
                        .set(SYSMETA_OBJECT_VERSIONS_CONTAINER, "%00versions%00c");
                    return resp;
                }
                if req.method == "HEAD" && req.path == "/v1/AUTH_test/\0versions\0c" {
                    return Response::new(404);
                }
                Response::new(204)
            })
        });

        let request = AsyncRequest {
            method: "DELETE".to_string(),
            path: "/v1/AUTH_test/c/o".to_string(),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: IncomingBody::from_bytes(Vec::new(), 1024),
        };
        let vw = VersionedWrites::new().with_object_versioning(true);
        let resp = vw.handle_streaming_request(request, next).await;
        assert_eq!(resp.status, 500);
        let calls = calls.lock().unwrap();
        assert!(!calls.iter().any(|(method, path, headers)| {
            method == "DELETE"
                && path == "/v1/AUTH_test/c/o"
                && !headers.contains_key(AUTHORIZE_ONLY_HEADER)
        }));
    }

    #[tokio::test]
    async fn test_modern_versions_listing_merges_hidden_versions() {
        let hidden = modern_versions_container("c");
        let first_version: Timestamp = "1787770000.00000".parse().unwrap();
        let second_version: Timestamp = "1787770001.00000".parse().unwrap();
        let first_name = modern_versions_object_name("o", first_version).unwrap();
        let second_name = modern_versions_object_name("o", second_version).unwrap();
        let primary_body = serde_json::to_vec(&vec![serde_json::json!({
            "name": "o",
            "bytes": 0,
            "hash": MD5_OF_EMPTY_STRING,
            "content_type": "text/plain",
            "last_modified": "2026-08-27T00:00:01.000000",
            "symlink_path": format!(
                "/v1/AUTH_test/{}/{}",
                quote_path(&hidden),
                quote_path(&second_name)
            ),
            "symlink_etag": "second-etag",
            "symlink_bytes": 6
        })])
        .unwrap();
        let hidden_body = serde_json::to_vec(&vec![
            serde_json::json!({
                "name": first_name,
                "bytes": 5,
                "hash": "first-etag",
                "content_type": "text/plain",
                "last_modified": "2026-08-27T00:00:00.000000"
            }),
            serde_json::json!({
                "name": second_name,
                "bytes": 6,
                "hash": "second-etag",
                "content_type": "text/plain",
                "last_modified": "2026-08-27T00:00:01.000000"
            }),
        ])
        .unwrap();

        let call_count = Arc::new(AtomicU64::new(0));
        let call_count2 = Arc::clone(&call_count);
        let next: AsyncNextFn = Arc::new(move |req: Request| {
            let call_count = Arc::clone(&call_count2);
            let primary_body = primary_body.clone();
            let hidden_body = hidden_body.clone();
            Box::pin(async move {
                match call_count.fetch_add(1, Ordering::SeqCst) {
                    0 => {
                        let mut resp = Response::with_body(200, primary_body);
                        resp.headers
                            .set(SYSMETA_OBJECT_VERSIONS_CONTAINER, "%00versions%00c");
                        resp.headers.set("X-Container-Bytes-Used", "0");
                        resp
                    }
                    1 => {
                        assert_eq!(req.method, "GET");
                        assert_eq!(req.path, "/v1/AUTH_test/\0versions\0c");
                        assert_eq!(
                            req.headers.get("X-Backend-Allow-Reserved-Names"),
                            Some("true")
                        );
                        let mut resp = Response::with_body(200, hidden_body);
                        resp.headers.set("X-Container-Bytes-Used", "11");
                        resp
                    }
                    n => panic!("unexpected listing subrequest {n}"),
                }
            })
        });

        let vw = VersionedWrites::new().with_object_versioning(true);
        assert!(vw.intercepts_response());
        let mut request = req("GET", "/v1/AUTH_test/c");
        request.query_string = "versions".to_string();
        request.body = Body::empty();
        let mut resp = vw.reassemble_async(request, next).await;
        assert_eq!(resp.status, 200);
        assert_eq!(resp.headers.get("X-Container-Bytes-Used"), Some("11"));
        let body = resp.body.materialize(MAX_CONTROL_BODY).unwrap();
        let listing: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(listing.len(), 2, "{listing:?}");
        assert!(listing.iter().all(|item| item["name"] == "o"));
        assert_eq!(
            listing
                .iter()
                .filter(|item| item["is_latest"] == true)
                .count(),
            1,
            "{listing:?}"
        );
        let version_ids: HashSet<&str> = listing
            .iter()
            .filter_map(|item| item["version_id"].as_str())
            .collect();
        assert_eq!(version_ids.len(), 2, "{listing:?}");
    }

    #[tokio::test]
    async fn test_modern_versions_listing_does_not_restore_unlisted_current_symlink() {
        let hidden = modern_versions_container("c");
        let listed_version: Timestamp = "1787770000.00000".parse().unwrap();
        let unlisted_version: Timestamp = "1787770001.00000".parse().unwrap();
        let listed_name = modern_versions_object_name("listed", listed_version).unwrap();
        let unlisted_name = modern_versions_object_name("unlisted", unlisted_version).unwrap();
        let primary_body = serde_json::to_vec(&vec![
            serde_json::json!({
                "name": "listed",
                "bytes": 5,
                "hash": "listed-etag",
                "content_type": "text/plain",
                "last_modified": "2026-08-27T00:00:00.000000",
                "symlink_path": format!(
                    "/v1/AUTH_test/{}/{}",
                    quote_path(&hidden),
                    quote_path(&listed_name)
                ),
                "symlink_etag": "listed-etag",
                "symlink_bytes": 5
            }),
            serde_json::json!({
                "name": "unlisted",
                "bytes": 8,
                "hash": "unlisted-etag",
                "content_type": "text/plain",
                "last_modified": "2026-08-27T00:00:01.000000",
                "symlink_path": format!(
                    "/v1/AUTH_test/{}/{}",
                    quote_path(&hidden),
                    quote_path(&unlisted_name)
                ),
                "symlink_etag": "unlisted-etag",
                "symlink_bytes": 8
            }),
        ])
        .unwrap();
        let hidden_body = serde_json::to_vec(&vec![serde_json::json!({
            "name": listed_name,
            "bytes": 5,
            "hash": "listed-etag",
            "content_type": "text/plain",
            "last_modified": "2026-08-27T00:00:00.000000"
        })])
        .unwrap();

        let call_count = Arc::new(AtomicU64::new(0));
        let call_count2 = Arc::clone(&call_count);
        let next: AsyncNextFn = Arc::new(move |_req: Request| {
            let call_count = Arc::clone(&call_count2);
            let primary_body = primary_body.clone();
            let hidden_body = hidden_body.clone();
            Box::pin(async move {
                match call_count.fetch_add(1, Ordering::SeqCst) {
                    0 => {
                        let mut resp = Response::with_body(200, primary_body);
                        resp.headers
                            .set(SYSMETA_OBJECT_VERSIONS_CONTAINER, "%00versions%00c");
                        resp
                    }
                    1 => Response::with_body(200, hidden_body),
                    n => panic!("unexpected listing subrequest {n}"),
                }
            })
        });

        let vw = VersionedWrites::new().with_object_versioning(true);
        let mut request = req("GET", "/v1/AUTH_test/c");
        request.query_string = "versions".to_string();
        request.body = Body::empty();
        let mut resp = vw.reassemble_async(request, next).await;
        assert_eq!(resp.status, 200);
        let body = resp.body.materialize(MAX_CONTROL_BODY).unwrap();
        let listing: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(listing.len(), 1, "{listing:?}");
        assert_eq!(listing[0]["name"], "listed", "{listing:?}");
    }

    #[tokio::test]
    async fn test_modern_versions_listing_restores_current_symlink_when_hidden_is_missing() {
        let hidden = modern_versions_container("c");
        let version: Timestamp = "1787770001.00000".parse().unwrap();
        let version_name = modern_versions_object_name("o", version).unwrap();
        let primary_body = serde_json::to_vec(&vec![serde_json::json!({
            "name": "o",
            "bytes": 8,
            "hash": "etag",
            "content_type": "text/plain",
            "last_modified": "2026-08-27T00:00:01.000000",
            "symlink_path": format!(
                "/v1/AUTH_test/{}/{}",
                quote_path(&hidden),
                quote_path(&version_name)
            ),
            "symlink_etag": "etag",
            "symlink_bytes": 8
        })])
        .unwrap();

        let call_count = Arc::new(AtomicU64::new(0));
        let call_count2 = Arc::clone(&call_count);
        let next: AsyncNextFn = Arc::new(move |_req: Request| {
            let call_count = Arc::clone(&call_count2);
            let primary_body = primary_body.clone();
            Box::pin(async move {
                match call_count.fetch_add(1, Ordering::SeqCst) {
                    0 => {
                        let mut resp = Response::with_body(200, primary_body);
                        resp.headers
                            .set(SYSMETA_OBJECT_VERSIONS_CONTAINER, "%00versions%00c");
                        resp
                    }
                    1 => Response::new(404),
                    n => panic!("unexpected listing subrequest {n}"),
                }
            })
        });

        let vw = VersionedWrites::new().with_object_versioning(true);
        let mut request = req("GET", "/v1/AUTH_test/c");
        request.query_string = "versions".to_string();
        request.body = Body::empty();
        let mut resp = vw.reassemble_async(request, next).await;
        assert_eq!(resp.status, 200);
        let body = resp.body.materialize(MAX_CONTROL_BODY).unwrap();
        let listing: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(listing.len(), 1, "{listing:?}");
        assert_eq!(listing[0]["name"], "o", "{listing:?}");
        assert_eq!(listing[0]["version_id"], version.internal(), "{listing:?}");
        assert_eq!(listing[0]["is_latest"], true, "{listing:?}");
    }

    #[tokio::test]
    async fn test_modern_versions_listing_translates_version_marker() {
        let marker: Timestamp = "1787770000.00000".parse().unwrap();
        let older: Timestamp = "1787769999.00000".parse().unwrap();
        let expected_hidden_marker = modern_versions_object_name("o", marker).unwrap();
        let older_name = modern_versions_object_name("o", older).unwrap();
        let hidden_body = serde_json::to_vec(&vec![serde_json::json!({
            "name": older_name,
            "bytes": 5,
            "hash": "older-etag",
            "content_type": "text/plain",
            "last_modified": "2026-08-26T23:59:59.000000"
        })])
        .unwrap();

        let call_count = Arc::new(AtomicU64::new(0));
        let call_count2 = Arc::clone(&call_count);
        let next: AsyncNextFn = Arc::new(move |req: Request| {
            let call_count = Arc::clone(&call_count2);
            let hidden_body = hidden_body.clone();
            let expected_hidden_marker = expected_hidden_marker.clone();
            Box::pin(async move {
                match call_count.fetch_add(1, Ordering::SeqCst) {
                    0 => {
                        let mut resp = Response::with_body(200, b"[]".to_vec());
                        resp.headers
                            .set(SYSMETA_OBJECT_VERSIONS_CONTAINER, "%00versions%00c");
                        resp
                    }
                    1 => {
                        assert_eq!(req.method, "GET");
                        assert_eq!(req.path, "/v1/AUTH_test/\0versions\0c");
                        let params: HashMap<String, String> =
                            parse_query(&req.query_string).into_iter().collect();
                        assert_eq!(params.get("format").map(String::as_str), Some("json"));
                        assert_eq!(
                            params.get("marker").map(String::as_str),
                            Some(expected_hidden_marker.as_str())
                        );
                        assert!(!params.contains_key("version_marker"));
                        Response::with_body(200, hidden_body)
                    }
                    n => panic!("unexpected listing subrequest {n}"),
                }
            })
        });

        let vw = VersionedWrites::new().with_object_versioning(true);
        let mut request = req("GET", "/v1/AUTH_test/c");
        request.query_string = "marker=o&version_marker=1787770000.00000&versions=".to_string();
        request.body = Body::empty();
        let mut resp = vw.reassemble_async(request, next).await;
        assert_eq!(resp.status, 200);
        let body = resp.body.materialize(MAX_CONTROL_BODY).unwrap();
        let listing: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(listing.len(), 1, "{listing:?}");
        assert_eq!(listing[0]["name"], "o");
        assert_eq!(listing[0]["version_id"], older.internal());
    }

    #[test]
    fn test_modern_versions_listing_query_matches_python_marker_semantics() {
        let build = |query: &str| {
            let mut request = req("GET", "/v1/AUTH_test/c");
            request.query_string = query.to_string();
            modern_versions_listing_query(&request)
        };
        let params = |query: String| -> HashMap<String, String> {
            parse_query(&query).into_iter().collect()
        };

        let marker_only = params(build("marker=o&versions=").unwrap());
        assert_eq!(
            marker_only.get("marker").map(String::as_str),
            Some("\0o\0:")
        );

        let null_marker = params(build("marker=o&version_marker=null&versions=").unwrap());
        assert_eq!(null_marker.get("marker").map(String::as_str), Some("\0o\0"));

        let forwarded =
            params(build("prefix=obj&delimiter=-&limit=17&reverse=true&versions=").unwrap());
        assert_eq!(forwarded.get("prefix").map(String::as_str), Some("\0obj"));
        assert_eq!(forwarded.get("delimiter").map(String::as_str), Some("-"));
        assert_eq!(forwarded.get("limit").map(String::as_str), Some("17"));
        assert_eq!(forwarded.get("reverse").map(String::as_str), Some("true"));

        let response = build("version_marker=1787770000.00000&versions=").unwrap_err();
        assert_eq!(response.status, 400);
        let response = build("marker=o&version_marker=invalid&versions=").unwrap_err();
        assert_eq!(response.status, 400);
        let response = build("delimiter=1&versions=").unwrap_err();
        assert_eq!(response.status, 400);
    }

    #[tokio::test]
    async fn test_modern_account_listing_hides_and_merges_versions_container() {
        let primary_body = serde_json::to_vec(&vec![serde_json::json!({
            "name": "c",
            "count": 1,
            "bytes": 0,
            "last_modified": "2026-08-27T00:00:01.000000"
        })])
        .unwrap();
        let hidden_body = serde_json::to_vec(&vec![serde_json::json!({
            "name": modern_versions_container("c"),
            "count": 2,
            "bytes": 11,
            "last_modified": "2026-08-27T00:00:02.000000"
        })])
        .unwrap();

        let call_count = Arc::new(AtomicU64::new(0));
        let call_count2 = Arc::clone(&call_count);
        let next: AsyncNextFn = Arc::new(move |req: Request| {
            let call_count = Arc::clone(&call_count2);
            let primary_body = primary_body.clone();
            let hidden_body = hidden_body.clone();
            Box::pin(async move {
                match call_count.fetch_add(1, Ordering::SeqCst) {
                    0 => {
                        let mut resp = Response::with_body(200, primary_body);
                        resp.headers.set("X-Account-Container-Count", "2");
                        resp
                    }
                    1 => {
                        assert_eq!(req.method, "GET");
                        assert_eq!(req.path, "/v1/AUTH_test");
                        assert!(req.query_string.contains("prefix=%00versions%00"));
                        assert_eq!(
                            req.headers.get("X-Backend-Allow-Reserved-Names"),
                            Some("true")
                        );
                        Response::with_body(200, hidden_body)
                    }
                    n => panic!("unexpected account-listing subrequest {n}"),
                }
            })
        });

        let vw = VersionedWrites::new().with_object_versioning(true);
        let mut request = req("GET", "/v1/AUTH_test");
        request.body = Body::empty();
        let mut resp = vw.reassemble_async(request, next).await;
        assert_eq!(resp.status, 200);
        // Account headers deliberately retain physical primary + hidden
        // counts; only the user-facing listing body is folded.
        assert_eq!(resp.headers.get("X-Account-Container-Count"), Some("2"));
        let body = resp.body.materialize(MAX_CONTROL_BODY).unwrap();
        let listing: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(listing.len(), 1, "{listing:?}");
        assert_eq!(listing[0]["name"], "c");
        assert_eq!(listing[0]["count"], 1);
        assert_eq!(listing[0]["bytes"], 11);
    }

    #[tokio::test]
    async fn test_modern_account_listing_surfaces_orphan_hidden_container() {
        // Python test_list_orphan_hidden_containers / probe
        // test_account_listing: a hidden versions container with no live
        // primary is rewritten to the user name with count=0.
        let primary_body = serde_json::to_vec(&Vec::<serde_json::Value>::new()).unwrap();
        let hidden_body = serde_json::to_vec(&vec![serde_json::json!({
            "name": modern_versions_container("container1"),
            "count": 3,
            "bytes": 16,
            "last_modified": "2026-09-04T00:00:00.000000"
        })])
        .unwrap();

        let call_count = Arc::new(AtomicU64::new(0));
        let call_count2 = Arc::clone(&call_count);
        let next: AsyncNextFn = Arc::new(move |req: Request| {
            let call_count = Arc::clone(&call_count2);
            let primary_body = primary_body.clone();
            let hidden_body = hidden_body.clone();
            Box::pin(async move {
                match call_count.fetch_add(1, Ordering::SeqCst) {
                    0 => {
                        let mut resp = Response::with_body(200, primary_body);
                        resp.headers.set("X-Account-Container-Count", "1");
                        resp.headers.set("X-Account-Object-Count", "3");
                        resp.headers.set("X-Account-Bytes-Used", "16");
                        resp
                    }
                    1 => {
                        assert_eq!(
                            req.headers.get("X-Backend-Allow-Reserved-Names"),
                            Some("true")
                        );
                        Response::with_body(200, hidden_body)
                    }
                    n => panic!("unexpected account-listing subrequest {n}"),
                }
            })
        });

        let vw = VersionedWrites::new().with_object_versioning(true);
        let mut request = req("GET", "/v1/AUTH_test");
        request.body = Body::empty();
        let mut resp = vw.reassemble_async(request, next).await;
        assert_eq!(resp.status, 200);
        assert_eq!(resp.headers.get("X-Account-Container-Count"), Some("1"));
        assert_eq!(resp.headers.get("X-Account-Object-Count"), Some("3"));
        assert_eq!(resp.headers.get("X-Account-Bytes-Used"), Some("16"));
        let body = resp.body.materialize(MAX_CONTROL_BODY).unwrap();
        let listing: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(listing.len(), 1, "{listing:?}");
        assert_eq!(listing[0]["name"], "container1");
        assert_eq!(listing[0]["count"], 0);
        assert_eq!(listing[0]["bytes"], 16);
    }

    #[test]
    fn test_modern_object_versioning_rejects_sync_source() {
        let app: NextFn = Arc::new(|r: Request| {
            if r.method == "HEAD" {
                let mut resp = Response::new(204);
                resp.headers.set("X-Container-Sync-To", "//r/c/a/d");
                return resp;
            }
            Response::new(204)
        });
        let vw = VersionedWrites::new().with_object_versioning(true);
        let mut r = req("POST", "/v1/AUTH_test/c");
        r.body = Body::empty();
        r.headers.set(CLIENT_VERSIONS_ENABLED, "true");
        let mut resp = vw.handle(r, &app);
        assert_eq!(resp.status, 400);
        let body = resp.body.materialize(MAX_CONTROL_BODY).unwrap();
        assert_eq!(
            body,
            b"Cannot enable object versioning on a container configured as source of container syncing."
        );
    }

    #[test]
    fn test_delete_history_archives_and_marker() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let log2 = log.clone();
        let app: NextFn = Arc::new(move |r: Request| {
            let ct = r.headers.get("Content-Type").unwrap_or("").to_string();
            log2.lock()
                .unwrap()
                .push((r.method.clone(), r.path.clone(), ct));
            match (r.method.as_str(), r.path.as_str()) {
                ("HEAD", p) if p.ends_with("/c") => {
                    let mut resp = Response::new(204);
                    resp.headers.set(SYSMETA_VERSIONS_LOC, "versions");
                    resp.headers.set(SYSMETA_VERSIONS_MODE, "history");
                    resp
                }
                ("GET", "/v1/AUTH_test/c/obj") => {
                    let mut resp = Response::with_body(200, b"cur".to_vec());
                    resp.headers.set("X-Timestamp", "1751500000.00000");
                    resp.headers.set("Content-Type", "text/plain");
                    resp
                }
                ("PUT", _) => Response::new(201),
                ("DELETE", _) => Response::new(204),
                _ => Response::new(200),
            }
        });
        let vw = VersionedWrites::new();
        let mut dreq = req("DELETE", "/v1/AUTH_test/c/obj");
        dreq.body = Body::empty();
        let resp = vw.handle(dreq, &app);
        assert_eq!(resp.status, 204);
        let calls = log.lock().unwrap();
        // Archive current, write delete-marker, then DELETE current.
        assert!(
            calls
                .iter()
                .any(|(m, p, _)| m == "PUT" && p.contains("/versions/003obj/")),
            "archive missing: {calls:?}"
        );
        assert!(
            calls.iter().any(|(m, p, ct)| {
                m == "PUT" && p.contains("/versions/") && ct == DELETE_MARKER_CONTENT_TYPE
            }),
            "delete marker missing: {calls:?}"
        );
        assert!(
            calls
                .iter()
                .any(|(m, p, _)| m == "DELETE" && p == "/v1/AUTH_test/c/obj"),
            "original delete missing: {calls:?}"
        );
    }

    #[tokio::test]
    async fn test_ordinary_listing_keeps_slo_etag_on_version_symlink() {
        let hidden = modern_versions_container("c");
        let version: Timestamp = "1787770001.00000".parse().unwrap();
        let version_name = modern_versions_object_name("my-slo-manifest", version).unwrap();
        let primary_body = serde_json::to_vec(&vec![serde_json::json!({
            "name": "my-slo-manifest",
            "bytes": 0,
            "hash": "387d1ab7d89eda2162bcf8e502667c86; slo_etag=71e938d37c1d06dc634dd24660255a88",
            "content_type": "application/octet-stream",
            "last_modified": "2026-08-27T00:00:01.000000",
            "symlink_path": format!(
                "/v1/AUTH_test/{}/{}",
                quote_path(&hidden),
                quote_path(&version_name)
            ),
            "symlink_etag": "387d1ab7d89eda2162bcf8e502667c86",
            "symlink_bytes": 1048576
        })])
        .unwrap();

        let next: AsyncNextFn = Arc::new(move |req: Request| {
            let primary_body = primary_body.clone();
            Box::pin(async move {
                if req.method == "HEAD" && req.path == "/v1/AUTH_test/\0versions\0c" {
                    let mut resp = Response::new(204);
                    resp.headers.set("X-Container-Bytes-Used", "1048576");
                    return resp;
                }
                let mut resp = Response::with_body(200, primary_body);
                resp.headers
                    .set(SYSMETA_OBJECT_VERSIONS_CONTAINER, "%00versions%00c");
                resp.headers.set("X-Container-Bytes-Used", "0");
                resp
            })
        });

        let vw = VersionedWrites::new().with_object_versioning(true);
        let mut request = req("GET", "/v1/AUTH_test/c");
        request.query_string = "format=json".to_string();
        request.body = Body::empty();
        let mut resp = vw.reassemble_async(request, next).await;
        assert_eq!(resp.status, 200);
        assert_eq!(resp.headers.get("X-Container-Bytes-Used"), Some("1048576"));
        let body = resp.body.materialize(MAX_CONTROL_BODY).unwrap();
        let listing: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(listing.len(), 1, "{listing:?}");
        assert_eq!(listing[0]["bytes"], 1048576, "{listing:?}");
        assert_eq!(listing[0]["version_symlink"], true, "{listing:?}");
        assert_eq!(
            listing[0]["hash"].as_str(),
            Some("387d1ab7d89eda2162bcf8e502667c86; slo_etag=71e938d37c1d06dc634dd24660255a88"),
            "{listing:?}"
        );
    }

    #[tokio::test]
    async fn test_versions_listing_delimiter_includes_delete_marker_prefix() {
        let hidden_body = serde_json::to_vec(&vec![
            serde_json::json!({"subdir": "\0del-"}),
            serde_json::json!({"subdir": "\0test-"}),
        ])
        .unwrap();
        let primary_body = serde_json::to_vec(&vec![
            serde_json::json!({"subdir": "off-"}),
            serde_json::json!({"name": "test", "bytes": 5, "hash": "h",
                "content_type": "text/plain", "last_modified": "2026-08-27T00:00:00.000000"}),
            serde_json::json!({"subdir": "test-"}),
        ])
        .unwrap();

        let call_count = Arc::new(AtomicU64::new(0));
        let call_count2 = Arc::clone(&call_count);
        let next: AsyncNextFn = Arc::new(move |req: Request| {
            let call_count = Arc::clone(&call_count2);
            let primary_body = primary_body.clone();
            let hidden_body = hidden_body.clone();
            Box::pin(async move {
                match call_count.fetch_add(1, Ordering::SeqCst) {
                    0 => {
                        assert_eq!(req.method, "GET");
                        let mut resp = Response::with_body(200, primary_body);
                        resp.headers
                            .set(SYSMETA_OBJECT_VERSIONS_CONTAINER, "%00versions%00c");
                        resp
                    }
                    1 => {
                        assert_eq!(req.method, "GET");
                        assert!(
                            req.query_string.contains("delimiter=-"),
                            "{}",
                            req.query_string
                        );
                        Response::with_body(200, hidden_body)
                    }
                    n => panic!(
                        "unexpected listing subrequest {n} {} {}",
                        req.method, req.path
                    ),
                }
            })
        });

        let vw = VersionedWrites::new().with_object_versioning(true);
        let mut request = req("GET", "/v1/AUTH_test/c");
        request.query_string = "versions=&delimiter=-&format=json".to_string();
        request.body = Body::empty();
        let mut resp = vw.reassemble_async(request, next).await;
        assert_eq!(resp.status, 200);
        let body = resp.body.materialize(MAX_CONTROL_BODY).unwrap();
        let listing: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        let names: Vec<&str> = listing
            .iter()
            .filter_map(|item| item.get("name").or_else(|| item.get("subdir")))
            .filter_map(|value| value.as_str())
            .collect();
        assert_eq!(names, ["del-", "off-", "test", "test-"], "{listing:?}");
    }

    #[tokio::test]
    async fn test_container_head_adds_hidden_bytes_used() {
        let next: AsyncNextFn = Arc::new(|req: Request| {
            Box::pin(async move {
                if req.method == "HEAD" && req.path == "/v1/AUTH_test/c" {
                    let mut resp = Response::new(204);
                    resp.headers
                        .set(SYSMETA_OBJECT_VERSIONS_CONTAINER, "%00versions%00c");
                    resp.headers.set("X-Container-Bytes-Used", "13");
                    resp.headers.set("X-Container-Object-Count", "2");
                    return resp;
                }
                if req.method == "HEAD" && req.path == "/v1/AUTH_test/\0versions\0c" {
                    let mut resp = Response::new(204);
                    resp.headers.set("X-Container-Bytes-Used", "32");
                    return resp;
                }
                panic!("unexpected {} {}", req.method, req.path);
            })
        });

        let vw = VersionedWrites::new().with_object_versioning(true);
        let mut request = req("HEAD", "/v1/AUTH_test/c");
        request.body = Body::empty();
        let resp = vw.reassemble_async(request, next).await;
        assert_eq!(resp.status, 204);
        assert_eq!(resp.headers.get("X-Container-Bytes-Used"), Some("45"));
        assert_eq!(resp.headers.get("X-Container-Object-Count"), Some("2"));
    }

    #[test]
    fn test_split_reserved_name_first_delimiter_prefix() {
        assert_eq!(split_reserved_name_first("\0del-"), Some("del-"));
        assert_eq!(split_reserved_name_first("\0test-"), Some("test-"));
        assert_eq!(
            split_reserved_name_first(&format!("\0test\0{}", "0000000001.00000")),
            Some("test"),
        );
        assert_eq!(split_reserved_name_first("del-"), None);
    }
}
