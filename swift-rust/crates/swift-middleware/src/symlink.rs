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

//! `symlink`: object symlinks, a port of the object half of
//! `swift/common/middleware/symlink.py`. A symlink is a zero-byte object
//! that stores a reference (`X-Symlink-Target: <container>/<object>`, plus
//! an optional `X-Symlink-Target-Account` for cross-account links) to a
//! target object.
//!
//! Ported behaviour (object requests):
//! * `PUT` with `X-Symlink-Target` -> validate the target, require a
//!   zero-byte body, move the client `X-Symlink-*` headers into the
//!   `X-Object-Sysmeta-Symlink-*` namespace, and stamp a
//!   container-update-override etag so the listing can flag the symlink.
//!   For a *static* symlink (`X-Symlink-Target-Etag`) a `HEAD`
//!   **subrequest** to the target verifies the etag and captures its size
//!   and content-type.
//! * `GET`/`HEAD` -> if the stored object is a symlink, follow
//!   `X-Object-Sysmeta-Symlink-Target` with a **subrequest** to the target
//!   (honouring `X-Object-Sysmeta-Symlink-Target-Account`), chaining
//!   through nested symlinks with loop detection (`symloop_max`, default 2;
//!   `X-Object-Sysmeta-Symloop-Extend` does not count against the limit),
//!   validating static-symlink etags, and stamping `Content-Location` with
//!   the resolved target. `?symlink=get` returns the symlink object itself
//!   (translating sysmeta back to the client `X-Symlink-*` headers).
//! * `POST` -> reject `X-Symlink-Target` (a `PUT` is required), and turn a
//!   `POST` that lands on a symlink into a `307 Temporary Redirect` to the
//!   target.
//!
//! The subrequest pattern: the `next` handler may be called multiple times.
//! To make a backend subrequest the middleware clones the original request,
//! rewrites method/path/headers, calls `next(subreq)`, inspects the
//! response, and (for `GET`/`HEAD`) either follows again or returns.
//!
//! Deferrals:
//! * `SymlinkContainerContext` / `_process_json_resp`: the container-listing
//!   JSON augmentation (`symlink_path`, `symlink_etag`, `symlink_bytes`,
//!   `slo_etag`) is not ported; container requests pass straight through.
//! * SLO/DLO etag leakage in `_validate_etag_and_update_sysmeta` (the
//!   `Container-Update-Override-Etag` `slo_etag` propagation and the
//!   `X-Object-Sysmeta-Slo-Etag` handling) is only partially ported: the
//!   target size falls back from `X-Object-Sysmeta-Slo-Size` to
//!   `Content-Length`, but the override-etag rewrite for SLO manifests is
//!   deferred.
//! * Reserved-name traversal follows Python's capability hand-off: only a
//!   symlink object carrying `X-Object-Sysmeta-Allow-Reserved-Names` may
//!   create a pre-authorized subrequest with
//!   `X-Backend-Allow-Reserved-Names`. The `swift.leave_relative_location`
//!   POST flag is not modelled.
//! * `X-Symlink-Target` is `wsgi_unquote`d then `wsgi_quote`d (safe `/`) so
//!   percent-encoded slashes in the object name normalize like Python.
//! * `filter_factory`, `register_swift_info`, and the logger are not ported
//!   (matching `gatekeeper`/`read_only`). The `status_map[...]` error body
//!   for a non-success static-symlink target is simplified to the bare
//!   status.

use swift_core::config::config_true_value;
use swift_core::constraints::check_account_format;

use std::future::Future;
use std::pin::Pin;

use swift_http::{
    body_too_large, normalize_etag, split_path, Body, HeaderKeyDict, Request, Response,
    MAX_CONTROL_BODY,
};

use crate::{AsyncNextFn, Middleware, MwPrep, NextFn};

const DEFAULT_SYMLOOP_MAX: usize = 2;

// Client-facing symlink headers (values are quoted target strings).
const TGT_OBJ_SYMLINK_HDR: &str = "X-Symlink-Target";
const TGT_ACCT_SYMLINK_HDR: &str = "X-Symlink-Target-Account";
const TGT_ETAG_SYMLINK_HDR: &str = "X-Symlink-Target-Etag";
const TGT_BYTES_SYMLINK_HDR: &str = "X-Symlink-Target-Bytes";

// Cluster-facing sysmeta headers (`get_sys_meta_prefix('object')` + name).
const TGT_OBJ_SYSMETA_SYMLINK_HDR: &str = "X-Object-Sysmeta-Symlink-Target";
const TGT_ACCT_SYSMETA_SYMLINK_HDR: &str = "X-Object-Sysmeta-Symlink-Target-Account";
const TGT_ETAG_SYSMETA_SYMLINK_HDR: &str = "X-Object-Sysmeta-Symlink-Target-Etag";
const TGT_BYTES_SYSMETA_SYMLINK_HDR: &str = "X-Object-Sysmeta-Symlink-Target-Bytes";
const SYMLOOP_EXTEND: &str = "X-Object-Sysmeta-Symloop-Extend";
const ALLOW_RESERVED_NAMES: &str = "X-Object-Sysmeta-Allow-Reserved-Names";

const CONTAINER_UPDATE_OVERRIDE_ETAG: &str = "X-Object-Sysmeta-Container-Update-Override-Etag";
const IGNORE_RANGE_HDR: &str = "X-Backend-Ignore-Range-If-Metadata-Present";
const MD5_OF_EMPTY_STRING: &str = "d41d8cd98f00b204e9800998ecf8427e";
const SYSMETA_SLO_ETAG: &str = "X-Object-Sysmeta-Slo-Etag";

/// Python `_validate_etag_and_update_sysmeta`: carry SLO listing etag onto
/// the zero-byte symlink so container listings expose `slo_etag`.
fn carry_slo_listing_etag(req: &mut Request, resp: &Response) {
    if req.headers.contains_key(CONTAINER_UPDATE_OVERRIDE_ETAG) {
        return;
    }
    if let Some(slo_etag) = resp
        .headers
        .get(SYSMETA_SLO_ETAG)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
    {
        req.headers.set(
            CONTAINER_UPDATE_OVERRIDE_ETAG,
            format!("{MD5_OF_EMPTY_STRING}; slo_etag={slo_etag}"),
        );
        return;
    }
    if let Some(ov) = resp.headers.get(CONTAINER_UPDATE_OVERRIDE_ETAG) {
        if let Some((_, params)) = ov.split_once(';') {
            if !params.trim().is_empty() {
                req.headers.set(
                    CONTAINER_UPDATE_OVERRIDE_ETAG,
                    format!("{MD5_OF_EMPTY_STRING};{params}"),
                );
            }
        }
    }
}

fn copy_target_content_type(req: &mut Request, resp: &Response) {
    let has_ct = req
        .headers
        .get("Content-Type")
        .map(|s| !s.is_empty())
        .unwrap_or(false);
    if has_ct {
        return;
    }
    let Some(ct) = resp.headers.get("Content-Type") else {
        return;
    };
    let cleaned = ct
        .split(';')
        .map(str::trim)
        .filter(|p| !p.is_empty() && !p.starts_with("swift_bytes="))
        .collect::<Vec<_>>()
        .join(";");
    if !cleaned.is_empty() {
        req.headers.set("Content-Type", cleaned);
    }
}

/// True for 2xx status codes (`swift.common.http.is_success`).
fn is_success(status: u16) -> bool {
    (200..300).contains(&status)
}

/// `swift.common.utils.csv_append`: append `item` to a comma-separated
/// list, or return `item` if the list is empty/absent.
fn csv_append(existing: Option<&str>, item: &str) -> String {
    match existing {
        Some(s) if !s.is_empty() => format!("{s},{item}"),
        _ => item.to_string(),
    }
}

/// `request_helpers.update_ignore_range_header`: record that the presence
/// of `name` on the object means the proxy wants the whole object.
fn update_ignore_range_header(headers: &mut HeaderKeyDict, name: &str) {
    let val = csv_append(headers.get(IGNORE_RANGE_HDR), name);
    headers.set(IGNORE_RANGE_HDR, val);
}

/// Python `swob.wsgi_unquote` / `urllib.parse.unquote(..., encoding='latin-1')`.
/// Invalid `%` sequences are left intact.
fn wsgi_unquote(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(hex) = std::str::from_utf8(&bytes[i + 1..i + 3]) {
                if let Ok(value) = u8::from_str_radix(hex, 16) {
                    out.push(value);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Python `swob.wsgi_quote` with default `safe='/'`.
fn wsgi_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'/' | b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            b => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// `symlink_usermeta_to_sysmeta`: move the client `X-Symlink-Target[-Account]`
/// headers into the `X-Object-Sysmeta-Symlink-*` namespace.
fn symlink_usermeta_to_sysmeta(headers: &mut HeaderKeyDict) {
    for (user, sysmeta) in [
        (TGT_OBJ_SYMLINK_HDR, TGT_OBJ_SYSMETA_SYMLINK_HDR),
        (TGT_ACCT_SYMLINK_HDR, TGT_ACCT_SYSMETA_SYMLINK_HDR),
    ] {
        if let Some(v) = headers.remove(user) {
            headers.set(sysmeta, v);
        }
    }
}

/// `symlink_sysmeta_to_usermeta`: the inverse, used on `?symlink=get`
/// responses so the client sees `X-Symlink-*` headers.
fn symlink_sysmeta_to_usermeta(headers: &mut HeaderKeyDict) {
    for (user, sysmeta) in [
        (TGT_OBJ_SYMLINK_HDR, TGT_OBJ_SYSMETA_SYMLINK_HDR),
        (TGT_ACCT_SYMLINK_HDR, TGT_ACCT_SYSMETA_SYMLINK_HDR),
        (TGT_ETAG_SYMLINK_HDR, TGT_ETAG_SYSMETA_SYMLINK_HDR),
        (TGT_BYTES_SYMLINK_HDR, TGT_BYTES_SYSMETA_SYMLINK_HDR),
    ] {
        if let Some(v) = headers.remove(sysmeta) {
            headers.set(user, v);
        }
    }
}

/// `HTTPException(body=..., content_type='text/plain')` shape.
fn err_text(status: u16, body: impl Into<Body>) -> Response {
    let mut resp = Response::with_body(status, body);
    resp.headers.set("Content-Type", "text/plain");
    resp
}

/// `HTTPException(body=...)` with swob's default content-type (a check that
/// omits `content_type`, e.g. `check_path_header`/`check_account_format`).
fn err_html(status: u16, body: impl Into<Body>) -> Response {
    let mut resp = Response::with_body(status, body);
    resp.headers.set("Content-Type", "text/html; charset=UTF-8");
    resp
}

/// `HTTPConflict(body=..., headers={'Content-Type':'text/plain',
/// 'Content-Location': ...})`.
fn conflict(body: impl Into<Body>, location: Option<&str>) -> Response {
    let mut resp = err_text(409, body);
    if let Some(loc) = location {
        resp.headers.set("Content-Location", loc);
    }
    resp
}

/// Middleware implementing object symlinks.
pub struct Symlink {
    /// Maximum number of chained symlinks to traverse (`symloop_max`).
    pub symloop_max: usize,
}

impl Default for Symlink {
    fn default() -> Self {
        Symlink {
            symloop_max: DEFAULT_SYMLOOP_MAX,
        }
    }
}

impl Symlink {
    pub fn new(symloop_max: usize) -> Self {
        Symlink { symloop_max }
    }

    /// Build from raw config, mirroring `filter_factory`: parse
    /// `symloop_max` as an int (default 2 on absence or a parse failure),
    /// and clamp any value below 1 up to the default.
    /// Fail closed on malformed `symloop_max` (non-integer).
    pub fn try_from_conf(symloop_max: Option<&str>) -> Result<Self, String> {
        match symloop_max {
            None => Ok(Self::from_conf(None)),
            Some(raw) => {
                let trimmed = raw.trim();
                if trimmed.is_empty() {
                    return Ok(Self::from_conf(None));
                }
                let parsed: i64 = trimmed.parse().map_err(|_| {
                    format!("invalid symlink symloop_max {raw:?}: expected an integer")
                })?;
                Ok(Self::from_conf(Some(&parsed.to_string())))
            }
        }
    }

    pub fn from_conf(symloop_max: Option<&str>) -> Self {
        let parsed = symloop_max
            .and_then(|s| s.trim().parse::<i64>().ok())
            .unwrap_or(DEFAULT_SYMLOOP_MAX as i64);
        let clamped = if parsed < 1 {
            DEFAULT_SYMLOOP_MAX as i64
        } else {
            parsed
        };
        Symlink {
            symloop_max: clamped as usize,
        }
    }

    fn handle_object(&self, req: Request, next: &NextFn) -> Response {
        if req.method == "GET" || req.method == "HEAD" {
            if req.param("symlink").as_deref() == Some("get") {
                self.handle_get_head_symlink(req, next)
            } else {
                self.handle_get_head(req, next)
            }
        } else if req.method == "PUT" && req.headers.contains_key(TGT_OBJ_SYMLINK_HDR) {
            self.handle_put(req, next)
        } else if req.method == "POST" {
            self.handle_post(req, next)
        } else {
            // DELETE, OPTIONS, and PUT without X-Symlink-Target behave like
            // any other object.
            next(req)
        }
    }

    /// `?symlink=get`: return the symlink object itself, translating its
    /// sysmeta back to the client `X-Symlink-*` headers.
    fn handle_get_head_symlink(&self, req: Request, next: &NextFn) -> Response {
        let mut resp = next(req);
        symlink_sysmeta_to_usermeta(&mut resp.headers);
        resp
    }

    /// `GET`/`HEAD`: follow the symlink chain to the target object.
    fn handle_get_head(&self, mut req: Request, next: &NextFn) -> Response {
        update_ignore_range_header(&mut req.headers, TGT_OBJ_SYSMETA_SYMLINK_HDR);
        let orig_req = req.clone_head();
        match self.recursive_get_head(&orig_req, req, next, None, true, None) {
            Ok((mut resp, last_target_path)) => {
                // Content-Location is applied only when at least one symlink
                // recursion occurred, showing the resolved target path.
                if let Some(loc) = last_target_path {
                    resp.headers.set("Content-Location", loc);
                }
                resp
            }
            Err(resp) => resp,
        }
    }

    /// Port of `_recursive_get_head`, unrolled into a loop (the framework's
    /// `handle` takes `&self`, so chain state lives in locals rather than
    /// instance fields).
    ///
    /// On success returns the final (non-symlink) response together with the
    /// last resolved target path (if any traversal happened). On an etag
    /// mismatch or loop-limit breach returns the error response to send.
    fn recursive_get_head(
        &self,
        orig_req: &Request,
        start_req: Request,
        next: &NextFn,
        mut target_etag: Option<String>,
        follow_softlinks: bool,
        mut last_target_path: Option<String>,
    ) -> Result<(Response, Option<String>), Response> {
        let mut cur = start_req;
        let mut loop_count: usize = 0;
        loop {
            let resp = next(cur.clone_head());
            let symlink_target = resp
                .headers
                .get(TGT_OBJ_SYSMETA_SYMLINK_HDR)
                .map(str::to_string);
            let resp_etag = resp
                .headers
                .get(TGT_ETAG_SYSMETA_SYMLINK_HDR)
                .map(str::to_string);

            // A static symlink (has resp_etag) is always followed; a dynamic
            // symlink is followed only when follow_softlinks is set.
            let is_symlink = symlink_target.is_some() && (resp_etag.is_some() || follow_softlinks);
            if is_symlink {
                let symlink_target = symlink_target.expect("checked is_some");
                let found_etag = resp_etag
                    .clone()
                    .or_else(|| resp.headers.get("etag").map(str::to_string));
                if let Some(te) = target_etag.as_deref() {
                    if Some(te) != found_etag.as_deref() {
                        return Err(conflict(
                            "X-Symlink-Target-Etag headers do not match",
                            last_target_path.as_deref(),
                        ));
                    }
                }
                if loop_count >= self.symloop_max {
                    return Err(err_text(
                        409,
                        format!(
                            "Too many levels of symbolic links, maximum allowed is {}",
                            self.symloop_max
                        ),
                    ));
                }
                let (new_req, quoted_path) =
                    build_traversal_req(&cur, &resp, &symlink_target, orig_req);
                last_target_path = Some(quoted_path);
                // An extended symloop (e.g. from versioned_writes) is not
                // counted against the limit.
                if !config_true_value(resp.headers.get(SYMLOOP_EXTEND).unwrap_or("")) {
                    loop_count += 1;
                }
                target_etag = resp_etag;
                cur = new_req;
                continue;
            }

            // Not a symlink to follow: this is the terminal response.
            let final_etag = resp.headers.get("etag").map(str::to_string);
            if let (Some(fe), Some(te)) = (final_etag.as_deref(), target_etag.as_deref()) {
                if fe != te {
                    return Err(conflict(
                        format!(
                            "Object Etag '{fe}' does not match X-Symlink-Target-Etag header '{te}'"
                        ),
                        last_target_path.as_deref(),
                    ));
                }
            }
            return Ok((resp, last_target_path));
        }
    }

    /// `PUT` with `X-Symlink-Target`: validate and store a zero-byte symlink.
    fn handle_put(&self, mut req: Request, next: &NextFn) -> Response {
        // Symlinks must be zero-byte objects. Python reads the body when no
        // Content-Length was declared (chunked upload); a body over the
        // control cap is certainly non-empty.
        let has_body = match req
            .headers
            .get("Content-Length")
            .map(|s| s.trim().parse::<i64>())
        {
            Some(Ok(cl)) => cl != 0,
            _ => match req.body.materialize(MAX_CONTROL_BODY) {
                Ok(bytes) => !bytes.is_empty(),
                Err(e) if body_too_large(&e) => true,
                Err(_) => return err_text(499, "Client Disconnect"),
            },
        };
        if has_body {
            return err_text(400, "Symlink requests require a zero byte body");
        }

        let (symlink_target_path, etag) = match validate_and_prep_request_headers(&mut req) {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        if let Some(etag) = &etag {
            if let Some(resp) =
                self.validate_etag_and_update_sysmeta(&mut req, &symlink_target_path, etag, next)
            {
                return resp;
            }
        }
        symlink_usermeta_to_sysmeta(&mut req.headers);

        // Store the symlink info in the container-update override etag so it
        // survives in object listings (a symlink is always 0 bytes, so the
        // md5 of the empty string is a safe base when no override was set).
        let mut etag_override = vec![
            req.headers
                .get(CONTAINER_UPDATE_OVERRIDE_ETAG)
                .map(str::to_string)
                .unwrap_or_else(|| MD5_OF_EMPTY_STRING.to_string()),
            format!(
                "symlink_target={}",
                req.headers.get(TGT_OBJ_SYSMETA_SYMLINK_HDR).unwrap_or("")
            ),
        ];
        if let Some(acct) = req
            .headers
            .get(TGT_ACCT_SYSMETA_SYMLINK_HDR)
            .map(str::to_string)
        {
            etag_override.push(format!("symlink_target_account={acct}"));
        }
        if let Some(tgt_etag) = req
            .headers
            .get(TGT_ETAG_SYSMETA_SYMLINK_HDR)
            .map(str::to_string)
        {
            // Whoever set the target etag sysmeta must also set the bytes
            // sysmeta; treat a missing value as empty.
            let tgt_bytes = req
                .headers
                .get(TGT_BYTES_SYSMETA_SYMLINK_HDR)
                .unwrap_or("")
                .to_string();
            etag_override.push(format!("symlink_target_etag={tgt_etag}"));
            etag_override.push(format!("symlink_target_bytes={tgt_bytes}"));
        }
        req.headers
            .set(CONTAINER_UPDATE_OVERRIDE_ETAG, etag_override.join("; "));

        next(req)
    }

    /// `_validate_etag_and_update_sysmeta`: for a static symlink, HEAD the
    /// target (a subrequest) to confirm it exists and its etag matches, then
    /// capture the target's size and content-type into sysmeta. Returns an
    /// error response on failure, or `None` on success (req is mutated).
    fn validate_etag_and_update_sysmeta(
        &self,
        req: &mut Request,
        symlink_target_path: &str,
        etag: &str,
        next: &NextFn,
    ) -> Option<Response> {
        if config_true_value(req.headers.get("X-Backend-Symlink-Override").unwrap_or("")) {
            let bytes = req
                .headers
                .get(TGT_BYTES_SYMLINK_HDR)
                .unwrap_or("")
                .to_string();
            req.headers.set(TGT_ETAG_SYSMETA_SYMLINK_HDR, etag);
            req.headers.set(TGT_BYTES_SYSMETA_SYMLINK_HDR, bytes);
            return None;
        }
        let orig_req = req.clone_head();
        let mut subreq = req.clone_head();
        subreq.method = "HEAD".to_string();
        subreq.path = symlink_target_path.to_string();
        subreq.query_string = String::new();

        let (resp, last_target_path) = match self.recursive_get_head(
            &orig_req,
            subreq,
            next,
            Some(etag.to_string()),
            false,
            Some(symlink_target_path.to_string()),
        ) {
            Ok(v) => v,
            Err(resp) => return Some(resp),
        };

        if resp.status == 404 {
            return Some(conflict(
                "X-Symlink-Target does not exist",
                last_target_path.as_deref(),
            ));
        }
        if !is_success(resp.status) {
            // status_map[status](request=req): propagate the status (body
            // simplified).
            return Some(Response::new(resp.status));
        }

        let bytes = resp
            .headers
            .get("X-Object-Sysmeta-Slo-Size")
            .or_else(|| resp.headers.get("Content-Length"))
            .unwrap_or("0")
            .to_string();
        req.headers.set(TGT_BYTES_SYSMETA_SYMLINK_HDR, bytes);
        req.headers.set(TGT_ETAG_SYSMETA_SYMLINK_HDR, etag);
        carry_slo_listing_etag(req, &resp);
        copy_target_content_type(req, &resp);
        None
    }

    /// `POST`: reject `X-Symlink-Target`, and redirect a POST that lands on a
    /// symlink to the target with `307 Temporary Redirect`.
    fn handle_post(&self, req: Request, next: &NextFn) -> Response {
        if req.headers.contains_key(TGT_OBJ_SYMLINK_HDR) {
            return err_text(400, "A PUT request is required to set a symlink target");
        }

        let head = req.clone_head();
        let resp = next(req);
        if !is_success(resp.status) {
            return resp;
        }
        let req = head;

        let tgt_co = match resp.headers.get(TGT_OBJ_SYSMETA_SYMLINK_HDR) {
            Some(v) => v.to_string(),
            None => return resp,
        };

        let parts = split_path(&req.path, 2, 3, true).unwrap_or_default();
        let version = parts.first().and_then(|o| o.clone()).unwrap_or_default();
        let account = parts.get(1).and_then(|o| o.clone()).unwrap_or_default();
        let target_acc = resp
            .headers
            .get(TGT_ACCT_SYSMETA_SYMLINK_HDR)
            .map(str::to_string)
            .unwrap_or(account);
        let location = format!("/{version}/{target_acc}/{tgt_co}");

        let errmsg = "The requested POST was applied to a symlink. POST \
                      directly to the target to apply requested metadata.";
        // Default swob content-type (text/html) is kept; add Location and
        // carry forward the symlink target sysmeta.
        let mut redirect = err_html(307, errmsg);
        redirect.headers.set("Location", location);
        if let Some(tgt_etag) = resp.headers.get(TGT_ETAG_SYSMETA_SYMLINK_HDR) {
            redirect.headers.set(TGT_ETAG_SYMLINK_HDR, tgt_etag);
        }
        for (key, value) in resp.headers.iter() {
            if key.to_lowercase().starts_with("x-object-sysmeta-") {
                redirect.headers.set(key, value);
            }
        }
        redirect
    }

    fn is_object_path(req: &Request) -> bool {
        matches!(split_path(&req.path, 4, 4, true), Ok(p) if p.get(3).and_then(|o| o.as_deref()).is_some_and(|o| !o.is_empty()))
    }

    async fn handle_object_async(&self, req: Request, next: AsyncNextFn) -> Response {
        if req.method == "GET" || req.method == "HEAD" {
            if req.param("symlink").as_deref() == Some("get") {
                let mut resp = next(req).await;
                symlink_sysmeta_to_usermeta(&mut resp.headers);
                resp
            } else {
                self.handle_get_head_async(req, next).await
            }
        } else if req.method == "PUT" && req.headers.contains_key(TGT_OBJ_SYMLINK_HDR) {
            self.handle_put_async(req, next).await
        } else if req.method == "POST" {
            self.handle_post_async(req, next).await
        } else {
            next(req).await
        }
    }

    async fn handle_get_head_async(&self, mut req: Request, next: AsyncNextFn) -> Response {
        update_ignore_range_header(&mut req.headers, TGT_OBJ_SYSMETA_SYMLINK_HDR);
        let orig_req = req.clone_head();
        match self
            .recursive_get_head_async(orig_req, req, next, None, true, None)
            .await
        {
            Ok((mut resp, last_target_path)) => {
                if let Some(loc) = last_target_path {
                    resp.headers.set("Content-Location", loc);
                }
                resp
            }
            Err(resp) => resp,
        }
    }

    async fn recursive_get_head_async(
        &self,
        orig_req: Request,
        start_req: Request,
        next: AsyncNextFn,
        mut target_etag: Option<String>,
        follow_softlinks: bool,
        mut last_target_path: Option<String>,
    ) -> Result<(Response, Option<String>), Response> {
        let mut cur = start_req;
        let mut loop_count: usize = 0;
        loop {
            let resp = next(cur.clone_head()).await;
            let symlink_target = resp
                .headers
                .get(TGT_OBJ_SYSMETA_SYMLINK_HDR)
                .map(str::to_string);
            let resp_etag = resp
                .headers
                .get(TGT_ETAG_SYSMETA_SYMLINK_HDR)
                .map(str::to_string);
            let is_symlink = symlink_target.is_some() && (resp_etag.is_some() || follow_softlinks);
            if is_symlink {
                let symlink_target = symlink_target.expect("checked is_some");
                let found_etag = resp_etag
                    .clone()
                    .or_else(|| resp.headers.get("etag").map(str::to_string));
                if let Some(te) = target_etag.as_deref() {
                    if Some(te) != found_etag.as_deref() {
                        return Err(conflict(
                            "X-Symlink-Target-Etag headers do not match",
                            last_target_path.as_deref(),
                        ));
                    }
                }
                if loop_count >= self.symloop_max {
                    return Err(err_text(
                        409,
                        format!(
                            "Too many levels of symbolic links, maximum allowed is {}",
                            self.symloop_max
                        ),
                    ));
                }
                let (new_req, quoted_path) =
                    build_traversal_req(&cur, &resp, &symlink_target, &orig_req);
                last_target_path = Some(quoted_path);
                if !config_true_value(resp.headers.get(SYMLOOP_EXTEND).unwrap_or("")) {
                    loop_count += 1;
                }
                target_etag = resp_etag;
                cur = new_req;
                continue;
            }
            let final_etag = resp.headers.get("etag").map(str::to_string);
            if let (Some(fe), Some(te)) = (final_etag.as_deref(), target_etag.as_deref()) {
                if fe != te {
                    return Err(conflict(
                        format!(
                            "Object Etag '{fe}' does not match X-Symlink-Target-Etag header '{te}'"
                        ),
                        last_target_path.as_deref(),
                    ));
                }
            }
            return Ok((resp, last_target_path));
        }
    }

    async fn handle_put_async(&self, mut req: Request, next: AsyncNextFn) -> Response {
        let has_body = match req
            .headers
            .get("Content-Length")
            .map(|s| s.trim().parse::<i64>())
        {
            Some(Ok(cl)) => cl != 0,
            _ => match req.body.materialize(MAX_CONTROL_BODY) {
                Ok(bytes) => !bytes.is_empty(),
                Err(e) if body_too_large(&e) => true,
                Err(_) => return err_text(499, "Client Disconnect"),
            },
        };
        if has_body {
            return err_text(400, "Symlink requests require a zero byte body");
        }

        let (symlink_target_path, etag) = match validate_and_prep_request_headers(&mut req) {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        if let Some(etag) = &etag {
            if let Some(resp) = self
                .validate_etag_and_update_sysmeta_async(
                    &mut req,
                    &symlink_target_path,
                    etag,
                    next.clone(),
                )
                .await
            {
                return resp;
            }
        }
        symlink_usermeta_to_sysmeta(&mut req.headers);

        let mut etag_override = vec![
            req.headers
                .get(CONTAINER_UPDATE_OVERRIDE_ETAG)
                .map(str::to_string)
                .unwrap_or_else(|| MD5_OF_EMPTY_STRING.to_string()),
            format!(
                "symlink_target={}",
                req.headers.get(TGT_OBJ_SYSMETA_SYMLINK_HDR).unwrap_or("")
            ),
        ];
        if let Some(acct) = req
            .headers
            .get(TGT_ACCT_SYSMETA_SYMLINK_HDR)
            .map(str::to_string)
        {
            etag_override.push(format!("symlink_target_account={acct}"));
        }
        if let Some(tgt_etag) = req
            .headers
            .get(TGT_ETAG_SYSMETA_SYMLINK_HDR)
            .map(str::to_string)
        {
            let tgt_bytes = req
                .headers
                .get(TGT_BYTES_SYSMETA_SYMLINK_HDR)
                .unwrap_or("")
                .to_string();
            etag_override.push(format!("symlink_target_etag={tgt_etag}"));
            etag_override.push(format!("symlink_target_bytes={tgt_bytes}"));
        }
        req.headers
            .set(CONTAINER_UPDATE_OVERRIDE_ETAG, etag_override.join("; "));
        next(req).await
    }

    async fn validate_etag_and_update_sysmeta_async(
        &self,
        req: &mut Request,
        symlink_target_path: &str,
        etag: &str,
        next: AsyncNextFn,
    ) -> Option<Response> {
        if config_true_value(req.headers.get("X-Backend-Symlink-Override").unwrap_or("")) {
            let bytes = req
                .headers
                .get(TGT_BYTES_SYMLINK_HDR)
                .unwrap_or("")
                .to_string();
            req.headers.set(TGT_ETAG_SYSMETA_SYMLINK_HDR, etag);
            req.headers.set(TGT_BYTES_SYSMETA_SYMLINK_HDR, bytes);
            return None;
        }
        let orig_req = req.clone_head();
        let mut subreq = req.clone_head();
        subreq.method = "HEAD".to_string();
        subreq.path = symlink_target_path.to_string();
        subreq.query_string = String::new();

        let (resp, last_target_path) = match self
            .recursive_get_head_async(
                orig_req,
                subreq,
                next,
                Some(etag.to_string()),
                false,
                Some(symlink_target_path.to_string()),
            )
            .await
        {
            Ok(v) => v,
            Err(resp) => return Some(resp),
        };

        if resp.status == 404 {
            return Some(conflict(
                "X-Symlink-Target does not exist",
                last_target_path.as_deref(),
            ));
        }
        if !is_success(resp.status) {
            return Some(Response::new(resp.status));
        }

        let bytes = resp
            .headers
            .get("X-Object-Sysmeta-Slo-Size")
            .or_else(|| resp.headers.get("Content-Length"))
            .unwrap_or("0")
            .to_string();
        req.headers.set(TGT_BYTES_SYSMETA_SYMLINK_HDR, bytes);
        req.headers.set(TGT_ETAG_SYSMETA_SYMLINK_HDR, etag);
        carry_slo_listing_etag(req, &resp);
        copy_target_content_type(req, &resp);
        None
    }

    async fn handle_post_async(&self, req: Request, next: AsyncNextFn) -> Response {
        if req.headers.contains_key(TGT_OBJ_SYMLINK_HDR) {
            return err_text(400, "A PUT request is required to set a symlink target");
        }
        let head = req.clone_head();
        let resp = next(req).await;
        if !is_success(resp.status) {
            return resp;
        }
        let req = head;
        let tgt_co = match resp.headers.get(TGT_OBJ_SYSMETA_SYMLINK_HDR) {
            Some(v) => v.to_string(),
            None => return resp,
        };
        let parts = split_path(&req.path, 2, 3, true).unwrap_or_default();
        let version = parts.first().and_then(|o| o.clone()).unwrap_or_default();
        let account = parts.get(1).and_then(|o| o.clone()).unwrap_or_default();
        let target_acc = resp
            .headers
            .get(TGT_ACCT_SYSMETA_SYMLINK_HDR)
            .map(str::to_string)
            .unwrap_or(account);
        let location = format!("/{version}/{target_acc}/{tgt_co}");
        let errmsg = "The requested POST was applied to a symlink. POST \
                      directly to the target to apply requested metadata.";
        let mut redirect = err_html(307, errmsg);
        redirect.headers.set("Location", location);
        if let Some(tgt_etag) = resp.headers.get(TGT_ETAG_SYSMETA_SYMLINK_HDR) {
            redirect.headers.set(TGT_ETAG_SYMLINK_HDR, tgt_etag);
        }
        for (key, value) in resp.headers.iter() {
            if key.to_lowercase().starts_with("x-object-sysmeta-") {
                redirect.headers.set(key, value);
            }
        }
        redirect
    }
}

impl Middleware for Symlink {
    fn prepare(&self, req: &mut Request) -> MwPrep {
        if matches!(req.method.as_str(), "GET" | "HEAD")
            && Self::is_object_path(req)
            && req.param("symlink").as_deref() != Some("get")
        {
            update_ignore_range_header(&mut req.headers, TGT_OBJ_SYSMETA_SYMLINK_HDR);
        }
        MwPrep::Continue
    }

    fn handle(&self, req: Request, next: &NextFn) -> Response {
        // Only container and object requests (3 or 4 path segments) are
        // handled; anything else passes through.
        let parts = match split_path(&req.path, 3, 4, true) {
            Ok(parts) => parts,
            Err(_) => return next(req),
        };
        let obj = parts.get(3).and_then(|o| o.clone());
        match obj {
            Some(o) if !o.is_empty() => self.handle_object(req, next),
            _ => {
                if req.method == "GET" {
                    let orig = req.clone_head();
                    process_container_listing_sync(&orig, next(req))
                } else {
                    next(req)
                }
            }
        }
    }

    fn intercepts_request(&self, req: &Request) -> bool {
        Self::is_object_path(req)
            && ((req.method == "PUT" && req.headers.contains_key(TGT_OBJ_SYMLINK_HDR))
                || req.method == "POST")
    }

    fn intercepts_response(&self) -> bool {
        true
    }

    fn handle_request_async(
        &self,
        req: Request,
        next: AsyncNextFn,
    ) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        Box::pin(async move { self.handle_object_async(req, next).await })
    }

    fn reassemble_async(
        &self,
        req: Request,
        next: AsyncNextFn,
    ) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        Box::pin(async move {
            if req.method == "GET" && is_container_listing_path(&req) {
                let (version, account) = listing_version_account(&req);
                let resp = next(req).await;
                return process_container_listing_async(version, account, resp).await;
            }
            if req.method == "GET" || req.method == "HEAD" {
                if !Self::is_object_path(&req) {
                    return next(req).await;
                }
                self.handle_object_async(req, next).await
            } else {
                next(req).await
            }
        })
    }
}

fn is_container_listing_path(req: &Request) -> bool {
    match split_path(&req.path, 3, 4, true) {
        Ok(parts) => {
            parts
                .get(2)
                .and_then(|c| c.as_deref())
                .is_some_and(|c| !c.is_empty())
                && parts
                    .get(3)
                    .and_then(|o| o.as_deref())
                    .is_none_or(str::is_empty)
        }
        Err(_) => false,
    }
}

/// Python `utils.parse_header` for a container-listing `hash` field:
/// `etag; symlink_target=c/o; symlink_target_bytes=N`.
fn parse_etag_params(raw: &str) -> (String, Vec<(String, String)>) {
    let mut parts = raw.split(';');
    let etag = parts.next().unwrap_or("").trim().to_string();
    let mut params = Vec::new();
    for part in parts {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((k, v)) = part.split_once('=') {
            params.push((k.trim().to_string(), v.trim().to_string()));
        } else {
            params.push((part.to_string(), String::new()));
        }
    }
    (etag, params)
}

/// `SymlinkContainerContext._extract_symlink_path_json`.
fn extract_symlink_path_json(obj: &mut serde_json::Value, version: &str, account: &str) {
    let Some(map) = obj.as_object_mut() else {
        return;
    };
    let Some(hash) = map.get("hash").and_then(|v| v.as_str()).map(str::to_string) else {
        return;
    };
    let (etag, params) = parse_etag_params(&hash);
    map.insert("hash".into(), serde_json::Value::String(etag));
    let mut account = account.to_string();
    let mut target: Option<String> = None;
    for (key, value) in params {
        match key.as_str() {
            "symlink_target" => target = Some(value),
            "symlink_target_account" => account = value,
            "symlink_target_etag" => {
                map.insert("symlink_etag".into(), serde_json::Value::String(value));
            }
            "symlink_target_bytes" => {
                if let Ok(n) = value.parse::<i64>() {
                    map.insert("symlink_bytes".into(), serde_json::Value::Number(n.into()));
                }
            }
            _ => {
                let current = map
                    .get("hash")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                map.insert(
                    "hash".into(),
                    serde_json::Value::String(format!("{current}; {key}={value}")),
                );
            }
        }
    }
    if let Some(target) = target {
        map.insert(
            "symlink_path".into(),
            serde_json::Value::String(format!("/{version}/{account}/{target}")),
        );
    }
}

fn rewrite_listing_json(body: &[u8], version: &str, account: &str) -> Option<Vec<u8>> {
    let mut items: Vec<serde_json::Value> = serde_json::from_slice(body).ok()?;
    for item in &mut items {
        extract_symlink_path_json(item, version, account);
    }
    serde_json::to_vec(&items).ok()
}

fn listing_version_account(req: &Request) -> (String, String) {
    let parts = split_path(&req.path, 2, 3, true).unwrap_or_default();
    let version = parts.first().and_then(|o| o.clone()).unwrap_or_default();
    let account = parts.get(1).and_then(|o| o.clone()).unwrap_or_default();
    (version, account)
}

fn apply_listing_rewrite(
    version: &str,
    account: &str,
    mut resp: Response,
    body: Vec<u8>,
) -> Response {
    // Ordinary listings must not be re-serialized. Only rewrite when the
    // container-update override etag actually carries symlink params.
    let has_symlink = std::str::from_utf8(&body)
        .map(|s| s.contains("symlink_target"))
        .unwrap_or(false);
    if !has_symlink {
        resp.body = Body::Buffered(body);
        return resp;
    }
    match rewrite_listing_json(&body, version, account) {
        Some(new_body) => {
            resp.headers
                .set("Content-Length", new_body.len().to_string());
            resp.body = Body::Buffered(new_body);
            resp
        }
        None => {
            resp.body = Body::Buffered(body);
            resp
        }
    }
}

fn process_container_listing_sync(req: &Request, mut resp: Response) -> Response {
    if req.method != "GET" || !(200..300).contains(&resp.status) {
        return resp;
    }
    let (version, account) = listing_version_account(req);
    let body = match resp.body.materialize(MAX_CONTROL_BODY) {
        Ok(b) => b.to_vec(),
        Err(_) => return resp,
    };
    apply_listing_rewrite(&version, &account, resp, body)
}

async fn process_container_listing_async(
    version: String,
    account: String,
    mut resp: Response,
) -> Response {
    if !(200..300).contains(&resp.status) {
        return resp;
    }
    let taken = std::mem::replace(&mut resp.body, Body::empty());
    let body = match taken.collect_async().await {
        Ok(b) => b,
        Err(_) => return resp,
    };
    apply_listing_rewrite(&version, &account, resp, body)
}

/// Build the subrequest that follows a symlink to its target, mirroring
/// `build_traversal_req` (`os.path.join('/', version, account, target)`).
/// The account comes from the symlink's target-account sysmeta when present,
/// otherwise the account of the current request path.
fn build_traversal_req(
    cur: &Request,
    resp: &Response,
    symlink_target: &str,
    orig_req: &Request,
) -> (Request, String) {
    let parts = split_path(&cur.path, 2, 3, true).unwrap_or_default();
    let version = parts.first().and_then(|o| o.clone()).unwrap_or_default();
    let account_from_path = parts.get(1).and_then(|o| o.clone()).unwrap_or_default();
    let account = resp
        .headers
        .get(TGT_ACCT_SYSMETA_SYMLINK_HDR)
        .map(str::to_string)
        .unwrap_or(account_from_path);
    let target = symlink_target.trim_start_matches('/');
    // Sysmeta is stored wsgi_quote'd (Content-Location keeps %20). Request.path
    // is already-decoded, so the follow hop must unquote or object lookup 404s.
    let quoted_path = format!("/{version}/{account}/{target}");
    let mut new_req = orig_req.clone_head();
    new_req.method = cur.method.clone();
    new_req.path = wsgi_unquote(&quoted_path);
    new_req.query_string = String::new();
    // Python `make_subrequest(orig_req.environ, ...)`. Copying `cur.headers`
    // leaks hop-1 `X-Backend-Authorize-Override` (reserved versions-symlink)
    // onto hop-2 user symlink (official test_container_acls line 404).
    new_req.headers = orig_req.headers.clone();
    new_req.headers.set("X-Backend-Source", "SYM");
    new_req.headers.remove("X-Backend-Authorize-Override");
    new_req.headers.remove("X-Backend-Allow-Reserved-Names");
    if resp
        .headers
        .get(ALLOW_RESERVED_NAMES)
        .is_some_and(|value| !value.is_empty())
    {
        // Python uses make_pre_authed_request for this hop. The stored
        // object sysmeta is the capability: ordinary/user-created symlinks
        // must never acquire reserved-name access merely from their target.
        new_req.headers.set("X-Backend-Authorize-Override", "true");
        new_req
            .headers
            .set("X-Backend-Allow-Reserved-Names", "true");
    }
    new_req.headers.remove("X-Backend-Storage-Policy-Index");
    (new_req, quoted_path)
}

/// Port of `_validate_and_prep_request_headers`. Validates the
/// `X-Symlink-Target` (and optional `X-Symlink-Target-Account`) headers,
/// normalises them on `req`, and returns the fully-qualified target path
/// plus the optional (normalised) target etag. On failure returns the error
/// response to send.
fn validate_and_prep_request_headers(
    req: &mut Request,
) -> Result<(String, Option<String>), Response> {
    const ERROR_BODY: &str =
        "X-Symlink-Target header must be of the form <container name>/<object name>";

    // Python: `wsgi_unquote` then `check_path_header` then `wsgi_quote` so
    // `dealde%2Fl04 011e%204c8df/flash.png` stores as
    // `dealde/l04%20011e%204c8df/flash.png` (TestSymlink encoded target).
    let raw_target = req
        .headers
        .get(TGT_OBJ_SYMLINK_HDR)
        .unwrap_or("")
        .to_string();
    let decoded_target = wsgi_unquote(&raw_target);
    if decoded_target.starts_with('/') {
        return Err(err_text(412, ERROR_BODY));
    }

    // check_path_header: prepend '/' if missing, then split into exactly two
    // segments (container/object, object may contain slashes).
    let hdr = format!("/{decoded_target}");
    let cont_obj = match split_path(&hdr, 2, 2, true) {
        Ok(parts) => parts,
        Err(_) => return Err(err_html(412, ERROR_BODY)),
    };
    let container = cont_obj.first().and_then(|o| o.clone()).unwrap_or_default();
    let obj = cont_obj.get(1).and_then(|o| o.clone()).unwrap_or_default();
    req.headers.set(
        TGT_OBJ_SYMLINK_HDR,
        wsgi_quote(&format!("{container}/{obj}")),
    );

    // Validate the target account format if the header is present.
    let target_account = match req.headers.get(TGT_ACCT_SYMLINK_HDR).map(str::to_string) {
        Some(acct) => match check_account_format(&wsgi_unquote(&acct)) {
            Ok(a) => Some(a.to_string()),
            // check_account_format raises HTTPPreconditionFailed (default
            // content-type).
            Err(e) => return Err(err_html(412, e.0)),
        },
        None => None,
    };

    // Extract the request's own account/container/object.
    let rp = split_path(&req.path, 4, 4, true).unwrap_or_default();
    let req_acc = rp.get(1).and_then(|o| o.clone()).unwrap_or_default();
    let req_cont = rp.get(2).and_then(|o| o.clone()).unwrap_or_default();
    let req_obj = rp.get(3).and_then(|o| o.clone()).unwrap_or_default();

    let account = match target_account {
        Some(a) => {
            req.headers.set(TGT_ACCT_SYMLINK_HDR, wsgi_quote(&a));
            a
        }
        None => req_acc.clone(),
    };

    // A symlink may not target itself.
    if (account.as_str(), container.as_str(), obj.as_str())
        == (req_acc.as_str(), req_cont.as_str(), req_obj.as_str())
    {
        return Err(err_text(400, "Symlink cannot target itself"));
    }

    let etag = req
        .headers
        .get(TGT_ETAG_SYMLINK_HDR)
        .map(|e| normalize_etag(e).to_string());
    if let Some(e) = &etag {
        if e.chars().any(|c| c == ';' || c == '"' || c == '\\') {
            return Err(err_text(400, "Bad X-Symlink-Target-Etag format"));
        }
    }

    let has_etag = etag.as_ref().map(|e| !e.is_empty()).unwrap_or(false);
    let has_ct = req
        .headers
        .get("Content-Type")
        .map(|s| !s.is_empty())
        .unwrap_or(false);
    if !has_etag && !has_ct {
        req.headers.set("Content-Type", "application/symlink");
    }

    Ok((
        format!("/v1/{account}/{container}/{obj}"),
        etag.filter(|e| !e.is_empty()),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    type BackendArc = Arc<dyn Fn(Request) -> Response + Send + Sync>;

    fn req(method: &str, path: &str, headers: &[(&str, &str)]) -> Request {
        let mut h = HeaderKeyDict::new();
        for (k, v) in headers {
            h.set(k, v);
        }
        Request {
            method: method.into(),
            path: path.into(),
            query_string: String::new(),
            headers: h,
            body: swift_http::Body::empty(),
        }
    }

    /// A backend keyed on (method, path); unmatched routes return 404.
    /// Canned responses are torn into Sync parts (a `Body` reader is only
    /// `Send`) and re-issued per request, so one route can serve many
    /// subrequests.
    #[allow(clippy::type_complexity)]
    fn backend(routes: Vec<(&'static str, &'static str, Response)>) -> BackendArc {
        let routes: Vec<(String, String, u16, HeaderKeyDict, Vec<u8>)> = routes
            .into_iter()
            .map(|(m, p, mut r)| {
                let body = r.body.materialize(u64::MAX).unwrap().to_vec();
                (m.to_string(), p.to_string(), r.status, r.headers, body)
            })
            .collect();
        Arc::new(move |req: Request| {
            for (m, p, status, headers, body) in &routes {
                if req.method == *m && req.path == *p {
                    let mut out = Response::new(*status);
                    out.headers = headers.clone();
                    out.body = body.clone().into();
                    return out;
                }
            }
            Response::new(404)
        })
    }

    /// A backend that reflects the request it received into the response
    /// headers (prefixed `Echo-`) so a test can inspect the mutated request.
    fn echo_backend(status: u16) -> BackendArc {
        Arc::new(move |req: Request| {
            let mut resp = Response::new(status);
            for (k, v) in req.headers.iter() {
                resp.headers.set(&format!("Echo-{k}"), v);
            }
            resp
        })
    }

    /// The returned body is materialized so assertions can read it in place.
    fn run(mw: &Symlink, req: Request, backend: BackendArc) -> Response {
        let mut resp = mw.handle(req, &backend);
        resp.body.materialize(u64::MAX).unwrap();
        resp
    }

    /// Test bodies are always buffered once `run` has materialized them.
    fn body_bytes(resp: &Response) -> &[u8] {
        match &resp.body {
            Body::Buffered(b) => b,
            Body::Streamed(_) | Body::Channel(_) => unreachable!(),
        }
    }

    fn symlink_resp(target: &str, account: Option<&str>, tgt_etag: Option<&str>) -> Response {
        let mut r = Response::new(200);
        r.headers.set(TGT_OBJ_SYSMETA_SYMLINK_HDR, target);
        if let Some(a) = account {
            r.headers.set(TGT_ACCT_SYSMETA_SYMLINK_HDR, a);
        }
        if let Some(e) = tgt_etag {
            r.headers.set(TGT_ETAG_SYSMETA_SYMLINK_HDR, e);
        }
        r.headers.set("Content-Length", "0");
        r.headers.set("Etag", MD5_OF_EMPTY_STRING);
        r
    }

    fn object_resp(body: &str, etag: &str) -> Response {
        let mut r = Response::with_body(200, body.as_bytes().to_vec());
        r.headers.set("Content-Length", body.len().to_string());
        r.headers.set("Etag", etag);
        r.headers.set("Content-Type", "text/plain");
        r
    }

    // ---- GET/HEAD follow -------------------------------------------------

    #[test]
    fn test_plain_object_passes_through() {
        let mw = Symlink::default();
        let be = backend(vec![("GET", "/v1/a/c/o", object_resp("hello", "e-hello"))]);
        let resp = run(&mw, req("GET", "/v1/a/c/o", &[]), be);
        assert_eq!(resp.status, 200);
        assert_eq!(body_bytes(&resp), b"hello");
        // No traversal happened, so there is no Content-Location.
        assert!(resp.headers.get("Content-Location").is_none());
    }

    #[test]
    fn test_dynamic_symlink_follows_target() {
        let mw = Symlink::default();
        let be = backend(vec![
            ("GET", "/v1/a/c/link", symlink_resp("c2/obj", None, None)),
            ("GET", "/v1/a/c2/obj", object_resp("payload", "e-payload")),
        ]);
        let resp = run(&mw, req("GET", "/v1/a/c/link", &[]), be);
        assert_eq!(resp.status, 200);
        assert_eq!(body_bytes(&resp), b"payload");
        assert_eq!(resp.headers.get("Content-Location"), Some("/v1/a/c2/obj"));
    }

    #[test]
    fn test_cross_account_symlink_uses_target_account() {
        let mw = Symlink::default();
        let be = backend(vec![
            (
                "GET",
                "/v1/a/c/link",
                symlink_resp("c2/obj", Some("a2"), None),
            ),
            ("GET", "/v1/a2/c2/obj", object_resp("xacct", "e-xacct")),
        ]);
        let resp = run(&mw, req("GET", "/v1/a/c/link", &[]), be);
        assert_eq!(resp.status, 200);
        assert_eq!(body_bytes(&resp), b"xacct");
        assert_eq!(resp.headers.get("Content-Location"), Some("/v1/a2/c2/obj"));
    }

    #[test]
    fn test_nested_symlink_chain_within_limit() {
        let mw = Symlink::new(2);
        let be = backend(vec![
            ("HEAD", "/v1/a/c/l0", symlink_resp("c/l1", None, None)),
            ("HEAD", "/v1/a/c/l1", symlink_resp("c/l2", None, None)),
            ("HEAD", "/v1/a/c/l2", object_resp("", "e-final")),
        ]);
        let resp = run(&mw, req("HEAD", "/v1/a/c/l0", &[]), be);
        assert_eq!(resp.status, 200);
        assert_eq!(resp.headers.get("Content-Location"), Some("/v1/a/c/l2"));
    }

    #[test]
    fn test_symloop_max_exceeded_conflicts() {
        let mw = Symlink::new(2);
        let be = backend(vec![
            ("GET", "/v1/a/c/l0", symlink_resp("c/l1", None, None)),
            ("GET", "/v1/a/c/l1", symlink_resp("c/l2", None, None)),
            ("GET", "/v1/a/c/l2", symlink_resp("c/l3", None, None)),
        ]);
        let resp = run(&mw, req("GET", "/v1/a/c/l0", &[]), be);
        assert_eq!(resp.status, 409);
        assert_eq!(
            String::from_utf8_lossy(body_bytes(&resp)),
            "Too many levels of symbolic links, maximum allowed is 2"
        );
        assert_eq!(resp.headers.get("Content-Type"), Some("text/plain"));
    }

    #[test]
    fn test_symlink_get_returns_symlink_itself() {
        let mw = Symlink::default();
        let be = backend(vec![(
            "GET",
            "/v1/a/c/link",
            symlink_resp("c2/obj", Some("a2"), None),
        )]);
        let mut r = req("GET", "/v1/a/c/link", &[]);
        r.query_string = "symlink=get".into();
        let resp = run(&mw, r, be);
        assert_eq!(resp.status, 200);
        // Sysmeta was translated to the client-facing header...
        assert_eq!(resp.headers.get(TGT_OBJ_SYMLINK_HDR), Some("c2/obj"));
        assert_eq!(resp.headers.get(TGT_ACCT_SYMLINK_HDR), Some("a2"));
        // ...and no longer appears under sysmeta.
        assert!(resp.headers.get(TGT_OBJ_SYSMETA_SYMLINK_HDR).is_none());
        // No follow happened, so no Content-Location.
        assert!(resp.headers.get("Content-Location").is_none());
    }

    #[test]
    fn test_static_symlink_get_etag_mismatch() {
        // A static symlink expecting etag "want" whose target has a
        // different etag -> 409.
        let mw = Symlink::default();
        let be = backend(vec![
            (
                "GET",
                "/v1/a/c/link",
                symlink_resp("c2/obj", None, Some("want")),
            ),
            ("GET", "/v1/a/c2/obj", object_resp("data", "got")),
        ]);
        let resp = run(&mw, req("GET", "/v1/a/c/link", &[]), be);
        assert_eq!(resp.status, 409);
        assert_eq!(
            String::from_utf8_lossy(body_bytes(&resp)),
            "Object Etag 'got' does not match X-Symlink-Target-Etag header 'want'"
        );
        assert_eq!(resp.headers.get("Content-Location"), Some("/v1/a/c2/obj"));
    }

    // ---- PUT (symlink creation) -----------------------------------------

    #[test]
    fn test_put_dynamic_symlink_stores_sysmeta() {
        let mw = Symlink::default();
        let resp = run(
            &mw,
            req("PUT", "/v1/a/c/link", &[(TGT_OBJ_SYMLINK_HDR, "c2/obj")]),
            echo_backend(201),
        );
        assert_eq!(resp.status, 201);
        // The client header was moved into sysmeta.
        assert_eq!(
            resp.headers
                .get(&format!("Echo-{TGT_OBJ_SYSMETA_SYMLINK_HDR}")),
            Some("c2/obj")
        );
        assert!(resp
            .headers
            .get(&format!("Echo-{TGT_OBJ_SYMLINK_HDR}"))
            .is_none());
        // Content-Type defaulted to application/symlink.
        assert_eq!(
            resp.headers.get("Echo-Content-Type"),
            Some("application/symlink")
        );
        // The container-update override etag encodes the symlink target.
        assert_eq!(
            resp.headers
                .get(&format!("Echo-{CONTAINER_UPDATE_OVERRIDE_ETAG}")),
            Some("d41d8cd98f00b204e9800998ecf8427e; symlink_target=c2/obj")
        );
    }

    #[test]
    fn test_put_non_zero_body_rejected() {
        let mw = Symlink::default();
        let mut r = req("PUT", "/v1/a/c/link", &[(TGT_OBJ_SYMLINK_HDR, "c2/obj")]);
        r.body = b"not empty".to_vec().into();
        let resp = run(&mw, r, echo_backend(201));
        assert_eq!(resp.status, 400);
        assert_eq!(
            String::from_utf8_lossy(body_bytes(&resp)),
            "Symlink requests require a zero byte body"
        );
        assert_eq!(resp.headers.get("Content-Type"), Some("text/plain"));
    }

    #[test]
    fn test_put_symlink_targeting_itself_rejected() {
        let mw = Symlink::default();
        let resp = run(
            &mw,
            req("PUT", "/v1/a/c/o", &[(TGT_OBJ_SYMLINK_HDR, "c/o")]),
            echo_backend(201),
        );
        assert_eq!(resp.status, 400);
        assert_eq!(
            String::from_utf8_lossy(body_bytes(&resp)),
            "Symlink cannot target itself"
        );
    }

    #[test]
    fn test_get_follows_quoted_symlink_target() {
        // Stored sysmeta is wsgi_quote'd (`%20`); Request.path is decoded.
        let mw = Symlink::default();
        let mut link = Response::new(200);
        link.headers.set(
            TGT_OBJ_SYSMETA_SYMLINK_HDR,
            "c2/dealde/l04%20011e%204c8df/flash.png",
        );
        let mut tgt = Response::with_body(200, b"png".to_vec());
        tgt.headers.set("ETag", "abc");
        let be = backend(vec![
            ("GET", "/v1/a/c/link", link),
            ("GET", "/v1/a/c2/dealde/l04 011e 4c8df/flash.png", tgt),
        ]);
        let resp = run(&mw, req("GET", "/v1/a/c/link", &[]), be);
        assert_eq!(resp.status, 200);
        assert_eq!(body_bytes(&resp), b"png");
        assert_eq!(
            resp.headers.get("Content-Location"),
            Some("/v1/a/c2/dealde/l04%20011e%204c8df/flash.png")
        );
    }

    #[test]
    fn test_reserved_symlink_capability_is_required_and_propagated() {
        let cur = req("GET", "/v1/a/c/link", &[]);
        let orig = cur.clone_head();
        let target = "%00versions%00c/%00o%001787770000.00000";

        let ordinary = symlink_resp(target, None, Some("abc"));
        let (ordinary_req, _) = build_traversal_req(&cur, &ordinary, target, &orig);
        assert_eq!(
            ordinary_req.path,
            "/v1/a/\0versions\0c/\0o\01787770000.00000"
        );
        assert_eq!(ordinary_req.headers.get("X-Backend-Source"), Some("SYM"));
        assert!(ordinary_req
            .headers
            .get("X-Backend-Allow-Reserved-Names")
            .is_none());
        assert!(ordinary_req
            .headers
            .get("X-Backend-Authorize-Override")
            .is_none());

        let mut authorized = symlink_resp(target, None, Some("abc"));
        authorized.headers.set(ALLOW_RESERVED_NAMES, "true");
        let (authorized_req, quoted_path) = build_traversal_req(&cur, &authorized, target, &orig);
        assert_eq!(
            authorized_req.path,
            "/v1/a/\0versions\0c/\0o\01787770000.00000"
        );
        assert_eq!(quoted_path, "/v1/a/%00versions%00c/%00o%001787770000.00000");
        assert_eq!(
            authorized_req.headers.get("X-Backend-Allow-Reserved-Names"),
            Some("true")
        );
        assert_eq!(
            authorized_req.headers.get("X-Backend-Authorize-Override"),
            Some("true")
        );
    }

    #[test]
    fn test_put_normalizes_percent_encoded_slash_in_target() {
        let mw = Symlink::default();
        let resp = run(
            &mw,
            req(
                "PUT",
                "/v1/a/c/link",
                &[(
                    TGT_OBJ_SYMLINK_HDR,
                    "c2/dealde%2Fl04 011e%204c8df/flash.png",
                )],
            ),
            echo_backend(201),
        );
        assert_eq!(resp.status, 201);
        assert_eq!(
            resp.headers
                .get(&format!("Echo-{TGT_OBJ_SYSMETA_SYMLINK_HDR}")),
            Some("c2/dealde/l04%20011e%204c8df/flash.png")
        );
    }

    #[test]
    fn test_put_target_with_leading_slash_rejected() {
        let mw = Symlink::default();
        let resp = run(
            &mw,
            req("PUT", "/v1/a/c/link", &[(TGT_OBJ_SYMLINK_HDR, "/c2/obj")]),
            echo_backend(201),
        );
        assert_eq!(resp.status, 412);
        assert_eq!(
            String::from_utf8_lossy(body_bytes(&resp)),
            "X-Symlink-Target header must be of the form <container name>/<object name>"
        );
        // The leading-slash check uses content_type='text/plain'.
        assert_eq!(resp.headers.get("Content-Type"), Some("text/plain"));
    }

    #[test]
    fn test_put_malformed_target_rejected() {
        let mw = Symlink::default();
        // No slash -> not a container/object pair.
        let resp = run(
            &mw,
            req(
                "PUT",
                "/v1/a/c/link",
                &[(TGT_OBJ_SYMLINK_HDR, "onlycontainer")],
            ),
            echo_backend(201),
        );
        assert_eq!(resp.status, 412);
        // check_path_header omits content_type, so swob's default is used.
        assert_eq!(
            resp.headers.get("Content-Type"),
            Some("text/html; charset=UTF-8")
        );
    }

    #[test]
    fn test_put_bad_target_account_rejected() {
        let mw = Symlink::default();
        let resp = run(
            &mw,
            req(
                "PUT",
                "/v1/a/c/link",
                &[
                    (TGT_OBJ_SYMLINK_HDR, "c2/obj"),
                    (TGT_ACCT_SYMLINK_HDR, "bad/acct"),
                ],
            ),
            echo_backend(201),
        );
        assert_eq!(resp.status, 412);
        assert_eq!(
            String::from_utf8_lossy(body_bytes(&resp)),
            "Account name cannot contain slashes"
        );
    }

    #[test]
    fn test_put_static_symlink_verifies_target() {
        let mw = Symlink::default();
        // Static symlink: HEAD subrequest to the target confirms the etag.
        // The PUT itself echoes the request so we can inspect sysmeta.
        let echo = echo_backend(201);
        let be: BackendArc = Arc::new(move |r: Request| {
            if r.method == "HEAD" && r.path == "/v1/a/c2/obj" {
                let mut target = Response::new(200);
                target.headers.set("Etag", "abc123");
                target.headers.set("Content-Length", "100");
                target.headers.set("Content-Type", "image/png");
                return target;
            }
            echo(r)
        });

        let resp = run(
            &mw,
            req(
                "PUT",
                "/v1/a/c/link",
                &[
                    (TGT_OBJ_SYMLINK_HDR, "c2/obj"),
                    (TGT_ETAG_SYMLINK_HDR, "abc123"),
                ],
            ),
            be,
        );
        assert_eq!(resp.status, 201);
        assert_eq!(
            resp.headers
                .get(&format!("Echo-{TGT_ETAG_SYSMETA_SYMLINK_HDR}")),
            Some("abc123")
        );
        assert_eq!(
            resp.headers
                .get(&format!("Echo-{TGT_BYTES_SYSMETA_SYMLINK_HDR}")),
            Some("100")
        );
        // Content-Type was inherited from the target.
        assert_eq!(resp.headers.get("Echo-Content-Type"), Some("image/png"));
        // The override etag carries the static-symlink fields.
        assert_eq!(
            resp.headers
                .get(&format!("Echo-{CONTAINER_UPDATE_OVERRIDE_ETAG}")),
            Some(
                "d41d8cd98f00b204e9800998ecf8427e; symlink_target=c2/obj; \
                 symlink_target_etag=abc123; symlink_target_bytes=100"
            )
        );
    }

    #[test]
    fn test_container_sync_override_trusts_static_symlink_metadata() {
        let mw = Symlink::default();
        let echo = echo_backend(201);
        let be: BackendArc = Arc::new(move |r: Request| {
            assert_ne!(r.method, "HEAD", "override must not resolve the target");
            echo(r)
        });
        let resp = run(
            &mw,
            req(
                "PUT",
                "/v1/a/c/link",
                &[
                    (TGT_OBJ_SYMLINK_HDR, "c2/obj"),
                    (TGT_ETAG_SYMLINK_HDR, "abc123"),
                    (TGT_BYTES_SYMLINK_HDR, "100"),
                    ("X-Backend-Symlink-Override", "true"),
                ],
            ),
            be,
        );
        assert_eq!(resp.status, 201);
        assert_eq!(
            resp.headers
                .get(&format!("Echo-{TGT_ETAG_SYSMETA_SYMLINK_HDR}")),
            Some("abc123")
        );
        assert_eq!(
            resp.headers
                .get(&format!("Echo-{TGT_BYTES_SYSMETA_SYMLINK_HDR}")),
            Some("100")
        );
    }

    #[test]
    fn test_put_static_symlink_to_slo_carries_slo_etag() {
        let mw = Symlink::default();
        let echo = echo_backend(201);
        let be: BackendArc = Arc::new(move |r: Request| {
            if r.method == "HEAD" && r.path == "/v1/a/c2/manifest" {
                let mut target = Response::new(200);
                target.headers.set("Etag", "physicaljson");
                target.headers.set("Content-Length", "12");
                target.headers.set(
                    "Content-Type",
                    "application/octet-stream;swift_bytes=1048577",
                );
                target.headers.set("X-Static-Large-Object", "True");
                target.headers.set(SYSMETA_SLO_ETAG, "slohash");
                target.headers.set("X-Object-Sysmeta-Slo-Size", "1048577");
                return target;
            }
            echo(r)
        });
        let resp = run(
            &mw,
            req(
                "PUT",
                "/v1/a/c/link",
                &[
                    (TGT_OBJ_SYMLINK_HDR, "c2/manifest"),
                    (TGT_ETAG_SYMLINK_HDR, "physicaljson"),
                ],
            ),
            be,
        );
        assert_eq!(resp.status, 201);
        assert_eq!(
            resp.headers.get("Echo-Content-Type"),
            Some("application/octet-stream")
        );
        assert_eq!(
            resp.headers
                .get(&format!("Echo-{TGT_BYTES_SYSMETA_SYMLINK_HDR}")),
            Some("1048577")
        );
        let ov = resp
            .headers
            .get(&format!("Echo-{CONTAINER_UPDATE_OVERRIDE_ETAG}"))
            .unwrap_or("");
        assert!(ov.contains("slo_etag=slohash"), "{ov}");
        assert!(ov.contains("symlink_target=c2/manifest"), "{ov}");
    }

    #[test]
    fn test_put_static_symlink_target_missing() {
        let mw = Symlink::default();
        // HEAD subrequest 404s -> the target does not exist.
        let be = backend(vec![("PUT", "/v1/a/c/link", Response::new(201))]);
        let resp = run(
            &mw,
            req(
                "PUT",
                "/v1/a/c/link",
                &[
                    (TGT_OBJ_SYMLINK_HDR, "c2/obj"),
                    (TGT_ETAG_SYMLINK_HDR, "abc123"),
                ],
            ),
            be,
        );
        assert_eq!(resp.status, 409);
        assert_eq!(
            String::from_utf8_lossy(body_bytes(&resp)),
            "X-Symlink-Target does not exist"
        );
        assert_eq!(resp.headers.get("Content-Location"), Some("/v1/a/c2/obj"));
    }

    #[test]
    fn test_put_static_symlink_etag_mismatch() {
        let mw = Symlink::default();
        let mut target = Response::new(200);
        target.headers.set("Etag", "different");
        target.headers.set("Content-Length", "100");
        let be = backend(vec![
            ("HEAD", "/v1/a/c2/obj", target),
            ("PUT", "/v1/a/c/link", Response::new(201)),
        ]);
        let resp = run(
            &mw,
            req(
                "PUT",
                "/v1/a/c/link",
                &[
                    (TGT_OBJ_SYMLINK_HDR, "c2/obj"),
                    (TGT_ETAG_SYMLINK_HDR, "abc123"),
                ],
            ),
            be,
        );
        assert_eq!(resp.status, 409);
        assert_eq!(
            String::from_utf8_lossy(body_bytes(&resp)),
            "Object Etag 'different' does not match X-Symlink-Target-Etag header 'abc123'"
        );
    }

    // ---- POST ------------------------------------------------------------

    #[test]
    fn test_container_listing_exposes_symlink_path() {
        let mw = Symlink::default();
        let listing = serde_json::json!([
            {
                "name": "link",
                "bytes": 0,
                "hash": "d41d8cd98f00b204e9800998ecf8427e; symlink_target=c2/obj"
            },
            {"name": "plain", "bytes": 3, "hash": "abc"}
        ]);
        let mut listed = Response::with_body(200, serde_json::to_vec(&listing).unwrap());
        listed.headers.set("Content-Type", "application/json");
        let be = backend(vec![("GET", "/v1/AUTH_a/c", listed)]);
        let resp = run(&mw, req("GET", "/v1/AUTH_a/c", &[]), be);
        assert_eq!(resp.status, 200);
        let items: Vec<serde_json::Value> = serde_json::from_slice(body_bytes(&resp)).unwrap();
        assert_eq!(items[0]["symlink_path"].as_str(), Some("/v1/AUTH_a/c2/obj"));
        assert_eq!(
            items[0]["hash"].as_str(),
            Some("d41d8cd98f00b204e9800998ecf8427e")
        );
        assert!(items[1].get("symlink_path").is_none());
        assert_eq!(items[1]["hash"].as_str(), Some("abc"));
    }

    #[test]
    fn test_post_with_symlink_target_rejected() {
        let mw = Symlink::default();
        let resp = run(
            &mw,
            req("POST", "/v1/a/c/o", &[(TGT_OBJ_SYMLINK_HDR, "c2/obj")]),
            echo_backend(202),
        );
        assert_eq!(resp.status, 400);
        assert_eq!(
            String::from_utf8_lossy(body_bytes(&resp)),
            "A PUT request is required to set a symlink target"
        );
        assert_eq!(resp.headers.get("Content-Type"), Some("text/plain"));
    }

    #[test]
    fn test_post_to_symlink_redirects() {
        let mw = Symlink::default();
        // The object server returns the symlink target sysmeta on POST.
        let mut posted = Response::new(202);
        posted.headers.set(TGT_OBJ_SYSMETA_SYMLINK_HDR, "c2/obj");
        let be = backend(vec![("POST", "/v1/a/c/link", posted)]);
        let resp = run(&mw, req("POST", "/v1/a/c/link", &[]), be);
        assert_eq!(resp.status, 307);
        assert_eq!(resp.headers.get("Location"), Some("/v1/a/c2/obj"));
        assert!(String::from_utf8_lossy(body_bytes(&resp)).contains("POST directly to the target"));
        // The carried-forward sysmeta appears on the redirect.
        assert_eq!(
            resp.headers.get(TGT_OBJ_SYSMETA_SYMLINK_HDR),
            Some("c2/obj")
        );
    }

    #[test]
    fn test_post_to_plain_object_passes_through() {
        let mw = Symlink::default();
        // No symlink sysmeta on the POST response -> ordinary passthrough.
        let be = backend(vec![("POST", "/v1/a/c/o", Response::new(202))]);
        let resp = run(&mw, req("POST", "/v1/a/c/o", &[]), be);
        assert_eq!(resp.status, 202);
        assert!(resp.headers.get("Location").is_none());
    }

    // ---- passthrough -----------------------------------------------------

    #[test]
    fn test_delete_passes_through() {
        let mw = Symlink::default();
        let be = backend(vec![("DELETE", "/v1/a/c/o", Response::new(204))]);
        let resp = run(&mw, req("DELETE", "/v1/a/c/o", &[]), be);
        assert_eq!(resp.status, 204);
    }

    #[test]
    fn test_container_request_passes_through() {
        // Container listing augmentation is deferred; the request passes
        // straight through.
        let mw = Symlink::default();
        let be = backend(vec![(
            "GET",
            "/v1/a/c",
            Response::with_body(200, b"[]".to_vec()),
        )]);
        let resp = run(&mw, req("GET", "/v1/a/c", &[]), be);
        assert_eq!(resp.status, 200);
        assert_eq!(body_bytes(&resp), b"[]");
    }

    #[test]
    fn test_non_swift_path_passes_through() {
        let mw = Symlink::default();
        let be = backend(vec![(
            "GET",
            "/healthcheck",
            Response::with_body(200, b"OK".to_vec()),
        )]);
        let resp = run(&mw, req("GET", "/healthcheck", &[]), be);
        assert_eq!(resp.status, 200);
        assert_eq!(body_bytes(&resp), b"OK");
    }

    #[test]
    fn test_from_conf_clamps_below_one() {
        assert_eq!(Symlink::from_conf(None).symloop_max, 2);
        assert_eq!(Symlink::from_conf(Some("5")).symloop_max, 5);
        assert_eq!(Symlink::from_conf(Some("0")).symloop_max, 2);
        assert_eq!(Symlink::from_conf(Some("-3")).symloop_max, 2);
        assert_eq!(Symlink::from_conf(Some("garbage")).symloop_max, 2);
    }

    #[test]
    fn test_intercepts_symlink_put_and_post_not_plain_get() {
        let mw = Symlink::new(2);
        let put = req("PUT", "/v1/a/c/link", &[(TGT_OBJ_SYMLINK_HDR, "c/target")]);
        assert!(mw.intercepts_request(&put));
        let post = req("POST", "/v1/a/c/link", &[]);
        assert!(mw.intercepts_request(&post));
        let get = req("GET", "/v1/a/c/link", &[]);
        assert!(!mw.intercepts_request(&get));
        assert!(mw.intercepts_response());
        let acc = req("GET", "/v1/a", &[]);
        assert!(!mw.intercepts_request(&acc));
    }

    #[tokio::test]
    async fn test_async_get_follows_symlink() {
        let mw = Symlink::new(2);
        let mut link = Response::new(200);
        link.headers.set(TGT_OBJ_SYSMETA_SYMLINK_HDR, "c/target");
        let mut tgt = Response::with_body(200, b"target body".to_vec());
        tgt.headers.set("ETag", "abc");
        let next: AsyncNextFn = {
            let routes =
                std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::from([
                    ("/v1/a/c/link".to_string(), link),
                    ("/v1/a/c/target".to_string(), tgt),
                ])));
            std::sync::Arc::new(move |r: Request| {
                let routes = std::sync::Arc::clone(&routes);
                Box::pin(async move {
                    routes
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .remove(&r.path)
                        .unwrap_or_else(|| Response::new(404))
                })
            })
        };
        let resp = mw
            .handle_object_async(req("GET", "/v1/a/c/link", &[]), next)
            .await;
        assert_eq!(resp.status, 200);
        let body = match resp.body {
            Body::Buffered(b) => b,
            _ => panic!("expected buffered body"),
        };
        assert_eq!(body, b"target body");
        assert_eq!(resp.headers.get("Content-Location"), Some("/v1/a/c/target"));
    }

    #[tokio::test]
    async fn test_versioned_user_symlink_follow_does_not_leak_override() {
        // Official test_container_acls: GET current is hop 1 reserved
        // versions-symlink (pre-auth) then hop 2 user symlink into another
        // container. Python make_subrequest uses the client environ for hop 2.
        // Copying cur.headers leaks X-Backend-Authorize-Override so user3
        // reads the target (ResponseError not raised at line 404).
        type Hop = (String, Option<String>);
        let hops: std::sync::Arc<std::sync::Mutex<Vec<Hop>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let hops2 = std::sync::Arc::clone(&hops);
        let next: AsyncNextFn = std::sync::Arc::new(move |r: Request| {
            let hops = std::sync::Arc::clone(&hops2);
            Box::pin(async move {
                hops.lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .push((
                        r.path.clone(),
                        r.headers
                            .get("X-Backend-Authorize-Override")
                            .map(str::to_string),
                    ));
                if r.path == "/v1/AUTH_test/c/obj" {
                    let mut link = Response::new(200);
                    link.headers
                        .set(TGT_OBJ_SYSMETA_SYMLINK_HDR, "%00versions%00c/archive");
                    link.headers.set(ALLOW_RESERVED_NAMES, "true");
                    link.headers.set(SYMLOOP_EXTEND, "true");
                    return link;
                }
                if r.path.contains("versions") {
                    let mut user = Response::new(200);
                    user.headers
                        .set(TGT_OBJ_SYSMETA_SYMLINK_HDR, "other/tgt");
                    return user;
                }
                if r.path == "/v1/AUTH_test/other/tgt" {
                    if r.headers
                        .get("X-Backend-Authorize-Override")
                        .is_some_and(config_true_value)
                    {
                        return Response::with_body(200, b"link".to_vec());
                    }
                    return Response::new(403);
                }
                Response::new(404)
            })
        });
        let mw = Symlink::new(2);
        let mut headers = HeaderKeyDict::new();
        headers.set("X-Auth-Token", "user3");
        let req = Request {
            method: "GET".to_string(),
            path: "/v1/AUTH_test/c/obj".to_string(),
            query_string: String::new(),
            headers,
            body: Body::empty(),
        };
        let resp = mw.handle_object_async(req, next).await;
        assert_eq!(
            resp.status, 403,
            "user symlink hop must 403 without leaked override; hops={:?}",
            hops.lock().unwrap_or_else(|p| p.into_inner())
        );
        let hops = hops.lock().unwrap_or_else(|p| p.into_inner());
        let target = hops
            .iter()
            .find(|(p, _)| p == "/v1/AUTH_test/other/tgt")
            .expect("must GET user-symlink target");
        assert_ne!(
            target.1.as_deref(),
            Some("true"),
            "hop 2 must not inherit Authorize-Override: {hops:?}"
        );
    }
}
