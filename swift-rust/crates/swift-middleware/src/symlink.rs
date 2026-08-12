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
//! * The `swift.symlink_override` fast path (versioned_writes integration),
//!   `X-Backend-Allow-Reserved-Names` / `make_pre_authed_request` reserved
//!   -name subrequests, and the `swift.leave_relative_location` POST flag
//!   are not modelled.
//! * `wsgi_quote`/`wsgi_unquote` round-tripping is simplified: paths and
//!   symlink-target headers are treated as already percent-decoded.
//! * `filter_factory`, `register_swift_info`, and the logger are not ported
//!   (matching `gatekeeper`/`read_only`). The `status_map[...]` error body
//!   for a non-success static-symlink target is simplified to the bare
//!   status.

use swift_core::config::config_true_value;
use swift_core::constraints::check_account_format;

use swift_http::{
    body_too_large, normalize_etag, split_path, Body, HeaderKeyDict, Request, Response,
    MAX_CONTROL_BODY,
};

use crate::{Middleware, NextFn};

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

const CONTAINER_UPDATE_OVERRIDE_ETAG: &str = "X-Object-Sysmeta-Container-Update-Override-Etag";
const IGNORE_RANGE_HDR: &str = "X-Backend-Ignore-Range-If-Metadata-Present";
const MD5_OF_EMPTY_STRING: &str = "d41d8cd98f00b204e9800998ecf8427e";

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
                let new_req = build_traversal_req(&cur, &resp, &symlink_target, orig_req);
                last_target_path = Some(new_req.path.clone());
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
        // NOTE: the swift.symlink_override fast path is deferred.
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

        let has_ct = req
            .headers
            .get("Content-Type")
            .map(|s| !s.is_empty())
            .unwrap_or(false);
        if !has_ct {
            if let Some(ct) = resp.headers.get("Content-Type").map(str::to_string) {
                req.headers.set("Content-Type", ct);
            }
        }
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
}

impl Middleware for Symlink {
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
            // Container context (listing symlink_path augmentation) is
            // deferred; pass the request through.
            _ => next(req),
        }
    }
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
) -> Request {
    let parts = split_path(&cur.path, 2, 3, true).unwrap_or_default();
    let version = parts.first().and_then(|o| o.clone()).unwrap_or_default();
    let account_from_path = parts.get(1).and_then(|o| o.clone()).unwrap_or_default();
    let account = resp
        .headers
        .get(TGT_ACCT_SYSMETA_SYMLINK_HDR)
        .map(str::to_string)
        .unwrap_or(account_from_path);
    let target = symlink_target.trim_start_matches('/');
    let target_path = format!("/{version}/{account}/{target}");

    // make_subrequest(orig_req.environ, path=..., method=req.method,
    // headers=dict(req.headers)): base on the original request, adopt the
    // current hop's method and headers, drop any storage-policy pin.
    let mut new_req = orig_req.clone_head();
    new_req.method = cur.method.clone();
    new_req.path = target_path;
    new_req.query_string = String::new();
    new_req.headers = cur.headers.clone();
    new_req.headers.remove("X-Backend-Storage-Policy-Index");
    new_req
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

    // The caller guarantees X-Symlink-Target is present. (wsgi_unquote is
    // simplified: the value is treated as already decoded.)
    let raw_target = req
        .headers
        .get(TGT_OBJ_SYMLINK_HDR)
        .unwrap_or("")
        .to_string();
    if raw_target.starts_with('/') {
        return Err(err_text(412, ERROR_BODY));
    }

    // check_path_header: prepend '/' if missing, then split into exactly two
    // segments (container/object, object may contain slashes).
    let hdr = format!("/{raw_target}");
    let cont_obj = match split_path(&hdr, 2, 2, true) {
        Ok(parts) => parts,
        Err(_) => return Err(err_html(412, ERROR_BODY)),
    };
    let container = cont_obj.first().and_then(|o| o.clone()).unwrap_or_default();
    let obj = cont_obj.get(1).and_then(|o| o.clone()).unwrap_or_default();
    req.headers
        .set(TGT_OBJ_SYMLINK_HDR, format!("{container}/{obj}"));

    // Validate the target account format if the header is present.
    let target_account = match req.headers.get(TGT_ACCT_SYMLINK_HDR).map(str::to_string) {
        Some(acct) => match check_account_format(&acct) {
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
            req.headers.set(TGT_ACCT_SYMLINK_HDR, a.clone());
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
            Body::Streamed(_) => unreachable!(),
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
}
