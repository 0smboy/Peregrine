//! JSON API for the Files surface. Everything here talks to the Swift cluster
//! with the session's token and re-auths transparently once on 401.

use crate::session;
use crate::swift::{self, SwiftError};
use crate::util::{enc_obj, enc_seg, fmt_bytes, hmac_sha1_hex, now_secs, rand_hex};
use crate::zipstream::{Crc32, ZipWriter};
use crate::AppState;
use axum::body::Body;
use axum::extract::{Path, Query, Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;
use bytes::Bytes;
use reqwest::Method;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

pub const TRASH: &str = ".trash";

// ------------------------------------------------------------- plumbing

fn jerr(status: StatusCode, msg: &str) -> Response {
    (status, Json(json!({ "error": msg }))).into_response()
}

fn jok(v: Value) -> Response {
    Json(v).into_response()
}

fn from_swift_err(e: SwiftError) -> Response {
    match e {
        SwiftError::Unauthorized => jerr(StatusCode::UNAUTHORIZED, "session expired"),
        SwiftError::Other(m) => jerr(StatusCode::BAD_GATEWAY, &m),
    }
}

pub fn need_session(
    state: &Arc<AppState>,
    headers: &HeaderMap,
) -> Result<(String, session::Session), Response> {
    session::from_headers(&state.sessions, headers)
        .ok_or_else(|| jerr(StatusCode::UNAUTHORIZED, "not signed in"))
}

fn valid_bucket(name: &str) -> Result<(), &'static str> {
    if name.is_empty() || name.len() > 255 {
        return Err("bucket name must be 1-255 characters");
    }
    if name.contains('/') {
        return Err("bucket name must not contain '/'");
    }
    Ok(())
}

fn header_str(h: &reqwest::header::HeaderMap, name: &str) -> Option<String> {
    h.get(name).and_then(|v| v.to_str().ok()).map(String::from)
}

fn meta_map(h: &reqwest::header::HeaderMap, prefix: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for (name, value) in h {
        let n = name.as_str();
        if let Some(k) = n
            .to_ascii_lowercase()
            .strip_prefix(prefix)
            .map(String::from)
        {
            if let Ok(v) = value.to_str() {
                out.insert(k, v.to_string());
            }
        }
    }
    out
}

// ------------------------------------------------------------- whoami

pub async fn whoami(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let (_, sess) = match need_session(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    jok(json!({
        "tenant": sess.tenant,
        "user": sess.user,
        "storage_url": sess.storage_url,
        "version": env!("CARGO_PKG_VERSION"),
        "cluster": state.cfg.cluster_name,
    }))
}

// ------------------------------------------------------------- buckets

pub async fn buckets_list(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let (sid, _) = match need_session(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let buckets = match swift::list_buckets(&state, &sid).await {
        Ok(b) => b,
        Err(e) => return from_swift_err(e),
    };
    let (st, ah) = match swift::head(&state, &sid, "").await {
        Ok(v) => v,
        Err(e) => return from_swift_err(e),
    };
    if st >= 300 {
        return jerr(StatusCode::BAD_GATEWAY, &format!("account HEAD failed ({st})"));
    }
    let items: Vec<Value> = buckets
        .iter()
        .map(|b| json!({ "name": b.name, "count": b.count, "bytes": b.bytes }))
        .collect();
    jok(json!({
        "buckets": items,
        "account": {
            "bytes_used": header_str(&ah, "x-account-bytes-used"),
            "container_count": header_str(&ah, "x-account-container-count"),
            "object_count": header_str(&ah, "x-account-object-count"),
            "quota_bytes": header_str(&ah, "x-account-meta-quota-bytes"),
        }
    }))
}

#[derive(Deserialize)]
pub struct BucketCreate {
    name: String,
}

pub async fn bucket_create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<BucketCreate>,
) -> Response {
    let (sid, _) = match need_session(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    if let Err(m) = valid_bucket(&body.name) {
        return jerr(StatusCode::BAD_REQUEST, m);
    }
    let sub = format!("/{}", enc_seg(&body.name));
    match swift::call(&state, &sid, Method::PUT, &sub, &[], &[], None).await {
        Ok(r) if r.status().is_success() => jok(json!({ "ok": true })),
        Ok(r) => jerr(
            StatusCode::BAD_GATEWAY,
            &format!("create failed ({})", r.status().as_u16()),
        ),
        Err(e) => from_swift_err(e),
    }
}

pub async fn bucket_delete(
    State(state): State<Arc<AppState>>,
    Path(bucket): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let (sid, _) = match need_session(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let force = q.get("force").map(|v| v == "1").unwrap_or(false);
    let sub = format!("/{}", enc_seg(&bucket));
    let mut removed = 0u64;
    if force {
        loop {
            let l = match swift::list_objects(&state, &sid, &bucket, "", true, 1000).await {
                Ok(l) => l,
                Err(e) => return from_swift_err(e),
            };
            if l.files.is_empty() {
                break;
            }
            for f in &l.files {
                let name = f.name.clone().unwrap_or_default();
                let osub = swift::obj_subpath(&bucket, &name);
                match swift::call(&state, &sid, Method::DELETE, &osub, &[], &[], None).await {
                    Ok(r) if r.status().is_success() || r.status().as_u16() == 404 => {
                        removed += 1
                    }
                    Ok(r) => {
                        return jerr(
                            StatusCode::BAD_GATEWAY,
                            &format!(
                                "failed deleting {} ({})",
                                name,
                                r.status().as_u16()
                            ),
                        )
                    }
                    Err(e) => return from_swift_err(e),
                }
            }
            if !l.truncated {
                break;
            }
        }
    }
    match swift::call(&state, &sid, Method::DELETE, &sub, &[], &[], None).await {
        Ok(r) if r.status().is_success() => {
            jok(json!({ "ok": true, "objects_removed": removed }))
        }
        Ok(r) if r.status().as_u16() == 409 => jerr(
            StatusCode::CONFLICT,
            "bucket is not empty (use force to delete its contents)",
        ),
        Ok(r) => jerr(
            StatusCode::BAD_GATEWAY,
            &format!("delete failed ({})", r.status().as_u16()),
        ),
        Err(e) => from_swift_err(e),
    }
}

fn bucket_meta_json(h: &reqwest::header::HeaderMap) -> Value {
    let mut meta = meta_map(h, "x-container-meta-");
    let quota_bytes = meta.remove("quota-bytes");
    let quota_count = meta.remove("quota-count");
    let read_acl = header_str(h, "x-container-read").unwrap_or_default();
    let write_acl = header_str(h, "x-container-write").unwrap_or_default();
    json!({
        "meta": meta,
        "read_acl": read_acl,
        "write_acl": write_acl,
        "public": read_acl.contains(".r:*"),
        "quota_bytes": quota_bytes,
        "quota_count": quota_count,
        "object_count": header_str(h, "x-container-object-count"),
        "bytes_used": header_str(h, "x-container-bytes-used"),
        "policy": header_str(h, "x-storage-policy"),
    })
}

pub async fn bucket_meta_get(
    State(state): State<Arc<AppState>>,
    Path(bucket): Path<String>,
    headers: HeaderMap,
) -> Response {
    let (sid, _) = match need_session(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let sub = format!("/{}", enc_seg(&bucket));
    match swift::head(&state, &sid, &sub).await {
        Ok((st, h)) if st < 300 => jok(bucket_meta_json(&h)),
        Ok((404, _)) => jerr(StatusCode::NOT_FOUND, "bucket not found"),
        Ok((st, _)) => jerr(StatusCode::BAD_GATEWAY, &format!("HEAD failed ({st})")),
        Err(e) => from_swift_err(e),
    }
}

#[derive(Deserialize, Default)]
pub struct MetaSet {
    #[serde(default)]
    set: HashMap<String, String>,
    #[serde(default)]
    remove: Vec<String>,
    read_acl: Option<String>,
    write_acl: Option<String>,
    quota_bytes: Option<String>,
    quota_count: Option<String>,
}

fn valid_meta_key(k: &str) -> bool {
    !k.is_empty()
        && k.len() <= 128
        && k.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

pub async fn bucket_meta_set(
    State(state): State<Arc<AppState>>,
    Path(bucket): Path<String>,
    headers: HeaderMap,
    Json(body): Json<MetaSet>,
) -> Response {
    let (sid, _) = match need_session(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let mut hs: Vec<(String, String)> = Vec::new();
    for (k, v) in &body.set {
        if !valid_meta_key(k) {
            return jerr(StatusCode::BAD_REQUEST, &format!("bad metadata key: {k}"));
        }
        hs.push((format!("X-Container-Meta-{}", k), v.clone()));
    }
    for k in &body.remove {
        if !valid_meta_key(k) {
            return jerr(StatusCode::BAD_REQUEST, &format!("bad metadata key: {k}"));
        }
        hs.push((format!("X-Container-Meta-{}", k), String::new()));
    }
    if let Some(r) = &body.read_acl {
        hs.push(("X-Container-Read".into(), r.clone()));
    }
    if let Some(w) = &body.write_acl {
        hs.push(("X-Container-Write".into(), w.clone()));
    }
    if let Some(qb) = &body.quota_bytes {
        if qb.is_empty() {
            hs.push(("X-Container-Meta-Quota-Bytes".into(), String::new()));
        } else {
            hs.push(("X-Container-Meta-Quota-Bytes".into(), qb.clone()));
        }
    }
    if let Some(qc) = &body.quota_count {
        if qc.is_empty() {
            hs.push(("X-Container-Meta-Quota-Count".into(), String::new()));
        } else {
            hs.push(("X-Container-Meta-Quota-Count".into(), qc.clone()));
        }
    }
    if hs.is_empty() {
        return jerr(StatusCode::BAD_REQUEST, "nothing to change");
    }
    let sub = format!("/{}", enc_seg(&bucket));
    match swift::call(&state, &sid, Method::POST, &sub, &[], &hs, None).await {
        Ok(r) if r.status().is_success() => jok(json!({ "ok": true })),
        Ok(r) => {
            let st = r.status().as_u16();
            let msg = r.text().await.unwrap_or_default();
            jerr(
                StatusCode::BAD_GATEWAY,
                &format!("update failed ({st}): {}", msg.trim()),
            )
        }
        Err(e) => from_swift_err(e),
    }
}

// ------------------------------------------------------------- objects

pub async fn objects_list(
    State(state): State<Arc<AppState>>,
    Path(bucket): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let (sid, _) = match need_session(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let prefix = q.get("prefix").cloned().unwrap_or_default();
    let flat = q.get("flat").map(|v| v == "1").unwrap_or(false);
    match swift::list_objects(&state, &sid, &bucket, &prefix, flat, 10000).await {
        Ok(l) => {
            let files: Vec<Value> = l
                .files
                .iter()
                .map(|f| {
                    json!({
                        "name": f.name,
                        "bytes": f.bytes,
                        "content_type": f.content_type,
                        "last_modified": f.last_modified,
                        "hash": f.hash,
                    })
                })
                .collect();
            jok(json!({ "files": files, "folders": l.folders, "truncated": l.truncated }))
        }
        Err(e) => from_swift_err(e),
    }
}

pub async fn prefix_count(
    State(state): State<Arc<AppState>>,
    Path(bucket): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let (sid, _) = match need_session(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let prefix = q.get("prefix").cloned().unwrap_or_default();
    match swift::list_objects(&state, &sid, &bucket, &prefix, true, 100000).await {
        Ok(l) => {
            let bytes: u64 = l.files.iter().map(|f| f.bytes).sum();
            jok(json!({ "count": l.files.len(), "bytes": bytes, "human": fmt_bytes(bytes) }))
        }
        Err(e) => from_swift_err(e),
    }
}

/// PUT an object: streams the request body straight to Swift.
/// Query `multipart-manifest=put` uploads an SLO manifest (buffered, retried).
pub async fn obj_put(
    State(state): State<Arc<AppState>>,
    Path((bucket, path)): Path<(String, String)>,
    Query(q): Query<HashMap<String, String>>,
    req: Request,
) -> Response {
    let (sid, _) = match need_session(&state, req.headers()) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let max = state.cfg.max_upload_bytes;
    if let Some(cl) = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
    {
        if cl > max {
            return jerr(
                StatusCode::PAYLOAD_TOO_LARGE,
                &format!(
                    "files larger than {} are not supported on this cluster (got {})",
                    fmt_bytes(max),
                    fmt_bytes(cl)
                ),
            );
        }
    }
    let mut hs: Vec<(String, String)> = Vec::new();
    if let Some(ct) = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
    {
        hs.push(("Content-Type".into(), ct.to_string()));
    }
    for (name, value) in req.headers() {
        let n = name.as_str().to_ascii_lowercase();
        if n.starts_with("x-object-meta-") || n == "x-delete-at" {
            if let Ok(v) = value.to_str() {
                hs.push((name.as_str().to_string(), v.to_string()));
            }
        }
    }
    let sub = swift::obj_subpath(&bucket, &path);
    let manifest = q.get("multipart-manifest").map(|v| v == "put").unwrap_or(false);
    let resp = if manifest {
        // Manifest bodies are small JSON: buffer so the call can be retried.
        let body = match axum::body::to_bytes(req.into_body(), 16 * 1024 * 1024).await {
            Ok(b) => b,
            Err(e) => return jerr(StatusCode::BAD_REQUEST, &format!("bad manifest body: {e}")),
        };
        swift::call(
            &state,
            &sid,
            Method::PUT,
            &sub,
            &[("multipart-manifest", "put".into())],
            &hs,
            Some(body),
        )
        .await
    } else {
        let stream = req.into_body().into_data_stream();
        swift::call_stream(
            &state,
            &sid,
            Method::PUT,
            &sub,
            &[],
            &hs,
            reqwest::Body::wrap_stream(stream),
        )
        .await
    };
    match resp {
        Ok(r) if r.status().is_success() => {
            // etag_quoter wraps etags in quotes; SLO manifests need them bare.
            let etag = header_str(r.headers(), "etag")
                .unwrap_or_default()
                .trim_matches('"')
                .to_string();
            jok(json!({ "ok": true, "etag": etag }))
        }
        Ok(r) => {
            let st = r.status().as_u16();
            let msg = r.text().await.unwrap_or_default();
            let code = if st == 413 {
                StatusCode::PAYLOAD_TOO_LARGE
            } else {
                StatusCode::BAD_GATEWAY
            };
            jerr(code, &format!("upload failed ({st}): {}", msg.trim()))
        }
        Err(e) => from_swift_err(e),
    }
}

pub async fn obj_delete(
    State(state): State<Arc<AppState>>,
    Path((bucket, path)): Path<(String, String)>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let (sid, _) = match need_session(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let with_segments = q.get("with_segments").map(|v| v == "1").unwrap_or(false);
    let sub = swift::obj_subpath(&bucket, &path);
    let mut segments_deleted = 0u64;
    if with_segments {
        // This cluster build's SLO middleware deletes only the manifest on
        // multipart-manifest=delete, so the console removes the segments
        // itself: read the manifest, delete each segment, then the manifest.
        let (st, h) = match swift::head(&state, &sid, &sub).await {
            Ok(v) => v,
            Err(e) => return from_swift_err(e),
        };
        let is_slo = st < 300
            && header_str(&h, "x-static-large-object")
                .map(|v| v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
        if is_slo {
            let r = match swift::call(
                &state,
                &sid,
                Method::GET,
                &sub,
                &[("multipart-manifest", "get".into())],
                &[],
                None,
            )
            .await
            {
                Ok(r) if r.status().is_success() => r,
                Ok(r) => {
                    return jerr(
                        StatusCode::BAD_GATEWAY,
                        &format!("manifest read failed ({})", r.status().as_u16()),
                    )
                }
                Err(e) => return from_swift_err(e),
            };
            #[derive(Deserialize)]
            struct Seg {
                name: String,
            }
            let segs: Vec<Seg> = match r.json().await {
                Ok(v) => v,
                Err(e) => {
                    return jerr(StatusCode::BAD_GATEWAY, &format!("bad manifest: {e}"))
                }
            };
            for s in &segs {
                let p = s.name.trim_start_matches('/');
                if let Some((c, o)) = p.split_once('/') {
                    if delete_object(&state, &sid, c, o).await.is_ok() {
                        segments_deleted += 1;
                    }
                }
            }
        }
    }
    match swift::call(&state, &sid, Method::DELETE, &sub, &[], &[], None).await {
        Ok(r) if r.status().is_success() => {
            jok(json!({ "ok": true, "segments_deleted": segments_deleted }))
        }
        Ok(r) if r.status().as_u16() == 404 => jerr(StatusCode::NOT_FOUND, "object not found"),
        Ok(r) => {
            let st = r.status().as_u16();
            let msg = r.text().await.unwrap_or_default();
            jerr(
                StatusCode::BAD_GATEWAY,
                &format!("delete failed ({st}): {}", msg.trim()),
            )
        }
        Err(e) => from_swift_err(e),
    }
}

#[derive(Deserialize)]
pub struct FolderCreate {
    bucket: String,
    prefix: String,
}

pub async fn folder_create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<FolderCreate>,
) -> Response {
    let (sid, _) = match need_session(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let mut name = body.prefix.trim().trim_matches('/').to_string();
    if name.is_empty() {
        return jerr(StatusCode::BAD_REQUEST, "folder name is empty");
    }
    name.push('/');
    let sub = swift::obj_subpath(&body.bucket, &name);
    let hs = vec![("Content-Type".to_string(), "application/directory".to_string())];
    match swift::call(&state, &sid, Method::PUT, &sub, &[], &hs, Some(Bytes::new())).await {
        Ok(r) if r.status().is_success() => jok(json!({ "ok": true, "name": name })),
        Ok(r) => jerr(
            StatusCode::BAD_GATEWAY,
            &format!("folder create failed ({})", r.status().as_u16()),
        ),
        Err(e) => from_swift_err(e),
    }
}

#[derive(Deserialize)]
pub struct FolderDelete {
    bucket: String,
    prefix: String,
}

pub async fn folder_delete(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<FolderDelete>,
) -> Response {
    let (sid, _) = match need_session(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let mut prefix = body.prefix.clone();
    if !prefix.ends_with('/') {
        prefix.push('/');
    }
    let mut deleted = 0u64;
    loop {
        let l = match swift::list_objects(&state, &sid, &body.bucket, &prefix, true, 1000).await
        {
            Ok(l) => l,
            Err(e) => return from_swift_err(e),
        };
        if l.files.is_empty() {
            break;
        }
        for f in &l.files {
            let name = f.name.clone().unwrap_or_default();
            let osub = swift::obj_subpath(&body.bucket, &name);
            match swift::call(&state, &sid, Method::DELETE, &osub, &[], &[], None).await {
                Ok(r) if r.status().is_success() || r.status().as_u16() == 404 => deleted += 1,
                Ok(r) => {
                    return jerr(
                        StatusCode::BAD_GATEWAY,
                        &format!("failed deleting {} ({})", name, r.status().as_u16()),
                    )
                }
                Err(e) => return from_swift_err(e),
            }
        }
        if !l.truncated {
            break;
        }
    }
    jok(json!({ "ok": true, "deleted": deleted }))
}

// ------------------------------------------------------------- object metadata

pub async fn obj_meta_get(
    State(state): State<Arc<AppState>>,
    Path((bucket, path)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let (sid, _) = match need_session(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let sub = swift::obj_subpath(&bucket, &path);
    match swift::head(&state, &sid, &sub).await {
        Ok((st, h)) if st < 300 => jok(json!({
            "content_type": header_str(&h, "content-type"),
            "bytes": header_str(&h, "content-length"),
            "last_modified": header_str(&h, "last-modified"),
            "etag": header_str(&h, "etag"),
            "delete_at": header_str(&h, "x-delete-at"),
            "is_slo": header_str(&h, "x-static-large-object").map(|v| v.eq_ignore_ascii_case("true")).unwrap_or(false),
            "meta": meta_map(&h, "x-object-meta-"),
        })),
        Ok((404, _)) => jerr(StatusCode::NOT_FOUND, "object not found"),
        Ok((st, _)) => jerr(StatusCode::BAD_GATEWAY, &format!("HEAD failed ({st})")),
        Err(e) => from_swift_err(e),
    }
}

#[derive(Deserialize, Default)]
pub struct ObjMetaSet {
    #[serde(default)]
    set: HashMap<String, String>,
    #[serde(default)]
    remove: Vec<String>,
    content_type: Option<String>,
    /// Unix timestamp to schedule deletion; empty string clears expiry.
    delete_at: Option<String>,
}

pub async fn obj_meta_set(
    State(state): State<Arc<AppState>>,
    Path((bucket, path)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<ObjMetaSet>,
) -> Response {
    let (sid, _) = match need_session(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let sub = swift::obj_subpath(&bucket, &path);
    // Object POST replaces the whole metadata set: read-merge-write.
    let (st, cur) = match swift::head(&state, &sid, &sub).await {
        Ok(v) => v,
        Err(e) => return from_swift_err(e),
    };
    if st >= 300 {
        return jerr(StatusCode::BAD_GATEWAY, &format!("HEAD failed ({st})"));
    }
    let mut merged = meta_map(&cur, "x-object-meta-");
    for k in &body.remove {
        merged.remove(&k.to_ascii_lowercase());
    }
    for (k, v) in &body.set {
        if !valid_meta_key(k) {
            return jerr(StatusCode::BAD_REQUEST, &format!("bad metadata key: {k}"));
        }
        merged.insert(k.to_ascii_lowercase(), v.clone());
    }
    let mut hs: Vec<(String, String)> = merged
        .iter()
        .map(|(k, v)| (format!("X-Object-Meta-{}", k), v.clone()))
        .collect();
    let ctype = body
        .content_type
        .clone()
        .filter(|c| !c.is_empty())
        .or_else(|| header_str(&cur, "content-type"));
    if let Some(ct) = ctype {
        hs.push(("Content-Type".into(), ct));
    }
    let is_slo = header_str(&cur, "x-static-large-object")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let cur_delete_at = header_str(&cur, "x-delete-at");
    // Desired expiry after this edit: explicit value, explicit clear, or keep.
    let want_delete_at: Option<String> = match &body.delete_at {
        Some(v) if v.is_empty() => None,
        Some(v) => {
            if v.parse::<u64>().is_err() {
                return jerr(StatusCode::BAD_REQUEST, "delete_at must be a unix timestamp");
            }
            Some(v.clone())
        }
        None => cur_delete_at.clone(),
    };
    // This cluster build persists X-Delete-At on PUT but not on POST, so any
    // edit that must end with an expiry set goes through a self-copy PUT.
    // A plain POST (replace-all) clears expiry, which covers the clear case.
    if let Some(da) = &want_delete_at {
        if is_slo {
            return jerr(
                StatusCode::BAD_REQUEST,
                "expiry on segmented (SLO) objects is not supported by this cluster build yet: copy-preserving-manifest is not deployed",
            );
        }
        hs.push(("X-Delete-At".into(), da.clone()));
        hs.push((
            "X-Copy-From".into(),
            format!("/{}/{}", enc_seg(&bucket), enc_obj(&path)),
        ));
        match swift::call(&state, &sid, Method::PUT, &sub, &[], &hs, Some(Bytes::new())).await {
            Ok(r) if r.status().is_success() => return jok(json!({ "ok": true })),
            Ok(r) => {
                let st = r.status().as_u16();
                let msg = r.text().await.unwrap_or_default();
                return jerr(
                    StatusCode::BAD_GATEWAY,
                    &format!("update failed ({st}): {}", msg.trim()),
                );
            }
            Err(e) => return from_swift_err(e),
        }
    }
    match swift::call(&state, &sid, Method::POST, &sub, &[], &hs, None).await {
        Ok(r) if r.status().is_success() => jok(json!({ "ok": true })),
        Ok(r) => {
            let st = r.status().as_u16();
            let msg = r.text().await.unwrap_or_default();
            jerr(
                StatusCode::BAD_GATEWAY,
                &format!("update failed ({st}): {}", msg.trim()),
            )
        }
        Err(e) => from_swift_err(e),
    }
}

// ------------------------------------------------------------- download / zip

pub async fn download(
    State(state): State<Arc<AppState>>,
    Path((bucket, path)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let (sid, _) = match session::from_headers(&state.sessions, &headers) {
        Some(v) => v,
        None => return Redirect::to("/login").into_response(),
    };
    let mut hs: Vec<(String, String)> = Vec::new();
    if let Some(range) = headers.get(header::RANGE).and_then(|v| v.to_str().ok()) {
        hs.push(("Range".into(), range.to_string()));
    }
    let sub = swift::obj_subpath(&bucket, &path);
    let resp = match swift::call(&state, &sid, Method::GET, &sub, &[], &hs, None).await {
        Ok(r) => r,
        Err(SwiftError::Unauthorized) => return Redirect::to("/login").into_response(),
        Err(e) => return jerr(StatusCode::BAD_GATEWAY, &e.msg()),
    };
    let st = resp.status().as_u16();
    if st == 404 {
        return (StatusCode::NOT_FOUND, "object not found\n").into_response();
    }
    if st >= 300 {
        return (
            StatusCode::BAD_GATEWAY,
            format!("download failed ({st})\n"),
        )
            .into_response();
    }
    let fname = path.rsplit('/').next().unwrap_or("download").to_string();
    let mut builder = Response::builder().status(st);
    {
        let out = builder.headers_mut().expect("headers");
        for key in ["content-type", "content-length", "content-range", "etag", "last-modified"] {
            if let Some(v) = resp.headers().get(key) {
                if let (Ok(hn), Ok(hv)) = (
                    header::HeaderName::from_bytes(key.as_bytes()),
                    header::HeaderValue::from_bytes(value_bytes(v)),
                ) {
                    out.insert(hn, hv);
                }
            }
        }
        if let Ok(hv) = header::HeaderValue::from_str(&format!(
            "attachment; filename*=UTF-8''{}",
            enc_seg(&fname)
        )) {
            out.insert(header::CONTENT_DISPOSITION, hv);
        }
        out.insert(
            header::HeaderName::from_static("x-content-type-options"),
            header::HeaderValue::from_static("nosniff"),
        );
    }
    builder
        .body(Body::from_stream(resp.bytes_stream()))
        .unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response())
}

fn value_bytes(v: &reqwest::header::HeaderValue) -> &[u8] {
    v.as_bytes()
}

const ZIP_MAX_TOTAL: u64 = 2 * 1024 * 1024 * 1024; // spool cap
const ZIP_MAX_ENTRIES: usize = 65000;

pub async fn zip_download(
    State(state): State<Arc<AppState>>,
    Path(bucket): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let (sid, _) = match session::from_headers(&state.sessions, &headers) {
        Some(v) => v,
        None => return Redirect::to("/login").into_response(),
    };
    let prefix = q.get("prefix").cloned().unwrap_or_default();
    let l = match swift::list_objects(&state, &sid, &bucket, &prefix, true, ZIP_MAX_ENTRIES).await
    {
        Ok(l) => l,
        Err(e) => return jerr(StatusCode::BAD_GATEWAY, &e.msg()),
    };
    if l.truncated || l.files.len() > ZIP_MAX_ENTRIES {
        return jerr(
            StatusCode::PAYLOAD_TOO_LARGE,
            "too many objects for a zip download",
        );
    }
    let total: u64 = l.files.iter().map(|f| f.bytes).sum();
    if total > ZIP_MAX_TOTAL {
        return jerr(
            StatusCode::PAYLOAD_TOO_LARGE,
            "folder is too large for a zip download (2 GiB cap)",
        );
    }
    // Entry names are relative to the parent of the prefix, so the zip
    // contains the folder itself.
    let parent = match prefix.trim_end_matches('/').rfind('/') {
        Some(i) if !prefix.is_empty() => prefix[..=i].to_string(),
        _ => String::new(),
    };
    let spool_path = std::env::temp_dir().join(format!("swift-console-zip-{}", rand_hex(8)));
    let file = match tokio::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&spool_path)
        .await
    {
        Ok(f) => f,
        Err(e) => return jerr(StatusCode::INTERNAL_SERVER_ERROR, &format!("spool: {e}")),
    };
    // Unlink immediately; the open handle keeps it alive.
    let _ = std::fs::remove_file(&spool_path);
    let mut zw = ZipWriter::new(file);
    for f in &l.files {
        let name = match &f.name {
            Some(n) => n.clone(),
            None => continue,
        };
        // Skip pseudo-folder markers.
        if f.bytes == 0
            && f.content_type
                .as_deref()
                .map(|c| c.starts_with("application/directory"))
                .unwrap_or(false)
        {
            continue;
        }
        let entry_name = name.strip_prefix(&parent).unwrap_or(&name).to_string();
        if let Err(e) = zw.begin_entry(&entry_name).await {
            return jerr(StatusCode::INTERNAL_SERVER_ERROR, &format!("zip: {e}"));
        }
        let sub = swift::obj_subpath(&bucket, &name);
        let mut resp = match swift::call(&state, &sid, Method::GET, &sub, &[], &[], None).await {
            Ok(r) if r.status().is_success() => r,
            Ok(r) => {
                return jerr(
                    StatusCode::BAD_GATEWAY,
                    &format!("failed reading {} ({})", name, r.status().as_u16()),
                )
            }
            Err(e) => return jerr(StatusCode::BAD_GATEWAY, &e.msg()),
        };
        let mut crc = Crc32::new();
        let mut size = 0u64;
        loop {
            match resp.chunk().await {
                Ok(Some(chunk)) => {
                    size += chunk.len() as u64;
                    if let Err(e) = zw.entry_data(&chunk, &mut crc).await {
                        return jerr(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            &format!("zip write: {e}"),
                        );
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    return jerr(StatusCode::BAD_GATEWAY, &format!("read {}: {e}", name))
                }
            }
        }
        if let Err(e) = zw.end_entry(crc, size).await {
            return jerr(StatusCode::INTERNAL_SERVER_ERROR, &format!("zip: {e}"));
        }
    }
    let (mut file, total) = match zw.finish().await {
        Ok(v) => v,
        Err(e) => return jerr(StatusCode::INTERNAL_SERVER_ERROR, &format!("zip: {e}")),
    };
    use tokio::io::AsyncSeekExt;
    if let Err(e) = file.seek(std::io::SeekFrom::Start(0)).await {
        return jerr(StatusCode::INTERNAL_SERVER_ERROR, &format!("zip: {e}"));
    }
    let zip_name = if prefix.is_empty() {
        format!("{}.zip", bucket)
    } else {
        format!(
            "{}.zip",
            prefix.trim_end_matches('/').rsplit('/').next().unwrap_or(&bucket)
        )
    };
    let stream = tokio_util::io::ReaderStream::new(file);
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/zip")
        .header(header::CONTENT_LENGTH, total)
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename*=UTF-8''{}", enc_seg(&zip_name)),
        )
        .body(Body::from_stream(stream))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

// ------------------------------------------------------------- sharing

#[derive(Deserialize)]
pub struct TempUrlReq {
    bucket: String,
    path: String,
    expiry_secs: Option<u64>,
}

async fn ensure_tempurl_key(
    state: &Arc<AppState>,
    sid: &str,
) -> Result<String, Response> {
    let (st, h) = swift::head(state, sid, "").await.map_err(from_swift_err)?;
    if st >= 300 {
        return Err(jerr(
            StatusCode::BAD_GATEWAY,
            &format!("account HEAD failed ({st})"),
        ));
    }
    if let Some(k) = header_str(&h, "x-account-meta-temp-url-key") {
        if !k.is_empty() {
            return Ok(k);
        }
    }
    let key = rand_hex(16);
    let hs = vec![("X-Account-Meta-Temp-URL-Key".to_string(), key.clone())];
    let r = swift::call(state, sid, Method::POST, "", &[], &hs, None)
        .await
        .map_err(from_swift_err)?;
    if !r.status().is_success() {
        return Err(jerr(
            StatusCode::BAD_GATEWAY,
            &format!("could not set temp url key ({})", r.status().as_u16()),
        ));
    }
    Ok(key)
}

pub async fn tempurl_make(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<TempUrlReq>,
) -> Response {
    let (sid, sess) = match need_session(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let key = match ensure_tempurl_key(&state, &sid).await {
        Ok(k) => k,
        Err(r) => return r,
    };
    let expiry = body.expiry_secs.unwrap_or(sess.tempurl_default_secs).max(60);
    let expires = now_secs() + expiry;
    // Signature is over the decoded path, as the middleware sees it.
    let acct_path = match sess.storage_url.find("/v1/") {
        Some(i) => sess.storage_url[i..].to_string(),
        None => return jerr(StatusCode::INTERNAL_SERVER_ERROR, "bad storage url"),
    };
    let sig_path = format!("{}/{}/{}", acct_path, body.bucket, body.path);
    let msg = format!("GET\n{}\n{}", expires, sig_path);
    let sig = hmac_sha1_hex(key.as_bytes(), msg.as_bytes());
    let url = format!(
        "{}/{}/{}?temp_url_sig={}&temp_url_expires={}",
        sess.storage_url,
        enc_seg(&body.bucket),
        enc_obj(&body.path),
        sig,
        expires
    );
    jok(json!({ "url": url, "expires": expires, "expiry_secs": expiry }))
}

pub async fn tempurl_key_get(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let (sid, sess) = match need_session(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    match swift::head(&state, &sid, "").await {
        Ok((st, h)) if st < 300 => jok(json!({
            "key_set": header_str(&h, "x-account-meta-temp-url-key").map(|k| !k.is_empty()).unwrap_or(false),
            "default_expiry_secs": sess.tempurl_default_secs,
        })),
        Ok((st, _)) => jerr(StatusCode::BAD_GATEWAY, &format!("HEAD failed ({st})")),
        Err(e) => from_swift_err(e),
    }
}

#[derive(Deserialize, Default)]
pub struct TempUrlKeySet {
    key: Option<String>,
    default_expiry_secs: Option<u64>,
}

pub async fn tempurl_key_set(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<TempUrlKeySet>,
) -> Response {
    let (sid, _) = match need_session(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let mut out = json!({ "ok": true });
    if let Some(k) = &body.key {
        let key = if k.is_empty() { rand_hex(16) } else { k.clone() };
        let hs = vec![("X-Account-Meta-Temp-URL-Key".to_string(), key.clone())];
        match swift::call(&state, &sid, Method::POST, "", &[], &hs, None).await {
            Ok(r) if r.status().is_success() => {
                out["key"] = json!(key);
            }
            Ok(r) => {
                return jerr(
                    StatusCode::BAD_GATEWAY,
                    &format!("could not set key ({})", r.status().as_u16()),
                )
            }
            Err(e) => return from_swift_err(e),
        }
    }
    if let Some(secs) = body.default_expiry_secs {
        let secs = secs.clamp(60, 30 * 24 * 3600);
        state.sessions.set_tempurl_default(&sid, secs);
        out["default_expiry_secs"] = json!(secs);
    }
    jok(out)
}

// ------------------------------------------------------------- trash

async fn ensure_trash(state: &Arc<AppState>, sid: &str) -> Result<(), Response> {
    let sub = format!("/{}", enc_seg(TRASH));
    let r = swift::call(state, sid, Method::PUT, &sub, &[], &[], None)
        .await
        .map_err(from_swift_err)?;
    if r.status().is_success() {
        Ok(())
    } else {
        Err(jerr(
            StatusCode::BAD_GATEWAY,
            &format!("could not create trash container ({})", r.status().as_u16()),
        ))
    }
}

async fn copy_object(
    state: &Arc<AppState>,
    sid: &str,
    from_bucket: &str,
    from_path: &str,
    to_bucket: &str,
    to_path: &str,
) -> Result<(), Response> {
    let dst = swift::obj_subpath(to_bucket, to_path);
    let src = format!("/{}/{}", enc_seg(from_bucket), enc_obj(from_path));
    let hs = vec![("X-Copy-From".to_string(), src)];
    let r = swift::call(state, sid, Method::PUT, &dst, &[], &hs, Some(Bytes::new()))
        .await
        .map_err(from_swift_err)?;
    if r.status().is_success() {
        Ok(())
    } else {
        let st = r.status().as_u16();
        Err(jerr(
            StatusCode::BAD_GATEWAY,
            &format!("copy {}/{} failed ({st})", from_bucket, from_path),
        ))
    }
}

async fn delete_object(
    state: &Arc<AppState>,
    sid: &str,
    bucket: &str,
    path: &str,
) -> Result<(), Response> {
    let sub = swift::obj_subpath(bucket, path);
    let r = swift::call(state, sid, Method::DELETE, &sub, &[], &[], None)
        .await
        .map_err(from_swift_err)?;
    if r.status().is_success() || r.status().as_u16() == 404 {
        Ok(())
    } else {
        Err(jerr(
            StatusCode::BAD_GATEWAY,
            &format!("delete {}/{} failed ({})", bucket, path, r.status().as_u16()),
        ))
    }
}

#[derive(Deserialize)]
pub struct TrashMove {
    bucket: String,
    path: Option<String>,
    prefix: Option<String>,
}

pub async fn trash_move(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<TrashMove>,
) -> Response {
    let (sid, _) = match need_session(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    if body.bucket == TRASH {
        return jerr(StatusCode::BAD_REQUEST, "cannot trash the trash");
    }
    if let Err(r) = ensure_trash(&state, &sid).await {
        return r;
    }
    let mut moved = 0u64;
    let mut targets: Vec<String> = Vec::new();
    if let Some(p) = &body.path {
        targets.push(p.clone());
    } else if let Some(prefix) = &body.prefix {
        let mut prefix = prefix.clone();
        if !prefix.ends_with('/') {
            prefix.push('/');
        }
        let l = match swift::list_objects(&state, &sid, &body.bucket, &prefix, true, 100000).await
        {
            Ok(l) => l,
            Err(e) => return from_swift_err(e),
        };
        targets = l.files.iter().filter_map(|f| f.name.clone()).collect();
    } else {
        return jerr(StatusCode::BAD_REQUEST, "path or prefix required");
    }
    for t in &targets {
        let trash_path = format!("{}/{}", body.bucket, t);
        if let Err(r) = copy_object(&state, &sid, &body.bucket, t, TRASH, &trash_path).await {
            return r;
        }
        if let Err(r) = delete_object(&state, &sid, &body.bucket, t).await {
            return r;
        }
        moved += 1;
    }
    jok(json!({ "ok": true, "moved": moved }))
}

pub async fn trash_list(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let (sid, _) = match need_session(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    match swift::list_objects(&state, &sid, TRASH, "", true, 100000).await {
        Ok(l) => {
            let items: Vec<Value> = l
                .files
                .iter()
                .map(|f| {
                    json!({
                        "name": f.name,
                        "bytes": f.bytes,
                        "last_modified": f.last_modified,
                        "content_type": f.content_type,
                    })
                })
                .collect();
            jok(json!({ "items": items }))
        }
        Err(SwiftError::Other(m)) if m.contains("not found") => jok(json!({ "items": [] })),
        Err(e) => from_swift_err(e),
    }
}

#[derive(Deserialize)]
pub struct TrashTarget {
    path: Option<String>,
    prefix: Option<String>,
}

fn trash_targets_from<'a>(body: &'a TrashTarget) -> Result<(&'a str, bool), Response> {
    if let Some(p) = &body.path {
        Ok((p.as_str(), false))
    } else if let Some(p) = &body.prefix {
        Ok((p.as_str(), true))
    } else {
        Err(jerr(StatusCode::BAD_REQUEST, "path or prefix required"))
    }
}

async fn trash_expand(
    state: &Arc<AppState>,
    sid: &str,
    target: &str,
    is_prefix: bool,
) -> Result<Vec<String>, Response> {
    if !is_prefix {
        return Ok(vec![target.to_string()]);
    }
    let mut prefix = target.to_string();
    if !prefix.ends_with('/') {
        prefix.push('/');
    }
    let l = swift::list_objects(state, sid, TRASH, &prefix, true, 100000)
        .await
        .map_err(from_swift_err)?;
    Ok(l.files.iter().filter_map(|f| f.name.clone()).collect())
}

pub async fn trash_restore(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<TrashTarget>,
) -> Response {
    let (sid, _) = match need_session(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let (target, is_prefix) = match trash_targets_from(&body) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let entries = match trash_expand(&state, &sid, target, is_prefix).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let mut restored = 0u64;
    for entry in &entries {
        let (bucket, rest) = match entry.split_once('/') {
            Some(v) => v,
            None => continue,
        };
        // Recreate the original bucket if needed.
        let sub = format!("/{}", enc_seg(bucket));
        match swift::call(&state, &sid, Method::PUT, &sub, &[], &[], None).await {
            Ok(r) if r.status().is_success() => {}
            Ok(r) => {
                return jerr(
                    StatusCode::BAD_GATEWAY,
                    &format!("could not ensure bucket {} ({})", bucket, r.status().as_u16()),
                )
            }
            Err(e) => return from_swift_err(e),
        }
        if let Err(r) = copy_object(&state, &sid, TRASH, entry, bucket, rest).await {
            return r;
        }
        if let Err(r) = delete_object(&state, &sid, TRASH, entry).await {
            return r;
        }
        restored += 1;
    }
    jok(json!({ "ok": true, "restored": restored }))
}

pub async fn trash_delete(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<TrashTarget>,
) -> Response {
    let (sid, _) = match need_session(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let (target, is_prefix) = match trash_targets_from(&body) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let entries = match trash_expand(&state, &sid, target, is_prefix).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let mut deleted = 0u64;
    for entry in &entries {
        if let Err(r) = delete_object(&state, &sid, TRASH, entry).await {
            return r;
        }
        deleted += 1;
    }
    jok(json!({ "ok": true, "deleted": deleted }))
}

pub async fn trash_empty(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let (sid, _) = match need_session(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let l = match swift::list_objects(&state, &sid, TRASH, "", true, 100000).await {
        Ok(l) => l,
        Err(SwiftError::Other(m)) if m.contains("not found") => {
            return jok(json!({ "ok": true, "deleted": 0 }))
        }
        Err(e) => return from_swift_err(e),
    };
    let mut deleted = 0u64;
    for f in &l.files {
        if let Some(name) = &f.name {
            if let Err(r) = delete_object(&state, &sid, TRASH, name).await {
                return r;
            }
            deleted += 1;
        }
    }
    jok(json!({ "ok": true, "deleted": deleted }))
}

// ------------------------------------------------------------- account

pub async fn account_get(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let (sid, _) = match need_session(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    match swift::head(&state, &sid, "").await {
        Ok((st, h)) if st < 300 => {
            let mut meta = meta_map(&h, "x-account-meta-");
            let quota = meta.remove("quota-bytes");
            let temp_key_set = meta
                .remove("temp-url-key")
                .map(|k| !k.is_empty())
                .unwrap_or(false);
            meta.remove("temp-url-key-2");
            jok(json!({
                "bytes_used": header_str(&h, "x-account-bytes-used"),
                "container_count": header_str(&h, "x-account-container-count"),
                "object_count": header_str(&h, "x-account-object-count"),
                "quota_bytes": quota,
                "meta": meta,
                "temp_url_key_set": temp_key_set,
            }))
        }
        Ok((st, _)) => jerr(StatusCode::BAD_GATEWAY, &format!("HEAD failed ({st})")),
        Err(e) => from_swift_err(e),
    }
}

#[derive(Deserialize, Default)]
pub struct AccountSet {
    #[serde(default)]
    set: HashMap<String, String>,
    #[serde(default)]
    remove: Vec<String>,
    quota_bytes: Option<String>,
}

pub async fn account_set(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<AccountSet>,
) -> Response {
    let (sid, _) = match need_session(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let mut hs: Vec<(String, String)> = Vec::new();
    for (k, v) in &body.set {
        if !valid_meta_key(k) {
            return jerr(StatusCode::BAD_REQUEST, &format!("bad metadata key: {k}"));
        }
        hs.push((format!("X-Account-Meta-{}", k), v.clone()));
    }
    for k in &body.remove {
        if !valid_meta_key(k) {
            return jerr(StatusCode::BAD_REQUEST, &format!("bad metadata key: {k}"));
        }
        hs.push((format!("X-Account-Meta-{}", k), String::new()));
    }
    if let Some(qb) = &body.quota_bytes {
        if qb.is_empty() {
            hs.push(("X-Account-Meta-Quota-Bytes".into(), String::new()));
        } else {
            hs.push(("X-Account-Meta-Quota-Bytes".into(), qb.clone()));
        }
    }
    if hs.is_empty() {
        return jerr(StatusCode::BAD_REQUEST, "nothing to change");
    }
    match swift::call(&state, &sid, Method::POST, "", &[], &hs, None).await {
        Ok(r) if r.status().is_success() => jok(json!({ "ok": true })),
        Ok(r) if r.status().as_u16() == 403 => jerr(
            StatusCode::FORBIDDEN,
            "rejected by the cluster: account quotas can only be set by a reseller admin (deployed configuration)",
        ),
        Ok(r) => {
            let st = r.status().as_u16();
            let msg = r.text().await.unwrap_or_default();
            jerr(
                StatusCode::BAD_GATEWAY,
                &format!("update failed ({st}): {}", msg.trim()),
            )
        }
        Err(e) => from_swift_err(e),
    }
}
