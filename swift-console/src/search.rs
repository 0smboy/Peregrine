//! Object metadata search.
//!
//! Swift has no native metadata query, so the console builds a per-account
//! index. The fast tier comes straight from container listings (name, size,
//! content-type, last-modified, etag — no per-object request). An optional deep
//! pass HEADs objects to pull custom `X-Object-Meta-*` into the index so they
//! can be searched too. The index lives in memory keyed by account and is
//! rebuilt on demand.

use crate::files_api::TRASH;
use crate::session;
use crate::swift::{self, SwiftError};
use crate::AppState;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Instant;

const DEEP_HEAD_CAP: usize = 4000;
const PER_CONTAINER_CAP: usize = 100_000;
const MAX_RESULTS: usize = 500;

#[derive(Clone)]
pub struct Entry {
    pub container: String,
    pub name: String,
    pub bytes: u64,
    pub content_type: String,
    pub last_modified: String,
    pub etag: String,
    pub meta: BTreeMap<String, String>,
}

pub struct AccountIndex {
    pub entries: Vec<Entry>,
    pub built: Instant,
    pub truncated: bool,
    pub deep: bool,
}

pub type IndexStore = std::sync::Mutex<HashMap<String, AccountIndex>>;

pub fn new_store() -> IndexStore {
    std::sync::Mutex::new(HashMap::new())
}

// ------------------------------------------------------------- crawl

async fn crawl(state: &Arc<AppState>, sid: &str, deep: bool) -> Result<AccountIndex, SwiftError> {
    let buckets = swift::list_buckets(state, sid).await?;
    let mut entries = Vec::new();
    let mut truncated = false;
    for b in &buckets {
        // Skip console-internal containers.
        if b.name == TRASH || b.name.ends_with("_segments") {
            continue;
        }
        let listing = swift::list_objects(state, sid, &b.name, "", true, PER_CONTAINER_CAP).await?;
        if listing.truncated {
            truncated = true;
        }
        for f in listing.files {
            let name = match f.name {
                Some(n) => n,
                None => continue,
            };
            entries.push(Entry {
                container: b.name.clone(),
                name,
                bytes: f.bytes,
                content_type: f.content_type.unwrap_or_default(),
                last_modified: f.last_modified.unwrap_or_default(),
                etag: f.hash.unwrap_or_default(),
                meta: BTreeMap::new(),
            });
        }
    }
    if deep {
        let head_n = entries.len().min(DEEP_HEAD_CAP);
        if entries.len() > DEEP_HEAD_CAP {
            truncated = true;
        }
        for i in 0..head_n {
            let sub = swift::obj_subpath(&entries[i].container, &entries[i].name);
            if let Ok((st, h)) = swift::head(state, sid, &sub).await {
                if st < 300 {
                    for (k, v) in h.iter() {
                        let kn = k.as_str().to_ascii_lowercase();
                        if let Some(mk) = kn.strip_prefix("x-object-meta-") {
                            entries[i]
                                .meta
                                .insert(mk.to_string(), v.to_str().unwrap_or("").to_string());
                        }
                    }
                }
            }
        }
    }
    Ok(AccountIndex {
        entries,
        built: Instant::now(),
        truncated,
        deep,
    })
}

// ------------------------------------------------------------- handlers

fn session_or_401(state: &Arc<AppState>, headers: &HeaderMap) -> Result<(String, session::Session), Response> {
    session::from_headers(&state.sessions, headers)
        .ok_or_else(|| (axum::http::StatusCode::UNAUTHORIZED, "session required").into_response())
}

#[derive(Deserialize)]
pub struct ReindexQ {
    #[serde(default)]
    deep: String,
}

pub async fn reindex(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<ReindexQ>,
) -> Response {
    let (sid, sess) = match session_or_401(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let deep = matches!(q.deep.as_str(), "1" | "true" | "yes" | "on");
    match crawl(&state, &sid, deep).await {
        Ok(idx) => {
            let out = json!({
                "count": idx.entries.len(),
                "truncated": idx.truncated,
                "deep": idx.deep,
            });
            state.search.lock().unwrap().insert(sess.tenant.clone(), idx);
            Json(out).into_response()
        }
        Err(e) => (axum::http::StatusCode::BAD_GATEWAY, Json(json!({ "error": e.msg() }))).into_response(),
    }
}

#[derive(Deserialize)]
pub struct SearchQ {
    #[serde(default)]
    q: String,
    #[serde(default)]
    container: String,
    #[serde(default)]
    ctype: String,
    #[serde(default)]
    min: Option<u64>,
    #[serde(default)]
    max: Option<u64>,
    #[serde(default)]
    metakey: String,
    #[serde(default)]
    metaval: String,
    #[serde(default)]
    from: String,
    #[serde(default)]
    to: String,
}

fn ci_contains(hay: &str, needle: &str) -> bool {
    needle.is_empty() || hay.to_lowercase().contains(&needle.to_lowercase())
}

pub async fn search(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(f): Query<SearchQ>,
) -> Response {
    let (_, sess) = match session_or_401(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let store = state.search.lock().unwrap();
    let idx = match store.get(&sess.tenant) {
        Some(i) => i,
        None => return Json(json!({ "needs_index": true })).into_response(),
    };
    let metakey = f.metakey.trim().to_lowercase();
    let mut hits: Vec<Value> = Vec::new();
    let mut total = 0usize;
    for e in &idx.entries {
        if !ci_contains(&e.name, &f.q) {
            continue;
        }
        if !f.container.is_empty() && e.container != f.container {
            continue;
        }
        if !ci_contains(&e.content_type, &f.ctype) {
            continue;
        }
        if let Some(mn) = f.min {
            if e.bytes < mn {
                continue;
            }
        }
        if let Some(mx) = f.max {
            if e.bytes > mx {
                continue;
            }
        }
        if !f.from.is_empty() && e.last_modified.as_str() < f.from.as_str() {
            continue;
        }
        if !f.to.is_empty() && !e.last_modified.is_empty() && e.last_modified.as_str() > f.to.as_str() {
            continue;
        }
        if !metakey.is_empty() {
            match e.meta.get(&metakey) {
                Some(v) if ci_contains(v, &f.metaval) => {}
                _ => continue,
            }
        } else if !f.metaval.trim().is_empty() {
            // value given without a key: match any meta value
            if !e.meta.values().any(|v| ci_contains(v, &f.metaval)) {
                continue;
            }
        }
        total += 1;
        if hits.len() < MAX_RESULTS {
            let meta: BTreeMap<&String, &String> = e.meta.iter().collect();
            hits.push(json!({
                "container": e.container,
                "name": e.name,
                "bytes": e.bytes,
                "content_type": e.content_type,
                "last_modified": e.last_modified,
                "etag": e.etag,
                "meta": meta,
            }));
        }
    }
    Json(json!({
        "results": hits,
        "total": total,
        "shown": hits.len(),
        "index": {
            "count": idx.entries.len(),
            "built_secs_ago": idx.built.elapsed().as_secs(),
            "truncated": idx.truncated,
            "deep": idx.deep,
        }
    }))
    .into_response()
}

/// Status of an account's index, for the page's initial render.
pub fn index_status(state: &Arc<AppState>, account: &str) -> Option<Value> {
    let store = state.search.lock().unwrap();
    store.get(account).map(|idx| {
        json!({
            "count": idx.entries.len(),
            "built_secs_ago": idx.built.elapsed().as_secs(),
            "truncated": idx.truncated,
            "deep": idx.deep,
        })
    })
}
