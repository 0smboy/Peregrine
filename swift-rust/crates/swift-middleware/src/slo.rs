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

//! Static Large Object (SLO) manifest arithmetic, ported from
//! `swift/common/middleware/slo.py`.
//!
//! An SLO is an object whose body is a JSON manifest listing segments; a GET
//! reassembles the segments into one stream. Two values are compatibility
//! contracts that must match Python byte-for-byte, because they are persisted
//! and validated across proxies:
//!
//! * the **SLO Etag** — `md5` over each segment's contribution (the segment's
//!   hash, or `"{hash}:{range};"` for a ranged segment, or `md5(raw_data)` for
//!   an inline data segment), and
//! * the **manifest Etag** — `md5` of the stored manifest JSON bytes.
//!
//! Both are golden-tested here. GET reassembly streams leaf segments
//! (including nested `sub_slo` expansion up to [`MAX_SLO_RECURSION_DEPTH`])
//! and honours a single top-level `Range` via per-segment ranged
//! subrequests. PUT validates/normalizes client manifests (HEAD each
//! segment, including sub-SLO sysmeta; inline `{"data":…}` base64 segments).
//! Also: `?multipart-manifest=delete` (sync segment+manifest delete, or
//! `async=yes` expirer enqueue + manifest DELETE), and `heartbeat=on` PUT
//! responses that stream whitespace during segment HEAD validation.
//!
//! Async delete matches Python on:
//! * **Expirer task container** — `ExpirerConfig.get_expirer_container`:
//!   `day_bucket - (int(hash_path(acc, cont, obj), 16) % 100)`, zero-padded
//!   via `normalize_delete_at_timestamp` (shard key = **manifest** a/c/o).
//! * **Write ACL probes** — HEAD on the manifest container and (when different)
//!   the segment container; 401/403 short-circuit like authorize + `write_acl`.
//!
//! **Concurrency:** PUT segment HEAD uses up to `concurrent_gets` threads
//! (default 10). Heartbeat whitespace respects `yield_frequency` (seconds
//! between yields; default 10). Container listing SLO-etag refetch is
//! available via [`refetch_listing_slo_etag`]. bulk Accept negotiation on
//! delete beyond JSON is residual. When the expirer `UPDATE` enqueue fails,
//! a best-effort background segment-DELETE thread is used instead of
//! Python's bare 503.

use std::future::Future;
use std::io::{Cursor, Read};
use std::pin::Pin;
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use md5::{Digest, Md5};
use swift_core::config::config_true_value;
use swift_core::hashing::HashPathConfig;
use swift_core::timestamp::{normalize_delete_at_timestamp, Timestamp};
use swift_http::{
    body_too_large, split_path, Body, FnReader, HeaderKeyDict, Range, Request, Response,
    MAX_CONTROL_BODY,
};

use crate::{AsyncNextFn, Middleware, NextFn};

/// `max_manifest_size` (Python slo.py default): the client manifest on a
/// `?multipart-manifest=put` may not exceed this.
const MAX_MANIFEST_SIZE: u64 = 8 * 1024 * 1024;

/// `max_manifest_segments` (Python slo.py default and the value advertised
/// by `/info`). Inline-data entries are deliberately excluded from this
/// limit; only entries that name an object-backed segment count.
const MAX_MANIFEST_SEGMENTS: usize = 1000;

/// Python `SloGetContext.max_slo_recursion_depth` — nested `sub_slo`
/// expansion beyond this depth is a 409 Conflict.
const MAX_SLO_RECURSION_DEPTH: usize = 10;

const SLO_HEADER: &str = "X-Static-Large-Object";
const MANIFEST_ETAG_HEADER: &str = "X-Manifest-Etag";
const IGNORE_RANGE_HDR: &str = "X-Backend-Ignore-Range-If-Metadata-Present";
const SYSMETA_SLO_ETAG: &str = "X-Object-Sysmeta-Slo-Etag";
const SYSMETA_SLO_SIZE: &str = "X-Object-Sysmeta-Slo-Size";

/// Default expirer account (Python `EXPIRER_ACCOUNT_NAME`).
const EXPIRER_ACCOUNT: &str = ".expiring_objects";
/// Default `expiring_objects_container_divisor` (one bucket per day).
const EXPIRER_CONTAINER_DIVISOR: i64 = 86400;
/// Content-type of async-delete expirer jobs (Python `ASYNC_DELETE_TYPE`).
const ASYNC_DELETE_TYPE: &str = "application/async-deleted";
/// md5 of empty string — etag on zero-byte async-delete task records.
const MD5_OF_EMPTY_STRING: &str = "d41d8cd98f00b204e9800998ecf8427e";

/// One entry in a validated SLO manifest, as far as the Etag/size calculation
/// is concerned.
#[derive(Debug, Clone, PartialEq)]
pub struct SloSegment {
    /// The segment object's Etag (its `hash`).
    pub hash: String,
    /// The number of bytes this segment contributes to the SLO.
    pub segment_length: i64,
    /// `Some("first-last")` for a ranged segment.
    pub range: Option<String>,
    /// Inline data (a `{"data": ...}` segment); its md5 is used instead of a
    /// stored hash.
    pub raw_data: Option<Vec<u8>>,
}

impl SloSegment {
    /// A plain whole-object segment.
    pub fn whole(hash: &str, length: i64) -> SloSegment {
        SloSegment {
            hash: hash.to_string(),
            segment_length: length,
            range: None,
            raw_data: None,
        }
    }
}

fn md5_hex(data: &[u8]) -> String {
    let digest = Md5::digest(data);
    let mut out = String::with_capacity(32);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Compute `(slo_etag, slo_size)` from the manifest segments, exactly as
/// `SloGetContext._get_manifest_read` / the manifest builder does: the size is
/// the sum of segment lengths, and the Etag is the md5 of each segment's
/// contribution concatenated in order.
pub fn slo_etag_and_size(segments: &[SloSegment]) -> (String, i64) {
    let mut size = 0i64;
    let mut hasher = Md5::new();
    for seg in segments {
        size += seg.segment_length;
        let contribution = if let Some(raw) = &seg.raw_data {
            md5_hex(raw)
        } else if let Some(range) = &seg.range {
            format!("{}:{};", seg.hash, range)
        } else {
            seg.hash.clone()
        };
        hasher.update(contribution.as_bytes());
    }
    let digest = hasher.finalize();
    let mut etag = String::with_capacity(32);
    for b in digest {
        etag.push_str(&format!("{b:02x}"));
    }
    (etag, size)
}

/// The manifest object's own Etag: `md5` of the stored manifest JSON bytes.
pub fn manifest_etag(manifest_json: &[u8]) -> String {
    md5_hex(manifest_json)
}

/// `swob.normalize_etag`: strip a single pair of surrounding double quotes
/// from an Etag (but leave a lone `"` untouched).
pub fn normalize_etag(tag: &str) -> &str {
    if tag.len() > 1 && tag.starts_with('"') && tag.ends_with('"') {
        &tag[1..tag.len() - 1]
    } else {
        tag
    }
}

/// The Dynamic Large Object (DLO) Etag, ported from `dlo.py`: the md5 of the
/// concatenated (quote-normalized) segment hashes, wrapped in double quotes as
/// it appears in the `Etag` header. `segment_hashes` are the listed segments'
/// Etags in order; the returned size is the summed segment byte counts.
pub fn dlo_etag_and_size(segment_hashes: &[(String, i64)]) -> (String, i64) {
    let mut hasher = Md5::new();
    let mut size = 0i64;
    for (hash, bytes) in segment_hashes {
        hasher.update(normalize_etag(hash).as_bytes());
        size += bytes;
    }
    let digest = hasher.finalize();
    let mut etag = String::with_capacity(34);
    etag.push('"');
    for b in digest {
        etag.push_str(&format!("{b:02x}"));
    }
    etag.push('"');
    (etag, size)
}

/// Static Large Object middleware: reassembles a manifest object on GET/HEAD.
///
/// The stored manifest object body is a JSON array of segment dicts (`name`
/// like `"/container/object"`, `bytes`, `hash`, optional `range` `"M-N"`,
/// optional `sub_slo`); the response carries `X-Static-Large-Object: true`.
/// On a plain GET/HEAD (no `multipart-manifest=get`) this expands nested
/// `sub_slo` manifests (depth ≤ [`MAX_SLO_RECURSION_DEPTH`]), fetches each
/// leaf segment with a **subrequest**, and streams the concatenation,
/// setting `Content-Length` to the summed segment lengths and `Etag` to the
/// SLO etag. A single top-level `Range` uses per-segment ranged subrequests.
///
/// Residual vs. `slo.py`: container-listing slo_etag refetch (optional).
/// Async-delete uses expirer hash_path container sharding and write ACL probes.
#[derive(Debug, Clone)]
pub struct Slo {
    /// Cluster hash path config for expirer task-container sharding (Python
    /// `ExpirerConfig.get_expirer_container`). Default `suffix=changeme` for
    /// unit tests / SAIO-shaped conf.
    hash_config: HashPathConfig,
    /// Max concurrent segment HEADs on PUT (Python `concurrency`). 1 = serial.
    pub concurrent_gets: usize,
    /// Seconds between heartbeat whitespace yields (Python `yield_frequency`).
    pub yield_frequency: f64,
}

impl Default for Slo {
    fn default() -> Self {
        Self::new()
    }
}

impl Slo {
    pub fn new() -> Self {
        Slo {
            hash_config: HashPathConfig::new(b"".to_vec(), b"changeme".to_vec())
                .expect("non-empty hash suffix"),
            concurrent_gets: 10,
            // 0 = emit heartbeat whitespace after every segment HEAD (unit
            // default + Python-compatible when HEADs are fast). Positive
            // values throttle by wall-clock seconds (Python yield_frequency).
            yield_frequency: 0.0,
        }
    }

    /// Construct with explicit `[swift-hash]` config (proxy/production path).
    pub fn with_hash_config(hash_config: HashPathConfig) -> Self {
        Slo {
            hash_config,
            concurrent_gets: 10,
            yield_frequency: 0.0,
        }
    }

    pub fn with_concurrency(mut self, n: usize) -> Self {
        self.concurrent_gets = n.max(1);
        self
    }

    pub fn with_yield_frequency(mut self, secs: f64) -> Self {
        self.yield_frequency = secs.max(0.0);
        self
    }
}

/// Refetch SLO etag for a container listing row (Python listing etag dance).
///
/// When `hash` looks like an SLO etag (`…-N` suffix) or the row is marked
/// SLO, replace `hash` with `X-Object-Sysmeta-Slo-Etag` from a HEAD of the
/// object. Pure helper + HEAD callback for tests.
pub fn refetch_listing_slo_etag(
    name: &str,
    current_hash: &str,
    head_headers: &swift_http::HeaderKeyDict,
) -> Option<String> {
    let is_slo = head_headers
        .get(SLO_HEADER)
        .map(config_true_value)
        .unwrap_or(false);
    let looks_slo_hash = current_hash.contains('-')
        && current_hash
            .rsplit_once('-')
            .map(|(_, n)| n.chars().all(|c| c.is_ascii_digit()))
            .unwrap_or(false);
    if !is_slo && !looks_slo_hash {
        return None;
    }
    let _ = name;
    head_headers
        .get(SYSMETA_SLO_ETAG)
        .map(|s| s.trim().trim_matches('"').to_string())
        .filter(|s| !s.is_empty())
}

/// One entry parsed from a stored SLO manifest.
#[derive(Debug, Clone)]
struct StoredSeg {
    name: String,
    bytes: i64,
    hash: String,
    range: Option<String>,
    sub_slo: bool,
    /// Base64-encoded inline data as stored (`{"data":…}` segments).
    data_b64: Option<String>,
}

/// A leaf segment after nested `sub_slo` expansion — ready for a GET
/// subrequest (or inline bytes). `range` is an inclusive `start-end` within
/// the segment object; `bytes` is this leaf's contribution length.
#[derive(Debug, Clone)]
struct LeafSeg {
    name: String,
    bytes: i64,
    range: Option<String>,
    raw_data: Option<Vec<u8>>,
}

/// Contribution length of a stored segment (range-adjusted when present).
fn contrib_length(seg: &StoredSeg) -> i64 {
    if let Some(b64) = &seg.data_b64 {
        return match B64.decode(b64.as_bytes()) {
            Ok(raw) => raw.len() as i64,
            Err(_) => 0,
        };
    }
    if let Some(range) = &seg.range {
        if let Some((start, end)) = parse_inclusive_range(range) {
            return (end - start + 1) as i64;
        }
    }
    seg.bytes
}

/// Parse an inclusive `M-N` range string written into a stored SLO manifest.
fn parse_inclusive_range(range: &str) -> Option<(u64, u64)> {
    let (a, b) = range.split_once('-')?;
    let start = a.parse().ok()?;
    let end = b.parse().ok()?;
    if end < start {
        return None;
    }
    Some((start, end))
}

/// Expand nested `sub_slo` entries into leaf object segments by fetching
/// submanifests through `next` (post-SLO pipeline — raw stored JSON).
fn expand_segments(
    orig: &Request,
    version: &str,
    account: &str,
    segments: &[StoredSeg],
    next: &NextFn,
    depth: usize,
) -> Result<Vec<LeafSeg>, Response> {
    let mut out = Vec::new();
    for seg in segments {
        if let Some(b64) = &seg.data_b64 {
            let raw = B64
                .decode(b64.as_bytes())
                .map_err(|_| Response::error(409, "Conflict"))?;
            let length = raw.len() as i64;
            if length <= 0 {
                continue;
            }
            out.push(LeafSeg {
                name: String::new(),
                bytes: length,
                range: None,
                raw_data: Some(raw),
            });
            continue;
        }
        if seg.sub_slo {
            if depth >= MAX_SLO_RECURSION_DEPTH {
                return Err(Response::error(409, "Conflict"));
            }
            let path = format!("/{version}/{account}{}", seg.name);
            let sub = slo_subreq(orig, path.clone(), None);
            let mut sresp = next(sub);
            if !(200..300).contains(&sresp.status) {
                return Err(Response::error(409, "Conflict"));
            }
            let body = match sresp.body.materialize(MAX_CONTROL_BODY) {
                Ok(b) => b,
                Err(_) => return Err(Response::error(409, "Conflict")),
            };
            let Some(sub_segs) = parse_stored_manifest(body) else {
                return Err(Response::error(409, "Conflict"));
            };
            let mut nested = expand_segments(orig, version, account, &sub_segs, next, depth + 1)?;
            // A ranged sub_slo contributes only a window of the nested aggregate.
            if let Some(range) = &seg.range {
                let Some((start, end)) = parse_inclusive_range(range) else {
                    return Err(Response::error(409, "Conflict"));
                };
                nested = slice_leaves_for_range(&nested, start, end + 1)?;
            }
            out.extend(nested);
        } else {
            let length = contrib_length(seg);
            if length <= 0 {
                continue;
            }
            out.push(LeafSeg {
                name: seg.name.clone(),
                bytes: length,
                range: seg.range.clone(),
                raw_data: None,
            });
        }
    }
    Ok(out)
}

async fn expand_segments_async(
    orig: Request,
    version: String,
    account: String,
    segments: Vec<StoredSeg>,
    next: AsyncNextFn,
    depth: usize,
) -> Result<Vec<LeafSeg>, Response> {
    let mut out = Vec::new();
    for seg in segments {
        if let Some(b64) = &seg.data_b64 {
            let raw = B64
                .decode(b64.as_bytes())
                .map_err(|_| Response::error(409, "Conflict"))?;
            let length = raw.len() as i64;
            if length <= 0 {
                continue;
            }
            out.push(LeafSeg {
                name: String::new(),
                bytes: length,
                range: None,
                raw_data: Some(raw),
            });
            continue;
        }
        if seg.sub_slo {
            if depth >= MAX_SLO_RECURSION_DEPTH {
                return Err(Response::error(409, "Conflict"));
            }
            let path = format!("/{version}/{account}{}", seg.name);
            let sub = slo_subreq(&orig, path.clone(), None);
            let sresp = next(sub).await;
            if !(200..300).contains(&sresp.status) {
                return Err(Response::error(409, "Conflict"));
            }
            let body = match sresp.body.collect_async().await {
                Ok(b) => b,
                Err(_) => return Err(Response::error(409, "Conflict")),
            };
            let Some(sub_segs) = parse_stored_manifest(&body) else {
                return Err(Response::error(409, "Conflict"));
            };
            let mut nested = Box::pin(expand_segments_async(
                orig.clone_head(),
                version.clone(),
                account.clone(),
                sub_segs,
                next.clone(),
                depth + 1,
            ))
            .await?;
            if let Some(range) = &seg.range {
                let Some((start, end)) = parse_inclusive_range(range) else {
                    return Err(Response::error(409, "Conflict"));
                };
                nested = slice_leaves_for_range(&nested, start, end + 1)?;
            }
            out.extend(nested);
        } else {
            let length = contrib_length(&seg);
            if length <= 0 {
                continue;
            }
            out.push(LeafSeg {
                name: seg.name.clone(),
                bytes: length,
                range: seg.range.clone(),
                raw_data: None,
            });
        }
    }
    Ok(out)
}

async fn forward_body_chunks(
    body: Body,
    tx: &tokio::sync::mpsc::Sender<Result<Vec<u8>, std::io::Error>>,
) -> Result<(), ()> {
    match body {
        Body::Buffered(b) => {
            if !b.is_empty() && tx.send(Ok(b)).await.is_err() {
                return Err(());
            }
            Ok(())
        }
        Body::Channel(ch) => {
            let (mut rx, _scope, _) = ch.into_rx();
            while let Some(chunk) = rx.recv().await {
                if tx.send(chunk).await.is_err() {
                    return Err(());
                }
            }
            Ok(())
        }
        Body::Streamed(s) => match Body::Streamed(s).collect_async().await {
            Ok(b) => {
                if !b.is_empty() && tx.send(Ok(b)).await.is_err() {
                    return Err(());
                }
                Ok(())
            }
            Err(e) => {
                let _ = tx.send(Err(e)).await;
                Err(())
            }
        },
    }
}

fn leaf_stream_channel(
    orig: Request,
    version: String,
    account: String,
    leaves: Vec<LeafSeg>,
    next: AsyncNextFn,
    total_len: u64,
) -> Body {
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    let scope = swift_runtime::TaskScope::bounded(1);
    let _ = scope.spawn(async move {
        for leaf in leaves {
            if let Some(raw) = leaf.raw_data {
                if tx.send(Ok(raw)).await.is_err() {
                    return;
                }
                continue;
            }
            let path = format!("/{version}/{account}{}", leaf.name);
            let sub = slo_subreq(&orig, path.clone(), leaf.range.as_deref());
            let sresp = next(sub).await;
            if !(200..300).contains(&sresp.status) {
                let _ = tx
                    .send(Err(std::io::Error::other(format!(
                        "SLO segment {path} returned {}",
                        sresp.status
                    ))))
                    .await;
                return;
            }
            if forward_body_chunks(sresp.body, &tx).await.is_err() {
                return;
            }
        }
    });
    Body::from_channel(rx, Some(total_len), scope)
}

/// Narrow `leaves` to the half-open aggregate window `[first, last_excl)`,
/// rewriting each surviving leaf's object `range` accordingly.
fn slice_leaves_for_range(
    leaves: &[LeafSeg],
    first: u64,
    last_excl: u64,
) -> Result<Vec<LeafSeg>, Response> {
    if last_excl <= first {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    let mut cursor = 0u64;
    for leaf in leaves {
        let len = leaf.bytes.max(0) as u64;
        let leaf_start = cursor;
        let leaf_end = cursor + len; // exclusive in aggregate space
        cursor = leaf_end;
        if first >= leaf_end || last_excl <= leaf_start {
            continue;
        }
        let take_from = first.max(leaf_start) - leaf_start;
        let take_to_excl = last_excl.min(leaf_end) - leaf_start;
        if take_to_excl <= take_from {
            continue;
        }
        // Map aggregate offsets into the segment object's byte space.
        let (obj_base, obj_end_incl) = if let Some(r) = &leaf.range {
            let Some((s, e)) = parse_inclusive_range(r) else {
                return Err(Response::error(409, "Conflict"));
            };
            (s, e)
        } else {
            (0u64, len.saturating_sub(1))
        };
        let obj_start = obj_base + take_from;
        let obj_last = obj_base + take_to_excl - 1;
        if obj_last > obj_end_incl {
            return Err(Response::error(409, "Conflict"));
        }
        let contrib = (obj_last - obj_start + 1) as i64;
        // Inline data: slice the raw bytes rather than object ranges.
        if let Some(raw) = &leaf.raw_data {
            let slice = raw
                .get(obj_start as usize..=obj_last as usize)
                .unwrap_or(&[])
                .to_vec();
            out.push(LeafSeg {
                name: String::new(),
                bytes: contrib,
                range: None,
                raw_data: Some(slice),
            });
            continue;
        }
        let need_range = obj_start != 0 || obj_last != obj_end_incl || leaf.range.is_some();
        out.push(LeafSeg {
            name: leaf.name.clone(),
            bytes: contrib,
            range: if need_range {
                Some(format!("{obj_start}-{obj_last}"))
            } else {
                None
            },
            raw_data: None,
        });
    }
    Ok(out)
}

fn parse_stored_manifest(json: &[u8]) -> Option<Vec<StoredSeg>> {
    let value: serde_json::Value = serde_json::from_slice(json).ok()?;
    let arr = value.as_array()?;
    let mut out = Vec::with_capacity(arr.len());
    for it in arr {
        if let Some(data) = it.get("data").and_then(|v| v.as_str()) {
            out.push(StoredSeg {
                name: String::new(),
                bytes: 0,
                hash: String::new(),
                range: None,
                sub_slo: false,
                data_b64: Some(data.to_string()),
            });
            continue;
        }
        let name = it.get("name").and_then(|v| v.as_str())?.to_string();
        out.push(StoredSeg {
            name,
            bytes: it.get("bytes").and_then(|v| v.as_i64()).unwrap_or(0),
            hash: it
                .get("hash")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            range: it.get("range").and_then(|v| v.as_str()).map(str::to_string),
            sub_slo: it
                .get("sub_slo")
                .map(|v| match v {
                    serde_json::Value::Bool(b) => *b,
                    serde_json::Value::String(s) => config_true_value(s),
                    _ => false,
                })
                .unwrap_or(false),
            data_b64: None,
        });
    }
    Some(out)
}

fn ignore_range(headers: &mut HeaderKeyDict, name: &str) {
    let val = match headers.get(IGNORE_RANGE_HDR) {
        Some(s) if !s.is_empty() => format!("{s},{name}"),
        _ => name.to_string(),
    };
    headers.set(IGNORE_RANGE_HDR, val);
}

fn slo_subreq(orig: &Request, path: String, range: Option<&str>) -> Request {
    let mut headers = orig.headers.clone();
    headers.remove("Range");
    headers.remove("Content-Length");
    headers.remove("If-Match");
    headers.remove("If-None-Match");
    headers.remove("If-Modified-Since");
    headers.remove("If-Unmodified-Since");
    headers.remove(IGNORE_RANGE_HDR);
    if let Some(r) = range {
        headers.set("Range", format!("bytes={r}"));
    }
    Request {
        method: "GET".to_string(),
        path,
        query_string: String::new(),
        headers,
        body: Body::empty(),
    }
}

impl Slo {
    fn handle_get_head(&self, mut req: Request, next: &NextFn) -> Response {
        ignore_range(&mut req.headers, SLO_HEADER);
        let orig = req.clone_head();
        let mut resp = next(req);

        let is_slo = resp
            .headers
            .get(SLO_HEADER)
            .map(config_true_value)
            .unwrap_or(false);
        if !is_slo {
            return resp;
        }

        // The backend Etag names the physical stored-manifest JSON.  Preserve
        // it before replacing the public Etag with the aggregate SLO value;
        // Python exposes this digest as X-Manifest-Etag on GET/HEAD/206.
        let mut json_etag = resp
            .headers
            .get("Etag")
            .map(normalize_etag)
            .filter(|etag| !etag.is_empty())
            .map(str::to_string);

        // Prefer sysmeta aggregate (Python `X-Backend-Etag-Is-At` path): a
        // HEAD returns an empty body, so we cannot parse the stored JSON.
        let sys_etag = resp
            .headers
            .get(SYSMETA_SLO_ETAG)
            .map(normalize_etag)
            .filter(|e| !e.is_empty())
            .map(str::to_string);
        let sys_size = resp
            .headers
            .get(SYSMETA_SLO_SIZE)
            .and_then(|s| s.parse::<i64>().ok());

        let is_get = orig.method == "GET";

        // Resolve segments when we need them for streaming, or when sysmeta
        // is missing (legacy manifests). HEAD with sysmeta skips the body.
        let (etag, total_len, segments) = if let (Some(e), Some(sz)) = (&sys_etag, sys_size) {
            if is_get {
                // Still need the segment listing for reassembly.
                let manifest_bytes = match resp.body.materialize(MAX_CONTROL_BODY) {
                    Ok(body) => body,
                    Err(_) => return resp,
                };
                if json_etag.is_none() {
                    json_etag = Some(manifest_etag(manifest_bytes));
                }
                let Some(segments) = parse_stored_manifest(manifest_bytes) else {
                    return resp;
                };
                (e.clone(), sz, segments)
            } else {
                (e.clone(), sz, Vec::new())
            }
        } else {
            // No sysmeta: need the manifest body. HEAD → refetch as GET.
            if !is_get {
                let mut get_req = orig.clone_head();
                get_req.method = "GET".to_string();
                ignore_range(&mut get_req.headers, SLO_HEADER);
                resp = next(get_req);
                if !resp
                    .headers
                    .get(SLO_HEADER)
                    .map(config_true_value)
                    .unwrap_or(false)
                {
                    return resp;
                }
                json_etag = resp
                    .headers
                    .get("Etag")
                    .map(normalize_etag)
                    .filter(|etag| !etag.is_empty())
                    .map(str::to_string)
                    .or(json_etag);
            }
            let manifest_bytes = match resp.body.materialize(MAX_CONTROL_BODY) {
                Ok(body) => body,
                Err(_) => return resp,
            };
            if json_etag.is_none() {
                json_etag = Some(manifest_etag(manifest_bytes));
            }
            let Some(segments) = parse_stored_manifest(manifest_bytes) else {
                return resp;
            };
            let slo_segs: Vec<SloSegment> = segments
                .iter()
                .map(|s| {
                    if let Some(b64) = &s.data_b64 {
                        let raw = B64.decode(b64.as_bytes()).unwrap_or_default();
                        SloSegment {
                            hash: String::new(),
                            segment_length: raw.len() as i64,
                            range: None,
                            raw_data: Some(raw),
                        }
                    } else {
                        SloSegment {
                            hash: s.hash.clone(),
                            segment_length: contrib_length(s),
                            range: s.range.clone(),
                            raw_data: None,
                        }
                    }
                })
                .collect();
            let (etag, total_len) = slo_etag_and_size(&slo_segs);
            (etag, total_len, segments)
        };

        // version, account from the manifest object's path.
        let parts = match split_path(&orig.path, 2, 3, true) {
            Ok(p) => p,
            Err(_) => return Response::error(400, "Invalid path"),
        };
        let version = parts[0].clone().unwrap_or_default();
        let account = parts[1].clone().unwrap_or_default();

        // Resolve a single top-level Range against the aggregate length.
        let mut byte_range: Option<(u64, u64)> = None;
        let mut unsatisfiable = false;
        let range = orig
            .headers
            .get("Range")
            .and_then(|h| Range::parse(h).ok())
            .filter(|r| r.ranges.len() == 1);
        if let Some(range) = range {
            match range.ranges_for_length(Some(total_len.max(0) as u64)) {
                Some(r) if r.is_empty() => unsatisfiable = true,
                Some(r) => byte_range = Some(r[0]),
                None => {}
            }
        }

        if unsatisfiable {
            let mut r = Response::error(416, "Requested Range Not Satisfiable");
            r.headers.set("Accept-Ranges", "bytes");
            r.headers
                .set("Content-Range", format!("bytes */{}", total_len.max(0)));
            return r;
        }

        let mut headers = resp.headers.clone();
        headers.remove("Content-Length");
        headers.remove("Content-Range");
        headers.remove("Transfer-Encoding");
        headers.remove("Etag");
        headers.remove(MANIFEST_ETAG_HEADER);
        headers.set("Etag", format!("\"{etag}\""));
        if let Some(json_etag) = json_etag {
            headers.set(MANIFEST_ETAG_HEADER, json_etag);
        }
        headers.set("Accept-Ranges", "bytes");

        // Expand nested sub_slo manifests before committing the response
        // status (a depth/parse failure is still a 409 the client can see).
        let leaves = if is_get {
            match expand_segments(&orig, &version, &account, &segments, next, 1) {
                Ok(l) => l,
                Err(err) => return err,
            }
        } else {
            Vec::new()
        };

        let (status, body, content_len) = if let Some((first, last_excl)) = byte_range {
            let ranged = if is_get {
                match slice_leaves_for_range(&leaves, first, last_excl) {
                    Ok(l) => l,
                    Err(err) => return err,
                }
            } else {
                Vec::new()
            };
            headers.set(
                "Content-Range",
                format!("bytes {}-{}/{}", first, last_excl - 1, total_len.max(0)),
            );
            let len = (last_excl - first) as i64;
            let body = if is_get {
                Self::leaf_stream_body(
                    orig.clone_head(),
                    version.clone(),
                    account.clone(),
                    ranged,
                    Arc::clone(next),
                    last_excl - first,
                )
            } else {
                Body::empty()
            };
            (206u16, body, len)
        } else if is_get {
            let body = Self::leaf_stream_body(
                orig.clone_head(),
                version.clone(),
                account.clone(),
                leaves,
                Arc::clone(next),
                total_len.max(0) as u64,
            );
            (200u16, body, total_len)
        } else {
            (200u16, Body::empty(), total_len)
        };

        headers.set("Content-Length", content_len.to_string());
        let mut out = Response::new(status);
        out.headers = headers;
        out.body = body;
        out
    }

    async fn handle_get_head_async(&self, mut req: Request, next: AsyncNextFn) -> Response {
        ignore_range(&mut req.headers, SLO_HEADER);
        let orig = req.clone_head();
        let mut resp = next(req).await;

        let is_slo = resp
            .headers
            .get(SLO_HEADER)
            .map(config_true_value)
            .unwrap_or(false);
        if !is_slo {
            return resp;
        }

        let mut json_etag = resp
            .headers
            .get("Etag")
            .map(normalize_etag)
            .filter(|etag| !etag.is_empty())
            .map(str::to_string);
        let sys_etag = resp
            .headers
            .get(SYSMETA_SLO_ETAG)
            .map(normalize_etag)
            .filter(|e| !e.is_empty())
            .map(str::to_string);
        let sys_size = resp
            .headers
            .get(SYSMETA_SLO_SIZE)
            .and_then(|s| s.parse::<i64>().ok());
        let is_get = orig.method == "GET";

        let (etag, total_len, segments) = if let (Some(e), Some(sz)) = (&sys_etag, sys_size) {
            if is_get {
                let body = std::mem::replace(&mut resp.body, Body::empty());
                let manifest_bytes = match body.collect_async().await {
                    Ok(body) => body,
                    Err(_) => return resp,
                };
                if json_etag.is_none() {
                    json_etag = Some(manifest_etag(&manifest_bytes));
                }
                let Some(segments) = parse_stored_manifest(&manifest_bytes) else {
                    return resp;
                };
                (e.clone(), sz, segments)
            } else {
                (e.clone(), sz, Vec::new())
            }
        } else {
            if !is_get {
                let mut get_req = orig.clone_head();
                get_req.method = "GET".to_string();
                ignore_range(&mut get_req.headers, SLO_HEADER);
                resp = next(get_req).await;
                if !resp
                    .headers
                    .get(SLO_HEADER)
                    .map(config_true_value)
                    .unwrap_or(false)
                {
                    return resp;
                }
                json_etag = resp
                    .headers
                    .get("Etag")
                    .map(normalize_etag)
                    .filter(|etag| !etag.is_empty())
                    .map(str::to_string)
                    .or(json_etag);
            }
            let body = std::mem::replace(&mut resp.body, Body::empty());
            let manifest_bytes = match body.collect_async().await {
                Ok(body) => body,
                Err(_) => return resp,
            };
            if json_etag.is_none() {
                json_etag = Some(manifest_etag(&manifest_bytes));
            }
            let Some(segments) = parse_stored_manifest(&manifest_bytes) else {
                return resp;
            };
            let slo_segs: Vec<SloSegment> = segments
                .iter()
                .map(|s| {
                    if let Some(b64) = &s.data_b64 {
                        let raw = B64.decode(b64.as_bytes()).unwrap_or_default();
                        SloSegment {
                            hash: String::new(),
                            segment_length: raw.len() as i64,
                            range: None,
                            raw_data: Some(raw),
                        }
                    } else {
                        SloSegment {
                            hash: s.hash.clone(),
                            segment_length: contrib_length(s),
                            range: s.range.clone(),
                            raw_data: None,
                        }
                    }
                })
                .collect();
            let (etag, total_len) = slo_etag_and_size(&slo_segs);
            (etag, total_len, segments)
        };

        let parts = match split_path(&orig.path, 2, 3, true) {
            Ok(p) => p,
            Err(_) => return Response::error(400, "Invalid path"),
        };
        let version = parts[0].clone().unwrap_or_default();
        let account = parts[1].clone().unwrap_or_default();

        let mut byte_range: Option<(u64, u64)> = None;
        let mut unsatisfiable = false;
        let range = orig
            .headers
            .get("Range")
            .and_then(|h| Range::parse(h).ok())
            .filter(|r| r.ranges.len() == 1);
        if let Some(range) = range {
            match range.ranges_for_length(Some(total_len.max(0) as u64)) {
                Some(r) if r.is_empty() => unsatisfiable = true,
                Some(r) => byte_range = Some(r[0]),
                None => {}
            }
        }
        if unsatisfiable {
            let mut r = Response::error(416, "Requested Range Not Satisfiable");
            r.headers.set("Accept-Ranges", "bytes");
            r.headers
                .set("Content-Range", format!("bytes */{}", total_len.max(0)));
            return r;
        }

        let mut headers = resp.headers.clone();
        headers.remove("Content-Length");
        headers.remove("Content-Range");
        headers.remove("Transfer-Encoding");
        headers.remove("Etag");
        headers.remove(MANIFEST_ETAG_HEADER);
        headers.set("Etag", format!("\"{etag}\""));
        if let Some(json_etag) = json_etag {
            headers.set(MANIFEST_ETAG_HEADER, json_etag);
        }
        headers.set("Accept-Ranges", "bytes");

        let leaves = if is_get {
            match expand_segments_async(
                orig.clone_head(),
                version.clone(),
                account.clone(),
                segments,
                next.clone(),
                1,
            )
            .await
            {
                Ok(l) => l,
                Err(err) => return err,
            }
        } else {
            Vec::new()
        };

        let (status, body, content_len) = if let Some((first, last_excl)) = byte_range {
            let ranged = if is_get {
                match slice_leaves_for_range(&leaves, first, last_excl) {
                    Ok(l) => l,
                    Err(err) => return err,
                }
            } else {
                Vec::new()
            };
            headers.set(
                "Content-Range",
                format!("bytes {}-{}/{}", first, last_excl - 1, total_len.max(0)),
            );
            let len = (last_excl - first) as i64;
            let body = if is_get {
                leaf_stream_channel(
                    orig.clone_head(),
                    version.clone(),
                    account.clone(),
                    ranged,
                    next,
                    last_excl - first,
                )
            } else {
                Body::empty()
            };
            (206u16, body, len)
        } else if is_get {
            let body = leaf_stream_channel(
                orig.clone_head(),
                version.clone(),
                account.clone(),
                leaves,
                next,
                total_len.max(0) as u64,
            );
            (200u16, body, total_len)
        } else {
            (200u16, Body::empty(), total_len)
        };

        headers.set("Content-Length", content_len.to_string());
        let mut out = Response::new(status);
        out.headers = headers;
        out.body = body;
        out
    }

    /// Lazy leaf-segment reassembly: each subrequest runs only when the
    /// client stream reaches that leaf; a mid-stream failure aborts the
    /// connection (Python parity — the status is already sent). Inline
    /// `data` leaves yield from memory without a subrequest.
    fn leaf_stream_body(
        orig: Request,
        version: String,
        account: String,
        leaves: Vec<LeafSeg>,
        next: NextFn,
        total_len: u64,
    ) -> Body {
        let mut queue = leaves.into_iter();
        let reader = FnReader::new(move || {
            let seg = queue.next()?;
            if let Some(raw) = seg.raw_data {
                let reader: Box<dyn Read + Send> = Box::new(Cursor::new(raw));
                return Some(Ok(reader));
            }
            let path = format!("/{version}/{account}{}", seg.name);
            let sub = slo_subreq(&orig, path.clone(), seg.range.as_deref());
            let sresp = next(sub);
            if !(200..300).contains(&sresp.status) {
                return Some(Err(std::io::Error::other(format!(
                    "SLO segment {path} returned {}",
                    sresp.status
                ))));
            }
            let (reader, _len): (Box<dyn Read + Send>, _) = sresp.body.into_reader();
            Some(Ok(reader))
        });
        Body::from_reader(Box::new(reader), Some(total_len))
    }

    /// `?multipart-manifest=put`: validate the client manifest (a JSON list of
    /// `{path, etag, size_bytes, range?}` or `{"data": base64}`), HEAD each
    /// object-backed segment to confirm it exists and matches, then store the
    /// normalized internal manifest with `X-Static-Large-Object: true`.
    /// A HEAD that identifies a segment as an SLO is validated against its
    /// aggregate SLO sysmeta, never the physical manifest JSON object's
    /// metadata. `heartbeat=on` returns `202 Accepted` immediately with a
    /// streamed body: a leading space, additional spaces after each segment
    /// HEAD (throttled by [`Self::yield_frequency`]), then `\r\n\r\n` + the
    /// final JSON status. Non-heartbeat PUT uses up to [`Self::concurrent_gets`]
    /// threads for segment HEAD pile (Python `concurrency`).
    fn handle_put(&self, mut req: Request, next: &NextFn) -> Response {
        let heartbeat = req
            .param("heartbeat")
            .as_deref()
            .map(config_true_value)
            .unwrap_or(false);
        let manifest_bytes = match req.body.materialize(MAX_MANIFEST_SIZE) {
            Ok(b) => b.to_vec(),
            Err(e) if body_too_large(&e) => {
                return Response::error(413, "Request Entity Too Large")
            }
            Err(_) => return Response::error(499, "Client Disconnect"),
        };
        let Ok(client) = serde_json::from_slice::<serde_json::Value>(&manifest_bytes) else {
            return Response::error(400, "Manifest must be valid json.");
        };
        let Some(entries) = client.as_array() else {
            return Response::error(400, "Manifest must be a list.");
        };
        let object_segment_count = entries
            .iter()
            .filter(|entry| {
                entry
                    .as_object()
                    .map(|segment| segment.contains_key("path"))
                    .unwrap_or(false)
            })
            .count();
        if object_segment_count > MAX_MANIFEST_SEGMENTS {
            // Python passes this text as HTTPRequestEntityTooLarge's body,
            // so it is intentionally plain rather than Response::error's
            // generated HTML document.
            let body =
                format!("Number of object-backed segments must be <= {MAX_MANIFEST_SEGMENTS}");
            let mut resp = Response::with_body(413, body.clone());
            resp.headers.set("Content-Type", "text/html; charset=UTF-8");
            resp.headers.set("Content-Length", body.len());
            return resp;
        }
        let parts = match split_path(&req.path, 4, 4, true) {
            Ok(p) => p,
            Err(_) => return Response::error(400, "Invalid path"),
        };
        let version = parts[0].clone().unwrap_or_default();
        let account = parts[1].clone().unwrap_or_default();

        if heartbeat {
            return heartbeat_put_stream(
                req,
                entries.clone(),
                version,
                account,
                Arc::clone(next),
                self.yield_frequency,
            );
        }

        // Concurrent HEAD pile warms backend caches / parallelizes validation
        // when concurrent_gets > 1 (Python slo concurrency).
        if self.concurrent_gets > 1 {
            concurrent_head_warm(
                entries,
                &version,
                &account,
                &req,
                next,
                self.concurrent_gets,
            );
        }

        let built = validate_put_entries(&req, entries, &version, &account, next, &mut || {});
        finish_put(req, next, built)
    }

    async fn handle_put_async(&self, mut req: Request, next: AsyncNextFn) -> Response {
        let manifest_bytes = match req.body.materialize(MAX_MANIFEST_SIZE) {
            Ok(b) => b.to_vec(),
            Err(e) if body_too_large(&e) => {
                return Response::error(413, "Request Entity Too Large")
            }
            Err(_) => return Response::error(499, "Client Disconnect"),
        };
        let Ok(client) = serde_json::from_slice::<serde_json::Value>(&manifest_bytes) else {
            return Response::error(400, "Manifest must be valid json.");
        };
        let Some(entries) = client.as_array() else {
            return Response::error(400, "Manifest must be a list.");
        };
        let object_segment_count = entries
            .iter()
            .filter(|entry| {
                entry
                    .as_object()
                    .map(|segment| segment.contains_key("path"))
                    .unwrap_or(false)
            })
            .count();
        if object_segment_count > MAX_MANIFEST_SEGMENTS {
            let body =
                format!("Number of object-backed segments must be <= {MAX_MANIFEST_SEGMENTS}");
            let mut resp = Response::with_body(413, body.clone());
            resp.headers.set("Content-Type", "text/html; charset=UTF-8");
            resp.headers.set("Content-Length", body.len());
            return resp;
        }
        let parts = match split_path(&req.path, 4, 4, true) {
            Ok(p) => p,
            Err(_) => return Response::error(400, "Invalid path"),
        };
        let version = parts[0].clone().unwrap_or_default();
        let account = parts[1].clone().unwrap_or_default();
        let mut heads: std::collections::HashMap<String, Response> =
            std::collections::HashMap::new();
        for e in entries {
            let Some(path) = e.get("path").and_then(|v| v.as_str()) else {
                continue;
            };
            let stored_path = format!("/{}", path.trim_start_matches('/'));
            let seg_path = format!("/{version}/{account}{stored_path}");
            let mut head = req.clone_head();
            head.method = "HEAD".to_string();
            head.path = seg_path.clone();
            head.query_string = String::new();
            head.headers.remove("Content-Length");
            heads.insert(seg_path, next(head).await);
        }
        let heads = std::sync::Mutex::new(heads);
        let next_heads: NextFn = Arc::new(move |r| {
            heads
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&r.path)
                .unwrap_or_else(|| Response::error(404, "Segment Not Found"))
        });
        let built = validate_put_entries(&req, entries, &version, &account, &next_heads, &mut || {});
        finish_put_async(req, next, built).await
    }

    /// `?multipart-manifest=delete`: expand the SLO (and nested sub_slo)
    /// segment list, DELETE each object-backed segment, then DELETE the
    /// manifest. Response mirrors bulk-delete JSON summary.
    ///
    /// With `async=yes`, schedule segments for expiry (UPDATE to
    /// `.expiring_objects`) then DELETE only the manifest — see
    /// [`Self::handle_async_delete`].
    fn handle_multipart_delete(&self, req: Request, next: &NextFn) -> Response {
        if req
            .param("async")
            .as_deref()
            .map(config_true_value)
            .unwrap_or(false)
        {
            return self.handle_async_delete(req, next);
        }
        let parts = match split_path(&req.path, 4, 4, true) {
            Ok(p) => p,
            Err(_) => return Response::error(400, "Invalid path"),
        };
        let version = parts[0].clone().unwrap_or_default();
        let account = parts[1].clone().unwrap_or_default();
        let container = parts[2].clone().unwrap_or_default();
        let object = parts[3].clone().unwrap_or_default();
        let manifest_name = format!("/{container}/{object}");

        // Fetch stored manifest (raw GET with multipart-manifest=get).
        let mut get = req.clone_head();
        get.method = "GET".to_string();
        get.query_string = "multipart-manifest=get".to_string();
        get.headers.remove("Content-Length");
        ignore_range(&mut get.headers, SLO_HEADER);
        let mut mresp = next(get);
        if !(200..300).contains(&mresp.status) {
            return Response::error(mresp.status, "Unable to load SLO manifest");
        }
        let is_slo = mresp
            .headers
            .get(SLO_HEADER)
            .map(config_true_value)
            .unwrap_or(false);
        if !is_slo {
            return Response::error(400, "Not an SLO manifest");
        }
        let body = match mresp.body.materialize(MAX_CONTROL_BODY) {
            Ok(b) => b.to_vec(),
            Err(_) => return Response::error(500, "Unable to load SLO manifest data"),
        };
        let Some(root_segs) = parse_stored_manifest(&body) else {
            return Response::error(400, "Invalid SLO manifest");
        };

        // Depth-first expand sub_slo; delete leaves first, then manifests.
        let mut to_delete: Vec<String> = Vec::new();
        let mut stack: Vec<(StoredSeg, bool)> = root_segs.into_iter().map(|s| (s, false)).collect();
        // Also delete the top-level manifest last.
        let mut pending_manifests: Vec<String> = vec![manifest_name];
        let mut expanded = 0usize;
        while let Some((seg, expanded_flag)) = stack.pop() {
            if seg.data_b64.is_some() {
                continue;
            }
            if expanded > MAX_SLO_RECURSION_DEPTH * 1000 {
                return Response::error(400, "Too many buffered slo segments to delete.");
            }
            if seg.sub_slo && !expanded_flag {
                let path = format!("/{version}/{account}{}", seg.name);
                let mut sub = req.clone_head();
                sub.method = "GET".to_string();
                sub.path = path;
                sub.query_string = "multipart-manifest=get".to_string();
                sub.headers.remove("Content-Length");
                ignore_range(&mut sub.headers, SLO_HEADER);
                let mut sresp = next(sub);
                if (200..300).contains(&sresp.status)
                    && sresp
                        .headers
                        .get(SLO_HEADER)
                        .map(config_true_value)
                        .unwrap_or(false)
                {
                    if let Ok(bytes) = sresp.body.materialize(MAX_CONTROL_BODY) {
                        if let Some(nested) = parse_stored_manifest(bytes) {
                            // Re-push self after children so nested manifest
                            // is deleted after its segments.
                            stack.push((seg.clone(), true));
                            for n in nested.into_iter().rev() {
                                stack.push((n, false));
                            }
                            expanded += 1;
                            continue;
                        }
                    }
                }
                // Failed to expand: still try to delete the path itself.
                if !seg.name.is_empty() {
                    to_delete.push(seg.name.clone());
                }
            } else if expanded_flag {
                // Nested manifest object after its segments.
                if !seg.name.is_empty() {
                    pending_manifests.push(seg.name.clone());
                }
            } else if !seg.name.is_empty() {
                to_delete.push(seg.name.clone());
            }
        }
        to_delete.extend(pending_manifests);

        let mut number_deleted = 0u64;
        let mut number_not_found = 0u64;
        let mut errors: Vec<(String, String)> = Vec::new();
        for name in &to_delete {
            // Manifest names are `/container/object` (absolute within account).
            let delete_path = if name.starts_with('/') {
                format!("/{version}/{account}{name}")
            } else {
                format!("/{version}/{account}/{name}")
            };
            let mut del = req.clone_head();
            del.method = "DELETE".to_string();
            del.path = delete_path;
            del.query_string = String::new();
            del.headers.remove("Content-Length");
            let resp = next(del);
            match resp.status {
                s if (200..300).contains(&s) => number_deleted += 1,
                404 => number_not_found += 1,
                s => errors.push((name.clone(), format!("{s}"))),
            }
        }

        let (status, body_note) = if !errors.is_empty() {
            (400u16, "")
        } else if number_deleted == 0 && number_not_found == 0 {
            (400, "Invalid bulk delete.")
        } else {
            (200, "")
        };
        let summary = serde_json::json!({
            "Number Deleted": number_deleted,
            "Number Not Found": number_not_found,
            "Response Status": format!("{status} {}", swift_http::reason_phrase(status)),
            "Response Body": body_note,
            "Errors": errors.iter().map(|(p, e)| vec![p.clone(), e.clone()]).collect::<Vec<_>>(),
        });
        let mut out = Response::with_body(200, summary.to_string().into_bytes());
        out.headers.set("Content-Type", "application/json");
        out
    }

    /// `?multipart-manifest=delete&async=yes`: Python `handle_async_delete`.
    ///
    /// Constraints (same as `slo.py`): all object-backed segments must share
    /// one container and none may be nested SLOs. Write ACL is probed via HEAD
    /// on the manifest container (and segment container when different).
    /// Segments are enqueued to `.expiring_objects` via `UPDATE` into the
    /// hash-sharded task container for the **manifest** a/c/o; the manifest is
    /// then DELETEd through the rest of the pipeline. If the expirer UPDATE
    /// fails, falls back to a best-effort detached-thread segment DELETE then
    /// still removes the manifest (Python would return 503 and leave the
    /// manifest).
    async fn handle_multipart_delete_async(
        &self,
        req: Request,
        next: AsyncNextFn,
    ) -> Response {
        if req
            .param("async")
            .as_deref()
            .map(config_true_value)
            .unwrap_or(false)
        {
            return next(req).await;
        }
        let parts = match split_path(&req.path, 4, 4, true) {
            Ok(p) => p,
            Err(_) => return Response::error(400, "Invalid path"),
        };
        let version = parts[0].clone().unwrap_or_default();
        let account = parts[1].clone().unwrap_or_default();
        let container = parts[2].clone().unwrap_or_default();
        let object = parts[3].clone().unwrap_or_default();
        let manifest_name = format!("/{container}/{object}");
        let mut get = req.clone_head();
        get.method = "GET".to_string();
        get.query_string = "multipart-manifest=get".to_string();
        get.headers.remove("Content-Length");
        ignore_range(&mut get.headers, SLO_HEADER);
        let mut mresp = next(get).await;
        if !(200..300).contains(&mresp.status) {
            return Response::error(mresp.status, "Unable to load SLO manifest");
        }
        let is_slo = mresp
            .headers
            .get(SLO_HEADER)
            .map(config_true_value)
            .unwrap_or(false);
        if !is_slo {
            return Response::error(400, "Not an SLO manifest");
        }
        let body = match std::mem::replace(&mut mresp.body, Body::empty())
            .collect_async()
            .await
        {
            Ok(b) => b,
            Err(_) => return Response::error(500, "Unable to load SLO manifest data"),
        };
        let Some(root_segs) = parse_stored_manifest(&body) else {
            return Response::error(400, "Invalid SLO manifest");
        };
        let mut to_delete: Vec<String> = root_segs
            .into_iter()
            .filter(|s| s.data_b64.is_none() && !s.name.is_empty())
            .map(|s| s.name)
            .collect();
        to_delete.push(manifest_name);
        let mut number_deleted = 0u64;
        let mut number_not_found = 0u64;
        let mut errors: Vec<(String, String)> = Vec::new();
        for name in &to_delete {
            let delete_path = if name.starts_with('/') {
                format!("/{version}/{account}{name}")
            } else {
                format!("/{version}/{account}/{name}")
            };
            let mut del = req.clone_head();
            del.method = "DELETE".to_string();
            del.path = delete_path;
            del.query_string = String::new();
            del.headers.remove("Content-Length");
            let resp = next(del).await;
            match resp.status {
                s if (200..300).contains(&s) => number_deleted += 1,
                404 => number_not_found += 1,
                s => errors.push((name.clone(), format!("{s}"))),
            }
        }
        let (status, body_note) = if !errors.is_empty() {
            (400u16, "")
        } else if number_deleted == 0 && number_not_found == 0 {
            (400, "Invalid bulk delete.")
        } else {
            (200, "")
        };
        let summary = serde_json::json!({
            "Number Deleted": number_deleted,
            "Number Not Found": number_not_found,
            "Response Status": format!("{status} {}", swift_http::reason_phrase(status)),
            "Response Body": body_note,
            "Errors": errors.iter().map(|(p, e)| vec![p.clone(), e.clone()]).collect::<Vec<_>>(),
        });
        let mut out = Response::with_body(200, summary.to_string().into_bytes());
        out.headers.set("Content-Type", "application/json");
        out
    }

    fn handle_async_delete(&self, req: Request, next: &NextFn) -> Response {
        let parts = match split_path(&req.path, 4, 4, true) {
            Ok(p) => p,
            Err(_) => return Response::error(400, "Invalid path"),
        };
        let version = parts[0].clone().unwrap_or_default();
        let account = parts[1].clone().unwrap_or_default();
        let container = parts[2].clone().unwrap_or_default();
        let object = parts[3].clone().unwrap_or_default();

        // Load SLO segments (top-level only; nested expansion is rejected).
        let mut get = req.clone_head();
        get.method = "GET".to_string();
        get.query_string = "multipart-manifest=get".to_string();
        get.headers.remove("Content-Length");
        ignore_range(&mut get.headers, SLO_HEADER);
        let mut mresp = next(get);
        if mresp.status == 404 {
            return Response::error(404, "SLO manifest not found");
        }
        if mresp.status == 401 {
            return Response::error(401, "401 Unauthorized");
        }
        if !(200..300).contains(&mresp.status) {
            return Response::error(500, "Unable to load SLO manifest or segment.");
        }
        let is_slo = mresp
            .headers
            .get(SLO_HEADER)
            .map(config_true_value)
            .unwrap_or(false);
        if !is_slo {
            return Response::error(400, "Not an SLO manifest");
        }
        let body = match mresp.body.materialize(MAX_CONTROL_BODY) {
            Ok(b) => b.to_vec(),
            Err(_) => return Response::error(500, "Unable to load SLO manifest"),
        };
        let Some(root_segs) = parse_stored_manifest(&body) else {
            return Response::error(500, "Unable to load SLO manifest");
        };

        let segments: Vec<&StoredSeg> = root_segs
            .iter()
            .filter(|s| s.data_b64.is_none() && !s.name.is_empty())
            .collect();

        if segments.is_empty() {
            // Degenerate: only inline data (or empty) — just delete the manifest.
            return next(req);
        }

        if segments.iter().any(|s| s.sub_slo) {
            return Response::error(400, "No segments may be large objects.");
        }

        let mut seg_containers: Vec<String> = Vec::new();
        let mut seg_objects: Vec<String> = Vec::new();
        for seg in &segments {
            let path = if seg.name.starts_with('/') {
                seg.name.clone()
            } else {
                format!("/{}", seg.name)
            };
            match split_path(&path, 2, 2, true) {
                Ok(p) => {
                    let c = p[0].clone().unwrap_or_default();
                    let o = p[1].clone().unwrap_or_default();
                    if c.is_empty() || o.is_empty() {
                        return Response::error(400, "Invalid segment path in manifest");
                    }
                    seg_containers.push(c);
                    seg_objects.push(o);
                }
                Err(_) => return Response::error(400, "Invalid segment path in manifest"),
            }
        }
        let mut unique_containers: Vec<String> = seg_containers.clone();
        unique_containers.sort();
        unique_containers.dedup();
        if unique_containers.len() > 1 {
            let csv = unique_containers
                .iter()
                .map(|c| format!("\"{c}\""))
                .collect::<Vec<_>>()
                .join(", ");
            return Response::error(
                400,
                &format!("All segments must be in one container. Found segments in {csv}"),
            );
        }
        let segment_container = unique_containers
            .into_iter()
            .next()
            .unwrap_or_else(|| container.clone());

        // Auth/ACL probes (Python: authorize with write_acl on manifest +
        // segment containers via get_container_info). Without a full authorize
        // callback, HEAD with client Authorization/X-Auth-Token returns
        // 401/403 the same way TempAuth/Keystone would.
        if let Some(denied) = probe_async_delete_write_acl(
            next,
            &req,
            &version,
            &account,
            &container,
            &segment_container,
        ) {
            return denied;
        }

        // Build expirer jobs and UPDATE .expiring_objects.
        let ts = Timestamp::now();
        let delete_at_secs = ts.as_secs_f64();
        let t_delete_at = normalize_delete_at_timestamp(delete_at_secs, true);
        let created_at = ts.internal();
        let jobs: Vec<serde_json::Value> = seg_objects
            .iter()
            .map(|obj| {
                serde_json::json!({
                    "content_type": ASYNC_DELETE_TYPE,
                    "created_at": created_at,
                    "deleted": 0,
                    "etag": MD5_OF_EMPTY_STRING,
                    "name": format!(
                        "{t_delete_at}-{account}/{segment_container}/{obj}"
                    ),
                    "size": 0,
                    "storage_policy_index": 0,
                })
            })
            .collect();
        // Python: get_expirer_account_and_container(ts, account, container, obj)
        // uses the *manifest* a/c/o for the task-container shard (one container
        // for the whole job, not per segment).
        let expirer_cont = expirer_task_container(
            delete_at_secs as i64,
            &self.hash_config,
            &account,
            &container,
            &object,
        );
        let jobs_body = serde_json::to_vec(&jobs).unwrap_or_default();
        let mut enqueue = req.clone_head();
        enqueue.method = "UPDATE".to_string();
        enqueue.path = format!("/v1/{EXPIRER_ACCOUNT}/{expirer_cont}");
        // Keep the original query string on the wire (Python pre-authed request
        // inherits environ query); harmless for container UPDATE.
        enqueue.headers.set("Content-Type", "application/json");
        enqueue
            .headers
            .set("Content-Length", jobs_body.len().to_string());
        enqueue.headers.set("X-Backend-Storage-Policy-Index", "0");
        enqueue
            .headers
            .set("X-Backend-Allow-Private-Methods", "True");
        enqueue.body = jobs_body.into();
        let enq_resp = next(enqueue);
        if !(200..300).contains(&enq_resp.status) {
            // Residual vs Python 503: best-effort background segment deletes
            // so the client still gets a usable async-ish path when the
            // expirer queue is unavailable.
            let next_bg = Arc::clone(next);
            let version_bg = version.clone();
            let account_bg = account.clone();
            let seg_paths: Vec<String> = segments
                .iter()
                .map(|s| {
                    if s.name.starts_with('/') {
                        format!("/{version_bg}/{account_bg}{}", s.name)
                    } else {
                        format!("/{version_bg}/{account_bg}/{}", s.name)
                    }
                })
                .collect();
            let head_template = req.clone_head();
            std::thread::spawn(move || {
                for path in seg_paths {
                    let mut del = head_template.clone_head();
                    del.method = "DELETE".to_string();
                    del.path = path;
                    del.query_string = String::new();
                    del.headers.remove("Content-Length");
                    let _ = next_bg(del);
                }
            });
        }

        // Finally delete the manifest (pass original DELETE through).
        next(req)
    }

    /// `?multipart-manifest=get&format=raw`: convert the stored internal
    /// listing (`name`/`bytes`/`hash`) to the client PUT shape
    /// (`path`/`size_bytes`/`etag`) so a server-side copy can re-PUT it.
    fn handle_manifest_get_raw(&self, req: Request, next: &NextFn) -> Response {
        let mut resp = next(req);
        let is_slo = resp
            .headers
            .get(SLO_HEADER)
            .map(config_true_value)
            .unwrap_or(false);
        if !is_slo {
            return resp;
        }
        if resp.body.materialize(MAX_CONTROL_BODY).is_err() {
            return resp;
        }
        let manifest_bytes = resp.body.materialize(MAX_CONTROL_BODY).expect("buffered");
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(manifest_bytes) else {
            return resp;
        };
        let Some(arr) = value.as_array() else {
            return resp;
        };
        let mut raw: Vec<serde_json::Value> = Vec::with_capacity(arr.len());
        for it in arr {
            let Some(obj) = it.as_object() else {
                continue;
            };
            if obj.contains_key("data") {
                raw.push(it.clone());
                continue;
            }
            let mut out = serde_json::Map::new();
            if let Some(name) = obj.get("name") {
                out.insert("path".into(), name.clone());
            }
            if let Some(bytes) = obj.get("bytes") {
                out.insert("size_bytes".into(), bytes.clone());
            }
            if let Some(hash) = obj.get("hash") {
                out.insert("etag".into(), hash.clone());
            }
            if let Some(range) = obj.get("range") {
                out.insert("range".into(), range.clone());
            }
            // sub_slo / content_type / last_modified intentionally dropped
            // (Python convert_segment_listing).
            raw.push(serde_json::Value::Object(out));
        }
        let body = serde_json::to_vec(&raw).unwrap_or_default();
        resp.headers.set("Content-Length", body.len().to_string());
        resp.headers.set("Etag", manifest_etag(&body));
        // Keep the large object's Content-Type (Python) so SSC works.
        resp.body = body.into();
        resp
    }

    /// `?multipart-manifest=get` returns the stored internal JSON.  Python
    /// exposes that representation as JSON regardless of the large object's
    /// original Content-Type; `format=raw` is handled separately and preserves
    /// the original type for server-side copy.
    fn handle_manifest_get(&self, req: Request, next: &NextFn) -> Response {
        let mut resp = next(req);
        let is_slo = resp
            .headers
            .get(SLO_HEADER)
            .map(config_true_value)
            .unwrap_or(false);
        if is_slo {
            resp.headers
                .set("Content-Type", "application/json; charset=utf-8");
        }
        resp
    }
}

/// Built internal manifest + etag inputs from a client PUT body.
struct PutManifestBuilt {
    internal: Vec<serde_json::Value>,
    slo_segs: Vec<SloSegment>,
    errors: Vec<String>,
    has_object_backed: bool,
    entry_count: usize,
}

/// Validate each client manifest entry (HEAD object-backed segments).
/// `on_head` is invoked after every segment HEAD (heartbeat whitespace).
fn validate_put_entries(
    req: &Request,
    entries: &[serde_json::Value],
    version: &str,
    account: &str,
    next: &NextFn,
    on_head: &mut dyn FnMut(),
) -> PutManifestBuilt {
    let mut internal: Vec<serde_json::Value> = Vec::new();
    let mut slo_segs: Vec<SloSegment> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    let mut has_object_backed = false;
    for (i, e) in entries.iter().enumerate() {
        let Some(e) = e.as_object() else {
            errors.push(format!("Index {i}: not a JSON object"));
            continue;
        };
        // Inline data segment: `{"data": "<base64>"}` (Python slo.py).
        if e.contains_key("data") {
            let Some(data_str) = e.get("data").and_then(|v| v.as_str()) else {
                errors.push(format!("Index {i}: data must be valid base64"));
                continue;
            };
            let raw = match B64.decode(data_str.as_bytes()) {
                Ok(r) => r,
                Err(_) => {
                    errors.push(format!("Index {i}: data must be valid base64"));
                    continue;
                }
            };
            if raw.is_empty() {
                errors.push(format!(
                    "Index {i}: too small; each segment must be at least 1 byte."
                ));
                continue;
            }
            let normalized = B64.encode(&raw);
            let mut stored = serde_json::Map::new();
            stored.insert("data".into(), normalized.into());
            internal.push(serde_json::Value::Object(stored));
            slo_segs.push(SloSegment {
                hash: String::new(),
                segment_length: raw.len() as i64,
                range: None,
                raw_data: Some(raw),
            });
            continue;
        }
        let Some(path) = e.get("path").and_then(|v| v.as_str()) else {
            errors.push(format!("Index {i}: no path in segment"));
            continue;
        };
        has_object_backed = true;
        let stripped_path = path.trim_matches('/');
        let valid_path = stripped_path
            .split_once('/')
            .map(|(container, object)| !container.is_empty() && !object.is_empty())
            .unwrap_or(false);
        if !valid_path {
            errors.push(format!(
                "Index {i}: path does not refer to an object. Path must be of the form /container/object."
            ));
            continue;
        }
        let stored_path = format!("/{}", path.trim_start_matches('/'));
        let seg_path = format!("/{version}/{account}{stored_path}");
        if req.path == seg_path {
            errors.push(format!(
                "Index {i}: manifest must not include itself as a segment"
            ));
            continue;
        }

        let client_etag = match e.get("etag") {
            None | Some(serde_json::Value::Null) => None,
            Some(serde_json::Value::String(etag)) => Some(normalize_etag(etag).to_string()),
            Some(_) => {
                errors.push(format!(
                    "Index {i}: etag must be a string or null (if provided)"
                ));
                continue;
            }
        };
        let client_size = match e.get("size_bytes") {
            None | Some(serde_json::Value::Null) => None,
            Some(value) => match value
                .as_i64()
                .or_else(|| value.as_str().and_then(|size| size.parse().ok()))
            {
                Some(size) if size >= 0 => Some(size),
                _ => {
                    errors.push(format!("Index {i}: invalid size_bytes"));
                    continue;
                }
            },
        };
        let requested_range = match e.get("range") {
            None | Some(serde_json::Value::Null) => None,
            Some(serde_json::Value::String(range)) if range.is_empty() => None,
            Some(serde_json::Value::String(range)) => {
                match Range::parse(&format!("bytes={range}")) {
                    Ok(parsed) if parsed.ranges.len() == 1 => Some(parsed),
                    _ => {
                        errors.push(format!("Index {i}: invalid range"));
                        continue;
                    }
                }
            }
            Some(_) => {
                errors.push(format!("Index {i}: invalid range"));
                continue;
            }
        };

        // HEAD the segment to confirm it exists and read its real etag/size.
        // (Serial path; concurrent pile is used when caller batches — see
        // `validate_put_entries_concurrent`.)
        let mut head = req.clone_head();
        head.method = "HEAD".to_string();
        head.path = seg_path.clone();
        head.query_string = String::new();
        head.headers.remove("Content-Length");
        let hr = next(head);
        on_head();
        if !(200..300).contains(&hr.status) {
            errors.push(format!("{path}, Segment Not Found"));
            continue;
        }
        let is_sub_slo = hr
            .headers
            .get(SLO_HEADER)
            .map(config_true_value)
            .unwrap_or(false);
        // For a sub-SLO, Etag and Content-Length describe the physical
        // manifest JSON. Python Swift validates against the aggregate SLO
        // values persisted in sysmeta instead.
        let real_etag = if is_sub_slo {
            hr.headers.get(SYSMETA_SLO_ETAG)
        } else {
            hr.headers.get("Etag")
        }
        .map(normalize_etag)
        .filter(|etag| !etag.is_empty());
        let real_size = if is_sub_slo {
            hr.headers.get(SYSMETA_SLO_SIZE)
        } else {
            hr.headers.get("Content-Length")
        }
        .and_then(|size| size.parse::<i64>().ok());
        if let (Some(ce), Some(re)) = (&client_etag, real_etag) {
            if !ce.is_empty() && !ce.eq_ignore_ascii_case(re) {
                errors.push(format!("{path}, Etag Mismatch"));
                continue;
            }
        }
        if let (Some(cs), Some(rs)) = (client_size, real_size) {
            if cs != rs {
                errors.push(format!("{path}, Size Mismatch"));
                continue;
            }
        }
        let size = real_size.or(client_size).unwrap_or(0);
        let hash = real_etag
            .map(str::to_string)
            .or_else(|| client_etag.clone())
            .unwrap_or_default();

        let (range, segment_length) = if let Some(requested_range) = requested_range {
            let ranges = requested_range.ranges_for_length(Some(size as u64));
            let Some(ranges) = ranges else {
                errors.push(format!("{path}, Unsatisfiable Range"));
                continue;
            };
            if ranges.len() != 1 {
                errors.push(format!("{path}, Unsatisfiable Range"));
                continue;
            }
            let (start, end) = ranges[0];
            if start == 0 && end == size as u64 {
                (None, size)
            } else {
                (Some(format!("{start}-{}", end - 1)), (end - start) as i64)
            }
        } else {
            (None, size)
        };
        if segment_length < 1 && i + 1 != entries.len() {
            errors.push(format!(
                "{path}, Too small; each segment must be at least 1 byte."
            ));
            continue;
        }

        let mut stored = serde_json::Map::new();
        stored.insert("name".to_string(), stored_path.into());
        stored.insert("bytes".to_string(), size.into());
        stored.insert("hash".to_string(), hash.clone().into());
        if let Some(range) = &range {
            stored.insert("range".to_string(), range.clone().into());
        }
        if is_sub_slo {
            stored.insert("sub_slo".to_string(), true.into());
        }
        internal.push(serde_json::Value::Object(stored));
        slo_segs.push(SloSegment {
            hash,
            segment_length,
            range,
            raw_data: None,
        });
    }
    PutManifestBuilt {
        internal,
        slo_segs,
        errors,
        has_object_backed,
        entry_count: entries.len(),
    }
}

/// Store the validated internal manifest (or return a 400).
fn finish_put(mut req: Request, next: &NextFn, built: PutManifestBuilt) -> Response {
    if !built.errors.is_empty() {
        return Response::error(400, &format!("Errors: {}", built.errors.join(", ")));
    }
    if built.entry_count > 0 && !built.has_object_backed {
        return Response::error(
            400,
            "Inline data segments require at least one object-backed segment.",
        );
    }

    let (slo_etag, total) = slo_etag_and_size(&built.slo_segs);
    let client_etag = req
        .headers
        .get("Etag")
        .map(normalize_etag)
        .filter(|etag| !etag.is_empty())
        .map(str::to_string);
    if let Some(client_etag) = client_etag {
        if client_etag != slo_etag {
            return Response::error(422, "Unable to process the contained instructions");
        }
    }
    let body = serde_json::to_vec(&built.internal).unwrap_or_default();
    let json_etag = manifest_etag(&body);
    req.method = "PUT".to_string();
    req.query_string = String::new();
    req.headers.set(SLO_HEADER, "True");
    req.headers.set("Content-Length", body.len().to_string());
    req.headers
        .set(SYSMETA_SLO_ETAG, slo_etag.trim_matches('"'));
    req.headers.set(SYSMETA_SLO_SIZE, total.to_string());
    // The object server validates the transformed stored JSON, not the client
    // manifest or the aggregate large-object representation.
    req.headers.set("Etag", json_etag);
    if req.headers.get("Content-Type").is_none() {
        req.headers.set("Content-Type", "application/json");
    }
    req.body = body.into();
    let mut resp = next(req);
    if (200..300).contains(&resp.status) {
        // The client-visible PUT response names the aggregate SLO, while the
        // backend response named the physical JSON bytes stored above.
        resp.headers.set("Etag", format!("\"{slo_etag}\""));
    }
    resp
}

async fn finish_put_async(
    mut req: Request,
    next: AsyncNextFn,
    built: PutManifestBuilt,
) -> Response {
    if !built.errors.is_empty() {
        return Response::error(400, &format!("Errors: {}", built.errors.join(", ")));
    }
    if built.entry_count > 0 && !built.has_object_backed {
        return Response::error(
            400,
            "Inline data segments require at least one object-backed segment.",
        );
    }
    let (slo_etag, total) = slo_etag_and_size(&built.slo_segs);
    let client_etag = req
        .headers
        .get("Etag")
        .map(normalize_etag)
        .filter(|etag| !etag.is_empty())
        .map(str::to_string);
    if let Some(client_etag) = client_etag {
        if client_etag != slo_etag {
            return Response::error(422, "Unable to process the contained instructions");
        }
    }
    let body = serde_json::to_vec(&built.internal).unwrap_or_default();
    let json_etag = manifest_etag(&body);
    req.method = "PUT".to_string();
    req.query_string = String::new();
    req.headers.set(SLO_HEADER, "True");
    req.headers.set("Content-Length", body.len().to_string());
    req.headers
        .set(SYSMETA_SLO_ETAG, slo_etag.trim_matches('"'));
    req.headers.set(SYSMETA_SLO_SIZE, total.to_string());
    req.headers.set("Etag", json_etag);
    if req.headers.get("Content-Type").is_none() {
        req.headers.set("Content-Type", "application/json");
    }
    req.body = body.into();
    let mut resp = next(req).await;
    if (200..300).contains(&resp.status) {
        resp.headers.set("Etag", format!("\"{slo_etag}\""));
    }
    resp
}

/// Streamed heartbeat PUT body (Python slo.py): leading space, per-HEAD
/// spaces, then `\r\n\r\n` + final JSON status under a 202 response.
struct HeartbeatPutBody {
    next: NextFn,
    req: Request,
    version: String,
    account: String,
    entries: Vec<serde_json::Value>,
    /// 0 = need first space, 1 = running validation+put, 2 = drained.
    phase: u8,
    pending: Vec<u8>,
    pending_pos: usize,
    yield_frequency: f64,
}

fn heartbeat_put_stream(
    req: Request,
    entries: Vec<serde_json::Value>,
    version: String,
    account: String,
    next: NextFn,
    yield_frequency: f64,
) -> Response {
    let reader = HeartbeatPutBody {
        next,
        req,
        version,
        account,
        entries,
        phase: 0,
        pending: Vec::new(),
        pending_pos: 0,
        yield_frequency,
    };
    let mut out = Response::new(202);
    out.headers.set("Content-Type", "application/json");
    // Unknown length → chunked on the wire (Python streams heartbeats).
    out.body = Body::from_reader(Box::new(reader), None);
    out
}

/// Warm segment HEADs with a bounded thread pile (Python concurrency).
fn concurrent_head_warm(
    entries: &[serde_json::Value],
    version: &str,
    account: &str,
    req: &Request,
    next: &NextFn,
    concurrent_gets: usize,
) {
    use std::sync::{Arc, Mutex};
    use std::thread;

    let mut jobs: Vec<(usize, String)> = Vec::new();
    for (i, e) in entries.iter().enumerate() {
        let Some(obj) = e.as_object() else { continue };
        if obj.contains_key("data") {
            continue;
        }
        let Some(path) = obj.get("path").and_then(|v| v.as_str()) else {
            continue;
        };
        let stored_path = format!("/{}", path.trim_start_matches('/'));
        let seg_path = format!("/{version}/{account}{stored_path}");
        jobs.push((i, seg_path));
    }
    if jobs.is_empty() || concurrent_gets <= 1 {
        return;
    }
    let next = Arc::clone(next);
    let req_template = req.clone_head();
    let queue: Arc<Mutex<Vec<(usize, String)>>> = Arc::new(Mutex::new(jobs));
    let workers = concurrent_gets.clamp(1, 16);
    let mut handles = Vec::new();
    for _ in 0..workers {
        let q = Arc::clone(&queue);
        let next = Arc::clone(&next);
        let tmpl = req_template.clone_head();
        handles.push(thread::spawn(move || loop {
            let job = {
                let mut g = q.lock().unwrap();
                g.pop()
            };
            let Some((_i, path)) = job else { break };
            let mut head = tmpl.clone_head();
            head.method = "HEAD".to_string();
            head.path = path;
            head.query_string = String::new();
            head.headers.remove("Content-Length");
            let _ = next(head);
        }));
    }
    for h in handles {
        let _ = h.join();
    }
}

impl HeartbeatPutBody {
    fn push(&mut self, bytes: &[u8]) {
        self.pending.extend_from_slice(bytes);
    }

    fn run_work(&mut self) {
        let mut spaces = Vec::new();
        let yf = self.yield_frequency;
        let mut last_yield = std::time::Instant::now();
        // Always emit at least one space per HEAD when yf == 0; otherwise
        // throttle to wall-clock yield_frequency (Python slo.py).
        let mut on_head = || {
            if yf <= 0.0 || last_yield.elapsed().as_secs_f64() >= yf {
                spaces.push(b' ');
                last_yield = std::time::Instant::now();
            }
        };
        let built = validate_put_entries(
            &self.req,
            &self.entries,
            &self.version,
            &self.account,
            &self.next,
            &mut on_head,
        );
        // Spaces collected during HEADs (after the leading space already sent).
        self.push(&spaces);
        let resp = if !built.errors.is_empty() {
            Response::error(400, &format!("Errors: {}", built.errors.join(", ")))
        } else if built.entry_count > 0 && !built.has_object_backed {
            Response::error(
                400,
                "Inline data segments require at least one object-backed segment.",
            )
        } else {
            // Need owned req for finish_put — clone_head + body empty then rebuild.
            let mut put_req = self.req.clone_head();
            put_req.method = "PUT".to_string();
            // finish_put overwrites method/query/body/headers as needed.
            finish_put(put_req, &self.next, built)
        };
        self.push(b"\r\n\r\n");
        self.push(&heartbeat_final_json(&resp));
    }
}

impl Read for HeartbeatPutBody {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if self.pending_pos < self.pending.len() {
                let n = (self.pending.len() - self.pending_pos).min(buf.len());
                buf[..n].copy_from_slice(&self.pending[self.pending_pos..self.pending_pos + n]);
                self.pending_pos += n;
                if self.pending_pos >= self.pending.len() {
                    self.pending.clear();
                    self.pending_pos = 0;
                }
                return Ok(n);
            }
            match self.phase {
                0 => {
                    // First heartbeat byte immediately (Python resp_iter).
                    self.push(b" ");
                    self.phase = 1;
                }
                1 => {
                    self.run_work();
                    self.phase = 2;
                }
                _ => return Ok(0),
            }
        }
    }
}

fn heartbeat_final_json(resp: &Response) -> Vec<u8> {
    let status = resp.status;
    let body_note = match &resp.body {
        Body::Buffered(b) if !b.is_empty() => String::from_utf8_lossy(b).into_owned(),
        _ => String::new(),
    };
    let summary = serde_json::json!({
        "Response Status": format!("{status} {}", swift_http::reason_phrase(status)),
        "Response Body": body_note,
        "Errors": [],
    });
    summary.to_string().into_bytes()
}

/// Python `EXPIRER_CONTAINER_PER_DIVISOR` — hash shards per day bucket.
const EXPIRER_CONTAINER_PER_DIVISOR: i64 = 100;

/// Expirer task container — Python `ExpirerConfig.get_expirer_container`.
///
/// ```text
/// shard_int = int(hash_path(acc, cont, obj), 16) % 100
/// bucket    = (x_delete_at // 86400) * 86400 - shard_int
/// return normalize_delete_at_timestamp(bucket)  # 10-digit zero-pad, clamped ≥ 0
/// ```
fn expirer_task_container(
    delete_at: i64,
    hash_config: &HashPathConfig,
    account: &str,
    container: &str,
    object: &str,
) -> String {
    let day = delete_at.div_euclid(EXPIRER_CONTAINER_DIVISOR) * EXPIRER_CONTAINER_DIVISOR;
    let shard = match hash_config.hash_path(account, Some(container), Some(object)) {
        Ok(hex) => {
            // MD5 hex is 128 bits; Python `int(hex, 16) % 100` — u128 is exact.
            let v = u128::from_str_radix(&hex, 16).unwrap_or(0);
            (v % (EXPIRER_CONTAINER_PER_DIVISOR as u128)) as i64
        }
        Err(_) => 0,
    };
    let bucket = day - shard;
    // Python normalize_delete_at_timestamp clamps negatives to 0.
    normalize_delete_at_timestamp(bucket as f64, false)
}

/// HEAD-probe write access for async-delete (Python authorize + get_container_info).
///
/// Always HEADs the manifest container with client auth headers; when
/// `segment_container` differs, also HEADs that path. 401/403 stop the flow.
fn probe_async_delete_write_acl(
    next: &NextFn,
    req: &Request,
    version: &str,
    account: &str,
    manifest_container: &str,
    segment_container: &str,
) -> Option<Response> {
    let probe_one = |container: &str| -> Option<Response> {
        let mut probe = req.clone_head();
        probe.method = "HEAD".to_string();
        probe.path = format!("/{version}/{account}/{container}");
        probe.query_string.clear();
        probe.headers.remove("Content-Length");
        probe.body = Body::empty();
        let pr = next(probe);
        if pr.status == 401 || pr.status == 403 {
            Some(Response::error(
                pr.status,
                if pr.status == 401 {
                    "401 Unauthorized"
                } else {
                    "403 Forbidden"
                },
            ))
        } else {
            None
        }
    };
    if let Some(r) = probe_one(manifest_container) {
        return Some(r);
    }
    if segment_container != manifest_container {
        if let Some(r) = probe_one(segment_container) {
            return Some(r);
        }
    }
    None
}

impl Middleware for Slo {
    fn intercepts_request(&self, req: &Request) -> bool {
        if split_path(&req.path, 4, 4, true).is_err() {
            return false;
        }
        let mpm = req.param("multipart-manifest");
        (req.method == "PUT" && mpm.as_deref() == Some("put"))
            || (req.method == "DELETE" && mpm.as_deref() == Some("delete"))
    }

    fn intercepts_response(&self) -> bool {
        true
    }

    fn handle_request_async(
        &self,
        req: Request,
        next: AsyncNextFn,
    ) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        Box::pin(async move {
            let mpm = req.param("multipart-manifest");
            if req.method == "PUT" && mpm.as_deref() == Some("put") {
                return self.handle_put_async(req, next).await;
            }
            if req.method == "DELETE" && mpm.as_deref() == Some("delete") {
                return self.handle_multipart_delete_async(req, next).await;
            }
            next(req).await
        })
    }

    fn reassemble_async(
        &self,
        req: Request,
        next: AsyncNextFn,
    ) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        Box::pin(async move {
            if split_path(&req.path, 4, 4, true).is_err() {
                return next(req).await;
            }
            if req.method == "GET" || req.method == "HEAD" {
                return self.handle_get_head_async(req, next).await;
            }
            next(req).await
        })
    }

    fn handle(&self, req: Request, next: &NextFn) -> Response {
        if split_path(&req.path, 4, 4, true).is_err() {
            return next(req);
        }
        let mpm = req.param("multipart-manifest");
        // PUT ?multipart-manifest=put creates an SLO from a client manifest.
        if req.method == "PUT" && mpm.as_deref() == Some("put") {
            return self.handle_put(req, next);
        }
        // DELETE ?multipart-manifest=delete removes segments then the manifest.
        if req.method == "DELETE" && mpm.as_deref() == Some("delete") {
            return self.handle_multipart_delete(req, next);
        }
        let is_get_head = req.method == "GET" || req.method == "HEAD";
        if is_get_head && mpm.as_deref() == Some("get") {
            // format=raw → client-shaped JSON for server-side copy.
            if req.param("format").as_deref() == Some("raw") {
                return self.handle_manifest_get_raw(req, next);
            }
            return self.handle_manifest_get(req, next);
        }
        // GET/HEAD reassembles unless ?multipart-manifest=get asked for raw.
        if is_get_head {
            return self.handle_get_head(req, next);
        }
        next(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slo_etag_whole_segments() {
        // md5("etag1" + "etag2")
        let segs = vec![
            SloSegment::whole("etag1", 100),
            SloSegment::whole("etag2", 250),
        ];
        let (etag, size) = slo_etag_and_size(&segs);
        assert_eq!(size, 350);
        assert_eq!(etag, md5_hex(b"etag1etag2"));
        assert_eq!(etag.len(), 32);
    }

    #[test]
    fn test_slo_etag_ranged_segment() {
        // ranged contribution is "{hash}:{range};"
        let segs = vec![SloSegment {
            hash: "abc".into(),
            segment_length: 10,
            range: Some("0-9".into()),
            raw_data: None,
        }];
        let (etag, size) = slo_etag_and_size(&segs);
        assert_eq!(size, 10);
        assert_eq!(etag, md5_hex(b"abc:0-9;"));
    }

    #[test]
    fn test_slo_etag_data_segment() {
        // inline data contributes md5(raw_data)
        let segs = vec![SloSegment {
            hash: String::new(),
            segment_length: 5,
            range: None,
            raw_data: Some(b"hello".to_vec()),
        }];
        let (etag, _) = slo_etag_and_size(&segs);
        assert_eq!(etag, md5_hex(md5_hex(b"hello").as_bytes()));
    }

    #[test]
    fn test_manifest_etag() {
        let json = br#"[{"path":"/c/o","etag":"e","size_bytes":1}]"#;
        assert_eq!(manifest_etag(json), md5_hex(json));
    }

    #[test]
    fn test_normalize_etag() {
        assert_eq!(normalize_etag("\"abc\""), "abc");
        assert_eq!(normalize_etag("abc"), "abc");
        assert_eq!(normalize_etag("\""), "\"");
        assert_eq!(normalize_etag(""), "");
    }

    #[test]
    fn test_dlo_etag() {
        // md5("h1" + "h2") wrapped in quotes; quotes on inputs are stripped
        let (etag, size) = dlo_etag_and_size(&[("\"h1\"".to_string(), 10), ("h2".to_string(), 20)]);
        assert_eq!(size, 30);
        assert_eq!(etag, format!("\"{}\"", md5_hex(b"h1h2")));
    }

    /// Canned responses are torn into Sync parts (a `Body` reader is only
    /// `Send`) and re-issued per request, so one route can serve many
    /// subrequests.
    #[allow(clippy::type_complexity)]
    fn backend(routes: Vec<(&'static str, &'static str, Response)>) -> NextFn {
        let routes: Vec<(String, String, u16, HeaderKeyDict, Vec<u8>)> = routes
            .into_iter()
            .map(|(m, p, mut r)| {
                let body = r.body.materialize(u64::MAX).unwrap().to_vec();
                (m.to_string(), p.to_string(), r.status, r.headers, body)
            })
            .collect();
        Arc::new(move |req: Request| {
            for (m, p, status, headers, body) in routes.iter() {
                if &req.method == m && &req.path == p {
                    // Object-server parity: ignore Range when the ignore-range
                    // header names metadata this response carries (SLO
                    // manifests must return the full JSON).
                    let ignore = req
                        .headers
                        .get(IGNORE_RANGE_HDR)
                        .map(|v| v.split(',').any(|n| headers.get(n.trim()).is_some()))
                        .unwrap_or(false);
                    let (status, slice) = if !ignore {
                        if let Some(rh) = req.headers.get("Range") {
                            if let Ok(parsed) = Range::parse(rh) {
                                if let Some(ranges) =
                                    parsed.ranges_for_length(Some(body.len() as u64))
                                {
                                    if ranges.len() == 1 {
                                        let (a, b) = ranges[0];
                                        let slice = body
                                            .get(a as usize..b as usize)
                                            .unwrap_or(&[])
                                            .to_vec();
                                        (206u16, slice)
                                    } else {
                                        (*status, body.clone())
                                    }
                                } else {
                                    (*status, body.clone())
                                }
                            } else {
                                (*status, body.clone())
                            }
                        } else {
                            (*status, body.clone())
                        }
                    } else {
                        (*status, body.clone())
                    };
                    let mut out = Response::new(status);
                    out.headers = headers.clone();
                    out.body = slice.into();
                    return out;
                }
            }
            Response::new(404)
        })
    }

    fn two_segment_manifest_json() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!([
            {"name": "/c/s1", "bytes": 3, "hash": md5_hex(b"one")},
            {"name": "/c/s2", "bytes": 3, "hash": md5_hex(b"two")},
        ]))
        .unwrap()
    }

    fn slo_manifest_backend() -> NextFn {
        let manifest_json = two_segment_manifest_json();
        let json_etag = manifest_etag(&manifest_json);
        let mut manifest = Response::with_body(200, manifest_json);
        manifest.headers.set("X-Static-Large-Object", "True");
        manifest.headers.set("Content-Type", "text/plain");
        manifest.headers.set("Etag", json_etag);
        backend(vec![
            ("GET", "/v1/a/c/manifest", manifest),
            (
                "GET",
                "/v1/a/c/s1",
                Response::with_body(200, b"one".to_vec()),
            ),
            (
                "GET",
                "/v1/a/c/s2",
                Response::with_body(200, b"two".to_vec()),
            ),
        ])
    }

    fn slo_get(path: &str, range: Option<&str>) -> Request {
        let mut headers = HeaderKeyDict::new();
        if let Some(r) = range {
            headers.set("Range", r);
        }
        Request {
            method: "GET".to_string(),
            path: path.to_string(),
            query_string: String::new(),
            headers,
            body: Body::empty(),
        }
    }

    fn body_of(resp: &mut Response) -> Vec<u8> {
        resp.body.materialize(u64::MAX).unwrap().to_vec()
    }

    #[test]
    fn test_slo_full_get_reassembles() {
        let be = slo_manifest_backend();
        let mut resp = Slo::new().handle(slo_get("/v1/a/c/manifest", None), &be);
        assert_eq!(resp.status, 200);
        // the streamed body declares the aggregate length before any segment
        // subrequest is issued
        assert_eq!(resp.body.content_length(), Some(6));
        assert_eq!(body_of(&mut resp), b"onetwo");
        assert_eq!(resp.headers.get("Content-Length"), Some("6"));
        assert_eq!(resp.headers.get("Content-Type"), Some("text/plain"));
        let aggregate = md5_hex(format!("{}{}", md5_hex(b"one"), md5_hex(b"two")).as_bytes());
        assert_eq!(
            resp.headers.get("Etag"),
            Some(format!("\"{aggregate}\"").as_str())
        );
        assert_eq!(
            resp.headers.get(MANIFEST_ETAG_HEADER),
            Some(manifest_etag(&two_segment_manifest_json()).as_str())
        );
    }

    #[test]
    fn test_slo_range_get() {
        // "onetwo"[2..5] = "etw"
        let be = slo_manifest_backend();
        let mut resp = Slo::new().handle(slo_get("/v1/a/c/manifest", Some("bytes=2-4")), &be);
        assert_eq!(resp.status, 206);
        assert_eq!(body_of(&mut resp), b"etw");
        assert_eq!(resp.headers.get("Content-Range"), Some("bytes 2-4/6"));
        assert_eq!(
            resp.headers.get(MANIFEST_ETAG_HEADER),
            Some(manifest_etag(&two_segment_manifest_json()).as_str())
        );
    }

    #[test]
    fn test_slo_non_manifest_passthrough() {
        let be = backend(vec![(
            "GET",
            "/v1/a/c/plain",
            Response::with_body(200, b"hi".to_vec()),
        )]);
        let mut resp = Slo::new().handle(slo_get("/v1/a/c/plain", None), &be);
        assert_eq!(resp.status, 200);
        assert_eq!(body_of(&mut resp), b"hi");
    }

    #[test]
    fn test_slo_get_is_lazy_and_aborts_midstream() {
        // The FnReader body issues each segment subrequest only as the
        // stream reaches it; a failing segment surfaces as a read error
        // (never a buffered 409 — the 200 head is already committed).
        let manifest_json = serde_json::to_vec(&serde_json::json!([
            {"name": "/c/s1", "bytes": 3, "hash": md5_hex(b"one")},
            {"name": "/c/missing", "bytes": 3, "hash": "x"},
        ]))
        .unwrap();
        let mut manifest = Response::with_body(200, manifest_json);
        manifest.headers.set("X-Static-Large-Object", "True");
        let be = backend(vec![
            ("GET", "/v1/a/c/manifest", manifest),
            (
                "GET",
                "/v1/a/c/s1",
                Response::with_body(200, b"one".to_vec()),
            ),
        ]);
        let resp = Slo::new().handle(slo_get("/v1/a/c/manifest", None), &be);
        assert_eq!(resp.status, 200);
        let (mut reader, len) = resp.body.into_reader();
        assert_eq!(len, Some(6));
        let mut out = Vec::new();
        let err = reader.read_to_end(&mut out).unwrap_err();
        assert!(err.to_string().contains("/v1/a/c/missing"), "{err}");
        assert_eq!(out, b"one");
    }

    #[test]
    fn test_slo_nested_sub_slo_get() {
        // Outer manifest references an inner SLO (sub_slo=true); GET must
        // expand the submanifest and stream leaf bytes.
        let inner_json = serde_json::to_vec(&serde_json::json!([
            {"name": "/c/a", "bytes": 2, "hash": md5_hex(b"aa")},
            {"name": "/c/b", "bytes": 2, "hash": md5_hex(b"bb")},
        ]))
        .unwrap();
        let outer_json = serde_json::to_vec(&serde_json::json!([
            {
                "name": "/c/inner",
                "bytes": 4,
                "hash": md5_hex(format!("{}{}", md5_hex(b"aa"), md5_hex(b"bb")).as_bytes()),
                "sub_slo": true
            },
            {"name": "/c/c", "bytes": 2, "hash": md5_hex(b"cc")},
        ]))
        .unwrap();
        let mut outer = Response::with_body(200, outer_json);
        outer.headers.set("X-Static-Large-Object", "True");
        outer.headers.set("Content-Type", "text/plain");
        let mut inner = Response::with_body(200, inner_json);
        inner.headers.set("X-Static-Large-Object", "True");
        let be = backend(vec![
            ("GET", "/v1/a/c/outer", outer),
            ("GET", "/v1/a/c/inner", inner),
            ("GET", "/v1/a/c/a", Response::with_body(200, b"aa".to_vec())),
            ("GET", "/v1/a/c/b", Response::with_body(200, b"bb".to_vec())),
            ("GET", "/v1/a/c/c", Response::with_body(200, b"cc".to_vec())),
        ]);
        let mut resp = Slo::new().handle(slo_get("/v1/a/c/outer", None), &be);
        assert_eq!(resp.status, 200);
        assert_eq!(body_of(&mut resp), b"aabbcc");
        assert_eq!(resp.headers.get("Content-Length"), Some("6"));
    }

    #[test]
    fn test_slo_range_uses_per_segment_range() {
        // Ranged GET must issue a Range on the intersecting segment only.
        use std::sync::{Arc, Mutex};
        let log = Arc::new(Mutex::new(Vec::<(String, Option<String>)>::new()));
        let log2 = log.clone();
        let manifest_json = serde_json::to_vec(&serde_json::json!([
            {"name": "/c/s1", "bytes": 3, "hash": md5_hex(b"one")},
            {"name": "/c/s2", "bytes": 3, "hash": md5_hex(b"two")},
        ]))
        .unwrap();
        let be: NextFn = Arc::new(move |req: Request| {
            if req.method == "GET" && req.path == "/v1/a/c/manifest" {
                let mut manifest = Response::with_body(200, manifest_json.clone());
                manifest.headers.set("X-Static-Large-Object", "True");
                return manifest;
            }
            let range = req.headers.get("Range").map(str::to_string);
            log2.lock().unwrap().push((req.path.clone(), range.clone()));
            match req.path.as_str() {
                "/v1/a/c/s1" => Response::with_body(200, b"one".to_vec()),
                "/v1/a/c/s2" => {
                    // bytes=0-0 of "two" → "t"
                    if range.as_deref() == Some("bytes=0-0") {
                        Response::with_body(206, b"t".to_vec())
                    } else {
                        Response::with_body(200, b"two".to_vec())
                    }
                }
                _ => Response::new(404),
            }
        });
        // "onetwo"[3..4] = "t" → only s2 with bytes=0-0
        let mut resp = Slo::new().handle(slo_get("/v1/a/c/manifest", Some("bytes=3-3")), &be);
        assert_eq!(resp.status, 206);
        assert_eq!(body_of(&mut resp), b"t");
        let calls = log.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "/v1/a/c/s2");
        assert_eq!(calls[0].1.as_deref(), Some("bytes=0-0"));
    }

    #[test]
    fn test_slo_head_uses_sysmeta_not_manifest_length() {
        // HEAD body is empty; Content-Length/Etag must come from SLO sysmeta.
        let physical_etag = md5_hex(b"stored-manifest-json");
        let backend_physical_etag = physical_etag.clone();
        let be: NextFn = Arc::new(move |req: Request| {
            assert_eq!(req.method, "HEAD");
            let mut resp = Response::new(200);
            resp.headers.set("X-Static-Large-Object", "True");
            resp.headers.set("Content-Length", "159"); // physical manifest
            resp.headers.set("Etag", &backend_physical_etag);
            resp.headers
                .set(SYSMETA_SLO_ETAG, "aabbccddeeff00112233445566778899");
            resp.headers.set(SYSMETA_SLO_SIZE, "6");
            resp.headers.set("Content-Type", "text/plain");
            resp
        });
        let req = Request {
            method: "HEAD".to_string(),
            path: "/v1/a/c/manifest".to_string(),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: Body::empty(),
        };
        let resp = Slo::new().handle(req, &be);
        assert_eq!(resp.status, 200);
        assert_eq!(resp.headers.get("Content-Length"), Some("6"));
        assert_eq!(
            resp.headers.get("Etag"),
            Some("\"aabbccddeeff00112233445566778899\"")
        );
        assert_eq!(
            resp.headers.get(MANIFEST_ETAG_HEADER),
            Some(physical_etag.as_str())
        );
    }

    #[test]
    fn test_multipart_manifest_get_uses_json_content_type() {
        let stored = two_segment_manifest_json();
        let physical_etag = manifest_etag(&stored);
        let mut manifest = Response::with_body(200, stored.clone());
        manifest.headers.set(SLO_HEADER, "True");
        manifest
            .headers
            .set("Content-Type", "application/octet-stream");
        manifest.headers.set("Etag", &physical_etag);
        let be = backend(vec![("GET", "/v1/a/c/manifest", manifest)]);
        let req = Request {
            method: "GET".to_string(),
            path: "/v1/a/c/manifest".to_string(),
            query_string: "multipart-manifest=get".to_string(),
            headers: HeaderKeyDict::new(),
            body: Body::empty(),
        };

        let mut resp = Slo::new().handle(req, &be);
        assert_eq!(resp.status, 200);
        assert_eq!(body_of(&mut resp), stored);
        assert_eq!(
            resp.headers.get("Content-Type"),
            Some("application/json; charset=utf-8")
        );
        assert_eq!(resp.headers.get("Etag"), Some(physical_etag.as_str()));
    }

    #[test]
    fn test_multipart_manifest_get_format_raw() {
        let stored = serde_json::to_vec(&serde_json::json!([
            {"name": "/c/s1", "bytes": 3, "hash": "abc", "sub_slo": false},
            {"name": "/c/s2", "bytes": 4, "hash": "def", "range": "0-1"},
        ]))
        .unwrap();
        let be: NextFn = Arc::new(move |req: Request| {
            assert!(req.query_string.contains("multipart-manifest=get"));
            let mut resp = Response::with_body(200, stored.clone());
            resp.headers.set("X-Static-Large-Object", "True");
            resp.headers.set("Content-Type", "application/octet-stream");
            resp
        });
        let req = Request {
            method: "GET".to_string(),
            path: "/v1/a/c/manifest".to_string(),
            query_string: "multipart-manifest=get&format=raw".to_string(),
            headers: HeaderKeyDict::new(),
            body: Body::empty(),
        };
        let mut resp = Slo::new().handle(req, &be);
        assert_eq!(resp.status, 200);
        let body = body_of(&mut resp);
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let arr = v.as_array().unwrap();
        assert_eq!(arr[0]["path"], "/c/s1");
        assert_eq!(arr[0]["size_bytes"], 3);
        assert_eq!(arr[0]["etag"], "abc");
        assert!(arr[0].get("sub_slo").is_none());
        assert_eq!(arr[1]["path"], "/c/s2");
        assert_eq!(arr[1]["range"], "0-1");
        assert_eq!(
            resp.headers.get("Content-Type"),
            Some("application/octet-stream")
        );
        assert_eq!(
            resp.headers.get("Etag"),
            Some(manifest_etag(&body).as_str())
        );
        assert!(resp.headers.get(MANIFEST_ETAG_HEADER).is_none());
    }

    #[test]
    fn test_inline_data_put_and_get() {
        use std::sync::{Arc as SArc, Mutex};
        let writes: SArc<Mutex<Vec<Vec<u8>>>> = SArc::new(Mutex::new(Vec::new()));
        let w_put = writes.clone();
        let w_get = writes.clone();
        let be: NextFn = Arc::new(move |mut req: Request| {
            if req.method == "HEAD" && req.path == "/v1/a/c/s1" {
                let mut r = Response::new(200);
                r.headers.set("Etag", md5_hex(b"one"));
                r.headers.set("Content-Length", "3");
                return r;
            }
            if req.method == "PUT" && req.path == "/v1/a/c/manifest" {
                let body = req.body.materialize(u64::MAX).unwrap().to_vec();
                w_put.lock().unwrap().push(body);
                return Response::new(201);
            }
            if req.method == "GET" && req.path == "/v1/a/c/manifest" {
                let body = w_get.lock().unwrap().last().cloned().unwrap_or_default();
                let mut r = Response::with_body(200, body);
                r.headers.set("X-Static-Large-Object", "True");
                // No sysmeta → reassembly recomputes etag/size from JSON.
                return r;
            }
            if req.method == "GET" && req.path == "/v1/a/c/s1" {
                return Response::with_body(200, b"one".to_vec());
            }
            Response::new(404)
        });
        let data_b64 = B64.encode(b" hi ");
        let manifest = serde_json::json!([
            {"path": "/c/s1", "etag": md5_hex(b"one"), "size_bytes": 3},
            {"data": data_b64},
        ]);
        let body = serde_json::to_vec(&manifest).unwrap();
        let put = Request {
            method: "PUT".into(),
            path: "/v1/a/c/manifest".into(),
            query_string: "multipart-manifest=put".into(),
            headers: HeaderKeyDict::new(),
            body: body.into(),
        };
        let resp = Slo::new().handle(put, &be);
        assert_eq!(resp.status, 201, "{resp:?}");
        let stored = writes.lock().unwrap()[0].clone();
        let v: serde_json::Value = serde_json::from_slice(&stored).unwrap();
        assert!(v[1].get("data").is_some());
        // GET reassembly: "one" + " hi "
        let mut get = Slo::new().handle(slo_get("/v1/a/c/manifest", None), &be);
        assert_eq!(get.status, 200);
        assert_eq!(body_of(&mut get), b"one hi ");
    }

    #[test]
    fn test_inline_data_only_rejected() {
        let be: NextFn = Arc::new(|_req: Request| Response::new(404));
        let manifest = serde_json::json!([{"data": B64.encode(b"x")}]);
        let body = serde_json::to_vec(&manifest).unwrap();
        let put = Request {
            method: "PUT".into(),
            path: "/v1/a/c/manifest".into(),
            query_string: "multipart-manifest=put".into(),
            headers: HeaderKeyDict::new(),
            body: body.into(),
        };
        let resp = Slo::new().handle(put, &be);
        assert_eq!(resp.status, 400);
    }

    #[test]
    fn test_heartbeat_put_returns_202() {
        let be: NextFn = Arc::new(|req: Request| {
            if req.method == "HEAD" {
                let mut r = Response::new(200);
                r.headers.set("Etag", "e");
                r.headers.set("Content-Length", "1");
                return r;
            }
            if req.method == "PUT" {
                return Response::new(201);
            }
            Response::new(404)
        });
        let manifest = serde_json::json!([{"path": "/c/s1", "etag": "e", "size_bytes": 1}]);
        let body = serde_json::to_vec(&manifest).unwrap();
        let put = Request {
            method: "PUT".into(),
            path: "/v1/a/c/manifest".into(),
            query_string: "multipart-manifest=put&heartbeat=on".into(),
            headers: HeaderKeyDict::new(),
            body: body.into(),
        };
        let mut resp = Slo::new().handle(put, &be);
        assert_eq!(resp.status, 202);
        // Streamed body (no pre-declared Content-Length) — heartbeats can
        // flush before validation finishes.
        assert!(matches!(resp.body, Body::Streamed(_)));
        assert_eq!(resp.body.content_length(), None);
        let b = body_of(&mut resp);
        assert!(b.starts_with(b" "), "{b:?}");
        assert!(b.windows(4).any(|w| w == b"\r\n\r\n"));
        // Leading space + one per HEAD + separator + JSON with 201.
        let text = String::from_utf8_lossy(&b);
        assert!(text.contains("201 Created"), "{text}");
    }

    #[test]
    fn test_heartbeat_put_yields_space_per_head() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let heads = Arc::new(AtomicUsize::new(0));
        let h2 = heads.clone();
        let be: NextFn = Arc::new(move |req: Request| {
            if req.method == "HEAD" {
                h2.fetch_add(1, Ordering::SeqCst);
                let mut r = Response::new(200);
                r.headers.set("Etag", "e");
                r.headers.set("Content-Length", "1");
                return r;
            }
            if req.method == "PUT" {
                return Response::new(201);
            }
            Response::new(404)
        });
        let manifest = serde_json::json!([
            {"path": "/c/s1", "etag": "e", "size_bytes": 1},
            {"path": "/c/s2", "etag": "e", "size_bytes": 1},
            {"path": "/c/s3", "etag": "e", "size_bytes": 1},
        ]);
        let body = serde_json::to_vec(&manifest).unwrap();
        let put = Request {
            method: "PUT".into(),
            path: "/v1/a/c/manifest".into(),
            query_string: "multipart-manifest=put&heartbeat=on".into(),
            headers: HeaderKeyDict::new(),
            body: body.into(),
        };
        let mut resp = Slo::new().handle(put, &be);
        assert_eq!(resp.status, 202);
        let b = body_of(&mut resp);
        assert_eq!(heads.load(Ordering::SeqCst), 3);
        // First space + one space per HEAD before the \r\n\r\n separator.
        let sep = b.windows(4).position(|w| w == b"\r\n\r\n").expect("sep");
        let prefix = &b[..sep];
        assert!(
            prefix.iter().filter(|&&c| c == b' ').count() >= 4,
            "expected leading + per-HEAD spaces, got prefix {prefix:?}"
        );
    }

    #[test]
    fn test_multipart_manifest_delete() {
        use std::sync::{Arc as SArc, Mutex};
        let deleted: SArc<Mutex<Vec<String>>> = SArc::new(Mutex::new(Vec::new()));
        let d2 = deleted.clone();
        let manifest_json = serde_json::to_vec(&serde_json::json!([
            {"name": "/c/s1", "bytes": 3, "hash": "h1"},
            {"name": "/c/s2", "bytes": 3, "hash": "h2"},
            {"data": B64.encode(b"x")},
        ]))
        .unwrap();
        let be: NextFn = Arc::new(move |req: Request| {
            if req.method == "GET"
                && req.path == "/v1/a/c/manifest"
                && req.query_string.contains("multipart-manifest=get")
            {
                let mut r = Response::with_body(200, manifest_json.clone());
                r.headers.set("X-Static-Large-Object", "True");
                return r;
            }
            if req.method == "DELETE" {
                d2.lock().unwrap().push(req.path.clone());
                return Response::new(204);
            }
            Response::new(404)
        });
        let req = Request {
            method: "DELETE".into(),
            path: "/v1/a/c/manifest".into(),
            query_string: "multipart-manifest=delete".into(),
            headers: HeaderKeyDict::new(),
            body: Body::empty(),
        };
        let mut resp = Slo::new().handle(req, &be);
        assert_eq!(resp.status, 200);
        let body = body_of(&mut resp);
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["Number Deleted"], 3); // s1, s2, manifest (data skipped)
        let paths = deleted.lock().unwrap().clone();
        assert!(paths.iter().any(|p| p.ends_with("/c/s1")), "{paths:?}");
        assert!(paths.iter().any(|p| p.ends_with("/c/s2")), "{paths:?}");
        assert!(paths.iter().any(|p| p == "/v1/a/c/manifest"), "{paths:?}");
        // manifest last
        assert_eq!(paths.last().map(String::as_str), Some("/v1/a/c/manifest"));
    }

    #[test]
    fn test_multipart_delete_async_enqueues_and_deletes_manifest() {
        use std::sync::{Arc as SArc, Mutex};
        let calls: SArc<Mutex<Vec<(String, String)>>> = SArc::new(Mutex::new(Vec::new()));
        let c2 = calls.clone();
        let update_body: SArc<Mutex<Vec<u8>>> = SArc::new(Mutex::new(Vec::new()));
        let ub2 = update_body.clone();
        let manifest_json = serde_json::to_vec(&serde_json::json!([
            {"name": "/c/s1", "bytes": 3, "hash": "h1"},
            {"name": "/c/s2", "bytes": 3, "hash": "h2"},
            {"data": B64.encode(b"x")},
        ]))
        .unwrap();
        let be: NextFn = Arc::new(move |mut req: Request| {
            c2.lock()
                .unwrap()
                .push((req.method.clone(), req.path.clone()));
            if req.method == "GET"
                && req.path == "/v1/a/c/manifest"
                && req.query_string.contains("multipart-manifest=get")
            {
                let mut r = Response::with_body(200, manifest_json.clone());
                r.headers.set("X-Static-Large-Object", "True");
                return r;
            }
            // ACL probes (HEAD) — allow.
            if req.method == "HEAD" {
                return Response::new(204);
            }
            if req.method == "UPDATE" && req.path.starts_with("/v1/.expiring_objects/") {
                if let Ok(b) = req.body.materialize(MAX_CONTROL_BODY) {
                    *ub2.lock().unwrap() = b.to_vec();
                }
                return Response::new(204);
            }
            if req.method == "DELETE" && req.path == "/v1/a/c/manifest" {
                return Response::new(204);
            }
            Response::new(404)
        });
        let slo = Slo::new();
        let req = Request {
            method: "DELETE".into(),
            path: "/v1/a/c/manifest".into(),
            query_string: "multipart-manifest=delete&async=yes".into(),
            headers: HeaderKeyDict::new(),
            body: Body::empty(),
        };
        let resp = slo.handle(req, &be);
        // Python: response is the manifest DELETE (204).
        assert_eq!(resp.status, 204, "{resp:?}");
        let paths = calls.lock().unwrap().clone();
        assert!(
            paths
                .iter()
                .any(|(m, p)| m == "GET" && p == "/v1/a/c/manifest"),
            "{paths:?}"
        );
        // Write ACL probe on manifest container (segment container == same).
        assert!(
            paths.iter().any(|(m, p)| m == "HEAD" && p == "/v1/a/c"),
            "missing ACL HEAD: {paths:?}"
        );
        let update_paths: Vec<_> = paths
            .iter()
            .filter(|(m, p)| m == "UPDATE" && p.starts_with("/v1/.expiring_objects/"))
            .map(|(_, p)| p.clone())
            .collect();
        assert_eq!(update_paths.len(), 1, "{paths:?}");
        // Task container = day_bucket - (hash_path(a,c,manifest)%100), not plain day.
        let cont_part = update_paths[0]
            .trim_start_matches("/v1/.expiring_objects/")
            .to_string();
        let n: i64 = cont_part.parse().expect("numeric expirer cont");
        let day = Timestamp::now().as_secs_f64() as i64;
        let day_bucket = day.div_euclid(86400) * 86400;
        assert!(
            day_bucket - 99 <= n && n <= day_bucket,
            "cont={cont_part} day_bucket={day_bucket}"
        );
        let hc = HashPathConfig::new(b"".to_vec(), b"changeme".to_vec()).unwrap();
        let expected = expirer_task_container(day, &hc, "a", "c", "manifest");
        assert_eq!(
            cont_part, expected,
            "UPDATE path must use hash-sharded task container"
        );
        assert_ne!(
            cont_part,
            format!("{day_bucket:010}"),
            "must not use plain day bucket"
        );
        assert!(
            paths
                .iter()
                .any(|(m, p)| m == "DELETE" && p == "/v1/a/c/manifest"),
            "{paths:?}"
        );
        // No synchronous segment DELETEs on the happy path.
        assert!(
            !paths
                .iter()
                .any(|(m, p)| m == "DELETE" && p.ends_with("/c/s1")),
            "segments must not be deleted synchronously: {paths:?}"
        );
        let body = update_body.lock().unwrap().clone();
        let jobs: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let arr = jobs.as_array().unwrap();
        assert_eq!(arr.len(), 2, "{jobs}"); // data segment skipped
        for job in arr {
            assert_eq!(job["content_type"], ASYNC_DELETE_TYPE);
            assert_eq!(job["etag"], MD5_OF_EMPTY_STRING);
            assert_eq!(job["size"], 0);
            assert_eq!(job["deleted"], 0);
            let name = job["name"].as_str().unwrap();
            assert!(
                name.contains("-a/c/s1") || name.contains("-a/c/s2"),
                "{name}"
            );
        }
    }

    #[test]
    fn test_multipart_delete_async_rejects_nested() {
        let manifest_json = serde_json::to_vec(&serde_json::json!([
            {"name": "/c/sub", "bytes": 10, "hash": "h", "sub_slo": true},
        ]))
        .unwrap();
        let be: NextFn = Arc::new(move |req: Request| {
            if req.method == "GET" {
                let mut r = Response::with_body(200, manifest_json.clone());
                r.headers.set("X-Static-Large-Object", "True");
                return r;
            }
            Response::new(404)
        });
        let req = Request {
            method: "DELETE".into(),
            path: "/v1/a/c/manifest".into(),
            query_string: "multipart-manifest=delete&async=on".into(),
            headers: HeaderKeyDict::new(),
            body: Body::empty(),
        };
        let mut resp = Slo::new().handle(req, &be);
        assert_eq!(resp.status, 400);
        let raw = body_of(&mut resp);
        let body = String::from_utf8_lossy(&raw);
        assert!(body.contains("No segments may be large objects"), "{body}");
    }

    #[test]
    fn test_multipart_delete_async_rejects_multi_container() {
        let manifest_json = serde_json::to_vec(&serde_json::json!([
            {"name": "/c1/a", "bytes": 1, "hash": "h1"},
            {"name": "/c2/b", "bytes": 1, "hash": "h2"},
        ]))
        .unwrap();
        let be: NextFn = Arc::new(move |req: Request| {
            if req.method == "GET" {
                let mut r = Response::with_body(200, manifest_json.clone());
                r.headers.set("X-Static-Large-Object", "True");
                return r;
            }
            Response::new(404)
        });
        let req = Request {
            method: "DELETE".into(),
            path: "/v1/a/c/manifest".into(),
            query_string: "multipart-manifest=delete&async=yes".into(),
            headers: HeaderKeyDict::new(),
            body: Body::empty(),
        };
        let mut resp = Slo::new().handle(req, &be);
        assert_eq!(resp.status, 400);
        let raw = body_of(&mut resp);
        let body = String::from_utf8_lossy(&raw);
        assert!(
            body.contains("All segments must be in one container"),
            "{body}"
        );
    }

    #[test]
    fn test_multipart_delete_async_manifest_missing() {
        let be: NextFn = Arc::new(|_r| Response::new(404));
        let req = Request {
            method: "DELETE".into(),
            path: "/v1/a/c/manifest".into(),
            query_string: "multipart-manifest=delete&async=yes".into(),
            headers: HeaderKeyDict::new(),
            body: Body::empty(),
        };
        let resp = Slo::new().handle(req, &be);
        assert_eq!(resp.status, 404);
    }

    #[test]
    fn test_multipart_delete_async_update_fallback_deletes_manifest() {
        use std::sync::{Arc as SArc, Mutex};
        use std::time::Duration;
        let deleted: SArc<Mutex<Vec<String>>> = SArc::new(Mutex::new(Vec::new()));
        let d2 = deleted.clone();
        let manifest_json = serde_json::to_vec(&serde_json::json!([
            {"name": "/c/s1", "bytes": 3, "hash": "h1"},
        ]))
        .unwrap();
        let be: NextFn = Arc::new(move |req: Request| {
            if req.method == "GET" {
                let mut r = Response::with_body(200, manifest_json.clone());
                r.headers.set("X-Static-Large-Object", "True");
                return r;
            }
            // UPDATE fails → background segment DELETE fallback.
            if req.method == "UPDATE" {
                return Response::new(503);
            }
            if req.method == "DELETE" {
                d2.lock().unwrap().push(req.path.clone());
                return Response::new(204);
            }
            Response::new(404)
        });
        let req = Request {
            method: "DELETE".into(),
            path: "/v1/a/c/manifest".into(),
            query_string: "multipart-manifest=delete&async=true".into(),
            headers: HeaderKeyDict::new(),
            body: Body::empty(),
        };
        let resp = Slo::new().handle(req, &be);
        assert_eq!(resp.status, 204);
        // Manifest deleted on the request path.
        assert!(
            deleted
                .lock()
                .unwrap()
                .iter()
                .any(|p| p == "/v1/a/c/manifest"),
            "{:?}",
            deleted.lock().unwrap()
        );
        // Best-effort background segment delete eventually runs.
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            if deleted.lock().unwrap().iter().any(|p| p.ends_with("/c/s1")) {
                break;
            }
            if std::time::Instant::now() > deadline {
                panic!(
                    "background segment delete never ran: {:?}",
                    deleted.lock().unwrap()
                );
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn test_expirer_task_container_hash_sharding() {
        // Golden values vs CPython `hash_path` with suffix "changeme",
        // empty prefix (see swift-core hashing tests).
        let hc = HashPathConfig::new(b"".to_vec(), b"changeme".to_vec()).unwrap();

        // hash_path('AUTH_test','c','o') = 7363996f2cfb95eaa18df19ccc31aece
        // int(...,16) % 100 = 38
        assert_eq!(
            hc.hash_path("AUTH_test", Some("c"), Some("o")).unwrap(),
            "7363996f2cfb95eaa18df19ccc31aece"
        );
        assert_eq!(
            expirer_task_container(1_782_000_000, &hc, "AUTH_test", "c", "o"),
            "1781999962" // day 1782000000 - 38
        );
        // hash_path('AUTH_test','c','other') % 100 = 90
        assert_eq!(
            expirer_task_container(1_782_000_000, &hc, "AUTH_test", "c", "other"),
            "1781999910" // day - 90
        );
        // hash_path('a','c','o') % 100 = 37
        assert_eq!(
            expirer_task_container(86_400, &hc, "a", "c", "o"),
            "0000086363"
        );
        assert_eq!(
            expirer_task_container(1_751_500_000, &hc, "a", "c", "o"),
            "1751414363"
        );
        // Python async-delete fixture path: manifest a/c/o drives the shard
        // hash_path('AUTH_test','deltest','man-all-there') % 100 = 71
        assert_eq!(
            expirer_task_container(1_751_500_000, &hc, "AUTH_test", "deltest", "man-all-there"),
            "1751414329"
        );
        // Day-zero clamp: bucket negative → normalize to 0000000000
        assert_eq!(
            expirer_task_container(0, &hc, "AUTH_test", "c", "o"),
            "0000000000"
        );
        // Must not be the plain day bucket
        let plain = format!("{:010}", 1_782_000_000i64.div_euclid(86400) * 86400);
        assert_ne!(
            expirer_task_container(1_782_000_000, &hc, "AUTH_test", "c", "o"),
            plain
        );
    }

    #[test]
    fn test_async_delete_acl_probe_forbidden() {
        use std::sync::{Arc as SArc, Mutex};
        let heads: SArc<Mutex<Vec<String>>> = SArc::new(Mutex::new(Vec::new()));
        let h2 = heads.clone();
        let backend: NextFn = Arc::new(move |req: Request| {
            if req.method == "GET" && req.query_string.contains("multipart-manifest=get") {
                let mut r = Response::with_body(
                    200,
                    br#"[{"name":"/segc/s1","bytes":1,"hash":"0"}]"#.to_vec(),
                );
                r.headers.set("X-Static-Large-Object", "True");
                return r;
            }
            // HEAD probes → 403
            if req.method == "HEAD" {
                h2.lock().unwrap().push(req.path.clone());
                return Response::error(403, "Forbidden");
            }
            Response::error(500, "unexpected")
        });
        let req = Request {
            method: "DELETE".into(),
            path: "/v1/AUTH_test/manic/manifest".into(),
            query_string: "multipart-manifest=delete&async=yes".into(),
            headers: HeaderKeyDict::new(),
            body: Body::empty(),
        };
        let resp = Slo::new().handle(req, &backend);
        assert_eq!(resp.status, 403, "expected ACL probe deny");
        // First probe is the manifest container (Python write_acl on DELETE target).
        let probed = heads.lock().unwrap().clone();
        assert_eq!(
            probed,
            vec!["/v1/AUTH_test/manic".to_string()],
            "{probed:?}"
        );
    }

    #[test]
    fn test_async_delete_acl_probe_segment_container() {
        use std::sync::{Arc as SArc, Mutex};
        let heads: SArc<Mutex<Vec<String>>> = SArc::new(Mutex::new(Vec::new()));
        let h2 = heads.clone();
        let backend: NextFn = Arc::new(move |req: Request| {
            if req.method == "GET" && req.query_string.contains("multipart-manifest=get") {
                let mut r = Response::with_body(
                    200,
                    br#"[{"name":"/segc/s1","bytes":1,"hash":"0"}]"#.to_vec(),
                );
                r.headers.set("X-Static-Large-Object", "True");
                return r;
            }
            if req.method == "HEAD" {
                h2.lock().unwrap().push(req.path.clone());
                // Manifest OK; segment container denied.
                if req.path.ends_with("/segc") {
                    return Response::error(401, "Unauthorized");
                }
                return Response::new(204);
            }
            Response::error(500, "unexpected")
        });
        let req = Request {
            method: "DELETE".into(),
            path: "/v1/AUTH_test/manic/manifest".into(),
            query_string: "multipart-manifest=delete&async=yes".into(),
            headers: HeaderKeyDict::new(),
            body: Body::empty(),
        };
        let resp = Slo::new().handle(req, &backend);
        assert_eq!(resp.status, 401);
        let probed = heads.lock().unwrap().clone();
        assert_eq!(
            probed,
            vec![
                "/v1/AUTH_test/manic".to_string(),
                "/v1/AUTH_test/segc".to_string(),
            ],
            "{probed:?}"
        );
    }
    #[test]
    fn test_refetch_listing_slo_etag() {
        let mut h = HeaderKeyDict::new();
        h.set(SLO_HEADER, "True");
        h.set(SYSMETA_SLO_ETAG, "abcdef");
        let et = refetch_listing_slo_etag("o", "deadbeef-2", &h);
        assert_eq!(et.as_deref(), Some("abcdef"));
        let h2 = HeaderKeyDict::new();
        assert!(refetch_listing_slo_etag("o", "plainmd5hash", &h2).is_none());
    }
}
