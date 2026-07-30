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
//! Both are golden-tested here. Deferred: the streaming GET reassembly, PUT
//! validation/normalization of the client manifest, and range math across
//! segment boundaries (the transport layer), plus DLO's prefix-listing
//! variant.

use std::io::Read;
use std::sync::Arc;

use md5::{Digest, Md5};
use swift_core::config::config_true_value;
use swift_http::{
    body_too_large, split_path, Body, FnReader, HeaderKeyDict, Range, Request, Response,
    MAX_CONTROL_BODY,
};

use crate::{Middleware, NextFn};

/// `max_manifest_size` (Python slo.py default): the client manifest on a
/// `?multipart-manifest=put` may not exceed this.
const MAX_MANIFEST_SIZE: u64 = 8 * 1024 * 1024;

const SLO_HEADER: &str = "X-Static-Large-Object";
const IGNORE_RANGE_HDR: &str = "X-Backend-Ignore-Range-If-Metadata-Present";
const SYSMETA_SLO_ETAG: &str = "X-Object-Sysmeta-Slo-Etag";
const SYSMETA_SLO_SIZE: &str = "X-Object-Sysmeta-Slo-Size";

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
/// like `"/container/object"`, `bytes`, `hash`, optional `range` `"M-N"`); the
/// response carries `X-Static-Large-Object: true`. On a plain GET/HEAD (no
/// `multipart-manifest=get`) this fetches each referenced segment with a
/// **subrequest** and streams the concatenation, setting `Content-Length` to
/// the summed segment lengths and `Etag` to the SLO etag.
///
/// Deferred vs. `slo.py`: nested `sub_slo` GET recursion, inline `data`
/// segments, the SLO-etag refetch dance, and per-segment range subrequests
/// (a single top-level `Range` is honoured by slicing the concatenation).
#[derive(Debug, Default, Clone)]
pub struct Slo;

impl Slo {
    pub fn new() -> Self {
        Slo
    }
}

/// One entry parsed from a stored SLO manifest.
#[derive(Debug, Clone)]
struct StoredSeg {
    name: String,
    bytes: i64,
    hash: String,
    range: Option<String>,
    sub_slo: bool,
}

fn parse_stored_manifest(json: &[u8]) -> Option<Vec<StoredSeg>> {
    let value: serde_json::Value = serde_json::from_slice(json).ok()?;
    let arr = value.as_array()?;
    let mut out = Vec::with_capacity(arr.len());
    for it in arr {
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

        // A stored manifest is bounded (max_manifest_size at PUT time); an
        // unexpectedly huge body cannot be a manifest, so relay it as-is.
        if resp.body.materialize(MAX_CONTROL_BODY).is_err() {
            return resp;
        }
        // Second materialize is a no-op on the now-buffered body.
        let manifest_bytes = resp.body.materialize(MAX_CONTROL_BODY).expect("buffered");
        let Some(segments) = parse_stored_manifest(manifest_bytes) else {
            // Malformed manifest; hand back what we got.
            return resp;
        };

        // version, account from the manifest object's path.
        let parts = match split_path(&orig.path, 2, 3, true) {
            Ok(p) => p,
            Err(_) => return Response::error(400, "Invalid path"),
        };
        let version = parts[0].clone().unwrap_or_default();
        let account = parts[1].clone().unwrap_or_default();

        // Aggregate size and SLO etag.
        let slo_segs: Vec<SloSegment> = segments
            .iter()
            .map(|s| SloSegment {
                hash: s.hash.clone(),
                segment_length: s.bytes,
                range: s.range.clone(),
                raw_data: None,
            })
            .collect();
        let (etag, total_len) = slo_etag_and_size(&slo_segs);

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
        headers.set("Etag", etag);
        headers.set("Accept-Ranges", "bytes");

        let is_get = orig.method == "GET";

        // Nested SLOs are not reassembled here (deferred); the manifest is
        // known up front, so reject before any segment is fetched.
        if is_get && segments.iter().any(|s| s.sub_slo) {
            return Response::error(409, "Conflict");
        }

        let (status, body, content_len) = if let Some((first, last_excl)) = byte_range {
            // P1-leftover: still buffered — a ranged SLO GET assembles the
            // whole concatenation and slices it (per-segment ranged
            // subrequests are a later pass).
            let full = if is_get {
                match self.fetch_segments(&orig, &version, &account, &segments, next) {
                    Ok(b) => b,
                    Err(resp) => return resp,
                }
            } else {
                Vec::new()
            };
            let slice = if is_get {
                let f = first as usize;
                let l = (last_excl as usize).min(full.len().max(f));
                full.get(f..l).unwrap_or(&[]).to_vec()
            } else {
                Vec::new()
            };
            headers.set(
                "Content-Range",
                format!("bytes {}-{}/{}", first, last_excl - 1, total_len.max(0)),
            );
            (206u16, Body::from(slice), (last_excl - first) as i64)
        } else if is_get {
            // Lazy segment streaming: each subrequest is issued only when the
            // client stream reaches that segment; a mid-stream failure aborts
            // the connection (Python parity — the status is already sent).
            let body = Self::segment_stream_body(
                orig.clone_head(),
                version.clone(),
                account.clone(),
                segments,
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

    /// The lazy SLO reassembly body: a [`FnReader`] that pulls one segment
    /// subrequest at a time through a cloned `NextFn`. Segment failures
    /// surface as `io::Error` (the transport aborts the response).
    fn segment_stream_body(
        orig: Request,
        version: String,
        account: String,
        segments: Vec<StoredSeg>,
        next: NextFn,
        total_len: u64,
    ) -> Body {
        let mut queue = segments.into_iter();
        let reader = FnReader::new(move || {
            let seg = queue.next()?;
            // seg.name is "/container/object"; prefix with /version/account.
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
    /// `{path, etag, size_bytes, range?}`), HEAD each segment to confirm it
    /// exists and matches, then store the normalized internal manifest with
    /// `X-Static-Large-Object: true` so a later GET can reassemble it. A HEAD
    /// that identifies a segment as an SLO is validated against its aggregate
    /// SLO sysmeta, never the physical manifest JSON object's metadata.
    /// (Deferred vs. slo.py: inline `data` segments.)
    fn handle_put(&self, mut req: Request, next: &NextFn) -> Response {
        let manifest_bytes = match req.body.materialize(MAX_MANIFEST_SIZE) {
            Ok(b) => b,
            Err(e) if body_too_large(&e) => {
                return Response::error(413, "Request Entity Too Large")
            }
            Err(_) => return Response::error(499, "Client Disconnect"),
        };
        let Ok(client) = serde_json::from_slice::<serde_json::Value>(manifest_bytes) else {
            return Response::error(400, "Manifest must be valid json.");
        };
        let Some(entries) = client.as_array() else {
            return Response::error(400, "Manifest must be a list.");
        };
        let parts = match split_path(&req.path, 4, 4, true) {
            Ok(p) => p,
            Err(_) => return Response::error(400, "Invalid path"),
        };
        let version = parts[0].clone().unwrap_or_default();
        let account = parts[1].clone().unwrap_or_default();

        let mut internal: Vec<serde_json::Value> = Vec::new();
        let mut slo_segs: Vec<SloSegment> = Vec::new();
        let mut errors: Vec<String> = Vec::new();
        for (i, e) in entries.iter().enumerate() {
            let Some(e) = e.as_object() else {
                errors.push(format!("Index {i}: not a JSON object"));
                continue;
            };
            let Some(path) = e.get("path").and_then(|v| v.as_str()) else {
                errors.push(format!("Index {i}: no path in segment"));
                continue;
            };
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
                Some(serde_json::Value::String(etag)) => {
                    Some(normalize_etag(etag).to_string())
                }
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
            let mut head = req.clone_head();
            head.method = "HEAD".to_string();
            head.path = seg_path.clone();
            head.query_string = String::new();
            head.headers.remove("Content-Length");
            let hr = next(head);
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
        if !errors.is_empty() {
            return Response::error(400, &format!("Errors: {}", errors.join(", ")));
        }

        let (slo_etag, total) = slo_etag_and_size(&slo_segs);
        let body = serde_json::to_vec(&internal).unwrap_or_default();
        req.method = "PUT".to_string();
        req.query_string = String::new();
        req.headers.set(SLO_HEADER, "True");
        req.headers.set("Content-Length", body.len().to_string());
        req.headers.set(SYSMETA_SLO_ETAG, slo_etag.trim_matches('"'));
        req.headers.set(SYSMETA_SLO_SIZE, total.to_string());
        if req.headers.get("Content-Type").is_none() {
            req.headers.set("Content-Type", "application/json");
        }
        req.body = body.into();
        next(req)
    }

    fn fetch_segments(
        &self,
        orig: &Request,
        version: &str,
        account: &str,
        segments: &[StoredSeg],
        next: &NextFn,
    ) -> Result<Vec<u8>, Response> {
        let mut body = Vec::new();
        for seg in segments {
            if seg.sub_slo {
                // Nested SLOs are not reassembled here (deferred).
                return Err(Response::error(409, "Conflict"));
            }
            // seg.name is "/container/object"; prefix with /version/account.
            let path = format!("/{version}/{account}{}", seg.name);
            let sub = slo_subreq(orig, path, seg.range.as_deref());
            let sresp = next(sub);
            if !(200..300).contains(&sresp.status) {
                return Err(Response::error(409, "Conflict"));
            }
            // P1-leftover: still buffered (ranged-GET assembly only).
            match sresp
                .body
                .into_vec(swift_core::constraints::MAX_FILE_SIZE as u64)
            {
                Ok(b) => body.extend_from_slice(&b),
                Err(_) => return Err(Response::error(409, "Conflict")),
            }
        }
        Ok(body)
    }
}

impl Middleware for Slo {
    fn handle(&self, req: Request, next: &NextFn) -> Response {
        if split_path(&req.path, 4, 4, true).is_err() {
            return next(req);
        }
        let mpm = req.param("multipart-manifest");
        // PUT ?multipart-manifest=put creates an SLO from a client manifest.
        if req.method == "PUT" && mpm.as_deref() == Some("put") {
            return self.handle_put(req, next);
        }
        // GET/HEAD reassembles, unless ?multipart-manifest=get asks for the raw
        // manifest.
        let is_get_head = req.method == "GET" || req.method == "HEAD";
        if is_get_head && mpm.as_deref() != Some("get") {
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
        let (etag, size) = dlo_etag_and_size(&[
            ("\"h1\"".to_string(), 10),
            ("h2".to_string(), 20),
        ]);
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
                    let mut out = Response::new(*status);
                    out.headers = headers.clone();
                    out.body = body.clone().into();
                    return out;
                }
            }
            Response::new(404)
        })
    }

    fn slo_manifest_backend() -> NextFn {
        let manifest_json = serde_json::to_vec(&serde_json::json!([
            {"name": "/c/s1", "bytes": 3, "hash": md5_hex(b"one")},
            {"name": "/c/s2", "bytes": 3, "hash": md5_hex(b"two")},
        ]))
        .unwrap();
        let mut manifest = Response::with_body(200, manifest_json);
        manifest.headers.set("X-Static-Large-Object", "True");
        manifest.headers.set("Content-Type", "text/plain");
        backend(vec![
            ("GET", "/v1/a/c/manifest", manifest),
            ("GET", "/v1/a/c/s1", Response::with_body(200, b"one".to_vec())),
            ("GET", "/v1/a/c/s2", Response::with_body(200, b"two".to_vec())),
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
    }

    #[test]
    fn test_slo_range_get() {
        // "onetwo"[2..5] = "etw"
        let be = slo_manifest_backend();
        let mut resp = Slo::new().handle(slo_get("/v1/a/c/manifest", Some("bytes=2-4")), &be);
        assert_eq!(resp.status, 206);
        assert_eq!(body_of(&mut resp), b"etw");
        assert_eq!(resp.headers.get("Content-Range"), Some("bytes 2-4/6"));
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
            ("GET", "/v1/a/c/s1", Response::with_body(200, b"one".to_vec())),
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
}
