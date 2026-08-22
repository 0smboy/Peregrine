// Copyright (c) 2013 OpenStack Foundation
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

//! `dlo`: Dynamic Large Object support, a port of the GET/HEAD reassembly and
//! PUT validation in `swift/common/middleware/dlo.py`.
//!
//! A DLO manifest is an object carrying an `X-Object-Manifest:
//! <container>/<prefix>` header. On GET/HEAD of that object the middleware:
//!
//! 1. issues container-listing **subrequests**
//!    (`GET /<v>/<a>/<container>?prefix=<prefix>[&marker=<name>]`) to
//!    enumerate all segments (sorted lexicographically by the container DB),
//! 2. computes the aggregate `Content-Length` (sum of segment `bytes`) and, for
//!    a complete listing, the DLO `Etag` (`md5` of the concatenated,
//!    quote-normalized segment hashes, wrapped in quotes),
//! 3. for a GET, fetches each segment with its own subrequest and streams the
//!    concatenation as the body — honouring a single `Range` header with
//!    per-segment ranged subrequests.
//!
//! A HEAD returns the aggregate metadata with no body. `multipart-manifest=get`
//! bypasses reassembly (returns the raw manifest object).
//!
//! As in Python Swift, only the first listing page is used to compute response
//! metadata. Later marker pages are fetched lazily while the response body is
//! consumed, so a DLO with more than `CONTAINER_LISTING_LIMIT` segments is not
//! truncated and does not require materializing the complete listing.

use std::collections::VecDeque;
use std::future::Future;
use std::io::{Cursor, Read};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use md5::{Digest, Md5};
use swift_http::{
    apply_conditional, split_path, unquote, Body, ChainReader, FnReader, HeaderKeyDict, Range,
    Request, Response, MAX_CONTROL_BODY, STREAM_CHUNK,
};

use crate::slo::{dlo_etag_and_size, normalize_etag};
use crate::{AsyncNextFn, Middleware, MwPrep, NextFn};

/// `swift.common.constraints.CONTAINER_LISTING_LIMIT`.
const CONTAINER_LISTING_LIMIT: usize = 10000;
const X_OBJECT_MANIFEST: &str = "X-Object-Manifest";
const IGNORE_RANGE_HDR: &str = "X-Backend-Ignore-Range-If-Metadata-Present";

/// Dynamic Large Object middleware.
#[derive(Debug, Clone)]
pub struct DynamicLargeObject {
    max_get_time: i64,
    rate_limit_after_segment: i64,
    rate_limit_segments_per_sec: i64,
    listing_limit: usize,
}

impl Default for DynamicLargeObject {
    fn default() -> Self {
        Self {
            // Python swift.common.middleware.dlo defaults.
            max_get_time: 86_400,
            rate_limit_after_segment: 10,
            rate_limit_segments_per_sec: 1,
            listing_limit: CONTAINER_LISTING_LIMIT,
        }
    }
}

impl DynamicLargeObject {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set Python's `max_get_time` (seconds). A negative value, like Python's
    /// `int` configuration, makes the stream expire after its first chunk.
    pub fn with_max_get_time(mut self, seconds: i64) -> Self {
        self.max_get_time = seconds;
        self
    }

    /// Set the number of yielded segments before rate limiting starts.
    pub fn with_rate_limit_after_segment(mut self, count: i64) -> Self {
        self.rate_limit_after_segment = count;
        self
    }

    /// Set the maximum yielded segments per second (`<= 0` disables it).
    pub fn with_rate_limit_segments_per_sec(mut self, rate: i64) -> Self {
        self.rate_limit_segments_per_sec = rate;
        self
    }

    #[cfg(test)]
    fn with_listing_limit(mut self, limit: usize) -> Self {
        assert!(limit > 0);
        self.listing_limit = limit;
        self
    }
}

/// One enumerated segment from the container listing.
#[derive(Debug, Clone)]
struct Segment {
    name: String,
    bytes: u64,
    hash: String,
}

#[derive(Debug)]
enum DloStreamFailure {
    SegmentStatus(u16, String),
    ListingStatus(u16, String),
    InvalidListing(String),
    InvalidLength(String),
    TimedOut,
}

impl std::fmt::Display for DloStreamFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SegmentStatus(status, path) => {
                write!(f, "DLO segment {path} returned {status}")
            }
            Self::ListingStatus(status, path) => {
                write!(f, "DLO listing {path} returned {status}")
            }
            Self::InvalidListing(message) | Self::InvalidLength(message) => f.write_str(message),
            Self::TimedOut => f.write_str("DLO maximum GET time exceeded"),
        }
    }
}

impl std::error::Error for DloStreamFailure {}

fn stream_failure(failure: DloStreamFailure) -> std::io::Error {
    std::io::Error::other(failure)
}

/// `urllib.parse.quote` with the default safe set, for query-string values.
fn quote(s: &str) -> String {
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

/// `request_helpers.update_ignore_range_header`: signal the backend to serve
/// the whole object (ignore `Range`) when `name` metadata is present, so the
/// manifest object itself is returned with its `X-Object-Manifest` header
/// intact even when the client sent a `Range`.
fn update_ignore_range_header(headers: &mut HeaderKeyDict, name: &str) {
    let val = match headers.get(IGNORE_RANGE_HDR) {
        Some(s) if !s.is_empty() => format!("{s},{name}"),
        _ => name.to_string(),
    };
    headers.set(IGNORE_RANGE_HDR, val);
}

/// Build a backend subrequest that preserves the original request's auth
/// context (headers/env) while overriding the method/path/query and dropping
/// the body plus any range/length/conditional headers.
fn make_subreq(orig: &Request, method: &str, path: String, query_string: String) -> Request {
    let mut sub = orig.clone_head();
    sub.method = method.to_string();
    sub.set_path(path);
    sub.query_string = query_string;
    sub.headers.remove("Range");
    sub.headers.remove("Content-Length");
    sub.headers.remove("If-Match");
    sub.headers.remove("If-None-Match");
    sub.headers.remove("If-Modified-Since");
    sub.headers.remove("If-Unmodified-Since");
    sub.headers.remove(IGNORE_RANGE_HDR);
    sub
}

fn parse_segments(json: &[u8], listing_limit: usize) -> Result<Vec<Segment>, String> {
    let value: serde_json::Value =
        serde_json::from_slice(json).map_err(|err| format!("Invalid DLO listing JSON: {err}"))?;
    let rows = value
        .as_array()
        .ok_or_else(|| "Invalid DLO listing: expected a JSON array".to_string())?;
    if rows.len() > listing_limit {
        return Err(format!(
            "Invalid DLO listing: {} rows exceeds limit {listing_limit}",
            rows.len()
        ));
    }

    let mut out = Vec::with_capacity(rows.len());
    let mut previous_name: Option<&str> = None;
    for (index, row) in rows.iter().enumerate() {
        let object = row
            .as_object()
            .ok_or_else(|| format!("Invalid DLO listing row {index}: expected an object"))?;
        let name = object
            .get("name")
            .and_then(|value| value.as_str())
            .filter(|name| !name.is_empty())
            .ok_or_else(|| format!("Invalid DLO listing row {index}: missing string name"))?;
        if previous_name.is_some_and(|previous| name <= previous) {
            return Err(format!(
                "Invalid DLO listing row {index}: names are not strictly increasing"
            ));
        }
        let bytes = object
            .get("bytes")
            .and_then(|value| value.as_i64())
            .filter(|bytes| *bytes >= 0)
            .map(|bytes| bytes as u64)
            .ok_or_else(|| {
                format!("Invalid DLO listing row {index}: bytes must be a non-negative integer")
            })?;
        let hash = object
            .get("hash")
            .and_then(|value| value.as_str())
            .ok_or_else(|| format!("Invalid DLO listing row {index}: missing string hash"))?;

        out.push(Segment {
            name: name.to_string(),
            bytes,
            hash: hash.to_string(),
        });
        previous_name = Some(name);
    }
    Ok(out)
}

fn listing_query(prefix: &str, marker: Option<&str>) -> String {
    let mut query = format!("prefix={}", quote(prefix));
    if let Some(marker) = marker {
        query.push_str("&marker=");
        query.push_str(&quote(marker));
    }
    // Rust's proxy does not have Python's implicit container-controller
    // rewrite to JSON on every internal request, so retain an explicit format.
    query.push_str("&format=json");
    query
}

/// `swift_http::Range` stores bounds as `u64`; avoid overflowing its generic
/// inclusive-end `+ 1` path for the largest representable explicit end. DLO
/// only supports one range, so this exact edge can be resolved locally.
fn single_range_for_length(range: &Range, length: u64) -> Option<Vec<(u64, u64)>> {
    match range.ranges.as_slice() {
        [(Some(start), Some(u64::MAX))] => Some(if *start < length {
            vec![(*start, length)]
        } else {
            Vec::new()
        }),
        _ => range.ranges_for_length(Some(length)),
    }
}

fn listing_subrequest(
    orig: &Request,
    version: &str,
    account: &str,
    container: &str,
    prefix: &str,
    marker: Option<&str>,
) -> Request {
    make_subreq(
        orig,
        "GET",
        format!("/{version}/{account}/{container}"),
        listing_query(prefix, marker),
    )
}

#[derive(Debug)]
struct SegmentFetch {
    segment: Segment,
    /// Segment-relative, exclusive-end range. `None` means the whole segment.
    byte_range: Option<(u64, u64)>,
}

/// Lazy equivalent of Python's `_segment_listing_iterator`: consume the
/// already-fetched first page, then marker-page only when its last segment has
/// drained. Absolute offsets avoid signed underflow while preserving Python's
/// first/last-byte intersection rules.
struct SegmentListingCursor {
    orig: Request,
    version: String,
    account: String,
    container: String,
    prefix: String,
    segments: VecDeque<Segment>,
    page_complete: bool,
    marker: Option<String>,
    absolute_offset: u64,
    wanted_range: Option<(u64, u64)>,
    finished: bool,
    next: NextFn,
    listing_limit: usize,
    rate_limit_after_segment: i64,
    rate_limit_segments_per_sec: i64,
    next_allowed: Option<Instant>,
}

impl SegmentListingCursor {
    #[allow(clippy::too_many_arguments)]
    fn new(
        orig: Request,
        version: String,
        account: String,
        container: String,
        prefix: String,
        first_page: Vec<Segment>,
        wanted_range: Option<(u64, u64)>,
        next: NextFn,
        listing_limit: usize,
        rate_limit_after_segment: i64,
        rate_limit_segments_per_sec: i64,
    ) -> Self {
        let page_complete = first_page.len() < listing_limit;
        let marker = first_page.last().map(|segment| segment.name.clone());
        Self {
            orig,
            version,
            account,
            container,
            prefix,
            segments: first_page.into(),
            page_complete,
            marker,
            absolute_offset: 0,
            wanted_range,
            finished: false,
            next,
            listing_limit,
            rate_limit_after_segment,
            rate_limit_segments_per_sec,
            next_allowed: None,
        }
    }

    fn load_next_page(&mut self) -> Result<(), DloStreamFailure> {
        let marker = self.marker.clone().ok_or_else(|| {
            DloStreamFailure::InvalidListing(
                "Invalid DLO listing: full page has no marker".to_string(),
            )
        })?;
        let request = listing_subrequest(
            &self.orig,
            &self.version,
            &self.account,
            &self.container,
            &self.prefix,
            Some(&marker),
        );
        let path = format!("{}?{}", request.path, request.query_string);
        let mut response = (self.next)(request);
        if !(200..300).contains(&response.status) {
            return Err(DloStreamFailure::ListingStatus(response.status, path));
        }
        let bytes = response.body.materialize(MAX_CONTROL_BODY).map_err(|err| {
            DloStreamFailure::InvalidListing(format!("Invalid DLO listing body from {path}: {err}"))
        })?;
        let page =
            parse_segments(bytes, self.listing_limit).map_err(DloStreamFailure::InvalidListing)?;
        if page
            .first()
            .is_some_and(|segment| segment.name.as_str() <= marker.as_str())
        {
            return Err(DloStreamFailure::InvalidListing(format!(
                "Invalid DLO listing: marker did not advance past {marker:?}"
            )));
        }

        self.page_complete = page.len() < self.listing_limit;
        if let Some(last) = page.last() {
            self.marker = Some(last.name.clone());
        }
        self.segments = page.into();
        Ok(())
    }

    fn next_fetch(&mut self) -> Result<Option<SegmentFetch>, DloStreamFailure> {
        loop {
            if self.finished {
                return Ok(None);
            }
            if self
                .wanted_range
                .is_some_and(|(_, wanted_end)| self.absolute_offset >= wanted_end)
            {
                self.finished = true;
                return Ok(None);
            }
            let segment = match self.segments.pop_front() {
                Some(segment) => segment,
                None if self.page_complete => return Ok(None),
                None => {
                    self.load_next_page()?;
                    continue;
                }
            };

            let segment_start = self.absolute_offset;
            let segment_end = segment_start.checked_add(segment.bytes).ok_or_else(|| {
                DloStreamFailure::InvalidLength(
                    "DLO aggregate length exceeds the supported range".to_string(),
                )
            })?;
            self.absolute_offset = segment_end;

            let byte_range = if let Some((wanted_start, wanted_end)) = self.wanted_range {
                if segment_end <= wanted_start {
                    continue;
                }
                if segment_start >= wanted_end {
                    self.finished = true;
                    return Ok(None);
                }
                let first = wanted_start.saturating_sub(segment_start);
                let last_exclusive = wanted_end.min(segment_end) - segment_start;
                if first >= last_exclusive {
                    continue;
                }
                if first == 0 && last_exclusive == segment.bytes {
                    None
                } else {
                    Some((first, last_exclusive))
                }
            } else {
                None
            };

            return Ok(Some(SegmentFetch {
                segment,
                byte_range,
            }));
        }
    }

    fn rate_limit(&mut self) {
        if self.rate_limit_after_segment > 0 {
            self.rate_limit_after_segment -= 1;
            return;
        }
        if self.rate_limit_segments_per_sec <= 0 {
            return;
        }

        let now = Instant::now();
        if let Some(allowed) = self.next_allowed {
            if allowed > now {
                std::thread::sleep(allowed.duration_since(now));
            }
        }
        let base = self.next_allowed.unwrap_or(now).max(Instant::now());
        let interval = Duration::from_secs_f64(1.0 / self.rate_limit_segments_per_sec as f64);
        self.next_allowed = base.checked_add(interval);
    }

    fn next_reader(&mut self) -> Option<std::io::Result<Box<dyn Read + Send>>> {
        let fetch = match self.next_fetch() {
            Ok(Some(fetch)) => fetch,
            Ok(None) => return None,
            Err(failure) => return Some(Err(stream_failure(failure))),
        };
        self.rate_limit();

        let path = format!(
            "/{}/{}/{}/{}",
            self.version, self.account, self.container, fetch.segment.name
        );
        let mut request = make_subreq(
            &self.orig,
            "GET",
            path.clone(),
            "multipart-manifest=get".to_string(),
        );
        if let Some((first, last_exclusive)) = fetch.byte_range {
            let value = if last_exclusive == fetch.segment.bytes {
                format!("bytes={first}-")
            } else {
                format!("bytes={first}-{}", last_exclusive - 1)
            };
            request.headers.set("Range", value);
        }
        let response = (self.next)(request);
        if !(200..300).contains(&response.status) {
            return Some(Err(stream_failure(DloStreamFailure::SegmentStatus(
                response.status,
                path,
            ))));
        }
        let status = response.status;
        let response_etag = response.headers.get("Etag").map(str::to_string);
        // Proxy object GETs stream with length on Body and often omit the
        // Content-Length header (write_response re-derives it for wire clients).
        // Prefer the header when present, else the streamed body's declared length.
        let response_length = response
            .headers
            .get("Content-Length")
            .and_then(|value| value.parse::<u64>().ok())
            .or_else(|| response.body.content_length());
        let (reader, _length) = response.body.into_reader();
        let reader: Box<dyn Read + Send> = match fetch.byte_range {
            Some((first, last_exclusive)) => Box::new(SegmentSliceReader {
                inner: reader,
                // A compliant backend's 206 body already starts at `first`;
                // a 200 means it ignored Range, so apply the offset locally.
                skip: if status == 206 { 0 } else { first },
                remaining: last_exclusive - first,
            }),
            None => match response_etag {
                Some(etag) => Box::new(ValidatingSegmentReader {
                    inner: reader,
                    hasher: Md5::new(),
                    actual_length: 0,
                    expected_length: response_length,
                    expected_etag: normalize_etag(&etag).to_string(),
                    finished: false,
                }),
                None => reader,
            },
        };
        Some(Ok(reader))
    }
}

/// Python `SegmentedIterable` verifies each non-ranged segment against that
/// segment response's own Content-Length and Etag (not against the stale
/// container-listing metadata). Keep the verification streaming and surface a
/// mismatch only after the bytes already read, so later-segment failures close
/// an already-started client response just like WSGI Swift.
struct ValidatingSegmentReader {
    inner: Box<dyn Read + Send>,
    hasher: Md5,
    actual_length: u64,
    expected_length: Option<u64>,
    expected_etag: String,
    finished: bool,
}

impl Read for ValidatingSegmentReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if self.finished || buffer.is_empty() {
            return Ok(0);
        }
        let read = self.inner.read(buffer)?;
        if read > 0 {
            self.actual_length = self.actual_length.checked_add(read as u64).ok_or_else(|| {
                stream_failure(DloStreamFailure::InvalidLength(
                    "DLO segment response length overflow".to_string(),
                ))
            })?;
            self.hasher.update(&buffer[..read]);
            return Ok(read);
        }
        self.finished = true;

        if let Some(expected) = self.expected_length {
            if expected != self.actual_length {
                return Err(stream_failure(DloStreamFailure::InvalidLength(format!(
                    "DLO segment response length was {}, expected {expected}",
                    self.actual_length
                ))));
            }
        }
        let digest = self.hasher.clone().finalize();
        let actual_etag = digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        if actual_etag != self.expected_etag {
            return Err(stream_failure(DloStreamFailure::InvalidLength(format!(
                "DLO segment MD5 was {actual_etag}, expected {}",
                self.expected_etag
            ))));
        }
        Ok(0)
    }
}

/// Bounded fallback for an internal segment server that ignores `Range` and
/// returns 200. It also prevents an overlong 206 from escaping its requested
/// segment window.
struct SegmentSliceReader {
    inner: Box<dyn Read + Send>,
    skip: u64,
    remaining: u64,
}

impl Read for SegmentSliceReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let mut discard = [0u8; STREAM_CHUNK];
        while self.skip > 0 {
            let amount = self.skip.min(discard.len() as u64) as usize;
            let read = self.inner.read(&mut discard[..amount])?;
            if read == 0 {
                return Err(stream_failure(DloStreamFailure::InvalidLength(
                    "DLO ranged segment ended before its requested offset".to_string(),
                )));
            }
            self.skip -= read as u64;
        }
        if self.remaining == 0 || buffer.is_empty() {
            return Ok(0);
        }
        let amount = self.remaining.min(buffer.len() as u64) as usize;
        let read = self.inner.read(&mut buffer[..amount])?;
        if read == 0 {
            return Err(stream_failure(DloStreamFailure::InvalidLength(
                "DLO ranged segment ended before its requested end".to_string(),
            )));
        }
        self.remaining -= read as u64;
        Ok(read)
    }
}

/// Enforce Python `SegmentedIterable`'s response byte budget and maximum GET
/// duration without buffering object data. An overrun is truncated to the
/// promised length and then aborts the stream; an underrun also aborts.
struct GuardedDloReader {
    inner: Box<dyn Read + Send>,
    remaining: Option<u64>,
    started: Instant,
    max_get_time: i64,
    pending_failure: Option<DloStreamFailure>,
}

impl GuardedDloReader {
    fn new(inner: Box<dyn Read + Send>, length: Option<u64>, max_get_time: i64) -> Self {
        Self {
            inner,
            remaining: length,
            started: Instant::now(),
            max_get_time,
            pending_failure: None,
        }
    }
}

impl Read for GuardedDloReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if let Some(failure) = self.pending_failure.take() {
            return Err(stream_failure(failure));
        }
        if buffer.is_empty() {
            return Ok(0);
        }

        if self.remaining == Some(0) {
            let mut probe = [0u8; 1];
            return match self.inner.read(&mut probe)? {
                0 => Ok(0),
                _ => Err(stream_failure(DloStreamFailure::InvalidLength(
                    "DLO segment data exceeds the promised response length".to_string(),
                ))),
            };
        }

        let read_limit = self
            .remaining
            .map(|remaining| remaining.min(buffer.len() as u64) as usize)
            .unwrap_or(buffer.len());
        let read = self.inner.read(&mut buffer[..read_limit])?;
        if read == 0 {
            if self.remaining.is_some_and(|remaining| remaining > 0) {
                return Err(stream_failure(DloStreamFailure::InvalidLength(
                    "DLO segment data ended before the promised response length".to_string(),
                )));
            }
            return Ok(0);
        }
        if let Some(remaining) = self.remaining.as_mut() {
            *remaining -= read as u64;
        }

        if self.started.elapsed().as_secs_f64() > self.max_get_time as f64 {
            // Python yields the chunk that crossed the deadline, then raises
            // when the iterator is resumed.
            self.pending_failure = Some(DloStreamFailure::TimedOut);
        }
        Ok(read)
    }
}

fn response_for_first_stream_error(error: &std::io::Error) -> Response {
    if let Some(DloStreamFailure::SegmentStatus(status, _)) = error
        .get_ref()
        .and_then(|source| source.downcast_ref::<DloStreamFailure>())
    {
        if (500..600).contains(status) {
            return Response::error(503, "Service Unavailable");
        }
    }
    Response::error(409, "Conflict")
}

impl DynamicLargeObject {
    /// GET or HEAD: detect a manifest object and, if present, reassemble it.
    fn handle_get_head(&self, mut req: Request, next: &NextFn) -> Response {
        update_ignore_range_header(&mut req.headers, X_OBJECT_MANIFEST);
        let orig_req = req.clone_head();
        let resp = next(req);

        match resp.headers.get(X_OBJECT_MANIFEST).map(str::to_string) {
            Some(x_object_manifest) => {
                self.get_or_head_response(&orig_req, &resp, &x_object_manifest, next)
            }
            // Not a DLO manifest; pass the response through unchanged.
            None => resp,
        }
    }

    /// Fetch the container listing for the manifest's `<container>/<prefix>`.
    /// On a non-2xx listing, returns the error response to relay.
    fn get_container_listing(
        &self,
        orig: &Request,
        version: &str,
        account: &str,
        container: &str,
        prefix: &str,
        next: &NextFn,
    ) -> Result<Vec<Segment>, Response> {
        let con_req = listing_subrequest(orig, version, account, container, prefix, None);
        let mut con_resp = next(con_req);
        if !(200..300).contains(&con_resp.status) {
            let mut err = con_resp;
            if orig.method == "HEAD" {
                err.body = Body::empty();
            }
            return Err(err);
        }
        let parsed = con_resp
            .body
            .materialize(MAX_CONTROL_BODY)
            .map_err(|err| format!("Invalid DLO listing body: {err}"))
            .and_then(|bytes| parse_segments(bytes, self.listing_limit));
        parsed.map_err(|message| {
            let mut response = Response::error(409, &message);
            if orig.method == "HEAD" {
                response.body = Body::empty();
            }
            response
        })
    }

    fn get_or_head_response(
        &self,
        req: &Request,
        manifest_resp: &Response,
        x_object_manifest: &str,
        next: &NextFn,
    ) -> Response {
        // Match Python Swift's wsgi_unquote before splitting. The listing
        // subrequest quotes the decoded prefix exactly once below.
        let decoded_manifest = unquote(x_object_manifest);
        let (container, obj_prefix) = decoded_manifest
            .split_once('/')
            .unwrap_or((decoded_manifest.as_str(), ""));

        // version, account from the manifest object's path.
        let parts = match split_path(&req.path, 2, 3, true) {
            Ok(p) => p,
            Err(_) => return Response::error(400, "Invalid path"),
        };
        let version = parts[0].clone().unwrap_or_default();
        let account = parts[1].clone().unwrap_or_default();

        let segments = match self
            .get_container_listing(req, &version, &account, container, obj_prefix, next)
        {
            Ok(s) => s,
            Err(resp) => return resp,
        };
        let have_complete_listing = segments.len() < self.listing_limit;

        // Aggregate size and (for a complete listing) the DLO Etag.
        let mut checked_total = 0i64;
        let mut pairs = Vec::with_capacity(segments.len());
        for segment in &segments {
            let bytes = i64::try_from(segment.bytes)
                .map_err(|_| ())
                .and_then(|bytes| {
                    checked_total = checked_total.checked_add(bytes).ok_or(())?;
                    Ok(bytes)
                });
            let Ok(bytes) = bytes else {
                let mut response = Response::error(
                    409,
                    "DLO aggregate length exceeds the supported response range",
                );
                if req.method == "HEAD" {
                    response.body = Body::empty();
                }
                return response;
            };
            pairs.push((segment.hash.clone(), bytes));
        }
        let (dlo_etag, total_len) = dlo_etag_and_size(&pairs);
        debug_assert_eq!(total_len, checked_total);
        let total_u = total_len as u64;

        // Resolve a single Range header against the aggregate length.
        // (first_byte, last_byte_exclusive)
        let mut byte_range: Option<(u64, u64)> = None;
        let mut unsatisfiable = false;
        let range = req
            .headers
            .get("Range")
            .and_then(|h| Range::parse(h).ok())
            .filter(|r| r.ranges.len() == 1);
        if let Some(range) = range {
            // Python also honors an explicit-end range on an incomplete first
            // page when its exclusive end is strictly below the bytes visible
            // in that page. Open-ended and suffix ranges remain unknowable.
            let known_from_first_page = match range.ranges[0] {
                (Some(_), Some(end)) => end
                    .checked_add(1)
                    .is_some_and(|exclusive_end| exclusive_end < total_u),
                _ => false,
            };
            if have_complete_listing || known_from_first_page {
                match single_range_for_length(&range, total_u) {
                    Some(ranges) if ranges.is_empty() || ranges[0].0 >= ranges[0].1 => {
                        unsatisfiable = true
                    }
                    Some(ranges) => byte_range = Some(ranges[0]),
                    None => {}
                }
            }
        }

        if unsatisfiable {
            let mut resp = Response::error(416, "Requested Range Not Satisfiable");
            resp.headers.set("Accept-Ranges", "bytes");
            if have_complete_listing {
                resp.headers
                    .set("Content-Range", format!("bytes */{total_u}"));
            }
            return resp;
        }

        // Assemble the response headers from the manifest object's headers,
        // dropping the ones we recompute.
        let mut headers = manifest_resp.headers.clone();
        headers.remove("Content-Length");
        headers.remove("Content-Range");
        headers.remove("Transfer-Encoding");
        if have_complete_listing {
            headers.remove("Etag");
            headers.set("Etag", &dlo_etag);
        }
        headers.set("Accept-Ranges", "bytes");

        let status = if byte_range.is_some() { 206 } else { 200 };
        let response_length = byte_range
            .map(|(first, last_exclusive)| last_exclusive - first)
            .or_else(|| have_complete_listing.then_some(total_u));
        if let Some((first, last_exclusive)) = byte_range {
            headers.set(
                "Content-Range",
                format!("bytes {}-{}/{total_u}", first, last_exclusive - 1),
            );
        }

        let body = if req.method == "GET" {
            match self.segment_stream_body(
                req.clone_head(),
                version.clone(),
                account.clone(),
                container.to_string(),
                obj_prefix.to_string(),
                segments,
                Arc::clone(next),
                byte_range,
                response_length,
            ) {
                Ok(body) => body,
                Err(response) => return response,
            }
        } else {
            Body::empty()
        };

        if let Some(length) = response_length {
            headers.set("Content-Length", length.to_string());
        }

        let mut resp = Response::new(status);
        resp.headers = headers;
        resp.body = body;
        resp
    }

    /// Lazy, marker-paginated reassembly. The first readable body chunk is
    /// prefetched so a missing/invalid first segment becomes 409 (or 503 for
    /// a backend 5xx) before the client response is committed. At most one
    /// stream chunk is retained for this validation.
    #[allow(clippy::too_many_arguments)]
    fn segment_stream_body(
        &self,
        orig: Request,
        version: String,
        account: String,
        container: String,
        prefix: String,
        first_page: Vec<Segment>,
        next: NextFn,
        byte_range: Option<(u64, u64)>,
        content_length: Option<u64>,
    ) -> Result<Body, Response> {
        let mut cursor = SegmentListingCursor::new(
            orig,
            version,
            account,
            container,
            prefix,
            first_page,
            byte_range,
            next,
            self.listing_limit,
            self.rate_limit_after_segment,
            self.rate_limit_segments_per_sec,
        );
        let chained = FnReader::new(move || cursor.next_reader());
        let mut guarded: Box<dyn Read + Send> = Box::new(GuardedDloReader::new(
            Box::new(chained),
            content_length,
            self.max_get_time,
        ));

        let mut first_chunk = vec![0u8; STREAM_CHUNK];
        let first_len = guarded
            .read(&mut first_chunk)
            .map_err(|error| response_for_first_stream_error(&error))?;
        first_chunk.truncate(first_len);
        let body_reader: Box<dyn Read + Send> = if first_chunk.is_empty() {
            guarded
        } else {
            Box::new(ChainReader::new(vec![
                Box::new(Cursor::new(first_chunk)),
                guarded,
            ]))
        };
        Ok(Body::from_reader(body_reader, content_length))
    }

    async fn handle_get_head_async(&self, mut req: Request, next: AsyncNextFn) -> Response {
        if split_path(&req.path, 4, 4, true).is_err() {
            return next(req).await;
        }
        let is_get_head = req.method == "GET" || req.method == "HEAD";
        if req.param("multipart-manifest").as_deref() == Some("get") || !is_get_head {
            return next(req).await;
        }
        update_ignore_range_header(&mut req.headers, X_OBJECT_MANIFEST);
        let orig = req.clone_head();
        let resp = next(req).await;
        let Some(manifest) = resp.headers.get(X_OBJECT_MANIFEST).map(str::to_string) else {
            return resp;
        };
        let decoded = unquote(&manifest);
        let (container, obj_prefix) = decoded.split_once('/').unwrap_or((decoded.as_str(), ""));
        let parts = match split_path(&orig.path, 2, 3, true) {
            Ok(p) => p,
            Err(_) => return Response::error(400, "Invalid path"),
        };
        let version = parts[0].clone().unwrap_or_default();
        let account = parts[1].clone().unwrap_or_default();
        let list_req = listing_subrequest(&orig, &version, &account, container, obj_prefix, None);
        let mut list_resp = next(list_req).await;
        if !(200..300).contains(&list_resp.status) {
            if orig.method == "HEAD" {
                list_resp.body = Body::empty();
            }
            return list_resp;
        }
        let body = match list_resp.body.collect_async().await {
            Ok(b) => b,
            Err(_) => return Response::error(409, "Invalid DLO listing body"),
        };
        let segments = match parse_segments(&body, self.listing_limit) {
            Ok(s) => s,
            Err(message) => {
                let mut r = Response::error(409, &message);
                if orig.method == "HEAD" {
                    r.body = Body::empty();
                }
                return r;
            }
        };
        let pairs: Vec<(String, i64)> = segments
            .iter()
            .map(|s| (s.hash.clone(), s.bytes as i64))
            .collect();
        let (dlo_etag, total_len) = dlo_etag_and_size(&pairs);
        let total_u = total_len.max(0) as u64;
        let have_complete_listing = segments.len() < self.listing_limit;
        let mut byte_range: Option<(u64, u64)> = None;
        let mut unsatisfiable = false;
        let range = orig
            .headers
            .get("Range")
            .and_then(|h| Range::parse(h).ok())
            .filter(|r| r.ranges.len() == 1);
        if let Some(range) = range {
            let known_from_first_page = match range.ranges[0] {
                (Some(_), Some(end)) => end
                    .checked_add(1)
                    .is_some_and(|exclusive_end| exclusive_end < total_u),
                _ => false,
            };
            if have_complete_listing || known_from_first_page {
                match single_range_for_length(&range, total_u) {
                    Some(ranges) if ranges.is_empty() || ranges[0].0 >= ranges[0].1 => {
                        unsatisfiable = true
                    }
                    Some(ranges) => byte_range = Some(ranges[0]),
                    None => {}
                }
            }
        }
        if unsatisfiable {
            let mut resp = Response::error(416, "Requested Range Not Satisfiable");
            resp.headers.set("Accept-Ranges", "bytes");
            if have_complete_listing {
                resp.headers
                    .set("Content-Range", format!("bytes */{total_u}"));
            }
            return resp;
        }
        let mut headers = resp.headers.clone();
        headers.remove("Content-Length");
        headers.remove("Content-Range");
        headers.remove("Transfer-Encoding");
        headers.remove("Etag");
        headers.set("Etag", &dlo_etag);
        headers.set("Accept-Ranges", "bytes");
        let status = if byte_range.is_some() { 206 } else { 200 };
        let response_length = byte_range
            .map(|(first, last_exclusive)| last_exclusive - first)
            .unwrap_or(total_u);
        if let Some((first, last_exclusive)) = byte_range {
            headers.set(
                "Content-Range",
                format!("bytes {}-{}/{total_u}", first, last_exclusive - 1),
            );
        }
        headers.set("Content-Length", response_length.to_string());
        let mut out = Response::new(status);
        out.headers = headers;
        if orig.method != "GET" {
            out.body = Body::empty();
            return apply_conditional(&orig, out);
        }
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let scope = swift_runtime::TaskScope::bounded(1);
        let orig_head = orig.clone_head();
        let container = container.to_string();
        let _ = scope.spawn(async move {
            let (skip, take) = byte_range
                .map(|(s, e)| (s, e.saturating_sub(s)))
                .unwrap_or((0, u64::MAX));
            let mut skipped = 0u64;
            let mut sent = 0u64;
            for seg in segments {
                if sent >= take {
                    break;
                }
                let path = format!("/{version}/{account}/{container}/{}", seg.name);
                let sub = make_subreq(&orig_head, "GET", path, String::new());
                let sresp = next(sub).await;
                if !(200..300).contains(&sresp.status) {
                    let _ = tx
                        .send(Err(std::io::Error::other(format!(
                            "DLO segment returned {}",
                            sresp.status
                        ))))
                        .await;
                    return;
                }
                match sresp.body.collect_async().await {
                    Ok(b) => {
                        let mut slice = b;
                        if skipped < skip {
                            let drop = (skip - skipped).min(slice.len() as u64) as usize;
                            skipped += drop as u64;
                            if drop >= slice.len() {
                                continue;
                            }
                            slice = slice[drop..].to_vec();
                        }
                        if sent + slice.len() as u64 > take {
                            slice.truncate((take - sent) as usize);
                        }
                        sent += slice.len() as u64;
                        if tx.send(Ok(slice)).await.is_err() {
                            return;
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(Err(e)).await;
                        return;
                    }
                }
            }
        });
        out.body = Body::from_channel(rx, Some(response_length), scope);
        apply_conditional(&orig, out)
    }
}

/// `_validate_x_object_manifest_header`: reject a malformed manifest header on
/// PUT with a 400 whose body Python sets verbatim.
fn validate_x_object_manifest_header(req: &Request) -> Option<Response> {
    let value = req.headers.get(X_OBJECT_MANIFEST)?;
    let (container, prefix) = match value.split_once('/') {
        Some((c, p)) => (c, p),
        None => ("", ""),
    };
    if container.is_empty()
        || prefix.is_empty()
        || value.contains('?')
        || value.contains('&')
        || prefix.starts_with('/')
    {
        let mut resp = Response::with_body(
            400,
            "X-Object-Manifest must be in the format container/prefix"
                .as_bytes()
                .to_vec(),
        );
        resp.headers.set("Content-Type", "text/html; charset=UTF-8");
        return Some(resp);
    }
    None
}

impl Middleware for DynamicLargeObject {
    fn prepare(&self, req: &mut Request) -> MwPrep {
        // Stamp ignore-range *before* the async app GET. intercepts_response
        // reassembly's first `next()` is the already-completed backend
        // response: without this stamp a client Range on a tiny manifest
        // 416s at the object server and DLO never sees X-Object-Manifest.
        if matches!(req.method.as_str(), "GET" | "HEAD")
            && split_path(&req.path, 4, 4, true).is_ok()
            && req.param("multipart-manifest").as_deref() != Some("get")
        {
            update_ignore_range_header(&mut req.headers, X_OBJECT_MANIFEST);
        }
        MwPrep::Continue
    }

    fn intercepts_request(&self, req: &Request) -> bool {
        req.method == "PUT"
            && req.headers.get(X_OBJECT_MANIFEST).is_some()
            && split_path(&req.path, 4, 4, true).is_ok()
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
            if let Some(err) = validate_x_object_manifest_header(&req) {
                return err;
            }
            next(req).await
        })
    }

    fn reassemble_async(
        &self,
        req: Request,
        next: AsyncNextFn,
    ) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        Box::pin(async move { self.handle_get_head_async(req, next).await })
    }

    fn handle(&self, req: Request, next: &NextFn) -> Response {
        // Only object requests (v/a/c/o) are candidates.
        if split_path(&req.path, 4, 4, true).is_err() {
            return next(req);
        }

        let is_get_head = req.method == "GET" || req.method == "HEAD";
        let mpm_get = req.param("multipart-manifest").as_deref() == Some("get");
        if is_get_head && !mpm_get {
            return self.handle_get_head(req, next);
        } else if req.method == "PUT" {
            if let Some(err) = validate_x_object_manifest_header(&req) {
                return err;
            }
        }
        next(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// A programmable backend: matches (method, path) to responses. Canned
    /// responses are torn into Sync parts (a `Body` reader is only `Send`)
    /// and re-issued per request, so one route can serve many subrequests.
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

    fn body_of(resp: &mut Response) -> Vec<u8> {
        resp.body.materialize(u64::MAX).unwrap().to_vec()
    }

    fn md5_hex(data: &[u8]) -> String {
        let d = Md5::digest(data);
        let mut s = String::new();
        for b in d {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    fn listing_json(entries: &[(&str, i64, &str)]) -> Vec<u8> {
        let items: Vec<serde_json::Value> = entries
            .iter()
            .map(|(name, bytes, hash)| {
                serde_json::json!({"name": name, "bytes": bytes, "hash": hash})
            })
            .collect();
        serde_json::to_vec(&items).unwrap()
    }

    #[test]
    fn test_prepare_stamps_ignore_range_on_get() {
        let dlo = DynamicLargeObject::new();
        let mut req = get_req("/v1/a/c/manifest", Some("bytes=100-200"));
        assert!(matches!(dlo.prepare(&mut req), crate::MwPrep::Continue));
        assert_eq!(
            req.headers.get(IGNORE_RANGE_HDR),
            Some(X_OBJECT_MANIFEST)
        );
        // Raw-manifest GET must still honour Range on the stored object.
        let mut raw = get_req("/v1/a/c/manifest", Some("bytes=0-0"));
        raw.query_string = "multipart-manifest=get".into();
        assert!(matches!(dlo.prepare(&mut raw), crate::MwPrep::Continue));
        assert!(raw.headers.get(IGNORE_RANGE_HDR).is_none());
    }

    fn get_req(path: &str, range: Option<&str>) -> Request {
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

    fn manifest_backend() -> NextFn {
        // manifest object -> zero body with X-Object-Manifest + Content-Type
        let mk_manifest = || {
            let mut manifest = Response::with_body(200, Vec::new());
            manifest.headers.set("X-Object-Manifest", "c/segs/");
            manifest.headers.set("Content-Type", "text/jibberish");
            manifest.headers.set("Content-Length", "0");
            manifest.headers.set("Etag", md5_hex(b""));
            manifest
        };
        let manifest = mk_manifest();
        let manifest_head = mk_manifest();

        let listing = Response::with_body(
            200,
            listing_json(&[
                ("segs/1", 3, &md5_hex(b"one")),
                ("segs/2", 3, &md5_hex(b"two")),
                ("segs/3", 5, &md5_hex(b"three")),
            ]),
        );

        backend(vec![
            ("GET", "/v1/a/c/manifest", manifest),
            ("HEAD", "/v1/a/c/manifest", manifest_head),
            ("GET", "/v1/a/c", listing),
            (
                "GET",
                "/v1/a/c/segs/1",
                Response::with_body(200, b"one".to_vec()),
            ),
            (
                "GET",
                "/v1/a/c/segs/2",
                Response::with_body(200, b"two".to_vec()),
            ),
            (
                "GET",
                "/v1/a/c/segs/3",
                Response::with_body(200, b"three".to_vec()),
            ),
        ])
    }

    fn manifest_response(value: &str) -> Response {
        let mut response = Response::with_body(200, Vec::new());
        response.headers.set("X-Object-Manifest", value);
        response.headers.set("Etag", "manifest-etag");
        response
    }

    #[test]
    fn test_full_get_reassembles() {
        let dlo = DynamicLargeObject::new();
        let be = manifest_backend();
        let mut resp = dlo.handle(get_req("/v1/a/c/manifest", None), &be);
        assert_eq!(resp.status, 200);
        assert_eq!(body_of(&mut resp), b"onetwothree");
        assert_eq!(resp.headers.get("Content-Type"), Some("text/jibberish"));
        assert_eq!(resp.headers.get("Content-Length"), Some("11"));
    }

    #[test]
    fn test_head_no_body() {
        let dlo = DynamicLargeObject::new();
        let be = manifest_backend();
        let mut req = get_req("/v1/a/c/manifest", None);
        req.method = "HEAD".to_string();
        let resp = dlo.handle(req, &be);
        assert_eq!(resp.status, 200);
        assert!(resp.body.is_definitely_empty());
        assert_eq!(resp.headers.get("Content-Length"), Some("11"));
    }

    #[test]
    fn test_range_from_start_of_second_segment() {
        // "onetwothree", bytes=3- -> "twothree", 206
        let dlo = DynamicLargeObject::new();
        let be = manifest_backend();
        let mut resp = dlo.handle(get_req("/v1/a/c/manifest", Some("bytes=3-")), &be);
        assert_eq!(resp.status, 206);
        assert_eq!(body_of(&mut resp), b"twothree");
        assert_eq!(resp.headers.get("Content-Range"), Some("bytes 3-10/11"));
    }

    #[test]
    fn test_range_middle() {
        // bytes=5-10 -> "onetwothree"[5..11] = "othree"
        let dlo = DynamicLargeObject::new();
        let be = manifest_backend();
        let mut resp = dlo.handle(get_req("/v1/a/c/manifest", Some("bytes=5-10")), &be);
        assert_eq!(resp.status, 206);
        assert_eq!(body_of(&mut resp), b"othree");
    }

    #[tokio::test]
    async fn test_async_range_out_of_range_and_if_match() {
        let dlo = DynamicLargeObject::new();
        let sync = manifest_backend();
        let next: crate::AsyncNextFn = Arc::new(move |r| {
            let sync = Arc::clone(&sync);
            Box::pin(async move { sync(r) })
        });
        let unsat = dlo
            .reassemble_async(get_req("/v1/a/c/manifest", Some("bytes=100-200")), next.clone())
            .await;
        assert_eq!(unsat.status, 416, "{}", unsat.reason);
        let mut ranged = dlo
            .reassemble_async(get_req("/v1/a/c/manifest", Some("bytes=3-")), next.clone())
            .await;
        assert_eq!(ranged.status, 206);
        let body = ranged.body.collect_async().await.unwrap();
        assert_eq!(body, b"twothree");
        let etag = ranged.headers.get("Etag").unwrap_or("").to_string();
        let mut inm = get_req("/v1/a/c/manifest", None);
        inm.headers.set("If-None-Match", etag);
        let cond = dlo.reassemble_async(inm, next).await;
        assert_eq!(cond.status, 304, "{}", cond.reason);
    }

    #[test]
    fn test_range_largest_u64_end_does_not_overflow() {
        let dlo = DynamicLargeObject::new().with_rate_limit_segments_per_sec(0);
        let be = manifest_backend();
        let mut response = dlo.handle(
            get_req("/v1/a/c/manifest", Some("bytes=0-18446744073709551615")),
            &be,
        );
        assert_eq!(response.status, 206);
        assert_eq!(response.headers.get("Content-Range"), Some("bytes 0-10/11"));
        assert_eq!(body_of(&mut response), b"onetwothree");
    }

    #[test]
    fn test_suffix_range_of_empty_dlo_is_unsatisfiable() {
        let backend: NextFn = Arc::new(move |request: Request| match request.path.as_str() {
            "/v1/a/c/manifest" => manifest_response("c/segs/"),
            "/v1/a/c" => Response::with_body(200, b"[]".to_vec()),
            _ => Response::new(404),
        });
        let response = DynamicLargeObject::new()
            .handle(get_req("/v1/a/c/manifest", Some("bytes=-1")), &backend);
        assert_eq!(response.status, 416);
        assert_eq!(response.headers.get("Content-Range"), Some("bytes */0"));
    }

    #[test]
    fn test_non_manifest_passthrough() {
        let dlo = DynamicLargeObject::new();
        let be = backend(vec![(
            "GET",
            "/v1/a/c/plain",
            Response::with_body(200, b"hello".to_vec()),
        )]);
        let mut resp = dlo.handle(get_req("/v1/a/c/plain", None), &be);
        assert_eq!(resp.status, 200);
        assert_eq!(body_of(&mut resp), b"hello");
    }

    #[test]
    fn test_listing_error_relayed() {
        let dlo = DynamicLargeObject::new();
        let mut manifest = Response::with_body(200, Vec::new());
        manifest.headers.set("X-Object-Manifest", "c/segs/");
        let be = backend(vec![
            ("GET", "/v1/a/c/manifest", manifest),
            ("GET", "/v1/a/c", Response::new(403)),
        ]);
        let resp = dlo.handle(get_req("/v1/a/c/manifest", None), &be);
        assert_eq!(resp.status, 403);
    }

    #[test]
    fn test_put_validation() {
        let dlo = DynamicLargeObject::new();
        let mut req = Request {
            method: "PUT".to_string(),
            path: "/v1/a/c/manifest".to_string(),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: Body::empty(),
        };
        req.headers.set("X-Object-Manifest", "badformat");
        let be = backend(vec![]);
        let resp = dlo.handle(req, &be);
        assert_eq!(resp.status, 400);
    }

    #[test]
    fn test_python_configuration_defaults_and_builders() {
        let defaults = DynamicLargeObject::new();
        assert_eq!(defaults.max_get_time, 86_400);
        assert_eq!(defaults.rate_limit_after_segment, 10);
        assert_eq!(defaults.rate_limit_segments_per_sec, 1);

        let configured = DynamicLargeObject::new()
            .with_max_get_time(2_900)
            .with_rate_limit_after_segment(13)
            .with_rate_limit_segments_per_sec(7);
        assert_eq!(configured.max_get_time, 2_900);
        assert_eq!(configured.rate_limit_after_segment, 13);
        assert_eq!(configured.rate_limit_segments_per_sec, 7);
    }

    #[test]
    fn test_invalid_listing_json_and_schema_fail_closed() {
        let invalid_listings: &[&[u8]] = &[
            b"not json",
            b"{}",
            br#"[null]"#,
            br#"[{"bytes":1,"hash":"h"}]"#,
            br#"[{"name":"s","hash":"h"}]"#,
            br#"[{"name":"s","bytes":-1,"hash":"h"}]"#,
            br#"[{"name":"s","bytes":1}]"#,
            br#"[{"name":"z","bytes":1,"hash":"h"},{"name":"a","bytes":1,"hash":"h"}]"#,
        ];
        for listing in invalid_listings {
            let listing = listing.to_vec();
            let served_listing = listing.clone();
            let backend: NextFn = Arc::new(move |request: Request| match request.path.as_str() {
                "/v1/a/c/manifest" => manifest_response("c/segs/"),
                "/v1/a/c" => Response::with_body(200, served_listing.clone()),
                _ => Response::new(404),
            });
            let response =
                DynamicLargeObject::new().handle(get_req("/v1/a/c/manifest", None), &backend);
            assert_eq!(response.status, 409, "listing {listing:?} must fail closed");
        }
    }

    #[test]
    fn test_marker_pagination_is_lazy_and_complete() {
        let calls = Arc::new(Mutex::new(Vec::<(String, String, Option<String>)>::new()));
        let seen = Arc::clone(&calls);
        let backend: NextFn = Arc::new(move |request: Request| {
            seen.lock().unwrap().push((
                request.path.clone(),
                request.query_string.clone(),
                request.headers.get("Range").map(str::to_string),
            ));
            match request.path.as_str() {
                "/v1/a/c/manifest" => manifest_response("c/segs/"),
                "/v1/a/c" if request.query_string == "prefix=segs/&format=json" => {
                    Response::with_body(
                        200,
                        listing_json(&[
                            ("segs/1", 3, &md5_hex(b"one")),
                            ("segs/2", 3, &md5_hex(b"two")),
                        ]),
                    )
                }
                "/v1/a/c" if request.query_string == "prefix=segs/&marker=segs/2&format=json" => {
                    Response::with_body(200, listing_json(&[("segs/3", 5, &md5_hex(b"three"))]))
                }
                "/v1/a/c/segs/1" => Response::with_body(200, b"one".to_vec()),
                "/v1/a/c/segs/2" => Response::with_body(200, b"two".to_vec()),
                "/v1/a/c/segs/3" => Response::with_body(200, b"three".to_vec()),
                _ => Response::new(404),
            }
        });
        let dlo = DynamicLargeObject::new()
            .with_listing_limit(2)
            .with_rate_limit_segments_per_sec(0);
        let mut response = dlo.handle(get_req("/v1/a/c/manifest", None), &backend);
        assert_eq!(response.status, 200);
        assert_eq!(response.headers.get("Content-Length"), None);
        assert_eq!(
            calls.lock().unwrap().as_slice(),
            &[
                ("/v1/a/c/manifest".to_string(), String::new(), None),
                (
                    "/v1/a/c".to_string(),
                    "prefix=segs/&format=json".to_string(),
                    None,
                ),
                (
                    "/v1/a/c/segs/1".to_string(),
                    "multipart-manifest=get".to_string(),
                    None,
                ),
            ],
            "only the first segment is prevalidated before body consumption"
        );

        assert_eq!(body_of(&mut response), b"onetwothree");
        let calls = calls.lock().unwrap();
        assert_eq!(calls[3].0, "/v1/a/c/segs/2");
        assert_eq!(calls[4].1, "prefix=segs/&marker=segs/2&format=json");
        assert_eq!(calls[5].0, "/v1/a/c/segs/3");
    }

    #[test]
    fn test_more_than_real_container_listing_limit_is_not_truncated() {
        let first_page = serde_json::to_vec(
            &(0..CONTAINER_LISTING_LIMIT)
                .map(|index| {
                    serde_json::json!({
                        "name": format!("segs/{index:05}"),
                        "bytes": 0,
                        "hash": "",
                    })
                })
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let last_page = listing_json(&[("segs/10000", 1, "hash")]);
        let second_listing_seen = Arc::new(Mutex::new(false));
        let seen = Arc::clone(&second_listing_seen);
        let backend: NextFn = Arc::new(move |request: Request| match request.path.as_str() {
            "/v1/a/c/manifest" => manifest_response("c/segs/"),
            "/v1/a/c" if !request.query_string.contains("marker=") => {
                Response::with_body(200, first_page.clone())
            }
            "/v1/a/c" => {
                assert_eq!(
                    request.query_string,
                    "prefix=segs/&marker=segs/09999&format=json"
                );
                *seen.lock().unwrap() = true;
                Response::with_body(200, last_page.clone())
            }
            "/v1/a/c/segs/10000" => Response::with_body(200, b"z".to_vec()),
            path if path.starts_with("/v1/a/c/segs/") => Response::with_body(200, Vec::new()),
            _ => Response::new(404),
        });

        let mut response = DynamicLargeObject::new()
            .with_rate_limit_segments_per_sec(0)
            .handle(get_req("/v1/a/c/manifest", None), &backend);
        assert_eq!(response.status, 200);
        assert_eq!(response.headers.get("Content-Length"), None);
        assert_eq!(body_of(&mut response), b"z");
        assert!(*second_listing_seen.lock().unwrap());
    }

    #[test]
    fn test_range_inside_incomplete_first_page_uses_segment_ranges_only() {
        let calls = Arc::new(Mutex::new(Vec::<(String, String, Option<String>)>::new()));
        let seen = Arc::clone(&calls);
        let backend: NextFn = Arc::new(move |request: Request| {
            seen.lock().unwrap().push((
                request.path.clone(),
                request.query_string.clone(),
                request.headers.get("Range").map(str::to_string),
            ));
            match request.path.as_str() {
                "/v1/a/c/manifest" => manifest_response("c/segs/"),
                "/v1/a/c" => Response::with_body(
                    200,
                    listing_json(&[
                        ("segs/1", 5, &md5_hex(b"aaaaa")),
                        ("segs/2", 5, &md5_hex(b"bbbbb")),
                        ("segs/3", 5, &md5_hex(b"ccccc")),
                    ]),
                ),
                "/v1/a/c/segs/1" => Response::with_body(200, b"aaaaa".to_vec()),
                "/v1/a/c/segs/2" => Response::with_body(200, b"bbbbb".to_vec()),
                "/v1/a/c/segs/3" => Response::with_body(200, b"ccccc".to_vec()),
                _ => Response::new(404),
            }
        });
        let dlo = DynamicLargeObject::new()
            .with_listing_limit(3)
            .with_rate_limit_segments_per_sec(0);
        let mut response = dlo.handle(get_req("/v1/a/c/manifest", Some("bytes=3-12")), &backend);
        assert_eq!(response.status, 206);
        assert_eq!(response.headers.get("Content-Length"), Some("10"));
        assert_eq!(response.headers.get("Content-Range"), Some("bytes 3-12/15"));
        assert_eq!(body_of(&mut response), b"aabbbbbccc");

        let calls = calls.lock().unwrap();
        let segments: Vec<_> = calls
            .iter()
            .filter(|(path, _, _)| path.starts_with("/v1/a/c/segs/"))
            .collect();
        assert_eq!(segments.len(), 3);
        assert_eq!(segments[0].2.as_deref(), Some("bytes=3-"));
        assert_eq!(segments[1].2, None);
        assert_eq!(segments[2].2.as_deref(), Some("bytes=0-2"));
        assert!(!calls.iter().any(|(_, query, _)| query.contains("marker=")));
    }

    #[test]
    fn test_unknown_range_is_ignored_and_all_pages_stream() {
        let calls = Arc::new(Mutex::new(Vec::<String>::new()));
        let seen = Arc::clone(&calls);
        let backend: NextFn = Arc::new(move |request: Request| {
            seen.lock().unwrap().push(request.query_string.clone());
            match request.path.as_str() {
                "/v1/a/c/manifest" => manifest_response("c/segs/"),
                "/v1/a/c" if !request.query_string.contains("marker=") => Response::with_body(
                    200,
                    listing_json(&[
                        ("segs/1", 5, "h1"),
                        ("segs/2", 5, "h2"),
                        ("segs/3", 5, "h3"),
                    ]),
                ),
                "/v1/a/c" => Response::with_body(
                    200,
                    listing_json(&[("segs/4", 5, "h4"), ("segs/5", 5, "h5")]),
                ),
                "/v1/a/c/segs/1" => Response::with_body(200, b"aaaaa".to_vec()),
                "/v1/a/c/segs/2" => Response::with_body(200, b"bbbbb".to_vec()),
                "/v1/a/c/segs/3" => Response::with_body(200, b"ccccc".to_vec()),
                "/v1/a/c/segs/4" => Response::with_body(200, b"ddddd".to_vec()),
                "/v1/a/c/segs/5" => Response::with_body(200, b"eeeee".to_vec()),
                _ => Response::new(404),
            }
        });
        let dlo = DynamicLargeObject::new()
            .with_listing_limit(3)
            .with_rate_limit_segments_per_sec(0);
        let mut response = dlo.handle(get_req("/v1/a/c/manifest", Some("bytes=10-22")), &backend);
        assert_eq!(response.status, 200);
        assert_eq!(response.headers.get("Content-Length"), None);
        assert_eq!(response.headers.get("Content-Range"), None);
        assert_eq!(body_of(&mut response), b"aaaaabbbbbcccccdddddeeeee");
        assert!(calls
            .lock()
            .unwrap()
            .iter()
            .any(|query| query == "prefix=segs/&marker=segs/3&format=json"));
    }

    #[test]
    fn test_first_segment_status_is_validated_before_commit() {
        for (segment_status, expected) in [(403, 409), (503, 503)] {
            let backend: NextFn = Arc::new(move |request: Request| match request.path.as_str() {
                "/v1/a/c/manifest" => manifest_response("c/segs/"),
                "/v1/a/c" => Response::with_body(200, listing_json(&[("segs/1", 1, "hash")])),
                "/v1/a/c/segs/1" => Response::new(segment_status),
                _ => Response::new(404),
            });
            let response = DynamicLargeObject::new()
                .with_rate_limit_segments_per_sec(0)
                .handle(get_req("/v1/a/c/manifest", None), &backend);
            assert_eq!(response.status, expected);
        }
    }

    #[test]
    fn test_segment_response_etag_and_length_are_checked_while_streaming() {
        for (declared_length, declared_etag) in [(Some("2"), None), (Some("3"), Some("bad"))] {
            let backend: NextFn = Arc::new(move |request: Request| match request.path.as_str() {
                "/v1/a/c/manifest" => manifest_response("c/segs/"),
                "/v1/a/c" => {
                    Response::with_body(200, listing_json(&[("segs/1", 3, "listing-hash")]))
                }
                "/v1/a/c/segs/1" => {
                    let mut response = Response::with_body(200, b"one".to_vec());
                    response.headers.set("Etag", declared_etag.unwrap_or("bad"));
                    if let Some(length) = declared_length {
                        response.headers.set("Content-Length", length);
                    }
                    response
                }
                _ => Response::new(404),
            });
            let response = DynamicLargeObject::new()
                .with_rate_limit_segments_per_sec(0)
                .handle(get_req("/v1/a/c/manifest", None), &backend);
            assert_eq!(response.status, 200);
            let (mut reader, _) = response.body.into_reader();
            let mut bytes = Vec::new();
            let error = reader.read_to_end(&mut bytes).unwrap_err();
            assert_eq!(bytes, b"one");
            assert!(error.to_string().contains("length") || error.to_string().contains("MD5"));
        }
    }

    #[test]
    fn test_later_listing_error_aborts_after_first_page_bytes() {
        let backend: NextFn = Arc::new(move |request: Request| match request.path.as_str() {
            "/v1/a/c/manifest" => manifest_response("c/segs/"),
            "/v1/a/c" if !request.query_string.contains("marker=") => Response::with_body(
                200,
                listing_json(&[("segs/1", 1, "h1"), ("segs/2", 1, "h2")]),
            ),
            "/v1/a/c" => Response::new(404),
            "/v1/a/c/segs/1" => Response::with_body(200, b"a".to_vec()),
            "/v1/a/c/segs/2" => Response::with_body(200, b"b".to_vec()),
            _ => Response::new(404),
        });
        let dlo = DynamicLargeObject::new()
            .with_listing_limit(2)
            .with_rate_limit_segments_per_sec(0);
        let response = dlo.handle(get_req("/v1/a/c/manifest", None), &backend);
        assert_eq!(response.status, 200);
        let (mut reader, _) = response.body.into_reader();
        let mut bytes = Vec::new();
        let error = reader.read_to_end(&mut bytes).unwrap_err();
        assert_eq!(bytes, b"ab");
        assert!(error.to_string().contains("listing"));
    }

    #[test]
    fn test_nonadvancing_marker_page_fails_closed_midstream() {
        let backend: NextFn = Arc::new(move |request: Request| match request.path.as_str() {
            "/v1/a/c/manifest" => manifest_response("c/segs/"),
            "/v1/a/c" if !request.query_string.contains("marker=") => Response::with_body(
                200,
                listing_json(&[("segs/1", 1, "h1"), ("segs/2", 1, "h2")]),
            ),
            "/v1/a/c" => Response::with_body(
                200,
                listing_json(&[("segs/2", 1, "h2"), ("segs/3", 1, "h3")]),
            ),
            "/v1/a/c/segs/1" => Response::with_body(200, b"a".to_vec()),
            "/v1/a/c/segs/2" => Response::with_body(200, b"b".to_vec()),
            _ => Response::new(404),
        });
        let response = DynamicLargeObject::new()
            .with_listing_limit(2)
            .with_rate_limit_segments_per_sec(0)
            .handle(get_req("/v1/a/c/manifest", None), &backend);
        assert_eq!(response.status, 200);
        let (mut reader, _) = response.body.into_reader();
        let mut bytes = Vec::new();
        let error = reader.read_to_end(&mut bytes).unwrap_err();
        assert_eq!(bytes, b"ab");
        assert!(error.to_string().contains("marker did not advance"));
    }

    #[test]
    fn test_max_get_time_is_enforced_without_hiding_first_chunk() {
        let backend: NextFn = Arc::new(move |request: Request| match request.path.as_str() {
            "/v1/a/c/manifest" => manifest_response("c/segs/"),
            "/v1/a/c" => Response::with_body(200, listing_json(&[("segs/1", 1, "hash")])),
            "/v1/a/c/segs/1" => Response::with_body(200, b"a".to_vec()),
            _ => Response::new(404),
        });
        let response = DynamicLargeObject::new()
            .with_max_get_time(-1)
            .with_rate_limit_segments_per_sec(0)
            .handle(get_req("/v1/a/c/manifest", None), &backend);
        assert_eq!(response.status, 200);
        let (mut reader, _) = response.body.into_reader();
        let mut first = [0u8; 1];
        assert_eq!(reader.read(&mut first).unwrap(), 1);
        assert_eq!(first, *b"a");
        let mut rest = Vec::new();
        assert!(reader.read_to_end(&mut rest).is_err());
    }
}
