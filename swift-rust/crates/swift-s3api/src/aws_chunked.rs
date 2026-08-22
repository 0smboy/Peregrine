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

//! AWS `aws-chunked` body framing decode for S3 SigV4 streaming uploads.
//!
//! Clients (AWS SDK, aws-cli) send PUT/POST bodies framed as:
//!
//! ```text
//! <hex-size>[;chunk-signature=<hex>]\r\n
//! <payload bytes>\r\n
//! …
//! 0[;chunk-signature=<hex>]\r\n
//! [trailers…]\r\n
//! [x-amz-trailer-signature:<hex>\r\n]
//! \r\n
//! ```
//!
//! Triggered only by `X-Amz-Content-SHA256: STREAMING-*`.
//! `Content-Encoding: aws-chunked` alone is not a dechunk signal (a client
//! may advertise the encoding while the payload hash is a regular SHA256 /
//! UNSIGNED-PAYLOAD, in which case the body is already raw). Port of Python
//! `StreamingInput` /
//! `ChunkReader` dechunk path (`s3request.py`). When `ChunkSigContext` is
//! supplied for STREAMING-AWS4-HMAC-SHA256-PAYLOAD*, per-chunk HMAC chain
//! verification is **enforced**: mismatch → [`AwsChunkedError::InvalidChunkSignature`].
//!
//! For `STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER` (and whenever
//! `x-amz-trailer-signature` is present under a signed HMAC context), trailer
//! content is verified with `AWS4-HMAC-SHA256-TRAILER` (previous-sig = terminal
//! 0-chunk signature). Mismatch → [`AwsChunkedError::InvalidTrailerSignature`].
//! `STREAMING-UNSIGNED-PAYLOAD-TRAILER` accepts trailers without HMAC.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::sync::{Arc, Mutex};

use crate::crypto::{hmac_sha256_hex, sha256_hex, streq_const_time};
use crate::sigv4::signing_key;
use swift_http::{BodyTransform, HeaderKeyDict, Request};

/// Max aws-chunked *chunk* (not object) we will buffer for HMAC.
/// Memory is O(chunk), not O(object).
pub const MAX_STREAMING_CHUNK: usize = 16 * 1024 * 1024;
const MAX_HEADER_LINE: usize = 4096;

/// `X-Amz-Content-SHA256` values that imply aws-chunked streaming
/// (Python `s3request._is_streaming`).
pub const AWS_CHUNKED_PAYLOAD_HASHES: &[&str] = &[
    "STREAMING-UNSIGNED-PAYLOAD-TRAILER",
    "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
    "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER",
    "STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD",
    "STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD-TRAILER",
];

/// ECDSA streaming modes we still reject (Python `S3NotImplemented`).
const ECDSA_STREAMING: &[&str] = &[
    "STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD",
    "STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD-TRAILER",
];

/// SHA-256 of empty payload (used in chunk string-to-sign).
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Decode errors mapped to S3 client-facing faults by the middleware.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AwsChunkedError {
    Incomplete,
    InvalidChunkHeader,
    SizeMismatch {
        expected: u64,
        provided: u64,
    },
    MissingDecodedContentLength,
    EcdsaNotImplemented,
    /// Per-chunk HMAC chain failed or chunk-signature missing in signed mode.
    InvalidChunkSignature,
    /// Trailer HMAC (`AWS4-HMAC-SHA256-TRAILER` / `x-amz-trailer-signature`)
    /// failed, or required trailer signature missing in signed trailer mode.
    InvalidTrailerSignature,
}

impl fmt::Display for AwsChunkedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "aws-chunked:{self:?}")
    }
}

impl std::error::Error for AwsChunkedError {}

/// Decoded payload + optional trailers after the terminal 0-chunk.
#[derive(Debug, Clone)]
pub struct DecodedChunkedBody {
    pub data: Vec<u8>,
    pub trailers: HashMap<String, String>,
    /// `Some(true)` when HMAC chunk-sig verify was attempted and all chunks
    /// validated. Invalid signatures fail with
    /// [`AwsChunkedError::InvalidChunkSignature`] rather than `Some(false)`.
    /// `None` when no [`ChunkSigContext`] was supplied.
    pub chunk_signatures_valid: Option<bool>,
    /// `Some(true)` when trailer signature was verified successfully.
    /// `Some(false)` is not used (failure → error). `None` when trailer HMAC
    /// was not applicable (unsigned mode / no trailer-sig present / not required).
    pub trailer_signature_valid: Option<bool>,
}

/// Context for STREAMING-AWS4-HMAC-SHA256-PAYLOAD chunk signature chain
/// verification. When passed to [`decode_aws_chunked`], invalid signatures
/// fail the decode with [`AwsChunkedError::InvalidChunkSignature`].
///
/// When [`Self::require_trailer_signature`] is true (PAYLOAD-TRAILER mode) or
/// trailers include `x-amz-trailer-signature`, trailer HMAC is also enforced.
#[derive(Debug, Clone)]
pub struct ChunkSigContext {
    pub secret_key: String,
    pub date: String,
    pub region: String,
    pub service: String,
    pub amz_date: String,
    /// Header (seed) signature; each chunk uses the previous signature.
    pub seed_signature: String,
    /// When true (`STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER`), trailers must
    /// carry a valid `x-amz-trailer-signature` if any trailer content is present.
    /// When false, trailer sig is still verified *if* the header is present.
    pub require_trailer_signature: bool,
}

/// True when `X-Amz-Content-SHA256` is a STREAMING-* value.
pub fn is_streaming_payload_hash(hash: &str) -> bool {
    AWS_CHUNKED_PAYLOAD_HASHES
        .iter()
        .any(|v| hash.eq_ignore_ascii_case(v))
}

/// True when the value is an ECDSA streaming mode we do not implement.
pub fn is_ecdsa_streaming(hash: &str) -> bool {
    ECDSA_STREAMING.iter().any(|v| hash.eq_ignore_ascii_case(v))
}

/// True when the request asks for aws-chunked / streaming payload framing.
///
/// Only `X-Amz-Content-SHA256: STREAMING-*` is authoritative. Encoding-only
/// `aws-chunked` must not dechunk: that would corrupt a raw body that
/// happens to carry the encoding token.
pub fn is_aws_chunked_request(req: &Request) -> bool {
    req.headers
        .get("X-Amz-Content-SHA256")
        .is_some_and(is_streaming_payload_hash)
}

/// Strip `aws-chunked` tokens from `Content-Encoding` (Python
/// `_cleanup_content_encoding`). Removes the header when nothing remains.
pub fn cleanup_content_encoding(headers: &mut HeaderKeyDict) {
    let Some(enc) = headers.get("Content-Encoding").map(str::to_string) else {
        return;
    };
    let kept: Vec<&str> = enc
        .split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty() && !p.eq_ignore_ascii_case("aws-chunked"))
        .collect();
    if kept.is_empty() {
        headers.remove("Content-Encoding");
    } else {
        headers.set("Content-Encoding", kept.join(", "));
    }
}

/// Incremental aws-chunked decoder. Buffer is O(current chunk), not O(object).
pub struct AwsChunkedDecoder {
    buf: Vec<u8>,
    pos: usize,
    state: DecState,
    expected: Option<u64>,
    decoded: u64,
    sig_ctx: Option<ChunkSigContext>,
    prev_sig: Option<String>,
    trailers: HashMap<String, String>,
    all_sigs_ok: Option<bool>,
    trailer_ok: Option<bool>,
    last_chunk_size: Option<usize>,
}

enum DecState {
    Header,
    Body {
        remaining: usize,
        chunk: Vec<u8>,
        chunk_sig: Option<String>,
    },
    BodyCrlf {
        chunk: Vec<u8>,
        chunk_sig: Option<String>,
        got: u8,
    },
    Trailers,
    Done,
}

impl AwsChunkedDecoder {
    pub fn new(expected: Option<u64>, sig_ctx: Option<ChunkSigContext>) -> Self {
        let all_sigs_ok = sig_ctx.as_ref().map(|_| true);
        let prev_sig = sig_ctx
            .as_ref()
            .map(|c| c.seed_signature.to_ascii_lowercase());
        Self {
            buf: Vec::new(),
            pos: 0,
            state: DecState::Header,
            expected,
            decoded: 0,
            sig_ctx,
            prev_sig,
            trailers: HashMap::new(),
            all_sigs_ok,
            trailer_ok: None,
            last_chunk_size: None,
        }
    }

    /// Wire bytes currently held (header remnant + in-progress chunk).
    pub fn buffered_wire_bytes(&self) -> usize {
        let pending = self.buf.len().saturating_sub(self.pos);
        pending
            + match &self.state {
                DecState::Body { chunk, .. } | DecState::BodyCrlf { chunk, .. } => chunk.len(),
                _ => 0,
            }
    }

    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<u8>, AwsChunkedError> {
        self.buf.extend_from_slice(bytes);
        let mut out = Vec::new();
        self.drain(&mut out, false)?;
        self.compact();
        Ok(out)
    }

    pub fn finish_payload(&mut self) -> Result<Vec<u8>, AwsChunkedError> {
        let mut out = Vec::new();
        self.drain(&mut out, true)?;
        if let Some(expected) = self.expected {
            if self.decoded != expected {
                return Err(AwsChunkedError::SizeMismatch {
                    expected,
                    provided: self.decoded,
                });
            }
        }
        self.trailer_ok = verify_trailers_if_needed(
            self.sig_ctx.as_ref(),
            self.prev_sig.as_deref(),
            &self.trailers,
        )?;
        Ok(out)
    }

    fn compact(&mut self) {
        if self.pos > 0 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
    }

    fn remaining(&self) -> &[u8] {
        &self.buf[self.pos..]
    }

    fn drain(&mut self, out: &mut Vec<u8>, eof: bool) -> Result<(), AwsChunkedError> {
        loop {
            match &mut self.state {
                DecState::Done => {
                    if eof && !self.remaining().is_empty() {
                        // stray bytes after terminal blank line
                    }
                    return Ok(());
                }
                DecState::Header => {
                    let rem = self.remaining();
                    let Some(nl) = rem.iter().position(|&b| b == b'\n') else {
                        if rem.len() > MAX_HEADER_LINE {
                            return Err(AwsChunkedError::InvalidChunkHeader);
                        }
                        if eof {
                            return Err(AwsChunkedError::Incomplete);
                        }
                        return Ok(());
                    };
                    let mut line = rem[..nl].to_vec();
                    self.pos += nl + 1;
                    if line.ends_with(&[b'\r']) {
                        line.pop();
                    }
                    let (size_str, params) = match line.iter().position(|&b| b == b';') {
                        Some(i) => (&line[..i], Some(&line[i + 1..])),
                        None => (line.as_slice(), None),
                    };
                    let size = parse_hex_size(size_str)?;
                    let _ = self.last_chunk_size.replace(size);
                    if size > MAX_STREAMING_CHUNK {
                        return Err(AwsChunkedError::InvalidChunkHeader);
                    }
                    if let Some(expected) = self.expected {
                        if self.decoded + size as u64 > expected {
                            return Err(AwsChunkedError::SizeMismatch {
                                expected,
                                provided: self.decoded + size as u64,
                            });
                        }
                    }
                    let chunk_sig = parse_chunk_signature(params);
                    if size == 0 {
                        if let Some(ctx) = self.sig_ctx.clone() {
                            match (chunk_sig, self.prev_sig.as_ref()) {
                                (Some(sig), Some(prev)) => {
                                    if !verify_chunk_signature(&ctx, prev, EMPTY_SHA256, &sig) {
                                        return Err(AwsChunkedError::InvalidChunkSignature);
                                    }
                                    self.all_sigs_ok = Some(true);
                                    self.prev_sig = Some(sig.to_ascii_lowercase());
                                }
                                _ => return Err(AwsChunkedError::InvalidChunkSignature),
                            }
                        }
                        self.state = DecState::Trailers;
                        continue;
                    }
                    self.state = DecState::Body {
                        remaining: size,
                        chunk: Vec::with_capacity(size),
                        chunk_sig,
                    };
                }
                DecState::Body { .. } => {
                    let (mut remaining, mut chunk, chunk_sig) = match &mut self.state {
                        DecState::Body {
                            remaining,
                            chunk,
                            chunk_sig,
                        } => (*remaining, std::mem::take(chunk), chunk_sig.take()),
                        _ => unreachable!(),
                    };
                    let avail = self.buf.len().saturating_sub(self.pos);
                    if avail == 0 {
                        self.state = DecState::Body {
                            remaining,
                            chunk,
                            chunk_sig,
                        };
                        if eof {
                            return Err(AwsChunkedError::Incomplete);
                        }
                        return Ok(());
                    }
                    let take = remaining.min(avail);
                    chunk.extend_from_slice(&self.buf[self.pos..self.pos + take]);
                    self.pos += take;
                    remaining -= take;
                    if remaining == 0 {
                        self.state = DecState::BodyCrlf {
                            chunk,
                            chunk_sig,
                            got: 0,
                        };
                    } else {
                        self.state = DecState::Body {
                            remaining,
                            chunk,
                            chunk_sig,
                        };
                    }
                }
                DecState::BodyCrlf { .. } => {
                    let (chunk, chunk_sig, mut got) = match &mut self.state {
                        DecState::BodyCrlf {
                            chunk,
                            chunk_sig,
                            got,
                        } => (std::mem::take(chunk), chunk_sig.take(), *got),
                        _ => unreachable!(),
                    };
                    let avail = self.buf.len().saturating_sub(self.pos);
                    if avail == 0 {
                        self.state = DecState::BodyCrlf {
                            chunk,
                            chunk_sig,
                            got,
                        };
                        if eof {
                            return Err(AwsChunkedError::Incomplete);
                        }
                        return Ok(());
                    }
                    let b = self.buf[self.pos];
                    self.pos += 1;
                    got = match (got, b) {
                        (0, b'\n') => 2,
                        (0, b'\r') => 1,
                        (1, b'\n') => 2,
                        _ => return Err(AwsChunkedError::InvalidChunkHeader),
                    };
                    if got < 2 {
                        self.state = DecState::BodyCrlf {
                            chunk,
                            chunk_sig,
                            got,
                        };
                        continue;
                    }
                    if let Some(ctx) = self.sig_ctx.clone() {
                        match (chunk_sig, self.prev_sig.as_ref()) {
                            (Some(sig), Some(prev)) => {
                                let data_hash = sha256_hex(&chunk);
                                if !verify_chunk_signature(&ctx, prev, &data_hash, &sig) {
                                    return Err(AwsChunkedError::InvalidChunkSignature);
                                }
                                self.all_sigs_ok = Some(true);
                                self.prev_sig = Some(sig.to_ascii_lowercase());
                            }
                            _ => return Err(AwsChunkedError::InvalidChunkSignature),
                        }
                    }
                    self.decoded += chunk.len() as u64;
                    out.extend_from_slice(&chunk);
                    self.state = DecState::Header;
                }
                DecState::Trailers => {
                    let rem = self.remaining();
                    let Some(nl) = rem.iter().position(|&b| b == b'\n') else {
                        if rem.is_empty() && eof {
                            self.state = DecState::Done;
                            return Ok(());
                        }
                        if rem.len() > MAX_HEADER_LINE {
                            return Err(AwsChunkedError::InvalidChunkHeader);
                        }
                        if eof {
                            if !rem.is_empty() {
                                let line = rem.to_vec();
                                self.pos += rem.len();
                                self.take_trailer_line(&line);
                            }
                            self.state = DecState::Done;
                            return Ok(());
                        }
                        return Ok(());
                    };
                    let mut line = rem[..nl].to_vec();
                    self.pos += nl + 1;
                    if line.ends_with(&[b'\r']) {
                        line.pop();
                    }
                    if line.is_empty() {
                        self.state = DecState::Done;
                        continue;
                    }
                    self.take_trailer_line(&line);
                }
            }
        }
    }

    fn take_trailer_line(&mut self, line: &[u8]) {
        if let Some(colon) = line.iter().position(|&b| b == b':') {
            let key = String::from_utf8_lossy(&line[..colon])
                .trim()
                .to_ascii_lowercase();
            let value = String::from_utf8_lossy(&line[colon + 1..])
                .trim()
                .to_string();
            self.trailers.insert(key, value);
        }
    }
}

/// Body transform for Hyper IncomingBody. Errors are stored on [`Self::error`]
/// so the S3 layer can return SignatureDoesNotMatch instead of a Swift 499.
pub struct AwsChunkedTransform {
    inner: AwsChunkedDecoder,
    finished: bool,
    /// Last decoder error (fail-closed).
    pub error: Arc<Mutex<Option<AwsChunkedError>>>,
}

impl AwsChunkedTransform {
    pub fn new(
        expected: Option<u64>,
        sig_ctx: Option<ChunkSigContext>,
        error: Arc<Mutex<Option<AwsChunkedError>>>,
    ) -> Self {
        Self {
            inner: AwsChunkedDecoder::new(expected, sig_ctx),
            finished: false,
            error,
        }
    }

    pub fn buffered_wire_bytes(&self) -> usize {
        self.inner.buffered_wire_bytes()
    }
}

impl BodyTransform for AwsChunkedTransform {
    fn push(&mut self, input: Option<&[u8]>) -> io::Result<Vec<u8>> {
        let r = match input {
            Some(b) => self.inner.push(b),
            None => {
                if self.finished {
                    return Ok(Vec::new());
                }
                self.finished = true;
                self.inner.finish_payload()
            }
        };
        match r {
            Ok(v) => Ok(v),
            Err(e) => {
                *self.error.lock().unwrap_or_else(|p| p.into_inner()) = Some(e.clone());
                Err(io::Error::new(io::ErrorKind::InvalidData, e))
            }
        }
    }
}

/// Decode an aws-chunked wire body into raw payload bytes.
///
/// Incremental: [`AwsChunkedDecoder`] holds at most one chunk. This helper
/// still concatenates the payload for callers that need the full object
/// (sync `handle()` path).
pub fn decode_aws_chunked(
    raw: &[u8],
    expected_decoded_len: Option<u64>,
    sig_ctx: Option<&ChunkSigContext>,
) -> Result<DecodedChunkedBody, AwsChunkedError> {
    let mut dec = AwsChunkedDecoder::new(expected_decoded_len, sig_ctx.cloned());
    let mut data = dec.push(raw)?;
    data.extend(dec.finish_payload()?);
    Ok(DecodedChunkedBody {
        data,
        trailers: dec.trailers,
        chunk_signatures_valid: dec.all_sigs_ok,
        trailer_signature_valid: dec.trailer_ok,
    })
}

/// Verify trailer HMAC when signed streaming context applies.
///
/// * `require_trailer_signature` + non-empty trailers without
///   `x-amz-trailer-signature` → error
/// * `x-amz-trailer-signature` present (any signed mode) → HMAC check
/// * Unsigned (`sig_ctx` None) → always `None` (accept)
fn verify_trailers_if_needed(
    sig_ctx: Option<&ChunkSigContext>,
    prev_sig: Option<&str>,
    trailers: &HashMap<String, String>,
) -> Result<Option<bool>, AwsChunkedError> {
    let Some(ctx) = sig_ctx else {
        return Ok(None);
    };
    let has_trailer_sig = trailers.contains_key("x-amz-trailer-signature");
    let has_any_trailer = !trailers.is_empty();

    // PAYLOAD-TRAILER: if client sent trailer content, signature is required.
    if ctx.require_trailer_signature && has_any_trailer && !has_trailer_sig {
        return Err(AwsChunkedError::InvalidTrailerSignature);
    }
    if !has_trailer_sig {
        // Residual: empty trailer block with require_trailer_signature still
        // accepted (clients that omit trailers entirely after 0-chunk).
        return Ok(None);
    }

    let Some(prev) = prev_sig else {
        return Err(AwsChunkedError::InvalidTrailerSignature);
    };
    let presented = trailers
        .get("x-amz-trailer-signature")
        .map(String::as_str)
        .unwrap_or("");
    if !verify_trailer_signature(ctx, prev, trailers, presented) {
        return Err(AwsChunkedError::InvalidTrailerSignature);
    }
    Ok(Some(true))
}

fn parse_hex_size(bytes: &[u8]) -> Result<usize, AwsChunkedError> {
    let s = std::str::from_utf8(bytes).map_err(|_| AwsChunkedError::InvalidChunkHeader)?;
    let s = s.trim();
    if s.is_empty() {
        return Err(AwsChunkedError::InvalidChunkHeader);
    }
    usize::from_str_radix(s, 16).map_err(|_| AwsChunkedError::InvalidChunkHeader)
}

fn parse_chunk_signature(params: Option<&[u8]>) -> Option<String> {
    let params = params?;
    let s = std::str::from_utf8(params).ok()?;
    // params may be "chunk-signature=HEX" or multiple `;`-joined fields.
    for part in s.split(';') {
        let part = part.trim();
        if let Some(rest) = part
            .strip_prefix("chunk-signature=")
            .or_else(|| part.strip_prefix("chunk-signature ="))
        {
            let sig = rest.trim();
            if !sig.is_empty() {
                return Some(sig.to_string());
            }
        }
    }
    None
}

/// Compute one STREAMING-AWS4-HMAC-SHA256-PAYLOAD chunk signature (lowercase hex).
///
/// `data_sha256` is the SHA-256 hex of the chunk payload, or the empty-payload
/// SHA-256 (`e3b0c442…`) for the terminal 0-size chunk.
pub fn compute_chunk_signature(
    ctx: &ChunkSigContext,
    previous_signature: &str,
    data_sha256: &str,
) -> String {
    // AWS4-HMAC-SHA256-PAYLOAD\n<amz_date>\n<scope>\n<prev_sig>\n<empty_sha>\n<data_sha>
    let scope = format!("{}/{}/{}/aws4_request", ctx.date, ctx.region, ctx.service);
    let sts = format!(
        "AWS4-HMAC-SHA256-PAYLOAD\n{}\n{}\n{}\n{}\n{}",
        ctx.amz_date,
        scope,
        previous_signature.to_ascii_lowercase(),
        EMPTY_SHA256,
        data_sha256.to_ascii_lowercase()
    );
    let key = signing_key(&ctx.secret_key, &ctx.date, &ctx.region, &ctx.service);
    hmac_sha256_hex(&key, sts.as_bytes())
}

fn verify_chunk_signature(
    ctx: &ChunkSigContext,
    previous_signature: &str,
    data_sha256: &str,
    presented: &str,
) -> bool {
    let expected = compute_chunk_signature(ctx, previous_signature, data_sha256);
    streq_const_time(&expected, &presented.to_ascii_lowercase())
}

/// Build the AWS trailer string-to-sign payload hash input:
/// sorted `key:value\n` lines excluding `x-amz-trailer-signature`, spaces
/// stripped (Python `sign_trailer` / AWS no-whitespace rule). Empty trailers
/// → a single `\n`.
pub fn canonical_trailer_bytes(trailers: &HashMap<String, String>) -> Vec<u8> {
    let mut keys: Vec<&str> = trailers
        .keys()
        .map(String::as_str)
        .filter(|k| *k != "x-amz-trailer-signature")
        .collect();
    keys.sort_unstable();
    let mut out = Vec::new();
    for k in keys {
        let v = trailers.get(k).map(String::as_str).unwrap_or("");
        // AWS: no whitespace around colon; strip residual spaces from values.
        let v_compact: String = v.chars().filter(|c| !c.is_whitespace()).collect();
        out.extend_from_slice(k.as_bytes());
        out.push(b':');
        out.extend_from_slice(v_compact.as_bytes());
        out.push(b'\n');
    }
    if out.is_empty() {
        out.push(b'\n');
    }
    out
}

/// Compute `AWS4-HMAC-SHA256-TRAILER` signature (lowercase hex).
///
/// `previous_signature` is the terminal 0-byte chunk signature.
/// `trailers` should include content trailers; `x-amz-trailer-signature` is
/// ignored if present in the map.
///
/// String-to-sign (AWS / Python `SigV4Request._trailer_string_to_sign`):
/// ```text
/// AWS4-HMAC-SHA256-TRAILER
/// <amz_date>
/// <date>/<region>/<service>/aws4_request
/// <previous_signature>
/// hex(sha256(canonical_trailers))
/// ```
pub fn compute_trailer_signature(
    ctx: &ChunkSigContext,
    previous_signature: &str,
    trailers: &HashMap<String, String>,
) -> String {
    let scope = format!("{}/{}/{}/aws4_request", ctx.date, ctx.region, ctx.service);
    let trailer_hash = sha256_hex(&canonical_trailer_bytes(trailers));
    let sts = format!(
        "AWS4-HMAC-SHA256-TRAILER\n{}\n{}\n{}\n{}",
        ctx.amz_date,
        scope,
        previous_signature.to_ascii_lowercase(),
        trailer_hash
    );
    let key = signing_key(&ctx.secret_key, &ctx.date, &ctx.region, &ctx.service);
    hmac_sha256_hex(&key, sts.as_bytes())
}

fn verify_trailer_signature(
    ctx: &ChunkSigContext,
    previous_signature: &str,
    trailers: &HashMap<String, String>,
    presented: &str,
) -> bool {
    let expected = compute_trailer_signature(ctx, previous_signature, trailers);
    streq_const_time(&expected, &presented.to_ascii_lowercase())
}

#[allow(dead_code)]
fn read_line(raw: &[u8], pos: &mut usize) -> Result<Vec<u8>, AwsChunkedError> {
    if *pos >= raw.len() {
        return Err(AwsChunkedError::Incomplete);
    }
    let start = *pos;
    while *pos < raw.len() {
        if raw[*pos] == b'\n' {
            let end = if *pos > start && raw[*pos - 1] == b'\r' {
                *pos - 1
            } else {
                *pos
            };
            *pos += 1;
            return Ok(raw[start..end].to_vec());
        }
        *pos += 1;
    }
    // EOF without newline — incomplete framing
    Err(AwsChunkedError::Incomplete)
}

#[allow(dead_code)]
fn consume_crlf(raw: &[u8], pos: &mut usize) -> bool {
    if *pos + 1 < raw.len() && raw[*pos] == b'\r' && raw[*pos + 1] == b'\n' {
        *pos += 2;
        return true;
    }
    if *pos < raw.len() && raw[*pos] == b'\n' {
        *pos += 1;
        return true;
    }
    false
}

/// Build a framed aws-chunked body (unsigned, no chunk-signature) for tests.
#[cfg(test)]
pub fn frame_aws_chunked_unsigned(payload: &[u8], chunk_size: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut offset = 0;
    let chunk_size = chunk_size.max(1);
    while offset < payload.len() {
        let end = (offset + chunk_size).min(payload.len());
        let slice = &payload[offset..end];
        out.extend_from_slice(format!("{:x}\r\n", slice.len()).as_bytes());
        out.extend_from_slice(slice);
        out.extend_from_slice(b"\r\n");
        offset = end;
    }
    out.extend_from_slice(b"0\r\n\r\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dechunk_unsigned_simple() {
        let payload = b"hello-aws-chunked";
        let framed = frame_aws_chunked_unsigned(payload, 5);
        let decoded = decode_aws_chunked(&framed, Some(payload.len() as u64), None).unwrap();
        assert_eq!(decoded.data, payload);
        assert!(decoded.trailers.is_empty());
        assert_eq!(decoded.chunk_signatures_valid, None);
    }

    #[test]
    fn incremental_push_peak_is_one_chunk() {
        let payload = vec![b'x'; 50_000];
        let framed = frame_aws_chunked_unsigned(&payload, 1024);
        let full = decode_aws_chunked(&framed, Some(payload.len() as u64), None)
            .unwrap()
            .data;
        let mut dec = AwsChunkedDecoder::new(Some(payload.len() as u64), None);
        let mut out = Vec::new();
        let mut peak = 0usize;
        for piece in framed.chunks(19) {
            out.extend(dec.push(piece).unwrap());
            peak = peak.max(dec.buffered_wire_bytes());
        }
        out.extend(dec.finish_payload().unwrap());
        assert_eq!(out, full);
        assert!(
            peak <= 1024 + 128,
            "decoder window must be O(chunk) not O(object): peak={peak}"
        );
    }

    #[test]
    fn dechunk_unsigned_single_chunk() {
        let payload = b"abcdefghij";
        let framed = b"a\r\nabcdefghij\r\n0\r\n\r\n";
        let decoded = decode_aws_chunked(framed, Some(10), None).unwrap();
        assert_eq!(decoded.data, payload);
    }

    #[test]
    fn dechunk_with_trailer() {
        // STREAMING-UNSIGNED-PAYLOAD-TRAILER style
        let mut framed = Vec::new();
        framed.extend_from_slice(b"5\r\nhello\r\n");
        framed.extend_from_slice(b"0\r\n");
        framed.extend_from_slice(b"x-amz-checksum-crc32:AAAAAA==\r\n");
        framed.extend_from_slice(b"\r\n");
        let decoded = decode_aws_chunked(&framed, Some(5), None).unwrap();
        assert_eq!(decoded.data, b"hello");
        assert_eq!(
            decoded
                .trailers
                .get("x-amz-checksum-crc32")
                .map(String::as_str),
            Some("AAAAAA==")
        );
    }

    #[test]
    fn dechunk_python_hmac_vector_without_verify() {
        // From test_s3request.py — 25-byte payload in 10+10+5 chunks with sigs.
        let body = b"a;chunk-signature=4a397f01db2cd700402dc38931b462e789ae49911d\
c229d93c9f9c46fd3e0b21\r\nabcdefghij\r\n\
a;chunk-signature=49177768ee3e9b77c6353ab9f3b9747d188adc11d4\
5b38be94a130616e6d64dc\r\nklmnopqrst\r\n\
5;chunk-signature=c884ebbca35b923cf864854e2a906aa8f5895a7140\
6c73cc6d4ee057527a8c23\r\nuvwz\n\r\n\
0;chunk-signature=50f7c470d6bf6c59126eecc2cb020d532a69c92322\
ddfbbd21811de45491022c\r\n\r\n";
        let decoded = decode_aws_chunked(body, Some(25), None).unwrap();
        assert_eq!(decoded.data, b"abcdefghijklmnopqrstuvwz\n");
    }

    fn test_ctx(require_trailer: bool) -> ChunkSigContext {
        ChunkSigContext {
            secret_key: "secret".into(),
            date: "20220330".into(),
            region: "us-east-1".into(),
            service: "s3".into(),
            amz_date: "20220330T095351Z".into(),
            seed_signature: "aa1b67fc5bc4503d05a636e6e740dcb757d3aa2352f32e7493f261f71acbe1d5"
                .into(),
            require_trailer_signature: require_trailer,
        }
    }

    #[test]
    fn dechunk_python_hmac_vector_with_verify() {
        let body = b"a;chunk-signature=4a397f01db2cd700402dc38931b462e789ae49911d\
c229d93c9f9c46fd3e0b21\r\nabcdefghij\r\n\
a;chunk-signature=49177768ee3e9b77c6353ab9f3b9747d188adc11d4\
5b38be94a130616e6d64dc\r\nklmnopqrst\r\n\
5;chunk-signature=c884ebbca35b923cf864854e2a906aa8f5895a7140\
6c73cc6d4ee057527a8c23\r\nuvwz\n\r\n\
0;chunk-signature=50f7c470d6bf6c59126eecc2cb020d532a69c92322\
ddfbbd21811de45491022c\r\n\r\n";
        let ctx = test_ctx(false);
        let decoded = decode_aws_chunked(body, Some(25), Some(&ctx)).unwrap();
        assert_eq!(decoded.data, b"abcdefghijklmnopqrstuvwz\n");
        assert_eq!(decoded.chunk_signatures_valid, Some(true));
        assert_eq!(decoded.trailer_signature_valid, None);
    }

    #[test]
    fn dechunk_bad_chunk_signature_errors() {
        let body = b"a;chunk-signature=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdead\
beefdeadbeefdeadbeefde\r\nabcdefghij\r\n0;chunk-signature=00\
00000000000000000000000000000000000000000000000000000000000000\r\n\r\n";
        let ctx = test_ctx(false);
        let err = decode_aws_chunked(body, Some(10), Some(&ctx)).unwrap_err();
        assert_eq!(err, AwsChunkedError::InvalidChunkSignature);
    }

    #[test]
    fn dechunk_missing_chunk_signature_in_signed_mode_errors() {
        let framed = frame_aws_chunked_unsigned(b"hello", 5);
        let ctx = test_ctx(false);
        let err = decode_aws_chunked(&framed, Some(5), Some(&ctx)).unwrap_err();
        assert_eq!(err, AwsChunkedError::InvalidChunkSignature);
    }

    /// Build signed body with trailers + valid x-amz-trailer-signature.
    fn frame_signed_with_trailer(
        payload: &[u8],
        trailers: &[(&str, &str)],
        require_trailer: bool,
        bad_trailer_sig: bool,
    ) -> (Vec<u8>, ChunkSigContext) {
        let ctx = test_ctx(require_trailer);
        let mut out = Vec::new();
        let mut prev = ctx.seed_signature.clone();
        let data_hash = sha256_hex(payload);
        let sig = compute_chunk_signature(&ctx, &prev, &data_hash);
        out.extend_from_slice(format!("{:x};chunk-signature={sig}\r\n", payload.len()).as_bytes());
        out.extend_from_slice(payload);
        out.extend_from_slice(b"\r\n");
        prev = sig;
        let sig0 = compute_chunk_signature(&ctx, &prev, EMPTY_SHA256);
        out.extend_from_slice(format!("0;chunk-signature={sig0}\r\n").as_bytes());
        prev = sig0;

        let mut trailer_map = HashMap::new();
        for (k, v) in trailers {
            trailer_map.insert(k.to_ascii_lowercase(), (*v).to_string());
            out.extend_from_slice(format!("{k}:{v}\r\n").as_bytes());
        }
        let trailer_sig = if bad_trailer_sig {
            "deadbeef".repeat(8)
        } else {
            compute_trailer_signature(&ctx, &prev, &trailer_map)
        };
        out.extend_from_slice(format!("x-amz-trailer-signature:{trailer_sig}\r\n").as_bytes());
        out.extend_from_slice(b"\r\n");
        (out, ctx)
    }

    #[test]
    fn dechunk_signed_trailer_signature_ok() {
        let payload = b"trailer-payload";
        let (framed, ctx) = frame_signed_with_trailer(
            payload,
            &[("x-amz-checksum-crc32", "AAAAAA==")],
            true,
            false,
        );
        let decoded = decode_aws_chunked(&framed, Some(payload.len() as u64), Some(&ctx)).unwrap();
        assert_eq!(decoded.data, payload);
        assert_eq!(decoded.chunk_signatures_valid, Some(true));
        assert_eq!(decoded.trailer_signature_valid, Some(true));
        assert_eq!(
            decoded
                .trailers
                .get("x-amz-checksum-crc32")
                .map(String::as_str),
            Some("AAAAAA==")
        );
        assert!(decoded.trailers.contains_key("x-amz-trailer-signature"));
    }

    #[test]
    fn dechunk_bad_trailer_signature_errors() {
        let payload = b"trailer-payload";
        let (framed, ctx) =
            frame_signed_with_trailer(payload, &[("x-amz-checksum-crc32", "AAAAAA==")], true, true);
        let err = decode_aws_chunked(&framed, Some(payload.len() as u64), Some(&ctx)).unwrap_err();
        assert_eq!(err, AwsChunkedError::InvalidTrailerSignature);
    }

    #[test]
    fn dechunk_trailer_mode_missing_trailer_sig_errors() {
        // PAYLOAD-TRAILER with content trailers but no x-amz-trailer-signature.
        let ctx = test_ctx(true);
        let mut out = Vec::new();
        let mut prev = ctx.seed_signature.clone();
        let payload = b"hello";
        let data_hash = sha256_hex(payload);
        let sig = compute_chunk_signature(&ctx, &prev, &data_hash);
        out.extend_from_slice(format!("{:x};chunk-signature={sig}\r\n", payload.len()).as_bytes());
        out.extend_from_slice(payload);
        out.extend_from_slice(b"\r\n");
        prev = sig;
        let sig0 = compute_chunk_signature(&ctx, &prev, EMPTY_SHA256);
        out.extend_from_slice(format!("0;chunk-signature={sig0}\r\n").as_bytes());
        out.extend_from_slice(b"x-amz-checksum-crc32:AAAAAA==\r\n\r\n");
        let err = decode_aws_chunked(&out, Some(5), Some(&ctx)).unwrap_err();
        assert_eq!(err, AwsChunkedError::InvalidTrailerSignature);
    }

    #[test]
    fn dechunk_unsigned_trailer_still_ok() {
        // STREAMING-UNSIGNED-PAYLOAD-TRAILER: no sig_ctx, trailers accepted.
        let mut framed = Vec::new();
        framed.extend_from_slice(b"5\r\nhello\r\n");
        framed.extend_from_slice(b"0\r\n");
        framed.extend_from_slice(b"x-amz-checksum-crc32:AAAAAA==\r\n");
        framed.extend_from_slice(b"\r\n");
        let decoded = decode_aws_chunked(&framed, Some(5), None).unwrap();
        assert_eq!(decoded.data, b"hello");
        assert_eq!(decoded.trailer_signature_valid, None);
        assert_eq!(
            decoded
                .trailers
                .get("x-amz-checksum-crc32")
                .map(String::as_str),
            Some("AAAAAA==")
        );
    }

    #[test]
    fn aws_doc_trailer_hash_vector() {
        // AWS docs: hash('x-amz-checksum-crc32c:sOO8/Q==\n') =
        // 1e376db7e1a34a8ef1c4bcee131a2d60a1cb62503747488624e10995f448d774
        let mut trailers = HashMap::new();
        trailers.insert("x-amz-checksum-crc32c".into(), "sOO8/Q==".into());
        let canon = canonical_trailer_bytes(&trailers);
        assert_eq!(canon, b"x-amz-checksum-crc32c:sOO8/Q==\n");
        assert_eq!(
            sha256_hex(&canon),
            "1e376db7e1a34a8ef1c4bcee131a2d60a1cb62503747488624e10995f448d774"
        );
    }

    #[test]
    fn size_mismatch_errors() {
        let framed = frame_aws_chunked_unsigned(b"hello", 5);
        let err = decode_aws_chunked(&framed, Some(3), None).unwrap_err();
        assert!(matches!(err, AwsChunkedError::SizeMismatch { .. }));
    }

    #[test]
    fn cleanup_strips_aws_chunked_token() {
        let mut h = HeaderKeyDict::new();
        h.set("Content-Encoding", "aws-chunked");
        cleanup_content_encoding(&mut h);
        assert!(h.get("Content-Encoding").is_none());

        let mut h = HeaderKeyDict::new();
        h.set("Content-Encoding", "aws-chunked, gzip");
        cleanup_content_encoding(&mut h);
        assert_eq!(h.get("Content-Encoding"), Some("gzip"));
    }

    #[test]
    fn is_aws_chunked_requires_streaming_hash() {
        let mut headers = HeaderKeyDict::new();
        headers.set("X-Amz-Content-SHA256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER");
        let req = Request {
            method: "PUT".into(),
            path: "/b/o".into(),
            query_string: String::new(),
            headers,
            body: swift_http::Body::empty(),
        };
        assert!(is_aws_chunked_request(&req));

        let mut headers = HeaderKeyDict::new();
        headers.set("Content-Encoding", "aws-chunked");
        let req = Request {
            method: "PUT".into(),
            path: "/b/o".into(),
            query_string: String::new(),
            headers,
            body: swift_http::Body::empty(),
        };
        assert!(!is_aws_chunked_request(&req));

        let mut headers = HeaderKeyDict::new();
        headers.set("Content-Encoding", "aws-chunked");
        headers.set("X-Amz-Content-SHA256", "UNSIGNED-PAYLOAD");
        let req = Request {
            method: "PUT".into(),
            path: "/b/o".into(),
            query_string: String::new(),
            headers,
            body: swift_http::Body::empty(),
        };
        assert!(!is_aws_chunked_request(&req));
    }
}
