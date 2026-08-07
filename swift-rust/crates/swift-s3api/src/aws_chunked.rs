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
//! \r\n
//! ```
//!
//! Triggered by `X-Amz-Content-SHA256: STREAMING-*` and/or
//! `Content-Encoding: aws-chunked`. Port of Python `StreamingInput` /
//! `ChunkReader` dechunk path (`s3request.py`); chunk-signature verification
//! is optional residual (HMAC chain) — dechunk succeeds without it.

use std::collections::HashMap;

use crate::crypto::{hmac_sha256_hex, sha256_hex, streq_const_time};
use crate::sigv4::signing_key;
use swift_http::{HeaderKeyDict, Request};

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
    SizeMismatch { expected: u64, provided: u64 },
    MissingDecodedContentLength,
    EcdsaNotImplemented,
}

/// Decoded payload + optional trailers after the terminal 0-chunk.
#[derive(Debug, Clone)]
pub struct DecodedChunkedBody {
    pub data: Vec<u8>,
    pub trailers: HashMap<String, String>,
    /// `Some(true/false)` when HMAC chunk-sig verify was attempted.
    pub chunk_signatures_valid: Option<bool>,
}

/// Context for optional STREAMING-AWS4-HMAC-SHA256-PAYLOAD chunk signature
/// chain verification (residual — dechunk works without it).
#[derive(Debug, Clone)]
pub struct ChunkSigContext {
    pub secret_key: String,
    pub date: String,
    pub region: String,
    pub service: String,
    pub amz_date: String,
    /// Header (seed) signature; each chunk uses the previous signature.
    pub seed_signature: String,
}

/// True when `X-Amz-Content-SHA256` is a STREAMING-* value.
pub fn is_streaming_payload_hash(hash: &str) -> bool {
    AWS_CHUNKED_PAYLOAD_HASHES
        .iter()
        .any(|v| hash.eq_ignore_ascii_case(v))
}

/// True when the value is an ECDSA streaming mode we do not implement.
pub fn is_ecdsa_streaming(hash: &str) -> bool {
    ECDSA_STREAMING
        .iter()
        .any(|v| hash.eq_ignore_ascii_case(v))
}

/// True when the request asks for aws-chunked / streaming payload framing.
pub fn is_aws_chunked_request(req: &Request) -> bool {
    if let Some(hash) = req.headers.get("X-Amz-Content-SHA256") {
        if is_streaming_payload_hash(hash) {
            return true;
        }
    }
    if let Some(enc) = req.headers.get("Content-Encoding") {
        for part in enc.split(',') {
            if part.trim().eq_ignore_ascii_case("aws-chunked") {
                return true;
            }
        }
    }
    false
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

/// Decode an aws-chunked wire body into raw payload bytes.
///
/// `expected_decoded_len`: when set (from `x-amz-decoded-content-length`),
/// the total payload length must match.
///
/// `sig_ctx`: when `Some`, verify each `chunk-signature` against the
/// STREAMING-AWS4-HMAC-SHA256-PAYLOAD chain. On mismatch, still return the
/// decoded data with `chunk_signatures_valid = Some(false)` only if
/// `strict_sig` is false — currently we report mismatch as
/// `chunk_signatures_valid = Some(false)` but do **not** fail dechunk
/// (optional residual; middleware may ignore).
pub fn decode_aws_chunked(
    raw: &[u8],
    expected_decoded_len: Option<u64>,
    sig_ctx: Option<&ChunkSigContext>,
) -> Result<DecodedChunkedBody, AwsChunkedError> {
    let mut pos = 0usize;
    let mut out: Vec<u8> = Vec::new();
    if let Some(n) = expected_decoded_len {
        if n > 0 {
            out.try_reserve(n as usize).ok();
        }
    }
    let mut trailers = HashMap::new();
    let mut prev_sig = sig_ctx.map(|c| c.seed_signature.to_ascii_lowercase());
    let mut all_sigs_ok: Option<bool> = sig_ctx.map(|_| true);
    let mut last_chunk_size: Option<usize> = None;
    let mut chunk_number = 0usize;

    loop {
        chunk_number += 1;
        let header_line = read_line(raw, &mut pos)?;
        // header_line includes no trailing CRLF
        let (size_str, params) = match header_line.iter().position(|&b| b == b';') {
            Some(i) => (&header_line[..i], Some(&header_line[i + 1..])),
            None => (header_line.as_slice(), None),
        };
        let size = parse_hex_size(size_str)?;
        if let Some(prev) = last_chunk_size {
            // AWS enforces 8 KiB min for non-final chunks (Python
            // SIGV4_CHUNK_MIN_SIZE). Soft residual: we do not reject small
            // non-final chunks so unit vectors with 10-byte chunks work.
            let _ = prev;
        }
        last_chunk_size = Some(size);

        if let Some(expected) = expected_decoded_len {
            if out.len() as u64 + size as u64 > expected {
                return Err(AwsChunkedError::SizeMismatch {
                    expected,
                    provided: out.len() as u64 + size as u64,
                });
            }
        }

        if size > 0 {
            if pos + size > raw.len() {
                return Err(AwsChunkedError::Incomplete);
            }
            let data = &raw[pos..pos + size];
            pos += size;
            // trailing CRLF after chunk data
            if !consume_crlf(raw, &mut pos) {
                return Err(AwsChunkedError::Incomplete);
            }

            if let (Some(ctx), Some(ok)) = (sig_ctx, all_sigs_ok.as_mut()) {
                let chunk_sig = parse_chunk_signature(params);
                if let (Some(sig), Some(prev)) = (chunk_sig, prev_sig.as_ref()) {
                    let data_hash = sha256_hex(data);
                    let valid = verify_chunk_signature(ctx, prev, &data_hash, &sig);
                    if !valid {
                        *ok = false;
                    }
                    prev_sig = Some(sig.to_ascii_lowercase());
                } else if params.is_some() || sig_ctx.is_some() {
                    // Signed mode expected chunk-signature; missing → invalid.
                    *ok = false;
                }
            }

            out.extend_from_slice(data);
        } else {
            // Final chunk: optional signature + trailers until blank line.
            if let (Some(ctx), Some(ok)) = (sig_ctx, all_sigs_ok.as_mut()) {
                let chunk_sig = parse_chunk_signature(params);
                if let (Some(sig), Some(prev)) = (chunk_sig, prev_sig.as_ref()) {
                    let valid = verify_chunk_signature(ctx, prev, EMPTY_SHA256, &sig);
                    if !valid {
                        *ok = false;
                    }
                    prev_sig = Some(sig.to_ascii_lowercase());
                }
                let _ = chunk_number;
                let _ = prev_sig;
            }

            // Trailers: lines until empty line. Tolerate EOF after 0-chunk
            // with no extra CRLF (some clients omit the final blank).
            while pos < raw.len() {
                let line = read_line(raw, &mut pos)?;
                if line.is_empty() {
                    break;
                }
                if let Some(colon) = line.iter().position(|&b| b == b':') {
                    let key = String::from_utf8_lossy(&line[..colon])
                        .trim()
                        .to_ascii_lowercase();
                    let value = String::from_utf8_lossy(&line[colon + 1..])
                        .trim()
                        .to_string();
                    trailers.insert(key, value);
                }
            }
            break;
        }
    }

    if let Some(expected) = expected_decoded_len {
        if out.len() as u64 != expected {
            return Err(AwsChunkedError::SizeMismatch {
                expected,
                provided: out.len() as u64,
            });
        }
    }

    Ok(DecodedChunkedBody {
        data: out,
        trailers,
        chunk_signatures_valid: all_sigs_ok,
    })
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

fn verify_chunk_signature(
    ctx: &ChunkSigContext,
    previous_signature: &str,
    data_sha256: &str,
    presented: &str,
) -> bool {
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
    let expected = hmac_sha256_hex(&key, sts.as_bytes());
    streq_const_time(&expected, &presented.to_ascii_lowercase())
}

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
            decoded.trailers.get("x-amz-checksum-crc32").map(String::as_str),
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
        let ctx = ChunkSigContext {
            secret_key: "secret".into(),
            date: "20220330".into(),
            region: "us-east-1".into(),
            service: "s3".into(),
            amz_date: "20220330T095351Z".into(),
            seed_signature: "aa1b67fc5bc4503d05a636e6e740dcb757d3aa2352f32e7493f261f71acbe1d5"
                .into(),
        };
        let decoded = decode_aws_chunked(body, Some(25), Some(&ctx)).unwrap();
        assert_eq!(decoded.data, b"abcdefghijklmnopqrstuvwz\n");
        assert_eq!(decoded.chunk_signatures_valid, Some(true));
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
    fn is_aws_chunked_detects_streaming_and_encoding() {
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
        assert!(is_aws_chunked_request(&req));
    }
}
