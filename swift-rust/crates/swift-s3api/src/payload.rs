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

//! Python `s3request.HashingInput` / `check_md5` / checksum-header parity.
//!
//! After signature verify (or, for V2 STREAMING-*, instead of aws-chunked
//! decode): SHA256 mismatch trumps BadDigest; malformed Content-MD5 is
//! InvalidDigest; V2 (and V4 query) STREAMING-* reads the raw body and
//! raises `XAmzContentSHA256Mismatch`.

use std::io;
use std::sync::{Arc, Mutex};

use sha1::{Digest, Sha1};
use sha2::Sha256;
use swift_http::{BodyTransform, Request, Response, MAX_CONTROL_BODY};

use crate::aws_chunked::is_streaming_payload_hash;
use crate::crypto::{hex_encode, md5, sha256_hex, Md5Hasher};
use crate::response::s3_error_response;
use crate::sigv2::base64_encode;
use crate::sigv4::parse_sigv4_auth;

const INVALID_SHA256_MSG: &str = "x-amz-content-sha256 must be UNSIGNED-PAYLOAD, \
STREAMING-UNSIGNED-PAYLOAD-TRAILER, STREAMING-AWS4-HMAC-SHA256-PAYLOAD, \
STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER or a valid sha256 value.";

const MISSING_SHA256_MSG: &str = "Missing required header for this request: x-amz-content-sha256";

const MISSING_MD5_OR_CHECKSUM_MSG: &str =
    "Missing required header for this request: Content-MD5 OR x-amz-checksum-*";

/// Python `_header_strip`: drop leading/trailing bytes `<= 0x20`.
pub fn header_strip(value: &str) -> Option<&str> {
    let trimmed = value.trim_matches(|c: char| (c as u32) <= 0x20);
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

pub fn looks_like_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

pub fn is_v4_header_auth(req: &Request) -> bool {
    parse_sigv4_auth(req).is_some_and(|a| !a.query_auth)
}

pub fn is_v4_query_auth(req: &Request) -> bool {
    parse_sigv4_auth(req).is_some_and(|a| a.query_auth)
}

fn header_ci<'a>(req: &'a Request, name: &str) -> Option<&'a str> {
    req.headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v)
}

fn content_md5_raw(req: &Request) -> Option<&str> {
    // Present empty Content-MD5 must stay Some("") so InvalidDigest fires.
    // header_strip("") is None and would skip the check.
    let raw = header_ci(req, "content-md5")?;
    Some(header_strip(raw).unwrap_or(""))
}

/// Standard base64 decode; `None` on alphabet/padding errors.
pub fn decode_base64(raw: &str) -> Option<Vec<u8>> {
    let b = raw.as_bytes();
    let mut i = 0;
    let mut acc = 0u32;
    let mut n = 0u32;
    let mut buf = Vec::with_capacity(raw.len() / 4 * 3 + 3);
    let mut saw_pad = false;
    while i < b.len() {
        let c = b[i];
        i += 1;
        if c == b'=' {
            saw_pad = true;
            continue;
        }
        if saw_pad {
            return None;
        }
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32;
        acc = (acc << 6) | v;
        n += 1;
        if n == 4 {
            buf.push((acc >> 16) as u8);
            buf.push((acc >> 8) as u8);
            buf.push(acc as u8);
            acc = 0;
            n = 0;
        }
    }
    if n == 2 {
        buf.push((acc >> 4) as u8);
    } else if n == 3 {
        buf.push((acc >> 10) as u8);
        buf.push((acc >> 2) as u8);
    } else if n == 1 {
        return None;
    }
    Some(buf)
}

pub fn content_md5_decoded_len(raw: &str) -> Option<usize> {
    if !raw
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/' || c == b'=')
    {
        return None;
    }
    if !raw.bytes().any(|c| c != b'=') {
        return None;
    }
    decode_base64(raw).map(|v| v.len())
}

fn decode_content_md5(raw: &str) -> Option<Vec<u8>> {
    let bytes = decode_base64(raw)?;
    if bytes.len() == 16 {
        Some(bytes)
    } else {
        None
    }
}

pub fn sha256_mismatch_response(client: &str, computed: &str) -> Response {
    s3_error_response(
        "XAmzContentSHA256Mismatch",
        None,
        &[
            ("ClientComputedContentSHA256", client),
            ("S3ComputedContentSHA256", computed),
        ],
    )
}

pub fn invalid_digest_response() -> Response {
    s3_error_response("InvalidDigest", None, &[])
}

/// Object PUT: ExpectedDigest is hex(Content-MD5). XML POST: base64.
pub fn bad_digest_response(content_md5: &str, expected_hex: bool) -> Response {
    let expected = if expected_hex {
        match decode_base64(content_md5) {
            Some(raw) => hex_encode(&raw),
            None => content_md5.to_string(),
        }
    } else {
        content_md5.to_string()
    };
    s3_error_response("BadDigest", None, &[("ExpectedDigest", expected.as_str())])
}

fn invalid_sha256_argument(value: &str) -> Response {
    s3_error_response(
        "InvalidArgument",
        Some(INVALID_SHA256_MSG),
        &[
            ("ArgumentName", "x-amz-content-sha256"),
            ("ArgumentValue", value),
        ],
    )
}

fn missing_sha256_response() -> Response {
    s3_error_response("InvalidRequest", Some(MISSING_SHA256_MSG), &[])
}

fn missing_md5_or_checksum_response() -> Response {
    s3_error_response("InvalidRequest", Some(MISSING_MD5_OR_CHECKSUM_MSG), &[])
}

/// Python `UploadsController.POST` pops Content-MD5 / ETag before writing the
/// empty upload marker. `check_md5` is not called on Initiate.
fn is_initiate_multipart(req: &Request) -> bool {
    if req.method != "POST" {
        return false;
    }
    let params = req.params();
    params.iter().any(|(k, _)| k == "uploads") && !params.iter().any(|(k, _)| k == "uploadId")
}

fn is_multi_delete_post(req: &Request) -> bool {
    req.method == "POST" && req.params().iter().any(|(k, _)| k == "delete")
}

/// Python `MultiObjectDeleteController`:
/// `min(2 * max_multi_delete_objects * MAX_OBJECT_NAME_LENGTH, 10 MiB)`.
const MAX_MULTI_DELETE_BODY: u64 = 2 * 1000 * 1024;

/// Python `s3request._validate_sha256` + HashingInput + check_md5 for a
/// materialized request. `v4_header_auth` is SigV4 *header* (not query).
pub fn validate_s3_payload(req: &mut Request, v4_header_auth: bool) -> Option<Response> {
    if let Some(resp) = validate_sha256_header(req, v4_header_auth) {
        return Some(resp);
    }
    if let Some(resp) = invalid_content_md5_response(req) {
        return Some(resp);
    }
    if let Some(resp) = validate_checksum_headers(req) {
        return Some(resp);
    }
    if !matches!(req.method.as_str(), "PUT" | "POST") {
        return None;
    }
    let aws_sha256 = header_ci(req, "x-amz-content-sha256").map(str::to_string);
    let v2_or_v4_query_streaming = aws_sha256.as_deref().is_some_and(is_streaming_payload_hash)
        && (!v4_header_auth || is_v4_query_auth(req));
    if v2_or_v4_query_streaming {
        return Some(v2_streaming_raw_mismatch(
            req,
            aws_sha256.as_deref().unwrap(),
        ));
    }
    if let Some(resp) = require_md5_for_multi_delete(req) {
        return Some(resp);
    }
    if is_multi_delete_post(req) {
        let cl = header_ci(req, "content-length")
            .and_then(|s| s.parse::<u64>().ok())
            .or_else(|| req.body.content_length());
        if cl.is_some_and(|n| n > MAX_MULTI_DELETE_BODY) {
            return Some(s3_error_response("MalformedXML", None, &[]));
        }
    }
    let cap = if is_multi_delete_post(req) {
        MAX_MULTI_DELETE_BODY
    } else {
        MAX_CONTROL_BODY
    };
    let body = match req.body.materialize(cap) {
        Ok(b) => b.to_vec(),
        Err(_) => {
            if is_multi_delete_post(req) {
                return Some(s3_error_response("MalformedXML", None, &[]));
            }
            return Some(s3_error_response("IncompleteBody", None, &[]));
        }
    };
    if let Some(expected) = aws_sha256.as_deref() {
        if expected != "UNSIGNED-PAYLOAD"
            && !is_streaming_payload_hash(expected)
            && header_ci(req, "content-length").is_some()
        {
            let computed = sha256_hex(&body);
            if computed != expected.to_ascii_lowercase() {
                return Some(sha256_mismatch_response(expected, &computed));
            }
        }
    }
    if checksum_should_verify(req) {
        if let Some(resp) = check_checksum_body(req, &body) {
            return Some(resp);
        }
    }
    // Python `S3Request.check_md5` is invoked by Complete MPU and MultiDelete
    // only. Initiate Multipart Upload (`POST ?uploads`) accepts a Content-MD5
    // header (format-checked above) and then drops it.
    if let Some(raw) = content_md5_raw(req) {
        if !is_initiate_multipart(req) {
            let got = md5(&body);
            if let Some(want) = decode_content_md5(raw) {
                if got.as_slice() != want.as_slice() {
                    let expected_hex = req.method == "PUT";
                    return Some(bad_digest_response(raw, expected_hex));
                }
                if req.method == "PUT" {
                    req.headers.set("ETag", hex_encode(&want));
                }
            }
        }
    }
    None
}

/// Header-only checks for the streaming PUT path (body hashed incrementally).
/// Python `_validate_headers`: Content-Length present and negative/non-int
/// is InvalidArgument 400.
fn invalid_content_length_header(req: &Request) -> Option<Response> {
    let raw = header_ci(req, "content-length")?;
    match raw.parse::<i64>() {
        Ok(n) if n < 0 => {}
        Ok(_) => return None,
        Err(_) => {}
    }
    Some(s3_error_response(
        "InvalidArgument",
        Some("Content-Length"),
        &[("ArgumentName", "Content-Length"), ("ArgumentValue", raw)],
    ))
}

pub fn validate_s3_payload_headers(req: &Request, v4_header_auth: bool) -> Option<Response> {
    if let Some(resp) = invalid_content_length_header(req) {
        return Some(resp);
    }
    if let Some(resp) = validate_sha256_header(req, v4_header_auth) {
        return Some(resp);
    }
    if let Some(resp) = invalid_content_md5_response(req) {
        return Some(resp);
    }
    validate_checksum_headers(req)
}

pub fn apply_content_md5_etag(req: &mut Request) {
    if let Some(raw) = content_md5_raw(req) {
        if let Some(bytes) = decode_content_md5(raw) {
            req.headers.set("ETag", hex_encode(&bytes));
        }
    }
}

pub fn invalid_content_md5_response(req: &Request) -> Option<Response> {
    if !matches!(req.method.as_str(), "PUT" | "POST") {
        return None;
    }
    let raw = content_md5_raw(req)?;
    if content_md5_decoded_len(raw) != Some(16) {
        return Some(invalid_digest_response());
    }
    None
}

fn validate_sha256_header(req: &Request, v4_header_auth: bool) -> Option<Response> {
    let raw = header_ci(req, "x-amz-content-sha256").map(str::trim);
    match raw {
        None | Some("") => {
            if v4_header_auth {
                Some(missing_sha256_response())
            } else {
                None
            }
        }
        Some("UNSIGNED-PAYLOAD") => None,
        Some(v) if is_streaming_payload_hash(v) => {
            if v4_header_auth && !is_v4_query_auth(req) {
                // Header V4 STREAMING: aws-chunked decode path.
                let decoded = header_ci(req, "x-amz-decoded-content-length");
                match decoded.and_then(|s| s.parse::<i64>().ok()) {
                    None => Some(s3_error_response(
                        "MissingContentLength",
                        Some("You must provide the Content-Length HTTP header."),
                        &[],
                    )),
                    Some(n) if n < 0 => Some(s3_error_response(
                        "InvalidArgument",
                        None,
                        &[
                            ("ArgumentName", "x-amz-decoded-content-length"),
                            ("ArgumentValue", decoded.unwrap_or("")),
                        ],
                    )),
                    Some(_) => None,
                }
            } else {
                None
            }
        }
        Some(v) if looks_like_sha256(v) => None,
        Some(v) if v4_header_auth => Some(invalid_sha256_argument(v)),
        Some(_) => None,
    }
}

fn v2_streaming_raw_mismatch(req: &mut Request, aws_sha256: &str) -> Response {
    let decoded_raw = header_ci(req, "x-amz-decoded-content-length");
    let decoded = match decoded_raw.and_then(|s| s.parse::<i64>().ok()) {
        None => {
            return s3_error_response(
                "MissingContentLength",
                Some("You must provide the Content-Length HTTP header."),
                &[],
            );
        }
        Some(n) if n < 0 => {
            return s3_error_response(
                "InvalidArgument",
                None,
                &[
                    ("ArgumentName", "x-amz-decoded-content-length"),
                    ("ArgumentValue", decoded_raw.unwrap_or("")),
                ],
            );
        }
        Some(n) => n as u64,
    };
    let content_length = req
        .headers
        .get("Content-Length")
        .and_then(|s| s.parse::<u64>().ok())
        .or_else(|| req.body.content_length())
        .unwrap_or(0);
    if decoded < content_length {
        return s3_error_response(
            "IncompleteBody",
            None,
            &[
                ("NumberBytesExpected", &decoded.to_string()),
                ("NumberBytesProvided", &content_length.to_string()),
            ],
        );
    }
    let body = match req.body.materialize(MAX_CONTROL_BODY) {
        Ok(b) => b.to_vec(),
        Err(_) => return s3_error_response("IncompleteBody", None, &[]),
    };
    let computed = sha256_hex(&body);
    sha256_mismatch_response(aws_sha256, &computed)
}

fn require_md5_for_multi_delete(req: &Request) -> Option<Response> {
    if req.method != "POST" {
        return None;
    }
    let is_delete = req.params().iter().any(|(k, _)| k == "delete");
    if !is_delete {
        return None;
    }
    if content_md5_raw(req).is_some() {
        return None;
    }
    if req.headers.iter().any(|(k, _)| {
        let l = k.to_ascii_lowercase();
        l.starts_with("x-amz-checksum-")
            && l != "x-amz-checksum-algorithm"
            && l != "x-amz-checksum-type"
    }) {
        return None;
    }
    Some(missing_md5_or_checksum_response())
}

fn checksum_should_verify(req: &Request) -> bool {
    match req.method.as_str() {
        "PUT" => true,
        "POST" => req.params().iter().any(|(k, _)| k == "delete"),
        _ => false,
    }
}

struct ChecksumSpec {
    header: String,
    algo: &'static str,
    digest_size: usize,
}

fn checksum_headers(req: &Request) -> Vec<(String, String)> {
    req.headers
        .iter()
        .filter_map(|(k, v)| {
            let l = k.to_ascii_lowercase();
            if l.starts_with("x-amz-checksum-")
                && l != "x-amz-checksum-algorithm"
                && l != "x-amz-checksum-type"
            {
                Some((l, v.to_string()))
            } else {
                None
            }
        })
        .collect()
}

fn checksum_spec(header: &str) -> Result<ChecksumSpec, ChecksumHeaderErr> {
    match header {
        "x-amz-checksum-crc32" => Ok(ChecksumSpec {
            header: header.to_string(),
            algo: "CRC32",
            digest_size: 4,
        }),
        "x-amz-checksum-sha1" => Ok(ChecksumSpec {
            header: header.to_string(),
            algo: "SHA1",
            digest_size: 20,
        }),
        "x-amz-checksum-sha256" => Ok(ChecksumSpec {
            header: header.to_string(),
            algo: "SHA256",
            digest_size: 32,
        }),
        "x-amz-checksum-crc32c" => Ok(ChecksumSpec {
            header: header.to_string(),
            algo: "CRC32C",
            digest_size: 4,
        }),
        "x-amz-checksum-crc64nvme" => Err(ChecksumHeaderErr::NotImplemented(header.to_string())),
        _ => Err(ChecksumHeaderErr::InvalidAlgorithm),
    }
}

enum ChecksumHeaderErr {
    InvalidAlgorithm,
    NotImplemented(String),
    Cardinality { headers_and_trailer: bool },
    InvalidValue(String),
    AlgoMismatch,
    DeclaredWithoutHeader,
    TrailerNotStreaming,
    TrailerUnsupported,
}

fn validate_checksum_headers(req: &Request) -> Option<Response> {
    if !matches!(req.method.as_str(), "PUT" | "POST") {
        return None;
    }
    match collect_checksum(req) {
        Ok(_) => None,
        Err(e) => Some(checksum_err_response(e)),
    }
}

fn collect_checksum(req: &Request) -> Result<Option<(ChecksumSpec, String)>, ChecksumHeaderErr> {
    let headers = checksum_headers(req);
    let trailer_raw = header_ci(req, "x-amz-trailer").unwrap_or("").trim();
    let trailers: Vec<&str> = if trailer_raw.is_empty() {
        Vec::new()
    } else {
        trailer_raw
            .trim_end_matches(',')
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect()
    };
    if trailers.iter().any(|h| {
        checksum_spec(&h.to_ascii_lowercase()).is_err() && !h.starts_with("x-amz-checksum-")
    }) {
        // Python: trailer name not in CHECKSUMS_BY_HEADER → InvalidRequest
        // "The value specified in the x-amz-trailer header is not supported"
        if !trailers.iter().all(|h| {
            let l = h.to_ascii_lowercase();
            l.starts_with("x-amz-checksum-")
        }) {
            return Err(ChecksumHeaderErr::TrailerUnsupported);
        }
    }
    for t in &trailers {
        if checksum_spec(&t.to_ascii_lowercase()).is_err() {
            let l = t.to_ascii_lowercase();
            if l.starts_with("x-amz-checksum-") {
                match checksum_spec(&l) {
                    Err(ChecksumHeaderErr::NotImplemented(_)) => {}
                    Err(ChecksumHeaderErr::InvalidAlgorithm) => {
                        return Err(ChecksumHeaderErr::TrailerUnsupported);
                    }
                    _ => {}
                }
            } else {
                return Err(ChecksumHeaderErr::TrailerUnsupported);
            }
        }
    }
    // Python: trailer list and header dict are cardinality-checked
    // separately (`headers_and_trailer=False` → "Multiple checksum Types"),
    // then the sum is checked with `headers_and_trailer=True` (short
    // message). Duplicate trailers therefore get the long message, while
    // exactly one header plus one trailer gets the short one.
    if trailers.len() > 1 {
        return Err(ChecksumHeaderErr::Cardinality {
            headers_and_trailer: false,
        });
    }
    if headers.len() > 1 {
        return Err(ChecksumHeaderErr::Cardinality {
            headers_and_trailer: false,
        });
    }
    if headers.len() + trailers.len() > 1 {
        return Err(ChecksumHeaderErr::Cardinality {
            headers_and_trailer: true,
        });
    }
    let aws_sha256 = header_ci(req, "x-amz-content-sha256").unwrap_or("");
    if !trailers.is_empty() && !is_streaming_payload_hash(aws_sha256) {
        return Err(ChecksumHeaderErr::TrailerNotStreaming);
    }
    if headers.is_empty() {
        let algo = header_ci(req, "x-amz-sdk-checksum-algorithm");
        if algo.is_some() && trailers.is_empty() {
            return Err(ChecksumHeaderErr::DeclaredWithoutHeader);
        }
        return Ok(None);
    }
    let (name, value) = &headers[0];
    let spec = checksum_spec(name)?;
    let trimmed = value.trim();
    match decode_base64(trimmed) {
        Some(raw) if raw.len() == spec.digest_size && base64_encode(&raw) == trimmed => {}
        _ => return Err(ChecksumHeaderErr::InvalidValue(spec.header.clone())),
    }
    if let Some(algo) = header_ci(req, "x-amz-sdk-checksum-algorithm") {
        if !algo.eq_ignore_ascii_case(spec.algo) {
            return Err(ChecksumHeaderErr::AlgoMismatch);
        }
    }
    Ok(Some((spec, value.trim().to_string())))
}

fn checksum_err_response(err: ChecksumHeaderErr) -> Response {
    match err {
        ChecksumHeaderErr::InvalidAlgorithm => s3_error_response(
            "InvalidRequest",
            Some("The algorithm type you specified in x-amz-checksum- header is invalid."),
            &[],
        ),
        ChecksumHeaderErr::NotImplemented(h) => {
            let msg = format!("The {h} algorithm is not supported.");
            s3_error_response("NotImplemented", Some(&msg), &[])
        }
        ChecksumHeaderErr::Cardinality {
            headers_and_trailer: true,
        } => s3_error_response(
            "InvalidRequest",
            Some("Expecting a single x-amz-checksum- header"),
            &[],
        ),
        ChecksumHeaderErr::Cardinality {
            headers_and_trailer: false,
        } => s3_error_response(
            "InvalidRequest",
            Some("Expecting a single x-amz-checksum- header. Multiple checksum Types are not allowed."),
            &[],
        ),
        ChecksumHeaderErr::InvalidValue(h) => {
            let msg = format!("Value for {h} header is invalid.");
            s3_error_response("InvalidRequest", Some(&msg), &[])
        }
        ChecksumHeaderErr::AlgoMismatch => s3_error_response(
            "InvalidRequest",
            Some("Value for x-amz-sdk-checksum-algorithm header is invalid."),
            &[],
        ),
        ChecksumHeaderErr::DeclaredWithoutHeader => s3_error_response(
            "InvalidRequest",
            Some(
                "x-amz-sdk-checksum-algorithm specified, but no corresponding x-amz-checksum-* or x-amz-trailer headers were found.",
            ),
            &[],
        ),
        ChecksumHeaderErr::TrailerNotStreaming => {
            s3_error_response("MalformedTrailerError", None, &[])
        }
        ChecksumHeaderErr::TrailerUnsupported => s3_error_response(
            "InvalidRequest",
            Some("The value specified in the x-amz-trailer header is not supported"),
            &[],
        ),
    }
}

fn check_checksum_body(req: &Request, body: &[u8]) -> Option<Response> {
    let (spec, expected_b64) = match collect_checksum(req) {
        Ok(Some(v)) => v,
        _ => return None,
    };
    let computed = checksum_b64(&spec, body);
    if computed != expected_b64 {
        let msg = format!(
            "The {} you specified did not match the calculated checksum.",
            spec.algo
        );
        return Some(s3_error_response("BadDigest", Some(&msg), &[]));
    }
    None
}

fn checksum_b64(spec: &ChecksumSpec, body: &[u8]) -> String {
    match spec.algo {
        "CRC32" => base64_encode(&crc32_ieee(body).to_be_bytes()),
        "CRC32C" => base64_encode(&crc32_castagnoli(body).to_be_bytes()),
        "SHA1" => {
            let d = Sha1::digest(body);
            base64_encode(d.as_slice())
        }
        "SHA256" => {
            let d = sha2::Sha256::digest(body);
            base64_encode(d.as_slice())
        }
        _ => String::new(),
    }
}

fn crc32_ieee(data: &[u8]) -> u32 {
    let mut hasher = Crc32Hasher::ieee();
    hasher.update(data);
    hasher.finalize()
}

fn crc32_castagnoli(data: &[u8]) -> u32 {
    let mut hasher = Crc32Hasher::castagnoli();
    hasher.update(data);
    hasher.finalize()
}

struct Crc32Hasher {
    crc: u32,
    poly: u32,
}

impl Crc32Hasher {
    fn ieee() -> Self {
        Self {
            crc: 0xFFFF_FFFF,
            poly: 0xEDB8_8320,
        }
    }
    fn castagnoli() -> Self {
        Self {
            crc: 0xFFFF_FFFF,
            poly: 0x82F6_3B78,
        }
    }
    fn update(&mut self, data: &[u8]) {
        for &b in data {
            self.crc ^= u32::from(b);
            for _ in 0..8 {
                self.crc = if self.crc & 1 != 0 {
                    (self.crc >> 1) ^ self.poly
                } else {
                    self.crc >> 1
                };
            }
        }
    }
    fn finalize(self) -> u32 {
        !self.crc
    }
}

/// Incremental HashingInput + checksum + Content-MD5 for streaming PUT.
pub struct PayloadHashTransform {
    sha256: Option<Sha256>,
    expected_sha256: Option<String>,
    md5: Option<Md5Hasher>,
    expected_md5: Option<Vec<u8>>,
    md5_header: Option<String>,
    md5_expected_hex: bool,
    crc32: Option<Crc32Hasher>,
    crc32c: Option<Crc32Hasher>,
    sha1: Option<Sha1>,
    checksum_sha256: Option<Sha256>,
    expected_checksum_b64: Option<String>,
    checksum_algo: Option<String>,
    content_length: Option<u64>,
    received: u64,
    finished: bool,
    slot: Arc<Mutex<Option<Response>>>,
}

impl PayloadHashTransform {
    pub fn from_request(req: &Request, slot: Arc<Mutex<Option<Response>>>) -> Self {
        Self::from_request_opts(req, slot, false)
    }

    /// `hash_streaming_token`: V2 / V4-query STREAMING-* is not aws-chunked;
    /// hash the raw body against the STREAMING token (always mismatch).
    pub fn from_request_opts(
        req: &Request,
        slot: Arc<Mutex<Option<Response>>>,
        hash_streaming_token: bool,
    ) -> Self {
        let has_cl = header_ci(req, "content-length").is_some()
            || header_ci(req, "x-amz-decoded-content-length").is_some();
        let expected_sha256 = header_ci(req, "x-amz-content-sha256")
            .filter(|v| *v != "UNSIGNED-PAYLOAD")
            .filter(|v| hash_streaming_token || !is_streaming_payload_hash(v))
            .filter(|_| has_cl)
            .map(|v| v.to_string());
        let sha256 = expected_sha256.as_ref().map(|_| Sha256::new());
        let md5_header = content_md5_raw(req).map(str::to_string);
        let expected_md5 = md5_header.as_deref().and_then(decode_content_md5);
        let md5 = expected_md5.as_ref().map(|_| Md5Hasher::new());
        let md5_expected_hex = req.method == "PUT";
        let mut crc32 = None;
        let mut crc32c = None;
        let mut sha1 = None;
        let mut checksum_sha256 = None;
        let mut expected_checksum_b64 = None;
        let mut checksum_algo = None;
        if checksum_should_verify(req) {
            if let Ok(Some((spec, b64))) = collect_checksum(req) {
                expected_checksum_b64 = Some(b64);
                checksum_algo = Some(spec.algo.to_string());
                match spec.algo {
                    "CRC32" => crc32 = Some(Crc32Hasher::ieee()),
                    "CRC32C" => crc32c = Some(Crc32Hasher::castagnoli()),
                    "SHA1" => sha1 = Some(Sha1::new()),
                    "SHA256" => checksum_sha256 = Some(Sha256::new()),
                    _ => {}
                }
            }
        }
        let content_length = header_ci(req, "content-length")
            .and_then(|s| s.parse().ok())
            .or_else(|| {
                header_ci(req, "x-amz-decoded-content-length").and_then(|s| s.parse().ok())
            });
        Self {
            sha256,
            expected_sha256,
            md5,
            expected_md5,
            md5_header,
            md5_expected_hex,
            crc32,
            crc32c,
            sha1,
            checksum_sha256,
            expected_checksum_b64,
            checksum_algo,
            content_length,
            received: 0,
            finished: false,
            slot,
        }
    }

    fn store_err(&self, resp: Response) {
        if let Ok(mut g) = self.slot.lock() {
            *g = Some(resp);
        }
    }

    fn finalize_payload_errors(&mut self) -> Option<Response> {
        if self.finished {
            return None;
        }
        self.finished = true;
        if let (Some(hasher), Some(expected)) =
            (self.sha256.take(), self.expected_sha256.as_deref())
        {
            let computed = hex_encode(&hasher.finalize());
            if computed != expected.to_ascii_lowercase() {
                return Some(sha256_mismatch_response(expected, &computed));
            }
        }
        if let (Some(algo), Some(expected)) = (
            self.checksum_algo.as_deref(),
            self.expected_checksum_b64.as_deref(),
        ) {
            let computed = match algo {
                "CRC32" => self
                    .crc32
                    .take()
                    .map(|h| base64_encode(&h.finalize().to_be_bytes())),
                "CRC32C" => self
                    .crc32c
                    .take()
                    .map(|h| base64_encode(&h.finalize().to_be_bytes())),
                "SHA1" => self
                    .sha1
                    .take()
                    .map(|h| base64_encode(h.finalize().as_slice())),
                "SHA256" => self
                    .checksum_sha256
                    .take()
                    .map(|h| base64_encode(h.finalize().as_slice())),
                _ => None,
            };
            if let Some(computed) = computed {
                if computed != expected {
                    let msg =
                        format!("The {algo} you specified did not match the calculated checksum.");
                    return Some(s3_error_response("BadDigest", Some(&msg), &[]));
                }
            }
        }
        if let (Some(hasher), Some(want), Some(hdr)) = (
            self.md5.take(),
            self.expected_md5.as_ref(),
            self.md5_header.as_deref(),
        ) {
            let got = hasher.finalize();
            if got.as_slice() != want.as_slice() {
                return Some(bad_digest_response(hdr, self.md5_expected_hex));
            }
        }
        None
    }
}

impl BodyTransform for PayloadHashTransform {
    fn push(&mut self, input: Option<&[u8]>) -> io::Result<Vec<u8>> {
        match input {
            Some(chunk) => {
                if let Some(h) = self.sha256.as_mut() {
                    h.update(chunk);
                }
                if let Some(h) = self.md5.as_mut() {
                    h.update(chunk);
                }
                if let Some(h) = self.crc32.as_mut() {
                    h.update(chunk);
                }
                if let Some(h) = self.crc32c.as_mut() {
                    h.update(chunk);
                }
                if let Some(h) = self.sha1.as_mut() {
                    h.update(chunk);
                }
                if let Some(h) = self.checksum_sha256.as_mut() {
                    h.update(chunk);
                }
                self.received = self.received.saturating_add(chunk.len() as u64);
                // Python ChecksummingInput validates on the read that
                // reaches Content-Length and withholds that chunk on
                // mismatch so the PUT never commits.
                if self.content_length.is_some_and(|n| self.received >= n) {
                    if let Some(resp) = self.finalize_payload_errors() {
                        self.store_err(resp);
                        return Err(io::Error::other("s3 payload hash mismatch"));
                    }
                }
                Ok(chunk.to_vec())
            }
            None => {
                if let Some(resp) = self.finalize_payload_errors() {
                    self.store_err(resp);
                    return Err(io::Error::other("s3 payload hash mismatch"));
                }
                Ok(Vec::new())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::md5_hex;
    use swift_http::{Body, HeaderKeyDict, Request};

    #[test]
    fn negative_content_length_is_invalid_argument() {
        let mut req = empty_put();
        req.headers.set("Content-Length", "-1");
        let resp = invalid_content_length_header(&req).expect("err");
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert_eq!(resp.status, 400);
        assert!(body.contains("InvalidArgument"), "{body}");
    }

    #[test]
    fn empty_content_length_is_invalid_argument() {
        let mut req = empty_put();
        req.headers.set("Content-Length", "");
        let resp = invalid_content_length_header(&req).expect("err");
        assert_eq!(resp.status, 400);
    }

    fn empty_put() -> Request {
        let mut headers = HeaderKeyDict::new();
        headers.set("Host", "localhost");
        Request {
            method: "PUT".into(),
            path: "/b/o".into(),
            query_string: String::new(),
            headers,
            body: Body::empty(),
        }
    }

    #[test]
    fn crc32_of_123456789_matches_aws_vector() {
        assert_eq!(
            base64_encode(&crc32_ieee(b"123456789").to_be_bytes()),
            "y/Q5Jg=="
        );
    }

    #[test]
    fn looks_like_sha256_accepts_upper() {
        let h = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855";
        assert!(looks_like_sha256(h));
        assert!(!looks_like_sha256("invalid"));
    }

    #[test]
    fn initiate_multipart_content_md5_is_not_checked_against_empty_body() {
        let mut req = empty_put();
        req.method = "POST".into();
        req.path = "/bucket/obj".into();
        req.query_string = "uploads".into();
        // Official test_object_multi_upload: base64(16 x 0x61) on Initiate.
        req.headers.set("Content-MD5", "YWFhYWFhYWFhYWFhYWFhYQ==");
        req.body = Body::Buffered(Vec::new());
        assert!(
            validate_s3_payload(&mut req, false).is_none(),
            "Initiate MPU must not BadDigest on unrelated Content-MD5"
        );
    }

    fn complete_multipart_content_md5_mismatch_is_bad_digest_base64() {
        let mut req = empty_put();
        req.method = "POST".into();
        req.path = "/bucket/obj".into();
        req.query_string = "uploadId=abc".into();
        req.headers.set("Content-MD5", "YWFhYWFhYWFhYWFhYWFhYQ==");
        req.body = Body::Buffered(b"<CompleteMultipartUpload/>".to_vec());
        let resp = validate_s3_payload(&mut req, false).unwrap();
        assert_eq!(resp.status, 400);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("<Code>BadDigest</Code>"), "{body}");
        assert!(
            body.contains("<ExpectedDigest>YWFhYWFhYWFhYWFhYWFhYQ==</ExpectedDigest>"),
            "{body}"
        );
    }

    fn multi_delete_content_length_over_python_cap_is_malformed_xml() {
        let mut req = empty_put();
        req.method = "POST".into();
        req.path = "/bucket".into();
        req.query_string = "delete".into();
        req.headers.set("Content-MD5", &base64_encode(&md5(b"x")));
        req.headers.set("Content-Length", "3000000");
        req.body = Body::Buffered(b"x".to_vec());
        let resp = validate_s3_payload(&mut req, false).unwrap();
        assert_eq!(resp.status, 400);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("<Code>MalformedXML</Code>"), "{body}");
    }

    fn malformed_content_md5_is_invalid_digest() {
        let mut req = empty_put();
        req.headers.set("content-md5", "invalid");
        req.body = Body::Buffered(b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx".to_vec());
        let resp = invalid_content_md5_response(&req).unwrap();
        assert_eq!(resp.status, 400);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("InvalidDigest"), "{body}");
    }

    #[test]
    fn bad_content_md5_is_bad_digest_with_hex_expected() {
        let mut req = empty_put();
        let empty_b64 = base64_encode(&md5(b""));
        req.headers.set("content-md5", &empty_b64);
        req.body = Body::Buffered(b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx".to_vec());
        let resp = validate_s3_payload(&mut req, false).unwrap();
        assert_eq!(resp.status, 400);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("BadDigest"), "{body}");
        assert!(
            body.contains(&format!(
                "<ExpectedDigest>{}</ExpectedDigest>",
                md5_hex(b"")
            )),
            "{body}"
        );
    }

    #[test]
    fn invalid_sha256_on_v2_is_mismatch_not_invalid_argument() {
        let mut req = empty_put();
        req.headers.set("x-amz-content-sha256", "invalid");
        req.headers.set("Content-Length", "32");
        req.body = Body::Buffered(b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx".to_vec());
        let resp = validate_s3_payload(&mut req, false).unwrap();
        assert_eq!(resp.status, 400);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("XAmzContentSHA256Mismatch"), "{body}");
        assert!(body.contains("<ClientComputedContentSHA256>invalid</ClientComputedContentSHA256>"));
        assert!(body.contains("<S3ComputedContentSHA256>"));
    }

    #[test]
    fn sha256_mismatch_trumps_bad_digest() {
        let mut req = empty_put();
        let empty_b64 = base64_encode(&md5(b""));
        req.headers.set("content-md5", &empty_b64);
        req.headers.set(
            "x-amz-content-sha256",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
        req.headers.set("Content-Length", "32");
        req.body = Body::Buffered(b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx".to_vec());
        let resp = validate_s3_payload(&mut req, false).unwrap();
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("XAmzContentSHA256Mismatch"), "{body}");
        assert!(!body.contains("BadDigest"), "{body}");
    }

    #[test]
    fn v2_streaming_reads_raw_body() {
        let mut req = empty_put();
        req.headers
            .set("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER");
        req.headers.set("x-amz-decoded-content-length", "32");
        req.headers.set("Content-Length", "32");
        req.body = Body::Buffered(b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx".to_vec());
        let resp = validate_s3_payload(&mut req, false).unwrap();
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("XAmzContentSHA256Mismatch"), "{body}");
        assert!(body.contains("STREAMING-UNSIGNED-PAYLOAD-TRAILER"));
        assert!(!body.contains("IncompleteBody"), "{body}");
    }

    #[test]
    fn v4_header_missing_sha256_is_invalid_request() {
        let req = empty_put();
        let resp = validate_sha256_header(&req, true).unwrap();
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("InvalidRequest"), "{body}");
        assert!(body.contains("x-amz-content-sha256"), "{body}");
    }

    #[test]
    fn v4_header_invalid_sha256_is_invalid_argument() {
        let mut req = empty_put();
        req.headers.set("x-amz-content-sha256", "invalid");
        let resp = validate_sha256_header(&req, true).unwrap();
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("InvalidArgument"), "{body}");
        assert!(body.contains("<ArgumentName>x-amz-content-sha256</ArgumentName>"));
        assert!(body.contains("<ArgumentValue>invalid</ArgumentValue>"));
    }

    #[test]
    fn checksum_crc32_bad_is_bad_digest() {
        let mut req = empty_put();
        req.headers.set("x-amz-checksum-crc32", "z/Q5Jg==");
        req.body = Body::Buffered(b"123456789".to_vec());
        let resp = validate_s3_payload(&mut req, false).unwrap();
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("BadDigest"), "{body}");
        assert!(body.contains("CRC32"), "{body}");
    }

    #[test]
    fn checksum_crc32_invalid_value() {
        let mut req = empty_put();
        req.headers.set("x-amz-checksum-crc32", "y/Q5Jh==");
        req.body = Body::Buffered(b"123456789".to_vec());
        let resp = validate_s3_payload(&mut req, false).unwrap();
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("InvalidRequest"), "{body}");
        assert!(body.contains("x-amz-checksum-crc32"), "{body}");
    }

    #[test]
    fn crc32c_of_123456789_matches_aws_vector() {
        assert_eq!(
            base64_encode(&crc32_castagnoli(b"123456789").to_be_bytes()),
            "4waSgw=="
        );
    }

    #[test]
    fn duplicate_trailer_checksums_are_multiple_types() {
        let mut req = empty_put();
        req.headers.set("x-amz-sdk-checksum-algorithm", "sha256");
        req.headers.set("x-amz-checksum-crc32", "y/Q5Jg==");
        req.headers.set(
            "x-amz-trailer",
            "x-amz-checksum-crc32, x-amz-checksum-crc32",
        );
        req.body = Body::Buffered(b"123456789".to_vec());
        let resp = validate_s3_payload(&mut req, false).unwrap();
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("InvalidRequest"), "{body}");
        assert!(
            body.contains("Multiple checksum Types are not allowed."),
            "{body}"
        );
    }

    #[test]
    fn one_header_plus_one_trailer_uses_short_cardinality_message() {
        let mut req = empty_put();
        req.headers.set("x-amz-checksum-crc32", "y/Q5Jg==");
        req.headers.set("x-amz-trailer", "x-amz-checksum-crc32");
        req.headers
            .set("x-amz-content-sha256", sha256_hex(b"123456789"));
        req.body = Body::Buffered(b"123456789".to_vec());
        let resp = validate_s3_payload(&mut req, false).unwrap();
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("InvalidRequest"), "{body}");
        assert!(
            body.contains("Expecting a single x-amz-checksum- header"),
            "{body}"
        );
        assert!(!body.contains("Multiple checksum Types"), "{body}");
    }

    #[test]
    fn v2_streaming_decoded_shorter_than_content_length_is_incomplete_body() {
        let mut req = empty_put();
        req.headers
            .set("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER");
        req.headers.set("x-amz-decoded-content-length", "9");
        req.headers.set("Content-Length", "15");
        req.body = Body::Buffered(b"9\r\n1234567890\r\n".to_vec());
        let resp = validate_s3_payload(&mut req, false).unwrap();
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("IncompleteBody"), "{body}");
        assert!(
            body.contains(
                "<Message>You did not provide the number of bytes specified by the Content-Length HTTP header</Message>"
            ),
            "{body}"
        );
        assert!(!body.contains("HTTP header.</Message>"), "{body}");
        assert!(
            body.contains("<NumberBytesExpected>9</NumberBytesExpected>"),
            "{body}"
        );
        assert!(
            body.contains("<NumberBytesProvided>15</NumberBytesProvided>"),
            "{body}"
        );
    }

    #[test]
    fn streaming_bad_crc32_rejects_completing_chunk() {
        let mut req = empty_put();
        req.headers.set("x-amz-checksum-crc32", "z/Q5Jg==");
        req.headers.set("Content-Length", "9");
        let slot = Arc::new(Mutex::new(None));
        let mut xform = PayloadHashTransform::from_request(&req, Arc::clone(&slot));
        assert!(xform.push(Some(b"123456789")).is_err());
        let resp = slot.lock().unwrap().take().expect("BadDigest slot");
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("BadDigest"), "{body}");
        assert!(body.contains("CRC32"), "{body}");
    }
}
