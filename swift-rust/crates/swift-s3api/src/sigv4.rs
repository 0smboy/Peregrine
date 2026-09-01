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

//! AWS Signature Version 4 for the S3 API.
//!
//! Ported from the `SigV4Mixin` / `SigCheckerV4` machinery in
//! `swift/common/middleware/s3api/s3request.py`. This builds the canonical
//! request, the string-to-sign and the HMAC-SHA256 signing-key chain, and
//! verifies a client-presented signature (header auth and presigned-URL
//! query auth).
//!
//! aws-chunked body framing is decoded in [`crate::aws_chunked`] (middleware
//! dechunks PUT/POST and enforces per-chunk HMAC for signed streaming modes).
//! This module only handles the **header** SigV4 signature (where
//! `X-Amz-Content-SHA256` is the literal `STREAMING-*` token).
//!
//! SigV2 lives in [`crate::sigv2`]. Clock-skew and query-expiry checks are
//! **experimental** (not live-proven, not AWS-complete). Still deferred:
//! Date-header-only V4 timestamp fallback (only `X-Amz-Date` is read),
//! `x-amz-content-sha256` payload validation, and Expires range/overflow
//! codes.

use crate::crypto::{hmac_sha256, hmac_sha256_hex, sha256_hex, streq_const_time};
use swift_http::{parse_http_date, parse_query, HeaderKeyDict, Request};

/// The AWS service name this endpoint signs for.
pub const SERVICE: &str = "s3";
/// The SigV4 algorithm identifier.
pub const ALGORITHM: &str = "AWS4-HMAC-SHA256";

/// Distinct auth failures so middleware can emit the matching S3 `Code`.
///
/// Experimental: not live-proven. Not AWS-complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigAuthError {
    SignatureDoesNotMatch,
    RequestTimeTooSkewed,
    /// Query auth past `X-Amz-Expires` / `Expires` (not a bad HMAC).
    AccessDenied,
    /// SigV2 query `Expires >= 2^31` (Python `_validate_expire_param`).
    AccessDeniedInvalidExpires,
    /// Header auth with empty/missing Date and x-amz-date (Python s3request).
    InvalidDate,
    /// SigV4 query `X-Amz-Expires` range/type (Python `_validate_expire_param`).
    AuthorizationQueryParametersError(&'static str),
}

impl SigAuthError {
    pub fn s3_code(self) -> &'static str {
        match self {
            Self::SignatureDoesNotMatch => "SignatureDoesNotMatch",
            Self::RequestTimeTooSkewed => "RequestTimeTooSkewed",
            Self::AccessDenied | Self::AccessDeniedInvalidExpires | Self::InvalidDate => {
                "AccessDenied"
            }
            Self::AuthorizationQueryParametersError(_) => "AuthorizationQueryParametersError",
        }
    }

    /// Override message; `None` uses [`crate::response::error_status_and_message`].
    pub fn s3_message(self) -> Option<&'static str> {
        match self {
            Self::AccessDenied => Some("Request has expired"),
            Self::AccessDeniedInvalidExpires => {
                Some("Invalid date (should be seconds since epoch)")
            }
            Self::InvalidDate => {
                Some("AWS authentication requires a valid Date or x-amz-date header")
            }
            Self::AuthorizationQueryParametersError(msg) => Some(msg),
            Self::SignatureDoesNotMatch | Self::RequestTimeTooSkewed => None,
        }
    }
}

/// The `<date>/<region>/<service>/<terminal>` credential scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialScope {
    pub date: String,
    pub region: String,
    pub service: String,
    pub terminal: String,
}

impl CredentialScope {
    /// The scope joined with `/` as it appears in the string-to-sign.
    pub fn scope_string(&self) -> String {
        format!(
            "{}/{}/{}/{}",
            self.date, self.region, self.service, self.terminal
        )
    }
}

/// Parsed SigV4 auth material presented by a client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigV4Auth {
    pub access_key: String,
    pub scope: CredentialScope,
    /// Lower-case header names, in the order given by the client.
    pub signed_headers: Vec<String>,
    /// The client-presented signature (lower-case hex).
    pub signature: String,
    /// True for presigned-URL (query) auth, false for `Authorization` header.
    pub query_auth: bool,
}

/// Parse an AWS credential string
/// `<access>/<date>/<region>/<service>/aws4_request`.
///
/// Port of `_parse_credential`. Returns the access key and scope, or `None`
/// if the string is malformed.
pub fn parse_credential(credential: &str) -> Option<(String, CredentialScope)> {
    let parts: Vec<&str> = credential.split('/').collect();
    if parts.len() != 5 || parts[0].is_empty() {
        return None;
    }
    Some((
        parts[0].to_string(),
        CredentialScope {
            date: parts[1].to_string(),
            region: parts[2].to_string(),
            service: parts[3].to_string(),
            terminal: parts[4].to_string(),
        },
    ))
}

/// Take the value of a `Name=` field in an `Authorization` header, up to the
/// next comma. Mirrors `auth_str.partition("Name=")[2].split(',')[0]`.
fn field_after(auth: &str, marker: &str) -> Option<String> {
    let idx = auth.find(marker)?;
    let rest = &auth[idx + marker.len()..];
    let end = rest.find(',').unwrap_or(rest.len());
    Some(rest[..end].to_string())
}

/// Parse a v4 `Authorization` header value.
///
/// Port of `SigV4Mixin._parse_header_authentication`. Expects the
/// `AWS4-HMAC-SHA256 ` prefix and `Credential=`, `SignedHeaders=`,
/// `Signature=` fields.
pub fn parse_authorization_header(auth: &str) -> Option<SigV4Auth> {
    if !auth.starts_with("AWS4-HMAC-SHA256 ") {
        return None;
    }
    let credential = field_after(auth, "Credential=")?;
    let signed = field_after(auth, "SignedHeaders=")?;
    let signature = field_after(auth, "Signature=")?;
    if signature.is_empty() || signed.is_empty() {
        return None;
    }
    let (access_key, scope) = parse_credential(&credential)?;
    Some(SigV4Auth {
        access_key,
        scope,
        signed_headers: signed.split(';').map(str::to_string).collect(),
        signature,
        query_auth: false,
    })
}

/// Parse presigned-URL (query) auth from the query parameters.
///
/// Port of `SigV4Mixin._parse_query_authentication` (the signature-relevant
/// parts). Expects `X-Amz-Algorithm=AWS4-HMAC-SHA256`, `X-Amz-Credential`,
/// `X-Amz-SignedHeaders` and `X-Amz-Signature`.
pub fn parse_query_authentication(params: &[(String, String)]) -> Option<SigV4Auth> {
    let get = |name: &str| {
        params
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
    };
    if get("X-Amz-Algorithm").as_deref() != Some(ALGORITHM) {
        return None;
    }
    let credential = get("X-Amz-Credential")?;
    let signature = get("X-Amz-Signature")?;
    let signed = get("X-Amz-SignedHeaders")?;
    if signature.is_empty() {
        return None;
    }
    let (access_key, scope) = parse_credential(&credential)?;
    Some(SigV4Auth {
        access_key,
        scope,
        signed_headers: signed.split(';').map(str::to_string).collect(),
        signature,
        query_auth: true,
    })
}

/// Detect and parse the SigV4 auth material on a request, from the
/// `Authorization` header if present, otherwise from query parameters.
pub fn parse_sigv4_auth(req: &Request) -> Option<SigV4Auth> {
    if let Some(auth) = req.headers.get("Authorization") {
        if auth.starts_with("AWS4-HMAC-SHA256 ") {
            return parse_authorization_header(auth);
        }
    }
    parse_query_authentication(&req.params())
}

/// The signing timestamp in `YYYYMMDDThhmmssZ` form. Read from the
/// `X-Amz-Date` header, else the `X-Amz-Date` query parameter, else `Date`.
/// Empty values count as missing (Python `s3request` InvalidDate).
pub fn amz_date(req: &Request) -> Option<String> {
    if let Some(d) = req.headers.get("X-Amz-Date") {
        if !d.trim().is_empty() {
            return Some(d.to_string());
        }
    }
    if let Some(d) = req.param("X-Amz-Date").filter(|d| !d.trim().is_empty()) {
        return Some(d);
    }
    req.headers
        .get("Date")
        .filter(|d| !d.trim().is_empty())
        .map(str::to_string)
}

/// Parse `YYYYMMDDThhmmssZ` to unix seconds. Experimental; not AWS-complete.
pub fn parse_amz_date(s: &str) -> Option<i64> {
    let s = s.trim();
    let b = s.as_bytes();
    if b.len() != 16 || b[8] != b'T' || b[15] != b'Z' {
        return None;
    }
    let y: i64 = s[0..4].parse().ok()?;
    let mo: u32 = s[4..6].parse().ok()?;
    let d: u32 = s[6..8].parse().ok()?;
    let h: i64 = s[9..11].parse().ok()?;
    let mi: i64 = s[11..13].parse().ok()?;
    let se: i64 = s[13..15].parse().ok()?;
    if !(1..=12).contains(&mo)
        || !(1..=31).contains(&d)
        || !(0..24).contains(&h)
        || !(0..60).contains(&mi)
        || !(0..61).contains(&se)
    {
        return None;
    }
    Some(days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + se)
}

/// Format unix seconds as `YYYYMMDDThhmmssZ`. Experimental; not AWS-complete.
pub fn format_amz_date(unix: i64) -> String {
    let days = unix.div_euclid(86400);
    let sod = unix.rem_euclid(86400);
    let (y, mo, d) = civil_from_days(days);
    let h = sod / 3600;
    let mi = (sod % 3600) / 60;
    let se = sod % 60;
    format!("{y:04}{mo:02}{d:02}T{h:02}{mi:02}{se:02}Z")
}

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 } as i64;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Clock-skew + V4 query expiry. Experimental: not live-proven. Not AWS-complete.
///
/// Query expiry (`signed_at + X-Amz-Expires < now` → `AccessDenied`) is
/// checked before skew so an expired presigned URL is not remapped to
/// `RequestTimeTooSkewed`. Header and query both apply
/// `abs(signing_ts - now) > allowable_clock_skew`.
/// boto2 SigV4 still lists `date` in SignedHeaders when the client passed
/// `Date: ""` (official `test_service_error_no_date_header`). The empty
/// Date may be dropped in transit; a later `X-Amz-Date` from the signer
/// must not hide that. Python raises InvalidDate / AccessDenied.
fn empty_date_header_is_invalid(req: &Request) -> bool {
    let auth = parse_sigv4_auth(req);
    if auth.as_ref().is_some_and(|a| a.query_auth) {
        return false;
    }
    let date = req.headers.get("Date").unwrap_or("");
    let amz = req.headers.get("X-Amz-Date").unwrap_or("");
    if !date.trim().is_empty() {
        return false;
    }
    if amz.trim().is_empty() {
        return true;
    }
    auth.is_some_and(|auth| {
        auth.signed_headers
            .iter()
            .any(|h| h.eq_ignore_ascii_case("date"))
    })
}

pub fn check_sigv4_time(
    req: &Request,
    now_unix: i64,
    allowable_clock_skew: u64,
) -> Result<(), SigAuthError> {
    if empty_date_header_is_invalid(req) {
        return Err(SigAuthError::InvalidDate);
    }
    let Some(date) = amz_date(req) else {
        let query_auth = parse_sigv4_auth(req).is_some_and(|a| a.query_auth);
        if query_auth {
            return Ok(());
        }
        return Err(SigAuthError::InvalidDate);
    };
    let Some(signing_ts) = parse_amz_date(&date).or_else(|| parse_http_date(&date)) else {
        // Empty or unparseable Date / X-Amz-Date: Python InvalidDate, not
        // SignatureDoesNotMatch (official test_service_error_no_date_header).
        return Err(SigAuthError::InvalidDate);
    };
    let query_auth = parse_sigv4_auth(req).is_some_and(|a| a.query_auth);
    if query_auth {
        if let Some(exp_s) = req.param("X-Amz-Expires") {
            // Python s3request._validate_expire_param (V4).
            match exp_s.parse::<i64>() {
                Err(_) => {
                    return Err(SigAuthError::AuthorizationQueryParametersError(
                        "X-Amz-Expires should be a number",
                    ));
                }
                Ok(expires) if expires < 0 => {
                    return Err(SigAuthError::AuthorizationQueryParametersError(
                        "X-Amz-Expires must be non-negative",
                    ));
                }
                Ok(expires) if expires > 604800 => {
                    return Err(SigAuthError::AuthorizationQueryParametersError(
                        "X-Amz-Expires must be less than a week (in seconds);                          that is, the given X-Amz-Expires must be less than                          604800 seconds",
                    ));
                }
                Ok(expires) if signing_ts.saturating_add(expires) <= now_unix => {
                    return Err(SigAuthError::AccessDenied);
                }
                Ok(_) => {}
            }
        }
    }
    if signing_ts.abs_diff(now_unix) > allowable_clock_skew {
        return Err(SigAuthError::RequestTimeTooSkewed);
    }
    Ok(())
}

/// `urllib.parse.quote(value, safe)` — RFC 3986 unreserved characters
/// (`A-Za-z0-9-_.~`) plus any byte in `safe` pass through; every other byte
/// is upper-case `%XX`. Operates on the UTF-8 bytes of `value`.
fn quote(value: &str, safe: &[u8]) -> String {
    let mut out = String::with_capacity(value.len());
    for &b in value.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-' | b'~') || safe.contains(&b)
        {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Collapse a header value for signing: strip leading/trailing control bytes
/// (`<= 0x20`) and collapse internal ASCII-whitespace runs to a single space.
/// Mirrors `' '.join(_header_strip(value).split())`.
fn normalize_header_value(v: &str) -> String {
    let trimmed = v.trim_matches(|c: char| (c as u32) <= 0x20);
    let mut out = String::with_capacity(trimmed.len());
    let mut in_ws = false;
    for c in trimmed.chars() {
        if c.is_ascii_whitespace() {
            if !in_ws {
                out.push(' ');
                in_ws = true;
            }
        } else {
            out.push(c);
            in_ws = false;
        }
    }
    out
}

/// The canonical URI: the (already-decoded) request path re-encoded with
/// `safe='-_.~/'`. Port of `_canonical_uri`.
pub fn canonical_uri(decoded_path: &str) -> String {
    quote(decoded_path, b"-_.~/")
}

/// The canonical query string: decoded params (excluding the signature),
/// sorted by `(key, value)`, each key and value re-encoded with `safe='-_.~'`,
/// joined by `&`. Port of `_canonical_query_string`.
pub fn canonical_query(raw_query: &str) -> String {
    let mut pairs = parse_query(raw_query);
    pairs.retain(|(k, _)| k != "Signature" && k != "X-Amz-Signature");
    pairs.sort();
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", quote(k, b"-_.~"), quote(v, b"-_.~")))
        .collect::<Vec<_>>()
        .join("&")
}

/// Build the sorted `(name, value)` list for the signed headers, looking each
/// up (case-insensitively) in `headers`. Returns `None` if any signed header
/// is absent (which AWS reports as `SignatureDoesNotMatch`).
/// Port of `_headers_to_sign`.
pub fn headers_to_sign(
    headers: &HeaderKeyDict,
    signed_headers: &[String],
) -> Option<Vec<(String, String)>> {
    let mut out = Vec::with_capacity(signed_headers.len());
    for name in signed_headers {
        let value = headers.get(name)?;
        out.push((name.to_ascii_lowercase(), normalize_header_value(value)));
    }
    out.sort();
    Some(out)
}

/// Assemble the canonical request string. Port of `_canonical_request`.
pub fn canonical_request(
    method: &str,
    canonical_uri: &str,
    canonical_query: &str,
    headers_to_sign: &[(String, String)],
    payload_hash: &str,
) -> String {
    let mut cr = String::new();
    cr.push_str(method);
    cr.push('\n');
    cr.push_str(canonical_uri);
    cr.push('\n');
    cr.push_str(canonical_query);
    cr.push('\n');
    for (k, v) in headers_to_sign {
        cr.push_str(k);
        cr.push(':');
        cr.push_str(v);
        cr.push('\n');
    }
    cr.push('\n');
    cr.push_str(
        &headers_to_sign
            .iter()
            .map(|(k, _)| k.as_str())
            .collect::<Vec<_>>()
            .join(";"),
    );
    cr.push('\n');
    cr.push_str(payload_hash);
    cr
}

/// The string-to-sign. Port of `SigCheckerV4._string_to_sign`.
pub fn string_to_sign(amz_date: &str, scope_string: &str, canonical_request: &str) -> String {
    format!(
        "{ALGORITHM}\n{amz_date}\n{scope_string}\n{}",
        sha256_hex(canonical_request.as_bytes())
    )
}

/// Derive the SigV4 signing key from the secret and scope. Port of
/// `SigCheckerV4._derive_secret`: `HMAC(HMAC(HMAC(HMAC("AWS4"+secret, date),
/// region), service), "aws4_request")`.
pub fn signing_key(secret: &str, date: &str, region: &str, service: &str) -> [u8; 32] {
    let k_date = hmac_sha256(format!("AWS4{secret}").as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

/// Compute the hex signature for a canonical request under the given secret
/// and scope/date. This is the full "signature" step of SigV4.
pub fn compute_signature(
    secret: &str,
    scope: &CredentialScope,
    amz_date: &str,
    canonical_request: &str,
) -> String {
    let sts = string_to_sign(amz_date, &scope.scope_string(), canonical_request);
    let key = signing_key(secret, &scope.date, &scope.region, &scope.service);
    hmac_sha256_hex(&key, sts.as_bytes())
}

/// The payload hash used in the canonical request: the value of the
/// `X-Amz-Content-SHA256` header, or `UNSIGNED-PAYLOAD` when absent (as for
/// presigned URLs). Port of the tail of `_canonical_request`.
pub fn payload_hash(req: &Request) -> String {
    req.headers
        .get("X-Amz-Content-SHA256")
        .unwrap_or("UNSIGNED-PAYLOAD")
        .to_string()
}

/// Build the raw SigV4 string-to-sign for a request (UTF-8), or `None` if
/// auth material / signed headers / date are incomplete.
///
/// Used by `s3api` when deferring an unknown access key to Keystone
/// `/v3/s3tokens` (Python `s3api.auth_details['string_to_sign']`).
pub fn string_to_sign_for_request(req: &Request) -> Option<String> {
    let auth = parse_sigv4_auth(req)?;
    let date = amz_date(req)?;
    let hts = headers_to_sign(&req.headers, &auth.signed_headers)?;
    let cr = canonical_request(
        &req.method,
        &canonical_uri(&req.path),
        &canonical_query(&req.query_string),
        &hts,
        &payload_hash(req),
    );
    Some(string_to_sign(&date, &auth.scope.scope_string(), &cr))
}

/// Verify a client-presented AWS Signature V4 against the given credentials.
///
/// `access_key` / `secret_key` are the credentials the caller looked up for
/// the presented access key. HMAC match is required. When `now_unix` is
/// `Some`, also applies experimental clock-skew / query-expiry checks
/// (`RequestTimeTooSkewed` / `AccessDenied`). `allowable_clock_skew` is
/// ignored when `now_unix` is `None` (HMAC-only, for golden vectors).
///
/// Supports header auth and presigned-URL query auth. Does **not** validate
/// `x-amz-content-sha256` payload bytes. Not live-proven. Not AWS-complete.
pub fn verify_sigv4(
    access_key: &str,
    secret_key: &str,
    req: &Request,
    now_unix: Option<i64>,
    allowable_clock_skew: Option<u64>,
) -> Result<(), SigAuthError> {
    let auth = match parse_sigv4_auth(req) {
        Some(a) => a,
        None => return Err(SigAuthError::SignatureDoesNotMatch),
    };
    if auth.access_key != access_key {
        return Err(SigAuthError::SignatureDoesNotMatch);
    }
    if let Some(now) = now_unix {
        check_sigv4_time(req, now, allowable_clock_skew.unwrap_or(u64::MAX))?;
    }
    let date = match amz_date(req) {
        Some(d) => d,
        None => {
            if auth.query_auth {
                return Err(SigAuthError::SignatureDoesNotMatch);
            }
            return Err(SigAuthError::InvalidDate);
        }
    };
    let hts = match headers_to_sign(&req.headers, &auth.signed_headers) {
        Some(h) => h,
        None => return Err(SigAuthError::SignatureDoesNotMatch),
    };
    let cr = canonical_request(
        &req.method,
        &canonical_uri(&req.path),
        &canonical_query(&req.query_string),
        &hts,
        &payload_hash(req),
    );
    let expected = compute_signature(secret_key, &auth.scope, &date, &cr);
    if streq_const_time(&expected, &auth.signature) {
        Ok(())
    } else {
        Err(SigAuthError::SignatureDoesNotMatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The canonical AWS documented SigV4 test vector: "GET Object" for
    // examplebucket/test.txt.
    // Source: AWS S3 API reference, "Examples of signature calculations".
    const ACCESS: &str = "AKIAIOSFODNN7EXAMPLE";
    const SECRET: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

    fn assert_sig_error_xml_matches_normalize(err: SigAuthError, status: u16) {
        let resp = crate::response::s3_error_response(err.s3_code(), err.s3_message(), &[]);
        assert_eq!(resp.status, status, "{}", err.s3_code());
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        let msg = err
            .s3_message()
            .unwrap_or(crate::response::error_status_and_message(err.s3_code()).1);
        crate::response::assert_error_xml_matches_normalize(&body, err.s3_code(), msg);
    }

    fn header_auth_request() -> Request {
        let mut headers = HeaderKeyDict::new();
        headers.set("Host", "examplebucket.s3.amazonaws.com");
        headers.set("Range", "bytes=0-9");
        headers.set(
            "x-amz-content-sha256",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
        headers.set("x-amz-date", "20130524T000000Z");
        headers.set(
            "Authorization",
            "AWS4-HMAC-SHA256 \
             Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, \
             SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, \
             Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41",
        );
        Request {
            method: "GET".to_string(),
            path: "/test.txt".to_string(),
            query_string: String::new(),
            headers,
            body: swift_http::Body::empty(),
        }
    }

    #[test]
    fn test_aws_vector_canonical_request() {
        let auth = parse_sigv4_auth(&header_auth_request()).unwrap();
        let req = header_auth_request();
        let hts = headers_to_sign(&req.headers, &auth.signed_headers).unwrap();
        let cr = canonical_request(
            &req.method,
            &canonical_uri(&req.path),
            &canonical_query(&req.query_string),
            &hts,
            &payload_hash(&req),
        );
        let expected = "GET\n\
             /test.txt\n\
             \n\
             host:examplebucket.s3.amazonaws.com\n\
             range:bytes=0-9\n\
             x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n\
             x-amz-date:20130524T000000Z\n\
             \n\
             host;range;x-amz-content-sha256;x-amz-date\n\
             e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(cr, expected);
        // Documented hash of the canonical request.
        assert_eq!(
            sha256_hex(cr.as_bytes()),
            "7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972"
        );
    }

    #[test]
    fn test_aws_vector_string_to_sign() {
        let auth = parse_sigv4_auth(&header_auth_request()).unwrap();
        let req = header_auth_request();
        let hts = headers_to_sign(&req.headers, &auth.signed_headers).unwrap();
        let cr = canonical_request(
            &req.method,
            &canonical_uri(&req.path),
            &canonical_query(&req.query_string),
            &hts,
            &payload_hash(&req),
        );
        let sts = string_to_sign(&amz_date(&req).unwrap(), &auth.scope.scope_string(), &cr);
        assert_eq!(
            sts,
            "AWS4-HMAC-SHA256\n\
             20130524T000000Z\n\
             20130524/us-east-1/s3/aws4_request\n\
             7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972"
        );
    }

    #[test]
    fn test_aws_vector_signing_key_and_signature() {
        let auth = parse_sigv4_auth(&header_auth_request()).unwrap();
        let req = header_auth_request();
        let hts = headers_to_sign(&req.headers, &auth.signed_headers).unwrap();
        let cr = canonical_request(
            &req.method,
            &canonical_uri(&req.path),
            &canonical_query(&req.query_string),
            &hts,
            &payload_hash(&req),
        );
        let sig = compute_signature(SECRET, &auth.scope, &amz_date(&req).unwrap(), &cr);
        assert_eq!(
            sig,
            "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
    }

    #[test]
    fn test_verify_sigv4_header_auth() {
        assert_eq!(
            verify_sigv4(ACCESS, SECRET, &header_auth_request(), None, None),
            Ok(())
        );
    }

    #[test]
    fn test_verify_sigv4_rejects_wrong_secret() {
        assert_eq!(
            verify_sigv4(
                ACCESS,
                "not-the-secret",
                &header_auth_request(),
                None,
                None
            ),
            Err(SigAuthError::SignatureDoesNotMatch)
        );
    }

    #[test]
    fn test_verify_sigv4_rejects_wrong_access_key() {
        assert_eq!(
            verify_sigv4("SOMEONE_ELSE", SECRET, &header_auth_request(), None, None),
            Err(SigAuthError::SignatureDoesNotMatch)
        );
    }

    #[test]
    fn test_verify_sigv4_rejects_tampered_path() {
        let mut req = header_auth_request();
        req.path = "/tampered.txt".to_string();
        assert_eq!(
            verify_sigv4(ACCESS, SECRET, &req, None, None),
            Err(SigAuthError::SignatureDoesNotMatch)
        );
    }

    // The AWS documented presigned-URL (query auth) vector for the same
    // object, X-Amz-Expires=86400, SignedHeaders=host.
    fn query_auth_request() -> Request {
        let mut headers = HeaderKeyDict::new();
        headers.set("Host", "examplebucket.s3.amazonaws.com");
        let qs = "X-Amz-Algorithm=AWS4-HMAC-SHA256\
                  &X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request\
                  &X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host\
                  &X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404";
        Request {
            method: "GET".to_string(),
            path: "/test.txt".to_string(),
            query_string: qs.to_string(),
            headers,
            body: swift_http::Body::empty(),
        }
    }

    #[test]
    fn test_verify_sigv4_query_auth() {
        assert_eq!(
            verify_sigv4(ACCESS, SECRET, &query_auth_request(), None, None),
            Ok(())
        );
        assert_eq!(
            verify_sigv4(ACCESS, "wrong", &query_auth_request(), None, None),
            Err(SigAuthError::SignatureDoesNotMatch)
        );
    }

    #[test]
    fn parse_format_amz_date_roundtrip() {
        let ts = parse_amz_date("20130524T000000Z").unwrap();
        assert_eq!(format_amz_date(ts), "20130524T000000Z");
        assert_eq!(parse_amz_date(&format_amz_date(ts)), Some(ts));
        assert!(parse_amz_date("garbage").is_none());
    }

    #[test]
    fn empty_date_with_auto_amz_date_is_invalid_date() {
        // Official TestS3ApiServiceSigV4.test_service_error_no_date_header:
        // client sends Date="" / x-amz-date=""; boto2 still adds X-Amz-Date
        // and lists `date` in SignedHeaders.
        let mut headers = HeaderKeyDict::new();
        headers.set("Host", "10.0.0.10:8080");
        headers.set("X-Amz-Date", "20260818T160951Z");
        headers.set(
            "x-amz-content-sha256",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
        headers.set(
            "Authorization",
            "AWS4-HMAC-SHA256 \
             Credential=AKIAIOSFODNN7EXAMPLE/20260818/us-east-1/s3/aws4_request, \
             SignedHeaders=date;host;x-amz-content-sha256;x-amz-date, \
             Signature=deadbeef",
        );
        let req = Request {
            method: "GET".to_string(),
            path: "/".to_string(),
            query_string: String::new(),
            headers,
            body: swift_http::Body::empty(),
        };
        assert_eq!(
            check_sigv4_time(&req, 1_776_553_000, 900),
            Err(SigAuthError::InvalidDate)
        );
        assert_eq!(SigAuthError::InvalidDate.s3_code(), "AccessDenied");
        assert_eq!(
            SigAuthError::InvalidDate.s3_message(),
            Some("AWS authentication requires a valid Date or x-amz-date header")
        );
    }

    #[test]
    fn verify_sigv4_header_clock_skew_rejects() {
        let signed = parse_amz_date("20130524T000000Z").unwrap();
        assert_eq!(
            verify_sigv4(
                ACCESS,
                SECRET,
                &header_auth_request(),
                Some(signed + 3600),
                Some(900)
            ),
            Err(SigAuthError::RequestTimeTooSkewed)
        );
        assert_eq!(
            verify_sigv4(
                ACCESS,
                SECRET,
                &header_auth_request(),
                Some(signed + 900),
                Some(900)
            ),
            Ok(())
        );
        assert_sig_error_xml_matches_normalize(SigAuthError::RequestTimeTooSkewed, 403);
    }

    #[test]
    fn verify_sigv4_query_clock_skew_rejects() {
        let signed = parse_amz_date("20130524T000000Z").unwrap();
        // Still inside X-Amz-Expires=86400; only skew fires.
        assert_eq!(
            verify_sigv4(
                ACCESS,
                SECRET,
                &query_auth_request(),
                Some(signed + 3600),
                Some(900)
            ),
            Err(SigAuthError::RequestTimeTooSkewed)
        );
        assert_sig_error_xml_matches_normalize(SigAuthError::RequestTimeTooSkewed, 403);
    }

    #[test]
    fn query_expires_negative_is_authorization_query_parameters_error() {
        let mut req = query_auth_request();
        req.query_string = req
            .query_string
            .replace("X-Amz-Expires=86400", "X-Amz-Expires=-1");
        let signed = parse_amz_date("20130524T000000Z").unwrap();
        match check_sigv4_time(&req, signed, 900) {
            Err(SigAuthError::AuthorizationQueryParametersError(msg)) => {
                assert!(msg.contains("non-negative"), "{msg}");
            }
            other => panic!("expected query-param error, got {other:?}"),
        }
        assert_sig_error_xml_matches_normalize(
            SigAuthError::AuthorizationQueryParametersError(
                "X-Amz-Expires must be non-negative",
            ),
            400,
        );
    }

    fn query_expires_over_week_is_authorization_query_parameters_error() {
        let mut req = query_auth_request();
        req.query_string = req
            .query_string
            .replace("X-Amz-Expires=86400", "X-Amz-Expires=604801");
        let signed = parse_amz_date("20130524T000000Z").unwrap();
        match check_sigv4_time(&req, signed, 900) {
            Err(SigAuthError::AuthorizationQueryParametersError(msg)) => {
                assert!(msg.contains("604800"), "{msg}");
            }
            other => panic!("expected query-param error, got {other:?}"),
        }
    }

    fn query_expires_zero_is_access_denied_even_in_the_same_second() {
        let mut req = query_auth_request();
        req.query_string = req
            .query_string
            .replace("X-Amz-Expires=86400", "X-Amz-Expires=0");
        let signed = parse_amz_date("20130524T000000Z").unwrap();
        assert_eq!(
            check_sigv4_time(&req, signed, 900),
            Err(SigAuthError::AccessDenied)
        );
    }

    #[test]
    fn verify_sigv4_query_expired_access_denied() {
        let signed = parse_amz_date("20130524T000000Z").unwrap();
        // signed_at + 86400 < now, but |signed_at - now| is still < 900.
        assert_eq!(
            verify_sigv4(
                ACCESS,
                SECRET,
                &query_auth_request(),
                Some(signed + 86401),
                Some(90_000)
            ),
            Err(SigAuthError::AccessDenied)
        );
        assert_sig_error_xml_matches_normalize(SigAuthError::AccessDenied, 403);
    }

    #[test]
    fn test_canonical_query_sorted_and_encoded() {
        // '/' encoded as %2F, keys sorted, X-Amz-Signature excluded.
        let cq = canonical_query(
            "X-Amz-Signature=deadbeef&X-Amz-Date=20130524T000000Z\
             &X-Amz-Credential=AK%2F20130524%2Fus-east-1%2Fs3%2Faws4_request",
        );
        assert_eq!(
            cq,
            "X-Amz-Credential=AK%2F20130524%2Fus-east-1%2Fs3%2Faws4_request\
             &X-Amz-Date=20130524T000000Z"
        );
    }

    #[test]
    fn test_parse_credential() {
        let (access, scope) = parse_credential("AKID/20130524/us-east-1/s3/aws4_request").unwrap();
        assert_eq!(access, "AKID");
        assert_eq!(scope.date, "20130524");
        assert_eq!(scope.region, "us-east-1");
        assert_eq!(scope.service, "s3");
        assert_eq!(scope.terminal, "aws4_request");
        assert_eq!(scope.scope_string(), "20130524/us-east-1/s3/aws4_request");
        // malformed
        assert!(parse_credential("AKID/20130524/us-east-1/s3").is_none());
        assert!(parse_credential("/20130524/us-east-1/s3/aws4_request").is_none());
    }
}
