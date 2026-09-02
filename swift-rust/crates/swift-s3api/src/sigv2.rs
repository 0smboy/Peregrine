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

//! AWS Signature Version 2 for the S3 API.
//!
//! Ported from the SigV2 path in OpenStack Swift `s3api` /
//! `s3request.py` (`SigCheckerV2`) and the AWS REST authentication docs.
//!
//! # Wire forms
//!
//! * **Header:** `Authorization: AWS <AccessKeyId>:<Signature>`
//! * **Query:** `AWSAccessKeyId`, `Signature`, `Expires` (optional `SecurityToken`)
//!
//! # String-to-sign
//!
//! ```text
//! HTTP-Verb + "\n" +
//! Content-MD5 + "\n" +
//! Content-Type + "\n" +
//! Date (or Expires for query auth) + "\n" +
//! CanonicalizedAmzHeaders +
//! CanonicalizedResource
//! ```
//!
//! Signature = Base64(HMAC-SHA1(SecretAccessKey, UTF-8(StringToSign))).

use sha1::{Digest, Sha1};
use swift_http::{parse_http_date, Request};

use crate::crypto::streq_const_time;
use crate::sigv4::{canonical_uri, parse_amz_date, SigAuthError};

/// Parsed SigV2 auth material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigV2Auth {
    pub access_key: String,
    /// Base64 signature as presented by the client (whitespace stripped).
    pub signature: String,
    /// True for query-string auth (`AWSAccessKeyId` + `Signature`).
    pub query_auth: bool,
    /// Unix expiry for query auth (`Expires`); `None` for header auth.
    pub expires: Option<i64>,
}

/// Parse `Authorization: AWS <key>:<signature>`.
///
/// Access keys may contain colons (TempAuth `account:user`); only the **last**
/// colon separates key from signature.
pub fn parse_authorization_header_v2(auth: &str) -> Option<SigV2Auth> {
    let auth = auth.trim();
    if !auth.starts_with("AWS ") || auth.starts_with("AWS4-") {
        return None;
    }
    let rest = auth[4..].trim();
    let colon = rest.rfind(':')?;
    let access_key = rest[..colon].trim();
    let signature = rest[colon + 1..].trim();
    if access_key.is_empty() || signature.is_empty() {
        return None;
    }
    Some(SigV2Auth {
        access_key: access_key.to_string(),
        signature: signature.to_string(),
        query_auth: false,
        expires: None,
    })
}

/// Parse query-string SigV2 (`AWSAccessKeyId`, `Signature`, optional `Expires`).
pub fn parse_query_authentication_v2(params: &[(String, String)]) -> Option<SigV2Auth> {
    let get = |name: &str| {
        params
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
    };
    let access_key = get("AWSAccessKeyId")?;
    let signature = get("Signature")?;
    if access_key.is_empty() || signature.is_empty() {
        return None;
    }
    // Presence of X-Amz-Algorithm=AWS4… means SigV4 query, not v2.
    if get("X-Amz-Algorithm")
        .as_deref()
        .map(|a| a.starts_with("AWS4"))
        .unwrap_or(false)
    {
        return None;
    }
    let expires = get("Expires").and_then(|s| s.parse::<i64>().ok());
    Some(SigV2Auth {
        access_key,
        signature,
        query_auth: true,
        expires,
    })
}

/// Detect and parse SigV2 from header or query.
pub fn parse_sigv2_auth(req: &Request) -> Option<SigV2Auth> {
    if let Some(auth) = req.headers.get("Authorization") {
        if let Some(v2) = parse_authorization_header_v2(auth) {
            return Some(v2);
        }
    }
    parse_query_authentication_v2(&req.params())
}

/// True when the request carries SigV2 auth material.
pub fn is_sigv2_auth(req: &Request) -> bool {
    parse_sigv2_auth(req).is_some()
}

/// Subresources that participate in the CanonicalizedResource (AWS docs).
const SIGNED_SUBRESOURCES: &[&str] = &[
    "acl",
    "cors",
    "delete",
    "lifecycle",
    "location",
    "logging",
    "notification",
    "partNumber",
    "policy",
    "requestPayment",
    "response-cache-control",
    "response-content-disposition",
    "response-content-encoding",
    "response-content-language",
    "response-content-type",
    "response-expires",
    "restore",
    "tagging",
    "torrent",
    "uploadId",
    "uploads",
    "versionId",
    "versioning",
    "versions",
    "website",
];

/// CanonicalizedAmzHeaders: sorted lower-case `x-amz-*` headers, each
/// `name:value\n`, multi-values comma-joined.
pub fn canonicalized_amz_headers(req: &Request) -> String {
    let mut pairs: Vec<(String, String)> = Vec::new();
    for (k, v) in req.headers.iter() {
        let kl = k.to_ascii_lowercase();
        if kl.starts_with("x-amz-") {
            pairs.push((kl, normalize_header_value(v)));
        }
    }
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    // Merge duplicates (AWS: values for same header comma-joined).
    let mut merged: Vec<(String, String)> = Vec::new();
    for (k, v) in pairs {
        if let Some(last) = merged.last_mut() {
            if last.0 == k {
                last.1.push(',');
                last.1.push_str(&v);
                continue;
            }
        }
        merged.push((k, v));
    }
    let mut out = String::new();
    for (k, v) in merged {
        out.push_str(&k);
        out.push(':');
        out.push_str(&v);
        out.push('\n');
    }
    out
}

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

/// CanonicalizedResource for SigV2.
///
/// Python s3api uses `wsgi_quote(PATH_INFO, safe='-_.~/')` — the decoded
/// path re-encoded. Spaces / `%` / unicode must match boto's URI encoding
/// or `test_object` 403s with SignatureDoesNotMatch.
pub fn canonicalized_resource(req: &Request) -> String {
    let mut resource = canonical_uri(&req.path);
    if resource.is_empty() {
        resource = "/".into();
    }
    // Ensure leading slash.
    if !resource.starts_with('/') {
        resource.insert(0, '/');
    }
    let params = req.params();
    let mut subs: Vec<(String, String)> = Vec::new();
    for (k, v) in &params {
        if SIGNED_SUBRESOURCES
            .iter()
            .any(|s| s.eq_ignore_ascii_case(k))
        {
            subs.push((k.clone(), v.clone()));
        }
    }
    // Also include override response headers already covered above.
    subs.sort_by_key(|a| a.0.to_ascii_lowercase());
    if !subs.is_empty() {
        resource.push('?');
        for (i, (k, v)) in subs.iter().enumerate() {
            if i > 0 {
                resource.push('&');
            }
            resource.push_str(k);
            if !v.is_empty() {
                resource.push('=');
                resource.push_str(v);
            }
        }
    }
    resource
}

/// Date field for the string-to-sign.
///
/// Header auth: empty if any `x-amz-date` is present (date moves into amz
/// headers); else `Date` header. Query auth: `Expires` value as string.
pub fn date_for_string_to_sign(req: &Request, auth: &SigV2Auth) -> String {
    if auth.query_auth {
        return auth
            .expires
            .map(|e| e.to_string())
            .or_else(|| {
                req.params()
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("Expires"))
                    .map(|(_, v)| v.clone())
            })
            .unwrap_or_default();
    }
    // Header: if x-amz-date present, Date slot is empty.
    let has_amz_date = req.headers.iter().any(|(k, _)| {
        let kl = k.to_ascii_lowercase();
        kl == "x-amz-date"
    }) || req.headers.get("x-amz-date").is_some()
        || req.headers.get("X-Amz-Date").is_some();
    // Check any x-amz-date via iter (case-insensitive get may work too).
    let has_amz_date = has_amz_date
        || req
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("x-amz-date"));
    if has_amz_date {
        return String::new();
    }
    req.headers
        .get("Date")
        .or_else(|| req.headers.get("date"))
        .unwrap_or("")
        .to_string()
}

/// Build the SigV2 string-to-sign.
pub fn string_to_sign_v2(req: &Request, auth: &SigV2Auth) -> String {
    let method = req.method.to_ascii_uppercase();
    let md5 = req
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-md5"))
        .map(|(_, v)| v.to_string())
        .unwrap_or_default();
    let ctype = req
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.to_string())
        .unwrap_or_default();
    let date = date_for_string_to_sign(req, auth);
    let amz = canonicalized_amz_headers(req);
    let resource = canonicalized_resource(req);
    format!("{method}\n{md5}\n{ctype}\n{date}\n{amz}{resource}")
}

/// HMAC-SHA1 raw digest (20 bytes).
pub fn hmac_sha1(key: &[u8], msg: &[u8]) -> [u8; 20] {
    const BLOCK: usize = 64;
    let mut key = key.to_vec();
    if key.len() > BLOCK {
        key = Sha1::digest(&key).to_vec();
    }
    if key.len() < BLOCK {
        key.resize(BLOCK, 0);
    }
    let ipad: Vec<u8> = key.iter().map(|b| b ^ 0x36).collect();
    let opad: Vec<u8> = key.iter().map(|b| b ^ 0x5c).collect();

    let mut inner = Sha1::new();
    inner.update(&ipad);
    inner.update(msg);
    let inner_digest = inner.finalize();

    let mut outer = Sha1::new();
    outer.update(&opad);
    outer.update(inner_digest);
    let mut out = [0u8; 20];
    out.copy_from_slice(&outer.finalize());
    out
}

/// Standard Base64 encode (no line wraps).
pub fn base64_encode(data: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    let mut i = 0;
    while i + 3 <= data.len() {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8) | (data[i + 2] as u32);
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 6) & 0x3f) as usize] as char);
        out.push(TABLE[(n & 0x3f) as usize] as char);
        i += 3;
    }
    let rem = data.len() - i;
    if rem == 1 {
        let n = (data[i] as u32) << 16;
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        out.push('=');
        out.push('=');
    } else if rem == 2 {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8);
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 6) & 0x3f) as usize] as char);
        out.push('=');
    }
    out
}

/// Compute Base64(HMAC-SHA1(secret, string_to_sign)).
pub fn compute_signature_v2(secret: &str, string_to_sign: &str) -> String {
    let dig = hmac_sha1(secret.as_bytes(), string_to_sign.as_bytes());
    base64_encode(&dig)
}

/// Header Date / `X-Amz-Date` used as the V2 signing timestamp.
///
/// Experimental: RFC 1123 first, then `YYYYMMDDThhmmssZ`. Not AWS-complete.
pub fn signing_ts_v2_header(req: &Request) -> Option<i64> {
    let raw = req
        .headers
        .get("X-Amz-Date")
        .or_else(|| req.headers.get("Date"))?;
    parse_http_date(raw).or_else(|| parse_amz_date(raw))
}

/// Clock-skew (header) + query `Expires`. Experimental: not live-proven.
///
/// Query `Expires < now` → `AccessDenied` (not `SignatureDoesNotMatch`).
/// Header `abs(signing_ts - now) > allowable_clock_skew` →
/// `RequestTimeTooSkewed`. Query auth does **not** reuse `Expires` as a
/// clock-skew timestamp.
pub fn check_sigv2_time(
    req: &Request,
    now_unix: i64,
    allowable_clock_skew: u64,
) -> Result<(), SigAuthError> {
    let Some(auth) = parse_sigv2_auth(req) else {
        return Ok(());
    };
    if auth.query_auth {
        if let Some(exp) = auth.expires {
            if exp < now_unix {
                return Err(SigAuthError::AccessDenied);
            }
            // Python: Expires >= 2^31 is AccessDenied "Invalid date (should
            // be seconds since epoch)" — official test_expiration_limits V2
            // uses expires_in=2**32.
            if exp >= (1 << 31) {
                return Err(SigAuthError::AccessDeniedInvalidExpires);
            }
        }
        return Ok(());
    }
    if header_date_missing(req) {
        return Err(SigAuthError::InvalidDate);
    }
    // Python `signing_timestamp`: unparseable or ts < 0 → AccessDenied
    // (InvalidDate), not SignatureDoesNotMatch / RequestTimeTooSkewed.
    match signing_ts_v2_header(req) {
        None => Err(SigAuthError::InvalidDate),
        Some(ts) if ts < 0 => Err(SigAuthError::InvalidDate),
        Some(ts) if ts.abs_diff(now_unix) > allowable_clock_skew => {
            Err(SigAuthError::RequestTimeTooSkewed)
        }
        Some(_) => Ok(()),
    }
}

fn header_date_missing(req: &Request) -> bool {
    let date_empty = req
        .headers
        .get("Date")
        .or_else(|| req.headers.get("date"))
        .map(|v| v.trim().is_empty())
        .unwrap_or(true);
    let amz_empty = !req
        .headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("x-amz-date") && !v.trim().is_empty());
    date_empty && amz_empty
}

/// Verify SigV2 signature against credentials.
///
/// When `now_unix` is `Some`, query `Expires < now` is `AccessDenied` and
/// header clock skew is `RequestTimeTooSkewed`. Experimental: not
/// live-proven. Not AWS-complete.
pub fn verify_sigv2(
    access_key: &str,
    secret_key: &str,
    req: &Request,
    now_unix: Option<i64>,
    allowable_clock_skew: Option<u64>,
) -> Result<(), SigAuthError> {
    let auth = match parse_sigv2_auth(req) {
        Some(a) => a,
        None => return Err(SigAuthError::SignatureDoesNotMatch),
    };
    if auth.access_key != access_key {
        return Err(SigAuthError::SignatureDoesNotMatch);
    }
    if let Some(now) = now_unix {
        check_sigv2_time(req, now, allowable_clock_skew.unwrap_or(u64::MAX))?;
    }
    let sts = string_to_sign_v2(req, &auth);
    let expected = compute_signature_v2(secret_key, &sts);
    // Clients may URL-encode `+` / `/` in query signatures; compare both raw
    // and a lightly unescaped form.
    let presented = auth.signature.replace(' ', "+");
    if streq_const_time(&expected, &presented)
        || streq_const_time(&expected, &url_decode_basic(&presented))
    {
        Ok(())
    } else {
        Err(SigAuthError::SignatureDoesNotMatch)
    }
}

fn url_decode_basic(s: &str) -> String {
    // Minimal: + → space is wrong for base64; only %XX
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let h = || -> Option<u8> {
                let hi = hex_nibble(bytes[i + 1])?;
                let lo = hex_nibble(bytes[i + 2])?;
                Some((hi << 4) | lo)
            };
            if let Some(b) = h() {
                out.push(b as char);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// String-to-sign bytes for Keystone `/v3/s3tokens` deferral (UTF-8).
pub fn string_to_sign_for_request_v2(req: &Request) -> Option<String> {
    let auth = parse_sigv2_auth(req)?;
    Some(string_to_sign_v2(req, &auth))
}

#[cfg(test)]
mod tests {
    use super::*;
    use swift_http::{Body, HeaderKeyDict};

    fn assert_sig_error_xml_matches_normalize(err: SigAuthError, status: u16) {
        let resp = crate::response::s3_error_response(err.s3_code(), err.s3_message(), &[]);
        assert_eq!(resp.status, status, "{}", err.s3_code());
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        let msg = err
            .s3_message()
            .unwrap_or(crate::response::error_status_and_message(err.s3_code()).1);
        crate::response::assert_error_xml_matches_normalize(&body, err.s3_code(), msg);
    }

    // AWS documented SigV2 example (GET Object):
    // https://docs.aws.amazon.com/AmazonS3/latest/userguide/RESTAuthentication.html
    const SECRET: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    const ACCESS: &str = "AKIAIOSFODNN7EXAMPLE";

    fn aws_vector_req() -> Request {
        let mut headers = HeaderKeyDict::new();
        headers.set("Host", "johnsmith.s3.amazonaws.com");
        headers.set("Date", "Tue, 27 Mar 2007 19:36:42 +0000");
        Request {
            method: "GET".into(),
            path: "/photos/puppy.jpg".into(),
            query_string: String::new(),
            headers,
            body: Body::empty(),
        }
    }

    #[test]
    fn string_to_sign_sees_lowercase_content_md5() {
        let mut headers = HeaderKeyDict::new();
        headers.set("content-md5", "abcdefghijklmnop1234==");
        headers.set("Date", "Tue, 27 Mar 2007 19:36:42 +0000");
        headers.set("Authorization", "AWS AKID:sig");
        let req = Request {
            method: "PUT".into(),
            path: "/b/o".into(),
            query_string: String::new(),
            headers,
            body: Body::empty(),
        };
        let auth = parse_sigv2_auth(&req).unwrap();
        let sts = string_to_sign_v2(&req, &auth);
        assert!(
            sts.contains("abcdefghijklmnop1234=="),
            "content-md5 must enter the v2 string-to-sign: {sts}"
        );
    }

    #[test]
    fn aws_vector_string_to_sign_and_signature() {
        // Virtual-host style: CanonicalizedResource includes bucket.
        // AWS example uses resource `/johnsmith/photos/puppy.jpg`.
        let mut req = aws_vector_req();
        req.path = "/johnsmith/photos/puppy.jpg".into();
        let auth = SigV2Auth {
            access_key: ACCESS.into(),
            signature: "bWq2s1WEIj+Ydj0vQ697zp+IXMU=".into(),
            query_auth: false,
            expires: None,
        };
        let sts = string_to_sign_v2(&req, &auth);
        assert_eq!(
            sts,
            "GET\n\n\nTue, 27 Mar 2007 19:36:42 +0000\n/johnsmith/photos/puppy.jpg"
        );
        let sig = compute_signature_v2(SECRET, &sts);
        assert_eq!(sig, "bWq2s1WEIj+Ydj0vQ697zp+IXMU=");
        // Attach Authorization and verify end-to-end.
        req.headers
            .set("Authorization", format!("AWS {ACCESS}:{sig}"));
        assert_eq!(verify_sigv2(ACCESS, SECRET, &req, None, None), Ok(()));
    }

    #[test]
    fn parse_header_with_colon_in_access_key() {
        let a = parse_authorization_header_v2("AWS test:tester:abc+def/ghi=").unwrap();
        assert_eq!(a.access_key, "test:tester");
        assert_eq!(a.signature, "abc+def/ghi=");
        assert!(!a.query_auth);
    }

    #[test]
    fn parse_query_auth() {
        let a = parse_query_authentication_v2(&[
            ("AWSAccessKeyId".into(), "test:tester".into()),
            ("Expires".into(), "2000000000".into()),
            ("Signature".into(), "abc+def=".into()),
        ])
        .unwrap();
        assert_eq!(a.access_key, "test:tester");
        assert_eq!(a.expires, Some(2_000_000_000));
        assert!(a.query_auth);
    }

    #[test]
    fn rejected_signature() {
        let mut req = aws_vector_req();
        req.path = "/johnsmith/photos/puppy.jpg".into();
        req.headers.set(
            "Authorization",
            format!("AWS {ACCESS}:wrongsig============"),
        );
        assert_eq!(
            verify_sigv2(ACCESS, SECRET, &req, None, None),
            Err(SigAuthError::SignatureDoesNotMatch)
        );
    }

    #[test]
    fn query_auth_expires_past_i32_is_invalid_date() {
        let mut req = aws_vector_req();
        req.path = "/johnsmith/photos/puppy.jpg".into();
        let exp: i64 = 1 << 31;
        let auth = SigV2Auth {
            access_key: ACCESS.into(),
            signature: String::new(),
            query_auth: true,
            expires: Some(exp),
        };
        let sts = string_to_sign_v2(&req, &auth);
        let sig = compute_signature_v2(SECRET, &sts);
        req.query_string = format!("AWSAccessKeyId={ACCESS}&Expires={exp}&Signature={sig}");
        assert_eq!(
            verify_sigv2(ACCESS, SECRET, &req, Some(1_700_000_000), None),
            Err(SigAuthError::AccessDeniedInvalidExpires)
        );
        assert_sig_error_xml_matches_normalize(SigAuthError::AccessDeniedInvalidExpires, 403);
    }

    fn query_auth_expired_fails() {
        let mut req = aws_vector_req();
        req.path = "/johnsmith/photos/puppy.jpg".into();
        let auth = SigV2Auth {
            access_key: ACCESS.into(),
            signature: String::new(),
            query_auth: true,
            expires: Some(100),
        };
        let sts = string_to_sign_v2(&req, &auth);
        let sig = compute_signature_v2(SECRET, &sts);
        req.query_string = format!(
            "AWSAccessKeyId={ACCESS}&Expires=100&Signature={}",
            // keep + unescaped for unit path
            sig.replace('+', "%2B").replace('=', "%3D")
        );
        // Rebuild with raw signature in params via header path alternative:
        req.query_string = format!("AWSAccessKeyId={ACCESS}&Expires=100&Signature={sig}");
        // parse may leave + as-is
        assert_eq!(
            verify_sigv2(ACCESS, SECRET, &req, Some(200), None),
            Err(SigAuthError::AccessDenied)
        );
    }

    #[test]
    fn verify_sigv2_unparseable_date_is_invalid_date() {
        let mut req = aws_vector_req();
        req.headers.set("Date", "Bad Date");
        req.headers
            .set("Authorization", format!("AWS {ACCESS}:abcd"));
        assert_eq!(
            verify_sigv2(ACCESS, SECRET, &req, Some(1_000_000), Some(900)),
            Err(SigAuthError::InvalidDate)
        );
    }

    #[test]
    fn verify_sigv2_empty_date_is_invalid_date() {
        let mut req = aws_vector_req();
        req.headers.set("Date", "");
        req.headers
            .set("Authorization", format!("AWS {ACCESS}:abcd"));
        assert_eq!(
            verify_sigv2(ACCESS, SECRET, &req, Some(1_000_000), Some(900)),
            Err(SigAuthError::InvalidDate)
        );
    }

    #[test]
    fn verify_sigv2_before_epoch_date_is_invalid_date() {
        let mut req = aws_vector_req();
        req.headers.set("Date", "Sun, 01 Jan 1950 00:00:00 +0000");
        req.headers
            .set("Authorization", format!("AWS {ACCESS}:abcd"));
        let err = verify_sigv2(ACCESS, SECRET, &req, Some(1_000_000), Some(900));
        assert_eq!(err, Err(SigAuthError::InvalidDate), "{err:?}");
        assert_ne!(err, Err(SigAuthError::RequestTimeTooSkewed));
    }

    #[test]
    fn verify_sigv2_header_clock_skew_rejects() {
        let mut req = aws_vector_req();
        req.path = "/johnsmith/photos/puppy.jpg".into();
        let auth = SigV2Auth {
            access_key: ACCESS.into(),
            signature: String::new(),
            query_auth: false,
            expires: None,
        };
        let sts = string_to_sign_v2(&req, &auth);
        let sig = compute_signature_v2(SECRET, &sts);
        req.headers
            .set("Authorization", format!("AWS {ACCESS}:{sig}"));
        let signed = parse_http_date("Tue, 27 Mar 2007 19:36:42 +0000").unwrap();
        assert_eq!(
            verify_sigv2(ACCESS, SECRET, &req, Some(signed + 3600), Some(900)),
            Err(SigAuthError::RequestTimeTooSkewed)
        );
        assert_eq!(
            verify_sigv2(ACCESS, SECRET, &req, Some(signed), Some(900)),
            Ok(())
        );
        assert_sig_error_xml_matches_normalize(SigAuthError::RequestTimeTooSkewed, 403);
    }

    #[test]
    fn verify_sigv2_query_expired_is_access_denied_not_bad_hmac() {
        let mut req = aws_vector_req();
        req.path = "/johnsmith/photos/puppy.jpg".into();
        let auth = SigV2Auth {
            access_key: ACCESS.into(),
            signature: String::new(),
            query_auth: true,
            expires: Some(100),
        };
        let sts = string_to_sign_v2(&req, &auth);
        let sig = compute_signature_v2(SECRET, &sts);
        req.query_string = format!("AWSAccessKeyId={ACCESS}&Expires=100&Signature={sig}");
        assert_eq!(
            verify_sigv2(ACCESS, SECRET, &req, Some(200), Some(900)),
            Err(SigAuthError::AccessDenied)
        );
        assert_ne!(
            verify_sigv2(ACCESS, SECRET, &req, Some(200), Some(900)),
            Err(SigAuthError::SignatureDoesNotMatch)
        );
        assert_sig_error_xml_matches_normalize(SigAuthError::AccessDenied, 403);
    }

    #[test]
    fn canonical_resource_quotes_space_percent_and_unicode() {
        let mut req = aws_vector_req();
        req.path = "/bucket/object name with %-sign 🙂".into();
        assert_eq!(
            canonicalized_resource(&req),
            "/bucket/object%20name%20with%20%25-sign%20%F0%9F%99%82"
        );
    }

    #[test]
    fn amz_headers_sorted_into_string_to_sign() {
        let mut headers = HeaderKeyDict::new();
        headers.set("Date", "Tue, 27 Mar 2007 19:36:42 +0000");
        headers.set("x-amz-meta-color", "blue");
        headers.set("x-amz-acl", "public-read");
        let req = Request {
            method: "PUT".into(),
            path: "/bucket/key".into(),
            query_string: String::new(),
            headers,
            body: Body::empty(),
        };
        let auth = SigV2Auth {
            access_key: "k".into(),
            signature: "s".into(),
            query_auth: false,
            expires: None,
        };
        let sts = string_to_sign_v2(&req, &auth);
        // x-amz-acl before x-amz-meta-color; Date present (no x-amz-date).
        assert!(sts.contains("x-amz-acl:public-read\nx-amz-meta-color:blue\n/bucket/key"));
    }

    #[test]
    fn base64_encode_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
    }
}
