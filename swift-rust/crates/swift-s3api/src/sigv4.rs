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
//! What is NOT here: SigV2 (middleware returns stable `501 NotImplemented`).
//! Also deferred: clock-skew/expiry checks, and the Date-header-only
//! timestamp fallback (only `X-Amz-Date` is read).

use crate::crypto::{hmac_sha256, hmac_sha256_hex, sha256_hex, streq_const_time};
use swift_http::{parse_query, HeaderKeyDict, Request};

/// The AWS service name this endpoint signs for.
pub const SERVICE: &str = "s3";
/// The SigV4 algorithm identifier.
pub const ALGORITHM: &str = "AWS4-HMAC-SHA256";

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
/// `X-Amz-Date` header, else the `X-Amz-Date` query parameter.
pub fn amz_date(req: &Request) -> Option<String> {
    if let Some(d) = req.headers.get("X-Amz-Date") {
        return Some(d.to_string());
    }
    req.param("X-Amz-Date")
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
/// the presented access key. Returns true iff the request carries SigV4 auth,
/// its presented access key matches `access_key`, and the recomputed
/// signature matches the presented one (constant-time comparison).
///
/// Supports header auth and presigned-URL query auth. Does NOT perform
/// clock-skew, expiry, or `x-amz-content-sha256` payload validation — those
/// are separate checks in the full request lifecycle (deferred).
pub fn verify_sigv4(access_key: &str, secret_key: &str, req: &Request) -> bool {
    let auth = match parse_sigv4_auth(req) {
        Some(a) => a,
        None => return false,
    };
    if auth.access_key != access_key {
        return false;
    }
    let date = match amz_date(req) {
        Some(d) => d,
        None => return false,
    };
    let hts = match headers_to_sign(&req.headers, &auth.signed_headers) {
        Some(h) => h,
        None => return false,
    };
    let cr = canonical_request(
        &req.method,
        &canonical_uri(&req.path),
        &canonical_query(&req.query_string),
        &hts,
        &payload_hash(req),
    );
    let expected = compute_signature(secret_key, &auth.scope, &date, &cr);
    streq_const_time(&expected, &auth.signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    // The canonical AWS documented SigV4 test vector: "GET Object" for
    // examplebucket/test.txt.
    // Source: AWS S3 API reference, "Examples of signature calculations".
    const ACCESS: &str = "AKIAIOSFODNN7EXAMPLE";
    const SECRET: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

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
        assert!(verify_sigv4(ACCESS, SECRET, &header_auth_request()));
    }

    #[test]
    fn test_verify_sigv4_rejects_wrong_secret() {
        assert!(!verify_sigv4(
            ACCESS,
            "not-the-secret",
            &header_auth_request()
        ));
    }

    #[test]
    fn test_verify_sigv4_rejects_wrong_access_key() {
        assert!(!verify_sigv4(
            "SOMEONE_ELSE",
            SECRET,
            &header_auth_request()
        ));
    }

    #[test]
    fn test_verify_sigv4_rejects_tampered_path() {
        let mut req = header_auth_request();
        req.path = "/tampered.txt".to_string();
        assert!(!verify_sigv4(ACCESS, SECRET, &req));
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
        assert!(verify_sigv4(ACCESS, SECRET, &query_auth_request()));
        assert!(!verify_sigv4(ACCESS, "wrong", &query_auth_request()));
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
