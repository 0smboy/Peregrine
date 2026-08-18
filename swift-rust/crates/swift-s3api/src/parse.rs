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

//! S3 request path parsing: path-style vs virtual-host bucket extraction,
//! bucket-name validation and the S3 -> Swift path mapping.
//!
//! Ported from `swift/common/middleware/s3api/utils.py` (`parse_host`,
//! `parse_path`, `extract_bucket_and_key`, `validate_bucket_name`) and the
//! `to_swift_req` path construction in `s3request.py`.

use swift_http::{split_path, Request};

/// Container suffix used by the multipart-upload machinery. Kept here for
/// reference; multipart is otherwise deferred.
pub const MULTIUPLOAD_SUFFIX: &str = "+segments";

/// Validate an S3 bucket name.
///
/// Port of `validate_bucket_name`. Returns true if valid. With
/// `dns_compliant` true the DNS rules apply (3..=63 chars, no adjacent
/// `.`/`-` combinations, no leading/trailing non-alphanumerics); otherwise
/// the looser legacy rules apply (3..=255 chars, upper-case and `_` allowed).
pub fn validate_bucket_name(name: &str, dns_compliant: bool) -> bool {
    let max_len = if dns_compliant { 63 } else { 255 };
    let bytes = name.as_bytes();

    if name.len() < 3 || name.len() > max_len {
        return false;
    }
    // name[0].isalnum()
    if !bytes[0].is_ascii_alphanumeric() {
        return false;
    }
    if dns_compliant
        && (name.contains(".-")
            || name.contains("-.")
            || name.contains("..")
            || !bytes[bytes.len() - 1].is_ascii_alphanumeric())
    {
        return false;
    }
    if name.ends_with('.') {
        return false;
    }
    if looks_like_ipv4(name) {
        return false;
    }
    // re.match("^[<valid_chars>]*$"): lowercase letters, digits, '-', '.',
    // plus (non-dns only) upper-case letters and '_'.
    name.bytes().all(|b| {
        b.is_ascii_lowercase()
            || b.is_ascii_digit()
            || b == b'-'
            || b == b'.'
            || (!dns_compliant && (b.is_ascii_uppercase() || b == b'_'))
    })
}

/// True if `name` is formatted as a dotted-quad IPv4 address (no leading
/// zeros, each octet 0..=255), matching the regex in `validate_bucket_name`.
fn looks_like_ipv4(name: &str) -> bool {
    let octets: Vec<&str> = name.split('.').collect();
    if octets.len() != 4 {
        return false;
    }
    octets.iter().all(|o| {
        let b = o.as_bytes();
        if b.is_empty() || b.len() > 3 || !b.iter().all(u8::is_ascii_digit) {
            return false;
        }
        // no leading zero unless the octet is exactly "0"
        if b.len() > 1 && b[0] == b'0' {
            return false;
        }
        o.parse::<u16>().map(|v| v <= 255).unwrap_or(false)
    })
}

/// Port of `parse_host`: given the `Host` header value (or `SERVER_NAME`) and
/// the configured `storage_domains`, return the bucket name embedded as the
/// leading label of the host, or `None`.
///
/// Note: like the Python, a host that is exactly a storage domain yields an
/// empty bucket string (`Some("")`); callers treat that as "no bucket".
pub fn parse_host(host: Option<&str>, storage_domains: &[String]) -> Option<String> {
    let given = host?;
    // strip a :port suffix
    let given = match given.rsplit_once(':') {
        Some((h, _)) => h,
        None => given,
    };
    for sd in storage_domains {
        let dotted = if sd.starts_with('.') {
            sd.clone()
        } else {
            format!(".{sd}")
        };
        if given.ends_with(&dotted) {
            return Some(given[..given.len() - dotted.len()].to_string());
        }
    }
    None
}

/// Extract `(bucket, key)` from a request, supporting both virtual-host style
/// (bucket in `Host`) and path style (`/bucket/key`).
///
/// Port of `extract_bucket_and_key` + `parse_path`. Returns `(None, None)` if
/// the path is unparseable or the path-style bucket name is invalid (the
/// Python swallows `InvalidBucketNameParseError`/`InvalidURIParseError`).
///
/// The returned bucket is `None` for a service request (path `/`); the key is
/// `None` when only a bucket is addressed.
pub fn extract_bucket_and_key(
    req: &Request,
    storage_domains: &[String],
    dns_compliant: bool,
) -> (Option<String>, Option<String>) {
    // Virtual-host style: a non-empty bucket label on the host wins.
    let bucket_in_host =
        parse_host(req.headers.get("Host"), storage_domains).filter(|b| !b.is_empty());
    if let Some(bucket) = bucket_in_host {
        let obj = if req.path.len() > 1 {
            Some(req.path[1..].to_string())
        } else {
            None
        };
        return (Some(bucket), obj);
    }

    // Path style: split_path(path, 0, 2, rest_with_last=True).
    let parts = match split_path(&req.path, 0, 2, true) {
        Ok(p) => p,
        Err(_) => return (None, None),
    };
    let bucket = parts.first().cloned().flatten().filter(|b| !b.is_empty());
    // s3cmd 2.4 path-style List/Create uses `/bucket/` (empty object name).
    // That is a bucket request, not GetObject of "". Empty key → None.
    let key = parts.get(1).cloned().flatten().filter(|k| !k.is_empty());

    if let Some(b) = &bucket {
        if !validate_bucket_name(b, dns_compliant) {
            return (None, None);
        }
    }
    (bucket, key)
}

/// Map an S3 `(account, bucket, key)` to the Swift back-end path.
///
/// Port of the `to_swift_req` path construction:
/// * `key`    -> `/v1/<account>/<bucket>/<key>`
/// * `bucket` -> `/v1/<account>/<bucket>`
/// * neither  -> `/v1/<account>`
///
/// Empty bucket/key are treated as absent, matching the Python truthiness
/// checks (`if obj:` / `elif container:`).
pub fn s3_to_swift_path(account: &str, bucket: Option<&str>, key: Option<&str>) -> String {
    let bucket = bucket.filter(|b| !b.is_empty());
    let key = key.filter(|k| !k.is_empty());
    match (bucket, key) {
        (Some(b), Some(k)) => format!("/v1/{account}/{b}/{k}"),
        (Some(b), None) => format!("/v1/{account}/{b}"),
        _ => format!("/v1/{account}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use swift_http::HeaderKeyDict;

    fn req(method: &str, path: &str, host: Option<&str>) -> Request {
        let mut headers = HeaderKeyDict::new();
        if let Some(h) = host {
            headers.set("Host", h);
        }
        Request {
            method: method.to_string(),
            path: path.to_string(),
            query_string: String::new(),
            headers,
            body: swift_http::Body::empty(),
        }
    }

    #[test]
    fn test_path_style_bucket_and_key() {
        let r = req("GET", "/mybucket/path/to/obj", None);
        let (b, k) = extract_bucket_and_key(&r, &[], true);
        assert_eq!(b.as_deref(), Some("mybucket"));
        assert_eq!(k.as_deref(), Some("path/to/obj"));
    }

    #[test]
    fn test_path_style_bucket_only() {
        let r = req("GET", "/mybucket", None);
        let (b, k) = extract_bucket_and_key(&r, &[], true);
        assert_eq!(b.as_deref(), Some("mybucket"));
        assert_eq!(k, None);
    }

    #[test]
    fn test_path_style_bucket_trailing_slash_is_bucket_only() {
        // s3cmd 2.4.0: GET /mytest/ must list, not GetObject "".
        let r = req("GET", "/mybucket/", None);
        let (b, k) = extract_bucket_and_key(&r, &[], true);
        assert_eq!(b.as_deref(), Some("mybucket"));
        assert_eq!(k, None);
    }

    #[test]
    fn test_path_style_service_request() {
        let r = req("GET", "/", None);
        let (b, k) = extract_bucket_and_key(&r, &[], true);
        assert_eq!(b, None);
        assert_eq!(k, None);
    }

    #[test]
    fn test_vhost_style() {
        let domains = vec!["s3.example.com".to_string()];
        // bucket + key
        let r = req("GET", "/path/to/obj", Some("mybucket.s3.example.com"));
        let (b, k) = extract_bucket_and_key(&r, &domains, true);
        assert_eq!(b.as_deref(), Some("mybucket"));
        assert_eq!(k.as_deref(), Some("path/to/obj"));

        // bucket only (root path)
        let r = req("GET", "/", Some("mybucket.s3.example.com"));
        let (b, k) = extract_bucket_and_key(&r, &domains, true);
        assert_eq!(b.as_deref(), Some("mybucket"));
        assert_eq!(k, None);

        // host == storage domain -> no vhost bucket, falls back to path style
        let r = req("GET", "/pathbucket/o", Some("s3.example.com"));
        let (b, k) = extract_bucket_and_key(&r, &domains, true);
        assert_eq!(b.as_deref(), Some("pathbucket"));
        assert_eq!(k.as_deref(), Some("o"));
    }

    #[test]
    fn test_vhost_port_stripped() {
        let domains = vec![".s3.example.com".to_string()];
        let r = req("GET", "/o", Some("bkt.s3.example.com:8080"));
        let (b, _k) = extract_bucket_and_key(&r, &domains, true);
        assert_eq!(b.as_deref(), Some("bkt"));
    }

    #[test]
    fn test_invalid_path_style_bucket_name() {
        // Upper-case is invalid under DNS-compliant rules -> (None, None).
        let r = req("GET", "/BadBucket/o", None);
        let (b, k) = extract_bucket_and_key(&r, &[], true);
        assert_eq!(b, None);
        assert_eq!(k, None);
        // ...but valid under legacy rules.
        let r = req("GET", "/BadBucket/o", None);
        let (b, k) = extract_bucket_and_key(&r, &[], false);
        assert_eq!(b.as_deref(), Some("BadBucket"));
        assert_eq!(k.as_deref(), Some("o"));
    }

    #[test]
    fn test_s3_to_swift_path() {
        assert_eq!(
            s3_to_swift_path("AUTH_test", Some("bucket"), Some("obj")),
            "/v1/AUTH_test/bucket/obj"
        );
        assert_eq!(
            s3_to_swift_path("AUTH_test", Some("bucket"), Some("dir/obj")),
            "/v1/AUTH_test/bucket/dir/obj"
        );
        assert_eq!(
            s3_to_swift_path("AUTH_test", Some("bucket"), None),
            "/v1/AUTH_test/bucket"
        );
        assert_eq!(s3_to_swift_path("AUTH_test", None, None), "/v1/AUTH_test");
        // empty strings treated as absent
        assert_eq!(
            s3_to_swift_path("AUTH_test", Some("bucket"), Some("")),
            "/v1/AUTH_test/bucket"
        );
    }

    #[test]
    fn test_validate_bucket_name_dns() {
        assert!(validate_bucket_name("my-bucket", true));
        assert!(validate_bucket_name("bucket.name.123", true));
        assert!(validate_bucket_name("abc", true));
        assert!(!validate_bucket_name("ab", true)); // too short
        assert!(!validate_bucket_name("MyBucket", true)); // upper-case
        assert!(!validate_bucket_name("bucket_name", true)); // underscore
        assert!(!validate_bucket_name("-bucket", true)); // leading '-'
        assert!(!validate_bucket_name("bucket-", true)); // trailing '-'
        assert!(!validate_bucket_name("bucket..name", true)); // adjacent dots
        assert!(!validate_bucket_name("bucket.-name", true)); // '.-'
        assert!(!validate_bucket_name("192.168.0.1", true)); // ip-like
        assert!(validate_bucket_name("192.168.0.1a", true)); // not 4 numeric octets
    }

    #[test]
    fn test_validate_bucket_name_legacy() {
        assert!(validate_bucket_name("MyBucket", false));
        assert!(validate_bucket_name("bucket_name", false));
        // trailing '-' allowed under legacy rules (no isalnum-tail check)
        assert!(validate_bucket_name("bucket-", false));
        // 255 is the legacy max
        assert!(validate_bucket_name(&"a".repeat(255), false));
        assert!(!validate_bucket_name(&"a".repeat(256), false));
    }
}
