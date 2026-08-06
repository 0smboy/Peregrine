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

//! Production S3 API gateway middleware (minimal surface).
//!
//! Wires the pure translation core ([`crate::parse`], [`crate::sigv4`],
//! [`crate::response`]) into the proxy pipeline as `s3api`. Pipeline order
//! matches OpenStack Swift: place `s3api` **before** `tempauth` /
//! `keystoneauth`.
//!
//! # Supported (Wave 3)
//!
//! * SigV4 header auth (TempAuth-derived `account:user` access keys)
//! * Service: ListBuckets (`GET /`)
//! * Bucket: Create / Delete / Head / ListObjects v1+v2 / GetBucketLocation
//! * MultiDelete (`POST ?delete`), basic ACL/CORS, multipart upload
//! * Object: Put / Get / Head / Delete; Copy via `x-amz-copy-source`
//!
//! # Residuals
//!
//! SigV2, aws-chunked, full IAM / grant-header object ACL (canned
//! private/public-read stored as sysmeta is claimable), versioning/tagging/lifecycle
//! (written WONTFIX for production stop-line unless reopened), clock-skew
//! on every path, advertising `s3api` on Swift `GET /info`. Multipart
//! includes ListMultipartUploads via `{bucket}+segments` upload markers.
//!
//! Unknown access keys (EC2) are deferred to Keystone via an optional
//! [`S3TokenClient`] (`with_s3token_client`); without a client, unknown keys
//! still return `InvalidAccessKeyId`.

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::Value;
use swift_http::{Body, HeaderKeyDict, Request, Response, MAX_CONTROL_BODY};
use swift_middleware::{Middleware, NextFn, S3TokenClient, S3TokenResult};

use crate::acl_cors::{
    acl_xml_from_swift_headers, apply_canned_acl, apply_object_canned_acl,
    clear_cors_swift_headers, cors_config_to_swift_headers, cors_xml_from_swift_headers,
    object_acl_xml_from_meta, parse_cors_configuration, xml_ok, S3_OBJECT_ACL_META,
};
use crate::delete::parse_multi_delete_body;
use crate::mpu::{
    complete_multipart_xml, initiate_response, list_multipart_uploads_xml, list_parts_xml_full,
    new_upload_id, parse_complete_body, parse_upload_marker_name, part_object_name,
    segments_container, slo_manifest_json, upload_marker_name, ListedPart, ListedUpload,
};
use crate::parse::{extract_bucket_and_key, s3_to_swift_path, validate_bucket_name};
use crate::response::{
    copy_object_result_xml, delete_object_response, delete_result_xml, list_all_my_buckets_xml,
    put_object_response, s3_error_response, xml_response, BucketInfo, DeleteError,
    ListBucketResult, ListBucketResultV2, Owner, S3Object,
};
use crate::sigv4::{parse_sigv4_auth, string_to_sign_for_request, verify_sigv4, SigV4Auth};
use crate::xml::Element;

/// One S3 credential mapped onto a Swift storage account.
#[derive(Debug, Clone)]
pub struct S3Credential {
    pub access_key: String,
    pub secret_key: String,
    /// Swift account path segment, e.g. `AUTH_test`.
    pub account: String,
    /// Groups stamped onto `X-Backend-Remote-User` (account owner etc.).
    pub groups: Vec<String>,
    /// Optional Keystone token id from an s3tokens exchange (stamped as
    /// `X-Auth-Token` on the Swift subrequest).
    pub auth_token: Option<String>,
}

/// `s3api` filter — ON-BY-CONFIG via `[pipeline:main]`.
pub struct S3Api {
    pub credentials: HashMap<String, S3Credential>,
    pub storage_domains: Vec<String>,
    pub dns_compliant_bucket_names: bool,
    /// Region reported by `?location` and accepted in SigV4 scope.
    pub location: String,
    /// Reseller prefix for Keystone project → Swift account (`AUTH_`).
    pub reseller_prefix: String,
    /// When set, unknown access keys are exchanged via Keystone `/v3/s3tokens`
    /// with a real base64 string-to-sign (EC2 deferral).
    pub s3token_client: Option<Arc<dyn S3TokenClient>>,
}

impl S3Api {
    pub fn new(credentials: HashMap<String, S3Credential>) -> Self {
        S3Api {
            credentials,
            storage_domains: Vec::new(),
            dns_compliant_bucket_names: true,
            location: "us-east-1".to_string(),
            reseller_prefix: "AUTH_".into(),
            s3token_client: None,
        }
    }

    pub fn with_location(mut self, location: impl Into<String>) -> Self {
        self.location = location.into();
        self
    }

    pub fn with_storage_domains(mut self, domains: Vec<String>) -> Self {
        self.storage_domains = domains;
        self
    }

    pub fn with_dns_compliant(mut self, dns: bool) -> Self {
        self.dns_compliant_bucket_names = dns;
        self
    }

    pub fn with_reseller_prefix(mut self, prefix: impl Into<String>) -> Self {
        let mut p = prefix.into();
        if !p.ends_with('_') {
            p.push('_');
        }
        self.reseller_prefix = p;
        self
    }

    pub fn with_s3token_client(mut self, client: Arc<dyn S3TokenClient>) -> Self {
        self.s3token_client = Some(client);
        self
    }

    /// Resolve a local TempAuth credential, or defer to Keystone s3tokens.
    /// Returns `(cred, signature_already_verified_by_keystone)`.
    fn resolve_credential(
        &self,
        auth: &SigV4Auth,
        req: &Request,
    ) -> Option<(S3Credential, bool)> {
        if let Some(cred) = self.credentials.get(&auth.access_key) {
            return Some((cred.clone(), false));
        }
        let client = self.s3token_client.as_ref()?;
        let sts = string_to_sign_for_request(req)?;
        let result = client.exchange(&auth.access_key, &auth.signature, &sts)?;
        Some((credential_from_s3token(&auth.access_key, &result, &self.reseller_prefix), true))
    }
}

fn credential_from_s3token(
    access_key: &str,
    result: &S3TokenResult,
    reseller_prefix: &str,
) -> S3Credential {
    let account = format!("{reseller_prefix}{}", result.project_id);
    let mut groups = vec![
        result.project_id.clone(),
        format!("{}:{}", result.project_name, result.user_name),
        account.clone(),
    ];
    for role in &result.roles {
        if !role.is_empty() && !groups.contains(role) {
            groups.push(role.clone());
        }
    }
    S3Credential {
        access_key: access_key.to_string(),
        secret_key: String::new(),
        account,
        groups,
        auth_token: if result.token_id.is_empty() {
            None
        } else {
            Some(result.token_id.clone())
        },
    }
}

/// Subresources still rejected with `NotImplemented` (honest residual).
const UNSUPPORTED_SUBRESOURCES: &[&str] = &[
    "lifecycle",
    "tagging",
    "versioning",
    "versions",
    "policy",
    "website",
    "replication",
    "object-lock",
    "legal-hold",
    "retention",
    "select",
    "torrent",
    "requestPayment",
    "accelerate",
    "logging",
    "notification",
    "encryption",
    "metrics",
    "analytics",
    "inventory",
    "publicAccessBlock",
    "ownershipControls",
];

fn is_s3_auth_request(req: &Request) -> bool {
    parse_sigv4_auth(req).is_some()
}

fn first_unsupported_subresource(params: &[(String, String)]) -> Option<&str> {
    for name in UNSUPPORTED_SUBRESOURCES {
        if params.iter().any(|(k, _)| k == *name) {
            return Some(*name);
        }
    }
    None
}

fn owner_for(cred: &S3Credential) -> Owner {
    Owner {
        id: cred.access_key.clone(),
        display_name: cred.access_key.clone(),
    }
}

/// Stamp auth bypass + groups so TempAuth / proxy authorize honour the
/// SigV4-authenticated identity (same pattern as TempURL override).
fn stamp_auth(req: &mut Request, cred: &S3Credential) {
    req.headers
        .set("X-Backend-Authorize-Override", "true");
    req.headers
        .set("X-Backend-Remote-User", cred.groups.join(","));
    req.headers.set("X-Backend-Swift-Owner", "true");
    if let Some(tok) = &cred.auth_token {
        req.headers.set("X-Auth-Token", tok);
        req.headers.set("X-Identity-Status", "Confirmed");
    }
}

fn strip_s3_only_headers(headers: &mut HeaderKeyDict) {
    // AWS headers must not leak into the Swift backend as client meta.
    let keys: Vec<String> = headers
        .iter()
        .map(|(k, _)| k.to_string())
        .filter(|k| {
            let lower = k.to_ascii_lowercase();
            lower.starts_with("x-amz-")
                || lower == "authorization"
                || lower == "x-sdk-date"
        })
        .collect();
    for k in keys {
        headers.remove(&k);
    }
}

fn map_amz_meta(req: &mut Request) {
    // x-amz-meta-* → X-Object-Meta-*
    let pairs: Vec<(String, String)> = req
        .headers
        .iter()
        .filter_map(|(k, v)| {
            let lower = k.to_ascii_lowercase();
            lower
                .strip_prefix("x-amz-meta-")
                .map(|rest| (format!("X-Object-Meta-{rest}"), v.to_string()))
        })
        .collect();
    for (k, v) in pairs {
        req.headers.set(&k, v);
    }
}

fn apply_copy_source(req: &mut Request) {
    if let Some(src) = req
        .headers
        .get("X-Amz-Copy-Source")
        .map(str::to_string)
    {
        let src = src.trim_start_matches('/');
        if !src.is_empty() {
            // URL-decode lightly: keep as-is when already decoded path.
            req.headers.set("X-Copy-From", src);
            // Copy must not forward a body.
            req.body = Body::empty();
            req.headers.remove("Content-Length");
        }
    }
}

fn s3_to_swift_query(params: &[(String, String)], for_container_list: bool) -> String {
    let mut out: Vec<(String, String)> = Vec::new();
    if for_container_list {
        out.push(("format".into(), "json".into()));
    }
    for (k, v) in params {
        match k.as_str() {
            "prefix" => out.push(("prefix".into(), v.clone())),
            "marker" => out.push(("marker".into(), v.clone())),
            "start-after" => out.push(("marker".into(), v.clone())),
            "continuation-token" => out.push(("marker".into(), v.clone())),
            "delimiter" => out.push(("delimiter".into(), v.clone())),
            "max-keys" => {
                // Swift uses `limit`.
                out.push(("limit".into(), v.clone()));
            }
            // Drop SigV4 query auth + S3-only keys from the Swift subrequest.
            "X-Amz-Algorithm"
            | "X-Amz-Credential"
            | "X-Amz-Date"
            | "X-Amz-Expires"
            | "X-Amz-SignedHeaders"
            | "X-Amz-Signature"
            | "X-Amz-Security-Token"
            | "location"
            | "encoding-type"
            | "list-type"
            | "fetch-owner"
            | "uploads"
            | "uploadId"
            | "partNumber"
            | "acl"
            | "cors"
            | "delete" => {}
            _ => {}
        }
    }
    out.iter()
        .map(|(k, v)| format!("{}={}", encode_query(k), encode_query(v)))
        .collect::<Vec<_>>()
        .join("&")
}

fn encode_query(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else if b == b' ' {
            out.push('%');
            out.push('2');
            out.push('0');
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn swift_ts_to_s3(ts: &str) -> String {
    // `2013-05-24T00:00:00.000000` → `2013-05-24T00:00:00.000Z`
    if let Some(dot) = ts.find('.') {
        let (head, frac) = ts.split_at(dot);
        let digits: String = frac
            .chars()
            .skip(1)
            .filter(|c| c.is_ascii_digit())
            .take(3)
            .collect();
        let digits = if digits.len() < 3 {
            format!("{digits:0<3}")
        } else {
            digits
        };
        format!("{head}.{digits}Z")
    } else if ts.ends_with('Z') {
        ts.to_string()
    } else {
        format!("{ts}.000Z")
    }
}

fn quote_etag(etag: &str) -> String {
    let t = etag.trim().trim_matches('"');
    format!("\"{t}\"")
}

fn bare_etag(etag: &str) -> String {
    etag.trim().trim_matches('"').to_string()
}

fn location_constraint_xml(location: &str) -> Vec<u8> {
    // Empty location == classic us-east-1 shape when configured as us-east-1.
    if location == "us-east-1" {
        Element::new("LocationConstraint").to_xml(true)
    } else {
        Element::leaf("LocationConstraint", location).to_xml(true)
    }
}

fn map_swift_error(status: u16, bucket: Option<&str>, key: Option<&str>) -> Response {
    let (code, extras): (&str, Vec<(&str, String)>) = match status {
        404 if key.is_some() => {
            let mut e = Vec::new();
            if let Some(k) = key {
                e.push(("Key", k.to_string()));
            }
            if let Some(b) = bucket {
                e.push(("BucketName", b.to_string()));
            }
            ("NoSuchKey", e)
        }
        404 => {
            let mut e = Vec::new();
            if let Some(b) = bucket {
                e.push(("BucketName", b.to_string()));
            }
            ("NoSuchBucket", e)
        }
        401 | 403 => ("AccessDenied", Vec::new()),
        409 => ("BucketNotEmpty", Vec::new()),
        411 => ("MissingContentLength", Vec::new()),
        412 => ("PreconditionFailed", Vec::new()),
        416 => ("InvalidRange", Vec::new()),
        507 | 413 => ("EntityTooLarge", Vec::new()),
        500..=599 => ("InternalError", Vec::new()),
        _ => ("InvalidRequest", Vec::new()),
    };
    let extras_ref: Vec<(&str, &str)> = extras.iter().map(|(k, v)| (*k, v.as_str())).collect();
    s3_error_response(code, None, &extras_ref)
}

fn translate_list_buckets(body: &[u8], owner: &Owner) -> Response {
    let parsed: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return s3_error_response("InternalError", Some("bad account listing"), &[]),
    };
    let arr = match parsed.as_array() {
        Some(a) => a,
        None => return s3_error_response("InternalError", Some("bad account listing"), &[]),
    };
    let buckets: Vec<BucketInfo> = arr
        .iter()
        .filter_map(|item| {
            let name = item.get("name")?.as_str()?.to_string();
            let created = item
                .get("last_modified")
                .and_then(|v| v.as_str())
                .unwrap_or("1970-01-01T00:00:00.000000");
            Some(BucketInfo {
                name,
                creation_date: swift_ts_to_s3(created),
            })
        })
        .collect();
    xml_response(200, list_all_my_buckets_xml(owner, &buckets))
}

fn translate_list_objects(
    body: &[u8],
    bucket: &str,
    params: &[(String, String)],
    owner: &Owner,
) -> Response {
    let parsed: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return s3_error_response("InternalError", Some("bad container listing"), &[]),
    };
    let arr = match parsed.as_array() {
        Some(a) => a,
        None => return s3_error_response("InternalError", Some("bad container listing"), &[]),
    };
    let prefix = params
        .iter()
        .find(|(k, _)| k == "prefix")
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    let marker = params
        .iter()
        .find(|(k, _)| k == "marker")
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    let delimiter = params
        .iter()
        .find(|(k, _)| k == "delimiter")
        .map(|(_, v)| v.clone());
    let max_keys = params
        .iter()
        .find(|(k, _)| k == "max-keys")
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(1000u32);

    let mut contents = Vec::new();
    let mut common_prefixes = Vec::new();
    for item in arr {
        if let Some(subdir) = item.get("subdir").and_then(|v| v.as_str()) {
            common_prefixes.push(subdir.to_string());
            continue;
        }
        let Some(name) = item.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        let hash = item
            .get("hash")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let bytes = item
            .get("bytes")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let last_modified = item
            .get("last_modified")
            .and_then(|v| v.as_str())
            .unwrap_or("1970-01-01T00:00:00.000000");
        contents.push(S3Object {
            key: name.to_string(),
            last_modified: swift_ts_to_s3(last_modified),
            etag: quote_etag(hash),
            size: bytes,
            storage_class: "STANDARD".into(),
            owner: Some(Owner {
                id: owner.id.clone(),
                display_name: owner.display_name.clone(),
            }),
        });
    }
    // Swift's limit truncates the JSON array; treat "hit max-keys" as truncated.
    let is_truncated = contents.len() as u32 >= max_keys;
    let next_marker = if is_truncated {
        contents.last().map(|o| o.key.clone())
    } else {
        None
    };
    let lbr = ListBucketResult {
        name: bucket.to_string(),
        prefix,
        marker,
        next_marker,
        max_keys,
        delimiter,
        encoding_type: None,
        is_truncated,
        contents,
        common_prefixes,
    };
    lbr.into_response()
}

fn translate_list_objects_v2(
    body: &[u8],
    bucket: &str,
    params: &[(String, String)],
    owner: &Owner,
) -> Response {
    let parsed: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return s3_error_response("InternalError", Some("bad container listing"), &[]),
    };
    let arr = match parsed.as_array() {
        Some(a) => a,
        None => return s3_error_response("InternalError", Some("bad container listing"), &[]),
    };
    let prefix = params
        .iter()
        .find(|(k, _)| k == "prefix")
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    let start_after = params
        .iter()
        .find(|(k, _)| k == "start-after")
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    let continuation_token = params
        .iter()
        .find(|(k, _)| k == "continuation-token")
        .map(|(_, v)| v.clone());
    let delimiter = params
        .iter()
        .find(|(k, _)| k == "delimiter")
        .map(|(_, v)| v.clone());
    let max_keys = params
        .iter()
        .find(|(k, _)| k == "max-keys")
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(1000u32);
    let fetch_owner = params
        .iter()
        .any(|(k, v)| k == "fetch-owner" && (v == "true" || v == "True" || v == "1"));

    let mut contents = Vec::new();
    let mut common_prefixes = Vec::new();
    for item in arr {
        if let Some(subdir) = item.get("subdir").and_then(|v| v.as_str()) {
            common_prefixes.push(subdir.to_string());
            continue;
        }
        let Some(name) = item.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        let hash = item.get("hash").and_then(|v| v.as_str()).unwrap_or("");
        let bytes = item.get("bytes").and_then(|v| v.as_u64()).unwrap_or(0);
        let last_modified = item
            .get("last_modified")
            .and_then(|v| v.as_str())
            .unwrap_or("1970-01-01T00:00:00.000000");
        contents.push(S3Object {
            key: name.to_string(),
            last_modified: swift_ts_to_s3(last_modified),
            etag: quote_etag(hash),
            size: bytes,
            storage_class: "STANDARD".into(),
            owner: if fetch_owner {
                Some(Owner {
                    id: owner.id.clone(),
                    display_name: owner.display_name.clone(),
                })
            } else {
                None
            },
        });
    }
    let key_count = (contents.len() + common_prefixes.len()) as u32;
    let is_truncated = contents.len() as u32 >= max_keys;
    let next_continuation_token = if is_truncated {
        contents.last().map(|o| o.key.clone())
    } else {
        None
    };
    ListBucketResultV2 {
        name: bucket.to_string(),
        prefix,
        start_after,
        continuation_token,
        next_continuation_token,
        key_count,
        max_keys,
        delimiter,
        encoding_type: None,
        is_truncated,
        contents,
        common_prefixes,
    }
    .into_response()
}

fn translate_object_success(
    method: &str,
    mut resp: Response,
    is_copy: bool,
) -> Response {
    match method {
        "PUT" if is_copy => {
            let etag = resp
                .headers
                .get("ETag")
                .map(bare_etag)
                .unwrap_or_default();
            let lm = resp
                .headers
                .get("Last-Modified")
                .unwrap_or("Thu, 01 Jan 1970 00:00:00 GMT")
                .to_string();
            // S3 CopyObjectResult wants ISO timestamp; approximate from HTTP date
            // when we lack a better source.
            let iso = http_date_to_s3_approx(&lm);
            xml_response(200, copy_object_result_xml(&iso, &etag))
        }
        "PUT" => {
            let etag = resp
                .headers
                .get("ETag")
                .map(bare_etag)
                .unwrap_or_default();
            put_object_response(&etag)
        }
        "DELETE" => delete_object_response(),
        "GET" | "HEAD" => {
            // S3 uses 200 for HEAD/GET; quote ETag if present.
            if let Some(etag) = resp.headers.get("ETag").map(str::to_string) {
                resp.headers.set("ETag", quote_etag(&etag));
            }
            if resp.status == 201 {
                resp.status = 200;
            }
            resp
        }
        _ => resp,
    }
}

fn http_date_to_s3_approx(http_date: &str) -> String {
    // Best-effort: if already ISO-ish, normalise; else epoch placeholder.
    if http_date.contains('T') {
        return swift_ts_to_s3(http_date);
    }
    "1970-01-01T00:00:00.000Z".into()
}

fn translate_bucket_success(method: &str, resp: Response) -> Response {
    match method {
        "PUT" => Response::new(200),
        "DELETE" => Response::new(204),
        "HEAD" => {
            let mut r = Response::new(200);
            // Preserve useful headers lightly.
            if let Some(v) = resp.headers.get("X-Container-Object-Count") {
                r.headers.set("x-amz-bucket-object-count", v);
            }
            r
        }
        _ => resp,
    }
}

impl Middleware for S3Api {
    fn handle(&self, req: Request, next: &NextFn) -> Response {
        // Non-S3 traffic (Swift v1, /auth, /info, healthcheck) passes through.
        if !is_s3_auth_request(&req) {
            return next(req);
        }

        let auth = match parse_sigv4_auth(&req) {
            Some(a) => a,
            None => return s3_error_response("AccessDenied", None, &[]),
        };
        let Some((cred, keystone_verified)) = self.resolve_credential(&auth, &req) else {
            return s3_error_response("InvalidAccessKeyId", None, &[]);
        };
        // Keystone `/v3/s3tokens` already validated the SigV4 signature against
        // the EC2 secret; local TempAuth keys still need verify_sigv4.
        if !keystone_verified && !verify_sigv4(&cred.access_key, &cred.secret_key, &req) {
            return s3_error_response("SignatureDoesNotMatch", None, &[]);
        }

        let params = req.params();
        if let Some(sub) = first_unsupported_subresource(&params) {
            return s3_error_response(
                "NotImplemented",
                Some(&format!("subresource '{sub}' is not implemented")),
                &[],
            );
        }

        let (bucket, key) = extract_bucket_and_key(
            &req,
            &self.storage_domains,
            self.dns_compliant_bucket_names,
        );
        if let Some(b) = &bucket {
            if !validate_bucket_name(b, self.dns_compliant_bucket_names) {
                return s3_error_response("InvalidBucketName", None, &[("BucketName", b)]);
            }
        }

        // GetBucketLocation — answered locally, no Swift hop.
        if key.is_none()
            && bucket.is_some()
            && req.method == "GET"
            && params.iter().any(|(k, _)| k == "location")
        {
            return xml_response(200, location_constraint_xml(&self.location));
        }

        let owner = owner_for(&cred);
        let list_v2 = params.iter().any(|(k, v)| k == "list-type" && v == "2");
        let has_delete = params.iter().any(|(k, _)| k == "delete");
        let has_acl = params.iter().any(|(k, _)| k == "acl");
        let has_cors = params.iter().any(|(k, _)| k == "cors");
        let has_uploads = params.iter().any(|(k, _)| k == "uploads");
        let upload_id = params
            .iter()
            .find(|(k, _)| k == "uploadId")
            .map(|(_, v)| v.clone());
        let part_number = params
            .iter()
            .find(|(k, _)| k == "partNumber")
            .and_then(|(_, v)| v.parse::<u32>().ok());

        // ---- MultiDelete ----
        if has_delete && req.method == "POST" && bucket.is_some() && key.is_none() {
            return handle_multi_delete(req, &cred, bucket.as_deref().unwrap(), &next);
        }

        // ---- ACL ----
        if has_acl && bucket.is_some() {
            return handle_acl(req, &cred, &owner, bucket.as_deref().unwrap(), key.as_deref(), &next);
        }

        // ---- CORS ----
        if has_cors && bucket.is_some() && key.is_none() {
            return handle_cors(req, &cred, bucket.as_deref().unwrap(), &next);
        }

        // ---- Multipart ----
        if has_uploads && req.method == "POST" && bucket.is_some() && key.is_some() {
            return handle_mpu_init(&cred, bucket.as_deref().unwrap(), key.as_deref().unwrap(), &next);
        }
        // ListMultipartUploads (`GET /bucket?uploads`, no key): list upload
        // markers under `{bucket}+segments` (must not fall through to ListObjects).
        if has_uploads && req.method == "GET" && bucket.is_some() && key.is_none() {
            return handle_list_multipart_uploads(
                &cred,
                bucket.as_deref().unwrap(),
                &params,
                &next,
            );
        }
        if has_uploads && bucket.is_some() && key.is_none() {
            return s3_error_response(
                "MethodNotAllowed",
                Some("ListMultipartUploads requires GET"),
                &[],
            );
        }
        if let Some(uid) = upload_id.clone() {
            if let (Some(b), Some(k)) = (bucket.clone(), key.clone()) {
                if req.method == "PUT" {
                    if let Some(pn) = part_number {
                        return handle_mpu_part(&cred, &b, &k, &uid, pn, req, &next);
                    }
                }
                if req.method == "POST" {
                    return handle_mpu_complete(&cred, &b, &k, &uid, req, &next);
                }
                if req.method == "DELETE" {
                    return handle_mpu_abort(&cred, &b, &k, &uid, &next);
                }
                if req.method == "GET" {
                    return handle_mpu_list_parts(&cred, &b, &k, &uid, &params, &next);
                }
            }
        }

        let method = req.method.clone();
        let is_copy = req.headers.get("X-Amz-Copy-Source").is_some();
        let for_list = matches!(method.as_str(), "GET" | "HEAD") && key.is_none();

        let mut swift_req = req;
        let swift_path = s3_to_swift_path(
            &cred.account,
            bucket.as_deref(),
            key.as_deref(),
        );
        swift_req.path = swift_path;
        if for_list && method == "GET" {
            swift_req.query_string = s3_to_swift_query(&params, true);
        } else if method == "GET" && bucket.is_none() {
            // ListBuckets
            swift_req.query_string = "format=json".into();
        } else {
            // Drop SigV4 query crumbs; keep empty for object ops.
            swift_req.query_string = s3_to_swift_query(&params, false);
        }

        map_amz_meta(&mut swift_req);
        apply_copy_source(&mut swift_req);
        if let Some(canned) = swift_req.headers.get("X-Amz-Acl").map(str::to_string) {
            if key.is_some() {
                // Object PUT: store canned ACL as object sysmeta (not container ACL).
                apply_object_canned_acl(&mut swift_req.headers, &canned);
            } else {
                apply_canned_acl(&mut swift_req.headers, &canned);
            }
        }
        strip_s3_only_headers(&mut swift_req.headers);
        stamp_auth(&mut swift_req, &cred);

        // Force JSON listings past any Accept noise.
        if for_list && method == "GET" {
            swift_req.headers.set("Accept", "application/json");
        }

        let resp = next(swift_req);

        // Success path translations.
        if bucket.is_none() && method == "GET" && (200..300).contains(&resp.status) {
            let body = match resp.body.into_vec(MAX_CONTROL_BODY) {
                Ok(b) => b,
                Err(_) => {
                    return s3_error_response("InternalError", Some("listing too large"), &[])
                }
            };
            return translate_list_buckets(&body, &owner);
        }

        if key.is_none() && bucket.is_some() {
            if method == "GET" && (200..300).contains(&resp.status) {
                let body = match resp.body.into_vec(MAX_CONTROL_BODY) {
                    Ok(b) => b,
                    Err(_) => {
                        return s3_error_response("InternalError", Some("listing too large"), &[])
                    }
                };
                if list_v2 {
                    return translate_list_objects_v2(
                        &body,
                        bucket.as_deref().unwrap(),
                        &params,
                        &owner,
                    );
                }
                return translate_list_objects(&body, bucket.as_deref().unwrap(), &params, &owner);
            }
            if (200..300).contains(&resp.status) {
                return translate_bucket_success(&method, resp);
            }
            return map_swift_error(resp.status, bucket.as_deref(), None);
        }

        if key.is_some() {
            if (200..300).contains(&resp.status) {
                return translate_object_success(&method, resp, is_copy);
            }
            return map_swift_error(resp.status, bucket.as_deref(), key.as_deref());
        }

        // Fallback (e.g. HEAD service)
        if (200..300).contains(&resp.status) {
            resp
        } else {
            map_swift_error(resp.status, bucket.as_deref(), key.as_deref())
        }
    }
}

fn make_swift_req(method: &str, path: &str) -> Request {
    Request {
        method: method.into(),
        path: path.into(),
        query_string: String::new(),
        headers: HeaderKeyDict::new(),
        body: Body::empty(),
    }
}

fn handle_multi_delete(
    req: Request,
    cred: &S3Credential,
    bucket: &str,
    next: &NextFn,
) -> Response {
    let body = match req.body.into_vec(MAX_CONTROL_BODY) {
        Ok(b) => b,
        Err(_) => return s3_error_response("IncompleteBody", None, &[]),
    };
    let parsed = match parse_multi_delete_body(&body) {
        Ok(p) => p,
        Err(_) => return s3_error_response("MalformedXML", None, &[]),
    };
    let mut deleted = Vec::new();
    let mut errors = Vec::new();
    for key in &parsed.keys {
        let mut del = make_swift_req(
            "DELETE",
            &s3_to_swift_path(&cred.account, Some(bucket), Some(key)),
        );
        stamp_auth(&mut del, cred);
        let resp = next(del);
        if (200..300).contains(&resp.status) || resp.status == 404 {
            deleted.push(key.clone());
        } else {
            errors.push(DeleteError {
                key: key.clone(),
                code: "InternalError".into(),
                message: format!("backend status {}", resp.status),
            });
        }
    }
    // Quiet mode: omit successful Deleted entries (errors still returned).
    let deleted_out = if parsed.quiet { Vec::new() } else { deleted };
    xml_response(200, delete_result_xml(&deleted_out, &errors))
}

fn handle_acl(
    req: Request,
    cred: &S3Credential,
    owner: &Owner,
    bucket: &str,
    key: Option<&str>,
    next: &NextFn,
) -> Response {
    if let Some(obj) = key {
        // Object ACL: canned name in X-Object-Sysmeta-S3-Acl.
        match req.method.as_str() {
            "GET" | "HEAD" => {
                let mut head = make_swift_req(
                    "HEAD",
                    &s3_to_swift_path(&cred.account, Some(bucket), Some(obj)),
                );
                stamp_auth(&mut head, cred);
                let resp = next(head);
                if !(200..300).contains(&resp.status) {
                    return map_swift_error(resp.status, Some(bucket), Some(obj));
                }
                let canned = resp
                    .headers
                    .get(S3_OBJECT_ACL_META)
                    .or_else(|| resp.headers.get("X-Object-Meta-S3-Acl"));
                xml_ok(object_acl_xml_from_meta(&owner.id, canned))
            }
            "PUT" => {
                let canned = req
                    .headers
                    .get("X-Amz-Acl")
                    .unwrap_or("private")
                    .to_string();
                let mut post = make_swift_req(
                    "POST",
                    &s3_to_swift_path(&cred.account, Some(bucket), Some(obj)),
                );
                apply_object_canned_acl(&mut post.headers, &canned);
                stamp_auth(&mut post, cred);
                let resp = next(post);
                if (200..300).contains(&resp.status) {
                    Response::new(200)
                } else {
                    map_swift_error(resp.status, Some(bucket), Some(obj))
                }
            }
            _ => s3_error_response("MethodNotAllowed", None, &[]),
        }
    } else {
        match req.method.as_str() {
            "GET" | "HEAD" => {
                let mut head =
                    make_swift_req("HEAD", &s3_to_swift_path(&cred.account, Some(bucket), None));
                stamp_auth(&mut head, cred);
                let resp = next(head);
                if !(200..300).contains(&resp.status) {
                    return map_swift_error(resp.status, Some(bucket), None);
                }
                xml_ok(acl_xml_from_swift_headers(
                    &owner.id,
                    resp.headers.get("X-Container-Read"),
                    resp.headers.get("X-Container-Write"),
                ))
            }
            "PUT" => {
                let canned = req
                    .headers
                    .get("X-Amz-Acl")
                    .unwrap_or("private")
                    .to_string();
                let mut post =
                    make_swift_req("POST", &s3_to_swift_path(&cred.account, Some(bucket), None));
                apply_canned_acl(&mut post.headers, &canned);
                stamp_auth(&mut post, cred);
                let resp = next(post);
                if (200..300).contains(&resp.status) {
                    Response::new(200)
                } else {
                    map_swift_error(resp.status, Some(bucket), None)
                }
            }
            _ => s3_error_response("MethodNotAllowed", None, &[]),
        }
    }
}

fn handle_cors(req: Request, cred: &S3Credential, bucket: &str, next: &NextFn) -> Response {
    match req.method.as_str() {
        "GET" | "HEAD" => {
            let mut head =
                make_swift_req("HEAD", &s3_to_swift_path(&cred.account, Some(bucket), None));
            stamp_auth(&mut head, cred);
            let resp = next(head);
            if !(200..300).contains(&resp.status) {
                return map_swift_error(resp.status, Some(bucket), None);
            }
            xml_ok(cors_xml_from_swift_headers(&resp.headers))
        }
        "PUT" => {
            let body = match req.body.into_vec(MAX_CONTROL_BODY) {
                Ok(b) => b,
                Err(_) => return s3_error_response("IncompleteBody", None, &[]),
            };
            let cfg = match parse_cors_configuration(&body) {
                Ok(c) => c,
                Err(_) => return s3_error_response("MalformedXML", None, &[]),
            };
            let mut post =
                make_swift_req("POST", &s3_to_swift_path(&cred.account, Some(bucket), None));
            cors_config_to_swift_headers(&mut post.headers, &cfg);
            stamp_auth(&mut post, cred);
            let resp = next(post);
            if (200..300).contains(&resp.status) {
                Response::new(200)
            } else {
                map_swift_error(resp.status, Some(bucket), None)
            }
        }
        "DELETE" => {
            let mut post =
                make_swift_req("POST", &s3_to_swift_path(&cred.account, Some(bucket), None));
            clear_cors_swift_headers(&mut post.headers);
            stamp_auth(&mut post, cred);
            let _ = next(post);
            Response::new(204)
        }
        _ => s3_error_response("MethodNotAllowed", None, &[]),
    }
}

fn handle_mpu_init(cred: &S3Credential, bucket: &str, key: &str, next: &NextFn) -> Response {
    let segs = segments_container(bucket);
    // Ensure segments container exists.
    let mut put_c =
        make_swift_req("PUT", &s3_to_swift_path(&cred.account, Some(&segs), None));
    stamp_auth(&mut put_c, cred);
    let _ = next(put_c);
    let upload_id = new_upload_id();
    let marker = upload_marker_name(key, &upload_id);
    let mut put_m = make_swift_req(
        "PUT",
        &s3_to_swift_path(&cred.account, Some(&segs), Some(&marker)),
    );
    put_m.body = Body::from(Vec::from(b"upload".as_slice()));
    put_m.headers.set("Content-Length", "6");
    stamp_auth(&mut put_m, cred);
    let resp = next(put_m);
    if !(200..300).contains(&resp.status) {
        return map_swift_error(resp.status, Some(bucket), Some(key));
    }
    initiate_response(bucket, key, &upload_id)
}

fn handle_mpu_part(
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    upload_id: &str,
    part_number: u32,
    req: Request,
    next: &NextFn,
) -> Response {
    let segs = segments_container(bucket);
    let part_name = part_object_name(key, upload_id, part_number);
    let mut put = req;
    put.method = "PUT".into();
    put.path = s3_to_swift_path(&cred.account, Some(&segs), Some(&part_name));
    put.query_string.clear();
    strip_s3_only_headers(&mut put.headers);
    stamp_auth(&mut put, cred);
    let resp = next(put);
    if (200..300).contains(&resp.status) {
        let etag = resp
            .headers
            .get("ETag")
            .map(|e| e.trim().trim_matches('"').to_string())
            .unwrap_or_default();
        put_object_response(&etag)
    } else {
        map_swift_error(resp.status, Some(bucket), Some(key))
    }
}

fn handle_mpu_complete(
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    upload_id: &str,
    req: Request,
    next: &NextFn,
) -> Response {
    let body = match req.body.into_vec(MAX_CONTROL_BODY) {
        Ok(b) => b,
        Err(_) => return s3_error_response("IncompleteBody", None, &[]),
    };
    let parts = match parse_complete_body(&body) {
        Ok(p) => p,
        Err(code) => return s3_error_response(&code, None, &[]),
    };
    let segs = segments_container(bucket);
    // HEAD each part for size.
    let mut sized: Vec<(u32, String, u64)> = Vec::new();
    for (num, etag) in &parts {
        let pname = part_object_name(key, upload_id, *num);
        let mut head = make_swift_req(
            "HEAD",
            &s3_to_swift_path(&cred.account, Some(&segs), Some(&pname)),
        );
        stamp_auth(&mut head, cred);
        let resp = next(head);
        if !(200..300).contains(&resp.status) {
            return s3_error_response("InvalidPart", None, &[]);
        }
        let size = resp
            .headers
            .get("Content-Length")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        sized.push((*num, etag.clone(), size));
    }
    let manifest = slo_manifest_json(&segs, key, upload_id, &sized);
    let mut put = make_swift_req(
        "PUT",
        &s3_to_swift_path(&cred.account, Some(bucket), Some(key)),
    );
    put.query_string = "multipart-manifest=put".into();
    put.body = Body::from(manifest.into_bytes());
    put.headers.set("Content-Type", "application/json");
    stamp_auth(&mut put, cred);
    let resp = next(put);
    if !(200..300).contains(&resp.status) {
        return map_swift_error(resp.status, Some(bucket), Some(key));
    }
    let etag = resp
        .headers
        .get("ETag")
        .map(|e| e.trim().trim_matches('"').to_string())
        .unwrap_or_else(|| "multipart".into());
    xml_response(
        200,
        complete_multipart_xml(bucket, key, &etag, &format!("/{bucket}/{key}")),
    )
}

fn handle_mpu_abort(
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    upload_id: &str,
    next: &NextFn,
) -> Response {
    let segs = segments_container(bucket);
    let marker = upload_marker_name(key, upload_id);
    let mut del = make_swift_req(
        "DELETE",
        &s3_to_swift_path(&cred.account, Some(&segs), Some(&marker)),
    );
    stamp_auth(&mut del, cred);
    let _ = next(del);
    Response::new(204)
}

fn handle_list_multipart_uploads(
    cred: &S3Credential,
    bucket: &str,
    params: &[(String, String)],
    next: &NextFn,
) -> Response {
    let prefix = params
        .iter()
        .find(|(k, _)| k == "prefix")
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    let key_marker = params
        .iter()
        .find(|(k, _)| k == "key-marker")
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    let upload_id_marker = params
        .iter()
        .find(|(k, _)| k == "upload-id-marker")
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    let max_uploads: u32 = params
        .iter()
        .find(|(k, _)| k == "max-uploads")
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(1000)
        .clamp(1, 1000);

    let segs = segments_container(bucket);
    let mut list = make_swift_req("GET", &s3_to_swift_path(&cred.account, Some(&segs), None));
    let mut qs = String::from("format=json");
    if !prefix.is_empty() {
        qs.push_str(&format!("&prefix={}", encode_query(prefix)));
    }
    list.query_string = qs;
    list.headers.set("Accept", "application/json");
    stamp_auth(&mut list, cred);
    let resp = next(list);
    // Missing segments container → empty upload list (not an error).
    if resp.status == 404 {
        return xml_response(
            200,
            list_multipart_uploads_xml(bucket, prefix, key_marker, upload_id_marker, max_uploads, false, &[]),
        );
    }
    if !(200..300).contains(&resp.status) {
        return map_swift_error(resp.status, Some(bucket), None);
    }
    let body = match resp.body.into_vec(MAX_CONTROL_BODY) {
        Ok(b) => b,
        Err(_) => return s3_error_response("InternalError", Some("listing too large"), &[]),
    };
    let parsed: Value = serde_json::from_slice(&body).unwrap_or(Value::Array(vec![]));
    let mut uploads = Vec::new();
    if let Some(arr) = parsed.as_array() {
        for item in arr {
            let Some(name) = item.get("name").and_then(|v| v.as_str()) else {
                continue;
            };
            let Some((key, uid)) = parse_upload_marker_name(name) else {
                continue;
            };
            if !prefix.is_empty() && !key.starts_with(prefix) {
                continue;
            }
            // Pagination: skip until past key-marker / upload-id-marker.
            if !key_marker.is_empty() {
                if key.as_str() < key_marker {
                    continue;
                }
                if key.as_str() == key_marker && !upload_id_marker.is_empty() && uid.as_str() <= upload_id_marker
                {
                    continue;
                }
            }
            let lm = item
                .get("last_modified")
                .and_then(|v| v.as_str())
                .unwrap_or("1970-01-01T00:00:00.000000");
            uploads.push(ListedUpload {
                key,
                upload_id: uid,
                initiated: swift_ts_to_s3(lm),
            });
        }
    }
    uploads.sort_by(|a, b| (&a.key, &a.upload_id).cmp(&(&b.key, &b.upload_id)));
    let truncated = uploads.len() as u32 > max_uploads;
    uploads.truncate(max_uploads as usize);
    xml_response(
        200,
        list_multipart_uploads_xml(
            bucket,
            prefix,
            key_marker,
            upload_id_marker,
            max_uploads,
            truncated,
            &uploads,
        ),
    )
}

fn handle_mpu_list_parts(
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    upload_id: &str,
    params: &[(String, String)],
    next: &NextFn,
) -> Response {
    // part-number-marker + max-parts (S3 ListParts query params).
    let param = |name: &str| -> Option<&str> {
        params
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    };
    let part_marker = param("part-number-marker")
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(0);
    let max_parts = param("max-parts")
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(1000)
        .clamp(1, 1000);
    let segs = segments_container(bucket);
    let prefix = format!("{key}/{upload_id}/");
    let mut list =
        make_swift_req("GET", &s3_to_swift_path(&cred.account, Some(&segs), None));
    list.query_string = format!("format=json&prefix={}", encode_query(&prefix));
    list.headers.set("Accept", "application/json");
    stamp_auth(&mut list, cred);
    let resp = next(list);
    if !(200..300).contains(&resp.status) {
        return map_swift_error(resp.status, Some(bucket), Some(key));
    }
    let body = match resp.body.into_vec(MAX_CONTROL_BODY) {
        Ok(b) => b,
        Err(_) => return s3_error_response("InternalError", None, &[]),
    };
    let parsed: Value = serde_json::from_slice(&body).unwrap_or(Value::Array(vec![]));
    let mut parts = Vec::new();
    if let Some(arr) = parsed.as_array() {
        for item in arr {
            let Some(name) = item.get("name").and_then(|v| v.as_str()) else {
                continue;
            };
            let Some(num_str) = name.rsplit('/').next() else {
                continue;
            };
            let Ok(num) = num_str.parse::<u32>() else {
                continue;
            };
            if num <= part_marker {
                continue;
            }
            let etag = item
                .get("hash")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let size = item.get("bytes").and_then(|v| v.as_u64()).unwrap_or(0);
            let lm = item
                .get("last_modified")
                .and_then(|v| v.as_str())
                .unwrap_or("1970-01-01T00:00:00.000000");
            parts.push(ListedPart {
                part_number: num,
                last_modified: swift_ts_to_s3(lm),
                etag,
                size,
            });
        }
    }
    parts.sort_by_key(|p| p.part_number);
    let truncated = parts.len() as u32 > max_parts;
    if truncated {
        parts.truncate(max_parts as usize);
    }
    xml_response(
        200,
        list_parts_xml_full(
            bucket,
            key,
            upload_id,
            part_marker,
            max_parts,
            truncated,
            &parts,
        ),
    )
}

/// Build credentials from TempAuth-style `user_<account>_<user> = <key> …`
/// records. Access key is `account:user`; secret is the TempAuth key;
/// storage account is `{reseller_prefix}{account}`.
pub fn credentials_from_tempauth_users(
    users: &[(String, String, String, Vec<String>)],
    reseller_prefix: &str,
) -> HashMap<String, S3Credential> {
    // users: (account, user, key, groups_from_conf)
    let mut map = HashMap::new();
    for (account, user, key, conf_groups) in users {
        let access_key = format!("{account}:{user}");
        let storage_account = format!("{reseller_prefix}{account}");
        let mut groups = vec![
            account.clone(),
            access_key.clone(),
        ];
        let mut is_admin = false;
        for g in conf_groups {
            if g == ".admin" {
                is_admin = true;
            } else {
                groups.push(g.clone());
            }
        }
        if is_admin {
            groups.push(storage_account.clone());
        }
        map.insert(
            access_key.clone(),
            S3Credential {
                access_key,
                secret_key: key.clone(),
                account: storage_account,
                groups,
                auth_token: None,
            },
        );
    }
    map
}

/// Helper for tests / proxy wiring: wrap [`S3Api`] as `Arc<dyn Middleware>`.
pub fn as_middleware(api: S3Api) -> Arc<dyn Middleware> {
    Arc::new(api)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sigv4::{
        amz_date, canonical_query, canonical_request, canonical_uri, compute_signature,
        headers_to_sign, payload_hash, parse_authorization_header,
    };

    fn cred_map() -> HashMap<String, S3Credential> {
        let mut m = HashMap::new();
        m.insert(
            "test:tester".into(),
            S3Credential {
                access_key: "test:tester".into(),
                secret_key: "testing".into(),
                account: "AUTH_test".into(),
                groups: vec![
                    "test".into(),
                    "test:tester".into(),
                    "AUTH_test".into(),
                ],
                auth_token: None,
            },
        );
        m
    }

    fn sign_request(mut req: Request, secret: &str) -> Request {
        let auth_hdr = req.headers.get("Authorization").unwrap().to_string();
        let auth = parse_authorization_header(&auth_hdr).unwrap();
        let date = amz_date(&req).unwrap();
        let hts = headers_to_sign(&req.headers, &auth.signed_headers).unwrap();
        let cr = canonical_request(
            &req.method,
            &canonical_uri(&req.path),
            &canonical_query(&req.query_string),
            &hts,
            &payload_hash(&req),
        );
        let sig = compute_signature(secret, &auth.scope, &date, &cr);
        // Rebuild Authorization with computed signature.
        let cred = format!(
            "{}/{}/{}/{}/{}",
            auth.access_key,
            auth.scope.date,
            auth.scope.region,
            auth.scope.service,
            auth.scope.terminal
        );
        let signed = auth.signed_headers.join(";");
        req.headers.set(
            "Authorization",
            format!(
                "AWS4-HMAC-SHA256 Credential={cred}, SignedHeaders={signed}, Signature={sig}"
            ),
        );
        req
    }

    fn base_s3_req(method: &str, path: &str, query: &str) -> Request {
        let mut headers = HeaderKeyDict::new();
        headers.set("Host", "localhost");
        headers.set(
            "x-amz-content-sha256",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
        headers.set("x-amz-date", "20130524T000000Z");
        // Placeholder signature — replaced by sign_request.
        headers.set(
            "Authorization",
            "AWS4-HMAC-SHA256 \
             Credential=test:tester/20130524/us-east-1/s3/aws4_request, \
             SignedHeaders=host;x-amz-content-sha256;x-amz-date, \
             Signature=00",
        );
        Request {
            method: method.into(),
            path: path.into(),
            query_string: query.into(),
            headers,
            body: Body::empty(),
        }
    }

    #[test]
    fn passthrough_without_sigv4() {
        let api = S3Api::new(cred_map());
        let req = Request {
            method: "GET".into(),
            path: "/v1/AUTH_test".into(),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: Body::empty(),
        };
        let next: NextFn = Arc::new(|r| {
            assert_eq!(r.path, "/v1/AUTH_test");
            Response::new(200)
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
    }

    #[test]
    fn reject_bad_access_key() {
        let api = S3Api::new(cred_map());
        let mut req = base_s3_req("GET", "/", "");
        req.headers.set(
            "Authorization",
            "AWS4-HMAC-SHA256 \
             Credential=nope:user/20130524/us-east-1/s3/aws4_request, \
             SignedHeaders=host;x-amz-content-sha256;x-amz-date, \
             Signature=00",
        );
        let req = sign_request(req, "testing");
        let next: NextFn = Arc::new(|_| Response::new(500));
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 403);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("InvalidAccessKeyId"));
    }

    #[test]
    fn unknown_ec2_key_defers_to_s3token_client() {
        use swift_middleware::{MapS3TokenClient, S3TokenResult};

        // Capture the raw string-to-sign passed into exchange (must not be X-Amz-Date).
        struct CapturingClient {
            inner: MapS3TokenClient,
            seen_sts: std::sync::Mutex<Option<String>>,
        }
        impl S3TokenClient for CapturingClient {
            fn exchange(
                &self,
                access_key: &str,
                signature: &str,
                string_to_sign: &str,
            ) -> Option<S3TokenResult> {
                *self.seen_sts.lock().unwrap() = Some(string_to_sign.to_string());
                self.inner.exchange(access_key, signature, string_to_sign)
            }
        }

        let mut map = MapS3TokenClient::new();
        map.insert(
            "AKIATEST",
            S3TokenResult {
                token_id: "subj-tok".into(),
                project_id: "proj123".into(),
                project_name: "demo".into(),
                user_id: "uid".into(),
                user_name: "alice".into(),
                roles: vec!["admin".into()],
            },
        );
        let client = Arc::new(CapturingClient {
            inner: map,
            seen_sts: std::sync::Mutex::new(None),
        });
        let api = S3Api::new(cred_map())
            .with_reseller_prefix("AUTH_")
            .with_s3token_client(client.clone());

        let mut req = base_s3_req("PUT", "/ec2bucket/obj", "");
        req.headers.set(
            "Authorization",
            "AWS4-HMAC-SHA256 \
             Credential=AKIATEST/20130524/us-east-1/s3/aws4_request, \
             SignedHeaders=host;x-amz-content-sha256;x-amz-date, \
             Signature=00",
        );
        // Signature is verified by Keystone on the deferral path; local verify skipped.
        req.body = Body::from(b"hello-ec2".to_vec());
        req.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");

        let next: NextFn = Arc::new(|r| {
            assert_eq!(r.path, "/v1/AUTH_proj123/ec2bucket/obj");
            assert_eq!(r.headers.get("X-Backend-Authorize-Override"), Some("true"));
            assert_eq!(r.headers.get("X-Auth-Token"), Some("subj-tok"));
            let mut resp = Response::new(201);
            resp.headers.set("ETag", "\"abc\"");
            resp
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        let sts = client.seen_sts.lock().unwrap().clone().unwrap();
        assert!(sts.starts_with("AWS4-HMAC-SHA256\n"), "sts={sts}");
        assert!(sts.contains("20130524T000000Z"));
        assert_ne!(sts, "20130524T000000Z");
    }

    #[test]
    fn unknown_ec2_key_without_client_still_invalid() {
        let api = S3Api::new(cred_map()); // no s3token_client
        let mut req = base_s3_req("GET", "/", "");
        req.headers.set(
            "Authorization",
            "AWS4-HMAC-SHA256 \
             Credential=AKIATEST/20130524/us-east-1/s3/aws4_request, \
             SignedHeaders=host;x-amz-content-sha256;x-amz-date, \
             Signature=00",
        );
        let next: NextFn = Arc::new(|_| Response::new(500));
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 403);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("InvalidAccessKeyId"));
    }

    #[test]
    fn reject_bad_signature() {
        let api = S3Api::new(cred_map());
        let req = base_s3_req("GET", "/", "");
        // Leave Signature=00 without recomputing.
        let next: NextFn = Arc::new(|_| Response::new(500));
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 403);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("SignatureDoesNotMatch"));
    }

    #[test]
    fn list_buckets_translates_json() {
        let api = S3Api::new(cred_map());
        let req = sign_request(base_s3_req("GET", "/", ""), "testing");
        let next: NextFn = Arc::new(|r| {
            assert_eq!(r.path, "/v1/AUTH_test");
            assert!(r.query_string.contains("format=json"));
            assert_eq!(
                r.headers.get("X-Backend-Authorize-Override"),
                Some("true")
            );
            Response::with_body(
                200,
                br#"[{"name":"b1","count":0,"bytes":0,"last_modified":"2013-05-24T00:00:00.000000"}]"#.to_vec(),
            )
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("ListAllMyBucketsResult"));
        assert!(body.contains("<Name>b1</Name>"));
        assert!(body.contains("2013-05-24T00:00:00.000Z"));
    }

    #[test]
    fn put_object_maps_path_and_status() {
        let api = S3Api::new(cred_map());
        let req = sign_request(base_s3_req("PUT", "/mybucket/dir/obj", ""), "testing");
        let next: NextFn = Arc::new(|r| {
            assert_eq!(r.path, "/v1/AUTH_test/mybucket/dir/obj");
            let mut resp = Response::new(201);
            resp.headers.set("ETag", "abc123");
            resp
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        assert_eq!(resp.headers.get("ETag"), Some("\"abc123\""));
    }

    #[test]
    fn get_object_404_is_nosuchkey() {
        let api = S3Api::new(cred_map());
        let req = sign_request(base_s3_req("GET", "/mybucket/missing", ""), "testing");
        let next: NextFn = Arc::new(|_| Response::new(404));
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 404);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("NoSuchKey"));
    }

    #[test]
    fn list_objects_translates() {
        let api = S3Api::new(cred_map());
        let req = sign_request(base_s3_req("GET", "/mybucket", "prefix=p"), "testing");
        let next: NextFn = Arc::new(|r| {
            assert_eq!(r.path, "/v1/AUTH_test/mybucket");
            assert!(r.query_string.contains("format=json"));
            assert!(r.query_string.contains("prefix=p"));
            Response::with_body(
                200,
                br#"[{"name":"p/a","hash":"deadbeef","bytes":3,"last_modified":"2013-05-24T00:00:00.000000"}]"#.to_vec(),
            )
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("ListBucketResult"));
        assert!(body.contains("<Key>p/a</Key>"));
        assert!(body.contains("\"deadbeef\""));
    }

    #[test]
    fn location_subresource_local() {
        let api = S3Api::new(cred_map()).with_location("eu-west-1");
        let req = sign_request(base_s3_req("GET", "/mybucket", "location"), "testing");
        let next: NextFn = Arc::new(|_| Response::new(500));
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("LocationConstraint"));
        assert!(body.contains("eu-west-1"));
    }

    #[test]
    fn get_acl_returns_private_policy() {
        let api = S3Api::new(cred_map());
        let req = sign_request(base_s3_req("GET", "/mybucket", "acl"), "testing");
        let next: NextFn = Arc::new(|_| {
            let mut r = Response::new(204);
            r.headers.set("X-Container-Read", "");
            r
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("AccessControlPolicy"));
        assert!(body.contains("FULL_CONTROL"));
    }

    #[test]
    fn list_objects_v2_emits_key_count() {
        let api = S3Api::new(cred_map());
        let req = sign_request(base_s3_req("GET", "/mybucket", "list-type=2"), "testing");
        let next: NextFn = Arc::new(|r| {
            assert!(r.query_string.contains("format=json"));
            Response::with_body(
                200,
                br#"[{"name":"a","hash":"aa","bytes":1,"last_modified":"2013-05-24T00:00:00.000000"}]"#.to_vec(),
            )
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("<KeyCount>1</KeyCount>"));
        assert!(body.contains("<Key>a</Key>"));
    }

    #[test]
    fn multi_delete_deletes_keys() {
        let api = S3Api::new(cred_map());
        let mut req = base_s3_req("POST", "/mybucket", "delete");
        req.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        req.body = Body::from(
            br#"<Delete><Object><Key>a</Key></Object><Object><Key>b</Key></Object></Delete>"#
                .to_vec(),
        );
        let req = sign_request(req, "testing");
        let next: NextFn = Arc::new(|r| {
            assert_eq!(r.method, "DELETE");
            Response::new(204)
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("<Deleted><Key>a</Key></Deleted>"));
        assert!(body.contains("<Deleted><Key>b</Key></Deleted>"));
    }

    #[test]
    fn list_multipart_uploads_lists_markers() {
        // `GET /bucket?uploads` lists in-progress markers from +segments.
        let api = S3Api::new(cred_map());
        let req = sign_request(base_s3_req("GET", "/mybucket", "uploads"), "testing");
        let next: NextFn = Arc::new(|r| {
            assert_eq!(r.method, "GET");
            assert_eq!(r.path, "/v1/AUTH_test/mybucket+segments");
            assert!(r.query_string.contains("format=json"));
            let body = br#"[
              {"name":"big/obj/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","bytes":6,"hash":"x","last_modified":"2026-08-05T12:00:00.000000"},
              {"name":"big/obj/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/00000001","bytes":3,"hash":"y","last_modified":"2026-08-05T12:01:00.000000"},
              {"name":"other/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","bytes":6,"hash":"z","last_modified":"2026-08-05T13:00:00.000000"}
            ]"#;
            Response::with_body(200, body.to_vec())
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("ListMultipartUploadsResult"));
        assert!(!body.contains("ListBucketResult"));
        assert!(body.contains("<Key>big/obj</Key>"));
        assert!(body.contains("<UploadId>aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa</UploadId>"));
        assert!(body.contains("<Key>other</Key>"));
        assert!(!body.contains("00000001"));
    }

    #[test]
    fn list_multipart_uploads_empty_when_segments_missing() {
        let api = S3Api::new(cred_map());
        let req = sign_request(base_s3_req("GET", "/mybucket", "uploads"), "testing");
        let next: NextFn = Arc::new(|_| Response::new(404));
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("ListMultipartUploadsResult"));
        assert!(body.contains("<IsTruncated>false</IsTruncated>"));
    }

    #[test]
    fn multipart_upload_initiate_part_and_complete_flow() {
        let api = S3Api::new(cred_map());

        // 1) Initiate: creates the `+segments` container + upload marker,
        // returns an UploadId.
        let init_req = sign_request(base_s3_req("POST", "/mybucket/big/obj", "uploads"), "testing");
        let init_next: NextFn = Arc::new(|r| {
            assert_eq!(r.method, "PUT");
            assert!(
                r.path == "/v1/AUTH_test/mybucket+segments"
                    || r.path.starts_with("/v1/AUTH_test/mybucket+segments/big/obj/")
            );
            Response::new(201)
        });
        let init_resp = api.handle(init_req, &init_next);
        assert_eq!(init_resp.status, 200);
        let init_body = String::from_utf8(init_resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(init_body.contains("InitiateMultipartUploadResult"));
        assert!(init_body.contains("<Bucket>mybucket</Bucket>"));
        assert!(init_body.contains("<Key>big/obj</Key>"));
        let upload_id = init_body
            .split("<UploadId>")
            .nth(1)
            .and_then(|s| s.split("</UploadId>").next())
            .unwrap()
            .to_string();
        assert!(!upload_id.is_empty());

        // 2) UploadPart: streams the part body straight to the segments
        // container under `{key}/{uploadId}/{partNumber:08}`.
        let mut part_req = base_s3_req(
            "PUT",
            "/mybucket/big/obj",
            &format!("partNumber=1&uploadId={upload_id}"),
        );
        part_req
            .headers
            .set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        part_req.body = Body::from(b"hello-part-one".to_vec());
        let part_req = sign_request(part_req, "testing");
        let expected_part_path =
            format!("/v1/AUTH_test/mybucket+segments/big/obj/{upload_id}/00000001");
        let part_next: NextFn = Arc::new(move |r| {
            assert_eq!(r.method, "PUT");
            assert_eq!(r.path, expected_part_path);
            let mut resp = Response::new(201);
            resp.headers.set("ETag", "partetag1");
            resp
        });
        let part_resp = api.handle(part_req, &part_next);
        assert_eq!(part_resp.status, 200);
        assert_eq!(part_resp.headers.get("ETag"), Some("\"partetag1\""));

        // 3) Complete: HEADs each listed part for size, then PUTs the SLO
        // manifest and returns the (Swift-computed) composite ETag.
        let mut complete_req =
            base_s3_req("POST", "/mybucket/big/obj", &format!("uploadId={upload_id}"));
        complete_req
            .headers
            .set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        complete_req.body = Body::from(
            br#"<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>"partetag1"</ETag></Part></CompleteMultipartUpload>"#
                .to_vec(),
        );
        let complete_req = sign_request(complete_req, "testing");
        let complete_next: NextFn = Arc::new(|r| {
            if r.method == "HEAD" {
                let mut resp = Response::new(200);
                resp.headers.set("Content-Length", "14");
                return resp;
            }
            assert_eq!(r.method, "PUT");
            assert_eq!(r.path, "/v1/AUTH_test/mybucket/big/obj");
            assert!(r.query_string.contains("multipart-manifest=put"));
            let mut resp = Response::new(201);
            resp.headers.set("ETag", "compositeetag-1");
            resp
        });
        let complete_resp = api.handle(complete_req, &complete_next);
        assert_eq!(complete_resp.status, 200);
        let complete_body =
            String::from_utf8(complete_resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(complete_body.contains("CompleteMultipartUploadResult"));
        assert!(complete_body.contains("compositeetag-1"));
    }

    #[test]
    fn multipart_upload_abort_deletes_marker() {
        let api = S3Api::new(cred_map());
        let req = sign_request(
            base_s3_req("DELETE", "/mybucket/obj", "uploadId=abc123"),
            "testing",
        );
        let next: NextFn = Arc::new(|r| {
            assert_eq!(r.method, "DELETE");
            assert_eq!(r.path, "/v1/AUTH_test/mybucket+segments/obj/abc123");
            Response::new(204)
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 204);
    }

    #[test]
    fn cors_put_then_get_round_trips() {
        let api = S3Api::new(cred_map());
        let mut put_req = base_s3_req("PUT", "/mybucket", "cors");
        put_req
            .headers
            .set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        put_req.body = Body::from(
            br#"<CORSConfiguration><CORSRule><AllowedOrigin>*</AllowedOrigin>
                <AllowedMethod>GET</AllowedMethod></CORSRule></CORSConfiguration>"#
                .to_vec(),
        );
        let put_req = sign_request(put_req, "testing");
        let put_next: NextFn = Arc::new(|r| {
            assert_eq!(r.method, "POST");
            assert_eq!(
                r.headers.get("X-Container-Meta-Access-Control-Allow-Origin"),
                Some("*")
            );
            Response::new(204)
        });
        assert_eq!(api.handle(put_req, &put_next).status, 200);

        let get_req = sign_request(base_s3_req("GET", "/mybucket", "cors"), "testing");
        let get_next: NextFn = Arc::new(|_| {
            let mut r = Response::new(204);
            r.headers
                .set("X-Container-Meta-Access-Control-Allow-Origin", "*");
            r.headers
                .set("X-Container-Meta-Access-Control-Allow-Methods", "GET");
            r
        });
        let resp = api.handle(get_req, &get_next);
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("CORSConfiguration"));
        assert!(body.contains("<AllowedOrigin>*</AllowedOrigin>"));
    }

    #[test]
    fn cors_multi_rule_put_stamps_s3_cors_meta() {
        use crate::acl_cors::S3_CORS_META;
        let api = S3Api::new(cred_map());
        let mut put_req = base_s3_req("PUT", "/mybucket", "cors");
        put_req
            .headers
            .set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        put_req.body = Body::from(
            br#"<CORSConfiguration>
              <CORSRule>
                <AllowedOrigin>https://a.example.com</AllowedOrigin>
                <AllowedMethod>GET</AllowedMethod>
              </CORSRule>
              <CORSRule>
                <AllowedOrigin>https://b.example.com</AllowedOrigin>
                <AllowedMethod>PUT</AllowedMethod>
                <AllowedMethod>POST</AllowedMethod>
              </CORSRule>
            </CORSConfiguration>"#
                .to_vec(),
        );
        let put_req = sign_request(put_req, "testing");
        let stored = std::sync::Arc::new(std::sync::Mutex::new(None::<HeaderKeyDict>));
        let stored_c = stored.clone();
        let put_next: NextFn = Arc::new(move |r| {
            assert_eq!(r.method, "POST");
            assert!(r.headers.get(S3_CORS_META).is_some_and(|v| !v.is_empty()));
            assert_eq!(
                r.headers.get("X-Container-Meta-Access-Control-Allow-Origin"),
                Some("https://a.example.com")
            );
            *stored_c.lock().unwrap() = Some(r.headers.clone());
            Response::new(204)
        });
        assert_eq!(api.handle(put_req, &put_next).status, 200);

        let hdrs = stored.lock().unwrap().clone().unwrap();
        let get_req = sign_request(base_s3_req("GET", "/mybucket", "cors"), "testing");
        let get_next: NextFn = Arc::new(move |_| {
            let mut r = Response::new(204);
            r.headers = hdrs.clone();
            r
        });
        let resp = api.handle(get_req, &get_next);
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert_eq!(body.matches("<CORSRule>").count(), 2);
        assert!(body.contains("https://a.example.com"));
        assert!(body.contains("https://b.example.com"));
        assert!(body.contains("<AllowedMethod>PUT</AllowedMethod>"));
    }

    #[test]
    fn put_bucket_acl_public_read_write() {
        let api = S3Api::new(cred_map());
        let mut req = base_s3_req("PUT", "/mybucket", "acl");
        req.headers.set("x-amz-acl", "public-read-write");
        req.headers
            .set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        let req = sign_request(req, "testing");
        let next: NextFn = Arc::new(|r| {
            assert_eq!(r.method, "POST");
            assert_eq!(
                r.headers.get("X-Container-Read"),
                Some(".r:*,.rlistings")
            );
            assert_eq!(r.headers.get("X-Container-Write"), Some(".r:*"));
            Response::new(204)
        });
        assert_eq!(api.handle(req, &next).status, 200);
    }

    #[test]
    fn put_object_stores_canned_acl_sysmeta() {
        let api = S3Api::new(cred_map());
        let mut req = base_s3_req("PUT", "/mybucket/obj1", "");
        req.headers.set("x-amz-acl", "public-read");
        req.headers
            .set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        req.body = Body::from(b"hi".to_vec());
        let req = sign_request(req, "testing");
        let next: NextFn = Arc::new(|r| {
            assert_eq!(r.method, "PUT");
            assert_eq!(r.path, "/v1/AUTH_test/mybucket/obj1");
            assert_eq!(
                r.headers.get(S3_OBJECT_ACL_META),
                Some("public-read")
            );
            // Object path must not stamp container ACL headers.
            assert!(r.headers.get("X-Container-Read").is_none());
            let mut resp = Response::new(201);
            resp.headers.set("Etag", "\"abc\"");
            resp
        });
        assert_eq!(api.handle(req, &next).status, 200);
    }

    #[test]
    fn get_object_acl_from_sysmeta() {
        let api = S3Api::new(cred_map());
        let req = sign_request(base_s3_req("GET", "/mybucket/obj1", "acl"), "testing");
        let next: NextFn = Arc::new(|r| {
            assert_eq!(r.method, "HEAD");
            assert_eq!(r.path, "/v1/AUTH_test/mybucket/obj1");
            let mut resp = Response::new(200);
            resp.headers.set(S3_OBJECT_ACL_META, "public-read");
            resp
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("AccessControlPolicy"));
        assert!(body.contains("AllUsers"));
        assert!(body.contains("<Permission>READ</Permission>"));
    }

    #[test]
    fn get_object_acl_defaults_private_when_no_meta() {
        let api = S3Api::new(cred_map());
        let req = sign_request(base_s3_req("GET", "/mybucket/obj1", "acl"), "testing");
        let next: NextFn = Arc::new(|_| Response::new(200));
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("FULL_CONTROL"));
        assert!(!body.contains("AllUsers"));
    }

    #[test]
    fn put_object_acl_posts_sysmeta() {
        let api = S3Api::new(cred_map());
        let mut req = base_s3_req("PUT", "/mybucket/obj1", "acl");
        req.headers.set("x-amz-acl", "private");
        req.headers
            .set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        let req = sign_request(req, "testing");
        let next: NextFn = Arc::new(|r| {
            assert_eq!(r.method, "POST");
            assert_eq!(r.path, "/v1/AUTH_test/mybucket/obj1");
            assert_eq!(r.headers.get(S3_OBJECT_ACL_META), Some("private"));
            Response::new(202)
        });
        assert_eq!(api.handle(req, &next).status, 200);
    }

    #[test]
    fn unsupported_lifecycle_still_501() {
        let api = S3Api::new(cred_map());
        let req = sign_request(base_s3_req("GET", "/mybucket", "lifecycle"), "testing");
        let next: NextFn = Arc::new(|_| Response::new(500));
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 501);
    }

    #[test]
    fn create_and_delete_bucket() {
        let api = S3Api::new(cred_map());
        let put = sign_request(base_s3_req("PUT", "/newbucket", ""), "testing");
        let next_put: NextFn = Arc::new(|r| {
            assert_eq!(r.path, "/v1/AUTH_test/newbucket");
            assert_eq!(r.method, "PUT");
            Response::new(201)
        });
        assert_eq!(api.handle(put, &next_put).status, 200);

        let del = sign_request(base_s3_req("DELETE", "/newbucket", ""), "testing");
        let next_del: NextFn = Arc::new(|r| {
            assert_eq!(r.path, "/v1/AUTH_test/newbucket");
            Response::new(204)
        });
        assert_eq!(api.handle(del, &next_del).status, 204);
    }

    #[test]
    fn credentials_from_tempauth_admin() {
        let users = vec![(
            "test".into(),
            "tester".into(),
            "testing".into(),
            vec![".admin".into()],
        )];
        let m = credentials_from_tempauth_users(&users, "AUTH_");
        let c = m.get("test:tester").unwrap();
        assert_eq!(c.secret_key, "testing");
        assert_eq!(c.account, "AUTH_test");
        assert!(c.groups.iter().any(|g| g == "AUTH_test"));
    }

    #[test]
    fn copy_object_sets_x_copy_from() {
        let api = S3Api::new(cred_map());
        let mut req = base_s3_req("PUT", "/dst/obj", "");
        req.headers.set("x-amz-copy-source", "/src/obj");
        // signed headers must include the copy source for a real client; for
        // path rewrite we only need a valid SigV4 over the declared set.
        let req = sign_request(req, "testing");
        let next: NextFn = Arc::new(|r| {
            assert_eq!(r.headers.get("X-Copy-From"), Some("src/obj"));
            let mut resp = Response::new(201);
            resp.headers.set("ETag", "ff");
            resp.headers
                .set("Last-Modified", "2013-05-24T00:00:00.000000");
            resp
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("CopyObjectResult"));
    }
}
