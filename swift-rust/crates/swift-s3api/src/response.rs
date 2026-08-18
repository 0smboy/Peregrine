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

//! S3 error XML and the bucket-listing / object-result XML shapes.
//!
//! Ported from `s3response.py` (`ErrorResponse`), `controllers/service.py`
//! (`ListAllMyBucketsResult`), `controllers/bucket.py` (`ListBucketResult`)
//! and `controllers/multi_delete.py` (`DeleteResult`). Wave 3 adds ListObjects
//! v2 shapes; ACL/CORS/MPU live in sibling modules.

use crate::xml::Element;
use swift_http::{parse_http_date, Response};

/// Howard Hinnant civil-from-days / days-from-civil (same as `swift_http::dates`).
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

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 } as i64;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn epoch_secs_to_s3_xml(secs: i64) -> String {
    let days = secs.div_euclid(86400);
    let sod = secs.rem_euclid(86400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.000Z",
        sod / 3600,
        (sod % 3600) / 60,
        sod % 60
    )
}

fn parse_iso_like_to_epoch(value: &str) -> Option<i64> {
    let mut s = value.trim();
    if let Some(rest) = s.strip_suffix('Z').or_else(|| s.strip_suffix('z')) {
        s = rest.trim_end();
    } else if let Some(idx) = s.rfind(|c: char| c == '+' || c == '-').filter(|&i| i >= 10) {
        s = s[..idx].trim_end();
    }
    let (date, time) = s.split_once('T').or_else(|| s.split_once(' '))?;
    let mut dparts = date.split('-');
    let y: i64 = dparts.next()?.parse().ok()?;
    let mo: u32 = dparts.next()?.parse().ok()?;
    let da: u32 = dparts.next()?.parse().ok()?;
    if dparts.next().is_some() {
        return None;
    }
    let time = time.split('.').next().unwrap_or(time);
    let mut tparts = time.split(':');
    let h: i64 = tparts.next()?.parse().ok()?;
    let mi: i64 = tparts.next()?.parse().ok()?;
    let se: i64 = tparts.next()?.parse().ok()?;
    if !(1..=12).contains(&mo) || !(1..=31).contains(&da) || !(0..=23).contains(&h)
        || !(0..=59).contains(&mi)
        || se > 60
    {
        return None;
    }
    Some(days_from_civil(y, mo, da) * 86400 + h * 3600 + mi * 60 + se)
}

/// S3 XML `LastModified` / `Initiated`: `YYYY-MM-DDTHH:MM:SS.000Z`.
///
/// Python `S3Timestamp.s3xmlformat`. Parses RFC 1123 (`Last-Modified`) and
/// Swift listing ISO (`2013-05-24T00:00:00.000000`). Always returns a string
/// that Python 3.9 `datetime.fromisoformat` accepts after the runner's
/// trailing-`Z` → `+00:00` rewrite. Unparseable input → epoch, never the raw
/// HTTP date (that is the CopyObject / ListVersions `_iso_time` hole).
pub fn s3_xml_timestamp(value: &str) -> String {
    let value = value.trim();
    if let Some(secs) = parse_http_date(value).or_else(|| parse_iso_like_to_epoch(value)) {
        return epoch_secs_to_s3_xml(secs);
    }
    "1970-01-01T00:00:00.000Z".to_string()
}

/// Look up the HTTP status and default message for a known S3 error code.
///
/// Port of the `_status`/`_msg` fields on the `ErrorResponse` subclasses in
/// `s3response.py`. Unknown codes default to `400 Bad Request` with the code
/// as the message.
pub fn error_status_and_message(code: &str) -> (u16, &'static str) {
    match code {
        "AccessDenied" => (403, "Access Denied."),
        "AccountProblem" => (
            403,
            "There is a problem with your AWS account that prevents the operation from completing successfully.",
        ),
        "AuthorizationHeaderMalformed" => (400, "The authorization header is malformed."),
        "AuthorizationQueryParametersError" => (400, "Query-string authentication is malformed."),
        "BadDigest" => (400, "The Content-MD5 you specified did not match what we received."),
        "BucketAlreadyExists" => (
            409,
            "The requested bucket name is not available. The bucket namespace is shared by all users of the system. Please select a different name and try again.",
        ),
        "BucketAlreadyOwnedByYou" => (
            409,
            "Your previous request to create the named bucket succeeded and you already own it.",
        ),
        "BucketNotEmpty" => (409, "The bucket you tried to delete is not empty"),
        "CredentialsNotSupported" => (400, "This request does not support credentials."),
        "EntityTooLarge" => (400, "Your proposed upload exceeds the maximum allowed object size."),
        "EntityTooSmall" => (
            400,
            "Your proposed upload is smaller than the minimum allowed object size.",
        ),
        "IncompleteBody" => (
            400,
            "You did not provide the number of bytes specified by the Content-Length HTTP header.",
        ),
        "InternalError" => (500, "We encountered an internal error. Please try again."),
        "InvalidAccessKeyId" => (
            403,
            "The AWS Access Key Id you provided does not exist in our records.",
        ),
        "InvalidArgument" => (400, "Invalid Argument."),
        "InvalidBucketName" => (400, "The specified bucket is not valid."),
        "InvalidBucketState" => (409, "The request is not valid with the current state of the bucket."),
        "InvalidDigest" => (400, "The Content-MD5 you specified was invalid."),
        "InvalidPart" => (
            400,
            "One or more of the specified parts could not be found. The part might not have been uploaded, or the specified entity tag might not have matched the part's entity tag.",
        ),
        "InvalidPartNumber" => (416, "The requested partnumber is not satisfiable"),
        "InvalidRange" => (416, "The requested range cannot be satisfied."),
        "InvalidRequest" => (400, "Invalid Request."),
        "InvalidStorageClass" => (400, "The storage class you specified is not valid."),
        "InvalidURI" => (400, "Couldn't parse the specified URI."),
        "MalformedXML" => (
            400,
            "The XML you provided was not well-formed or did not validate against our published schema",
        ),
        "MethodNotAllowed" => (405, "The specified method is not allowed against this resource."),
        "MissingContentLength" => (411, "You must provide the Content-Length HTTP header."),
        "NoSuchBucket" => (404, "The specified bucket does not exist."),
        "NoSuchKey" => (404, "The specified key does not exist."),
        "NoSuchLifecycleConfiguration" => (
            404,
            "The lifecycle configuration does not exist.",
        ),
        "NoSuchTagSet" => (404, "The TagSet does not exist."),
        "NoSuchUpload" => (
            404,
            "The specified multipart upload does not exist. The upload ID might be invalid, or the multipart upload might have been aborted or completed.",
        ),
        "NoSuchVersion" => (404, "The specified version does not exist."),
        "ObjectLockConfigurationNotFoundError" => (
            404,
            "Object Lock configuration does not exist for this bucket.",
        ),
        "NotImplemented" => (501, "A header you provided implies functionality that is not implemented."),
        "PermanentRedirect" => (
            301,
            "The bucket you are attempting to access must be addressed using the specified endpoint. Please send all future requests to this endpoint.",
        ),
        "PreconditionFailed" => (412, "At least one of the preconditions you specified did not hold."),
        "RequestTimeout" => (
            400,
            "Your socket connection to the server was not read from or written to within the timeout period.",
        ),
        "RequestTimeTooSkewed" => (
            403,
            "The difference between the request time and the current time is too large.",
        ),
        "ServiceUnavailable" => (503, "Please reduce your request rate."),
        "SignatureDoesNotMatch" => (
            403,
            "The request signature we calculated does not match the signature you provided. Check your key and signing method.",
        ),
        "SlowDown" => (503, "Please reduce your request rate."),
        "TooManyBuckets" => (400, "You have attempted to create more buckets than allowed."),
        _ => (400, "Bad Request"),
    }
}

/// Python `generate_trans_id('')`: `tx{21 hex}-{10 hex unix time}` (34 chars).
///
/// grok-merge `_normalize_error` rewrites the value to `"<dynamic-id>"` when
/// the element is present. Empty extras must still emit the child — that is
/// the post-F1 delta vs Python `ErrorResponse._body_iter`.
fn default_request_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static SEQ: AtomicU64 = AtomicU64::new(1);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let pid = u64::from(std::process::id());
    let mixed = pid
        .wrapping_mul(0x9e3779b97f4a7c15)
        .wrapping_add(seq)
        .wrapping_mul(0xbf58476d1ce4e5b9);
    let rand21 = format!("{:016x}{:05x}", mixed, seq & 0xfffff);
    format!("tx{}-{:010x}", &rand21[..21], now)
}

/// Build an S3 error document (no XML namespace on the root).
///
/// `extras` are appended as child elements (e.g. `("BucketName", "b")`,
/// `("Resource", "/b/o")`), matching the `info` dict rendered by
/// `ErrorResponse._body_iter`. A `RequestId` child is always present
/// (inserted after `Message` when `extras` does not already carry one).
/// Do not auto-emit `HostId` / `Resource` / `RequestTime` / `ServerTime` /
/// `MaxAllowedSkew` — Python 2.33 did not, and `_normalize_error` would
/// keep the allowed ones as a dict mismatch.
pub fn s3_error_xml(code: &str, message: &str, extras: &[(&str, &str)]) -> Vec<u8> {
    let mut error = Element::new("Error");
    error.push_leaf("Code", code);
    error.push_leaf("Message", message);
    let generated_id = if extras
        .iter()
        .any(|(tag, _)| tag.eq_ignore_ascii_case("RequestId"))
    {
        None
    } else {
        Some(default_request_id())
    };
    if let Some(ref rid) = generated_id {
        error.push_leaf("RequestId", rid.as_str());
    }
    for (tag, value) in extras {
        error.push_leaf(*tag, *value);
    }
    error.to_xml(false)
}

/// Build a complete S3 error [`Response`]: correct status, an
/// `application/xml` body carrying the error document. When `message` is
/// `None` the default message for `code` is used.
pub fn s3_error_response(code: &str, message: Option<&str>, extras: &[(&str, &str)]) -> Response {
    let (status, default_msg) = error_status_and_message(code);
    let msg = message.unwrap_or(default_msg);
    let body = s3_error_xml(code, msg, extras);
    let mut resp = Response::with_body(status, body);
    resp.headers.set("Content-Type", "application/xml");
    resp
}

/// Child text of `<tag>…</tag>` in compact S3 Error XML (no attributes).
#[cfg(test)]
pub(crate) fn error_xml_leaf<'a>(body: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = body.find(&open)? + open.len();
    let rest = &body[start..];
    let end = rest.find(&close)?;
    Some(&rest[..end])
}

/// Whether `value` would survive grok-merge `_normalize_error` for RequestId.
#[cfg(test)]
pub(crate) fn request_id_survives_normalize(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 2048
        && !value.chars().any(|c| {
            let o = c as u32;
            o < 32 || o == 127
        })
}

/// Code + Message + RequestId only — the post-`_normalize_error` shape of
/// the five F1 deny bodies (invalid-storage-class, two clock-skew, two
/// query-expired). Status is not checked here.
#[cfg(test)]
pub(crate) fn assert_error_xml_matches_normalize(body: &str, code: &str, message: &str) {
    assert_eq!(error_xml_leaf(body, "Code"), Some(code), "Code in {body}");
    assert_eq!(
        error_xml_leaf(body, "Message"),
        Some(message),
        "Message in {body}"
    );
    let rid = error_xml_leaf(body, "RequestId").expect("RequestId required after _normalize_error");
    assert!(
        request_id_survives_normalize(rid),
        "RequestId {rid:?} would fail _normalize_error"
    );
    for tag in [
        "Resource",
        "HostId",
        "Endpoint",
        "BucketName",
        "Key",
        "ArgumentName",
        "ArgumentValue",
        "RequestTime",
        "ServerTime",
        "MaxAllowedSkew",
    ] {
        assert!(
            error_xml_leaf(body, tag).is_none(),
            "unexpected <{tag}> in {body}"
        );
    }
}

/// An object owner (`ID`/`DisplayName`).
#[derive(Debug, Clone)]
pub struct Owner {
    pub id: String,
    pub display_name: String,
}

/// One `<Contents>` entry in a bucket listing.
#[derive(Debug, Clone)]
pub struct S3Object {
    pub key: String,
    /// S3 XML timestamp, e.g. `2013-05-24T00:00:00.000Z`.
    pub last_modified: String,
    /// The ETag as it should appear, including surrounding quotes.
    pub etag: String,
    pub size: u64,
    pub storage_class: String,
    pub owner: Option<Owner>,
}

/// A `ListBucketResult` (S3 ListObjects v1) document builder.
#[derive(Debug, Clone, Default)]
pub struct ListBucketResult {
    pub name: String,
    pub prefix: String,
    pub marker: String,
    pub next_marker: Option<String>,
    pub max_keys: u32,
    pub delimiter: Option<String>,
    pub encoding_type: Option<String>,
    pub is_truncated: bool,
    pub contents: Vec<S3Object>,
    pub common_prefixes: Vec<String>,
}

impl ListBucketResult {
    /// Serialize to the S3 XML bytes (with the S3 namespace on the root).
    pub fn to_xml(&self) -> Vec<u8> {
        let mut elem = Element::new("ListBucketResult");
        elem.push_leaf("Name", &self.name);
        elem.push_leaf("Prefix", &self.prefix);
        elem.push_leaf("Marker", &self.marker);
        if let Some(nm) = &self.next_marker {
            elem.push_leaf("NextMarker", nm);
        }
        elem.push_leaf("MaxKeys", self.max_keys.to_string());
        if let Some(d) = &self.delimiter {
            elem.push_leaf("Delimiter", d);
        }
        if let Some(e) = &self.encoding_type {
            elem.push_leaf("EncodingType", e);
        }
        elem.push_leaf(
            "IsTruncated",
            if self.is_truncated { "true" } else { "false" },
        );
        for obj in &self.contents {
            elem.push(object_element(obj));
        }
        for prefix in &self.common_prefixes {
            let cp = Element::new("CommonPrefixes").with_leaf("Prefix", prefix);
            elem.push(cp);
        }
        elem.to_xml(true)
    }

    /// A ready-to-send `200 OK` `application/xml` [`Response`].
    pub fn into_response(self) -> Response {
        xml_response(200, self.to_xml())
    }
}

/// A `ListBucketResult` for ListObjectsV2 (`list-type=2`).
#[derive(Debug, Clone, Default)]
pub struct ListBucketResultV2 {
    pub name: String,
    pub prefix: String,
    pub start_after: String,
    pub continuation_token: Option<String>,
    pub next_continuation_token: Option<String>,
    pub key_count: u32,
    pub max_keys: u32,
    pub delimiter: Option<String>,
    pub encoding_type: Option<String>,
    pub is_truncated: bool,
    pub contents: Vec<S3Object>,
    pub common_prefixes: Vec<String>,
}

impl ListBucketResultV2 {
    pub fn to_xml(&self) -> Vec<u8> {
        let mut elem = Element::new("ListBucketResult");
        elem.push_leaf("Name", &self.name);
        elem.push_leaf("Prefix", &self.prefix);
        if !self.start_after.is_empty() {
            elem.push_leaf("StartAfter", &self.start_after);
        }
        if let Some(ct) = &self.continuation_token {
            elem.push_leaf("ContinuationToken", ct);
        }
        if let Some(nct) = &self.next_continuation_token {
            elem.push_leaf("NextContinuationToken", nct);
        }
        elem.push_leaf("KeyCount", self.key_count.to_string());
        elem.push_leaf("MaxKeys", self.max_keys.to_string());
        if let Some(d) = &self.delimiter {
            elem.push_leaf("Delimiter", d);
        }
        if let Some(e) = &self.encoding_type {
            elem.push_leaf("EncodingType", e);
        }
        elem.push_leaf(
            "IsTruncated",
            if self.is_truncated { "true" } else { "false" },
        );
        for obj in &self.contents {
            elem.push(object_element(obj));
        }
        for prefix in &self.common_prefixes {
            let cp = Element::new("CommonPrefixes").with_leaf("Prefix", prefix);
            elem.push(cp);
        }
        elem.to_xml(true)
    }

    pub fn into_response(self) -> Response {
        xml_response(200, self.to_xml())
    }
}

fn object_element(obj: &S3Object) -> Element {
    let mut contents = Element::new("Contents");
    contents.push_leaf("Key", &obj.key);
    contents.push_leaf("LastModified", &obj.last_modified);
    // AWS / Python s3api always emit a quote-wrapped ETag in ListBucketResult.
    // s3cmd and other plain-XML clients expect `<ETag>"md5"</ETag>` (quotes inside).
    let etag = ensure_quoted_etag(&obj.etag);
    contents.push_leaf("ETag", etag);
    contents.push_leaf("Size", obj.size.to_string());
    if let Some(owner) = &obj.owner {
        contents.push(owner_element(owner));
    }
    contents.push_leaf("StorageClass", &obj.storage_class);
    contents
}

/// Ensure `etag` is wrapped in double quotes for S3 XML (and headers).
fn ensure_quoted_etag(etag: &str) -> String {
    let t = etag.trim().trim_matches('"');
    format!("\"{t}\"")
}

fn owner_element(owner: &Owner) -> Element {
    Element::new("Owner")
        .with_leaf("ID", &owner.id)
        .with_leaf("DisplayName", &owner.display_name)
}

/// One `<Bucket>` in a service (list-all-my-buckets) listing.
#[derive(Debug, Clone)]
pub struct BucketInfo {
    pub name: String,
    /// S3 XML timestamp.
    pub creation_date: String,
}

/// Build a `ListAllMyBucketsResult` (S3 ListBuckets) document.
/// Port of `ServiceController.GET`.
pub fn list_all_my_buckets_xml(owner: &Owner, buckets: &[BucketInfo]) -> Vec<u8> {
    let mut root = Element::new("ListAllMyBucketsResult");
    root.push(owner_element(owner));
    let mut buckets_elem = Element::new("Buckets");
    for b in buckets {
        buckets_elem.push(
            Element::new("Bucket")
                .with_leaf("Name", &b.name)
                .with_leaf("CreationDate", &b.creation_date),
        );
    }
    root.push(buckets_elem);
    root.to_xml(true)
}

/// Build a `CopyObjectResult` document (used for PUT-copy).
pub fn copy_object_result_xml(last_modified: &str, etag: &str) -> Vec<u8> {
    Element::new("CopyObjectResult")
        .with_leaf("LastModified", s3_xml_timestamp(last_modified))
        .with_leaf("ETag", format!("\"{}\"", etag.trim().trim_matches('"')))
        .to_xml(true)
}

/// Build a `CopyPartResult` document for UploadPartCopy.
pub fn copy_part_result_xml(last_modified: &str, etag: &str) -> Vec<u8> {
    Element::new("CopyPartResult")
        .with_leaf("LastModified", s3_xml_timestamp(last_modified))
        .with_leaf("ETag", format!("\"{}\"", etag.trim().trim_matches('"')))
        .to_xml(true)
}

/// `GetBucketPolicyStatus`: no stored policy means the bucket is not public.
pub fn policy_status_xml(is_public: bool) -> Vec<u8> {
    Element::new("PolicyStatus")
        .with_leaf("IsPublic", if is_public { "true" } else { "false" })
        .to_xml(true)
}

/// `GetObjectAttributes` subset from object HEAD (ETag / ObjectSize / StorageClass).
pub fn get_object_attributes_xml(
    requested: &str,
    etag: &str,
    object_size: &str,
    storage_class: &str,
) -> Vec<u8> {
    let wanted: Vec<String> = requested
        .split(',')
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    let want = |name: &str| wanted.iter().any(|w| w == name);
    let mut root = Element::new("GetObjectAttributesOutput");
    if want("etag") {
        root.push_leaf("ETag", etag.trim().trim_matches('"'));
    }
    if want("objectsize") {
        root.push_leaf("ObjectSize", object_size);
    }
    if want("storageclass") {
        root.push_leaf("StorageClass", storage_class);
    }
    root.to_xml(true)
}

/// One error entry in a multi-object delete result.
#[derive(Debug, Clone)]
pub struct DeleteError {
    pub key: String,
    pub version_id: Option<String>,
    pub code: String,
    pub message: String,
}

/// One successful multi-delete entry, including version/delete-marker detail.
#[derive(Debug, Clone)]
pub struct DeletedObject {
    pub key: String,
    pub version_id: Option<String>,
    pub delete_marker: bool,
    pub delete_marker_version_id: Option<String>,
}

/// Build a `DeleteResult` document for `POST /bucket?delete`.
/// Port of `MultiObjectDeleteController`.
pub fn delete_result_xml(deleted: &[DeletedObject], errors: &[DeleteError]) -> Vec<u8> {
    let mut root = Element::new("DeleteResult");
    for deleted in deleted {
        let mut item = Element::new("Deleted").with_leaf("Key", &deleted.key);
        if let Some(version_id) = &deleted.version_id {
            item.push_leaf("VersionId", version_id);
        }
        if deleted.delete_marker {
            item.push_leaf("DeleteMarker", "true");
        }
        if let Some(version_id) = &deleted.delete_marker_version_id {
            item.push_leaf("DeleteMarkerVersionId", version_id);
        }
        root.push(item);
    }
    for err in errors {
        let mut item = Element::new("Error").with_leaf("Key", &err.key);
        if let Some(version_id) = &err.version_id {
            item.push_leaf("VersionId", version_id);
        }
        item.push_leaf("Code", &err.code);
        item.push_leaf("Message", &err.message);
        root.push(item);
    }
    root.to_xml(true)
}

/// Wrap XML bytes in an `application/xml` response with the given status.
pub fn xml_response(status: u16, body: Vec<u8>) -> Response {
    let mut resp = Response::with_body(status, body);
    resp.headers.set("Content-Type", "application/xml");
    resp
}

/// A `PUT`-object success response: `200 OK`, `ETag` header set to the
/// quote-wrapped `etag`, empty body. Port of the object PUT success shape.
pub fn put_object_response(etag: &str) -> Response {
    let mut resp = Response::new(200);
    resp.headers.set("ETag", format!("\"{etag}\""));
    resp
}

/// A `DELETE` success response: `204 No Content`.
pub fn delete_object_response() -> Response {
    Response::new(204)
}

/// A `HEAD`/`GET`-object metadata response: `200 OK` with the standard object
/// headers. `body` is empty for HEAD. The `etag` is quote-wrapped.
pub fn object_metadata_response(
    content_length: u64,
    etag: &str,
    last_modified_http: &str,
    content_type: &str,
    body: Vec<u8>,
) -> Response {
    let mut resp = Response::with_body(200, body);
    resp.headers
        .set("Content-Length", content_length.to_string());
    resp.headers.set("ETag", format!("\"{etag}\""));
    resp.headers.set("Last-Modified", last_modified_http);
    resp.headers.set("Content-Type", content_type);
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_xml_shape() {
        let body = s3_error_xml(
            "NoSuchBucket",
            "The specified bucket does not exist.",
            &[("RequestId", "txfixed"), ("BucketName", "faux-bucket")],
        );
        let got = String::from_utf8(body).unwrap();
        assert_eq!(
            got,
            "<?xml version='1.0' encoding='UTF-8'?>\n\
             <Error><Code>NoSuchBucket</Code>\
             <Message>The specified bucket does not exist.</Message>\
             <RequestId>txfixed</RequestId>\
             <BucketName>faux-bucket</BucketName></Error>"
        );
    }

    #[test]
    fn test_error_xml_inserts_request_id_when_missing() {
        let body = s3_error_xml(
            "NoSuchBucket",
            "The specified bucket does not exist.",
            &[("BucketName", "faux-bucket")],
        );
        let got = String::from_utf8(body).unwrap();
        let rid = error_xml_leaf(&got, "RequestId").expect("auto RequestId");
        assert!(request_id_survives_normalize(rid));
        assert_eq!(rid.len(), 34, "{rid}");
        assert!(rid.starts_with("tx"), "{rid}");
        assert!(got.contains("<BucketName>faux-bucket</BucketName>"));
        assert_eq!(got.matches("<RequestId>").count(), 1);
    }

    #[test]
    fn five_deny_error_xml_bodies_match_normalize_for_skew_and_storage_class() {
        // Three Code/Message pairs cover the five runner cases
        // (v2/v4 share codes). Status stays 403/400.
        let cases: &[(&str, Option<&str>, &str, u16)] = &[
            (
                "InvalidStorageClass",
                None,
                "The storage class you specified is not valid.",
                400,
            ),
            (
                "RequestTimeTooSkewed",
                None,
                "The difference between the request time and the current time is too large.",
                403,
            ),
            (
                "AccessDenied",
                Some("Request has expired"),
                "Request has expired",
                403,
            ),
        ];
        for (code, msg, expected_msg, status) in cases {
            let resp = s3_error_response(code, *msg, &[]);
            assert_eq!(resp.status, *status, "{code} status");
            assert_eq!(resp.headers.get("Content-Type"), Some("application/xml"));
            let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
            assert_error_xml_matches_normalize(&body, code, expected_msg);
        }
    }

    #[test]
    fn test_error_response_status_and_default_message() {
        let resp = s3_error_response("NoSuchKey", None, &[("Key", "obj")]);
        assert_eq!(resp.status, 404);
        assert_eq!(resp.headers.get("Content-Type"), Some("application/xml"));
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("<Code>NoSuchKey</Code>"));
        assert!(body.contains("<Message>The specified key does not exist.</Message>"));
        assert!(body.contains("<Key>obj</Key>"));
        let rid = error_xml_leaf(&body, "RequestId").expect("RequestId");
        assert!(request_id_survives_normalize(rid));
    }

    #[test]
    fn test_error_response_signature_does_not_match() {
        let resp = s3_error_response("SignatureDoesNotMatch", None, &[]);
        assert_eq!(resp.status, 403);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        let rid = error_xml_leaf(&body, "RequestId").expect("RequestId");
        assert!(request_id_survives_normalize(rid));
    }

    #[test]
    fn test_list_bucket_result_shape() {
        let lbr = ListBucketResult {
            name: "bucket".to_string(),
            prefix: String::new(),
            marker: String::new(),
            next_marker: None,
            max_keys: 1000,
            delimiter: None,
            encoding_type: None,
            is_truncated: false,
            contents: vec![S3Object {
                key: "obj".to_string(),
                last_modified: "2013-05-24T00:00:00.000Z".to_string(),
                etag: "\"0000\"".to_string(),
                size: 42,
                storage_class: "STANDARD".to_string(),
                owner: None,
            }],
            common_prefixes: vec!["photos/".to_string()],
        };
        let got = String::from_utf8(lbr.to_xml()).unwrap();
        assert_eq!(
            got,
            "<?xml version='1.0' encoding='UTF-8'?>\n\
             <ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
             <Name>bucket</Name><Prefix></Prefix><Marker></Marker><MaxKeys>1000</MaxKeys>\
             <IsTruncated>false</IsTruncated>\
             <Contents><Key>obj</Key><LastModified>2013-05-24T00:00:00.000Z</LastModified>\
             <ETag>\"0000\"</ETag><Size>42</Size><StorageClass>STANDARD</StorageClass></Contents>\
             <CommonPrefixes><Prefix>photos/</Prefix></CommonPrefixes>\
             </ListBucketResult>"
        );
    }

    /// s3cmd `ls` path: Content-Type + xmlns + quoted ETag on ListObjects v1.
    #[test]
    fn test_list_bucket_result_into_response_content_type_and_etag() {
        let lbr = ListBucketResult {
            name: "b".to_string(),
            prefix: String::new(),
            marker: String::new(),
            next_marker: None,
            max_keys: 1000,
            delimiter: None,
            encoding_type: None,
            is_truncated: false,
            contents: vec![S3Object {
                key: "k".to_string(),
                last_modified: "2013-05-24T00:00:00.000Z".to_string(),
                // Unquoted input must still serialize as quoted (Python parity).
                etag: "deadbeef".to_string(),
                size: 1,
                storage_class: "STANDARD".to_string(),
                owner: None,
            }],
            common_prefixes: vec![],
        };
        let resp = lbr.into_response();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.headers.get("Content-Type"), Some("application/xml"));
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(
            body.starts_with("<?xml version='1.0' encoding='UTF-8'?>\n<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"),
            "root+xmlns missing: {body}"
        );
        assert!(
            body.contains("<ETag>\"deadbeef\"</ETag>"),
            "quoted ETag missing: {body}"
        );
        assert!(body.contains("<IsTruncated>false</IsTruncated>"));
        assert!(body.contains("<Contents>"));
        assert!(body.ends_with("</ListBucketResult>") || body.contains("</ListBucketResult>"));
    }

    /// ListObjectsV2: same Content-Type / xmlns / ETag contract as v1.
    #[test]
    fn test_list_bucket_result_v2_into_response_content_type_and_etag() {
        let lbr = ListBucketResultV2 {
            name: "b".to_string(),
            prefix: String::new(),
            start_after: String::new(),
            continuation_token: None,
            next_continuation_token: None,
            key_count: 1,
            max_keys: 1000,
            delimiter: None,
            encoding_type: None,
            is_truncated: false,
            contents: vec![S3Object {
                key: "a".to_string(),
                last_modified: "2013-05-24T00:00:00.000Z".to_string(),
                etag: "\"aa\"".to_string(),
                size: 1,
                storage_class: "STANDARD".to_string(),
                owner: None,
            }],
            common_prefixes: vec![],
        };
        let resp = lbr.into_response();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.headers.get("Content-Type"), Some("application/xml"));
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(
            body.contains("<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">")
        );
        assert!(body.contains("<KeyCount>1</KeyCount>"));
        assert!(body.contains("<ETag>\"aa\"</ETag>"));
        assert!(body.contains("<Key>a</Key>"));
    }

    #[test]
    fn test_list_bucket_result_with_owner_and_delimiter() {
        let lbr = ListBucketResult {
            name: "b".to_string(),
            prefix: "p".to_string(),
            marker: "m".to_string(),
            next_marker: Some("n".to_string()),
            max_keys: 10,
            delimiter: Some("/".to_string()),
            encoding_type: Some("url".to_string()),
            is_truncated: true,
            contents: vec![S3Object {
                key: "k".to_string(),
                last_modified: "2013-05-24T00:00:00.000Z".to_string(),
                etag: "\"e\"".to_string(),
                size: 1,
                storage_class: "STANDARD".to_string(),
                owner: Some(Owner {
                    id: "acct".to_string(),
                    display_name: "acct".to_string(),
                }),
            }],
            common_prefixes: vec![],
        };
        let got = String::from_utf8(lbr.to_xml()).unwrap();
        assert!(got.contains("<NextMarker>n</NextMarker>"));
        assert!(got.contains("<Delimiter>/</Delimiter>"));
        assert!(got.contains("<EncodingType>url</EncodingType>"));
        assert!(got.contains("<IsTruncated>true</IsTruncated>"));
        assert!(got.contains("<Owner><ID>acct</ID><DisplayName>acct</DisplayName></Owner>"));
    }

    #[test]
    fn test_list_all_my_buckets() {
        let owner = Owner {
            id: "acct".to_string(),
            display_name: "acct".to_string(),
        };
        let buckets = vec![
            BucketInfo {
                name: "one".to_string(),
                creation_date: "2013-05-24T00:00:00.000Z".to_string(),
            },
            BucketInfo {
                name: "two".to_string(),
                creation_date: "2013-05-25T00:00:00.000Z".to_string(),
            },
        ];
        let got = String::from_utf8(list_all_my_buckets_xml(&owner, &buckets)).unwrap();
        assert_eq!(
            got,
            "<?xml version='1.0' encoding='UTF-8'?>\n\
             <ListAllMyBucketsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
             <Owner><ID>acct</ID><DisplayName>acct</DisplayName></Owner>\
             <Buckets>\
             <Bucket><Name>one</Name><CreationDate>2013-05-24T00:00:00.000Z</CreationDate></Bucket>\
             <Bucket><Name>two</Name><CreationDate>2013-05-25T00:00:00.000Z</CreationDate></Bucket>\
             </Buckets></ListAllMyBucketsResult>"
        );
    }

    #[test]
    fn test_delete_result() {
        let got = String::from_utf8(delete_result_xml(
            &[
                DeletedObject {
                    key: "a".to_string(),
                    version_id: None,
                    delete_marker: false,
                    delete_marker_version_id: None,
                },
                DeletedObject {
                    key: "b".to_string(),
                    version_id: Some("v1".to_string()),
                    delete_marker: false,
                    delete_marker_version_id: None,
                },
            ],
            &[DeleteError {
                key: "c".to_string(),
                version_id: None,
                code: "AccessDenied".to_string(),
                message: "Access Denied.".to_string(),
            }],
        ))
        .unwrap();
        assert_eq!(
            got,
            "<?xml version='1.0' encoding='UTF-8'?>\n\
             <DeleteResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
             <Deleted><Key>a</Key></Deleted><Deleted><Key>b</Key><VersionId>v1</VersionId></Deleted>\
             <Error><Key>c</Key><Code>AccessDenied</Code><Message>Access Denied.</Message></Error>\
             </DeleteResult>"
        );
    }

    #[test]
    fn test_object_responses() {
        let put = put_object_response("abc123");
        assert_eq!(put.status, 200);
        assert_eq!(put.headers.get("ETag"), Some("\"abc123\""));
        assert!(put.body.is_definitely_empty());

        let del = delete_object_response();
        assert_eq!(del.status, 204);

        let head = object_metadata_response(
            123,
            "abc123",
            "Fri, 24 May 2013 00:00:00 GMT",
            "text/plain",
            Vec::new(),
        );
        assert_eq!(head.status, 200);
        assert_eq!(head.headers.get("Content-Length"), Some("123"));
        assert_eq!(head.headers.get("ETag"), Some("\"abc123\""));
        assert_eq!(head.headers.get("Content-Type"), Some("text/plain"));
    }

    #[test]
    fn test_copy_object_result() {
        let got =
            String::from_utf8(copy_object_result_xml("2013-05-24T00:00:00.000Z", "abc")).unwrap();
        assert_eq!(
            got,
            "<?xml version='1.0' encoding='UTF-8'?>\n\
             <CopyObjectResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
             <LastModified>2013-05-24T00:00:00.000Z</LastModified><ETag>\"abc\"</ETag>\
             </CopyObjectResult>"
        );
    }

    #[test]
    fn s3_xml_timestamp_http_date_and_swift_iso_parse_as_iso() {
        assert_eq!(
            s3_xml_timestamp("Fri, 24 May 2013 00:00:00 GMT"),
            "2013-05-24T00:00:00.000Z"
        );
        assert_eq!(
            s3_xml_timestamp("2013-05-24T00:00:00.000000"),
            "2013-05-24T00:00:00.000Z"
        );
        assert_eq!(
            s3_xml_timestamp("2013-05-24T00:00:00+00:00"),
            "2013-05-24T00:00:00.000Z"
        );
        assert_eq!(s3_xml_timestamp("not-a-date"), "1970-01-01T00:00:00.000Z");
        let http_copy =
            String::from_utf8(copy_object_result_xml("Fri, 24 May 2013 00:00:00 GMT", "ff"))
                .unwrap();
        assert!(http_copy.contains("<LastModified>2013-05-24T00:00:00.000Z</LastModified>"));
        assert!(!http_copy.contains("Fri, 24 May"));
    }
}
