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

//! Multipart upload helpers (Swift `+segments` container + SLO complete).
//!
//! Convention (Python s3api parity):
//! * Init → create `{bucket}+segments` if needed; store marker object
//!   `{key}/{uploadId}` under that container.
//! * UploadPart → PUT `{bucket}+segments/{key}/{uploadId}/{partNumber:08}`
//! * Complete → build SLO manifest from listed parts; PUT to `{bucket}/{key}`
//!   with `?multipart-manifest=put`.
//! * Abort → DELETE marker + parts under the segments path prefix.

use crate::parse::MULTIUPLOAD_SUFFIX;
use crate::xml::Element;
use swift_http::Response;

/// Build an InitiateMultipartUploadResult XML body.
pub fn initiate_multipart_xml(bucket: &str, key: &str, upload_id: &str) -> Vec<u8> {
    Element::new("InitiateMultipartUploadResult")
        .with_leaf("Bucket", bucket)
        .with_leaf("Key", key)
        .with_leaf("UploadId", upload_id)
        .to_xml(true)
}

/// Build a CompleteMultipartUploadResult XML body.
pub fn complete_multipart_xml(bucket: &str, key: &str, etag: &str, location: &str) -> Vec<u8> {
    Element::new("CompleteMultipartUploadResult")
        .with_leaf("Location", location)
        .with_leaf("Bucket", bucket)
        .with_leaf("Key", key)
        .with_leaf("ETag", format!("\"{etag}\""))
        .to_xml(true)
}

/// One part in a ListParts result.
#[derive(Debug, Clone)]
pub struct ListedPart {
    pub part_number: u32,
    pub last_modified: String,
    pub etag: String,
    pub size: u64,
}

/// Build ListPartsResult XML (no pagination metadata).
pub fn list_parts_xml(bucket: &str, key: &str, upload_id: &str, parts: &[ListedPart]) -> Vec<u8> {
    list_parts_xml_full(bucket, key, upload_id, 0, 1000, false, parts)
}

/// Build ListPartsResult XML with part-number-marker / max-parts / IsTruncated.
pub fn list_parts_xml_full(
    bucket: &str,
    key: &str,
    upload_id: &str,
    part_number_marker: u32,
    max_parts: u32,
    is_truncated: bool,
    parts: &[ListedPart],
) -> Vec<u8> {
    let mut root = Element::new("ListPartsResult");
    root.push_leaf("Bucket", bucket);
    root.push_leaf("Key", key);
    root.push_leaf("UploadId", upload_id);
    root.push_leaf("PartNumberMarker", part_number_marker.to_string());
    if let Some(last) = parts.last() {
        root.push_leaf("NextPartNumberMarker", last.part_number.to_string());
    } else {
        root.push_leaf("NextPartNumberMarker", part_number_marker.to_string());
    }
    root.push_leaf("MaxParts", max_parts.to_string());
    root.push_leaf("IsTruncated", if is_truncated { "true" } else { "false" });
    root.push_leaf("StorageClass", "STANDARD");
    for p in parts {
        root.push(
            Element::new("Part")
                .with_leaf("PartNumber", p.part_number.to_string())
                .with_leaf("LastModified", &p.last_modified)
                .with_leaf("ETag", format!("\"{}\"", p.etag.trim_matches('"')))
                .with_leaf("Size", p.size.to_string()),
        );
    }
    root.to_xml(true)
}

/// One in-progress upload in a ListMultipartUploads result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedUpload {
    pub key: String,
    pub upload_id: String,
    pub initiated: String,
}

/// Parse a segments-container object name into an upload marker
/// (`{key}/{uploadId}`). Part objects (`…/{uploadId}/{part:08}`) return
/// `None`.
pub fn parse_upload_marker_name(name: &str) -> Option<(String, String)> {
    let (key, upload_id) = name.rsplit_once('/')?;
    if key.is_empty() || upload_id.is_empty() {
        return None;
    }
    // Parts end with an 8-digit part number; markers end with the upload id.
    if upload_id.len() == 8 && upload_id.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    // Upload ids from [`new_upload_id`] are 32 hex chars; accept any non-empty
    // non-part suffix so lab/custom ids still list.
    if !upload_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some((key.to_string(), upload_id.to_string()))
}

/// Build ListMultipartUploadsResult XML.
pub fn list_multipart_uploads_xml(
    bucket: &str,
    prefix: &str,
    key_marker: &str,
    upload_id_marker: &str,
    max_uploads: u32,
    is_truncated: bool,
    uploads: &[ListedUpload],
) -> Vec<u8> {
    let mut root = Element::new("ListMultipartUploadsResult");
    root.push_leaf("Bucket", bucket);
    root.push_leaf("Prefix", prefix);
    root.push_leaf("KeyMarker", key_marker);
    root.push_leaf("UploadIdMarker", upload_id_marker);
    if let Some(last) = uploads.last() {
        root.push_leaf("NextKeyMarker", &last.key);
        root.push_leaf("NextUploadIdMarker", &last.upload_id);
    } else {
        root.push_leaf("NextKeyMarker", "");
        root.push_leaf("NextUploadIdMarker", "");
    }
    root.push_leaf("MaxUploads", max_uploads.to_string());
    root.push_leaf("IsTruncated", if is_truncated { "true" } else { "false" });
    for u in uploads {
        root.push(
            Element::new("Upload")
                .with_leaf("Key", &u.key)
                .with_leaf("UploadId", &u.upload_id)
                .with_leaf("Initiated", &u.initiated)
                .with_leaf("StorageClass", "STANDARD"),
        );
    }
    root.to_xml(true)
}

/// Segments container name for a bucket.
pub fn segments_container(bucket: &str) -> String {
    format!("{bucket}{MULTIUPLOAD_SUFFIX}")
}

/// Object name for an uploaded part inside the segments container.
pub fn part_object_name(key: &str, upload_id: &str, part_number: u32) -> String {
    format!("{key}/{upload_id}/{part_number:08}")
}

/// Marker object that records an in-progress upload.
pub fn upload_marker_name(key: &str, upload_id: &str) -> String {
    format!("{key}/{upload_id}")
}

/// Generate a hex upload id (timestamp-based, unique enough for unit tests
/// and lab use; production can swap in a stronger RNG later).
pub fn new_upload_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{nanos:032x}")
}

/// Parse `<CompleteMultipartUpload><Part>…` into ordered part numbers + etags.
pub fn parse_complete_body(body: &[u8]) -> Result<Vec<(u32, String)>, String> {
    let text = std::str::from_utf8(body).map_err(|_| "MalformedXML".to_string())?;
    if !text.contains("CompleteMultipartUpload") {
        return Err("MalformedXML".into());
    }
    let mut parts = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("<Part>") {
        let after = &rest[start..];
        let Some(end_rel) = after.find("</Part>") else {
            break;
        };
        let part_xml = &after[..end_rel];
        let num = extract_tag(part_xml, "PartNumber")
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| "InvalidPartNumber".to_string())?;
        let etag = extract_tag(part_xml, "ETag")
            .unwrap_or_default()
            .trim()
            .trim_matches('"')
            .to_string();
        parts.push((num, etag));
        rest = &after[end_rel + "</Part>".len()..];
    }
    parts.sort_by_key(|(n, _)| *n);
    Ok(parts)
}

fn extract_tag(body: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = body.find(&open)? + open.len();
    let end = body[start..].find(&close)? + start;
    Some(body[start..end].to_string())
}

/// Build an SLO client-manifest JSON list from completed parts.
/// Each entry is `{ "path": "/segments/…", "etag": "…", "size_bytes": … }`.
pub fn slo_manifest_json(
    segments_container: &str,
    key: &str,
    upload_id: &str,
    parts: &[(u32, String, u64)],
) -> String {
    let mut items = Vec::new();
    for (num, etag, size) in parts {
        let path = format!(
            "/{segments_container}/{}",
            part_object_name(key, upload_id, *num)
        );
        items.push(format!(
            "{{\"path\":\"{path}\",\"etag\":\"{etag}\",\"size_bytes\":{size}}}"
        ));
    }
    format!("[{}]", items.join(","))
}

/// 200 OK wrapping initiate XML.
pub fn initiate_response(bucket: &str, key: &str, upload_id: &str) -> Response {
    let mut resp = Response::with_body(200, initiate_multipart_xml(bucket, key, upload_id));
    resp.headers.set("Content-Type", "application/xml");
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segments_and_part_names() {
        assert_eq!(segments_container("b"), "b+segments");
        assert_eq!(part_object_name("k", "uid", 3), "k/uid/00000003");
    }

    #[test]
    fn parse_complete() {
        let body = br#"
<CompleteMultipartUpload>
  <Part><PartNumber>2</PartNumber><ETag>"bb"</ETag></Part>
  <Part><PartNumber>1</PartNumber><ETag>"aa"</ETag></Part>
</CompleteMultipartUpload>"#;
        let parts = parse_complete_body(body).unwrap();
        assert_eq!(parts, vec![(1, "aa".into()), (2, "bb".into())]);
    }

    #[test]
    fn slo_json_shape() {
        let j = slo_manifest_json("b+segments", "k", "u", &[(1, "aa".into(), 10)]);
        assert!(j.contains("\"path\":\"/b+segments/k/u/00000001\""));
        assert!(j.contains("\"etag\":\"aa\""));
    }

    #[test]
    fn parse_marker_vs_part() {
        let (k, u) = parse_upload_marker_name("big/obj/abcdef0123456789abcdef0123456789").unwrap();
        assert_eq!(k, "big/obj");
        assert_eq!(u, "abcdef0123456789abcdef0123456789");
        assert!(
            parse_upload_marker_name("big/obj/abcdef0123456789abcdef0123456789/00000001").is_none()
        );
    }

    #[test]
    fn list_mpu_xml_shape() {
        let xml = String::from_utf8(list_multipart_uploads_xml(
            "b",
            "",
            "",
            "",
            1000,
            false,
            &[ListedUpload {
                key: "k".into(),
                upload_id: "uid".into(),
                initiated: "2026-08-05T00:00:00.000Z".into(),
            }],
        ))
        .unwrap();
        assert!(xml.contains("ListMultipartUploadsResult"));
        assert!(xml.contains("<Key>k</Key>"));
        assert!(xml.contains("<UploadId>uid</UploadId>"));
        assert!(xml.contains("<IsTruncated>false</IsTruncated>"));
    }
}
