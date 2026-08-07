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

//! S3 bucket/object config subresources stored as Swift container/object meta.
//!
//! # Claimable (this module + middleware handlers)
//! * **versioning** GET/PUT — status `Enabled`|`Suspended` in
//!   [`S3_VERSIONING_META`]; GET returns AWS `VersioningConfiguration` XML.
//! * **tagging** GET/PUT/DELETE on bucket and object — TagSet in
//!   [`S3_BUCKET_TAGGING_META`] / [`S3_OBJECT_TAGGING_META`]; Tagging XML.
//! * **lifecycle** GET/PUT/DELETE — raw `LifecycleConfiguration` XML in
//!   [`S3_LIFECYCLE_META`] (percent-encoded for header safety); round-trip.
//! * **object-lock** GET/PUT — raw `ObjectLockConfiguration` XML in
//!   [`S3_OBJECT_LOCK_META`].
//! * **versions** list — empty `ListVersionsResult` (no multi-version bodies).
//!
//! # Residuals
//! * Multi-version object storage / versionId GET-DELETE / delete-markers are
//!   **not** implemented — only the versioning *status* API surface.
//! * Lifecycle rules are stored and returned; no expirer enforcement from this
//!   meta alone.
//! * Object Lock retention/legal-hold object APIs and WORM enforcement residual.

use crate::xml::Element;
use swift_http::HeaderKeyDict;

/// Bucket versioning status (`Enabled` / `Suspended`).
pub const S3_VERSIONING_META: &str = "X-Container-Meta-S3-Versioning";

/// Compact bucket TagSet encoding (sysmeta — off public container meta listing).
pub const S3_BUCKET_TAGGING_META: &str = "X-Container-Sysmeta-S3-Tagging";

/// Compact object TagSet encoding (sysmeta — off public `x-amz-meta-*`).
pub const S3_OBJECT_TAGGING_META: &str = "X-Object-Sysmeta-S3-Tagging";

/// Percent-encoded raw LifecycleConfiguration XML.
pub const S3_LIFECYCLE_META: &str = "X-Container-Meta-S3-Lifecycle";

/// Percent-encoded raw ObjectLockConfiguration XML.
pub const S3_OBJECT_LOCK_META: &str = "X-Container-Meta-S3-Object-Lock";

const TAG_SEP: &str = "||";
const KV_SEP: char = '\u{1f}';

// ---------------------------------------------------------------------------
// Percent-encode / decode for raw XML in HTTP meta headers
// ---------------------------------------------------------------------------

/// Encode arbitrary bytes for a single HTTP meta header value (no CR/LF).
pub fn encode_meta_blob(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().saturating_mul(2));
    for &b in data {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Decode a value produced by [`encode_meta_blob`].
pub fn decode_meta_blob(s: &str) -> Result<Vec<u8>, String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err("bad percent encoding".into());
            }
            let h = std::str::from_utf8(&bytes[i + 1..i + 3])
                .map_err(|_| "bad percent encoding".to_string())?;
            let v = u8::from_str_radix(h, 16).map_err(|_| "bad percent encoding".to_string())?;
            out.push(v);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Versioning
// ---------------------------------------------------------------------------

/// Build `VersioningConfiguration` XML. `status` is `Some("Enabled"|"Suspended")`
/// or `None` when never configured (empty element, matching Python GET).
pub fn versioning_configuration_xml(status: Option<&str>) -> Vec<u8> {
    let mut root = Element::new("VersioningConfiguration");
    if let Some(s) = status {
        if !s.is_empty() {
            root.push_leaf("Status", s);
        }
    }
    root.to_xml(true)
}

/// Parse PUT VersioningConfiguration body → `Enabled` or `Suspended`.
pub fn parse_versioning_status(body: &[u8]) -> Result<&'static str, String> {
    let text = std::str::from_utf8(body).map_err(|_| "MalformedXML".to_string())?;
    if !text.contains("VersioningConfiguration") {
        return Err("MalformedXML".into());
    }
    // Prefer <Status>…</Status>
    if let Some(s) = extract_first_tag(text, "Status") {
        return match s.as_str() {
            "Enabled" => Ok("Enabled"),
            "Suspended" => Ok("Suspended"),
            _ => Err("MalformedXML".into()),
        };
    }
    Err("MalformedXML".into())
}

/// Stamp versioning status onto container meta headers.
pub fn apply_versioning_meta(headers: &mut HeaderKeyDict, status: &str) {
    headers.set(S3_VERSIONING_META, status);
}

/// Read stored versioning status (`Enabled` / `Suspended` / None).
pub fn versioning_status_from_headers(headers: &HeaderKeyDict) -> Option<String> {
    headers
        .get(S3_VERSIONING_META)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

// ---------------------------------------------------------------------------
// Tagging
// ---------------------------------------------------------------------------

/// One S3 tag.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct S3Tag {
    pub key: String,
    pub value: String,
}

/// Build Tagging XML from a tag set.
pub fn tagging_xml(tags: &[S3Tag]) -> Vec<u8> {
    let mut root = Element::new("Tagging");
    let mut set = Element::new("TagSet");
    for t in tags {
        set.push(
            Element::new("Tag")
                .with_leaf("Key", t.key.as_str())
                .with_leaf("Value", t.value.as_str()),
        );
    }
    root.push(set);
    root.to_xml(true)
}

/// Empty Tagging document (empty TagSet).
pub fn empty_tagging_xml() -> Vec<u8> {
    tagging_xml(&[])
}

/// Parse a Tagging body into tags.
pub fn parse_tagging_body(body: &[u8]) -> Result<Vec<S3Tag>, String> {
    let text = std::str::from_utf8(body).map_err(|_| "MalformedXML".to_string())?;
    if !text.contains("Tagging") {
        return Err("MalformedXML".into());
    }
    let mut tags = Vec::new();
    let mut rest = text;
    let open = "<Tag>";
    let close = "</Tag>";
    while let Some(s) = rest.find(open) {
        let start = s + open.len();
        let Some(end_rel) = rest[start..].find(close) else {
            break;
        };
        let block = &rest[start..start + end_rel];
        let key = extract_first_tag(block, "Key").unwrap_or_default();
        let value = extract_first_tag(block, "Value").unwrap_or_default();
        if !key.is_empty() {
            tags.push(S3Tag { key, value });
        }
        rest = &rest[start + end_rel + close.len()..];
    }
    Ok(tags)
}

/// Compact encode TagSet for meta storage.
pub fn encode_tagset_meta(tags: &[S3Tag]) -> String {
    tags.iter()
        .map(|t| format!("{}{KV_SEP}{}", t.key, t.value))
        .collect::<Vec<_>>()
        .join(TAG_SEP)
}

/// Decode compact TagSet meta.
pub fn decode_tagset_meta(s: &str) -> Vec<S3Tag> {
    if s.is_empty() {
        return Vec::new();
    }
    s.split(TAG_SEP)
        .filter(|part| !part.is_empty())
        .map(|part| {
            if let Some((k, v)) = part.split_once(KV_SEP) {
                S3Tag {
                    key: k.to_string(),
                    value: v.to_string(),
                }
            } else {
                S3Tag {
                    key: part.to_string(),
                    value: String::new(),
                }
            }
        })
        .collect()
}

/// Stamp bucket tagging meta.
pub fn apply_bucket_tagging_meta(headers: &mut HeaderKeyDict, tags: &[S3Tag]) {
    headers.set(S3_BUCKET_TAGGING_META, encode_tagset_meta(tags));
}

/// Clear bucket tagging meta.
pub fn clear_bucket_tagging_meta(headers: &mut HeaderKeyDict) {
    headers.set(S3_BUCKET_TAGGING_META, "");
}

/// Stamp object tagging sysmeta.
pub fn apply_object_tagging_meta(headers: &mut HeaderKeyDict, tags: &[S3Tag]) {
    headers.set(S3_OBJECT_TAGGING_META, encode_tagset_meta(tags));
}

/// Clear object tagging sysmeta.
pub fn clear_object_tagging_meta(headers: &mut HeaderKeyDict) {
    headers.set(S3_OBJECT_TAGGING_META, "");
}

/// Rebuild Tagging XML from a meta value (empty TagSet when missing/blank).
pub fn tagging_xml_from_meta(meta: Option<&str>) -> Vec<u8> {
    match meta {
        Some(s) if !s.is_empty() => tagging_xml(&decode_tagset_meta(s)),
        _ => empty_tagging_xml(),
    }
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

/// Validate a LifecycleConfiguration body (root present; non-empty rules optional for MVP).
pub fn validate_lifecycle_xml(body: &[u8]) -> Result<(), String> {
    let text = std::str::from_utf8(body).map_err(|_| "MalformedXML".to_string())?;
    if !text.contains("LifecycleConfiguration") {
        return Err("MalformedXML".into());
    }
    Ok(())
}

/// Store raw lifecycle XML (percent-encoded) on container meta.
pub fn apply_lifecycle_meta(headers: &mut HeaderKeyDict, body: &[u8]) {
    headers.set(S3_LIFECYCLE_META, encode_meta_blob(body));
}

/// Clear lifecycle meta.
pub fn clear_lifecycle_meta(headers: &mut HeaderKeyDict) {
    headers.set(S3_LIFECYCLE_META, "");
}

/// Recover stored lifecycle XML bytes from headers.
pub fn lifecycle_xml_from_headers(headers: &HeaderKeyDict) -> Option<Vec<u8>> {
    let raw = headers.get(S3_LIFECYCLE_META).filter(|s| !s.is_empty())?;
    decode_meta_blob(raw).ok()
}

// ---------------------------------------------------------------------------
// Object Lock
// ---------------------------------------------------------------------------

/// Validate ObjectLockConfiguration body.
pub fn validate_object_lock_xml(body: &[u8]) -> Result<(), String> {
    let text = std::str::from_utf8(body).map_err(|_| "MalformedXML".to_string())?;
    if !text.contains("ObjectLockConfiguration") {
        return Err("MalformedXML".into());
    }
    Ok(())
}

/// Store raw object-lock XML on container meta.
pub fn apply_object_lock_meta(headers: &mut HeaderKeyDict, body: &[u8]) {
    headers.set(S3_OBJECT_LOCK_META, encode_meta_blob(body));
}

/// Recover stored object-lock XML bytes.
pub fn object_lock_xml_from_headers(headers: &HeaderKeyDict) -> Option<Vec<u8>> {
    let raw = headers.get(S3_OBJECT_LOCK_META).filter(|s| !s.is_empty())?;
    decode_meta_blob(raw).ok()
}

// ---------------------------------------------------------------------------
// ListVersions (empty residual)
// ---------------------------------------------------------------------------

/// Empty `ListVersionsResult` — multi-version object listing residual.
pub fn empty_list_versions_result_xml(
    bucket: &str,
    prefix: &str,
    key_marker: &str,
    version_id_marker: &str,
    max_keys: u32,
) -> Vec<u8> {
    Element::new("ListVersionsResult")
        .with_leaf("Name", bucket)
        .with_leaf("Prefix", prefix)
        .with_leaf("KeyMarker", key_marker)
        .with_leaf("VersionIdMarker", version_id_marker)
        .with_leaf("MaxKeys", max_keys.to_string())
        .with_leaf("IsTruncated", "false")
        .to_xml(true)
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn extract_first_tag(text: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let s = text.find(&open)?;
    let start = s + open.len();
    let end_rel = text[start..].find(&close)?;
    Some(text[start..start + end_rel].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versioning_xml_enabled_suspended_empty() {
        let en = String::from_utf8(versioning_configuration_xml(Some("Enabled"))).unwrap();
        assert!(en.contains("VersioningConfiguration"));
        assert!(en.contains("<Status>Enabled</Status>"));
        let su = String::from_utf8(versioning_configuration_xml(Some("Suspended"))).unwrap();
        assert!(su.contains("<Status>Suspended</Status>"));
        let empty = String::from_utf8(versioning_configuration_xml(None)).unwrap();
        assert!(empty.contains("VersioningConfiguration"));
        assert!(!empty.contains("<Status>"));
    }

    #[test]
    fn parse_versioning_roundtrip() {
        let body = br#"<?xml version="1.0"?>
        <VersioningConfiguration>
          <Status>Enabled</Status>
        </VersioningConfiguration>"#;
        assert_eq!(parse_versioning_status(body).unwrap(), "Enabled");
        let body2 = br#"<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
          <Status>Suspended</Status>
        </VersioningConfiguration>"#;
        assert_eq!(parse_versioning_status(body2).unwrap(), "Suspended");
        assert!(parse_versioning_status(br"<VersioningConfiguration/>").is_err());
        assert!(parse_versioning_status(br"<VersioningConfiguration><Status>Bogus</Status></VersioningConfiguration>").is_err());
    }

    #[test]
    fn versioning_meta_stamp() {
        let mut h = HeaderKeyDict::new();
        apply_versioning_meta(&mut h, "Enabled");
        assert_eq!(h.get(S3_VERSIONING_META), Some("Enabled"));
        assert_eq!(
            versioning_status_from_headers(&h).as_deref(),
            Some("Enabled")
        );
    }

    #[test]
    fn tagging_parse_encode_roundtrip() {
        let body = br#"
        <Tagging>
          <TagSet>
            <Tag><Key>env</Key><Value>prod</Value></Tag>
            <Tag><Key>team</Key><Value>storage</Value></Tag>
          </TagSet>
        </Tagging>"#;
        let tags = parse_tagging_body(body).unwrap();
        assert_eq!(tags.len(), 2);
        assert_eq!(tags[0].key, "env");
        assert_eq!(tags[0].value, "prod");
        let enc = encode_tagset_meta(&tags);
        let dec = decode_tagset_meta(&enc);
        assert_eq!(dec, tags);
        let xml = String::from_utf8(tagging_xml(&dec)).unwrap();
        assert!(xml.contains("<Key>env</Key>"));
        assert!(xml.contains("<Value>storage</Value>"));
    }

    #[test]
    fn tagging_empty_xml() {
        let xml = String::from_utf8(empty_tagging_xml()).unwrap();
        assert!(xml.contains("Tagging"));
        assert!(xml.contains("TagSet"));
        assert!(!xml.contains("<Tag>"));
    }

    #[test]
    fn lifecycle_meta_blob_roundtrip() {
        let body = br#"<?xml version="1.0"?>
<LifecycleConfiguration>
  <Rule>
    <ID>expire-logs</ID>
    <Prefix>logs/</Prefix>
    <Status>Enabled</Status>
    <Expiration><Days>30</Days></Expiration>
  </Rule>
</LifecycleConfiguration>"#;
        validate_lifecycle_xml(body).unwrap();
        let mut h = HeaderKeyDict::new();
        apply_lifecycle_meta(&mut h, body);
        let got = lifecycle_xml_from_headers(&h).unwrap();
        assert_eq!(got, body);
        assert!(std::str::from_utf8(&got).unwrap().contains("expire-logs"));
        clear_lifecycle_meta(&mut h);
        assert!(lifecycle_xml_from_headers(&h).is_none());
    }

    #[test]
    fn object_lock_meta_blob_roundtrip() {
        let body = br#"<ObjectLockConfiguration>
  <ObjectLockEnabled>Enabled</ObjectLockEnabled>
  <Rule>
    <DefaultRetention>
      <Mode>GOVERNANCE</Mode>
      <Days>1</Days>
    </DefaultRetention>
  </Rule>
</ObjectLockConfiguration>"#;
        validate_object_lock_xml(body).unwrap();
        let mut h = HeaderKeyDict::new();
        apply_object_lock_meta(&mut h, body);
        let got = object_lock_xml_from_headers(&h).unwrap();
        assert_eq!(got, body);
        assert!(std::str::from_utf8(&got)
            .unwrap()
            .contains("ObjectLockEnabled"));
    }

    #[test]
    fn empty_list_versions_shape() {
        let xml = String::from_utf8(empty_list_versions_result_xml(
            "mybucket", "", "", "", 1000,
        ))
        .unwrap();
        assert!(xml.contains("ListVersionsResult"));
        assert!(xml.contains("<Name>mybucket</Name>"));
        assert!(xml.contains("<IsTruncated>false</IsTruncated>"));
        assert!(!xml.contains("<Version>"));
    }

    #[test]
    fn meta_blob_encode_decode_binary_safe() {
        let data = b"<\nA&\rB>";
        let enc = encode_meta_blob(data);
        assert!(!enc.contains('\n'));
        assert!(!enc.contains('\r'));
        assert_eq!(decode_meta_blob(&enc).unwrap(), data);
    }
}
