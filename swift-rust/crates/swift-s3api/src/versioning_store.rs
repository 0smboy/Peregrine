// Copyright (c) 2026 OpenStack Foundation
//! S3 multi-version object data-plane helpers.
//!
//! Storage model (bucket versioning = Enabled):
//! * current object at normal path with SYS_VERSION_ID / SYS_DELETE_MARKER
//! * archive container `{bucket}+versions`
//! * archive name `{hex(key)}/{version_id}` (hex is reversible UTF-8 encoding)
//! * index at `{hex(key)}/index.json` for ListVersions

use crate::xml::Element;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub const SYS_VERSION_ID: &str = "X-Object-Sysmeta-S3-Version-Id";
pub const SYS_DELETE_MARKER: &str = "X-Object-Sysmeta-S3-Delete-Marker";
pub const SYS_OBJECT_KEY: &str = "X-Object-Sysmeta-S3-Object-Key";
pub const HDR_VERSION_ID: &str = "x-amz-version-id";
pub const HDR_DELETE_MARKER: &str = "x-amz-delete-marker";
pub const INDEX_NAME: &str = "index.json";

pub fn versions_container(bucket: &str) -> String {
    format!("{bucket}+versions")
}

pub fn key_hex(key: &str) -> String {
    let mut out = String::with_capacity(key.len() * 2);
    for b in key.as_bytes() {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

pub fn key_from_hex(enc: &str) -> Option<String> {
    if enc.is_empty() || !enc.len().is_multiple_of(2) {
        return None;
    }
    let mut bytes = Vec::with_capacity(enc.len() / 2);
    let b = enc.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let h = std::str::from_utf8(&b[i..i + 2]).ok()?;
        bytes.push(u8::from_str_radix(h, 16).ok()?);
        i += 2;
    }
    String::from_utf8(bytes).ok()
}

pub fn archive_object_name(key: &str, version_id: &str) -> String {
    format!("{}/{}", key_hex(key), version_id)
}

pub fn index_object_name(key: &str) -> String {
    format!("{}/{}", key_hex(key), INDEX_NAME)
}

pub fn parse_archive_object_name(name: &str) -> Option<(String, String)> {
    let (enc, vid) = name.rsplit_once('/')?;
    if enc.is_empty() || vid.is_empty() || vid == INDEX_NAME {
        return None;
    }
    if !vid.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let key = key_from_hex(enc)?;
    Some((key, vid.to_string()))
}

pub fn generate_version_id() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let c = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mixed = c
        .wrapping_mul(0x9e37_79b9_7f4a_7c15)
        .wrapping_add(nanos.rotate_left(7));
    format!("{nanos:016x}{mixed:016x}")
}

pub fn versioning_enabled(status: Option<&str>) -> bool {
    matches!(status.map(|s| s.trim()), Some("Enabled"))
}

pub fn is_delete_marker_header(val: Option<&str>) -> bool {
    matches!(
        val.map(|s| s.trim().to_ascii_lowercase()).as_deref(),
        Some("true") | Some("1") | Some("yes")
    )
}

pub fn bare_etag(etag: &str) -> String {
    etag.trim().trim_matches('"').to_string()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionRecord {
    pub version_id: String,
    pub is_delete_marker: bool,
    pub is_latest: bool,
    pub last_modified: String,
    pub etag: String,
    pub size: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VersionIndex {
    pub key: String,
    pub versions: Vec<VersionRecord>,
}

impl VersionIndex {
    pub fn new(key: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            versions: Vec::new(),
        }
    }

    pub fn to_json(&self) -> Vec<u8> {
        let versions: Vec<Value> = self
            .versions
            .iter()
            .map(|v| {
                json!({
                    "version_id": v.version_id,
                    "is_delete_marker": v.is_delete_marker,
                    "is_latest": v.is_latest,
                    "last_modified": v.last_modified,
                    "etag": v.etag,
                    "size": v.size,
                })
            })
            .collect();
        serde_json::to_vec(&json!({ "key": self.key, "versions": versions })).unwrap_or_default()
    }

    pub fn from_json(data: &[u8]) -> Option<Self> {
        let v: Value = serde_json::from_slice(data).ok()?;
        let key = v.get("key")?.as_str()?.to_string();
        let arr = v.get("versions")?.as_array()?;
        let mut versions = Vec::with_capacity(arr.len());
        for item in arr {
            versions.push(VersionRecord {
                version_id: item.get("version_id")?.as_str()?.to_string(),
                is_delete_marker: item
                    .get("is_delete_marker")
                    .and_then(|x| x.as_bool())
                    .unwrap_or(false),
                is_latest: item
                    .get("is_latest")
                    .and_then(|x| x.as_bool())
                    .unwrap_or(false),
                last_modified: item
                    .get("last_modified")
                    .and_then(|x| x.as_str())
                    .unwrap_or("1970-01-01T00:00:00.000Z")
                    .to_string(),
                etag: item
                    .get("etag")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string(),
                size: item.get("size").and_then(|x| x.as_i64()).unwrap_or(0),
            });
        }
        Some(Self { key, versions })
    }

    pub fn push_latest(&mut self, mut rec: VersionRecord) {
        for v in &mut self.versions {
            v.is_latest = false;
        }
        rec.is_latest = true;
        self.versions.insert(0, rec);
    }

    pub fn find(&self, version_id: &str) -> Option<&VersionRecord> {
        self.versions.iter().find(|v| v.version_id == version_id)
    }

    pub fn remove_version(&mut self, version_id: &str) -> Option<String> {
        let was_latest = self.find(version_id).map(|v| v.is_latest).unwrap_or(false);
        self.versions.retain(|v| v.version_id != version_id);
        if was_latest {
            if let Some(first) = self.versions.first_mut() {
                first.is_latest = true;
                return Some(first.version_id.clone());
            }
        }
        None
    }
}

/// Build `ListVersionsResult` XML with S3-faithful pagination.
///
/// Ordering: keys ascending; within a key, version order follows each
/// [`VersionIndex`] (latest-first via [`VersionIndex::push_latest`]).
///
/// Markers (`key-marker` / `version-id-marker`):
/// * skip all keys lexicographically before `key_marker`
/// * when `key == key_marker` and `version_id_marker` is non-empty, skip that
///   version and all earlier positions in the key's version list (start *after*
///   the marker pair — matches AWS continuation via Next* markers)
/// * when `key == key_marker` and `version_id_marker` is empty, include versions
///   of that key from the beginning
///
/// When `max-keys` cuts the flat listing, `IsTruncated=true` and both
/// `NextKeyMarker` / `NextVersionIdMarker` are set to the last returned entry.
pub fn list_versions_result_xml(
    bucket: &str,
    prefix: &str,
    key_marker: &str,
    version_id_marker: &str,
    max_keys: u32,
    indexes: &[VersionIndex],
) -> Vec<u8> {
    // Stable key order across multi-key indexes (listing order independent of
    // how the versions container returned index.json objects).
    let mut ordered: Vec<&VersionIndex> = indexes.iter().collect();
    ordered.sort_by(|a, b| a.key.cmp(&b.key));

    let mut entries: Vec<(String, VersionRecord)> = Vec::new();
    for idx in ordered {
        if !prefix.is_empty() && !idx.key.starts_with(prefix) {
            continue;
        }
        if !key_marker.is_empty() && idx.key.as_str() < key_marker {
            continue;
        }

        let start =
            if !key_marker.is_empty() && idx.key == key_marker && !version_id_marker.is_empty() {
                match idx
                    .versions
                    .iter()
                    .position(|x| x.version_id == version_id_marker)
                {
                    // Start strictly after the marked version (continuation).
                    Some(pos) => pos.saturating_add(1),
                    // Unknown version-id-marker on this key: soft residual — start
                    // at beginning of the key (AWS would 400 InvalidArgument).
                    None => 0,
                }
            } else {
                0
            };

        for v in idx.versions.iter().skip(start) {
            entries.push((idx.key.clone(), v.clone()));
        }
    }

    let take_n = max_keys as usize;
    let truncated = entries.len() > take_n;
    let slice: Vec<_> = entries.into_iter().take(take_n).collect();

    let mut root = Element::new("ListVersionsResult");
    root.push_leaf("Name", bucket);
    root.push_leaf("Prefix", prefix);
    root.push_leaf("KeyMarker", key_marker);
    root.push_leaf("VersionIdMarker", version_id_marker);
    // Schema order: Next* before MaxKeys / IsTruncated (list_versions_result.rnc).
    if truncated {
        if let Some((k, v)) = slice.last() {
            root.push_leaf("NextKeyMarker", k);
            root.push_leaf("NextVersionIdMarker", &v.version_id);
        }
    }
    root.push_leaf("MaxKeys", max_keys.to_string());
    root.push_leaf("IsTruncated", if truncated { "true" } else { "false" });
    for (key, v) in &slice {
        if v.is_delete_marker {
            let mut dm = Element::new("DeleteMarker");
            dm.push_leaf("Key", key);
            dm.push_leaf("VersionId", &v.version_id);
            dm.push_leaf("IsLatest", if v.is_latest { "true" } else { "false" });
            dm.push_leaf("LastModified", &v.last_modified);
            root.push(dm);
        } else {
            let mut ver = Element::new("Version");
            ver.push_leaf("Key", key);
            ver.push_leaf("VersionId", &v.version_id);
            ver.push_leaf("IsLatest", if v.is_latest { "true" } else { "false" });
            ver.push_leaf("LastModified", &v.last_modified);
            let etag = if v.etag.starts_with('"') {
                v.etag.clone()
            } else {
                format!("\"{}\"", v.etag)
            };
            ver.push_leaf("ETag", etag);
            ver.push_leaf("Size", v.size.to_string());
            ver.push_leaf("StorageClass", "STANDARD");
            root.push(ver);
        }
    }
    root.to_xml(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_hex_roundtrip() {
        for k in ["a", "dir/obj", "x y"] {
            let h = key_hex(k);
            assert!(!h.contains('/'));
            assert_eq!(key_from_hex(&h).as_deref(), Some(k));
        }
    }

    #[test]
    fn archive_name_parse() {
        let n = archive_object_name("foo/bar", "0123456789abcdef0123456789abcdef");
        let (k, v) = parse_archive_object_name(&n).unwrap();
        assert_eq!(k, "foo/bar");
        assert_eq!(v, "0123456789abcdef0123456789abcdef");
    }

    #[test]
    fn version_id_unique_32_hex() {
        let a = generate_version_id();
        let b = generate_version_id();
        assert_eq!(a.len(), 32);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }

    #[test]
    fn index_push_and_list_xml() {
        let mut idx = VersionIndex::new("k");
        idx.push_latest(VersionRecord {
            version_id: "v1".into(),
            is_delete_marker: false,
            is_latest: true,
            last_modified: "2020-01-01T00:00:00.000Z".into(),
            etag: "e1".into(),
            size: 3,
        });
        idx.push_latest(VersionRecord {
            version_id: "v2".into(),
            is_delete_marker: false,
            is_latest: true,
            last_modified: "2020-01-02T00:00:00.000Z".into(),
            etag: "e2".into(),
            size: 5,
        });
        let xml =
            String::from_utf8(list_versions_result_xml("b", "", "", "", 1000, &[idx])).unwrap();
        assert!(xml.contains("<Version>"));
        assert!(xml.contains("<VersionId>v1</VersionId>"));
        assert!(xml.contains("<VersionId>v2</VersionId>"));
        assert!(!xml.contains("NextKeyMarker"));
        assert!(xml.contains("<IsTruncated>false</IsTruncated>"));
    }

    fn rec(vid: &str, latest: bool) -> VersionRecord {
        VersionRecord {
            version_id: vid.into(),
            is_delete_marker: false,
            is_latest: latest,
            last_modified: "2020-01-01T00:00:00.000Z".into(),
            etag: format!("e-{vid}"),
            size: 1,
        }
    }

    fn tag_text(xml: &str, tag: &str) -> Option<String> {
        let open = format!("<{tag}>");
        let close = format!("</{tag}>");
        let s = xml.find(&open)?;
        let start = s + open.len();
        let end_rel = xml[start..].find(&close)?;
        Some(xml[start..start + end_rel].to_string())
    }

    fn count_tag(xml: &str, tag: &str) -> usize {
        xml.matches(&format!("<{tag}>")).count()
    }

    /// Multi-key, multi-version: max-keys cuts mid-list; Next* + marker page-2.
    #[test]
    fn list_versions_multi_key_pagination() {
        // Intentionally reverse key order in the input slice — XML must still
        // emit keys ascending (a then b then c).
        let mut idx_c = VersionIndex::new("c");
        idx_c.versions = vec![rec("c1", true)];
        let mut idx_a = VersionIndex::new("a");
        // latest-first order (as push_latest would leave it)
        idx_a.versions = vec![rec("a2", true), rec("a1", false)];
        let mut idx_b = VersionIndex::new("b");
        idx_b.versions = vec![rec("b2", true), rec("b1", false)];
        let indexes = [idx_c, idx_a, idx_b];

        // Flat stream after sort: a2, a1, b2, b1, c1  (5 entries)
        let page1 =
            String::from_utf8(list_versions_result_xml("bucket", "", "", "", 2, &indexes)).unwrap();
        assert!(page1.contains("<IsTruncated>true</IsTruncated>"));
        assert_eq!(tag_text(&page1, "NextKeyMarker").as_deref(), Some("a"));
        assert_eq!(
            tag_text(&page1, "NextVersionIdMarker").as_deref(),
            Some("a1")
        );
        assert_eq!(count_tag(&page1, "Version"), 2);
        assert!(page1.contains("<VersionId>a2</VersionId>"));
        assert!(page1.contains("<VersionId>a1</VersionId>"));
        assert!(!page1.contains("<VersionId>b2</VersionId>"));
        // Echo request markers
        assert!(page1.contains("<KeyMarker></KeyMarker>") || page1.contains("<KeyMarker/>"));
        assert_eq!(tag_text(&page1, "MaxKeys").as_deref(), Some("2"));

        // Page 2: continue after (a, a1) → b2, b1  (max 2) still truncated
        let page2 = String::from_utf8(list_versions_result_xml(
            "bucket", "", "a", "a1", 2, &indexes,
        ))
        .unwrap();
        assert!(page2.contains("<IsTruncated>true</IsTruncated>"));
        assert_eq!(tag_text(&page2, "KeyMarker").as_deref(), Some("a"));
        assert_eq!(tag_text(&page2, "VersionIdMarker").as_deref(), Some("a1"));
        assert_eq!(tag_text(&page2, "NextKeyMarker").as_deref(), Some("b"));
        assert_eq!(
            tag_text(&page2, "NextVersionIdMarker").as_deref(),
            Some("b1")
        );
        assert_eq!(count_tag(&page2, "Version"), 2);
        assert!(page2.contains("<VersionId>b2</VersionId>"));
        assert!(page2.contains("<VersionId>b1</VersionId>"));
        assert!(!page2.contains("<VersionId>a2</VersionId>"));
        assert!(!page2.contains("<VersionId>c1</VersionId>"));

        // Page 3: after (b, b1) → c1 only, not truncated, no Next*
        let page3 = String::from_utf8(list_versions_result_xml(
            "bucket", "", "b", "b1", 2, &indexes,
        ))
        .unwrap();
        assert!(page3.contains("<IsTruncated>false</IsTruncated>"));
        assert!(!page3.contains("NextKeyMarker"));
        assert!(!page3.contains("NextVersionIdMarker"));
        assert_eq!(count_tag(&page3, "Version"), 1);
        assert!(page3.contains("<VersionId>c1</VersionId>"));

        // Cut mid-key: max-keys=1 on key a → only a2, Next=(a,a2)
        let mid =
            String::from_utf8(list_versions_result_xml("bucket", "", "", "", 1, &indexes)).unwrap();
        assert!(mid.contains("<IsTruncated>true</IsTruncated>"));
        assert_eq!(tag_text(&mid, "NextKeyMarker").as_deref(), Some("a"));
        assert_eq!(tag_text(&mid, "NextVersionIdMarker").as_deref(), Some("a2"));
        let mid2 = String::from_utf8(list_versions_result_xml(
            "bucket", "", "a", "a2", 1, &indexes,
        ))
        .unwrap();
        assert!(mid2.contains("<VersionId>a1</VersionId>"));
        assert!(!mid2.contains("<VersionId>a2</VersionId>"));
        assert_eq!(tag_text(&mid2, "NextKeyMarker").as_deref(), Some("a"));
        assert_eq!(
            tag_text(&mid2, "NextVersionIdMarker").as_deref(),
            Some("a1")
        );
    }

    #[test]
    fn list_versions_prefix_filter() {
        let mut logs = VersionIndex::new("logs/2020");
        logs.versions = vec![rec("l1", true)];
        let mut other = VersionIndex::new("other/x");
        other.versions = vec![rec("o1", true)];
        let mut logs2 = VersionIndex::new("logs/2021");
        logs2.versions = vec![rec("l2", true)];
        let indexes = [logs, other, logs2];

        let xml = String::from_utf8(list_versions_result_xml(
            "b", "logs/", "", "", 1000, &indexes,
        ))
        .unwrap();
        assert!(xml.contains("<Prefix>logs/</Prefix>"));
        assert!(xml.contains("<VersionId>l1</VersionId>"));
        assert!(xml.contains("<VersionId>l2</VersionId>"));
        assert!(!xml.contains("<VersionId>o1</VersionId>"));
        assert!(!xml.contains("other/x"));
        assert!(xml.contains("<IsTruncated>false</IsTruncated>"));
        assert_eq!(count_tag(&xml, "Version"), 2);

        // Prefix + max-keys truncation still emits Next* among filtered set
        let page =
            String::from_utf8(list_versions_result_xml("b", "logs/", "", "", 1, &indexes)).unwrap();
        assert!(page.contains("<IsTruncated>true</IsTruncated>"));
        assert_eq!(
            tag_text(&page, "NextKeyMarker").as_deref(),
            Some("logs/2020")
        );
        assert_eq!(
            tag_text(&page, "NextVersionIdMarker").as_deref(),
            Some("l1")
        );
        assert!(!page.contains("<VersionId>l2</VersionId>"));
    }

    #[test]
    fn list_versions_empty_indexes_and_empty_versions() {
        // Empty container / no indexes → empty ListVersionsResult
        let empty =
            String::from_utf8(list_versions_result_xml("b", "", "", "", 1000, &[])).unwrap();
        assert!(empty.contains("ListVersionsResult"));
        assert!(empty.contains("<Name>b</Name>"));
        assert!(empty.contains("<IsTruncated>false</IsTruncated>"));
        assert!(!empty.contains("<Version>"));
        assert!(!empty.contains("<DeleteMarker>"));
        assert!(!empty.contains("NextKeyMarker"));

        // Index present but zero versions (and a sibling with versions filtered by prefix)
        let mut hollow = VersionIndex::new("k");
        hollow.versions = vec![];
        let hollow_xml =
            String::from_utf8(list_versions_result_xml("b", "", "", "", 10, &[hollow])).unwrap();
        assert!(hollow_xml.contains("<IsTruncated>false</IsTruncated>"));
        assert!(!hollow_xml.contains("<Version>"));
        assert_eq!(count_tag(&hollow_xml, "Version"), 0);

        // DeleteMarker still counts toward max-keys / Next*
        let mut dm_idx = VersionIndex::new("d");
        dm_idx.versions = vec![VersionRecord {
            version_id: "dm1".into(),
            is_delete_marker: true,
            is_latest: true,
            last_modified: "2020-01-01T00:00:00.000Z".into(),
            etag: String::new(),
            size: 0,
        }];
        let mut ver_idx = VersionIndex::new("e");
        ver_idx.versions = vec![rec("e1", true)];
        let mixed = String::from_utf8(list_versions_result_xml(
            "b",
            "",
            "",
            "",
            1,
            &[dm_idx, ver_idx],
        ))
        .unwrap();
        assert!(mixed.contains("<IsTruncated>true</IsTruncated>"));
        assert!(mixed.contains("<DeleteMarker>"));
        assert!(!mixed.contains("<Version>"));
        assert_eq!(tag_text(&mixed, "NextKeyMarker").as_deref(), Some("d"));
        assert_eq!(
            tag_text(&mixed, "NextVersionIdMarker").as_deref(),
            Some("dm1")
        );
    }

    #[test]
    fn versioning_enabled_only_enabled() {
        assert!(versioning_enabled(Some("Enabled")));
        assert!(!versioning_enabled(Some("Suspended")));
        assert!(!versioning_enabled(None));
    }
}
