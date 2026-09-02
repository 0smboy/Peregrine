// Copyright (c) 2026 OpenStack Foundation
//! S3 multi-version object data-plane helpers.
//!
//! Storage model (bucket versioning = Enabled):
//! * current object at normal path with SYS_VERSION_ID / SYS_DELETE_MARKER
//! * archive container `{bucket}+versions`
//! * archive name `{hex(key)}/{version_id}` (hex is reversible UTF-8 encoding)
//! * index mirror at `{hex(key)}/index.json` for ListVersions and readers
//! * one immutable fence per committed generation at
//!   `{hex(key)}/index.g{N:020}.json` (see [`index_generation_object_name`])
//!
//! [`VersionIndex::apply_if_match`] / [`VersionIndex::cas_etag`] are
//! **in-process** CAS helpers only. Cross-proxy serialization is provided
//! by the backend fence protocol in `middleware::cas_save_version_index`:
//! each committed generation is created exactly once with
//! `If-None-Match: *` (enforced by every object-server generation since the
//! monorepo import), so two proxies can never both apply the same
//! generation. See docs/fairness-lab/VERSION-CAS-DESIGN-20260817.md.

use crate::crypto::sha256_hex;
use crate::response::s3_xml_timestamp;
use crate::xml::Element;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub const SYS_VERSION_ID: &str = "X-Object-Sysmeta-S3-Version-Id";
pub const SYS_DELETE_MARKER: &str = "X-Object-Sysmeta-S3-Delete-Marker";
pub const SYS_OBJECT_KEY: &str = "X-Object-Sysmeta-S3-Object-Key";
pub const HDR_VERSION_ID: &str = "x-amz-version-id";
pub const HDR_DELETE_MARKER: &str = "x-amz-delete-marker";
pub const INDEX_NAME: &str = "index.json";

/// Hard cap on `versions[]` accepted by [`VersionIndex::from_json`].
/// Larger indexes fail closed so a single `index.json` cannot boundlessly
/// allocate.
pub const MAX_INDEX_VERSIONS: usize = 10_000;

/// S3 null version-id written by a Suspended PUT.
pub const NULL_VERSION_ID: &str = "null";

/// Bucket versioning configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersioningStatus {
    Unversioned,
    Enabled,
    Suspended,
}

impl VersioningStatus {
    /// Suspended PUT writes the null version. Hidden versions stay hidden
    /// unless the caller supplies an explicit record.
    pub const fn suspended_put_overwrites_null(self) -> bool {
        matches!(self, Self::Suspended)
    }
}

/// Map container versioning sysmeta to [`VersioningStatus`].
///
/// Only the exact tokens `Enabled` / `Suspended` are recognized (same as
/// [`versioning_enabled`]). Anything else is Unversioned.
pub fn versioning_status(status: Option<&str>) -> VersioningStatus {
    match status.map(str::trim) {
        Some("Enabled") => VersioningStatus::Enabled,
        Some("Suspended") => VersioningStatus::Suspended,
        _ => VersioningStatus::Unversioned,
    }
}

/// Archive / index path segment check for a version-id.
///
/// `false` for empty, `.`, `..`, any `/`, any NUL, and the whole reserved
/// `index.*` namespace: `index.json` (the mirror) and `index.g<N>.json`
/// (per-generation CAS fence objects) must never be addressable as archive
/// objects.
pub fn is_safe_version_id(s: &str) -> bool {
    if s.is_empty() || s == "." || s == ".." {
        return false;
    }
    if s == INDEX_NAME || s.starts_with("index.") {
        return false;
    }
    if s.contains('/') || s.contains('\0') {
        return false;
    }
    true
}

/// In-process compare-and-swap denial (the fast path). The backend fence in
/// `middleware::cas_save_version_index` serializes across proxies; conflicts
/// there surface the same client-visible class as this denial.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CasDenied {
    /// `expected_generation` did not equal [`VersionIndex::generation`].
    Mismatch,
    /// `expected_generation` was `None` while `generation > 0`.
    MissingExpected,
}

/// [`VersionIndex::remove_version_checked`] failure.
///
/// `Missing` must not be treated as success — MultiDelete cannot hide a
/// lost update behind a silent no-op.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoveVersionError {
    Missing,
}

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

/// Immutable fence object for one committed index generation:
/// `{hex(key)}/index.g{generation:020}.json`.
///
/// Zero-padded to 20 digits (u64 max) so lexicographic order equals numeric
/// order. Fences are created with `If-None-Match: *` and never overwritten
/// or deleted: exactly one writer can own a generation, which is what makes
/// the index CAS hold across proxies. Reusing a generation name after a
/// delete would fork history, so fences are permanent until an offline
/// compactor with its own safety proof (follow-up window).
pub fn index_generation_object_name(key: &str, generation: u64) -> String {
    format!("{}/index.g{generation:020}.json", key_hex(key))
}

/// `{key_hex}/index.json` mirror or `{key_hex}/index.g{N:020}.json` fence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionIndexObjectName {
    Mirror { key_hex: String },
    Fence { key_hex: String, generation: u64 },
}

pub fn parse_version_index_object_name(name: &str) -> Option<VersionIndexObjectName> {
    let (enc, fname) = name.rsplit_once('/')?;
    if enc.is_empty() {
        return None;
    }
    if fname == INDEX_NAME {
        return Some(VersionIndexObjectName::Mirror {
            key_hex: enc.to_string(),
        });
    }
    let rest = fname.strip_prefix("index.g")?.strip_suffix(".json")?;
    if rest.len() != 20 || !rest.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let generation = rest.parse().ok()?;
    Some(VersionIndexObjectName::Fence {
        key_hex: enc.to_string(),
        generation,
    })
}

/// Object names ListVersions must GET: the highest generation fence per
/// key, or the `index.json` mirror when no fence exists.
///
/// Concurrent PUTs commit the full snapshot into an immutable fence
/// *before* the mirror. An unconditional heal can clobber a newer
/// `index.json`. Listing the max fence is the source of truth.
pub fn version_index_fetch_names(listing_names: &[String]) -> Vec<String> {
    struct Best {
        mirror: Option<String>,
        fence_gen: u64,
        fence: Option<String>,
    }
    let mut by_hex: HashMap<String, Best> = HashMap::new();
    for name in listing_names {
        match parse_version_index_object_name(name) {
            Some(VersionIndexObjectName::Mirror { key_hex }) => {
                by_hex
                    .entry(key_hex)
                    .or_insert(Best {
                        mirror: None,
                        fence_gen: 0,
                        fence: None,
                    })
                    .mirror = Some(name.clone());
            }
            Some(VersionIndexObjectName::Fence {
                key_hex,
                generation,
            }) => {
                let e = by_hex.entry(key_hex).or_insert(Best {
                    mirror: None,
                    fence_gen: 0,
                    fence: None,
                });
                if e.fence.is_none() || generation > e.fence_gen {
                    e.fence_gen = generation;
                    e.fence = Some(name.clone());
                }
            }
            None => {}
        }
    }
    let mut out = Vec::new();
    for b in by_hex.into_values() {
        if let Some(n) = b.fence {
            out.push(n);
        } else if let Some(n) = b.mirror {
            out.push(n);
        }
    }
    out
}

/// Object keys that have an index mirror or generation fence in a versions
/// container listing. ListVersions snapshot-loads each key (GET + adopt
/// fences with X-Newest) instead of trusting a stale listing of fence names.
pub fn version_index_keys_from_listing_names(listing_names: &[String]) -> Vec<String> {
    let mut keys: HashSet<String> = HashSet::new();
    for name in listing_names {
        if let Some((k, _)) = parse_archive_object_name(name) {
            keys.insert(k);
            continue;
        }
        let hex = match parse_version_index_object_name(name) {
            Some(VersionIndexObjectName::Mirror { key_hex })
            | Some(VersionIndexObjectName::Fence { key_hex, .. }) => key_hex,
            None => continue,
        };
        if let Some(k) = key_from_hex(&hex) {
            keys.insert(k);
        }
    }
    keys.into_iter().collect()
}

/// Keep the highest-generation index per object key.
pub fn collapse_version_indexes_latest(indexes: Vec<VersionIndex>) -> Vec<VersionIndex> {
    let mut best: HashMap<String, VersionIndex> = HashMap::new();
    for idx in indexes {
        match best.get(&idx.key) {
            Some(prev)
                if prev.generation > idx.generation
                    || (prev.generation == idx.generation
                        && prev.versions.len() >= idx.versions.len()) => {}
            _ => {
                best.insert(idx.key.clone(), idx);
            }
        }
    }
    best.into_values().collect()
}

pub fn parse_archive_object_name(name: &str) -> Option<(String, String)> {
    let (enc, vid) = name.rsplit_once('/')?;
    // INDEX_NAME / `?versionId=index.json` cannot be an archive object.
    if enc.is_empty() || !is_safe_version_id(vid) {
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
    /// Index CAS generation. Optional on the wire (`generation`, default
    /// `0` for legacy mirrors). In-process it gates [`Self::apply_if_match`]
    /// (fast path); across proxies each committed generation is fenced by a
    /// create-only backend object (see [`index_generation_object_name`]).
    pub generation: u64,
}

impl VersionIndex {
    pub fn new(key: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            versions: Vec::new(),
            generation: 0,
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
        // Existing shape is `key` + `versions`. `generation` is optional
        // and omitted at the default of 0.
        let mut obj = serde_json::Map::new();
        obj.insert("key".to_string(), json!(self.key));
        obj.insert("versions".to_string(), Value::Array(versions));
        if self.generation != 0 {
            obj.insert("generation".to_string(), json!(self.generation));
        }
        serde_json::to_vec(&Value::Object(obj)).unwrap_or_default()
    }

    pub fn from_json(data: &[u8]) -> Option<Self> {
        let v: Value = serde_json::from_slice(data).ok()?;
        let key = v.get("key")?.as_str()?.to_string();
        let versions_val = v.get("versions")?;
        if !versions_val.is_array() {
            return None;
        }
        let arr = versions_val.as_array()?;
        if arr.len() > MAX_INDEX_VERSIONS {
            return None;
        }
        let generation = match v.get("generation") {
            None | Some(Value::Null) => 0,
            Some(g) => g.as_u64()?,
        };
        let mut versions = Vec::with_capacity(arr.len());
        for item in arr {
            let version_id = item.get("version_id")?.as_str()?.to_string();
            // Reject index.json and any id that cannot be an archive name.
            if !is_safe_version_id(&version_id) {
                return None;
            }
            versions.push(VersionRecord {
                version_id,
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
        Some(Self {
            key,
            versions,
            generation,
        })
    }

    pub fn push_latest(&mut self, mut rec: VersionRecord) {
        self.versions.retain(|v| v.version_id != rec.version_id);
        for v in &mut self.versions {
            v.is_latest = false;
        }
        rec.is_latest = true;
        self.versions.insert(0, rec);
    }

    /// Suspended PUT: overwrite the null version as latest.
    ///
    /// Hidden versions stay in the index and are **not** resurrected as
    /// latest. Resurrection requires an explicit [`VersionRecord`] via
    /// [`Self::push_latest`] / [`Self::apply_if_match`].
    pub fn suspended_put_overwrites_null(&mut self, mut rec: VersionRecord) {
        rec.version_id = NULL_VERSION_ID.to_string();
        self.versions.retain(|v| v.version_id != NULL_VERSION_ID);
        self.push_latest(rec);
    }

    pub fn find(&self, version_id: &str) -> Option<&VersionRecord> {
        self.versions.iter().find(|v| v.version_id == version_id)
    }

    fn latest_version_id(&self) -> &str {
        self.versions
            .iter()
            .find(|v| v.is_latest)
            .or_else(|| self.versions.first())
            .map(|v| v.version_id.as_str())
            .unwrap_or("")
    }

    /// Opaque hex of `generation` + latest `version_id` + `key`.
    ///
    /// In-process identity only — never sent to the backend (the backend
    /// CAS is the create-only generation fence, not this digest).
    pub fn cas_etag(&self) -> String {
        let latest = self.latest_version_id();
        let mut material = Vec::with_capacity(8 + latest.len() + self.key.len() + 2);
        material.extend_from_slice(&self.generation.to_be_bytes());
        material.push(0);
        material.extend_from_slice(latest.as_bytes());
        material.push(0);
        material.extend_from_slice(self.key.as_bytes());
        sha256_hex(&material)
    }

    /// In-process CAS write: accept `rec` as latest iff `expected_generation`
    /// matches, then increment [`Self::generation`].
    ///
    /// * `Some(g)` must equal the current generation.
    /// * `None` is allowed only when `generation == 0` (uninitialized).
    /// * `None` when `generation > 0` is denied.
    ///
    /// This is the in-process fast path; the resulting generation is then
    /// committed across proxies by the backend fence in
    /// `middleware::cas_save_version_index`.
    pub fn apply_if_match(
        &mut self,
        expected_generation: Option<u64>,
        rec: VersionRecord,
    ) -> Result<(), CasDenied> {
        match expected_generation {
            Some(g) if g == self.generation => {}
            None if self.generation == 0 => {}
            Some(_) => return Err(CasDenied::Mismatch),
            None => return Err(CasDenied::MissingExpected),
        }
        self.push_latest(rec);
        self.generation = self.generation.saturating_add(1);
        Ok(())
    }

    /// Existing behaviour: missing target is a silent no-op (`None`).
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

    /// Like [`Self::remove_version`], but a missing target is
    /// [`RemoveVersionError::Missing`] rather than success.
    ///
    /// MultiDelete must opt into this so a lost update cannot be hidden.
    pub fn remove_version_checked(
        &mut self,
        version_id: &str,
    ) -> Result<Option<String>, RemoveVersionError> {
        if self.find(version_id).is_none() {
            return Err(RemoveVersionError::Missing);
        }
        Ok(self.remove_version(version_id))
    }
}

/// One current object that never entered `{bucket}+versions`.
///
/// AWS ListObjectVersions still emits these as `VersionId=null` /
/// `IsLatest=true` on never-versioned and pre-versioning keys.
pub fn null_version_index(
    key: impl Into<String>,
    last_modified: impl Into<String>,
    etag: impl Into<String>,
    size: i64,
) -> VersionIndex {
    VersionIndex {
        key: key.into(),
        versions: vec![VersionRecord {
            version_id: NULL_VERSION_ID.to_string(),
            is_delete_marker: false,
            is_latest: true,
            last_modified: last_modified.into(),
            etag: etag.into(),
            size,
        }],
        generation: 0,
    }
}

/// Fold archive objects (`{hex}/{vid}`) into a key's index when the JSON
/// mirror/fence raced and dropped an acknowledged version. Listing then
/// matches versions-container reality (Python object_versioning).
/// Keep delete-markers and rows whose object bytes still exist
/// (`live_vids` = archive vids ∪ current SYS_VERSION_ID).
/// Concurrent DELETE can empty archives while a forked fence still
/// lists the vid; ListVersions must not emit those ghosts.
pub fn retain_live_version_rows(idx: &mut VersionIndex, live_vids: &HashSet<String>) {
    idx.versions
        .retain(|v| v.is_delete_marker || live_vids.contains(&v.version_id));
    if !idx.versions.iter().any(|v| v.is_latest) {
        if let Some(first) = idx.versions.first_mut() {
            first.is_latest = true;
        }
    }
}

pub fn merge_archive_objects_into_index(
    idx: &mut VersionIndex,
    archives: &[(String, String, i64, String)],
) {
    for (vid, etag, size, last_modified) in archives {
        if !is_safe_version_id(vid) || idx.find(vid).is_some() {
            continue;
        }
        idx.versions.push(VersionRecord {
            version_id: vid.clone(),
            is_delete_marker: false,
            is_latest: false,
            last_modified: last_modified.clone(),
            etag: etag.clone(),
            size: *size,
        });
    }
}

/// Fold data-container objects into the version listing when they have no
/// index row. Keys already present in `indexes` stay index-authored so an
/// Enabled current copy is not duplicated as a second `null`.
pub fn merge_unindexed_current_objects(
    indexes: &mut Vec<VersionIndex>,
    current: &[(String, String, i64, String)],
) {
    let have: HashSet<String> = indexes.iter().map(|idx| idx.key.clone()).collect();
    for (key, etag, size, last_modified) in current {
        if have.contains(key) {
            continue;
        }
        indexes.push(null_version_index(key, last_modified, etag, *size));
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
/// * when `key == key_marker` and `version_id_marker` is unknown: AWS would
///   400 InvalidArgument. Residual: this helper has no error channel, so it
///   does not emit that 400. Fail closed by skipping the whole key (do not
///   start at 0). Cross-proxy listing linearization is still BLOCKED.
///
/// When `max-keys` cuts the flat listing, `IsTruncated=true` and both
/// `NextKeyMarker` / `NextVersionIdMarker` are set to the last returned entry.
pub fn list_versions_result_xml(
    bucket: &str,
    prefix: &str,
    key_marker: &str,
    version_id_marker: &str,
    max_keys: u32,
    delimiter: &str,
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
                    // Unknown version-id-marker: AWS ListObjectVersions returns
                    // 400 InvalidArgument. Residual: this helper has no error
                    // channel, so we do not emit that 400. Fail closed by
                    // skipping the whole key — do not start at 0 (a stale
                    // marker must not replay the key from the beginning).
                    // Cross-proxy listing linearization is still BLOCKED.
                    None => continue,
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
    root.push_leaf("Delimiter", delimiter);
    root.push_leaf("IsTruncated", if truncated { "true" } else { "false" });
    for (key, v) in &slice {
        if v.is_delete_marker {
            let mut dm = Element::new("DeleteMarker");
            dm.push_leaf("Key", key);
            dm.push_leaf("VersionId", &v.version_id);
            dm.push_leaf("IsLatest", if v.is_latest { "true" } else { "false" });
            dm.push_leaf("LastModified", s3_xml_timestamp(&v.last_modified));
            root.push(dm);
        } else {
            let mut ver = Element::new("Version");
            ver.push_leaf("Key", key);
            ver.push_leaf("VersionId", &v.version_id);
            ver.push_leaf("IsLatest", if v.is_latest { "true" } else { "false" });
            ver.push_leaf("LastModified", s3_xml_timestamp(&v.last_modified));
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
            String::from_utf8(list_versions_result_xml("b", "", "", "", 1000, "", &[idx])).unwrap();
        assert!(xml.contains("<Version>"));
        assert!(xml.contains("<VersionId>v1</VersionId>"));
        assert!(xml.contains("<VersionId>v2</VersionId>"));
        assert!(!xml.contains("NextKeyMarker"));
        assert!(xml.contains("<IsTruncated>false</IsTruncated>"));
        assert!(xml.contains("<LastModified>2020-01-01T00:00:00.000Z</LastModified>"));
    }

    #[test]
    fn list_versions_http_date_last_modified_emits_iso() {
        let mut idx = VersionIndex::new("k");
        idx.push_latest(VersionRecord {
            version_id: "v1".into(),
            is_delete_marker: false,
            is_latest: true,
            last_modified: "Fri, 24 May 2013 00:00:00 GMT".into(),
            etag: "e1".into(),
            size: 3,
        });
        idx.push_latest(VersionRecord {
            version_id: "dm".into(),
            is_delete_marker: true,
            is_latest: true,
            last_modified: "2013-05-24T00:00:00.000000".into(),
            etag: String::new(),
            size: 0,
        });
        let xml =
            String::from_utf8(list_versions_result_xml("b", "", "", "", 1000, "", &[idx])).unwrap();
        assert_eq!(
            xml.matches("<LastModified>2013-05-24T00:00:00.000Z</LastModified>")
                .count(),
            2
        );
        assert!(!xml.contains("Fri, 24 May"));
        assert!(!xml.contains("00:00:00.000000"));
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
        let page1 = String::from_utf8(list_versions_result_xml(
            "bucket", "", "", "", 2, "", &indexes,
        ))
        .unwrap();
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
            "bucket", "", "a", "a1", 2, "", &indexes,
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
            "bucket", "", "b", "b1", 2, "", &indexes,
        ))
        .unwrap();
        assert!(page3.contains("<IsTruncated>false</IsTruncated>"));
        assert!(!page3.contains("NextKeyMarker"));
        assert!(!page3.contains("NextVersionIdMarker"));
        assert_eq!(count_tag(&page3, "Version"), 1);
        assert!(page3.contains("<VersionId>c1</VersionId>"));

        // Cut mid-key: max-keys=1 on key a → only a2, Next=(a,a2)
        let mid = String::from_utf8(list_versions_result_xml(
            "bucket", "", "", "", 1, "", &indexes,
        ))
        .unwrap();
        assert!(mid.contains("<IsTruncated>true</IsTruncated>"));
        assert_eq!(tag_text(&mid, "NextKeyMarker").as_deref(), Some("a"));
        assert_eq!(tag_text(&mid, "NextVersionIdMarker").as_deref(), Some("a2"));
        let mid2 = String::from_utf8(list_versions_result_xml(
            "bucket", "", "a", "a2", 1, "", &indexes,
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
            "b", "logs/", "", "", 1000, "", &indexes,
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
        let page = String::from_utf8(list_versions_result_xml(
            "b", "logs/", "", "", 1, "", &indexes,
        ))
        .unwrap();
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
    fn merge_unindexed_current_objects_emits_null_and_skips_indexed() {
        let mut indexed = VersionIndex::new("already");
        indexed.push_latest(VersionRecord {
            version_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            is_delete_marker: false,
            is_latest: true,
            last_modified: "2020-01-02T00:00:00.000Z".into(),
            etag: "e2".into(),
            size: 2,
        });
        let mut indexes = vec![indexed];
        merge_unindexed_current_objects(
            &mut indexes,
            &[
                (
                    "already".into(),
                    "ignored".into(),
                    9,
                    "2020-01-03T00:00:00.000Z".into(),
                ),
                (
                    "foo".into(),
                    "abc".into(),
                    3,
                    "2020-01-01T00:00:00.000Z".into(),
                ),
            ],
        );
        assert_eq!(indexes.len(), 2);
        assert_eq!(indexes[0].key, "already");
        assert_eq!(
            indexes[0].versions[0].version_id,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(indexes[1].key, "foo");
        assert_eq!(indexes[1].versions[0].version_id, NULL_VERSION_ID);
        assert!(indexes[1].versions[0].is_latest);
        let xml = String::from_utf8(list_versions_result_xml(
            "b", "", "", "", 1000, "", &indexes,
        ))
        .unwrap();
        assert!(xml.contains("<Key>foo</Key>"));
        assert!(xml.contains("<VersionId>null</VersionId>"));
        assert_eq!(xml.matches("<Version>").count(), 2);
    }

    #[test]
    fn list_versions_empty_indexes_and_empty_versions() {
        // Empty container / no indexes → empty ListVersionsResult
        let empty =
            String::from_utf8(list_versions_result_xml("b", "", "", "", 1000, "", &[])).unwrap();
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
            String::from_utf8(list_versions_result_xml("b", "", "", "", 10, "", &[hollow]))
                .unwrap();
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
            "",
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

    #[test]
    fn versioning_status_unversioned_enabled_suspended() {
        assert_eq!(versioning_status(None), VersioningStatus::Unversioned);
        assert_eq!(versioning_status(Some("")), VersioningStatus::Unversioned);
        assert_eq!(
            versioning_status(Some("Disabled")),
            VersioningStatus::Unversioned
        );
        assert_eq!(
            versioning_status(Some("Enabled")),
            VersioningStatus::Enabled
        );
        assert_eq!(
            versioning_status(Some(" Suspended ")),
            VersioningStatus::Suspended
        );
        assert!(VersioningStatus::Suspended.suspended_put_overwrites_null());
        assert!(!VersioningStatus::Enabled.suspended_put_overwrites_null());
        assert!(!VersioningStatus::Unversioned.suspended_put_overwrites_null());
    }

    #[test]
    fn suspended_put_overwrites_null_does_not_resurrect_hidden() {
        let mut idx = VersionIndex::new("k");
        idx.push_latest(rec("v1", true));
        idx.push_latest(rec("v2", true));
        // v1 is hidden; Suspended PUT must write null, not promote v1.
        idx.suspended_put_overwrites_null(rec("ignored", true));
        assert_eq!(idx.versions.len(), 3);
        assert_eq!(idx.versions[0].version_id, NULL_VERSION_ID);
        assert!(idx.versions[0].is_latest);
        assert_eq!(idx.find("v1").map(|v| v.is_latest), Some(false));
        assert_eq!(idx.find("v2").map(|v| v.is_latest), Some(false));

        // Second Suspended PUT overwrites the existing null version.
        let mut over = rec("also-ignored", true);
        over.etag = "e-null-2".into();
        idx.suspended_put_overwrites_null(over);
        assert_eq!(
            idx.versions
                .iter()
                .filter(|v| v.version_id == NULL_VERSION_ID)
                .count(),
            1
        );
        assert_eq!(idx.versions[0].etag, "e-null-2");
        assert_eq!(idx.versions.len(), 3);
        assert!(idx.find("v1").is_some());
        assert!(idx.find("v2").is_some());
    }

    #[test]
    fn is_safe_version_id_rejects_path_and_index_tokens() {
        assert!(!is_safe_version_id(""));
        assert!(!is_safe_version_id(INDEX_NAME));
        assert!(!is_safe_version_id("index.json"));
        assert!(!is_safe_version_id("."));
        assert!(!is_safe_version_id(".."));
        assert!(!is_safe_version_id("a/b"));
        assert!(!is_safe_version_id("/abc"));
        assert!(!is_safe_version_id("abc/"));
        assert!(!is_safe_version_id("ab\0c"));
        assert!(is_safe_version_id("0123456789abcdef0123456789abcdef"));
        assert!(is_safe_version_id(NULL_VERSION_ID));
    }

    #[test]
    fn is_safe_version_id_reserves_generation_fence_namespace() {
        // A poisoned index listing a fence name as a version-id could make
        // an exact-version DELETE remove the fence and fork history.
        assert!(!is_safe_version_id("index.g00000000000000000001.json"));
        assert!(!is_safe_version_id("index.g1.json"));
        assert!(!is_safe_version_id("index."));
        assert!(!is_safe_version_id("index.anything"));
        // Bare "index" without the dot stays a (weird but) legal id.
        assert!(is_safe_version_id("index"));
    }

    #[test]
    fn index_generation_object_name_orders_and_never_parses_as_archive() {
        let g1 = index_generation_object_name("obj", 1);
        assert_eq!(
            g1,
            format!("{}/index.g00000000000000000001.json", key_hex("obj"))
        );
        // Zero-padding: lexicographic order equals numeric order, including
        // across digit-count boundaries and at u64::MAX.
        let g9 = index_generation_object_name("obj", 9);
        let g10 = index_generation_object_name("obj", 10);
        let gmax = index_generation_object_name("obj", u64::MAX);
        assert!(g1 < g9 && g9 < g10 && g10 < gmax);
        // Fences are not archives and must never resolve as one.
        assert_eq!(parse_archive_object_name(&g1), None);
        assert_eq!(parse_archive_object_name(&gmax), None);
        // Fences do not share the mirror suffix; ListVersions must select
        // them via [`parse_version_index_object_name`], not `ends_with`.
        assert!(!g1.ends_with(INDEX_NAME));
        assert_eq!(
            parse_version_index_object_name(&g1),
            Some(VersionIndexObjectName::Fence {
                key_hex: key_hex("obj"),
                generation: 1,
            })
        );
        // A fence read back as a full index snapshot round-trips.
        let mut idx = VersionIndex::new("obj");
        idx.generation = 7;
        let parsed = VersionIndex::from_json(&idx.to_json()).unwrap();
        assert_eq!(parsed.generation, 7);
    }

    #[test]
    fn version_index_fetch_names_prefers_max_fence_over_stale_mirror() {
        let hex = key_hex("k");
        let mirror = format!("{hex}/index.json");
        let g3 = index_generation_object_name("k", 3);
        let g8 = index_generation_object_name("k", 8);
        let archive = format!("{hex}/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let names = vec![
            archive,
            mirror.clone(),
            g3.clone(),
            g8.clone(),
            format!("{}/index.json", key_hex("other")),
        ];
        let fetch = version_index_fetch_names(&names);
        assert!(fetch.contains(&g8), "{fetch:?}");
        assert!(!fetch.contains(&g3), "{fetch:?}");
        assert!(!fetch.contains(&mirror), "{fetch:?}");
        assert_eq!(fetch.len(), 2);
    }

    #[test]
    fn collapse_version_indexes_latest_keeps_higher_generation() {
        let mut a = VersionIndex::new("k");
        a.generation = 3;
        a.push_latest(VersionRecord {
            version_id: "v3".into(),
            is_delete_marker: false,
            is_latest: true,
            last_modified: "t".into(),
            etag: "e".into(),
            size: 1,
        });
        let mut b = VersionIndex::new("k");
        b.generation = 8;
        b.push_latest(VersionRecord {
            version_id: "v8".into(),
            is_delete_marker: false,
            is_latest: true,
            last_modified: "t".into(),
            etag: "e".into(),
            size: 1,
        });
        b.push_latest(VersionRecord {
            version_id: "v7".into(),
            is_delete_marker: false,
            is_latest: true,
            last_modified: "t".into(),
            etag: "e".into(),
            size: 1,
        });
        let out = collapse_version_indexes_latest(vec![a, b]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].generation, 8);
        assert_eq!(out[0].versions.len(), 2);
    }

    #[test]
    fn push_latest_replaces_duplicate_version_id() {
        let mut idx = VersionIndex::new("k");
        idx.push_latest(VersionRecord {
            version_id: "v1".into(),
            is_delete_marker: false,
            is_latest: true,
            last_modified: "t1".into(),
            etag: "e1".into(),
            size: 1,
        });
        idx.push_latest(VersionRecord {
            version_id: "v1".into(),
            is_delete_marker: false,
            is_latest: true,
            last_modified: "t2".into(),
            etag: "e2".into(),
            size: 2,
        });
        assert_eq!(idx.versions.len(), 1);
        assert_eq!(idx.versions[0].etag, "e2");
        assert!(idx.versions[0].is_latest);
    }

    #[test]
    fn merge_archive_objects_adds_missing_vid_only() {
        let mut idx = VersionIndex::new("k");
        idx.push_latest(VersionRecord {
            version_id: "v1".into(),
            is_delete_marker: false,
            is_latest: true,
            last_modified: "t".into(),
            etag: "e1".into(),
            size: 1,
        });
        merge_archive_objects_into_index(
            &mut idx,
            &[
                ("v1".into(), "e1".into(), 1, "t".into()),
                ("v2".into(), "e2".into(), 2, "t".into()),
            ],
        );
        assert_eq!(idx.versions.len(), 2);
        assert!(idx.find("v2").is_some());
        assert!(idx.find("v1").unwrap().is_latest);
    }

    #[test]
    fn retain_live_version_rows_drops_ghost_data_keeps_delete_marker() {
        let mut idx = VersionIndex::new("k");
        idx.push_latest(VersionRecord {
            version_id: "live".into(),
            is_delete_marker: false,
            is_latest: true,
            last_modified: "t".into(),
            etag: "e".into(),
            size: 1,
        });
        idx.versions.push(VersionRecord {
            version_id: "ghost".into(),
            is_delete_marker: false,
            is_latest: false,
            last_modified: "t".into(),
            etag: "e".into(),
            size: 1,
        });
        idx.versions.push(VersionRecord {
            version_id: "dm".into(),
            is_delete_marker: true,
            is_latest: false,
            last_modified: "t".into(),
            etag: "".into(),
            size: 0,
        });
        let mut live = HashSet::new();
        live.insert("live".into());
        retain_live_version_rows(&mut idx, &live);
        assert!(idx.find("live").is_some());
        assert!(idx.find("ghost").is_none());
        assert!(idx.find("dm").is_some());
    }

    #[test]
    fn parse_archive_rejects_version_id_index_json() {
        // `?versionId=index.json` must not address `{hex}/index.json`.
        let as_query = "index.json";
        assert!(!is_safe_version_id(as_query));
        assert_eq!(
            parse_archive_object_name(&archive_object_name("obj", "index.json")),
            None
        );
        assert_eq!(
            parse_archive_object_name(&format!("{}/index.json", key_hex("obj"))),
            None
        );
        assert_eq!(
            parse_archive_object_name(&format!("{}/?versionId=index.json", key_hex("obj"))),
            None
        );
        // Control: a real hex version-id still parses.
        let ok = archive_object_name("obj", "0123456789abcdef0123456789abcdef");
        assert!(parse_archive_object_name(&ok).is_some());
    }

    #[test]
    fn from_json_keeps_key_versions_generation_optional() {
        let old = br#"{"key":"k","versions":[{"version_id":"v1","is_delete_marker":false,"is_latest":true,"last_modified":"t","etag":"e","size":1}]}"#;
        let idx = VersionIndex::from_json(old).unwrap();
        assert_eq!(idx.key, "k");
        assert_eq!(idx.generation, 0);
        assert_eq!(idx.versions.len(), 1);
        assert_eq!(idx.versions[0].version_id, "v1");

        let empty_shape = VersionIndex::new("k");
        let v: Value = serde_json::from_slice(&empty_shape.to_json()).unwrap();
        assert_eq!(v.get("key").and_then(|x| x.as_str()), Some("k"));
        assert!(v.get("versions").and_then(|x| x.as_array()).is_some());
        assert!(v.get("generation").is_none());

        let mut with_gen = VersionIndex::new("k");
        with_gen.generation = 7;
        let v2: Value = serde_json::from_slice(&with_gen.to_json()).unwrap();
        assert_eq!(v2.get("generation").and_then(|x| x.as_u64()), Some(7));
        let back = VersionIndex::from_json(&with_gen.to_json()).unwrap();
        assert_eq!(back.generation, 7);

        let explicit_zero = br#"{"key":"k","versions":[],"generation":0}"#;
        assert_eq!(
            VersionIndex::from_json(explicit_zero).unwrap().generation,
            0
        );
    }

    #[test]
    fn from_json_fail_closed_malformed_and_unsafe_ids() {
        assert!(VersionIndex::from_json(b"not-json").is_none());
        assert!(VersionIndex::from_json(br#"{"key":"k"}"#).is_none());
        assert!(VersionIndex::from_json(br#"{"key":"k","versions":{}}"#).is_none());
        assert!(VersionIndex::from_json(br#"{"key":"k","versions":"nope"}"#).is_none());
        assert!(VersionIndex::from_json(br#"{"key":"k","versions":null}"#).is_none());
        assert!(VersionIndex::from_json(
            br#"{"key":"k","versions":[{"version_id":"index.json"}]}"#
        )
        .is_none());
        assert!(
            VersionIndex::from_json(br#"{"key":"k","versions":[{"version_id":"a/b"}]}"#).is_none()
        );
        assert!(
            VersionIndex::from_json(br#"{"key":"k","versions":[{"version_id":"ab\u0000c"}]}"#)
                .is_none()
        );
        assert!(
            VersionIndex::from_json(br#"{"key":"k","versions":[{"version_id":""}]}"#).is_none()
        );
        assert!(
            VersionIndex::from_json(br#"{"key":"k","versions":[{"version_id":"."}]}"#).is_none()
        );
        assert!(
            VersionIndex::from_json(br#"{"key":"k","versions":[{"version_id":".."}]}"#).is_none()
        );
        assert!(
            VersionIndex::from_json(br#"{"key":"k","versions":[],"generation":"1"}"#).is_none()
        );
    }

    #[test]
    fn from_json_fail_closed_extra_large_index() {
        assert_eq!(MAX_INDEX_VERSIONS, 10_000);
        fn body(n: usize) -> String {
            let mut s = String::from(r#"{"key":"k","versions":["#);
            for i in 0..n {
                if i > 0 {
                    s.push(',');
                }
                s.push_str(&format!(r#"{{"version_id":"{i:x}"}}"#));
            }
            s.push_str("]}");
            s
        }
        assert!(VersionIndex::from_json(body(MAX_INDEX_VERSIONS).as_bytes()).is_some());
        assert!(VersionIndex::from_json(body(MAX_INDEX_VERSIONS + 1).as_bytes()).is_none());
    }

    #[test]
    fn cas_etag_opaque_hex_of_generation_latest_and_key() {
        let mut idx = VersionIndex::new("k");
        idx.push_latest(rec("v1", true));
        let e1 = idx.cas_etag();
        assert_eq!(e1.len(), 64);
        assert!(e1.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(idx.cas_etag(), e1);

        idx.generation = 1;
        let e_gen = idx.cas_etag();
        assert_ne!(e1, e_gen);

        idx.generation = 0;
        idx.push_latest(rec("v2", true));
        let e_latest = idx.cas_etag();
        assert_ne!(e1, e_latest);

        let mut other_key = VersionIndex::new("other");
        other_key.push_latest(rec("v1", true));
        assert_ne!(e1, other_key.cas_etag());
    }

    #[test]
    fn apply_if_match_is_in_process_cas() {
        let mut idx = VersionIndex::new("k");
        assert_eq!(idx.generation, 0);
        assert_eq!(idx.apply_if_match(None, rec("v1", true)), Ok(()));
        assert_eq!(idx.generation, 1);
        assert_eq!(idx.versions[0].version_id, "v1");
        let etag_after_first = idx.cas_etag();

        assert_eq!(
            idx.apply_if_match(None, rec("v2", true)),
            Err(CasDenied::MissingExpected)
        );
        assert_eq!(idx.generation, 1);
        assert_eq!(idx.cas_etag(), etag_after_first);

        assert_eq!(
            idx.apply_if_match(Some(0), rec("v2", true)),
            Err(CasDenied::Mismatch)
        );
        assert_eq!(idx.generation, 1);
        assert_eq!(idx.versions.len(), 1);

        assert_eq!(idx.apply_if_match(Some(1), rec("v2", true)), Ok(()));
        assert_eq!(idx.generation, 2);
        assert_eq!(idx.versions[0].version_id, "v2");
        assert!(idx.versions[0].is_latest);
        assert!(!idx.versions[1].is_latest);
        assert_ne!(idx.cas_etag(), etag_after_first);

        // Some(0) on a fresh index is a match.
        let mut fresh = VersionIndex::new("k");
        assert_eq!(fresh.apply_if_match(Some(0), rec("v0", true)), Ok(()));
        assert_eq!(fresh.generation, 1);
    }

    #[test]
    fn remove_version_silent_missing_checked_reports_missing() {
        let mut idx = VersionIndex::new("k");
        idx.push_latest(rec("v1", true));
        idx.push_latest(rec("v2", true));

        // Existing caller behaviour: missing target is a silent no-op.
        let before = idx.clone();
        assert_eq!(idx.remove_version("no-such"), None);
        assert_eq!(idx, before);

        // Opt-in: Missing so MultiDelete cannot hide a lost update.
        assert_eq!(
            idx.remove_version_checked("no-such"),
            Err(RemoveVersionError::Missing)
        );
        assert_eq!(idx, before);

        assert_eq!(idx.remove_version_checked("v2"), Ok(Some("v1".to_string())));
        assert!(idx.find("v2").is_none());
        assert_eq!(idx.find("v1").map(|v| v.is_latest), Some(true));

        assert_eq!(idx.remove_version_checked("v1"), Ok(None));
        assert!(idx.versions.is_empty());
        assert_eq!(
            idx.remove_version_checked("v1"),
            Err(RemoveVersionError::Missing)
        );
    }

    #[test]
    fn list_versions_unknown_version_id_marker_skips_key() {
        let mut idx_a = VersionIndex::new("a");
        idx_a.versions = vec![rec("a2", true), rec("a1", false)];
        let mut idx_b = VersionIndex::new("b");
        idx_b.versions = vec![rec("b1", true)];
        let indexes = [idx_a, idx_b];

        // AWS-400 residual: unknown marker does not 400 here; fail closed
        // by skipping key `a` instead of the old start-at-0 replay.
        let xml = String::from_utf8(list_versions_result_xml(
            "bucket",
            "",
            "a",
            "does-not-exist",
            100,
            "",
            &indexes,
        ))
        .unwrap();
        assert!(!xml.contains("<VersionId>a2</VersionId>"));
        assert!(!xml.contains("<VersionId>a1</VersionId>"));
        assert!(xml.contains("<VersionId>b1</VersionId>"));
        assert_eq!(count_tag(&xml, "Version"), 1);

        // Known marker still continues after that version on the same key.
        let cont = String::from_utf8(list_versions_result_xml(
            "bucket", "", "a", "a2", 100, "", &indexes,
        ))
        .unwrap();
        assert!(cont.contains("<VersionId>a1</VersionId>"));
        assert!(!cont.contains("<VersionId>a2</VersionId>"));
        assert!(cont.contains("<VersionId>b1</VersionId>"));
    }
}
