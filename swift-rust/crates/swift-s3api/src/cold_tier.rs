// Copyright (c) 2026 OpenStack Foundation
//! Cold-tier / Glacier-like storage-policy transition **policy map + meta stamps**.
//!
//! # Honest boundary
//!
//! **Physical cold backend (tape/Glacier cloud) is not implemented.** Lab
//! adapters [`MemoryColdBackend`] / [`LocalDirColdBackend`] can archive bytes
//! locally when wired via [`ColdBackend::archive_durable`]. Without a backend, this
//! module is a policy map + metadata-stamp helper only. Lifecycle Transition
//! stamps (see [`crate::lifecycle_exec`]) mark objects as intending a cold
//! class. Helpers here can prepare headers an *external* mover would need:
//!
//! 1. Map S3 StorageClass → Swift storage-policy index (`cold_policy_map`).
//! 2. On due transition: stamp cold/hot policy indices (+ optional lab archive URI).
//! 3. Restore: temporary rehydrate window via [`SYS_RESTORE_UNTIL`] plus
//!    optional policy index restore target.
//!
//! Lab `archive` / `restore_stage` move **local** bytes only. This crate does
//! **not** talk to tape/Glacier cloud or schedule a fleet mover. Proxy may
//! populate [`ColdPolicyMap`] / `cold_backend_root` from conf. Python Swift
//! 2.33 rejects direct non-`STANDARD` storage classes and `?restore`. Do not
//! claim tape/Glacier cloud from this crate.
//!
//! [`ColdStateMachine`] is the restore/archive transition table (plus CAS
//! generations). [`LocalDirColdBackend`] is proxy-local, not Glacier, not
//! shared durable, and not production.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use swift_http::HeaderKeyDict;

use crate::crypto::{hex_encode, sha256, sha256_hex};
use crate::lifecycle_exec::{
    is_cold_storage_class, META_STORAGE_CLASS, SYS_RESTORE_UNTIL, SYS_TRANSITIONED,
    SYS_TRANSITION_AT,
};

/// Sysmeta: storage policy index of the cold tier holding object bytes.
pub const SYS_COLD_POLICY_INDEX: &str = "X-Object-Sysmeta-S3-Cold-Policy-Index";
/// Sysmeta: original (hot) storage policy index before transition.
pub const SYS_HOT_POLICY_INDEX: &str = "X-Object-Sysmeta-S3-Hot-Policy-Index";
/// Sysmeta: backend path hint for tape/glacier adapters (opaque).
pub const SYS_COLD_BACKEND_URI: &str = "X-Object-Sysmeta-S3-Cold-Backend-Uri";
/// Sysmeta: byte length committed by the cold backend.
pub const SYS_COLD_CONTENT_LENGTH: &str = "X-Object-Sysmeta-S3-Cold-Content-Length";
/// Sysmeta: SHA-256 of the bytes committed by the cold backend.
pub const SYS_COLD_CONTENT_SHA256: &str = "X-Object-Sysmeta-S3-Cold-Content-Sha256";
/// Sysmeta: explicit cold archive state. Only `durable` permits hot reclamation.
pub const SYS_COLD_ARCHIVE_STATE: &str = "X-Object-Sysmeta-S3-Cold-Archive-State";
/// Sysmeta: CAS counter for archive commit / post-expiry return-to-durable.
/// Middleware can later compare this on PUT against a POST restore.
pub const SYS_COLD_ARCHIVE_GENERATION: &str = "X-Object-Sysmeta-S3-Cold-Archive-Generation";
/// Sysmeta: CAS counter for begin/complete restore. Middleware can later
/// compare this on POST restore against a concurrent PUT.
pub const SYS_COLD_RESTORE_GENERATION: &str = "X-Object-Sysmeta-S3-Cold-Restore-Generation";
/// Request header used by proxy to force object server policy selection.
pub const HDR_BACKEND_STORAGE_POLICY_INDEX: &str = "X-Backend-Storage-Policy-Index";

const COLD_ARCHIVE_DURABLE: &str = "durable";
/// Conceptual default for `cold_delete_hot_after_archive`. Must stay false.
/// Callers pass the flag explicitly; nothing here assumes it is true.
pub const COLD_DELETE_HOT_AFTER_ARCHIVE_DEFAULT: bool = false;
const SECONDS_PER_DAY: i64 = 86_400;
const LOCAL_ARCHIVE_MAGIC: &[u8] = b"PEREGRINE-COLD-V2\0";
const LOCAL_ARCHIVE_IDENTITY_DOMAIN: &[u8] = b"PEREGRINE-COLD-IDENTITY-V1\0";
// policy + account length + container length + key length + payload length,
// followed by the identity and payload SHA-256 digests.
const LOCAL_ARCHIVE_FIXED_HEADER_LEN: usize = LOCAL_ARCHIVE_MAGIC.len() + (5 * 8) + 32 + 32;
static LOCAL_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// State of a physical archive attempt / restore window.
///
/// Existing variants (`MetadataOnly`, `UnverifiedReference`, `Durable`) keep
/// their meaning. Restore/failure variants extend the table; they are not
/// renames. `MetadataOnly`, `UnverifiedReference`, `Failed`, `Restoring` and
/// `Restored` are never safe for hot reclamation. `Durable` is accepted only
/// together with a receipt whose length and digest match the exact hot payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColdArchiveState {
    MetadataOnly,
    UnverifiedReference,
    Durable,
    Restoring { days: i64, restore_until_unix: i64 },
    Restored { restore_until_unix: i64 },
    Failed,
}

impl ColdArchiveState {
    pub fn restore_until_unix(self) -> Option<i64> {
        match self {
            Self::Restoring {
                restore_until_unix, ..
            }
            | Self::Restored { restore_until_unix } => Some(restore_until_unix),
            _ => None,
        }
    }

    pub fn is_restore_window(self) -> bool {
        matches!(self, Self::Restoring { .. } | Self::Restored { .. })
    }
}

/// Proof returned after a backend durably commits and verifies an archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColdArchiveReceipt {
    pub backend_uri: String,
    pub content_length: u64,
    pub content_sha256: String,
    pub state: ColdArchiveState,
}

impl ColdArchiveReceipt {
    fn durable(backend_uri: String, body: &[u8]) -> Result<Self, String> {
        let content_length = u64::try_from(body.len())
            .map_err(|_| "cold archive payload length exceeds u64".to_string())?;
        Ok(Self {
            backend_uri,
            content_length,
            content_sha256: sha256_hex(body),
            state: ColdArchiveState::Durable,
        })
    }

    /// Verify that this durable receipt describes `body` exactly.
    pub fn verifies_payload(&self, body: &[u8]) -> bool {
        self.state == ColdArchiveState::Durable
            && u64::try_from(body.len()).ok() == Some(self.content_length)
            && self.content_sha256.len() == 64
            && self.content_sha256 == sha256_hex(body)
            && !self.backend_uri.is_empty()
    }

    fn same_archive_identity(&self, other: &Self) -> bool {
        self.backend_uri == other.backend_uri
            && self.content_length == other.content_length
            && self.content_sha256 == other.content_sha256
    }

    fn stamp_headers(&self, headers: &mut HeaderKeyDict) {
        headers.set(SYS_COLD_BACKEND_URI, &self.backend_uri);
        headers.set(SYS_COLD_CONTENT_LENGTH, self.content_length.to_string());
        headers.set(SYS_COLD_CONTENT_SHA256, &self.content_sha256);
        headers.set(SYS_COLD_ARCHIVE_STATE, COLD_ARCHIVE_DURABLE);
    }
}

/// Formal cold lifecycle with CAS generations for later POST-restore vs PUT.
///
/// Transitions are the pure functions below. Generations increment only on a
/// successful state change. This record is not a tape/Glacier backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColdStateMachine {
    pub state: ColdArchiveState,
    pub receipt: Option<ColdArchiveReceipt>,
    pub archive_generation: u64,
    pub restore_generation: u64,
}

impl Default for ColdStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl ColdStateMachine {
    pub fn new() -> Self {
        Self {
            state: ColdArchiveState::MetadataOnly,
            receipt: None,
            archive_generation: 0,
            restore_generation: 0,
        }
    }

    pub fn stamp_generation_headers(&self, headers: &mut HeaderKeyDict) {
        headers.set(
            SYS_COLD_ARCHIVE_GENERATION,
            self.archive_generation.to_string(),
        );
        headers.set(
            SYS_COLD_RESTORE_GENERATION,
            self.restore_generation.to_string(),
        );
    }

    /// Apply [`archive_commit`]. Success bumps `archive_generation`.
    /// 206/partial or non-verifying receipts return `Err` and do not bump.
    pub fn apply_archive_commit(
        &self,
        receipt: ColdArchiveReceipt,
        body: &[u8],
        is_range_or_206: bool,
    ) -> Result<Self, String> {
        match archive_commit(&receipt, body, is_range_or_206) {
            Ok(state) => Ok(Self {
                state,
                receipt: Some(receipt),
                archive_generation: self.archive_generation.saturating_add(1),
                restore_generation: self.restore_generation,
            }),
            Err(error) => Err(error),
        }
    }

    /// Same as [`Self::apply_archive_commit`] but a rejected commit lands in
    /// [`ColdArchiveState::Failed`] instead of leaving the caller to map `Err`.
    pub fn apply_archive_commit_or_fail(
        &self,
        receipt: ColdArchiveReceipt,
        body: &[u8],
        is_range_or_206: bool,
    ) -> Self {
        match self.apply_archive_commit(receipt.clone(), body, is_range_or_206) {
            Ok(next) => next,
            Err(_) => Self {
                state: ColdArchiveState::Failed,
                receipt: Some(receipt),
                archive_generation: self.archive_generation,
                restore_generation: self.restore_generation,
            },
        }
    }

    pub fn apply_begin_restore(&self, now: i64, days: i64) -> Result<Self, String> {
        Ok(Self {
            state: begin_restore(self.state, now, days)?,
            receipt: self.receipt.clone(),
            archive_generation: self.archive_generation,
            restore_generation: self.restore_generation.saturating_add(1),
        })
    }

    pub fn apply_complete_restore(&self, now: i64) -> Result<Self, String> {
        Ok(Self {
            state: complete_restore(self.state, now)?,
            receipt: self.receipt.clone(),
            archive_generation: self.archive_generation,
            restore_generation: self.restore_generation.saturating_add(1),
        })
    }

    pub fn apply_maybe_rearchive(
        &self,
        now: i64,
        delete_hot_enabled: bool,
    ) -> Result<Self, String> {
        let next = maybe_rearchive(self.state, now, delete_hot_enabled)?;
        let archive_generation = if next != self.state {
            self.archive_generation.saturating_add(1)
        } else {
            self.archive_generation
        };
        Ok(Self {
            state: next,
            receipt: self.receipt.clone(),
            archive_generation,
            restore_generation: self.restore_generation,
        })
    }

    pub fn hot_reclamation_allowed(
        &self,
        delete_hot_enabled: bool,
        body: &[u8],
        is_range_or_206: bool,
    ) -> bool {
        hot_reclamation_allowed(
            self.state,
            self.receipt.as_ref(),
            body,
            delete_hot_enabled,
            is_range_or_206,
        )
    }
}

/// Archive of a range / HTTP 206 body is an error and never Durable.
pub fn reject_partial_body(is_range_or_206: bool) -> Result<(), String> {
    if is_range_or_206 {
        Err("cannot archive a range or HTTP 206 partial body".into())
    } else {
        Ok(())
    }
}

/// Commit an archive. Returns [`ColdArchiveState::Durable`] only when `receipt`
/// verifies `body` and the body is not a range/206. Otherwise `Err` (never Durable).
pub fn archive_commit(
    receipt: &ColdArchiveReceipt,
    body: &[u8],
    is_range_or_206: bool,
) -> Result<ColdArchiveState, String> {
    reject_partial_body(is_range_or_206)?;
    if !receipt.verifies_payload(body) {
        return Err("cold archive receipt does not verify payload".into());
    }
    Ok(ColdArchiveState::Durable)
}

/// Durable → Restoring. `days` must be positive.
pub fn begin_restore(
    state: ColdArchiveState,
    now: i64,
    days: i64,
) -> Result<ColdArchiveState, String> {
    match state {
        ColdArchiveState::Durable => {
            if days <= 0 {
                return Err("restore days must be positive".into());
            }
            let restore_until_unix = now.saturating_add(days.saturating_mul(SECONDS_PER_DAY));
            Ok(ColdArchiveState::Restoring {
                days,
                restore_until_unix,
            })
        }
        _ => Err("begin_restore requires Durable".into()),
    }
}

/// Restoring → Restored. Allowed immediately; expiry is `restore_until_unix`.
pub fn complete_restore(state: ColdArchiveState, now: i64) -> Result<ColdArchiveState, String> {
    match state {
        ColdArchiveState::Restoring {
            restore_until_unix, ..
        } => {
            let _ = now;
            Ok(ColdArchiveState::Restored { restore_until_unix })
        }
        _ => Err("complete_restore requires Restoring".into()),
    }
}

/// Restored before `restore_until` must not rearchive. After expiry the state
/// may return to Durable **metadata only** (no new payload write).
///
/// `delete_hot_enabled` is a required explicit argument and defaults conceptually
/// to [`COLD_DELETE_HOT_AFTER_ARCHIVE_DEFAULT`] (`false`). This function never
/// assumes it is true and never deletes hot bytes.
pub fn maybe_rearchive(
    state: ColdArchiveState,
    now: i64,
    delete_hot_enabled: bool,
) -> Result<ColdArchiveState, String> {
    let _ = delete_hot_enabled;
    match state {
        ColdArchiveState::Restored { restore_until_unix } if now < restore_until_unix => Ok(state),
        ColdArchiveState::Restoring { .. } => Ok(state),
        ColdArchiveState::Restored { .. } => Ok(ColdArchiveState::Durable),
        other => Ok(other),
    }
}

/// Hot reclamation is allowed only when every gate is true:
/// `delete_hot_enabled` (passed in, never assumed), state is Durable (not
/// Restoring/Restored), the receipt verifies `body`, and the body is not a
/// range/206.
pub fn hot_reclamation_allowed(
    state: ColdArchiveState,
    receipt: Option<&ColdArchiveReceipt>,
    body: &[u8],
    delete_hot_enabled: bool,
    is_range_or_206: bool,
) -> bool {
    if !delete_hot_enabled || is_range_or_206 || state.is_restore_window() {
        return false;
    }
    state == ColdArchiveState::Durable
        && receipt.is_some_and(|receipt| receipt.verifies_payload(body))
}

/// Maps S3 storage class names → Swift storage policy indices.
#[derive(Debug, Clone, Default)]
pub struct ColdPolicyMap {
    /// Uppercase class → policy index.
    pub class_to_policy: HashMap<String, i64>,
    /// Default cold policy when class unmapped but still cold (optional).
    pub default_cold_policy: Option<i64>,
    /// Hot/default policy for restore target.
    pub default_hot_policy: i64,
}

impl ColdPolicyMap {
    pub fn new() -> Self {
        Self {
            class_to_policy: HashMap::new(),
            default_cold_policy: None,
            default_hot_policy: 0,
        }
    }

    /// Parse conf: `GLACIER:2,DEEP_ARCHIVE:3` plus optional defaults.
    pub fn from_csv(csv: &str) -> Self {
        let mut m = Self::new();
        for part in csv.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if let Some((k, v)) = part.split_once(':') {
                let k = k.trim().to_ascii_uppercase();
                if let Ok(idx) = v.trim().parse::<i64>() {
                    if k == "DEFAULT" || k == "*" {
                        m.default_cold_policy = Some(idx);
                    } else if k == "HOT" || k == "STANDARD" {
                        m.default_hot_policy = idx;
                    } else {
                        m.class_to_policy.insert(k, idx);
                    }
                }
            }
        }
        m
    }

    pub fn policy_for_class(&self, storage_class: &str) -> Option<i64> {
        let key = storage_class.trim().to_ascii_uppercase();
        self.class_to_policy
            .get(&key)
            .copied()
            .or(self.default_cold_policy)
    }

    pub fn is_configured(&self) -> bool {
        !self.class_to_policy.is_empty() || self.default_cold_policy.is_some()
    }
}

/// Cold transition result. Policy-only calls carry no proof; archive calls may
/// attach a [`ColdArchiveReceipt`] verified for the exact payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColdMetaStamp {
    pub storage_class: String,
    pub cold_policy_index: i64,
    pub hot_policy_index: i64,
    pub backend_uri: String,
    /// Durable backend receipt for the exact archived payload, when proven.
    pub archive_receipt: Option<ColdArchiveReceipt>,
    /// Explicitly distinguishes policy-only or legacy URI stamps from a
    /// durable archive commit.
    pub archive_state: ColdArchiveState,
}

impl ColdMetaStamp {
    /// Hot bytes may be reclaimed only for the same payload that produced a
    /// durable archive receipt in this transition.
    pub fn hot_reclamation_safe_for(&self, body: &[u8]) -> bool {
        self.archive_state == ColdArchiveState::Durable
            && self
                .archive_receipt
                .as_ref()
                .is_some_and(|receipt| receipt.verifies_payload(body))
    }
}

fn receipt_from_headers(headers: &HeaderKeyDict) -> Option<ColdArchiveReceipt> {
    if headers.get(SYS_COLD_ARCHIVE_STATE)? != COLD_ARCHIVE_DURABLE {
        return None;
    }
    let backend_uri = headers.get(SYS_COLD_BACKEND_URI)?.to_string();
    let content_length = headers.get(SYS_COLD_CONTENT_LENGTH)?.parse().ok()?;
    let content_sha256 = headers.get(SYS_COLD_CONTENT_SHA256)?.to_string();
    if backend_uri.is_empty()
        || content_sha256.len() != 64
        || !content_sha256.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return None;
    }
    Some(ColdArchiveReceipt {
        backend_uri,
        content_length,
        content_sha256: content_sha256.to_ascii_lowercase(),
        // Persisted sysmeta is evidence to re-check, not current proof that
        // the referenced backend bytes are still present and intact.
        state: ColdArchiveState::UnverifiedReference,
    })
}

#[deprecated(note = "renamed to ColdMetaStamp — meta stamp only, not physical media move")]
pub type PhysicalTransition = ColdMetaStamp;

/// Stamp cold-transition **metadata** when a policy map is configured.
///
/// Sets [`SYS_TRANSITIONED`], cold/hot policy indices, and
/// `X-Backend-Storage-Policy-Index`. Does **not** set [`SYS_COLD_BACKEND_URI`]
/// (that requires [`ColdBackend::archive_durable`] — see
/// [`maybe_stamp_and_archive_due_cold`]). Without a backend this is meta-only
/// honesty. Returns `None` if class is not cold or no policy mapping exists.
pub fn stamp_cold_policy_meta(
    headers: &mut HeaderKeyDict,
    map: &ColdPolicyMap,
    storage_class: &str,
    hot_policy_index: Option<i64>,
    _object_account: &str,
    _object_container: &str,
    _object_key: &str,
) -> Option<ColdMetaStamp> {
    if !is_cold_storage_class(storage_class) {
        return None;
    }
    let cold = map.policy_for_class(storage_class)?;
    let hot = hot_policy_index.unwrap_or(map.default_hot_policy);
    headers.set(META_STORAGE_CLASS, storage_class);
    headers.set(SYS_TRANSITIONED, "1");
    headers.set(SYS_COLD_POLICY_INDEX, cold.to_string());
    headers.set(SYS_HOT_POLICY_INDEX, hot.to_string());
    headers.set(HDR_BACKEND_STORAGE_POLICY_INDEX, cold.to_string());
    // Preserve any URI already set (e.g. prior archive); never invent one.
    let backend_uri = headers.get(SYS_COLD_BACKEND_URI).unwrap_or("").to_string();
    let archive_receipt = receipt_from_headers(headers);
    let archive_state = if backend_uri.is_empty() {
        ColdArchiveState::MetadataOnly
    } else {
        ColdArchiveState::UnverifiedReference
    };
    Some(ColdMetaStamp {
        storage_class: storage_class.to_string(),
        cold_policy_index: cold,
        hot_policy_index: hot,
        backend_uri,
        archive_receipt,
        archive_state,
    })
}

/// If transition is due and a policy map is configured, prepare **meta** stamps only.
pub fn maybe_stamp_due_cold_transition(
    headers: &mut HeaderKeyDict,
    map: &ColdPolicyMap,
    now_unix: i64,
    account: &str,
    container: &str,
    key: &str,
) -> Option<ColdMetaStamp> {
    if !map.is_configured() {
        return None;
    }
    let sc = headers
        .get(META_STORAGE_CLASS)
        .or_else(|| headers.get("X-Object-Meta-Storage-Class"))?
        .to_string();
    if !is_cold_storage_class(&sc) {
        return None;
    }
    // Due?
    let due = if let Some(at_s) = headers.get(SYS_TRANSITION_AT) {
        at_s.parse::<i64>()
            .ok()
            .map(|at| at <= now_unix)
            .unwrap_or(false)
    } else {
        headers.get(SYS_TRANSITIONED).is_some()
    };
    if !due && headers.get(SYS_TRANSITIONED).is_none() {
        return None;
    }
    // Already physical?
    if headers.get(SYS_COLD_POLICY_INDEX).is_some() {
        let cold = headers.get(SYS_COLD_POLICY_INDEX)?.parse().ok()?;
        let hot = headers
            .get(SYS_HOT_POLICY_INDEX)
            .and_then(|s| s.parse().ok())
            .unwrap_or(map.default_hot_policy);
        let backend_uri = headers.get(SYS_COLD_BACKEND_URI).unwrap_or("").to_string();
        let archive_receipt = receipt_from_headers(headers);
        let archive_state = if backend_uri.is_empty() {
            ColdArchiveState::MetadataOnly
        } else {
            ColdArchiveState::UnverifiedReference
        };
        return Some(ColdMetaStamp {
            storage_class: sc,
            cold_policy_index: cold,
            hot_policy_index: hot,
            backend_uri,
            archive_receipt,
            archive_state,
        });
    }
    stamp_cold_policy_meta(headers, map, &sc, None, account, container, key)
}

/// Stamp due cold meta; when a lab [`ColdBackend`] + body are provided and
/// [`SYS_COLD_BACKEND_URI`] is empty, call [`ColdBackend::archive_durable`] and
/// stamp its URI, length, checksum and durable state. A recorded URI is
/// re-verified before its receipt is promoted for this invocation. Without a
/// backend, meta-only (no URI) — honest boundary.
///
/// Returns `Ok(None)` when no due cold transition applies. Archive errors
/// surface as `Err` (callers map to S3 errors; do not panic).
pub fn maybe_stamp_and_archive_due_cold(
    headers: &mut HeaderKeyDict,
    map: &ColdPolicyMap,
    now_unix: i64,
    account: &str,
    container: &str,
    key: &str,
    backend: Option<&dyn ColdBackend>,
    body: Option<&[u8]>,
) -> Result<Option<ColdMetaStamp>, String> {
    let Some(mut stamp) =
        maybe_stamp_due_cold_transition(headers, map, now_unix, account, container, key)
    else {
        return Ok(None);
    };
    if let (Some(be), Some(bytes)) = (backend, body) {
        let existing = headers.get(SYS_COLD_BACKEND_URI).unwrap_or("").to_string();
        let verified_existing = if existing.is_empty() {
            None
        } else {
            be.verify_archive(&existing)
                .ok()
                .filter(|receipt| receipt.verifies_payload(bytes))
        };
        let receipt = if let Some(receipt) = verified_existing {
            receipt
        } else {
            be.archive_durable(stamp.cold_policy_index, account, container, key, bytes)?
        };
        if archive_commit(&receipt, bytes, false).ok() != Some(ColdArchiveState::Durable) {
            return Err("cold backend returned a non-durable or mismatched archive receipt".into());
        }
        receipt.stamp_headers(headers);
        stamp.backend_uri = receipt.backend_uri.clone();
        stamp.archive_state = ColdArchiveState::Durable;
        stamp.archive_receipt = Some(receipt);
    }
    Ok(Some(stamp))
}

/// Apply restore **stamps**: set restore-until and optionally route GETs to hot
/// policy index during the window. Does not rehydrate bytes from cold media.
pub fn stamp_cold_restore_meta(
    headers: &mut HeaderKeyDict,
    map: &ColdPolicyMap,
    days: i64,
    now_unix: i64,
) {
    let until = now_unix.saturating_add(days.saturating_mul(SECONDS_PER_DAY).max(0));
    headers.set(SYS_RESTORE_UNTIL, until.to_string());
    let hot = headers
        .get(SYS_HOT_POLICY_INDEX)
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(map.default_hot_policy);
    // During restore window, serve from hot policy if rehydrated; operators
    // may async-copy. Stamp backend index to hot for GET routing.
    headers.set(HDR_BACKEND_STORAGE_POLICY_INDEX, hot.to_string());
}

/// Policy index the object server should use for a read.
///
/// Cold + not restored → cold policy (GET may still be blocked by
/// [`crate::lifecycle_exec::transition_blocks_get`]). Restored → hot.
pub fn read_policy_index(
    headers: &HeaderKeyDict,
    map: &ColdPolicyMap,
    now_unix: i64,
) -> Option<i64> {
    let cold = headers
        .get(SYS_COLD_POLICY_INDEX)
        .and_then(|s| s.parse().ok());
    let hot = headers
        .get(SYS_HOT_POLICY_INDEX)
        .and_then(|s| s.parse().ok())
        .unwrap_or(map.default_hot_policy);
    let restored = headers
        .get(SYS_RESTORE_UNTIL)
        .and_then(|s| s.parse::<i64>().ok())
        .map(|u| u > now_unix)
        .unwrap_or(false);
    if restored {
        Some(hot)
    } else {
        cold.or(Some(hot))
    }
}

/// Tape / glacier adapter trait (LAB product boundary).
pub trait ColdBackend: Send + Sync {
    /// Durably archive object bytes and return a verifiable receipt.
    ///
    /// Implementations must not return `Ok` until the payload and the backend
    /// reference needed to find it have been durably committed.
    fn archive_durable(
        &self,
        policy_index: i64,
        account: &str,
        container: &str,
        key: &str,
        body: &[u8],
    ) -> Result<ColdArchiveReceipt, String>;
    /// Compatibility helper for callers that only need a URI. New hot-delete
    /// paths must use [`ColdBackend::archive_durable`] and inspect its receipt.
    fn archive(
        &self,
        policy_index: i64,
        account: &str,
        container: &str,
        key: &str,
        body: &[u8],
    ) -> Result<String, String> {
        self.archive_durable(policy_index, account, container, key, body)
            .map(|receipt| receipt.backend_uri)
    }
    /// Fetch archived bytes and return them only after strict length and
    /// checksum validation. This is object-safe so middleware can perform a
    /// real rehydrate through `Arc<dyn ColdBackend>`.
    fn fetch_verified(&self, backend_uri: &str) -> Result<(Vec<u8>, ColdArchiveReceipt), String>;
    /// Re-read and validate an archive without retaining its payload.
    fn verify_archive(&self, backend_uri: &str) -> Result<ColdArchiveReceipt, String> {
        self.fetch_verified(backend_uri).map(|(_, receipt)| receipt)
    }
    /// Stage restore from cold media into hot policy path.
    fn restore_stage(&self, backend_uri: &str, _days: i64) -> Result<(), String> {
        self.verify_archive(backend_uri).map(|_| ())
    }
}

/// In-process lab backend: stores archived blobs in memory (tests / SAIO).
#[derive(Debug, Default)]
pub struct MemoryColdBackend {
    pub blobs: std::sync::Mutex<HashMap<String, Vec<u8>>>,
    receipts: std::sync::Mutex<HashMap<String, ColdArchiveReceipt>>,
}

impl ColdBackend for MemoryColdBackend {
    fn archive_durable(
        &self,
        policy_index: i64,
        account: &str,
        container: &str,
        key: &str,
        body: &[u8],
    ) -> Result<ColdArchiveReceipt, String> {
        let digest = sha256_hex(body);
        let uri = format!("memory://{policy_index}/{account}/{container}/{key}/{digest}");
        let receipt = ColdArchiveReceipt::durable(uri.clone(), body)?;
        self.blobs
            .lock()
            .map_err(|e| e.to_string())?
            .insert(uri.clone(), body.to_vec());
        self.receipts
            .lock()
            .map_err(|e| e.to_string())?
            .insert(uri, receipt.clone());
        Ok(receipt)
    }

    fn fetch_verified(&self, backend_uri: &str) -> Result<(Vec<u8>, ColdArchiveReceipt), String> {
        let guard = self.blobs.lock().map_err(|e| e.to_string())?;
        let body = guard
            .get(backend_uri)
            .ok_or_else(|| format!("unknown backend uri {backend_uri}"))?;
        let receipts = self.receipts.lock().map_err(|e| e.to_string())?;
        let receipt = receipts
            .get(backend_uri)
            .ok_or_else(|| format!("archive receipt missing for {backend_uri}"))?;
        if !receipt.verifies_payload(body) {
            return Err(format!("cold payload integrity mismatch for {backend_uri}"));
        }
        Ok((body.clone(), receipt.clone()))
    }
}

/// Local directory cold backend — archives object bytes under `root/`.
///
/// **Honesty:** [`LocalDirColdBackend`] is **proxy-local** lab storage. It is
/// not Glacier, not shared durable media, and not a production cold backend.
/// A node-local directory is not a tape replacement and must not be treated
/// as cluster-shared durability.
///
/// URI form:
/// `filecold://v2/{policy}/{identity-shard}/{identity-sha256}/{payload-sha256}.cold`
///
/// The fixed-length identity digest is domain-separated over the exact policy,
/// account, container and UTF-8 key (including their lengths). The envelope
/// also carries those exact identity fields and digest, so moving a valid blob
/// to another URI fails closed. This keeps every path component below common
/// `NAME_MAX` limits even for long or Unicode object keys, while the receipt's
/// URI remains bound to the complete object identity and payload.
#[derive(Debug, Clone)]
pub struct LocalDirColdBackend {
    pub root: PathBuf,
}

impl LocalDirColdBackend {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, String> {
        let root = root.into();
        std::fs::create_dir_all(&root).map_err(|e| format!("cold root mkdir: {e}"))?;
        Ok(Self { root })
    }

    fn path_for_uri(&self, backend_uri: &str) -> Result<PathBuf, String> {
        Self::parse_archive_address(backend_uri)?;
        let rest = backend_uri
            .strip_prefix("filecold://")
            .ok_or_else(|| format!("not a filecold uri: {backend_uri}"))?;
        // Reject absolute, empty, dot, backslash and traversal components.
        if rest.is_empty()
            || rest.starts_with('/')
            || rest.contains('\\')
            || rest
                .split('/')
                .any(|component| component.is_empty() || component == "." || component == "..")
            || Path::new(rest)
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            return Err("invalid filecold uri path".into());
        }
        Ok(self.root.join(rest))
    }

    fn is_lower_hex_digest(value: &str) -> bool {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }

    fn parse_archive_address(backend_uri: &str) -> Result<(i64, &str, &str), String> {
        let rest = backend_uri
            .strip_prefix("filecold://")
            .ok_or_else(|| format!("not a filecold uri: {backend_uri}"))?;
        let mut components = rest.split('/');
        let version = components.next().unwrap_or_default();
        let policy_component = components.next().unwrap_or_default();
        let identity_shard = components.next().unwrap_or_default();
        let identity_sha256 = components.next().unwrap_or_default();
        let payload_file = components.next().unwrap_or_default();
        if version != "v2" || components.next().is_some() {
            return Err("invalid filecold v2 uri layout".into());
        }
        let policy_index = policy_component
            .parse::<i64>()
            .map_err(|_| "invalid filecold policy index".to_string())?;
        if policy_component != policy_index.to_string() {
            return Err("non-canonical filecold policy index".into());
        }
        if !Self::is_lower_hex_digest(identity_sha256)
            || identity_shard.len() != 2
            || identity_shard != &identity_sha256[..2]
        {
            return Err("invalid filecold identity digest".into());
        }
        let payload_sha256 = payload_file
            .strip_suffix(".cold")
            .ok_or_else(|| "invalid filecold payload filename".to_string())?;
        if !Self::is_lower_hex_digest(payload_sha256) {
            return Err("invalid filecold payload digest".into());
        }
        Ok((policy_index, identity_sha256, payload_sha256))
    }

    fn identity_digest(
        policy_index: i64,
        account: &[u8],
        container: &[u8],
        key: &[u8],
    ) -> Result<[u8; 32], String> {
        let account_length = u64::try_from(account.len())
            .map_err(|_| "cold archive account length exceeds u64".to_string())?;
        let container_length = u64::try_from(container.len())
            .map_err(|_| "cold archive container length exceeds u64".to_string())?;
        let key_length = u64::try_from(key.len())
            .map_err(|_| "cold archive key length exceeds u64".to_string())?;
        let capacity = LOCAL_ARCHIVE_IDENTITY_DOMAIN
            .len()
            .checked_add(8 + 8 + 8 + 8)
            .and_then(|length| length.checked_add(account.len()))
            .and_then(|length| length.checked_add(container.len()))
            .and_then(|length| length.checked_add(key.len()))
            .ok_or_else(|| "cold archive identity length overflow".to_string())?;
        let mut encoded = Vec::with_capacity(capacity);
        encoded.extend_from_slice(LOCAL_ARCHIVE_IDENTITY_DOMAIN);
        encoded.extend_from_slice(&policy_index.to_be_bytes());
        encoded.extend_from_slice(&account_length.to_be_bytes());
        encoded.extend_from_slice(account);
        encoded.extend_from_slice(&container_length.to_be_bytes());
        encoded.extend_from_slice(container);
        encoded.extend_from_slice(&key_length.to_be_bytes());
        encoded.extend_from_slice(key);
        Ok(sha256(&encoded))
    }

    fn archive_location(
        &self,
        policy_index: i64,
        account: &str,
        container: &str,
        key: &str,
        body: &[u8],
    ) -> Result<(String, PathBuf, ColdArchiveReceipt), String> {
        let content_length = u64::try_from(body.len())
            .map_err(|_| "cold archive payload length exceeds u64".to_string())?;
        let payload_digest = sha256_hex(body);
        let identity_digest = hex_encode(&Self::identity_digest(
            policy_index,
            account.as_bytes(),
            container.as_bytes(),
            key.as_bytes(),
        )?);
        let rel = format!(
            "v2/{}/{}/{}/{}.cold",
            policy_index,
            &identity_digest[..2],
            identity_digest,
            payload_digest,
        );
        let backend_uri = format!("filecold://{rel}");
        let path = self.root.join(&rel);
        let receipt = ColdArchiveReceipt {
            backend_uri: backend_uri.clone(),
            content_length,
            content_sha256: payload_digest,
            state: ColdArchiveState::Durable,
        };
        Ok((backend_uri, path, receipt))
    }

    fn create_same_dir_temp(path: &Path) -> Result<(PathBuf, File), String> {
        let parent = path
            .parent()
            .ok_or_else(|| "cold archive path has no parent".to_string())?;
        let final_name = path
            .file_name()
            .ok_or_else(|| "cold archive path has no file name".to_string())?
            .to_string_lossy();
        for _ in 0..128 {
            let sequence = LOCAL_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let temp_path = parent.join(format!(
                ".{final_name}.tmp.{}.{}",
                std::process::id(),
                sequence
            ));
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            options.mode(0o600);
            match options.open(&temp_path) {
                Ok(file) => return Ok((temp_path, file)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(format!("cold temp create: {error}")),
            }
        }
        Err("cold temp create: exhausted unique names".into())
    }

    #[cfg(unix)]
    fn ensure_private_permissions(path: &Path) -> Result<(), String> {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("cold chmod 0600: {error}"))
    }

    #[cfg(not(unix))]
    fn ensure_private_permissions(_path: &Path) -> Result<(), String> {
        Err("LocalDirColdBackend requires Unix file permissions".into())
    }

    fn sync_archive_path(&self, path: &Path) -> Result<(), String> {
        File::open(path)
            .and_then(|file| file.sync_all())
            .map_err(|error| format!("cold file sync: {error}"))?;
        let mut current = path.parent();
        let mut synced_root = false;
        while let Some(directory_path) = current {
            if directory_path.as_os_str().is_empty() {
                break;
            }
            File::open(directory_path)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| {
                    format!("cold directory sync {}: {error}", directory_path.display())
                })?;
            if directory_path == self.root {
                synced_root = true;
                break;
            }
            current = directory_path.parent();
        }
        if synced_root {
            Ok(())
        } else {
            Err("cold archive path escaped configured root".into())
        }
    }

    fn write_atomic_archive(
        &self,
        path: &Path,
        policy_index: i64,
        account: &str,
        container: &str,
        key: &str,
        body: &[u8],
    ) -> Result<(), String> {
        let parent = path
            .parent()
            .ok_or_else(|| "cold archive path has no parent".to_string())?;
        std::fs::create_dir_all(parent).map_err(|error| format!("cold mkdir: {error}"))?;
        let account_length = u64::try_from(account.len())
            .map_err(|_| "cold archive account length exceeds u64".to_string())?;
        let container_length = u64::try_from(container.len())
            .map_err(|_| "cold archive container length exceeds u64".to_string())?;
        let key_length = u64::try_from(key.len())
            .map_err(|_| "cold archive key length exceeds u64".to_string())?;
        let content_length = u64::try_from(body.len())
            .map_err(|_| "cold archive payload length exceeds u64".to_string())?;
        let identity_digest = Self::identity_digest(
            policy_index,
            account.as_bytes(),
            container.as_bytes(),
            key.as_bytes(),
        )?;
        let payload_digest = sha256(body);
        let (temp_path, mut temp_file) = Self::create_same_dir_temp(path)?;
        let write_result = (|| {
            temp_file
                .write_all(LOCAL_ARCHIVE_MAGIC)
                .map_err(|error| format!("cold header write: {error}"))?;
            temp_file
                .write_all(&policy_index.to_be_bytes())
                .map_err(|error| format!("cold policy write: {error}"))?;
            temp_file
                .write_all(&account_length.to_be_bytes())
                .map_err(|error| format!("cold account length write: {error}"))?;
            temp_file
                .write_all(&container_length.to_be_bytes())
                .map_err(|error| format!("cold container length write: {error}"))?;
            temp_file
                .write_all(&key_length.to_be_bytes())
                .map_err(|error| format!("cold key length write: {error}"))?;
            temp_file
                .write_all(&content_length.to_be_bytes())
                .map_err(|error| format!("cold payload length write: {error}"))?;
            temp_file
                .write_all(&identity_digest)
                .map_err(|error| format!("cold identity digest write: {error}"))?;
            temp_file
                .write_all(&payload_digest)
                .map_err(|error| format!("cold payload digest write: {error}"))?;
            temp_file
                .write_all(account.as_bytes())
                .map_err(|error| format!("cold account write: {error}"))?;
            temp_file
                .write_all(container.as_bytes())
                .map_err(|error| format!("cold container write: {error}"))?;
            temp_file
                .write_all(key.as_bytes())
                .map_err(|error| format!("cold key write: {error}"))?;
            temp_file
                .write_all(body)
                .map_err(|error| format!("cold payload write: {error}"))?;
            temp_file
                .sync_all()
                .map_err(|error| format!("cold temp sync: {error}"))?;
            drop(temp_file);
            std::fs::rename(&temp_path, path)
                .map_err(|error| format!("cold atomic rename: {error}"))?;
            Self::ensure_private_permissions(path)?;
            self.sync_archive_path(path)
        })();
        if write_result.is_err() {
            let _ = std::fs::remove_file(&temp_path);
        }
        write_result
    }

    fn decode_archive(
        backend_uri: &str,
        encoded: &[u8],
    ) -> Result<(Vec<u8>, ColdArchiveReceipt), String> {
        let (uri_policy_index, uri_identity_sha256, uri_payload_sha256) =
            Self::parse_archive_address(backend_uri)?;
        if encoded.len() < LOCAL_ARCHIVE_FIXED_HEADER_LEN {
            return Err(format!("cold archive truncated: {backend_uri}"));
        }
        if &encoded[..LOCAL_ARCHIVE_MAGIC.len()] != LOCAL_ARCHIVE_MAGIC {
            return Err(format!("cold archive magic mismatch: {backend_uri}"));
        }
        let mut cursor = LOCAL_ARCHIVE_MAGIC.len();
        let mut read_u64 = |field: &str| -> Result<u64, String> {
            let end = cursor
                .checked_add(8)
                .ok_or_else(|| format!("cold archive {field} offset overflow: {backend_uri}"))?;
            let bytes: [u8; 8] = encoded
                .get(cursor..end)
                .ok_or_else(|| format!("cold archive {field} header invalid: {backend_uri}"))?
                .try_into()
                .map_err(|_| format!("cold archive {field} header invalid: {backend_uri}"))?;
            cursor = end;
            Ok(u64::from_be_bytes(bytes))
        };
        let stored_policy_bits = read_u64("policy")?;
        let stored_policy_index = i64::from_be_bytes(stored_policy_bits.to_be_bytes());
        let account_length = usize::try_from(read_u64("account length")?)
            .map_err(|_| format!("cold archive account length unsupported: {backend_uri}"))?;
        let container_length = usize::try_from(read_u64("container length")?)
            .map_err(|_| format!("cold archive container length unsupported: {backend_uri}"))?;
        let key_length = usize::try_from(read_u64("key length")?)
            .map_err(|_| format!("cold archive key length unsupported: {backend_uri}"))?;
        let declared_length = read_u64("payload length")?;
        let payload_length = usize::try_from(declared_length)
            .map_err(|_| format!("cold archive length unsupported: {backend_uri}"))?;
        if stored_policy_index != uri_policy_index {
            return Err(format!(
                "cold archive policy identity mismatch: {backend_uri}"
            ));
        }
        let identity_digest_end = cursor
            .checked_add(32)
            .ok_or_else(|| format!("cold archive identity digest overflow: {backend_uri}"))?;
        let stored_identity_digest = encoded
            .get(cursor..identity_digest_end)
            .ok_or_else(|| format!("cold archive identity digest truncated: {backend_uri}"))?;
        cursor = identity_digest_end;
        let payload_digest_end = cursor
            .checked_add(32)
            .ok_or_else(|| format!("cold archive payload digest overflow: {backend_uri}"))?;
        let stored_payload_digest = encoded
            .get(cursor..payload_digest_end)
            .ok_or_else(|| format!("cold archive payload digest truncated: {backend_uri}"))?;
        cursor = payload_digest_end;
        debug_assert_eq!(cursor, LOCAL_ARCHIVE_FIXED_HEADER_LEN);

        let account_end = cursor
            .checked_add(account_length)
            .ok_or_else(|| format!("cold archive account length overflow: {backend_uri}"))?;
        let container_end = account_end
            .checked_add(container_length)
            .ok_or_else(|| format!("cold archive container length overflow: {backend_uri}"))?;
        let key_end = container_end
            .checked_add(key_length)
            .ok_or_else(|| format!("cold archive key length overflow: {backend_uri}"))?;
        let expected_total = key_end
            .checked_add(payload_length)
            .ok_or_else(|| format!("cold archive length overflow: {backend_uri}"))?;
        if encoded.len() != expected_total {
            return Err(format!(
                "cold archive length mismatch: {backend_uri} declared={declared_length} actual={}",
                encoded.len().saturating_sub(key_end)
            ));
        }
        let account = encoded
            .get(cursor..account_end)
            .ok_or_else(|| format!("cold archive account truncated: {backend_uri}"))?;
        let container = encoded
            .get(account_end..container_end)
            .ok_or_else(|| format!("cold archive container truncated: {backend_uri}"))?;
        let key = encoded
            .get(container_end..key_end)
            .ok_or_else(|| format!("cold archive key truncated: {backend_uri}"))?;
        std::str::from_utf8(account)
            .map_err(|_| format!("cold archive account is not UTF-8: {backend_uri}"))?;
        std::str::from_utf8(container)
            .map_err(|_| format!("cold archive container is not UTF-8: {backend_uri}"))?;
        std::str::from_utf8(key)
            .map_err(|_| format!("cold archive key is not UTF-8: {backend_uri}"))?;
        let computed_identity_digest =
            Self::identity_digest(stored_policy_index, account, container, key)?;
        let computed_identity_sha256 = hex_encode(&computed_identity_digest);
        if stored_identity_digest != computed_identity_digest.as_slice()
            || uri_identity_sha256 != computed_identity_sha256.as_str()
        {
            return Err(format!(
                "cold archive object identity mismatch: {backend_uri}"
            ));
        }

        let payload = &encoded[key_end..];
        let computed_payload_digest = sha256(payload);
        let computed_payload_sha256 = hex_encode(&computed_payload_digest);
        if stored_payload_digest != computed_payload_digest.as_slice()
            || uri_payload_sha256 != computed_payload_sha256.as_str()
        {
            return Err(format!("cold archive checksum mismatch: {backend_uri}"));
        }
        let receipt = ColdArchiveReceipt {
            backend_uri: backend_uri.to_string(),
            content_length: declared_length,
            content_sha256: computed_payload_sha256,
            state: ColdArchiveState::Durable,
        };
        Ok((payload.to_vec(), receipt))
    }

    fn read_verified(&self, backend_uri: &str) -> Result<(Vec<u8>, ColdArchiveReceipt), String> {
        let path = self.path_for_uri(backend_uri)?;
        let encoded = std::fs::read(&path).map_err(|error| format!("cold read: {error}"))?;
        Self::decode_archive(backend_uri, &encoded)
    }

    /// Read archived bytes back after verifying the self-contained length and
    /// SHA-256 record. Legacy raw files and corrupted envelopes are rejected.
    pub fn fetch(&self, backend_uri: &str) -> Result<Vec<u8>, String> {
        self.read_verified(backend_uri).map(|(body, _)| body)
    }

    /// Fetch and additionally require an exact match to a caller-held receipt.
    pub fn fetch_with_receipt(&self, expected: &ColdArchiveReceipt) -> Result<Vec<u8>, String> {
        let (body, actual) = self.read_verified(&expected.backend_uri)?;
        if !actual.same_archive_identity(expected) || !actual.verifies_payload(&body) {
            return Err(format!(
                "cold archive receipt mismatch: {}",
                expected.backend_uri
            ));
        }
        Ok(body)
    }
}

impl ColdBackend for LocalDirColdBackend {
    fn archive_durable(
        &self,
        policy_index: i64,
        account: &str,
        container: &str,
        key: &str,
        body: &[u8],
    ) -> Result<ColdArchiveReceipt, String> {
        let (backend_uri, path, expected) =
            self.archive_location(policy_index, account, container, key, body)?;
        let existing_is_valid = self.read_verified(&backend_uri).ok().is_some_and(
            |(existing_body, existing_receipt)| {
                existing_receipt == expected && expected.verifies_payload(&existing_body)
            },
        );
        if existing_is_valid {
            Self::ensure_private_permissions(&path)?;
            self.sync_archive_path(&path)?;
            return Ok(expected);
        }
        self.write_atomic_archive(&path, policy_index, account, container, key, body)?;
        let (_, committed_receipt) = self.read_verified(&backend_uri)?;
        if committed_receipt != expected {
            return Err(format!(
                "cold archive post-commit verification failed: {backend_uri}"
            ));
        }
        Ok(committed_receipt)
    }

    fn fetch_verified(&self, backend_uri: &str) -> Result<(Vec<u8>, ColdArchiveReceipt), String> {
        self.read_verified(backend_uri)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_dir(name: &str) -> PathBuf {
        let sequence = LOCAL_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "peregrine-cold-{name}-{}-{sequence}",
            std::process::id()
        ))
    }

    #[test]
    fn csv_map_and_cold_meta_stamp() {
        let map = ColdPolicyMap::from_csv("GLACIER:2,DEEP_ARCHIVE:3,HOT:0");
        assert_eq!(map.policy_for_class("glacier"), Some(2));
        assert_eq!(map.default_hot_policy, 0);
        let mut h = HeaderKeyDict::new();
        let t = stamp_cold_policy_meta(
            &mut h,
            &map,
            "GLACIER",
            Some(0),
            "AUTH_test",
            "bucket",
            "obj",
        )
        .unwrap();
        assert_eq!(t.cold_policy_index, 2);
        assert_eq!(h.get(SYS_TRANSITIONED), Some("1"));
        assert_eq!(h.get(SYS_COLD_POLICY_INDEX), Some("2"));
        assert_eq!(h.get(HDR_BACKEND_STORAGE_POLICY_INDEX), Some("2"));
        assert_eq!(t.archive_state, ColdArchiveState::MetadataOnly);
        assert!(t.archive_receipt.is_none());
        assert!(!t.hot_reclamation_safe_for(b"payload"));
    }

    #[test]
    fn restore_routes_to_hot() {
        let map = ColdPolicyMap::from_csv("GLACIER:2,HOT:0");
        let mut h = HeaderKeyDict::new();
        stamp_cold_policy_meta(&mut h, &map, "GLACIER", Some(0), "a", "c", "k").unwrap();
        stamp_cold_restore_meta(&mut h, &map, 1, 1000);
        assert_eq!(read_policy_index(&h, &map, 1000), Some(0));
        assert_eq!(read_policy_index(&h, &map, 1000 + 86_400 + 1), Some(2));
    }

    #[test]
    fn memory_backend_archive_restore() {
        let be = MemoryColdBackend::default();
        let receipt = be.archive_durable(2, "a", "c", "k", b"payload").unwrap();
        assert!(receipt.backend_uri.starts_with("memory://"));
        assert_eq!(receipt.content_length, 7);
        assert!(receipt.verifies_payload(b"payload"));
        assert_eq!(be.verify_archive(&receipt.backend_uri).unwrap(), receipt);
        let (restored, verified) = be.fetch_verified(&receipt.backend_uri).unwrap();
        assert_eq!(restored, b"payload");
        assert_eq!(verified, receipt);
        be.restore_stage(&receipt.backend_uri, 1).unwrap();
        assert!(be.restore_stage("memory://missing", 1).is_err());
    }

    #[test]
    fn memory_backend_restore_rejects_corruption() {
        let be = MemoryColdBackend::default();
        let receipt = be.archive_durable(2, "a", "c", "k", b"payload").unwrap();
        be.blobs
            .lock()
            .unwrap()
            .insert(receipt.backend_uri.clone(), b"tampered".to_vec());
        assert!(be.fetch_verified(&receipt.backend_uri).is_err());
        assert!(be.restore_stage(&receipt.backend_uri, 1).is_err());
    }

    #[test]
    fn localdir_backend_archive_is_private_atomic_and_verifiable() {
        let dir = test_dir("archive");
        let be = LocalDirColdBackend::new(&dir).unwrap();
        let receipt = be
            .archive_durable(2, "AUTH_test", "bkt", "dir/obj", b"payload")
            .unwrap();
        assert!(receipt.backend_uri.starts_with("filecold://"));
        assert_eq!(receipt.content_length, 7);
        assert!(receipt.verifies_payload(b"payload"));
        be.restore_stage(&receipt.backend_uri, 1).unwrap();
        assert_eq!(be.fetch(&receipt.backend_uri).unwrap(), b"payload");
        assert_eq!(be.fetch_with_receipt(&receipt).unwrap(), b"payload");
        assert_eq!(be.verify_archive(&receipt.backend_uri).unwrap(), receipt);
        let (restored, verified) = be.fetch_verified(&receipt.backend_uri).unwrap();
        assert_eq!(restored, b"payload");
        assert_eq!(verified, receipt);

        let path = be.path_for_uri(&receipt.backend_uri).unwrap();
        assert!(path.is_file());
        let encoded = std::fs::read(&path).unwrap();
        assert!(encoded.starts_with(LOCAL_ARCHIVE_MAGIC));
        assert_eq!(
            encoded.len(),
            LOCAL_ARCHIVE_FIXED_HEADER_LEN + "AUTH_test".len() + "bkt".len() + "dir/obj".len() + 7
        );
        let parent_entries = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(
            parent_entries.iter().all(|name| !name.contains(".tmp.")),
            "temporary archive was not cleaned up: {parent_entries:?}"
        );
        #[cfg(unix)]
        {
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        assert!(be
            .restore_stage("filecold://2/AUTH_test/bkt/dead", 1)
            .is_err());
        assert!(be.fetch("filecold://../escape").is_err());
        assert!(be.fetch("filecold:///absolute").is_err());
        assert!(be.fetch("filecold://2\\escape").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn localdir_fetch_and_restore_reject_corruption_then_archive_repairs_it() {
        let dir = test_dir("corrupt");
        let be = LocalDirColdBackend::new(&dir).unwrap();
        let receipt = be
            .archive_durable(2, "AUTH_test", "bkt", "obj", b"payload")
            .unwrap();
        let path = be.path_for_uri(&receipt.backend_uri).unwrap();
        let mut encoded = std::fs::read(&path).unwrap();
        *encoded.last_mut().unwrap() ^= 0x01;
        std::fs::write(&path, encoded).unwrap();
        assert!(be.fetch(&receipt.backend_uri).is_err());
        assert!(be.fetch_verified(&receipt.backend_uri).is_err());
        assert!(be.restore_stage(&receipt.backend_uri, 1).is_err());

        let repaired = be
            .archive_durable(2, "AUTH_test", "bkt", "obj", b"payload")
            .unwrap();
        assert_eq!(repaired, receipt);
        assert_eq!(be.fetch_with_receipt(&receipt).unwrap(), b"payload");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn localdir_same_key_versions_have_distinct_content_addressed_uris() {
        let dir = test_dir("versions");
        let be = LocalDirColdBackend::new(&dir).unwrap();
        let first = be
            .archive_durable(2, "AUTH_test", "bkt", "obj", b"version-one")
            .unwrap();
        let second = be
            .archive_durable(2, "AUTH_test", "bkt", "obj", b"version-two")
            .unwrap();
        assert_ne!(first.backend_uri, second.backend_uri);
        assert_eq!(be.fetch_with_receipt(&first).unwrap(), b"version-one");
        assert_eq!(be.fetch_with_receipt(&second).unwrap(), b"version-two");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn localdir_long_and_unicode_keys_use_fixed_length_safe_paths() {
        let dir = test_dir("long-keys");
        let be = LocalDirColdBackend::new(&dir).unwrap();
        let keys = [
            "k".repeat(127),
            "k".repeat(128),
            "k".repeat(1024),
            "对象/层级/🚀/данные/ملف".repeat(32),
        ];
        assert_eq!(keys[0].as_bytes().len(), 127);
        assert_eq!(keys[1].as_bytes().len(), 128);
        assert_eq!(keys[2].as_bytes().len(), 1024);

        let mut uris = Vec::new();
        for key in &keys {
            let receipt = be
                .archive_durable(2, "AUTH_test", "bucket", key, b"same payload")
                .unwrap();
            assert!(receipt.backend_uri.len() < 192, "{}", receipt.backend_uri);
            let relative = receipt.backend_uri.strip_prefix("filecold://").unwrap();
            assert!(
                relative
                    .split('/')
                    .all(|component| !component.is_empty() && component.len() <= 69),
                "unsafe path component in {relative}"
            );
            assert_eq!(be.fetch_with_receipt(&receipt).unwrap(), b"same payload");
            uris.push(receipt.backend_uri);
        }
        for (index, uri) in uris.iter().enumerate() {
            assert!(uris[..index].iter().all(|prior| prior != uri));
        }
        assert!(uris
            .iter()
            .map(String::len)
            .all(|length| length == uris[0].len()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn localdir_envelope_and_receipt_reject_object_identity_mismatch_and_tamper() {
        let dir = test_dir("identity");
        let be = LocalDirColdBackend::new(&dir).unwrap();
        let source = be
            .archive_durable(2, "AUTH_source", "bucket", "key", b"payload")
            .unwrap();
        let source_path = be.path_for_uri(&source.backend_uri).unwrap();
        let source_envelope = std::fs::read(&source_path).unwrap();

        let mismatched_identities = [
            ("AUTH_other", "bucket", "key"),
            ("AUTH_source", "other-bucket", "key"),
            ("AUTH_source", "bucket", "other-key"),
        ];
        for (account, container, key) in mismatched_identities {
            let target = be
                .archive_durable(2, account, container, key, b"payload")
                .unwrap();
            assert_ne!(source.backend_uri, target.backend_uri);
            let target_path = be.path_for_uri(&target.backend_uri).unwrap();
            std::fs::write(&target_path, &source_envelope).unwrap();
            let error = be.fetch_verified(&target.backend_uri).unwrap_err();
            assert!(error.contains("identity mismatch"), "{error}");
        }

        let mut tampered_identity = source_envelope.clone();
        tampered_identity[LOCAL_ARCHIVE_FIXED_HEADER_LEN] ^= 0x01;
        std::fs::write(&source_path, &tampered_identity).unwrap();
        let error = be.fetch_with_receipt(&source).unwrap_err();
        assert!(error.contains("identity mismatch"), "{error}");

        let repaired = be
            .archive_durable(2, "AUTH_source", "bucket", "key", b"payload")
            .unwrap();
        assert_eq!(repaired, source);
        let mut tampered_digest = std::fs::read(&source_path).unwrap();
        let identity_digest_offset = LOCAL_ARCHIVE_MAGIC.len() + (5 * 8);
        tampered_digest[identity_digest_offset] ^= 0x01;
        std::fs::write(&source_path, tampered_digest).unwrap();
        let error = be.verify_archive(&source.backend_uri).unwrap_err();
        assert!(error.contains("identity mismatch"), "{error}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn localdir_rejects_truncated_legacy_and_mismatched_receipt() {
        let dir = test_dir("invalid");
        let be = LocalDirColdBackend::new(&dir).unwrap();
        let receipt = be
            .archive_durable(2, "AUTH_test", "bkt", "obj", b"payload")
            .unwrap();
        let path = be.path_for_uri(&receipt.backend_uri).unwrap();
        std::fs::write(&path, &LOCAL_ARCHIVE_MAGIC[..4]).unwrap();
        assert!(be.fetch(&receipt.backend_uri).is_err());
        assert!(be.fetch_verified(&receipt.backend_uri).is_err());
        assert!(be.restore_stage(&receipt.backend_uri, 1).is_err());

        let (legacy_uri, legacy_path, _) = be
            .archive_location(2, "AUTH_test", "bkt", "legacy", b"legacy raw payload")
            .unwrap();
        std::fs::create_dir_all(legacy_path.parent().unwrap()).unwrap();
        std::fs::write(&legacy_path, b"legacy raw payload").unwrap();
        assert!(be.fetch(&legacy_uri).is_err());
        assert!(be.restore_stage(&legacy_uri, 1).is_err());

        let valid = be
            .archive_durable(2, "AUTH_test", "bkt", "different", b"payload")
            .unwrap();
        let mut mismatched = valid.clone();
        mismatched.content_length += 1;
        assert!(be.fetch_with_receipt(&mismatched).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unmapped_class_no_stamp() {
        let map = ColdPolicyMap::new();
        let mut h = HeaderKeyDict::new();
        assert!(stamp_cold_policy_meta(&mut h, &map, "GLACIER", None, "a", "c", "k").is_none());
    }

    #[test]
    fn stamp_meta_does_not_invent_backend_uri() {
        let map = ColdPolicyMap::from_csv("GLACIER:2,HOT:0");
        let mut h = HeaderKeyDict::new();
        let t = stamp_cold_policy_meta(&mut h, &map, "GLACIER", Some(0), "a", "c", "k").unwrap();
        assert!(t.backend_uri.is_empty());
        assert!(h.get(SYS_COLD_BACKEND_URI).is_none());
        assert_eq!(h.get(SYS_COLD_POLICY_INDEX), Some("2"));
    }

    #[test]
    fn due_transition_with_memory_backend_stamps_uri() {
        use crate::lifecycle_exec::{META_STORAGE_CLASS, SYS_TRANSITION_AT};
        let map = ColdPolicyMap::from_csv("GLACIER:2,HOT:0");
        let be = MemoryColdBackend::default();
        let mut h = HeaderKeyDict::new();
        h.set(META_STORAGE_CLASS, "GLACIER");
        h.set(SYS_TRANSITION_AT, "50");
        let stamp = maybe_stamp_and_archive_due_cold(
            &mut h,
            &map,
            100,
            "AUTH_test",
            "bkt",
            "obj",
            Some(&be),
            Some(b"payload"),
        )
        .unwrap()
        .expect("due cold stamp");
        assert!(stamp.backend_uri.starts_with("memory://"));
        assert_eq!(stamp.archive_state, ColdArchiveState::Durable);
        assert!(stamp.hot_reclamation_safe_for(b"payload"));
        assert!(!stamp.hot_reclamation_safe_for(b"different"));
        let receipt = stamp.archive_receipt.as_ref().expect("durable receipt");
        assert_eq!(receipt.content_length, 7);
        assert_eq!(h.get(SYS_COLD_ARCHIVE_STATE), Some("durable"));
        assert_eq!(h.get(SYS_COLD_CONTENT_LENGTH), Some("7"));
        let expected_sha256 = sha256_hex(b"payload");
        assert_eq!(
            h.get(SYS_COLD_CONTENT_SHA256),
            Some(expected_sha256.as_str())
        );
        assert_eq!(h.get(SYS_COLD_BACKEND_URI).unwrap(), stamp.backend_uri);
        assert_eq!(h.get(SYS_COLD_POLICY_INDEX), Some("2"));
        assert_eq!(h.get(SYS_TRANSITIONED), Some("1"));
        be.restore_stage(&stamp.backend_uri, 1).unwrap();

        let reconstructed =
            maybe_stamp_due_cold_transition(&mut h, &map, 100, "AUTH_test", "bkt", "obj")
                .expect("reconstruct durable receipt from sysmeta");
        assert_eq!(
            reconstructed.archive_state,
            ColdArchiveState::UnverifiedReference
        );
        let recorded = reconstructed
            .archive_receipt
            .as_ref()
            .expect("recorded receipt fields");
        assert!(recorded.same_archive_identity(receipt));
        assert!(!reconstructed.hot_reclamation_safe_for(b"payload"));

        let reverified = maybe_stamp_and_archive_due_cold(
            &mut h,
            &map,
            100,
            "AUTH_test",
            "bkt",
            "obj",
            Some(&be),
            Some(b"payload"),
        )
        .unwrap()
        .expect("backend re-verifies recorded receipt");
        assert_eq!(reverified.archive_state, ColdArchiveState::Durable);
        assert!(reverified.hot_reclamation_safe_for(b"payload"));
    }

    #[test]
    fn due_transition_without_backend_meta_only_no_uri() {
        use crate::lifecycle_exec::{META_STORAGE_CLASS, SYS_TRANSITION_AT};
        let map = ColdPolicyMap::from_csv("GLACIER:2,HOT:0");
        let mut h = HeaderKeyDict::new();
        h.set(META_STORAGE_CLASS, "GLACIER");
        h.set(SYS_TRANSITION_AT, "50");
        let stamp = maybe_stamp_and_archive_due_cold(
            &mut h,
            &map,
            100,
            "AUTH_test",
            "bkt",
            "obj",
            None,
            Some(b"payload"),
        )
        .unwrap()
        .expect("due cold stamp");
        assert!(stamp.backend_uri.is_empty());
        assert_eq!(stamp.archive_state, ColdArchiveState::MetadataOnly);
        assert!(stamp.archive_receipt.is_none());
        assert!(!stamp.hot_reclamation_safe_for(b"payload"));
        assert!(h.get(SYS_COLD_BACKEND_URI).is_none());
        assert!(h.get(SYS_COLD_ARCHIVE_STATE).is_none());
        assert_eq!(h.get(SYS_COLD_POLICY_INDEX), Some("2"));
        assert_eq!(h.get(SYS_TRANSITIONED), Some("1"));
    }

    #[test]
    fn legacy_uri_without_receipt_is_not_hot_reclamation_safe() {
        let map = ColdPolicyMap::from_csv("GLACIER:2,HOT:0");
        let mut h = HeaderKeyDict::new();
        h.set(META_STORAGE_CLASS, "GLACIER");
        h.set(SYS_TRANSITIONED, "1");
        h.set(SYS_COLD_POLICY_INDEX, "2");
        h.set(SYS_COLD_BACKEND_URI, "filecold://legacy/object");
        let stamp = maybe_stamp_due_cold_transition(&mut h, &map, 100, "a", "c", "k")
            .expect("legacy cold stamp");
        assert_eq!(stamp.archive_state, ColdArchiveState::UnverifiedReference);
        assert!(stamp.archive_receipt.is_none());
        assert!(!stamp.hot_reclamation_safe_for(b"payload"));
    }

    #[derive(Debug)]
    struct MismatchedReceiptBackend;

    impl ColdBackend for MismatchedReceiptBackend {
        fn archive_durable(
            &self,
            _policy_index: i64,
            _account: &str,
            _container: &str,
            _key: &str,
            _body: &[u8],
        ) -> Result<ColdArchiveReceipt, String> {
            ColdArchiveReceipt::durable("bad://receipt".into(), b"different")
        }

        fn fetch_verified(
            &self,
            _backend_uri: &str,
        ) -> Result<(Vec<u8>, ColdArchiveReceipt), String> {
            Err("not archived".into())
        }
    }

    #[test]
    fn transition_rejects_backend_receipt_for_different_payload() {
        let map = ColdPolicyMap::from_csv("GLACIER:2,HOT:0");
        let mut h = HeaderKeyDict::new();
        h.set(META_STORAGE_CLASS, "GLACIER");
        h.set(SYS_TRANSITION_AT, "50");
        let error = maybe_stamp_and_archive_due_cold(
            &mut h,
            &map,
            100,
            "AUTH_test",
            "bkt",
            "obj",
            Some(&MismatchedReceiptBackend),
            Some(b"payload"),
        )
        .unwrap_err();
        assert!(error.contains("mismatched archive receipt"), "{error}");
        assert!(h.get(SYS_COLD_BACKEND_URI).is_none());
        assert!(h.get(SYS_COLD_ARCHIVE_STATE).is_none());
    }

    #[test]
    fn reject_partial_body_206_never_durable() {
        let body = b"payload";
        let receipt = ColdArchiveReceipt::durable("memory://obj".into(), body).unwrap();
        assert!(reject_partial_body(true).is_err());
        assert!(reject_partial_body(false).is_ok());
        assert!(archive_commit(&receipt, body, true).is_err());
        assert_eq!(
            archive_commit(&receipt, body, false).unwrap(),
            ColdArchiveState::Durable
        );
        let failed =
            ColdStateMachine::new().apply_archive_commit_or_fail(receipt.clone(), body, true);
        assert_eq!(failed.state, ColdArchiveState::Failed);
        assert_ne!(failed.state, ColdArchiveState::Durable);
        assert_eq!(failed.archive_generation, 0);
        assert!(!hot_reclamation_allowed(
            ColdArchiveState::Durable,
            Some(&receipt),
            body,
            true,
            true,
        ));
    }

    #[test]
    fn restore_does_not_immediately_rearchive() {
        let body = b"payload";
        let receipt = ColdArchiveReceipt::durable("memory://obj".into(), body).unwrap();
        let machine = ColdStateMachine::new()
            .apply_archive_commit(receipt, body, false)
            .unwrap();
        let now = 1_000;
        let days = 1;
        let restoring = machine.apply_begin_restore(now, days).unwrap();
        assert!(matches!(
            restoring.state,
            ColdArchiveState::Restoring {
                days: 1,
                restore_until_unix
            } if restore_until_unix == now + SECONDS_PER_DAY
        ));
        assert_eq!(
            maybe_rearchive(restoring.state, now, false).unwrap(),
            restoring.state
        );
        assert_eq!(
            maybe_rearchive(restoring.state, now, true).unwrap(),
            restoring.state
        );

        let restored = restoring.apply_complete_restore(now).unwrap();
        assert_eq!(
            restored.state,
            ColdArchiveState::Restored {
                restore_until_unix: now + SECONDS_PER_DAY
            }
        );
        // Same instant as complete: still inside the window — must not rearchive,
        // even if delete_hot is explicitly true.
        assert_eq!(
            maybe_rearchive(restored.state, now, false).unwrap(),
            restored.state
        );
        assert_eq!(
            maybe_rearchive(restored.state, now, true).unwrap(),
            restored.state
        );
        let unchanged = restored.apply_maybe_rearchive(now, true).unwrap();
        assert_eq!(unchanged.state, restored.state);
        assert_eq!(unchanged.archive_generation, restored.archive_generation);

        let expired = restored
            .apply_maybe_rearchive(now + SECONDS_PER_DAY, false)
            .unwrap();
        assert_eq!(expired.state, ColdArchiveState::Durable);
        assert_eq!(expired.archive_generation, restored.archive_generation + 1);
    }

    #[test]
    fn delete_hot_defaults_false_and_must_be_passed() {
        assert!(
            !COLD_DELETE_HOT_AFTER_ARCHIVE_DEFAULT,
            "cold_delete_hot_after_archive must default false"
        );
        let body = b"payload";
        let receipt = ColdArchiveReceipt::durable("memory://obj".into(), body).unwrap();
        let machine = ColdStateMachine::new()
            .apply_archive_commit(receipt.clone(), body, false)
            .unwrap();
        assert!(!machine.hot_reclamation_allowed(
            COLD_DELETE_HOT_AFTER_ARCHIVE_DEFAULT,
            body,
            false
        ));
        assert!(!hot_reclamation_allowed(
            machine.state,
            machine.receipt.as_ref(),
            body,
            COLD_DELETE_HOT_AFTER_ARCHIVE_DEFAULT,
            false,
        ));
        assert!(machine.hot_reclamation_allowed(true, body, false));
        assert!(!machine.hot_reclamation_allowed(true, body, true));
        let restoring = machine.apply_begin_restore(10, 1).unwrap();
        assert!(!restoring.hot_reclamation_allowed(true, body, false));
        let restored = restoring.apply_complete_restore(10).unwrap();
        assert!(!restored.hot_reclamation_allowed(true, body, false));
    }

    #[test]
    fn successful_transitions_bump_generations() {
        let body = b"payload";
        let receipt = ColdArchiveReceipt::durable("memory://obj".into(), body).unwrap();
        let start = ColdStateMachine::new();
        assert_eq!(start.archive_generation, 0);
        assert_eq!(start.restore_generation, 0);

        let durable = start
            .apply_archive_commit(receipt.clone(), body, false)
            .unwrap();
        assert_eq!(durable.state, ColdArchiveState::Durable);
        assert_eq!(durable.archive_generation, 1);
        assert_eq!(durable.restore_generation, 0);

        let restoring = durable.apply_begin_restore(50, 2).unwrap();
        assert_eq!(restoring.archive_generation, 1);
        assert_eq!(restoring.restore_generation, 1);

        let restored = restoring.apply_complete_restore(50).unwrap();
        assert_eq!(restored.archive_generation, 1);
        assert_eq!(restored.restore_generation, 2);

        let still = restored.apply_maybe_rearchive(50, false).unwrap();
        assert_eq!(still.archive_generation, 1);
        assert_eq!(still.restore_generation, 2);

        let rearchived = restored
            .apply_maybe_rearchive(50 + 2 * SECONDS_PER_DAY, false)
            .unwrap();
        assert_eq!(rearchived.state, ColdArchiveState::Durable);
        assert_eq!(rearchived.archive_generation, 2);
        assert_eq!(rearchived.restore_generation, 2);

        let mut headers = HeaderKeyDict::new();
        rearchived.stamp_generation_headers(&mut headers);
        assert_eq!(headers.get(SYS_COLD_ARCHIVE_GENERATION), Some("2"));
        assert_eq!(headers.get(SYS_COLD_RESTORE_GENERATION), Some("2"));
    }

    #[test]
    fn tampered_receipt_never_becomes_durable() {
        let body = b"payload";
        let good = ColdArchiveReceipt::durable("memory://obj".into(), body).unwrap();
        let mut tampered = good.clone();
        tampered.content_sha256 = "0".repeat(64);
        assert!(!tampered.verifies_payload(body));
        assert!(archive_commit(&tampered, body, false).is_err());
        let failed =
            ColdStateMachine::new().apply_archive_commit_or_fail(tampered.clone(), body, false);
        assert_eq!(failed.state, ColdArchiveState::Failed);
        assert_eq!(failed.archive_generation, 0);
        assert!(!hot_reclamation_allowed(
            failed.state,
            failed.receipt.as_ref(),
            body,
            true,
            false,
        ));

        let mut wrong_len = good.clone();
        wrong_len.content_length += 1;
        assert!(archive_commit(&wrong_len, body, false).is_err());
        assert!(ColdStateMachine::new()
            .apply_archive_commit(wrong_len, body, false)
            .is_err());
    }

    #[test]
    fn localdir_1024_byte_key_stays_under_name_max() {
        const NAME_MAX: usize = 255;
        let dir = test_dir("name-max-1024");
        let be = LocalDirColdBackend::new(&dir).unwrap();
        let key = "k".repeat(1024);
        assert_eq!(key.len(), 1024);
        let receipt = be
            .archive_durable(2, "AUTH_test", "bucket", &key, b"payload")
            .unwrap();
        let path = be.path_for_uri(&receipt.backend_uri).unwrap();
        assert!(path.is_file());
        for component in path.components() {
            if let std::path::Component::Normal(name) = component {
                assert!(
                    name.len() <= NAME_MAX,
                    "path component {name:?} is {} bytes, exceeds NAME_MAX={NAME_MAX}",
                    name.len()
                );
            }
        }
        let relative = receipt.backend_uri.strip_prefix("filecold://").unwrap();
        for component in relative.split('/') {
            assert!(
                !component.is_empty() && component.len() <= NAME_MAX,
                "uri component {component:?} exceeds NAME_MAX={NAME_MAX}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
