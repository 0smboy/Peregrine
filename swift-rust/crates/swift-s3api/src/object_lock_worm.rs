// Copyright (c) 2026 OpenStack Foundation
//! Object Lock enforcement helpers (experimental / best-effort).
//!
//! Not a production WORM or compliance claim. Helpers stay fail-closed, but
//! CAS tokens, clock-health, and native `/v1` enforcement are not live-proven.
//!
//! Object subresources (`?legal-hold`, `?retention`) store sysmeta defined
//! here. DELETE is denied when legal-hold is ON or retain-until is in the
//! future.
//!
//! **Bypass:** `x-amz-bypass-governance-retention: true` allows DELETE /
//! overwrite only when the lock mode is **GOVERNANCE**, IAM has authorized
//! the bypass, and the block reason is retention (not legal-hold). Header
//! alone or IAM alone is not enough. **COMPLIANCE** cannot be shortened,
//! downgraded, or bypassed. Legal-hold ignores bypass. `clock_ok=false`
//! denies COMPLIANCE claims.

use crate::crypto::{sha256_hex, streq_const_time};
use crate::xml::Element;
use swift_http::HeaderKeyDict;

pub const SYS_LEGAL_HOLD: &str = "X-Object-Sysmeta-S3-Legal-Hold";
pub const SYS_LOCK_MODE: &str = "X-Object-Sysmeta-S3-Object-Lock-Mode";
pub const SYS_RETAIN_UNTIL: &str = "X-Object-Sysmeta-S3-Retain-Until-Date";
/// Persisted revision mixed into the lock If-Match token.
pub const SYS_LOCK_REVISION: &str = "X-Object-Sysmeta-S3-Object-Lock-Revision";
pub const HDR_BYPASS_GOVERNANCE: &str = "x-amz-bypass-governance-retention";
/// Experimental lock-state If-Match header. Object-server does not honor it yet.
pub const HDR_LOCK_IF_MATCH: &str = "X-Backend-Object-Lock-If-Match";

/// Maximum Object Lock retention supported by S3 (100 years).
pub const MAX_RETENTION_DAYS: i64 = 36_500;

/// Object Lock retention mode persisted on one concrete object version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectLockMode {
    Governance,
    Compliance,
}

impl ObjectLockMode {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim() {
            "GOVERNANCE" => Some(Self::Governance),
            "COMPLIANCE" => Some(Self::Compliance),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Governance => "GOVERNANCE",
            Self::Compliance => "COMPLIANCE",
        }
    }
}

/// A syntactically valid retention request or persisted retention record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectRetention {
    pub mode: ObjectLockMode,
    /// Validated request value retained for S3 response XML/sysmeta.
    pub retain_until: String,
    pub retain_until_unix: i64,
}

/// Parsed WORM state for exactly one resolved object version.
///
/// Version selection belongs to the middleware. It must HEAD the requested
/// version and pass only that version's headers to this API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectVersionLockState {
    pub legal_hold_on: bool,
    pub retention: Option<ObjectRetention>,
}

/// Corrupt or incomplete persisted WORM metadata. Callers must fail closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistedLockError {
    InvalidLegalHold,
    IncompleteRetention,
    InvalidRetentionMode,
    InvalidRetainUntilDate,
}

/// Governance bypass requires both the explicit request header and IAM grant.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GovernanceBypass {
    pub requested: bool,
    pub authorized: bool,
}

impl GovernanceBypass {
    pub const NONE: Self = Self {
        requested: false,
        authorized: false,
    };

    pub const fn effective(self) -> bool {
        self.requested && self.authorized
    }
}

/// Persist-layer error. Neither variant is an unlocked object.
///
/// Experimental mapping so callers cannot treat unknown backend or
/// unreadable lock metadata as "no lock".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistError {
    /// Backend HEAD/GET was 5xx, timed out, or any non-2xx/non-404 status.
    Backend5xx,
    /// Stored lock sysmeta is present but not a valid lock record.
    Malformed,
}

impl From<PersistedLockError> for PersistError {
    fn from(_error: PersistedLockError) -> Self {
        Self::Malformed
    }
}

/// True when the caller reports an untrusted clock. COMPLIANCE claims deny.
pub const fn clock_unhealthy(clock_ok: bool) -> bool {
    !clock_ok
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WormDenyReason {
    LegalHold,
    GovernanceRetention,
    ComplianceRetention,
    InvalidPersistedState(PersistedLockError),
    Persist(PersistError),
    ClockUnhealthy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WormDecision {
    Allow,
    Deny(WormDenyReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetentionUpdateDenyReason {
    InvalidRequest,
    InvalidPersistedState(PersistedLockError),
    ComplianceProtected,
    GovernanceBypassRequired,
    ClockUnhealthy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetentionUpdateDecision {
    Allow,
    Deny(RetentionUpdateDenyReason),
}

/// Default retention extracted from bucket `ObjectLockConfiguration`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultRetention {
    pub mode: String,
    /// Exactly one of Days or Years is set, as required by S3.
    pub days: Option<i64>,
    pub years: Option<i64>,
}

/// Compatibility Boolean helper for the governance-bypass header.
pub fn bypass_governance_requested(header_val: Option<&str>) -> bool {
    parse_bypass_governance_header(header_val).unwrap_or(false)
}

/// Strictly parse `x-amz-bypass-governance-retention`.
///
/// Missing means false. Invalid Boolean spellings are not silently treated as
/// false by callers that use this result directly.
pub fn parse_bypass_governance_header(header_val: Option<&str>) -> Result<bool, String> {
    match header_val.map(str::trim) {
        None | Some("") => Ok(false),
        Some(value) if value.eq_ignore_ascii_case("true") => Ok(true),
        Some(value) if value.eq_ignore_ascii_case("false") => Ok(false),
        Some(_) => Err("InvalidArgument".into()),
    }
}

/// Parse the WORM sysmeta attached to one resolved object version.
///
/// Any malformed legal-hold value, partial retention pair, invalid mode, or
/// invalid date is an error. Destructive callers must map the error to deny,
/// never to an unlocked object.
pub fn object_version_lock_state(
    headers: &HeaderKeyDict,
) -> Result<ObjectVersionLockState, PersistedLockError> {
    let legal_hold_on = match headers.get(SYS_LEGAL_HOLD).map(str::trim) {
        None | Some("") | Some("OFF") => false,
        Some("ON") => true,
        Some(_) => return Err(PersistedLockError::InvalidLegalHold),
    };

    let retention = persisted_retention(headers)?;

    Ok(ObjectVersionLockState {
        legal_hold_on,
        retention,
    })
}

/// Decide whether a destructive operation may target one resolved version.
pub fn evaluate_object_version_worm(
    headers: &HeaderKeyDict,
    now_unix: i64,
    bypass: GovernanceBypass,
) -> WormDecision {
    evaluate_object_version_worm_with_clock(headers, now_unix, true, bypass)
}

/// Same as [`evaluate_object_version_worm`], with an explicit clock-health bit.
///
/// `clock_ok=false` denies COMPLIANCE claims (cannot trust retain-until vs now).
pub fn evaluate_object_version_worm_with_clock(
    headers: &HeaderKeyDict,
    now_unix: i64,
    clock_ok: bool,
    bypass: GovernanceBypass,
) -> WormDecision {
    match object_version_lock_state(headers) {
        Ok(state) => evaluate_lock_state(&state, now_unix, clock_ok, bypass),
        Err(error) => WormDecision::Deny(WormDenyReason::InvalidPersistedState(error)),
    }
}

/// Evaluate an already-parsed lock record.
pub fn evaluate_lock_state(
    state: &ObjectVersionLockState,
    now_unix: i64,
    clock_ok: bool,
    bypass: GovernanceBypass,
) -> WormDecision {
    if state.legal_hold_on {
        return WormDecision::Deny(WormDenyReason::LegalHold);
    }
    let Some(retention) = state.retention.as_ref() else {
        return WormDecision::Allow;
    };
    if retention.mode == ObjectLockMode::Compliance && clock_unhealthy(clock_ok) {
        return WormDecision::Deny(WormDenyReason::ClockUnhealthy);
    }
    if retention.retain_until_unix <= now_unix {
        return WormDecision::Allow;
    }
    match retention.mode {
        ObjectLockMode::Governance if bypass.effective() => WormDecision::Allow,
        ObjectLockMode::Governance => WormDecision::Deny(WormDenyReason::GovernanceRetention),
        ObjectLockMode::Compliance => WormDecision::Deny(WormDenyReason::ComplianceRetention),
    }
}

/// Map a backend object HEAD/GET status into lock state or a persist error.
///
/// * 2xx → parse headers (missing lock headers = unlocked)
/// * 404 → unlocked empty state
/// * 5xx / any other status / missing header map → [`PersistError::Backend5xx`]
/// * 2xx with unparseable lock sysmeta → [`PersistError::Malformed`]
///
/// Callers must not treat `Err(_)` as unlocked.
pub fn lock_state_from_backend_status(
    status: u16,
    headers: Option<&HeaderKeyDict>,
) -> Result<ObjectVersionLockState, PersistError> {
    match status {
        200..=299 => {
            let headers = headers.ok_or(PersistError::Backend5xx)?;
            object_version_lock_state(headers).map_err(PersistError::from)
        }
        404 => Ok(ObjectVersionLockState {
            legal_hold_on: false,
            retention: None,
        }),
        _ => Err(PersistError::Backend5xx),
    }
}

/// True only for a successfully read, lock-free object. 5xx and malformed are false.
pub fn persist_is_unlocked(result: &Result<ObjectVersionLockState, PersistError>) -> bool {
    matches!(
        result,
        Ok(state) if !state.legal_hold_on && state.retention.is_none()
    )
}

/// Fail-closed decision from a backend HEAD plus lock headers.
pub fn evaluate_object_version_worm_from_backend(
    status: u16,
    headers: Option<&HeaderKeyDict>,
    now_unix: i64,
    clock_ok: bool,
    bypass: GovernanceBypass,
) -> WormDecision {
    match lock_state_from_backend_status(status, headers) {
        Ok(state) => evaluate_lock_state(&state, now_unix, clock_ok, bypass),
        Err(error) => WormDecision::Deny(WormDenyReason::Persist(error)),
    }
}

/// Canonical lock tuple used to mint the If-Match token.
///
/// Format: `v1|{ON|OFF}|{GOVERNANCE|COMPLIANCE|NONE}|{retain_until_unix}|{revision}`.
pub fn canonical_lock_tuple(state: &ObjectVersionLockState, revision: u64) -> String {
    let hold = if state.legal_hold_on { "ON" } else { "OFF" };
    let (mode, until) = match state.retention.as_ref() {
        Some(retention) => (retention.mode.as_str(), retention.retain_until_unix),
        None => ("NONE", 0),
    };
    format!("v1|{hold}|{mode}|{until}|{revision}")
}

/// Opaque hex If-Match token (SHA-256 of the canonical lock tuple + revision).
///
/// Experimental: middleware can attach [`HDR_LOCK_IF_MATCH`] later; the
/// object-server does not CAS on this token yet.
pub fn lock_if_match_token(state: &ObjectVersionLockState, revision: u64) -> String {
    sha256_hex(canonical_lock_tuple(state, revision).as_bytes())
}

/// Revision counter from lock sysmeta. Missing or unparseable is 0.
pub fn lock_revision(headers: &HeaderKeyDict) -> u64 {
    headers
        .get(SYS_LOCK_REVISION)
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(0)
}

/// If-Match token for the lock headers on one version, or persist Malformed.
pub fn lock_if_match_token_from_headers(headers: &HeaderKeyDict) -> Result<String, PersistError> {
    let state = object_version_lock_state(headers).map_err(PersistError::from)?;
    Ok(lock_if_match_token(&state, lock_revision(headers)))
}

/// Constant-time compare of two lock If-Match tokens.
pub fn lock_if_match_matches(expected: &str, provided: &str) -> bool {
    streq_const_time(expected, provided)
}

/// True if DELETE must be denied (no bypass path).
pub fn worm_blocks_delete(headers: &HeaderKeyDict, now_unix: i64) -> bool {
    worm_blocks_delete_with_bypass(headers, now_unix, false)
}

/// True if DELETE/overwrite must be denied, honouring governance bypass.
///
/// * Legal-hold ON → always block (bypass ignored)
/// * Active retention + COMPLIANCE → always block
/// * Active retention + GOVERNANCE → block unless `bypass_governance`
/// * Active retention + missing mode → treat as COMPLIANCE-like (block; safe default)
///
/// `bypass_governance` must already represent an IAM-authorized bypass. New
/// request paths should use [`evaluate_object_version_worm`] with separate
/// requested/authorized bits instead of passing a raw header Boolean here.
pub fn worm_blocks_delete_with_bypass(
    headers: &HeaderKeyDict,
    now_unix: i64,
    bypass_governance: bool,
) -> bool {
    matches!(
        evaluate_object_version_worm(
            headers,
            now_unix,
            GovernanceBypass {
                requested: bypass_governance,
                authorized: bypass_governance,
            },
        ),
        WormDecision::Deny(_)
    )
}

/// Inverse of [`worm_blocks_delete_with_bypass`] — true when the operation is allowed.
pub fn worm_allows_operation(
    headers: &HeaderKeyDict,
    now_unix: i64,
    bypass_governance: bool,
) -> bool {
    !worm_blocks_delete_with_bypass(headers, now_unix, bypass_governance)
}

/// True if PUT `?retention` must be denied given existing object sysmeta.
///
/// Compatibility wrapper around the version-aware retention decision API:
/// * No existing (or expired) retention → allow
/// * **COMPLIANCE**: cannot shorten retain-until; cannot switch to GOVERNANCE;
///   bypass is ignored
/// * **GOVERNANCE**: cannot shorten unless `bypass_governance`; may upgrade
///   to COMPLIANCE
/// * Unparseable `new_until` or unknown mode → block (safe default)
pub fn worm_blocks_retention_put(
    existing: &HeaderKeyDict,
    new_mode: &str,
    new_until: &str,
    now_unix: i64,
    bypass_governance: bool,
) -> bool {
    let Some(requested) = parse_object_retention(new_mode, new_until) else {
        return true;
    };
    matches!(
        evaluate_retention_update(
            existing,
            &requested,
            now_unix,
            GovernanceBypass {
                requested: bypass_governance,
                authorized: bypass_governance,
            },
        ),
        RetentionUpdateDecision::Deny(_)
    )
}

/// Parse one requested Object Lock retention value.
pub fn parse_object_retention(mode: &str, retain_until: &str) -> Option<ObjectRetention> {
    let mode = ObjectLockMode::parse(mode)?;
    let retain_until = retain_until.trim();
    let retain_until_unix = parse_retain_until(retain_until)?;
    Some(ObjectRetention {
        mode,
        retain_until: retain_until.to_string(),
        retain_until_unix,
    })
}

fn persisted_retention(
    headers: &HeaderKeyDict,
) -> Result<Option<ObjectRetention>, PersistedLockError> {
    let mode = headers.get(SYS_LOCK_MODE).map(str::trim).filter(|v| !v.is_empty());
    let until = headers
        .get(SYS_RETAIN_UNTIL)
        .map(str::trim)
        .filter(|v| !v.is_empty());
    match (mode, until) {
        (None, None) => Ok(None),
        (Some(_), None) | (None, Some(_)) => Err(PersistedLockError::IncompleteRetention),
        (Some(mode), Some(until)) => {
            let mode = ObjectLockMode::parse(mode)
                .ok_or(PersistedLockError::InvalidRetentionMode)?;
            let retain_until_unix = parse_retain_until(until)
                .ok_or(PersistedLockError::InvalidRetainUntilDate)?;
            Ok(Some(ObjectRetention {
                mode,
                retain_until: until.to_string(),
                retain_until_unix,
            }))
        }
    }
}

/// Evaluate a retention update for exactly one resolved object version.
///
/// The request must contain a future RFC3339 timestamp no more than 100 years
/// away. Any malformed existing retention fails closed.
pub fn evaluate_retention_update(
    existing: &HeaderKeyDict,
    requested: &ObjectRetention,
    now_unix: i64,
    bypass: GovernanceBypass,
) -> RetentionUpdateDecision {
    evaluate_retention_update_with_clock(existing, requested, now_unix, true, bypass)
}

/// Same as [`evaluate_retention_update`], with an explicit clock-health bit.
///
/// `clock_ok=false` denies COMPLIANCE claims (new or existing).
pub fn evaluate_retention_update_with_clock(
    existing: &HeaderKeyDict,
    requested: &ObjectRetention,
    now_unix: i64,
    clock_ok: bool,
    bypass: GovernanceBypass,
) -> RetentionUpdateDecision {
    if clock_unhealthy(clock_ok) && requested.mode == ObjectLockMode::Compliance {
        return RetentionUpdateDecision::Deny(RetentionUpdateDenyReason::ClockUnhealthy);
    }
    if !retention_date_is_valid_for_put(requested, now_unix) {
        return RetentionUpdateDecision::Deny(RetentionUpdateDenyReason::InvalidRequest);
    }
    let old = match persisted_retention(existing) {
        Ok(old) => old,
        Err(error) => {
            return RetentionUpdateDecision::Deny(
                RetentionUpdateDenyReason::InvalidPersistedState(error),
            );
        }
    };
    let Some(old) = old else {
        return RetentionUpdateDecision::Allow;
    };
    if old.mode == ObjectLockMode::Compliance && clock_unhealthy(clock_ok) {
        return RetentionUpdateDecision::Deny(RetentionUpdateDenyReason::ClockUnhealthy);
    }
    if old.retain_until_unix <= now_unix {
        return RetentionUpdateDecision::Allow;
    }
    match old.mode {
        ObjectLockMode::Compliance => {
            if requested.mode == ObjectLockMode::Governance
                || requested.retain_until_unix < old.retain_until_unix
            {
                RetentionUpdateDecision::Deny(RetentionUpdateDenyReason::ComplianceProtected)
            } else {
                RetentionUpdateDecision::Allow
            }
        }
        ObjectLockMode::Governance => {
            if requested.retain_until_unix < old.retain_until_unix && !bypass.effective() {
                RetentionUpdateDecision::Deny(
                    RetentionUpdateDenyReason::GovernanceBypassRequired,
                )
            } else {
                RetentionUpdateDecision::Allow
            }
        }
    }
}

/// S3 accepts only a future retention date within its 100-year maximum.
pub fn retention_date_is_valid_for_put(retention: &ObjectRetention, now_unix: i64) -> bool {
    let max_until = now_unix.saturating_add(MAX_RETENTION_DAYS.saturating_mul(86_400));
    retention.retain_until_unix > now_unix && retention.retain_until_unix <= max_until
}

/// Parse an RFC3339 timestamp accepted by S3 Object Lock.
///
/// Bare unix seconds, invalid calendar dates, missing timezone, leap seconds,
/// and trailing data are rejected. Fractional seconds and numeric offsets are
/// accepted and normalized to unix seconds.
pub fn parse_retain_until(s: &str) -> Option<i64> {
    let s = s.trim();
    if !s.is_ascii() || s.len() < 20 {
        return None;
    }
    let b = s.as_bytes();
    if b.get(4) != Some(&b'-')
        || b.get(7) != Some(&b'-')
        || b.get(10) != Some(&b'T')
        || b.get(13) != Some(&b':')
        || b.get(16) != Some(&b':')
    {
        return None;
    }
    let digits = |range: std::ops::Range<usize>| -> Option<u32> {
        let part = b.get(range)?;
        if !part.iter().all(u8::is_ascii_digit) {
            return None;
        }
        std::str::from_utf8(part).ok()?.parse().ok()
    };
    let y = digits(0..4)? as i32;
    let m = digits(5..7)?;
    let d = digits(8..10)?;
    let hh = digits(11..13)?;
    let mm = digits(14..16)?;
    let ss = digits(17..19)?;
    if y == 0 || hh > 23 || mm > 59 || ss > 59 {
        return None;
    }

    let mut pos = 19;
    if b.get(pos) == Some(&b'.') {
        pos += 1;
        let frac_start = pos;
        while b.get(pos).is_some_and(u8::is_ascii_digit) {
            pos += 1;
        }
        if pos == frac_start {
            return None;
        }
    }
    let offset_seconds = match b.get(pos) {
        Some(b'Z') if pos + 1 == b.len() => 0i64,
        Some(sign @ (b'+' | b'-')) if pos + 6 == b.len() => {
            if b.get(pos + 3) != Some(&b':') {
                return None;
            }
            let off_h = digits(pos + 1..pos + 3)?;
            let off_m = digits(pos + 4..pos + 6)?;
            if off_h > 23 || off_m > 59 {
                return None;
            }
            let offset = (off_h as i64) * 3_600 + (off_m as i64) * 60;
            if *sign == b'+' { offset } else { -offset }
        }
        _ => return None,
    };

    let days = days_from_civil(y, m, d)?;
    Some(
        days.saturating_mul(86_400)
            .saturating_add((hh as i64) * 3_600)
            .saturating_add((mm as i64) * 60)
            .saturating_add(ss as i64)
            .saturating_sub(offset_seconds),
    )
}

/// Format unix seconds as `YYYY-MM-DDTHH:MM:SSZ` (UTC).
pub fn format_retain_until_iso(unix: i64) -> String {
    let days = unix.div_euclid(86400);
    let tod = unix.rem_euclid(86400) as u32;
    let (y, m, d) = civil_from_days(days);
    let hh = tod / 3600;
    let mm = (tod % 3600) / 60;
    let ss = tod % 60;
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// Strictly parse an AWS `ObjectLockConfiguration` document.
///
/// The root must enable Object Lock. A rule is optional, but when present it
/// must contain one mode and exactly one positive Days/Years period. Unknown,
/// duplicate, mixed-content, DTD, comment, and malformed elements are rejected.
pub fn parse_object_lock_configuration(
    xml: &[u8],
) -> Result<Option<DefaultRetention>, String> {
    let root = parse_xml_document(xml)?;
    require_node_name(&root, "ObjectLockConfiguration")?;
    require_branch_text_empty(&root)?;
    require_only_children(&root, &["ObjectLockEnabled", "Rule"])?;

    let enabled = required_child(&root, "ObjectLockEnabled")?;
    if leaf_text(enabled)? != "Enabled" {
        return Err("MalformedXML".into());
    }
    let rules = children_named(&root, "Rule");
    if rules.len() > 1 {
        return Err("MalformedXML".into());
    }
    let Some(rule) = rules.first() else {
        return Ok(None);
    };
    require_branch_text_empty(rule)?;
    require_only_children(rule, &["DefaultRetention"])?;
    let default = required_child(rule, "DefaultRetention")?;
    require_branch_text_empty(default)?;
    require_only_children(default, &["Mode", "Days", "Years"])?;

    let mode = ObjectLockMode::parse(leaf_text(required_child(default, "Mode")?)?)
        .ok_or_else(|| "MalformedXML".to_string())?;
    let days = optional_positive_period(default, "Days", MAX_RETENTION_DAYS)?;
    let years = optional_positive_period(default, "Years", 100)?;
    if days.is_some() == years.is_some() {
        return Err("MalformedXML".into());
    }
    Ok(Some(DefaultRetention {
        mode: mode.as_str().to_string(),
        days,
        years,
    }))
}

/// Parse `DefaultRetention` from ObjectLockConfiguration XML.
///
/// Compatibility wrapper for existing middleware; malformed documents and
/// configurations without a default rule both return `None`. New callers that
/// must distinguish those cases should use [`parse_object_lock_configuration`].
pub fn default_retention_from_lock_xml(xml: &[u8]) -> Option<DefaultRetention> {
    parse_object_lock_configuration(xml).ok().flatten()
}

/// Compute retain-until unix from default retention and `now_unix`.
pub fn retain_until_from_default(def: &DefaultRetention, now_unix: i64) -> i64 {
    let mut add = 0i64;
    if let Some(d) = def.days {
        add = add.saturating_add(d.saturating_mul(86400));
    }
    if let Some(y) = def.years {
        // AWS: Years ≈ 365 days each for Object Lock default retention.
        add = add.saturating_add(y.saturating_mul(365 * 86400));
    }
    now_unix.saturating_add(add)
}

/// Stamp default retention sysmeta onto object PUT headers when absent.
pub fn apply_default_retention_headers(
    headers: &mut HeaderKeyDict,
    def: &DefaultRetention,
    now_unix: i64,
) {
    if headers.get(SYS_RETAIN_UNTIL).is_some() {
        return;
    }
    let until = retain_until_from_default(def, now_unix);
    headers.set(SYS_LOCK_MODE, &def.mode);
    headers.set(SYS_RETAIN_UNTIL, format_retain_until_iso(until));
}

/// Apply explicit `x-amz-object-lock-*` request headers → sysmeta.
pub fn apply_amz_object_lock_headers(headers: &mut HeaderKeyDict) {
    let _ = validate_and_apply_amz_object_lock_headers(headers);
}

/// Validate and apply explicit `x-amz-object-lock-*` request headers.
///
/// Retention mode and date must be supplied together. Legal hold is exactly
/// `ON` or `OFF`. Validation completes before any sysmeta is mutated.
pub fn validate_and_apply_amz_object_lock_headers(
    headers: &mut HeaderKeyDict,
) -> Result<(), String> {
    let mode = headers
        .get("X-Amz-Object-Lock-Mode")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let until = headers
        .get("X-Amz-Object-Lock-Retain-Until-Date")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let retention = match (mode.as_deref(), until.as_deref()) {
        (None, None) => None,
        (Some(_), None) | (None, Some(_)) => return Err("InvalidRequest".into()),
        (Some(mode), Some(until)) => {
            Some(parse_object_retention(mode, until).ok_or_else(|| "InvalidRequest".to_string())?)
        }
    };
    let legal_hold = headers
        .get("X-Amz-Object-Lock-Legal-Hold")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    if !matches!(legal_hold.as_deref(), None | Some("ON") | Some("OFF")) {
        return Err("InvalidRequest".into());
    }

    if let Some(retention) = retention {
        headers.set(SYS_LOCK_MODE, retention.mode.as_str());
        headers.set(SYS_RETAIN_UNTIL, retention.retain_until);
    }
    if let Some(legal_hold) = legal_hold {
        headers.set(SYS_LEGAL_HOLD, legal_hold);
    }
    Ok(())
}

fn days_from_civil(y: i32, m: u32, d: u32) -> Option<i64> {
    if y == 0 || !(1..=12).contains(&m) || d == 0 || d > days_in_month(y, m) {
        return None;
    }
    let y = y as i64;
    let m = m as i64;
    let d = d as i64;
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146097 + doe - 719468)
}

fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Inverse of [`days_from_civil`] (Howard Hinnant).
fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m as u32, d as u32)
}

pub fn legal_hold_xml(status_on: bool) -> Vec<u8> {
    let st = if status_on { "ON" } else { "OFF" };
    Element::new("LegalHold")
        .with_leaf("Status", st)
        .to_xml(true)
}

pub fn parse_legal_hold_body(body: &[u8]) -> Result<bool, String> {
    let root = parse_xml_document(body)?;
    require_node_name(&root, "LegalHold")?;
    require_branch_text_empty(&root)?;
    require_only_children(&root, &["Status"])?;
    match leaf_text(required_child(&root, "Status")?)? {
        "ON" => Ok(true),
        "OFF" => Ok(false),
        _ => Err("MalformedXML".into()),
    }
}

pub fn retention_xml(mode: &str, retain_until: &str) -> Vec<u8> {
    Element::new("Retention")
        .with_leaf("Mode", mode)
        .with_leaf("RetainUntilDate", retain_until)
        .to_xml(true)
}

pub fn parse_retention_body(body: &[u8]) -> Result<(String, String), String> {
    let root = parse_xml_document(body)?;
    require_node_name(&root, "Retention")?;
    require_branch_text_empty(&root)?;
    require_only_children(&root, &["Mode", "RetainUntilDate"])?;
    let mode = leaf_text(required_child(&root, "Mode")?)?;
    let until = leaf_text(required_child(&root, "RetainUntilDate")?)?;
    let retention = parse_object_retention(mode, until).ok_or_else(|| "MalformedXML".to_string())?;
    Ok((
        retention.mode.as_str().to_string(),
        retention.retain_until,
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct XmlNode {
    name: String,
    text: String,
    children: Vec<XmlNode>,
}

struct XmlParser<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> XmlParser<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, pos: 0 }
    }

    fn parse_document(mut self) -> Result<XmlNode, String> {
        if self.input.starts_with(&[0xef, 0xbb, 0xbf]) {
            self.pos = 3;
        }
        self.skip_ws();
        if self.starts_with(b"<?xml") {
            self.consume_processing_instruction()?;
            self.skip_ws();
        }
        let root = self.parse_element(0)?;
        self.skip_ws();
        if self.pos != self.input.len() {
            return Err("MalformedXML".into());
        }
        Ok(root)
    }

    fn parse_element(&mut self, depth: usize) -> Result<XmlNode, String> {
        if depth > 16 || self.input.get(self.pos) != Some(&b'<') {
            return Err("MalformedXML".into());
        }
        self.pos += 1;
        if matches!(self.input.get(self.pos), Some(b'/' | b'!' | b'?')) {
            return Err("MalformedXML".into());
        }
        let name = self.parse_name()?;
        loop {
            self.skip_ws();
            match self.input.get(self.pos) {
                Some(b'>') => {
                    self.pos += 1;
                    break;
                }
                Some(b'/') if self.input.get(self.pos + 1) == Some(&b'>') => {
                    self.pos += 2;
                    return Ok(XmlNode {
                        name,
                        text: String::new(),
                        children: Vec::new(),
                    });
                }
                Some(_) => self.consume_attribute()?,
                None => return Err("MalformedXML".into()),
            }
        }

        let mut text = Vec::new();
        let mut children = Vec::new();
        loop {
            let Some(next) = self.input.get(self.pos) else {
                return Err("MalformedXML".into());
            };
            if *next != b'<' {
                let start = self.pos;
                while self.input.get(self.pos).is_some_and(|byte| *byte != b'<') {
                    self.pos += 1;
                }
                let chunk = &self.input[start..self.pos];
                if chunk.contains(&b'&') {
                    return Err("MalformedXML".into());
                }
                text.extend_from_slice(chunk);
                continue;
            }
            if self.starts_with(b"</") {
                self.pos += 2;
                let close_name = self.parse_name()?;
                self.skip_ws();
                if close_name != name || self.input.get(self.pos) != Some(&b'>') {
                    return Err("MalformedXML".into());
                }
                self.pos += 1;
                break;
            }
            if self.starts_with(b"<!") || self.starts_with(b"<?") {
                return Err("MalformedXML".into());
            }
            children.push(self.parse_element(depth + 1)?);
        }
        let text = std::str::from_utf8(&text)
            .map_err(|_| "MalformedXML".to_string())?
            .to_string();
        if !children.is_empty() && !text.trim().is_empty() {
            return Err("MalformedXML".into());
        }
        Ok(XmlNode {
            name,
            text,
            children,
        })
    }

    fn parse_name(&mut self) -> Result<String, String> {
        let start = self.pos;
        while self.input.get(self.pos).is_some_and(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':')
        }) {
            self.pos += 1;
        }
        if self.pos == start {
            return Err("MalformedXML".into());
        }
        std::str::from_utf8(&self.input[start..self.pos])
            .map(str::to_string)
            .map_err(|_| "MalformedXML".to_string())
    }

    fn consume_attribute(&mut self) -> Result<(), String> {
        self.parse_name()?;
        self.skip_ws();
        if self.input.get(self.pos) != Some(&b'=') {
            return Err("MalformedXML".into());
        }
        self.pos += 1;
        self.skip_ws();
        let quote = match self.input.get(self.pos) {
            Some(b'\'' | b'\"') => self.input[self.pos],
            _ => return Err("MalformedXML".into()),
        };
        self.pos += 1;
        while let Some(byte) = self.input.get(self.pos) {
            if *byte == quote {
                self.pos += 1;
                return Ok(());
            }
            if matches!(byte, b'<' | b'&') {
                return Err("MalformedXML".into());
            }
            self.pos += 1;
        }
        Err("MalformedXML".into())
    }

    fn consume_processing_instruction(&mut self) -> Result<(), String> {
        let Some(end) = self.input[self.pos + 5..]
            .windows(2)
            .position(|pair| pair == b"?>")
        else {
            return Err("MalformedXML".into());
        };
        self.pos += 5 + end + 2;
        Ok(())
    }

    fn skip_ws(&mut self) {
        while self.input.get(self.pos).is_some_and(u8::is_ascii_whitespace) {
            self.pos += 1;
        }
    }

    fn starts_with(&self, prefix: &[u8]) -> bool {
        self.input[self.pos..].starts_with(prefix)
    }
}

fn parse_xml_document(body: &[u8]) -> Result<XmlNode, String> {
    if body.is_empty() || std::str::from_utf8(body).is_err() {
        return Err("MalformedXML".into());
    }
    XmlParser::new(body).parse_document()
}

fn local_name(name: &str) -> &str {
    name.rsplit_once(':').map_or(name, |(_, local)| local)
}

fn require_node_name(node: &XmlNode, expected: &str) -> Result<(), String> {
    if local_name(&node.name) == expected {
        Ok(())
    } else {
        Err("MalformedXML".into())
    }
}

fn require_branch_text_empty(node: &XmlNode) -> Result<(), String> {
    if node.text.trim().is_empty() {
        Ok(())
    } else {
        Err("MalformedXML".into())
    }
}

fn require_only_children(node: &XmlNode, allowed: &[&str]) -> Result<(), String> {
    if node
        .children
        .iter()
        .all(|child| allowed.contains(&local_name(&child.name)))
    {
        Ok(())
    } else {
        Err("MalformedXML".into())
    }
}

fn children_named<'a>(node: &'a XmlNode, name: &str) -> Vec<&'a XmlNode> {
    node.children
        .iter()
        .filter(|child| local_name(&child.name) == name)
        .collect()
}

fn required_child<'a>(node: &'a XmlNode, name: &str) -> Result<&'a XmlNode, String> {
    let matches = children_named(node, name);
    if matches.len() == 1 {
        Ok(matches[0])
    } else {
        Err("MalformedXML".into())
    }
}

fn leaf_text(node: &XmlNode) -> Result<&str, String> {
    if !node.children.is_empty() || node.text.trim().is_empty() {
        return Err("MalformedXML".into());
    }
    Ok(node.text.trim())
}

fn optional_positive_period(
    node: &XmlNode,
    name: &str,
    maximum: i64,
) -> Result<Option<i64>, String> {
    let matches = children_named(node, name);
    match matches.as_slice() {
        [] => Ok(None),
        [value] => {
            let text = leaf_text(value)?;
            if !text.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err("MalformedXML".into());
            }
            let value = text
                .parse::<i64>()
                .map_err(|_| "MalformedXML".to_string())?;
            if !(1..=maximum).contains(&value) {
                return Err("MalformedXML".into());
            }
            Ok(Some(value))
        }
        _ => Err("MalformedXML".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legal_hold_blocks() {
        let mut h = HeaderKeyDict::new();
        h.set(SYS_LEGAL_HOLD, "ON");
        assert!(worm_blocks_delete(&h, 0));
        h.set(SYS_LEGAL_HOLD, "OFF");
        assert!(!worm_blocks_delete(&h, 0));
    }

    #[test]
    fn retention_future_blocks() {
        let mut h = HeaderKeyDict::new();
        h.set(SYS_LOCK_MODE, "COMPLIANCE");
        h.set(SYS_RETAIN_UNTIL, "2033-05-18T03:33:20Z");
        assert!(worm_blocks_delete(&h, 1_700_000_000));
        assert!(!worm_blocks_delete(&h, 2_100_000_000));
    }

    #[test]
    fn governance_bypass_allows_delete() {
        let mut h = HeaderKeyDict::new();
        h.set(SYS_LOCK_MODE, "GOVERNANCE");
        h.set(SYS_RETAIN_UNTIL, "2033-05-18T03:33:20Z");
        let now = 1_700_000_000i64;
        // Without bypass → deny.
        assert!(worm_blocks_delete_with_bypass(&h, now, false));
        assert!(!worm_allows_operation(&h, now, false));
        // With bypass → allow (GOVERNANCE + retain-until only).
        assert!(!worm_blocks_delete_with_bypass(&h, now, true));
        assert!(worm_allows_operation(&h, now, true));
        // S3 Boolean header form; arbitrary truthy aliases are rejected.
        assert!(bypass_governance_requested(Some("true")));
        assert!(bypass_governance_requested(Some("True")));
        assert!(!bypass_governance_requested(Some("1")));
        assert!(!bypass_governance_requested(Some("yes")));
        assert!(!bypass_governance_requested(Some("false")));
        assert!(!bypass_governance_requested(None));
        assert_eq!(
            parse_bypass_governance_header(Some("1")),
            Err("InvalidArgument".to_string())
        );
    }

    #[test]
    fn governance_without_bypass_denies() {
        let mut h = HeaderKeyDict::new();
        h.set(SYS_LOCK_MODE, "GOVERNANCE");
        h.set(SYS_RETAIN_UNTIL, "2033-05-18T03:33:20Z");
        let now = 1_700_000_000i64;
        assert!(worm_blocks_delete(&h, now));
        assert!(worm_blocks_delete_with_bypass(&h, now, false));
        assert!(!worm_allows_operation(&h, now, false));
    }

    #[test]
    fn governance_bypass_requires_request_and_iam_authorization() {
        let mut h = HeaderKeyDict::new();
        h.set(SYS_LOCK_MODE, "GOVERNANCE");
        h.set(SYS_RETAIN_UNTIL, "2033-05-18T03:33:20Z");
        let now = 1_700_000_000i64;
        assert_eq!(
            evaluate_object_version_worm(
                &h,
                now,
                GovernanceBypass {
                    requested: true,
                    authorized: false,
                },
            ),
            WormDecision::Deny(WormDenyReason::GovernanceRetention)
        );
        assert_eq!(
            evaluate_object_version_worm(
                &h,
                now,
                GovernanceBypass {
                    requested: true,
                    authorized: true,
                },
            ),
            WormDecision::Allow
        );
    }

    #[test]
    fn compliance_bypass_denied() {
        let mut h = HeaderKeyDict::new();
        h.set(SYS_LOCK_MODE, "COMPLIANCE");
        h.set(SYS_RETAIN_UNTIL, "2033-05-18T03:33:20Z");
        let now = 1_700_000_000i64;
        assert!(worm_blocks_delete_with_bypass(&h, now, true));
        assert!(!worm_allows_operation(&h, now, true));
    }

    #[test]
    fn legal_hold_ignores_governance_bypass() {
        let mut h = HeaderKeyDict::new();
        h.set(SYS_LEGAL_HOLD, "ON");
        h.set(SYS_LOCK_MODE, "GOVERNANCE");
        h.set(SYS_RETAIN_UNTIL, "2033-05-18T03:33:20Z");
        assert!(worm_blocks_delete_with_bypass(&h, 1_700_000_000, true));
        assert!(!worm_allows_operation(&h, 1_700_000_000, true));
    }

    #[test]
    fn expired_retain_allows_even_without_bypass() {
        let mut h = HeaderKeyDict::new();
        h.set(SYS_LOCK_MODE, "GOVERNANCE");
        h.set(SYS_RETAIN_UNTIL, "2001-09-09T01:46:40Z");
        let now = 1_700_000_000i64;
        assert!(!worm_blocks_delete(&h, now));
        assert!(worm_allows_operation(&h, now, false));
        // COMPLIANCE expired also allows.
        h.set(SYS_LOCK_MODE, "COMPLIANCE");
        assert!(!worm_blocks_delete_with_bypass(&h, now, false));
    }

    #[test]
    fn malformed_persisted_lock_fails_closed() {
        let mut h = HeaderKeyDict::new();
        h.set(SYS_LOCK_MODE, "GOVERNANCE");
        h.set(SYS_RETAIN_UNTIL, "not-a-date");
        assert_eq!(
            evaluate_object_version_worm(&h, 1_700_000_000, GovernanceBypass::NONE),
            WormDecision::Deny(WormDenyReason::InvalidPersistedState(
                PersistedLockError::InvalidRetainUntilDate,
            ))
        );
        assert!(worm_blocks_delete_with_bypass(&h, i64::MAX, true));

        h.set(SYS_RETAIN_UNTIL, "");
        assert_eq!(
            object_version_lock_state(&h),
            Err(PersistedLockError::IncompleteRetention)
        );
        h.set(SYS_LOCK_MODE, "");
        h.set(SYS_LEGAL_HOLD, "maybe");
        assert_eq!(
            object_version_lock_state(&h),
            Err(PersistedLockError::InvalidLegalHold)
        );
    }

    #[test]
    fn retention_put_compliance_cannot_shorten_or_downgrade() {
        let mut h = HeaderKeyDict::new();
        h.set(SYS_LOCK_MODE, "COMPLIANCE");
        h.set(SYS_RETAIN_UNTIL, "2030-01-01T00:00:00Z");
        let now = 1_700_000_000i64;
        // Shorten → deny (bypass ignored).
        assert!(worm_blocks_retention_put(
            &h,
            "COMPLIANCE",
            "2028-01-01T00:00:00Z",
            now,
            true
        ));
        // Mode downgrade → deny.
        assert!(worm_blocks_retention_put(
            &h,
            "GOVERNANCE",
            "2035-01-01T00:00:00Z",
            now,
            true
        ));
        // Extend same mode → allow.
        assert!(!worm_blocks_retention_put(
            &h,
            "COMPLIANCE",
            "2035-01-01T00:00:00Z",
            now,
            false
        ));
    }

    #[test]
    fn retention_put_governance_shorten_needs_bypass() {
        let mut h = HeaderKeyDict::new();
        h.set(SYS_LOCK_MODE, "GOVERNANCE");
        h.set(SYS_RETAIN_UNTIL, "2030-01-01T00:00:00Z");
        let now = 1_700_000_000i64;
        assert!(worm_blocks_retention_put(
            &h,
            "GOVERNANCE",
            "2028-01-01T00:00:00Z",
            now,
            false
        ));
        assert!(!worm_blocks_retention_put(
            &h,
            "GOVERNANCE",
            "2028-01-01T00:00:00Z",
            now,
            true
        ));
        // Upgrade to COMPLIANCE (same or later date) → allow.
        assert!(!worm_blocks_retention_put(
            &h,
            "COMPLIANCE",
            "2030-01-01T00:00:00Z",
            now,
            false
        ));
    }

    #[test]
    fn retention_put_no_existing_or_expired_allows() {
        let mut h = HeaderKeyDict::new();
        let now = 1_700_000_000i64;
        assert!(!worm_blocks_retention_put(
            &h,
            "COMPLIANCE",
            "2030-01-01T00:00:00Z",
            now,
            false
        ));
        h.set(SYS_LOCK_MODE, "COMPLIANCE");
        h.set(SYS_RETAIN_UNTIL, "2000-01-01T00:00:00Z");
        assert!(!worm_blocks_retention_put(
            &h,
            "GOVERNANCE",
            "2030-01-01T00:00:00Z",
            now,
            false
        ));
        assert!(worm_blocks_retention_put(
            &h,
            "COMPLIANCE",
            "not-a-date",
            now,
            false
        ));
        assert!(worm_blocks_retention_put(
            &h,
            "BOGUS",
            "2030-01-01T00:00:00Z",
            now,
            false
        ));
        h.set(SYS_RETAIN_UNTIL, "corrupt");
        assert!(worm_blocks_retention_put(
            &h,
            "COMPLIANCE",
            "2030-01-01T00:00:00Z",
            now,
            false
        ));
    }

    #[test]
    fn legal_hold_xml_roundtrip() {
        let xml = legal_hold_xml(true);
        assert!(parse_legal_hold_body(&xml).unwrap());
        assert!(!parse_legal_hold_body(&legal_hold_xml(false)).unwrap());
    }

    #[test]
    fn retention_xml_roundtrip() {
        let xml = retention_xml("GOVERNANCE", "2030-01-01T00:00:00Z");
        let (m, u) = parse_retention_body(&xml).unwrap();
        assert_eq!(m, "GOVERNANCE");
        assert!(u.starts_with("2030"));
    }

    #[test]
    fn retention_date_is_strict_rfc3339() {
        assert_eq!(
            parse_retain_until("2030-01-01T01:00:00+01:00"),
            parse_retain_until("2030-01-01T00:00:00Z")
        );
        assert_eq!(
            parse_retain_until("2024-02-29T00:00:00.123Z"),
            parse_retain_until("2024-02-29T00:00:00Z")
        );
        for invalid in [
            "2000000000",
            "2030-02-29T00:00:00Z",
            "2030-04-31T00:00:00Z",
            "2030-01-01T24:00:00Z",
            "2030-01-01T00:00:60Z",
            "2030-01-01T00:00:00",
            "2030-01-01t00:00:00Z",
            "2030-01-01T00:00:00Zjunk",
        ] {
            assert_eq!(parse_retain_until(invalid), None, "accepted {invalid}");
        }
    }

    #[test]
    fn object_lock_xml_is_structurally_validated() {
        assert!(parse_legal_hold_body(
            br#"<LegalHold><Status>ON</Status><Status>OFF</Status></LegalHold>"#
        )
        .is_err());
        assert!(parse_legal_hold_body(br#"<Other><!-- <Status>ON</Status> --></Other>"#).is_err());
        assert!(parse_legal_hold_body(br#"<LegalHold><Status>on</Status></LegalHold>"#).is_err());
        assert!(parse_retention_body(
            br#"<Retention><Mode>GOVERNANCE</Mode><Mode>COMPLIANCE</Mode><RetainUntilDate>2030-01-01T00:00:00Z</RetainUntilDate></Retention>"#
        )
        .is_err());
        assert!(parse_retention_body(
            br#"<Retention><Mode>governance</Mode><RetainUntilDate>2030-01-01T00:00:00Z</RetainUntilDate></Retention>"#
        )
        .is_err());
    }

    #[test]
    fn explicit_lock_headers_validate_before_mutation() {
        let mut h = HeaderKeyDict::new();
        h.set("X-Amz-Object-Lock-Mode", "GOVERNANCE");
        assert_eq!(
            validate_and_apply_amz_object_lock_headers(&mut h),
            Err("InvalidRequest".to_string())
        );
        assert_eq!(h.get(SYS_LOCK_MODE), None);

        h.set(
            "X-Amz-Object-Lock-Retain-Until-Date",
            "2030-01-01T00:00:00Z",
        );
        h.set("X-Amz-Object-Lock-Legal-Hold", "ON");
        validate_and_apply_amz_object_lock_headers(&mut h).unwrap();
        assert_eq!(h.get(SYS_LOCK_MODE), Some("GOVERNANCE"));
        assert_eq!(h.get(SYS_LEGAL_HOLD), Some("ON"));
    }

    #[test]
    fn default_retention_days_and_stamp() {
        let xml = br#"<ObjectLockConfiguration>
  <ObjectLockEnabled>Enabled</ObjectLockEnabled>
  <Rule><DefaultRetention>
    <Mode>COMPLIANCE</Mode><Days>2</Days>
  </DefaultRetention></Rule>
</ObjectLockConfiguration>"#;
        let def = default_retention_from_lock_xml(xml).unwrap();
        assert_eq!(def.mode, "COMPLIANCE");
        assert_eq!(def.days, Some(2));
        let now = 1_700_000_000i64;
        let until = retain_until_from_default(&def, now);
        assert_eq!(until, now + 2 * 86400);
        let mut h = HeaderKeyDict::new();
        apply_default_retention_headers(&mut h, &def, now);
        assert_eq!(h.get(SYS_LOCK_MODE), Some("COMPLIANCE"));
        let stored = h.get(SYS_RETAIN_UNTIL).unwrap();
        assert!(worm_blocks_delete(&h, now));
        assert!(!worm_blocks_delete(&h, until + 1));
        assert_eq!(parse_retain_until(stored).unwrap(), until);
        // Does not overwrite existing retain-until.
        h.set(SYS_RETAIN_UNTIL, "2099-01-01T00:00:00Z");
        apply_default_retention_headers(&mut h, &def, now);
        assert_eq!(h.get(SYS_RETAIN_UNTIL), Some("2099-01-01T00:00:00Z"));
    }

    #[test]
    fn default_retention_requires_exactly_one_bounded_period() {
        assert!(parse_object_lock_configuration(
            br#"<ObjectLockConfiguration>
  <ObjectLockEnabled>Enabled</ObjectLockEnabled>
  <Rule><DefaultRetention>
    <Mode>COMPLIANCE</Mode><Days>1</Days><Years>1</Years>
  </DefaultRetention></Rule>
</ObjectLockConfiguration>"#
        )
        .is_err());
        assert!(parse_object_lock_configuration(
            br#"<ObjectLockConfiguration>
  <ObjectLockEnabled>Enabled</ObjectLockEnabled>
  <Rule><DefaultRetention><Mode>COMPLIANCE</Mode><Years>101</Years></DefaultRetention></Rule>
</ObjectLockConfiguration>"#
        )
        .is_err());
        assert_eq!(
            parse_object_lock_configuration(
                br#"<ObjectLockConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>"#
            ),
            Ok(None)
        );
    }

    #[test]
    fn format_iso_roundtrip_epoch() {
        assert_eq!(format_retain_until_iso(0), "1970-01-01T00:00:00Z");
        let s = format_retain_until_iso(1_700_000_000);
        assert_eq!(parse_retain_until(&s).unwrap(), 1_700_000_000);
    }

    #[test]
    fn persist_backend_5xx_is_deny_not_unlocked() {
        let empty = HeaderKeyDict::new();
        let unlocked_ok = lock_state_from_backend_status(200, Some(&empty));
        assert!(persist_is_unlocked(&unlocked_ok));
        let unlocked = lock_state_from_backend_status(404, None);
        assert!(persist_is_unlocked(&unlocked));

        let five = lock_state_from_backend_status(503, None);
        assert_eq!(five, Err(PersistError::Backend5xx));
        assert!(!persist_is_unlocked(&five));
        assert_eq!(
            evaluate_object_version_worm_from_backend(
                500,
                None,
                1_700_000_000,
                true,
                GovernanceBypass::NONE,
            ),
            WormDecision::Deny(WormDenyReason::Persist(PersistError::Backend5xx))
        );
        assert_eq!(
            evaluate_object_version_worm_from_backend(
                0,
                None,
                1_700_000_000,
                true,
                GovernanceBypass::NONE,
            ),
            WormDecision::Deny(WormDenyReason::Persist(PersistError::Backend5xx))
        );
    }

    #[test]
    fn persist_malformed_is_deny_not_unlocked() {
        let mut h = HeaderKeyDict::new();
        h.set(SYS_LOCK_MODE, "COMPLIANCE");
        h.set(SYS_RETAIN_UNTIL, "not-a-date");
        let parsed = lock_state_from_backend_status(200, Some(&h));
        assert_eq!(parsed, Err(PersistError::Malformed));
        assert!(!persist_is_unlocked(&parsed));
        assert_eq!(
            evaluate_object_version_worm_from_backend(
                200,
                Some(&h),
                1_700_000_000,
                true,
                GovernanceBypass::NONE,
            ),
            WormDecision::Deny(WormDenyReason::Persist(PersistError::Malformed))
        );
        assert_eq!(
            PersistError::from(PersistedLockError::InvalidLegalHold),
            PersistError::Malformed
        );
    }

    #[test]
    fn clock_ok_false_denies_compliance_claim() {
        let mut h = HeaderKeyDict::new();
        h.set(SYS_LOCK_MODE, "COMPLIANCE");
        h.set(SYS_RETAIN_UNTIL, "2033-05-18T03:33:20Z");
        let now = 1_700_000_000i64;
        assert_eq!(
            evaluate_object_version_worm_with_clock(&h, now, false, GovernanceBypass::NONE),
            WormDecision::Deny(WormDenyReason::ClockUnhealthy)
        );
        // Unhealthy clock cannot treat COMPLIANCE as expired.
        assert_eq!(
            evaluate_object_version_worm_with_clock(&h, i64::MAX, false, GovernanceBypass::NONE),
            WormDecision::Deny(WormDenyReason::ClockUnhealthy)
        );
        let requested = parse_object_retention("COMPLIANCE", "2035-01-01T00:00:00Z").unwrap();
        assert_eq!(
            evaluate_retention_update_with_clock(
                &HeaderKeyDict::new(),
                &requested,
                now,
                false,
                GovernanceBypass::NONE,
            ),
            RetentionUpdateDecision::Deny(RetentionUpdateDenyReason::ClockUnhealthy)
        );
        // GOVERNANCE still evaluates when the clock is marked unhealthy.
        h.set(SYS_LOCK_MODE, "GOVERNANCE");
        assert_eq!(
            evaluate_object_version_worm_with_clock(&h, now, false, GovernanceBypass::NONE),
            WormDecision::Deny(WormDenyReason::GovernanceRetention)
        );
    }

    #[test]
    fn clock_unhealthy_denies_updates_touching_existing_compliance() {
        // Wave-9 fault injection: any retention update that touches an
        // existing COMPLIANCE record must deny when the clock is untrusted,
        // regardless of the requested mode or of apparent expiry.
        let mut existing = HeaderKeyDict::new();
        existing.set(SYS_LOCK_MODE, "COMPLIANCE");
        existing.set(SYS_RETAIN_UNTIL, "2030-01-01T00:00:00Z");
        let now = 1_700_000_000i64;

        // Requested GOVERNANCE over existing COMPLIANCE → ClockUnhealthy,
        // not ComplianceProtected (deny happens before mode comparison).
        let gov = parse_object_retention("GOVERNANCE", "2035-01-01T00:00:00Z").unwrap();
        assert_eq!(
            evaluate_retention_update_with_clock(
                &existing,
                &gov,
                now,
                false,
                GovernanceBypass::NONE,
            ),
            RetentionUpdateDecision::Deny(RetentionUpdateDenyReason::ClockUnhealthy)
        );

        // Extending COMPLIANCE (normally Allow) also denies with a bad clock.
        let extend = parse_object_retention("COMPLIANCE", "2040-01-01T00:00:00Z").unwrap();
        assert_eq!(
            evaluate_retention_update_with_clock(
                &existing,
                &extend,
                now,
                false,
                GovernanceBypass::NONE,
            ),
            RetentionUpdateDecision::Deny(RetentionUpdateDenyReason::ClockUnhealthy)
        );

        // An apparently expired COMPLIANCE record cannot be trusted as
        // expired when the clock is unhealthy: requested GOVERNANCE would
        // normally be allowed (old lock expired), but must deny here.
        existing.set(SYS_RETAIN_UNTIL, "2000-01-01T00:00:00Z");
        assert_eq!(
            evaluate_retention_update_with_clock(
                &existing,
                &gov,
                now,
                false,
                GovernanceBypass::NONE,
            ),
            RetentionUpdateDecision::Deny(RetentionUpdateDenyReason::ClockUnhealthy)
        );
    }

    #[test]
    fn clock_unhealthy_leaves_governance_paths_intact() {
        // clock_ok=false must only affect COMPLIANCE claims. GOVERNANCE
        // decisions (allow and deny) stay exactly as with a healthy clock.
        let now = 1_700_000_000i64;
        let both = GovernanceBypass {
            requested: true,
            authorized: true,
        };

        // New GOVERNANCE retention on an unlocked object → Allow.
        let gov = parse_object_retention("GOVERNANCE", "2035-01-01T00:00:00Z").unwrap();
        assert_eq!(
            evaluate_retention_update_with_clock(
                &HeaderKeyDict::new(),
                &gov,
                now,
                false,
                GovernanceBypass::NONE,
            ),
            RetentionUpdateDecision::Allow
        );

        // GOVERNANCE shorten with effective bypass → Allow even clock-bad.
        let mut existing = HeaderKeyDict::new();
        existing.set(SYS_LOCK_MODE, "GOVERNANCE");
        existing.set(SYS_RETAIN_UNTIL, "2035-01-01T00:00:00Z");
        let shorten = parse_object_retention("GOVERNANCE", "2030-01-01T00:00:00Z").unwrap();
        assert_eq!(
            evaluate_retention_update_with_clock(&existing, &shorten, now, false, both),
            RetentionUpdateDecision::Allow
        );
        // Same shorten without bypass → GovernanceBypassRequired (unchanged).
        assert_eq!(
            evaluate_retention_update_with_clock(
                &existing,
                &shorten,
                now,
                false,
                GovernanceBypass::NONE,
            ),
            RetentionUpdateDecision::Deny(RetentionUpdateDenyReason::GovernanceBypassRequired)
        );

        // Destructive-op eval: expired GOVERNANCE allows, active GOVERNANCE
        // with effective bypass allows — all with clock_ok=false.
        let mut expired = HeaderKeyDict::new();
        expired.set(SYS_LOCK_MODE, "GOVERNANCE");
        expired.set(SYS_RETAIN_UNTIL, "2000-01-01T00:00:00Z");
        assert_eq!(
            evaluate_object_version_worm_with_clock(&expired, now, false, GovernanceBypass::NONE),
            WormDecision::Allow
        );
        assert_eq!(
            evaluate_object_version_worm_with_clock(&existing, now, false, both),
            WormDecision::Allow
        );
    }

    #[test]
    fn backend_eval_clock_unhealthy_denies_compliance_only() {
        // The backend-status entry point honours the same clock rule.
        let now = 1_700_000_000i64;
        let mut comp = HeaderKeyDict::new();
        comp.set(SYS_LOCK_MODE, "COMPLIANCE");
        comp.set(SYS_RETAIN_UNTIL, "2033-05-18T03:33:20Z");
        assert_eq!(
            evaluate_object_version_worm_from_backend(
                200,
                Some(&comp),
                now,
                false,
                GovernanceBypass::NONE,
            ),
            WormDecision::Deny(WormDenyReason::ClockUnhealthy)
        );

        let mut gov = HeaderKeyDict::new();
        gov.set(SYS_LOCK_MODE, "GOVERNANCE");
        gov.set(SYS_RETAIN_UNTIL, "2033-05-18T03:33:20Z");
        assert_eq!(
            evaluate_object_version_worm_from_backend(
                200,
                Some(&gov),
                now,
                false,
                GovernanceBypass::NONE,
            ),
            WormDecision::Deny(WormDenyReason::GovernanceRetention)
        );

        // 404 (no object) stays Allow: nothing locked, clock irrelevant.
        assert_eq!(
            evaluate_object_version_worm_from_backend(
                404,
                None,
                now,
                false,
                GovernanceBypass::NONE,
            ),
            WormDecision::Allow
        );
    }

    #[test]
    fn lock_if_match_token_is_opaque_hex_from_tuple_and_revision() {
        let mut h = HeaderKeyDict::new();
        h.set(SYS_LEGAL_HOLD, "OFF");
        h.set(SYS_LOCK_MODE, "COMPLIANCE");
        h.set(SYS_RETAIN_UNTIL, "2033-05-18T03:33:20Z");
        h.set(SYS_LOCK_REVISION, "3");
        let state = object_version_lock_state(&h).unwrap();
        let token = lock_if_match_token_from_headers(&h).unwrap();
        assert_eq!(token.len(), 64);
        assert!(token.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(token, lock_if_match_token(&state, 3));
        assert_ne!(token, lock_if_match_token(&state, 4));
        assert!(lock_if_match_matches(&token, &token));
        assert!(!lock_if_match_matches(&token, &lock_if_match_token(&state, 4)));
        let until = state.retention.as_ref().unwrap().retain_until_unix;
        assert_eq!(
            canonical_lock_tuple(&state, 3),
            format!("v1|OFF|COMPLIANCE|{until}|3")
        );
    }
}
