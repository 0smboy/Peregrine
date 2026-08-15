// Copyright (c) 2026 OpenStack Foundation
//! Native `/v1` object-mutation lock gate (experimental).
//!
//! Wired on object-server PUT/POST/DELETE of an existing object. A POST
//! that updates only lock sysmeta is not treated as a data overwrite.
//! Not live-proven, not deployed, not a compliance claim. CAS and
//! clock-health are still missing; the write path passes `clock_ok=true`
//! until a clock-health signal exists.
//!
//! This crate cannot depend on `swift-s3api`. The parser here is an
//! independent fail-closed copy of the lock sysmeta rules:
//! malformed headers deny; missing lock headers allow (no lock).

use swift_http::HeaderKeyDict;

pub const SYS_LEGAL_HOLD: &str = "X-Object-Sysmeta-S3-Legal-Hold";
pub const SYS_LOCK_MODE: &str = "X-Object-Sysmeta-S3-Object-Lock-Mode";
pub const SYS_RETAIN_UNTIL: &str = "X-Object-Sysmeta-S3-Retain-Until-Date";
pub const SYS_LOCK_REVISION: &str = "X-Object-Sysmeta-S3-Object-Lock-Revision";

const LOCK_SYS_META: &[&str] = &[
    SYS_LEGAL_HOLD,
    SYS_LOCK_MODE,
    SYS_RETAIN_UNTIL,
    SYS_LOCK_REVISION,
];

/// Governance bypass on the native path still needs both bits.
///
/// Native `/v1` has no S3 IAM; callers must leave this as [`Self::NONE`]
/// unless both the request header and an authorized principal are proven.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NativeGovernanceBypass {
    pub requested: bool,
    pub authorized: bool,
}

impl NativeGovernanceBypass {
    pub const NONE: Self = Self {
        requested: false,
        authorized: false,
    };

    pub const fn effective(self) -> bool {
        self.requested && self.authorized
    }
}

/// Whether a native object-server mutation may proceed against `object_headers`.
///
/// * GET/HEAD/OPTIONS → allow (not a mutation)
/// * lock-sysmeta-only POST → allow (not a data overwrite; see
///   [`is_s3_lock_control_plane_post`])
/// * missing lock headers → allow
/// * malformed lock headers → deny
/// * legal-hold ON → deny (bypass ignored)
/// * COMPLIANCE + `clock_ok=false` → deny
/// * active GOVERNANCE → allow only when `bypass` is header AND authorized
///
/// Lock-sysmeta-only POST is allowed via [`native_mutation_allowed_for`].
/// PUT overwrite and DELETE stay denied when the object is locked.
pub fn native_mutation_allowed(
    method: &str,
    object_headers: &HeaderKeyDict,
    now_unix: i64,
    clock_ok: bool,
    bypass: NativeGovernanceBypass,
) -> bool {
    native_mutation_allowed_for(method, object_headers, None, now_unix, clock_ok, bypass)
}

/// [`native_mutation_allowed`] plus the request headers used to recognize an
/// S3 lock control-plane POST.
pub fn native_mutation_allowed_for(
    method: &str,
    object_headers: &HeaderKeyDict,
    request_headers: Option<&HeaderKeyDict>,
    now_unix: i64,
    clock_ok: bool,
    bypass: NativeGovernanceBypass,
) -> bool {
    if request_headers.is_some_and(|headers| is_s3_lock_control_plane_post(method, headers)) {
        return true;
    }
    if !is_mutation_method(method) {
        return true;
    }
    if !has_lock_headers(object_headers) {
        return true;
    }
    let Ok(state) = parse_native_lock(object_headers) else {
        return false;
    };
    if state.legal_hold_on {
        return false;
    }
    let Some((mode, retain_until_unix)) = state.retention else {
        return true;
    };
    if mode == NativeMode::Compliance && !clock_ok {
        return false;
    }
    if retain_until_unix <= now_unix {
        return true;
    }
    match mode {
        NativeMode::Governance => bypass.effective(),
        NativeMode::Compliance => false,
    }
}

fn is_mutation_method(method: &str) -> bool {
    matches!(
        method.to_ascii_uppercase().as_str(),
        "PUT" | "POST" | "DELETE"
    )
}

/// True when `request_headers` is an S3 Object Lock control-plane POST:
/// only lock sysmeta (`Legal-Hold` / `Object-Lock-Mode` / `Retain-Until-Date`
/// / `Object-Lock-Revision`) and not a data overwrite.
pub fn is_s3_lock_control_plane_post(method: &str, request_headers: &HeaderKeyDict) -> bool {
    if !method.eq_ignore_ascii_case("POST") {
        return false;
    }
    let mut saw_lock = false;
    for (key, value) in request_headers.iter() {
        if value.trim().is_empty() {
            continue;
        }
        if is_lock_sysmeta_key(key) {
            saw_lock = true;
            continue;
        }
        if is_lock_post_transport_header(key) {
            continue;
        }
        if is_object_persistable_header(key) {
            return false;
        }
    }
    saw_lock
}

fn is_lock_sysmeta_key(key: &str) -> bool {
    LOCK_SYS_META
        .iter()
        .any(|name| key.eq_ignore_ascii_case(name))
}

fn is_lock_post_transport_header(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "x-timestamp"
            | "content-type"
            | "content-type-timestamp"
            | "content-length"
            | "content-md5"
            | "etag"
            | "authorization"
            | "x-auth-token"
            | "host"
            | "user-agent"
            | "expect"
            | "date"
            | "connection"
            | "transfer-encoding"
            | "accept"
            | "x-trans-id"
    ) || lower.starts_with("x-backend-")
}

fn is_object_persistable_header(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    (lower.starts_with("x-object-meta-") && lower.len() > "x-object-meta-".len())
        || (lower.starts_with("x-object-sysmeta-") && lower.len() > "x-object-sysmeta-".len())
        || (lower.starts_with("x-object-transient-sysmeta-")
            && lower.len() > "x-object-transient-sysmeta-".len())
        || matches!(
            lower.as_str(),
            "x-object-manifest"
                | "x-static-large-object"
                | "content-disposition"
                | "content-encoding"
                | "content-language"
                | "cache-control"
                | "expires"
                | "x-robots-tag"
                | "x-delete-at"
                | "x-delete-after"
        )
}

fn has_lock_headers(headers: &HeaderKeyDict) -> bool {
    header_present(headers, SYS_LEGAL_HOLD)
        || header_present(headers, SYS_LOCK_MODE)
        || header_present(headers, SYS_RETAIN_UNTIL)
}

fn header_present(headers: &HeaderKeyDict, key: &str) -> bool {
    headers
        .get(key)
        .is_some_and(|value| !value.trim().is_empty())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NativeMode {
    Governance,
    Compliance,
}

struct NativeLock {
    legal_hold_on: bool,
    retention: Option<(NativeMode, i64)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NativeLockError {
    Malformed,
}

fn parse_native_lock(headers: &HeaderKeyDict) -> Result<NativeLock, NativeLockError> {
    let legal_hold_on = match headers.get(SYS_LEGAL_HOLD).map(str::trim) {
        None | Some("") | Some("OFF") => false,
        Some("ON") => true,
        Some(_) => return Err(NativeLockError::Malformed),
    };
    let mode = headers
        .get(SYS_LOCK_MODE)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let until = headers
        .get(SYS_RETAIN_UNTIL)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let retention = match (mode, until) {
        (None, None) => None,
        (Some(_), None) | (None, Some(_)) => return Err(NativeLockError::Malformed),
        (Some(mode), Some(until)) => {
            let mode = match mode {
                "GOVERNANCE" => NativeMode::Governance,
                "COMPLIANCE" => NativeMode::Compliance,
                _ => return Err(NativeLockError::Malformed),
            };
            let retain_until_unix = parse_retain_until(until).ok_or(NativeLockError::Malformed)?;
            Some((mode, retain_until_unix))
        }
    };
    Ok(NativeLock {
        legal_hold_on,
        retention,
    })
}

/// RFC3339 retain-until used by lock sysmeta. Invalid input is None (deny).
fn parse_retain_until(s: &str) -> Option<i64> {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn locked_compliance() -> HeaderKeyDict {
        let mut headers = HeaderKeyDict::new();
        headers.set(SYS_LOCK_MODE, "COMPLIANCE");
        headers.set(SYS_RETAIN_UNTIL, "2033-05-18T03:33:20Z");
        headers
    }

    #[test]
    fn native_delete_denied_when_locked() {
        let headers = locked_compliance();
        assert!(!native_mutation_allowed(
            "DELETE",
            &headers,
            1_700_000_000,
            true,
            NativeGovernanceBypass::NONE,
        ));
        assert!(!native_mutation_allowed(
            "PUT",
            &headers,
            1_700_000_000,
            true,
            NativeGovernanceBypass::NONE,
        ));
        assert!(!native_mutation_allowed(
            "POST",
            &headers,
            1_700_000_000,
            true,
            NativeGovernanceBypass::NONE,
        ));
    }

    #[test]
    fn native_delete_allowed_when_unlocked() {
        let headers = HeaderKeyDict::new();
        assert!(native_mutation_allowed(
            "DELETE",
            &headers,
            1_700_000_000,
            true,
            NativeGovernanceBypass::NONE,
        ));
        assert!(native_mutation_allowed(
            "PUT",
            &headers,
            1_700_000_000,
            false,
            NativeGovernanceBypass::NONE,
        ));
    }

    #[test]
    fn malformed_lock_headers_deny() {
        let mut headers = HeaderKeyDict::new();
        headers.set(SYS_LOCK_MODE, "COMPLIANCE");
        headers.set(SYS_RETAIN_UNTIL, "not-a-date");
        assert!(!native_mutation_allowed(
            "DELETE",
            &headers,
            1_700_000_000,
            true,
            NativeGovernanceBypass::NONE,
        ));
        headers = HeaderKeyDict::new();
        headers.set(SYS_LOCK_MODE, "GOVERNANCE");
        assert!(!native_mutation_allowed(
            "PUT",
            &headers,
            1_700_000_000,
            true,
            NativeGovernanceBypass::NONE,
        ));
    }

    #[test]
    fn legal_hold_ignores_bypass() {
        let mut headers = HeaderKeyDict::new();
        headers.set(SYS_LEGAL_HOLD, "ON");
        let bypass = NativeGovernanceBypass {
            requested: true,
            authorized: true,
        };
        assert!(!native_mutation_allowed(
            "DELETE",
            &headers,
            1_700_000_000,
            true,
            bypass,
        ));
    }

    #[test]
    fn governance_header_only_denies_native() {
        let mut headers = HeaderKeyDict::new();
        headers.set(SYS_LOCK_MODE, "GOVERNANCE");
        headers.set(SYS_RETAIN_UNTIL, "2033-05-18T03:33:20Z");
        let header_only = NativeGovernanceBypass {
            requested: true,
            authorized: false,
        };
        assert!(!native_mutation_allowed(
            "DELETE",
            &headers,
            1_700_000_000,
            true,
            header_only,
        ));
        let both = NativeGovernanceBypass {
            requested: true,
            authorized: true,
        };
        assert!(native_mutation_allowed(
            "DELETE",
            &headers,
            1_700_000_000,
            true,
            both,
        ));
    }

    #[test]
    fn clock_ok_false_denies_compliance() {
        let headers = locked_compliance();
        assert!(!native_mutation_allowed(
            "DELETE",
            &headers,
            i64::MAX,
            false,
            NativeGovernanceBypass::NONE,
        ));
    }

    #[test]
    fn unlocked_put_ok() {
        let headers = HeaderKeyDict::new();
        assert!(native_mutation_allowed(
            "PUT",
            &headers,
            1_700_000_000,
            true,
            NativeGovernanceBypass::NONE,
        ));
    }

    #[test]
    fn legal_hold_delete_deny() {
        let mut headers = HeaderKeyDict::new();
        headers.set(SYS_LEGAL_HOLD, "ON");
        assert!(!native_mutation_allowed(
            "DELETE",
            &headers,
            1_700_000_000,
            true,
            NativeGovernanceBypass::NONE,
        ));
    }

    #[test]
    fn compliance_future_delete_deny() {
        let headers = locked_compliance();
        assert!(!native_mutation_allowed(
            "DELETE",
            &headers,
            1_700_000_000,
            true,
            NativeGovernanceBypass::NONE,
        ));
    }

    #[test]
    fn missing_headers_allow() {
        let headers = HeaderKeyDict::new();
        for method in ["PUT", "POST", "DELETE"] {
            assert!(native_mutation_allowed(
                method,
                &headers,
                1_700_000_000,
                true,
                NativeGovernanceBypass::NONE,
            ));
        }
    }

    #[test]
    fn get_is_not_a_mutation() {
        let mut headers = locked_compliance();
        headers.set(SYS_LEGAL_HOLD, "ON");
        assert!(native_mutation_allowed(
            "GET",
            &headers,
            1_700_000_000,
            true,
            NativeGovernanceBypass::NONE,
        ));
        assert!(native_mutation_allowed(
            "HEAD",
            &headers,
            1_700_000_000,
            false,
            NativeGovernanceBypass::NONE,
        ));
    }

    #[test]
    fn lock_control_plane_post_is_not_denied() {
        let object = locked_compliance();
        let mut lock_only = HeaderKeyDict::new();
        lock_only.set(SYS_LEGAL_HOLD, "ON");
        lock_only.set(SYS_LOCK_REVISION, "1");
        assert!(is_s3_lock_control_plane_post("POST", &lock_only));
        assert!(native_mutation_allowed_for(
            "POST",
            &object,
            Some(&lock_only),
            1_700_000_000,
            true,
            NativeGovernanceBypass::NONE,
        ));

        let put_lock = lock_only.clone();
        assert!(!is_s3_lock_control_plane_post("PUT", &put_lock));
        assert!(!native_mutation_allowed_for(
            "PUT",
            &object,
            Some(&put_lock),
            1_700_000_000,
            true,
            NativeGovernanceBypass::NONE,
        ));

        let mut extra_meta = lock_only;
        extra_meta.set("X-Object-Meta-Color", "blue");
        assert!(!is_s3_lock_control_plane_post("POST", &extra_meta));
        assert!(!native_mutation_allowed_for(
            "POST",
            &object,
            Some(&extra_meta),
            1_700_000_000,
            true,
            NativeGovernanceBypass::NONE,
        ));
    }
}
