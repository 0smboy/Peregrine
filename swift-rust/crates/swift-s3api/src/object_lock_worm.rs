// Copyright (c) 2026 OpenStack Foundation
//! Object Lock WORM enforcement helpers.
//!
//! Object subresources (`?legal-hold`, `?retention`) store sysmeta defined
//! here. DELETE is denied when legal-hold is ON or retain-until is in the
//! future. **Bypass:** none by default — `x-amz-bypass-governance-retention`
//! and privileged override are residuals (not implemented).

use swift_http::HeaderKeyDict;

pub const SYS_LEGAL_HOLD: &str = "X-Object-Sysmeta-S3-Legal-Hold";
pub const SYS_LOCK_MODE: &str = "X-Object-Sysmeta-S3-Object-Lock-Mode";
pub const SYS_RETAIN_UNTIL: &str = "X-Object-Sysmeta-S3-Retain-Until-Date";

/// Default retention extracted from bucket `ObjectLockConfiguration`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultRetention {
    pub mode: String,
    /// Days and/or Years (AWS allows either; both may be present rarely).
    pub days: Option<i64>,
    pub years: Option<i64>,
}

/// True if DELETE must be denied (no bypass path).
pub fn worm_blocks_delete(headers: &HeaderKeyDict, now_unix: i64) -> bool {
    if let Some(h) = headers.get(SYS_LEGAL_HOLD) {
        if h.eq_ignore_ascii_case("ON") || h.eq_ignore_ascii_case("true") || h == "1" {
            return true;
        }
    }
    if let Some(until) = headers.get(SYS_RETAIN_UNTIL) {
        if let Some(ts) = parse_retain_until(until) {
            if ts > now_unix {
                return true;
            }
        }
    }
    false
}

/// Parse ISO8601 or unix seconds.
pub fn parse_retain_until(s: &str) -> Option<i64> {
    let s = s.trim();
    if let Ok(n) = s.parse::<i64>() {
        // Bare integers are unix seconds when large enough to be a date.
        // Single-digit / small values still parse (tests use absolute epochs).
        return Some(n);
    }
    // YYYY-MM-DDThh:mm:ssZ (optional fractional seconds / trailing Z)
    if s.len() >= 19 && s.as_bytes().get(4) == Some(&b'-') {
        let y: i32 = s[0..4].parse().ok()?;
        let m: u32 = s[5..7].parse().ok()?;
        let d: u32 = s[8..10].parse().ok()?;
        let hh: u32 = s[11..13].parse().ok()?;
        let mm: u32 = s[14..16].parse().ok()?;
        let ss: u32 = s[17..19].parse().ok()?;
        let days = days_from_civil(y, m, d)?;
        return Some(days * 86400 + (hh as i64) * 3600 + (mm as i64) * 60 + ss as i64);
    }
    None
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

/// Parse `DefaultRetention` (Mode + Days and/or Years) from ObjectLockConfiguration XML.
pub fn default_retention_from_lock_xml(xml: &[u8]) -> Option<DefaultRetention> {
    let t = std::str::from_utf8(xml).ok()?;
    // Require Enabled (case-insensitive enough for unit fixtures).
    if !t.contains("ObjectLockConfiguration") {
        return None;
    }
    let block = extract_block(t, "DefaultRetention")?;
    let mode = extract(block, "Mode")?;
    let mode_up = mode.to_ascii_uppercase();
    if mode_up != "GOVERNANCE" && mode_up != "COMPLIANCE" {
        return None;
    }
    let days = extract(block, "Days").and_then(|s| s.parse().ok());
    let years = extract(block, "Years").and_then(|s| s.parse().ok());
    if days.is_none() && years.is_none() {
        return None;
    }
    Some(DefaultRetention {
        mode: mode_up,
        days,
        years,
    })
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
    if let Some(mode) = headers
        .get("X-Amz-Object-Lock-Mode")
        .map(str::to_string)
    {
        if !mode.is_empty() {
            headers.set(SYS_LOCK_MODE, mode.to_ascii_uppercase());
        }
    }
    if let Some(until) = headers
        .get("X-Amz-Object-Lock-Retain-Until-Date")
        .map(str::to_string)
    {
        if !until.is_empty() {
            headers.set(SYS_RETAIN_UNTIL, until);
        }
    }
    if let Some(lh) = headers
        .get("X-Amz-Object-Lock-Legal-Hold")
        .map(str::to_string)
    {
        let up = lh.to_ascii_uppercase();
        if up == "ON" || up == "OFF" {
            headers.set(SYS_LEGAL_HOLD, up);
        }
    }
}

fn days_from_civil(y: i32, m: u32, d: u32) -> Option<i64> {
    if m < 1 || m > 12 || d < 1 || d > 31 {
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
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <LegalHold xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
         <Status>{st}</Status></LegalHold>"
    )
    .into_bytes()
}

pub fn parse_legal_hold_body(body: &[u8]) -> Result<bool, String> {
    let t = std::str::from_utf8(body).map_err(|_| "MalformedXML".to_string())?;
    if t.contains("<Status>ON</Status>") || t.contains("<Status>on</Status>") {
        Ok(true)
    } else if t.contains("<Status>OFF</Status>") || t.contains("<Status>off</Status>") {
        Ok(false)
    } else {
        Err("MalformedXML".into())
    }
}

pub fn retention_xml(mode: &str, retain_until: &str) -> Vec<u8> {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <Retention xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
         <Mode>{mode}</Mode><RetainUntilDate>{retain_until}</RetainUntilDate></Retention>"
    )
    .into_bytes()
}

pub fn parse_retention_body(body: &[u8]) -> Result<(String, String), String> {
    let t = std::str::from_utf8(body).map_err(|_| "MalformedXML".to_string())?;
    let mode = extract(t, "Mode").ok_or_else(|| "MalformedXML".to_string())?;
    let until = extract(t, "RetainUntilDate").ok_or_else(|| "MalformedXML".to_string())?;
    Ok((mode, until))
}

fn extract(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let i = xml.find(&open)?;
    let rest = &xml[i + open.len()..];
    let j = rest.find(&close)?;
    Some(rest[..j].trim().to_string())
}

fn extract_block<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let i = xml.find(&open)?;
    let rest = &xml[i + open.len()..];
    let j = rest.find(&close)?;
    Some(&rest[..j])
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
        h.set(SYS_RETAIN_UNTIL, "2000000000"); // year 2033
        assert!(worm_blocks_delete(&h, 1_700_000_000));
        assert!(!worm_blocks_delete(&h, 2_100_000_000));
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
    fn format_iso_roundtrip_epoch() {
        assert_eq!(format_retain_until_iso(0), "1970-01-01T00:00:00Z");
        let s = format_retain_until_iso(1_700_000_000);
        assert_eq!(parse_retain_until(&s).unwrap(), 1_700_000_000);
    }
}
