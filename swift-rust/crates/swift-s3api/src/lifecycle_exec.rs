// Copyright (c) 2026 OpenStack Foundation
//! Execute S3 lifecycle rules on object PUT / MPU init.
//!
//! # Expiration (KEEP)
//! Parses stored `LifecycleConfiguration` XML (bucket meta) for **Enabled**
//! rules with `Expiration` **Days** or **Date** and an optional **Prefix**
//! (`Prefix` or `Filter/Prefix`). On object PUT the matching rule stamps
//! `X-Delete-At = now + Days*86400` (or absolute Date), which the object
//! expirer honors.
//!
//! # Transition (metadata stamp only — LAB-HARD-GREEN)
//! Enabled rules with `<Transition><Days|Date><StorageClass>` stamp
//! observability meta on object PUT:
//! * `X-Object-Meta-S3-Storage-Class` = StorageClass
//! * `X-Object-Sysmeta-S3-Transition-At` = unix seconds when transition applies
//!
//! **No tiering backend is faked.** This is an explicit metadata stamp so
//! operators / clients can observe intended class; data remains in the
//! primary Swift store.
//!
//! # AbortIncompleteMultipartUpload
//! Enabled rules with `<AbortIncompleteMultipartUpload><DaysAfterInitiation>`
//! are applied when creating the MPU upload marker: stamp `X-Delete-At =
//! now + Days*86400` so the object expirer reaps incomplete uploads.
//! Also stamps `X-Object-Sysmeta-S3-Abort-Mpu-Days` for observability.
//!
//! Pure functions live here so callers do not depend on concurrent edits to
//! [`crate::bucket_config`].

use swift_http::HeaderKeyDict;

use crate::bucket_config::lifecycle_xml_from_headers;

const SECONDS_PER_DAY: i64 = 86_400;

/// Object user-meta: intended S3 storage class from a Transition rule.
pub const META_STORAGE_CLASS: &str = "X-Object-Meta-S3-Storage-Class";
/// Object sysmeta: unix seconds at which Transition applies (observability).
pub const SYS_TRANSITION_AT: &str = "X-Object-Sysmeta-S3-Transition-At";
/// Object sysmeta on MPU marker: DaysAfterInitiation from abort rule.
pub const SYS_ABORT_MPU_DAYS: &str = "X-Object-Sysmeta-S3-Abort-Mpu-Days";

/// One Enabled expiration rule (subset of LifecycleConfiguration).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpirationRule {
    /// Key prefix (empty = match all).
    pub prefix: String,
    pub days: Option<i64>,
    pub date_unix: Option<i64>,
}

/// One Enabled Transition rule (metadata stamp only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionRule {
    pub prefix: String,
    pub days: Option<i64>,
    pub date_unix: Option<i64>,
    pub storage_class: String,
}

/// One Enabled AbortIncompleteMultipartUpload rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbortIncompleteRule {
    pub prefix: String,
    pub days_after_initiation: i64,
}

/// Parse LifecycleConfiguration XML for Enabled Expiration Days/Date rules.
pub fn parse_expiration_rules(xml: &[u8]) -> Vec<ExpirationRule> {
    let text = match std::str::from_utf8(xml) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    let mut rules = Vec::new();
    for body in each_enabled_rule(text) {
        let Some(exp) = extract_inner(body, "Expiration") else {
            continue;
        };
        let days = extract_tag(exp, "Days").and_then(|s| s.parse().ok());
        let date_unix = extract_tag(exp, "Date").and_then(|s| parse_iso8601_date(&s));
        if days.is_none() && date_unix.is_none() {
            continue;
        }
        rules.push(ExpirationRule {
            prefix: rule_prefix(body),
            days,
            date_unix,
        });
    }
    rules
}

/// Parse Enabled Transition rules (Days|Date + StorageClass + Prefix/Filter).
pub fn parse_transition_rules(xml: &[u8]) -> Vec<TransitionRule> {
    let text = match std::str::from_utf8(xml) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    let mut rules = Vec::new();
    for body in each_enabled_rule(text) {
        let Some(tr) = extract_inner(body, "Transition") else {
            continue;
        };
        let storage_class = match extract_tag(tr, "StorageClass") {
            Some(s) if !s.is_empty() => s,
            _ => continue,
        };
        let days = extract_tag(tr, "Days").and_then(|s| s.parse().ok());
        let date_unix = extract_tag(tr, "Date").and_then(|s| parse_iso8601_date(&s));
        if days.is_none() && date_unix.is_none() {
            continue;
        }
        rules.push(TransitionRule {
            prefix: rule_prefix(body),
            days,
            date_unix,
            storage_class,
        });
    }
    rules
}

/// Parse Enabled AbortIncompleteMultipartUpload rules.
pub fn parse_abort_incomplete_rules(xml: &[u8]) -> Vec<AbortIncompleteRule> {
    let text = match std::str::from_utf8(xml) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    let mut rules = Vec::new();
    for body in each_enabled_rule(text) {
        let Some(abort) = extract_inner(body, "AbortIncompleteMultipartUpload") else {
            continue;
        };
        let Some(days) = extract_tag(abort, "DaysAfterInitiation").and_then(|s| s.parse().ok())
        else {
            continue;
        };
        if days < 0 {
            continue;
        }
        rules.push(AbortIncompleteRule {
            prefix: rule_prefix(body),
            days_after_initiation: days,
        });
    }
    rules
}

fn each_enabled_rule(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("<Rule>") {
        let after = &rest[start + 6..];
        let end = match after.find("</Rule>") {
            Some(i) => i,
            None => break,
        };
        let body = &after[..end];
        rest = &after[end + 7..];
        if status_enabled(body) {
            out.push(body);
        }
    }
    out
}

fn status_enabled(rule_body: &str) -> bool {
    extract_tag(rule_body, "Status")
        .map(|s| s.eq_ignore_ascii_case("Enabled"))
        .unwrap_or(false)
}

fn rule_prefix(rule_body: &str) -> String {
    if let Some(filter) = extract_inner(rule_body, "Filter") {
        if let Some(p) = extract_tag(filter, "Prefix") {
            return p;
        }
    }
    extract_tag(rule_body, "Prefix").unwrap_or_default()
}

fn extract_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let i = xml.find(&open)?;
    let rest = &xml[i + open.len()..];
    let j = rest.find(&close)?;
    Some(rest[..j].trim().to_string())
}

fn extract_inner<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let i = xml.find(&open)?;
    let rest = &xml[i + open.len()..];
    let j = rest.find(&close)?;
    Some(&rest[..j])
}

/// Parse `YYYY-MM-DD` or `YYYY-MM-DDThh:mm:ssZ` to unix seconds (date-only → midnight UTC).
fn parse_iso8601_date(s: &str) -> Option<i64> {
    let s = s.trim();
    let date = if s.len() >= 10 { &s[..10] } else { return None };
    let mut parts = date.split('-');
    let y: i32 = parts.next()?.parse().ok()?;
    let m: u32 = parts.next()?.parse().ok()?;
    let d: u32 = parts.next()?.parse().ok()?;
    let mut hour = 0u32;
    let mut min = 0u32;
    let mut sec = 0u32;
    if let Some(tpos) = s.find('T').or_else(|| s.find('t')) {
        let t = &s[tpos + 1..];
        let t = t.trim_end_matches('Z').trim_end_matches('z');
        let t = t.split('.').next().unwrap_or(t);
        let mut tp = t.split(':');
        hour = tp.next()?.parse().ok()?;
        min = tp.next().unwrap_or("0").parse().ok()?;
        sec = tp.next().unwrap_or("0").parse().ok()?;
    }
    let days = days_from_civil(y, m, d)?;
    Some(days * SECONDS_PER_DAY + i64::from(hour) * 3600 + i64::from(min) * 60 + i64::from(sec))
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

fn prefix_matches(prefix: &str, object_key: &str) -> bool {
    prefix.is_empty() || object_key.starts_with(prefix)
}

fn schedule_at(days: Option<i64>, date_unix: Option<i64>, now_unix: i64) -> Option<i64> {
    if let Some(days) = days {
        Some(now_unix.saturating_add(days.saturating_mul(SECONDS_PER_DAY)))
    } else {
        date_unix
    }
}

/// Pure: Unix `X-Delete-At` for `object_key` under parsed rules.
///
/// * **Days** → `now_unix + days * 86400`
/// * **Date** → absolute Unix
/// * Prefix: empty matches all; otherwise key must start with prefix
/// * Multiple matches → earliest (`min`) delete-at
pub fn compute_delete_at_from_rules(
    rules: &[ExpirationRule],
    object_key: &str,
    now_unix: i64,
) -> Option<i64> {
    let mut best: Option<i64> = None;
    for r in rules {
        if !prefix_matches(&r.prefix, object_key) {
            continue;
        }
        let Some(at) = schedule_at(r.days, r.date_unix, now_unix) else {
            continue;
        };
        best = Some(match best {
            Some(b) => b.min(at),
            None => at,
        });
    }
    best
}

/// Pure: parse lifecycle XML then compute delete-at for the object key.
pub fn compute_delete_at(
    lifecycle_xml: &[u8],
    object_key: &str,
    now_unix: i64,
) -> Option<i64> {
    let rules = parse_expiration_rules(lifecycle_xml);
    compute_delete_at_from_rules(&rules, object_key, now_unix)
}

/// Alias used by some call sites / tests.
pub fn lifecycle_delete_at_for_object(
    lifecycle_xml: &[u8],
    object_key: &str,
    now_unix: i64,
) -> Option<i64> {
    compute_delete_at(lifecycle_xml, object_key, now_unix)
}

/// Matching Transition for `object_key`: earliest transition-at wins;
/// returns `(storage_class, transition_at_unix)`.
pub fn compute_transition_from_rules(
    rules: &[TransitionRule],
    object_key: &str,
    now_unix: i64,
) -> Option<(String, i64)> {
    let mut best: Option<(String, i64)> = None;
    for r in rules {
        if !prefix_matches(&r.prefix, object_key) {
            continue;
        }
        let Some(at) = schedule_at(r.days, r.date_unix, now_unix) else {
            continue;
        };
        best = Some(match best {
            Some((sc, b)) if b <= at => (sc, b),
            _ => (r.storage_class.clone(), at),
        });
    }
    best
}

/// Pure: parse lifecycle XML then compute transition stamp for the key.
pub fn compute_transition(
    lifecycle_xml: &[u8],
    object_key: &str,
    now_unix: i64,
) -> Option<(String, i64)> {
    let rules = parse_transition_rules(lifecycle_xml);
    compute_transition_from_rules(&rules, object_key, now_unix)
}

/// Pure: DaysAfterInitiation for incomplete MPU of `object_key` (min if multiple).
pub fn compute_abort_mpu_days_from_rules(
    rules: &[AbortIncompleteRule],
    object_key: &str,
) -> Option<i64> {
    let mut best: Option<i64> = None;
    for r in rules {
        if !prefix_matches(&r.prefix, object_key) {
            continue;
        }
        best = Some(match best {
            Some(b) => b.min(r.days_after_initiation),
            None => r.days_after_initiation,
        });
    }
    best
}

/// Pure: parse lifecycle XML then abort-days for the object key.
pub fn compute_abort_mpu_days(lifecycle_xml: &[u8], object_key: &str) -> Option<i64> {
    let rules = parse_abort_incomplete_rules(lifecycle_xml);
    compute_abort_mpu_days_from_rules(&rules, object_key)
}

/// Apply helper: if lifecycle XML has a matching Enabled Expiration rule,
/// set `X-Delete-At` on `headers`. No-op when no match.
pub fn apply_lifecycle_delete_at(
    headers: &mut HeaderKeyDict,
    lifecycle_xml: &[u8],
    object_key: &str,
    now_unix: i64,
) {
    if let Some(at) = compute_delete_at(lifecycle_xml, object_key, now_unix) {
        headers.set("X-Delete-At", at.to_string());
    }
}

/// Apply Transition metadata stamp (LAB-HARD-GREEN; no tiering backend).
///
/// Sets [`META_STORAGE_CLASS`] and [`SYS_TRANSITION_AT`] when a matching
/// Enabled Transition rule exists. Does not move data.
pub fn apply_lifecycle_transition_meta(
    headers: &mut HeaderKeyDict,
    lifecycle_xml: &[u8],
    object_key: &str,
    now_unix: i64,
) {
    if let Some((storage_class, at)) = compute_transition(lifecycle_xml, object_key, now_unix) {
        headers.set(META_STORAGE_CLASS, storage_class);
        headers.set(SYS_TRANSITION_AT, at.to_string());
    }
}

/// Stamp `X-Delete-At` on an MPU upload marker from AbortIncomplete rules.
///
/// Practical path: `X-Delete-At = now + DaysAfterInitiation * 86400` so the
/// Swift expirer cleans incomplete multiparts. Also sets [`SYS_ABORT_MPU_DAYS`].
pub fn apply_abort_incomplete_on_marker(
    headers: &mut HeaderKeyDict,
    lifecycle_xml: &[u8],
    object_key: &str,
    now_unix: i64,
) {
    if let Some(days) = compute_abort_mpu_days(lifecycle_xml, object_key) {
        let at = now_unix.saturating_add(days.saturating_mul(SECONDS_PER_DAY));
        headers.set("X-Delete-At", at.to_string());
        headers.set(SYS_ABORT_MPU_DAYS, days.to_string());
    }
}

/// Apply from container HEAD headers (reads `S3_LIFECYCLE_META` blob).
pub fn apply_lifecycle_delete_at_from_container(
    object_headers: &mut HeaderKeyDict,
    container_headers: &HeaderKeyDict,
    object_key: &str,
    now_unix: i64,
) {
    if let Some(xml) = lifecycle_xml_from_headers(container_headers) {
        apply_lifecycle_delete_at(object_headers, &xml, object_key, now_unix);
    }
}

/// Apply Expiration + Transition from container HEAD headers on object PUT.
pub fn apply_lifecycle_on_put_from_container(
    object_headers: &mut HeaderKeyDict,
    container_headers: &HeaderKeyDict,
    object_key: &str,
    now_unix: i64,
) {
    if let Some(xml) = lifecycle_xml_from_headers(container_headers) {
        // Leave client-supplied X-Delete-At alone (expiration only).
        if object_headers.get("X-Delete-At").is_none() {
            apply_lifecycle_delete_at(object_headers, &xml, object_key, now_unix);
        }
        apply_lifecycle_transition_meta(object_headers, &xml, object_key, now_unix);
    }
}

/// Apply AbortIncomplete from container HEAD onto MPU marker headers.
pub fn apply_abort_incomplete_from_container(
    marker_headers: &mut HeaderKeyDict,
    container_headers: &HeaderKeyDict,
    object_key: &str,
    now_unix: i64,
) {
    if let Some(xml) = lifecycle_xml_from_headers(container_headers) {
        apply_abort_incomplete_on_marker(marker_headers, &xml, object_key, now_unix);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bucket_config::{apply_lifecycle_meta, S3_LIFECYCLE_META};

    const LC_DAYS1_PREFIX: &[u8] = br#"<?xml version="1.0"?>
<LifecycleConfiguration>
  <Rule>
    <ID>expire-logs</ID>
    <Status>Enabled</Status>
    <Filter><Prefix>logs/</Prefix></Filter>
    <Expiration><Days>1</Days></Expiration>
  </Rule>
  <Rule>
    <ID>disabled</ID>
    <Status>Disabled</Status>
    <Filter><Prefix></Prefix></Filter>
    <Expiration><Days>1</Days></Expiration>
  </Rule>
</LifecycleConfiguration>"#;

    const LC_TRANSITION_ABORT: &[u8] = br#"<?xml version="1.0"?>
<LifecycleConfiguration>
  <Rule>
    <ID>trans-logs</ID>
    <Status>Enabled</Status>
    <Filter><Prefix>logs/</Prefix></Filter>
    <Transition>
      <Days>30</Days>
      <StorageClass>GLACIER</StorageClass>
    </Transition>
    <Expiration><Days>90</Days></Expiration>
    <AbortIncompleteMultipartUpload>
      <DaysAfterInitiation>7</DaysAfterInitiation>
    </AbortIncompleteMultipartUpload>
  </Rule>
  <Rule>
    <ID>trans-date</ID>
    <Status>Enabled</Status>
    <Prefix>archive/</Prefix>
    <Transition>
      <Date>2025-06-01T00:00:00.000Z</Date>
      <StorageClass>STANDARD_IA</StorageClass>
    </Transition>
  </Rule>
  <Rule>
    <ID>disabled-trans</ID>
    <Status>Disabled</Status>
    <Filter><Prefix>logs/</Prefix></Filter>
    <Transition>
      <Days>1</Days>
      <StorageClass>DEEP_ARCHIVE</StorageClass>
    </Transition>
  </Rule>
</LifecycleConfiguration>"#;

    #[test]
    fn compute_delete_at_days_one() {
        let now = 1_700_000_000i64;
        let at = compute_delete_at(LC_DAYS1_PREFIX, "logs/a.txt", now).unwrap();
        assert_eq!(at, now + 86_400);
    }

    #[test]
    fn compute_delete_at_prefix_filter() {
        let now = 1_700_000_000i64;
        assert!(compute_delete_at(LC_DAYS1_PREFIX, "logs/a.txt", now).is_some());
        assert!(compute_delete_at(LC_DAYS1_PREFIX, "other/a", now).is_none());
        assert!(compute_delete_at(LC_DAYS1_PREFIX, "log", now).is_none());
    }

    #[test]
    fn disabled_rule_ignored() {
        let xml = br#"<LifecycleConfiguration><Rule>
          <Status>Disabled</Status>
          <Expiration><Days>1</Days></Expiration>
        </Rule></LifecycleConfiguration>"#;
        assert!(parse_expiration_rules(xml).is_empty());
        assert!(compute_delete_at(xml, "any", 0).is_none());
    }

    #[test]
    fn apply_sets_x_delete_at_header() {
        let mut h = HeaderKeyDict::new();
        let now = 1_700_000_000i64;
        apply_lifecycle_delete_at(&mut h, LC_DAYS1_PREFIX, "logs/x", now);
        assert_eq!(
            h.get("X-Delete-At"),
            Some((now + 86_400).to_string().as_str())
        );
        let mut h2 = HeaderKeyDict::new();
        apply_lifecycle_delete_at(&mut h2, LC_DAYS1_PREFIX, "nope", now);
        assert!(h2.get("X-Delete-At").is_none());
    }

    #[test]
    fn apply_from_container_meta() {
        let mut container = HeaderKeyDict::new();
        apply_lifecycle_meta(&mut container, LC_DAYS1_PREFIX);
        assert!(container.get(S3_LIFECYCLE_META).is_some());
        let mut obj = HeaderKeyDict::new();
        let now = 1_600_000_000i64;
        apply_lifecycle_delete_at_from_container(&mut obj, &container, "logs/b", now);
        assert_eq!(
            obj.get("X-Delete-At"),
            Some((now + 86_400).to_string().as_str())
        );
    }

    #[test]
    fn date_rule() {
        let xml = br#"<LifecycleConfiguration><Rule><Status>Enabled</Status>
          <Filter><Prefix></Prefix></Filter>
          <Expiration><Date>2020-01-02T00:00:00.000Z</Date></Expiration>
        </Rule></LifecycleConfiguration>"#;
        let at = compute_delete_at(xml, "any", 0).unwrap();
        assert_eq!(at, 1_577_923_200);
    }

    #[test]
    fn parse_enabled_only() {
        let rules = parse_expiration_rules(LC_DAYS1_PREFIX);
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].prefix, "logs/");
        assert_eq!(rules[0].days, Some(1));
    }

    #[test]
    fn top_level_prefix_legacy_shape() {
        let xml = br#"<LifecycleConfiguration>
  <Rule>
    <Prefix>tmp/</Prefix>
    <Status>Enabled</Status>
    <Expiration><Days>1</Days></Expiration>
  </Rule>
</LifecycleConfiguration>"#;
        let now = 1000i64;
        assert_eq!(compute_delete_at(xml, "tmp/x", now), Some(now + 86400));
        assert_eq!(compute_delete_at(xml, "other", now), None);
    }

    #[test]
    fn parse_transition_and_abort_from_sample_xml() {
        let tr = parse_transition_rules(LC_TRANSITION_ABORT);
        assert_eq!(tr.len(), 2, "disabled transition must be ignored");
        assert_eq!(tr[0].prefix, "logs/");
        assert_eq!(tr[0].days, Some(30));
        assert_eq!(tr[0].storage_class, "GLACIER");
        assert_eq!(tr[1].prefix, "archive/");
        assert_eq!(tr[1].storage_class, "STANDARD_IA");
        assert!(tr[1].date_unix.is_some());

        let ab = parse_abort_incomplete_rules(LC_TRANSITION_ABORT);
        assert_eq!(ab.len(), 1);
        assert_eq!(ab[0].prefix, "logs/");
        assert_eq!(ab[0].days_after_initiation, 7);

        // Expiration still parsed from same document.
        let exp = parse_expiration_rules(LC_TRANSITION_ABORT);
        assert_eq!(exp.len(), 1);
        assert_eq!(exp[0].days, Some(90));
    }

    #[test]
    fn apply_transition_meta_matching_key() {
        let mut h = HeaderKeyDict::new();
        let now = 1_700_000_000i64;
        apply_lifecycle_transition_meta(&mut h, LC_TRANSITION_ABORT, "logs/a.txt", now);
        assert_eq!(h.get(META_STORAGE_CLASS), Some("GLACIER"));
        assert_eq!(
            h.get(SYS_TRANSITION_AT),
            Some((now + 30 * 86_400).to_string().as_str())
        );
    }

    #[test]
    fn apply_transition_meta_non_matching_prefix_skips() {
        let mut h = HeaderKeyDict::new();
        let now = 1_700_000_000i64;
        apply_lifecycle_transition_meta(&mut h, LC_TRANSITION_ABORT, "other/x", now);
        assert!(h.get(META_STORAGE_CLASS).is_none());
        assert!(h.get(SYS_TRANSITION_AT).is_none());
    }

    #[test]
    fn expiration_still_works_alongside_transition() {
        let now = 1_700_000_000i64;
        let at = compute_delete_at(LC_TRANSITION_ABORT, "logs/a.txt", now).unwrap();
        assert_eq!(at, now + 90 * 86_400);
        let mut h = HeaderKeyDict::new();
        apply_lifecycle_on_put_from_container(
            &mut h,
            &{
                let mut c = HeaderKeyDict::new();
                apply_lifecycle_meta(&mut c, LC_TRANSITION_ABORT);
                c
            },
            "logs/a.txt",
            now,
        );
        assert_eq!(
            h.get("X-Delete-At"),
            Some((now + 90 * 86_400).to_string().as_str())
        );
        assert_eq!(h.get(META_STORAGE_CLASS), Some("GLACIER"));
    }

    #[test]
    fn abort_incomplete_stamps_delete_at_on_marker() {
        let mut h = HeaderKeyDict::new();
        let now = 1_700_000_000i64;
        apply_abort_incomplete_on_marker(&mut h, LC_TRANSITION_ABORT, "logs/big.bin", now);
        assert_eq!(
            h.get("X-Delete-At"),
            Some((now + 7 * 86_400).to_string().as_str())
        );
        assert_eq!(h.get(SYS_ABORT_MPU_DAYS), Some("7"));

        let mut h2 = HeaderKeyDict::new();
        apply_abort_incomplete_on_marker(&mut h2, LC_TRANSITION_ABORT, "other/x", now);
        assert!(h2.get("X-Delete-At").is_none());
    }

    #[test]
    fn transition_date_rule() {
        let (sc, at) = compute_transition(LC_TRANSITION_ABORT, "archive/old", 0).unwrap();
        assert_eq!(sc, "STANDARD_IA");
        // 2025-06-01T00:00:00Z
        assert_eq!(at, 1_748_736_000);
    }
}
