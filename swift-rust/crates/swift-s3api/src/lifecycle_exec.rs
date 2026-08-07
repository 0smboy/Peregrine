// Copyright (c) 2026 OpenStack Foundation
//! Execute S3 lifecycle Expiration rules → Swift `X-Delete-At` on object PUT.
//!
//! Parses stored `LifecycleConfiguration` XML (bucket meta) for **Enabled**
//! rules with `Expiration` **Days** or **Date** and an optional **Prefix**
//! (`Prefix` or `Filter/Prefix`). On object PUT the matching rule stamps
//! `X-Delete-At = now + Days*86400` (or absolute Date), which the object
//! expirer honors.
//!
//! Pure functions live here so callers do not depend on concurrent edits to
//! [`crate::bucket_config`].

use swift_http::HeaderKeyDict;

use crate::bucket_config::lifecycle_xml_from_headers;

const SECONDS_PER_DAY: i64 = 86_400;

/// One Enabled expiration rule (subset of LifecycleConfiguration).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpirationRule {
    /// Key prefix (empty = match all).
    pub prefix: String,
    pub days: Option<i64>,
    pub date_unix: Option<i64>,
}

/// Parse LifecycleConfiguration XML for Enabled Expiration Days/Date rules.
pub fn parse_expiration_rules(xml: &[u8]) -> Vec<ExpirationRule> {
    let text = match std::str::from_utf8(xml) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    let mut rules = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("<Rule>") {
        let after = &rest[start + 6..];
        let end = match after.find("</Rule>") {
            Some(i) => i,
            None => break,
        };
        let body = &after[..end];
        rest = &after[end + 7..];
        if !status_enabled(body) {
            continue;
        }
        let exp = extract_inner(body, "Expiration").unwrap_or(body);
        let days = extract_tag(exp, "Days").and_then(|s| s.parse().ok());
        let date_unix = extract_tag(exp, "Date").and_then(|s| parse_iso8601_date(&s));
        if days.is_none() && date_unix.is_none() {
            continue;
        }
        let prefix = rule_prefix(body);
        rules.push(ExpirationRule {
            prefix,
            days,
            date_unix,
        });
    }
    rules
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
        if !r.prefix.is_empty() && !object_key.starts_with(&r.prefix) {
            continue;
        }
        let at = if let Some(days) = r.days {
            now_unix.saturating_add(days.saturating_mul(SECONDS_PER_DAY))
        } else if let Some(date) = r.date_unix {
            date
        } else {
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
}
