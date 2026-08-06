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

//! Swift container and account ACL parsing, ported from
//! `swift/common/middleware/acl.py`.
//!
//! The v1 ACL string on `X-Container-Read`/`X-Container-Write` mixes referrer
//! designations (`.r:<host>`, `.r:*`, `.r:-<host>`) with group names. Auth
//! middlewares (tempauth, keystoneauth, tempurl) share this parsing and the
//! [`referrer_allowed`] host-match to decide anonymous/referrer access, so the
//! matching semantics — including the `.` suffix wildcard and `-` negation —
//! must match Python exactly.
//!
//! Account ACLs (`X-Account-Access-Control`) use the v2 JSON form
//! (`admin` / `read-write` / `read-only` group lists) persisted as account
//! sysmeta `core-access-control`.

/// `parse_acl_v1`: split an ACL string into `(referrers, groups)`. Values
/// beginning `.r:` are referrer designations (with the prefix stripped);
/// everything else is a group name (percent-decoded).
pub fn parse_acl_v1(acl_string: &str) -> (Vec<String>, Vec<String>) {
    let mut referrers = Vec::new();
    let mut groups = Vec::new();
    if !acl_string.is_empty() {
        for value in acl_string.split(',') {
            if let Some(rest) = value.strip_prefix(".r:") {
                referrers.push(rest.to_string());
            } else {
                groups.push(unquote(value));
            }
        }
    }
    (referrers, groups)
}

/// `referrer_allowed`: whether `referrer` is permitted by `referrer_acl` (the
/// referrers list from [`parse_acl_v1`]). A `-`-prefixed entry denies, and a
/// `.`-prefixed entry is a domain-suffix wildcard; the last matching rule in
/// list order wins.
pub fn referrer_allowed(referrer: Option<&str>, referrer_acl: &[String]) -> bool {
    let mut allow = false;
    if !referrer_acl.is_empty() {
        let rhost = hostname_of(referrer.unwrap_or("")).unwrap_or_else(|| "unknown".to_string());
        for mhost in referrer_acl {
            if let Some(neg) = mhost.strip_prefix('-') {
                if neg == rhost || (neg.starts_with('.') && rhost.ends_with(neg)) {
                    allow = false;
                }
            } else if mhost == "*"
                || *mhost == rhost
                || (mhost.starts_with('.') && rhost.ends_with(mhost.as_str()))
            {
                allow = true;
            }
        }
    }
    allow
}

/// The host component of a URL, matching Python `urlparse(...).hostname`:
/// lowercased, without userinfo or port. Returns `None` when there is no
/// `scheme://netloc` authority (a bare word has no hostname).
fn hostname_of(url: &str) -> Option<String> {
    // netloc is the text after "://" up to the next '/', '?' or '#'
    let after_scheme = url.split_once("://")?.1;
    let netloc_end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let netloc = &after_scheme[..netloc_end];
    // strip userinfo
    let host_port = netloc.rsplit_once('@').map(|(_, h)| h).unwrap_or(netloc);
    // strip port (but keep IPv6 brackets intact)
    let host = if let Some(stripped) = host_port.strip_prefix('[') {
        // [ipv6]:port -> ipv6
        stripped.split_once(']').map(|(h, _)| h).unwrap_or(stripped)
    } else {
        host_port.split_once(':').map(|(h, _)| h).unwrap_or(host_port)
    };
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

/// Account ACL roles recognized by TempAuth (`admin` / `read-write` /
/// `read-only`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AccountAcls {
    pub admin: Vec<String>,
    pub read_write: Vec<String>,
    pub read_only: Vec<String>,
}

impl AccountAcls {
    pub fn is_empty(&self) -> bool {
        self.admin.is_empty() && self.read_write.is_empty() && self.read_only.is_empty()
    }

    /// Whether any of `user_groups` is in the admin list.
    pub fn is_admin(&self, user_groups: &[String]) -> bool {
        intersects(user_groups, &self.admin)
    }

    /// Whether any of `user_groups` is in the read-write list.
    pub fn is_read_write(&self, user_groups: &[String]) -> bool {
        intersects(user_groups, &self.read_write)
    }

    /// Whether any of `user_groups` is in the read-only list.
    pub fn is_read_only(&self, user_groups: &[String]) -> bool {
        intersects(user_groups, &self.read_only)
    }
}

fn intersects(user_groups: &[String], acl_groups: &[String]) -> bool {
    user_groups.iter().any(|ug| acl_groups.iter().any(|ag| ag == ug))
}

/// `parse_acl_v2`: parse a JSON ACL string into a raw map, or `None` when
/// the input is missing / not a JSON object. An empty string yields `{}`.
pub fn parse_acl_v2(data: Option<&str>) -> Option<serde_json::Map<String, serde_json::Value>> {
    let data = data?;
    if data.is_empty() {
        return Some(serde_json::Map::new());
    }
    match serde_json::from_str::<serde_json::Value>(data) {
        Ok(serde_json::Value::Object(map)) => Some(map),
        _ => None,
    }
}

/// Compact JSON encoding matching Python `format_acl_v2` (sorted keys,
/// no whitespace, ASCII-forced via serde's default string escaping).
pub fn format_acl_v2(acl: &AccountAcls) -> String {
    let mut map = serde_json::Map::new();
    if !acl.admin.is_empty() {
        map.insert(
            "admin".into(),
            serde_json::Value::Array(acl.admin.iter().cloned().map(serde_json::Value::String).collect()),
        );
    }
    if !acl.read_only.is_empty() {
        map.insert(
            "read-only".into(),
            serde_json::Value::Array(
                acl.read_only
                    .iter()
                    .cloned()
                    .map(serde_json::Value::String)
                    .collect(),
            ),
        );
    }
    if !acl.read_write.is_empty() {
        map.insert(
            "read-write".into(),
            serde_json::Value::Array(
                acl.read_write
                    .iter()
                    .cloned()
                    .map(serde_json::Value::String)
                    .collect(),
            ),
        );
    }
    serde_json::Value::Object(map).to_string()
}

/// Validate a client `X-Account-Access-Control` value for TempAuth.
/// Returns `Ok(Some(json))` to persist (possibly empty to clear), `Ok(None)`
/// when the header is absent, or `Err(message)` on syntax / key errors.
pub fn validate_account_acl_header(header: Option<&str>) -> Result<Option<String>, String> {
    let Some(acl_data) = header else {
        return Ok(None);
    };
    let Some(raw) = parse_acl_v2(Some(acl_data)) else {
        return Err(format!("Syntax error in input ({acl_data:?})"));
    };
    const KEYS: [&str; 3] = ["admin", "read-write", "read-only"];
    for key in raw.keys() {
        if !KEYS.contains(&key.as_str()) {
            return Err(format!("Key \"{key}\" not recognized"));
        }
    }
    let mut acls = AccountAcls::default();
    for key in KEYS {
        let Some(val) = raw.get(key) else { continue };
        let Some(arr) = val.as_array() else {
            return Err(format!("Value for key \"{key}\" must be a list"));
        };
        let mut members = Vec::with_capacity(arr.len());
        for item in arr {
            let Some(s) = item.as_str() else {
                return Err(format!("Elements of \"{key}\" list must be strings"));
            };
            members.push(s.to_string());
        }
        match key {
            "admin" => acls.admin = members,
            "read-write" => acls.read_write = members,
            "read-only" => acls.read_only = members,
            _ => {}
        }
    }
    // Persist even when empty so a POST can clear the ACL (Python keeps the
    // empty dict / empty header translation path).
    Ok(Some(format_acl_v2(&acls)))
}

/// `acls_from_account_info`: extract TempAuth account ACLs from the
/// `core-access-control` sysmeta string. Returns `None` when unset / empty.
pub fn acls_from_sysmeta(sysmeta_value: Option<&str>) -> Option<AccountAcls> {
    let raw = parse_acl_v2(sysmeta_value)?;
    let string_list = |key: &str| -> Vec<String> {
        raw.get(key)
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };
    let acls = AccountAcls {
        admin: string_list("admin"),
        read_write: string_list("read-write"),
        read_only: string_list("read-only"),
    };
    if acls.is_empty() {
        None
    } else {
        Some(acls)
    }
}

/// Minimal percent-decode for group names (`urllib.parse.unquote`).
fn unquote(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (
                (bytes[i + 1] as char).to_digit(16),
                (bytes[i + 2] as char).to_digit(16),
            ) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_acl_v1() {
        let (refs, groups) = parse_acl_v1(".r:*,.r:-bad.com,AUTH_test,.rlistings");
        assert_eq!(refs, vec!["*", "-bad.com"]);
        assert_eq!(groups, vec!["AUTH_test", ".rlistings"]);
        assert_eq!(parse_acl_v1(""), (vec![], vec![]));
    }

    #[test]
    fn test_referrer_star_allows_any() {
        let acl = vec!["*".to_string()];
        assert!(referrer_allowed(Some("http://any.example.com/x"), &acl));
        assert!(referrer_allowed(None, &acl)); // rhost 'unknown' matches *
    }

    #[test]
    fn test_referrer_exact_and_suffix() {
        let acl = vec!["example.com".to_string()];
        assert!(referrer_allowed(Some("http://example.com/"), &acl));
        assert!(!referrer_allowed(Some("http://www.example.com/"), &acl));

        let suffix = vec![".example.com".to_string()];
        assert!(referrer_allowed(Some("http://www.example.com/"), &suffix));
        assert!(!referrer_allowed(Some("http://example.com/"), &suffix));
    }

    #[test]
    fn test_referrer_negation_last_wins() {
        // allow the domain but deny one host
        let acl = vec![".example.com".to_string(), "-evil.example.com".to_string()];
        assert!(referrer_allowed(Some("http://good.example.com/"), &acl));
        assert!(!referrer_allowed(Some("http://evil.example.com/"), &acl));
    }

    #[test]
    fn test_hostname_extraction() {
        assert_eq!(hostname_of("http://Www.Example.com:8080/p"), Some("www.example.com".into()));
        assert_eq!(hostname_of("https://user:pw@host.com/p"), Some("host.com".into()));
        assert_eq!(hostname_of("notaurl"), None);
        assert_eq!(hostname_of(""), None);
    }

    #[test]
    fn test_empty_acl_denies() {
        assert!(!referrer_allowed(Some("http://example.com/"), &[]));
    }

    #[test]
    fn test_parse_and_validate_account_acl_v2() {
        let raw = r#"{"admin":["AUTH_a"],"read-only":["AUTH_b:u"],"read-write":["AUTH_c"]}"#;
        let acls = acls_from_sysmeta(Some(raw)).expect("parsed");
        assert_eq!(acls.admin, vec!["AUTH_a"]);
        assert_eq!(acls.read_only, vec!["AUTH_b:u"]);
        assert_eq!(acls.read_write, vec!["AUTH_c"]);
        assert!(acls.is_admin(&[String::from("AUTH_a")]));
        assert!(!acls.is_admin(&[String::from("AUTH_c")]));

        let ok = validate_account_acl_header(Some(raw)).unwrap().unwrap();
        let round = acls_from_sysmeta(Some(&ok)).unwrap();
        assert_eq!(round, acls);

        assert!(validate_account_acl_header(Some(r#"{"nope":[]}"#)).is_err());
        assert!(validate_account_acl_header(Some("not-json")).is_err());
        assert!(validate_account_acl_header(Some(r#"{"admin":"x"}"#)).is_err());
        assert_eq!(validate_account_acl_header(None).unwrap(), None);
    }
}
