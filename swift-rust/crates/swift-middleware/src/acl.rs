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

//! Swift container ACL parsing and referrer matching, ported from
//! `swift/common/middleware/acl.py`.
//!
//! The v1 ACL string on `X-Container-Read`/`X-Container-Write` mixes referrer
//! designations (`.r:<host>`, `.r:*`, `.r:-<host>`) with group names. Auth
//! middlewares (tempauth, keystoneauth, tempurl) share this parsing and the
//! [`referrer_allowed`] host-match to decide anonymous/referrer access, so the
//! matching semantics — including the `.` suffix wildcard and `-` negation —
//! must match Python exactly.

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
}
