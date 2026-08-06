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

//! S3 ACL / CORS XML shapes mapped onto Swift container headers.
//!
//! # Claimable (this module)
//! * Canned bucket ACLs: **private**, **public-read**, **public-read-write**
//!   via `X-Container-Read` / `X-Container-Write` (Python `acl_utils.swift_acl_translate`).
//! * **bucket-owner-read** / **bucket-owner-full-control** collapse to private
//!   (same as Python when object ACLs are unavailable).
//! * Multi-rule CORSConfiguration put/get: rules stored as compact meta
//!   (`X-Container-Meta-S3-Cors`) plus first-rule `Access-Control-*` stamps for
//!   Swift CORS middleware interop.
//!
//! # Residuals
//! * **authenticated-read** / **log-delivery-write**: Python raises
//!   `S3NotImplemented` in `swift_acl_translate` — we treat them as unsupported
//!   (map to private on apply; no Swift ACL equivalent for AuthenticatedUsers).
//! * Full IAM / per-object ACL / ACL XML body PUT (only `x-amz-acl` canned).
//! * CORS `ExposeHeader` / `ID` fields not persisted in the compact encoding.

use crate::xml::Element;
use swift_http::{HeaderKeyDict, Response};

const ALL_USERS: &str = "http://acs.amazonaws.com/groups/global/AllUsers";
const AUTH_USERS: &str = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers";

/// Meta header holding the compact multi-rule CORS encoding.
pub const S3_CORS_META: &str = "X-Container-Meta-S3-Cors";

// ---------------------------------------------------------------------------
// ACL
// ---------------------------------------------------------------------------

fn owner_grant(owner_id: &str) -> Element {
    Element::new("Grant")
        .with(
            Element::new("Grantee")
                .with_leaf("ID", owner_id)
                .with_leaf("DisplayName", owner_id),
        )
        .with_leaf("Permission", "FULL_CONTROL")
}

fn group_grant(uri: &str, permission: &str) -> Element {
    Element::new("Grant")
        .with(Element::new("Grantee").with_leaf("URI", uri))
        .with_leaf("Permission", permission)
}

fn acl_policy(owner_id: &str, grants: Vec<Element>) -> Vec<u8> {
    let mut root = Element::new("AccessControlPolicy");
    root.push(
        Element::new("Owner")
            .with_leaf("ID", owner_id)
            .with_leaf("DisplayName", owner_id),
    );
    let mut acl = Element::new("AccessControlList");
    for g in grants {
        acl.push(g);
    }
    root.push(acl);
    root.to_xml(true)
}

/// Canned private ACL for the bucket owner.
pub fn private_acl_xml(owner_id: &str) -> Vec<u8> {
    acl_policy(owner_id, vec![owner_grant(owner_id)])
}

/// Public-read ACL (owner FULL_CONTROL + AllUsers READ).
pub fn public_read_acl_xml(owner_id: &str) -> Vec<u8> {
    acl_policy(
        owner_id,
        vec![owner_grant(owner_id), group_grant(ALL_USERS, "READ")],
    )
}

/// Public-read-write ACL (owner FULL_CONTROL + AllUsers READ + WRITE).
pub fn public_read_write_acl_xml(owner_id: &str) -> Vec<u8> {
    acl_policy(
        owner_id,
        vec![
            owner_grant(owner_id),
            group_grant(ALL_USERS, "READ"),
            group_grant(ALL_USERS, "WRITE"),
        ],
    )
}

/// Authenticated-read ACL XML (owner FULL_CONTROL + AuthenticatedUsers READ).
///
/// Generated for completeness / documentation; Swift has no ACL that matches
/// AuthenticatedUsers, and Python `swift_acl_translate` raises NotImplemented.
pub fn authenticated_read_acl_xml(owner_id: &str) -> Vec<u8> {
    acl_policy(
        owner_id,
        vec![owner_grant(owner_id), group_grant(AUTH_USERS, "READ")],
    )
}

/// Map `x-amz-acl` canned ACL name → Swift container read/write headers.
///
/// Mirrors Python `swift.common.middleware.s3api.acl_utils.swift_acl_translate`
/// for the canned names that Swift can express.
pub fn apply_canned_acl(headers: &mut HeaderKeyDict, canned: &str) {
    match canned {
        "public-read" => {
            headers.set("X-Container-Read", ".r:*,.rlistings");
            headers.set("X-Container-Write", "");
        }
        "public-read-write" => {
            // Python: Write=.r:* ; Read=.r:*,.rlistings
            headers.set("X-Container-Read", ".r:*,.rlistings");
            headers.set("X-Container-Write", ".r:*");
        }
        // Python maps these to private (no per-object ACL).
        "private" | "" | "bucket-owner-read" | "bucket-owner-full-control" => {
            headers.set("X-Container-Read", "");
            headers.set("X-Container-Write", "");
        }
        // authenticated-read / log-delivery-write → Python S3NotImplemented.
        // Residual: treat as private so PUT does not 500.
        _ => {
            headers.set("X-Container-Read", "");
            headers.set("X-Container-Write", "");
        }
    }
}

/// Whether a canned ACL name is claimably supported for header translation.
pub fn is_supported_canned_acl(canned: &str) -> bool {
    matches!(
        canned,
        "private"
            | ""
            | "public-read"
            | "public-read-write"
            | "bucket-owner-read"
            | "bucket-owner-full-control"
    )
}

/// Infer canned ACL XML from Swift `X-Container-Read` / `X-Container-Write`.
pub fn acl_xml_from_swift_headers(
    owner_id: &str,
    read_acl: Option<&str>,
    write_acl: Option<&str>,
) -> Vec<u8> {
    let read = read_acl.unwrap_or("");
    let write = write_acl.unwrap_or("");
    let public_read = read.contains(".r:*");
    // Python public-read-write stamps Write=.r:*
    let public_write = write.contains(".r:*");
    if public_read && public_write {
        public_read_write_acl_xml(owner_id)
    } else if public_read {
        public_read_acl_xml(owner_id)
    } else {
        private_acl_xml(owner_id)
    }
}

/// Infer canned ACL XML from Swift `X-Container-Read` only (legacy helper).
pub fn acl_xml_from_swift_read(owner_id: &str, read_acl: Option<&str>) -> Vec<u8> {
    acl_xml_from_swift_headers(owner_id, read_acl, None)
}

// ---------------------------------------------------------------------------
// CORS
// ---------------------------------------------------------------------------

/// One S3 CORSRule.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CorsRule {
    pub allowed_origins: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub allowed_headers: Vec<String>,
    pub expose_headers: Vec<String>,
    pub max_age: Option<u32>,
}

/// Full CORSConfiguration (zero or more rules).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CorsConfiguration {
    pub rules: Vec<CorsRule>,
}

/// Build CORSConfiguration XML from rules.
pub fn cors_configuration_xml_from_rules(rules: &[CorsRule]) -> Vec<u8> {
    let mut root = Element::new("CORSConfiguration");
    for rule in rules {
        let mut el = Element::new("CORSRule");
        for o in &rule.allowed_origins {
            el.push_leaf("AllowedOrigin", o.as_str());
        }
        for m in &rule.allowed_methods {
            el.push_leaf("AllowedMethod", m.as_str());
        }
        for h in &rule.allowed_headers {
            el.push_leaf("AllowedHeader", h.as_str());
        }
        for h in &rule.expose_headers {
            el.push_leaf("ExposeHeader", h.as_str());
        }
        if let Some(age) = rule.max_age {
            el.push_leaf("MaxAgeSeconds", age.to_string());
        }
        root.push(el);
    }
    root.to_xml(true)
}

/// Minimal CORSConfiguration with one rule (convenience).
pub fn cors_configuration_xml(
    allowed_origins: &[&str],
    allowed_methods: &[&str],
    allowed_headers: &[&str],
    max_age: Option<u32>,
) -> Vec<u8> {
    let rule = CorsRule {
        allowed_origins: allowed_origins.iter().map(|s| (*s).to_string()).collect(),
        allowed_methods: allowed_methods.iter().map(|s| (*s).to_string()).collect(),
        allowed_headers: allowed_headers.iter().map(|s| (*s).to_string()).collect(),
        expose_headers: Vec::new(),
        max_age,
    };
    cors_configuration_xml_from_rules(&[rule])
}

/// Default empty CORS (no rules).
pub fn empty_cors_xml() -> Vec<u8> {
    Element::new("CORSConfiguration").to_xml(true)
}

/// Extract all text values for a tag from a slice of XML text.
fn extract_tag_values(text: &str, tag: &str) -> Vec<String> {
    let mut out = Vec::new();
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut rest = text;
    while let Some(s) = rest.find(&open) {
        let start = s + open.len();
        let Some(end_rel) = rest[start..].find(&close) else {
            break;
        };
        out.push(rest[start..start + end_rel].to_string());
        rest = &rest[start + end_rel + close.len()..];
    }
    out
}

fn parse_one_rule_xml(rule_xml: &str) -> CorsRule {
    let mut rule = CorsRule::default();
    rule.allowed_origins = extract_tag_values(rule_xml, "AllowedOrigin");
    rule.allowed_methods = extract_tag_values(rule_xml, "AllowedMethod");
    rule.allowed_headers = extract_tag_values(rule_xml, "AllowedHeader");
    rule.expose_headers = extract_tag_values(rule_xml, "ExposeHeader");
    if let Some(s) = rule_xml.find("<MaxAgeSeconds>") {
        let start = s + "<MaxAgeSeconds>".len();
        if let Some(end_rel) = rule_xml[start..].find("</MaxAgeSeconds>") {
            rule.max_age = rule_xml[start..start + end_rel].parse().ok();
        }
    }
    rule
}

/// Parse a CORSConfiguration body into zero or more rules.
pub fn parse_cors_configuration(body: &[u8]) -> Result<CorsConfiguration, String> {
    let text = std::str::from_utf8(body).map_err(|_| "MalformedXML".to_string())?;
    if !text.contains("CORSConfiguration") {
        return Err("MalformedXML".into());
    }
    let mut rules = Vec::new();
    let mut rest = text;
    let open = "<CORSRule>";
    let close = "</CORSRule>";
    while let Some(s) = rest.find(open) {
        let start = s + open.len();
        let Some(end_rel) = rest[start..].find(close) else {
            break;
        };
        let rule_body = &rest[start..start + end_rel];
        rules.push(parse_one_rule_xml(rule_body));
        rest = &rest[start + end_rel + close.len()..];
    }
    // Self-closing or empty CORSRule is rare; also accept tags with attributes.
    if rules.is_empty() && text.contains("CORSRule") {
        // Fallback: single-rule parse over the whole document (legacy).
        let rule = parse_one_rule_xml(text);
        if !rule.allowed_origins.is_empty() || !rule.allowed_methods.is_empty() {
            rules.push(rule);
        }
    }
    Ok(CorsConfiguration { rules })
}

/// Parse CORS body; returns the **first** rule for backward-compat callers.
/// Prefer [`parse_cors_configuration`] for multi-rule.
pub fn parse_cors_body(body: &[u8]) -> Result<CorsRule, String> {
    let cfg = parse_cors_configuration(body)?;
    Ok(cfg.rules.into_iter().next().unwrap_or_default())
}

// ---------------------------------------------------------------------------
// Compact multi-rule storage in Swift meta
// ---------------------------------------------------------------------------
//
// Encoding (ASCII-safe, no base64 dep):
//   rules joined by "||"
//   within a rule: fields joined by ";;"
//   field form: O=<origins comma-sep> | M=<methods> | H=<headers> | E=<expose> | A=<maxage>
// Origins/methods may contain commas (URLs rarely do); we use \x1f as list sep
// inside a field if needed — for claimable AWS CORS, comma-free values are normal.
// We use `\x1f` (unit separator) as the intra-list delimiter.

const RULE_SEP: &str = "||";
const FIELD_SEP: &str = ";;";
const LIST_SEP: char = '\u{1f}';

fn encode_list(items: &[String]) -> String {
    items.join(&LIST_SEP.to_string())
}

fn decode_list(s: &str) -> Vec<String> {
    if s.is_empty() {
        return Vec::new();
    }
    s.split(LIST_SEP).map(|x| x.to_string()).collect()
}

/// Encode multi-rule CORS into a single meta value.
pub fn encode_cors_meta(cfg: &CorsConfiguration) -> String {
    cfg.rules
        .iter()
        .map(|r| {
            let mut parts = vec![
                format!("O={}", encode_list(&r.allowed_origins)),
                format!("M={}", encode_list(&r.allowed_methods)),
                format!("H={}", encode_list(&r.allowed_headers)),
                format!("E={}", encode_list(&r.expose_headers)),
            ];
            if let Some(age) = r.max_age {
                parts.push(format!("A={age}"));
            }
            parts.join(FIELD_SEP)
        })
        .collect::<Vec<_>>()
        .join(RULE_SEP)
}

/// Decode compact multi-rule meta.
pub fn decode_cors_meta(s: &str) -> CorsConfiguration {
    if s.is_empty() {
        return CorsConfiguration::default();
    }
    let mut rules = Vec::new();
    for rule_s in s.split(RULE_SEP) {
        if rule_s.is_empty() {
            continue;
        }
        let mut rule = CorsRule::default();
        for field in rule_s.split(FIELD_SEP) {
            if let Some(v) = field.strip_prefix("O=") {
                rule.allowed_origins = decode_list(v);
            } else if let Some(v) = field.strip_prefix("M=") {
                rule.allowed_methods = decode_list(v);
            } else if let Some(v) = field.strip_prefix("H=") {
                rule.allowed_headers = decode_list(v);
            } else if let Some(v) = field.strip_prefix("E=") {
                rule.expose_headers = decode_list(v);
            } else if let Some(v) = field.strip_prefix("A=") {
                rule.max_age = v.parse().ok();
            }
        }
        rules.push(rule);
    }
    CorsConfiguration { rules }
}

/// Stamp Swift meta headers for a full CORS configuration.
///
/// * `X-Container-Meta-S3-Cors` — compact multi-rule encoding (authoritative).
/// * First rule also stamped onto `Access-Control-*` for Swift CORS middleware.
pub fn cors_config_to_swift_headers(headers: &mut HeaderKeyDict, cfg: &CorsConfiguration) {
    if cfg.rules.is_empty() {
        headers.set(S3_CORS_META, "");
        headers.set("X-Container-Meta-Access-Control-Allow-Origin", "");
        headers.set("X-Container-Meta-Access-Control-Allow-Methods", "");
        headers.set("X-Container-Meta-Access-Control-Allow-Headers", "");
        headers.set("X-Container-Meta-Access-Control-Max-Age", "");
        return;
    }
    headers.set(S3_CORS_META, encode_cors_meta(cfg));
    // First-rule Swift CORS interop.
    cors_to_swift_headers(headers, &cfg.rules[0]);
}

/// Stamp Swift meta headers for a single CORS rule (legacy helper).
pub fn cors_to_swift_headers(headers: &mut HeaderKeyDict, rule: &CorsRule) {
    headers.set(
        "X-Container-Meta-Access-Control-Allow-Origin",
        rule.allowed_origins.join(","),
    );
    headers.set(
        "X-Container-Meta-Access-Control-Allow-Methods",
        rule.allowed_methods.join(","),
    );
    if !rule.allowed_headers.is_empty() {
        headers.set(
            "X-Container-Meta-Access-Control-Allow-Headers",
            rule.allowed_headers.join(","),
        );
    }
    if let Some(age) = rule.max_age {
        headers.set(
            "X-Container-Meta-Access-Control-Max-Age",
            age.to_string(),
        );
    }
}

/// Rebuild CORS XML from Swift headers (prefers multi-rule meta).
pub fn cors_xml_from_swift_headers(headers: &HeaderKeyDict) -> Vec<u8> {
    if let Some(raw) = headers.get(S3_CORS_META) {
        if !raw.is_empty() {
            let cfg = decode_cors_meta(raw);
            if !cfg.rules.is_empty() {
                return cors_configuration_xml_from_rules(&cfg.rules);
            }
        }
    }
    // Legacy single-rule Access-Control-* path.
    let origins = headers
        .get("X-Container-Meta-Access-Control-Allow-Origin")
        .unwrap_or("")
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect::<Vec<_>>();
    if origins.is_empty() {
        return empty_cors_xml();
    }
    let methods = headers
        .get("X-Container-Meta-Access-Control-Allow-Methods")
        .unwrap_or("GET,HEAD")
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect::<Vec<_>>();
    let hdrs = headers
        .get("X-Container-Meta-Access-Control-Allow-Headers")
        .unwrap_or("")
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect::<Vec<_>>();
    let max_age = headers
        .get("X-Container-Meta-Access-Control-Max-Age")
        .and_then(|v| v.parse().ok());
    let rule = CorsRule {
        allowed_origins: origins,
        allowed_methods: methods,
        allowed_headers: hdrs,
        expose_headers: Vec::new(),
        max_age,
    };
    cors_configuration_xml_from_rules(&[rule])
}

/// Clear all CORS-related Swift meta headers.
pub fn clear_cors_swift_headers(headers: &mut HeaderKeyDict) {
    headers.set(S3_CORS_META, "");
    headers.set("X-Container-Meta-Access-Control-Allow-Origin", "");
    headers.set("X-Container-Meta-Access-Control-Allow-Methods", "");
    headers.set("X-Container-Meta-Access-Control-Allow-Headers", "");
    headers.set("X-Container-Meta-Access-Control-Max-Age", "");
}

pub fn xml_ok(body: Vec<u8>) -> Response {
    let mut resp = Response::with_body(200, body);
    resp.headers.set("Content-Type", "application/xml");
    resp
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_acl_contains_full_control() {
        let xml = String::from_utf8(private_acl_xml("owner")).unwrap();
        assert!(xml.contains("FULL_CONTROL"));
        assert!(xml.contains("<ID>owner</ID>"));
    }

    #[test]
    fn public_read_write_acl_xml_has_read_and_write() {
        let xml = String::from_utf8(public_read_write_acl_xml("owner")).unwrap();
        assert!(xml.contains(ALL_USERS));
        assert!(xml.contains("<Permission>READ</Permission>"));
        assert!(xml.contains("<Permission>WRITE</Permission>"));
        assert!(xml.contains("FULL_CONTROL"));
    }

    #[test]
    fn apply_canned_public_read_write() {
        let mut h = HeaderKeyDict::new();
        apply_canned_acl(&mut h, "public-read-write");
        assert_eq!(
            h.get("X-Container-Read"),
            Some(".r:*,.rlistings")
        );
        assert_eq!(h.get("X-Container-Write"), Some(".r:*"));
    }

    #[test]
    fn apply_canned_public_read() {
        let mut h = HeaderKeyDict::new();
        apply_canned_acl(&mut h, "public-read");
        assert_eq!(
            h.get("X-Container-Read"),
            Some(".r:*,.rlistings")
        );
        assert_eq!(h.get("X-Container-Write"), Some(""));
    }

    #[test]
    fn apply_canned_bucket_owner_collapses_to_private() {
        let mut h = HeaderKeyDict::new();
        apply_canned_acl(&mut h, "bucket-owner-full-control");
        assert_eq!(h.get("X-Container-Read"), Some(""));
        assert_eq!(h.get("X-Container-Write"), Some(""));
    }

    #[test]
    fn authenticated_read_is_unsupported_maps_private() {
        assert!(!is_supported_canned_acl("authenticated-read"));
        let mut h = HeaderKeyDict::new();
        apply_canned_acl(&mut h, "authenticated-read");
        assert_eq!(h.get("X-Container-Read"), Some(""));
    }

    #[test]
    fn infer_acl_from_read_write_headers() {
        let xml = String::from_utf8(acl_xml_from_swift_headers(
            "o",
            Some(".r:*,.rlistings"),
            Some(".r:*"),
        ))
        .unwrap();
        assert!(xml.contains("WRITE"));
        let xml2 = String::from_utf8(acl_xml_from_swift_headers(
            "o",
            Some(".r:*,.rlistings"),
            Some(""),
        ))
        .unwrap();
        assert!(!xml2.contains("<Permission>WRITE</Permission>"));
        assert!(xml2.contains("<Permission>READ</Permission>"));
    }

    #[test]
    fn parse_cors_roundtrip_fields() {
        let body = br#"
<CORSConfiguration>
  <CORSRule>
    <AllowedOrigin>*</AllowedOrigin>
    <AllowedMethod>GET</AllowedMethod>
    <AllowedMethod>PUT</AllowedMethod>
    <AllowedHeader>*</AllowedHeader>
    <MaxAgeSeconds>3600</MaxAgeSeconds>
  </CORSRule>
</CORSConfiguration>"#;
        let rule = parse_cors_body(body).unwrap();
        assert_eq!(rule.allowed_origins, vec!["*"]);
        assert_eq!(rule.allowed_methods, vec!["GET", "PUT"]);
        assert_eq!(rule.max_age, Some(3600));
    }

    #[test]
    fn parse_multi_rule_cors() {
        let body = br#"
<CORSConfiguration>
  <CORSRule>
    <AllowedOrigin>https://a.example.com</AllowedOrigin>
    <AllowedMethod>GET</AllowedMethod>
    <MaxAgeSeconds>100</MaxAgeSeconds>
  </CORSRule>
  <CORSRule>
    <AllowedOrigin>https://b.example.com</AllowedOrigin>
    <AllowedMethod>PUT</AllowedMethod>
    <AllowedMethod>POST</AllowedMethod>
    <AllowedHeader>x-amz-meta-*</AllowedHeader>
  </CORSRule>
</CORSConfiguration>"#;
        let cfg = parse_cors_configuration(body).unwrap();
        assert_eq!(cfg.rules.len(), 2);
        assert_eq!(cfg.rules[0].allowed_origins, vec!["https://a.example.com"]);
        assert_eq!(cfg.rules[0].allowed_methods, vec!["GET"]);
        assert_eq!(cfg.rules[0].max_age, Some(100));
        assert_eq!(cfg.rules[1].allowed_origins, vec!["https://b.example.com"]);
        assert_eq!(cfg.rules[1].allowed_methods, vec!["PUT", "POST"]);
        assert_eq!(cfg.rules[1].allowed_headers, vec!["x-amz-meta-*"]);
    }

    #[test]
    fn multi_rule_meta_encode_decode_roundtrip() {
        let cfg = CorsConfiguration {
            rules: vec![
                CorsRule {
                    allowed_origins: vec!["https://a.example.com".into()],
                    allowed_methods: vec!["GET".into()],
                    allowed_headers: vec![],
                    expose_headers: vec!["ETag".into()],
                    max_age: Some(60),
                },
                CorsRule {
                    allowed_origins: vec!["*".into()],
                    allowed_methods: vec!["PUT".into(), "POST".into()],
                    allowed_headers: vec!["*".into()],
                    expose_headers: vec![],
                    max_age: None,
                },
            ],
        };
        let enc = encode_cors_meta(&cfg);
        let dec = decode_cors_meta(&enc);
        assert_eq!(dec, cfg);

        let mut h = HeaderKeyDict::new();
        cors_config_to_swift_headers(&mut h, &cfg);
        assert!(h.get(S3_CORS_META).is_some_and(|v| !v.is_empty()));
        assert_eq!(
            h.get("X-Container-Meta-Access-Control-Allow-Origin"),
            Some("https://a.example.com")
        );
        let xml = String::from_utf8(cors_xml_from_swift_headers(&h)).unwrap();
        assert!(xml.contains("https://a.example.com"));
        assert!(xml.contains("https://b.example.com") || xml.contains("*"));
        // second rule origin is *
        assert!(xml.matches("CORSRule").count() >= 2 || xml.contains("<CORSRule>"));
        // Count rule openings
        assert_eq!(xml.matches("<CORSRule>").count(), 2);
    }

    #[test]
    fn legacy_single_rule_headers_still_work() {
        let mut h = HeaderKeyDict::new();
        h.set("X-Container-Meta-Access-Control-Allow-Origin", "*");
        h.set("X-Container-Meta-Access-Control-Allow-Methods", "GET,HEAD");
        let xml = String::from_utf8(cors_xml_from_swift_headers(&h)).unwrap();
        assert!(xml.contains("<AllowedOrigin>*</AllowedOrigin>"));
        assert!(xml.contains("<AllowedMethod>GET</AllowedMethod>"));
    }

    #[test]
    fn multi_rule_xml_builder() {
        let rules = vec![
            CorsRule {
                allowed_origins: vec!["https://a".into()],
                allowed_methods: vec!["GET".into()],
                ..Default::default()
            },
            CorsRule {
                allowed_origins: vec!["https://b".into()],
                allowed_methods: vec!["PUT".into()],
                max_age: Some(9),
                ..Default::default()
            },
        ];
        let xml = String::from_utf8(cors_configuration_xml_from_rules(&rules)).unwrap();
        assert_eq!(xml.matches("<CORSRule>").count(), 2);
        assert!(xml.contains("https://a"));
        assert!(xml.contains("https://b"));
        assert!(xml.contains("<MaxAgeSeconds>9</MaxAgeSeconds>"));
    }
}
