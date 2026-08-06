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

//! Basic S3 ACL / CORS XML shapes mapped onto Swift container headers.
//!
//! Honest scope: canned **private** / **public-read** bucket ACLs via
//! `X-Container-Read` / `X-Container-Write`, and a single CORS rule stored
//! as `X-Container-Meta-Access-Control-*` (Python s3api approx). Full IAM /
//! object ACL / multi-rule CORS remain residuals.

use crate::xml::Element;
use swift_http::{HeaderKeyDict, Response};

/// Canned private ACL for the bucket owner.
pub fn private_acl_xml(owner_id: &str) -> Vec<u8> {
    let mut root = Element::new("AccessControlPolicy");
    root.push(
        Element::new("Owner")
            .with_leaf("ID", owner_id)
            .with_leaf("DisplayName", owner_id),
    );
    let grant = Element::new("Grant")
        .with(
            Element::new("Grantee")
                .with_leaf("ID", owner_id)
                .with_leaf("DisplayName", owner_id),
        )
        .with_leaf("Permission", "FULL_CONTROL");
    root.push(Element::new("AccessControlList").with(grant));
    root.to_xml(true)
}

/// Public-read ACL (owner FULL_CONTROL + AllUsers READ).
pub fn public_read_acl_xml(owner_id: &str) -> Vec<u8> {
    let mut root = Element::new("AccessControlPolicy");
    root.push(
        Element::new("Owner")
            .with_leaf("ID", owner_id)
            .with_leaf("DisplayName", owner_id),
    );
    let mut acl = Element::new("AccessControlList");
    acl.push(
        Element::new("Grant")
            .with(
                Element::new("Grantee")
                    .with_leaf("ID", owner_id)
                    .with_leaf("DisplayName", owner_id),
            )
            .with_leaf("Permission", "FULL_CONTROL"),
    );
    acl.push(
        Element::new("Grant")
            .with(Element::new("Grantee").with_leaf("URI", "http://acs.amazonaws.com/groups/global/AllUsers"))
            .with_leaf("Permission", "READ"),
    );
    root.push(acl);
    root.to_xml(true)
}

/// Map `x-amz-acl` canned ACL name → Swift container read/write headers.
pub fn apply_canned_acl(headers: &mut HeaderKeyDict, canned: &str) {
    match canned {
        "public-read" => {
            headers.set("X-Container-Read", ".r:*,.rlistings");
            headers.set("X-Container-Write", "");
        }
        "private" | "" => {
            headers.set("X-Container-Read", "");
            headers.set("X-Container-Write", "");
        }
        _ => {
            // Unsupported canned ACL → treat as private (honest residual).
            headers.set("X-Container-Read", "");
            headers.set("X-Container-Write", "");
        }
    }
}

/// Infer canned ACL XML from Swift `X-Container-Read`.
pub fn acl_xml_from_swift_read(owner_id: &str, read_acl: Option<&str>) -> Vec<u8> {
    if read_acl.is_some_and(|r| r.contains(".r:*")) {
        public_read_acl_xml(owner_id)
    } else {
        private_acl_xml(owner_id)
    }
}

/// Minimal CORSConfiguration with one rule.
pub fn cors_configuration_xml(
    allowed_origins: &[&str],
    allowed_methods: &[&str],
    allowed_headers: &[&str],
    max_age: Option<u32>,
) -> Vec<u8> {
    let mut rule = Element::new("CORSRule");
    for o in allowed_origins {
        rule.push_leaf("AllowedOrigin", *o);
    }
    for m in allowed_methods {
        rule.push_leaf("AllowedMethod", *m);
    }
    for h in allowed_headers {
        rule.push_leaf("AllowedHeader", *h);
    }
    if let Some(age) = max_age {
        rule.push_leaf("MaxAgeSeconds", age.to_string());
    }
    Element::new("CORSConfiguration").with(rule).to_xml(true)
}

/// Default empty CORS (no rules).
pub fn empty_cors_xml() -> Vec<u8> {
    Element::new("CORSConfiguration").to_xml(true)
}

/// Parse a simple one-rule CORSConfiguration body.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CorsRule {
    pub allowed_origins: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub allowed_headers: Vec<String>,
    pub max_age: Option<u32>,
}

pub fn parse_cors_body(body: &[u8]) -> Result<CorsRule, String> {
    let text = std::str::from_utf8(body).map_err(|_| "MalformedXML".to_string())?;
    if !text.contains("CORSConfiguration") {
        return Err("MalformedXML".into());
    }
    let mut rule = CorsRule::default();
    for tag in ["AllowedOrigin", "AllowedMethod", "AllowedHeader"] {
        let mut rest = text;
        let open = format!("<{tag}>");
        let close = format!("</{tag}>");
        while let Some(s) = rest.find(&open) {
            let start = s + open.len();
            let Some(end_rel) = rest[start..].find(&close) else {
                break;
            };
            let val = rest[start..start + end_rel].to_string();
            match tag {
                "AllowedOrigin" => rule.allowed_origins.push(val),
                "AllowedMethod" => rule.allowed_methods.push(val),
                "AllowedHeader" => rule.allowed_headers.push(val),
                _ => {}
            }
            rest = &rest[start + end_rel + close.len()..];
        }
    }
    if let Some(s) = text.find("<MaxAgeSeconds>") {
        let start = s + "<MaxAgeSeconds>".len();
        if let Some(end_rel) = text[start..].find("</MaxAgeSeconds>") {
            rule.max_age = text[start..start + end_rel].parse().ok();
        }
    }
    Ok(rule)
}

/// Stamp Swift meta headers for a CORS rule (readable by GET ?cors).
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

pub fn cors_xml_from_swift_headers(headers: &HeaderKeyDict) -> Vec<u8> {
    let origins = headers
        .get("X-Container-Meta-Access-Control-Allow-Origin")
        .unwrap_or("")
        .split(',')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>();
    if origins.is_empty() {
        return empty_cors_xml();
    }
    let methods = headers
        .get("X-Container-Meta-Access-Control-Allow-Methods")
        .unwrap_or("GET,HEAD")
        .split(',')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>();
    let hdrs = headers
        .get("X-Container-Meta-Access-Control-Allow-Headers")
        .unwrap_or("")
        .split(',')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>();
    let max_age = headers
        .get("X-Container-Meta-Access-Control-Max-Age")
        .and_then(|v| v.parse().ok());
    cors_configuration_xml(&origins, &methods, &hdrs, max_age)
}

pub fn xml_ok(body: Vec<u8>) -> Response {
    let mut resp = Response::with_body(200, body);
    resp.headers.set("Content-Type", "application/xml");
    resp
}

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
}
