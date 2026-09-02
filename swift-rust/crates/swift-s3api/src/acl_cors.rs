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

//! S3 ACL / CORS XML shapes mapped onto Swift container / object headers.
//!
//! # Claimable (this module)
//! * Canned bucket ACLs: **private**, **public-read**, **public-read-write**
//!   via `X-Container-Read` / `X-Container-Write` (Python `acl_utils.swift_acl_translate`).
//! * **bucket-owner-read** / **bucket-owner-full-control** collapse to private
//!   (same as Python when object ACLs are unavailable).
//! * Object canned ACLs on PUT object / PUT `?acl`: **private**, **public-read**
//!   (and **public-read-write** as stored name) via
//!   [`S3_OBJECT_ACL_META`] (`X-Object-Sysmeta-S3-Acl`); GET object `?acl`
//!   reconstructs AccessControlPolicy XML from that meta (default private).
//! * **Grant headers** (`x-amz-grant-read|write|full-control|read-acp|write-acp`)
//!   and **AccessControlPolicy XML body** on PUT object/bucket `?acl` (and
//!   grant headers on PUT object): parsed into structured grants, stored as
//!   compact JSON ([`S3_OBJECT_ACL_JSON_META`] /
//!   [`S3_BUCKET_ACL_JSON_META`]). Bucket AllUsers READ/WRITE also map to
//!   `X-Container-Read` / `X-Container-Write`. GET `?acl` prefers JSON grants
//!   when present, else canned / container-header inference.
//! * **Precedence:** `x-amz-acl` canned wins if present alongside grant headers
//!   or ACP body (AWS forbids both; we keep canned for operational safety).
//! * **Object GET/HEAD grant enforcement** (LAB-HARD-GREEN): structured JSON
//!   grants with non-empty `Grant` list require the SigV4 principal to be
//!   owner or hold READ/FULL_CONTROL; else `AccessDenied`. Missing/empty
//!   grants do not invent denials.
//! * Multi-rule CORSConfiguration put/get: rules stored as compact meta
//!   (`X-Container-Meta-S3-Cors`) plus first-rule `Access-Control-*` stamps for
//!   Swift CORS middleware interop.
//!
//! # Residuals
//! * **authenticated-read** / **log-delivery-write**: Python raises
//!   `S3NotImplemented` in `swift_acl_translate` — we treat them as unsupported
//!   (map to private on apply; no Swift ACL equivalent for AuthenticatedUsers).
//! * Full IAM identity service / emailAddress grantee resolution (email stored
//!   in JSON for GET fidelity only; not resolved to canonical user).
//! * **Object ACP grant enforcement on GET/HEAD** (LAB-HARD-GREEN subset):
//!   when [`S3_OBJECT_ACL_JSON_META`] is present with non-empty grants, the
//!   request principal (`access_key` / account id) must be the owner or hold
//!   READ/FULL_CONTROL (or AllUsers/AuthenticatedUsers for **authenticated**
//!   callers) — else `AccessDenied`. Owner always allowed. Missing/empty
//!   grants → no new denial (existing canned/Swift path). See
//!   [`object_grants_allow_read`] / [`object_acl_denies_read`].
//! * Object public-read / AllUsers READ does **not** grant anonymous Swift GET
//!   by itself (container ACL still gates access; unauthenticated traffic never
//!   enters s3api SigV4 enforcement). Meta remains for S3 GET `?acl` fidelity.
//!   See [`object_canned_allows_anonymous_read`] / [`grants_allow_anonymous_read`].
//! * CORS `ExposeHeader` / `ID` fields not persisted in the compact encoding.

use crate::xml::{Element, XMLNS_XSI};
use serde_json::{json, Value};
use swift_http::{HeaderKeyDict, Response};

const ALL_USERS: &str = "http://acs.amazonaws.com/groups/global/AllUsers";
const AUTH_USERS: &str = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers";

/// S3 ACL permissions accepted in grant headers / ACP XML.
pub const ACL_PERMISSIONS: &[&str] = &["FULL_CONTROL", "READ", "WRITE", "READ_ACP", "WRITE_ACP"];

/// Meta header holding the compact multi-rule CORS encoding.
pub const S3_CORS_META: &str = "X-Container-Meta-S3-Cors";

/// Object sysmeta holding the canned ACL name (`private` / `public-read` / …).
///
/// Minimal stand-in for Python `s3_acl` JSON in `X-Object-Sysmeta-S3api-Acl`.
/// Sysmeta keeps the value off the public `x-amz-meta-*` surface.
pub const S3_OBJECT_ACL_META: &str = "X-Object-Sysmeta-S3-Acl";

/// Object sysmeta holding structured ACP grants as compact JSON.
///
/// Shape: `{"Owner":"id","Grant":[{"Permission":"READ","URI":"..."},…]}`.
/// Prefer this over [`S3_OBJECT_ACL_META`] when present on GET `?acl`.
pub const S3_OBJECT_ACL_JSON_META: &str = "X-Object-Sysmeta-S3-Acl-Json";

/// Bucket meta holding structured ACP grants as compact JSON (same shape).
pub const S3_BUCKET_ACL_JSON_META: &str = "X-Container-Meta-S3-Acl-Json";

// ---------------------------------------------------------------------------
// ACL
// ---------------------------------------------------------------------------

fn grantee_canonical_user(id: &str, display_name: &str) -> Element {
    // Python s3api/subresource.py User.elem(): xmlns:xsi + xsi:type=CanonicalUser.
    Element::new("Grantee")
        .with_xmlns("xsi", XMLNS_XSI)
        .with_attr("xsi:type", "CanonicalUser")
        .with_leaf("ID", id)
        .with_leaf("DisplayName", display_name)
}

fn grantee_group(uri: &str) -> Element {
    Element::new("Grantee")
        .with_xmlns("xsi", XMLNS_XSI)
        .with_attr("xsi:type", "Group")
        .with_leaf("URI", uri)
}

fn grantee_email(email: &str) -> Element {
    Element::new("Grantee")
        .with_xmlns("xsi", XMLNS_XSI)
        .with_attr("xsi:type", "AmazonCustomerByEmail")
        .with_leaf("EmailAddress", email)
}

fn owner_grant(owner_id: &str) -> Element {
    Element::new("Grant")
        .with(grantee_canonical_user(owner_id, owner_id))
        .with_leaf("Permission", "FULL_CONTROL")
}

fn group_grant(uri: &str, permission: &str) -> Element {
    Element::new("Grant")
        .with(grantee_group(uri))
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
/// for the canned names that Swift can express. Clears structured JSON policy
/// so GET `?acl` uses the canned / container-header path.
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
    headers.set(S3_BUCKET_ACL_JSON_META, "");
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

/// Normalize a canned ACL name for object storage.
///
/// Claimable: `private`, `public-read` (and empty → private).
/// `public-read-write` is stored as-is for GET `?acl` XML fidelity.
/// `bucket-owner-*` collapse to `private` (Python non-s3_acl best-effort).
/// Unsupported names (`authenticated-read`, …) → `private`.
pub fn normalize_object_canned_acl(canned: &str) -> &'static str {
    match canned {
        "public-read" => "public-read",
        "public-read-write" => "public-read-write",
        "private" | "" | "bucket-owner-read" | "bucket-owner-full-control" => "private",
        _ => "private",
    }
}

/// Stamp object sysmeta for a canned `x-amz-acl` (does not set container ACL).
/// Clears structured JSON grants so GET prefers canned reconstruction.
pub fn apply_object_canned_acl(headers: &mut HeaderKeyDict, canned: &str) {
    headers.set(S3_OBJECT_ACL_META, normalize_object_canned_acl(canned));
    headers.set(S3_OBJECT_ACL_JSON_META, "");
}

/// Build AccessControlPolicy XML from stored object canned ACL meta.
pub fn object_acl_xml_from_meta(owner_id: &str, canned: Option<&str>) -> Vec<u8> {
    match normalize_object_canned_acl(canned.unwrap_or("private")) {
        "public-read" => public_read_acl_xml(owner_id),
        "public-read-write" => public_read_write_acl_xml(owner_id),
        _ => private_acl_xml(owner_id),
    }
}

/// Whether a stored object canned ACL *would* grant AllUsers READ under S3
/// semantics (`public-read` / `public-read-write`).
///
/// Used by unsigned GET/HEAD when [`crate::middleware::S3Api::anonymous_account`]
/// is configured: object `public-read` / AllUsers READ may pass after the
/// Swift container `.r:*` hop succeeds. Without `anonymous_account`, unsigned
/// traffic never enters this check (passthrough). Multi-tenant deployments
/// must set the account explicitly — path-style alone cannot infer it.
pub fn object_canned_allows_anonymous_read(canned: Option<&str>) -> bool {
    matches!(
        normalize_object_canned_acl(canned.unwrap_or("private")),
        "public-read" | "public-read-write"
    )
}

// ---------------------------------------------------------------------------
// Structured grants (ACP XML + x-amz-grant-* headers)
// ---------------------------------------------------------------------------

/// Grantee identity in an S3 Grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Grantee {
    /// Canonical user id (+ optional display name).
    Id {
        id: String,
        display_name: Option<String>,
    },
    /// Predefined group URI (AllUsers, AuthenticatedUsers, LogDelivery, …).
    Uri { uri: String },
    /// emailAddress form (stored for fidelity; not resolved to canonical id).
    Email { email: String },
}

/// One Grant: grantee + permission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub grantee: Grantee,
    pub permission: String,
}

/// Full AccessControlPolicy (owner + grants).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessControlPolicy {
    pub owner_id: String,
    pub owner_display_name: Option<String>,
    pub grants: Vec<Grant>,
}

impl AccessControlPolicy {
    /// Owner-only FULL_CONTROL private policy.
    pub fn private(owner_id: &str) -> Self {
        Self {
            owner_id: owner_id.to_string(),
            owner_display_name: Some(owner_id.to_string()),
            grants: vec![Grant {
                grantee: Grantee::Id {
                    id: owner_id.to_string(),
                    display_name: Some(owner_id.to_string()),
                },
                permission: "FULL_CONTROL".into(),
            }],
        }
    }
}

fn normalize_permission(raw: &str) -> Option<String> {
    let up = raw.trim().to_ascii_uppercase().replace('-', "_");
    if ACL_PERMISSIONS.contains(&up.as_str()) {
        Some(up)
    } else {
        None
    }
}

fn first_tag_text(text: &str, tag: &str) -> Option<String> {
    extract_tag_values(text, tag).into_iter().next()
}

fn grant_element(g: &Grant) -> Element {
    let grantee_el = match &g.grantee {
        Grantee::Id { id, display_name } => {
            let dn = display_name.as_deref().unwrap_or(id.as_str());
            grantee_canonical_user(id, dn)
        }
        Grantee::Uri { uri } => grantee_group(uri),
        Grantee::Email { email } => grantee_email(email),
    };
    Element::new("Grant")
        .with(grantee_el)
        .with_leaf("Permission", g.permission.as_str())
}

/// Serialize structured policy to AccessControlPolicy XML.
pub fn access_control_policy_xml(policy: &AccessControlPolicy) -> Vec<u8> {
    let owner_dn = policy
        .owner_display_name
        .as_deref()
        .unwrap_or(policy.owner_id.as_str());
    let mut root = Element::new("AccessControlPolicy");
    root.push(
        Element::new("Owner")
            .with_leaf("ID", policy.owner_id.as_str())
            .with_leaf("DisplayName", owner_dn),
    );
    let mut acl = Element::new("AccessControlList");
    for g in &policy.grants {
        acl.push(grant_element(g));
    }
    root.push(acl);
    root.to_xml(true)
}

/// Parse AccessControlPolicy XML body into structured grants.
pub fn parse_acp_xml(body: &[u8]) -> Result<AccessControlPolicy, String> {
    let text = std::str::from_utf8(body).map_err(|_| "MalformedACLError".to_string())?;
    if !text.contains("AccessControlPolicy") {
        return Err("MalformedACLError".into());
    }
    // Owner block (best-effort; default empty then filled by caller if needed).
    let owner_section = text
        .find("<Owner>")
        .and_then(|s| {
            let rest = &text[s..];
            rest.find("</Owner>")
                .map(|e| rest[..e + "</Owner>".len()].to_string())
        })
        .unwrap_or_default();
    let owner_id = first_tag_text(&owner_section, "ID").unwrap_or_default();
    let owner_display_name = first_tag_text(&owner_section, "DisplayName");

    let mut grants = Vec::new();
    let mut rest = text;
    let open = "<Grant>";
    let close = "</Grant>";
    while let Some(s) = rest.find(open) {
        let start = s + open.len();
        let Some(end_rel) = rest[start..].find(close) else {
            break;
        };
        let grant_body = &rest[start..start + end_rel];
        rest = &rest[start + end_rel + close.len()..];

        let Some(perm_raw) = first_tag_text(grant_body, "Permission") else {
            continue;
        };
        let Some(permission) = normalize_permission(&perm_raw) else {
            return Err("MalformedACLError".into());
        };

        let grantee = if let Some(id) = first_tag_text(grant_body, "ID") {
            Grantee::Id {
                display_name: first_tag_text(grant_body, "DisplayName"),
                id,
            }
        } else if let Some(uri) = first_tag_text(grant_body, "URI") {
            Grantee::Uri { uri }
        } else if let Some(email) = first_tag_text(grant_body, "EmailAddress") {
            Grantee::Email { email }
        } else {
            return Err("MalformedACLError".into());
        };
        grants.push(Grant {
            grantee,
            permission,
        });
    }
    Ok(AccessControlPolicy {
        owner_id,
        owner_display_name,
        grants,
    })
}

/// Parse one grantee token from grant-header list form:
/// `id=…`, `uri=…`, or `emailAddress=…` (optional quotes).
pub fn parse_grantee_token(token: &str) -> Result<Grantee, String> {
    let token = token.trim();
    if token.is_empty() {
        return Err("InvalidArgument".into());
    }
    let Some((kind, value)) = token.split_once('=') else {
        return Err("InvalidArgument".into());
    };
    let kind = kind.trim().to_ascii_lowercase();
    let value = value.trim().trim_matches(|c| c == '"' || c == '\'');
    if value.is_empty() {
        return Err("InvalidArgument".into());
    }
    match kind.as_str() {
        "id" => Ok(Grantee::Id {
            id: value.to_string(),
            display_name: Some(value.to_string()),
        }),
        "uri" => Ok(Grantee::Uri {
            uri: value.to_string(),
        }),
        "emailaddress" | "email" => Ok(Grantee::Email {
            email: value.to_string(),
        }),
        _ => Err("InvalidArgument".into()),
    }
}

/// Parse comma-separated grantee list for one permission header value.
pub fn parse_grant_header_value(value: &str, permission: &str) -> Result<Vec<Grant>, String> {
    let Some(permission) = normalize_permission(permission) else {
        return Err("InvalidArgument".into());
    };
    let mut grants = Vec::new();
    // Split on commas that separate grantees (values themselves rarely contain commas).
    for part in value.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        grants.push(Grant {
            grantee: parse_grantee_token(part)?,
            permission: permission.clone(),
        });
    }
    Ok(grants)
}

/// Header name → permission mapping for `x-amz-grant-*`.
fn grant_header_permission(header_lower: &str) -> Option<&'static str> {
    match header_lower {
        "x-amz-grant-read" => Some("READ"),
        "x-amz-grant-write" => Some("WRITE"),
        "x-amz-grant-full-control" => Some("FULL_CONTROL"),
        "x-amz-grant-read-acp" => Some("READ_ACP"),
        "x-amz-grant-write-acp" => Some("WRITE_ACP"),
        _ => None,
    }
}

/// Whether any `x-amz-grant-*` headers are present.
pub fn has_grant_headers(headers: &HeaderKeyDict) -> bool {
    headers
        .iter()
        .any(|(k, _)| grant_header_permission(&k.to_ascii_lowercase()).is_some())
}

/// Collect grants from `x-amz-grant-*` headers.
pub fn parse_grant_headers(headers: &HeaderKeyDict) -> Result<Vec<Grant>, String> {
    let mut grants = Vec::new();
    for (k, v) in headers.iter() {
        let lower = k.to_ascii_lowercase();
        if let Some(perm) = grant_header_permission(&lower) {
            grants.extend(parse_grant_header_value(v, perm)?);
        }
    }
    Ok(grants)
}

/// Encode policy to compact JSON for sysmeta / container meta.
pub fn encode_acl_json(policy: &AccessControlPolicy) -> String {
    let grants: Vec<Value> = policy
        .grants
        .iter()
        .map(|g| {
            let mut m = serde_json::Map::new();
            m.insert("Permission".into(), json!(g.permission));
            match &g.grantee {
                Grantee::Id { id, display_name } => {
                    m.insert("ID".into(), json!(id));
                    if let Some(dn) = display_name {
                        m.insert("DisplayName".into(), json!(dn));
                    }
                }
                Grantee::Uri { uri } => {
                    m.insert("URI".into(), json!(uri));
                }
                Grantee::Email { email } => {
                    m.insert("EmailAddress".into(), json!(email));
                }
            }
            Value::Object(m)
        })
        .collect();
    let mut root = serde_json::Map::new();
    root.insert("Owner".into(), json!(policy.owner_id));
    if let Some(dn) = &policy.owner_display_name {
        root.insert("OwnerDisplayName".into(), json!(dn));
    }
    root.insert("Grant".into(), Value::Array(grants));
    Value::Object(root).to_string()
}

/// Decode compact JSON policy; `None` if empty / invalid.
pub fn decode_acl_json(raw: &str) -> Option<AccessControlPolicy> {
    if raw.is_empty() {
        return None;
    }
    let v: Value = serde_json::from_str(raw).ok()?;
    let obj = v.as_object()?;
    let owner_id = obj
        .get("Owner")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let owner_display_name = obj
        .get("OwnerDisplayName")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string());
    let mut grants = Vec::new();
    if let Some(arr) = obj.get("Grant").and_then(|x| x.as_array()) {
        for g in arr {
            let Some(go) = g.as_object() else {
                continue;
            };
            let perm = go.get("Permission").and_then(|x| x.as_str()).unwrap_or("");
            let Some(permission) = normalize_permission(perm) else {
                continue;
            };
            let grantee = if let Some(id) = go.get("ID").and_then(|x| x.as_str()) {
                Grantee::Id {
                    id: id.to_string(),
                    display_name: go
                        .get("DisplayName")
                        .and_then(|x| x.as_str())
                        .map(|s| s.to_string()),
                }
            } else if let Some(uri) = go.get("URI").and_then(|x| x.as_str()) {
                Grantee::Uri {
                    uri: uri.to_string(),
                }
            } else if let Some(email) = go.get("EmailAddress").and_then(|x| x.as_str()) {
                Grantee::Email {
                    email: email.to_string(),
                }
            } else {
                continue;
            };
            grants.push(Grant {
                grantee,
                permission,
            });
        }
    }
    Some(AccessControlPolicy {
        owner_id,
        owner_display_name,
        grants,
    })
}

/// Map AllUsers READ/WRITE grants onto Swift container ACL headers.
pub fn apply_grants_to_container(headers: &mut HeaderKeyDict, grants: &[Grant]) {
    let mut public_read = false;
    let mut public_write = false;
    for g in grants {
        let is_all_users = matches!(&g.grantee, Grantee::Uri { uri } if uri == ALL_USERS);
        if !is_all_users {
            continue;
        }
        match g.permission.as_str() {
            "READ" | "READ_ACP" => public_read = true,
            "WRITE" | "WRITE_ACP" => public_write = true,
            "FULL_CONTROL" => {
                public_read = true;
                public_write = true;
            }
            _ => {}
        }
    }
    if public_read {
        headers.set("X-Container-Read", ".r:*,.rlistings");
    } else {
        headers.set("X-Container-Read", "");
    }
    if public_write {
        headers.set("X-Container-Write", ".r:*");
    } else {
        headers.set("X-Container-Write", "");
    }
}

/// Store structured object ACL JSON (clears canned name meta).
pub fn apply_object_acl_policy(headers: &mut HeaderKeyDict, policy: &AccessControlPolicy) {
    headers.set(S3_OBJECT_ACL_JSON_META, encode_acl_json(policy));
    headers.set(S3_OBJECT_ACL_META, "");
}

/// Store structured bucket ACL JSON + map AllUsers to container read/write.
pub fn apply_bucket_acl_policy(headers: &mut HeaderKeyDict, policy: &AccessControlPolicy) {
    headers.set(S3_BUCKET_ACL_JSON_META, encode_acl_json(policy));
    apply_grants_to_container(headers, &policy.grants);
}

/// Build object ACP XML from response headers (JSON grants preferred, else canned).
pub fn object_acl_xml_from_headers(owner_id: &str, headers: &HeaderKeyDict) -> Vec<u8> {
    if let Some(raw) = headers
        .get(S3_OBJECT_ACL_JSON_META)
        .or_else(|| headers.get("X-Object-Meta-S3-Acl-Json"))
    {
        if let Some(mut policy) = decode_acl_json(raw) {
            if policy.owner_id.is_empty() {
                policy.owner_id = owner_id.to_string();
            }
            return access_control_policy_xml(&policy);
        }
    }
    let canned = headers
        .get(S3_OBJECT_ACL_META)
        .or_else(|| headers.get("X-Object-Meta-S3-Acl"));
    object_acl_xml_from_meta(owner_id, canned)
}

/// Build bucket ACP XML from headers (JSON grants preferred, else container ACL).
pub fn bucket_acl_xml_from_headers(owner_id: &str, headers: &HeaderKeyDict) -> Vec<u8> {
    if let Some(raw) = headers.get(S3_BUCKET_ACL_JSON_META) {
        if let Some(mut policy) = decode_acl_json(raw) {
            if policy.owner_id.is_empty() {
                policy.owner_id = owner_id.to_string();
            }
            return access_control_policy_xml(&policy);
        }
    }
    acl_xml_from_swift_headers(
        owner_id,
        headers.get("X-Container-Read"),
        headers.get("X-Container-Write"),
    )
}

/// Whether grants include AllUsers READ / FULL_CONTROL (S3 anonymous-read intent).
///
/// Pure helper — **not** wired into unauthenticated authorization.
pub fn grants_allow_anonymous_read(grants: &[Grant]) -> bool {
    grants.iter().any(|g| {
        matches!(&g.grantee, Grantee::Uri { uri } if uri == ALL_USERS)
            && matches!(g.permission.as_str(), "READ" | "FULL_CONTROL")
    })
}

fn permission_allows_object_read(permission: &str) -> bool {
    matches!(permission, "READ" | "FULL_CONTROL")
}

/// True when `id` matches the request principal (`access_key` and/or account).
fn principal_matches(id: &str, principal_access_key: &str, principal_account: &str) -> bool {
    !id.is_empty()
        && (id == principal_access_key
            || (!principal_account.is_empty() && id == principal_account))
}

/// Whether structured object ACL JSON grants allow this principal to READ
/// object content (GET/HEAD).
///
/// # Return values
/// * `None` — missing/empty JSON grants: **no enforcement** (keep canned/Swift
///   path; do not invent denials).
/// * `Some(true)` — principal is owner, or holds READ/FULL_CONTROL (Id grantee
///   match on access_key/account, or AllUsers/AuthenticatedUsers URI for
///   **authenticated** callers that reach this check).
/// * `Some(false)` — non-empty grants present and principal is not authorized.
///
/// # Residuals
/// * EmailAddress grantees are **not** resolved (never match).
/// * AllUsers READ does **not** open the anonymous unauthenticated path:
///   requests without SigV4 never enter s3api ACL evaluation.
pub fn object_grants_allow_read(
    headers: &HeaderKeyDict,
    principal_access_key: &str,
    principal_account: &str,
) -> Option<bool> {
    let raw = headers
        .get(S3_OBJECT_ACL_JSON_META)
        .or_else(|| headers.get("X-Object-Meta-S3-Acl-Json"))?;
    if raw.is_empty() {
        return None;
    }
    let policy = decode_acl_json(raw)?;
    if policy.grants.is_empty() {
        return None;
    }

    // Owner always allowed.
    if principal_matches(&policy.owner_id, principal_access_key, principal_account) {
        return Some(true);
    }

    for g in &policy.grants {
        if !permission_allows_object_read(&g.permission) {
            continue;
        }
        match &g.grantee {
            Grantee::Id { id, .. } => {
                if principal_matches(id, principal_access_key, principal_account) {
                    return Some(true);
                }
            }
            Grantee::Uri { uri } => {
                // Authenticated SigV4 callers only invoke this helper.
                if uri == ALL_USERS || uri == AUTH_USERS {
                    return Some(true);
                }
            }
            Grantee::Email { email } => {
                // Without directory, email never matches (IAM residual closed
                // via object_grants_allow_read_with_iam).
                let _ = email;
            }
        }
    }
    Some(false)
}

/// READ check with optional [`crate::iam::IdentityDirectory`] for email +
/// access_key → canonical id resolution.
pub fn object_grants_allow_read_with_iam(
    headers: &HeaderKeyDict,
    principal_access_key: &str,
    principal_account: &str,
    iam: Option<&crate::iam::IdentityDirectory>,
) -> Option<bool> {
    let raw = headers
        .get(S3_OBJECT_ACL_JSON_META)
        .or_else(|| headers.get("X-Object-Meta-S3-Acl-Json"))?;
    if raw.is_empty() {
        return None;
    }
    let policy = decode_acl_json(raw)?;
    if policy.grants.is_empty() {
        return None;
    }
    let owner = if policy.owner_id.is_empty() {
        principal_account
    } else {
        policy.owner_id.as_str()
    };
    if principal_matches(owner, principal_access_key, principal_account) {
        return Some(true);
    }
    if let Some(dir) = iam {
        if dir.principal_matches_id(owner, principal_access_key, principal_account) {
            return Some(true);
        }
    }
    for g in &policy.grants {
        if !permission_allows_object_read(&g.permission) {
            continue;
        }
        match &g.grantee {
            Grantee::Id { id, .. } => {
                if principal_matches(id, principal_access_key, principal_account) {
                    return Some(true);
                }
                if let Some(dir) = iam {
                    if dir.principal_matches_id(id, principal_access_key, principal_account) {
                        return Some(true);
                    }
                }
            }
            Grantee::Uri { uri } => {
                if uri == ALL_USERS || uri == AUTH_USERS {
                    return Some(true);
                }
            }
            Grantee::Email { email } => {
                if let Some(dir) = iam {
                    if let Some(id) = dir.resolve_email(email) {
                        if dir.principal_matches_id(&id, principal_access_key, principal_account)
                            || principal_matches(&id, principal_access_key, principal_account)
                        {
                            return Some(true);
                        }
                    }
                }
            }
        }
    }
    Some(false)
}

/// WRITE permission for object overwrite / DELETE / PUT.
fn permission_allows_object_write(permission: &str) -> bool {
    matches!(permission, "WRITE" | "FULL_CONTROL")
}

/// Whether structured grants allow object WRITE (overwrite/delete).
/// Same `None` / `Some` semantics as [`object_grants_allow_read`].
pub fn object_grants_allow_write(
    headers: &HeaderKeyDict,
    principal_access_key: &str,
    principal_account: &str,
) -> Option<bool> {
    object_grants_allow_write_with_iam(headers, principal_access_key, principal_account, None)
}

pub fn object_grants_allow_write_with_iam(
    headers: &HeaderKeyDict,
    principal_access_key: &str,
    principal_account: &str,
    iam: Option<&crate::iam::IdentityDirectory>,
) -> Option<bool> {
    let raw = headers
        .get(S3_OBJECT_ACL_JSON_META)
        .or_else(|| headers.get("X-Object-Meta-S3-Acl-Json"))?;
    if raw.is_empty() {
        return None;
    }
    let policy = decode_acl_json(raw)?;
    if policy.grants.is_empty() {
        return None;
    }
    let owner = if policy.owner_id.is_empty() {
        principal_account
    } else {
        policy.owner_id.as_str()
    };
    if principal_matches(owner, principal_access_key, principal_account) {
        return Some(true);
    }
    if let Some(dir) = iam {
        if dir.principal_matches_id(owner, principal_access_key, principal_account) {
            return Some(true);
        }
    }
    for g in &policy.grants {
        if !permission_allows_object_write(&g.permission) {
            continue;
        }
        match &g.grantee {
            Grantee::Id { id, .. } => {
                if principal_matches(id, principal_access_key, principal_account) {
                    return Some(true);
                }
                if let Some(dir) = iam {
                    if dir.principal_matches_id(id, principal_access_key, principal_account) {
                        return Some(true);
                    }
                }
            }
            Grantee::Uri { uri } => {
                if uri == ALL_USERS || uri == AUTH_USERS {
                    return Some(true);
                }
            }
            Grantee::Email { email } => {
                if let Some(dir) = iam {
                    if let Some(id) = dir.resolve_email(email) {
                        if dir.principal_matches_id(&id, principal_access_key, principal_account)
                            || principal_matches(&id, principal_access_key, principal_account)
                        {
                            return Some(true);
                        }
                    }
                }
            }
        }
    }
    Some(false)
}

/// True when object JSON ACL is present with non-empty grants and the
/// principal is **denied** object READ (GET/HEAD → AccessDenied).
///
/// Missing/empty grants → `false` (no new denial).
pub fn object_acl_denies_read(
    headers: &HeaderKeyDict,
    principal_access_key: &str,
    principal_account: &str,
) -> bool {
    matches!(
        object_grants_allow_read(headers, principal_access_key, principal_account),
        Some(false)
    )
}

pub fn object_acl_denies_write(
    headers: &HeaderKeyDict,
    principal_access_key: &str,
    principal_account: &str,
) -> bool {
    matches!(
        object_grants_allow_write(headers, principal_access_key, principal_account),
        Some(false)
    )
}

fn policy_from_bucket_headers(headers: &HeaderKeyDict) -> Option<AccessControlPolicy> {
    let raw = headers.get(S3_BUCKET_ACL_JSON_META)?;
    if raw.is_empty() {
        return None;
    }
    let policy = decode_acl_json(raw)?;
    if policy.grants.is_empty() {
        return None;
    }
    Some(policy)
}

/// Bucket READ (ListObjects / HEAD bucket) from stored JSON grants.
pub fn bucket_grants_allow_read(
    headers: &HeaderKeyDict,
    principal_access_key: &str,
    principal_account: &str,
) -> Option<bool> {
    let policy = policy_from_bucket_headers(headers)?;
    if principal_matches(&policy.owner_id, principal_access_key, principal_account) {
        return Some(true);
    }
    for g in &policy.grants {
        if !permission_allows_object_read(&g.permission) {
            continue;
        }
        match &g.grantee {
            Grantee::Id { id, .. } => {
                if principal_matches(id, principal_access_key, principal_account) {
                    return Some(true);
                }
            }
            Grantee::Uri { uri } => {
                if uri == ALL_USERS || uri == AUTH_USERS {
                    return Some(true);
                }
            }
            Grantee::Email { .. } => {}
        }
    }
    Some(false)
}

/// Bucket WRITE (PUT/DELETE object, PUT bucket ACL) from stored JSON grants.
pub fn bucket_grants_allow_write(
    headers: &HeaderKeyDict,
    principal_access_key: &str,
    principal_account: &str,
) -> Option<bool> {
    let policy = policy_from_bucket_headers(headers)?;
    if principal_matches(&policy.owner_id, principal_access_key, principal_account) {
        return Some(true);
    }
    for g in &policy.grants {
        if !permission_allows_object_write(&g.permission) {
            continue;
        }
        match &g.grantee {
            Grantee::Id { id, .. } => {
                if principal_matches(id, principal_access_key, principal_account) {
                    return Some(true);
                }
            }
            Grantee::Uri { uri } => {
                if uri == ALL_USERS || uri == AUTH_USERS {
                    return Some(true);
                }
            }
            Grantee::Email { .. } => {}
        }
    }
    Some(false)
}

pub fn bucket_acl_denies_read(
    headers: &HeaderKeyDict,
    principal_access_key: &str,
    principal_account: &str,
) -> bool {
    matches!(
        bucket_grants_allow_read(headers, principal_access_key, principal_account),
        Some(false)
    )
}

pub fn bucket_acl_denies_write(
    headers: &HeaderKeyDict,
    principal_access_key: &str,
    principal_account: &str,
) -> bool {
    matches!(
        bucket_grants_allow_write(headers, principal_access_key, principal_account),
        Some(false)
    )
}

/// Resolved ACL input for PUT object/bucket (canned takes precedence).
#[derive(Debug, Clone)]
pub enum AclPutInput {
    /// `x-amz-acl` canned name (wins over grants / body).
    Canned(String),
    /// Structured policy from grant headers and/or ACP body.
    Policy(AccessControlPolicy),
    /// No ACL material; caller may default to private for `?acl` PUT.
    None,
}

/// Resolve ACL PUT input with AWS-like precedence: canned first, then grants,
/// then ACP XML body.
pub fn resolve_acl_put_input(
    headers: &HeaderKeyDict,
    body: Option<&[u8]>,
    default_owner_id: &str,
) -> Result<AclPutInput, String> {
    if let Some(canned) = headers.get("X-Amz-Acl") {
        // Canned wins even if grant headers / body present.
        return Ok(AclPutInput::Canned(canned.to_string()));
    }

    let mut grants = Vec::new();
    if has_grant_headers(headers) {
        grants.extend(parse_grant_headers(headers)?);
    }

    let body_nonempty = body.is_some_and(|b| {
        let t = std::str::from_utf8(b).unwrap_or("").trim();
        !t.is_empty()
    });
    if body_nonempty {
        let mut policy = parse_acp_xml(body.unwrap())?;
        if policy.owner_id.is_empty() {
            policy.owner_id = default_owner_id.to_string();
        }
        // Merge grant-header grants into body policy (headers already forbid
        // canned+grants; body+grants is unusual — append header grants).
        policy.grants.extend(grants);
        return Ok(AclPutInput::Policy(policy));
    }

    if !grants.is_empty() {
        return Ok(AclPutInput::Policy(AccessControlPolicy {
            owner_id: default_owner_id.to_string(),
            owner_display_name: Some(default_owner_id.to_string()),
            grants,
        }));
    }

    Ok(AclPutInput::None)
}

/// Apply resolved ACL input to object headers (sysmeta only).
pub fn apply_object_acl_input(headers: &mut HeaderKeyDict, input: &AclPutInput) {
    match input {
        AclPutInput::Canned(c) => apply_object_canned_acl(headers, c),
        AclPutInput::Policy(p) => apply_object_acl_policy(headers, p),
        AclPutInput::None => {}
    }
}

/// Canned ACL → structured policy (Python `canned_acl_grantees`).
pub fn policy_from_canned(owner_id: &str, canned: &str) -> AccessControlPolicy {
    let owner_grant = Grant {
        grantee: Grantee::Id {
            id: owner_id.to_string(),
            display_name: Some(owner_id.to_string()),
        },
        permission: "FULL_CONTROL".into(),
    };
    let all_users_read = Grant {
        grantee: Grantee::Uri {
            uri: ALL_USERS.to_string(),
        },
        permission: "READ".into(),
    };
    let all_users_write = Grant {
        grantee: Grantee::Uri {
            uri: ALL_USERS.to_string(),
        },
        permission: "WRITE".into(),
    };
    let auth_read = Grant {
        grantee: Grantee::Uri {
            uri: AUTH_USERS.to_string(),
        },
        permission: "READ".into(),
    };
    match canned.trim() {
        "public-read" => AccessControlPolicy {
            owner_id: owner_id.to_string(),
            owner_display_name: Some(owner_id.to_string()),
            grants: vec![all_users_read, owner_grant],
        },
        "public-read-write" => AccessControlPolicy {
            owner_id: owner_id.to_string(),
            owner_display_name: Some(owner_id.to_string()),
            grants: vec![all_users_read, all_users_write, owner_grant],
        },
        "authenticated-read" => AccessControlPolicy {
            owner_id: owner_id.to_string(),
            owner_display_name: Some(owner_id.to_string()),
            grants: vec![auth_read, owner_grant],
        },
        _ => AccessControlPolicy::private(owner_id),
    }
}

fn stamp_object_canned_with_json(headers: &mut HeaderKeyDict, canned: &str, owner_id: &str) {
    let name = normalize_object_canned_acl(canned);
    headers.set(S3_OBJECT_ACL_META, name);
    headers.set(
        S3_OBJECT_ACL_JSON_META,
        encode_acl_json(&policy_from_canned(owner_id, canned)),
    );
}

fn stamp_bucket_canned_with_json(headers: &mut HeaderKeyDict, canned: &str, owner_id: &str) {
    apply_canned_acl(headers, canned);
    headers.set(
        S3_BUCKET_ACL_JSON_META,
        encode_acl_json(&policy_from_canned(owner_id, canned)),
    );
}

/// Object PUT ACL with Python `s3_acl` default-private stamping.
///
/// When `default_private` is true (live `[filter:s3api] s3_acl = true`), a
/// missing canned/grant/ACP body becomes canned `private` **and** JSON grants
/// so GET/HEAD deny helpers can 403 non-owners. When false, `None` is a no-op
/// (historical non-s3_acl path).
pub fn apply_object_acl_put(
    headers: &mut HeaderKeyDict,
    input: &AclPutInput,
    owner_id: &str,
    default_private: bool,
) {
    let resolved = match input {
        AclPutInput::None if default_private => AclPutInput::Canned("private".into()),
        other => other.clone(),
    };
    match &resolved {
        AclPutInput::None => {}
        AclPutInput::Canned(c) => stamp_object_canned_with_json(headers, c, owner_id),
        AclPutInput::Policy(p) => apply_object_acl_policy(headers, p),
    }
}

/// Bucket PUT ACL. `None` already maps to canned private container headers;
/// with `default_private` also persist JSON grants for same-account alt-user
/// enforcement (TempAuth Swift-owner override bypasses container ACL).
pub fn apply_bucket_acl_put(
    headers: &mut HeaderKeyDict,
    input: &AclPutInput,
    owner_id: &str,
    default_private: bool,
) {
    let resolved = match input {
        AclPutInput::None if default_private => AclPutInput::Canned("private".into()),
        other => other.clone(),
    };
    match &resolved {
        AclPutInput::None => apply_canned_acl(headers, "private"),
        AclPutInput::Canned(c) => {
            if default_private || !c.is_empty() {
                stamp_bucket_canned_with_json(headers, c, owner_id);
            } else {
                apply_canned_acl(headers, c);
            }
        }
        AclPutInput::Policy(p) => apply_bucket_acl_policy(headers, p),
    }
}

/// Apply resolved ACL input to bucket/container headers.
pub fn apply_bucket_acl_input(headers: &mut HeaderKeyDict, input: &AclPutInput) {
    match input {
        AclPutInput::Canned(c) => apply_canned_acl(headers, c),
        AclPutInput::Policy(p) => apply_bucket_acl_policy(headers, p),
        AclPutInput::None => apply_canned_acl(headers, "private"),
    }
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
    let mut rule = CorsRule {
        allowed_origins: extract_tag_values(rule_xml, "AllowedOrigin"),
        allowed_methods: extract_tag_values(rule_xml, "AllowedMethod"),
        allowed_headers: extract_tag_values(rule_xml, "AllowedHeader"),
        expose_headers: extract_tag_values(rule_xml, "ExposeHeader"),
        ..Default::default()
    };
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
        headers.set("X-Container-Meta-Access-Control-Max-Age", age.to_string());
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
        assert_eq!(h.get("X-Container-Read"), Some(".r:*,.rlistings"));
        assert_eq!(h.get("X-Container-Write"), Some(".r:*"));
    }

    #[test]
    fn apply_canned_public_read() {
        let mut h = HeaderKeyDict::new();
        apply_canned_acl(&mut h, "public-read");
        assert_eq!(h.get("X-Container-Read"), Some(".r:*,.rlistings"));
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
    fn object_canned_acl_private_and_public_read() {
        assert_eq!(normalize_object_canned_acl("private"), "private");
        assert_eq!(normalize_object_canned_acl(""), "private");
        assert_eq!(normalize_object_canned_acl("public-read"), "public-read");
        assert_eq!(normalize_object_canned_acl("bucket-owner-read"), "private");
        assert_eq!(normalize_object_canned_acl("authenticated-read"), "private");

        let mut h = HeaderKeyDict::new();
        apply_object_canned_acl(&mut h, "public-read");
        assert_eq!(h.get(S3_OBJECT_ACL_META), Some("public-read"));
        // Must not stamp container ACL headers on objects.
        assert!(h.get("X-Container-Read").is_none());

        let xml =
            String::from_utf8(object_acl_xml_from_meta("owner", Some("public-read"))).unwrap();
        assert!(xml.contains(ALL_USERS));
        assert!(xml.contains("<Permission>READ</Permission>"));
        assert!(!xml.contains("<Permission>WRITE</Permission>"));

        let priv_xml = String::from_utf8(object_acl_xml_from_meta("owner", None)).unwrap();
        assert!(priv_xml.contains("FULL_CONTROL"));
        assert!(!priv_xml.contains(ALL_USERS));

        assert!(object_canned_allows_anonymous_read(Some("public-read")));
        assert!(object_canned_allows_anonymous_read(Some(
            "public-read-write"
        )));
        assert!(!object_canned_allows_anonymous_read(Some("private")));
        assert!(!object_canned_allows_anonymous_read(None));
        assert!(!object_canned_allows_anonymous_read(Some(
            "authenticated-read"
        )));
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

    #[test]
    fn acp_xml_roundtrip_structured_grants() {
        let body = br#"<?xml version="1.0" encoding="UTF-8"?>
<AccessControlPolicy>
  <Owner>
    <ID>owner1</ID>
    <DisplayName>owner1</DisplayName>
  </Owner>
  <AccessControlList>
    <Grant>
      <Grantee>
        <ID>owner1</ID>
        <DisplayName>owner1</DisplayName>
      </Grantee>
      <Permission>FULL_CONTROL</Permission>
    </Grant>
    <Grant>
      <Grantee>
        <URI>http://acs.amazonaws.com/groups/global/AllUsers</URI>
      </Grantee>
      <Permission>READ</Permission>
    </Grant>
    <Grant>
      <Grantee>
        <URI>http://acs.amazonaws.com/groups/global/AllUsers</URI>
      </Grantee>
      <Permission>WRITE_ACP</Permission>
    </Grant>
  </AccessControlList>
</AccessControlPolicy>"#;
        let policy = parse_acp_xml(body).unwrap();
        assert_eq!(policy.owner_id, "owner1");
        assert_eq!(policy.grants.len(), 3);
        assert_eq!(policy.grants[0].permission, "FULL_CONTROL");
        assert!(matches!(&policy.grants[0].grantee, Grantee::Id { id, .. } if id == "owner1"));
        assert_eq!(policy.grants[1].permission, "READ");
        assert!(matches!(
            &policy.grants[1].grantee,
            Grantee::Uri { uri } if uri == ALL_USERS
        ));
        assert_eq!(policy.grants[2].permission, "WRITE_ACP");

        let json = encode_acl_json(&policy);
        let dec = decode_acl_json(&json).unwrap();
        assert_eq!(dec.owner_id, "owner1");
        assert_eq!(dec.grants.len(), 3);

        let xml = String::from_utf8(access_control_policy_xml(&dec)).unwrap();
        assert!(xml.contains("AccessControlPolicy"));
        assert!(xml.contains("<Permission>FULL_CONTROL</Permission>"));
        assert!(xml.contains("<Permission>READ</Permission>"));
        assert!(xml.contains("<Permission>WRITE_ACP</Permission>"));
        assert!(xml.contains(ALL_USERS));
        assert!(xml.contains("<ID>owner1</ID>"));
        assert!(xml.contains("<Grant>"));
    }

    #[test]
    fn grant_read_allusers_maps_public_read_container_headers() {
        let mut h = HeaderKeyDict::new();
        h.set(
            "x-amz-grant-read",
            "uri=http://acs.amazonaws.com/groups/global/AllUsers",
        );
        let grants = parse_grant_headers(&h).unwrap();
        assert_eq!(grants.len(), 1);
        assert!(grants_allow_anonymous_read(&grants));

        let policy = AccessControlPolicy {
            owner_id: "owner".into(),
            owner_display_name: Some("owner".into()),
            grants: {
                let mut g = vec![Grant {
                    grantee: Grantee::Id {
                        id: "owner".into(),
                        display_name: Some("owner".into()),
                    },
                    permission: "FULL_CONTROL".into(),
                }];
                g.extend(grants);
                g
            },
        };
        let mut out = HeaderKeyDict::new();
        apply_bucket_acl_policy(&mut out, &policy);
        assert_eq!(out.get("X-Container-Read"), Some(".r:*,.rlistings"));
        assert_eq!(out.get("X-Container-Write"), Some(""));
        assert!(out
            .get(S3_BUCKET_ACL_JSON_META)
            .is_some_and(|v| v.contains("AllUsers")));

        // GET reconstruction from stored meta.
        let xml = String::from_utf8(bucket_acl_xml_from_headers("owner", &out)).unwrap();
        assert!(xml.contains("<Permission>READ</Permission>"));
        assert!(xml.contains(ALL_USERS));
    }

    #[test]
    fn object_acp_json_store_and_get_xml() {
        let policy = parse_acp_xml(
            br#"<AccessControlPolicy>
  <Owner><ID>o</ID><DisplayName>o</DisplayName></Owner>
  <AccessControlList>
    <Grant>
      <Grantee><ID>o</ID></Grantee>
      <Permission>FULL_CONTROL</Permission>
    </Grant>
    <Grant>
      <Grantee><URI>http://acs.amazonaws.com/groups/global/AllUsers</URI></Grantee>
      <Permission>READ</Permission>
    </Grant>
  </AccessControlList>
</AccessControlPolicy>"#,
        )
        .unwrap();
        let mut h = HeaderKeyDict::new();
        apply_object_acl_policy(&mut h, &policy);
        assert!(h
            .get(S3_OBJECT_ACL_JSON_META)
            .is_some_and(|v| !v.is_empty()));
        assert_eq!(h.get(S3_OBJECT_ACL_META), Some(""));

        let xml = String::from_utf8(object_acl_xml_from_headers("o", &h)).unwrap();
        assert!(xml.contains("<Grant>"));
        assert!(xml.contains("<Permission>FULL_CONTROL</Permission>"));
        assert!(xml.contains("<Permission>READ</Permission>"));
        assert!(xml.contains(ALL_USERS));
    }

    #[test]
    fn canned_takes_precedence_over_grant_headers() {
        let mut h = HeaderKeyDict::new();
        h.set("x-amz-acl", "private");
        h.set(
            "x-amz-grant-read",
            "uri=\"http://acs.amazonaws.com/groups/global/AllUsers\"",
        );
        let input = resolve_acl_put_input(&h, None, "owner").unwrap();
        match input {
            AclPutInput::Canned(c) => assert_eq!(c, "private"),
            _ => panic!("expected canned"),
        }
    }

    #[test]
    fn parse_grant_header_list_form() {
        let grants = parse_grant_header_value(
            r#"id="user-a",uri="http://acs.amazonaws.com/groups/global/AllUsers""#,
            "read",
        )
        .unwrap();
        assert_eq!(grants.len(), 2);
        assert!(matches!(&grants[0].grantee, Grantee::Id { id, .. } if id == "user-a"));
        assert!(matches!(&grants[1].grantee, Grantee::Uri { uri } if uri == ALL_USERS));
        assert_eq!(grants[0].permission, "READ");
    }

    #[test]
    fn resolve_grant_headers_to_policy() {
        let mut h = HeaderKeyDict::new();
        h.set("x-amz-grant-full-control", "id=owner");
        h.set(
            "x-amz-grant-read",
            "uri=http://acs.amazonaws.com/groups/global/AllUsers",
        );
        let input = resolve_acl_put_input(&h, None, "owner").unwrap();
        match input {
            AclPutInput::Policy(p) => {
                assert_eq!(p.owner_id, "owner");
                assert!(p.grants.iter().any(|g| g.permission == "FULL_CONTROL"));
                assert!(p.grants.iter().any(|g| g.permission == "READ"));
            }
            _ => panic!("expected policy"),
        }
    }

    #[test]
    fn object_grants_allow_read_enforcement_matrix() {
        // Missing JSON → no enforcement.
        let empty = HeaderKeyDict::new();
        assert_eq!(object_grants_allow_read(&empty, "foreign", "AUTH_x"), None);
        assert!(!object_acl_denies_read(&empty, "foreign", "AUTH_x"));

        // Empty grants → no enforcement.
        let mut h_empty_grants = HeaderKeyDict::new();
        h_empty_grants.set(S3_OBJECT_ACL_JSON_META, r#"{"Owner":"owner","Grant":[]}"#);
        assert_eq!(
            object_grants_allow_read(&h_empty_grants, "foreign", "AUTH_x"),
            None
        );

        // Private (owner FULL_CONTROL only): owner OK, foreign denied.
        let private = AccessControlPolicy {
            owner_id: "owner-ak".into(),
            owner_display_name: Some("owner-ak".into()),
            grants: vec![Grant {
                grantee: Grantee::Id {
                    id: "owner-ak".into(),
                    display_name: Some("owner-ak".into()),
                },
                permission: "FULL_CONTROL".into(),
            }],
        };
        let mut h = HeaderKeyDict::new();
        apply_object_acl_policy(&mut h, &private);
        assert_eq!(
            object_grants_allow_read(&h, "owner-ak", "AUTH_owner"),
            Some(true)
        );
        // Owner match via account id when policy owner is account form.
        let mut private_acct = private.clone();
        private_acct.owner_id = "AUTH_owner".into();
        let mut h_acct = HeaderKeyDict::new();
        apply_object_acl_policy(&mut h_acct, &private_acct);
        assert_eq!(
            object_grants_allow_read(&h_acct, "other", "AUTH_owner"),
            Some(true)
        );
        assert_eq!(
            object_grants_allow_read(&h, "foreign-ak", "AUTH_foreign"),
            Some(false)
        );
        assert!(object_acl_denies_read(&h, "foreign-ak", "AUTH_foreign"));

        // Explicit READ grant to principal id → allowed.
        let with_read = AccessControlPolicy {
            owner_id: "owner-ak".into(),
            owner_display_name: None,
            grants: vec![
                Grant {
                    grantee: Grantee::Id {
                        id: "owner-ak".into(),
                        display_name: None,
                    },
                    permission: "FULL_CONTROL".into(),
                },
                Grant {
                    grantee: Grantee::Id {
                        id: "friend-ak".into(),
                        display_name: None,
                    },
                    permission: "READ".into(),
                },
            ],
        };
        let mut h2 = HeaderKeyDict::new();
        apply_object_acl_policy(&mut h2, &with_read);
        assert_eq!(
            object_grants_allow_read(&h2, "friend-ak", "AUTH_friend"),
            Some(true)
        );
        assert!(!object_acl_denies_read(&h2, "friend-ak", "AUTH_friend"));
        // READ_ACP alone does not authorize object GET.
        let acp_only = AccessControlPolicy {
            owner_id: "owner-ak".into(),
            owner_display_name: None,
            grants: vec![Grant {
                grantee: Grantee::Id {
                    id: "friend-ak".into(),
                    display_name: None,
                },
                permission: "READ_ACP".into(),
            }],
        };
        let mut h3 = HeaderKeyDict::new();
        apply_object_acl_policy(&mut h3, &acp_only);
        assert_eq!(
            object_grants_allow_read(&h3, "friend-ak", "AUTH_friend"),
            Some(false)
        );
    }
    #[test]
    fn private_acl_xml_emits_xsi_type_canonical_user() {
        let xml = String::from_utf8(private_acl_xml("test:tester")).unwrap();
        assert!(xml.contains("xsi:type=\"CanonicalUser\""), "{xml}");
        assert!(
            xml.contains("xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""),
            "{xml}"
        );
    }

    #[test]
    fn apply_object_acl_put_default_private_stamps_json() {
        let mut h = HeaderKeyDict::new();
        apply_object_acl_put(&mut h, &AclPutInput::None, "test:tester", true);
        assert_eq!(h.get(S3_OBJECT_ACL_META), Some("private"));
        let raw = h.get(S3_OBJECT_ACL_JSON_META).expect("json");
        assert!(!raw.is_empty(), "{raw}");
        assert!(object_acl_denies_read(&h, "test:tester2", "AUTH_test"));
        assert!(!object_acl_denies_read(&h, "test:tester", "AUTH_test"));
    }

    #[test]
    fn apply_object_acl_put_none_without_flag_is_noop() {
        let mut h = HeaderKeyDict::new();
        apply_object_acl_put(&mut h, &AclPutInput::None, "test:tester", false);
        assert!(h.get(S3_OBJECT_ACL_JSON_META).unwrap_or("").is_empty());
        assert!(!object_acl_denies_read(&h, "test:tester2", "AUTH_test"));
    }

    #[test]
    fn apply_bucket_acl_put_default_private_denies_alt() {
        let mut h = HeaderKeyDict::new();
        apply_bucket_acl_put(&mut h, &AclPutInput::None, "test:tester", true);
        assert!(bucket_acl_denies_read(&h, "test:tester2", "AUTH_test"));
        assert!(!bucket_acl_denies_read(&h, "test:tester", "AUTH_test"));
        assert!(bucket_acl_denies_write(&h, "test:tester2", "AUTH_test"));
    }
}
