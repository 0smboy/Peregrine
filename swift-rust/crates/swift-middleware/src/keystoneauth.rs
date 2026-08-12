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

//! The keystoneauth authorization decision + middleware, ported from
//! `swift/common/middleware/keystoneauth.py`.
//!
//! Token *validation* lives in [`crate::authtoken`]. This module:
//! 1. reads Confirmed identity headers stamped by authtoken
//! 2. stamps unspoofable `X-Backend-Keystone-*` / `X-Backend-Auth-Plugin`
//! 3. exposes [`authorize`] for the proxy to enforce roles + ACLs
//!
//! Deferred: container-sync `swift_sync_key` fast-path; project-domain-id
//! sysmeta persistence on account create (name-ACL allow_names still works
//! via the request flag).

use std::collections::HashMap;

use swift_http::{Request, Response};

use crate::acl::{parse_acl_v1, referrer_allowed};
use crate::{Middleware, NextFn};

/// Backend header the proxy uses to dispatch Keystone vs TempAuth authorize.
pub const AUTH_PLUGIN_HEADER: &str = "X-Backend-Auth-Plugin";
pub const AUTH_PLUGIN_KEYSTONE: &str = "keystone";

/// The caller's confirmed identity (roles already lowercased).
#[derive(Debug, Clone, Default)]
pub struct Identity {
    pub user_id: String,
    pub user_name: String,
    pub tenant_id: String,
    pub tenant_name: String,
    pub roles: Vec<String>,
    pub service_roles: Vec<String>,
}

/// The role configuration for the account being accessed (already lowercased).
#[derive(Debug, Clone, Default)]
pub struct RoleConfig {
    pub reseller_admin_role: String,
    pub system_reader_roles: Vec<String>,
    pub operator_roles: Vec<String>,
    pub service_roles: Vec<String>,
    pub project_reader_roles: Vec<String>,
}

/// The request being authorized.
#[derive(Debug, Clone)]
pub struct AuthRequest {
    pub method: String,
    pub container: Option<String>,
    pub obj: Option<String>,
    pub referrer: Option<String>,
    /// The container read/write ACL string (`req.acl`), if any.
    pub acl: Option<String>,
    /// Whether the account being accessed maps to the caller's tenant.
    pub account_matches_tenant: bool,
    /// Whether cross-tenant ACLs may match tenant/user *names* (not just ids).
    pub allow_names: bool,
}

/// The authorization outcome.
#[derive(Debug, Clone, PartialEq)]
pub enum AuthResult {
    /// Access granted; `swift_owner` gets privileged operations (ACL edits,
    /// account delete).
    Allow { swift_owner: bool },
    /// Access denied (the middleware maps this to 401/403).
    Deny,
}

/// `_authorize_cross_tenant`: match `tenant:user` (id, name, or `*`) against
/// the ACL groups, in the same nested order Python uses. Returns the matched
/// `"tenant:user"` string, or `None`.
pub fn cross_tenant_match(id: &Identity, groups: &[String], allow_names: bool) -> Option<String> {
    let mut tenant_match = vec![id.tenant_id.as_str(), "*"];
    let mut user_match = vec![id.user_id.as_str(), "*"];
    if allow_names {
        tenant_match.push(id.tenant_name.as_str());
        user_match.push(id.user_name.as_str());
    }
    for tenant in &tenant_match {
        for user in &user_match {
            let s = format!("{tenant}:{user}");
            if groups.iter().any(|g| g == &s) {
                return Some(s);
            }
        }
    }
    None
}

fn intersects(a: &[String], b: &[String]) -> bool {
    a.iter().any(|x| b.contains(x))
}

fn is_read(method: &str) -> bool {
    method == "GET" || method == "HEAD"
}

/// The keystoneauth `authorize` decision.
pub fn authorize(id: &Identity, cfg: &RoleConfig, req: &AuthRequest) -> AuthResult {
    // OPTIONS proceeds as normal.
    if req.method == "OPTIONS" {
        return AuthResult::Allow { swift_owner: false };
    }

    let (referrers, groups) = req
        .acl
        .as_deref()
        .map(parse_acl_v1)
        .unwrap_or_else(|| (Vec::new(), Vec::new()));

    // Reseller admin: unconditional owner.
    if !cfg.reseller_admin_role.is_empty() && id.roles.contains(&cfg.reseller_admin_role) {
        return AuthResult::Allow { swift_owner: true };
    }

    // System reader: read-only pass (no swift_owner).
    if intersects(&cfg.system_reader_roles, &id.roles) && is_read(&req.method) {
        return AuthResult::Allow { swift_owner: false };
    }

    // A user may not DELETE its own account.
    if req.container.is_none() && req.obj.is_none() && req.method == "DELETE" {
        return AuthResult::Deny;
    }

    // Cross-tenant ACL grant.
    if !groups.is_empty() && cross_tenant_match(id, &groups, req.allow_names).is_some() {
        return AuthResult::Allow { swift_owner: false };
    }

    // Unconfirmed-identity referrer ACL.
    if referrer_allowed(req.referrer.as_deref(), &referrers)
        && (req.obj.is_some() || groups.iter().any(|g| g == ".rlistings"))
    {
        return AuthResult::Allow { swift_owner: false };
    }

    // The account must belong to the caller's tenant for the role checks.
    if !req.account_matches_tenant {
        return AuthResult::Deny;
    }

    // Operator / service role table.
    let have_operator = intersects(&cfg.operator_roles, &id.roles);
    let have_service = intersects(&cfg.service_roles, &id.service_roles);
    let operator_ok = if !cfg.service_roles.is_empty() {
        have_operator && have_service
    } else {
        have_operator
    };
    if operator_ok {
        return AuthResult::Allow { swift_owner: true };
    }

    // Project reader: read-only, no swift_owner.
    if intersects(&cfg.project_reader_roles, &id.roles) && is_read(&req.method) {
        return AuthResult::Allow { swift_owner: false };
    }

    // Role name listed directly in the container ACL (Python authorize end).
    if id.roles.iter().any(|r| groups.iter().any(|g| g == r)) {
        return AuthResult::Allow { swift_owner: false };
    }

    AuthResult::Deny
}

/// Per-reseller-prefix role table (`AUTH_operator_roles`, …).
#[derive(Debug, Clone, Default)]
pub struct AccountRules {
    pub operator_roles: Vec<String>,
    pub service_roles: Vec<String>,
    pub project_reader_roles: Vec<String>,
}

/// Configured keystoneauth filter (Clone so proxy + pipeline share it).
#[derive(Debug, Clone)]
pub struct KeystoneAuth {
    pub reseller_prefixes: Vec<String>,
    pub account_rules: HashMap<String, AccountRules>,
    pub reseller_admin_role: String,
    pub system_reader_roles: Vec<String>,
    pub allow_overrides: bool,
    pub allow_names_in_acls: bool,
    pub default_domain_id: String,
}

impl Default for KeystoneAuth {
    fn default() -> Self {
        let mut account_rules = HashMap::new();
        account_rules.insert(
            "AUTH_".into(),
            AccountRules {
                operator_roles: vec!["admin".into(), "swiftoperator".into()],
                service_roles: vec![],
                project_reader_roles: vec![],
            },
        );
        Self {
            reseller_prefixes: vec!["AUTH_".into()],
            account_rules,
            reseller_admin_role: "reselleradmin".into(),
            system_reader_roles: vec![],
            allow_overrides: true,
            allow_names_in_acls: true,
            default_domain_id: "default".into(),
        }
    }
}

impl KeystoneAuth {
    /// Build from `[filter:keystoneauth]` items (key → value).
    pub fn from_items(items: &[(String, String)]) -> Self {
        let mut map: HashMap<String, String> = HashMap::new();
        for (k, v) in items {
            map.insert(k.to_ascii_lowercase(), v.clone());
        }
        let get = |k: &str, default: &str| -> String {
            map.get(k).cloned().unwrap_or_else(|| default.to_string())
        };
        let true_val = |k: &str, default: bool| -> bool {
            map.get(k)
                .map(|v| {
                    matches!(
                        v.to_ascii_lowercase().as_str(),
                        "true" | "1" | "yes" | "on" | "t" | "y"
                    )
                })
                .unwrap_or(default)
        };
        let list = |s: &str| -> Vec<String> {
            s.split(',')
                .map(|p| p.trim().to_ascii_lowercase())
                .filter(|p| !p.is_empty())
                .collect()
        };

        let raw_prefixes = get("reseller_prefix", "AUTH");
        let mut reseller_prefixes: Vec<String> = raw_prefixes
            .split(',')
            .map(|p| {
                let p = p.trim();
                if p.is_empty() {
                    String::new()
                } else if p.ends_with('_') {
                    p.to_string()
                } else {
                    format!("{p}_")
                }
            })
            .collect();
        if reseller_prefixes.is_empty() {
            reseller_prefixes.push("AUTH_".into());
        }

        let default_ops = list(&get("operator_roles", "admin,swiftoperator"));
        let default_svc = list(&get("service_roles", ""));
        let default_reader = list(&get("project_reader_roles", ""));

        let mut account_rules = HashMap::new();
        for prefix in &reseller_prefixes {
            let stem = prefix.trim_end_matches('_');
            let ops = map
                .get(&format!("{}_operator_roles", stem.to_ascii_lowercase()))
                .map(|s| list(s))
                .unwrap_or_else(|| default_ops.clone());
            let svc = map
                .get(&format!("{}_service_roles", stem.to_ascii_lowercase()))
                .map(|s| list(s))
                .unwrap_or_else(|| default_svc.clone());
            let reader = map
                .get(&format!(
                    "{}_project_reader_roles",
                    stem.to_ascii_lowercase()
                ))
                .map(|s| list(s))
                .unwrap_or_else(|| default_reader.clone());
            account_rules.insert(
                prefix.clone(),
                AccountRules {
                    operator_roles: ops,
                    service_roles: svc,
                    project_reader_roles: reader,
                },
            );
        }

        Self {
            reseller_prefixes,
            account_rules,
            reseller_admin_role: get("reseller_admin_role", "ResellerAdmin").to_ascii_lowercase(),
            system_reader_roles: list(&get("system_reader_roles", "")),
            allow_overrides: true_val("allow_overrides", true),
            allow_names_in_acls: true_val("allow_names_in_acls", true),
            default_domain_id: get("default_domain_id", "default"),
        }
    }

    pub fn role_config_for_account(&self, account: &str) -> RoleConfig {
        let prefix = self
            .account_prefix(account)
            .unwrap_or_else(|| self.reseller_prefixes.first().cloned().unwrap_or_default());
        let rules = self.account_rules.get(&prefix).cloned().unwrap_or_default();
        RoleConfig {
            reseller_admin_role: self.reseller_admin_role.clone(),
            system_reader_roles: self.system_reader_roles.clone(),
            operator_roles: rules.operator_roles,
            service_roles: rules.service_roles,
            project_reader_roles: rules.project_reader_roles,
        }
    }

    pub fn account_prefix(&self, account: &str) -> Option<String> {
        for prefix in self.reseller_prefixes.iter().filter(|p| !p.is_empty()) {
            if account.starts_with(prefix.as_str()) {
                return Some(prefix.clone());
            }
        }
        if self.reseller_prefixes.iter().any(|p| p.is_empty()) {
            return Some(String::new());
        }
        None
    }

    pub fn account_matches_tenant(&self, account: &str, tenant_id: &str) -> bool {
        self.reseller_prefixes
            .iter()
            .any(|p| format!("{p}{tenant_id}") == account)
    }

    pub fn is_our_account(&self, account: &str) -> bool {
        self.account_prefix(account).is_some()
    }

    /// Read Confirmed identity from authtoken headers (or backend stamps).
    ///
    /// Client-facing `X-Identity-Status` is trusted only when authtoken has
    /// stamped `X-Backend-Authtoken-Status: Confirmed` (gatekeeper strips
    /// inbound `X-Backend-*`, so clients cannot forge the marker).
    pub fn identity_from_request(req: &Request) -> Option<Identity> {
        if let Some(id) = Self::identity_from_backend(req) {
            return Some(id);
        }
        let authtoken_ok = req
            .headers
            .get("X-Backend-Authtoken-Status")
            .map(|v| v.eq_ignore_ascii_case("Confirmed"))
            .unwrap_or(false);
        if !authtoken_ok {
            return None;
        }
        let status = req.headers.get("X-Identity-Status")?;
        if !status.eq_ignore_ascii_case("Confirmed") {
            return None;
        }
        let svc_status = req.headers.get("X-Service-Identity-Status");
        if let Some(s) = svc_status {
            if !s.eq_ignore_ascii_case("Confirmed") {
                return None;
            }
        }
        let split = |k: &str| -> Vec<String> {
            req.headers
                .get(k)
                .unwrap_or("")
                .split(',')
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect()
        };
        Some(Identity {
            user_id: req.headers.get("X-User-Id").unwrap_or("").to_string(),
            user_name: req.headers.get("X-User-Name").unwrap_or("").to_string(),
            tenant_id: req
                .headers
                .get("X-Project-Id")
                .or_else(|| req.headers.get("X-Tenant-Id"))
                .unwrap_or("")
                .to_string(),
            tenant_name: req
                .headers
                .get("X-Project-Name")
                .or_else(|| req.headers.get("X-Tenant-Name"))
                .unwrap_or("")
                .to_string(),
            roles: split("X-Roles"),
            service_roles: split("X-Service-Roles"),
        })
    }

    fn identity_from_backend(req: &Request) -> Option<Identity> {
        let tenant = req.headers.get("X-Backend-Keystone-Project-Id")?;
        if tenant.is_empty() {
            return None;
        }
        let split = |k: &str| -> Vec<String> {
            req.headers
                .get(k)
                .unwrap_or("")
                .split(',')
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect()
        };
        Some(Identity {
            user_id: req
                .headers
                .get("X-Backend-Keystone-User-Id")
                .unwrap_or("")
                .to_string(),
            user_name: req
                .headers
                .get("X-Backend-Keystone-User-Name")
                .unwrap_or("")
                .to_string(),
            tenant_id: tenant.to_string(),
            tenant_name: req
                .headers
                .get("X-Backend-Keystone-Project-Name")
                .unwrap_or("")
                .to_string(),
            roles: split("X-Backend-Keystone-Roles"),
            service_roles: split("X-Backend-Keystone-Service-Roles"),
        })
    }

    fn stamp_backend(req: &mut Request, id: Option<&Identity>, reseller: bool) {
        req.headers.set(AUTH_PLUGIN_HEADER, AUTH_PLUGIN_KEYSTONE);
        // Clear prior stamps.
        for k in [
            "X-Backend-Keystone-User-Id",
            "X-Backend-Keystone-User-Name",
            "X-Backend-Keystone-Project-Id",
            "X-Backend-Keystone-Project-Name",
            "X-Backend-Keystone-Roles",
            "X-Backend-Keystone-Service-Roles",
            "X-Backend-Reseller-Request",
        ] {
            req.headers.remove(k);
        }
        if let Some(id) = id {
            req.headers.set("X-Backend-Keystone-User-Id", &id.user_id);
            req.headers
                .set("X-Backend-Keystone-User-Name", &id.user_name);
            req.headers
                .set("X-Backend-Keystone-Project-Id", &id.tenant_id);
            req.headers
                .set("X-Backend-Keystone-Project-Name", &id.tenant_name);
            req.headers
                .set("X-Backend-Keystone-Roles", id.roles.join(","));
            if !id.service_roles.is_empty() {
                req.headers.set(
                    "X-Backend-Keystone-Service-Roles",
                    id.service_roles.join(","),
                );
            }
            // TempAuth-compatible Remote-User stamp (tenant id) for logging.
            req.headers
                .set("X-Backend-Remote-User", id.tenant_id.as_str());
        }
        if reseller {
            req.headers.set("X-Backend-Reseller-Request", "true");
        }
    }

    pub fn denied_response(has_identity: bool) -> Response {
        let status = if has_identity { 403 } else { 401 };
        let mut resp = Response::with_body(
            status,
            if status == 401 {
                "Unauthorized\n"
            } else {
                "Forbidden\n"
            },
        );
        resp.headers
            .set("Content-Type", "text/plain; charset=UTF-8");
        resp
    }

    /// Proxy-side authorize. `None` = allow; `Some(resp)` = deny.
    pub fn authorize_request(
        &self,
        req: &Request,
        account: &str,
        container: Option<&str>,
        object: Option<&str>,
        acl: Option<&str>,
        referrer: Option<&str>,
    ) -> (Option<Response>, bool /* swift_owner */) {
        let identity = Self::identity_from_request(req);
        if identity.is_none() {
            // Anonymous: only our reseller accounts; referrer ACL.
            if req.method == "OPTIONS" {
                return (None, false);
            }
            if !self.is_our_account(account) {
                return (Some(Self::denied_response(false)), false);
            }
            let (referrers, groups) = acl.map(parse_acl_v1).unwrap_or_default();
            let ok = referrer_allowed(referrer, &referrers)
                && (object.is_some() || groups.iter().any(|g| g == ".rlistings"));
            return if ok {
                (None, false)
            } else {
                (Some(Self::denied_response(false)), false)
            };
        }
        let id = identity.unwrap();
        let cfg = self.role_config_for_account(account);
        let auth_req = AuthRequest {
            method: req.method.clone(),
            container: container.map(|s| s.to_string()),
            obj: object.map(|s| s.to_string()),
            referrer: referrer.map(|s| s.to_string()),
            acl: acl.map(|s| s.to_string()),
            account_matches_tenant: self.account_matches_tenant(account, &id.tenant_id),
            allow_names: self.allow_names_in_acls,
        };
        match authorize(&id, &cfg, &auth_req) {
            AuthResult::Allow { swift_owner } => (None, swift_owner),
            AuthResult::Deny => (Some(Self::denied_response(true)), false),
        }
    }
}

impl Middleware for KeystoneAuth {
    fn handle(&self, mut req: Request, next: &NextFn) -> Response {
        if self.allow_overrides
            && req
                .headers
                .get("X-Backend-Authorize-Override")
                .map(|v| matches!(v.to_ascii_lowercase().as_str(), "true" | "1" | "yes" | "on"))
                .unwrap_or(false)
        {
            return next(req);
        }

        let identity = Self::identity_from_request(&req);
        // Only stamp Auth-Plugin=keystone when Keystone identity is confirmed.
        // Claiming every reseller-prefix account (AUTH_*) without identity steals
        // authorize from TempAuth in keystone_coexist pipelines (TempAuth list → 401).
        // Anonymous / TempAuth-authenticated AUTH_* traffic must fall through so
        // the proxy can use TempAuth ACLs (or deny as anonymous).
        if let Some(ref id) = identity {
            let reseller = !self.reseller_admin_role.is_empty()
                && id.roles.contains(&self.reseller_admin_role);
            Self::stamp_backend(&mut req, Some(id), reseller);
        }

        next(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(roles: &[&str]) -> Identity {
        Identity {
            user_id: "u1".into(),
            user_name: "alice".into(),
            tenant_id: "t1".into(),
            tenant_name: "proj".into(),
            roles: roles.iter().map(|s| s.to_string()).collect(),
            service_roles: vec![],
        }
    }
    fn cfg() -> RoleConfig {
        RoleConfig {
            reseller_admin_role: "reselleradmin".into(),
            system_reader_roles: vec!["sysreader".into()],
            operator_roles: vec!["admin".into(), "swiftoperator".into()],
            service_roles: vec![],
            project_reader_roles: vec!["projreader".into()],
        }
    }
    fn objreq(method: &str) -> AuthRequest {
        AuthRequest {
            method: method.into(),
            container: Some("c".into()),
            obj: Some("o".into()),
            referrer: None,
            acl: None,
            account_matches_tenant: true,
            allow_names: true,
        }
    }

    #[test]
    fn test_reseller_admin_is_owner() {
        assert_eq!(
            authorize(&id(&["reselleradmin"]), &cfg(), &objreq("PUT")),
            AuthResult::Allow { swift_owner: true }
        );
    }

    #[test]
    fn test_operator_is_owner() {
        assert_eq!(
            authorize(&id(&["admin"]), &cfg(), &objreq("PUT")),
            AuthResult::Allow { swift_owner: true }
        );
    }

    #[test]
    fn test_system_reader_read_only() {
        assert_eq!(
            authorize(&id(&["sysreader"]), &cfg(), &objreq("GET")),
            AuthResult::Allow { swift_owner: false }
        );
        // a write falls through to deny (no operator role, tenant matches but
        // no operator role) -> Deny
        assert_eq!(
            authorize(&id(&["sysreader"]), &cfg(), &objreq("PUT")),
            AuthResult::Deny
        );
    }

    #[test]
    fn test_project_reader_read_only() {
        assert_eq!(
            authorize(&id(&["projreader"]), &cfg(), &objreq("HEAD")),
            AuthResult::Allow { swift_owner: false }
        );
        assert_eq!(
            authorize(&id(&["projreader"]), &cfg(), &objreq("PUT")),
            AuthResult::Deny
        );
    }

    #[test]
    fn test_no_role_denied() {
        assert_eq!(
            authorize(&id(&["member"]), &cfg(), &objreq("GET")),
            AuthResult::Deny
        );
    }

    #[test]
    fn test_self_account_delete_denied() {
        let mut req = objreq("DELETE");
        req.container = None;
        req.obj = None;
        assert_eq!(authorize(&id(&["member"]), &cfg(), &req), AuthResult::Deny);
    }

    #[test]
    fn test_options_allowed() {
        assert_eq!(
            authorize(&id(&[]), &cfg(), &objreq("OPTIONS")),
            AuthResult::Allow { swift_owner: false }
        );
    }

    #[test]
    fn test_cross_tenant_acl_grant() {
        let mut req = objreq("GET");
        req.account_matches_tenant = false; // different account
        req.acl = Some("t1:u1".into()); // tenant:user grant
        assert_eq!(
            authorize(&id(&["member"]), &cfg(), &req),
            AuthResult::Allow { swift_owner: false }
        );
        assert_eq!(
            cross_tenant_match(&id(&["member"]), &["t1:u1".to_string()], true),
            Some("t1:u1".to_string())
        );
        // name-based grant only when allow_names
        assert_eq!(
            cross_tenant_match(&id(&[]), &["proj:alice".to_string()], true),
            Some("proj:alice".to_string())
        );
        assert_eq!(
            cross_tenant_match(&id(&[]), &["proj:alice".to_string()], false),
            None
        );
    }

    #[test]
    fn test_referrer_acl_grant() {
        let mut req = objreq("GET");
        req.account_matches_tenant = false;
        req.referrer = Some("http://ok.example.com/".into());
        req.acl = Some(".r:.example.com".into());
        // obj is set, so referrer ACL grants
        assert_eq!(
            authorize(&id(&["member"]), &cfg(), &req),
            AuthResult::Allow { swift_owner: false }
        );
        // container listing without .rlistings is denied even if referrer ok
        req.obj = None;
        assert_eq!(authorize(&id(&["member"]), &cfg(), &req), AuthResult::Deny);
        // ...but .rlistings in the ACL allows the listing
        req.acl = Some(".r:.example.com,.rlistings".into());
        assert_eq!(
            authorize(&id(&["member"]), &cfg(), &req),
            AuthResult::Allow { swift_owner: false }
        );
    }

    #[test]
    fn test_operator_requires_service_role_when_configured() {
        let mut c = cfg();
        c.service_roles = vec!["svc".into()];
        // operator role but no service role -> deny
        assert_eq!(
            authorize(&id(&["admin"]), &c, &objreq("PUT")),
            AuthResult::Deny
        );
        // with the service role -> owner
        let mut who = id(&["admin"]);
        who.service_roles = vec!["svc".into()];
        assert_eq!(
            authorize(&who, &c, &objreq("PUT")),
            AuthResult::Allow { swift_owner: true }
        );
    }

    #[test]
    fn test_role_name_in_container_acl() {
        let mut req = objreq("GET");
        req.acl = Some("member".into());
        assert_eq!(
            authorize(&id(&["member"]), &cfg(), &req),
            AuthResult::Allow { swift_owner: false }
        );
    }

    #[test]
    fn test_from_items_and_middleware_stamp() {
        let ka = KeystoneAuth::from_items(&[
            ("operator_roles".into(), "admin".into()),
            ("reseller_prefix".into(), "AUTH".into()),
            ("reseller_admin_role".into(), "ResellerAdmin".into()),
        ]);
        assert!(ka.account_matches_tenant("AUTH_t1", "t1"));
        assert_eq!(
            ka.role_config_for_account("AUTH_t1").operator_roles,
            vec!["admin".to_string()]
        );

        let mut h = swift_http::HeaderKeyDict::new();
        h.set("X-Backend-Authtoken-Status", "Confirmed");
        h.set("X-Identity-Status", "Confirmed");
        h.set("X-User-Id", "u1");
        h.set("X-Project-Id", "t1");
        h.set("X-Roles", "admin,ResellerAdmin");
        let req = Request {
            method: "GET".into(),
            path: "/v1/AUTH_t1/c".into(),
            query_string: String::new(),
            headers: h,
            body: swift_http::Body::empty(),
        };
        let seen = std::sync::Arc::new(std::sync::Mutex::new(None::<String>));
        let s2 = seen.clone();
        let app: NextFn = std::sync::Arc::new(move |r| {
            *s2.lock().unwrap() = r.headers.get(AUTH_PLUGIN_HEADER).map(|s| s.to_string());
            assert_eq!(r.headers.get("X-Backend-Keystone-Project-Id"), Some("t1"));
            assert_eq!(r.headers.get("X-Backend-Reseller-Request"), Some("true"));
            Response::new(204)
        });
        assert_eq!(ka.handle(req, &app).status, 204);
        assert_eq!(seen.lock().unwrap().as_deref(), Some(AUTH_PLUGIN_KEYSTONE));
    }

    #[test]
    fn test_authorize_request_deny_cross_tenant() {
        let ka = KeystoneAuth::default();
        let mut h = swift_http::HeaderKeyDict::new();
        h.set("X-Backend-Auth-Plugin", "keystone");
        h.set("X-Backend-Keystone-Project-Id", "t1");
        h.set("X-Backend-Keystone-User-Id", "u1");
        h.set("X-Backend-Keystone-Roles", "member");
        let req = Request {
            method: "GET".into(),
            path: "/v1/AUTH_other/c/o".into(),
            query_string: String::new(),
            headers: h,
            body: swift_http::Body::empty(),
        };
        let (denied, _) =
            ka.authorize_request(&req, "AUTH_other", Some("c"), Some("o"), None, None);
        assert_eq!(denied.map(|r| r.status), Some(403));
    }

    #[test]
    fn test_anonymous_referrer_acl() {
        let ka = KeystoneAuth::default();
        let req = Request {
            method: "GET".into(),
            path: "/v1/AUTH_t1/c/o".into(),
            query_string: String::new(),
            headers: swift_http::HeaderKeyDict::new(),
            body: swift_http::Body::empty(),
        };
        let (denied, _) = ka.authorize_request(
            &req,
            "AUTH_t1",
            Some("c"),
            Some("o"),
            Some(".r:.example.com"),
            Some("http://ok.example.com/"),
        );
        assert!(denied.is_none());
        let (denied2, _) = ka.authorize_request(&req, "AUTH_t1", Some("c"), Some("o"), None, None);
        assert_eq!(denied2.map(|r| r.status), Some(401));
    }

    #[test]
    fn test_coexist_no_stamp_without_identity() {
        // TempAuth coexist: AUTH_* path with no Keystone identity must NOT
        // stamp Auth-Plugin=keystone (otherwise proxy authorize steals the
        // request and TempAuth list returns 401 Unauthorized).
        let ka = KeystoneAuth::default();
        let req = Request {
            method: "GET".into(),
            path: "/v1/AUTH_test".into(),
            query_string: String::new(),
            headers: swift_http::HeaderKeyDict::new(),
            body: swift_http::Body::empty(),
        };
        let seen = std::sync::Arc::new(std::sync::Mutex::new(None::<String>));
        let s2 = seen.clone();
        let app: NextFn = std::sync::Arc::new(move |r| {
            *s2.lock().unwrap() = r.headers.get(AUTH_PLUGIN_HEADER).map(|s| s.to_string());
            Response::new(204)
        });
        assert_eq!(ka.handle(req, &app).status, 204);
        assert_eq!(seen.lock().unwrap().as_deref(), None);
    }
}
