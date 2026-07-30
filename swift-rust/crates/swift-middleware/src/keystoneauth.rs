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

//! The keystoneauth authorization decision, ported from the `authorize`
//! method of `swift/common/middleware/keystoneauth.py`.
//!
//! Token *validation* (turning an `X-Auth-Token` into an identity) is
//! keystonemiddleware's job and needs a live Keystone; that plumbing is out of
//! scope here. What this module ports is the security-critical part that runs
//! once an identity is known: given the caller's roles, the account being
//! accessed, and the container ACL, decide allow/deny and whether the caller
//! is a `swift_owner`. Getting this wrong either leaks data or breaks access,
//! so the full decision tree — reseller-admin, system-reader, self-account
//! delete, cross-tenant ACL grants, referrer/`.rlistings` ACLs, tenant match,
//! and the operator/service-role table — is ported faithfully and unit-tested.
//!
//! Deferred: the container-sync `swift_sync_key` fast-path (needs the WSGI
//! env) and domain-scoped name matching (`allow_names` is an input here).

use crate::acl::{parse_acl_v1, referrer_allowed};

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
    if !groups.is_empty()
        && cross_tenant_match(id, &groups, req.allow_names).is_some()
    {
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

    AuthResult::Deny
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
        assert_eq!(authorize(&id(&["sysreader"]), &cfg(), &objreq("PUT")), AuthResult::Deny);
    }

    #[test]
    fn test_project_reader_read_only() {
        assert_eq!(
            authorize(&id(&["projreader"]), &cfg(), &objreq("HEAD")),
            AuthResult::Allow { swift_owner: false }
        );
        assert_eq!(authorize(&id(&["projreader"]), &cfg(), &objreq("PUT")), AuthResult::Deny);
    }

    #[test]
    fn test_no_role_denied() {
        assert_eq!(authorize(&id(&["member"]), &cfg(), &objreq("GET")), AuthResult::Deny);
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
        assert_eq!(cross_tenant_match(&id(&["member"]), &["t1:u1".to_string()], true), Some("t1:u1".to_string()));
        // name-based grant only when allow_names
        assert_eq!(cross_tenant_match(&id(&[]), &["proj:alice".to_string()], true), Some("proj:alice".to_string()));
        assert_eq!(cross_tenant_match(&id(&[]), &["proj:alice".to_string()], false), None);
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
        assert_eq!(authorize(&id(&["admin"]), &c, &objreq("PUT")), AuthResult::Deny);
        // with the service role -> owner
        let mut who = id(&["admin"]);
        who.service_roles = vec!["svc".into()];
        assert_eq!(
            authorize(&who, &c, &objreq("PUT")),
            AuthResult::Allow { swift_owner: true }
        );
    }
}
