// Copyright (c) 2026 OpenStack Foundation
//! Multi-tenant IAM-style identity + policy engine for S3 ACL / authorize.
//!
//! OpenStack Swift does not run AWS IAM. This module provides a **local
//! multi-tenant IAM product surface** used by ACP grant evaluation and
//! optional request authorize hooks:
//!
//! * **Identity directory** — access_key / email → canonical user id
//! * **Tenants** — isolated namespaces of principals + policies
//! * **Policy documents** — Allow/Deny statements with Action/Resource/Principal
//! * **Evaluation** — explicit Deny wins; else any Allow; else default deny
//!   when a policy is attached (missing policy → no extra deny)
//!
//! Configure via conf under `[filter:s3api]`:
//! * `iam_email_map = a@b.com:user1,...`
//! * `iam_access_key_map = AKIA:alice,...`
//! * `iam_policy_json = {...}` or path via `iam_policy_file`
//! * `iam_tenants = tenantA:alice,bob;tenantB:carol`

use std::collections::HashMap;

/// Local IAM identity directory for grant matching.
#[derive(Debug, Clone, Default)]
pub struct IdentityDirectory {
    /// access_key → canonical id (if absent, access_key is the id).
    pub access_key_to_id: HashMap<String, String>,
    /// email → canonical id.
    pub email_to_id: HashMap<String, String>,
    /// Extra aliases that resolve to the same principal id.
    pub id_aliases: HashMap<String, String>,
}

impl IdentityDirectory {
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse `email:id,email2:id2` conf fragment.
    pub fn with_email_map_csv(mut self, csv: &str) -> Self {
        for part in csv.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if let Some((em, id)) = part.split_once(':') {
                let em = em.trim().to_ascii_lowercase();
                let id = id.trim().to_string();
                if !em.is_empty() && !id.is_empty() {
                    self.email_to_id.insert(em, id);
                }
            }
        }
        self
    }

    /// Parse `access_key:id,...`.
    pub fn with_access_key_map_csv(mut self, csv: &str) -> Self {
        for part in csv.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if let Some((ak, id)) = part.split_once(':') {
                let ak = ak.trim().to_string();
                let id = id.trim().to_string();
                if !ak.is_empty() && !id.is_empty() {
                    self.access_key_to_id.insert(ak, id);
                }
            }
        }
        self
    }

    pub fn canonical_id_for_access_key(&self, access_key: &str) -> String {
        self.access_key_to_id
            .get(access_key)
            .cloned()
            .unwrap_or_else(|| access_key.to_string())
    }

    pub fn resolve_email(&self, email: &str) -> Option<String> {
        self.email_to_id.get(&email.to_ascii_lowercase()).cloned()
    }

    /// Whether grantee id matches principal (access_key, account, or mapped ids).
    pub fn principal_matches_id(
        &self,
        grantee_id: &str,
        access_key: &str,
        account: &str,
    ) -> bool {
        if grantee_id.is_empty() {
            return false;
        }
        let canon = self.canonical_id_for_access_key(access_key);
        if grantee_id == access_key || grantee_id == canon {
            return true;
        }
        if !account.is_empty()
            && (grantee_id == account || grantee_id == account.trim_start_matches("AUTH_"))
        {
            return true;
        }
        if let Some(alias) = self.id_aliases.get(grantee_id) {
            if alias == access_key || alias == &canon || alias == account {
                return true;
            }
        }
        false
    }
}

/// Effect of a policy statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    Allow,
    Deny,
}

/// One IAM-style statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyStatement {
    pub sid: String,
    pub effect: Effect,
    /// Actions like `s3:GetObject`, `s3:PutObject`, `s3:*`.
    pub actions: Vec<String>,
    /// Resources like `arn:aws:s3:::bucket/*`, `arn:aws:s3:::bucket/key`.
    pub resources: Vec<String>,
    /// Principals: `*` or canonical ids / access keys.
    pub principals: Vec<String>,
}

/// Named policy document (version + statements).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicyDocument {
    pub version: String,
    pub statements: Vec<PolicyStatement>,
}

/// Multi-tenant IAM store: tenants → principals; optional policies by ARN/name.
#[derive(Debug, Clone, Default)]
pub struct IamService {
    pub identity: IdentityDirectory,
    /// tenant_id → set of principal ids belonging to the tenant.
    pub tenants: HashMap<String, Vec<String>>,
    /// principal id → list of attached policy names.
    pub principal_policies: HashMap<String, Vec<String>>,
    /// policy name → document.
    pub policies: HashMap<String, PolicyDocument>,
    /// When true, missing Allow is deny for evaluated actions (strict mode).
    pub default_deny: bool,
}

impl IamService {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_identity(mut self, identity: IdentityDirectory) -> Self {
        self.identity = identity;
        self
    }

    /// Parse `tenantA:alice,bob;tenantB:carol`.
    pub fn with_tenants_csv(mut self, csv: &str) -> Self {
        for tenant_part in csv.split(';') {
            let tenant_part = tenant_part.trim();
            if tenant_part.is_empty() {
                continue;
            }
            let Some((tid, members)) = tenant_part.split_once(':') else {
                continue;
            };
            let tid = tid.trim().to_string();
            let list: Vec<String> = members
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if !tid.is_empty() && !list.is_empty() {
                self.tenants.insert(tid, list);
            }
        }
        self
    }

    pub fn attach_policy(&mut self, principal: &str, policy_name: &str, doc: PolicyDocument) {
        self.policies.insert(policy_name.to_string(), doc);
        self.principal_policies
            .entry(principal.to_string())
            .or_default()
            .push(policy_name.to_string());
    }

    /// Tenant that owns principal, if any.
    pub fn tenant_of(&self, principal: &str) -> Option<&str> {
        for (tid, members) in &self.tenants {
            if members.iter().any(|m| m == principal) {
                return Some(tid.as_str());
            }
        }
        None
    }

    /// Cross-tenant isolation: principals in different tenants never match
    /// unless policy explicitly allows `*` principal on that resource.
    pub fn same_tenant(&self, a: &str, b: &str) -> bool {
        match (self.tenant_of(a), self.tenant_of(b)) {
            (Some(ta), Some(tb)) => ta == tb,
            (None, None) => true,
            _ => false,
        }
    }

    /// Evaluate whether `principal` may perform `action` on `resource`.
    ///
    /// Returns `Some(true)` allow, `Some(false)` deny, `None` when no policy
    /// applies (caller falls through to ACL / Swift auth).
    pub fn evaluate(&self, principal: &str, action: &str, resource: &str) -> Option<bool> {
        let mut saw_policy = false;
        let mut allowed = false;
        let names = self
            .principal_policies
            .get(principal)
            .cloned()
            .unwrap_or_default();
        // Also evaluate policies attached to `*` or tenant-wide if any.
        let mut all_names = names;
        if let Some(extra) = self.principal_policies.get("*") {
            for n in extra {
                if !all_names.contains(n) {
                    all_names.push(n.clone());
                }
            }
        }
        for name in &all_names {
            let Some(doc) = self.policies.get(name) else {
                continue;
            };
            saw_policy = true;
            for stmt in &doc.statements {
                if !principal_matches_stmt(principal, &stmt.principals) {
                    continue;
                }
                if !action_matches(action, &stmt.actions) {
                    continue;
                }
                if !resource_matches(resource, &stmt.resources) {
                    continue;
                }
                match stmt.effect {
                    Effect::Deny => return Some(false),
                    Effect::Allow => allowed = true,
                }
            }
        }
        if !saw_policy {
            return None;
        }
        if allowed {
            Some(true)
        } else if self.default_deny {
            Some(false)
        } else {
            // Policy present but no match → deny in AWS; we match AWS default.
            Some(false)
        }
    }

    /// Convenience: S3 action from HTTP method + object presence.
    pub fn s3_action(method: &str, has_key: bool) -> &'static str {
        match (method.to_ascii_uppercase().as_str(), has_key) {
            ("GET", true) | ("HEAD", true) => "s3:GetObject",
            ("PUT", true) | ("POST", true) => "s3:PutObject",
            ("DELETE", true) => "s3:DeleteObject",
            ("GET", false) | ("HEAD", false) => "s3:ListBucket",
            ("PUT", false) => "s3:CreateBucket",
            ("DELETE", false) => "s3:DeleteBucket",
            _ => "s3:*",
        }
    }

    pub fn s3_resource(bucket: &str, key: Option<&str>) -> String {
        match key {
            Some(k) if !k.is_empty() => format!("arn:aws:s3:::{bucket}/{k}"),
            _ => format!("arn:aws:s3:::{bucket}"),
        }
    }

    /// Parse a minimal JSON policy document (subset of AWS IAM).
    ///
    /// ```json
    /// {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*","Principal":"*"}]}
    /// ```
    pub fn parse_policy_json(json: &str) -> Option<PolicyDocument> {
        let v: serde_json::Value = serde_json::from_str(json).ok()?;
        let version = v
            .get("Version")
            .and_then(|x| x.as_str())
            .unwrap_or("2012-10-17")
            .to_string();
        let stmts = v.get("Statement")?;
        let arr = if stmts.is_array() {
            stmts.as_array()?.clone()
        } else {
            vec![stmts.clone()]
        };
        let mut statements = Vec::new();
        for s in arr {
            let effect = match s.get("Effect").and_then(|e| e.as_str()).unwrap_or("") {
                "Allow" | "allow" => Effect::Allow,
                "Deny" | "deny" => Effect::Deny,
                _ => continue,
            };
            let actions = json_string_list(s.get("Action"));
            let resources = json_string_list(s.get("Resource"));
            let principals = json_principal_list(s.get("Principal"));
            let sid = s
                .get("Sid")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            if actions.is_empty() || resources.is_empty() {
                continue;
            }
            statements.push(PolicyStatement {
                sid,
                effect,
                actions,
                resources,
                principals,
            });
        }
        Some(PolicyDocument {
            version,
            statements,
        })
    }
}

fn json_string_list(v: Option<&serde_json::Value>) -> Vec<String> {
    match v {
        Some(serde_json::Value::String(s)) => vec![s.clone()],
        Some(serde_json::Value::Array(a)) => a
            .iter()
            .filter_map(|x| x.as_str().map(|s| s.to_string()))
            .collect(),
        _ => Vec::new(),
    }
}

fn json_principal_list(v: Option<&serde_json::Value>) -> Vec<String> {
    match v {
        None => vec!["*".into()],
        Some(serde_json::Value::String(s)) => vec![s.clone()],
        Some(serde_json::Value::Array(a)) => a
            .iter()
            .filter_map(|x| x.as_str().map(|s| s.to_string()))
            .collect(),
        Some(serde_json::Value::Object(map)) => {
            // {"AWS":"*"} or {"AWS":["id1","id2"]}
            if let Some(aws) = map.get("AWS") {
                return json_string_list(Some(aws));
            }
            vec!["*".into()]
        }
        _ => vec!["*".into()],
    }
}

fn principal_matches_stmt(principal: &str, principals: &[String]) -> bool {
    if principals.is_empty() {
        return true;
    }
    principals
        .iter()
        .any(|p| p == "*" || p == principal || p.ends_with(&format!("/{principal}")))
}

fn action_matches(action: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|p| wildcard_match(p, action))
}

fn resource_matches(resource: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|p| wildcard_match(p, resource))
}

/// Simple `*` wildcard match (not full IAM regex).
fn wildcard_match(pattern: &str, value: &str) -> bool {
    if pattern == "*" || pattern == value {
        return true;
    }
    if let Some(idx) = pattern.find('*') {
        let (pre, rest) = pattern.split_at(idx);
        let post = &rest[1..];
        if !value.starts_with(pre) {
            return false;
        }
        if post.is_empty() {
            return true;
        }
        // Single * only for product surface.
        if post.contains('*') {
            let after_pre = &value[pre.len()..];
            return after_pre.ends_with(post.trim_start_matches('*'))
                || wildcard_match(post, after_pre);
        }
        return value[pre.len()..].ends_with(post) || value[pre.len()..].contains(post) && {
            // prefix*suffix
            value.starts_with(pre) && value.ends_with(post)
        };
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_map_and_access_key() {
        let d = IdentityDirectory::new()
            .with_email_map_csv("a@x.com:alice,b@y.com:bob")
            .with_access_key_map_csv("AKIA:alice");
        assert_eq!(d.resolve_email("A@X.COM").as_deref(), Some("alice"));
        assert_eq!(d.canonical_id_for_access_key("AKIA"), "alice");
        assert!(d.principal_matches_id("alice", "AKIA", "AUTH_test"));
        assert!(!d.principal_matches_id("bob", "AKIA", "AUTH_test"));
    }

    #[test]
    fn multi_tenant_isolation() {
        let iam = IamService::new().with_tenants_csv("t1:alice,bob;t2:carol");
        assert_eq!(iam.tenant_of("alice"), Some("t1"));
        assert!(iam.same_tenant("alice", "bob"));
        assert!(!iam.same_tenant("alice", "carol"));
    }

    #[test]
    fn policy_allow_get_deny_delete() {
        let mut iam = IamService::new();
        let doc = IamService::parse_policy_json(
            r#"{
              "Version":"2012-10-17",
              "Statement":[
                {"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*","Principal":"alice"},
                {"Effect":"Deny","Action":"s3:DeleteObject","Resource":"arn:aws:s3:::b/*","Principal":"*"}
              ]
            }"#,
        )
        .unwrap();
        iam.attach_policy("alice", "p1", doc);
        assert_eq!(
            iam.evaluate("alice", "s3:GetObject", "arn:aws:s3:::b/x"),
            Some(true)
        );
        assert_eq!(
            iam.evaluate("alice", "s3:DeleteObject", "arn:aws:s3:::b/x"),
            Some(false)
        );
        assert_eq!(
            iam.evaluate("alice", "s3:PutObject", "arn:aws:s3:::b/x"),
            Some(false)
        );
    }

    #[test]
    fn no_policy_returns_none() {
        let iam = IamService::new();
        assert_eq!(
            iam.evaluate("alice", "s3:GetObject", "arn:aws:s3:::b/x"),
            None
        );
    }

    #[test]
    fn s3_action_resource_helpers() {
        assert_eq!(IamService::s3_action("GET", true), "s3:GetObject");
        assert_eq!(
            IamService::s3_resource("buck", Some("k")),
            "arn:aws:s3:::buck/k"
        );
    }
}
