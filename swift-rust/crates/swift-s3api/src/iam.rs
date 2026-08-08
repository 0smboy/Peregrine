// Copyright (c) 2026 OpenStack Foundation
//! Minimal IAM-style identity resolution for S3 ACL grantees.
//!
//! OpenStack Swift does not run AWS IAM. This module provides a **local
//! identity directory** used by ACP grant evaluation:
//!
//! * `access_key` → canonical user id (defaults to access_key itself)
//! * `email` → canonical user id (optional map)
//! * group URIs (`AllUsers`, `AuthenticatedUsers`) remain URI-matched
//!
//! Configure via S3Api fields or conf keys under `[filter:s3api]`:
//! `iam_email_map = a@b.com:user1,c@d.com:user2`

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
        if !account.is_empty() && (grantee_id == account || grantee_id == account.trim_start_matches("AUTH_")) {
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
}
