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

//! `keymaster`: root-secret holder + per-path key derivation for at-rest
//! encryption, ported from
//! `swift/common/middleware/crypto/keymaster.py`.
//!
//! Derivation is deterministic:
//! ```text
//! path_key = HMAC_SHA256(root_secret, path_utf8)
//! ```
//! with container path `/account/container` and object path
//! `/account/container/object` (meta version `"2"` — the Python default).
//!
//! Multi-root-secret rotation (Python `load_multikey_opts`):
//! * `encryption_root_secret` — default / unlabeled secret (`secret_id = None`)
//! * `encryption_root_secret_<id>` — named secrets for rotation
//! * `active_root_secret_id` — which secret new writes use (empty → default)
//!
//! Crypto-meta `key_id` may carry `secret_id` so decrypter can re-derive the
//! historic key when reading data encrypted under a retired root secret.
//!
//! Residuals (honest):
//! * **KMIP / KMS keymasters** — still deferred (external KMS; see
//!   `kmip_keymaster.py` / `kms_keymaster.py` in Python Swift)
//! * meta version `"1"` path derivation: leading-slash object bug + py3
//!   WSGI latin1 path rewrite for `"1"`/`"2"` (not trivial; we write/read
//!   `"2"`/`"3"` path form only — `meta_version_to_write` is still accepted)
//! * `keymaster_config_path` external file (use inline filter conf)
//! * Python `swift.callback.fetch_crypto_keys` environ hook — Encrypter /
//!   Decrypter hold an [`Arc`] to this keymaster and call
//!   [`KeyMaster::fetch_keys`] / [`KeyMaster::fetch_keys_with_key_id`] directly

use std::collections::HashMap;
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use swift_crypto::{container_key, object_key, KEY_LENGTH};
use swift_http::{split_path, Request, Response};

use crate::{Middleware, NextFn};

/// Per-path encryption keys for one request (Python
/// `KeyMasterContext.fetch_crypto_keys` return value, simplified).
#[derive(Debug, Clone)]
pub struct CryptoKeys {
    /// Object path key (`keys['object']`), when the request path includes an
    /// object segment.
    pub object: Option<[u8; KEY_LENGTH]>,
    /// Container path key (`keys['container']`), when the request path
    /// includes a container segment.
    pub container: Option<[u8; KEY_LENGTH]>,
    /// Opaque key-id dict persisted into crypto-meta (`keys['id']`).
    pub id: serde_json::Value,
    /// All key-id dicts for every loaded root secret (`keys['all_ids']`).
    pub all_ids: Vec<serde_json::Value>,
}

/// Root-secret keymaster. Shared by the keymaster filter and by
/// encrypter/decrypter via [`Arc`].
///
/// Secrets are keyed by optional id: `None` is the default unlabeled
/// `encryption_root_secret`; `Some(id)` is `encryption_root_secret_<id>`.
#[derive(Debug, Clone)]
pub struct KeyMaster {
    /// Decoded root secrets (≥ 32 bytes each). Key is secret id (`None` =
    /// default).
    root_secrets: HashMap<Option<String>, Vec<u8>>,
    /// Secret used for new encryption (`active_root_secret_id`; `None` =
    /// default unlabeled secret).
    active_secret_id: Option<String>,
    /// Meta version written into `key_id` (Python `meta_version_to_write`,
    /// default `"2"`).
    pub meta_version_to_write: String,
}

impl KeyMaster {
    /// Build from a raw root secret (already decoded). Secret must be at
    /// least [`KEY_LENGTH`] bytes. Registers it as the default (unlabeled)
    /// secret and sets it active.
    pub fn new(root_secret: Vec<u8>) -> Result<Self, String> {
        if root_secret.len() < KEY_LENGTH {
            return Err(format!(
                "encryption_root_secret must be a base64 encoding of at least {KEY_LENGTH} raw bytes"
            ));
        }
        let mut root_secrets = HashMap::new();
        root_secrets.insert(None, root_secret);
        Ok(KeyMaster {
            root_secrets,
            active_secret_id: None,
            meta_version_to_write: "2".into(),
        })
    }

    /// Decode a base64 root secret (Python `KeyMaster._decode_root_secret`:
    /// strict base64, allow line breaks/whitespace, ≥ 32 raw bytes).
    pub fn from_b64_root_secret(b64: &str) -> Result<Self, String> {
        let secret = Self::decode_root_secret(b64)?;
        Self::new(secret)
    }

    /// Decode one base64 root secret string.
    pub fn decode_root_secret(b64: &str) -> Result<Vec<u8>, String> {
        let cleaned: String = b64.chars().filter(|c| !c.is_whitespace()).collect();
        let secret = B64
            .decode(cleaned.as_bytes())
            .map_err(|e| format!("encryption_root_secret base64 decode failed: {e}"))?;
        if secret.len() < KEY_LENGTH {
            return Err(format!(
                "encryption_root_secret must be a base64 encoding of at least {KEY_LENGTH} raw bytes"
            ));
        }
        Ok(secret)
    }

    /// Build from filter conf items. Loads multi-key options matching Python
    /// `load_multikey_opts(conf, 'encryption_root_secret', allow_none_key=True)`:
    ///
    /// * `encryption_root_secret` → secret_id `None`
    /// * `encryption_root_secret_<id>` → secret_id `Some(id)`
    /// * `active_root_secret_id` → which secret new writes use
    /// * `meta_version_to_write` → `"1"` / `"2"` / `"3"`
    pub fn from_conf_items(items: &[(String, String)]) -> Result<Self, String> {
        let mut root_secrets: HashMap<Option<String>, Vec<u8>> = HashMap::new();
        let mut active: Option<String> = None;
        let mut meta_version = "2".to_string();

        const PREFIX: &str = "encryption_root_secret";
        for (k, v) in items {
            let kl = k.to_ascii_lowercase();
            if kl == "active_root_secret_id" {
                active = if v.is_empty() { None } else { Some(v.clone()) };
            } else if kl == "meta_version_to_write" && !v.is_empty() {
                meta_version = v.clone();
            } else if kl == PREFIX {
                root_secrets.insert(None, Self::decode_root_secret(v)?);
            } else if let Some(id) = kl.strip_prefix("encryption_root_secret_") {
                if id.is_empty() {
                    return Err(format!("Malformed multi-key option name {k}"));
                }
                // Preserve id casing from the original option name when the
                // key was lowercased only for matching (Python keeps case).
                let secret_id = if k.len() >= PREFIX.len() + 1 + id.len() {
                    k[k.len() - id.len()..].to_string()
                } else {
                    id.to_string()
                };
                root_secrets.insert(Some(secret_id), Self::decode_root_secret(v)?);
            } else if kl.starts_with(PREFIX) {
                // e.g. encryption_root_secretfoo without underscore
                return Err(format!("Malformed multi-key option name {k}"));
            }
            // other filter opts (use, keymaster_config_path residual) ignored
        }

        if root_secrets.is_empty() {
            return Err(
                "keymaster requires encryption_root_secret (base64 of ≥32 bytes)".to_string(),
            );
        }

        let active_key = active.clone();
        if !root_secrets.contains_key(&active_key) {
            return Err(format!(
                "No secret loaded for active_root_secret_id {}",
                active.as_deref().unwrap_or("<none>")
            ));
        }

        if !matches!(meta_version.as_str(), "1" | "2" | "3") {
            return Err(format!(
                "Unknown/unsupported metadata version: {meta_version:?}"
            ));
        }

        Ok(KeyMaster {
            root_secrets,
            active_secret_id: active,
            meta_version_to_write: meta_version,
        })
    }

    /// Active root secret id used for new encryption (`None` = default).
    pub fn active_secret_id(&self) -> Option<&str> {
        self.active_secret_id.as_deref()
    }

    /// Sorted secret ids (Python `root_secret_ids`; `None` sorts as `""`).
    pub fn root_secret_ids(&self) -> Vec<Option<String>> {
        let mut ids: Vec<Option<String>> = self.root_secrets.keys().cloned().collect();
        ids.sort_by(|a, b| a.as_deref().unwrap_or("").cmp(b.as_deref().unwrap_or("")));
        ids
    }

    /// Look up raw root secret bytes by id (`None` = default unlabeled).
    pub fn root_secret_for(&self, secret_id: Option<&str>) -> Result<&[u8], String> {
        let key = secret_id.map(|s| s.to_string());
        self.root_secrets
            .get(&key)
            .map(|s| s.as_slice())
            .ok_or_else(|| format!("Unrecognised secret id: {}", secret_id.unwrap_or("<none>")))
    }

    /// Derive keys for the given path parts using the **active** root secret
    /// (write path / Python `fetch_crypto_keys` without `key_id`).
    pub fn fetch_keys(
        &self,
        account: &str,
        container: Option<&str>,
        object: Option<&str>,
    ) -> CryptoKeys {
        self.fetch_keys_for_secret(account, container, object, self.active_secret_id.as_deref())
            .expect("active secret is validated at construction")
    }

    /// Derive keys using the secret referenced by crypto-meta `key_id`
    /// (Python `fetch_crypto_keys(key_id=...)`).
    ///
    /// * `key_id == None` → use active secret (same as [`fetch_keys`])
    /// * `key_id` present without `secret_id` → default unlabeled secret
    /// * `key_id.secret_id` set → that named secret
    pub fn fetch_keys_with_key_id(
        &self,
        account: &str,
        container: Option<&str>,
        object: Option<&str>,
        key_id: Option<&serde_json::Value>,
    ) -> Result<CryptoKeys, String> {
        let secret_id = match key_id {
            None => self.active_secret_id.as_deref(),
            Some(kid) => kid.get("secret_id").and_then(|v| v.as_str()),
        };
        self.fetch_keys_for_secret(account, container, object, secret_id)
    }

    fn fetch_keys_for_secret(
        &self,
        account: &str,
        container: Option<&str>,
        object: Option<&str>,
        secret_id: Option<&str>,
    ) -> Result<CryptoKeys, String> {
        let root = self.root_secret_for(secret_id)?;
        let mut keys = CryptoKeys {
            object: None,
            container: None,
            id: serde_json::Value::Null,
            all_ids: Vec::new(),
        };
        let Some(cont) = container.filter(|c| !c.is_empty()) else {
            return Ok(keys);
        };
        keys.container = Some(container_key(root, account, cont));
        let path = if let Some(obj) = object.filter(|o| !o.is_empty()) {
            keys.object = Some(object_key(root, account, cont, obj));
            format!("/{account}/{cont}/{obj}")
        } else {
            format!("/{account}/{cont}")
        };
        keys.id = Self::make_key_id(&path, secret_id, &self.meta_version_to_write);
        keys.all_ids = self
            .root_secret_ids()
            .into_iter()
            .map(|id| Self::make_key_id(&path, id.as_deref(), &self.meta_version_to_write))
            .collect();
        Ok(keys)
    }

    fn make_key_id(path: &str, secret_id: Option<&str>, version: &str) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        map.insert("v".into(), serde_json::Value::String(version.into()));
        map.insert("path".into(), serde_json::Value::String(path.into()));
        if let Some(sid) = secret_id.filter(|s| !s.is_empty()) {
            map.insert(
                "secret_id".into(),
                serde_json::Value::String(sid.to_string()),
            );
        }
        serde_json::Value::Object(map)
    }

    /// Object path keys for **every** loaded root secret (Python
    /// `CryptoKeyHelper.get_multiple_keys` → each `keys['object']`).
    ///
    /// Used by encrypter when masking `If-Match` / `If-None-Match`: the
    /// on-disk Etag-Mac may have been produced under any historic root
    /// secret, so each HMAC is appended.
    pub fn fetch_all_object_keys(
        &self,
        account: &str,
        container: &str,
        object: &str,
    ) -> Vec<[u8; KEY_LENGTH]> {
        self.root_secret_ids()
            .into_iter()
            .filter_map(|id| {
                self.fetch_keys_for_secret(account, Some(container), Some(object), id.as_deref())
                    .ok()
                    .and_then(|k| k.object)
            })
            .collect()
    }

    /// Root secret bytes for the active secret (tests / diagnostics only —
    /// never log).
    #[cfg(test)]
    pub fn root_secret(&self) -> &[u8] {
        self.root_secret_for(self.active_secret_id.as_deref())
            .expect("active secret present")
    }
}

/// Middleware filter: currently a pass-through that owns the shared
/// [`KeyMaster`]. Encrypter/decrypter receive the same `Arc` at pipeline
/// build time (the Python environ callback is not modelled on `Request`).
pub struct KeyMasterMw {
    pub state: Arc<KeyMaster>,
}

impl KeyMasterMw {
    pub fn new(state: Arc<KeyMaster>) -> Self {
        KeyMasterMw { state }
    }
}

impl Middleware for KeyMasterMw {
    fn handle(&self, req: Request, next: &NextFn) -> Response {
        // Python installs fetch_crypto_keys on PUT/POST/GET/HEAD for
        // account/container/object paths. Keys are derived by encrypter /
        // decrypter from the shared Arc — no per-request environ stamp.
        let _ = split_path(&req.path, 2, 4, true);
        next(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn b64_of(raw: &[u8]) -> String {
        B64.encode(raw)
    }

    #[test]
    fn from_b64_and_fetch_keys_known() {
        // root = bytes(range(32)) — same vector as swift-crypto keymaster tests
        let root = unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let b64 = B64.encode(&root);
        let km = KeyMaster::from_b64_root_secret(&b64).unwrap();
        let keys = km.fetch_keys("acct", Some("cont"), Some("obj"));
        let obj = keys.object.unwrap();
        let hex: String = obj.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "fcf56600dc7f6db65eecb4afb6ccac9148a24e6cad20e76b2e9ea86eca689305"
        );
        assert_eq!(keys.id["v"], "2");
        assert_eq!(keys.id["path"], "/acct/cont/obj");
        assert!(keys.id.get("secret_id").is_none());
    }

    #[test]
    fn rejects_short_secret() {
        let short = B64.encode([0u8; 16]);
        assert!(KeyMaster::from_b64_root_secret(&short).is_err());
    }

    #[test]
    fn multi_root_secret_conf_and_active() {
        let root_a = unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let root_b = vec![0xffu8; 32];
        let items = vec![
            ("encryption_root_secret".into(), b64_of(&root_a)),
            ("encryption_root_secret_old".into(), b64_of(&root_b)),
            ("active_root_secret_id".into(), "old".into()),
            ("meta_version_to_write".into(), "2".into()),
        ];
        let km = KeyMaster::from_conf_items(&items).unwrap();
        assert_eq!(km.active_secret_id(), Some("old"));
        assert_eq!(km.root_secret_ids().len(), 2);

        // Writes use active ("old") secret → key_id carries secret_id.
        let keys = km.fetch_keys("acct", Some("cont"), Some("obj"));
        assert_eq!(keys.id["secret_id"], "old");
        let obj_old = keys.object.unwrap();

        // Historic default secret via key_id without secret_id field.
        let kid_default = serde_json::json!({"v": "2", "path": "/acct/cont/obj"});
        let keys_def = km
            .fetch_keys_with_key_id("acct", Some("cont"), Some("obj"), Some(&kid_default))
            .unwrap();
        assert!(keys_def.id.get("secret_id").is_none());
        assert_ne!(keys_def.object.unwrap(), obj_old);

        // Named secret via key_id.secret_id
        let kid_old = serde_json::json!({
            "v": "2",
            "path": "/acct/cont/obj",
            "secret_id": "old",
        });
        let keys_named = km
            .fetch_keys_with_key_id("acct", Some("cont"), Some("obj"), Some(&kid_old))
            .unwrap();
        assert_eq!(keys_named.object.unwrap(), obj_old);

        // Unknown secret_id errors
        let kid_bad = serde_json::json!({"v": "2", "path": "/x", "secret_id": "nope"});
        assert!(km
            .fetch_keys_with_key_id("acct", Some("cont"), Some("obj"), Some(&kid_bad))
            .is_err());
    }

    #[test]
    fn active_must_exist() {
        let root = unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let items = vec![
            ("encryption_root_secret".into(), b64_of(&root)),
            ("active_root_secret_id".into(), "missing".into()),
        ];
        let err = KeyMaster::from_conf_items(&items).unwrap_err();
        assert!(err.contains("active_root_secret_id"), "{err}");
    }

    #[test]
    fn named_only_secret_with_active() {
        // Only encryption_root_secret_s1, active = s1 (no default None secret).
        let root = unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let items = vec![
            ("encryption_root_secret_s1".into(), b64_of(&root)),
            ("active_root_secret_id".into(), "s1".into()),
        ];
        let km = KeyMaster::from_conf_items(&items).unwrap();
        let keys = km.fetch_keys("a", Some("c"), Some("o"));
        assert_eq!(keys.id["secret_id"], "s1");
        assert_eq!(keys.all_ids.len(), 1);
    }

    #[test]
    fn fetch_all_object_keys_covers_every_secret() {
        let root_a = unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let root_b = vec![0xabu8; 32];
        let items = vec![
            ("encryption_root_secret".into(), b64_of(&root_a)),
            ("encryption_root_secret_b".into(), b64_of(&root_b)),
        ];
        let km = KeyMaster::from_conf_items(&items).unwrap();
        let all = km.fetch_all_object_keys("a", "c", "o");
        assert_eq!(all.len(), 2);
        assert_ne!(all[0], all[1]);
    }
}
