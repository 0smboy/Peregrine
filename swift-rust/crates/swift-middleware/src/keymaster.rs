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
//! Residuals (honest):
//! * multi-root-secret rotation (`encryption_root_secret_<id>`,
//!   `active_root_secret_id`) — only the single default root secret is loaded
//! * KMIP / KMS keymasters
//! * meta version `"1"` / `"3"` and the legacy leading-slash object path bug
//! * `keymaster_config_path` external file (use inline filter conf)
//! * Python `swift.callback.fetch_crypto_keys` environ hook — Encrypter /
//!   Decrypter hold an [`Arc`] to this keymaster and call
//!   [`KeyMaster::fetch_keys`] directly

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
}

/// Root-secret keymaster. Shared by the keymaster filter and by
/// encrypter/decrypter via [`Arc`].
#[derive(Debug, Clone)]
pub struct KeyMaster {
    /// Decoded root secret bytes (≥ 32).
    root_secret: Vec<u8>,
    /// Meta version written into `key_id` (Python `meta_version_to_write`,
    /// default `"2"`).
    pub meta_version_to_write: String,
}

impl KeyMaster {
    /// Build from a raw root secret (already decoded). Secret must be at
    /// least [`KEY_LENGTH`] bytes.
    pub fn new(root_secret: Vec<u8>) -> Result<Self, String> {
        if root_secret.len() < KEY_LENGTH {
            return Err(format!(
                "encryption_root_secret must be a base64 encoding of at least {KEY_LENGTH} raw bytes"
            ));
        }
        Ok(KeyMaster {
            root_secret,
            meta_version_to_write: "2".into(),
        })
    }

    /// Decode a base64 root secret (Python `KeyMaster._decode_root_secret`:
    /// strict base64, allow line breaks/whitespace, ≥ 32 raw bytes).
    pub fn from_b64_root_secret(b64: &str) -> Result<Self, String> {
        let cleaned: String = b64.chars().filter(|c| !c.is_whitespace()).collect();
        let secret = B64
            .decode(cleaned.as_bytes())
            .map_err(|e| format!("encryption_root_secret base64 decode failed: {e}"))?;
        Self::new(secret)
    }

    /// Build from filter conf items. Looks for `encryption_root_secret`
    /// (the default / None secret_id). Multi-id keys are residual.
    pub fn from_conf_items(items: &[(String, String)]) -> Result<Self, String> {
        let mut root: Option<String> = None;
        let mut meta_version = "2".to_string();
        for (k, v) in items {
            let kl = k.to_ascii_lowercase();
            if kl == "encryption_root_secret" {
                root = Some(v.clone());
            } else if kl == "meta_version_to_write" && !v.is_empty() {
                meta_version = v.clone();
            }
        }
        let b64 = root.ok_or_else(|| {
            "keymaster requires encryption_root_secret (base64 of ≥32 bytes)".to_string()
        })?;
        let mut km = Self::from_b64_root_secret(&b64)?;
        if !matches!(meta_version.as_str(), "1" | "2" | "3") {
            return Err(format!(
                "Unknown/unsupported metadata version: {meta_version:?}"
            ));
        }
        km.meta_version_to_write = meta_version;
        Ok(km)
    }

    /// Derive keys for the given path parts (account required; container /
    /// object optional). Mirrors `KeyMasterContext.fetch_crypto_keys` for
    /// the non-`key_id` (write / active secret) path.
    pub fn fetch_keys(
        &self,
        account: &str,
        container: Option<&str>,
        object: Option<&str>,
    ) -> CryptoKeys {
        let mut keys = CryptoKeys {
            object: None,
            container: None,
            id: serde_json::Value::Null,
        };
        let Some(cont) = container.filter(|c| !c.is_empty()) else {
            return keys;
        };
        keys.container = Some(container_key(&self.root_secret, account, cont));
        let path = if let Some(obj) = object.filter(|o| !o.is_empty()) {
            keys.object = Some(object_key(&self.root_secret, account, cont, obj));
            format!("/{account}/{cont}/{obj}")
        } else {
            format!("/{account}/{cont}")
        };
        keys.id = serde_json::json!({
            "v": self.meta_version_to_write,
            "path": path,
        });
        keys
    }

    /// Root secret bytes (tests / diagnostics only — never log).
    #[cfg(test)]
    pub fn root_secret(&self) -> &[u8] {
        &self.root_secret
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
    }

    #[test]
    fn rejects_short_secret() {
        let short = B64.encode([0u8; 16]);
        assert!(KeyMaster::from_b64_root_secret(&short).is_err());
    }
}
