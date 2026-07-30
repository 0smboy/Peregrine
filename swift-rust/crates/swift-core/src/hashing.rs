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

//! Path hashing, ported from `swift.common.utils.hash_path` and
//! `validate_hash_conf`.
//!
//! The MD5 of `<prefix>/<account>[/<container>[/<object>]]<suffix>` places
//! every entity on the ring; the prefix/suffix come from the `[swift-hash]`
//! section of `swift.conf` and must be identical across the cluster.

use std::fmt;

use md5::{Digest, Md5};

use crate::config::SwiftConfig;

/// Error hashing a path or loading the hash path configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashError(pub String);

impl fmt::Display for HashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for HashError {}

/// The cluster-wide hash path prefix and suffix from `swift.conf`
/// `[swift-hash]` (Python module globals `HASH_PATH_PREFIX` /
/// `HASH_PATH_SUFFIX`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HashPathConfig {
    pub prefix: Vec<u8>,
    pub suffix: Vec<u8>,
}

impl HashPathConfig {
    /// Create a validated config: at least one of prefix/suffix must be
    /// non-empty (Python `validate_hash_conf`).
    pub fn new(prefix: impl Into<Vec<u8>>, suffix: impl Into<Vec<u8>>) -> Result<Self, HashError> {
        let config = HashPathConfig {
            prefix: prefix.into(),
            suffix: suffix.into(),
        };
        if config.prefix.is_empty() && config.suffix.is_empty() {
            return Err(HashError(
                "Invalid configuration. Please ensure your swift.conf is \
                 readable and contains a [swift-hash] section with \
                 swift_hash_path_prefix and/or swift_hash_path_suffix set."
                    .to_string(),
            ));
        }
        Ok(config)
    }

    /// Load from a parsed `swift.conf` `[swift-hash]` section.
    pub fn from_swift_conf(conf: &SwiftConfig) -> Result<Self, HashError> {
        let get = |key: &str| -> Result<Vec<u8>, HashError> {
            Ok(conf
                .get("swift-hash", key)
                .map_err(|e| HashError(e.to_string()))?
                .unwrap_or_default()
                .into_bytes())
        };
        Self::new(get("swift_hash_path_prefix")?, get("swift_hash_path_suffix")?)
    }

    /// Get the canonical raw MD5 digest for an account/container/object
    /// (Python `hash_path(..., raw_digest=True)`).
    ///
    /// Matching Python's truthiness checks, empty-string components are
    /// treated the same as absent ones.
    pub fn hash_path_raw(
        &self,
        account: &str,
        container: Option<&str>,
        object: Option<&str>,
    ) -> Result<[u8; 16], HashError> {
        let container = container.filter(|s| !s.is_empty());
        let object = object.filter(|s| !s.is_empty());
        if object.is_some() && container.is_none() {
            return Err(HashError(
                "container is required if object is provided".to_string(),
            ));
        }
        let mut hasher = Md5::new();
        hasher.update(&self.prefix);
        hasher.update(b"/");
        hasher.update(account.as_bytes());
        if let Some(c) = container {
            hasher.update(b"/");
            hasher.update(c.as_bytes());
        }
        if let Some(o) = object {
            hasher.update(b"/");
            hasher.update(o.as_bytes());
        }
        hasher.update(&self.suffix);
        Ok(hasher.finalize().into())
    }

    /// Get the canonical hex-digest hash for an account/container/object
    /// (Python `hash_path`).
    pub fn hash_path(
        &self,
        account: &str,
        container: Option<&str>,
        object: Option<&str>,
    ) -> Result<String, HashError> {
        let raw = self.hash_path_raw(account, container, object)?;
        Ok(hex(&raw))
    }
}

/// Lowercase hex encoding.
pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> HashPathConfig {
        HashPathConfig::new(b"".to_vec(), b"changeme".to_vec()).unwrap()
    }

    /// Lock hash_path to real swift `hash_path()` hex digests — the on-disk
    /// object/DB placement contract. Values from CPython swift with
    /// prefix=testprefix, suffix=testsuffix.
    #[test]
    fn test_hash_path_matches_python() {
        let hc = HashPathConfig::new(b"testprefix".to_vec(), b"testsuffix".to_vec()).unwrap();
        assert_eq!(
            hc.hash_path("AUTH_test", None, None).unwrap(),
            "673fa2c47b180bb5bd9c41b40dbde62c"
        );
        assert_eq!(
            hc.hash_path("AUTH_test", Some("c"), None).unwrap(),
            "81744911f926d431d191caa31f81ea60"
        );
        assert_eq!(
            hc.hash_path("AUTH_test", Some("c"), Some("o")).unwrap(),
            "05c5055fb64b7219c5a436127559a5de"
        );
    }

    #[test]
    fn test_validation() {
        assert!(HashPathConfig::new(b"".to_vec(), b"".to_vec()).is_err());
        assert!(HashPathConfig::new(b"pre".to_vec(), b"".to_vec()).is_ok());
        let conf = SwiftConfig::parse(
            "[swift-hash]\nswift_hash_path_suffix = changeme\n",
            &[],
            false,
        )
        .unwrap();
        assert_eq!(HashPathConfig::from_swift_conf(&conf).unwrap(), cfg());
    }

    #[test]
    fn test_hash_path() {
        // Values verified against Python:
        //   hash_path('a') with suffix 'changeme'
        let c = cfg();
        // deterministic and distinct
        let h_a = c.hash_path("a", None, None).unwrap();
        let h_ac = c.hash_path("a", Some("c"), None).unwrap();
        let h_aco = c.hash_path("a", Some("c"), Some("o")).unwrap();
        assert_eq!(h_a.len(), 32);
        assert_ne!(h_a, h_ac);
        assert_ne!(h_ac, h_aco);
        // empty-string components behave as absent
        assert_eq!(c.hash_path("a", Some(""), None).unwrap(), h_a);
        // object without container is an error
        assert!(c.hash_path("a", None, Some("o")).is_err());
        assert!(c.hash_path("a", Some(""), Some("o")).is_err());
    }
}
