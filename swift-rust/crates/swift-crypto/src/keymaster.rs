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

//! Deterministic per-path key derivation, ported from
//! `BaseKeyMaster.create_key` in
//! `swift/common/middleware/crypto/keymaster.py`.
//!
//! Every resource path is associated with a key derived from the path itself,
//! so the per-object keys never have to be stored:
//!
//! ```text
//! <path_key> = HMAC_SHA256(<root_secret>, <path>)
//! ```
//!
//! The path is UTF-8 encoded before hashing (Python `path.encode('utf-8')`).
//! Rust `str` is already UTF-8, so [`create_key`] hashes `path.as_bytes()`
//! directly and is byte-for-byte identical with the Python output.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::crypto::KEY_LENGTH;

type HmacSha256 = Hmac<Sha256>;

/// Derive the encryption key for `path` under `root_secret`
/// (`HMAC_SHA256(root_secret, path)`), matching
/// `BaseKeyMaster.create_key`.
///
/// The returned key is always [`KEY_LENGTH`] (32) bytes, the SHA-256 output
/// size, so it is directly usable as an AES-256 key. HMAC accepts a root
/// secret of any length; Swift requires the root secret to be at least 32
/// bytes, but that policy check lives in the keymaster config loader, not here.
pub fn create_key(root_secret: &[u8], path: &str) -> [u8; KEY_LENGTH] {
    let mut mac =
        HmacSha256::new_from_slice(root_secret).expect("HMAC accepts a key of any length");
    mac.update(path.as_bytes());
    mac.finalize().into_bytes().into()
}

/// Derive the container key: `create_key(root, "/<account>/<container>")`.
///
/// This mirrors the container path built in
/// `KeyMasterContext.fetch_crypto_keys` (`'/' + account + '/' + container`).
pub fn container_key(root_secret: &[u8], account: &str, container: &str) -> [u8; KEY_LENGTH] {
    create_key(root_secret, &format!("/{account}/{container}"))
}

/// Derive the object key:
/// `create_key(root, "/<account>/<container>/<object>")`.
///
/// This mirrors the (non-legacy) object path built in
/// `KeyMasterContext.fetch_crypto_keys`. The legacy v1 leading-slash-object
/// special case is intentionally not reproduced here (see the crate's deferred
/// notes).
pub fn object_key(
    root_secret: &[u8],
    account: &str,
    container: &str,
    object: &str,
) -> [u8; KEY_LENGTH] {
    create_key(root_secret, &format!("/{account}/{container}/{object}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // ---- RFC 4231 Test Case 1 for HMAC-SHA-256. Python's create_key uses
    // hmac.new(key, msg, hashlib.sha256), which conforms to this vector, so
    // matching it proves the derivation primitive is interoperable. ----
    #[test]
    fn rfc4231_hmac_sha256_known_answer() {
        let key = vec![0x0bu8; 20];
        // create_key hashes path.as_bytes(); "Hi There" is the RFC test data.
        let derived = create_key(&key, "Hi There");
        assert_eq!(
            hex(&derived),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    // ---- Known-answer vectors generated directly from keymaster.py's
    // create_key with root_secret = bytes(range(32)). ----
    const ROOT: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    #[test]
    fn create_key_known_answers() {
        let root = unhex(ROOT);
        assert_eq!(
            hex(&create_key(&root, "/acct")),
            "13266fd94110c53faa810d073cada6c5f52c944a943591bcda1fc9b25025066b"
        );
        assert_eq!(
            hex(&create_key(&root, "/acct/cont")),
            "0135c0a31119f87a2bdb3a50efa0fe894bc8ae03bd5a5eeaedc0f342036d5fba"
        );
        assert_eq!(
            hex(&create_key(&root, "/acct/cont/obj")),
            "fcf56600dc7f6db65eecb4afb6ccac9148a24e6cad20e76b2e9ea86eca689305"
        );
    }

    #[test]
    fn create_key_utf8_object_name() {
        // A multibyte (utf-8) object name must hash the utf-8 bytes, matching
        // Python's path.encode('utf-8').
        let root = unhex(ROOT);
        assert_eq!(
            hex(&create_key(&root, "/acct/cont/\u{4e16}\u{754c}")),
            "1e1f1f7cdc33f44239b8b274ef7f652e7524df0ccc6e93c37b8336bbd9dcdf68"
        );
    }

    #[test]
    fn container_and_object_key_paths() {
        let root = unhex(ROOT);
        // Convenience helpers must build exactly the same paths.
        assert_eq!(
            container_key(&root, "acct", "cont"),
            create_key(&root, "/acct/cont")
        );
        assert_eq!(
            object_key(&root, "acct", "cont", "obj"),
            create_key(&root, "/acct/cont/obj")
        );
    }

    #[test]
    fn derivation_is_deterministic_and_path_dependent() {
        let root = unhex(ROOT);
        // Deterministic: same inputs -> same key.
        assert_eq!(create_key(&root, "/a/b/c"), create_key(&root, "/a/b/c"));
        // Distinct paths -> distinct keys.
        assert_ne!(create_key(&root, "/a/b"), create_key(&root, "/a/b/c"));
        // Distinct root secrets -> distinct keys.
        let other = vec![0xffu8; KEY_LENGTH];
        assert_ne!(create_key(&root, "/a/b/c"), create_key(&other, "/a/b/c"));
        // Output is always a 32-byte AES-256 key.
        assert_eq!(create_key(&root, "/a/b/c").len(), KEY_LENGTH);
    }
}
