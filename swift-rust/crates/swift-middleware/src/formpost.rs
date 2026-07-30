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

//! `formpost` signature verification, ported from
//! `swift/common/middleware/formpost.py`.
//!
//! formpost lets a browser upload directly to Swift via an HTML `<form>` whose
//! hidden `signature` field is an HMAC over the form's constraints, signed
//! with a temp-URL key. The signature is the security contract — get it wrong
//! and either legitimate uploads fail or forged ones succeed — so this module
//! ports the HMAC exactly (golden-tested vs Python) and the validation of it.
//!
//! The signed message is
//! `"{path}\n{redirect}\n{max_file_size}\n{max_file_count}\n{expires}"`, and
//! the `signature` form field may be a bare hex digest or `"<algo>:<b64>"`
//! (shared with tempurl's `extract_digest_and_algorithm`).
//!
//! Deferred: the multipart/form-data streaming parser and the per-file object
//! PUT fan-out; those belong to the transport layer and are not part of the
//! signature contract this module guarantees.

use crate::tempurl::{extract_digest_and_algorithm, hmac_hex};

/// The set of digests accepted by default (`digest.DEFAULT_ALLOWED_DIGESTS`
/// = `"sha1 sha256 sha512"`; formpost still permits sha1 by default).
pub const DEFAULT_ALLOWED_DIGESTS: &[&str] = &["sha1", "sha256", "sha512"];

/// The signed form constraints.
#[derive(Debug, Clone, PartialEq)]
pub struct FormPostAttributes {
    pub path: String,
    pub redirect: String,
    pub max_file_size: u64,
    pub max_file_count: u64,
    pub expires: i64,
}

impl FormPostAttributes {
    /// The exact HMAC message body Python builds.
    fn hmac_body(&self) -> String {
        format!(
            "{}\n{}\n{}\n{}\n{}",
            self.path, self.redirect, self.max_file_size, self.max_file_count, self.expires
        )
    }
}

/// Compute the formpost signature for `key` under `algo` (`sha1|sha256|sha512`).
/// Returns the lower-case hex digest, or `None` for an unknown algorithm.
pub fn formpost_hmac(algo: &str, key: &[u8], attrs: &FormPostAttributes) -> Option<String> {
    hmac_hex(algo, key, attrs.hmac_body().as_bytes())
}

/// The result of verifying a formpost signature.
#[derive(Debug, Clone, PartialEq)]
pub enum FormPostVerify {
    Valid,
    /// The signature did not match any key.
    BadSignature,
    /// The signature encoding or algorithm was rejected.
    Invalid,
    /// `expires` is in the past (relative to `now`).
    Expired,
}

/// Constant-time hex-string comparison (Python `streq_const_time`).
fn streq_const_time(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Verify a formpost `signature` against every candidate `key`.
///
/// Mirrors `FormPost._perform_check`: reject an expired form, reject an
/// unknown digest/encoding, then accept if any key reproduces the signature.
pub fn verify_signature(
    keys: &[&[u8]],
    attrs: &FormPostAttributes,
    signature: &str,
    now: i64,
    allowed_digests: &[String],
) -> FormPostVerify {
    if attrs.expires < now {
        return FormPostVerify::Expired;
    }
    let Ok((algo, sig_hex)) = extract_digest_and_algorithm(signature) else {
        return FormPostVerify::Invalid;
    };
    if !allowed_digests.iter().any(|a| a == &algo) {
        return FormPostVerify::Invalid;
    }
    for key in keys {
        if let Some(sig) = formpost_hmac(&algo, key, attrs) {
            if streq_const_time(&sig, &sig_hex) {
                return FormPostVerify::Valid;
            }
        }
    }
    FormPostVerify::BadSignature
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attrs() -> FormPostAttributes {
        FormPostAttributes {
            path: "/v1/AUTH_test/container".into(),
            redirect: "https://example.com/done".into(),
            max_file_size: 1048576,
            max_file_count: 10,
            expires: 2000000000,
        }
    }

    #[test]
    fn test_hmac_lengths_per_algo() {
        let key = b"mykey";
        assert_eq!(formpost_hmac("sha1", key, &attrs()).unwrap().len(), 40);
        assert_eq!(formpost_hmac("sha256", key, &attrs()).unwrap().len(), 64);
        assert_eq!(formpost_hmac("sha512", key, &attrs()).unwrap().len(), 128);
        assert!(formpost_hmac("md5", key, &attrs()).is_none());
    }

    #[test]
    fn test_verify_valid_and_invalid() {
        let key: &[u8] = b"mykey";
        let sig = formpost_hmac("sha256", key, &attrs()).unwrap();
        let allowed: Vec<String> = DEFAULT_ALLOWED_DIGESTS.iter().map(|s| s.to_string()).collect();

        // valid
        assert_eq!(
            verify_signature(&[key], &attrs(), &sig, 0, &allowed),
            FormPostVerify::Valid
        );
        // wrong key
        assert_eq!(
            verify_signature(&[b"other"], &attrs(), &sig, 0, &allowed),
            FormPostVerify::BadSignature
        );
        // expired
        assert_eq!(
            verify_signature(&[key], &attrs(), &sig, 3000000000, &allowed),
            FormPostVerify::Expired
        );
        // sha1 IS in the default allowed set (matches Python)
        let sig1 = formpost_hmac("sha1", key, &attrs()).unwrap();
        assert_eq!(
            verify_signature(&[key], &attrs(), &sig1, 0, &allowed),
            FormPostVerify::Valid
        );
        // a digest not in a restricted allowed set is Invalid
        let only256 = vec!["sha256".to_string()];
        assert_eq!(
            verify_signature(&[key], &attrs(), &sig1, 0, &only256),
            FormPostVerify::Invalid
        );
    }
}
