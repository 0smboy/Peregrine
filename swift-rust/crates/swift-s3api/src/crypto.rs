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

//! SHA-256, HMAC-SHA256 and constant-time comparison primitives.
//!
//! HMAC is hand-rolled (RFC 2104) over the RustCrypto `sha2` `Digest`
//! trait rather than pulling in the `hmac` crate, matching the existing
//! `swift-middleware` `tempurl` implementation and keeping the dependency
//! surface to a single already-vendored crate (`sha2`).

use sha2::{Digest, Sha256};

/// Lowercase hex encoding of `bytes`.
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// SHA-256 of `data`, raw 32 bytes.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// SHA-256 of `data`, lowercase hex (`hashlib.sha256(data).hexdigest()`).
pub fn sha256_hex(data: &[u8]) -> String {
    hex_encode(&sha256(data))
}

/// RFC 2104 HMAC-SHA256 (`hmac.new(key, msg, sha256).digest()`).
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    const BLOCK_SIZE: usize = 64;
    let mut key = key.to_vec();
    if key.len() > BLOCK_SIZE {
        key = Sha256::digest(&key).to_vec();
    }
    if key.len() < BLOCK_SIZE {
        key.resize(BLOCK_SIZE, 0);
    }
    let ipad: Vec<u8> = key.iter().map(|b| b ^ 0x36).collect();
    let opad: Vec<u8> = key.iter().map(|b| b ^ 0x5c).collect();

    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(msg);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(inner_digest);
    let mut out = [0u8; 32];
    out.copy_from_slice(&outer.finalize());
    out
}

/// HMAC-SHA256, lowercase hex (`hmac.new(...).hexdigest()`).
pub fn hmac_sha256_hex(key: &[u8], msg: &[u8]) -> String {
    hex_encode(&hmac_sha256(key, msg))
}

/// Constant-time string comparison, port of `streq_const_time`.
pub fn streq_const_time(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        result |= x ^ y;
    }
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_empty() {
        // The well-known SHA-256 of the empty string.
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_sha256_abc() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn test_hmac_rfc4231_case2() {
        // RFC 4231 test case 2: key="Jefe", data="what do ya want for nothing?"
        assert_eq!(
            hmac_sha256_hex(b"Jefe", b"what do ya want for nothing?"),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn test_streq_const_time() {
        assert!(streq_const_time("abcdef", "abcdef"));
        assert!(!streq_const_time("abcdef", "abcdeg"));
        assert!(!streq_const_time("abc", "abcd"));
    }
}
