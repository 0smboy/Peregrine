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

//! AES-256-CTR encryption primitives, ported from the `Crypto` class in
//! `swift/common/middleware/crypto/crypto_utils.py`.

use std::fmt;

use aes::Aes256;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ctr::cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr128BE;

/// AES-256-CTR with a big-endian 128-bit counter, matching
/// `pyca cryptography`'s `modes.CTR`.
type Aes256Ctr = Ctr128BE<Aes256>;

/// Length in bytes of an AES-256 key (Python `Crypto.key_length`).
pub const KEY_LENGTH: usize = 32;

/// Length in bytes of the IV / counter block, i.e. the AES block size
/// (Python `Crypto.iv_length`).
pub const IV_LENGTH: usize = 16;

/// Cipher identifier persisted in crypto-meta (Python `Crypto.cipher`).
pub const CIPHER: &str = "AES_CTR_256";

/// Errors raised by the crypto primitives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// A key was not exactly [`KEY_LENGTH`] bytes long
    /// (Python `Crypto.check_key` `ValueError`).
    BadKeyLength(usize),
    /// An IV was not exactly [`IV_LENGTH`] bytes long.
    BadIvLength(usize),
    /// An empty value was passed to [`encrypt_header_value`]
    /// (Python `encrypt_header_val` `ValueError`).
    EmptyValue,
    /// A base64 value could not be decoded.
    Base64(String),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::BadKeyLength(n) => {
                write!(f, "Key must be length {KEY_LENGTH} bytes, got {n}")
            }
            CryptoError::BadIvLength(n) => {
                write!(f, "IV must be length {IV_LENGTH} bytes, got {n}")
            }
            CryptoError::EmptyValue => write!(f, "empty value is not acceptable"),
            CryptoError::Base64(e) => write!(f, "invalid base64: {e}"),
        }
    }
}

impl std::error::Error for CryptoError {}

/// Validate that `key` is exactly [`KEY_LENGTH`] bytes (Python
/// `Crypto.check_key`).
pub fn check_key(key: &[u8]) -> Result<(), CryptoError> {
    if key.len() != KEY_LENGTH {
        return Err(CryptoError::BadKeyLength(key.len()));
    }
    Ok(())
}

fn check_iv(iv: &[u8]) -> Result<(), CryptoError> {
    if iv.len() != IV_LENGTH {
        return Err(CryptoError::BadIvLength(iv.len()));
    }
    Ok(())
}

/// A streaming AES-256-CTR cipher context.
///
/// This mirrors the encryptor/decryptor objects returned by the Python
/// `Crypto.create_encryption_ctxt` / `create_decryption_ctxt`: repeated calls
/// to [`update`](CryptoCtxt::update) consume successive chunks of the stream
/// and keep the keystream position across calls. Because CTR mode is
/// symmetric, encryption and decryption use the identical operation; only the
/// initial counter (IV) differs, which is why decryption has its own
/// constructor that applies the offset adjustment.
pub struct CryptoCtxt {
    cipher: Aes256Ctr,
}

impl CryptoCtxt {
    /// Encrypt/decrypt a chunk, returning a freshly allocated buffer. Equivalent
    /// to the Python context's `update(chunk)`.
    pub fn update(&mut self, data: &[u8]) -> Vec<u8> {
        let mut buf = data.to_vec();
        self.cipher.apply_keystream(&mut buf);
        buf
    }

    /// Encrypt/decrypt a chunk in place, avoiding an allocation.
    pub fn update_in_place(&mut self, buf: &mut [u8]) {
        self.cipher.apply_keystream(buf);
    }
}

/// Create a context for encrypting, from a 256-bit `key` and 128-bit `iv`
/// (Python `Crypto.create_encryption_ctxt`).
pub fn create_encryption_ctxt(key: &[u8], iv: &[u8]) -> Result<CryptoCtxt, CryptoError> {
    check_key(key)?;
    check_iv(iv)?;
    // Lengths already validated, so new_from_slices cannot fail.
    let cipher = Aes256Ctr::new_from_slices(key, iv).expect("key/iv length checked");
    Ok(CryptoCtxt { cipher })
}

/// Compute the CTR counter and intra-block byte offset for a ranged read.
///
/// This is the exact arithmetic from Python `create_decryption_ctxt`:
/// `offset_blocks, offset_in_block = divmod(offset, 16)`, then the counter is
/// `(iv_as_big_endian_int + offset_blocks) mod 2^128`.
fn adjust_iv(iv: &[u8], offset: u64) -> ([u8; IV_LENGTH], usize) {
    let offset_blocks = (offset / IV_LENGTH as u64) as u128;
    let offset_in_block = (offset % IV_LENGTH as u64) as usize;
    let base = u128::from_be_bytes(iv.try_into().expect("iv length checked"));
    // wrapping_add gives the modulo-2^128 behaviour of the Python code.
    let counter = base.wrapping_add(offset_blocks);
    (counter.to_be_bytes(), offset_in_block)
}

/// Create a context for decrypting, adjusted so that the first byte produced
/// corresponds to `offset` bytes into the plaintext message (Python
/// `Crypto.create_decryption_ctxt`).
///
/// For a whole-object read pass `offset = 0`. For a ranged read pass the byte
/// offset of the first byte of the response body within the object content.
pub fn create_decryption_ctxt(
    key: &[u8],
    iv: &[u8],
    offset: u64,
) -> Result<CryptoCtxt, CryptoError> {
    check_key(key)?;
    check_iv(iv)?;
    let (adj_iv, offset_in_block) = adjust_iv(iv, offset);
    let mut cipher = Aes256Ctr::new_from_slices(key, &adj_iv).expect("key/iv length checked");
    if offset_in_block > 0 {
        // Advance the keystream to the correct position within the current AES
        // block. Python does `dec.update(b'*' * offset_in_block)`; the bytes
        // fed in are irrelevant, only the keystream advance matters.
        let mut discard = vec![b'*'; offset_in_block];
        cipher.apply_keystream(&mut discard);
    }
    Ok(CryptoCtxt { cipher })
}

/// One-shot encryption of a whole buffer with `key` and `iv`.
pub fn encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut ctxt = create_encryption_ctxt(key, iv)?;
    Ok(ctxt.update(data))
}

/// One-shot decryption of a whole buffer, starting `offset` bytes into the
/// plaintext message (`offset = 0` for a whole-object read).
pub fn decrypt(key: &[u8], iv: &[u8], offset: u64, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut ctxt = create_decryption_ctxt(key, iv, offset)?;
    Ok(ctxt.update(data))
}

/// A key wrapped under another key (Python `Crypto.wrap_key` return value).
///
/// `key` is the AES-256-CTR ciphertext of the wrapped key; `iv` is the random
/// counter used to produce it. Both are persisted in the body crypto-meta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedKey {
    pub key: Vec<u8>,
    pub iv: [u8; IV_LENGTH],
}

/// Wrap (encrypt) `key_to_wrap` under `wrapping_key` using a caller-supplied
/// random `iv` (Python `Crypto.wrap_key`).
///
/// Swift deliberately does *not* use an RFC 3394 key-wrap here; it simply
/// AES-256-CTR encrypts the key material with a fresh random IV. The caller is
/// responsible for supplying a cryptographically random `iv` (the Python
/// middleware calls `os.urandom(16)`); this crate keeps the primitive
/// deterministic so it stays free of a randomness dependency.
pub fn wrap_key(
    wrapping_key: &[u8],
    key_to_wrap: &[u8],
    iv: [u8; IV_LENGTH],
) -> Result<WrappedKey, CryptoError> {
    let mut ctxt = create_encryption_ctxt(wrapping_key, &iv)?;
    Ok(WrappedKey {
        key: ctxt.update(key_to_wrap),
        iv,
    })
}

/// Unwrap (decrypt) a [`WrappedKey`] produced by [`wrap_key`] (Python
/// `Crypto.unwrap_key`).
///
/// The unwrapped key is validated to be [`KEY_LENGTH`] bytes, matching the
/// early length check the Python code performs.
pub fn unwrap_key(wrapping_key: &[u8], wrapped: &WrappedKey) -> Result<Vec<u8>, CryptoError> {
    // Python checks the wrapped key length up front; CTR does not change length.
    check_key(&wrapped.key)?;
    let mut ctxt = create_decryption_ctxt(wrapping_key, &wrapped.iv, 0)?;
    Ok(ctxt.update(&wrapped.key))
}

/// Encrypt a metadata/header value and base64-encode it (the core of Python
/// `encrypter.encrypt_header_val`).
///
/// Returns the standard-alphabet, padded base64 of the AES-256-CTR ciphertext,
/// as an ASCII string. The caller supplies the per-value random `iv` (which the
/// Python middleware persists alongside the value as crypto-meta). An empty
/// `value` is rejected, matching Python.
///
/// Note: the Python code applies `wsgi_to_bytes`/`bytes_to_wsgi` (latin-1) at
/// the WSGI string boundary; here `value` is already raw bytes and the returned
/// base64 is pure ASCII, so no additional transcoding is needed at this layer.
pub fn encrypt_header_value(key: &[u8], iv: &[u8], value: &[u8]) -> Result<String, CryptoError> {
    if value.is_empty() {
        return Err(CryptoError::EmptyValue);
    }
    let ciphertext = encrypt(key, iv, value)?;
    Ok(B64.encode(ciphertext))
}

/// Base64-decode and decrypt a metadata/header value produced by
/// [`encrypt_header_value`] (the core of the Python
/// `decrypter.decrypt_value`).
///
/// Metadata values are never ranged, so decryption always starts at offset 0.
pub fn decrypt_header_value(
    key: &[u8],
    iv: &[u8],
    b64_value: &str,
) -> Result<Vec<u8>, CryptoError> {
    let ciphertext = B64
        .decode(b64_value.as_bytes())
        .map_err(|e| CryptoError::Base64(e.to_string()))?;
    decrypt(key, iv, 0, &ciphertext)
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

    // ---- Standard NIST SP 800-38A F.5.5 CTR-AES256 known-answer vector. ----
    // This is the canonical AES-256-CTR test vector. `pyca cryptography` (used
    // by Swift) conforms to it, so matching it proves byte-for-byte
    // interoperability of the core cipher with the Python implementation. The
    // counter starts at f0f1...feff and increments over the full 128-bit block,
    // exercising the carry that both modes.CTR and Ctr128BE perform.
    const NIST_KEY: &str = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
    const NIST_IV: &str = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
    const NIST_PT: &str = "6bc1bee22e409f96e93d7e117393172a\
                           ae2d8a571e03ac9c9eb76fac45af8e51\
                           30c81c46a35ce411e5fbc1191a0a52ef\
                           f69f2445df4f9b17ad2b417be66c3710";
    const NIST_CT: &str = "601ec313775789a5b7a7f504bbf3d228\
                           f443e3ca4d62b59aca84e990cacaf5c5\
                           2b0930daa23de94ce87017ba2d84988d\
                           dfc9c58db67aada613c2dd08457941a6";

    #[test]
    fn nist_ctr_aes256_known_answer() {
        let key = unhex(NIST_KEY);
        let iv = unhex(NIST_IV);
        let pt = unhex(NIST_PT);
        let ct = encrypt(&key, &iv, &pt).unwrap();
        assert_eq!(hex(&ct), NIST_CT);
        // CTR is symmetric: whole-object decrypt recovers the plaintext.
        let back = decrypt(&key, &iv, 0, &ct).unwrap();
        assert_eq!(hex(&back), NIST_PT);
    }

    // ---- Known-answer vector generated directly from crypto_utils.py's exact
    // construction (pyca cryptography 49.0.0), see the crate's test notes. ----
    // key = bytes(range(32)); iv = 00..00ff (chosen to force a counter carry).
    const PY_KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const PY_IV: &str = "000000000000000000000000000000ff";
    const PY_PT: &str = "54686520717569636b2062726f776e20666f78206a756d7073206f\
                         76657220746865206c617a7920646f672e203132333435363738393021";
    const PY_CT: &str = "5ddfb1aeb168853a59fa4ab6e612f0ba37412e10bbd9303f30e8180b\
                         0b7d531149a9b889b257adbcfaae9556c2f68a5cae8b03ec62b16c0f";

    #[test]
    fn python_derived_body_known_answer() {
        let key = unhex(PY_KEY);
        let iv = unhex(PY_IV);
        let pt = unhex(PY_PT);
        let ct = encrypt(&key, &iv, &pt).unwrap();
        assert_eq!(hex(&ct), PY_CT, "ciphertext must match crypto_utils.py");
    }

    #[test]
    fn body_round_trip_streaming_chunks() {
        let key = unhex(PY_KEY);
        let iv = unhex(PY_IV);
        let pt = unhex(PY_PT);

        // Encrypt in awkward chunk sizes to exercise the streaming state.
        let mut enc = create_encryption_ctxt(&key, &iv).unwrap();
        let mut ct = Vec::new();
        for chunk in pt.chunks(7) {
            ct.extend_from_slice(&enc.update(chunk));
        }
        assert_eq!(hex(&ct), PY_CT);

        // Decrypt in different chunk sizes.
        let mut dec = create_decryption_ctxt(&key, &iv, 0).unwrap();
        let mut back = Vec::new();
        for chunk in ct.chunks(5) {
            back.extend_from_slice(&dec.update(chunk));
        }
        assert_eq!(back, pt);
    }

    #[test]
    fn offset_ranged_decrypt_matches_whole() {
        let key = unhex(PY_KEY);
        let iv = unhex(PY_IV);
        let pt = unhex(PY_PT);
        let ct = encrypt(&key, &iv, &pt).unwrap();

        // For every offset, decrypting ct[offset..] at that offset must recover
        // pt[offset..]. Cover block-aligned, mid-block, and cross-block cases,
        // including the offset==16 carry boundary.
        for &off in &[0usize, 1, 5, 15, 16, 17, 20, 31, 32, 33, 55] {
            let dec = decrypt(&key, &iv, off as u64, &ct[off..]).unwrap();
            assert_eq!(dec, pt[off..].to_vec(), "offset {off} decrypt mismatch");
        }
    }

    #[test]
    fn offset_adjusted_iv_matches_python() {
        // Python: offset 16 -> counter incremented by exactly 1 block.
        // iv 00..00ff  =>  adjusted 00..0100.
        let iv = unhex(PY_IV);
        let (adj, in_block) = adjust_iv(&iv, 16);
        assert_eq!(hex(&adj), "00000000000000000000000000000100");
        assert_eq!(in_block, 0);

        // offset 20 -> 1 block + 4 bytes into the next block.
        let (adj2, in_block2) = adjust_iv(&iv, 20);
        assert_eq!(hex(&adj2), "00000000000000000000000000000100");
        assert_eq!(in_block2, 4);

        // The whole IV space wraps modulo 2^128, matching Python's
        // `ivl %= 1 << 128`. All-ones IV + 1 block wraps to zero.
        let all_ones = vec![0xffu8; IV_LENGTH];
        let (wrapped, _) = adjust_iv(&all_ones, 16);
        assert_eq!(hex(&wrapped), "00000000000000000000000000000000");
    }

    #[test]
    fn wrap_unwrap_round_trip() {
        let wrapping_key = unhex(PY_KEY);
        let body_key = vec![0x5au8; KEY_LENGTH];
        let iv = [0u8; IV_LENGTH];
        let wrapped = wrap_key(&wrapping_key, &body_key, iv).unwrap();
        assert_eq!(wrapped.key.len(), KEY_LENGTH);
        assert_ne!(wrapped.key, body_key, "wrapped key must be ciphertext");
        let unwrapped = unwrap_key(&wrapping_key, &wrapped).unwrap();
        assert_eq!(unwrapped, body_key);
    }

    #[test]
    fn wrap_key_is_ctr_encrypt() {
        // wrap_key is documented as "just AES-CTR encrypt the key material",
        // so it must equal a plain encrypt() with the same wrapping key + iv.
        let wrapping_key = unhex(PY_KEY);
        let body_key = vec![0x11u8; KEY_LENGTH];
        let iv = [0x22u8; IV_LENGTH];
        let wrapped = wrap_key(&wrapping_key, &body_key, iv).unwrap();
        let expected = encrypt(&wrapping_key, &iv, &body_key).unwrap();
        assert_eq!(wrapped.key, expected);
    }

    // ---- Metadata value helper, generated from Python encrypt_header_val:
    // key = 0xAA*32; iv = 00..0f; value = "Hello, 世界" (utf-8). ----
    const META_KEY: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const META_IV: &str = "000102030405060708090a0b0c0d0e0f";
    const META_VALUE_UTF8: &str = "Hello, 世界";
    const META_ENC_B64: &str = "qU/Kk5d/J8URxRcgvQ==";

    #[test]
    fn metadata_value_known_answer() {
        let key = unhex(META_KEY);
        let iv = unhex(META_IV);
        let enc = encrypt_header_value(&key, &iv, META_VALUE_UTF8.as_bytes()).unwrap();
        assert_eq!(enc, META_ENC_B64, "must match encrypter.encrypt_header_val");
    }

    #[test]
    fn metadata_value_round_trip() {
        let key = unhex(META_KEY);
        let iv = unhex(META_IV);
        let enc = encrypt_header_value(&key, &iv, META_VALUE_UTF8.as_bytes()).unwrap();
        let dec = decrypt_header_value(&key, &iv, &enc).unwrap();
        assert_eq!(dec, META_VALUE_UTF8.as_bytes());
    }

    #[test]
    fn metadata_empty_value_rejected() {
        let key = unhex(META_KEY);
        let iv = unhex(META_IV);
        assert_eq!(
            encrypt_header_value(&key, &iv, b""),
            Err(CryptoError::EmptyValue)
        );
    }

    #[test]
    fn base64_uses_standard_padded_alphabet() {
        // Python base64.b64encode uses the standard alphabet with padding.
        let key = vec![0u8; KEY_LENGTH];
        let iv = [0u8; IV_LENGTH];
        // Encrypting 5 bytes yields 5 ciphertext bytes -> base64 with '=' pad.
        let enc = encrypt_header_value(&key, &iv, b"hello").unwrap();
        assert!(enc.ends_with('='), "expected standard padding");
        assert!(!enc.contains('-') && !enc.contains('_'), "not url-safe");
    }

    #[test]
    fn key_and_iv_length_validation() {
        assert_eq!(check_key(&[0u8; 31]), Err(CryptoError::BadKeyLength(31)));
        assert_eq!(check_key(&[0u8; 33]), Err(CryptoError::BadKeyLength(33)));
        assert!(check_key(&[0u8; 32]).is_ok());
        assert_eq!(
            create_encryption_ctxt(&[0u8; 32], &[0u8; 15]).err(),
            Some(CryptoError::BadIvLength(15))
        );
        assert_eq!(
            create_decryption_ctxt(&[0u8; 32], &[0u8; 17], 0).err(),
            Some(CryptoError::BadIvLength(17))
        );
    }
}
