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

//! At-rest encryption primitives, ported from
//! `swift/common/middleware/crypto/`.
//!
//! This crate is a *compatibility contract*: the ciphertext, wrapped keys,
//! derived keys and base64 metadata values produced here must be byte-identical
//! with those produced by the Python `crypto_utils.Crypto` class and the
//! `keymaster.BaseKeyMaster.create_key` method, so that data written by a
//! Python proxy can be read by a Rust proxy and vice versa.
//!
//! Two modules cover the two halves of the scheme:
//!
//! * [`crypto`] - AES-256-CTR body/metadata encryption, IV derivation for
//!   ranged reads, key wrapping, and the base64 metadata helpers. This mirrors
//!   `crypto_utils.py`'s [`Crypto`](crypto::Crypto) class.
//! * [`keymaster`] - deterministic per-path key derivation
//!   (`HMAC_SHA256(root_secret, path)`), mirroring `keymaster.py`'s
//!   `create_key`.
//!
//! # Cipher construction (the compatibility-critical details)
//!
//! Swift uses AES-256 in CTR mode with a full 128-bit counter block as the IV.
//! The Python code builds the cipher with `modes.CTR(iv)` from `pyca
//! cryptography`; that counter is **big-endian** and is incremented over the
//! whole 128-bit block, wrapping modulo 2^128. The RustCrypto
//! [`ctr::Ctr128BE`] flavour has exactly the same semantics, which is what
//! makes the two implementations interoperable.
//!
//! For a ranged (offset) read the Python code adjusts the counter by
//! `offset / 16` blocks and then discards `offset % 16` bytes of keystream;
//! [`crypto::create_decryption_ctxt`] reproduces this exactly.

pub mod crypto;
pub mod crypto_meta;
pub mod keymaster;

pub use crypto_meta::{
    append_crypto_meta, dump_crypto_meta, extract_crypto_meta, hmac_etag, load_crypto_meta,
    py_json_dumps_sorted,
};

pub use crypto::{
    create_decryption_ctxt, create_encryption_ctxt, decrypt, decrypt_header_value, encrypt,
    encrypt_header_value, unwrap_key, wrap_key, CryptoCtxt, CryptoError, WrappedKey, CIPHER,
    IV_LENGTH, KEY_LENGTH,
};
pub use keymaster::{container_key, create_key, object_key};
