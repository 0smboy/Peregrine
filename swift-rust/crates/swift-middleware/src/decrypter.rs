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

//! `decrypter`: decrypt object GET/HEAD responses (body + user metadata),
//! ported from `swift/common/middleware/crypto/decrypter.py`.
//!
//! Scope implemented:
//! * object `GET`/`HEAD` — unwrap body key from
//!   `X-Object-Sysmeta-Crypto-Body-Meta`, decrypt body (with Content-Range
//!   offset), restore plaintext `Etag` from `X-Object-Sysmeta-Crypto-Etag`,
//!   restore user meta from `X-Object-Transient-Sysmeta-Crypto-Meta-*`,
//!   purge crypto sysmeta from the client response
//!
//! Residuals (honest):
//! * container listing JSON hash decryption (`DecrypterContContext`)
//! * multipart/byteranges ranged GET decryption
//! * CORS `Access-Control-Expose-Headers` rewrite for decrypted meta
//! * multi-root-secret / unknown `key_id` recovery beyond active secret
//! * streaming body decrypt without materialize (GET body is decrypted in
//!   one shot after materialize up to max file size)

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use swift_core::config::config_true_value;
use swift_core::constraints::{MAX_FILE_SIZE, VALID_API_VERSIONS};
use swift_crypto::{
    decrypt, decrypt_header_value, extract_crypto_meta, load_crypto_meta, unwrap_key, CryptoError,
    WrappedKey, CIPHER, IV_LENGTH, KEY_LENGTH,
};
use swift_http::{split_path, Body, Request, Response};

use crate::encrypter::{BODY_META_HEADER, ETAG_HEADER, ETAG_MAC_HEADER, OVERRIDE_ETAG_HEADER};
use crate::keymaster::KeyMaster;
use crate::{Middleware, NextFn};

const TRANSIENT_META_PREFIX: &str = "x-object-transient-sysmeta-crypto-meta-";
const TRANSIENT_CRYPTO_META: &str = "x-object-transient-sysmeta-crypto-meta";
const USER_META_PREFIX: &str = "X-Object-Meta-";

/// Decrypt an object body given the serialized body crypto-meta header and
/// the object path key. `offset` is the Content-Range start (0 for full GET).
pub fn decrypt_object_body(
    object_key: &[u8; KEY_LENGTH],
    body_meta_header: &str,
    offset: u64,
    ciphertext: &[u8],
) -> Result<Vec<u8>, String> {
    let meta = load_crypto_meta(body_meta_header).map_err(|e| e)?;
    check_crypto_meta(&meta)?;
    let body_key = unwrap_body_key(object_key, &meta)?;
    let iv = meta_iv(&meta)?;
    decrypt(&body_key, &iv, offset, ciphertext).map_err(|e| e.to_string())
}

fn check_crypto_meta(meta: &serde_json::Value) -> Result<(), String> {
    let cipher = meta
        .get("cipher")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Bad crypto meta: Missing cipher".to_string())?;
    if cipher != CIPHER {
        return Err(format!("Bad crypto meta: Cipher must be {CIPHER}"));
    }
    let iv = meta_iv(meta)?;
    if iv.len() != IV_LENGTH {
        return Err(format!(
            "Bad crypto meta: IV must be length {IV_LENGTH} bytes"
        ));
    }
    Ok(())
}

fn meta_iv(meta: &serde_json::Value) -> Result<[u8; IV_LENGTH], String> {
    let s = meta
        .get("iv")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Bad crypto meta: Missing iv".to_string())?;
    let bytes = B64
        .decode(s.as_bytes())
        .map_err(|e| format!("Bad crypto meta: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| format!("Bad crypto meta: IV must be length {IV_LENGTH} bytes"))
}

fn unwrap_body_key(
    wrapping_key: &[u8; KEY_LENGTH],
    meta: &serde_json::Value,
) -> Result<Vec<u8>, String> {
    let bk = meta
        .get("body_key")
        .ok_or_else(|| "Missing body_key".to_string())?;
    let key_b64 = bk
        .get("key")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing body_key.key".to_string())?;
    let iv_b64 = bk
        .get("iv")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing body_key.iv".to_string())?;
    let key = B64
        .decode(key_b64.as_bytes())
        .map_err(|e| format!("body_key.key base64: {e}"))?;
    let iv_bytes = B64
        .decode(iv_b64.as_bytes())
        .map_err(|e| format!("body_key.iv base64: {e}"))?;
    let iv: [u8; IV_LENGTH] = iv_bytes
        .try_into()
        .map_err(|_| format!("body_key.iv must be {IV_LENGTH} bytes"))?;
    let wrapped = WrappedKey { key, iv };
    unwrap_key(wrapping_key, &wrapped).map_err(|e: CryptoError| e.to_string())
}

/// At-rest decryption middleware.
pub struct Decrypter {
    pub keymaster: Arc<KeyMaster>,
}

impl Decrypter {
    pub fn new(keymaster: Arc<KeyMaster>) -> Self {
        Decrypter { keymaster }
    }
}

impl Middleware for Decrypter {
    fn handle(&self, req: Request, next: &NextFn) -> Response {
        if config_true_value(req.headers.get("Swift-Crypto-Override").unwrap_or("")) {
            return next(req);
        }

        let parts = match split_path(&req.path, 3, 4, true) {
            Ok(p) => p,
            Err(_) => return next(req),
        };
        let version = parts[0].as_deref().unwrap_or("");
        if !VALID_API_VERSIONS.contains(&version) {
            return next(req);
        }
        let account = match parts[1].as_deref().filter(|s| !s.is_empty()) {
            Some(a) => a.to_string(),
            None => return next(req),
        };
        let container = parts[2].as_deref().filter(|s| !s.is_empty()).map(str::to_string);
        let object = parts
            .get(3)
            .and_then(|p| p.as_deref())
            .filter(|s| !s.is_empty())
            .map(str::to_string);

        // Object GET/HEAD only (container listing residual).
        if object.is_none() || !matches!(req.method.as_str(), "GET" | "HEAD") {
            return next(req);
        }
        let container = match container {
            Some(c) => c,
            None => return next(req),
        };
        let object = object.unwrap();
        let method = req.method.clone();

        let mut resp = next(req);

        let successish = (200..300).contains(&resp.status) || resp.status == 304 || resp.status == 412;
        if !successish {
            return resp;
        }

        let body_meta = resp
            .headers
            .get(BODY_META_HEADER)
            .map(|s| s.to_string());
        let keys = self
            .keymaster
            .fetch_keys(&account, Some(&container), Some(&object));
        let Some(object_key) = keys.object else {
            return Response::error(500, "Unable to retrieve encryption keys.");
        };

        // Decrypt plaintext etag into the client Etag header.
        if let Some(enc_etag) = resp.headers.get(ETAG_HEADER).map(|s| s.to_string()) {
            match decrypt_value_with_meta(&enc_etag, &object_key) {
                Ok(pt) => {
                    if let Ok(s) = String::from_utf8(pt) {
                        resp.headers.set("Etag", s);
                    }
                }
                Err(_) => {
                    return Response::error(500, "Error decrypting header");
                }
            }
        }

        // Restore user metadata from transient crypto-meta headers.
        decrypt_user_metadata(&mut resp, &object_key);

        // Decrypt body on successful GET with body crypto-meta.
        if method == "GET" && (200..300).contains(&resp.status) {
            if let Some(meta_hdr) = body_meta {
                let offset = content_range_offset(resp.headers.get("Content-Range"));
                let ciphertext = match materialize_body(&mut resp) {
                    Ok(b) => b,
                    Err(_) => return Response::error(500, "Error decrypting object"),
                };
                match decrypt_object_body(&object_key, &meta_hdr, offset, &ciphertext) {
                    Ok(pt) => {
                        resp.headers.set("Content-Length", pt.len());
                        resp.body = Body::from(pt);
                    }
                    Err(_) => {
                        return Response::error(500, "Error decrypting object");
                    }
                }
            }
        }

        purge_crypto_sysmeta(&mut resp);
        resp
    }
}

fn decrypt_value_with_meta(value: &str, key: &[u8; KEY_LENGTH]) -> Result<Vec<u8>, String> {
    let (extracted, meta) = extract_crypto_meta(value);
    let meta = meta.ok_or_else(|| "Missing crypto meta".to_string())?;
    check_crypto_meta(&meta)?;
    let iv = meta_iv(&meta)?;
    if extracted.is_empty() {
        return Ok(Vec::new());
    }
    decrypt_header_value(key, &iv, &extracted).map_err(|e| e.to_string())
}

fn decrypt_user_metadata(resp: &mut Response, object_key: &[u8; KEY_LENGTH]) {
    let candidates: Vec<(String, String)> = resp
        .headers
        .iter()
        .filter(|(k, v)| {
            let kl = k.to_ascii_lowercase();
            kl.starts_with(TRANSIENT_META_PREFIX) && kl != TRANSIENT_CRYPTO_META && !v.is_empty()
        })
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    for (name, val) in candidates {
        let short = {
            let lower = name.to_ascii_lowercase();
            if let Some(rest) = lower.strip_prefix(TRANSIENT_META_PREFIX) {
                // Preserve original casing of the short name when possible.
                name[name.len() - rest.len()..].to_string()
            } else {
                continue;
            }
        };
        match decrypt_value_with_meta(&val, object_key) {
            Ok(pt) => {
                if let Ok(s) = String::from_utf8(pt) {
                    resp.headers
                        .set(&format!("{USER_META_PREFIX}{short}"), s);
                }
                resp.headers.remove(&name);
            }
            Err(_) => {
                // Leave encrypted header; purge will drop transient crypto ones.
            }
        }
    }
}

fn purge_crypto_sysmeta(resp: &mut Response) {
    let to_remove: Vec<String> = resp
        .headers
        .iter()
        .filter(|(k, _)| {
            let kl = k.to_ascii_lowercase();
            kl.starts_with("x-object-sysmeta-crypto-")
                || kl.starts_with("x-object-transient-sysmeta-crypto-")
                || kl == ETAG_HEADER.to_ascii_lowercase()
                || kl == BODY_META_HEADER.to_ascii_lowercase()
                || kl == ETAG_MAC_HEADER.to_ascii_lowercase()
                || kl == OVERRIDE_ETAG_HEADER.to_ascii_lowercase()
        })
        .map(|(k, _)| k.to_string())
        .collect();
    for name in to_remove {
        resp.headers.remove(&name);
    }
}

fn content_range_offset(header: Option<&str>) -> u64 {
    // Content-Range: bytes START-END/TOTAL
    let Some(v) = header else {
        return 0;
    };
    let v = v.trim();
    let rest = v
        .strip_prefix("bytes ")
        .or_else(|| v.strip_prefix("bytes"))
        .unwrap_or(v)
        .trim();
    let start = rest.split('-').next().unwrap_or("0");
    start.parse().unwrap_or(0)
}

fn materialize_body(resp: &mut Response) -> Result<Vec<u8>, u16> {
    let mut body = resp.body.take();
    match body.materialize(MAX_FILE_SIZE as u64) {
        Ok(slice) => Ok(slice.to_vec()),
        Err(_) => Err(500),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encrypter::encrypt_object_body;
    use crate::keymaster::KeyMaster;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn offset_decrypt_slice() {
        let root = unhex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        );
        let km = KeyMaster::new(root).unwrap();
        let keys = km.fetch_keys("a", Some("c"), Some("o"));
        let ok = keys.object.unwrap();
        let ck = keys.container.unwrap();
        let pt = b"0123456789abcdefghijklmnopqrstuvwxyz";
        let mut body_iv = [0u8; IV_LENGTH];
        body_iv[15] = 1;
        let body_key = [0xabu8; KEY_LENGTH];
        let enc = encrypt_object_body(
            &ok,
            &ck,
            &keys.id,
            pt,
            body_iv,
            body_key,
            [2u8; IV_LENGTH],
            [3u8; IV_LENGTH],
        )
        .unwrap();
        let off = 10u64;
        let slice = &enc.ciphertext[off as usize..];
        let got = decrypt_object_body(&ok, &enc.body_meta_header, off, slice).unwrap();
        assert_eq!(got, pt[off as usize..]);
    }
}
