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

//! `decrypter`: decrypt object GET/HEAD responses (body + user metadata) and
//! container listing etags, ported from
//! `swift/common/middleware/crypto/decrypter.py`.
//!
//! Scope implemented:
//! * object `GET`/`HEAD` — unwrap body key from
//!   `X-Object-Sysmeta-Crypto-Body-Meta`, decrypt body (with Content-Range
//!   offset), restore plaintext `Etag` from `X-Object-Sysmeta-Crypto-Etag`,
//!   restore user meta from `X-Object-Transient-Sysmeta-Crypto-Meta-*`,
//!   purge crypto sysmeta from the client response; resolves multi-root
//!   secrets via crypto-meta `key_id.secret_id`
//! * container `GET` JSON listings — decrypt each object's `hash` when it
//!   carries `; swift_meta=...` (Python `DecrypterContContext`); unknown
//!   secret → `"<unknown>"`
//!
//! Residuals (honest):
//! * multipart/byteranges ranged GET decryption
//! * CORS `Access-Control-Expose-Headers` rewrite for decrypted meta
//! * streaming body decrypt without materialize (GET body is decrypted in
//!   one shot after materialize up to max file size)
//! * **KMIP / KMS keymasters** — still deferred (keymaster residual)

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
const UNKNOWN_ETAG: &str = "<unknown>";

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

/// Decrypt a container-listing object `hash` value that may carry crypto-meta
/// (Python `DecrypterContContext.decrypt_obj_dict`). Returns the plaintext
/// etag, or `None` if the value was not encrypted.
pub fn decrypt_listing_hash(
    container_key: &[u8; KEY_LENGTH],
    hash_value: &str,
) -> Result<Option<String>, String> {
    let (ciphertext, crypto_meta) = extract_crypto_meta(hash_value);
    let Some(meta) = crypto_meta else {
        return Ok(None);
    };
    check_crypto_meta(&meta)?;
    let iv = meta_iv(&meta)?;
    let pt = decrypt_header_value(container_key, &iv, &ciphertext).map_err(|e| e.to_string())?;
    String::from_utf8(pt).map(Some).map_err(|e| e.to_string())
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

        match (object.as_deref(), container.as_deref(), req.method.as_str()) {
            (Some(obj), Some(cont), "GET" | "HEAD") => {
                self.handle_object(req, next, &account, cont, obj)
            }
            (None, Some(cont), "GET") => self.handle_container_listing(req, next, &account, cont),
            _ => next(req),
        }
    }
}

impl Decrypter {
    fn handle_object(
        &self,
        req: Request,
        next: &NextFn,
        account: &str,
        container: &str,
        object: &str,
    ) -> Response {
        let method = req.method.clone();
        let mut resp = next(req);

        let successish =
            (200..300).contains(&resp.status) || resp.status == 304 || resp.status == 412;
        if !successish {
            return resp;
        }

        let body_meta = resp.headers.get(BODY_META_HEADER).map(|s| s.to_string());
        let put_key_id = body_meta
            .as_ref()
            .and_then(|h| load_crypto_meta(h).ok())
            .and_then(|m| m.get("key_id").cloned());

        let post_key_id = resp
            .headers
            .get("X-Object-Transient-Sysmeta-Crypto-Meta")
            .and_then(|h| load_crypto_meta(h).ok())
            .and_then(|m| m.get("key_id").cloned());

        let put_keys = match self.keymaster.fetch_keys_with_key_id(
            account,
            Some(container),
            Some(object),
            put_key_id.as_ref(),
        ) {
            Ok(k) => k,
            Err(_) => return Response::error(500, "Unable to retrieve encryption keys."),
        };
        let post_keys = match self.keymaster.fetch_keys_with_key_id(
            account,
            Some(container),
            Some(object),
            post_key_id.as_ref().or(put_key_id.as_ref()),
        ) {
            Ok(k) => k,
            Err(_) => return Response::error(500, "Unable to retrieve encryption keys."),
        };

        let Some(object_key) = put_keys.object else {
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
        if let Some(post_ok) = post_keys.object {
            decrypt_user_metadata(&mut resp, &post_ok);
        }

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

    /// Python `DecrypterContContext`: decrypt encrypted etags in JSON container
    /// listings.
    fn handle_container_listing(
        &self,
        req: Request,
        next: &NextFn,
        account: &str,
        container: &str,
    ) -> Response {
        let mut resp = next(req);

        if !(200..300).contains(&resp.status) {
            return resp;
        }

        let content_type = resp
            .headers
            .get("Content-Type")
            .or_else(|| resp.headers.get("content-type"))
            .unwrap_or("");
        let base_ct = content_type.split(';').next().unwrap_or("").trim();
        if !base_ct.eq_ignore_ascii_case("application/json") {
            return resp;
        }

        let body = match materialize_body(&mut resp) {
            Ok(b) => b,
            Err(_) => return resp,
        };

        match decrypt_container_listing_json(&self.keymaster, account, container, &body) {
            Ok(new_body) => {
                resp.headers.set("Content-Length", new_body.len());
                resp.body = Body::from(new_body);
            }
            Err(_) => {
                // Leave original body on parse failure (unencrypted / non-list).
                resp.body = Body::from(body);
            }
        }
        resp
    }
}

/// Walk a container listing JSON array and decrypt each object's `hash` when
/// encrypted. Mirrors `DecrypterContContext.process_json_resp`.
pub fn decrypt_container_listing_json(
    keymaster: &KeyMaster,
    account: &str,
    container: &str,
    body: &[u8],
) -> Result<Vec<u8>, String> {
    let mut list: Vec<serde_json::Value> =
        serde_json::from_slice(body).map_err(|e| format!("listing json: {e}"))?;

    for obj_dict in &mut list {
        let Some(hash_val) = obj_dict.get("hash").and_then(|h| h.as_str()) else {
            continue;
        };
        let hash_val = hash_val.to_string();
        let (ciphertext, crypto_meta) = extract_crypto_meta(&hash_val);
        let Some(meta) = crypto_meta else {
            continue;
        };

        let new_hash = match decrypt_one_listing_hash(keymaster, account, container, &ciphertext, &meta)
        {
            Ok(pt) => pt,
            Err(_) => UNKNOWN_ETAG.to_string(),
        };
        if let Some(obj) = obj_dict.as_object_mut() {
            obj.insert("hash".into(), serde_json::Value::String(new_hash));
        }
    }

    // Compact JSON is fine; clients parse, Content-Length is updated.
    serde_json::to_vec(&list).map_err(|e| e.to_string())
}

fn decrypt_one_listing_hash(
    keymaster: &KeyMaster,
    account: &str,
    container: &str,
    ciphertext: &str,
    crypto_meta: &serde_json::Value,
) -> Result<String, String> {
    check_crypto_meta(crypto_meta)?;
    let key_id = crypto_meta.get("key_id");
    let keys =
        keymaster.fetch_keys_with_key_id(account, Some(container), None, key_id)?;
    let container_key = keys
        .container
        .ok_or_else(|| "missing container key".to_string())?;
    let iv = meta_iv(crypto_meta)?;
    let pt =
        decrypt_header_value(&container_key, &iv, ciphertext).map_err(|e| e.to_string())?;
    String::from_utf8(pt).map_err(|e| e.to_string())
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
    use swift_crypto::{append_crypto_meta, encrypt_header_value, IV_LENGTH};

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

    #[test]
    fn listing_hash_decrypt_roundtrip() {
        let root = unhex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        );
        let km = KeyMaster::new(root).unwrap();
        let keys = km.fetch_keys("acct", Some("cont"), None);
        let ck = keys.container.unwrap();
        let etag = "d41d8cd98f00b204e9800998ecf8427e";
        let iv = [0x11u8; IV_LENGTH];
        let enc = encrypt_header_value(&ck, &iv, etag.as_bytes()).unwrap();
        let mut meta = serde_json::json!({
            "cipher": CIPHER,
            "iv": B64.encode(iv),
            "key_id": keys.id,
        });
        let hash_hdr = append_crypto_meta(&enc, &meta);

        let got = decrypt_listing_hash(&ck, &hash_hdr).unwrap().unwrap();
        assert_eq!(got, etag);

        // Via full listing JSON helper
        let listing = serde_json::json!([
            {"name": "o1", "hash": hash_hdr, "bytes": 0},
            {"name": "o2", "hash": "plain-md5-hex", "bytes": 1},
        ]);
        let body = serde_json::to_vec(&listing).unwrap();
        let out = decrypt_container_listing_json(&km, "acct", "cont", &body).unwrap();
        let parsed: Vec<serde_json::Value> = serde_json::from_slice(&out).unwrap();
        assert_eq!(parsed[0]["hash"], etag);
        assert_eq!(parsed[1]["hash"], "plain-md5-hex");

        // Unknown secret_id → <unknown>
        if let Some(obj) = meta.as_object_mut() {
            obj.insert(
                "key_id".into(),
                serde_json::json!({"v": "2", "path": "/acct/cont", "secret_id": "nope"}),
            );
        }
        let bad_hash = append_crypto_meta(&enc, &meta);
        let listing2 = serde_json::json!([{"name": "x", "hash": bad_hash}]);
        let out2 =
            decrypt_container_listing_json(&km, "acct", "cont", &serde_json::to_vec(&listing2).unwrap())
                .unwrap();
        let p2: Vec<serde_json::Value> = serde_json::from_slice(&out2).unwrap();
        assert_eq!(p2[0]["hash"], UNKNOWN_ETAG);
    }

    #[test]
    fn multi_secret_object_decrypt_uses_key_id() {
        use std::sync::Arc;
        use swift_http::HeaderKeyDict;

        let root_new = unhex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        );
        let root_old = vec![0x55u8; 32];
        let items = vec![
            (
                "encryption_root_secret".into(),
                B64.encode(&root_new),
            ),
            (
                "encryption_root_secret_legacy".into(),
                B64.encode(&root_old),
            ),
            // Active is default (new); data was written under "legacy"
            ("active_root_secret_id".into(), String::new()),
        ];
        let km = Arc::new(KeyMaster::from_conf_items(&items).unwrap());

        // Encrypt under legacy secret by deriving keys with that id.
        let kid = serde_json::json!({
            "v": "2",
            "path": "/a/c/o",
            "secret_id": "legacy",
        });
        let keys = km
            .fetch_keys_with_key_id("a", Some("c"), Some("o"), Some(&kid))
            .unwrap();
        let ok = keys.object.unwrap();
        let ck = keys.container.unwrap();
        let pt = b"rotated-secret-payload";
        let enc = encrypt_object_body(
            &ok,
            &ck,
            &keys.id,
            pt,
            [1u8; IV_LENGTH],
            [2u8; KEY_LENGTH],
            [3u8; IV_LENGTH],
            [4u8; IV_LENGTH],
        )
        .unwrap();

        let decrypter = Decrypter::new(Arc::clone(&km));
        let app: NextFn = Arc::new(move |_req: Request| {
            let mut resp = Response::with_body(200, enc.ciphertext.clone());
            resp.headers.set(BODY_META_HEADER, &enc.body_meta_header);
            resp.headers.set(ETAG_HEADER, &enc.crypto_etag_header);
            resp.headers.set("Etag", &enc.ciphertext_etag);
            resp
        });
        let req = Request {
            method: "GET".into(),
            path: "/v1/a/c/o".into(),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: Body::empty(),
        };
        let resp = decrypter.handle(req, &app);
        assert_eq!(resp.status, 200);
        let got = match resp.body {
            Body::Buffered(b) => b,
            _ => panic!("buffered"),
        };
        assert_eq!(got, pt);
    }
}
