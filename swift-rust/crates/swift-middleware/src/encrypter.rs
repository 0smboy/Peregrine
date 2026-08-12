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

//! `encrypter`: encrypt object PUT/POST bodies and user metadata at rest,
//! ported from `swift/common/middleware/crypto/encrypter.py`.
//!
//! Scope implemented:
//! * object `PUT` — AES-256-CTR body encrypt, body-key wrap, crypto sysmeta
//!   headers (`X-Object-Sysmeta-Crypto-Body-Meta`, `-Etag`, `-Etag-Mac`),
//!   container-listing etag override, user-meta → transient-sysmeta
//! * object `POST` — user-meta encryption only
//! * response `Etag` rewrite to plaintext on successful PUT
//! * **chunked encrypt-while-read** on PUT: plaintext is never held as a
//!   second full copy; AES-CTR + dual MD5 (pt/ct) advance in
//!   [`STREAM_CHUNK`] windows. Ciphertext is still assembled in one
//!   buffer so etag/crypto sysmeta can be stamped as *request headers*
//!   before the proxy opens backend connections.
//!
//! Residuals (honest):
//! * **True zero-copy streaming PUT** is blocked without
//!   `swift.callback.update_footers` on the replication object-PUT path
//!   (Python's `EncInputWrapper` encrypts per-chunk as the body is
//!   pulled, then stamps etag/crypto sysmeta as MIME/trailers *after*
//!   the stream). Until the proxy putter gains a footer callback for
//!   repl policy, the ciphertext must exist before `next(req)` so
//!   `Etag` + crypto sysmeta travel as ordinary headers.
//!   `// P1-leftover: ciphertext still fully buffered (footer residual)`.
//! * full `swift.crypto.override` environ path — **incomplete**: only the
//!   `Swift-Crypto-Override` request header is honoured (Python checks
//!   `env['swift.crypto.override']`). `Request` has no WSGI environ map
//!   yet, so middleware cannot set the override out-of-band.
//! * **KMIP / KMS keymasters** — still deferred (keymaster residual)
//!
//! Multi-root secrets: writes use the keymaster's active root secret; the
//! resulting `key_id` (including optional `secret_id`) is stamped into
//! body/listing crypto-meta for later decrypt. GET/HEAD conditionals mask
//! `If-Match` / `If-None-Match` with HMAC etags under **all** root secrets
//! and set `X-Backend-Etag-Is-At: X-Object-Sysmeta-Crypto-Etag-Mac`
//! (Python `_mask_conditional_etags` + `update_etag_is_at_header`).

use std::io::Read;
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use md5::{Digest, Md5};
use swift_core::config::config_true_value;
use swift_core::constraints::{MAX_FILE_SIZE, VALID_API_VERSIONS};
use swift_crypto::{
    append_crypto_meta, create_encryption_ctxt, dump_crypto_meta, encrypt_header_value, hmac_etag,
    wrap_key, CryptoError, WrappedKey, CIPHER, IV_LENGTH, KEY_LENGTH,
};
use swift_http::{
    body_too_large, normalize_etag, split_path, Body, Match, Request, Response, STREAM_CHUNK,
};

use crate::keymaster::KeyMaster;
use crate::{Middleware, NextFn};

/// Sysmeta header holding serialized body crypto-meta.
pub const BODY_META_HEADER: &str = "X-Object-Sysmeta-Crypto-Body-Meta";
/// Sysmeta header holding the encrypted plaintext etag.
pub const ETAG_HEADER: &str = "X-Object-Sysmeta-Crypto-Etag";
/// Sysmeta header holding HMAC(plaintext_etag) for conditional requests.
pub const ETAG_MAC_HEADER: &str = "X-Object-Sysmeta-Crypto-Etag-Mac";
/// Container-listing etag override (encrypted under the container key).
pub const OVERRIDE_ETAG_HEADER: &str = "X-Object-Sysmeta-Container-Update-Override-Etag";

const TRANSIENT_META_PREFIX: &str = "X-Object-Transient-Sysmeta-Crypto-Meta-";
const TRANSIENT_CRYPTO_META: &str = "X-Object-Transient-Sysmeta-Crypto-Meta";

/// Result of encrypting one object body (headers the caller stamps on the
/// PUT request + the ciphertext).
#[derive(Debug, Clone)]
pub struct EncryptedObject {
    pub ciphertext: Vec<u8>,
    pub plaintext_etag: String,
    pub ciphertext_etag: String,
    pub body_meta_header: String,
    pub crypto_etag_header: String,
    pub etag_mac_header: String,
    pub override_etag_header: String,
}

/// Encrypt `plaintext` under a body key wrapped by `object_key`.
///
/// `body_iv` / `body_key` / `wrap_iv` / `etag_iv` are caller-supplied so
/// unit tests can use known vectors; production passes
/// [`random_iv`] / [`random_key`].
///
/// Internally delegates to [`encrypt_object_body_from_reader`] so the
/// one-shot and streaming paths share the same CTR + dual-MD5 loop.
pub fn encrypt_object_body(
    object_key: &[u8; KEY_LENGTH],
    container_key: &[u8; KEY_LENGTH],
    key_id: &serde_json::Value,
    plaintext: &[u8],
    body_iv: [u8; IV_LENGTH],
    body_key: [u8; KEY_LENGTH],
    wrap_iv: [u8; IV_LENGTH],
    etag_iv: [u8; IV_LENGTH],
) -> Result<EncryptedObject, CryptoError> {
    match encrypt_object_body_from_reader(
        object_key,
        container_key,
        key_id,
        &mut std::io::Cursor::new(plaintext),
        Some(plaintext.len() as u64),
        MAX_FILE_SIZE as u64,
        body_iv,
        body_key,
        wrap_iv,
        etag_iv,
    ) {
        Ok(enc) => Ok(enc),
        Err(EncryptBodyError::Crypto(c)) => Err(c),
        // In-memory slice under MAX_FILE_SIZE cannot hit IO / cap errors.
        Err(EncryptBodyError::TooLarge | EncryptBodyError::Io(_)) => {
            unreachable!("encrypt_object_body: in-memory body under cap")
        }
    }
}

/// Errors from the chunked encrypt-while-read path.
#[derive(Debug)]
pub enum EncryptBodyError {
    /// Body exceeded the materialize/encrypt cap (map to 413).
    TooLarge,
    /// Underlying reader failed (map to 400).
    Io(std::io::Error),
    /// Crypto primitive failure (map to 500).
    Crypto(CryptoError),
}

impl From<CryptoError> for EncryptBodyError {
    fn from(e: CryptoError) -> Self {
        EncryptBodyError::Crypto(e)
    }
}

impl From<std::io::Error> for EncryptBodyError {
    fn from(e: std::io::Error) -> Self {
        if body_too_large(&e) {
            EncryptBodyError::TooLarge
        } else {
            EncryptBodyError::Io(e)
        }
    }
}

/// Chunked AES-256-CTR encrypt of a body reader (Python
/// `EncInputWrapper.chunk_update` loop).
///
/// Reads at most `cap` bytes in [`STREAM_CHUNK`] windows, encrypts each
/// window in place, and accumulates **ciphertext only**. Plaintext is
/// never retained beyond the current window — dual MD5 (plaintext +
/// ciphertext) advances per chunk so etags match the one-shot path.
///
/// Prefer [`encrypt_object_body_from_body`] when you already own a
/// [`Body`]: the buffered branch encrypts **in place** (one allocation).
///
/// # Residual
///
/// The returned [`EncryptedObject::ciphertext`] is still a full buffer
/// (`// P1-leftover: ciphertext still fully buffered (footer residual)`).
/// True end-to-end streaming needs proxy PUT footers so crypto sysmeta
/// can be stamped after the body stream (see module docs).
pub fn encrypt_object_body_from_reader(
    object_key: &[u8; KEY_LENGTH],
    container_key: &[u8; KEY_LENGTH],
    key_id: &serde_json::Value,
    reader: &mut dyn Read,
    declared_len: Option<u64>,
    cap: u64,
    body_iv: [u8; IV_LENGTH],
    body_key: [u8; KEY_LENGTH],
    wrap_iv: [u8; IV_LENGTH],
    etag_iv: [u8; IV_LENGTH],
) -> Result<EncryptedObject, EncryptBodyError> {
    if let Some(len) = declared_len {
        if len > cap {
            return Err(EncryptBodyError::TooLarge);
        }
    }

    let mut plaintext_md5 = Md5::new();
    let mut ciphertext_md5 = Md5::new();
    let mut ciphertext: Vec<u8> = match declared_len {
        Some(len) => Vec::with_capacity(len as usize),
        None => Vec::new(),
    };
    let mut ctxt = create_encryption_ctxt(&body_key, &body_iv)?;

    let mut buf = [0u8; STREAM_CHUNK];
    let mut total: u64 = 0;
    loop {
        let n = reader.read(&mut buf).map_err(EncryptBodyError::from)?;
        if n == 0 {
            break;
        }
        total = total.saturating_add(n as u64);
        if total > cap {
            return Err(EncryptBodyError::TooLarge);
        }
        let chunk = &mut buf[..n];
        plaintext_md5.update(&*chunk);
        ctxt.update_in_place(chunk);
        ciphertext_md5.update(&*chunk);
        ciphertext
            .try_reserve(n)
            .map_err(|e| EncryptBodyError::Io(std::io::Error::other(e)))?;
        ciphertext.extend_from_slice(chunk);
    }

    finish_encrypted_object(
        object_key,
        container_key,
        key_id,
        body_iv,
        body_key,
        wrap_iv,
        etag_iv,
        ciphertext,
        plaintext_md5,
        ciphertext_md5,
    )
}

/// Encrypt a [`Body`]: buffered bodies encrypt **in place** (peak ≈ body
/// size); streamed bodies encrypt-while-read into a ciphertext buffer
/// (peak ≈ body size + [`STREAM_CHUNK`]).
///
/// `// P1-leftover: ciphertext still fully buffered (footer residual)`.
pub fn encrypt_object_body_from_body(
    object_key: &[u8; KEY_LENGTH],
    container_key: &[u8; KEY_LENGTH],
    key_id: &serde_json::Value,
    body: Body,
    cap: u64,
    body_iv: [u8; IV_LENGTH],
    body_key: [u8; KEY_LENGTH],
    wrap_iv: [u8; IV_LENGTH],
    etag_iv: [u8; IV_LENGTH],
) -> Result<EncryptedObject, EncryptBodyError> {
    match body {
        Body::Buffered(mut plaintext) => {
            if plaintext.len() as u64 > cap {
                return Err(EncryptBodyError::TooLarge);
            }
            let mut ctxt = create_encryption_ctxt(&body_key, &body_iv)?;
            let mut plaintext_md5 = Md5::new();
            let mut ciphertext_md5 = Md5::new();
            // In-place CTR: MD5 plaintext, encrypt, MD5 ciphertext — all
            // per STREAM_CHUNK window without a second full allocation.
            for chunk in plaintext.chunks_mut(STREAM_CHUNK) {
                plaintext_md5.update(&*chunk);
                ctxt.update_in_place(chunk);
                ciphertext_md5.update(&*chunk);
            }
            finish_encrypted_object(
                object_key,
                container_key,
                key_id,
                body_iv,
                body_key,
                wrap_iv,
                etag_iv,
                plaintext, // now ciphertext
                plaintext_md5,
                ciphertext_md5,
            )
        }
        streamed @ Body::Streamed(_) => {
            let declared = streamed.content_length();
            let (mut reader, _) = streamed.into_reader();
            encrypt_object_body_from_reader(
                object_key,
                container_key,
                key_id,
                &mut reader,
                declared,
                cap,
                body_iv,
                body_key,
                wrap_iv,
                etag_iv,
            )
        }
    }
}

/// Wrap body key + stamp crypto-meta / etag headers after the CTR loop.
fn finish_encrypted_object(
    object_key: &[u8; KEY_LENGTH],
    container_key: &[u8; KEY_LENGTH],
    key_id: &serde_json::Value,
    body_iv: [u8; IV_LENGTH],
    body_key: [u8; KEY_LENGTH],
    wrap_iv: [u8; IV_LENGTH],
    etag_iv: [u8; IV_LENGTH],
    ciphertext: Vec<u8>,
    plaintext_md5: Md5,
    ciphertext_md5: Md5,
) -> Result<EncryptedObject, EncryptBodyError> {
    let wrapped = wrap_key(object_key, &body_key, wrap_iv)?;
    let plaintext_etag = format!("{:x}", plaintext_md5.finalize());
    let ciphertext_etag = format!("{:x}", ciphertext_md5.finalize());

    let body_meta = body_crypto_meta_json(&body_iv, &wrapped, key_id);
    let body_meta_header = dump_crypto_meta(&body_meta);

    let (enc_etag, etag_meta) =
        encrypt_value_with_meta(object_key, etag_iv, plaintext_etag.as_bytes())?;
    let crypto_etag_header = append_crypto_meta(&enc_etag, &etag_meta);

    let etag_mac_header = hmac_etag(object_key, &plaintext_etag);

    // Fresh IV for the listing etag (reuse wrap_iv only when tests force it).
    let (enc_listing, mut listing_meta) =
        encrypt_value_with_meta(container_key, wrap_iv, plaintext_etag.as_bytes())?;
    if let Some(obj) = listing_meta.as_object_mut() {
        obj.insert("key_id".into(), key_id.clone());
    }
    let override_etag_header = append_crypto_meta(&enc_listing, &listing_meta);

    Ok(EncryptedObject {
        ciphertext,
        plaintext_etag,
        ciphertext_etag,
        body_meta_header,
        crypto_etag_header,
        etag_mac_header,
        override_etag_header,
    })
}

fn body_crypto_meta_json(
    body_iv: &[u8; IV_LENGTH],
    wrapped: &WrappedKey,
    key_id: &serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "cipher": CIPHER,
        "iv": B64.encode(body_iv),
        "body_key": {
            "key": B64.encode(&wrapped.key),
            "iv": B64.encode(wrapped.iv),
        },
        "key_id": key_id,
    })
}

fn encrypt_value_with_meta(
    key: &[u8],
    iv: [u8; IV_LENGTH],
    value: &[u8],
) -> Result<(String, serde_json::Value), CryptoError> {
    let enc = encrypt_header_value(key, &iv, value)?;
    let meta = serde_json::json!({
        "cipher": CIPHER,
        "iv": B64.encode(iv),
    });
    Ok((enc, meta))
}

#[cfg(test)]
fn md5_hex(data: &[u8]) -> String {
    let mut h = Md5::new();
    h.update(data);
    format!("{:x}", h.finalize())
}

/// Cryptographically random IV (`os.urandom(16)`).
pub fn random_iv() -> [u8; IV_LENGTH] {
    let mut buf = [0u8; IV_LENGTH];
    fill_random(&mut buf);
    buf
}

/// Cryptographically random AES-256 key (`os.urandom(32)`).
pub fn random_key() -> [u8; KEY_LENGTH] {
    let mut buf = [0u8; KEY_LENGTH];
    fill_random(&mut buf);
    buf
}

fn fill_random(buf: &mut [u8]) {
    use std::fs::File;
    use std::io::Read as _;
    let mut f = File::open("/dev/urandom").expect("/dev/urandom");
    f.read_exact(buf).expect("urandom read");
}

/// At-rest encryption middleware.
pub struct Encrypter {
    pub keymaster: Arc<KeyMaster>,
    /// When true, skip encrypting new PUT/POST data (Python
    /// `disable_encryption`). Middleware stays in the pipeline so GETs of
    /// already-encrypted objects still work via decrypter.
    pub disable_encryption: bool,
}

impl Encrypter {
    pub fn new(keymaster: Arc<KeyMaster>, disable_encryption: bool) -> Self {
        Encrypter {
            keymaster,
            disable_encryption,
        }
    }

    pub fn from_conf(keymaster: Arc<KeyMaster>, disable_encryption: Option<&str>) -> Self {
        Encrypter {
            keymaster,
            disable_encryption: disable_encryption.map(config_true_value).unwrap_or(false),
        }
    }
}

impl Middleware for Encrypter {
    fn handle(&self, req: Request, next: &NextFn) -> Response {
        if config_true_value(req.headers.get("Swift-Crypto-Override").unwrap_or("")) {
            return next(req);
        }

        let parts = match split_path(&req.path, 4, 4, true) {
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
        let container = match parts[2].as_deref().filter(|s| !s.is_empty()) {
            Some(c) => c.to_string(),
            None => return next(req),
        };
        let object = match parts[3].as_deref().filter(|s| !s.is_empty()) {
            Some(o) => o.to_string(),
            None => return next(req),
        };

        if self.disable_encryption && matches!(req.method.as_str(), "PUT" | "POST") {
            return next(req);
        }

        match req.method.as_str() {
            "PUT" => self.handle_put(req, next, &account, &container, &object),
            "POST" => self.handle_post(req, next, &account, &container, &object),
            "GET" | "HEAD" => self.handle_get_or_head(req, next, &account, &container, &object),
            _ => next(req),
        }
    }
}

impl Encrypter {
    fn handle_put(
        &self,
        mut req: Request,
        next: &NextFn,
        account: &str,
        container: &str,
        object: &str,
    ) -> Response {
        let keys = self
            .keymaster
            .fetch_keys(account, Some(container), Some(object));
        let (Some(object_key), Some(container_key)) = (keys.object, keys.container) else {
            return Response::error(500, "Unable to retrieve encryption keys.");
        };

        encrypt_user_metadata(&mut req, &object_key, &keys.id);

        // Chunked encrypt-while-read (Python EncInputWrapper.chunk_update).
        // Buffered bodies encrypt in place; streamed bodies keep only a
        // STREAM_CHUNK plaintext window. Ciphertext is still fully buffered
        // so etag/crypto sysmeta can be stamped as request headers before
        // the proxy opens backend connections.
        // P1-leftover: ciphertext still fully buffered (footer residual).
        let client_etag = req
            .headers
            .remove("Etag")
            .or_else(|| req.headers.remove("ETag"));

        let enc = match encrypt_object_body_from_body(
            &object_key,
            &container_key,
            &keys.id,
            req.body.take(),
            MAX_FILE_SIZE as u64,
            random_iv(),
            random_key(),
            random_iv(),
            random_iv(),
        ) {
            Ok(e) => e,
            Err(EncryptBodyError::TooLarge) => {
                return Response::error(413, "Request Entity Too Large");
            }
            Err(EncryptBodyError::Io(_)) => {
                return Response::error(400, "Error reading request body");
            }
            Err(EncryptBodyError::Crypto(_)) => {
                return Response::error(500, "Error encrypting object");
            }
        };

        if let Some(ref etag) = client_etag {
            let norm = normalize_etag(etag);
            if !norm.is_empty() && norm != enc.plaintext_etag {
                return Response::error(422, "Etag Mismatch");
            }
        }

        req.headers.set(BODY_META_HEADER, &enc.body_meta_header);
        req.headers.set(ETAG_HEADER, &enc.crypto_etag_header);
        req.headers.set(ETAG_MAC_HEADER, &enc.etag_mac_header);
        req.headers
            .set(OVERRIDE_ETAG_HEADER, &enc.override_etag_header);
        // Ciphertext etag travels as the object Etag so the object server
        // stores / validates against the on-disk bytes.
        req.headers.set("Etag", &enc.ciphertext_etag);
        req.headers.set("Content-Length", enc.ciphertext.len());
        req.body = Body::from(enc.ciphertext);

        let mut resp = next(req);

        // On success, surface the plaintext etag to the client.
        if (200..300).contains(&resp.status) {
            if let Some(resp_etag) = resp.headers.get("Etag").map(|s| s.to_string()) {
                if normalize_etag(&resp_etag) == enc.ciphertext_etag {
                    resp.headers.set("Etag", &enc.plaintext_etag);
                }
            } else {
                resp.headers.set("Etag", &enc.plaintext_etag);
            }
        }
        resp
    }

    fn handle_post(
        &self,
        mut req: Request,
        next: &NextFn,
        account: &str,
        container: &str,
        object: &str,
    ) -> Response {
        let keys = self
            .keymaster
            .fetch_keys(account, Some(container), Some(object));
        let Some(object_key) = keys.object else {
            return Response::error(500, "Unable to retrieve encryption keys.");
        };
        encrypt_user_metadata(&mut req, &object_key, &keys.id);
        next(req)
    }

    /// Python `EncrypterObjContext.handle_get_or_head`: mask conditional etag
    /// headers with HMAC values so the object server can match against
    /// `X-Object-Sysmeta-Crypto-Etag-Mac`.
    fn handle_get_or_head(
        &self,
        mut req: Request,
        next: &NextFn,
        account: &str,
        container: &str,
        object: &str,
    ) -> Response {
        let object_keys = self
            .keymaster
            .fetch_all_object_keys(account, container, object);
        if object_keys.is_empty() {
            return next(req);
        }
        let masked1 = mask_conditional_etags(&mut req, "If-Match", &object_keys);
        let masked2 = mask_conditional_etags(&mut req, "If-None-Match", &object_keys);
        if masked1 || masked2 {
            update_etag_is_at_header(&mut req, ETAG_MAC_HEADER);
        }
        next(req)
    }
}

/// Python `_mask_conditional_etags`: keep the original etag tags (unencrypted
/// objects still match) and append HMAC(object_key, etag) for every root
/// secret. Returns true when any masking was applied.
pub fn mask_conditional_etags(
    req: &mut Request,
    header_name: &str,
    object_keys: &[[u8; KEY_LENGTH]],
) -> bool {
    let Some(old) = req.headers.get(header_name).map(|s| s.to_string()) else {
        return false;
    };
    if old.is_empty() {
        return false;
    }
    let tags = Match::parse(&old).tags;
    if tags.is_empty() {
        return false;
    }
    let mut new_etags: Vec<String> = Vec::new();
    let mut masked = false;
    for etag in tags {
        if etag == "*" {
            new_etags.push(etag);
            continue;
        }
        new_etags.push(format!("\"{etag}\""));
        for key in object_keys {
            let mac = hmac_etag(key, &etag);
            new_etags.push(format!("\"{mac}\""));
        }
        masked = true;
    }
    if masked {
        req.headers.set(header_name, new_etags.join(", "));
    }
    masked
}

/// Python `update_etag_is_at_header` / `csv_append`.
fn update_etag_is_at_header(req: &mut Request, name: &str) {
    let existing = req
        .headers
        .get("X-Backend-Etag-Is-At")
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    let value = match existing {
        Some(e) => format!("{e},{name}"),
        None => name.to_string(),
    };
    req.headers.set("X-Backend-Etag-Is-At", value);
}

fn encrypt_user_metadata(
    req: &mut Request,
    object_key: &[u8; KEY_LENGTH],
    key_id: &serde_json::Value,
) {
    let user_metas: Vec<(String, String)> = req
        .headers
        .iter()
        .filter(|(k, v)| k.to_ascii_lowercase().starts_with("x-object-meta-") && !v.is_empty())
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    let mut any = false;
    let mut last_cipher: Option<String> = None;
    for (name, val) in user_metas {
        // Strip the "X-Object-Meta-" prefix case-insensitively.
        let lower = name.to_ascii_lowercase();
        let short = name
            .get("x-object-meta-".len()..)
            .or_else(|| {
                lower
                    .strip_prefix("x-object-meta-")
                    .map(|_| &name["x-object-meta-".len()..])
            })
            .unwrap_or(name.as_str());
        // Prefer original casing after the fixed-length prefix when present.
        let short = if name.len() > "X-Object-Meta-".len()
            && name[.."X-Object-Meta-".len()].eq_ignore_ascii_case("X-Object-Meta-")
        {
            &name["X-Object-Meta-".len()..]
        } else {
            short
        };

        let iv = random_iv();
        if let Ok((enc, meta)) = encrypt_value_with_meta(object_key, iv, val.as_bytes()) {
            let new_name = format!("{TRANSIENT_META_PREFIX}{short}");
            req.headers.set(&new_name, append_crypto_meta(&enc, &meta));
            req.headers.remove(&name);
            last_cipher = meta
                .get("cipher")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            any = true;
        }
    }
    if any {
        let common = serde_json::json!({
            "cipher": last_cipher.unwrap_or_else(|| CIPHER.to_string()),
            "key_id": key_id,
        });
        req.headers
            .set(TRANSIENT_CRYPTO_META, dump_crypto_meta(&common));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decrypter::{decrypt_object_body, Decrypter};
    use crate::keymaster::KeyMaster;
    use std::sync::Arc;
    use swift_http::HeaderKeyDict;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn root_km() -> Arc<KeyMaster> {
        let root = unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        Arc::new(KeyMaster::new(root).unwrap())
    }

    #[test]
    fn body_encrypt_decrypt_roundtrip_known_ivs() {
        let km = root_km();
        let keys = km.fetch_keys("acct", Some("cont"), Some("obj"));
        let object_key = keys.object.unwrap();
        let container_key = keys.container.unwrap();
        let plaintext = b"The quick brown fox jumps over the lazy dog. 1234567890!";

        let body_iv = {
            let mut iv = [0u8; IV_LENGTH];
            iv[15] = 0xff;
            iv
        };
        let body_key: [u8; KEY_LENGTH] = {
            let v = unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
            v.try_into().unwrap()
        };
        let wrap_iv = [0x22u8; IV_LENGTH];
        let etag_iv = [0x33u8; IV_LENGTH];

        let enc = encrypt_object_body(
            &object_key,
            &container_key,
            &keys.id,
            plaintext,
            body_iv,
            body_key,
            wrap_iv,
            etag_iv,
        )
        .unwrap();

        // Ciphertext must match swift-crypto python-derived vector when using
        // the same key/iv/pt as that crate's PY_* constants.
        // Here object_key != PY_KEY, so just check roundtrip via body meta.
        let recovered = decrypt_object_body(&object_key, &enc.body_meta_header, 0, &enc.ciphertext)
            .expect("decrypt");
        assert_eq!(recovered, plaintext);
        assert_eq!(enc.plaintext_etag, md5_hex(plaintext));
        assert_eq!(enc.ciphertext_etag, md5_hex(&enc.ciphertext));
        assert!(!enc.crypto_etag_header.is_empty());
        assert!(!enc.etag_mac_header.is_empty());
    }

    /// In-place buffered encrypt must match the reader path for the same IVs.
    #[test]
    fn buffered_in_place_matches_reader_path() {
        let km = root_km();
        let keys = km.fetch_keys("acct", Some("cont"), Some("obj"));
        let object_key = keys.object.unwrap();
        let container_key = keys.container.unwrap();
        let plaintext: Vec<u8> = (0..STREAM_CHUNK + 3).map(|i| (i % 200) as u8).collect();
        let body_iv = [0x55u8; IV_LENGTH];
        let body_key = [0x66u8; KEY_LENGTH];
        let wrap_iv = [0x77u8; IV_LENGTH];
        let etag_iv = [0x88u8; IV_LENGTH];

        let from_body = encrypt_object_body_from_body(
            &object_key,
            &container_key,
            &keys.id,
            Body::from(plaintext.clone()),
            MAX_FILE_SIZE as u64,
            body_iv,
            body_key,
            wrap_iv,
            etag_iv,
        )
        .unwrap();
        let from_reader = encrypt_object_body_from_reader(
            &object_key,
            &container_key,
            &keys.id,
            &mut std::io::Cursor::new(&plaintext),
            Some(plaintext.len() as u64),
            MAX_FILE_SIZE as u64,
            body_iv,
            body_key,
            wrap_iv,
            etag_iv,
        )
        .unwrap();
        assert_eq!(from_body.ciphertext, from_reader.ciphertext);
        assert_eq!(from_body.plaintext_etag, from_reader.plaintext_etag);
        assert_eq!(from_body.ciphertext_etag, from_reader.ciphertext_etag);
        assert_eq!(from_body.body_meta_header, from_reader.body_meta_header);
    }

    /// Chunked encrypt-while-read must byte-match one-shot for the same IVs,
    /// including bodies larger than STREAM_CHUNK (multi-window path).
    #[test]
    fn chunked_encrypt_matches_oneshot_across_stream_chunks() {
        let km = root_km();
        let keys = km.fetch_keys("acct", Some("cont"), Some("obj"));
        let object_key = keys.object.unwrap();
        let container_key = keys.container.unwrap();

        // 3 * STREAM_CHUNK + 17 → exercises several full windows + a tail.
        let mut plaintext = vec![0u8; STREAM_CHUNK * 3 + 17];
        for (i, b) in plaintext.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }

        let body_iv = [0x11u8; IV_LENGTH];
        let body_key = [0x22u8; KEY_LENGTH];
        let wrap_iv = [0x33u8; IV_LENGTH];
        let etag_iv = [0x44u8; IV_LENGTH];

        let oneshot = encrypt_object_body(
            &object_key,
            &container_key,
            &keys.id,
            &plaintext,
            body_iv,
            body_key,
            wrap_iv,
            etag_iv,
        )
        .unwrap();

        // Feed the reader in small non-aligned reads to stress the loop.
        struct PieceReader<'a> {
            data: &'a [u8],
            pos: usize,
            piece: usize,
        }
        impl Read for PieceReader<'_> {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.pos >= self.data.len() {
                    return Ok(0);
                }
                let n = self.piece.min(self.data.len() - self.pos).min(buf.len());
                buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
                self.pos += n;
                Ok(n)
            }
        }
        let mut reader = PieceReader {
            data: &plaintext,
            pos: 0,
            piece: 1000, // not STREAM_CHUNK-aligned
        };
        let chunked = encrypt_object_body_from_reader(
            &object_key,
            &container_key,
            &keys.id,
            &mut reader,
            Some(plaintext.len() as u64),
            MAX_FILE_SIZE as u64,
            body_iv,
            body_key,
            wrap_iv,
            etag_iv,
        )
        .unwrap();

        assert_eq!(chunked.ciphertext, oneshot.ciphertext);
        assert_eq!(chunked.plaintext_etag, oneshot.plaintext_etag);
        assert_eq!(chunked.ciphertext_etag, oneshot.ciphertext_etag);
        assert_eq!(chunked.body_meta_header, oneshot.body_meta_header);
        assert_eq!(chunked.crypto_etag_header, oneshot.crypto_etag_header);
        assert_eq!(chunked.etag_mac_header, oneshot.etag_mac_header);
        assert_eq!(chunked.override_etag_header, oneshot.override_etag_header);

        let recovered = decrypt_object_body(
            &object_key,
            &chunked.body_meta_header,
            0,
            &chunked.ciphertext,
        )
        .expect("decrypt");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn chunked_encrypt_respects_cap() {
        let km = root_km();
        let keys = km.fetch_keys("a", Some("c"), Some("o"));
        let object_key = keys.object.unwrap();
        let container_key = keys.container.unwrap();
        let data = vec![7u8; 100];
        let err = encrypt_object_body_from_reader(
            &object_key,
            &container_key,
            &keys.id,
            &mut std::io::Cursor::new(&data),
            Some(data.len() as u64),
            50, // cap below body
            [0u8; IV_LENGTH],
            [1u8; KEY_LENGTH],
            [2u8; IV_LENGTH],
            [3u8; IV_LENGTH],
        )
        .unwrap_err();
        assert!(matches!(err, EncryptBodyError::TooLarge));
    }

    #[allow(clippy::type_complexity)]
    fn put_get_pipeline(
        km: Arc<KeyMaster>,
    ) -> (
        Arc<dyn Fn(Request) -> Response + Send + Sync>,
        Arc<std::sync::Mutex<Option<(HeaderKeyDict, Vec<u8>)>>>,
    ) {
        let encrypter = Encrypter::new(Arc::clone(&km), false);
        let decrypter = Decrypter::new(Arc::clone(&km));
        let store: Arc<std::sync::Mutex<Option<(HeaderKeyDict, Vec<u8>)>>> =
            Arc::new(std::sync::Mutex::new(None));
        let store_w = Arc::clone(&store);
        let app: NextFn = Arc::new(move |req: Request| {
            if req.method == "PUT" {
                let body = match &req.body {
                    Body::Buffered(b) => b.clone(),
                    Body::Streamed(_) => {
                        // Encrypter always re-buffers ciphertext for header
                        // stamp (footer residual); treat empty as bug.
                        Vec::new()
                    }
                };
                let etag = req.headers.get("Etag").unwrap_or("").to_string();
                *store_w.lock().unwrap() = Some((req.headers.clone(), body.clone()));
                let mut resp = Response::with_body(201, "");
                resp.headers.set("Etag", etag);
                resp
            } else {
                let guard = store_w.lock().unwrap();
                let (headers, body) = guard.as_ref().unwrap();
                let mut resp = Response::with_body(200, body.clone());
                for (k, v) in headers.iter() {
                    let kl = k.to_lowercase();
                    if kl.starts_with("x-object-sysmeta-")
                        || kl.starts_with("x-object-transient-sysmeta-")
                        || kl == "etag"
                        || kl == "content-type"
                    {
                        resp.headers.set(k, v);
                    }
                }
                resp
            }
        });
        let pipeline = crate::build_pipeline(
            vec![
                Arc::new(decrypter) as Arc<dyn Middleware>,
                Arc::new(encrypter) as Arc<dyn Middleware>,
            ],
            app,
        );
        (pipeline, store)
    }

    #[test]
    fn middleware_put_get_roundtrip() {
        let km = root_km();
        let (pipeline, store) = put_get_pipeline(Arc::clone(&km));

        let plaintext = b"hello encrypted world";
        let put = Request {
            method: "PUT".into(),
            path: "/v1/AUTH_test/c1/o1".into(),
            query_string: String::new(),
            headers: {
                let mut h = HeaderKeyDict::new();
                h.set("Content-Type", "text/plain");
                h.set("X-Object-Meta-Color", "blue");
                h
            },
            body: Body::from(plaintext.as_slice()),
        };
        let put_resp = pipeline(put);
        assert_eq!(put_resp.status, 201, "put failed");
        let expected_etag = md5_hex(plaintext);
        assert_eq!(
            put_resp.headers.get("Etag").map(normalize_etag),
            Some(expected_etag.as_str())
        );

        // Backend must have seen ciphertext, not plaintext.
        {
            let guard = store.lock().unwrap();
            let (hdrs, body) = guard.as_ref().unwrap();
            assert_ne!(body.as_slice(), plaintext);
            assert!(hdrs.get(BODY_META_HEADER).is_some());
            assert!(hdrs.get(ETAG_HEADER).is_some());
            // user meta moved to transient sysmeta
            assert!(hdrs.get("X-Object-Meta-Color").is_none());
            assert!(hdrs.iter().any(|(k, _)| k
                .to_ascii_lowercase()
                .starts_with("x-object-transient-sysmeta-crypto-meta-color")));
        }

        let get = Request {
            method: "GET".into(),
            path: "/v1/AUTH_test/c1/o1".into(),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: Body::empty(),
        };
        let mut get_resp = pipeline(get);
        assert_eq!(get_resp.status, 200);
        let got = get_resp
            .body
            .materialize(MAX_FILE_SIZE as u64)
            .expect("materialize get body")
            .to_vec();
        assert_eq!(got, plaintext);
        assert_eq!(
            get_resp.headers.get("Etag").map(normalize_etag),
            Some(expected_etag.as_str())
        );
        assert_eq!(get_resp.headers.get("X-Object-Meta-Color"), Some("blue"));
        // crypto sysmeta stripped from client response
        assert!(get_resp.headers.get(BODY_META_HEADER).is_none());
    }

    /// PUT body arrives as a stream (chunked / unknown length): encrypter
    /// must still encrypt-while-read without requiring a pre-buffered body.
    #[test]
    fn middleware_put_streamed_body_roundtrip() {
        let km = root_km();
        let (pipeline, store) = put_get_pipeline(Arc::clone(&km));

        let plaintext: Vec<u8> = (0..STREAM_CHUNK + 99).map(|i| (i % 256) as u8).collect();
        let put = Request {
            method: "PUT".into(),
            path: "/v1/AUTH_test/c1/o_stream".into(),
            query_string: String::new(),
            headers: {
                let mut h = HeaderKeyDict::new();
                h.set("Content-Type", "application/octet-stream");
                h
            },
            // No declared Content-Length — forces the unknown-length branch.
            body: Body::from_reader(Box::new(std::io::Cursor::new(plaintext.clone())), None),
        };
        let put_resp = pipeline(put);
        assert_eq!(put_resp.status, 201, "streamed put failed");
        let expected_etag = md5_hex(&plaintext);
        assert_eq!(
            put_resp.headers.get("Etag").map(normalize_etag),
            Some(expected_etag.as_str())
        );

        {
            let guard = store.lock().unwrap();
            let (hdrs, body) = guard.as_ref().unwrap();
            assert_ne!(body.as_slice(), plaintext.as_slice());
            assert_eq!(body.len(), plaintext.len()); // CTR length-preserving
            assert!(hdrs.get(BODY_META_HEADER).is_some());
            assert_eq!(
                hdrs.get("Content-Length").and_then(|s| s.parse().ok()),
                Some(plaintext.len())
            );
        }

        let get = Request {
            method: "GET".into(),
            path: "/v1/AUTH_test/c1/o_stream".into(),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: Body::empty(),
        };
        let mut get_resp = pipeline(get);
        assert_eq!(get_resp.status, 200);
        let got = get_resp
            .body
            .materialize(MAX_FILE_SIZE as u64)
            .expect("materialize")
            .to_vec();
        assert_eq!(got, plaintext);
    }

    #[test]
    fn middleware_put_client_etag_mismatch() {
        let km = root_km();
        let enc = Encrypter::new(km, false);
        let app: NextFn = Arc::new(|_req: Request| Response::new(201));
        let req = Request {
            method: "PUT".into(),
            path: "/v1/a/c/o".into(),
            query_string: String::new(),
            headers: {
                let mut h = HeaderKeyDict::new();
                h.set("Etag", "00000000000000000000000000000000");
                h
            },
            body: Body::from(&b"not-matching"[..]),
        };
        assert_eq!(enc.handle(req, &app).status, 422);
    }

    #[test]
    fn middleware_put_crypto_override_header_skips() {
        let km = root_km();
        let enc = Encrypter::new(km, false);
        let app: NextFn = Arc::new(|req: Request| {
            let body = match &req.body {
                Body::Buffered(b) => b.clone(),
                _ => Vec::new(),
            };
            assert_eq!(body, b"plain");
            assert!(req.headers.get(BODY_META_HEADER).is_none());
            Response::new(201)
        });
        let req = Request {
            method: "PUT".into(),
            path: "/v1/a/c/o".into(),
            query_string: String::new(),
            headers: {
                let mut h = HeaderKeyDict::new();
                h.set("Swift-Crypto-Override", "true");
                h
            },
            body: Body::from(&b"plain"[..]),
        };
        assert_eq!(enc.handle(req, &app).status, 201);
    }

    #[test]
    fn disable_encryption_skips_put() {
        let km = root_km();
        let enc = Encrypter::new(km, true);
        let app: NextFn = Arc::new(|req: Request| {
            let body = match &req.body {
                Body::Buffered(b) => b.clone(),
                _ => Vec::new(),
            };
            // body should still be plaintext
            assert_eq!(body, b"plain");
            assert!(req.headers.get(BODY_META_HEADER).is_none());
            Response::new(201)
        });
        let req = Request {
            method: "PUT".into(),
            path: "/v1/a/c/o".into(),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: Body::from(&b"plain"[..]),
        };
        let resp = enc.handle(req, &app);
        assert_eq!(resp.status, 201);
    }

    #[test]
    fn mask_conditional_etags_appends_hmac_all_secrets() {
        let root_a = unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let root_b = vec![0xffu8; 32];
        let items = vec![
            ("encryption_root_secret".into(), B64.encode(&root_a)),
            ("encryption_root_secret_old".into(), B64.encode(&root_b)),
        ];
        let km = Arc::new(KeyMaster::from_conf_items(&items).unwrap());
        let keys = km.fetch_all_object_keys("a", "c", "o");
        assert_eq!(keys.len(), 2);

        let plaintext_etag = "d41d8cd98f00b204e9800998ecf8427e";
        let mut req = Request {
            method: "GET".into(),
            path: "/v1/a/c/o".into(),
            query_string: String::new(),
            headers: {
                let mut h = HeaderKeyDict::new();
                h.set("If-None-Match", format!("\"{plaintext_etag}\""));
                h
            },
            body: Body::empty(),
        };
        assert!(mask_conditional_etags(&mut req, "If-None-Match", &keys));
        let val = req.headers.get("If-None-Match").unwrap();
        // Original plaintext etag preserved (unencrypted objects).
        assert!(val.contains(plaintext_etag), "{val}");
        for k in &keys {
            let mac = hmac_etag(k, plaintext_etag);
            assert!(val.contains(&mac), "missing hmac {mac} in {val}");
        }
        // Wildcard alone is not "masked" into HMACs.
        let mut star = Request {
            method: "GET".into(),
            path: "/v1/a/c/o".into(),
            query_string: String::new(),
            headers: {
                let mut h = HeaderKeyDict::new();
                h.set("If-Match", "*");
                h
            },
            body: Body::empty(),
        };
        assert!(!mask_conditional_etags(&mut star, "If-Match", &keys));
        assert_eq!(star.headers.get("If-Match"), Some("*"));
    }

    #[test]
    fn middleware_get_masks_and_sets_etag_is_at() {
        let km = root_km();
        let enc = Encrypter::new(Arc::clone(&km), false);
        let plaintext_etag = "abc123deadbeef";
        let expected_mac = {
            let keys = km.fetch_keys("a", Some("c"), Some("o"));
            hmac_etag(&keys.object.unwrap(), plaintext_etag)
        };
        let app: NextFn = Arc::new(move |req: Request| {
            let inm = req.headers.get("If-None-Match").unwrap_or("").to_string();
            assert!(inm.contains(plaintext_etag), "{inm}");
            assert!(inm.contains(&expected_mac), "{inm}");
            assert_eq!(
                req.headers.get("X-Backend-Etag-Is-At"),
                Some(ETAG_MAC_HEADER)
            );
            Response::new(200)
        });
        let req = Request {
            method: "GET".into(),
            path: "/v1/a/c/o".into(),
            query_string: String::new(),
            headers: {
                let mut h = HeaderKeyDict::new();
                h.set("If-None-Match", format!("\"{plaintext_etag}\""));
                h
            },
            body: Body::empty(),
        };
        assert_eq!(enc.handle(req, &app).status, 200);
    }
}
