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

//! Crypto-meta serialization + the etag HMAC, ported from
//! `swift/common/middleware/crypto/crypto_utils.py` and `encrypter.py`.
//!
//! Crypto-meta (the per-value IV / cipher / wrapped-key info stored alongside
//! an encrypted object) is serialized as
//! `quote_plus(json.dumps(meta, sort_keys=True))` with the `iv`/`key` fields
//! base64-encoded, and appended to a value as `"<value>; swift_meta=<meta>"`.
//! Because this travels between a Python proxy and a Rust proxy it must be
//! byte-identical, so the JSON is emitted with Python's `, `/`: ` separators,
//! `ensure_ascii`, and sorted keys.
//!
//! Here the crypto-meta is modelled as a `serde_json::Value` in which `iv`/
//! `key` are already base64 *strings* (the on-wire form); serializing them
//! directly yields the same bytes Python produces from its `bytes` values.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

type HmacSha256 = Hmac<Sha256>;

/// `dump_crypto_meta`: serialize a crypto-meta dict to a header-safe string.
pub fn dump_crypto_meta(crypto_meta: &serde_json::Value) -> String {
    quote_plus(&py_json_dumps_sorted(crypto_meta))
}

/// `load_crypto_meta`: parse a crypto-meta string back into a JSON value. The
/// `iv`/`key` fields are left as base64 strings (decode them when needed).
pub fn load_crypto_meta(value: &str) -> Result<serde_json::Value, String> {
    let json = unquote_plus(value);
    let v: serde_json::Value =
        serde_json::from_str(&json).map_err(|e| format!("Bad crypto meta: {e}"))?;
    if !v.is_object() {
        return Err("crypto meta not a Mapping".to_string());
    }
    Ok(v)
}

/// `append_crypto_meta`: `"<value>; swift_meta=<serialized crypto meta>"`.
pub fn append_crypto_meta(value: &str, crypto_meta: &serde_json::Value) -> String {
    format!("{value}; swift_meta={}", dump_crypto_meta(crypto_meta))
}

/// `extract_crypto_meta`: split a value that may carry a trailing
/// `; swift_meta=...` parameter, returning `(value, Some(meta))` or
/// `(value, None)`.
pub fn extract_crypto_meta(value: &str) -> (String, Option<serde_json::Value>) {
    // parse_header: the value up to the first ';' then ';'-separated params
    let mut parts = value.split(';');
    let base = parts.next().unwrap_or("").trim().to_string();
    for param in parts {
        let param = param.trim();
        if let Some(rest) = param.strip_prefix("swift_meta=") {
            if let Ok(meta) = load_crypto_meta(rest) {
                return (base, Some(meta));
            }
        }
    }
    (base, None)
}

/// `_hmac_etag`: base64(HMAC-SHA256(key, etag)).
pub fn hmac_etag(key: &[u8], etag: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(etag.as_bytes());
    B64.encode(mac.finalize().into_bytes())
}

/// Serialize a JSON value the way Python `json.dumps(sort_keys=True)` does:
/// `, `/`: ` separators, sorted object keys, and `ensure_ascii` escaping.
pub fn py_json_dumps_sorted(v: &serde_json::Value) -> String {
    let mut out = String::new();
    write_value(v, &mut out);
    out
}

fn write_value(v: &serde_json::Value, out: &mut String) {
    match v {
        serde_json::Value::Null => out.push_str("null"),
        serde_json::Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        serde_json::Value::Number(n) => out.push_str(&n.to_string()),
        serde_json::Value::String(s) => escape_ascii(s, out),
        serde_json::Value::Array(a) => {
            out.push('[');
            for (i, item) in a.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_value(item, out);
            }
            out.push(']');
        }
        serde_json::Value::Object(m) => {
            out.push('{');
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                escape_ascii(k, out);
                out.push_str(": ");
                write_value(&m[*k], out);
            }
            out.push('}');
        }
    }
}

/// Python `json.dumps` `ensure_ascii` string escaping.
fn escape_ascii(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c if (c as u32) < 0x7f => out.push(c),
            c => {
                // non-ASCII: \uXXXX (surrogate pair for astral code points)
                let cp = c as u32;
                if cp <= 0xffff {
                    out.push_str(&format!("\\u{cp:04x}"));
                } else {
                    let v = cp - 0x10000;
                    let hi = 0xd800 + (v >> 10);
                    let lo = 0xdc00 + (v & 0x3ff);
                    out.push_str(&format!("\\u{hi:04x}\\u{lo:04x}"));
                }
            }
        }
    }
    out.push('"');
}

/// `urllib.parse.quote_plus` with the default safe set: keep
/// `A-Za-z0-9_.-~`, encode space as `+`, everything else `%XX`.
fn quote_plus(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            b => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// `urllib.parse.unquote_plus`: `+` -> space, `%XX` -> byte.
fn unquote_plus(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                if let (Some(h), Some(l)) = (
                    (bytes[i + 1] as char).to_digit(16),
                    (bytes[i + 2] as char).to_digit(16),
                ) {
                    out.push((h * 16 + l) as u8);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_json_dumps_sorted_matches_python() {
        // Python json.dumps({...}, sort_keys=True): sorted keys, ", "/": "
        let v = json!({"cipher": "AES_CTR_256", "b": 2, "a": [1, 2]});
        assert_eq!(
            py_json_dumps_sorted(&v),
            "{\"a\": [1, 2], \"b\": 2, \"cipher\": \"AES_CTR_256\"}"
        );
    }

    #[test]
    fn test_dump_load_roundtrip() {
        let meta = json!({"cipher": "AES_CTR_256", "iv": "AAAAAAAAAAAAAAAAAAAAAA=="});
        let dumped = dump_crypto_meta(&meta);
        // quote_plus escapes the JSON punctuation
        assert!(dumped.contains("%7B") || dumped.contains("%22")); // { or "
        let loaded = load_crypto_meta(&dumped).unwrap();
        assert_eq!(loaded, meta);
    }

    #[test]
    fn test_append_extract() {
        let meta = json!({"cipher": "AES_CTR_256", "iv": "AAAA"});
        let appended = append_crypto_meta("ciphertext", &meta);
        assert!(appended.starts_with("ciphertext; swift_meta="));
        let (value, extracted) = extract_crypto_meta(&appended);
        assert_eq!(value, "ciphertext");
        assert_eq!(extracted, Some(meta));
        // a value without crypto meta
        let (v2, m2) = extract_crypto_meta("plainvalue");
        assert_eq!(v2, "plainvalue");
        assert!(m2.is_none());
    }

    #[test]
    fn test_quote_plus_roundtrip() {
        let s = "{\"a\": 1, \"b\": \"x/y\"}";
        assert_eq!(unquote_plus(&quote_plus(s)), s);
    }
}
