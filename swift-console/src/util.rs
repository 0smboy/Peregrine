//! Small dependency-free helpers: escaping, encoding, formatting.

/// HTML-escape a string for safe embedding in element content or attributes.
pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

/// Percent-encode a single path segment (also encodes '/').
pub fn enc_seg(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        if is_unreserved(b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

/// Percent-encode an object path, preserving '/' separators.
pub fn enc_obj(s: &str) -> String {
    s.split('/').map(enc_seg).collect::<Vec<_>>().join("/")
}

/// Percent-encode a query value.
pub fn enc_q(s: &str) -> String {
    enc_seg(s)
}

/// Minimal base64 (standard alphabet, padded) for the Basic auth header.
pub fn b64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    out
}

/// Human-readable byte size.
pub fn fmt_bytes(n: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    if n < 1024 {
        return format!("{} B", n);
    }
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if v >= 100.0 {
        format!("{:.0} {}", v, UNITS[i])
    } else if v >= 10.0 {
        format!("{:.1} {}", v, UNITS[i])
    } else {
        format!("{:.2} {}", v, UNITS[i])
    }
}

/// Parse the Cookie header for a named cookie.
pub fn cookie_value(headers: &axum::http::HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        let part = part.trim();
        if let Some(v) = part.strip_prefix(name) {
            if let Some(v) = v.strip_prefix('=') {
                return Some(v.to_string());
            }
        }
    }
    None
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Random hex string of `bytes` random bytes.
pub fn rand_hex(bytes: usize) -> String {
    use rand::RngCore;
    let mut buf = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

/// HMAC-SHA1 hex digest (Swift temp URL signature).
pub fn hmac_sha1_hex(key: &[u8], msg: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    use sha1::Sha1;
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(key).expect("hmac key");
    mac.update(msg);
    hex::encode(mac.finalize().into_bytes())
}

/// URL-safe base64 without padding, for self-describing share tokens.
pub fn b64url(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for c in bytes.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        if c.len() > 1 {
            out.push(T[(n >> 6) as usize & 63] as char);
        }
        if c.len() > 2 {
            out.push(T[n as usize & 63] as char);
        }
    }
    out
}

pub fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    let val = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => (c - b'A') as u32,
            b'a'..=b'z' => (c - b'a') as u32 + 26,
            b'0'..=b'9' => (c - b'0') as u32 + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        })
    };
    let b = s.as_bytes();
    let mut out = Vec::new();
    for c in b.chunks(4) {
        let mut n = 0u32;
        for (i, ch) in c.iter().enumerate() {
            n |= val(*ch)? << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if c.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if c.len() > 3 {
            out.push(n as u8);
        }
    }
    Some(out)
}

/// Constant-time string compare, so a signature check cannot be timed.
pub fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod token_tests {
    use super::*;

    #[test]
    fn b64url_round_trips_and_avoids_url_unsafe_chars() {
        for case in [&b""[..], b"a", b"ab", b"abc", b"abcd", &[0xff, 0xfe, 0xfd][..]] {
            let enc = b64url(case);
            assert!(!enc.contains('+') && !enc.contains('/') && !enc.contains('='), "{enc}");
            assert_eq!(b64url_decode(&enc).as_deref(), Some(case), "round trip {enc}");
        }
    }

    #[test]
    fn ct_eq_matches_normal_equality() {
        assert!(ct_eq("abc", "abc"));
        assert!(!ct_eq("abc", "abd"));
        assert!(!ct_eq("abc", "abcd"));
        assert!(ct_eq("", ""));
    }
}
