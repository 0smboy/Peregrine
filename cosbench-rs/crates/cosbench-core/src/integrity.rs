//! Content generation + hash trailer (COSBench hashCheck), with **u64-safe** gap math.
//! Fixes the Java int overflow in PR #426 / issue #425.

use bytes::{Bytes, BytesMut};
use sha2::{Digest, Sha256};

/// Length of the hex-encoded SHA-256 trailer we embed.
pub const HASH_HEX_LEN: u64 = 64;

/// Generate object payload of `size` bytes.
/// If `hash_check`, the final `HASH_HEX_LEN` bytes are the hex SHA-256 of the preceding payload
/// (or of the whole logical content excluding the trailer region).
pub fn generate_payload(size: u64, hash_check: bool, seed: u64) -> Bytes {
    if size == 0 {
        return Bytes::new();
    }

    if !hash_check || size <= HASH_HEX_LEN {
        return fill_pattern(size, seed);
    }

    let data_len = size - HASH_HEX_LEN;
    let body = fill_pattern(data_len, seed);
    let digest = Sha256::digest(&body);
    let hex = hex::encode(digest);
    debug_assert_eq!(hex.len() as u64, HASH_HEX_LEN);

    let mut out = BytesMut::with_capacity(size as usize);
    out.extend_from_slice(&body);
    out.extend_from_slice(hex.as_bytes());
    // Ensure exact size (hash is fixed 64).
    debug_assert_eq!(out.len() as u64, size);
    let _ = body;
    out.freeze()
}

/// Verify payload produced by [`generate_payload`] with hash_check=true.
pub fn verify_payload(data: &[u8]) -> Result<(), String> {
    if (data.len() as u64) <= HASH_HEX_LEN {
        return Err("payload shorter than hash trailer".into());
    }
    let split = data.len() - HASH_HEX_LEN as usize;
    let (body, trailer) = data.split_at(split);
    let expected = hex::encode(Sha256::digest(body));
    let got = std::str::from_utf8(trailer).map_err(|e| e.to_string())?;
    if got != expected {
        return Err(format!("hash mismatch: expected {expected}, got {got}"));
    }
    Ok(())
}

/// Process a write stream in chunks applying the same gap logic as Java RandomInputStream,
/// expressed with u64 to avoid overflow when size > 2GB.
///
/// This is primarily a unit-testable model of the fix from PR #426.
pub fn gap_hash_append_model(processed: u64, length: u64, size: u64, hash_len: u64) -> (u64, bool) {
    // Java (buggy): int gap = (int) ((processed + length) - (size - hashLen));
    // Fixed: long gap = (processed + length) - (size - hashLen);
    let gap = (processed + length) as i128 - (size - hash_len) as i128;
    if gap > 0 {
        let new_len = length.saturating_sub(gap as u64);
        (new_len, true)
    } else {
        (length, false)
    }
}

fn fill_pattern(size: u64, seed: u64) -> Bytes {
    // Deterministic cheap pattern (not CSPRNG). Fine for benchmarks.
    let mut buf = BytesMut::zeroed(size as usize);
    let mut x = seed ^ 0x9e37_79b9_7f4a_7c15;
    for chunk in buf.chunks_mut(8) {
        x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9).wrapping_add(1);
        let bytes = x.to_le_bytes();
        for (i, b) in chunk.iter_mut().enumerate() {
            *b = bytes[i];
        }
    }
    buf.freeze()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_roundtrip() {
        let p = generate_payload(1024, true, 42);
        assert_eq!(p.len(), 1024);
        verify_payload(&p).unwrap();
    }

    #[test]
    fn gap_math_large_size_no_overflow() {
        // size > 2GB — Java int gap overflowed here
        let size: u64 = 3_000_000_000;
        let hash_len = HASH_HEX_LEN;
        let processed = size - hash_len - 10;
        let length = 100;
        let (new_len, partial) = gap_hash_append_model(processed, length, size, hash_len);
        assert!(partial);
        assert_eq!(new_len, 10);
    }

    #[test]
    fn gap_math_no_partial() {
        let (new_len, partial) = gap_hash_append_model(0, 100, 1000, 64);
        assert!(!partial);
        assert_eq!(new_len, 100);
    }
}
