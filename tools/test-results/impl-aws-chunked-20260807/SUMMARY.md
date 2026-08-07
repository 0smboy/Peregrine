# aws-chunked / STREAMING-* body decode · 2026-08-07

**Claim level:** unit + code-path. **Not** live Contabo KEEP. **Not** PRODUCTION-GO-LIVE.

**Command:** `cd swift-rust && cargo test -p swift-s3api -- --nocapture`  
**Result:** **117 passed; 0 failed** (see `01-cargo-test.txt`)  
**Filter:** `cargo test -p swift-s3api aws_chunked` → **15/15** (`02-aws-chunked-filter.txt`)

## Implemented (no longer WONTFIX 501)

| Mode | Behavior |
|------|----------|
| `Content-Encoding: aws-chunked` | Dechunk framing; strip `aws-chunked` token; forward raw body + fixed `Content-Length` |
| `STREAMING-UNSIGNED-PAYLOAD-TRAILER` | Dechunk **without** signature verify; trailers discarded (checksum residual) |
| `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` | Dechunk; optional per-chunk HMAC verify residual (dechunk succeeds even if chunk sig wrong) |
| `STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER` | Same as HMAC payload + trailers discarded |
| Header SigV4 | Still verified **before** dechunk using literal `STREAMING-*` as payload hash |

## Still residual / 501

| Item | Status |
|------|--------|
| `STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD*` | **501** NotImplemented (Python parity) |
| Strict reject on bad per-chunk HMAC | residual — dechunk always lands payload |
| Trailer checksum / `x-amz-trailer-signature` enforce | residual |
| Streaming (non-buffered) dechunk for multi-GB | residual — body materialized up to ~5GB cap |

## Tests (formerly expected 501)

- `aws_chunked_streaming_payload_dechunks_to_backend`
- `aws_chunked_content_encoding_dechunks_to_backend`
- `aws_chunked_trailer_unsigned_dechunks_to_backend`
- `aws_chunked_malformed_returns_incomplete_body`
- `aws_chunked_streaming_missing_decoded_length_is_411`
- `aws_chunked::tests::dechunk_python_hmac_vector_with_verify` (Python `test_s3request` vector)

## Code anchors

- `crates/swift-s3api/src/aws_chunked.rs` — pure dechunk + optional chunk-sig chain
- `crates/swift-s3api/src/middleware.rs` — `decode_and_fix_aws_chunked` after SigV4 verify
- Early 501 for aws-chunked **removed** (ECDSA still 501)
