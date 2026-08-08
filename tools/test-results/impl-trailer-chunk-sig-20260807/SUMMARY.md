# P1-3 strict verify — Trailer signature STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER

## VERDICT: **KEEP**

## Git worktree (absolute path for orchestrator merge)

```
/Users/oboy/Downloads/Peregrine
```

- **Branch:** `build/phase1-deploy-rs-lb`
- **HEAD:** `56b40118ec9499ce3e5dccf3824a2b0f99e81412` (base; P1-3 files uncommitted on worktree)
- **Crate root:** `/Users/oboy/Downloads/Peregrine/swift-rust` (package `swift-s3api`)
- **Git toplevel:** `/Users/oboy/Downloads/Peregrine` (`git rev-parse --show-toplevel`)

## Cargo (strict re-run)

```text
$ cd /Users/oboy/Downloads/Peregrine/swift-rust && cargo test -p swift-s3api --lib | tee .../cargo-test.txt
...
test result: ok. 198 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
FULL_EXIT:0
```

Log: `/Users/oboy/Downloads/Peregrine/tools/test-results/impl-trailer-chunk-sig-20260807/cargo-test.txt`

Trailer-focused filter (10/10 ok): `/Users/oboy/Downloads/Peregrine/tools/test-results/impl-trailer-chunk-sig-20260807/trailer-filter.txt`

| Test | Status |
|------|--------|
| `aws_chunked::dechunk_signed_trailer_signature_ok` | ok |
| `aws_chunked::dechunk_bad_trailer_signature_errors` | ok |
| `aws_chunked::dechunk_trailer_mode_missing_trailer_sig_errors` | ok |
| `aws_chunked::dechunk_unsigned_trailer_still_ok` | ok |
| `aws_chunked::aws_doc_trailer_hash_vector` | ok |
| `middleware::aws_chunked_signed_trailer_ok_dechunks_to_backend` | ok (200) |
| `middleware::aws_chunked_bad_trailer_signature_is_signature_does_not_match` | ok (403 SignatureDoesNotMatch) |
| `middleware::aws_chunked_trailer_unsigned_dechunks_to_backend` | ok |

## Enforcement confirmed

1. **`aws_chunked.rs`**: `AWS4-HMAC-SHA256-TRAILER` via `compute_trailer_signature`; terminal 0-chunk sig seeds trailer HMAC; `require_trailer_signature` + trailers without `x-amz-trailer-signature` → `InvalidTrailerSignature`; bad HMAC → same error.
2. **`middleware.rs`**: `STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER` sets `require_trailer_signature: true`; maps `InvalidChunkSignature | InvalidTrailerSignature` → `SignatureDoesNotMatch` 403.
3. **UNSIGNED**: `STREAMING-UNSIGNED-PAYLOAD-TRAILER` still dechunks without trailer HMAC.

## Residuals (documented, not blockers)

- Empty trailer block under PAYLOAD-TRAILER does not force `x-amz-trailer-signature`
- Trailer content discarded after verify (not applied as object metadata)
- Live multi-chunk AWS S3 golden e2e not in CI (unit hash vector + round-trip HMAC covered)

## Files changed (this impl)

| Path (relative to git toplevel) |
|---------------------------------|
| `swift-rust/crates/swift-s3api/src/aws_chunked.rs` |
| `swift-rust/crates/swift-s3api/src/middleware.rs` |
| `swift-rust/crates/swift-s3api/src/lib.rs` |

## Checklist

| Requirement | Status |
|-------------|--------|
| PAYLOAD-TRAILER + trailers: verify trailer sig | **PASS** |
| Bad trailer sig → SignatureDoesNotMatch 403 | **PASS** |
| UNSIGNED-PAYLOAD-TRAILER still OK | **PASS** |
| cargo test -p swift-s3api --lib | **PASS** (198) |
| Evidence `cargo-test.txt` + SUMMARY worktree | **PASS** |
