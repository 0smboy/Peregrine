# P0-1 strict verify — STREAMING-AWS4-HMAC-SHA256-PAYLOAD per-chunk sig enforce

## VERDICT: **KEEP**

## Git worktree (absolute path for orchestrator merge)

```
/Users/oboy/Downloads/Peregrine
```

- **Branch:** `build/phase1-deploy-rs-lb`
- **Crate root:** `/Users/oboy/Downloads/Peregrine/swift-rust` (package `swift-s3api`)
- **Git toplevel:** `/Users/oboy/Downloads/Peregrine` (`git rev-parse --show-toplevel`)

## Cargo

```text
$ cd /Users/oboy/Downloads/Peregrine/swift-rust && cargo test -p swift-s3api
...
test result: ok. 176 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
Doc-tests swift_s3api: ok. 0 passed; 0 failed
FULL_EXIT:0
```

Log: `/Users/oboy/Downloads/Peregrine/tools/test-results/impl-chunk-sig-enforce-20260807/cargo-test.txt`

Focused chunk-sig tests (all **ok**):
- `aws_chunked::dechunk_python_hmac_vector_with_verify`
- `aws_chunked::dechunk_bad_chunk_signature_errors`
- `aws_chunked::dechunk_missing_chunk_signature_in_signed_mode_errors`
- `middleware::aws_chunked_streaming_payload_dechunks_to_backend`
- `middleware::aws_chunked_streaming_multi_chunk_signed_dechunks_to_backend`
- `middleware::aws_chunked_bad_chunk_signature_is_signature_does_not_match` → 403 + SignatureDoesNotMatch
- `middleware::aws_chunked_trailer_unsigned_dechunks_to_backend`

## Middleware no longer ignores `Some(false)`

**Confirmed.** Failures never soft-return `chunk_signatures_valid == Some(false)`:

1. **`aws_chunked.rs`**: on missing/bad `chunk-signature` when `ChunkSigContext` is set → immediate `return Err(AwsChunkedError::InvalidChunkSignature)` (lines ~216–239). Success path only yields `Some(true)`.
2. **`middleware.rs`**: maps `InvalidChunkSignature` → `s3_error_response("SignatureDoesNotMatch", …)` HTTP 403 (lines ~426–431). Comment at 434: *“Some(false) no longer soft-ignored.”* The leftover `let _ = decoded.chunk_signatures_valid` is only reached after `Ok` (valid chain).

No residual `// Residual: chunk_signatures_valid == Some(false) does not abort` path remains.

## `rg` (evidence also in `rg-enforce.txt`)

Key hits under `crates/swift-s3api/src/`:
- `InvalidChunkSignature` enum + hard-fail returns in `aws_chunked.rs`
- Middleware map to `SignatureDoesNotMatch` (403)
- Unit/middleware assertions for bad sig → 403

## Files changed (this impl)

| Path (relative to git toplevel) |
|---------------------------------|
| `swift-rust/crates/swift-s3api/src/aws_chunked.rs` |
| `swift-rust/crates/swift-s3api/src/middleware.rs` |
| `swift-rust/crates/swift-s3api/src/lib.rs` |
| `swift-rust/crates/swift-s3api/src/sigv4.rs` |

(`git status` shows these four as modified on `build/phase1-deploy-rs-lb`.)

## Behavior checklist

| Requirement | Status |
|-------------|--------|
| HMAC STREAMING-* + ctx: bad/missing chunk-sig → SignatureDoesNotMatch 403, no body forward | **PASS** |
| STREAMING-UNSIGNED-PAYLOAD-TRAILER still dechunks | **PASS** |
| ECDSA streaming still 501 | **PASS** (unchanged path) |
| SigV2 WONTFIX untouched | **PASS** |
| Docs say per-chunk ENFORCED when signed + credentials | **PASS** |
