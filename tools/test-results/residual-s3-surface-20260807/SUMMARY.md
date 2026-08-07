# Residual S3 surface · 2026-08-07

**Claim level:** unit + code-path honesty only. **Not** live Contabo KEEP for this residual matrix. **Not** PRODUCTION-GO-LIVE.

**Command:** `cd swift-rust && cargo test -p swift-s3api -- --nocapture`  
**Result:** **93 passed; 0 failed** (see `01-cargo-test.txt`)

## Matrix

| Item | Status | Evidence |
|------|--------|----------|
| SigV4 + CRUD + ListObjects v1/v2 + MultiDelete + MPU | **KEEP** (prior waves; not re-lived here) | prior `s3-deep-live` / wave3 |
| Canned bucket ACL (`private` / `public-read` / `public-read-write`) | **KEEP** unit | `apply_canned_*`, `put_bucket_acl_public_read_write` |
| Object canned ACL store (`x-amz-acl` → `X-Object-Sysmeta-S3-Acl` + GET `?acl`) | **KEEP** unit | `put_object_stores_canned_acl_sysmeta`, `get_object_acl_*`, `put_object_acl_posts_sysmeta` |
| Multi-rule CORS put/get | **KEEP** unit | `cors_multi_rule_put_stamps_s3_cors_meta`, `parse_multi_rule_cors`, `multi_rule_meta_encode_decode_roundtrip` |
| SigV2 auth | **WONTFIX** — stable **501** `Code=NotImplemented` | `sigv2_header_auth_returns_501`, `sigv2_query_auth_returns_501` |
| aws-chunked / STREAMING-* | **WONTFIX** — stable **501** | `aws_chunked_streaming_payload_returns_501`, `aws_chunked_content_encoding_returns_501`, `aws_chunked_trailer_unsigned_returns_501` |
| versioning / versions / tagging / lifecycle / object-lock | **SUPERSEDED 2026-08-07** — meta API implemented (unit); see `impl-s3-versioning-surface-20260807/` | multi-version bodies still residual |
| Full IAM / grant-header ACL / ACP XML body PUT | **RESIDUAL — not implemented** | only `x-amz-acl` canned; no `x-amz-grant-*`, no AccessControlPolicy body parse on PUT |
| Object public-read → anonymous Swift GET | **RESIDUAL** | sysmeta for S3 GET `?acl` fidelity only; container ACL still gates access |
| authenticated-read / log-delivery-write canned | **RESIDUAL** (Python NotImplemented-ish) | map to private; no AuthenticatedUsers Swift ACL |

## Honesty notes

- Do **not** claim full IAM / grant-header object ACL as KEEP.
- Do **not** treat stable 501 WONTFIX rows as “implemented.”
- Multi-rule CORS is unit-proven (meta encode + first-rule `Access-Control-*` stamps); live preflight ExposeHeader edge cases remain residual.
- Parity table: `docs/fairness-lab/RUST-VS-PYTHON-PARITY.md` §3 refreshed 2026-08-07.

## Code anchors

- `crates/swift-s3api/src/lib.rs` — residual / WONTFIX module docs
- `crates/swift-s3api/src/middleware.rs` — SigV2 / aws-chunked intercept + `UNSUPPORTED_SUBRESOURCES` 501
- `crates/swift-s3api/src/acl_cors.rs` — canned ACL + multi-rule CORS; full IAM residual documented
