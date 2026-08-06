# P3-s3 Summary

| Field | Value |
|-------|-------|
| Wave | P3-s3 |
| Date | 2026-08-04 |
| Verdict | **PARTIAL GREEN** |
| Scope | Production S3 API path from `swift-s3api` + proxy wiring |
| Default pipeline | unchanged (s3api ON-BY-CONFIG) |
| `/info` | does **not** advertise `s3api` |

## What shipped

1. `swift-s3api::middleware::S3Api` — SigV4 verify, path map, TempAuth credential map, ListBuckets/ListObjects v1, bucket/object CRUD, CopyObject, GetBucketLocation; unsupported subresources → `501 NotImplemented`.
2. Proxy `build_configured_filters` wires `s3api` when listed and TempAuth `user_*` exist.
3. `bundle-rust` proxy template documents ON-BY-CONFIG sample (commented).
4. Unit evidence: 47/47 `swift-s3api`; proxy `pipeline_s3api_wires_without_info_pollution` PASS.

## Residuals (not GREEN blockers for this minimal surface)

- MPU, ListObjects v2, multi-delete, S3 ACL/CORS/versioning/tagging/lifecycle
- SigV2, aws-chunked, clock-skew/expiry enforcement
- s3token / Keystone (P3-auth parallel)
- Contabo VIP with s3api enabled (not in default pipeline; no wipe / no CORE-PATH baseline change)

## Paths

- Code: `swift-rust/crates/swift-s3api/src/middleware.rs`
- Wire: `swift-rust/crates/swift-proxy-server/src/main.rs` (`build_s3api`)
- Evidence: this directory + `P3S3-REPORT.html`
- Docs: `docs/fairness-lab/PRODUCTION-GAP-ROADMAP.md`, `blocked-by-missing-impl.md`, `CONTRACTS.md`
