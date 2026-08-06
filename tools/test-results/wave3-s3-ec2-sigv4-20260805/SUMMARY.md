# Wave 3 Contabo — Rust s3api → Keystone s3token EC2 deferral (2026-08-05)

**Verdict: GREEN** · VIP S3 SigV4 with EC2 keys **PASS** · unit + live proved · **not** PRODUCTION-GO-LIVE

Evidence pack: `tools/test-results/wave3-s3-ec2-sigv4-20260805/`  
Prior backlog: `tools/test-results/wave3-s3token-fix-20260805/` (Keystone s3tokens GREEN; VIP S3 SigV4 BLOCKED)

## What this cycle did

1. Fixed Rust `HttpS3TokenClient` to urlsafe-base64 encode the raw SigV4 string-to-sign for Keystone `credentials.token` (Python parity). Never posts `X-Amz-Date` as token.
2. Fixed `S3Token` middleware to require `X-Backend-S3-String-To-Sign` (passthrough without inventing a date token).
3. Added `S3Api::with_s3token_client` + `resolve_credential`: unknown access keys exchange via Keystone `/v3/s3tokens` with a real STS; on success map to `AUTH_{project_id}` and skip local signature verify (Keystone already checked).
4. Proxy wiring: when `[filter:s3token] auth_uri` is set, inject `HttpS3TokenClient` into `s3api` (inline deferral).
5. Unit tests + Contabo deploy (ELF ×4) + live VIP EC2 SigV4 PUT/GET.

## Measured effect

| Item | Before | After |
|------|--------|-------|
| Unknown EC2 key on VIP S3 SigV4 | **InvalidAccessKeyId** (Rust rejects before s3token) | **200** ListBuckets / CreateBucket / Put / Get |
| s3token `credentials.token` | `X-Amz-Date` string (would 401) | urlsafe-base64 of SigV4 STS |
| Proxy note | `s3api enabled (SigV4+CRUD+list; …)` | `… + EC2→s3token deferral; …` |
| TempAuth S3 ListBuckets | 200 | **200** (unchanged) |

## Gates

| Gate | Result | Evidence |
|------|--------|----------|
| `cargo test` s3token (7) | **PASS** | `00-cargo-unit.txt` |
| `cargo test` unknown_ec2 (2) | **PASS** | `00-cargo-unit.txt` |
| proxy EC2 deferral wiring | **PASS** | `00-cargo-unit.txt` |
| Deploy ELF ×4 same SHA | **PASS** | `04-redeploy-consistent-and-reprove.txt` SHA `a0c252bc…` |
| Pipeline notes show deferral ×4 | **PASS** | `04-…` |
| VIP EC2 SigV4 PUT/GET | **PASS** | `02-vip-ec2-sigv4-putget.txt`, `04-…` reprove |
| TempAuth S3 regression | **PASS** | `03-cluster-and-tempauth.txt` |
| PRODUCTION-GO-LIVE | **NO** | LAB only |

## Remaining / FROZEN

- **FROZEN:** PRODUCTION-GO-LIVE / full Wave-3 stop-line without remaining plan hard gates (L3b quorum etc.).
- **Ops note:** Do not scp macOS Mach-O into `/usr/local/bin/swift-proxy-server` (Exec format error / crash loop). Build on Contabo (`cargo build --release -p swift-proxy-server --features ec`).

## Claims discipline

- May claim Contabo **LAB** VIP S3 SigV4 with EC2 keys GREEN (this pack).
- Must **not** claim PRODUCTION-GO-LIVE.
