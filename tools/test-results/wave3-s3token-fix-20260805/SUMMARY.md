# Wave 3 Contabo — Keystone `/v3/s3tokens` crash fix (2026-08-05)

**Verdict: PARTIAL** · Keystone s3tokens live exchange **GREEN** · EC2→s3token→Swift native PUT/GET over VIP **GREEN** · VIP S3 SigV4 with EC2 keys **BLOCKED** (Rust) · **not** PRODUCTION-GO-LIVE

Evidence pack: `tools/test-results/wave3-s3token-fix-20260805/`  
Prior failure: `tools/test-results/wave3-s3-l3b-live-20260805/` (`31-s3token-verdict.txt`)

## What this cycle did

1. Reproduced Keystone `/v3/s3tokens` worker disconnect (`RemoteDisconnected`).
2. Root-caused: uncaught `binascii.Error: Incorrect padding` in `s3tokens._check_signature` when `credentials.token` is not valid urlsafe-base64 (uwsgi returned HTTP/1.1 500 with 0 bytes / client saw disconnect).
3. Patched `keystone/api/s3tokens.py` on swift1–3:
   - catch `binascii.Error` / `ValueError` / `TypeError` → `Unauthorized` (401)
   - set `X-Subject-Token = token.id` (parity with `/v3/ec2tokens`; Fernet id absent from JSON body)
4. Confirmed credential-keys + fernet-keys MD5 identical on swift1–3; restarted Keystone only after keys present.
5. Proved VIP HTTPS EC2→s3tokens→Swift native container/object PUT/GET; measured VIP S3 SigV4 with EC2 still `InvalidAccessKeyId`.

## Measured effect

| Item | Before | After |
|------|--------|-------|
| Valid EC2 `/v3/s3tokens` (local :5001 / VIP :5000 HTTPS) | intermittent RemoteDisconnected / no Subject-Token | **200** ×30 local, ×10 VIP; `X-Subject-Token` len 183 |
| Invalid base64 `token` field | **RemoteDisconnected** / worker 500 empty | **401 Unauthorized** |
| Wrong signature / rust-style date token | 401 | 401 (unchanged) |
| EC2 → Swift native PUT/GET via VIP `:8085` | 401 (no Subject-Token) | **201/200** create+put+get |
| EC2 → VIP S3 SigV4 ListBuckets | InvalidAccessKeyId | **still InvalidAccessKeyId** (Rust s3api rejects before s3token) |

## Gates

| Gate | Result | Evidence |
|------|--------|----------|
| Credential + Fernet key sync swift1–3 | **PASS** | `15-patch-sync-proof.txt` |
| s3tokens.py patch identical ×3 | **PASS** | md5 `3c4c5669…` |
| `/v3/s3tokens` valid EC2 exchange | **PASS** | `13-post-fix-verify.txt`, `14-vip-swift-native-proof.txt` |
| bad base64 no longer crashes uwsgi | **PASS** | `13` / `14` → HTTP 401 |
| `X-Subject-Token` on s3tokens | **PASS** | `subj_len 183` |
| EC2 → s3token → Swift native PUT/GET VIP | **PASS** | `14-vip-swift-native-proof.txt` |
| EC2 → VIP S3 SigV4 PUT/GET | **BLOCKED** | `InvalidAccessKeyId` in `13` / `14` |
| PRODUCTION-GO-LIVE | **NO** | LAB TLS + S3 EC2 gap + plan hard gates |

## Root cause (honest)

Not a missing credential-key sync on the steady-state path (keys matched; encrypted blobs decrypt). The live “crash” was an **uncaught `binascii.Error`** on malformed `credentials.token`, plus **missing `X-Subject-Token`** so even successful exchanges could not authorize Swift.

Fernet/credential keys must exist **before** uwsgi workers start (historical `DAMN ! worker … died` + `/etc/keystone/fernet-keys/ does not exist` in supervisor logs at bootstrap).

## Remaining / FROZEN

- **Backlog:** Rust `s3api` unknown-key path must defer to `s3token` (or call Keystone inline) with a real base64 string-to-sign; today’s binary rejects EC2 access keys with `InvalidAccessKeyId` before `s3token` runs. Current Rust `s3token` also posts `X-Amz-Date` as `token` (not base64 string-to-sign) — would 401 even if passthrough existed.
- **FROZEN:** PRODUCTION-GO-LIVE / full W3 GREEN without S3 EC2 e2e + L3b quorum + remaining plan hard gates.
- **Ops:** Contabo site-package patch lives on nodes + `s3tokens.py.patched` / `apply_s3tokens_patch.py` in this pack; re-apply after Keystone RPM upgrade.

## Claims discipline

- May claim Contabo **LAB** Keystone `/v3/s3tokens` live exchange GREEN and EC2→Swift native path GREEN.
- Must **not** claim VIP S3 SigV4 with EC2 GREEN, full W3 stop-line GREEN, or PRODUCTION-GO-LIVE.
