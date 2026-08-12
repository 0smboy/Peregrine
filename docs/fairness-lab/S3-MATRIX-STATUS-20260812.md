# S3 / middleware matrix status — 2026-08-12

Tip reference: `build/phase1-deploy-rs-lb` @ `48fa98e` (+).

## Runner
- `tools/strict-s3-parity.py` + `tools/strict-s3-parity-selftest.py` (landed; offline selftest PASS)
- `tools/wave3-s3-unit-suite.sh` — unit stop-line
- `tools/wave3-s3-contabo-gate.sh` — Contabo VIP live (ON-BY-CONFIG)

## KEEP (unit / wired in middleware)
- SigV4 CRUD/list/MPU; SigV2 unit; aws-chunked HMAC (incl. PAYLOAD-TRAILER sig verify)
- Canned ACL + CORS unit; grant/ACP JSON + object ACP GET/HEAD deny
- Local IAM directory unit; lifecycle/cold **meta map** unit; Paste registry names
- Object Lock WORM helpers **wired** on DELETE/overwrite (`worm_blocks_key`) + unit tests
- Multi-version data plane (`{bucket}+versions`, versionId GET/DELETE, delete-marker, ListVersions) — unit path
- ECDSA streaming modes → stable **501 NotImplemented** (intentional stop-line)

## OPEN / non-claim (honest)
- Anonymous unauthenticated GET for AllUsers/`public-read` (SigV4 missing → passthrough; container ACL still gates — **no** open anon S3 GET)
- Physical cold/tape backend (meta stamps only)
- Contabo production multi-hour live S3 / full live matrix vs Python oracle
- AWS IAM cloud (local directory only)
- Broader live soak beyond unit stop-line

## WONTFIX / stop-line (documented 501)
- ECDSA `STREAMING-AWS4-ECDSA-P256-SHA256-*`
- Selected S3 subresources listed in middleware `501` table (policy, torrent, …)

Claim boundary: **IMPLEMENTED_SUBSET_ONLY**.
