# S3 / middleware matrix status — 2026-08-12

Tip reference: `build/phase1-deploy-rs-lb` (fmt tip `53e43d8`+).

## Runner
- `tools/strict-s3-parity.py` + `tools/strict-s3-parity-selftest.py` (landed this branch)
- `tools/wave3-s3-unit-suite.sh` — unit stop-line
- `tools/wave3-s3-contabo-gate.sh` — Contabo VIP live (ON-BY-CONFIG)

## KEEP (unit / prior lab)
SigV4 CRUD/list/MPU, SigV2 unit, aws-chunked HMAC (non-ECDSA), canned ACL + CORS unit, local IAM directory unit, lifecycle/cold **meta map** unit, Paste registry standard names.

## OPEN / non-claim
Multi-version object bodies; Object Lock WORM enforce; anon public-read→Swift GET; ECDSA streaming (501); trailer checksum; physical cold/tape backend; AWS IAM cloud; Contabo production multi-hour live S3.

Claim boundary: **IMPLEMENTED_SUBSET_ONLY**.
