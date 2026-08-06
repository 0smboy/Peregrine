# S3 ON-BY-CONFIG (Contabo / production stop-line)

**Status:** enable by explicit pipeline edit. Contabo LAB 2026-08-05 live pack
enabled `s3api`+`s3token` on all four proxies (see
`tools/test-results/wave3-s3-l3b-live-20260805/`). Default bundle templates still
omit them until an ops cutover pins the inventory.

## What is ON-BY-CONFIG

| Piece | Default Contabo | Enable |
|-------|-----------------|--------|
| `s3api` filter | **off** (not in `[pipeline:main]`) | Add `s3api` **before** `tempauth` (or before `s3token` + `keystoneauth`) |
| Swift `GET /info` | never advertises `s3api` | unchanged (parallel API; honest discovery) |
| `s3token` | **off** | Add `s3token` with `[filter:s3token] auth_uri=…` after Keystone is live (W1) |
| SigV4 credentials | TempAuth `user_<acct>_<user>` → access key `account:user` | same map `s3api` already uses |

## Sample proxy.conf fragment

```ini
[pipeline:main]
# Contabo default today (do not replace blindly):
# pipeline = catch_errors gatekeeper healthcheck proxy-logging cache tempauth …
# S3 enable (LAB / maintenance window):
pipeline = catch_errors gatekeeper healthcheck proxy-logging cache s3api tempauth copy proxy-logging proxy-server

[filter:s3api]
use = egg:swift#s3api
location = RegionOne
# dns_compliant_bucket_names = true

# After Wave 1 Keystone cutover (not Contabo default):
# pipeline = … s3api s3token authtoken keystoneauth …
# [filter:s3token]
# auth_uri = http://10.0.0.11:5000
# reseller_prefix = AUTH_
```

Rust proxy reads the same section names via `build_configured_filters`
(`swift-proxy-server`); `HttpS3TokenClient` POSTs to `{auth_uri}/v3/s3tokens`.

## Suite scripts

| Script | Purpose |
|--------|---------|
| [`tools/wave3-s3-unit-suite.sh`](../../tools/wave3-s3-unit-suite.sh) | cargo unit stop-line (s3api / s3token / sharder / proxy fan-out) |
| [`tools/wave3-s3-contabo-gate.sh`](../../tools/wave3-s3-contabo-gate.sh) | Contabo VIP health + optional S3 smoke; **skips** if meta dirty or cluster unhealthy |

## Production stop-line matrix

See evidence packs:

- `tools/test-results/wave3-s3-l3b-prod-YYYYMMDD/S3-COMPAT-MATRIX.md`
- Prior: `tools/test-results/wave3-s3-l3b-20260805/S3-COMPAT-MATRIX.md`

**WONTFIX (written)** unless a later plan reopens: SigV2, aws-chunked streaming,
bucket versioning / tagging / lifecycle / object-lock. Full IAM ACL fidelity
remains residual (basic canned ACL + read ACL XML only).

## Claims discipline

- Do **not** claim Contabo live S3 GREEN without suite evidence under
  `tools/test-results/…`.
- Do **not** claim PRODUCTION-COMPLETE from HTTP lab alone (TLS / Keystone
  hard gates are W1 + P3-ops).
- ListMultipartUploads must not return `501` (markers under `{bucket}+segments`).
