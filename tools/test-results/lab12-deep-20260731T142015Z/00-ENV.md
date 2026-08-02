# 00-ENV — Lab12 deep (salvage copy)

UTC: 2026-07-31T14:20:15Z continued on swift1 until Azure stopped VMs ~14:50Z.

## Peer config (verified post-fix)

- swift_base: http://10.42.30.11:8085
- shadow_peer_base: http://127.0.0.1:8090
- shadow_peer_auth: http://127.0.0.1:8090/auth/v1.0
- shadow_peer_label: Python SAIO

Before (00-ENV-before.md on host): peer pointed at :8081 Rust SAIO with Python label (LIE). Corrected before Shadow hard gate.

## Python SAIO repair

- Root cause: rings list sdb1..sdb4; `/srv/node/d1/pysaio/sdb{1..4}` missing → account HEAD [] → 503 / autocreate fail
- Fix: mkdir device trees; restart pyswift proxy/account/container/object
- Auth Storage-Url: http://127.0.0.1:8090/v1/AUTH_test

## func-suite

| Label | Endpoint | PASS | FAIL |
|-------|----------|------|------|
| cluster-ha | http://10.42.30.11:8085 | 54 | 0 |
| py-saio | http://127.0.0.1:8090 | 54 | 0 |

## Gate E0

PASS — dual peer allowed. Cluster later stopped by Azure subscription warning.
