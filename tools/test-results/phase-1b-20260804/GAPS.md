# Phase 1B gap table (honest — not full Paste)

Date: 2026-08-04

| Item | Python SAIO (:8090) | Rust SAIO (:8081) | Claim |
|------|---------------------|-------------------|-------|
| func-suite | 54/54 | 54/54 | CORE-PATH-ONLY PASS |
| catch_errors / gatekeeper / healthcheck | yes (Paste) | yes (always-on) | aligned |
| tempauth / copy / slo / dlo | yes | yes | aligned |
| ratelimit | off in 1B conf | off (no `[filter:ratelimit]`) | aligned (both off) |
| cache / memcache | required by Py tempauth | not wired | **GAP** |
| proxy-logging / listing_formats | in thin pipeline | not wired | **GAP** |
| bulk / tempurl / formpost / staticweb / quotas | not in thin pipeline | not wired | not claimed |
| Keystone / S3 | no | no | not claimed |
| Configurable subset `pipeline=` | Paste native | B4 code (optional `[pipeline:main]`) | code done; SAIO still default order |

**Forbidden claim:** "full Paste pipeline parity."
