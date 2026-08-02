# Swift Rust functional test — 2026-07-31T13:01:16Z

## Verdict: **ACCEPT** (4-node cluster)

Primary target: cluster HAProxy `http://10.42.30.1N:8085`. Fresh lab; leftover probe objects only.

| Gate | Result |
|------|--------|
| func-suite swift1 | **54/54 PASS** |
| func-suite peer :12/:13/:14 | **54/54 each** |
| ACL + meta length | 200→401 revoke; meta 300→400, 200→202 |
| edge-diag | ETag/422/fast-POST/EC proxy+VIP OK |
| EC heal | degraded+post-heal md5 YES |
| Rust SAIO :8081 (after restart onto EC bins) | `RESULT  label=rust-saio  PASS=54  FAIL=0` |

## Coverage
auth, account/container/object CRUD+meta, ETag 422, ranges, conditionals, 4MB,
SLO/DLO, copy, expiry, unicode, listings, EC put/get/range, security negatives,
ACL revoke, EC fragment heal.

## Notes
- SAIO initially failed EC with 501 because processes held a deleted non-EC binary; restarted onto `/usr/local/bin/*`.
- Evidence: `/root/func-test-20260731T125943Z` on swift1.
