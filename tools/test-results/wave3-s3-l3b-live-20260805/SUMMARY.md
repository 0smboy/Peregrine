# Wave 3 Contabo live — S3 + L3b (2026-08-05 retry)

**Verdict: PARTIAL** · Contabo TempAuth S3 live **GREEN** · live Keystone s3token exchange **BLOCKED** · L3b multi-node quorum **not claimed** · **not** PRODUCTION-GO-LIVE · **no 4KB KEEP**

Prior unit stop-line: `wave3-s3-l3b-prod-20260805/` (was Contabo BLOCKED on empty `/info`).  
This pack is the Contabo live retry after VIP HTTPS + `/info` tempauth+keystoneauth.

## What this cycle did

1. Probed `https://10.0.0.10:8085/info` from inside Contabo → **200** with `tempauth`+`keystoneauth`; no `s3api` key.
2. Enabled **s3api + s3token** ON-BY-CONFIG on swift1–4 proxy pipelines; restarted Rust proxies (all four backends 200).
3. Ran TempAuth SigV4 live suite via VIP HTTPS (`curl -k` / ssl unverified).
4. Created Keystone OS-EC2 credentials; probed `/v3/s3tokens` (endpoint alive; valid-cred exchange crashes uwsgi worker).
5. Documented L3b: no multi-node shard HTTP quorum suite this cycle; no KEEP claim.

## Measured effect

| Item | Before (prod pack) | After (this pack) |
|------|--------------------|-------------------|
| VIP `/info` | HTTP 000 / unhealthy | HTTPS **200** tempauth+keystoneauth |
| s3api pipeline | off | **ON-BY-CONFIG enabled** ×4 |
| Contabo ListBuckets…ListMPU | not run | **PASS** (VIP HTTPS) |
| ListMultipartUploads | n/a live | **200** (not 501) |
| Keystone s3tokens live | W1 not ready | endpoint OK; **exchange CRASH** |
| 4KB KEEP | not claimed | still **not claimed** |

## Gates

| Gate | Result | Evidence |
|------|--------|----------|
| VIP `/info` 200 + honest no `s3api` | **PASS** | `20-contabo-s3-gate.txt`, `20-health-body.txt` |
| TempAuth CRUD path still up | **PASS** | gate + suite |
| ListBuckets / CreateBucket / Put/Get | **PASS** | `30-s3-live-suite.txt` |
| ListObjectsV2 | **PASS** | same |
| MultiDelete | **PASS** | same |
| MPU create/upload/list/abort | **PASS** | same |
| ListMultipartUploads ≠ 501 | **PASS** | same |
| ACL / CORS / location basics | **PASS** | same |
| s3token filter wired | **PASS** | `32-post-cluster-health.txt` |
| Keystone `/v3/s3tokens` live exchange | **BLOCKED** | `31-s3token-verdict.txt` (worker disconnect on valid EC2 access) |
| VIP EC2→s3token e2e | **BLOCKED** | s3api rejects unknown keys before s3token |
| L3b multi-node HTTP quorum | **NOT RUN** | backlog |
| 4KB KEEP | **NOT CLAIMED** | no对照 perf data |
| PRODUCTION-GO-LIVE | **NO** | self-signed LAB + s3token/L3b gaps |

## Remaining / FROZEN

- **FROZEN / backlog:** Keystone s3tokens worker crash on valid EC2 credential (credential decrypt path); enable uwsgi stderr; fix before claiming live s3token GREEN.
- **Backlog:** Rust `s3api` passthrough (or dual-auth) so unknown EC2 keys reach `s3token`.
- **Backlog:** Contabo multi-node shard HTTP quorum (L3b PRODUCTION stop-line).
- **FROZEN:** 4KB KEEP / PRODUCTION-GO-LIVE without对照 data + remaining hard gates.

## Claims discipline

- Contabo TempAuth S3 path may be called **LAB live GREEN** for the matrix rows that passed.
- Do **not** upgrade to PRODUCTION-GO-LIVE or full W3 GREEN (s3token live + L3b quorum incomplete).
