# S3 + L3b probe · 2026-08-06

## S3 live matrix (TempAuth SigV4 @ VIP HTTPS)

| Op | Result |
|----|--------|
| ListBuckets | PASS 200 |
| CreateBucket / Put / Get / List v1 / List v2 | PASS |
| DeleteObject / DeleteBucket | PASS |
| **ListMultipartUploads** (`uploads=`) | **PASS 200** (not 501) |
| ListMPU bare `uploads` | SignatureDoesNotMatch (client query canonicalization; not server 501) |

**Verdict: LAB S3 path GREEN** for core matrix. Full production matrix residuals (MPU complete lifecycle, ACL/CORS depth, EC2 regression this pack) still backlog.

Pipeline live includes `s3api s3token` before authtoken/keystoneauth/tempauth.

## L3b

| Item | Status |
|------|--------|
| swift-container-sharder ×4 | **active** |
| Behavior | local cleave; logs `sharding=0 skipped=N` (no SHARDING containers) |
| Multi-node HTTP quorum / KEEP | **NOT CLAIMED** |
| manage-shard-ranges | binary present; needs DB path for live drill |

**Verdict: L3b daemon PRESENT, production L3b stop-line still open.**
