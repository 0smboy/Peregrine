# S3 Compatibility Matrix — Contabo live 2026-08-05

VIP: `https://10.0.0.10:8085` (self-signed LAB, `curl -k`)  
Credential model: TempAuth `test:tester` / `azure-swift-2026.bench` → SigV4 access key `test:tester`.  
Pipeline (enabled this cycle): `… s3api s3token authtoken keystoneauth tempauth …`

| Capability | Mechanism | Contabo live | Evidence |
|------------|-----------|--------------|----------|
| SigV4 header auth | TempAuth map in s3api | **PASS** | `30-s3-live-suite.txt` |
| ListBuckets | GET `/` | **PASS** | same |
| CreateBucket / DeleteBucket | PUT/DELETE `/{bucket}` | **PASS** | same |
| PutObject / GetObject | PUT/GET object | **PASS** | same |
| ListObjects v1 | GET `/{bucket}` | **PASS** | same |
| ListObjectsV2 | `?list-type=2` | **PASS** | same |
| GetBucketLocation | `?location` | **PASS** | same |
| GetBucketAcl | `?acl` | **PASS** | same |
| GetBucketCors | `?cors` | **PASS** (200 recorded) | same |
| MultiDelete | POST `?delete` | **PASS** | same |
| CreateMultipartUpload | POST `?uploads` | **PASS** | same |
| UploadPart / ListParts | partNumber + uploadId | **PASS** | same |
| ListMultipartUploads | GET `?uploads` | **PASS** (not 501) | same |
| AbortMultipartUpload | DELETE uploadId | **PASS** | same |
| `/info` honesty | no `s3api` key | **PASS** | `20-health-body.txt` |
| s3token filter wired | auth_uri → Keystone :5001 | **PASS** (wired) | `32-post-cluster-health.txt` |
| Keystone `/v3/s3tokens` exchange | OS-EC2 cred | **BLOCKED** (uwsgi crash) | `31-s3token-verdict.txt` |
| VIP EC2 → s3token e2e | SigV4 with EC2 keys | **BLOCKED** | s3api InvalidAccessKeyId before s3token |
| SigV2 / aws-chunked / versioning | — | **WONTFIX** | S3-ON-BY-CONFIG.md |

**Overall Contabo S3:** **PARTIAL** — TempAuth SigV4 live GREEN; live s3token BLOCKED. Not PRODUCTION-GO-LIVE.
