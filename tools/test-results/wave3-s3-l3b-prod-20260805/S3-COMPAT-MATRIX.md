# S3 Compatibility Matrix — Wave 3 PRODUCTION stop-line (2026-08-05)

Evidence: `tools/test-results/wave3-s3-l3b-prod-20260805/`  
Prior: `tools/test-results/wave3-s3-l3b-20260805/`  
Credential model: TempAuth `account:user` → SigV4; `s3token` → Keystone `/v3/s3tokens` via `HttpS3TokenClient` when `auth_uri` set.

| Op | Method / path | Status | Evidence |
|----|---------------|--------|----------|
| SigV4 header auth | `Authorization: AWS4-HMAC-SHA256 …` | **PASS** | `05-cargo-s3api.txt` |
| SigV4 reject bad key/sig | wrong key/signature | **PASS** | middleware tests |
| Passthrough non-S3 | `/v1/…` without SigV4 | **PASS** | `passthrough_without_sigv4` |
| ListBuckets | `GET /` | **PASS** | unit |
| Create/Delete/Head Bucket | `PUT/DELETE/HEAD /bucket` | **PASS** | unit |
| ListObjects v1 | `GET /bucket` | **PASS** | unit |
| ListObjects v2 | `GET /bucket?list-type=2` | **PASS** | unit |
| GetBucketLocation | `GET /bucket?location` | **PASS** | unit |
| Put/Get/Head/Delete Object | object CRUD | **PASS** | unit |
| CopyObject | `x-amz-copy-source` | **PASS** | unit |
| MultiDelete | `POST /bucket?delete` | **PASS** | unit |
| MPU Initiate / UploadPart / Complete / Abort | `?uploads` / `uploadId` / `partNumber` | **PASS** | unit |
| ListParts | `GET …?uploadId=` | **PASS** (minimal) | mpu module |
| ListMultipartUploads | `GET /bucket?uploads` | **PASS** | `list_multipart_uploads_lists_markers` (markers under `+segments`) |
| ACL GET/PUT basics | `?acl` + canned `x-amz-acl` | **PASS** (basic) | unit |
| CORS PUT/GET basics | `?cors` → Swift meta | **PASS** (single rule) | unit |
| Proxy wire `s3api` | pipeline | **PASS** | `05-cargo-proxy-s3api.txt` |
| Swift `/info` clean | no `s3api` key | **PASS** | same |
| s3token filter | Keystone `/v3/s3tokens` | **PASS** (unit live HTTP) | `http_s3token_client_live_against_local_listener`; Contabo Keystone **not available** (W1) |
| SigV2 | — | **WONTFIX** (written) | production stop-line |
| aws-chunked streaming | — | **WONTFIX** (written) | production stop-line |
| Versioning / tagging / lifecycle | — | **WONTFIX** (written) | still honest `501` where probed |
| Contabo VIP default pipeline + s3api | — | **SUPERSEDED** | Live cutover + suite in `../wave3-s3-l3b-live-20260805/` (LAB PARTIAL; ListMPU PASS; s3token E2E FAIL) |

## Verdict

**PARTIAL** — unit PRODUCTION S3 stop-line green (incl. ListMultipartUploads + live-ready s3token). Contabo live cutover moved to `../wave3-s3-l3b-live-20260805/` (LAB PARTIAL). Not PRODUCTION-GO-LIVE.
