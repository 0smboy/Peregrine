# S3 Compatibility Matrix — Wave 3 (2026-08-05)

Evidence: `tools/test-results/wave3-s3-l3b-20260805/`  
Prior baseline: `tools/test-results/p3-s3-20260804/`  
Credential model: TempAuth `account:user` → SigV4; optional `s3token` filter for Keystone (stub HTTP).

| Op | Method / path | Status | Evidence |
|----|---------------|--------|----------|
| SigV4 header auth | `Authorization: AWS4-HMAC-SHA256 …` | **PASS** | `05-cargo-s3api.txt` |
| SigV4 reject bad key/sig | wrong key/signature | **PASS** | middleware tests |
| Passthrough non-S3 | `/v1/…` without SigV4 | **PASS** | `passthrough_without_sigv4` |
| ListBuckets | `GET /` | **PASS** | unit |
| Create/Delete/Head Bucket | `PUT/DELETE/HEAD /bucket` | **PASS** | unit |
| ListObjects v1 | `GET /bucket` | **PASS** | `list_objects_translates` |
| ListObjects v2 | `GET /bucket?list-type=2` | **PASS** | `list_objects_v2_emits_key_count` |
| GetBucketLocation | `GET /bucket?location` | **PASS** | unit |
| Put/Get/Head/Delete Object | object CRUD | **PASS** | unit |
| CopyObject | `x-amz-copy-source` | **PASS** | unit |
| MultiDelete | `POST /bucket?delete` | **PASS** | `multi_delete_deletes_keys` |
| MPU Initiate / UploadPart / Complete / Abort | `?uploads` / `uploadId` / `partNumber` | **PASS** | `multipart_upload_*` (SLO complete via `+segments`) |
| ListParts | `GET …?uploadId=` | **PASS** (minimal) | mpu module |
| ListMultipartUploads | `GET /bucket?uploads` | **501 honest residual** | `list_multipart_uploads_is_honest_not_implemented` |
| ACL GET/PUT basics | `?acl` + canned `x-amz-acl` | **PASS** (basic) | `get_acl_returns_private_policy` |
| CORS PUT/GET basics | `?cors` → Swift meta | **PASS** (single rule) | `cors_put_then_get_round_trips` |
| Proxy wire `s3api` | pipeline | **PASS** | `05-cargo-proxy-s3api.txt` |
| Swift `/info` clean | no `s3api` key | **PASS** | same |
| s3token filter | Keystone `/v3/s3tokens` | **PARTIAL** — trait + Map client + header stamp; live HTTP stub | `05-cargo-s3token.txt` |
| SigV2 / aws-chunked / versioning / tagging / lifecycle | — | **Deferred residual** | crate notes |
| Contabo VIP default pipeline + s3api | — | **Not run** | ON-BY-CONFIG; CORE-PATH baseline unchanged |

## Verdict

**PARTIAL GREEN** — Wave 3 S3 surface (v2 list, multi-delete, MPU, ACL/CORS basics, s3token hooks) unit-proven; Contabo live not enabled; ListMultipartUploads + full IAM ACL + live Keystone s3tokens remain residuals.
