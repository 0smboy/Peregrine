# P3-s3 Compatibility Matrix (minimal production surface)

Date: 2026-08-04  
Evidence: `tools/test-results/p3-s3-20260804/`  
Credential model: TempAuth `user_<account>_<user>` → access key `account:user`, secret = TempAuth key.

| Op | Method / path | Status | Evidence |
|----|---------------|--------|----------|
| SigV4 header auth | `Authorization: AWS4-HMAC-SHA256 …` | **PASS** | `swift-s3api` sigv4 + middleware tests |
| SigV4 reject bad key | wrong access key | **PASS** | `reject_bad_access_key` |
| SigV4 reject bad sig | wrong signature | **PASS** | `reject_bad_signature` |
| Passthrough non-S3 | `/v1/…` without SigV4 | **PASS** | `passthrough_without_sigv4` |
| ListBuckets | `GET /` | **PASS** | `list_buckets_translates_json` |
| CreateBucket | `PUT /bucket` | **PASS** | `create_and_delete_bucket` |
| DeleteBucket | `DELETE /bucket` | **PASS** | `create_and_delete_bucket` |
| HeadBucket | `HEAD /bucket` | **PASS** (unit path map) | middleware success path |
| ListObjects v1 | `GET /bucket` | **PASS** | `list_objects_translates` |
| GetBucketLocation | `GET /bucket?location` | **PASS** | `location_subresource_local` |
| PutObject | `PUT /bucket/key` | **PASS** | `put_object_maps_path_and_status` |
| GetObject | `GET /bucket/key` | **PASS** (404→NoSuchKey) | `get_object_404_is_nosuchkey` |
| HeadObject | `HEAD /bucket/key` | **PASS** (unit) | translate_object_success |
| DeleteObject | `DELETE /bucket/key` | **PASS** (unit) | delete_object_response |
| CopyObject | `PUT` + `x-amz-copy-source` | **PASS** | `copy_object_sets_x_copy_from` |
| Proxy wire `s3api` | `build_configured_filters` | **PASS** | `pipeline_s3api_wires_without_info_pollution` |
| Swift `/info` clean | no `s3api` key when wired | **PASS** | same test |
| ListObjects v2 | `?list-type=2` | **NotImplemented** (residual) | middleware reject |
| Multipart upload | `?uploads` / `uploadId` | **NotImplemented** (residual) | subresource guard |
| S3 ACL / CORS / versioning / tagging | subresources | **NotImplemented** (residual) | subresource guard |
| Multi-delete | `POST ?delete` | **NotImplemented** (residual) | subresource guard |
| SigV2 / aws-chunked | — | **Deferred** | crate notes |
| s3token + Keystone | — | **Deferred** (P3-auth track) | parallel; not owned here |
| Contabo VIP with s3api in default pipeline | — | **Not run** | ON-BY-CONFIG; default pipeline unchanged (CORE-PATH baseline) |

## Verdict

**PARTIAL GREEN** — coherent minimal production surface (auth + CRUD + list) wired and unit-proven; residuals documented; Swift v1 `/info` not polluted.
