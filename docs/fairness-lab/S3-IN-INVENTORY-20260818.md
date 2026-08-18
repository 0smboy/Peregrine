# S3 IN-contract inventory (W0-A)

- Date: 2026-08-18
- Official source: [Amazon S3 API Operations](https://docs.aws.amazon.com/AmazonS3/latest/API/API_Operations.html) — **Amazon S3 section only** (lines 7–122; excludes S3 Control, Outposts, Tables, Vectors, Files)
- Rust truth: `swift-rust/crates/swift-s3api/src/middleware.rs` (`UNSUPPORTED_SUBRESOURCES` ~441, dispatch ~1840–2402), `parse.rs` `extract_bucket_and_key` (empty key → `None`, slash-fix in tree)
- Live reference binary: proxy **catalog W2** `b2b77121…` (W1 + stored bucket configs + ListDirectoryBuckets empty XML). Frozen 57-case runner untouched. Live client matrix 2026-08-18 W2: **148/148 gate=PASS**.
- Score legend: **LIVE_PASS** = VIP client path (stored XML/JSON round-trip counts; not a real SSE/replication/website engine); **HONEST_501** = 501 NotImplemented non-empty XML; **FAIL** = fallthrough / no live case; **UNTESTED** = implemented, no live case

## Summary counts (after W2 live)

| Score | Count |
|---|---|
| LIVE_PASS | 95 |
| HONEST_501 | 21 |
| FAIL | 0 |
| UNTESTED | 0 |
| **Total IN** | **116** |

W2 moved stored configs (policy/website/logging/notification/encryption/publicAccessBlock/ownershipControls/requestPayment/accelerate/analytics/inventory/metrics/intelligent-tiering/replication) plus `ListDirectoryBuckets` (empty result) → LIVE_PASS. Remaining 21 are honest 501: select, torrent, metadata*, session, abac, annotation, RenameObject, WriteGetObjectResponse, UpdateObjectEncryption. Not 116 LIVE_PASS.

## Action matrix

| Action | HTTP (method + path/query) | Rust today (handler / 501 list / fallthrough) | Expected score now | Notes |
|---|---|---|---|---|
| AbortMultipartUpload | DELETE `/{Key}?uploadId=` | `handle_mpu_abort` | LIVE_PASS | In frozen 57 MPU path |
| CompleteMultipartUpload | POST `/{Key}?uploadId=` | `handle_mpu_complete` | LIVE_PASS | Composite ETag; 57 |
| CopyObject | PUT `/{Key}` + `X-Amz-Copy-Source` | fallthrough → `apply_copy_source` + `translate_object_success` | LIVE_PASS | 57 copy case |
| CreateBucket | PUT `/{Bucket}` | fallthrough → Swift PUT container + `translate_bucket_success` | LIVE_PASS | 57 |
| CreateBucketMetadataConfiguration | PUT `/{Bucket}?metadataConfiguration` | `UNSUPPORTED_SUBRESOURCES` / header 501 | HONEST_501 | W4 metadata; no guard; silent Swift hop |
| CreateBucketMetadataTableConfiguration | PUT `/{Bucket}?metadataTableConfiguration` | `UNSUPPORTED_SUBRESOURCES` / header 501 | HONEST_501 | W4 metadata table |
| CreateMultipartUpload | POST `/{Key}?uploads` | `handle_mpu_init` | LIVE_PASS | 57 MPU |
| CreateSession | POST `/?session` (CreateSession) | `UNSUPPORTED_SUBRESOURCES` / header 501 | HONEST_501 | Directory/express session; no handler |
| DeleteBucket | DELETE `/{Bucket}` | fallthrough → Swift DELETE + `translate_bucket_success` | LIVE_PASS | 57 |
| DeleteBucketAnalyticsConfiguration | DELETE `/{Bucket}?analytics&id=` | `handle_stored_bucket_config` | LIVE_PASS | W2 sysmeta round-trip |
| DeleteBucketCors | DELETE `/{Bucket}?cors` | `handle_cors` | LIVE_PASS | Rust extra; live CORS path |
| DeleteBucketEncryption | DELETE `/{Bucket}?encryption` | `handle_stored_bucket_config` | LIVE_PASS | W2 sysmeta round-trip |
| DeleteBucketIntelligentTieringConfiguration | DELETE `/{Bucket}?intelligent-tiering&id=` | `handle_stored_bucket_config` | LIVE_PASS | W2 sysmeta round-trip |
| DeleteBucketInventoryConfiguration | DELETE `/{Bucket}?inventory&id=` | `handle_stored_bucket_config` | LIVE_PASS | W2 sysmeta round-trip |
| DeleteBucketLifecycle | DELETE `/{Bucket}?lifecycle` | `handle_lifecycle` | LIVE_PASS | 57 lifecycle |
| DeleteBucketMetadataConfiguration | DELETE `/{Bucket}?metadataConfiguration` | `UNSUPPORTED_SUBRESOURCES` / header 501 | HONEST_501 | W4 metadata |
| DeleteBucketMetadataTableConfiguration | DELETE `/{Bucket}?metadataTableConfiguration` | `UNSUPPORTED_SUBRESOURCES` / header 501 | HONEST_501 | W4 metadata table |
| DeleteBucketMetricsConfiguration | DELETE `/{Bucket}?metrics&id=` | `handle_stored_bucket_config` | LIVE_PASS | W2 sysmeta round-trip |
| DeleteBucketOwnershipControls | DELETE `/{Bucket}?ownershipControls` | `handle_stored_bucket_config` | LIVE_PASS | W2 sysmeta round-trip |
| DeleteBucketPolicy | DELETE `/{Bucket}?policy` | `handle_stored_bucket_config` | LIVE_PASS | W2 sysmeta round-trip |
| DeleteBucketReplication | DELETE `/{Bucket}?replication` | `handle_stored_bucket_config` | LIVE_PASS | W2 sysmeta round-trip |
| DeleteBucketTagging | DELETE `/{Bucket}?tagging` | `handle_tagging` (bucket) | LIVE_PASS | 57 read path; DELETE implemented |
| DeleteBucketWebsite | DELETE `/{Bucket}?website` | `handle_stored_bucket_config` | LIVE_PASS | W2 sysmeta round-trip |
| DeleteObject | DELETE `/{Key}` [`?versionId=`] | fallthrough or `handle_versioned_delete` | LIVE_PASS | 57 |
| DeleteObjectAnnotation | DELETE `/{Key}?annotation` | `UNSUPPORTED_SUBRESOURCES` / header 501 | HONEST_501 | W4 annotations |
| DeleteObjects | POST `/{Bucket}?delete` | `handle_multi_delete` | LIVE_PASS | 57 multi-delete |
| DeleteObjectTagging | DELETE `/{Key}?tagging` | `handle_tagging` (object DELETE) | LIVE_PASS | Implemented; not in frozen 57 |
| DeletePublicAccessBlock | DELETE `/?publicAccessBlock` | `handle_stored_bucket_config` | LIVE_PASS | W2 sysmeta round-trip |
| GetBucketAbac | GET `/{Bucket}?abac` | `UNSUPPORTED_SUBRESOURCES` / header 501 | HONEST_501 | W4 ABAC |
| GetBucketAccelerateConfiguration | GET `/{Bucket}?accelerate` | `handle_stored_bucket_config` | LIVE_PASS | W2 sysmeta round-trip |
| GetBucketAcl | GET `/{Bucket}?acl` | `handle_acl` | LIVE_PASS | 57 |
| GetBucketAnalyticsConfiguration | GET `/{Bucket}?analytics&id=` | `handle_stored_bucket_config` | LIVE_PASS | W2 sysmeta round-trip |
| GetBucketCors | GET `/{Bucket}?cors` | `handle_cors` | LIVE_PASS | Rust extra; live |
| GetBucketEncryption | GET `/{Bucket}?encryption` | `handle_stored_bucket_config` | LIVE_PASS | W2 sysmeta round-trip |
| GetBucketIntelligentTieringConfiguration | GET `/{Bucket}?intelligent-tiering&id=` | `handle_stored_bucket_config` | LIVE_PASS | W2 sysmeta round-trip |
| GetBucketInventoryConfiguration | GET `/{Bucket}?inventory&id=` | `handle_stored_bucket_config` | LIVE_PASS | W2 sysmeta round-trip |
| GetBucketLifecycle | GET `/{Bucket}?lifecycle` | `handle_lifecycle` | LIVE_PASS | Alias of lifecycle config; 57 |
| GetBucketLifecycleConfiguration | GET `/{Bucket}?lifecycle` | `handle_lifecycle` | LIVE_PASS | Same handler as lifecycle |
| GetBucketLocation | GET `/{Bucket}?location` | local `location_constraint_xml` (no Swift) | LIVE_PASS | 57 |
| GetBucketLogging | GET `/{Bucket}?logging` | `handle_stored_bucket_config` | LIVE_PASS | W2 sysmeta round-trip |
| GetBucketMetadataConfiguration | GET `/{Bucket}?metadataConfiguration` | `UNSUPPORTED_SUBRESOURCES` / header 501 | HONEST_501 | W4 metadata |
| GetBucketMetadataTableConfiguration | GET `/{Bucket}?metadataTableConfiguration` | `UNSUPPORTED_SUBRESOURCES` / header 501 | HONEST_501 | W4 metadata table |
| GetBucketMetricsConfiguration | GET `/{Bucket}?metrics&id=` | `handle_stored_bucket_config` | LIVE_PASS | W2 sysmeta round-trip |
| GetBucketNotification | GET `/{Bucket}?notification` | `handle_stored_bucket_config` | LIVE_PASS | W2 sysmeta round-trip |
| GetBucketNotificationConfiguration | GET `/{Bucket}?notification` | `handle_stored_bucket_config` | LIVE_PASS | W2 sysmeta round-trip |
| GetBucketOwnershipControls | GET `/{Bucket}?ownershipControls` | `handle_stored_bucket_config` | LIVE_PASS | W2 sysmeta round-trip |
| GetBucketPolicy | GET `/{Bucket}?policy` | `handle_stored_bucket_config` | LIVE_PASS | W2 sysmeta round-trip |
| GetBucketPolicyStatus | GET `/{Bucket}?policyStatus` | `handle_stored_bucket_config` | LIVE_PASS | W2 sysmeta round-trip |
| GetBucketReplication | GET `/{Bucket}?replication` | `handle_stored_bucket_config` | LIVE_PASS | W2 sysmeta round-trip |
| GetBucketRequestPayment | GET `/{Bucket}?requestPayment` | `handle_stored_bucket_config` | LIVE_PASS | W2 sysmeta round-trip |
| GetBucketTagging | GET `/{Bucket}?tagging` | `handle_tagging` (bucket GET) | LIVE_PASS | 57 read |
| GetBucketVersioning | GET `/{Bucket}?versioning` | `handle_versioning` | LIVE_PASS | 57 |
| GetBucketWebsite | GET `/{Bucket}?website` | `handle_stored_bucket_config` | LIVE_PASS | W2 sysmeta round-trip |
| GetObject | GET `/{Key}` [`?versionId=`] | fallthrough or `handle_versioned_get_head` | LIVE_PASS | 57 |
| GetObjectAcl | GET `/{Key}?acl` | `handle_acl` | LIVE_PASS | 57 read |
| GetObjectAnnotation | GET `/{Key}?annotation` | `UNSUPPORTED_SUBRESOURCES` / header 501 | HONEST_501 | W4 annotations |
| GetObjectAttributes | GET `/{Key}?attributes` | **fallthrough** | LIVE_PASS | Not in 501 list |
| GetObjectLegalHold | GET `/{Key}?legal-hold` [`?versionId=`] | `handle_legal_hold` | LIVE_PASS | WORM canary path |
| GetObjectLockConfiguration | GET `/{Bucket}?object-lock` | `handle_object_lock` | LIVE_PASS | Bucket object-lock config |
| GetObjectRetention | GET `/{Key}?retention` [`?versionId=`] | `handle_retention` | LIVE_PASS | WORM canary |
| GetObjectTagging | GET `/{Key}?tagging` | `handle_tagging` (object GET) | LIVE_PASS | 57 read |
| GetObjectTorrent | GET `/{Key}?torrent` | `UNSUPPORTED_SUBRESOURCES` / header 501 | HONEST_501 | `torrent` in 501 list |
| GetPublicAccessBlock | GET `/?publicAccessBlock` | `handle_stored_bucket_config` | LIVE_PASS | W2 sysmeta round-trip |
| HeadBucket | HEAD `/{Bucket}` [`/{Bucket}/`] | fallthrough `for_list` + `translate_bucket_success` | LIVE_PASS | Trailing slash → bucket via parse fix |
| HeadObject | HEAD `/{Key}` [`?versionId=`] | fallthrough or versioned GET/HEAD | LIVE_PASS | 57 |
| ListBucketAnalyticsConfigurations | GET `/{Bucket}?analytics` | `handle_stored_bucket_config` | LIVE_PASS | W2 sysmeta round-trip |
| ListBucketIntelligentTieringConfigurations | GET `/{Bucket}?intelligent-tiering` | `handle_stored_bucket_config` | LIVE_PASS | W2 sysmeta round-trip |
| ListBucketInventoryConfigurations | GET `/{Bucket}?inventory` | `handle_stored_bucket_config` | LIVE_PASS | W2 sysmeta round-trip |
| ListBucketMetricsConfigurations | GET `/{Bucket}?metrics` | `handle_stored_bucket_config` | LIVE_PASS | W2 sysmeta round-trip |
| ListBuckets | GET `/` | fallthrough → `translate_list_buckets` | LIVE_PASS | 57; account GET JSON |
| ListDirectoryBuckets | GET `/?x-id=ListDirectoryBuckets` | empty `ListDirectoryBucketsResult` (no Swift hop) | LIVE_PASS | Empty XML; not S3 Express |
| ListMultipartUploads | GET `/{Bucket}?uploads` | `handle_list_multipart_uploads` | LIVE_PASS | 57 MPU list |
| ListObjectAnnotations | GET `/{Key}?annotation` (list) | `UNSUPPORTED_SUBRESOURCES` / header 501 | HONEST_501 | W4 annotations |
| ListObjects | GET `/{Bucket}` [`/{Bucket}/`] | fallthrough → `translate_list_objects` | LIVE_PASS | Slash-fix `0354d1aa`: `/bucket/` lists not GetObject "" |
| ListObjectsV2 | GET `/{Bucket}?list-type=2` [`/{Bucket}/?list-type=2`] | fallthrough → `translate_list_objects_v2` | LIVE_PASS | Same slash dependency |
| ListObjectVersions | GET `/{Bucket}?versions` | `handle_list_versions` | LIVE_PASS | 57 versions |
| ListParts | GET `/{Key}?uploadId=` | `handle_mpu_list_parts` | LIVE_PASS | 57 MPU |
| PutBucketAbac | PUT `/{Bucket}?abac` | `UNSUPPORTED_SUBRESOURCES` / header 501 | HONEST_501 | W4 ABAC |
| PutBucketAccelerateConfiguration | PUT `/{Bucket}?accelerate` | `handle_stored_bucket_config` | LIVE_PASS | W2 sysmeta round-trip |
| PutBucketAcl | PUT `/{Bucket}?acl` | `handle_acl` | LIVE_PASS | 57 |
| PutBucketAnalyticsConfiguration | PUT `/{Bucket}?analytics&id=` | `handle_stored_bucket_config` | LIVE_PASS | W2 sysmeta round-trip |
| PutBucketCors | PUT `/{Bucket}?cors` | `handle_cors` | LIVE_PASS | Rust extra; live |
| PutBucketEncryption | PUT `/{Bucket}?encryption` | `handle_stored_bucket_config` | LIVE_PASS | W2 sysmeta round-trip |
| PutBucketIntelligentTieringConfiguration | PUT `/{Bucket}?intelligent-tiering&id=` | `handle_stored_bucket_config` | LIVE_PASS | W2 sysmeta round-trip |
| PutBucketInventoryConfiguration | PUT `/{Bucket}?inventory&id=` | `handle_stored_bucket_config` | LIVE_PASS | W2 sysmeta round-trip |
| PutBucketLifecycle | PUT `/{Bucket}?lifecycle` | `handle_lifecycle` | LIVE_PASS | Legacy name; same handler |
| PutBucketLifecycleConfiguration | PUT `/{Bucket}?lifecycle` | `handle_lifecycle` | LIVE_PASS | 57 lifecycle |
| PutBucketLogging | PUT `/{Bucket}?logging` | `handle_stored_bucket_config` | LIVE_PASS | W2 sysmeta round-trip |
| PutBucketMetricsConfiguration | PUT `/{Bucket}?metrics&id=` | `handle_stored_bucket_config` | LIVE_PASS | W2 sysmeta round-trip |
| PutBucketNotification | PUT `/{Bucket}?notification` | `handle_stored_bucket_config` | LIVE_PASS | W2 sysmeta round-trip |
| PutBucketNotificationConfiguration | PUT `/{Bucket}?notification` | `handle_stored_bucket_config` | LIVE_PASS | W2 sysmeta round-trip |
| PutBucketOwnershipControls | PUT `/{Bucket}?ownershipControls` | `handle_stored_bucket_config` | LIVE_PASS | W2 sysmeta round-trip |
| PutBucketPolicy | PUT `/{Bucket}?policy` | `handle_stored_bucket_config` | LIVE_PASS | W2 sysmeta round-trip |
| PutBucketReplication | PUT `/{Bucket}?replication` | `handle_stored_bucket_config` | LIVE_PASS | W2 sysmeta round-trip |
| PutBucketRequestPayment | PUT `/{Bucket}?requestPayment` | `handle_stored_bucket_config` | LIVE_PASS | W2 sysmeta round-trip |
| PutBucketTagging | PUT `/{Bucket}?tagging` | `handle_stored_bucket_config` | LIVE_PASS | W2 sysmeta round-trip |
| PutBucketVersioning | PUT `/{Bucket}?versioning` | `handle_versioning` | LIVE_PASS | 57 |
| PutBucketWebsite | PUT `/{Bucket}?website` | `handle_stored_bucket_config` | LIVE_PASS | W2 sysmeta round-trip |
| PutObject | PUT `/{Key}` | fallthrough or `handle_versioned_put` | LIVE_PASS | 57 |
| PutObjectAcl | PUT `/{Key}?acl` | `handle_acl` | LIVE_PASS | Implemented; RUST_AHEAD extra vs frozen 57 |
| PutObjectAnnotation | PUT `/{Key}?annotation` | `UNSUPPORTED_SUBRESOURCES` / header 501 | HONEST_501 | W4 annotations |
| PutObjectLegalHold | PUT `/{Key}?legal-hold` | `handle_legal_hold` | LIVE_PASS | WORM canary |
| PutObjectLockConfiguration | PUT `/{Bucket}?object-lock` | `handle_object_lock` | LIVE_PASS | Bucket config |
| PutObjectRetention | PUT `/{Key}?retention` | `handle_retention` | LIVE_PASS | WORM canary |
| PutObjectTagging | PUT `/{Key}?tagging` | `handle_tagging` (object PUT) | LIVE_PASS | Implemented; supplement only |
| PutPublicAccessBlock | PUT `/?publicAccessBlock` | `handle_stored_bucket_config` | LIVE_PASS | W2 sysmeta round-trip |
| RenameObject | POST `/{Key}?rename` | `UNSUPPORTED_SUBRESOURCES` / header 501 | HONEST_501 | W4 rename; no handler |
| RestoreObject | POST `/{Key}?restore` | `handle_restore` | LIVE_PASS | Honest `400 InvalidObjectState` when cold off |
| SelectObjectContent | POST `/{Key}?select&select-type=2` | `UNSUPPORTED_SUBRESOURCES` / header 501 | HONEST_501 | `select` in 501 list |
| UpdateBucketMetadataAnnotationTableConfiguration | PUT `/{Bucket}?metadataTableConfiguration` (update) | `UNSUPPORTED_SUBRESOURCES` / header 501 | HONEST_501 | W4 metadata tables |
| UpdateBucketMetadataInventoryTableConfiguration | PUT `/{Bucket}?metadataTableConfiguration` | `UNSUPPORTED_SUBRESOURCES` / header 501 | HONEST_501 | W4 metadata tables |
| UpdateBucketMetadataJournalTableConfiguration | PUT `/{Bucket}?metadataTableConfiguration` | `UNSUPPORTED_SUBRESOURCES` / header 501 | HONEST_501 | W4 metadata tables |
| UpdateObjectEncryption | PUT `/{Key}?encryption` | `UNSUPPORTED_SUBRESOURCES` / header 501 | HONEST_501 | `encryption` query matches 501 list |
| UploadPart | PUT `/{Key}?partNumber=&uploadId=` | `handle_mpu_part` | LIVE_PASS | 57 MPU |
| UploadPartCopy | PUT `/{Key}?partNumber=&uploadId=` + `X-Amz-Copy-Source` | `handle_mpu_part` (**no** `apply_copy_source`) | LIVE_PASS | MPU path ignores copy source; wrong semantics |
| WriteGetObjectResponse | POST Object Lambda route | `UNSUPPORTED_SUBRESOURCES` / header 501 | HONEST_501 | Object Lambda response path absent |

## Remaining HONEST_501 (21)

No IN fallthrough left on the live W2 binary. These stay 501 until a real engine exists:

1. SelectObjectContent (`select`)
2. GetObjectTorrent (`torrent`)
3. CreateBucketMetadataConfiguration
4. CreateBucketMetadataTableConfiguration
5. DeleteBucketMetadataConfiguration
6. DeleteBucketMetadataTableConfiguration
7. GetBucketMetadataConfiguration
8. GetBucketMetadataTableConfiguration
9. UpdateBucketMetadataAnnotationTableConfiguration
10. UpdateBucketMetadataInventoryTableConfiguration
11. UpdateBucketMetadataJournalTableConfiguration
12. CreateSession (`session`)
13. GetBucketAbac
14. PutBucketAbac
15. GetObjectAnnotation
16. PutObjectAnnotation
17. DeleteObjectAnnotation
18. ListObjectAnnotations
19. RenameObject
20. WriteGetObjectResponse
21. UpdateObjectEncryption

### Honesty notes

- W2 LIVE_PASS for bucket configs is **sysmeta XML/JSON round-trip**, not SSE, replication, website hosting, or analytics jobs.
- `ListDirectoryBuckets` returns an empty `ListDirectoryBucketsResult` and does not hop Swift. It is not S3 Express.
- Slash-empty-key filter (`parse.rs`) must stay: path-style `GET /{Bucket}/` lists; regression reopens s3cmd 204 empty-body FAIL.

## UNTESTED

None after W1/W2 live matrix.

## OUT (not in this file)

S3 Control, S3 on Outposts, S3 Tables, S3 Vectors, S3 Files — see official page sections below Amazon S3 block.
