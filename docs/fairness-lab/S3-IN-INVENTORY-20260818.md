# S3 IN-contract inventory (W0-A)

- Date: 2026-08-18
- Official source: [Amazon S3 API Operations](https://docs.aws.amazon.com/AmazonS3/latest/API/API_Operations.html) — **Amazon S3 section only** (lines 7–122; excludes S3 Control, Outposts, Tables, Vectors, Files)
- Rust truth: `swift-rust/crates/swift-s3api/src/middleware.rs` (`UNSUPPORTED_SUBRESOURCES` ~441, dispatch ~1840–2402), `parse.rs` `extract_bucket_and_key` (empty key → `None`, slash-fix in tree)
- Live reference binary: proxy **catalog W1** `ded3b7a4…` (slash-fix + UploadPartCopy + PolicyStatus + ObjectAttributes + leak 501s). Frozen 57-case runner untouched. Live client matrix 2026-08-18 W1: **99/99 gate=PASS**.
- Score legend: **LIVE_PASS** = VIP client path; **HONEST_501** = 501 NotImplemented non-empty XML; **FAIL** = fallthrough / no live case; **UNTESTED** = implemented, no live case

## Summary counts (after W1 live)

| Score | Count |
|---|---|
| LIVE_PASS | 50 |
| HONEST_501 | 62 |
| FAIL | 4 |
| UNTESTED | 0 |
| **Total IN** | **116** |

W1 moved: UploadPartCopy / GetBucketPolicyStatus / GetObjectAttributes / tagging writes / PutObjectAcl → LIVE_PASS. intelligent-tiering + W4 query/header leaks → HONEST_501. Remaining FAIL: `ListDirectoryBuckets`, `UpdateBucketMetadataAnnotationTableConfiguration`, `UpdateBucketMetadataInventoryTableConfiguration`, `UpdateBucketMetadataJournalTableConfiguration`.

## Action matrix

| Action | HTTP (method + path/query) | Rust today (handler / 501 list / fallthrough) | Expected score now | Notes |
|---|---|---|---|---|
| AbortMultipartUpload | DELETE `/{Key}?uploadId=` | `handle_mpu_abort` | LIVE_PASS | In frozen 57 MPU path |
| CompleteMultipartUpload | POST `/{Key}?uploadId=` | `handle_mpu_complete` | LIVE_PASS | Composite ETag; 57 |
| CopyObject | PUT `/{Key}` + `X-Amz-Copy-Source` | fallthrough → `apply_copy_source` + `translate_object_success` | LIVE_PASS | 57 copy case |
| CreateBucket | PUT `/{Bucket}` | fallthrough → Swift PUT container + `translate_bucket_success` | LIVE_PASS | 57 |
| CreateBucketMetadataConfiguration | PUT `/{Bucket}?metadataConfiguration` | **fallthrough** → Swift | FAIL | W4 metadata; no guard; silent Swift hop |
| CreateBucketMetadataTableConfiguration | PUT `/{Bucket}?metadataTableConfiguration` | **fallthrough** | FAIL | W4 metadata table |
| CreateMultipartUpload | POST `/{Key}?uploads` | `handle_mpu_init` | LIVE_PASS | 57 MPU |
| CreateSession | POST `/?session` (CreateSession) | **fallthrough** → Swift account | FAIL | Directory/express session; no handler |
| DeleteBucket | DELETE `/{Bucket}` | fallthrough → Swift DELETE + `translate_bucket_success` | LIVE_PASS | 57 |
| DeleteBucketAnalyticsConfiguration | DELETE `/{Bucket}?analytics&id=` | `UNSUPPORTED_SUBRESOURCES` → `not_implemented_subresource` | HONEST_501 | `analytics` in 501 list |
| DeleteBucketCors | DELETE `/{Bucket}?cors` | `handle_cors` | LIVE_PASS | Rust extra; live CORS path |
| DeleteBucketEncryption | DELETE `/{Bucket}?encryption` | `UNSUPPORTED_SUBRESOURCES` | HONEST_501 | `encryption` in 501 list |
| DeleteBucketIntelligentTieringConfiguration | DELETE `/{Bucket}?intelligent-tiering&id=` | **fallthrough** | FAIL | Not in 501 list; leaks to Swift |
| DeleteBucketInventoryConfiguration | DELETE `/{Bucket}?inventory&id=` | `UNSUPPORTED_SUBRESOURCES` | HONEST_501 | `inventory` in 501 list |
| DeleteBucketLifecycle | DELETE `/{Bucket}?lifecycle` | `handle_lifecycle` | LIVE_PASS | 57 lifecycle |
| DeleteBucketMetadataConfiguration | DELETE `/{Bucket}?metadataConfiguration` | **fallthrough** | FAIL | W4 metadata |
| DeleteBucketMetadataTableConfiguration | DELETE `/{Bucket}?metadataTableConfiguration` | **fallthrough** | FAIL | W4 metadata table |
| DeleteBucketMetricsConfiguration | DELETE `/{Bucket}?metrics&id=` | `UNSUPPORTED_SUBRESOURCES` | HONEST_501 | `metrics` in 501 list |
| DeleteBucketOwnershipControls | DELETE `/{Bucket}?ownershipControls` | `UNSUPPORTED_SUBRESOURCES` | HONEST_501 | `ownershipControls` in 501 list |
| DeleteBucketPolicy | DELETE `/{Bucket}?policy` | `UNSUPPORTED_SUBRESOURCES` | HONEST_501 | `policy` in 501 list |
| DeleteBucketReplication | DELETE `/{Bucket}?replication` | `UNSUPPORTED_SUBRESOURCES` | HONEST_501 | `replication` in 501 list |
| DeleteBucketTagging | DELETE `/{Bucket}?tagging` | `handle_tagging` (bucket) | LIVE_PASS | 57 read path; DELETE implemented |
| DeleteBucketWebsite | DELETE `/{Bucket}?website` | `UNSUPPORTED_SUBRESOURCES` | HONEST_501 | `website` in 501 list |
| DeleteObject | DELETE `/{Key}` [`?versionId=`] | fallthrough or `handle_versioned_delete` | LIVE_PASS | 57 |
| DeleteObjectAnnotation | DELETE `/{Key}?annotation` | **fallthrough** | FAIL | W4 annotations |
| DeleteObjects | POST `/{Bucket}?delete` | `handle_multi_delete` | LIVE_PASS | 57 multi-delete |
| DeleteObjectTagging | DELETE `/{Key}?tagging` | `handle_tagging` (object DELETE) | UNTESTED | Implemented; not in frozen 57 |
| DeletePublicAccessBlock | DELETE `/?publicAccessBlock` | `UNSUPPORTED_SUBRESOURCES` | HONEST_501 | `publicAccessBlock` in 501 list |
| GetBucketAbac | GET `/{Bucket}?abac` | **fallthrough** | FAIL | W4 ABAC |
| GetBucketAccelerateConfiguration | GET `/{Bucket}?accelerate` | `UNSUPPORTED_SUBRESOURCES` | HONEST_501 | `accelerate` in 501 list |
| GetBucketAcl | GET `/{Bucket}?acl` | `handle_acl` | LIVE_PASS | 57 |
| GetBucketAnalyticsConfiguration | GET `/{Bucket}?analytics&id=` | `UNSUPPORTED_SUBRESOURCES` | HONEST_501 | `analytics` in 501 list |
| GetBucketCors | GET `/{Bucket}?cors` | `handle_cors` | LIVE_PASS | Rust extra; live |
| GetBucketEncryption | GET `/{Bucket}?encryption` | `UNSUPPORTED_SUBRESOURCES` | HONEST_501 | `encryption` in 501 list |
| GetBucketIntelligentTieringConfiguration | GET `/{Bucket}?intelligent-tiering&id=` | **fallthrough** | FAIL | Not in 501 list |
| GetBucketInventoryConfiguration | GET `/{Bucket}?inventory&id=` | `UNSUPPORTED_SUBRESOURCES` | HONEST_501 | `inventory` in 501 list |
| GetBucketLifecycle | GET `/{Bucket}?lifecycle` | `handle_lifecycle` | LIVE_PASS | Alias of lifecycle config; 57 |
| GetBucketLifecycleConfiguration | GET `/{Bucket}?lifecycle` | `handle_lifecycle` | LIVE_PASS | Same handler as lifecycle |
| GetBucketLocation | GET `/{Bucket}?location` | local `location_constraint_xml` (no Swift) | LIVE_PASS | 57 |
| GetBucketLogging | GET `/{Bucket}?logging` | `UNSUPPORTED_SUBRESOURCES` | HONEST_501 | `logging` in 501 list |
| GetBucketMetadataConfiguration | GET `/{Bucket}?metadataConfiguration` | **fallthrough** | FAIL | W4 metadata |
| GetBucketMetadataTableConfiguration | GET `/{Bucket}?metadataTableConfiguration` | **fallthrough** | FAIL | W4 metadata table |
| GetBucketMetricsConfiguration | GET `/{Bucket}?metrics&id=` | `UNSUPPORTED_SUBRESOURCES` | HONEST_501 | `metrics` in 501 list |
| GetBucketNotification | GET `/{Bucket}?notification` | `UNSUPPORTED_SUBRESOURCES` | HONEST_501 | `notification` in 501 list |
| GetBucketNotificationConfiguration | GET `/{Bucket}?notification` | `UNSUPPORTED_SUBRESOURCES` | HONEST_501 | Same subresource key |
| GetBucketOwnershipControls | GET `/{Bucket}?ownershipControls` | `UNSUPPORTED_SUBRESOURCES` | HONEST_501 | `ownershipControls` in 501 list |
| GetBucketPolicy | GET `/{Bucket}?policy` | `UNSUPPORTED_SUBRESOURCES` | HONEST_501 | `policy` in 501 list |
| GetBucketPolicyStatus | GET `/{Bucket}?policyStatus` | **fallthrough** | FAIL | `policyStatus` ≠ `policy`; no 501 guard |
| GetBucketReplication | GET `/{Bucket}?replication` | `UNSUPPORTED_SUBRESOURCES` | HONEST_501 | `replication` in 501 list |
| GetBucketRequestPayment | GET `/{Bucket}?requestPayment` | `UNSUPPORTED_SUBRESOURCES` | HONEST_501 | `requestPayment` in 501 list |
| GetBucketTagging | GET `/{Bucket}?tagging` | `handle_tagging` (bucket GET) | LIVE_PASS | 57 read |
| GetBucketVersioning | GET `/{Bucket}?versioning` | `handle_versioning` | LIVE_PASS | 57 |
| GetBucketWebsite | GET `/{Bucket}?website` | `UNSUPPORTED_SUBRESOURCES` | HONEST_501 | `website` in 501 list |
| GetObject | GET `/{Key}` [`?versionId=`] | fallthrough or `handle_versioned_get_head` | LIVE_PASS | 57 |
| GetObjectAcl | GET `/{Key}?acl` | `handle_acl` | LIVE_PASS | 57 read |
| GetObjectAnnotation | GET `/{Key}?annotation` | **fallthrough** | FAIL | W4 annotations |
| GetObjectAttributes | GET `/{Key}?attributes` | **fallthrough** | FAIL | Not in 501 list |
| GetObjectLegalHold | GET `/{Key}?legal-hold` [`?versionId=`] | `handle_legal_hold` | LIVE_PASS | WORM canary path |
| GetObjectLockConfiguration | GET `/{Bucket}?object-lock` | `handle_object_lock` | LIVE_PASS | Bucket object-lock config |
| GetObjectRetention | GET `/{Key}?retention` [`?versionId=`] | `handle_retention` | LIVE_PASS | WORM canary |
| GetObjectTagging | GET `/{Key}?tagging` | `handle_tagging` (object GET) | LIVE_PASS | 57 read |
| GetObjectTorrent | GET `/{Key}?torrent` | `UNSUPPORTED_SUBRESOURCES` | HONEST_501 | `torrent` in 501 list |
| GetPublicAccessBlock | GET `/?publicAccessBlock` | `UNSUPPORTED_SUBRESOURCES` | HONEST_501 | `publicAccessBlock` in 501 list |
| HeadBucket | HEAD `/{Bucket}` [`/{Bucket}/`] | fallthrough `for_list` + `translate_bucket_success` | LIVE_PASS | Trailing slash → bucket via parse fix |
| HeadObject | HEAD `/{Key}` [`?versionId=`] | fallthrough or versioned GET/HEAD | LIVE_PASS | 57 |
| ListBucketAnalyticsConfigurations | GET `/{Bucket}?analytics` | `UNSUPPORTED_SUBRESOURCES` | HONEST_501 | `analytics` list prefix |
| ListBucketIntelligentTieringConfigurations | GET `/{Bucket}?intelligent-tiering` | **fallthrough** | FAIL | Not in 501 list |
| ListBucketInventoryConfigurations | GET `/{Bucket}?inventory` | `UNSUPPORTED_SUBRESOURCES` | HONEST_501 | `inventory` list |
| ListBucketMetricsConfigurations | GET `/{Bucket}?metrics` | `UNSUPPORTED_SUBRESOURCES` | HONEST_501 | `metrics` list |
| ListBuckets | GET `/` | fallthrough → `translate_list_buckets` | LIVE_PASS | 57; account GET JSON |
| ListDirectoryBuckets | GET `/?x-id=ListDirectoryBuckets` | **fallthrough** → Swift account | FAIL | Directory buckets; no handler |
| ListMultipartUploads | GET `/{Bucket}?uploads` | `handle_list_multipart_uploads` | LIVE_PASS | 57 MPU list |
| ListObjectAnnotations | GET `/{Key}?annotation` (list) | **fallthrough** | FAIL | W4 annotations |
| ListObjects | GET `/{Bucket}` [`/{Bucket}/`] | fallthrough → `translate_list_objects` | LIVE_PASS | Slash-fix `0354d1aa`: `/bucket/` lists not GetObject "" |
| ListObjectsV2 | GET `/{Bucket}?list-type=2` [`/{Bucket}/?list-type=2`] | fallthrough → `translate_list_objects_v2` | LIVE_PASS | Same slash dependency |
| ListObjectVersions | GET `/{Bucket}?versions` | `handle_list_versions` | LIVE_PASS | 57 versions |
| ListParts | GET `/{Key}?uploadId=` | `handle_mpu_list_parts` | LIVE_PASS | 57 MPU |
| PutBucketAbac | PUT `/{Bucket}?abac` | **fallthrough** | FAIL | W4 ABAC |
| PutBucketAccelerateConfiguration | PUT `/{Bucket}?accelerate` | `UNSUPPORTED_SUBRESOURCES` | HONEST_501 | `accelerate` in 501 list |
| PutBucketAcl | PUT `/{Bucket}?acl` | `handle_acl` | LIVE_PASS | 57 |
| PutBucketAnalyticsConfiguration | PUT `/{Bucket}?analytics&id=` | `UNSUPPORTED_SUBRESOURCES` | HONEST_501 | `analytics` in 501 list |
| PutBucketCors | PUT `/{Bucket}?cors` | `handle_cors` | LIVE_PASS | Rust extra; live |
| PutBucketEncryption | PUT `/{Bucket}?encryption` | `UNSUPPORTED_SUBRESOURCES` | HONEST_501 | `encryption` in 501 list |
| PutBucketIntelligentTieringConfiguration | PUT `/{Bucket}?intelligent-tiering&id=` | **fallthrough** | FAIL | Not in 501 list |
| PutBucketInventoryConfiguration | PUT `/{Bucket}?inventory&id=` | `UNSUPPORTED_SUBRESOURCES` | HONEST_501 | `inventory` in 501 list |
| PutBucketLifecycle | PUT `/{Bucket}?lifecycle` | `handle_lifecycle` | LIVE_PASS | Legacy name; same handler |
| PutBucketLifecycleConfiguration | PUT `/{Bucket}?lifecycle` | `handle_lifecycle` | LIVE_PASS | 57 lifecycle |
| PutBucketLogging | PUT `/{Bucket}?logging` | `UNSUPPORTED_SUBRESOURCES` | HONEST_501 | `logging` in 501 list |
| PutBucketMetricsConfiguration | PUT `/{Bucket}?metrics&id=` | `UNSUPPORTED_SUBRESOURCES` | HONEST_501 | `metrics` in 501 list |
| PutBucketNotification | PUT `/{Bucket}?notification` | `UNSUPPORTED_SUBRESOURCES` | HONEST_501 | `notification` in 501 list |
| PutBucketNotificationConfiguration | PUT `/{Bucket}?notification` | `UNSUPPORTED_SUBRESOURCES` | HONEST_501 | Same subresource key |
| PutBucketOwnershipControls | PUT `/{Bucket}?ownershipControls` | `UNSUPPORTED_SUBRESOURCES` | HONEST_501 | `ownershipControls` in 501 list |
| PutBucketPolicy | PUT `/{Bucket}?policy` | `UNSUPPORTED_SUBRESOURCES` | HONEST_501 | `policy` in 501 list |
| PutBucketReplication | PUT `/{Bucket}?replication` | `UNSUPPORTED_SUBRESOURCES` | HONEST_501 | `replication` in 501 list |
| PutBucketRequestPayment | PUT `/{Bucket}?requestPayment` | `UNSUPPORTED_SUBRESOURCES` | HONEST_501 | `requestPayment` in 501 list |
| PutBucketTagging | PUT `/{Bucket}?tagging` | `handle_tagging` (bucket PUT) | UNTESTED | Implemented; supplement only, not frozen 57 |
| PutBucketVersioning | PUT `/{Bucket}?versioning` | `handle_versioning` | LIVE_PASS | 57 |
| PutBucketWebsite | PUT `/{Bucket}?website` | `UNSUPPORTED_SUBRESOURCES` | HONEST_501 | `website` in 501 list |
| PutObject | PUT `/{Key}` | fallthrough or `handle_versioned_put` | LIVE_PASS | 57 |
| PutObjectAcl | PUT `/{Key}?acl` | `handle_acl` | UNTESTED | Implemented; RUST_AHEAD extra vs frozen 57 |
| PutObjectAnnotation | PUT `/{Key}?annotation` | **fallthrough** | FAIL | W4 annotations |
| PutObjectLegalHold | PUT `/{Key}?legal-hold` | `handle_legal_hold` | LIVE_PASS | WORM canary |
| PutObjectLockConfiguration | PUT `/{Bucket}?object-lock` | `handle_object_lock` | LIVE_PASS | Bucket config |
| PutObjectRetention | PUT `/{Key}?retention` | `handle_retention` | LIVE_PASS | WORM canary |
| PutObjectTagging | PUT `/{Key}?tagging` | `handle_tagging` (object PUT) | UNTESTED | Implemented; supplement only |
| PutPublicAccessBlock | PUT `/?publicAccessBlock` | `UNSUPPORTED_SUBRESOURCES` | HONEST_501 | `publicAccessBlock` in 501 list |
| RenameObject | POST `/{Key}?rename` | **fallthrough** | FAIL | W4 rename; no handler |
| RestoreObject | POST `/{Key}?restore` | `handle_restore` | LIVE_PASS | Honest `400 InvalidObjectState` when cold off |
| SelectObjectContent | POST `/{Key}?select&select-type=2` | `UNSUPPORTED_SUBRESOURCES` | HONEST_501 | `select` in 501 list |
| UpdateBucketMetadataAnnotationTableConfiguration | PUT `/{Bucket}?metadataTableConfiguration` (update) | **fallthrough** | FAIL | W4 metadata tables |
| UpdateBucketMetadataInventoryTableConfiguration | PUT `/{Bucket}?metadataTableConfiguration` | **fallthrough** | FAIL | W4 metadata tables |
| UpdateBucketMetadataJournalTableConfiguration | PUT `/{Bucket}?metadataTableConfiguration` | **fallthrough** | FAIL | W4 metadata tables |
| UpdateObjectEncryption | PUT `/{Key}?encryption` | `UNSUPPORTED_SUBRESOURCES` | HONEST_501 | `encryption` query matches 501 list |
| UploadPart | PUT `/{Key}?partNumber=&uploadId=` | `handle_mpu_part` | LIVE_PASS | 57 MPU |
| UploadPartCopy | PUT `/{Key}?partNumber=&uploadId=` + `X-Amz-Copy-Source` | `handle_mpu_part` (**no** `apply_copy_source`) | FAIL | MPU path ignores copy source; wrong semantics |
| WriteGetObjectResponse | POST Object Lambda route | **fallthrough** / not routed | FAIL | Object Lambda response path absent |

## FAIL / fallthrough risk register (26)

These must get red matrix cases in W0-B before any PASS claim:

1. CreateBucketMetadataConfiguration
2. CreateBucketMetadataTableConfiguration
3. CreateSession
4. DeleteBucketIntelligentTieringConfiguration
5. DeleteBucketMetadataConfiguration
6. DeleteBucketMetadataTableConfiguration
7. GetBucketAbac
8. GetBucketIntelligentTieringConfiguration
9. GetBucketMetadataConfiguration
10. GetBucketMetadataTableConfiguration
11. GetBucketPolicyStatus
12. GetObjectAnnotation
13. GetObjectAttributes
14. ListBucketIntelligentTieringConfigurations
15. ListDirectoryBuckets
16. ListObjectAnnotations
17. PutBucketAbac
18. PutBucketIntelligentTieringConfiguration
19. PutObjectAnnotation
20. DeleteObjectAnnotation
21. RenameObject
22. UpdateBucketMetadataAnnotationTableConfiguration
23. UpdateBucketMetadataInventoryTableConfiguration
24. UpdateBucketMetadataJournalTableConfiguration
25. UploadPartCopy
26. WriteGetObjectResponse

### Cross-cutting fallthrough patterns

- **`intelligent-tiering`**: four List/Get/Put/Delete config actions miss `UNSUPPORTED_SUBRESOURCES`; requests hit Swift container/object APIs.
- **`policyStatus`**: distinct from `policy`; bypasses 501 guard.
- **W4 metadata / ABAC / annotations / rename / directory / session / Object Lambda**: no dispatch arm; default Swift translation.
- **UploadPartCopy**: MPU branch never calls `apply_copy_source` (~5347 `handle_mpu_part`).
- **List empty-body risk (mitigated on `0354d1aa`)**: path-style `GET /{Bucket}/` must stay bucket-list (`parse.rs` empty-key filter); regression reopens s3cmd 204 empty-body FAIL.

## UNTESTED (4) — implement before matrix, add live case in W0-B

| Action | Handler |
|---|---|
| PutBucketTagging | `handle_tagging` bucket PUT |
| PutObjectTagging | `handle_tagging` object PUT |
| DeleteObjectTagging | `handle_tagging` object DELETE |
| PutObjectAcl | `handle_acl` object PUT |

## OUT (not in this file)

S3 Control, S3 on Outposts, S3 Tables, S3 Vectors, S3 Files — see official page sections below Amazon S3 block.
