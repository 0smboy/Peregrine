# S3 IN-contract inventory (W0-A)

- Date: 2026-08-18
- Official source: [Amazon S3 API Operations](https://docs.aws.amazon.com/AmazonS3/latest/API/API_Operations.html) — **Amazon S3 section only** (lines 7–122; excludes S3 Control, Outposts, Tables, Vectors, Files)
- Rust truth: `swift-rust/crates/swift-s3api/src/middleware.rs` (`UNSUPPORTED_SUBRESOURCES` empty after W3; WriteGetObjectResponse 501 via `x-amz-request-route`), `parse.rs` `extract_bucket_and_key` (empty key → `None`, slash-fix in tree)
- Live reference binary: proxy **catalog W3.1** `70405da7…` (W3 + select star/LIMIT only; projection/WHERE → 400). Frozen 57-case runner untouched. Live client matrix 2026-08-18 W3.1: **169/169 gate=PASS**.
- Score legend: **LIVE_PASS** = VIP client path (stored XML/JSON round-trip counts; select is `SELECT * FROM S3Object` plus optional `LIMIT n`; torrent is a generated single-file .torrent; CreateSession echoes TempAuth keys; RenameObject is copy+delete). **HONEST_501** = 501 NotImplemented non-empty XML; **FAIL** = fallthrough / no live case; **UNTESTED** = implemented, no live case

## Summary counts (after W3 live)

| Score | Count |
|---|---|
| LIVE_PASS | 115 |
| HONEST_501 | 1 |
| FAIL | 0 |
| UNTESTED | 0 |
| **Total IN** | **116** |

W3 moved metadata*, ABAC, annotation, CreateSession, RenameObject, SelectObjectContent (star-only), GetObjectTorrent, UpdateObjectEncryption → LIVE_PASS. Remaining honest 501 is **WriteGetObjectResponse** (Object Lambda). Not 116 LIVE_PASS.

## Action matrix

| Action | HTTP (method + path/query) | Rust today (handler / 501 list / fallthrough) | Expected score now | Notes |
|---|---|---|---|---|
| AbortMultipartUpload | DELETE `/{Key}?uploadId=` | `handle_mpu_abort` | LIVE_PASS | In frozen 57 MPU path |
| CompleteMultipartUpload | POST `/{Key}?uploadId=` | `handle_mpu_complete` | LIVE_PASS | Composite ETag; 57 |
| CopyObject | PUT `/{Key}` + `X-Amz-Copy-Source` | fallthrough → `apply_copy_source` + `translate_object_success` | LIVE_PASS | 57 copy case |
| CreateBucket | PUT `/{Bucket}` | fallthrough → Swift PUT container + `translate_bucket_success` | LIVE_PASS | 57 |
| CreateBucketMetadataConfiguration | PUT `/{Bucket}?metadataConfiguration` | `handle_stored_bucket_config` | LIVE_PASS | W3 sysmeta round-trip |
| CreateBucketMetadataTableConfiguration | PUT `/{Bucket}?metadataTableConfiguration` | `handle_stored_bucket_config` | LIVE_PASS | W3 sysmeta round-trip |
| CreateMultipartUpload | POST `/{Key}?uploads` | `handle_mpu_init` | LIVE_PASS | 57 MPU |
| CreateSession | GET\|HEAD\|POST `/{Bucket}?session` | `handle_create_session` | LIVE_PASS | Echoes caller TempAuth keys + 15min token; not S3 Express |
| DeleteBucket | DELETE `/{Bucket}` | fallthrough → Swift DELETE + `translate_bucket_success` | LIVE_PASS | 57 |
| DeleteBucketAnalyticsConfiguration | DELETE `/{Bucket}?analytics&id=` | `handle_stored_bucket_config` | LIVE_PASS | W2 sysmeta round-trip |
| DeleteBucketCors | DELETE `/{Bucket}?cors` | `handle_cors` | LIVE_PASS | Rust extra; live CORS path |
| DeleteBucketEncryption | DELETE `/{Bucket}?encryption` | `handle_stored_bucket_config` | LIVE_PASS | W2 sysmeta round-trip |
| DeleteBucketIntelligentTieringConfiguration | DELETE `/{Bucket}?intelligent-tiering&id=` | `handle_stored_bucket_config` | LIVE_PASS | W2 sysmeta round-trip |
| DeleteBucketInventoryConfiguration | DELETE `/{Bucket}?inventory&id=` | `handle_stored_bucket_config` | LIVE_PASS | W2 sysmeta round-trip |
| DeleteBucketLifecycle | DELETE `/{Bucket}?lifecycle` | `handle_lifecycle` | LIVE_PASS | 57 lifecycle |
| DeleteBucketMetadataConfiguration | DELETE `/{Bucket}?metadataConfiguration` | `handle_stored_bucket_config` | LIVE_PASS | W3 sysmeta round-trip |
| DeleteBucketMetadataTableConfiguration | DELETE `/{Bucket}?metadataTableConfiguration` | `handle_stored_bucket_config` | LIVE_PASS | W3 sysmeta round-trip |
| DeleteBucketMetricsConfiguration | DELETE `/{Bucket}?metrics&id=` | `handle_stored_bucket_config` | LIVE_PASS | W2 sysmeta round-trip |
| DeleteBucketOwnershipControls | DELETE `/{Bucket}?ownershipControls` | `handle_stored_bucket_config` | LIVE_PASS | W2 sysmeta round-trip |
| DeleteBucketPolicy | DELETE `/{Bucket}?policy` | `handle_stored_bucket_config` | LIVE_PASS | W2 sysmeta round-trip |
| DeleteBucketReplication | DELETE `/{Bucket}?replication` | `handle_stored_bucket_config` | LIVE_PASS | W2 sysmeta round-trip |
| DeleteBucketTagging | DELETE `/{Bucket}?tagging` | `handle_tagging` (bucket) | LIVE_PASS | 57 read path; DELETE implemented |
| DeleteBucketWebsite | DELETE `/{Bucket}?website` | `handle_stored_bucket_config` | LIVE_PASS | W2 sysmeta round-trip |
| DeleteObject | DELETE `/{Key}` [`?versionId=`] | fallthrough or `handle_versioned_delete` | LIVE_PASS | 57 |
| DeleteObjectAnnotation | DELETE `/{Key}?annotation` | object sysmeta blob | LIVE_PASS | W3 object sysmeta |
| DeleteObjects | POST `/{Bucket}?delete` | `handle_multi_delete` | LIVE_PASS | 57 multi-delete |
| DeleteObjectTagging | DELETE `/{Key}?tagging` | `handle_tagging` (object DELETE) | LIVE_PASS | Implemented; not in frozen 57 |
| DeletePublicAccessBlock | DELETE `/?publicAccessBlock` | `handle_stored_bucket_config` | LIVE_PASS | W2 sysmeta round-trip |
| GetBucketAbac | GET `/{Bucket}?abac` | `handle_stored_bucket_config` | LIVE_PASS | W3 sysmeta round-trip |
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
| GetBucketMetadataConfiguration | GET `/{Bucket}?metadataConfiguration` | `handle_stored_bucket_config` | LIVE_PASS | W3 sysmeta round-trip |
| GetBucketMetadataTableConfiguration | GET `/{Bucket}?metadataTableConfiguration` | `handle_stored_bucket_config` | LIVE_PASS | W3 sysmeta round-trip |
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
| GetObjectAnnotation | GET `/{Key}?annotation` | object sysmeta blob | LIVE_PASS | W3 object sysmeta; missing → NoSuchConfiguration |
| GetObjectAttributes | GET `/{Key}?attributes` | **fallthrough** | LIVE_PASS | Not in 501 list |
| GetObjectLegalHold | GET `/{Key}?legal-hold` [`?versionId=`] | `handle_legal_hold` | LIVE_PASS | WORM canary path |
| GetObjectLockConfiguration | GET `/{Bucket}?object-lock` | `handle_object_lock` | LIVE_PASS | Bucket object-lock config |
| GetObjectRetention | GET `/{Key}?retention` [`?versionId=`] | `handle_retention` | LIVE_PASS | WORM canary |
| GetObjectTagging | GET `/{Key}?tagging` | `handle_tagging` (object GET) | LIVE_PASS | 57 read |
| GetObjectTorrent | GET `/{Key}?torrent` | `handle_object_torrent` | LIVE_PASS | Generated single-file .torrent; no tracker |
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
| ListObjectAnnotations | GET `/{Key}?annotation` (list) | object sysmeta blob | LIVE_PASS | W3 object sysmeta |
| ListObjects | GET `/{Bucket}` [`/{Bucket}/`] | fallthrough → `translate_list_objects` | LIVE_PASS | Slash-fix `0354d1aa`: `/bucket/` lists not GetObject "" |
| ListObjectsV2 | GET `/{Bucket}?list-type=2` [`/{Bucket}/?list-type=2`] | fallthrough → `translate_list_objects_v2` | LIVE_PASS | Same slash dependency |
| ListObjectVersions | GET `/{Bucket}?versions` | `handle_list_versions` | LIVE_PASS | 57 versions |
| ListParts | GET `/{Key}?uploadId=` | `handle_mpu_list_parts` | LIVE_PASS | 57 MPU |
| PutBucketAbac | PUT `/{Bucket}?abac` | `handle_stored_bucket_config` | LIVE_PASS | W3 sysmeta round-trip |
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
| PutObjectAnnotation | PUT `/{Key}?annotation` | object sysmeta blob | LIVE_PASS | W3 object sysmeta |
| PutObjectLegalHold | PUT `/{Key}?legal-hold` | `handle_legal_hold` | LIVE_PASS | WORM canary |
| PutObjectLockConfiguration | PUT `/{Bucket}?object-lock` | `handle_object_lock` | LIVE_PASS | Bucket config |
| PutObjectRetention | PUT `/{Key}?retention` | `handle_retention` | LIVE_PASS | WORM canary |
| PutObjectTagging | PUT `/{Key}?tagging` | `handle_tagging` (object PUT) | LIVE_PASS | Implemented; supplement only |
| PutPublicAccessBlock | PUT `/?publicAccessBlock` | `handle_stored_bucket_config` | LIVE_PASS | W2 sysmeta round-trip |
| RenameObject | POST `/{Key}` + `x-amz-rename-source` | `handle_rename_object` | LIVE_PASS | Copy then delete; 204; not atomic S3 Express |
| RestoreObject | POST `/{Key}?restore` | `handle_restore` | LIVE_PASS | Honest `400 InvalidObjectState` when cold off |
| SelectObjectContent | POST `/{Key}?select` | `handle_select_object` | LIVE_PASS | `SELECT * FROM S3Object` [LIMIT n] event-stream; projection/WHERE → 400 |
| UpdateBucketMetadataAnnotationTableConfiguration | PUT `/{Bucket}?metadataAnnotationTableConfiguration` | `handle_stored_bucket_config` | LIVE_PASS | W3 sysmeta round-trip |
| UpdateBucketMetadataInventoryTableConfiguration | PUT `/{Bucket}?metadataInventoryTableConfiguration` | `handle_stored_bucket_config` | LIVE_PASS | W3 sysmeta round-trip |
| UpdateBucketMetadataJournalTableConfiguration | PUT `/{Bucket}?metadataJournalTableConfiguration` | `handle_stored_bucket_config` | LIVE_PASS | W3 sysmeta round-trip |
| UpdateObjectEncryption | PUT `/{Key}?encryption` | object sysmeta blob | LIVE_PASS | W3 object sysmeta; missing GET → ServerSideEncryptionConfigurationNotFoundError |
| UploadPart | PUT `/{Key}?partNumber=&uploadId=` | `handle_mpu_part` | LIVE_PASS | 57 MPU |
| UploadPartCopy | PUT `/{Key}?partNumber=&uploadId=` + `X-Amz-Copy-Source` | `handle_mpu_part_copy` | LIVE_PASS | Copy-source + optional range; live W1+ |
| WriteGetObjectResponse | POST + `x-amz-request-route` | header 501 before account-root 405 | HONEST_501 | Object Lambda; no engine; stays 501 |

## Remaining HONEST_501 (1)

1. WriteGetObjectResponse (`x-amz-request-route`) — Object Lambda WriteGetObjectResponse. No Lambda runtime on this fleet.

### Honesty notes

- Bucket configs (including metadata*/ABAC) are **sysmeta XML/JSON round-trip**, not SSE, replication, website hosting, analytics jobs, or S3 Metadata tables.
- Select is **`SELECT * FROM S3Object` plus optional `LIMIT n`**, not a SQL engine. Projection and WHERE return 400.
- Torrent is a generated single-file `.torrent` with no tracker.
- CreateSession echoes existing TempAuth keys plus a 15-minute `peregrine-session` token.
- RenameObject is GET+PUT+DELETE, not an atomic S3 Express rename.
- Object annotation and object encryption are object sysmeta blobs.
- `ListDirectoryBuckets` returns an empty `ListDirectoryBucketsResult` and does not hop Swift. It is not S3 Express.
- Slash-empty-key filter (`parse.rs`) must stay: path-style `GET /{Bucket}/` lists; regression reopens s3cmd 204 empty-body FAIL.

## UNTESTED

None after W3 live matrix.

## OUT (not in this file)

S3 Control, S3 on Outposts, S3 Tables, S3 Vectors, S3 Files — see official page sections below Amazon S3 block.
