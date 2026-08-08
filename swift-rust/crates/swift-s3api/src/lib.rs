// Copyright (c) 2026 OpenStack Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Core of the S3 API translation layer, ported from
//! `swift/common/middleware/s3api/`.
//!
//! # Production surface (Wave 3)
//!
//! [`middleware::S3Api`]: SigV4 + CRUD + ListObjects v1/v2 + MultiDelete +
//! basic ACL/CORS + multipart upload (segments + SLO complete). Enable via
//! `pipeline = … s3api tempauth …` (or s3token + keystoneauth). Does **not**
//! register on Swift `GET /info`.
//!
//! # Residuals / stable rejections
//!
//! These return a **stable** S3 `501 NotImplemented` XML body (unit-tested)
//! rather than falling through to non-S3 filters:
//!
//! * **SigV2** auth (`Authorization: AWS …` / `AWSAccessKeyId`) — **IMPLEMENTED**
//!   (HMAC-SHA1 + Base64; header + query; see [`sigv2`])
//!
//! **aws-chunked / STREAMING-*** (`Content-Encoding: aws-chunked` and/or
//! `X-Amz-Content-SHA256: STREAMING-*`) is **implemented**: framed PUT/POST
//! bodies are dechunked after SigV4 header verify; decoded bytes go to the
//! backend with fixed `Content-Length`. When the mode is
//! `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` / `*-TRAILER` and credentials are
//! available, **per-chunk HMAC signatures are enforced** (mismatch →
//! `SignatureDoesNotMatch`). For `*-PAYLOAD-TRAILER`, **trailer HMAC**
//! (`x-amz-trailer-signature` / `AWS4-HMAC-SHA256-TRAILER`) is enforced when
//! trailer content is present. `STREAMING-UNSIGNED-PAYLOAD-TRAILER` dechunks
//! without requiring signatures.
//!
//! # Subresource config APIs (meta round-trip)
//!
//! * **versioning** GET/PUT — `Enabled`|`Suspended` in container meta
//! * **tagging** GET/PUT/DELETE on bucket and object
//! * **lifecycle** GET/PUT/DELETE — raw LifecycleConfiguration XML round-trip
//! * **lifecycle execution** — object PUT stamps Swift `X-Delete-At` from
//!   Enabled Expiration Days/Date (+ Prefix); Transition stamps
//!   `X-Object-Meta-S3-Storage-Class` + `X-Object-Sysmeta-S3-Transition-At`
//!   (**metadata only**, no tiering backend — LAB-HARD-GREEN); MPU init stamps
//!   `X-Delete-At` on the upload marker from AbortIncompleteMultipartUpload
//!   DaysAfterInitiation; see [`lifecycle_exec`]
//! * **object-lock** GET/PUT — raw ObjectLockConfiguration XML round-trip
//! * **legal-hold** / **retention** object GET/PUT + WORM on DELETE/overwrite
//!   (see [`object_lock_worm`])
//! * **versions** list — `ListVersionsResult` from `{bucket}+versions` indexes
//! * **multi-version object data plane** when versioning is **Enabled**
//!   ([`versioning_store`]): archive, delete-markers, `?versionId=` GET/DELETE
//!
//! **Object Lock governance bypass** (`x-amz-bypass-governance-retention`) is
//! **IMPLEMENTED** for mode=`GOVERNANCE` only; COMPLIANCE + legal-hold still
//! hard-block (see [`object_lock_worm::worm_blocks_delete_with_bypass`]).
//!
//! Other residuals (not claimable as implemented):
//!
//! * lifecycle tag / And filters
//! * physical Glacier/tape via storage-policy map is claimable unit surface
//!   ([`cold_tier`]); requires operator policy map conf
//! * multi-tenant IAM policy engine ([`iam::IamService`]) + IdentityDirectory.
//!   Grant headers + ACP
//!   XML body store/GET round-trip **is** claimable (JSON sysmeta + container
//!   AllUsers mapping); canned `x-amz-acl` still works and wins if both present.
//!   **Object ACP grant enforcement on GET/HEAD** (LAB-HARD-GREEN): when
//!   `S3_OBJECT_ACL_JSON_META` has non-empty grants, principal (`access_key` /
//!   account) must be owner or hold READ/FULL_CONTROL else `AccessDenied`;
//!   owner always OK; missing/empty grants → no new denial. AllUsers READ does
//!   **not** by itself authorize anonymous unauthenticated Swift GET —
//!   container ACL still gates; unauthenticated traffic never enters SigV4
//!   grant evaluation.
//! * authenticated-read / log-delivery-write canned ACLs (Python NotImplemented)
//! * CORS ExposeHeader edge cases in live preflight
//! * clock-skew/expiry enforcement on every path
//! * requiring `x-amz-trailer-signature` when PAYLOAD-TRAILER mode has an
//!   *empty* trailer block (we only enforce when trailer lines are present);
//!   full AWS multi-chunk trailer golden-vector e2e against live S3 is not
//!   re-run in CI (unit vector for trailer hash + round-trip HMAC is covered)
//!
//! Unknown access keys (EC2 / Keystone) are deferred via an optional
//! [`swift_middleware::S3TokenClient`] on [`middleware::S3Api`] (inline
//! `/v3/s3tokens` exchange with a real base64 string-to-sign). The
//! `s3token` pipeline filter remains available for environ-style stamped
//! auth details.

pub mod acl_cors;
pub mod aws_chunked;
pub mod bucket_config;
pub mod cold_tier;
pub mod crypto;
pub mod delete;
pub mod iam;
pub mod lifecycle_exec;
pub mod middleware;
pub mod mpu;
pub mod object_lock_worm;
pub mod parse;
pub mod response;
pub mod sigv2;
pub mod sigv4;
pub mod versioning_store;
pub mod xml;

pub use middleware::{
    as_middleware, credentials_from_tempauth_users, S3Api, S3Credential,
};
pub use parse::{
    extract_bucket_and_key, parse_host, s3_to_swift_path, validate_bucket_name, MULTIUPLOAD_SUFFIX,
};
pub use response::{
    copy_object_result_xml, delete_object_response, delete_result_xml, error_status_and_message,
    list_all_my_buckets_xml, object_metadata_response, put_object_response, s3_error_response,
    s3_error_xml, BucketInfo, DeleteError, ListBucketResult, ListBucketResultV2, Owner, S3Object,
};
pub use sigv2::{
    compute_signature_v2, is_sigv2_auth, parse_sigv2_auth, string_to_sign_v2, verify_sigv2,
    SigV2Auth,
};
pub use sigv4::{
    amz_date, canonical_query, canonical_request, canonical_uri, compute_signature,
    headers_to_sign, parse_authorization_header, parse_credential, parse_query_authentication,
    parse_sigv4_auth, payload_hash, signing_key, string_to_sign, string_to_sign_for_request,
    verify_sigv4, CredentialScope, SigV4Auth, ALGORITHM, SERVICE,
};
pub use xml::{Element, XMLNS_S3};
