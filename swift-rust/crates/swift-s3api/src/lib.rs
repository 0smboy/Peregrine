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
//! * **SigV2** auth (`Authorization: AWS …` / `AWSAccessKeyId`) — WONTFIX
//! * **aws-chunked** streaming (`STREAMING-*` / `Content-Encoding: aws-chunked`)
//!   — WONTFIX
//! * **versioning / tagging / lifecycle** (+ related subresources) — WONTFIX
//!   production stop-line unless reopened
//!
//! Other residuals (not claimable as implemented):
//!
//! * full IAM / grant-header object ACL (canned private/public-read object ACL
//!   via sysmeta **is** claimable for PUT/GET `?acl`; object public-read does
//!   **not** by itself authorize anonymous Swift GET — container ACL still
//!   gates access)
//! * authenticated-read / log-delivery-write canned ACLs (Python NotImplemented)
//! * CORS ExposeHeader edge cases in live preflight
//! * clock-skew/expiry enforcement on every path
//!
//! Unknown access keys (EC2 / Keystone) are deferred via an optional
//! [`swift_middleware::S3TokenClient`] on [`middleware::S3Api`] (inline
//! `/v3/s3tokens` exchange with a real base64 string-to-sign). The
//! `s3token` pipeline filter remains available for environ-style stamped
//! auth details.

pub mod acl_cors;
pub mod crypto;
pub mod delete;
pub mod middleware;
pub mod mpu;
pub mod parse;
pub mod response;
pub mod sigv4;
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
pub use sigv4::{
    amz_date, canonical_query, canonical_request, canonical_uri, compute_signature,
    headers_to_sign, parse_authorization_header, parse_credential, parse_query_authentication,
    parse_sigv4_auth, payload_hash, signing_key, string_to_sign, string_to_sign_for_request,
    verify_sigv4, CredentialScope, SigV4Auth, ALGORITHM, SERVICE,
};
pub use xml::{Element, XMLNS_S3};
