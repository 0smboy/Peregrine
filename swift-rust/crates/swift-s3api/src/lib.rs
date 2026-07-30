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
//! This crate implements the parts of the S3 gateway that are pure and
//! well-specified:
//!
//! * [`parse`] — bucket/key extraction from path-style and virtual-host-style
//!   requests, bucket-name validation, and the S3 -> Swift path mapping
//!   (`/bucket/key` -> `/v1/<account>/bucket/key`).
//! * [`sigv4`] — AWS Signature Version 4: the canonical request, the
//!   string-to-sign, the HMAC-SHA256 signing-key chain, and
//!   [`sigv4::verify_sigv4`] to verify a client-presented signature (header
//!   auth and presigned-URL query auth).
//! * [`xml`] — a byte-faithful minimal XML writer matching the middleware's
//!   `lxml` output.
//! * [`response`] — S3 error documents and the bucket-listing / object-result
//!   XML shapes for GET/PUT/DELETE/HEAD on buckets and objects.
//! * [`crypto`] — SHA-256, HMAC-SHA256, and constant-time comparison.
//!
//! It reuses [`swift_http::Request`] / [`swift_http::Response`] /
//! [`swift_http::HeaderKeyDict`] as its HTTP containers.
//!
//! # Deferred (documented, not implemented)
//!
//! Multipart upload, ACLs and the ACL/subresource signing rules, object
//! versioning, CORS/tagging/lifecycle/object-lock documents, SigV2, the
//! aws-chunked streaming signature/trailer chain, request-lifecycle concerns
//! (clock-skew and expiry checks, error-code mapping from Swift backend
//! responses), and the full middleware `__call__` dispatch. These belong to
//! later stages; the pieces here are the reusable, deterministic core.

pub mod crypto;
pub mod parse;
pub mod response;
pub mod sigv4;
pub mod xml;

pub use parse::{
    extract_bucket_and_key, parse_host, s3_to_swift_path, validate_bucket_name, MULTIUPLOAD_SUFFIX,
};
pub use response::{
    copy_object_result_xml, delete_object_response, delete_result_xml, error_status_and_message,
    list_all_my_buckets_xml, object_metadata_response, put_object_response, s3_error_response,
    s3_error_xml, BucketInfo, DeleteError, ListBucketResult, Owner, S3Object,
};
pub use sigv4::{
    amz_date, canonical_query, canonical_request, canonical_uri, compute_signature,
    headers_to_sign, parse_authorization_header, parse_credential, parse_query_authentication,
    parse_sigv4_auth, payload_hash, signing_key, string_to_sign, verify_sigv4, CredentialScope,
    SigV4Auth, ALGORITHM, SERVICE,
};
pub use xml::{Element, XMLNS_S3};
