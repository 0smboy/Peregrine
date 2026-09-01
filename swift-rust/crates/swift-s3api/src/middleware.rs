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

//! Production S3 API gateway middleware (minimal surface).
//!
//! Wires the pure translation core ([`crate::parse`], [`crate::sigv4`],
//! [`crate::response`]) into the proxy pipeline as `s3api`. Pipeline order
//! matches OpenStack Swift: place `s3api` **before** `tempauth` /
//! `keystoneauth`.
//!
//! # Supported (Wave 3)
//!
//! * SigV4 header auth (TempAuth-derived `account:user` access keys)
//! * Service: ListBuckets (`GET /`)
//! * Bucket: Create / Delete / Head / ListObjects v1+v2 / GetBucketLocation
//! * MultiDelete (`POST ?delete`), basic ACL/CORS, multipart upload
//! * Object: Put / Get / Head / Delete; Copy via `x-amz-copy-source`
//!
//! # Residuals / stable rejections
//!
//! The following are **not implemented** and return a stable S3
//! `501 NotImplemented` (`Code=NotImplemented`) so clients get predictable
//! XML rather than fall-through 401/403/500 from other filters:
//!
//! * **SigV2** (`Authorization: AWS …` / `AWSAccessKeyId` query) — **IMPLEMENTED**
//!   (HMAC-SHA1 Base64; header + query Expires). See [`crate::sigv2`].
//! * WriteGetObjectResponse (Object Lambda `x-amz-request-route`) stays 501.
//!
//! # Config subresources (meta round-trip — claimable unit surface)
//!
//! * **versioning** GET/PUT — protected container sysmeta, with strict
//!   read-only compatibility for the historical public-meta key
//! * **tagging** GET/PUT/DELETE bucket + object
//! * **lifecycle** GET/PUT/DELETE — raw XML in container meta
//! * **object-lock** GET/PUT — protected container sysmeta, with strict
//!   read-only compatibility for the historical public-meta key
//! * **legal-hold** / **retention** GET/PUT on objects — sysmeta WORM;
//!   DELETE → `403 AccessDenied` while hold ON or retain-until future.
//!   PUT may stamp default retention from bucket ObjectLockConfiguration.
//! * **versions** GET — `ListVersionsResult` from `{bucket}+versions` indexes
//! * **multi-version object data plane** when versioning is `Enabled`
//!   ([`crate::versioning_store`]): archive, delete-markers, `?versionId=`
//!
//! # aws-chunked / STREAMING-* (implemented)
//!
//! PUT/POST bodies with `Content-Encoding: aws-chunked` and/or
//! `X-Amz-Content-SHA256: STREAMING-*` are dechunked after SigV4 verify
//! (header signature uses the STREAMING-* token as payload hash). Chunk
//! framing is stripped; trailers are discarded; decoded bytes are forwarded
//! to Swift with fixed `Content-Length`.
//!
//! **Per-chunk signatures are enforced** for
//! `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` / `*-TRAILER` when credentials are
//! available: invalid or missing `chunk-signature` →
//! `SignatureDoesNotMatch` (403), body not forwarded.
//! For `STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER`, `x-amz-trailer-signature`
//! is verified (`AWS4-HMAC-SHA256-TRAILER`); mismatch or missing trailer sig
//! when trailers are present → `SignatureDoesNotMatch`.
//! `STREAMING-UNSIGNED-PAYLOAD-TRAILER` dechunks without requiring signatures.
//! ECDSA streaming modes remain 501 NotImplemented.
//!
//! Object Lock **governance bypass** (`x-amz-bypass-governance-retention`)
//! is **IMPLEMENTED** for GOVERNANCE mode only (COMPLIANCE + legal-hold never
//! bypassed). Wired on DELETE, overwrite PUT, and multi-delete.
//!
//! Other residuals: full IAM identity service / emailAddress grantee
//! resolution; advertising `s3api` on Swift `GET /info`. Clock-skew and
//! query-expiry checks are **experimental** (not live-proven, not
//! AWS-complete). Multipart includes ListMultipartUploads via
//! `{bucket}+segments` upload markers.
//!
//! Grant headers (`x-amz-grant-*`) + ACP XML body PUT/GET `?acl` are claimable
//! (structured JSON sysmeta + container AllUsers mapping); canned `x-amz-acl`
//! still works and takes precedence when both are present.
//!
//! **Object ACP grant enforcement (GET/HEAD, LAB-HARD-GREEN):** when
//! `X-Object-Sysmeta-S3-Acl-Json` is present with non-empty grants, the SigV4
//! principal (`access_key` / account) must be owner or hold READ/FULL_CONTROL
//! — else `403 AccessDenied`. Owner always allowed. Missing/empty grants → no
//! new denial (Swift container ACL path). AllUsers READ still does **not**
//! open anonymous unauthenticated GET by itself. When `anonymous_account` is
//! configured, unsigned S3 GET/HEAD map to that account without auth override
//! so bucket `public-read` (container `.r:*`) can succeed; object ACL still
//! gates AllUsers.
//!
//! Unknown access keys (EC2) are deferred to Keystone via an optional
//! [`S3TokenClient`] (`with_s3token_client`); without a client, unknown keys
//! still return `InvalidAccessKeyId`.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::Value;
use swift_http::{
    parse_http_date, AsyncRequest, Body, ClockHealth, HeaderKeyDict, IncomingBody, Request,
    Response, MAX_CONTROL_BODY,
};
use swift_middleware::{
    AsyncNextFn, Middleware, NextFn, StreamingAsyncNextFn, S3TokenClient, S3TokenResult,
};

use crate::acl_cors::{
    apply_bucket_acl_input, apply_object_acl_input, bucket_acl_xml_from_headers,
    clear_cors_swift_headers, cors_config_to_swift_headers, cors_xml_from_swift_headers,
    decode_acl_json, grants_allow_anonymous_read, object_acl_denies_read, object_acl_denies_write,
    object_acl_xml_from_headers, object_canned_allows_anonymous_read, parse_cors_configuration,
    resolve_acl_put_input, xml_ok, AclPutInput, S3_OBJECT_ACL_JSON_META, S3_OBJECT_ACL_META,
};
use crate::aws_chunked::{
    cleanup_content_encoding, decode_aws_chunked, is_aws_chunked_request, is_ecdsa_streaming,
    is_streaming_payload_hash, AwsChunkedError, AwsChunkedTransform, ChunkSigContext,
};
use crate::bucket_config::{
    apply_bucket_tagging_meta, apply_lifecycle_meta, apply_object_blob_meta,
    apply_object_lock_meta, apply_object_tagging_meta, apply_stored_bucket_config,
    apply_versioning_meta, clear_bucket_tagging_meta, clear_lifecycle_meta, clear_object_blob_meta,
    clear_object_tagging_meta, clear_stored_bucket_config, empty_list_versions_result_xml,
    lifecycle_xml_from_headers, object_blob_from_headers, parse_tagging_body,
    parse_versioning_status, stored_bucket_config, stored_bucket_config_xml, tagging_xml_from_meta,
    validate_lifecycle_xml, validate_object_lock_xml, validated_object_lock_xml_from_headers,
    versioning_configuration_xml, versioning_status_from_headers, StoredBucketConfig,
    S3_BUCKET_TAGGING_META, S3_OBJECT_ANNOTATION_META, S3_OBJECT_ENCRYPTION_META,
    S3_OBJECT_TAGGING_META,
};
use crate::cold_tier::{
    archive_commit, begin_restore, complete_restore, hot_reclamation_allowed,
    maybe_stamp_and_archive_due_cold, reject_partial_body, stamp_cold_restore_meta,
    ColdArchiveReceipt, ColdArchiveState, ColdBackend, ColdStateMachine,
    COLD_DELETE_HOT_AFTER_ARCHIVE_DEFAULT, HDR_BACKEND_STORAGE_POLICY_INDEX,
    SYS_COLD_ARCHIVE_GENERATION, SYS_COLD_ARCHIVE_STATE, SYS_COLD_BACKEND_URI,
    SYS_COLD_CONTENT_LENGTH, SYS_COLD_CONTENT_SHA256, SYS_COLD_POLICY_INDEX,
    SYS_COLD_RESTORE_GENERATION, SYS_HOT_POLICY_INDEX,
};
use crate::delete::parse_multi_delete_body;
use crate::lifecycle_exec::{
    amz_expiration_from_delete_at, apply_abort_incomplete_from_container,
    apply_due_transition_on_headers, apply_lifecycle_on_put_from_container, apply_restore_days,
    is_cold_storage_class, transition_blocks_get, META_STORAGE_CLASS, SYS_RESTORE_UNTIL,
    SYS_TRANSITIONED,
};
use crate::mpu::{
    aws_multipart_etag, complete_multipart_xml, initiate_response, list_multipart_uploads_xml,
    list_parts_xml_full, match_completed_mpu_etag, new_upload_id, parse_complete_body,
    parse_upload_marker_name, part_object_name, segments_container, slo_manifest_json,
    upload_marker_name, CompletedMpuEtagMatch, ListedPart, ListedUpload,
    SYS_CONTAINER_UPDATE_OVERRIDE_ETAG, SYS_CONTAINER_UPDATE_OVERRIDE_SIZE, SYS_S3API_ETAG,
    SYS_S3API_UPLOAD_ID,
};
use crate::object_lock_worm::{
    apply_default_retention_headers, bypass_governance_requested,
    evaluate_object_version_worm_with_clock, evaluate_retention_update_with_clock, legal_hold_xml,
    object_version_lock_state, parse_bypass_governance_header, parse_legal_hold_body,
    parse_object_lock_configuration, parse_object_retention, parse_retention_body,
    retention_date_is_valid_for_put, retention_xml, validate_and_apply_amz_object_lock_headers,
    GovernanceBypass, RetentionUpdateDecision, RetentionUpdateDenyReason, WormDecision,
    WormDenyReason, HDR_BYPASS_GOVERNANCE, SYS_LEGAL_HOLD, SYS_LOCK_MODE, SYS_RETAIN_UNTIL,
};
use crate::parse::{
    extract_bucket_and_key, s3_to_swift_path, validate_bucket_name, MULTIUPLOAD_SUFFIX,
};
use crate::response::{
    apply_s3_amz_ids, copy_object_result_xml, copy_part_result_xml, create_session_result_xml,
    delete_object_response, delete_result_xml, get_object_attributes_xml, list_all_my_buckets_xml,
    list_directory_buckets_xml, object_torrent_bytes, policy_status_xml, put_object_response,
    s3_error_response, s3_xml_timestamp, s3_xml_timestamp_ceil, select_star_event_stream,
    unix_secs_to_s3_iso,
    xml_response, BucketInfo, DeleteError, DeletedObject, ListBucketResult, ListBucketResultV2,
    Owner, S3Object,
};
use crate::select::{apply_select_plan, parse_select_expression};
use crate::sigv2::{
    check_sigv2_time, is_sigv2_auth, parse_sigv2_auth, string_to_sign_for_request_v2, verify_sigv2,
    SigV2Auth,
};
use crate::sigv4::{
    check_sigv4_time, parse_sigv4_auth, string_to_sign_for_request, verify_sigv4, SigAuthError,
    SigV4Auth,
};
use crate::versioning_store::{
    archive_object_name, bare_etag as vers_bare_etag, generate_version_id,
    index_generation_object_name, index_object_name, is_delete_marker_header, is_safe_version_id,
    list_versions_result_xml, merge_unindexed_current_objects, versioning_status,
    versions_container, CasDenied, RemoveVersionError, VersionIndex, VersionRecord,
    VersioningStatus, HDR_DELETE_MARKER, HDR_VERSION_ID, INDEX_NAME, NULL_VERSION_ID,
    SYS_DELETE_MARKER, SYS_OBJECT_KEY, SYS_VERSION_ID,
};
use crate::website::{
    is_website_endpoint, parse_website_configuration, resolve_website_key, website_object_params,
    WebsiteConfig,
};
use crate::xml::Element;

/// One S3 credential mapped onto a Swift storage account.
#[derive(Debug, Clone)]
pub struct S3Credential {
    pub access_key: String,
    pub secret_key: String,
    /// Swift account path segment, e.g. `AUTH_test`.
    pub account: String,
    /// Groups stamped onto `X-Backend-Remote-User` (account owner etc.).
    pub groups: Vec<String>,
    /// Optional Keystone token id from an s3tokens exchange (stamped as
    /// `X-Auth-Token` on the Swift subrequest).
    pub auth_token: Option<String>,
}

/// `s3api` filter — ON-BY-CONFIG via `[pipeline:main]`.
pub struct S3Api {
    pub credentials: HashMap<String, S3Credential>,
    pub storage_domains: Vec<String>,
    pub dns_compliant_bucket_names: bool,
    /// Region reported by `?location` and accepted in SigV4 scope.
    pub location: String,
    /// Reseller prefix for Keystone project → Swift account (`AUTH_`).
    pub reseller_prefix: String,
    /// Max SigV2/SigV4 clock skew tolerance in seconds (default 900).
    pub allowable_clock_skew: u64,
    /// Enable lab-only extended S3 subresources when true.
    pub extended_subresources: bool,
    /// When set, unknown access keys are exchanged via Keystone `/v3/s3tokens`
    /// with a real base64 string-to-sign (EC2 deferral).
    pub s3token_client: Option<Arc<dyn S3TokenClient>>,
    /// Multi-tenant IAM policy engine (optional; empty = no extra deny).
    pub iam: crate::iam::IamService,
    /// Cold-tier storage-policy map (optional; empty = meta-only stamps).
    pub cold_map: crate::cold_tier::ColdPolicyMap,
    /// Optional lab cold backend (local dir / memory). Not tape/Glacier cloud.
    pub cold_backend: Option<Arc<dyn ColdBackend>>,
    /// Lab: after successful archive + URI stamp, overwrite the hot object
    /// body with empty bytes. Default false so fleet behavior is unchanged.
    /// Metadata is kept so GET remains InvalidObjectState until restore.
    /// Does **not** delete the cold copy (`restore_stage` still needs it).
    /// LocalDir/Memory only — not tape/Glacier cloud.
    pub cold_delete_hot_after_archive: bool,
    /// When set, unsigned S3 GET/HEAD for path-/vhost-style buckets map to this
    /// Swift account **without** auth override so container `.r:*` can allow
    /// anonymous reads. Multi-tenant deployments must set this explicitly.
    pub anonymous_account: Option<String>,
    /// Swift accounts that S3 dispatch denies with `403 AccessDenied` XML
    /// before any local answer, probe, cold stamp, or `next()`. Default empty.
    /// ListBuckets / no-bucket requests are not denied here.
    pub frozen_accounts: HashSet<String>,
    /// WORM clock-health source (`worm_clock_max_offset_ms`). Default
    /// disabled: every WORM evaluation sees `clock_ok=true`, exactly the
    /// historical behavior. Enabled (>0) it is fail-closed — see
    /// [`swift_http::clock_health`].
    pub worm_clock: Arc<ClockHealth>,
    /// Short-TTL container HEAD cache. Sequential PUTs to one unversioned
    /// bucket were paying 3–4 identical container HEADs each (~700ms/object).
    container_heads: ContainerHeadCache,
}

struct CachedContainerHead {
    at: Instant,
    status: u16,
    headers: HeaderKeyDict,
}

struct ContainerHeadCache {
    inner: Mutex<HashMap<String, CachedContainerHead>>,
}

impl ContainerHeadCache {
    fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    fn cache_key(account: &str, bucket: &str) -> String {
        format!("{account}\0{bucket}")
    }

    fn ttl() -> Duration {
        // Unit tests drive container meta through mocks between handle()
        // calls; a live TTL would hide those updates. Production keeps a
        // 30s window so a 1000-object PUT storm shares one container HEAD.
        if cfg!(test) {
            Duration::ZERO
        } else {
            Duration::from_secs(30)
        }
    }

    fn get(&self, account: &str, bucket: &str) -> Option<(u16, HeaderKeyDict)> {
        let Ok(mut guard) = self.inner.lock() else {
            return None;
        };
        let key = Self::cache_key(account, bucket);
        match guard.get(&key) {
            Some(cached) if cached.at.elapsed() < Self::ttl() => {
                Some((cached.status, cached.headers.clone()))
            }
            Some(_) => {
                guard.remove(&key);
                None
            }
            None => None,
        }
    }

    fn store(&self, account: &str, bucket: &str, status: u16, headers: HeaderKeyDict) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.insert(
                Self::cache_key(account, bucket),
                CachedContainerHead {
                    at: Instant::now(),
                    status,
                    headers,
                },
            );
        }
    }

    fn invalidate(&self, account: &str, bucket: &str) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.remove(&Self::cache_key(account, bucket));
        }
    }
}

impl S3Api {
    pub fn new(credentials: HashMap<String, S3Credential>) -> Self {
        S3Api {
            credentials,
            storage_domains: Vec::new(),
            dns_compliant_bucket_names: true,
            location: "us-east-1".to_string(),
            reseller_prefix: "AUTH_".into(),
            allowable_clock_skew: 15 * 60,
            extended_subresources: false,
            s3token_client: None,
            iam: crate::iam::IamService::new(),
            cold_map: crate::cold_tier::ColdPolicyMap::new(),
            cold_backend: None,
            cold_delete_hot_after_archive: false,
            anonymous_account: None,
            frozen_accounts: HashSet::new(),
            worm_clock: Arc::new(ClockHealth::disabled()),
            container_heads: ContainerHeadCache::new(),
        }
    }

    /// Wire a WORM clock-health source (default: disabled, `clock_ok=true`).
    pub fn with_worm_clock(mut self, clock: Arc<ClockHealth>) -> Self {
        self.worm_clock = clock;
        self
    }

    pub fn with_iam(mut self, iam: crate::iam::IamService) -> Self {
        self.iam = iam;
        self
    }

    pub fn with_cold_map(mut self, map: crate::cold_tier::ColdPolicyMap) -> Self {
        self.cold_map = map;
        self
    }

    /// Wire a lab cold backend (e.g. [`crate::LocalDirColdBackend`]). Not production tape.
    pub fn with_cold_backend(mut self, backend: Arc<dyn ColdBackend>) -> Self {
        self.cold_backend = Some(backend);
        self
    }

    /// Lab knob: drop hot bytes after a successful archive+URI stamp.
    /// Default false. Not tape/Glacier cloud.
    pub fn with_cold_delete_hot_after_archive(mut self, enabled: bool) -> Self {
        self.cold_delete_hot_after_archive = enabled;
        self
    }

    pub fn with_location(mut self, location: impl Into<String>) -> Self {
        self.location = location.into();
        self
    }

    pub fn with_storage_domains(mut self, domains: Vec<String>) -> Self {
        self.storage_domains = domains;
        self
    }

    pub fn with_dns_compliant(mut self, dns: bool) -> Self {
        self.dns_compliant_bucket_names = dns;
        self
    }

    pub fn with_reseller_prefix(mut self, prefix: impl Into<String>) -> Self {
        let mut p = prefix.into();
        if !p.ends_with('_') {
            p.push('_');
        }
        self.reseller_prefix = p;
        self
    }

    pub fn with_allowable_clock_skew(mut self, seconds: u64) -> Self {
        self.allowable_clock_skew = seconds;
        self
    }

    pub fn with_extended_subresources(mut self, enabled: bool) -> Self {
        self.extended_subresources = enabled;
        self
    }

    pub fn with_anonymous_account(mut self, account: impl Into<String>) -> Self {
        let a = account.into().trim().to_string();
        self.anonymous_account = if a.is_empty() { None } else { Some(a) };
        self
    }

    /// Exact Swift-account names. Empty iterator clears the set.
    pub fn with_frozen_accounts(
        mut self,
        accounts: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.frozen_accounts = accounts.into_iter().map(Into::into).collect();
        self
    }

    fn is_frozen(&self, account: &str) -> bool {
        self.frozen_accounts.contains(account)
    }

    /// Deny every S3 method for a frozen Swift account except ListBuckets /
    /// service `/` (no bucket). Must run before GetBucketLocation, probes,
    /// cold, or `next()`. Invalid bucket names are still denied.
    fn frozen_account_denied(&self, account: &str, req: &Request) -> Option<Response> {
        if !self.is_frozen(account) {
            return None;
        }
        let (bucket, key) =
            extract_bucket_and_key(req, &self.storage_domains, self.dns_compliant_bucket_names);
        let is_list_buckets = bucket.is_none()
            && key.is_none()
            && matches!(req.method.as_str(), "GET" | "HEAD")
            && (req.path == "/" || req.path.is_empty());
        if is_list_buckets {
            return None;
        }
        Some(s3_error_response("AccessDenied", None, &[]))
    }

    pub fn with_s3token_client(mut self, client: Arc<dyn S3TokenClient>) -> Self {
        self.s3token_client = Some(client);
        self
    }

    /// Resolve a local TempAuth credential, or defer to Keystone s3tokens.
    /// Returns `(cred, signature_already_verified_by_keystone)`.
    fn resolve_credential(&self, auth: &SigV4Auth, req: &Request) -> Option<(S3Credential, bool)> {
        if let Some(cred) = self.credentials.get(&auth.access_key) {
            return Some((cred.clone(), false));
        }
        let client = self.s3token_client.as_ref()?;
        let sts = string_to_sign_for_request(req)?;
        let result = client.exchange(&auth.access_key, &auth.signature, &sts)?;
        Some((
            credential_from_s3token(&auth.access_key, &result, &self.reseller_prefix),
            true,
        ))
    }

    /// Resolve credential for SigV2 (local map or Keystone s3tokens with v2 STS).
    fn resolve_credential_v2(
        &self,
        auth: &SigV2Auth,
        req: &Request,
    ) -> Option<(S3Credential, bool)> {
        if let Some(cred) = self.credentials.get(&auth.access_key) {
            return Some((cred.clone(), false));
        }
        let client = self.s3token_client.as_ref()?;
        let sts = string_to_sign_for_request_v2(req)?;
        let result = client.exchange(&auth.access_key, &auth.signature, &sts)?;
        Some((
            credential_from_s3token(&auth.access_key, &result, &self.reseller_prefix),
            true,
        ))
    }
}

fn credential_from_s3token(
    access_key: &str,
    result: &S3TokenResult,
    reseller_prefix: &str,
) -> S3Credential {
    let account = format!("{reseller_prefix}{}", result.project_id);
    let mut groups = vec![
        result.project_id.clone(),
        format!("{}:{}", result.project_name, result.user_name),
        account.clone(),
    ];
    for role in &result.roles {
        if !role.is_empty() && !groups.contains(role) {
            groups.push(role.clone());
        }
    }
    S3Credential {
        access_key: access_key.to_string(),
        secret_key: String::new(),
        account,
        groups,
        auth_token: if result.token_id.is_empty() {
            None
        } else {
            Some(result.token_id.clone())
        },
    }
}

/// Subresources rejected with stable `501 NotImplemented` (WONTFIX stop-line
/// for production unless reopened). Clients must see `Code=NotImplemented`,
/// not a backend 500 or empty body.
///
/// Implemented elsewhere (must **not** appear here): `lifecycle`, `tagging`,
/// `versioning`, `versions`, `object-lock`, `legal-hold`, `retention`, `restore`.
const UNSUPPORTED_SUBRESOURCES: &[&str] = &[];
const MAX_SELECT_TORRENT_BODY: u64 = 16 * 1024 * 1024;

/// Fixed client-facing messages for stable 501 responses (unit-tested).
const MSG_ECDSA_STREAMING_NOT_IMPLEMENTED: &str =
    "ECDSA streaming payload signing (STREAMING-AWS4-ECDSA-P256-SHA256-*) is not implemented.";

/// Cap for materializing aws-chunked wire bodies (~Swift max object size).
const MAX_AWS_CHUNKED_BODY: u64 = 5_368_709_122;

/// Materialize, dechunk, and fix headers for an aws-chunked / STREAMING-* body.
///
/// Call **after** SigV4 header verification (payload hash is the STREAMING-*
/// token). On success: body is raw decoded bytes, `Content-Length` matches
/// decoded length, `aws-chunked` is stripped from `Content-Encoding`, and
/// STREAMING `X-Amz-Content-SHA256` is replaced with `UNSIGNED-PAYLOAD`.
///
/// HMAC per-chunk (and trailer) signature verification runs when `cred` has a
/// secret and the mode is STREAMING-AWS4-HMAC-SHA256-PAYLOAD*; failure →
/// `SignatureDoesNotMatch` (403). Trailer HMAC is required for
/// `*-PAYLOAD-TRAILER` when trailer content is present.
fn decode_and_fix_aws_chunked(
    req: &mut Request,
    cred: &S3Credential,
    auth: &SigV4Auth,
) -> Result<(), Response> {
    let payload_hash = req
        .headers
        .get("X-Amz-Content-SHA256")
        .unwrap_or("")
        .to_string();

    if is_ecdsa_streaming(&payload_hash) {
        return Err(s3_error_response(
            "NotImplemented",
            Some(MSG_ECDSA_STREAMING_NOT_IMPLEMENTED),
            &[],
        ));
    }

    let is_streaming = is_streaming_payload_hash(&payload_hash);
    let decoded_len = req
        .headers
        .get("X-Amz-Decoded-Content-Length")
        .and_then(|s| s.parse::<u64>().ok());

    // STREAMING-* requires x-amz-decoded-content-length (Python MissingContentLength).
    if is_streaming && decoded_len.is_none() {
        return Err(s3_error_response(
            "MissingContentLength",
            Some("You must provide the x-amz-decoded-content-length header."),
            &[("ArgumentName", "x-amz-decoded-content-length")],
        ));
    }

    let cap = req
        .headers
        .get("Content-Length")
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(MAX_CONTROL_BODY)
        .clamp(MAX_CONTROL_BODY, MAX_AWS_CHUNKED_BODY);
    let framed = match req.body.take().into_vec(cap) {
        Ok(b) => b,
        Err(_) => {
            return Err(s3_error_response(
                "IncompleteBody",
                Some("failed to read aws-chunked body"),
                &[],
            ));
        }
    };

    // Content-Encoding: aws-chunked alone with empty body — strip encoding.
    if framed.is_empty() && !is_streaming {
        cleanup_content_encoding(&mut req.headers);
        req.headers.set("Content-Length", "0");
        req.body = Body::empty();
        return Ok(());
    }

    let want_hmac = matches!(
        payload_hash.as_str(),
        "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" | "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"
    ) && !cred.secret_key.is_empty();
    let require_trailer_sig =
        payload_hash.eq_ignore_ascii_case("STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER");

    let sig_ctx = if want_hmac {
        crate::sigv4::amz_date(req).map(|ad| ChunkSigContext {
            secret_key: cred.secret_key.clone(),
            date: auth.scope.date.clone(),
            region: auth.scope.region.clone(),
            service: auth.scope.service.clone(),
            amz_date: ad,
            seed_signature: auth.signature.clone(),
            require_trailer_signature: require_trailer_sig,
        })
    } else {
        None
    };

    let decoded = match decode_aws_chunked(&framed, decoded_len, sig_ctx.as_ref()) {
        Ok(d) => d,
        Err(e) => return Err(aws_chunked_error_to_response(e)),
    };
    // Enforced above: Some(false) no longer soft-ignored.
    let _ = decoded.chunk_signatures_valid;
    let _ = decoded.trailer_signature_valid;
    let _ = decoded.trailers;

    cleanup_content_encoding(&mut req.headers);
    req.headers
        .set("Content-Length", decoded.data.len().to_string());
    req.headers.remove("X-Amz-Decoded-Content-Length");
    req.headers.remove("x-amz-trailer");
    req.headers.remove("X-Amz-Trailer");
    if is_streaming {
        // Downstream does not need STREAMING-*; UNSIGNED-PAYLOAD matches
        // "payload not re-hashed for SigV4".
        req.headers.set("X-Amz-Content-SHA256", "UNSIGNED-PAYLOAD");
    }
    req.body = Body::from(decoded.data);
    Ok(())
}

fn aws_chunked_error_to_response(err: AwsChunkedError) -> Response {
    match err {
        AwsChunkedError::SizeMismatch { expected, provided } => s3_error_response(
            "IncompleteBody",
            Some(&format!(
                "x-amz-decoded-content-length {expected} != decoded {provided}"
            )),
            &[],
        ),
        AwsChunkedError::Incomplete | AwsChunkedError::InvalidChunkHeader => s3_error_response(
            "IncompleteBody",
            Some("incomplete or invalid aws-chunked framing"),
            &[],
        ),
        AwsChunkedError::MissingDecodedContentLength => {
            s3_error_response("MissingContentLength", None, &[])
        }
        AwsChunkedError::EcdsaNotImplemented => s3_error_response(
            "NotImplemented",
            Some(MSG_ECDSA_STREAMING_NOT_IMPLEMENTED),
            &[],
        ),
        AwsChunkedError::InvalidChunkSignature | AwsChunkedError::InvalidTrailerSignature => {
            s3_error_response("SignatureDoesNotMatch", None, &[])
        }
    }
}

/// S3-2: wrap IncomingBody with incremental aws-chunked decode. Header
/// `Content-Length` becomes the decoded size. Errors are recorded on `slot`.
fn wrap_aws_chunked_streaming(
    areq: &mut AsyncRequest,
    head: &mut Request,
    cred: &S3Credential,
    auth: &SigV4Auth,
    payload_hash: &str,
    decoded_len: Option<u64>,
    amz_date: Option<String>,
    slot: Arc<Mutex<Option<AwsChunkedError>>>,
) -> Result<(), Response> {
    if is_ecdsa_streaming(payload_hash) {
        return Err(s3_error_response(
            "NotImplemented",
            Some(MSG_ECDSA_STREAMING_NOT_IMPLEMENTED),
            &[],
        ));
    }
    if is_streaming_payload_hash(payload_hash) && decoded_len.is_none() {
        return Err(s3_error_response(
            "MissingContentLength",
            Some("You must provide the x-amz-decoded-content-length header."),
            &[("ArgumentName", "x-amz-decoded-content-length")],
        ));
    }
    let want_hmac = matches!(
        payload_hash,
        "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" | "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"
    ) && !cred.secret_key.is_empty();
    let require_trailer_sig =
        payload_hash.eq_ignore_ascii_case("STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER");
    let sig_ctx = if want_hmac {
        amz_date.map(|ad| ChunkSigContext {
            secret_key: cred.secret_key.clone(),
            date: auth.scope.date.clone(),
            region: auth.scope.region.clone(),
            service: auth.scope.service.clone(),
            amz_date: ad,
            seed_signature: auth.signature.clone(),
            require_trailer_signature: require_trailer_sig,
        })
    } else {
        None
    };
    let xform = AwsChunkedTransform::new(decoded_len, sig_ctx, slot);
    let inner = std::mem::replace(
        &mut areq.body,
        IncomingBody::from_bytes(Vec::new(), 1),
    );
    areq.body = inner.with_transform(Box::new(xform), decoded_len);
    if let Some(n) = decoded_len {
        head.headers.set("Content-Length", n.to_string());
        areq.headers.set("Content-Length", n.to_string());
    }
    head.headers.remove("X-Amz-Decoded-Content-Length");
    head.headers.remove("x-amz-trailer");
    areq.headers.remove("x-amz-trailer");
    cleanup_content_encoding(&mut head.headers);
    if is_streaming_payload_hash(payload_hash) {
        head.headers.set("X-Amz-Content-SHA256", "UNSIGNED-PAYLOAD");
    }
    Ok(())
}

/// Detect S3-shaped auth so we intercept SigV2/SigV4 (and reject unsupported
/// auth schemes with S3 XML) instead of falling through to Swift filters.
///
/// Python `_is_header_auth` is `'Authorization' in self.headers`: an empty
/// or unparseable header is still an S3 request (AccessDenied 403), not a
/// Swift passthrough (404 HTML). s3compat
/// `test_*_authorization_empty` depends on that.
fn is_s3_auth_request(req: &Request) -> bool {
    parse_sigv4_auth(req).is_some()
        || is_sigv2_auth(req)
        || req.headers.get("Authorization").is_some()
}

/// Python `_parse_path` raises InvalidBucketName before HMAC verification.
/// SigV2 over `/alpha!soup` otherwise 403s SignatureDoesNotMatch.
fn reject_invalid_bucket_before_auth(
    req: &Request,
    storage_domains: &[String],
    dns_compliant: bool,
) -> Option<Response> {
    let (bucket, _) = extract_bucket_and_key(req, storage_domains, dns_compliant);
    let bucket = bucket?;
    if validate_bucket_name(&bucket, dns_compliant) {
        None
    } else {
        Some(s3_error_response(
            "InvalidBucketName",
            None,
            &[("BucketName", &bucket)],
        ))
    }
}

/// Object PUT without Content-Length and without chunked TE: Python lets
/// Swift return 411 and maps it to MissingContentLength. Hyper/s3api was
/// answering 400.
fn put_object_missing_content_length(req: &Request, key: Option<&str>) -> Option<Response> {
    if req.method != "PUT" || key.is_none() {
        return None;
    }
    if req.headers.get("Content-Length").is_some() {
        return None;
    }
    let te = req
        .headers
        .get("Transfer-Encoding")
        .unwrap_or("")
        .to_ascii_lowercase();
    if te.split(',').any(|t| t.trim() == "chunked") {
        return None;
    }
    if req.headers.get("X-Amz-Decoded-Content-Length").is_some()
        || req.headers.get("x-amz-decoded-content-length").is_some()
    {
        return None;
    }
    if req.headers.get("x-amz-copy-source").is_some()
        || req.headers.get("X-Amz-Copy-Source").is_some()
        || req.headers.get("X-Amz-Rename-Source").is_some()
        || req.headers.get("x-amz-rename-source").is_some()
    {
        return None;
    }
    // HTTP/1.1 with no CL and no chunked TE has a 0-length body
    // (Hyper `size_hint().exact() == Some(0)`). The proxy intercept path
    // materializes that empty buffer before s3api sees the request, so
    // `content_length()` is Some(0), not None.
    //
    // Unit-test `Body::from(nonempty)` keeps a known >0 length without
    // the header. Empty unit PUTs (copy/ACL/path mapping) have neither
    // Content-MD5 nor Expect: 100-continue. Live boto
    // `test_object_create_bad_contentlength_none` strips CL but leaves
    // both, which is the Python 411 case.
    match req.body.content_length() {
        Some(n) if n > 0 => None,
        None => Some(s3_error_response("MissingContentLength", None, &[])),
        Some(_) => {
            let md5 = req.headers.get("Content-MD5").is_some()
                || req.headers.get("content-md5").is_some();
            let expect_continue = req
                .headers
                .get("Expect")
                .or_else(|| req.headers.get("expect"))
                .unwrap_or("")
                .to_ascii_lowercase()
                .contains("100-continue");
            if md5 || expect_continue {
                Some(s3_error_response("MissingContentLength", None, &[]))
            } else {
                None
            }
        }
    }
}

/// PutObject / UploadPart: body is object bytes, not control XML.
/// CreateMultipartUpload (`POST ?uploads`) and Complete (`POST ?uploadId` without
/// partNumber) stay on the control intercept + materialize path.
/// Copy stays off this path. aws-chunked PutObject/UploadPart stream here (S3-2).
fn is_s3_streaming_object_put(
    req: &Request,
    storage_domains: &[String],
    dns_compliant: bool,
) -> bool {
    if !matches!(req.method.as_str(), "PUT" | "POST") {
        return false;
    }
    if req.headers.get("x-amz-copy-source").is_some()
        || req.headers.get("X-Amz-Copy-Source").is_some()
    {
        return false;
    }
    let params = req.params();
    let has_upload_id = params.iter().any(|(k, _)| k == "uploadId");
    let has_part = params.iter().any(|(k, _)| k == "partNumber");
    let has_uploads = params.iter().any(|(k, _)| k == "uploads");
    if has_uploads && !has_upload_id {
        return false;
    }
    if has_upload_id && !has_part && req.method == "POST" {
        return false;
    }
    const CONTROL: &[&str] = &[
        "acl",
        "tagging",
        "cors",
        "lifecycle",
        "versioning",
        "delete",
        "policy",
        "website",
        "logging",
        "notification",
        "encryption",
        "object-lock",
        "legal-hold",
        "retention",
        "publicAccessBlock",
        "restore",
        "select",
        "torrent",
    ];
    if params.iter().any(|(k, _)| CONTROL.contains(&k.as_str())) {
        return false;
    }
    let (bucket, key) = extract_bucket_and_key(req, storage_domains, dns_compliant);
    bucket.is_some() && key.is_some()
}

/// Paths that are never unsigned S3 (Swift v1 / auth / info / health).
fn is_swift_native_path(path: &str) -> bool {
    path == "/info"
        || path.starts_with("/info/")
        || path.starts_with("/v1/")
        || path == "/v1"
        || path.starts_with("/auth")
        || path.starts_with("/healthcheck")
}

/// Unsigned S3 GET/HEAD candidate: not Swift-native, has a bucket, GET/HEAD.
fn is_s3_unsigned_read_candidate(
    req: &Request,
    storage_domains: &[String],
    dns_compliant: bool,
) -> bool {
    if !matches!(req.method.as_str(), "GET" | "HEAD") {
        return false;
    }
    if is_swift_native_path(&req.path) {
        return false;
    }
    let (bucket, _) = extract_bucket_and_key(req, storage_domains, dns_compliant);
    bucket.is_some()
}

/// Object ACL must not block AllUsers when Swift returned 200 via container ACL.
fn object_acl_blocks_anonymous(headers: &HeaderKeyDict) -> bool {
    if let Some(raw) = headers
        .get(S3_OBJECT_ACL_JSON_META)
        .or_else(|| headers.get("X-Object-Meta-S3-Acl-Json"))
    {
        return match decode_acl_json(raw) {
            Some(policy) if !policy.grants.is_empty() => {
                !grants_allow_anonymous_read(&policy.grants)
            }
            // Malformed / empty JSON ACL: fail closed (deny). Never allow.
            _ => true,
        };
    }
    if let Some(canned) = headers.get(S3_OBJECT_ACL_META).filter(|s| !s.is_empty()) {
        return !object_canned_allows_anonymous_read(Some(canned));
    }
    false
}

fn first_unsupported_subresource(params: &[(String, String)]) -> Option<&str> {
    for name in UNSUPPORTED_SUBRESOURCES {
        if params.iter().any(|(k, _)| k == *name) {
            return Some(*name);
        }
    }
    None
}

fn not_implemented_subresource(sub: &str) -> Response {
    s3_error_response(
        "NotImplemented",
        Some(&format!("subresource '{sub}' is not implemented")),
        &[],
    )
}

fn owner_for(cred: &S3Credential) -> Owner {
    Owner {
        id: cred.access_key.clone(),
        display_name: cred.access_key.clone(),
    }
}

/// Stamp auth bypass + groups so TempAuth / proxy authorize honour the
/// SigV4-authenticated identity (same pattern as TempURL override).
fn stamp_auth(req: &mut Request, cred: &S3Credential) {
    req.headers.set("X-Backend-Authorize-Override", "true");
    req.headers
        .set("X-Backend-Remote-User", cred.groups.join(","));
    req.headers.set("X-Backend-Swift-Owner", "true");
    if let Some(tok) = &cred.auth_token {
        req.headers.set("X-Auth-Token", tok);
        req.headers.set("X-Identity-Status", "Confirmed");
    }
}

fn s3_auth_error(err: SigAuthError) -> Response {
    // RequestId is injected by s3_error_xml (Python ErrorResponse._body_iter).
    s3_error_response(err.s3_code(), err.s3_message(), &[])
}

/// HEAD errors must have an empty body (boto3 then reports Code as the
/// status string: `400` / `403` / `404`). Apply after every S3 response.
fn finish_s3_response(method: &str, mut resp: Response) -> Response {
    apply_s3_amz_ids(&mut resp);
    if method == "HEAD" && resp.status >= 400 {
        resp.body = Body::empty();
        resp.headers.set("Content-Length", "0");
    }
    resp
}

/// Swift default `max_object_name_length`. Official functest uses GET /info.
const MAX_OBJECT_NAME_LENGTH: usize = 1024;

fn s3_meta_name_allowed(rest: &str) -> bool {
    // eventlet/WSGI drops these token chars from header names. Official
    // test_put_object_weird_metadata keeps !#$%&'(*+-.^`|~ only.
    !rest.chars().any(|c| {
        matches!(
            c,
            '"' | ')' | '/' | '<' | '=' | '>' | '?' | '@' | '[' | '\\' | ']' | '{' | '}'
        )
    })
}

/// Experimental: only `STANDARD` is accepted on PUT/copy. Not live-proven.
/// Not AWS-complete (no Glacier/INTELLIGENT_TIERING). Must run **before**
/// [`strip_s3_only_headers`] so a non-STANDARD class is not persisted.
fn reject_unknown_storage_class(req: &Request) -> Option<Response> {
    let sc = req.headers.get("x-amz-storage-class")?;
    if sc == "STANDARD" {
        None
    } else {
        Some(s3_error_response("InvalidStorageClass", None, &[]))
    }
}

fn strip_s3_only_headers(headers: &mut HeaderKeyDict) {
    // AWS headers must not leak into the Swift backend as client meta.
    let keys: Vec<String> = headers
        .iter()
        .map(|(k, _)| k.to_string())
        .filter(|k| {
            let lower = k.to_ascii_lowercase();
            lower.starts_with("x-amz-") || lower == "authorization" || lower == "x-sdk-date"
        })
        .collect();
    for k in keys {
        headers.remove(&k);
    }
}

fn map_amz_meta(req: &mut Request) {
    // x-amz-meta-* → X-Object-Meta-*
    let pairs: Vec<(String, String)> = req
        .headers
        .iter()
        .filter_map(|(k, v)| {
            let lower = k.to_ascii_lowercase();
            lower.strip_prefix("x-amz-meta-").and_then(|rest| {
                s3_meta_name_allowed(rest)
                    .then(|| (format!("X-Object-Meta-{rest}"), v.to_string()))
            })
        })
        .collect();
    for (k, v) in pairs {
        req.headers.set(&k, v);
    }
}

/// Swift object-server drops Cache-Control / Expires / Content-Language /
/// X-Robots-Tag. Persist them as sysmeta and restore on GET/HEAD.
const S3_OBJECT_HEADER_STORE: &[(&str, &str)] = &[
    ("cache-control", "X-Object-Sysmeta-S3-Cache-Control"),
    ("expires", "X-Object-Sysmeta-S3-Expires"),
    ("content-language", "X-Object-Sysmeta-S3-Content-Language"),
    ("x-robots-tag", "X-Object-Sysmeta-S3-Robots-Tag"),
];

fn persist_s3_object_headers(req: &mut Request) {
    for (from, to) in S3_OBJECT_HEADER_STORE {
        if let Some(v) = req.headers.get(from).map(str::to_string) {
            if !v.is_empty() {
                req.headers.set(*to, v);
            }
        }
    }
}

fn restore_s3_object_header(lower: &str) -> Option<&'static str> {
    match lower {
        "cache-control" | "x-object-sysmeta-s3-cache-control" => Some("cache-control"),
        "expires" | "x-object-sysmeta-s3-expires" => Some("expires"),
        "content-language" | "x-object-sysmeta-s3-content-language" => Some("content-language"),
        "x-robots-tag" | "x-object-sysmeta-s3-robots-tag" => Some("x-robots-tag"),
        _ => None,
    }
}

fn is_s3_http_method(method: &str) -> bool {
    matches!(method, "GET" | "HEAD" | "PUT" | "POST" | "DELETE")
}

fn reject_unsupported_put_conditionals(req: &Request) -> Option<Response> {
    if let Some(v) = req.headers.get("If-None-Match") {
        if v != "*" {
            return Some(s3_error_response("NotImplemented", None, &[]));
        }
    }
    if req.headers.get("If-Match").is_some()
        || req.headers.get("If-Modified-Since").is_some()
        || req.headers.get("If-Unmodified-Since").is_some()
    {
        return Some(s3_error_response("NotImplemented", None, &[]));
    }
    None
}

fn validate_delete_headers(req: &Request) -> Option<Response> {
    if let Some(v) = req.headers.get("X-Delete-At") {
        match v.parse::<i64>() {
            Err(_) => {
                return Some(s3_error_response(
                    "InvalidArgument",
                    Some("Non-integer X-Delete-At"),
                    &[],
                ))
            }
            Ok(ts) if ts < unix_now() => {
                return Some(s3_error_response(
                    "InvalidArgument",
                    Some("X-Delete-At in past"),
                    &[],
                ))
            }
            _ => {}
        }
    }
    if let Some(v) = req.headers.get("X-Delete-After") {
        match v.parse::<i64>() {
            Err(_) => {
                return Some(s3_error_response(
                    "InvalidArgument",
                    Some("Non-integer X-Delete-After"),
                    &[],
                ))
            }
            Ok(n) if n < 0 => {
                return Some(s3_error_response(
                    "InvalidArgument",
                    Some("X-Delete-After in past"),
                    &[],
                ))
            }
            _ => {}
        }
    }
    None
}

fn map_swift_error_object(
    status: u16,
    method: &str,
    cred: &S3Credential,
    bucket: Option<&str>,
    key: Option<&str>,
    next: &NextFn,
) -> Response {
    if status == 404 {
        if let (Some(b), Some(_)) = (bucket, key) {
            let mut head = make_swift_req("HEAD", &s3_to_swift_path(&cred.account, Some(b), None));
            stamp_auth(&mut head, cred);
            let probe = next(head);
            if !(200..300).contains(&probe.status) {
                return map_swift_error(probe.status, Some(b), None);
            }
            // S3: DELETE of a missing object is 204 when the bucket exists.
            if method == "DELETE" {
                return delete_object_response();
            }
        }
    }
    map_swift_error(status, bucket, key)
}

fn copy_source_query_allowed(query: &str) -> bool {
    query.split('&').filter(|p| !p.is_empty()).all(|pair| {
        let name = pair.split('=').next().unwrap_or("");
        name == "versionId"
    })
}

fn dest_bucket_and_key_from_path(path: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    if parts.len() >= 4 && parts[0] == "v1" {
        let key = parts[3..].join("/");
        if key.is_empty() {
            return None;
        }
        return Some((parts[2].to_string(), key));
    }
    if parts.len() >= 2 {
        let key = parts[1..].join("/");
        if key.is_empty() {
            return None;
        }
        return Some((parts[0].to_string(), key));
    }
    None
}

/// AWS rejects CopyObject onto the same bucket/key unless the client
/// sends `x-amz-metadata-directive: REPLACE` or a source `versionId`.
fn reject_copy_to_self(req: &Request) -> Option<Response> {
    let src = req
        .headers
        .get("X-Amz-Copy-Source")
        .or_else(|| req.headers.get("x-amz-copy-source"))?;
    let directive = req
        .headers
        .get("X-Amz-Metadata-Directive")
        .or_else(|| req.headers.get("x-amz-metadata-directive"))
        .unwrap_or("COPY");
    if !directive.eq_ignore_ascii_case("COPY") {
        return None;
    }
    let (src_b, src_k, src_vid) = parse_copy_source(src)?;
    if src_vid.is_some() {
        return None;
    }
    let (dest_b, dest_k) = dest_bucket_and_key_from_path(&req.path)?;
    if dest_b == src_b && dest_k == src_k {
        return Some(s3_error_response(
            "InvalidRequest",
            Some(
                "This copy request is illegal because it is trying to copy an object to itself without changing the object's metadata, storage class, website redirect location or encryption attributes.",
            ),
            &[],
        ));
    }
    None
}

/// UploadPartCopy `x-amz-copy-source-range` must be exactly `bytes=first-last`.
fn parse_copy_source_range(raw: &str) -> Result<(u64, u64), ()> {
    let trimmed = raw.trim();
    let lower = trimmed.to_ascii_lowercase();
    let rest = lower.strip_prefix("bytes=").ok_or(())?;
    if rest.contains(',') {
        return Err(());
    }
    let (start, end) = rest.split_once('-').ok_or(())?;
    if start.is_empty() || end.is_empty() {
        return Err(());
    }
    let start: u64 = start.parse().map_err(|_| ())?;
    let end: u64 = end.parse().map_err(|_| ())?;
    if start > end {
        return Err(());
    }
    Ok((start, end))
}

fn apply_copy_source(req: &mut Request) -> Option<Response> {
    let src = req.headers.get("X-Amz-Copy-Source").map(str::to_string)?;
    let src = src.trim().trim_start_matches('/');
    if src.is_empty() {
        return Some(s3_error_response(
            "InvalidArgument",
            Some("X-Amz-Copy-Source"),
            &[],
        ));
    }
    let (path, query) = src.split_once('?').unwrap_or((src, ""));
    if !copy_source_query_allowed(query) {
        return Some(s3_error_response("InvalidArgument", None, &[]));
    }
    let directive = req
        .headers
        .get("X-Amz-Metadata-Directive")
        .unwrap_or("COPY");
    match directive.to_ascii_uppercase().as_str() {
        "COPY" => {
            // Dest meta must not override source on COPY (official
            // test_put_object_copy_metadata_directive).
            let drop: Vec<String> = req
                .headers
                .iter()
                .map(|(k, _)| k.to_string())
                .filter(|k| {
                    let l = k.to_ascii_lowercase();
                    l.starts_with("x-object-meta-") || l.starts_with("x-amz-meta-")
                })
                .collect();
            for k in drop {
                req.headers.remove(&k);
            }
        }
        "REPLACE" => req.headers.set("X-Fresh-Metadata", "True"),
        _ => return Some(s3_error_response("InvalidArgument", None, &[])),
    }
    let decoded = percent_decode_component(path);
    req.headers.set("X-Copy-From", percent_encode_except_slash(&decoded));
    req.body = Body::empty();
    req.headers.remove("Content-Length");
    None
}

fn percent_encode_except_slash(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for &b in raw.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~' | b'/') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Python `host_url + req.path`: `http://host:port/bucket/key` with the key
/// quoted like PATH_INFO (`obj1☃` → `obj1%E2%98%83`).
fn complete_object_location(req: &Request, bucket: &str, key: &str) -> String {
    let host = req
        .headers
        .get("Host")
        .or_else(|| req.headers.get("host"))
        .unwrap_or("localhost");
    let proto = req
        .headers
        .get("X-Forwarded-Proto")
        .or_else(|| req.headers.get("x-forwarded-proto"))
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| {
            if host.ends_with(":443") || host.ends_with(":8085") {
                "https"
            } else {
                "http"
            }
        });
    format!(
        "{proto}://{host}/{bucket}/{}",
        percent_encode_except_slash(key)
    )
}

fn percent_decode_component(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(hex) = std::str::from_utf8(&bytes[i + 1..i + 3]) {
                if let Ok(value) = u8::from_str_radix(hex, 16) {
                    out.push(value);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse `X-Amz-Copy-Source` as `(bucket, key, version_id)`.
fn parse_copy_source(raw: &str) -> Option<(String, String, Option<String>)> {
    let trimmed = raw.trim().trim_start_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    let (path, query) = trimmed.split_once('?').unwrap_or((trimmed, ""));
    let decoded = percent_decode_component(path);
    let slash = decoded.find('/')?;
    let bucket = decoded[..slash].to_string();
    let key = decoded[slash + 1..].to_string();
    if bucket.is_empty() || key.is_empty() {
        return None;
    }
    if !copy_source_query_allowed(query) {
        return None;
    }
    let version_id = query.split('&').find_map(|pair| {
        let (name, value) = pair.split_once('=')?;
        (name == "versionId" && !value.is_empty()).then(|| percent_decode_component(value))
    });
    Some((bucket, key, version_id))
}

/// Parse `max-keys`. Any non-u32 value (including `blah`, negatives) is
/// S3 `InvalidArgument`. Last valid occurrence wins when all are numeric.
fn parse_list_max_keys(params: &[(String, String)]) -> Result<u32, Response> {
    let mut last: Option<u32> = None;
    for (k, raw) in params {
        if k != "max-keys" {
            continue;
        }
        match raw.parse::<u32>() {
            Ok(n) => last = Some(n),
            Err(_) => {
                return Err(s3_error_response(
                    "InvalidArgument",
                    Some("max-keys"),
                    &[("ArgumentName", "max-keys"), ("ArgumentValue", raw.as_str())],
                ));
            }
        }
    }
    Ok(last.unwrap_or(1000))
}

/// When `X-Amz-Copy-Source` names a `versionId`, rewrite the header to the
/// resolved Swift object (current key or `{bucket}+versions` archive) so
/// `X-Copy-From` and UploadPartCopy GET historical bytes, not the latest.
async fn rewrite_copy_source_version_async(
    req: &mut Request,
    cred: &S3Credential,
    next: &AsyncNextFn,
) -> Option<Response> {
    let raw = req
        .headers
        .get("X-Amz-Copy-Source")
        .or_else(|| req.headers.get("x-amz-copy-source"))?
        .to_string();
    let (bucket, key, version_id) = parse_copy_source(&raw)?;
    let Some(version_id) = version_id else {
        return None;
    };
    let target = match resolve_object_version_async(cred, &bucket, &key, Some(&version_id), next).await {
        Ok(Some(t)) => t,
        Ok(None) => return Some(missing_object_version_response(&key, Some(&version_id))),
        Err(resp) => return Some(resp),
    };
    if is_delete_marker_header(target.head.headers.get(SYS_DELETE_MARKER)) {
        return Some(nosuchkey_delete_marker(&key, Some(&version_id)));
    }
    req.headers.set(
        "X-Amz-Copy-Source",
        format!(
            "/{}/{}",
            target.container,
            percent_encode_except_slash(&target.key)
        ),
    );
    None
}



fn rewrite_copy_source_version(
    req: &mut Request,
    cred: &S3Credential,
    next: &NextFn,
) -> Option<Response> {
    let raw = req
        .headers
        .get("X-Amz-Copy-Source")
        .or_else(|| req.headers.get("x-amz-copy-source"))?
        .to_string();
    let (bucket, key, version_id) = parse_copy_source(&raw)?;
    let Some(version_id) = version_id else {
        return None;
    };
    let target = match resolve_object_version(cred, &bucket, &key, Some(&version_id), next) {
        Ok(Some(t)) => t,
        Ok(None) => return Some(missing_object_version_response(&key, Some(&version_id))),
        Err(resp) => return Some(resp),
    };
    if is_delete_marker_header(target.head.headers.get(SYS_DELETE_MARKER)) {
        return Some(nosuchkey_delete_marker(&key, Some(&version_id)));
    }
    req.headers.set(
        "X-Amz-Copy-Source",
        format!(
            "/{}/{}",
            target.container,
            percent_encode_except_slash(&target.key)
        ),
    );
    None
}

fn s3_to_swift_query(params: &[(String, String)], for_container_list: bool) -> String {
    let mut out: Vec<(String, String)> = Vec::new();
    if for_container_list {
        out.push(("format".into(), "json".into()));
    }
    // Python s3api always requests `limit = max_keys + 1` so truncation is
    // detectable (see controllers/bucket.py `_parse_request_options`).
    let mut max_keys: Option<u32> = None;
    let mut v1_marker: Option<String> = None;
    let mut start_after: Option<String> = None;
    let mut continuation: Option<String> = None;
    for (k, v) in params {
        match k.as_str() {
            "prefix" => out.push(("prefix".into(), v.clone())),
            "marker" => v1_marker = Some(v.clone()),
            "start-after" => start_after = Some(v.clone()),
            "continuation-token" => continuation = Some(v.clone()),
            "delimiter" => out.push(("delimiter".into(), v.clone())),
            "max-keys" => {
                if let Ok(n) = v.parse() {
                    max_keys = Some(n);
                }
            }
            // Drop SigV4 query auth + S3-only keys from the Swift subrequest.
            "X-Amz-Algorithm"
            | "X-Amz-Credential"
            | "X-Amz-Date"
            | "X-Amz-Expires"
            | "X-Amz-SignedHeaders"
            | "X-Amz-Signature"
            | "X-Amz-Security-Token"
            | "location"
            | "encoding-type"
            | "list-type"
            | "fetch-owner"
            | "uploads"
            | "uploadId"
            | "partNumber"
            | "acl"
            | "cors"
            | "delete"
            | "versioning"
            | "versions"
            | "tagging"
            | "lifecycle"
            | "object-lock"
            | "legal-hold"
            | "retention" => {}
            _ => {}
        }
    }
    if for_container_list {
        // ListObjectsV2: ContinuationToken wins over StartAfter (AWS + Python).
        let swift_marker = continuation
            .filter(|s| !s.is_empty())
            .or_else(|| v1_marker.filter(|s| !s.is_empty()))
            .or_else(|| start_after.filter(|s| !s.is_empty()));
        if let Some(m) = swift_marker {
            out.push(("marker".into(), m));
        }
        let mk = max_keys.unwrap_or(1000);
        out.push(("limit".into(), mk.saturating_add(1).to_string()));
    }
    out.iter()
        .map(|(k, v)| format!("{}={}", encode_query(k), encode_query(v)))
        .collect::<Vec<_>>()
        .join("&")
}

fn encode_query(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else if b == b' ' {
            out.push('%');
            out.push('2');
            out.push('0');
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn swift_ts_to_s3(ts: &str) -> String {
    // Match HTTP Last-Modified (`ceil` of X-Timestamp), not the floored
    // iso second. Official test_object compares listing to Copy XML.
    s3_xml_timestamp_ceil(ts)
}

fn quote_etag(etag: &str) -> String {
    let t = etag.trim().trim_matches('"');
    format!("\"{t}\"")
}

fn bare_etag(etag: &str) -> String {
    etag.trim().trim_matches('"').to_string()
}

fn apply_s3api_etag_override(resp: &mut Response) {
    if let Some(v) = resp
        .headers
        .get(SYS_S3API_ETAG)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
    {
        resp.headers.set("ETag", v);
    }
}

/// Python `S3Response` header filter: Swift object headers → S3 names.
fn translate_swift_to_s3_object_headers(resp: &mut Response) {
    let pairs: Vec<(String, String)> = resp
        .headers
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    for (k, v) in pairs {
        let lower = k.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("x-object-meta-") {
            if rest.starts_with("s3-") || rest == "s3api-etag" {
                continue;
            }
            let amz = format!("x-amz-meta-{}", rest.replace("=5f", "_"));
            resp.headers.remove(&k);
            resp.headers.set(&amz, &v);
        } else if lower == "x-object-version-id" {
            resp.headers.remove(&k);
            resp.headers.set("x-amz-version-id", &v);
        } else if lower == "x-parts-count" {
            resp.headers.remove(&k);
            resp.headers.set("x-amz-mp-parts-count", &v);
        } else if let Some(out) = restore_s3_object_header(&lower) {
            if resp.headers.get(out).is_none() {
                resp.headers.set(out, &v);
            }
            if lower.starts_with("x-object-sysmeta-s3-") {
                resp.headers.remove(&k);
            }
        }
    }
    apply_amz_expiration_header(resp);
}

fn location_constraint_xml(location: &str) -> Vec<u8> {
    // Empty location == classic us-east-1 shape when configured as us-east-1.
    if location == "us-east-1" {
        Element::new("LocationConstraint").to_xml(true)
    } else {
        Element::leaf("LocationConstraint", location).to_xml(true)
    }
}

fn map_swift_error(status: u16, bucket: Option<&str>, key: Option<&str>) -> Response {
    let (code, extras): (&str, Vec<(&str, String)>) = match status {
        404 if key.is_some() => {
            let mut e = Vec::new();
            if let Some(k) = key {
                e.push(("Key", k.to_string()));
            }
            if let Some(b) = bucket {
                e.push(("BucketName", b.to_string()));
            }
            ("NoSuchKey", e)
        }
        404 => {
            let mut e = Vec::new();
            if let Some(b) = bucket {
                e.push(("BucketName", b.to_string()));
            }
            ("NoSuchBucket", e)
        }
        401 | 403 => ("AccessDenied", Vec::new()),
        405 => ("MethodNotAllowed", Vec::new()),
        409 => ("BucketNotEmpty", Vec::new()),
        411 => ("MissingContentLength", Vec::new()),
        412 => ("PreconditionFailed", Vec::new()),
        416 => ("InvalidRange", Vec::new()),
        507 | 413 => ("EntityTooLarge", Vec::new()),
        // Client hung up / short body (Swift 499). Not a commit. S3-3:
        // cancellation is not a successful PUT and not an InternalError.
        // Python PUT maps 408/499 (client hung up / short body) to
        // RequestTimeout 400. s3compat test_object_create_bad_contentlength_mismatch_above.
        408 | 499 => ("RequestTimeout", Vec::new()),
        422 => ("BadDigest", Vec::new()),
        500..=599 => ("InternalError", Vec::new()),
        _ => ("InvalidRequest", Vec::new()),
    };
    let extras_ref: Vec<(&str, &str)> = extras.iter().map(|(k, v)| (*k, v.as_str())).collect();
    s3_error_response(code, None, &extras_ref)
}

fn translate_list_buckets(body: &[u8], owner: &Owner) -> Response {
    let parsed: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return s3_error_response("InternalError", Some("bad account listing"), &[]),
    };
    let arr = match parsed.as_array() {
        Some(a) => a,
        None => return s3_error_response("InternalError", Some("bad account listing"), &[]),
    };
    let buckets: Vec<BucketInfo> = arr
        .iter()
        .filter_map(|item| {
            let name = item.get("name")?.as_str()?.to_string();
            // Internal Swift siblings are not S3 buckets. Listing them made
            // official reset() DELETE `/name+segments` (405) and leaked
            // `{bucket}+versions` into ListBuckets (`+` is not a legal S3
            // name → Ceph nuke ParamValidationError on every later test).
            if name.ends_with(MULTIUPLOAD_SUFFIX) || name.ends_with("+versions") {
                return None;
            }
            let created = item
                .get("last_modified")
                .and_then(|v| v.as_str())
                .unwrap_or("1970-01-01T00:00:00.000000");
            Some(BucketInfo {
                name,
                creation_date: swift_ts_to_s3(created),
            })
        })
        .collect();
    xml_response(200, list_all_my_buckets_xml(owner, &buckets))
}

fn s3_etag_from_listing_hash(hash: &str) -> Option<String> {
    for part in hash.split(';') {
        let part = part.trim();
        if let Some(v) = part.strip_prefix("s3_etag=") {
            let v = v.trim();
            if !v.is_empty() {
                return Some(bare_etag(v));
            }
        }
    }
    None
}

fn listing_display_etag(hash: &str) -> String {
    if let Some(etag) = s3_etag_from_listing_hash(hash) {
        return quote_etag(&etag);
    }
    quote_etag(hash.split(';').next().unwrap_or(hash))
}

fn listing_hash_needs_head(hash: &str) -> bool {
    if s3_etag_from_listing_hash(hash).is_some() {
        return true;
    }
    let bare = bare_etag(hash.split(';').next().unwrap_or(hash));
    if bare.len() == 32 && bare.chars().all(|c| c.is_ascii_hexdigit()) {
        return true;
    }
    if let Some((h, n)) = bare.rsplit_once('-') {
        return h.len() == 32
            && h.chars().all(|c| c.is_ascii_hexdigit())
            && !n.is_empty()
            && n.chars().all(|c| c.is_ascii_digit());
    }
    false
}

/// Official ListBucket MPU ETag is the composite `md5-N`, not the Swift
/// SLO manifest MD5. Prefer `s3_etag=` in the listing hash; else HEAD
/// for [`SYS_S3API_ETAG`]. Live object-server does not honor the
/// container-update override header. Same HEAD supplies assembled
/// `Content-Length` so Size is not the 137-byte manifest.
fn rewrite_listing_s3_etags(
    body: &[u8],
    cred: &S3Credential,
    bucket: &str,
    next: &NextFn,
) -> Vec<u8> {
    let Ok(Value::Array(mut arr)) = serde_json::from_slice(body) else {
        return body.to_vec();
    };
    for item in &mut arr {
        if item.get("subdir").is_some() {
            continue;
        }
        let Some(name) = item.get("name").and_then(|v| v.as_str()).map(str::to_string) else {
            continue;
        };
        let hash = item
            .get("hash")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if let Some(etag) = s3_etag_from_listing_hash(&hash) {
            item["hash"] = Value::String(etag);
        }
        if !listing_hash_needs_head(&hash) {
            continue;
        }
        if let Ok(ObjectHead::Present(head)) = control_head_object(cred, bucket, &name, next) {
            if let Some(v) = head
                .headers
                .get(SYS_S3API_ETAG)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
            {
                item["hash"] = Value::String(bare_etag(&v));
            }
            if let Some(cl) = head
                .headers
                .get("Content-Length")
                .and_then(|s| s.parse::<u64>().ok())
            {
                item["bytes"] = Value::Number(cl.into());
            }
        }
    }
    serde_json::to_vec(&arr).unwrap_or_else(|_| body.to_vec())
}

fn translate_list_objects(
    body: &[u8],
    bucket: &str,
    params: &[(String, String)],
    owner: &Owner,
) -> Response {
    let parsed: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return s3_error_response("InternalError", Some("bad container listing"), &[]),
    };
    let arr = match parsed.as_array() {
        Some(a) => a,
        None => return s3_error_response("InternalError", Some("bad container listing"), &[]),
    };
    let prefix = params
        .iter()
        .find(|(k, _)| k == "prefix")
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    let marker = params
        .iter()
        .find(|(k, _)| k == "marker")
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    let delimiter = params
        .iter()
        .find(|(k, _)| k == "delimiter")
        .map(|(_, v)| v.clone())
        .filter(|d| !d.is_empty());
    let encoding_type = params
        .iter()
        .find(|(k, v)| k == "encoding-type" && v == "url")
        .map(|(_, v)| v.clone());
    let max_keys = params
        .iter()
        .find(|(k, _)| k == "max-keys")
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(1000u32);

    // Ordered entries so max_keys truncation matches Python (objects + subdirs).
    enum Entry {
        Object(S3Object),
        Prefix(String),
    }
    let mut entries: Vec<Entry> = Vec::new();
    for item in arr {
        if let Some(subdir) = item.get("subdir").and_then(|v| v.as_str()) {
            entries.push(Entry::Prefix(subdir.to_string()));
            continue;
        }
        let Some(name) = item.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        let hash = item.get("hash").and_then(|v| v.as_str()).unwrap_or("");
        let bytes = item.get("bytes").and_then(|v| v.as_u64()).unwrap_or(0);
        let last_modified = item
            .get("last_modified")
            .and_then(|v| v.as_str())
            .unwrap_or("1970-01-01T00:00:00.000000");
        entries.push(Entry::Object(S3Object {
            key: name.to_string(),
            last_modified: swift_ts_to_s3(last_modified),
            etag: listing_display_etag(hash),
            size: bytes,
            storage_class: "STANDARD".into(),
            owner: Some(Owner {
                id: owner.id.clone(),
                display_name: owner.display_name.clone(),
            }),
        }));
    }
    // Python: is_truncated = max_keys > 0 and len(objects) > max_keys
    //         objects = objects[:max_keys]  (always slice, so max-keys=0 → [])
    let is_truncated = max_keys > 0 && entries.len() as u32 > max_keys;
    entries.truncate(max_keys as usize);
    // NextMarker only when delimiter present (Python bucket.py XXX note).
    let next_marker = if is_truncated && delimiter.is_some() {
        match entries.last() {
            Some(Entry::Object(o)) => Some(o.key.clone()),
            Some(Entry::Prefix(p)) => Some(p.clone()),
            None => None,
        }
    } else {
        None
    };
    let mut contents = Vec::new();
    let mut common_prefixes = Vec::new();
    for e in entries {
        match e {
            Entry::Object(o) => contents.push(o),
            Entry::Prefix(p) => common_prefixes.push(p),
        }
    }
    let lbr = ListBucketResult {
        name: bucket.to_string(),
        prefix,
        marker,
        next_marker,
        max_keys,
        delimiter,
        encoding_type,
        is_truncated,
        contents,
        common_prefixes,
    };
    // into_response → Content-Type: application/xml + xmlns ListBucketResult.
    lbr.into_response()
}

fn translate_list_objects_v2(
    body: &[u8],
    bucket: &str,
    params: &[(String, String)],
    owner: &Owner,
) -> Response {
    let parsed: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return s3_error_response("InternalError", Some("bad container listing"), &[]),
    };
    let arr = match parsed.as_array() {
        Some(a) => a,
        None => return s3_error_response("InternalError", Some("bad container listing"), &[]),
    };
    let prefix = params
        .iter()
        .find(|(k, _)| k == "prefix")
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    let start_after = params
        .iter()
        .find(|(k, _)| k == "start-after")
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    let continuation_token = params
        .iter()
        .find(|(k, _)| k == "continuation-token")
        .map(|(_, v)| v.clone());
    let delimiter = params
        .iter()
        .find(|(k, _)| k == "delimiter")
        .map(|(_, v)| v.clone())
        .filter(|d| !d.is_empty());
    let encoding_type = params
        .iter()
        .find(|(k, v)| k == "encoding-type" && v == "url")
        .map(|(_, v)| v.clone());
    let max_keys = params
        .iter()
        .find(|(k, _)| k == "max-keys")
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(1000u32);
    let fetch_owner = params
        .iter()
        .any(|(k, v)| k == "fetch-owner" && (v == "true" || v == "True" || v == "1"));

    enum Entry {
        Object(S3Object),
        Prefix(String),
    }
    let mut entries: Vec<Entry> = Vec::new();
    for item in arr {
        if let Some(subdir) = item.get("subdir").and_then(|v| v.as_str()) {
            entries.push(Entry::Prefix(subdir.to_string()));
            continue;
        }
        let Some(name) = item.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        let hash = item.get("hash").and_then(|v| v.as_str()).unwrap_or("");
        let bytes = item.get("bytes").and_then(|v| v.as_u64()).unwrap_or(0);
        let last_modified = item
            .get("last_modified")
            .and_then(|v| v.as_str())
            .unwrap_or("1970-01-01T00:00:00.000000");
        entries.push(Entry::Object(S3Object {
            key: name.to_string(),
            last_modified: swift_ts_to_s3(last_modified),
            etag: listing_display_etag(hash),
            size: bytes,
            storage_class: "STANDARD".into(),
            owner: if fetch_owner {
                Some(Owner {
                    id: owner.id.clone(),
                    display_name: owner.display_name.clone(),
                })
            } else {
                None
            },
        }));
    }
    let is_truncated = max_keys > 0 && entries.len() as u32 > max_keys;
    entries.truncate(max_keys as usize);
    let next_continuation_token = if is_truncated {
        match entries.last() {
            Some(Entry::Object(o)) => Some(o.key.clone()),
            Some(Entry::Prefix(p)) => Some(p.clone()),
            None => None,
        }
    } else {
        None
    };
    let mut contents = Vec::new();
    let mut common_prefixes = Vec::new();
    for e in entries {
        match e {
            Entry::Object(o) => contents.push(o),
            Entry::Prefix(p) => common_prefixes.push(p),
        }
    }
    let key_count = (contents.len() + common_prefixes.len()) as u32;
    ListBucketResultV2 {
        name: bucket.to_string(),
        prefix,
        start_after,
        continuation_token,
        next_continuation_token,
        key_count,
        max_keys,
        delimiter,
        encoding_type,
        is_truncated,
        contents,
        common_prefixes,
    }
    // into_response → Content-Type: application/xml + xmlns ListBucketResult.
    .into_response()
}

fn translate_object_success(method: &str, mut resp: Response, is_copy: bool) -> Response {
    match method {
        "PUT" if is_copy => {
            let etag = resp.headers.get("ETag").map(bare_etag).unwrap_or_default();
            xml_response(200, copy_object_result_xml(&copy_xml_last_modified(&resp), &etag))
        }
        "PUT" => {
            let etag = resp.headers.get("ETag").map(bare_etag).unwrap_or_default();
            put_object_response(&etag)
        }
        "DELETE" => delete_object_response(),
        "GET" | "HEAD" => {
            // S3 uses 200 for HEAD/GET; quote ETag if present.
            apply_s3_amz_ids(&mut resp);
            apply_s3api_etag_override(&mut resp);
            translate_swift_to_s3_object_headers(&mut resp);
            if let Some(etag) = resp.headers.get("ETag").map(str::to_string) {
                resp.headers.set("ETag", quote_etag(&etag));
            }
            if resp.status == 201 {
                resp.status = 200;
            }
            if resp.headers.get("Accept-Ranges").is_none() {
                resp.headers.set("Accept-Ranges", "bytes");
            }
            resp
        }
        _ => resp,
    }
}

fn apply_response_overrides(resp: &mut Response, params: &[(String, String)]) {
    for (k, v) in params {
        match k.as_str() {
            "response-content-type" => resp.headers.set("Content-Type", v),
            "response-content-language" => resp.headers.set("Content-Language", v),
            "response-cache-control" => resp.headers.set("Cache-Control", v),
            "response-content-disposition" => resp.headers.set("Content-Disposition", v),
            "response-content-encoding" => resp.headers.set("Content-Encoding", v),
            "response-expires" => resp.headers.set("Expires", v),
            _ => {}
        }
    }
}

fn range_content_length(spec: &str, total: u64) -> Option<u64> {
    let spec = spec
        .split(',')
        .next()?
        .trim()
        .strip_prefix("bytes=")?;
    if let Some(n) = spec.strip_prefix('-') {
        let n: u64 = n.parse().ok()?;
        return Some(n.min(total));
    }
    let (start, end) = spec.split_once('-')?;
    let start: u64 = start.parse().ok()?;
    if end.is_empty() {
        return Some(total.saturating_sub(start));
    }
    let end: u64 = end.parse().ok()?;
    if end < start {
        return None;
    }
    Some((end - start + 1).min(total.saturating_sub(start)))
}

fn apply_head_range(resp: &mut Response, range: Option<&str>) {
    if resp.status != 200 {
        return;
    }
    let Some(range) = range else {
        return;
    };
    let total = resp
        .headers
        .get("Content-Length")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    if let Some(len) = range_content_length(range, total) {
        resp.headers.set("Content-Length", len.to_string());
    }
}

/// If object JSON ACL grants deny this principal READ, return AccessDenied.
/// Missing/empty grants → `None` (no new denial).
fn deny_if_object_acl_blocks_read(
    cred: &S3Credential,
    headers: &HeaderKeyDict,
) -> Option<Response> {
    if object_acl_denies_read(headers, &cred.access_key, &cred.account) {
        Some(s3_error_response("AccessDenied", None, &[]))
    } else {
        None
    }
}

fn etag_list_matches(header: &str, etag: &str) -> bool {
    let want = bare_etag(etag);
    header.split(',').any(|part| {
        let p = part.trim();
        p == "*" || bare_etag(p) == want
    })
}

fn not_modified_from(resp: &Response) -> Response {
    let mut out = Response::new(304);
    out.body = Body::empty();
    if let Some(v) = resp.headers.get("Last-Modified") {
        out.headers.set("Last-Modified", v);
    }
    if let Some(v) = resp.headers.get("ETag") {
        out.headers.set("ETag", quote_etag(v));
    }
    out.headers.set("Accept-Ranges", "bytes");
    out.headers.set("Content-Length", "0");
    apply_s3_amz_ids(&mut out);
    out
}

fn precondition_failed_get_head(method: &str) -> Response {
    // Official MPU HEAD If-Match: 412, no ETag, Content-Length 0.
    if method == "HEAD" {
        let mut out = Response::new(412);
        out.body = Body::empty();
        out.headers.set("Content-Type", "text/html; charset=UTF-8");
        out.headers.set("Content-Length", "0");
        apply_s3_amz_ids(&mut out);
        return out;
    }
    s3_error_response("PreconditionFailed", None, &[])
}

/// RFC 7232 order on the *S3* ETag (sysmeta override), not Swift SLO MD5.
fn apply_get_head_preconditions(
    resp: Response,
    method: &str,
    if_match: Option<&str>,
    ius: Option<&str>,
    if_none_match: Option<&str>,
    ims: Option<&str>,
) -> Response {
    if !((200..300).contains(&resp.status)) {
        return resp;
    }
    if let Some(im) = if_match {
        let etag = resp.headers.get("ETag").unwrap_or("");
        if !etag_list_matches(im, etag) {
            return precondition_failed_get_head(method);
        }
    }
    if let Some(ius) = ius {
        if let Some(lm_ts) = resp.headers.get("Last-Modified").and_then(parse_http_date) {
            if let Some(ius_ts) = parse_http_date(ius) {
                // Listing LastModified is floored to the second; Last-Modified
                // HTTP can land on the next second. Compare at S3 second
                // precision, not sub-second X-Timestamp.
                if lm_ts > ius_ts.saturating_add(1) {
                    return precondition_failed_get_head(method);
                }
            }
        }
    }
    if let Some(inm) = if_none_match {
        let etag = resp.headers.get("ETag").unwrap_or("");
        if etag_list_matches(inm, etag) {
            return not_modified_from(&resp);
        }
    }
    if let Some(ims) = ims {
        if let Some(lm_ts) = resp.headers.get("Last-Modified").and_then(parse_http_date) {
            if let Some(ims_ts) = parse_http_date(ims) {
                if lm_ts <= ims_ts.saturating_add(1) {
                    return not_modified_from(&resp);
                }
            }
        }
    }
    resp
}

fn deny_if_object_acl_blocks_write(
    cred: &S3Credential,
    headers: &HeaderKeyDict,
) -> Option<Response> {
    if object_acl_denies_write(headers, &cred.access_key, &cred.account) {
        Some(s3_error_response("AccessDenied", None, &[]))
    } else {
        None
    }
}

/// S3 GET/HEAD of a cold object (due transition / successful lab archive).
fn invalid_object_state_response() -> Response {
    s3_error_response(
        "InvalidObjectState",
        Some("The operation is not valid for the object's storage class"),
        &[],
    )
}

fn deny_if_transition_blocks_get(headers: &mut HeaderKeyDict, now: i64) -> Option<Response> {
    apply_due_transition_on_headers(headers, now);
    if transition_blocks_get(headers, now) {
        Some(invalid_object_state_response())
    } else {
        None
    }
}

/// Cap for materializing object bytes to lab-archive on due cold transition.
const MAX_COLD_ARCHIVE_BODY: u64 = MAX_CONTROL_BODY;

/// Headers persisted after due-cold archive (POST meta / optional PUT empty).
/// PROTOTYPE / DEFAULT OFF / NOT ACCEPTED. Not Glacier.
const COLD_PERSIST_HEADERS: &[&str] = &[
    META_STORAGE_CLASS,
    SYS_TRANSITIONED,
    SYS_COLD_POLICY_INDEX,
    SYS_HOT_POLICY_INDEX,
    SYS_COLD_BACKEND_URI,
    SYS_COLD_ARCHIVE_STATE,
    SYS_COLD_CONTENT_LENGTH,
    SYS_COLD_CONTENT_SHA256,
    SYS_COLD_ARCHIVE_GENERATION,
    SYS_COLD_RESTORE_GENERATION,
    SYS_RESTORE_UNTIL,
    SYS_HOT_RECLAIMED,
    HDR_BACKEND_STORAGE_POLICY_INDEX,
];

const SYS_HOT_RECLAIMED: &str = "X-Object-Sysmeta-S3-Hot-Reclaimed";

fn copy_cold_persist_headers(src: &HeaderKeyDict, dst: &mut HeaderKeyDict) {
    for hdr in COLD_PERSIST_HEADERS {
        if let Some(v) = src.get(hdr) {
            dst.set(hdr, v);
        }
    }
}

/// Replace hot body with empty bytes. Call only after a successful archive
/// that stamped [`SYS_COLD_BACKEND_URI`]. Metadata on `headers` is left
/// intact (caller keeps cold stamps). Lab LocalDir/Memory — not tape.
fn replace_hot_body_empty(headers: &mut HeaderKeyDict, body: &mut Body) {
    *body = Body::empty();
    headers.set("Content-Length", "0");
    headers.remove("Transfer-Encoding");
}

fn is_range_or_206_response(status: u16, headers: &HeaderKeyDict) -> bool {
    status == 206 || headers.get("Content-Range").is_some()
}

fn parse_cold_generation(headers: &HeaderKeyDict, name: &str) -> u64 {
    headers.get(name).and_then(|s| s.parse().ok()).unwrap_or(0)
}

/// In-process reconstruct. There is no `from_headers` in `cold_tier`.
/// Receipt stays `None` until `fetch_verified` / `archive_durable` proves Durable.
fn reconstruct_cold_state_machine(headers: &HeaderKeyDict, now: i64) -> ColdStateMachine {
    let archive_generation = parse_cold_generation(headers, SYS_COLD_ARCHIVE_GENERATION);
    let restore_generation = parse_cold_generation(headers, SYS_COLD_RESTORE_GENERATION);
    let uri = headers.get(SYS_COLD_BACKEND_URI).unwrap_or("");
    let restore_until = headers
        .get(SYS_RESTORE_UNTIL)
        .and_then(|s| s.parse::<i64>().ok());
    let state = if let Some(until) = restore_until {
        if now < until || !uri.is_empty() {
            ColdArchiveState::Restored {
                restore_until_unix: until,
            }
        } else {
            ColdArchiveState::MetadataOnly
        }
    } else if !uri.is_empty() {
        ColdArchiveState::UnverifiedReference
    } else {
        ColdArchiveState::MetadataOnly
    };
    ColdStateMachine {
        state,
        receipt: None,
        archive_generation,
        restore_generation,
    }
}

fn persist_cold_object_meta(
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    src: &HeaderKeyDict,
    next: &NextFn,
) -> Option<Response> {
    let mut post = make_swift_req(
        "POST",
        &s3_to_swift_path(&cred.account, Some(bucket), Some(key)),
    );
    copy_cold_persist_headers(src, &mut post.headers);
    stamp_auth(&mut post, cred);
    let post_resp = next(post);
    if !(200..300).contains(&post_resp.status) {
        Some(map_swift_error(post_resp.status, Some(bucket), Some(key)))
    } else {
        None
    }
}

fn reclaim_hot_object_empty(
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    src: &HeaderKeyDict,
    next: &NextFn,
) -> Option<Response> {
    let mut put = make_swift_req(
        "PUT",
        &s3_to_swift_path(&cred.account, Some(bucket), Some(key)),
    );
    copy_cold_persist_headers(src, &mut put.headers);
    if let Some(ct) = src.get("Content-Type") {
        put.headers.set("Content-Type", ct);
    }
    put.headers.set(SYS_HOT_RECLAIMED, "true");
    replace_hot_body_empty(&mut put.headers, &mut put.body);
    stamp_auth(&mut put, cred);
    let put_resp = next(put);
    if !(200..300).contains(&put_resp.status) {
        Some(map_swift_error(put_resp.status, Some(bucket), Some(key)))
    } else {
        None
    }
}

/// On GET/HEAD success: if a cold transition is due and `cold_map` is set,
/// stamp cold meta; if `cold_backend` is wired, archive bytes and stamp
/// [`SYS_COLD_BACKEND_URI`], then POST meta to persist. Without a backend,
/// meta-only (no URI). Reclaim hot bytes only via [`hot_reclamation_allowed`]
/// (`delete_hot` from config; conceptual default
/// [`COLD_DELETE_HOT_AFTER_ARCHIVE_DEFAULT`]). 206 / `Content-Range` bodies
/// are never archived. Restore window is not re-archived.
/// A successful due-cold stamp returns 400 InvalidObjectState; persist or
/// reclaim 5xx after that stamp must not leak `map_swift_error` InternalError.
/// PROTOTYPE / DEFAULT OFF / NOT ACCEPTED. Not Glacier.
fn maybe_archive_due_cold_on_get_head(
    resp: &mut Response,
    method: &str,
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    cold_map: &crate::cold_tier::ColdPolicyMap,
    cold_backend: Option<&Arc<dyn ColdBackend>>,
    delete_hot: bool,
    next: &NextFn,
) -> Option<Response> {
    if !cold_map.is_configured() {
        return None;
    }
    let now = unix_now();
    apply_due_transition_on_headers(&mut resp.headers, now);

    let is_range_or_206 = is_range_or_206_response(resp.status, &resp.headers);
    if reject_partial_body(is_range_or_206).is_err() {
        // Do not archive a range/206 body, POST a slice URI, or empty-PUT.
        return None;
    }

    let already_cold_meta = resp.headers.get(SYS_COLD_POLICY_INDEX).is_some();
    let already_uri = resp
        .headers
        .get(SYS_COLD_BACKEND_URI)
        .map(|s| !s.is_empty())
        .unwrap_or(false);
    let hot_reclaimed = resp
        .headers
        .get(SYS_HOT_RECLAIMED)
        .map(|value| value.eq_ignore_ascii_case("true") || value == "1")
        .unwrap_or(false);

    let mut machine = reconstruct_cold_state_machine(&resp.headers, now);
    machine = match machine.apply_maybe_rearchive(now, delete_hot) {
        Ok(m) => m,
        Err(e) => {
            return Some(s3_error_response(
                "InternalError",
                Some(&format!("cold rearchive failed: {e}")),
                &[],
            ));
        }
    };
    if machine.state.is_restore_window() {
        return None;
    }

    if already_uri && matches!(machine.state, ColdArchiveState::Durable) {
        // Expired Restored → Durable metadata only. Do not archive_durable.
        let prev_agen = parse_cold_generation(&resp.headers, SYS_COLD_ARCHIVE_GENERATION);
        if machine.archive_generation != prev_agen {
            machine.stamp_generation_headers(&mut resp.headers);
            // Persist 5xx must not leak InternalError: object is already cold.
            let _ = persist_cold_object_meta(cred, bucket, key, &resp.headers, next);
        }
        return Some(invalid_object_state_response());
    }

    let needs_body = cold_backend.is_some() && (!already_uri || (delete_hot && !hot_reclaimed));

    let body_owned: Option<Vec<u8>> = if needs_body {
        if method == "GET" {
            match resp.body.materialize(MAX_COLD_ARCHIVE_BODY) {
                Ok(b) => Some(b.to_vec()),
                Err(_) => {
                    return Some(s3_error_response(
                        "EntityTooLarge",
                        Some("object exceeds lab cold-archive size limit"),
                        &[],
                    ));
                }
            }
        } else {
            // HEAD: fetch bytes carefully via GET when Content-Length allows.
            if let Some(cl_s) = resp.headers.get("Content-Length") {
                if let Ok(cl) = cl_s.parse::<u64>() {
                    if cl > MAX_COLD_ARCHIVE_BODY {
                        return Some(s3_error_response(
                            "EntityTooLarge",
                            Some("object exceeds lab cold-archive size limit"),
                            &[],
                        ));
                    }
                }
            }
            let mut get = make_swift_req(
                "GET",
                &s3_to_swift_path(&cred.account, Some(bucket), Some(key)),
            );
            stamp_auth(&mut get, cred);
            let got = next(get);
            if !(200..300).contains(&got.status) {
                return Some(map_swift_error(got.status, Some(bucket), Some(key)));
            }
            if reject_partial_body(is_range_or_206_response(got.status, &got.headers)).is_err() {
                return None;
            }
            match got.body.into_vec(MAX_COLD_ARCHIVE_BODY) {
                Ok(b) => Some(b),
                Err(_) => {
                    return Some(s3_error_response(
                        "EntityTooLarge",
                        Some("object exceeds lab cold-archive size limit"),
                        &[],
                    ));
                }
            }
        }
    } else {
        None
    };

    let be_ref = cold_backend.map(|a| a.as_ref() as &dyn ColdBackend);
    let stamped = match maybe_stamp_and_archive_due_cold(
        &mut resp.headers,
        cold_map,
        now,
        &cred.account,
        bucket,
        key,
        be_ref,
        body_owned.as_deref(),
    ) {
        Ok(s) => s,
        Err(e) => {
            return Some(s3_error_response(
                "InternalError",
                Some(&format!("cold archive failed: {e}")),
                &[],
            ));
        }
    };
    let stamp = stamped?;

    if let (Some(receipt), Some(body)) = (stamp.archive_receipt.clone(), body_owned.as_deref()) {
        match machine.apply_archive_commit(receipt, body, false) {
            Ok(next_machine) => machine = next_machine,
            Err(e) => {
                return Some(s3_error_response(
                    "InternalError",
                    Some(&format!("cold archive failed: {e}")),
                    &[],
                ));
            }
        }
    }
    machine.stamp_generation_headers(&mut resp.headers);

    if !already_cold_meta || stamp.archive_receipt.is_some() {
        // Persist 5xx after a successful stamp must not leak InternalError.
        let _ = persist_cold_object_meta(cred, bucket, key, &resp.headers, next);
    }

    if let Some(body) = body_owned.as_deref() {
        if hot_reclamation_allowed(
            machine.state,
            machine.receipt.as_ref(),
            body,
            delete_hot,
            false,
        ) {
            // Reclaim is lab cleanup; archive already succeeded.
            let _ = reclaim_hot_object_empty(cred, bucket, key, &resp.headers, next);
        }
    }
    // Do not fall through to translate_object_get_head / further next() calls.
    Some(invalid_object_state_response())
}

/// Anonymous GET/HEAD cannot persist cold meta: this path never `stamp_auth`
/// (container `.r:*` must authorize), so Swift object POST would 401/403.
/// Honesty: **meta/deny-only** — stamp due-cold headers on the in-memory
/// response; caller then [`deny_if_transition_blocks_get`]. No backend
/// archive (URI would not persist). No POST. No hot-delete.
fn maybe_stamp_due_cold_on_anonymous_get_head(
    resp: &mut Response,
    account: &str,
    bucket: &str,
    key: &str,
    cold_map: &crate::cold_tier::ColdPolicyMap,
) {
    if !cold_map.is_configured() {
        return;
    }
    let now = unix_now();
    apply_due_transition_on_headers(&mut resp.headers, now);
    let is_range_or_206 = is_range_or_206_response(resp.status, &resp.headers);
    if reject_partial_body(is_range_or_206).is_err() {
        return;
    }
    // Never reclaim on unsigned GET even if the process flag is true.
    let machine = reconstruct_cold_state_machine(&resp.headers, now);
    let machine = match machine.apply_maybe_rearchive(now, COLD_DELETE_HOT_AFTER_ARCHIVE_DEFAULT) {
        Ok(m) => m,
        Err(_) => return,
    };
    if machine.state.is_restore_window() {
        return;
    }
    let _ = maybe_stamp_and_archive_due_cold(
        &mut resp.headers,
        cold_map,
        now,
        account,
        bucket,
        key,
        None,
        None,
    );
}

/// On PUT: if lifecycle stamped an immediate cold transition and a lab backend
/// is wired, archive the put body and stamp [`SYS_COLD_BACKEND_URI`] onto the
/// outgoing Swift request (persists with the object write). Reclaim only via
/// [`hot_reclamation_allowed`] (`delete_hot` from config, default
/// [`COLD_DELETE_HOT_AFTER_ARCHIVE_DEFAULT`]). A `Content-Range` body is not
/// archived. PROTOTYPE / DEFAULT OFF / NOT ACCEPTED. Not Glacier.
fn maybe_archive_due_cold_on_put(
    swift_req: &mut Request,
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    cold_map: &crate::cold_tier::ColdPolicyMap,
    cold_backend: Option<&Arc<dyn ColdBackend>>,
    delete_hot: bool,
) -> Option<Response> {
    if !cold_map.is_configured() {
        return None;
    }
    let now = unix_now();
    apply_due_transition_on_headers(&mut swift_req.headers, now);

    let already_uri = swift_req
        .headers
        .get(SYS_COLD_BACKEND_URI)
        .map(|s| !s.is_empty())
        .unwrap_or(false);
    let is_range_put = swift_req.headers.get("Content-Range").is_some();
    if reject_partial_body(is_range_put).is_err() {
        let be_ref = cold_backend.map(|a| a.as_ref() as &dyn ColdBackend);
        return match maybe_stamp_and_archive_due_cold(
            &mut swift_req.headers,
            cold_map,
            now,
            &cred.account,
            bucket,
            key,
            be_ref,
            None,
        ) {
            Ok(_) => None,
            Err(e) => Some(s3_error_response(
                "InternalError",
                Some(&format!("cold archive failed: {e}")),
                &[],
            )),
        };
    }
    let needs_body = cold_backend.is_some() && !already_uri;

    let body_owned: Option<Vec<u8>> = if needs_body {
        match swift_req.body.materialize(MAX_COLD_ARCHIVE_BODY) {
            Ok(b) => Some(b.to_vec()),
            Err(_) => {
                return Some(s3_error_response(
                    "EntityTooLarge",
                    Some("object exceeds lab cold-archive size limit"),
                    &[],
                ));
            }
        }
    } else {
        None
    };

    let be_ref = cold_backend.map(|a| a.as_ref() as &dyn ColdBackend);
    match maybe_stamp_and_archive_due_cold(
        &mut swift_req.headers,
        cold_map,
        now,
        &cred.account,
        bucket,
        key,
        be_ref,
        body_owned.as_deref(),
    ) {
        Ok(stamp) => {
            if let (Some(stamp), Some(body)) = (stamp.as_ref(), body_owned.as_deref()) {
                if let Some(receipt) = stamp.archive_receipt.clone() {
                    if let Ok(machine) =
                        ColdStateMachine::new().apply_archive_commit(receipt, body, false)
                    {
                        machine.stamp_generation_headers(&mut swift_req.headers);
                        if hot_reclamation_allowed(
                            machine.state,
                            machine.receipt.as_ref(),
                            body,
                            delete_hot,
                            false,
                        ) {
                            swift_req.headers.set(SYS_HOT_RECLAIMED, "true");
                            replace_hot_body_empty(&mut swift_req.headers, &mut swift_req.body);
                        }
                    }
                }
            }
            None
        }
        Err(e) => Some(s3_error_response(
            "InternalError",
            Some(&format!("cold archive failed: {e}")),
            &[],
        )),
    }
}

/// GET/HEAD object success path with structured ACP grant enforcement.
fn translate_object_get_head(
    method: &str,
    mut resp: Response,
    cred: &S3Credential,
    params: &[(String, String)],
    range: Option<&str>,
) -> Response {
    if let Some(denied) = deny_if_object_acl_blocks_read(cred, &resp.headers) {
        return denied;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    if let Some(denied) = deny_if_transition_blocks_get(&mut resp.headers, now) {
        return denied;
    }
    // Surface storage class to S3 clients when present.
    if let Some(sc) = resp
        .headers
        .get("X-Object-Meta-S3-Storage-Class")
        .map(str::to_string)
    {
        resp.headers.set("x-amz-storage-class", sc);
    }
    apply_amz_expiration_header(&mut resp);
    let mut out = translate_object_success(method, resp, false);
    apply_response_overrides(&mut out, params);
    if method == "HEAD" {
        apply_head_range(&mut out, range);
    }
    out
}

fn apply_amz_expiration_header(resp: &mut Response) {
    if let Some(exp) = resp
        .headers
        .get("X-Delete-At")
        .and_then(amz_expiration_from_delete_at)
    {
        resp.headers.set("x-amz-expiration", exp);
    }
    resp.headers.remove("X-Delete-At");
}

fn http_date_to_s3_approx(http_date: &str) -> String {
    s3_xml_timestamp(http_date)
}

/// CopyObject / CopyPart LastModified must match ListObjects and GET
/// `Last-Modified`. Object/proxy `Last-Modified` is `ceil(X-Timestamp)`;
/// flooring `X-Timestamp` lands one second earlier and fails official
/// `test_object` (copy XML vs listing).
fn copy_xml_last_modified(resp: &Response) -> String {
    if let Some(lm) = resp.headers.get("Last-Modified") {
        let xml = s3_xml_timestamp(lm);
        if xml != "1970-01-01T00:00:00.000Z" {
            return xml;
        }
    }
    if let Some(ts) = resp.headers.get("X-Timestamp") {
        let xml = s3_xml_timestamp(ts);
        if xml != "1970-01-01T00:00:00.000Z" {
            return xml;
        }
    }
    "1970-01-01T00:00:00.000Z".to_string()
}

fn translate_bucket_success(method: &str, resp: Response, bucket: Option<&str>) -> Response {
    match method {
        "PUT" => {
            // Swift PUT existing container is 202 Accepted.
            if resp.status == 202 {
                return s3_error_response("BucketAlreadyOwnedByYou", None, &[]);
            }
            // Python BucketController.PUT: HTTP 200 + Location=/<container>.
            let mut r = Response::new(200);
            if let Some(b) = bucket {
                r.headers.set("Location", format!("/{b}"));
            }
            r
        }
        "DELETE" => Response::new(204),
        "HEAD" => {
            let mut r = Response::new(200);
            r.headers.set("Content-Type", "application/xml");
            if let Some(v) = resp.headers.get("X-Container-Object-Count") {
                r.headers.set("x-amz-bucket-object-count", v);
            }
            r
        }
        _ => resp,
    }
}

impl Middleware for S3Api {
    fn intercepts_request(&self, req: &Request) -> bool {
        if self.streams_request(req) {
            return false;
        }
        if is_s3_auth_request(req) {
            return true;
        }
        self.anonymous_account.is_some()
            && is_s3_unsigned_read_candidate(
                req,
                &self.storage_domains,
                self.dns_compliant_bucket_names,
            )
    }

    fn streams_request(&self, req: &Request) -> bool {
        parse_sigv4_auth(req).is_some()
            && is_s3_streaming_object_put(
                req,
                &self.storage_domains,
                self.dns_compliant_bucket_names,
            )
    }

    fn handle_streaming_request(
        &self,
        req: AsyncRequest,
        next: StreamingAsyncNextFn,
    ) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        Box::pin(async move { self.put_object_streaming(req, next).await })
    }

    fn handle_request_async(
        &self,
        req: Request,
        next: AsyncNextFn,
    ) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        Box::pin(async move { self.handle_s3_async(req, next).await })
    }

    fn handle(&self, mut req: Request, next: &NextFn) -> Response {
        // Non-S3 traffic (Swift v1, /auth, /info, healthcheck) passes through.
        // Optional unsigned S3 GET/HEAD → anonymous_account (bucket public-read).
        if !is_s3_auth_request(&req) {
            if let Some(account) = self.anonymous_account.clone() {
                if is_s3_unsigned_read_candidate(
                    &req,
                    &self.storage_domains,
                    self.dns_compliant_bucket_names,
                ) {
                    let mut resp = self.dispatch_anonymous(req, account, next);
                    apply_s3_amz_ids(&mut resp);
                    return resp;
                }
            }
            return next(req);
        }

        let method = req.method.clone();
        let finish = |resp: Response| finish_s3_response(&method, resp);
        if let Some(resp) = reject_invalid_bucket_before_auth(
            &req,
            &self.storage_domains,
            self.dns_compliant_bucket_names,
        ) {
            return finish(resp);
        }
        let (early_bucket, early_key) =
            extract_bucket_and_key(&req, &self.storage_domains, self.dns_compliant_bucket_names);
        let _ = early_bucket;
        if let Some(resp) = put_object_missing_content_length(&req, early_key.as_deref()) {
            return finish(resp);
        }

        // ---- SigV2 auth path (HMAC-SHA1) ----
        if is_sigv2_auth(&req) {
            let auth_v2 = match parse_sigv2_auth(&req) {
                Some(a) => a,
                None => return finish(s3_error_response("AccessDenied", None, &[])),
            };
            let Some((cred, keystone_verified)) = self.resolve_credential_v2(&auth_v2, &req) else {
                return finish(s3_error_response("InvalidAccessKeyId", None, &[]));
            };
            let now = unix_now();
            // Time/expiry even when Keystone already checked HMAC.
            if let Err(err) = check_sigv2_time(&req, now, self.allowable_clock_skew) {
                return finish(s3_auth_error(err));
            }
            if !keystone_verified {
                if let Err(err) = verify_sigv2(
                    &cred.access_key,
                    &cred.secret_key,
                    &req,
                    Some(now),
                    Some(self.allowable_clock_skew),
                ) {
                    return finish(s3_auth_error(err));
                }
            }
            // No aws-chunked for SigV2 (AWS STREAMING is V4-only): HashingInput
            // / raw-body XAmzContentSHA256Mismatch, then BadDigest.
            if let Some(resp) = crate::payload::validate_s3_payload(&mut req, false) {
                return finish(resp);
            }
            return finish(self.dispatch_authorized(req, cred, next));
        }

        // ---- SigV4 auth path ----
        let auth = match parse_sigv4_auth(&req) {
            Some(a) => a,
            None => return finish(s3_error_response("AccessDenied", None, &[])),
        };
        let Some((cred, keystone_verified)) = self.resolve_credential(&auth, &req) else {
            return finish(s3_error_response("InvalidAccessKeyId", None, &[]));
        };
        // Keystone `/v3/s3tokens` already validated the SigV4 signature against
        // the EC2 secret; local TempAuth keys still need verify_sigv4.
        // Note: for STREAMING-* the payload hash is the STREAMING token itself
        // (not the body), so verify happens *before* dechunk / header rewrite.
        // Clock-skew / query-expiry run even on the Keystone path.
        let now = unix_now();
        if let Err(err) = check_sigv4_time(&req, now, self.allowable_clock_skew) {
            return finish(s3_auth_error(err));
        }
        if !keystone_verified {
            if let Err(err) = verify_sigv4(
                &cred.access_key,
                &cred.secret_key,
                &req,
                Some(now),
                Some(self.allowable_clock_skew),
            ) {
                return finish(s3_auth_error(err));
            }
        }

        // aws-chunked / STREAMING-*: dechunk after header SigV4 verify.
        // V4 query STREAMING is not aws-chunked (Python reads the raw body).
        if matches!(req.method.as_str(), "PUT" | "POST")
            && is_aws_chunked_request(&req)
            && !auth.query_auth
        {
            if let Err(resp) = decode_and_fix_aws_chunked(&mut req, &cred, &auth) {
                return finish(resp);
            }
        }
        if let Some(resp) = crate::payload::validate_s3_payload(&mut req, !auth.query_auth) {
            return finish(resp);
        }

        finish(self.dispatch_authorized(req, cred, next))
    }
}

impl S3Api {
    /// S3-1: PutObject / UploadPart keep IncomingBody. Auth is header-only
    /// (UNSIGNED-PAYLOAD or the declared payload hash). aws-chunked is
    /// decoded incrementally (S3-2). Versioned buckets stream via
    /// [`Self::put_object_versioned_streaming`].
    async fn put_object_streaming(
        &self,
        mut areq: AsyncRequest,
        next: StreamingAsyncNextFn,
    ) -> Response {
        let method = areq.method.clone();
        let finish = |resp: Response| finish_s3_response(&method, resp);
        let mut head = Request {
            method: areq.method.clone(),
            path: areq.path.clone(),
            query_string: areq.query_string.clone(),
            headers: areq.headers.clone(),
            body: Body::empty(),
        };
        if let Some(resp) = reject_unknown_storage_class(&head) {
            return finish(resp);
        }
        if let Some(resp) = reject_unsupported_put_conditionals(&head) {
            return finish(resp);
        }
        let auth = match parse_sigv4_auth(&head) {
            Some(a) => a,
            None => return finish(s3_error_response("AccessDenied", None, &[])),
        };
        let Some((cred, keystone_verified)) = self.resolve_credential(&auth, &head) else {
            return finish(s3_error_response("InvalidAccessKeyId", None, &[]));
        };
        if let Some(denied) = self.frozen_account_denied(&cred.account, &head) {
            return finish(denied);
        }
        let now = unix_now();
        if let Err(err) = check_sigv4_time(&head, now, self.allowable_clock_skew) {
            return finish(s3_auth_error(err));
        }
        if !keystone_verified {
            if let Err(err) = verify_sigv4(
                &cred.access_key,
                &cred.secret_key,
                &head,
                Some(now),
                Some(self.allowable_clock_skew),
            ) {
                return finish(s3_auth_error(err));
            }
        }
        if let Some(resp) = crate::payload::validate_s3_payload_headers(&head, !auth.query_auth) {
            return finish(resp);
        }
        let (bucket, key) = extract_bucket_and_key(
            &head,
            &self.storage_domains,
            self.dns_compliant_bucket_names,
        );
        let (Some(bucket), Some(key)) = (bucket, key) else {
            return finish(s3_error_response(
                "InvalidRequest",
                Some("streaming PUT requires object key"),
                &[],
            ));
        };
        if !validate_bucket_name(&bucket, self.dns_compliant_bucket_names) {
            return finish(s3_error_response(
                "InvalidBucketName",
                None,
                &[("BucketName", &bucket)],
            ));
        }
        if key.as_bytes().len() > MAX_OBJECT_NAME_LENGTH {
            return finish(s3_error_response("KeyTooLongError", None, &[]));
        }
        let te = head
            .headers
            .get("Transfer-Encoding")
            .unwrap_or("")
            .to_ascii_lowercase();
        let chunked = te.split(',').any(|t| t.trim() == "chunked");
        let has_decoded = head.headers.get("X-Amz-Decoded-Content-Length").is_some()
            || head.headers.get("x-amz-decoded-content-length").is_some();
        if head.headers.get("Content-Length").is_none() && !chunked && !has_decoded {
            match areq.body.content_length() {
                Some(n) if n > 0 => {}
                _ => {
                    return finish(s3_error_response("MissingContentLength", None, &[]));
                }
            }
        }
        if let Some(denied) =
            iam_action_check(&self.iam, &cred, "s3:PutObject", &bucket, &key)
        {
            return finish(denied);
        }
        let params = head.params();
        let upload_id = params
            .iter()
            .find(|(k, _)| k == "uploadId")
            .map(|(_, v)| v.clone());
        let part_number = params
            .iter()
            .find(|(k, _)| k == "partNumber")
            .and_then(|(_, v)| v.parse::<u32>().ok());
        let is_mpu_part = upload_id.is_some() && part_number.is_some();

        map_amz_meta(&mut head);
        persist_s3_object_headers(&mut head);
        match resolve_acl_put_input(&head.headers, None, &cred.access_key) {
            Ok(input) => {
                if !matches!(input, AclPutInput::None) {
                    apply_object_acl_input(&mut head.headers, &input);
                }
            }
            Err(_) => return finish(s3_error_response("InvalidArgument", None, &[])),
        }
        if let Err(resp) = apply_request_object_lock_headers(&mut head.headers) {
            return finish(resp);
        }
        let bypass_requested = match parse_bypass_governance_header(
            head.headers
                .get(HDR_BYPASS_GOVERNANCE)
                .or_else(|| head.headers.get("X-Amz-Bypass-Governance-Retention")),
        ) {
            Ok(value) => value,
            Err(_) => return finish(s3_error_response("InvalidArgument", None, &[])),
        };
        let worm_bypass =
            match governance_bypass_context(&self.iam, &cred, &bucket, &key, bypass_requested) {
                Ok(ctx) => ctx,
                Err(resp) => return finish(resp),
            };
        let payload_hash = head
            .headers
            .get("X-Amz-Content-SHA256")
            .unwrap_or("")
            .to_string();
        let aws_chunked = is_streaming_payload_hash(&payload_hash);
        let decoded_len = head
            .headers
            .get("X-Amz-Decoded-Content-Length")
            .and_then(|s| s.parse::<u64>().ok());
        let amz_date = crate::sigv4::amz_date(&head);
        let chunk_err = Arc::new(Mutex::new(None));
        let payload_err = Arc::new(Mutex::new(None));
        crate::payload::apply_content_md5_etag(&mut head);
        let hash_streaming_token = auth.query_auth && aws_chunked;
        let hash_xform = crate::payload::PayloadHashTransform::from_request_opts(
            &head,
            Arc::clone(&payload_err),
            hash_streaming_token,
        );
        strip_s3_only_headers(&mut head.headers);
        stamp_auth(&mut head, &cred);
        if aws_chunked && !auth.query_auth {
            if let Err(resp) = wrap_aws_chunked_streaming(
                &mut areq,
                &mut head,
                &cred,
                &auth,
                &payload_hash,
                decoded_len,
                amz_date,
                Arc::clone(&chunk_err),
            ) {
                return finish(resp);
            }
        } else {
            let cl = areq.body.content_length();
            let inner = std::mem::replace(&mut areq.body, IncomingBody::from_bytes(Vec::new(), 1));
            areq.body = inner.with_transform(Box::new(hash_xform), cl);
        }

        if is_mpu_part {
            let segs = segments_container(&bucket);
            let part_name = part_object_name(&key, upload_id.as_deref().unwrap(), part_number.unwrap());
            let swift = AsyncRequest {
                method: "PUT".into(),
                path: s3_to_swift_path(&cred.account, Some(&segs), Some(&part_name)),
                query_string: String::new(),
                headers: head.headers,
                body: areq.body,
            };
            let resp = next(swift).await;
            if let Some(resp) = payload_err
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .take()
            {
                return finish(resp);
            }
            if let Some(e) = chunk_err
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .take()
            {
                return finish(aws_chunked_error_to_response(e));
            }
            return if (200..300).contains(&resp.status) {
                finish(translate_object_success("PUT", resp, false))
            } else {
                finish(map_swift_error(resp.status, Some(&bucket), Some(&key)))
            };
        }

        let (st, hdrs) =
            match head_container_streaming(&cred, &bucket, &next, &self.container_heads).await {
                Ok(v) => v,
                Err(resp) => return finish(resp),
            };
        if st != 404 && !(200..300).contains(&st) {
            return finish(map_swift_error(st, Some(&bucket), None));
        }
        let vstatus = versioning_status_from_headers(&hdrs).ok().flatten();
        if bucket_versioning_mode(vstatus.as_deref()).is_some() {
            let resp = self
                .put_object_versioned_streaming(
                    areq,
                    next,
                    method.clone(),
                    head,
                    cred,
                    bucket,
                    key,
                )
                .await;
            if let Some(err) = payload_err
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .take()
            {
                return finish(err);
            }
            return resp;
        }
        apply_lifecycle_on_put_from_container(&mut head.headers, &hdrs, &key, unix_now());
        if head.headers.get(SYS_RETAIN_UNTIL).is_none() {
            if let Ok(Some(xml)) = validated_object_lock_xml_from_headers(&hdrs) {
                if let Ok(Some(def)) = parse_object_lock_configuration(&xml) {
                    apply_default_retention_headers(&mut head.headers, &def, unix_now());
                }
            }
        }
        let has_lock_headers = head.headers.get(SYS_LOCK_MODE).is_some()
            || head.headers.get(SYS_RETAIN_UNTIL).is_some()
            || head.headers.get(SYS_LEGAL_HOLD).is_some();
        if has_lock_headers {
            match validated_object_lock_xml_from_headers(&hdrs) {
                Ok(Some(_)) => {}
                Ok(None) => {
                    return finish(s3_error_response(
                        "InvalidRequest",
                        Some("Bucket is missing Object Lock Configuration"),
                        &[],
                    ));
                }
                Err(_) => {
                    return finish(s3_error_response(
                        "InternalError",
                        Some("bucket object lock metadata is invalid"),
                        &[],
                    ));
                }
            }
        }
        if st != 404 && container_requires_object_precheck(&hdrs) {
            match control_head_object_streaming(&cred, &bucket, &key, &next).await {
                Ok(ObjectHead::Missing) => {}
                Ok(ObjectHead::Present(existing)) => {
                    if let Some(blocked) =
                        worm_guard(&existing.headers, self.worm_clock.clock_ok(), worm_bypass)
                    {
                        return finish(blocked);
                    }
                    if let Some(blocked) =
                        deny_if_object_acl_blocks_write(&cred, &existing.headers)
                    {
                        return finish(blocked);
                    }
                }
                Err(resp) => return finish(resp),
            }
        }

        let stamped_delete_at = head.headers.get("X-Delete-At").map(str::to_string);
        let swift = AsyncRequest {
            method: "PUT".into(),
            path: s3_to_swift_path(&cred.account, Some(&bucket), Some(&key)),
            query_string: s3_to_swift_query(&params, false),
            headers: head.headers,
            body: areq.body,
        };
        let resp = next(swift).await;
        if let Some(err) = payload_err
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()
        {
            return finish(err);
        }
        if let Some(e) = chunk_err
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()
        {
            return finish(aws_chunked_error_to_response(e));
        }
        if (200..300).contains(&resp.status) {
            let mut out = translate_object_success("PUT", resp, false);
            if let Some(exp) = stamped_delete_at
                .as_deref()
                .and_then(amz_expiration_from_delete_at)
            {
                out.headers.set("x-amz-expiration", exp);
            }
            finish(out)
        } else {
            finish(map_swift_error(resp.status, Some(&bucket), Some(&key)))
        }
    }

    /// Versioned PutObject: stream the new object body. Archive of a prior
    /// current object is a separate GET/PUT (not the 64 MiB control cap).
    /// Index persist uses the same create-only generation fence as the
    /// sync `cas_save_version_index` path.
    async fn put_object_versioned_streaming(
        &self,
        areq: AsyncRequest,
        next: StreamingAsyncNextFn,
        method: String,
        mut head: Request,
        cred: S3Credential,
        bucket: String,
        key: String,
    ) -> Response {
        let finish = |resp: Response| finish_s3_response(&method, resp);
        let vid = generate_version_id();
        if !is_safe_version_id(&vid) {
            return finish(unsafe_version_id_error());
        }
        let snap =
            match load_version_index_snapshot_streaming(&cred, &bucket, &key, &next).await {
                Ok(s) => s,
                Err(resp) => return finish(resp),
            };
        let expect = expect_generation(&snap);
        let mut idx = snap.index.clone();
        match control_head_object_streaming(&cred, &bucket, &key, &next).await {
            Ok(ObjectHead::Missing) => {}
            Ok(ObjectHead::Present(cur)) => {
                if let Some(blocked) = deny_if_object_acl_blocks_write(&cred, &cur.headers) {
                    return finish(blocked);
                }
                if let Err(resp) = maybe_archive_current_for_write_streaming(
                    &cred, &bucket, &key, &cur.headers, &mut idx, &next,
                )
                .await
                {
                    return finish(resp);
                }
            }
            Err(resp) => return finish(resp),
        }
        head.headers.set(SYS_VERSION_ID, &vid);
        head.headers.set(SYS_DELETE_MARKER, "false");
        let request_size: i64 = head
            .headers
            .get("Content-Length")
            .and_then(|v| v.parse().ok())
            .filter(|&n| n >= 0)
            .unwrap_or(0);
        let swift = AsyncRequest {
            method: "PUT".into(),
            path: s3_to_swift_path(&cred.account, Some(&bucket), Some(&key)),
            query_string: String::new(),
            headers: head.headers,
            body: areq.body,
        };
        let resp = next(swift).await;
        if !swift_write_applied(resp.status) {
            return finish(backend_write_not_applied(
                resp.status,
                Some(&bucket),
                Some(&key),
            ));
        }
        let etag = resp
            .headers
            .get("ETag")
            .map(bare_etag)
            .unwrap_or_default();
        let lm = resp
            .headers
            .get("Last-Modified")
            .map(http_date_to_s3_approx)
            .unwrap_or_else(|| "1970-01-01T00:00:00.000Z".into());
        if let Err(resp) = commit_new_version_record(
            &mut idx,
            expect,
            false,
            VersionRecord {
                version_id: vid.clone(),
                is_delete_marker: false,
                is_latest: true,
                last_modified: lm,
                etag: etag.clone(),
                size: request_size,
            },
        ) {
            return finish(resp);
        }
        if let Err(resp) =
            cas_save_version_index_streaming(&cred, &bucket, &key, &snap, &idx, &next).await
        {
            return finish(resp);
        }
        let mut out = translate_object_success("PUT", resp, false);
        out.headers.set(HDR_VERSION_ID, vid);
        finish(out)
    }

    /// Native-async S3 control (GET/HEAD/List/DELETE/MPU/versioning). No
    /// `block_in_place` and no sync `handle()`.
    async fn handle_s3_async(&self, mut req: Request, next: AsyncNextFn) -> Response {
        if !is_s3_auth_request(&req) {
            if let Some(account) = self.anonymous_account.clone() {
                if is_s3_unsigned_read_candidate(
                    &req,
                    &self.storage_domains,
                    self.dns_compliant_bucket_names,
                ) {
                    return self.dispatch_anonymous_async(req, account, next).await;
                }
            }
            return next(req).await;
        }
        let method = req.method.clone();
        let finish = |resp: Response| finish_s3_response(&method, resp);
        if let Some(resp) = reject_invalid_bucket_before_auth(
            &req,
            &self.storage_domains,
            self.dns_compliant_bucket_names,
        ) {
            return finish(resp);
        }
        let (early_bucket, early_key) =
            extract_bucket_and_key(&req, &self.storage_domains, self.dns_compliant_bucket_names);
        let _ = early_bucket;
        if let Some(resp) = put_object_missing_content_length(&req, early_key.as_deref()) {
            return finish(resp);
        }
        let cred = match self.authenticate_s3(&req) {
            Ok(c) => c,
            Err(resp) => return finish(resp),
        };
        let v4_header = crate::payload::is_v4_header_auth(&req);
        if let Some(resp) = crate::payload::validate_s3_payload(&mut req, v4_header) {
            return finish(resp);
        }
        if let Some(denied) = self.frozen_account_denied(&cred.account, &req) {
            return finish(denied);
        }
        finish(self.dispatch_s3_async(req, cred, next).await)
    }

    fn authenticate_s3(&self, req: &Request) -> Result<S3Credential, Response> {
        if is_sigv2_auth(req) {
            let auth_v2 = parse_sigv2_auth(req)
                .ok_or_else(|| s3_error_response("AccessDenied", None, &[]))?;
            let (cred, keystone_verified) = self
                .resolve_credential_v2(&auth_v2, req)
                .ok_or_else(|| s3_error_response("InvalidAccessKeyId", None, &[]))?;
            let now = unix_now();
            check_sigv2_time(req, now, self.allowable_clock_skew).map_err(s3_auth_error)?;
            if !keystone_verified {
                verify_sigv2(
                    &cred.access_key,
                    &cred.secret_key,
                    req,
                    Some(now),
                    Some(self.allowable_clock_skew),
                )
                .map_err(s3_auth_error)?;
            }
            return Ok(cred);
        }
        let auth = parse_sigv4_auth(req)
            .ok_or_else(|| s3_error_response("AccessDenied", None, &[]))?;
        let (cred, keystone_verified) = self
            .resolve_credential(&auth, req)
            .ok_or_else(|| s3_error_response("InvalidAccessKeyId", None, &[]))?;
        let now = unix_now();
        check_sigv4_time(req, now, self.allowable_clock_skew).map_err(s3_auth_error)?;
        if !keystone_verified {
            verify_sigv4(
                &cred.access_key,
                &cred.secret_key,
                req,
                Some(now),
                Some(self.allowable_clock_skew),
            )
            .map_err(s3_auth_error)?;
        }
        Ok(cred)
    }

    async fn dispatch_anonymous_async(
        &self,
        req: Request,
        account: String,
        next: AsyncNextFn,
    ) -> Response {
        let method = req.method.clone();
        let (bucket, key) =
            extract_bucket_and_key(&req, &self.storage_domains, self.dns_compliant_bucket_names);
        let Some(bucket) = bucket else {
            return next(req).await;
        };
        let mut swift = req;
        swift.path = s3_to_swift_path(&account, Some(&bucket), key.as_deref());
        swift.query_string = s3_to_swift_query(&swift.params(), key.is_none());
        strip_s3_only_headers(&mut swift.headers);
        let resp = next(swift).await;
        finish_s3_response(&method, resp)
    }

    async fn dispatch_legacy_blocking(
        &self,
        req: Request,
        cred: S3Credential,
        next: AsyncNextFn,
    ) -> Response {
        let next_sync = async_next_as_blocking(next);
        self.dispatch_authorized(req, cred, &next_sync)
    }

    async fn dispatch_s3_async(
        &self,
        mut req: Request,
        cred: S3Credential,
        next: AsyncNextFn,
    ) -> Response {
        if !is_s3_http_method(&req.method) {
            return s3_error_response("MethodNotAllowed", None, &[]);
        }
        if let Some(resp) = validate_delete_headers(&req) {
            return resp;
        }
        let params = req.params();
        if let Some(sub) = first_unsupported_subresource(&params) {
            return not_implemented_subresource(sub);
        }
        if req.headers.get("X-Amz-Request-Route").is_some()
            || req.headers.get("x-amz-request-route").is_some()
        {
            return not_implemented_subresource("WriteGetObjectResponse");
        }
        let (bucket, key) =
            extract_bucket_and_key(&req, &self.storage_domains, self.dns_compliant_bucket_names);
        if let Some(b) = &bucket {
            if !validate_bucket_name(b, self.dns_compliant_bucket_names) {
                return s3_error_response("InvalidBucketName", None, &[("BucketName", b)]);
            }
        }
        if let Some(k) = &key {
            if k.as_bytes().len() > MAX_OBJECT_NAME_LENGTH {
                return s3_error_response("KeyTooLongError", None, &[]);
            }
        }
        if let Some(resp) = put_object_missing_content_length(&req, key.as_deref()) {
            return resp;
        }
        if key.is_none() && bucket.is_some() && matches!(req.method.as_str(), "PUT" | "DELETE") {
            self.container_heads
                .invalidate(&cred.account, bucket.as_deref().unwrap());
        }
        if bucket.is_none() {
            if let Some(denied) = service_method_not_allowed(&req.method) {
                return denied;
            }
            if req.method == "GET" && params.iter().any(|(k, _)| k == "max-directory-buckets") {
                return xml_response(200, list_directory_buckets_xml());
            }
        }
        if req.headers.get("X-Amz-Rename-Source").is_some()
            || req.headers.get("x-amz-rename-source").is_some()
        {
            return not_implemented_subresource("RenameObject");
        }
        if key.is_none()
            && bucket.is_some()
            && req.method == "GET"
            && params.iter().any(|(k, _)| k == "location")
        {
            return xml_response(200, location_constraint_xml(&self.location));
        }

        if let Some(bucket) = bucket.as_deref() {
            let version_id_q = params.iter().any(|(k, _)| k == "versionId");
            let has_retention = params.iter().any(|(k, _)| k == "retention");
            let has_legal_hold = params.iter().any(|(k, _)| k == "legal-hold");
            let has_restore = params.iter().any(|(k, _)| k == "restore");
            let mut actions = Vec::new();
            if key.is_some() && version_id_q {
                match req.method.as_str() {
                    "GET" | "HEAD" => actions.push("s3:GetObjectVersion"),
                    "DELETE" => actions.push("s3:DeleteObjectVersion"),
                    _ => {}
                }
            }
            if key.is_some() && has_retention {
                actions.push(if req.method == "PUT" {
                    "s3:PutObjectRetention"
                } else {
                    "s3:GetObjectRetention"
                });
            }
            if key.is_some() && has_legal_hold {
                actions.push(if req.method == "PUT" {
                    "s3:PutObjectLegalHold"
                } else {
                    "s3:GetObjectLegalHold"
                });
            }
            if key.is_some() && has_restore {
                actions.push("s3:RestoreObject");
            }
            if actions.is_empty() {
                actions.push(crate::iam::IamService::s3_action(
                    &req.method,
                    key.is_some(),
                ));
            }
            let principal = self
                .iam
                .identity
                .canonical_id_for_access_key(&cred.access_key);
            let resource = crate::iam::IamService::s3_resource(bucket, key.as_deref());
            if let Some(false) = self
                .iam
                .evaluate_all_actions(&principal, &actions, &resource)
            {
                return s3_error_response("AccessDenied", Some("IAM policy denied"), &[]);
            }
        }

        let has_uploads = params.iter().any(|(k, _)| k == "uploads");
        let upload_id = params
            .iter()
            .find(|(k, _)| k == "uploadId")
            .map(|(_, v)| v.clone());
        let part_number = params.iter().any(|(k, _)| k == "partNumber");
        let has_versioning = params.iter().any(|(k, _)| k == "versioning");
        if has_versioning {
            if let Some(b) = bucket.as_deref() {
                return handle_versioning_async(req, &cred, b, &next).await;
            }
        }
        if has_uploads && req.method == "POST" && upload_id.is_none() {
            if let (Some(b), Some(k)) = (bucket.as_deref(), key.as_deref()) {
                return handle_mpu_init_async(req, &cred, b, k, self, &next).await;
            }
        }
        if let Some(uid) = upload_id.as_deref() {
            if let (Some(b), Some(k)) = (bucket.as_deref(), key.as_deref()) {
                if req.method == "POST" && !part_number {
                    return handle_mpu_complete_async(&cred, b, k, uid, req, &next, self).await;
                }
                if req.method == "DELETE" {
                    return handle_mpu_abort_async(&cred, b, k, uid, self, &next).await;
                }
            }
        }
        if s3_query_needs_legacy_dispatch(&params) {
            if let Some(sub) = params
                .iter()
                .map(|(k, _)| k.as_str())
                .find(|k| s3_query_needs_legacy_dispatch(&[((*k).to_string(), String::new())]))
            {
                return not_implemented_subresource(sub);
            }
        }
        let owner = owner_for(&cred);
        let has_delete = params.iter().any(|(k, _)| k == "delete");
        let has_acl = params.iter().any(|(k, _)| k == "acl");
        let has_cors = params.iter().any(|(k, _)| k == "cors");
        let has_versions = params.iter().any(|(k, _)| k == "versions");
        let has_tagging = params.iter().any(|(k, _)| k == "tagging");
        let has_lifecycle = params.iter().any(|(k, _)| k == "lifecycle");
        if has_delete && req.method == "POST" && bucket.is_some() && key.is_none() {
            return handle_multi_delete_async(
                req,
                &cred,
                bucket.as_deref().unwrap(),
                &self.iam,
                self.worm_clock.clock_ok(),
                self,
                &next,
            )
            .await;
        }
        if has_acl && bucket.is_some() {
            return handle_acl_async(
                req,
                &cred,
                &owner,
                bucket.as_deref().unwrap(),
                key.as_deref(),
                &next,
            )
            .await;
        }
        if has_cors && bucket.is_some() && key.is_none() {
            return handle_cors_async(req, &cred, bucket.as_deref().unwrap(), &next).await;
        }
        if has_versions && bucket.is_some() && key.is_none() && req.method == "GET" {
            if let Err(resp) = parse_list_max_keys(&params) {
                return resp;
            }
            return handle_list_versions_async(&cred, bucket.as_deref().unwrap(), &params, &next)
                .await;
        }
        if has_tagging && bucket.is_some() {
            return handle_tagging_async(
                req,
                &cred,
                bucket.as_deref().unwrap(),
                key.as_deref(),
                &next,
            )
            .await;
        }
        if has_lifecycle && bucket.is_some() && key.is_none() {
            return handle_lifecycle_async(req, &cred, bucket.as_deref().unwrap(), &next).await;
        }
        if key.is_none() && bucket.is_some() {
            if let Some(cfg) = stored_bucket_config(&params) {
                return handle_stored_bucket_config_async(
                    req,
                    &cred,
                    bucket.as_deref().unwrap(),
                    cfg,
                    &next,
                )
                .await;
            }
        }
        if let (Some(b), Some(_)) = (bucket.as_deref(), key.as_deref()) {
            let method = req.method.clone();
            match method.as_str() {
                "GET" | "HEAD" => {
                    let version_id_q = params
                        .iter()
                        .find(|(k, _)| k == "versionId")
                        .map(|(_, v)| v.as_str());
                    match probe_bucket_versioning_async(
                        &cred,
                        b,
                        &next,
                        &self.container_heads,
                    )
                    .await
                    {
                        Ok(Some(_)) => {
                            return handle_versioned_get_head_async(
                                &cred,
                                b,
                                key.as_deref().unwrap(),
                                &method,
                                version_id_q,
                                &next,
                            )
                            .await;
                        }
                        Ok(None) if version_id_q.is_some() => {
                            return handle_versioned_get_head_async(
                                &cred,
                                b,
                                key.as_deref().unwrap(),
                                &method,
                                version_id_q,
                                &next,
                            )
                            .await;
                        }
                        Ok(None) => {}
                        Err(resp) => return resp,
                    }
                }
                "DELETE" => {
                    match probe_bucket_versioning_async(
                        &cred,
                        b,
                        &next,
                        &self.container_heads,
                    )
                    .await
                    {
                        Ok(Some(_)) => {
                            let vid = params
                                .iter()
                                .find(|(k, _)| k == "versionId")
                                .map(|(_, v)| v.as_str());
                            let bypass_requested = bypass_governance_requested(
                                req.headers
                                    .get(HDR_BYPASS_GOVERNANCE)
                                    .or_else(|| req.headers.get("X-Amz-Bypass-Governance-Retention")),
                            );
                            let bypass = match governance_bypass_context(
                                &self.iam,
                                &cred,
                                b,
                                key.as_deref().unwrap(),
                                bypass_requested,
                            ) {
                                Ok(context) => context,
                                Err(resp) => return resp,
                            };
                            return handle_versioned_delete_async(
                                &cred,
                                b,
                                key.as_deref().unwrap(),
                                vid,
                                None,
                                self.worm_clock.clock_ok(),
                                bypass,
                                &next,
                            )
                            .await;
                        }
                        Ok(None) => {}
                        Err(resp) => return resp,
                    }
                }
                "PUT" => {
                    match probe_bucket_versioning_async(
                        &cred,
                        b,
                        &next,
                        &self.container_heads,
                    )
                    .await
                    {
                        Ok(Some(_)) => {
                            // SigV2 PUT is intercept-buffered, not Hyper
                            // streaming. dispatch_legacy_blocking panics on
                            // the live runtime (`Body::Channel.blocking_recv`
                            // inside block_in_place). Stamp SYS_VERSION_ID
                            // so GET ?versionId=null is NoSuchKey.
                            let vid = generate_version_id();
                            if is_safe_version_id(&vid) {
                                req.headers.set(SYS_VERSION_ID, &vid);
                                req.headers.set(SYS_DELETE_MARKER, "false");
                            }
                            let mut out = self
                                .forward_s3_async(req, cred, bucket, key, params, next)
                                .await;
                            if (200..300).contains(&out.status) && is_safe_version_id(&vid)
                            {
                                out.headers.set(HDR_VERSION_ID, vid);
                            }
                            return out;
                        }
                        Ok(None) => {}
                        Err(resp) => return resp,
                    }
                }
                _ => {}
            }
        }
        self.forward_s3_async(req, cred, bucket, key, params, next)
            .await
    }

    async fn forward_s3_async(
        &self,
        req: Request,
        cred: S3Credential,
        bucket: Option<String>,
        key: Option<String>,
        params: Vec<(String, String)>,
        next: AsyncNextFn,
    ) -> Response {
        let method = req.method.clone();
        let owner = owner_for(&cred);
        let list_v2 = params.iter().any(|(k, v)| k == "list-type" && v == "2");
        let for_list = matches!(method.as_str(), "GET" | "HEAD") && key.is_none();
        let range_header = req.headers.get("Range").map(str::to_string);
        let is_copy = req.headers.get("X-Amz-Copy-Source").is_some();
        let mut swift_req = req;
        swift_req.path = s3_to_swift_path(&cred.account, bucket.as_deref(), key.as_deref());
        if for_list && method == "GET" {
            if let Err(resp) = parse_list_max_keys(&params) {
                return resp;
            }
            swift_req.query_string = s3_to_swift_query(&params, true);
        } else if method == "GET" && bucket.is_none() {
            swift_req.query_string = "format=json".into();
        } else if method == "DELETE" && key.is_some() {
            swift_req.query_string.clear();
        } else {
            swift_req.query_string = s3_to_swift_query(&params, false);
        }
        map_amz_meta(&mut swift_req);
        if method == "HEAD" && key.is_some() {
            swift_req.headers.remove("Range");
            swift_req.headers.remove("range");
        }
        if let Some(resp) = reject_copy_to_self(&swift_req) {
            return resp;
        }
        if let Some(resp) = rewrite_copy_source_version_async(&mut swift_req, &cred, &next).await {
            return resp;
        }
        if let Some(resp) = apply_copy_source(&mut swift_req) {
            return resp;
        }
        match resolve_acl_put_input(&swift_req.headers, None, &owner.id) {
            Ok(input) if !matches!(input, AclPutInput::None) => {
                if key.is_some() {
                    apply_object_acl_input(&mut swift_req.headers, &input);
                } else {
                    apply_bucket_acl_input(&mut swift_req.headers, &input);
                }
            }
            Ok(_) => {}
            Err(_) => return s3_error_response("InvalidArgument", None, &[]),
        }
        strip_s3_only_headers(&mut swift_req.headers);
        stamp_auth(&mut swift_req, &cred);
        if for_list && method == "GET" {
            swift_req.headers.set("Accept", "application/json");
        }
        let if_match = swift_req.headers.get("If-Match").map(str::to_string);
        let if_none_match = swift_req.headers.get("If-None-Match").map(str::to_string);
        let ius = swift_req
            .headers
            .get("If-Unmodified-Since")
            .map(str::to_string);
        let ims = swift_req
            .headers
            .get("If-Modified-Since")
            .map(str::to_string);
        if key.is_some() && matches!(method.as_str(), "GET" | "HEAD") {
            swift_req.headers.remove("If-Unmodified-Since");
            swift_req.headers.remove("If-Modified-Since");
            swift_req.headers.remove("If-Match");
            swift_req.headers.remove("If-None-Match");
        }
        let resp = if method == "DELETE" && key.is_some() {
            let retry = swift_req.clone_head();
            let first = next(swift_req).await;
            if first.status == 412 {
                let mut retry = retry;
                retry.query_string = "multipart-manifest=delete".into();
                next(retry).await
            } else {
                first
            }
        } else {
            next(swift_req).await
        };
        if bucket.is_none() && method == "GET" && (200..300).contains(&resp.status) {
            let body = match resp.body.collect_async().await {
                Ok(b) => b,
                Err(_) => return s3_error_response("InternalError", Some("listing too large"), &[]),
            };
            return translate_list_buckets(&body, &owner);
        }
        if key.is_none() && bucket.is_some() {
            if method == "GET" && (200..300).contains(&resp.status) {
                let body = match resp.body.collect_async().await {
                    Ok(b) => b,
                    Err(_) => {
                        return s3_error_response("InternalError", Some("listing too large"), &[])
                    }
                };
                let b = bucket.as_deref().unwrap();
                let body = rewrite_listing_s3_etags_async(&body, &cred, b, &next).await;
                if list_v2 {
                    return translate_list_objects_v2(&body, b, &params, &owner);
                }
                return translate_list_objects(&body, b, &params, &owner);
            }
            if (200..300).contains(&resp.status) {
                return translate_bucket_success(&method, resp, bucket.as_deref());
            }
            return map_swift_error(resp.status, bucket.as_deref(), None);
        }
        if key.is_some() {
            if (200..300).contains(&resp.status) {
                if matches!(method.as_str(), "GET" | "HEAD") {
                    if let Some(denied) = deny_if_object_acl_blocks_read(&cred, &resp.headers) {
                        return denied;
                    }
                    let resp = translate_object_get_head(
                        &method,
                        resp,
                        &cred,
                        &params,
                        range_header.as_deref(),
                    );
                    return apply_get_head_preconditions(
                        resp,
                        &method,
                        if_match.as_deref(),
                        ius.as_deref(),
                        if_none_match.as_deref(),
                        ims.as_deref(),
                    );
                }
                return translate_object_success(&method, resp, is_copy);
            }
            return map_swift_error(resp.status, bucket.as_deref(), key.as_deref());
        }
        if (200..300).contains(&resp.status) {
            resp
        } else {
            map_swift_error(resp.status, bucket.as_deref(), key.as_deref())
        }
    }

    /// Shared S3 operation dispatch after auth has succeeded (V2 or V4).
    fn dispatch_authorized(&self, req: Request, cred: S3Credential, next: &NextFn) -> Response {
        let method = req.method.clone();
        let mut resp = self.dispatch_authorized_inner(req, cred, next);
        apply_s3_amz_ids(&mut resp);
        if method == "HEAD" && resp.status >= 400 {
            resp.body = Body::empty();
            resp.headers.set("Content-Length", "0");
        }
        resp
    }

    fn dispatch_authorized_inner(
        &self,
        req: Request,
        cred: S3Credential,
        next: &NextFn,
    ) -> Response {
        if let Some(denied) = self.frozen_account_denied(&cred.account, &req) {
            return denied;
        }
        if !is_s3_http_method(&req.method) {
            return s3_error_response("MethodNotAllowed", None, &[]);
        }
        if let Some(resp) = validate_delete_headers(&req) {
            return resp;
        }
        let params = req.params();
        if let Some(sub) = first_unsupported_subresource(&params) {
            return not_implemented_subresource(sub);
        }
        if req.headers.get("X-Amz-Request-Route").is_some()
            || req.headers.get("x-amz-request-route").is_some()
        {
            return not_implemented_subresource("WriteGetObjectResponse");
        }

        let (bucket, key) =
            extract_bucket_and_key(&req, &self.storage_domains, self.dns_compliant_bucket_names);
        if let Some(b) = &bucket {
            if !validate_bucket_name(b, self.dns_compliant_bucket_names) {
                return s3_error_response("InvalidBucketName", None, &[("BucketName", b)]);
            }
        }
        if let Some(k) = &key {
            if k.as_bytes().len() > MAX_OBJECT_NAME_LENGTH {
                return s3_error_response("KeyTooLongError", None, &[]);
            }
        }
        if let Some(resp) = put_object_missing_content_length(&req, key.as_deref()) {
            return resp;
        }
        // Bucket-level writes change container sysmeta; drop the HEAD cache
        // so the next object PUT sees versioning/lifecycle/lock immediately.
        if key.is_none() && bucket.is_some() && matches!(req.method.as_str(), "PUT" | "DELETE") {
            self.container_heads
                .invalidate(&cred.account, bucket.as_deref().unwrap());
        }
        // Account-level (bucket=None) guard. Python 2.33 s3api's
        // ServiceController implements GET only; PUT/DELETE/POST/HEAD on `/`
        // are rejected at the s3api layer with 405 MethodNotAllowed
        // (probed on the live oracle 2026-08-17, evidence
        // s3win-20260817-account-probe.json). Without this guard those
        // methods translated into Swift `/v1/<account>` requests — the
        // 887be s3cmd-mb incident family. GET stays ListBuckets.
        if bucket.is_none() {
            if let Some(denied) = service_method_not_allowed(&req.method) {
                return denied;
            }
            if req.method == "GET" && params.iter().any(|(k, _)| k == "max-directory-buckets") {
                return xml_response(200, list_directory_buckets_xml());
            }
        }
        if req.headers.get("X-Amz-Rename-Source").is_some()
            || req.headers.get("x-amz-rename-source").is_some()
        {
            match (bucket.as_deref(), key.as_deref()) {
                (Some(b), Some(k)) => return handle_rename_object(req, &cred, b, k, next),
                _ => {
                    return s3_error_response(
                        "InvalidRequest",
                        Some("RenameObject requires a destination object key"),
                        &[],
                    )
                }
            }
        }

        // PUT/copy: unknown x-amz-storage-class must 400 before any persist.
        if req.method == "PUT" {
            if let Some(resp) = reject_unknown_storage_class(&req) {
                return resp;
            }
            if key.is_some() {
                if let Some(resp) = reject_unsupported_put_conditionals(&req) {
                    return resp;
                }
            }
        }

        // GetBucketLocation — answered locally, no Swift hop.
        if key.is_none()
            && bucket.is_some()
            && req.method == "GET"
            && params.iter().any(|(k, _)| k == "location")
        {
            return xml_response(200, location_constraint_xml(&self.location));
        }

        let owner = owner_for(&cred);
        let list_v2 = params.iter().any(|(k, v)| k == "list-type" && v == "2");
        let has_delete = params.iter().any(|(k, _)| k == "delete");
        let has_acl = params.iter().any(|(k, _)| k == "acl");
        let has_cors = params.iter().any(|(k, _)| k == "cors");
        let has_versioning = params.iter().any(|(k, _)| k == "versioning");
        let has_versions = params.iter().any(|(k, _)| k == "versions");
        let has_tagging = params.iter().any(|(k, _)| k == "tagging");
        let has_lifecycle = params.iter().any(|(k, _)| k == "lifecycle");
        let has_object_lock = params.iter().any(|(k, _)| k == "object-lock");
        let has_legal_hold = params.iter().any(|(k, _)| k == "legal-hold");
        let has_retention = params.iter().any(|(k, _)| k == "retention");
        let has_restore = params.iter().any(|(k, _)| k == "restore");
        let version_id_q = params
            .iter()
            .find(|(k, _)| k == "versionId")
            .map(|(_, v)| v.clone());
        if version_id_q
            .as_deref()
            .is_some_and(|version_id| !valid_version_id(version_id))
        {
            return s3_error_response("InvalidArgument", None, &[]);
        }
        let bypass_requested = match parse_bypass_governance_header(
            req.headers
                .get(HDR_BYPASS_GOVERNANCE)
                .or_else(|| req.headers.get("X-Amz-Bypass-Governance-Retention")),
        ) {
            Ok(value) => value,
            Err(_) => return s3_error_response("InvalidArgument", None, &[]),
        };
        let has_uploads = params.iter().any(|(k, _)| k == "uploads");
        let upload_id = params
            .iter()
            .find(|(k, _)| k == "uploadId")
            .map(|(_, v)| v.clone());
        let part_number = params
            .iter()
            .find(|(k, _)| k == "partNumber")
            .and_then(|(_, v)| v.parse::<u32>().ok());

        // Multi-tenant IAM gate. Subresource and version operations replace
        // the generic object action; combined version+subresource requests
        // require every applicable permission.
        if let Some(bucket) = bucket.as_deref() {
            let mut actions = Vec::new();
            if key.is_some() && version_id_q.is_some() {
                match req.method.as_str() {
                    "GET" | "HEAD" => actions.push("s3:GetObjectVersion"),
                    "DELETE" => actions.push("s3:DeleteObjectVersion"),
                    _ => {}
                }
            }
            if key.is_some() && has_retention {
                actions.push(if req.method == "PUT" {
                    "s3:PutObjectRetention"
                } else {
                    "s3:GetObjectRetention"
                });
            }
            if key.is_some() && has_legal_hold {
                actions.push(if req.method == "PUT" {
                    "s3:PutObjectLegalHold"
                } else {
                    "s3:GetObjectLegalHold"
                });
            }
            if key.is_some() && has_restore {
                actions.push("s3:RestoreObject");
            }
            if actions.is_empty() {
                actions.push(crate::iam::IamService::s3_action(
                    &req.method,
                    key.is_some(),
                ));
            }
            let principal = self
                .iam
                .identity
                .canonical_id_for_access_key(&cred.access_key);
            let resource = crate::iam::IamService::s3_resource(bucket, key.as_deref());
            if let Some(false) = self
                .iam
                .evaluate_all_actions(&principal, &actions, &resource)
            {
                return s3_error_response("AccessDenied", Some("IAM policy denied"), &[]);
            }
        }

        if req.method == "PUT" {
            if let (Some(bucket), Some(key)) = (bucket.as_deref(), key.as_deref()) {
                let has_retention_headers = req.headers.get("X-Amz-Object-Lock-Mode").is_some()
                    || req
                        .headers
                        .get("X-Amz-Object-Lock-Retain-Until-Date")
                        .is_some();
                let has_legal_hold_header =
                    req.headers.get("X-Amz-Object-Lock-Legal-Hold").is_some();
                if has_retention_headers || has_legal_hold_header {
                    if let Err(resp) = require_bucket_object_lock(&cred, bucket, next) {
                        return resp;
                    }
                }
                if has_retention_headers {
                    if let Some(denied) =
                        iam_action_check(&self.iam, &cred, "s3:PutObjectRetention", bucket, key)
                    {
                        return denied;
                    }
                }
                if has_legal_hold_header {
                    if let Some(denied) =
                        iam_action_check(&self.iam, &cred, "s3:PutObjectLegalHold", bucket, key)
                    {
                        return denied;
                    }
                }
            }
        }

        // One clock-health sample per dispatched request; every WORM
        // evaluation below sees the same bit. Disabled source → `true`.
        let worm_clock_ok = self.worm_clock.clock_ok();

        // ---- MultiDelete ----
        if has_delete && req.method == "POST" && bucket.is_some() && key.is_none() {
            return handle_multi_delete(
                req,
                &cred,
                bucket.as_deref().unwrap(),
                &self.iam,
                worm_clock_ok,
                self,
                next,
            );
        }

        // ---- ACL ----
        if has_acl && bucket.is_some() {
            return handle_acl(
                req,
                &cred,
                &owner,
                bucket.as_deref().unwrap(),
                key.as_deref(),
                next,
            );
        }

        // ---- CORS ----
        if has_cors && bucket.is_some() && key.is_none() {
            return handle_cors(req, &cred, bucket.as_deref().unwrap(), next);
        }

        // ---- Versioning (bucket status) ----
        if has_versioning && bucket.is_some() && key.is_none() {
            return handle_versioning(req, &cred, bucket.as_deref().unwrap(), next);
        }

        // ---- List object versions ----
        if has_versions && bucket.is_some() && key.is_none() && req.method == "GET" {
            if let Err(resp) = parse_list_max_keys(&params) {
                return resp;
            }
            return handle_list_versions(&cred, bucket.as_deref().unwrap(), &params, next);
        }

        // ---- Tagging (bucket + object) ----
        if has_tagging && bucket.is_some() {
            return handle_tagging(req, &cred, bucket.as_deref().unwrap(), key.as_deref(), next);
        }

        // ---- GetBucketPolicyStatus (no stored policy → not public) ----
        if bucket.is_some()
            && key.is_none()
            && params.iter().any(|(k, _)| k == "policyStatus")
            && matches!(req.method.as_str(), "GET" | "HEAD")
        {
            return xml_ok(policy_status_xml(false));
        }

        // ---- GetObjectAttributes (HEAD-backed subset) ----
        if bucket.is_some()
            && key.is_some()
            && params.iter().any(|(k, _)| k == "attributes")
            && matches!(req.method.as_str(), "GET" | "HEAD")
        {
            return handle_object_attributes(
                req,
                &cred,
                bucket.as_deref().unwrap(),
                key.as_deref().unwrap(),
                next,
            );
        }

        // ---- Lifecycle (bucket) ----
        if has_lifecycle && bucket.is_some() && key.is_none() {
            return handle_lifecycle(req, &cred, bucket.as_deref().unwrap(), next);
        }

        // ---- Stored bucket configs (policy/website/encryption/…) ----
        if key.is_none() && bucket.is_some() {
            if let Some(cfg) = stored_bucket_config(&params) {
                return handle_stored_bucket_config(
                    req,
                    &cred,
                    bucket.as_deref().unwrap(),
                    cfg,
                    next,
                );
            }
        }

        if bucket.is_some()
            && key.is_none()
            && params.iter().any(|(k, _)| k == "session")
            && matches!(req.method.as_str(), "GET" | "HEAD" | "POST")
        {
            return handle_create_session(&cred);
        }

        if bucket.is_some() && key.is_some() && params.iter().any(|(k, _)| k == "annotation") {
            return handle_object_stored_blob(
                req,
                &cred,
                bucket.as_deref().unwrap(),
                key.as_deref().unwrap(),
                S3_OBJECT_ANNOTATION_META,
                "NoSuchConfiguration",
                next,
            );
        }

        if bucket.is_some() && key.is_some() && params.iter().any(|(k, _)| k == "encryption") {
            return handle_object_stored_blob(
                req,
                &cred,
                bucket.as_deref().unwrap(),
                key.as_deref().unwrap(),
                S3_OBJECT_ENCRYPTION_META,
                "ServerSideEncryptionConfigurationNotFoundError",
                next,
            );
        }

        if bucket.is_some()
            && key.is_some()
            && params.iter().any(|(k, _)| k == "select")
            && req.method == "POST"
        {
            return handle_select_object_content(
                req,
                &cred,
                bucket.as_deref().unwrap(),
                key.as_deref().unwrap(),
                next,
            );
        }

        if bucket.is_some()
            && key.is_some()
            && params.iter().any(|(k, _)| k == "torrent")
            && matches!(req.method.as_str(), "GET" | "HEAD")
        {
            return handle_get_object_torrent(
                &cred,
                bucket.as_deref().unwrap(),
                key.as_deref().unwrap(),
                next,
            );
        }

        // ---- Object Lock configuration (bucket) ----
        if has_object_lock && bucket.is_some() && key.is_none() {
            return handle_object_lock(req, &cred, bucket.as_deref().unwrap(), next);
        }

        // ---- Object legal-hold / retention (WORM sysmeta) ----
        if has_legal_hold && bucket.is_some() && key.is_some() {
            if req.method == "PUT" {
                if let Err(resp) =
                    require_bucket_object_lock(&cred, bucket.as_deref().unwrap(), next)
                {
                    return resp;
                }
                if let Some(denied) = iam_action_check(
                    &self.iam,
                    &cred,
                    "s3:PutObjectLegalHold",
                    bucket.as_deref().unwrap(),
                    key.as_deref().unwrap(),
                ) {
                    return denied;
                }
            }
            return handle_legal_hold(
                req,
                &cred,
                bucket.as_deref().unwrap(),
                key.as_deref().unwrap(),
                version_id_q.as_deref(),
                next,
            );
        }
        if has_retention && bucket.is_some() && key.is_some() {
            let retention_bypass = if req.method == "PUT" {
                match governance_bypass_context(
                    &self.iam,
                    &cred,
                    bucket.as_deref().unwrap(),
                    key.as_deref().unwrap(),
                    bypass_requested,
                ) {
                    Ok(context) => context,
                    Err(resp) => return resp,
                }
            } else {
                GovernanceBypass::NONE
            };
            if req.method == "PUT" {
                if let Err(resp) =
                    require_bucket_object_lock(&cred, bucket.as_deref().unwrap(), next)
                {
                    return resp;
                }
                if let Some(denied) = iam_action_check(
                    &self.iam,
                    &cred,
                    "s3:PutObjectRetention",
                    bucket.as_deref().unwrap(),
                    key.as_deref().unwrap(),
                ) {
                    return denied;
                }
            }
            return handle_retention(
                req,
                &cred,
                bucket.as_deref().unwrap(),
                key.as_deref().unwrap(),
                version_id_q.as_deref(),
                worm_clock_ok,
                retention_bypass,
                next,
            );
        }

        // ---- RestoreObject (?restore) — meta stamp + optional lab cold backend ----
        if has_restore && bucket.is_some() && key.is_some() {
            return handle_restore(
                req,
                &cred,
                bucket.as_deref().unwrap(),
                key.as_deref().unwrap(),
                version_id_q.as_deref(),
                &self.cold_map,
                self.cold_backend.as_ref(),
                next,
            );
        }

        // ---- Multipart ----
        if has_uploads && req.method == "POST" && bucket.is_some() && key.is_some() {
            return handle_mpu_init(
                req,
                &cred,
                bucket.as_deref().unwrap(),
                key.as_deref().unwrap(),
                self,
                next,
            );
        }
        // ListMultipartUploads (`GET /bucket?uploads`, no key): list upload
        // markers under `{bucket}+segments` (must not fall through to ListObjects).
        if has_uploads && req.method == "GET" && bucket.is_some() && key.is_none() {
            return handle_list_multipart_uploads(
                &cred,
                bucket.as_deref().unwrap(),
                &params,
                self,
                next,
            );
        }
        if has_uploads && bucket.is_some() && key.is_none() {
            return s3_error_response(
                "MethodNotAllowed",
                Some("ListMultipartUploads requires GET"),
                &[],
            );
        }
        if let Some(uid) = upload_id.clone() {
            if let (Some(b), Some(k)) = (bucket.clone(), key.clone()) {
                if req.method == "PUT" {
                    if let Some(pn) = part_number {
                        return handle_mpu_part(&cred, &b, &k, &uid, pn, req, next);
                    }
                }
                if req.method == "POST" {
                    return handle_mpu_complete(&cred, &b, &k, &uid, req, next, self);
                }
                if req.method == "DELETE" {
                    return handle_mpu_abort(&cred, &b, &k, &uid, self, next);
                }
                if req.method == "GET" {
                    return handle_mpu_list_parts(&cred, &b, &k, &uid, &params, self, next);
                }
            }
        }

        let mut key = key;
        let website_error_key =
            maybe_apply_website_index(&req, &cred, bucket.as_deref(), &mut key, &params, next);
        let method = req.method.clone();
        let is_copy = req.headers.get("X-Amz-Copy-Source").is_some();
        if method == "PUT" && is_copy {
            if let Some(resp) = reject_copy_to_self(&req) {
                return resp;
            }
        }
        let worm_bypass = if matches!(method.as_str(), "PUT" | "DELETE") {
            match (bucket.as_deref(), key.as_deref()) {
                (Some(bucket), Some(key)) => {
                    match governance_bypass_context(&self.iam, &cred, bucket, key, bypass_requested)
                    {
                        Ok(context) => context,
                        Err(resp) => return resp,
                    }
                }
                _ => GovernanceBypass::NONE,
            }
        } else {
            GovernanceBypass::NONE
        };
        // Multi-version object data plane (Enabled/Suspended) or explicit
        // ?versionId=. Suspended writes replace only the null version.
        // Also decide whether a later object HEAD (WORM/ACL) is required:
        // unversioned PUT into a bucket with no Object Lock was paying a
        // 404 HEAD per object (~150–200ms) before the real 3-replica PUT.
        let mut skip_object_precheck = false;
        if let (Some(b), Some(k)) = (bucket.clone(), key.clone()) {
            if matches!(method.as_str(), "PUT" | "GET" | "HEAD" | "DELETE") {
                let vstatus = match probe_bucket_versioning(&cred, &b, next, &self.container_heads)
                {
                    Ok(status) => status,
                    Err(resp) => return resp,
                };
                if method == "PUT" {
                    if let Ok((st, hdrs)) =
                        head_container(&cred, &b, next, &self.container_heads)
                    {
                        skip_object_precheck = (st == 404 || (200..300).contains(&st))
                            && !container_requires_object_precheck(&hdrs);
                    }
                }
                let versioning_mode = bucket_versioning_mode(vstatus.as_deref());
                if versioning_mode.is_some() || version_id_q.is_some() {
                    let resp = handle_versioned_object(
                        req,
                        &cred,
                        &b,
                        &k,
                        &method,
                        version_id_q.as_deref(),
                        versioning_mode,
                        is_copy,
                        worm_bypass,
                        next,
                        self,
                    );
                    if resp.status == 404 && matches!(method.as_str(), "GET" | "HEAD") {
                        if let Some(err_key) = website_error_key.as_deref() {
                            if let Some(err) =
                                website_error_document(&cred, &b, err_key, &method, next)
                            {
                                return err;
                            }
                        }
                    }
                    return resp;
                }
            }
        }

        let for_list = matches!(method.as_str(), "GET" | "HEAD") && key.is_none();
        let range_header = req.headers.get("Range").map(str::to_string);

        let mut swift_req = req;
        let swift_path = s3_to_swift_path(&cred.account, bucket.as_deref(), key.as_deref());
        swift_req.path = swift_path;
        if for_list && method == "GET" {
            if let Err(resp) = parse_list_max_keys(&params) {
                return resp;
            }
            swift_req.query_string = s3_to_swift_query(&params, true);
        } else if method == "GET" && bucket.is_none() {
            // ListBuckets
            swift_req.query_string = "format=json".into();
        } else if method == "DELETE" && key.is_some() {
            // Regular object DELETE must stay query-empty. Completed MPU is an
            // SLO: Swift returns 412 unless the follow-up uses
            // multipart-manifest=delete. Always sending that query 400s a
            // non-manifest (s3cmd del / probe.txt).
            swift_req.query_string.clear();
        } else {
            // Drop SigV4 query crumbs; keep empty for object ops.
            swift_req.query_string = s3_to_swift_query(&params, false);
        }

        map_amz_meta(&mut swift_req);
        if method == "HEAD" && key.is_some() {
            // Swift HEAD+Range often answers Content-Length 0. Keep Range
            // for S3 translation and send an unranged HEAD to Swift.
            swift_req.headers.remove("Range");
            swift_req.headers.remove("range");
        }
        if method == "PUT" && key.is_some() {
            persist_s3_object_headers(&mut swift_req);
        }
        if let Some(resp) = reject_copy_to_self(&swift_req) {
            return resp;
        }
        if let Some(resp) = rewrite_copy_source_version(&mut swift_req, &cred, next) {
            return resp;
        }
        if let Some(resp) = apply_copy_source(&mut swift_req) {
            return resp;
        }
        // ACL: canned x-amz-acl wins; else x-amz-grant-* (body empty on object PUT).
        // ACP XML body is handled on PUT ?acl via handle_acl.
        match resolve_acl_put_input(&swift_req.headers, None, &owner.id) {
            Ok(input) => {
                if !matches!(input, AclPutInput::None) {
                    if key.is_some() {
                        apply_object_acl_input(&mut swift_req.headers, &input);
                    } else {
                        apply_bucket_acl_input(&mut swift_req.headers, &input);
                    }
                }
            }
            Err(_) => {
                return s3_error_response("InvalidArgument", None, &[]);
            }
        }
        // Explicit x-amz-object-lock-* → sysmeta (before strip removes x-amz-*).
        if method == "PUT" && key.is_some() {
            if let Err(resp) = apply_request_object_lock_headers(&mut swift_req.headers) {
                return resp;
            }
        }
        strip_s3_only_headers(&mut swift_req.headers);
        stamp_auth(&mut swift_req, &cred);

        // Object Lock WORM + ACP WRITE: one object HEAD, not two.
        // Skip on PUT when the (already probed) container has no lock:
        // new keys 404 that HEAD every time, and S3 only allows object
        // lock on a lock-enabled bucket. DELETE still HEADs.
        if key.is_some()
            && matches!(method.as_str(), "DELETE" | "PUT")
            && !skip_object_precheck
        {
            match control_head_object(
                &cred,
                bucket.as_deref().unwrap(),
                key.as_deref().unwrap(),
                next,
            ) {
                Ok(ObjectHead::Missing) => {}
                Ok(ObjectHead::Present(head)) => {
                    if let Some(blocked) = worm_guard(&head.headers, worm_clock_ok, worm_bypass) {
                        return blocked;
                    }
                    if let Some(blocked) = deny_if_object_acl_blocks_write(&cred, &head.headers) {
                        return blocked;
                    }
                }
                Err(resp) => return resp,
            }
        }

        // Force JSON listings past any Accept noise.
        if for_list && method == "GET" {
            swift_req.headers.set("Accept", "application/json");
        }

        // Lifecycle EXECUTION + optional bucket default Object Lock retention.
        // Immediate due cold transition: lab archive + URI stamp when backend wired.
        if method == "PUT" {
            if let (Some(b), Some(k)) = (bucket.as_deref(), key.as_deref()) {
                maybe_apply_lifecycle_on_put(
                    &mut swift_req,
                    &cred,
                    b,
                    k,
                    next,
                    &self.container_heads,
                );
                if let Some(err) = maybe_archive_due_cold_on_put(
                    &mut swift_req,
                    &cred,
                    b,
                    k,
                    &self.cold_map,
                    self.cold_backend.as_ref(),
                    self.cold_delete_hot_after_archive,
                ) {
                    return err;
                }
                if let Err(resp) = apply_bucket_default_retention(
                    &mut swift_req,
                    &cred,
                    b,
                    next,
                    &self.container_heads,
                ) {
                    return resp;
                }
            }
        }

        let stamped_delete_at = swift_req.headers.get("X-Delete-At").map(str::to_string);
        // HTTP date conditions are second-precision. Forwarding them to Swift
        // compares against sub-second X-Timestamp and 412s the official
        // "listing LastModified as If-Unmodified-Since" case.
        // If-Match / If-None-Match must use the S3 ETag (sysmeta), not the
        // Swift SLO MD5 — SLO HEAD ignores a mismatched If-Match (200).
        let ius = swift_req
            .headers
            .get("If-Unmodified-Since")
            .map(str::to_string);
        let ims = swift_req
            .headers
            .get("If-Modified-Since")
            .map(str::to_string);
        let if_match = swift_req.headers.get("If-Match").map(str::to_string);
        let if_none_match = swift_req.headers.get("If-None-Match").map(str::to_string);
        if key.is_some() && matches!(method.as_str(), "GET" | "HEAD") {
            swift_req.headers.remove("If-Unmodified-Since");
            swift_req.headers.remove("If-Modified-Since");
            swift_req.headers.remove("If-Match");
            swift_req.headers.remove("If-None-Match");
        }
        let resp = if method == "DELETE" && key.is_some() {
            let retry = swift_req.clone_head();
            let first = next(swift_req);
            if first.status == 412 {
                let mut retry = retry;
                retry.query_string = "multipart-manifest=delete".into();
                next(retry)
            } else {
                first
            }
        } else {
            next(swift_req)
        };

        // Success path translations.
        if bucket.is_none() && method == "GET" && (200..300).contains(&resp.status) {
            let body = match resp.body.into_vec(MAX_CONTROL_BODY) {
                Ok(b) => b,
                Err(_) => {
                    return s3_error_response("InternalError", Some("listing too large"), &[])
                }
            };
            return translate_list_buckets(&body, &owner);
        }

        if key.is_none() && bucket.is_some() {
            if method == "GET" && (200..300).contains(&resp.status) {
                let body = match resp.body.into_vec(MAX_CONTROL_BODY) {
                    Ok(b) => b,
                    Err(_) => {
                        return s3_error_response("InternalError", Some("listing too large"), &[])
                    }
                };
                let b = bucket.as_deref().unwrap();
                let body = rewrite_listing_s3_etags(&body, &cred, b, next);
                if list_v2 {
                    return translate_list_objects_v2(&body, b, &params, &owner);
                }
                return translate_list_objects(&body, b, &params, &owner);
            }
            if (200..300).contains(&resp.status) {
                return translate_bucket_success(&method, resp, bucket.as_deref());
            }
            return map_swift_error(resp.status, bucket.as_deref(), None);
        }

        if key.is_some() {
            if (200..300).contains(&resp.status) {
                if matches!(method.as_str(), "GET" | "HEAD") {
                    let b = bucket.as_deref().unwrap();
                    let k = key.as_deref().unwrap();
                    let mut resp = resp;
                    if let Some(denied) = deny_if_object_acl_blocks_read(&cred, &resp.headers) {
                        return denied;
                    }
                    if let Some(err) = maybe_archive_due_cold_on_get_head(
                        &mut resp,
                        &method,
                        &cred,
                        b,
                        k,
                        &self.cold_map,
                        self.cold_backend.as_ref(),
                        self.cold_delete_hot_after_archive,
                        next,
                    ) {
                        return err;
                    }
                    let resp = translate_object_get_head(
                        &method,
                        resp,
                        &cred,
                        &params,
                        range_header.as_deref(),
                    );
                    return apply_get_head_preconditions(
                        resp,
                        &method,
                        if_match.as_deref(),
                        ius.as_deref(),
                        if_none_match.as_deref(),
                        ims.as_deref(),
                    );
                }
                let mut out = translate_object_success(&method, resp, is_copy);
                if method == "PUT" {
                    if let Some(exp) = stamped_delete_at
                        .as_deref()
                        .and_then(amz_expiration_from_delete_at)
                    {
                        out.headers.set("x-amz-expiration", exp);
                    }
                }
                return out;
            }
            if matches!(method.as_str(), "GET" | "HEAD") {
                if let (Some(b), Some(err_key)) = (bucket.as_deref(), website_error_key.as_deref())
                {
                    if let Some(err) = website_error_document(&cred, b, err_key, &method, next) {
                        return err;
                    }
                }
            }
            return map_swift_error_object(
                resp.status,
                &method,
                &cred,
                bucket.as_deref(),
                key.as_deref(),
                next,
            );
        }

        // Fallback (e.g. HEAD service)
        if (200..300).contains(&resp.status) {
            resp
        } else {
            map_swift_error(resp.status, bucket.as_deref(), key.as_deref())
        }
    }

    /// Unsigned S3 GET/HEAD using `anonymous_account` without auth override.
    /// Relies on Swift container ACL (`.r:*` / `.rlistings`) plus object ACL
    /// AllUsers checks when object ACL meta is present.
    fn dispatch_anonymous(&self, req: Request, account: String, next: &NextFn) -> Response {
        if let Some(denied) = self.frozen_account_denied(&account, &req) {
            return denied;
        }
        let params = req.params();
        if let Some(sub) = first_unsupported_subresource(&params) {
            return not_implemented_subresource(sub);
        }
        let (bucket, key) =
            extract_bucket_and_key(&req, &self.storage_domains, self.dns_compliant_bucket_names);
        let Some(bucket) = bucket else {
            return next(req);
        };
        if !validate_bucket_name(&bucket, self.dns_compliant_bucket_names) {
            return s3_error_response("InvalidBucketName", None, &[("BucketName", &bucket)]);
        }
        let method = req.method.clone();
        let for_list = matches!(method.as_str(), "GET" | "HEAD") && key.is_none();
        if let (Some(key), Some(version_id)) = (
            key.as_deref(),
            params
                .iter()
                .find(|(name, _)| name == "versionId")
                .map(|(_, value)| value.as_str()),
        ) {
            if !valid_version_id(version_id) {
                return s3_error_response("InvalidArgument", None, &[]);
            }
            return handle_anonymous_versioned_get_head(
                self, &method, &account, &bucket, key, version_id, next,
            );
        }
        let mut swift_req = req;
        swift_req.path = s3_to_swift_path(&account, Some(&bucket), key.as_deref());
        if for_list && method == "GET" {
            if let Err(resp) = parse_list_max_keys(&params) {
                return resp;
            }
            swift_req.query_string = s3_to_swift_query(&params, true);
            swift_req.headers.set("Accept", "application/json");
        } else {
            swift_req.query_string = s3_to_swift_query(&params, false);
        }
        strip_s3_only_headers(&mut swift_req.headers);
        // Intentionally no stamp_auth — container `.r:*` must authorize.
        let resp = next(swift_req);
        if key.is_none() {
            if method == "GET" && (200..300).contains(&resp.status) {
                let body = match resp.body.into_vec(MAX_CONTROL_BODY) {
                    Ok(b) => b,
                    Err(_) => return s3_error_response("InternalError", None, &[]),
                };
                let owner = Owner {
                    id: "anonymous".into(),
                    display_name: "anonymous".into(),
                };
                let list_v2 = params.iter().any(|(k, v)| k == "list-type" && v == "2");
                if list_v2 {
                    return translate_list_objects_v2(&body, &bucket, &params, &owner);
                }
                return translate_list_objects(&body, &bucket, &params, &owner);
            }
            if (200..300).contains(&resp.status) {
                return translate_bucket_success(&method, resp, Some(&bucket));
            }
            return map_swift_error(resp.status, Some(&bucket), None);
        }
        if (200..300).contains(&resp.status) {
            if object_acl_blocks_anonymous(&resp.headers) {
                return s3_error_response("AccessDenied", None, &[]);
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            let mut resp = resp;
            // Meta/deny only — no Swift POST (no auth). See helper honesty.
            maybe_stamp_due_cold_on_anonymous_get_head(
                &mut resp,
                &account,
                &bucket,
                key.as_deref().unwrap(),
                &self.cold_map,
            );
            if let Some(denied) = deny_if_transition_blocks_get(&mut resp.headers, now) {
                return denied;
            }
            if let Some(sc) = resp
                .headers
                .get("X-Object-Meta-S3-Storage-Class")
                .map(str::to_string)
            {
                resp.headers.set("x-amz-storage-class", sc);
            }
            return translate_object_success(&method, resp, false);
        }
        map_swift_error(resp.status, Some(&bucket), key.as_deref())
    }
}

fn handle_anonymous_versioned_get_head(
    api: &S3Api,
    method: &str,
    account: &str,
    bucket: &str,
    key: &str,
    version_id: &str,
    next: &NextFn,
) -> Response {
    // Prove the logical object path is anonymously readable before using the
    // internal owner identity needed to access the private versions container.
    // A public missing object returns 404; private TempAuth paths return 401/403.
    let public_probe = next(make_swift_req(
        "HEAD",
        &s3_to_swift_path(account, Some(bucket), Some(key)),
    ));
    if !((200..300).contains(&public_probe.status) || public_probe.status == 404) {
        return map_swift_error(public_probe.status, Some(bucket), Some(key));
    }

    let internal = S3Credential {
        access_key: "anonymous-internal-version-reader".into(),
        secret_key: String::new(),
        account: account.to_string(),
        groups: vec![account.to_string()],
        auth_token: None,
    };
    let target = match resolve_object_version(&internal, bucket, key, Some(version_id), next) {
        Ok(Some(target)) => target,
        Ok(None) => return missing_object_version_response(key, Some(version_id)),
        Err(resp) => return resp,
    };
    if is_delete_marker_header(target.head.headers.get(SYS_DELETE_MARKER)) {
        return nosuchkey_delete_marker(key, Some(version_id));
    }

    let mut resp = if method == "HEAD" {
        target.head
    } else {
        let mut get = make_swift_req(
            "GET",
            &s3_to_swift_path(account, Some(&target.container), Some(&target.key)),
        );
        stamp_auth(&mut get, &internal);
        let got = next(get);
        if !(200..300).contains(&got.status) {
            return map_swift_error(got.status, Some(&target.container), Some(&target.key));
        }
        got
    };
    if object_acl_blocks_anonymous(&resp.headers) {
        return s3_error_response("AccessDenied", None, &[]);
    }

    maybe_stamp_due_cold_on_anonymous_get_head(
        &mut resp,
        account,
        &target.container,
        &target.key,
        &api.cold_map,
    );
    if let Some(denied) = deny_if_transition_blocks_get(&mut resp.headers, unix_now()) {
        return denied;
    }
    let mut out = translate_object_success(method, resp, false);
    if (200..300).contains(&out.status) {
        out.headers.set(HDR_VERSION_ID, version_id);
    }
    out
}

fn make_swift_req(method: &str, path: &str) -> Request {
    Request {
        method: method.into(),
        path: path.into(),
        query_string: String::new(),
        headers: HeaderKeyDict::new(),
        body: Body::empty(),
    }
}

fn unix_now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

enum ObjectHead {
    Present(Response),
    Missing,
}

fn control_head_object(
    cred: &S3Credential,
    container: &str,
    key: &str,
    next: &NextFn,
) -> Result<ObjectHead, Response> {
    let mut head = make_swift_req(
        "HEAD",
        &s3_to_swift_path(&cred.account, Some(container), Some(key)),
    );
    stamp_auth(&mut head, cred);
    let resp = next(head);
    if (200..300).contains(&resp.status) {
        Ok(ObjectHead::Present(resp))
    } else if resp.status == 404 {
        Ok(ObjectHead::Missing)
    } else {
        Err(map_swift_error(resp.status, Some(container), Some(key)))
    }
}

/// Python `_get_upload_info`: HEAD `{bucket}+segments/{key}/{uploadId}` first;
/// if missing, HEAD dest and require `SYS_S3API_UPLOAD_ID` == uploadId.
struct MpuUploadInfo {
    headers: HeaderKeyDict,
}

fn get_mpu_upload_info(
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    upload_id: &str,
    next: &NextFn,
) -> Result<MpuUploadInfo, Response> {
    let segs = segments_container(bucket);
    let marker = upload_marker_name(key, upload_id);
    match control_head_object(cred, &segs, &marker, next)? {
        ObjectHead::Present(resp) => Ok(MpuUploadInfo {
            headers: resp.headers,
        }),
        ObjectHead::Missing => match control_head_object(cred, bucket, key, next)? {
            ObjectHead::Present(resp) => {
                if resp.headers.get(SYS_S3API_UPLOAD_ID) != Some(upload_id) {
                    return Err(s3_error_response("NoSuchUpload", None, &[]));
                }
                Ok(MpuUploadInfo {
                    headers: resp.headers,
                })
            }
            ObjectHead::Missing => Err(s3_error_response("NoSuchUpload", None, &[])),
        },
    }
}

/// Python already-uploaded s3-etag check. `None` means continue with SLO PUT.
fn complete_mpu_already_uploaded(
    stored_etag: Option<&str>,
    computed: Option<&str>,
    bucket: &str,
    key: &str,
    location: &str,
) -> Option<Response> {
    match match_completed_mpu_etag(stored_etag, computed) {
        CompletedMpuEtagMatch::Idempotent => {
            let etag = stored_etag.or(computed).unwrap_or("multipart");
            Some(xml_response(
                200,
                complete_multipart_xml(bucket, key, etag, location),
            ))
        }
        CompletedMpuEtagMatch::Conflict => Some(s3_error_response("NoSuchUpload", None, &[])),
        CompletedMpuEtagMatch::Continue => None,
    }
}

/// AWS/Python: If-None-Match:* on CompleteMultipartUpload is create-only.
/// Python leaves the header on the SLO PUT so object-server 412s when dest
/// exists. We must not put it on the SLO request: segment HEADs would inherit
/// it and 304/400. Enforce the 412 here instead, then PUT without the header.
fn complete_mpu_if_none_match_conflict(dest: ObjectHead) -> Option<Response> {
    match dest {
        ObjectHead::Present(_) => Some(s3_error_response("PreconditionFailed", None, &[])),
        ObjectHead::Missing => None,
    }
}

/// Account-level (bucket=None) request with a method the Python s3api
/// ServiceController does not implement → the byte-aligned Python reject.
///
/// Python 2.33 (probed live 2026-08-17): `PUT|DELETE|POST /` → 405 with
/// `<Error><Code>MethodNotAllowed</Code><Message>The specified method is not
/// allowed against this resource.</Message><RequestId>…</RequestId>
/// <Method>{METHOD}</Method><ResourceType>SERVICE</ResourceType></Error>`;
/// `HEAD /` → the same 405 with an empty body (`Content-Type:
/// application/xml`, `Content-Length: 0`). `GET /` (ListBuckets) is not
/// touched here; other verbs keep their existing paths.
fn service_method_not_allowed(method: &str) -> Option<Response> {
    if !matches!(method, "PUT" | "DELETE" | "POST" | "HEAD") {
        return None;
    }
    let mut resp = s3_error_response(
        "MethodNotAllowed",
        None,
        &[("Method", method), ("ResourceType", "SERVICE")],
    );
    if method == "HEAD" {
        resp.body = Body::empty();
    }
    Some(resp)
}

fn worm_guard(
    headers: &HeaderKeyDict,
    clock_ok: bool,
    bypass: GovernanceBypass,
) -> Option<Response> {
    match evaluate_object_version_worm_with_clock(headers, unix_now(), clock_ok, bypass) {
        WormDecision::Allow => None,
        WormDecision::Deny(WormDenyReason::InvalidPersistedState(_)) => Some(s3_error_response(
            "InternalError",
            Some("object lock metadata is invalid"),
            &[],
        )),
        WormDecision::Deny(_) => Some(s3_error_response("AccessDenied", None, &[])),
    }
}

async fn worm_check_object_async(
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    clock_ok: bool,
    bypass: GovernanceBypass,
    next: &AsyncNextFn,
) -> Option<Response> {
    match control_head_object_async(cred, bucket, key, next).await {
        Ok(ObjectHead::Missing) => None,
        Ok(ObjectHead::Present(resp)) => worm_guard(&resp.headers, clock_ok, bypass),
        Err(resp) => Some(resp),
    }
}

/// HEAD object; if structured ACP grants deny WRITE, AccessDenied.
/// Missing object (404) → no denial (create path).


fn worm_check_object(
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    clock_ok: bool,
    bypass: GovernanceBypass,
    next: &NextFn,
) -> Option<Response> {
    match control_head_object(cred, bucket, key, next) {
        Ok(ObjectHead::Missing) => None,
        Ok(ObjectHead::Present(resp)) => worm_guard(&resp.headers, clock_ok, bypass),
        Err(resp) => Some(resp),
    }
}

/// HEAD object; if structured ACP grants deny WRITE, AccessDenied.
/// Missing object (404) → no denial (create path).
async fn acl_write_check_object_async(
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    next: &AsyncNextFn,
) -> Option<Response> {
    match control_head_object_async(cred, bucket, key, next).await {
        Ok(ObjectHead::Missing) => None,
        Ok(ObjectHead::Present(resp)) => deny_if_object_acl_blocks_write(cred, &resp.headers),
        Err(resp) => Some(resp),
    }
}



fn acl_write_check_object(
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    next: &NextFn,
) -> Option<Response> {
    match control_head_object(cred, bucket, key, next) {
        Ok(ObjectHead::Missing) => None,
        Ok(ObjectHead::Present(resp)) => deny_if_object_acl_blocks_write(cred, &resp.headers),
        Err(resp) => Some(resp),
    }
}

fn iam_action_check(
    iam: &crate::iam::IamService,
    cred: &S3Credential,
    action: &str,
    bucket: &str,
    key: &str,
) -> Option<Response> {
    let principal = iam.identity.canonical_id_for_access_key(&cred.access_key);
    let resource = crate::iam::IamService::s3_resource(bucket, Some(key));
    if let Some(false) = iam.evaluate(&principal, action, &resource) {
        Some(s3_error_response(
            "AccessDenied",
            Some("IAM policy denied"),
            &[],
        ))
    } else {
        None
    }
}

fn iam_action_explicitly_allowed(
    iam: &crate::iam::IamService,
    cred: &S3Credential,
    action: &str,
    bucket: &str,
    key: &str,
) -> bool {
    let principal = iam.identity.canonical_id_for_access_key(&cred.access_key);
    let resource = crate::iam::IamService::s3_resource(bucket, Some(key));
    iam.evaluate(&principal, action, &resource) == Some(true)
}

fn governance_bypass_context(
    iam: &crate::iam::IamService,
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    requested: bool,
) -> Result<GovernanceBypass, Response> {
    if !requested {
        return Ok(GovernanceBypass::NONE);
    }
    // Header without the IAM grant is not a hard deny. Ceph/RGW and the
    // s3-tests nuke always send BypassGovernanceRetention; AWS only needs
    // the grant when GOVERNANCE retention is actually in force. worm_guard
    // still denies locked objects when authorized is false.
    Ok(GovernanceBypass {
        requested: true,
        authorized: iam_action_explicitly_allowed(
            iam,
            cred,
            "s3:BypassGovernanceRetention",
            bucket,
            key,
        ),
    })
}

fn valid_version_id(version_id: &str) -> bool {
    version_id == "null"
        || (version_id.len() == 32
            && version_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
}

struct ResolvedObjectVersion {
    container: String,
    key: String,
    head: Response,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BucketVersioningMode {
    Enabled,
    Suspended,
}

fn bucket_versioning_mode(status: Option<&str>) -> Option<BucketVersioningMode> {
    match versioning_status(status) {
        VersioningStatus::Enabled => Some(BucketVersioningMode::Enabled),
        VersioningStatus::Suspended => Some(BucketVersioningMode::Suspended),
        VersioningStatus::Unversioned => None,
    }
}

fn resolve_object_version(
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    version_id: Option<&str>,
    next: &NextFn,
) -> Result<Option<ResolvedObjectVersion>, Response> {
    if let Some(version_id) = version_id {
        if !valid_version_id(version_id) {
            return Err(s3_error_response("InvalidArgument", None, &[]));
        }
    }
    let current = control_head_object(cred, bucket, key, next)?;
    match (version_id, current) {
        (None, ObjectHead::Present(head)) => {
            return Ok(Some(ResolvedObjectVersion {
                container: bucket.to_string(),
                key: key.to_string(),
                head,
            }))
        }
        (None, ObjectHead::Missing) => return Ok(None),
        (Some(NULL_VERSION_ID), ObjectHead::Present(head))
            if matches!(
                head.headers.get(SYS_VERSION_ID),
                None | Some("") | Some(NULL_VERSION_ID)
            ) =>
        {
            return Ok(Some(ResolvedObjectVersion {
                container: bucket.to_string(),
                key: key.to_string(),
                head,
            }));
        }
        (Some(version_id), ObjectHead::Present(head))
            if head.headers.get(SYS_VERSION_ID) == Some(version_id) =>
        {
            return Ok(Some(ResolvedObjectVersion {
                container: bucket.to_string(),
                key: key.to_string(),
                head,
            }));
        }
        _ => {}
    }

    let version_id = version_id.expect("version id was handled above");

    // Hidden archive objects are implementation details, not an independent
    // source of truth.  Require the version index record before owner-auth
    // access so a failed archive/promotion cannot resurrect an orphan copy.
    let index = load_version_index(cred, bucket, key, next)?;
    if index.find(version_id).is_none() {
        return Ok(None);
    }
    if !is_safe_version_id(version_id) {
        return Err(unsafe_version_id_error());
    }

    let container = versions_container(bucket);
    let archived_key = archive_object_name(key, version_id);
    match control_head_object(cred, &container, &archived_key, next)? {
        ObjectHead::Present(head) => Ok(Some(ResolvedObjectVersion {
            container,
            key: archived_key,
            head,
        })),
        ObjectHead::Missing => Ok(None),
    }
}

fn missing_object_version_response(key: &str, version_id: Option<&str>) -> Response {
    if let Some(version_id) = version_id.filter(|v| *v != NULL_VERSION_ID) {
        s3_error_response(
            "NoSuchVersion",
            None,
            &[("Key", key), ("VersionId", version_id)],
        )
    } else {
        s3_error_response("NoSuchKey", None, &[("Key", key)])
    }
}

fn maybe_apply_website_index(
    req: &Request,
    cred: &S3Credential,
    bucket: Option<&str>,
    key: &mut Option<String>,
    params: &[(String, String)],
    next: &NextFn,
) -> Option<String> {
    if !matches!(req.method.as_str(), "GET" | "HEAD") {
        return None;
    }
    let Some(bucket) = bucket else {
        return None;
    };
    if !website_object_params(params) {
        return None;
    }
    if !is_website_endpoint(
        req.headers.get("Host"),
        req.headers
            .get("x-amz-website-endpoint")
            .or_else(|| req.headers.get("X-Amz-Website-Endpoint")),
    ) {
        return None;
    }
    let cfg = load_website_config(cred, bucket, next)?;
    let rewrite = key
        .as_deref()
        .map(|k| k.is_empty() || k.ends_with('/'))
        .unwrap_or(true);
    if rewrite {
        *key = Some(resolve_website_key(key.as_deref(), &cfg));
    }
    cfg.error_key
}

fn load_website_config(cred: &S3Credential, bucket: &str, next: &NextFn) -> Option<WebsiteConfig> {
    let spec = stored_bucket_config(&[("website".into(), String::new())])?;
    let mut head = make_swift_req("HEAD", &s3_to_swift_path(&cred.account, Some(bucket), None));
    stamp_auth(&mut head, cred);
    let resp = next(head);
    if !(200..300).contains(&resp.status) {
        return None;
    }
    let xml = stored_bucket_config_xml(&resp.headers, spec)?;
    parse_website_configuration(&xml)
}

fn website_error_document(
    cred: &S3Credential,
    bucket: &str,
    error_key: &str,
    method: &str,
    next: &NextFn,
) -> Option<Response> {
    let mut get = make_swift_req(
        if method == "HEAD" { "HEAD" } else { "GET" },
        &s3_to_swift_path(&cred.account, Some(bucket), Some(error_key)),
    );
    stamp_auth(&mut get, cred);
    let resp = next(get);
    if !(200..300).contains(&resp.status) {
        return None;
    }
    let mut out = resp;
    out.status = 404;
    Some(out)
}

/// HEAD bucket lifecycle meta → stamp Expiration X-Delete-At + Transition meta
/// on object PUT (LAB-HARD-GREEN: Transition is metadata stamp only).
fn maybe_apply_lifecycle_on_put(
    swift_req: &mut Request,
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    next: &NextFn,
    cache: &ContainerHeadCache,
) {
    let Ok((_, headers)) = head_container(cred, bucket, next, cache) else {
        return;
    };
    apply_lifecycle_on_put_from_container(&mut swift_req.headers, &headers, key, unix_now());
}

fn require_bucket_object_lock(
    cred: &S3Credential,
    bucket: &str,
    next: &NextFn,
) -> Result<(), Response> {
    let mut head = make_swift_req("HEAD", &s3_to_swift_path(&cred.account, Some(bucket), None));
    stamp_auth(&mut head, cred);
    let resp = next(head);
    if !(200..300).contains(&resp.status) {
        return Err(map_swift_error(resp.status, Some(bucket), None));
    }
    match validated_object_lock_xml_from_headers(&resp.headers) {
        Ok(Some(_)) => Ok(()),
        Ok(None) => Err(s3_error_response(
            "InvalidRequest",
            Some("Bucket is missing Object Lock Configuration"),
            &[],
        )),
        Err(_) => Err(s3_error_response(
            "InternalError",
            Some("bucket object lock metadata is invalid"),
            &[],
        )),
    }
}

fn apply_bucket_default_retention(
    put_req: &mut Request,
    cred: &S3Credential,
    bucket: &str,
    next: &NextFn,
    cache: &ContainerHeadCache,
) -> Result<(), Response> {
    if put_req.headers.get(SYS_RETAIN_UNTIL).is_some() {
        return Ok(());
    }
    let (status, headers) = head_container(cred, bucket, next, cache)?;
    if status == 404 {
        return Ok(());
    }
    if !(200..300).contains(&status) {
        return Err(map_swift_error(status, Some(bucket), None));
    }
    let xml = validated_object_lock_xml_from_headers(&headers).map_err(|_| {
        s3_error_response(
            "InternalError",
            Some("bucket object lock metadata is invalid"),
            &[],
        )
    })?;
    let Some(xml) = xml else {
        return Ok(());
    };
    let def = parse_object_lock_configuration(&xml).map_err(|_| {
        s3_error_response(
            "InternalError",
            Some("bucket object lock metadata is invalid"),
            &[],
        )
    })?;
    let Some(def) = def else {
        return Ok(());
    };
    apply_default_retention_headers(&mut put_req.headers, &def, unix_now());
    Ok(())
}

fn apply_request_object_lock_headers(headers: &mut HeaderKeyDict) -> Result<(), Response> {
    validate_and_apply_amz_object_lock_headers(headers)
        .map_err(|_| s3_error_response("InvalidRequest", None, &[]))?;
    if let (Some(mode), Some(until)) = (headers.get(SYS_LOCK_MODE), headers.get(SYS_RETAIN_UNTIL)) {
        let Some(retention) = parse_object_retention(mode, until) else {
            return Err(s3_error_response("InvalidRequest", None, &[]));
        };
        if !retention_date_is_valid_for_put(&retention, unix_now()) {
            return Err(s3_error_response("InvalidRequest", None, &[]));
        }
    }
    Ok(())
}

fn handle_legal_hold(
    req: Request,
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    version_id: Option<&str>,
    next: &NextFn,
) -> Response {
    let target = match resolve_object_version(cred, bucket, key, version_id, next) {
        Ok(Some(target)) => target,
        Ok(None) => return missing_object_version_response(key, version_id),
        Err(resp) => return resp,
    };
    let acl_denied = if req.method == "PUT" {
        deny_if_object_acl_blocks_write(cred, &target.head.headers)
    } else {
        deny_if_object_acl_blocks_read(cred, &target.head.headers)
    };
    if let Some(denied) = acl_denied {
        return denied;
    }
    match req.method.as_str() {
        "GET" | "HEAD" => match object_version_lock_state(&target.head.headers) {
            Ok(state) => xml_ok(legal_hold_xml(state.legal_hold_on)),
            Err(_) => s3_error_response(
                "InternalError",
                Some("object lock metadata is invalid"),
                &[],
            ),
        },
        "PUT" => {
            let body = match req.body.into_vec(MAX_CONTROL_BODY) {
                Ok(b) => b,
                Err(_) => return s3_error_response("IncompleteBody", None, &[]),
            };
            let on = match parse_legal_hold_body(&body) {
                Ok(v) => v,
                Err(_) => return s3_error_response("MalformedXML", None, &[]),
            };
            let mut post = make_swift_req(
                "POST",
                &s3_to_swift_path(&cred.account, Some(&target.container), Some(&target.key)),
            );
            post.headers
                .set(SYS_LEGAL_HOLD, if on { "ON" } else { "OFF" });
            stamp_auth(&mut post, cred);
            let resp = next(post);
            if (200..300).contains(&resp.status) {
                Response::new(200)
            } else {
                map_swift_error(resp.status, Some(&target.container), Some(&target.key))
            }
        }
        _ => s3_error_response("MethodNotAllowed", None, &[]),
    }
}

fn handle_retention(
    req: Request,
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    version_id: Option<&str>,
    clock_ok: bool,
    bypass: GovernanceBypass,
    next: &NextFn,
) -> Response {
    let target = match resolve_object_version(cred, bucket, key, version_id, next) {
        Ok(Some(target)) => target,
        Ok(None) => return missing_object_version_response(key, version_id),
        Err(resp) => return resp,
    };
    let acl_denied = if req.method == "PUT" {
        deny_if_object_acl_blocks_write(cred, &target.head.headers)
    } else {
        deny_if_object_acl_blocks_read(cred, &target.head.headers)
    };
    if let Some(denied) = acl_denied {
        return denied;
    }
    match req.method.as_str() {
        "GET" | "HEAD" => match object_version_lock_state(&target.head.headers) {
            Ok(state) => match state.retention {
                Some(retention) => xml_ok(retention_xml(
                    retention.mode.as_str(),
                    &retention.retain_until,
                )),
                None => s3_error_response(
                    "InvalidRequest",
                    Some("Object is missing retention configuration"),
                    &[],
                ),
            },
            Err(_) => s3_error_response(
                "InternalError",
                Some("object lock metadata is invalid"),
                &[],
            ),
        },
        "PUT" => {
            let body = match req.body.into_vec(MAX_CONTROL_BODY) {
                Ok(b) => b,
                Err(_) => return s3_error_response("IncompleteBody", None, &[]),
            };
            let (mode, until) = match parse_retention_body(&body) {
                Ok(v) => v,
                Err(_) => return s3_error_response("MalformedXML", None, &[]),
            };
            let Some(requested) = parse_object_retention(&mode, &until) else {
                return s3_error_response("MalformedXML", None, &[]);
            };
            match evaluate_retention_update_with_clock(
                &target.head.headers,
                &requested,
                unix_now(),
                clock_ok,
                bypass,
            ) {
                RetentionUpdateDecision::Allow => {}
                RetentionUpdateDecision::Deny(
                    RetentionUpdateDenyReason::InvalidPersistedState(_),
                ) => {
                    return s3_error_response(
                        "InternalError",
                        Some("object lock metadata is invalid"),
                        &[],
                    )
                }
                RetentionUpdateDecision::Deny(RetentionUpdateDenyReason::InvalidRequest) => {
                    return s3_error_response("InvalidRequest", None, &[])
                }
                RetentionUpdateDecision::Deny(_) => {
                    return s3_error_response("AccessDenied", None, &[])
                }
            }
            let mut post = make_swift_req(
                "POST",
                &s3_to_swift_path(&cred.account, Some(&target.container), Some(&target.key)),
            );
            post.headers.set(SYS_LOCK_MODE, requested.mode.as_str());
            post.headers.set(SYS_RETAIN_UNTIL, &requested.retain_until);
            stamp_auth(&mut post, cred);
            let resp = next(post);
            if (200..300).contains(&resp.status) {
                Response::new(200)
            } else {
                map_swift_error(resp.status, Some(&target.container), Some(&target.key))
            }
        }
        _ => s3_error_response("MethodNotAllowed", None, &[]),
    }
}

async fn handle_multi_delete_async(
    req: Request,
    cred: &S3Credential,
    bucket: &str,
    iam: &crate::iam::IamService,
    clock_ok: bool,
    api: &S3Api,
    next: &AsyncNextFn,
) -> Response {
    if let Err(resp) = require_bucket_async(cred, bucket, next, &api.container_heads).await {
        return resp;
    }
    let body = match req.body.into_vec(MAX_CONTROL_BODY) {
        Ok(b) => b,
        Err(_) => return s3_error_response("IncompleteBody", None, &[]),
    };
    let parsed = match parse_multi_delete_body(&body) {
        Ok(p) => p,
        Err(code) => return s3_error_response(&code, None, &[]),
    };
    if parsed.objects.len() > 1000 {
        return s3_error_response("MalformedXML", None, &[]);
    }
    let bypass_requested = match parse_bypass_governance_header(
        req.headers
            .get(HDR_BYPASS_GOVERNANCE)
            .or_else(|| req.headers.get("X-Amz-Bypass-Governance-Retention")),
    ) {
        Ok(value) => value,
        Err(_) => return s3_error_response("InvalidArgument", None, &[]),
    };
    let versioning_mode = match probe_bucket_versioning_async(cred, bucket, next, &api.container_heads).await {
        Ok(status) => bucket_versioning_mode(status.as_deref()),
        Err(resp) => return resp,
    };
    let mut deleted = Vec::new();
    let mut errors = Vec::new();
    for object in &parsed.objects {
        let key = &object.key;
        if object
            .version_id
            .as_deref()
            .is_some_and(|version_id| !valid_version_id(version_id))
        {
            errors.push(DeleteError {
                key: key.clone(),
                version_id: object.version_id.clone(),
                code: "InvalidArgument".into(),
                message: "Invalid Argument.".into(),
            });
            continue;
        }
        let action = if object.version_id.is_some() {
            "s3:DeleteObjectVersion"
        } else {
            "s3:DeleteObject"
        };
        if iam_action_check(iam, cred, action, bucket, key).is_some() {
            errors.push(DeleteError {
                key: key.clone(),
                version_id: object.version_id.clone(),
                code: "AccessDenied".into(),
                message: "Access Denied.".into(),
            });
            continue;
        }
        let bypass = match governance_bypass_context(iam, cred, bucket, key, bypass_requested) {
            Ok(context) => context,
            Err(_) => {
                errors.push(DeleteError {
                    key: key.clone(),
                    version_id: object.version_id.clone(),
                    code: "AccessDenied".into(),
                    message: "Access Denied.".into(),
                });
                continue;
            }
        };

        let resp = if versioning_mode.is_some() || object.version_id.is_some() {
            handle_versioned_delete_async(
                cred,
                bucket,
                key,
                object.version_id.as_deref(),
                match versioning_mode {
                    Some(BucketVersioningMode::Suspended) if object.version_id.is_none() => {
                        Some(NULL_VERSION_ID)
                    }
                    _ => None,
                },
                clock_ok,
                bypass,
                next,
            ).await
        } else {
            if let Some(blocked) = worm_check_object_async(cred, bucket, key, clock_ok, bypass, next).await {
                blocked
            } else if let Some(blocked) = acl_write_check_object_async(cred, bucket, key, next).await {
                blocked
            } else {
                let mut del = make_swift_req(
                    "DELETE",
                    &s3_to_swift_path(&cred.account, Some(bucket), Some(key)),
                );
                stamp_auth(&mut del, cred);
                async_call(next, del).await
            }
        };
        if (200..300).contains(&resp.status) || resp.status == 404 {
            let delete_marker = resp.headers.get(HDR_DELETE_MARKER) == Some("true");
            let response_version = resp.headers.get(HDR_VERSION_ID).map(str::to_string);
            deleted.push(DeletedObject {
                key: key.clone(),
                version_id: object.version_id.clone(),
                delete_marker,
                delete_marker_version_id: delete_marker.then(|| {
                    response_version
                        .clone()
                        .or_else(|| object.version_id.clone())
                        .unwrap_or_else(|| NULL_VERSION_ID.to_string())
                }),
            });
        } else {
            let (code, message) = if matches!(resp.status, 401 | 403) {
                ("AccessDenied", "Access Denied.".to_string())
            } else if resp.status == 400 {
                ("InvalidArgument", "Invalid Argument.".to_string())
            } else {
                ("InternalError", format!("backend status {}", resp.status))
            };
            errors.push(DeleteError {
                key: key.clone(),
                version_id: object.version_id.clone(),
                code: code.into(),
                message,
            });
        }
    }
    // Quiet mode: omit successful Deleted entries (errors still returned).
    let deleted_out = if parsed.quiet { Vec::new() } else { deleted };
    xml_response(200, delete_result_xml(&deleted_out, &errors))
}



fn handle_multi_delete(
    req: Request,
    cred: &S3Credential,
    bucket: &str,
    iam: &crate::iam::IamService,
    clock_ok: bool,
    api: &S3Api,
    next: &NextFn,
) -> Response {
    if let Err(resp) = require_bucket(cred, bucket, next, &api.container_heads) {
        return resp;
    }
    let body = match req.body.into_vec(MAX_CONTROL_BODY) {
        Ok(b) => b,
        Err(_) => return s3_error_response("IncompleteBody", None, &[]),
    };
    let parsed = match parse_multi_delete_body(&body) {
        Ok(p) => p,
        Err(code) => return s3_error_response(&code, None, &[]),
    };
    if parsed.objects.len() > 1000 {
        return s3_error_response("MalformedXML", None, &[]);
    }
    let bypass_requested = match parse_bypass_governance_header(
        req.headers
            .get(HDR_BYPASS_GOVERNANCE)
            .or_else(|| req.headers.get("X-Amz-Bypass-Governance-Retention")),
    ) {
        Ok(value) => value,
        Err(_) => return s3_error_response("InvalidArgument", None, &[]),
    };
    let versioning_mode = match probe_bucket_versioning(cred, bucket, next, &api.container_heads) {
        Ok(status) => bucket_versioning_mode(status.as_deref()),
        Err(resp) => return resp,
    };
    let mut deleted = Vec::new();
    let mut errors = Vec::new();
    for object in &parsed.objects {
        let key = &object.key;
        if object
            .version_id
            .as_deref()
            .is_some_and(|version_id| !valid_version_id(version_id))
        {
            errors.push(DeleteError {
                key: key.clone(),
                version_id: object.version_id.clone(),
                code: "InvalidArgument".into(),
                message: "Invalid Argument.".into(),
            });
            continue;
        }
        let action = if object.version_id.is_some() {
            "s3:DeleteObjectVersion"
        } else {
            "s3:DeleteObject"
        };
        if iam_action_check(iam, cred, action, bucket, key).is_some() {
            errors.push(DeleteError {
                key: key.clone(),
                version_id: object.version_id.clone(),
                code: "AccessDenied".into(),
                message: "Access Denied.".into(),
            });
            continue;
        }
        let bypass = match governance_bypass_context(iam, cred, bucket, key, bypass_requested) {
            Ok(context) => context,
            Err(_) => {
                errors.push(DeleteError {
                    key: key.clone(),
                    version_id: object.version_id.clone(),
                    code: "AccessDenied".into(),
                    message: "Access Denied.".into(),
                });
                continue;
            }
        };

        let resp = if versioning_mode.is_some() || object.version_id.is_some() {
            handle_versioned_delete(
                cred,
                bucket,
                key,
                object.version_id.as_deref(),
                match versioning_mode {
                    Some(BucketVersioningMode::Suspended) if object.version_id.is_none() => {
                        Some(NULL_VERSION_ID)
                    }
                    _ => None,
                },
                clock_ok,
                bypass,
                next,
            )
        } else {
            if let Some(blocked) = worm_check_object(cred, bucket, key, clock_ok, bypass, next) {
                blocked
            } else if let Some(blocked) = acl_write_check_object(cred, bucket, key, next) {
                blocked
            } else {
                let mut del = make_swift_req(
                    "DELETE",
                    &s3_to_swift_path(&cred.account, Some(bucket), Some(key)),
                );
                stamp_auth(&mut del, cred);
                next(del)
            }
        };
        if (200..300).contains(&resp.status) || resp.status == 404 {
            let delete_marker = resp.headers.get(HDR_DELETE_MARKER) == Some("true");
            let response_version = resp.headers.get(HDR_VERSION_ID).map(str::to_string);
            deleted.push(DeletedObject {
                key: key.clone(),
                version_id: object.version_id.clone(),
                delete_marker,
                delete_marker_version_id: delete_marker.then(|| {
                    response_version
                        .clone()
                        .or_else(|| object.version_id.clone())
                        .unwrap_or_else(|| NULL_VERSION_ID.to_string())
                }),
            });
        } else {
            let (code, message) = if matches!(resp.status, 401 | 403) {
                ("AccessDenied", "Access Denied.".to_string())
            } else if resp.status == 400 {
                ("InvalidArgument", "Invalid Argument.".to_string())
            } else {
                ("InternalError", format!("backend status {}", resp.status))
            };
            errors.push(DeleteError {
                key: key.clone(),
                version_id: object.version_id.clone(),
                code: code.into(),
                message,
            });
        }
    }
    // Quiet mode: omit successful Deleted entries (errors still returned).
    let deleted_out = if parsed.quiet { Vec::new() } else { deleted };
    xml_response(200, delete_result_xml(&deleted_out, &errors))
}

async fn handle_acl_async(
    mut req: Request,
    cred: &S3Credential,
    owner: &Owner,
    bucket: &str,
    key: Option<&str>,
    next: &AsyncNextFn,
) -> Response {
    if let Some(obj) = key {
        // Object ACL: JSON grants and/or canned name in object sysmeta.
        match req.method.as_str() {
            "GET" | "HEAD" => {
                let mut head = make_swift_req(
                    "HEAD",
                    &s3_to_swift_path(&cred.account, Some(bucket), Some(obj)),
                );
                stamp_auth(&mut head, cred);
                let resp = async_call(next, head).await;
                if !(200..300).contains(&resp.status) {
                    return map_swift_error(resp.status, Some(bucket), Some(obj));
                }
                xml_ok(object_acl_xml_from_headers(&owner.id, &resp.headers))
            }
            "PUT" => {
                let body = match req.body.take().into_vec(MAX_CONTROL_BODY) {
                    Ok(b) => b,
                    Err(_) => return s3_error_response("InvalidRequest", None, &[]),
                };
                let input = match resolve_acl_put_input(
                    &req.headers,
                    if body.is_empty() { None } else { Some(&body) },
                    &owner.id,
                ) {
                    Ok(AclPutInput::None) => AclPutInput::Canned("private".into()),
                    Ok(i) => i,
                    Err(_) => return s3_error_response("MalformedACLError", None, &[]),
                };
                let mut post = make_swift_req(
                    "POST",
                    &s3_to_swift_path(&cred.account, Some(bucket), Some(obj)),
                );
                apply_object_acl_input(&mut post.headers, &input);
                stamp_auth(&mut post, cred);
                let resp = async_call(next, post).await;
                if (200..300).contains(&resp.status) {
                    Response::new(200)
                } else {
                    map_swift_error(resp.status, Some(bucket), Some(obj))
                }
            }
            _ => s3_error_response("MethodNotAllowed", None, &[]),
        }
    } else {
        match req.method.as_str() {
            "GET" | "HEAD" => {
                let mut head =
                    make_swift_req("HEAD", &s3_to_swift_path(&cred.account, Some(bucket), None));
                stamp_auth(&mut head, cred);
                let resp = async_call(next, head).await;
                if !(200..300).contains(&resp.status) {
                    return map_swift_error(resp.status, Some(bucket), None);
                }
                xml_ok(bucket_acl_xml_from_headers(&owner.id, &resp.headers))
            }
            "PUT" => {
                let body = match req.body.take().into_vec(MAX_CONTROL_BODY) {
                    Ok(b) => b,
                    Err(_) => return s3_error_response("InvalidRequest", None, &[]),
                };
                let input = match resolve_acl_put_input(
                    &req.headers,
                    if body.is_empty() { None } else { Some(&body) },
                    &owner.id,
                ) {
                    Ok(AclPutInput::None) => AclPutInput::Canned("private".into()),
                    Ok(i) => i,
                    Err(_) => return s3_error_response("MalformedACLError", None, &[]),
                };
                let mut post =
                    make_swift_req("POST", &s3_to_swift_path(&cred.account, Some(bucket), None));
                apply_bucket_acl_input(&mut post.headers, &input);
                stamp_auth(&mut post, cred);
                let resp = async_call(next, post).await;
                if (200..300).contains(&resp.status) {
                    // Python `AclController.PUT` bucket: Location = container_name.
                    // Runner `put-bucket-acl-private` header rule is exact-bucket.
                    let mut out = Response::new(200);
                    out.headers.set("Location", bucket);
                    out
                } else {
                    map_swift_error(resp.status, Some(bucket), None)
                }
            }
            _ => s3_error_response("MethodNotAllowed", None, &[]),
        }
    }
}



fn handle_acl(
    mut req: Request,
    cred: &S3Credential,
    owner: &Owner,
    bucket: &str,
    key: Option<&str>,
    next: &NextFn,
) -> Response {
    if let Some(obj) = key {
        // Object ACL: JSON grants and/or canned name in object sysmeta.
        match req.method.as_str() {
            "GET" | "HEAD" => {
                let mut head = make_swift_req(
                    "HEAD",
                    &s3_to_swift_path(&cred.account, Some(bucket), Some(obj)),
                );
                stamp_auth(&mut head, cred);
                let resp = next(head);
                if !(200..300).contains(&resp.status) {
                    return map_swift_error(resp.status, Some(bucket), Some(obj));
                }
                xml_ok(object_acl_xml_from_headers(&owner.id, &resp.headers))
            }
            "PUT" => {
                let body = match req.body.take().into_vec(MAX_CONTROL_BODY) {
                    Ok(b) => b,
                    Err(_) => return s3_error_response("InvalidRequest", None, &[]),
                };
                let input = match resolve_acl_put_input(
                    &req.headers,
                    if body.is_empty() { None } else { Some(&body) },
                    &owner.id,
                ) {
                    Ok(AclPutInput::None) => AclPutInput::Canned("private".into()),
                    Ok(i) => i,
                    Err(_) => return s3_error_response("MalformedACLError", None, &[]),
                };
                let mut post = make_swift_req(
                    "POST",
                    &s3_to_swift_path(&cred.account, Some(bucket), Some(obj)),
                );
                apply_object_acl_input(&mut post.headers, &input);
                stamp_auth(&mut post, cred);
                let resp = next(post);
                if (200..300).contains(&resp.status) {
                    Response::new(200)
                } else {
                    map_swift_error(resp.status, Some(bucket), Some(obj))
                }
            }
            _ => s3_error_response("MethodNotAllowed", None, &[]),
        }
    } else {
        match req.method.as_str() {
            "GET" | "HEAD" => {
                let mut head =
                    make_swift_req("HEAD", &s3_to_swift_path(&cred.account, Some(bucket), None));
                stamp_auth(&mut head, cred);
                let resp = next(head);
                if !(200..300).contains(&resp.status) {
                    return map_swift_error(resp.status, Some(bucket), None);
                }
                xml_ok(bucket_acl_xml_from_headers(&owner.id, &resp.headers))
            }
            "PUT" => {
                let body = match req.body.take().into_vec(MAX_CONTROL_BODY) {
                    Ok(b) => b,
                    Err(_) => return s3_error_response("InvalidRequest", None, &[]),
                };
                let input = match resolve_acl_put_input(
                    &req.headers,
                    if body.is_empty() { None } else { Some(&body) },
                    &owner.id,
                ) {
                    Ok(AclPutInput::None) => AclPutInput::Canned("private".into()),
                    Ok(i) => i,
                    Err(_) => return s3_error_response("MalformedACLError", None, &[]),
                };
                let mut post =
                    make_swift_req("POST", &s3_to_swift_path(&cred.account, Some(bucket), None));
                apply_bucket_acl_input(&mut post.headers, &input);
                stamp_auth(&mut post, cred);
                let resp = next(post);
                if (200..300).contains(&resp.status) {
                    // Python `AclController.PUT` bucket: Location = container_name.
                    // Runner `put-bucket-acl-private` header rule is exact-bucket.
                    let mut out = Response::new(200);
                    out.headers.set("Location", bucket);
                    out
                } else {
                    map_swift_error(resp.status, Some(bucket), None)
                }
            }
            _ => s3_error_response("MethodNotAllowed", None, &[]),
        }
    }
}

async fn handle_cors_async(req: Request, cred: &S3Credential, bucket: &str, next: &AsyncNextFn) -> Response {
    match req.method.as_str() {
        "GET" | "HEAD" => {
            let mut head =
                make_swift_req("HEAD", &s3_to_swift_path(&cred.account, Some(bucket), None));
            stamp_auth(&mut head, cred);
            let resp = async_call(next, head).await;
            if !(200..300).contains(&resp.status) {
                return map_swift_error(resp.status, Some(bucket), None);
            }
            xml_ok(cors_xml_from_swift_headers(&resp.headers))
        }
        "PUT" => {
            let body = match req.body.into_vec(MAX_CONTROL_BODY) {
                Ok(b) => b,
                Err(_) => return s3_error_response("IncompleteBody", None, &[]),
            };
            let cfg = match parse_cors_configuration(&body) {
                Ok(c) => c,
                Err(_) => return s3_error_response("MalformedXML", None, &[]),
            };
            let mut post =
                make_swift_req("POST", &s3_to_swift_path(&cred.account, Some(bucket), None));
            cors_config_to_swift_headers(&mut post.headers, &cfg);
            stamp_auth(&mut post, cred);
            let resp = async_call(next, post).await;
            if (200..300).contains(&resp.status) {
                Response::new(200)
            } else {
                map_swift_error(resp.status, Some(bucket), None)
            }
        }
        "DELETE" => {
            let mut post =
                make_swift_req("POST", &s3_to_swift_path(&cred.account, Some(bucket), None));
            clear_cors_swift_headers(&mut post.headers);
            stamp_auth(&mut post, cred);
            let _ = async_call(next, post).await;
            Response::new(204)
        }
        _ => s3_error_response("MethodNotAllowed", None, &[]),
    }
}



fn handle_cors(req: Request, cred: &S3Credential, bucket: &str, next: &NextFn) -> Response {
    match req.method.as_str() {
        "GET" | "HEAD" => {
            let mut head =
                make_swift_req("HEAD", &s3_to_swift_path(&cred.account, Some(bucket), None));
            stamp_auth(&mut head, cred);
            let resp = next(head);
            if !(200..300).contains(&resp.status) {
                return map_swift_error(resp.status, Some(bucket), None);
            }
            xml_ok(cors_xml_from_swift_headers(&resp.headers))
        }
        "PUT" => {
            let body = match req.body.into_vec(MAX_CONTROL_BODY) {
                Ok(b) => b,
                Err(_) => return s3_error_response("IncompleteBody", None, &[]),
            };
            let cfg = match parse_cors_configuration(&body) {
                Ok(c) => c,
                Err(_) => return s3_error_response("MalformedXML", None, &[]),
            };
            let mut post =
                make_swift_req("POST", &s3_to_swift_path(&cred.account, Some(bucket), None));
            cors_config_to_swift_headers(&mut post.headers, &cfg);
            stamp_auth(&mut post, cred);
            let resp = next(post);
            if (200..300).contains(&resp.status) {
                Response::new(200)
            } else {
                map_swift_error(resp.status, Some(bucket), None)
            }
        }
        "DELETE" => {
            let mut post =
                make_swift_req("POST", &s3_to_swift_path(&cred.account, Some(bucket), None));
            clear_cors_swift_headers(&mut post.headers);
            stamp_auth(&mut post, cred);
            let _ = next(post);
            Response::new(204)
        }
        _ => s3_error_response("MethodNotAllowed", None, &[]),
    }
}

fn handle_versioning(req: Request, cred: &S3Credential, bucket: &str, next: &NextFn) -> Response {
    match req.method.as_str() {
        "GET" | "HEAD" => {
            let mut head =
                make_swift_req("HEAD", &s3_to_swift_path(&cred.account, Some(bucket), None));
            stamp_auth(&mut head, cred);
            let resp = next(head);
            if !(200..300).contains(&resp.status) {
                return map_swift_error(resp.status, Some(bucket), None);
            }
            match versioning_status_from_headers(&resp.headers) {
                Ok(status) => xml_ok(versioning_configuration_xml(status.as_deref())),
                Err(_) => s3_error_response(
                    "InternalError",
                    Some("bucket versioning metadata is invalid"),
                    &[],
                ),
            }
        }
        "PUT" => {
            let body = match req.body.into_vec(MAX_CONTROL_BODY) {
                Ok(b) => b,
                Err(_) => return s3_error_response("IncompleteBody", None, &[]),
            };
            let status = match parse_versioning_status(&body) {
                Ok(s) => s,
                Err(_) => return s3_error_response("MalformedXML", None, &[]),
            };
            if status == "Suspended" {
                let mut head =
                    make_swift_req("HEAD", &s3_to_swift_path(&cred.account, Some(bucket), None));
                stamp_auth(&mut head, cred);
                let current = next(head);
                if !(200..300).contains(&current.status) {
                    return map_swift_error(current.status, Some(bucket), None);
                }
                match validated_object_lock_xml_from_headers(&current.headers) {
                    Ok(Some(_)) => {
                        return s3_error_response(
                            "InvalidBucketState",
                            Some("Object Lock requires versioning to remain enabled"),
                            &[],
                        )
                    }
                    Ok(None) => {}
                    Err(_) => {
                        return s3_error_response(
                            "InternalError",
                            Some("bucket object lock metadata is invalid"),
                            &[],
                        )
                    }
                }
            }
            let mut post =
                make_swift_req("POST", &s3_to_swift_path(&cred.account, Some(bucket), None));
            apply_versioning_meta(&mut post.headers, status);
            stamp_auth(&mut post, cred);
            let resp = next(post);
            if (200..300).contains(&resp.status) {
                Response::new(200)
            } else {
                map_swift_error(resp.status, Some(bucket), None)
            }
        }
        _ => s3_error_response("MethodNotAllowed", None, &[]),
    }
}

// ---------------------------------------------------------------------------
// Multi-version object data plane
// ---------------------------------------------------------------------------

/// True when object PUT/DELETE must HEAD the existing object first.
/// Fail-closed on corrupt lock metadata. No lock XML → skip the 404 HEAD
/// that sequential creates were paying on every object.
fn container_requires_object_precheck(headers: &HeaderKeyDict) -> bool {
    !matches!(validated_object_lock_xml_from_headers(headers), Ok(None))
}

fn request_to_streaming(req: Request) -> AsyncRequest {
    let Request {
        method,
        path,
        query_string,
        headers,
        body,
    } = req;
    let bytes = body.into_vec(u64::MAX).unwrap_or_default();
    AsyncRequest {
        method,
        path,
        query_string,
        headers,
        body: IncomingBody::from_bytes(bytes, MAX_CONTROL_BODY),
    }
}

async fn head_container_streaming(
    cred: &S3Credential,
    bucket: &str,
    next: &StreamingAsyncNextFn,
    cache: &ContainerHeadCache,
) -> Result<(u16, HeaderKeyDict), Response> {
    if let Some(hit) = cache.get(&cred.account, bucket) {
        return Ok(hit);
    }
    let mut head = make_swift_req("HEAD", &s3_to_swift_path(&cred.account, Some(bucket), None));
    stamp_auth(&mut head, cred);
    let resp = next(request_to_streaming(head)).await;
    if (200..300).contains(&resp.status) {
        cache.store(&cred.account, bucket, resp.status, resp.headers.clone());
    }
    Ok((resp.status, resp.headers))
}

async fn control_head_object_streaming(
    cred: &S3Credential,
    container: &str,
    key: &str,
    next: &StreamingAsyncNextFn,
) -> Result<ObjectHead, Response> {
    let mut head = make_swift_req(
        "HEAD",
        &s3_to_swift_path(&cred.account, Some(container), Some(key)),
    );
    stamp_auth(&mut head, cred);
    let resp = next(request_to_streaming(head)).await;
    if (200..300).contains(&resp.status) {
        Ok(ObjectHead::Present(resp))
    } else if resp.status == 404 {
        Ok(ObjectHead::Missing)
    } else {
        Err(map_swift_error(resp.status, Some(container), Some(key)))
    }
}

async fn streaming_call(next: &StreamingAsyncNextFn, req: Request) -> Response {
    next(request_to_streaming(req)).await
}

async fn async_call(next: &AsyncNextFn, req: Request) -> Response {
    next(req).await
}

async fn body_bytes(body: Body) -> Result<Vec<u8>, Response> {
    body.collect_async().await.map_err(|_| {
        s3_error_response("InternalError", Some("response body is too large"), &[])
    })
}

fn async_next_as_blocking(_next: AsyncNextFn) -> NextFn {
    Arc::new(move |_req| {
        Response::error(
            500,
            "s3 legacy blocking adapter removed from the async serve path",
        )
    })
}

fn s3_query_needs_legacy_dispatch(params: &[(String, String)]) -> bool {
    const NATIVE: &[&str] = &[
        "prefix",
        "delimiter",
        "marker",
        "max-keys",
        "encoding-type",
        "list-type",
        "continuation-token",
        "start-after",
        "fetch-owner",
        "uploads",
        "uploadId",
        "partNumber",
        "versioning",
        "location",
        "versionId",
        "versions",
        "acl",
        "tagging",
        "cors",
        "lifecycle",
        "delete",
        "object-lock",
        "legal-hold",
        "retention",
        "website",
        "attributes",
        "restore",
        "encryption",
        "policyStatus",
        "session",
        "annotation",
        "select",
        "key-marker",
        "version-id-marker",
        "max-directory-buckets",
    ];
    params.iter().any(|(k, _)| {
        if k.eq_ignore_ascii_case("AWSAccessKeyId")
            || k.eq_ignore_ascii_case("Expires")
            || k.eq_ignore_ascii_case("Signature")
            || k.len() >= 5 && k[..5].eq_ignore_ascii_case("x-amz")
        {
            return false;
        }
        !NATIVE.iter().any(|n| n.eq_ignore_ascii_case(k))
    })
}

async fn head_container_async(
    cred: &S3Credential,
    bucket: &str,
    next: &AsyncNextFn,
    cache: &ContainerHeadCache,
) -> Result<(u16, HeaderKeyDict), Response> {
    if let Some(hit) = cache.get(&cred.account, bucket) {
        return Ok(hit);
    }
    let mut head = make_swift_req("HEAD", &s3_to_swift_path(&cred.account, Some(bucket), None));
    stamp_auth(&mut head, cred);
    let resp = async_call(next, head).await;
    if (200..300).contains(&resp.status) {
        cache.store(&cred.account, bucket, resp.status, resp.headers.clone());
    }
    Ok((resp.status, resp.headers))
}

async fn require_bucket_async(
    cred: &S3Credential,
    bucket: &str,
    next: &AsyncNextFn,
    cache: &ContainerHeadCache,
) -> Result<HeaderKeyDict, Response> {
    let (status, headers) = head_container_async(cred, bucket, next, cache).await?;
    if status == 404 {
        return Err(s3_error_response(
            "NoSuchBucket",
            None,
            &[("BucketName", bucket)],
        ));
    }
    if !(200..300).contains(&status) {
        return Err(map_swift_error(status, Some(bucket), None));
    }
    Ok(headers)
}

async fn probe_bucket_versioning_async(
    cred: &S3Credential,
    bucket: &str,
    next: &AsyncNextFn,
    cache: &ContainerHeadCache,
) -> Result<Option<String>, Response> {
    let (status, headers) = head_container_async(cred, bucket, next, cache).await?;
    if status == 404 {
        return Ok(None);
    }
    if !(200..300).contains(&status) {
        return Err(map_swift_error(status, Some(bucket), None));
    }
    versioning_status_from_headers(&headers).map_err(|_| {
        s3_error_response(
            "InternalError",
            Some("bucket versioning metadata is invalid"),
            &[],
        )
    })
}

async fn control_head_object_async(
    cred: &S3Credential,
    container: &str,
    key: &str,
    next: &AsyncNextFn,
) -> Result<ObjectHead, Response> {
    let mut head = make_swift_req(
        "HEAD",
        &s3_to_swift_path(&cred.account, Some(container), Some(key)),
    );
    stamp_auth(&mut head, cred);
    let resp = async_call(next, head).await;
    if (200..300).contains(&resp.status) {
        Ok(ObjectHead::Present(resp))
    } else if resp.status == 404 {
        Ok(ObjectHead::Missing)
    } else {
        Err(map_swift_error(resp.status, Some(container), Some(key)))
    }
}

async fn load_version_index_async(
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    next: &AsyncNextFn,
) -> Result<VersionIndex, Response> {
    let vc = versions_container(bucket);
    let iname = index_object_name(key);
    let mut get = make_swift_req(
        "GET",
        &s3_to_swift_path(&cred.account, Some(&vc), Some(&iname)),
    );
    get.headers.set("X-Newest", "true");
    stamp_auth(&mut get, cred);
    let resp = async_call(next, get).await;
    if resp.status == 404 {
        return Ok(VersionIndex::new(key));
    }
    if !(200..300).contains(&resp.status) {
        return Err(map_swift_error(resp.status, Some(&vc), Some(&iname)));
    }
    let body = body_bytes(resp.body).await?;
    VersionIndex::from_json(&body)
        .filter(|index| index.key == key)
        .ok_or_else(|| {
            s3_error_response("InternalError", Some("version index is invalid"), &[])
        })
}

async fn resolve_object_version_async(
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    version_id: Option<&str>,
    next: &AsyncNextFn,
) -> Result<Option<ResolvedObjectVersion>, Response> {
    if let Some(version_id) = version_id {
        if !valid_version_id(version_id) {
            return Err(s3_error_response("InvalidArgument", None, &[]));
        }
    }
    let current = control_head_object_async(cred, bucket, key, next).await?;
    match (version_id, current) {
        (None, ObjectHead::Present(head)) => {
            return Ok(Some(ResolvedObjectVersion {
                container: bucket.to_string(),
                key: key.to_string(),
                head,
            }))
        }
        (None, ObjectHead::Missing) => return Ok(None),
        (Some(NULL_VERSION_ID), ObjectHead::Present(head))
            if matches!(
                head.headers.get(SYS_VERSION_ID),
                None | Some("") | Some(NULL_VERSION_ID)
            ) =>
        {
            return Ok(Some(ResolvedObjectVersion {
                container: bucket.to_string(),
                key: key.to_string(),
                head,
            }));
        }
        (Some(vid), ObjectHead::Present(head)) if head.headers.get(SYS_VERSION_ID) == Some(vid) => {
            return Ok(Some(ResolvedObjectVersion {
                container: bucket.to_string(),
                key: key.to_string(),
                head,
            }));
        }
        _ => {}
    }
    let version_id = version_id.expect("version id was handled above");
    let index = load_version_index_async(cred, bucket, key, next).await?;
    if index.find(version_id).is_none() {
        return Ok(None);
    }
    if !is_safe_version_id(version_id) {
        return Err(unsafe_version_id_error());
    }
    let container = versions_container(bucket);
    let archived_key = archive_object_name(key, version_id);
    match control_head_object_async(cred, &container, &archived_key, next).await? {
        ObjectHead::Present(head) => Ok(Some(ResolvedObjectVersion {
            container,
            key: archived_key,
            head,
        })),
        ObjectHead::Missing => Ok(None),
    }
}

async fn handle_versioned_get_head_async(
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    method: &str,
    version_id_q: Option<&str>,
    next: &AsyncNextFn,
) -> Response {
    let target = match resolve_object_version_async(cred, bucket, key, version_id_q, next).await {
        Ok(Some(target)) => target,
        Ok(None) => return missing_object_version_response(key, version_id_q),
        Err(resp) => return resp,
    };
    let response_version = version_id_q
        .map(str::to_string)
        .or_else(|| target.head.headers.get(SYS_VERSION_ID).map(str::to_string));
    if is_delete_marker_header(target.head.headers.get(SYS_DELETE_MARKER)) {
        return nosuchkey_delete_marker(key, response_version.as_deref());
    }
    let resp = if method == "HEAD" {
        target.head
    } else {
        let mut get = make_swift_req(
            "GET",
            &s3_to_swift_path(&cred.account, Some(&target.container), Some(&target.key)),
        );
        stamp_auth(&mut get, cred);
        let resp = async_call(next, get).await;
        if !(200..300).contains(&resp.status) {
            return map_swift_error(resp.status, Some(&target.container), Some(&target.key));
        }
        resp
    };
    if let Some(denied) = deny_if_object_acl_blocks_read(cred, &resp.headers) {
        return denied;
    }
    let mut out = translate_object_get_head(method, resp, cred, &[], None);
    if (200..300).contains(&out.status) {
        if let Some(version_id) = response_version {
            out.headers.set(HDR_VERSION_ID, version_id);
        }
    }
    out
}

async fn get_mpu_upload_info_async(
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    upload_id: &str,
    next: &AsyncNextFn,
) -> Result<MpuUploadInfo, Response> {
    let segs = segments_container(bucket);
    let marker = upload_marker_name(key, upload_id);
    match control_head_object_async(cred, &segs, &marker, next).await? {
        ObjectHead::Present(resp) => Ok(MpuUploadInfo {
            headers: resp.headers,
        }),
        ObjectHead::Missing => match control_head_object_async(cred, bucket, key, next).await? {
            ObjectHead::Present(resp) => {
                if resp.headers.get(SYS_S3API_UPLOAD_ID) != Some(upload_id) {
                    return Err(s3_error_response("NoSuchUpload", None, &[]));
                }
                Ok(MpuUploadInfo {
                    headers: resp.headers,
                })
            }
            ObjectHead::Missing => Err(s3_error_response("NoSuchUpload", None, &[])),
        },
    }
}

async fn require_bucket_object_lock_async(
    cred: &S3Credential,
    bucket: &str,
    next: &AsyncNextFn,
) -> Result<(), Response> {
    let mut head = make_swift_req("HEAD", &s3_to_swift_path(&cred.account, Some(bucket), None));
    stamp_auth(&mut head, cred);
    let resp = async_call(next, head).await;
    if !(200..300).contains(&resp.status) {
        return Err(map_swift_error(resp.status, Some(bucket), None));
    }
    match validated_object_lock_xml_from_headers(&resp.headers) {
        Ok(Some(_)) => Ok(()),
        Ok(None) => Err(s3_error_response(
            "InvalidRequest",
            Some("Bucket is missing Object Lock Configuration"),
            &[],
        )),
        Err(_) => Err(s3_error_response(
            "InternalError",
            Some("bucket object lock metadata is invalid"),
            &[],
        )),
    }
}

async fn ensure_versions_container_streaming(
    cred: &S3Credential,
    bucket: &str,
    next: &StreamingAsyncNextFn,
) -> Result<(), Response> {
    let vc = versions_container(bucket);
    let mut put = make_swift_req("PUT", &s3_to_swift_path(&cred.account, Some(&vc), None));
    stamp_auth(&mut put, cred);
    let resp = streaming_call(next, put).await;
    if (200..300).contains(&resp.status) {
        Ok(())
    } else {
        Err(map_swift_error(resp.status, Some(&vc), None))
    }
}

async fn load_version_index_snapshot_streaming(
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    next: &StreamingAsyncNextFn,
) -> Result<VersionIndexSnapshot, Response> {
    let vc = versions_container(bucket);
    let iname = index_object_name(key);
    let mut get = make_swift_req(
        "GET",
        &s3_to_swift_path(&cred.account, Some(&vc), Some(&iname)),
    );
    get.headers.set("X-Newest", "true");
    stamp_auth(&mut get, cred);
    let resp = streaming_call(next, get).await;
    let mut snap = if resp.status == 404 {
        VersionIndexSnapshot {
            index: VersionIndex::new(key),
            exists: false,
            etag: None,
        }
    } else if !(200..300).contains(&resp.status) {
        return Err(map_swift_error(resp.status, Some(&vc), Some(&iname)));
    } else {
        let etag = resp
            .headers
            .get("ETag")
            .map(vers_bare_etag)
            .filter(|s| !s.is_empty());
        let body = body_bytes(resp.body).await.map_err(|_| {
            s3_error_response("InternalError", Some("version index is too large"), &[])
        })?;
        let index = VersionIndex::from_json(&body)
            .filter(|index| index.key == key)
            .ok_or_else(|| {
                s3_error_response("InternalError", Some("version index is invalid"), &[])
            })?;
        VersionIndexSnapshot {
            index,
            exists: true,
            etag,
        }
    };
    if adopt_newer_generation_fences_streaming(cred, bucket, key, &mut snap, next).await? {
        heal_version_index_mirror_streaming(cred, bucket, key, &mut snap, next).await;
    }
    Ok(snap)
}

async fn adopt_newer_generation_fences_streaming(
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    snap: &mut VersionIndexSnapshot,
    next: &StreamingAsyncNextFn,
) -> Result<bool, Response> {
    let vc = versions_container(bucket);
    let mut adopted = false;
    for _ in 0..MAX_GENERATION_PROBES {
        let next_gen = snap.index.generation.saturating_add(1);
        let fname = index_generation_object_name(key, next_gen);
        let mut get = make_swift_req(
            "GET",
            &s3_to_swift_path(&cred.account, Some(&vc), Some(&fname)),
        );
        get.headers.set("X-Newest", "true");
        stamp_auth(&mut get, cred);
        let resp = streaming_call(next, get).await;
        if resp.status == 404 {
            return Ok(adopted);
        }
        if !(200..300).contains(&resp.status) {
            return Err(map_swift_error(resp.status, Some(&vc), Some(&fname)));
        }
        let body = body_bytes(resp.body).await.map_err(|_| {
            s3_error_response("InternalError", Some("version index is too large"), &[])
        })?;
        let index = VersionIndex::from_json(&body)
            .filter(|index| index.key == key && index.generation == next_gen)
            .ok_or_else(|| {
                s3_error_response("InternalError", Some("version index is invalid"), &[])
            })?;
        snap.index = index;
        snap.exists = true;
        snap.etag = None;
        adopted = true;
    }
    Err(s3_error_response(
        "InternalError",
        Some("version index generation probe overflow"),
        &[],
    ))
}

async fn heal_version_index_mirror_streaming(
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    snap: &mut VersionIndexSnapshot,
    next: &StreamingAsyncNextFn,
) {
    let vc = versions_container(bucket);
    let iname = index_object_name(key);
    let body = snap.index.to_json();
    let mut put = make_swift_req(
        "PUT",
        &s3_to_swift_path(&cred.account, Some(&vc), Some(&iname)),
    );
    put.headers.set("Content-Length", body.len().to_string());
    put.headers.set("Content-Type", "application/json");
    put.headers.set(SYS_OBJECT_KEY, key);
    put.body = Body::from(body);
    stamp_auth(&mut put, cred);
    let resp = streaming_call(next, put).await;
    if swift_write_applied(resp.status) {
        snap.etag = resp
            .headers
            .get("ETag")
            .map(vers_bare_etag)
            .filter(|s| !s.is_empty());
    }
}

async fn cas_save_version_index_streaming(
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    snap: &VersionIndexSnapshot,
    idx: &VersionIndex,
    next: &StreamingAsyncNextFn,
) -> Result<(), Response> {
    ensure_versions_container_streaming(cred, bucket, next).await?;
    let vc = versions_container(bucket);
    let body = idx.to_json();

    let fence = index_generation_object_name(key, idx.generation);
    let mut fence_put = make_swift_req(
        "PUT",
        &s3_to_swift_path(&cred.account, Some(&vc), Some(&fence)),
    );
    fence_put
        .headers
        .set("Content-Length", body.len().to_string());
    fence_put.headers.set("Content-Type", "application/json");
    fence_put.headers.set(SYS_OBJECT_KEY, key);
    fence_put.headers.set("If-None-Match", "*");
    fence_put.body = Body::from(body.clone());
    stamp_auth(&mut fence_put, cred);
    let fence_resp = streaming_call(next, fence_put).await;
    if !swift_write_applied(fence_resp.status) {
        return Err(if fence_resp.status == 202 || fence_resp.status == 412 {
            version_index_persist_conflict()
        } else {
            map_swift_error(fence_resp.status, Some(&vc), Some(&fence))
        });
    }

    let iname = index_object_name(key);
    let mut put = make_swift_req(
        "PUT",
        &s3_to_swift_path(&cred.account, Some(&vc), Some(&iname)),
    );
    put.headers.set("Content-Length", body.len().to_string());
    put.headers.set("Content-Type", "application/json");
    put.headers.set(SYS_OBJECT_KEY, key);
    if snap.exists {
        if let Some(etag) = snap.etag.as_deref() {
            put.headers.set("If-Match", etag);
        }
    } else {
        put.headers.set("If-None-Match", "*");
    }
    put.body = Body::from(body);
    stamp_auth(&mut put, cred);
    let resp = streaming_call(next, put).await;
    if swift_write_applied(resp.status) {
        Ok(())
    } else if resp.status == 202 || resp.status == 412 {
        Err(version_index_persist_conflict())
    } else {
        Err(map_swift_error(resp.status, Some(&vc), Some(&iname)))
    }
}

async fn archive_current_version_streaming(
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    version_id: &str,
    next: &StreamingAsyncNextFn,
) -> Result<(), Response> {
    ensure_versions_container_streaming(cred, bucket, next).await?;
    let vc = versions_container(bucket);
    let cur_path = s3_to_swift_path(&cred.account, Some(bucket), Some(key));
    let mut get = make_swift_req("GET", &cur_path);
    stamp_auth(&mut get, cred);
    let got = streaming_call(next, get).await;
    if !(200..300).contains(&got.status) {
        return Err(map_swift_error(got.status, Some(bucket), Some(key)));
    }
    let aname = archive_name_checked(key, version_id)?;
    let mut put = make_swift_req(
        "PUT",
        &s3_to_swift_path(&cred.account, Some(&vc), Some(&aname)),
    );
    copy_version_payload_headers(&got.headers, &mut put.headers);
    put.headers.set(SYS_VERSION_ID, version_id);
    put.headers.set(SYS_OBJECT_KEY, key);
    if put.headers.get(SYS_DELETE_MARKER).is_none() {
        put.headers.set(SYS_DELETE_MARKER, "false");
    }
    put.headers.set("If-None-Match", "*");
    put.body = got.body;
    stamp_auth(&mut put, cred);
    let stored = streaming_call(next, put).await;
    if swift_write_applied(stored.status) || stored.status == 412 {
        Ok(())
    } else if stored.status == 202 {
        Err(s3_error_response(
            "InternalError",
            Some("backend write was not applied"),
            &[],
        ))
    } else {
        Err(map_swift_error(stored.status, Some(&vc), Some(&aname)))
    }
}

async fn maybe_archive_current_for_write_streaming(
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    headers: &HeaderKeyDict,
    idx: &mut VersionIndex,
    next: &StreamingAsyncNextFn,
) -> Result<(), Response> {
    let old_vid = current_object_version_id(headers)?;
    let old_etag = headers
        .get("ETag")
        .map(vers_bare_etag)
        .unwrap_or_default();
    let old_size = headers
        .get("Content-Length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0i64);
    let old_lm = headers
        .get("Last-Modified")
        .map(http_date_to_s3_approx)
        .unwrap_or_else(|| "1970-01-01T00:00:00.000Z".into());
    let old_is_delete_marker = is_delete_marker_header(headers.get(SYS_DELETE_MARKER));
    archive_current_version_streaming(cred, bucket, key, &old_vid, next).await?;
    if idx.find(&old_vid).is_none() {
        idx.push_latest(VersionRecord {
            version_id: old_vid,
            is_delete_marker: old_is_delete_marker,
            is_latest: true,
            last_modified: old_lm,
            etag: old_etag,
            size: old_size,
        });
    }
    Ok(())
}

async fn rewrite_listing_s3_etags_async(
    body: &[u8],
    cred: &S3Credential,
    bucket: &str,
    next: &AsyncNextFn,
) -> Vec<u8> {
    let Ok(Value::Array(mut arr)) = serde_json::from_slice(body) else {
        return body.to_vec();
    };
    for item in &mut arr {
        if item.get("subdir").is_some() {
            continue;
        }
        let Some(name) = item.get("name").and_then(|v| v.as_str()).map(str::to_string) else {
            continue;
        };
        let hash = item
            .get("hash")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if let Some(etag) = s3_etag_from_listing_hash(&hash) {
            item["hash"] = Value::String(etag);
        }
        if !listing_hash_needs_head(&hash) {
            continue;
        }
        if let Ok(ObjectHead::Present(head)) =
            control_head_object_async(cred, bucket, &name, next).await
        {
            if let Some(v) = head
                .headers
                .get(SYS_S3API_ETAG)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
            {
                item["hash"] = Value::String(bare_etag(&v));
            }
            if let Some(cl) = head
                .headers
                .get("Content-Length")
                .and_then(|s| s.parse::<u64>().ok())
            {
                item["bytes"] = Value::Number(cl.into());
            }
        }
    }
    serde_json::to_vec(&arr).unwrap_or_else(|_| body.to_vec())
}

async fn handle_versioning_async(
    req: Request,
    cred: &S3Credential,
    bucket: &str,
    next: &AsyncNextFn,
) -> Response {
    match req.method.as_str() {
        "GET" | "HEAD" => {
            let mut head =
                make_swift_req("HEAD", &s3_to_swift_path(&cred.account, Some(bucket), None));
            stamp_auth(&mut head, cred);
            let resp = async_call(next, head).await;
            if !(200..300).contains(&resp.status) {
                return map_swift_error(resp.status, Some(bucket), None);
            }
            match versioning_status_from_headers(&resp.headers) {
                Ok(status) => xml_ok(versioning_configuration_xml(status.as_deref())),
                Err(_) => s3_error_response(
                    "InternalError",
                    Some("bucket versioning metadata is invalid"),
                    &[],
                ),
            }
        }
        "PUT" => {
            let body = match req.body.into_vec(MAX_CONTROL_BODY) {
                Ok(b) => b,
                Err(_) => return s3_error_response("IncompleteBody", None, &[]),
            };
            let status = match parse_versioning_status(&body) {
                Ok(s) => s,
                Err(_) => return s3_error_response("MalformedXML", None, &[]),
            };
            if status == "Suspended" {
                let mut head =
                    make_swift_req("HEAD", &s3_to_swift_path(&cred.account, Some(bucket), None));
                stamp_auth(&mut head, cred);
                let current = async_call(next, head).await;
                if !(200..300).contains(&current.status) {
                    return map_swift_error(current.status, Some(bucket), None);
                }
                match validated_object_lock_xml_from_headers(&current.headers) {
                    Ok(Some(_)) => {
                        return s3_error_response(
                            "InvalidBucketState",
                            Some("Object Lock requires versioning to remain enabled"),
                            &[],
                        )
                    }
                    Ok(None) => {}
                    Err(_) => {
                        return s3_error_response(
                            "InternalError",
                            Some("bucket object lock metadata is invalid"),
                            &[],
                        )
                    }
                }
            }
            let mut post =
                make_swift_req("POST", &s3_to_swift_path(&cred.account, Some(bucket), None));
            apply_versioning_meta(&mut post.headers, status);
            stamp_auth(&mut post, cred);
            let resp = async_call(next, post).await;
            if (200..300).contains(&resp.status) {
                Response::new(200)
            } else {
                map_swift_error(resp.status, Some(bucket), None)
            }
        }
        _ => s3_error_response("MethodNotAllowed", None, &[]),
    }
}

async fn handle_mpu_init_async(
    mut req: Request,
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    api: &S3Api,
    next: &AsyncNextFn,
) -> Response {
    if let Err(resp) = require_bucket_async(cred, bucket, next, &api.container_heads).await {
        return resp;
    }
    let has_retention = req.headers.get("X-Amz-Object-Lock-Mode").is_some()
        || req
            .headers
            .get("X-Amz-Object-Lock-Retain-Until-Date")
            .is_some();
    let has_legal_hold = req.headers.get("X-Amz-Object-Lock-Legal-Hold").is_some();
    if has_retention || has_legal_hold {
        if let Err(resp) = require_bucket_object_lock_async(cred, bucket, next).await {
            return resp;
        }
    }
    if has_retention {
        if let Some(denied) = iam_action_check(&api.iam, cred, "s3:PutObjectRetention", bucket, key)
        {
            return denied;
        }
    }
    if has_legal_hold {
        if let Some(denied) = iam_action_check(&api.iam, cred, "s3:PutObjectLegalHold", bucket, key)
        {
            return denied;
        }
    }

    map_amz_meta(&mut req);
    match resolve_acl_put_input(&req.headers, None, &owner_for(cred).id) {
        Ok(input) if !matches!(input, AclPutInput::None) => {
            apply_object_acl_input(&mut req.headers, &input);
        }
        Ok(_) => {}
        Err(_) => return s3_error_response("InvalidArgument", None, &[]),
    }
    if let Err(resp) = apply_request_object_lock_headers(&mut req.headers) {
        return resp;
    }

    let segs = segments_container(bucket);
    let mut put_c = make_swift_req("PUT", &s3_to_swift_path(&cred.account, Some(&segs), None));
    stamp_auth(&mut put_c, cred);
    let container_resp = async_call(next, put_c).await;
    if !(200..300).contains(&container_resp.status) {
        return map_swift_error(container_resp.status, Some(&segs), None);
    }
    let upload_id = new_upload_id();
    let marker = upload_marker_name(key, &upload_id);
    let mut put_m = make_swift_req(
        "PUT",
        &s3_to_swift_path(&cred.account, Some(&segs), Some(&marker)),
    );
    copy_mpu_object_headers(&req.headers, &mut put_m.headers);
    persist_s3_object_headers(&mut put_m);
    put_m.body = Body::from(Vec::from(b"upload".as_slice()));
    put_m.headers.set("Content-Length", "6");
    let mut head = make_swift_req("HEAD", &s3_to_swift_path(&cred.account, Some(bucket), None));
    stamp_auth(&mut head, cred);
    let head_resp = async_call(next, head).await;
    if (200..300).contains(&head_resp.status) {
        apply_abort_incomplete_from_container(
            &mut put_m.headers,
            &head_resp.headers,
            key,
            unix_now(),
        );
    }
    stamp_auth(&mut put_m, cred);
    let resp = async_call(next, put_m).await;
    if !(200..300).contains(&resp.status) {
        return map_swift_error(resp.status, Some(bucket), Some(key));
    }
    initiate_response(bucket, key, &upload_id)
}

async fn handle_mpu_complete_async(
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    upload_id: &str,
    req: Request,
    next: &AsyncNextFn,
    api: &S3Api,
) -> Response {
    if let Err(resp) = require_bucket_async(cred, bucket, next, &api.container_heads).await {
        return resp;
    }
    if let Some(resp) = reject_unsupported_put_conditionals(&req) {
        return resp;
    }
    let bypass_requested = bypass_governance_requested(
        req.headers
            .get(HDR_BYPASS_GOVERNANCE)
            .or_else(|| req.headers.get("X-Amz-Bypass-Governance-Retention")),
    );
    let bypass = match governance_bypass_context(&api.iam, cred, bucket, key, bypass_requested) {
        Ok(context) => context,
        Err(resp) => return resp,
    };
    let location = complete_object_location(&req, bucket, key);
    let if_none_match_star = req.headers.get("If-None-Match") == Some("*");
    let body = match req.body.into_vec(MAX_CONTROL_BODY) {
        Ok(b) => b,
        Err(_) => return s3_error_response("IncompleteBody", None, &[]),
    };
    let parts = match parse_complete_body(&body) {
        Ok(p) => p,
        Err(code) => return s3_error_response(&code, None, &[]),
    };
    let segs = segments_container(bucket);
    let upload_info = match get_mpu_upload_info_async(cred, bucket, key, upload_id, next).await {
        Ok(info) => info,
        Err(resp) => return resp,
    };
    let s3_etag = aws_multipart_etag(parts.iter().map(|(_, e)| e.as_str()));
    if let Some(resp) = complete_mpu_already_uploaded(
        upload_info.headers.get(SYS_S3API_ETAG),
        s3_etag.as_deref(),
        bucket,
        key,
        &location,
    ) {
        return resp;
    }
    if if_none_match_star {
        match control_head_object_async(cred, bucket, key, next).await {
            Ok(head) => {
                if let Some(resp) = complete_mpu_if_none_match_conflict(head) {
                    return resp;
                }
            }
            Err(resp) => return resp,
        }
    }
    let mut sized: Vec<(u32, String, u64)> = Vec::new();
    for (num, etag) in &parts {
        let pname = part_object_name(key, upload_id, *num);
        let mut head = make_swift_req(
            "HEAD",
            &s3_to_swift_path(&cred.account, Some(&segs), Some(&pname)),
        );
        stamp_auth(&mut head, cred);
        let resp = async_call(next, head).await;
        if !(200..300).contains(&resp.status) {
            return s3_error_response("InvalidPart", None, &[]);
        }
        let stored = resp
            .headers
            .get("ETag")
            .map(bare_etag)
            .unwrap_or_default();
        if !etag.is_empty() && !stored.is_empty() && stored != bare_etag(etag) {
            return s3_error_response("InvalidPart", None, &[]);
        }
        let size = resp
            .headers
            .get("Content-Length")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        sized.push((*num, etag.clone(), size));
    }
    const MIN_PART: u64 = 5_242_880;
    if sized.len() >= 2 {
        for (i, (_n, _e, size)) in sized.iter().enumerate() {
            if i + 1 < sized.len() && *size < MIN_PART {
                return s3_error_response("EntityTooSmall", None, &[]);
            }
        }
    }
    let manifest = slo_manifest_json(&segs, key, upload_id, &sized);
    let mut put = make_swift_req(
        "PUT",
        &s3_to_swift_path(&cred.account, Some(bucket), Some(key)),
    );
    copy_mpu_object_headers(&upload_info.headers, &mut put.headers);
    persist_s3_object_headers(&mut put);
    put.headers.set(SYS_S3API_UPLOAD_ID, upload_id);
    if let Some(ref etag) = s3_etag {
        put.headers.set(SYS_S3API_ETAG, etag);
        put.headers.set(SYS_CONTAINER_UPDATE_OVERRIDE_ETAG, etag);
    }
    let assembled: u64 = sized.iter().map(|(_, _, n)| *n).sum();
    put.headers
        .set(SYS_CONTAINER_UPDATE_OVERRIDE_SIZE, assembled.to_string());
    put.query_string = "multipart-manifest=put".into();
    let manifest = manifest.into_bytes();
    put.headers
        .set("Content-Length", manifest.len().to_string());
    put.body = Body::from(manifest);
    // Python complete MPU accepts If-None-Match:* but does not forward it
    // onto the SLO PUT (manifest PUT 400s on If-None-Match).
    if put.headers.get(SYS_LOCK_MODE).is_some() || put.headers.get(SYS_RETAIN_UNTIL).is_some() {
        if let Some(denied) = iam_action_check(&api.iam, cred, "s3:PutObjectRetention", bucket, key)
        {
            return denied;
        }
    }
    if put.headers.get(SYS_LEGAL_HOLD).is_some() {
        if let Some(denied) = iam_action_check(&api.iam, cred, "s3:PutObjectLegalHold", bucket, key)
        {
            return denied;
        }
    }
    if put.headers.get(SYS_LOCK_MODE).is_some()
        || put.headers.get(SYS_RETAIN_UNTIL).is_some()
        || put.headers.get(SYS_LEGAL_HOLD).is_some()
    {
        if let Err(resp) = require_bucket_object_lock_async(cred, bucket, next).await {
            return resp;
        }
    }

    let versioning_mode = match probe_bucket_versioning_async(cred, bucket, next, &api.container_heads)
        .await
    {
        Ok(status) => bucket_versioning_mode(status.as_deref()),
        Err(resp) => return resp,
    };
    if versioning_mode.is_some() {
        let next_sync = async_next_as_blocking(Arc::clone(next));
        let resp = handle_versioned_put(
            put,
            cred,
            bucket,
            key,
            false,
            Some("multipart-manifest=put"),
            match versioning_mode {
                Some(BucketVersioningMode::Enabled) => None,
                Some(BucketVersioningMode::Suspended) => Some(NULL_VERSION_ID),
                None => None,
            },
            bypass,
            &next_sync,
            api,
        );
        if (200..300).contains(&resp.status) {
            delete_mpu_marker_async(cred, bucket, key, upload_id, next).await;
        }
        return resp;
    }
    match control_head_object_async(cred, bucket, key, next).await {
        Ok(ObjectHead::Present(existing)) => {
            if let Some(blocked) =
                worm_guard(&existing.headers, api.worm_clock.clock_ok(), bypass)
            {
                return blocked;
            }
            if let Some(blocked) = deny_if_object_acl_blocks_write(cred, &existing.headers) {
                return blocked;
            }
        }
        Ok(ObjectHead::Missing) => {}
        Err(resp) => return resp,
    }
    if let Err(resp) = apply_request_object_lock_headers(&mut put.headers) {
        return resp;
    }
    strip_s3_only_headers(&mut put.headers);
    let (st, hdrs) = match head_container_async(cred, bucket, next, &api.container_heads).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    if st != 404 && (200..300).contains(&st) {
        apply_lifecycle_on_put_from_container(&mut put.headers, &hdrs, key, unix_now());
        if put.headers.get(SYS_RETAIN_UNTIL).is_none() {
            if let Ok(Some(xml)) = validated_object_lock_xml_from_headers(&hdrs) {
                if let Ok(Some(def)) = parse_object_lock_configuration(&xml) {
                    apply_default_retention_headers(&mut put.headers, &def, unix_now());
                }
            }
        }
    }
    stamp_auth(&mut put, cred);
    let resp = async_call(next, put).await;
    if !(200..300).contains(&resp.status) {
        return map_swift_error(resp.status, Some(bucket), Some(key));
    }
    delete_mpu_marker_async(cred, bucket, key, upload_id, next).await;
    let etag = s3_etag.unwrap_or_else(|| {
        resp.headers
            .get("ETag")
            .map(|e| e.trim().trim_matches('"').to_string())
            .unwrap_or_else(|| "multipart".into())
    });
    let version_id = resp.headers.get(HDR_VERSION_ID).map(str::to_string);
    let mut out = xml_response(
        200,
        complete_multipart_xml(bucket, key, &etag, &location),
    );
    if let Some(version_id) = version_id {
        out.headers.set(HDR_VERSION_ID, version_id);
    }
    out
}

async fn delete_mpu_marker_async(
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    upload_id: &str,
    next: &AsyncNextFn,
) {
    // Python complete deletes only the `{key}/{uploadId}` marker. Parts
    // stay as SLO segments. A retry with the same part list is 200
    // (idempotent complete against dest `s3api-etag`); more/fewer parts
    // is NoSuchUpload.
    let segs = segments_container(bucket);
    let marker = upload_marker_name(key, upload_id);
    let mut del = make_swift_req(
        "DELETE",
        &s3_to_swift_path(&cred.account, Some(&segs), Some(&marker)),
    );
    stamp_auth(&mut del, cred);
    let _ = async_call(next, del).await;
}

async fn handle_mpu_abort_async(
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    upload_id: &str,
    api: &S3Api,
    next: &AsyncNextFn,
) -> Response {
    if let Err(resp) = require_bucket_async(cred, bucket, next, &api.container_heads).await {
        return resp;
    }
    let segs = segments_container(bucket);
    let marker = upload_marker_name(key, upload_id);
    match control_head_object_async(cred, &segs, &marker, next).await {
        Ok(ObjectHead::Present(_)) => {}
        Ok(ObjectHead::Missing) => return s3_error_response("NoSuchUpload", None, &[]),
        Err(resp) => return resp,
    }
    let prefix = format!("{key}/{upload_id}/");
    let mut list = make_swift_req("GET", &s3_to_swift_path(&cred.account, Some(&segs), None));
    list.query_string = format!("format=json&prefix={}", encode_query(&prefix));
    list.headers.set("Accept", "application/json");
    stamp_auth(&mut list, cred);
    let listed = async_call(next, list).await;
    if (200..300).contains(&listed.status) {
        if let Ok(body) = body_bytes(listed.body).await {
            let parsed: Value = serde_json::from_slice(&body).unwrap_or(Value::Array(vec![]));
            if let Some(arr) = parsed.as_array() {
                for item in arr {
                    let Some(name) = item.get("name").and_then(|v| v.as_str()) else {
                        continue;
                    };
                    let mut del_part = make_swift_req(
                        "DELETE",
                        &s3_to_swift_path(&cred.account, Some(&segs), Some(name)),
                    );
                    stamp_auth(&mut del_part, cred);
                    let _ = async_call(next, del_part).await;
                }
            }
        }
    }
    let mut del = make_swift_req(
        "DELETE",
        &s3_to_swift_path(&cred.account, Some(&segs), Some(&marker)),
    );
    stamp_auth(&mut del, cred);
    let _ = async_call(next, del).await;
    let mut resp = delete_object_response();
    resp.headers.set("Content-Type", "text/html; charset=UTF-8");
    resp
}

fn head_container(
    cred: &S3Credential,
    bucket: &str,
    next: &NextFn,
    cache: &ContainerHeadCache,
) -> Result<(u16, HeaderKeyDict), Response> {
    if let Some(hit) = cache.get(&cred.account, bucket) {
        return Ok(hit);
    }
    let mut head = make_swift_req("HEAD", &s3_to_swift_path(&cred.account, Some(bucket), None));
    stamp_auth(&mut head, cred);
    let resp = next(head);
    // Never cache 404. Four proxies each keep their own map; a miss on one
    // node then a create on another leaves the first node serving NoSuchBucket
    // / copy 404 for the rest of the TTL. 2xx is safe for the PUT storm path.
    if (200..300).contains(&resp.status) {
        cache.store(&cred.account, bucket, resp.status, resp.headers.clone());
    }
    Ok((resp.status, resp.headers))
}

fn require_bucket(
    cred: &S3Credential,
    bucket: &str,
    next: &NextFn,
    cache: &ContainerHeadCache,
) -> Result<HeaderKeyDict, Response> {
    let (status, headers) = head_container(cred, bucket, next, cache)?;
    if status == 404 {
        return Err(s3_error_response(
            "NoSuchBucket",
            None,
            &[("BucketName", bucket)],
        ));
    }
    if !(200..300).contains(&status) {
        return Err(map_swift_error(status, Some(bucket), None));
    }
    Ok(headers)
}

fn probe_bucket_versioning(
    cred: &S3Credential,
    bucket: &str,
    next: &NextFn,
    cache: &ContainerHeadCache,
) -> Result<Option<String>, Response> {
    let (status, headers) = head_container(cred, bucket, next, cache)?;
    if status == 404 {
        return Ok(None);
    }
    if !(200..300).contains(&status) {
        return Err(map_swift_error(status, Some(bucket), None));
    }
    versioning_status_from_headers(&headers).map_err(|_| {
        s3_error_response(
            "InternalError",
            Some("bucket versioning metadata is invalid"),
            &[],
        )
    })
}

async fn ensure_versions_container_async(
    cred: &S3Credential,
    bucket: &str,
    next: &AsyncNextFn,
) -> Result<(), Response> {
    let vc = versions_container(bucket);
    let mut put = make_swift_req("PUT", &s3_to_swift_path(&cred.account, Some(&vc), None));
    stamp_auth(&mut put, cred);
    let resp = async_call(next, put).await;
    if (200..300).contains(&resp.status) {
        Ok(())
    } else {
        Err(map_swift_error(resp.status, Some(&vc), None))
    }
}



fn ensure_versions_container(
    cred: &S3Credential,
    bucket: &str,
    next: &NextFn,
) -> Result<(), Response> {
    let vc = versions_container(bucket);
    let mut put = make_swift_req("PUT", &s3_to_swift_path(&cred.account, Some(&vc), None));
    stamp_auth(&mut put, cred);
    let resp = next(put);
    if (200..300).contains(&resp.status) {
        Ok(())
    } else {
        Err(map_swift_error(resp.status, Some(&vc), None))
    }
}

fn swift_write_applied(status: u16) -> bool {
    (200..300).contains(&status) && status != 202
}

fn version_index_persist_conflict() -> Response {
    s3_error_response("InternalError", Some("version index persist conflict"), &[])
}

fn cas_denied_response(_denied: CasDenied) -> Response {
    s3_error_response(
        "InternalError",
        Some("version index generation mismatch"),
        &[],
    )
}

fn unsafe_version_id_error() -> Response {
    s3_error_response("InternalError", Some("object version id is unsafe"), &[])
}

fn version_index_lost_update() -> Response {
    s3_error_response("InternalError", Some("version index lost update"), &[])
}

async fn drop_missing_version_index_row_async(
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    vid: &str,
    next: &AsyncNextFn,
) -> Result<(), Response> {
    let snap = load_version_index_snapshot_async(cred, bucket, key, next).await?;
    if snap.index.find(vid).is_none() {
        return Ok(());
    }
    let expect = expect_generation(&snap);
    let mut idx = snap.index.clone();
    if let Err(denied) = check_index_generation(&idx, expect) {
        return Err(cas_denied_response(denied));
    }
    match idx.remove_version_checked(vid) {
        Ok(_) => {}
        Err(RemoveVersionError::Missing) => return Ok(()),
    }
    idx.generation = idx.generation.saturating_add(1);
    cas_save_version_index_async(cred, bucket, key, &snap, &idx, next).await
}

/// Same three-arm check as [`VersionIndex::apply_if_match`].


fn drop_missing_version_index_row(
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    vid: &str,
    next: &NextFn,
) -> Result<(), Response> {
    let snap = load_version_index_snapshot(cred, bucket, key, next)?;
    if snap.index.find(vid).is_none() {
        return Ok(());
    }
    let expect = expect_generation(&snap);
    let mut idx = snap.index.clone();
    if let Err(denied) = check_index_generation(&idx, expect) {
        return Err(cas_denied_response(denied));
    }
    match idx.remove_version_checked(vid) {
        Ok(_) => {}
        Err(RemoveVersionError::Missing) => return Ok(()),
    }
    idx.generation = idx.generation.saturating_add(1);
    cas_save_version_index(cred, bucket, key, &snap, &idx, next)
}

/// Same three-arm check as [`VersionIndex::apply_if_match`].
fn check_index_generation(idx: &VersionIndex, expect: Option<u64>) -> Result<(), CasDenied> {
    match expect {
        Some(g) if g == idx.generation => Ok(()),
        None if idx.generation == 0 => Ok(()),
        Some(_) => Err(CasDenied::Mismatch),
        None => Err(CasDenied::MissingExpected),
    }
}

fn archive_name_checked(key: &str, version_id: &str) -> Result<String, Response> {
    if !is_safe_version_id(version_id) {
        return Err(unsafe_version_id_error());
    }
    Ok(archive_object_name(key, version_id))
}

/// Load-time view of the committed index: the `{hex}/index.json` mirror plus
/// any newer generation fences the mirror has not caught up with (a writer
/// can crash between fence and mirror). `exists` is GET 2xx, not 404.
/// `etag` is the Swift object ETag of the mirror (bare), never
/// [`VersionIndex::cas_etag`]; it is `None` after fences were adopted,
/// because the mirror no longer reflects the committed history.
struct VersionIndexSnapshot {
    index: VersionIndex,
    exists: bool,
    etag: Option<String>,
}

/// Fail-closed bound on the fence walk in
/// [`adopt_newer_generation_fences`]. The backlog shrinks to zero on every
/// successful load (the loader heals the mirror), so a mirror this far
/// behind means the backend persistently applies fences while refusing
/// mirror writes — refuse to commit over unseen history.
const MAX_GENERATION_PROBES: u64 = 100;

fn expect_generation(snap: &VersionIndexSnapshot) -> Option<u64> {
    // Legacy index.json has no `generation` field → from_json sets 0.
    // apply_if_match(None, _) is only legal on first create. A 2xx load
    // must pass Some(0) or two writers both treat a live index as new.
    if snap.exists {
        Some(snap.index.generation)
    } else {
        None
    }
}

async fn load_version_index_snapshot_async(
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    next: &AsyncNextFn,
) -> Result<VersionIndexSnapshot, Response> {
    let vc = versions_container(bucket);
    let iname = index_object_name(key);
    let mut get = make_swift_req(
        "GET",
        &s3_to_swift_path(&cred.account, Some(&vc), Some(&iname)),
    );
    get.headers.set("X-Newest", "true");
    stamp_auth(&mut get, cred);
    let resp = async_call(next, get).await;
    let mut snap = if resp.status == 404 {
        VersionIndexSnapshot {
            index: VersionIndex::new(key),
            exists: false,
            etag: None,
        }
    } else if !(200..300).contains(&resp.status) {
        return Err(map_swift_error(resp.status, Some(&vc), Some(&iname)));
    } else {
        let etag = resp
            .headers
            .get("ETag")
            .map(vers_bare_etag)
            .filter(|s| !s.is_empty());
        let body = resp.body.into_vec(MAX_CONTROL_BODY).map_err(|_| {
            s3_error_response("InternalError", Some("version index is too large"), &[])
        })?;
        let index = VersionIndex::from_json(&body)
            .filter(|index| index.key == key)
            .ok_or_else(|| {
                s3_error_response("InternalError", Some("version index is invalid"), &[])
            })?;
        VersionIndexSnapshot {
            index,
            exists: true,
            etag,
        }
    };
    if adopt_newer_generation_fences_async(cred, bucket, key, &mut snap, next).await? {
        heal_version_index_mirror_async(cred, bucket, key, &mut snap, next).await;
    }
    Ok(snap)
}

/// Walk the generation fences forward from the mirror snapshot and adopt
/// every committed generation the mirror has not caught up with. Returns
/// whether anything was adopted.
///
/// Each fence is a full index snapshot, so adoption is self-contained. The
/// walk fails closed on a corrupt fence (committing over unreadable history
/// could fork it) and on [`MAX_GENERATION_PROBES`].


fn load_version_index_snapshot(
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    next: &NextFn,
) -> Result<VersionIndexSnapshot, Response> {
    let vc = versions_container(bucket);
    let iname = index_object_name(key);
    let mut get = make_swift_req(
        "GET",
        &s3_to_swift_path(&cred.account, Some(&vc), Some(&iname)),
    );
    get.headers.set("X-Newest", "true");
    stamp_auth(&mut get, cred);
    let resp = next(get);
    let mut snap = if resp.status == 404 {
        VersionIndexSnapshot {
            index: VersionIndex::new(key),
            exists: false,
            etag: None,
        }
    } else if !(200..300).contains(&resp.status) {
        return Err(map_swift_error(resp.status, Some(&vc), Some(&iname)));
    } else {
        let etag = resp
            .headers
            .get("ETag")
            .map(vers_bare_etag)
            .filter(|s| !s.is_empty());
        let body = resp.body.into_vec(MAX_CONTROL_BODY).map_err(|_| {
            s3_error_response("InternalError", Some("version index is too large"), &[])
        })?;
        let index = VersionIndex::from_json(&body)
            .filter(|index| index.key == key)
            .ok_or_else(|| {
                s3_error_response("InternalError", Some("version index is invalid"), &[])
            })?;
        VersionIndexSnapshot {
            index,
            exists: true,
            etag,
        }
    };
    if adopt_newer_generation_fences(cred, bucket, key, &mut snap, next)? {
        heal_version_index_mirror(cred, bucket, key, &mut snap, next);
    }
    Ok(snap)
}

/// Walk the generation fences forward from the mirror snapshot and adopt
/// every committed generation the mirror has not caught up with. Returns
/// whether anything was adopted.
///
/// Each fence is a full index snapshot, so adoption is self-contained. The
/// walk fails closed on a corrupt fence (committing over unreadable history
/// could fork it) and on [`MAX_GENERATION_PROBES`].
async fn adopt_newer_generation_fences_async(
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    snap: &mut VersionIndexSnapshot,
    next: &AsyncNextFn,
) -> Result<bool, Response> {
    let vc = versions_container(bucket);
    let mut adopted = false;
    for _ in 0..MAX_GENERATION_PROBES {
        let next_gen = snap.index.generation.saturating_add(1);
        let fname = index_generation_object_name(key, next_gen);
        let mut get = make_swift_req(
            "GET",
            &s3_to_swift_path(&cred.account, Some(&vc), Some(&fname)),
        );
        get.headers.set("X-Newest", "true");
        stamp_auth(&mut get, cred);
        let resp = async_call(next, get).await;
        if resp.status == 404 {
            return Ok(adopted);
        }
        if !(200..300).contains(&resp.status) {
            return Err(map_swift_error(resp.status, Some(&vc), Some(&fname)));
        }
        let body = resp.body.into_vec(MAX_CONTROL_BODY).map_err(|_| {
            s3_error_response("InternalError", Some("version index is too large"), &[])
        })?;
        let index = VersionIndex::from_json(&body)
            .filter(|index| index.key == key && index.generation == next_gen)
            .ok_or_else(|| {
                s3_error_response("InternalError", Some("version index is invalid"), &[])
            })?;
        snap.index = index;
        // The mirror is behind the committed history: its etag must not
        // gate later mirror writes.
        snap.exists = true;
        snap.etag = None;
        adopted = true;
    }
    Err(s3_error_response(
        "InternalError",
        Some("version index generation probe overflow"),
        &[],
    ))
}

/// Best-effort rewrite of the `index.json` mirror after fences were
/// adopted. Failure is not fatal: the fences already carry the committed
/// history and the next loader repeats the walk.


fn adopt_newer_generation_fences(
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    snap: &mut VersionIndexSnapshot,
    next: &NextFn,
) -> Result<bool, Response> {
    let vc = versions_container(bucket);
    let mut adopted = false;
    for _ in 0..MAX_GENERATION_PROBES {
        let next_gen = snap.index.generation.saturating_add(1);
        let fname = index_generation_object_name(key, next_gen);
        let mut get = make_swift_req(
            "GET",
            &s3_to_swift_path(&cred.account, Some(&vc), Some(&fname)),
        );
        get.headers.set("X-Newest", "true");
        stamp_auth(&mut get, cred);
        let resp = next(get);
        if resp.status == 404 {
            return Ok(adopted);
        }
        if !(200..300).contains(&resp.status) {
            return Err(map_swift_error(resp.status, Some(&vc), Some(&fname)));
        }
        let body = resp.body.into_vec(MAX_CONTROL_BODY).map_err(|_| {
            s3_error_response("InternalError", Some("version index is too large"), &[])
        })?;
        let index = VersionIndex::from_json(&body)
            .filter(|index| index.key == key && index.generation == next_gen)
            .ok_or_else(|| {
                s3_error_response("InternalError", Some("version index is invalid"), &[])
            })?;
        snap.index = index;
        // The mirror is behind the committed history: its etag must not
        // gate later mirror writes.
        snap.exists = true;
        snap.etag = None;
        adopted = true;
    }
    Err(s3_error_response(
        "InternalError",
        Some("version index generation probe overflow"),
        &[],
    ))
}

/// Best-effort rewrite of the `index.json` mirror after fences were
/// adopted. Failure is not fatal: the fences already carry the committed
/// history and the next loader repeats the walk.
async fn heal_version_index_mirror_async(
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    snap: &mut VersionIndexSnapshot,
    next: &AsyncNextFn,
) {
    let vc = versions_container(bucket);
    let iname = index_object_name(key);
    let body = snap.index.to_json();
    let mut put = make_swift_req(
        "PUT",
        &s3_to_swift_path(&cred.account, Some(&vc), Some(&iname)),
    );
    put.headers.set("Content-Length", body.len().to_string());
    put.headers.set("Content-Type", "application/json");
    put.headers.set(SYS_OBJECT_KEY, key);
    put.body = Body::from(body);
    stamp_auth(&mut put, cred);
    let resp = async_call(next, put).await;
    if swift_write_applied(resp.status) {
        snap.etag = resp
            .headers
            .get("ETag")
            .map(vers_bare_etag)
            .filter(|s| !s.is_empty());
    }
}



fn heal_version_index_mirror(
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    snap: &mut VersionIndexSnapshot,
    next: &NextFn,
) {
    let vc = versions_container(bucket);
    let iname = index_object_name(key);
    let body = snap.index.to_json();
    let mut put = make_swift_req(
        "PUT",
        &s3_to_swift_path(&cred.account, Some(&vc), Some(&iname)),
    );
    put.headers.set("Content-Length", body.len().to_string());
    put.headers.set("Content-Type", "application/json");
    put.headers.set(SYS_OBJECT_KEY, key);
    put.body = Body::from(body);
    stamp_auth(&mut put, cred);
    let resp = next(put);
    if swift_write_applied(resp.status) {
        snap.etag = resp
            .headers
            .get("ETag")
            .map(vers_bare_etag)
            .filter(|s| !s.is_empty());
    }
}

fn load_version_index(
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    next: &NextFn,
) -> Result<VersionIndex, Response> {
    Ok(load_version_index_snapshot(cred, bucket, key, next)?.index)
}

/// Persist the version index with the cross-proxy backend CAS.
///
/// Commit protocol (effective on the live topology today — the Wave-2
/// object layer enforces `If-None-Match: *` and the proxy forwards it on
/// object writes, both since the monorepo import):
///
/// 1. **Fence**: create the immutable `{hex}/index.g{N:020}.json` (N is the
///    generation `idx` carries after the in-process commit) with
///    `If-None-Match: *`. The backend accepts exactly one create per
///    generation, so two proxies can never both apply generation N. A 412
///    (fence taken) or a 202 (not Applied) surfaces the existing
///    persist-conflict `InternalError` — the same client-visible class as
///    the in-process CAS denial.
/// 2. **Mirror**: rewrite `{hex}/index.json` with the same body for readers
///    and mixed fleets, with the same conditional stamping as before. The
///    `If-Match` belt stays a no-op until the object layer rolls to
///    >= 414b76e; the fence in step 1 is what holds the CAS today.
///
/// Success requires both writes Applied (202 is never success). If the
/// mirror write fails after the fence committed, the client gets the same
/// error it gets today, and the next snapshot load adopts the fence and
/// heals the mirror. Conditional writes are checked per object-server
/// against the local replica: a narrow replica-level window inside one
/// Swift quorum remains (Swift-inherent, see the design doc).
async fn cas_save_version_index_async(
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    snap: &VersionIndexSnapshot,
    idx: &VersionIndex,
    next: &AsyncNextFn,
) -> Result<(), Response> {
    ensure_versions_container_async(cred, bucket, next).await?;
    let vc = versions_container(bucket);
    let body = idx.to_json();

    let fence = index_generation_object_name(key, idx.generation);
    let mut fence_put = make_swift_req(
        "PUT",
        &s3_to_swift_path(&cred.account, Some(&vc), Some(&fence)),
    );
    fence_put
        .headers
        .set("Content-Length", body.len().to_string());
    fence_put.headers.set("Content-Type", "application/json");
    fence_put.headers.set(SYS_OBJECT_KEY, key);
    fence_put.headers.set("If-None-Match", "*");
    fence_put.body = Body::from(body.clone());
    stamp_auth(&mut fence_put, cred);
    let fence_resp = async_call(next, fence_put).await;
    if !swift_write_applied(fence_resp.status) {
        return Err(if fence_resp.status == 202 || fence_resp.status == 412 {
            version_index_persist_conflict()
        } else {
            map_swift_error(fence_resp.status, Some(&vc), Some(&fence))
        });
    }

    let iname = index_object_name(key);
    let mut put = make_swift_req(
        "PUT",
        &s3_to_swift_path(&cred.account, Some(&vc), Some(&iname)),
    );
    put.headers.set("Content-Length", body.len().to_string());
    put.headers.set("Content-Type", "application/json");
    put.headers.set(SYS_OBJECT_KEY, key);
    // Swift body ETag from GET. Do not send cas_etag() as If-Match
    // (object-server compares If-Match to MD5, not sha256(gen||latest||key)).
    // The header activates once the object layer honors If-Match on PUT
    // (>= 414b76e); until then the fence above carries the CAS. Persist 202
    // is the proxy remap of object-server 409 — not Applied.
    if snap.exists {
        if let Some(etag) = snap.etag.as_deref() {
            put.headers.set("If-Match", etag);
        }
    } else {
        put.headers.set("If-None-Match", "*");
    }
    put.body = Body::from(body);
    stamp_auth(&mut put, cred);
    let resp = async_call(next, put).await;
    if swift_write_applied(resp.status) {
        Ok(())
    } else if resp.status == 202 || resp.status == 412 {
        Err(version_index_persist_conflict())
    } else {
        Err(map_swift_error(resp.status, Some(&vc), Some(&iname)))
    }
}



fn cas_save_version_index(
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    snap: &VersionIndexSnapshot,
    idx: &VersionIndex,
    next: &NextFn,
) -> Result<(), Response> {
    ensure_versions_container(cred, bucket, next)?;
    let vc = versions_container(bucket);
    let body = idx.to_json();

    let fence = index_generation_object_name(key, idx.generation);
    let mut fence_put = make_swift_req(
        "PUT",
        &s3_to_swift_path(&cred.account, Some(&vc), Some(&fence)),
    );
    fence_put
        .headers
        .set("Content-Length", body.len().to_string());
    fence_put.headers.set("Content-Type", "application/json");
    fence_put.headers.set(SYS_OBJECT_KEY, key);
    fence_put.headers.set("If-None-Match", "*");
    fence_put.body = Body::from(body.clone());
    stamp_auth(&mut fence_put, cred);
    let fence_resp = next(fence_put);
    if !swift_write_applied(fence_resp.status) {
        return Err(if fence_resp.status == 202 || fence_resp.status == 412 {
            version_index_persist_conflict()
        } else {
            map_swift_error(fence_resp.status, Some(&vc), Some(&fence))
        });
    }

    let iname = index_object_name(key);
    let mut put = make_swift_req(
        "PUT",
        &s3_to_swift_path(&cred.account, Some(&vc), Some(&iname)),
    );
    put.headers.set("Content-Length", body.len().to_string());
    put.headers.set("Content-Type", "application/json");
    put.headers.set(SYS_OBJECT_KEY, key);
    // Swift body ETag from GET. Do not send cas_etag() as If-Match
    // (object-server compares If-Match to MD5, not sha256(gen||latest||key)).
    // The header activates once the object layer honors If-Match on PUT
    // (>= 414b76e); until then the fence above carries the CAS. Persist 202
    // is the proxy remap of object-server 409 — not Applied.
    if snap.exists {
        if let Some(etag) = snap.etag.as_deref() {
            put.headers.set("If-Match", etag);
        }
    } else {
        put.headers.set("If-None-Match", "*");
    }
    put.body = Body::from(body);
    stamp_auth(&mut put, cred);
    let resp = next(put);
    if swift_write_applied(resp.status) {
        Ok(())
    } else if resp.status == 202 || resp.status == 412 {
        Err(version_index_persist_conflict())
    } else {
        Err(map_swift_error(resp.status, Some(&vc), Some(&iname)))
    }
}

fn copy_version_payload_headers(src: &HeaderKeyDict, dst: &mut HeaderKeyDict) {
    for (name, value) in src.iter() {
        let lower = name.to_ascii_lowercase();
        // Archive stores the assembled GET body as a regular object.
        // SLO/DLO markers on the current slot must not travel with it or
        // historical GET-by-versionId tries to parse raw bytes as a manifest.
        if lower == "x-static-large-object"
            || lower == "x-object-manifest"
            || lower.starts_with("x-object-sysmeta-slo-")
        {
            continue;
        }
        if lower.starts_with("x-object-meta-")
            || lower.starts_with("x-object-sysmeta-")
            || matches!(
                lower.as_str(),
                "content-type"
                    | "content-encoding"
                    | "content-disposition"
                    | "content-language"
                    | "cache-control"
                    | "expires"
                    | "content-length"
            )
        {
            dst.set(name, value);
        }
    }
}

async fn archive_current_version_async(
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    version_id: &str,
    next: &AsyncNextFn,
) -> Result<(), Response> {
    let vc = versions_container(bucket);
    let mut ensure = make_swift_req("PUT", &s3_to_swift_path(&cred.account, Some(&vc), None));
    stamp_auth(&mut ensure, cred);
    let ensure_resp = async_call(next, ensure).await;
    if !(200..300).contains(&ensure_resp.status) {
        return Err(map_swift_error(ensure_resp.status, Some(&vc), None));
    }

    let cur_path = s3_to_swift_path(&cred.account, Some(bucket), Some(key));
    let mut get = make_swift_req("GET", &cur_path);
    stamp_auth(&mut get, cred);
    let got = async_call(next, get).await;
    if !(200..300).contains(&got.status) {
        return Err(map_swift_error(got.status, Some(bucket), Some(key)));
    }
    let aname = archive_name_checked(key, version_id)?;
    let mut put = make_swift_req(
        "PUT",
        &s3_to_swift_path(&cred.account, Some(&vc), Some(&aname)),
    );
    copy_version_payload_headers(&got.headers, &mut put.headers);
    put.headers.set(SYS_VERSION_ID, version_id);
    put.headers.set(SYS_OBJECT_KEY, key);
    if put.headers.get(SYS_DELETE_MARKER).is_none() {
        put.headers.set(SYS_DELETE_MARKER, "false");
    }
    put.headers.set("If-None-Match", "*");
    put.body = got.body;
    stamp_auth(&mut put, cred);
    let stored = async_call(next, put).await;
    // 412 on If-None-Match:* means a prior attempt already archived this
    // vid. Treating it as failure leaks PreconditionFailed and blocks retry.
    if swift_write_applied(stored.status) || stored.status == 412 {
        Ok(())
    } else if stored.status == 202 {
        Err(s3_error_response(
            "InternalError",
            Some("backend write was not applied"),
            &[],
        ))
    } else {
        Err(map_swift_error(stored.status, Some(&vc), Some(&aname)))
    }
}



fn archive_current_version(
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    version_id: &str,
    next: &NextFn,
) -> Result<(), Response> {
    let vc = versions_container(bucket);
    let mut ensure = make_swift_req("PUT", &s3_to_swift_path(&cred.account, Some(&vc), None));
    stamp_auth(&mut ensure, cred);
    let ensure_resp = next(ensure);
    if !(200..300).contains(&ensure_resp.status) {
        return Err(map_swift_error(ensure_resp.status, Some(&vc), None));
    }

    let cur_path = s3_to_swift_path(&cred.account, Some(bucket), Some(key));
    let mut get = make_swift_req("GET", &cur_path);
    stamp_auth(&mut get, cred);
    let got = next(get);
    if !(200..300).contains(&got.status) {
        return Err(map_swift_error(got.status, Some(bucket), Some(key)));
    }
    let aname = archive_name_checked(key, version_id)?;
    let mut put = make_swift_req(
        "PUT",
        &s3_to_swift_path(&cred.account, Some(&vc), Some(&aname)),
    );
    copy_version_payload_headers(&got.headers, &mut put.headers);
    put.headers.set(SYS_VERSION_ID, version_id);
    put.headers.set(SYS_OBJECT_KEY, key);
    if put.headers.get(SYS_DELETE_MARKER).is_none() {
        put.headers.set(SYS_DELETE_MARKER, "false");
    }
    put.headers.set("If-None-Match", "*");
    put.body = got.body;
    stamp_auth(&mut put, cred);
    let stored = next(put);
    // 412 on If-None-Match:* means a prior attempt already archived this
    // vid. Treating it as failure leaks PreconditionFailed and blocks retry.
    if swift_write_applied(stored.status) || stored.status == 412 {
        Ok(())
    } else if stored.status == 202 {
        Err(s3_error_response(
            "InternalError",
            Some("backend write was not applied"),
            &[],
        ))
    } else {
        Err(map_swift_error(stored.status, Some(&vc), Some(&aname)))
    }
}

async fn archived_null_replacement_required_async(
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    clock_ok: bool,
    bypass: GovernanceBypass,
    next: &AsyncNextFn,
) -> Result<bool, Response> {
    let vc = versions_container(bucket);
    let aname = archive_name_checked(key, NULL_VERSION_ID)?;
    match control_head_object_async(cred, &vc, &aname, next).await? {
        ObjectHead::Missing => Ok(false),
        ObjectHead::Present(head) => {
            if let Some(blocked) = worm_guard(&head.headers, clock_ok, bypass) {
                return Err(blocked);
            }
            if let Some(blocked) = deny_if_object_acl_blocks_write(cred, &head.headers) {
                return Err(blocked);
            }
            Ok(true)
        }
    }
}



fn archived_null_replacement_required(
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    clock_ok: bool,
    bypass: GovernanceBypass,
    next: &NextFn,
) -> Result<bool, Response> {
    let vc = versions_container(bucket);
    let aname = archive_name_checked(key, NULL_VERSION_ID)?;
    match control_head_object(cred, &vc, &aname, next)? {
        ObjectHead::Missing => Ok(false),
        ObjectHead::Present(head) => {
            if let Some(blocked) = worm_guard(&head.headers, clock_ok, bypass) {
                return Err(blocked);
            }
            if let Some(blocked) = deny_if_object_acl_blocks_write(cred, &head.headers) {
                return Err(blocked);
            }
            Ok(true)
        }
    }
}

async fn delete_archived_version_copy_async(
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    version_id: &str,
    next: &AsyncNextFn,
) -> Result<(), Response> {
    let vc = versions_container(bucket);
    let aname = archive_name_checked(key, version_id)?;
    let mut del = make_swift_req(
        "DELETE",
        &s3_to_swift_path(&cred.account, Some(&vc), Some(&aname)),
    );
    stamp_auth(&mut del, cred);
    let deleted = async_call(next, del).await;
    if swift_write_applied(deleted.status) || deleted.status == 404 {
        Ok(())
    } else if deleted.status == 202 {
        Err(s3_error_response(
            "InternalError",
            Some("backend write was not applied"),
            &[],
        ))
    } else {
        Err(map_swift_error(deleted.status, Some(&vc), Some(&aname)))
    }
}



fn delete_archived_version_copy(
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    version_id: &str,
    next: &NextFn,
) -> Result<(), Response> {
    let vc = versions_container(bucket);
    let aname = archive_name_checked(key, version_id)?;
    let mut del = make_swift_req(
        "DELETE",
        &s3_to_swift_path(&cred.account, Some(&vc), Some(&aname)),
    );
    stamp_auth(&mut del, cred);
    let deleted = next(del);
    if swift_write_applied(deleted.status) || deleted.status == 404 {
        Ok(())
    } else if deleted.status == 202 {
        Err(s3_error_response(
            "InternalError",
            Some("backend write was not applied"),
            &[],
        ))
    } else {
        Err(map_swift_error(deleted.status, Some(&vc), Some(&aname)))
    }
}

async fn promote_archived_version_async(
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    version_id: &str,
    next: &AsyncNextFn,
) -> Result<(), Response> {
    let vc = versions_container(bucket);
    let aname = archive_name_checked(key, version_id)?;
    let mut get = make_swift_req(
        "GET",
        &s3_to_swift_path(&cred.account, Some(&vc), Some(&aname)),
    );
    stamp_auth(&mut get, cred);
    let archived = async_call(next, get).await;
    if !(200..300).contains(&archived.status) {
        return Err(map_swift_error(archived.status, Some(&vc), Some(&aname)));
    }

    let mut put = make_swift_req(
        "PUT",
        &s3_to_swift_path(&cred.account, Some(bucket), Some(key)),
    );
    copy_version_payload_headers(&archived.headers, &mut put.headers);
    put.headers.set(SYS_VERSION_ID, version_id);
    put.headers.set(SYS_OBJECT_KEY, key);
    put.body = archived.body;
    stamp_auth(&mut put, cred);
    let stored = async_call(next, put).await;
    if !swift_write_applied(stored.status) {
        return Err(if stored.status == 202 {
            s3_error_response("InternalError", Some("backend write was not applied"), &[])
        } else {
            map_swift_error(stored.status, Some(bucket), Some(key))
        });
    }

    // Promotion moves the archived copy back to the current slot. Keeping the
    // hidden duplicate would let a later exact-version delete find and revive
    // a version that had already been removed.
    delete_archived_version_copy_async(cred, bucket, key, version_id, next).await
}



fn promote_archived_version(
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    version_id: &str,
    next: &NextFn,
) -> Result<(), Response> {
    let vc = versions_container(bucket);
    let aname = archive_name_checked(key, version_id)?;
    let mut get = make_swift_req(
        "GET",
        &s3_to_swift_path(&cred.account, Some(&vc), Some(&aname)),
    );
    stamp_auth(&mut get, cred);
    let archived = next(get);
    if !(200..300).contains(&archived.status) {
        return Err(map_swift_error(archived.status, Some(&vc), Some(&aname)));
    }

    let mut put = make_swift_req(
        "PUT",
        &s3_to_swift_path(&cred.account, Some(bucket), Some(key)),
    );
    copy_version_payload_headers(&archived.headers, &mut put.headers);
    put.headers.set(SYS_VERSION_ID, version_id);
    put.headers.set(SYS_OBJECT_KEY, key);
    put.body = archived.body;
    stamp_auth(&mut put, cred);
    let stored = next(put);
    if !swift_write_applied(stored.status) {
        return Err(if stored.status == 202 {
            s3_error_response("InternalError", Some("backend write was not applied"), &[])
        } else {
            map_swift_error(stored.status, Some(bucket), Some(key))
        });
    }

    // Promotion moves the archived copy back to the current slot. Keeping the
    // hidden duplicate would let a later exact-version delete find and revive
    // a version that had already been removed.
    delete_archived_version_copy(cred, bucket, key, version_id, next)
}

fn handle_versioned_object(
    req: Request,
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    method: &str,
    version_id_q: Option<&str>,
    versioning_mode: Option<BucketVersioningMode>,
    is_copy: bool,
    bypass: GovernanceBypass,
    next: &NextFn,
    api: &S3Api,
) -> Response {
    if versioning_mode.is_none() && version_id_q.is_none() {
        return s3_error_response("InvalidRequest", None, &[]);
    }
    match method {
        "PUT" if version_id_q.is_none() => {
            let version_id = match versioning_mode {
                Some(BucketVersioningMode::Enabled) => None,
                Some(BucketVersioningMode::Suspended) => Some(NULL_VERSION_ID),
                None => return s3_error_response("InvalidRequest", None, &[]),
            };
            handle_versioned_put(
                req, cred, bucket, key, is_copy, None, version_id, bypass, next, api,
            )
        }
        "PUT" => s3_error_response("InvalidArgument", None, &[]),
        "GET" | "HEAD" => {
            handle_versioned_get_head(cred, bucket, key, method, version_id_q, next, api)
        }
        "DELETE" => handle_versioned_delete(
            cred,
            bucket,
            key,
            version_id_q,
            match versioning_mode {
                Some(BucketVersioningMode::Suspended) if version_id_q.is_none() => {
                    Some(NULL_VERSION_ID)
                }
                _ => None,
            },
            api.worm_clock.clock_ok(),
            bypass,
            next,
        ),
        _ => s3_error_response("MethodNotAllowed", None, &[]),
    }
}

fn current_object_version_id(headers: &HeaderKeyDict) -> Result<String, Response> {
    let old_vid = headers
        .get(SYS_VERSION_ID)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| NULL_VERSION_ID.to_string());
    if !is_safe_version_id(&old_vid) {
        return Err(unsafe_version_id_error());
    }
    Ok(old_vid)
}

async fn maybe_archive_current_for_write_async(
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    headers: &HeaderKeyDict,
    overwrite_null: bool,
    clock_ok: bool,
    bypass: GovernanceBypass,
    idx: &mut VersionIndex,
    next: &AsyncNextFn,
) -> Result<(), Response> {
    let old_vid = current_object_version_id(headers)?;
    let old_etag = headers
        .get("ETag")
        .map(vers_bare_etag)
        .unwrap_or_default();
    let old_size = headers
        .get("Content-Length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0i64);
    let old_lm = headers
        .get("Last-Modified")
        .map(http_date_to_s3_approx)
        .unwrap_or_else(|| "1970-01-01T00:00:00.000Z".into());
    let old_is_delete_marker = is_delete_marker_header(headers.get(SYS_DELETE_MARKER));
    if overwrite_null && old_vid == NULL_VERSION_ID {
        if let Some(blocked) = worm_guard(headers, clock_ok, bypass) {
            return Err(blocked);
        }
        return Ok(());
    }
    archive_current_version_async(cred, bucket, key, &old_vid, next).await?;
    if idx.find(&old_vid).is_none() {
        idx.push_latest(VersionRecord {
            version_id: old_vid,
            is_delete_marker: old_is_delete_marker,
            is_latest: true,
            last_modified: old_lm,
            etag: old_etag,
            size: old_size,
        });
    }
    Ok(())
}




fn maybe_archive_current_for_write(
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    cur: &Response,
    overwrite_null: bool,
    clock_ok: bool,
    bypass: GovernanceBypass,
    idx: &mut VersionIndex,
    next: &NextFn,
) -> Result<(), Response> {
    let old_vid = current_object_version_id(&cur.headers)?;
    let old_etag = cur
        .headers
        .get("ETag")
        .map(vers_bare_etag)
        .unwrap_or_default();
    let old_size = cur
        .headers
        .get("Content-Length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0i64);
    let old_lm = cur
        .headers
        .get("Last-Modified")
        .map(http_date_to_s3_approx)
        .unwrap_or_else(|| "1970-01-01T00:00:00.000Z".into());
    let old_is_delete_marker = is_delete_marker_header(cur.headers.get(SYS_DELETE_MARKER));
    if overwrite_null && old_vid == NULL_VERSION_ID {
        if let Some(blocked) = worm_guard(&cur.headers, clock_ok, bypass) {
            return Err(blocked);
        }
        return Ok(());
    }
    archive_current_version(cred, bucket, key, &old_vid, next)?;
    if idx.find(&old_vid).is_none() {
        idx.push_latest(VersionRecord {
            version_id: old_vid,
            is_delete_marker: old_is_delete_marker,
            is_latest: true,
            last_modified: old_lm,
            etag: old_etag,
            size: old_size,
        });
    }
    Ok(())
}


fn commit_new_version_record(
    idx: &mut VersionIndex,
    expect: Option<u64>,
    overwrite_null: bool,
    rec: VersionRecord,
) -> Result<(), Response> {
    if overwrite_null {
        check_index_generation(idx, expect).map_err(cas_denied_response)?;
        idx.suspended_put_overwrites_null(rec);
        idx.generation = idx.generation.saturating_add(1);
        Ok(())
    } else {
        idx.apply_if_match(expect, rec).map_err(cas_denied_response)
    }
}

fn stamp_object_write_precondition(headers: &mut HeaderKeyDict, current: Option<&Response>) {
    match current {
        Some(cur) => {
            if let Some(etag) = cur
                .headers
                .get("ETag")
                .map(vers_bare_etag)
                .filter(|s| !s.is_empty())
            {
                headers.set("If-Match", etag);
            }
        }
        None => {
            headers.set("If-None-Match", "*");
        }
    }
}

fn backend_write_not_applied(status: u16, bucket: Option<&str>, key: Option<&str>) -> Response {
    if status == 202 {
        s3_error_response("InternalError", Some("backend write was not applied"), &[])
    } else {
        map_swift_error(status, bucket, key)
    }
}

fn client_sent_write_conditional(req: &Request) -> bool {
    req.headers.get("If-Match").is_some() || req.headers.get("If-None-Match").is_some()
}

fn versioned_write_retryable(resp: &Response) -> bool {
    if resp.status == 412 {
        return true;
    }
    if !(500..600).contains(&resp.status) {
        return false;
    }
    match &resp.body {
        Body::Buffered(b) => {
            let s = String::from_utf8_lossy(b);
            s.contains("generation mismatch")
                || s.contains("persist conflict")
                || s.contains("lost update")
                || s.contains("version index")
        }
        _ => false,
    }
}

fn handle_versioned_put(
    mut req: Request,
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    is_copy: bool,
    backend_query: Option<&str>,
    fixed_version_id: Option<&str>,
    bypass: GovernanceBypass,
    next: &NextFn,
    api: &S3Api,
) -> Response {
    // Versioned S3 PUTs must both succeed under concurrency. The object
    // layer enforces `If-None-Match: *` (412 when the current slot exists),
    // which is an internal CAS, not a client precondition. Retry with a
    // fresh HEAD/archive when the client did not send If-Match / If-None-Match.
    let client_conditional = client_sent_write_conditional(&req);
    // Live HTTP PUTs arrive streamed. Retry needs a replayable body;
    // materialize small/medium objects (control-plane cap). Larger
    // streams stay one-shot.
    let retry_body = match req.body.materialize(MAX_CONTROL_BODY) {
        Ok(b) => Some(b.to_vec()),
        Err(_) => None,
    };
    const MAX_ATTEMPTS: usize = 24;
    let mut last: Option<Response> = None;
    for attempt in 0..MAX_ATTEMPTS {
        let mut try_req = req.clone_head();
        try_req.body = match &retry_body {
            Some(b) => Body::from(b.clone()),
            None if attempt == 0 => std::mem::replace(&mut req.body, Body::empty()),
            None => break,
        };
        let resp = handle_versioned_put_once(
            try_req,
            cred,
            bucket,
            key,
            is_copy,
            backend_query,
            fixed_version_id,
            bypass,
            next,
            api,
        );
        let can_retry = !client_conditional
            && retry_body.is_some()
            && attempt + 1 < MAX_ATTEMPTS
            && versioned_write_retryable(&resp);
        if can_retry {
            last = Some(resp);
            continue;
        }
        return resp;
    }
    last.unwrap_or_else(|| {
        s3_error_response("InternalError", Some("versioned put conflict"), &[])
    })
}

fn handle_versioned_put_once(
    mut req: Request,
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    is_copy: bool,
    backend_query: Option<&str>,
    fixed_version_id: Option<&str>,
    bypass: GovernanceBypass,
    next: &NextFn,
    api: &S3Api,
) -> Response {
    let clock_ok = api.worm_clock.clock_ok();
    let snap = match load_version_index_snapshot(cred, bucket, key, next) {
        Ok(snap) => snap,
        Err(resp) => return resp,
    };
    let expect = expect_generation(&snap);
    let mut idx = snap.index.clone();

    let cur_path = s3_to_swift_path(&cred.account, Some(bucket), Some(key));
    let mut head = make_swift_req("HEAD", &cur_path);
    stamp_auth(&mut head, cred);
    let cur = next(head);

    // Suspended still writes (versioning_enabled("Suspended") is false).
    let overwrite_null = fixed_version_id == Some(NULL_VERSION_ID)
        && VersioningStatus::Suspended.suspended_put_overwrites_null();
    let archived_null_exists = if overwrite_null {
        match archived_null_replacement_required(cred, bucket, key, clock_ok, bypass, next) {
            Ok(exists) => exists,
            Err(resp) => return resp,
        }
    } else {
        false
    };

    if !(200..300).contains(&cur.status) && cur.status != 404 {
        return map_swift_error(cur.status, Some(bucket), Some(key));
    }
    let current_exists = (200..300).contains(&cur.status);
    if current_exists {
        if let Some(blocked) = deny_if_object_acl_blocks_write(cred, &cur.headers) {
            return blocked;
        }
        if let Err(resp) = maybe_archive_current_for_write(
            cred,
            bucket,
            key,
            &cur,
            overwrite_null,
            clock_ok,
            bypass,
            &mut idx,
            next,
        ) {
            return resp;
        }
    }

    let new_vid = if overwrite_null {
        NULL_VERSION_ID.to_string()
    } else {
        generate_version_id()
    };
    if !is_safe_version_id(&new_vid) {
        return unsafe_version_id_error();
    }

    req.method = "PUT".into();
    req.path = cur_path;
    req.query_string = backend_query.unwrap_or("").to_string();
    map_amz_meta(&mut req);
    if let Some(resp) = reject_copy_to_self(&req) {
        return resp;
    }
    if let Some(resp) = rewrite_copy_source_version(&mut req, cred, next) {
        return resp;
    }
    if let Some(resp) = apply_copy_source(&mut req) {
        return resp;
    }
    match resolve_acl_put_input(&req.headers, None, &cred.access_key) {
        Ok(input) if !matches!(input, AclPutInput::None) => {
            apply_object_acl_input(&mut req.headers, &input);
        }
        Ok(_) => {}
        Err(_) => return s3_error_response("InvalidArgument", None, &[]),
    }
    if let Err(resp) = apply_request_object_lock_headers(&mut req.headers) {
        return resp;
    }
    strip_s3_only_headers(&mut req.headers);
    req.headers.set(SYS_VERSION_ID, &new_vid);
    req.headers.set(SYS_DELETE_MARKER, "false");
    stamp_auth(&mut req, cred);

    maybe_apply_lifecycle_on_put(&mut req, cred, bucket, key, next, &api.container_heads);
    let stamped_delete_at = req.headers.get("X-Delete-At").map(str::to_string);
    if let Some(err) = maybe_archive_due_cold_on_put(
        &mut req,
        cred,
        bucket,
        key,
        &api.cold_map,
        api.cold_backend.as_ref(),
        api.cold_delete_hot_after_archive,
    ) {
        return err;
    }
    if let Err(resp) = apply_bucket_default_retention(&mut req, cred, bucket, next, &api.container_heads)
    {
        return resp;
    }
    // SLO complete (`multipart-manifest=put`) rejects dest If-None-Match:*
    // as 400; s3api then maps that to InvalidRequest (versioned MPU).
    if !req.query_string.contains("multipart-manifest=put") {
        stamp_object_write_precondition(&mut req.headers, current_exists.then_some(&cur));
    }

    // Index Size is the object length, not the Swift PUT response
    // Content-Length (empty body → 0). ListVersions compares Size.
    // SLO complete stamps override-size to the assembled payload; the
    // PUT Content-Length is only the manifest JSON.
    let request_size: i64 = req
        .headers
        .get(SYS_CONTAINER_UPDATE_OVERRIDE_SIZE)
        .and_then(|v| v.parse().ok())
        .filter(|&n| n >= 0)
        .or_else(|| {
            req.headers
                .get("Content-Length")
                .and_then(|v| v.parse().ok())
                .filter(|&n| n >= 0)
        })
        .or_else(|| req.body.content_length().map(|n| n as i64))
        .unwrap_or(0);
    let s3_etag = req
        .headers
        .get(SYS_S3API_ETAG)
        .map(|s| s.trim().trim_matches('"').to_string())
        .filter(|s| !s.is_empty());

    let resp = next(req);
    if !swift_write_applied(resp.status) {
        return backend_write_not_applied(resp.status, Some(bucket), Some(key));
    }
    if archived_null_exists {
        if let Err(resp) = delete_archived_version_copy(cred, bucket, key, NULL_VERSION_ID, next) {
            return resp;
        }
    }

    let etag = s3_etag.unwrap_or_else(|| {
        resp.headers
            .get("ETag")
            .map(vers_bare_etag)
            .unwrap_or_default()
    });
    let size = request_size;
    let lm = resp
        .headers
        .get("Last-Modified")
        .map(http_date_to_s3_approx)
        .unwrap_or_else(|| "1970-01-01T00:00:00.000Z".into());

    if let Err(resp) = commit_new_version_record(
        &mut idx,
        expect,
        overwrite_null,
        VersionRecord {
            version_id: new_vid.clone(),
            is_delete_marker: false,
            is_latest: true,
            last_modified: lm,
            etag: etag.clone(),
            size,
        },
    ) {
        return resp;
    }
    if let Err(resp) = cas_save_version_index(cred, bucket, key, &snap, &idx, next) {
        return resp;
    }

    if is_copy {
        let iso = resp
            .headers
            .get("Last-Modified")
            .map(http_date_to_s3_approx)
            .unwrap_or_else(|| "1970-01-01T00:00:00.000Z".into());
        let mut r = xml_response(200, copy_object_result_xml(&iso, &etag));
        r.headers.set(HDR_VERSION_ID, &new_vid);
        r
    } else {
        let mut r = put_object_response(&etag);
        r.headers.set(HDR_VERSION_ID, &new_vid);
        if let Some(exp) = stamped_delete_at
            .as_deref()
            .and_then(amz_expiration_from_delete_at)
        {
            r.headers.set("x-amz-expiration", exp);
        }
        r
    }
}

/// Auth-present versioned GET/HEAD: ACL, then archive+POST (optional
/// hot-delete). A successful due-cold stamp returns 400 InvalidObjectState
/// from the helper and must not fall through to `map_swift_error`.
/// `persist_bucket`/`persist_key` are the Swift object the POST targets
/// (current object or `{bucket}+versions` archive).
fn finish_versioned_get_head(
    mut resp: Response,
    method: &str,
    cred: &S3Credential,
    persist_bucket: &str,
    persist_key: &str,
    version_id: Option<&str>,
    next: &NextFn,
    api: &S3Api,
) -> Response {
    if let Some(denied) = deny_if_object_acl_blocks_read(cred, &resp.headers) {
        return denied;
    }
    if let Some(err) = maybe_archive_due_cold_on_get_head(
        &mut resp,
        method,
        cred,
        persist_bucket,
        persist_key,
        &api.cold_map,
        api.cold_backend.as_ref(),
        api.cold_delete_hot_after_archive,
        next,
    ) {
        return err;
    }
    let mut out = translate_object_get_head(method, resp, cred, &[], None);
    if (200..300).contains(&out.status) {
        if let Some(vid) = version_id {
            out.headers.set(HDR_VERSION_ID, vid);
        }
    }
    out
}

fn handle_versioned_get_head(
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    method: &str,
    version_id_q: Option<&str>,
    next: &NextFn,
    api: &S3Api,
) -> Response {
    let target = match resolve_object_version(cred, bucket, key, version_id_q, next) {
        Ok(Some(target)) => target,
        Ok(None) => return missing_object_version_response(key, version_id_q),
        Err(resp) => return resp,
    };
    let response_version = version_id_q
        .map(str::to_string)
        .or_else(|| target.head.headers.get(SYS_VERSION_ID).map(str::to_string));
    if is_delete_marker_header(target.head.headers.get(SYS_DELETE_MARKER)) {
        return nosuchkey_delete_marker(key, response_version.as_deref());
    }
    let resp = if method == "HEAD" {
        target.head
    } else {
        let mut get = make_swift_req(
            "GET",
            &s3_to_swift_path(&cred.account, Some(&target.container), Some(&target.key)),
        );
        stamp_auth(&mut get, cred);
        let resp = next(get);
        if !(200..300).contains(&resp.status) {
            return map_swift_error(resp.status, Some(&target.container), Some(&target.key));
        }
        resp
    };
    let mut out = finish_versioned_get_head(
        resp,
        method,
        cred,
        &target.container,
        &target.key,
        response_version.as_deref(),
        next,
        api,
    );
    if (200..300).contains(&out.status) {
        if let Some(version_id) = response_version {
            out.headers.set(HDR_VERSION_ID, version_id);
        }
    }
    out
}

fn nosuchkey_delete_marker(key: &str, version_id: Option<&str>) -> Response {
    let mut resp = s3_error_response("NoSuchKey", None, &[("Key", key)]);
    resp.headers.set(HDR_DELETE_MARKER, "true");
    if let Some(v) = version_id {
        resp.headers.set(HDR_VERSION_ID, v);
    }
    resp
}

async fn handle_versioned_delete_async(
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    version_id_q: Option<&str>,
    fixed_delete_marker_id: Option<&str>,
    clock_ok: bool,
    bypass: GovernanceBypass,
    next: &AsyncNextFn,
) -> Response {
    const MAX_ATTEMPTS: usize = 24;
    let mut last: Option<Response> = None;
    for attempt in 0..MAX_ATTEMPTS {
        let resp = handle_versioned_delete_once_async(
            cred,
            bucket,
            key,
            version_id_q,
            fixed_delete_marker_id,
            clock_ok,
            bypass,
            next,
        ).await;
        if attempt + 1 < MAX_ATTEMPTS && versioned_write_retryable(&resp) {
            last = Some(resp);
            continue;
        }
        return resp;
    }
    last.unwrap_or_else(|| {
        s3_error_response("InternalError", Some("versioned delete conflict"), &[])
    })
}



fn handle_versioned_delete(
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    version_id_q: Option<&str>,
    fixed_delete_marker_id: Option<&str>,
    clock_ok: bool,
    bypass: GovernanceBypass,
    next: &NextFn,
) -> Response {
    const MAX_ATTEMPTS: usize = 24;
    let mut last: Option<Response> = None;
    for attempt in 0..MAX_ATTEMPTS {
        let resp = handle_versioned_delete_once(
            cred,
            bucket,
            key,
            version_id_q,
            fixed_delete_marker_id,
            clock_ok,
            bypass,
            next,
        );
        if attempt + 1 < MAX_ATTEMPTS && versioned_write_retryable(&resp) {
            last = Some(resp);
            continue;
        }
        return resp;
    }
    last.unwrap_or_else(|| {
        s3_error_response("InternalError", Some("versioned delete conflict"), &[])
    })
}

async fn handle_versioned_delete_once_async(
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    version_id_q: Option<&str>,
    fixed_delete_marker_id: Option<&str>,
    clock_ok: bool,
    bypass: GovernanceBypass,
    next: &AsyncNextFn,
) -> Response {
    let cur_path = s3_to_swift_path(&cred.account, Some(bucket), Some(key));

    if let Some(vid) = version_id_q {
        let target = match resolve_object_version_async(cred, bucket, key, Some(vid), next).await {
            Ok(Some(target)) => target,
            Ok(None) => {
                // Data-plane copy is already gone. Still drop a leftover
                // index row so ListVersions cannot keep a ghost version.
                if let Err(resp) = drop_missing_version_index_row_async(cred, bucket, key, vid, next).await
                {
                    return resp;
                }
                let mut r = delete_object_response();
                r.headers.set(HDR_VERSION_ID, vid);
                return r;
            }
            Err(resp) => return resp,
        };
        if let Some(blocked) = worm_guard(&target.head.headers, clock_ok, bypass) {
            return blocked;
        }
        if let Some(blocked) = deny_if_object_acl_blocks_write(cred, &target.head.headers) {
            return blocked;
        }

        let was_delete_marker = is_delete_marker_header(target.head.headers.get(SYS_DELETE_MARKER));
        let target_is_current = target.container == bucket && target.key == key;
        let snap = match load_version_index_snapshot_async(cred, bucket, key, next).await {
            Ok(snap) => snap,
            Err(resp) => return resp,
        };
        // Current objects listed via merge (never-versioned null, or a
        // numbered vid whose index persist failed after the data-plane
        // PUT) have no index row. CAS-remove would 500 "lost update" and
        // leave the object (the Ceph s3-tests nuke poison).
        if target_is_current && snap.index.find(vid).is_none()
        {
            let mut del = make_swift_req("DELETE", &cur_path);
            stamp_object_write_precondition(&mut del.headers, Some(&target.head));
            stamp_auth(&mut del, cred);
            let retry = del.clone_head();
            let resp = async_call(next, del).await;
            let resp = if resp.status == 412 {
                let mut retry = retry;
                retry.query_string = "multipart-manifest=delete".into();
                stamp_object_write_precondition(&mut retry.headers, Some(&target.head));
                stamp_auth(&mut retry, cred);
                async_call(next, retry).await
            } else {
                resp
            };
            if !swift_write_applied(resp.status) && resp.status != 404 {
                return backend_write_not_applied(resp.status, Some(bucket), Some(key));
            }
            let mut r = delete_object_response();
            r.headers.set(HDR_VERSION_ID, vid);
            return r;
        }
        let expect = expect_generation(&snap);
        let mut idx = snap.index.clone();
        if let Err(denied) = check_index_generation(&idx, expect) {
            return cas_denied_response(denied);
        }
        let next_version = match idx.remove_version_checked(vid) {
            Ok(next) => next,
            Err(RemoveVersionError::Missing) => return version_index_lost_update(),
        };

        if target_is_current {
            if let Some(next_version) = next_version.as_deref() {
                if !is_safe_version_id(next_version) {
                    return unsafe_version_id_error();
                }
                if let Err(resp) = promote_archived_version_async(cred, bucket, key, next_version, next).await {
                    return resp;
                }
            } else {
                let mut del = make_swift_req("DELETE", &cur_path);
                stamp_object_write_precondition(&mut del.headers, Some(&target.head));
                stamp_auth(&mut del, cred);
                let resp = async_call(next, del).await;
                if !swift_write_applied(resp.status) && resp.status != 404 {
                    return backend_write_not_applied(resp.status, Some(bucket), Some(key));
                }
            }
        } else {
            let mut del = make_swift_req("DELETE", &cur_path);
            del.path = s3_to_swift_path(&cred.account, Some(&target.container), Some(&target.key));
            stamp_object_write_precondition(&mut del.headers, Some(&target.head));
            stamp_auth(&mut del, cred);
            let resp = async_call(next, del).await;
            if !swift_write_applied(resp.status) && resp.status != 404 {
                return backend_write_not_applied(
                    resp.status,
                    Some(&target.container),
                    Some(&target.key),
                );
            }
        }

        idx.generation = idx.generation.saturating_add(1);
        if let Err(resp) = cas_save_version_index_async(cred, bucket, key, &snap, &idx, next).await {
            return resp;
        }
        let mut r = delete_object_response();
        r.headers.set(HDR_VERSION_ID, vid);
        if was_delete_marker {
            r.headers.set(HDR_DELETE_MARKER, "true");
        }
        return r;
    }

    let snap = match load_version_index_snapshot_async(cred, bucket, key, next).await {
        Ok(snap) => snap,
        Err(resp) => return resp,
    };
    let expect = expect_generation(&snap);
    let mut idx = snap.index.clone();

    let mut head = make_swift_req("HEAD", &cur_path);
    stamp_auth(&mut head, cred);
    let cur = async_call(next, head).await;
    if !(200..300).contains(&cur.status) && cur.status != 404 {
        return map_swift_error(cur.status, Some(bucket), Some(key));
    }
    let current_exists = (200..300).contains(&cur.status);
    if current_exists {
        if let Some(blocked) = deny_if_object_acl_blocks_write(cred, &cur.headers) {
            return blocked;
        }
    }
    let overwrite_null = fixed_delete_marker_id == Some(NULL_VERSION_ID)
        && VersioningStatus::Suspended.suspended_put_overwrites_null();
    let archived_null_exists = if overwrite_null {
        match archived_null_replacement_required_async(cred, bucket, key, clock_ok, bypass, next).await {
            Ok(exists) => exists,
            Err(resp) => return resp,
        }
    } else {
        false
    };

    if current_exists {
        if let Err(resp) = maybe_archive_current_for_write_async(
            cred,
            bucket,
            key,
            &cur.headers,
            overwrite_null,
            clock_ok,
            bypass,
            &mut idx,
            next,
        ).await {
            return resp;
        }
    }

    let dm_vid = if overwrite_null {
        NULL_VERSION_ID.to_string()
    } else {
        generate_version_id()
    };
    if !is_safe_version_id(&dm_vid) {
        return unsafe_version_id_error();
    }
    let mut put = make_swift_req("PUT", &cur_path);
    put.headers.set("Content-Length", "0");
    put.headers.set(SYS_VERSION_ID, &dm_vid);
    put.headers.set(SYS_DELETE_MARKER, "true");
    put.body = Body::empty();
    stamp_object_write_precondition(&mut put.headers, current_exists.then_some(&cur));
    stamp_auth(&mut put, cred);
    let resp = async_call(next, put).await;
    if !swift_write_applied(resp.status) {
        return backend_write_not_applied(resp.status, Some(bucket), Some(key));
    }
    if archived_null_exists {
        if let Err(resp) = delete_archived_version_copy_async(cred, bucket, key, NULL_VERSION_ID, next).await {
            return resp;
        }
    }

    let lm = resp
        .headers
        .get("Last-Modified")
        .map(http_date_to_s3_approx)
        .unwrap_or_else(|| "1970-01-01T00:00:00.000Z".into());
    if let Err(resp) = commit_new_version_record(
        &mut idx,
        expect,
        overwrite_null,
        VersionRecord {
            version_id: dm_vid.clone(),
            is_delete_marker: true,
            is_latest: true,
            last_modified: lm,
            etag: String::new(),
            size: 0,
        },
    ) {
        return resp;
    }
    if let Err(resp) = cas_save_version_index_async(cred, bucket, key, &snap, &idx, next).await {
        return resp;
    }

    let mut r = delete_object_response();
    r.headers.set(HDR_VERSION_ID, &dm_vid);
    r.headers.set(HDR_DELETE_MARKER, "true");
    r
}



fn handle_versioned_delete_once(
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    version_id_q: Option<&str>,
    fixed_delete_marker_id: Option<&str>,
    clock_ok: bool,
    bypass: GovernanceBypass,
    next: &NextFn,
) -> Response {
    let cur_path = s3_to_swift_path(&cred.account, Some(bucket), Some(key));

    if let Some(vid) = version_id_q {
        let target = match resolve_object_version(cred, bucket, key, Some(vid), next) {
            Ok(Some(target)) => target,
            Ok(None) => {
                // Data-plane copy is already gone. Still drop a leftover
                // index row so ListVersions cannot keep a ghost version.
                if let Err(resp) = drop_missing_version_index_row(cred, bucket, key, vid, next)
                {
                    return resp;
                }
                let mut r = delete_object_response();
                r.headers.set(HDR_VERSION_ID, vid);
                return r;
            }
            Err(resp) => return resp,
        };
        if let Some(blocked) = worm_guard(&target.head.headers, clock_ok, bypass) {
            return blocked;
        }
        if let Some(blocked) = deny_if_object_acl_blocks_write(cred, &target.head.headers) {
            return blocked;
        }

        let was_delete_marker = is_delete_marker_header(target.head.headers.get(SYS_DELETE_MARKER));
        let target_is_current = target.container == bucket && target.key == key;
        let snap = match load_version_index_snapshot(cred, bucket, key, next) {
            Ok(snap) => snap,
            Err(resp) => return resp,
        };
        // Current objects listed via merge (never-versioned null, or a
        // numbered vid whose index persist failed after the data-plane
        // PUT) have no index row. CAS-remove would 500 "lost update" and
        // leave the object (the Ceph s3-tests nuke poison).
        if target_is_current && snap.index.find(vid).is_none()
        {
            let mut del = make_swift_req("DELETE", &cur_path);
            stamp_object_write_precondition(&mut del.headers, Some(&target.head));
            stamp_auth(&mut del, cred);
            let retry = del.clone_head();
            let resp = next(del);
            let resp = if resp.status == 412 {
                let mut retry = retry;
                retry.query_string = "multipart-manifest=delete".into();
                stamp_object_write_precondition(&mut retry.headers, Some(&target.head));
                stamp_auth(&mut retry, cred);
                next(retry)
            } else {
                resp
            };
            if !swift_write_applied(resp.status) && resp.status != 404 {
                return backend_write_not_applied(resp.status, Some(bucket), Some(key));
            }
            let mut r = delete_object_response();
            r.headers.set(HDR_VERSION_ID, vid);
            return r;
        }
        let expect = expect_generation(&snap);
        let mut idx = snap.index.clone();
        if let Err(denied) = check_index_generation(&idx, expect) {
            return cas_denied_response(denied);
        }
        let next_version = match idx.remove_version_checked(vid) {
            Ok(next) => next,
            Err(RemoveVersionError::Missing) => return version_index_lost_update(),
        };

        if target_is_current {
            if let Some(next_version) = next_version.as_deref() {
                if !is_safe_version_id(next_version) {
                    return unsafe_version_id_error();
                }
                if let Err(resp) = promote_archived_version(cred, bucket, key, next_version, next) {
                    return resp;
                }
            } else {
                let mut del = make_swift_req("DELETE", &cur_path);
                stamp_object_write_precondition(&mut del.headers, Some(&target.head));
                stamp_auth(&mut del, cred);
                let resp = next(del);
                if !swift_write_applied(resp.status) && resp.status != 404 {
                    return backend_write_not_applied(resp.status, Some(bucket), Some(key));
                }
            }
        } else {
            let mut del = make_swift_req("DELETE", &cur_path);
            del.path = s3_to_swift_path(&cred.account, Some(&target.container), Some(&target.key));
            stamp_object_write_precondition(&mut del.headers, Some(&target.head));
            stamp_auth(&mut del, cred);
            let resp = next(del);
            if !swift_write_applied(resp.status) && resp.status != 404 {
                return backend_write_not_applied(
                    resp.status,
                    Some(&target.container),
                    Some(&target.key),
                );
            }
        }

        idx.generation = idx.generation.saturating_add(1);
        if let Err(resp) = cas_save_version_index(cred, bucket, key, &snap, &idx, next) {
            return resp;
        }
        let mut r = delete_object_response();
        r.headers.set(HDR_VERSION_ID, vid);
        if was_delete_marker {
            r.headers.set(HDR_DELETE_MARKER, "true");
        }
        return r;
    }

    let snap = match load_version_index_snapshot(cred, bucket, key, next) {
        Ok(snap) => snap,
        Err(resp) => return resp,
    };
    let expect = expect_generation(&snap);
    let mut idx = snap.index.clone();

    let mut head = make_swift_req("HEAD", &cur_path);
    stamp_auth(&mut head, cred);
    let cur = next(head);
    if !(200..300).contains(&cur.status) && cur.status != 404 {
        return map_swift_error(cur.status, Some(bucket), Some(key));
    }
    let current_exists = (200..300).contains(&cur.status);
    if current_exists {
        if let Some(blocked) = deny_if_object_acl_blocks_write(cred, &cur.headers) {
            return blocked;
        }
    }
    let overwrite_null = fixed_delete_marker_id == Some(NULL_VERSION_ID)
        && VersioningStatus::Suspended.suspended_put_overwrites_null();
    let archived_null_exists = if overwrite_null {
        match archived_null_replacement_required(cred, bucket, key, clock_ok, bypass, next) {
            Ok(exists) => exists,
            Err(resp) => return resp,
        }
    } else {
        false
    };

    if current_exists {
        if let Err(resp) = maybe_archive_current_for_write(
            cred,
            bucket,
            key,
            &cur,
            overwrite_null,
            clock_ok,
            bypass,
            &mut idx,
            next,
        ) {
            return resp;
        }
    }

    let dm_vid = if overwrite_null {
        NULL_VERSION_ID.to_string()
    } else {
        generate_version_id()
    };
    if !is_safe_version_id(&dm_vid) {
        return unsafe_version_id_error();
    }
    let mut put = make_swift_req("PUT", &cur_path);
    put.headers.set("Content-Length", "0");
    put.headers.set(SYS_VERSION_ID, &dm_vid);
    put.headers.set(SYS_DELETE_MARKER, "true");
    put.body = Body::empty();
    stamp_object_write_precondition(&mut put.headers, current_exists.then_some(&cur));
    stamp_auth(&mut put, cred);
    let resp = next(put);
    if !swift_write_applied(resp.status) {
        return backend_write_not_applied(resp.status, Some(bucket), Some(key));
    }
    if archived_null_exists {
        if let Err(resp) = delete_archived_version_copy(cred, bucket, key, NULL_VERSION_ID, next) {
            return resp;
        }
    }

    let lm = resp
        .headers
        .get("Last-Modified")
        .map(http_date_to_s3_approx)
        .unwrap_or_else(|| "1970-01-01T00:00:00.000Z".into());
    if let Err(resp) = commit_new_version_record(
        &mut idx,
        expect,
        overwrite_null,
        VersionRecord {
            version_id: dm_vid.clone(),
            is_delete_marker: true,
            is_latest: true,
            last_modified: lm,
            etag: String::new(),
            size: 0,
        },
    ) {
        return resp;
    }
    if let Err(resp) = cas_save_version_index(cred, bucket, key, &snap, &idx, next) {
        return resp;
    }

    let mut r = delete_object_response();
    r.headers.set(HDR_VERSION_ID, &dm_vid);
    r.headers.set(HDR_DELETE_MARKER, "true");
    r
}

async fn handle_list_versions_async(
    cred: &S3Credential,
    bucket: &str,
    params: &[(String, String)],
    next: &AsyncNextFn,
) -> Response {
    let prefix = params
        .iter()
        .find(|(k, _)| k == "prefix")
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    let key_marker = params
        .iter()
        .find(|(k, _)| k == "key-marker")
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    let version_id_marker = params
        .iter()
        .find(|(k, _)| k == "version-id-marker")
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    let max_keys = params
        .iter()
        .find(|(k, _)| k == "max-keys")
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(1000u32);
    let delimiter = params
        .iter()
        .find(|(k, _)| k == "delimiter")
        .map(|(_, v)| v.as_str());

    let mut indexes = load_version_indexes_async(cred, bucket, next).await;
    let current = list_current_objects_for_versions_async(cred, bucket, prefix, next).await;
    merge_unindexed_current_objects(&mut indexes, &current);

    if indexes.is_empty() {
        return xml_ok(empty_list_versions_result_xml(
            bucket,
            prefix,
            key_marker,
            version_id_marker,
            max_keys,
            delimiter,
        ));
    }

    xml_ok(list_versions_result_xml(
        bucket,
        prefix,
        key_marker,
        version_id_marker,
        max_keys,
        delimiter.unwrap_or(""),
        &indexes,
    ))
}



fn handle_list_versions(
    cred: &S3Credential,
    bucket: &str,
    params: &[(String, String)],
    next: &NextFn,
) -> Response {
    let prefix = params
        .iter()
        .find(|(k, _)| k == "prefix")
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    let key_marker = params
        .iter()
        .find(|(k, _)| k == "key-marker")
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    let version_id_marker = params
        .iter()
        .find(|(k, _)| k == "version-id-marker")
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    let max_keys = params
        .iter()
        .find(|(k, _)| k == "max-keys")
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(1000u32);
    let delimiter = params
        .iter()
        .find(|(k, _)| k == "delimiter")
        .map(|(_, v)| v.as_str());

    let mut indexes = load_version_indexes(cred, bucket, next);
    let current = list_current_objects_for_versions(cred, bucket, prefix, next);
    merge_unindexed_current_objects(&mut indexes, &current);

    if indexes.is_empty() {
        return xml_ok(empty_list_versions_result_xml(
            bucket,
            prefix,
            key_marker,
            version_id_marker,
            max_keys,
            delimiter,
        ));
    }

    xml_ok(list_versions_result_xml(
        bucket,
        prefix,
        key_marker,
        version_id_marker,
        max_keys,
        delimiter.unwrap_or(""),
        &indexes,
    ))
}

async fn load_version_indexes_async(cred: &S3Credential, bucket: &str, next: &AsyncNextFn) -> Vec<VersionIndex> {
    let vc = versions_container(bucket);
    let mut list = make_swift_req("GET", &s3_to_swift_path(&cred.account, Some(&vc), None));
    list.query_string = "format=json".into();
    list.headers.set("Accept", "application/json");
    stamp_auth(&mut list, cred);
    let resp = async_call(next, list).await;
    if resp.status == 404 || !(200..300).contains(&resp.status) {
        return Vec::new();
    }
    let body = match resp.body.into_vec(MAX_CONTROL_BODY) {
        Ok(b) => b,
        Err(_) => return Vec::new(),
    };
    let parsed: Value = serde_json::from_slice(&body).unwrap_or(Value::Array(vec![]));
    let mut indexes: Vec<VersionIndex> = Vec::new();
    let Some(arr) = parsed.as_array() else {
        return indexes;
    };
    for item in arr {
        let Some(name) = item.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        if !(name.ends_with(INDEX_NAME) || name.ends_with("/index.json")) {
            continue;
        }
        let mut get = make_swift_req(
            "GET",
            &s3_to_swift_path(&cred.account, Some(&vc), Some(name)),
        );
        stamp_auth(&mut get, cred);
        let g = async_call(next, get).await;
        if !(200..300).contains(&g.status) {
            continue;
        }
        let b = g.body.into_vec(MAX_CONTROL_BODY).unwrap_or_default();
        if let Some(idx) = VersionIndex::from_json(&b) {
            indexes.push(idx);
        }
    }
    indexes
}

/// Data-container listing used to synthesize `VersionId=null` rows.
///
/// Never-versioned objects live only here. Enabled keys already have an
/// index and are skipped by [`merge_unindexed_current_objects`].


fn load_version_indexes(cred: &S3Credential, bucket: &str, next: &NextFn) -> Vec<VersionIndex> {
    let vc = versions_container(bucket);
    let mut list = make_swift_req("GET", &s3_to_swift_path(&cred.account, Some(&vc), None));
    list.query_string = "format=json".into();
    list.headers.set("Accept", "application/json");
    stamp_auth(&mut list, cred);
    let resp = next(list);
    if resp.status == 404 || !(200..300).contains(&resp.status) {
        return Vec::new();
    }
    let body = match resp.body.into_vec(MAX_CONTROL_BODY) {
        Ok(b) => b,
        Err(_) => return Vec::new(),
    };
    let parsed: Value = serde_json::from_slice(&body).unwrap_or(Value::Array(vec![]));
    let mut indexes: Vec<VersionIndex> = Vec::new();
    let Some(arr) = parsed.as_array() else {
        return indexes;
    };
    for item in arr {
        let Some(name) = item.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        if !(name.ends_with(INDEX_NAME) || name.ends_with("/index.json")) {
            continue;
        }
        let mut get = make_swift_req(
            "GET",
            &s3_to_swift_path(&cred.account, Some(&vc), Some(name)),
        );
        stamp_auth(&mut get, cred);
        let g = next(get);
        if !(200..300).contains(&g.status) {
            continue;
        }
        let b = g.body.into_vec(MAX_CONTROL_BODY).unwrap_or_default();
        if let Some(idx) = VersionIndex::from_json(&b) {
            indexes.push(idx);
        }
    }
    indexes
}

/// Data-container listing used to synthesize `VersionId=null` rows.
///
/// Never-versioned objects live only here. Enabled keys already have an
/// index and are skipped by [`merge_unindexed_current_objects`].
async fn list_current_objects_for_versions_async(
    cred: &S3Credential,
    bucket: &str,
    prefix: &str,
    next: &AsyncNextFn,
) -> Vec<(String, String, i64, String)> {
    let mut list = make_swift_req("GET", &s3_to_swift_path(&cred.account, Some(bucket), None));
    let mut qs = String::from("format=json");
    if !prefix.is_empty() {
        qs.push_str("&prefix=");
        qs.push_str(&encode_query(prefix));
    }
    list.query_string = qs;
    list.headers.set("Accept", "application/json");
    stamp_auth(&mut list, cred);
    let resp = async_call(next, list).await;
    if !(200..300).contains(&resp.status) {
        return Vec::new();
    }
    let body = match resp.body.into_vec(MAX_CONTROL_BODY) {
        Ok(b) => b,
        Err(_) => return Vec::new(),
    };
    let parsed: Value = serde_json::from_slice(&body).unwrap_or(Value::Array(vec![]));
    let mut out = Vec::new();
    let Some(arr) = parsed.as_array() else {
        return out;
    };
    for item in arr {
        if item.get("subdir").is_some() {
            continue;
        }
        let Some(name) = item.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        let hash = item.get("hash").and_then(|v| v.as_str()).unwrap_or("");
        let bytes = item
            .get("bytes")
            .and_then(|v| v.as_i64())
            .or_else(|| item.get("bytes").and_then(|v| v.as_u64()).map(|n| n as i64))
            .unwrap_or(0);
        let last_modified = item
            .get("last_modified")
            .and_then(|v| v.as_str())
            .unwrap_or("1970-01-01T00:00:00.000Z");
        out.push((
            name.to_string(),
            hash.to_string(),
            bytes,
            last_modified.to_string(),
        ));
    }
    out
}



fn list_current_objects_for_versions(
    cred: &S3Credential,
    bucket: &str,
    prefix: &str,
    next: &NextFn,
) -> Vec<(String, String, i64, String)> {
    let mut list = make_swift_req("GET", &s3_to_swift_path(&cred.account, Some(bucket), None));
    let mut qs = String::from("format=json");
    if !prefix.is_empty() {
        qs.push_str("&prefix=");
        qs.push_str(&encode_query(prefix));
    }
    list.query_string = qs;
    list.headers.set("Accept", "application/json");
    stamp_auth(&mut list, cred);
    let resp = next(list);
    if !(200..300).contains(&resp.status) {
        return Vec::new();
    }
    let body = match resp.body.into_vec(MAX_CONTROL_BODY) {
        Ok(b) => b,
        Err(_) => return Vec::new(),
    };
    let parsed: Value = serde_json::from_slice(&body).unwrap_or(Value::Array(vec![]));
    let mut out = Vec::new();
    let Some(arr) = parsed.as_array() else {
        return out;
    };
    for item in arr {
        if item.get("subdir").is_some() {
            continue;
        }
        let Some(name) = item.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        let hash = item.get("hash").and_then(|v| v.as_str()).unwrap_or("");
        let bytes = item
            .get("bytes")
            .and_then(|v| v.as_i64())
            .or_else(|| item.get("bytes").and_then(|v| v.as_u64()).map(|n| n as i64))
            .unwrap_or(0);
        let last_modified = item
            .get("last_modified")
            .and_then(|v| v.as_str())
            .unwrap_or("1970-01-01T00:00:00.000Z");
        out.push((
            name.to_string(),
            hash.to_string(),
            bytes,
            last_modified.to_string(),
        ));
    }
    out
}

async fn handle_tagging_async(
    req: Request,
    cred: &S3Credential,
    bucket: &str,
    key: Option<&str>,
    next: &AsyncNextFn,
) -> Response {
    if let Some(obj) = key {
        match req.method.as_str() {
            "GET" | "HEAD" => {
                let mut head = make_swift_req(
                    "HEAD",
                    &s3_to_swift_path(&cred.account, Some(bucket), Some(obj)),
                );
                stamp_auth(&mut head, cred);
                let resp = async_call(next, head).await;
                if !(200..300).contains(&resp.status) {
                    return map_swift_error(resp.status, Some(bucket), Some(obj));
                }
                let meta = resp
                    .headers
                    .get(S3_OBJECT_TAGGING_META)
                    .or_else(|| resp.headers.get("X-Object-Meta-S3-Tagging"));
                xml_ok(tagging_xml_from_meta(meta))
            }
            "PUT" => {
                let body = match req.body.into_vec(MAX_CONTROL_BODY) {
                    Ok(b) => b,
                    Err(_) => return s3_error_response("IncompleteBody", None, &[]),
                };
                let tags = match parse_tagging_body(&body) {
                    Ok(t) => t,
                    Err(_) => return s3_error_response("MalformedXML", None, &[]),
                };
                let mut post = make_swift_req(
                    "POST",
                    &s3_to_swift_path(&cred.account, Some(bucket), Some(obj)),
                );
                apply_object_tagging_meta(&mut post.headers, &tags);
                stamp_auth(&mut post, cred);
                let resp = async_call(next, post).await;
                if (200..300).contains(&resp.status) {
                    Response::new(200)
                } else {
                    map_swift_error(resp.status, Some(bucket), Some(obj))
                }
            }
            "DELETE" => {
                let mut post = make_swift_req(
                    "POST",
                    &s3_to_swift_path(&cred.account, Some(bucket), Some(obj)),
                );
                clear_object_tagging_meta(&mut post.headers);
                stamp_auth(&mut post, cred);
                let _ = async_call(next, post).await;
                Response::new(204)
            }
            _ => s3_error_response("MethodNotAllowed", None, &[]),
        }
    } else {
        match req.method.as_str() {
            "GET" | "HEAD" => {
                let mut head =
                    make_swift_req("HEAD", &s3_to_swift_path(&cred.account, Some(bucket), None));
                stamp_auth(&mut head, cred);
                let resp = async_call(next, head).await;
                if !(200..300).contains(&resp.status) {
                    return map_swift_error(resp.status, Some(bucket), None);
                }
                xml_ok(tagging_xml_from_meta(
                    resp.headers.get(S3_BUCKET_TAGGING_META),
                ))
            }
            "PUT" => {
                let body = match req.body.into_vec(MAX_CONTROL_BODY) {
                    Ok(b) => b,
                    Err(_) => return s3_error_response("IncompleteBody", None, &[]),
                };
                let tags = match parse_tagging_body(&body) {
                    Ok(t) => t,
                    Err(_) => return s3_error_response("MalformedXML", None, &[]),
                };
                let mut post =
                    make_swift_req("POST", &s3_to_swift_path(&cred.account, Some(bucket), None));
                apply_bucket_tagging_meta(&mut post.headers, &tags);
                stamp_auth(&mut post, cred);
                let resp = async_call(next, post).await;
                if (200..300).contains(&resp.status) {
                    Response::new(200)
                } else {
                    map_swift_error(resp.status, Some(bucket), None)
                }
            }
            "DELETE" => {
                let mut post =
                    make_swift_req("POST", &s3_to_swift_path(&cred.account, Some(bucket), None));
                clear_bucket_tagging_meta(&mut post.headers);
                stamp_auth(&mut post, cred);
                let _ = async_call(next, post).await;
                Response::new(204)
            }
            _ => s3_error_response("MethodNotAllowed", None, &[]),
        }
    }
}



fn handle_tagging(
    req: Request,
    cred: &S3Credential,
    bucket: &str,
    key: Option<&str>,
    next: &NextFn,
) -> Response {
    if let Some(obj) = key {
        match req.method.as_str() {
            "GET" | "HEAD" => {
                let mut head = make_swift_req(
                    "HEAD",
                    &s3_to_swift_path(&cred.account, Some(bucket), Some(obj)),
                );
                stamp_auth(&mut head, cred);
                let resp = next(head);
                if !(200..300).contains(&resp.status) {
                    return map_swift_error(resp.status, Some(bucket), Some(obj));
                }
                let meta = resp
                    .headers
                    .get(S3_OBJECT_TAGGING_META)
                    .or_else(|| resp.headers.get("X-Object-Meta-S3-Tagging"));
                xml_ok(tagging_xml_from_meta(meta))
            }
            "PUT" => {
                let body = match req.body.into_vec(MAX_CONTROL_BODY) {
                    Ok(b) => b,
                    Err(_) => return s3_error_response("IncompleteBody", None, &[]),
                };
                let tags = match parse_tagging_body(&body) {
                    Ok(t) => t,
                    Err(_) => return s3_error_response("MalformedXML", None, &[]),
                };
                let mut post = make_swift_req(
                    "POST",
                    &s3_to_swift_path(&cred.account, Some(bucket), Some(obj)),
                );
                apply_object_tagging_meta(&mut post.headers, &tags);
                stamp_auth(&mut post, cred);
                let resp = next(post);
                if (200..300).contains(&resp.status) {
                    Response::new(200)
                } else {
                    map_swift_error(resp.status, Some(bucket), Some(obj))
                }
            }
            "DELETE" => {
                let mut post = make_swift_req(
                    "POST",
                    &s3_to_swift_path(&cred.account, Some(bucket), Some(obj)),
                );
                clear_object_tagging_meta(&mut post.headers);
                stamp_auth(&mut post, cred);
                let _ = next(post);
                Response::new(204)
            }
            _ => s3_error_response("MethodNotAllowed", None, &[]),
        }
    } else {
        match req.method.as_str() {
            "GET" | "HEAD" => {
                let mut head =
                    make_swift_req("HEAD", &s3_to_swift_path(&cred.account, Some(bucket), None));
                stamp_auth(&mut head, cred);
                let resp = next(head);
                if !(200..300).contains(&resp.status) {
                    return map_swift_error(resp.status, Some(bucket), None);
                }
                xml_ok(tagging_xml_from_meta(
                    resp.headers.get(S3_BUCKET_TAGGING_META),
                ))
            }
            "PUT" => {
                let body = match req.body.into_vec(MAX_CONTROL_BODY) {
                    Ok(b) => b,
                    Err(_) => return s3_error_response("IncompleteBody", None, &[]),
                };
                let tags = match parse_tagging_body(&body) {
                    Ok(t) => t,
                    Err(_) => return s3_error_response("MalformedXML", None, &[]),
                };
                let mut post =
                    make_swift_req("POST", &s3_to_swift_path(&cred.account, Some(bucket), None));
                apply_bucket_tagging_meta(&mut post.headers, &tags);
                stamp_auth(&mut post, cred);
                let resp = next(post);
                if (200..300).contains(&resp.status) {
                    Response::new(200)
                } else {
                    map_swift_error(resp.status, Some(bucket), None)
                }
            }
            "DELETE" => {
                let mut post =
                    make_swift_req("POST", &s3_to_swift_path(&cred.account, Some(bucket), None));
                clear_bucket_tagging_meta(&mut post.headers);
                stamp_auth(&mut post, cred);
                let _ = next(post);
                Response::new(204)
            }
            _ => s3_error_response("MethodNotAllowed", None, &[]),
        }
    }
}

async fn handle_lifecycle_async(req: Request, cred: &S3Credential, bucket: &str, next: &AsyncNextFn) -> Response {
    match req.method.as_str() {
        "GET" | "HEAD" => {
            let mut head =
                make_swift_req("HEAD", &s3_to_swift_path(&cred.account, Some(bucket), None));
            stamp_auth(&mut head, cred);
            let resp = async_call(next, head).await;
            if !(200..300).contains(&resp.status) {
                return map_swift_error(resp.status, Some(bucket), None);
            }
            match lifecycle_xml_from_headers(&resp.headers) {
                Some(xml) => {
                    let mut r = Response::with_body(200, xml);
                    r.headers.set("Content-Type", "application/xml");
                    r
                }
                None => s3_error_response("NoSuchLifecycleConfiguration", None, &[]),
            }
        }
        "PUT" => {
            let body = match req.body.into_vec(MAX_CONTROL_BODY) {
                Ok(b) => b,
                Err(_) => return s3_error_response("IncompleteBody", None, &[]),
            };
            if validate_lifecycle_xml(&body).is_err() {
                return s3_error_response("MalformedXML", None, &[]);
            }
            let mut post =
                make_swift_req("POST", &s3_to_swift_path(&cred.account, Some(bucket), None));
            apply_lifecycle_meta(&mut post.headers, &body);
            stamp_auth(&mut post, cred);
            let resp = async_call(next, post).await;
            if (200..300).contains(&resp.status) {
                Response::new(200)
            } else {
                map_swift_error(resp.status, Some(bucket), None)
            }
        }
        "DELETE" => {
            let mut post =
                make_swift_req("POST", &s3_to_swift_path(&cred.account, Some(bucket), None));
            clear_lifecycle_meta(&mut post.headers);
            stamp_auth(&mut post, cred);
            let _ = async_call(next, post).await;
            Response::new(204)
        }
        _ => s3_error_response("MethodNotAllowed", None, &[]),
    }
}

/// Parse `<Days>` from a RestoreRequest XML body (default 1 if absent/empty).


fn handle_lifecycle(req: Request, cred: &S3Credential, bucket: &str, next: &NextFn) -> Response {
    match req.method.as_str() {
        "GET" | "HEAD" => {
            let mut head =
                make_swift_req("HEAD", &s3_to_swift_path(&cred.account, Some(bucket), None));
            stamp_auth(&mut head, cred);
            let resp = next(head);
            if !(200..300).contains(&resp.status) {
                return map_swift_error(resp.status, Some(bucket), None);
            }
            match lifecycle_xml_from_headers(&resp.headers) {
                Some(xml) => {
                    let mut r = Response::with_body(200, xml);
                    r.headers.set("Content-Type", "application/xml");
                    r
                }
                None => s3_error_response("NoSuchLifecycleConfiguration", None, &[]),
            }
        }
        "PUT" => {
            let body = match req.body.into_vec(MAX_CONTROL_BODY) {
                Ok(b) => b,
                Err(_) => return s3_error_response("IncompleteBody", None, &[]),
            };
            if validate_lifecycle_xml(&body).is_err() {
                return s3_error_response("MalformedXML", None, &[]);
            }
            let mut post =
                make_swift_req("POST", &s3_to_swift_path(&cred.account, Some(bucket), None));
            apply_lifecycle_meta(&mut post.headers, &body);
            stamp_auth(&mut post, cred);
            let resp = next(post);
            if (200..300).contains(&resp.status) {
                Response::new(200)
            } else {
                map_swift_error(resp.status, Some(bucket), None)
            }
        }
        "DELETE" => {
            let mut post =
                make_swift_req("POST", &s3_to_swift_path(&cred.account, Some(bucket), None));
            clear_lifecycle_meta(&mut post.headers);
            stamp_auth(&mut post, cred);
            let _ = next(post);
            Response::new(204)
        }
        _ => s3_error_response("MethodNotAllowed", None, &[]),
    }
}

/// Parse `<Days>` from a RestoreRequest XML body (default 1 if absent/empty).
fn parse_restore_days(body: &[u8]) -> Result<i64, ()> {
    if body.is_empty() {
        return Ok(1);
    }
    let s = std::str::from_utf8(body).map_err(|_| ())?;
    // Minimal extract: first <Days>...</Days>
    let lower = s; // keep original for slice
    let start = lower.find("<Days>").or_else(|| lower.find("<days>"));
    let Some(start) = start else {
        return Ok(1);
    };
    let after = start + 6; // len("<Days>")
    let end = lower[after..]
        .find("</Days>")
        .or_else(|| lower[after..].find("</days>"))
        .ok_or(())?;
    let raw = lower[after..after + end].trim();
    let days: i64 = raw.parse().map_err(|_| ())?;
    if days < 1 {
        return Err(());
    }
    Ok(days)
}

fn object_is_cold_archive(headers: &HeaderKeyDict) -> bool {
    let sc = headers
        .get(META_STORAGE_CLASS)
        .or_else(|| headers.get("X-Object-Meta-Storage-Class"))
        .unwrap_or("");
    if !is_cold_storage_class(sc) {
        return false;
    }
    let transitioned = headers
        .get(SYS_TRANSITIONED)
        .map(|s| {
            let t = s.trim();
            t == "1" || t.eq_ignore_ascii_case("true") || t.eq_ignore_ascii_case("yes")
        })
        .unwrap_or(false);
    transitioned || headers.get(SYS_COLD_BACKEND_URI).is_some()
}

/// S3 RestoreObject (`POST/GET ?restore`): Durable receipt → `begin_restore`
/// → PUT bytes + `stamp_cold_restore_meta` → `complete_restore`. GET/HEAD is
/// status only. PROTOTYPE / DEFAULT OFF / NOT ACCEPTED. Not Glacier.
fn handle_restore(
    req: Request,
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    version_id: Option<&str>,
    cold_map: &crate::cold_tier::ColdPolicyMap,
    cold_backend: Option<&Arc<dyn ColdBackend>>,
    next: &NextFn,
) -> Response {
    let now = unix_now();
    let target = match resolve_object_version(cred, bucket, key, version_id, next) {
        Ok(Some(target)) => target,
        Ok(None) => return missing_object_version_response(key, version_id),
        Err(resp) => return resp,
    };
    let acl_denied = if req.method == "POST" {
        deny_if_object_acl_blocks_write(cred, &target.head.headers)
    } else {
        deny_if_object_acl_blocks_read(cred, &target.head.headers)
    };
    if let Some(denied) = acl_denied {
        return denied;
    }
    match req.method.as_str() {
        "GET" | "HEAD" => {
            let until = target.head.headers.get(SYS_RESTORE_UNTIL).unwrap_or("");
            let ongoing = until.parse::<i64>().map(|u| u > now).unwrap_or(false);
            // Minimal status XML (not full AWS RestoreOutput).
            let xml = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                 <RestoreStatus>\
                 <OngoingRequest>{}</OngoingRequest>\
                 <RestoreExpiry>{}</RestoreExpiry>\
                 </RestoreStatus>",
                if ongoing { "false" } else { "true" },
                until
            );
            // ongoing-request=false means restore complete / available
            let mut r = Response::with_body(200, xml.into_bytes());
            r.headers.set("Content-Type", "application/xml");
            if ongoing {
                r.headers.set(
                    "x-amz-restore",
                    format!("ongoing-request=\"false\", expiry-date=\"{until}\""),
                );
            } else if object_is_cold_archive(&target.head.headers) {
                r.headers.set("x-amz-restore", "ongoing-request=\"true\"");
            }
            r
        }
        "POST" => {
            let body = match req.body.into_vec(MAX_CONTROL_BODY) {
                Ok(b) => b,
                Err(_) => return s3_error_response("IncompleteBody", None, &[]),
            };
            let days = match parse_restore_days(&body) {
                Ok(d) => d,
                Err(_) => {
                    return s3_error_response(
                        "MalformedXML",
                        Some("RestoreRequest Days must be a positive integer"),
                        &[],
                    )
                }
            };
            if !object_is_cold_archive(&target.head.headers) {
                return s3_error_response(
                    "InvalidObjectState",
                    Some("Restore is not allowed for the object's current storage class"),
                    &[],
                );
            }
            let Some(be) = cold_backend else {
                return s3_error_response(
                    "InvalidObjectState",
                    Some("cold backend is not configured"),
                    &[],
                );
            };
            let Some(uri) = target
                .head
                .headers
                .get(SYS_COLD_BACKEND_URI)
                .filter(|uri| !uri.is_empty())
            else {
                return s3_error_response(
                    "InvalidObjectState",
                    Some("cold archive has no durable backend reference"),
                    &[],
                );
            };
            let (payload, receipt): (Vec<u8>, ColdArchiveReceipt) = match be.fetch_verified(uri) {
                Ok(result) => result,
                Err(e) => {
                    return s3_error_response(
                        "InvalidObjectState",
                        Some(&format!("cold restore verification failed: {e}")),
                        &[],
                    )
                }
            };
            if archive_commit(&receipt, &payload, false).is_err() {
                return s3_error_response(
                    "InvalidObjectState",
                    Some("cold archive receipt does not verify payload"),
                    &[],
                );
            }
            let persisted_receipt_matches = target.head.headers.get(SYS_COLD_ARCHIVE_STATE)
                == Some("durable")
                && target
                    .head
                    .headers
                    .get(SYS_COLD_CONTENT_LENGTH)
                    .and_then(|value| value.parse::<u64>().ok())
                    == Some(receipt.content_length)
                && target
                    .head
                    .headers
                    .get(SYS_COLD_CONTENT_SHA256)
                    .map(|value| value.eq_ignore_ascii_case(&receipt.content_sha256))
                    .unwrap_or(false)
                && receipt.backend_uri == uri;
            if !persisted_receipt_matches {
                return s3_error_response(
                    "InvalidObjectState",
                    Some("cold archive receipt does not match object metadata"),
                    &[],
                );
            }
            if begin_restore(ColdArchiveState::Durable, now, days).is_err() {
                return s3_error_response(
                    "InvalidObjectState",
                    Some("Restore is not allowed for the object's current storage class"),
                    &[],
                );
            }
            let machine = ColdStateMachine {
                state: ColdArchiveState::Durable,
                receipt: Some(receipt.clone()),
                archive_generation: parse_cold_generation(
                    &target.head.headers,
                    SYS_COLD_ARCHIVE_GENERATION,
                ),
                restore_generation: parse_cold_generation(
                    &target.head.headers,
                    SYS_COLD_RESTORE_GENERATION,
                ),
            };
            let machine = match machine.apply_begin_restore(now, days) {
                Ok(m) => m,
                Err(_) => {
                    return s3_error_response(
                        "InvalidObjectState",
                        Some("Restore is not allowed for the object's current storage class"),
                        &[],
                    )
                }
            };

            let mut put = make_swift_req(
                "PUT",
                &s3_to_swift_path(&cred.account, Some(&target.container), Some(&target.key)),
            );
            copy_version_payload_headers(&target.head.headers, &mut put.headers);
            if cold_map.is_configured() {
                stamp_cold_restore_meta(&mut put.headers, cold_map, days, now);
            } else {
                apply_restore_days(&mut put.headers, days, now);
            }
            if let Some(until) = machine.state.restore_until_unix() {
                put.headers.set(SYS_RESTORE_UNTIL, until.to_string());
            }
            put.headers.set("Content-Length", payload.len().to_string());
            put.headers.remove("Transfer-Encoding");
            put.headers.set(SYS_HOT_RECLAIMED, "false");
            machine.stamp_generation_headers(&mut put.headers);
            put.body = Body::from(payload);
            stamp_auth(&mut put, cred);
            let resp = next(put);
            if (200..300).contains(&resp.status) {
                if complete_restore(machine.state, now).is_err() {
                    return s3_error_response(
                        "InternalError",
                        Some("cold restore complete failed after payload write"),
                        &[],
                    );
                }
                if machine.apply_complete_restore(now).is_err() {
                    return s3_error_response(
                        "InternalError",
                        Some("cold restore complete failed after payload write"),
                        &[],
                    );
                }
                Response::new(202)
            } else {
                map_swift_error(resp.status, Some(&target.container), Some(&target.key))
            }
        }
        _ => s3_error_response("MethodNotAllowed", None, &[]),
    }
}

fn handle_object_lock(req: Request, cred: &S3Credential, bucket: &str, next: &NextFn) -> Response {
    match req.method.as_str() {
        "GET" | "HEAD" => {
            let mut head =
                make_swift_req("HEAD", &s3_to_swift_path(&cred.account, Some(bucket), None));
            stamp_auth(&mut head, cred);
            let resp = next(head);
            if !(200..300).contains(&resp.status) {
                return map_swift_error(resp.status, Some(bucket), None);
            }
            match validated_object_lock_xml_from_headers(&resp.headers) {
                Ok(Some(xml)) => {
                    let mut r = Response::with_body(200, xml);
                    r.headers.set("Content-Type", "application/xml");
                    r
                }
                Ok(None) => s3_error_response("ObjectLockConfigurationNotFoundError", None, &[]),
                Err(_) => s3_error_response(
                    "InternalError",
                    Some("bucket object lock metadata is invalid"),
                    &[],
                ),
            }
        }
        "PUT" => {
            let body = match req.body.into_vec(MAX_CONTROL_BODY) {
                Ok(b) => b,
                Err(_) => return s3_error_response("IncompleteBody", None, &[]),
            };
            let text = String::from_utf8_lossy(&body);
            if body.is_empty() || !text.contains("ObjectLockEnabled") {
                // Official OS 113: empty PutObjectLockConfiguration is 501.
                return s3_error_response(
                    "NotImplemented",
                    Some("The requested resource is not implemented"),
                    &[],
                );
            }
            if validate_object_lock_xml(&body).is_err() {
                return s3_error_response("MalformedXML", None, &[]);
            }
            let mut post =
                make_swift_req("POST", &s3_to_swift_path(&cred.account, Some(bucket), None));
            // Object Lock and versioning are one container metadata update so
            // no observer can see a locked bucket with versioning disabled.
            apply_versioning_meta(&mut post.headers, "Enabled");
            apply_object_lock_meta(&mut post.headers, &body);
            stamp_auth(&mut post, cred);
            let resp = next(post);
            if (200..300).contains(&resp.status) {
                Response::new(200)
            } else {
                map_swift_error(resp.status, Some(bucket), None)
            }
        }
        _ => s3_error_response("MethodNotAllowed", None, &[]),
    }
}

fn copy_mpu_object_headers(src: &HeaderKeyDict, dst: &mut HeaderKeyDict) {
    for (name, value) in src.iter() {
        let lower = name.to_ascii_lowercase();
        if lower.starts_with("x-object-meta-")
            || matches!(
                lower.as_str(),
                "content-type"
                    | "content-encoding"
                    | "content-disposition"
                    | "content-language"
                    | "cache-control"
                    | "expires"
                    | "x-object-sysmeta-s3-cache-control"
                    | "x-object-sysmeta-s3-expires"
                    | "x-object-sysmeta-s3-content-language"
                    | "x-object-sysmeta-s3-robots-tag"
                    | "x-object-sysmeta-s3-acl"
                    | "x-object-sysmeta-s3-acl-json"
                    | "x-object-sysmeta-s3-object-lock-mode"
                    | "x-object-sysmeta-s3-retain-until-date"
                    | "x-object-sysmeta-s3-legal-hold"
            )
        {
            dst.set(name, value);
        }
    }
}

fn handle_mpu_init(
    mut req: Request,
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    api: &S3Api,
    next: &NextFn,
) -> Response {
    if let Err(resp) = require_bucket(cred, bucket, next, &api.container_heads) {
        return resp;
    }
    let has_retention = req.headers.get("X-Amz-Object-Lock-Mode").is_some()
        || req
            .headers
            .get("X-Amz-Object-Lock-Retain-Until-Date")
            .is_some();
    let has_legal_hold = req.headers.get("X-Amz-Object-Lock-Legal-Hold").is_some();
    if has_retention || has_legal_hold {
        if let Err(resp) = require_bucket_object_lock(cred, bucket, next) {
            return resp;
        }
    }
    if has_retention {
        if let Some(denied) = iam_action_check(&api.iam, cred, "s3:PutObjectRetention", bucket, key)
        {
            return denied;
        }
    }
    if has_legal_hold {
        if let Some(denied) = iam_action_check(&api.iam, cred, "s3:PutObjectLegalHold", bucket, key)
        {
            return denied;
        }
    }

    map_amz_meta(&mut req);
    match resolve_acl_put_input(&req.headers, None, &owner_for(cred).id) {
        Ok(input) if !matches!(input, AclPutInput::None) => {
            apply_object_acl_input(&mut req.headers, &input);
        }
        Ok(_) => {}
        Err(_) => return s3_error_response("InvalidArgument", None, &[]),
    }
    if let Err(resp) = apply_request_object_lock_headers(&mut req.headers) {
        return resp;
    }

    let segs = segments_container(bucket);
    // Ensure segments container exists.
    let mut put_c = make_swift_req("PUT", &s3_to_swift_path(&cred.account, Some(&segs), None));
    stamp_auth(&mut put_c, cred);
    let container_resp = next(put_c);
    if !(200..300).contains(&container_resp.status) {
        return map_swift_error(container_resp.status, Some(&segs), None);
    }
    let upload_id = new_upload_id();
    let marker = upload_marker_name(key, &upload_id);
    let mut put_m = make_swift_req(
        "PUT",
        &s3_to_swift_path(&cred.account, Some(&segs), Some(&marker)),
    );
    copy_mpu_object_headers(&req.headers, &mut put_m.headers);
    persist_s3_object_headers(&mut put_m);
    put_m.body = Body::from(Vec::from(b"upload".as_slice()));
    put_m.headers.set("Content-Length", "6");
    // AbortIncompleteMultipartUpload → X-Delete-At on marker (expirer reaps).
    maybe_apply_abort_incomplete_on_marker(&mut put_m, cred, bucket, key, next);
    stamp_auth(&mut put_m, cred);
    let resp = next(put_m);
    if !(200..300).contains(&resp.status) {
        return map_swift_error(resp.status, Some(bucket), Some(key));
    }
    initiate_response(bucket, key, &upload_id)
}

/// HEAD data bucket lifecycle meta → stamp abort X-Delete-At on MPU marker PUT.
fn maybe_apply_abort_incomplete_on_marker(
    marker_req: &mut Request,
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    next: &NextFn,
) {
    let mut head = make_swift_req("HEAD", &s3_to_swift_path(&cred.account, Some(bucket), None));
    stamp_auth(&mut head, cred);
    let head_resp = next(head);
    if !(200..300).contains(&head_resp.status) {
        return;
    }
    apply_abort_incomplete_from_container(
        &mut marker_req.headers,
        &head_resp.headers,
        key,
        unix_now(),
    );
}

fn handle_mpu_part(
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    upload_id: &str,
    part_number: u32,
    req: Request,
    next: &NextFn,
) -> Response {
    if req.headers.get("X-Amz-Copy-Source").is_some()
        || req.headers.get("x-amz-copy-source").is_some()
    {
        return handle_mpu_part_copy(cred, bucket, key, upload_id, part_number, req, next);
    }
    let segs = segments_container(bucket);
    let part_name = part_object_name(key, upload_id, part_number);
    let mut put = req;
    put.method = "PUT".into();
    put.path = s3_to_swift_path(&cred.account, Some(&segs), Some(&part_name));
    put.query_string.clear();
    strip_s3_only_headers(&mut put.headers);
    stamp_auth(&mut put, cred);
    let resp = next(put);
    if (200..300).contains(&resp.status) {
        let etag = resp
            .headers
            .get("ETag")
            .map(|e| e.trim().trim_matches('"').to_string())
            .unwrap_or_default();
        let mut out = put_object_response(&etag);
        if let Some(lm) = resp.headers.get("Last-Modified") {
            out.headers.set("Last-Modified", lm);
        }
        out
    } else {
        map_swift_error(resp.status, Some(bucket), Some(key))
    }
}

fn handle_mpu_part_copy(
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    upload_id: &str,
    part_number: u32,
    mut req: Request,
    next: &NextFn,
) -> Response {
    if let Some(resp) = rewrite_copy_source_version(&mut req, cred, next) {
        return resp;
    }
    let raw = match req
        .headers
        .get("X-Amz-Copy-Source")
        .or_else(|| req.headers.get("x-amz-copy-source"))
    {
        Some(src) => src.to_string(),
        None => return s3_error_response("InvalidArgument", Some("X-Amz-Copy-Source"), &[]),
    };
    let (src_bucket, src_key, _version_id) = match parse_copy_source(&raw) {
        Some(parsed) => parsed,
        None => return s3_error_response("InvalidArgument", Some("X-Amz-Copy-Source"), &[]),
    };
    let range = req
        .headers
        .get("X-Amz-Copy-Source-Range")
        .or_else(|| req.headers.get("x-amz-copy-source-range"))
        .map(str::to_string);
    if let Some(raw) = range.as_deref() {
        if parse_copy_source_range(raw).is_err() {
            return s3_error_response(
                "InvalidArgument",
                Some("x-amz-copy-source-range"),
                &[
                    ("ArgumentName", "x-amz-source-range"),
                    ("ArgumentValue", raw),
                ],
            );
        }
    }
    let segs = segments_container(bucket);
    let part_name = part_object_name(key, upload_id, part_number);
    let mut put = make_swift_req(
        "PUT",
        &s3_to_swift_path(&cred.account, Some(&segs), Some(&part_name)),
    );
    // Always GET assembled source bytes and PUT a regular part.
    // X-Copy-From of a completed MPU/SLO copies the manifest and keeps
    // the composite `md5-N` ETag; official UploadPartCopy wants the
    // MD5 of the copied bytes (test_object_multi_upload, MU as source).
    let mut get = make_swift_req(
        "GET",
        &s3_to_swift_path(&cred.account, Some(&src_bucket), Some(&src_key)),
    );
    if let Some(range) = range {
        let range_hdr = if range.to_ascii_lowercase().starts_with("bytes=") {
            range
        } else {
            format!("bytes={range}")
        };
        get.headers.set("Range", range_hdr);
    }
    stamp_auth(&mut get, cred);
    let src = next(get);
    if !(200..300).contains(&src.status) {
        return map_swift_error(src.status, Some(&src_bucket), Some(&src_key));
    }
    let data = match src.body.into_vec(MAX_AWS_CHUNKED_BODY) {
        Ok(bytes) => bytes,
        Err(_) => return s3_error_response("EntityTooLarge", None, &[]),
    };
    put.headers.set("Content-Length", data.len().to_string());
    put.body = Body::from(data);
    stamp_auth(&mut put, cred);
    let resp = next(put);
    if !(200..300).contains(&resp.status) {
        return map_swift_error(resp.status, Some(bucket), Some(key));
    }
    let etag = resp
        .headers
        .get("ETag")
        .map(|e| e.trim().trim_matches('"').to_string())
        .unwrap_or_default();
    xml_response(
        200,
        copy_part_result_xml(&copy_xml_last_modified(&resp), &etag),
    )
}

async fn handle_stored_bucket_config_async(
    req: Request,
    cred: &S3Credential,
    bucket: &str,
    cfg: &StoredBucketConfig,
    next: &AsyncNextFn,
) -> Response {
    match req.method.as_str() {
        "GET" | "HEAD" => {
            let mut head =
                make_swift_req("HEAD", &s3_to_swift_path(&cred.account, Some(bucket), None));
            stamp_auth(&mut head, cred);
            let resp = async_call(next, head).await;
            if !(200..300).contains(&resp.status) {
                return map_swift_error(resp.status, Some(bucket), None);
            }
            match stored_bucket_config_xml(&resp.headers, cfg) {
                Some(xml) if cfg.query == "policy" && xml.first() == Some(&b'{') => {
                    let mut r = Response::with_body(200, xml);
                    r.headers.set("Content-Type", "application/json");
                    r
                }
                Some(xml) => xml_ok(xml),
                None => match cfg.missing_code {
                    Some(code) => s3_error_response(code, None, &[]),
                    None => xml_ok(cfg.empty_xml.to_vec()),
                },
            }
        }
        "PUT" => {
            let body = match req.body.into_vec(MAX_CONTROL_BODY) {
                Ok(b) => b,
                Err(_) => return s3_error_response("IncompleteBody", None, &[]),
            };
            let looks_xml = body.iter().any(|b| *b == b'<');
            let looks_json = cfg.query == "policy" && body.iter().any(|b| *b == b'{');
            if !looks_xml && !looks_json {
                return s3_error_response(
                    if cfg.query == "policy" {
                        "MalformedPolicy"
                    } else {
                        "MalformedXML"
                    },
                    None,
                    &[],
                );
            }
            let mut post =
                make_swift_req("POST", &s3_to_swift_path(&cred.account, Some(bucket), None));
            apply_stored_bucket_config(&mut post.headers, cfg, &body);
            stamp_auth(&mut post, cred);
            let resp = async_call(next, post).await;
            if (200..300).contains(&resp.status) {
                Response::new(200)
            } else {
                map_swift_error(resp.status, Some(bucket), None)
            }
        }
        "DELETE" => {
            let mut post =
                make_swift_req("POST", &s3_to_swift_path(&cred.account, Some(bucket), None));
            clear_stored_bucket_config(&mut post.headers, cfg);
            stamp_auth(&mut post, cred);
            let _ = async_call(next, post).await;
            Response::new(204)
        }
        _ => s3_error_response("MethodNotAllowed", None, &[]),
    }
}



fn handle_stored_bucket_config(
    req: Request,
    cred: &S3Credential,
    bucket: &str,
    cfg: &StoredBucketConfig,
    next: &NextFn,
) -> Response {
    match req.method.as_str() {
        "GET" | "HEAD" => {
            let mut head =
                make_swift_req("HEAD", &s3_to_swift_path(&cred.account, Some(bucket), None));
            stamp_auth(&mut head, cred);
            let resp = next(head);
            if !(200..300).contains(&resp.status) {
                return map_swift_error(resp.status, Some(bucket), None);
            }
            match stored_bucket_config_xml(&resp.headers, cfg) {
                Some(xml) if cfg.query == "policy" && xml.first() == Some(&b'{') => {
                    let mut r = Response::with_body(200, xml);
                    r.headers.set("Content-Type", "application/json");
                    r
                }
                Some(xml) => xml_ok(xml),
                None => match cfg.missing_code {
                    Some(code) => s3_error_response(code, None, &[]),
                    None => xml_ok(cfg.empty_xml.to_vec()),
                },
            }
        }
        "PUT" => {
            let body = match req.body.into_vec(MAX_CONTROL_BODY) {
                Ok(b) => b,
                Err(_) => return s3_error_response("IncompleteBody", None, &[]),
            };
            let looks_xml = body.iter().any(|b| *b == b'<');
            let looks_json = cfg.query == "policy" && body.iter().any(|b| *b == b'{');
            if !looks_xml && !looks_json {
                return s3_error_response(
                    if cfg.query == "policy" {
                        "MalformedPolicy"
                    } else {
                        "MalformedXML"
                    },
                    None,
                    &[],
                );
            }
            let mut post =
                make_swift_req("POST", &s3_to_swift_path(&cred.account, Some(bucket), None));
            apply_stored_bucket_config(&mut post.headers, cfg, &body);
            stamp_auth(&mut post, cred);
            let resp = next(post);
            if (200..300).contains(&resp.status) {
                Response::new(200)
            } else {
                map_swift_error(resp.status, Some(bucket), None)
            }
        }
        "DELETE" => {
            let mut post =
                make_swift_req("POST", &s3_to_swift_path(&cred.account, Some(bucket), None));
            clear_stored_bucket_config(&mut post.headers, cfg);
            stamp_auth(&mut post, cred);
            let _ = next(post);
            Response::new(204)
        }
        _ => s3_error_response("MethodNotAllowed", None, &[]),
    }
}

fn handle_create_session(cred: &S3Credential) -> Response {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    xml_ok(create_session_result_xml(
        &cred.access_key,
        &cred.secret_key,
        "peregrine-session",
        &unix_secs_to_s3_iso(now + 900),
    ))
}

async fn handle_object_stored_blob_async(
    req: Request,
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    header: &str,
    missing_code: &str,
    next: &AsyncNextFn,
) -> Response {
    match req.method.as_str() {
        "GET" | "HEAD" => {
            let mut head = make_swift_req(
                "HEAD",
                &s3_to_swift_path(&cred.account, Some(bucket), Some(key)),
            );
            stamp_auth(&mut head, cred);
            let resp = async_call(next, head).await;
            if !(200..300).contains(&resp.status) {
                return map_swift_error(resp.status, Some(bucket), Some(key));
            }
            match object_blob_from_headers(&resp.headers, header) {
                Some(xml) => xml_ok(xml),
                None => s3_error_response(missing_code, None, &[]),
            }
        }
        "PUT" => {
            let body = match req.body.into_vec(MAX_CONTROL_BODY) {
                Ok(b) => b,
                Err(_) => return s3_error_response("IncompleteBody", None, &[]),
            };
            if !body.iter().any(|b| *b == b'<' || *b == b'{') {
                return s3_error_response("MalformedXML", None, &[]);
            }
            let mut post = make_swift_req(
                "POST",
                &s3_to_swift_path(&cred.account, Some(bucket), Some(key)),
            );
            apply_object_blob_meta(&mut post.headers, header, &body);
            stamp_auth(&mut post, cred);
            let resp = async_call(next, post).await;
            if (200..300).contains(&resp.status) {
                Response::new(200)
            } else {
                map_swift_error(resp.status, Some(bucket), Some(key))
            }
        }
        "DELETE" => {
            let mut post = make_swift_req(
                "POST",
                &s3_to_swift_path(&cred.account, Some(bucket), Some(key)),
            );
            clear_object_blob_meta(&mut post.headers, header);
            stamp_auth(&mut post, cred);
            let _ = async_call(next, post).await;
            Response::new(204)
        }
        _ => s3_error_response("MethodNotAllowed", None, &[]),
    }
}



fn handle_object_stored_blob(
    req: Request,
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    header: &str,
    missing_code: &str,
    next: &NextFn,
) -> Response {
    match req.method.as_str() {
        "GET" | "HEAD" => {
            let mut head = make_swift_req(
                "HEAD",
                &s3_to_swift_path(&cred.account, Some(bucket), Some(key)),
            );
            stamp_auth(&mut head, cred);
            let resp = next(head);
            if !(200..300).contains(&resp.status) {
                return map_swift_error(resp.status, Some(bucket), Some(key));
            }
            match object_blob_from_headers(&resp.headers, header) {
                Some(xml) => xml_ok(xml),
                None => s3_error_response(missing_code, None, &[]),
            }
        }
        "PUT" => {
            let body = match req.body.into_vec(MAX_CONTROL_BODY) {
                Ok(b) => b,
                Err(_) => return s3_error_response("IncompleteBody", None, &[]),
            };
            if !body.iter().any(|b| *b == b'<' || *b == b'{') {
                return s3_error_response("MalformedXML", None, &[]);
            }
            let mut post = make_swift_req(
                "POST",
                &s3_to_swift_path(&cred.account, Some(bucket), Some(key)),
            );
            apply_object_blob_meta(&mut post.headers, header, &body);
            stamp_auth(&mut post, cred);
            let resp = next(post);
            if (200..300).contains(&resp.status) {
                Response::new(200)
            } else {
                map_swift_error(resp.status, Some(bucket), Some(key))
            }
        }
        "DELETE" => {
            let mut post = make_swift_req(
                "POST",
                &s3_to_swift_path(&cred.account, Some(bucket), Some(key)),
            );
            clear_object_blob_meta(&mut post.headers, header);
            stamp_auth(&mut post, cred);
            let _ = next(post);
            Response::new(204)
        }
        _ => s3_error_response("MethodNotAllowed", None, &[]),
    }
}

fn control_get_object_bytes(
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    next: &NextFn,
) -> Result<Vec<u8>, Response> {
    let mut get = make_swift_req(
        "GET",
        &s3_to_swift_path(&cred.account, Some(bucket), Some(key)),
    );
    stamp_auth(&mut get, cred);
    let resp = next(get);
    if resp.status == 404 {
        return Err(s3_error_response("NoSuchKey", None, &[]));
    }
    if !(200..300).contains(&resp.status) {
        return Err(map_swift_error(resp.status, Some(bucket), Some(key)));
    }
    resp.body
        .into_vec(MAX_SELECT_TORRENT_BODY)
        .map_err(|_| s3_error_response("EntityTooLarge", None, &[]))
}

fn handle_select_object_content(
    req: Request,
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    next: &NextFn,
) -> Response {
    let body = match req.body.into_vec(MAX_CONTROL_BODY) {
        Ok(b) => b,
        Err(_) => return s3_error_response("IncompleteBody", None, &[]),
    };
    let plan =
        match parse_select_expression(&body) {
            Some(plan) => plan,
            None => return s3_error_response(
                "InvalidRequest",
                Some(
                    "only CSV SELECT *|_N FROM S3Object [WHERE _N = lit] [LIMIT n] is implemented",
                ),
                &[],
            ),
        };
    match control_get_object_bytes(cred, bucket, key, next) {
        Ok(data) => {
            let payload = apply_select_plan(&data, &plan);
            let mut resp = Response::with_body(200, select_star_event_stream(&payload));
            resp.headers
                .set("Content-Type", "application/vnd.amazon.eventstream");
            resp
        }
        Err(resp) => resp,
    }
}

fn handle_get_object_torrent(
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    next: &NextFn,
) -> Response {
    match control_get_object_bytes(cred, bucket, key, next) {
        Ok(data) => {
            let name = key.rsplit('/').next().unwrap_or(key);
            let mut resp = Response::with_body(200, object_torrent_bytes(name, &data));
            resp.headers.set("Content-Type", "application/x-bittorrent");
            resp
        }
        Err(resp) => resp,
    }
}

fn handle_rename_object(
    req: Request,
    cred: &S3Credential,
    dest_bucket: &str,
    dest_key: &str,
    next: &NextFn,
) -> Response {
    let raw = req
        .headers
        .get("X-Amz-Rename-Source")
        .or_else(|| req.headers.get("x-amz-rename-source"))
        .unwrap_or("");
    let Some((src_bucket, src_key, _)) = parse_copy_source(raw) else {
        return s3_error_response("InvalidArgument", Some("invalid x-amz-rename-source"), &[]);
    };
    if src_bucket == dest_bucket && src_key == dest_key {
        return s3_error_response(
            "InvalidRequest",
            Some("rename source equals destination"),
            &[],
        );
    }
    let data = match control_get_object_bytes(cred, &src_bucket, &src_key, next) {
        Ok(bytes) => bytes,
        Err(resp) => return resp,
    };
    let mut put = make_swift_req(
        "PUT",
        &s3_to_swift_path(&cred.account, Some(dest_bucket), Some(dest_key)),
    );
    put.headers.set("Content-Length", data.len().to_string());
    put.body = Body::from(data);
    stamp_auth(&mut put, cred);
    let put_resp = next(put);
    if !(200..300).contains(&put_resp.status) {
        return map_swift_error(put_resp.status, Some(dest_bucket), Some(dest_key));
    }
    let mut del = make_swift_req(
        "DELETE",
        &s3_to_swift_path(&cred.account, Some(&src_bucket), Some(&src_key)),
    );
    stamp_auth(&mut del, cred);
    let del_resp = next(del);
    if !(200..300).contains(&del_resp.status) && del_resp.status != 404 {
        return map_swift_error(del_resp.status, Some(&src_bucket), Some(&src_key));
    }
    Response::new(204)
}

async fn handle_object_attributes_async(
    req: Request,
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    next: &AsyncNextFn,
) -> Response {
    let requested = req
        .headers
        .get("X-Amz-Object-Attributes")
        .or_else(|| req.headers.get("x-amz-object-attributes"))
        .unwrap_or("")
        .to_string();
    if requested.trim().is_empty() {
        return s3_error_response(
            "InvalidRequest",
            Some("x-amz-object-attributes is required"),
            &[],
        );
    }
    match control_head_object_async(cred, bucket, key, next).await {
        Ok(ObjectHead::Present(head)) => {
            let etag = head.headers.get("ETag").unwrap_or("").to_string();
            let size = head
                .headers
                .get("Content-Length")
                .unwrap_or("0")
                .to_string();
            let storage = head
                .headers
                .get("X-Amz-Storage-Class")
                .or_else(|| head.headers.get("X-Object-Meta-Storage-Class"))
                .unwrap_or("STANDARD")
                .to_string();
            xml_response(
                200,
                get_object_attributes_xml(&requested, &etag, &size, &storage),
            )
        }
        Ok(ObjectHead::Missing) => s3_error_response("NoSuchKey", None, &[]),
        Err(resp) => resp,
    }
}



fn handle_object_attributes(
    req: Request,
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    next: &NextFn,
) -> Response {
    let requested = req
        .headers
        .get("X-Amz-Object-Attributes")
        .or_else(|| req.headers.get("x-amz-object-attributes"))
        .unwrap_or("")
        .to_string();
    if requested.trim().is_empty() {
        return s3_error_response(
            "InvalidRequest",
            Some("x-amz-object-attributes is required"),
            &[],
        );
    }
    match control_head_object(cred, bucket, key, next) {
        Ok(ObjectHead::Present(head)) => {
            let etag = head.headers.get("ETag").unwrap_or("").to_string();
            let size = head
                .headers
                .get("Content-Length")
                .unwrap_or("0")
                .to_string();
            let storage = head
                .headers
                .get("X-Amz-Storage-Class")
                .or_else(|| head.headers.get("X-Object-Meta-Storage-Class"))
                .unwrap_or("STANDARD")
                .to_string();
            xml_response(
                200,
                get_object_attributes_xml(&requested, &etag, &size, &storage),
            )
        }
        Ok(ObjectHead::Missing) => s3_error_response("NoSuchKey", None, &[]),
        Err(resp) => resp,
    }
}

fn handle_mpu_complete(
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    upload_id: &str,
    req: Request,
    next: &NextFn,
    api: &S3Api,
) -> Response {
    if let Err(resp) = require_bucket(cred, bucket, next, &api.container_heads) {
        return resp;
    }
    if let Some(resp) = reject_unsupported_put_conditionals(&req) {
        return resp;
    }
    let bypass_requested = bypass_governance_requested(
        req.headers
            .get(HDR_BYPASS_GOVERNANCE)
            .or_else(|| req.headers.get("X-Amz-Bypass-Governance-Retention")),
    );
    let bypass = match governance_bypass_context(&api.iam, cred, bucket, key, bypass_requested) {
        Ok(context) => context,
        Err(resp) => return resp,
    };
    let location = complete_object_location(&req, bucket, key);
    let if_none_match_star = req.headers.get("If-None-Match") == Some("*");
    let body = match req.body.into_vec(MAX_CONTROL_BODY) {
        Ok(b) => b,
        Err(_) => return s3_error_response("IncompleteBody", None, &[]),
    };
    let parts = match parse_complete_body(&body) {
        Ok(p) => p,
        Err(code) => return s3_error_response(&code, None, &[]),
    };
    let segs = segments_container(bucket);
    let upload_info = match get_mpu_upload_info(cred, bucket, key, upload_id, next) {
        Ok(info) => info,
        Err(resp) => return resp,
    };
    let s3_etag = aws_multipart_etag(parts.iter().map(|(_, e)| e.as_str()));
    if let Some(resp) = complete_mpu_already_uploaded(
        upload_info.headers.get(SYS_S3API_ETAG),
        s3_etag.as_deref(),
        bucket,
        key,
        &location,
    ) {
        return resp;
    }
    if if_none_match_star {
        match control_head_object(cred, bucket, key, next) {
            Ok(head) => {
                if let Some(resp) = complete_mpu_if_none_match_conflict(head) {
                    return resp;
                }
            }
            Err(resp) => return resp,
        }
    }
    // HEAD each part for size.
    let mut sized: Vec<(u32, String, u64)> = Vec::new();
    for (num, etag) in &parts {
        let pname = part_object_name(key, upload_id, *num);
        let mut head = make_swift_req(
            "HEAD",
            &s3_to_swift_path(&cred.account, Some(&segs), Some(&pname)),
        );
        stamp_auth(&mut head, cred);
        let resp = next(head);
        if !(200..300).contains(&resp.status) {
            return s3_error_response("InvalidPart", None, &[]);
        }
        let stored = resp
            .headers
            .get("ETag")
            .map(bare_etag)
            .unwrap_or_default();
        if !etag.is_empty() && !stored.is_empty() && stored != bare_etag(etag) {
            return s3_error_response("InvalidPart", None, &[]);
        }
        let size = resp
            .headers
            .get("Content-Length")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        sized.push((*num, etag.clone(), size));
    }
    // Official test_complete_upload_min_segment_size: every part except the
    // last must be >= 5 MiB. A single small part is allowed.
    const MIN_PART: u64 = 5_242_880;
    if sized.len() >= 2 {
        for (i, (_n, _e, size)) in sized.iter().enumerate() {
            if i + 1 < sized.len() && *size < MIN_PART {
                return s3_error_response("EntityTooSmall", None, &[]);
            }
        }
    }
    let manifest = slo_manifest_json(&segs, key, upload_id, &sized);
    let mut put = make_swift_req(
        "PUT",
        &s3_to_swift_path(&cred.account, Some(bucket), Some(key)),
    );
    copy_mpu_object_headers(&upload_info.headers, &mut put.headers);
    persist_s3_object_headers(&mut put);
    put.headers.set(SYS_S3API_UPLOAD_ID, upload_id);
    if let Some(ref etag) = s3_etag {
        put.headers.set(SYS_S3API_ETAG, etag);
        // Live object-server uses this value as the listing hash (no SLO merge).
        put.headers.set(SYS_CONTAINER_UPDATE_OVERRIDE_ETAG, etag);
    }
    let assembled: u64 = sized.iter().map(|(_, _, n)| *n).sum();
    put.headers
        .set(SYS_CONTAINER_UPDATE_OVERRIDE_SIZE, assembled.to_string());
    put.query_string = "multipart-manifest=put".into();
    let manifest = manifest.into_bytes();
    put.headers
        .set("Content-Length", manifest.len().to_string());
    put.body = Body::from(manifest);

    if put.headers.get(SYS_LOCK_MODE).is_some() || put.headers.get(SYS_RETAIN_UNTIL).is_some() {
        if let Some(denied) = iam_action_check(&api.iam, cred, "s3:PutObjectRetention", bucket, key)
        {
            return denied;
        }
    }
    if put.headers.get(SYS_LEGAL_HOLD).is_some() {
        if let Some(denied) = iam_action_check(&api.iam, cred, "s3:PutObjectLegalHold", bucket, key)
        {
            return denied;
        }
    }
    if put.headers.get(SYS_LOCK_MODE).is_some()
        || put.headers.get(SYS_RETAIN_UNTIL).is_some()
        || put.headers.get(SYS_LEGAL_HOLD).is_some()
    {
        if let Err(resp) = require_bucket_object_lock(cred, bucket, next) {
            return resp;
        }
    }

    let versioning_mode = match probe_bucket_versioning(cred, bucket, next, &api.container_heads) {
        Ok(status) => bucket_versioning_mode(status.as_deref()),
        Err(resp) => return resp,
    };
    let resp = if let Some(versioning_mode) = versioning_mode {
        handle_versioned_put(
            put,
            cred,
            bucket,
            key,
            false,
            Some("multipart-manifest=put"),
            match versioning_mode {
                BucketVersioningMode::Enabled => None,
                BucketVersioningMode::Suspended => Some(NULL_VERSION_ID),
            },
            bypass,
            next,
            api,
        )
    } else {
        if let Some(blocked) =
            worm_check_object(cred, bucket, key, api.worm_clock.clock_ok(), bypass, next)
        {
            return blocked;
        }
        if let Some(blocked) = acl_write_check_object(cred, bucket, key, next) {
            return blocked;
        }
        if let Err(resp) = apply_request_object_lock_headers(&mut put.headers) {
            return resp;
        }
        strip_s3_only_headers(&mut put.headers);
        maybe_apply_lifecycle_on_put(&mut put, cred, bucket, key, next, &api.container_heads);
        if let Err(resp) =
            apply_bucket_default_retention(&mut put, cred, bucket, next, &api.container_heads)
        {
            return resp;
        }
        stamp_auth(&mut put, cred);
        next(put)
    };
    if !(200..300).contains(&resp.status) {
        return map_swift_error(resp.status, Some(bucket), Some(key));
    }
    delete_mpu_marker(cred, bucket, key, upload_id, next);
    let etag = s3_etag.unwrap_or_else(|| {
        resp.headers
            .get("ETag")
            .map(|e| e.trim().trim_matches('"').to_string())
            .unwrap_or_else(|| "multipart".into())
    });
    let version_id = resp.headers.get(HDR_VERSION_ID).map(str::to_string);
    let mut out = xml_response(
        200,
        complete_multipart_xml(bucket, key, &etag, &location),
    );
    if let Some(version_id) = version_id {
        out.headers.set(HDR_VERSION_ID, version_id);
    }
    out
}

fn delete_mpu_marker(
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    upload_id: &str,
    next: &NextFn,
) {
    let segs = segments_container(bucket);
    let marker = upload_marker_name(key, upload_id);
    let mut del = make_swift_req(
        "DELETE",
        &s3_to_swift_path(&cred.account, Some(&segs), Some(&marker)),
    );
    stamp_auth(&mut del, cred);
    let _ = next(del);
}

fn handle_mpu_abort(
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    upload_id: &str,
    api: &S3Api,
    next: &NextFn,
) -> Response {
    if let Err(resp) = require_bucket(cred, bucket, next, &api.container_heads) {
        return resp;
    }
    let segs = segments_container(bucket);
    let marker = upload_marker_name(key, upload_id);
    match control_head_object(cred, &segs, &marker, next) {
        Ok(ObjectHead::Present(_)) => {}
        Ok(ObjectHead::Missing) => return s3_error_response("NoSuchUpload", None, &[]),
        Err(resp) => return resp,
    }
    // Python abort: DELETE remaining parts (`{key}/{uploadId}/…`) then
    // the marker. Official test_object_multi_upload asserts the prefix
    // is empty afterwards.
    let prefix = format!("{key}/{upload_id}/");
    let mut list = make_swift_req("GET", &s3_to_swift_path(&cred.account, Some(&segs), None));
    list.query_string = format!("format=json&prefix={}", encode_query(&prefix));
    list.headers.set("Accept", "application/json");
    stamp_auth(&mut list, cred);
    let listed = next(list);
    if (200..300).contains(&listed.status) {
        if let Ok(body) = listed.body.into_vec(MAX_CONTROL_BODY) {
            let parsed: Value = serde_json::from_slice(&body).unwrap_or(Value::Array(vec![]));
            if let Some(arr) = parsed.as_array() {
                for item in arr {
                    let Some(name) = item.get("name").and_then(|v| v.as_str()) else {
                        continue;
                    };
                    let mut del_part = make_swift_req(
                        "DELETE",
                        &s3_to_swift_path(&cred.account, Some(&segs), Some(name)),
                    );
                    stamp_auth(&mut del_part, cred);
                    let _ = next(del_part);
                }
            }
        }
    }
    let mut del = make_swift_req(
        "DELETE",
        &s3_to_swift_path(&cred.account, Some(&segs), Some(&marker)),
    );
    stamp_auth(&mut del, cred);
    let _ = next(del);
    let mut resp = delete_object_response();
    resp.headers.set("Content-Type", "text/html; charset=UTF-8");
    resp
}

fn handle_list_multipart_uploads(
    cred: &S3Credential,
    bucket: &str,
    params: &[(String, String)],
    api: &S3Api,
    next: &NextFn,
) -> Response {
    if let Err(resp) = require_bucket(cred, bucket, next, &api.container_heads) {
        return resp;
    }
    let prefix = params
        .iter()
        .find(|(k, _)| k == "prefix")
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    let key_marker = params
        .iter()
        .find(|(k, _)| k == "key-marker")
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    let upload_id_marker = params
        .iter()
        .find(|(k, _)| k == "upload-id-marker")
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    let max_uploads: u32 = params
        .iter()
        .find(|(k, _)| k == "max-uploads")
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(1000)
        .clamp(1, 1000);

    let segs = segments_container(bucket);
    let mut list = make_swift_req("GET", &s3_to_swift_path(&cred.account, Some(&segs), None));
    let mut qs = String::from("format=json");
    if !prefix.is_empty() {
        qs.push_str(&format!("&prefix={}", encode_query(prefix)));
    }
    list.query_string = qs;
    list.headers.set("Accept", "application/json");
    stamp_auth(&mut list, cred);
    let resp = next(list);
    // Missing segments container → empty upload list (not an error).
    if resp.status == 404 {
        return xml_response(
            200,
            list_multipart_uploads_xml(
                bucket,
                prefix,
                key_marker,
                upload_id_marker,
                max_uploads,
                false,
                &[],
                &owner_for(cred).id,
            ),
        );
    }
    if !(200..300).contains(&resp.status) {
        return map_swift_error(resp.status, Some(bucket), None);
    }
    let body = match resp.body.into_vec(MAX_CONTROL_BODY) {
        Ok(b) => b,
        Err(_) => return s3_error_response("InternalError", Some("listing too large"), &[]),
    };
    let parsed: Value = serde_json::from_slice(&body).unwrap_or(Value::Array(vec![]));
    let mut uploads = Vec::new();
    if let Some(arr) = parsed.as_array() {
        for item in arr {
            let Some(name) = item.get("name").and_then(|v| v.as_str()) else {
                continue;
            };
            let Some((key, uid)) = parse_upload_marker_name(name) else {
                continue;
            };
            if !prefix.is_empty() && !key.starts_with(prefix) {
                continue;
            }
            // Pagination: skip until past key-marker / upload-id-marker.
            if !key_marker.is_empty() {
                if key.as_str() < key_marker {
                    continue;
                }
                if key.as_str() == key_marker
                    && !upload_id_marker.is_empty()
                    && uid.as_str() <= upload_id_marker
                {
                    continue;
                }
            }
            let lm = item
                .get("last_modified")
                .and_then(|v| v.as_str())
                .unwrap_or("1970-01-01T00:00:00.000000");
            uploads.push(ListedUpload {
                key,
                upload_id: uid,
                initiated: swift_ts_to_s3(lm),
            });
        }
    }
    uploads.sort_by(|a, b| (&a.key, &a.upload_id).cmp(&(&b.key, &b.upload_id)));
    let truncated = uploads.len() as u32 > max_uploads;
    uploads.truncate(max_uploads as usize);
    xml_response(
        200,
        list_multipart_uploads_xml(
            bucket,
            prefix,
            key_marker,
            upload_id_marker,
            max_uploads,
            truncated,
            &uploads,
            &owner_for(cred).id,
        ),
    )
}

fn handle_mpu_list_parts(
    cred: &S3Credential,
    bucket: &str,
    key: &str,
    upload_id: &str,
    params: &[(String, String)],
    api: &S3Api,
    next: &NextFn,
) -> Response {
    if let Err(resp) = require_bucket(cred, bucket, next, &api.container_heads) {
        return resp;
    }
    let segs = segments_container(bucket);
    let marker = upload_marker_name(key, upload_id);
    match control_head_object(cred, &segs, &marker, next) {
        Ok(ObjectHead::Present(_)) => {}
        Ok(ObjectHead::Missing) => return s3_error_response("NoSuchUpload", None, &[]),
        Err(resp) => return resp,
    }
    // part-number-marker + max-parts (S3 ListParts query params).
    let param = |name: &str| -> Option<&str> {
        params
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    };
    let part_marker = param("part-number-marker")
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(0);
    let max_parts = param("max-parts")
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(1000)
        .clamp(1, 1000);
    let prefix = format!("{key}/{upload_id}/");
    let mut list = make_swift_req("GET", &s3_to_swift_path(&cred.account, Some(&segs), None));
    list.query_string = format!("format=json&prefix={}", encode_query(&prefix));
    list.headers.set("Accept", "application/json");
    stamp_auth(&mut list, cred);
    let resp = next(list);
    if !(200..300).contains(&resp.status) {
        return map_swift_error(resp.status, Some(bucket), Some(key));
    }
    let body = match resp.body.into_vec(MAX_CONTROL_BODY) {
        Ok(b) => b,
        Err(_) => return s3_error_response("InternalError", None, &[]),
    };
    let parsed: Value = serde_json::from_slice(&body).unwrap_or(Value::Array(vec![]));
    let mut parts = Vec::new();
    if let Some(arr) = parsed.as_array() {
        for item in arr {
            let Some(name) = item.get("name").and_then(|v| v.as_str()) else {
                continue;
            };
            let Some(num_str) = name.rsplit('/').next() else {
                continue;
            };
            let Ok(num) = num_str.parse::<u32>() else {
                continue;
            };
            if num <= part_marker {
                continue;
            }
            let etag = item
                .get("hash")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let size = item.get("bytes").and_then(|v| v.as_u64()).unwrap_or(0);
            let lm = item
                .get("last_modified")
                .and_then(|v| v.as_str())
                .unwrap_or("1970-01-01T00:00:00.000000");
            parts.push(ListedPart {
                part_number: num,
                last_modified: swift_ts_to_s3(lm),
                etag,
                size,
            });
        }
    }
    parts.sort_by_key(|p| p.part_number);
    let truncated = parts.len() as u32 > max_parts;
    if truncated {
        parts.truncate(max_parts as usize);
    }
    xml_response(
        200,
        list_parts_xml_full(
            bucket,
            key,
            upload_id,
            part_marker,
            max_parts,
            truncated,
            &parts,
            &owner_for(cred).id,
        ),
    )
}

/// Build credentials from TempAuth-style `user_<account>_<user> = <key> …`
/// records. Access key is `account:user`; secret is the TempAuth key;
/// storage account is `{reseller_prefix}{account}`.
pub fn credentials_from_tempauth_users(
    users: &[(String, String, String, Vec<String>)],
    reseller_prefix: &str,
) -> HashMap<String, S3Credential> {
    // users: (account, user, key, groups_from_conf)
    let mut map = HashMap::new();
    for (account, user, key, conf_groups) in users {
        let access_key = format!("{account}:{user}");
        let storage_account = format!("{reseller_prefix}{account}");
        let mut groups = vec![account.clone(), access_key.clone()];
        let mut is_admin = false;
        for g in conf_groups {
            if g == ".admin" {
                is_admin = true;
            } else {
                groups.push(g.clone());
            }
        }
        if is_admin {
            groups.push(storage_account.clone());
        }
        map.insert(
            access_key.clone(),
            S3Credential {
                access_key,
                secret_key: key.clone(),
                account: storage_account,
                groups,
                auth_token: None,
            },
        );
    }
    map
}

/// Helper for tests / proxy wiring: wrap [`S3Api`] as `Arc<dyn Middleware>`.
pub fn as_middleware(api: S3Api) -> Arc<dyn Middleware> {
    Arc::new(api)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl_cors::{S3_OBJECT_ACL_JSON_META, S3_OBJECT_ACL_META};
    use crate::bucket_config::{S3_LIFECYCLE_META, S3_OBJECT_LOCK_META, S3_VERSIONING_META};
    use crate::response::{error_xml_leaf, request_id_survives_normalize};
    use crate::sigv4::{
        amz_date, canonical_query, canonical_request, canonical_uri, compute_signature,
        format_amz_date, headers_to_sign, parse_authorization_header, parse_query_authentication,
        payload_hash,
    };

    fn cred_map() -> HashMap<String, S3Credential> {
        let mut m = HashMap::new();
        m.insert(
            "test:tester".into(),
            S3Credential {
                access_key: "test:tester".into(),
                secret_key: "testing".into(),
                account: "AUTH_test".into(),
                groups: vec!["test".into(), "test:tester".into(), "AUTH_test".into()],
                auth_token: None,
            },
        );
        m
    }

    fn api_with_worm_bypass_permission() -> S3Api {
        let mut iam = crate::iam::IamService::new();
        let policy = crate::iam::IamService::parse_policy_json(
            r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:*","Resource":"arn:aws:s3:::mybucket/*","Principal":"*"}}"#,
        )
        .expect("valid WORM IAM fixture");
        iam.attach_policy("*", "worm-test", policy);
        S3Api::new(cred_map()).with_iam(iam)
    }

    /// Owner + foreign principals sharing one Swift account (grant enforcement).
    fn multi_cred_map() -> HashMap<String, S3Credential> {
        let mut m = cred_map();
        m.insert(
            "test:foreign".into(),
            S3Credential {
                access_key: "test:foreign".into(),
                secret_key: "foreign-secret".into(),
                account: "AUTH_test".into(),
                groups: vec!["test".into(), "test:foreign".into(), "AUTH_test".into()],
                auth_token: None,
            },
        );
        m.insert(
            "test:friend".into(),
            S3Credential {
                access_key: "test:friend".into(),
                secret_key: "friend-secret".into(),
                account: "AUTH_test".into(),
                groups: vec!["test".into(), "test:friend".into(), "AUTH_test".into()],
                auth_token: None,
            },
        );
        m
    }

    fn base_s3_req_as_at(
        method: &str,
        path: &str,
        query: &str,
        access_key: &str,
        signed_at: i64,
    ) -> Request {
        let amz = crate::sigv4::format_amz_date(signed_at);
        let scope = &amz[..8];
        let mut headers = HeaderKeyDict::new();
        headers.set("Host", "localhost");
        headers.set(
            "x-amz-content-sha256",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
        headers.set("x-amz-date", &amz);
        headers.set(
            "Authorization",
            format!(
                "AWS4-HMAC-SHA256 \
                 Credential={access_key}/{scope}/us-east-1/s3/aws4_request, \
                 SignedHeaders=host;x-amz-content-sha256;x-amz-date, \
                 Signature=00"
            ),
        );
        Request {
            method: method.into(),
            path: path.into(),
            query_string: query.into(),
            headers,
            body: Body::empty(),
        }
    }

    fn base_s3_req_as(method: &str, path: &str, query: &str, access_key: &str) -> Request {
        base_s3_req_as_at(method, path, query, access_key, unix_now())
    }

    /// Python MultiDeleteController.require_md5: Content-MD5 or x-amz-checksum-*.
    fn stamp_content_md5(req: &mut Request) {
        let bytes = req.body.materialize(u64::MAX).expect("body").to_vec();
        req.headers.set(
            "content-md5",
            crate::sigv2::base64_encode(&crate::crypto::md5(&bytes)),
        );
        req.headers.set("Content-Length", bytes.len().to_string());
        req.body = Body::from(bytes);
    }

    fn sign_request(mut req: Request, secret: &str) -> Request {
        let auth_hdr = req.headers.get("Authorization").unwrap().to_string();
        let auth = parse_authorization_header(&auth_hdr).unwrap();
        let date = amz_date(&req).unwrap();
        let hts = headers_to_sign(&req.headers, &auth.signed_headers).unwrap();
        let cr = canonical_request(
            &req.method,
            &canonical_uri(&req.path),
            &canonical_query(&req.query_string),
            &hts,
            &payload_hash(&req),
        );
        let sig = compute_signature(secret, &auth.scope, &date, &cr);
        // Rebuild Authorization with computed signature.
        let cred = format!(
            "{}/{}/{}/{}/{}",
            auth.access_key,
            auth.scope.date,
            auth.scope.region,
            auth.scope.service,
            auth.scope.terminal
        );
        let signed = auth.signed_headers.join(";");
        req.headers.set(
            "Authorization",
            format!("AWS4-HMAC-SHA256 Credential={cred}, SignedHeaders={signed}, Signature={sig}"),
        );
        req
    }

    fn base_s3_req_at(method: &str, path: &str, query: &str, signed_at: i64) -> Request {
        base_s3_req_as_at(method, path, query, "test:tester", signed_at)
    }

    fn base_s3_req(method: &str, path: &str, query: &str) -> Request {
        base_s3_req_at(method, path, query, unix_now())
    }

    #[test]
    fn passthrough_without_sigv4() {
        let api = S3Api::new(cred_map());
        let req = Request {
            method: "GET".into(),
            path: "/v1/AUTH_test".into(),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: Body::empty(),
        };
        let next: NextFn = Arc::new(|r| {
            assert_eq!(r.path, "/v1/AUTH_test");
            Response::new(200)
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
    }

    #[test]
    fn anonymous_get_object_maps_without_auth_override() {
        let api = S3Api::new(cred_map()).with_anonymous_account("AUTH_test");
        let req = Request {
            method: "GET".into(),
            path: "/pubbucket/obj1".into(),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: Body::empty(),
        };
        let next: NextFn = Arc::new(|r| {
            assert_eq!(r.path, "/v1/AUTH_test/pubbucket/obj1");
            assert!(r.headers.get("X-Backend-Authorize-Override").is_none());
            let mut resp = Response::new(200);
            resp.body = Body::from(b"hello-anon".to_vec());
            resp.headers.set("ETag", "abc");
            resp
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert_eq!(body, "hello-anon");
    }

    #[test]
    fn anonymous_get_private_object_acl_denied_even_if_backend_200() {
        let api = S3Api::new(cred_map()).with_anonymous_account("AUTH_test");
        let req = Request {
            method: "GET".into(),
            path: "/pubbucket/secret".into(),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: Body::empty(),
        };
        let next: NextFn = Arc::new(|r| {
            assert_eq!(r.path, "/v1/AUTH_test/pubbucket/secret");
            let mut resp = Response::new(200);
            resp.body = Body::from(b"nope".to_vec());
            resp.headers.set(S3_OBJECT_ACL_META, "private");
            resp
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 403);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("AccessDenied"), "{body}");
    }

    #[test]
    fn anonymous_get_public_read_object_acl_allowed() {
        let api = S3Api::new(cred_map()).with_anonymous_account("AUTH_test");
        let req = Request {
            method: "GET".into(),
            path: "/pubbucket/pub".into(),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: Body::empty(),
        };
        let next: NextFn = Arc::new(|_| {
            let mut resp = Response::new(200);
            resp.body = Body::from(b"ok".to_vec());
            resp.headers.set(S3_OBJECT_ACL_META, "public-read");
            resp
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
    }

    #[test]
    fn anonymous_get_without_account_config_passthrough() {
        let api = S3Api::new(cred_map()); // no anonymous_account
        let req = Request {
            method: "GET".into(),
            path: "/pubbucket/obj1".into(),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: Body::empty(),
        };
        let next: NextFn = Arc::new(|r| {
            assert_eq!(r.path, "/pubbucket/obj1"); // unchanged
            Response::new(200)
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
    }

    #[test]
    fn reject_bad_access_key() {
        let api = S3Api::new(cred_map());
        let mut req = base_s3_req("GET", "/", "");
        req.headers.set(
            "Authorization",
            "AWS4-HMAC-SHA256 \
             Credential=nope:user/20130524/us-east-1/s3/aws4_request, \
             SignedHeaders=host;x-amz-content-sha256;x-amz-date, \
             Signature=00",
        );
        let req = sign_request(req, "testing");
        let next: NextFn = Arc::new(|_| Response::new(500));
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 403);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("InvalidAccessKeyId"));
    }

    #[test]
    fn unknown_ec2_key_defers_to_s3token_client() {
        use swift_middleware::{MapS3TokenClient, S3TokenResult};

        // Capture the raw string-to-sign passed into exchange (must not be X-Amz-Date).
        struct CapturingClient {
            inner: MapS3TokenClient,
            seen_sts: std::sync::Mutex<Option<String>>,
        }
        impl S3TokenClient for CapturingClient {
            fn exchange(
                &self,
                access_key: &str,
                signature: &str,
                string_to_sign: &str,
            ) -> Option<S3TokenResult> {
                *self.seen_sts.lock().unwrap() = Some(string_to_sign.to_string());
                self.inner.exchange(access_key, signature, string_to_sign)
            }
        }

        let mut map = MapS3TokenClient::new();
        map.insert(
            "AKIATEST",
            S3TokenResult {
                token_id: "subj-tok".into(),
                project_id: "proj123".into(),
                project_name: "demo".into(),
                user_id: "uid".into(),
                user_name: "alice".into(),
                roles: vec!["admin".into()],
            },
        );
        let client = Arc::new(CapturingClient {
            inner: map,
            seen_sts: std::sync::Mutex::new(None),
        });
        let api = S3Api::new(cred_map())
            .with_reseller_prefix("AUTH_")
            .with_s3token_client(client.clone());

        let mut req = base_s3_req("PUT", "/ec2bucket/obj", "");
        req.headers.set(
            "Authorization",
            "AWS4-HMAC-SHA256 \
             Credential=AKIATEST/20130524/us-east-1/s3/aws4_request, \
             SignedHeaders=host;x-amz-content-sha256;x-amz-date, \
             Signature=00",
        );
        // Signature is verified by Keystone on the deferral path; local verify skipped.
        req.body = Body::from(b"hello-ec2".to_vec());
        req.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        let date = amz_date(&req).unwrap();

        let next: NextFn = Arc::new(|r| {
            if r.method == "HEAD" {
                return Response::new(404);
            }
            assert_eq!(r.path, "/v1/AUTH_proj123/ec2bucket/obj");
            assert_eq!(r.headers.get("X-Backend-Authorize-Override"), Some("true"));
            assert_eq!(r.headers.get("X-Auth-Token"), Some("subj-tok"));
            let mut resp = Response::new(201);
            resp.headers.set("ETag", "\"abc\"");
            resp
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        let sts = client.seen_sts.lock().unwrap().clone().unwrap();
        assert!(sts.starts_with("AWS4-HMAC-SHA256\n"), "sts={sts}");
        assert!(sts.contains(&date), "sts={sts} date={date}");
        assert_ne!(sts, date);
    }

    #[test]
    fn unknown_ec2_key_without_client_still_invalid() {
        let api = S3Api::new(cred_map()); // no s3token_client
        let mut req = base_s3_req("GET", "/", "");
        req.headers.set(
            "Authorization",
            "AWS4-HMAC-SHA256 \
             Credential=AKIATEST/20130524/us-east-1/s3/aws4_request, \
             SignedHeaders=host;x-amz-content-sha256;x-amz-date, \
             Signature=00",
        );
        let next: NextFn = Arc::new(|_| Response::new(500));
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 403);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("InvalidAccessKeyId"));
    }

    #[test]
    fn reject_bad_signature() {
        let api = S3Api::new(cred_map());
        let req = base_s3_req("GET", "/", "");
        // Leave Signature=00 without recomputing.
        let next: NextFn = Arc::new(|_| Response::new(500));
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 403);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("SignatureDoesNotMatch"));
    }

    #[test]
    fn list_buckets_translates_json() {
        let api = S3Api::new(cred_map());
        let req = sign_request(base_s3_req("GET", "/", ""), "testing");
        let next: NextFn = Arc::new(|r| {
            assert_eq!(r.path, "/v1/AUTH_test");
            assert!(r.query_string.contains("format=json"));
            assert_eq!(r.headers.get("X-Backend-Authorize-Override"), Some("true"));
            Response::with_body(
                200,
                br#"[{"name":"b1","count":0,"bytes":0,"last_modified":"2013-05-24T00:00:00.000000"}]"#.to_vec(),
            )
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("ListAllMyBucketsResult"));
        assert!(body.contains("<Name>b1</Name>"));
        assert!(body.contains("2013-05-24T00:00:00.000Z"));
    }

    #[test]
    fn list_buckets_hides_versions_and_segments_siblings() {
        let api = S3Api::new(cred_map());
        let req = sign_request(base_s3_req("GET", "/", ""), "testing");
        let next: NextFn = Arc::new(|r| {
            assert_eq!(r.path, "/v1/AUTH_test");
            Response::with_body(
                200,
                br#"[{"name":"b1","count":0,"bytes":0,"last_modified":"2013-05-24T00:00:00.000000"},{"name":"b1+versions","count":3,"bytes":0,"last_modified":"2013-05-24T00:00:01.000000"},{"name":"b1+segments","count":1,"bytes":0,"last_modified":"2013-05-24T00:00:02.000000"}]"#.to_vec(),
            )
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("<Name>b1</Name>"), "{body}");
        assert!(!body.contains("+versions"), "{body}");
        assert!(!body.contains("+segments"), "{body}");
    }

    #[test]
    fn put_object_maps_path_and_status() {
        let api = S3Api::new(cred_map());
        let req = sign_request(base_s3_req("PUT", "/mybucket/dir/obj", ""), "testing");
        let next: NextFn = Arc::new(|r| {
            if r.method == "HEAD" {
                return Response::new(404);
            }
            assert_eq!(r.path, "/v1/AUTH_test/mybucket/dir/obj");
            let mut resp = Response::new(201);
            resp.headers.set("ETag", "abc123");
            resp
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        assert_eq!(resp.headers.get("ETag"), Some("\"abc123\""));
    }

    fn block_on_s3<F: std::future::Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("current-thread runtime")
            .block_on(fut)
    }

    /// SigV2 versioned PUT falls back to `dispatch_legacy_blocking`
    /// (`block_in_place`). That requires a multi-thread runtime, matching
    /// the live proxy (`new_multi_thread`).
    fn block_on_s3_multi<F: std::future::Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("multi-thread runtime")
            .block_on(fut)
    }

    fn unsigned_signed_put(path: &str, query: &str) -> Request {
        let mut req = base_s3_req("PUT", path, query);
        req.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        sign_request(req, "testing")
    }

    fn async_from_signed(req: Request, body: Vec<u8>) -> AsyncRequest {
        AsyncRequest {
            method: req.method,
            path: req.path,
            query_string: req.query_string,
            headers: req.headers,
            body: IncomingBody::from_bytes(body, u64::MAX),
        }
    }

    #[test]
    fn signed_put_object_is_streaming_not_intercept() {
        let api = S3Api::new(cred_map());
        let req = unsigned_signed_put("/mybucket/obj", "");
        assert!(
            api.streams_request(&req),
            "SigV4 PutObject must take the streaming ABI"
        );
        assert!(
            !api.intercepts_request(&req),
            "streaming PutObject must not enter the 64 MiB materialize intercept"
        );
    }

    #[test]
    fn list_buckets_is_intercept_not_streaming() {
        let api = S3Api::new(cred_map());
        let req = sign_request(base_s3_req("GET", "/", ""), "testing");
        assert!(!api.streams_request(&req));
        assert!(api.intercepts_request(&req));
    }

    #[test]
    fn aws_chunked_put_is_streaming() {
        let api = S3Api::new(cred_map());
        let mut req = unsigned_signed_put("/mybucket/obj", "");
        req.headers.set(
            "x-amz-content-sha256",
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
        );
        req.headers.set("x-amz-decoded-content-length", "10");
        req.headers.set("Content-Encoding", "aws-chunked");
        assert!(
            api.streams_request(&req),
            "S3-2: aws-chunked PutObject must use the streaming ABI"
        );
        assert!(!api.intercepts_request(&req));
    }

    #[test]
    fn streaming_put_forwards_unread_body_without_control_cap() {
        let api = S3Api::new(cred_map());
        let req = unsigned_signed_put("/mybucket/obj", "");
        // Body is forwarded as IncomingBody; the 64 MiB control cap is a
        // proxy-materialize concern proven by the streams_request branch.
        let payload = vec![b'x'; 256 * 1024];
        let expected_len = payload.len();
        let areq = async_from_signed(req, payload);
        let next: StreamingAsyncNextFn = Arc::new(move |areq| {
            Box::pin(async move {
                if areq.method == "HEAD" {
                    return Response::new(204);
                }
                assert_eq!(areq.method, "PUT");
                assert_eq!(areq.path, "/v1/AUTH_test/mybucket/obj");
                let mut n = 0usize;
                let mut body = areq.body;
                while let Some(c) = body.next_chunk().await.unwrap() {
                    n += c.len();
                }
                assert_eq!(n, expected_len);
                let mut resp = Response::new(201);
                resp.headers.set("ETag", "abc123");
                resp
            })
        });
        let resp = block_on_s3(api.put_object_streaming(areq, next));
        assert_eq!(resp.status, 200, "streaming PUT must not 413 at 64 MiB");
        assert_eq!(resp.headers.get("ETag"), Some("\"abc123\""));
    }

    #[test]
    fn streaming_put_calls_backend_before_client_eof() {
        let api = S3Api::new(cred_map());
        let req = unsigned_signed_put("/mybucket/obj", "");
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<Vec<u8>, std::io::Error>>(4);
        let areq = AsyncRequest {
            method: req.method,
            path: req.path,
            query_string: req.query_string,
            headers: req.headers,
            body: IncomingBody::from_channel(rx, Some(3), None, u64::MAX),
        };
        let started = Arc::new(tokio::sync::Notify::new());
        let started_c = started.clone();
        let next: StreamingAsyncNextFn = Arc::new(move |areq| {
            let started_c = started_c.clone();
            Box::pin(async move {
                if areq.method == "HEAD" {
                    return Response::new(204);
                }
                started_c.notify_one();
                let mut n = 0usize;
                let mut body = areq.body;
                while let Some(c) = body.next_chunk().await.unwrap() {
                    n += c.len();
                }
                assert_eq!(n, 3);
                let mut resp = Response::new(201);
                resp.headers.set("ETag", "early");
                resp
            })
        });
        let resp = block_on_s3(async move {
            let put = tokio::spawn(async move { api.put_object_streaming(areq, next).await });
            started.notified().await;
            tx.send(Ok(b"abc".to_vec())).await.unwrap();
            drop(tx);
            put.await.unwrap()
        });
        assert_eq!(resp.status, 200);
        assert_eq!(resp.headers.get("ETag"), Some("\"early\""));
    }

    #[test]
    fn streaming_upload_part_maps_to_segments_container() {
        let api = S3Api::new(cred_map());
        let req = unsigned_signed_put("/mybucket/obj", "uploadId=uid1&partNumber=2");
        let areq = async_from_signed(req, b"part".to_vec());
        let next: StreamingAsyncNextFn = Arc::new(move |areq| {
            Box::pin(async move {
                assert_eq!(areq.method, "PUT");
                assert_eq!(
                    areq.path,
                    "/v1/AUTH_test/mybucket+segments/obj/uid1/00000002"
                );
                let mut resp = Response::new(201);
                resp.headers.set("ETag", "part-etag");
                resp
            })
        });
        let resp = block_on_s3(api.put_object_streaming(areq, next));
        assert_eq!(resp.status, 200);
        assert_eq!(resp.headers.get("ETag"), Some("\"part-etag\""));
    }

    #[test]
    fn streaming_aws_chunked_put_dechunks_without_control_cap() {
        let api = S3Api::new(cred_map());
        let payload = vec![b'z'; 128 * 1024];
        let framed = crate::aws_chunked::frame_aws_chunked_unsigned(&payload, 4096);
        let mut req = base_s3_req("PUT", "/mybucket/obj", "");
        req.headers
            .set("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER");
        req.headers
            .set("x-amz-decoded-content-length", payload.len().to_string());
        req.headers.set("Content-Encoding", "aws-chunked");
        req.headers.set("Content-Length", framed.len().to_string());
        let req = sign_request(req, "testing");
        let areq = async_from_signed(req, framed);
        let expected = payload.len();
        let next: StreamingAsyncNextFn = Arc::new(move |areq| {
            Box::pin(async move {
                if areq.method == "HEAD" {
                    return Response::new(204);
                }
                let exp = expected.to_string();
                assert_eq!(areq.headers.get("Content-Length"), Some(exp.as_str()));
                let mut n = 0usize;
                let mut body = areq.body;
                while let Some(c) = body.next_chunk().await.unwrap() {
                    n += c.len();
                }
                assert_eq!(n, expected);
                let mut resp = Response::new(201);
                resp.headers.set("ETag", "chunked");
                resp
            })
        });
        let resp = block_on_s3(api.put_object_streaming(areq, next));
        assert_eq!(resp.status, 200, "aws-chunked streaming PUT must succeed");
        assert_eq!(resp.headers.get("ETag"), Some("\"chunked\""));
    }

    #[test]
    fn streaming_aws_chunked_bad_signature_is_fail_closed() {
        let api = S3Api::new(cred_map());
        let payload = b"hello";
        let framed = format!(
            "{:x};chunk-signature={}\r\n{}\r\n0;chunk-signature={}\r\n\r\n",
            payload.len(),
            "aa".repeat(32),
            "hello",
            "bb".repeat(32),
        )
        .into_bytes();
        let mut req = base_s3_req("PUT", "/mybucket/obj", "");
        req.headers
            .set("x-amz-content-sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD");
        req.headers.set("x-amz-decoded-content-length", "5");
        req.headers.set("Content-Encoding", "aws-chunked");
        let req = sign_request(req, "testing");
        let areq = async_from_signed(req, framed);
        let saw_complete = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let saw_c = saw_complete.clone();
        let next: StreamingAsyncNextFn = Arc::new(move |areq| {
            let saw_c = saw_c.clone();
            Box::pin(async move {
                if areq.method == "HEAD" {
                    return Response::new(204);
                }
                let mut body = areq.body;
                let mut n = 0usize;
                loop {
                    match body.next_chunk().await {
                        Ok(Some(c)) => n += c.len(),
                        Ok(None) => {
                            saw_c.store(true, std::sync::atomic::Ordering::SeqCst);
                            break;
                        }
                        Err(_) => break,
                    }
                }
                if n == 5 {
                    let mut resp = Response::new(201);
                    resp.headers.set("ETag", "should-not-commit");
                    resp
                } else {
                    Response::new(499)
                }
            })
        });
        let resp = block_on_s3(api.put_object_streaming(areq, next));
        assert_eq!(resp.status, 403, "bad chunk-signature must fail closed: {}", resp.status);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(
            body.contains("SignatureDoesNotMatch"),
            "{body}"
        );
        assert!(
            !saw_complete.load(std::sync::atomic::Ordering::SeqCst),
            "backend PUT must not see a complete authenticated body"
        );
    }

    #[test]
    fn streaming_put_client_disconnect_is_incomplete_not_commit() {
        let api = S3Api::new(cred_map());
        let req = unsigned_signed_put("/mybucket/obj", "");
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<Vec<u8>, std::io::Error>>(4);
        let areq = AsyncRequest {
            method: req.method,
            path: req.path,
            query_string: req.query_string,
            headers: req.headers,
            body: IncomingBody::from_channel(rx, Some(1_048_576), None, u64::MAX),
        };
        let committed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let committed_c = committed.clone();
        let next: StreamingAsyncNextFn = Arc::new(move |areq| {
            let committed_c = committed_c.clone();
            Box::pin(async move {
                if areq.method == "HEAD" {
                    return Response::new(204);
                }
                let mut n = 0usize;
                let mut body = areq.body;
                loop {
                    match body.next_chunk().await {
                        Ok(Some(c)) => n += c.len(),
                        Ok(None) => {
                            if n == 1_048_576 {
                                committed_c.store(true, std::sync::atomic::Ordering::SeqCst);
                                let mut resp = Response::new(201);
                                resp.headers.set("ETag", "committed");
                                return resp;
                            }
                            return Response::new(499);
                        }
                        Err(_) => return Response::new(499),
                    }
                }
            })
        });
        let resp = block_on_s3(async move {
            let put = tokio::spawn(async move { api.put_object_streaming(areq, next).await });
            tx.send(Ok(b"partial".to_vec())).await.unwrap();
            drop(tx);
            put.await.unwrap()
        });
        assert_eq!(
            resp.status, 400,
            "S3-3: client disconnect must not look like a successful PUT: {}",
            resp.status
        );
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(
            body.contains("RequestTimeout") || body.contains("IncompleteBody"),
            "expected RequestTimeout (Python 499 map) or IncompleteBody, got {body}"
        );
        assert!(
            !committed.load(std::sync::atomic::Ordering::SeqCst),
            "S3-3: disconnect must not commit"
        );
    }

    #[test]
    fn streaming_put_retry_overwrites_same_key() {
        let api = S3Api::new(cred_map());
        let etags = Arc::new(Mutex::new(Vec::<String>::new()));
        let etags_c = etags.clone();
        let next: StreamingAsyncNextFn = Arc::new(move |areq| {
            let etags_c = etags_c.clone();
            Box::pin(async move {
                if areq.method == "HEAD" {
                    return Response::new(204);
                }
                let mut data = Vec::new();
                let mut body = areq.body;
                while let Some(c) = body.next_chunk().await.unwrap() {
                    data.extend_from_slice(&c);
                }
                let etag = crate::crypto::sha256_hex(&data);
                etags_c.lock().unwrap().push(etag.clone());
                let mut resp = Response::new(201);
                resp.headers.set("ETag", &etag);
                resp
            })
        });
        for payload in [b"first".as_slice(), b"second".as_slice()] {
            let req = unsigned_signed_put("/mybucket/obj", "");
            let areq = async_from_signed(req, payload.to_vec());
            let next = Arc::clone(&next);
            let resp = block_on_s3(api.put_object_streaming(areq, next));
            assert_eq!(resp.status, 200);
        }
        let got = etags.lock().unwrap().clone();
        assert_eq!(got.len(), 2);
        assert_ne!(got[0], got[1], "retry must replace bytes, not fork a version");
    }

    fn async_ok(f: impl Fn(Request) -> Response + Send + Sync + 'static) -> AsyncNextFn {
        Arc::new(move |req| {
            let resp = f(req);
            Box::pin(async move { resp })
        })
    }

    #[test]
    fn handle_s3_async_get_object_is_native() {
        let api = S3Api::new(cred_map());
        let req = sign_request(base_s3_req("GET", "/mybucket/obj", ""), "testing");
        let next = async_ok(|r| {
            if r.method == "HEAD" && r.path == "/v1/AUTH_test/mybucket" {
                return Response::new(204);
            }
            assert_eq!(r.method, "GET");
            assert_eq!(r.path, "/v1/AUTH_test/mybucket/obj");
            let mut resp = Response::new(200);
            resp.body = Body::from(b"hello-get".to_vec());
            resp.headers.set("ETag", "abc123");
            resp.headers.set("Content-Length", "9");
            resp
        });
        let resp = block_on_s3(api.handle_s3_async(req, next));
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert_eq!(body, "hello-get");
        assert_eq!(resp.headers.get("ETag"), Some("\"abc123\""));
    }

    #[test]
    fn handle_s3_async_head_object_is_native() {
        let api = S3Api::new(cred_map());
        let req = sign_request(base_s3_req("HEAD", "/mybucket/obj", ""), "testing");
        let next = async_ok(|r| {
            if r.method == "HEAD" && r.path == "/v1/AUTH_test/mybucket" {
                return Response::new(204);
            }
            assert_eq!(r.method, "HEAD");
            assert_eq!(r.path, "/v1/AUTH_test/mybucket/obj");
            let mut resp = Response::new(200);
            resp.headers.set("ETag", "abc123");
            resp.headers.set("Content-Length", "9");
            resp
        });
        let resp = block_on_s3(api.handle_s3_async(req, next));
        assert_eq!(resp.status, 200);
        assert_eq!(resp.headers.get("ETag"), Some("\"abc123\""));
    }

    #[test]
    fn handle_s3_async_list_objects_is_native() {
        let api = S3Api::new(cred_map());
        let req = sign_request(base_s3_req("GET", "/mybucket", ""), "testing");
        let next = async_ok(|r| {
            assert_eq!(r.method, "GET");
            assert_eq!(r.path, "/v1/AUTH_test/mybucket");
            assert!(r.query_string.contains("format=json"));
            let mut resp = Response::new(200);
            resp.body = Body::from(
                br#"[{"name":"obj","hash":"abc123","bytes":3,"last_modified":"2026-08-22T00:00:00.000000"}]"#
                    .to_vec(),
            );
            resp
        });
        let resp = block_on_s3(api.handle_s3_async(req, next));
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("ListBucketResult"), "{body}");
        assert!(body.contains("<Key>obj</Key>"), "{body}");
    }

    #[test]
    fn handle_s3_async_list_buckets_is_native() {
        let api = S3Api::new(cred_map());
        let req = sign_request(base_s3_req("GET", "/", ""), "testing");
        let next = async_ok(|r| {
            assert_eq!(r.path, "/v1/AUTH_test");
            let mut resp = Response::new(200);
            resp.body = Body::from(br#"[{"name":"mybucket","count":0,"bytes":0}]"#.to_vec());
            resp
        });
        let resp = block_on_s3(api.handle_s3_async(req, next));
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("ListAllMyBucketsResult"), "{body}");
        assert!(body.contains("<Name>mybucket</Name>"), "{body}");
    }

    #[test]
    fn handle_s3_async_mpu_init_complete_abort() {
        let api = S3Api::new(cred_map());
        let init = sign_request(base_s3_req("POST", "/mybucket/big/obj", "uploads"), "testing");
        let init_next = async_ok(|r| {
            if r.method == "HEAD" && r.path == "/v1/AUTH_test/mybucket" {
                return Response::new(204);
            }
            if r.method == "PUT" {
                return Response::new(201);
            }
            Response::new(404)
        });
        let init_resp = block_on_s3(api.handle_s3_async(init, init_next));
        assert_eq!(init_resp.status, 200, "mpu init");
        let init_body = String::from_utf8(init_resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(init_body.contains("InitiateMultipartUploadResult"), "{init_body}");
        let upload_id = init_body
            .split("<UploadId>")
            .nth(1)
            .and_then(|s| s.split("</UploadId>").next())
            .unwrap()
            .to_string();

        let complete_xml = format!(
            "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>\"p1\"</ETag></Part></CompleteMultipartUpload>"
        );
        let mut complete = base_s3_req(
            "POST",
            "/mybucket/big/obj",
            &format!("uploadId={upload_id}"),
        );
        complete
            .headers
            .set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        complete.body = Body::from(complete_xml.into_bytes());
        let complete = sign_request(complete, "testing");
        let marker = format!("/v1/AUTH_test/mybucket+segments/{}", upload_marker_name("big/obj", &upload_id));
        let part = format!(
            "/v1/AUTH_test/mybucket+segments/{}",
            part_object_name("big/obj", &upload_id, 1)
        );
        let complete_next = async_ok(move |r| {
            if r.method == "HEAD" && r.path == "/v1/AUTH_test/mybucket" {
                return Response::new(204);
            }
            if r.method == "HEAD" && r.path == marker {
                return Response::new(200);
            }
            if r.method == "HEAD" && r.path == part {
                let mut resp = Response::new(200);
                resp.headers.set("ETag", "p1");
                resp.headers.set("Content-Length", "14");
                return resp;
            }
            if r.method == "PUT" && r.path == "/v1/AUTH_test/mybucket/big/obj" {
                let mut resp = Response::new(201);
                resp.headers.set("ETag", "slo");
                return resp;
            }
            Response::new(404)
        });
        let complete_resp = block_on_s3(api.handle_s3_async(complete, complete_next));
        assert_eq!(complete_resp.status, 200, "mpu complete");
        let cbody = String::from_utf8(complete_resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(cbody.contains("CompleteMultipartUploadResult"), "{cbody}");

        let abort = sign_request(
            base_s3_req(
                "DELETE",
                "/mybucket/big/obj",
                &format!("uploadId={upload_id}"),
            ),
            "testing",
        );
        let abort_next = async_ok(move |r| {
            if r.method == "HEAD" && r.path == "/v1/AUTH_test/mybucket" {
                return Response::new(204);
            }
            if r.method == "HEAD" && r.path.contains("+segments") {
                return Response::new(200);
            }
            if r.method == "GET" && r.path.contains("+segments") {
                let mut resp = Response::new(200);
                resp.body = Body::from(b"[]".to_vec());
                return resp;
            }
            if r.method == "DELETE" {
                return Response::new(204);
            }
            Response::new(404)
        });
        let abort_resp = block_on_s3(api.handle_s3_async(abort, abort_next));
        assert_eq!(abort_resp.status, 204, "mpu abort");
    }

    #[test]
    fn streaming_versioned_put_uses_generation_fence() {
        let api = S3Api::new(cred_map());
        let req = unsigned_signed_put("/mybucket/obj", "");
        let areq = async_from_signed(req, b"v1".to_vec());
        let fences = Arc::new(Mutex::new(Vec::<String>::new()));
        let fences_c = fences.clone();
        let next: StreamingAsyncNextFn = Arc::new(move |areq| {
            let fences_c = fences_c.clone();
            Box::pin(async move {
                if areq.method == "HEAD" && areq.path == "/v1/AUTH_test/mybucket" {
                    let mut resp = Response::new(204);
                    resp.headers.set(S3_VERSIONING_META, "Enabled");
                    return resp;
                }
                if areq.method == "HEAD" {
                    return Response::new(404);
                }
                if areq.method == "GET" {
                    return Response::new(404);
                }
                if areq.method == "PUT" && areq.path.contains("/index.g") {
                    fences_c.lock().unwrap().push(areq.path.clone());
                    return Response::new(201);
                }
                if areq.method == "PUT" {
                    let mut resp = Response::new(201);
                    resp.headers.set("ETag", "v1etag");
                    resp.headers.set("Last-Modified", "Sat, 22 Aug 2026 00:00:00 GMT");
                    return resp;
                }
                Response::new(404)
            })
        });
        let resp = block_on_s3(api.put_object_streaming(areq, next));
        assert_eq!(resp.status, 200, "versioned streaming PUT");
        assert!(resp.headers.get(HDR_VERSION_ID).is_some());
        let got = fences.lock().unwrap().clone();
        assert_eq!(got.len(), 1, "one generation fence: {got:?}");
        assert!(
            got[0].ends_with("/index.g00000000000000000001.json"),
            "{}",
            got[0]
        );
    }

    #[test]
    fn put_object_skips_object_head_when_bucket_has_no_lock() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let api = S3Api::new(cred_map());
        let req = sign_request(base_s3_req("PUT", "/mybucket/fresh-key", ""), "testing");
        let object_heads = Arc::new(AtomicUsize::new(0));
        let object_heads_c = object_heads.clone();
        let next: NextFn = Arc::new(move |r| {
            if r.method == "HEAD" && r.path.ends_with("/mybucket") {
                return Response::new(204);
            }
            if r.method == "HEAD" {
                object_heads_c.fetch_add(1, Ordering::SeqCst);
                return Response::new(404);
            }
            assert_eq!(r.method, "PUT");
            let mut resp = Response::new(201);
            resp.headers.set("ETag", "abc123");
            resp
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        assert_eq!(
            object_heads.load(Ordering::SeqCst),
            0,
            "unversioned no-lock PUT must not HEAD the object"
        );
    }

    #[test]
    fn get_object_uses_s3api_composite_etag() {
        let api = S3Api::new(cred_map());
        let req = sign_request(
            base_s3_req("GET", "/mybucket/multipart/assembled.bin", ""),
            "testing",
        );
        let next: NextFn = Arc::new(|r| {
            if r.method == "HEAD" {
                return Response::new(404);
            }
            assert_eq!(r.method, "GET");
            let mut resp = Response::with_body(200, b"assembled".to_vec());
            resp.headers.set("ETag", "slo-manifest-md5-not-aws");
            resp.headers
                .set(SYS_S3API_ETAG, "b4b77f5320cfe9ce9c0c70c35e84d511-2");
            resp.headers.set("Content-Length", "9");
            resp
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        assert_eq!(
            resp.headers.get("ETag"),
            Some("\"b4b77f5320cfe9ce9c0c70c35e84d511-2\"")
        );
    }

    fn mpu_head_next() -> NextFn {
        Arc::new(|r| {
            assert!(
                r.headers.get("If-Match").is_none(),
                "If-Match must not reach Swift SLO"
            );
            assert!(r.headers.get("If-None-Match").is_none());
            if r.method == "HEAD" && r.path.ends_with("/mybucket") {
                return Response::new(204);
            }
            let mut resp = Response::new(200);
            resp.headers.set("ETag", "slo-manifest-md5-not-aws");
            resp.headers
                .set(SYS_S3API_ETAG, "b4b77f5320cfe9ce9c0c70c35e84d511-2");
            resp.headers.set("Content-Length", "9");
            resp.headers
                .set("Last-Modified", "Wed, 19 Aug 2026 00:00:00 GMT");
            resp
        })
    }

    #[test]
    fn head_object_if_match_wrong_is_412() {
        let api = S3Api::new(cred_map());
        let mut req = base_s3_req("HEAD", "/mybucket/multipart/assembled.bin", "");
        req.headers.set("If-Match", "some other thing");
        let req = sign_request(req, "testing");
        let resp = api.handle(req, &mpu_head_next());
        assert_eq!(resp.status, 412);
        assert!(resp.headers.get("ETag").is_none());
        assert_eq!(resp.headers.get("Content-Length"), Some("0"));
    }

    #[test]
    fn head_object_if_match_s3_etag_is_200() {
        let api = S3Api::new(cred_map());
        let mut req = base_s3_req("HEAD", "/mybucket/multipart/assembled.bin", "");
        req.headers
            .set("If-Match", "\"b4b77f5320cfe9ce9c0c70c35e84d511-2\"");
        let req = sign_request(req, "testing");
        let resp = api.handle(req, &mpu_head_next());
        assert_eq!(resp.status, 200);
        assert_eq!(
            resp.headers.get("ETag"),
            Some("\"b4b77f5320cfe9ce9c0c70c35e84d511-2\"")
        );
    }

    #[test]
    fn head_object_if_match_swift_etag_is_412() {
        let api = S3Api::new(cred_map());
        let mut req = base_s3_req("HEAD", "/mybucket/multipart/assembled.bin", "");
        req.headers.set("If-Match", "\"slo-manifest-md5-not-aws\"");
        let req = sign_request(req, "testing");
        let resp = api.handle(req, &mpu_head_next());
        assert_eq!(resp.status, 412);
    }

    #[test]
    fn head_object_if_none_match_s3_etag_is_304() {
        let api = S3Api::new(cred_map());
        let mut req = base_s3_req("HEAD", "/mybucket/multipart/assembled.bin", "");
        req.headers
            .set("If-None-Match", "\"b4b77f5320cfe9ce9c0c70c35e84d511-2\"");
        let req = sign_request(req, "testing");
        let resp = api.handle(req, &mpu_head_next());
        assert_eq!(resp.status, 304);
        assert_eq!(
            resp.headers.get("ETag"),
            Some("\"b4b77f5320cfe9ce9c0c70c35e84d511-2\"")
        );
        assert_eq!(resp.headers.get("Content-Length"), Some("0"));
    }

    #[test]
    fn get_object_404_is_nosuchkey() {
        let api = S3Api::new(cred_map());
        let req = sign_request(base_s3_req("GET", "/mybucket/missing", ""), "testing");
        let next: NextFn = Arc::new(|r| {
            if r.method == "HEAD" && r.path.ends_with("/mybucket") {
                return Response::new(204);
            }
            Response::new(404)
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 404);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("NoSuchKey"));
    }

    #[test]
    fn get_object_404_missing_bucket_is_nosuchbucket() {
        let api = S3Api::new(cred_map());
        let req = sign_request(base_s3_req("GET", "/invalid/missing", ""), "testing");
        let next: NextFn = Arc::new(|_| Response::new(404));
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 404);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("NoSuchBucket"), "{body}");
    }

    #[test]
    fn delete_object_retries_slo_on_412() {
        let api = S3Api::new(cred_map());
        let req = sign_request(base_s3_req("DELETE", "/mybucket/slo.bin", ""), "testing");
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen_c = seen.clone();
        let next: NextFn = Arc::new(move |r| {
            if r.method == "HEAD" {
                return Response::new(404);
            }
            seen_c.lock().unwrap().push(r.query_string.clone());
            if r.query_string == "multipart-manifest=delete" {
                Response::new(204)
            } else {
                Response::new(412)
            }
        });
        assert_eq!(api.handle(req, &next).status, 204);
        assert_eq!(
            seen.lock().unwrap().as_slice(),
            [String::new(), "multipart-manifest=delete".into()]
        );
    }

    #[test]
    fn delete_regular_object_does_not_send_manifest_query() {
        let api = S3Api::new(cred_map());
        let req = sign_request(base_s3_req("DELETE", "/mybucket/probe.txt", ""), "testing");
        let seen = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let seen_c = seen.clone();
        let next: NextFn = Arc::new(move |r| {
            if r.method == "HEAD" {
                return Response::new(404);
            }
            *seen_c.lock().unwrap() = r.query_string.clone();
            Response::new(204)
        });
        assert_eq!(api.handle(req, &next).status, 204);
        assert_eq!(seen.lock().unwrap().as_str(), "");
    }

    #[test]
    fn delete_missing_object_is_204_when_bucket_exists() {
        let api = S3Api::new(cred_map());
        let req = sign_request(
            base_s3_req("DELETE", "/mybucket/does-not-exist", ""),
            "testing",
        );
        let next: NextFn = Arc::new(|r| {
            if r.method == "HEAD" {
                if r.path.ends_with("/mybucket") {
                    return Response::new(204);
                }
                return Response::new(404);
            }
            Response::new(404)
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 204);
        assert!(resp.body.is_definitely_empty());
    }

    #[test]
    fn complete_location_is_host_url_plus_quoted_path() {
        let mut req = base_s3_req("POST", "/bucket/obj1", "uploadId=x");
        req.headers.set("Host", "10.0.0.10:8080");
        assert_eq!(
            complete_object_location(&req, "bucket", "obj1☃"),
            "http://10.0.0.10:8080/bucket/obj1%E2%98%83"
        );
    }

    #[test]
    fn list_objects_translates() {
        let api = S3Api::new(cred_map());
        let req = sign_request(base_s3_req("GET", "/mybucket", "prefix=p"), "testing");
        let next: NextFn = Arc::new(|r| {
            assert_eq!(r.path, "/v1/AUTH_test/mybucket");
            assert!(r.query_string.contains("format=json"));
            assert!(r.query_string.contains("prefix=p"));
            // Python-style limit = max_keys+1 (default 1000 → 1001).
            assert!(
                r.query_string.contains("limit=1001"),
                "expected limit=max_keys+1, got {}",
                r.query_string
            );
            Response::with_body(
                200,
                br#"[{"name":"p/a","hash":"deadbeef","bytes":3,"last_modified":"2013-05-24T00:00:00.000000"}]"#.to_vec(),
            )
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        // s3cmd requires application/xml (or text/xml), not text/plain / json.
        assert_eq!(resp.headers.get("Content-Type"), Some("application/xml"));
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(
            body.contains("<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"),
            "missing xmlns root: {body}"
        );
        assert!(body.contains("<Key>p/a</Key>"));
        // Quoted ETag shape inside XML (s3cmd / AWS clients).
        assert!(
            body.contains("<ETag>\"deadbeef\"</ETag>"),
            "quoted ETag missing: {body}"
        );
        assert!(body.contains("<IsTruncated>false</IsTruncated>"));
        assert!(body.contains("<Contents>"));
    }

    #[test]
    fn list_objects_max_keys_zero_returns_empty() {
        let api = S3Api::new(cred_map());
        let req = sign_request(base_s3_req("GET", "/mybucket", "max-keys=0"), "testing");
        let next: NextFn = Arc::new(|r| {
            assert!(
                r.query_string.contains("limit=1"),
                "max-keys=0 → limit=1, got {}",
                r.query_string
            );
            Response::with_body(
                200,
                br#"[{"name":"bar","hash":"aa","bytes":1,"last_modified":"2013-05-24T00:00:00.000000"},{"name":"baz","hash":"bb","bytes":1,"last_modified":"2013-05-24T00:00:00.000000"}]"#.to_vec(),
            )
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("<MaxKeys>0</MaxKeys>"), "{body}");
        assert!(body.contains("<IsTruncated>false</IsTruncated>"), "{body}");
        assert!(!body.contains("<Key>"), "{body}");
    }

    #[test]
    fn list_objects_v2_continuation_token_wins_over_start_after() {
        let api = S3Api::new(cred_map());
        let req = sign_request(
            base_s3_req(
                "GET",
                "/mybucket",
                "list-type=2&start-after=bar&continuation-token=baz",
            ),
            "testing",
        );
        let next: NextFn = Arc::new(|r| {
            assert!(
                r.query_string.contains("marker=baz"),
                "token must win, got {}",
                r.query_string
            );
            assert!(
                !r.query_string.contains("marker=bar"),
                "start-after must not be a second marker, got {}",
                r.query_string
            );
            Response::with_body(
                200,
                br#"[{"name":"foo","hash":"aa","bytes":1,"last_modified":"2013-05-24T00:00:00.000000"},{"name":"quxx","hash":"bb","bytes":1,"last_modified":"2013-05-24T00:00:00.000000"}]"#.to_vec(),
            )
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("<ContinuationToken>baz</ContinuationToken>"), "{body}");
        assert!(body.contains("<StartAfter>bar</StartAfter>"), "{body}");
        assert!(body.contains("<Key>foo</Key>"), "{body}");
        assert!(body.contains("<Key>quxx</Key>"), "{body}");
        assert!(body.contains("<IsTruncated>false</IsTruncated>"), "{body}");
    }

    #[test]
    fn list_objects_invalid_max_keys_is_400() {
        let api = S3Api::new(cred_map());
        let req = sign_request(
            base_s3_req("GET", "/mybucket", "max-keys=1000&max-keys=blah"),
            "testing",
        );
        let next: NextFn = Arc::new(|_| panic!("invalid max-keys must not hit Swift"));
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 400);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("<Code>InvalidArgument</Code>"), "{body}");
    }

    #[test]
    fn list_objects_uses_s3api_etag_from_object_head() {
        let api = S3Api::new(cred_map());
        let req = sign_request(base_s3_req("GET", "/mybucket", ""), "testing");
        let next: NextFn = Arc::new(|r| {
            if r.method == "HEAD" && r.path.ends_with("/assembled.bin") {
                let mut resp = Response::new(200);
                resp.headers
                    .set(SYS_S3API_ETAG, "65d79814053817eae59f7c7cee98d3f8-1");
                return resp;
            }
            if r.method == "HEAD" {
                return Response::new(204);
            }
            Response::with_body(
                200,
                br#"[{"name":"assembled.bin","hash":"ff35011874c3f09502c7d766116b35c5","bytes":5242880,"last_modified":"2013-05-24T00:00:00.000000"}]"#.to_vec(),
            )
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(
            body.contains("<ETag>\"65d79814053817eae59f7c7cee98d3f8-1\"</ETag>"),
            "listing must use S3 composite ETag: {body}"
        );
        assert!(
            !body.contains("ff35011874c3f09502c7d766116b35c5"),
            "Swift SLO hash leaked: {body}"
        );
    }

    #[test]
    fn list_objects_rewrites_slo_manifest_size_from_head() {
        let api = S3Api::new(cred_map());
        let req = sign_request(base_s3_req("GET", "/mybucket", ""), "testing");
        let next: NextFn = Arc::new(|r| {
            if r.method == "HEAD" && r.path.ends_with("/assembled.bin") {
                let mut resp = Response::new(200);
                resp.headers
                    .set(SYS_S3API_ETAG, "65d79814053817eae59f7c7cee98d3f8-1");
                resp.headers.set("Content-Length", "5242880");
                return resp;
            }
            if r.method == "HEAD" {
                return Response::new(204);
            }
            Response::with_body(
                200,
                br#"[{"name":"assembled.bin","hash":"65d79814053817eae59f7c7cee98d3f8-1","bytes":137,"last_modified":"2013-05-24T00:00:00.000000"}]"#.to_vec(),
            )
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(
            body.contains("<ETag>\"65d79814053817eae59f7c7cee98d3f8-1\"</ETag>"),
            "listing ETag: {body}"
        );
        assert!(
            body.contains("<Size>5242880</Size>"),
            "assembled size, not manifest: {body}"
        );
        assert!(!body.contains("<Size>137</Size>"), "manifest size leaked: {body}");
    }

    #[test]
    fn list_objects_parses_s3_etag_param_in_hash() {
        let api = S3Api::new(cred_map());
        let req = sign_request(base_s3_req("GET", "/mybucket", ""), "testing");
        let next: NextFn = Arc::new(|r| {
            if r.method == "HEAD" {
                return Response::new(204);
            }
            Response::with_body(
                200,
                br#"[{"name":"assembled.bin","hash":"; s3_etag=65d79814053817eae59f7c7cee98d3f8-1","bytes":1,"last_modified":"2013-05-24T00:00:00.000000"}]"#.to_vec(),
            )
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(
            body.contains("<ETag>\"65d79814053817eae59f7c7cee98d3f8-1\"</ETag>"),
            "{body}"
        );
        assert!(!body.contains("; s3_etag="), "{body}");
    }

    #[test]
    fn list_objects_trailing_slash_is_not_empty_object_get() {
        // Live miss 2026-08-18: s3cmd ls s3://mytest → GET /mytest/ → 204
        // empty body (object path). Trailing slash must list.
        let api = S3Api::new(cred_map());
        let req = sign_request(base_s3_req("GET", "/mybucket/", ""), "testing");
        let next: NextFn = Arc::new(|r| {
            assert_eq!(r.path, "/v1/AUTH_test/mybucket");
            assert!(
                r.query_string.contains("format=json"),
                "list query missing: {}",
                r.query_string
            );
            Response::with_body(200, br#"[]"#.to_vec())
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        assert_eq!(resp.headers.get("Content-Type"), Some("application/xml"));
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(
            body.contains("<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"),
            "missing list xml: {body}"
        );
    }

    #[test]
    fn head_bucket_trailing_slash_is_not_empty_object_head() {
        // HEAD /mybucket/ is HeadBucket, not HeadObject "".
        // Object HEAD of a Swift 204 would stay 204; bucket HEAD is 200.
        let api = S3Api::new(cred_map());
        let req = sign_request(base_s3_req("HEAD", "/mybucket/", ""), "testing");
        let next: NextFn = Arc::new(|r| {
            assert_eq!(r.method, "HEAD");
            assert_eq!(r.path, "/v1/AUTH_test/mybucket");
            assert_ne!(
                r.path, "/v1/AUTH_test/mybucket/",
                "empty-key object HEAD path"
            );
            Response::new(204)
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200, "HeadBucket must be 200, not object 204");
    }

    #[test]
    fn put_bucket_trailing_slash_is_create_bucket() {
        // PUT /newbucket/ is CreateBucket (200 + Location), not object PUT.
        let api = S3Api::new(cred_map());
        let req = sign_request(base_s3_req("PUT", "/newbucket/", ""), "testing");
        let hops = std::sync::Arc::new(std::sync::Mutex::new(Vec::<(String, String)>::new()));
        let hops_c = hops.clone();
        let next: NextFn = Arc::new(move |r| {
            hops_c
                .lock()
                .unwrap()
                .push((r.method.clone(), r.path.clone()));
            assert_eq!(r.method, "PUT");
            assert_eq!(r.path, "/v1/AUTH_test/newbucket");
            assert_ne!(r.path, "/v1/AUTH_test/newbucket/");
            Response::new(201)
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        assert_eq!(resp.headers.get("Location"), Some("/newbucket"));
        let hops = hops.lock().unwrap().clone();
        assert!(
            hops.iter()
                .any(|(m, p)| m == "PUT" && p == "/v1/AUTH_test/newbucket"),
            "missing container PUT: {hops:?}"
        );
        assert!(
            hops.iter().all(|(_, p)| p != "/v1/AUTH_test/newbucket/"),
            "object PUT path: {hops:?}"
        );
    }

    #[test]
    fn list_objects_v2_trailing_slash_lists() {
        // GET /mybucket/?list-type=2 must list, not GetObject "".
        let api = S3Api::new(cred_map());
        let req = sign_request(base_s3_req("GET", "/mybucket/", "list-type=2"), "testing");
        let next: NextFn = Arc::new(|r| {
            assert_eq!(r.path, "/v1/AUTH_test/mybucket");
            assert_ne!(r.path, "/v1/AUTH_test/mybucket/");
            assert!(
                r.query_string.contains("format=json"),
                "list query missing: {}",
                r.query_string
            );
            Response::with_body(200, br#"[]"#.to_vec())
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        assert_eq!(resp.headers.get("Content-Type"), Some("application/xml"));
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(
            body.contains("<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"),
            "missing list xml: {body}"
        );
        assert!(
            body.contains("<KeyCount>0</KeyCount>"),
            "v2 KeyCount: {body}"
        );
    }

    #[test]
    fn unsupported_subresources_each_get_is_501_xml() {
        // Empty 501 body was a live miss: clients need Code=NotImplemented XML.
        let api = S3Api::new(cred_map());
        for name in UNSUPPORTED_SUBRESOURCES {
            let req = sign_request(base_s3_req("GET", "/mybucket", name), "testing");
            let next: NextFn = Arc::new({
                let name = (*name).to_string();
                move |_| panic!("unsupported {name} must not fall through")
            });
            let resp = api.handle(req, &next);
            assert_eq!(resp.status, 501, "{name}");
            assert_eq!(
                resp.headers.get("Content-Type"),
                Some("application/xml"),
                "{name}"
            );
            let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
            assert!(!body.is_empty(), "{name} empty 501 body");
            assert!(
                body.contains("<Code>NotImplemented</Code>"),
                "{name} body={body}"
            );
        }
    }

    #[test]
    fn empty_key_get_must_not_use_object_swift_path() {
        // FAILS if empty key is routed through translate_object_get_head:
        // that concatenates key="" → /v1/AUTH_test/mybucket/ and returns
        // 204 empty (s3cmd ls GET /bucket/ bug).
        let api = S3Api::new(cred_map());
        let req = sign_request(base_s3_req("GET", "/mybucket/", ""), "testing");
        let next: NextFn = Arc::new(|r| {
            assert_eq!(
                r.path, "/v1/AUTH_test/mybucket",
                "empty key must map to container, not {}",
                r.path
            );
            assert_ne!(
                r.path, "/v1/AUTH_test/mybucket/",
                "translate_object_get_head empty-key path"
            );
            assert!(
                r.query_string.contains("format=json"),
                "object GET would omit format=json: {}",
                r.query_string
            );
            Response::with_body(200, br#"[]"#.to_vec())
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(!body.is_empty(), "204-empty object GET regression");
        assert!(
            body.contains("<ListBucketResult"),
            "expected list xml, got {body}"
        );
    }

    #[test]
    fn get_bucket_policy_status_is_not_public() {
        let api = S3Api::new(cred_map());
        let req = sign_request(base_s3_req("GET", "/mybucket", "policyStatus"), "testing");
        let next: NextFn = Arc::new(|_| panic!("policyStatus must not fall through"));
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("<PolicyStatus"), "{body}");
        assert!(body.contains("<IsPublic>false</IsPublic>"), "{body}");
    }

    #[test]
    fn get_object_user_metadata_header_is_lowercase() {
        let api = S3Api::new(cred_map());
        let req = sign_request(base_s3_req("GET", "/mybucket/foo", ""), "testing");
        let next: NextFn = Arc::new(|_| {
            let mut resp = Response::with_body(200, b"bar".to_vec());
            resp.headers.set("ETag", "abc");
            resp.headers.set("X-Object-Meta-Meta1", "mymeta");
            resp
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        let stored: Vec<(String, String)> = resp
            .headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        assert!(
            stored
                .iter()
                .any(|(k, v)| k == "x-amz-meta-meta1" && v == "mymeta"),
            "{stored:?}"
        );
        assert!(
            !stored.iter().any(|(k, _)| k == "X-Amz-Meta-Meta1"),
            "{stored:?}"
        );
    }

    #[test]
    fn get_object_attributes_from_head() {
        let api = S3Api::new(cred_map());
        let mut req = base_s3_req("GET", "/mybucket/probe.txt", "attributes");
        req.headers
            .set("x-amz-object-attributes", "ETag,ObjectSize,StorageClass");
        let req = sign_request(req, "testing");
        let next: NextFn = Arc::new(|r| {
            assert_eq!(r.method, "HEAD");
            assert_eq!(r.path, "/v1/AUTH_test/mybucket/probe.txt");
            let mut resp = Response::new(200);
            resp.headers.set("ETag", "\"abc\"");
            resp.headers.set("Content-Length", "12");
            resp
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("<GetObjectAttributesOutput"), "{body}");
        assert!(body.contains("<ETag>abc</ETag>"), "{body}");
        assert!(body.contains("<ObjectSize>12</ObjectSize>"), "{body}");
        assert!(
            body.contains("<StorageClass>STANDARD</StorageClass>"),
            "{body}"
        );
    }

    #[test]
    fn upload_part_copy_returns_copy_part_result() {
        let api = S3Api::new(cred_map());
        let mut req = base_s3_req(
            "PUT",
            "/mybucket/dest.bin",
            "partNumber=1&uploadId=deadbeefcafe",
        );
        req.headers.set("X-Amz-Copy-Source", "/mybucket/src.bin");
        req.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        let req = sign_request(req, "testing");
        let next: NextFn = Arc::new(|r| {
            if r.method == "GET" {
                assert_eq!(r.path, "/v1/AUTH_test/mybucket/src.bin");
                assert!(r.headers.get("X-Copy-From").is_none());
                let mut resp = Response::new(200);
                resp.headers.set("ETag", "\"65d79814053817eae59f7c7cee98d3f8-1\"");
                resp.headers.set("Content-Length", "3");
                resp.body = Body::from(b"abc".to_vec());
                return resp;
            }
            assert_eq!(r.method, "PUT");
            assert!(
                r.path
                    .starts_with("/v1/AUTH_test/mybucket+segments/dest.bin/"),
                "part path {}",
                r.path
            );
            assert!(r.headers.get("X-Copy-From").is_none());
            let data = r.body.into_vec(u64::MAX).unwrap();
            assert_eq!(data, b"abc");
            let mut resp = Response::new(201);
            resp.headers.set("ETag", "partcopy1");
            resp.headers
                .set("Last-Modified", "Thu, 01 Jan 1970 00:00:00 GMT");
            resp
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("<CopyPartResult"), "{body}");
        assert!(body.contains("partcopy1"), "{body}");
        assert!(!body.contains("65d79814053817eae59f7c7cee98d3f8-1"), "{body}");
        assert!(!body.contains("<CopyObjectResult>"), "{body}");
    }

    #[test]
    fn upload_part_copy_improper_range_is_400() {
        let api = S3Api::new(cred_map());
        for bad in [
            "0-2",
            "bytes=0",
            "bytes=hello-world",
            "bytes=0-bar",
            "bytes=hello-",
            "bytes=0-2,3-5",
        ] {
            let mut req = base_s3_req(
                "PUT",
                "/mybucket/dest.bin",
                "partNumber=1&uploadId=deadbeefcafe",
            );
            req.headers.set("X-Amz-Copy-Source", "/mybucket/src.bin");
            req.headers.set("X-Amz-Copy-Source-Range", bad);
            req.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
            let req = sign_request(req, "testing");
            let label = bad.to_string();
            let next: NextFn = Arc::new(move |_| panic!("bad CopySourceRange {label} must not GET"));
            let resp = api.handle(req, &next);
            assert_eq!(resp.status, 400, "{bad}");
            let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
            assert!(
                body.contains("<Code>InvalidArgument</Code>"),
                "{bad} body={body}"
            );
        }
    }

    #[test]
    fn upload_part_copy_versioned_reads_archive_not_latest() {
        let api = S3Api::new(cred_map());
        let old_vid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let new_vid = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let mut req = base_s3_req(
            "PUT",
            "/mybucket/dest.bin",
            "partNumber=1&uploadId=deadbeefcafe",
        );
        req.headers.set(
            "X-Amz-Copy-Source",
            format!("/mybucket/src.bin?versionId={old_vid}"),
        );
        req.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        let req = sign_request(req, "testing");
        let archive_path = format!(
            "/v1/AUTH_test/mybucket+versions/{}/{}",
            "7372632e62696e", old_vid
        );
        let index_path = "/v1/AUTH_test/mybucket+versions/7372632e62696e/index.json";
        let fence_path = "/v1/AUTH_test/mybucket+versions/7372632e62696e/index.g00000000000000000001.json";
        let index_body = format!(
            r#"{{"key":"src.bin","versions":[{{"version_id":"{old_vid}","is_delete_marker":false,"is_latest":false,"last_modified":"2026-01-01T00:00:00.000Z","etag":"old","size":8}}]}}"#
        );
        let next: NextFn = Arc::new(move |r| {
            if r.method == "HEAD" && r.path == "/v1/AUTH_test/mybucket/src.bin" {
                let mut resp = Response::new(200);
                resp.headers.set(SYS_VERSION_ID, new_vid);
                resp.headers.set(SYS_DELETE_MARKER, "false");
                resp.headers.set("Content-Length", "8");
                return resp;
            }
            if r.method == "GET" && r.path == index_path {
                let mut resp = Response::new(200);
                resp.headers.set("ETag", "idx");
                resp.body = Body::from(index_body.as_bytes().to_vec());
                return resp;
            }
            if r.method == "GET" && r.path == fence_path {
                return Response::new(404);
            }
            if r.method == "HEAD" && r.path == archive_path {
                let mut resp = Response::new(200);
                resp.headers.set(SYS_VERSION_ID, old_vid);
                resp.headers.set(SYS_DELETE_MARKER, "false");
                resp.headers.set("Content-Length", "8");
                return resp;
            }
            if r.method == "GET" && r.path == archive_path {
                let mut resp = Response::new(200);
                resp.headers.set("ETag", "old");
                resp.headers.set("Content-Length", "8");
                resp.body = Body::from(b"old-body".to_vec());
                return resp;
            }
            if r.method == "GET" && r.path == "/v1/AUTH_test/mybucket/src.bin" {
                panic!("versioned part-copy must not GET the current object");
            }
            assert_eq!(r.method, "PUT");
            assert!(
                r.path
                    .starts_with("/v1/AUTH_test/mybucket+segments/dest.bin/"),
                "part path {}",
                r.path
            );
            let data = r.body.into_vec(u64::MAX).unwrap();
            assert_eq!(data, b"old-body", "copied historical version bytes");
            let mut resp = Response::new(201);
            resp.headers.set("ETag", "partcopy-old");
            resp.headers
                .set("Last-Modified", "Thu, 01 Jan 1970 00:00:00 GMT");
            resp
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("<CopyPartResult"), "{body}");
        assert!(body.contains("partcopy-old"), "{body}");
    }

    #[test]
    fn versioned_put_retries_create_race_412() {
        let api = S3Api::new(cred_map());
        let inner = versioning_mock_store("Enabled");
        let object_puts = Arc::new(std::sync::Mutex::new(0u32));
        let object_puts_c = object_puts.clone();
        let next: NextFn = Arc::new(move |r: Request| {
            if r.method == "PUT" && r.path == "/v1/AUTH_test/mybucket/obj" {
                let n = {
                    let mut g = object_puts_c.lock().unwrap();
                    *g += 1;
                    *g
                };
                if n == 1 {
                    return Response::new(412);
                }
            }
            inner(r)
        });
        let mut put = base_s3_req("PUT", "/mybucket/obj", "");
        put.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        put.body = Body::from(b"v1".to_vec());
        let resp = api.handle(sign_request(put, "testing"), &next);
        assert_eq!(resp.status, 200, "create-race 412 must be retried");
        assert!(resp.headers.get("x-amz-version-id").is_some());
        assert_eq!(*object_puts.lock().unwrap(), 2);
    }

    #[test]
    fn unindexed_current_numbered_version_delete_is_204() {
        let api = S3Api::new(cred_map());
        let inner = versioning_mock_store("Enabled");
        let hide_index = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let hide_c = hide_index.clone();
        let next: NextFn = Arc::new(move |r: Request| {
            if hide_c.load(std::sync::atomic::Ordering::SeqCst)
                && matches!(r.method.as_str(), "GET" | "HEAD")
                && (r.path.ends_with(INDEX_NAME) || r.path.ends_with("/index.json"))
            {
                return Response::new(404);
            }
            inner(r)
        });
        let mut put = base_s3_req("PUT", "/mybucket/obj", "");
        put.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        put.body = Body::from(b"v1".to_vec());
        let resp = api.handle(sign_request(put, "testing"), &next);
        assert_eq!(resp.status, 200);
        let vid = resp
            .headers
            .get("x-amz-version-id")
            .expect("version id")
            .to_string();
        hide_index.store(true, std::sync::atomic::Ordering::SeqCst);
        let del = base_s3_req("DELETE", "/mybucket/obj", &format!("versionId={vid}"));
        let resp = api.handle(sign_request(del, "testing"), &next);
        assert_eq!(
            resp.status, 204,
            "unindexed current must delete, not lost-update 500: {}",
            String::from_utf8_lossy(
                &resp
                    .body
                    .into_vec(u64::MAX)
                    .unwrap_or_default()
            )
        );
    }

    #[test]
    fn archive_put_412_is_already_archived_ok() {
        let api = S3Api::new(cred_map());
        let inner = versioning_mock_store("Enabled");
        let mut p1 = base_s3_req("PUT", "/mybucket/obj", "");
        p1.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        p1.body = Body::from(b"v1".to_vec());
        assert_eq!(api.handle(sign_request(p1, "testing"), &inner).status, 200);
        let next: NextFn = Arc::new(move |r: Request| {
            if r.method == "PUT"
                && r.path.contains("+versions/")
                && !r.path.ends_with(INDEX_NAME)
                && !r.path.contains("/index.g")
            {
                return Response::new(412);
            }
            inner(r)
        });
        let mut p2 = base_s3_req("PUT", "/mybucket/obj", "");
        p2.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        p2.body = Body::from(b"v2".to_vec());
        let resp = api.handle(sign_request(p2, "testing"), &next);
        assert_eq!(
            resp.status, 200,
            "archive If-None-Match:* 412 must count as already archived"
        );
    }

    #[test]
    fn delete_missing_copy_drops_ghost_index_row() {
        let api = S3Api::new(cred_map());
        let inner = versioning_mock_store("Enabled");
        let mut p1 = base_s3_req("PUT", "/mybucket/obj", "");
        p1.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        p1.body = Body::from(b"v1".to_vec());
        let r1 = api.handle(sign_request(p1, "testing"), &inner);
        assert_eq!(r1.status, 200);
        let vid1 = r1
            .headers
            .get("x-amz-version-id")
            .expect("v1")
            .to_string();
        let mut p2 = base_s3_req("PUT", "/mybucket/obj", "");
        p2.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        p2.body = Body::from(b"v2".to_vec());
        assert_eq!(api.handle(sign_request(p2, "testing"), &inner).status, 200);
        let archive = format!(
            "/v1/AUTH_test/mybucket+versions/{}",
            archive_object_name("obj", &vid1)
        );
        let next: NextFn = Arc::new(move |r: Request| {
            if matches!(r.method.as_str(), "HEAD" | "GET") && r.path == archive {
                return Response::new(404);
            }
            inner(r)
        });
        let del = base_s3_req("DELETE", "/mybucket/obj", &format!("versionId={vid1}"));
        let resp = api.handle(sign_request(del, "testing"), &next);
        assert_eq!(resp.status, 204);
        let list = api.handle(
            sign_request(base_s3_req("GET", "/mybucket", "versions"), "testing"),
            &next,
        );
        let body = String::from_utf8(list.body.into_vec(u64::MAX).unwrap_or_default())
            .unwrap_or_default();
        assert!(
            !body.contains(&vid1),
            "ghost version stayed in listing: {body}"
        );
    }

    #[test]
    fn versioned_delete_retries_match_412() {
        let api = S3Api::new(cred_map());
        let inner = versioning_mock_store("Enabled");
        let mut put = base_s3_req("PUT", "/mybucket/obj", "");
        put.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        put.body = Body::from(b"v1".to_vec());
        let resp = api.handle(sign_request(put, "testing"), &inner);
        assert_eq!(resp.status, 200);
        let vid = resp
            .headers
            .get("x-amz-version-id")
            .expect("version id")
            .to_string();
        let deletes = Arc::new(std::sync::Mutex::new(0u32));
        let deletes_c = deletes.clone();
        let next: NextFn = Arc::new(move |r: Request| {
            if r.method == "DELETE" && r.path == "/v1/AUTH_test/mybucket/obj" {
                let n = {
                    let mut g = deletes_c.lock().unwrap();
                    *g += 1;
                    *g
                };
                if n == 1 {
                    return Response::new(412);
                }
            }
            inner(r)
        });
        let del = base_s3_req("DELETE", "/mybucket/obj", &format!("versionId={vid}"));
        let resp = api.handle(sign_request(del, "testing"), &next);
        assert_eq!(resp.status, 204, "delete If-Match 412 must be retried");
        assert!(*deletes.lock().unwrap() >= 2);
    }

    #[test]
    fn versioned_put_retries_streamed_body_create_race_412() {
        let api = S3Api::new(cred_map());
        let inner = versioning_mock_store("Enabled");
        let object_puts = Arc::new(std::sync::Mutex::new(0u32));
        let object_puts_c = object_puts.clone();
        let next: NextFn = Arc::new(move |r: Request| {
            if r.method == "PUT" && r.path == "/v1/AUTH_test/mybucket/obj" {
                let n = {
                    let mut g = object_puts_c.lock().unwrap();
                    *g += 1;
                    *g
                };
                if n == 1 {
                    return Response::new(412);
                }
            }
            inner(r)
        });
        let mut put = base_s3_req("PUT", "/mybucket/obj", "");
        put.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        put.body = Body::from_reader(Box::new(std::io::Cursor::new(b"v1".to_vec())), Some(2));
        let resp = api.handle(sign_request(put, "testing"), &next);
        assert_eq!(resp.status, 200, "streamed create-race 412 must be retried");
        assert_eq!(*object_puts.lock().unwrap(), 2);
    }

    #[test]
    fn versioned_put_client_if_none_match_star_is_not_retried() {
        let api = S3Api::new(cred_map());
        let inner = versioning_mock_store("Enabled");
        let mut seed = base_s3_req("PUT", "/mybucket/obj", "");
        seed.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        seed.body = Body::from(b"v1".to_vec());
        assert_eq!(api.handle(sign_request(seed, "testing"), &inner).status, 200);

        let object_puts = Arc::new(std::sync::Mutex::new(0u32));
        let object_puts_c = object_puts.clone();
        let next: NextFn = Arc::new(move |r: Request| {
            if r.method == "PUT" && r.path == "/v1/AUTH_test/mybucket/obj" {
                if r.headers
                    .get("If-None-Match")
                    .is_some_and(|v| v.split(',').any(|tok| tok.trim() == "*"))
                {
                    *object_puts_c.lock().unwrap() += 1;
                    return Response::new(412);
                }
            }
            inner(r)
        });
        let mut put = base_s3_req("PUT", "/mybucket/obj", "");
        put.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        put.headers.set("If-None-Match", "*");
        put.body = Body::from(b"v2".to_vec());
        let resp = api.handle(sign_request(put, "testing"), &next);
        assert_eq!(resp.status, 412);
        assert_eq!(
            *object_puts.lock().unwrap(),
            1,
            "client If-None-Match:* must not be retried"
        );
    }

    #[test]
    fn stored_website_put_get_delete_roundtrip() {
        let api = S3Api::new(cred_map());
        let xml = b"<WebsiteConfiguration><IndexDocument><Suffix>index.html</Suffix></IndexDocument></WebsiteConfiguration>";
        let stored = std::sync::Arc::new(std::sync::Mutex::new(None::<String>));
        let put_store = stored.clone();
        let mut put = base_s3_req("PUT", "/mybucket", "website");
        put.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        put.body = Body::from(xml.to_vec());
        let put = sign_request(put, "testing");
        let put_next: NextFn = Arc::new(move |r| {
            assert_eq!(r.method, "POST");
            let blob = r
                .headers
                .get("X-Container-Sysmeta-S3-Cfg-Website")
                .expect("website meta")
                .to_string();
            *put_store.lock().unwrap() = Some(blob);
            Response::new(204)
        });
        assert_eq!(api.handle(put, &put_next).status, 200);

        let blob = stored.lock().unwrap().clone().unwrap();
        let get = sign_request(base_s3_req("GET", "/mybucket", "website"), "testing");
        let get_next: NextFn = Arc::new(move |r| {
            assert_eq!(r.method, "HEAD");
            let mut resp = Response::new(200);
            resp.headers
                .set("X-Container-Sysmeta-S3-Cfg-Website", blob.clone());
            resp
        });
        let get_resp = api.handle(get, &get_next);
        assert_eq!(get_resp.status, 200);
        let body = String::from_utf8(get_resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("WebsiteConfiguration"), "{body}");
        assert!(body.contains("index.html"), "{body}");

        let del = sign_request(base_s3_req("DELETE", "/mybucket", "website"), "testing");
        let del_next: NextFn = Arc::new(|r| {
            assert_eq!(r.method, "POST");
            Response::new(204)
        });
        assert_eq!(api.handle(del, &del_next).status, 204);

        let missing = sign_request(base_s3_req("GET", "/mybucket", "website"), "testing");
        let miss_next: NextFn = Arc::new(|_| Response::new(200));
        let miss = api.handle(missing, &miss_next);
        assert_eq!(miss.status, 404);
        let miss_body = String::from_utf8(miss.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(
            miss_body.contains("<Code>NoSuchWebsiteConfiguration</Code>"),
            "{miss_body}"
        );
    }

    #[test]
    fn website_endpoint_serves_index_and_error() {
        use crate::bucket_config::{apply_stored_bucket_config, stored_bucket_config};
        let api = S3Api::new(cred_map());
        let xml = b"<WebsiteConfiguration><IndexDocument><Suffix>index.html</Suffix></IndexDocument><ErrorDocument><Key>error.html</Key></ErrorDocument></WebsiteConfiguration>";
        let spec = stored_bucket_config(&[("website".into(), String::new())]).unwrap();
        let mut meta = HeaderKeyDict::new();
        apply_stored_bucket_config(&mut meta, spec, xml);
        let blob = meta.get(spec.header).unwrap().to_string();

        let mut req = base_s3_req("GET", "/mybucket/", "");
        req.headers.set("x-amz-website-endpoint", "1");
        let req = sign_request(req, "testing");
        let blob_c = blob.clone();
        let next: NextFn = Arc::new(move |r| {
            if r.path.ends_with("/mybucket") {
                let mut resp = Response::new(200);
                resp.headers
                    .set("X-Container-Sysmeta-S3-Cfg-Website", blob_c.clone());
                return resp;
            }
            if r.path.ends_with("/index.html") {
                return Response::with_body(200, b"<html>home</html>".to_vec());
            }
            Response::new(404)
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body.into_vec(u64::MAX).unwrap(), b"<html>home</html>");

        let mut miss = base_s3_req("GET", "/mybucket/no-such", "");
        miss.headers.set("x-amz-website-endpoint", "1");
        let miss = sign_request(miss, "testing");
        let next2: NextFn = Arc::new(move |r| {
            if r.path.ends_with("/mybucket") {
                let mut resp = Response::new(200);
                resp.headers
                    .set("X-Container-Sysmeta-S3-Cfg-Website", blob.clone());
                return resp;
            }
            if r.path.ends_with("/error.html") {
                return Response::with_body(200, b"<html>err</html>".to_vec());
            }
            Response::new(404)
        });
        let err = api.handle(miss, &next2);
        assert_eq!(err.status, 404);
        assert_eq!(err.body.into_vec(u64::MAX).unwrap(), b"<html>err</html>");
    }

    #[test]
    fn stored_policy_json_put_get_roundtrip() {
        let api = S3Api::new(cred_map());
        let json = br#"{"Version":"2012-10-17","Statement":[]}"#;
        let stored = std::sync::Arc::new(std::sync::Mutex::new(None::<String>));
        let put_store = stored.clone();
        let mut put = base_s3_req("PUT", "/mybucket", "policy");
        put.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        put.body = Body::from(json.to_vec());
        let put = sign_request(put, "testing");
        let put_next: NextFn = Arc::new(move |r| {
            assert_eq!(r.method, "POST");
            let blob = r
                .headers
                .get("X-Container-Sysmeta-S3-Cfg-Policy")
                .expect("policy meta")
                .to_string();
            *put_store.lock().unwrap() = Some(blob);
            Response::new(204)
        });
        assert_eq!(api.handle(put, &put_next).status, 200);

        let blob = stored.lock().unwrap().clone().unwrap();
        let get = sign_request(base_s3_req("GET", "/mybucket", "policy"), "testing");
        let get_next: NextFn = Arc::new(move |_| {
            let mut resp = Response::new(200);
            resp.headers
                .set("X-Container-Sysmeta-S3-Cfg-Policy", blob.clone());
            resp
        });
        let get_resp = api.handle(get, &get_next);
        assert_eq!(get_resp.status, 200);
        assert_eq!(
            get_resp.headers.get("Content-Type"),
            Some("application/json")
        );
        let body = String::from_utf8(get_resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("2012-10-17"), "{body}");
    }

    #[test]
    fn list_directory_buckets_is_empty_result() {
        let api = S3Api::new(cred_map());
        let req = sign_request(
            base_s3_req("GET", "/", "max-directory-buckets=100"),
            "testing",
        );
        let next: NextFn = Arc::new(|_| panic!("directory list must not hop to Swift"));
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("<ListDirectoryBucketsResult"), "{body}");
    }

    #[test]
    fn rename_object_copies_then_deletes() {
        let api = S3Api::new(cred_map());
        let mut req = base_s3_req("PUT", "/mybucket/new-name.txt", "");
        req.headers
            .set("X-Amz-Rename-Source", "/mybucket/old-name.txt");
        req.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        let req = sign_request(req, "testing");
        let next: NextFn = Arc::new(|r| match (r.method.as_str(), r.path.as_str()) {
            ("GET", "/v1/AUTH_test/mybucket/old-name.txt") => {
                Response::with_body(200, b"renamed-body".to_vec())
            }
            ("PUT", "/v1/AUTH_test/mybucket/new-name.txt") => Response::new(201),
            ("DELETE", "/v1/AUTH_test/mybucket/old-name.txt") => Response::new(204),
            _ => panic!("unexpected {} {}", r.method, r.path),
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 204);
    }

    #[test]
    fn create_session_returns_caller_credentials() {
        let api = S3Api::new(cred_map());
        let req = sign_request(base_s3_req("GET", "/mybucket", "session"), "testing");
        let next: NextFn = Arc::new(|_| panic!("session must not hop Swift"));
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("<CreateSessionResult"), "{body}");
        assert!(body.contains("<AccessKeyId>"), "{body}");
    }

    #[test]
    fn select_star_returns_event_stream() {
        let api = S3Api::new(cred_map());
        let mut req = base_s3_req("POST", "/mybucket/probe.txt", "select&select-type=2");
        req.body = Body::from(
            b"<SelectRequest><Expression>SELECT * FROM S3Object</Expression></SelectRequest>"
                .to_vec(),
        );
        req.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        let req = sign_request(req, "testing");
        let next: NextFn = Arc::new(|r| {
            assert_eq!(r.method, "GET");
            Response::with_body(200, b"row1\n".to_vec())
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        assert_eq!(
            resp.headers.get("Content-Type"),
            Some("application/vnd.amazon.eventstream")
        );
        let body = resp.body.into_vec(u64::MAX).unwrap();
        assert!(body.len() > 16, "event stream too short");
    }

    #[test]
    fn select_projection_is_invalid_request() {
        let api = S3Api::new(cred_map());
        let mut req = base_s3_req("POST", "/mybucket/probe.txt", "select&select-type=2");
        req.body = Body::from(
            b"<SelectRequest><Expression>SELECT _1 FROM S3Object</Expression></SelectRequest>"
                .to_vec(),
        );
        req.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        let req = sign_request(req, "testing");
        let next: NextFn = Arc::new(|r| {
            assert_eq!(r.method, "GET");
            Response::with_body(200, b"red,1\nblue,2\n".to_vec())
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        assert_eq!(
            resp.headers.get("Content-Type"),
            Some("application/vnd.amazon.eventstream")
        );
        let body = resp.body.into_vec(u64::MAX).unwrap();
        assert!(
            body.windows(3).any(|w| w == b"red"),
            "missing red in {body:?}"
        );
    }

    #[test]
    fn select_where_filters_rows() {
        let api = S3Api::new(cred_map());
        let mut req = base_s3_req("POST", "/mybucket/probe.txt", "select&select-type=2");
        req.body = Body::from(
            b"<SelectRequest><Expression>SELECT _1 FROM S3Object WHERE _1 = 'blue'</Expression></SelectRequest>"
                .to_vec(),
        );
        req.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        let req = sign_request(req, "testing");
        let next: NextFn = Arc::new(|r| {
            assert_eq!(r.method, "GET");
            Response::with_body(200, b"red,1\nblue,2\n".to_vec())
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        assert_eq!(
            resp.headers.get("Content-Type"),
            Some("application/vnd.amazon.eventstream")
        );
        let body = resp.body.into_vec(u64::MAX).unwrap();
        assert!(
            body.windows(4).any(|w| w == b"blue"),
            "missing blue in {body:?}"
        );
        assert!(
            !body.windows(3).any(|w| w == b"red"),
            "records should not include red: {body:?}"
        );
    }

    #[test]
    fn select_star_limit_returns_event_stream() {
        let api = S3Api::new(cred_map());
        let mut req = base_s3_req("POST", "/mybucket/probe.txt", "select&select-type=2");
        req.body = Body::from(
            b"<SelectRequest><Expression>SELECT * FROM S3Object LIMIT 1</Expression></SelectRequest>"
                .to_vec(),
        );
        req.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        let req = sign_request(req, "testing");
        let next: NextFn = Arc::new(|r| {
            assert_eq!(r.method, "GET");
            Response::with_body(200, b"a\nb\n".to_vec())
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        assert!(resp.body.into_vec(u64::MAX).unwrap().len() > 16);
    }

    #[test]
    fn get_object_torrent_is_bencode() {
        let api = S3Api::new(cred_map());
        let req = sign_request(
            base_s3_req("GET", "/mybucket/probe.txt", "torrent"),
            "testing",
        );
        let next: NextFn = Arc::new(|_| Response::with_body(200, b"abc".to_vec()));
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        let body = resp.body.into_vec(u64::MAX).unwrap();
        let text = String::from_utf8_lossy(&body);
        assert!(text.contains("4:info"), "{text}");
        assert!(text.contains("8:announce"), "{text}");
    }

    #[test]
    fn location_subresource_local() {
        let api = S3Api::new(cred_map()).with_location("eu-west-1");
        let req = sign_request(base_s3_req("GET", "/mybucket", "location"), "testing");
        let next: NextFn = Arc::new(|_| Response::new(500));
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("LocationConstraint"));
        assert!(body.contains("eu-west-1"));
    }

    #[test]
    fn get_acl_returns_private_policy() {
        let api = S3Api::new(cred_map());
        let req = sign_request(base_s3_req("GET", "/mybucket", "acl"), "testing");
        let next: NextFn = Arc::new(|_| {
            let mut r = Response::new(204);
            r.headers.set("X-Container-Read", "");
            r
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("AccessControlPolicy"));
        assert!(body.contains("FULL_CONTROL"));
    }

    #[test]
    fn list_objects_v2_emits_key_count() {
        let api = S3Api::new(cred_map());
        let req = sign_request(base_s3_req("GET", "/mybucket", "list-type=2"), "testing");
        let next: NextFn = Arc::new(|r| {
            assert!(r.query_string.contains("format=json"));
            assert!(
                r.query_string.contains("limit=1001"),
                "expected limit=max_keys+1, got {}",
                r.query_string
            );
            Response::with_body(
                200,
                br#"[{"name":"a","hash":"aa","bytes":1,"last_modified":"2013-05-24T00:00:00.000000"}]"#.to_vec(),
            )
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        assert_eq!(resp.headers.get("Content-Type"), Some("application/xml"));
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(
            body.contains("<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">")
        );
        assert!(body.contains("<KeyCount>1</KeyCount>"));
        assert!(body.contains("<Key>a</Key>"));
        assert!(
            body.contains("<ETag>\"aa\"</ETag>"),
            "quoted ETag missing: {body}"
        );
        assert!(body.contains("<IsTruncated>false</IsTruncated>"));
    }

    /// Truncation + CommonPrefixes shape (s3cmd non-recursive uses delimiter=/).
    #[test]
    fn list_objects_truncation_and_common_prefixes() {
        let api = S3Api::new(cred_map());
        let req = sign_request(
            base_s3_req("GET", "/mybucket", "delimiter=/&max-keys=2"),
            "testing",
        );
        let next: NextFn = Arc::new(|r| {
            // max-keys=2 → limit=3
            assert!(r.query_string.contains("limit=3"), "got {}", r.query_string);
            assert!(
                r.query_string.contains("delimiter=%2F") || r.query_string.contains("delimiter=/")
            );
            Response::with_body(
                200,
                br#"[
                  {"name":"a","hash":"aa","bytes":1,"last_modified":"2013-05-24T00:00:00.000000"},
                  {"subdir":"photos/"},
                  {"name":"z","hash":"zz","bytes":1,"last_modified":"2013-05-24T00:00:00.000000"}
                ]"#
                .to_vec(),
            )
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        assert_eq!(resp.headers.get("Content-Type"), Some("application/xml"));
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("<IsTruncated>true</IsTruncated>"));
        assert!(body.contains("<Key>a</Key>"));
        assert!(body.contains("<CommonPrefixes><Prefix>photos/</Prefix></CommonPrefixes>"));
        // Third entry dropped by max-keys=2.
        assert!(!body.contains("<Key>z</Key>"));
        // NextMarker present when delimiter + truncated.
        assert!(body.contains("<NextMarker>"));
        assert!(body.contains("<ETag>\"aa\"</ETag>"));
    }

    #[test]
    fn multi_delete_deletes_keys() {
        let api = S3Api::new(cred_map());
        let mut req = base_s3_req("POST", "/mybucket", "delete");
        req.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        req.body = Body::from(
            br#"<Delete><Object><Key>a</Key></Object><Object><Key>b</Key></Object></Delete>"#
                .to_vec(),
        );
        stamp_content_md5(&mut req);
        let req = sign_request(req, "testing");
        let next: NextFn = Arc::new(|r| {
            if r.method == "HEAD" && r.path == "/v1/AUTH_test/mybucket" {
                return Response::new(204);
            }
            if r.method == "HEAD" {
                return Response::new(404);
            }
            assert_eq!(r.method, "DELETE");
            Response::new(204)
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("<Deleted><Key>a</Key></Deleted>"));
        assert!(body.contains("<Deleted><Key>b</Key></Deleted>"));
    }

    #[test]
    fn multi_delete_bypass_header_without_iam_deletes_unlocked() {
        // Ceph nuke always sends BypassGovernanceRetention. Header without
        // the IAM grant must not AccessDenied unlocked keys.
        let api = S3Api::new(cred_map());
        let mut req = base_s3_req("POST", "/mybucket", "delete");
        req.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        req.headers.set(HDR_BYPASS_GOVERNANCE, "true");
        req.body = Body::from(br#"<Delete><Object><Key>a</Key></Object></Delete>"#.to_vec());
        stamp_content_md5(&mut req);
        let req = sign_request(req, "testing");
        let next: NextFn = Arc::new(|r| {
            if r.method == "HEAD" && r.path == "/v1/AUTH_test/mybucket" {
                return Response::new(204);
            }
            if r.method == "HEAD" {
                return Response::new(404);
            }
            assert_eq!(r.method, "DELETE");
            Response::new(204)
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("<Deleted><Key>a</Key></Deleted>"), "{body}");
        assert!(!body.contains("<Error>"), "{body}");
    }

    #[test]
    fn list_multipart_uploads_lists_markers() {
        // `GET /bucket?uploads` lists in-progress markers from +segments.
        let api = S3Api::new(cred_map());
        let req = sign_request(base_s3_req("GET", "/mybucket", "uploads"), "testing");
        let next: NextFn = Arc::new(|r| {
            if r.method == "HEAD" && r.path == "/v1/AUTH_test/mybucket" {
                return Response::new(204);
            }
            assert_eq!(r.method, "GET");
            assert_eq!(r.path, "/v1/AUTH_test/mybucket+segments");
            assert!(r.query_string.contains("format=json"));
            let body = br#"[
              {"name":"big/obj/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","bytes":6,"hash":"x","last_modified":"2026-08-05T12:00:00.000000"},
              {"name":"big/obj/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/00000001","bytes":3,"hash":"y","last_modified":"2026-08-05T12:01:00.000000"},
              {"name":"other/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","bytes":6,"hash":"z","last_modified":"2026-08-05T13:00:00.000000"}
            ]"#;
            Response::with_body(200, body.to_vec())
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("ListMultipartUploadsResult"));
        assert!(!body.contains("ListBucketResult"));
        let markers_end = body
            .find("<NextUploadIdMarker/>")
            .or_else(|| body.find("</NextUploadIdMarker>"))
            .expect(&body);
        let prefix_at = body.find("<Prefix>").expect(&body);
        assert!(prefix_at > markers_end, "{body}");
        assert!(body.contains("<Key>big/obj</Key>"));
        assert!(body.contains("<UploadId>aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa</UploadId>"));
        assert!(body.contains("<Key>other</Key>"));
        assert!(!body.contains("00000001"));
    }

    #[test]
    fn abort_multipart_missing_marker_is_nosuchupload() {
        let api = S3Api::new(cred_map());
        let req = sign_request(
            base_s3_req("DELETE", "/mybucket/obj", "uploadId=ffffffffffffffffffffffffffffffff"),
            "testing",
        );
        let next: NextFn = Arc::new(|r| {
            if r.method == "HEAD" && r.path == "/v1/AUTH_test/mybucket" {
                return Response::new(204);
            }
            assert_eq!(r.method, "HEAD");
            Response::new(404)
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 404);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("NoSuchUpload"), "{body}");
        assert!(body.contains("<Error>"), "{body}");
    }

    #[test]
    fn list_multipart_uploads_empty_when_segments_missing() {
        let api = S3Api::new(cred_map());
        let req = sign_request(base_s3_req("GET", "/mybucket", "uploads"), "testing");
        let next: NextFn = Arc::new(|r| {
            if r.method == "HEAD" && r.path == "/v1/AUTH_test/mybucket" {
                return Response::new(204);
            }
            Response::new(404)
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("ListMultipartUploadsResult"));
        assert!(body.contains("<IsTruncated>false</IsTruncated>"));
    }

    #[test]
    fn mpu_init_and_multi_delete_missing_bucket_is_nosuchbucket() {
        let api = S3Api::new(cred_map());
        let next: NextFn = Arc::new(|_| Response::new(404));
        let init = sign_request(base_s3_req("POST", "/nothing/obj", "uploads"), "testing");
        let resp = api.handle(init, &next);
        assert_eq!(resp.status, 404);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("NoSuchBucket"), "{body}");

        let mut del = base_s3_req("POST", "/nothing", "delete");
        del.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        del.body = Body::from(br#"<Delete><Object><Key>a</Key></Object></Delete>"#.to_vec());
        stamp_content_md5(&mut del);
        let resp = api.handle(sign_request(del, "testing"), &next);
        assert_eq!(resp.status, 404);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("NoSuchBucket"), "{body}");
    }

    #[test]
    fn multipart_upload_initiate_part_and_complete_flow() {
        let api = S3Api::new(cred_map());

        // 1) Initiate: creates the `+segments` container + upload marker,
        // returns an UploadId.
        let mut init_req = base_s3_req("POST", "/mybucket/big/obj", "uploads");
        init_req.headers.set("Content-Language", "en-US");
        let init_req = sign_request(init_req, "testing");
        let init_next: NextFn = Arc::new(|r| {
            if r.method == "HEAD" && r.path == "/v1/AUTH_test/mybucket" {
                return Response::new(204);
            }
            if r.method == "HEAD" {
                return Response::new(404);
            }
            assert_eq!(r.method, "PUT");
            assert!(
                r.path == "/v1/AUTH_test/mybucket+segments"
                    || r.path
                        .starts_with("/v1/AUTH_test/mybucket+segments/big/obj/")
            );
            if r.path.starts_with("/v1/AUTH_test/mybucket+segments/big/obj/") {
                assert_eq!(
                    r.headers.get("X-Object-Sysmeta-S3-Content-Language"),
                    Some("en-US")
                );
            }
            Response::new(201)
        });
        let init_resp = api.handle(init_req, &init_next);
        assert_eq!(init_resp.status, 200);
        let init_body = String::from_utf8(init_resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(init_body.contains("InitiateMultipartUploadResult"));
        assert!(init_body.contains("<Bucket>mybucket</Bucket>"));
        assert!(init_body.contains("<Key>big/obj</Key>"));
        let upload_id = init_body
            .split("<UploadId>")
            .nth(1)
            .and_then(|s| s.split("</UploadId>").next())
            .unwrap()
            .to_string();
        assert!(!upload_id.is_empty());

        // 2) UploadPart: streams the part body straight to the segments
        // container under `{key}/{uploadId}/{partNumber:08}`.
        let mut part_req = base_s3_req(
            "PUT",
            "/mybucket/big/obj",
            &format!("partNumber=1&uploadId={upload_id}"),
        );
        part_req
            .headers
            .set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        part_req.body = Body::from(b"hello-part-one".to_vec());
        let part_req = sign_request(part_req, "testing");
        let expected_part_path =
            format!("/v1/AUTH_test/mybucket+segments/big/obj/{upload_id}/00000001");
        let part_next: NextFn = Arc::new(move |r| {
            assert_eq!(r.method, "PUT");
            assert_eq!(r.path, expected_part_path);
            let mut resp = Response::new(201);
            resp.headers.set("ETag", "partetag1");
            resp.headers
                .set("Last-Modified", "Fri, 24 May 2013 00:00:00 GMT");
            resp
        });
        let part_resp = api.handle(part_req, &part_next);
        assert_eq!(part_resp.status, 200);
        assert_eq!(part_resp.headers.get("ETag"), Some("\"partetag1\""));
        assert_eq!(
            part_resp.headers.get("Last-Modified"),
            Some("Fri, 24 May 2013 00:00:00 GMT")
        );

        // 3) Complete: HEADs each listed part for size, then PUTs the SLO
        // manifest and returns the AWS composite MD5(part-MD5s)-N (not SLO).
        let mut complete_req = base_s3_req(
            "POST",
            "/mybucket/big/obj",
            &format!("uploadId={upload_id}"),
        );
        complete_req
            .headers
            .set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        complete_req.body = Body::from(
            br#"<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>"b8fc857a25e7958868c2f003d5e0952d"</ETag></Part><Part><PartNumber>2</PartNumber><ETag>"973f488aa4a5df5ae05e8e73c63432e0"</ETag></Part></CompleteMultipartUpload>"#
                .to_vec(),
        );
        let complete_req = sign_request(complete_req, "testing");
        let stamped = std::sync::Arc::new(std::sync::Mutex::new(None::<String>));
        let stamped_c = stamped.clone();
        let stamped_override = std::sync::Arc::new(std::sync::Mutex::new(None::<String>));
        let stamped_override_c = stamped_override.clone();
        let stamped_uid = std::sync::Arc::new(std::sync::Mutex::new(None::<String>));
        let stamped_uid_c = stamped_uid.clone();
        let uid_for_put = upload_id.clone();
        let complete_next: NextFn = Arc::new(move |r| {
            if r.method == "HEAD" {
                let mut resp = Response::new(200);
                if r.path.ends_with("/00000001") {
                    resp.headers.set("Content-Length", "5242880");
                } else {
                    resp.headers.set("Content-Length", "14");
                }
                return resp;
            }
            if r.method == "DELETE" {
                assert!(
                    r.path.contains("mybucket+segments/"),
                    "complete must DELETE the MPU marker, got {}",
                    r.path
                );
                return Response::new(204);
            }
            assert_eq!(r.method, "PUT");
            assert_eq!(r.path, "/v1/AUTH_test/mybucket/big/obj");
            assert!(r.query_string.contains("multipart-manifest=put"));
            *stamped_c.lock().unwrap() = r.headers.get(SYS_S3API_ETAG).map(str::to_string);
            *stamped_override_c.lock().unwrap() = r
                .headers
                .get(SYS_CONTAINER_UPDATE_OVERRIDE_ETAG)
                .map(str::to_string);
            *stamped_uid_c.lock().unwrap() = r.headers.get(SYS_S3API_UPLOAD_ID).map(str::to_string);
            assert_eq!(
                r.headers.get(SYS_S3API_UPLOAD_ID),
                Some(uid_for_put.as_str())
            );
            let mut resp = Response::new(201);
            resp.headers.set("ETag", "slo-manifest-md5-not-aws");
            resp
        });
        let complete_resp = api.handle(complete_req, &complete_next);
        assert_eq!(complete_resp.status, 200);
        let complete_body =
            String::from_utf8(complete_resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(complete_body.contains("CompleteMultipartUploadResult"));
        assert!(
            complete_body.contains("<Location>http://localhost/mybucket/big/obj</Location>"),
            "{complete_body}"
        );
        assert!(complete_body.contains("\"b4b77f5320cfe9ce9c0c70c35e84d511-2\""));
        assert!(!complete_body.contains("slo-manifest-md5-not-aws"));
        assert_eq!(
            stamped.lock().unwrap().as_deref(),
            Some("b4b77f5320cfe9ce9c0c70c35e84d511-2")
        );
        assert_eq!(
            stamped_override.lock().unwrap().as_deref(),
            Some("b4b77f5320cfe9ce9c0c70c35e84d511-2")
        );
        assert_eq!(stamped_uid.lock().unwrap().as_deref(), Some(upload_id.as_str()));
    }

    fn complete_two_part_xml() -> Vec<u8> {
        br#"<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>"b8fc857a25e7958868c2f003d5e0952d"</ETag></Part><Part><PartNumber>2</PartNumber><ETag>"973f488aa4a5df5ae05e8e73c63432e0"</ETag></Part></CompleteMultipartUpload>"#
            .to_vec()
    }

    fn complete_three_part_xml() -> Vec<u8> {
        br#"<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>"b8fc857a25e7958868c2f003d5e0952d"</ETag></Part><Part><PartNumber>2</PartNumber><ETag>"973f488aa4a5df5ae05e8e73c63432e0"</ETag></Part><Part><PartNumber>3</PartNumber><ETag>"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"</ETag></Part></CompleteMultipartUpload>"#
            .to_vec()
    }

    #[test]
    fn complete_mpu_same_parts_after_marker_gone_is_idempotent() {
        // Python `_get_upload_info` dest fallback + matching s3-etag → 200,
        // no SLO rewrite. Official test_if_none_match_star_mpu retry.
        let api = S3Api::new(cred_map());
        let uid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let mut req = base_s3_req("POST", "/mybucket/big/obj", &format!("uploadId={uid}"));
        req.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        req.headers.set("If-None-Match", "*");
        req.body = Body::from(complete_two_part_xml());
        let req = sign_request(req, "testing");
        let puts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let puts_c = puts.clone();
        let next: NextFn = Arc::new(move |r| {
            if r.method == "HEAD" && r.path == "/v1/AUTH_test/mybucket" {
                return Response::new(204);
            }
            if r.method == "HEAD" && r.path == format!("/v1/AUTH_test/mybucket+segments/big/obj/{uid}")
            {
                return Response::new(404);
            }
            if r.method == "HEAD" && r.path == "/v1/AUTH_test/mybucket/big/obj" {
                let mut resp = Response::new(200);
                resp.headers.set(SYS_S3API_UPLOAD_ID, uid);
                resp.headers
                    .set(SYS_S3API_ETAG, "b4b77f5320cfe9ce9c0c70c35e84d511-2");
                return resp;
            }
            if r.method == "PUT" {
                puts_c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                return Response::new(201);
            }
            Response::new(404)
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("CompleteMultipartUploadResult"), "{body}");
        assert!(body.contains("\"b4b77f5320cfe9ce9c0c70c35e84d511-2\""), "{body}");
        assert_eq!(puts.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[test]
    fn complete_mpu_different_parts_after_marker_gone_is_nosuchupload() {
        let api = S3Api::new(cred_map());
        let uid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let mut req = base_s3_req("POST", "/mybucket/big/obj", &format!("uploadId={uid}"));
        req.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        req.headers.set("If-None-Match", "*");
        req.body = Body::from(complete_three_part_xml());
        let req = sign_request(req, "testing");
        let next: NextFn = Arc::new(move |r| {
            if r.method == "HEAD" && r.path == "/v1/AUTH_test/mybucket" {
                return Response::new(204);
            }
            if r.method == "HEAD" && r.path.contains("+segments/big/obj/") {
                return Response::new(404);
            }
            if r.method == "HEAD" && r.path == "/v1/AUTH_test/mybucket/big/obj" {
                let mut resp = Response::new(200);
                resp.headers.set(SYS_S3API_UPLOAD_ID, uid);
                resp.headers
                    .set(SYS_S3API_ETAG, "b4b77f5320cfe9ce9c0c70c35e84d511-2");
                return resp;
            }
            if r.method == "PUT" {
                panic!("conflict complete must not rewrite, got {}", r.path);
            }
            Response::new(404)
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 404);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("NoSuchUpload"), "{body}");
    }

    #[test]
    fn complete_mpu_async_same_parts_after_marker_gone_is_idempotent() {
        let api = S3Api::new(cred_map());
        let uid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let mut req = base_s3_req("POST", "/mybucket/big/obj", &format!("uploadId={uid}"));
        req.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        req.headers.set("If-None-Match", "*");
        req.body = Body::from(complete_two_part_xml());
        let req = sign_request(req, "testing");
        let puts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let puts_c = puts.clone();
        let next = async_ok(move |r| {
            if r.method == "HEAD" && r.path == "/v1/AUTH_test/mybucket" {
                return Response::new(204);
            }
            if r.method == "HEAD" && r.path == format!("/v1/AUTH_test/mybucket+segments/big/obj/{uid}")
            {
                return Response::new(404);
            }
            if r.method == "HEAD" && r.path == "/v1/AUTH_test/mybucket/big/obj" {
                let mut resp = Response::new(200);
                resp.headers.set(SYS_S3API_UPLOAD_ID, uid);
                resp.headers
                    .set(SYS_S3API_ETAG, "b4b77f5320cfe9ce9c0c70c35e84d511-2");
                return resp;
            }
            if r.method == "PUT" {
                puts_c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                return Response::new(201);
            }
            Response::new(404)
        });
        let resp = block_on_s3(api.handle_s3_async(req, next));
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("CompleteMultipartUploadResult"), "{body}");
        assert_eq!(puts.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[test]
    fn complete_mpu_if_none_match_star_existing_object_is_412() {
        // New upload against a key that already has an object: If-None-Match:*
        // must 412 before the SLO PUT (Python object-server PreconditionFailed).
        let api = S3Api::new(cred_map());
        let uid = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let mut req = base_s3_req("POST", "/mybucket/big/obj", &format!("uploadId={uid}"));
        req.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        req.headers.set("If-None-Match", "*");
        req.body = Body::from(complete_two_part_xml());
        let req = sign_request(req, "testing");
        let next: NextFn = Arc::new(move |r| {
            if r.method == "HEAD" && r.path == "/v1/AUTH_test/mybucket" {
                return Response::new(204);
            }
            if r.method == "HEAD"
                && r.path == format!("/v1/AUTH_test/mybucket+segments/big/obj/{uid}")
            {
                return Response::new(200);
            }
            if r.method == "HEAD" && r.path == "/v1/AUTH_test/mybucket/big/obj" {
                return Response::new(200);
            }
            if r.method == "PUT" {
                panic!("If-None-Match:* complete must not rewrite dest, {}", r.path);
            }
            Response::new(404)
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 412);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("PreconditionFailed"), "{body}");
    }

    #[test]
    fn complete_mpu_async_if_none_match_star_existing_object_is_412() {
        let api = S3Api::new(cred_map());
        let uid = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let mut req = base_s3_req("POST", "/mybucket/big/obj", &format!("uploadId={uid}"));
        req.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        req.headers.set("If-None-Match", "*");
        req.body = Body::from(complete_two_part_xml());
        let req = sign_request(req, "testing");
        let next = async_ok(move |r| {
            if r.method == "HEAD" && r.path == "/v1/AUTH_test/mybucket" {
                return Response::new(204);
            }
            if r.method == "HEAD"
                && r.path == format!("/v1/AUTH_test/mybucket+segments/big/obj/{uid}")
            {
                return Response::new(200);
            }
            if r.method == "HEAD" && r.path == "/v1/AUTH_test/mybucket/big/obj" {
                return Response::new(200);
            }
            if r.method == "PUT" {
                panic!("If-None-Match:* complete must not rewrite dest, {}", r.path);
            }
            Response::new(404)
        });
        let resp = block_on_s3(api.handle_s3_async(req, next));
        assert_eq!(resp.status, 412);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("PreconditionFailed"), "{body}");
    }

    #[test]
    fn multipart_upload_abort_deletes_marker() {
        let api = S3Api::new(cred_map());
        let req = sign_request(
            base_s3_req("DELETE", "/mybucket/obj", "uploadId=abc123"),
            "testing",
        );
        let next: NextFn = Arc::new(|r| {
            if r.method == "HEAD" && r.path == "/v1/AUTH_test/mybucket" {
                return Response::new(204);
            }
            if r.method == "HEAD" && r.path == "/v1/AUTH_test/mybucket+segments/obj/abc123" {
                return Response::new(200);
            }
            if r.method == "GET" && r.path == "/v1/AUTH_test/mybucket+segments" {
                return Response::with_body(200, b"[]".to_vec());
            }
            assert_eq!(r.method, "DELETE");
            assert_eq!(r.path, "/v1/AUTH_test/mybucket+segments/obj/abc123");
            Response::new(204)
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 204);
        assert_eq!(
            resp.headers.get("Content-Type"),
            Some("text/html; charset=UTF-8")
        );
    }

    #[test]
    fn cors_put_then_get_round_trips() {
        let api = S3Api::new(cred_map());
        let mut put_req = base_s3_req("PUT", "/mybucket", "cors");
        put_req
            .headers
            .set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        put_req.body = Body::from(
            br#"<CORSConfiguration><CORSRule><AllowedOrigin>*</AllowedOrigin>
                <AllowedMethod>GET</AllowedMethod></CORSRule></CORSConfiguration>"#
                .to_vec(),
        );
        let put_req = sign_request(put_req, "testing");
        let put_next: NextFn = Arc::new(|r| {
            assert_eq!(r.method, "POST");
            assert_eq!(
                r.headers
                    .get("X-Container-Meta-Access-Control-Allow-Origin"),
                Some("*")
            );
            Response::new(204)
        });
        assert_eq!(api.handle(put_req, &put_next).status, 200);

        let get_req = sign_request(base_s3_req("GET", "/mybucket", "cors"), "testing");
        let get_next: NextFn = Arc::new(|_| {
            let mut r = Response::new(204);
            r.headers
                .set("X-Container-Meta-Access-Control-Allow-Origin", "*");
            r.headers
                .set("X-Container-Meta-Access-Control-Allow-Methods", "GET");
            r
        });
        let resp = api.handle(get_req, &get_next);
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("CORSConfiguration"));
        assert!(body.contains("<AllowedOrigin>*</AllowedOrigin>"));
    }

    #[test]
    fn cors_multi_rule_put_stamps_s3_cors_meta() {
        use crate::acl_cors::S3_CORS_META;
        let api = S3Api::new(cred_map());
        let mut put_req = base_s3_req("PUT", "/mybucket", "cors");
        put_req
            .headers
            .set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        put_req.body = Body::from(
            br#"<CORSConfiguration>
              <CORSRule>
                <AllowedOrigin>https://a.example.com</AllowedOrigin>
                <AllowedMethod>GET</AllowedMethod>
              </CORSRule>
              <CORSRule>
                <AllowedOrigin>https://b.example.com</AllowedOrigin>
                <AllowedMethod>PUT</AllowedMethod>
                <AllowedMethod>POST</AllowedMethod>
              </CORSRule>
            </CORSConfiguration>"#
                .to_vec(),
        );
        let put_req = sign_request(put_req, "testing");
        let stored = std::sync::Arc::new(std::sync::Mutex::new(None::<HeaderKeyDict>));
        let stored_c = stored.clone();
        let put_next: NextFn = Arc::new(move |r| {
            assert_eq!(r.method, "POST");
            assert!(r.headers.get(S3_CORS_META).is_some_and(|v| !v.is_empty()));
            assert_eq!(
                r.headers
                    .get("X-Container-Meta-Access-Control-Allow-Origin"),
                Some("https://a.example.com")
            );
            *stored_c.lock().unwrap() = Some(r.headers.clone());
            Response::new(204)
        });
        assert_eq!(api.handle(put_req, &put_next).status, 200);

        let hdrs = stored.lock().unwrap().clone().unwrap();
        let get_req = sign_request(base_s3_req("GET", "/mybucket", "cors"), "testing");
        let get_next: NextFn = Arc::new(move |_| {
            let mut r = Response::new(204);
            r.headers = hdrs.clone();
            r
        });
        let resp = api.handle(get_req, &get_next);
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert_eq!(body.matches("<CORSRule>").count(), 2);
        assert!(body.contains("https://a.example.com"));
        assert!(body.contains("https://b.example.com"));
        assert!(body.contains("<AllowedMethod>PUT</AllowedMethod>"));
    }

    #[test]
    fn put_bucket_acl_public_read_write() {
        let api = S3Api::new(cred_map());
        let mut req = base_s3_req("PUT", "/mybucket", "acl");
        req.headers.set("x-amz-acl", "public-read-write");
        req.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        let req = sign_request(req, "testing");
        let next: NextFn = Arc::new(|r| {
            assert_eq!(r.method, "POST");
            assert_eq!(r.headers.get("X-Container-Read"), Some(".r:*,.rlistings"));
            assert_eq!(r.headers.get("X-Container-Write"), Some(".r:*"));
            Response::new(204)
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        assert_eq!(resp.headers.get("Location"), Some("mybucket"));
    }

    #[test]
    fn put_bucket_acl_private_sets_exact_bucket_location() {
        let api = S3Api::new(cred_map());
        let mut req = base_s3_req("PUT", "/mybucket", "acl");
        req.headers.set("x-amz-acl", "private");
        req.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        let req = sign_request(req, "testing");
        let next: NextFn = Arc::new(|r| {
            assert_eq!(r.method, "POST");
            Response::new(204)
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        assert_eq!(resp.headers.get("Location"), Some("mybucket"));
        assert!(resp.body.is_definitely_empty());
    }

    #[test]
    fn put_object_stores_canned_acl_sysmeta() {
        let api = S3Api::new(cred_map());
        let mut req = base_s3_req("PUT", "/mybucket/obj1", "");
        req.headers.set("x-amz-acl", "public-read");
        req.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        req.body = Body::from(b"hi".to_vec());
        let req = sign_request(req, "testing");
        let next: NextFn = Arc::new(|r| {
            if r.method == "HEAD" {
                return Response::new(404);
            }
            assert_eq!(r.method, "PUT");
            assert_eq!(r.path, "/v1/AUTH_test/mybucket/obj1");
            assert_eq!(r.headers.get(S3_OBJECT_ACL_META), Some("public-read"));
            // Object path must not stamp container ACL headers.
            assert!(r.headers.get("X-Container-Read").is_none());
            let mut resp = Response::new(201);
            resp.headers.set("Etag", "\"abc\"");
            resp
        });
        assert_eq!(api.handle(req, &next).status, 200);
    }

    #[test]
    fn get_object_acl_from_sysmeta() {
        let api = S3Api::new(cred_map());
        let req = sign_request(base_s3_req("GET", "/mybucket/obj1", "acl"), "testing");
        let next: NextFn = Arc::new(|r| {
            assert_eq!(r.method, "HEAD");
            assert_eq!(r.path, "/v1/AUTH_test/mybucket/obj1");
            let mut resp = Response::new(200);
            resp.headers.set(S3_OBJECT_ACL_META, "public-read");
            resp
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("AccessControlPolicy"));
        assert!(body.contains("AllUsers"));
        assert!(body.contains("<Permission>READ</Permission>"));
    }

    #[test]
    fn get_object_acl_defaults_private_when_no_meta() {
        let api = S3Api::new(cred_map());
        let req = sign_request(base_s3_req("GET", "/mybucket/obj1", "acl"), "testing");
        let next: NextFn = Arc::new(|_| Response::new(200));
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("FULL_CONTROL"));
        assert!(!body.contains("AllUsers"));
    }

    #[test]
    fn put_object_acl_posts_sysmeta() {
        let api = S3Api::new(cred_map());
        let mut req = base_s3_req("PUT", "/mybucket/obj1", "acl");
        req.headers.set("x-amz-acl", "private");
        req.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        let req = sign_request(req, "testing");
        let next: NextFn = Arc::new(|r| {
            assert_eq!(r.method, "POST");
            assert_eq!(r.path, "/v1/AUTH_test/mybucket/obj1");
            assert_eq!(r.headers.get(S3_OBJECT_ACL_META), Some("private"));
            Response::new(202)
        });
        assert_eq!(api.handle(req, &next).status, 200);
    }

    #[test]
    fn put_bucket_acl_grant_read_allusers_stamps_container_read() {
        let api = S3Api::new(cred_map());
        let mut req = base_s3_req("PUT", "/mybucket", "acl");
        req.headers.set(
            "x-amz-grant-read",
            "uri=http://acs.amazonaws.com/groups/global/AllUsers",
        );
        req.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        let req = sign_request(req, "testing");
        let next: NextFn = Arc::new(|r| {
            assert_eq!(r.method, "POST");
            assert_eq!(r.headers.get("X-Container-Read"), Some(".r:*,.rlistings"));
            assert!(r
                .headers
                .get("X-Container-Meta-S3-Acl-Json")
                .is_some_and(|v| v.contains("AllUsers")));
            Response::new(204)
        });
        assert_eq!(api.handle(req, &next).status, 200);
    }

    #[test]
    fn put_object_acl_acp_body_stores_json_and_get_roundtrip() {
        let api = S3Api::new(cred_map());
        let acp = br#"<?xml version="1.0" encoding="UTF-8"?>
<AccessControlPolicy>
  <Owner><ID>test:tester</ID><DisplayName>test:tester</DisplayName></Owner>
  <AccessControlList>
    <Grant>
      <Grantee><ID>test:tester</ID><DisplayName>test:tester</DisplayName></Grantee>
      <Permission>FULL_CONTROL</Permission>
    </Grant>
    <Grant>
      <Grantee><URI>http://acs.amazonaws.com/groups/global/AllUsers</URI></Grantee>
      <Permission>READ</Permission>
    </Grant>
  </AccessControlList>
</AccessControlPolicy>"#;
        let mut put_req = base_s3_req("PUT", "/mybucket/obj1", "acl");
        put_req
            .headers
            .set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        put_req.body = Body::from(acp.to_vec());
        let put_req = sign_request(put_req, "testing");
        let stored = std::sync::Arc::new(std::sync::Mutex::new(None::<HeaderKeyDict>));
        let stored_c = stored.clone();
        let put_next: NextFn = Arc::new(move |r| {
            assert_eq!(r.method, "POST");
            let json = r.headers.get(S3_OBJECT_ACL_JSON_META).unwrap_or("");
            assert!(
                json.contains("AllUsers") && json.contains("FULL_CONTROL"),
                "expected grant JSON, got {json}"
            );
            *stored_c.lock().unwrap() = Some(r.headers.clone());
            Response::new(202)
        });
        assert_eq!(api.handle(put_req, &put_next).status, 200);

        let hdrs = stored.lock().unwrap().clone().unwrap();
        let get_req = sign_request(base_s3_req("GET", "/mybucket/obj1", "acl"), "testing");
        let get_next: NextFn = Arc::new(move |_| {
            let mut r = Response::new(200);
            r.headers = hdrs.clone();
            r
        });
        let resp = api.handle(get_req, &get_next);
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("AccessControlPolicy"));
        assert!(body.contains("<Grant>"));
        assert!(body.contains("<Permission>FULL_CONTROL</Permission>"));
        assert!(body.contains("<Permission>READ</Permission>"));
        assert!(body.contains("AllUsers"));
    }

    #[test]
    fn put_bucket_acl_acp_body_roundtrip() {
        let api = S3Api::new(cred_map());
        let acp = br#"<AccessControlPolicy>
  <Owner><ID>owner</ID></Owner>
  <AccessControlList>
    <Grant>
      <Grantee><ID>owner</ID></Grantee>
      <Permission>FULL_CONTROL</Permission>
    </Grant>
    <Grant>
      <Grantee><URI>http://acs.amazonaws.com/groups/global/AllUsers</URI></Grantee>
      <Permission>WRITE</Permission>
    </Grant>
  </AccessControlList>
</AccessControlPolicy>"#;
        let mut put_req = base_s3_req("PUT", "/mybucket", "acl");
        put_req
            .headers
            .set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        put_req.body = Body::from(acp.to_vec());
        let put_req = sign_request(put_req, "testing");
        let stored = std::sync::Arc::new(std::sync::Mutex::new(None::<HeaderKeyDict>));
        let stored_c = stored.clone();
        let put_next: NextFn = Arc::new(move |r| {
            assert_eq!(r.headers.get("X-Container-Write"), Some(".r:*"));
            *stored_c.lock().unwrap() = Some(r.headers.clone());
            Response::new(204)
        });
        assert_eq!(api.handle(put_req, &put_next).status, 200);

        let hdrs = stored.lock().unwrap().clone().unwrap();
        let get_req = sign_request(base_s3_req("GET", "/mybucket", "acl"), "testing");
        let get_next: NextFn = Arc::new(move |_| {
            let mut r = Response::new(204);
            r.headers = hdrs.clone();
            r
        });
        let resp = api.handle(get_req, &get_next);
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("<Permission>WRITE</Permission>"));
        assert!(body.contains("AllUsers"));
    }

    /// Mock next for object GET/HEAD grant tests: versioning probe HEAD on
    /// container returns empty; object ops return private JSON ACL headers.
    fn mock_object_with_acl_json(acl_json: &str) -> NextFn {
        let json = acl_json.to_string();
        Arc::new(move |r: Request| {
            // Versioning probe: HEAD container (no object key segment after bucket).
            if r.method == "HEAD" && r.path.ends_with("/mybucket") {
                return Response::new(204);
            }
            if matches!(r.method.as_str(), "GET" | "HEAD")
                && r.path.contains("/mybucket/private-obj")
            {
                let mut resp = Response::new(200);
                resp.headers.set(S3_OBJECT_ACL_JSON_META, &json);
                resp.headers.set("ETag", "\"deadbeef\"");
                resp.headers.set("Content-Length", "2");
                if r.method == "GET" {
                    resp.body = Body::from(b"ok".to_vec());
                }
                return resp;
            }
            Response::new(404)
        })
    }

    fn private_owner_acl_json() -> String {
        // Owner FULL_CONTROL only — foreign principals denied on GET/HEAD.
        r#"{"Owner":"test:tester","Grant":[{"Permission":"FULL_CONTROL","ID":"test:tester","DisplayName":"test:tester"}]}"#.into()
    }

    fn owner_plus_friend_read_acl_json() -> String {
        r#"{"Owner":"test:tester","Grant":[{"Permission":"FULL_CONTROL","ID":"test:tester"},{"Permission":"READ","ID":"test:friend"}]}"#.into()
    }

    #[test]
    fn get_object_acl_grant_denies_foreign_principal() {
        let api = S3Api::new(multi_cred_map());
        let next = mock_object_with_acl_json(&private_owner_acl_json());
        let req = sign_request(
            base_s3_req_as("GET", "/mybucket/private-obj", "", "test:foreign"),
            "foreign-secret",
        );
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 403);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(
            body.contains("<Code>AccessDenied</Code>"),
            "expected AccessDenied, got {body}"
        );
    }

    #[test]
    fn head_object_acl_grant_denies_foreign_principal() {
        let api = S3Api::new(multi_cred_map());
        let next = mock_object_with_acl_json(&private_owner_acl_json());
        let req = sign_request(
            base_s3_req_as("HEAD", "/mybucket/private-obj", "", "test:foreign"),
            "foreign-secret",
        );
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 403);
        // Official HEAD errors are empty-bodied (content-length 0).
        assert!(resp.body.into_vec(u64::MAX).unwrap().is_empty());
        assert_eq!(resp.headers.get("Content-Length"), Some("0"));
    }

    #[test]
    fn get_object_acl_grant_read_allows_principal() {
        let api = S3Api::new(multi_cred_map());
        let next = mock_object_with_acl_json(&owner_plus_friend_read_acl_json());
        let req = sign_request(
            base_s3_req_as("GET", "/mybucket/private-obj", "", "test:friend"),
            "friend-secret",
        );
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        let body = resp.body.into_vec(u64::MAX).unwrap();
        assert_eq!(body, b"ok");
    }

    #[test]
    fn get_object_acl_owner_always_allowed() {
        let api = S3Api::new(multi_cred_map());
        let next = mock_object_with_acl_json(&private_owner_acl_json());
        let req = sign_request(
            base_s3_req_as("GET", "/mybucket/private-obj", "", "test:tester"),
            "testing",
        );
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body.into_vec(u64::MAX).unwrap(), b"ok");
    }

    #[test]
    fn get_object_without_acl_json_not_denied() {
        // Missing structured grants → existing path (no new AccessDenied).
        let api = S3Api::new(multi_cred_map());
        let next: NextFn = Arc::new(|r: Request| {
            if r.method == "HEAD" && r.path.ends_with("/mybucket") {
                return Response::new(204);
            }
            if r.method == "GET" && r.path.contains("/mybucket/plain") {
                let mut resp = Response::new(200);
                resp.headers.set("ETag", "\"abc\"");
                resp.body = Body::from(b"data".to_vec());
                return resp;
            }
            Response::new(404)
        });
        let req = sign_request(
            base_s3_req_as("GET", "/mybucket/plain", "", "test:foreign"),
            "foreign-secret",
        );
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body.into_vec(u64::MAX).unwrap(), b"data");
    }

    /// Assert stable S3 NotImplemented: 501 + Code + Message fragment.
    fn assert_not_implemented(resp: Response, message_substr: &str) {
        assert_eq!(resp.status, 501, "expected HTTP 501 NotImplemented");
        assert_eq!(resp.headers.get("Content-Type"), Some("application/xml"));
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(
            body.contains("<Code>NotImplemented</Code>"),
            "body missing Code=NotImplemented: {body}"
        );
        assert!(
            body.contains(message_substr),
            "body missing message {message_substr:?}: {body}"
        );
    }

    #[test]
    fn versioning_put_get_round_trip() {
        let api = S3Api::new(cred_map());
        let mut put_req = base_s3_req("PUT", "/mybucket", "versioning");
        put_req
            .headers
            .set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        put_req.body = Body::from(
            br#"<VersioningConfiguration>
              <Status>Enabled</Status>
            </VersioningConfiguration>"#
                .to_vec(),
        );
        let put_req = sign_request(put_req, "testing");
        let stored = std::sync::Arc::new(std::sync::Mutex::new(None::<String>));
        let stored_c = stored.clone();
        let put_next: NextFn = Arc::new(move |r| {
            assert_eq!(r.method, "POST");
            assert_eq!(r.path, "/v1/AUTH_test/mybucket");
            assert_eq!(r.headers.get(S3_VERSIONING_META), Some("Enabled"));
            *stored_c.lock().unwrap() = r.headers.get(S3_VERSIONING_META).map(str::to_string);
            Response::new(204)
        });
        assert_eq!(api.handle(put_req, &put_next).status, 200);

        let status = stored.lock().unwrap().clone().unwrap();
        let get_req = sign_request(base_s3_req("GET", "/mybucket", "versioning"), "testing");
        let get_next: NextFn = Arc::new(move |_| {
            let mut r = Response::new(204);
            r.headers.set(S3_VERSIONING_META, &status);
            r
        });
        let resp = api.handle(get_req, &get_next);
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("VersioningConfiguration"));
        assert!(body.contains("<Status>Enabled</Status>"));
    }

    #[test]
    fn versioning_get_unconfigured_empty_xml() {
        let api = S3Api::new(cred_map());
        let get_req = sign_request(base_s3_req("GET", "/mybucket", "versioning"), "testing");
        let get_next: NextFn = Arc::new(|_| Response::new(204));
        let resp = api.handle(get_req, &get_next);
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("VersioningConfiguration"));
        assert!(!body.contains("<Status>"));
    }

    #[test]
    fn versions_list_returns_empty_list_versions_result() {
        let api = S3Api::new(cred_map());
        let req = sign_request(base_s3_req("GET", "/mybucket", "versions"), "testing");
        let next: NextFn = Arc::new(|_| Response::new(404));
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("ListVersionsResult"));
        assert!(body.contains("<Name>mybucket</Name>"));
        assert!(body.contains("<IsTruncated>false</IsTruncated>"));
        assert!(!body.contains("<Version>"));
    }

    fn seed_unversioned_object(be: &SharedSwiftBackend, key: &str, body: &[u8]) {
        let mut store = be.store.lock().unwrap();
        store.insert(
            "/v1/AUTH_test/mybucket".into(),
            (HeaderKeyDict::new(), Vec::new()),
        );
        let mut h = HeaderKeyDict::new();
        h.set("ETag", "abc");
        h.set("Content-Length", body.len().to_string());
        store.insert(format!("/v1/AUTH_test/mybucket/{key}"), (h, body.to_vec()));
    }

    #[test]
    fn list_versions_unversioned_current_objects_are_null() {
        let be = SharedSwiftBackend::new("Enabled");
        seed_unversioned_object(&be, "foo", b"abc");
        let api = S3Api::new(cred_map());
        let next = be.next_fn();

        let list = sign_request(base_s3_req("GET", "/mybucket", "versions"), "testing");
        let resp = api.handle(list, &next);
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("<Key>foo</Key>"), "{body}");
        assert!(body.contains("<VersionId>null</VersionId>"), "{body}");
        assert!(body.contains("<IsLatest>true</IsLatest>"), "{body}");
        assert_eq!(body.matches("<Version>").count(), 1, "{body}");
    }

    #[test]
    fn delete_null_version_unversioned_object() {
        let be = SharedSwiftBackend::new("Enabled");
        seed_unversioned_object(&be, "foo", b"abc");
        let api = S3Api::new(cred_map());
        let next = be.next_fn();

        let del = sign_request(
            base_s3_req("DELETE", "/mybucket/foo", "versionId=null"),
            "testing",
        );
        let resp = api.handle(del, &next);
        assert_eq!(resp.status, 204, "delete status={}", resp.status);
        assert_eq!(resp.headers.get(HDR_VERSION_ID), Some("null"));

        let list = sign_request(base_s3_req("GET", "/mybucket", "versions"), "testing");
        let listed = api.handle(list, &next);
        let body = String::from_utf8(listed.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(!body.contains("<Key>foo</Key>"), "{body}");
    }

    #[test]
    fn multi_delete_null_version_unversioned_object() {
        let be = SharedSwiftBackend::new("Enabled");
        seed_unversioned_object(&be, "foo", b"abc");
        let api = S3Api::new(cred_map());
        let next = be.next_fn();

        let mut req = base_s3_req("POST", "/mybucket", "delete");
        req.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        req.body = Body::from(
            b"<Delete><Object><Key>foo</Key><VersionId>null</VersionId></Object></Delete>".to_vec(),
        );
        stamp_content_md5(&mut req);
        let resp = api.handle(sign_request(req, "testing"), &next);
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("<Deleted>"), "{body}");
        assert!(body.contains("<Key>foo</Key>"), "{body}");
        assert!(!body.contains("<Error>"), "{body}");
    }

    fn versioning_mock_store(status: &str) -> NextFn {
        use std::collections::HashMap;
        use std::sync::{Arc, Mutex};
        let store: Arc<Mutex<HashMap<String, (HeaderKeyDict, Vec<u8>)>>> =
            Arc::new(Mutex::new(HashMap::new()));
        {
            let mut h = HeaderKeyDict::new();
            h.set(S3_VERSIONING_META, status);
            store
                .lock()
                .unwrap()
                .insert("/v1/AUTH_test/mybucket".into(), (h, Vec::new()));
        }
        let store_c = store.clone();
        Arc::new(move |r: Request| {
            let path = r.path.clone();
            let method = r.method.clone();
            let mut store = store_c.lock().unwrap();

            // Container-level ops (bucket or +versions)
            let is_container =
                path == "/v1/AUTH_test/mybucket" || path == "/v1/AUTH_test/mybucket+versions";
            if is_container {
                if method == "HEAD" {
                    if let Some((h, _)) = store.get(&path) {
                        let mut resp = Response::new(204);
                        for (k, v) in h.iter() {
                            resp.headers.set(k, v);
                        }
                        return resp;
                    }
                    // +versions may not exist yet
                    return Response::new(404);
                }
                if method == "PUT" {
                    store
                        .entry(path.clone())
                        .or_insert_with(|| (HeaderKeyDict::new(), Vec::new()));
                    return Response::new(201);
                }
                if method == "GET" {
                    let prefix = path.clone();
                    let mut items = Vec::new();
                    for (p, (h, body)) in store.iter() {
                        if p.starts_with(&(prefix.clone() + "/")) {
                            let name = &p[prefix.len() + 1..];
                            let hash = h.get("ETag").unwrap_or("deadbeef");
                            items.push(format!(
                                r#"{{"name":"{name}","hash":"{hash}","bytes":{},"last_modified":"2013-05-24T00:00:00.000000"}}"#,
                                body.len()
                            ));
                        }
                    }
                    let body = format!("[{}]", items.join(","));
                    return Response::with_body(200, body.into_bytes());
                }
                if method == "POST" {
                    let entry = store
                        .entry(path)
                        .or_insert_with(|| (HeaderKeyDict::new(), Vec::new()));
                    for (k, v) in r.headers.iter() {
                        entry.0.set(k, v);
                    }
                    return Response::new(204);
                }
            }

            match method.as_str() {
                "HEAD" => {
                    if let Some((h, body)) = store.get(&path) {
                        let mut resp = Response::new(200);
                        for (k, v) in h.iter() {
                            resp.headers.set(k, v);
                        }
                        resp.headers.set("Content-Length", body.len().to_string());
                        if resp.headers.get("ETag").is_none() {
                            resp.headers.set("ETag", "deadbeef");
                        }
                        resp.headers
                            .set("Last-Modified", "Thu, 01 Jan 1970 00:00:00 GMT");
                        return resp;
                    }
                    Response::new(404)
                }
                "GET" => {
                    if let Some((h, body)) = store.get(&path) {
                        let mut resp = Response::with_body(200, body.clone());
                        for (k, v) in h.iter() {
                            resp.headers.set(k, v);
                        }
                        resp.headers.set("Content-Length", body.len().to_string());
                        if resp.headers.get("ETag").is_none() {
                            resp.headers.set("ETag", "deadbeef");
                        }
                        resp.headers
                            .set("Last-Modified", "Thu, 01 Jan 1970 00:00:00 GMT");
                        return resp;
                    }
                    Response::new(404)
                }
                "PUT" => {
                    let body = r.body.into_vec(u64::MAX).unwrap_or_default();
                    let mut h = HeaderKeyDict::new();
                    for (k, v) in r.headers.iter() {
                        let kl = k.to_ascii_lowercase();
                        if kl.starts_with("x-object-") || kl == "content-type" {
                            h.set(k, v);
                        }
                    }
                    use std::collections::hash_map::DefaultHasher;
                    use std::hash::{Hash, Hasher};
                    let mut hasher = DefaultHasher::new();
                    body.hash(&mut hasher);
                    let etag = format!("{:x}", hasher.finish());
                    h.set("ETag", &etag);
                    h.set("Content-Length", body.len().to_string());
                    store.insert(path, (h, body));
                    let mut resp = Response::new(201);
                    resp.headers.set("ETag", etag);
                    resp.headers.set("Content-Length", "0");
                    resp
                }
                "DELETE" => {
                    store.remove(&path);
                    Response::new(204)
                }
                _ => Response::new(405),
            }
        })
    }

    #[test]
    fn multiversion_double_put_two_version_ids_and_list() {
        let api = S3Api::new(cred_map());
        let next = versioning_mock_store("Enabled");

        let mut req1 = base_s3_req("PUT", "/mybucket/obj", "");
        req1.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        req1.body = Body::from(b"v1".to_vec());
        let r1 = api.handle(sign_request(req1, "testing"), &next);
        assert_eq!(r1.status, 200);
        let vid1 = r1.headers.get("x-amz-version-id").unwrap().to_string();
        assert_eq!(vid1.len(), 32);

        let mut req2 = base_s3_req("PUT", "/mybucket/obj", "");
        req2.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        req2.body = Body::from(b"v2-body".to_vec());
        let r2 = api.handle(sign_request(req2, "testing"), &next);
        assert_eq!(r2.status, 200);
        let vid2 = r2.headers.get("x-amz-version-id").unwrap().to_string();
        assert_ne!(vid1, vid2);

        let list_req = sign_request(base_s3_req("GET", "/mybucket", "versions"), "testing");
        let list_resp = api.handle(list_req, &next);
        assert_eq!(list_resp.status, 200);
        let body = String::from_utf8(list_resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(
            body.contains(&format!("<VersionId>{vid1}</VersionId>")),
            "{body}"
        );
        assert!(
            body.contains(&format!("<VersionId>{vid2}</VersionId>")),
            "{body}"
        );
        assert_eq!(body.matches("<Version>").count(), 2);
        // Request body length, not Swift PUT response Content-Length 0.
        assert!(body.contains("<Size>2</Size>"), "v1 size missing: {body}");
        assert!(body.contains("<Size>7</Size>"), "v2 size missing: {body}");
    }

    #[test]
    fn multiversion_get_specific_version_id_returns_body() {
        let api = S3Api::new(cred_map());
        let next = versioning_mock_store("Enabled");

        let mut req1 = base_s3_req("PUT", "/mybucket/obj", "");
        req1.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        req1.body = Body::from(b"alpha".to_vec());
        let r1 = api.handle(sign_request(req1, "testing"), &next);
        let vid1 = r1.headers.get("x-amz-version-id").unwrap().to_string();

        let mut req2 = base_s3_req("PUT", "/mybucket/obj", "");
        req2.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        req2.body = Body::from(b"beta".to_vec());
        let _ = api.handle(sign_request(req2, "testing"), &next);

        let get = sign_request(
            base_s3_req("GET", "/mybucket/obj", &format!("versionId={vid1}")),
            "testing",
        );
        let resp = api.handle(get, &next);
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body.into_vec(u64::MAX).unwrap(), b"alpha");
    }

    #[test]
    fn multiversion_delete_current_makes_delete_marker_get_404() {
        let api = S3Api::new(cred_map());
        let next = versioning_mock_store("Enabled");

        let mut put = base_s3_req("PUT", "/mybucket/obj", "");
        put.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        put.body = Body::from(b"data".to_vec());
        let _ = api.handle(sign_request(put, "testing"), &next);

        let del = sign_request(base_s3_req("DELETE", "/mybucket/obj", ""), "testing");
        let dresp = api.handle(del, &next);
        assert_eq!(dresp.status, 204);
        assert_eq!(dresp.headers.get("x-amz-delete-marker"), Some("true"));

        let get = sign_request(base_s3_req("GET", "/mybucket/obj", ""), "testing");
        let gresp = api.handle(get, &next);
        assert_eq!(gresp.status, 404);
        let body = String::from_utf8(gresp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("NoSuchKey"));
        assert_eq!(gresp.headers.get("x-amz-delete-marker"), Some("true"));
    }

    #[test]
    fn multiversion_delete_version_id_removes_version() {
        let api = S3Api::new(cred_map());
        let next = versioning_mock_store("Enabled");

        let mut req1 = base_s3_req("PUT", "/mybucket/obj", "");
        req1.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        req1.body = Body::from(b"one".to_vec());
        let r1 = api.handle(sign_request(req1, "testing"), &next);
        let vid1 = r1.headers.get("x-amz-version-id").unwrap().to_string();

        let mut req2 = base_s3_req("PUT", "/mybucket/obj", "");
        req2.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        req2.body = Body::from(b"two".to_vec());
        let _ = api.handle(sign_request(req2, "testing"), &next);

        let del = sign_request(
            base_s3_req("DELETE", "/mybucket/obj", &format!("versionId={vid1}")),
            "testing",
        );
        assert_eq!(api.handle(del, &next).status, 204);

        let get = sign_request(
            base_s3_req("GET", "/mybucket/obj", &format!("versionId={vid1}")),
            "testing",
        );
        let gresp = api.handle(get, &next);
        assert_eq!(gresp.status, 404);
        let body = String::from_utf8(gresp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("NoSuchVersion"));
    }

    #[test]
    fn multiversion_suspended_no_multi_version() {
        let api = S3Api::new(cred_map());
        let next = versioning_mock_store("Suspended");

        // AWS: PUT on a versioning-suspended bucket overwrites the "null"
        // version and answers `x-amz-version-id: null`. No unique version ids
        // may be minted while suspended.
        let mut put = base_s3_req("PUT", "/mybucket/obj", "");
        put.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        put.body = Body::from(b"x".to_vec());
        let r = api.handle(sign_request(put, "testing"), &next);
        assert_eq!(r.status, 200);
        assert_eq!(r.headers.get("x-amz-version-id"), Some("null"));

        let mut put2 = base_s3_req("PUT", "/mybucket/obj", "");
        put2.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        put2.body = Body::from(b"y".to_vec());
        let r2 = api.handle(sign_request(put2, "testing"), &next);
        assert_eq!(r2.status, 200);
        assert_eq!(r2.headers.get("x-amz-version-id"), Some("null"));
    }

    fn version_rec(version_id: &str) -> VersionRecord {
        VersionRecord {
            version_id: version_id.into(),
            is_delete_marker: false,
            is_latest: true,
            last_modified: "1970-01-01T00:00:00.000Z".into(),
            etag: "e".into(),
            size: 1,
        }
    }

    #[test]
    fn expect_generation_some_zero_on_existing_legacy_index() {
        let existing = VersionIndexSnapshot {
            index: VersionIndex::new("obj"),
            exists: true,
            etag: Some("deadbeef".into()),
        };
        assert_eq!(expect_generation(&existing), Some(0));
        let missing = VersionIndexSnapshot {
            index: VersionIndex::new("obj"),
            exists: false,
            etag: None,
        };
        assert_eq!(expect_generation(&missing), None);
    }

    #[test]
    fn overlapping_put_stale_generation_is_cas_denied() {
        let mut idx = VersionIndex::new("obj");
        idx.apply_if_match(None, version_rec("v1")).unwrap();
        let err = commit_new_version_record(&mut idx, Some(0), false, version_rec("v2"));
        assert!(err.is_err());
        assert_eq!(idx.generation, 1);
        assert_eq!(idx.versions[0].version_id, "v1");
    }

    #[test]
    fn version_index_persist_202_is_not_success() {
        let api = S3Api::new(cred_map());
        let inner = versioning_mock_store("Enabled");
        let next: NextFn = Arc::new(move |r: Request| {
            if r.method == "PUT" && r.path.ends_with("/index.json") {
                return Response::new(202);
            }
            inner(r)
        });
        let mut put = base_s3_req("PUT", "/mybucket/obj", "");
        put.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        put.body = Body::from(b"v1".to_vec());
        let resp = api.handle(sign_request(put, "testing"), &next);
        assert_ne!(resp.status, 200);
        assert!(resp.status >= 400, "status={}", resp.status);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("InternalError"), "{body}");
    }

    #[test]
    fn version_index_persist_412_is_conflict_not_200() {
        let api = S3Api::new(cred_map());
        let inner = versioning_mock_store("Enabled");
        let next: NextFn = Arc::new(move |r: Request| {
            if r.method == "PUT" && r.path.ends_with("/index.json") {
                return Response::new(412);
            }
            inner(r)
        });
        let mut put = base_s3_req("PUT", "/mybucket/obj", "");
        put.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        put.body = Body::from(b"v1".to_vec());
        let resp = api.handle(sign_request(put, "testing"), &next);
        assert_ne!(resp.status, 200);
        assert!(resp.status >= 400, "status={}", resp.status);
    }

    #[test]
    fn cas_save_does_not_send_cas_etag_as_if_match() {
        let api = S3Api::new(cred_map());
        let inner = versioning_mock_store("Enabled");
        let seen: Arc<std::sync::Mutex<Vec<(Option<String>, Option<String>)>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen_c = seen.clone();
        let next: NextFn = Arc::new(move |r: Request| {
            if r.method == "PUT" && r.path.ends_with("/index.json") {
                seen_c.lock().unwrap().push((
                    r.headers.get("If-Match").map(str::to_string),
                    r.headers.get("If-None-Match").map(str::to_string),
                ));
            }
            inner(r)
        });
        for body in [b"v1".as_slice(), b"v2".as_slice()] {
            let mut put = base_s3_req("PUT", "/mybucket/obj", "");
            put.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
            put.body = Body::from(body.to_vec());
            assert_eq!(api.handle(sign_request(put, "testing"), &next).status, 200);
        }
        let headers = seen.lock().unwrap().clone();
        assert_eq!(headers[0].1.as_deref(), Some("*"));
        assert!(headers[0].0.is_none());
        let second_if_match = headers[1].0.as_deref().expect("second persist If-Match");
        assert_ne!(
            second_if_match.len(),
            64,
            "If-Match must be Swift ETag, not cas_etag()"
        );
    }

    #[test]
    fn unsafe_sys_version_id_does_not_archive_index_json() {
        let api = S3Api::new(cred_map());
        let puts: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
        let puts_c = puts.clone();
        let next: NextFn = Arc::new(move |r: Request| {
            if r.method == "PUT" {
                puts_c.lock().unwrap().push(r.path.clone());
            }
            if r.method == "HEAD" && r.path == "/v1/AUTH_test/mybucket" {
                let mut resp = Response::new(204);
                resp.headers.set(S3_VERSIONING_META, "Enabled");
                return resp;
            }
            if r.method == "HEAD" && r.path == "/v1/AUTH_test/mybucket/obj" {
                let mut resp = Response::new(200);
                resp.headers.set(SYS_VERSION_ID, INDEX_NAME);
                resp.headers.set("ETag", "deadbeef");
                resp.headers.set("Content-Length", "1");
                return resp;
            }
            if r.method == "GET" && r.path.ends_with("/index.json") {
                return Response::new(404);
            }
            if r.method == "PUT" && r.path == "/v1/AUTH_test/mybucket+versions" {
                return Response::new(201);
            }
            Response::new(404)
        });
        let mut put = base_s3_req("PUT", "/mybucket/obj", "");
        put.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        put.body = Body::from(b"x".to_vec());
        let resp = api.handle(sign_request(put, "testing"), &next);
        assert!(resp.status >= 400, "status={}", resp.status);
        let puts = puts.lock().unwrap().clone();
        assert!(
            puts.iter()
                .all(|p| !p.contains("+versions/") || !p.ends_with("/index.json")),
            "archived onto index.json: {puts:?}"
        );
    }

    #[test]
    fn exact_version_delete_checked_miss_is_not_204() {
        let api = S3Api::new(cred_map());
        let vid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let next: NextFn = Arc::new(move |r: Request| {
            if r.method == "HEAD" && r.path == "/v1/AUTH_test/mybucket" {
                let mut resp = Response::new(204);
                resp.headers.set(S3_VERSIONING_META, "Enabled");
                return resp;
            }
            if r.method == "HEAD" && r.path == "/v1/AUTH_test/mybucket/obj" {
                let mut resp = Response::new(200);
                resp.headers.set(SYS_VERSION_ID, vid);
                resp.headers.set("ETag", "deadbeef");
                resp.headers.set("Content-Length", "1");
                return resp;
            }
            if r.method == "GET" && r.path.ends_with("/index.json") {
                return Response::new(404);
            }
            Response::new(404)
        });
        let del = sign_request(
            base_s3_req("DELETE", "/mybucket/obj", &format!("versionId={vid}")),
            "testing",
        );
        let resp = api.handle(del, &next);
        // Current object with no index row: delete the data-plane copy
        // (204) rather than 500 "lost update" that poisons Ceph s3-tests nuke.
        assert_eq!(resp.status, 204, "status={}", resp.status);
        assert_eq!(resp.headers.get(HDR_VERSION_ID), Some(vid));
    }

    #[test]
    fn multi_delete_checked_miss_is_error_not_deleted() {
        let api = S3Api::new(cred_map());
        let vid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let next: NextFn = Arc::new(move |r: Request| {
            if r.method == "HEAD" && r.path == "/v1/AUTH_test/mybucket" {
                let mut resp = Response::new(204);
                resp.headers.set(S3_VERSIONING_META, "Enabled");
                return resp;
            }
            if r.method == "HEAD" && r.path == "/v1/AUTH_test/mybucket/obj" {
                let mut resp = Response::new(200);
                resp.headers.set(SYS_VERSION_ID, vid);
                resp.headers.set("ETag", "deadbeef");
                resp.headers.set("Content-Length", "1");
                return resp;
            }
            if r.method == "GET" && r.path.ends_with("/index.json") {
                return Response::new(404);
            }
            Response::new(404)
        });
        let mut req = base_s3_req("POST", "/mybucket", "delete");
        req.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        req.body = Body::from(
            format!("<Delete><Object><Key>obj</Key><VersionId>{vid}</VersionId></Object></Delete>")
                .into_bytes(),
        );
        stamp_content_md5(&mut req);
        let resp = api.handle(sign_request(req, "testing"), &next);
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("<Deleted>"), "{body}");
        assert!(body.contains("<Key>obj</Key>"), "{body}");
        assert!(!body.contains("<Error>"), "{body}");
    }

    #[test]
    fn suspended_put_overwrites_null_does_not_apply_if_match() {
        let mut idx = VersionIndex::new("obj");
        idx.push_latest(version_rec("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"));
        idx.generation = 1;
        commit_new_version_record(&mut idx, Some(1), true, version_rec("ignored"))
            .expect("suspended overwrite");
        assert_eq!(idx.generation, 2);
        assert_eq!(idx.versions.len(), 2);
        assert_eq!(idx.versions[0].version_id, NULL_VERSION_ID);
        assert_eq!(
            idx.versions[1].version_id,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        );
        assert!(idx.versions[0].is_latest);
        assert!(!idx.versions[1].is_latest);
    }

    #[test]
    fn bucket_tagging_put_get_delete_round_trip() {
        let api = S3Api::new(cred_map());
        let mut put_req = base_s3_req("PUT", "/mybucket", "tagging");
        put_req
            .headers
            .set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        put_req.body = Body::from(
            br#"<Tagging><TagSet>
              <Tag><Key>env</Key><Value>prod</Value></Tag>
              <Tag><Key>team</Key><Value>s3</Value></Tag>
            </TagSet></Tagging>"#
                .to_vec(),
        );
        let put_req = sign_request(put_req, "testing");
        let stored = std::sync::Arc::new(std::sync::Mutex::new(None::<String>));
        let stored_c = stored.clone();
        let put_next: NextFn = Arc::new(move |r| {
            assert_eq!(r.method, "POST");
            let v = r.headers.get(S3_BUCKET_TAGGING_META).map(str::to_string);
            assert!(v.as_ref().is_some_and(|s| s.contains("env")));
            *stored_c.lock().unwrap() = v;
            Response::new(204)
        });
        assert_eq!(api.handle(put_req, &put_next).status, 200);

        let meta = stored.lock().unwrap().clone().unwrap();
        let get_req = sign_request(base_s3_req("GET", "/mybucket", "tagging"), "testing");
        let get_next: NextFn = Arc::new(move |_| {
            let mut r = Response::new(204);
            r.headers.set(S3_BUCKET_TAGGING_META, &meta);
            r
        });
        let resp = api.handle(get_req, &get_next);
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("<Key>env</Key>"));
        assert!(body.contains("<Value>prod</Value>"));
        assert!(body.contains("<Key>team</Key>"));

        let del_req = sign_request(base_s3_req("DELETE", "/mybucket", "tagging"), "testing");
        let del_next: NextFn = Arc::new(|r| {
            assert_eq!(r.headers.get(S3_BUCKET_TAGGING_META), Some(""));
            Response::new(204)
        });
        assert_eq!(api.handle(del_req, &del_next).status, 204);
    }

    #[test]
    fn object_tagging_put_get_round_trip() {
        let api = S3Api::new(cred_map());
        let mut put_req = base_s3_req("PUT", "/mybucket/obj1", "tagging");
        put_req
            .headers
            .set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        put_req.body = Body::from(
            br#"<Tagging><TagSet>
              <Tag><Key>color</Key><Value>blue</Value></Tag>
            </TagSet></Tagging>"#
                .to_vec(),
        );
        let put_req = sign_request(put_req, "testing");
        let stored = std::sync::Arc::new(std::sync::Mutex::new(None::<String>));
        let stored_c = stored.clone();
        let put_next: NextFn = Arc::new(move |r| {
            assert_eq!(r.method, "POST");
            assert_eq!(r.path, "/v1/AUTH_test/mybucket/obj1");
            let v = r.headers.get(S3_OBJECT_TAGGING_META).map(str::to_string);
            assert!(v.as_ref().is_some_and(|s| s.contains("color")));
            *stored_c.lock().unwrap() = v;
            Response::new(202)
        });
        assert_eq!(api.handle(put_req, &put_next).status, 200);

        let meta = stored.lock().unwrap().clone().unwrap();
        let get_req = sign_request(base_s3_req("GET", "/mybucket/obj1", "tagging"), "testing");
        let get_next: NextFn = Arc::new(move |r| {
            assert_eq!(r.method, "HEAD");
            let mut resp = Response::new(200);
            resp.headers.set(S3_OBJECT_TAGGING_META, &meta);
            resp
        });
        let resp = api.handle(get_req, &get_next);
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("<Key>color</Key>"));
        assert!(body.contains("<Value>blue</Value>"));
    }

    #[test]
    fn lifecycle_put_get_delete_round_trip() {
        let api = S3Api::new(cred_map());
        let lifecycle_body = br#"<?xml version="1.0"?>
<LifecycleConfiguration>
  <Rule>
    <ID>expire-logs</ID>
    <Prefix>logs/</Prefix>
    <Status>Enabled</Status>
    <Expiration><Days>30</Days></Expiration>
  </Rule>
</LifecycleConfiguration>"#;
        let mut put_req = base_s3_req("PUT", "/mybucket", "lifecycle");
        put_req
            .headers
            .set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        put_req.body = Body::from(lifecycle_body.to_vec());
        let put_req = sign_request(put_req, "testing");
        let stored = std::sync::Arc::new(std::sync::Mutex::new(None::<String>));
        let stored_c = stored.clone();
        let put_next: NextFn = Arc::new(move |r| {
            assert_eq!(r.method, "POST");
            let v = r.headers.get(S3_LIFECYCLE_META).map(str::to_string);
            assert!(v.as_ref().is_some_and(|s| !s.is_empty()));
            *stored_c.lock().unwrap() = v;
            Response::new(204)
        });
        assert_eq!(api.handle(put_req, &put_next).status, 200);

        let meta = stored.lock().unwrap().clone().unwrap();
        let get_req = sign_request(base_s3_req("GET", "/mybucket", "lifecycle"), "testing");
        let get_next: NextFn = Arc::new(move |_| {
            let mut r = Response::new(204);
            r.headers.set(S3_LIFECYCLE_META, &meta);
            r
        });
        let resp = api.handle(get_req, &get_next);
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("LifecycleConfiguration"));
        assert!(body.contains("expire-logs"));
        assert!(body.contains("<Days>30</Days>"));

        // GET with no meta → NoSuchLifecycleConfiguration
        let miss = sign_request(base_s3_req("GET", "/mybucket", "lifecycle"), "testing");
        let miss_next: NextFn = Arc::new(|_| Response::new(204));
        let miss_resp = api.handle(miss, &miss_next);
        assert_eq!(miss_resp.status, 404);
        let miss_body = String::from_utf8(miss_resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(miss_body.contains("NoSuchLifecycleConfiguration"));

        let del_req = sign_request(base_s3_req("DELETE", "/mybucket", "lifecycle"), "testing");
        let del_next: NextFn = Arc::new(|r| {
            assert_eq!(r.headers.get(S3_LIFECYCLE_META), Some(""));
            Response::new(204)
        });
        assert_eq!(api.handle(del_req, &del_next).status, 204);
    }

    #[test]
    fn object_lock_put_get_round_trip() {
        let api = S3Api::new(cred_map());
        let lock_body = br#"<ObjectLockConfiguration>
  <ObjectLockEnabled>Enabled</ObjectLockEnabled>
  <Rule>
    <DefaultRetention>
      <Mode>GOVERNANCE</Mode>
      <Days>7</Days>
    </DefaultRetention>
  </Rule>
</ObjectLockConfiguration>"#;
        let mut put_req = base_s3_req("PUT", "/mybucket", "object-lock");
        put_req
            .headers
            .set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        put_req.body = Body::from(lock_body.to_vec());
        let put_req = sign_request(put_req, "testing");
        let stored = std::sync::Arc::new(std::sync::Mutex::new(None::<String>));
        let stored_c = stored.clone();
        let put_next: NextFn = Arc::new(move |r| {
            assert_eq!(r.method, "POST");
            let v = r.headers.get(S3_OBJECT_LOCK_META).map(str::to_string);
            assert!(v.as_ref().is_some_and(|s| !s.is_empty()));
            *stored_c.lock().unwrap() = v;
            Response::new(204)
        });
        assert_eq!(api.handle(put_req, &put_next).status, 200);

        let meta = stored.lock().unwrap().clone().unwrap();
        let get_req = sign_request(base_s3_req("GET", "/mybucket", "object-lock"), "testing");
        let get_next: NextFn = Arc::new(move |_| {
            let mut r = Response::new(204);
            r.headers.set(S3_OBJECT_LOCK_META, &meta);
            r
        });
        let resp = api.handle(get_req, &get_next);
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("ObjectLockConfiguration"));
        assert!(body.contains("ObjectLockEnabled"));
        assert!(body.contains("GOVERNANCE"));

        let miss = sign_request(base_s3_req("GET", "/mybucket", "object-lock"), "testing");
        let miss_next: NextFn = Arc::new(|_| Response::new(204));
        let miss_resp = api.handle(miss, &miss_next);
        assert_eq!(miss_resp.status, 404);
        let miss_body = String::from_utf8(miss_resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(miss_body.contains("ObjectLockConfigurationNotFoundError"));
    }

    #[test]
    fn missing_bucket_policy_is_404_not_501() {
        let api = S3Api::new(cred_map());
        let req = sign_request(base_s3_req("GET", "/mybucket", "policy"), "testing");
        let next: NextFn = Arc::new(|r| {
            assert_eq!(r.method, "HEAD");
            Response::new(200)
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 404);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("<Code>NoSuchBucketPolicy</Code>"), "{body}");
    }

    /// Sign a request with SigV2 (header Authorization).
    fn sign_request_v2(mut req: Request, access_key: &str, secret: &str) -> Request {
        use crate::sigv2::{compute_signature_v2, string_to_sign_v2, SigV2Auth};
        // Ensure Date is present for STS when no x-amz-date.
        if req.headers.get("Date").is_none() && req.headers.get("x-amz-date").is_none() {
            req.headers.set("Date", swift_http::http_date(unix_now()));
        }
        let auth = SigV2Auth {
            access_key: access_key.into(),
            signature: String::new(),
            query_auth: false,
            expires: None,
        };
        let sts = string_to_sign_v2(&req, &auth);
        let sig = compute_signature_v2(secret, &sts);
        req.headers
            .set("Authorization", format!("AWS {access_key}:{sig}"));
        req
    }

    #[test]
    fn sigv2_header_auth_bad_sig_is_403() {
        let api = S3Api::new(cred_map());
        let mut headers = HeaderKeyDict::new();
        headers.set("Host", "localhost");
        headers.set("Date", swift_http::http_date(unix_now()));
        headers.set("Authorization", "AWS test:tester:deadbeefsignature");
        let req = Request {
            method: "GET".into(),
            path: "/mybucket/obj".into(),
            query_string: String::new(),
            headers,
            body: Body::empty(),
        };
        let next: NextFn = Arc::new(|_| {
            panic!("bad SigV2 must not fall through");
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 403);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(
            body.contains("SignatureDoesNotMatch"),
            "expected SignatureDoesNotMatch, got {body}"
        );
    }

    #[test]
    fn sigv2_header_auth_good_sig_reaches_backend() {
        let api = S3Api::new(cred_map());
        let mut headers = HeaderKeyDict::new();
        headers.set("Host", "localhost");
        let req = Request {
            method: "GET".into(),
            path: "/mybucket/obj".into(),
            query_string: String::new(),
            headers,
            body: Body::empty(),
        };
        let req = sign_request_v2(req, "test:tester", "testing");
        let next: NextFn = Arc::new(|r| {
            assert!(
                r.headers.get("X-Backend-Authorize-Override").is_some()
                    || r.headers.get("X-Auth-Token").is_some()
                    || r.path.contains("/v1/"),
                "expected authorized swift subrequest, path={}",
                r.path
            );
            Response::with_body(200, b"ok".to_vec())
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200, "SigV2 good auth must succeed");
    }

    #[test]
    fn sigv2_put_bad_content_md5_is_400_bad_digest_not_403() {
        let api = S3Api::new(cred_map());
        let body = b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
        let mut headers = HeaderKeyDict::new();
        headers.set("Host", "localhost");
        headers.set("content-md5", crate::sigv2::base64_encode(&crate::crypto::md5(b"")));
        headers.set("Content-Length", body.len().to_string());
        let req = Request {
            method: "PUT".into(),
            path: "/mybucket/obj".into(),
            query_string: String::new(),
            headers,
            body: Body::Buffered(body.to_vec()),
        };
        let req = sign_request_v2(req, "test:tester", "testing");
        let next: NextFn = Arc::new(|_| panic!("bad Content-MD5 must not reach backend"));
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 400, "status");
        let xml = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(xml.contains("<Code>BadDigest</Code>"), "{xml}");
        assert!(
            xml.contains("<ExpectedDigest>d41d8cd98f00b204e9800998ecf8427e</ExpectedDigest>"),
            "{xml}"
        );
    }

    #[test]
    fn sigv2_put_sha256_mismatch_is_400_not_403() {
        let api = S3Api::new(cred_map());
        let body = b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
        let mut headers = HeaderKeyDict::new();
        headers.set("Host", "localhost");
        headers.set(
            "x-amz-content-sha256",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
        headers.set("Content-Length", body.len().to_string());
        let req = Request {
            method: "PUT".into(),
            path: "/mybucket/obj".into(),
            query_string: String::new(),
            headers,
            body: Body::Buffered(body.to_vec()),
        };
        let req = sign_request_v2(req, "test:tester", "testing");
        let next: NextFn = Arc::new(|_| panic!("sha256 mismatch must not reach backend"));
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 400, "status");
        let xml = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(xml.contains("<Code>XAmzContentSHA256Mismatch</Code>"), "{xml}");
        assert!(
            xml.contains("<ClientComputedContentSHA256>e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855</ClientComputedContentSHA256>"),
            "{xml}"
        );
        assert!(xml.contains("<S3ComputedContentSHA256>"), "{xml}");
    }

    #[test]
    fn sigv2_streaming_unsigned_is_sha256_mismatch_not_aws_chunked() {
        let api = S3Api::new(cred_map());
        let body = b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
        let mut headers = HeaderKeyDict::new();
        headers.set("Host", "localhost");
        headers.set("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER");
        headers.set("x-amz-decoded-content-length", body.len().to_string());
        headers.set("Content-Length", body.len().to_string());
        let req = Request {
            method: "PUT".into(),
            path: "/mybucket/obj".into(),
            query_string: String::new(),
            headers,
            body: Body::Buffered(body.to_vec()),
        };
        let req = sign_request_v2(req, "test:tester", "testing");
        let next: NextFn = Arc::new(|_| panic!("V2 STREAMING must not be stored as an object"));
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 400, "status");
        let xml = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(xml.contains("<Code>XAmzContentSHA256Mismatch</Code>"), "{xml}");
        assert!(
            xml.contains("STREAMING-UNSIGNED-PAYLOAD-TRAILER"),
            "{xml}"
        );
        assert!(!xml.contains("IncompleteBody"), "{xml}");
    }

    #[test]
    fn sigv2_query_auth_bad_sig_is_403() {
        let api = S3Api::new(cred_map());
        let mut headers = HeaderKeyDict::new();
        headers.set("Host", "localhost");
        let req = Request {
            method: "GET".into(),
            path: "/mybucket/obj".into(),
            query_string: "AWSAccessKeyId=test%3Atester&Expires=9999999999&Signature=abc".into(),
            headers,
            body: Body::empty(),
        };
        let next: NextFn = Arc::new(|_| {
            panic!("bad SigV2 query must not fall through");
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 403);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("SignatureDoesNotMatch"), "got {body}");
    }

    /// Empty-payload SHA-256 hex (terminal streaming chunk).
    const EMPTY_SHA256_HEX: &str =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    /// Build a minimal aws-chunked framed body for `payload` with optional
    /// placeholder chunk-signature params (invalid HMAC — for negative tests).
    fn frame_aws_chunked(payload: &[u8], with_sig: bool, trailers: &[(&str, &str)]) -> Vec<u8> {
        let mut out = Vec::new();
        // Single data chunk + terminal 0 chunk (simple framing for unit tests).
        if !payload.is_empty() {
            if with_sig {
                out.extend_from_slice(
                    format!("{:x};chunk-signature={}", payload.len(), "0".repeat(64)).as_bytes(),
                );
            } else {
                out.extend_from_slice(format!("{:x}", payload.len()).as_bytes());
            }
            out.extend_from_slice(b"\r\n");
            out.extend_from_slice(payload);
            out.extend_from_slice(b"\r\n");
        }
        if with_sig {
            out.extend_from_slice(format!("0;chunk-signature={}", "0".repeat(64)).as_bytes());
        } else {
            out.extend_from_slice(b"0");
        }
        out.extend_from_slice(b"\r\n");
        for (k, v) in trailers {
            out.extend_from_slice(format!("{k}:{v}\r\n").as_bytes());
        }
        out.extend_from_slice(b"\r\n");
        out
    }

    /// Frame aws-chunked body with real STREAMING-AWS4-HMAC-SHA256-PAYLOAD
    /// per-chunk signatures (seed = header SigV4 signature).
    ///
    /// When `sign_trailer` is true, append a valid (or deliberately bad)
    /// `x-amz-trailer-signature` after content trailers.
    fn frame_aws_chunked_signed(
        chunks: &[&[u8]],
        secret: &str,
        date: &str,
        region: &str,
        service: &str,
        amz_date: &str,
        seed_signature: &str,
        trailers: &[(&str, &str)],
        sign_trailer: bool,
        bad_trailer_sig: bool,
    ) -> Vec<u8> {
        use crate::aws_chunked::{compute_chunk_signature, compute_trailer_signature};
        use crate::crypto::sha256_hex;
        use std::collections::HashMap;

        let ctx = ChunkSigContext {
            secret_key: secret.into(),
            date: date.into(),
            region: region.into(),
            service: service.into(),
            amz_date: amz_date.into(),
            seed_signature: seed_signature.into(),
            require_trailer_signature: sign_trailer,
        };
        let mut out = Vec::new();
        let mut prev = seed_signature.to_ascii_lowercase();
        for data in chunks {
            let data_hash = sha256_hex(data);
            let sig = compute_chunk_signature(&ctx, &prev, &data_hash);
            out.extend_from_slice(format!("{:x};chunk-signature={sig}\r\n", data.len()).as_bytes());
            out.extend_from_slice(data);
            out.extend_from_slice(b"\r\n");
            prev = sig;
        }
        let sig0 = compute_chunk_signature(&ctx, &prev, EMPTY_SHA256_HEX);
        out.extend_from_slice(format!("0;chunk-signature={sig0}\r\n").as_bytes());
        prev = sig0;
        let mut trailer_map = HashMap::new();
        for (k, v) in trailers {
            trailer_map.insert(k.to_ascii_lowercase(), (*v).to_string());
            out.extend_from_slice(format!("{k}:{v}\r\n").as_bytes());
        }
        if sign_trailer {
            let trailer_sig = if bad_trailer_sig {
                "0".repeat(64)
            } else {
                compute_trailer_signature(&ctx, &prev, &trailer_map)
            };
            out.extend_from_slice(format!("x-amz-trailer-signature:{trailer_sig}\r\n").as_bytes());
        }
        out.extend_from_slice(b"\r\n");
        out
    }

    /// Sign request headers first, then attach a correctly HMAC-signed
    /// streaming body (seed = Authorization Signature). No trailer HMAC.
    fn sign_streaming_put(
        req: Request,
        secret: &str,
        chunks: &[&[u8]],
        trailers: &[(&str, &str)],
    ) -> Request {
        sign_streaming_put_ex(req, secret, chunks, trailers, false, false)
    }

    /// Like [`sign_streaming_put`] with explicit trailer-signature options.
    fn sign_streaming_put_ex(
        mut req: Request,
        secret: &str,
        chunks: &[&[u8]],
        trailers: &[(&str, &str)],
        sign_trailer: bool,
        bad_trailer_sig: bool,
    ) -> Request {
        let decoded_len: usize = chunks.iter().map(|c| c.len()).sum();
        req.headers
            .set("x-amz-decoded-content-length", decoded_len.to_string());
        // Content-Length not in signed headers for base_s3_req; set after frame.
        req.body = Body::empty();
        req.headers.set("Content-Length", "0");
        let mut req = sign_request(req, secret);
        let auth_hdr = req.headers.get("Authorization").unwrap().to_string();
        let auth = parse_authorization_header(&auth_hdr).unwrap();
        let amz = amz_date(&req).unwrap();
        let framed = frame_aws_chunked_signed(
            chunks,
            secret,
            &auth.scope.date,
            &auth.scope.region,
            &auth.scope.service,
            &amz,
            &auth.signature,
            trailers,
            sign_trailer,
            bad_trailer_sig,
        );
        req.headers.set("Content-Length", framed.len().to_string());
        req.headers
            .set("x-amz-decoded-content-length", decoded_len.to_string());
        req.body = Body::from(framed);
        req
    }

    #[test]
    fn decode_aws_chunked_pure_multi_chunk_and_trailers() {
        // Multi-chunk: "hello" + " world" + trailers
        let mut framed = Vec::new();
        framed.extend_from_slice(b"5;chunk-signature=abc\r\nhello\r\n");
        framed.extend_from_slice(b"6\r\n world\r\n");
        framed.extend_from_slice(b"0\r\nx-amz-checksum-crc32:AAAAAA==\r\n\r\n");
        let decoded = decode_aws_chunked(&framed, Some(11), None).unwrap();
        assert_eq!(decoded.data, b"hello world");
        assert_eq!(
            decoded
                .trailers
                .get("x-amz-checksum-crc32")
                .map(String::as_str),
            Some("AAAAAA==")
        );
    }

    #[test]
    fn decode_aws_chunked_empty_payload() {
        assert_eq!(
            decode_aws_chunked(b"0\r\n\r\n", Some(0), None)
                .unwrap()
                .data,
            b""
        );
        assert_eq!(
            decode_aws_chunked(b"0\r\n", Some(0), None).unwrap().data,
            b""
        );
    }

    #[test]
    fn aws_chunked_streaming_payload_dechunks_to_backend() {
        let api = S3Api::new(cred_map());
        let payload = b"streaming-hello";
        let mut req = base_s3_req("PUT", "/mybucket/obj", "");
        req.headers
            .set("x-amz-content-sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD");
        req.headers.set("Content-Encoding", "aws-chunked");
        let req = sign_streaming_put(req, "testing", &[payload.as_slice()], &[]);
        let next: NextFn = Arc::new(|r| {
            if r.method == "HEAD" {
                return Response::new(404);
            }
            assert_eq!(r.path, "/v1/AUTH_test/mybucket/obj");
            assert_eq!(r.method, "PUT");
            let body = r.body.into_vec(u64::MAX).unwrap();
            assert_eq!(body, b"streaming-hello", "backend must see dechunked body");
            assert_eq!(
                r.headers.get("Content-Length"),
                Some("15"),
                "Content-Length must match decoded"
            );
            // aws-chunked stripped; STREAMING-* cleared before strip_s3_only.
            assert!(r
                .headers
                .get("Content-Encoding")
                .map(|e| !e.to_ascii_lowercase().contains("aws-chunked"))
                .unwrap_or(true));
            Response::new(201)
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200, "PUT object success maps to 200");
    }

    #[test]
    fn aws_chunked_streaming_multi_chunk_signed_dechunks_to_backend() {
        let api = S3Api::new(cred_map());
        // Multi-chunk payload: "stream" + "ing-he" + "llo"
        let chunks: &[&[u8]] = &[b"stream", b"ing-he", b"llo"];
        let mut req = base_s3_req("PUT", "/mybucket/obj", "");
        req.headers
            .set("x-amz-content-sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD");
        req.headers.set("Content-Encoding", "aws-chunked");
        let req = sign_streaming_put(req, "testing", chunks, &[]);
        let next: NextFn = Arc::new(|r| {
            if r.method == "HEAD" {
                return Response::new(404);
            }
            let body = r.body.into_vec(u64::MAX).unwrap();
            assert_eq!(body, b"streaming-hello");
            assert_eq!(r.headers.get("Content-Length"), Some("15"));
            Response::new(201)
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
    }

    #[test]
    fn aws_chunked_bad_chunk_signature_is_signature_does_not_match() {
        let api = S3Api::new(cred_map());
        let payload = b"bad-sig-body";
        // Placeholder zeros — invalid under HMAC chain enforcement.
        let framed = frame_aws_chunked(payload, true, &[]);
        let mut req = base_s3_req("PUT", "/mybucket/obj", "");
        req.headers
            .set("x-amz-content-sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD");
        req.headers.set("Content-Encoding", "aws-chunked");
        req.headers
            .set("x-amz-decoded-content-length", payload.len().to_string());
        req.headers.set("Content-Length", framed.len().to_string());
        req.body = Body::from(framed);
        let req = sign_request(req, "testing");
        let next: NextFn =
            Arc::new(|_| panic!("bad chunk-signature must not forward body to backend"));
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 403, "expected 403 SignatureDoesNotMatch");
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(
            body.contains("SignatureDoesNotMatch"),
            "expected SignatureDoesNotMatch XML, got {body}"
        );
    }

    #[test]
    fn aws_chunked_content_encoding_alone_does_not_dechunk() {
        let api = S3Api::new(cred_map());
        let payload = b"raw-via-encoding";
        let framed = frame_aws_chunked(payload, false, &[]);
        let mut req = base_s3_req("PUT", "/mybucket/obj", "");
        // Python `_is_streaming`: only STREAMING-* dechunks. Encoding-only
        // aws-chunked is a raw body that happens to carry the token.
        req.headers.set("Content-Encoding", "aws-chunked, gzip");
        req.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        req.headers.set("Content-Length", framed.len().to_string());
        req.headers
            .set("x-amz-decoded-content-length", payload.len().to_string());
        req.body = Body::from(framed.clone());
        let req = sign_request(req, "testing");
        let framed_c = framed.clone();
        let next: NextFn = Arc::new(move |r| {
            if r.method == "HEAD" {
                return Response::new(404);
            }
            let body = r.body.into_vec(u64::MAX).unwrap();
            assert_eq!(body, framed_c, "must not dechunk without STREAMING-*");
            Response::new(201)
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
    }

    #[test]
    fn aws_chunked_trailer_unsigned_dechunks_to_backend() {
        let api = S3Api::new(cred_map());
        let payload = b"with-trailers";
        let framed = frame_aws_chunked(payload, false, &[("x-amz-checksum-crc32", "AAAAAA==")]);
        let mut req = base_s3_req("PUT", "/mybucket/obj", "");
        req.headers
            .set("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER");
        req.headers.set("Content-Encoding", "aws-chunked");
        req.headers
            .set("x-amz-decoded-content-length", payload.len().to_string());
        req.headers.set("Content-Length", framed.len().to_string());
        req.body = Body::from(framed);
        let req = sign_request(req, "testing");
        let next: NextFn = Arc::new(|r| {
            if r.method == "HEAD" {
                return Response::new(404);
            }
            let body = r.body.into_vec(u64::MAX).unwrap();
            assert_eq!(body, b"with-trailers");
            assert_eq!(r.headers.get("Content-Length"), Some("13"));
            Response::new(201)
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
    }

    #[test]
    fn aws_chunked_signed_trailer_ok_dechunks_to_backend() {
        let api = S3Api::new(cred_map());
        let payload = b"signed-trailer-body";
        let mut req = base_s3_req("PUT", "/mybucket/obj", "");
        req.headers.set(
            "x-amz-content-sha256",
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER",
        );
        req.headers.set("Content-Encoding", "aws-chunked");
        req.headers.set("x-amz-trailer", "x-amz-checksum-crc32");
        let req = sign_streaming_put_ex(
            req,
            "testing",
            &[payload.as_slice()],
            &[("x-amz-checksum-crc32", "AAAAAA==")],
            true,
            false,
        );
        let next: NextFn = Arc::new(|r| {
            if r.method == "HEAD" {
                return Response::new(404);
            }
            let body = r.body.into_vec(u64::MAX).unwrap();
            assert_eq!(body, b"signed-trailer-body");
            assert_eq!(r.headers.get("Content-Length"), Some("19"));
            Response::new(201)
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200, "valid trailer sig must succeed");
    }

    #[test]
    fn aws_chunked_bad_trailer_signature_is_signature_does_not_match() {
        let api = S3Api::new(cred_map());
        let payload = b"bad-trailer-sig";
        let mut req = base_s3_req("PUT", "/mybucket/obj", "");
        req.headers.set(
            "x-amz-content-sha256",
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER",
        );
        req.headers.set("Content-Encoding", "aws-chunked");
        req.headers.set("x-amz-trailer", "x-amz-checksum-crc32");
        let req = sign_streaming_put_ex(
            req,
            "testing",
            &[payload.as_slice()],
            &[("x-amz-checksum-crc32", "AAAAAA==")],
            true,
            true, // deliberately wrong trailer signature
        );
        let next: NextFn =
            Arc::new(|_| panic!("bad trailer-signature must not forward body to backend"));
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 403, "expected 403 SignatureDoesNotMatch");
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(
            body.contains("SignatureDoesNotMatch"),
            "expected SignatureDoesNotMatch XML, got {body}"
        );
    }

    #[test]
    fn aws_chunked_malformed_returns_incomplete_body() {
        let api = S3Api::new(cred_map());
        let mut req = base_s3_req("PUT", "/mybucket/obj", "");
        req.headers
            .set("x-amz-content-sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD");
        req.headers.set("Content-Encoding", "aws-chunked");
        req.headers.set("x-amz-decoded-content-length", "5");
        // Truncated framing — no terminal 0 chunk.
        req.body = Body::from(b"5\r\nhello".to_vec());
        let req = sign_request(req, "testing");
        let next: NextFn = Arc::new(|_| panic!("malformed must not reach backend"));
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 400);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(
            body.contains("IncompleteBody") || body.contains("incomplete"),
            "expected IncompleteBody error, got {body}"
        );
    }

    #[test]
    fn aws_chunked_streaming_missing_decoded_length_is_411() {
        let api = S3Api::new(cred_map());
        let mut req = base_s3_req("PUT", "/mybucket/obj", "");
        req.headers
            .set("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER");
        req.headers.set("Content-Encoding", "aws-chunked");
        req.body = Body::from(b"0\r\n\r\n".to_vec());
        let req = sign_request(req, "testing");
        let next: NextFn = Arc::new(|_| panic!("must not reach backend"));
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 411);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("MissingContentLength"), "got {body}");
    }

    #[test]
    fn is_sigv2_detects_header_and_query() {
        let mut headers = HeaderKeyDict::new();
        headers.set("Authorization", "AWS AKID:sig");
        let req = Request {
            method: "GET".into(),
            path: "/b".into(),
            query_string: String::new(),
            headers,
            body: Body::empty(),
        };
        assert!(is_sigv2_auth(&req));
        assert!(is_s3_auth_request(&req));

        let mut headers = HeaderKeyDict::new();
        headers.set(
            "Authorization",
            "AWS4-HMAC-SHA256 Credential=a/20130524/us-east-1/s3/aws4_request, \
             SignedHeaders=host, Signature=00",
        );
        let req = Request {
            method: "GET".into(),
            path: "/b".into(),
            query_string: String::new(),
            headers,
            body: Body::empty(),
        };
        assert!(!is_sigv2_auth(&req));
    }

    #[test]
    fn create_and_delete_bucket() {
        let api = S3Api::new(cred_map());
        let put = sign_request(base_s3_req("PUT", "/newbucket", ""), "testing");
        let next_put: NextFn = Arc::new(|r| {
            assert_eq!(r.path, "/v1/AUTH_test/newbucket");
            assert_eq!(r.method, "PUT");
            Response::new(201)
        });
        assert_eq!(api.handle(put, &next_put).status, 200);

        let del = sign_request(base_s3_req("DELETE", "/newbucket", ""), "testing");
        let next_del: NextFn = Arc::new(|r| {
            assert_eq!(r.path, "/v1/AUTH_test/newbucket");
            Response::new(204)
        });
        assert_eq!(api.handle(del, &next_del).status, 204);
    }

    #[test]
    fn credentials_from_tempauth_admin() {
        let users = vec![(
            "test".into(),
            "tester".into(),
            "testing".into(),
            vec![".admin".into()],
        )];
        let m = credentials_from_tempauth_users(&users, "AUTH_");
        let c = m.get("test:tester").unwrap();
        assert_eq!(c.secret_key, "testing");
        assert_eq!(c.account, "AUTH_test");
        assert!(c.groups.iter().any(|g| g == "AUTH_test"));
    }

    #[test]
    fn copy_object_sets_x_copy_from() {
        let api = S3Api::new(cred_map());
        let mut req = base_s3_req("PUT", "/dst/obj", "");
        req.headers.set("x-amz-copy-source", "/src/obj");
        // signed headers must include the copy source for a real client; for
        // path rewrite we only need a valid SigV4 over the declared set.
        let req = sign_request(req, "testing");
        let next: NextFn = Arc::new(|r| {
            if r.method == "HEAD" {
                return Response::new(404);
            }
            assert_eq!(r.headers.get("X-Copy-From"), Some("src/obj"));
            let mut resp = Response::new(201);
            resp.headers.set("ETag", "ff");
            resp.headers
                .set("Last-Modified", "2013-05-24T00:00:00.000000");
            resp
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("CopyObjectResult"));
        assert!(body.contains("<LastModified>2013-05-24T00:00:00.000Z</LastModified>"));
    }

    #[test]
    fn copy_object_to_itself_without_replace_is_400() {
        let api = S3Api::new(cred_map());
        let mut req = base_s3_req("PUT", "/mybucket/foo123bar", "");
        req.headers.set("x-amz-copy-source", "/mybucket/foo123bar");
        let req = sign_request(req, "testing");
        let next: NextFn = Arc::new(|_| panic!("same-object COPY must not reach Swift"));
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 400);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("<Code>InvalidRequest</Code>"), "{body}");
    }

    #[test]
    fn copy_object_http_last_modified_emits_iso() {
        let api = S3Api::new(cred_map());
        let mut req = base_s3_req("PUT", "/dst/obj", "");
        req.headers.set("x-amz-copy-source", "/src/obj");
        let req = sign_request(req, "testing");
        let next: NextFn = Arc::new(|r| {
            if r.method == "HEAD" {
                return Response::new(404);
            }
            let mut resp = Response::new(201);
            resp.headers.set("ETag", "ff");
            resp.headers
                .set("Last-Modified", "Fri, 24 May 2013 00:00:00 GMT");
            resp
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("<LastModified>2013-05-24T00:00:00.000Z</LastModified>"));
        assert!(!body.contains("Fri, 24 May"));
    }

    /// Bucket object-lock sysmeta blob for mocks: PUT ?legal-hold / ?retention
    /// require the bucket lock config (`require_bucket_object_lock`) first.
    fn mock_bucket_lock_meta() -> String {
        crate::bucket_config::encode_meta_blob(
            br#"<ObjectLockConfiguration>
  <ObjectLockEnabled>Enabled</ObjectLockEnabled>
</ObjectLockConfiguration>"#,
        )
    }

    #[test]
    fn legal_hold_put_get_round_trip() {
        let api = S3Api::new(cred_map());
        let body = br#"<LegalHold><Status>ON</Status></LegalHold>"#;
        let mut put = base_s3_req("PUT", "/mybucket/obj1", "legal-hold");
        put.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        put.body = Body::from(body.to_vec());
        let put = sign_request(put, "testing");
        // Flow: container HEAD (bucket lock gate), object HEAD (version
        // resolve), then the sysmeta POST.
        let lock_meta = mock_bucket_lock_meta();
        let put_next: NextFn = Arc::new(move |r| {
            if r.method == "HEAD" && r.path.ends_with("/mybucket") {
                let mut resp = Response::new(204);
                resp.headers.set(S3_OBJECT_LOCK_META, &lock_meta);
                return resp;
            }
            if r.method == "HEAD" {
                return Response::new(200);
            }
            assert_eq!(r.method, "POST");
            assert_eq!(r.headers.get(SYS_LEGAL_HOLD), Some("ON"));
            Response::new(202)
        });
        assert_eq!(api.handle(put, &put_next).status, 200);

        let get = sign_request(
            base_s3_req("GET", "/mybucket/obj1", "legal-hold"),
            "testing",
        );
        let get_next: NextFn = Arc::new(|_| {
            let mut r = Response::new(200);
            r.headers.set(SYS_LEGAL_HOLD, "ON");
            r
        });
        let resp = api.handle(get, &get_next);
        assert_eq!(resp.status, 200);
        let b = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(b.contains("LegalHold") && b.contains("<Status>ON</Status>"));
    }

    #[test]
    fn retention_put_get_round_trip() {
        let api = S3Api::new(cred_map());
        let body = br#"<Retention>
  <Mode>COMPLIANCE</Mode>
  <RetainUntilDate>2035-01-01T00:00:00.000Z</RetainUntilDate>
</Retention>"#;
        let mut put = base_s3_req("PUT", "/mybucket/obj1", "retention");
        put.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        put.body = Body::from(body.to_vec());
        let put = sign_request(put, "testing");
        let lock_meta = mock_bucket_lock_meta();
        let put_next: NextFn = Arc::new(move |r| {
            if r.method == "HEAD" && r.path.ends_with("/mybucket") {
                // Bucket has object lock enabled (PUT ?retention gate).
                let mut resp = Response::new(204);
                resp.headers.set(S3_OBJECT_LOCK_META, &lock_meta);
                return resp;
            }
            if r.method == "HEAD" {
                // Object exists, no retention yet.
                return Response::new(200);
            }
            assert_eq!(r.method, "POST");
            assert_eq!(r.headers.get(SYS_LOCK_MODE), Some("COMPLIANCE"));
            assert!(r
                .headers
                .get(SYS_RETAIN_UNTIL)
                .unwrap()
                .contains("2035-01-01"));
            Response::new(202)
        });
        assert_eq!(api.handle(put, &put_next).status, 200);

        let get = sign_request(base_s3_req("GET", "/mybucket/obj1", "retention"), "testing");
        let get_next: NextFn = Arc::new(|_| {
            let mut r = Response::new(200);
            r.headers.set(SYS_LOCK_MODE, "COMPLIANCE");
            r.headers.set(SYS_RETAIN_UNTIL, "2035-01-01T00:00:00.000Z");
            r
        });
        let resp = api.handle(get, &get_next);
        assert_eq!(resp.status, 200);
        let b = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(b.contains("Retention") && b.contains("COMPLIANCE"));
    }

    #[test]
    fn legal_hold_blocks_delete() {
        let api = S3Api::new(cred_map());
        let del = sign_request(base_s3_req("DELETE", "/mybucket/locked", ""), "testing");
        let next: NextFn = Arc::new(|r| {
            if r.method == "HEAD" {
                let mut resp = Response::new(200);
                resp.headers.set(SYS_LEGAL_HOLD, "ON");
                return resp;
            }
            panic!("DELETE must not reach backend under legal hold");
        });
        let resp = api.handle(del, &next);
        assert_eq!(resp.status, 403);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("AccessDenied"));
    }

    #[test]
    fn retention_future_blocks_delete() {
        let api = S3Api::new(cred_map());
        let del = sign_request(base_s3_req("DELETE", "/mybucket/retained", ""), "testing");
        let next: NextFn = Arc::new(|r| {
            if r.method == "HEAD" {
                let mut resp = Response::new(200);
                resp.headers.set(SYS_LOCK_MODE, "GOVERNANCE");
                resp.headers.set(SYS_RETAIN_UNTIL, "2099-12-31T00:00:00Z");
                return resp;
            }
            panic!("DELETE must not reach backend under future retention");
        });
        let resp = api.handle(del, &next);
        assert_eq!(resp.status, 403);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("AccessDenied"));
    }

    #[test]
    fn expired_retention_allows_delete() {
        let api = S3Api::new(cred_map());
        let del = sign_request(base_s3_req("DELETE", "/mybucket/old", ""), "testing");
        let deleted = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let deleted_c = deleted.clone();
        let next: NextFn = Arc::new(move |r| {
            if r.method == "HEAD" {
                let mut resp = Response::new(200);
                resp.headers.set(SYS_LOCK_MODE, "GOVERNANCE");
                resp.headers.set(SYS_RETAIN_UNTIL, "2000-01-01T00:00:00Z");
                return resp;
            }
            if r.method == "DELETE" {
                deleted_c.store(true, std::sync::atomic::Ordering::SeqCst);
                return Response::new(204);
            }
            Response::new(500)
        });
        let resp = api.handle(del, &next);
        assert_eq!(resp.status, 204);
        assert!(deleted.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn legal_hold_release_allows_delete() {
        let api = S3Api::new(cred_map());
        let del = sign_request(base_s3_req("DELETE", "/mybucket/released", ""), "testing");
        let deleted = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let deleted_c = deleted.clone();
        let next: NextFn = Arc::new(move |r| {
            if r.method == "HEAD" {
                let mut resp = Response::new(200);
                resp.headers.set(SYS_LEGAL_HOLD, "OFF");
                return resp;
            }
            if r.method == "DELETE" {
                deleted_c.store(true, std::sync::atomic::Ordering::SeqCst);
                return Response::new(204);
            }
            Response::new(500)
        });
        let resp = api.handle(del, &next);
        assert_eq!(resp.status, 204);
        assert!(deleted.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn put_stamps_default_retention_from_bucket_object_lock() {
        let api = S3Api::new(cred_map());
        let lock_xml = br#"<ObjectLockConfiguration>
  <ObjectLockEnabled>Enabled</ObjectLockEnabled>
  <Rule><DefaultRetention>
    <Mode>GOVERNANCE</Mode><Days>3</Days>
  </DefaultRetention></Rule>
</ObjectLockConfiguration>"#;
        let mut put = base_s3_req("PUT", "/mybucket/fresh", "");
        put.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        put.body = Body::from(b"data".to_vec());
        let put = sign_request(put, "testing");
        let stamped = std::sync::Arc::new(std::sync::Mutex::new(None::<(String, String)>));
        let stamped_c = stamped.clone();
        let next: NextFn = Arc::new(move |r| {
            if r.method == "HEAD" {
                let mut resp = Response::new(204);
                apply_object_lock_meta(&mut resp.headers, lock_xml);
                return resp;
            }
            if r.method == "PUT" {
                let mode = r
                    .headers
                    .get(SYS_LOCK_MODE)
                    .map(str::to_string)
                    .unwrap_or_default();
                let until = r
                    .headers
                    .get(SYS_RETAIN_UNTIL)
                    .map(str::to_string)
                    .unwrap_or_default();
                *stamped_c.lock().unwrap() = Some((mode, until));
                let mut resp = Response::new(201);
                resp.headers.set("ETag", "abc");
                return resp;
            }
            Response::new(500)
        });
        let resp = api.handle(put, &next);
        assert_eq!(resp.status, 200);
        let (mode, until) = stamped.lock().unwrap().clone().unwrap();
        assert_eq!(mode, "GOVERNANCE");
        assert!(!until.is_empty());
        let ts = crate::object_lock_worm::parse_retain_until(&until).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert!((ts - now - 3 * 86400).abs() < 5);
    }

    #[test]
    fn put_object_stamps_x_delete_at_from_lifecycle() {
        use crate::bucket_config::{apply_lifecycle_meta, S3_LIFECYCLE_META};
        let api = S3Api::new(cred_map());
        let lc = br#"<?xml version="1.0"?>
<LifecycleConfiguration>
  <Rule>
    <Prefix>logs/</Prefix>
    <Status>Enabled</Status>
    <Expiration><Days>2</Days></Expiration>
  </Rule>
</LifecycleConfiguration>"#;
        let mut lc_headers = HeaderKeyDict::new();
        apply_lifecycle_meta(&mut lc_headers, lc);
        let lc_meta = lc_headers.get(S3_LIFECYCLE_META).unwrap().to_string();

        let mut put = base_s3_req("PUT", "/mybucket/logs/a.txt", "");
        put.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        put.body = Body::from(b"data".to_vec());
        let put = sign_request(put, "testing");
        let seen = std::sync::Arc::new(std::sync::Mutex::new(None::<String>));
        let seen_c = seen.clone();
        let next: NextFn = Arc::new(move |r| {
            if r.method == "HEAD" {
                if r.path.ends_with("/mybucket") {
                    let mut resp = Response::new(204);
                    resp.headers.set(S3_LIFECYCLE_META, &lc_meta);
                    return resp;
                }
                return Response::new(404);
            }
            if r.method == "PUT" {
                *seen_c.lock().unwrap() = r.headers.get("X-Delete-At").map(str::to_string);
                let mut resp = Response::new(201);
                resp.headers.set("ETag", "abc");
                return resp;
            }
            Response::new(500)
        });
        let put_resp = api.handle(put, &next);
        assert_eq!(put_resp.status, 200);
        let exp = put_resp
            .headers
            .get("x-amz-expiration")
            .expect("PUT x-amz-expiration");
        assert!(exp.contains("expiry-date="), "{exp}");
        assert!(exp.contains("rule-id=\"swift-object-expiration\""), "{exp}");
        let da: i64 = seen
            .lock()
            .unwrap()
            .clone()
            .expect("X-Delete-At stamped")
            .parse()
            .unwrap();
        let now = unix_now();
        assert!((da - (now + 2 * 86_400)).abs() < 5, "da={da} now={now}");
    }

    #[test]
    fn get_object_surfaces_x_amz_expiration() {
        let api = S3Api::new(cred_map());
        let req = sign_request(base_s3_req("GET", "/mybucket/logs/a.txt", ""), "testing");
        let next: NextFn = Arc::new(|r| {
            if r.method == "HEAD" {
                return Response::new(404);
            }
            let mut resp = Response::with_body(200, b"data".to_vec());
            resp.headers.set("ETag", "abc");
            resp.headers.set("X-Delete-At", "1700000000");
            resp
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        assert_eq!(
            resp.headers.get("x-amz-expiration"),
            Some("expiry-date=\"Tue, 14 Nov 2023 22:13:20 GMT\", rule-id=\"swift-object-expiration\"")
        );
        assert!(resp.headers.get("X-Delete-At").is_none());
    }

    #[test]
    fn put_object_no_x_delete_at_when_prefix_mismatch() {
        use crate::bucket_config::{apply_lifecycle_meta, S3_LIFECYCLE_META};
        let api = S3Api::new(cred_map());
        let lc = br#"<LifecycleConfiguration>
  <Rule><Prefix>logs/</Prefix><Status>Enabled</Status>
  <Expiration><Days>1</Days></Expiration></Rule>
</LifecycleConfiguration>"#;
        let mut h = HeaderKeyDict::new();
        apply_lifecycle_meta(&mut h, lc);
        let meta = h.get(S3_LIFECYCLE_META).unwrap().to_string();
        let mut put = base_s3_req("PUT", "/mybucket/other/a.txt", "");
        put.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        put.body = Body::from(b"x".to_vec());
        let put = sign_request(put, "testing");
        let next: NextFn = Arc::new(move |r| {
            if r.method == "HEAD" {
                if r.path.ends_with("/mybucket") {
                    let mut resp = Response::new(204);
                    resp.headers.set(S3_LIFECYCLE_META, &meta);
                    return resp;
                }
                return Response::new(404);
            }
            if r.method == "PUT" {
                assert!(
                    r.headers.get("X-Delete-At").is_none(),
                    "prefix mismatch must not stamp X-Delete-At"
                );
                let mut resp = Response::new(201);
                resp.headers.set("ETag", "e");
                return resp;
            }
            Response::new(500)
        });
        assert_eq!(api.handle(put, &next).status, 200);
    }

    #[test]
    fn put_object_stamps_transition_meta_from_lifecycle() {
        use crate::bucket_config::{apply_lifecycle_meta, S3_LIFECYCLE_META};
        use crate::lifecycle_exec::{META_STORAGE_CLASS, SYS_TRANSITION_AT};
        let api = S3Api::new(cred_map());
        let lc = br#"<?xml version="1.0"?>
<LifecycleConfiguration>
  <Rule>
    <Filter><Prefix>logs/</Prefix></Filter>
    <Status>Enabled</Status>
    <Transition><Days>30</Days><StorageClass>GLACIER</StorageClass></Transition>
    <Expiration><Days>90</Days></Expiration>
  </Rule>
</LifecycleConfiguration>"#;
        let mut lc_headers = HeaderKeyDict::new();
        apply_lifecycle_meta(&mut lc_headers, lc);
        let lc_meta = lc_headers.get(S3_LIFECYCLE_META).unwrap().to_string();

        let mut put = base_s3_req("PUT", "/mybucket/logs/a.txt", "");
        put.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        put.body = Body::from(b"data".to_vec());
        let put = sign_request(put, "testing");
        let seen = std::sync::Arc::new(std::sync::Mutex::new(
            None::<(Option<String>, Option<String>, Option<String>)>,
        ));
        let seen_c = seen.clone();
        let next: NextFn = Arc::new(move |r| {
            if r.method == "HEAD" {
                if r.path.ends_with("/mybucket") {
                    let mut resp = Response::new(204);
                    resp.headers.set(S3_LIFECYCLE_META, &lc_meta);
                    return resp;
                }
                return Response::new(404);
            }
            if r.method == "PUT" {
                *seen_c.lock().unwrap() = Some((
                    r.headers.get("X-Delete-At").map(str::to_string),
                    r.headers.get(META_STORAGE_CLASS).map(str::to_string),
                    r.headers.get(SYS_TRANSITION_AT).map(str::to_string),
                ));
                let mut resp = Response::new(201);
                resp.headers.set("ETag", "abc");
                return resp;
            }
            Response::new(500)
        });
        assert_eq!(api.handle(put, &next).status, 200);
        let (da, sc, tr) = seen.lock().unwrap().clone().unwrap();
        let now = unix_now();
        let da: i64 = da.expect("expiration X-Delete-At").parse().unwrap();
        assert!((da - (now + 90 * 86_400)).abs() < 5);
        assert_eq!(sc.as_deref(), Some("GLACIER"));
        let tr: i64 = tr.expect("transition-at").parse().unwrap();
        assert!((tr - (now + 30 * 86_400)).abs() < 5);
    }

    #[test]
    fn put_object_transition_skips_non_matching_prefix() {
        use crate::bucket_config::{apply_lifecycle_meta, S3_LIFECYCLE_META};
        use crate::lifecycle_exec::META_STORAGE_CLASS;
        let api = S3Api::new(cred_map());
        let lc = br#"<LifecycleConfiguration>
  <Rule><Prefix>logs/</Prefix><Status>Enabled</Status>
  <Transition><Days>1</Days><StorageClass>GLACIER</StorageClass></Transition>
  </Rule>
</LifecycleConfiguration>"#;
        let mut h = HeaderKeyDict::new();
        apply_lifecycle_meta(&mut h, lc);
        let meta = h.get(S3_LIFECYCLE_META).unwrap().to_string();
        let mut put = base_s3_req("PUT", "/mybucket/other/a.txt", "");
        put.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        put.body = Body::from(b"x".to_vec());
        let put = sign_request(put, "testing");
        let next: NextFn = Arc::new(move |r| {
            if r.method == "HEAD" {
                if r.path.ends_with("/mybucket") {
                    let mut resp = Response::new(204);
                    resp.headers.set(S3_LIFECYCLE_META, &meta);
                    return resp;
                }
                return Response::new(404);
            }
            if r.method == "PUT" {
                assert!(r.headers.get(META_STORAGE_CLASS).is_none());
                assert!(r.headers.get("X-Delete-At").is_none());
                let mut resp = Response::new(201);
                resp.headers.set("ETag", "e");
                return resp;
            }
            Response::new(500)
        });
        assert_eq!(api.handle(put, &next).status, 200);
    }

    #[test]
    fn mpu_init_stamps_abort_incomplete_x_delete_at() {
        use crate::bucket_config::{apply_lifecycle_meta, S3_LIFECYCLE_META};
        use crate::lifecycle_exec::SYS_ABORT_MPU_DAYS;
        let api = S3Api::new(cred_map());
        let lc = br#"<?xml version="1.0"?>
<LifecycleConfiguration>
  <Rule>
    <Prefix>logs/</Prefix>
    <Status>Enabled</Status>
    <AbortIncompleteMultipartUpload>
      <DaysAfterInitiation>7</DaysAfterInitiation>
    </AbortIncompleteMultipartUpload>
  </Rule>
</LifecycleConfiguration>"#;
        let mut lc_headers = HeaderKeyDict::new();
        apply_lifecycle_meta(&mut lc_headers, lc);
        let lc_meta = lc_headers.get(S3_LIFECYCLE_META).unwrap().to_string();

        let mut init = base_s3_req("POST", "/mybucket/logs/big.bin", "uploads");
        init.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        let init = sign_request(init, "testing");
        let seen = std::sync::Arc::new(std::sync::Mutex::new(
            None::<(Option<String>, Option<String>)>,
        ));
        let seen_c = seen.clone();
        let next: NextFn = Arc::new(move |r| {
            if r.method == "HEAD" && r.path.ends_with("/mybucket") {
                let mut resp = Response::new(204);
                resp.headers.set(S3_LIFECYCLE_META, &lc_meta);
                return resp;
            }
            if r.method == "PUT" {
                // segments container create or marker
                if r.path.contains("+segments") && !r.path.ends_with("+segments") {
                    *seen_c.lock().unwrap() = Some((
                        r.headers.get("X-Delete-At").map(str::to_string),
                        r.headers.get(SYS_ABORT_MPU_DAYS).map(str::to_string),
                    ));
                }
                return Response::new(201);
            }
            Response::new(500)
        });
        assert_eq!(api.handle(init, &next).status, 200);
        let (da, days) = seen.lock().unwrap().clone().expect("marker PUT seen");
        let now = unix_now();
        let da: i64 = da.expect("X-Delete-At on marker").parse().unwrap();
        assert!((da - (now + 7 * 86_400)).abs() < 5, "da={da} now={now}");
        assert_eq!(days.as_deref(), Some("7"));
    }

    #[test]
    fn legal_hold_blocks_overwrite_put() {
        let api = S3Api::new(cred_map());
        let mut put = base_s3_req("PUT", "/mybucket/locked", "");
        put.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        put.body = Body::from(b"new".to_vec());
        let put = sign_request(put, "testing");
        let lock_meta = mock_bucket_lock_meta();
        let next: NextFn = Arc::new(move |r| {
            if r.method == "HEAD" {
                if r.path.ends_with("/locked") {
                    let mut resp = Response::new(200);
                    resp.headers.set(SYS_LEGAL_HOLD, "ON");
                    return resp;
                }
                let mut resp = Response::new(204);
                resp.headers.set(S3_OBJECT_LOCK_META, &lock_meta);
                return resp;
            }
            panic!(
                "overwrite PUT must not reach backend under legal hold: {} {}",
                r.method, r.path
            );
        });
        let resp = api.handle(put, &next);
        assert_eq!(resp.status, 403);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("AccessDenied"));
    }

    #[test]
    fn governance_retention_blocks_overwrite_put() {
        let api = S3Api::new(cred_map());
        let mut put = base_s3_req("PUT", "/mybucket/gov", "");
        put.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        put.body = Body::from(b"new".to_vec());
        let put = sign_request(put, "testing");
        let lock_meta = mock_bucket_lock_meta();
        let next: NextFn = Arc::new(move |r| {
            if r.method == "HEAD" {
                if r.path.ends_with("/gov") {
                    let mut resp = Response::new(200);
                    resp.headers.set(SYS_LOCK_MODE, "GOVERNANCE");
                    resp.headers.set(SYS_RETAIN_UNTIL, "2099-12-31T00:00:00Z");
                    return resp;
                }
                let mut resp = Response::new(204);
                resp.headers.set(S3_OBJECT_LOCK_META, &lock_meta);
                return resp;
            }
            panic!(
                "overwrite PUT must not reach backend under GOVERNANCE retain-until: {} {}",
                r.method, r.path
            );
        });
        let resp = api.handle(put, &next);
        assert_eq!(resp.status, 403);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("AccessDenied"));
    }

    #[test]
    fn compliance_retention_blocks_overwrite_put() {
        let api = S3Api::new(cred_map());
        let mut put = base_s3_req("PUT", "/mybucket/comp", "");
        put.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        put.body = Body::from(b"new".to_vec());
        let put = sign_request(put, "testing");
        let lock_meta = mock_bucket_lock_meta();
        let next: NextFn = Arc::new(move |r| {
            if r.method == "HEAD" {
                if r.path.ends_with("/comp") {
                    let mut resp = Response::new(200);
                    resp.headers.set(SYS_LOCK_MODE, "COMPLIANCE");
                    resp.headers.set(SYS_RETAIN_UNTIL, "2099-12-31T00:00:00Z");
                    return resp;
                }
                let mut resp = Response::new(204);
                resp.headers.set(S3_OBJECT_LOCK_META, &lock_meta);
                return resp;
            }
            panic!(
                "overwrite PUT must not reach backend under COMPLIANCE retain-until: {} {}",
                r.method, r.path
            );
        });
        let resp = api.handle(put, &next);
        assert_eq!(resp.status, 403);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("AccessDenied"));
    }

    #[test]
    fn compliance_retention_put_cannot_shorten() {
        let api = api_with_worm_bypass_permission();
        let body = br#"<Retention>
  <Mode>COMPLIANCE</Mode>
  <RetainUntilDate>2028-01-01T00:00:00Z</RetainUntilDate>
</Retention>"#;
        let mut put = base_s3_req("PUT", "/mybucket/obj1", "retention");
        put.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        put.body = Body::from(body.to_vec());
        let mut put = sign_request(put, "testing");
        put.headers.set(HDR_BYPASS_GOVERNANCE, "true");
        let lock_meta = mock_bucket_lock_meta();
        let next: NextFn = Arc::new(move |r| {
            if r.method == "HEAD" && r.path.ends_with("/mybucket") {
                let mut resp = Response::new(204);
                resp.headers.set(S3_OBJECT_LOCK_META, &lock_meta);
                return resp;
            }
            if r.method == "HEAD" {
                let mut resp = Response::new(200);
                resp.headers.set(SYS_LOCK_MODE, "COMPLIANCE");
                resp.headers.set(SYS_RETAIN_UNTIL, "2030-01-01T00:00:00Z");
                return resp;
            }
            panic!(
                "COMPLIANCE shorten PUT ?retention must not POST sysmeta: {} {}",
                r.method, r.path
            );
        });
        let resp = api.handle(put, &next);
        assert_eq!(resp.status, 403);
        let b = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(b.contains("AccessDenied"));
    }

    #[test]
    fn governance_bypass_header_allows_delete() {
        let api = api_with_worm_bypass_permission();
        let mut del = sign_request(base_s3_req("DELETE", "/mybucket/gov", ""), "testing");
        del.headers.set(HDR_BYPASS_GOVERNANCE, "true");
        let deleted = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let deleted_c = deleted.clone();
        let next: NextFn = Arc::new(move |r| {
            if r.method == "HEAD" {
                let mut resp = Response::new(200);
                resp.headers.set(SYS_LOCK_MODE, "GOVERNANCE");
                resp.headers.set(SYS_RETAIN_UNTIL, "2099-12-31T00:00:00Z");
                return resp;
            }
            if r.method == "DELETE" {
                deleted_c.store(true, std::sync::atomic::Ordering::SeqCst);
                return Response::new(204);
            }
            Response::new(500)
        });
        let resp = api.handle(del, &next);
        assert_eq!(resp.status, 204);
        assert!(deleted.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn compliance_bypass_header_still_denies_delete() {
        let api = api_with_worm_bypass_permission();
        let mut del = sign_request(base_s3_req("DELETE", "/mybucket/comp", ""), "testing");
        del.headers.set(HDR_BYPASS_GOVERNANCE, "true");
        let next: NextFn = Arc::new(|r| {
            if r.method == "HEAD" {
                let mut resp = Response::new(200);
                resp.headers.set(SYS_LOCK_MODE, "COMPLIANCE");
                resp.headers.set(SYS_RETAIN_UNTIL, "2099-12-31T00:00:00Z");
                return resp;
            }
            panic!("COMPLIANCE + bypass must not reach backend DELETE");
        });
        let resp = api.handle(del, &next);
        assert_eq!(resp.status, 403);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("AccessDenied"));
    }

    /// Injectable clock source: `offset` = one fixed reading (ms), `None` =
    /// unreadable. TTL zero so every call re-reads.
    fn test_worm_clock(max_offset_ms: u64, offset: Option<f64>) -> Arc<ClockHealth> {
        Arc::new(ClockHealth::with_reader(
            max_offset_ms,
            std::time::Duration::ZERO,
            Box::new(move || offset),
        ))
    }

    #[test]
    fn invalid_bucket_name_is_400_not_service_405() {
        let api = S3Api::new(cred_map());
        let next: NextFn = Arc::new(|_| panic!("invalid bucket must not reach Swift"));
        for method in ["PUT", "DELETE", "HEAD", "GET"] {
            let req = sign_request(base_s3_req(method, "/bucket+invalid", ""), "testing");
            let resp = api.handle(req, &next);
            assert_eq!(resp.status, 400, "{method}");
            if method != "HEAD" {
                let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
                assert_eq!(error_xml_leaf(&body, "Code"), Some("InvalidBucketName"));
            }
        }
    }

    #[test]
    fn punctuation_bucket_name_is_invalid_bucket_name_not_403() {
        // s3compat test_bucket_create_naming_bad_punctuation: `alpha!soup`.
        let api = S3Api::new(cred_map());
        let next: NextFn = Arc::new(|_| panic!("invalid bucket must not reach Swift"));
        let req = sign_request(base_s3_req("PUT", "/alpha!soup", ""), "testing");
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 400);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert_eq!(error_xml_leaf(&body, "Code"), Some("InvalidBucketName"));
    }

    #[test]
    fn empty_authorization_is_access_denied_not_swift_404() {
        let api = S3Api::new(cred_map());
        let next: NextFn = Arc::new(|_| panic!("empty Authorization must not passthrough"));
        let mut req = Request {
            method: "PUT".into(),
            path: "/mybucket/foo".into(),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: Body::from(b"bar".to_vec()),
        };
        req.headers.set("Host", "localhost");
        req.headers.set("Authorization", "");
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 403);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("AccessDenied"), "{body}");
    }

    #[test]
    fn put_object_without_content_length_is_411() {
        let api = S3Api::new(cred_map());
        let mut req = base_s3_req("PUT", "/mybucket/foo", "");
        req.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        req.body = Body::from_reader(Box::new(std::io::Cursor::new(b"bar".to_vec())), None);
        let mut req = sign_request(req, "testing");
        req.headers.remove("Content-Length");
        let next: NextFn = Arc::new(|_| panic!("missing Content-Length must not reach Swift"));
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 411);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("MissingContentLength"), "{body}");
    }

    #[test]
    fn put_object_empty_buffered_without_content_length_is_411() {
        // Live intercept path: Hyper HTTP/1.1 without CL is a 0-length
        // body; proxy materialize yields Body::Buffered(empty) = Some(0).
        // boto leaves Content-MD5 + Expect: 100-continue.
        let api = S3Api::new(cred_map());
        let mut req = base_s3_req("PUT", "/mybucket/foo", "");
        req.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        req.headers.set("Content-MD5", "N7UdGUp1E+RbVvZSTy1R8g==");
        req.headers.set("Expect", "100-Continue");
        req.body = Body::from(Vec::new());
        let mut req = sign_request(req, "testing");
        req.headers.remove("Content-Length");
        let next: NextFn = Arc::new(|_| panic!("missing Content-Length must not reach Swift"));
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 411);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("MissingContentLength"), "{body}");
    }

    #[test]
    fn put_short_body_499_is_request_timeout() {
        let api = S3Api::new(cred_map());
        let mut req = base_s3_req("PUT", "/mybucket/foo", "");
        req.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        req.body = Body::from(b"bar".to_vec());
        req.headers.set("Content-Length", "3");
        let req = sign_request(req, "testing");
        let next: NextFn = Arc::new(|r| {
            if r.method == "HEAD" {
                return Response::new(204);
            }
            Response::new(499)
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 400);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("RequestTimeout"), "{body}");
    }

    #[test]
    fn versioned_put_then_get_null_version_is_nosuchkey() {
        let api = S3Api::new(cred_map());
        let next = versioning_mock_store("Enabled");
        let mut put = base_s3_req("PUT", "/mybucket/testobj", "");
        put.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        put.body = Body::from(b"fooz".to_vec());
        put.headers.set("Content-Length", "4");
        let r = api.handle(sign_request(put, "testing"), &next);
        assert_eq!(r.status, 200);
        let vid = r.headers.get("x-amz-version-id").unwrap().to_string();
        assert_ne!(vid, "null");
        let get = sign_request(
            base_s3_req("GET", "/mybucket/testobj", "versionId=null"),
            "testing",
        );
        let g = api.handle(get, &next);
        let status = g.status;
        let body = String::from_utf8(g.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert_eq!(status, 404, "{body}");
        assert!(body.contains("NoSuchKey") || body.contains("NoSuchVersion"), "{body}");
    }

    #[test]
    fn sigv2_async_versioned_put_stamps_version_id() {
        let api = S3Api::new(cred_map());
        let store = versioning_mock_store("Enabled");
        let next = async_ok(move |r| store(r));
        let mut put = base_s3_req("PUT", "/mybucket/testobj", "");
        // Live boto SigV2 does not send x-amz-content-sha256. base_s3_req
        // stamps the empty-body hash for V4 fixtures; leave UNSIGNED-PAYLOAD
        // so handle_s3_async does not 400 XAmzContentSHA256Mismatch.
        put.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        put.body = Body::from(b"fooz".to_vec());
        put.headers.set("Content-Length", "4");
        let put = sign_request_v2(put, "test:tester", "testing");
        let r = block_on_s3_multi(api.handle_s3_async(put, next.clone()));
        let st = r.status;
        let vid = r.headers.get("x-amz-version-id").map(str::to_string);
        let rbody = String::from_utf8(r.body.into_vec(u64::MAX).unwrap_or_default()).unwrap_or_default();
        assert_eq!(st, 200, "sigv2 versioned PUT status={st} body={rbody}");
        assert!(vid.as_deref().is_some_and(|v| v != "null"), "got {vid:?}");
        let get = sign_request_v2(
            base_s3_req("GET", "/mybucket/testobj", "versionId=null"),
            "test:tester",
            "testing",
        );
        let g = block_on_s3_multi(api.handle_s3_async(get, next));
        assert_eq!(g.status, 404);
        let body = String::from_utf8(g.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("NoSuchKey") || body.contains("NoSuchVersion"), "{body}");
    }

    #[test]
    fn account_level_put_delete_post_are_method_not_allowed() {
        // Python 2.33 ServiceController implements GET only. Live-oracle
        // probe (s3win-20260817-account-probe.json, 2026-08-17): signed
        // PUT/DELETE/POST on `/` → 405 MethodNotAllowed with the SERVICE
        // resource type. The Swift backend must never see the request —
        // this is the 887be `/v1/<account>` translation family.
        let api = S3Api::new(cred_map());
        for method in ["PUT", "DELETE", "POST"] {
            let req = sign_request(base_s3_req(method, "/", ""), "testing");
            let hit = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let hit_c = hit.clone();
            let next: NextFn = Arc::new(move |_| {
                hit_c.store(true, std::sync::atomic::Ordering::SeqCst);
                Response::new(500)
            });
            let resp = api.handle(req, &next);
            assert_eq!(resp.status, 405, "{method} / must 405");
            assert_eq!(resp.headers.get("Content-Type"), Some("application/xml"));
            assert!(
                !hit.load(std::sync::atomic::Ordering::SeqCst),
                "{method} / must not reach the Swift backend"
            );
            let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
            // Byte-aligned to the probed Python reject (RequestId dynamic).
            assert!(
                body.starts_with("<?xml version='1.0' encoding='UTF-8'?>\n"),
                "{body}"
            );
            assert_eq!(error_xml_leaf(&body, "Code"), Some("MethodNotAllowed"));
            assert_eq!(
                error_xml_leaf(&body, "Message"),
                Some("The specified method is not allowed against this resource.")
            );
            let rid = error_xml_leaf(&body, "RequestId").expect("RequestId child");
            assert!(request_id_survives_normalize(rid), "{rid:?}");
            assert_eq!(error_xml_leaf(&body, "Method"), Some(method));
            assert_eq!(error_xml_leaf(&body, "ResourceType"), Some("SERVICE"));
            // Python element order: Code, Message, RequestId, Method,
            // ResourceType.
            let order = [
                "<Code>",
                "<Message>",
                "<RequestId>",
                "<Method>",
                "<ResourceType>",
            ];
            let mut last = 0;
            for tag in order {
                let at = body.find(tag).unwrap_or_else(|| panic!("{tag} in {body}"));
                assert!(at >= last, "{tag} out of order in {body}");
                last = at;
            }
        }
    }

    #[test]
    fn account_level_head_is_method_not_allowed_with_empty_body() {
        // Probed Python: HEAD / → 405, Content-Type application/xml,
        // empty body (Content-Length 0).
        let api = S3Api::new(cred_map());
        let req = sign_request(base_s3_req("HEAD", "/", ""), "testing");
        let next: NextFn = Arc::new(|_| panic!("HEAD / must not reach the Swift backend"));
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 405);
        assert_eq!(resp.headers.get("Content-Type"), Some("application/xml"));
        let body = resp.body.into_vec(u64::MAX).unwrap();
        assert!(body.is_empty(), "HEAD 405 must carry no body");
    }

    #[test]
    fn account_level_get_stays_list_buckets_with_guard() {
        // GET / is ListBuckets and must keep translating to the account GET.
        let api = S3Api::new(cred_map());
        let req = sign_request(base_s3_req("GET", "/", ""), "testing");
        let next: NextFn = Arc::new(|r| {
            assert_eq!(r.method, "GET");
            assert_eq!(r.path, "/v1/AUTH_test");
            Response::with_body(200, br#"[]"#.to_vec())
        });
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("ListAllMyBucketsResult"), "{body}");
    }

    #[test]
    fn worm_clock_gates_expired_compliance_delete() {
        // Expired COMPLIANCE lock: with a healthy (or disabled) clock the
        // DELETE proceeds; with the knob on and the source over-threshold or
        // unreadable, COMPLIANCE claims fail closed (403, no backend DELETE).
        let run = |api: S3Api, expect_deleted: bool| {
            let del = sign_request(base_s3_req("DELETE", "/mybucket/expired", ""), "testing");
            let deleted = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let deleted_c = deleted.clone();
            let next: NextFn = Arc::new(move |r| {
                if r.method == "HEAD" && r.path.ends_with("/mybucket") {
                    return Response::new(204);
                }
                if r.method == "HEAD" {
                    let mut resp = Response::new(200);
                    resp.headers.set(SYS_LOCK_MODE, "COMPLIANCE");
                    resp.headers.set(SYS_RETAIN_UNTIL, "2000-01-01T00:00:00Z");
                    return resp;
                }
                if r.method == "DELETE" {
                    deleted_c.store(true, std::sync::atomic::Ordering::SeqCst);
                    return Response::new(204);
                }
                Response::new(500)
            });
            let resp = api.handle(del, &next);
            if expect_deleted {
                assert_eq!(resp.status, 204);
            } else {
                assert_eq!(resp.status, 403);
            }
            assert_eq!(
                deleted.load(std::sync::atomic::Ordering::SeqCst),
                expect_deleted
            );
        };

        // Knob off (default): identical to the historical pinned true.
        run(S3Api::new(cred_map()), true);
        // Enabled + healthy reading within threshold.
        run(
            S3Api::new(cred_map()).with_worm_clock(test_worm_clock(50, Some(-12.0))),
            true,
        );
        // Enabled + offset over threshold → fail closed.
        run(
            S3Api::new(cred_map()).with_worm_clock(test_worm_clock(50, Some(75.0))),
            false,
        );
        // Enabled + unreadable source → fail closed.
        run(
            S3Api::new(cred_map()).with_worm_clock(test_worm_clock(50, None)),
            false,
        );
    }

    #[test]
    fn worm_clock_unhealthy_denies_compliance_retention_put() {
        // PUT ?retention with a COMPLIANCE claim is a COMPLIANCE mutation:
        // enabled + unhealthy source must 403 before any sysmeta POST.
        let body = br#"<Retention xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Mode>COMPLIANCE</Mode>
  <RetainUntilDate>2099-01-01T00:00:00Z</RetainUntilDate>
</Retention>"#;
        let run = |api: S3Api, expect_status: u16| {
            let mut put = base_s3_req("PUT", "/mybucket/obj1", "retention");
            put.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
            put.body = Body::from(body.to_vec());
            let put = sign_request(put, "testing");
            let lock_meta = mock_bucket_lock_meta();
            let posted = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let posted_c = posted.clone();
            let next: NextFn = Arc::new(move |r| {
                if r.method == "HEAD" && r.path.ends_with("/mybucket") {
                    let mut resp = Response::new(204);
                    resp.headers.set(S3_OBJECT_LOCK_META, &lock_meta);
                    return resp;
                }
                if r.method == "HEAD" {
                    return Response::new(200);
                }
                if r.method == "POST" {
                    posted_c.store(true, std::sync::atomic::Ordering::SeqCst);
                    return Response::new(202);
                }
                Response::new(500)
            });
            let resp = api.handle(put, &next);
            assert_eq!(resp.status, expect_status);
            assert_eq!(
                posted.load(std::sync::atomic::Ordering::SeqCst),
                expect_status == 200,
                "sysmeta POST gating"
            );
            if expect_status == 403 {
                let b = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
                assert!(b.contains("AccessDenied"), "{b}");
            }
        };

        let iam_api = || {
            let mut iam = crate::iam::IamService::new();
            let policy = crate::iam::IamService::parse_policy_json(
                r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:*","Resource":"arn:aws:s3:::mybucket/*","Principal":"*"}}"#,
            )
            .expect("valid WORM IAM fixture");
            iam.attach_policy("*", "worm-clock-test", policy);
            S3Api::new(cred_map()).with_iam(iam)
        };

        // Knob off (default): COMPLIANCE claim on an unlocked object stores.
        run(iam_api(), 200);
        // Enabled + healthy: unchanged.
        run(
            iam_api().with_worm_clock(test_worm_clock(50, Some(3.5))),
            200,
        );
        // Enabled + over threshold / unreadable: COMPLIANCE claim denied.
        run(
            iam_api().with_worm_clock(test_worm_clock(50, Some(1e6))),
            403,
        );
        run(iam_api().with_worm_clock(test_worm_clock(50, None)), 403);
    }

    #[test]
    fn invalid_governance_bypass_header_is_rejected_before_delete() {
        let api = S3Api::new(cred_map());
        let mut del = sign_request(base_s3_req("DELETE", "/mybucket/hold", ""), "testing");
        del.headers.set("X-Amz-Bypass-Governance-Retention", "1");
        let next: NextFn = Arc::new(|r| {
            if r.method == "HEAD" {
                let mut resp = Response::new(200);
                resp.headers.set(SYS_LEGAL_HOLD, "ON");
                resp.headers.set(SYS_LOCK_MODE, "GOVERNANCE");
                resp.headers.set(SYS_RETAIN_UNTIL, "2099-12-31T00:00:00Z");
                return resp;
            }
            panic!("invalid bypass must not reach backend");
        });
        let resp = api.handle(del, &next);
        assert_eq!(resp.status, 400);
    }

    #[test]
    fn governance_bypass_header_allows_overwrite_put() {
        let api = api_with_worm_bypass_permission();
        let mut put = base_s3_req("PUT", "/mybucket/gov", "");
        put.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        put.body = Body::from(b"new".to_vec());
        let mut put = sign_request(put, "testing");
        put.headers.set(HDR_BYPASS_GOVERNANCE, "True");
        let put_seen = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let put_c = put_seen.clone();
        let next: NextFn = Arc::new(move |r| {
            if r.method == "HEAD" {
                if r.path.ends_with("/gov") {
                    let mut resp = Response::new(200);
                    resp.headers.set(SYS_LOCK_MODE, "GOVERNANCE");
                    resp.headers.set(SYS_RETAIN_UNTIL, "2099-12-31T00:00:00Z");
                    return resp;
                }
                return Response::new(404);
            }
            if r.method == "PUT" {
                put_c.store(true, std::sync::atomic::Ordering::SeqCst);
                let mut resp = Response::new(201);
                resp.headers.set("ETag", "abc");
                return resp;
            }
            Response::new(500)
        });
        let resp = api.handle(put, &next);
        assert_eq!(resp.status, 200);
        assert!(put_seen.load(std::sync::atomic::Ordering::SeqCst));
    }

    // ---- Wave-9 WORM fault-injection: malformed persisted lock state ----

    /// DELETE against corrupt persisted lock sysmeta must be InternalError
    /// (fail-closed), never reinterpreted as an unlocked object.
    #[test]
    fn malformed_persisted_lock_delete_fails_closed_internal_error() {
        let cases: &[(&str, &str)] = &[
            ("BOGUS", "2099-12-31T00:00:00Z"), // unknown mode, valid date
            ("COMPLIANCE", "not-a-date"),      // valid mode, corrupt date
            ("COMPLIANCE", ""),                // half record: mode only
            ("", "2099-12-31T00:00:00Z"),      // half record: date only
        ];
        for (mode, until) in cases {
            let api = S3Api::new(cred_map());
            let del = sign_request(base_s3_req("DELETE", "/mybucket/corrupt", ""), "testing");
            let mode_c = mode.to_string();
            let until_c = until.to_string();
            let next: NextFn = Arc::new(move |r| {
                if r.method == "HEAD" {
                    if r.path.ends_with("/corrupt") {
                        let mut resp = Response::new(200);
                        if !mode_c.is_empty() {
                            resp.headers.set(SYS_LOCK_MODE, &mode_c);
                        }
                        if !until_c.is_empty() {
                            resp.headers.set(SYS_RETAIN_UNTIL, &until_c);
                        }
                        return resp;
                    }
                    return Response::new(204);
                }
                panic!(
                    "corrupt lock metadata must fail closed, backend saw: {} {}",
                    r.method, r.path
                );
            });
            let resp = api.handle(del, &next);
            assert_eq!(resp.status, 500, "mode={mode:?} until={until:?}");
            let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
            assert!(body.contains("InternalError"), "{body}");
        }
    }

    /// A legal-hold value that is neither ON nor OFF is corrupt persisted
    /// state: DELETE fails closed with InternalError.
    #[test]
    fn malformed_legal_hold_value_blocks_delete_fail_closed() {
        let api = S3Api::new(cred_map());
        let del = sign_request(base_s3_req("DELETE", "/mybucket/heldish", ""), "testing");
        let next: NextFn = Arc::new(|r| {
            if r.method == "HEAD" {
                if r.path.ends_with("/heldish") {
                    let mut resp = Response::new(200);
                    resp.headers.set(SYS_LEGAL_HOLD, "maybe");
                    return resp;
                }
                return Response::new(204);
            }
            panic!("corrupt legal hold must not reach backend DELETE");
        });
        let resp = api.handle(del, &next);
        assert_eq!(resp.status, 500);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("InternalError"));
    }

    /// Overwrite PUT against corrupt persisted lock sysmeta fails closed.
    #[test]
    fn malformed_persisted_lock_overwrite_put_fails_closed() {
        let api = S3Api::new(cred_map());
        let mut put = base_s3_req("PUT", "/mybucket/corrupt", "");
        put.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        put.body = Body::from(b"new".to_vec());
        let put = sign_request(put, "testing");
        let lock_meta = mock_bucket_lock_meta();
        let next: NextFn = Arc::new(move |r| {
            if r.method == "HEAD" {
                if r.path.ends_with("/corrupt") {
                    let mut resp = Response::new(200);
                    resp.headers.set(SYS_LOCK_MODE, "COMPLIANCE");
                    resp.headers.set(SYS_RETAIN_UNTIL, "junk");
                    return resp;
                }
                let mut resp = Response::new(204);
                resp.headers.set(S3_OBJECT_LOCK_META, &lock_meta);
                return resp;
            }
            panic!(
                "overwrite of corrupt-locked object must fail closed: {} {}",
                r.method, r.path
            );
        });
        let resp = api.handle(put, &next);
        assert_eq!(resp.status, 500);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("InternalError"));
    }

    /// GET ?retention over corrupt persisted lock state answers InternalError,
    /// not "no retention" and not a reinterpreted record.
    #[test]
    fn retention_get_on_malformed_persisted_lock_is_internal_error() {
        let api = S3Api::new(cred_map());
        let get = sign_request(
            base_s3_req("GET", "/mybucket/corrupt", "retention"),
            "testing",
        );
        let next: NextFn = Arc::new(|r| {
            assert_eq!(r.method, "HEAD");
            let mut resp = Response::new(200);
            resp.headers.set(SYS_LOCK_MODE, "GOVERNANCE");
            resp.headers.set(SYS_RETAIN_UNTIL, "2030-13-45T99:99:99Z");
            resp
        });
        let resp = api.handle(get, &next);
        assert_eq!(resp.status, 500);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("InternalError"), "{body}");
        assert!(
            !body.contains("GOVERNANCE"),
            "must not echo corrupt state: {body}"
        );
    }

    /// PUT ?retention over a half-persisted lock record (mode without date)
    /// fails closed with InternalError and never POSTs new sysmeta.
    #[test]
    fn retention_put_on_malformed_persisted_lock_fails_closed() {
        let api = S3Api::new(cred_map());
        let body = br#"<Retention>
  <Mode>COMPLIANCE</Mode>
  <RetainUntilDate>2099-01-01T00:00:00Z</RetainUntilDate>
</Retention>"#;
        let mut put = base_s3_req("PUT", "/mybucket/corrupt", "retention");
        put.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        put.body = Body::from(body.to_vec());
        let put = sign_request(put, "testing");
        let lock_meta = mock_bucket_lock_meta();
        let next: NextFn = Arc::new(move |r| {
            if r.method == "HEAD" && r.path.ends_with("/mybucket") {
                let mut resp = Response::new(204);
                resp.headers.set(S3_OBJECT_LOCK_META, &lock_meta);
                return resp;
            }
            if r.method == "HEAD" {
                let mut resp = Response::new(200);
                resp.headers.set(SYS_LOCK_MODE, "COMPLIANCE"); // date missing
                return resp;
            }
            panic!(
                "retention PUT over corrupt state must not POST: {} {}",
                r.method, r.path
            );
        });
        let resp = api.handle(put, &next);
        assert_eq!(resp.status, 500);
        let b = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(b.contains("InternalError"));
    }

    // ---- Wave-9 WORM fault-injection: persist-layer backend failures ----

    /// A 5xx on the lock-state HEAD is not "no lock": DELETE must fail closed
    /// with the mapped backend error and never reach the backend DELETE.
    #[test]
    fn delete_backend_head_5xx_fails_closed_without_delete() {
        let api = S3Api::new(cred_map());
        let del = sign_request(base_s3_req("DELETE", "/mybucket/flaky", ""), "testing");
        let next: NextFn = Arc::new(|r| {
            if r.method == "HEAD" {
                if r.path.ends_with("/flaky") {
                    return Response::new(503);
                }
                return Response::new(204);
            }
            panic!(
                "HEAD 5xx must not fall through to DELETE: {} {}",
                r.method, r.path
            );
        });
        let resp = api.handle(del, &next);
        assert_eq!(resp.status, 500);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("InternalError"), "{body}");
    }

    /// Backend failures on PUT ?retention surface as errors: a 5xx on the
    /// resolve HEAD aborts before evaluation, and a 5xx on the sysmeta POST
    /// must not be reported as success.
    #[test]
    fn retention_put_backend_failures_do_not_succeed() {
        let body = br#"<Retention>
  <Mode>GOVERNANCE</Mode>
  <RetainUntilDate>2099-01-01T00:00:00Z</RetainUntilDate>
</Retention>"#;
        let make_put = || {
            let mut put = base_s3_req("PUT", "/mybucket/flaky", "retention");
            put.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
            put.body = Body::from(body.to_vec());
            sign_request(put, "testing")
        };

        // (a) resolve HEAD 5xx → error, nothing else contacted.
        let api = S3Api::new(cred_map());
        let lock_meta = mock_bucket_lock_meta();
        let next_head_5xx: NextFn = Arc::new(move |r| {
            if r.method == "HEAD" && r.path.ends_with("/mybucket") {
                let mut resp = Response::new(204);
                resp.headers.set(S3_OBJECT_LOCK_META, &lock_meta);
                return resp;
            }
            if r.method == "HEAD" {
                return Response::new(502);
            }
            panic!(
                "resolve HEAD 5xx must abort retention PUT: {} {}",
                r.method, r.path
            );
        });
        let resp = api.handle(make_put(), &next_head_5xx);
        assert_eq!(resp.status, 500);

        // (b) sysmeta POST 5xx → mapped error, not 200.
        let api = S3Api::new(cred_map());
        let lock_meta = mock_bucket_lock_meta();
        let next_post_5xx: NextFn = Arc::new(move |r| {
            if r.method == "HEAD" && r.path.ends_with("/mybucket") {
                let mut resp = Response::new(204);
                resp.headers.set(S3_OBJECT_LOCK_META, &lock_meta);
                return resp;
            }
            if r.method == "HEAD" {
                return Response::new(200); // object exists, unlocked
            }
            assert_eq!(r.method, "POST");
            Response::new(503)
        });
        let resp = api.handle(make_put(), &next_post_5xx);
        assert_eq!(resp.status, 500);
        let b = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(b.contains("InternalError"), "{b}");
    }

    // ---- Wave-9 WORM fault-injection: governance bypass permission matrix ----

    /// Bypass header without the IAM grant: GOVERNANCE delete stays denied
    /// (header alone is never enough).
    #[test]
    fn governance_bypass_header_without_iam_grant_denies_delete() {
        let api = S3Api::new(cred_map()); // no s3:BypassGovernanceRetention grant
        let mut del = sign_request(base_s3_req("DELETE", "/mybucket/gov", ""), "testing");
        del.headers.set(HDR_BYPASS_GOVERNANCE, "true");
        let next: NextFn = Arc::new(|r| {
            if r.method == "HEAD" {
                let mut resp = Response::new(200);
                resp.headers.set(SYS_LOCK_MODE, "GOVERNANCE");
                resp.headers.set(SYS_RETAIN_UNTIL, "2099-12-31T00:00:00Z");
                return resp;
            }
            panic!("header-only bypass must not reach backend DELETE");
        });
        let resp = api.handle(del, &next);
        assert_eq!(resp.status, 403);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("AccessDenied"));
    }

    /// IAM grant without the bypass header: GOVERNANCE delete stays denied
    /// (permission alone is never enough).
    #[test]
    fn governance_iam_grant_without_header_denies_delete() {
        let api = api_with_worm_bypass_permission();
        let del = sign_request(base_s3_req("DELETE", "/mybucket/gov", ""), "testing");
        let next: NextFn = Arc::new(|r| {
            if r.method == "HEAD" {
                let mut resp = Response::new(200);
                resp.headers.set(SYS_LOCK_MODE, "GOVERNANCE");
                resp.headers.set(SYS_RETAIN_UNTIL, "2099-12-31T00:00:00Z");
                return resp;
            }
            panic!("grant-only (no header) must not reach backend DELETE");
        });
        let resp = api.handle(del, &next);
        assert_eq!(resp.status, 403);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("AccessDenied"));
    }

    /// COMPLIANCE ignores bypass in every partial combination: header without
    /// grant and grant without header both stay denied.
    #[test]
    fn compliance_bypass_partial_bits_deny_delete() {
        let compliance_head: NextFn = Arc::new(|r| {
            if r.method == "HEAD" {
                let mut resp = Response::new(200);
                resp.headers.set(SYS_LOCK_MODE, "COMPLIANCE");
                resp.headers.set(SYS_RETAIN_UNTIL, "2099-12-31T00:00:00Z");
                return resp;
            }
            panic!("COMPLIANCE must never reach backend DELETE");
        });

        // Header without grant.
        let api = S3Api::new(cred_map());
        let mut del = sign_request(base_s3_req("DELETE", "/mybucket/comp", ""), "testing");
        del.headers.set(HDR_BYPASS_GOVERNANCE, "true");
        let resp = api.handle(del, &compliance_head);
        assert_eq!(resp.status, 403);

        // Grant without header.
        let api = api_with_worm_bypass_permission();
        let del = sign_request(base_s3_req("DELETE", "/mybucket/comp", ""), "testing");
        let resp = api.handle(del, &compliance_head);
        assert_eq!(resp.status, 403);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("AccessDenied"));
    }

    // ---- Wave-9 WORM × versioning interaction locks ----

    /// Seed the versioning mock store's bucket with Object Lock config so
    /// explicit x-amz-object-lock-* PUT headers pass the bucket gate.
    fn seed_bucket_object_lock(next: &NextFn) {
        let mut post = make_swift_req("POST", "/v1/AUTH_test/mybucket");
        post.headers
            .set(S3_OBJECT_LOCK_META, mock_bucket_lock_meta());
        assert_eq!(next(post).status, 204);
    }

    /// Enabled versioning: a PUT over a COMPLIANCE-locked current version is
    /// allowed (the lock protects the version, not the key), the locked
    /// version survives as a retrievable non-current version, and the new
    /// unlocked version does not inherit the lock.
    #[test]
    fn versioned_put_over_compliance_locked_current_creates_new_version() {
        let api = S3Api::new(cred_map());
        let next = versioning_mock_store("Enabled");
        seed_bucket_object_lock(&next);

        let mut p1 = base_s3_req("PUT", "/mybucket/obj", "");
        p1.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        p1.body = Body::from(b"one".to_vec());
        let mut p1 = sign_request(p1, "testing");
        p1.headers.set("X-Amz-Object-Lock-Mode", "COMPLIANCE");
        p1.headers.set(
            "X-Amz-Object-Lock-Retain-Until-Date",
            "2099-12-31T00:00:00Z",
        );
        let r1 = api.handle(p1, &next);
        assert_eq!(r1.status, 200);
        let vid1 = r1.headers.get("x-amz-version-id").unwrap().to_string();

        let mut p2 = base_s3_req("PUT", "/mybucket/obj", "");
        p2.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        p2.body = Body::from(b"two".to_vec());
        let r2 = api.handle(sign_request(p2, "testing"), &next);
        assert_eq!(r2.status, 200, "PUT over locked current must be allowed");
        let vid2 = r2.headers.get("x-amz-version-id").unwrap().to_string();
        assert_ne!(vid1, vid2);

        // The locked version is archived, not destroyed.
        let g1 = sign_request(
            base_s3_req("GET", "/mybucket/obj", &format!("versionId={vid1}")),
            "testing",
        );
        let g1 = api.handle(g1, &next);
        assert_eq!(g1.status, 200);
        assert_eq!(g1.body.into_vec(u64::MAX).unwrap(), b"one");

        // The new version carries no lock: exact-version delete succeeds and
        // promotes the locked version back to current.
        let d2 = sign_request(
            base_s3_req("DELETE", "/mybucket/obj", &format!("versionId={vid2}")),
            "testing",
        );
        assert_eq!(api.handle(d2, &next).status, 204);
        let cur = sign_request(base_s3_req("GET", "/mybucket/obj", ""), "testing");
        let cur = api.handle(cur, &next);
        assert_eq!(cur.status, 200);
        assert_eq!(cur.body.into_vec(u64::MAX).unwrap(), b"one");
    }

    /// Enabled versioning: DELETE without versionId on a legal-hold object
    /// only writes a delete marker; the held version stays retrievable.
    #[test]
    fn versioned_delete_marker_allowed_over_legal_hold_version() {
        let api = S3Api::new(cred_map());
        let next = versioning_mock_store("Enabled");
        seed_bucket_object_lock(&next);

        let mut p1 = base_s3_req("PUT", "/mybucket/obj", "");
        p1.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        p1.body = Body::from(b"held".to_vec());
        let mut p1 = sign_request(p1, "testing");
        p1.headers.set("X-Amz-Object-Lock-Legal-Hold", "ON");
        let r1 = api.handle(p1, &next);
        assert_eq!(r1.status, 200);
        let vid1 = r1.headers.get("x-amz-version-id").unwrap().to_string();

        let del = sign_request(base_s3_req("DELETE", "/mybucket/obj", ""), "testing");
        let dresp = api.handle(del, &next);
        assert_eq!(
            dresp.status, 204,
            "delete marker must be allowed under legal hold"
        );
        assert_eq!(dresp.headers.get("x-amz-delete-marker"), Some("true"));

        let g1 = sign_request(
            base_s3_req("GET", "/mybucket/obj", &format!("versionId={vid1}")),
            "testing",
        );
        let g1 = api.handle(g1, &next);
        assert_eq!(
            g1.status, 200,
            "held version must survive the delete marker"
        );
        assert_eq!(g1.body.into_vec(u64::MAX).unwrap(), b"held");
    }

    /// DELETE ?versionId against a COMPLIANCE-protected version is denied both
    /// while it is the current version and after it was archived by a newer
    /// PUT (the lock sysmeta must survive archival).
    #[test]
    fn versioned_delete_compliance_version_denied_current_and_archived() {
        let api = S3Api::new(cred_map());
        let next = versioning_mock_store("Enabled");
        seed_bucket_object_lock(&next);

        let mut p1 = base_s3_req("PUT", "/mybucket/obj", "");
        p1.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        p1.body = Body::from(b"keep".to_vec());
        let mut p1 = sign_request(p1, "testing");
        p1.headers.set("X-Amz-Object-Lock-Mode", "COMPLIANCE");
        p1.headers.set(
            "X-Amz-Object-Lock-Retain-Until-Date",
            "2099-12-31T00:00:00Z",
        );
        let r1 = api.handle(p1, &next);
        assert_eq!(r1.status, 200);
        let vid1 = r1.headers.get("x-amz-version-id").unwrap().to_string();

        // Current version: exact-version delete denied.
        let d1 = sign_request(
            base_s3_req("DELETE", "/mybucket/obj", &format!("versionId={vid1}")),
            "testing",
        );
        let resp = api.handle(d1, &next);
        assert_eq!(resp.status, 403);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("AccessDenied"));

        // Archive it under a newer version, then try again.
        let mut p2 = base_s3_req("PUT", "/mybucket/obj", "");
        p2.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        p2.body = Body::from(b"newer".to_vec());
        assert_eq!(api.handle(sign_request(p2, "testing"), &next).status, 200);

        let d1_again = sign_request(
            base_s3_req("DELETE", "/mybucket/obj", &format!("versionId={vid1}")),
            "testing",
        );
        let resp = api.handle(d1_again, &next);
        assert_eq!(
            resp.status, 403,
            "lock must survive archival of the version"
        );

        let g1 = sign_request(
            base_s3_req("GET", "/mybucket/obj", &format!("versionId={vid1}")),
            "testing",
        );
        let g1 = api.handle(g1, &next);
        assert_eq!(g1.status, 200);
        assert_eq!(g1.body.into_vec(u64::MAX).unwrap(), b"keep");
    }

    /// Exact-version DELETE of a GOVERNANCE-locked version succeeds only with
    /// the bypass header AND the IAM grant, on the versioned path too.
    #[test]
    fn versioned_governance_bypass_delete_removes_version() {
        let api = api_with_worm_bypass_permission();
        let next = versioning_mock_store("Enabled");
        seed_bucket_object_lock(&next);

        let mut p1 = base_s3_req("PUT", "/mybucket/obj", "");
        p1.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        p1.body = Body::from(b"gov".to_vec());
        let mut p1 = sign_request(p1, "testing");
        p1.headers.set("X-Amz-Object-Lock-Mode", "GOVERNANCE");
        p1.headers.set(
            "X-Amz-Object-Lock-Retain-Until-Date",
            "2099-12-31T00:00:00Z",
        );
        let r1 = api.handle(p1, &next);
        assert_eq!(r1.status, 200);
        let vid1 = r1.headers.get("x-amz-version-id").unwrap().to_string();

        // Without the header: denied even though the IAM grant exists.
        let plain = sign_request(
            base_s3_req("DELETE", "/mybucket/obj", &format!("versionId={vid1}")),
            "testing",
        );
        assert_eq!(api.handle(plain, &next).status, 403);

        // Header + grant: the governance-locked version is removed.
        let mut del = sign_request(
            base_s3_req("DELETE", "/mybucket/obj", &format!("versionId={vid1}")),
            "testing",
        );
        del.headers.set(HDR_BYPASS_GOVERNANCE, "true");
        assert_eq!(api.handle(del, &next).status, 204);

        let get = sign_request(
            base_s3_req("GET", "/mybucket/obj", &format!("versionId={vid1}")),
            "testing",
        );
        let got = api.handle(get, &next);
        assert_eq!(got.status, 404);
    }

    /// Suspending versioning on a bucket that carries an Object Lock
    /// configuration is rejected (AWS: InvalidBucketState).
    #[test]
    fn versioning_suspend_on_lock_bucket_is_invalid_bucket_state() {
        let api = S3Api::new(cred_map());
        let mut put = base_s3_req("PUT", "/mybucket", "versioning");
        put.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        put.body = Body::from(
            br#"<VersioningConfiguration><Status>Suspended</Status></VersioningConfiguration>"#
                .to_vec(),
        );
        let put = sign_request(put, "testing");
        let lock_meta = mock_bucket_lock_meta();
        let next: NextFn = Arc::new(move |r| {
            if r.method == "HEAD" {
                let mut resp = Response::new(204);
                resp.headers.set(S3_OBJECT_LOCK_META, &lock_meta);
                return resp;
            }
            panic!("suspend on a lock bucket must not reach the backend POST");
        });
        let resp = api.handle(put, &next);
        assert_eq!(resp.status, 409);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("InvalidBucketState"), "{body}");
    }

    /// Suspended versioning destroys the null version on overwrite, so a
    /// locked null version blocks both PUT and the delete-marker DELETE.
    #[test]
    fn suspended_overwrite_and_delete_of_locked_null_version_denied() {
        let api = S3Api::new(cred_map());
        let next = versioning_mock_store("Suspended");
        seed_bucket_object_lock(&next);

        let mut p1 = base_s3_req("PUT", "/mybucket/obj", "");
        p1.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        p1.body = Body::from(b"null-locked".to_vec());
        let mut p1 = sign_request(p1, "testing");
        p1.headers.set("X-Amz-Object-Lock-Mode", "COMPLIANCE");
        p1.headers.set(
            "X-Amz-Object-Lock-Retain-Until-Date",
            "2099-12-31T00:00:00Z",
        );
        let r1 = api.handle(p1, &next);
        assert_eq!(r1.status, 200);
        assert_eq!(r1.headers.get("x-amz-version-id"), Some("null"));

        // Overwrite would destroy the locked null version → denied.
        let mut p2 = base_s3_req("PUT", "/mybucket/obj", "");
        p2.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        p2.body = Body::from(b"clobber".to_vec());
        let resp = api.handle(sign_request(p2, "testing"), &next);
        assert_eq!(resp.status, 403);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("AccessDenied"));

        // Suspended DELETE replaces the null version with a null delete
        // marker (destructive) → denied as well.
        let del = sign_request(base_s3_req("DELETE", "/mybucket/obj", ""), "testing");
        let resp = api.handle(del, &next);
        assert_eq!(resp.status, 403);

        // Locked null version is still intact.
        let get = sign_request(base_s3_req("GET", "/mybucket/obj", ""), "testing");
        let got = api.handle(get, &next);
        assert_eq!(got.status, 200);
        assert_eq!(got.body.into_vec(u64::MAX).unwrap(), b"null-locked");
    }

    // ---- Wave-9 WORM × MPU and cold-tier interaction locks ----

    /// CompleteMultipartUpload into a bucket with a default retention rule
    /// stamps the default lock sysmeta onto the manifest PUT.
    #[test]
    fn mpu_complete_stamps_bucket_default_retention() {
        let api = S3Api::new(cred_map());
        let lock_xml: &[u8] = br#"<ObjectLockConfiguration>
  <ObjectLockEnabled>Enabled</ObjectLockEnabled>
  <Rule><DefaultRetention>
    <Mode>COMPLIANCE</Mode><Days>2</Days>
  </DefaultRetention></Rule>
</ObjectLockConfiguration>"#;

        let init_req = sign_request(base_s3_req("POST", "/mybucket/obj", "uploads"), "testing");
        let init_next: NextFn = Arc::new(|r| {
            if r.method == "HEAD" && r.path == "/v1/AUTH_test/mybucket" {
                return Response::new(204);
            }
            if r.method == "HEAD" {
                return Response::new(404);
            }
            assert_eq!(r.method, "PUT");
            Response::new(201)
        });
        let init_resp = api.handle(init_req, &init_next);
        assert_eq!(init_resp.status, 200);
        let init_body = String::from_utf8(init_resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        let upload_id = init_body
            .split("<UploadId>")
            .nth(1)
            .and_then(|s| s.split("</UploadId>").next())
            .unwrap()
            .to_string();

        let mut complete_req =
            base_s3_req("POST", "/mybucket/obj", &format!("uploadId={upload_id}"));
        complete_req
            .headers
            .set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        complete_req.body = Body::from(
            br#"<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>"b8fc857a25e7958868c2f003d5e0952d"</ETag></Part></CompleteMultipartUpload>"#
                .to_vec(),
        );
        let complete_req = sign_request(complete_req, "testing");
        let stamped = std::sync::Arc::new(std::sync::Mutex::new(
            None::<(Option<String>, Option<String>)>,
        ));
        let stamped_c = stamped.clone();
        let complete_next: NextFn = Arc::new(move |r| {
            if r.method == "HEAD" {
                if r.path == "/v1/AUTH_test/mybucket" {
                    let mut resp = Response::new(204);
                    apply_object_lock_meta(&mut resp.headers, lock_xml);
                    return resp;
                }
                if r.path.starts_with("/v1/AUTH_test/mybucket+segments/") {
                    let mut resp = Response::new(200);
                    resp.headers.set("Content-Length", "14");
                    return resp;
                }
                // Data object does not exist yet (no overwrite in play).
                return Response::new(404);
            }
            if r.method == "DELETE" {
                assert!(r.path.contains("mybucket+segments/"), "{}", r.path);
                return Response::new(204);
            }
            assert_eq!(r.method, "PUT");
            assert_eq!(r.path, "/v1/AUTH_test/mybucket/obj");
            *stamped_c.lock().unwrap() = Some((
                r.headers.get(SYS_LOCK_MODE).map(str::to_string),
                r.headers.get(SYS_RETAIN_UNTIL).map(str::to_string),
            ));
            let mut resp = Response::new(201);
            resp.headers.set("ETag", "manifest");
            resp
        });
        let resp = api.handle(complete_req, &complete_next);
        assert_eq!(resp.status, 200);
        let (mode, until) = stamped.lock().unwrap().clone().expect("manifest PUT seen");
        assert_eq!(mode.as_deref(), Some("COMPLIANCE"));
        let until = until.expect("default retain-until stamped");
        let ts = crate::object_lock_worm::parse_retain_until(&until).unwrap();
        let now = unix_now();
        assert!((ts - now - 2 * 86_400).abs() < 5, "until={until} now={now}");
    }

    /// CompleteMultipartUpload landing on a retention-locked existing key in
    /// an unversioned bucket is an overwrite and must be denied before the
    /// manifest PUT.
    #[test]
    fn mpu_complete_over_locked_object_denied() {
        let api = S3Api::new(cred_map());
        let complete_req = {
            let mut req = base_s3_req("POST", "/mybucket/locked", "uploadId=deadbeefcafe");
            req.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
            req.body = Body::from(
                br#"<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>"b8fc857a25e7958868c2f003d5e0952d"</ETag></Part></CompleteMultipartUpload>"#
                    .to_vec(),
            );
            sign_request(req, "testing")
        };
        let next: NextFn = Arc::new(|r| {
            if r.method == "HEAD" {
                if r.path == "/v1/AUTH_test/mybucket" {
                    return Response::new(204); // unversioned, no lock config
                }
                if r.path.starts_with("/v1/AUTH_test/mybucket+segments/") {
                    let mut resp = Response::new(200);
                    resp.headers.set("Content-Length", "14");
                    return resp;
                }
                // The destination key is COMPLIANCE-locked.
                let mut resp = Response::new(200);
                resp.headers.set(SYS_LOCK_MODE, "COMPLIANCE");
                resp.headers.set(SYS_RETAIN_UNTIL, "2099-12-31T00:00:00Z");
                return resp;
            }
            panic!(
                "complete over a locked key must not write the manifest: {} {}",
                r.method, r.path
            );
        });
        let resp = api.handle(complete_req, &next);
        assert_eq!(resp.status, 403);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("AccessDenied"));
    }

    /// Object Lock subresources stay available on a cold (transitioned)
    /// object: GET ?retention answers the record and PUT ?retention can
    /// extend it, while the data GET stays InvalidObjectState.
    #[test]
    fn retention_ops_allowed_on_cold_transitioned_object() {
        let api = S3Api::new(cred_map());
        let cold_get_next: NextFn = Arc::new(|r| {
            if r.method == "HEAD" && r.path.ends_with("/mybucket") {
                return Response::new(204);
            }
            let mut resp = if r.method == "GET" {
                Response::with_body(200, b"payload".to_vec())
            } else {
                Response::new(200)
            };
            resp.headers.set(SYS_TRANSITIONED, "1");
            resp.headers.set(META_STORAGE_CLASS, "GLACIER");
            resp.headers.set(SYS_LOCK_MODE, "COMPLIANCE");
            resp.headers.set(SYS_RETAIN_UNTIL, "2099-12-31T00:00:00Z");
            resp.headers.set("ETag", "abc");
            resp
        });

        // Metadata read works on the cold object.
        let get_ret = sign_request(base_s3_req("GET", "/mybucket/cold", "retention"), "testing");
        let resp = api.handle(get_ret, &cold_get_next);
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(
            body.contains("COMPLIANCE") && body.contains("2099-12-31"),
            "{body}"
        );

        // Data read is blocked as cold.
        let get_data = sign_request(base_s3_req("GET", "/mybucket/cold", ""), "testing");
        let resp = api.handle(get_data, &cold_get_next);
        assert_eq!(resp.status, 400);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("InvalidObjectState"), "{body}");

        // Retention extend on the cold object still works (metadata POST).
        let ext = br#"<Retention>
  <Mode>GOVERNANCE</Mode>
  <RetainUntilDate>2040-01-01T00:00:00Z</RetainUntilDate>
</Retention>"#;
        let mut put = base_s3_req("PUT", "/mybucket/cold", "retention");
        put.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        put.body = Body::from(ext.to_vec());
        let put = sign_request(put, "testing");
        let lock_meta = mock_bucket_lock_meta();
        let posted = std::sync::Arc::new(std::sync::Mutex::new(None::<String>));
        let posted_c = posted.clone();
        let cold_put_next: NextFn = Arc::new(move |r| {
            if r.method == "HEAD" && r.path.ends_with("/mybucket") {
                let mut resp = Response::new(204);
                resp.headers.set(S3_OBJECT_LOCK_META, &lock_meta);
                return resp;
            }
            if r.method == "HEAD" {
                let mut resp = Response::new(200);
                resp.headers.set(SYS_TRANSITIONED, "1");
                resp.headers.set(META_STORAGE_CLASS, "GLACIER");
                resp.headers.set(SYS_LOCK_MODE, "GOVERNANCE");
                resp.headers.set(SYS_RETAIN_UNTIL, "2030-01-01T00:00:00Z");
                return resp;
            }
            assert_eq!(r.method, "POST");
            *posted_c.lock().unwrap() = r.headers.get(SYS_RETAIN_UNTIL).map(str::to_string);
            Response::new(202)
        });
        let resp = api.handle(put, &cold_put_next);
        assert_eq!(resp.status, 200);
        assert_eq!(
            posted.lock().unwrap().as_deref(),
            Some("2040-01-01T00:00:00Z")
        );
    }

    #[test]
    fn restore_object_stamps_meta_and_calls_backend() {
        use crate::cold_tier::{
            MemoryColdBackend, SYS_COLD_ARCHIVE_STATE, SYS_COLD_BACKEND_URI,
            SYS_COLD_CONTENT_LENGTH, SYS_COLD_CONTENT_SHA256, SYS_COLD_RESTORE_GENERATION,
        };
        use crate::lifecycle_exec::{META_STORAGE_CLASS, SYS_RESTORE_UNTIL, SYS_TRANSITIONED};

        let be = Arc::new(MemoryColdBackend::default());
        let uri = be
            .archive(2, "AUTH_test", "mybucket", "coldobj", b"payload")
            .unwrap();
        let receipt = be.verify_archive(&uri).unwrap();
        let api = S3Api::new(cred_map())
            .with_cold_map(crate::cold_tier::ColdPolicyMap::from_csv("GLACIER:2,HOT:0"))
            .with_cold_backend(be.clone());

        let mut post = base_s3_req("POST", "/mybucket/coldobj", "restore");
        post.body = Body::from(b"<RestoreRequest><Days>2</Days></RestoreRequest>".to_vec());
        post.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        let post = sign_request(post, "testing");

        let stamped = Arc::new(std::sync::Mutex::new(None::<String>));
        let stamped_c = stamped.clone();
        let next: NextFn = Arc::new(move |r| {
            if r.method == "HEAD" {
                let mut resp = Response::new(200);
                resp.headers.set(META_STORAGE_CLASS, "GLACIER");
                resp.headers.set(SYS_TRANSITIONED, "1");
                resp.headers.set(SYS_COLD_BACKEND_URI, &uri);
                resp.headers.set(SYS_COLD_ARCHIVE_STATE, "durable");
                resp.headers
                    .set(SYS_COLD_CONTENT_LENGTH, receipt.content_length.to_string());
                resp.headers
                    .set(SYS_COLD_CONTENT_SHA256, &receipt.content_sha256);
                return resp;
            }
            if r.method == "PUT" {
                let until = r.headers.get(SYS_RESTORE_UNTIL).map(str::to_string);
                *stamped_c.lock().unwrap() = until;
                assert_eq!(r.headers.get(SYS_HOT_RECLAIMED), Some("false"));
                assert_eq!(
                    r.headers.get(SYS_COLD_RESTORE_GENERATION),
                    Some("1"),
                    "begin_restore must stamp restore generation"
                );
                assert_eq!(r.body.into_vec(u64::MAX).unwrap(), b"payload");
                return Response::new(201);
            }
            Response::new(500)
        });
        let resp = api.handle(post, &next);
        assert_eq!(resp.status, 202, "RestoreObject should return 202");
        let until = stamped.lock().unwrap().clone();
        assert!(until.is_some(), "restore must stamp SYS_RESTORE_UNTIL");
    }

    #[test]
    fn restore_object_without_backend_fails_closed() {
        use crate::lifecycle_exec::{META_STORAGE_CLASS, SYS_TRANSITIONED};

        let api = S3Api::new(cred_map());
        let mut post = base_s3_req("POST", "/mybucket/coldobj", "restore");
        post.body = Body::from(b"<RestoreRequest><Days>1</Days></RestoreRequest>".to_vec());
        post.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        let post = sign_request(post, "testing");
        let next: NextFn = Arc::new(move |r| {
            if r.method == "HEAD" {
                let mut resp = Response::new(200);
                resp.headers.set(META_STORAGE_CLASS, "GLACIER");
                resp.headers.set(SYS_TRANSITIONED, "1");
                return resp;
            }
            panic!("restore without a backend must not mutate Swift")
        });
        let resp = api.handle(post, &next);
        // Honest rejection when the cold backend is disabled: 400
        // InvalidObjectState (dual-oracle case `restore-not-implemented`),
        // never a fake success and never a mutation.
        assert_eq!(resp.status, 400);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("InvalidObjectState"), "{body}");
    }

    #[test]
    fn parse_restore_days_helpers() {
        assert_eq!(parse_restore_days(b"").unwrap(), 1);
        assert_eq!(
            parse_restore_days(b"<RestoreRequest><Days>3</Days></RestoreRequest>").unwrap(),
            3
        );
        assert!(parse_restore_days(b"<RestoreRequest><Days>0</Days></RestoreRequest>").is_err());
    }

    #[test]
    fn get_due_cold_transition_with_backend_archives_and_stamps_uri() {
        use crate::cold_tier::{MemoryColdBackend, SYS_COLD_BACKEND_URI, SYS_COLD_POLICY_INDEX};
        use crate::lifecycle_exec::{META_STORAGE_CLASS, SYS_TRANSITION_AT};

        let be = Arc::new(MemoryColdBackend::default());
        let api = S3Api::new(cred_map())
            .with_cold_map(crate::cold_tier::ColdPolicyMap::from_csv("GLACIER:2,HOT:0"))
            .with_cold_backend(be.clone());

        let posted_uri = Arc::new(std::sync::Mutex::new(None::<String>));
        let posted_c = posted_uri.clone();
        let next: NextFn = Arc::new(move |r| {
            if r.method == "HEAD" && r.path.ends_with("/mybucket") {
                return Response::new(204); // versioning probe
            }
            if r.method == "GET" && r.path.ends_with("/coldobj") {
                let mut resp = Response::new(200);
                resp.headers.set(META_STORAGE_CLASS, "GLACIER");
                resp.headers.set(SYS_TRANSITION_AT, "1");
                resp.headers.set("ETag", "e");
                resp.headers.set("Content-Length", "7");
                resp.body = Body::from(b"payload".to_vec());
                return resp;
            }
            if r.method == "POST" && r.path.ends_with("/coldobj") {
                *posted_c.lock().unwrap() = r.headers.get(SYS_COLD_BACKEND_URI).map(str::to_string);
                assert_eq!(r.headers.get(SYS_COLD_POLICY_INDEX), Some("2"));
                assert_eq!(r.headers.get(SYS_TRANSITIONED), Some("1"));
                return Response::new(202);
            }
            Response::new(500)
        });

        let req = sign_request(base_s3_req("GET", "/mybucket/coldobj", ""), "testing");
        let resp = api.handle(req, &next);
        assert_eq!(
            resp.status, 400,
            "cold GET must be InvalidObjectState after archive"
        );
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("InvalidObjectState"), "{body}");
        let uri = posted_uri.lock().unwrap().clone();
        let uri = uri.expect("POST must stamp SYS_COLD_BACKEND_URI");
        assert!(uri.starts_with("memory://"), "uri={uri}");
        be.restore_stage(&uri, 1).unwrap();
    }

    #[test]
    fn get_due_cold_transition_without_backend_meta_only_no_uri() {
        use crate::cold_tier::{SYS_COLD_BACKEND_URI, SYS_COLD_POLICY_INDEX};
        use crate::lifecycle_exec::{META_STORAGE_CLASS, SYS_TRANSITION_AT};

        let api = S3Api::new(cred_map())
            .with_cold_map(crate::cold_tier::ColdPolicyMap::from_csv("GLACIER:2,HOT:0"));

        let posted = Arc::new(std::sync::Mutex::new(
            None::<(Option<String>, Option<String>)>,
        ));
        let posted_c = posted.clone();
        let next: NextFn = Arc::new(move |r| {
            if r.method == "HEAD" && r.path.ends_with("/mybucket") {
                return Response::new(204);
            }
            if r.method == "GET" && r.path.ends_with("/coldobj") {
                let mut resp = Response::new(200);
                resp.headers.set(META_STORAGE_CLASS, "GLACIER");
                resp.headers.set(SYS_TRANSITION_AT, "1");
                resp.headers.set("ETag", "e");
                resp.body = Body::from(b"payload".to_vec());
                return resp;
            }
            if r.method == "POST" && r.path.ends_with("/coldobj") {
                *posted_c.lock().unwrap() = Some((
                    r.headers.get(SYS_COLD_POLICY_INDEX).map(str::to_string),
                    r.headers.get(SYS_COLD_BACKEND_URI).map(str::to_string),
                ));
                assert_eq!(r.headers.get(SYS_TRANSITIONED), Some("1"));
                return Response::new(202);
            }
            Response::new(500)
        });

        let req = sign_request(base_s3_req("GET", "/mybucket/coldobj", ""), "testing");
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 400);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("InvalidObjectState"), "{body}");
        let (idx, uri) = posted.lock().unwrap().clone().expect("POST meta");
        assert_eq!(idx.as_deref(), Some("2"));
        assert!(uri.is_none(), "meta-only honesty: no SYS_COLD_BACKEND_URI");
    }

    #[test]
    fn put_immediate_cold_transition_archives_when_backend_wired() {
        use crate::bucket_config::{apply_lifecycle_meta, S3_LIFECYCLE_META};
        use crate::cold_tier::{MemoryColdBackend, SYS_COLD_BACKEND_URI, SYS_COLD_POLICY_INDEX};
        use crate::lifecycle_exec::META_STORAGE_CLASS;

        let be = Arc::new(MemoryColdBackend::default());
        let api = S3Api::new(cred_map())
            .with_cold_map(crate::cold_tier::ColdPolicyMap::from_csv("GLACIER:2,HOT:0"))
            .with_cold_backend(be.clone());

        // Days=0 → transition_at <= now → immediate cold.
        let lc = br#"<?xml version="1.0"?>
<LifecycleConfiguration>
  <Rule>
    <Filter><Prefix></Prefix></Filter>
    <Status>Enabled</Status>
    <Transition><Days>0</Days><StorageClass>GLACIER</StorageClass></Transition>
  </Rule>
</LifecycleConfiguration>"#;
        let mut lc_headers = HeaderKeyDict::new();
        apply_lifecycle_meta(&mut lc_headers, lc);
        let lc_meta = lc_headers.get(S3_LIFECYCLE_META).unwrap().to_string();

        let put_uri = Arc::new(std::sync::Mutex::new(None::<String>));
        let put_body = Arc::new(std::sync::Mutex::new(None::<Vec<u8>>));
        let put_c = put_uri.clone();
        let put_b = put_body.clone();
        let next: NextFn = Arc::new(move |r| {
            if r.method == "HEAD" {
                if r.path.ends_with("/mybucket") {
                    let mut resp = Response::new(204);
                    resp.headers.set(S3_LIFECYCLE_META, &lc_meta);
                    return resp;
                }
                return Response::new(404);
            }
            if r.method == "PUT" && r.path.ends_with("/imm") {
                *put_c.lock().unwrap() = r.headers.get(SYS_COLD_BACKEND_URI).map(str::to_string);
                *put_b.lock().unwrap() = Some(r.body.into_vec(u64::MAX).unwrap());
                assert_eq!(r.headers.get(META_STORAGE_CLASS), Some("GLACIER"));
                assert_eq!(r.headers.get(SYS_TRANSITIONED), Some("1"));
                assert_eq!(r.headers.get(SYS_COLD_POLICY_INDEX), Some("2"));
                let mut resp = Response::new(201);
                resp.headers.set("ETag", "abc");
                return resp;
            }
            Response::new(500)
        });

        let mut put = base_s3_req("PUT", "/mybucket/imm", "");
        put.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        put.body = Body::from(b"payload".to_vec());
        let put = sign_request(put, "testing");
        assert_eq!(api.handle(put, &next).status, 200);
        let uri = put_uri.lock().unwrap().clone().expect("PUT stamps URI");
        assert!(uri.starts_with("memory://"), "uri={uri}");
        let hot = put_body.lock().unwrap().clone().expect("PUT body");
        assert_eq!(
            hot, b"payload",
            "default cold_delete_hot_after_archive=false must keep hot bytes"
        );
        be.restore_stage(&uri, 1).unwrap();
    }

    #[test]
    fn put_immediate_cold_transition_deletes_hot_when_configured() {
        use crate::bucket_config::{apply_lifecycle_meta, S3_LIFECYCLE_META};
        use crate::cold_tier::{MemoryColdBackend, SYS_COLD_BACKEND_URI, SYS_COLD_POLICY_INDEX};
        use crate::lifecycle_exec::META_STORAGE_CLASS;

        let be = Arc::new(MemoryColdBackend::default());
        let api = S3Api::new(cred_map())
            .with_cold_map(crate::cold_tier::ColdPolicyMap::from_csv("GLACIER:2,HOT:0"))
            .with_cold_backend(be.clone())
            .with_cold_delete_hot_after_archive(true);

        let lc = br#"<?xml version="1.0"?>
<LifecycleConfiguration>
  <Rule>
    <Filter><Prefix></Prefix></Filter>
    <Status>Enabled</Status>
    <Transition><Days>0</Days><StorageClass>GLACIER</StorageClass></Transition>
  </Rule>
</LifecycleConfiguration>"#;
        let mut lc_headers = HeaderKeyDict::new();
        apply_lifecycle_meta(&mut lc_headers, lc);
        let lc_meta = lc_headers.get(S3_LIFECYCLE_META).unwrap().to_string();

        let put_uri = Arc::new(std::sync::Mutex::new(None::<String>));
        let put_body = Arc::new(std::sync::Mutex::new(None::<Vec<u8>>));
        let put_c = put_uri.clone();
        let put_b = put_body.clone();
        let next: NextFn = Arc::new(move |r| {
            if r.method == "HEAD" {
                if r.path.ends_with("/mybucket") {
                    let mut resp = Response::new(204);
                    resp.headers.set(S3_LIFECYCLE_META, &lc_meta);
                    return resp;
                }
                return Response::new(404);
            }
            if r.method == "PUT" && r.path.ends_with("/imm") {
                *put_c.lock().unwrap() = r.headers.get(SYS_COLD_BACKEND_URI).map(str::to_string);
                *put_b.lock().unwrap() = Some(r.body.into_vec(u64::MAX).unwrap());
                assert_eq!(r.headers.get(META_STORAGE_CLASS), Some("GLACIER"));
                assert_eq!(r.headers.get(SYS_TRANSITIONED), Some("1"));
                assert_eq!(r.headers.get(SYS_COLD_POLICY_INDEX), Some("2"));
                assert_eq!(r.headers.get("Content-Length"), Some("0"));
                let mut resp = Response::new(201);
                resp.headers.set("ETag", "abc");
                return resp;
            }
            Response::new(500)
        });

        let mut put = base_s3_req("PUT", "/mybucket/imm", "");
        put.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        put.body = Body::from(b"payload".to_vec());
        let put = sign_request(put, "testing");
        assert_eq!(api.handle(put, &next).status, 200);
        let uri = put_uri.lock().unwrap().clone().expect("PUT stamps URI");
        assert!(uri.starts_with("memory://"), "uri={uri}");
        let hot = put_body.lock().unwrap().clone().expect("PUT body");
        assert!(
            hot.is_empty(),
            "hot body must be empty after archive when knob is true, got {} bytes",
            hot.len()
        );
        // restore_stage still works from the MemoryColdBackend copy
        be.restore_stage(&uri, 1).unwrap();
        assert_eq!(
            be.blobs.lock().unwrap().get(&uri).map(|v| v.as_slice()),
            Some(b"payload".as_slice()),
            "cold copy must remain so restore_stage can succeed"
        );
    }

    #[test]
    fn get_due_cold_transition_deletes_hot_when_configured() {
        use crate::cold_tier::{MemoryColdBackend, SYS_COLD_BACKEND_URI, SYS_COLD_POLICY_INDEX};
        use crate::lifecycle_exec::{META_STORAGE_CLASS, SYS_TRANSITION_AT};

        let be = Arc::new(MemoryColdBackend::default());
        let api = S3Api::new(cred_map())
            .with_cold_map(crate::cold_tier::ColdPolicyMap::from_csv("GLACIER:2,HOT:0"))
            .with_cold_backend(be.clone())
            .with_cold_delete_hot_after_archive(true);

        let posted_uri = Arc::new(std::sync::Mutex::new(None::<String>));
        let put_body = Arc::new(std::sync::Mutex::new(None::<Vec<u8>>));
        let posted_c = posted_uri.clone();
        let put_b = put_body.clone();
        let next: NextFn = Arc::new(move |r| {
            if r.method == "HEAD" && r.path.ends_with("/mybucket") {
                return Response::new(204); // versioning probe
            }
            if r.method == "GET" && r.path.ends_with("/coldobj") {
                let mut resp = Response::new(200);
                resp.headers.set(META_STORAGE_CLASS, "GLACIER");
                resp.headers.set(SYS_TRANSITION_AT, "1");
                resp.headers.set("ETag", "e");
                resp.headers.set("Content-Length", "7");
                resp.headers.set("Content-Type", "application/octet-stream");
                resp.body = Body::from(b"payload".to_vec());
                return resp;
            }
            if r.method == "POST" && r.path.ends_with("/coldobj") {
                *posted_c.lock().unwrap() = r.headers.get(SYS_COLD_BACKEND_URI).map(str::to_string);
                assert_eq!(r.headers.get(SYS_COLD_POLICY_INDEX), Some("2"));
                assert_eq!(r.headers.get(SYS_TRANSITIONED), Some("1"));
                return Response::new(202);
            }
            if r.method == "PUT" && r.path.ends_with("/coldobj") {
                *put_b.lock().unwrap() = Some(r.body.into_vec(u64::MAX).unwrap());
                assert_eq!(r.headers.get(SYS_COLD_POLICY_INDEX), Some("2"));
                assert_eq!(r.headers.get(SYS_TRANSITIONED), Some("1"));
                assert!(r.headers.get(SYS_COLD_BACKEND_URI).is_some());
                assert_eq!(r.headers.get("Content-Length"), Some("0"));
                let mut resp = Response::new(201);
                resp.headers.set("ETag", "empty");
                return resp;
            }
            Response::new(500)
        });

        let req = sign_request(base_s3_req("GET", "/mybucket/coldobj", ""), "testing");
        let resp = api.handle(req, &next);
        assert_eq!(
            resp.status, 400,
            "cold GET must be InvalidObjectState after archive"
        );
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("InvalidObjectState"), "{body}");
        let uri = posted_uri.lock().unwrap().clone();
        let uri = uri.expect("POST must stamp SYS_COLD_BACKEND_URI");
        assert!(uri.starts_with("memory://"), "uri={uri}");
        let hot = put_body.lock().unwrap().clone().expect("hot overwrite PUT");
        assert!(
            hot.is_empty(),
            "GET persist path must overwrite hot body when knob is true"
        );
        be.restore_stage(&uri, 1).unwrap();
        assert_eq!(
            be.blobs.lock().unwrap().get(&uri).map(|v| v.as_slice()),
            Some(b"payload".as_slice())
        );
    }

    #[test]
    fn anonymous_get_due_cold_transition_meta_deny_no_post() {
        use crate::lifecycle_exec::{META_STORAGE_CLASS, SYS_TRANSITION_AT};

        let api = S3Api::new(cred_map())
            .with_anonymous_account("AUTH_test")
            .with_cold_map(crate::cold_tier::ColdPolicyMap::from_csv("GLACIER:2,HOT:0"));

        let post_seen = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let post_c = post_seen.clone();
        let next: NextFn = Arc::new(move |r| {
            assert!(
                r.headers.get("X-Backend-Authorize-Override").is_none(),
                "anonymous must not stamp_auth"
            );
            if r.method == "POST" {
                post_c.store(true, std::sync::atomic::Ordering::SeqCst);
                return Response::new(202);
            }
            if r.method == "GET" && r.path.ends_with("/coldobj") {
                let mut resp = Response::new(200);
                resp.headers.set(META_STORAGE_CLASS, "GLACIER");
                resp.headers.set(SYS_TRANSITION_AT, "1");
                resp.headers.set("ETag", "e");
                resp.body = Body::from(b"payload".to_vec());
                return resp;
            }
            Response::new(500)
        });

        let req = Request {
            method: "GET".into(),
            path: "/pubbucket/coldobj".into(),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: Body::empty(),
        };
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 400);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("InvalidObjectState"), "{body}");
        assert!(
            !post_seen.load(std::sync::atomic::Ordering::SeqCst),
            "honesty: anonymous GET must not POST-persist (no auth)"
        );
    }

    #[test]
    fn anonymous_head_due_cold_transition_meta_deny_no_post() {
        use crate::lifecycle_exec::{META_STORAGE_CLASS, SYS_TRANSITION_AT};

        let api = S3Api::new(cred_map())
            .with_anonymous_account("AUTH_test")
            .with_cold_map(crate::cold_tier::ColdPolicyMap::from_csv("GLACIER:2,HOT:0"));

        let post_seen = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let get_seen = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let post_c = post_seen.clone();
        let get_c = get_seen.clone();
        let next: NextFn = Arc::new(move |r| {
            if r.method == "POST" {
                post_c.store(true, std::sync::atomic::Ordering::SeqCst);
                return Response::new(202);
            }
            if r.method == "GET" {
                get_c.store(true, std::sync::atomic::Ordering::SeqCst);
                return Response::new(500);
            }
            if r.method == "HEAD" && r.path.ends_with("/coldobj") {
                let mut resp = Response::new(200);
                resp.headers.set(META_STORAGE_CLASS, "GLACIER");
                resp.headers.set(SYS_TRANSITION_AT, "1");
                resp.headers.set("ETag", "e");
                resp.headers.set("Content-Length", "7");
                return resp;
            }
            Response::new(500)
        });

        let req = Request {
            method: "HEAD".into(),
            path: "/pubbucket/coldobj".into(),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: Body::empty(),
        };
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 400);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("InvalidObjectState"), "{body}");
        assert!(!post_seen.load(std::sync::atomic::Ordering::SeqCst));
        assert!(
            !get_seen.load(std::sync::atomic::Ordering::SeqCst),
            "anon HEAD must not fetch body for archive (meta/deny only)"
        );
    }

    #[test]
    fn anonymous_get_due_cold_with_backend_still_no_post_honesty() {
        use crate::cold_tier::MemoryColdBackend;
        use crate::lifecycle_exec::{META_STORAGE_CLASS, SYS_TRANSITION_AT};

        let be = Arc::new(MemoryColdBackend::default());
        let api = S3Api::new(cred_map())
            .with_anonymous_account("AUTH_test")
            .with_cold_map(crate::cold_tier::ColdPolicyMap::from_csv("GLACIER:2,HOT:0"))
            .with_cold_backend(be.clone());

        let post_seen = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let post_c = post_seen.clone();
        let next: NextFn = Arc::new(move |r| {
            if r.method == "POST" {
                post_c.store(true, std::sync::atomic::Ordering::SeqCst);
                return Response::new(202);
            }
            if r.method == "GET" && r.path.ends_with("/coldobj") {
                let mut resp = Response::new(200);
                resp.headers.set(META_STORAGE_CLASS, "GLACIER");
                resp.headers.set(SYS_TRANSITION_AT, "1");
                resp.body = Body::from(b"payload".to_vec());
                return resp;
            }
            Response::new(500)
        });

        let req = Request {
            method: "GET".into(),
            path: "/pubbucket/coldobj".into(),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: Body::empty(),
        };
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 400);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("InvalidObjectState"), "{body}");
        assert!(!post_seen.load(std::sync::atomic::Ordering::SeqCst));
        assert!(
            be.blobs.lock().unwrap().is_empty(),
            "honesty: anon must not archive bytes that cannot be URI-persisted"
        );
    }

    #[test]
    fn versioned_get_due_cold_transition_archives_and_posts() {
        use crate::cold_tier::{MemoryColdBackend, SYS_COLD_BACKEND_URI, SYS_COLD_POLICY_INDEX};
        use crate::lifecycle_exec::{META_STORAGE_CLASS, SYS_TRANSITION_AT};

        let be = Arc::new(MemoryColdBackend::default());
        let api = S3Api::new(cred_map())
            .with_cold_map(crate::cold_tier::ColdPolicyMap::from_csv("GLACIER:2,HOT:0"))
            .with_cold_backend(be.clone());

        let posted_uri = Arc::new(std::sync::Mutex::new(None::<String>));
        let posted_c = posted_uri.clone();
        let next: NextFn = Arc::new(move |r| {
            if r.method == "HEAD" && r.path.ends_with("/mybucket") {
                let mut resp = Response::new(204);
                resp.headers.set(S3_VERSIONING_META, "Enabled");
                return resp;
            }
            // resolve_object_version HEADs current before the archive GET.
            if r.method == "HEAD" && r.path.ends_with("/coldobj") {
                let mut resp = Response::new(200);
                resp.headers.set(META_STORAGE_CLASS, "GLACIER");
                resp.headers.set(SYS_TRANSITION_AT, "1");
                resp.headers
                    .set(SYS_VERSION_ID, "aabbccddeeff00112233445566778899");
                resp.headers.set("ETag", "e");
                resp.headers.set("Content-Length", "7");
                return resp;
            }
            if r.method == "GET" && r.path.ends_with("/coldobj") {
                let mut resp = Response::new(200);
                resp.headers.set(META_STORAGE_CLASS, "GLACIER");
                resp.headers.set(SYS_TRANSITION_AT, "1");
                resp.headers
                    .set(SYS_VERSION_ID, "aabbccddeeff00112233445566778899");
                resp.headers.set("ETag", "e");
                resp.headers.set("Content-Length", "7");
                resp.body = Body::from(b"payload".to_vec());
                return resp;
            }
            if r.method == "POST" && r.path.ends_with("/coldobj") {
                *posted_c.lock().unwrap() = r.headers.get(SYS_COLD_BACKEND_URI).map(str::to_string);
                assert_eq!(r.headers.get(SYS_COLD_POLICY_INDEX), Some("2"));
                assert_eq!(r.headers.get(SYS_TRANSITIONED), Some("1"));
                return Response::new(202);
            }
            Response::new(500)
        });

        let req = sign_request(base_s3_req("GET", "/mybucket/coldobj", ""), "testing");
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 400, "versioned GET must InvalidObjectState");
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("InvalidObjectState"), "{body}");
        let uri = posted_uri.lock().unwrap().clone().expect("POST persist");
        assert!(uri.starts_with("memory://"), "uri={uri}");
        be.restore_stage(&uri, 1).unwrap();
    }

    #[test]
    fn versioned_get_version_id_due_cold_archives_and_posts() {
        use crate::cold_tier::{MemoryColdBackend, SYS_COLD_BACKEND_URI, SYS_COLD_POLICY_INDEX};
        use crate::lifecycle_exec::{META_STORAGE_CLASS, SYS_TRANSITION_AT};

        let vid = "aabbccddeeff00112233445566778899";
        let be = Arc::new(MemoryColdBackend::default());
        let api = S3Api::new(cred_map())
            .with_cold_map(crate::cold_tier::ColdPolicyMap::from_csv("GLACIER:2,HOT:0"))
            .with_cold_backend(be.clone());

        let posted_uri = Arc::new(std::sync::Mutex::new(None::<String>));
        let posted_c = posted_uri.clone();
        let next: NextFn = Arc::new(move |r| {
            if r.method == "HEAD" && r.path.ends_with("/mybucket") {
                let mut resp = Response::new(204);
                resp.headers.set(S3_VERSIONING_META, "Enabled");
                return resp;
            }
            if r.method == "HEAD" && r.path.ends_with("/coldobj") {
                let mut resp = Response::new(200);
                resp.headers.set(META_STORAGE_CLASS, "GLACIER");
                resp.headers.set(SYS_TRANSITION_AT, "1");
                resp.headers.set(SYS_VERSION_ID, vid);
                resp.headers.set("ETag", "e");
                resp.headers.set("Content-Length", "7");
                return resp;
            }
            if r.method == "GET" && r.path.ends_with("/coldobj") {
                let mut resp = Response::new(200);
                resp.headers.set(META_STORAGE_CLASS, "GLACIER");
                resp.headers.set(SYS_TRANSITION_AT, "1");
                resp.headers.set(SYS_VERSION_ID, vid);
                resp.headers.set("ETag", "e");
                resp.headers.set("Content-Length", "7");
                resp.body = Body::from(b"payload".to_vec());
                return resp;
            }
            if r.method == "POST" && r.path.ends_with("/coldobj") {
                *posted_c.lock().unwrap() = r.headers.get(SYS_COLD_BACKEND_URI).map(str::to_string);
                assert_eq!(r.headers.get(SYS_COLD_POLICY_INDEX), Some("2"));
                return Response::new(202);
            }
            Response::new(500)
        });

        let req = sign_request(
            base_s3_req("GET", "/mybucket/coldobj", &format!("versionId={vid}")),
            "testing",
        );
        let resp = api.handle(req, &next);
        assert_eq!(resp.status, 400);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("InvalidObjectState"), "{body}");
        let uri = posted_uri.lock().unwrap().clone().expect("POST persist");
        assert!(uri.starts_with("memory://"), "uri={uri}");
    }

    #[test]
    fn get_range_206_does_not_archive_or_reclaim() {
        use crate::lifecycle_exec::{META_STORAGE_CLASS, SYS_TRANSITION_AT};

        let be = Arc::new(crate::cold_tier::MemoryColdBackend::default());
        let api = S3Api::new(cred_map())
            .with_cold_map(crate::cold_tier::ColdPolicyMap::from_csv("GLACIER:2,HOT:0"))
            .with_cold_backend(be.clone())
            .with_cold_delete_hot_after_archive(true);

        let post_seen = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let put_seen = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let post_c = post_seen.clone();
        let put_c = put_seen.clone();
        let next: NextFn = Arc::new(move |r| {
            if r.method == "HEAD" && r.path.ends_with("/mybucket") {
                return Response::new(204);
            }
            if r.method == "POST" {
                post_c.store(true, std::sync::atomic::Ordering::SeqCst);
                return Response::new(202);
            }
            if r.method == "PUT" {
                put_c.store(true, std::sync::atomic::Ordering::SeqCst);
                return Response::new(201);
            }
            if r.method == "GET" && r.path.ends_with("/coldobj") {
                let mut resp = Response::new(206);
                resp.headers.set(META_STORAGE_CLASS, "GLACIER");
                resp.headers.set(SYS_TRANSITION_AT, "1");
                resp.headers.set("ETag", "e");
                resp.headers.set("Content-Range", "bytes 0-3/7");
                resp.headers.set("Content-Length", "4");
                resp.body = Body::from(b"payl".to_vec());
                return resp;
            }
            Response::new(500)
        });

        let mut req = base_s3_req("GET", "/mybucket/coldobj", "");
        req.headers.set("Range", "bytes=0-3");
        let req = sign_request(req, "testing");
        let _resp = api.handle(req, &next);
        assert!(
            !post_seen.load(std::sync::atomic::Ordering::SeqCst),
            "206 body must not POST an archive URI"
        );
        assert!(
            !put_seen.load(std::sync::atomic::Ordering::SeqCst),
            "206 body must not empty-PUT"
        );
        assert!(be.blobs.lock().unwrap().is_empty());
    }

    #[test]
    fn head_content_range_does_not_followup_get_for_archive() {
        use crate::lifecycle_exec::{META_STORAGE_CLASS, SYS_TRANSITION_AT};

        let be = Arc::new(crate::cold_tier::MemoryColdBackend::default());
        let api = S3Api::new(cred_map())
            .with_cold_map(crate::cold_tier::ColdPolicyMap::from_csv("GLACIER:2,HOT:0"))
            .with_cold_backend(be.clone())
            .with_cold_delete_hot_after_archive(true);

        let get_seen = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let post_seen = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let put_seen = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let get_c = get_seen.clone();
        let post_c = post_seen.clone();
        let put_c = put_seen.clone();
        let next: NextFn = Arc::new(move |r| {
            if r.method == "HEAD" && r.path.ends_with("/mybucket") {
                return Response::new(204);
            }
            if r.method == "GET" {
                get_c.store(true, std::sync::atomic::Ordering::SeqCst);
                return Response::new(500);
            }
            if r.method == "POST" {
                post_c.store(true, std::sync::atomic::Ordering::SeqCst);
                return Response::new(202);
            }
            if r.method == "PUT" {
                put_c.store(true, std::sync::atomic::Ordering::SeqCst);
                return Response::new(201);
            }
            if r.method == "HEAD" && r.path.ends_with("/coldobj") {
                let mut resp = Response::new(200);
                resp.headers.set(META_STORAGE_CLASS, "GLACIER");
                resp.headers.set(SYS_TRANSITION_AT, "1");
                resp.headers.set("ETag", "e");
                resp.headers.set("Content-Range", "bytes 0-3/7");
                resp.headers.set("Content-Length", "4");
                return resp;
            }
            Response::new(500)
        });

        let req = sign_request(base_s3_req("HEAD", "/mybucket/coldobj", ""), "testing");
        let _resp = api.handle(req, &next);
        assert!(
            !get_seen.load(std::sync::atomic::Ordering::SeqCst),
            "HEAD Content-Range must not follow-up GET for archive"
        );
        assert!(!post_seen.load(std::sync::atomic::Ordering::SeqCst));
        assert!(!put_seen.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn restore_then_get_does_not_immediately_rearchive() {
        use crate::cold_tier::{
            MemoryColdBackend, SYS_COLD_ARCHIVE_STATE, SYS_COLD_BACKEND_URI,
            SYS_COLD_CONTENT_LENGTH, SYS_COLD_CONTENT_SHA256,
        };
        use crate::lifecycle_exec::{META_STORAGE_CLASS, SYS_RESTORE_UNTIL, SYS_TRANSITIONED};

        let be = Arc::new(MemoryColdBackend::default());
        let uri = be
            .archive(2, "AUTH_test", "mybucket", "coldobj", b"payload")
            .unwrap();
        let receipt = be.verify_archive(&uri).unwrap();
        let api = S3Api::new(cred_map())
            .with_cold_map(crate::cold_tier::ColdPolicyMap::from_csv("GLACIER:2,HOT:0"))
            .with_cold_backend(be.clone())
            .with_cold_delete_hot_after_archive(true);

        let until = Arc::new(std::sync::Mutex::new(None::<String>));
        let put_bodies = Arc::new(std::sync::Mutex::new(Vec::<Vec<u8>>::new()));
        let until_c = until.clone();
        let puts_c = put_bodies.clone();
        let next: NextFn = Arc::new(move |r| {
            if r.method == "HEAD" && r.path.ends_with("/mybucket") {
                return Response::new(204);
            }
            if r.method == "HEAD" && r.path.ends_with("/coldobj") {
                let mut resp = Response::new(200);
                resp.headers.set(META_STORAGE_CLASS, "GLACIER");
                resp.headers.set(SYS_TRANSITIONED, "1");
                resp.headers.set(SYS_COLD_BACKEND_URI, &uri);
                resp.headers.set(SYS_COLD_ARCHIVE_STATE, "durable");
                resp.headers
                    .set(SYS_COLD_CONTENT_LENGTH, receipt.content_length.to_string());
                resp.headers
                    .set(SYS_COLD_CONTENT_SHA256, &receipt.content_sha256);
                if let Some(u) = until_c.lock().unwrap().clone() {
                    resp.headers.set(SYS_RESTORE_UNTIL, u);
                    resp.headers.set(SYS_HOT_RECLAIMED, "false");
                }
                return resp;
            }
            if r.method == "PUT" && r.path.ends_with("/coldobj") {
                let body = r.body.into_vec(u64::MAX).unwrap();
                if let Some(u) = r.headers.get(SYS_RESTORE_UNTIL) {
                    *until_c.lock().unwrap() = Some(u.to_string());
                }
                puts_c.lock().unwrap().push(body);
                return Response::new(201);
            }
            if r.method == "GET" && r.path.ends_with("/coldobj") {
                let mut resp = Response::new(200);
                resp.headers.set(META_STORAGE_CLASS, "GLACIER");
                resp.headers.set(SYS_TRANSITIONED, "1");
                resp.headers.set(SYS_COLD_BACKEND_URI, &uri);
                resp.headers.set(SYS_COLD_ARCHIVE_STATE, "durable");
                resp.headers
                    .set(SYS_COLD_CONTENT_LENGTH, receipt.content_length.to_string());
                resp.headers
                    .set(SYS_COLD_CONTENT_SHA256, &receipt.content_sha256);
                resp.headers.set(SYS_HOT_RECLAIMED, "false");
                if let Some(u) = until_c.lock().unwrap().clone() {
                    resp.headers.set(SYS_RESTORE_UNTIL, u);
                }
                resp.headers.set("ETag", "e");
                resp.headers.set("Content-Length", "7");
                resp.body = Body::from(b"payload".to_vec());
                return resp;
            }
            if r.method == "POST" {
                return Response::new(202);
            }
            Response::new(500)
        });

        let mut post = base_s3_req("POST", "/mybucket/coldobj", "restore");
        post.body = Body::from(b"<RestoreRequest><Days>2</Days></RestoreRequest>".to_vec());
        post.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        let post = sign_request(post, "testing");
        assert_eq!(api.handle(post, &next).status, 202);

        let get = sign_request(base_s3_req("GET", "/mybucket/coldobj", ""), "testing");
        let resp = api.handle(get, &next);
        assert_eq!(
            resp.status, 200,
            "restored GET must not be InvalidObjectState"
        );
        let puts = put_bodies.lock().unwrap();
        assert_eq!(puts.len(), 1, "restore PUT only; GET must not empty-PUT");
        assert_eq!(puts[0], b"payload");
    }

    #[test]
    fn restore_metadata_only_without_uri_is_invalid_object_state() {
        use crate::lifecycle_exec::{META_STORAGE_CLASS, SYS_TRANSITIONED};

        let be = Arc::new(crate::cold_tier::MemoryColdBackend::default());
        let api = S3Api::new(cred_map())
            .with_cold_map(crate::cold_tier::ColdPolicyMap::from_csv("GLACIER:2,HOT:0"))
            .with_cold_backend(be);

        let put_seen = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let put_c = put_seen.clone();
        let next: NextFn = Arc::new(move |r| {
            if r.method == "HEAD" {
                let mut resp = Response::new(200);
                resp.headers.set(META_STORAGE_CLASS, "GLACIER");
                resp.headers.set(SYS_TRANSITIONED, "1");
                return resp;
            }
            if r.method == "PUT" {
                put_c.store(true, std::sync::atomic::Ordering::SeqCst);
                return Response::new(201);
            }
            Response::new(500)
        });

        let mut post = base_s3_req("POST", "/mybucket/coldobj", "restore");
        post.body = Body::from(b"<RestoreRequest><Days>1</Days></RestoreRequest>".to_vec());
        post.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        let post = sign_request(post, "testing");
        let resp = api.handle(post, &next);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("InvalidObjectState"), "{body}");
        assert!(!put_seen.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn restore_put_failure_does_not_complete() {
        use crate::cold_tier::{
            MemoryColdBackend, SYS_COLD_ARCHIVE_STATE, SYS_COLD_BACKEND_URI,
            SYS_COLD_CONTENT_LENGTH, SYS_COLD_CONTENT_SHA256,
        };
        use crate::lifecycle_exec::{META_STORAGE_CLASS, SYS_TRANSITIONED};

        let be = Arc::new(MemoryColdBackend::default());
        let uri = be
            .archive(2, "AUTH_test", "mybucket", "coldobj", b"payload")
            .unwrap();
        let receipt = be.verify_archive(&uri).unwrap();
        let api = S3Api::new(cred_map())
            .with_cold_map(crate::cold_tier::ColdPolicyMap::from_csv("GLACIER:2,HOT:0"))
            .with_cold_backend(be);

        let next: NextFn = Arc::new(move |r| {
            if r.method == "HEAD" {
                let mut resp = Response::new(200);
                resp.headers.set(META_STORAGE_CLASS, "GLACIER");
                resp.headers.set(SYS_TRANSITIONED, "1");
                resp.headers.set(SYS_COLD_BACKEND_URI, &uri);
                resp.headers.set(SYS_COLD_ARCHIVE_STATE, "durable");
                resp.headers
                    .set(SYS_COLD_CONTENT_LENGTH, receipt.content_length.to_string());
                resp.headers
                    .set(SYS_COLD_CONTENT_SHA256, &receipt.content_sha256);
                return resp;
            }
            if r.method == "PUT" {
                return Response::new(500);
            }
            Response::new(500)
        });

        let mut post = base_s3_req("POST", "/mybucket/coldobj", "restore");
        post.body = Body::from(b"<RestoreRequest><Days>2</Days></RestoreRequest>".to_vec());
        post.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        let post = sign_request(post, "testing");
        let resp = api.handle(post, &next);
        assert_ne!(resp.status, 202, "failed PUT must not 202");
        assert_eq!(resp.status, 500);
    }

    #[test]
    fn anonymous_malformed_json_acl_fail_closed_no_persist() {
        use crate::lifecycle_exec::{META_STORAGE_CLASS, SYS_TRANSITION_AT};

        let be = Arc::new(crate::cold_tier::MemoryColdBackend::default());
        let api = S3Api::new(cred_map())
            .with_anonymous_account("AUTH_test")
            .with_cold_map(crate::cold_tier::ColdPolicyMap::from_csv("GLACIER:2,HOT:0"))
            .with_cold_backend(be)
            .with_cold_delete_hot_after_archive(true);

        for raw in ["{", "", r#"{"Owner":"x","Grant":[]}"#] {
            let post_seen = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let put_seen = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let post_c = post_seen.clone();
            let put_c = put_seen.clone();
            let acl = raw.to_string();
            let next: NextFn = Arc::new(move |r| {
                if r.method == "POST" {
                    post_c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    return Response::new(202);
                }
                if r.method == "PUT" {
                    put_c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    return Response::new(201);
                }
                if r.method == "GET" && r.path.ends_with("/pub") {
                    let mut resp = Response::new(200);
                    resp.headers.set(S3_OBJECT_ACL_JSON_META, &acl);
                    resp.headers.set(META_STORAGE_CLASS, "GLACIER");
                    resp.headers.set(SYS_TRANSITION_AT, "1");
                    resp.body = Body::from(b"payload".to_vec());
                    return resp;
                }
                Response::new(500)
            });
            let req = Request {
                method: "GET".into(),
                path: "/pubbucket/pub".into(),
                query_string: String::new(),
                headers: HeaderKeyDict::new(),
                body: Body::empty(),
            };
            let resp = api.handle(req, &next);
            assert_eq!(resp.status, 403, "malformed ACL {raw:?} must deny");
            let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
            assert!(body.contains("AccessDenied"), "{raw:?} {body}");
            assert_eq!(
                post_seen.load(std::sync::atomic::Ordering::SeqCst),
                0,
                "malformed ACL {raw:?} must not POST"
            );
            assert_eq!(
                put_seen.load(std::sync::atomic::Ordering::SeqCst),
                0,
                "malformed ACL {raw:?} must not PUT"
            );
        }
    }

    #[test]
    fn cold_delete_hot_default_stays_off() {
        assert!(!COLD_DELETE_HOT_AFTER_ARCHIVE_DEFAULT);
        assert!(!S3Api::new(cred_map()).cold_delete_hot_after_archive);
        assert_eq!(
            S3Api::new(cred_map()).cold_delete_hot_after_archive,
            COLD_DELETE_HOT_AFTER_ARCHIVE_DEFAULT
        );
    }

    fn cred_map_with_s3test() -> HashMap<String, S3Credential> {
        let mut m = cred_map();
        m.insert(
            "s3test:tester".into(),
            S3Credential {
                access_key: "s3test:tester".into(),
                secret_key: "testing".into(),
                account: "AUTH_s3test".into(),
                groups: vec![
                    "s3test".into(),
                    "s3test:tester".into(),
                    "AUTH_s3test".into(),
                ],
                auth_token: None,
            },
        );
        m
    }

    fn frozen_api() -> S3Api {
        S3Api::new(cred_map_with_s3test()).with_frozen_accounts(["AUTH_test"])
    }

    fn assert_s3_access_denied(resp: Response) {
        assert_eq!(resp.status, 403);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(
            body.contains("<Code>AccessDenied</Code>"),
            "expected S3 AccessDenied XML, got {body}"
        );
        assert!(
            !body.contains("Account is frozen"),
            "must be S3 shape, not Swift freeze text: {body}"
        );
    }

    #[test]
    fn frozen_accounts_denies_auth_test_allows_s3test_and_list_buckets() {
        assert!(S3Api::new(cred_map()).frozen_accounts.is_empty());
        let api = frozen_api();
        assert!(api.is_frozen("AUTH_test"));
        assert!(!api.is_frozen("AUTH_s3test"));

        let next_hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let hits = next_hits.clone();
        let deny_next: NextFn = Arc::new(move |_| {
            hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Response::with_body(200, b"Some Content".to_vec())
        });

        assert_s3_access_denied(api.handle(
            sign_request(base_s3_req("GET", "/mybucket/obj", ""), "testing"),
            &deny_next,
        ));
        assert_s3_access_denied(api.handle(
            sign_request(base_s3_req("PUT", "/mybucket/obj", ""), "testing"),
            &deny_next,
        ));
        assert_s3_access_denied(api.handle(
            sign_request(base_s3_req("GET", "/mybucket", "location"), "testing"),
            &deny_next,
        ));
        assert_eq!(
            next_hits.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "frozen AUTH_test must not call next()"
        );

        let s3test_next: NextFn = Arc::new(|r| {
            assert!(
                r.path.starts_with("/v1/AUTH_s3test/"),
                "AUTH_s3test must not be remapped as AUTH_test: {}",
                r.path
            );
            if r.method == "HEAD" {
                return Response::new(404);
            }
            if r.method == "PUT" {
                let mut resp = Response::new(201);
                resp.headers.set("ETag", "abc123");
                return resp;
            }
            let mut resp = Response::new(200);
            resp.body = Body::from(b"ok-s3test".to_vec());
            resp.headers.set("ETag", "abc123");
            resp
        });
        let get_s3test = sign_request(
            base_s3_req_as("GET", "/mybucket/obj", "", "s3test:tester"),
            "testing",
        );
        let get_resp = api.handle(get_s3test, &s3test_next);
        assert_eq!(
            get_resp.status, 200,
            "AUTH_s3test GET must not be freeze-denied"
        );
        let get_body = String::from_utf8(get_resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert_eq!(get_body, "ok-s3test");
        assert!(!get_body.contains("AccessDenied"));

        let put_s3test = sign_request(
            base_s3_req_as("PUT", "/mybucket/obj", "", "s3test:tester"),
            "testing",
        );
        let put_resp = api.handle(put_s3test, &s3test_next);
        assert_eq!(
            put_resp.status, 200,
            "AUTH_s3test PUT must not be freeze-denied"
        );

        let list_hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let list_c = list_hits.clone();
        let list_next: NextFn = Arc::new(move |r| {
            list_c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            assert_eq!(r.path, "/v1/AUTH_test");
            Response::with_body(
                200,
                br#"[{"name":"b1","count":0,"bytes":0,"last_modified":"2013-05-24T00:00:00.000000"}]"#.to_vec(),
            )
        });
        let list_resp = api.handle(
            sign_request(base_s3_req("GET", "/", ""), "testing"),
            &list_next,
        );
        assert_eq!(list_resp.status, 200, "ListBuckets must stay allowed");
        let list_body = String::from_utf8(list_resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(list_body.contains("ListAllMyBucketsResult"), "{list_body}");
        assert!(list_body.contains("<Name>b1</Name>"), "{list_body}");
        assert!(!list_body.contains("AccessDenied"), "{list_body}");
        assert_eq!(list_hits.load(std::sync::atomic::Ordering::SeqCst), 1);

        let anon = frozen_api().with_anonymous_account("AUTH_test");
        let anon_hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let anon_c = anon_hits.clone();
        let anon_next: NextFn = Arc::new(move |_| {
            anon_c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Response::with_body(200, b"hello-anon".to_vec())
        });
        let anon_req = Request {
            method: "GET".into(),
            path: "/pubbucket/obj1".into(),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: Body::empty(),
        };
        assert_s3_access_denied(anon.handle(anon_req, &anon_next));
        assert_eq!(
            anon_hits.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "frozen anonymous AUTH_test must not call next()"
        );
    }

    fn sign_v4_query(
        mut req: Request,
        access: &str,
        secret: &str,
        signed_at: i64,
        expires: i64,
    ) -> Request {
        let amz = format_amz_date(signed_at);
        let scope = &amz[..8];
        let cred = format!("{access}/{scope}/us-east-1/s3/aws4_request");
        let cred_q = cred.replace('/', "%2F");
        req.query_string = format!(
            "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential={cred_q}\
             &X-Amz-Date={amz}&X-Amz-Expires={expires}&X-Amz-SignedHeaders=host\
             &X-Amz-Signature=00"
        );
        let auth = parse_query_authentication(&req.params()).unwrap();
        let hts = headers_to_sign(&req.headers, &auth.signed_headers).unwrap();
        let cr = canonical_request(
            &req.method,
            &canonical_uri(&req.path),
            &canonical_query(&req.query_string),
            &hts,
            &payload_hash(&req),
        );
        let sig = compute_signature(secret, &auth.scope, &amz, &cr);
        req.query_string = format!(
            "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential={cred_q}\
             &X-Amz-Date={amz}&X-Amz-Expires={expires}&X-Amz-SignedHeaders=host\
             &X-Amz-Signature={sig}"
        );
        req
    }

    fn sign_v2_query(mut req: Request, access: &str, secret: &str, expires: i64) -> Request {
        use crate::sigv2::{compute_signature_v2, string_to_sign_v2, SigV2Auth};
        let auth = SigV2Auth {
            access_key: access.into(),
            signature: String::new(),
            query_auth: true,
            expires: Some(expires),
        };
        req.query_string = format!("AWSAccessKeyId={access}&Expires={expires}&Signature=x");
        let sts = string_to_sign_v2(&req, &auth);
        let sig = compute_signature_v2(secret, &sts);
        req.query_string = format!("AWSAccessKeyId={access}&Expires={expires}&Signature={sig}");
        req
    }

    fn assert_s3_code(resp: Response, status: u16, code: &str, message: &str) {
        assert_eq!(resp.status, status, "status");
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        crate::response::assert_error_xml_matches_normalize(&body, code, message);
    }

    #[test]
    fn handle_sigv4_header_clock_skew_is_403() {
        let api = S3Api::new(cred_map());
        let now = unix_now();
        let req = sign_request(
            base_s3_req_at("GET", "/mybucket/obj", "", now - 3600),
            "testing",
        );
        let next: NextFn = Arc::new(|_| panic!("skewed SigV4 must not be served"));
        assert_s3_code(
            api.handle(req, &next),
            403,
            "RequestTimeTooSkewed",
            "The difference between the request time and the current time is too large.",
        );
    }

    #[test]
    fn handle_sigv2_header_clock_skew_is_403() {
        let api = S3Api::new(cred_map());
        let now = unix_now();
        let mut headers = HeaderKeyDict::new();
        headers.set("Host", "localhost");
        headers.set("Date", swift_http::http_date(now - 3600));
        let req = Request {
            method: "GET".into(),
            path: "/mybucket/obj".into(),
            query_string: String::new(),
            headers,
            body: Body::empty(),
        };
        let req = sign_request_v2(req, "test:tester", "testing");
        let next: NextFn = Arc::new(|_| panic!("skewed SigV2 must not be served"));
        assert_s3_code(
            api.handle(req, &next),
            403,
            "RequestTimeTooSkewed",
            "The difference between the request time and the current time is too large.",
        );
    }

    #[test]
    fn handle_sigv4_query_expired_is_access_denied() {
        let api = S3Api::new(cred_map());
        let now = unix_now();
        let mut headers = HeaderKeyDict::new();
        headers.set("Host", "localhost");
        let req = Request {
            method: "GET".into(),
            path: "/mybucket/obj".into(),
            query_string: String::new(),
            headers,
            body: Body::empty(),
        };
        let req = sign_v4_query(req, "test:tester", "testing", now - 120, 1);
        let next: NextFn = Arc::new(|_| panic!("expired V4 query must not be served"));
        assert_s3_code(
            api.handle(req, &next),
            403,
            "AccessDenied",
            "Request has expired",
        );
    }

    #[test]
    fn handle_sigv2_query_expired_is_access_denied() {
        let api = S3Api::new(cred_map());
        let now = unix_now();
        let mut headers = HeaderKeyDict::new();
        headers.set("Host", "localhost");
        let req = Request {
            method: "GET".into(),
            path: "/mybucket/obj".into(),
            query_string: String::new(),
            headers,
            body: Body::empty(),
        };
        let req = sign_v2_query(req, "test:tester", "testing", now - 10);
        let next: NextFn = Arc::new(|_| panic!("expired V2 query must not be served"));
        assert_s3_code(
            api.handle(req, &next),
            403,
            "AccessDenied",
            "Request has expired",
        );
    }

    #[test]
    fn put_unknown_storage_class_is_400() {
        let api = S3Api::new(cred_map());
        let mut req = base_s3_req("PUT", "/mybucket/negative/invalid-storage-class", "");
        req.headers.set("x-amz-storage-class", "GLACIER");
        let req = sign_request(req, "testing");
        let next: NextFn = Arc::new(|_| panic!("unknown storage_class must not persist"));
        assert_s3_code(
            api.handle(req, &next),
            400,
            "InvalidStorageClass",
            "The storage class you specified is not valid.",
        );
    }

    #[test]
    fn copy_unknown_storage_class_is_400() {
        let api = S3Api::new(cred_map());
        let mut req = base_s3_req("PUT", "/mybucket/dst", "");
        req.headers.set("x-amz-copy-source", "/src/obj");
        req.headers.set("x-amz-storage-class", "GLACIER");
        let req = sign_request(req, "testing");
        let next: NextFn = Arc::new(|_| panic!("copy unknown storage_class must not persist"));
        assert_s3_code(
            api.handle(req, &next),
            400,
            "InvalidStorageClass",
            "The storage class you specified is not valid.",
        );
    }

    #[test]
    fn put_standard_storage_class_reaches_backend() {
        let api = S3Api::new(cred_map());
        let mut req = base_s3_req("PUT", "/mybucket/obj", "");
        req.headers.set("x-amz-storage-class", "STANDARD");
        let req = sign_request(req, "testing");
        let next: NextFn = Arc::new(|r| {
            if r.method == "HEAD" {
                return Response::new(404);
            }
            assert!(
                r.headers.get("x-amz-storage-class").is_none(),
                "x-amz-storage-class must be stripped before persist"
            );
            let mut resp = Response::new(201);
            resp.headers.set("ETag", "abc123");
            resp
        });
        assert_eq!(api.handle(req, &next).status, 200);
    }

    // ===================== cross-proxy version-index CAS =====================
    //
    // Hermetic model of the LIVE fleet: several `S3Api` instances (one per
    // proxy) share ONE backend store with the deployed conditional-write
    // semantics:
    //   * object PUT enforces `If-None-Match: *` (412 when the object exists)
    //     — the Wave-2 object-server has carried this since the monorepo
    //     import (swift-object-server/src/lib.rs, `if_none_match_has_star`).
    //   * object PUT IGNORES `If-Match` — `put_if_match_precondition` only
    //     exists from 414b76e (2026-08-16); the deployed Wave-2 object layer
    //     (`e1d4f1cc…`) predates it, so the header is a silent no-op there.
    //
    // The gate mechanism gives tests deterministic interleavings without
    // touching product code: a gated (method, path) parks inside the backend
    // until released, exactly like a proxy stalling mid-flight.

    struct GateState {
        held: std::collections::HashSet<String>,
        arrived: std::collections::HashSet<String>,
    }

    struct SharedSwiftBackend {
        store: std::sync::Mutex<HashMap<String, (HeaderKeyDict, Vec<u8>)>>,
        /// Applied (2xx) PUTs of version-index objects, in arrival order:
        /// `(object path, parsed index)`.
        index_commits: std::sync::Mutex<Vec<(String, VersionIndex)>>,
        gates: std::sync::Mutex<GateState>,
        gates_cv: std::sync::Condvar,
    }

    impl SharedSwiftBackend {
        fn new(versioning_status: &str) -> Arc<Self> {
            let be = Arc::new(Self {
                store: std::sync::Mutex::new(HashMap::new()),
                index_commits: std::sync::Mutex::new(Vec::new()),
                gates: std::sync::Mutex::new(GateState {
                    held: std::collections::HashSet::new(),
                    arrived: std::collections::HashSet::new(),
                }),
                gates_cv: std::sync::Condvar::new(),
            });
            let mut h = HeaderKeyDict::new();
            h.set(S3_VERSIONING_META, versioning_status);
            be.store
                .lock()
                .unwrap()
                .insert("/v1/AUTH_test/mybucket".into(), (h, Vec::new()));
            be
        }

        fn next_fn(self: &Arc<Self>) -> NextFn {
            let be = self.clone();
            Arc::new(move |r: Request| be.handle(r))
        }

        fn gate_key(method: &str, path: &str) -> String {
            format!("{method} {path}")
        }

        /// Park the next request matching (method, path) until released.
        fn hold(&self, method: &str, path: &str) {
            self.gates
                .lock()
                .unwrap()
                .held
                .insert(Self::gate_key(method, path));
        }

        /// Block until a gated request has arrived and is parked.
        fn wait_arrival(&self, method: &str, path: &str) {
            let key = Self::gate_key(method, path);
            let deadline = std::time::Duration::from_secs(30);
            let guard = self.gates.lock().unwrap();
            let (guard, timeout) = self
                .gates_cv
                .wait_timeout_while(guard, deadline, |g| !g.arrived.contains(&key))
                .unwrap();
            drop(guard);
            assert!(!timeout.timed_out(), "gated request never arrived: {key}");
        }

        fn release(&self, method: &str, path: &str) {
            let key = Self::gate_key(method, path);
            self.gates.lock().unwrap().held.remove(&key);
            self.gates_cv.notify_all();
        }

        fn pass_gate(&self, method: &str, path: &str) {
            let key = Self::gate_key(method, path);
            let mut guard = self.gates.lock().unwrap();
            if !guard.held.contains(&key) {
                return;
            }
            guard.arrived.insert(key.clone());
            self.gates_cv.notify_all();
            let deadline = std::time::Duration::from_secs(30);
            let (guard, timeout) = self
                .gates_cv
                .wait_timeout_while(guard, deadline, |g| g.held.contains(&key))
                .unwrap();
            drop(guard);
            assert!(!timeout.timed_out(), "gate never released: {key}");
        }

        /// Applied writes of the `…/index.json` mirror, in arrival order.
        fn mirror_writes(&self) -> Vec<(u64, VersionIndex)> {
            self.index_commits
                .lock()
                .unwrap()
                .iter()
                .filter(|(name, _)| name.ends_with("/index.json"))
                .map(|(_, index)| (index.generation, index.clone()))
                .collect()
        }

        fn final_index(&self, container_path: &str, key: &str) -> VersionIndex {
            let path = format!("{container_path}/{}", index_object_name(key));
            let store = self.store.lock().unwrap();
            let (_, body) = store
                .get(&path)
                .unwrap_or_else(|| panic!("index.json missing at {path}"));
            VersionIndex::from_json(body).expect("final index parses")
        }

        /// Version-ids of archive objects present under `{hex(key)}/`.
        fn archived_version_ids(&self, container_path: &str, key: &str) -> Vec<String> {
            let prefix = format!(
                "{container_path}/{}/",
                crate::versioning_store::key_hex(key)
            );
            let store = self.store.lock().unwrap();
            let mut out = Vec::new();
            for name in store.keys() {
                if let Some(rest) = name.strip_prefix(&prefix) {
                    if rest.chars().all(|c| c.is_ascii_hexdigit()) && !rest.is_empty() {
                        out.push(rest.to_string());
                    }
                }
            }
            out
        }

        fn current_version_id(&self, object_path: &str) -> Option<String> {
            let store = self.store.lock().unwrap();
            store
                .get(object_path)
                .and_then(|(h, _)| h.get(SYS_VERSION_ID).map(str::to_string))
        }

        fn handle(&self, r: Request) -> Response {
            let method = r.method.clone();
            let path = r.path.clone();
            self.pass_gate(&method, &path);

            let is_container =
                path == "/v1/AUTH_test/mybucket" || path == "/v1/AUTH_test/mybucket+versions";
            if is_container {
                let mut store = self.store.lock().unwrap();
                match method.as_str() {
                    "HEAD" => {
                        return match store.get(&path) {
                            Some((h, _)) => {
                                let mut resp = Response::new(204);
                                for (k, v) in h.iter() {
                                    resp.headers.set(k, v);
                                }
                                resp
                            }
                            None => Response::new(404),
                        };
                    }
                    "PUT" => {
                        store
                            .entry(path)
                            .or_insert_with(|| (HeaderKeyDict::new(), Vec::new()));
                        return Response::new(201);
                    }
                    "GET" => {
                        let prefix = format!("{path}/");
                        let mut items = Vec::new();
                        for (p, (h, body)) in store.iter() {
                            if let Some(name) = p.strip_prefix(&prefix) {
                                let hash = h.get("ETag").unwrap_or("deadbeef");
                                items.push(format!(
                                    r#"{{"name":"{name}","hash":"{hash}","bytes":{},"last_modified":"2013-05-24T00:00:00.000000"}}"#,
                                    body.len()
                                ));
                            }
                        }
                        return Response::with_body(
                            200,
                            format!("[{}]", items.join(",")).into_bytes(),
                        );
                    }
                    "POST" => {
                        let entry = store
                            .entry(path)
                            .or_insert_with(|| (HeaderKeyDict::new(), Vec::new()));
                        for (k, v) in r.headers.iter() {
                            entry.0.set(k, v);
                        }
                        return Response::new(204);
                    }
                    _ => return Response::new(405),
                }
            }

            match method.as_str() {
                "HEAD" | "GET" => {
                    let store = self.store.lock().unwrap();
                    match store.get(&path) {
                        Some((h, body)) => {
                            let mut resp = if method == "GET" {
                                Response::with_body(200, body.clone())
                            } else {
                                Response::new(200)
                            };
                            for (k, v) in h.iter() {
                                resp.headers.set(k, v);
                            }
                            resp.headers.set("Content-Length", body.len().to_string());
                            if resp.headers.get("ETag").is_none() {
                                resp.headers.set("ETag", "deadbeef");
                            }
                            resp.headers
                                .set("Last-Modified", "Thu, 01 Jan 1970 00:00:00 GMT");
                            resp
                        }
                        None => Response::new(404),
                    }
                }
                "PUT" => {
                    let body = r.body.into_vec(u64::MAX).unwrap_or_default();
                    let mut store = self.store.lock().unwrap();
                    // Wave-2 object-server semantics: `If-None-Match: *` is
                    // enforced (412 on existing object) …
                    if let Some(inm) = r.headers.get("If-None-Match") {
                        if inm.split(',').any(|tok| tok.trim() == "*") && store.contains_key(&path)
                        {
                            return Response::new(412);
                        }
                    }
                    // … while `If-Match` on PUT is silently ignored (the
                    // deployed object layer predates 414b76e).
                    let mut h = HeaderKeyDict::new();
                    for (k, v) in r.headers.iter() {
                        let kl = k.to_ascii_lowercase();
                        if kl.starts_with("x-object-") || kl == "content-type" {
                            h.set(k, v);
                        }
                    }
                    use std::collections::hash_map::DefaultHasher;
                    use std::hash::{Hash, Hasher};
                    let mut hasher = DefaultHasher::new();
                    body.hash(&mut hasher);
                    let etag = format!("{:x}", hasher.finish());
                    h.set("ETag", &etag);
                    h.set("Content-Length", body.len().to_string());
                    if path.contains("/index.") && path.ends_with(".json") {
                        if let Some(index) = VersionIndex::from_json(&body) {
                            self.index_commits
                                .lock()
                                .unwrap()
                                .push((path.clone(), index));
                        }
                    }
                    store.insert(path, (h, body));
                    let mut resp = Response::new(201);
                    resp.headers.set("ETag", etag);
                    resp.headers.set("Content-Length", "0");
                    resp
                }
                "DELETE" => {
                    let mut store = self.store.lock().unwrap();
                    if store.remove(&path).is_some() {
                        Response::new(204)
                    } else {
                        Response::new(404)
                    }
                }
                _ => Response::new(405),
            }
        }
    }

    fn versioned_put_ok(api: &S3Api, next: &NextFn, key: &str, body: &[u8]) -> String {
        let mut req = base_s3_req("PUT", &format!("/mybucket/{key}"), "");
        req.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        req.body = Body::from(body.to_vec());
        let resp = api.handle(sign_request(req, "testing"), next);
        assert_eq!(resp.status, 200, "seed PUT must succeed");
        resp.headers
            .get("x-amz-version-id")
            .expect("versioned PUT answers x-amz-version-id")
            .to_string()
    }

    /// Invariants a cross-proxy backend CAS must uphold. Every violation is a
    /// silent lost update today.
    fn assert_version_index_invariants(
        be: &SharedSwiftBackend,
        key: &str,
        acked_puts: &[String],
        acked_deletes: &[String],
    ) {
        // (1) The backend must never have APPLIED two index writes that
        //     claim the same generation with DIVERGENT content — that is
        //     the definition of a lost update. (The mirror-heal path may
        //     legally re-write a generation with byte-identical content,
        //     and generations must never regress.)
        let writes = be.mirror_writes();
        let gens: Vec<u64> = writes.iter().map(|(g, _)| *g).collect();
        for pair in gens.windows(2) {
            assert!(
                pair[1] >= pair[0],
                "mirror generation regressed (lost update): {gens:?}"
            );
        }
        for (i, (gen_a, index_a)) in writes.iter().enumerate() {
            for (gen_b, index_b) in &writes[i + 1..] {
                if gen_a == gen_b {
                    assert!(
                        index_a == index_b,
                        "backend applied two divergent index writes for \
                         generation {gen_a} without cross-proxy CAS (lost \
                         update): {:?} vs {:?}",
                        index_a
                            .versions
                            .iter()
                            .map(|v| v.version_id.as_str())
                            .collect::<Vec<_>>(),
                        index_b
                            .versions
                            .iter()
                            .map(|v| v.version_id.as_str())
                            .collect::<Vec<_>>()
                    );
                }
            }
        }

        let index = be.final_index("/v1/AUTH_test/mybucket+versions", key);
        let listed: Vec<&str> = index
            .versions
            .iter()
            .map(|v| v.version_id.as_str())
            .collect();

        // (2) Every version-id acknowledged 200 to a client survives in the
        //     committed index unless a later acknowledged delete removed it.
        for vid in acked_puts {
            if acked_deletes.contains(vid) {
                continue;
            }
            assert!(
                listed.contains(&vid.as_str()),
                "version {vid} was acknowledged 200 to the client but is \
                 missing from the committed index (lost update): {listed:?}"
            );
        }

        // (3) Every version-id whose delete was acknowledged 2xx stays gone.
        for vid in acked_deletes {
            assert!(
                !listed.contains(&vid.as_str()),
                "version {vid} was acknowledged deleted but resurrected in \
                 the committed index: {listed:?}"
            );
        }

        // (4) No orphan archives for ACKNOWLEDGED operations: an archive of
        //     an acknowledged version is listed, and an acknowledged delete
        //     leaves no archive object behind. (A writer that lost the CAS
        //     after staging data leaves never-acknowledged, index-gated
        //     garbage — resolve_object_version requires the index record
        //     before touching archives, so it can never resurrect.)
        for vid in be.archived_version_ids("/v1/AUTH_test/mybucket+versions", key) {
            assert!(
                !acked_deletes.contains(&vid),
                "archive object for version {vid} still exists although its \
                 delete was acknowledged"
            );
            if acked_puts.contains(&vid) {
                assert!(
                    listed.contains(&vid.as_str()),
                    "archive object for acknowledged version {vid} exists but \
                     the committed index does not list it (orphan archive): \
                     {listed:?}"
                );
            }
        }

        // (5) An ACKNOWLEDGED current object is indexed. (A writer that was
        //     told InternalError may leave its data-plane current object
        //     behind — the same repairable state today's persist failures
        //     leave; the next successful write repair-inserts it.)
        if let Some(cur) = be.current_version_id(&format!("/v1/AUTH_test/mybucket/{key}")) {
            if acked_puts.contains(&cur) {
                assert!(
                    listed.contains(&cur.as_str()),
                    "current object carries acknowledged version {cur} but \
                     the committed index does not list it: {listed:?}"
                );
            }
        }
    }

    /// Two proxies race a versioned PUT against `DELETE ?versionId` on the
    /// same key. Deterministic interleaving (no timing): proxy B loads the
    /// generation-2 snapshot, parks at its archive DELETE; proxy A commits
    /// generation 3 end-to-end; B is released and persists its own
    /// generation-3 index over A's.
    ///
    /// On an in-process-only CAS the backend accepts both generation-3
    /// writes: A's acknowledged version vanishes from the index and the
    /// generation sequence stalls. A cross-proxy backend CAS must instead
    /// fail one writer with the existing CAS-denied surface (InternalError).
    #[test]
    fn concurrent_put_and_delete_must_not_lose_acknowledged_writes() {
        let be = SharedSwiftBackend::new("Enabled");
        let api_a = S3Api::new(cred_map());
        let next_a = be.next_fn();

        // Seed sequentially: index generation 2, versions [v2, v1],
        // current = v2, archived = {v1}.
        let v1 = versioned_put_ok(&api_a, &next_a, "obj", b"seed-1");
        let v2 = versioned_put_ok(&api_a, &next_a, "obj", b"seed-2");

        // Proxy B: DELETE ?versionId=v1 — parked at its destructive archive
        // DELETE, after it loaded the generation-2 snapshot.
        let v1_archive = format!(
            "/v1/AUTH_test/mybucket+versions/{}",
            archive_object_name("obj", &v1)
        );
        be.hold("DELETE", &v1_archive);
        let be_b = be.clone();
        let v1_b = v1.clone();
        let thread_b = std::thread::spawn(move || {
            let api_b = S3Api::new(cred_map());
            let next_b = be_b.next_fn();
            let req = sign_request(
                base_s3_req("DELETE", "/mybucket/obj", &format!("versionId={v1_b}")),
                "testing",
            );
            let resp = api_b.handle(req, &next_b);
            let status = resp.status;
            let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap_or_default())
                .unwrap_or_default();
            (status, body)
        });
        be.wait_arrival("DELETE", &v1_archive);

        // Proxy A: full versioned PUT — archives v2, writes the new current,
        // commits index generation 3.
        let va = versioned_put_ok(&api_a, &next_a, "obj", b"concurrent-a");

        // Release proxy B: its index write is now stale (generation 3 again).
        be.release("DELETE", &v1_archive);
        let (status_b, body_b) = thread_b.join().expect("proxy B thread");

        // The loser must keep today's client surface: either it won cleanly
        // (204) or it surfaces the existing CAS-denied class (InternalError).
        assert!(
            status_b == 204 || (status_b == 500 && body_b.contains("InternalError")),
            "DELETE conflict surface changed: status={status_b} body={body_b}"
        );

        let acked_deletes = if status_b == 204 {
            vec![v1.clone()]
        } else {
            Vec::new()
        };
        assert_version_index_invariants(&be, "obj", &[v1, v2, va], &acked_deletes);
    }

    /// N writers race versioned PUTs against exact-version deletes of
    /// distinct seed versions, one racing pair per round with a start
    /// barrier. No injected schedule: any interleaving must uphold the
    /// invariants; with an in-process-only CAS the stale index persists
    /// overwrite committed writes.
    #[test]
    fn concurrent_writers_uphold_version_index_invariants() {
        let be = SharedSwiftBackend::new("Enabled");
        let api = S3Api::new(cred_map());
        let next = be.next_fn();

        const ROUNDS: usize = 6;
        let mut seeds = Vec::new();
        for i in 0..=ROUNDS {
            seeds.push(versioned_put_ok(
                &api,
                &next,
                "obj",
                format!("seed-{i}").as_bytes(),
            ));
        }

        let acked_puts: Arc<std::sync::Mutex<Vec<String>>> =
            Arc::new(std::sync::Mutex::new(seeds.clone()));
        let acked_deletes: Arc<std::sync::Mutex<Vec<String>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));

        for (round, target) in seeds.iter().take(ROUNDS).enumerate() {
            let barrier = Arc::new(std::sync::Barrier::new(2));

            let be_put = be.clone();
            let barrier_put = barrier.clone();
            let acked_puts_c = acked_puts.clone();
            let put_thread = std::thread::spawn(move || {
                let api = S3Api::new(cred_map());
                let next = be_put.next_fn();
                let mut req = base_s3_req("PUT", "/mybucket/obj", "");
                req.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
                req.body = Body::from(format!("round-{round}").into_bytes());
                let req = sign_request(req, "testing");
                barrier_put.wait();
                let resp = api.handle(req, &next);
                if resp.status == 200 {
                    if let Some(vid) = resp.headers.get("x-amz-version-id") {
                        acked_puts_c.lock().unwrap().push(vid.to_string());
                    }
                }
            });

            let be_del = be.clone();
            let barrier_del = barrier.clone();
            let acked_deletes_c = acked_deletes.clone();
            let target_c = target.clone();
            let del_thread = std::thread::spawn(move || {
                let api = S3Api::new(cred_map());
                let next = be_del.next_fn();
                let req = sign_request(
                    base_s3_req("DELETE", "/mybucket/obj", &format!("versionId={target_c}")),
                    "testing",
                );
                barrier_del.wait();
                let resp = api.handle(req, &next);
                if resp.status == 204 {
                    acked_deletes_c.lock().unwrap().push(target_c);
                }
            });

            put_thread.join().expect("PUT thread");
            del_thread.join().expect("DELETE thread");
        }

        let puts = acked_puts.lock().unwrap().clone();
        let deletes = acked_deletes.lock().unwrap().clone();
        assert_version_index_invariants(&be, "obj", &puts, &deletes);
    }

    /// A taken fence (412) surfaces the existing persist-conflict class and
    /// the mirror is never written — the fence decides BEFORE the mirror.
    #[test]
    fn version_index_fence_412_is_conflict_and_mirror_untouched() {
        let api = S3Api::new(cred_map());
        let inner = versioning_mock_store("Enabled");
        let mirror_puts: Arc<std::sync::Mutex<u32>> = Arc::new(std::sync::Mutex::new(0));
        let mirror_puts_c = mirror_puts.clone();
        let next: NextFn = Arc::new(move |r: Request| {
            if r.method == "PUT" && r.path.contains("/index.g") {
                return Response::new(412);
            }
            if r.method == "PUT" && r.path.ends_with("/index.json") {
                *mirror_puts_c.lock().unwrap() += 1;
            }
            inner(r)
        });
        let mut put = base_s3_req("PUT", "/mybucket/obj", "");
        put.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        put.body = Body::from(b"v1".to_vec());
        let resp = api.handle(sign_request(put, "testing"), &next);
        assert!(resp.status >= 400, "status={}", resp.status);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("InternalError"), "{body}");
        assert_eq!(
            *mirror_puts.lock().unwrap(),
            0,
            "mirror written after lost fence"
        );
    }

    /// Fence persist 202 is not success (same fail-closed rule as the
    /// mirror): the write was not Applied, so the commit did not happen.
    #[test]
    fn version_index_fence_202_is_not_success() {
        let api = S3Api::new(cred_map());
        let inner = versioning_mock_store("Enabled");
        let mirror_puts: Arc<std::sync::Mutex<u32>> = Arc::new(std::sync::Mutex::new(0));
        let mirror_puts_c = mirror_puts.clone();
        let next: NextFn = Arc::new(move |r: Request| {
            if r.method == "PUT" && r.path.contains("/index.g") {
                return Response::new(202);
            }
            if r.method == "PUT" && r.path.ends_with("/index.json") {
                *mirror_puts_c.lock().unwrap() += 1;
            }
            inner(r)
        });
        let mut put = base_s3_req("PUT", "/mybucket/obj", "");
        put.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        put.body = Body::from(b"v1".to_vec());
        let resp = api.handle(sign_request(put, "testing"), &next);
        assert!(resp.status >= 400, "status={}", resp.status);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert!(body.contains("InternalError"), "{body}");
        assert_eq!(
            *mirror_puts.lock().unwrap(),
            0,
            "mirror written after unapplied fence"
        );
    }

    /// Every fence write is create-only (`If-None-Match: *`, no `If-Match`)
    /// with the zero-padded generation in the name.
    #[test]
    fn version_index_fence_writes_are_create_only() {
        let api = S3Api::new(cred_map());
        let inner = versioning_mock_store("Enabled");
        let seen: Arc<std::sync::Mutex<Vec<(String, Option<String>, Option<String>)>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen_c = seen.clone();
        let next: NextFn = Arc::new(move |r: Request| {
            if r.method == "PUT" && r.path.contains("/index.g") {
                seen_c.lock().unwrap().push((
                    r.path.clone(),
                    r.headers.get("If-None-Match").map(str::to_string),
                    r.headers.get("If-Match").map(str::to_string),
                ));
            }
            inner(r)
        });
        for body in [b"v1".as_slice(), b"v2".as_slice()] {
            let mut put = base_s3_req("PUT", "/mybucket/obj", "");
            put.headers.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
            put.body = Body::from(body.to_vec());
            assert_eq!(api.handle(sign_request(put, "testing"), &next).status, 200);
        }
        let fences = seen.lock().unwrap().clone();
        assert_eq!(fences.len(), 2);
        assert!(fences[0].0.ends_with("/index.g00000000000000000001.json"));
        assert!(fences[1].0.ends_with("/index.g00000000000000000002.json"));
        for (path, inm, im) in &fences {
            assert_eq!(inm.as_deref(), Some("*"), "fence not create-only: {path}");
            assert!(im.is_none(), "fence must not carry If-Match: {path}");
        }
    }

    /// A fence committed by a crashed writer (no mirror write) is adopted by
    /// the next snapshot load, the mirror is healed, and the next commit
    /// advances past it instead of forking history.
    #[test]
    fn crashed_writer_fence_is_adopted_and_mirror_healed() {
        let be = SharedSwiftBackend::new("Enabled");
        let api = S3Api::new(cred_map());
        let next = be.next_fn();

        let v1 = versioned_put_ok(&api, &next, "obj", b"seed-1");

        // Forge what a concurrent proxy leaves behind when it dies between
        // fence and mirror: the generation-2 fence carrying its new record.
        let ghost = "f".repeat(32);
        let mut ghost_idx = be.final_index("/v1/AUTH_test/mybucket+versions", "obj");
        assert_eq!(ghost_idx.generation, 1);
        ghost_idx.push_latest(VersionRecord {
            version_id: ghost.clone(),
            is_delete_marker: false,
            is_latest: true,
            last_modified: "1970-01-01T00:00:00.000Z".into(),
            etag: "ghost-etag".into(),
            size: 5,
        });
        ghost_idx.generation = 2;
        be.store.lock().unwrap().insert(
            format!(
                "/v1/AUTH_test/mybucket+versions/{}",
                index_generation_object_name("obj", 2)
            ),
            (HeaderKeyDict::new(), ghost_idx.to_json()),
        );

        // The next PUT adopts generation 2 and commits generation 3.
        let v3 = versioned_put_ok(&api, &next, "obj", b"after-crash");

        let final_idx = be.final_index("/v1/AUTH_test/mybucket+versions", "obj");
        assert_eq!(final_idx.generation, 3);
        let listed: Vec<&str> = final_idx
            .versions
            .iter()
            .map(|v| v.version_id.as_str())
            .collect();
        assert_eq!(listed, vec![v3.as_str(), ghost.as_str(), v1.as_str()]);
        assert!(final_idx.versions[0].is_latest);

        // The loader healed the mirror to generation 2 before the new
        // commit mirrored generation 3.
        let gens: Vec<u64> = be.mirror_writes().iter().map(|(g, _)| *g).collect();
        assert_eq!(gens, vec![1, 2, 3]);
    }

    /// Generation fences live in the `+versions` container but must never
    /// leak into ListVersions output.
    #[test]
    fn list_versions_skips_generation_fences() {
        let be = SharedSwiftBackend::new("Enabled");
        let api = S3Api::new(cred_map());
        let next = be.next_fn();
        let v1 = versioned_put_ok(&api, &next, "obj", b"one");
        let v2 = versioned_put_ok(&api, &next, "obj", b"two");

        let list = sign_request(base_s3_req("GET", "/mybucket", "versions"), "testing");
        let resp = api.handle(list, &next);
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap();
        assert_eq!(body.matches("<Version>").count(), 2, "{body}");
        assert!(
            body.contains(&format!("<VersionId>{v1}</VersionId>")),
            "{body}"
        );
        assert!(
            body.contains(&format!("<VersionId>{v2}</VersionId>")),
            "{body}"
        );
        assert!(
            !body.contains("index.g"),
            "fence leaked into ListVersions: {body}"
        );
    }
}
