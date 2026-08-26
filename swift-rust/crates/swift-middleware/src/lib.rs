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

//! A WSGI-style middleware pipeline, the Rust counterpart of Swift's
//! PasteDeploy filter chain. Each middleware wraps the next handler; the
//! innermost handler is the proxy app. The `pipeline = ...` line in
//! `proxy-server.conf` names the filters in order.
//!
//! This crate provides the framework plus the always-on structural
//! middlewares: `catch_errors` (trans-id + exception guard),
//! `gatekeeper` (strips client-supplied backend/sysmeta headers — a
//! security boundary), and `healthcheck`.
//!
//! P0 wired (proxy `build_configured_filters`): `cache`, `listing_formats`,
//! `proxy_logging` (optional logger sink). P1a adds `bulk` (delete),
//! `tempurl`, account ACL helpers, and deployable `ratelimit`. P1b adds
//! `formpost`, `staticweb`, quotas, `symlink`, `versioned_writes`, and the
//! smaller L2 filters. P3-auth wires `authtoken` + `keystoneauth`. P3-s3
//! `s3api` lives in `swift-s3api` (proxy-wired; not advertised on `/info`).
//! At-rest crypto: `keymaster` + `encrypter` + `decrypter` (or composite
//! `encryption`), ON-BY-CONFIG only.

mod account_freeze;
mod account_quotas;
mod acl;
mod authtoken;
mod backend_ratelimit;
mod bulk;
mod cache;
mod catch_errors;
mod cname_lookup;
mod container_quotas;
mod container_sync;
mod copy;
mod crossdomain;
mod decrypter;
mod dlo;
mod domain_remap;
mod encrypter;
mod etag_quoter;
mod formpost;
mod gatekeeper;
mod healthcheck;
mod keymaster;
mod keystoneauth;
mod list_endpoints;
mod listing_formats;
mod name_check;
mod passthrough;
mod plugin_registry;
mod proxy_logging;
mod ratelimit;
mod read_only;
mod s3token;
mod slo;
mod staticweb;
mod symlink;
mod tempauth;
mod tempurl;
mod versioned_writes;
mod xprofile;

pub use account_freeze::AccountFreeze;
pub use account_quotas::AccountQuotas;
pub use acl::{
    acls_from_sysmeta, format_acl_v2, parse_acl_v1, parse_acl_v2, referrer_allowed,
    validate_account_acl_header, AccountAcls,
};
pub use authtoken::{
    AuthToken, HttpKeystoneValidator, HttpTokenValidator, MapTokenValidator, StaticTokenMap,
    TokenOutcome, TokenValidator, ValidatedToken,
};
pub use backend_ratelimit::BackendRateLimit;
pub use bulk::{parse_delete_body, Bulk, BulkDeleteResult};
pub use cache::{Cache, DEFAULT_MEMCACHE_SERVERS};
pub use catch_errors::CatchErrors;
pub use cname_lookup::{CnameLookup, Resolver};
pub use container_quotas::ContainerQuotas;
pub use container_sync::{
    get_sig as container_sync_get_sig, ClosureSyncKeyProvider, ContainerSync, MapSyncKeyProvider,
    RealmInfo, RealmsConf, SyncKeyProvider,
};
pub use copy::Copy;
pub use crossdomain::Crossdomain;
pub use decrypter::{
    decrypt_container_listing_json, decrypt_listing_hash, decrypt_object_body, Decrypter,
};
pub use dlo::DynamicLargeObject;
pub use domain_remap::DomainRemap;
pub use encrypter::{
    encrypt_object_body, encrypt_object_body_from_body, encrypt_object_body_from_reader, random_iv,
    random_key, EncryptBodyError, EncryptedObject, Encrypter, BODY_META_HEADER, ETAG_HEADER,
    ETAG_MAC_HEADER, OVERRIDE_ETAG_HEADER,
};
pub use etag_quoter::EtagQuoter;
pub use formpost::{
    formpost_hmac, multipart_boundary, parse_content_disposition,
    verify_signature as formpost_verify, FormPost, FormPostAttributes, FormPostVerify,
    DEFAULT_ALLOWED_DIGESTS as FORMPOST_DEFAULT_DIGESTS,
};
pub use gatekeeper::Gatekeeper;
pub use healthcheck::HealthCheck;
pub use keymaster::{CryptoKeys, KeyMaster, KeyMasterMw};
pub use keystoneauth::{
    authorize as keystone_authorize, cross_tenant_match, AccountRules, AuthRequest, AuthResult,
    Identity, KeystoneAuth, RoleConfig, AUTH_PLUGIN_HEADER, AUTH_PLUGIN_KEYSTONE,
};
pub use list_endpoints::{EndpointResolver, ListEndpoints, StaticEndpoints};
pub use listing_formats::ListingFormats;
pub use name_check::NameCheck;
pub use passthrough::NamedPassthrough;
pub use plugin_registry::{global_registry, PluginFactory, PluginRegistry};
pub use proxy_logging::{LogContext, LogSink, ProxyLogging};
pub use ratelimit::{Clock, RateLimit, RateTier, SystemClock};
pub use read_only::ReadOnly;
pub use s3token::{
    access_key_from_authorization, encode_s3tokens_token, HttpS3TokenClient, MapS3TokenClient,
    S3Token, S3TokenClient, S3TokenResult, HDR_S3_ACCESS_KEY, HDR_S3_SIGNATURE,
    HDR_S3_STRING_TO_SIGN,
};
pub use slo::{
    dlo_etag_and_size, manifest_etag, normalize_etag, refetch_listing_slo_etag, slo_etag_and_size,
    Slo, SloSegment,
};
pub use staticweb::{build_listing_html, html_escape, human_readable, ListingItem, StaticWeb};
pub use symlink::Symlink;
pub use tempauth::{TempAuth, UserRecord};
pub use tempurl::{ClosureKeyProvider, KeyProvider, TempUrl};
pub use versioned_writes::{
    versions_object_name, VersionedWrites,
    AUTHORIZE_ONLY_HEADER as VERSIONED_WRITES_AUTHORIZE_ONLY_HEADER,
    OWNER_INFO_HEADER as VERSIONED_WRITES_OWNER_INFO_HEADER,
};
pub use xprofile::XProfile;

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use swift_http::{AsyncRequest, Request, Response};

/// The innermost app or the next middleware in the chain. An `Arc` so a
/// middleware can `Arc::clone(next)` INTO a streaming response body (the
/// lazy SLO/DLO segment readers).
pub type NextFn = Arc<dyn Fn(Request) -> Response + Send + Sync>;

/// Async inner app for production Hyper serve. SLO/DLO segment subrequests
/// must go through this, not a blocking `handle()`.
pub type AsyncNextFn =
    Arc<dyn Fn(Request) -> Pin<Box<dyn Future<Output = Response> + Send>> + Send + Sync>;

/// Production Hyper inner app that keeps the request body as a stream.
pub type StreamingAsyncNextFn =
    Arc<dyn Fn(AsyncRequest) -> Pin<Box<dyn Future<Output = Response> + Send>> + Send + Sync>;

/// Header-only phase on the production Hyper path. Must not read the
/// request body (object PUT/GET stay on `handle_async`).
pub enum MwPrep {
    Continue,
    ShortCircuit(Response),
}

/// A pipeline filter. `handle` may inspect/mutate the request, call
/// `next`, and inspect/mutate the response.
///
/// Production serve splits the filter into:
/// * [`prepare`] — stamp/strip headers or short-circuit (tempauth, gatekeeper)
/// * the async app (`handle_async`) for object streaming
/// * [`intercepts_response`] — SLO/DLO/listing wrap the app response
/// * [`finish`] — outbound header rewrite
pub trait Middleware: Send + Sync {
    fn handle(&self, req: Request, next: &NextFn) -> Response;

    fn prepare(&self, _req: &mut Request) -> MwPrep {
        MwPrep::Continue
    }

    /// Header phase on the Hyper path. Default is [`prepare`]. Auth filters
    /// that talk to Keystone over the network must override this so the
    /// wait is a Future, not `std::net` on a Tokio worker.
    fn prepare_async<'a>(
        &'a self,
        req: &'a mut Request,
    ) -> Pin<Box<dyn Future<Output = MwPrep> + Send + 'a>> {
        Box::pin(async move { self.prepare(req) })
    }

    fn finish(&self, _req: &Request, resp: Response) -> Response {
        resp
    }

    /// Manifest PUT/DELETE and similar control-plane intercepts: the
    /// server materializes at [`swift_http::MAX_CONTROL_BODY`] and runs
    /// the sync pipeline (inner `handle`, not object-sized PUT).
    fn intercepts_request(&self, _req: &Request) -> bool {
        false
    }

    /// Object-sized PUT/UploadPart: the Hyper path must not materialize
    /// [`swift_http::MAX_CONTROL_BODY`] before calling the filter.
    fn streams_request(&self, _req: &Request) -> bool {
        false
    }

    /// Streaming intercept. Default forwards the unread body.
    fn handle_streaming_request(
        &self,
        req: AsyncRequest,
        next: StreamingAsyncNextFn,
    ) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        Box::pin(async move { next(req).await })
    }

    /// Control-plane intercept (SLO PUT/DELETE) with async inner app.
    fn handle_request_async(
        &self,
        req: Request,
        next: AsyncNextFn,
    ) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        Box::pin(async move { next(req).await })
    }

    /// GET/HEAD reassembly or listing rewrite after the async app returns.
    fn intercepts_response(&self) -> bool {
        false
    }

    /// Production Hyper path: first `next` is the async app response;
    /// further `next` calls (SLO/DLO segments) are also async.
    fn reassemble_async(
        &self,
        req: Request,
        next: AsyncNextFn,
    ) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        Box::pin(async move {
            let first = next(req.clone_head()).await;
            let cap = std::sync::Mutex::new(Some(first));
            let sync: NextFn = Arc::new(move |r| {
                let _ = r;
                cap.lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .take()
                    .unwrap_or_else(|| {
                        Response::error(500, "sync intercept issued a second subrequest")
                    })
            });
            self.handle(req, &sync)
        })
    }
}

/// Compose a list of middlewares (outermost first) around a final app,
/// producing a single handler. The first middleware in `filters` sees
/// the request first, matching the `pipeline =` reading order.
pub fn build_pipeline(filters: Vec<Arc<dyn Middleware>>, app: NextFn) -> NextFn {
    // fold from the innermost (app) outward, so filters[0] ends up
    // outermost
    let mut handler: NextFn = app;
    for filter in filters.into_iter().rev() {
        let inner = handler;
        handler = Arc::new(move |req: Request| filter.handle(req, &inner));
    }
    handler
}
