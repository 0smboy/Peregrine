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
//! Deferred: proxy_logging (needs a logger sink), tempauth/keystoneauth
//! (token validation), and the ~35 feature middlewares.

mod account_quotas;
mod acl;
mod backend_ratelimit;
mod bulk;
mod catch_errors;
mod container_quotas;
mod copy;
mod crossdomain;
mod cname_lookup;
mod dlo;
mod domain_remap;
mod etag_quoter;
mod formpost;
mod gatekeeper;
mod healthcheck;
mod keystoneauth;
mod listing_formats;
mod name_check;
mod proxy_logging;
mod ratelimit;
mod read_only;
mod slo;
mod staticweb;
mod symlink;
mod tempauth;
mod tempurl;
mod versioned_writes;

pub use account_quotas::AccountQuotas;
pub use acl::{parse_acl_v1, referrer_allowed};
pub use backend_ratelimit::BackendRateLimit;
pub use bulk::{parse_delete_body, Bulk, BulkDeleteResult};
pub use catch_errors::CatchErrors;
pub use container_quotas::ContainerQuotas;
pub use copy::Copy;
pub use dlo::DynamicLargeObject;
pub use crossdomain::Crossdomain;
pub use cname_lookup::{CnameLookup, Resolver};
pub use domain_remap::DomainRemap;
pub use etag_quoter::EtagQuoter;
pub use formpost::{
    formpost_hmac, verify_signature as formpost_verify, FormPostAttributes, FormPostVerify,
    DEFAULT_ALLOWED_DIGESTS as FORMPOST_DEFAULT_DIGESTS,
};
pub use gatekeeper::Gatekeeper;
pub use healthcheck::HealthCheck;
pub use keystoneauth::{
    authorize as keystone_authorize, cross_tenant_match, AuthRequest, AuthResult, Identity,
    RoleConfig,
};
pub use listing_formats::ListingFormats;
pub use name_check::NameCheck;
pub use proxy_logging::{LogContext, ProxyLogging};
pub use ratelimit::{Clock, RateLimit, RateTier, SystemClock};
pub use read_only::ReadOnly;
pub use slo::{
    dlo_etag_and_size, manifest_etag, normalize_etag, slo_etag_and_size, Slo, SloSegment,
};
pub use staticweb::{
    build_listing_html, html_escape, human_readable, ListingItem, StaticWeb,
};
pub use symlink::Symlink;
pub use tempauth::{TempAuth, UserRecord};
pub use tempurl::{KeyProvider, TempUrl};
pub use versioned_writes::{versions_object_name, VersionedWrites};

use std::sync::Arc;

use swift_http::{Request, Response};

/// The innermost app or the next middleware in the chain. An `Arc` so a
/// middleware can `Arc::clone(next)` INTO a streaming response body (the
/// lazy SLO/DLO segment readers).
pub type NextFn = Arc<dyn Fn(Request) -> Response + Send + Sync>;

/// A pipeline filter. `handle` may inspect/mutate the request, call
/// `next`, and inspect/mutate the response.
pub trait Middleware: Send + Sync {
    fn handle(&self, req: Request, next: &NextFn) -> Response;
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
