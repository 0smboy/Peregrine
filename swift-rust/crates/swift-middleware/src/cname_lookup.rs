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

//! `cname_lookup`: translates an unknown domain in the `Host` header into
//! one that ends with the configured `storage_domain`, by following the
//! domain's DNS CNAME chain (up to `lookup_depth` hops). If a hop lands in
//! the storage domain the request's `Host` is rewritten and passed on;
//! otherwise the request is rejected `400`. Port of
//! `swift/common/middleware/cname_lookup.py`.
//!
//! DNS is abstracted behind the [`Resolver`] trait so the middleware is
//! testable with a fake resolver — the Python `lookup_cname(domain,
//! resolver)` helper (which returns `(ttl, result)` where `result` is a
//! domain, `False`, or `None`) collapses here to `Option<String>`: `None`
//! means "no CNAME / lookup failed", `Some(domain)` is the CNAME target.
//!
//! Deferred vs. the Python module (none affect the rewrite decision):
//!   * memcache caching of CNAME results — the `ttl` and `swift.cache`
//!     plumbing is dropped; every un-cached lookup goes to the resolver.
//!   * nameserver configuration / `parse_socket_string` validation — the
//!     resolver is injected, so `conf['nameservers']` has no analogue.
//!   * `get_logger` info/debug "Mapped ..."/"Following CNAME chain ..."
//!     lines.
//!   * `register_swift_info` registration.
//!   * `SERVER_NAME` fallback when `Host` is absent — the Rust threaded
//!     server always supplies `Host`; a missing `Host` passes through
//!     unchanged (same observable result as the Python passthrough).

use std::sync::Arc;

use swift_core::config::list_from_csv;
use swift_http::{Request, Response};

use crate::{Middleware, NextFn};

/// Injectable DNS CNAME resolver. Mirrors Python's
/// `lookup_cname(domain, resolver)`: returns the CNAME target for `domain`,
/// or `None` when there is no CNAME record or the lookup failed.
pub trait Resolver: Send + Sync {
    fn lookup_cname(&self, domain: &str) -> Option<String>;
}

pub struct CnameLookup {
    /// The storage domains, each normalized to a leading-dot suffix
    /// (`example.com` -> `.example.com`), matching
    /// `CNAMELookupMiddleware.storage_domain`.
    pub storage_domain: Vec<String>,
    pub lookup_depth: usize,
    pub resolver: Arc<dyn Resolver>,
}

/// Parse the `storage_domain` conf value into the normalized suffix list,
/// exactly as the Python constructor does: undotted entries get a leading
/// `.` and come first, already-dotted entries are appended as-is.
fn parse_storage_domain(storage_domain: &str) -> Vec<String> {
    let mut out: Vec<String> = list_from_csv(storage_domain)
        .into_iter()
        .filter(|s| !s.starts_with('.'))
        .map(|s| format!(".{s}"))
        .collect();
    out.extend(
        list_from_csv(storage_domain)
            .into_iter()
            .filter(|s| s.starts_with('.')),
    );
    out
}

/// Port of `swift.common.utils.is_valid_ip` (`inet_pton` for IPv4 or IPv6).
fn is_valid_ip(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok()
}

/// swob `HTTPBadRequest(body=msg, content_type='text/plain')`.
fn bad_request(msg: &str) -> Response {
    let mut resp = Response::with_body(400, msg.as_bytes().to_vec());
    resp.headers.set("Content-Type", "text/plain");
    resp
}

/// The `_CnameLookupContext`/`RewriteContext` substitution: on the
/// `Location`/`Content-Location` response headers, rewrite an absolute URL
/// whose host is `rewritten` back to `requested`. Manual port of the regex
/// `^(https?://)<rewritten>(/.*)?$` -> `\1<requested>\2`.
fn rewrite_location_value(value: &str, rewritten: &str, requested: &str) -> String {
    for scheme in ["http://", "https://"] {
        if let Some(rest) = value.strip_prefix(scheme) {
            if let Some(after) = rest.strip_prefix(rewritten) {
                // group 2 is `(/.*)?$`: the remainder must be empty or start
                // with `/`, otherwise `rewritten` was only a host prefix.
                if after.is_empty() || after.starts_with('/') {
                    return format!("{scheme}{requested}{after}");
                }
            }
        }
    }
    value.to_string()
}

impl CnameLookup {
    pub fn new(storage_domain: &str, lookup_depth: usize, resolver: Arc<dyn Resolver>) -> Self {
        CnameLookup {
            storage_domain: parse_storage_domain(storage_domain),
            lookup_depth,
            resolver,
        }
    }

    /// Port of `_domain_endswith_in_storage_domain`.
    fn domain_endswith_in_storage_domain(&self, a_domain: &str) -> bool {
        let a = format!(".{a_domain}");
        self.storage_domain.iter().any(|d| a.ends_with(d))
    }
}

impl Middleware for CnameLookup {
    fn handle(&self, mut req: Request, next: &NextFn) -> Response {
        // No storage domain configured -> nothing to remap.
        if self.storage_domain.is_empty() {
            return next(req);
        }

        // `requested_host` keeps the port (used by the Location rewrite);
        // a missing Host passes through (see the SERVER_NAME deferral note).
        let requested_host = match req.headers.get("Host") {
            Some(h) => h.to_string(),
            None => return next(req),
        };

        // Strip a trailing `:port` (rsplit on the last colon, like Python).
        let mut given_domain = requested_host.as_str();
        let mut port = "";
        if let Some(idx) = given_domain.rfind(':') {
            port = &given_domain[idx + 1..];
            given_domain = &given_domain[..idx];
        }

        if is_valid_ip(given_domain) {
            return next(req);
        }

        let mut a_domain = given_domain.to_string();
        // Already inside the storage domain -> pass straight through with no
        // DNS lookup at all.
        if self.domain_endswith_in_storage_domain(&a_domain) {
            return next(req);
        }

        // Follow the CNAME chain up to `lookup_depth` hops.
        let mut error = true;
        let mut found_domain: Option<String> = None;
        for _ in 0..self.lookup_depth {
            let looked = self.resolver.lookup_cname(&a_domain);
            let empty = looked.as_deref().is_none_or(str::is_empty);
            if empty || looked.as_deref() == Some(a_domain.as_str()) {
                // No CNAME record, or a record pointing at itself: give up.
                error = true;
                found_domain = None;
                break;
            }
            let fd = looked.expect("checked non-empty above");
            if self.domain_endswith_in_storage_domain(&fd) {
                // Found it!
                error = false;
                found_domain = Some(fd);
                break;
            }
            // Try one hop deeper in the chain.
            found_domain = Some(fd.clone());
            a_domain = fd;
        }

        if error {
            let msg = if found_domain.is_some() {
                // ran out of hops while still following the chain
                format!("CNAME lookup failed after {} tries", self.lookup_depth)
            } else {
                "CNAME lookup failed to resolve to a valid domain".to_string()
            };
            return bad_request(&msg);
        }

        // Matched: rewrite the Host header (re-appending the port if any).
        let matched = found_domain.expect("error == false implies a match");
        let new_host = if port.is_empty() {
            matched
        } else {
            format!("{matched}:{port}")
        };
        req.headers.set("Host", &new_host);

        let mut resp = next(req);
        // Rewrite Location/Content-Location back to the requested host.
        for name in ["Location", "Content-Location"] {
            if let Some(current) = resp.headers.get(name).map(str::to_string) {
                let rewritten = rewrite_location_value(&current, &new_host, &requested_host);
                if rewritten != current {
                    resp.headers.set(name, rewritten);
                }
            }
        }
        resp
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use swift_http::HeaderKeyDict;

    /// A `Resolver` backed by a closure, plus a call counter.
    struct FnResolver<F> {
        f: F,
        calls: AtomicUsize,
    }
    impl<F: Fn(&str) -> Option<String> + Send + Sync> FnResolver<F> {
        fn new(f: F) -> Arc<Self> {
            Arc::new(FnResolver {
                f,
                calls: AtomicUsize::new(0),
            })
        }
    }
    impl<F: Fn(&str) -> Option<String> + Send + Sync> Resolver for FnResolver<F> {
        fn lookup_cname(&self, domain: &str) -> Option<String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            (self.f)(domain)
        }
    }

    fn req_with_host(host: Option<&str>) -> Request {
        let mut headers = HeaderKeyDict::new();
        if let Some(h) = host {
            headers.set("Host", h);
        }
        Request {
            method: "GET".into(),
            path: "/".into(),
            query_string: String::new(),
            headers,
            body: swift_http::Body::empty(),
        }
    }

    /// FakeApp: returns `200 FAKE APP` and echoes the Host it received.
    fn fake_app() -> NextFn {
        Arc::new(|req: Request| {
            let mut resp = Response::with_body(200, b"FAKE APP".to_vec());
            if let Some(h) = req.headers.get("Host") {
                resp.headers.set("X-Echo-Host", h);
            }
            resp
        })
    }

    fn body_of(resp: &mut Response) -> Vec<u8> {
        resp.body.materialize(u64::MAX).unwrap().to_vec()
    }

    // ----- passthrough cases -----

    #[test]
    fn test_pass_ip_addresses() {
        let r = FnResolver::new(|_| panic!("resolver must not be called for IPs"));
        let cn = CnameLookup::new("example.com", 2, r.clone());

        for host in ["10.134.23.198", "fc00:7ea1:f155::6321:8841"] {
            let mut resp = cn.handle(req_with_host(Some(host)), &fake_app());
            assert_eq!(body_of(&mut resp), b"FAKE APP");
            assert_eq!(resp.headers.get("X-Echo-Host"), Some(host));
        }
        assert_eq!(r.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_passthrough_already_in_storage_domain() {
        // Identity resolver; host already ends in the storage domain, so no
        // lookup happens and Host is untouched.
        let r = FnResolver::new(|d: &str| Some(d.to_string()));
        let cn = CnameLookup::new("example.com", 2, r.clone());

        for host in ["foo.example.com", "foo.example.com:8080"] {
            let mut resp = cn.handle(req_with_host(Some(host)), &fake_app());
            assert_eq!(body_of(&mut resp), b"FAKE APP");
            assert_eq!(resp.headers.get("X-Echo-Host"), Some(host));
        }
        assert_eq!(r.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_missing_host_passes_through() {
        let r = FnResolver::new(|_| None);
        let cn = CnameLookup::new("example.com", 2, r);
        let mut resp = cn.handle(req_with_host(None), &fake_app());
        assert_eq!(body_of(&mut resp), b"FAKE APP");
    }

    #[test]
    fn test_empty_storage_domain_passes_through() {
        let r = FnResolver::new(|_| None);
        let cn = CnameLookup::new("", 2, r.clone());
        let mut resp = cn.handle(req_with_host(Some("c.a.example.com")), &fake_app());
        assert_eq!(body_of(&mut resp), b"FAKE APP");
        assert_eq!(resp.headers.get("X-Echo-Host"), Some("c.a.example.com"));
        assert_eq!(r.calls.load(Ordering::SeqCst), 0);
    }

    // ----- successful remaps -----

    #[test]
    fn test_good_lookup_rewrites_host() {
        let r = FnResolver::new(|d: &str| Some(format!("{d}.example.com")));
        let cn = CnameLookup::new("example.com", 2, r);

        let mut resp = cn.handle(req_with_host(Some("mysite.com")), &fake_app());
        assert_eq!(body_of(&mut resp), b"FAKE APP");
        assert_eq!(resp.headers.get("X-Echo-Host"), Some("mysite.com.example.com"));
    }

    #[test]
    fn test_good_lookup_preserves_port() {
        let r = FnResolver::new(|d: &str| Some(format!("{d}.example.com")));
        let cn = CnameLookup::new("example.com", 2, r);

        let resp = cn.handle(req_with_host(Some("mysite.com:8080")), &fake_app());
        // the port is stripped before lookup (resolver sees "mysite.com") and
        // re-appended to the rewritten host afterwards
        assert_eq!(resp.headers.get("X-Echo-Host"), Some("mysite.com.example.com:8080"));
    }

    #[test]
    fn test_resolution_to_storage_domain_exactly() {
        // storage_domain == the resolved domain (minus leading dot) matches.
        let r = FnResolver::new(|_| Some("example.com".to_string()));
        let cn = CnameLookup::new("example.com", 1, r);

        let mut resp = cn.handle(req_with_host(Some("mysite.com")), &fake_app());
        assert_eq!(body_of(&mut resp), b"FAKE APP");
        assert_eq!(resp.headers.get("X-Echo-Host"), Some("example.com"));
    }

    #[test]
    fn test_multiple_storage_domains() {
        let make = |back: &'static str| {
            let r = FnResolver::new(move |_: &str| Some(back.to_string()));
            CnameLookup::new("storage1.com, storage2.com", 2, r)
        };

        for good in ["c.storage1.com", "c.storage2.com"] {
            let cn = make(good);
            let mut resp = cn.handle(req_with_host(Some("c.a.example.com")), &fake_app());
            assert_eq!(body_of(&mut resp), b"FAKE APP");
            assert_eq!(resp.headers.get("X-Echo-Host"), Some(good));
        }

        // c.badtest.com -> follows itself, exhausts, self-reference -> reject
        let cn = make("c.badtest.com");
        let mut resp = cn.handle(req_with_host(Some("c.a.example.com")), &fake_app());
        assert_eq!(resp.status, 400);
        assert_eq!(body_of(&mut resp), b"CNAME lookup failed to resolve to a valid domain");
    }

    // ----- rejections -----

    #[test]
    fn test_lookup_chain_too_long() {
        let r = FnResolver::new(|d: &str| {
            Some(
                match d {
                    "mysite.com" => "level1.foo.com",
                    "level1.foo.com" => "level2.foo.com",
                    "level2.foo.com" => "bar.example.com",
                    _ => "bar.example.com",
                }
                .to_string(),
            )
        });
        let cn = CnameLookup::new("example.com", 2, r);

        let mut resp = cn.handle(req_with_host(Some("mysite.com")), &fake_app());
        assert_eq!(resp.status, 400);
        assert_eq!(body_of(&mut resp), b"CNAME lookup failed after 2 tries");
        assert_eq!(resp.headers.get("Content-Type"), Some("text/plain"));
    }

    #[test]
    fn test_lookup_chain_bad_target() {
        // Always resolves to the same non-storage domain: second hop is a
        // self-reference -> "failed to resolve".
        let r = FnResolver::new(|_| Some("some.invalid.site.com".to_string()));
        let cn = CnameLookup::new("example.com", 2, r);

        let mut resp = cn.handle(req_with_host(Some("mysite.com")), &fake_app());
        assert_eq!(resp.status, 400);
        assert_eq!(body_of(&mut resp), b"CNAME lookup failed to resolve to a valid domain");
    }

    #[test]
    fn test_something_weird_none() {
        let r = FnResolver::new(|_| None);
        let cn = CnameLookup::new("example.com", 2, r);

        let mut resp = cn.handle(req_with_host(Some("mysite.com")), &fake_app());
        assert_eq!(resp.status, 400);
        assert_eq!(body_of(&mut resp), b"CNAME lookup failed to resolve to a valid domain");
    }

    #[test]
    fn test_cname_matching_ending_not_domain() {
        // 'c.aexample.com' ends in 'aexample.com', which does NOT match the
        // '.example.com' suffix (needs a dot boundary).
        let r = FnResolver::new(|_| Some("c.aexample.com".to_string()));
        let cn = CnameLookup::new("example.com", 2, r);

        let mut resp = cn.handle(req_with_host(Some("foo.com")), &fake_app());
        assert_eq!(resp.status, 400);
        assert_eq!(body_of(&mut resp), b"CNAME lookup failed to resolve to a valid domain");
    }

    #[test]
    fn test_host_is_storage_domain_skips_resolver() {
        // 'c.badtest.com' triggers exactly one (failing) lookup.
        let r = FnResolver::new(|_| None);
        let cn = CnameLookup::new("storage.example.com", 2, r.clone());
        let mut resp = cn.handle(req_with_host(Some("c.badtest.com")), &fake_app());
        assert_eq!(resp.status, 400);
        assert_eq!(body_of(&mut resp), b"CNAME lookup failed to resolve to a valid domain");
        assert_eq!(r.calls.load(Ordering::SeqCst), 1);

        // The host itself IS the storage domain -> passthrough, zero lookups.
        let r2 = FnResolver::new(|_| None);
        let cn2 = CnameLookup::new("storage.example.com", 2, r2.clone());
        let mut resp = cn2.handle(req_with_host(Some("storage.example.com")), &fake_app());
        assert_eq!(body_of(&mut resp), b"FAKE APP");
        assert_eq!(r2.calls.load(Ordering::SeqCst), 0);
    }

    // ----- Location rewrite (RewriteContext) -----

    #[test]
    fn test_redirect_rewrites_location() {
        let r = FnResolver::new(|_| Some("cont.acct.example.com".to_string()));
        let cn = CnameLookup::new("example.com", 1, r);

        // App redirects to an absolute URL built from the (rewritten) Host.
        let redirect_app: NextFn = Arc::new(|req: Request| {
            let host = req.headers.get("Host").unwrap_or("").to_string();
            let mut resp = Response::new(301);
            resp.headers.set("Location", format!("http://{host}/test/"));
            resp
        });

        let resp = cn.handle(req_with_host(Some("mysite.com")), &redirect_app);
        assert_eq!(resp.status, 301);
        assert_eq!(resp.headers.get("Location"), Some("http://mysite.com/test/"));
    }

    #[test]
    fn test_location_rewrite_leaves_foreign_urls_alone() {
        // A host that only prefix-matches the rewritten host must be untouched.
        assert_eq!(
            rewrite_location_value(
                "http://cont.acct.example.com.evil/x",
                "cont.acct.example.com",
                "mysite.com",
            ),
            "http://cont.acct.example.com.evil/x"
        );
        // Bare host, no path.
        assert_eq!(
            rewrite_location_value("https://a.example.com", "a.example.com", "mysite.com"),
            "https://mysite.com"
        );
    }

    // ----- config parsing -----

    #[test]
    fn test_storage_domains_conf_format() {
        assert_eq!(parse_storage_domain("foo.com"), vec![".foo.com"]);
        assert_eq!(parse_storage_domain("foo.com, "), vec![".foo.com"]);
        assert_eq!(
            parse_storage_domain("foo.com, bar.com"),
            vec![".foo.com", ".bar.com"]
        );
        assert_eq!(
            parse_storage_domain("foo.com, .bar.com"),
            vec![".foo.com", ".bar.com"]
        );
        assert_eq!(
            parse_storage_domain(".foo.com, .bar.com"),
            vec![".foo.com", ".bar.com"]
        );
    }
}
