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

//! `domain_remap`: translates the account/container parts of a virtual-host
//! `Host` header into a `/<path_root>/<account>/<container>/...` path the
//! proxy understands, a faithful port of
//! `swift/common/middleware/domain_remap.py`.
//!
//! The rewrite only fires when the host ends with one of the configured
//! `storage_domain` suffixes. The leftmost labels become the container and
//! account (`c.AUTH_a.example.com` -> account `AUTH_a`, container `c`); a
//! single label is account-only. The account's reseller prefix is
//! case-normalised against `reseller_prefixes` (browsers lowercase the
//! `Host`), a leading `-` is turned into `_`, and an unmatched prefix is
//! either given the `default_reseller_prefix` or left untouched (passthrough).
//! On success the request path is rewritten before the app runs, and any
//! `Location` / `Content-Location` on the response is rewritten back to the
//! client's virtual-host URL (Swift's `RewriteContext`).
//!
//! Deferred:
//!  * WSGI `SERVER_NAME` fallback — the owned `Request` carries no server
//!    name, so when the `Host` header is absent we pass the request through
//!    unchanged (Python falls back to `env['SERVER_NAME']`).
//!  * `wsgi_quote` re-encoding — the `Location` rewrite matches on the
//!    already-decoded path (no re-quoting); exact for the ASCII paths in the
//!    golden tests.
//!  * `filter_factory` / `register_swift_info` — the swift-info registry
//!    registration lives outside the middleware itself.

use swift_core::config::{config_true_value, list_from_csv};
use swift_http::{Request, Response};

use crate::{Middleware, NextFn};

pub struct DomainRemap {
    /// Normalised suffix list, each element beginning with `.`, in Python's
    /// order: dot-prepended entries first, then already-dotted entries.
    pub storage_domain: Vec<String>,
    /// Path root including the trailing `/`, e.g. `"v1/"`.
    pub path_root: String,
    pub reseller_prefixes: Vec<String>,
    reseller_prefixes_lower: Vec<String>,
    pub default_reseller_prefix: Option<String>,
    pub mangle_client_paths: bool,
}

impl Default for DomainRemap {
    fn default() -> Self {
        DomainRemap::from_conf(None, None, None, None, None)
    }
}

impl DomainRemap {
    /// Build from raw config strings, mirroring the Python `__init__`
    /// (each `conf.get(key, default)` is applied here).
    pub fn from_conf(
        storage_domain: Option<&str>,
        path_root: Option<&str>,
        reseller_prefixes: Option<&str>,
        default_reseller_prefix: Option<&str>,
        mangle_client_paths: Option<&str>,
    ) -> Self {
        let storage_domain_conf = storage_domain.unwrap_or("example.com");
        // ['.' + s for s in csv if not s.startswith('.')]
        let mut storage_domain: Vec<String> = list_from_csv(storage_domain_conf)
            .into_iter()
            .filter(|s| !s.starts_with('.'))
            .map(|s| format!(".{s}"))
            .collect();
        // += [s for s in csv if s.startswith('.')]
        storage_domain.extend(
            list_from_csv(storage_domain_conf)
                .into_iter()
                .filter(|s| s.starts_with('.')),
        );

        let path_root = format!("{}/", path_root.unwrap_or("v1").trim_matches('/'));

        let reseller_prefixes = list_from_csv(reseller_prefixes.unwrap_or("AUTH"));
        let reseller_prefixes_lower =
            reseller_prefixes.iter().map(|p| p.to_lowercase()).collect();

        DomainRemap {
            storage_domain,
            path_root,
            reseller_prefixes,
            reseller_prefixes_lower,
            default_reseller_prefix: default_reseller_prefix.map(str::to_string),
            mangle_client_paths: mangle_client_paths
                .map(config_true_value)
                .unwrap_or(false),
        }
    }
}

impl Middleware for DomainRemap {
    fn handle(&self, mut req: Request, next: &NextFn) -> Response {
        if self.storage_domain.is_empty() {
            return next(req);
        }
        // Source the virtual host from the `Host` header. (The WSGI
        // `SERVER_NAME` fallback has no equivalent on the owned Request; see
        // the module docs.)
        let given_domain = match req.headers.get("Host").map(str::to_string) {
            Some(h) => h,
            None => return next(req),
        };
        // Strip an optional `:port` on the last colon (Python captures the
        // port but never uses it).
        let given_domain = given_domain
            .rsplit_once(':')
            .map(|(host, _)| host.to_string())
            .unwrap_or(given_domain);

        // First storage domain the host ends with, else passthrough.
        let storage_domain = match self
            .storage_domain
            .iter()
            .find(|d| given_domain.ends_with(d.as_str()))
        {
            Some(d) => d.as_str(),
            None => return next(req),
        };

        let prefix = &given_domain[..given_domain.len() - storage_domain.len()];
        let parts: Vec<&str> = prefix.trim_matches('.').split('.').collect();
        let (container, mut account): (Option<String>, String) = match parts.len() {
            2 => (Some(parts[0].to_string()), parts[1].to_string()),
            1 => (None, parts[0].to_string()),
            _ => {
                let mut resp = Response::with_body(400, "Bad domain in host header");
                resp.headers.set("Content-Type", "text/plain");
                return resp;
            }
        };

        if !self.reseller_prefixes.is_empty() {
            if !account.contains('_') && account.contains('-') {
                account = account.replacen('-', "_", 1);
            }
            let account_reseller_prefix =
                account.split('_').next().unwrap_or("").to_lowercase();

            if let Some(idx) = self
                .reseller_prefixes_lower
                .iter()
                .position(|p| *p == account_reseller_prefix)
            {
                let real_prefix = &self.reseller_prefixes[idx];
                if !account.starts_with(real_prefix.as_str()) {
                    let account_suffix = &account[real_prefix.len()..];
                    account = format!("{real_prefix}{account_suffix}");
                }
            } else if self
                .default_reseller_prefix
                .as_deref()
                .is_some_and(|d| !d.is_empty())
            {
                // account prefix is not in config list. Add default one.
                let def = self.default_reseller_prefix.as_deref().unwrap();
                account = format!("{def}_{account}");
            } else {
                // account prefix is not in config list. bail.
                return next(req);
            }
        }

        let requested_path = req.path.clone();
        // path = requested_path[1:] — drop the first character.
        let path0 = {
            let mut chars = requested_path.chars();
            chars.next();
            chars.as_str().to_string()
        };
        // path_root[:-1] — drop the trailing '/'.
        let path_root_no_slash =
            self.path_root.strip_suffix('/').unwrap_or(&self.path_root).to_string();

        let mut new_path_parts: Vec<String> =
            vec![String::new(), path_root_no_slash, account];
        if let Some(c) = container {
            // Python `if container:` — falsy for None or empty string.
            if !c.is_empty() {
                new_path_parts.push(c);
            }
        }
        let mut path = path0;
        if self.mangle_client_paths && format!("{path}/").starts_with(&self.path_root) {
            // Python `path[len(self.path_root):]` — an out-of-range start
            // yields the empty string.
            path = path.get(self.path_root.len()..).unwrap_or("").to_string();
        }
        new_path_parts.push(path);
        let new_path = new_path_parts.join("/");
        req.path = new_path.clone();

        let mut resp = next(req);
        // RewriteContext: undo the remap in Location/Content-Location so a
        // redirect points back at the client's virtual-host URL.
        for name in ["Location", "Content-Location"] {
            if let Some(value) = resp.headers.get(name).map(str::to_string) {
                let rewritten = rewrite_location(&value, &new_path, &requested_path);
                if rewritten != value {
                    resp.headers.set(name, rewritten);
                }
            }
        }
        resp
    }
}

/// Port of `RewriteContext.base_re` substitution:
/// `^(https?://[^/]+)<rewritten>(.*)$` -> `\1<requested>\2`.
/// Literal (regex-escaped) match on `rewritten`, single substitution.
fn rewrite_location(value: &str, rewritten: &str, requested: &str) -> String {
    for scheme in ["http://", "https://"] {
        if let Some(rest) = value.strip_prefix(scheme) {
            // host is `[^/]+`: at least one char, up to the first '/'.
            let host_end = rest.find('/').unwrap_or(rest.len());
            if host_end == 0 {
                return value.to_string();
            }
            let (host, after) = rest.split_at(host_end);
            if let Some(tail) = after.strip_prefix(rewritten) {
                return format!("{scheme}{host}{requested}{tail}");
            }
            return value.to_string();
        }
    }
    value.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use swift_http::HeaderKeyDict;

    fn req(host: &str, path: &str) -> Request {
        let mut req = Request {
            method: "GET".into(),
            path: path.into(),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: swift_http::Body::empty(),
        };
        if !host.is_empty() {
            req.headers.set("Host", host);
        }
        req
    }

    /// FakeApp: echo the (rewritten) PATH_INFO into the body.
    fn echo() -> crate::NextFn {
        std::sync::Arc::new(|r: Request| Response::with_body(200, r.path))
    }

    /// Run through the middleware against the echo app; return the body.
    fn remap(app: &DomainRemap, host: &str, path: &str) -> String {
        let resp = app.handle(req(host, path), &echo());
        String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap()
    }

    #[test]
    fn test_passthrough() {
        let app = DomainRemap::default();
        // host equals (not endswith) the domain -> no remap
        assert_eq!(remap(&app, "example.com", "/"), "/");
        // port is stripped before the endswith check
        assert_eq!(remap(&app, "example.com:8080", "/"), "/");
        // no Host header -> passthrough (no SERVER_NAME on the owned Request)
        assert_eq!(remap(&app, "", "/"), "/");
    }

    #[test]
    fn test_account() {
        let app = DomainRemap::default();
        assert_eq!(remap(&app, "AUTH_a.example.com", "/"), "/v1/AUTH_a/");
        // hyphen after the reseller prefix becomes an underscore
        assert_eq!(remap(&app, "AUTH-uuid.example.com", "/"), "/v1/AUTH_uuid/");
    }

    #[test]
    fn test_account_container() {
        let app = DomainRemap::default();
        assert_eq!(remap(&app, "c.AUTH_a.example.com", "/"), "/v1/AUTH_a/c/");
    }

    #[test]
    fn test_extra_subdomains_is_bad_request() {
        let app = DomainRemap::default();
        let resp = app.handle(req("x.y.c.AUTH_a.example.com", "/"), &echo());
        assert_eq!(resp.status, 400);
        assert_eq!(
            String::from_utf8(resp.body.into_vec(u64::MAX).unwrap()).unwrap(),
            "Bad domain in host header"
        );
        assert_eq!(resp.headers.get("Content-Type"), Some("text/plain"));
    }

    #[test]
    fn test_account_with_path_root_container() {
        let app = DomainRemap::default();
        assert_eq!(remap(&app, "AUTH_a.example.com", "/v1"), "/v1/AUTH_a/v1");
    }

    #[test]
    fn test_account_with_path_root_unicode_container() {
        // Rust path is the decoded (UTF-8) PATH_INFO.
        let app = DomainRemap::default();
        assert_eq!(
            remap(&app, "AUTH_a.example.com", "/\u{4f60}\u{597d}"),
            "/v1/AUTH_a/\u{4f60}\u{597d}"
        );
    }

    #[test]
    fn test_account_container_with_path_root_obj() {
        let app = DomainRemap::default();
        assert_eq!(remap(&app, "c.AUTH_a.example.com", "/v1"), "/v1/AUTH_a/c/v1");
    }

    #[test]
    fn test_account_container_with_path_obj_slash_v1() {
        let app = DomainRemap::default();
        assert_eq!(
            remap(&app, "c.AUTH_a.example.com", "//v1"),
            "/v1/AUTH_a/c//v1"
        );
    }

    #[test]
    fn test_account_container_with_root_path_obj_slash_v1() {
        let app = DomainRemap::default();
        assert_eq!(
            remap(&app, "c.AUTH_a.example.com", "/v1//v1"),
            "/v1/AUTH_a/c/v1//v1"
        );
    }

    #[test]
    fn test_account_container_with_path_trailing_slash() {
        let app = DomainRemap::default();
        assert_eq!(
            remap(&app, "c.AUTH_a.example.com", "/obj/"),
            "/v1/AUTH_a/c/obj/"
        );
    }

    #[test]
    fn test_account_container_with_path() {
        let app = DomainRemap::default();
        assert_eq!(remap(&app, "c.AUTH_a.example.com", "/obj"), "/v1/AUTH_a/c/obj");
    }

    #[test]
    fn test_account_container_with_path_root_and_path() {
        let app = DomainRemap::default();
        assert_eq!(
            remap(&app, "c.AUTH_a.example.com", "/v1/obj"),
            "/v1/AUTH_a/c/v1/obj"
        );
    }

    #[test]
    fn test_with_path_root_and_path_no_slash() {
        let app = DomainRemap::default();
        assert_eq!(
            remap(&app, "c.AUTH_a.example.com", "/v1obj"),
            "/v1/AUTH_a/c/v1obj"
        );
    }

    #[test]
    fn test_account_matching_ending_not_domain() {
        let app = DomainRemap::default();
        assert_eq!(remap(&app, "c.aexample.com", "/dontchange"), "/dontchange");
    }

    #[test]
    fn test_configured_with_empty_storage_domain() {
        let app = DomainRemap::from_conf(Some(""), None, None, None, None);
        assert!(app.storage_domain.is_empty());
        assert_eq!(remap(&app, "c.AUTH_a.example.com", "/test"), "/test");
    }

    #[test]
    fn test_storage_domains_conf_format() {
        let dom = |s: &str| DomainRemap::from_conf(Some(s), None, None, None, None).storage_domain;
        assert_eq!(dom("foo.com"), vec![".foo.com"]);
        assert_eq!(dom("foo.com, "), vec![".foo.com"]);
        assert_eq!(dom("foo.com, bar.com"), vec![".foo.com", ".bar.com"]);
        assert_eq!(dom("foo.com, .bar.com"), vec![".foo.com", ".bar.com"]);
        assert_eq!(dom(".foo.com, .bar.com"), vec![".foo.com", ".bar.com"]);
        // default
        assert_eq!(DomainRemap::default().storage_domain, vec![".example.com"]);
    }

    #[test]
    fn test_configured_with_prefixes() {
        let app = DomainRemap::from_conf(None, None, Some("PREFIX"), None, None);
        assert_eq!(
            remap(&app, "c.prefix_uuid.example.com", "/test"),
            "/v1/PREFIX_uuid/c/test"
        );
    }

    #[test]
    fn test_configured_with_bad_prefixes() {
        let app = DomainRemap::from_conf(None, None, Some("UNKNOWN"), None, None);
        assert_eq!(remap(&app, "c.prefix_uuid.example.com", "/test"), "/test");
    }

    #[test]
    fn test_configured_with_no_prefixes() {
        let app = DomainRemap::from_conf(None, None, Some(""), None, None);
        assert!(app.reseller_prefixes.is_empty());
        assert_eq!(remap(&app, "c.uuid.example.com", "/test"), "/v1/uuid/c/test");
    }

    #[test]
    fn test_add_prefix() {
        let app = DomainRemap::from_conf(None, None, None, Some("FOO"), None);
        assert_eq!(remap(&app, "uuid.example.com", "/test"), "/v1/FOO_uuid/test");
    }

    #[test]
    fn test_add_prefix_already_there() {
        let app = DomainRemap::from_conf(None, None, None, Some("AUTH"), None);
        assert_eq!(
            remap(&app, "auth-uuid.example.com", "/test"),
            "/v1/AUTH_uuid/test"
        );
    }

    #[test]
    fn test_multiple_storage_domains() {
        let app =
            DomainRemap::from_conf(Some("storage1.com, storage2.com"), None, None, None, None);
        assert_eq!(remap(&app, "auth-uuid.storage1.com", "/test"), "/v1/AUTH_uuid/test");
        assert_eq!(remap(&app, "auth-uuid.storage2.com", "/test"), "/v1/AUTH_uuid/test");
        // not one of the configured domains -> passthrough
        assert_eq!(remap(&app, "auth-uuid.storage3.com", "/test"), "/test");
    }

    #[test]
    fn test_redirect() {
        let app = DomainRemap::default();
        // RedirectSlashApp: absolute Location = http://<host><rewritten>/ .
        let redirect: crate::NextFn = std::sync::Arc::new(|r: Request| {
            let host = r.headers.get("Host").unwrap_or("").to_string();
            let loc = format!("http://{host}{}/", r.path);
            let mut resp = Response::new(301);
            resp.headers.set("Location", loc);
            resp
        });
        let run = |host: &str, path: &str| {
            let resp = app.handle(req(host, path), &redirect);
            (resp.status, resp.headers.get("Location").unwrap().to_string())
        };

        assert_eq!(
            run("auth-uuid.example.com", "/cont"),
            (301, "http://auth-uuid.example.com/cont/".to_string())
        );
        assert_eq!(
            run("auth-uuid.example.com", "/cont/test"),
            (301, "http://auth-uuid.example.com/cont/test/".to_string())
        );
        assert_eq!(
            run("cont.auth-uuid.example.com", "/test"),
            (301, "http://cont.auth-uuid.example.com/test/".to_string())
        );
    }

    // ---- mangle_client_paths = True -------------------------------------

    fn mangling() -> DomainRemap {
        DomainRemap::from_conf(None, None, None, None, Some("true"))
    }

    #[test]
    fn test_mangle_account_with_path_root_container() {
        assert_eq!(remap(&mangling(), "AUTH_a.example.com", "/v1"), "/v1/AUTH_a/");
    }

    #[test]
    fn test_mangle_account_container_with_path_root_obj() {
        assert_eq!(remap(&mangling(), "c.AUTH_a.example.com", "/v1"), "/v1/AUTH_a/c/");
    }

    #[test]
    fn test_mangle_account_container_with_path_obj_slash_v1() {
        // path '//v1' -> stripped to '/v1' which does NOT start with 'v1/'.
        assert_eq!(
            remap(&mangling(), "c.AUTH_a.example.com", "//v1"),
            "/v1/AUTH_a/c//v1"
        );
    }

    #[test]
    fn test_mangle_account_container_with_root_path_obj_slash_v1() {
        // path '/v1//v1' -> 'v1//v1' starts with 'v1/' -> mangled to '/v1'.
        assert_eq!(
            remap(&mangling(), "c.AUTH_a.example.com", "/v1//v1"),
            "/v1/AUTH_a/c//v1"
        );
    }

    #[test]
    fn test_mangle_account_container_with_path_trailing_slash() {
        assert_eq!(
            remap(&mangling(), "c.AUTH_a.example.com", "/obj/"),
            "/v1/AUTH_a/c/obj/"
        );
    }

    #[test]
    fn test_mangle_account_container_with_path_root_and_path() {
        // 'v1/obj' starts with 'v1/' -> mangled to 'obj'.
        assert_eq!(
            remap(&mangling(), "c.AUTH_a.example.com", "/v1/obj"),
            "/v1/AUTH_a/c/obj"
        );
    }

    #[test]
    fn test_mangle_with_path_root_and_path_no_slash() {
        // 'v1obj/' does not start with 'v1/' -> unchanged.
        assert_eq!(
            remap(&mangling(), "c.AUTH_a.example.com", "/v1obj"),
            "/v1/AUTH_a/c/v1obj"
        );
    }
}
