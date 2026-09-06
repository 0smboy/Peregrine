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

//! `staticweb`, ported from `swift/common/middleware/staticweb.py`.
//!
//! A container flagged with `X-Container-Meta-Web-Index` and/or
//! `-Web-Listings` is served like a static website: a GET to the container (or
//! a pseudo-directory) resolves to its index object, or falls back to an HTML
//! listing of the objects and sub-directories. This middleware learns the
//! config from a container HEAD, then either serves the index (a GET
//! subrequest) or builds the listing (from a delimiter-`/` container-listing
//! subrequest).
//!
//! The listing HTML structure mirrors Python's (`Listing of …`, a table with
//! Name/Size/Date columns, a `../` parent row, `subdir` rows, then object rows
//! carrying `type-<ct>` classes and human-readable sizes). Deferred: the CSS
//! path building, tempurl query-string propagation, custom Web-Error docs,
//! and directory-marker suppression.
//!
//! Production Hyper serve never calls `handle()` for ordinary GET/HEAD.
//! Index + HTML listing run in [`Middleware::reassemble_async`]: the first
//! `next()` is the captured app response (container/object GET); further
//! `next()` calls issue the container HEAD, index GET, and delimiter-`/`
//! listing. `handle()` keeps the same behaviour for the sync pipeline.

use std::future::Future;
use std::pin::Pin;

use swift_core::config::config_true_value;
use swift_http::{split_path, Body, HeaderKeyDict, Request, Response, MAX_CONTROL_BODY};

use crate::{AsyncNextFn, Middleware, NextFn};

/// The `staticweb` middleware.
#[derive(Default)]
pub struct StaticWeb;

impl StaticWeb {
    pub fn new() -> Self {
        StaticWeb
    }
}

/// `human_readable`: a byte count as `"<n>"`, or `"<n>Ki/Mi/Gi/…"` once it
/// reaches 1024, with round-half-to-even at each division (matching Python's
/// `round`).
pub fn human_readable(value: u64) -> String {
    let suffixes = ['K', 'M', 'G', 'T', 'P', 'E', 'Z', 'Y'];
    let mut v = value as f64;
    let mut index: i32 = -1;
    while v >= 1024.0 && (index + 1) < suffixes.len() as i32 {
        index += 1;
        v = round_half_even(v / 1024.0);
    }
    if index == -1 {
        format!("{}", value)
    } else {
        format!("{}{}i", v as u64, suffixes[index as usize])
    }
}

/// Round half to even (Python 3 `round`).
fn round_half_even(x: f64) -> f64 {
    let floor = x.floor();
    let diff = x - floor;
    if diff < 0.5 {
        floor
    } else if diff > 0.5 {
        floor + 1.0
    } else if (floor as i64) % 2 == 0 {
        floor
    } else {
        floor + 1.0
    }
}

/// `html.escape`: escape `&`, `<`, `>`, `"`, `'`.
pub fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
    out
}

/// Percent-encode a path component the way `urllib.parse.quote` does with the
/// default safe set (letters, digits, `_.-~` and `/`).
fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-' | b'~' | b'/' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// One entry from a container listing (the fields staticweb renders).
#[derive(Debug, Clone)]
pub enum ListingItem {
    Subdir(String),
    Object {
        name: String,
        content_type: String,
        bytes: u64,
        last_modified: String,
    },
}

/// Build the HTML listing body, byte-compatible with Python's `_listing`
/// (default CSS branch). `label` is the display label, `prefix` the pseudo-dir
/// prefix already applied to the listing.
pub fn build_listing_html(label: &str, prefix: &str, items: &[ListingItem]) -> String {
    build_listing_html_full(label, prefix, items, None, "", "")
}

fn build_listing_html_full(
    label: &str,
    prefix: &str,
    items: &[ListingItem],
    listings_css: Option<&str>,
    tempurl_qs: &str,
    tempurl_prefix: &str,
) -> String {
    let esc_label = html_escape(label);
    let mut body = String::new();
    body.push_str("<!DOCTYPE html>\n<html>\n <head>\n");
    body.push_str(&format!("  <title>Listing of {esc_label}</title>\n"));
    if let Some(css) = listings_css {
        body.push_str(&format!(
            "  <link type=\"text/css\" rel=\"stylesheet\" href=\"{}\" />\n",
            html_escape(css)
        ));
    } else {
        body.push_str(
            "  <style type=\"text/css\">\n\
             \x20  h1 {font-size: 1em; font-weight: bold;}\n\
             \x20  th {text-align: left; padding: 0px 1em 0px 1em;}\n\
             \x20  td {padding: 0px 1em 0px 1em;}\n\
             \x20  a {text-decoration: none;}\n\
             \x20 </style>\n",
        );
    }
    body.push_str(" </head>\n <body>\n");
    body.push_str(&format!("  <h1 id=\"title\">Listing of {esc_label}</h1>\n"));
    body.push_str("  <table id=\"listing\">\n   <tr id=\"heading\">\n");
    body.push_str("    <th class=\"colname\">Name</th>\n");
    body.push_str("    <th class=\"colsize\">Size</th>\n");
    body.push_str("    <th class=\"coldate\">Date</th>\n   </tr>\n");

    if prefix.len() > tempurl_prefix.len() {
        body.push_str(&format!(
            "   <tr id=\"parent\" class=\"item\">\n\
             \x20   <td class=\"colname\"><a href=\"../{tempurl_qs}\">../</a></td>\n\
             \x20   <td class=\"colsize\">&nbsp;</td>\n\
             \x20   <td class=\"coldate\">&nbsp;</td>\n   </tr>\n",
        ));
    }

    for item in items {
        if let ListingItem::Subdir(subdir) = item {
            let shown = subdir.strip_prefix(prefix).unwrap_or(subdir);
            body.push_str("   <tr class=\"item subdir\">\n");
            body.push_str(&format!(
                "    <td class=\"colname\"><a href=\"{}{}\">{}</a></td>\n",
                quote(shown),
                tempurl_qs,
                html_escape(shown)
            ));
            body.push_str(
                "    <td class=\"colsize\">&nbsp;</td>\n\
                 \x20   <td class=\"coldate\">&nbsp;</td>\n   </tr>\n",
            );
        }
    }
    for item in items {
        if let ListingItem::Object {
            name,
            content_type,
            bytes,
            last_modified,
        } = item
        {
            let shown = name.strip_prefix(prefix).unwrap_or(name);
            let classes: Vec<String> = content_type
                .split('/')
                .map(|t| format!("type-{}", html_escape(&t.to_lowercase())))
                .collect();
            let date = last_modified
                .split('.')
                .next()
                .unwrap_or("")
                .replace('T', " ");
            body.push_str(&format!("   <tr class=\"item {}\">\n", classes.join(" ")));
            body.push_str(&format!(
                "    <td class=\"colname\"><a href=\"{}{}\">{}</a></td>\n",
                quote(shown),
                tempurl_qs,
                html_escape(shown)
            ));
            body.push_str(&format!(
                "    <td class=\"colsize\">{}</td>\n",
                human_readable(*bytes)
            ));
            body.push_str(&format!(
                "    <td class=\"coldate\">{}</td>\n   </tr>\n",
                html_escape(&date)
            ));
        }
    }
    body.push_str("  </table>\n </body>\n</html>\n");
    body
}

fn parse_listing(json: &[u8]) -> Vec<ListingItem> {
    let value: serde_json::Value = match serde_json::from_slice(json) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let mut items = Vec::new();
    if let Some(arr) = value.as_array() {
        for it in arr {
            if let Some(subdir) = it.get("subdir").and_then(|v| v.as_str()) {
                items.push(ListingItem::Subdir(subdir.to_string()));
            } else if let Some(name) = it.get("name").and_then(|v| v.as_str()) {
                items.push(ListingItem::Object {
                    name: name.to_string(),
                    content_type: it
                        .get("content_type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("application/octet-stream")
                        .to_string(),
                    bytes: it.get("bytes").and_then(|v| v.as_u64()).unwrap_or(0),
                    last_modified: it
                        .get("last_modified")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                });
            }
        }
    }
    items
}

#[derive(Debug, Default, Clone)]
struct WebConfig {
    index: Option<String>,
    listings: bool,
    listings_css: Option<String>,
    listings_label: Option<String>,
    dir_type: String,
}

impl WebConfig {
    fn from_headers(headers: &HeaderKeyDict) -> Self {
        let meta = |name: &str| {
            headers
                .get(name)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        };
        WebConfig {
            index: meta("X-Container-Meta-Web-Index"),
            listings: headers
                .get("X-Container-Meta-Web-Listings")
                .is_some_and(config_true_value),
            listings_css: meta("X-Container-Meta-Web-Listings-Css")
                .or_else(|| meta("X-Container-Meta-Web-Listings-CSS")),
            listings_label: meta("X-Container-Meta-Web-Listings-Label"),
            dir_type: meta("X-Container-Meta-Web-Directory-Type")
                .unwrap_or_else(|| "application/directory".to_string()),
        }
    }

    fn enabled(&self) -> bool {
        self.index.is_some() || self.listings
    }
}

struct Scope {
    version: String,
    account: String,
    container: String,
    obj: String,
}

impl Scope {
    fn parse(req: &Request) -> Option<Self> {
        let parts = split_path(&req.path, 3, 4, true).ok()?;
        let container = parts[2].clone().unwrap_or_default();
        if container.is_empty() {
            return None;
        }
        Some(Scope {
            version: parts[0].clone().unwrap_or_default(),
            account: parts[1].clone().unwrap_or_default(),
            container,
            obj: parts[3].clone().unwrap_or_default(),
        })
    }

    fn container_path(&self) -> String {
        format!("/{}/{}/{}", self.version, self.account, self.container)
    }

    fn listing_label(&self, req: &Request, cfg: &WebConfig) -> String {
        if let Some(label) = &cfg.listings_label {
            let rest = if self.obj.is_empty() {
                String::new()
            } else {
                format!("/{}", self.obj.trim_end_matches('/'))
            };
            if rest.is_empty() {
                format!("{label}/")
            } else {
                format!("{label}{rest}/")
            }
        } else if req.path.ends_with('/') {
            req.path.clone()
        } else {
            format!("{}/", req.path)
        }
    }
}

fn is_get_head(req: &Request) -> bool {
    matches!(req.method.as_str(), "GET" | "HEAD")
}

/// Python: skip unless anonymous, TempURL, or `X-Web-Mode`.
fn web_mode_allowed(req: &Request) -> bool {
    let user = req.headers.get("X-Backend-Remote-User").unwrap_or("");
    if user.is_empty() || user == ".wsgi.tempurl" {
        return true;
    }
    req.headers.get("X-Web-Mode").is_some_and(config_true_value)
}

fn is_success(status: u16) -> bool {
    (200..300).contains(&status)
}

fn is_redirect(status: u16) -> bool {
    (300..400).contains(&status)
}

fn is_dir_marker(resp: &Response, dir_type: &str) -> bool {
    let ct = resp
        .headers
        .get("Content-Type")
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim();
    let len = resp
        .headers
        .get("Content-Length")
        .and_then(|s| s.parse::<u64>().ok())
        .or_else(|| resp.body.content_length())
        .unwrap_or(0);
    ct.eq_ignore_ascii_case(dir_type) && len <= 1
}

fn redirect_with_slash(req: &Request) -> Response {
    let path = if req.path.ends_with('/') {
        req.path.clone()
    } else {
        format!("{}/", req.path)
    };
    let quoted = quote(&path);
    let host = req.headers.get("Host").unwrap_or("").trim();
    let scheme = req
        .headers
        .get("X-Forwarded-Proto")
        .or_else(|| req.headers.get("X-Backend-Proto"))
        .unwrap_or("http")
        .trim();
    let location = if host.is_empty() {
        quoted
    } else {
        format!("{scheme}://{host}{quoted}")
    };
    let mut resp = Response::new(301);
    resp.headers.set("Location", location);
    resp
}

fn css_href(css: &str, prefix: &str) -> String {
    if css.starts_with('/') || css.starts_with("http://") || css.starts_with("https://") {
        quote_safe(css, b":/")
    } else {
        format!(
            "{}{}",
            "../".repeat(prefix.matches('/').count()),
            quote(css)
        )
    }
}

fn quote_safe(s: &str, extra: &[u8]) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-' | b'~' => {
                out.push(b as char)
            }
            _ if extra.contains(&b) => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn tempurl_listing_bits(req: &Request) -> (String, String) {
    if req.headers.get("X-Backend-Remote-User") != Some(".wsgi.tempurl") {
        return (String::new(), String::new());
    }
    let params = req.params();
    let first = |key: &str| -> Option<String> {
        params
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
    };
    let Some(sig) = first("temp_url_sig").filter(|s| !s.is_empty()) else {
        return (String::new(), String::new());
    };
    let expires = first("temp_url_expires").unwrap_or_default();
    let prefix = first("temp_url_prefix").unwrap_or_default();
    let mut parts = vec![
        format!("temp_url_prefix={}", quote(&prefix)),
        format!("temp_url_expires={}", quote(&expires)),
        format!("temp_url_sig={}", quote(&sig)),
    ];
    if let Some(ip) = first("temp_url_ip_range") {
        parts.push(format!("temp_url_ip_range={}", quote(&ip)));
    }
    if params.iter().any(|(k, _)| k == "inline") {
        parts.push("inline".to_string());
    }
    (format!("?{}", parts.join("&amp;")), prefix)
}

fn listing_subrequest(scope: &Scope, prefix: &str) -> Request {
    let mut list_req = Request {
        method: "GET".to_string(),
        path: scope.container_path(),
        query_string: if prefix.is_empty() {
            "delimiter=/&format=json".to_string()
        } else {
            format!("delimiter=/&format=json&prefix={}", quote(prefix))
        },
        headers: HeaderKeyDict::new(),
        body: Body::empty(),
    };
    list_req.headers.set("X-Backend-Source", "staticweb");
    list_req
}

fn index_subrequest(scope: &Scope, prefix: &str, index: &str) -> Request {
    Request {
        method: "GET".to_string(),
        path: format!("{}/{prefix}{index}", scope.container_path()),
        query_string: String::new(),
        headers: HeaderKeyDict::new(),
        body: Body::empty(),
    }
}

fn container_head_request(req: &Request, scope: &Scope) -> Request {
    let mut head = req.clone_head();
    head.method = "HEAD".to_string();
    head.path = scope.container_path();
    head.query_string = String::new();
    head.headers.remove("Content-Length");
    head
}

fn html_listing_response(
    req: &Request,
    scope: &Scope,
    cfg: &WebConfig,
    prefix: &str,
    items: &[ListingItem],
) -> Response {
    if !prefix.is_empty() && items.is_empty() {
        return Response::error(404, "Not Found");
    }
    let (tempurl_qs, tempurl_prefix) = tempurl_listing_bits(req);
    let css = cfg.listings_css.as_deref().map(|c| css_href(c, prefix));
    let html = build_listing_html_full(
        &scope.listing_label(req, cfg),
        prefix,
        items,
        css.as_deref(),
        &tempurl_qs,
        &tempurl_prefix,
    );
    let mut out = Response::with_body(200, html.into_bytes());
    out.headers.set("Content-Type", "text/html; charset=UTF-8");
    out.headers.set("X-Backend-Content-Generator", "staticweb");
    out
}

fn listing_from_response(
    req: &Request,
    scope: &Scope,
    cfg: &WebConfig,
    prefix: &str,
    mut resp: Response,
) -> Response {
    if !is_success(resp.status) {
        return resp;
    }
    if resp.body.materialize(MAX_CONTROL_BODY).is_err() {
        return resp;
    }
    let items = parse_listing(resp.body.materialize(MAX_CONTROL_BODY).expect("buffered"));
    html_listing_response(req, scope, cfg, prefix, &items)
}

impl StaticWeb {
    fn serve_listing(
        &self,
        req: &Request,
        scope: &Scope,
        cfg: &WebConfig,
        prefix: &str,
        next: &NextFn,
    ) -> Response {
        if !cfg.listings {
            return Response::error(404, "Not Found");
        }
        listing_from_response(
            req,
            scope,
            cfg,
            prefix,
            next(listing_subrequest(scope, prefix)),
        )
    }

    fn handle_container(
        &self,
        req: Request,
        scope: Scope,
        cfg: WebConfig,
        next: &NextFn,
    ) -> Response {
        if !cfg.enabled() {
            if req.headers.get("X-Web-Mode").is_some_and(config_true_value) {
                return Response::error(404, "Not Found");
            }
            return next(req);
        }
        if !req.path.ends_with('/') {
            return redirect_with_slash(&req);
        }
        if let Some(index) = &cfg.index {
            let index_resp = next(index_subrequest(&scope, "", index));
            if is_success(index_resp.status) || is_redirect(index_resp.status) {
                return index_resp;
            }
        }
        self.serve_listing(&req, &scope, &cfg, "", next)
    }

    fn handle_object(
        &self,
        req: Request,
        scope: Scope,
        mut first: Response,
        cfg: WebConfig,
        next: &NextFn,
    ) -> Response {
        if is_success(first.status) || is_redirect(first.status) {
            if is_dir_marker(&first, &cfg.dir_type) {
                first = Response::error(404, "Not Found");
            } else {
                return first;
            }
        }
        if first.status != 404 || !cfg.enabled() {
            return first;
        }
        let prefix = if scope.obj.ends_with('/') {
            scope.obj.clone()
        } else {
            format!("{}/", scope.obj)
        };
        if let Some(index) = &cfg.index {
            let index_resp = next(index_subrequest(&scope, &prefix, index));
            if is_success(index_resp.status) || is_redirect(index_resp.status) {
                if !req.path.ends_with('/') {
                    return redirect_with_slash(&req);
                }
                return index_resp;
            }
        }
        if !req.path.ends_with('/') {
            let mut probe = listing_subrequest(&scope, &prefix);
            probe.query_string =
                format!("limit=1&delimiter=/&format=json&prefix={}", quote(&prefix));
            let mut probe_resp = next(probe);
            if !is_success(probe_resp.status)
                || probe_resp.body.materialize(MAX_CONTROL_BODY).is_err()
            {
                return first;
            }
            let items = parse_listing(
                probe_resp
                    .body
                    .materialize(MAX_CONTROL_BODY)
                    .expect("buffered"),
            );
            if items.is_empty() {
                return first;
            }
            return redirect_with_slash(&req);
        }
        self.serve_listing(&req, &scope, &cfg, &scope.obj, next)
    }
}

impl Middleware for StaticWeb {
    fn intercepts_response(&self) -> bool {
        true
    }

    fn reassemble_async(
        &self,
        req: Request,
        next: AsyncNextFn,
    ) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        Box::pin(async move {
            if !is_get_head(&req) || !web_mode_allowed(&req) {
                return next(req).await;
            }
            let Some(scope) = Scope::parse(&req) else {
                return next(req).await;
            };
            let path_has_slash = req.path.ends_with('/');
            let web_mode = req.headers.get("X-Web-Mode").is_some_and(config_true_value);
            let head = req.clone_head();
            let head_req = container_head_request(&req, &scope);
            // First next() is the captured original app response.
            let first = next(req.clone_head()).await;
            if scope.obj.is_empty() {
                let cfg = if is_success(first.status) {
                    WebConfig::from_headers(&first.headers)
                } else {
                    WebConfig::from_headers(&next(head_req).await.headers)
                };
                if !cfg.enabled() {
                    if web_mode {
                        return Response::error(404, "Not Found");
                    }
                    return first;
                }
                if !path_has_slash {
                    return redirect_with_slash(&head);
                }
                if let Some(index) = &cfg.index {
                    let index_resp = next(index_subrequest(&scope, "", index)).await;
                    if is_success(index_resp.status) || is_redirect(index_resp.status) {
                        return index_resp;
                    }
                }
                if !cfg.listings {
                    return Response::error(404, "Not Found");
                }
                let listing = next(listing_subrequest(&scope, "")).await;
                return listing_from_response(&head, &scope, &cfg, "", listing);
            }

            let cfg = WebConfig::from_headers(&next(head_req).await.headers);
            let mut first = first;
            if is_success(first.status) || is_redirect(first.status) {
                if is_dir_marker(&first, &cfg.dir_type) {
                    first = Response::error(404, "Not Found");
                } else {
                    return first;
                }
            }
            if first.status != 404 || !cfg.enabled() {
                return first;
            }
            let prefix = if scope.obj.ends_with('/') {
                scope.obj.clone()
            } else {
                format!("{}/", scope.obj)
            };
            if let Some(index) = &cfg.index {
                let index_resp = next(index_subrequest(&scope, &prefix, index)).await;
                if is_success(index_resp.status) || is_redirect(index_resp.status) {
                    if !path_has_slash {
                        return redirect_with_slash(&head);
                    }
                    return index_resp;
                }
            }
            if !path_has_slash {
                let mut probe = listing_subrequest(&scope, &prefix);
                probe.query_string =
                    format!("limit=1&delimiter=/&format=json&prefix={}", quote(&prefix));
                let mut probe_resp = next(probe).await;
                if !is_success(probe_resp.status)
                    || probe_resp.body.materialize(MAX_CONTROL_BODY).is_err()
                {
                    return first;
                }
                let items = parse_listing(
                    probe_resp
                        .body
                        .materialize(MAX_CONTROL_BODY)
                        .expect("buffered"),
                );
                if items.is_empty() {
                    return first;
                }
                return redirect_with_slash(&head);
            }
            if !cfg.listings {
                return Response::error(404, "Not Found");
            }
            let listing = next(listing_subrequest(&scope, &scope.obj)).await;
            listing_from_response(&head, &scope, &cfg, &scope.obj, listing)
        })
    }

    fn handle(&self, req: Request, next: &NextFn) -> Response {
        if !is_get_head(&req) || !web_mode_allowed(&req) {
            return next(req);
        }
        let Some(scope) = Scope::parse(&req) else {
            return next(req);
        };
        if scope.obj.is_empty() {
            let cfg = WebConfig::from_headers(&next(container_head_request(&req, &scope)).headers);
            return self.handle_container(req, scope, cfg, next);
        }
        let first = next(req.clone_head());
        let cfg = WebConfig::from_headers(&next(container_head_request(&req, &scope)).headers);
        self.handle_object(req, scope, first, cfg, next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn test_human_readable() {
        assert_eq!(human_readable(0), "0");
        assert_eq!(human_readable(512), "512");
        assert_eq!(human_readable(1023), "1023");
        assert_eq!(human_readable(1024), "1Ki");
        assert_eq!(human_readable(1536), "2Ki"); // round-half-even 1.5 -> 2
        assert_eq!(human_readable(1048576), "1Mi");
        assert_eq!(human_readable(1073741824), "1Gi");
    }

    #[test]
    fn test_html_escape() {
        assert_eq!(html_escape("a<b>&\"'"), "a&lt;b&gt;&amp;&quot;&#x27;");
    }

    #[test]
    fn test_listing_html_includes_css() {
        let html = build_listing_html_full("/v1/a/c/", "", &[], Some("listings.css"), "", "");
        assert!(
            html.contains(r#"<link type="text/css" rel="stylesheet" href="listings.css" />"#),
            "{html}"
        );
    }

    #[test]
    fn test_listing_html_structure() {
        let items = vec![
            ListingItem::Subdir("photos/".into()),
            ListingItem::Object {
                name: "readme.txt".into(),
                content_type: "text/plain".into(),
                bytes: 2048,
                last_modified: "2026-07-16T12:00:00.000000".into(),
            },
        ];
        let html = build_listing_html("/v1/a/c/", "", &items);
        assert!(html.contains("<title>Listing of /v1/a/c/</title>"));
        assert!(html.contains("class=\"item subdir\""));
        assert!(html.contains("<a href=\"photos/\">photos/</a>"));
        assert!(html.contains("class=\"item type-text type-plain\""));
        assert!(html.contains("<td class=\"colsize\">2Ki</td>"));
        assert!(html.contains("<td class=\"coldate\">2026-07-16 12:00:00</td>"));
    }

    #[allow(clippy::type_complexity)]
    fn backend(
        index: Option<&'static str>,
        listings: bool,
        index_exists: bool,
    ) -> (Arc<Mutex<Vec<(String, String)>>>, crate::NextFn) {
        let log = Arc::new(Mutex::new(Vec::new()));
        let log2 = log.clone();
        let app: crate::NextFn = Arc::new(move |r: Request| {
            log2.lock()
                .unwrap()
                .push((r.method.clone(), r.path.clone()));
            if r.method == "HEAD" {
                let mut resp = Response::new(204);
                if let Some(i) = index {
                    resp.headers.set("X-Container-Meta-Web-Index", i);
                }
                if listings {
                    resp.headers.set("X-Container-Meta-Web-Listings", "true");
                }
                resp
            } else if r.path.ends_with("index.html") {
                if index_exists {
                    Response::with_body(200, b"<h1>home</h1>".to_vec())
                } else {
                    Response::new(404)
                }
            } else {
                // container listing
                Response::with_body(
                    200,
                    br#"[{"subdir":"d/"},{"name":"a.txt","content_type":"text/plain","bytes":10,"last_modified":"2026-07-16T00:00:00.0"}]"#.to_vec(),
                )
            }
        });
        (log, app)
    }

    #[test]
    fn test_serves_index_when_present() {
        let (log, app) = backend(Some("index.html"), false, true);
        let sw = StaticWeb::new();
        let req = Request {
            method: "GET".into(),
            path: "/v1/AUTH_test/c/".into(),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: swift_http::Body::empty(),
        };
        let mut resp = sw.handle(req, &app);
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body.materialize(u64::MAX).unwrap(), b"<h1>home</h1>");
        let calls = log.lock().unwrap();
        assert_eq!(calls[0].0, "HEAD");
        assert!(calls[1].1.ends_with("index.html"));
    }

    #[test]
    fn test_falls_back_to_listing() {
        let (_log, app) = backend(Some("index.html"), true, false);
        let sw = StaticWeb::new();
        let req = Request {
            method: "GET".into(),
            path: "/v1/AUTH_test/c/".into(),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: swift_http::Body::empty(),
        };
        let mut resp = sw.handle(req, &app);
        assert_eq!(resp.status, 200);
        let body = String::from_utf8_lossy(resp.body.materialize(u64::MAX).unwrap()).into_owned();
        assert!(body.contains("Listing of"), "{body}");
        assert!(body.contains("a.txt"));
    }

    #[test]
    fn test_unconfigured_passes_through() {
        let (_log, app) = backend(None, false, false);
        let sw = StaticWeb::new();
        let req = Request {
            method: "GET".into(),
            path: "/v1/AUTH_test/c/".into(),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: b"orig".to_vec().into(),
        };
        // no web config -> falls through to next (returns the container listing 200)
        let mut resp = sw.handle(req, &app);
        assert_eq!(resp.status, 200);
        // body is the raw listing JSON (passed through), not HTML
        assert!(resp.body.materialize(u64::MAX).unwrap().starts_with(b"["));
    }

    // ---- Hyper prepare/finish / intercepts_response split ----
    // Isolated :18080 never calls handle(). Default reassemble_async feeds
    // handle() a one-shot next (first call = captured app response, second
    // = 500). Index + listing need real follow-up subrequests.

    fn async_backend(
        index: Option<&'static str>,
        listings: bool,
        index_exists: bool,
    ) -> crate::AsyncNextFn {
        let (_, sync) = backend(index, listings, index_exists);
        Arc::new(move |r| {
            let sync = Arc::clone(&sync);
            Box::pin(async move { sync(r) })
        })
    }

    fn listing_json() -> &'static [u8] {
        br#"[{"subdir":"d/"},{"name":"a.txt","content_type":"text/plain","bytes":10,"last_modified":"2026-07-16T00:00:00.0"}]"#
    }

    /// First `next()` returns the captured original GET (Hyper contract);
    /// later calls hit the real backend. Mirrors `apply_outbound_filters`.
    fn hyper_next(captured: Response, rest: crate::AsyncNextFn) -> crate::AsyncNextFn {
        let slot = Arc::new(Mutex::new(Some(captured)));
        Arc::new(move |r| {
            let slot = Arc::clone(&slot);
            let rest = Arc::clone(&rest);
            Box::pin(async move {
                if let Some(inner) = slot.lock().unwrap().take() {
                    return inner;
                }
                rest(r).await
            })
        })
    }

    fn container_get_captured(index: Option<&str>, listings: bool) -> Response {
        let mut resp = Response::with_body(200, listing_json().to_vec());
        if let Some(i) = index {
            resp.headers.set("X-Container-Meta-Web-Index", i);
        }
        if listings {
            resp.headers.set("X-Container-Meta-Web-Listings", "true");
        }
        resp
    }

    #[test]
    fn test_intercepts_response_so_hyper_path_runs_reassemble() {
        assert!(
            StaticWeb::new().intercepts_response(),
            "staticweb must intercept responses on the Hyper path"
        );
    }

    #[tokio::test]
    async fn test_reassemble_async_serves_html_listing() {
        let sw = StaticWeb::new();
        let req = Request {
            method: "GET".into(),
            path: "/v1/AUTH_test/c/".into(),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: Body::empty(),
        };
        let next = hyper_next(
            container_get_captured(None, true),
            async_backend(None, true, false),
        );
        let mut resp = sw.reassemble_async(req, next).await;
        assert_eq!(
            resp.status, 200,
            "Hyper path must serve HTML listing, got {}",
            resp.status
        );
        let body = String::from_utf8_lossy(resp.body.materialize(u64::MAX).unwrap()).into_owned();
        assert!(body.contains("Listing of"), "{body}");
        assert!(body.contains("a.txt"), "{body}");
        assert_eq!(
            resp.headers.get("X-Backend-Content-Generator"),
            Some("staticweb")
        );
        assert!(
            resp.headers
                .get("Content-Type")
                .unwrap_or("")
                .contains("text/html"),
            "{:?}",
            resp.headers.get("Content-Type")
        );
    }

    #[tokio::test]
    async fn test_reassemble_async_serves_index() {
        let sw = StaticWeb::new();
        let req = Request {
            method: "GET".into(),
            path: "/v1/AUTH_test/c/".into(),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: Body::empty(),
        };
        let next = hyper_next(
            container_get_captured(Some("index.html"), false),
            async_backend(Some("index.html"), false, true),
        );
        let mut resp = sw.reassemble_async(req, next).await;
        assert_eq!(resp.status, 200, "got {}", resp.status);
        let body = resp.body.materialize(u64::MAX).unwrap().to_vec();
        assert_eq!(body, b"<h1>home</h1>");
        assert!(!String::from_utf8_lossy(&body).contains("Listing of"));
    }

    #[tokio::test]
    async fn test_reassemble_async_redirects_container_without_slash() {
        let sw = StaticWeb::new();
        let mut headers = HeaderKeyDict::new();
        headers.set("Host", "swift.example:18080");
        let req = Request {
            method: "GET".into(),
            path: "/v1/AUTH_test/c".into(),
            query_string: String::new(),
            headers,
            body: Body::empty(),
        };
        let next = hyper_next(
            container_get_captured(None, true),
            async_backend(None, true, false),
        );
        let resp = sw.reassemble_async(req, next).await;
        assert_eq!(resp.status, 301, "Python redirects container GET without /");
        assert_eq!(
            resp.headers.get("Location"),
            Some("http://swift.example:18080/v1/AUTH_test/c/")
        );
    }

    #[test]
    fn test_handle_redirects_container_without_slash() {
        let (_log, app) = backend(None, true, false);
        let sw = StaticWeb::new();
        let mut headers = HeaderKeyDict::new();
        headers.set("Host", "swift.example:18080");
        let req = Request {
            method: "GET".into(),
            path: "/v1/AUTH_test/c".into(),
            query_string: String::new(),
            headers,
            body: Body::empty(),
        };
        let resp = sw.handle(req, &app);
        assert_eq!(resp.status, 301);
        assert_eq!(
            resp.headers.get("Location"),
            Some("http://swift.example:18080/v1/AUTH_test/c/")
        );
    }

    #[tokio::test]
    async fn test_reassemble_async_dir_prefix_listing() {
        let sw = StaticWeb::new();
        let req = Request {
            method: "GET".into(),
            path: "/v1/AUTH_test/c/dir/".into(),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: Body::empty(),
        };
        let rest: crate::AsyncNextFn = Arc::new(|r: Request| {
            Box::pin(async move {
                if r.method == "HEAD" {
                    let mut resp = Response::new(204);
                    resp.headers.set("X-Container-Meta-Web-Listings", "true");
                    return resp;
                }
                if r.query_string.contains("prefix=") {
                    return Response::with_body(
                        200,
                        br#"[{"name":"dir/obj","content_type":"text/plain","bytes":4,"last_modified":"2026-07-16T00:00:00.0"},{"subdir":"dir/sub/"}]"#.to_vec(),
                    );
                }
                Response::new(404)
            })
        });
        let next = hyper_next(Response::new(404), rest);
        let mut resp = sw.reassemble_async(req, next).await;
        assert_eq!(resp.status, 200, "got {}", resp.status);
        let body = String::from_utf8_lossy(resp.body.materialize(u64::MAX).unwrap()).into_owned();
        assert!(body.contains("Listing of /v1/AUTH_test/c/dir/"), "{body}");
        assert!(body.contains("obj"), "{body}");
        assert!(body.contains("sub/"), "{body}");
        assert!(body.contains("href=\"../\""), "{body}");
    }

    #[test]
    fn test_handle_dir_prefix_listing() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let log2 = log.clone();
        let app: crate::NextFn = Arc::new(move |r: Request| {
            log2.lock()
                .unwrap()
                .push((r.method.clone(), r.path.clone(), r.query_string.clone()));
            if r.method == "HEAD" {
                let mut resp = Response::new(204);
                resp.headers.set("X-Container-Meta-Web-Listings", "true");
                return resp;
            }
            if r.path.ends_with("/dir/") {
                return Response::new(404);
            }
            if r.query_string.contains("prefix=dir") {
                return Response::with_body(
                    200,
                    br#"[{"name":"dir/obj","content_type":"text/plain","bytes":4,"last_modified":"2026-07-16T00:00:00.0"}]"#.to_vec(),
                );
            }
            Response::new(404)
        });
        let sw = StaticWeb::new();
        let req = Request {
            method: "GET".into(),
            path: "/v1/AUTH_test/c/dir/".into(),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: Body::empty(),
        };
        let mut resp = sw.handle(req, &app);
        assert_eq!(resp.status, 200);
        let body = String::from_utf8_lossy(resp.body.materialize(u64::MAX).unwrap()).into_owned();
        assert!(body.contains("Listing of /v1/AUTH_test/c/dir/"), "{body}");
        assert!(body.contains("obj"), "{body}");
        assert!(
            log.lock()
                .unwrap()
                .iter()
                .any(|(m, _p, q)| m == "GET" && q.contains("prefix=dir")),
            "dir listing must request prefix=dir, calls={:?}",
            log.lock().unwrap()
        );
    }

    #[test]
    fn test_authenticated_without_web_mode_passthrough() {
        let (_log, app) = backend(None, true, false);
        let sw = StaticWeb::new();
        let mut headers = HeaderKeyDict::new();
        headers.set("X-Backend-Remote-User", "AUTH_test,AUTH_test:tester");
        let req = Request {
            method: "GET".into(),
            path: "/v1/AUTH_test/c/".into(),
            query_string: String::new(),
            headers,
            body: Body::empty(),
        };
        let mut resp = sw.handle(req, &app);
        assert_eq!(resp.status, 200);
        assert!(resp.body.materialize(u64::MAX).unwrap().starts_with(b"["));
    }
}
