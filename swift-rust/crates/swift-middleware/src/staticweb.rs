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
//! carrying `type-<ct>` classes and human-readable sizes). Object and subdir
//! hrefs use the official `./{quote(name)}` form (45a303c / bug 1884285) so
//! names like `prefix//obj` become `.//obj`. Dots in those hrefs are `%2E`
//! like Python `quote(name).replace('.', '%2E')`. CSS stays
//! `quote(css)` / `../{quote(css)}` with no `./`. Listing subrequests
//! copy the original request's auth/Host context (Python `make_env`) and force
//! JSON. Listing subrequests drop `X-Backend-Listing-Out-Content-Type` and set
//! `X-Backend-Source: staticweb` so Hyper `listing_formats` cannot rewrite the
//! follow-up to `text/plain`. `parse_listing` also accepts that text shape.
//! Delimiter grouping is applied even when the backend returns a flat
//! listing. Deferred: custom Web-Error docs and domain_remap Host listing titles.
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

/// Official `_listing` href target after 45a303c: `./` + `quote(name)` with
/// `.` forced to `%2E`, then the TempURL query (already `?…`).
fn listing_href(shown: &str, tempurl_qs: &str) -> String {
    format!("./{}{}", quote(shown).replace('.', "%2E"), tempurl_qs)
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
        // Official _listing (OpenStack staticweb.py): rel, then type, then href.
        // Field G4 on b20f569: 4 listing_*_direct_with_css fails were this order.
        body.push_str(&format!(
            "  <link rel=\"stylesheet\" type=\"text/css\" href=\"{}\" />\n",
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
                "    <td class=\"colname\"><a href=\"{}\">{}</a></td>\n",
                listing_href(shown, tempurl_qs),
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
                "    <td class=\"colname\"><a href=\"{}\">{}</a></td>\n",
                listing_href(shown, tempurl_qs),
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

fn parse_listing(body: &[u8]) -> Vec<ListingItem> {
    if let Some(items) = parse_json_listing(body) {
        return items;
    }
    parse_text_listing(body)
}

fn parse_json_listing(json: &[u8]) -> Option<Vec<ListingItem>> {
    let value: serde_json::Value = serde_json::from_slice(json).ok()?;
    let arr = value.as_array()?;
    let mut items = Vec::new();
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
                bytes: it
                    .get("bytes")
                    .and_then(|v| {
                        v.as_u64()
                            .or_else(|| v.as_i64().and_then(|n| n.try_into().ok()))
                    })
                    .unwrap_or(0),
                last_modified: it
                    .get("last_modified")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            });
        }
    }
    Some(items)
}

/// `listing_formats` text/plain body: one object name or `subdir/` per line.
/// Hyper prepare stamps `X-Backend-Listing-Out-Content-Type: text/plain` on
/// the client GET; if that header rides a staticweb listing subrequest,
/// the follow-up is this shape instead of JSON.
fn parse_text_listing(body: &[u8]) -> Vec<ListingItem> {
    let Ok(text) = std::str::from_utf8(body) else {
        return Vec::new();
    };
    if text.contains('<') {
        return Vec::new();
    }
    let mut items = Vec::new();
    for line in text.lines() {
        let name = line.trim_end_matches('\r');
        if name.is_empty() {
            continue;
        }
        if name.ends_with('/') {
            items.push(ListingItem::Subdir(name.to_string()));
        } else {
            items.push(ListingItem::Object {
                name: name.to_string(),
                content_type: "application/octet-stream".to_string(),
                bytes: 0,
                last_modified: String::new(),
            });
        }
    }
    items
}

/// Python container GET `delimiter=/` grouping. Applied even when the
/// listing body is a flat name list (Hyper captured GET has no delimiter).
fn apply_web_delimiter(items: Vec<ListingItem>, prefix: &str) -> Vec<ListingItem> {
    let prefix = listing_prefix(prefix);
    let mut subdirs = Vec::new();
    let mut seen_subdirs = std::collections::HashSet::new();
    let mut objects = Vec::new();
    for item in items {
        match item {
            ListingItem::Subdir(subdir) => {
                let Some(rest) = subdir.strip_prefix(prefix.as_str()) else {
                    continue;
                };
                if rest.is_empty() {
                    continue;
                }
                let seg = rest.split('/').next().unwrap_or(rest);
                if seg.is_empty() {
                    continue;
                }
                let key = format!("{prefix}{seg}/");
                if seen_subdirs.insert(key.clone()) {
                    subdirs.push(ListingItem::Subdir(key));
                }
            }
            ListingItem::Object {
                name,
                content_type,
                bytes,
                last_modified,
            } => {
                let Some(rest) = name.strip_prefix(prefix.as_str()) else {
                    continue;
                };
                if rest.is_empty() {
                    continue;
                }
                if let Some((seg, after)) = rest.split_once('/') {
                    if seg.is_empty() {
                        continue;
                    }
                    if !after.is_empty() || name.ends_with('/') {
                        let key = format!("{prefix}{seg}/");
                        if seen_subdirs.insert(key.clone()) {
                            subdirs.push(ListingItem::Subdir(key));
                        }
                        continue;
                    }
                }
                objects.push(ListingItem::Object {
                    name,
                    content_type,
                    bytes,
                    last_modified,
                });
            }
        }
    }
    subdirs.extend(objects);
    subdirs
}

fn listing_body_is_json_array(resp: &mut Response) -> bool {
    if !is_success(resp.status) {
        return false;
    }
    if resp.body.materialize(MAX_CONTROL_BODY).is_err() {
        return false;
    }
    matches!(
        serde_json::from_slice::<serde_json::Value>(
            resp.body.materialize(MAX_CONTROL_BODY).expect("buffered")
        ),
        Ok(serde_json::Value::Array(_))
    )
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

    /// Python `_get_container_info` is a container HEAD. The captured
    /// first `next()` may already be the index *object* (`index contents`)
    /// with no web-* headers — `from_headers(first)` then makes
    /// `enabled()` false and Hyper `return first` leaks those bytes.
    /// Prefer a live container HEAD when it looks like container metadata
    /// (including listings-off after `X-Remove-Container-Meta-Web-Listings`).
    /// Fall back to captured meta only if HEAD carried no container identity
    /// (HEAD 401 / empty) so a leftover index object cannot skip config.
    fn from_captured_or_head(first: &HeaderKeyDict, head: &HeaderKeyDict) -> Self {
        let from_head = Self::from_headers(head);
        if container_head_is_authoritative(head) {
            return from_head;
        }
        if from_head.enabled() {
            from_head
        } else {
            Self::from_headers(first)
        }
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

/// True when `head` is a real container HEAD (Python `_get_container_info`),
/// not an empty 401. Official `test_staticweb_off` POSTs
/// `X-Remove-Container-Meta-Web-Listings` then GETs with a prefix TempURL:
/// HEAD is 2xx without web-listings and must win over leftover captured meta.
fn container_head_is_authoritative(head: &HeaderKeyDict) -> bool {
    head.get("X-Container-Object-Count").is_some()
        || head.get("X-Container-Bytes-Used").is_some()
        || head.get("X-Timestamp").is_some()
        || head.iter().any(|(key, _)| {
            let lower = key.to_ascii_lowercase();
            lower.starts_with("x-container-")
        })
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

/// Python `make_env`: keep Host / REMOTE_USER / token / authorize-equivalent
/// headers, retarget method/path/query, drop range/conditionals.
fn staticweb_subrequest(
    orig: &Request,
    method: &str,
    path: String,
    query_string: String,
) -> Request {
    let mut sub = orig.clone_head();
    sub.method = method.to_string();
    sub.path = path;
    sub.query_string = query_string;
    sub.headers.remove("Range");
    sub.headers.remove("Content-Length");
    sub.headers.remove("If-Match");
    sub.headers.remove("If-None-Match");
    sub.headers.remove("If-Modified-Since");
    sub.headers.remove("If-Unmodified-Since");
    // listing_formats.prepare on the client GET stashes the negotiated
    // client type (default text/plain). clone_head would make the listing
    // subrequest come back as text/plain, which Python never does: its
    // make_env listing is JSON from the inner app. Drop the stash and
    // mark the source so listing_formats leaves JSON alone.
    sub.headers.remove("X-Backend-Listing-Out-Content-Type");
    sub.headers.remove("X-Backend-Listing-Can-Vary");
    sub.headers.set("X-Backend-Source", "staticweb");
    sub
}

fn listing_prefix(prefix: &str) -> String {
    if prefix.is_empty() || prefix.ends_with('/') {
        prefix.to_string()
    } else {
        format!("{prefix}/")
    }
}

fn listing_subrequest(orig: &Request, scope: &Scope, prefix: &str) -> Request {
    let prefix = listing_prefix(prefix);
    let query = if prefix.is_empty() {
        "delimiter=/&format=json".to_string()
    } else {
        format!("delimiter=/&format=json&prefix={}", quote(&prefix))
    };
    let mut list_req = staticweb_subrequest(orig, "GET", scope.container_path(), query);
    list_req.headers.set("Accept", "application/json");
    list_req
}

fn index_subrequest(orig: &Request, scope: &Scope, prefix: &str, index: &str) -> Request {
    staticweb_subrequest(
        orig,
        "GET",
        format!("{}/{prefix}{index}", scope.container_path()),
        String::new(),
    )
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
    let items = apply_web_delimiter(
        parse_listing(resp.body.materialize(MAX_CONTROL_BODY).expect("buffered")),
        prefix,
    );
    html_listing_response(req, scope, cfg, &listing_prefix(prefix), &items)
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
            next(listing_subrequest(req, scope, prefix)),
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
        // Official listing_*_direct: listings on, web-index removed.
        // Python `if not self._index: return _listing`. When leftover
        // web-index is still present *with* listings (index tests ran
        // first), listing style must not serve the index object body.
        if cfg.listings {
            return self.serve_listing(&req, &scope, &cfg, "", next);
        }
        if let Some(index) = &cfg.index {
            let index_resp = next(index_subrequest(&req, &scope, "", index));
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
            let index_resp = next(index_subrequest(&req, &scope, &prefix, index));
            if is_success(index_resp.status) || is_redirect(index_resp.status) {
                if !req.path.ends_with('/') {
                    return redirect_with_slash(&req);
                }
                return index_resp;
            }
        }
        if !req.path.ends_with('/') {
            let mut probe = listing_subrequest(&req, &scope, &prefix);
            probe.query_string =
                format!("limit=1&delimiter=/&format=json&prefix={}", quote(&prefix));
            let mut probe_resp = next(probe);
            if !is_success(probe_resp.status)
                || probe_resp.body.materialize(MAX_CONTROL_BODY).is_err()
            {
                return first;
            }
            let items = apply_web_delimiter(
                parse_listing(
                    probe_resp
                        .body
                        .materialize(MAX_CONTROL_BODY)
                        .expect("buffered"),
                ),
                &prefix,
            );
            if items.is_empty() {
                return first;
            }
            return redirect_with_slash(&req);
        }
        self.serve_listing(&req, &scope, &cfg, &prefix, next)
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
                // Always HEAD. A successful first body can be the leftover
                // index object (`index contents`) from `_test_index`; its
                // 200 must not skip config or leak as the listing page.
                let cfg =
                    WebConfig::from_captured_or_head(&first.headers, &next(head_req).await.headers);
                if !cfg.enabled() {
                    if web_mode {
                        return Response::error(404, "Not Found");
                    }
                    return first;
                }
                if !path_has_slash {
                    return redirect_with_slash(&head);
                }
                // listing_*_direct style: listings wins over a leftover
                // web-index (field G4 on 668b948 returned "index contents").
                if !cfg.listings {
                    if let Some(index) = &cfg.index {
                        let index_resp = next(index_subrequest(&head, &scope, "", index)).await;
                        if is_success(index_resp.status) || is_redirect(index_resp.status) {
                            return index_resp;
                        }
                    }
                    return Response::error(404, "Not Found");
                }
                let mut listing = next(listing_subrequest(&head, &scope, "")).await;
                if !listing_body_is_json_array(&mut listing) {
                    let mut captured = first;
                    if listing_body_is_json_array(&mut captured) {
                        listing = captured;
                    }
                }
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
                let index_resp = next(index_subrequest(&head, &scope, &prefix, index)).await;
                if is_success(index_resp.status) || is_redirect(index_resp.status) {
                    if !path_has_slash {
                        return redirect_with_slash(&head);
                    }
                    return index_resp;
                }
            }
            if !path_has_slash {
                let mut probe = listing_subrequest(&head, &scope, &prefix);
                probe.query_string =
                    format!("limit=1&delimiter=/&format=json&prefix={}", quote(&prefix));
                let mut probe_resp = next(probe).await;
                if !is_success(probe_resp.status)
                    || probe_resp.body.materialize(MAX_CONTROL_BODY).is_err()
                {
                    return first;
                }
                let items = apply_web_delimiter(
                    parse_listing(
                        probe_resp
                            .body
                            .materialize(MAX_CONTROL_BODY)
                            .expect("buffered"),
                    ),
                    &prefix,
                );
                if items.is_empty() {
                    return first;
                }
                return redirect_with_slash(&head);
            }
            if !cfg.listings {
                return Response::error(404, "Not Found");
            }
            let listing = next(listing_subrequest(&head, &scope, &prefix)).await;
            listing_from_response(&head, &scope, &cfg, &prefix, listing)
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
    fn test_parse_text_listing_from_listing_formats() {
        let items = parse_listing(b"idx.html\nfolder/\nnested/obj\n");
        assert!(
            items
                .iter()
                .any(|i| matches!(i, ListingItem::Object { name, .. } if name == "idx.html")),
            "{items:?}"
        );
        assert!(
            items
                .iter()
                .any(|i| matches!(i, ListingItem::Subdir(s) if s == "folder/")),
            "{items:?}"
        );
        let grouped = apply_web_delimiter(items, "");
        assert!(
            grouped
                .iter()
                .any(|i| matches!(i, ListingItem::Subdir(s) if s == "folder/")),
            "text listing must still group nested names: {grouped:?}"
        );
        assert!(
            !grouped
                .iter()
                .any(|i| matches!(i, ListingItem::Object { name, .. } if name == "nested/obj")),
            "{grouped:?}"
        );
        assert!(parse_listing(b"<html>Listing of /v1</html>").is_empty());
    }

    #[test]
    fn listing_subrequest_drops_listing_formats_negotiation() {
        // Failed first: clone_head kept X-Backend-Listing-Out-Content-Type
        // from listing_formats.prepare, so the follow-up was text/plain.
        let mut headers = HeaderKeyDict::new();
        headers.set("Host", "swift.example:18080");
        headers.set("X-Backend-Listing-Out-Content-Type", "text/plain");
        headers.set("X-Backend-Listing-Can-Vary", "1");
        headers.set("X-Auth-Token", "AUTH_tk123");
        let req = Request {
            method: "GET".into(),
            path: "/v1/AUTH_test/c/".into(),
            query_string: String::new(),
            headers,
            body: Body::empty(),
        };
        let scope = Scope::parse(&req).unwrap();
        let sub = listing_subrequest(&req, &scope, "");
        assert_eq!(sub.headers.get("X-Backend-Listing-Out-Content-Type"), None);
        assert_eq!(sub.headers.get("X-Backend-Listing-Can-Vary"), None);
        assert_eq!(sub.headers.get("X-Backend-Source"), Some("staticweb"));
        assert_eq!(sub.headers.get("Accept"), Some("application/json"));
        assert_eq!(sub.headers.get("Host"), Some("swift.example:18080"));
        assert_eq!(sub.headers.get("X-Auth-Token"), Some("AUTH_tk123"));
        assert!(
            sub.query_string.contains("delimiter=/"),
            "{}",
            sub.query_string
        );
        assert!(
            sub.query_string.contains("format=json"),
            "{}",
            sub.query_string
        );
    }

    #[test]
    fn test_apply_web_delimiter_hides_nested_names() {
        let items = parse_listing(
            br#"[{"name":"idx.html","content_type":"text/html","bytes":1,"last_modified":"2026-07-16T00:00:00.0"},{"name":"folder/nested","content_type":"text/plain","bytes":1,"last_modified":"2026-07-16T00:00:00.0"}]"#,
        );
        let grouped = apply_web_delimiter(items, "");
        assert!(grouped
            .iter()
            .any(|i| matches!(i, ListingItem::Object { name, .. } if name == "idx.html")));
        assert!(grouped
            .iter()
            .any(|i| matches!(i, ListingItem::Subdir(s) if s == "folder/")));
        assert!(!grouped
            .iter()
            .any(|i| matches!(i, ListingItem::Object { name, .. } if name.contains("nested"))));
    }

    #[test]
    fn test_listing_html_includes_css() {
        let html = build_listing_html_full("/v1/a/c/", "", &[], Some("listings.css"), "", "");
        assert!(
            html.contains(r#"<link rel="stylesheet" type="text/css" href="listings.css" />"#),
            "field b20f569 official CSS attr order is rel then type then href: {html}"
        );
        assert!(
            !html.contains(r#"<link type="text/css" rel="stylesheet""#),
            "type-before-rel is the b20f569 field miss: {html}"
        );
        assert!(
            !html.contains(r#"href="./listings.css""#),
            "official _build_css_path does not prefix CSS with ./: {html}"
        );
    }

    /// Field G4 on `b20f569`: listing object `./` hrefs passed; the 4 leftover
    /// `listing_*_direct_with_css` identities failed on attribute order:
    /// official `'<link rel="stylesheet" type="text/css" href="…" />'` vs
    /// rust `type` before `rel`.
    #[test]
    fn test_listing_html_css_link_is_rel_then_type_then_href() {
        let html = build_listing_html_full("/v1/AUTH_test/c/", "", &[], Some("style.css"), "", "");
        assert!(
            html.contains(r#"<link rel="stylesheet" type="text/css" href="style.css" />"#),
            "{html}"
        );
    }

    /// Field G4 on `93bd70c`: title + `<table id="listing">` exist, but
    /// official `_test_listing` `'<a href="./{quote(link)}">{link}</a>'` is
    /// missing. Names are `uuid4().hex` (no dots).
    #[test]
    fn test_listing_html_field_object_href_is_dot_slash_quoted_name() {
        let name = "174c0506bc3d4bec986aa2dfb6f49ab3";
        let items = vec![ListingItem::Object {
            name: name.into(),
            content_type: "application/octet-stream".into(),
            bytes: 4,
            last_modified: "2026-07-16T00:00:00.0".into(),
        }];
        let html = build_listing_html(
            "/v1/AUTH_test/c7a1e2b3c4d5e6f7a8b9c0d1e2f30415/",
            "",
            &items,
        );
        assert!(
            html.contains(
                "<title>Listing of /v1/AUTH_test/c7a1e2b3c4d5e6f7a8b9c0d1e2f30415/</title>"
            ),
            "{html}"
        );
        assert!(html.contains("<table id=\"listing\">"), "{html}");
        assert!(
            html.contains(&format!("<a href=\"./{name}\">{name}</a>")),
            "official listing_*_direct href missing: {html}"
        );
        assert!(
            !html.contains(&format!("<a href=\"{name}\">{name}</a>")),
            "pre-45a303c href without ./ must not be the object link: {html}"
        );
        assert!(
            html.contains("class=\"item"),
            "listing table must not be empty: {html}"
        );
    }

    /// 45a303c / bug 1884285: listing `prefix/` + object `prefix//obj`
    /// must link to `.//obj`, not `/obj`.
    #[test]
    fn test_listing_html_double_slash_object_uses_dot_slash_href() {
        let items = vec![ListingItem::Object {
            name: "prefix//obj".into(),
            content_type: "text/plain".into(),
            bytes: 1,
            last_modified: "2026-07-16T00:00:00.0".into(),
        }];
        let html = build_listing_html("/v1/a/c/prefix/", "prefix/", &items);
        assert!(
            html.contains("<a href=\".//obj\">/obj</a>"),
            "double-slash leaf must be ./ + /obj: {html}"
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
        assert!(html.contains("<a href=\"./photos/\">photos/</a>"));
        assert!(html.contains("<a href=\"./readme%2Etxt\">readme.txt</a>"));
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

    /// Field G4 leftovers on `5434983`: `listing_{anon,auth}_direct_{with,without}_css`
    /// × ascii + UTF-8. Mirrors OpenStack `test_staticweb.py` `_test_listing_direct`.
    #[derive(Clone)]
    struct DirectListingEnv {
        account: &'static str,
        container: String,
        index: String,
        css: String,
        dir: String,
        dir_obj: String,
        subdir: String,
        nested: String,
    }

    impl DirectListingEnv {
        fn ascii() -> Self {
            Self {
                account: "AUTH_test",
                container: "webc".into(),
                index: "idx.html".into(),
                css: "listings.css".into(),
                dir: "folder".into(),
                dir_obj: "nested".into(),
                subdir: "some sub%dir".into(),
                nested: "deep".into(),
            }
        }

        fn utf8() -> Self {
            Self {
                account: "AUTH_test",
                container: "站点".into(),
                index: "首页.html".into(),
                css: "样式.css".into(),
                dir: "目录".into(),
                dir_obj: "物件".into(),
                subdir: "子 目录%名".into(),
                nested: "深层".into(),
            }
        }

        /// Official `Utils.create_name()` / `uuid4().hex` — no dots, no `%`.
        /// Virtual keys like `dir/some sub%dir/` are setup-only in
        /// `test_staticweb.py`; stored names are random.
        fn field_ascii() -> Self {
            Self {
                account: "AUTH_test",
                container: "c7a1e2b3c4d5e6f7a8b9c0d1e2f30415".into(),
                index: "aa11bb22cc33dd44ee55ff6677889900".into(),
                css: "0123456789abcdef0123456789abcdef".into(),
                dir: "d00dfeedfacebaba0000111122223333".into(),
                dir_obj: "0b1ec7ab1e0000001111222233334444".into(),
                subdir: "5e7e0000111122223333444455556666".into(),
                nested: "9e57ed00001111222233334444555566".into(),
            }
        }

        fn storage_path(&self) -> String {
            format!("/v1/{}/{}", self.account, self.container)
        }

        fn container_url(&self) -> String {
            format!("{}/", self.storage_path())
        }

        fn dir_url(&self) -> String {
            format!("{}/{}/", self.storage_path(), self.dir)
        }

        fn dir_obj_name(&self) -> String {
            format!("{}/{}", self.dir, self.dir_obj)
        }

        fn subdir_name(&self) -> String {
            format!("{}/{}/", self.dir, self.subdir)
        }

        fn nested_name(&self) -> String {
            format!("{}/{}/{}", self.dir, self.subdir, self.nested)
        }

        fn flat_listing_json(&self) -> Vec<u8> {
            let rows = serde_json::json!([
                {"name": self.index, "content_type": "text/html", "bytes": 4, "last_modified": "2026-07-16T00:00:00.0"},
                {"name": "error.html", "content_type": "text/html", "bytes": 4, "last_modified": "2026-07-16T00:00:00.0"},
                {"name": self.css, "content_type": "text/css", "bytes": 4, "last_modified": "2026-07-16T00:00:00.0"},
                {"name": self.dir, "content_type": "application/directory", "bytes": 0, "last_modified": "2026-07-16T00:00:00.0"},
                {"name": self.dir_obj_name(), "content_type": "text/plain", "bytes": 4, "last_modified": "2026-07-16T00:00:00.0"},
                {"name": format!("{}/{}", self.dir, self.subdir), "content_type": "application/directory", "bytes": 0, "last_modified": "2026-07-16T00:00:00.0"},
                {"name": self.nested_name(), "content_type": "text/plain", "bytes": 4, "last_modified": "2026-07-16T00:00:00.0"},
            ]);
            serde_json::to_vec(&rows).unwrap()
        }

        fn delimited_listing_json(&self, prefix: &str) -> Vec<u8> {
            if prefix.is_empty() {
                let rows = serde_json::json!([
                    {"name": self.index, "content_type": "text/html", "bytes": 4, "last_modified": "2026-07-16T00:00:00.0"},
                    {"name": "error.html", "content_type": "text/html", "bytes": 4, "last_modified": "2026-07-16T00:00:00.0"},
                    {"name": self.css, "content_type": "text/css", "bytes": 4, "last_modified": "2026-07-16T00:00:00.0"},
                    {"name": self.dir, "content_type": "application/directory", "bytes": 0, "last_modified": "2026-07-16T00:00:00.0"},
                    {"subdir": format!("{}/", self.dir)},
                ]);
                return serde_json::to_vec(&rows).unwrap();
            }
            let rows = serde_json::json!([
                {"name": self.dir_obj_name(), "content_type": "text/plain", "bytes": 4, "last_modified": "2026-07-16T00:00:00.0"},
                {"subdir": self.subdir_name()},
            ]);
            serde_json::to_vec(&rows).unwrap()
        }

        fn captured_container(&self, css: bool) -> Response {
            let mut resp = Response::with_body(200, self.flat_listing_json());
            resp.headers.set("X-Container-Meta-Web-Listings", "true");
            if css {
                resp.headers
                    .set("X-Container-Meta-Web-Listings-Css", &self.css);
            }
            resp
        }

        fn captured_dir_marker(&self) -> Response {
            let mut resp = Response::with_body(200, Vec::new());
            resp.headers.set("Content-Type", "application/directory");
            resp.headers.set("Content-Length", "0");
            resp
        }
    }

    fn python_quote(s: &str) -> String {
        quote(s)
    }

    /// Official `_test_listing`: `'<a href="./{0}">{1}</a>'.format(quote(link), link)`.
    /// Hrefs also `%2E`-encode `.` like Python `quote(name).replace('.', '%2E')`.
    fn python_link(name: &str) -> String {
        format!(
            "<a href=\"./{}\">{}</a>",
            python_quote(name).replace('.', "%2E"),
            name
        )
    }

    fn python_css_link(href: &str) -> String {
        format!(
            "<link rel=\"stylesheet\" type=\"text/css\" href=\"{}\" />",
            python_quote(href)
        )
    }

    /// Python `make_env` copies Host / REMOTE_USER / authorize. A listing GET
    /// that drops them is 401 here (field Hyper hole). `Accept: text/html`
    /// without `format=json` is 406 like listing_formats. Missing `delimiter=/`
    /// returns the flat listing (nested names) so HTML must still group.
    fn hyper_listing_next(env: DirectListingEnv, css: bool) -> crate::AsyncNextFn {
        let rest: crate::AsyncNextFn = Arc::new(move |r: Request| {
            let env = env.clone();
            Box::pin(async move {
                if r.method == "HEAD" && r.path == env.storage_path() {
                    if r.headers.get("Host").unwrap_or("").is_empty() {
                        return Response::error(401, "Unauthorized");
                    }
                    let mut resp = Response::new(204);
                    resp.headers.set("X-Container-Meta-Web-Listings", "true");
                    if css {
                        resp.headers
                            .set("X-Container-Meta-Web-Listings-Css", &env.css);
                    }
                    return resp;
                }
                if r.method == "GET" && r.path == env.storage_path() {
                    // Python make_env copies HTTP_HOST and REMOTE_USER.
                    if r.headers.get("Host").unwrap_or("").is_empty() {
                        return Response::error(401, "Unauthorized");
                    }
                    let accept = r.headers.get("Accept").unwrap_or("");
                    if !r.query_string.contains("format=json")
                        && accept.contains("text/html")
                        && !accept.contains("application/json")
                    {
                        return Response::error(406, "Not Acceptable");
                    }
                    let prefix = r.param("prefix").unwrap_or_default();
                    if r.query_string.contains("delimiter=") {
                        return Response::with_body(200, env.delimited_listing_json(&prefix));
                    }
                    return Response::with_body(200, env.flat_listing_json());
                }
                Response::new(404)
            })
        });
        rest
    }

    async fn assert_listing_direct(env: DirectListingEnv, anonymous: bool, listings_css: bool) {
        let sw = StaticWeb::new();
        let host = "swift.example:18080";
        let mut headers = HeaderKeyDict::new();
        headers.set("Host", host);
        if anonymous {
            headers.set("X-Web-Mode", "False");
        } else {
            headers.set("X-Web-Mode", "True");
            headers.set("X-Backend-Remote-User", "AUTH_test,AUTH_test:tester");
            headers.set("X-Auth-Token", "AUTH_tk123");
        }

        let container_path = env.container_url();
        let dir_path = env.dir_url();
        let index = env.index.clone();
        let dir_slash = format!("{}/", env.dir);
        let dir_obj_leaf = env.dir_obj.clone();
        let subdir_leaf = format!("{}/", env.subdir);
        let nested_full = env.nested_name();
        let css_name = env.css.clone();
        let dir_obj_full = env.dir_obj_name();

        let req = Request {
            method: "GET".into(),
            path: container_path.clone(),
            query_string: String::new(),
            headers: headers.clone(),
            body: Body::empty(),
        };
        let next = hyper_next(
            env.captured_container(listings_css),
            hyper_listing_next(env.clone(), listings_css),
        );
        let mut resp = sw.reassemble_async(req, next).await;
        assert_eq!(resp.status, 200, "container listing status {}", resp.status);
        let body = String::from_utf8(resp.body.materialize(u64::MAX).unwrap().to_vec())
            .expect("utf8 listing");
        assert!(
            body.contains(&format!("Listing of {container_path}")),
            "title missing in {body}"
        );
        assert!(
            body.contains(&python_link(&index)),
            "index link missing: {body}"
        );
        assert!(
            body.contains(&python_link(&dir_slash)),
            "dir link missing: {body}"
        );
        assert!(
            !body.contains(&dir_obj_full),
            "nested dir/obj must not appear: {body}"
        );
        if listings_css {
            assert!(
                body.contains(&python_css_link(&css_name)),
                "container CSS missing: {body}"
            );
        } else {
            assert!(
                !body.contains("rel=\"stylesheet\""),
                "unexpected CSS link: {body}"
            );
        }

        let req = Request {
            method: "GET".into(),
            path: dir_path.clone(),
            query_string: String::new(),
            headers,
            body: Body::empty(),
        };
        let next = hyper_next(
            env.captured_dir_marker(),
            hyper_listing_next(env, listings_css),
        );
        let mut resp = sw.reassemble_async(req, next).await;
        assert_eq!(resp.status, 200, "dir listing status {}", resp.status);
        let body = String::from_utf8(resp.body.materialize(u64::MAX).unwrap().to_vec())
            .expect("utf8 dir listing");
        assert!(
            body.contains(&format!("Listing of {dir_path}")),
            "dir title missing in {body}"
        );
        assert!(
            body.contains(&python_link(&dir_obj_leaf)),
            "dir obj link missing: {body}"
        );
        assert!(
            body.contains(&python_link(&subdir_leaf)),
            "percent-subdir link missing: {body}"
        );
        assert!(
            !body.contains(&index),
            "index must not appear in dir: {body}"
        );
        assert!(
            !body.contains(&nested_full),
            "nested subdir/obj must not appear: {body}"
        );
        if listings_css {
            let href = format!("../{css_name}");
            assert!(
                body.contains(&python_css_link(&href)),
                "dir CSS missing: {body}"
            );
        }
    }

    #[tokio::test]
    async fn test_reassemble_listing_anon_direct_without_css() {
        assert_listing_direct(DirectListingEnv::ascii(), true, false).await;
    }

    #[tokio::test]
    async fn test_reassemble_listing_anon_direct_with_css() {
        assert_listing_direct(DirectListingEnv::ascii(), true, true).await;
    }

    #[tokio::test]
    async fn test_reassemble_listing_auth_direct_without_css() {
        assert_listing_direct(DirectListingEnv::ascii(), false, false).await;
    }

    #[tokio::test]
    async fn test_reassemble_listing_auth_direct_with_css() {
        assert_listing_direct(DirectListingEnv::ascii(), false, true).await;
    }

    #[tokio::test]
    async fn test_reassemble_listing_anon_direct_without_css_utf8() {
        assert_listing_direct(DirectListingEnv::utf8(), true, false).await;
    }

    #[tokio::test]
    async fn test_reassemble_listing_anon_direct_with_css_utf8() {
        assert_listing_direct(DirectListingEnv::utf8(), true, true).await;
    }

    #[tokio::test]
    async fn test_reassemble_listing_auth_direct_without_css_utf8() {
        assert_listing_direct(DirectListingEnv::utf8(), false, false).await;
    }

    #[tokio::test]
    async fn test_reassemble_listing_auth_direct_with_css_utf8() {
        assert_listing_direct(DirectListingEnv::utf8(), false, true).await;
    }

    fn listing_formats_then(rest: crate::AsyncNextFn) -> crate::AsyncNextFn {
        Arc::new(move |r: Request| {
            let rest = Arc::clone(&rest);
            Box::pin(async move { crate::ListingFormats.reassemble_async(r, rest).await })
        })
    }

    fn listing_formats_convert(req: &Request, mut resp: Response) -> Response {
        if resp.headers.get("Content-Type").unwrap_or("").is_empty() {
            resp.headers.set("Content-Type", "application/json");
        }
        let status = resp.status;
        let headers = resp.headers.clone();
        let body = resp.body.materialize(u64::MAX).unwrap().to_vec();
        let app: crate::NextFn = Arc::new(move |_| {
            let mut out = Response::with_body(status, body.clone());
            out.headers = headers.clone();
            out
        });
        crate::ListingFormats.handle(req.clone_head(), &app)
    }

    /// Official `_test_listing_direct`: container GET is always anonymous
    /// (`X-Web-Mode: False`, no token) even in auth tests; dir GET uses the
    /// real anonymous flag.
    fn listing_direct_headers(anonymous: bool) -> HeaderKeyDict {
        let mut headers = HeaderKeyDict::new();
        headers.set("Host", "swift.example:18080");
        if anonymous {
            headers.set("X-Web-Mode", "False");
        } else {
            headers.set("X-Web-Mode", "True");
            headers.set("X-Backend-Remote-User", "AUTH_test,AUTH_test:tester");
            headers.set("X-Auth-Token", "AUTH_tk123");
        }
        headers
    }

    /// Field G4 on `84751c9` still failed the 8 listing_*_direct identities.
    /// Isolated Hyper runs listing_formats.prepare on the client GET (default
    /// Accept → text/plain out-type) before staticweb.reassemble. When
    /// listing_formats is also in remaining (or converts the captured GET
    /// first), the listing body is text/plain — the old unit fixtures never
    /// did that and stayed green.
    ///
    /// Mirrors OpenStack `test_staticweb.py` `_test_listing` assertions:
    /// `Listing of {unquote(path)}`, `<a href="./{quote(link)}">{link}</a>`,
    /// CSS `<link rel="stylesheet" type="text/css" href="{quote(css)}" />`.
    async fn assert_listing_direct_field_pipeline(
        env: DirectListingEnv,
        anonymous: bool,
        listings_css: bool,
    ) {
        let sw = StaticWeb::new();
        let container_path = env.container_url();
        let dir_path = env.dir_url();
        let index = env.index.clone();
        let dir_slash = format!("{}/", env.dir);
        let dir_obj_leaf = env.dir_obj.clone();
        let subdir_leaf = format!("{}/", env.subdir);
        let nested_full = env.nested_name();
        let css_name = env.css.clone();
        let dir_obj_full = env.dir_obj_name();

        // Official: container listing is always anonymous=True.
        let mut req = Request {
            method: "GET".into(),
            path: container_path.clone(),
            query_string: String::new(),
            headers: listing_direct_headers(true),
            body: Body::empty(),
        };
        assert!(
            matches!(
                crate::ListingFormats.prepare(&mut req),
                crate::MwPrep::Continue
            ),
            "container GET must not 406 without Accept"
        );
        assert_eq!(
            req.headers.get("X-Backend-Listing-Out-Content-Type"),
            Some("text/plain"),
            "no Accept → listing_formats negotiates text/plain"
        );
        let captured = listing_formats_convert(&req, env.captured_container(listings_css));
        assert!(
            captured
                .headers
                .get("Content-Type")
                .unwrap_or("")
                .contains("text/plain"),
            "inner listing_formats must rewrite captured JSON to text/plain, ct={:?}",
            captured.headers.get("Content-Type")
        );
        let next = hyper_next(
            captured,
            listing_formats_then(hyper_listing_next(env.clone(), listings_css)),
        );
        let mut resp = sw.reassemble_async(req, next).await;
        assert_eq!(resp.status, 200, "container listing status {}", resp.status);
        let body = String::from_utf8(resp.body.materialize(u64::MAX).unwrap().to_vec())
            .expect("utf8 listing");
        assert!(
            body.contains(&format!("Listing of {container_path}")),
            "title missing in {body}"
        );
        assert!(
            body.contains("<table id=\"listing\">"),
            "field 93bd70c table missing: {body}"
        );
        assert!(
            body.contains(&python_link(&index)),
            "field 93bd70c official './{{quote(link)}}' object href missing: {body}"
        );
        assert!(
            body.contains(&python_link(&dir_slash)),
            "dir link missing: {body}"
        );
        assert!(
            !body.contains(&dir_obj_full),
            "nested dir/obj must not appear: {body}"
        );
        if listings_css {
            assert!(
                body.contains(&python_css_link(&css_name)),
                "container CSS missing: {body}"
            );
            assert!(
                !body.contains(&format!(
                    "<link rel=\"stylesheet\" type=\"text/css\" href=\"./{}\" />",
                    python_quote(&css_name)
                )),
                "official container CSS has no ./ prefix: {body}"
            );
        } else {
            assert!(
                !body.contains("rel=\"stylesheet\""),
                "unexpected CSS link: {body}"
            );
        }

        let mut req = Request {
            method: "GET".into(),
            path: dir_path.clone(),
            query_string: String::new(),
            headers: listing_direct_headers(anonymous),
            body: Body::empty(),
        };
        let _ = crate::ListingFormats.prepare(&mut req);
        let next = hyper_next(
            env.captured_dir_marker(),
            listing_formats_then(hyper_listing_next(env, listings_css)),
        );
        let mut resp = sw.reassemble_async(req, next).await;
        assert_eq!(resp.status, 200, "dir listing status {}", resp.status);
        let body = String::from_utf8(resp.body.materialize(u64::MAX).unwrap().to_vec())
            .expect("utf8 dir listing");
        assert!(
            body.contains(&format!("Listing of {dir_path}")),
            "dir title missing in {body}"
        );
        assert!(
            body.contains("<table id=\"listing\">"),
            "field 93bd70c dir table missing: {body}"
        );
        assert!(
            body.contains(&python_link(&dir_obj_leaf)),
            "field 93bd70c dir './{{quote(link)}}' href missing: {body}"
        );
        assert!(
            body.contains(&python_link(&subdir_leaf)),
            "subdir link missing: {body}"
        );
        assert!(
            !body.contains(&index),
            "index must not appear in dir: {body}"
        );
        assert!(
            !body.contains(&nested_full),
            "nested subdir/obj must not appear: {body}"
        );
        if listings_css {
            let href = format!("../{css_name}");
            assert!(
                body.contains(&python_css_link(&href)),
                "dir CSS missing: {body}"
            );
        }
    }

    /// Field G4 on `93bd70c`: Listing HTML is already the mode (title +
    /// table), but official `'<a href="./{uuid}">{uuid}</a>'` is absent.
    #[tokio::test]
    async fn test_field_listing_direct_href_dot_slash_through_hyper() {
        let mut env = DirectListingEnv::field_ascii();
        env.index = "174c0506bc3d4bec986aa2dfb6f49ab3".into();
        assert_listing_direct_field_pipeline(env, true, true).await;
    }

    #[tokio::test]
    async fn test_field_listing_anon_direct_without_css_through_listing_formats() {
        assert_listing_direct_field_pipeline(DirectListingEnv::field_ascii(), true, false).await;
    }

    #[tokio::test]
    async fn test_field_listing_auth_direct_with_css_through_listing_formats() {
        assert_listing_direct_field_pipeline(DirectListingEnv::field_ascii(), false, true).await;
    }

    #[tokio::test]
    async fn test_field_listing_anon_direct_with_css_utf8_through_listing_formats() {
        assert_listing_direct_field_pipeline(DirectListingEnv::utf8(), true, true).await;
    }

    /// Defense in depth: remaining listing_formats still rewrote the follow-up
    /// to text/plain (stash kept / source stripped). HTML must still grow
    /// official `quote(link)` hrefs from that name-per-line body.
    #[tokio::test]
    async fn test_field_listing_text_plain_followup_parses_like_json() {
        let env = DirectListingEnv::field_ascii();
        let sw = StaticWeb::new();
        let container_path = env.container_url();
        let index = env.index.clone();
        let dir_slash = format!("{}/", env.dir);
        let text = format!(
            "{}\nerror.html\n{}\n{}\n{}/\n",
            env.index, env.css, env.dir, env.dir
        );
        let rest: crate::AsyncNextFn = {
            let env = env.clone();
            Arc::new(move |r: Request| {
                let env = env.clone();
                let text = text.clone();
                Box::pin(async move {
                    if r.method == "HEAD" {
                        let mut resp = Response::new(204);
                        resp.headers.set("X-Container-Meta-Web-Listings", "true");
                        return resp;
                    }
                    if r.method == "GET" && r.path == env.storage_path() {
                        let mut resp = Response::with_body(200, text.into_bytes());
                        resp.headers
                            .set("Content-Type", "text/plain; charset=utf-8");
                        return resp;
                    }
                    Response::new(404)
                })
            })
        };
        let mut req = Request {
            method: "GET".into(),
            path: container_path.clone(),
            query_string: String::new(),
            headers: listing_direct_headers(true),
            body: Body::empty(),
        };
        let _ = crate::ListingFormats.prepare(&mut req);
        let next = hyper_next(env.captured_container(false), rest);
        let mut resp = sw.reassemble_async(req, next).await;
        assert_eq!(resp.status, 200, "got {}", resp.status);
        let body = String::from_utf8(resp.body.materialize(u64::MAX).unwrap().to_vec())
            .expect("utf8 listing");
        assert!(
            body.contains(&format!("Listing of {container_path}")),
            "{body}"
        );
        assert!(body.contains(&python_link(&index)), "{body}");
        assert!(body.contains(&python_link(&dir_slash)), "{body}");
        assert!(
            !body.contains(&env.dir_obj_name()),
            "nested name leaked: {body}"
        );
    }

    /// P1b pipeline (`listing_formats` outer of `staticweb`): captured GET
    /// stays JSON; listing_formats.handle must pass the HTML through.
    #[tokio::test]
    async fn test_field_listing_formats_outer_passthrough_html() {
        let env = DirectListingEnv::field_ascii();
        let sw = StaticWeb::new();
        let container_path = env.container_url();
        let mut req = Request {
            method: "GET".into(),
            path: container_path.clone(),
            query_string: String::new(),
            headers: listing_direct_headers(true),
            body: Body::empty(),
        };
        assert!(matches!(
            crate::ListingFormats.prepare(&mut req),
            crate::MwPrep::Continue
        ));
        let next = hyper_next(
            env.captured_container(false),
            hyper_listing_next(env.clone(), false),
        );
        let mut html = sw.reassemble_async(req.clone_head(), next).await;
        assert_eq!(html.status, 200);
        assert!(html
            .headers
            .get("Content-Type")
            .unwrap_or("")
            .contains("text/html"));
        let app: crate::NextFn = {
            let status = html.status;
            let headers = html.headers.clone();
            let body = html.body.materialize(u64::MAX).unwrap().to_vec();
            Arc::new(move |_| {
                let mut out = Response::with_body(status, body.clone());
                out.headers = headers.clone();
                out
            })
        };
        let mut resp = crate::ListingFormats.handle(req, &app);
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.materialize(u64::MAX).unwrap().to_vec())
            .expect("utf8 listing");
        assert!(
            body.contains(&format!("Listing of {container_path}")),
            "{body}"
        );
        assert!(body.contains(&python_link(&env.index)), "{body}");
        assert!(
            body.contains(&python_link(&format!("{}/", env.dir))),
            "{body}"
        );
    }

    /// Official `('%s contents' % item)` for item `'index'` — the field
    /// body on `668b948` (`AssertionError: 'Listing of …' not found in
    /// 'index contents'`).
    const INDEX_OBJECT_BYTES: &str = "index contents";

    fn leftover_index_listing_env() -> DirectListingEnv {
        // Official `Utils.create_name()` uuid; body is still
        // `('%s contents' % 'index')` → `index contents`.
        DirectListingEnv::field_ascii()
    }

    /// Captured first `next()` is already the index object, not a
    /// container listing. Official listing tests still HEAD listings-on
    /// / web-index removed (`_set_staticweb_headers(listings=True)`).
    fn index_object_captured(
        env: &DirectListingEnv,
        leftover_web_index: bool,
        leftover_listings: bool,
    ) -> Response {
        let mut resp = Response::with_body(200, INDEX_OBJECT_BYTES.as_bytes().to_vec());
        resp.headers.set("Content-Type", "text/plain");
        if leftover_web_index {
            resp.headers.set("X-Container-Meta-Web-Index", &env.index);
        }
        if leftover_listings {
            resp.headers.set("X-Container-Meta-Web-Listings", "true");
        }
        resp
    }

    fn listing_head_next(env: DirectListingEnv) -> crate::AsyncNextFn {
        let rest = hyper_listing_next(env.clone(), false);
        let index_path = format!("{}/{}", env.storage_path(), env.index);
        Arc::new(move |r: Request| {
            let rest = Arc::clone(&rest);
            let index_path = index_path.clone();
            Box::pin(async move {
                if r.method == "GET" && r.path == index_path {
                    return Response::with_body(200, INDEX_OBJECT_BYTES.as_bytes().to_vec());
                }
                rest(r).await
            })
        })
    }

    fn official_listing_of_asserts(body: &str, container_path: &str, index: &str) {
        assert!(
            body.contains(&format!("Listing of {container_path}")),
            "official _test_listing expects Listing of {container_path} in body, got {body:?}"
        );
        assert!(
            body.contains("<table id=\"listing\">"),
            "field 93bd70c: title without table: {body:?}"
        );
        assert_ne!(
            body.trim(),
            INDEX_OBJECT_BYTES,
            "body must be listing HTML, not the index object bytes (field 668b948)"
        );
        assert_ne!(
            body, INDEX_OBJECT_BYTES,
            "body must not equal the index object content"
        );
        assert!(
            body.contains(&format!("<a href=\"./{index}\">{index}</a>")),
            "field 93bd70c official './{{name}}' href missing: {body}"
        );
        assert!(
            body.contains(&python_link(index)),
            "listing should quote-link the index object, not serve it: {body}"
        );
    }

    /// Field sample: captured GET is `index contents` (no web-* meta).
    /// HEAD has listings. Must not `return first`.
    #[tokio::test]
    async fn test_reassemble_listing_direct_ignores_index_bytes_without_web_headers() {
        let env = leftover_index_listing_env();
        let sw = StaticWeb::new();
        let container_path = env.container_url();
        let index = env.index.clone();
        let req = Request {
            method: "GET".into(),
            path: container_path.clone(),
            query_string: String::new(),
            headers: listing_direct_headers(true),
            body: Body::empty(),
        };
        let next = hyper_next(
            index_object_captured(&env, false, false),
            listing_head_next(env),
        );
        let mut resp = sw.reassemble_async(req, next).await;
        assert_eq!(resp.status, 200, "got {}", resp.status);
        let body = String::from_utf8(resp.body.materialize(u64::MAX).unwrap().to_vec())
            .expect("utf8 listing");
        official_listing_of_asserts(&body, &container_path, &index);
    }

    /// Leftover `X-Container-Meta-Web-Index` from `_test_index` on the
    /// captured GET, plus listings (official listing tests XOR-remove
    /// web-index). Body must still be Listing-of HTML, not `index contents`.
    #[tokio::test]
    async fn test_reassemble_listing_direct_not_index_object_body() {
        let env = leftover_index_listing_env();
        let sw = StaticWeb::new();
        let container_path = env.container_url();
        let index = env.index.clone();
        let req = Request {
            method: "GET".into(),
            path: container_path.clone(),
            query_string: String::new(),
            headers: listing_direct_headers(true),
            body: Body::empty(),
        };
        let next = hyper_next(
            index_object_captured(&env, true, true),
            listing_head_next(env.clone()),
        );
        let mut resp = sw.reassemble_async(req, next).await;
        assert_eq!(resp.status, 200, "got {}", resp.status);
        let body = String::from_utf8(resp.body.materialize(u64::MAX).unwrap().to_vec())
            .expect("utf8 listing");
        official_listing_of_asserts(&body, &container_path, &index);
        assert!(
            body.contains(&python_link(&format!("{}/", env.dir))),
            "sibling dir link missing: {body}"
        );
    }

    /// Leftover web-index only on captured GET; HEAD is listings-only
    /// (official remove). Must HEAD and list, not serve the index object.
    #[tokio::test]
    async fn test_reassemble_listing_direct_head_listings_beats_leftover_web_index() {
        let env = leftover_index_listing_env();
        let sw = StaticWeb::new();
        let container_path = env.container_url();
        let index = env.index.clone();
        let req = Request {
            method: "GET".into(),
            path: container_path.clone(),
            query_string: String::new(),
            headers: listing_direct_headers(true),
            body: Body::empty(),
        };
        let next = hyper_next(
            index_object_captured(&env, true, false),
            listing_head_next(env),
        );
        let mut resp = sw.reassemble_async(req, next).await;
        assert_eq!(resp.status, 200, "got {}", resp.status);
        let body = String::from_utf8(resp.body.materialize(u64::MAX).unwrap().to_vec())
            .expect("utf8 listing");
        official_listing_of_asserts(&body, &container_path, &index);
    }

    /// Sync `handle_container`: listings on + leftover web-index must not
    /// GET/return the index object (`index contents`).
    #[test]
    fn test_handle_container_listings_not_index_object_when_both_set() {
        let env = leftover_index_listing_env();
        let listing = env.delimited_listing_json("");
        let index_name = env.index.clone();
        let index_for_assert = index_name.clone();
        let container_path = env.container_url();
        let storage = env.storage_path();
        let app: crate::NextFn = Arc::new(move |r: Request| {
            if r.method == "HEAD" && r.path == storage {
                let mut resp = Response::new(204);
                resp.headers.set("X-Container-Meta-Web-Listings", "true");
                resp.headers.set("X-Container-Meta-Web-Index", &index_name);
                return resp;
            }
            if r.path.ends_with(&format!("/{index_name}")) {
                return Response::with_body(200, INDEX_OBJECT_BYTES.as_bytes().to_vec());
            }
            if r.method == "GET" && r.path == storage {
                return Response::with_body(200, listing.clone());
            }
            Response::new(404)
        });
        let sw = StaticWeb::new();
        let req = Request {
            method: "GET".into(),
            path: container_path.clone(),
            query_string: String::new(),
            headers: listing_direct_headers(true),
            body: Body::empty(),
        };
        let mut resp = sw.handle(req, &app);
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body.materialize(u64::MAX).unwrap().to_vec())
            .expect("utf8 listing");
        official_listing_of_asserts(&body, &container_path, &index_for_assert);
    }

    /// Official TestStaticWebTempurl.test_staticweb_off: after
    /// `X-Remove-Container-Meta-Web-Listings`, a live container HEAD is
    /// authoritative even when the captured GET still carries leftover
    /// listings meta. Must not emit `X-Backend-Content-Generator: staticweb`
    /// so TempURL finish 401s the container-root carve-out.
    #[tokio::test]
    async fn test_reassemble_listings_off_head_beats_leftover_captured_listings() {
        let env = leftover_index_listing_env();
        let sw = StaticWeb::new();
        let container_path = env.container_url();
        let storage = env.storage_path();
        let mut captured = index_object_captured(&env, false, true);
        captured
            .headers
            .set("X-Container-Meta-Web-Listings", "true");
        let rest: crate::AsyncNextFn = Arc::new(move |r: Request| {
            let storage = storage.clone();
            Box::pin(async move {
                if r.method == "HEAD" && r.path == storage {
                    let mut resp = Response::new(204);
                    resp.headers.set("X-Container-Object-Count", "4");
                    resp.headers.set("X-Timestamp", "1000.00000");
                    return resp;
                }
                Response::new(404)
            })
        });
        let mut headers = listing_direct_headers(true);
        headers.set("X-Backend-Remote-User", ".wsgi.tempurl");
        let req = Request {
            method: "GET".into(),
            path: container_path,
            query_string: String::new(),
            headers,
            body: Body::empty(),
        };
        let mut resp = sw.reassemble_async(req, hyper_next(captured, rest)).await;
        assert_eq!(
            resp.status, 200,
            "passthrough captured GET, got {}",
            resp.status
        );
        assert_ne!(
            resp.headers.get("X-Backend-Content-Generator"),
            Some("staticweb"),
            "listings-off must not stamp staticweb so TempURL finish can 401"
        );
        assert_eq!(
            String::from_utf8_lossy(&resp.body.materialize(u64::MAX).unwrap_or_default().to_vec())
                .as_ref(),
            INDEX_OBJECT_BYTES
        );
    }

    /// Official test_staticweb_off dir GET: listings removed, directory
    /// marker must stay 404 (not a listing page).
    #[tokio::test]
    async fn test_reassemble_listings_off_dir_marker_is_404() {
        let sw = StaticWeb::new();
        let mut marker = Response::with_body(200, b"".to_vec());
        marker.headers.set("Content-Type", "application/directory");
        marker.headers.set("Content-Length", "0");
        let rest: crate::AsyncNextFn = Arc::new(|r: Request| {
            Box::pin(async move {
                if r.method == "HEAD" {
                    let mut resp = Response::new(204);
                    resp.headers.set("X-Container-Object-Count", "1");
                    return resp;
                }
                Response::new(404)
            })
        });
        let req = Request {
            method: "GET".into(),
            path: "/v1/AUTH_test/c/dir/".into(),
            query_string: String::new(),
            headers: listing_direct_headers(true),
            body: Body::empty(),
        };
        let resp = sw.reassemble_async(req, hyper_next(marker, rest)).await;
        assert_eq!(resp.status, 404, "got {}", resp.status);
    }

    /// Index-style (`listings=false`, web-index set) still serves the
    /// index object — do not invert `_test_index`.
    #[tokio::test]
    async fn test_reassemble_index_style_still_serves_index_not_listing() {
        let next: crate::AsyncNextFn = Arc::new(|r: Request| {
            Box::pin(async move {
                if r.method == "HEAD" {
                    let mut resp = Response::new(204);
                    resp.headers.set("X-Container-Meta-Web-Index", "index.html");
                    return resp;
                }
                if r.path.ends_with("/index.html") {
                    return Response::with_body(200, b"<h1>home</h1>".to_vec());
                }
                Response::with_body(200, INDEX_OBJECT_BYTES.as_bytes().to_vec())
            })
        });
        let sw = StaticWeb::new();
        let req = Request {
            method: "GET".into(),
            path: "/v1/AUTH_test/web/".into(),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: Body::empty(),
        };
        let first = Response::with_body(200, INDEX_OBJECT_BYTES.as_bytes().to_vec());
        let mut resp = sw.reassemble_async(req, hyper_next(first, next)).await;
        let body = resp.body.materialize(u64::MAX).unwrap().to_vec();
        assert_eq!(&body, b"<h1>home</h1>");
        assert!(
            !String::from_utf8_lossy(&body).contains("Listing of"),
            "index-style must not emit a listing page"
        );
    }
}
