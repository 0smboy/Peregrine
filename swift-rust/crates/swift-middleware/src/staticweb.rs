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

use swift_http::{split_path, Body, HeaderKeyDict, Request, Response, MAX_CONTROL_BODY};

use crate::{Middleware, NextFn};

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
    let esc_label = html_escape(label);
    let mut body = String::new();
    body.push_str("<!DOCTYPE html>\n<html>\n <head>\n");
    body.push_str(&format!("  <title>Listing of {esc_label}</title>\n"));
    body.push_str(
        "  <style type=\"text/css\">\n\
         \x20  h1 {font-size: 1em; font-weight: bold;}\n\
         \x20  th {text-align: left; padding: 0px 1em 0px 1em;}\n\
         \x20  td {padding: 0px 1em 0px 1em;}\n\
         \x20  a {text-decoration: none;}\n\
         \x20 </style>\n",
    );
    body.push_str(" </head>\n <body>\n");
    body.push_str(&format!("  <h1 id=\"title\">Listing of {esc_label}</h1>\n"));
    body.push_str("  <table id=\"listing\">\n   <tr id=\"heading\">\n");
    body.push_str("    <th class=\"colname\">Name</th>\n");
    body.push_str("    <th class=\"colsize\">Size</th>\n");
    body.push_str("    <th class=\"coldate\">Date</th>\n   </tr>\n");

    if !prefix.is_empty() {
        body.push_str(
            "   <tr id=\"parent\" class=\"item\">\n\
             \x20   <td class=\"colname\"><a href=\"../\">../</a></td>\n\
             \x20   <td class=\"colsize\">&nbsp;</td>\n\
             \x20   <td class=\"coldate\">&nbsp;</td>\n   </tr>\n",
        );
    }

    for item in items {
        if let ListingItem::Subdir(subdir) = item {
            let shown = subdir.strip_prefix(prefix).unwrap_or(subdir);
            body.push_str("   <tr class=\"item subdir\">\n");
            body.push_str(&format!(
                "    <td class=\"colname\"><a href=\"{}\">{}</a></td>\n",
                quote(shown),
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
                quote(shown),
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

impl StaticWeb {
    fn serve_listing(
        &self,
        version: &str,
        account: &str,
        container: &str,
        label: &str,
        prefix: &str,
        next: &NextFn,
    ) -> Response {
        let mut list_req = Request {
            method: "GET".to_string(),
            path: format!("/{version}/{account}/{container}"),
            query_string: if prefix.is_empty() {
                "delimiter=/&format=json".to_string()
            } else {
                format!("delimiter=/&format=json&prefix={}", quote(prefix))
            },
            headers: HeaderKeyDict::new(),
            body: Body::empty(),
        };
        list_req.headers.set("X-Backend-Source", "staticweb");
        let mut resp = next(list_req);
        if !(200..300).contains(&resp.status) {
            return resp;
        }
        // A listing is bounded by the container listing limit; anything
        // larger cannot be one — relay it untouched.
        if resp.body.materialize(MAX_CONTROL_BODY).is_err() {
            return resp;
        }
        let items = parse_listing(resp.body.materialize(MAX_CONTROL_BODY).expect("buffered"));
        if !prefix.is_empty() && items.is_empty() {
            return Response::error(404, "Not Found");
        }
        let html = build_listing_html(label, prefix, &items);
        let mut out = Response::with_body(200, html.into_bytes());
        out.headers.set("Content-Type", "text/html; charset=UTF-8");
        out.headers.set("X-Backend-Content-Generator", "staticweb");
        out
    }
}

impl Middleware for StaticWeb {
    fn handle(&self, req: Request, next: &NextFn) -> Response {
        if req.method != "GET" && req.method != "HEAD" {
            return next(req);
        }
        // container GET: /v1/account/container  (3 segments)
        let parts = match split_path(&req.path, 3, 4, true) {
            Ok(p) => p,
            Err(_) => return next(req),
        };
        let version = parts[0].clone().unwrap_or_default();
        let account = parts[1].clone().unwrap_or_default();
        let container = parts[2].clone().unwrap_or_default();
        let obj = parts[3].clone();

        // HEAD the container for its web config.
        let head = Request {
            method: "HEAD".to_string(),
            path: format!("/{version}/{account}/{container}"),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: Body::empty(),
        };
        let cinfo = next(head);
        let web_index = cinfo
            .headers
            .get("X-Container-Meta-Web-Index")
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty());
        let web_listings = cinfo
            .headers
            .get("X-Container-Meta-Web-Listings")
            .map(|s| s.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        if web_index.is_none() && !web_listings {
            return next(req);
        }

        // Determine the pseudo-dir prefix (object path acting as a directory).
        let prefix = match &obj {
            Some(o) if o.is_empty() || o.ends_with('/') => o.clone(),
            None => String::new(),
            // a real object request: only index/dir resolution applies to
            // paths ending in '/'; otherwise pass through to the object.
            Some(_) => return next(req),
        };
        let label = if prefix.is_empty() {
            format!("/{version}/{account}/{container}/")
        } else {
            format!("/{version}/{account}/{container}/{prefix}")
        };

        // Try the index object first.
        if let Some(index) = &web_index {
            let index_path = if prefix.is_empty() {
                format!("/{version}/{account}/{container}/{index}")
            } else {
                format!("/{version}/{account}/{container}/{prefix}{index}")
            };
            let index_req = Request {
                method: "GET".to_string(),
                path: index_path,
                query_string: String::new(),
                headers: HeaderKeyDict::new(),
                body: Body::empty(),
            };
            let index_resp = next(index_req);
            if (200..300).contains(&index_resp.status)
                || (300..400).contains(&index_resp.status)
            {
                return index_resp;
            }
            // index not found -> fall to listing (if enabled)
        }

        if web_listings {
            return self.serve_listing(&version, &account, &container, &label, &prefix, next);
        }
        Response::error(404, "Not Found")
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
            log2.lock().unwrap().push((r.method.clone(), r.path.clone()));
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
            path: "/v1/AUTH_test/c".into(),
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
            path: "/v1/AUTH_test/c".into(),
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
            path: "/v1/AUTH_test/c".into(),
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
}
