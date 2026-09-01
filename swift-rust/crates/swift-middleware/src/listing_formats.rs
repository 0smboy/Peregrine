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

//! `listing_formats`: the response-side listing formatter for account and
//! container `GET`/`HEAD`, porting
//! `swift/common/middleware/listing_formats.py` (the `ListingFilter`).
//!
//! On the way in it forces the backend subrequest to `format=json`; on the
//! way out it converts that JSON listing body into `text/plain`, XML, or a
//! re-serialized JSON document depending on the `format=` query param /
//! `Accept` header. The XML and text byte shapes match `account_to_xml`,
//! `container_to_xml`, and `listing_to_text` exactly (verified against
//! Python `cElementTree`, including the self-closing empty-element quirks),
//! and coincide with the shapes emitted by the Rust account/container
//! servers.
//!
//! Deferred (documented divergences from the Python source):
//! - Content negotiation is simplified to the `format=` param plus an
//!   `Accept` substring match, matching the golden-tested account/container
//!   servers' `listing_content_type`. Full RFC-7231 `Accept.best_match`
//!   q-value negotiation is not reproduced. Unmatched `Accept` (e.g. `foo/bar`)
//!   is `406 Not Acceptable`, as `get_listing_content_type` does in Python.
//! - The `swift.format_listing` opt-out env flag and the WSGI
//!   `call_application` plumbing have no analog in this buffered pipeline.
//!   Python `object_versioning._list_versions` sets that flag so `?versions`
//!   listings stay JSON; this filter skips reformatting when the `versions`
//!   query param is present. `?versions` plus a non-JSON `format=` / `Accept`
//!   is `406` here (Python raises that in object_versioning after this filter
//!   rewrites `req.accept` from `format=`).
//! - `filter_reserved` still drops entries carrying the reserved byte but
//!   does not emit the warning log lines (the pipeline has no logger).
//! - The oversize guard measures the buffered response body rather than the
//!   backend `Content-Length` header; a buffered `Response` always has a
//!   known length, so Python's `resp_length is None` streaming case cannot
//!   arise.
//! - Lone unpaired UTF-16 surrogates in `\uXXXX` escapes and non-integer
//!   JSON number renormalization on the json passthrough are approximated
//!   (`U+FFFD` / verbatim token) rather than reproduced byte-for-byte;
//!   real account/container listings contain neither.

use swift_core::config::config_true_value;
use swift_core::constraints::{RESERVED_STR, VALID_API_VERSIONS};
use swift_http::{
    listing_query_invalid_utf8_param, split_path, HeaderKeyDict, Request, Response,
    MAX_CONTROL_BODY,
};

use crate::{Middleware, MwPrep, NextFn};

const LISTING_OUT_TYPE: &str = "X-Backend-Listing-Out-Content-Type";
const LISTING_CAN_VARY: &str = "X-Backend-Listing-Can-Vary";

/// Maximum size of a valid JSON container listing body. A larger response is
/// assumed to be a staticweb page and passed straight through
/// (`MAX_CONTAINER_LISTING_CONTENT_LENGTH`).
const MAX_CONTAINER_LISTING_CONTENT_LENGTH: usize = 1024 * 10000 * 2;

pub struct ListingFormats;

impl Default for ListingFormats {
    fn default() -> Self {
        ListingFormats
    }
}

impl Middleware for ListingFormats {
    fn prepare(&self, req: &mut Request) -> MwPrep {
        let parts = match split_path(&req.path, 2, 3, false) {
            Ok(p) => p,
            Err(_) => return MwPrep::Continue,
        };
        let version = parts[0].clone().unwrap_or_default();
        if !VALID_API_VERSIONS.contains(&version.as_str())
            || (req.method != "GET" && req.method != "HEAD")
        {
            return MwPrep::Continue;
        }
        if let Some(resp) = invalid_utf8_listing_param(&req.query_string) {
            // Must run on the raw query. `force_format_json` uses lossy
            // `unquote` (`%FF` → U+FFFD), after which the proxy's UTF-8
            // check would 200 (probe test_sharding_listing delimiter=%ff).
            return MwPrep::ShortCircuit(resp);
        }
        let is_container = parts
            .get(2)
            .and_then(|c| c.as_ref())
            .is_some_and(|c| !c.is_empty());
        if let Some(resp) = listing_not_acceptable(req, is_container) {
            return MwPrep::ShortCircuit(resp);
        }
        let out = get_listing_content_type(req);
        req.headers.set(LISTING_OUT_TYPE, out);
        if !req.params().iter().any(|(k, _)| k == "format") {
            req.headers.set(LISTING_CAN_VARY, "1");
        }
        req.query_string = force_format_json(&req.params());
        MwPrep::Continue
    }

    fn intercepts_response(&self) -> bool {
        true
    }

    fn handle(&self, mut req: Request, next: &NextFn) -> Response {
        // account and container only: `req.split_path(2, 3)`
        let parts = match split_path(&req.path, 2, 3, false) {
            Ok(p) => p,
            Err(_) => return next(req),
        };
        let version = parts[0].clone().unwrap_or_default();
        let acct = parts[1].clone().unwrap_or_default();
        // `if cont:` in Python is falsy for both the account case (None) and
        // an empty trailing segment.
        let cont = parts[2].clone().filter(|c| !c.is_empty());

        let method = req.method.clone();
        if !VALID_API_VERSIONS.contains(&version.as_str()) || (method != "GET" && method != "HEAD")
        {
            return next(req);
        }

        if let Some(resp) = invalid_utf8_listing_param(&req.query_string) {
            return resp;
        }

        if let Some(resp) = listing_not_acceptable(&req, cont.is_some()) {
            return resp;
        }

        // Desired output content-type, then force the subrequest to JSON.
        let stashed = req.headers.get(LISTING_OUT_TYPE).map(str::to_string);
        let out_content_type = stashed
            .as_deref()
            .unwrap_or_else(|| get_listing_content_type(&req));

        let params = req.params();
        let can_vary = req.headers.get(LISTING_CAN_VARY).is_some()
            || !params.iter().any(|(k, _)| k == "format");
        // Python object_versioning._list_versions sets
        // `swift.format_listing = False` so `?versions` stays JSON.
        let skip_format_listing = cont.is_some() && params.iter().any(|(k, _)| k == "versions");
        let allow_reserved = req
            .headers
            .get("X-Backend-Allow-Reserved-Names")
            .is_some_and(config_true_value);
        req.query_string = force_format_json(&params);

        let mut resp = next(req);

        if skip_format_listing {
            return resp;
        }

        // 200/204 only; anything else passes through untouched.
        if resp.status != 200 && resp.status != 204 {
            return resp;
        }

        let resp_content_type = resp
            .headers
            .get("Content-Type")
            .unwrap_or("")
            .split(';')
            .next()
            .unwrap_or("")
            .to_string();

        if can_vary {
            add_vary_accept(&mut resp.headers);
        }

        // HEAD 204 from the container/account servers is `text/plain` with no
        // body. Python listing_formats still stamps the negotiated type
        // (`format=json` → application/json). Do that before the JSON-body
        // guard or official test_GET_HEAD_content_type fails on HEAD.
        if method == "HEAD" {
            resp.headers
                .set("Content-Type", format!("{out_content_type}; charset=utf-8"));
            resp.headers.set("Content-Length", 0);
            return resp;
        }

        // Only reformat a JSON body; otherwise (staticweb, etc.) pass through.
        if resp_content_type != "application/json" {
            return resp;
        }

        // A response too large to be a real listing is assumed to be a
        // staticweb page and passed straight through untouched.
        if resp.body.materialize(MAX_CONTROL_BODY).is_err() {
            return resp;
        }
        // Second materialize is a no-op on the now-buffered body.
        let body_bytes = resp.body.materialize(MAX_CONTROL_BODY).expect("buffered");
        if body_bytes.len() > MAX_CONTAINER_LISTING_CONTENT_LENGTH {
            return resp;
        }

        // Parse + sanity-check the listing (a JSON array of objects). A
        // funky staticweb body that is not valid JSON passes straight
        // through (Python's `except ValueError`).
        let listing = match parse_listing(body_bytes) {
            Some(l) => l,
            None => return resp,
        };

        let listing = if allow_reserved {
            listing
        } else {
            filter_reserved(listing)
        };

        // Convert. A missing required field raises `KeyError` in Python; we
        // signal that with `Err(())` and pass the original body through.
        let converted: Result<Vec<u8>, ()> = if out_content_type.ends_with("/xml") {
            match &cont {
                Some(c) => container_to_xml(&listing, c),
                None => account_to_xml(&listing, &acct),
            }
        } else if out_content_type == "text/plain" {
            listing_to_text(&listing)
        } else {
            Ok(json_dumps_listing(&listing))
        };
        let body = match converted {
            Ok(b) => b,
            Err(()) => return resp,
        };

        // An empty formatted body collapses to 204 No Content.
        if body.is_empty() {
            resp.status = 204;
            resp.reason = "No Content".to_string();
        }
        resp.headers
            .set("Content-Type", format!("{out_content_type}; charset=utf-8"));
        resp.headers.set("Content-Length", body.len());
        resp.body = body.into();
        resp
    }
}

fn not_acceptable() -> Response {
    Response::error(
        406,
        "The resource could not be generated in the requested format.",
    )
}

/// Python `get_listing_content_type`: unmatched Accept is 406. `format=`
/// always maps (unknown → text/plain) and never 406s by itself.
fn accept_header_unmatched(req: &Request) -> bool {
    if req.param("format").filter(|f| !f.is_empty()).is_some() {
        return false;
    }
    let Some(accept) = req.headers.get("Accept") else {
        return false;
    };
    let accept = accept.to_lowercase();
    let accept = accept.trim();
    if accept.is_empty() || accept == "*" || accept.contains("*/*") {
        return false;
    }
    !(accept.contains("application/json")
        || accept.contains("application/xml")
        || accept.contains("text/xml")
        || accept.contains("text/plain"))
}

/// Python `object_versioning._list_versions`: after listing_formats may
/// rewrite Accept from `format=`, `best_match(['application/json'])` or 406.
fn versions_listing_rejects_non_json(req: &Request, is_container: bool) -> bool {
    if !is_container || !req.params().iter().any(|(k, _)| k == "versions") {
        return false;
    }
    if let Some(format) = req.param("format").filter(|f| !f.is_empty()) {
        return !format.eq_ignore_ascii_case("json");
    }
    match req.headers.get("Accept") {
        None => false,
        Some(accept) => {
            let accept = accept.to_lowercase();
            let accept = accept.trim();
            !(accept.contains("application/json") || accept.contains("*/*") || accept == "*")
        }
    }
}

fn listing_not_acceptable(req: &Request, is_container: bool) -> Option<Response> {
    if accept_header_unmatched(req) || versions_listing_rejects_non_json(req, is_container) {
        Some(not_acceptable())
    } else {
        None
    }
}

/// `get_listing_content_type`, simplified to the `format=` param and an
/// `Accept` substring match (see the module deferral notes).
fn get_listing_content_type(req: &Request) -> &'static str {
    if let Some(format) = req.param("format").filter(|f| !f.is_empty()) {
        return match format.to_lowercase().as_str() {
            "json" => "application/json",
            "xml" => "application/xml",
            _ => "text/plain",
        };
    }
    if let Some(accept) = req.headers.get("Accept") {
        let accept = accept.to_lowercase();
        if accept.contains("application/json") {
            return "application/json";
        }
        if accept.contains("application/xml") {
            return "application/xml";
        }
        if accept.contains("text/xml") {
            return "text/xml";
        }
    }
    "text/plain"
}

/// `can_vary` handling: append `Accept` to the `Vary` header unless it is
/// already listed (`list_from_csv` semantics).
fn add_vary_accept(headers: &mut HeaderKeyDict) {
    match headers.get("Vary") {
        Some(existing) => {
            let has_accept = existing
                .to_lowercase()
                .split(',')
                .any(|p| p.trim() == "accept");
            if !has_accept {
                let updated = format!("{existing}, Accept");
                headers.set("Vary", updated);
            }
        }
        None => headers.set("Vary", "Accept"),
    }
}

/// Python `get_param` / `validate_container_params`: listing query values
/// that are not valid UTF-8 after percent-decode are 400
/// `"<name>" parameter not valid UTF-8`.
fn invalid_utf8_listing_param(query: &str) -> Option<Response> {
    let name = listing_query_invalid_utf8_param(query)?;
    let mut resp = Response::with_body(
        400,
        format!("\"{name}\" parameter not valid UTF-8").into_bytes(),
    );
    resp.headers.set("Content-Type", "text/plain");
    Some(resp)
}

/// Rebuild the query string with `format=json` forced, preserving every
/// other parameter (Python `params['format'] = 'json'`).
fn force_format_json(params: &[(String, String)]) -> String {
    let mut out = String::new();
    for (k, v) in params.iter().filter(|(k, _)| k != "format") {
        if !out.is_empty() {
            out.push('&');
        }
        encode_component(k, &mut out);
        out.push('=');
        encode_component(v, &mut out);
    }
    if !out.is_empty() {
        out.push('&');
    }
    out.push_str("format=json");
    out
}

/// `urllib.parse.quote_plus`: unreserved bytes verbatim, space to `+`, the
/// rest percent-encoded with uppercase hex.
fn encode_component(s: &str, out: &mut String) {
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => {
                out.push('%');
                out.push_str(&format!("{b:02X}"));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Reserved-name filtering
// ---------------------------------------------------------------------------

/// `ListingFilter.filter_reserved`: drop any entry whose `name` or `subdir`
/// carries the reserved byte.
fn filter_reserved(listing: Vec<Obj>) -> Vec<Obj> {
    listing
        .into_iter()
        .filter(|entry| {
            for key in ["name", "subdir"] {
                if let Some(Json::Str(v)) = obj_get(entry, key) {
                    if v.contains(RESERVED_STR) {
                        return false;
                    }
                }
            }
            true
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Body formatters (byte-identical to the Python module + Rust servers)
// ---------------------------------------------------------------------------

/// `account_to_xml`. The `<account>` root always carries the `'\n'` text
/// node, so it never self-closes even when empty.
fn account_to_xml(listing: &[Obj], account_name: &str) -> Result<Vec<u8>, ()> {
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<account name=\"");
    xml_escape_attr(account_name, &mut out);
    out.push_str("\">\n");
    for record in listing {
        if let Some(subdir) = obj_get(record, "subdir") {
            out.push_str("<subdir name=\"");
            xml_escape_attr(&py_str(subdir), &mut out);
            out.push_str("\" />\n");
        } else {
            out.push_str("<container>");
            for field in ["name", "count", "bytes", "last_modified"] {
                let value = obj_get(record, field).ok_or(())?;
                xml_field(&mut out, field, &py_str(value));
            }
            if let Some(policy) = obj_get(record, "storage_policy") {
                xml_field(&mut out, "storage_policy", &py_str(policy));
            }
            out.push_str("</container>\n");
        }
    }
    out.push_str("</account>");
    Ok(out.into_bytes())
}

/// `container_to_xml`. The `<container>` root has no text node, so an empty
/// listing self-closes as `<container name="c" />` (ElementTree behaviour).
fn container_to_xml(listing: &[Obj], base_name: &str) -> Result<Vec<u8>, ()> {
    let mut children = String::new();
    for record in listing {
        if let Some(subdir) = obj_get(record, "subdir") {
            let name = py_str(subdir);
            children.push_str("<subdir name=\"");
            xml_escape_attr(&name, &mut children);
            children.push_str("\">");
            xml_field(&mut children, "name", &name);
            children.push_str("</subdir>");
        } else {
            children.push_str("<object>");
            for field in ["name", "hash", "bytes", "content_type", "last_modified"] {
                let value = obj_get(record, field).ok_or(())?;
                xml_field(&mut children, field, &py_str(value));
            }
            children.push_str("</object>");
        }
    }
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<container name=\"");
    xml_escape_attr(base_name, &mut out);
    out.push('"');
    if children.is_empty() {
        out.push_str(" />");
    } else {
        out.push('>');
        out.push_str(&children);
        out.push_str("</container>");
    }
    Ok(out.into_bytes())
}

/// `listing_to_text`: `name` if present, else `subdir`, one per line. A
/// record with neither key raises `KeyError` in Python (`Err(())` here).
fn listing_to_text(listing: &[Obj]) -> Result<Vec<u8>, ()> {
    let mut out = Vec::new();
    for item in listing {
        if let Some(name) = obj_get(item, "name") {
            out.extend_from_slice(py_str(name).as_bytes());
        } else if let Some(subdir) = obj_get(item, "subdir") {
            out.extend_from_slice(py_str(subdir).as_bytes());
        } else {
            return Err(());
        }
        out.push(b'\n');
    }
    Ok(out)
}

/// ElementTree text escaping.
fn xml_escape_text(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            c => out.push(c),
        }
    }
}

/// ElementTree attribute escaping.
fn xml_escape_attr(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\n' => out.push_str("&#10;"),
            '\t' => out.push_str("&#09;"),
            '\r' => out.push_str("&#13;"),
            c => out.push(c),
        }
    }
}

/// A single element with text content; empty text self-closes as `<tag />`.
fn xml_field(out: &mut String, tag: &str, value: &str) {
    if value.is_empty() {
        out.push_str(&format!("<{tag} />"));
    } else {
        out.push_str(&format!("<{tag}>"));
        xml_escape_text(value, out);
        out.push_str(&format!("</{tag}>"));
    }
}

// ---------------------------------------------------------------------------
// A small JSON model + parser + Python-`json.dumps`-compatible serializer
// ---------------------------------------------------------------------------

/// An ordered object (Python `dict` preserves insertion order).
type Obj = Vec<(String, Json)>;

enum Json {
    Null,
    Bool(bool),
    /// The verbatim number token, re-emitted as-is (exact for integers).
    Num(String),
    Str(String),
    Arr(Vec<Json>),
    Obj(Obj),
}

fn obj_get<'a>(obj: &'a Obj, key: &str) -> Option<&'a Json> {
    obj.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

/// Python `str(value)` for the scalar values that appear in listing fields.
fn py_str(v: &Json) -> String {
    match v {
        Json::Str(s) => s.clone(),
        Json::Num(n) => n.clone(),
        Json::Bool(true) => "True".to_string(),
        Json::Bool(false) => "False".to_string(),
        Json::Null => "None".to_string(),
        // Arrays/objects never appear as a formatted field value; emit a
        // JSON rendering rather than crash.
        other => {
            let mut s = String::new();
            json_write(other, &mut s);
            s
        }
    }
}

/// Parse a listing body, enforcing Python's two sanity checks: the document
/// is an array, and every element is an object. Returns `None` on any parse
/// failure or violated invariant (Python's `except ValueError`).
fn parse_listing(body: &[u8]) -> Option<Vec<Obj>> {
    let mut p = Parser { b: body, i: 0 };
    let val = p.parse_value().ok()?;
    p.skip_ws();
    if p.i != body.len() {
        return None; // trailing garbage
    }
    match val {
        Json::Arr(items) => {
            let mut out = Vec::with_capacity(items.len());
            for it in items {
                match it {
                    Json::Obj(o) => out.push(o),
                    _ => return None,
                }
            }
            Some(out)
        }
        _ => None,
    }
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    fn lit(&mut self, s: &str) -> Result<(), ()> {
        if self.b[self.i..].starts_with(s.as_bytes()) {
            self.i += s.len();
            Ok(())
        } else {
            Err(())
        }
    }

    fn parse_value(&mut self) -> Result<Json, ()> {
        self.skip_ws();
        match self.peek() {
            Some(b'{') => self.parse_object(),
            Some(b'[') => self.parse_array(),
            Some(b'"') => Ok(Json::Str(self.parse_string()?)),
            Some(b't') => {
                self.lit("true")?;
                Ok(Json::Bool(true))
            }
            Some(b'f') => {
                self.lit("false")?;
                Ok(Json::Bool(false))
            }
            Some(b'n') => {
                self.lit("null")?;
                Ok(Json::Null)
            }
            Some(c) if c == b'-' || c.is_ascii_digit() => self.parse_number(),
            _ => Err(()),
        }
    }

    fn parse_object(&mut self) -> Result<Json, ()> {
        self.i += 1; // consume '{'
        let mut pairs: Obj = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok(Json::Obj(pairs));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(());
            }
            let key = self.parse_string()?;
            self.skip_ws();
            if self.peek() != Some(b':') {
                return Err(());
            }
            self.i += 1;
            let value = self.parse_value()?;
            // Python `dict`: a repeated key keeps its position, last value wins.
            match pairs.iter_mut().find(|(k, _)| *k == key) {
                Some(slot) => slot.1 = value,
                None => pairs.push((key, value)),
            }
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    break;
                }
                _ => return Err(()),
            }
        }
        Ok(Json::Obj(pairs))
    }

    fn parse_array(&mut self) -> Result<Json, ()> {
        self.i += 1; // consume '['
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Ok(Json::Arr(items));
        }
        loop {
            let value = self.parse_value()?;
            items.push(value);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    break;
                }
                _ => return Err(()),
            }
        }
        Ok(Json::Arr(items))
    }

    fn parse_number(&mut self) -> Result<Json, ()> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        match self.peek() {
            Some(b'0') => self.i += 1,
            Some(c) if c.is_ascii_digit() => {
                while matches!(self.peek(), Some(d) if d.is_ascii_digit()) {
                    self.i += 1;
                }
            }
            _ => return Err(()),
        }
        if self.peek() == Some(b'.') {
            self.i += 1;
            if !matches!(self.peek(), Some(d) if d.is_ascii_digit()) {
                return Err(());
            }
            while matches!(self.peek(), Some(d) if d.is_ascii_digit()) {
                self.i += 1;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.i += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.i += 1;
            }
            if !matches!(self.peek(), Some(d) if d.is_ascii_digit()) {
                return Err(());
            }
            while matches!(self.peek(), Some(d) if d.is_ascii_digit()) {
                self.i += 1;
            }
        }
        let token = std::str::from_utf8(&self.b[start..self.i]).map_err(|_| ())?;
        Ok(Json::Num(token.to_string()))
    }

    fn parse_hex4(&mut self) -> Result<u32, ()> {
        let mut v = 0u32;
        for _ in 0..4 {
            let c = self.peek().ok_or(())?;
            let d = (c as char).to_digit(16).ok_or(())?;
            v = v * 16 + d;
            self.i += 1;
        }
        Ok(v)
    }

    fn parse_string(&mut self) -> Result<String, ()> {
        self.i += 1; // consume opening quote
        let mut bytes: Vec<u8> = Vec::new();
        loop {
            let c = self.peek().ok_or(())?;
            match c {
                b'"' => {
                    self.i += 1;
                    break;
                }
                b'\\' => {
                    self.i += 1;
                    let e = self.peek().ok_or(())?;
                    self.i += 1;
                    match e {
                        b'"' => bytes.push(b'"'),
                        b'\\' => bytes.push(b'\\'),
                        b'/' => bytes.push(b'/'),
                        b'b' => bytes.push(0x08),
                        b'f' => bytes.push(0x0c),
                        b'n' => bytes.push(b'\n'),
                        b'r' => bytes.push(b'\r'),
                        b't' => bytes.push(b'\t'),
                        b'u' => {
                            let cp = self.parse_hex4()?;
                            let ch = if (0xD800..=0xDBFF).contains(&cp) {
                                if self.peek() == Some(b'\\')
                                    && self.b.get(self.i + 1).copied() == Some(b'u')
                                {
                                    self.i += 2;
                                    let lo = self.parse_hex4()?;
                                    if (0xDC00..=0xDFFF).contains(&lo) {
                                        let c = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                                        char::from_u32(c).unwrap_or('\u{FFFD}')
                                    } else {
                                        '\u{FFFD}'
                                    }
                                } else {
                                    '\u{FFFD}'
                                }
                            } else if (0xDC00..=0xDFFF).contains(&cp) {
                                '\u{FFFD}'
                            } else {
                                char::from_u32(cp).unwrap_or('\u{FFFD}')
                            };
                            let mut buf = [0u8; 4];
                            bytes.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                        }
                        _ => return Err(()),
                    }
                }
                // Raw control characters are invalid in a JSON string
                // (Python `json.loads` is strict by default).
                0x00..=0x1f => return Err(()),
                _ => {
                    bytes.push(c);
                    self.i += 1;
                }
            }
        }
        String::from_utf8(bytes).map_err(|_| ())
    }
}

/// `json.dumps(listing).encode('ascii')` for a list of objects.
fn json_dumps_listing(listing: &[Obj]) -> Vec<u8> {
    let mut out = String::from("[");
    for (i, obj) in listing.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        json_write_obj(obj, &mut out);
    }
    out.push(']');
    out.into_bytes()
}

fn json_write(v: &Json, out: &mut String) {
    match v {
        Json::Null => out.push_str("null"),
        Json::Bool(true) => out.push_str("true"),
        Json::Bool(false) => out.push_str("false"),
        Json::Num(n) => out.push_str(n),
        Json::Str(s) => json_escape(s, out),
        Json::Arr(items) => {
            out.push('[');
            for (i, it) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                json_write(it, out);
            }
            out.push(']');
        }
        Json::Obj(pairs) => json_write_obj(pairs, out),
    }
}

fn json_write_obj(obj: &Obj, out: &mut String) {
    out.push('{');
    for (i, (k, v)) in obj.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        json_escape(k, out);
        out.push_str(": ");
        json_write(v, out);
    }
    out.push('}');
}

/// Python `json.dumps` string escaping with `ensure_ascii=True`.
fn json_escape(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c if (c as u32) > 0x7e => {
                let cp = c as u32;
                if cp > 0xffff {
                    let v = cp - 0x10000;
                    out.push_str(&format!("\\u{:04x}", 0xd800 + (v >> 10)));
                    out.push_str(&format!("\\u{:04x}", 0xdc00 + (v & 0x3ff)));
                } else {
                    out.push_str(&format!("\\u{cp:04x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(method: &str, path: &str, query: &str) -> Request {
        Request {
            method: method.into(),
            path: path.into(),
            query_string: query.into(),
            headers: HeaderKeyDict::new(),
            body: swift_http::Body::empty(),
        }
    }

    /// Run the filter with a mock backend supplied by `factory`, which sees
    /// the (format-forced) subrequest and returns the backend response. The
    /// returned body is materialized so assertions can read it in place.
    fn call(
        request: Request,
        factory: impl Fn(&Request) -> Response + Send + Sync + 'static,
    ) -> Response {
        let lf = ListingFormats;
        let next: crate::NextFn = std::sync::Arc::new(move |r: Request| factory(&r));
        let mut resp = lf.handle(request, &next);
        resp.body.materialize(u64::MAX).unwrap();
        resp
    }

    /// Test bodies are always buffered once `call` has materialized them.
    fn body_bytes(resp: &Response) -> &[u8] {
        match &resp.body {
            swift_http::Body::Buffered(b) => b,
            swift_http::Body::Streamed(_) | swift_http::Body::Channel(_) => unreachable!(),
        }
    }

    /// A 200 `application/json` backend response with the given body.
    fn json_backend(body: &[u8]) -> Response {
        let mut resp = Response::new(200);
        resp.headers
            .set("Content-Type", "application/json; charset=utf-8");
        resp.body = body.to_vec().into();
        resp
    }

    #[test]
    fn test_account_get_json_roundtrip() {
        // format=json => re-serialized JSON, no Vary (client fixed the format).
        let body = br#"[{"subdir": "s/"}, {"name": "c", "count": 2, "bytes": 3}]"#;
        let resp = call(req("GET", "/v1/AUTH_a", "format=json"), move |_| {
            json_backend(body)
        });
        assert_eq!(resp.status, 200);
        assert_eq!(body_bytes(&resp), body);
        assert_eq!(
            resp.headers.get("Content-Type"),
            Some("application/json; charset=utf-8")
        );
        assert_eq!(
            resp.headers.get("Content-Length"),
            Some(body.len().to_string().as_str())
        );
        assert!(resp.headers.get("Vary").is_none());
    }

    #[test]
    fn test_account_get_xml() {
        let body = br#"[{"subdir": "s/"}, {"name": "c", "count": 2, "bytes": 3, "last_modified": "2024", "storage_policy": "gold"}]"#;
        let resp = call(req("GET", "/v1/acct<>&", "format=xml"), move |_| {
            json_backend(body)
        });
        let expected = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<account name=\"acct&lt;&gt;&amp;\">\n<subdir name=\"s/\" />\n<container><name>c</name><count>2</count><bytes>3</bytes><last_modified>2024</last_modified><storage_policy>gold</storage_policy></container>\n</account>";
        assert_eq!(body_bytes(&resp), expected);
        assert_eq!(
            resp.headers.get("Content-Type"),
            Some("application/xml; charset=utf-8")
        );
    }

    #[test]
    fn test_container_get_xml() {
        let body = br#"[{"subdir": "photos/"}, {"name": "o", "hash": "h", "bytes": 5, "content_type": "text/plain", "last_modified": "2024"}]"#;
        let resp = call(req("GET", "/v1/a/cont", "format=xml"), move |_| {
            json_backend(body)
        });
        let expected = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<container name=\"cont\"><subdir name=\"photos/\"><name>photos/</name></subdir><object><name>o</name><hash>h</hash><bytes>5</bytes><content_type>text/plain</content_type><last_modified>2024</last_modified></object></container>";
        assert_eq!(body_bytes(&resp), expected);
    }

    #[test]
    fn test_container_get_xml_empty_self_closes() {
        // ElementTree self-closes an empty <container>; the account root does not.
        let resp = call(req("GET", "/v1/a/c", "format=xml"), move |_| {
            json_backend(b"[]")
        });
        assert_eq!(
            body_bytes(&resp),
            b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<container name=\"c\" />"
        );
    }

    #[test]
    fn test_account_get_xml_empty_keeps_text_node() {
        let resp = call(req("GET", "/v1/a", "format=xml"), move |_| {
            json_backend(b"[]")
        });
        assert_eq!(
            body_bytes(&resp),
            b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<account name=\"a\">\n</account>"
        );
    }

    #[test]
    fn test_get_text() {
        let body = br#"[{"name": "a"}, {"subdir": "b/"}, {"name": "c", "hash": "x"}]"#;
        let resp = call(req("GET", "/v1/a/c", "format=plain"), move |_| {
            json_backend(body)
        });
        assert_eq!(body_bytes(&resp), b"a\nb/\nc\n");
        assert_eq!(
            resp.headers.get("Content-Type"),
            Some("text/plain; charset=utf-8")
        );
        assert_eq!(resp.status, 200);
    }

    #[test]
    fn test_empty_text_becomes_204() {
        let resp = call(req("GET", "/v1/a/c", "format=plain"), move |_| {
            json_backend(b"[]")
        });
        assert_eq!(resp.status, 204);
        assert_eq!(resp.reason, "No Content");
        assert!(body_bytes(&resp).is_empty());
        assert_eq!(resp.headers.get("Content-Length"), Some("0"));
        assert_eq!(
            resp.headers.get("Content-Type"),
            Some("text/plain; charset=utf-8")
        );
    }

    #[test]
    fn test_accept_header_negotiation_adds_vary() {
        // No format param => can_vary; Accept picks xml.
        let mut request = req("GET", "/v1/a/c", "");
        request.headers.set("Accept", "application/xml");
        let resp = call(request, move |_| json_backend(b"[]"));
        assert_eq!(
            body_bytes(&resp),
            b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<container name=\"c\" />"
        );
        assert_eq!(resp.headers.get("Vary"), Some("Accept"));
    }

    #[test]
    fn test_vary_not_duplicated() {
        let mut request = req("GET", "/v1/a/c", "");
        request.headers.set("Accept", "application/xml");
        let resp = call(request, move |_| {
            let mut r = json_backend(b"[]");
            r.headers.set("Vary", "Accept");
            r
        });
        assert_eq!(resp.headers.get("Vary"), Some("Accept"));
    }

    #[test]
    fn test_vary_appended_to_existing() {
        let mut request = req("GET", "/v1/a/c", "");
        request.headers.set("Accept", "application/json");
        let resp = call(request, move |_| {
            let mut r = json_backend(b"[]");
            r.headers.set("Vary", "Origin");
            r
        });
        assert_eq!(resp.headers.get("Vary"), Some("Origin, Accept"));
    }

    #[test]
    fn test_reserved_names_filtered() {
        let body = br#"[{"name": "ok"}, {"name": "bad\u0000name"}, {"subdir": "sub\u0000/"}]"#;
        let resp = call(req("GET", "/v1/a/c", "format=plain"), move |_| {
            json_backend(body)
        });
        assert_eq!(body_bytes(&resp), b"ok\n");
    }

    #[test]
    fn test_allow_reserved_names_header_keeps_them() {
        let body = br#"[{"name": "ok"}, {"name": "bad\u0000name"}]"#;
        let mut request = req("GET", "/v1/a/c", "format=plain");
        request
            .headers
            .set("X-Backend-Allow-Reserved-Names", "true");
        let resp = call(request, move |_| json_backend(body));
        assert_eq!(body_bytes(&resp), b"ok\nbad\x00name\n");
    }

    #[test]
    fn test_bad_json_passthrough_with_vary() {
        let mut request = req("GET", "/v1/a/c", "");
        request.headers.set("Accept", "application/xml");
        let resp = call(request, move |_| json_backend(b"not json{{{"));
        // Untouched body, still application/json, but Vary was added.
        assert_eq!(body_bytes(&resp), b"not json{{{");
        assert_eq!(
            resp.headers.get("Content-Type"),
            Some("application/json; charset=utf-8")
        );
        assert_eq!(resp.headers.get("Vary"), Some("Accept"));
    }

    #[test]
    fn test_non_array_json_passthrough() {
        // Valid JSON but not a list => ValueError sanity check => passthrough.
        let resp = call(req("GET", "/v1/a/c", "format=xml"), move |_| {
            json_backend(br#"{"not": "a list"}"#)
        });
        assert_eq!(body_bytes(&resp), br#"{"not": "a list"}"#);
        assert_eq!(
            resp.headers.get("Content-Type"),
            Some("application/json; charset=utf-8")
        );
    }

    #[test]
    fn test_array_of_non_objects_passthrough() {
        let resp = call(req("GET", "/v1/a/c", "format=xml"), move |_| {
            json_backend(br#"[1, 2, 3]"#)
        });
        assert_eq!(body_bytes(&resp), b"[1, 2, 3]");
    }

    #[test]
    fn test_missing_required_field_keyerror_passthrough() {
        // A container object missing hash/bytes/... => KeyError => original body.
        let body = br#"[{"name": "o"}]"#;
        let resp = call(req("GET", "/v1/a/c", "format=xml"), move |_| {
            json_backend(body)
        });
        assert_eq!(body_bytes(&resp), body);
        assert_eq!(
            resp.headers.get("Content-Type"),
            Some("application/json; charset=utf-8")
        );
    }

    #[test]
    fn test_text_missing_name_and_subdir_keyerror_passthrough() {
        let body = br#"[{"hash": "x"}]"#;
        let resp = call(req("GET", "/v1/a/c", "format=plain"), move |_| {
            json_backend(body)
        });
        assert_eq!(body_bytes(&resp), body);
    }

    #[test]
    fn test_object_request_passthrough_untouched() {
        // /v1/a/c/o has too many segments => not an account/container listing.
        let resp = call(req("GET", "/v1/a/c/o", "format=xml"), move |r| {
            // subrequest must NOT have been rewritten to json
            assert_eq!(r.query_string, "format=xml");
            json_backend(b"[{\"name\": \"o\"}]")
        });
        assert_eq!(body_bytes(&resp), b"[{\"name\": \"o\"}]");
        assert_eq!(
            resp.headers.get("Content-Type"),
            Some("application/json; charset=utf-8")
        );
        assert!(resp.headers.get("Vary").is_none());
    }

    #[test]
    fn test_invalid_api_version_passthrough() {
        let resp = call(req("GET", "/v2/a/c", "format=xml"), move |r| {
            assert_eq!(r.query_string, "format=xml");
            json_backend(b"[]")
        });
        assert_eq!(body_bytes(&resp), b"[]");
    }

    #[test]
    fn test_post_method_passthrough() {
        let resp = call(req("POST", "/v1/a/c", "format=xml"), move |r| {
            assert_eq!(r.query_string, "format=xml");
            json_backend(b"[]")
        });
        assert_eq!(body_bytes(&resp), b"[]");
    }

    #[test]
    fn test_head_format_json_when_backend_head_is_plain_204() {
        let resp = call(req("HEAD", "/v1/a/c", "format=json"), move |_| {
            let mut r = Response::new(204);
            r.headers.set("Content-Type", "text/plain; charset=utf-8");
            r.headers.set("Content-Length", 0);
            r
        });
        assert_eq!(resp.status, 204);
        assert_eq!(
            resp.headers.get("Content-Type"),
            Some("application/json; charset=utf-8")
        );
        assert_eq!(resp.headers.get("Content-Length"), Some("0"));
    }

    #[test]
    fn test_head_sets_content_type_and_zero_length() {
        let resp = call(req("HEAD", "/v1/a", "format=xml"), move |_| {
            let mut r = Response::new(204);
            r.headers
                .set("Content-Type", "application/json; charset=utf-8");
            r
        });
        assert_eq!(resp.status, 204);
        assert!(body_bytes(&resp).is_empty());
        assert_eq!(
            resp.headers.get("Content-Type"),
            Some("application/xml; charset=utf-8")
        );
        assert_eq!(resp.headers.get("Content-Length"), Some("0"));
    }

    #[test]
    fn test_non_2xx_status_passthrough() {
        let resp = call(req("GET", "/v1/a/c", "format=xml"), move |_| {
            let mut r = Response::new(404);
            r.headers
                .set("Content-Type", "application/json; charset=utf-8");
            r.body = b"[]".to_vec().into();
            r
        });
        assert_eq!(resp.status, 404);
        assert_eq!(body_bytes(&resp), b"[]");
        // status check returns before Vary is ever considered
        assert!(resp.headers.get("Vary").is_none());
    }

    #[test]
    fn test_non_json_content_type_passthrough_with_vary() {
        let mut request = req("GET", "/v1/a/c", "");
        request.headers.set("Accept", "text/plain");
        let resp = call(request, move |_| {
            let mut r = Response::new(200);
            r.headers.set("Content-Type", "text/html");
            r.body = b"<html>staticweb</html>".to_vec().into();
            r
        });
        assert_eq!(body_bytes(&resp), b"<html>staticweb</html>");
        assert_eq!(resp.headers.get("Content-Type"), Some("text/html"));
        assert_eq!(resp.headers.get("Vary"), Some("Accept"));
    }

    #[test]
    fn test_oversize_body_passthrough() {
        let big = vec![b' '; MAX_CONTAINER_LISTING_CONTENT_LENGTH + 1];
        let expected_len = big.len();
        let resp = call(req("GET", "/v1/a/c", "format=xml"), move |_| {
            json_backend(&big)
        });
        assert_eq!(body_bytes(&resp).len(), expected_len);
        assert_eq!(
            resp.headers.get("Content-Type"),
            Some("application/json; charset=utf-8")
        );
    }

    #[test]
    fn test_format_forced_to_json_preserving_other_params() {
        let resp = call(
            req("GET", "/v1/a/c", "prefix=a%2Fb&format=xml&limit=5"),
            move |r| {
                let mut resp = json_backend(b"[]");
                resp.headers.set("X-Seen-Query", r.query_string.as_str());
                resp
            },
        );
        assert_eq!(
            resp.headers.get("X-Seen-Query"),
            Some("prefix=a%2Fb&limit=5&format=json")
        );
    }

    #[test]
    fn test_versions_query_stays_json_without_format() {
        // Python object_versioning._list_versions opts listing_formats out.
        // GET ?versions (no format=) must remain application/json, not names+\n.
        let body = br#"[{"bytes": 5, "content_type": "text/plain", "hash": "h", "is_latest": true, "last_modified": "2026-09-01T00:00:00.000000", "name": "obj1", "version_id": "1788248172.69139"}]"#;
        for query in ["versions", "versions=None", "versions="] {
            let resp = call(req("GET", "/v1/a/c", query), {
                let body = body;
                move |_| json_backend(body)
            });
            assert_eq!(resp.status, 200, "query={query}");
            assert_eq!(body_bytes(&resp), body, "query={query}");
            let ct = resp.headers.get("Content-Type").unwrap_or("");
            assert!(
                ct.starts_with("application/json"),
                "query={query} content-type={ct:?}"
            );
        }
    }

    #[test]
    fn test_versions_empty_listing_stays_json_array() {
        // Empty text listings collapse to 204; versions listings must stay `[]`.
        let resp = call(req("GET", "/v1/a/c", "versions"), move |_| {
            json_backend(b"[]")
        });
        assert_eq!(resp.status, 200);
        assert_eq!(body_bytes(&resp), b"[]");
        assert_eq!(
            resp.headers.get("Content-Type"),
            Some("application/json; charset=utf-8")
        );
    }

    #[test]
    fn test_versions_format_plain_or_xml_is_406() {
        // test.functional.test_object_versioning.TestContainerOperations::test_unacceptable
        for query in ["format=plain&versions", "format=xml&versions"] {
            let resp = call(req("GET", "/v1/a/c", query), |_| {
                panic!("backend must not run for versions non-json format")
            });
            assert_eq!(resp.status, 406, "query={query}");
        }
    }

    #[test]
    fn test_versions_non_json_accept_is_406() {
        for accept in ["text/plain", "text/xml", "application/xml", "foo/bar"] {
            let mut request = req("GET", "/v1/a/c", "versions");
            request.headers.set("Accept", accept);
            let resp = call(request, {
                let accept = accept.to_string();
                move |_| panic!("backend must not run for versions Accept={accept}")
            });
            assert_eq!(resp.status, 406, "Accept={accept}");
        }
    }

    #[test]
    fn test_unmatched_accept_without_versions_is_406() {
        let mut request = req("GET", "/v1/a/c", "");
        request.headers.set("Accept", "foo/bar");
        let resp = call(request, |_| {
            panic!("backend must not run for Accept=foo/bar")
        });
        assert_eq!(resp.status, 406);
    }

    #[test]
    fn test_unknown_format_defaults_to_text() {
        let body = br#"[{"name": "a"}]"#;
        let resp = call(req("GET", "/v1/a/c", "format=banana"), move |_| {
            json_backend(body)
        });
        assert_eq!(body_bytes(&resp), b"a\n");
        assert_eq!(
            resp.headers.get("Content-Type"),
            Some("text/plain; charset=utf-8")
        );
    }

    #[test]
    fn test_json_reserialization_escapes_non_ascii() {
        // format=json path re-dumps with ensure_ascii.
        let body = "[{\"name\": \"\u{4e2d}\"}]".as_bytes();
        let resp = call(req("GET", "/v1/a/c", "format=json"), move |_| {
            json_backend(body)
        });
        // ensure_ascii => the raw U+4E2D comes back escaped as 中.
        assert_eq!(body_bytes(&resp), b"[{\"name\": \"\\u4e2d\"}]");
    }

    #[test]
    fn test_xml_field_empty_self_closes() {
        let body =
            br#"[{"name": "", "hash": "h", "bytes": 0, "content_type": "", "last_modified": ""}]"#;
        let resp = call(req("GET", "/v1/a/c", "format=xml"), move |_| {
            json_backend(body)
        });
        assert_eq!(
            body_bytes(&resp),
            b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<container name=\"c\"><object><name /><hash>h</hash><bytes>0</bytes><content_type /><last_modified /></object></container>"
        );
    }

    #[test]
    fn test_non_utf8_delimiter_is_400() {
        // Probe test_sharding_listing: delimiter=%ff must 400 before
        // force_format_json lossy-unquotes it to U+FFFD.
        let lf = ListingFormats;
        let mut r = req("GET", "/v1/AUTH_test/c", "delimiter=%ff");
        match lf.prepare(&mut r) {
            crate::MwPrep::ShortCircuit(resp) => {
                assert_eq!(resp.status, 400);
                let body = String::from_utf8_lossy(match &resp.body {
                    swift_http::Body::Buffered(b) => b,
                    _ => panic!("expected buffered 400 body"),
                });
                assert!(body.contains("not valid UTF-8"), "{body:?}");
                assert!(body.contains("delimiter"), "{body:?}");
            }
            crate::MwPrep::Continue => panic!("delimiter=%ff must short-circuit"),
        }

        let resp = call(req("GET", "/v1/AUTH_test/c", "delimiter=%ff"), |_| {
            panic!("backend must not run for delimiter=%ff")
        });
        assert_eq!(resp.status, 400);
        let body = String::from_utf8_lossy(body_bytes(&resp));
        assert!(body.contains("not valid UTF-8"), "{body:?}");
        assert!(body.contains("delimiter"), "{body:?}");
        assert_eq!(resp.headers.get("Content-Type"), Some("text/plain"));
    }
}
