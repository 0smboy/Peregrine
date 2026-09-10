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

//! `formpost`: browser HTML form → object PUT, ported from
//! `swift/common/middleware/formpost.py`.
//!
//! A `POST` with `Content-Type: multipart/form-data` carries signed form
//! fields (`redirect`, `max_file_size`, `max_file_count`, `expires`,
//! `signature`) plus one or more file parts. Each file becomes a
//! pre-authorized `PUT` subrequest whose path is the form action path with
//! the filename appended. The HMAC is
//! `"{path}\n{redirect}\n{max_file_size}\n{max_file_count}\n{expires}"`
//! keyed by an account or container Temp-URL key (same keys as TempURL).
//!
//! Keys come from an injectable [`KeyProvider`] (proxy HEADs account /
//! container meta). Multipart parsing uses [`swift_http::MimeDocs`].
//!
//! Wontfix / deferred (documented):
//! * Metrics (`formpost.digests.*` counters).
//! * Streaming mid-PUT abort that leaves a partial object when
//!   `max_file_size` is exceeded after the backend has already accepted
//!   bytes — we enforce the cap before issuing the subrequest body (buffer
//!   up to `max_file_size + 1`).

use std::future::Future;
use std::io::Read;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use swift_http::{split_path, Body, HeaderKeyDict, MimeDocs, Request, Response};

use crate::tempurl::{extract_digest_and_algorithm, hmac_hex, KeyProvider};
use crate::{AsyncNextFn, Middleware, NextFn};

/// Default digests (`digest.DEFAULT_ALLOWED_DIGESTS`).
pub const DEFAULT_ALLOWED_DIGESTS: &[&str] = &["sha1", "sha256", "sha512"];

const MAX_VALUE_LENGTH: usize = 4096;
const READ_CHUNK_SIZE: usize = 4096;

/// Signed form constraints (HMAC inputs).
#[derive(Debug, Clone, PartialEq)]
pub struct FormPostAttributes {
    pub path: String,
    pub redirect: String,
    pub max_file_size: u64,
    pub max_file_count: u64,
    pub expires: i64,
}

impl FormPostAttributes {
    fn hmac_body(&self) -> String {
        format!(
            "{}\n{}\n{}\n{}\n{}",
            self.path, self.redirect, self.max_file_size, self.max_file_count, self.expires
        )
    }
}

/// Compute the formpost signature for `key` under `algo`.
pub fn formpost_hmac(algo: &str, key: &[u8], attrs: &FormPostAttributes) -> Option<String> {
    hmac_hex(algo, key, attrs.hmac_body().as_bytes())
}

/// Result of verifying a formpost signature.
#[derive(Debug, Clone, PartialEq)]
pub enum FormPostVerify {
    Valid,
    BadSignature,
    Invalid,
    Expired,
}

fn streq_const_time(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Verify a formpost `signature` against every candidate `key`.
pub fn verify_signature(
    keys: &[&[u8]],
    attrs: &FormPostAttributes,
    signature: &str,
    now: i64,
    allowed_digests: &[String],
) -> FormPostVerify {
    if attrs.expires < now {
        return FormPostVerify::Expired;
    }
    let Ok((algo, sig_hex)) = extract_digest_and_algorithm(signature) else {
        return FormPostVerify::Invalid;
    };
    if !allowed_digests.iter().any(|a| a == &algo) {
        return FormPostVerify::Invalid;
    }
    for key in keys {
        if let Some(sig) = formpost_hmac(&algo, key, attrs) {
            if streq_const_time(&sig, &sig_hex) {
                return FormPostVerify::Valid;
            }
        }
    }
    FormPostVerify::BadSignature
}

/// Parse `Content-Disposition` / `Content-Type` attribute lists
/// (`swift.common.utils.parse_content_disposition`).
pub fn parse_content_disposition(
    header: &str,
) -> (String, std::collections::HashMap<String, String>) {
    let mut attributes = std::collections::HashMap::new();
    let (main, attrs) = match header.split_once(';') {
        Some((h, a)) => (h.trim().to_string(), a.trim()),
        None => return (header.trim().to_string(), attributes),
    };
    let mut rest = attrs;
    while !rest.is_empty() {
        rest = rest.trim_start();
        if rest.is_empty() {
            break;
        }
        let eq = match rest.find('=') {
            Some(i) => i,
            None => break,
        };
        let name = rest[..eq].trim().to_ascii_lowercase();
        let after = rest[eq + 1..].trim_start();
        let (value, next) = if let Some(stripped) = after.strip_prefix('"') {
            if let Some(end) = stripped.find('"') {
                (
                    stripped[..end].to_string(),
                    stripped[end + 1..].trim_start_matches(';').trim_start(),
                )
            } else {
                (stripped.to_string(), "")
            }
        } else {
            let end = after.find(';').unwrap_or(after.len());
            let value = after[..end].trim().to_string();
            let next = after[end..].trim_start_matches(';').trim_start();
            (value, next)
        };
        attributes.insert(name, value);
        rest = next;
    }
    (main, attributes)
}

/// Extract `boundary` from a `Content-Type: multipart/form-data; boundary=…`
/// header. Returns `None` when the type is not multipart/form-data or the
/// boundary is missing.
pub fn multipart_boundary(content_type: &str) -> Option<String> {
    let (main, attrs) = parse_content_disposition(content_type);
    if main.eq_ignore_ascii_case("multipart/form-data") {
        attrs.get("boundary").cloned().filter(|b| !b.is_empty())
    } else {
        None
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn is_success(status: u16) -> bool {
    (200..300).contains(&status)
}

fn unauthorized(message: &str) -> Response {
    let body = format!("FormPost: {}", title_case_words(message));
    let mut resp = Response::with_body(401, body.into_bytes());
    resp.headers.set("Content-Type", "text/plain");
    resp
}

fn bad_request(message: &str) -> Response {
    let body = format!("FormPost: {message}");
    let mut resp = Response::with_body(400, body.into_bytes());
    resp.headers.set("Content-Type", "text/plain");
    resp
}

fn title_case_words(s: &str) -> String {
    s.split_whitespace()
        .map(|w| {
            let mut c = w.chars();
            match c.next() {
                None => String::new(),
                Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn quote_query(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// The `formpost` middleware.
pub struct FormPost {
    key_provider: Arc<dyn KeyProvider>,
    pub allowed_digests: Vec<String>,
}

impl FormPost {
    pub fn new(key_provider: Arc<dyn KeyProvider>) -> Self {
        FormPost {
            key_provider,
            allowed_digests: DEFAULT_ALLOWED_DIGESTS
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
        }
    }

    fn translate_form(&self, mut req: Request, boundary: &str, next: &NextFn) -> Response {
        let path = req.path.clone();
        let parts = match split_path(&path, 3, 4, true) {
            Ok(p) => p,
            Err(_) => return unauthorized("invalid signature"),
        };
        let account = parts[1].clone().unwrap_or_default();
        let container = parts[2].clone().unwrap_or_default();
        if account.is_empty() || container.is_empty() {
            return unauthorized("invalid signature");
        }
        let keys = self.key_provider.keys_for(&account, &container);
        if keys.is_empty() {
            return unauthorized("invalid signature");
        }

        let (reader, _) = req.body.take().into_reader();
        let mut mime = MimeDocs::new(reader, boundary.as_bytes());

        let mut attributes: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        let mut status: u16 = 0;
        let mut message = String::new();
        let mut subheaders = HeaderKeyDict::new();
        let mut resp_body: Option<Vec<u8>> = None;
        let mut file_count: u64 = 0;

        loop {
            let headers = match mime.next_document() {
                Ok(Some(h)) => h,
                Ok(None) => break,
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::InvalidData
                        && e.to_string().contains("invalid starting boundary")
                    {
                        return bad_request("invalid starting boundary");
                    }
                    return bad_request(&e.to_string());
                }
            };
            let disposition = headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("Content-Disposition"))
                .map(|(_, v)| v.as_str())
                .unwrap_or("");
            let (disp, attrs) = parse_content_disposition(disposition);
            if disp == "form-data" && attrs.contains_key("filename") {
                file_count += 1;
                let max_count: u64 = match attributes
                    .get("max_file_count")
                    .map(|s| s.as_str())
                    .unwrap_or("0")
                    .parse()
                {
                    Ok(n) => n,
                    Err(_) => return bad_request("max_file_count not an integer"),
                };
                if file_count > max_count {
                    status = 400;
                    message = "max file count exceeded".into();
                    break;
                }
                let mut file_attributes = attributes.clone();
                let filename = attrs
                    .get("filename")
                    .cloned()
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "filename".into());
                file_attributes.insert("filename".into(), filename);
                if !file_attributes.contains_key("content-type") {
                    if let Some((_, ct)) = headers
                        .iter()
                        .find(|(k, _)| k.eq_ignore_ascii_case("Content-Type"))
                    {
                        file_attributes.insert(
                            "content-type".into(),
                            if ct.is_empty() {
                                "application/octet-stream".into()
                            } else {
                                ct.clone()
                            },
                        );
                    }
                }
                if !file_attributes.contains_key("content-encoding") {
                    if let Some((_, ce)) = headers
                        .iter()
                        .find(|(k, _)| k.eq_ignore_ascii_case("Content-Encoding"))
                    {
                        file_attributes.insert("content-encoding".into(), ce.clone());
                    }
                }
                match self
                    .perform_subrequest(&path, &file_attributes, &mut mime, &keys, |put| next(put))
                {
                    Ok((st, hdrs, body)) => {
                        status = st;
                        subheaders = hdrs;
                        resp_body = Some(body);
                        if !is_success(st) {
                            break;
                        }
                    }
                    Err(FormError::Unauthorized(m)) => return unauthorized(&m),
                    Err(FormError::Invalid(m)) => return bad_request(&m),
                    Err(FormError::Eof(m)) => return bad_request(&m),
                }
            } else {
                let mut data = Vec::new();
                let mut remaining = MAX_VALUE_LENGTH;
                let mut buf = [0u8; READ_CHUNK_SIZE];
                while remaining > 0 {
                    let n = match mime.read(&mut buf[..remaining.min(READ_CHUNK_SIZE)]) {
                        Ok(0) => break,
                        Ok(n) => n,
                        Err(e) => return bad_request(&e.to_string()),
                    };
                    data.extend_from_slice(&buf[..n]);
                    remaining = remaining.saturating_sub(n);
                }
                // Drain remainder of the part.
                let mut sink = [0u8; READ_CHUNK_SIZE];
                while mime.read(&mut sink).unwrap_or(0) > 0 {}
                let mut text = String::from_utf8_lossy(&data).into_owned();
                // Python: data.rstrip('\r\n--')
                while text.ends_with('\r') || text.ends_with('\n') || text.ends_with('-') {
                    text.pop();
                }
                if let Some(name) = attrs.get("name") {
                    attributes.insert(name.to_ascii_lowercase(), text);
                }
            }
        }

        finish_formpost(status, message, subheaders, resp_body, &attributes)
    }

    fn build_put_request(
        &self,
        orig_path: &str,
        attributes: &std::collections::HashMap<String, String>,
        mime: &mut MimeDocs,
        keys: &[String],
    ) -> Result<Request, FormError> {
        let max_file_size: u64 = attributes
            .get("max_file_size")
            .map(|s| s.as_str())
            .unwrap_or("0")
            .parse()
            .map_err(|_| FormError::Invalid("max_file_size not an integer".into()))?;

        // Buffer up to max_file_size+1 so we can reject before the PUT.
        let mut file_data = Vec::new();
        let mut buf = [0u8; READ_CHUNK_SIZE];
        loop {
            let n = mime
                .read(&mut buf)
                .map_err(|e| FormError::Invalid(e.to_string()))?;
            if n == 0 {
                break;
            }
            file_data.extend_from_slice(&buf[..n]);
            if file_data.len() as u64 > max_file_size {
                return Err(FormError::Eof("max_file_size exceeded".into()));
            }
        }

        let mut put_path = orig_path.to_string();
        if !put_path.ends_with('/') && put_path.matches('/').count() < 4 {
            put_path.push('/');
        }
        let filename = attributes
            .get("filename")
            .map(|s| s.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or("filename");
        put_path.push_str(filename);

        let expires: i64 = attributes
            .get("expires")
            .map(|s| s.as_str())
            .unwrap_or("0")
            .parse()
            .map_err(|_| FormError::Invalid("expired not an integer".into()))?;
        if expires < now_unix() {
            return Err(FormError::Unauthorized("form expired".into()));
        }

        let redirect = attributes.get("redirect").cloned().unwrap_or_default();
        let max_file_count = attributes
            .get("max_file_count")
            .cloned()
            .unwrap_or_else(|| "0".into());
        let max_file_size_s = attributes
            .get("max_file_size")
            .cloned()
            .unwrap_or_else(|| "0".into());
        let expires_s = attributes
            .get("expires")
            .cloned()
            .unwrap_or_else(|| "0".into());

        // HMAC over the string form fields (matches Python %s formatting).
        let hmac_body =
            format!("{orig_path}\n{redirect}\n{max_file_size_s}\n{max_file_count}\n{expires_s}");
        let signature = attributes.get("signature").cloned().unwrap_or_default();
        let (algo, sig_hex) = extract_digest_and_algorithm(&signature)
            .map_err(|_| FormError::Unauthorized("invalid signature".into()))?;
        if !self.allowed_digests.iter().any(|a| a == &algo) {
            return Err(FormError::Unauthorized("invalid signature".into()));
        }
        let mut valid = false;
        for key in keys {
            if let Some(sig) = hmac_hex(&algo, key.as_bytes(), hmac_body.as_bytes()) {
                if streq_const_time(&sig, &sig_hex) {
                    valid = true;
                    break;
                }
            }
        }
        if !valid {
            return Err(FormError::Unauthorized("invalid signature".into()));
        }

        let mut put = Request {
            method: "PUT".into(),
            path: put_path,
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: Body::from(file_data),
        };
        put.headers.set("X-Backend-Authorize-Override", "true");
        put.headers.set("X-Backend-Remote-User", ".wsgi.formpost");
        put.headers.set("X-Backend-Source", "FP");
        if let Some(v) = attributes.get("x_delete_at") {
            let _: i64 = v.parse().map_err(|_| {
                FormError::Invalid("x_delete_at not an integer: Unix timestamp required.".into())
            })?;
            put.headers.set("X-Delete-At", v);
        }
        if let Some(v) = attributes.get("x_delete_after") {
            let _: i64 = v.parse().map_err(|_| {
                FormError::Invalid(
                    "x_delete_after not an integer: Number of seconds required.".into(),
                )
            })?;
            put.headers.set("X-Delete-After", v);
        }
        if let Some(ct) = attributes.get("content-type") {
            put.headers.set(
                "Content-Type",
                if ct.is_empty() {
                    "application/octet-stream"
                } else {
                    ct
                },
            );
        }
        if let Some(ce) = attributes.get("content-encoding") {
            put.headers.set("Content-Encoding", ce);
        }
        Ok(put)
    }

    fn perform_subrequest<F>(
        &self,
        orig_path: &str,
        attributes: &std::collections::HashMap<String, String>,
        mime: &mut MimeDocs,
        keys: &[String],
        next: F,
    ) -> Result<(u16, HeaderKeyDict, Vec<u8>), FormError>
    where
        F: FnOnce(Request) -> Response,
    {
        let put = self.build_put_request(orig_path, attributes, mime, keys)?;
        Ok(put_result(next(put)))
    }

    async fn translate_form_async(
        &self,
        mut req: Request,
        boundary: &str,
        next: AsyncNextFn,
    ) -> Response {
        let path = req.path.clone();
        let parts = match split_path(&path, 3, 4, true) {
            Ok(p) => p,
            Err(_) => return unauthorized("invalid signature"),
        };
        let account = parts[1].clone().unwrap_or_default();
        let container = parts[2].clone().unwrap_or_default();
        if account.is_empty() || container.is_empty() {
            return unauthorized("invalid signature");
        }
        let keys = self.key_provider.keys_for(&account, &container);
        if keys.is_empty() {
            return unauthorized("invalid signature");
        }

        let (reader, _) = req.body.take().into_reader();
        let mut mime = MimeDocs::new(reader, boundary.as_bytes());

        let mut attributes: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        let mut status: u16 = 0;
        let mut message = String::new();
        let mut subheaders = HeaderKeyDict::new();
        let mut resp_body: Option<Vec<u8>> = None;
        let mut file_count: u64 = 0;

        loop {
            let headers = match mime.next_document() {
                Ok(Some(h)) => h,
                Ok(None) => break,
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::InvalidData
                        && e.to_string().contains("invalid starting boundary")
                    {
                        return bad_request("invalid starting boundary");
                    }
                    return bad_request(&e.to_string());
                }
            };
            let disposition = headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("Content-Disposition"))
                .map(|(_, v)| v.as_str())
                .unwrap_or("");
            let (disp, attrs) = parse_content_disposition(disposition);
            if disp == "form-data" && attrs.contains_key("filename") {
                file_count += 1;
                let max_count: u64 = match attributes
                    .get("max_file_count")
                    .map(|s| s.as_str())
                    .unwrap_or("0")
                    .parse()
                {
                    Ok(n) => n,
                    Err(_) => return bad_request("max_file_count not an integer"),
                };
                if file_count > max_count {
                    status = 400;
                    message = "max file count exceeded".into();
                    break;
                }
                let mut file_attributes = attributes.clone();
                let filename = attrs
                    .get("filename")
                    .cloned()
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "filename".into());
                file_attributes.insert("filename".into(), filename);
                if !file_attributes.contains_key("content-type") {
                    if let Some((_, ct)) = headers
                        .iter()
                        .find(|(k, _)| k.eq_ignore_ascii_case("Content-Type"))
                    {
                        file_attributes.insert(
                            "content-type".into(),
                            if ct.is_empty() {
                                "application/octet-stream".into()
                            } else {
                                ct.clone()
                            },
                        );
                    }
                }
                if !file_attributes.contains_key("content-encoding") {
                    if let Some((_, ce)) = headers
                        .iter()
                        .find(|(k, _)| k.eq_ignore_ascii_case("Content-Encoding"))
                    {
                        file_attributes.insert("content-encoding".into(), ce.clone());
                    }
                }
                match self.build_put_request(&path, &file_attributes, &mut mime, &keys) {
                    Ok(put) => {
                        let (st, hdrs, body) = put_result(next(put).await);
                        status = st;
                        subheaders = hdrs;
                        resp_body = Some(body);
                        if !is_success(st) {
                            break;
                        }
                    }
                    Err(FormError::Unauthorized(m)) => return unauthorized(&m),
                    Err(FormError::Invalid(m)) => return bad_request(&m),
                    Err(FormError::Eof(m)) => return bad_request(&m),
                }
            } else {
                let mut data = Vec::new();
                let mut remaining = MAX_VALUE_LENGTH;
                let mut buf = [0u8; READ_CHUNK_SIZE];
                while remaining > 0 {
                    let n = match mime.read(&mut buf[..remaining.min(READ_CHUNK_SIZE)]) {
                        Ok(0) => break,
                        Ok(n) => n,
                        Err(e) => return bad_request(&e.to_string()),
                    };
                    data.extend_from_slice(&buf[..n]);
                    remaining = remaining.saturating_sub(n);
                }
                let mut sink = [0u8; READ_CHUNK_SIZE];
                while mime.read(&mut sink).unwrap_or(0) > 0 {}
                let mut text = String::from_utf8_lossy(&data).into_owned();
                while text.ends_with('\r') || text.ends_with('\n') || text.ends_with('-') {
                    text.pop();
                }
                if let Some(name) = attrs.get("name") {
                    attributes.insert(name.to_ascii_lowercase(), text);
                }
            }
        }

        finish_formpost(status, message, subheaders, resp_body, &attributes)
    }
}

fn put_result(mut resp: Response) -> (u16, HeaderKeyDict, Vec<u8>) {
    let body = resp.body.take().into_vec(64 * 1024).unwrap_or_default();
    (resp.status, resp.headers, body)
}

fn finish_formpost(
    mut status: u16,
    mut message: String,
    subheaders: HeaderKeyDict,
    resp_body: Option<Vec<u8>>,
    attributes: &std::collections::HashMap<String, String>,
) -> Response {
    if status == 0 {
        status = 400;
        message = "no files to process".into();
    }

    let mut headers = HeaderKeyDict::new();
    for (k, v) in subheaders.iter() {
        if k.to_ascii_lowercase().starts_with("access-control") {
            headers.set(k, v);
        }
    }

    let redirect = attributes.get("redirect").cloned().unwrap_or_default();
    if redirect.is_empty() {
        let mut body = format!("{status} {}", reason(status));
        if !message.is_empty() {
            body = format!(
                "{status} {}\r\nFormPost: {}",
                reason(status),
                title_case_words(&message)
            );
        }
        let mut body_bytes = body.into_bytes();
        if !is_success(status) {
            if let Some(rb) = resp_body {
                if !rb.is_empty() {
                    body_bytes = rb;
                }
            }
        }
        let mut resp = Response::with_body(status, body_bytes);
        for (k, v) in headers.iter() {
            resp.headers.set(k, v);
        }
        resp.headers.set("Content-Type", "text/plain");
        return resp;
    }

    let sep = if redirect.contains('?') { '&' } else { '?' };
    let location = format!(
        "{redirect}{sep}status={}&message={}",
        quote_query(&status.to_string()),
        quote_query(&message)
    );
    let html =
        format!("<html><body><p><a href=\"{location}\">Click to continue...</a></p></body></html>");
    let mut resp = Response::with_body(303, html.into_bytes());
    for (k, v) in headers.iter() {
        resp.headers.set(k, v);
    }
    resp.headers.set("Location", location);
    resp
}

fn formpost_boundary(req: &Request) -> Option<String> {
    if req.method != "POST" {
        return None;
    }
    multipart_boundary(req.headers.get("Content-Type").unwrap_or(""))
}

enum FormError {
    Unauthorized(String),
    Invalid(String),
    Eof(String),
}

fn reason(status: u16) -> &'static str {
    swift_http::reason_phrase(status)
}

impl Middleware for FormPost {
    fn intercepts_request(&self, req: &Request) -> bool {
        formpost_boundary(req).is_some()
    }

    fn handle_request_async(
        &self,
        req: Request,
        next: AsyncNextFn,
    ) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        Box::pin(async move {
            match formpost_boundary(&req) {
                Some(boundary) => self.translate_form_async(req, &boundary, next).await,
                None => next(req).await,
            }
        })
    }

    fn handle(&self, req: Request, next: &NextFn) -> Response {
        match formpost_boundary(&req) {
            Some(boundary) => self.translate_form(req, &boundary, next),
            None => next(req),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ClosureKeyProvider;
    use std::sync::{Arc, Mutex};

    fn attrs() -> FormPostAttributes {
        FormPostAttributes {
            path: "/v1/AUTH_test/container".into(),
            redirect: "https://example.com/done".into(),
            max_file_size: 1048576,
            max_file_count: 10,
            expires: 2000000000,
        }
    }

    #[test]
    fn test_hmac_lengths_per_algo() {
        let key = b"mykey";
        assert_eq!(formpost_hmac("sha1", key, &attrs()).unwrap().len(), 40);
        assert_eq!(formpost_hmac("sha256", key, &attrs()).unwrap().len(), 64);
        assert_eq!(formpost_hmac("sha512", key, &attrs()).unwrap().len(), 128);
        assert!(formpost_hmac("md5", key, &attrs()).is_none());
    }

    #[test]
    fn test_verify_valid_and_invalid() {
        let key: &[u8] = b"mykey";
        let sig = formpost_hmac("sha256", key, &attrs()).unwrap();
        let allowed: Vec<String> = DEFAULT_ALLOWED_DIGESTS
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(
            verify_signature(&[key], &attrs(), &sig, 0, &allowed),
            FormPostVerify::Valid
        );
        assert_eq!(
            verify_signature(&[b"other"], &attrs(), &sig, 0, &allowed),
            FormPostVerify::BadSignature
        );
        assert_eq!(
            verify_signature(&[key], &attrs(), &sig, 3000000000, &allowed),
            FormPostVerify::Expired
        );
        let sig1 = formpost_hmac("sha1", key, &attrs()).unwrap();
        assert_eq!(
            verify_signature(&[key], &attrs(), &sig1, 0, &allowed),
            FormPostVerify::Valid
        );
        let only256 = vec!["sha256".to_string()];
        assert_eq!(
            verify_signature(&[key], &attrs(), &sig1, 0, &only256),
            FormPostVerify::Invalid
        );
    }

    #[test]
    fn test_parse_content_disposition() {
        let (main, attrs) =
            parse_content_disposition(r#"form-data; name="file1"; filename="test.html""#);
        assert_eq!(main, "form-data");
        assert_eq!(attrs.get("name").map(String::as_str), Some("file1"));
        assert_eq!(attrs.get("filename").map(String::as_str), Some("test.html"));
        let (ct, a) =
            parse_content_disposition("multipart/form-data; boundary=----WebKitFormBoundary");
        assert_eq!(ct, "multipart/form-data");
        assert_eq!(
            a.get("boundary").map(String::as_str),
            Some("----WebKitFormBoundary")
        );
    }

    fn multipart_body(fields: &[(&str, &str)], files: &[(&str, &str, &[u8])]) -> Vec<u8> {
        let boundary = "BOUND";
        let mut out = Vec::new();
        for (name, value) in fields {
            out.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
            out.extend_from_slice(
                format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes(),
            );
            out.extend_from_slice(value.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        for (name, filename, data) in files {
            out.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
            out.extend_from_slice(
                format!(
                    "Content-Disposition: form-data; name=\"{name}\"; filename=\"{filename}\"\r\n"
                )
                .as_bytes(),
            );
            out.extend_from_slice(b"Content-Type: text/plain\r\n\r\n");
            out.extend_from_slice(data);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
        out
    }

    #[test]
    fn test_formpost_upload_success_and_negatives() {
        let key = "form-key";
        let path = "/v1/AUTH_test/c/prefix_";
        let redirect = "";
        let max_file_size = "1024";
        let max_file_count = "2";
        let expires = "2000000000";
        let attrs = FormPostAttributes {
            path: path.into(),
            redirect: redirect.into(),
            max_file_size: 1024,
            max_file_count: 2,
            expires: 2000000000,
        };
        let sig = formpost_hmac("sha256", key.as_bytes(), &attrs).unwrap();

        let log = Arc::new(Mutex::new(Vec::new()));
        let log2 = log.clone();
        let app: NextFn = Arc::new(move |r: Request| {
            log2.lock()
                .unwrap()
                .push((r.method.clone(), r.path.clone()));
            Response::new(201)
        });
        let provider = Arc::new(ClosureKeyProvider::new(|_, _| vec![key.to_string()]));
        let fp = FormPost::new(provider);

        let body = multipart_body(
            &[
                ("redirect", redirect),
                ("max_file_size", max_file_size),
                ("max_file_count", max_file_count),
                ("expires", expires),
                ("signature", &sig),
            ],
            &[("file1", "hello.txt", b"hi")],
        );
        let mut req = Request {
            method: "POST".into(),
            path: path.into(),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: Body::from(body),
        };
        req.headers
            .set("Content-Type", "multipart/form-data; boundary=BOUND");
        let resp = fp.handle(req, &app);
        assert_eq!(resp.status, 201, "got {}", resp.status);
        let calls = log.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0],
            ("PUT".into(), "/v1/AUTH_test/c/prefix_hello.txt".into())
        );

        // Tampered signature → 401
        let body = multipart_body(
            &[
                ("redirect", ""),
                ("max_file_size", "1024"),
                ("max_file_count", "1"),
                ("expires", expires),
                ("signature", "deadbeef"),
            ],
            &[("file1", "x.txt", b"x")],
        );
        let mut req = Request {
            method: "POST".into(),
            path: path.into(),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: Body::from(body),
        };
        req.headers
            .set("Content-Type", "multipart/form-data; boundary=BOUND");
        assert_eq!(fp.handle(req, &app).status, 401);

        // Expired → 401
        let attrs_exp = FormPostAttributes {
            path: path.into(),
            redirect: String::new(),
            max_file_size: 1024,
            max_file_count: 1,
            expires: 1,
        };
        let sig_exp = formpost_hmac("sha256", key.as_bytes(), &attrs_exp).unwrap();
        let body = multipart_body(
            &[
                ("redirect", ""),
                ("max_file_size", "1024"),
                ("max_file_count", "1"),
                ("expires", "1"),
                ("signature", &sig_exp),
            ],
            &[("file1", "x.txt", b"x")],
        );
        let mut req = Request {
            method: "POST".into(),
            path: path.into(),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: Body::from(body),
        };
        req.headers
            .set("Content-Type", "multipart/form-data; boundary=BOUND");
        assert_eq!(fp.handle(req, &app).status, 401);
    }

    #[tokio::test]
    async fn test_formpost_hyper_handle_request_async_uploads() {
        let key = "form-key";
        let path = "/v1/AUTH_test/c/prefix_";
        let attrs = FormPostAttributes {
            path: path.into(),
            redirect: String::new(),
            max_file_size: 1024,
            max_file_count: 2,
            expires: 2000000000,
        };
        let sig = formpost_hmac("sha256", key.as_bytes(), &attrs).unwrap();
        let log = Arc::new(Mutex::new(Vec::new()));
        let log2 = log.clone();
        let app: AsyncNextFn = Arc::new(move |r: Request| {
            let log2 = log2.clone();
            Box::pin(async move {
                log2.lock()
                    .unwrap()
                    .push((r.method.clone(), r.path.clone()));
                Response::new(201)
            })
        });
        let provider = Arc::new(ClosureKeyProvider::new(|_, _| vec![key.to_string()]));
        let fp = FormPost::new(provider);
        let body = multipart_body(
            &[
                ("redirect", ""),
                ("max_file_size", "1024"),
                ("max_file_count", "2"),
                ("expires", "2000000000"),
                ("signature", &sig),
            ],
            &[("file1", "hello.txt", b"hi")],
        );
        let mut req = Request {
            method: "POST".into(),
            path: path.into(),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: Body::from(body),
        };
        req.headers
            .set("Content-Type", "multipart/form-data; boundary=BOUND");
        assert!(fp.intercepts_request(&req));
        let resp = fp.handle_request_async(req, app).await;
        assert_eq!(resp.status, 201, "got {}", resp.status);
        let calls = log.lock().unwrap();
        assert_eq!(
            calls[0],
            ("PUT".into(), "/v1/AUTH_test/c/prefix_hello.txt".into())
        );
    }

    #[test]
    fn test_non_multipart_passthrough() {
        let provider = Arc::new(ClosureKeyProvider::new(|_, _| vec![]));
        let fp = FormPost::new(provider);
        let app: NextFn = Arc::new(|_r| Response::new(204));
        let req = Request {
            method: "POST".into(),
            path: "/v1/a/c".into(),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: Body::empty(),
        };
        assert_eq!(fp.handle(req, &app).status, 204);
    }
}
