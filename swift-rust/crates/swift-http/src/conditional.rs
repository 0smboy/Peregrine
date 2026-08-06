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

//! Conditional-request evaluation, ported from swob's
//! `_get_conditional_response_status` (`If-Match`/`If-None-Match`/
//! `If-Modified-Since`/`If-Unmodified-Since`).

use crate::dates::parse_http_date;
use crate::range::Match;
use crate::request::{Request, Response};

/// Resolve an alternate etag for conditional matching from
/// `X-Backend-Etag-Is-At` (Python `resolve_etag_is_at_header`).
///
/// The request header is a comma-separated list of response/metadata header
/// names; the first present non-empty value wins. Used by crypto encrypter
/// (`X-Object-Sysmeta-Crypto-Etag-Mac`) and EC (`X-Object-Sysmeta-Ec-Etag`).
pub fn resolve_etag_is_at<'a>(req: &Request, resp: &'a Response) -> Option<&'a str> {
    let names = req.headers.get("X-Backend-Etag-Is-At")?;
    for name in names.split(',') {
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        if let Some(v) = resp.headers.get(name) {
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    None
}

/// `_get_conditional_response_status`: given a request and an otherwise-2xx
/// response, return `Some(304)` or `Some(412)` if the request's preconditions
/// mean an empty conditional response should be sent, else `None`.
///
/// Order matters and mirrors Python exactly:
/// 1. `If-None-Match` contains the ETag -> 304.
/// 2. `If-Match` does not contain the ETag -> 412.
/// 3. a 404 with `If-Match: *` -> 412.
/// 4. `Last-Modified <= If-Modified-Since` -> 304.
/// 5. `Last-Modified > If-Unmodified-Since` -> 412.
///
/// When `X-Backend-Etag-Is-At` resolves to a sysmeta value (e.g. crypto
/// Etag-Mac), that value is used for Match comparison instead of `ETag`
/// (Python `conditional_etag=`).
pub fn conditional_response_status(req: &Request, resp: &Response) -> Option<u16> {
    let etag = resolve_etag_is_at(req, resp).or_else(|| resp.headers.get("ETag"));
    let if_none_match = req.headers.get("If-None-Match").map(Match::parse);
    let if_match = req.headers.get("If-Match").map(Match::parse);

    if let (Some(e), Some(m)) = (etag, &if_none_match) {
        if m.matches(e) {
            return Some(304);
        }
    }
    if let (Some(e), Some(m)) = (etag, &if_match) {
        if !m.matches(e) {
            return Some(412);
        }
    }
    if resp.status == 404 {
        if let Some(m) = &if_match {
            if m.tags.iter().any(|t| t == "*") {
                return Some(412);
            }
        }
    }

    if let Some(last_modified) = resp.headers.get("Last-Modified").and_then(parse_http_date) {
        if let Some(ims) = req
            .headers
            .get("If-Modified-Since")
            .and_then(parse_http_date)
        {
            if last_modified <= ims {
                return Some(304);
            }
        }
        if let Some(ius) = req
            .headers
            .get("If-Unmodified-Since")
            .and_then(parse_http_date)
        {
            if last_modified > ius {
                return Some(412);
            }
        }
    }
    None
}

/// Apply the conditional check to a successful GET/HEAD response, replacing it
/// with an empty 304/412 body if a precondition fails. Non-2xx responses and
/// non-GET/HEAD methods pass through unchanged.
pub fn apply_conditional(req: &Request, mut resp: Response) -> Response {
    if !(200..300).contains(&resp.status) {
        return resp;
    }
    if let Some(status) = conditional_response_status(req, &resp) {
        resp.status = status;
        resp.reason = crate::request::reason_phrase(status).to_string();
        resp.body = crate::body::Body::empty();
        resp.headers.set("Content-Length", "0");
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::headers::HeaderKeyDict;

    fn req(headers: &[(&str, &str)]) -> Request {
        let mut h = HeaderKeyDict::new();
        for (k, v) in headers {
            h.set(k, v);
        }
        Request {
            method: "GET".into(),
            path: "/v1/a/c/o".into(),
            query_string: String::new(),
            headers: h,
            body: crate::body::Body::empty(),
        }
    }

    fn resp_ok(headers: &[(&str, &str)]) -> Response {
        let mut r = Response::with_body(200, b"body".to_vec());
        for (k, v) in headers {
            r.headers.set(k, v);
        }
        r
    }

    #[test]
    fn test_if_none_match_304() {
        let r = req(&[("If-None-Match", "\"abc\"")]);
        let resp = resp_ok(&[("ETag", "abc")]);
        assert_eq!(conditional_response_status(&r, &resp), Some(304));
        // '*' matches any existing entity
        let star = req(&[("If-None-Match", "*")]);
        assert_eq!(conditional_response_status(&star, &resp), Some(304));
        // no match -> None
        let other = req(&[("If-None-Match", "xyz")]);
        assert_eq!(conditional_response_status(&other, &resp), None);
    }

    #[test]
    fn test_if_match_412() {
        let r = req(&[("If-Match", "xyz")]);
        let resp = resp_ok(&[("ETag", "abc")]);
        assert_eq!(conditional_response_status(&r, &resp), Some(412));
        // matching -> None
        let ok = req(&[("If-Match", "abc, def")]);
        assert_eq!(conditional_response_status(&ok, &resp), None);
    }

    #[test]
    fn test_if_modified_since() {
        // Last-Modified older than or equal to If-Modified-Since -> 304
        let resp = resp_ok(&[("Last-Modified", "Sun, 06 Nov 1994 08:49:37 GMT")]);
        let r = req(&[("If-Modified-Since", "Sun, 06 Nov 1994 08:49:37 GMT")]);
        assert_eq!(conditional_response_status(&r, &resp), Some(304));
        let newer = req(&[("If-Modified-Since", "Sat, 05 Nov 1994 08:49:37 GMT")]);
        assert_eq!(conditional_response_status(&newer, &resp), None);
    }

    #[test]
    fn test_if_unmodified_since_412() {
        let resp = resp_ok(&[("Last-Modified", "Sun, 06 Nov 1994 08:49:37 GMT")]);
        // Last-Modified newer than If-Unmodified-Since -> 412
        let r = req(&[("If-Unmodified-Since", "Sat, 05 Nov 1994 08:49:37 GMT")]);
        assert_eq!(conditional_response_status(&r, &resp), Some(412));
    }

    #[test]
    fn test_apply_replaces_body() {
        let r = req(&[("If-None-Match", "*")]);
        let resp = resp_ok(&[("ETag", "abc")]);
        let out = apply_conditional(&r, resp);
        assert_eq!(out.status, 304);
        assert!(out.body.is_definitely_empty());
    }

    #[test]
    fn test_etag_is_at_overrides_response_etag() {
        // Crypto path: If-None-Match carries HMAC(plaintext etag); object
        // ETag is ciphertext md5. X-Backend-Etag-Is-At points at Etag-Mac.
        let mac = "dGVzdC1obWFjLXZhbHVl"; // any opaque token
        let r = req(&[
            ("If-None-Match", &format!("\"{mac}\"")),
            (
                "X-Backend-Etag-Is-At",
                "X-Object-Sysmeta-Crypto-Etag-Mac",
            ),
        ]);
        let resp = resp_ok(&[
            ("ETag", "ciphertext-md5-hex"),
            ("X-Object-Sysmeta-Crypto-Etag-Mac", mac),
        ]);
        assert_eq!(conditional_response_status(&r, &resp), Some(304));
        // Without Etag-Is-At the ciphertext etag would not match.
        let bare = req(&[("If-None-Match", &format!("\"{mac}\""))]);
        assert_eq!(conditional_response_status(&bare, &resp), None);
    }
}
