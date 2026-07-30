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

//! Request/Response containers and path/query helpers
//! (`swift.common.utils.split_path`, WSGI unquoting).

use crate::body::Body;
use crate::headers::HeaderKeyDict;

/// A parsed HTTP request as seen by a Swift backend server.
///
/// The body is either buffered or a stream consumed at most once, so
/// `Request` is deliberately NOT `Clone`; subrequest patterns use
/// [`Request::clone_head`] and move the body explicitly.
#[derive(Debug)]
pub struct Request {
    pub method: String,
    /// Percent-decoded path.
    pub path: String,
    /// Raw (still-encoded) query string.
    pub query_string: String,
    pub headers: HeaderKeyDict,
    pub body: Body,
}

impl Request {
    pub fn params(&self) -> Vec<(String, String)> {
        parse_query(&self.query_string)
    }

    pub fn param(&self, name: &str) -> Option<String> {
        self.params()
            .into_iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v)
    }

    /// Clone everything but the body (which becomes empty). The
    /// subrequest idiom: `let mut sub = req.clone_head();` plus
    /// `sub.body = req.body.take();` when the body must travel.
    pub fn clone_head(&self) -> Request {
        Request {
            method: self.method.clone(),
            path: self.path.clone(),
            query_string: self.query_string.clone(),
            headers: self.headers.clone(),
            body: Body::empty(),
        }
    }
}

/// A response to serialize back to the client. Like [`Request`], not
/// `Clone` (its body may be a stream).
#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub reason: String,
    pub headers: HeaderKeyDict,
    pub body: Body,
}

impl Response {
    pub fn new(status: u16) -> Response {
        Response {
            status,
            reason: reason_phrase(status).to_string(),
            headers: HeaderKeyDict::new(),
            body: Body::empty(),
        }
    }

    pub fn with_body(status: u16, body: impl Into<Body>) -> Response {
        let mut resp = Response::new(status);
        resp.body = body.into();
        resp
    }

    /// Standard error body shape swob produces for simple errors.
    pub fn error(status: u16, message: &str) -> Response {
        let mut resp = Response::with_body(
            status,
            format!(
                "<html><h1>{}</h1><p>{}</p></html>",
                reason_phrase(status),
                message
            ),
        );
        resp.headers.set("Content-Type", "text/html; charset=UTF-8");
        resp
    }
}

pub fn reason_phrase(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        206 => "Partial Content",
        301 => "Moved Permanently",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        409 => "Conflict",
        411 => "Length Required",
        412 => "Precondition Failed",
        413 => "Request Entity Too Large",
        416 => "Requested Range Not Satisfiable",
        417 => "Expectation Failed",
        422 => "Unprocessable Entity",
        499 => "Client Disconnect",
        500 => "Internal Error",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        507 => "Insufficient Storage",
        _ => "Unknown",
    }
}

/// Percent-decode a path or query component (no `+` handling).
///
/// The Swift server pipeline is `wsgi_unquote` (latin-1) then `wsgi_to_str`
/// (`bytes.decode('utf8', errors='surrogateescape')`), and that proper-`str`
/// form is what both `hash_path` and the DB listings use. For valid UTF-8
/// (ASCII and every ordinary Unicode name — the overwhelming common case)
/// that is exactly a UTF-8 decode of the percent-decoded bytes, so decoding to
/// bytes and UTF-8-decoding here matches Python end-to-end (object placement
/// hash AND stored name).
///
/// Limitation: a percent-escape sequence that is not valid UTF-8 (a raw
/// non-UTF-8 byte in an object name) is Python-decoded with `surrogateescape`
/// to a lone surrogate (`0xFF` -> `U+DCFF`) that re-encodes to the original
/// byte. A Rust `String` cannot hold surrogates, so such bytes are replaced
/// (`U+FFFD`); fully matching Python here would require carrying names as
/// bytes through the whole stack rather than as `String`.
pub fn unquote(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (
                (bytes[i + 1] as char).to_digit(16),
                (bytes[i + 2] as char).to_digit(16),
            ) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    // utf-8 decode of the percent-decoded bytes == Python wsgi_to_str for
    // valid UTF-8 (the common case), which is the form hash_path/DB use.
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse a query string: percent-decoding plus `+` as space, preserving
/// parameter order.
pub fn parse_query(query: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for piece in query.split('&') {
        if piece.is_empty() {
            continue;
        }
        let (k, v) = piece.split_once('=').unwrap_or((piece, ""));
        let decode = |s: &str| unquote(&s.replace('+', " "));
        out.push((decode(k), decode(v)));
    }
    out
}

/// Port of `swift.common.utils.split_path`.
pub fn split_path(
    path: &str,
    minsegs: usize,
    maxsegs: usize,
    rest_with_last: bool,
) -> Result<Vec<Option<String>>, String> {
    let err = || format!("Invalid path: {path}");
    let maxsegs = if maxsegs == 0 { minsegs } else { maxsegs };
    if minsegs > maxsegs {
        return Err(format!("minsegs > maxsegs: {minsegs} > {maxsegs}"));
    }
    // mirror the Python exactly: in the rest_with_last branch the split
    // happens BEFORE min/max are incremented, otherwise after
    let (segs, minsegs, maxsegs): (Vec<&str>, usize, usize) = if rest_with_last {
        let segs = path.splitn(maxsegs + 1, '/').collect();
        (segs, minsegs + 1, maxsegs + 1)
    } else {
        let (minsegs, maxsegs) = (minsegs + 1, maxsegs + 1);
        (path.splitn(maxsegs + 1, '/').collect(), minsegs, maxsegs)
    };
    let count = segs.len();
    if rest_with_last {
        if !segs[0].is_empty()
            || count < minsegs
            || count > maxsegs
            || segs[1..minsegs.min(count)].iter().any(|s| s.is_empty())
        {
            return Err(err());
        }
    } else if !segs[0].is_empty()
        || count < minsegs
        || count > maxsegs + 1
        || segs[1..minsegs.min(count)].iter().any(|s| s.is_empty())
        || (count == maxsegs + 1 && !segs[maxsegs].is_empty())
    {
        return Err(err());
    }
    let mut out: Vec<Option<String>> = segs[1..maxsegs.min(count)]
        .iter()
        .map(|s| Some(s.to_string()))
        .collect();
    if out
        .iter()
        .take(out.len().saturating_sub(1))
        .any(|s| s.as_deref().is_none_or(str::is_empty))
    {
        return Err(err());
    }
    while out.len() < maxsegs - 1 {
        out.push(None);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sp(path: &str, min: usize, max: usize, rest: bool) -> Result<Vec<Option<String>>, String> {
        split_path(path, min, max, rest)
    }

    #[test]
    fn test_split_path() {
        assert_eq!(sp("/a", 1, 1, false).unwrap(), vec![Some("a".into())]);
        assert_eq!(
            sp("/a", 1, 2, false).unwrap(),
            vec![Some("a".into()), None]
        );
        assert_eq!(
            sp("/a/c", 1, 2, false).unwrap(),
            vec![Some("a".into()), Some("c".into())]
        );
        assert_eq!(
            sp("/a/c/o/r", 1, 3, true).unwrap(),
            vec![Some("a".into()), Some("c".into()), Some("o/r".into())]
        );
        // a trailing empty segment is legal when maxsegs allows it
        assert_eq!(
            sp("/a/", 1, 2, false).unwrap(),
            vec![Some("a".into()), Some("".into())]
        );
        assert!(sp("a/c", 1, 2, false).is_err()); // no leading slash
        assert!(sp("//c", 1, 2, false).is_err()); // empty account
        assert!(sp("/a/c/o", 1, 2, false).is_err()); // too many segs
        assert_eq!(
            sp("/a/c/", 1, 3, true).unwrap(),
            vec![Some("a".into()), Some("c".into()), Some("".into())]
        );
    }

    #[test]
    fn test_unquote_and_query() {
        // valid UTF-8 percent-escapes decode to the proper string (matching
        // Python's wsgi_to_str, the form hash_path and DB listings use)
        assert_eq!(unquote("/v1/AUTH_test/%E4%B8%AD%2F"), "/v1/AUTH_test/中/");
        assert_eq!(
            parse_query("prefix=a%2Fb&delimiter=%2F&plus=a+b"),
            vec![
                ("prefix".into(), "a/b".into()),
                ("delimiter".into(), "/".into()),
                ("plus".into(), "a b".into()),
            ]
        );
    }
}
