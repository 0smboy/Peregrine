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

//! `name_check` (`swift/common/middleware/name_check.py`): rejects any
//! request whose path contains a forbidden character, exceeds the maximum
//! length, or matches the forbidden regular expression, answering `400 Bad
//! Request` with the same plain-text bodies the Python emits. The three
//! checks run in the Python order — character, then length, then regexp —
//! and the first that trips wins.
//!
//! Like swob's `path_info`, the checks operate on the percent-decoded path
//! (`Request::path`), not the re-encoded `req.path` used only for the
//! Python debug logging.
//!
//! Deferred:
//! - `register_swift_info` (`/info` capability advertising) — out of scope
//!   for the pipeline port, as with the other middlewares.
//! - `get_logger` debug output — no logging sink here.
//! - Arbitrary user-supplied `forbidden_regexp` patterns: the workspace has
//!   no regex engine, so only the built-in `FORBIDDEN_REGEXP` is evaluated
//!   natively (see [`default_forbidden_regexp_matches`]). `None` disables
//!   the regexp check, mirroring a falsy `forbidden_regexp` in Python; any
//!   other custom pattern is treated as not-matching and should be flagged
//!   before it is relied upon.

use swift_http::{Request, Response};

use crate::{Middleware, MwPrep, NextFn};

/// Default forbidden characters (`FORBIDDEN_CHARS`): single-quote,
/// double-quote, backtick, `<`, `>`.
pub const FORBIDDEN_CHARS: &str = "'\"`<>";
/// Default maximum path length (`MAX_LENGTH`).
pub const MAX_LENGTH: usize = 255;
/// Default forbidden regular expression (`FORBIDDEN_REGEXP`): `/./`, `/../`,
/// or a path ending in `/.` or `/..`.
pub const FORBIDDEN_REGEXP: &str = r"/\./|/\.\./|/\.$|/\.\.$";

pub struct NameCheck {
    /// Characters that may not appear anywhere in the path.
    pub forbidden_chars: Vec<char>,
    /// Inclusive maximum number of characters (Unicode scalar values, as
    /// with Python's `len`) allowed in the path.
    pub maximum_length: usize,
    /// The forbidden-substring regexp pattern. `None` disables the check;
    /// `Some(FORBIDDEN_REGEXP)` is evaluated natively (see the module note
    /// on deferred custom patterns).
    pub forbidden_regexp: Option<String>,
}

impl Default for NameCheck {
    fn default() -> Self {
        NameCheck {
            forbidden_chars: FORBIDDEN_CHARS.chars().collect(),
            maximum_length: MAX_LENGTH,
            forbidden_regexp: Some(FORBIDDEN_REGEXP.to_string()),
        }
    }
}

impl NameCheck {
    /// True if the path contains any forbidden character
    /// (Python `check_character`).
    fn check_character(&self, path: &str) -> bool {
        self.forbidden_chars.iter().any(|c| path.contains(*c))
    }

    /// True if the path is longer than the maximum length
    /// (Python `check_length`). Length is counted in Unicode scalar values
    /// to match Python's `len(str)`, not bytes.
    fn check_length(&self, path: &str) -> bool {
        path.chars().count() > self.maximum_length
    }

    /// True if the path matches the forbidden regexp (Python
    /// `check_regexp`). Only the built-in [`FORBIDDEN_REGEXP`] is supported
    /// natively; `None` disables the check and any other pattern is treated
    /// as not-matching (see the module-level deferral note).
    fn check_regexp(&self, path: &str) -> bool {
        match self.forbidden_regexp.as_deref() {
            None => false,
            Some(pat) if pat == FORBIDDEN_REGEXP => default_forbidden_regexp_matches(path),
            Some(_) => false,
        }
    }

    /// Render the forbidden characters back to a string for the error body,
    /// matching Python's `%s` formatting of `self.forbidden_chars`.
    fn forbidden_chars_display(&self) -> String {
        self.forbidden_chars.iter().collect()
    }

    /// First matching check in Python order (character, length, regexp).
    /// IsolatedIdentity Hyper never calls `handle()`; `prepare` must 400.
    fn reject(&self, path: &str) -> Option<Response> {
        if self.check_character(path) {
            return Some(bad_request(format!(
                "Object/Container/Account name contains forbidden chars from {}",
                self.forbidden_chars_display()
            )));
        }
        if self.check_length(path) {
            return Some(bad_request(format!(
                "Object/Container/Account name longer than the allowed maximum {}",
                self.maximum_length
            )));
        }
        if self.check_regexp(path) {
            return Some(bad_request(format!(
                "Object/Container/Account name contains a forbidden substring \
                 from regular expression {}",
                self.forbidden_regexp.as_deref().unwrap_or("")
            )));
        }
        None
    }
}

impl Middleware for NameCheck {
    fn prepare(&self, req: &mut Request) -> MwPrep {
        match self.reject(&req.path) {
            Some(resp) => MwPrep::ShortCircuit(resp),
            None => MwPrep::Continue,
        }
    }

    fn handle(&self, mut req: Request, next: &NextFn) -> Response {
        match self.prepare(&mut req) {
            MwPrep::ShortCircuit(resp) => resp,
            MwPrep::Continue => next(req),
        }
    }
}

/// Build the `400 Bad Request` the Python `HTTPBadRequest(request=req,
/// body=...)` produces: the message is the verbatim response body (swob
/// does not wrap an explicit `body=` in its HTML template).
fn bad_request(message: String) -> Response {
    let mut resp = Response::with_body(400, message);
    resp.headers.set("Content-Type", "text/html; charset=UTF-8");
    resp
}

/// Native evaluation of the built-in [`FORBIDDEN_REGEXP`],
/// `r"/\./|/\.\./|/\.$|/\.\.$"`: the alternation matches when `path`
/// contains `/./` or `/../`, or ends with `/.` or `/..`. For a boolean
/// `re.search`, the OR of the four alternatives is equivalent to the
/// pattern.
fn default_forbidden_regexp_matches(path: &str) -> bool {
    path.contains("/./")
        || path.contains("/../")
        || ends_at_line_end(path, "/.")
        || ends_at_line_end(path, "/..")
}

/// Reproduce Python's `re` `$` in the default (non-MULTILINE) mode: it
/// anchors at the end of the string, or immediately before a single
/// trailing `\n`. So `suffix$` matches when `path` ends with `suffix`, or
/// ends with `suffix` followed by exactly one `\n`.
fn ends_at_line_end(path: &str, suffix: &str) -> bool {
    path.ends_with(suffix) || path.strip_suffix('\n').is_some_and(|p| p.ends_with(suffix))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use swift_http::HeaderKeyDict;

    fn req(path: &str) -> Request {
        Request {
            method: "PUT".into(),
            path: path.into(),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: swift_http::Body::empty(),
        }
    }

    /// Run `nc` over `path` with a downstream app that answers `200 OK`,
    /// standing in for the Python `FakeApp`. The returned body is
    /// materialized so assertions can read it in place.
    fn run(nc: &NameCheck, path: &str) -> Response {
        let app: crate::NextFn = Arc::new(|_r| Response::with_body(200, b"OK".to_vec()));
        let mut resp = nc.handle(req(path), &app);
        resp.body.materialize(u64::MAX).unwrap();
        resp
    }

    /// Test bodies are always buffered once `run` has materialized them.
    fn body_bytes(resp: &Response) -> &[u8] {
        match &resp.body {
            swift_http::Body::Buffered(b) => b,
            swift_http::Body::Streamed(_) | swift_http::Body::Channel(_) => unreachable!(),
        }
    }

    // test_valid_length_and_character
    #[test]
    fn test_valid_length_and_character() {
        let nc = NameCheck::default();
        // '/V1.0/' + 'c' * (MAX_LENGTH - 6) == exactly MAX_LENGTH chars
        let path = format!("/V1.0/{}", "c".repeat(MAX_LENGTH - 6));
        assert_eq!(path.chars().count(), MAX_LENGTH);
        let resp = run(&nc, &path);
        assert_eq!(resp.status, 200);
        assert_eq!(body_bytes(&resp), b"OK");
    }

    // test_invalid_character
    #[test]
    fn test_invalid_character() {
        let nc = NameCheck::default();
        let expected = format!(
            "Object/Container/Account name contains forbidden chars from {}",
            FORBIDDEN_CHARS
        );
        for c in FORBIDDEN_CHARS.chars() {
            let path = format!("/V1.0/1234{c}5");
            let resp = run(&nc, &path);
            assert_eq!(resp.status, 400, "char {c:?} should be rejected");
            assert_eq!(body_bytes(&resp), expected.as_bytes());
        }
    }

    // test_invalid_length
    #[test]
    fn test_invalid_length() {
        let nc = NameCheck::default();
        // '/V1.0/' + 'c' * (MAX_LENGTH - 5) == MAX_LENGTH + 1 chars
        let path = format!("/V1.0/{}", "c".repeat(MAX_LENGTH - 5));
        assert_eq!(path.chars().count(), MAX_LENGTH + 1);
        let resp = run(&nc, &path);
        assert_eq!(resp.status, 400);
        assert_eq!(
            body_bytes(&resp),
            format!(
                "Object/Container/Account name longer than the allowed maximum {}",
                MAX_LENGTH
            )
            .as_bytes()
        );
    }

    // test_maximum_length_from_config
    #[test]
    fn test_maximum_length_from_config() {
        let nc = NameCheck {
            maximum_length: 500,
            ..Default::default()
        };
        // invalid: 501 chars
        let path = format!("/V1.0/a/c/{}", "o".repeat(500 - 9));
        assert_eq!(path.chars().count(), 501);
        let resp = run(&nc, &path);
        assert_eq!(resp.status, 400);
        assert_eq!(
            body_bytes(&resp),
            b"Object/Container/Account name longer than the allowed maximum 500"
        );

        // valid: exactly 500 chars (not strictly greater)
        let path = format!("/V1.0/a/c/{}", "o".repeat(500 - 10));
        assert_eq!(path.chars().count(), 500);
        let resp = run(&nc, &path);
        assert_eq!(resp.status, 200);
        assert_eq!(body_bytes(&resp), b"OK");
    }

    // test_invalid_regexp
    #[test]
    fn test_invalid_regexp() {
        let nc = NameCheck::default();
        let expected = format!(
            "Object/Container/Account name contains a forbidden substring \
             from regular expression {}",
            FORBIDDEN_REGEXP
        );
        for s in ["/.", "/..", "/./foo", "/../foo"] {
            let path = format!("/V1.0/{s}");
            let resp = run(&nc, &path);
            assert_eq!(resp.status, 400, "path {path:?} should be rejected");
            assert_eq!(body_bytes(&resp), expected.as_bytes(), "path {path:?}");
        }
    }

    // test_valid_regexp
    #[test]
    fn test_valid_regexp() {
        let nc = NameCheck::default();
        // note: '/.\.' is a literal backslash between the dots
        for s in ["/...", "/.\\.", "/foo"] {
            let path = format!("/V1.0/{s}");
            let resp = run(&nc, &path);
            assert_eq!(resp.status, 200, "path {path:?} should be allowed");
            assert_eq!(body_bytes(&resp), b"OK", "path {path:?}");
        }
    }

    // The character check runs before the length and regexp checks, so a
    // path that trips several rules returns the character message.
    #[test]
    fn test_check_order_character_wins() {
        let nc = NameCheck::default();
        // contains a forbidden '"' AND ends with '/.'
        let resp = run(&nc, "/a/\"/.");
        assert_eq!(resp.status, 400);
        assert_eq!(
            body_bytes(&resp),
            format!(
                "Object/Container/Account name contains forbidden chars from {}",
                FORBIDDEN_CHARS
            )
            .as_bytes()
        );
    }

    // A falsy forbidden_regexp (None) disables the regexp check, matching
    // Python's `forbidden_regexp_compiled is None` branch.
    #[test]
    fn test_regexp_disabled() {
        let nc = NameCheck {
            forbidden_regexp: None,
            ..Default::default()
        };
        // would match the default regexp, but the check is off
        let resp = run(&nc, "/V1.0//./foo");
        assert_eq!(resp.status, 200);
        assert_eq!(body_bytes(&resp), b"OK");
    }

    // Length is counted in Unicode scalar values (Python `len`), not bytes:
    // multi-byte characters each count once.
    #[test]
    fn test_length_counts_characters_not_bytes() {
        let nc = NameCheck::default();
        // 255 two-byte chars -> 255 chars (510 bytes): allowed
        let path: String = "é".repeat(MAX_LENGTH);
        assert_eq!(path.chars().count(), MAX_LENGTH);
        assert!(path.len() > MAX_LENGTH); // byte length far exceeds the limit
        assert_eq!(run(&nc, &path).status, 200);

        // 256 chars: rejected
        let path: String = "é".repeat(MAX_LENGTH + 1);
        assert_eq!(run(&nc, &path).status, 400);
    }

    // IsolatedIdentity Hyper only calls prepare(); it must 400 the same
    // forbidden-char body as handle().
    #[test]
    fn test_prepare_rejects_forbidden_character() {
        let nc = NameCheck::default();
        let mut request = req("/V1.0/1234\"5");
        match nc.prepare(&mut request) {
            MwPrep::ShortCircuit(mut resp) => {
                resp.body.materialize(u64::MAX).unwrap();
                assert_eq!(resp.status, 400);
                assert_eq!(
                    body_bytes(&resp),
                    format!(
                        "Object/Container/Account name contains forbidden chars from {}",
                        FORBIDDEN_CHARS
                    )
                    .as_bytes()
                );
            }
            MwPrep::Continue => panic!("prepare must short-circuit forbidden chars"),
        }
        let mut ok = req("/V1.0/ok");
        assert!(matches!(nc.prepare(&mut ok), MwPrep::Continue));
    }

    // Fidelity to Python's `$`: it also anchors just before a single
    // trailing newline, so a path ending '/.\n' still matches.
    #[test]
    fn test_regexp_dollar_before_trailing_newline() {
        let nc = NameCheck::default();
        assert_eq!(run(&nc, "/a/.\n").status, 400);
        assert_eq!(run(&nc, "/a/..\n").status, 400);
        // two trailing newlines: the anchor only skips one, so no match
        assert_eq!(run(&nc, "/a/.\n\n").status, 200);
    }
}
