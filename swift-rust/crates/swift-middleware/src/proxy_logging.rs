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

//! `proxy_logging`: builds the Swift proxy access-log line from a
//! request/response pair, porting `swift/common/middleware/proxy_logging.py`
//! (specifically `ProxyLoggingMiddleware.log_request` and the helpers it
//! calls: `get_remote_client`, `get_policy_index`, `cap_length`,
//! `LogStringFormatter`, `StrFormatTime`).
//!
//! The documented, space-separated, per-field-url-encoded format is
//! reproduced exactly:
//!
//! ```text
//! client_ip remote_addr end_time.datetime method path protocol
//! status_int referer user_agent auth_token bytes_recvd bytes_sent
//! client_etag transaction_id headers request_time source log_info
//! start_time end_time policy_index
//! ```
//!
//! The formatted line is exposed via [`ProxyLogging::get_log_line`]. When a
//! [`LogSink`] is installed (proxy wiring passes the process `Logger`),
//! [`Middleware::handle`] emits one access-log line after the inner app
//! returns. Without a sink the filter stays a pure pass-through.
//!
//! Deferred (need external plumbing that does not exist here, and none of
//! which changes the default log line):
//!   * StatsD metrics (`*.timing`, `*.xfer`, ttfb, labeled counters);
//!   * `StrAnonymizer.anonymized` (md5/salt hashing) — only reached when a
//!     custom `log_msg_template` uses the `.anonymized` format spec; the
//!     documented default format never does, so values pass through as the
//!     quoted raw string;
//!   * a configurable `log_msg_template` — the documented field order is
//!     hardcoded here (so `access_user_id`, `pid`, `ttfb`, `domain`, `wire_
//!     status_int`, etc. are not emitted);
//!   * `swift.orig_req_method` (COPY rewriting), `swift.backend_path`
//!     (only used for statsd resource labels, not the log line), s3api
//!     bucket/key labels, and sensitive *query-param* obscuring
//!     (`get_sensitive_params`, which round-trips through swob's
//!     params<->query_string). Sensitive *header* obscuring for the two
//!     headers proxy_logging itself registers (`x-auth-token`,
//!     `x-storage-token`) IS implemented.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use swift_http::{Request, Response};

use crate::{Middleware, NextFn};

/// Destination for a formatted proxy access-log line.
pub type LogSink = Arc<dyn Fn(&str) + Send + Sync>;

/// Missing/zero values render as a single hyphen (`LogStringFormatter`'s
/// `default='-'`).
const DEFAULT: &str = "-";

/// Headers proxy_logging registers as sensitive in its `filter_factory`
/// (`register_sensitive_header`). Their values are capped in both the
/// `auth_token` field and the `headers` dump, matching `obscure_req`.
const SENSITIVE_HEADERS: [&str; 2] = ["x-auth-token", "x-storage-token"];

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// The per-request values that live in the WSGI environ rather than on the
/// `Request`/`Response`, plus the timing/byte counters the server tallies.
/// These are the arguments `ProxyLoggingMiddleware.log_request` receives
/// out of band.
#[derive(Debug, Clone)]
pub struct LogContext {
    /// `REMOTE_ADDR` — the socket peer.
    pub remote_addr: String,
    /// `SERVER_PROTOCOL`, e.g. `"HTTP/1.0"`.
    pub protocol: String,
    /// `swift.trans_id`.
    pub trans_id: Option<String>,
    /// `swift.source` (set by middlewares that make subrequests).
    pub source: Option<String>,
    /// `swift.log_info` — joined with `,` for the `log_info` field.
    pub log_info: Vec<String>,
    /// Epoch seconds when the request started.
    pub start_time: f64,
    /// Epoch seconds when the request completed.
    pub end_time: f64,
    /// Bytes successfully read from the request body.
    pub bytes_recvd: u64,
    /// Bytes yielded to the WSGI server.
    pub bytes_sent: u64,
    /// The status to log (`swift.proxy_logging_status`, forced to 499 on a
    /// client disconnect or 500 on an unhandled exception).
    pub status_int: u16,
}

impl Default for LogContext {
    fn default() -> Self {
        LogContext {
            remote_addr: String::new(),
            protocol: String::new(),
            trans_id: None,
            source: None,
            log_info: Vec::new(),
            start_time: 0.0,
            end_time: 0.0,
            bytes_recvd: 0,
            bytes_sent: 0,
            status_int: 0,
        }
    }
}

/// The proxy access-logging middleware.
pub struct ProxyLogging {
    /// `reveal_sensitive_prefix`: how many leading characters of a
    /// sensitive header value survive before it is truncated with `...`.
    pub reveal_sensitive_prefix: usize,
    /// `access_log_headers` / `log_headers`: dump the request headers into
    /// the `headers` field.
    pub log_hdrs: bool,
    /// `access_log_headers_only`: if non-empty, only these (title-cased)
    /// header names are dumped. Ignored unless `log_hdrs` is set.
    pub log_hdrs_only: Vec<String>,
    /// Optional sink; when set, [`Middleware::handle`] emits the line.
    sink: Option<LogSink>,
}

impl Default for ProxyLogging {
    fn default() -> Self {
        ProxyLogging {
            reveal_sensitive_prefix: 16,
            log_hdrs: false,
            log_hdrs_only: Vec::new(),
            sink: None,
        }
    }
}

impl ProxyLogging {
    /// Attach a logger sink so the filter emits access lines at runtime.
    pub fn with_sink(mut self, sink: LogSink) -> Self {
        self.sink = Some(sink);
        self
    }

    /// Build from `[filter:proxy-logging]` / `[filter:proxy_logging]` items.
    pub fn from_conf(options: &std::collections::HashMap<String, String>) -> Self {
        let mut pl = ProxyLogging::default();
        if let Some(v) = options.get("reveal_sensitive_prefix") {
            if let Ok(n) = v.trim().parse::<usize>() {
                pl.reveal_sensitive_prefix = n;
            }
        }
        let log_hdrs = options
            .get("access_log_headers")
            .or_else(|| options.get("log_headers"))
            .map(|v| {
                matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "true" | "1" | "yes" | "on"
                )
            })
            .unwrap_or(false);
        pl.log_hdrs = log_hdrs;
        if let Some(only) = options.get("access_log_headers_only") {
            pl.log_hdrs_only = only
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| {
                    // Title-Case like Python's header dump keys.
                    s.split('-')
                        .map(|p| {
                            let mut c = p.chars();
                            match c.next() {
                                None => String::new(),
                                Some(f) => {
                                    f.to_uppercase().collect::<String>()
                                        + &c.as_str().to_lowercase()
                                }
                            }
                        })
                        .collect::<Vec<_>>()
                        .join("-")
                })
                .collect();
        }
        pl
    }

    /// `LogStringFormatter.format_field` for a single field: falsy (empty)
    /// values become `-`, everything else is url-quoted with `:/{}` kept
    /// safe (`quote(log, ':/{}')`).
    fn field(&self, value: &str) -> String {
        if value.is_empty() {
            DEFAULT.to_string()
        } else {
            url_quote(value, ":/{}")
        }
    }

    /// An integer field: Python's `not value` treats `0` as falsy, so zero
    /// counts and statuses render as `-`.
    fn field_num(&self, n: u64) -> String {
        if n == 0 {
            DEFAULT.to_string()
        } else {
            self.field(&n.to_string())
        }
    }

    /// `obscure_sensitive`: `cap_length(value, reveal_sensitive_prefix)`.
    fn obscure(&self, value: &str) -> String {
        cap_length(value, self.reveal_sensitive_prefix)
    }

    /// The `headers` field: `None` (rendered `-`) unless header logging is
    /// enabled, else the `\n`-joined `Name: value` dump, optionally
    /// filtered to `log_hdrs_only` and with sensitive values capped
    /// (mirroring the post-`obscure_req` state of `req.headers`).
    fn logged_headers(&self, req: &Request) -> String {
        if !self.log_hdrs {
            return String::new();
        }
        let mut lines: Vec<String> = Vec::new();
        for (k, v) in req.headers.iter() {
            if !self.log_hdrs_only.is_empty() && !self.log_hdrs_only.iter().any(|h| h == k) {
                continue;
            }
            let shown = if SENSITIVE_HEADERS.iter().any(|s| k.eq_ignore_ascii_case(s)) {
                self.obscure(v)
            } else {
                v.to_string()
            };
            lines.push(format!("{k}: {shown}"));
        }
        lines.join("\n")
    }

    /// Build the access-log line for `req`/`resp` and the out-of-band
    /// `ctx`. Port of `ProxyLoggingMiddleware.log_request` restricted to
    /// the documented default `log_msg_template`.
    pub fn get_log_line(&self, req: &Request, resp: &Response, ctx: &LogContext) -> String {
        // client_ip / auth_token reflect obscure_req: the auth token is
        // capped because x-auth-token is a registered sensitive header.
        let client_ip = get_remote_client(req, &ctx.remote_addr);
        let auth_token = match req.headers.get("x-auth-token") {
            Some(v) => self.obscure(v),
            None => String::new(),
        };

        // path == req.path_qs: swob re-quotes the decoded path (safe='/'),
        // appends the raw query string, and the formatter quotes it AGAIN
        // (safe=':/{}'), so `%` and `?`/`&`/`=` get percent-encoded.
        let mut path_qs = url_quote(&req.path, "/");
        if !req.query_string.is_empty() {
            path_qs.push('?');
            path_qs.push_str(&req.query_string);
        }

        let request_time = format!("{:.4}", ctx.end_time - ctx.start_time);
        let start_time = format!("{:.9}", ctx.start_time);
        let end_time = format!("{:.9}", ctx.end_time);
        let log_info = ctx.log_info.join(",");
        let policy_index = get_policy_index(req, resp).unwrap_or_default();

        let fields = [
            self.field(&client_ip),
            self.field(&ctx.remote_addr),
            self.field(&str_format_datetime(ctx.end_time)),
            self.field(&req.method),
            self.field(&path_qs),
            self.field(&ctx.protocol),
            self.field_num(ctx.status_int as u64),
            self.field(req.headers.get("referer").unwrap_or("")),
            self.field(req.headers.get("user-agent").unwrap_or("")),
            self.field(&auth_token),
            self.field_num(ctx.bytes_recvd),
            self.field_num(ctx.bytes_sent),
            self.field(req.headers.get("etag").unwrap_or("")),
            self.field(ctx.trans_id.as_deref().unwrap_or("")),
            self.field(&self.logged_headers(req)),
            self.field(&request_time),
            self.field(ctx.source.as_deref().unwrap_or("")),
            self.field(&log_info),
            self.field(&start_time),
            self.field(&end_time),
            self.field(&policy_index),
        ];
        fields.join(" ")
    }
}

impl Middleware for ProxyLogging {
    fn handle(&self, req: Request, next: &NextFn) -> Response {
        // Never mutates request/response; only observes them for the line.
        let start_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);
        let bytes_recvd = req.body.content_length().unwrap_or(0) as u64;
        let remote_addr = req
            .headers
            .get("x-real-ip")
            .or_else(|| req.headers.get("remote-addr"))
            .unwrap_or("")
            .to_string();
        let head = req.clone_head();
        let resp = next(req);
        if let Some(sink) = &self.sink {
            let end_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs_f64())
                .unwrap_or(start_time);
            let bytes_sent = resp.body.content_length().unwrap_or(0) as u64;
            let ctx = LogContext {
                remote_addr,
                protocol: "HTTP/1.0".to_string(),
                trans_id: resp
                    .headers
                    .get("x-trans-id")
                    .or_else(|| head.headers.get("x-trans-id"))
                    .map(|s| s.to_string()),
                source: None,
                log_info: Vec::new(),
                start_time,
                end_time,
                bytes_recvd,
                bytes_sent,
                status_int: resp.status,
            };
            sink(&self.get_log_line(&head, &resp, &ctx));
        }
        resp
    }
}

/// `swift.common.utils.get_remote_client`: prefer `X-Cluster-Client-Ip`,
/// then the first element of `X-Forwarded-For`, then `REMOTE_ADDR`.
fn get_remote_client(req: &Request, remote_addr: &str) -> String {
    let mut client = req
        .headers
        .get("x-cluster-client-ip")
        .unwrap_or("")
        .to_string();
    if client.is_empty() {
        if let Some(xff) = req.headers.get("x-forwarded-for") {
            client = xff.split(',').next().unwrap_or("").trim().to_string();
        }
    }
    if client.is_empty() {
        client = remote_addr.to_string();
    }
    client
}

/// `swift.common.utils.logs.get_policy_index`: response header wins over
/// request header; the value is returned verbatim (note that a policy
/// index of `"0"` is a non-empty string and therefore is NOT hyphenated).
fn get_policy_index(req: &Request, resp: &Response) -> Option<String> {
    let header = "X-Backend-Storage-Policy-Index";
    resp.headers
        .get(header)
        .or_else(|| req.headers.get(header))
        .map(|s| s.to_string())
}

/// `swift.common.utils.cap_length`: truncate to `max_length` code points,
/// appending `...`, only when the value is longer than `max_length`.
fn cap_length(value: &str, max_length: usize) -> String {
    if value.chars().count() > max_length {
        let prefix: String = value.chars().take(max_length).collect();
        format!("{prefix}...")
    } else {
        value.to_string()
    }
}

/// `urllib.parse.quote` over the UTF-8 bytes (swift's `quote`): keep the
/// always-safe unreserved set plus `safe`, percent-encode the rest as
/// uppercase `%XX`.
fn url_quote(s: &str, safe: &str) -> String {
    let safe = safe.as_bytes();
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-' | b'~') || safe.contains(&b)
        {
            out.push(b as char);
        } else {
            out.push('%');
            out.push_str(&format!("{b:02X}"));
        }
    }
    out
}

/// `StrFormatTime(ts).datetime`: `time.strftime('%d/%b/%Y/%H/%M/%S',
/// gmtime(ts))`. gmtime truncates the fractional seconds.
fn str_format_datetime(ts: f64) -> String {
    let epoch_secs = ts.floor() as i64;
    let days = epoch_secs.div_euclid(86400);
    let sod = epoch_secs.rem_euclid(86400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{:02}/{}/{}/{:02}/{:02}/{:02}",
        day,
        MONTHS[(month - 1) as usize],
        year,
        sod / 3600,
        (sod % 3600) / 60,
        sod % 60,
    )
}

/// Days-from-civil (Howard Hinnant's algorithm), mirroring
/// `swift-http`'s private `dates::civil_from_days`.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use swift_http::{title_case, HeaderKeyDict};

    fn make_req(method: &str, path: &str, qs: &str, headers: &[(&str, &str)]) -> Request {
        let mut h = HeaderKeyDict::new();
        for (k, v) in headers {
            h.set(k, *v);
        }
        Request {
            method: method.into(),
            path: path.into(),
            query_string: qs.into(),
            headers: h,
            body: swift_http::Body::empty(),
        }
    }

    fn make_resp(status: u16, headers: &[(&str, &str)]) -> Response {
        let mut r = Response::new(status);
        for (k, v) in headers {
            r.headers.set(k, *v);
        }
        r
    }

    /// A context pinned to 2025-07-02T23:46:41Z so the datetime/time fields
    /// are deterministic (matches swift-http's dates.rs golden test).
    fn base_ctx() -> LogContext {
        LogContext {
            remote_addr: "10.0.0.1".into(),
            protocol: "HTTP/1.0".into(),
            trans_id: Some("tx123abc".into()),
            source: None,
            log_info: Vec::new(),
            start_time: 1751500000.0,
            end_time: 1751500001.0,
            bytes_recvd: 1024,
            bytes_sent: 0,
            status_int: 201,
        }
    }

    #[test]
    fn test_full_happy_path() {
        let pl = ProxyLogging::default();
        let req = make_req(
            "PUT",
            "/v1/a/c/o",
            "",
            &[
                ("User-Agent", "python-swiftclient"),
                ("Etag", "d41d8cd98f00b204e9800998ecf8427e"),
            ],
        );
        let resp = make_resp(201, &[("X-Backend-Storage-Policy-Index", "0")]);
        let line = pl.get_log_line(&req, &resp, &base_ctx());
        assert_eq!(
            line,
            "10.0.0.1 10.0.0.1 02/Jul/2025/23/46/41 PUT /v1/a/c/o HTTP/1.0 201 \
             - python-swiftclient - 1024 - d41d8cd98f00b204e9800998ecf8427e \
             tx123abc - 1.0000 - - 1751500000.000000000 1751500001.000000000 0"
        );
    }

    #[test]
    fn test_missing_values_become_hyphen() {
        // no referer/user-agent/auth-token/etag, zero bytes, no trans_id,
        // no source, no log_info, no policy header -> all '-'.
        let pl = ProxyLogging::default();
        let req = make_req("GET", "/v1/a", "", &[]);
        let resp = make_resp(200, &[]);
        let ctx = LogContext {
            trans_id: None,
            bytes_recvd: 0,
            bytes_sent: 0,
            status_int: 200,
            ..base_ctx()
        };
        let line = pl.get_log_line(&req, &resp, &ctx);
        assert_fields(
            &line,
            &[
                (6, "200"), // status_int is non-zero
                (7, "-"),   // referer
                (8, "-"),   // user_agent
                (9, "-"),   // auth_token
                (10, "-"),  // bytes_recvd (0)
                (11, "-"),  // bytes_sent (0)
                (12, "-"),  // client_etag
                (13, "-"),  // transaction_id
                (14, "-"),  // headers (logging off)
                (16, "-"),  // source
                (17, "-"),  // log_info
                (20, "-"),  // policy_index
            ],
        );
    }

    fn assert_fields(line: &str, expect: &[(usize, &str)]) {
        let fields: Vec<&str> = line.split(' ').collect();
        assert_eq!(
            fields.len(),
            21,
            "expected 21 fields, got {}: {line}",
            fields.len()
        );
        for (idx, want) in expect {
            assert_eq!(fields[*idx], *want, "field {idx} of: {line}");
        }
    }

    #[test]
    fn test_client_ip_precedence() {
        let pl = ProxyLogging::default();
        let resp = make_resp(200, &[]);
        let ctx = base_ctx();

        // x-cluster-client-ip wins even when x-forwarded-for is present.
        let req = make_req(
            "GET",
            "/v1/a",
            "",
            &[
                ("X-Cluster-Client-Ip", "198.51.100.7"),
                ("X-Forwarded-For", "203.0.113.5, 10.0.0.9"),
            ],
        );
        assert_fields(&pl.get_log_line(&req, &resp, &ctx), &[(0, "198.51.100.7")]);

        // else the first (stripped) element of x-forwarded-for.
        let req = make_req(
            "GET",
            "/v1/a",
            "",
            &[("X-Forwarded-For", "203.0.113.5, 10.0.0.9")],
        );
        assert_fields(&pl.get_log_line(&req, &resp, &ctx), &[(0, "203.0.113.5")]);

        // else REMOTE_ADDR (from the context).
        let req = make_req("GET", "/v1/a", "", &[]);
        assert_fields(&pl.get_log_line(&req, &resp, &ctx), &[(0, "10.0.0.1")]);
    }

    #[test]
    fn test_path_is_double_quoted_with_query() {
        let pl = ProxyLogging::default();
        // decoded path has a space; raw query is already percent-encoded.
        let req = make_req("GET", "/v1/AUTH_test/obj name", "prefix=a%20b&limit=1", &[]);
        let resp = make_resp(200, &[]);
        // path -> quote('/') -> "/v1/AUTH_test/obj%20name?prefix=a%20b&limit=1"
        // -> quote(':/{}') -> '%' => %25, '?' => %3F, '=' => %3D, '&' => %26
        assert_fields(
            &pl.get_log_line(&req, &resp, &base_ctx()),
            &[(
                4,
                "/v1/AUTH_test/obj%2520name%3Fprefix%3Da%2520b%26limit%3D1",
            )],
        );
    }

    #[test]
    fn test_policy_index_response_wins_and_zero_survives() {
        let pl = ProxyLogging::default();
        let ctx = base_ctx();

        // response header wins over the request header
        let req = make_req(
            "GET",
            "/v1/a/c/o",
            "",
            &[("X-Backend-Storage-Policy-Index", "1")],
        );
        let resp = make_resp(200, &[("X-Backend-Storage-Policy-Index", "2")]);
        assert_fields(&pl.get_log_line(&req, &resp, &ctx), &[(20, "2")]);

        // request header used when the response lacks it
        let resp = make_resp(200, &[]);
        assert_fields(&pl.get_log_line(&req, &resp, &ctx), &[(20, "1")]);

        // "0" is a valid non-empty index and must NOT be hyphenated
        let req = make_req("GET", "/v1/a/c/o", "", &[]);
        let resp = make_resp(200, &[("X-Backend-Storage-Policy-Index", "0")]);
        assert_fields(&pl.get_log_line(&req, &resp, &ctx), &[(20, "0")]);

        // neither present -> '-'
        let resp = make_resp(200, &[]);
        assert_fields(&pl.get_log_line(&req, &resp, &ctx), &[(20, "-")]);
    }

    #[test]
    fn test_auth_token_is_capped() {
        let pl = ProxyLogging::default(); // reveal_sensitive_prefix = 16
                                          // 23 chars -> first 16 + "..."
        let token = "AUTH_tk0123456789abcdef";
        let req = make_req("GET", "/v1/a", "", &[("X-Auth-Token", token)]);
        let resp = make_resp(200, &[]);
        assert_fields(
            &pl.get_log_line(&req, &resp, &base_ctx()),
            &[(9, "AUTH_tk012345678...")],
        );

        // <= 16 chars is left intact
        let req = make_req("GET", "/v1/a", "", &[("X-Auth-Token", "shorttoken")]);
        assert_fields(
            &pl.get_log_line(&req, &resp, &base_ctx()),
            &[(9, "shorttoken")],
        );
    }

    #[test]
    fn test_headers_dump_all_with_sensitive_capping() {
        let pl = ProxyLogging {
            log_hdrs: true,
            ..Default::default()
        };
        let req = make_req(
            "GET",
            "/v1/a",
            "",
            &[
                ("X-Auth-Token", "AUTH_tk0123456789abcdef"),
                ("User-Agent", "swift"),
                ("Content-Length", "42"),
            ],
        );
        let resp = make_resp(200, &[]);
        // "X-Auth-Token: AUTH_tk012345678...\nUser-Agent: swift\n
        //  Content-Length: 42" quoted with ':/{}' -> ' ' %20, '\n' %0A
        assert_fields(
            &pl.get_log_line(&req, &resp, &base_ctx()),
            &[(
                14,
                "X-Auth-Token:%20AUTH_tk012345678...%0AUser-Agent:%20swift%0AContent-Length:%2042",
            )],
        );
    }

    #[test]
    fn test_headers_dump_only_filter() {
        let pl = ProxyLogging {
            log_hdrs: true,
            log_hdrs_only: vec![title_case("user-agent")], // "User-Agent"
            ..Default::default()
        };
        let req = make_req(
            "GET",
            "/v1/a",
            "",
            &[("User-Agent", "swift"), ("Content-Length", "42")],
        );
        let resp = make_resp(200, &[]);
        assert_fields(
            &pl.get_log_line(&req, &resp, &base_ctx()),
            &[(14, "User-Agent:%20swift")],
        );
    }

    #[test]
    fn test_log_info_and_source_and_referer_encoding() {
        let pl = ProxyLogging::default();
        let req = make_req(
            "GET",
            "/v1/a",
            "",
            &[("Referer", "http://example.com/x?y=1")],
        );
        let resp = make_resp(200, &[]);
        let ctx = LogContext {
            source: Some("RL".into()),
            log_info: vec!["x-delete-at:1751500000".into(), "staticweb".into()],
            ..base_ctx()
        };
        let line = pl.get_log_line(&req, &resp, &ctx);
        assert_fields(
            &line,
            &[
                // referer: ':' '/' safe, '?' %3F, '=' %3D
                (7, "http://example.com/x%3Fy%3D1"),
                (16, "RL"),
                // log_info joined by ',' then quoted: ',' %2C, ':' safe
                (17, "x-delete-at:1751500000%2Cstaticweb"),
            ],
        );
    }

    #[test]
    fn test_time_fields_formatting() {
        let pl = ProxyLogging::default();
        let req = make_req("GET", "/v1/a", "", &[]);
        let resp = make_resp(200, &[]);
        let ctx = LogContext {
            start_time: 0.0,
            end_time: 0.0,
            ..base_ctx()
        };
        assert_fields(
            &pl.get_log_line(&req, &resp, &ctx),
            &[
                (2, "01/Jan/1970/00/00/00"), // end_time.datetime
                (15, "0.0000"),              // request_time
                (18, "0.000000000"),         // start_time
                (19, "0.000000000"),         // end_time
            ],
        );
    }

    #[test]
    fn test_middleware_passthrough_is_unchanged() {
        use std::sync::Arc;
        let pl = ProxyLogging::default();
        let req = make_req("GET", "/v1/a/c/o", "", &[("X-Object-Meta-Foo", "bar")]);
        let app: Arc<dyn Fn(Request) -> Response + Send + Sync> = Arc::new(|r: Request| {
            // reflect the request back so we can prove it reached the app
            // untouched
            let mut resp = Response::new(204);
            resp.headers.set("Echo-Method", &r.method);
            resp.headers.set(
                "Echo-Meta",
                r.headers.get("x-object-meta-foo").unwrap_or(""),
            );
            resp
        });
        let resp = pl.handle(req, &app);
        assert_eq!(resp.status, 204);
        assert_eq!(resp.headers.get("Echo-Method"), Some("GET"));
        assert_eq!(resp.headers.get("Echo-Meta"), Some("bar"));
    }

    #[test]
    fn test_sink_emits_access_line() {
        use std::sync::{Arc, Mutex};
        let lines: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let sink_lines = Arc::clone(&lines);
        let pl = ProxyLogging::default().with_sink(Arc::new(move |line: &str| {
            sink_lines.lock().unwrap().push(line.to_string());
        }));
        let req = make_req("GET", "/v1/a/c/o", "", &[]);
        let app: Arc<dyn Fn(Request) -> Response + Send + Sync> =
            Arc::new(|_r: Request| Response::new(200));
        let resp = pl.handle(req, &app);
        assert_eq!(resp.status, 200);
        let got = lines.lock().unwrap();
        assert_eq!(got.len(), 1);
        assert!(got[0].contains("GET"), "{}", got[0]);
        assert!(got[0].contains("/v1/a/c/o"), "{}", got[0]);
        assert!(got[0].contains("200"), "{}", got[0]);
    }
}
