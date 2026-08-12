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

//! `backend_ratelimit`: the storage-node backend rate limiter, a port of
//! `swift/common/middleware/backend_ratelimit.py`.
//!
//! Rate-limits requests to backend storage-node *devices*. Each
//! `(device, method)` combination is limited independently, and every
//! rate-limited request is *also* checked against an aggregate per-device
//! limit that spans all methods. Only `GET`, `HEAD`, `PUT`, `POST`,
//! `DELETE`, `UPDATE` and `REPLICATE` are rate limited. A request is
//! allowed only when neither the per-device aggregate limiter nor the
//! per-`(device, method)` limiter has been exhausted; if either rejects
//! it, a `529 Too Many Backend Requests` response is returned (matching
//! swob's `HTTPTooManyBackendRequests`).
//!
//! The limiter itself is a faithful port of
//! `swift.common.utils.EventletRateLimiter`/`AbstractRateLimiter`: a
//! millisecond running-time window with a `rate_buffer` catch-up
//! allowance and `burst_after_idle` semantics. Limiters are created
//! on-demand per `(device, method)` and kept in an in-process map.
//!
//! Deferrals (everything that is *not* the rate-limiting decision):
//! * Periodic config-file reload — `_maybe_reload_config`,
//!   `_load_config_file`, `readconf` of `backend-ratelimit.conf`,
//!   `config_reload_interval`, `_refresh_ratelimiters`. There is no
//!   `readconf`/hot-reload facility in this workspace yet; rates are
//!   fixed at construction. The full decision logic is ported.
//! * Metrics and logging side effects —
//!   `self.logger.increment('backend.ratelimit')` and the info/debug/
//!   warning log lines. No logger sink is wired into this crate (the same
//!   deferral `lib.rs` notes for `proxy_logging`). The `529` is still
//!   returned.
//! * The limiter's blocking path (`block=True`/`wait`/`_sleep`) is unused
//!   by this middleware — it only ever calls `is_allowed()` non-blocking —
//!   so it is not ported.
//! * `filter_factory` (PasteDeploy wiring).
//! * Minor: Python `int(partition)` accepts exotic Unicode digit strings;
//!   this port validates ASCII digits (with underscores permitted only
//!   between digits, as in a Python int literal) plus an optional sign and
//!   surrounding whitespace — sufficient for a device-path partition.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use swift_http::{split_path, Request, Response};

use crate::{Middleware, NextFn};

/// Methods that are subject to backend rate limiting
/// (`RATE_LIMITED_METHODS`).
const RATE_LIMITED_METHODS: [&str; 7] = [
    "GET",
    "HEAD",
    "PUT",
    "POST",
    "DELETE",
    "UPDATE",
    "REPLICATE",
];

/// swob `HTTPTooManyBackendRequests`.
const TOO_MANY_BACKEND_REQUESTS: u16 = 529;

/// `AbstractRateLimiter.clock_accuracy`: 1000ms == 1s.
const CLOCK_ACCURACY: f64 = 1000.0;

const DEFAULT_REQUESTS_PER_DEVICE_RATE_BUFFER: f64 = 1.0;

/// Port of `swift.common.utils.EventletRateLimiter` /
/// `AbstractRateLimiter`, restricted to the non-blocking `is_allowed`
/// path this middleware uses (`incr_by == 1`, `block == False`).
#[derive(Debug)]
struct RateLimiter {
    max_rate: f64,
    /// `clock_accuracy / max_rate` (ms per increment), or 0 when unlimited.
    time_per_incr: f64,
    /// `rate_buffer * clock_accuracy` (ms).
    rate_buffer_ms: f64,
    burst_after_idle: bool,
    /// Running time in milliseconds of the next allowable request.
    running_time: f64,
}

impl RateLimiter {
    fn new(max_rate: f64, rate_buffer: f64, running_time: f64, burst_after_idle: bool) -> Self {
        let mut rl = RateLimiter {
            max_rate: 0.0,
            time_per_incr: 0.0,
            rate_buffer_ms: 0.0,
            burst_after_idle,
            running_time,
        };
        rl.set_max_rate(max_rate);
        rl.set_rate_buffer(rate_buffer);
        rl
    }

    fn set_max_rate(&mut self, max_rate: f64) {
        self.max_rate = max_rate;
        self.time_per_incr = if max_rate != 0.0 {
            CLOCK_ACCURACY / max_rate
        } else {
            0.0
        };
    }

    fn set_rate_buffer(&mut self, rate_buffer: f64) {
        self.rate_buffer_ms = rate_buffer * CLOCK_ACCURACY;
    }

    /// `is_allowed(incr_by=1, now=now, block=False)`. `now` is in seconds
    /// (as `time.time()` returns); the method converts to milliseconds
    /// internally, exactly like the Python.
    fn is_allowed(&mut self, now_secs: f64) -> bool {
        // max_rate <= 0 (or incr_by <= 0, always 1 here) => no limiting.
        if self.max_rate <= 0.0 {
            return true;
        }
        let now = now_secs * CLOCK_ACCURACY;
        let time_per_request = self.time_per_incr; // * incr_by(1)
        if now - self.running_time > self.rate_buffer_ms {
            self.running_time = now;
            if self.burst_after_idle {
                self.running_time -= self.rate_buffer_ms;
            }
        }
        if now >= self.running_time {
            self.running_time += time_per_request;
            true
        } else {
            false
        }
    }
}

/// Backend rate-limiting middleware
/// (`BackendRateLimitMiddleware`).
pub struct BackendRateLimit {
    /// Aggregate per-device limit spanning all methods, in requests per
    /// second (Python's `None` key in `requests_per_device_per_second`).
    /// 0 disables the aggregate limiter.
    pub requests_per_device_per_second: f64,
    /// Per-method per-device limits, keyed by method name; every method in
    /// `RATE_LIMITED_METHODS` is present, defaulting to 0 (disabled).
    method_requests_per_device_per_second: HashMap<String, f64>,
    /// `rate_buffer` (seconds) applied to every limiter.
    requests_per_device_rate_buffer: f64,
    /// Status returned when a request is rate limited; `529` by default,
    /// matching swob's `HTTPTooManyBackendRequests`.
    too_many_requests_status: u16,
    /// On-demand `(device, method)` -> limiter map. `method` is `None` for
    /// the aggregate per-device limiter.
    rate_limiters: Mutex<HashMap<(String, Option<String>), RateLimiter>>,
}

impl Default for BackendRateLimit {
    fn default() -> Self {
        BackendRateLimit::new()
    }
}

impl BackendRateLimit {
    /// A limiter with everything disabled (all rates 0), the default
    /// `rate_buffer` of 1.0s, and the `529` reject status.
    pub fn new() -> Self {
        let mut method_rates = HashMap::new();
        for method in RATE_LIMITED_METHODS {
            method_rates.insert(method.to_string(), 0.0);
        }
        BackendRateLimit {
            requests_per_device_per_second: 0.0,
            method_requests_per_device_per_second: method_rates,
            requests_per_device_rate_buffer: DEFAULT_REQUESTS_PER_DEVICE_RATE_BUFFER,
            too_many_requests_status: TOO_MANY_BACKEND_REQUESTS,
            rate_limiters: Mutex::new(HashMap::new()),
        }
    }

    /// Set the aggregate per-device rate (`requests_per_device_per_second`).
    pub fn with_device_rate(mut self, rate: f64) -> Self {
        self.requests_per_device_per_second = rate;
        self
    }

    /// Set the per-device rate for one method
    /// (`<method>_requests_per_device_per_second`). `method` is
    /// upper-cased to match `RATE_LIMITED_METHODS`.
    pub fn with_method_rate(mut self, method: &str, rate: f64) -> Self {
        self.method_requests_per_device_per_second
            .insert(method.to_ascii_uppercase(), rate);
        self
    }

    /// Set the `rate_buffer` (seconds) shared by every limiter.
    pub fn with_rate_buffer(mut self, buffer: f64) -> Self {
        self.requests_per_device_rate_buffer = buffer;
        self
    }

    /// Override the reject status (default `529`).
    pub fn with_status(mut self, status: u16) -> Self {
        self.too_many_requests_status = status;
        self
    }

    /// `is_any_rate_limit_configured`: true when the aggregate limit or any
    /// method limit is non-zero (`any(requests_per_device_per_second.values())`).
    fn is_any_rate_limit_configured(&self) -> bool {
        self.requests_per_device_per_second != 0.0
            || self
                .method_requests_per_device_per_second
                .values()
                .any(|&v| v != 0.0)
    }

    /// The configured aggregate/method rate for a limiter key. `None`
    /// method selects the aggregate per-device rate.
    fn max_rate_for(&self, method: &Option<String>) -> f64 {
        match method {
            None => self.requests_per_device_per_second,
            Some(m) => self
                .method_requests_per_device_per_second
                .get(m)
                .copied()
                .unwrap_or(0.0),
        }
    }

    /// `_is_allowed`: a request is allowed only when the aggregate
    /// per-device limiter *and* the per-`(device, method)` limiter both
    /// allow it. Mirrors the Python `and` short-circuit exactly — if the
    /// aggregate limiter rejects, the method limiter is not consulted and
    /// its running-time is left unchanged.
    fn is_allowed(&self, device: &str, method: &str, now_secs: f64) -> bool {
        let buffer = self.requests_per_device_rate_buffer;
        let mut limiters = self.rate_limiters.lock().unwrap();

        let agg_key = (device.to_string(), None);
        let agg_rate = self.max_rate_for(&agg_key.1);
        let agg_allowed = limiters
            .entry(agg_key)
            .or_insert_with(|| RateLimiter::new(agg_rate, buffer, now_secs, true))
            .is_allowed(now_secs);
        if !agg_allowed {
            return false;
        }

        let method_key = (device.to_string(), Some(method.to_string()));
        let method_rate = self.max_rate_for(&method_key.1);
        limiters
            .entry(method_key)
            .or_insert_with(|| RateLimiter::new(method_rate, buffer, now_secs, true))
            .is_allowed(now_secs)
    }

    /// The core decision, factored out for deterministic testing. Returns
    /// `Some(reject_response)` when the request must be rate limited, or
    /// `None` when it should pass through to the next handler. `now_secs`
    /// is the wall-clock time in seconds.
    fn evaluate(&self, req: &Request, now_secs: f64) -> Option<Response> {
        if !self.is_any_rate_limit_configured() {
            return None;
        }
        if !RATE_LIMITED_METHODS.contains(&req.method.as_str()) {
            return None;
        }
        // split_and_validate_path(req, 1, 3, True) + int(partition); any
        // failure (bad path, bad device/partition, non-int partition)
        // means the request has no device/partition to limit (e.g. a
        // healthcheck) and is passed through.
        let segs = match split_path(&req.path, 1, 3, true) {
            Ok(segs) => segs,
            Err(_) => return None,
        };
        let device = segs.first().and_then(|s| s.clone())?;
        let partition = segs.get(1).and_then(|s| s.clone())?;
        if !validate_device_partition(&device, &partition) {
            return None;
        }
        if !python_int_ok(&partition) {
            return None;
        }
        if self.is_allowed(&device, &req.method, now_secs) {
            None
        } else {
            Some(self.reject_response())
        }
    }

    /// Build the reject response. For the default `529` this reproduces
    /// swob's `HTTPTooManyBackendRequests` title and body verbatim.
    fn reject_response(&self) -> Response {
        let status = self.too_many_requests_status;
        let mut resp = if status == TOO_MANY_BACKEND_REQUESTS {
            let body = "<html><h1>Too Many Backend Requests</h1><p>The server is \
                        incapable of performing the requested operation due to too \
                        many requests. Slow down.</p></html>";
            let mut r = Response::with_body(status, body.as_bytes().to_vec());
            r.reason = "Too Many Backend Requests".to_string();
            r
        } else {
            Response::new(status)
        };
        resp.headers.set("Content-Type", "text/html; charset=UTF-8");
        resp
    }
}

impl Middleware for BackendRateLimit {
    fn handle(&self, req: Request, next: &NextFn) -> Response {
        // note: periodic config-file reload (`_maybe_reload_config`) is a
        // deferred concern; see the module header.
        match self.evaluate(&req, now_secs()) {
            Some(resp) => resp,
            None => next(req),
        }
    }
}

/// Wall-clock time in seconds, as `time.time()` returns.
fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Port of `swift.common.utils.validate_device_partition`, returning
/// `false` where the Python raises `ValueError`.
fn validate_device_partition(device: &str, partition: &str) -> bool {
    let bad = |s: &str| s.is_empty() || s.contains('/') || s == "." || s == "..";
    !bad(device) && !bad(partition)
}

/// True when `int(partition)` would succeed in Python: optional
/// surrounding whitespace, an optional single sign, then ASCII digits with
/// underscores permitted only between two digits.
fn python_int_ok(s: &str) -> bool {
    let t = s.trim();
    let t = t.strip_prefix(|c| c == '+' || c == '-').unwrap_or(t);
    if t.is_empty() {
        return false;
    }
    let bytes = t.as_bytes();
    let mut prev_underscore = false;
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'_' {
            // an underscore is only legal strictly between two digits
            if i == 0 || i == bytes.len() - 1 || prev_underscore {
                return false;
            }
            prev_underscore = true;
        } else if b.is_ascii_digit() {
            prev_underscore = false;
        } else {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use swift_http::HeaderKeyDict;

    fn req(method: &str, path: &str) -> Request {
        Request {
            method: method.into(),
            path: path.into(),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: swift_http::Body::empty(),
        }
    }

    /// A next-handler that echoes a 200 with a marker header, so a `handle`
    /// test can tell a pass-through from a rate-limited reject.
    fn passthrough() -> Arc<dyn Fn(Request) -> Response + Send + Sync> {
        Arc::new(|_req: Request| {
            let mut resp = Response::new(200);
            resp.headers.set("X-Reached-App", "yes");
            resp
        })
    }

    // ---- helper-level tests -------------------------------------------

    #[test]
    fn test_validate_device_partition() {
        assert!(validate_device_partition("sda1", "1"));
        assert!(!validate_device_partition("", "1"));
        assert!(!validate_device_partition("sda1", ""));
        assert!(!validate_device_partition(".", "1"));
        assert!(!validate_device_partition("..", "1"));
        assert!(!validate_device_partition("sda1", "."));
        assert!(!validate_device_partition("s/da", "1"));
    }

    #[test]
    fn test_python_int_ok() {
        assert!(python_int_ok("0"));
        assert!(python_int_ok("123"));
        assert!(python_int_ok("  42  ")); // int() strips whitespace
        assert!(python_int_ok("+7"));
        assert!(python_int_ok("-7"));
        assert!(python_int_ok("1_000")); // underscore between digits
        assert!(!python_int_ok(""));
        assert!(!python_int_ok("abc"));
        assert!(!python_int_ok("12.5"));
        assert!(!python_int_ok("0x1f"));
        assert!(!python_int_ok("_1"));
        assert!(!python_int_ok("1_"));
        assert!(!python_int_ok("1__0"));
        assert!(!python_int_ok("+ 5")); // sign then space is invalid
    }

    // ---- pass-through cases (no rate limiting applied) ----------------

    #[test]
    fn test_no_limits_configured_passes() {
        let mw = BackendRateLimit::new();
        assert!(!mw.is_any_rate_limit_configured());
        // even a well-formed GET at the same instant, many times, passes.
        for _ in 0..5 {
            assert!(mw.evaluate(&req("GET", "/sda1/1/a/c/o"), 1000.0).is_none());
        }
    }

    #[test]
    fn test_non_rate_limited_method_passes() {
        let mw = BackendRateLimit::new().with_device_rate(1.0);
        // OPTIONS is not in RATE_LIMITED_METHODS -> never limited.
        for _ in 0..5 {
            assert!(mw.evaluate(&req("OPTIONS", "/sda1/1/a"), 1000.0).is_none());
        }
    }

    #[test]
    fn test_unparseable_or_incomplete_path_passes() {
        let mw = BackendRateLimit::new().with_device_rate(1.0);
        // no leading slash -> split_path fails
        assert!(mw.evaluate(&req("GET", "relative/1/a"), 1000.0).is_none());
        // missing partition
        assert!(mw.evaluate(&req("GET", "/sda1"), 1000.0).is_none());
        // empty device
        assert!(mw.evaluate(&req("GET", "//1/a"), 1000.0).is_none());
        // device is '..'
        assert!(mw.evaluate(&req("GET", "/../1/a"), 1000.0).is_none());
        // even called repeatedly, a passthrough path never rejects
        for _ in 0..5 {
            assert!(mw.evaluate(&req("GET", "/sda1"), 1000.0).is_none());
        }
    }

    #[test]
    fn test_non_integer_partition_passes() {
        let mw = BackendRateLimit::new().with_device_rate(1.0);
        // partition not an int -> passed through even under load
        for _ in 0..5 {
            assert!(mw
                .evaluate(&req("GET", "/sda1/notanint/a"), 1000.0)
                .is_none());
        }
    }

    // ---- enforcement --------------------------------------------------

    #[test]
    fn test_aggregate_device_limit_enforced() {
        // rate 1/s, no buffer: exactly one request per second per device.
        let mw = BackendRateLimit::new()
            .with_device_rate(1.0)
            .with_rate_buffer(0.0);

        // first request at t=1000s allowed
        assert!(mw.evaluate(&req("GET", "/sda1/1/a/c/o"), 1000.0).is_none());
        // second at the same instant rejected with 529
        let rejected = mw.evaluate(&req("GET", "/sda1/1/a/c/o"), 1000.0);
        assert_eq!(rejected.map(|r| r.status), Some(529));
        // a *different* device has its own limiter -> allowed
        assert!(mw.evaluate(&req("GET", "/sdb1/1/a/c/o"), 1000.0).is_none());
        // one second later the first device is allowed again
        assert!(mw.evaluate(&req("GET", "/sda1/1/a/c/o"), 1001.0).is_none());
    }

    #[test]
    fn test_method_is_part_of_the_key() {
        // Aggregate off; only GET is limited. HEAD (rate 0) is unlimited,
        // and PUT to the same device is a different limiter key.
        let mw = BackendRateLimit::new()
            .with_method_rate("GET", 1.0)
            .with_rate_buffer(0.0);
        assert!(mw.is_any_rate_limit_configured());

        assert!(mw.evaluate(&req("GET", "/sda1/1/a"), 1000.0).is_none());
        // second GET at same instant -> 529
        assert_eq!(
            mw.evaluate(&req("GET", "/sda1/1/a"), 1000.0)
                .map(|r| r.status),
            Some(529)
        );
        // HEAD is not limited (rate 0) even though GET is exhausted
        for _ in 0..5 {
            assert!(mw.evaluate(&req("HEAD", "/sda1/1/a"), 1000.0).is_none());
        }
    }

    #[test]
    fn test_aggregate_blocks_even_when_method_has_capacity() {
        // Aggregate 1/s but a very high per-method rate: the aggregate
        // limiter must still reject the second request.
        let mw = BackendRateLimit::new()
            .with_device_rate(1.0)
            .with_method_rate("GET", 1000.0)
            .with_rate_buffer(0.0);
        assert!(mw.evaluate(&req("GET", "/sda1/1/a"), 1000.0).is_none());
        assert_eq!(
            mw.evaluate(&req("GET", "/sda1/1/a"), 1000.0)
                .map(|r| r.status),
            Some(529)
        );
    }

    #[test]
    fn test_rate_buffer_allows_a_burst() {
        // rate 1/s with a 1s buffer and burst_after_idle: the first two
        // requests at the same instant are allowed (1 buffered + 1), the
        // third is rejected.
        let mw = BackendRateLimit::new()
            .with_device_rate(1.0)
            .with_rate_buffer(1.0);
        assert!(mw.evaluate(&req("GET", "/sda1/1/a"), 1000.0).is_none());
        assert!(mw.evaluate(&req("GET", "/sda1/1/a"), 1000.0).is_none());
        assert_eq!(
            mw.evaluate(&req("GET", "/sda1/1/a"), 1000.0)
                .map(|r| r.status),
            Some(529)
        );
    }

    // ---- response shape & config --------------------------------------

    #[test]
    fn test_529_response_shape() {
        let mw = BackendRateLimit::new()
            .with_device_rate(1.0)
            .with_rate_buffer(0.0);
        assert!(mw.evaluate(&req("GET", "/sda1/1/a"), 1000.0).is_none());
        let mut resp = mw.evaluate(&req("GET", "/sda1/1/a"), 1000.0).unwrap();
        assert_eq!(resp.status, 529);
        assert_eq!(resp.reason, "Too Many Backend Requests");
        assert_eq!(
            resp.headers.get("Content-Type"),
            Some("text/html; charset=UTF-8")
        );
        let body = String::from_utf8(resp.body.materialize(u64::MAX).unwrap().to_vec()).unwrap();
        assert!(body.contains("<h1>Too Many Backend Requests</h1>"));
        assert!(body.contains("too many requests. Slow down."));
    }

    #[test]
    fn test_configured_reject_status() {
        let mw = BackendRateLimit::new()
            .with_device_rate(1.0)
            .with_rate_buffer(0.0)
            .with_status(503);
        assert!(mw.evaluate(&req("GET", "/sda1/1/a"), 1000.0).is_none());
        assert_eq!(
            mw.evaluate(&req("GET", "/sda1/1/a"), 1000.0)
                .map(|r| r.status),
            Some(503)
        );
    }

    // ---- full handle() path -------------------------------------------

    #[test]
    fn test_handle_passes_through_when_allowed() {
        let mw = BackendRateLimit::new().with_device_rate(1.0);
        let app = passthrough();
        let resp = mw.handle(req("GET", "/sda1/1/a/c/o"), &app);
        assert_eq!(resp.status, 200);
        assert_eq!(resp.headers.get("X-Reached-App"), Some("yes"));
    }

    #[test]
    fn test_handle_rejects_second_rapid_request() {
        // rate 1/s, no buffer: two back-to-back handle() calls (same
        // wall-clock second) -> first reaches the app, second is a 529 and
        // never reaches the app.
        let mw = BackendRateLimit::new()
            .with_device_rate(1.0)
            .with_rate_buffer(0.0);

        let app1 = passthrough();
        let first = mw.handle(req("GET", "/sda1/1/a/c/o"), &app1);
        assert_eq!(first.status, 200);
        assert_eq!(first.headers.get("X-Reached-App"), Some("yes"));

        let app2 = passthrough();
        let second = mw.handle(req("GET", "/sda1/1/a/c/o"), &app2);
        assert_eq!(second.status, 529);
        assert!(second.headers.get("X-Reached-App").is_none());
    }
}
