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

//! `ratelimit`: token-bucket rate limiting on both the account and the
//! container level, a faithful port of
//! `swift/common/middleware/ratelimit.py`.
//!
//! Requests are limited per account (container `PUT`/`DELETE`), per
//! container (object `PUT`/`DELETE`/`POST`/`COPY`, size-tiered), per
//! container listing (container `GET`, size-tiered), and per account-wide
//! "global write" limit. Configured limits interpolate linearly between
//! the container-size tiers (`interpret_conf_limits`/`get_maxrate`).
//!
//! The bucket is the exact millisecond running-time algorithm from
//! `_get_sleep_time`: each request advances a per-key running time by
//! `clock_accuracy / max_rate` ticks; a request that would have to sleep
//! past `max_sleep_time_seconds` is rejected with `498 Rate Limited`
//! (body `Slow down`). A `rate_buffer_seconds` catch-up window resets an
//! idle key to `now`. Black/white-listing short-circuits the bucket:
//! whitelisted accounts skip limiting entirely, blacklisted accounts get
//! `497 Blacklisted` (body `Your account has been blacklisted`) after a
//! `BLACK_LIST_SLEEP` pause.
//!
//! Deferrals (everything that is *not* the rate-limiting decision):
//! * The memcache backend is replaced by an in-process
//!   `Mutex<HashMap<String, i64>>`. memcache's `incr`/`set`/`decr` map
//!   onto this store with the same integer, clamp-at-zero semantics, so
//!   the bucket arithmetic is byte-identical. Consequently `cache_from_env`,
//!   the "cannot ratelimit without a memcached client" pass-through, and
//!   the `MemcacheConnectionError` -> "return 0, do not limit" recovery
//!   path are N/A (there is no external cache to be missing or to fail).
//! * `get_account_info(...).sysmeta['global-write-ratelimit']` is sourced
//!   from the request header `X-Account-Sysmeta-Global-Write-Ratelimit`
//!   instead of an account-info cache/subrequest lookup — exactly as
//!   `read_only.rs` sources `X-Account-Sysmeta-Read-Only`. It is the value
//!   the account-info resolution step populates in the full pipeline, and
//!   a header `gatekeeper` forbids clients from forging.
//! * `get_container_info(...)['object_count']` (via `get_container_size`)
//!   is sourced from the internal header
//!   `X-Backend-Ratelimit-Container-Object-Count` (default `0`). Resolving
//!   it from the info-cache / a backend subrequest is the deferred part;
//!   the size-tier selection built on top of it is fully ported.
//! * The `swift.ratelimit.handled` env dedup guard (which suppresses a
//!   second ratelimit filter in the same pipeline) is N/A for a single
//!   middleware pass.
//! * Logging is not ported (no logger sink is wired into this crate — the
//!   same deferral `lib.rs` notes for `proxy_logging`): the
//!   `log_sleep_time_seconds` warning, the deprecation warnings for
//!   `account_whitelist`/`account_blacklist`, and the 497/498 error lines.
//!   `log_sleep_time_seconds` is retained as a field. The 497/498 bodies
//!   are still returned.
//! * `filter_factory` / `register_swift_info` (`/info` publication).
//! * The [`Clock`] trait is extended past the requested `now_secs` with a
//!   `sleep` method: production sleeps the OS thread, test clocks advance
//!   their virtual time, mirroring the Python tests where `sleep` advances
//!   the mocked `time.time()`.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use swift_core::constraints::VALID_API_VERSIONS;
use swift_http::{split_path, Request, Response};

use crate::{Middleware, NextFn};

/// Header carrying the account sysmeta `global-write-ratelimit` value
/// (`WHITELIST`, `BLACKLIST`, or a float). See the module deferral note.
const GLOBAL_RATELIMIT_HEADER: &str = "X-Account-Sysmeta-Global-Write-Ratelimit";
/// Internal header carrying the container `object_count`, standing in for
/// the deferred `get_container_info` lookup. See the module deferral note.
const CONTAINER_COUNT_HEADER: &str = "X-Backend-Ratelimit-Container-Object-Count";

/// A monotonic time source, injectable so tests can drive the bucket
/// deterministically. `now_secs` mirrors Python's `time.time()`.
pub trait Clock: Send + Sync {
    /// Current time, in seconds.
    fn now_secs(&self) -> f64;

    /// Sleep for `secs` seconds. The default sleeps the OS thread;
    /// virtual/test clocks override this to advance their own time,
    /// mirroring the Python tests where `sleep` advances the mocked clock.
    fn sleep(&self, secs: f64) {
        if secs > 0.0 {
            std::thread::sleep(Duration::from_secs_f64(secs));
        }
    }
}

/// Production clock: monotonic seconds since construction.
pub struct SystemClock {
    base: Instant,
}

impl SystemClock {
    pub fn new() -> Self {
        SystemClock {
            base: Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        SystemClock::new()
    }
}

impl Clock for SystemClock {
    fn now_secs(&self) -> f64 {
        self.base.elapsed().as_secs_f64()
    }
}

/// The interpolation function for one container-size tier
/// (`interpret_conf_limits`'s `line_func`). `Linear` interpolates between
/// this tier and the next; `Const` is the final (highest) tier.
#[derive(Debug, Clone, Copy, PartialEq)]
enum LineFunc {
    Linear {
        cur_size: i64,
        slope: f64,
        cur_rate: f64,
    },
    Const {
        rate: f64,
    },
}

impl LineFunc {
    /// `line_func(x)` — matches the Python lambdas exactly:
    /// `(x - cur_size) * slope + cur_rate`, or the constant `cur_rate`.
    fn eval(&self, x: i64) -> f64 {
        match *self {
            LineFunc::Linear {
                cur_size,
                slope,
                cur_rate,
            } => (x - cur_size) as f64 * slope + cur_rate,
            LineFunc::Const { rate } => rate,
        }
    }
}

/// One parsed container-size ratelimit tier: `(cur_size, cur_rate,
/// line_func)` in the Python.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RateTier {
    /// Container object-count at which this tier begins.
    pub size: i64,
    /// Requests-per-second at exactly `size`.
    pub rate: f64,
    func: LineFunc,
}

/// Port of `interpret_conf_limits`: collect every `conf` key starting with
/// `name_prefix`, read its integer suffix as a container size and its value
/// as a rate, sort by `(size, rate)`, and build the per-tier linear
/// interpolation functions.
///
/// (Minor deviation from Python: a key whose suffix is not an integer, or
/// whose value is not a float, is skipped rather than raising — the Python
/// `int()`/`float()` would abort `filter_factory` on such a config.)
pub fn interpret_conf_limits(conf: &HashMap<String, String>, name_prefix: &str) -> Vec<RateTier> {
    let mut conf_limits: Vec<(i64, f64)> = Vec::new();
    for (key, value) in conf {
        if let Some(suffix) = key.strip_prefix(name_prefix) {
            if let (Ok(size), Ok(rate)) = (suffix.parse::<i64>(), value.trim().parse::<f64>()) {
                conf_limits.push((size, rate));
            }
        }
    }
    conf_limits.sort_by(|a, b| {
        a.0.cmp(&b.0)
            .then(a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
    });

    let n = conf_limits.len();
    let mut ratelimits = Vec::with_capacity(n);
    for i in 0..n {
        let (cur_size, cur_rate) = conf_limits[i];
        let func = if i + 1 < n {
            let (next_size, next_rate) = conf_limits[i + 1];
            let slope = (next_rate - cur_rate) / (next_size - cur_size) as f64;
            LineFunc::Linear {
                cur_size,
                slope,
                cur_rate,
            }
        } else {
            LineFunc::Const { rate: cur_rate }
        };
        ratelimits.push(RateTier {
            size: cur_size,
            rate: cur_rate,
            func,
        });
    }
    ratelimits
}

/// Port of `get_maxrate`: requests-per-second allowed for a container of
/// `size` objects, or `None` when the size is `0`/below the lowest tier.
pub fn get_maxrate(ratelimits: &[RateTier], size: i64) -> Option<f64> {
    // Python `if size:` — a zero size is falsy and yields no rate.
    if size == 0 {
        return None;
    }
    let mut last_func: Option<LineFunc> = None;
    for tier in ratelimits {
        if size < tier.size {
            break;
        }
        last_func = Some(tier.func);
    }
    last_func.map(|f| f.eval(size))
}

/// Round half-to-even (Python's `round`), for the non-negative products
/// (`now_secs * clock_accuracy`, `clock_accuracy / max_rate`) the bucket
/// feeds it. Rust's `f64::round` rounds half away from zero, which would
/// diverge on exact `.5` boundaries.
fn py_round(x: f64) -> i64 {
    let floor = x.floor();
    let diff = x - floor;
    if diff < 0.5 {
        floor as i64
    } else if diff > 0.5 {
        floor as i64 + 1
    } else {
        let f = floor as i64;
        if f % 2 == 0 {
            f
        } else {
            f + 1
        }
    }
}

/// Internal marker for `MaxSleepTimeHitError`.
struct MaxSleepTimeHit;

/// Rate limiting middleware. Limits requests on both an account and a
/// container level; limits are configurable.
pub struct RateLimit {
    /// Requests-per-second for account writes (config `account_ratelimit`).
    pub account_ratelimit: f64,
    /// Requests would-be sleep past this cap are rejected with `498`
    /// (config `max_sleep_time_seconds`).
    pub max_sleep_time_seconds: f64,
    /// Sleeps longer than this are logged (config `log_sleep_time_seconds`).
    /// Retained for parity; logging itself is deferred.
    pub log_sleep_time_seconds: f64,
    /// Sub-second granularity of the running-time bucket, in ticks per
    /// second (config `clock_accuracy`).
    pub clock_accuracy: i64,
    /// Catch-up window: a key whose running time trails `now` by more than
    /// this many seconds is reset to `now` (config `rate_buffer_seconds`).
    pub rate_buffer_seconds: i64,
    /// Seconds to pause before answering a blacklisted account
    /// (`BLACK_LIST_SLEEP`, Python constant `1`).
    pub black_list_sleep: f64,
    /// Accounts exempt from limiting (config `account_whitelist`).
    pub ratelimit_whitelist: Vec<String>,
    /// Accounts always rejected with `497` (config `account_blacklist`).
    pub ratelimit_blacklist: Vec<String>,
    /// Size-tiered container object-write limits
    /// (`container_ratelimit_*`).
    pub container_ratelimits: Vec<RateTier>,
    /// Size-tiered container listing limits
    /// (`container_listing_ratelimit_*`).
    pub container_listing_ratelimits: Vec<RateTier>,
    clock: Box<dyn Clock>,
    /// Per-key running time, in `clock_accuracy` ticks (replaces memcache).
    store: Mutex<HashMap<String, i64>>,
}

impl RateLimit {
    /// A limiter with Python's default configuration and the given clock.
    pub fn new(clock: Box<dyn Clock>) -> Self {
        RateLimit {
            account_ratelimit: 0.0,
            max_sleep_time_seconds: 60.0,
            log_sleep_time_seconds: 0.0,
            clock_accuracy: 1000,
            rate_buffer_seconds: 5,
            black_list_sleep: 1.0,
            ratelimit_whitelist: Vec::new(),
            ratelimit_blacklist: Vec::new(),
            container_ratelimits: Vec::new(),
            container_listing_ratelimits: Vec::new(),
            clock,
            store: Mutex::new(HashMap::new()),
        }
    }

    /// Build from raw config strings, mirroring `RateLimitMiddleware.__init__`.
    /// Validating constructor used by the proxy builder. Currently wraps
    /// [`Self::from_conf`] (no extra fail-closed checks beyond parse defaults).
    pub fn try_from_conf(
        conf: &HashMap<String, String>,
        clock: Box<dyn Clock>,
    ) -> Result<Self, String> {
        Ok(Self::from_conf(conf, clock))
    }

    pub fn from_conf(conf: &HashMap<String, String>, clock: Box<dyn Clock>) -> Self {
        let get_float = |key: &str, default: f64| {
            conf.get(key)
                .and_then(|v| v.trim().parse::<f64>().ok())
                .unwrap_or(default)
        };
        let get_int = |key: &str, default: i64| {
            conf.get(key)
                .and_then(|v| v.trim().parse::<i64>().ok())
                .unwrap_or(default)
        };
        let csv = |key: &str| -> Vec<String> {
            conf.get(key)
                .map(|v| {
                    v.split(',')
                        .map(|s| s.trim())
                        .filter(|s| !s.is_empty())
                        .map(|s| s.to_string())
                        .collect()
                })
                .unwrap_or_default()
        };
        RateLimit {
            account_ratelimit: get_float("account_ratelimit", 0.0),
            max_sleep_time_seconds: get_float("max_sleep_time_seconds", 60.0),
            log_sleep_time_seconds: get_float("log_sleep_time_seconds", 0.0),
            clock_accuracy: get_int("clock_accuracy", 1000),
            rate_buffer_seconds: get_int("rate_buffer_seconds", 5),
            black_list_sleep: 1.0,
            ratelimit_whitelist: csv("account_whitelist"),
            ratelimit_blacklist: csv("account_blacklist"),
            container_ratelimits: interpret_conf_limits(conf, "container_ratelimit_"),
            container_listing_ratelimits: interpret_conf_limits(
                conf,
                "container_listing_ratelimit_",
            ),
            clock,
            store: Mutex::new(HashMap::new()),
        }
    }

    // --- in-process store, matching memcache incr/set/decr semantics ---

    fn incr(&self, key: &str, delta: i64) -> i64 {
        let mut store = self.store.lock().unwrap();
        let v = store.entry(key.to_string()).or_insert(0);
        *v += delta;
        if *v < 0 {
            *v = 0; // memcache clamps at 0
        }
        *v
    }

    fn set(&self, key: &str, value: i64) {
        self.store.lock().unwrap().insert(key.to_string(), value);
    }

    fn decr(&self, key: &str, delta: i64) {
        self.incr(key, -delta);
    }

    /// Port of `get_ratelimitable_key_tuples`: the ordered list of
    /// `(memcache key, max_rate)` pairs to check for this request. COPYs are
    /// not account-limited; container/listing rates come from the size-tiers.
    fn ratelimitable_key_tuples(
        &self,
        method: &str,
        account: Option<&str>,
        container: Option<&str>,
        obj: Option<&str>,
        container_size: i64,
        global_ratelimit: Option<&str>,
    ) -> Vec<(String, f64)> {
        // Python truthiness of a path name: present and non-empty.
        let truthy = |o: Option<&str>| matches!(o, Some(s) if !s.is_empty());
        let acc = account.unwrap_or("");
        let cont = container.unwrap_or("");
        let mut keys: Vec<(String, f64)> = Vec::new();

        // account write (container PUT/DELETE under an account)
        if self.account_ratelimit != 0.0
            && truthy(account)
            && truthy(container)
            && !truthy(obj)
            && matches!(method, "PUT" | "DELETE")
        {
            keys.push((format!("ratelimit/{acc}"), self.account_ratelimit));
        }

        // container object write, size-tiered
        if truthy(account)
            && truthy(container)
            && truthy(obj)
            && matches!(method, "PUT" | "DELETE" | "POST" | "COPY")
        {
            if let Some(rate) = get_maxrate(&self.container_ratelimits, container_size) {
                if rate != 0.0 {
                    keys.push((format!("ratelimit/{acc}/{cont}"), rate));
                }
            }
        }

        // container listing (GET), size-tiered
        if truthy(account) && truthy(container) && !truthy(obj) && method == "GET" {
            if let Some(rate) = get_maxrate(&self.container_listing_ratelimits, container_size) {
                if rate != 0.0 {
                    keys.push((format!("ratelimit_listing/{acc}/{cont}"), rate));
                }
            }
        }

        // account-wide global write limit
        if truthy(account) && matches!(method, "PUT" | "DELETE" | "POST" | "COPY") {
            if let Some(g) = global_ratelimit {
                if !g.is_empty() {
                    if let Ok(gr) = g.parse::<f64>() {
                        if gr > 0.0 {
                            keys.push((format!("ratelimit/global-write/{acc}"), gr));
                        }
                    }
                }
            }
        }

        keys
    }

    /// Port of `_get_sleep_time`: advance the running-time bucket for `key`
    /// and return the seconds to sleep, or `Err(MaxSleepTimeHit)` when the
    /// sleep would exceed `max_sleep_time_seconds`.
    fn get_sleep_time(&self, key: &str, max_rate: f64) -> Result<f64, MaxSleepTimeHit> {
        let now_m = py_round(self.clock.now_secs() * self.clock_accuracy as f64);
        let time_per_request_m = py_round(self.clock_accuracy as f64 / max_rate);
        let running_time_m = self.incr(key, time_per_request_m);
        let mut need_to_sleep_m: i64 = 0;
        if now_m - running_time_m > self.rate_buffer_seconds * self.clock_accuracy {
            let next_avail_time = now_m + time_per_request_m;
            self.set(key, next_avail_time);
        } else {
            need_to_sleep_m = std::cmp::max(running_time_m - now_m - time_per_request_m, 0);
        }

        let max_sleep_m = self.max_sleep_time_seconds * self.clock_accuracy as f64;
        if max_sleep_m - need_to_sleep_m as f64 <= self.clock_accuracy as f64 * 0.01 {
            // treat as no-op decrement time
            self.decr(key, time_per_request_m);
            return Err(MaxSleepTimeHit);
        }

        Ok(need_to_sleep_m as f64 / self.clock_accuracy as f64)
    }

    /// Port of `handle_ratelimit`: white/black-listing plus per-key
    /// limiting. Returns `Some(response)` to reject (`497`/`498`), or `None`
    /// to pass the request through (possibly after sleeping to throttle).
    fn handle_ratelimit(
        &self,
        req: &Request,
        account: Option<&str>,
        container: Option<&str>,
        obj: Option<&str>,
    ) -> Option<Response> {
        let global = req.headers.get(GLOBAL_RATELIMIT_HEADER);
        let acc = account.unwrap_or("");

        // whitelist: skip limiting entirely
        if self.ratelimit_whitelist.iter().any(|a| a == acc) || global == Some("WHITELIST") {
            return None;
        }

        // blacklist: always reject
        if self.ratelimit_blacklist.iter().any(|a| a == acc) || global == Some("BLACKLIST") {
            self.clock.sleep(self.black_list_sleep);
            return Some(rate_limited_response(
                497,
                "Blacklisted",
                "Your account has been blacklisted",
            ));
        }

        let container_size = req
            .headers
            .get(CONTAINER_COUNT_HEADER)
            .and_then(|s| s.trim().parse::<i64>().ok())
            .unwrap_or(0);

        for (key, max_rate) in self.ratelimitable_key_tuples(
            &req.method,
            account,
            container,
            obj,
            container_size,
            global,
        ) {
            match self.get_sleep_time(&key, max_rate) {
                Ok(need_to_sleep) => {
                    if need_to_sleep > 0.0 {
                        self.clock.sleep(need_to_sleep);
                    }
                }
                Err(MaxSleepTimeHit) => {
                    return Some(rate_limited_response(498, "Rate Limited", "Slow down"));
                }
            }
        }
        None
    }
}

/// swob `Response(status='<code> <reason>', body=<body>)` for the 497/498
/// rejections: the body is exactly the message, content-type `text/html`.
fn rate_limited_response(status: u16, reason: &str, body: &str) -> Response {
    let mut resp = Response::with_body(status, body);
    resp.reason = reason.to_string();
    resp.headers.set("Content-Type", "text/html; charset=UTF-8");
    resp
}

impl Middleware for RateLimit {
    fn handle(&self, req: Request, next: &NextFn) -> Response {
        // A malformed path is not a Swift request we police (Python catches
        // the ValueError from split_path) -- pass it through.
        let parts = match split_path(&req.path, 1, 4, true) {
            Ok(parts) => parts,
            Err(_) => return next(req),
        };
        let version = parts[0].as_deref().unwrap_or("");
        let account = parts.get(1).and_then(|o| o.as_deref());
        let container = parts.get(2).and_then(|o| o.as_deref());
        let obj = parts.get(3).and_then(|o| o.as_deref());

        if !VALID_API_VERSIONS.contains(&version) {
            return next(req);
        }

        match self.handle_ratelimit(&req, account, container, obj) {
            Some(resp) => resp,
            None => next(req),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use swift_http::HeaderKeyDict;

    /// A virtual clock the test drives directly. `sleep` advances its time
    /// (like the Python `mock_sleep`) and records the total slept.
    struct ManualClock {
        now: Mutex<f64>,
        slept: Mutex<f64>,
    }

    impl ManualClock {
        fn new(t: f64) -> Self {
            ManualClock {
                now: Mutex::new(t),
                slept: Mutex::new(0.0),
            }
        }
        fn set(&self, t: f64) {
            *self.now.lock().unwrap() = t;
        }
        fn total_slept(&self) -> f64 {
            *self.slept.lock().unwrap()
        }
    }

    impl Clock for ManualClock {
        fn now_secs(&self) -> f64 {
            *self.now.lock().unwrap()
        }
        fn sleep(&self, secs: f64) {
            *self.slept.lock().unwrap() += secs;
            *self.now.lock().unwrap() += secs;
        }
    }

    impl Clock for Arc<ManualClock> {
        fn now_secs(&self) -> f64 {
            (**self).now_secs()
        }
        fn sleep(&self, secs: f64) {
            (**self).sleep(secs)
        }
    }

    fn conf(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn mk(method: &str, path: &str, headers: &[(&str, &str)]) -> Request {
        let mut h = HeaderKeyDict::new();
        for (k, v) in headers {
            h.set(k, v);
        }
        Request {
            method: method.into(),
            path: path.into(),
            query_string: String::new(),
            headers: h,
            body: swift_http::Body::empty(),
        }
    }

    // Innermost app: a fixed 200 so a pass-through is distinguishable from a
    // middleware rejection (mirrors the Python FakeApp `Some Content`).
    fn content_app() -> Arc<dyn Fn(Request) -> Response + Send + Sync> {
        Arc::new(|_r| Response::with_body(200, b"Some Content".to_vec()))
    }

    /// The returned body is materialized so assertions can read it in place.
    fn run(rl: &RateLimit, req: Request) -> Response {
        let mut resp = rl.handle(req, &content_app());
        resp.body.materialize(u64::MAX).unwrap();
        resp
    }

    /// Test bodies are always buffered once `run` has materialized them.
    fn body_bytes(resp: &Response) -> &[u8] {
        match &resp.body {
            swift_http::Body::Buffered(b) => b,
            swift_http::Body::Streamed(_) => unreachable!(),
        }
    }

    fn assert_pass(resp: &Response) {
        assert_eq!(resp.status, 200);
        assert_eq!(body_bytes(resp), b"Some Content");
    }

    // ------------------------------------------------------------------
    // Pure helpers: interpret_conf_limits / get_maxrate.
    // ------------------------------------------------------------------

    #[test]
    fn test_get_maxrate() {
        // Mirrors test_ratelimit.TestRateLimit.test_get_maxrate.
        let tiers = interpret_conf_limits(
            &conf(&[
                ("container_ratelimit_10", "200"),
                ("container_ratelimit_50", "100"),
                ("container_ratelimit_75", "30"),
            ]),
            "container_ratelimit_",
        );
        assert_eq!(get_maxrate(&tiers, 0), None);
        assert_eq!(get_maxrate(&tiers, 5), None);
        assert_eq!(get_maxrate(&tiers, 10), Some(200.0));
        assert_eq!(get_maxrate(&tiers, 60), Some(72.0));
        assert_eq!(get_maxrate(&tiers, 160), Some(30.0));
    }

    // ------------------------------------------------------------------
    // Key selection: get_ratelimitable_key_tuples.
    // ------------------------------------------------------------------

    #[test]
    fn test_ratelimitable_key_tuples() {
        // Mirrors test_get_ratelimitable_key_tuples: account_ratelimit=13,
        // container_ratelimit_3=200, container object_count=5.
        let clock = Arc::new(ManualClock::new(0.0));
        let mut rl = RateLimit::new(Box::new(clock));
        rl.account_ratelimit = 13.0;
        rl.container_ratelimits = interpret_conf_limits(
            &conf(&[("container_ratelimit_3", "200")]),
            "container_ratelimit_",
        );
        let size = 5;

        let tup = |m, a, c, o, g| rl.ratelimitable_key_tuples(m, a, c, o, size, g);

        // COPYs / reads / missing container produce no account key.
        assert_eq!(tup("DELETE", Some("a"), None, None, None).len(), 0);
        assert_eq!(tup("PUT", Some("a"), Some("c"), None, None).len(), 1);
        assert_eq!(tup("DELETE", Some("a"), Some("c"), None, None).len(), 1);
        assert_eq!(tup("GET", Some("a"), Some("c"), Some("o"), None).len(), 0);
        assert_eq!(tup("PUT", Some("a"), Some("c"), Some("o"), None).len(), 1);

        // account key value.
        assert_eq!(
            tup("PUT", Some("a"), Some("c"), None, None)[0],
            ("ratelimit/a".to_string(), 13.0)
        );
        // object write picks the container size-tier rate.
        assert_eq!(
            tup("PUT", Some("a"), Some("c"), Some("o"), None)[0],
            ("ratelimit/a/c".to_string(), 200.0)
        );

        // a valid global-write float adds a second key, in order.
        let g = tup("PUT", Some("a"), Some("c"), None, Some("10"));
        assert_eq!(g.len(), 2);
        assert_eq!(g[1], ("ratelimit/global-write/a".to_string(), 10.0));

        // a non-float global-write value is ignored.
        assert_eq!(
            tup("PUT", Some("a"), Some("c"), None, Some("notafloat")).len(),
            1
        );
    }

    #[test]
    fn test_empty_container_not_size_limited() {
        // object_count 0 -> get_maxrate None -> no container key, so an
        // object write to an empty container is not size-limited.
        let clock = Arc::new(ManualClock::new(0.0));
        let mut rl = RateLimit::new(Box::new(clock));
        rl.container_ratelimits = interpret_conf_limits(
            &conf(&[("container_ratelimit_0", "2")]),
            "container_ratelimit_",
        );
        assert_eq!(
            rl.ratelimitable_key_tuples("PUT", Some("a"), Some("c"), Some("o"), 0, None)
                .len(),
            0
        );
        assert_eq!(
            rl.ratelimitable_key_tuples("PUT", Some("a"), Some("c"), Some("o"), 1, None)
                .len(),
            1
        );
    }

    // ------------------------------------------------------------------
    // The token bucket: account, container, listing.
    // ------------------------------------------------------------------

    fn double_rate_rl(clock: Arc<ManualClock>) -> RateLimit {
        // account_ratelimit=2, clock_accuracy=100, max_sleep=1: the shape of
        // test_ratelimit_max_rate_double.
        let mut rl = RateLimit::new(Box::new(clock));
        rl.account_ratelimit = 2.0;
        rl.clock_accuracy = 100;
        rl.max_sleep_time_seconds = 1.0;
        rl
    }

    #[test]
    fn test_account_bucket_rejects_then_recovers() {
        // Mirrors test_ratelimit_max_rate_double: four PUTs to /v1/a/c at the
        // same instant -- the 1st/2nd pass (2nd throttled), the 3rd/4th are
        // 498, and once the clock advances a request passes again.
        let clock = Arc::new(ManualClock::new(0.0));
        let rl = double_rate_rl(clock.clone());
        let req = || mk("PUT", "/v1/a/c", &[]);

        clock.set(0.0);
        assert_pass(&run(&rl, req())); // running -> 50, no sleep
        clock.set(0.0);
        assert_pass(&run(&rl, req())); // running -> 100, sleeps 0.5
        clock.set(0.0);
        let r = run(&rl, req()); // running -> 150 then decremented
        assert_eq!(r.status, 498);
        assert_eq!(body_bytes(&r), b"Slow down");
        clock.set(0.0);
        assert_eq!(run(&rl, req()).status, 498);
        clock.set(0.9); // now_m=90 -> need 10 ticks, under the cap
        assert_pass(&run(&rl, req()));
    }

    #[test]
    fn test_container_bucket_rejects() {
        // Mirrors test_ratelimit_max_rate_double_container: PUT of an object,
        // container_ratelimit_0=2, object_count sourced from the header.
        let clock = Arc::new(ManualClock::new(0.0));
        let mut rl = double_rate_rl(clock.clone());
        rl.account_ratelimit = 0.0;
        rl.container_ratelimits = interpret_conf_limits(
            &conf(&[("container_ratelimit_0", "2")]),
            "container_ratelimit_",
        );
        let req = || mk("PUT", "/v1/a/c/o", &[(CONTAINER_COUNT_HEADER, "1")]);

        clock.set(0.0);
        assert_pass(&run(&rl, req()));
        clock.set(0.0);
        assert_pass(&run(&rl, req()));
        clock.set(0.0);
        let r = run(&rl, req());
        assert_eq!(r.status, 498);
        assert_eq!(body_bytes(&r), b"Slow down");
    }

    #[test]
    fn test_container_listing_bucket_rejects() {
        // Mirrors test_ratelimit_max_rate_double_container_listing: GET of a
        // container, container_listing_ratelimit_0=2.
        let clock = Arc::new(ManualClock::new(0.0));
        let mut rl = double_rate_rl(clock.clone());
        rl.account_ratelimit = 0.0;
        rl.container_listing_ratelimits = interpret_conf_limits(
            &conf(&[("container_listing_ratelimit_0", "2")]),
            "container_listing_ratelimit_",
        );
        let req = || mk("GET", "/v1/a/c", &[(CONTAINER_COUNT_HEADER, "1")]);

        clock.set(0.0);
        assert_pass(&run(&rl, req()));
        clock.set(0.0);
        assert_pass(&run(&rl, req()));
        clock.set(0.0);
        assert_eq!(run(&rl, req()).status, 498);
    }

    #[test]
    fn test_bucket_resets_after_idle() {
        // Exercises the rate_buffer_seconds catch-up reset: after a long idle
        // the running time is re-based to now (not credited), so the very next
        // request must sleep again -- which only holds if the reset happened.
        let clock = Arc::new(ManualClock::new(0.0));
        let mut rl = RateLimit::new(Box::new(clock.clone()));
        rl.account_ratelimit = 2.0;
        rl.clock_accuracy = 100;
        rl.rate_buffer_seconds = 5;
        rl.max_sleep_time_seconds = 1000.0; // large: never a 498 here
        let req = || mk("PUT", "/v1/a/c", &[]);

        clock.set(0.0);
        assert_pass(&run(&rl, req())); // running -> 50
        clock.set(1000.0); // idle far past the buffer -> reset, no sleep
        assert_pass(&run(&rl, req()));
        assert_eq!(clock.total_slept(), 0.0);
        clock.set(1000.0); // immediately after the reset -> must sleep 0.5s
        assert_pass(&run(&rl, req()));
        assert!((clock.total_slept() - 0.5).abs() < 1e-9);
    }

    // ------------------------------------------------------------------
    // White / black listing (config and sysmeta).
    // ------------------------------------------------------------------

    #[test]
    fn test_whitelist_config_skips_limiting() {
        let clock = Arc::new(ManualClock::new(0.0));
        let mut rl = double_rate_rl(clock.clone());
        rl.ratelimit_whitelist = vec!["a".to_string()];
        // A burst that would otherwise 498 sails through untouched.
        for _ in 0..10 {
            clock.set(0.0);
            assert_pass(&run(&rl, mk("PUT", "/v1/a/c", &[])));
        }
        assert_eq!(clock.total_slept(), 0.0);
    }

    #[test]
    fn test_whitelist_sysmeta_skips_limiting() {
        let clock = Arc::new(ManualClock::new(0.0));
        let rl = double_rate_rl(clock.clone());
        let hdr = [(GLOBAL_RATELIMIT_HEADER, "WHITELIST")];
        for _ in 0..10 {
            clock.set(0.0);
            assert_pass(&run(&rl, mk("PUT", "/v1/a/c", &hdr)));
        }
        assert_eq!(clock.total_slept(), 0.0);
    }

    #[test]
    fn test_blacklist_config_rejects_497() {
        let clock = Arc::new(ManualClock::new(0.0));
        let mut rl = double_rate_rl(clock);
        rl.ratelimit_blacklist = vec!["b".to_string()];
        rl.black_list_sleep = 0.0;
        let r = run(&rl, mk("PUT", "/v1/b/c", &[]));
        assert_eq!(r.status, 497);
        assert_eq!(body_bytes(&r), b"Your account has been blacklisted");
        // blacklisting is method-agnostic: even a GET is rejected.
        assert_eq!(run(&rl, mk("GET", "/v1/b/c", &[])).status, 497);
    }

    #[test]
    fn test_blacklist_sysmeta_rejects_497() {
        let clock = Arc::new(ManualClock::new(0.0));
        let mut rl = double_rate_rl(clock);
        rl.black_list_sleep = 0.0;
        let hdr = [(GLOBAL_RATELIMIT_HEADER, "BLACKLIST")];
        let r = run(&rl, mk("PUT", "/v1/a/c", &hdr));
        assert_eq!(r.status, 497);
        assert!(String::from_utf8_lossy(body_bytes(&r)).starts_with("Your account"));
    }

    #[test]
    fn test_global_write_ratelimit_sysmeta() {
        // A numeric X-Account-Sysmeta-Global-Write-Ratelimit header adds the
        // global-write key and limits writes even with account_ratelimit=0.
        let clock = Arc::new(ManualClock::new(0.0));
        let mut rl = double_rate_rl(clock.clone());
        rl.account_ratelimit = 0.0;
        let hdr = [(GLOBAL_RATELIMIT_HEADER, "2")];
        let req = || mk("PUT", "/v1/a/c", &hdr);

        clock.set(0.0);
        assert_pass(&run(&rl, req()));
        clock.set(0.0);
        assert_pass(&run(&rl, req()));
        clock.set(0.0);
        assert_eq!(run(&rl, req()).status, 498);
    }

    // ------------------------------------------------------------------
    // Path handling.
    // ------------------------------------------------------------------

    #[test]
    fn test_invalid_and_non_swift_paths_pass_through() {
        let clock = Arc::new(ManualClock::new(0.0));
        let mut rl = double_rate_rl(clock);
        // even a blacklisted-looking account cannot be reached on a bad path
        rl.ratelimit_blacklist = vec!["b".to_string()];
        rl.black_list_sleep = 0.0;

        // malformed path (empty account) -> split_path error -> pass through
        assert_pass(&run(&rl, mk("GET", "//v1/AUTH_1234567890", &[])));
        // non-Swift API version -> pass through
        assert_pass(&run(
            &rl,
            mk("GET", "/ive/got/a/lovely/bunch/of/coconuts", &[]),
        ));
        // valid version but no account segment -> no keys, pass through
        assert_pass(&run(&rl, mk("PUT", "/v1", &[])));
    }

    // ------------------------------------------------------------------
    // Config parsing.
    // ------------------------------------------------------------------

    #[test]
    fn test_from_conf() {
        let c = conf(&[
            ("account_ratelimit", "1"),
            ("max_sleep_time_seconds", "60"),
            ("clock_accuracy", "100"),
            ("rate_buffer_seconds", "7"),
            ("account_whitelist", "a, ,b"),
            ("account_blacklist", "c"),
            ("container_ratelimit_10", "200"),
            ("container_listing_ratelimit_5", "50"),
        ]);
        let rl = RateLimit::from_conf(&c, Box::new(SystemClock::new()));
        assert_eq!(rl.account_ratelimit, 1.0);
        assert_eq!(rl.max_sleep_time_seconds, 60.0);
        assert_eq!(rl.clock_accuracy, 100);
        assert_eq!(rl.rate_buffer_seconds, 7);
        // CSV trims whitespace and drops empty entries.
        assert_eq!(
            rl.ratelimit_whitelist,
            vec!["a".to_string(), "b".to_string()]
        );
        assert_eq!(rl.ratelimit_blacklist, vec!["c".to_string()]);
        assert_eq!(rl.container_ratelimits.len(), 1);
        assert_eq!(rl.container_ratelimits[0].size, 10);
        assert_eq!(rl.container_ratelimits[0].rate, 200.0);
        assert_eq!(rl.container_listing_ratelimits[0].size, 5);
        assert_eq!(rl.container_listing_ratelimits[0].rate, 50.0);

        // defaults when options are absent
        let rl = RateLimit::from_conf(&conf(&[]), Box::new(SystemClock::new()));
        assert_eq!(rl.account_ratelimit, 0.0);
        assert_eq!(rl.max_sleep_time_seconds, 60.0);
        assert_eq!(rl.clock_accuracy, 1000);
        assert_eq!(rl.rate_buffer_seconds, 5);
        assert!(rl.ratelimit_whitelist.is_empty());
        assert!(rl.container_ratelimits.is_empty());
    }
}
