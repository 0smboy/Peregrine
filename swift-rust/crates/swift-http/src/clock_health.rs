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

//! Cached local clock-health signal for WORM COMPLIANCE enforcement.
//!
//! Shared by `swift-s3api` (proxy WORM evaluate calls) and
//! `swift-object-server` (native lock gate); those crates must not depend
//! on each other, so the reader lives here next to the other cross-server
//! infrastructure (`thread_concurrency`).
//!
//! Semantics (`worm_clock_max_offset_ms`):
//! * `0` (default) — **disabled**: `clock_ok()` is constant `true`, the
//!   reader is never invoked, and behavior is identical to the historical
//!   hard-coded `clock_ok=true`.
//! * `> 0` — **enabled, fail-closed**: the offset reader (chrony tracking
//!   by default) is consulted through a TTL cache. `clock_ok()` is `true`
//!   only when a fresh-enough reading exists and its absolute offset is
//!   within the threshold. Unreadable source, unparseable data, or an
//!   offset over the threshold all yield `false`.
//!
//! The reader is never invoked more than once per TTL window (default 30s),
//! including on failure: a failed refresh is cached as unhealthy for one TTL
//! so a broken chrony cannot turn every request into a subprocess spawn.

use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Refresh reader: one measurement of the local clock offset in
/// milliseconds (signed), or `None` when the source is unreadable or the
/// clock is not synchronised.
pub type ClockOffsetReader = Box<dyn Fn() -> Option<f64> + Send + Sync>;

/// How long one reading (success or failure) stays authoritative.
pub const CLOCK_HEALTH_TTL: Duration = Duration::from_secs(30);

struct ClockCache {
    /// `None` = never refreshed.
    fetched_at: Option<Instant>,
    /// Last reading: `Some(offset_ms)` or `None` (source unhealthy).
    offset_ms: Option<f64>,
}

/// Lazily refreshed clock-health source. See the module docs for the
/// disabled / enabled / fail-closed contract.
pub struct ClockHealth {
    max_offset_ms: u64,
    ttl: Duration,
    reader: Option<ClockOffsetReader>,
    cache: Mutex<ClockCache>,
}

impl std::fmt::Debug for ClockHealth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClockHealth")
            .field("max_offset_ms", &self.max_offset_ms)
            .field("ttl", &self.ttl)
            .finish_non_exhaustive()
    }
}

impl Default for ClockHealth {
    fn default() -> Self {
        Self::disabled()
    }
}

impl ClockHealth {
    /// Disabled source: `clock_ok()` is constant `true` (historical behavior).
    pub fn disabled() -> Self {
        ClockHealth {
            max_offset_ms: 0,
            ttl: CLOCK_HEALTH_TTL,
            reader: None,
            cache: Mutex::new(ClockCache {
                fetched_at: None,
                offset_ms: None,
            }),
        }
    }

    /// Enabled source with an injected reader (tests, alternate backends).
    /// `max_offset_ms == 0` still means disabled regardless of the reader.
    pub fn with_reader(max_offset_ms: u64, ttl: Duration, reader: ClockOffsetReader) -> Self {
        ClockHealth {
            max_offset_ms,
            ttl,
            reader: Some(reader),
            cache: Mutex::new(ClockCache {
                fetched_at: None,
                offset_ms: None,
            }),
        }
    }

    /// Production source: `chronyc -c tracking` behind the TTL cache.
    pub fn chrony(max_offset_ms: u64) -> Self {
        Self::with_reader(
            max_offset_ms,
            CLOCK_HEALTH_TTL,
            Box::new(read_chronyc_tracking_offset_ms),
        )
    }

    /// Configured threshold; `0` = disabled.
    pub fn max_offset_ms(&self) -> u64 {
        self.max_offset_ms
    }

    /// Whether enforcement is on (threshold configured and a reader wired).
    pub fn enabled(&self) -> bool {
        self.max_offset_ms > 0 && self.reader.is_some()
    }

    /// Current clock-health bit for WORM evaluation.
    ///
    /// Disabled → `true`. Enabled → fail-closed: `true` only for a
    /// fresh-enough reading whose `|offset|` is within `max_offset_ms`.
    pub fn clock_ok(&self) -> bool {
        if self.max_offset_ms == 0 {
            return true;
        }
        let Some(reader) = self.reader.as_ref() else {
            // Enabled without a source cannot prove health.
            return false;
        };
        let mut cache = match self.cache.lock() {
            Ok(cache) => cache,
            // A poisoned cache means a reader panicked mid-refresh; treat
            // the source as unhealthy rather than guessing.
            Err(_) => return false,
        };
        let stale = match cache.fetched_at {
            None => true,
            Some(at) => at.elapsed() >= self.ttl,
        };
        if stale {
            cache.offset_ms = reader();
            cache.fetched_at = Some(Instant::now());
        }
        match cache.offset_ms {
            Some(offset_ms) => {
                offset_ms.is_finite() && offset_ms.abs() <= self.max_offset_ms as f64
            }
            None => false,
        }
    }
}

/// Parse `chronyc -c tracking` CSV output into a signed offset in
/// milliseconds. `None` when the output is not healthy tracking data.
///
/// CSV fields (chrony 4.x): refid, refid-address, stratum, ref-time,
/// **current correction (s)** [4], last offset (s), RMS offset (s),
/// freq ppm, resid freq, skew, root delay, root dispersion,
/// update interval, **leap status** [13].
///
/// Fail-closed rules: fewer than 14 fields, stratum 0, leap status
/// `Not synchronised`, or an unparseable/non-finite correction → `None`.
pub fn parse_chronyc_tracking_csv(output: &str) -> Option<f64> {
    let line = output.lines().find(|l| !l.trim().is_empty())?.trim();
    let fields: Vec<&str> = line.split(',').collect();
    if fields.len() < 14 {
        return None;
    }
    let stratum: u32 = fields[2].trim().parse().ok()?;
    if stratum == 0 {
        return None;
    }
    let leap = fields[fields.len() - 1].trim();
    if leap.eq_ignore_ascii_case("not synchronised")
        || leap.eq_ignore_ascii_case("not synchronized")
    {
        return None;
    }
    let correction_seconds: f64 = fields[4].trim().parse().ok()?;
    if !correction_seconds.is_finite() {
        return None;
    }
    Some(correction_seconds * 1000.0)
}

/// Run `chronyc -c tracking` and parse it. Any spawn/exit/parse failure is
/// `None` (unhealthy). Only invoked through the [`ClockHealth`] TTL cache.
fn read_chronyc_tracking_offset_ms() -> Option<f64> {
    let output = std::process::Command::new("chronyc")
        .args(["-c", "tracking"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    parse_chronyc_tracking_csv(&text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    const HEALTHY_CSV: &str = "2D5AA2FD,45.90.162.253,4,1786976880.900600870,-0.000065028,\
         0.000064621,0.000062506,6.943,0.001,0.021,0.018722098,0.002635939,1033.7,Normal\n";

    #[test]
    fn parse_healthy_tracking() {
        let offset = parse_chronyc_tracking_csv(HEALTHY_CSV).expect("healthy line parses");
        assert!((offset - (-0.065028)).abs() < 1e-9, "offset_ms={offset}");
    }

    #[test]
    fn parse_rejects_unsynchronised_and_garbage() {
        // chrony reports stratum 0 + "Not synchronised" when unsynced.
        let unsynced = "7F7F0101,,0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,Not synchronised\n";
        assert_eq!(parse_chronyc_tracking_csv(unsynced), None);
        assert_eq!(parse_chronyc_tracking_csv(""), None);
        assert_eq!(
            parse_chronyc_tracking_csv("506 Cannot talk to daemon\n"),
            None
        );
        let short = "2D5AA2FD,1.2.3.4,4,1.0,-0.001\n";
        assert_eq!(parse_chronyc_tracking_csv(short), None);
        let bad_correction = "2D5AA2FD,1.2.3.4,4,1.0,abc,0,0,0,0,0,0,0,0,Normal\n";
        assert_eq!(parse_chronyc_tracking_csv(bad_correction), None);
    }

    #[test]
    fn disabled_is_always_ok_and_never_reads() {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_c = Arc::clone(&calls);
        let clock = ClockHealth::with_reader(
            0,
            Duration::ZERO,
            Box::new(move || {
                calls_c.fetch_add(1, Ordering::SeqCst);
                None
            }),
        );
        assert!(!clock.enabled());
        assert!(clock.clock_ok());
        assert_eq!(calls.load(Ordering::SeqCst), 0, "disabled must not read");
        assert!(ClockHealth::disabled().clock_ok());
        assert!(ClockHealth::default().clock_ok());
    }

    #[test]
    fn enabled_healthy_within_threshold_is_ok() {
        let clock = ClockHealth::with_reader(50, Duration::ZERO, Box::new(|| Some(-12.5)));
        assert!(clock.enabled());
        assert!(clock.clock_ok());
    }

    #[test]
    fn enabled_over_threshold_is_fail_closed() {
        let clock = ClockHealth::with_reader(50, Duration::ZERO, Box::new(|| Some(50.1)));
        assert!(!clock.clock_ok());
        let negative = ClockHealth::with_reader(50, Duration::ZERO, Box::new(|| Some(-51.0)));
        assert!(!negative.clock_ok());
        let nan = ClockHealth::with_reader(50, Duration::ZERO, Box::new(|| Some(f64::NAN)));
        assert!(!nan.clock_ok());
    }

    #[test]
    fn enabled_unreadable_is_fail_closed() {
        let clock = ClockHealth::with_reader(50, Duration::ZERO, Box::new(|| None));
        assert!(!clock.clock_ok());
    }

    #[test]
    fn boundary_offset_equal_to_threshold_is_ok() {
        let clock = ClockHealth::with_reader(50, Duration::ZERO, Box::new(|| Some(50.0)));
        assert!(clock.clock_ok());
    }

    #[test]
    fn ttl_caches_success_and_failure() {
        // Large TTL: first read is cached, the reader runs exactly once.
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_c = Arc::clone(&calls);
        let clock = ClockHealth::with_reader(
            50,
            Duration::from_secs(3600),
            Box::new(move || {
                calls_c.fetch_add(1, Ordering::SeqCst);
                Some(1.0)
            }),
        );
        for _ in 0..10 {
            assert!(clock.clock_ok());
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1, "reader must be cached");

        // Failure is cached the same way (no per-request shell out storm).
        let fail_calls = Arc::new(AtomicUsize::new(0));
        let fail_calls_c = Arc::clone(&fail_calls);
        let failing = ClockHealth::with_reader(
            50,
            Duration::from_secs(3600),
            Box::new(move || {
                fail_calls_c.fetch_add(1, Ordering::SeqCst);
                None
            }),
        );
        for _ in 0..10 {
            assert!(!failing.clock_ok());
        }
        assert_eq!(
            fail_calls.load(Ordering::SeqCst),
            1,
            "failure must be cached"
        );
    }

    #[test]
    fn zero_ttl_refreshes_every_call() {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_c = Arc::clone(&calls);
        let clock = ClockHealth::with_reader(
            50,
            Duration::ZERO,
            Box::new(move || {
                let n = calls_c.fetch_add(1, Ordering::SeqCst);
                // Healthy first, over-threshold afterwards: the transition
                // must be visible as soon as the cache expires.
                if n == 0 {
                    Some(0.0)
                } else {
                    Some(1e9)
                }
            }),
        );
        assert!(clock.clock_ok());
        assert!(!clock.clock_ok());
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
}
