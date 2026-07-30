use hdrhistogram::Histogram;
use parking_lot::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Thread-safe metrics accumulator for one stage.
#[derive(Clone)]
pub struct StageMetrics {
    inner: Arc<Inner>,
}

struct Inner {
    ops_ok: AtomicU64,
    ops_fail: AtomicU64,
    bytes: AtomicU64,
    /// latency in microseconds
    lat_us: Mutex<Histogram<u64>>,
    /// error samples (bounded)
    errors: Mutex<Vec<String>>,
}

impl StageMetrics {
    pub fn new() -> Self {
        let lat = Histogram::<u64>::new_with_bounds(1, 60_000_000, 3)
            .expect("histogram bounds");
        Self {
            inner: Arc::new(Inner {
                ops_ok: AtomicU64::new(0),
                ops_fail: AtomicU64::new(0),
                bytes: AtomicU64::new(0),
                lat_us: Mutex::new(lat),
                errors: Mutex::new(Vec::new()),
            }),
        }
    }

    pub fn record_ok(&self, latency: Duration, bytes: u64) {
        self.inner.ops_ok.fetch_add(1, Ordering::Relaxed);
        self.inner.bytes.fetch_add(bytes, Ordering::Relaxed);
        let us = latency.as_micros().min(u128::from(u64::MAX)) as u64;
        let us = us.max(1);
        let mut h = self.inner.lat_us.lock();
        let _ = h.record(us);
    }

    pub fn record_err(&self, latency: Duration, msg: impl Into<String>) {
        self.inner.ops_fail.fetch_add(1, Ordering::Relaxed);
        let us = latency.as_micros().min(u128::from(u64::MAX)) as u64;
        let us = us.max(1);
        {
            let mut h = self.inner.lat_us.lock();
            let _ = h.record(us);
        }
        let mut e = self.inner.errors.lock();
        if e.len() < 32 {
            e.push(msg.into());
        }
    }

    pub fn total_ops(&self) -> u64 {
        self.inner.ops_ok.load(Ordering::Relaxed) + self.inner.ops_fail.load(Ordering::Relaxed)
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        let ok = self.inner.ops_ok.load(Ordering::Relaxed);
        let fail = self.inner.ops_fail.load(Ordering::Relaxed);
        let bytes = self.inner.bytes.load(Ordering::Relaxed);
        let h = self.inner.lat_us.lock();
        let errors = self.inner.errors.lock().clone();
        MetricsSnapshot {
            ops_ok: ok,
            ops_fail: fail,
            bytes,
            success_ratio: if ok + fail == 0 {
                1.0
            } else {
                ok as f64 / (ok + fail) as f64
            },
            lat_p50_us: percentile(&h, 50.0),
            lat_p95_us: percentile(&h, 95.0),
            lat_p99_us: percentile(&h, 99.0),
            lat_mean_us: if h.is_empty() { 0.0 } else { h.mean() },
            sample_errors: errors,
        }
    }
}

impl Default for StageMetrics {
    fn default() -> Self {
        Self::new()
    }
}

fn percentile(h: &Histogram<u64>, p: f64) -> u64 {
    if h.is_empty() {
        0
    } else {
        h.value_at_percentile(p)
    }
}

#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    pub ops_ok: u64,
    pub ops_fail: u64,
    pub bytes: u64,
    pub success_ratio: f64,
    pub lat_p50_us: u64,
    pub lat_p95_us: u64,
    pub lat_p99_us: u64,
    pub lat_mean_us: f64,
    pub sample_errors: Vec<String>,
}

impl MetricsSnapshot {
    pub fn throughput_ops(&self, elapsed_secs: f64) -> f64 {
        if elapsed_secs <= 0.0 {
            0.0
        } else {
            (self.ops_ok + self.ops_fail) as f64 / elapsed_secs
        }
    }

    pub fn bandwidth_mib_s(&self, elapsed_secs: f64) -> f64 {
        if elapsed_secs <= 0.0 {
            0.0
        } else {
            (self.bytes as f64 / (1024.0 * 1024.0)) / elapsed_secs
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_ratio() {
        let m = StageMetrics::new();
        m.record_ok(Duration::from_millis(1), 10);
        m.record_ok(Duration::from_millis(2), 10);
        m.record_err(Duration::from_millis(3), "x");
        let s = m.snapshot();
        assert_eq!(s.ops_ok, 2);
        assert_eq!(s.ops_fail, 1);
        assert!((s.success_ratio - 2.0 / 3.0).abs() < 1e-9);
    }
}
