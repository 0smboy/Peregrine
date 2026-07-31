//! Per-stage timeline sampling: completed ops aggregated into fixed buckets.
//!
//! Workers send one [`TimelineSample`] per completed operation over an
//! unbounded channel (a non-blocking push, so the hot path is not slowed);
//! a collector task owned by the driver feeds them into [`TimelineBuilder`].
//! Samples are bucketed by completion time relative to stage start.
//!
//! Memory stays bounded two ways: at most [`MAX_BUCKET_SAMPLES`] latency
//! values are kept per (bucket, op) pair, and buckets more than one interval
//! behind the newest observed bucket are finalized into plain counters plus
//! percentiles while the stage is still running.

use crate::ops::OpKind;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

/// Default bucket width in seconds (workload YAML key `sample_interval_secs`).
pub const DEFAULT_SAMPLE_INTERVAL_SECS: u64 = 5;
/// Hard cap on latency samples kept per (bucket, op) pair.
pub const MAX_BUCKET_SAMPLES: usize = 100_000;
/// Per-series point budget when embedding timelines into the JSON report.
pub const MAX_JSON_POINTS_PER_SERIES: usize = 400;

const MIB: f64 = 1024.0 * 1024.0;

/// Clamp a configured sample interval to the supported 1..=60 s range.
pub fn clamp_interval_secs(secs: u64) -> u64 {
    secs.clamp(1, 60)
}

/// One completed operation, as sent from a worker to the collector task.
#[derive(Debug, Clone, Copy)]
pub struct TimelineSample {
    /// Completion time relative to stage start.
    pub offset: Duration,
    pub op: OpKind,
    pub ok: bool,
    pub lat_us: u64,
    pub bytes: u64,
}

/// Nearest-rank percentile over an ascending-sorted slice. Returns 0 when
/// the slice is empty.
pub fn percentile_us(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let n = sorted.len();
    let rank = ((p / 100.0) * n as f64).ceil() as usize;
    sorted[rank.clamp(1, n) - 1]
}

#[derive(Default)]
struct BucketAcc {
    ok: u64,
    fail: u64,
    bytes: u64,
    lat_us: Vec<u64>,
}

#[derive(Default, Clone, Copy)]
struct DoneBucket {
    ok: u64,
    fail: u64,
    bytes: u64,
    p50_us: u64,
    p95_us: u64,
    p99_us: u64,
}

/// Streaming bucket aggregator for one stage.
pub struct TimelineBuilder {
    interval_secs: u64,
    sample_cap: usize,
    /// Highest bucket index observed so far.
    watermark: u64,
    /// Buckets below this index are finalized; late samples for them only
    /// update counters (their percentiles are already fixed).
    flushed_below: u64,
    active: BTreeMap<u64, BTreeMap<OpKind, BucketAcc>>,
    done: BTreeMap<u64, BTreeMap<OpKind, DoneBucket>>,
}

impl TimelineBuilder {
    pub fn new(interval_secs: u64, sample_cap: usize) -> Self {
        Self {
            interval_secs: clamp_interval_secs(interval_secs),
            sample_cap: sample_cap.max(1),
            watermark: 0,
            flushed_below: 0,
            active: BTreeMap::new(),
            done: BTreeMap::new(),
        }
    }

    pub fn interval_secs(&self) -> u64 {
        self.interval_secs
    }

    pub fn record(&mut self, s: &TimelineSample) {
        let idx = s.offset.as_secs() / self.interval_secs;
        if idx > self.watermark {
            self.watermark = idx;
            // Keep the newest bucket and its predecessor open for stragglers;
            // everything older is finalized now to bound memory.
            self.flush_below(self.watermark.saturating_sub(1));
        }
        if idx < self.flushed_below {
            let d = self.done.entry(idx).or_default().entry(s.op).or_default();
            if s.ok {
                d.ok += 1;
            } else {
                d.fail += 1;
            }
            d.bytes += s.bytes;
        } else {
            let acc = self.active.entry(idx).or_default().entry(s.op).or_default();
            if s.ok {
                acc.ok += 1;
            } else {
                acc.fail += 1;
            }
            acc.bytes += s.bytes;
            if acc.lat_us.len() < self.sample_cap {
                acc.lat_us.push(s.lat_us);
            }
        }
    }

    fn flush_below(&mut self, limit: u64) {
        let keys: Vec<u64> = self.active.range(..limit).map(|(k, _)| *k).collect();
        for k in keys {
            let ops = self.active.remove(&k).unwrap_or_default();
            let dst = self.done.entry(k).or_default();
            for (op, acc) in ops {
                let d = dst.entry(op).or_default();
                d.ok += acc.ok;
                d.fail += acc.fail;
                d.bytes += acc.bytes;
                let mut lat = acc.lat_us;
                lat.sort_unstable();
                d.p50_us = percentile_us(&lat, 50.0);
                d.p95_us = percentile_us(&lat, 95.0);
                d.p99_us = percentile_us(&lat, 99.0);
            }
        }
        self.flushed_below = self.flushed_below.max(limit);
    }

    /// Finalize all buckets and produce the stage timeline. `elapsed_secs`
    /// is the total stage duration; the trailing bucket's rates are computed
    /// over its actual (possibly partial) width.
    pub fn finish(mut self, elapsed_secs: f64) -> StageTimeline {
        self.flush_below(u64::MAX);
        let mut points = Vec::new();
        for (idx, ops) in &self.done {
            let bucket_start = idx * self.interval_secs;
            let full = self.interval_secs as f64;
            let dur = {
                let bs = bucket_start as f64;
                if elapsed_secs > bs {
                    (elapsed_secs - bs).min(full)
                } else {
                    full
                }
            }
            .max(1e-3);
            for (op, d) in ops {
                let count = d.ok + d.fail;
                points.push(TimelinePoint {
                    t_offset_secs: bucket_start,
                    op: op.name().to_string(),
                    ok: d.ok,
                    fail: d.fail,
                    bytes: d.bytes,
                    dur_secs: dur,
                    ops_per_sec: count as f64 / dur,
                    mbytes_per_sec: d.bytes as f64 / MIB / dur,
                    p50_ms: d.p50_us as f64 / 1000.0,
                    p95_ms: d.p95_us as f64 / 1000.0,
                    p99_ms: d.p99_us as f64 / 1000.0,
                });
            }
        }
        points.sort_by(|a, b| {
            (a.t_offset_secs, a.op.as_str()).cmp(&(b.t_offset_secs, b.op.as_str()))
        });
        StageTimeline {
            interval_secs: self.interval_secs,
            points,
        }
    }
}

/// One (bucket, op) row of a stage timeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelinePoint {
    /// Bucket start, seconds since stage start.
    pub t_offset_secs: u64,
    pub op: String,
    pub ok: u64,
    pub fail: u64,
    pub bytes: u64,
    /// Effective bucket width in seconds (the last bucket may be partial).
    pub dur_secs: f64,
    pub ops_per_sec: f64,
    /// MiB per second (1024 * 1024 bytes).
    pub mbytes_per_sec: f64,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
}

/// Full timeline of one stage: rows sorted by (t_offset_secs, op).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StageTimeline {
    pub interval_secs: u64,
    pub points: Vec<TimelinePoint>,
}

impl StageTimeline {
    /// Distinct operation names, sorted.
    pub fn op_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.points.iter().map(|p| p.op.clone()).collect();
        names.sort();
        names.dedup();
        names
    }

    /// Rows for one operation, in time order.
    pub fn op_points(&self, op: &str) -> Vec<&TimelinePoint> {
        self.points.iter().filter(|p| p.op == op).collect()
    }

    /// Reduce each per-op series to at most `max_points_per_series` points by
    /// merging adjacent buckets. Counts and bytes are summed and rates are
    /// recomputed over the merged span; percentile values are averaged
    /// weighted by op count (an approximation, used for display only).
    pub fn downsampled(&self, max_points_per_series: usize) -> StageTimeline {
        let max_points_per_series = max_points_per_series.max(1);
        let mut by_op: BTreeMap<&str, Vec<&TimelinePoint>> = BTreeMap::new();
        for p in &self.points {
            by_op.entry(p.op.as_str()).or_default().push(p);
        }
        let mut out: Vec<TimelinePoint> = Vec::new();
        for (_, pts) in by_op {
            if pts.len() <= max_points_per_series {
                out.extend(pts.into_iter().cloned());
                continue;
            }
            let group = pts.len().div_ceil(max_points_per_series);
            for chunk in pts.chunks(group) {
                let ok: u64 = chunk.iter().map(|p| p.ok).sum();
                let fail: u64 = chunk.iter().map(|p| p.fail).sum();
                let bytes: u64 = chunk.iter().map(|p| p.bytes).sum();
                let count = ok + fail;
                let dur: f64 = chunk.iter().map(|p| p.dur_secs).sum::<f64>().max(1e-3);
                let (mut p50, mut p95, mut p99) = (0.0, 0.0, 0.0);
                if count > 0 {
                    let cf = count as f64;
                    p50 = chunk
                        .iter()
                        .map(|p| p.p50_ms * (p.ok + p.fail) as f64)
                        .sum::<f64>()
                        / cf;
                    p95 = chunk
                        .iter()
                        .map(|p| p.p95_ms * (p.ok + p.fail) as f64)
                        .sum::<f64>()
                        / cf;
                    p99 = chunk
                        .iter()
                        .map(|p| p.p99_ms * (p.ok + p.fail) as f64)
                        .sum::<f64>()
                        / cf;
                }
                out.push(TimelinePoint {
                    t_offset_secs: chunk[0].t_offset_secs,
                    op: chunk[0].op.clone(),
                    ok,
                    fail,
                    bytes,
                    dur_secs: dur,
                    ops_per_sec: count as f64 / dur,
                    mbytes_per_sec: bytes as f64 / MIB / dur,
                    p50_ms: p50,
                    p95_ms: p95,
                    p99_ms: p99,
                });
            }
        }
        out.sort_by(|a, b| {
            (a.t_offset_secs, a.op.as_str()).cmp(&(b.t_offset_secs, b.op.as_str()))
        });
        StageTimeline {
            interval_secs: self.interval_secs,
            points: out,
        }
    }

    pub fn csv_string(&self) -> String {
        let mut out = String::from(
            "t_offset_secs,op,ok,fail,ops_per_sec,mbytes_per_sec,p50_ms,p95_ms,p99_ms\n",
        );
        for p in &self.points {
            out.push_str(&format!(
                "{},{},{},{},{:.3},{:.3},{:.3},{:.3},{:.3}\n",
                p.t_offset_secs,
                p.op,
                p.ok,
                p.fail,
                p.ops_per_sec,
                p.mbytes_per_sec,
                p.p50_ms,
                p.p95_ms,
                p.p99_ms
            ));
        }
        out
    }

    pub fn write_csv(&self, path: impl AsRef<Path>) -> anyhow::Result<()> {
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, self.csv_string())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(offset_ms: u64, op: OpKind, ok: bool, lat_us: u64, bytes: u64) -> TimelineSample {
        TimelineSample {
            offset: Duration::from_millis(offset_ms),
            op,
            ok,
            lat_us,
            bytes,
        }
    }

    #[test]
    fn interval_is_clamped() {
        assert_eq!(TimelineBuilder::new(0, 10).interval_secs(), 1);
        assert_eq!(TimelineBuilder::new(5, 10).interval_secs(), 5);
        assert_eq!(TimelineBuilder::new(600, 10).interval_secs(), 60);
    }

    #[test]
    fn bucket_assignment_by_completion_offset() {
        let mut b = TimelineBuilder::new(5, MAX_BUCKET_SAMPLES);
        for off in [0, 4_999, 5_000, 9_999, 10_000] {
            b.record(&sample(off, OpKind::Write, true, 1_000, 10));
        }
        let tl = b.finish(11.0);
        let t: Vec<u64> = tl.points.iter().map(|p| p.t_offset_secs).collect();
        assert_eq!(t, vec![0, 5, 10]);
        let ok: Vec<u64> = tl.points.iter().map(|p| p.ok).collect();
        assert_eq!(ok, vec![2, 2, 1]);
    }

    #[test]
    fn percentile_nearest_rank() {
        let v: Vec<u64> = (1..=100).collect();
        assert_eq!(percentile_us(&v, 50.0), 50);
        assert_eq!(percentile_us(&v, 95.0), 95);
        assert_eq!(percentile_us(&v, 99.0), 99);
        assert_eq!(percentile_us(&[42], 99.0), 42);
        assert_eq!(percentile_us(&[], 50.0), 0);
    }

    #[test]
    fn bucket_rates_and_percentiles() {
        let mut b = TimelineBuilder::new(5, MAX_BUCKET_SAMPLES);
        // 5 ok ops in bucket 0, 10..=50 ms latency, 1 MiB each.
        for (i, lat_ms) in [10u64, 20, 30, 40, 50].iter().enumerate() {
            b.record(&sample(
                i as u64 * 100,
                OpKind::Read,
                true,
                lat_ms * 1_000,
                1024 * 1024,
            ));
        }
        let tl = b.finish(5.0);
        assert_eq!(tl.points.len(), 1);
        let p = &tl.points[0];
        assert_eq!(p.op, "read");
        assert_eq!(p.ok, 5);
        assert!((p.ops_per_sec - 1.0).abs() < 1e-9);
        assert!((p.mbytes_per_sec - 1.0).abs() < 1e-9);
        assert!((p.p50_ms - 30.0).abs() < 1e-9);
        assert!((p.p95_ms - 50.0).abs() < 1e-9);
        assert!((p.p99_ms - 50.0).abs() < 1e-9);
    }

    #[test]
    fn failures_count_toward_rate_but_not_bytes() {
        let mut b = TimelineBuilder::new(1, MAX_BUCKET_SAMPLES);
        b.record(&sample(100, OpKind::Write, true, 1_000, 512));
        b.record(&sample(200, OpKind::Write, false, 2_000, 0));
        let tl = b.finish(1.0);
        let p = &tl.points[0];
        assert_eq!((p.ok, p.fail), (1, 1));
        assert!((p.ops_per_sec - 2.0).abs() < 1e-9);
        assert_eq!(p.bytes, 512);
    }

    #[test]
    fn trailing_partial_bucket_uses_actual_width() {
        let mut b = TimelineBuilder::new(5, MAX_BUCKET_SAMPLES);
        b.record(&sample(12_000, OpKind::Write, true, 1_000, 0));
        let tl = b.finish(13.0);
        let p = &tl.points[0];
        assert_eq!(p.t_offset_secs, 10);
        assert!((p.dur_secs - 3.0).abs() < 1e-9);
        assert!((p.ops_per_sec - 1.0 / 3.0).abs() < 1e-9);
    }

    #[test]
    fn sample_cap_bounds_memory_but_keeps_counts() {
        let mut b = TimelineBuilder::new(5, 10);
        for i in 0..100u64 {
            b.record(&sample(0, OpKind::Read, true, (i + 1) * 1_000, 1));
        }
        let tl = b.finish(5.0);
        let p = &tl.points[0];
        assert_eq!(p.ok, 100);
        // Percentiles come from the first 10 retained samples (1..=10 ms).
        assert!((p.p99_ms - 10.0).abs() < 1e-9);
    }

    #[test]
    fn late_sample_after_flush_updates_counters_only() {
        let mut b = TimelineBuilder::new(1, MAX_BUCKET_SAMPLES);
        b.record(&sample(500, OpKind::Write, true, 5_000, 100));
        // Jump ahead: buckets < 4 get finalized.
        b.record(&sample(5_500, OpKind::Write, true, 1_000, 100));
        // Late arrival for bucket 0: counted, percentiles unchanged.
        b.record(&sample(600, OpKind::Write, false, 900_000, 0));
        let tl = b.finish(6.0);
        let first = &tl.points[0];
        assert_eq!(first.t_offset_secs, 0);
        assert_eq!((first.ok, first.fail), (1, 1));
        assert!((first.p99_ms - 5.0).abs() < 1e-9);
        assert!(tl.points.iter().any(|p| p.t_offset_secs == 5));
    }

    #[test]
    fn multiple_ops_per_bucket_are_separate_rows() {
        let mut b = TimelineBuilder::new(5, MAX_BUCKET_SAMPLES);
        b.record(&sample(100, OpKind::Write, true, 1_000, 10));
        b.record(&sample(200, OpKind::Read, true, 1_000, 10));
        let tl = b.finish(5.0);
        assert_eq!(tl.op_names(), vec!["read".to_string(), "write".to_string()]);
        assert_eq!(tl.points.len(), 2);
    }

    #[test]
    fn downsample_caps_series_and_preserves_totals() {
        let points: Vec<TimelinePoint> = (0..1000u64)
            .map(|i| TimelinePoint {
                t_offset_secs: i * 5,
                op: "write".into(),
                ok: 10,
                fail: 2,
                bytes: 1024 * 1024,
                dur_secs: 5.0,
                ops_per_sec: 12.0 / 5.0,
                mbytes_per_sec: 1.0 / 5.0,
                p50_ms: 10.0,
                p95_ms: 20.0,
                p99_ms: 30.0,
            })
            .collect();
        let tl = StageTimeline {
            interval_secs: 5,
            points,
        };
        let ds = tl.downsampled(400);
        assert!(ds.points.len() <= 400);
        assert!(ds.points.len() >= 300);
        assert_eq!(ds.points.iter().map(|p| p.ok).sum::<u64>(), 10_000);
        assert_eq!(ds.points.iter().map(|p| p.fail).sum::<u64>(), 2_000);
        assert_eq!(
            ds.points.iter().map(|p| p.bytes).sum::<u64>(),
            1000 * 1024 * 1024
        );
        // Uniform input: merged rates and percentiles are unchanged.
        for p in &ds.points {
            assert!((p.ops_per_sec - 12.0 / 5.0).abs() < 1e-9);
            assert!((p.p95_ms - 20.0).abs() < 1e-9);
        }
        // Time order preserved.
        let mut prev = 0;
        for p in &ds.points {
            assert!(p.t_offset_secs >= prev);
            prev = p.t_offset_secs;
        }
        // Short series pass through untouched.
        let ds2 = tl.downsampled(2000);
        assert_eq!(ds2.points.len(), 1000);
    }

    #[test]
    fn csv_has_expected_header_and_rows() {
        let mut b = TimelineBuilder::new(1, MAX_BUCKET_SAMPLES);
        b.record(&sample(100, OpKind::Write, true, 2_000, 4096));
        let tl = b.finish(1.0);
        let csv = tl.csv_string();
        let mut lines = csv.lines();
        assert_eq!(
            lines.next(),
            Some("t_offset_secs,op,ok,fail,ops_per_sec,mbytes_per_sec,p50_ms,p95_ms,p99_ms")
        );
        let row = lines.next().unwrap();
        assert!(row.starts_with("0,write,1,0,"));
    }
}
