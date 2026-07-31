//! JSON / CSV report export and report-file loading.

use crate::driver::StageReport;
use crate::timeline::{StageTimeline, MAX_JSON_POINTS_PER_SERIES};
use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportBundle {
    pub workload: String,
    pub generated_at: String,
    pub stages: Vec<StageReportJson>,
    /// Per-stage timelines keyed by stage name, downsampled to at most
    /// [`MAX_JSON_POINTS_PER_SERIES`] points per op series. Full resolution
    /// lives in the `timeline-<stage>.csv` files.
    #[serde(default)]
    pub timeline: BTreeMap<String, StageTimeline>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageReportJson {
    pub name: String,
    pub elapsed_secs: f64,
    pub ops_ok: u64,
    pub ops_fail: u64,
    pub bytes: u64,
    pub success_ratio: f64,
    pub throughput_ops: f64,
    pub bandwidth_mib_s: f64,
    pub lat_p50_us: u64,
    pub lat_p95_us: u64,
    pub lat_p99_us: u64,
    pub lat_mean_us: f64,
    pub sample_errors: Vec<String>,
}

impl ReportBundle {
    pub fn from_stages(workload: &str, stages: &[StageReport]) -> Self {
        let timeline = stages
            .iter()
            .map(|r| {
                (
                    r.name.clone(),
                    r.timeline.downsampled(MAX_JSON_POINTS_PER_SERIES),
                )
            })
            .collect();
        let stages = stages
            .iter()
            .map(|r| StageReportJson {
                name: r.name.clone(),
                elapsed_secs: r.elapsed_secs,
                ops_ok: r.metrics.ops_ok,
                ops_fail: r.metrics.ops_fail,
                bytes: r.metrics.bytes,
                success_ratio: r.metrics.success_ratio,
                throughput_ops: r.metrics.throughput_ops(r.elapsed_secs),
                bandwidth_mib_s: r.metrics.bandwidth_mib_s(r.elapsed_secs),
                lat_p50_us: r.metrics.lat_p50_us,
                lat_p95_us: r.metrics.lat_p95_us,
                lat_p99_us: r.metrics.lat_p99_us,
                lat_mean_us: r.metrics.lat_mean_us,
                sample_errors: r.metrics.sample_errors.clone(),
            })
            .collect();
        Self {
            workload: workload.to_string(),
            generated_at: chrono::Utc::now().to_rfc3339(),
            stages,
            timeline,
        }
    }

    pub fn write_json(&self, path: impl AsRef<Path>) -> anyhow::Result<()> {
        if let Some(parent) = path.as_ref().parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }

    pub fn write_csv(&self, path: impl AsRef<Path>) -> anyhow::Result<()> {
        if let Some(parent) = path.as_ref().parent() {
            fs::create_dir_all(parent)?;
        }
        let mut out = String::from(
            "stage,elapsed_secs,ops_ok,ops_fail,bytes,success_ratio,ops_per_s,mib_per_s,p50_us,p95_us,p99_us,mean_us\n",
        );
        for s in &self.stages {
            out.push_str(&format!(
                "{},{:.6},{},{},{},{:.6},{:.3},{:.3},{},{},{},{:.3}\n",
                s.name,
                s.elapsed_secs,
                s.ops_ok,
                s.ops_fail,
                s.bytes,
                s.success_ratio,
                s.throughput_ops,
                s.bandwidth_mib_s,
                s.lat_p50_us,
                s.lat_p95_us,
                s.lat_p99_us,
                s.lat_mean_us
            ));
        }
        fs::write(path, out)?;
        Ok(())
    }
}

/// Keep stage names safe as a single path component.
fn sanitize_component(name: &str) -> String {
    let s: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if s.is_empty() {
        "stage".into()
    } else {
        s
    }
}

/// Write one full-resolution `timeline-<stage>.csv` per stage into `dir`.
/// Returns the written paths.
pub fn write_timeline_csvs(
    dir: impl AsRef<Path>,
    stages: &[StageReport],
) -> anyhow::Result<Vec<PathBuf>> {
    let dir = dir.as_ref();
    fs::create_dir_all(dir)?;
    let mut written = Vec::new();
    for s in stages {
        let path = dir.join(format!("timeline-{}.csv", sanitize_component(&s.name)));
        s.timeline.write_csv(&path)?;
        written.push(path);
    }
    Ok(written)
}

/// Load a run report from a JSON file, or from a report directory (the most
/// recently modified `*.json` that parses as a run report is used).
pub fn load_report_input(path: impl AsRef<Path>) -> anyhow::Result<(PathBuf, ReportBundle)> {
    let p = path.as_ref();
    if p.is_dir() {
        let mut best: Option<(std::time::SystemTime, PathBuf, ReportBundle)> = None;
        for entry in fs::read_dir(p).with_context(|| format!("read dir {}", p.display()))? {
            let entry = entry?;
            let ep = entry.path();
            if ep.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let Ok(text) = fs::read_to_string(&ep) else {
                continue;
            };
            let Ok(bundle) = serde_json::from_str::<ReportBundle>(&text) else {
                continue;
            };
            let mtime = entry
                .metadata()
                .and_then(|m| m.modified())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
            if best.as_ref().map(|(t, _, _)| mtime >= *t).unwrap_or(true) {
                best = Some((mtime, ep, bundle));
            }
        }
        best.map(|(_, ep, b)| (ep, b))
            .ok_or_else(|| anyhow::anyhow!("no run report JSON found in {}", p.display()))
    } else {
        let text =
            fs::read_to_string(p).with_context(|| format!("read run report {}", p.display()))?;
        let bundle = serde_json::from_str(&text)
            .with_context(|| format!("parse run report JSON {}", p.display()))?;
        Ok((p.to_path_buf(), bundle))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::timeline::TimelinePoint;

    fn tiny_bundle() -> ReportBundle {
        let mut timeline = BTreeMap::new();
        timeline.insert(
            "main".to_string(),
            StageTimeline {
                interval_secs: 5,
                points: vec![TimelinePoint {
                    t_offset_secs: 0,
                    op: "write".into(),
                    ok: 3,
                    fail: 0,
                    bytes: 300,
                    dur_secs: 5.0,
                    ops_per_sec: 0.6,
                    mbytes_per_sec: 0.0001,
                    p50_ms: 1.0,
                    p95_ms: 2.0,
                    p99_ms: 3.0,
                }],
            },
        );
        ReportBundle {
            workload: "w".into(),
            generated_at: "2026-07-31T00:00:00Z".into(),
            stages: vec![],
            timeline,
        }
    }

    #[test]
    fn json_round_trip_keeps_timeline() {
        let b = tiny_bundle();
        let text = serde_json::to_string(&b).unwrap();
        let back: ReportBundle = serde_json::from_str(&text).unwrap();
        assert_eq!(back.timeline["main"].points.len(), 1);
        assert_eq!(back.timeline["main"].points[0].op, "write");
    }

    #[test]
    fn old_reports_without_timeline_still_parse() {
        let text = r#"{"workload":"w","generated_at":"t","stages":[]}"#;
        let back: ReportBundle = serde_json::from_str(text).unwrap();
        assert!(back.timeline.is_empty());
    }

    #[test]
    fn load_report_input_picks_parseable_json_in_dir() {
        let dir = std::env::temp_dir().join(format!("cosbench-report-load-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("junk.json"), "{\"not\": \"a report\"}").unwrap();
        fs::write(dir.join("note.txt"), "ignored").unwrap();
        tiny_bundle().write_json(dir.join("run.json")).unwrap();
        let (path, bundle) = load_report_input(&dir).unwrap();
        assert!(path.ends_with("run.json"));
        assert_eq!(bundle.workload, "w");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn sanitize_keeps_paths_single_component() {
        assert_eq!(sanitize_component("main"), "main");
        assert_eq!(sanitize_component("a/b..c"), "a_b__c");
        assert_eq!(sanitize_component(""), "stage");
    }
}
