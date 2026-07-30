//! JSON / CSV report export.

use crate::driver::StageReport;
use serde::Serialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize)]
pub struct ReportBundle {
    pub workload: String,
    pub generated_at: String,
    pub stages: Vec<StageReportJson>,
}

#[derive(Debug, Clone, Serialize)]
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
