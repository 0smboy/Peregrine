use crate::env_cfg;
use crate::list;
use crate::report_xlsx::{self, ReportMeta};
use anyhow::Result;
use chrono::Local;
use std::fs;
use std::path::PathBuf;

pub fn collect_normal(out: Option<&str>) -> Result<()> {
    env_cfg::ensure_dirs()?;
    // rebuild collect cache via list
    let _ = fs::remove_file(env_cfg::cabt_home().join("result").join(".collect"));
    list::list_results(None)?;

    let src = env_cfg::cabt_home().join("result").join(".collect");
    let meta = ReportMeta::from_env();

    let out = out.map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from(format!(
            "standard-{}.xlsx",
            Local::now().format("%Y-%m-%d")
        ))
    });

    // always keep a CSV sidecar for tooling
    let csv_sidecar = out.with_extension("csv");
    if src.is_file() {
        fs::copy(&src, &csv_sidecar)?;
    }

    if src.is_file() {
        report_xlsx::write_standard_xlsx(&src, &out, &meta)?;
        println!("collect result: {}", out.display());
        println!("csv sidecar:    {}", csv_sidecar.display());
    } else {
        fs::write(
            &csv_sidecar,
            "time,obj_size,worker,op_type,op_count,byte_count,wid\n",
        )?;
        println!("collect result (empty): {}", csv_sidecar.display());
    }
    Ok(())
}

pub fn collect_fool() -> Result<()> {
    env_cfg::ensure_dirs()?;
    let fool_dir = env_cfg::cabt_home().join("fool");
    let _ = fs::remove_file(fool_dir.join(".collect"));
    list::list_results(Some("fool"))?;

    let ts = Local::now().format("%Y-%m-%d-%H-%M-%S");
    let xlsx_out = PathBuf::from(format!("benchmark_report{ts}.xlsx"));
    let csv_out = PathBuf::from(format!("benchmark_report{ts}.csv"));

    let one = fool_dir.join("one-worker.csv");
    let more = fool_dir.join("more-worker.csv");
    let collect = fool_dir.join(".collect");
    let meta = ReportMeta::from_env();

    // Prefer .collect as richer source for standard-style sheet inside fool report;
    // also fill one/more worker sections when present.
    report_xlsx::write_fool_xlsx(&one, &more, &xlsx_out, &meta)?;

    // If .collect exists, also write a full standard xlsx next to it
    if collect.is_file() {
        let body = fs::read_to_string(&collect).unwrap_or_default();
        if body.lines().any(|l| !l.trim().is_empty()) {
            let full = PathBuf::from(format!("benchmark_report{ts}-detail.xlsx"));
            if let Err(e) = report_xlsx::write_standard_xlsx(&collect, &full, &meta) {
                tracing::warn!("detail xlsx skipped: {e:#}");
            } else {
                println!("detail result:  {}", full.display());
            }
            fs::copy(&collect, &csv_out)?;
            println!("csv:            {}", csv_out.display());
        }
    }
    println!("collect result: {}", xlsx_out.display());
    Ok(())
}
