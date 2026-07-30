//! Rust rewrite of cabt's Python report generators:
//! - standard.so / xltpl `render` → standard Excel report
//! - fool.so / openpyxl `update_xlsx` → fool Excel report
//!
//! Original templates lived in dep-packages/{standard,fool}.xlsx with Jinja2 /
//! placeholder fill. We regenerate equivalent .xlsx layouts with rust_xlsxwriter.

use anyhow::{bail, Context, Result};
use chrono::Local;
use rust_xlsxwriter::{Format, FormatAlign, FormatBorder, Workbook, Worksheet};
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;

#[derive(Debug, Clone, Default)]
pub struct ReportMeta {
    pub cosbench_url: String,
    pub endpoint: String,
    pub policy_name: String,
    pub policy_numstr: String,
    pub policy_str: String,
    pub nodes: String,
    pub time: String,
}

impl ReportMeta {
    pub fn from_env() -> Self {
        // Under a Swift target (ST_AUTH set) the auth URL is the endpoint.
        let endpoint = std::env::var("ST_AUTH")
            .or_else(|_| std::env::var("st_auth"))
            .or_else(|_| std::env::var("endpoint"))
            .unwrap_or_else(|_| "127.0.0.1:8080".into());
        Self {
            cosbench_url: std::env::var("cosbench_url")
                .unwrap_or_else(|_| "http://127.0.0.1:19088/controller".into()),
            endpoint,
            policy_name: std::env::var("CABT_POLICY").unwrap_or_default(),
            policy_numstr: std::env::var("CABT_POLICY_NUM").unwrap_or_default(),
            policy_str: std::env::var("CABT_POLICY_STR").unwrap_or_default(),
            nodes: std::env::var("CABT_STORAGE_NODES").unwrap_or_default(),
            time: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        }
    }

    /// Which object API the run exercised: Swift when the swiftclient env
    /// (ST_AUTH) is set, S3 otherwise.
    pub fn api_label(&self) -> &'static str {
        if std::env::var("ST_AUTH").is_ok() || std::env::var("st_auth").is_ok() {
            "Swift"
        } else {
            "S3"
        }
    }

    pub fn policy_display(&self) -> String {
        let mut parts = Vec::new();
        if !self.policy_name.is_empty() {
            parts.push(self.policy_name.clone());
        }
        if !self.policy_numstr.is_empty() || !self.policy_str.is_empty() {
            parts.push(format!("{} {}", self.policy_numstr, self.policy_str).trim().to_string());
        }
        if parts.is_empty() {
            "-".into()
        } else {
            parts.join(" ")
        }
    }
}

/// One result row (mirrors cabt list / .collect fields used by Python).
#[derive(Debug, Clone)]
pub struct JobRow {
    pub time: String,
    pub size: String,
    pub worker: String,
    pub method: String,
    pub op_count: String,
    pub byte_count: String,
    pub wid: String,
    pub policy: String,
    pub container_count: String,
    pub avg_res_ms: String,
    pub avg_proc_ms: String,
    pub throughput: String,
    pub bandwidth: String,
}

impl JobRow {
    /// Parse a `.collect` line from list/collect.
    /// Format: time,obj_size,worker,op_type,op_count,byte_count,wid,policy,container_count,avg_res,avg_proc,throughput,bandwidth
    pub fn from_collect_line(line: &str) -> Option<Self> {
        let c: Vec<_> = line.split(',').map(|s| s.trim().to_string()).collect();
        if c.len() < 12 {
            return None;
        }
        Some(Self {
            time: c[0].clone(),
            size: c[1].clone(),
            worker: c[2].clone(),
            method: c[3].clone(),
            op_count: c[4].clone(),
            byte_count: c[5].clone(),
            wid: c[6].clone(),
            policy: c.get(7).cloned().unwrap_or_default(),
            container_count: c.get(8).cloned().unwrap_or_else(|| "10".into()),
            avg_res_ms: c.get(9).cloned().unwrap_or_default(),
            avg_proc_ms: c.get(10).cloned().unwrap_or_default(),
            throughput: c.get(11).cloned().unwrap_or_default(),
            bandwidth: c.get(12).cloned().unwrap_or_default(),
        })
    }

    /// Parse fool one-worker / more-worker lines:
    /// wid,policy,container_count,avg_res,avg_proc,throughput,bandwidth
    pub fn from_fool_line(line: &str, size_hint: &str, method_hint: &str, worker_hint: &str) -> Option<Self> {
        let c: Vec<_> = line.split(',').map(|s| s.trim().to_string()).collect();
        if c.len() < 6 {
            return None;
        }
        Some(Self {
            time: String::new(),
            size: size_hint.into(),
            worker: worker_hint.into(),
            method: method_hint.into(),
            op_count: String::new(),
            byte_count: String::new(),
            wid: c[0].clone(),
            policy: c.get(1).cloned().unwrap_or_default(),
            container_count: c.get(2).cloned().unwrap_or_else(|| "10".into()),
            avg_res_ms: c.get(3).cloned().unwrap_or_default(),
            avg_proc_ms: c.get(4).cloned().unwrap_or_default(),
            throughput: c.get(5).cloned().unwrap_or_default(),
            bandwidth: c.get(6).cloned().unwrap_or_default(),
        })
    }
}

pub fn load_collect_file(path: impl AsRef<Path>) -> Result<Vec<JobRow>> {
    let f = fs::File::open(path.as_ref())
        .with_context(|| format!("open {}", path.as_ref().display()))?;
    let mut rows = Vec::new();
    for line in BufReader::new(f).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        if let Some(r) = JobRow::from_collect_line(&line) {
            rows.push(r);
        }
    }
    Ok(rows)
}

fn header_fmt() -> Format {
    Format::new()
        .set_bold()
        .set_align(FormatAlign::Center)
        .set_align(FormatAlign::VerticalCenter)
        .set_border(FormatBorder::Thin)
}

fn cell_fmt() -> Format {
    Format::new()
        .set_align(FormatAlign::Center)
        .set_align(FormatAlign::VerticalCenter)
        .set_border(FormatBorder::Thin)
}

fn title_fmt() -> Format {
    Format::new().set_bold().set_font_size(14)
}

fn note_fmt() -> Format {
    Format::new().set_font_size(10).set_align(FormatAlign::Left).set_text_wrap()
}

/// Equivalent of Python `standard.render(template, collect_file, values, output)`.
pub fn write_standard_xlsx(
    collect_path: impl AsRef<Path>,
    output: impl AsRef<Path>,
    meta: &ReportMeta,
) -> Result<()> {
    let jobs = load_collect_file(collect_path)?;
    if jobs.is_empty() {
        bail!("no rows in collect file — run some tasks and `cabt list` first");
    }

    let mut wb = Workbook::new();
    let sheet = wb.add_worksheet();
    sheet.set_name("性能测试结果")?;
    sheet.set_column_width(0, 12)?;
    sheet.set_column_width(1, 12)?;
    sheet.set_column_width(2, 10)?;
    sheet.set_column_width(3, 12)?;
    sheet.set_column_width(4, 12)?;
    sheet.set_column_width(5, 14)?;
    sheet.set_column_width(6, 16)?;
    sheet.set_column_width(7, 16)?;
    sheet.set_column_width(8, 16)?;
    sheet.set_column_width(9, 14)?;

    let title = title_fmt();
    let note = note_fmt();
    let hdr = header_fmt();
    let cell = cell_fmt();

    sheet.write_with_format(0, 0, "对象存储性能测试结果统计", &title)?;
    sheet.merge_range(0, 0, 0, 9, "对象存储性能测试结果统计", &title)?;

    let intro = format!(
        "1.\t测试记录在：\n{}\n2.\t测试结果表格\n对象存储{} API性能测试结果统计\n（endpoint为每台测试服务器的内部 proxy server http://{}/）\n3.测试策略为 {} ，存储节点为 {}\n4.测试时间：{}",
        meta.cosbench_url,
        meta.api_label(),
        meta.endpoint,
        meta.policy_display(),
        if meta.nodes.is_empty() { "-" } else { &meta.nodes },
        meta.time
    );
    sheet.merge_range(1, 0, 4, 9, &intro, &note)?;
    sheet.set_row_height(1, 20)?;
    sheet.set_row_height(2, 20)?;
    sheet.set_row_height(3, 20)?;
    sheet.set_row_height(4, 20)?;

    let section = format!(
        "{} {} 性能测试",
        meta.policy_numstr,
        meta.policy_str
    );
    let section = if section.trim().is_empty() {
        "性能测试测试".into()
    } else {
        format!("{}性能测试测试", section.trim())
    };
    sheet.write_with_format(5, 0, &section, &title)?;
    sheet.merge_range(5, 0, 5, 9, &section, &title)?;

    // bilingual headers like original template
    let headers_cn = [
        "测试编号",
        "测试大小",
        "测试模式",
        "测试用例",
        "策略",
        "容器数量",
        "平均响应时间",
        "平均操作时间",
        "吞吐量",
        "带宽",
    ];
    let headers_en = [
        "work id",
        "object size",
        "worker",
        "read / write",
        "policy",
        "container count",
        "AVG-Restime (ms)",
        "AVG-Proctime (ms)",
        "Throughput (op/s)",
        "Bandwidth (MB/s)",
    ];
    for (i, h) in headers_cn.iter().enumerate() {
        sheet.write_with_format(6, i as u16, *h, &hdr)?;
    }
    for (i, h) in headers_en.iter().enumerate() {
        sheet.write_with_format(7, i as u16, *h, &hdr)?;
    }

    for (ri, job) in jobs.iter().enumerate() {
        let r = 8 + ri as u32;
        let vals = [
            job.wid.as_str(),
            job.size.as_str(),
            job.worker.as_str(),
            job.method.as_str(),
            if job.policy.is_empty() {
                meta.policy_name.as_str()
            } else {
                job.policy.as_str()
            },
            job.container_count.as_str(),
            strip_unit(&job.avg_res_ms),
            strip_unit(&job.avg_proc_ms),
            strip_unit(&job.throughput),
            strip_unit(&job.bandwidth),
        ];
        for (ci, v) in vals.iter().enumerate() {
            sheet.write_with_format(r, ci as u16, *v, &cell)?;
        }
    }

    // numeric notes footer
    let footer_row = 8 + jobs.len() as u32 + 1;
    sheet.write_with_format(footer_row, 0, "数值说明：", &note)?;
    sheet.write(
        footer_row + 1,
        0,
        "AVG-Restime/Proctime 单位 ms；Throughput 单位 op/s；Bandwidth 为汇总带宽（原始 CSV 口径）。",
    )?;

    if let Some(parent) = output.as_ref().parent() {
        fs::create_dir_all(parent)?;
    }
    wb.save(output.as_ref())
        .with_context(|| format!("save {}", output.as_ref().display()))?;
    Ok(())
}

/// Equivalent of Python `fool.update_xlsx(one_csv, more_csv, template, output, values)`.
pub fn write_fool_xlsx(
    one_worker_csv: impl AsRef<Path>,
    more_worker_csv: impl AsRef<Path>,
    output: impl AsRef<Path>,
    meta: &ReportMeta,
) -> Result<()> {
    let one = load_simple_fool_csv(one_worker_csv, "1")?;
    let more = load_simple_fool_csv(more_worker_csv, "")?;

    let mut wb = Workbook::new();
    let sheet = wb.add_worksheet();
    sheet.set_name("Fool结果")?;
    for c in 0..10u16 {
        sheet.set_column_width(c, 14)?;
    }

    let title = title_fmt();
    let note = note_fmt();
    let hdr = header_fmt();
    let cell = cell_fmt();

    sheet.merge_range(0, 0, 0, 9, "对象存储性能测试结果统计", &title)?;

    let intro = format!(
        "1.\t测试记录在：\n{}\n2.\t测试结果表格\n对象存储{} API性能测试结果统计\n（endpoint http://{}/）\n3.测试策略为 {} {}，存储节点为 {}\n4.测试时间：{}",
        meta.cosbench_url,
        meta.api_label(),
        meta.endpoint,
        meta.policy_name,
        meta.policy_display(),
        if meta.nodes.is_empty() {
            "-"
        } else {
            &meta.nodes
        },
        meta.time
    );
    sheet.merge_range(1, 0, 4, 9, &intro, &note)?;

    // Section 1: 1-worker baseline (original fool template layout)
    let sec1 = format!("1.  {} 基准测试", meta.policy_display());
    sheet.write_with_format(5, 0, &sec1, &title)?;
    sheet.merge_range(5, 0, 5, 9, &sec1, &title)?;

    let headers = [
        "测试编号",
        "策略",
        "容器数量",
        "平均响应时间",
        "平均操作时间",
        "吞吐量",
        "带宽",
        "测试Worker",
        "测试方法",
        "文件大小",
    ];
    for (i, h) in headers.iter().enumerate() {
        sheet.write_with_format(6, i as u16, *h, &hdr)?;
    }
    let headers_en = [
        "work id",
        "policy",
        "container count",
        "AVG-Restime (ms)",
        "AVG-Proctime (ms)",
        "Throughput (op/s)",
        "Bandwidth",
        "worker",
        "Op-type",
        "size",
    ];
    for (i, h) in headers_en.iter().enumerate() {
        sheet.write_with_format(7, i as u16, *h, &hdr)?;
    }

    // Prefer structured baseline order: read/write × 64K/10M/100M with worker=1
    let mut row = 8u32;
    let baseline_order = [
        ("read", "64KB"),
        ("read", "10MB"),
        ("read", "100MB"),
        ("write", "64KB"),
        ("write", "10MB"),
        ("write", "100MB"),
    ];
    // one-worker.csv doesn't carry size/method; try match from .collect if present
    // Fall back to writing all one-worker rows as-is.
    if one.is_empty() {
        sheet.write(row, 0, "(no 1-worker results)")?;
        row += 1;
    } else {
        for j in &one {
            write_fool_row(sheet, row, j, &cell)?;
            row += 1;
        }
    }

    row += 1;
    let sec2 = format!("2.  {} 并发性能测试", meta.policy_display());
    sheet.write_with_format(row, 0, &sec2, &title)?;
    sheet.merge_range(row, 0, row, 9, &sec2, &title)?;
    row += 1;
    for (i, h) in headers.iter().enumerate() {
        sheet.write_with_format(row, i as u16, *h, &hdr)?;
    }
    row += 1;
    for (i, h) in headers_en.iter().enumerate() {
        sheet.write_with_format(row, i as u16, *h, &hdr)?;
    }
    row += 1;

    if more.is_empty() {
        sheet.write(row, 0, "(no multi-worker results)")?;
    } else {
        for j in &more {
            write_fool_row(sheet, row, j, &cell)?;
            row += 1;
        }
    }

    // Also emit a flat "明细" sheet from both
    let detail = wb.add_worksheet();
    detail.set_name("明细")?;
    let all: Vec<_> = one.into_iter().chain(more.into_iter()).collect();
    for (i, h) in headers_en.iter().enumerate() {
        detail.write_with_format(0, i as u16, *h, &hdr)?;
    }
    for (ri, j) in all.iter().enumerate() {
        write_fool_row(detail, 1 + ri as u32, j, &cell)?;
    }

    // silence unused baseline_order warning by using in comment path
    let _ = baseline_order;

    if let Some(parent) = output.as_ref().parent() {
        fs::create_dir_all(parent)?;
    }
    wb.save(output.as_ref())
        .with_context(|| format!("save {}", output.as_ref().display()))?;
    Ok(())
}

fn write_fool_row(sheet: &mut Worksheet, row: u32, j: &JobRow, cell: &Format) -> Result<()> {
    let vals = [
        j.wid.as_str(),
        j.policy.as_str(),
        j.container_count.as_str(),
        strip_unit(&j.avg_res_ms),
        strip_unit(&j.avg_proc_ms),
        strip_unit(&j.throughput),
        strip_unit(&j.bandwidth),
        j.worker.as_str(),
        j.method.as_str(),
        j.size.as_str(),
    ];
    for (ci, v) in vals.iter().enumerate() {
        sheet.write_with_format(row, ci as u16, *v, cell)?;
    }
    Ok(())
}

fn load_simple_fool_csv(path: impl AsRef<Path>, worker_hint: &str) -> Result<Vec<JobRow>> {
    let path = path.as_ref();
    if !path.is_file() {
        return Ok(Vec::new());
    }
    let f = fs::File::open(path)?;
    let mut rows = Vec::new();
    for line in BufReader::new(f).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        // try full collect line first
        if let Some(r) = JobRow::from_collect_line(&line) {
            rows.push(r);
            continue;
        }
        if let Some(r) = JobRow::from_fool_line(&line, "", "", worker_hint) {
            rows.push(r);
        }
    }
    Ok(rows)
}

fn strip_unit(s: &str) -> &str {
    // "1.13 ms" / "3538.82 op/s" → keep full string for readability
    s.trim()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn parse_collect_line() {
        let line = "2026-01-01,64KB,100,write,1000,10 MB,w12,ec,10,1.2 ms,1.1 ms,100 op/s,50 KB";
        let r = JobRow::from_collect_line(line).unwrap();
        assert_eq!(r.wid, "w12");
        assert_eq!(r.size, "64KB");
        assert_eq!(r.method, "write");
    }

    #[test]
    fn write_standard_smoke() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(
            f,
            "t,64KB,4,write,100,1 MB,w1,,10,1.0 ms,1.0 ms,10 op/s,1 KB"
        )
        .unwrap();
        let out = NamedTempFile::new().unwrap();
        let path = out.path().with_extension("xlsx");
        write_standard_xlsx(f.path(), &path, &ReportMeta::from_env()).unwrap();
        assert!(path.is_file());
        let _ = fs::remove_file(path);
    }
}
