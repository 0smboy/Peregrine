//! Excel report generation: a formatted workbook per collect, with a chart
//! sheet so a finished sweep reads as pictures rather than a wall of numbers.
//!
//! Two layouts: the standard report (one row per run) and the fool-suite
//! report (1-worker baseline section plus the concurrency matrix). Both are
//! built with rust_xlsxwriter — no template files, nothing external.

use anyhow::{bail, Context, Result};
use chrono::Local;
use rust_xlsxwriter::{
    Chart, ChartType, Format, FormatAlign, FormatBorder, Workbook, Worksheet,
};
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
            policy_name: std::env::var("AUTOCOS_POLICY").unwrap_or_default(),
            policy_numstr: std::env::var("AUTOCOS_POLICY_NUM").unwrap_or_default(),
            policy_str: std::env::var("AUTOCOS_POLICY_STR").unwrap_or_default(),
            nodes: std::env::var("AUTOCOS_STORAGE_NODES").unwrap_or_default(),
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

/// One result row (the fields autocos list / .collect carry).
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

/// The standard report: one formatted sheet, one row per run, plus charts.
pub fn write_standard_xlsx(
    collect_path: impl AsRef<Path>,
    output: impl AsRef<Path>,
    meta: &ReportMeta,
) -> Result<()> {
    let jobs = load_collect_file(collect_path)?;
    if jobs.is_empty() {
        bail!("no rows in collect file — run some tasks and `autocos list` first");
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

    // bilingual headers
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

    // Column K (index 10) holds a short category label for the chart sheet —
    // size + op + workers — so the axes stay readable without inventing a
    // second table of numbers.
    sheet.set_column_width(10, 22)?;
    sheet.write_with_format(6, 10, "图表标签", &hdr)?;
    sheet.write_with_format(7, 10, "chart label", &hdr)?;

    let first = 8u32;
    let last = 8 + jobs.len() as u32 - 1;
    for (ri, job) in jobs.iter().enumerate() {
        let r = first + ri as u32;
        let policy = if job.policy.is_empty() {
            meta.policy_name.as_str()
        } else {
            job.policy.as_str()
        };
        let label = format!("{} {} ×{}", job.size, job.method, job.worker);
        sheet.write_with_format(r, 0, job.wid.as_str(), &cell)?;
        sheet.write_with_format(r, 1, job.size.as_str(), &cell)?;
        sheet.write_with_format(r, 2, job.worker.as_str(), &cell)?;
        sheet.write_with_format(r, 3, job.method.as_str(), &cell)?;
        sheet.write_with_format(r, 4, policy, &cell)?;
        sheet.write_with_format(r, 5, job.container_count.as_str(), &cell)?;
        // Metric columns as numbers so Excel charts can plot them.
        write_num(sheet, r, 6, &job.avg_res_ms, &cell)?;
        write_num(sheet, r, 7, &job.avg_proc_ms, &cell)?;
        write_num(sheet, r, 8, &job.throughput, &cell)?;
        write_num(sheet, r, 9, &job.bandwidth, &cell)?;
        sheet.write_with_format(r, 10, label.as_str(), &cell)?;
    }

    // numeric notes footer
    let footer_row = last + 2;
    sheet.write_with_format(footer_row, 0, "数值说明：", &note)?;
    sheet.write(
        footer_row + 1,
        0,
        "AVG-Restime/Proctime 单位 ms；Throughput 单位 op/s；Bandwidth 为数值（原始 CSV 口径，单位以表头为准）。",
    )?;

    // Chart sheet: three column charts over the same numeric columns.
    let charts = wb.add_worksheet();
    charts.set_name("图表")?;
    charts.write_with_format(0, 0, "性能测试图表（与「性能测试结果」同一批数据）", &title)?;
    charts.merge_range(0, 0, 0, 8, "性能测试图表（与「性能测试结果」同一批数据）", &title)?;
    charts.write(
        1,
        0,
        "下方三张图分别画出吞吐量、带宽、平均响应时间。类别轴是每行的「图表标签」。",
    )?;

    let data_sheet = "性能测试结果";
    let cats = (data_sheet, first, 10u16, last, 10u16);
    insert_column_chart(
        charts,
        3,
        0,
        "吞吐量 (op/s)",
        "op/s",
        cats,
        (data_sheet, first, 8, last, 8),
    )?;
    insert_column_chart(
        charts,
        20,
        0,
        "带宽",
        "bandwidth",
        cats,
        (data_sheet, first, 9, last, 9),
    )?;
    insert_column_chart(
        charts,
        37,
        0,
        "平均响应时间 (ms)",
        "ms",
        cats,
        (data_sheet, first, 6, last, 6),
    )?;

    if let Some(parent) = output.as_ref().parent() {
        fs::create_dir_all(parent)?;
    }
    wb.save(output.as_ref())
        .with_context(|| format!("save {}", output.as_ref().display()))?;
    Ok(())
}

/// The fool-suite report: 1-worker baseline, concurrency matrix, detail sheet.
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

    // Section 1: 1-worker baseline
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
    sheet.write_with_format(row, 0, j.wid.as_str(), cell)?;
    sheet.write_with_format(row, 1, j.policy.as_str(), cell)?;
    sheet.write_with_format(row, 2, j.container_count.as_str(), cell)?;
    write_num(sheet, row, 3, &j.avg_res_ms, cell)?;
    write_num(sheet, row, 4, &j.avg_proc_ms, cell)?;
    write_num(sheet, row, 5, &j.throughput, cell)?;
    write_num(sheet, row, 6, &j.bandwidth, cell)?;
    sheet.write_with_format(row, 7, j.worker.as_str(), cell)?;
    sheet.write_with_format(row, 8, j.method.as_str(), cell)?;
    sheet.write_with_format(row, 9, j.size.as_str(), cell)?;
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

/// Pull the leading number out of strings like `"1.13 ms"` / `"3538.82 op/s"`.
fn parse_num(s: &str) -> Option<f64> {
    let t = s.trim();
    if t.is_empty() {
        return None;
    }
    let end = t
        .char_indices()
        .find(|(_, c)| !(c.is_ascii_digit() || *c == '.' || *c == '-' || *c == '+' || *c == 'e' || *c == 'E'))
        .map(|(i, _)| i)
        .unwrap_or(t.len());
    t[..end].parse().ok()
}

fn write_num(sheet: &mut Worksheet, row: u32, col: u16, raw: &str, fmt: &Format) -> Result<()> {
    if let Some(n) = parse_num(raw) {
        sheet.write_with_format(row, col, n, fmt)?;
    } else {
        sheet.write_with_format(row, col, strip_unit(raw), fmt)?;
    }
    Ok(())
}

fn insert_column_chart(
    sheet: &mut Worksheet,
    row: u32,
    col: u16,
    title: &str,
    y_name: &str,
    categories: (&str, u32, u16, u32, u16),
    values: (&str, u32, u16, u32, u16),
) -> Result<()> {
    let mut chart = Chart::new(ChartType::Column);
    chart.title().set_name(title);
    chart.x_axis().set_name("case");
    chart.y_axis().set_name(y_name);
    chart
        .add_series()
        .set_categories(categories)
        .set_values(values)
        .set_name(title);
    sheet.insert_chart(row, col, &chart)?;
    Ok(())
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
        writeln!(
            f,
            "t,1MB,8,read,200,2 MB,w2,,10,2.5 ms,2.0 ms,80 op/s,40 KB"
        )
        .unwrap();
        let out = NamedTempFile::new().unwrap();
        let path = out.path().with_extension("xlsx");
        write_standard_xlsx(f.path(), &path, &ReportMeta::from_env()).unwrap();
        let meta = fs::metadata(&path).unwrap();
        // A bare table is a few KB; three embedded charts push it well past that.
        assert!(meta.len() > 8_000, "xlsx too small to hold charts: {} bytes", meta.len());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn parse_num_strips_units() {
        assert_eq!(parse_num("1.13 ms"), Some(1.13));
        assert_eq!(parse_num("3538.82 op/s"), Some(3538.82));
        assert_eq!(parse_num("  50 "), Some(50.0));
        assert_eq!(parse_num(""), None);
    }
}
