//! Self-contained HTML run report.
//!
//! One output file, no scripts, no external assets: metadata header,
//! per-stage summary table, and inline SVG charts (throughput, bandwidth,
//! latency percentiles over time) rendered from the embedded timeline.
//! Used by both the `report` CLI subcommand and the `serve` run-detail view.

use crate::report::{ReportBundle, StageReportJson};
use crate::svgchart::{line_chart_svg, ChartSpec, Series, PERCENTILE_COLORS};
use crate::timeline::StageTimeline;

const CSS: &str = "\
:root { color-scheme: light; }\n\
body { margin: 2.4rem auto 4rem; max-width: 960px; padding: 0 1.6rem; background: #ffffff;\n\
  color: #1c1c1a; font: 14px/1.55 -apple-system, 'Segoe UI', 'Helvetica Neue', Arial, sans-serif; }\n\
h1 { font-size: 21px; font-weight: 600; margin: 0 0 4px; }\n\
h2 { font-size: 16px; font-weight: 600; margin: 2.4rem 0 0.4rem; }\n\
p { margin: 0.4rem 0; }\n\
.quiet { color: #55554f; }\n\
table { border-collapse: collapse; margin: 0.7rem 0 1rem; font-size: 13px; }\n\
th, td { border: 1px solid #cfcfc8; padding: 0.3rem 0.55rem; text-align: left; }\n\
th { background: #f3f3ee; font-weight: 600; }\n\
td.n { text-align: right; font-variant-numeric: tabular-nums;\n\
  font-family: ui-monospace, 'SF Mono', Menlo, Consolas, monospace; font-size: 12.5px; }\n\
svg { display: block; margin: 0.9rem 0 1.1rem; max-width: 100%; height: auto; }\n\
ul.errors { margin: 0.3rem 0 0.8rem 1.2rem; padding: 0; }\n\
ul.errors li { margin: 0.15rem 0; }\n\
code { font-family: ui-monospace, 'SF Mono', Menlo, Consolas, monospace; font-size: 12.5px; }\n\
";

/// Escape text for use in HTML (and SVG) element content and attributes.
pub fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn fmt_bytes(b: u64) -> String {
    const KIB: f64 = 1024.0;
    let b = b as f64;
    if b >= KIB * KIB * KIB {
        format!("{:.2} GiB", b / (KIB * KIB * KIB))
    } else if b >= KIB * KIB {
        format!("{:.2} MiB", b / (KIB * KIB))
    } else if b >= KIB {
        format!("{:.1} KiB", b / KIB)
    } else {
        format!("{b:.0} B")
    }
}

/// Render the whole run report as one self-contained HTML document.
pub fn render_html(bundle: &ReportBundle) -> String {
    let mut b = String::with_capacity(96 * 1024);
    b.push_str("<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
    b.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
    b.push_str(&format!(
        "<title>{}: run report</title>\n",
        escape_html(&bundle.workload)
    ));
    b.push_str("<style>\n");
    b.push_str(CSS);
    b.push_str("</style>\n</head>\n<body>\n");

    b.push_str("<h1>cosbench-rs run report</h1>\n");
    let total_ok: u64 = bundle.stages.iter().map(|s| s.ops_ok).sum();
    let total_fail: u64 = bundle.stages.iter().map(|s| s.ops_fail).sum();
    let total_bytes: u64 = bundle.stages.iter().map(|s| s.bytes).sum();
    b.push_str(&format!(
        "<p class=\"quiet\">workload {}, generated {}, {} stage(s), \
         {} ops ok, {} failed, {} moved.</p>\n",
        escape_html(&bundle.workload),
        escape_html(&bundle.generated_at),
        bundle.stages.len(),
        total_ok,
        total_fail,
        fmt_bytes(total_bytes)
    ));

    // Per-stage summary table.
    b.push_str("<table>\n<tr><th>stage</th><th>elapsed s</th><th>ok</th><th>fail</th>\
        <th>success</th><th>ops/s</th><th>MiB/s</th><th>p50 ms</th><th>p95 ms</th>\
        <th>p99 ms</th><th>mean ms</th><th>bytes</th></tr>\n");
    for s in &bundle.stages {
        b.push_str(&summary_row(s));
    }
    b.push_str("</table>\n");

    for s in &bundle.stages {
        b.push_str(&format!("<h2>stage: {}</h2>\n", escape_html(&s.name)));
        match bundle.timeline.get(&s.name) {
            Some(tl) if !tl.points.is_empty() => {
                b.push_str(&format!(
                    "<p class=\"quiet\">timeline: {} s buckets, {} row(s).</p>\n",
                    tl.interval_secs,
                    tl.points.len()
                ));
                b.push_str(&stage_charts(tl));
            }
            _ => {
                b.push_str("<p class=\"quiet\">no timeline samples recorded.</p>\n");
            }
        }
        if !s.sample_errors.is_empty() {
            b.push_str(&format!(
                "<p class=\"quiet\">sample errors ({} shown):</p>\n<ul class=\"errors\">\n",
                s.sample_errors.len().min(5)
            ));
            for e in s.sample_errors.iter().take(5) {
                b.push_str(&format!("<li><code>{}</code></li>\n", escape_html(e)));
            }
            b.push_str("</ul>\n");
        }
    }

    b.push_str(&format!(
        "<p class=\"quiet\">cosbench-rs {}</p>\n",
        env!("CARGO_PKG_VERSION")
    ));
    b.push_str("</body>\n</html>\n");
    b
}

fn summary_row(s: &StageReportJson) -> String {
    format!(
        "<tr><td>{}</td><td class=\"n\">{:.2}</td><td class=\"n\">{}</td><td class=\"n\">{}</td>\
         <td class=\"n\">{:.2}%</td><td class=\"n\">{:.1}</td><td class=\"n\">{:.2}</td>\
         <td class=\"n\">{:.2}</td><td class=\"n\">{:.2}</td><td class=\"n\">{:.2}</td>\
         <td class=\"n\">{:.2}</td><td class=\"n\">{}</td></tr>\n",
        escape_html(&s.name),
        s.elapsed_secs,
        s.ops_ok,
        s.ops_fail,
        s.success_ratio * 100.0,
        s.throughput_ops,
        s.bandwidth_mib_s,
        s.lat_p50_us as f64 / 1000.0,
        s.lat_p95_us as f64 / 1000.0,
        s.lat_p99_us as f64 / 1000.0,
        s.lat_mean_us / 1000.0,
        fmt_bytes(s.bytes)
    )
}

/// Throughput, bandwidth and latency percentile charts for one stage.
fn stage_charts(tl: &StageTimeline) -> String {
    let ops = tl.op_names();
    let x_label = "time (s)".to_string();
    let mut out = String::new();

    let series_of = |f: &dyn Fn(&crate::timeline::TimelinePoint) -> f64| -> Vec<Series> {
        ops.iter()
            .map(|op| Series {
                name: op.clone(),
                points: tl
                    .op_points(op)
                    .iter()
                    .map(|p| (p.t_offset_secs as f64, f(p)))
                    .collect(),
            })
            .collect()
    };

    out.push_str(&line_chart_svg(&ChartSpec {
        title: "throughput (ops/s)".into(),
        y_unit: "ops/s".into(),
        x_label: x_label.clone(),
        series: series_of(&|p| p.ops_per_sec),
        palette: vec![],
    }));

    out.push_str(&line_chart_svg(&ChartSpec {
        title: "bandwidth (MiB/s)".into(),
        y_unit: "MiB/s".into(),
        x_label: x_label.clone(),
        series: series_of(&|p| p.mbytes_per_sec),
        palette: vec![],
    }));

    for op in &ops {
        let pts = tl.op_points(op);
        let lat_series = |pick: &dyn Fn(&crate::timeline::TimelinePoint) -> f64, name: &str| Series {
            name: name.to_string(),
            points: pts.iter().map(|p| (p.t_offset_secs as f64, pick(p))).collect(),
        };
        out.push_str(&line_chart_svg(&ChartSpec {
            title: format!("latency: {op} (ms)"),
            y_unit: "ms".into(),
            x_label: x_label.clone(),
            series: vec![
                lat_series(&|p| p.p50_ms, "p50"),
                lat_series(&|p| p.p95_ms, "p95"),
                lat_series(&|p| p.p99_ms, "p99"),
            ],
            palette: PERCENTILE_COLORS.to_vec(),
        }));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::timeline::TimelinePoint;
    use std::collections::BTreeMap;

    fn point(t: u64, op: &str, ops_s: f64) -> TimelinePoint {
        TimelinePoint {
            t_offset_secs: t,
            op: op.into(),
            ok: 10,
            fail: 0,
            bytes: 1024,
            dur_secs: 5.0,
            ops_per_sec: ops_s,
            mbytes_per_sec: 0.5,
            p50_ms: 2.0,
            p95_ms: 4.0,
            p99_ms: 8.0,
        }
    }

    #[test]
    fn report_contains_tables_and_charts() {
        let mut timeline = BTreeMap::new();
        timeline.insert(
            "main".to_string(),
            StageTimeline {
                interval_secs: 5,
                points: vec![
                    point(0, "read", 20.0),
                    point(0, "write", 10.0),
                    point(5, "read", 22.0),
                    point(5, "write", 12.0),
                ],
            },
        );
        let bundle = ReportBundle {
            workload: "w&1".into(),
            generated_at: "2026-07-31T00:00:00Z".into(),
            stages: vec![StageReportJson {
                name: "main".into(),
                elapsed_secs: 10.0,
                ops_ok: 320,
                ops_fail: 1,
                bytes: 4096,
                success_ratio: 320.0 / 321.0,
                throughput_ops: 32.1,
                bandwidth_mib_s: 0.4,
                lat_p50_us: 2_000,
                lat_p95_us: 4_000,
                lat_p99_us: 8_000,
                lat_mean_us: 2_500.0,
                sample_errors: vec!["boom <tag>".into()],
            }],
            timeline,
        };
        let html = render_html(&bundle);
        assert!(html.starts_with("<!doctype html>"));
        assert!(html.contains("w&amp;1"));
        assert!(html.contains("stage: main"));
        // Three chart kinds: throughput + bandwidth + one latency chart per op.
        assert_eq!(html.matches("<svg").count(), 4);
        assert!(html.contains("throughput (ops/s)"));
        assert!(html.contains("bandwidth (MiB/s)"));
        assert!(html.contains("latency: read (ms)"));
        assert!(html.contains("latency: write (ms)"));
        assert!(html.contains("boom &lt;tag&gt;"));
        // Self-contained: no scripts, no external references.
        assert!(!html.contains("<script"));
        assert!(!html.contains("http://"));
        assert!(!html.contains("https://"));
    }

    #[test]
    fn missing_timeline_is_reported_plainly() {
        let bundle = ReportBundle {
            workload: "w".into(),
            generated_at: "t".into(),
            stages: vec![StageReportJson {
                name: "main".into(),
                elapsed_secs: 1.0,
                ops_ok: 1,
                ops_fail: 0,
                bytes: 0,
                success_ratio: 1.0,
                throughput_ops: 1.0,
                bandwidth_mib_s: 0.0,
                lat_p50_us: 1,
                lat_p95_us: 1,
                lat_p99_us: 1,
                lat_mean_us: 1.0,
                sample_errors: vec![],
            }],
            timeline: BTreeMap::new(),
        };
        let html = render_html(&bundle);
        assert!(html.contains("no timeline samples recorded"));
    }
}
