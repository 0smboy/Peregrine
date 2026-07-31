//! End-to-end (offline, mock storage): a short run must produce a timeline
//! with at least 3 buckets, per-stage timeline CSVs, a JSON report with an
//! embedded timeline, and a renderable self-contained HTML report.

use cosbench_core::html_report::render_html;
use cosbench_core::report::{load_report_input, write_timeline_csvs, ReportBundle};
use cosbench_core::{Driver, Workload};
use std::collections::BTreeSet;
use std::path::PathBuf;

const WORKLOAD_YAML: &str = r#"
name: timeline-mock
sample_interval_secs: 1
storage:
  type: mock
  latency_us: 400
stages:
  - name: prepare
    kind: prepare
    workers: 4
    total_ops: 40
    sequential: true
    operations:
      - type: write
        ratio: 100
    objects:
      cprefix: b
      containers: { start: 1, end: 1 }
      oprefix: o
      objects: { start: 1, end: 40 }
      size: 8192
      hash_check: true
  - name: main
    workers: 4
    runtime_secs: 4
    operations:
      - type: read
        ratio: 60
      - type: write
        ratio: 40
    objects:
      cprefix: b
      containers: { start: 1, end: 1 }
      oprefix: o
      objects: { start: 1, end: 40 }
      size: 8192
      hash_check: true
"#;

#[tokio::test]
async fn mock_run_yields_timeline_csv_json_and_html_report() {
    let wl: Workload = serde_yaml::from_str(WORKLOAD_YAML).unwrap();
    wl.validate().unwrap();
    assert_eq!(wl.sample_interval_secs, 1);

    let reports = Driver::new(wl).run_all().await.unwrap();
    assert_eq!(reports.len(), 2);

    // The 4 s main stage sampled at 1 s must span at least 3 buckets, with
    // both op types present.
    let main = &reports[1];
    let buckets: BTreeSet<u64> = main
        .timeline
        .points
        .iter()
        .map(|p| p.t_offset_secs)
        .collect();
    assert!(
        buckets.len() >= 3,
        "expected >=3 buckets, got {buckets:?}"
    );
    let ops = main.timeline.op_names();
    assert_eq!(ops, vec!["read".to_string(), "write".to_string()]);
    assert_eq!(main.timeline.interval_secs, 1);
    let sampled: u64 = main.timeline.points.iter().map(|p| p.ok + p.fail).sum();
    assert_eq!(
        sampled,
        main.metrics.ops_ok + main.metrics.ops_fail,
        "every completed op lands in exactly one bucket"
    );

    // Persist everything like `run --report-dir` does.
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("timeline-report-test");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let bundle = ReportBundle::from_stages("timeline-mock", &reports);
    bundle.write_json(dir.join("timeline-mock.json")).unwrap();
    bundle.write_csv(dir.join("timeline-mock.csv")).unwrap();
    let csv_paths = write_timeline_csvs(&dir, &reports).unwrap();
    assert_eq!(csv_paths.len(), 2);

    // Timeline CSV: exact header, and >=3 rows for the write series of main.
    let csv = std::fs::read_to_string(dir.join("timeline-main.csv")).unwrap();
    let mut lines = csv.lines();
    assert_eq!(
        lines.next(),
        Some("t_offset_secs,op,ok,fail,ops_per_sec,mbytes_per_sec,p50_ms,p95_ms,p99_ms")
    );
    let write_rows = csv.lines().filter(|l| l.contains(",write,")).count();
    let read_rows = csv.lines().filter(|l| l.contains(",read,")).count();
    assert!(write_rows >= 3, "write rows: {write_rows}");
    assert!(read_rows >= 3, "read rows: {read_rows}");

    // JSON report embeds the timeline under "timeline".
    let json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("timeline-mock.json")).unwrap())
            .unwrap();
    let points = json["timeline"]["main"]["points"].as_array().unwrap();
    assert!(points.len() >= 6, "points: {}", points.len());
    let json_ops: BTreeSet<&str> = points
        .iter()
        .map(|p| p["op"].as_str().unwrap())
        .collect();
    assert!(json_ops.contains("read") && json_ops.contains("write"));
    // Existing summary fields are still present (backward compatibility).
    assert!(json["stages"][1]["ops_ok"].as_u64().unwrap() > 0);

    // HTML report: load the report back the way the CLI subcommand does,
    // render, and check the expected series are charted.
    let (src, loaded) = load_report_input(&dir).unwrap();
    assert!(src.ends_with("timeline-mock.json"));
    let html = render_html(&loaded);
    let html_path = dir.join("report.html");
    std::fs::write(&html_path, &html).unwrap();

    assert!(html.contains("<svg"));
    assert!(html.contains("throughput (ops/s)"));
    assert!(html.contains("bandwidth (MiB/s)"));
    assert!(html.contains("latency: read (ms)"));
    assert!(html.contains("latency: write (ms)"));
    assert!(html.contains("stage: prepare"));
    assert!(html.contains("stage: main"));
    assert!(!html.contains("<script"));
    assert!(
        std::fs::metadata(&html_path).unwrap().len() > 5_000,
        "report.html should be a substantial document"
    );
}
