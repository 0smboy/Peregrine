use cosbench_core::{Driver, Workload};
use std::io::Write;

#[tokio::test]
async fn mock_mixed_end_to_end() {
    let yaml = r#"
name: e2e
storage:
  type: mock
  latency_us: 0
stages:
  - name: init
    kind: init
    workers: 1
    total_ops: 1
    sequential: true
    operations:
      - type: create_container
        ratio: 100
    objects:
      cprefix: b
      containers: { start: 1, end: 1 }
      oprefix: o
      objects: { start: 1, end: 1 }
      size: 1
  - name: prepare
    kind: prepare
    workers: 4
    total_ops: 50
    sequential: true
    operations:
      - type: write
        ratio: 100
    objects:
      cprefix: b
      containers: { start: 1, end: 1 }
      oprefix: o
      objects: { start: 1, end: 50 }
      size: 1024
      hash_check: true
  - name: main
    workers: 4
    total_ops: 100
    operations:
      - type: read
        ratio: 60
      - type: write
        ratio: 30
      - type: list
        ratio: 10
    objects:
      cprefix: b
      containers: { start: 1, end: 1 }
      oprefix: o
      objects: { start: 1, end: 50 }
      size: 1024
      hash_check: true
"#;
    let p = std::env::temp_dir().join(format!("cosbench-rs-e2e-{}.yaml", std::process::id()));
    {
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(yaml.as_bytes()).unwrap();
    }
    let wl = Workload::from_yaml_file(&p).unwrap();
    let reports = Driver::new(wl).run_all().await.unwrap();
    let _ = std::fs::remove_file(&p);
    assert_eq!(reports.len(), 3);
    assert_eq!(reports[1].metrics.ops_fail, 0, "prepare should be perfect");
    assert!(
        reports[2].metrics.success_ratio > 0.95,
        "main success={}",
        reports[2].metrics.success_ratio
    );
}
