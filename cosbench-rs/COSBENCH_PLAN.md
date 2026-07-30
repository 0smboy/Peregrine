# COSBench Maintenance + Rust Rewrite Plan

Host: AWS `root@18.232.108.188`  
Date: 2026-07-17  
Upstream: https://github.com/intel-cloud/cosbench (last meaningful release v0.4.2 / 2017; open PRs stale)

## Reality check

1. We **cannot merge into `intel-cloud/cosbench`** (no write access; project effectively unmaintained).
2. Work product lives on this host under `/root/work/`:
   - `cosbench` — Java baseline on branch `maintained/0.4.2-plus` with accepted PR patches integrated.
   - `cosbench-rs` — Rust rewrite of the **core benchmark engine** (not an OSGi/web clone).
3. Full line-by-line port of every OSGi plugin + Freemarker web UI is multi-month and low ROI.  
   Quality bar: correct core ops, solid metrics, S3-compatible storage, tests, clean CLI.

## Phase A — Java fork: PR / issue triage

### Accepted and integrated (`maintained/0.4.2-plus`)

| PR | Title | Decision |
|----|-------|----------|
| #426 | hashCheck gap int overflow >2GB | **Merged** — critical correctness |
| #417 | Remove CORBA (Java 11+) | **Merged** |
| #420 | openio .classpath | **Merged** |
| #418 | oss .classpath | **Merged** |
| #345 | librados sample missing workflow tag | **Merged** |
| #424 | S3 list operation | **Integrated** into S3Storage |
| #351 | S3 range GET | **Integrated** (combined with list) |
| #396 | error stats / Counter / timing | **Selective** core bugfixes only |
| #428 | Keystone v3 | **Applied** (supersedes #421) |
| #416 | equinox launcher upgrade | **Merged** |

### Rejected / deferred (with reason)

| PR | Reason |
|----|--------|
| #421 | Superseded by #428 |
| #410 | Jar-bomb AWS SDK 1.11 swap; idea absorbed in Rust via modern SDK, not Java jar drop |
| #403 / #338 / #310 | Empty/noise titles, stale branches |
| #373 | Kitchen-sink beginner fixes already covered by thatdone PRs + risk of outdated churn |
| #355 | ECS plugin + IntelliJ cleanup — optional vertical, not core |
| #396 full branch | Would pull unrelated adaptors, binary docs, VERSION wars — only bugfixes kept |

### Issues (137 open) — handling policy

| Category | Action |
|----------|--------|
| Bugs with PR (#425→#426, #412→#417, #411→#416, #413/#414, #409→#428, #405→#396) | Fixed in maintained branch |
| Questions / how-to / support (#432, #391, #390, #407, …) | Doc only; not code defects |
| Dead project (#381) | Acknowledged; this fork + Rust rewrite is the path |
| Metric correctness (#435, #366) | Re-implemented carefully in Rust metrics |
| Timeout hang (#434) | Rust: explicit per-op timeouts |
| Multipart / large object (#389, #347, #379) | Rust: u64 sizes + multipart path planned |

## Phase B — Rust rewrite scope (`cosbench-rs`)

### In scope (v0.1)

- Workload config: YAML (primary) + subset mapping from COSBench concepts  
  (stages, workers, runtime/totalOps, ops ratios, size, containers/objects generators)
- Ops: `init`, `prepare`, `write`, `read`, `delete`, `list`, `cleanup`
- Storage: `mock` (tests) + `s3` (AWS SDK / path-style / custom endpoint for Ceph RGW / MinIO)
- Workers: Tokio multi-task concurrency
- Metrics: ops count, bytes, success ratio, latency histogram (hdrhistogram), throughput
- Integrity: optional hash trailer with **u64-safe** gap math (PR #426)
- CLI: `cosbench-rs run -c workload.yaml`
- Tests: unit + mock end-to-end

### Out of scope (v0.1)

- Full OSGi controller/driver split and web UI
- Every legacy adaptor (GCS, CDMI, Amplidata, ECS, OpenIO, …)
- Binary-compatible Freemarker reports

### Absorbed fixes in Rust by design

- All sizes/latencies: `u64` / `Duration` (no int overflow)
- List op first-class
- Range GET optional
- Error aggregation without empty-stacktrace panics
- Monotonic clocks (`Instant`) not wall clock for latency

## Phase C — Quality gates

1. `cargo fmt`, `cargo clippy -D warnings`, `cargo test`
2. Mock workload: prepare → mixed read/write → cleanup
3. Optional: MinIO local if docker available
4. Document mainline paths and how to run

## Deliverable layout

```
/root/work/
  COSBENCH_PLAN.md          # this file
  cosbench/                 # Java maintained fork
  cosbench-rs/              # Rust rewrite (mainline for new work)
```
