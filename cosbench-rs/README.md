# cosbench-rs v1.0

Rust rewrite of [intel-cloud/cosbench](https://github.com/intel-cloud/cosbench) core engine.

## GitHub

| Project | Location |
|---------|----------|
| **Rust (this repo)** | https://github.com/0smboy/myfile **main** (rename to `cosbench-rs` in GitHub Settings if you want) |
| Mirror | https://github.com/0smboy/testone/tree/cosbench-rs |
| Java maintained | https://github.com/0smboy/testone/tree/cosbench-maintained |

> PAT cannot create new repository names; `myfile` is the dedicated published home.

## Features

- mock / **S3** (multipart, range GET, path-style) / **Swift** (Keystone token)
- Keystone v3 auth (domain name/id)
- sequential prepare/cleanup, hash integrity (u64-safe)
- JSON/CSV reports
- per-stage timeline sampling (throughput, bandwidth, latency percentiles over time)
- self-contained HTML report with inline SVG charts (`report` subcommand)
- HTTP control plane + dashboard (`serve`), with an HTML run-detail view at `/runs/{id}`
- COSBench XML subset import

## Commands

```bash
cargo test --workspace
cargo build --release -p cosbench-cli
./target/release/cosbench-rs run -c examples/mock-mixed.yaml --report-dir reports
./target/release/cosbench-rs report -i reports -o reports/report.html
./target/release/cosbench-rs import-xml -i examples/sample-cosbench.xml -o /tmp/w.yaml
./target/release/cosbench-rs serve --bind 0.0.0.0:8080
```

The workspace pins a Rust toolchain in `rust-toolchain.toml`; the locked AWS
SDK crates require rustc 1.94.1 or newer.

## Timeline sampling

Every stage aggregates completed operations into fixed time buckets while it
runs. Bucket width is set per workload:

```yaml
name: my-workload
sample_interval_secs: 5   # optional; default 5, clamped to 1..=60
```

Each bucket records, per operation type: ok count, fail count, bytes moved,
and latency percentiles (p50/p95/p99, nearest-rank over the bucket's samples).
Bucketing happens in a collector task fed by a channel, so the worker hot path
only pays for one non-blocking send per op. Memory is bounded: at most 100 000
latency samples are kept per (bucket, op), and older buckets are finalized
into counters while the stage is still running.

With `run --report-dir <dir>`, each stage writes `<dir>/timeline-<stage>.csv`
at full resolution:

```
t_offset_secs,op,ok,fail,ops_per_sec,mbytes_per_sec,p50_ms,p95_ms,p99_ms
```

`t_offset_secs` is the bucket start relative to stage start; `mbytes_per_sec`
is MiB/s (1024 * 1024 bytes). Rates for the trailing partial bucket use its
actual width. The run's JSON report embeds the same data under a top-level
`"timeline"` key (per stage), downsampled to at most 400 points per op series
by merging adjacent buckets (counts summed, rates recomputed; percentiles are
count-weighted averages when merged, so treat downsampled percentiles as a
display approximation and use the CSV for exact values).

## HTML report

```bash
cosbench-rs report -i <run-report.json | report-dir> -o report.html
```

Renders one self-contained HTML file: run metadata, a per-stage summary
table, and inline SVG line charts per stage (throughput per op type,
bandwidth per op type, and p50/p95/p99 latency per op type over time). No
external assets, no scripts; the file works offline and can be attached to
tickets or mail. When `-i` is a directory, the most recently modified JSON
that parses as a run report is used.

The `serve` dashboard renders the same charts server-side (same Rust module)
for finished runs at `/runs/{id}`; the index page links there when a
submitted workload completes.
