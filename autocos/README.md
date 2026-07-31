# autocos

Benchmark automation for object-storage clusters. autocos turns a task name
like `64KB_write_100` into a full benchmark run — workload generation,
submission, a progress bar, result collection — and turns finished runs into
CSV and Excel reports.

- Runs benchmarks via **cosbench-rs** (embedded engine) by default
- Optionally talks to a Java COSBench controller (`--backend java`)
- Drives Swift directly (`--backend swift`, tempauth via `ST_AUTH`/`ST_USER`/`ST_KEY`)
- Stores state under `~/.autocos/`
- `collect` writes a CSV plus a formatted `.xlsx` report with embedded charts

## Install (on the bench node)

```bash
cd autocos
cargo build --release
install -m 755 target/release/autocos /usr/local/bin/autocos
```

## Environment

S3 credentials from env or `~/.s3cfg`:

```bash
export accesskey=...
export secretkey=...
export endpoint=127.0.0.1:9000   # host[:port], no scheme required
```

Swift credentials (used when set — the report then labels the run as Swift API):

```bash
export ST_AUTH=http://127.0.0.1:8080/auth/v1.0
export ST_USER=test:tester
export ST_KEY=testing
```

## Examples

```bash
autocos run 64KB_write_20
autocos run 64KB_read_100 --runtime 60
autocos run fool                    # full suite
autocos run fool --start-task 64KB_write_100
autocos list
autocos list fool
autocos remove w0001
autocos collect                     # CSV + Excel report under ~/.autocos/report/
```

## Task name format

`<size>_<read|write>_<workers>` e.g. `64KB_write_100`, `10MB_read_50`, `100MB_write_15`.

## Reports

`autocos collect` (and the fool suite on completion) writes:

- `collect-<stamp>.csv` — one row per finished run
- `report-<stamp>.xlsx` — a formatted workbook: run matrix with bilingual
  headers, plus a chart sheet with throughput, bandwidth, and latency charts
  across every case, so a finished sweep reads as pictures rather than a wall
  of numbers
