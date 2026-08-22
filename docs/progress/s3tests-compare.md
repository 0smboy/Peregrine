# s3-tests compare: Python SAIO (Swift1 :8090) vs Rust SAIO (Swift2 :8081)

Date: 2026-08-21. Suite: Ceph `s3tests/functional/test_s3.py --assert=plain`.
Collect-only on Rust: **838**. Unique testcase names in both JUnit files: **838** (complete overlap, 0 only-py / 0 only-rs).

Do **not** treat this as GREEN. Do **not** pad to 838.

## Environment (not equivalent)

| | Python SAIO Swift1 | Rust SAIO Swift2 |
|---|---|---|
| conf | `/etc/pyswift` | `/etc/rsaio` |
| proxy | `:8090` `workers=2` (3 processes) | `:8081` `workers=64` (1 process, ~67 OS threads) |
| devices | `/srv/node/d1/pysaio` | `/srv/node/d1/rsaio-xfs` |
| binary | pyswift venv | grok-merge Hyper HTTP/1.1; proxy sha `0a2e5f16…` |
| VIP | untouched | production `/usr/local/bin/swift-proxy-server` still `ab5cb95c…`; `:8080` 200 |

`workers` is not the same resource. Latency is this lab, not a perf bake-off.

## Suite totals (JUnit XML)

| | tests attr | pass | fail | error | skip | wall |
|---|---:|---:|---:|---:|---:|---|
| Python | **838** | **241** | **503** | **0** | **94** | 993.6s |
| Rust | **841** attr / **838** names | **106** | **64** | **670** | **1** | 5827s (1h37m) |

Rust pytest footer (log): `64 failed, 107 passed, 1 skipped, 670 errors in 5827.23s`. XML `pass=106` vs footer `107` — comparison below uses **unique names (838)**.

Discarded: first 6-shard parallel run (852 rows, 851 ListBuckets setup errors). Cause: Hyper path did not call `s3api.handle()`. After intercept deploy, ListBuckets 200; this table is the **single-process** rerun.

## Unique-name comparison (838 ∩ 838)

| | N |
|---|---:|
| both pass | **103** |
| both non-pass (fail/error/skip) | **60** |
| Python pass, Rust not | **138** |
| Rust pass, Python not | **1** (`test_object_write_with_chunked_transfer_encoding`: py fail, rs pass) |

Of the 138 Python-pass/Rust-not:

- **131** setup `botocore.exceptions.ConnectionClosedError` (connection closed before valid response)
- 3 other error
- 4 assertion fail
- 1 ClientError

So the bulk of the Rust gap on tests Python can pass is **connection drop under s3-tests load**, not XML assertion diffs.

## Swift REST dual-feed (function first, then ms)

40 atoms + 1 recapture in `swift-api-diff.jsonl`. Status matched on all atoms except `object: POST meta` rust **000** at 04:37 (proxy rebuild/load). Recapture 04:52: **py 202 / rs 202**. PUT/GET/COPY/range/Expect/chunked/unicode/401/409 all matched.

Timings are not a performance claim (worker models differ).

## Timeouts

- `2026-08-21T04:37:47Z` `object: POST meta` rust 000. Recapture 202/202.
- Rust 838 `timeout 3600` wrapper would have SIGKILL ~05:28; wrapper PID killed at ~40m so pytest could finish. Pytest itself did not hang.

## Files

- `{SCRATCH}/s3tests-python.xml` `s3tests-rust.xml`
- `{SCRATCH}/swift-api-diff.jsonl`
- `{SCRATCH}/timeouts.log`
- `{SCRATCH}/s3-compare-stats.json`
- `{SCRATCH}/progress-10m.log`
