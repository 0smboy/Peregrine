# cabt (Rust)

Rust rewrite of the **x86-64** [cabt](https://github.com/0smboy/cabt) shell automation tool for COSBench.

Originally: bash wrapper that submits COSBench XML workloads, shows a progress bar, lists/collects results.

This rewrite:
- Keeps the same CLI shape: `run` / `list` / `remove` / `collect` / fool suite
- Runs benchmarks via **cosbench-rs** (local engine) by default
- Optionally talks to a Java COSBench controller (`--backend java`)
- Stores state under `~/.cabt/`

## Install (on the bench node)

```bash
cd /root/work/cabt-rs
cargo build --release
install -m 755 target/release/cabt /usr/local/bin/cabt
```

## Environment

S3 credentials from env or `~/.s3cfg`:

```bash
export accesskey=...
export secretkey=...
export endpoint=127.0.0.1:9000   # host[:port], no scheme required
```

## Examples

```bash
cabt run 64KB_write_20
cabt run 64KB_read_100 --runtime 60
cabt run fool                    # full suite
cabt run fool --start-task 64KB_write_100
cabt list
cabt list fool
cabt remove w0001
cabt collect
```

## Task name format

`<size>_<read|write>_<workers>` e.g. `64KB_write_100`, `10MB_read_50`, `100MB_write_15`.
