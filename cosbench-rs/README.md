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
- HTTP control plane + dashboard (`serve`)
- COSBench XML subset import

## Commands

```bash
cargo test --workspace
cargo build --release -p cosbench-cli
./target/release/cosbench-rs run -c examples/mock-mixed.yaml --report-dir reports
./target/release/cosbench-rs import-xml -i examples/sample-cosbench.xml -o /tmp/w.yaml
./target/release/cosbench-rs serve --bind 0.0.0.0:8080
```
