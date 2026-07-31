# Testing & verification

Peregrine is verified at four levels, from unit tests up to production-grade
load against a live high-availability cluster.

## 1. Unit + golden (format fidelity)

Every serialized format has a golden-fixture round-trip: the real Python Swift
writes a fixture, `swift-rust` must read it and reproduce it byte-for-byte, and
then Rust writes and Python reads back. The workspace runs ~946 tests.

```sh
cd swift-rust
cargo test --workspace --exclude swift-ec                     # format fidelity
cargo test -p swift-ec -p swift-object-server -p swift-proxy-server \
  --features swift-proxy-server/ec,swift-object-server/ec      # EC (Linux)
cargo clippy --workspace --exclude swift-ec --all-targets -- -D warnings
```

## 2. Functional parity vs the Python oracle

A single parameterized functional suite runs against both a Rust stack and a
Python Swift SAIO, so the two PASS/FAIL tables are a direct parity comparison:
account/container/object CRUD, byte ranges (single, suffix, multipart), swob
conditionals (304/412), SLO and DLO large objects, erasure coding, server-side
copy, expiry, ACLs (public / restricted / revoked), cross-account denial, and
negative/security cases. The harness lives at `swift-rust/tools/func-suite.sh`.

## 3. Performance A/B

`swift-rust/tools/bench.py` drives a concurrent PUT/GET matrix (object sizes ×
concurrency) and reports throughput (ops/s, MB/s) and latency percentiles
(p50/p95/p99). Run it against a Rust SAIO and a Python SAIO on the same host for
an implementation A/B, and against the 4-node cluster for production numbers.
`cosbench-rs` + `autocos` provide COSBench-grade load for larger runs.

## 4. Production, on the HA cluster

The reference cluster is four nodes (`swift1–4`) behind an Azure load balancer,
running the full daemon set plus a Prometheus/Loki/statsd observability stack.
Layout, EC install rules, and cutover notes: [`lab-cluster.md`](lab-cluster.md).

Against it we run:

- the functional suite on the real client path (prefer node HAProxy `:8085`
  when driving load from a backend VM — ILB hairpin is unreliable);
- sustained `cosbench-rs`/`autocos` load at production concurrency;
- the console **Lab** for fault injection (fragment loss → reconstructor heal,
  node down) with read-back integrity verification;
- large-object streaming-memory checks (a multi-GB PUT/GET while sampling RSS);
- after a VM/subscription cutover: `ha-test.sh`, `ec-heal-test.sh`, and
  Prometheus `nodes_up=4` before declaring the new cluster ready.

## What test infrastructure ships here

`swift-rust/tools/` contains the harnesses used for the above, all runnable
against any endpoint:

| Script | Purpose |
|--------|---------|
| `func-suite.sh` | parameterized functional suite (Rust and Python, one script) |
| `bench.py` | concurrent throughput + latency-percentile benchmark |
| `edge-diag.sh` | isolated checks for ETag, metadata, EC edge cases |
| `acl-meta-verify.sh` | ACL enforcement/revocation and metadata-limit parity |
| `ha-test.sh` | node-down failover drill |
| `ec-heal-test.sh` | EC fragment-loss → reconstructor heal |
| `py-saio-setup.sh` | stand up a Python Swift SAIO (parity oracle) |
| `rust-saio-setup.sh` | stand up a single-node Rust SAIO |
| `ci-fulltest.sh` | remote build + test + clippy + fmt |
| `regress.sh` | full workspace regression tally |

Operator cutover scripts and evidence summaries: repo-root [`tools/`](../tools/).

## The verification bar

A change is done when: the workspace tests are green, clippy is clean, the
functional suite matches the Python oracle, and — for anything on the data path
— the behavior is confirmed live on the cluster, not just in a unit test.
Reports state what was actually observed, including failures and skips.
