# Peregrine

A production object-storage platform: a ground-up **Rust rewrite of OpenStack
Swift** together with everything needed to deploy it, drive it, and prove it —
the storage engine, a Python-free deployer, a load generator, a benchmark
automation harness, and a web console, in one repository.

Every on-disk and on-the-wire format is **byte-for-byte compatible** with
Python Swift, so a Peregrine binary can be dropped onto a node in a live Python
cluster and validated one component at a time. Format fidelity is the design
constraint; the parity is proven against the real Python implementation as a
golden oracle.

**Documentation: <https://peregrine-docs-ochre.vercel.app>** — built with
[Nimbus](https://nimbus-docs.com/) (agent-native: every page has a markdown
alternate, plus [`/llms.txt`](https://peregrine-docs-ochre.vercel.app/llms.txt)).
Source in [`docs-site/`](docs-site/).

---

## Components

| Directory | What it is | Language | Status |
|-----------|-----------|----------|--------|
| [`swift-rust/`](swift-rust/) | The storage engine — proxy, object, container, account servers, all consistency daemons, erasure coding, the ring, the SQLite backends, the middleware pipeline. A 17-crate workspace. | Rust | Feature-complete data path; 946 workspace tests; runs a live 4-node cluster. |
| [`swift-deploy-rs/`](swift-deploy-rs/) | A bounded, Python-free deployer. Executes the upstream Swift Ansible v3 plan natively — no Ansible, no `ansible-playbook` — with sealed, re-verified plans and per-action authorization for destructive steps. Ships its own web control console. | Rust | Covers v3's 57 task/handler files, 413 leaf tasks, 28 modules. |
| [`cosbench-rs/`](cosbench-rs/) | A Rust rewrite of Intel's COSBench core: an S3/Swift load generator with prepare/main/cleanup workloads, hash-integrity checks, and JSON/CSV reports. | Rust | mock / S3 / Swift drivers, Keystone v3. |
| [`cabt-rs/`](cabt-rs/) | Benchmark automation over `cosbench-rs`: submit workloads, track progress, list, collect, and archive results. | Rust | `run` / `list` / `remove` / `collect`. |
| [`swift-console/`](swift-console/) | The web console: a files browser, deploy control, live monitoring, and a chaos/verification lab, served from a single Rust binary. | Rust | Files / Deploy / Monitor / Lab. |

Nothing here depends on Python at runtime. The Python Swift tree is **not**
vendored into this repo — it lives upstream and is used only to generate the
golden fixtures that `swift-rust` is checked against.

---

## Architecture

```
                          ┌───────────────────────────────┐
        operator ───────▶ │        swift-console          │  files · deploy · monitor · lab
                          │        (Rust web UI)          │
                          └───────┬───────────────┬───────┘
                                  │               │
                        control   │               │  live metrics (Prometheus/Loki/statsd)
                                  ▼               ▼
                          ┌───────────────┐   ┌───────────────────────────────┐
        deploy ─────────▶ │ swift-deploy- │   │           swift-rust          │
        (sealed plans)    │      rs       │──▶│  proxy ─┬─ object  ─┬─ replicator/reconstructor
                          └───────────────┘   │         ├─ container┤   updater/auditor/expirer
                                              │         └─ account ─┘   sharder/reaper/relinker
                                              │  ring · diskfile · SQLite · EC · middleware
                                              └───────────────┬───────────────┘
                                                              ▲
                              load  ┌───────────────┐         │  S3 / Swift API
                            ───────▶│  cabt-rs      │────────▶ │
                                    │   └▶ cosbench-rs (workers)│
                                    └───────────────┘
```

- **Data plane** — clients speak the Swift v1 REST API (and S3) to the
  `swift-rust` proxy, which fans out to the object/container/account servers over
  the ring. The consistency daemons keep replicas and erasure-coded fragments
  whole.
- **Control plane** — `swift-deploy-rs` stands up and reconfigures the cluster
  from sealed, re-verified plans; `swift-console` drives day-to-day operation.
- **Test plane** — `cosbench-rs` generates S3/Swift load; `cabt-rs` scripts the
  runs and collects the results; the console's Lab injects faults and verifies
  integrity.

See [`docs/architecture.md`](docs/architecture.md) for the full picture and
[`docs/testing.md`](docs/testing.md) for the verification strategy.

---

## Quickstart

Each component builds and runs independently; there is no monorepo-wide build
step, and no single Cargo workspace is forced across them (each keeps its own).

```sh
# The storage engine (default profile builds anywhere, incl. macOS).
cd swift-rust
cargo build --release
cargo test --workspace --exclude swift-ec        # swift-ec needs liberasurecode (Linux)

# Erasure coding (Linux, with liberasurecode installed):
cargo build --release --features swift-proxy-server/ec,swift-object-server/ec
```

```sh
# The deployer + its web console.
cd swift-deploy-rs && cargo build --release

# The load generator and its automation.
cd cosbench-rs && cargo build --release
cd cabt-rs      && cargo build --release

# The web console.
cd swift-console && cargo build --release
```

A one-command single-host cluster (SAIO) lives in
[`swift-rust/deploy/`](swift-rust/deploy/).

---

## Repository layout

```
Peregrine/
├── swift-rust/         the storage engine (17-crate Rust workspace)
├── swift-deploy-rs/    Python-free native deployer + control console
├── cosbench-rs/        COSBench-compatible S3/Swift load generator
├── cabt-rs/            benchmark automation over cosbench-rs
├── swift-console/      web console (files / deploy / monitor / lab)
└── docs/               architecture and testing methodology
```

## License

Apache-2.0, matching upstream OpenStack Swift. See [`LICENSE`](LICENSE).
