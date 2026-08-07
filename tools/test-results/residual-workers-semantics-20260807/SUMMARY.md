# Workers semantics residual · 2026-08-07

**Claim level:** unit + ISO-CONFIG tooling honesty only. **Not** true eventlet prefork rewrite. **Not** PRODUCTION-GO-LIVE.

**Command:** `cd swift-rust && cargo test -p swift-object-server effective_concurrency -- --nocapture`  
**Result:** **6 passed; 0 failed** on `servers_per_port::tests::effective_concurrency_*` (see `01-cargo-test.txt`)

**CLI:** `swift-effective-concurrency` samples in `02-cli-samples.txt` (binary builds and runs).

## Honest equivalence

| Layer | Python eventlet | Rust | Equivalent? |
|-------|-----------------|------|-------------|
| `workers` (object/account/container when spp=0) | prefork OS processes × greenlets | `workers * max_clients → worker_threads` (cap 128), **one process** | **No** — threads ≠ processes |
| `workers` (proxy) | prefork OS processes | conf `workers` → `worker_threads` **directly** (not product); `0`/`auto` → CPU default | **No** — same residual class |
| `max_clients` | greenlets per worker | connection_queue + product factor (object path) | Partial (queue depth vs greenlets) |
| `servers_per_port>0` | process per port (workers ignored) | Wave2 process-per-(port, worker) supervise; workers ignored | **Closer** (process-isolated; not claimed bit-identical) |
| ISO-CONFIG tooling | manual arithmetic | `swift-effective-concurrency` JSON + unit tests | **KEEP / GREEN** |

## Mapping matrix (object-server `effective_concurrency`)

| Inputs | Output (key fields) | Notes |
|--------|---------------------|-------|
| workers=2, max_clients=64, spp=0 | worker_threads=128 (capped), acceptors=1 | product 128; “NOT prefork” |
| workers=2, max_clients=32, spp=0 | worker_threads=64 | unclamped product |
| workers=0, max_clients=1024, spp=0 | worker_threads = cpus\*16 clamp 16..128 | ServerConfig default path |
| spp=4, max_clients=1024, ports=1 | per-process threads=128, acceptors=4 | workers ignored |
| spp=2, ports=3, workers=99, max_clients=8 | threads=8, acceptors=6 | spp wins over workers |

## Tests strengthened (edge cases)

- `effective_concurrency_workers_zero_uses_cpu_default`
- `effective_concurrency_workers_product_uncapped_when_small`
- `effective_concurrency_workers_times_max_clients_clamps_at_128`
- `effective_concurrency_spp_gt_zero_ignores_workers`
- `effective_concurrency_spp_one_clamps_max_clients`
- `effective_concurrency_max_clients_zero_treated_as_one`

## Out of scope (explicit)

- **Do not** rewrite servers to true eventlet multi-process prefork for classic `workers`.
- Fairness claims must use **ISO-CONFIG** (match effective concurrency / CPU quota), not raw `workers=` integers.

## Verdict

| Item | Status |
|------|--------|
| ISO-CONFIG tooling | **GREEN** |
| Process model (classic workers / proxy path) | **RESIDUAL — not equivalent** |
| spp process isolation (Wave2) | Closer; lab-dependent |

**TOOLING/DOC KEEP** for fairness ISO-CONFIG.  
**Process-model residual remains** for classic `workers` prefork and proxy path (documented map-not-clone; WONTFIX as full rewrite).

## Authority / anchors

- `docs/fairness-lab/WORKERS-SEMANTICS.md`
- `swift-rust/crates/swift-object-server/src/servers_per_port.rs` — `effective_concurrency`
- `swift-rust/crates/swift-object-server/src/bin/effective_concurrency.rs` — CLI
- `swift-rust/crates/swift-proxy-server/src/main.rs` — workers → worker_threads direct
- Parity row: `docs/fairness-lab/RUST-VS-PYTHON-PARITY.md` §7
