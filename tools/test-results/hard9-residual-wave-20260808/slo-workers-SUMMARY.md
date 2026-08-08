# hard9 · SLO + workers strict verify · 2026-08-08

**Crate root:** `/Users/oboy/Downloads/Peregrine/swift-rust`  
**Evidence dir:** `tools/test-results/hard9-residual-wave-20260808/`  
**Raw log:** `slo-workers-cargo.txt`  
**Workflow:** `hard9-slo-workers`

## Result: PASS (API + conf + tests)

| # | Command (cargo accepts one filter; split) | Exit | Outcome |
|---|-------------------------------------------|------|---------|
| 1a | `cargo test -p swift-middleware --lib slo::` | 0 | **28 passed**, 0 failed, 386 filtered |
| 1b | `cargo test -p swift-middleware --lib refetch` | 0 | **1 passed** (`slo::tests::test_refetch_listing_slo_etag`) |
| 2a | `cargo test -p swift-proxy-server --bin swift-proxy-server process_workers` | 0 | **1 passed** (`startup_policy_tests::process_workers_conf_parses`) |
| 2b | `cargo test -p swift-proxy-server --bin swift-proxy-server server_options` | 0 | **1 passed** (`startup_policy_tests::server_options_read_workers_clients_timeout_and_log_conf`) |

Note: cargo rejects multi-filter forms like `slo:: refetch` / `process_workers server_options` (`unexpected argument`). Ran as four single-filter invocations; same coverage as requested.

Warnings only (non-fatal): unused `mut` in `slo.rs:2675` under lib-test; unused import/`md5_hex` under proxy dep build of middleware lib.

---

## 3) Code confirmations

### A. `Slo.concurrent_gets` / `Slo.yield_frequency`

**File:** `crates/swift-middleware/src/slo.rs`

| Item | Location | Detail |
|------|----------|--------|
| Fields | L209–211 | `pub concurrent_gets: usize`, `pub yield_frequency: f64` |
| Defaults | L225–226, L234–235 | `concurrent_gets: 10`, `yield_frequency: 10.0` in `new()` / `with_hash_config()` |
| Builders | L239–246 | `with_concurrency(n)` → `n.max(1)`; `with_yield_frequency(secs)` → `secs.max(0.0)` |
| Docs | L45–48 module, L209–211 field, L770–774 `handle_put` | Document Python parity intent |

**Usage honesty (boundary):** fields + setters exist and are public API. Grep shows **no runtime read** of `self.concurrent_gets` / `self.yield_frequency` in HEAD/heartbeat path. `handle_put` residual comment (L773–774): *“no concurrent HEAD pile / wall-clock `yield_frequency`”*. Heartbeat still yields whitespace per HEAD serially (`test_heartbeat_put_yields_space_per_head` ok). Matches main SUMMARY item 8 **KEEP (API)**.

### B. Listing etag refetch

| Item | Location | Detail |
|------|----------|--------|
| Helper | `slo.rs` L255+ | `pub fn refetch_listing_slo_etag(name, current_hash, head_headers) -> Option<String>` |
| Unit | L2669–2677 | SLO/`…-N` hash → `X-Object-Sysmeta-Slo-Etag`; plain hash → `None` |
| Test | `test_refetch_listing_slo_etag` | **ok** under both `slo::` and `refetch` filters |

### C. `process_workers_from_conf` + `prefork_workers`

**File:** `crates/swift-proxy-server/src/main.rs`

| Item | Location | Detail |
|------|----------|--------|
| Parse | L716–740 | Prefer `process_workers`; else if `worker_model` ∈ {process, prefork, eventlet} use numeric `workers`; else **1** |
| Prefork | L744–771 | Unix: `fork()` n−1 children; non-unix no-op |
| main() wire | L235–246 | After bind: if `process_workers > 1` call `prefork_workers` |
| Unit | L2980–2998 | `process_workers=4` → 4; `worker_model=process` + `workers=3` → 3; plain `workers=8` (thread default) → **1** |
| server_options | L2378–2421 | Thread-pool `workers` / max_clients / timeouts / statsd / trace (orthogonal to process prefork) |

---

## Verdict

| Surface | Status | Verified by |
|---------|--------|-------------|
| SLO unit suite + refetch | **PASS** | cargo 28 + 1 |
| process_workers conf parse | **PASS** | cargo + source |
| prefork_workers implementation + main call site | **PRESENT** | source (runtime fork not exercised in unit) |
| concurrent_gets / yield_frequency fields + builders | **PRESENT (API)** | source |
| concurrent HEAD pile + wall-clock yield_frequency behavior | **RESIDUAL** (documented) | no field reads in put path |
| server_options conf | **PASS** | cargo |

**Gate for hard9 items 7–9:** tests green; process prefork conf+code confirmed; SLO concurrent/yield **API** confirmed; full concurrent-pile runtime remains residual per source comment.

## Reproduce

```bash
export CARGO_HOME=/Users/oboy/Downloads/Peregrine/swift-rust/.cargo-home
cd /Users/oboy/Downloads/Peregrine/swift-rust
cargo test -p swift-middleware --lib slo::
cargo test -p swift-middleware --lib refetch
cargo test -p swift-proxy-server --bin swift-proxy-server process_workers
cargo test -p swift-proxy-server --bin swift-proxy-server server_options
```
