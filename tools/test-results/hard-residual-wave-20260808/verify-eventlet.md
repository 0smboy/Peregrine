# STRICT VERIFY — item10 Eventlet parity

**Date:** 2026-08-08  
**Workspace:** `/Users/oboy/Downloads/Peregrine/swift-rust`  
**Module:** `crates/swift-http/src/eventlet_parity.rs`  
**Command:**
```bash
export CARGO_HOME=/Users/oboy/Downloads/Peregrine/.cargo-home
cd /Users/oboy/Downloads/Peregrine/swift-rust
cargo test -p swift-http --lib -- eventlet_parity
```

## VERDICT: KEEP

## Test counts
| Metric | Count |
|--------|------:|
| passed | 5 |
| failed | 0 |
| ignored | 0 |
| measured | 0 |
| filtered out | 53 |
| duration | 0.01s |

## Full test list
```
test eventlet_parity::tests::heartbeat_yield_frequency ... ok
test eventlet_parity::tests::concurrency_thread_model ... ok
test eventlet_parity::tests::concurrency_eventlet_model ... ok
test eventlet_parity::tests::green_local_is_thread_scoped ... ok
test eventlet_parity::tests::greenthread_pool_runs_jobs ... ok

test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 53 filtered out; finished in 0.01s
```

## Greenthread pool — confirmed

| Eventlet concept | Rust surface | Status |
|------------------|--------------|--------|
| `eventlet.spawn(f)` | `GreenthreadPool::spawn` | OK |
| `eventlet.sleep(0)` | `cooperative_yield` (`thread::yield_now` + yield counter) | OK |
| greenthread pool | `GreenthreadPool::new(size)` — bounded OS threads, `size.clamp(1, 128)` | OK |
| greenthread local | `GreenLocal<T>` keyed by `ThreadId` | OK |
| heartbeat yield | `should_yield_heartbeat(elapsed, yield_frequency, last_yield)` | OK |

**Pool behavior (test `greenthread_pool_runs_jobs`):**
- Pool size 2; 20 jobs spawned; all complete within 2s idle join
- Each job completion path calls `cooperative_yield` → `yield_count() >= 20`
- Drop notifies shutdown + joins worker handles

## Concurrency formula — confirmed

`WORKER_THREADS_CAP = 128`

### Eventlet / process / prefork model
When `worker_model ∈ {eventlet, process, prefork}` **or** `process_workers > 1`:

```
worker_threads     = max_clients.clamp(1, 128)
connection_queue   = max_clients
aggregate_threads  = process_workers × worker_threads
formula            = "eventlet: process_workers=N × max_clients→threads=T (cap 128)"
```

**Test vector:** `compute_concurrency(4, 8, 1024, "eventlet")`
- `process_workers = 4`
- `worker_threads = 128` (1024 capped)
- `connection_queue = 1024`
- formula contains `"eventlet"`

### Thread-only model
When `worker_model == "thread"` and `process_workers == 1`:

```
worker_threads = (workers × max_clients).clamp(1, 128)
formula        = "thread: workers×max_clients=P (cap 128)"
```

**Test vector:** `compute_concurrency(1, 2, 10, "thread")` → `worker_threads = 20`

### Alignment with object-server effective concurrency
`swift_object_server::servers_per_port::effective_concurrency` uses the same cap and product mapping for the non-spp path (`workers * max_clients → worker_threads`, cap 128). Eventlet-model path in this module maps greenthread capacity to **per-process `max_clients`** (Python eventlet wsgi), which matches spp/prefork product semantics in `WORKERS-SEMANTICS.md`.

## Claim boundary
- **KEEP** for unit / lab scheduling-contract surface (spawn, yield, green local, concurrency formula).
- Not CPython eventlet bytecode / hub identity — module docs state full greenlet bit-identity is impossible; observable contract is what is tested.

## Files
- `/Users/oboy/Downloads/Peregrine/swift-rust/crates/swift-http/src/eventlet_parity.rs`
- re-exports: `swift-http/src/lib.rs` (`compute_concurrency`, `cooperative_yield`, `green_sleep`, `should_yield_heartbeat`, `yield_count`)
