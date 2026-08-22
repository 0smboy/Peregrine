# CONCURRENCY-PHASE-01

**Phase:** 1 — Peregrine Runtime Substrate (`AGENTS.md` §4–§5, §18, §33)  
**Date:** 2026-08-20T04:43:03Z (UTC)  
**Tree:** `.agent-handoff/peregrine-grok-merge-20260814`  
**Workspace:** `swift-rust/`  
**Constitution:** `/Users/oboy/Downloads/swift-master/AGENTS.md`  
**Predecessor:** `docs/progress/CONCURRENCY-PHASE-00.md` (forensic GO; Gate 1 NO-GO *at Phase 1*)

> **2026-08-21 recapture:** Phase 1 substrate GO/NO-GO below is historical. Current Gates 1–5 / Eventlet-solved is `phase-gogo.txt`.  
**CI note:** `docs/progress/CONCURRENCY-PHASE-01-ci.md` (identifier gate; later rustdoc reword so the checker is green)

Phase 1 is **runtime substrate only**. It does not serve HTTP. It does not wrap the existing `Handler`. It does not change worker defaults.

## Scope completed

Logical boundaries from `AGENTS.md` §4, mapped onto **existing crate names** (no rename split):

| AGENTS.md name | This tree |
|---|---|
| `peregrine-runtime` | `crates/swift-runtime` |
| `peregrine-admission` | `swift-runtime::admission` |
| `peregrine-http` | still `swift-http` (sync; **not wired**) |
| `peregrine-storage-io` | **not this phase** (`DeviceScheduler` / `ThreadedPosixIo` are Phase 4) |
| `peregrine-db-runtime` | **not this phase** (`DbExecutor` is Phase 6) |
| `peregrine-proxy-io` | **not this phase** (Phase 7) |

Substrate that exists and is tested:

- `AdmissionController` / `AdmissionLimits` — independent finite caps: `max_connections`, `max_active_requests`, Foreground / Replication / Reconstruction / Auditor. Fail-closed try-acquire. Legacy `max_clients` is a **deprecated alias of `max_active_requests` only**; it is not copied onto `max_connections` and there is no hidden 1024 default.
- `TrafficClass` — four named classes, no `Other` / FIFO catch-all.
- `TaskScope` + hierarchical `CancellationToken` — spawn retains `JoinHandle`; drop aborts; child cancel does not cancel parent; finite child bound (`DEFAULT_SCOPE_BOUND = 1024` is a **per-request child-task** analog, not `max_connections`).
- `RequestContext` — `CancellationToken`, `DeadlineBudget`, `TrafficClass`, `TransId`, child `TaskScope`.
- `DurabilityBarrier` — `#[must_use]`; drop without `complete()` panics (L7 commit-shield type; **not** wired into PUT).
- Typed deadlines — ten kinds; `BodyIdleDeadline` is progress-aware; `UploadLifetimeDeadline` is not; they are distinct types.
- `BlockingDomain` — the **only** workspace `tokio::task::spawn_blocking(` site. Finite `thread_cap` + `queue_bound`. Submit is fail-closed (`QueueFull`). In-flight blocking work cannot abort (documented + tested).

Tokio is a `swift-runtime` dependency only:

```toml
tokio = { version = "1", default-features = false, features = ["rt", "sync", "time", "macros"] }
```

No `net`, no `fs`, no `rt-multi-thread` feature. Application crates do not depend on `swift-runtime` or `tokio`.

CI architecture gate (`AGENTS.md` §5 / §24) applied now via `swift-rust/ci/check-concurrency-boundaries.sh` (script not weakened).

**Explicitly out of this phase (server unchanged):**

- `swift-http::server` is still `Handler = Arc<dyn Fn(Request) -> Response + Send + Sync>`.
- Idle keep-alive is still `read_head` on an OS worker (`head_deadline_secs`, default 30).
- No Hyper, no async connection runtime, no `max_connections` on the serve path.
- No `DeviceScheduler`, `ThreadedPosixIo`, `DbExecutor`, io_uring.

## Files changed

Serve architecture **not** modified. No other crate `Cargo.toml` lists `swift-runtime`.

```
swift-rust/Cargo.toml                                      (workspace member)
swift-rust/crates/swift-runtime/Cargo.toml
swift-rust/crates/swift-runtime/src/lib.rs                 #![forbid(unsafe_code)]
swift-rust/crates/swift-runtime/src/admission.rs
swift-rust/crates/swift-runtime/src/blocking.rs            unique spawn_blocking call
swift-rust/crates/swift-runtime/src/context.rs
swift-rust/crates/swift-runtime/src/deadline.rs
swift-rust/crates/swift-runtime/src/scope.rs               unique tokio::spawn (handle retained)
swift-rust/crates/swift-runtime/src/traffic.rs
swift-rust/ci/check-concurrency-boundaries.sh
swift-rust/ci/README.md
docs/progress/CONCURRENCY-PHASE-01-ci.md
docs/progress/CONCURRENCY-PHASE-01.md                      (this file)
```

Not touched (Gate 1 still the Phase 0 server):

```
swift-rust/crates/swift-http/src/server.rs
swift-rust/crates/swift-proxy-server/src/lib.rs
swift-rust/crates/swift-object-server/src/lib.rs
```

## Architectural invariants affected

| Law | Phase 1 substrate | Serve path (unchanged) |
|---|---|---|
| **L1** | BlockingDomain forbids holding a blocking thread across network wait. | **VIOLATED.** Keep-alive `read_head` still occupies the HTTP worker (`server.rs:784-802`). |
| **L2** | `spawn_blocking` sealed in `BlockingDomain`; Tokio has no `fs`/`net` features. | **VIOLATED.** `sync_all` / rusqlite / xattr still run on the HTTP worker. There is still no separate network runtime on the serve path. |
| **L3** | Admission caps, TaskScope bound, BlockingDomain queue bound are finite. Submit / try-acquire fail closed. | Accept queue still bounded. Proxy fan-out still uses unbounded `std::sync::mpsc::channel()` (see Unbounded). |
| **L4** | BlockingDomain `QueueFull` does not grow. Admission never waits. | Unchanged: accept 503s; proxy tee still stalls the client on a slow replica. |
| **L5** | Connection vs request vs four class budgets are independent types. | Serve path still uses `workers` as the only real execution budget. Substrate is not wired. |
| **L6** | `TaskScope` retains handles; drop aborts; no fire-and-forget API. | Serve path still has detached `std::thread::spawn` on proxy fan-out. |
| **L7** | `DurabilityBarrier` panics on unfinished drop. | PUT is still a blocking procedure; barrier is not on the write path. |
| **L8** | Four `TrafficClass` budgets, no shared FIFO. | SSYNC / replicator / auditor / client still share process threads. |
| **L9** | No wire/storage change. | Held (no serve-path change). |
| **L10** | No worker-default change; no mio reactor. | Held. SAIO `workers=64` remains an ops workaround, not this phase. |

`AGENTS.md` §5: Tokio is infrastructure. Application crates contain **zero** `tokio::spawn` / `tokio::task::spawn_blocking` / `tokio::sync::Semaphore`.

## Tests added

All live under `#[cfg(test)]` in `crates/swift-runtime/src/*.rs` (no separate `tests/` dir).

| Module | Tests | Property |
|---|---|---|
| `admission` | 11 | independent caps; `max_clients` ≠ `max_connections`; class isolation; zero cap fail-closed; concurrent CAS never exceeds cap |
| `blocking` | 5 | zero bounds rejected; job runs; queue-full reject (closure does not run); thread_cap respected; abort queued ≠ abort in-flight |
| `context` | 6 | required fields; parent→child cancel; child ↛ parent; spawned child stops; barrier complete vs drop-panic |
| `deadline` | 6 | ten kinds; BodyIdle ≠ UploadLifetime (type + refresh) |
| `scope` | 8 | hierarchical cancel; join waits; bound; drop aborts (no detach); sibling isolation |
| `traffic` | 2 | four classes; unknown parse is `None`; exhaustive match has no wildcard |

**38 tests.** No Hyper/HTTP tests in this crate (it does not serve).

Gate tests from Phase 0 were **not** rewritten. They remain the RED oracle for Gate 1/2:

| Test | Gate | Result this run |
|---|---|---|
| `swift-http --test worker_starvation` | 1 idle ≠ thread | **FAIL** (see Tests passed) |
| `slowloris` / `slow_put` / `slow_reader` | 1 / 2 | not re-run; server unchanged, still the Phase 0 RED suite |

## Tests passed

### `cargo test -p swift-runtime --offline`

```text
cwd: /Users/oboy/Downloads/swift-master/.agent-handoff/peregrine-grok-merge-20260814/swift-rust
command: cargo test -p swift-runtime --offline
```

```
running 38 tests
test admission::tests::legacy_max_clients_aliases_active_requests_not_connections ... ok
test admission::tests::reject_when_connections_full ... ok
test admission::tests::connections_and_requests_are_independent ... ok
test admission::tests::construction_requires_all_caps_and_has_no_default ... ok
test admission::tests::drop_releases_both_request_and_class_slots ... ok
test admission::tests::class_budgets_are_independent_not_shared_fifo ... ok
test admission::tests::reject_when_class_full_does_not_consume_global_request ... ok
test admission::tests::reject_when_requests_full ... ok
test admission::tests::zero_cap_fails_closed ... ok
test blocking::tests::rejects_zero_bounds ... ok
test admission::tests::concurrent_try_acquire_never_exceeds_connection_cap ... ok
test context::tests::child_context_cancel_does_not_cancel_parent ... ok
test admission::tests::concurrent_class_caps_stay_isolated ... ok
test context::tests::durability_barrier_type_exists ... ok
test context::tests::request_context_holds_required_fields ... ok
test context::tests::parent_cancels_child ... ok
test deadline::tests::all_ten_kinds_exist_and_body_idle_is_not_upload_lifetime ... ok
test deadline::tests::body_idle_and_upload_lifetime_are_distinct_parameters ... ok
test deadline::tests::each_struct_reports_its_kind ... ok
test context::tests::parent_cancel_stops_child_spawned_task ... ok
test deadline::tests::zero_timeout_is_expired ... ok
test scope::tests::child_cancel_does_not_cancel_sibling_or_parent ... ok
test blocking::tests::job_runs ... ok
test scope::tests::child_does_not_cancel_parent ... ok
test scope::tests::child_scope_cancel_is_hierarchical ... ok
test scope::tests::drop_aborts_children_no_detach ... ok
test scope::tests::parent_cancels_child ... ok
test scope::tests::parent_scope_cancels_spawned_child_task ... ok
test scope::tests::spawn_respects_finite_bound ... ok
test traffic::tests::exhaustive_match_has_no_wildcard_arm ... ok
test context::tests::durability_barrier_drop_without_complete_is_forbidden - should panic ... ok
test traffic::tests::four_named_classes_no_catch_all ... ok
test blocking::tests::abort_queued_job_does_not_stop_in_flight ... ok
test blocking::tests::reject_when_queue_full ... ok
test scope::tests::join_waits_for_children ... ok
test deadline::tests::body_idle_refresh_on_progress_extends_deadline ... ok
test deadline::tests::refresh_body_idle_does_not_move_upload_lifetime ... ok
test blocking::tests::thread_cap_is_respected ... ok

test result: ok. 38 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.03s

   Doc-tests swift_runtime
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

**38 passed; 0 failed.** This is the Phase 1 cargo gate.

### `ci/check-concurrency-boundaries.sh`

```text
cwd: .../swift-rust
command: bash ci/check-concurrency-boundaries.sh
exit: 0 PASS
files scanned: 219
spawn_blocking FAIL:        0
spawn_blocking ALLOW:       16  (crates/swift-runtime/src/blocking)
unbounded FAIL (prod src):  0
unbounded LIST (tests):     0
tokio::fs FAIL:             0
std::net WARN (proxy src):  16  (not a fail until Phase 2)
hard failures:              0
```

Unique real call (ALLOW):

```rust
// crates/swift-runtime/src/blocking.rs:577
let join = tokio::task::spawn_blocking(run);
```

### Gate 1 (must stay RED)

```text
command: cargo test -p swift-http --test worker_starvation --offline
exit: 101
```

```
thread 'idle_keepalive_does_not_starve_a_third_request' panicked at
crates/swift-http/tests/concurrency/worker_starvation.rs:22:10:
third request must complete without waiting for an idle keep-alive deadline:
Os { code: 35, kind: WouldBlock, message: "Resource temporarily unavailable" }
test idle_keepalive_does_not_starve_a_third_request ... FAILED
test result: FAILED. 0 passed; 1 failed
```

Idle keep-alive still occupies the worker. **Gate 1 NO-GO.** Do not paper this over with `workers=64`.

Full workspace `cargo test` was **not** run this phase (no serve-path change; Phase 0 lib baseline still applies).

## Differential results

Not run. No execution-model change on the wire. Python SAIO vs Rust SAIO numbers remain `bench/baseline/current-sync.json`.

## Benchmark before/after

Phase 1 has no serve-path after. Before = `bench/baseline/current-sync.json`.

Do not treat SAIO `workers=64` / 14m08 as a Phase 1 win.

## Known limitations

- `swift-runtime` is **not a dependency** of `swift-http` / `swift-proxy-server` / `swift-object-server` / account / container. Admission, scopes, deadlines, BlockingDomain are unused on the serve path.
- `tokio::spawn` exists once, inside `TaskScope::spawn`, with the `JoinHandle` stored. Application crates still must not call it. Phase 2+ must route HTTP tasks through `TaskScope`, not naked `tokio::spawn`.
- `CancellationToken` child registry is `Mutex<Vec<Weak<CancelInner>>>` with no numeric cap (Weak list, cleaned on new child). Not a work queue; still not a documented finite bound (L3 residual inside the substrate).
- `DurabilityBarrier` is a drop-panic guard, not a PUT state machine. Phase 4 must wire it.
- `BlockingDomain` cannot abort in-flight POSIX/SQLite/FFI once `spawn_blocking` has started (Tokio contract). Callers must submit **finite** jobs. Wrapping a whole PUT/GET handler remains a non-goal (`AGENTS.md` §32.4).
- Checker matches the identifier `spawn_blocking` on every scanned line, including comments. Prose outside `src/blocking.rs` must not name it (fixed for `lib.rs` / `scope.rs`; see `CONCURRENCY-PHASE-01-ci.md`).
- Proxy `std::net` is WARN until Phase 2 (16 production-src hits).
- `std::sync::mpsc::channel()` is unbounded and is **not** in the current checker pattern (`unbounded_channel` / `crossbeam_channel::unbounded` / `::unbounded(`). Listed below; do not treat checker PASS as “no unbounded queues in the process”.
- No Hyper. HTTP/2 not started (correct).
- No `DeviceScheduler` / `DbExecutor` / io_uring (correct; later phases / forbidden).

## Blocking operations remaining

`rg` performed from `swift-rust/` on `crates/**/*.rs`, exclude `target/`.  
**Do not read this section as “none known”.** Counts are the audit.

### Command set

```text
rg -n --glob '*.rs' --glob '!target/**' 'spawn_blocking' crates
rg -n --glob '*.rs' --glob '!target/**' 'tokio::task::spawn_blocking\(' crates
rg -n --glob '*.rs' --glob '!target/**' 'tokio::spawn' crates
rg -n --glob '*.rs' --glob '!target/**' 'tokio::fs' crates
rg -n --glob '*.rs' --glob '!target/**' 'tokio::sync::Semaphore' crates
rg -n --glob '*.rs' --glob '!target/**' 'io_uring|io-uring' crates
rg --count-matches --glob '*.rs' --glob '!target/**' 'std::net::' crates
rg --count-matches --glob '*.rs' --glob '!target/**' --glob '!**/tests/**' 'std::net::' crates
rg -l --glob '*.rs' --glob '!target/**' --glob '!**/tests/**' 'TcpStream|TcpListener' crates
rg --count-matches --glob '*.rs' --glob '!target/**' --glob '!**/tests/**' 'std::fs::' crates
rg --count-matches --glob '*.rs' --glob '!target/**' 'rusqlite' crates
rg -n --glob '*.rs' --glob '!target/**' --glob '!**/tests/**' 'sync_all|fdatasync|fsync\(' crates
rg -n --glob '*.rs' --glob '!target/**' --glob '!**/tests/**' 'xattr::' crates
rg -n --glob '*.rs' --glob '!target/**' --glob '!**/tests/**' 'thread::spawn\(' crates
```

### `spawn_blocking` — 16 identifier hits, 1 call, 0 violations

All 16 are `crates/swift-runtime/src/blocking.rs`. **0** hits in any other crate (including rustdoc after the CI follow-up).

```
crates/swift-runtime/src/blocking.rs:19://! call [`tokio::task::spawn_blocking`]. Callers submit a finite job through
crates/swift-runtime/src/blocking.rs:26://! * `thread_cap` — maximum concurrent `spawn_blocking` invocations.
crates/swift-runtime/src/blocking.rs:37://! `spawn_blocking`. **In-flight blocking work cannot abort.** Tokio's
crates/swift-runtime/src/blocking.rs:65:    /// Maximum concurrent blocking threads (`spawn_blocking` in flight).
crates/swift-runtime/src/blocking.rs:141:    /// Job was cancelled before `spawn_blocking` started.
crates/swift-runtime/src/blocking.rs:174:    /// Sum of queue-wait nanoseconds for jobs that reached `spawn_blocking`.
crates/swift-runtime/src/blocking.rs:194:/// tasks; in-flight `spawn_blocking` closures still run to completion.
crates/swift-runtime/src/blocking.rs:214:            // Aborts the worker *task*. Does not abort in-flight spawn_blocking.
crates/swift-runtime/src/blocking.rs:307:/// Dropping this handle cancels a queued job. If `spawn_blocking` has
crates/swift-runtime/src/blocking.rs:319:    /// If the job had already entered `spawn_blocking`, this waits for the
crates/swift-runtime/src/blocking.rs:338:    /// Returns `false` if `spawn_blocking` has started (or the job already
crates/swift-runtime/src/blocking.rs:352:    /// `true` once the job has entered `spawn_blocking`.
crates/swift-runtime/src/blocking.rs:373:    /// `tokio::task::spawn_blocking`. Must be called from inside a runtime.
crates/swift-runtime/src/blocking.rs:574:    // Unique workspace `spawn_blocking` site. Aborting the worker task or
crates/swift-runtime/src/blocking.rs:577:    let join = tokio::task::spawn_blocking(run);
crates/swift-runtime/src/blocking.rs:773:        assert!(!in_flight.abort(), "in-flight spawn_blocking cannot abort");
```

`tokio::task::spawn_blocking(` **call** sites:

```
crates/swift-runtime/src/blocking.rs:577:    let join = tokio::task::spawn_blocking(run);
```

**Reviewed: 16 identifier occurrences / 1 call. 0 outside `crates/swift-runtime/src/blocking`. spawn_blocking is confined.**

### `tokio::spawn` — 1 production call (handle retained)

```
crates/swift-runtime/src/scope.rs:313:        let handle = tokio::spawn(async move {
```

`JoinHandle` is pushed onto `TaskScope` (`scope.rs:322-323`). Drop of the scope aborts remaining children. **0** `tokio::spawn` in HTTP/proxy/object/account/container/db/diskfile.

`BlockingDomain` worker tasks use `tokio::runtime::Handle::spawn` (not the `tokio::spawn` identifier):

```
crates/swift-runtime/src/blocking.rs:393:            handles.push(rt.spawn(worker_loop(inner)));
```

Handles stored in `WorkerSet`; drop aborts worker **tasks**, not in-flight `spawn_blocking`.

### `tokio::fs` — 0

```
rg tokio::fs  crates/**/*.rs  →  0 occurrences
```

Checker: `tokio::fs FAIL: 0` (http / proxy / s3api).

### `tokio::sync::Semaphore` — 0

```
rg tokio::sync::Semaphore  crates/**/*.rs  →  0 occurrences
```

Admission is `AdmissionController`, not a Tokio semaphore.

### `io_uring` / `io-uring` — 0

```
rg 'io_uring|io-uring'  crates/**/*.rs  →  0 occurrences
```

Forbidden on this migration (`AGENTS.md` §22 / NON-GOAL 11).

### `hyper::` — 0

```
rg 'hyper::'  crates/**/*.rs  →  0 occurrences
```

Phase 2.

### `std::net::` — 135 hits / 44 files (all crates incl. tests); 63 hits production src (no `tests/`)

Per-file `rg --count-matches` (all crates, include tests):

```
crates/swift-proxy-server/src/main.rs:1
crates/swift-proxy-server/src/lib.rs:15
crates/swift-proxy-server/tests/integration.rs:31
crates/swift-proxy-server/tests/ec_integration.rs:8
crates/swift-container-server/src/main.rs:1
crates/swift-container-server/src/sync.rs:1
crates/swift-container-server/src/lib.rs:3
crates/swift-container-server/src/reconciler.rs:1
crates/swift-container-server/src/bin/container_sync.rs:1
crates/swift-container-server/src/sharder.rs:1
crates/swift-container-server/src/updater.rs:1
crates/swift-container-server/tests/golden.rs:7
crates/swift-container-server/tests/replication.rs:1
crates/swift-memcache/src/conn.rs:1
crates/main.rs:1
crates/swift-core/src/statsd.rs:1
crates/swift-core/src/localdev.rs:1
crates/swift-core/src/otlp.rs:2
crates/swift-account-server/src/reaper.rs:1
crates/swift-account-server/src/main.rs:1
crates/swift-account-server/src/lib.rs:2
crates/swift-account-server/tests/golden.rs:3
crates/swift-middleware/src/cname_lookup.rs:1
crates/swift-middleware/src/authtoken.rs:1
crates/swift-middleware/src/s3token.rs:2
crates/swift-db/src/replicator.rs:3
crates/swift-object-server/src/expirer.rs:1
crates/swift-object-server/src/lib.rs:5
crates/swift-object-server/src/updater.rs:1
crates/swift-object-server/src/servers_per_port.rs:2
crates/swift-object-server/src/localdev.rs:1
crates/swift-object-server/src/ssync_sender.rs:2
crates/swift-object-server/src/bin/object_replicator.rs:1
crates/swift-object-server/src/reconstructor.rs:4
crates/swift-object-server/tests/multiphase.rs:4
crates/swift-object-server/tests/ssync_ec.rs:1
crates/swift-object-server/tests/golden.rs:5
crates/swift-http/src/server.rs:4
crates/swift-http/tests/concurrency/slow_reader.rs:2
crates/swift-http/tests/concurrency/align_expect_continue.rs:1
crates/swift-http/tests/concurrency/harness.rs:4
crates/swift-http/tests/concurrency/slow_put.rs:2
crates/swift-http/tests/concurrency/slowloris.rs:1
crates/swift-http/tests/golden.rs:2
```

**Sum: 135.** Production src (exclude `**/tests/**`): **63**. Proxy production src: **16** (15 `lib.rs` + 1 `main.rs`) — checker WARN, not FAIL until Phase 2.

`TcpStream` / `TcpListener` production-src files (**26**):

```
crates/swift-proxy-server/src/main.rs
crates/swift-proxy-server/src/lib.rs
crates/swift-memcache/src/conn.rs
crates/main.rs
crates/swift-object-server/src/servers_per_port.rs
crates/swift-object-server/src/reconstructor.rs
crates/swift-db/src/replicator.rs
crates/swift-object-server/src/ssync_sender.rs
crates/swift-middleware/src/authtoken.rs
crates/swift-object-server/src/updater.rs
crates/swift-core/src/otlp.rs
crates/swift-object-server/src/expirer.rs
crates/swift-account-server/src/reaper.rs
crates/swift-object-server/src/lib.rs
crates/swift-account-server/src/main.rs
crates/swift-object-server/src/bin/object_replicator.rs
crates/swift-http/src/server.rs
crates/swift-account-server/src/lib.rs
crates/swift-middleware/src/s3token.rs
crates/swift-container-server/src/main.rs
crates/swift-container-server/src/sync.rs
crates/swift-container-server/src/lib.rs
crates/swift-container-server/src/reconciler.rs
crates/swift-container-server/src/updater.rs
crates/swift-container-server/src/sharder.rs
crates/swift-container-server/src/bin/container_sync.rs
```

L1: every one of these network waits still occupies a blocking worker / daemon thread. Phase 2/7/9.

### `std::fs::` production src — 525 hits / 64 files

`rg --count-matches` exclude `tests/` / `target/`:

```
crates/swift-diskfile/src/auditor.rs:13
crates/swift-diskfile/src/hashes.rs:17
crates/swift-diskfile/src/metadata.rs:4
crates/swift-diskfile/src/relinker.rs:11
crates/swift-diskfile/src/layout.rs:13
crates/swift-diskfile/src/diskfile.rs:15
crates/swift-diskfile/src/cleanup.rs:5
crates/swift-proxy-server/src/main.rs:12
crates/main.rs:1
crates/swift-container-server/src/main.rs:1
crates/swift-container-server/src/sync.rs:13
crates/swift-ring/src/writer.rs:1
crates/swift-account-server/src/reaper.rs:3
crates/swift-db/src/container.rs:26
crates/swift-container-server/src/lib.rs:1
crates/swift-account-server/src/main.rs:1
crates/swift-db/src/auditor.rs:12
crates/swift-container-server/src/updater.rs:5
crates/swift-account-server/src/lib.rs:1
crates/swift-db/src/account.rs:7
crates/swift-container-server/src/bin/container_reconciler.rs:1
crates/swift-ring/src/io.rs:1
crates/swift-db/src/replicator.rs:6
crates/swift-container-server/src/bin/container_updater.rs:2
crates/swift-account-server/src/bin/account_reaper.rs:2
crates/swift-container-server/src/bin/container_sharder.rs:2
crates/swift-container-server/src/bin/container_sync.rs:1
crates/swift-middleware/src/container_sync.rs:2
crates/swift-container-server/src/sharder.rs:49
crates/swift-middleware/src/encrypter.rs:1
crates/swift-middleware/src/healthcheck.rs:3
crates/swift-core/src/constraints.rs:5
crates/swift-core/src/daemon.rs:3
crates/swift-core/src/lockutil.rs:8
crates/swift-middleware/src/xprofile.rs:2
crates/swift-core/src/recon.rs:18
crates/swift-core/src/obslog.rs:2
crates/swift-db/src/repl_loop.rs:6
crates/swift-db/src/util.rs:34
crates/swift-object-server/src/servers_per_port.rs:5
crates/swift-object-server/src/reconstructor.rs:17
crates/swift-db/src/vacuum.rs:4
crates/swift-s3api/src/cold_tier.rs:28
crates/swift-object-server/src/main.rs:1
crates/swift-object-server/src/ssync_sender.rs:9
crates/swift-object-server/src/lib.rs:14
crates/swift-object-server/src/daemonutil.rs:3
crates/swift-object-server/src/replicator.rs:27
crates/swift-object-server/src/updater.rs:29
crates/swift-object-server/src/bin/object_replicator.rs:2
crates/swift-object-server/src/bin/object_reconstructor.rs:3
crates/swift-object-server/src/bin/object_updater.rs:2
crates/swift-object-server/src/bin/object_expirer.rs:1
crates/swift-cli/src/auditor_daemon.rs:4
crates/swift-cli/src/space_metrics.rs:15
crates/swift-cli/src/info.rs:3
crates/swift-cli/src/daemon.rs:3
crates/swift-cli/src/recon.rs:24
crates/swift-cli/src/bin/db_replicator.rs:2
crates/swift-cli/src/bin/get_nodes.rs:1
crates/swift-cli/src/bin/db_auditor.rs:1
crates/swift-cli/src/bin/ring_builder.rs:2
crates/swift-cli/src/bin/drive_audit.rs:1
crates/swift-cli/src/bin/recon.rs:1
crates/swift-cli/src/bin/object_auditor.rs:2
crates/swift-cli/src/bin/manage_shard_ranges.rs:11
```

**Sum: 525.** Including tests: **89 files** contain `std::fs::`. L2: these still run on the caller thread. Phase 4 `ThreadedPosixIo` is the intended isolation. **0** of these were moved in Phase 1.

### `rusqlite` — 92 hits / 5 files (all `swift-db`)

```
crates/swift-db/src/container.rs:39
crates/swift-db/src/broker.rs:7
crates/swift-db/src/account.rs:28
crates/swift-db/src/vacuum.rs:1
crates/swift-db/src/util.rs:17
```

**Sum: 92.** Caller-thread SQLite. Phase 6 `DbExecutor`. **0** hits in http/proxy.

### `sync_all` / `fdatasync` / `fsync(` — 12 production hits

```
crates/swift-diskfile/src/hashes.rs:178:        f.sync_all()?;
crates/swift-diskfile/src/layout.rs:163:            std::fs::File::open(dirpath)?.sync_all()?;
crates/swift-diskfile/src/diskfile.rs:110:    /// When true (default), `put` fsyncs the datafile (`sync_all`) and the
crates/swift-diskfile/src/diskfile.rs:833:            file.sync_all()?;
crates/swift-diskfile/src/diskfile.rs:866:                std::fs::File::open(&self.df.datadir)?.sync_all()?;
crates/swift-object-server/src/lib.rs:2756:            let _ = dir.sync_all();
crates/swift-s3api/src/cold_tier.rs:992:            .and_then(|file| file.sync_all())
crates/swift-s3api/src/cold_tier.rs:1001:                .and_then(|directory| directory.sync_all())
crates/swift-s3api/src/cold_tier.rs:1088:                .sync_all()
crates/swift-db/src/util.rs:302:        f.sync_all()?;
crates/swift-db/src/util.rs:316:        std::fs::File::open(d)?.sync_all()?;
crates/swift-db/src/util.rs:342:        std::fs::File::open(d)?.sync_all()?;
```

**Reviewed: 12.** Durability still on the HTTP/DB caller thread (L2 / Gate 3).

### `xattr::` production — 5 hits (`swift-diskfile/src/metadata.rs`)

```
crates/swift-diskfile/src/metadata.rs:160:            XattrSource::Path(p) => xattr::get(p, name),
crates/swift-diskfile/src/metadata.rs:162:                use xattr::FileExt;
crates/swift-diskfile/src/metadata.rs:163:                f.get_xattr(name)
crates/swift-diskfile/src/metadata.rs:170:            XattrSource::Path(p) => xattr::set(p, name, value),
crates/swift-diskfile/src/metadata.rs:172:                use xattr::FileExt;
crates/swift-diskfile/src/metadata.rs:173:                f.set_xattr(name, value)
crates/swift-diskfile/src/metadata.rs:307:        xattr::set(&path, METADATA_CHECKSUM_KEY, b"0000").unwrap();
```

(Line 307 is an in-module unit test.) PUT finalize still does xattr on the handler thread (`diskfile.rs:831`).

### `std::thread::spawn(` production src (exclude `tests/`)

Serve / fan-out (L1/L6 residual — Phase 2/7):

```
crates/swift-proxy-server/src/lib.rs:1545:            std::thread::spawn(move || {          // make_requests
crates/swift-proxy-server/src/lib.rs:1626:            std::thread::spawn(move || loop {     // stream_put_object
crates/swift-proxy-server/src/lib.rs:1843:            std::thread::spawn(move || loop {     // post_fan_out
crates/swift-proxy-server/src/lib.rs:3945:            std::thread::spawn(move || {          // EC put connect
crates/swift-proxy-server/src/lib.rs:4169:            std::thread::spawn(move || {
crates/swift-proxy-server/src/lib.rs:4499:            std::thread::spawn(move || {
crates/swift-proxy-server/src/main.rs:2194:    std::thread::spawn(move || {
```

HTTP workers are `std::thread::Builder::new().spawn` (`server.rs:317-329`), one OS thread per `worker_threads`, each looping `handle_connection` — this **is** Gate 1.

Other production `thread::spawn(` (daemons / in-src tests / lab):

```
crates/swift-core/src/otlp.rs:130
crates/swift-core/src/otlp.rs:410
crates/swift-http/src/thread_concurrency.rs:151
crates/swift-http/src/thread_concurrency.rs:296
crates/swift-runtime/src/admission.rs:563          # unit test
crates/swift-runtime/src/admission.rs:594          # unit test
crates/swift-http/src/server.rs:1305               # in-src test
crates/swift-http/src/server.rs:1551
crates/swift-http/src/server.rs:1622
crates/swift-http/src/server.rs:1698
crates/swift-http/src/server.rs:1738
crates/swift-http/src/server.rs:1768
crates/swift-http/src/server.rs:1796
crates/swift-http/src/server.rs:1831
crates/swift-http/src/server.rs:1912
crates/swift-http/src/server.rs:1943
crates/swift-s3api/src/middleware.rs:15404
crates/swift-s3api/src/middleware.rs:15475
crates/swift-s3api/src/middleware.rs:15495
crates/swift-db/src/replicator.rs:507
crates/swift-core/src/lockutil.rs:152
crates/swift-middleware/src/slo.rs:1223
crates/swift-middleware/src/slo.rs:1673
crates/swift-middleware/src/s3token.rs:537
```

**Reviewed: all listed.** Phase 1 did not remove OS-thread fan-out.

### Blocking-domain isolation score for this phase

| Question | Result |
|---|---|
| Application crate `spawn_blocking(` ? | **0** |
| Identifier `spawn_blocking` outside `src/blocking.rs`? | **0** |
| Network wait on BlockingDomain thread? | Domain unused on serve path; HTTP worker still waits (L1) |
| FS/SQLite on Tokio runtime thread? | No Tokio runtime on serve path; FS/SQLite still on HTTP worker (L2) |

## Unbounded resources remaining

### Checker pattern (hard-fail)

```text
rg -n --glob '*.rs' --glob '!target/**' \
   'unbounded_channel|crossbeam_channel::unbounded|::unbounded\(' crates
```

**0 occurrences.** Checker: `unbounded FAIL (prod src): 0`, `unbounded LIST (tests): 0`.

`tokio::sync::mpsc::unbounded` / `unbounded_channel`: **0**.

HTTP accept path uses **bounded** `crossbeam_channel::bounded` (`swift-http/src/server.rs:26`, `server.rs:310`).

OTLP exporter uses **bounded** `std::sync::mpsc::sync_channel(QUEUE_CAPACITY)` (`swift-core/src/otlp.rs:127`).

`BlockingDomain::submit` uses **bounded** `tokio::sync::mpsc::channel(1)` (`blocking.rs:435`).

### Unbounded `std::sync::mpsc::channel()` — 6 production sites (proxy fan-out)

Checker does **not** match this API. L3 residual. Full hits:

```
crates/swift-proxy-server/src/lib.rs:1531:        let (tx, rx) = mpsc::channel();   // make_requests
crates/swift-proxy-server/src/lib.rs:1619:        let (tx, rx) = mpsc::channel();   // stream_put_object
crates/swift-proxy-server/src/lib.rs:1836:        let (tx, rx) = mpsc::channel();   // post_fan_out
crates/swift-proxy-server/src/lib.rs:3938:        let (tx, rx) = mpsc::channel();   // EC put connect
crates/swift-proxy-server/src/lib.rs:4163:        let (tx, rx) = mpsc::channel();
crates/swift-proxy-server/src/lib.rs:4492:        let (tx, rx) = mpsc::channel();
```

`use std::sync::mpsc;` at `lib.rs:34`. Each replica thread can send without a pending-byte window. Phase 7 (`FanoutGroup` + bounded result stream). **Reviewed: 6. 6 L3 violations on the current proxy path.**

### Other unbounded / comment hits for the word `unbounded`

```
crates/swift-proxy-server/src/lib.rs:834:    // EOF unbounded.
crates/swift-http/src/thread_concurrency.rs:85:/// Cap matching existing Swift-Rust servers (avoid unbounded thread spawn).
crates/swift-http/src/server.rs:556:    /// unfinished chunked body (unbounded, never drained).
crates/swift-runtime/src/blocking.rs:73:    /// "unbounded" or "use Tokio defaults".
crates/swift-runtime/src/admission.rs:23://! an unbounded queue, and never invent a default cap.
```

**Reviewed: 5 comment/doc hits. 0 extra APIs.**

### Substrate internals without a numeric cap

```
crates/swift-runtime/src/scope.rs:50:    children: Mutex<Vec<Weak<CancelInner>>>,
```

Child-token Weak list grows with `child_token()` calls. Not a work queue; not fail-closed. TaskScope **jobs** are capped (`bound`). Phase 1 accepts this as a known L3 residual inside cancellation topology, not a job queue.

Listing / in-memory `Vec` collections in account/container/object listing paths were not exhaustively recapped this phase (same as Phase 0 follow-up).

**Unbounded audit: checker pattern 0 reviewed / 0 violations; `mpsc::channel()` 6 reviewed / 6 serve-path L3 residuals; CancellationToken Weak vec 1 reviewed / 1 uncapped topology list.**

## Unsafe code introduced

**None in Phase 1.** `swift-runtime` is `#![forbid(unsafe_code)]` (`lib.rs:24`).

```
rg -n 'unsafe' crates/swift-runtime
crates/swift-runtime/src/lib.rs:24:#![forbid(unsafe_code)]
```

Pre-existing `unsafe {` in production src (not introduced here; listed so this is not “none known”):

```
crates/swift-proxy-server/src/main.rs:843:            match unsafe { libc::fork() } {
crates/swift-ec/src/lib.rs:116,167,180,212,226,253,267,291,310,431,444
crates/swift-http/src/server.rs:165,181,195,199,202,234,237,239,242,266,1969
crates/swift-core/src/localdev.rs:33
crates/swift-core/src/lockutil.rs:64,109
crates/swift-core/src/fsutil.rs:34,38
crates/swift-object-server/src/localdev.rs:53
```

**Files with `unsafe {` (prod src): 7.** HTTP bind_listener `from_raw_fd` unchanged from Phase 0. EC liberasurecode FFI unchanged.

`#![forbid(unsafe_code)]` exists only on `swift-runtime` this phase. HTTP crate is **not** yet `forbid` (`AGENTS.md` §24 is Phase 12 remaining work on application crates).

## Regression analysis

- Serve path not modified. Worker defaults not modified.
- Gate 1 test still FAILs with the same WouldBlock @400ms signature as Phase 0. That is required: Phase 1 must not hide L1.
- `swift-runtime` tests: 38/38 pass.
- Concurrency-boundary checker: PASS (0 hard failures). Proxy `std::net` remains 16 WARN.
- No semantic change to PUT/GET/COPY/SSYNC/S3.
- Risk of a later phase wrapping `Handler` in `BlockingDomain::submit`: **forbidden**. CI will FAIL any `spawn_blocking` outside `src/blocking`.

## GO / NO-GO recommendation

| Question | Verdict |
|---|---|
| Runtime substrate crate present with admission / scope / deadlines / BlockingDomain / traffic class? | **GO** |
| `cargo test -p swift-runtime` 38/38? | **GO** |
| `spawn_blocking` confined to `crates/swift-runtime/src/blocking` (16 ALLOW, 0 FAIL, 1 call)? | **GO** |
| Checker `exit 0` / unbounded_channel 0 / tokio::fs 0? | **GO** |
| Tokio sealed (only `swift-runtime` depends on it; no `tokio::fs` / `Semaphore` in app crates)? | **GO** |
| Serve architecture unchanged (no custom mio reactor, no Hyper, no worker-default change)? | **GO** (correct for Phase 1) |
| Idle connection ≠ worker thread (Gate 1)? | **NO-GO** (`worker_starvation` FAIL, WouldBlock) |
| Slow PUT/GET ≠ blocking worker (Gate 2)? | **NO-GO** (server unchanged) |
| fsync/sqlite/FFI ≠ network runtime (Gate 3)? | **NO-GO** (single thread domain on serve path) |
| Bounded overload as a complete model (Gate 4)? | **NO-GO** (proxy `mpsc::channel()` × 6 still unbounded) |
| Semantic parity claimed (Gate 5)? | **NO-GO** (not claimed; differential not run) |
| Claim “Eventlet problem solved”? | **NO-GO** (Gates 1–5 unmet) |
| Wrap current Handler in `spawn_blocking` as Phase 2? | **NO-GO** (NON-GOAL 4) |
| Raise product `workers` as the L1 fix? | **NO-GO** (NON-GOAL 13; L1) |

**Phase 1 substrate verdict: GO.**

Conditions the constitution named for this phase both hold: `cargo test -p swift-runtime` passed, and `spawn_blocking` is confined.

**Release / Eventlet verdict: NO-GO.** Gate 1 is still NO-GO because the server is unchanged.

Phase 2 (async HTTP core, Tokio+Hyper HTTP/1.1, connection ≠ request) may start. It must wire `AdmissionController` / `TaskScope` / typed deadlines onto a new connection runtime. It must **not** declare Gate 1 GO until `worker_starvation` is green on that runtime. It must **not** put object PUT/GET through `LegacyServiceAdapter` / a whole-handler `BlockingDomain` job.
