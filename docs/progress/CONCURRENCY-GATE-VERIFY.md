# CONCURRENCY-GATE-VERIFY

**Date:** 2026-08-20T06:51:33Z (UTC)  
**Tree:** `.agent-handoff/peregrine-grok-merge-20260814`  
**Workspace:** `swift-rust/`  
**Constitution:** `/Users/oboy/Downloads/swift-master/AGENTS.md` L1–L10  
**Product:** `/Users/oboy/Downloads/swift-master/.agent-handoff/peregrine-grok-merge-20260814/swift-rust`  
**Tooling:** rustc 1.93.0 (254b59607 2026-01-19); cargo 1.93.0 (083ac5135 2025-12-15)  
**Constraints honored:** did not raise `worker_threads`; did not edit tests to skip; did not claim Eventlet solved.

> **2026-08-21 recapture:** This note is an earlier cargo-slice GO. Current Gates 1–5 / Eventlet-solved under plan fallbacks is `phase-gogo.txt`. Scratch logs live in the goal implementer dir (occupancy, isolation, overload, Gate5, phase11/13/14, CI, idle-50k, sanitizer).

## Recommendation

**GO** — every executed test in the four specified cargo commands passed (69 tests, 0 failed, 0 ignored). No required test file was missing.

This GO covers **only** the cargo commands below. It is **not** an Eventlet-solved claim and **not** AGENTS.md §35 Gate 1–5 production completion (no 10k/50k/100k idle density, no Python differential, no soak, no full serve-path L1–L10 audit in this run).

## Test file presence

| Gate command | Required files | Present? |
|---|---|---|
| `swift-http` 6 `--test` crates | `crates/swift-http/tests/concurrency/{worker_starvation,slow_put,slow_reader,slowloris,align_expect_continue,fsync_storm}.rs` | **yes** (`Cargo.toml` `[[test]]` paths) |
| `swift-runtime --lib` | `crates/swift-runtime/src/lib.rs` | **yes** |
| `swift-diskfile --test storage_isolation` | `crates/swift-diskfile/tests/storage_isolation.rs` | **yes** |
| `swift-db --test db_isolation` | `crates/swift-db/tests/db_isolation.rs` | **yes** |

Missing-file rule: not triggered. No gate is NO-GO for a missing test file.

## Commands (cwd)

```text
cd /Users/oboy/Downloads/swift-master/.agent-handoff/peregrine-grok-merge-20260814/swift-rust
```

`--test-threads=1` on all four. No `-- --skip`. No worker-count flags.

## Results

| # | Command | Exit | Summary |
|---|---|---|---|
| 1 | `cargo test -p swift-http --test worker_starvation --test slow_put --test slow_reader --test slowloris --test align_expect_continue --test fsync_storm -- --test-threads=1` | **0 PASS** | 6 tests, 6 ok |
| 2 | `cargo test -p swift-runtime --lib -- --test-threads=1` | **0 PASS** | 57 passed; 0 failed |
| 3 | `cargo test -p swift-diskfile --test storage_isolation -- --test-threads=1` | **0 PASS** | 2 passed; 0 failed |
| 4 | `cargo test -p swift-db --test db_isolation -- --test-threads=1` | **0 PASS** | 4 passed; 0 failed |

**Totals:** 69 passed; 0 failed; 0 ignored.

---

### Command 1 — `swift-http` concurrency suite

**Start:** 2026-08-20T06:51:32Z  
**End:** 2026-08-20T06:51:32Z  
**Exit:** 0

```text
warning: method `prepend` is never used
   --> crates/swift-http/src/server.rs:556:8
    |
547 | impl ConnRead {
    | ------------- method in this implementation
...
556 |     fn prepend(&mut self, data: &[u8]) {
    |        ^^^^^^^
    |
    = note: `#[warn(dead_code)]` (part of `#[warn(unused)]`) on by default

warning: `swift-http` (lib) generated 1 warning
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.03s
     Running tests/concurrency/align_expect_continue.rs (target/debug/deps/align_expect_continue-3d80f3762e5f2fd6)

running 1 test
test three_keepalive_clients_with_two_workers_expect_continue_is_not_starved ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.09s

     Running tests/concurrency/fsync_storm.rs (target/debug/deps/fsync_storm-29ffa8b59ea4ff04)

running 1 test
test fsync_storm_does_not_starve_a_health_get ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s

     Running tests/concurrency/slow_put.rs (target/debug/deps/slow_put-3755c17ed871dde9)

running 1 test
test slow_put_body_does_not_starve_a_health_get ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.09s

     Running tests/concurrency/slow_reader.rs (target/debug/deps/slow_reader-7348d3388afbd5a5)

running 1 test
test slow_get_reader_does_not_starve_a_health_get ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.09s

     Running tests/concurrency/slowloris.rs (target/debug/deps/slowloris-bec955d15d746b75)

running 1 test
test slow_headers_do_not_starve_healthy_requests ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.09s

     Running tests/concurrency/worker_starvation.rs (target/debug/deps/worker_starvation-334abd87fcaec546)

running 1 test
test idle_keepalive_does_not_starve_a_third_request ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.09s
```

| Test binary | Test fn | PASS/FAIL |
|---|---|---|
| `worker_starvation` | `idle_keepalive_does_not_starve_a_third_request` | **PASS** |
| `slow_put` | `slow_put_body_does_not_starve_a_health_get` | **PASS** |
| `slow_reader` | `slow_get_reader_does_not_starve_a_health_get` | **PASS** |
| `slowloris` | `slow_headers_do_not_starve_healthy_requests` | **PASS** |
| `align_expect_continue` | `three_keepalive_clients_with_two_workers_expect_continue_is_not_starved` | **PASS** |
| `fsync_storm` | `fsync_storm_does_not_starve_a_health_get` | **PASS** |

---

### Command 2 — `swift-runtime --lib`

**Start:** 2026-08-20T06:51:32Z  
**End:** 2026-08-20T06:51:33Z  
**Exit:** 0

```text
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.02s
     Running unittests src/lib.rs (target/debug/deps/swift_runtime-361bc6f5ed16b390)

running 57 tests
test admission::tests::class_budgets_are_independent_not_shared_fifo ... ok
test admission::tests::concurrent_class_caps_stay_isolated ... ok
test admission::tests::concurrent_try_acquire_never_exceeds_connection_cap ... ok
test admission::tests::connections_and_requests_are_independent ... ok
test admission::tests::construction_requires_all_caps_and_has_no_default ... ok
test admission::tests::drop_releases_both_request_and_class_slots ... ok
test admission::tests::legacy_max_clients_aliases_active_requests_not_connections ... ok
test admission::tests::reject_when_class_full_does_not_consume_global_request ... ok
test admission::tests::reject_when_connections_full ... ok
test admission::tests::reject_when_requests_full ... ok
test admission::tests::zero_cap_fails_closed ... ok
test blocking::tests::abort_queued_job_does_not_stop_in_flight ... ok
test blocking::tests::job_runs ... ok
test blocking::tests::reject_when_queue_full ... ok
test blocking::tests::rejects_zero_bounds ... ok
test blocking::tests::thread_cap_is_respected ... ok
test context::tests::child_context_cancel_does_not_cancel_parent ... ok
test context::tests::durability_barrier_drop_without_complete_is_forbidden - should panic ... ok
test context::tests::durability_barrier_type_exists ... ok
test context::tests::parent_cancel_stops_child_spawned_task ... ok
test context::tests::parent_cancels_child ... ok
test context::tests::request_context_holds_required_fields ... ok
test db_exec::tests::connection_cap_fails_closed_on_new_identity ... ok
test db_exec::tests::different_shards_run_in_parallel ... ok
test db_exec::tests::mailbox_full_fails_closed ... ok
test db_exec::tests::rejects_zero_shard_or_mailbox ... ok
test db_exec::tests::rusqlite_runs_on_executor_not_caller ... ok
test db_exec::tests::same_db_is_serialized ... ok
test db_exec::tests::same_path_same_shard ... ok
test db_exec::tests::shard_owns_connection_state ... ok
test db_exec::tests::zero_connection_cap_never_opens ... ok
test deadline::tests::all_ten_kinds_exist_and_body_idle_is_not_upload_lifetime ... ok
test deadline::tests::body_idle_and_upload_lifetime_are_distinct_parameters ... ok
test deadline::tests::body_idle_refresh_on_progress_extends_deadline ... ok
test deadline::tests::each_struct_reports_its_kind ... ok
test deadline::tests::refresh_body_idle_does_not_move_upload_lifetime ... ok
test deadline::tests::zero_timeout_is_expired ... ok
test scope::tests::child_cancel_does_not_cancel_sibling_or_parent ... ok
test scope::tests::child_does_not_cancel_parent ... ok
test scope::tests::child_scope_cancel_is_hierarchical ... ok
test scope::tests::drop_aborts_children_no_detach ... ok
test scope::tests::join_waits_for_children ... ok
test scope::tests::parent_cancels_child ... ok
test scope::tests::parent_scope_cancels_spawned_child_task ... ok
test scope::tests::spawn_respects_finite_bound ... ok
test storage::tests::device_and_class_budgets_are_independent ... ok
test storage::tests::device_busy_does_not_submit_posix_work ... ok
test storage::tests::queue_full_fails_closed_and_does_not_write ... ok
test storage::tests::rejects_zero_domain_bounds ... ok
test storage::tests::run_finite_holds_device_permit_and_does_not_block_reactor ... ok
test storage::tests::threaded_posix_io_runs_on_blocking_domain ... ok
test storage::tests::write_at_does_not_truncate ... ok
test storage::tests::write_at_is_a_chunk_not_a_whole_put ... ok
test storage::tests::write_sync_all_rename_are_separate_posix_ops ... ok
test storage::tests::zero_device_cap_fails_closed ... ok
test traffic::tests::exhaustive_match_has_no_wildcard_arm ... ok
test traffic::tests::four_named_classes_no_catch_all ... ok

test result: ok. 57 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.20s
```

---

### Command 3 — `swift-diskfile` `storage_isolation`

**Start:** 2026-08-20T06:51:33Z  
**End:** 2026-08-20T06:51:33Z  
**Exit:** 0

```text
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.03s
     Running tests/storage_isolation.rs (target/debug/deps/storage_isolation-5a17e89c8ffb49f6)

running 2 tests
test diskfile_put_does_not_block_reactor_or_try_acquire ... ok
test diskfile_put_finalize_runs_on_storage_executor ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.03s
```

| Test fn | PASS/FAIL |
|---|---|
| `diskfile_put_does_not_block_reactor_or_try_acquire` | **PASS** |
| `diskfile_put_finalize_runs_on_storage_executor` | **PASS** |

---

### Command 4 — `swift-db` `db_isolation`

**Start:** 2026-08-20T06:51:33Z  
**End:** 2026-08-20T06:51:33Z  
**Exit:** 0

```text
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.03s
     Running tests/db_isolation.rs (target/debug/deps/db_isolation-169f1b5df3b43306)

running 4 tests
test account_broker_does_not_block_reactor ... ok
test account_broker_put_container_runs_on_db_executor ... ok
test container_broker_does_not_block_reactor ... ok
test container_broker_put_object_runs_on_db_executor ... ok

test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.06s
```

| Test fn | PASS/FAIL |
|---|---|
| `account_broker_does_not_block_reactor` | **PASS** |
| `account_broker_put_container_runs_on_db_executor` | **PASS** |
| `container_broker_does_not_block_reactor` | **PASS** |
| `container_broker_put_object_runs_on_db_executor` | **PASS** |

---

## What this does / does not prove

In-process probes (`swift-http` keep-alive / slow PUT / slow GET / slowloris / Expect: 100-continue / fsync-storm; `swift-runtime` lib units; diskfile/db executor isolation) are green.

Not proven here, and **not** claimed:

- Eventlet semantic replacement complete
- AGENTS.md §35 Gate 1 idle scalability at 10k/50k/100k
- Python Swift differential (§28)
- 24h soak, fault-injection matrix, proxy blackhole, process-model / worker-default freeze beyond these tests

Compiler warning on unused `ConnRead::prepend` in `swift-http` is recorded, not treated as a test failure.

## GO / NO-GO

**GO** for the four executed cargo commands.

**Not** Eventlet-solved.

---

## Adversarial HTTP serve audit — `check-concurrency-boundaries.sh` + `server.rs`

**Date:** 2026-08-20T06:54:08Z (UTC)  
**Constraint:** `src/` not edited. Eventlet **not** claimed solved.

### `ci/check-concurrency-boundaries.sh`

```text
bash /Users/oboy/Downloads/swift-master/.agent-handoff/peregrine-grok-merge-20260814/swift-rust/ci/check-concurrency-boundaries.sh
```

| Field | Value |
|---|---|
| **Exit code** | **0** |
| files scanned | 224 |
| `spawn_blocking` FAIL | 0 |
| `spawn_blocking` ALLOW | 16, all `crates/swift-runtime/src/blocking.rs` |
| unbounded FAIL (prod src) | 0 |
| `tokio::fs` FAIL | 0 (`swift-http` / `swift-proxy-server` / `swift-s3api`) |
| `std::net` WARN (proxy src) | **16** (script: “not a fail until Phase 2”) |
| hard failures | 0 |
| script summary | `PASS` |

Exit 0 is **boundary-scan PASS**, not a Phase 3 streaming ABI GO. The 16 proxy `std::net::TcpStream` WARNs remain (connect/read on `std::net` in `swift-proxy-server/src/lib.rs`). Unique `spawn_blocking` call site is `blocking.rs:577`. **Zero** `spawn_blocking` in `crates/swift-http`.

### File read

`/Users/oboy/Downloads/swift-master/.agent-handoff/peregrine-grok-merge-20260814/swift-rust/crates/swift-http/src/server.rs`

`rg spawn_blocking` on that file: **no matches**. Same for `crates/swift-http` as a crate.

Module comment L26–27 claims “Bodies STREAM … Nothing object-sized is buffered here.” That is **false** of the production Handler path (L81–108). Treat the comment as marketing, not as the ABI.

### Confirm 1 — keep-alive wait is `tokio::time::timeout`, not a dedicated OS worker

**Confirmed.** Production loop is `accept_loop_async` → `JoinSet::spawn` of `handle_connection_async` (L481–486). Idle wait is **not** `thread → blocking read()`.

Keep-alive first-byte wait (`read_head_async`, L864–871):

```text
if keepalive {
    let wait = idle.unwrap_or(Duration::from_secs(24 * 3600));
    match tokio::time::timeout(wait, reader.fill_buf()).await {
        Err(_) => return Ok(None),
        Ok(Ok([])) => return Ok(None),
        ...
    }
}
```

Header lines use the same primitive (`read_line_async`, L929–930): `tokio::time::timeout(t, reader.read_until(...))`. `ConnRead::poll_read` / `poll_fill_buf` are reactor `Poll::Pending`, not `std::net::TcpStream::read`. `worker_threads` sizes the Tokio runtime (L133–134, L379–388), not one OS thread per connection.

Caveat (does not refute the confirm): `#[allow(dead_code)] handle_connection` (L1326+) is still a blocking `TimedStream` / `set_read_timeout` path. File claims it is the unit-test path, not production accept. Production `serve_forever*` does **not** call it.

### Confirm 2 — `handler()` still runs on the runtime thread

**Confirmed.** `LegacyService::call` (L81–108) is an `async move` on the connection task:

1. `req.body.materialize(max).await`
2. `catch_unwind(|| handler(request))` — **synchronous**, in the Future, on the Tokio worker
3. comment L69–70: “run the sync Handler on the Tokio task. Not `BlockingDomain::submit(handler)`.”

There is no `BlockingDomain`, no `spawn_blocking`, no off-runtime hop around `handler()`. `serve_forever_multi` (L389) always wraps the production `Handler` in `LegacyService`. If that `Handler` does disk/SQLite/FFI, it runs on the network runtime thread (L2). Occupancy tests stay green because they use tiny CPU handlers.

`write_response_async` `Body::Streamed` (L1012–1021) also does `src.read(&mut buf)?` (`std::io::Read`) on that same runtime thread.

### Confirm 3 — request bodies are `Body::Buffered`

**Confirmed.** `LegacyService` is the only `Handler` adapter. It always:

```text
let body = match req.body.materialize(max).await {
    Ok(bytes) => Body::Buffered(bytes),
    ...
};
```

`IncomingBody::materialize` (L738–748) loops `next_chunk` into a `Vec` until EOF, cap `max_body_bytes` (`ServerConfig` default = `MAX_FILE_SIZE`). That is whole-object buffering (NON-GOAL 8), not a streaming ABI.

`IncomingBody::next_chunk` exists (L654). Production `serve_forever` / `serve_forever_with_config` / `serve_forever_multi` never hand it to a `Handler`. `AsyncService::call` still returns `Response` (`Body`), not `OutgoingBody`. No `RequestContext`.

Corroboration (read-only grep, not a `src/` edit): object `handle_async` (`swift-object-server/src/lib.rs:565–581`) and account `AccountAsyncService` also `materialize` → `Body::Buffered` before the sync handler. Proxy/container still `serve_forever*` → `LegacyService`.

### Confirm 4 — `spawn_blocking` absent from `server.rs`

**Confirmed.** `rg spawn_blocking crates/swift-http/src/server.rs` → 0 hits. `JoinSet::spawn` of async tasks (acceptors L445, connections L481) is not `tokio::task::spawn_blocking`. Test helpers use `std::thread::spawn` around `serve_forever_with_config`.

Absence of `spawn_blocking` in HTTP is the **required** CI rule. It is **not** proof of a streaming ABI. The replacement is “async materialize + whole Handler on Tokio,” which is AGENTS.md §8’s forbidden shape with the blocking pool deleted.

### Phase 3 streaming ABI

| Gate | Result |
|---|---|
| AGENTS.md §8 target `async fn call(ctx, Request<IncomingBody>) -> Result<Response<OutgoingBody>>` | **not present** |
| Request body wait off blocking worker (`next_chunk` as handler ABI) | **occupancy only**; Handler sees `Body::Buffered` |
| §9 Legacy adapter limited to HEAD / small metadata / bounded small body | **violated** — `LegacyService` is the default for all methods |
| NON-GOAL 8 (do not buffer an entire object) | **violated** |
| Bodies fully buffered | **yes** |

**Phase 3 streaming ABI: NO-GO.**

Idle keep-alive as a pending Future and `spawn_blocking` confined to `swift-runtime/src/blocking.rs` do not make this a GO. File-header “Bodies STREAM” is contradicted by `LegacyService::call`.

### GO / NO-GO (this audit)

| Item | Verdict |
|---|---|
| `check-concurrency-boundaries.sh` | **GO** (exit 0) |
| Keep-alive = tokio timeout / pending Future, not dedicated OS worker | **confirmed** |
| `handler()` on Tokio runtime thread | **confirmed** |
| Request bodies `Body::Buffered` via full `materialize` | **confirmed** |
| `spawn_blocking` absent from `server.rs` | **confirmed** |
| Phase 3 streaming ABI | **NO-GO** |
| Eventlet solved / AGENTS.md §35 Gate 1–5 | **not claimed** |

