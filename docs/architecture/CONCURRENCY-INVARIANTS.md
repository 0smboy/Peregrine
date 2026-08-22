# Concurrency invariants (L1–L10)

Source of truth: `AGENTS.md` PEREGRINE CONCURRENCY LAWS.  
**Phase 0 status** of the *current* sync server. Phase 0 does not fix violations.

| Law | Statement | Current sync server |
|---|---|---|
| **L1** | No network wait may occupy a blocking worker. | **VIOLATED.** Keep-alive `read_head`, backend `connect`/`read`, slow client `write` all run on the HTTP worker. |
| **L2** | No blocking FS/SQLite/FFI/EC/durability on a network runtime thread. | **VIOLATED** in the only thread that exists: PUT `fsync`/`xattr`/`rename` and rusqlite run on the same worker that owns the client socket. (There is no separate network runtime yet.) |
| **L3** | Every queue/buffer/pool is finite. | **MOSTLY HELD** at HTTP accept: `connection_queue` is bounded; overflow → 503. Body cap `max_body_bytes`. Crossbeam channel is bounded. No `unbounded_channel` in `swift-rust` src. |
| **L4** | Backpressure toward the producer; memory is not overload control. | **PARTIAL.** Accept queue 503s. Proxy fan-out does not stop reading the client when a replica stalls (no per-backend pending-byte window). |
| **L5** | Connection, request, backend, device, DB, memory concurrency are independent. | **VIOLATED.** `workers` is the only real execution budget on the serve path. `max_clients` is the accept queue, not green concurrency. |
| **L6** | Structured hierarchical cancellation; no detached request tasks. | **N/A / weak.** No request task tree. Panic is caught per connection. No `CancellationToken`. Backend waits use socket timeouts, not a parent scope. |
| **L7** | Durability commit is a protected transition; dropping a Future must not leave durability ambiguous. | **PARTIAL (sync).** PUT is a blocking procedure on one thread, so drop-a-Future does not apply. There is no named DurabilityBarrier state machine. Client disconnect mid-fsync is not a specified commit-shield. |
| **L8** | Client / replication / maintenance have independent budgets. | **VIOLATED.** SSYNC, replicator, auditor, expirer, client PUT share process/thread pools without traffic-class admission. |
| **L9** | Swift wire/storage semantics must not change because the execution model changes. | **CONSTRAINT.** Phase 0 does not change semantics. Later phases must differential-test. |
| **L10** | No optimization may weaken correctness, observability, boundedness, or isolation. | **CONSTRAINT.** SAIO `workers=64` is explicitly **not** an L1 fix. |

## Gate mapping (AGENTS.md §35)

| Gate | Required | Phase 0 |
|---|---|---|
| 1 Idle scalability | idle connection ≠ worker thread | **FAIL** (see `worker_starvation`) |
| 2 Streaming scalability | slow PUT/GET ≠ blocking worker | **FAIL** (see `slow_put`, `slow_reader`) |
| 3 Blocking isolation | fsync/sqlite/FFI ≠ network runtime | **FAIL** (single thread domain) |
| 4 Bounded overload | overload → shed, not RSS/thread explosion | **PARTIAL** (503 on accept queue only) |
| 5 Semantic parity | Python ≈ Peregrine | unchanged; not claimed |

A law or gate listed FAIL/VIOLATED cannot be waived by a faster s3-tests wall clock.
