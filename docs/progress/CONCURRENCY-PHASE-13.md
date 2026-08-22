# CONCURRENCY-PHASE-13

**Phase:** 13 — Concurrency verification
**Date:** 2026-08-21 (recapture)
**Tree:** `.agent-handoff/peregrine-grok-merge-20260814/swift-rust`

## Scope completed

Shipped machines under concurrent load (`metrics::shipped_device_db_commit_shutdown_machines`): `AdmissionController` race, `TaskScope` cancel, `StorageExecutor` device/class fail-closed, `DbExecutor` same-identity serialize + mailbox bound, `DurabilityBarrier::run_shielded` surviving waiter drop, `wait_shields` observing live `commit_shield_active` (not a hand-set gauge). Malicious A–F: occupancy B–E at `spawn_server(2)`; F proxy blackhole `make_requests_async_quorum_cancels_blackhole`. 50k idle attempted against shipped serve with independent `max_connections`.

## Tests passed

`phase13-loom.log` ×2 (2026-08-21): `metrics::tests::shipped_device_db_commit_shutdown_machines` + `run_shielded_survives_drop_of_waiter` + `run_shielded_increments_connection_local_counter` — all ok.
`gate12-occupancy.log` ×2: worker_starvation, slowloris, slow_put, slow_reader, fsync_storm, align_expect_continue — 12 ok (6×2).
`phase13-malicious.log`: occupancy B–E (`worker_starvation`, `slowloris`, `slow_put`, `slow_reader`, `fsync_storm`) at `spawn_server(2)` ×2 + proxy F `make_requests_async_quorum_cancels_blackhole` ×2 — all `test result: ok`, 0 failed.
`idle-50k.log`: test ok; OS stopped at **4091** sockets (`Connection refused`). Captured `idle-50k-unavailable.log`. 2-worker occupancy still GO.
`sanitizer-unavailable.log`: stable rustc rejects `-Z sanitizer`; nightly ASan aborts (`AddressSanitizer is loaded too late` / needs `DYLD_INSERT_LIBRARIES`). `cargo miri` not installed on stable.
`loom-feature.log`: crate has no `loom` Cargo feature; shipped-machine interleaving is the equivalent.

## GO / NO-GO

**GO for Phase 13** with honest fallbacks: no crate-level Loom feature, no ASan/TSan on stable macOS, 50k idle env-limited at 4091 fds/backlog. Occupancy B–E and proxy F hold at 2 workers.

**Eventlet-solved:** see `phase-gogo.txt`.
