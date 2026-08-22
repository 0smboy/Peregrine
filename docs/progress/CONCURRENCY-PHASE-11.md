# CONCURRENCY-PHASE-11

**Phase:** 11 — Observability  
**Date:** 2026-08-20  
**Tree:** `.agent-handoff/peregrine-grok-merge-20260814/swift-rust`

## Scope completed

Queryable `ConcurrencyMetrics` snapshot on the shipped Hyper path (`GET /recon/concurrency` and in-process `snapshot()` / `render()`). All AGENTS.md §23 names are present. Labels are only `{phase}` / `{reason}`. Forbidden high-cardinality labels (`object_path=`, `trans_id=`, `container=`, `account=`) are rejected by test.

## Files changed

- `crates/swift-runtime/src/metrics.rs`
- `crates/swift-runtime/src/{lib,context,scope,fanout,db_exec}.rs`
- `crates/swift-http/src/{server,hyper_serve}.rs`
- `crates/swift-object-server/src/lib.rs`
- `crates/swift-account-server/src/lib.rs`, `crates/swift-container-server/src/lib.rs`
- `crates/swift-http/tests/concurrency/phase11_metrics.rs`

## Tests passed

`phase11-metrics.log`: HTTP crate 5/5 ×2 plus runtime
`metrics::tests::storage_and_db_gauges_move_then_return_to_zero` ×2 (`device_ops_active` and `db_ops_active` move then return to 0 on shipped StorageExecutor / DbExecutor)
and `metrics::tests::fanout_inflight_and_cancel_reason_move` ×2 (`backend_requests_inflight` / `backend_queue_depth` move, `cancellations_total{reason=quorum}` increments, inflight returns to 0).

HTTP crate 5: `snapshot_moves_on_admitted_request_and_recon_endpoint`, `admission_reject_increments_snapshot`, `body_idle_timeout_increments_labeled_counter`, `incoming_body_buffer_bytes_move_on_from_bytes`, `commit_shield_and_device_gauges_during_put_finalize`.

Named gauges asserted present: `connections_open`, `connections_idle`, `requests_active`, `runtime_tasks`, `runtime_scheduler_lag`, `admission_rejected_total`, `request_body_buffer_bytes`, `response_body_buffer_bytes`, `backend_requests_inflight`, `backend_queue_depth`, `device_ops_active`, `device_queue_depth`, `device_queue_wait_seconds`, `db_ops_active`, `db_queue_depth`, `db_queue_wait_seconds`, `timeouts_total`, `cancellations_total`, `commit_shield_active`, `graceful_shutdown_requests`, `process_threads`, `open_fds` (plus `shutdown_waiting_*` for Phase 14).

## Blocking operations remaining

`rg -n 'spawn_blocking\(' crates --glob '!**/target/**'` performed.  
**1 occurrence reviewed, 0 violations** (unique site is the blocking domain):

```
crates/swift-runtime/src/blocking.rs:577:    let join = tokio::task::spawn_blocking(run);
```

## Unbounded resources remaining

`rg -n 'unbounded_channel\(' crates --glob '!**/target/**'` performed.  
**0 occurrences reviewed, 0 violations.**

## GO / NO-GO recommendation

**GO for Phase 11.** Snapshot moves under real admitted requests, storage/DB/fan-out, timeouts, cancellations, and commit-shield. No high-cardinality metric labels.

This phase note does **not** claim Eventlet-solved. That is Gates 1–5 after Phases 11–14 (`phase-gogo.txt`).
