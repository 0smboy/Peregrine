# CONCURRENCY-PHASE-14

**Phase:** 14 — Graceful shutdown
**Date:** 2026-08-21
**Tree:** `.agent-handoff/peregrine-grok-merge-20260814/swift-rust`

## Scope completed

SIGTERM flag (`ServerConfig.shutdown` / `install_sigterm_flag`) drives: StopAccepting → close idle keep-alives → stop admit (503) → cancel cancellable in-flight (`tokio::sleep` request, not a blocking `thread::sleep`) → wait this connection's durability (`DurabilityBarrier::run_shielded` on a tracked task; HTTP Future drop does not abort commit) → drain the HTTP response after `complete()` → `ShutdownDeadline` → force HTTP off. Commit-shield JoinHandles are joined, never aborted. `shutdown_waiting_requests` / `shutdown_waiting_commits` update while waiting.

## Recapture bug (fixed on shipped path)

2026-08-21 recapture of `commit_shield_survives_shutdown_and_gauges_are_readable` failed: shielded PUT returned **0** instead of **201**.

Cause: after `DurabilityBarrier::complete()` the process-wide `commit_shield_active` dropped to 0 while `inflight` was still 1 (ObjectServer still writing 201). The Hyper shutdown loop treated `commits == 0` as “cancellable” and dropped the connection.

Fix:
- Per-connection `CONN_SHIELDS` task-local, incremented by `commit_shield_inc` / `dec`.
- `run_shielded` and `TaskScope::spawn` re-bind metrics **and** the connection counter after `tokio::spawn` (task-locals do not inherit).
- Shutdown: idle close when this connection's inflight and conn-shields are 0; drain while this connection saw a shield (do not cancel the 201); cancel only never-shielded in-flight; force at `ShutdownDeadline` without aborting shields.

## Files changed

- `crates/swift-http/src/hyper_serve.rs`
- `crates/swift-runtime/src/metrics.rs`
- `crates/swift-runtime/src/context.rs`
- `crates/swift-runtime/src/scope.rs`

## Tests passed

`phase14-shutdown.log` ×2: 5 passed, 0 failed (scratch recapture 2026-08-21)
- `stop_accept_does_not_admit_a_new_request`
- `idle_keepalive_is_closed_on_shutdown`
- `cancellable_inflight_is_cancelled_when_not_in_commit_shield` (yielding `AsyncService` `tokio::sleep`, asserts `cancellations_total{reason=shutdown}` and handler `finished==false`)
- `commit_shield_survives_shutdown_and_gauges_are_readable` (real ObjectServer PUT stall, **201 after SIGTERM/stop-accept** once stall is released)
- `shutdown_deadline_forces_http_without_ambiguous_commit` (client read timeout 10s vs `ShutdownDeadline` 1s: HTTP closes in <1.5s, `timeouts_total{phase=shutdown}>=1`, shielded `durable.commit` still writes `.data`)

Also `context::tests::run_shielded_increments_connection_local_counter`.

Occupancy remains `spawn_server(2)`.

## Blocking / unbounded

`rg -n 'spawn_blocking\(' crates --glob '*.rs'` performed.
**1 occurrence reviewed, 0 violations:** `crates/swift-runtime/src/blocking.rs:577`

`rg -n 'unbounded_channel\(' crates --glob '*.rs'` performed.
**0 occurrences reviewed, 0 violations.**

## GO / NO-GO

**GO for Phase 14.** Durability barrier is not cancelled by dropping the client/shutdown future; after commit this connection is drained so the client still gets 201 when the deadline has not fired; idle and never-shielded requests are cancelled; force still increments `timeouts_total{phase=shutdown}`.

**Eventlet-solved:** see `phase-gogo.txt`.
