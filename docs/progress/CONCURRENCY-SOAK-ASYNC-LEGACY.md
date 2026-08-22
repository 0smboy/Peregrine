# Soak, async default, legacy removal (AGENTS.md §29 soak + idle density, §31)

**Date:** 2026-08-21
**Tree:** `.agent-handoff/peregrine-grok-merge-20260814/swift-rust`
**Occupancy:** `spawn_server(2)` / `worker_threads=2`

## Soak (§29)

Shipped driver: `crates/swift-http/tests/concurrency/soak.rs` on `serve_with_config` (ObjectServer `AsyncService` / Hyper HTTP/1.1). Program default **86400s**. Injections on that path: missing-device PUT (backend fail-closed), slow PUT body, `commit_stall` fsync, shutdown+respawn worker restart. After drain `commit_shield_active==0`; `open_fds` / `process_threads` / `runtime_tasks` must not grow without bound; RSS must not increase on every sample.

**GO** for the soak program. Session recapture used `PEREGRINE_SOAK_SECS=15` of the same driver (`soak.log` ×2 ok). 24h wall-clock did not run here (`soak-24h-unavailable.log`).

## Idle density

`idle_density.rs` climbs once toward 100k at `worker_threads=2`. This OS refused further connects at **4090**. Occupancy probe (dedicated keep-alive, then GET on a held waiting connection) must return **200**; **503 fails the test**. `idle-density.log` ×2: `health=200` at 4090 held. **Not** 10k/50k/100k sockets.

## Async default (§31)

Production object / proxy / account / container entry calls `serve_forever_multi_service`. No `server_runtime` flag is required. `server_runtime=legacy` is a hard startup error (`reject_legacy_server_runtime`). Worker/process defaults are unchanged (`workers=0` keeps existing CPU-scaled default).

`async_default_launch.log` ×2: real `swift-object-server` binary, `/recon/concurrency` snapshot, PUT 201 + GET body, legacy flag exits non-zero.

**GO** for async as the only production default.

## Legacy production serve removed

Object/proxy/account/container production src does not construct `LegacyService` or call `handle_connection`. CI `legacy production FAIL: 0`. `legacy_removed.log` ×2: checker PASS + 5 tests including shipped object PUT/GET on `serve_with_config`. `handle_connection` remains the HTTP crate **unit-test** round-trip path only. `LegacyService` remains the small-handler adapter used by occupancy `spawn_server(2)` (HEAD/tiny body), not Object PUT/GET/COPY/SSYNC.

**GO** for one production connection engine (`hyper/http1`).

## Not claimed

§29 throughput ±5% / p99 ±10% vs Python baseline; live 24h wall-clock; 10k/50k/100k sockets on this OS; live pyeclib SAIO.
