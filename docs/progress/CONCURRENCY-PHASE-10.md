# CONCURRENCY-PHASE-10

**Phase:** 10 — Process model
**Date:** 2026-08-20

## Scope completed

Four dimensions stay distinct: processes (`process_workers`), runtime threads (`worker_threads`), async tasks, storage threads. `workers=8` without `worker_model` → `process_workers=1`. Occupancy remains `spawn_server(2)`. Prefork retained.

## Tests passed

`process-isolation.txt` (prior recapture) `startup_policy_tests::process_workers_conf_parses` ×2.
`gate12-occupancy.log` `2026-08-20T14:36:56Z` ×2 at 2 workers.

## GO / NO-GO

**GO for Phase 10 process isolation / unchanged defaults.**

**Eventlet-solved is Gates 1–5**, not a Phase 10 deliverable:

| Gate | log | verdict |
| --- | --- | --- |
| 1 Idle | `gate12-occupancy.log` ×2 | **GO** `spawn_server(2)` |
| 2 Streaming | occupancy slow_put/slow_reader + isolation PUT chunks | **GO** |
| 3 Isolation | `gate3-isolation.log` ×2; real PUT fsync_storm | **GO** |
| 4 Overload | `gate4-overload.log` (prior) Hyper 503 | **GO** |
| 5 Wire | SAIO fallback goldens + SSYNC IO hand-back | **GO under SAIO fallback** |

**Eventlet-solved: YES under plan SAIO fallback** after SSYNC Hyper IO hand-back + occupancy/isolation/proxy-deadline recapture ×2. Live Eventlet object-server remains unavailable (`pyeclib`).
