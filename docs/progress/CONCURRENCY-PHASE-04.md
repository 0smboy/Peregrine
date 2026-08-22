# CONCURRENCY-PHASE-04

**Phase:** 4 — Object storage executor / PUT state machine
**Date:** 2026-08-20

## Scope completed

Object PUT: `next_chunk().await` then `StorageExecutor::run_finite` write. Finalize (xattr/fsync/rename) on the executor (`finish_pending_put`). Durability commit is not dropped with the request future.

`fsync_storm` drives a **real** Hyper PUT `/sda1/0/AUTH_test/c/o` whose commit `run_finite` is stalled (`thread_cap=1`); PUT has not returned 201; concurrent GET `/health` completes; then PUT 201. Not a dummy park + `/health` that fails `obj_path`.

## Tests passed

`gate3-isolation.log` ×2: `shipped_put_finalize_runs_on_storage_executor`, `two_concurrent_puts_both_commit_distinct_objects`.
`gate12-occupancy.log` ×2: `fsync_storm_does_not_starve_a_health_get`.

## GO / NO-GO

**GO for Phase 4.** PUT pipeline + commit-shield on StorageExecutor; fsync storm is a real in-flight PUT.

**Eventlet-solved:** see `phase-gogo.txt`.
