# CONCURRENCY-PHASE-08

**Phase:** 8 — Typed deadlines
**Date:** 2026-08-20

## Scope completed

`IncomingBody` arms `BodyIdleDeadline` (progress-aware) and `UploadLifetimeDeadline` independently. Hyper serve sets them from `body_idle_timeout_secs` / `max_upload_time_secs`. Citation `wsgi.py:442`.

## Tests passed

`phase279-proxy-ssync-deadlines.log` ×2: `body_idle_fires_on_stalled_chunk_while_upload_lifetime_is_separate` (408/499 in <5s while lifetime is 30s), `production_engine_is_hyper_http1`.

## GO / NO-GO

**GO for Phase 8 typed deadlines.** Idle and lifetime are not mixed.

**Eventlet-solved:** see `phase-gogo.txt`.
