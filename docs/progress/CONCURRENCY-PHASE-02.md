# CONCURRENCY-PHASE-02

**Phase:** 2 — Async HTTP/1.1 connection runtime
**Date:** 2026-08-20
**Tree:** `.agent-handoff/peregrine-grok-merge-20260814/swift-rust`
**Scratch:** `{SCRATCH}` implementer dir

## Scope completed

Production serve is Tokio + Hyper HTTP/1.1 (`PRODUCTION_HTTP1_ENGINE = "hyper/http1"`). Keep-alive is a pending Future. `header_read_timeout` is the slowloris bound. HTTP/2 is not enabled (`hyper` features = `http1, server` only).

SSYNC connections peek the request line then **hand the socket back** (`PrefixedIo` for other methods; `serve_ssync_handoff` for SSYNC). Occupancy tests stay `spawn_server(2)`.

## Tests passed

`gate12-occupancy.log` run1 `2026-08-20T14:36:56Z` + run2: worker_starvation, slowloris, align_expect_continue, fsync_storm (real PUT commit stall), slow_put, slow_reader — 6+6, 0 failed. `spawn-server-2.txt` still `spawn_server(2, ...)`.

## Blocking / unbounded

`spawn_blocking` unique site `crates/swift-runtime/src/blocking.rs:577`. `unbounded_channel` prod src: 0.

## GO / NO-GO

**GO for Phase 2.** Occupancy ×2 at 2 workers; engine hyper/http1.

**Eventlet-solved:** see `phase-gogo.txt` after Gates 1–5 recapture.
