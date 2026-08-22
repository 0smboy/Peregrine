# CONCURRENCY-PHASE-07

**Phase:** 7 — Proxy async fan-out
**Date:** 2026-08-20

## Scope completed

Production `ProxyAsyncService` → `handle_async` (not leftover `handle()`):

- Object PUT: bounded tee (`SharedWindow`), quorum, cancel unused
- COPY: Channel GET → `IncomingBody::from_channel` → PUT tee
- GET/HEAD/POST/DELETE: Tokio backend I/O
- OPTIONS/info: local async (`container_info_async` for CORS)

`handle_async` does **not** fall back to `self.handle()` (sync `std::net` fan-out). CI grep `self.handle(Request {` = 0.

## Tests passed

`phase279-proxy-ssync-deadlines.log` ×2: `stream_put_async_drops_stalled_replica_and_keeps_window_bounded`, `make_requests_async_quorum_cancels_blackhole`, `hyper_serve_copy_is_get_then_put_on_shipped_proxy`.

## GO / NO-GO

**GO for Phase 7 production async proxy data plane.** Leftover `handle()` remains compiled for tests/sync controller only.

**Eventlet-solved:** see `phase-gogo.txt`.
