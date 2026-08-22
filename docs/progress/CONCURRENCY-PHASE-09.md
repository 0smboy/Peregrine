# CONCURRENCY-PHASE-09

**Phase:** 9 — SSYNC async session
**Date:** 2026-08-20
**Tree:** `.agent-handoff/peregrine-grok-merge-20260814/swift-rust`

## Scope completed

Production SSYNC is **Hyper IO hand-back**, not a blocking hijack:

1. `serve_http1_connection` peeks the request line.
2. If `SSYNC `, headers finish on the async socket; the fd is **not** given to Hyper’s HTTP/1 body/response machine (`serve_ssync_handoff`).
3. Request body is HTTP-chunked or Content-Length on `OwnedReadHalf` → `IncomingBody`.
4. `ObjectServer::ssync_async` returns **200 + Channel immediately** (`ssync_sender.py:264-272`).
5. Protocol FS is `StorageExecutor.run_finite(..., TrafficClass::Replication)`.
6. Response frames are written as HTTP chunks on `OwnedWriteHalf`.

Non-SSYNC connections replay peeked bytes through `PrefixedIo` into Hyper.

`handle_async` routes SSYNC to `ssync_async`. `handle_buffered_async` / `dispatch_fs_on_storage` refuse SSYNC (500). Legacy `fn ssync` hijack remains only for `tests/ssync.rs`.

## Tests passed

`phase279-proxy-ssync-deadlines.log` ×2:

- `hyper_serve_ssync_full_duplex_async_socket` — 200 before body; health GET on same 2-worker listener; MISSING_CHECK/UPDATES
- `handle_async_ssync_returns_200_before_sender_body`
- `hyper_serve_shipped_put_delete_ssync_wire` — PUT 201, DELETE 204, SSYNC Accept-No-Commit (`obj/server.py:1406-1415`)

## GO / NO-GO

**GO for SSYNC as an async socket session with FS on StorageExecutor.** Not `req.body.hijack()` on the Hyper serve path.

**NO-GO for live replicator dual-feed** (no `pyeclib`). Out of this goal under the SAIO fallback policy.

**Eventlet-solved:** see `phase-gogo.txt`.
