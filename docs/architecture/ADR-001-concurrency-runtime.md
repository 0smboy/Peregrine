# ADR-001 — Peregrine Concurrency Runtime

- **Status:** Accepted as the architecture program; **not implemented** on the serve path.
- **Date:** 2026-08-20
- **Constitution:** `/Users/oboy/Downloads/swift-master/AGENTS.md`
- **Phase:** 0 (forensic). This ADR does not change `swift-http`.

## Context

Python Swift still serves with Eventlet WSGI (`RestrictedGreenPool`, default `max_clients=1024`). Peregrine today serves with a **bounded synchronous thread pool** (`swift-http::server`). One keep-alive connection occupies one OS worker for the entire idle `read_head` wait (`head_deadline_secs`, default 30).

SAIO copied Python `workers = 2`. Python: 2 processes × ~1024 greenlets. Rust: 2 blocking threads. Ceph `test_s3.py` (3 boto keep-alive clients per test) starved the third connection for 30s. Official full run: 5h11 with `workers=2`; 14m08 after an **ops** bump to `workers=64`. That bump is **not** this ADR.

OpenStack is retiring Eventlet (`feature/threaded`). Eventlet is Peregrine's **semantic oracle**, not an implementation blueprint.

## Decision

Implement a **Peregrine Concurrency Runtime** that preserves Swift concurrency *guarantees* without green threads or monkey-patching:

| Layer | Choice |
|---|---|
| Network / HTTP/1.1 | Tokio + Hyper (Tokio sealed in infrastructure) |
| Storage | `ThreadedPosixIo` behind `DeviceScheduler` — not `tokio::fs` |
| SQLite | dedicated `DbExecutor` shards — not the HTTP worker |
| Process model | keep prefork as **failure domains**; do not drop it because Rust has no GIL |
| io_uring | forbidden on the first production migration |

`spawn_blocking` may exist only under a runtime blocking domain. Wrapping the current `Handler(Request) -> Response` in `spawn_blocking` is a **non-goal** (it relocates Eventlet's bug into Tokio's blocking pool).

A custom mio/epoll idle-reactor is **forbidden** (AGENTS.md §1, NON-GOAL 3) except a flagged temporary hotfix if live production is starving. Current live proxies do not set `workers=2`; SAIO starvation is not that exception. **No hotfix.**

## Consequences

- Phase 0 must finish (this document set + reproducing tests + baseline) before Phase 1 crate boundaries.
- `workers=64` on SAIO remains an ops workaround until Gate 1 (`idle connection != worker thread`) passes.
- Do not change production worker defaults as part of this program (NON-GOAL 13).
- L1–L10 in `CONCURRENCY-INVARIANTS.md` are release-blocking. Faster benchmarks cannot override them.

## Current serve path (as-is)

```
accept → bounded crossbeam queue → OS worker thread
       → handle_connection loop
            read_head (KEEP-ALIVE BLOCKS HERE)
            handler: Fn(Request) -> Response   // std::io::Read body
            write_response
            loop | close
```

Proxy backend hops use `TcpStream::connect_timeout` + `Connection: close` on the same calling thread as the client handler.
