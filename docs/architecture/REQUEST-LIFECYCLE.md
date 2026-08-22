# Request lifecycle — current sync server

Phase 0 map of **what exists**. Target lifecycle (async ConnectionTask, RequestContext, DurabilityBarrier) is AGENTS.md §6–§13 and is not implemented.

## Connection

```
TcpListener.accept                    [accept thread]
        │
        ▼
crossbeam bounded queue               [connection_queue / max_clients]
        │  full → 503 Service Unavailable
        ▼
OS worker thread  (worker_threads)
        │
        ▼
handle_connection
   loop i in 0..max_requests_per_connection
        arm head_deadline
        read_head                     ← KEEP-ALIVE WAITS HERE (L1)
        build Streamed Body (Read over the same socket)
        handler(Request) -> Response  ← APP + DISK + DB (L2)
        write_response
        if keep-alive: drain ≤64KiB remainder; loop
        else: shutdown write; return
```

Idle keep-alive: `Future` does not exist. State is `thread blocked in read()` with `head_deadline_secs` (default 30) as the only unpark.

## Client PUT (object)

```
proxy worker: parse S3/Swift
     → connect_node replica A (block)
     → connect_node replica B (block)
     → connect_node replica C (block)   # quorum 2/3 still waits on this thread
     → stream body to backends
object worker: DiskFile put
     write tmp
     xattr
     fsync          [Durability, unnamed]
     rename + dir fsync
     container_update HTTP (sync, production KEEP)  # network on storage worker
```

Client disconnect during fsync: no commit-shield type. The worker runs the procedure to completion or IO error.

## Client GET (object)

```
object worker: open datafile, write_response copy loop 64KiB
     slow client → worker stuck in write   (Gate 2)
```

## Proxy-only control request (e.g. ListBuckets)

```
proxy worker
  → account server HTTP (block)
  → JSON translate
  → write_response
```

s3-tests: three boto clients (main/alt/tenant) keep connections. With `workers=2`, the third ListBuckets waits for a `read_head` deadline on an idle keep-alive — the 5h11 fingerprint.

## SSYNC

HTTP request hits `handler`; `InterimResponder` hijacks the `TcpStream`. The same worker stays in the SSYNC state machine until the session ends. Filesystem ops on that worker.

## Shutdown (current)

`ServerConfig.shutdown` AtomicBool: accept loop stops, sender dropped, workers drain **in-flight connections including idle keep-alives until head deadline or close**. No distinction idle vs durability-barrier vs cancellable request. AGENTS.md §30 shutdown state machine is **not** implemented.
