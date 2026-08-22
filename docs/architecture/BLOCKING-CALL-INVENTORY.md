# Blocking-call inventory (Phase 0)

Audit date: 2026-08-20. Tree: `peregrine-grok-merge-20260814/swift-rust`.  
Method: `rg` on `crates/` excluding `target/` and most `tests/`.  
Phase 0 does not remove these calls.

## rg performed

| Pattern | Production src hits (files with matches) | Notes |
|---|---|---|
| `spawn_blocking` / `tokio::spawn` / `unbounded_channel` / `crossbeam_channel::unbounded` | **0** | No Tokio on the serve path. No unbounded channels found. |
| `std::net` / `TcpStream` / `TcpListener` | 31 files | Network waits = worker waits |
| `rusqlite` | 5 files in `swift-db` | DB on caller thread |
| `sync_all` / `fsync(` | diskfile, db util, object-server, s3 cold_tier | Durability on caller thread |
| `Handler` / `Fn(Request) -> Response` | swift-http, middleware, proxy | Sync ABI |

Exact `rg` invocations (re-run from `swift-rust/`):

```text
rg -n --type rust 'spawn_blocking|tokio::spawn|unbounded_channel|crossbeam_channel::unbounded' crates --glob '!**/target/**'
rg -c --type rust 'std::net::|TcpStream::|TcpListener' crates --glob '!**/target/**' -g '!**/tests/**'
rg -c --type rust 'rusqlite' crates --glob '!**/target/**' -g '!**/tests/**'
rg -n --type rust 'sync_all|fdatasync|fsync\(' crates --glob '!**/target/**' -g '!**/tests/**'
```

Do not write “none known”. Counts above are the audit.

## Classification along the hot path

### accept() → HTTP worker

| Site | Class | What blocks |
|---|---|---|
| `swift-http/src/server.rs` `TcpListener::accept` | NETWORK | Accept thread (dedicated). OK-ish. |
| `dispatch_connection` `try_send` | — | Bounded queue; full → 503. L3 held here. |
| `handle_connection` `read_head` | NETWORK | **Keep-alive idle and slowloris headers occupy the worker** (`head_deadline_secs`). **L1.** |
| `handle_connection` body `Read` | NETWORK | Slow PUT occupies the worker. **L1 / Gate 2.** |
| `handler(request)` | mixed | Entire application, including disk/DB. **L2.** |
| `write_response` | NETWORK | Slow GET reader occupies the worker. **L1 / Gate 2.** |

### proxy

| Site | Class | What blocks |
|---|---|---|
| `swift-proxy-server/src/lib.rs` `connect_node` | NETWORK | `TcpStream::connect_timeout` + read/write timeouts on the **client worker** |
| backend GET/PUT stream | NETWORK | Replica IO on the client worker |
| middleware `Fn(Request)->Response` | mixed | Same thread |

### object / diskfile

| Site | Class | What blocks |
|---|---|---|
| `swift-diskfile/src/diskfile.rs` `File` write, `sync_all`, xattr, `renamer` | FILESYSTEM / durability | PUT finalize on HTTP worker |
| `layout.rs` directory `sync_all` walk | FILESYSTEM | rename fsync parents |
| `hashes.rs` `hashes.pkl` write + `sync_all` | FILESYSTEM | partition hash |
| `swift-object-server` SSYNC sender/receiver `TcpStream` | NETWORK | replication on that process's threads |
| reconstructor/replicator `connect_timeout` | NETWORK | maintenance vs client: **L8 missing** |

### container / account / db

| Site | Class | What blocks |
|---|---|---|
| `swift-db` rusqlite `Connection::open` / execute / commit | DATABASE | Caller thread; SQLite locks serialize same DB only accidentally |
| `swift-db/src/util.rs` `sync_all` after atomic replace | FILESYSTEM | DB file durability |
| replicator/reaper/updater `TcpStream::connect` | NETWORK | daemon traffic |

### CPU / FFI (not idle-conn, still L2 once a network runtime exists)

| Site | Class |
|---|---|
| `swift-ec` liberasurecode | FFI / CPU |
| crypto AES/HMAC | CPU |
| md5/etag | CPU |

## L1 edges (network wait on a worker) — must not remain after Phase 2/7

1. Keep-alive `read_head` (`server.rs` `handle_connection` loop).
2. Request body stream read in `Handler`.
3. Response body write to a slow client.
4. `connect_node` and backend socket IO in proxy.
5. SSYNC/replicator TCP on shared pools.

## L2 edges (blocking storage/DB on whatever thread owns the client)

1. `diskfile` put: write + `sync_all` + xattr + rename fsync.
2. rusqlite on account/container request threads.
3. EC encode/decode FFI during PUT/GET.

## Unbounded resources

`rg` found **0** `unbounded_channel` / `crossbeam_channel::unbounded` in production src.  
Not a proof that every Vec is bounded (listings, in-memory pending). Those are follow-ups in later phase reports, listed by new `rg`.
