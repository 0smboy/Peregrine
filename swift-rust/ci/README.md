# Concurrency-boundary CI

Phase 12 architecture enforcement for Peregrine (`AGENTS.md` §24, §32).
The checker is a `rg`/`grep` gate, not a substitute for review.

```text
./ci/check-concurrency-boundaries.sh
```

Run from anywhere; the script cds to the swift-rust workspace (parent of `ci/`).
It prints each hit as `KIND  rule  file:line: snippet`, then a summary.
**No log files.** stdout/stderr only.

| Exit | Meaning |
|------|---------|
| 0 | No hard failures. `WARN` / `LIST` / `ALLOW` may still be printed. |
| 1 | At least one hard failure. |
| 2 | Tree/tooling error (no `crates/`, extra args, etc.). |

## Scan set

From the workspace root:

```text
crates/**/*.rs
```

Excluded:

- `**/target/**` — build output
- `**/tests/fixtures/**` — generated/golden fixtures, not production concurrency code

Everything else under `crates/` is scanned, including `src/`, `src/bin/`, `tests/`, `examples/`, and `benches/`.

**Production src** (hard-fail for unbounded queues) is any scanned file that is *not* under `tests/`, `examples/`, or `benches/`. Unit tests living inside `src/**` count as production src: put unbounded test-only channels in `tests/` if you need them.

## Hard-fail rules

### 1. `spawn_blocking`

Matches the identifier `spawn_blocking` (covers `tokio::task::spawn_blocking`, `spawn_blocking(`, and `use` imports).

**Allowlist (only):**

```text
crates/swift-runtime/src/blocking.rs
crates/swift-runtime/src/blocking/**
```

Hits there print `ALLOW` and do not fail. Hits anywhere else — including tests of HTTP/proxy/object — print `FAIL`.

There is no per-line escape hatch. Wrapping the request handler in `spawn_blocking` is a non-goal (`AGENTS.md` §32.4).

### 2. Unbounded channels

Matches:

- identifier `unbounded_channel` (Tokio `mpsc::unbounded_channel`, etc.)
- `crossbeam_channel::unbounded`
- `::unbounded(`
- a line that names `crossbeam_channel` and the identifier `unbounded` (grouped `use` on one line)

**Production src:** `FAIL`.
**`tests/` / `examples/` / `benches/`:** `LIST` only (see below). Not a fail.

No production allowlist. Bounded `crossbeam_channel::bounded` / `mpsc::channel` are the intended APIs.

### 3. `tokio::fs` in HTTP / proxy / S3

Matches `tokio::fs` (`tokio::fs::…`, `use tokio::fs`, `use tokio::fs::{…}`).

**Forbidden crates (any scanned file in the crate, including that crate's tests):**

```text
crates/swift-http
crates/swift-proxy-server
crates/swift-s3api
```

Storage IO belongs behind `ThreadedPosixIo` / `DeviceScheduler`, not `tokio::fs` on a network runtime thread (`AGENTS.md` L2, §10, §32.6).

Other crates are **not** failed for `tokio::fs` by this script (still the wrong storage architecture; later phases).

## Allowlist

| Rule | Allowed locations | How to extend |
|------|-------------------|---------------|
| `spawn_blocking` | `crates/swift-runtime/src/blocking` only | Put the call in that domain. Do not add path exceptions for app/HTTP crates. |
| unbounded channels | none in production src | Tests may use them; they are **listed**, not allowlisted as silent. |
| `tokio::fs` in http/proxy/s3api | none | Do not add. |
| `std::net` in proxy | current production src (Phase 0/1) | **WARN, not FAIL**, until Phase 2. |

`ALLOW` lines are the reviewed `spawn_blocking` sites in the blocking domain. Phase reports should quote these counts (`N` reviewed, `0` violations) rather than write “none known”.

### Tests may be listed (unbounded)

Integration/unit tests under `crates/*/tests/` (and examples/benches) may construct an unbounded channel. The script **prints every such hit** as:

```text
LIST  unbounded  crates/<crate>/tests/<file>.rs:<line>: <snippet>
```

That is the allowlist for tests: visible, countable, not a silent skip. If a test starts buffering object-sized data through an unbounded queue, the listing is the review hook. Production src with the same pattern is still `FAIL`.

`tests/fixtures/` is excluded entirely (not listed).

## WARN: `std::net` in proxy (not a fail)

`AGENTS.md` §24 will eventually forbid `std::net::` in HTTP/proxy. **Do not turn that into a hard fail yet.**

Current proxy serve/connect is synchronous `std::net` (`TcpListener` / `TcpStream::connect_timeout` on the client worker). That is Phase 0/1 truth; replacing it is Phase 2 (async HTTP). Failing CI on it now would block the tree without an architecture to move to.

The script prints each production-src hit in `crates/swift-proxy-server` as:

```text
WARN  std::net  crates/swift-proxy-server/src/…:<line>: <snippet>
```

Warnings do **not** change the exit code. Proxy `tests/` `std::net` usage is ignored (harness sockets).

`crates/swift-http` also uses `std::net` on the threaded server; that is the same current-truth class and is **not** a hard fail here. Flip both to `FAIL` in the same Phase 2 change, with a removal note, once the async connection runtime exists.

## Intentionally not hard-failed (yet)

These are in `AGENTS.md` §24 for HTTP/proxy but are **out of scope** for this checker until the named phase:

| Pattern | Why not FAIL today |
|---------|--------------------|
| `std::net::` in proxy/http | WARN only; Phase 2 |
| `std::fs::` in proxy/http | Object/diskfile still POSIX-on-caller; Phase 4 |
| `rusqlite::` in proxy/http | Should not appear there; DB domain is Phase 6 — not this script |
| `tokio::spawn(` without a saved handle | Structured concurrency is Phase 1/7 |
| `unsafe` / missing `// SAFETY:` | Separate lint; not this script |
| `io_uring` | Forbidden on the first migration; not scanned here |

Do not “fix” a WARN by widening workers, queues, or timeouts.

## Kind column

| Kind | Exit impact |
|------|-------------|
| `FAIL` | Counts toward exit 1 |
| `WARN` | Printed; exit still 0 if no `FAIL` |
| `LIST` | Test/example unbounded hits; exit 0 |
| `ALLOW` | `spawn_blocking` in the blocking domain; exit 0 |
