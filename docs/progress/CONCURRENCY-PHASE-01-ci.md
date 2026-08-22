# CONCURRENCY-PHASE-01-ci

**Phase:** 1 CI architecture gate (`AGENTS.md` §24 / §33; checker is the Phase 12 script, applied now)  
**Date:** 2026-08-20T04:18:56Z (UTC)  
**Tree:** `.agent-handoff/peregrine-grok-merge-20260814`  
**Workspace:** `swift-rust/`  
**Script:** `swift-rust/ci/check-concurrency-boundaries.sh` (present, executable, **not modified**)  
**Constitution:** `AGENTS.md`

> **2026-08-21 recapture:** This identifier-gate NO-GO is historical. Current CI checker PASS is `ci-boundaries.log` ×2 / `phase-gogo.txt` Phase 12 GO.

## Command

```text
cwd: /Users/oboy/Downloads/swift-master/.agent-handoff/peregrine-grok-merge-20260814/swift-rust

bash /Users/oboy/Downloads/swift-master/.agent-handoff/peregrine-grok-merge-20260814/swift-rust/ci/check-concurrency-boundaries.sh
```

The script `cd`s to the parent of `ci/` (`swift-rust/`) itself. stderr was empty (0 bytes).

**Exit code: 1** (`FAIL` — hard failures > 0)

## Expected vs actual (this tree)

| Hard / warn rule | Expected for GO | Actual |
|---|---|---|
| `spawn_blocking` FAIL (outside `crates/swift-runtime/src/blocking`) | **0** | **2** |
| unbounded FAIL (prod src) | **0** | **0** |
| `tokio::fs` FAIL (http / proxy / s3api) | 0 | 0 |
| `std::net` WARN (proxy src) | WARN, not fail | **16 WARN** |
| Script exit | 0 `PASS` | **1 `FAIL`** |

The checker was not weakened, allowlisted, or comment-skipped to force a pass.

## Command output (stdout, verbatim)

```
== check-concurrency-boundaries ==
workspace: /Users/oboy/Downloads/swift-master/.agent-handoff/peregrine-grok-merge-20260814/swift-rust
scan: crates/**/*.rs (exclude target/, tests/fixtures/)
files scanned: 218

WARN  std::net         crates/swift-proxy-server/src/lib.rs:611: reader: std::io::BufReader<std::net::TcpStream>,
WARN  std::net         crates/swift-proxy-server/src/lib.rs:667: reader: std::io::BufReader<std::net::TcpStream>,
WARN  std::net         crates/swift-proxy-server/src/lib.rs:694: reader: &mut std::io::BufReader<std::net::TcpStream>,
WARN  std::net         crates/swift-proxy-server/src/lib.rs:715: reader: &mut std::io::BufReader<std::net::TcpStream>,
WARN  std::net         crates/swift-proxy-server/src/lib.rs:791: ) -> std::io::Result<std::net::TcpStream> {
WARN  std::net         crates/swift-proxy-server/src/lib.rs:793: let sock_addr: std::net::SocketAddr = addr
WARN  std::net         crates/swift-proxy-server/src/lib.rs:796: let conn = std::net::TcpStream::connect_timeout(&sock_addr, conn_timeout)?;
WARN  std::net         crates/swift-proxy-server/src/lib.rs:846: stream: std::net::TcpStream,
WARN  std::net         crates/swift-proxy-server/src/lib.rs:847: reader: std::io::BufReader<std::net::TcpStream>,
WARN  std::net         crates/swift-proxy-server/src/lib.rs:1054: stream: std::net::TcpStream,
WARN  std::net         crates/swift-proxy-server/src/lib.rs:1055: reader: std::io::BufReader<std::net::TcpStream>,
WARN  std::net         crates/swift-proxy-server/src/lib.rs:4917: pub fn serve(listener: std::net::TcpListener, app: Arc<ProxyApp>) -> std::io::Result<()> {
WARN  std::net         crates/swift-proxy-server/src/lib.rs:4957: listener: std::net::TcpListener,
WARN  std::net         crates/swift-proxy-server/src/lib.rs:4967: listener: std::net::TcpListener,
WARN  std::net         crates/swift-proxy-server/src/lib.rs:4985: listener: std::net::TcpListener,
WARN  std::net         crates/swift-proxy-server/src/main.rs:236: let listener = std::net::TcpListener::bind(&bind).unwrap_or_else(|e| {
ALLOW spawn_blocking   crates/swift-runtime/src/blocking.rs:19: //! call [`tokio::task::spawn_blocking`]. Callers submit a finite job through
ALLOW spawn_blocking   crates/swift-runtime/src/blocking.rs:26: //! * `thread_cap` — maximum concurrent `spawn_blocking` invocations.
ALLOW spawn_blocking   crates/swift-runtime/src/blocking.rs:37: //! `spawn_blocking`. **In-flight blocking work cannot abort.** Tokio's
ALLOW spawn_blocking   crates/swift-runtime/src/blocking.rs:68: /// Maximum concurrent blocking threads (`spawn_blocking` in flight).
ALLOW spawn_blocking   crates/swift-runtime/src/blocking.rs:144: /// Job was cancelled before `spawn_blocking` started.
ALLOW spawn_blocking   crates/swift-runtime/src/blocking.rs:177: /// Sum of queue-wait nanoseconds for jobs that reached `spawn_blocking`.
ALLOW spawn_blocking   crates/swift-runtime/src/blocking.rs:197: /// tasks; in-flight `spawn_blocking` closures still run to completion.
ALLOW spawn_blocking   crates/swift-runtime/src/blocking.rs:216: // Aborts the worker *task*. Does not abort in-flight spawn_blocking.
ALLOW spawn_blocking   crates/swift-runtime/src/blocking.rs:312: /// Dropping this handle cancels a queued job. If `spawn_blocking` has
ALLOW spawn_blocking   crates/swift-runtime/src/blocking.rs:324: /// If the job had already entered `spawn_blocking`, this waits for the
ALLOW spawn_blocking   crates/swift-runtime/src/blocking.rs:343: /// Returns `false` if `spawn_blocking` has started (or the job already
ALLOW spawn_blocking   crates/swift-runtime/src/blocking.rs:357: /// `true` once the job has entered `spawn_blocking`.
ALLOW spawn_blocking   crates/swift-runtime/src/blocking.rs:378: /// `tokio::task::spawn_blocking`. Must be called from inside a runtime.
ALLOW spawn_blocking   crates/swift-runtime/src/blocking.rs:596: // Unique workspace `spawn_blocking` site. Aborting the worker task or
ALLOW spawn_blocking   crates/swift-runtime/src/blocking.rs:599: let join = tokio::task::spawn_blocking(run);
ALLOW spawn_blocking   crates/swift-runtime/src/blocking.rs:785: assert!(!in_flight.abort(), "in-flight spawn_blocking cannot abort");
FAIL  spawn_blocking   crates/swift-runtime/src/lib.rs:20: //! Application code must not call `tokio::task::spawn_blocking`; the single
FAIL  spawn_blocking   crates/swift-runtime/src/scope.rs:22: //! This module does not call `spawn_blocking`.

== summary ==
files scanned:              218
spawn_blocking FAIL:        2
spawn_blocking ALLOW:       16  (crates/swift-runtime/src/blocking)
unbounded FAIL (prod src):  0
unbounded LIST (tests):     0
tokio::fs FAIL:             0  (swift-http / swift-proxy-server / swift-s3api)
std::net WARN (proxy src):  16  (not a fail until Phase 2)
hard failures:              2
FAIL
```

## Command output (stderr, verbatim)

*(empty)*

## Independent `rg` (same tree, immediately after the run)

Scan set: `crates/**/*.rs`, exclude `**/target/**`.

```
spawn_blocking
  16 hits  crates/swift-runtime/src/blocking.rs
           (allowlisted path; includes the unique call
            `tokio::task::spawn_blocking(run)` at blocking.rs:599)
   1 hit   crates/swift-runtime/src/lib.rs:20     (crate rustdoc)
   1 hit   crates/swift-runtime/src/scope.rs:22   (module rustdoc)

unbounded_channel | crossbeam_channel::unbounded | ::unbounded(
  → 0 hits

tokio::fs  in swift-http / swift-proxy-server / swift-s3api
  → 0 hits

std::net::  in crates/swift-proxy-server production src
  → 16 hits  (lib.rs 15 + main.rs 1; tests/ ignored by the WARN rule)
```

Reviewed: **18** `spawn_blocking` identifier occurrences, **0** unbounded occurrences, **16** proxy `std::net` production-src occurrences.

## Classification of the two FAILs

Neither FAIL is a `spawn_blocking(` call on an HTTP/proxy/object worker.

| File | Kind | Why the script fails it |
|---|---|---|
| `crates/swift-runtime/src/lib.rs:20` | crate rustdoc forbidding the API | identifier match; path is **not** `src/blocking.rs` / `src/blocking/*` |
| `crates/swift-runtime/src/scope.rs:22` | module rustdoc saying it does not call the API | same |

The unique real call is:

```rust
// crates/swift-runtime/src/blocking.rs:599
let join = tokio::task::spawn_blocking(run);
```

That site is **ALLOW** (`ci/README.md` allowlist). `AGENTS.md` L2 / §5 / NON-GOAL 4 still hold for application crates: no `spawn_blocking` outside the blocking domain.

**Do not** make the gate pass by teaching the script to skip comments, adding path exceptions, or dropping the identifier match. The two rustdocs must stop naming the identifier (or move that prose into the allowlisted blocking module).

## Scope completed (this note)

- Ran the Phase 12 checker from `swift-rust/`.
- Captured stdout / stderr / exit.
- Did **not** edit `ci/check-concurrency-boundaries.sh`.
- Did **not** change serve architecture, worker defaults, or allowlists.

## Files changed

```
docs/progress/CONCURRENCY-PHASE-01-ci.md   (this file only)
```

## Architectural invariants affected

None by this note. The checker is reporting on the tree:

- L2 / §5: the only `spawn_blocking(` call is inside `BlockingDomain` (**ALLOW**).
- L3: 0 unbounded channels in scanned crates.
- §24 proxy `std::net::`: still the sync serve path; **WARN until Phase 2**, not a hard fail.

## Tests added

None (CI report only).

## Tests passed

The checker itself: **FAIL** (exit 1). Not a cargo test run.

## Differential results

Not run.

## Benchmark before/after

Not run. Baseline remains `bench/baseline/current-sync.json`.

## Known limitations

- The checker matches the **identifier** `spawn_blocking` on every scanned line, including rustdoc / comments. There is no per-line escape hatch (`ci/README.md`).
- `files scanned` moved 214 → 218 while Phase 1 runtime files were landing in the same tree. This report is pinned to the 04:18:56Z run (218 files).
- Proxy `tests/**` `std::net` usage is ignored by design; only production src WARNs.

## Blocking operations remaining

`rg` / checker performed on `crates/**/*.rs` (exclude target):

```
spawn_blocking
  18 identifier hits reviewed
  1 call: crates/swift-runtime/src/blocking.rs:599  ALLOW
  15 docs/comments in the same allowlisted file     ALLOW
  2 rustdoc hits outside the allowlist              FAIL  (lib.rs:20, scope.rs:22)

tokio::fs in http/proxy/s3api
  0

std::net:: in proxy production src
  16 WARN  (Phase 2)
```

**0** application-crate `spawn_blocking(` calls. **2** identifier violations of the hard rule as written.

## Unbounded resources remaining

```
rg unbounded_channel | crossbeam_channel::unbounded | ::unbounded(
  crates/**/*.rs  →  0 occurrences
```

Checker: `unbounded FAIL (prod src): 0`, `unbounded LIST (tests): 0`.

## Unsafe code introduced

None by this note.

## Regression analysis

No serve-path change in this note. The CI gate is red because two rustdoc lines name `spawn_blocking` outside the blocking domain.

## GO / NO-GO recommendation

| Question | Verdict |
|---|---|
| Script present and executed? | **GO** (ran; stderr empty) |
| Checker weakened to pass? | **GO** (not weakened) |
| unbounded FAIL in prod src = 0? | **GO** |
| `std::net` in proxy src = WARN, not FAIL? | **GO** (16 WARN) |
| spawn_blocking FAIL = 0? | **NO-GO** (2) |
| This CI gate (`exit 0` / `PASS`)? | **NO-GO** |
| Claim Phase 1 architecture CI is green? | **NO-GO** |
| Proceed as if Eventlet/concurrency gates 1–5 are solved? | **NO-GO** |

**Workflow verdict at 04:18Z: NO-GO** (2 rustdoc identifier hits). Script was not weakened.

**Follow-up (same session):** reworded `swift-runtime/src/lib.rs` and `scope.rs` rustdoc so they no longer contain the identifier `spawn_blocking`. Re-ran the same script: **exit 0 PASS**, hard failures 0, 16 proxy `std::net` WARN. Unique call remains `blocking.rs` ALLOW. Gate 1 (idle ≠ thread) is still NO-GO — this is only the CI identifier gate.
