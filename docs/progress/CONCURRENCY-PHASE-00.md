# CONCURRENCY-PHASE-00

**Phase:** 0 Forensic Audit  
**Date:** 2026-08-20  
**Tree:** `.agent-handoff/peregrine-grok-merge-20260814`  
**Constitution:** `AGENTS.md`

> **2026-08-21 recapture:** This file is the Phase 0 forensic snapshot (Gates 1–5 were unmet *then*). Current post-Phase-14 Eventlet-solved / GO-NO-GO is `phase-gogo.txt`, not the Gate rows below.

## Scope completed

- Serve architecture **not** modified (no Tokio, no Hyper, no mio reactor, no worker-default change).
- Architecture docs, Eventlet matrix, blocking inventory, request lifecycle, sync baseline JSON.
- Four Gate tests that encode the *target* property and **fail** on the current thread-pool server.

## Files changed

```
docs/architecture/ADR-001-concurrency-runtime.md
docs/architecture/CONCURRENCY-INVARIANTS.md
docs/architecture/EVENTLET-SEMANTICS-MATRIX.md
docs/architecture/BLOCKING-CALL-INVENTORY.md
docs/architecture/REQUEST-LIFECYCLE.md
docs/progress/CONCURRENCY-PHASE-00.md
bench/baseline/current-sync.json
swift-rust/crates/swift-http/Cargo.toml
swift-rust/crates/swift-http/tests/concurrency/harness.rs
swift-rust/crates/swift-http/tests/concurrency/worker_starvation.rs
swift-rust/crates/swift-http/tests/concurrency/slowloris.rs
swift-rust/crates/swift-http/tests/concurrency/slow_put.rs
swift-rust/crates/swift-http/tests/concurrency/slow_reader.rs
```

## Architectural invariants affected

Documented only. L1, L2, L5, L8 **VIOLATED** on the current server. L3 mostly held at accept. L4 partial. L6/L7 not yet applicable as typed machines. See `CONCURRENCY-INVARIANTS.md`.

## Tests added

| Test | Gate | Result on current server |
|---|---|---|
| `swift-http --test worker_starvation` | 1 idle ≠ thread | **FAIL** (3rd GET WouldBlock @400ms) |
| `swift-http --test slowloris` | 1 / §26.B | **FAIL** |
| `swift-http --test slow_put` | 2 slow PUT ≠ worker | **FAIL** |
| `swift-http --test slow_reader` | 2 slow GET ≠ worker | **FAIL** |

RED is the Phase 0 success criterion (failure is reproducible, not papered over).

## Tests passed

Existing `cargo test -p swift-http --lib` — see command output in this phase (must remain green). Gate tests must stay red until a later phase implements the runtime.

## Differential results

Not run (no execution-model change). Python SAIO 241/503/0/94 in 33min vs Rust SAIO `workers=2` 194/174/470/1 in 5h11 vs `workers=64` 246/256/318/20 in 14m08 recorded in `bench/baseline/current-sync.json`. The 14m08 figure **does not** pass Gate 1.

## Benchmark before/after

Phase 0 has no after. Before = `current-sync.json`.

## Known limitations

- Inventory is `rg` on this merge tree; daemon/test-only paths are listed but not every Vec bound.
- Gate tests use 2 workers + 400ms probe; they characterize `swift-http` in-process, not a full proxy→object PUT.
- SAIO still running `workers=64` as ops workaround; not product default.

## Blocking operations remaining

`rg` performed (from `swift-rust/`, production src, tests excluded where noted):

```
spawn_blocking|tokio::spawn|unbounded_channel|crossbeam_channel::unbounded
  → 0 occurrences

std::net::|TcpStream::|TcpListener
  → 31 files (see BLOCKING-CALL-INVENTORY.md)

rusqlite
  → 5 files under crates/swift-db

sync_all|fdatasync|fsync(
  → diskfile.rs, hashes.rs, layout.rs, db/util.rs, object-server, s3api/cold_tier.rs
```

N files reviewed: as in inventory. **Violations of L1/L2: all NETWORK/FS/DB sites on the HTTP worker.** 0 Tokio `spawn_blocking` (there is no network runtime to misuse yet).

## Unbounded resources remaining

```
rg unbounded_channel|crossbeam_channel::unbounded  → 0 occurrences in crates src
```

Accept path is bounded. Listing/in-memory collections not exhaustively capped; follow-up in later phase `rg`.

## Unsafe code introduced

**None** in this phase. Existing `swift-http` `bind_listener` SO_REUSEPORT `from_raw_fd` unchanged.

## Regression analysis

No serve-path behavior change. Lib tests for `swift-http` must stay at pre-phase baseline.

## GO / NO-GO recommendation

| Question | Verdict |
|---|---|
| Phase 0 forensic package complete? | **GO** |
| May Phase 1 (runtime substrate, Tokio sealed) start? | **GO** (audit gate) |
| Idle connection ≠ worker (Gate 1)? | **NO-GO** |
| Claim “Eventlet problem solved”? | **NO-GO** (Gates 1–5 unmet) |
| Custom mio idle-reactor / raise product `workers` as the fix? | **NO-GO** (AGENTS.md NON-GOALS 3, 13; L1) |

**Do not continue by hiding L1 behind SAIO `workers=64`.** That configuration is explicitly out of the architecture.
