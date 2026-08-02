# Optimization plan: write concurrency

Status: **A/B program closed** (2026-08-02 Contabo + SAIO). Workers + lock-free
accept shipped earlier; L1a parallel container update **KEEP**; L1b always-async
**DROP**; L2 fsync-off **DROP**; L4 `SO_REUSEPORT` **DROP**; L3a multi-container
kept as ops guidance. Evidence:
`tools/test-results/contabo-deploy-20260801/perf-levers/SUMMARY.json`.

## Implemented / decided

- **Object worker floor raised 2 → 16 (config, deployed).**
- **Lock-free accept dispatch (`swift-http` crossbeam MPMC).**
- **L1a KEEP — parallel bounded `container_update`.** Object server fans out
  container replicas under `container_update_timeout` (default 1.0s). Contabo
  primary gate `4KB_write_128` c1: ~**+24% PUT/s**, p99 ~**-30%** vs Phase0,
  fail=0. Deployed with `container_update_mode = sync`.
- **L1b DROP — always-async mode.** Code kept behind
  `container_update_mode = async` + updater `concurrency`/`interval`, but
  Contabo measured ~**0.95×** Phase0 (async_pending fsync cost). Production
  left on `sync`. SAIO Rust still ≫ Python at 1KB c32 without needing async.
- **L3a KEEP (ops) — multi-container.** c4/c1 ≈ **1.19×** on 128-worker writes;
  c16 did not beat c4 on the shared load host. Full sharding (L3b) deferred.
- **L2 DROP — `fsync_on_close=false`.** ~**+4.9%** PUT/s (<10% KEEP gate).
- **L4 DROP — `SO_REUSEPORT`.** No gain on single-acceptor thread pool
  (regression in the A/B). Knob retained as `reuse_port=false`.
- **L5 tokio:** ADR/spike only; not required while SAIO Rust 1KB c32 is
  ~**3.8×** Python.

## Observation

On the fixed 4-node cluster (through a HAProxy address, 0 hairpin):

| Path | Result |
|------|--------|
| Reads | scale cleanly — 4KB read **4,180 ops/s** @ 128 workers, 1MB read 1,346 MB/s, 16MB read 1,920 MB/s, p99 tens of ms |
| Writes | plateau — ~**800** 4KB-ops/s, ~210 1MB-ops/s, **p99 1–3 s** at 32–128 workers; **0 failures** throughout |

Raising the object server's `workers` from 2 to 32 did **not** move write
throughput (a quick, uncontrolled A/B showed ~equal or slightly lower). Reads
already reach 4,180 ops/s on just 2 workers.

## Root cause

The write ceiling is **not** the HTTP concurrency layer (the single-threaded
acceptor and the worker pool clearly sustain 4k+ read ops/s). It is the
**storage-side write path**, which each object PUT pays synchronously:

1. **Synchronous per-PUT container update.** Every object PUT updates the
   container DB inline on the write path. With few containers this is a
   serialization hotspot; the container SQLite backend becomes the limiter well
   before the HTTP layer does.
2. **Per-object fsync durability.** Each PUT fsyncs the datafile (and directory);
   under concurrency these serialize at the device.
3. **Per-partition `.lock` contention** during hash invalidation / updates.

More worker threads cannot raise throughput past these; they just wait on the
same disk and container DB (and, at large pool sizes, add `Mutex`-guarded
receiver contention in the accept dispatch).

## Plan (in priority order)

1. **Asynchronous / batched container updates** — biggest lever. Take the
   container update off the synchronous PUT path (or batch multiple updates per
   DB transaction), relying on the object updater + async_pending for
   durability, so a PUT acks as soon as the object is durable.
2. **fsync coalescing / tunable durability** — group-commit datafile fsyncs, or
   expose a durability knob, to amortize the per-object sync under load.
3. **Spread the container hotspot** — run with more containers and enable
   container **sharding** so writes are not funneled through one container DB.
4. **Lock-free accept dispatch (DONE) + `SO_REUSEPORT` (remaining)** — the
   `Arc<Mutex<Receiver>>` work queue is now a lock-free crossbeam MPMC (shipped);
   the remaining piece is multiple accept sockets via `SO_REUSEPORT` so a single
   acceptor thread is not the ceiling for connection-heavy small-object bursts.
5. **Long-term: async (tokio) server** — an event-driven server gives
   eventlet-parity concurrency (thousands of in-flight requests on a few
   threads) without a large OS-thread pool, removing the thread-count tradeoff
   entirely.

## Verification

Each lever must be A/B'd controlled: same cluster state, same workload, run the
write tasks 3×/config and compare medians (the quick 2-vs-32 worker test above
was too noisy to conclude and is not evidence either way). Target: raise
sustained 4KB write throughput and cut write p99 under 128-worker concurrency,
with zero failures preserved.
