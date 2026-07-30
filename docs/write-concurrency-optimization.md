# Optimization plan: write concurrency

Status: **partially implemented** (2026-07-30). Two levers shipped and deployed;
the rest scoped below. Root-caused against the live 4-node cluster and a clean
single-node A/B.

## Implemented

- **Object worker floor raised 2 → 16 (config, deployed to all 4 nodes).** The
  deployed `object-server.conf` pinned `workers = 2`, so each object server
  processed only two requests at a time. A clean single-node A/B (4 KB writes,
  concurrency 64) showed 2 → 16 workers roughly **doubled write throughput
  (194 → 344 PUT/s) and cut p50 187 → 113 ms, p99 2028 → 784 ms**; 16 → 64 was
  flat, pointing at the shared work-queue lock and single-disk fsync as the next
  limiters.
- **Lock-free accept dispatch (code, `swift-http`).** Replaced the
  `Arc<Mutex<Receiver>>` work queue with a `crossbeam-channel` MPMC: every worker
  `recv()`s directly, so raising the pool no longer serializes workers on a
  shared mutex. 946/946 workspace tests still pass; deployed to all 4 nodes.

  A clean throughput delta for the lock-free change could not be isolated on the
  shared test host (swift1 also runs the live cluster, Loki and Prometheus, so
  the single-node numbers are too noisy to A/B a second-order change) — it is
  shipped as a correct, non-regressing contention fix, to be re-measured on a
  dedicated load source.

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
