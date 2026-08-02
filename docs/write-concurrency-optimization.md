# Write concurrency — closed A/B program

Status: **closed** (2026-08-02 Contabo + SAIO). Evidence:
`tools/test-results/contabo-deploy-20260801/perf-levers/SUMMARY.json`.

## Decisions (authoritative)

| Lever | Decision | Notes |
|-------|----------|-------|
| Object workers 2 → 16 | **SHIPPED** | Controlled single-node: 4 KB PUT/s 194 → **344**, p99 2028 → 784 ms |
| Lock-free accept (crossbeam MPMC) | **SHIPPED** | Replaced `Arc<Mutex<Receiver>>` |
| L1a parallel bounded `container_update` | **KEEP** | Contabo `4KB_write_128` c1 ~**+24%** ops, p99 ~**−30%**; fail=0 |
| L1b always-async (`container_update_mode=async`) | **DROP** | ~0.95× Phase0; code retained behind flag; prod = `sync` |
| L2 `fsync_on_close=false` | **DROP** | ~+4.9% (&lt;10% gate); prod = `true` |
| L4 `SO_REUSEPORT` | **DROP** | ~0.84×; prod = `reuse_port=false` |
| L3a multi-container | **ops guidance** | c4/c1 ≈1.19× @128; L3b sharding deferred |
| L5 tokio | **ADR only** | SAIO Rust 1 KB PUT @c32 ~**3.79×** Python (`saio_phase0`) |

## Production config (post-program)

```ini
workers = 16
container_update_mode = sync
container_update_timeout = 1.0
fsync_on_close = true
reuse_port = false
```

Updater: `concurrency = 16`, `interval = 5` (pending drain). Contabo load note:
autocos from `swift1` against `10.0.0.1:8085` (shared load host; noisy).

## SAIO 1 KB PUT (same-host, phase0 medians)

| Side | c1 | c32 |
|------|---:|----:|
| Rust | 71.8 | 264.4 |
| Python 2.35 | 32.3 | 69.8 |

Ratio @c32 ≈ **3.79×**. This is **not** an L1a KEEP claim — L1a SAIO re-check
was ~0.92× phase0 Rust; the KEEP gate was Contabo 4 KB write.

Retired (pre workers/accept): Rust 54/159 vs Python 32/255.

## Earlier observation (pre-lever context)

On the four-node path, reads already scaled (4 KB read **4,180 ops/s** @128,
1 MB 1,346 MB/s, 16 MB 1,920 MB/s). Writes plateaued under container-DB / fsync /
partition-lock pressure. An uncontrolled 2-vs-32 worker trial on the shared load
host was **too noisy to use as evidence**; the controlled single-node 2→16 A/B
is the worker decision record.

## Remaining write ceiling (after shipped work)

HTTP accept/worker starvation is no longer the primary story. Remaining
hotspots on the synchronous PUT path:

1. Container DB updates (mitigated by L1a fanout under timeout; still sync)
2. Per-object `fsync` (L2 off failed the KEEP gate — durability stays on)
3. Per-partition `.lock` / hash invalidation
4. Container hotspot shape (multi-container ops; sharding deferred)

## Deferred / not KEEP

- Full container sharding (L3b)
- tokio rewrite (L5 ADR)
- Revisit L1b only after cheaper `async_pending` path
- Dedicated load host re-measure (shared `swift1` noise)

## How it was verified

Controlled A/B: same cluster state, same workload, write tasks 3×/config,
compare medians; dual gate Contabo + SAIO. Primary Contabo KEEP gate:
`4KB_write_128` c1 vs Phase0. Artifacts under `perf-levers/`
(`COMPARE.json` / `DECISION.json` / `SUMMARY.json`).
