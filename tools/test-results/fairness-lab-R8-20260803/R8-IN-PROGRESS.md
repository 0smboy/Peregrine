# R8 — in progress

| | |
|--|--|
| **Started** | 2026-08-03T12:04Z |
| **Host** | swift4 `/tmp/fairness-R8/r8-16mb-soak.sh` |
| **Scope this cycle** | 16MB_read retune (ACCEPT path) + 6h soak; **not** L3b/plugin code |

## Probe (pre-flight)

`object_count=40` `runtime=180` on DIRECT `10.0.0.1`:

- prepare ok=40 fail=0 (100%)
- normal ok=854 fail=0 (100%)

## Running sequence

1. DIRECT-4PROXY `16MB_read_4` — warm 2 + measured 8
2. HA-PATH `16MB_read_4` — warm 2 + measured 8
3. Soak 6h DIRECT `4KB_write_128` (chunks 1800s)

ETA ≈ 1h (16MB cells) + 6h soak.

## Explicitly out of this R8 execution window

- L3b container sharding (needs clean baseline cell + feature work)
- Paste pipeline / memcache / servers_per_port Rust impl
- Full 4-node Python Performance cluster
- Dedicated monitoring / dual bench hardware
