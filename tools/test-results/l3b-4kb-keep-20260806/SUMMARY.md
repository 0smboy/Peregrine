# L3b 4KB post-shard probe · Contabo · 2026-08-06

Container: `l3bclean1786024121` (already SHARDED from clean e2e)

## Results

| Gate | Result |
|------|--------|
| Baseline list (pre 4KB) | 60 |
| PUT 20×4KiB (`k4-*`) before update-routing fix | **201** all; **GET 200 size=4096** 5/5 |
| List showed `k4-*` before fix | **0** (updates hit root DB only) |
| After `X-Backend-Container-Path` + root residual merge | list includes residual **k4 20** |
| PUT 10×4KiB (`k4b-*`) after routing fix | **201**; land on **shard** DB; **list k4b=10**; GET 200/4096 |
| Product multi-node 4KB KEEP vs Python | **not claimed** (lab probe only) |

## Root cause (fixed in tree)

Object PUT container-update always targeted the **root** container nodes.  
When sharded, listings fan out to **shard** DBs → new keys invisible in list while GET still 200.

**Fix:** proxy `resolve_updating_shard` + `X-Backend-Container-Path`; object-server honors path for container_update; listing merges residual root rows + dedupes names.

## Files

`01-4kb-probe.txt`, `02-after-shard-update-route.txt`
