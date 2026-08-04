# R8 Stop — 16MB retune + 6h soak

| | |
|--|--|
| **Status** | **GREEN** |
| **When** | 2026-08-04T02:28Z |
| **Params** | object_count=40 runtime=180 (retune from R4 object_count=2000@30s) |

## Stop 验收

| 条 | 结果 |
|----|------|
| DIRECT 16MB_read ≥8 ACCEPT | **ACCEPT** (n=8, median ops/s=4.078) |
| HA 16MB_read ≥8 ACCEPT | **ACCEPT** (n=8, median ops/s=4.153) |
| Soak 6h fails=0 | **ACCEPT** (ok=2199378, fail=0, chunks=12) |

## Note
Soak SUMMARY was backfilled after a heredoc bug at script end; all 12 chunk lines show fail=0 in `soak/summary.tsv`.

## Still backlog (not this gate)
- L3b sharding · Paste pipeline · memcache · servers_per_port · Python formal cluster · dedicated hub HW
