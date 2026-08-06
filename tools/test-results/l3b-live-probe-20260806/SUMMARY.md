# L3b live probe · 2026-08-06

**Verdict: PRESENT / multi-node KEEP NOT CLAIMED**

| Item | Result |
|------|--------|
| swift-container-sharder ×4 | **active** |
| Passes | `sharding=0 skipped=N failures=0` (no containers in SHARDING) |
| `auto_shard` | **false** in conf (local cleave only) |
| Multi-node HTTP shard quorum live | **not exercised** |
| 4KB KEEP | **not claimed** |

## Residual for production L3b stop-line

1. Enable a container into SHARDING (manage-shard-ranges / enable_sharding)  
2. Wire daemon to `HttpShardReplicator` (not local-only)  
3. Prove multi-node create + cleave + listing fan-out  
4. Only then consider KEEP with Python对照

Unit stop-line remains prior GREEN under `wave3-s3-l3b-prod-20260805/`.
