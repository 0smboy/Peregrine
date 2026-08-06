# L3b auto_shard live · 2026-08-06

**Verdict: PARTIAL / NOT CLAIMED for multi-node KEEP**

| Step | Result |
|------|--------|
| Set `auto_shard=true`, threshold=8, min=2 ×4 | applied + restored |
| Container 20 objects | created |
| Sharder activity (sharding/cleaved>0) | **NOT observed** in 100s (still skipped) |
| Backend path probe | 400 Invalid path (client URL shape) |
| conf restored | yes |

## Why auto_shard may not fire

- Daemon only transitions **Unsharded** containers already on disk when `object_count >= threshold`; pending flush / which devices walked may delay.
- Or conf keys not all read (need verify `shard_container_threshold` landed under `[container-sharder]` on each node).
- HTTP multi-node quorum still requires daemon path using `HttpShardReplicator` (current mode: local cleave).

## Residual

Force SHARDING via direct broker / manage tooling, or wire HTTP replicator into sharder binary for live multi-node proof.
