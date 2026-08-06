# L3b compact / shrink residual (2026-08-06)

## Proven
- `l3bclean1786024121` root **db_state=sharded** (epoch-only DB).
- `swift-manage-shard-ranges compact` runs dry-run on SHARDED roots
  (no longer blocked by false `db_state=sharding` when only epoch file remains).
- `l3bretest` advanced SHARDING→SHARDED after retiring non-epoch `.db` removed
  (lab only; sharder `set_sharded_state` residual when dual files linger).

## Residual
- Compact identified **0 sequences** with current ranges (2 shards,
  `obj-00030` split) at shrink_threshold=100 — likely range `state`/`row_count`
  not meeting donor criteria (need ACTIVE + row_count < threshold).
- Full shrink/expand + sharder donor migration not exercised end-to-end.
- Not product KEEP for compact.
