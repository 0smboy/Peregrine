# Sharder shrink + sharded HEAD count (2026-08-06)

## Code (unit KEEP)
- `process_shrinking_donors`: move donor objects → covering ACTIVE acceptor,
  mark donor **SHRUNK** + deleted (timestamp-bumped merge).
- Only runs when the **donor shard DB already exists** on the local device
  (no auto-create empty DB → no false SHRUNK on multi-primary).
- Unit: `test_process_shrinking_donors_moves_objects_and_marks_shrunk` PASS.

## Proxy HEAD count
- `patch_sharded_head_counts`: for sharded/sharding HEAD, sum live object
  counts from listing-state shard containers (skip SHRUNK).
- Lab `l3bclean`: HEAD was stale 80; after patch HEAD=60 (shard sum).
  List JSON len=80 (fan-out still includes residual root rows).
  GET post-shard keys still 200 (k4b-wave2-01 size=4096).

## Live Contabo residual
- Early deploy briefly auto-created empty local donor DBs and marked SHRUNK
  without local data (fixed by open_existing). Root range table now shows
  single ACTIVE acceptor on the replica that ran shrink.
- Full multi-node shrink KEEP (quorum + all primaries) **not claimed**.
- HEAD count still may lag list when root residual rows are listed.
