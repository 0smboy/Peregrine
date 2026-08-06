# Sharder shrink KEEP (2026-08-06)

## Unit
- `process_shrinking_donors` moves objects, marks SHRUNK (timestamp-bumped merge)
- Skip when donor DB not local (no false SHRUNK)

## Contabo lab KEEP (`02-shrinklab-KEEP.txt`)
- Container `shrinklab1786029572`: 20 objects, 2 local shards
- CLEAVED → ACTIVE → compact SHRINKING → sharder shrink
- Donor **SHRUNK** live=0; acceptor live=20
- Client HEAD count=20, list=20, GET 20/20

## Proxy HEAD counts
- `patch_sharded_head_counts` sums shard HEADs for sharded roots

## Not claimed
- Multi-primary shrink when donor/acceptor on different nodes (needs remote move / replicate)
- PRODUCTION-GO-LIVE
