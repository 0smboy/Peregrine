# Sharder shrink KEEP (2026-08-06)

## Unit
- `process_shrinking_donors`: local move + SHRUNK; skip missing donor DB

## Contabo LAB KEEP
1. **shrinklab1786029572** (`02-shrinklab-KEEP.txt`): single-node full path
   CLEAVED→ACTIVE→compact→shrink; donor SHRUNK; acceptor 20; GET 20/20
2. **l3bclean co-located repair** (`03-l3bclean-colocate-shrink.txt`):
   donor 90→0, acceptor 0→90 after root DB co-located with donor on swift1

## Proxy HEAD
- Sums listing-state shard HEADs; may lag list when residual root rows exist

## Residual (honest)
- Automatic multi-primary shrink (range table only on nodes without donor data)
  needs container-replicator / root fan-out — **not claimed**
- PRODUCTION-GO-LIVE not claimed
