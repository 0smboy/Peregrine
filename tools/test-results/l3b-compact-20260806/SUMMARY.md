# L3b compact / shrink (2026-08-06 update)

## Proven (lab)
- Root `db_state=sharded` compactable after CLEAVED stuck diagnosed
- CLI: `activate_cleaved --force`, `compact --include-cleaved`, `compact --force`
- Live: CLEAVED→ACTIVE→donor **SHRINKING** + acceptor expanded full namespace
- Unit: 11/11 manage-shard-ranges tests including cleaved include flag

## Residual
- Sharder did not finish shrink object migration in one `once` pass
- Multi-node range replication after compact not verified
- Product shrink KEEP / Python对照 not claimed
