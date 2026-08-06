# L3b after Linux redeploy · Contabo · 2026-08-06

**Verdict: PARTIAL — CLI+cleave progress; NOT listing KEEP product claim**

## A. Redeploy (PASS)

See `../linux-redeploy-20260806/SUMMARY.md` — manage-shard-ranges / sharder / container-sync
built on swift1 and installed ×4.

## B. Container `l3bdrill1786014205` (pre-fix CLI)

| Gate | Result |
|------|--------|
| New CLI | **PASS** |
| find / find_and_replace --enable (without set_sharding_state) | ranges injected; **db_state stayed unsharded** |
| Listing / GET while only sysmeta set | **PASS** listed 100, GET 200 |

## C. Container `l3bkeep1786018114` (after enable→set_sharding_state fix)

| Gate | Result |
|------|--------|
| `find_and_replace --force --enable` | **PASS** — `Created epoch DB for SHARDING state` |
| `db_state` after enable | **sharding** (epoch file present) |
| Sharder multi-pass | Created **shard DBs** (`…-0`, `…-1`); `cleaving_done=true` |
| Root listing | **FAIL** — `listed 0` after cleave |
| Object GET by name | **PASS** — obj-00001/30/60 → **200** (data not lost) |
| `db_state = sharded` | **FAIL** — still not clean SHARDED product state |

## Root cause fixed in tree

`cmd_enable` now calls `ContainerBroker::set_sharding_state()` after
`enable_sharding` so epoch DB exists and sharder can enter the SHARDING arm.

## Product claim

| Claim | Allowed? |
|-------|----------|
| Linux redeploy of L3b tools | **YES** |
| CLI find/enable/analyze on Contabo | **YES** |
| Sharder creates shard DBs live | **YES (lab)** |
| Multi-node listing KEEP product | **NO** (listing empty post-cleave) |
| PRODUCTION-GO-LIVE | **NO** |

## Next engineering

1. Proxy listing fan-out over shard ranges after root object_count→0  
2. Finish SHARDED transition (own range, retiring cleanup)  
3. Replicate ranges to all primaries before cleave  

## Files

`02-ops.txt` … `07-cleave-finish.txt`, `06-fixed-enable-cleave.txt`
