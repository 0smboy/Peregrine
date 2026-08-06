# L3b clean e2e · Contabo · 2026-08-06

**Verdict: LAB CLEAN PASS — no manual relocate**

Container: `l3bclean1786024121` · N=60 · shard_size=30

## Procedure (ops rules)

1. PUT 60 objects (`obj-00001` … `obj-00060`)
2. **`find_and_replace --force --enable` ONCE** on a single replica (`swift2` only)
3. Wait continuous container-replicator + sharder multipass (daemon + once)
4. **No** DB symlink, **no** scp relocate

## Results

| Gate | Result |
|------|--------|
| object_count pre-shard | **60** |
| enable once + epoch DB | **PASS** (`db_state` → sharding then sharded) |
| Shard placement vs ring part | **RIGHT** on all observed nodes (parts 2502 / 4765) |
| Wrong-root-part leftover | **0** |
| Proxy listing (no relocate) | **listed 60** first `obj-00001` last `obj-00060` |
| Object GET sample | **200** (01/30/31/60) |
| Multi-replica independent enable | **not used** (avoids multi-epoch poison) |

## Placement sample (`04-placement.txt`)

- Shard-0 / part **2502**: data on swift2/3/4 (oc=30); empty stubs on swift1
- Shard-1 / part **4765**: data on swift2/4 (oc=30); empty stubs elsewhere  
All paths match `swift-get-nodes` partition.

## Binaries at run

| Binary | sha256 (prefix) |
|--------|-----------------|
| proxy | `fa5aa0b98d9f…` (fan-out empty-skip object walk) |
| container-server | `766e0dc37823…` (epoch is_deleted + set_sharded own-range) |
| sharder | `93dd610b251f…` at cleave time (ring-part); own-range SHARDED bump needs sharder rebuild link of new db |
| manage-shard-ranges | `63f90b6404e3…` |

## Residual (honest)

| Item | Status |
|------|--------|
| Lab clean listing KEEP (this path) | **PASS** |
| Own-range `state_text` still `sharding` while `db_state=sharded` on pre-rebuild sharder pass | **known**; fixed in tree for next sharder deploy |
| Product KEEP / 4KB Python对照 | **not claimed** |
| PRODUCTION-GO-LIVE | **no** |
| Ranges not yet on every root replica before cleave finished | acceptable here because enable host cleaved fully; prefer waiting for range replicate in ops |

## Files

`01-clean-e2e.log`, `02-enable.txt`, `03-list-before-seed.txt`, `04-placement.txt`, `05-own-range.txt`
