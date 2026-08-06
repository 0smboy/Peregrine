# L3b listing KEEP retest · Contabo · 2026-08-06

**Verdict: LAB listing KEEP demonstrated (engineered path) — not PRODUCTION-GO-LIVE**

Container: `l3bretest1786020669` (59 objects after fill; printf octal quirk lost 08/09)

## Pass gates (live)

| Gate | Result |
|------|--------|
| Deploy fixed `swift-proxy` (unit `swift-proxy`, not `swift-proxy-server`) | **PASS** ×4 |
| Deploy fixed `swift-container-server` (epoch-only `is_deleted`) | **PASS** ×4 |
| `find_and_replace --force --enable` + `set_sharding_state` | **PASS** → `db_state=sharded` |
| Sharder multipass cleave | **PASS** shard DBs with object rows |
| Object GET by name post-cleave | **PASS** 200 |
| Proxy listing after fan-out + ring-correct shard placement | **PASS `listed 59`** |

Evidence: `10-listing-keep-pass.txt`, `03-enable.txt`, `05-post-info.txt`, `07-direct-after-fix.txt`, `09-quorum-shards.txt`.

## Root causes fixed this wave

1. **Proxy unit name** — deploy must restart `swift-proxy` (binary replace left `(deleted)` process).
2. **`is_deleted` / `get_info_is_deleted`** — checked constructor `<hash>.db` only; after `set_sharded_state` only `<hash>_<epoch>.db` remains → false 404. Fixed to use `db_files()`.
3. **Listing fan-out empty-replica short-circuit** — `get_or_head` first-wins on `[]` from a lagging primary; walk primaries for non-empty `states=listing`.
4. **Sharder wrote shard DBs under root partition** — ring partition for `.shards_*` differs; proxy fan-out missed data. Code: place under shard's own ring part (`process_sharding_container_detailed_with_ring`). Live retest: relocated + copied shard DBs to ring primaries.

## Residual honesty

| Claim | Allowed? |
|-------|----------|
| Lab multi-node listing after cleave (this container, after relocate) | **YES (lab)** |
| Automatic cleave always lands on ring part without ops relocate | **After sharder rebuild/redeploy** (source fixed; redeploy this session) |
| Multi-epoch enable on all replicas independently | **Avoid** — enable once, replicate |
| PRODUCTION-GO-LIVE / product KEEP vs Python对照 | **NO** |
| Operator TLS PEM / multi-cluster sync soak / KMIP | **NO** |

## Binaries (swift1 at pass)

See `10-listing-keep-pass.txt` sha256 lines for proxy / container-server / sharder / manage-shard-ranges.

## Next

1. Redeploy `swift-container-sharder` with ring-part local cleave.
2. Fresh container end-to-end without manual relocate.
3. Update parity matrix: L3b listing KEEP **lab partial** only.
