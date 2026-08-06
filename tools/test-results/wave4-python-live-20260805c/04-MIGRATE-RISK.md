# Why Rust d1 → d2/d3 migrate was NOT executed this cycle

**Decision: BLOCKED_UNSAFE_MID_IDENTITY** — prefer honest BLOCKED over live ring surgery.

## Live facts (2026-08-05c)

| Fact | Value |
|------|--------|
| Account ring | d1-only ×4, port 6202 |
| Container ring | d1-only ×4, port 6201 |
| Object / object-1 | d1+d2+d3 ×4, ports 6210–6212 (spp) |
| Contabo `/etc/swift/build_rings.sh` | **STALE** vs live: still greenfield plan `object :6200 /d1` only; stamp SHA matches script (so stamp path is a landmine if force-rebuild) |
| `swift-ring-builder` on Contabo | `create\|add\|rebalance` only — **no `remove`**; `add` can update weight |
| Rebalance semantics | Rust builder **full remap** from device list (no replica2part2dev persistence) — see P3-OPS-CONTRACT |
| Identity | W1 LAB GREEN: Keystone+TLS coexist; VIP `https://10.0.0.10:8085` healthcheck **200** |
| Auth regression this cycle | TempAuth token OK but account list **401**; Keystone token OK but Swift **403** — do not stack ring remap on fragile auth |
| d1 data size | ~50–90 MiB/node (A+C+O) — heal would be small **if** remap were safe |
| openstack-swift | **not installed** on any node |

## Why migrate now is unsafe

1. **Identity window still hot:** Keystone cutover is LAB-green but TempAuth/Keystone Swift CRUD is not clean this probe. Ring remap during auth noise makes rollback attribution impossible.
2. **Tooling mismatch:** Live object spp rings are out-of-band vs stamped `build_rings.sh`. Accidental greenfield/force rebuild would snap object back to `:6200/d1` and break spp.
3. **No gradual drain:** Weight→0 + rebalance is a **cluster-wide partition shuffle**, not Python-style min_part_hours drain. VIP must be in a declared maintenance window with ring backups on all four nodes.
4. **Object still claims d1:** Migrating only A/C leaves object on d1 → PORT-DISK-MATRIX still FAIL. Full isolation needs object d1 weight drained too (larger blast).
5. **Matrix honesty:** Revising the matrix to “share d1” would enable an unsafe Python install. **Rejected.** Target assignment unchanged: Python exclusive `d1`, Rust `d2` (+`d3`).

## What was deliberately not done

- No `swift-ring-builder … rebalance` on account/container/object
- No openstack-swift package install
- No mkfs / no `/srv/node` wipe
- No PRODUCTION-GO-LIVE claim
