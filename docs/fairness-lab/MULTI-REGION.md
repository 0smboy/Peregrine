# Multi-region notes (bundle-rust · Wave 2)

## What ships

| Piece | Behavior |
|-------|----------|
| `host_vars.region` / `zone` | Rendered by workspace; consumed by `build_rings.sh.j2` as `r<R>z<Z>-…` |
| Sample Contabo-shaped labels | `10.0.0.11`/`12` → **r1** z1/z2; `10.0.0.13`/`14` → **r2** z1/z2 |
| Default | `region: 1`, zone = group order if omitted |
| Affinity | Swift ring handoffs prefer other regions then zones (library behavior) |
| Per-device object ports | `object_port_per_device` (d1→6200, d2→6201, …) independent of region labels |

## What does **not** ship

- Independent per-region clusters with separate hashes / auth endpoints
- Cross-region WAN replication tooling or async container-sync (container-sync still wontfix)
- UI wizard multi-region topology designer beyond per-node `region`/`zone` fields
- Guaranteed low partition movement on expand (Rust builder has no persistent replica2part2dev)
- Claiming Contabo dual-region **labels** as real multi-site / cross-city DR

## Operator guidance

1. Assign **region** for true geographic/failure domains; use **zone** for rack/AZ inside a region.
2. Production rings should keep ≥2 distinct `(region, zone)` pairs (workspace already warns/errors for production).
3. Adding a node in a new region: update inventory → `expand.yml` (sets `ring_expand`) → let replicators heal. Maintenance window required.
4. Do **not** wipe `/srv/node` when changing regions; only rings + replication move data.

## Contabo lab drill (dry-run until Wave 0 frees space)

**Live ring rebuild / expand is BACKLOG** while `/srv/node/d*` is near-full (see Wave 0 evidence). No wipe.

| Step | Action | Gate |
|------|--------|------|
| 1 | Set host_vars: swift1/2 → `region: 1`, swift3/4 → `region: 2` (zones distinct) | inventory dry-run |
| 2 | Render `build_rings.sh` with `object_port_per_device=true` | template shows `r1z*…` and `r2z*…` |
| 3 | When disk Avail is safe: `ring_force_rebuild` **or** expand add (no wipe) | discovery returns 3 ports/node if 3 disks |
| 4 | PUT object; inspect ring handoffs for cross-region replica placement | honest: same-LAN latency |
| 5 | `expand.yml` add a device/zone; wait replicator heal | no data wipe |

Evidence: `tools/test-results/wave2-spp-region-YYYYMMDD/` (plan artifacts + unit proof; live Contabo rebuild deferred).
