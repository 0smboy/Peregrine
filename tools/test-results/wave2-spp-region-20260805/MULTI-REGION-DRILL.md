# Multi-region Contabo drill — dry-run plan (Wave 2)

Date: 2026-08-05  
Authority: `docs/fairness-lab/MULTI-REGION.md`

## Target labels (not WAN)

| Node | Public (mgmt) | Client | region | zone |
|------|---------------|--------|--------|------|
| swift1 | 169.58.108.85 | 10.0.0.1 | 1 | 1 |
| swift2 | (inventory) | 10.0.0.2 | 1 | 2 |
| swift3 | (inventory) | 10.0.0.3 | 2 | 1 |
| swift4 | (inventory) | 10.0.0.4 | 2 | 2 |

Sample templates: `swift-deploy-rs/bundle-rust/config_sample/host_vars/10.0.0.{11..14}.yml`.

## Steps (when Wave 0 frees space — **no wipe**)

1. Patch live `host_vars` region/zone per table.
2. Prefer `expand.yml` / `ring_expand=true` (idempotent add). Only use `ring_force_rebuild` if ops accept full ring replace **without** touching `/srv/node`.
3. Confirm `swift-ring-builder object.ring.gz search` shows both `r1z…` and `r2z…`.
4. PUT/GET via VIP `:8085`; let replicators heal.
5. Record placement sample (which devices got copies) — affinity preference, not latency SLA.

## Explicit non-claims

- Not cross-city DR
- Not async container-sync
- Not independent per-region auth endpoints

## Status

**Dry-run / plan only this cycle.** Live apply = backlog.
