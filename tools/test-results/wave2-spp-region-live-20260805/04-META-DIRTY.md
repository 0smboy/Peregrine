# META_DIRTY gate (W2 live abort)

Date: 2026-08-05

## Observation

| Check | Result |
|-------|--------|
| VIP auth `test:tester` | OK |
| `GET /v1/AUTH_test` container count | **~968** (ghost/autocos* residue after Wave 0 object clear) |
| `*.data` on swift1 | 162 (d1 only) |
| `*.db` on swift1 | 978 across d1/d2/d3 |
| W0′ owner | **another agent** (plan coordinate: R0/W0′/W1) |
| Concurrent SSH | `root@pts/0` since 06:34 from 38.175.104.123 |

## Why this blocks live ring rebuild

1. Plan abort path: **meta dirty conflict** → runbook + dry-run only.
2. `ring_force_rebuild` rewrites partition maps; residual account/container DBs + ghosts make heal/listing noise uninterpretable during the window.
3. Parallel W0′ work must finish (or explicitly waive) before maintenance-window spp cutover.

## Explicit non-claims

- Wave 0 disk reclaim (~2% Use%) is **not** META clean.
- CRUD smoke / func 54/54 do **not** clear META_DIRTY.
