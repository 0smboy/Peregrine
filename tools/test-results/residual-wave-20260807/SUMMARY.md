# Residual priority wave · Contabo · 2026-08-07

**Claim level:** LAB-HARD-GREEN only. **Not** PRODUCTION-GO-LIVE.

| Pri | Item | Result | Evidence |
|-----|------|--------|----------|
| P0 | Operator TLS PEM | **BLOCKED** — script ready; no operator PEM; lab self-signed live | `01-tls-operator-path.txt` |
| P0 | L3b product 4KB | already KEEP prior wave | `priority-wave-20260806` |
| P1 | multi-primary auto-shrink | **RESIDUAL** — peer roots missing live `shard_range` rows; local shrink KEEP prior | `04-*`, `04b-*` |
| P1 | same-cluster sync re-verify | **KEEP** when sync runs on SRC primary node (swift2) | `05-sync-reverify.txt`, `08-sync-swift2-once.txt` |
| P1 | multi-cluster sync | **RESIDUAL** — no realms conf / second cluster | `03-multi-cluster-residual.txt` |
| P1 | Python对照 | **BLOCKED** — PYTHON_CLUSTER_ABSENT | `02-python-cluster-absent.txt` |

## Sync re-verify detail
- Fail when: only `swift-container-sync once` on swift1 while SRC lives on 10.0.4.2–4
- KEEP: once on swift2 → dst count=5, GET 5/5 `payload-N`
- Ops: continuous container-sync unit should run on **all** nodes

## Multi-primary shrink detail
- swift1 shrinklab: SHRUNK donor + ACTIVE acceptor already
- 10.0.4.3/4 shrinklab roots: object_count=100 but **empty** non-deleted ranges
- Auto multi-primary shrink still residual (needs range table + donor co-location via replicator)

## Not claimed
- PRODUCTION-GO-LIVE
- Operator PEM
- Multi-cluster realm soak
- Full Rust vs Python L3b对照
