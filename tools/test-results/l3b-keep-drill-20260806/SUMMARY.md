# L3b KEEP drill · Contabo · 2026-08-06

**Verdict: PARTIAL — NOT multi-node KEEP product claim**

## What ran (live, non-wipe)

| Step | Result |
|------|--------|
| Auth TempAuth local `:8080` | OK (`test:tester` / lab key) |
| Create container + 100 objects | **PASS** `l3bdrill1786014205` (API HEAD object_count=100) |
| VIP HTTPS storage URL | Needs `curl -k` (lab self-signed) — used local HTTP |
| Container DB replicas | **Found on swift2, swift3, swift4** (`/srv/node/d2/containers/...`); **not on swift1** (ring placement) |
| `swift-manage-shard-ranges info/enable/analyze` | **BLOCKED** — Contabo binary (2026-08-04) only supports **`find`**: `only the 'find' subcommand is supported` |
| Sharder unit ×4 | **active** (prior probe) |
| Multi-node KEEP / cleave under load | **not executed** (needs new Linux binaries redeployed) |

## Blocker for KEEP claim

1. **Redeploy** Linux `swift-manage-shard-ranges` + `swift-container-sharder` built from `d21dc41+` (analyze/compact/repair + ring HTTP path).
2. Then: `find_and_replace --force --enable` on all replica DBs → sharder pass → verify SHARDED + listing KEEP.

## Residual honesty

- Status probe (daemon active ×4) ≠ KEEP.
- Lab self-signed VIP TLS still blocks naive external clients.

## Evidence files

- `00-env.txt`, `02-l3b-drill-local.txt`, `05-find-db-all-nodes.txt`, `06-shard-ops-swift2.txt`
