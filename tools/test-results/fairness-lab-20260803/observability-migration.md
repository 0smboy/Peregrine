# P7 — Observability / control-plane migration record

**Date:** 2026-08-03  
**Status:** PLAN APPLIED IN REPO · LIVE MOVE PENDING OPERATOR WINDOW

## Current (polluting)

| Service | Host | Port |
|---------|------|------|
| Prometheus | swift1 | 127.0.0.1:9090 |
| Loki | swift1 | :3100 |
| swift-console | swift1 | :9000 |
| deploy UI | swift1 | :8789 |
| Python SAIO | swift1 | :8090 |
| Rust SAIO | swift1 | :8081 |

## Target

1. **Preferred:** dedicated monitoring/controller host outside the four storage nodes.
2. **Interim:** relocate Prometheus/Loki/console to **swift4** loopback-only; keep Alloy/node_exporter on all nodes; **forbid** SAIO and autocos load generation on the monitoring host.
3. Bench clients: external preferred; interim **swift4 as client only** during Performance mode (no SAIO on client).

## Gate

Formal `DIRECT-4PROXY` Performance citations require either (a) monitoring off VIP MASTER, or (b) explicit `HUB_COLOCATED` tag and exclusion from main scorecard.

## Actions logged this cycle

- Inventory roles documented in `tools/fairness-lab/inventory/cluster.yml`
- Scorecard template: `SCORECARDS.html`
- Live systemd move **not** executed automatically (needs maintenance window)
