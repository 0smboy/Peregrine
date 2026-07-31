# Repair Debt calibration

Recorded on the azure-swift cluster after deploying `/lab/debt`.

| Phase | Debt | Interest %/h | TTI | Hosts up (`nodes_up`) | Notes |
|-------|------|--------------|-----|------------------------|-------|
| healthy baseline | ~1–5 | negative | ∞ | 4 | hosts + Swift both fine |
| swift4 taken down | ~71 | **+150** | ~4.8 h | 4 | host still scrapes; Swift units down |
| swift4 restored | declines toward baseline | negative | ∞ | 4 | back to baseline |

## Observations

1. **Monitor `nodes_up` is host online only** (`up{job="node"}`). A node with Swift stopped still counts as online. Swift unit health lives on the Services / Node HA surfaces, not as a second overview tile.
2. **Debt responds within seconds** of a node take-down via replicator failure rates and unhealthy-node fraction (async_pending stayed 0 — expected for a clean stop without object churn).
3. **Proxies are honest** — the page states there is no Prom backlog gauge; feeds expose async_pending, quarantine, balance_pct, disk, rates, unhealthy_frac.

## How to re-run

```bash
# login cookie then:
curl -b CK http://127.0.0.1:9000/lab/api/debt/snapshot
# take down / bring up via /lab/api/node/{down,up}
```
