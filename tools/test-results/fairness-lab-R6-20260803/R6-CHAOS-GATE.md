# R6 Stop — Chaos + Soak

| | |
|--|--|
| **Status** | **GREEN** |
| **When** | 2026-08-03 |

## Chaos

| Scenario | Result | Evidence |
|----------|--------|----------|
| dry-health | auth 200 | `chaos/dry-health/` |
| proxy-loss | **ok=20 fail=0**；swift2 recovered | `chaos/proxy-loss/SUMMARY.json` |
| object-loss | **ok=20 fail=0**；swift3 recovered | `chaos/object-loss/SUMMARY.json` |
| vip-master (ha-test) | baseline/degraded/recovered PASS | `chaos/vip-master-loss/ha-test.log` |

## Soak

| | |
|--|--|
| Window | **1h smoke**（07:18–08:18Z）；目标 6h → backlog |
| Entry | DIRECT-4PROXY · `1KB_write_64` |
| Result | **fails=0** · iters=147 |
| Evidence | `soak/SUMMARY.json` · `soak/soak.log` |

## Residual

无未恢复故障。
