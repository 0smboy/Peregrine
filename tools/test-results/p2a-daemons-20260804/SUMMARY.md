# P2a daemons — SUMMARY

**Verdict: GREEN** (2026-08-04)

## What shipped

| Daemon | Binary | Conf section | systemd | Cluster |
|--------|--------|--------------|---------|---------|
| object-expirer | `swift-object-expirer` | `[object-expirer]` in object-server.conf | `swift-object-expirer.service` | active ×4 |
| account-reaper | `swift-account-reaper` | `[account-reaper]` in account-server.conf | `swift-account-reaper.service` | active ×4 |
| container-updater | `swift-container-updater` | `[container-updater]` in container-server.conf | `swift-container-updater.service` | active ×4 |
| container-reconciler | `swift-container-reconciler` | `[container-reconciler]` in container-server.conf | `swift-container-reconciler.service` | active ×4 |

All units: `Restart=on-failure`, `TimeoutStopSec=180`.

## Gates

| Gate | Result | Evidence |
|------|--------|----------|
| Lib unit tests | 20/20 | `07-cargo-lib-units.txt` |
| P2a specialty suite VIP | **21/21** | `21-p2a-suite.txt` |
| Expirer hard-delete | PASS (`expired>=1`, `.data` removed) | `16-expire-hard-verify.txt`, suite |
| CORE-PATH func VIP | **54/54** | `22-func-suite-vip.txt` |
| Disk pressure | ~49% root; `/srv/node` not wiped | `23-disk-pressure.txt` |
| HTML report | shipped | `P2A-REPORT.html` |

## Residuals (honest, not blockers)

- Reaper: no reseller account-DELETE purge E2E on VIP this wave.
- Reconciler: no multi-policy misplaced inject on single-policy lab.
- Container-updater long first sweep mitigated with `TimeoutStopSec=180`.

## Next

P2b (auditor continuity / container-sync) — not started.
