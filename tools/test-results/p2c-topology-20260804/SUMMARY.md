# P2c topology / workers — SUMMARY (2026-08-04)

**Verdict: GREEN** (with honest residuals below)

## What shipped

| Item | Status |
|------|--------|
| `servers_per_port` parse + ring port discovery | Done (`servers_per_port.rs`) |
| Multi-port / REUSEPORT acceptors → shared pool | Done (`serve_forever_multi`) |
| Workers semantics doc | `docs/fairness-lab/WORKERS-SEMANTICS.md` |
| Calibration tools | `swift-effective-concurrency` + `tools/fairness-lab/scripts/effective-concurrency.py` |
| CONFIG-PARITY upgrade | `servers_per_port` / `ring_ip` / `workers` mapped |
| Contabo deploy (Linux build on swift1, fanout ×4) | Done; default `servers_per_port=0` |

## Gates

| Gate | Result |
|------|--------|
| Unit (`servers_per_port` 8/8 on Mac + Contabo) | PASS |
| Contabo object-server active ×4 on `:6200` | PASS |
| CORE-PATH func VIP | **54/54** |
| Perf smoke 50×64KB PUT/GET | **PASS** (PUT avg 258ms, GET avg 133ms; 0 fails) |
| Disk / no wipe | OK (~22% root on swift4 sample) |
| Contract updates | DONE |

## Residuals (do not block GREEN)

- Shared thread pool ≠ Python prefork per-disk I/O isolation.
- Contabo rings are single-port-per-node (`6200`); discovery returns `{6200}`. Multi-disk ports need ring rebuild (not this wave; no wipe).
- Default lab keeps `servers_per_port=0` (same shape as pre-P2c CORE-PATH baseline).
- Ops note: an accidental macOS arm64 binary push caused brief Exec-format crash loops; recovered by building ELF on swift1 and fanout.

## Evidence

- This directory + `P2C-REPORT.html`
- Units: `05-cargo-unit.txt`, Contabo `12-build-swift1.txt`
- Deploy/fanout: `13-fanout.txt`
- Func: `14-func-suite-vip.txt`
- Perf: `15-perf-smoke.txt`
- Discovery: `07-discovery-smoke.txt`
