# Auditor SLA — Rust vs Python (P2b)

Evidence: `tools/test-results/p2b-audit-20260804/` (2026-08-04).

## Model chosen: continuous daemon (not timer-equivalent)

Rust P2b ships **conf-driven continuous auditors**, matching Python's
`ObjectAuditor` / `DatabaseAuditor` loop shape — not a "prove nightly timer
equals continuous" claim. The legacy nightly `swift-audit-sweep.timer` is
**disabled** when continuous units are installed.

| Dimension | Python | Rust P2b |
|-----------|--------|----------|
| Process model | Long-lived daemon, sleep between passes | Long-lived systemd `Type=simple`, sleep between passes |
| Object interval default | 30s (`swift/obj/auditor.py`) | 30s (`[object-auditor] interval`) |
| Account/container interval default | 1800s (`swift/common/db_auditor.py`) | 1800s (`[account-auditor]` / `[container-auditor]`) |
| Restart | init/systemd | `Restart=on-failure` |
| One-shot | `swift-init … once` | `<bin> <conf> once` + legacy per-device CLI |
| Nightly timer | N/A (daemon is primary) | Disabled (manual oneshot retained) |

## Fairness / ops claim language

- **Allowed:** "Rust auditors run continuously with Python-default intervals
  (object 30s, DB 1800s) under systemd."
- **Not allowed:** "Nightly timer is SLA-equivalent to Python continuous
  auditor" (pre-P2b model; retired).
- **Not allowed:** "container-sync is production-complete" (wontfix P2b).

## Residuals (documented, not GREEN blockers)

- First Contabo `/srv/node` object pass can take many minutes (2 policies ×
  disk contents); continuous unit remains active; tiny-devices once proves
  the pass path in suite.
- No rate limiting / `hashes.pkl` incremental / ZBF / watcher plugins.
- DB auditor classifies corrupt DBs; quarantine move still deferred.
- Stop mid-pass waits for current sweep (`TimeoutStopSec=180`).
