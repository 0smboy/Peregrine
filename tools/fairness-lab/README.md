# Fairness lab tooling

Implements Contabo redesign per `deep-swiftrust-test.md` principles using
existing Peregrine deploy/test stacks (no copied ansible tree).

| Script | Phase |
|--------|-------|
| `scripts/preflight-collect.sh` | P1 |
| `scripts/mode-switch.sh` | P2 |
| `scripts/destructive-reset.sh` | P2/P5 (guarded; no auto-wipe) |
| `scripts/compat-diff.sh` | P4 |
| `scripts/perf-formal.sh` | P5 |
| `scripts/chaos-run.sh` | P6 |
| `scripts/soak-run.sh` | P6 |

Docs: `docs/fairness-lab/`. Evidence: `tools/test-results/fairness-lab-*/`.
