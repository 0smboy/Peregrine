# Fairness lab sync manifest — 2026-08-03

| Channel | Location |
|---------|----------|
| Git tip | `b9f5506` |
| Vercel | `dpl_B3B4t7vsde5TQWz7khFaZFDvw8TN` |
| Evidence | `tools/test-results/fairness-lab-20260803/` |
| Tooling | `tools/fairness-lab/` |
| Docs | `docs/fairness-lab/` |
| Visual | `REPORT.html`, `SCORECARDS.html`, canvas `fairness-lab-20260803.canvas.tsx` |
| Drive (after publish) | `gdrive:Peregrine/2026-08-03-fairness-lab/` |

## Gate snapshot

| Item | Result |
|------|--------|
| P0 audit report | shipped |
| P1 preflight | 4/4 hosts ssh_ok; by-uuid devices filled |
| P2 mode-switch | scripts + systemd target overlays |
| P3 CONFIG-PARITY | 73 rows; 11 unsupported |
| P4 compat-diff CORE-PATH | **PASS** fail=0 (11 cases) |
| P5 formal DIRECT-4PROXY | harness + dry-run; formal ≥8 A/B **pending** mode exclusivity |
| P6 chaos | dry-health OK; proxy-loss scenario harness |
| P7 observability | migration record; live move needs window |
| P8 hybrid honesty | DEPLOY-HYBRID + blocked-by-missing-impl |
