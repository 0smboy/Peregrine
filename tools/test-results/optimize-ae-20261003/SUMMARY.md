A, B, C, and E met their acceptance lines. D is NOT ACCEPTED. G7 verdict is RED: 1 PASS, 18 FAIL, 1 NOT RUN (`eio`, reason `no EIO mapper`), from `tools/test-results/optimize-ae-20261003/verdict.json` (2026-10-03). Console gate stays ACCEPT_WITH_WARN (`tools/test-results/console-accept-20261002/SUMMARY.md`, 2026-10-02). `POST /api/apply` was not sent.

`16MB_read_8` stays ACCEPT_WITH_WARN (`tools/test-results/contabo-deploy-20260801/deep-verify-20260802/PERF-REMEASURE.md`, 2026-08-02).

## Phases

| Phase | Acceptance | Evidence |
|---|---|---|
| A tests | met | `0A-tests.md` |
| B docs | met. `tools/docs-claim-audit.sh` exit 0. Live tokens in `0B-docs.md` | `0B-docs.md` |
| C swift4 disk | met. `/` 939M free (98%) before, 1.5G free after. VIP still on swift1. `/info` 200 | `0C-disk.md` |
| D G7 | NOT ACCEPTED | `0D-g7.md`, `verdict.json` |
| E L3b failure case | met. Docs still say L3b deferred | `0E-l3b.md` |

## G7

Listening binary on swift1 `:18080`: sha256 `352da6f120d4f9661a736b0911f8cb6f2c36f74fa014a3b06524e0564a2f92c6`, commit `45956edfaa5ed2205603c78702f089994f9e2250` (`/root/work/g6-rust-bin/G0-IDENTITY-45956ed.txt`). New yaml: `g7-acceptance.yaml`. Lab stayed on `/etc/g6-rust` and `:18080`.
