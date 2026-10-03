A, B, C, and E met their acceptance lines. D is NOT ACCEPTED. G7 verdict is RED: 17 PASS, 3 FAIL, 0 ENVIRONMENT BLOCKED, 0 missing, from `tools/test-results/optimize-ae-20261003/verdict.json` (2026-10-03). The three FAIL cases are `slow_put_1000`, `slow_get_receiver`, and `bounded_queue_overload`. Console gate stays ACCEPT_WITH_WARN (`tools/test-results/console-accept-20261002/SUMMARY.md`, 2026-10-02). `POST /api/apply` was not sent.

`16MB_read_8` stays ACCEPT_WITH_WARN (`tools/test-results/contabo-deploy-20260801/deep-verify-20260802/PERF-REMEASURE.md`, 2026-08-02).

## Phases

| Phase | Acceptance | Evidence |
|---|---|---|
| A tests | met | `0A-tests.md` |
| B docs | met. `tools/docs-claim-audit.sh` exit 0. Live tokens in `0B-docs.md` | `0B-docs.md` |
| C swift4 disk | met. `/` 939M free (98%) before, 1.5G free after. VIP still on swift1. `/info` 200 | `0C-disk.md` |
| D G7 | NOT ACCEPTED. 17 PASS, 3 FAIL, 0 blocked | `0D-g7.md`, `verdict.json` |
| E L3b failure case | met. Docs still say L3b deferred | `0E-l3b.md` |

## G7

Listening binary on swift1 `:18080`: sha256 `e6ac2931b2e11925e89f60867137f45727a8344328ca03227efc06557ad897dc` at `/root/work/g6-rust-bin/swift-proxy-server` (2026-10-03). Production binary sha256 stayed `5cac5960c45b3a206a794e0a0c52d89f51c251b0ce698de21f245da7fa6a2397`. New yaml: `g7-acceptance.yaml`. Lab stayed on `/etc/g6-rust` and `:18080`.
