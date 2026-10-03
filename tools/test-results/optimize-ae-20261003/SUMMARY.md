A, B, C, and E met their acceptance lines. D is NOT ACCEPTED. The 2026-10-03 follow-up in `tools/test-results/optimize-ae-20261003/verdict.json` is RED: 1 PASS, 3 FAIL, 16 NOT RUN, 0 ENVIRONMENT BLOCKED. The three FAIL cases are `slow_put_1000` (scheduler lag p99 310.72917 ms, http_2xx 62), `slow_get_receiver` (completed 194 of 200, http_2xx 200), and `bounded_queue_overload` (scheduler lag p99 571.349475 ms, health p99 129.6479245647788 ms). `idle_keepalive_10k` passed. The other 16 cases were not re-run on this binary. Console gate stays ACCEPT_WITH_WARN (`tools/test-results/console-accept-20261002/SUMMARY.md`, 2026-10-02). `POST /api/apply` was not sent.

`16MB_read_8` stays ACCEPT_WITH_WARN (`tools/test-results/contabo-deploy-20260801/deep-verify-20260802/PERF-REMEASURE.md`, 2026-08-02).

## Phases

| Phase | Acceptance | Evidence |
|---|---|---|
| A tests | met | `0A-tests.md` |
| B docs | met. `tools/docs-claim-audit.sh` exit 0. Live tokens in `0B-docs.md` | `0B-docs.md` |
| C swift4 disk | met. `/` 939M free (98%) before, 1.5G free after. VIP still on swift1. `/info` 200 | `0C-disk.md` |
| D G7 | NOT ACCEPTED. Follow-up 1 PASS, 3 FAIL, 16 NOT RUN | `0D-g7.md`, `verdict.json` |
| E L3b failure case | met. Docs still say L3b deferred | `0E-l3b.md` |

## G7

Listening binary on swift1 `:18080`: sha256 `3bac7c9ce904a39476009549eb568f4356dfe4336aa4d39416604c1aaebc3dc5` at `/root/work/g6-rust-bin/swift-proxy-server` (2026-10-03). Production binary sha256 stayed `5cac5960c45b3a206a794e0a0c52d89f51c251b0ce698de21f245da7fa6a2397`, pid 3495932. `:8080`, `:8085`, and VIP `10.0.0.10/22` stayed up. New yaml: `g7-acceptance.yaml`. Lab stayed on `/etc/g6-rust` and `:18080`.
