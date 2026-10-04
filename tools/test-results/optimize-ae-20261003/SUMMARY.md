A, B, C, D, and E met their acceptance lines. D is ACCEPTED. The 2026-10-03 full yaml run in `tools/test-results/optimize-ae-20261003/verdict.json` (source `swift4:/root/work/g7-optimize-ae-20261003/out-rerun3/verdict.json`) is GREEN: 20 PASS, 0 FAIL, 0 NOT RUN, 0 ENVIRONMENT BLOCKED. `slow_put_1000` is http_2xx 1000, http_503 0, lag p99 41.298006 ms, health p99 47.349 ms. `slow_get_receiver` is http_2xx 200, completed 200, lag p99 2.389661 ms, health p99 37.27054409682751 ms. `bounded_queue_overload` is http_2xx 545, http_503 3455, lag p99 49.51831 ms, health p99 166.6510784998536 ms. Console gate stays ACCEPT_WITH_WARN (`tools/test-results/console-accept-20261002/SUMMARY.md`, 2026-10-02). `POST /api/apply` was not sent. On 2026-10-04 production `/usr/local/bin/swift-proxy-server` on swift1–4 is sha256 `dc22cca7b45e6bbc4a096f99675aeab8855282276fc9f8caaa2d6ed00f402314` (`0G-prod-roll.md`). The production G7 suite was not re-run on `:8085`. The production cluster did not pass G7. Production readiness remains NO-GO. Object, container, and account servers were not rolled. A newly sealed identity plan, digest `8195ef0adca513ae7c67c2966ff4aaaa11693bfb19d4efea6bf386d7abe6a9b9`, was not applied.

`16MB_read_8` stays ACCEPT_WITH_WARN (`tools/test-results/contabo-deploy-20260801/deep-verify-20260802/PERF-REMEASURE.md`, 2026-08-02).

## Phases

| Phase | Acceptance | Evidence |
|---|---|---|
| A tests | met | `0A-tests.md` |
| B docs | met. `tools/docs-claim-audit.sh` exit 0. Live tokens in `0B-docs.md` | `0B-docs.md` |
| C swift4 disk | met. `/` 939M free (98%) before, 1.5G free after. VIP still on swift1. `/info` 200 | `0C-disk.md` |
| D G7 | ACCEPTED. Full yaml 20 PASS, 0 FAIL, 0 NOT RUN (`out-rerun3`, 2026-10-03) | `0D-g7.md`, `verdict.json` |
| E L3b failure case | met. Docs still say L3b deferred | `0E-l3b.md` |

## G7

Listening binary on swift1 `:18080`: sha256 `dc22cca7b45e6bbc4a096f99675aeab8855282276fc9f8caaa2d6ed00f402314` at `/root/work/g6-rust-bin/swift-proxy-server`, context `bin_t` (2026-10-03, `verdict.json`). Lab object server sha256 `add3f2b92f9435555801a98b2fdae9eb154a7f6d23d3af9755def3aa5a73e478`. During that lab run the production binary stayed sha256 `5cac5960c45b3a206a794e0a0c52d89f51c251b0ce698de21f245da7fa6a2397`, pid 3495932. It was replaced on 2026-10-04: `0G-prod-roll.md`. `:8080` and `:8085` stayed up through the lab run. At 13:49:37 UTC keepalived removed VIP `10.0.0.10` from swift1 `eth1` after `chk_http_port` timed out. It was still absent from swift1 after the green run because swift2 held it. `http://10.0.0.10:8080/healthcheck` returned 200 from that owner. Restored to swift1 only: `0F-vip.md`. Yaml: `g7-acceptance.yaml`. Lab stayed on `/etc/g6-rust` and `:18080`.
