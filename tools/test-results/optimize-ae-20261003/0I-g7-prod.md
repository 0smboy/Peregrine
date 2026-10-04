# Production G7

Date: 2026-10-04. Final source log: `swift4:/root/work/g7-prod-20261004-r3/verdict.json`. Copied here as `verdict-prod.json`.

The harness speaks HTTP. The run used `http://10.0.0.10:8080`. Port `:18080` was not used. Case bounds were not changed. Acceptance sha256 `04492c4b37200421559529e58af0597a5ee4476e788057d2516c27a4794f613c` matches `swift-rust/tools/test-lab/g7/acceptance.yaml`.

An earlier same-day run (`swift4:/root/work/g7-prod-20261004/out/verdict.json`) on proxy sha256 `167b6622a6aeb7065eeeb20dc8918f0296f06ec65f73b12322679fcad0f85012` was 3 PASS, 17 FAIL. That binary is not the one this tally measures.

| | |
|---|---|
| cases | 20 |
| PASS | 16 |
| FAIL | 4 |
| NOT RUN | 0 |
| gate word | RED |
| production readiness | NO-GO |

PASS: `idle_keepalive_10k`, `idle_keepalive_50k`, `idle_keepalive_100k`, `slowloris`, `slow_get_receiver`, `keepalive_churn`, `fsync_stall`, `backend_blackhole`, `quorum_degradation`, `client_cancellation`, `sigterm_during_put`, `fd_exhaustion`, `enospc`, `eio`, `partial_write`, `backend_connect_timeout`.

FAIL:

| case | reason |
|---|---|
| `slow_put_1000` | http_2xx 112, http_503 888, responses 1000. Thread growth stayed inside the bound (peak 68, baseline 67). |
| `sqlite_stall` | operation_status 503. fault_hits 25. operation_ms 21400.9. |
| `bounded_queue_overload` | responses 3990, http_2xx 316, http_503 3674, failed 10. Ten opens had no 2xx or 503. |
| `sigterm_during_durability` | put_status None. fault_hits 6. |

Unfinished cases were not marked PASS. The 2026-10-03 lab run on proxy sha256 `dc22cca7b45e6bbc4a096f99675aeab8855282276fc9f8caaa2d6ed00f402314` remains 20/20 (`verdict.json`). None of these four failures occurred on that lab binary.

VIP `10.0.0.10/22` stayed on swift1. `https://10.0.0.10:8085/info` stayed 200. Production proxy sha256 on swift1–4 and hkserver is `59303115c7e51ac6bc6a07db746a2377acf6309639fd11aa03c8db2b13657224`, context `bin_t` on swift1–4. hkserver SELinux is Disabled, so `restorecon` does not attach `bin_t` there. Object, container, and account binaries were not replaced. Their unit file-descriptor limit is 500000.

Console gate stays ACCEPT_WITH_WARN (`tools/test-results/console-accept-20261002/SUMMARY.md`, 2026-10-02). `16MB_read_8` stays ACCEPT (`0J-16mb.md`, 2026-10-04). This run did not re-run it.

Production readiness stays NO-GO.
