# Production G7

Date: 2026-10-04.

The full production yaml is `swift4:/root/work/g7-prod-20261004-r21/verdict.json`, copied here as `verdict-prod.json`. That run is 20 PASS, 0 FAIL, 0 NOT RUN. It measured proxy sha256 `ce738dc3a7adb01167c16660924e79a1e215a3245d5d90bbe682d36b7cfa5696` and object-server sha256 `feae2bc515e1ea2141d4f7cfd96292e0b9166f9b51afc3b9a7031c5cee83a629` on swift1–4 and hkserver. The harness spoke HTTP at `http://10.0.0.10:8080`. Port `:18080` was not used. Acceptance sha256 `04492c4b37200421559529e58af0597a5ee4476e788057d2516c27a4794f613c` matches `swift-rust/tools/test-lab/g7/acceptance.yaml`.

An earlier same-day full run, `swift4:/root/work/g7-prod-20261004-r3/verdict.json`, was 16 PASS, 4 FAIL, 0 NOT RUN on proxy sha256 `59303115c7e51ac6bc6a07db746a2377acf6309639fd11aa03c8db2b13657224`. That tally is not the current one.

The four cases that failed on that earlier run, measured in the r21 full yaml:

| case | fresh result |
|---|---|
| `slow_put_1000` | PASS. http_2xx 1000, http_503 0, responses 1000, failed 0. |
| `sqlite_stall` | PASS. operation_status 201, operation_ms 27839.00987636298, fault_hits 15. |
| `bounded_queue_overload` | PASS. responses 4000, http_2xx 1024, http_503 2976, failed 0, other_status {}. |
| `sigterm_during_durability` | PASS. put_status 201, get_after 200, len 4096, expected_len 4096, fault_hits 6. |

Bounds were not changed. Container and account binaries were not replaced.

| | |
|---|---|
| cases | 20 |
| PASS | 20 |
| FAIL | 0 |
| NOT RUN | 0 |
| gate word | GREEN |
| production readiness | GO |

VIP `10.0.0.10/22` stayed on swift1. `https://10.0.0.10:8085/info` stayed 200. Proxy context is `bin_t` on swift1–4. hkserver SELinux is Disabled, so `restorecon` does not attach `bin_t` there. Object-server context is `bin_t` on swift1–4.

Console gate is ACCEPT (`tools/test-results/console-reaccept-20261004/SUMMARY.md`, addendum 2026-10-04). The 2026-10-02 gate remains ACCEPT_WITH_WARN (`tools/test-results/console-accept-20261002/SUMMARY.md`). `16MB_read_8` stays ACCEPT (`0J-16mb.md`, 2026-10-04). This run did not re-run it.

Production readiness is GO.
