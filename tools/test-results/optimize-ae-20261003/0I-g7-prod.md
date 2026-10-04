# Production G7

Date: 2026-10-04. Source log: `swift4:/root/work/g7-prod-20261004/out/verdict.json`. Copied here as `verdict-prod.json`.

The harness speaks HTTP. `https://10.0.0.10:8085/auth/v1.0` failed with `invalid peer certificate: CaUsedAsEndEntity`. `http://10.0.0.10:8085` did not connect. The run used `http://10.0.0.10:8080`, the production proxy on the VIP address. Port `:18080` was not used. Case bounds were not changed. The frozen lab yaml still forbids `:8080` and `:8085`. This run set `G7_PROD=1` and a server-side spec whose cases and bounds match `swift-rust/tools/test-lab/g7/acceptance.json`.

VIP `10.0.0.10/22` stayed on swift1 for the whole run. `https://10.0.0.10:8085/info` stayed 200. The suite was not aborted.

| | |
|---|---|
| cases | 20 |
| PASS | 3 |
| FAIL | 17 |
| NOT RUN | 0 |
| gate word | RED |
| production readiness | NO-GO |

PASS: `slowloris`, `sigterm_during_put`, `partial_write`.

Every other case is FAIL. Unfinished cases were not marked PASS. Fault-injection cases still drive the lab helpers under `/etc/g6-rust` and `/var/run/g6-rust`. They did not prove those faults on the production process, and the runner recorded FAIL for that. That is the tally. It is not a pass.

Production readiness stays NO-GO.
