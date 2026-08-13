# Fleet cold canary 8663d11 — swift1/swift2/swift4

**UTC:** 2026-08-13T03:11:52Z–03:15:30Z · **SGT (UTC+8):** 2026-08-13 11:11–11:15

swift3 was already live (Smoke B GREEN) and was **not rebuilt, not restarted, binary not replaced**.

## Per-node APPLY

| node | result | evidence | rollback dir |
|------|--------|----------|--------------|
| swift1 | **APPLY_OK** | `/root/work/peregrine-acceptance-20260810/fleet-8663d11-cold-swift1-20260813T031152Z` | `/root/peregrine-proxy-rollback-8663d11-swift1-20260813T031152Z-hH4PaG` |
| swift2 | **APPLY_OK** | `/root/work/peregrine-acceptance-20260810/fleet-8663d11-cold-swift2-20260813T031243Z` | `/root/peregrine-proxy-rollback-8663d11-swift2-20260813T031243Z-EUgIna` |
| swift4 | **APPLY_OK** | `/root/work/peregrine-acceptance-20260810/fleet-8663d11-cold-swift4-20260813T031338Z` | `/root/peregrine-proxy-rollback-8663d11-swift4-20260813T031338Z-oBFOkq` |
| swift3 | **untouched** (already canary) | — | — |

No node required rollback. One aborted pre-state on swift1 (`fleet-8663d11-cold-swift1-20260813T031112Z`): `grep -c` exit 1 under `pipefail` before drain; binary/conf/service unchanged; retried APPLY_OK.

## Procedure (one node at a time)

1. scp sealed artifact from swift3 (`peregrine-proxy-8663d11-ec.tar.gz` SHA `50c0245d030409b230ad6ccaa0577a769954d185a7c0b05715aae2eaedf362c0`).
2. Stop `swift-proxy.service`; wait **that** node's HAProxy backend DOWN via read-only `show stat` (no disable/enable write).
3. Install binary from sealed tar (`bin/swift-proxy-server`). Deploy script `deploy-peregrine-proxy-only-8663d11.sh` (commit-name adapt of 77dd9f4) copied to each node; **not used to mutate conf**.
4. `mkdir /var/cache/peregrine-cold` mode **750**; insert `[filter:s3api]` `cold_backend_root` + `cold_policy_map = GLACIER:0` (copied from live swift3 template).
5. Start; localhost:8080 health **200**; wait that backend UP; next node.

## Final fleet SHAs (installed + running exe)

All four nodes:

`b64deec239833c567604d9efe0211b3bd20b543b570de675cc40fd7fe4785148`

| node | health :8080 | cold_backend_root | cold_policy_map | cold dir 750 |
|------|----------------|-------------------|-----------------|--------------|
| swift1 | 200 | yes | GLACIER:0 | yes |
| swift2 | 200 | yes | GLACIER:0 | yes |
| swift3 | 200 | yes (pre-existing) | GLACIER:0 (pre-existing) | yes |
| swift4 | 200 | yes | GLACIER:0 | yes |

HAProxy `swift_proxy_back`: **proxy1=UP proxy2=UP proxy3=UP proxy4=UP** (verified on all four nodes).

swift3 binary mtime still 2026-08-13 02:53 UTC; unit ActiveEnterTimestamp 2026-08-13 03:03:07 UTC (Smoke B drain-restart, not this roll). NRestarts=0.

## Tiny smoke (swift1 localhost:8080, not VIP, not Smoke B)

TempAuth PUT container **201**, PUT object **201**, GET **200** (payload match). Cleanup DELETE. Verdict `TINY_PUTGET_PASS`.

## Secrets

`peregrine-lab.env` never printed. Evidence secret-scan hits=0 on all three apply leaves. Conf evidence redacted.

## Mac mirror

`tools/test-results/fleet-8663d11-cold-20260813T031152Z/`
