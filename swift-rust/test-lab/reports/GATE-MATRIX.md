# GATE-MATRIX — G0–G8 (2026-08-21, this goal)

A completed workflow is not a passed test. No gate GREEN by narrative.
G8 is not GREEN. Production VIP / HAProxy / Keepalived / `:8080` were not changed.

Workflows started (parallel; complete() ≠ GREEN):

- `g0-g2-test-lab-2`
- `g3-async-path-2`
- `g3-deploy-rsaio`
- `g1-environment-inventory-2`

Evidence in this scratch: `TEST-PROVENANCE.json`, `preflight.log`, `preflight.2.log`, `g2-pipeline-diff.log`, `g3-async-path.log`, `test-lab-unittests.log`, `workflows-started.log`.

## Matrix (AGENTS.md T6)

| Gate | Python | Peregrine | Result |
|---|---|---|---|
| Environment parity | 4 CPU AMD EPYC, 7.5 GiB, kernel 5.14.0-687.31.1.el9_8, no VIP | same kernel/CPU; **VIP `10.0.0.10` on eth1**; no cgroup CPU/memory; rings differ | **RED** |
| Pipeline parity | `s3api tempauth copy slo dlo versioned_writes symlink` | extra `bulk tempurl formpost staticweb container_quotas account_quotas` | **RED** unexpected=**6** |
| Native async path | N/A | Live `:8081` after G3 deploy: `http_requests_total{engine="hyper"}=6`, `native_async_requests_total=6`, `legacy_sync_handler_requests_total=0`, `block_in_place_total=0` on Swift PUT/GET. S3 source still `block_in_place`. | **RED** (Swift GET/PUT proven; **S3 ASYNC GATE = NO-GO**; not 100% required routes) |
| Swift functional | not run | not run | **NOT TESTED** (T5 FAIL_COUNT=10) |
| Swift EC functional | not run | not run | **NOT TESTED** |
| Swift s3api | not run | not run | **NOT TESTED** |
| Ceph s3 expected | — | — | **NOT TESTED** (no known-failure run this goal; do not chase 670 ERROR) |
| Ceph s3 unexpected regression | — | — | **NOT TESTED** |
| Probe tests | not run | not run | **NOT TESTED** |
| 50k idle | — | — | **NOT RUN** (VIP + T5 FAIL) |
| Slow PUT | — | — | **NOT RUN** |
| Fsync isolation | — | — | **NOT RUN** |
| 24h soak | — | — | **NO-GO / INVALID** |
| Controlled perf P1 | — | — | **INVALID** |
| Equal-resource perf P2 | — | — | **INVALID** |
| Production tuning P3 | — | — | **INVALID** |

## T5 preflight (twice, identical FAIL set, exit 1)

```
[PASS] exact Python Swift commit pinned  (541a59863752de0636a1747e5c3223676a904c35)
[PASS] exact Peregrine commit pinned  (e65d26a05a34ba16caad2054d011563fad3c1320)
[FAIL] test suite commit pinned          (ceph_s3tests_git_sha empty)
[FAIL] pipeline semantic diff = 0        (unexpected=6)
[FAIL] storage policies identical
[FAIL] rings equivalent
[PASS] filesystem equivalent
[FAIL] host production traffic = 0       (VIP 10.0.0.10)
[FAIL] CPU budgets equivalent
[FAIL] memory budgets equivalent
[FAIL] data state clean
[FAIL] no competing benchmark process
[FAIL] collected test names frozen
FAIL_COUNT=10  ABORT
```

Python oracle is git SHA `541a5986…` / `swift.__version__=0.0.0`, **not** Rust `/info` `swift.version=2.33.0`.
`ceph_s3tests_git_sha` remains empty: swift1 `/root/work/s3-tests` is not a git checkout.

## G3 live probe (RSAIO `:8081` only)

| Item | Value |
|---|---|
| Compile host | swift3, rustc 1.97.1, `CARGO_HOME=/root/work/peregrine-cargo-home`, `--offline --locked --release` |
| rsaio proxy SHA | `f47d480b3c0de3136aad3b2c32180d41e59586ec82ae277800896c2540da55f0` |
| `/usr/local/bin/swift-proxy-server` | **unchanged** `ab5cb95c5c3973db8336e4940711fba18ce3cabaae62e13da0865c07ad31622b` |
| `:8080` healthcheck | 200 |
| VIP | still `10.0.0.10` on swift2 eth1 (untouched) |
| Auth PUT container | 201 |
| PUT object | 201 |
| GET object body | `hello-g3-activation` |
| After request | hyper=6 native_async=6 legacy=0 block_in_place=0 |
| `/recon/concurrency` 200 alone | **not** a pass (recon is excluded from G3 counters; real PUT/GET required) |

S3 `handle_request_async` still calls `tokio::task::block_in_place` → **S3 ASYNC GATE = NO-GO**.

## Formal status

```
Concurrency redesign implementation: PARTIALLY PROVEN (Swift GET/PUT on live RSAIO Hyper native async)
Swift API compatibility:             NOT TESTED (official .functests not run)
S3 compatibility:                    NO-GO (async path incomplete; official suites not run)
Performance comparison:              INVALID
Production readiness:                NO-GO
```
