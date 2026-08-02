# Next cycle brief — L3b container sharding (not started)

**Prerequisite:** deep-verify-20260802 A–F green (see
`tools/test-results/contabo-deploy-20260801/deep-verify-20260802/GATES.md`).

## Problem

Even after L1a parallel sync `container_update` KEEP, Contabo 4KB writes remain
bounded by container-DB hotspot shape. L3a multi-container ops guidance showed
c4/c1 ≈1.19× @128 on a noisy load host; full sharding (L3b) was deferred.

## Success metric

On a **clean client** (e.g. swift4 → VIP `10.0.0.10:8085`), median of 3×
`4KB_write_128` with sharded container(s) vs current L1a baseline
(~138 ops/s fail=0 from 2026-08-02 clean-load). Target: clear, documented uplift
with fail=0 and no listing/consistency regressions in `func-suite.sh`.

## Risks

- Proxy routing / container DB migration compatibility with Python oracle
- Shard count vs ring/partition interaction
- Updater / async_pending behaviour across shards

## Required tests before KEEP

1. `func-suite.sh` VIP + both SAIOs 54/54
2. Clean-load autocos 4KB write/read + 1MB write/read fail=0
3. HA drill + EC heal md5 match
4. docs-site + SUMMARY.json atomic update (evidence-alignment rule)
