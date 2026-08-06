# P3-data evidence — PARTIAL

**Date:** 2026-08-04  
**Verdict:** **PARTIAL** (honest; not full L3b production)  
**HTML:** [`P3-DATA-REPORT.html`](P3-DATA-REPORT.html)

## What this cycle did

1. **X-Newest best-source selection** in `swift-proxy-server` `get_or_head`: when `X-Newest` is truthy, collect valid sources and return the newest timestamp (Python `base.py` parity). Resumable mid-stream multi-node GET remains deferred.
2. **L3b sharder daemon MVP**: `swift-container-sharder` binary + `[container-sharder]` conf + systemd unit on Contabo ×4. Local cleave only for containers already in `SHARDING`; `auto_shard` ignored.
3. **`X-Backend-Sharding-State`** now reports real `get_db_state()` (was hardcoded `unsharded`).
4. **At-rest crypto**: not wired (library primitives only) — deferred as unrealistic this wave.

## Gate table

| Gate | Result | Evidence |
|------|--------|----------|
| Sharder unit (`sharder::`) | **4/4 PASS** | `05-cargo-unit-local.txt`, `03-build.txt` |
| Proxy X-Newest unit | **PASS** | `05-cargo-unit-local.txt` |
| Container HTTP sharding test | **PASS** | local `cargo test --test sharding` |
| Contabo deploy proxy+container+sharder ×4 | **PASS** | `05-fanout-deploy.txt` |
| Sharder continuous (scan, failures=0) | **PASS** | `10-daemon-status.txt` |
| Backend `X-Backend-Sharding-State: unsharded` | **PASS** | `12-sharding-state.txt` |
| X-Newest smoke GET VIP | **200** | `11-xnewest-smoke.txt` |
| CORE-PATH func VIP | **54/54** | `20-func-suite-vip.txt` |
| At-rest crypto middleware | **DEFERRED** | — |
| Resumable multi-node GET | **DEFERRED** | — |
| Full L3b production / perf uplift | **NOT CLAIMED** | — |

## Must NOT claim

- Full container sharding production (proxy shard listing fan-out, HTTP shard create + replication quorum, `auto_shard`, misplaced pass, cleave-context DB persistence).
- At-rest encryption on the Rust proxy.
- Resumable mid-stream GET failover.
- 4KB-write uplift vs L1a baseline (needs dedicated clean-load cycle per L3b brief).

## Disk / wipe

No wipe. Contabo `/srv/node/d1` on swift1 remains ~100% (pre-existing); root free. Sharder did not create SHARDING containers.
