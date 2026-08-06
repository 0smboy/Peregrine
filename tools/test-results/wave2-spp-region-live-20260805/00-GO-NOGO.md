# Wave 2 Contabo live — GO / NO-GO (2026-08-05)

## Verdict: **NO-GO · BACKLOG** (executable runbook + dry-run only)

Do **not** claim W2 Contabo GREEN. Hard gates for live ring rebuild / spp enable failed.

## Gate matrix

| Gate | Required | Observed | Result |
|------|----------|----------|--------|
| Disk Use% ~2% after Wave 0 | yes | All `/srv/node/d*` **2%** on swift1–4 | **PASS** |
| Cluster services up | yes | `swift-*` + haproxy + keepalived active; VIP `/healthcheck` 200; 4 backends 200 | **PASS** |
| META clean / no dirty conflict | yes | Account lists **968** containers; sample HEAD **30/30 = 404**; headers claim ~846k objects / ~176 GiB while disks ~2% | **FAIL · META_DIRTY** |
| Wave2 ring template on Contabo | yes | Deployed `build_rings.sh.j2` **66 lines** (pre-wave2); local repo **213 lines** with `object_port_per_device` | **FAIL · CODE_NOT_DEPLOYED** |
| Object ring already multi-device | for spp discovery | Live `object.ring.gz` decode = **4 devices** (d1 only × 4 nodes), port **6200**, **region=1** (`13-LIVE-RING-DECODE.txt`). Note: builder.json on swift2–4 falsely lists 12 devices — **do not trust builder.json; trust ring.gz** | **FAIL · RING_SHAPE** |
| Port plan safe vs account/container | yes | Plan d2→6201 / d3→6202 **collides** with live container:6201 / account:6202 | **FAIL · PORT_COLLISION** |
| `servers_per_port≥1` live | goal | Conf key **absent** (defaults 0); single listen `:6200` | not attempted |
| func 54/54 + spp smoke + failover + soak | post-apply | Baseline func only (see `11-func-suite-vip-baseline.txt`); spp/failover/soak **not** run | **N/A (blocked)** |

## Why META_DIRTY blocks rebuild

Ring rebuild / force-rebalance moves partition→device→port mapping. With ghost account/container DB rows claiming 176 GiB that is not on disk, replicators/updaters/reapers will chase inconsistent handoffs across new ports. W0′ (owned by another agent) must clear or isolate meta before maintenance-window apply.

## Coordination

- Another agent owns R0 / W0′ / W1 — this pack does **not** install Galera/Keystone or TLS cutover.
- No mkfs / no destructive disk wipe performed.

## Partial execution this cycle

1. Verified wave2-spp-region-20260805 code landed in **repo** (not Contabo deploy tree).
2. Full Contabo baseline probe (df/mem/units/rings/meta/CRUD).
3. Dry-run port plan + abort criteria recorded.
4. Executable runbook: `EXECUTABLE-RUNBOOK.md`.
5. VIP CRUD smoke PASS; func-suite baseline captured separately.
6. Live ring rebuild / spp enable / r1-r2 apply / soak: **not started**.
