# Wave 4 — Python ↔ Rust port / disk matrix (Contabo)

Authority: [MODES.md](../../../docs/fairness-lab/MODES.md),
[USER-METHOD-PLAN.md](../../../docs/fairness-lab/USER-METHOD-PLAN.md) stage 3.

## Roles

| Host | Client / monitor | Python data-plane | Rust data-plane |
|------|------------------|-------------------|-----------------|
| swift1 | Request + monitor (stage 3) | **no** (until optional 4-node) | demote from exclusive owner when dual-stack |
| swift2 | — | yes | yes (separate disks/ports) |
| swift3 | — | yes | yes |
| swift4 | — | yes | yes |

## Disk assignment (Compatibility / stage-3 dual)

| Mount | Owner | Notes |
|-------|-------|-------|
| `/srv/node/d1` | **Python** | Dedicated when Python cluster present |
| `/srv/node/d2` | **Rust** | |
| `/srv/node/d3` | Reserved / expand | Prefer leave free until spp/region waves |

**Today (2026-08-05d live):** mounts ~**2%** Use%; W0′ **LAB_META_CLEAN**.
Rust after migrate: account/container **d2** :6202/:6201; object **d2+d3**
ports **6211–6212** (no d1). Isolation **PASS**. Python 3-node on
swift2/3/4: `/etc/pyswift`, device **`py`** under `/srv/node/d1`, ports
8090/6102/6101/6100 (`wave4-python-live-20260805d/` LAB GREEN). No mkfs.
No PRODUCTION-GO-LIVE.

## Port matrix (do not collide)

| Service | Python (proposed) | Rust (live Contabo) |
|---------|-------------------|---------------------|
| Proxy / API | **8090** (node) · optional LB **8086** | **8080** node · VIP **8085** |
| Account | **6102** | **6202** |
| Container | **6101** | **6201** |
| Object | **6100** (or spp 6100–6102) | **6210–6212** (spp live; was 6200) |
| rsync | **8873** | **873** / ssh-rsync per rust deploy |
| memcached | **11212** | **11211** |

VIP `10.0.0.10:8085` stays **Rust**. Python gets a separate entry (direct
`10.0.0.2–4:8090` or a distinct HAProxy frontend `:8086`) — never share
TempAuth HMAC rings across stacks.

## Rings

| Stack | part_power | replicas | devices |
|-------|------------|----------|---------|
| Python 3-node | 9 | 3 | d1 on swift2/3/4 |
| Rust (compat) | 9 or current | 3 | d2 (+d3 if reserved released) |

Throughput from Compatibility mode is never a formal Performance conclusion.
