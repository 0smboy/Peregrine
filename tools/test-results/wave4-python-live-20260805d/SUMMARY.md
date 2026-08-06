# Wave 4 Python live — 2026-08-05d

**Verdict: LAB GREEN (3-node)** · `PYTHON_CLUSTER=PRESENT` on swift2/3/4  
**PRODUCTION-GO-LIVE: not claimed** · 4-node **not** executed

## 1) What this cycle did

1. Confirmed VIP TempAuth+Keystone CRUD GREEN (`vip-auth-crud-fix-20260805`).
2. Backed up rings/conf on all nodes (`/root/w4-ring-backup-20260805T113908Z`).
3. First migrate attempt via Contabo `swift-ring-builder add … 0` **failed** (binary lacks weight-update; duplicated devices). **Rolled back** before distribute.
4. Clean migrate: rewrite `*.builder.json` → account/container **d2 only**; object/object-1 **d2@6211 + d3@6212** (no d1) → rebalance → distribute → restart A/C/O.
5. VIP regression PASS (TempAuth+Keystone CRUD). Isolation PASS.
6. Python 3-node: Caracal RPM blocked (`pyxattr` RPM provide missing). Deployed via `/opt/pyswift-venv` + `/etc/pyswift` (INSTALL-PLAN SAIO→cluster path), matrix ports 8090/6102/6101/6100, device `py` on disk **d1**.
7. Python CRUD PASS on all three proxies from Contabo LAN. Rust VIP still healthy.

## 2) Optimized / fixed / demoted

| Item | Action |
|------|--------|
| Contabo `add` weight-0 | Demoted — broken; use JSON rewrite |
| Stale `build_rings.sh` | Replaced with stamp guard (no greenfield spp wipe) |
| Shared-d1 Python | Rejected — Rust left d1 |
| openstack-swift RPM | Blocked by deps — venv path used instead |
| 4-node | Deferred (eligible on disk) |

## 3) Measured effect

| Metric | Before (05c) | After (05d) |
|--------|--------------|-------------|
| Rust A/C devices | d1 | **d2** |
| Rust object devices | d1+d2+d3 | **d2+d3** (6211/6212) |
| Isolation | FAIL | **PASS** |
| Python cluster | ABSENT | **3-node PRESENT** |
| VIP CRUD | GREEN (auth fix) | **GREEN post-migrate** |
| Use% | 2% | **2%** |

## 4) Hard gates

| Gate | Result | Evidence |
|------|--------|----------|
| Use% &lt;70% | **PASS** | `00-df-mem-gate.txt` |
| Isolation Python exclusive d1 | **PASS** | `08-rust-vip-regression.txt` |
| VIP TempAuth+Keystone CRUD | **PASS** | same |
| Python 3-node listeners | **PASS** | `09-python-listeners.txt` |
| Python CRUD ×3 | **PASS** | `08-python-crud-internal.txt` |
| 4-node | **N/A** (not run) | Use% already &lt;50% |

## 5) Topology (live)

| Stack | Entry | Disks | Ports |
|-------|-------|-------|-------|
| Rust VIP | `https://10.0.0.10:8085` | d2 (+d3 objects) | 6202/6201/6211–6212 |
| Python | `http://10.0.0.2–4:8090` (LAN) | d1/`py` | 6102/6101/6100 |

## 6) Remaining / FROZEN

- **FROZEN:** 4-node Python on swift1 (optional; disk eligible).
- Contabo security group / firewall: operator Mac → `:8090` empty-reply; internal LAN works.
- Prefer shipping Contabo `swift-ring-builder` with idempotent weight update (source has it; live binary 2026-08-04 lacks it).
- Stage 3B dual-API compare matrix can proceed with evidence path here.
- No PRODUCTION-GO-LIVE.

## Claims discipline

- Dual-stack LAB only; not SAIO-as-cluster (rings list 10.0.4.2–4).
- No openstack-swift RPM claim (venv path documented).
