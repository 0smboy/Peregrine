# Wave 4 Python LIVE — 2026-08-05

## Verdict: **BLOCKED** · `PYTHON_CLUSTER` **ABSENT** · install not started

Disk/memory hard gates for *considering* install are **PASS**, but PORT-DISK-MATRIX / freeze checklist still block a safe 3-node Python install on Contabo.

## What this cycle did

1. Re-checked `df` / MemAvailable on swift1–4 (`00-df-mem-gate.txt`).
2. Confirmed openstack-swift RPM absent; `import swift` fails on 2/3/4.
3. Confirmed `:8090` on swift2 is a **pyswift-venv leftover** (`/root/work/pyswift-venv/.../swift-proxy-server` + `/etc/pyswift/`), **not** an openstack-swift RPM 3-node cluster — still `PYTHON_CLUSTER ABSENT`.
4. Did **not** install packages; did **not** start 4-node.
5. Refreshed freeze checklist with current numbers (`../wave4-python-prep-20260805/FREEZE-UNFREEZE-CHECKLIST.md`).

## Gate table

| Gate | Result | Evidence |
|------|--------|----------|
| Use% &lt;70% on swift2/3/4 `/srv/node/d1` | **PASS** (2%) | `00-df-mem-gate.txt` |
| MemAvailable re-check | **PASS** (~4.8–5.0 GiB) | same |
| PORT-DISK-MATRIX: Python can claim d1 without Rust collision | **FAIL** | Rust object/account/container rings still **d1-only** on 10.0.4.2–4 |
| W0′ META clean or isolated on Rust disks | **FAIL** | META_DIRTY (see wave2-spp-region-live pack) |
| W2 spp/region live complete (ordering) | **FAIL** | W2 live BACKLOG |
| 3-node install executed | **NO** | — |
| 4-node | **NOT STARTED** (needs 3-node GREEN; Use% already &lt;50%) | — |

## Measured effect

| Check | Prep (earlier today) | Now |
|-------|----------------------|-----|
| d* Use% | 89–100% (prep freeze) | **2%** after Wave 0 |
| Disk gate | FAIL | **PASS** |
| PYTHON_CLUSTER | ABSENT | **ABSENT** (unchanged) |
| Stage 3A/3B/3D | FROZEN | **still FROZEN** (matrix/meta/W2) |

## Remaining (honest)

Unfreeze 3A only after:

1. Rust rings no longer require exclusive `d1` for Python claim (migrate Rust data-plane to d2 per matrix, or dual-stack partition written + proven), **and**
2. META_DIRTY cleared or explicitly isolated, **and**
3. Follow `INSTALL-PLAN.md` on swift2/3/4 only; keep VIP `:8085` Rust.

Until then leave `PYTHON_CLUSTER ABSENT`. Do not claim SAIO as 3-node.
