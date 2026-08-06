# Wave 4 Python live re-gate — 2026-08-05b

**Verdict: BLOCKED** · `PYTHON_CLUSTER=ABSENT` · 3-node install **not started**

Disk Use% and W0′ META no longer block consideration, but **PORT-DISK-MATRIX Rust/Python disk isolation is still unsolved**. Prefer honest BLOCKED over unsafe install on shared `d1`.

## What this cycle did

1. Re-checked `df` Use% and MemAvailable on swift1–4.
2. Re-read rings (via pyswift venv on swift2): object spp ports 6210–6212 on d1/d2/d3; account/container still **d1-only**.
3. Confirmed W0′ **LAB_META_CLEAN** (`w0-meta-repair-20260805`).
4. Confirmed leftover `/etc/pyswift` single-node on swift2 (proxy :8090, devices `d1/pysaio`) — not a 3-node cluster.
5. Did **not** install Python 3-node (isolation FAIL).

## Measured effect (vs prior live pack)

| Item | wave4-python-live-20260805 | This pack (05b) |
|------|----------------------------|-----------------|
| Use% | 2% PASS | **2% PASS** |
| META | META_DIRTY cited | **LAB_META_CLEAN** |
| Rings | d1-only all | object multi-disk/spp; **account/container still d1** |
| Isolation | FAIL | **FAIL** (unchanged conclusion) |
| 3-node install | not started | **not started** |

## Hard gates

| Gate | Result | Evidence |
|------|--------|----------|
| Use% &lt;70% on swift2/3/4 | **PASS** | `00-df-mem-gate.txt` |
| Use% &lt;50% (4-node precondition disk) | **PASS** (disk only) | same |
| W0′ META clean or isolated | **PASS (LAB)** | `01-META-STATUS.txt` |
| PORT-DISK-MATRIX: Python exclusive d1 | **FAIL** | `02-RING-AND-PYSWIFT-RECONCILE.txt` |
| 3-node install | **BLOCKED** | — |
| 4-node | **N/A** (needs 3-node GREEN) | — |

## Remaining / FROZEN

- Stages 3A/3B/3D remain **FROZEN**.
- **Next (clear):** rebuild/migrate Rust rings so account+container (+object weight) leave Python’s exclusive `d1` (Rust on `d2` per matrix), prove VIP regression still 54/54, then run `INSTALL-PLAN.md` on swift2/3/4 only.
- Do not share TempAuth HMAC rings across stacks; VIP `:8085` stays Rust.

## Claims discipline

- No Python dual-stack GREEN claim.
- No SAIO-as-cluster claim (swift2 leftover ≠ stage-3).
