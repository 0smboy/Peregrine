# Wave 4 Python prep — 2026-08-05

**Verdict: PREP COMPLETE · Contabo live BLOCKED · PYTHON_CLUSTER ABSENT**

## What this cycle did

1. Re-checked Contabo df on swift1–4 (same pressure as Wave 1: d* 89–100%).
2. Wrote exact install plan, port/disk matrix, freeze↔unfreeze checklist.
3. Did **not** install openstack-swift; did **not** claim Python 3-node present.

## Optimized / demoted

| Item | Action |
|------|--------|
| Live Python 3-node on 2/3/4 | **BLOCKED** until disk &lt;~70% |
| Optional Python 4-node | **Deferred** (after 3-node green) |
| SAIO-as-3-node | **Rejected** |

## Measured effect

| Check | Result |
|-------|--------|
| `import swift` / openstack-swift units | absent (unchanged) |
| Python listeners :8090/:6100 | absent |
| Rust VIP :8085 | still the only cluster entry |
| Stage 3A/3B/3D | remain **FROZEN** |

## Gates

| Gate | Result | Evidence |
|------|--------|----------|
| Disk &lt;~70% for install | **FAIL** | `00-df-evidence.txt` |
| Install plan + matrix + checklist | **PASS** | `INSTALL-PLAN.md`, `PORT-DISK-MATRIX.md`, `FREEZE-UNFREEZE-CHECKLIST.md` |
| PYTHON_CLUSTER present | **NO** | honest |

## Remaining

Unfreeze only via checklist after Wave 0. Evidence for live must be a new
`wave4-python-live-*` pack — this prep pack is not that proof.

## Probe (2026-08-05 refresh)

See `PYTHON-PROBE.txt`: openstack-swift RPM absent on swift2/3/4; `PYTHON_CLUSTER` remains **ABSENT**. Listeners on `:8090` (if any) are Rust leftovers, not a Python 3-node cluster.
