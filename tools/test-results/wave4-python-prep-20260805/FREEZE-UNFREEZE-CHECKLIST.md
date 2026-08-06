# Stage-3 Python freeze ↔ unfreeze checklist

## Current (2026-08-05d, wave4-python-live-20260805d) — 3A UNFROZEN (LAB)

| Item | State | Proof |
|------|-------|-------|
| `PYTHON_CLUSTER` | **PRESENT (3-node)** | `../wave4-python-live-20260805d/` — pyswift units on swift2/3/4; rings 10.0.4.2–4 `/py` |
| Stage 3A install | **DONE (LAB)** | listeners + CRUD PASS |
| Stage 3B dual API | **unfrozen / ready** | depends on this pack for compare |
| Stage 3D Python-only | backlog | separate cutover |
| Stage 3C Rust-only topology | backlog | separate cutover |
| 4-node | **FROZEN** | eligible (Use% 2%&lt;50%); not executed — swift1 client/monitor |

## Live df / mem (2026-08-05T12:09Z Zulu)

| Host | d1 Use% | d2 Use% | d3 Use% |
|------|---------|---------|---------|
| swift1–4 | 2% | 2% | 2% |

## Unfreeze gate results

- [x] Wave 0 reclaim / df &lt;70%
- [x] META LAB clean
- [x] Port/disk isolation (Rust left d1) — PASS
- [x] Install plan executed (venv path; RPM blocked by pyxattr)
- [x] `ss` Python ports on 2/3/4
- [x] Python rings only swift2/3/4 device `py` on d1
- [x] Auth + CRUD smoke (internal)
- [x] Rust VIP healthy post-install
- [x] Pack `wave4-python-live-20260805d/` with LAB GREEN (not PRODUCTION-GO-LIVE)
