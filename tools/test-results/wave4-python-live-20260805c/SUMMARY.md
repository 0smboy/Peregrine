# Wave 4 Python live — 2026-08-05c

**Verdict: BLOCKED** · `PYTHON_CLUSTER=ABSENT` · 3-node install **not started**  
**PRODUCTION-GO-LIVE: not claimed**

Prefer honest BLOCKED over unsafe Python install on shared `d1`, and over mid-Identity ring remap with stale `build_rings.sh` + full-remap Rust builder.

## 1) What this cycle did

1. Re-gated df Use% / MemAvailable on swift1–4 (**2%**, MemAvail ~2.9–4.6 GiB).
2. Re-read rings: object spp **6210–6212** on d1/d2/d3; account/container still **d1-only**.
3. Confirmed Contabo `build_rings.sh` **STALE** (still `object :6200 /d1`) while live object rings are spp multi-disk.
4. Assessed migrate tooling: Contabo `swift-ring-builder` = `create|add|rebalance` only; rebalance = full remap (P3-OPS honesty).
5. VIP `https://10.0.0.10:8085/healthcheck` **200**; `/info` 200 with tempauth+keystoneauth. Auth CRUD this probe: TempAuth list **401**, Keystone Swift **403** → migrate deferred.
6. Documented exact operator migrate steps (`05-OPERATOR-MIGRATE-STEPS.md`); **did not** rebalance; **did not** install openstack-swift.
7. Matrix **not** revised to allow shared-d1 Python (that would be dishonest).

## 2) Optimized / fixed / demoted

| Item | Action |
|------|--------|
| Disk / META gates | Reconfirmed PASS (LAB META clean) — not the blocker |
| Isolation | Still FAIL — unchanged |
| Live migrate A/C→d2 | **Demoted** to operator maintenance window (risk) |
| Shared-d1 Python install | **Rejected** |
| Matrix exclusive-d1 target | **Kept** (honest) |

## 3) Measured effect (vs 05b)

| Item | 05b | 05c |
|------|-----|-----|
| Use% | 2% PASS | **2% PASS** |
| META | LAB_META_CLEAN | **LAB_META_CLEAN** (ref) |
| A/C rings | d1-only | **d1-only** |
| Object rings | d1+d2+d3 spp | **same** |
| Isolation | FAIL | **FAIL** |
| Migrate | “next clear step” | **Documented + BLOCKED as unsafe now** |
| 3-node install | not started | **not started** |
| VIP health | (prior) | **200** healthcheck/info |

## 4) Hard gates

| Gate | Result | Evidence |
|------|--------|----------|
| Use% &lt;70% (swift2/3/4) | **PASS** | `00-df-mem-gate.txt` |
| Use% &lt;50% (4-node disk precondition) | **PASS** (disk only) | same |
| W0′ META clean or isolated | **PASS (LAB)** | `01-META-STATUS.txt` |
| PORT-DISK-MATRIX Python exclusive d1 | **FAIL** | `01-ring-isolation.txt` |
| Migrate executed safely | **NO** | `04-MIGRATE-RISK.md` |
| 3-node install | **BLOCKED** | — |
| 4-node | **N/A** | needs 3-node GREEN |

## 5) Remaining / FROZEN

- Stages **3A / 3B / 3D** remain **FROZEN**.
- **Next (operator):** run `05-OPERATOR-MIGRATE-STEPS.md` in a maintenance window after auth CRUD is green and `build_rings.sh` is synced; prove VIP regression; then `INSTALL-PLAN.md` on swift2/3/4 only.
- Do not share TempAuth HMAC rings across stacks; VIP `:8085` stays Rust.
- Fix TempAuth 401 / Keystone 403 on Swift path **before** ring surgery (attribution).

## Claims discipline

- No Python dual-stack GREEN.
- No SAIO-as-cluster (swift2 `:8090` leftover ≠ stage-3).
- No PRODUCTION-GO-LIVE.
