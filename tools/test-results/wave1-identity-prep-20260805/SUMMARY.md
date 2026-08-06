# Wave 1 Identity prep — 2026-08-05

**Verdict: PREP COMPLETE · Contabo live BLOCKED**

VIP TempAuth untouched: `http://10.0.0.10:8085`

## What this cycle did

1. SSH df/mem/identity probe on swift1–4 (evidence `00-df-evidence.txt`).
2. Built python-bundle Contabo inventory `bundle/config_contabo_identity/` (Galera×3 on swift1–3, Keystone HA plan, empty Swift/format groups).
3. Documented dual-bundle duties in `docs/fairness-lab/KEYSTONE-LIVE.md`.
4. Added bundle-rust Identity **对接** templates (`IDENTITY.md`, proxy/haproxy fragments, overlay example).
5. Extended `HttpTokenValidator` HTTP client to accept `https://` via `native-tls`.
6. Produced `dry-run-plan.json` (ansible not installed on controller; plan is the dry-run artifact).

## What was optimized / demoted

| Item | Action |
|------|--------|
| Contabo live Galera/Keystone | **Demoted / BLOCKED** — disks 89–100%; Wave 0 unproven |
| python `haproxy_servers` on Contabo | **Demoted** — would clobber rust VIP frontend; use additive rust listeners |
| Rewriting Galera into bundle-rust | **Rejected** (plan) |

## Measured effect

| Metric | Before (P3-auth 2026-08-04) | After (this prep) |
|--------|-----------------------------|-------------------|
| Contabo Keystone | ABSENT | ABSENT (unchanged — honest) |
| Identity inventory | none | `config_contabo_identity/` |
| KEYSTONE-LIVE.md | missing | present |
| bundle-rust Identity 对接 | comment sample only | templates + flags + docs |
| HttpTokenValidator TLS | http only | http + https |

## Gates

| Gate | Result | Evidence |
|------|--------|----------|
| Disk gate for live install | **FAIL / BLOCK** | `00-df-evidence.txt`, `CONTABO-LIVE-BLOCKED.md` |
| Inventory + dry-run plan | **PASS** | `dry-run-plan.json`, `config_contabo_identity/` |
| Docs / dual-bundle | **PASS** | `KEYSTONE-LIVE.md`, `IDENTITY.md` |
| Contabo Keystone E2E CRUD | **NOT RUN** (blocked) | — |
| TempAuth VIP left alone | **PASS** (no pipeline cutover) | intentional |

## Consolidation (same day)

- Canonical inventory: `bundle/config_contabo_identity/` (draft `inventories/contabo-identity/` is a redirect only).
- HAProxy: single `identity_haproxy_enabled` overlay (removed duplicate `identity_bridge_enabled` block).
- Proxy: `auth_method=keystone|keystone_coexist` switches pipeline **and** renders filters (aligned with `identity_proxy_enabled`).
- Disk gate JSON: `00-DISK-GATE.json` (+ per-host df under `wave1-keystone-20260805/`).

## Remaining / next

- Wave 0 must free `/srv/node` before live apply (**FROZEN** Contabo live Identity).
- Then: ansible `--check` → live tags → rust haproxy identity overlay → proxy cutover → `p3-auth-live-*`.
- Re-check RAM; may still need daemon demotion on Galera nodes.
