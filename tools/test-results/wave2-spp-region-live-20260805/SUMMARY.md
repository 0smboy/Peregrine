# Wave 2 spp + region LIVE — 2026-08-05 (apply cycle)

## Verdict: **PARTIAL** (topology/spp applied; soak fail≠0; canonical func 54/54 not met)

Not GREEN. Not PRODUCTION-GO-LIVE.

| Claim | Status |
|-------|--------|
| Contabo object ring rebuild (6210+) + spp≥1 | **DONE** |
| Discovery 3 ports (6210–6212) all nodes | **DONE** |
| r1/r2 label drill | **PASS** (`apply/05-region-port-drill.txt`) |
| spp smoke (Keystone PUT/GET) | **PASS** (`apply/04-spp-smoke-keystone.txt`) |
| Failover drill | **PASS** (`apply/06b-failover-complete.txt`) |
| Soak ≥1h | **COMPLETE / WARN** — `SOAK_END … n=192 ok=185 fail=7` (`apply/09-soak-result.log`) |
| func-suite 54/54 TempAuth HTTPS | **FAIL 5/54** (TempAuth storage → 401 Keystone) |
| Keystone-adapted suite | **46 PASS / 13 FAIL** (not canonical; EC 501) |

## What this cycle did

1. Maintenance-window apply: backed up rings/conf → `/root/w2-ring-backup-20260805T100051Z/` on each node.
2. Force-rebuilt **object.ring.gz** + **object-1.ring.gz** only (A/C unchanged): 12 devices d1/d2/d3 × swift1–4; ports **6210/6211/6212**; regions swift1/2→**r1**, swift3/4→**r2**.
3. Set `object-server.conf`: `bind_port=6210`, `servers_per_port=1`; restarted `swift-object` on all four.
4. Verified listen on 6210–6212; A/C remain 6201/6202 (no collision).
5. Keystone CRUD smoke + region/port drill OK.
6. Failover: stop keepalived on swift2 → VIP to swift1 → CRUD OK → restore.
7. 1h Keystone soak on swift1: start `2026-08-05T10:13:50Z` → end `2026-08-05T11:13:52Z`; **185/192 ok, fail=7**.

## Optimized / demoted

| Item | Action |
|------|--------|
| Object base 6200 / colliding 6201–6202 | **Fixed** → 6210+ |
| Live spp enable | **Applied** (one process binds 3 sockets; acceptors=3) |
| TempAuth as func gate | **Demoted** — data plane is Keystone; TempAuth tokens 401 on storage |
| EC path in func suite | **Blocked** — proxy binary without `--features ec` (501) |
| Soak fail=0 gate | **Not met** (7 failures) — WARN, not soak PASS |
| PRODUCTION-GO-LIVE / W2 GREEN | **Rejected** |

## Measured effect

| Check | Prep pack (pre-apply) | After apply |
|-------|----------------------|-------------|
| Contabo object ports | `{6200}` | `{6210,6211,6212}` |
| `servers_per_port` | 0 / absent | **1** |
| Ring devices | 4× d1 r1 | **12** d1/d2/d3 r1+r2 |
| Disk Use% | ~2% | ~2% |
| Failover | note only | **PASS** |
| Soak 1h | not run | **WARN** 185/192 (fail=7) |
| Func TempAuth | 54/54 baseline (HTTP era) | **5/54** HTTPS TempAuth |

## Soak residual (fail=7)

| Class | Iters | Note |
|-------|-------|------|
| 401/409 | n=22, n=24 | Soak-script token mid-cycle expiry / empty token; not IdP outage |
| 503 ×5 | n=60–64 (~10:33Z) | Concurrent proxy binary deploy: `Exec format error` / `Text file busy` → HAProxy `swift_proxy_back` empty → VIP 503 |

Full note: `apply/09b-soak-503-rca.txt`. Identity/TLS not touched. Object ports/spp stayed healthy; post-soak VIP + all four proxies `/healthcheck` **200** (`apply/10-post-soak-health.txt`).

## Remaining work

- **BACKLOG:** Keystone-native func-suite 54/54 (or TempAuth storage coexist); re-soak with serialized proxy install + token refresh hardening; optional proxy rebuild with `--features ec`.
- **FROZEN:** mkfs; PRODUCTION-GO-LIVE claim from this pack; ring rebuild (not needed for soak close).

## Evidence index (apply/)

| File | Content |
|------|---------|
| `01-apply2.log` | Live apply script log |
| `02-object-ring-after.json` / `02-object-server.conf.after` | Post-apply ring/conf |
| `03-func-suite-tempauth-https.log` | TempAuth 5/54 |
| `03b-func-suite-keystone-https.log` | Keystone adapted 46/13 |
| `04-spp-smoke-keystone.txt` | Smoke PASS |
| `05-region-port-drill.txt` | REGION_PORT_DRILL_OK |
| `06b-failover-complete.txt` | Failover PASS |
| `07-soak-start.log` | Soak start marker |
| `08-post-apply-snapshot.txt` | Disks/ports/units/VIP |
| `09-soak-result.log` | `SOAK_END … n=192 ok=185 fail=7` |
| `09b-soak-503-rca.txt` | 503/401 residual RCA (no Id/TLS change) |
| `10-post-soak-health.txt` | VIP/backends 200 after soak |
| `WAVE2-LIVE-REPORT.html` | Visual report (root of pack) |
