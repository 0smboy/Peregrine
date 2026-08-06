# Wave 1 Identity live — 2026-08-05

**Verdict: LAB GREEN · PRODUCTION-GO-LIVE NOT claimed**

VIP after cutover: `https://10.0.0.10:8085` (TLS terminate, self-signed LAB)  
Keystone public: `https://10.0.0.10:5000` (TLS terminate, self-signed LAB)

## What this cycle did

1. Disk/mem gate PASS (~2% `/srv/node`, MemAvailable ~5 GiB) — `gates/00-DISK-MEM-GATE.json`.
2. Enabled CloudSIG Caracal; installed Galera×3 + Keystone on swift1–3.
3. Bootstrap Fernet + credential keys synced; admin/swift/test users created.
4. Additive HAProxy listeners `:3030/:5000/:35357` (Swift `:8085` preserved).
5. Proxy cutover to `authtoken keystoneauth tempauth` coexist; Keystone token→CRUD PASS.
6. TempAuth rollback drill (bak restore) — PARTIAL (see gates).
7. P3-ops LAB TLS: VIP + Keystone HAProxy SSL self-signed; HTTPS CRUD PASS.

## Measured effect

| Metric | Before | After |
|--------|--------|-------|
| Contabo Keystone | ABSENT / BLOCKED | LIVE (uwsgi×3) |
| Galera | absent | `wsrep_cluster_size=3` |
| VIP `/info` | `tempauth` only (HTTP) | `tempauth`+`keystoneauth` (HTTPS) |
| Identity CRUD | N/A | HTTPS PUT/GET/DELETE 201/200/204 |
| PRODUCTION-GO-LIVE | no | still no (self-signed LAB) |

## Gates

| Gate | Result | Evidence |
|------|--------|----------|
| Disk Use% &lt;70% | PASS | `gates/00-DISK-MEM-GATE.json` |
| MemAvailable ≥3 GiB | PASS | same |
| Galera size=3 | PASS | `gates/10-galera-keystone-live.txt` |
| Fernet sync ×3 | PASS | 2 keys/node |
| Token → CRUD (HTTP window) | PASS | cycle log |
| HTTPS CRUD + Keystone TLS | PASS | `gates/20-vip-tls-info.txt` + HTTPS 201/201/tls-obj/204 |
| Threat negative (bogus token) | PASS | HTTP 401 |
| TempAuth rollback drill | PARTIAL | bak exists; one clean window hit proxy-down 503 |
| Secrets not in git | PASS | `/root/contabo-identity-secrets.yml` Contabo-only |
| VIP :8085 not clobbered | PASS | additive overlay |

## Remaining / FROZEN

- **PRODUCTION-GO-LIVE TLS:** operator PEM + rotation runbook (self-signed ≠ prod).
- Permanent systemd unit for rust proxy (currently `systemd-run` transient).
- Pin Contabo `bundle-rust` inventory flags (`identity_haproxy_enabled`, `auth_method=keystone_coexist`) for next ansible apply.
- `openstack` CLI `role add` bug — use REST assign (documented).
