# Keystone live path — dual-bundle Identity (Contabo)

**Status (2026-08-05 live):** Contabo Galera×3 + Keystone **LAB GREEN** on
swift1–3; rust additive HAProxy Identity listeners; proxy
`authtoken`+`keystoneauth` coexist with TempAuth. VIP TLS terminate is
**LAB self-signed** (see p3-ops). **Not** PRODUCTION-GO-LIVE (no operator PEM).

Evidence: `tools/test-results/wave1-identity-live-20260805/`  
TLS: `tools/test-results/p3-ops-tls-live-20260805/`  
Auth CRUD re-green (coexist fix): `tools/test-results/vip-auth-crud-fix-20260805/`  
Prep (historical BLOCK): `tools/test-results/wave1-identity-prep-20260805/`

## Dual-bundle duties (locked)

| Layer | Bundle | Responsibility |
|-------|--------|----------------|
| Identity DB + API | `swift-deploy-rs/bundle/` | MariaDB Galera ×3 (swift1–3), Keystone install/bootstrap |
| Swift + VIP LB | `swift-deploy-rs/bundle-rust/` | Rust proxy/account/container/object + Keepalived VIP `:8085` |
| Identity LB listeners | `bundle-rust` haproxy overlay | Additive `:5000` / `:35357` / MariaDB `:3030` — **never** replace Swift frontend via python `haproxy_servers` |
| Proxy auth filters | Rust `authtoken` + `keystoneauth` | Contabo live: `keystone_coexist` (TempAuth retained) |

**Do not** rewrite Galera into `bundle-rust`. `workspace.rs` still rejects
`mariadb`/`keystone` roles on `stack: rust`.

## Contabo inventory

Path: [`swift-deploy-rs/bundle/config_contabo_identity/`](../../swift-deploy-rs/bundle/config_contabo_identity/)

- `[mariadb_servers]` = swift1–3 (management `169.58.108.85–87`, Galera on `10.0.4.x`)
- `[keystones]` = same three; bootstrap host = first MariaDB
- Swift groups empty (Identity-only apply)
- `[haproxy_servers]` empty on purpose (rust owns Contabo haproxy.cfg)
- `[format_disk_servers]` empty — **mkfs forbidden**
- Secrets: `-e @/root/contabo-identity-secrets.yml` on Contabo (mode 0600, **not in git**)

## Live apply notes (Rocky 9.8 Contabo)

1. **Gate:** `/srv/node/d*` Use% &lt;70%; MemAvailable ≥3 GiB (passed 2026-08-05: ~2% disk, ~5 GiB).
2. Enable CloudSIG OpenStack: `centos-release-openstack-caracal` → `openstack-keystone`.
3. Rocky AppStream: `mariadb-backup`, `galera`, `mariadb-server-galera` (provides `galera_new_cluster`), `wsrep_provider=/usr/lib64/galera/libgalera_smm.so`.
4. Jinja2/MarkupSafe conflict: pin/upgrade pip Jinja2≥3.1 so `keystone-manage` imports.
5. HAProxy Identity overlay additive on existing rust `haproxy.cfg` (`:3030/:5000/:35357`).
6. Proxy `auth_url` validates against local Keystone uwsgi `http://127.0.0.1:5001/v3` (swift4 → `10.0.4.1:5001`); public `www_authenticate_uri` = `https://10.0.0.10:5000`.
7. TempAuth bak: `/etc/swift/proxy-server.conf.bak-tempauth-20260805`; coexist bak: `.bak-keystone-coexist-20260805`.

## Acceptance (LAB, 2026-08-05)

| Gate | Result |
|------|--------|
| `wsrep_cluster_size=3` | PASS |
| Fernet keys synced ×3 | PASS |
| Keystone token via VIP `:5000` | PASS (HTTPS after TLS) |
| Keystone token → Swift CRUD | PASS (HTTP then HTTPS) |
| TempAuth coexist | PASS (re-proven 2026-08-05 after keystoneauth stamp fix) |
| TempAuth rollback drill | PARTIAL (bak restore proven; one clean window hit proxy-down 503 — process mgmt) |
| VIP `:8085` not clobbered | PASS (additive listeners) |

## Coexist regression (fixed 2026-08-05)

Wave4 probes saw TempAuth list **401** and Keystone **403** on `AUTH_test`:

1. **Keystone 403 on `AUTH_test`** — probe/client bug, not IdP. Storage account is
   `AUTH_<project_id>` (e.g. `AUTH_29af7f1e19774999bf700fbef31994d3` for project
   `test`). Cross-tenant list correctly returns 403. Keystone token→CRUD on the
   project account was already green before the proxy fix.
2. **TempAuth 401** — Rust `keystoneauth` stamped `X-Backend-Auth-Plugin:
   keystone` for every `AUTH_*` account even when identity was absent, so proxy
   authorize used Keystone (anonymous → 401) and never TempAuth ACLs. Fix: stamp
   Auth-Plugin only when Keystone identity is Confirmed (`keystoneauth.rs`).
   `authtoken` `delay_auth_decision=true` deferral was already correct.

Re-proof: `tools/test-results/vip-auth-crud-fix-20260805/` — TempAuth + Keystone
CRUD both PASS on VIP `https://10.0.0.10:8085`. Proxy sha256
`657e07439cde3520e83dd1bb47bf0f130120e532d39fda53a2925a0d938c2f77` ×4.

## Honest non-claims

- **PRODUCTION-GO-LIVE** requires operator TLS PEM (not Contabo self-signed LAB).
- `openstack role add` CLI hit a client bug; role assign via Keystone REST (204).
- Contabo proxy is `swift-proxy.service` (rust); keep payload bin in sync on apply.
- Secrets live only under `/root/contabo-identity-secrets.yml` on Contabo.
