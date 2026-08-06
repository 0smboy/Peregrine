# Contabo Identity inventory (python `bundle/` · Galera ×3 + Keystone)

**Stack duty:** this inventory is for `swift-deploy-rs/bundle/` (python ansible-v3)
only. It provisions MariaDB Galera + Keystone. It does **not** deploy Rust Swift
and must **not** replace Contabo’s `bundle-rust` HAProxy Swift VIP frontend.

| Bundle | Owns |
|--------|------|
| `bundle/` (this inventory) | MariaDB Galera on swift1–3, Keystone on swift1–3, Keystone DB bootstrap |
| `bundle-rust` | Swift data plane + VIP `:8085`; optional Identity *listeners* overlay (`identity_haproxy_enabled`) + proxy `authtoken`/`keystoneauth` filters |

## Topology (locked)

| Role | Nodes | Notes |
|------|-------|-------|
| `[mariadb_servers]` | swift1–3 (`169.58.108.85–87`) | Odd quorum; Galera on storage plane `10.0.4.x` |
| `[keystones]` | swift1–3 (first MariaDB = bootstrap) | Public via HAProxy `:5000` |
| HAProxy Identity | Contabo existing haproxy (rust) | Listen `:3030` MariaDB, `:5000`/`:35357` Keystone — **additive** |
| swift4 | **out** of Galera | Monitor / hub; keep odd DB count |

## Live Contabo gate

**Live (2026-08-05):** Galera×3 + Keystone LAB GREEN — see
`tools/test-results/wave1-identity-live-20260805/`. Disk/mem gate passed after W0′.
Secrets: Contabo `/root/contabo-identity-secrets.yml` only (not git).

## Apply order (when unblocked)

```bash
cd swift-deploy-rs/bundle
# Standalone playbook tags: install_standalone_mariadb / install_standalone_keystone
ansible-playbook -i config_contabo_identity/swift_hosts \
  install_mariadb_keystone.yml --check --diff

# Or via swift.yml Identity tags only:
# ansible-playbook -i config_contabo_identity/swift_hosts swift.yml \
#   --tags mariadb_servers,keystones_install,keystones_setup --check

# After Galera/Keystone healthy — separate cutover window on bundle-rust:
# 1) identity_haproxy_enabled=true + backends 10.0.4.1-3; haproxy -c; reload
# 2) auth_method=keystone_coexist (or keystone) + identity_proxy_enabled=true
# 3) rolling restart proxies; smoke Keystone token CRUD; keep TempAuth window if coexist
```

Passwords in `group_vars/all` are **placeholders** — replace before any live apply.
Never commit real secrets.
