# Contabo Identity inventory (python `bundle/` · Galera ×3 + Keystone)

**Stack duty:** this inventory is for `swift-deploy-rs/bundle/` (python ansible-v3)
only. It does **not** deploy Rust Swift and must **not** replace Contabo’s
`bundle-rust` HAProxy Swift VIP frontend. As of 2026-10-04 the MariaDB,
Keystone, disk-format, and package-upgrade groups are empty, so a sealed
`swift.yml` plan does not install those services or wipe disks on the live nodes.

| Bundle | Owns |
|--------|------|
| `bundle/` (this inventory) | Sealed plan for the four live management addresses. MariaDB, Keystone, disk format, yum upgrade, and sshd restart groups are empty |
| `bundle-rust` | Swift data plane + VIP `:8085`; optional Identity *listeners* overlay (`identity_haproxy_enabled`) + proxy `authtoken`/`keystoneauth` filters |

## Topology (locked)

| Role | Nodes | Notes |
|------|-------|-------|
| `[mariadb_servers]` | empty | 2026-10-04: left empty so a sealed `swift.yml` plan does not install MariaDB on the live nodes |
| `[keystones]` | empty | 2026-10-04: left empty so a sealed `swift.yml` plan does not install Keystone on the live nodes |
| `[mutable_base_servers]` | empty | Yum upgrade and sshd restart. Empty so those tasks seal with no hosts |
| `[format_disk_servers]` | empty | Disk-wipe tasks stay in the plan with empty host lists |
| HAProxy Identity | Contabo existing haproxy (rust) | Listen `:3030` MariaDB, `:5000`/`:35357` Keystone — **additive** |
| swift4 | **out** of Galera | Monitor / hub; keep odd DB count |

## Live Contabo gate

**Live (2026-08-05):** Galera×3 + Keystone LAB GREEN — see
`tools/test-results/wave1-identity-live-20260805/`. Disk/mem gate passed after W0′.
Secrets: Contabo `/root/contabo-identity-secrets.yml` only (not git).

## Apply order

Do not apply a plan from this inventory that still names hosts for disk wipe,
yum upgrade, sshd restart, or MariaDB/Keystone install. Those groups are empty
so `swift.yml` seals them with empty host lists. The commands below are the
2026-08-05 procedure and are not the current apply path.

```bash
cd swift-deploy-rs/bundle
# Historical. Groups are empty, so this does not target the live nodes.
# ansible-playbook -i config_contabo_identity/swift_hosts \
#   install_mariadb_keystone.yml --check --diff
```

Passwords in `group_vars/all` are **placeholders** — replace before any live apply.
Never commit real secrets.
