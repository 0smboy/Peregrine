# python_only_identity (docs mapping)

MariaDB Galera + Keystone **provisioning** is Python-only.

| Python role | Purpose |
|-------------|---------|
| `mariadb_servers` | Galera install/config/bootstrap |
| `keystone_install` | Keystone packages + config |
| `keystones` | bootstrap, Swift service, credentials |

Playbooks: `bundle/install_mariadb_keystone.yml`, tagged plays on `bundle/swift.yml`.  
Inventory sample: `bundle/config_contabo_identity/`.

## Rust 对接 (after Python Identity is up)

Set in rust `group_vars` (defaults false — TempAuth VIP unchanged):

- `identity_haproxy_enabled` + backend lists
- `identity_proxy_enabled` and/or `auth_method: keystone_coexist`
- optional play: `rust_identity_bridge` (assert only)

Never rewrite Galera into bundle-rust. Never replace Contabo Swift VIP haproxy
with python `haproxy_servers` without a cutover plan.

See [KEYSTONE-LIVE.md](../../../../docs/fairness-lab/KEYSTONE-LIVE.md),
[IDENTITY.md](../../IDENTITY.md).
