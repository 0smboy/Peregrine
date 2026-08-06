# Identity 对接 templates (bundle-rust)

**Scope:** wire Rust proxy + Contabo HAProxy to an externally installed
Keystone/Galera. **Not** a Galera rewrite.

| Artifact | Purpose |
|----------|---------|
| `group_vars_identity_bridge.yml.sample` | Knobs to merge into project `group_vars/all` |
| `roles/rust_haproxy/templates/haproxy.cfg.j2` | Optional MariaDB `:3030` + Keystone `:5000`/`:35357` listeners when `identity_haproxy_enabled` |
| `roles/rust_config/templates/proxy-server.conf.j2` | Renders `authtoken`+`keystoneauth` when `auth_method` is `keystone` or `keystone_coexist` |

Install path for Identity packages: `bundle/inventories/contabo-identity/` +
`install_mariadb_keystone.yml`. Operator runbook:
`docs/fairness-lab/KEYSTONE-LIVE.md`.
