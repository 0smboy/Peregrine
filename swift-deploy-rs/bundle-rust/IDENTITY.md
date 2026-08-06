# Identity 对接 (bundle-rust)

`bundle-rust` **does not** deploy MariaDB or Keystone. Contabo Identity is
installed with the python [`bundle/config_contabo_identity`](../bundle/config_contabo_identity/)
inventory. This file documents the **对接** surface only.

## Templates

| Path | Purpose |
|------|---------|
| `roles/rust_config/templates/proxy-server.conf.j2` | Inlined `[filter:authtoken]`/`keystoneauth` when `identity_proxy_enabled` |
| `roles/rust_haproxy/templates/haproxy.cfg.j2` | Inlined Identity listeners when `identity_haproxy_enabled` |
| `roles/*/templates/identity/*.j2` | Reference fragments (docs); deploy-rs has **no** Jinja include loader |
| `config_sample/identity/identity_overlay.example.yml` | Variable knobs |

Default Contabo apply leaves both flags **false** (TempAuth VIP unchanged).

## Cutover checklist

1. Galera `wsrep_cluster_size=3` + Keystone token issue OK
2. `identity_haproxy_enabled=true` → `haproxy -c` → reload (Swift `:8085` unchanged)
3. Render proxy filters; flip pipeline; rolling restart proxies
4. Smoke: Keystone token CRUD via VIP; TempAuth path per window policy
5. Evidence under `tools/test-results/p3-auth-live-YYYYMMDD/`

See [KEYSTONE-LIVE.md](../../docs/fairness-lab/KEYSTONE-LIVE.md).
