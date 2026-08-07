# rust_identity_bridge

Optional play role for Identity **对接** (not provisioning).

- Runs only when `identity_haproxy_enabled`, `identity_proxy_enabled`, or
  `auth_method` is `keystone` / `keystone_coexist`.
- Asserts backend lists when HAProxy Identity listeners are enabled.
- **Never** installs Keystone or MariaDB; **never** touches `/srv/node`.

See [IDENTITY.md](../../IDENTITY.md) and
[ANSIBLE-V3-SURFACE.md](../../../../docs/fairness-lab/ANSIBLE-V3-SURFACE.md).
