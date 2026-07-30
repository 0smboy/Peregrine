# bundle-rust — Rust Swift deployment bundle for swift-deploy-rs

Deploys the **Rust-version OpenStack Swift** (tempauth, replicated storage,
optional erasure-coding policy) onto Rocky 9 nodes, driven by the
swift-deploy-rs executor (the Ansible-subset engine, not real Ansible).
This is the second stack next to `bundle/` (python-v3); workspaces select it
with `stack: rust` and carry the `deploy_stack: rust` marker in
`group_vars/all`.

## What gets deployed

| Piece | Detail |
| --- | --- |
| Binaries | 19 `swift-*` binaries → `/usr/local/bin` (payload inside the bundle, see `roles/rust_payload/PAYLOAD.md`) |
| Libraries | liberasurecode family → `/usr/lib64` + ldconfig |
| Config | `/etc/swift/{swift,proxy-server,account-server,container-server,object-server}.conf`, verified against what the Rust binaries actually parse |
| Rings | built once on the first proxy node with `swift-ring-builder`, staged on the controller under `ring_fetch_dir`, distributed to every node |
| Services | one systemd unit per service: `swift-proxy`, `swift-account`, `swift-container`, `swift-object`, `swift-account-replicator`, `swift-container-replicator`, `swift-object-replicator`, `swift-object-updater`, and `swift-object-reconstructor` on EC clusters. `Environment=SWIFT_DIR=/etc/swift`, `Restart=on-failure` |
| Auditors | `swift-object-auditor` / `swift-db-auditor` are one-shot per-device tools (not conf daemons), scheduled as a nightly cron sweep (`/usr/local/libexec/swift-audit-sweep.sh`) |
| LB | haproxy on `haproxy_servers` when `use_lb`, balancing every proxy's business address on `swift_lb_port`, stats guarded by `haproxy_stats_user/password` |
| Verify | fail-closed: `/healthcheck` per proxy, tempauth token for the first account, container PUT/GET round trip |

All server daemons run as **root** (matching the reference `deploy/bootstrap.sh`
model); no `swift` unix user is created.

## Topology rules

- Same inventory groups as v3: `proxy_servers`, `account_servers`,
  `container_servers`, `object_servers`, `storage_nodes` (children),
  `haproxy_servers`, `ntp_server`/`ntp_clients`; the keystone/mariadb/
  keepalived/... groups must EXIST but may be empty. `inventory_hostname` is
  the management IP, `ansible_user=root`.
- Per-node devices come from `host_vars/<ip>.yml`:
  - `custom_disks` non-empty → each disk is formatted **xfs** (only when not
    already xfs — an existing xfs filesystem is never wiped), mounted at
    `/srv/node/<basename>`, persisted in fstab; ring device = basename.
  - `custom_disks: []` → one directory device `/srv/node/d1`, no mount,
    `mount_check = false`.
- Zones are assigned per node in group order (`z1..zN`), region fixed at `r1`,
  weight from `swift_device_weight`.
- Replication transport is chosen by cluster size
  (`groups['object_servers'] | length > 1`):
  - multi-node → rsync-over-ssh: `rsync_ssh_opts` +
    `rsync_devices_root = srv_node_root`, using one ed25519 key generated on
    the first storage node and authorized on all storage nodes.
  - single node → local `peer_map = <port>:<srv_node_root>` model.
- All servers bind `0.0.0.0` on `proxy/account/container/object_bind_port`.
- The EC reconstructor unit is installed only when more than one storage
  policy exists (`swift_policies | length > 1`).

## Variables (group_vars/all)

See `config_sample/group_vars/all` — it defines every variable any template
or task references, which is exactly the set workspace.rs must render:

- contract vars: `deploy_stack`, `auth_method`, `swift_tempauth_users`,
  `proxy/account/container/object_bind_port`, `srv_node_root`,
  `object_workers`, `swift_policies`, `swift_lb_port`, `swift_device_weight`
- v3-shared vars: `INSTALL_MODE`, `SAIO`, `timezone`, ntp vars, `admin_ips`,
  `ssh_bind_port`, `swift_hash_path_prefix/suffix`,
  `account/container_swift_{partition_power,replicas,minimum_time}`,
  `use_lb`, `lb_mode`, `auth_url_ip`, `haproxy_stats_user/password`
- bundle-rust additions: `ring_fetch_dir` (controller-side staging directory
  for fetched rings and the replication keypair; give every project its own
  path), plus optional `haproxy_monitor_port` / `haproxy_max_conn`
  (defaulted in-template).

`config_sample/` is a structure example: applying from a `config_sample`
path is permanently refused by the UI/backend, and its secrets/key paths are
obvious placeholders.

## Idempotency

Re-applying a converged cluster reports changed=0: templates/copies compare
content, formatting/mounting/units/packages are probe-guarded, ring building
is `creates:`-guarded plus per-ring skips inside the script. Config drift
triggers the `restart swift services` handler; unit-file drift restarts the
affected unit; ring files hot-reload without restarts.

## Honest non-goals (v1)

- No keepalived/VIP for the rust stack; `ingress` is direct or haproxy only.
- No TLS anywhere (`lb_mode: https` is not honored — the haproxy frontend is
  plain http).
- No S3 API.
- No ring rebalance-only reruns: add-disk/add-node flows are not supported.
  Rings build once; topology changes need the ring files removed and rebuilt
  (or a manual `swift-ring-builder` run) — deliberately manual in v1.
- Rocky 9 x86_64 only (prebuilt binaries; glibc >= 2.34).
- Single-node clusters: the DB replicators' full-DB rsync fallback addresses
  peers as `127.0.0.1:<port>` in local peer_map mode, so with rings built on
  a real storage IP that fallback is inert; same-host usync over REPLICATE
  still converges DBs. Multi-node clusters use the ssh path and are unaffected.
- NTP/chrony is not managed by this bundle (groups kept for validation only).

## Layout

```
swift.yml            roles-only plays (planner reads hosts: + roles:)
ansible.cfg
config_sample/       swift_hosts, group_vars/all, host_vars/<ip>.yml
roles/
  rust_common/       timezone, dirs, rsync dep, stop legacy SAIO unit
  rust_disks/        xfs format+mount OR directory device
  rust_payload/      binaries + libs (payload files, see PAYLOAD.md)
  rust_config/       swift.conf + per-server confs (+ restart handler)
  rust_replication_key/  ed25519 keypair, fetched + distributed
  rust_rings/        build_rings.sh.j2, build once, fetch, distribute
  rust_systemd/      per-service units + auditor cron sweep
  rust_haproxy/      haproxy when use_lb
  rust_verify/       healthcheck + tempauth + PUT/GET round trip
```
