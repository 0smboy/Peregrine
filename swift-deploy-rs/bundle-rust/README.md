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
| Binaries | 23 `swift-*` binaries → `/usr/local/bin` (payload inside the bundle, see `roles/rust_payload/PAYLOAD.md`) |
| Libraries | liberasurecode family → `/usr/lib64` + ldconfig |
| Config | `/etc/swift/{swift,proxy-server,account-server,container-server,object-server}.conf`, verified against what the Rust binaries actually parse |
| Rings | built on the first proxy with `swift-ring-builder`, staged under `ring_fetch_dir`, distributed to every node. Greenfield uses a content stamp; **expand** via `expand.yml` (`ring_expand`) idempotently adds missing devices |
| Services | one systemd unit per service (proxy/account/container/object + replicators/updater/expirer/reaper/reconciler/auditors; EC reconstructor when multi-policy) |
| Devices | `host_vars.swift_devices` (default `d1`) — **mkdir only**, never mkfs/wipe `/srv/node` |
| LB | haproxy when `use_lb`; `lb_mode=http` or **`https`** (TLS terminate at HAProxy); optional Keepalived VIP |
| Verify | fail-closed: `/healthcheck`, tempauth token, container PUT/GET |

All server daemons run as **root** (matching the reference `deploy/bootstrap.sh`
model); no `swift` unix user is created.

## Topology rules

- Same inventory groups as v3: `proxy_servers`, `account_servers`,
  `container_servers`, `object_servers`, `storage_nodes` (children),
  `haproxy_servers`, `ntp_server`/`ntp_clients`; the keystone/mariadb/
  keepalived/... groups must EXIST but may be empty. `inventory_hostname` is
  the management IP, `ansible_user=root`.
- Per-node devices: `swift_devices: [d1, d2, …]` under `srv_node_root`.
  Block devices must be prepared **out-of-band** (XFS mount already present).
- `region` / `zone` from host_vars feed ring device ids (`r<R>z<Z>-…`).
  See [MULTI-REGION.md](../../docs/fairness-lab/MULTI-REGION.md).
- Replication transport: multi-node → rsync-over-ssh; single node → local peer_map.

## P3-ops: TLS

When `lb_mode: https` (workspace `ingress.http_mode=https` with haproxy/keepalived):

1. Operator PEM: set `haproxy_tls_pem_src` to a controller-side cert+key PEM, or
2. Lab self-signed: `haproxy_tls_self_signed: true` (default) generates CN=`auth_url_ip`.

Backends stay plain HTTP to proxies. Contabo lab may already use self-signed on
VIP; **production** needs an operator-trusted PEM (no secrets in git).

One-shot operator install (does not auto-touch Contabo without `--ssh`):

```sh
# from monorepo root
./tools/ops/apply-vip-tls-pem.sh --pem /secure/vip.pem --check
./tools/ops/apply-vip-tls-pem.sh --pem /secure/vip.pem \
  --ssh swift1,swift2,swift3,swift4 --reload   # after explicit confirmation
./tools/ops/check-haproxy-tls-contract.sh      # static dry-run, no cluster
```

See [`tools/ops/README.md`](../../tools/ops/README.md) and
[P3-OPS-CONTRACT.md](../../docs/fairness-lab/P3-OPS-CONTRACT.md).

## P3-ops: add-disk / add-node

Playbook: **`expand.yml`** (sets `ring_expand` via `rust_expand_mode`).

1. Mount/prepare new device out-of-band at `/srv/node/<name>` (or bring up a node).
2. Update inventory host_vars (`swift_devices`, region/zone, groups).
3. `swift-deploy apply … --playbook expand.yml`
4. Dual-guard: no wipe of `/srv/node` without an explicit ticket outside this bundle.

Honest note: Rust `swift-ring-builder` rebalance rebuilds assignment from the
device list (no persistent replica2part2dev) — expect partition movement;
replicators heal. Use a maintenance window.

## Variables (group_vars/all)

See `config_sample/group_vars/all` — includes TLS (`haproxy_tls_*`) and expand
(`ring_expand`, `ADD_NODES`, `ring_force_rebuild`) knobs. Workspace.rs renders
the real project file from the same contract.

## Idempotency

Re-applying a converged cluster reports changed=0 when stamp matches.
Topology edits re-render `build_rings.sh` (stamp change → rebuild) or use
`expand.yml` for additive expand. Config drift restarts services via handlers.

## Identity 对接 (not provisioning)

MariaDB Galera + Keystone are installed with the **python**
[`bundle/config_contabo_identity`](../bundle/config_contabo_identity/) inventory.
This bundle only wires:

- optional HAProxy Identity listeners (`identity_haproxy_enabled`)
- optional proxy `authtoken`/`keystoneauth` filters (`identity_proxy_enabled`)

See [IDENTITY.md](IDENTITY.md) and [KEYSTONE-LIVE.md](../../docs/fairness-lab/KEYSTONE-LIVE.md).
Default Contabo remains TempAuth on VIP `:8085`.

## Honest non-goals

- No S3 API default; no MariaDB/Keystone *provisioning* in this bundle.
- No managed block-device wipe/format (dual-guard).
- Rocky 9 x86_64 only (prebuilt binaries; glibc >= 2.34).
- NTP/chrony groups kept for validation only (not managed here).

## Layout

```
swift.yml            DEFAULT Contabo/greenfield (PARTIAL; dual-guard, no format_disks)
swift-full-v3.yml    OPT-IN full ansible-v3 twin (every bundle/swift.yml role;
                     rust where present, Python ABSENT via roles_path/symlinks;
                     format_disks only when allow_disk_format=true)
expand.yml           P3-ops add-disk/add-node (ring_expand)
identity.yml         optional Identity 对接 re-render (when flags)
monitoring.yml       pointer + tags → sibling bundle-monitoring
deferred-python.yml  Python-only surfaces; explicit when: default false
ansible.cfg          roles_path = roles:../bundle/roles
config_sample/       swift_hosts, group_vars/all, host_vars/<ip>.yml
roles/
  rust_common/       timezone, dirs, rsync dep, stop legacy SAIO unit
  rust_disks/        mkdir-only devices; refuse inventory wipe flags
  rust_payload/      binaries + libs
  rust_config/       swift.conf + per-server confs
  rust_replication_key/  ed25519 keypair
  rust_rings/        build_rings.sh.j2 (create / expand / force)
  rust_expand_mode/  set_fact ring_expand for expand.yml
  rust_systemd/      per-service units
  rust_haproxy/      haproxy (+ optional TLS + identity listeners)
  rust_keepalived/   Keepalived VIP
  rust_identity_bridge/  optional Identity 对接 assert (never installs Keystone)
  rust_verify/       healthcheck + tempauth + PUT/GET
  python_only_*/     docs + fail-closed wrappers for ABSENT Python roles
  monitoring_overlay_path/  points at bundle-monitoring (not inlined)
  <ABSENT python>/   symlinks → ../../bundle/roles/* for full-v3 / real Ansible
```

Full Python↔Rust role matrix: [ANSIBLE-V3-SURFACE.md](../../docs/fairness-lab/ANSIBLE-V3-SURFACE.md).
