# Impl: Full ansible v3 surface · 2026-08-07

**Claim level:** inventory + sealed plan + dual-guard proof. **Not** Contabo live re-apply. **Not** PRODUCTION-GO-LIVE.  
**Authority doc:** [`docs/fairness-lab/ANSIBLE-V3-SURFACE.md`](../../../docs/fairness-lab/ANSIBLE-V3-SURFACE.md)  
**Parity row:** Platform · Full ansible v3 surface → **PARTIAL/GREEN** (not full Python twin)

## What closed

| Deliverable | Result |
|-------------|--------|
| Full role matrix (Python \| Rust \| status) | `docs/fairness-lab/ANSIBLE-V3-SURFACE.md` + `matrix.json` / `inventory-roles.yml` |
| Greenfield `swift.yml` + optional identity bridge | `when:` identity flags; tags `common`…`verify` |
| **`identity.yml`** optional 对接 re-render | `rust_config` + `rust_haproxy` + `rust_identity_bridge` with `when:` |
| **`monitoring.yml`** + monitoring tags | pointer role `monitoring_overlay_path`; sibling `bundle-monitoring/swift.yml` tags `monitoring`, `mon_*` |
| **`expand.yml`** | add-disk/add-node; tags `expand`; dual-guard no wipe |
| **`deferred-python.yml`** | Keystone / format_disks / platform / extras with `when: include_python_* \| default(false)` — fail-closed |
| Dual-guard Contabo disks | `rust_disks` mkdir-only + refuse wipe inventory flags; workspace rejects `node.disks` for rust; all plans `disk_wipe=0` |
| Thin wrapper roles | `python_only_{identity,format_disks,platform,extras}`, `monitoring_overlay_path`, `rust_identity_bridge` |
| Bundle audit | `compatible=true` rust + monitoring (`20-audit.txt`) |

## Plan gates (sample inventory, offline)

| Playbook | Tasks | DiskWipe | Roles (summary) | Evidence |
|----------|------:|---------:|-----------------|----------|
| `swift.yml` | 140 | **0** | common/payload/disks/config/rings/systemd/haproxy/keepalived/identity_bridge/verify | `21-plan-swift.txt`, `plan-swift.json` |
| `expand.yml` | 51 | **0** | expand_mode/disks/rings/haproxy/keepalived/verify | `21-plan-expand.txt` |
| `identity.yml` | 22 | **0** | config/haproxy/identity_bridge (all `when:`) | `21-plan-identity.txt` |
| `monitoring.yml` | 1 | **0** | monitoring_overlay_path (`when: deploy_monitoring`) | `21-plan-monitoring.txt` |
| `deferred-python.yml` | 5 | **0** | python_only_* (all `when: include_python_*` default false) | `21-plan-deferred-python.txt` |
| `bundle-monitoring/swift.yml` | 24 | **0** | mon_payload/config/systemd | `21-plan-monitoring-sibling.txt` |

Risk class on data-plane plans: **HostReconfigure only** (no DiskWipe / Firewall). See `plan-risk-summary.json`.

## Dual-guard (Contabo)

1. Static: no executable `mkfs` / `wipefs` / `dd if=/dev/zero` / `parted /dev` in `bundle-rust/roles/**/tasks` (`10-static-dual-guard.txt`).  
2. Plan: every sealed plan above has `disk_wipe=0`.  
3. Runtime: `rust_disks` fails if inventory sets `force_format_disks` / `include_python_format_disks` / `allow_disk_wipe` / `use_format_disks`.  
4. Workspace: rust stack rejects non-empty `node.disks` (no DiskWipe risk class on rust plans).  
5. Contabo wipe of `/srv/node` requires ticket + `--allow-disk-wipe` on a **non-bundle-rust** path.

## Optional Python-only pattern

```yaml
# deferred-python.yml (snippet)
- hosts: keystones
  roles:
    - role: python_only_identity
      when: include_python_keystone_install | default(false)

- hosts: format_disk_servers
  roles:
    - role: python_only_format_disks
      when: include_python_format_disks | default(false)
```

Default false → no-op at apply. Forced true → fail closed with pointer to Python bundle. Real install:

```sh
swift-deploy apply … --bundle bundle --playbook install_mariadb_keystone.yml
# disks: OOB mount + expand.yml  (never Contabo live wipe via rust)
```

## Residual (honest — still not FULL)

1. format_disks / format_new_disks never in rust (by design dual-guard).  
2. MariaDB Galera / Keystone package install stays Python-only.  
3. chrony, security, performance_tuning, system_tuning, proxyfs, docker, cosbench ABSENT.  
4. No dedicated `add_new_ring.yml` twin.  
5. Monitoring is sibling `bundle-monitoring`, not inlined.  
6. Ring expand semantics differ (no replica2part2dev persistence) — P3 contract.  
7. deploy-rs does not filter Ansible `tags:` (documentation / real-Ansible only).  
8. Contabo live re-apply of this revision **not** run (plan-only gate).

## Verdict

**PARTIAL GREEN** — implemented Rust data-plane + LB + expand + Identity 对接 + monitoring overlay path are deployable via bundle-rust companion plays; full Python ansible-v3 role set is **not** cloned 1:1; Contabo disks dual-guard held.
