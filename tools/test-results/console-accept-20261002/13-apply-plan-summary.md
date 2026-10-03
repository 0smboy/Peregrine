# 13. Live Contabo plan summary

Date: 2026-10-02. Console `swift4` `127.0.0.1:9000`. No tokens, login keys, CSRF values, or passwords are in this file.

`config_sample` was not the inventory for this plan. The deploy UI's stored config before this call was still `bundle/config_sample/swift_hosts` (job 3, sealed sample plan, hosts `192.168.2.51` and `192.168.2.52`). That file `/opt/swift-deploy/swift-plan.json` was not overwritten and was not applied. On swift4 the only `swift_hosts` already on disk was that sample. There is no `/var/lib/swift-deploy` workspace. The inventory used here is the repo's Contabo identity inventory, copied to `/opt/swift-deploy/config_contabo_identity/` (mode 600). It is not under `config_sample`.

## Inventory

| item | value |
|---|---|
| path | `/opt/swift-deploy/config_contabo_identity/swift_hosts` |
| bundle | `/opt/swift-deploy/bundle` |
| playbook | `/opt/swift-deploy/bundle/swift.yml` |
| plan file | `/opt/swift-deploy/swift-plan-contabo-identity.json` (mode 600) |
| hosts | `169.58.108.85`, `169.58.108.86`, `169.58.108.87`, `169.58.108.121` (swift1–4 management) |
| business addresses | `10.0.0.1`–`10.0.0.4` in host_vars |
| VIP in group_vars | `10.0.0.10`, `swift_lb_port` 8085 |
| `custom_disks` | `[]` on all four hosts |
| device names d1/d2/d3 | not listed. `devices` is the path `/srv/node`. `[format_disk_servers]` is empty. Swift groups `proxy_servers`, `account_servers`, `container_servers`, `object_servers` are empty |
| `use_custom_disks` | false |
| `REINSTALL` | false |
| `hostname_modifiable` | false |
| `auth_method` | keystone |
| `use_local_mariadbs` | true |

`bundle-rust/config_contabo_live` is an overlay of host_vars only. It has no `swift_hosts`, so it cannot be planned. It was not loaded.

## API

Login `POST /login` tenant `test`, user `tester`, key read at runtime from swift4 `proxy-server.conf` (first field, 64 characters). Status **303**, location `/files`. Key not written down.

| id | method | status | verdict |
|---|---|---|---|
| state before | `GET /api/state` | 200 | recorded. Inventory still `bundle/config_sample/swift_hosts`. Job 3 plan `succeeded` |
| validate | `POST /api/validate` with the Contabo identity config | 202 `{"ok":true,"id":4}` | then `succeeded`, message `inventory validation passed` |
| plan | `POST /api/plan` with the same config | 202 `{"ok":true,"id":5}` | then `succeeded`, message `sealed plan created` |

Validate `sample` is true because apply blockers are non-empty, not because the path contains `config_sample`. Blockers: the four Swift groups have no hosts, and `group_vars/all` still has placeholder account keys and placeholder passwords. `placeholders` in the validate report was an empty list. `host_disks` for all four hosts is `[]`.

## Sealed plan

Digest length 64, prefix `d962336aac56`. Hosts: the four live management addresses above. 336 tasks, 2 handlers. 216 tasks have a non-empty host list.

Risks present on tasks that name hosts: `host_reconfigure`, `ssh_reconfigure`, `firewall`.

### Disk / format / wipe

Yes. Six tasks carry `disk_wipe`. All six have an empty host list, because `[format_disk_servers]` is empty. The executor only iterates `task.hosts`, so these tasks would not run on a machine.

`use_custom_disks` is false, so the live `when` is `not use_custom_disks`.

| id | task | when | hosts | risk |
|---|---|---|---|---|
| 117 | Change disks partition table to mbr before DD | `not use_custom_disks` | none | `disk_wipe` |
| 118 | DD before mkfs | `not use_custom_disks` | none | `disk_wipe` |
| 120 | Format all storage nodes disks | `not use_custom_disks` | none | `disk_wipe` |
| 132 | Change disks partition table to mbr before DD | `use_custom_disks` | none | `disk_wipe` |
| 133 | DD before mkfs | `use_custom_disks` | none | `disk_wipe` |
| 135 | Format all storage nodes disks | `use_custom_disks` | none | `disk_wipe` |

The words mkfs, disk_wipe, DD, format, and wipe appear on these tasks. Other `format_disks` tasks (ids 107–148 except the six above) also match the word "format" via the role name. Their host lists are empty too.

### Tasks that do name the live hosts

Not a no-op. Roles with at least one host: `check` 1, `common` 58, `chrony` 4, `ring_builder` 22, `ring_utils` 10, `finalize_installation` 14, `mariadb_servers` 28, `keystone_install` 22, `keystones` 46, `security` 11.

Unconditional (`when` empty) tasks on all four nodes include `Yum Upgrade`, `Restart sshd`, `Restart SSH service`, `Disable selinux`, `Disable iptables and firewalld`, `Start iptables service`, and `Import iptables rules`. MariaDB tasks on swift1–3 are gated by `use_local_mariadbs` (true), including `Deleting old mariadb` and `Installing mariadb packages`. Keystone tasks on swift1–3 are gated by `auth_method == keystone` (true), including `Removing old keystone package` and `Install Keystone and dependencies`.

`reinstall swift_cluster` is gated by `REINSTALL` (false). `Setup hostname` is gated by `hostname_modifiable` (false). `Ensure service state on keepalived servers` is gated by membership in `keepalived_servers` (empty). Those three would skip. The yum, ssh, selinux, firewall, MariaDB, and Keystone tasks would not.

`POST /api/apply` was not sent. See `13-apply.md`.
