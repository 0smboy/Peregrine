# 13. Deploy apply against the live Contabo inventory

Date: 2026-10-02. Cluster contabo-swift-2026. Console `swift4` `127.0.0.1:9000`. VIP `https://10.0.0.10:8085`. No tokens, login keys, or passwords are in this file.

Plan detail: `tools/test-results/console-accept-20261002/13-apply-plan-summary.md`.

## Apply

`POST /api/apply` was **not sent**.

The sealed plan is `/opt/swift-deploy/swift-plan-contabo-identity.json` (digest prefix `d962336aac56`, 336 tasks, hosts `169.58.108.85` / `.86` / `.87` / `.121`). It is not the sample plan. The sample file `/opt/swift-deploy/swift-plan.json` is unchanged (mtime 2026-10-02 15:30:45Z, digest prefix `35bcf3bcdd33`, hosts `192.168.2.51` and `192.168.2.52`) and was not executed.

Apply is impossible without changing the live nodes. The plan is not empty, not a no-op, and not a restart of the existing swift units.

Disk tasks still in the plan, all with an empty host list:

- `Change disks partition table to mbr before DD` (ids 117 and 132)
- `DD before mkfs` (ids 118 and 133)
- `Format all storage nodes disks` (ids 120 and 135)

Ids 117, 118, and 120 are the live branch (`when`: `not use_custom_disks`, and `use_custom_disks` is false). They would not touch a disk only because `[format_disk_servers]` has no hosts. The same sealed plan would still, on hosts it does name:

- `Yum Upgrade`, `Restart sshd`, `Restart SSH service`, `Disable selinux`
- `Disable iptables and firewalld`, `Start iptables service`, `Import iptables rules`
- MariaDB install on swift1–3 (`Deleting old mariadb`, `Installing mariadb packages`)
- Keystone install on swift1–3 (`Removing old keystone package`, `Install Keystone and dependencies`)

`/srv/node` was not removed. Risk acknowledgements were not sent. `allow_disk_wipe` was not set. Keepalived was not started or restarted by this run.

The validate report also blocks Apply until the four empty Swift groups and the placeholder values in `group_vars/all` are fixed. That check was not used as a substitute for reading the plan. The plan itself is enough to refuse apply.

## Cluster after the plan call

Plan does not contact hosts. These checks are after `POST /api/plan` and without `POST /api/apply`.

| id | check | result | verdict |
|---|---|---|---|
| vip address | `ip -4 addr` on swift1–4 | `10.0.0.10` on swift1 only. Absent on swift2, swift3, swift4 | PASS |
| vip info | `GET https://10.0.0.10:8085/info` from swift1 | 200, 1270 bytes | PASS |
| units | `systemctl is-active` on swift1–4 | `swift-proxy`, `swift-object`, `swift-container`, `swift-account` are `active` on all four | PASS |

## Verdict

| step | verdict |
|---|---|
| plan against Contabo identity inventory | recorded. Job 5 `succeeded`. Not `config_sample` |
| deploy apply | not sent. Plan still names disk wipe tasks, and the tasks that have hosts would reconfigure the four live nodes |

Overall: **ACCEPT_WITH_WARN**. Apply cannot be completed as a no-op. Running this plan would change packages, sshd, firewall, MariaDB, and Keystone on the live nodes. The disk-wipe task names are still in the sealed plan.

## Left in place

- New plan file `/opt/swift-deploy/swift-plan-contabo-identity.json` on swift4. Not executed.
- Inventory copy `/opt/swift-deploy/config_contabo_identity/`. The UI's stored config now points at that inventory and that plan file, because `POST /api/plan` saves the submitted config.
- Previous sample plan `/opt/swift-deploy/swift-plan.json`. Not executed.
- No second Keepalived master. VIP remains on swift1 only.
