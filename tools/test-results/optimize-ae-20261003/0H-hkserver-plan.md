# hkserver node-add plan, sealed before apply

Date: 2026-10-04. This file was written before `POST /api/apply`. The digest below is the only digest that may be applied.

`config_sample` was not used. Digest `8195ef0adca513ae7c67c2966ff4aaaa11693bfb19d4efea6bf386d7abe6a9b9` was not applied. Digest `d962336aac56` was not applied.

## What was reachable

hkserver (`ssh hkserver`, public `103.117.121.203`, Tailscale `100.70.202.32`) is Rocky 9.2. Its only disk is `vda` / `vda1` mounted on `/`. There is no non-root data disk. The root disk is not a format target.

hkserver could not reach `10.0.0.0/22`, `10.0.4.0/22`, or `10.0.8.0/22`. Tailscale is installed on hkserver and is not installed on swift1–4. A WireGuard interface `wg-hk` was brought up on the five hosts only. swift1–4 accept UDP `51820` only from `103.117.121.203`. hkserver's public zone is `DROP` with ssh, plus UDP `51820` only from `169.58.108.85`, `.86`, `.87`, and `.121`. `wg-hk` is in the trusted zone. Proxy and replication ports are not opened on the public zone.

| host | business | storage | replication | tunnel |
|---|---|---|---|---|
| swift1 | 10.0.0.1 | 10.0.4.1 | 10.0.8.1 | 10.44.0.1 |
| swift2 | 10.0.0.2 | 10.0.4.2 | 10.0.8.2 | 10.44.0.2 |
| swift3 | 10.0.0.3 | 10.0.4.3 | 10.0.8.3 | 10.44.0.3 |
| swift4 | 10.0.0.4 | 10.0.4.4 | 10.0.8.4 | 10.44.0.4 |
| hkserver | 10.0.0.5 | 10.0.4.5 | 10.0.8.5 | 10.44.0.5 |

hkserver management address on the host is `10.0.36.5`. SSH uses `103.117.121.203`. After the tunnel, hkserver pinged `10.0.0.1`, `10.0.4.1`, and `10.0.8.1`. swift1–4 pinged `10.0.0.5`, `10.0.4.5`, and `10.0.8.5`. VIP `10.0.0.10/22` was on swift1 only.

## Sealed plan

Bundle `swift-deploy-rs/bundle-hkserver-add`. Playbook `hkserver-add.yml`. Inventory `config_hkserver_add/swift_hosts` (not `config_sample`).

Digest `9c78c318b439ee077cb5c56953a2d188af2da3af28908cc52eb3c3a73f0ce5b8`.

27 tasks, 0 handlers, 5 hosts. Capabilities required: `DiskWipe`, `HostReconfigure`. Firewall and SSH-reconfigure capabilities are not required. `format_disk_servers`, `mutable_base_servers`, and `keepalived_servers` are empty.

The only `mkfs` task is task 1. Its host list is `103.117.121.203`. It formats `/var/lib/peregrine-node/d2.img` (40G file, weight 80) and mounts it at `/srv/node/d2`. The script exits if the mkfs target or the mount source is `/dev/vda`, `/dev/vda1`, or the filesystem mounted on `/`.

No task is named `Install swift`, `Yum Upgrade`, `Restart sshd`, `Restart SSH service`, `Disable selinux`, `Import iptables rules`, `DD before mkfs`, `Change disks partition table to mbr before DD`, or `Format all storage nodes disks`. None of those names have a host.

| id | task | hosts |
|---|---|---|
| 1 | Create hkserver data volume | 103.117.121.203 |
| 2 | Install haproxy on hkserver | 103.117.121.203 |
| 3 | Install rsync on hkserver | 103.117.121.203 |
| 4 | Unpack hkserver swift payload | 103.117.121.203 |
| 5 | Install rust swift files on hkserver | 103.117.121.203 |
| 6 | Add hkserver devices and rebalance | 169.58.108.85 |
| 7 | Fetch account ring | 169.58.108.85 |
| 8 | Fetch account builder | 169.58.108.85 |
| 9 | Fetch container ring | 169.58.108.85 |
| 10 | Fetch container builder | 169.58.108.85 |
| 11 | Fetch object ring | 169.58.108.85 |
| 12 | Fetch object builder | 169.58.108.85 |
| 13 | Fetch object-1 ring | 169.58.108.85 |
| 14 | Fetch object-1 builder | 169.58.108.85 |
| 15 | Backup existing rings before distribute | 103.117.121.203, 169.58.108.121, 169.58.108.85, 169.58.108.86, 169.58.108.87 |
| 16 | Install account ring | same five |
| 17 | Install account builder | same five |
| 18 | Install container ring | same five |
| 19 | Install container builder | same five |
| 20 | Install object ring | same five |
| 21 | Install object builder | same five |
| 22 | Install object-1 ring | same five |
| 23 | Install object-1 builder | same five |
| 24 | Start hkserver swift services | 103.117.121.203 |
| 25 | Add hkserver to haproxy | same five |
| 26 | Validate haproxy configuration | same five |
| 27 | Reload haproxy | same five |

Task 6 adds only these devices, then rebalances. It does not rebuild the rings from an inventory device list, so existing region and zone ids stay as they are.

| ring | spec | weight |
|---|---|---|
| account | `r1z5-10.0.4.5:6202R10.0.8.5:6202/d2` | 80 |
| container | `r1z5-10.0.4.5:6201R10.0.8.5:6201/d2` | 80 |
| object and object-1 | `r3z1-10.0.4.5:6211R10.0.8.5:6211/d2` | 80 |

Tasks 15–23 copy the new rings. They do not mkfs. Task 25 inserts `server proxy5 10.0.0.5:8080` and does not remove the existing `proxy2` `disabled` flag. Task 27 reloads haproxy and exits if `10.0.0.10/22` is present on a host whose short hostname is not `swift1`. keepalived is not in this plan.

`POST /api/apply` had not been sent when this file was written.
