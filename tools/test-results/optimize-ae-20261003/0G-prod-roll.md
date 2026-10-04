# Production proxy roll and sealed-plan refusal

Date: 2026-10-04. Source binary: swift1 `/root/work/g6-rust-bin/swift-proxy-server`, sha256 `dc22cca7b45e6bbc4a096f99675aeab8855282276fc9f8caaa2d6ed00f402314`, context `bin_t`. That is the file named by `tools/test-results/optimize-ae-20261003/verdict.json` (2026-10-03). It still matched that hash immediately before the copy. `/root/work/prod-backup-20261002` was not deleted.

The production G7 suite was not re-run on `:8080` or `:8085`. This file does not say the production cluster passed G7. Production readiness stays NO-GO until a prod-port G7 verdict exists. That verdict was not created here.

## Proxy

Each node kept the previous binary at `/root/work/prod-backup-20261004/swift-proxy-server.5cac5960-prod`, sha256 `5cac5960c45b3a206a794e0a0c52d89f51c251b0ce698de21f245da7fa6a2397`. `restorecon` left `/usr/local/bin/swift-proxy-server` as `system_u:object_r:bin_t:s0`. Only `swift-proxy` was restarted. After each restart, that node's `http://127.0.0.1:8080/info` was 200, `10.0.0.10/22` was only on swift1, and `https://10.0.0.10:8085/info` was 200.

| UTC | node | pid | `:8080/info` | VIP `10.0.0.10/22` |
|---|---|---|---|---|
| 00:51:28 | swift2 | 3115590 | 200 | still only on swift1, `:8085/info` 200 |
| 00:52:19 | swift4 | 4142789 | 200 | still only on swift1, `:8085/info` 200 |
| 00:54:16 | swift3 | 4128065 | 200 | still only on swift1, `:8085/info` 200 |
| 00:55:14 | swift1 | 4123826 | 200 | stayed on swift1 through five checks, `:8085/info` 200 |

swift1's previous process was pid 3495932, started Fri Oct 2 12:16:43 2026. The swift4 step ran before swift3: the VIP check loop in that script overwrote the target address, so the install landed on 10.0.0.4. swift3 was still the old hash after that step and was rolled next. The VIP did not move, so the previous binary was not restored.

After all four, `/proc/<pid>/exe` on each node is sha256 `dc22cca7b45e6bbc4a096f99675aeab8855282276fc9f8caaa2d6ed00f402314`. `swift-proxy` is active. `http://127.0.0.1:8080/info` is 200 on each node. `10.0.0.10/22` is on swift1 `eth1` only. `https://10.0.0.10:8085/info` is 200.

## Object, container, account

Not rolled. G7 commits `3f5ea6a`, `0a1d590`, and `06a78a6` changed `swift-http` and `swift-proxy-server`. They did not change the object, container, or account server sources. `5644a9d` added a container sharder unit test only.

| binary | lab `/root/work/g6-rust-bin` on swift1 | production `/usr/local/bin` on all four |
|---|---|---|
| swift-object-server | `add3f2b92f9435555801a98b2fdae9eb154a7f6d23d3af9755def3aa5a73e478` (mtime 2026-09-29 07:13 UTC) | `6c3cd551c6943422cc87dc7b4652987e566d9136fc75960e472c7dd16b33f315` (mtime 2026-10-01 15:36 UTC) |
| swift-container-server | `33c4d72055c00f6e90b8adcbff43d79581bc3976a87a3f8a47e892cc32457fa0` (mtime 2026-10-03 11:40 UTC) | `6e697697545d9ab7c1d5bd0276348bfacd2d86d6ed7558f351690c13b504a263` |
| swift-account-server | `8fbe7475fd7240536d47e537e8c9d0f4090d44fd19a45ed76d6d21f547e41273` (mtime 2026-10-03 11:40 UTC) | `f2cb830c4403febc28bee0d33036c497c6a3194d6ed28d13c1e0128b80cc00c9` |

The lab object file is the one named in `verdict.json` and is older than the production object server. The lab account and container files were built at 11:40 UTC, before green commit `06a78a6` (15:39 UTC). They are not that commit's binaries.

## VIP object check

From swift4 at 00:56:10 UTC, tempauth `test:tester` against `https://10.0.0.10:8085`. The key was read on the host and was not written here.

| step | code |
|---|---|
| `GET /auth/v1.0` | 200, storage path `/v1/AUTH_test` |
| `PUT /v1/AUTH_test/console-rollout-20261004` | 201 |
| `PUT .../console-rollout-20261004` | 201 |
| `GET` the object | 200, sha256 `3a06bd8652df6c60e043144e9162fd03457763126bf069c44be88bbbd37365d7` matches the 25-byte body |
| `DELETE` the object | 204 |
| `DELETE` the container | 204 |
| `GET` the container | 404 |

No autocos, chaos, or node-down run.

## Apply

`POST /api/apply` was not sent. `config_sample` was not applied. Digest `d962336aac56` was not applied.

The updated inventory seals a different plan. `swift-deploy plan` on `swift-deploy-rs/bundle/config_contabo_identity/swift_hosts` and `bundle/swift.yml` produced digest `8195ef0adca513ae7c67c2966ff4aaaa11693bfb19d4efea6bf386d7abe6a9b9` (336 tasks, 2 handlers, 117 tasks with hosts). Disk-wipe, yum upgrade, sshd restart, and MariaDB/Keystone install tasks are still in the plan and have empty host lists:

- `Restart sshd`
- `Yum Upgrade`
- `Restart SSH service`
- `Change disks partition table to mbr before DD` (both `use_custom_disks` branches)
- `DD before mkfs` (both branches)
- `Format all storage nodes disks` (both branches)
- `Installing mariadb packages`
- `Install Keystone and dependencies`

This plan is not empty. `[keepalived_servers]` is empty, so it does not restate the live keepalived `timeout 4` / `fall 3`. The 117 hosted tasks include these unconditional ones, which is why apply was refused:

- `Set timezone to {{ timezone }}`
- `Restart crond`
- `Disable sshd accept locale configs`
- `Change all locale related configs into /etc/profile`
- `Change all locale related configs into /etc/bashrc`
- `Make pip conf dir`
- `Deliver pip.conf`
- `Backup repo files`
- `Turn off rpm gpgcheck`
- `Copy template repo file`
- `Remove yum lockfile`
- `Yum clean all`
- `Show yum repo list`
- `Echo repolist`
- `Install common pkgs`
- `Deliver rsyslog conf`
- `Deliver ha rsyslog conf`
- `Deliver logrotate conf`
- `Deliver rsyncd logrotate conf`
- `Check existance of haproxy logrotate conf`
- `Check existance of keepalived logrotate conf`
- `Remove rsyslog log rate limit`
- `Set rsyslog udp reception`
- `Remove systemd log rate limit`
- `Create /etc/swift/ directory`
- `Create swift user`
- `Download python-swiftclient  pkgs`
- `Rename python-swiftclient folder`
- `Install python-swiftclient`
- `Download swift pkgs`
- `Rename swift folder`
- `Install swift`
- `Copy swift systemd unit files`
- `Reload  systemctl`
- `Cleanup python-swiftclient and swift directory`
- `Pip install s3cmd`
- `Copy s3cfg files`
- `Set ak sk in s3cfg`
- `Generate uniq dir name for distribute`
- `Make uniq_dir`
- `Set uniq_dir fact`
- `Distribute ac_ring files to all hosts`
- `Distribute object_ring ring.gz to all hosts`
- `Clean uniq_dir`
- `Ensure proper permission on all nodes`
- `Disable selinux`
- `Clear SSH service bind settings`
- `Change SSH service bind settings`
- `Disable iptables and firewalld`
- `Start iptables service`
- `Backup iptables.save1`
- `Copy iptables template`
- `Import iptables rules`
- `Save iptables rules`
- `Backup iptables.save2`

`[ntp_server]` and `[ntp_clients]` still name hosts, so the chrony tasks are in the hosted set as well. Their `when` limits which host runs which file. They are not a keepalived restatement.
