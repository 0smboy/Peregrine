# Phase F — VIP restore

Date: 2026-10-03. Host journal times below are UTC (they match the 13:49:37 UTC timeout). No keepalived config change. No production binary change. `POST /api/apply` was not sent.

## Before

| node | eth1 | keepalived | VIP `10.0.0.10/22` | configured priority |
|---|---|---|---|---|
| swift1 | `10.0.0.1/22`, MAC `bc:24:11:23:34:c9` | active, pid 1588818, state BACKUP | absent | 140, `nopreempt` |
| swift2 | `10.0.0.2/22`, MAC `bc:24:11:64:ab:9e` | active, pid 656963, MASTER since 13:49:32 | present | 130, `nopreempt` |
| swift3 | `10.0.0.3/22`, MAC `bc:24:11:9d:49:28` | active | absent | 120, `nopreempt` |
| swift4 | `10.0.0.4/22`, MAC `bc:24:11:52:cd:0b` | active | absent | 110, `nopreempt` |

All four use VRID 51 on `eth1`, `advert_int 1`, and `vrrp_script chk_http_port` with `interval 1`, `weight -10`, and no `timeout` key. Keepalived is v2.2.8. The script is `/etc/keepalived/check_haproxy.sh`. It counts `haproxy` processes. It does not connect to `:18080`, `:8080`, or `:8085`. If the count is zero it starts haproxy and stops keepalived. The script was left as it was.

From swift1, before the restore, `ip route get 10.0.0.10` was on-link `dev eth1 src 10.0.0.1`, not local. The neighbor was `bc:24:11:64:ab:9e`, which is swift2. `http://10.0.0.10:8080/healthcheck` and `https://10.0.0.10:8085/info` returned 200 because swift2 owned the address and answered. That was not a local bind on swift1. swift1 was already listening on `0.0.0.0:8080` and `0.0.0.0:8085`, but `10.0.0.10` was not a local address, so the packet left via eth1.

Production `/usr/local/bin/swift-proxy-server` was sha256 `5cac5960c45b3a206a794e0a0c52d89f51c251b0ce698de21f245da7fa6a2397`, pid 3495932, started Fri Oct 2 12:16:43 2026. `http://127.0.0.1:8080/healthcheck` was 200. haproxy was active. The check script exited 0. Load average was 3.82, 3.58, 6.03.

## Why the address left swift1

At 13:49:17–13:49:37 swift1 logged that `chk_http_port` was already running, that thread timers had expired (1.5s, then 2.4s, then 12.886870s), and then:

```
Oct 03 13:49:37 swift1 Keepalived_vrrp[1588818]: VRRP_Script(chk_http_port) timed_out
Oct 03 13:49:37 swift1 Keepalived_vrrp[1588818]: (swift) Changing effective priority from 140 to 130
Oct 03 13:49:37 swift1 Keepalived_vrrp[1588818]: (swift) Master received advert from 10.0.0.2 with same priority 130 but higher IP address than ours
Oct 03 13:49:37 swift1 Keepalived_vrrp[1588818]: (swift) Entering BACKUP STATE
Oct 03 13:49:37 swift1 Keepalived_vrrp[1588818]: (swift) removing VIPs.
```

With `timeout` unset, v2.2.8 uses the interval (1 second). The G7 lab load on this host stalled keepalived’s own timers and the `ps` check did not return inside that second. `weight -10` dropped swift1 from 140 to 130, tying swift2. The higher IP (`10.0.0.2`) won. At 13:49:41 the script succeeded and the effective priority returned to 140. `nopreempt` left swift1 in BACKUP, so swift2 kept the address. swift2’s journal shows MASTER at 13:49:27, BACKUP at 13:49:28, and MASTER again at 13:49:32 (`setting VIPs`). It still held `10.0.0.10/22` at 15:55 UTC.

An earlier timeout at 10:49:41 dropped and restored priority without this BACKUP transition. The 13:49:37 transition is the one that stuck.

## Restore

Restarting keepalived on swift1 while swift2 was still MASTER would not take the address back: swift1’s config is `state BACKUP` with `nopreempt`. swift3 and swift4 were already without the address.

At 15:56:21 UTC, `systemctl stop keepalived` on swift2 only. swift2 sent priority 0 and removed `10.0.0.10`. swift1’s existing process (pid 1588818) logged:

```
Oct 03 15:56:21 swift1 Keepalived_vrrp[1588818]: (swift) Backup received priority 0 advertisement
Oct 03 15:56:22 swift1 Keepalived_vrrp[1588818]: (swift) Receive advertisement timeout
Oct 03 15:56:22 swift1 Keepalived_vrrp[1588818]: (swift) Entering MASTER STATE
Oct 03 15:56:22 swift1 Keepalived_vrrp[1588818]: (swift) setting VIPs.
```

swift3 and swift4 logged `Backup received priority 0 advertisement` and did not install the address. keepalived on swift1 was not restarted. A restart after it was already the only master would have dropped the address and opened another election.

At 15:57:08 UTC, `systemctl start keepalived` on swift2. It logged `Entering BACKUP STATE (init)` and did not install `10.0.0.10`.

## After

| node | eth1 | keepalived | VIP `10.0.0.10/22` |
|---|---|---|---|
| swift1 | `10.0.0.1/22` and `10.0.0.10/22` | active, MASTER since 15:56:22, same pid 1588818 | present, exactly one owner |
| swift2 | `10.0.0.2/22` | active since 15:57:08, BACKUP (init), pid 2521490 | absent |
| swift3 | `10.0.0.3/22` | active | absent |
| swift4 | `10.0.0.4/22` | active | absent |

From swift1 after the restore, `ip route get 10.0.0.10` is `local 10.0.0.10 dev lo`. `ss` shows `0.0.0.0:8080` and `0.0.0.0:8085` listening. `https://10.0.0.10:8085/info` is HTTP/2 200, `content-length: 1270`. `http://10.0.0.10:8080/healthcheck` is 200.

Production `/usr/local/bin/swift-proxy-server` is still sha256 `5cac5960c45b3a206a794e0a0c52d89f51c251b0ce698de21f245da7fa6a2397`, pid 3495932, started Fri Oct 2 12:16:43 2026.

## Script timeout

Date: 2026-10-03, after the restore above. Keepalived v2.2.8 on all four. Each node has one file, `/etc/keepalived/keepalived.conf`. No include. The check command stayed `/etc/keepalived/check_haproxy.sh`. Priority, `virtual_router_id` 51, `nopreempt`, `advert_int`, `weight -10`, `interval 1`, and authentication were not changed. `track_script` stayed `chk_http_port`. Nothing was pointed at `:18080`.

Before the edit, `10.0.0.10/22` was only on swift1 `eth1`. swift2, swift3, and swift4 did not have it. The script block was the same on all four:

```
vrrp_script chk_http_port {

     script   "/etc/keepalived/check_haproxy.sh"

    interval 1
    weight -10
}
```

v2.2.8's `vrrp_script` block uses `timeout <INTEGER>` for the seconds after which the script is considered failed, and `fall <INTEGER>` for how many failures are required before the KO transition. With `timeout` unset, this build uses the interval. The compiled defaults are `rise 1` and `fall 1`, so one timeout applies `weight -10`. That is the 13:49:37 UTC demotion.

`timeout 4` and `fall 3` were inserted in that script block on each node. `rise` was left at its default of 1. A `ps` that returns within 4 seconds does not fail the check. Three consecutive failures are required before the weight is applied. `keepalived -t` exits 6 with the same pre-existing message on the old and new files: `SECURITY VIOLATION - scripts are being executed but script_security not enabled.` The running process accepted the file.

Reload was `systemctl reload` (`kill -HUP` on the existing main pid), backups first. Parent and VRRP child pids did not change.

| UTC | node | reload result | `10.0.0.10/22` |
|---|---|---|---|
| 16:16:03 | swift4 | same pids 3859021 / 3859027, stayed BACKUP | still only on swift1 |
| 16:19:03 | swift3 | same pids 4035440 / 4035441, stayed BACKUP | still only on swift1 |
| 16:20:04 | swift2 | same pids 2521489 / 2521490, stayed BACKUP | still only on swift1. A 0.2s watch on swift1 saw no absence |
| 16:22:38 | swift1 | same pids 1588805 / 1588818. Logged `setting VIPs` and did not enter BACKUP | stayed on swift1. A 0.1s watch saw no absence |

The backup reloads logged `(swift) removing VIPs` under `--log-detail`. The address was not on those nodes before or after, and swift1's journal stayed empty through those three reloads. swift1's own reload logged `(swift) setting VIPs` and kept the address.

After, the script block is the same on all four:

```
vrrp_script chk_http_port {

     script   "/etc/keepalived/check_haproxy.sh"

    interval 1
    timeout 4
    fall 3
    weight -10
}
```

A `SIGUSR1` data dump of each VRRP child, then deleted, showed:

| node | state | priority | effective | timeout | fall | rise | result | status |
|---|---|---|---|---|---|---|---|---|
| swift1 | MASTER | 140 | 140 | 4 sec | 3 | 1 | 3 | GOOD |
| swift2 | BACKUP | 130 | 130 | 4 sec | 3 | 1 | 3 | GOOD |
| swift3 | BACKUP | 120 | 120 | 4 sec | 3 | 1 | 3 | GOOD |
| swift4 | BACKUP | 110 | 110 | 4 sec | 3 | 1 | 3 | GOOD |

`10.0.0.10/22` is only on swift1. `ip route get 10.0.0.10` from swift1 is `local 10.0.0.10 dev lo`. `https://10.0.0.10:8085/info` is HTTP/2 200. Production pid 3495932 is still the process started Fri Oct 2 12:16:43 2026, and `/usr/local/bin/swift-proxy-server` is still sha256 `5cac5960c45b3a206a794e0a0c52d89f51c251b0ce698de21f245da7fa6a2397`.

The live file is not in git. `swift-deploy-rs` only has the Jinja templates `bundle/roles/keepalived_servers/templates/keepalived.conf.j2` and `bundle-rust/roles/rust_keepalived/templates/keepalived.conf.j2`. Those templates still omit `timeout` and `fall`. A later render from them would drop this change. Each node kept the previous file at `/etc/keepalived/keepalived.conf.bak-20261003-flap`.
