# Phase C — swift4 root disk

Date: 2026-10-03. SSH `BatchMode`, `ControlMaster=no`, `ControlPath=none`. No partition, `dd`, or `mkfs`. `/srv/node` was not deleted. `/root/work/prod-backup-20261002` is not on swift4 (`ls` returned no such file). Keepalived and HAProxy were not restarted. VIP was not moved.

## Before (2026-10-03T06:19:29Z)

`hostname` swift4.

```
df -h /
/dev/sda4  40G  40G  939M  98% /

df -i /
/dev/sda4  Inodes 2110352  IUsed 186757  IFree 1923595  IUse% 9%
```

Use was 98%, above 95%. Inodes were not full.

## Deleted

Only regenerable logs and the dnf cache:

- `journalctl --vacuum-size=100M` freed 408.1M of archived journals.
- `dnf clean all` removed 25 cache files.

`/var/lib/loki` (21G) and `/var/lib/prometheus` (6.1G) were left in place. Free space crossed 1.3G without them.

## After (2026-10-03T06:20:31Z, two reads)

```
df -h /
/dev/sda4  40G  39G  1.5G  97% /
```

The second read, 3 seconds later, was the same 1.5G available. A third read at 06:20:31Z was still 1.5G. Free space is above 1.3G.

```
df -i /
/dev/sda4  Inodes 3152304  IUsed 186682  IFree 2965622  IUse% 6%
```

XFS reports a larger inode capacity after the free-space change. IUsed stayed about 186k.

## Cluster checks (2026-10-03T06:20:44Z–06:20:56Z)

`curl -sk https://10.0.0.10:8085/info` from swift4: HTTP 200, 1270 bytes.

| node | `10.0.0.10/22` | swift-proxy | swift-object | swift-container | swift-account |
|---|---|---|---|---|---|
| swift1 | `inet 10.0.0.10/22 scope global secondary eth1` | active | active | active | active |
| swift2 | absent | active | active | active | active |
| swift3 | absent | active | active | active | active |
| swift4 | absent | active | active | active | active |

VIP stays on swift1.
