# swift1 object reconstructor binary

Date: 2026-10-02. No tokens or login keys.

`swift-object-reconstructor` on swift1 was `activating` / `auto-restart` with exit `203/EXEC`. The unit file `ExecStart` is `/usr/local/bin/swift-object-reconstructor`, and that path was missing. swift2, swift3, and swift4 were already `active` / `running`. Their on-disk files and the running `/proc/<pid>/exe` hashes all matched, so the copy came from swift2.

| | |
|---|---|
| source | swift2 `/usr/local/bin/swift-object-reconstructor` (same hash on swift3 and swift4) |
| sha256 | `65dcf1881e9bc36a67c9704055c172918fd8014b02a85be3f62c7b13cda9f262` |
| size / mode | 1782864 bytes, 755 |
| restorecon | exit 0. `ls -Z` is `unconfined_u:object_r:bin_t:s0`. `matchpathcon` expects `system_u:object_r:bin_t:s0`. The type is `bin_t`. |
| unit | `active` / `running` since 2026-10-02 12:24:12 UTC. `NRestarts=0`, `ExecMainStatus=0`. Still `active` after more than 10 seconds, and the lab probe still counted it. |

The unit was stopped only long enough to install the file, then `reset-failed` and `start`. Other copies already on swift1 (under `/root/work`, `/opt/swift-deploy`, and a `.d` directory) were left in place. keepalived was not stopped. `/srv/node` was not touched.

`https://10.0.0.10:8085/info` is **200** (1270 bytes). `10.0.0.10/22` is on swift1 `eth1` and is absent on swift2, swift3, and swift4.

Lab `GET /lab/api/node/status` from swift4 `127.0.0.1:9000`:

| node | active | up |
|---|---|---|
| swift1 | 10/10 | true |
| swift2 | 10/10 | true |
| swift3 | 10/10 | true |
| swift4 | 10/10 | true |
