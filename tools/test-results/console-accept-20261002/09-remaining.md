# 09. Remaining console acceptance

Date: 2026-10-02. Cluster contabo-swift-2026. Console `swift4` `127.0.0.1:9000`. VIP `https://10.0.0.10:8085`. No tokens, login keys, or passwords are in this file.

Object body is the 25 bytes `console-accept-20261002b\n`. sha256 `825b63d079b5eefb45b760fd3624cb591fca54983dda793d1d32b21c079157ac`.

Account create did not 404, so the DELETED-tombstone repair from `07-fix.md` was not repeated. Lab ports `:18080` and `:18082` were not used. `POST /api/apply` was not called. `/srv/node` was not removed. The VIP was not moved.

Overall: **ACCEPT_WITH_WARN**. The file path and the HA recovery passed. Shadow failed because the peer rejected login, and that item was stopped there.

## 1. File path

| id | method | status | verdict |
|---|---|---|---|
| login | `POST /login` tenant `test`, user `tester`, key read from swift4 `proxy-server.conf` at runtime | 200 | PASS. Session cookie set |
| create | `POST /files/api/buckets` `console-accept-20261002b` | 200 | PASS. `{"ok":true}` |
| put | `PUT /files/api/obj/console-accept-20261002b/hello.txt` | 200 | PASS. etag `9f89ef51ccf8c2fe489c17c61dfb9f91` |
| console get | `GET /files/download/console-accept-20261002b/hello.txt` | 200 | PASS. 25 bytes, sha256 matches |
| vip get | `GET https://10.0.0.10:8085/v1/AUTH_test/console-accept-20261002b/hello.txt` | 200 | PASS. 25 bytes, sha256 matches |
| replicas | `swift-get-nodes --json /etc/swift/object.ring.gz AUTH_test console-accept-20261002b hello.txt` | 0 | PASS. Primaries on three nodes: `10.0.4.2 d3`, `10.0.4.3 d3`, `10.0.4.4 d3`. Partition 10071 |

## 2. Lab paths while the object existed

Genome evolve and the policy compare success path were already PASS in `03-monitor-deploy-lab.md` (`L-genome-evolve` 200, `L-genome-result` 200, `L-pol-compare` 200 with `raw_tb` 1). They were not run again.

| id | method | status | verdict |
|---|---|---|---|
| capsule page | `GET /lab/capsule/AUTH_test/console-accept-20261002b/hello.txt` | 200 | PASS. 12047 bytes, object name present |
| capsule api | `GET /lab/api/capsule` with that account, container, object | 200 | PASS. `present` 3, read status 200, read bytes 25 |
| tombstone page | `GET /lab/tombstone/AUTH_test/console-accept-20261002b/hello.txt` | 200 | PASS. 9514 bytes, object name present |
| tombstone api | `GET /lab/api/tombstone` with the same path | 200 | PASS. Report keys include primaries, files, events. `error` is null |
| warehouse sample | `GET /lab/api/warehouse/sample?object=console-accept-20261002b/hello.txt` | 200 | PASS. `ok` true, 25 of 25 bytes, sample is the object text. Promote was not called |
| profilemap pulse | `POST /lab/api/profilemap/pulse` `{"n":1,"bytes":64}` | 200 | PASS. `puts` 1 |
| profilemap delete | `DELETE /files/api/bucket/lab-profilemap?force=1` | 200 | PASS. 1 object removed |
| expired run | `POST /lab/api/expired/run` `{"n":1,"base_ttl_secs":10,"step_secs":1}` | 200 | PASS. id `e6abfad09`, container `lab-expired-e6abfad09`, count alive 1 |
| expired status | `GET /lab/api/expired/status` | 200 | PASS. shown id `e6abfad09` |
| expired delete | `DELETE` that container with `force=1` | 200 | PASS |
| shadow peer | `GET http://10.0.0.3:8090/info` | 200 | PASS. Peer is up |
| shadow run | `POST /lab/api/shadow/run` | 502 | FAIL. `second endpoint refused the login: auth rejected (401)`. The run writes only inside `shadow-probe` and `shadow-probe-empty`, which it creates and deletes, so it was called. The peer error stopped the item. `POST /lab/api/shadow/mutate` was not called |
| genome | not called | n/a | PASS. Already recorded in 03 |
| policy compare | not called | n/a | PASS. Success path already recorded in 03. The 422 was only the empty-body check |

## 3. Chaos

`GET /lab/api/chaos/catalogue` 200, `armed` true. Policies: Policy-0 replication, ec-2-1 erasure coding. Each fault was `POST /lab/api/chaos/run` with deadline 60, then polled `/lab/api/chaos/status` until the phase was done, then `POST /lab/api/chaos/recover`. The tool's arena is `chaos-arcade` (policy 1: `chaos-arcade-p1`), not `hello.txt`. After each recover, VIP GET of `hello.txt` still matched the original sha256. `drop_durable` was sent with policy 1 because policy 0 has no durability marker.

| fault | start | status | recover | VIP sha |
|---|---|---|---|---|
| drop_copy | 200 run `4304bb60aaae` policy 0 | 200 phase done, elapsed 65s, last sample copies 2/3 | 200 undone 0, failed [] | PASS match |
| corrupt_copy | 200 run `9b98abe1e49f` policy 0 | 200 phase done, elapsed 66s, last sample copies 2/3 | 200 undone 0, failed [] | PASS match |
| drop_durable | 200 run `d023b0a8cdb5` policy 1 | 200 phase done, elapsed 35s, copies 3/3 | 200 undone 0, failed [] | PASS match |
| stale_timestamp | 200 run `2a148f4d8705` policy 0 | 200 phase done, elapsed 65s, last sample copies 2/3 | 200 undone 0, failed [] | PASS match |

None stuck. Bytes of `hello.txt` did not change, so the sequence was not stopped early. Recover found nothing still outstanding because each experiment undoes its own journal entry before the phase becomes done.

## 4. HA

Before the drill, `GET /lab/api/node/status` was 200 and all four nodes were reachable, up, 10/10. VIP holders: swift1 only. `GET /info` 200, 1270 bytes.

`POST /lab/api/node/down` `{"node":"swift3","ttl_secs":90}` 200. Journal `fa2f0fda3ec20703`. Status then showed swift3 active 0/10, up false, held_down true. Immediate VIP GET of `hello.txt` was 200 and the sha256 matched.

`POST /lab/api/node/up` `{"node":"swift3"}` 200, `restarted` true. Status then showed swift3 10/10, up true. TTL was not used as the recovery. VIP stayed on swift1. `/info` stayed 200. swift1 and swift4 were not stopped.

## 5. Autocos

`test_enabled` was true. `GET /test/api/export.csv` header, before and after the successful run: `finished,size,operation,workers,operations,bytes,avg_response_ms,avg_process_ms,throughput_ops,bandwidth_bytes,success_pct`.

| attempt | what happened | status | verdict |
|---|---|---|---|
| first `POST /test/api/run` `4KB` write, workers 1, objects 2, runtime 5 | API 200 `task=4KB_write_1`, then no new CSV. Direct run of the same command returned `swift v1 auth failed HTTP 401`. Console `test_key` was 22 characters and auth against `http://127.0.0.1:8080/auth/v1.0` was 401. The live `user_test_tester` key in `proxy-server.conf` is 64 characters and the same auth was 200. The two values were not equal | 401 on the benchmark auth | fixed, then retried. `test_key` in `/etc/swift-console/config.json` was replaced with the live proxy key. Console restarted. The key is not recorded here |
| second | New row `w503-4KB-write-1-2026-10-02-13:23:01.csv`: 524 ops, 0 bytes, success 0.00. No container appeared. Auth now returned storage URL `https://10.0.0.10:8085/v1/AUTH_test`. `curl` to that URL without `-k` exits 60, self-signed certificate. Proxy journals for that window show auth and account GET/HEAD only, no PUT | n/a | fixed, then retried. Drop-in `/etc/systemd/system/swift-console.service.d/autocos-endpoint.conf` sets `ST_ENDPOINT=http://127.0.0.1:8080/v1/AUTH_test`. Console restarted. Page defaults (8 workers / 500 objects) were not used |
| third | `w504-4KB-write-1-2026-10-02-13:25:46.csv`: 11 ops, success 100.00. Container `autocos9122519e1` | 200 | PASS |
| delete | `DELETE /files/api/bucket/autocos9122519e1?force=1` | 200 | PASS. 2 objects removed |

## 6. Cleanup

| id | method | status | verdict |
|---|---|---|---|
| object | `DELETE /files/api/obj/console-accept-20261002b/hello.txt` | 200 | PASS |
| container | `DELETE /files/api/bucket/console-accept-20261002b?force=1` | 200 | PASS |
| arenas | `DELETE` `chaos-arcade` and `chaos-arcade-p1` with `force=1` | 200 | PASS. 1 object each |
| list | `GET /files/api/buckets` | 200 | PASS. 79 buckets. None named `console-accept-20261002b`, `lab-profilemap`, `lab-expired-*`, `autocos*`, `chaos-arcade*`, or `shadow-probe*` |
| nodes | `GET /lab/api/node/status` | 200 | PASS. swift1–4 each 10/10, up true, not held down |
| vip | holders plus `GET /info` | 200 | PASS. Only swift1 holds `10.0.0.10/22`. Body 1270 bytes |

## Left in place

- Console `test_key` now matches the live proxy user. The previous 22-character value did not authenticate.
- systemd drop-in `autocos-endpoint.conf` so console-launched autocos uses the local HTTP proxy instead of the self-signed VIP URL.
- No git commit.
