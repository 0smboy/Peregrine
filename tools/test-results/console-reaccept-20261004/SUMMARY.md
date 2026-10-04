# Console reaccept, 2026-10-04

**ACCEPT_WITH_WARN.** Dated 2026-10-04. The file path passed, the VIP download sha256 matched, and the bucket name is gone. `GET /lab/api/node/status` still omits hkserver. Monitor `nodes_up` is 4.0, not empty. The warn is the missing hkserver row. Create and sha256 did not fail.

Console: swift4 `127.0.0.1:9000`, cluster `contabo-swift-2026`. Disposable container `console-reaccept-20261004`, object `hello.txt`. The login key was read at runtime from swift4 `/etc/swift/proxy-server.conf` (`user_test_tester`, 64 characters, first token only). This file has no key, token, cookie, or password.

## File path

| check | result |
|---|---|
| bad key `POST /login` | 200, rejection text present, no `sc_session` |
| `POST /login` tenant `test` user `tester` | 303, `Location: /files`, session created |
| `GET /files` | 200, 196357 bytes |
| `GET /files/api/whoami` | 200, tenant `test`, user `tester`, storage `http://127.0.0.1:8080/v1/AUTH_test` |
| `POST /files/api/buckets` | 200 `{"ok":true}`. The name was not in the list beforehand (103 buckets) |
| `PUT /files/api/obj/console-reaccept-20261004/hello.txt` | 200, etag `6fe787ef97c341e51c449a2e59d700a2` |
| console `GET /files/download/.../hello.txt` | 200, 37 bytes |
| `GET https://10.0.0.10:8085/v1/AUTH_test/console-reaccept-20261004/hello.txt` | 200, 37 bytes |

Object body is the 37 bytes `hello from console-reaccept-20261004` plus a newline. sha256 `c6d5d52dfd36c62073cc0daaa92eda73d9f59d141eabed38d06e1e2ea4aca396` on both downloads.

The VIP GET used the `X-Auth-Token` from `GET http://127.0.0.1:8080/auth/v1.0` for `test:tester`. A second local auth returned the same token. `GET https://10.0.0.10:8085/auth/v1.0` returned that same token. Storage URL on both was `https://10.0.0.10:8085/v1/AUTH_test`. The token value is not recorded. The console download used the console session for that same login.

`swift-get-nodes --json /etc/swift/object.ring.gz AUTH_test console-reaccept-20261004 hello.txt` returned 0. Partition 7588. Primaries, handoff false:

| ip | port | device |
|---|---|---|
| 10.0.4.1 | 6211 | d2 |
| 10.0.4.3 | 6211 | d2 |
| 10.0.4.5 | 6211 | d2 |

Those are three nodes. `10.0.4.5` is one of them. From swift4 and from swift1, TCP to `10.0.4.5:6211` timed out, so the hkserver replica was not read back on disk during this run. The two reachable object servers later answered HEAD 404 after the object delete.

Policy 0 is `Policy-0`, default yes. Policy 1 is `ec-2-1`. This object used the default policy and `object.ring.gz`.

## Delete

The first console `DELETE` of `hello.txt` was 200. The first console `DELETE` of the bucket was 502, body `delete failed (503)`. A retry was 409, `bucket is not empty`. Proxy `DELETE` of the container was 409. Proxy `HEAD` and `GET` of the container were 404. The account prefix for the name was already empty, and the console bucket list no longer contained it, while one container primary still had a database.

Container ring primaries for the container (not the object path), partition 4060:

| ip | port | device | HEAD before repair |
|---|---|---|---|
| 10.0.4.3 | 6201 | d2 | 404 |
| 10.0.4.4 | 6201 | d2 | 204, `x-container-object-count=1`, listing `hello.txt` |
| 10.0.4.5 | 6201 | d2 | TCP timeout |

The object row on `10.0.4.4:6201` was removed with the container-server `DELETE` for that object name, then the container `DELETE` on that server returned 204. A later HEAD was 404. `10.0.4.3` stayed 404. Nothing under `/srv/node` was deleted as a file.

After that repair: VIP `HEAD` of the container 404, account prefix count 0, console bucket list does not contain the name (103 buckets).

## Files UI

Headless Chrome on this machine through `ssh -L 9000:127.0.0.1:9000 swift4`. The login form rejected a bad key (`Sign in failed` / `登录失败`, still on `/login`). A good login landed on `/files`. The new-bucket control opened and create navigated to `/files/b/console-reaccept-20261004`. Upload of `hello.txt` reported Done. The page then downloaded `/files/download/console-reaccept-20261004/hello.txt`: 200, 37 bytes, the same sha256. An earlier upload in that browser session used the filename `console-reaccept-hello.txt`; that object was deleted with the cleanup below. The tunnel and the browser profile were removed at the end.

The UI session's bucket `DELETE` was 409 and the name was still listed, because the two reachable container primaries had diverged: `10.0.4.3` still listed `console-reaccept-hello.txt`, and `10.0.4.4` still listed `hello.txt`. Each object row was deleted through that container server, then each container `DELETE` returned 204 and the following HEAD was 404. `10.0.4.5:6201` timed out again. After that, proxy `DELETE` of the container was 404, VIP `HEAD` was 404, the account prefix count was 0, both object names `GET` on the VIP were 404, and the console bucket list did not contain the name (103 buckets).

## Node status

`/etc/swift-console/config.json` `cluster_nodes` has four entries: swift1 `10.0.4.1`, swift2 `10.0.4.2`, swift3 `10.0.4.3`, swift4 `10.0.4.4`. `proxy_nodes` is `10.0.0.1` through `10.0.0.4`. hkserver is not in that roster. The config was not edited. Adding the node would be a console-config change, and the console probes `storage_ip` over SSH. TCP from swift4 and from swift1 to `10.0.4.5` ports 22, 6201, and 6211 timed out, and from swift4 to `10.0.8.5:22`, `10.0.0.5:22`, and `10.0.0.5:8080` timed out. A fifth row would not have been a reachable node. `POST /api/apply` was not sent. No node-down, chaos, or autocos.

`GET /lab/api/node/status` 200, four nodes:

| node | reachable | active | up |
|---|---|---|---|
| swift1 | true | 10/10 | true |
| swift2 | true | 10/10 | true |
| swift3 | true | 10/10 | true |
| swift4 | true | 10/10 | true |

hkserver did not appear. Reachable count 4.

`GET /monitor/api/panel?id=nodes_up` 200, `{"id":"nodes_up","kind":"stat","unit":"num","value":4.0}`. `GET /monitor/api/dash` 200, 6924 bytes. `GET /monitor/api/panel?id=svc_grid` 200, four rows, swift1–swift4, each `reachable` true.

## Cluster at the end of the checks

swift4 `/usr/local/bin/swift-proxy-server` sha256 `ce738dc3a7adb01167c16660924e79a1e215a3245d5d90bbe682d36b7cfa5696`. `https://10.0.0.10:8085/info` 200, 1668 bytes, sha256 `65ddec492e0821e66decc1aab2ca87abbacf7d6190c4b3d8e181af4abd2e3ad4`. `10.0.0.10/22` was on swift1 and absent on swift2, swift3, and swift4. swift4 `swift-proxy`, `swift-object`, `swift-container`, and `swift-account` were active. The console stayed on `127.0.0.1:9000`.
