# 11. Browser recheck and swift4 root disk

Date: 2026-10-02. Console on swift4 `127.0.0.1:9000`, reached from this machine with `ssh -L 9000:127.0.0.1:9000 swift4`. Headless Chrome submitted the login form and clicked the Files controls. The login key was read from swift4 `proxy-server.conf` (`user_test_tester`) at runtime and was not written here. No `POST /api/apply`. No shadow mutate. `/srv/node` was not touched. The VIP was not moved. The tunnel and the browser profile were removed at the end.

Overall for this file: **PASS**. The Files path, Monitor, and Deploy checks below passed. The root filesystem was already past the stop line, so nothing on it was deleted.

## Browser file path

The first driver click on New bucket happened before `/static/console.js` had bound the button, so the dialog did not open and no bucket was created. That was the driver. The retry waited until the page script was bound, then used the same controls. No console code change.

Object body is the 23 bytes `console-accept-browser\n`. sha256 `081003cd18937992c8253c3b7bdf7f6d816100dad4ece56e386c16dfd4295e2f`.

| id | what the browser did | status | verdict |
|---|---|---|---|
| login | Submit the login form, tenant `test`, user `tester` | next document `GET /files` 200 | PASS |
| create | Click New bucket, type `console-accept-browser`, click Create | `POST /files/api/buckets` 200, then `GET /files/b/console-accept-browser` 200 | PASS |
| upload | Open Upload, set `hello.txt` on `#up-input`, click Start | `PUT /files/api/obj/console-accept-browser/hello.txt` 200, row status `Done` | PASS |
| download | Click the row's download link | `GET /files/download/console-accept-browser/hello.txt` 200, saved `hello.txt`, 23 bytes, sha256 matches | PASS |
| share | Click Share, click Generate link | `POST /files/api/tempurl` 200. URL host `127.0.0.1:8080`, path `/v1/AUTH_test/console-accept-browser/hello.txt`, both tempurl query params present. Fetch from swift4: 200, 23 bytes, sha256 matches | PASS |
| delete object | Click the row delete control and accept the confirm | dialog `Permanently delete "hello.txt"?`. `DELETE /files/api/obj/console-accept-browser/hello.txt` 200. Row gone | PASS |
| delete bucket | On `/files`, reveal the row, click delete, accept the confirm | dialog asked before a force delete. `DELETE /files/api/bucket/console-accept-browser` 200. Name absent from the table and the sidebar | PASS |

After that, a local-proxy check on swift4 (key not recorded): account listing `container_count` 79, `console-accept-browser` not present, `console-accept-browser_segments` not present, `HEAD` of the container **404**.

## Monitor and Deploy

| id | what the browser did | status | verdict |
|---|---|---|---|
| nodes up | Open `/monitor` and read the Nodes up tile | displayed `4`. `GET /monitor/api/panel?id=nodes_up` 200 | PASS |
| storage nodes | Click the Storage nodes tab | tab became active. Node buttons: All, swift1, swift2, swift3, swift4 (4 nodes). Panel requests returned 200 | PASS |
| refresh | Click Refresh | further `/monitor/api/panel` requests returned 200 | PASS. Not a dead control |
| deploy | Open `/deploy`. Do not click Execute sealed plan | iframe document loaded. `GET /api/state` 200. Apply control present. `POST /api/apply` count 0 | PASS |

## swift4 root filesystem

Checked before deciding whether to delete anything, and again at the end. Both readings are already a few hundred MB free and millions of free inodes, so journal vacuum, package caches, and `/root/work` were left alone. `/srv/node`, `/etc/swift`, and `/root/work/prod-backup-20261002` were not removed.

| | size | used | avail | use% | inodes | iused | ifree | iuse% |
|---|---|---|---|---|---|---|---|---|
| start | 40G | 39G | 1.3G (`1370288128` bytes) | 97% | 2864168 | 186322 | 2677846 | 7% |
| end | 40G | 39G | 1.3G (`1368436736` bytes) | 97% | 2860056 | 186327 | 2673729 | 7% |

Mount: `/dev/sda4` on `/`.

## Cluster after the pass

| check | result | verdict |
|---|---|---|
| `https://10.0.0.10:8085/info` from swift4 | 200, 1270 bytes | PASS |
| VIP address | `10.0.0.10/22` on swift1 only. Absent on swift2, swift3, swift4 | PASS |
| swift1–4 units | `swift-proxy`, `swift-object`, `swift-container`, `swift-account`, the three replicators, `swift-object-reconstructor`, `swift-object-updater`, `swift-container-updater`: all `active` | PASS |
| test bucket | gone from the Files list and from the account listing. HEAD 404 | PASS |

This machine has no route to `10.0.0.10` (`curl` exited before a status). The `/info` check above is the one from swift4.
