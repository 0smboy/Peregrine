# 07. Fixes after the 2026-10-02 console acceptance FAIL

Date: 2026-10-02. No tokens, login keys, or tempurl keys are in this file.

## Account `AUTH_test`

`PUT` account does not resurrect `status=DELETED`. In `swift-account-server`, `is_status_deleted()` is true when the status column is `DELETED` or `delete_timestamp > put_timestamp`, and `put_account` answers **403 Recently deleted**. The three primary databases (partition 15623, device d2, on swift2, swift3, and swift4) had `status=DELETED`. `delete_timestamp` was already older than `put_timestamp`, so clearing the status column is enough for both `is_deleted()` and `is_status_deleted()`.

Account replicators on swift1, swift3, and swift4 were stopped first. swift2's account server was already down, so its database was edited on disk before that server started. Only those three `DELETED` databases were updated (`status` set to empty, `status_changed_at` moved forward). Other on-disk copies of the same account hash were already empty-status and were left alone. Replicators were started again only after the three primaries agreed. A later read still showed `status=''` on swift1's handoff copy and on all three primaries.

| check | before | after |
|---|---|---|
| account-server `HEAD /d2/15623/AUTH_test` on swift3 and swift4 | 404 | 204 |
| `PUT` container `console-accept-20261002` via swift4 `:8080` | 404 | 201 |
| same `PUT` via `https://10.0.0.10:8085` | 404 | 202 (already created by the local PUT) |

## Console SSH

`/etc/swift-console/config.json` already named `/root/.ssh/id_ed25519`, and that file was missing. The only key in `/root/.ssh` (`id_ed25519_g7lab_swift1`) got `Permission denied` to `10.0.4.1–4`. swift1's `/root/.ssh/id_ed25519` authenticates as root to all four storage addresses. That key was installed at the path the config already names (`ssh_home_t`, mode 600). Console was not restarted for the key alone.

Lab `/lab/api/node/status` after the key was in place: reachable **4/4**. `up` is not 4/4: swift2 is 7/10 (see below). swift1's object reconstructor was `enabled` but `inactive` with an empty journal; it was started and is `active`/`running` now.

## Deploy proxy body

`swift-console/src/proxy.rs` was dropping `Content-Length` and forwarding a chunked stream. swift-deploy reads only `Content-Length`, so `POST /api/validate` and `POST /api/plan` were **400** `EOF while parsing`. The proxy now buffers the operator body (cap 1 MiB, the upstream limit) and sets `Content-Length` to that size.

Console binary replaced on swift4 (`/usr/local/bin/swift-console`, previous hash prefix `d00406f72cc4fdc1`, now `e7e02ff1ae59f544`), `restorecon` to `bin_t`, unit restarted. `GET /` is still 303 `/login`.

| call | before | after |
|---|---|---|
| `POST /api/validate` with the state config and CSRF | 400 EOF | **202** `{"ok":true}`; job later `succeeded` (`inventory validation passed`) |
| `POST /api/plan` | 400 EOF | first try **409** `another deployment UI job is already running` (validate still running); after that job finished, **202** and the plan job `succeeded` (`sealed plan created`) |

`POST /api/apply` was not called.

## Proxy cutover

Object, container, and account binaries were copied from the running swift1 binaries onto swift2, swift3, and swift4 (backup under `/root/bin-backup-20261002-pre-cutover/`, `restorecon` `bin_t`, one node at a time). Hash prefixes now match swift1:

- object `6c3cd551c6943422`
- container `6e697697545d9ab7`
- account `f2cb830c4403febc`

The swift1 proxy binary `352da6f120d4f966` was copied the same way and `/info` matched it (1668 bytes) on swift2, swift3, and swift4. That binary then failed the file read: it treats storage policy 0 as EC (`ec=1 ndata=2` in the proxy log) and `GET` of a real object returned **200** with `Content-Length: 0` and no ETag, while the object server on `:6212` returned the 30 body bytes. Policy 0 in `/etc/swift/swift.conf` is `Policy-0` with no erasure-coding type.

The proxy was rebuilt from this repo (`cargo build --release -p swift-proxy-server --features ec` on swift1) and rolled to all four nodes. New proxy hash prefix `5cac5960c45b3a20`. `s3api` is enabled in the pipeline and is intentionally not advertised on Swift `/info` (info body 1270 bytes). A side-port check on swift1 `:18083` showed `GET` bytes matching before the production restart. VIP `https://10.0.0.10:8085/info` stayed **200** through the restarts. Old `352da6f1` binaries are kept as `swift-proxy-server.352da6f120d4f966` in the same backup directory. `/root/work/prod-backup-20261002` was not deleted.

## swift2 data plane

`swift-proxy`, `swift-object`, `swift-container`, `swift-account`, and the three replicators were `enable --now`. All of those are `active`.

Keepalived on swift2 is `state BACKUP`, `nopreempt`, priority 130. swift1 (the VIP holder) is priority 140, swift3 120, swift4 110, same VRID, no unicast peer list. Keepalived was enabled. After that, `10.0.0.10/22` was still only on swift1. It was left enabled.

Not started, because they were outside the data-plane list and are still `inactive`: `swift-object-reconstructor`, `swift-object-updater`, `swift-container-updater`. That is why Lab reports swift2 `up=false` (7/10) even though SSH reachability is true.

## swift4 root filesystem

Before: `/` 100% (~20K free) and inodes 100% (~59 free). Freed by removing regenerable `/root/work/s3-tests-venv` and `/root/work/pyswift-venv`, `dnf clean all`, `journalctl --vacuum-size=200M`, and truncating `/var/log/messages` from about 1.4G to the last 8MiB. `/srv/node`, `/etc/swift`, and `/root/work/prod-backup-20261002` were not removed (the backup directory is not on swift4).

After: about **1.3G** free and about **2.7 million** inodes free.

## File path (re-run)

Object body sha256: `6afdaa625a6d8ee0e37b7aa2032ec6d5f2e1103346ba3c900da9b0fd6877aca8`

| path | status | sha match |
|---|---|---|
| `GET` via swift4 `127.0.0.1:8080` | 200 | yes |
| `GET` via `https://10.0.0.10:8085` | 200 | yes |
| console `GET /files/download/console-accept-20261002/hello.txt` | 200 | yes |

`swift-get-nodes` primaries (not handoff): `10.0.4.4 d3`, `10.0.4.1 d3`, `10.0.4.2 d3`.

Cleanup through the API: `DELETE` object on `:8080` **204**, `DELETE` container on `:8080` **204**. The following VIP `DELETE`s were **404** because the local deletes had already removed the name. `HEAD` container **404**. Account prefix listing `[]`. Account `status` still empty. The container row remains as a deleted tombstone (`deleted=1`), which is what a successful API delete leaves. The orphan container database was not removed by hand.

## Monitor

`nodes_up` value **4.0** (was 0.0). `svc_grid`: all four nodes `reachable=true`. Inactive cells are swift1 none after the reconstructor start, and on swift2 the three units listed above.

## Left as-is

- No chaos, node-down, or autocos run.
- No git commit.
- `/info` is no longer the `352da6f1` document (s3api block omitted). Object download through the proxy did not work on that binary.

## swift2 updaters (follow-up)

Date: 2026-10-02. The three units left inactive above were started and enabled. Unit files were already at `/etc/systemd/system/`. Binaries were already `bin_t`. No ring or account-database change. VIP was not moved.

| unit | before | after |
|---|---|---|
| `swift-object-reconstructor` | inactive (dead), disabled | active (running), enabled |
| `swift-object-updater` | inactive (dead), disabled | active (running), enabled |
| `swift-container-updater` | inactive (dead), disabled | active (running), enabled |

`https://10.0.0.10:8085/info` is **200** (1270 bytes). `10.0.0.10/22` is on swift1 `eth1`. It is absent on swift2. keepalived stays active on both.

Lab `GET /lab/api/node/status` from swift4 `127.0.0.1:9000` (session via `user_test_tester` in `proxy-server.conf`; key not recorded):

| node | active | up |
|---|---|---|
| swift1 | 9/10 | false |
| swift2 | 10/10 | true |
| swift3 | 10/10 | true |
| swift4 | 10/10 | true |

swift2 matches swift3 and swift4. The unit that still differs is swift1 `swift-object-reconstructor`: `activating` / `auto-restart`, exit `203/EXEC`, journal `Failed to locate executable /usr/local/bin/swift-object-reconstructor`. That binary is not on swift1. It was not copied in this follow-up.
