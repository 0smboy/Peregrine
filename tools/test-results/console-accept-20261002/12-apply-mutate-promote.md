# 12. Shadow mutate, warehouse promote, deploy apply

Date: 2026-10-02. Cluster contabo-swift-2026. Console `swift4` `127.0.0.1:9000`. VIP `https://10.0.0.10:8085`. No tokens, login keys, or passwords are in this file.

Login: `POST /login` tenant `test`, user `tester`, key read from swift4 `proxy-server.conf` (`user_test_tester`, 64 characters) at runtime. Status **303**, location `/files`, session cookie set. The key was not written down.

`/srv/node` was not removed. Ring files, device lists, and Keepalived ownership were not edited.

## 1. Shadow mutate

`POST /lab/api/shadow/mutate` does not take a run id. The body is optional JSON; `seed` defaults to 839245. The earlier run `r1790948703-8e3c36` is still in `/var/lib/swift-console/shadow/corpus.jsonl`. `POST /lab/api/shadow/run` was not repeated.

| id | method | status | verdict |
|---|---|---|---|
| mutate | `POST /lab/api/shadow/mutate` `{"seed":839245}` `Accept: application/json` | 200 | PASS. Run `m839245-3cd595`, seed 839245, peer true, diverged false, class `identical`. 8 steps. Both sides: 201, 202, 206, 202, 201, 202, 202, 200. `error` null |
| corpus | file still contains `r1790948703-8e3c36` and `m839245-3cd595` | n/a | recorded. `mutations.jsonl` last row is this mutation |

The handler's `setup` creates `shadow-probe` and `shadow-probe-empty` on the console account and on the peer `http://10.0.0.3:8090`. Mutate does not tear them down.

| id | method | status | verdict |
|---|---|---|---|
| console `shadow-probe` | `DELETE /files/api/bucket/shadow-probe?force=1` | 200 | PASS. `objects_removed` 4 |
| console `shadow-probe-empty` | `DELETE /files/api/bucket/shadow-probe-empty?force=1` | 200 | PASS. `objects_removed` 0 |
| console list | `GET /files/api/buckets` | 200 | PASS. 79 buckets. No name containing `shadow` |
| peer objects | `DELETE` of the 4 objects in `shadow-probe` on `10.0.0.3:8090` | 204 | PASS |
| peer containers | `DELETE` `shadow-probe` and `shadow-probe-empty` | 204 | PASS. Following `HEAD` is 404. `shadow-probe-absent` was already 404 |

## 2. Warehouse promote

`POST /lab/api/warehouse/promote` copies `jobs/<job>/working/<name>` to `jobs/<job>/artifacts/<dest_name>`. `POST /lab/api/warehouse/job` only writes the layout and `inputs/`, so a working file has to exist first. That write is `POST /mcp` tool `result_write` (there is no separate HTTP route for it).

Before this call, `GET /lab/api/warehouse/jobs` was 200, `exists` false, `total_objects` 0, no jobs. Account `test` / user `tester`.

| id | method | status | verdict |
|---|---|---|---|
| create | `POST /lab/api/warehouse/job` goal `console accept disposable promote`, input `note.txt` body `ok\n`, ttl 120 | 200 | PASS. Job `job-1790954920-93ef44`, container `warehouse`, `container_status` 201 (this call created it), input etag `eff5bc1ef8ec9d03e640fc4370f5eacd`, 3 bytes |
| working file | `POST /mcp` `result_write` name `note.txt` | 200 | PASS. Object status 201, path `jobs/job-1790954920-93ef44/working/note.txt`, expiry read back |
| promote | `POST /lab/api/warehouse/promote` `job`, `name` `note.txt`, `dest_name` `note.txt` | 200 | PASS. Artifact `jobs/job-1790954920-93ef44/artifacts/note.txt`, object status 200, `copy_mode` `server-side copy`, `bytes_moved_through_console` 0, `etag_match` true, same etag as the source. Lineage record `jobs/job-1790954920-93ef44/report/lineage.json`, 1 entry |

Cleanup, only names under `jobs/job-1790954920-93ef44/`:

| id | method | status | verdict |
|---|---|---|---|
| nine objects | `DELETE /files/api/obj/warehouse/...` for the input, working file, artifact, manifest, lineage, and four directory markers | 200 each | PASS. Recount `files` 0 |
| container | `DELETE /files/api/bucket/warehouse?force=1` | 200 | PASS. `objects_removed` 0. The container did not exist before this job. After the job objects were gone it was empty, so it was removed. A later list is 502 `bucket not found` |
| account list | `GET /files/api/buckets` | 200 | PASS. 79 buckets. `warehouse` is absent |

No other container was deleted.

## 3. Deploy apply

The Deploy UI on swift4 is `swift-deploy ui` with `--bundle /opt/swift-deploy/bundle`. `GET /api/state` was **200**. The config already stored there, and the config `POST /api/validate` and `POST /api/plan` accepted in `07-fix.md`, is:

- bundle `/opt/swift-deploy/bundle`
- inventory `bundle/config_sample/swift_hosts`
- playbook `bundle/swift.yml`
- plan `swift-plan.json`
- known_hosts empty

That is the sample inventory, not a contabo host list. No other inventory on swift4 describes swift1–4.

| id | method | status | verdict |
|---|---|---|---|
| state | `GET /api/state` | 200 | recorded. Previous job was plan `succeeded` |
| plan | `POST /api/plan` with that config, `Content-Type: application/json`, CSRF header taken from `/deploy/` at runtime (64 characters, not recorded) | 202 `{"ok":true,"id":3}` | job then `succeeded`, message `sealed plan created` |
| apply | `POST /api/apply` | not called | FAIL |

The sealed plan at `/opt/swift-deploy/swift-plan.json` (digest length 64, prefix `35bcf3bcdd33`):

- hosts `192.168.2.51` and `192.168.2.52`, not swift1–4
- 336 tasks, 2 handlers
- risks `disk_wipe`, `firewall`, `ssh_reconfigure`, `host_reconfigure`
- `disk_wipe` tasks include `DD before mkfs` and `Format all storage nodes disks` (mkfs), twice: one path when `use_custom_disks` is false and one when it is true, so one of those format paths is live
- `/srv/node` appears in the format role's mount tasks for those two sample hosts
- keepalived tasks in this plan have an empty host list

`POST /api/apply` was not sent. The diff is not empty, not a no-op, and not a restart of the existing swift1–4 stack. Applying it would format disks. Risk acknowledgements were not sent, and `allow_disk_wipe` was not set.

## Cluster after these calls

| id | check | result | verdict |
|---|---|---|---|
| vip address | `ip -4 addr` on swift1–4 | `10.0.0.10/22` on swift1 only. Absent on swift2, swift3, swift4 | PASS |
| vip info | `GET https://10.0.0.10:8085/info` from swift1 | 200, 1270 bytes | PASS |
| units | `systemctl is-active` on swift1–4 | `swift-proxy`, `swift-object`, `swift-container`, `swift-account` are `active` on all four | PASS |

Keepalived is `active` on all four nodes. The VIP address is only on swift1.

## Verdict

| step | verdict |
|---|---|
| shadow mutate | PASS |
| warehouse promote | PASS |
| deploy apply | FAIL. Plan 202, apply not called, sealed plan would format disks |

Overall: **ACCEPT_WITH_WARN**. The warning is deploy apply.

## Left in place

- Sealed sample plan `/opt/swift-deploy/swift-plan.json` on swift4 (written by `POST /api/plan`). It was not executed.
- Shadow corpus and `mutations.jsonl` gained the mutation row. No shadow containers remain.
- No warehouse container remains. No container from this run was left behind.
