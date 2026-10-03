# 10. Shadow peer login

Date: 2026-10-02. Cluster contabo-swift-2026. Console `swift4` `127.0.0.1:9000`. VIP `https://10.0.0.10:8085`. No tokens, login keys, or passwords are in this file.

`09-remaining.md` had one FAIL: `POST /lab/api/shadow/run` was 502 because `http://10.0.0.3:8090` rejected the console session with 401. This file is that item, re-run after the console was pointed at the peer's existing account.

## Cause

`swift-console` logs the shadow peer in with the signed-in session unless `shadow_peer_user` and `shadow_peer_key` are set (`swift-console/src/shadow.rs`, `peer_login`). The live config on swift4 had `shadow_peer_base` `http://10.0.0.3:8090` and `shadow_peer_auth` `http://10.0.0.3:8090/auth/v1.0`, and no peer user or key. The session is tenant `test`, user `tester`, key read from swift4 `proxy-server.conf` (`user_test_tester`, 64 characters).

The process on `10.0.0.3:8090` is `pyswift-proxy` (`/etc/pyswift/proxy-server.conf`). Its `[filter:tempauth]` already has `user_test_tester`. That account's own key is 22 characters. Logging in to the peer with that existing account returned 200 and storage path `/v1/AUTH_test`. The 64-character cluster key and the 22-character peer key are not the same value. The peer was not given a new account, and its auth file was not edited.

## Change

Console config on swift4 now sets `shadow_peer_tenant` `test`, `shadow_peer_user` `tester`, and `shadow_peer_key` to the peer's existing key. That key is not the console `test_key` (still 64 characters). `shadow_peer_base` is unchanged.

`peer_login` uses that configured account when both user and key are non-empty, and otherwise keeps the session. Unit tests `peer_login_uses_the_configured_account`, `peer_login_keeps_the_session_when_unset`, and `peer_login_ignores_a_user_without_a_key` passed on swift1 (`cargo test peer_login`, 3 passed).

Release binary built on swift1 and installed at `/usr/local/bin/swift-console` on swift4. sha256 prefix `7bf985c5695a1ad1`. Previous binary kept at `/root/swift-console.bin-20261002`. `restorecon` left the new file `bin_t`. `systemctl restart swift-console` only. `GET /` is 303. Prod proxy `:8080`, rings, and `/srv/node` were not touched. `pyswift-proxy` was not restarted.

## Shadow run

Login: `POST /login` tenant `test`, user `tester`, key from swift4 `proxy-server.conf` at runtime. Status 303, session cookie set.

| id | method | status | verdict |
|---|---|---|---|
| shadow run | `POST /lab/api/shadow/run` `Accept: application/json` | 200 | PASS. Finished in 19.2s. `run` `r1790948703-8e3c36`, `mode` `dual`, `cases` 31, `breaking` 2, `semantic` 24, `cosmetic` 0, `peer` true, `error` null |
| corpus | `GET /lab/api/shadow/corpus` | 200 | PASS. 31 records, 1 run, same id |
| mutate | not called | n/a | not called |

The 31 case counts are the diff the tool recorded after both sides answered. They are not a 502 and not a login failure.

## Cleanup and cluster

| id | method | status | verdict |
|---|---|---|---|
| console delete | `DELETE /files/api/bucket/shadow-probe?force=1` and `shadow-probe-empty` | 502 `bucket not found` | PASS. Teardown inside the run had already removed them |
| console list | `GET /files/api/buckets` | 200 | PASS. 79 buckets. None named `shadow-probe*` |
| peer list | `GET` account listing on `http://10.0.0.3:8090` as the existing `test:tester` | 200 | PASS. 565 containers. None with `shadow` in the name |
| nodes | `GET /lab/api/node/status` | 200 | PASS. swift1–4 each 10/10, up true, reachable, not held down |
| vip holder | `ip -4 addr` on swift1–4 | n/a | PASS. `10.0.0.10/22` on swift1 only |
| vip info | `GET https://10.0.0.10:8085/info` | 200 | PASS. 1270 bytes |

`POST /lab/api/shadow/mutate`, `POST /api/apply`, node-down, and chaos were not called.

## Verdict

`09-remaining.md` has no FAIL other than the shadow 502 this file replaces. Overall: **ACCEPT**.

## Left in place

- swift4 `/etc/swift-console/config.json` peer account fields, as above. The peer key is not written here.
- Console binary prefix `7bf985c5695a1ad1`, backup `/root/swift-console.bin-20261002`.
- Build tree `/root/work/swift-console-shadowfix` on swift1.
- Source change in `swift-console/src/shadow.rs`. No git commit.
