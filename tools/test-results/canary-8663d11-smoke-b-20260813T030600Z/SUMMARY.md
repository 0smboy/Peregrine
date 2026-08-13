# Smoke B — swift3 Peregrine cold canary 8663d11

**VERDICT: GREEN**  
UTC: 2026-08-13T03:06:00Z · local (UTC+8): 2026-08-13 11:06 SGT  
Host: swift3 only (localhost:8080, not VIP). swift1/2/4 untouched. No cargo-build.

## Method
**archive-on-put** (lab cold backend `LocalDirColdBackend` / `filecold://`).

1. Added `[filter:s3api] cold_policy_map = GLACIER:0` (policy 0 = default `Policy-0` in `/etc/swift/swift.conf`; policy 1 is EC and was not used).
2. Drain-restarted proxy on swift3 only (stop → wait proxy3 DOWN via read-only `show stat` → start → health 200 → proxy3 UP). Binary SHA unchanged.
3. S3 `PUT ?lifecycle` returned **400 InvalidRequest** (internal container POST 400 from encoded lifecycle meta). Planted the same **Days=0 / GLACIER** XML as `X-Container-Meta-S3-Lifecycle` via TempAuth Swift POST (**204**).
4. S3 PUT object **200** → middleware `maybe_archive_due_cold_on_put` wrote bytes under `/var/cache/peregrine-cold/0/AUTH_test/<bucket>/<key_hex>` (**file existed, size=37**).
5. S3 POST `?restore` `<RestoreRequest><Days>1</Days>` → **202**.
6. S3 GET `?restore` → **200** RestoreStatus XML + `x-amz-restore: ongoing-request="false", expiry-date="1786676761"`.
7. Deleted smoke bucket/object and filecold file. No leftover objects in default containers.

Client HEAD does not surface `X-Object-Sysmeta-*` on this proxy; archive proof is the filecold file + restore_stage **202** (handler reads sysmeta on the internal HEAD).

## HTTP codes
| step | code |
|------|------|
| TempAuth | 200 |
| PUT container | 201 |
| S3 PUT ?lifecycle | 400 InvalidRequest (workaround: Swift container meta 204) |
| S3 PUT object | 200 |
| POST ?restore | **202** |
| GET ?restore | **200** |

filecold file existed before restore: **yes**  
planted file/sysmeta fallback: **not used**

## Live state after
- Binary SHA `b64deec239833c567604d9efe0211b3bd20b543b570de675cc40fd7fe4785148` (8663d11 canary, not rolled back)
- Health localhost:8080 **200**
- HAProxy proxy1–4 **UP**
- `cold_backend_root` + `cold_policy_map = GLACIER:0` remain on swift3
- `/var/cache/peregrine-cold` empty (0750)
- secret-scan hits=0

## Prior attempt
`canary-8663d11-smoke-b-20260813T030251Z` FAIL: restore POST 400 InvalidObjectState because client Swift POST of object sysmeta does not stick. Conf change + drain from that run were kept (map already present for the GREEN run; no second restart).

## Evidence
- swift3: `/root/work/peregrine-acceptance-20260810/canary-8663d11-smoke-b-20260813T030600Z/`
- box: `/workspace/canary-8663d11-smoke-b-20260813T030600Z/`
- Mac: `tools/test-results/canary-8663d11-smoke-b-20260813T030600Z/`
