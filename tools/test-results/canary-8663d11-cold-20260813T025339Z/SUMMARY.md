# swift3-only cold canary 8663d11 — 20260813T025339Z

**APPLY_OK** · **SMOKE_A_PASS** · **not rolled back**

## Binary
- Built/installed SHA: `b64deec239833c567604d9efe0211b3bd20b543b570de675cc40fd7fe4785148`
- Tip: `8663d11` LocalDir + RestoreObject + archive-on-transition (Mac rust tree MD5-matched; later `df9280e` docs-only)
- Artifact: `/root/work/peregrine-artifacts/peregrine-proxy-8663d11-ec.tar.gz`
- Artifact SHA: `50c0245d030409b230ad6ccaa0577a769954d185a7c0b05715aae2eaedf362c0`
- Rollback dir (pre-canary 77dd9f4 binary): `/root/peregrine-proxy-rollback-8663d11-swift3-20260813T025352Z-2q7Ob4`
- Fleet rollback artifact still `215f4d81a7bab1b373abc86c7e77f478f04b382878db01a8b00dde62c61825a2` / live SHA `117d7b08...` on peers

## Config (swift3 only)
- `[filter:s3api] cold_backend_root = /var/cache/peregrine-cold`
- bak: `/etc/swift/proxy-server.conf.bak-pre-cold-8663d11-20260813T025339Z`
- dir `/var/cache/peregrine-cold` mode 750

## Smoke A (localhost:8080, not VIP)
- TempAuth PUT container 201, PUT object 201, GET 200
- S3 POST `?restore` on warm object: HTTP 400 `InvalidObjectState` / Restore is not allowed for the object current storage class (handler live)
- No secrets in evidence (secret-scan.txt)

## HAProxy
- Drain: stop swift-proxy, wait proxy3 DOWN via read-only `show stat` (no disable/enable write)
- After canary: all proxy1-4 UP. VIP mixed ~25% canary on swift3. HAProxy/Keepalived configs untouched.

## Peers
- swift1/2/4 still `117d7b088e691be6826cca0fca067353bfc52c76f96b25aec1882f1d80d3052c`, no cold_backend_root

## Prior aborted attempt
- 20260813T025247Z: APPLY_OK then smoke missed exported env; automatic ROLLBACK_OK to 117d7b08 before this successful re-apply.
