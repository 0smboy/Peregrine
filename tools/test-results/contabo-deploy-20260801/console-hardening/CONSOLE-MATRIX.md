# CONSOLE-MATRIX — Contabo surface acceptance

Date: 2026-08-01 17:49:56 +0200
Verdict: **ACCEPT** (FAIL=0 WARN=0)

| Page | Action | Expect | Status | Evidence |
|------|--------|--------|--------|----------|
| Login | POST /login tenant=test user=tester | session established (whoami=tester) | **PASS** | `http=200 cookies=['sc_session'] whoami_http=200 user=tester` |
| Language | POST /lang l=zh then en | accepted switch | **PASS** | `http=200->200` |
| Files | GET /files | 200 HTML buckets page | **PASS** | `http=200 size=102434` |
| Files | GET /files/api/whoami | tester identity | **PASS** | `http=200 {'cluster': 'contabo-swift-2026', 'storage_url': 'http://10.0.0.10:8085/v1/AUTH_test', 'tenant': 'test', 'user': 'tester', 'version': '0.1.0'}` |
| Files | GET /files/api/buckets | 200 container list | **PASS** | `http=200 type=dict snippet={'account': {'bytes_used': '7252403511', 'container_count': '56', 'object_count': '21369', 'quota_bytes': None}, 'buckets': [{'bytes': 3256320, 'count': 795, 'n` |
| Files | create container matrix-1785599392 | 2xx create | **PASS** | `http=200 body=b'{"ok":true}'` |
| Files | upload+download small object | PUT ok + GET body match | **PASS** | `swift PUT matrix-1785599392/hello.txt http=201; download http=200 match=True` |
| Deploy | GET /deploy shell | 200 with iframe to /deploy/ | **PASS** | `http=200 size=3712` |
| Deploy | GET /deploy/ upstream | 200 proxied HTML (not 502) | **PASS** | `http=200 size=35008 head=b'<!doctype html>\n<html lang="zh-CN">\n  <head>\n    <meta chars'` |
| Deploy | GET /deploy/api/health (if any) | non-502 | **PASS** | `http=404 size=21` |
| Deploy | destructive format/apply | NOT executed (policy) | **PASS** | `skipped by design — audit/validate only` |
| Monitor | GET /monitor | 200 page | **PASS** | `http=200 size=4869` |
| Monitor | GET /monitor/api/dash | catalog with overview | **PASS** | `http=200 size=6924` |
| Monitor | panel nodes_up | non-empty value/series | **PASS** | `http=200 {"id": "nodes_up", "kind": "stat", "unit": "num", "value": 4.0}` |
| Monitor | panel reqs | non-empty value/series | **PASS** | `http=200 {"id": "reqs", "kind": "stat", "unit": "reqs", "value": 0.9866666666666667}` |
| Monitor | panel cpu | non-empty value/series | **PASS** | `http=200 {"id": "cpu", "kind": "series", "series": [{"key": "swift1", "name": "swift1", "points": [[1785595792.0, 0.24219444444445082], [1785595816.0` |
| Monitor | panel net_storage | non-empty value/series | **PASS** | `http=200 {"id": "net_storage", "kind": "series", "series": [{"name": "rx", "points": [[1785599008.0, 114347.79057309432], [1785599032.0, 234781.77877` |
| Lab | GET /lab | 200 page (or 303 to login-free) | **PASS** | `http=200 size=8175` |
| Lab | GET /lab/nodes | 200 page (or 303 to login-free) | **PASS** | `http=200 size=7754` |
| Lab | GET /lab/shadow | 200 page (or 303 to login-free) | **PASS** | `http=200 size=137875` |
| Lab | GET /lab/chaos | 200 page (or 303 to login-free) | **PASS** | `http=200 size=8701` |
| Lab | GET /lab/api/node/status | 200 JSON status | **PASS** | `http=200 snippet=b'{"nodes":[{"active_services":10,"expires":null,"held_down":false,"journal_id":null,"node":"swift1","reachable":true,"total_services":10,"up":true},{"active_serv'` |
| Test | GET /test | 200 page if enabled | **PASS** | `http=200 size=5288` |
| Test | GET /test/api/runs | 200 list | **PASS** | `http=200 snippet=b'{"running":null,"runs":[{"avg_proc_ms":0.21,"avg_res_ms":0.3,"bandwidth":0.0,"bytes":0,"finished":"2026-08-01-16:14:16","op":"read","ops":1597719,"size":"16MB",'` |
| Test | POST /test/api/run 64KB_write_2 (10s) | accepted short suite | **PASS** | `http=200 body=b'{"ok":true,"task":"64KB_write_2"}'` |
| Test | GET /test/api/runs after start | running or recent run visible | **PASS** | `http=200 snippet=b'{"running":{"note":"","started":1785599393,"task":"64KB_write_2"},"runs":[{"avg_proc_ms":0.21,"avg_res_ms":0.3,"bandwidth":0.0,"bytes":0,"finished":"2026-08-01-16:14:16","op":"read'` |

## Notes
- Deploy destructive ops (format/apply) intentionally not exercised.
- Monitor Grafana not required; Prom/Loki panels used.
- Lab deep chaos/shadow covered separately by lab12; this matrix is surface smoke only.
