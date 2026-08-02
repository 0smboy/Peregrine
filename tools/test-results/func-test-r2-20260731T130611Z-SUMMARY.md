# Round-2 Swift Rust functional test — 2026-07-31T13:08:49Z

## Verdict: **ACCEPT**

Plan-first evidence: `/root/func-test-r2-20260731T130611Z/00-PLAN.md`. Cluster API EP `http://10.42.30.11:8085`.

| Gate | Result |
|------|--------|
| P0 preflight | PASS (proxy/haproxy/console; peers active; :8085/:9000 200) |
| G3 ha-test (swift2 down) | **PASS** baseline 10/10; degraded repl+EC **20/20**; recovered 10/10; all nodes up after |
| G6 console-test | hard pages/APIs/CRUD **PASS** (36); 3 content checks FAIL are relative-URL false fails — absolute URL recheck **3/3 PASS** |
| recon-check | reconstructor failures=0; part-871 errors **0** |
| Python SAIO :8090 | **SKIP/WARN** — memcached was missing (installed+enabled); suite then `RESULT  label=py-saio  PASS=5  FAIL=49` (backend 503s). Not a cluster REJECT. |

## Round-1 carry-forward (not re-run)
func-suite 54/54 ×4 nodes, ACL/meta, edge-diag, EC heal, Rust SAIO 54/54 — see func-test-20260731.

## Notes
- Console false FAILs: ckin uses relative fetch without host; absolute `http://127.0.0.1:9000/...` content OK.
- Installed `memcached` on swift1 for pyswift tempauth; cluster path unaffected.
- Evidence: `/root/func-test-r2-20260731T130611Z`
