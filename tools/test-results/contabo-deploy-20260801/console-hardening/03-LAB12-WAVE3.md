# Wave 3 — Lab WARN clear + lab12-deep one-shot

Date: 2026-08-01

## Fixes

1. capsule/tombstone: query param `obj` to `object` (API CapQ/ObjQ).
2. warehouse: body uses `goal` + `inputs[{name,content}]` (old name/input caused 400/502).
3. lab12-deep.sh: export OUT; temp-url key sync before Shadow; drop_durable policy=1;
   chaos 409 retry + longer poll; former WARNs are hard checks.
4. Shadow breaking=0: side A uses local `127.0.0.1:8080` when session storage_url is VIP
   (HAProxy strips Content-Length on 204 vs Python CL:0).
5. profilemap: proxy bind_ip=0.0.0.0 so hub scrapes `10.0.0.N:8080/recon/stage`
   (was loopback-only after security bind lockdown).

## Result

OUT=`/root/contabo-deploy-20260801T125749Z/lab12-deep-wave3b`

- Verdict: **ACCEPT**
- PASS=36 FAIL=0 WARN=0
- Shadow dual breaking=0 (31 cases)
- capsule / tombstone / warehouse PASS
- chaos x4 + HA 20/20 + profile non-empty

Re-run: `OUT=/path bash /root/work/lab12-deep.sh`
