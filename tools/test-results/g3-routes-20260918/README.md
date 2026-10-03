# G3 per-route activation evidence — 2026-09-18

First per-route G3 evidence collected for any candidate. Produced by
`tools/g3-route-probe.py` against the live lab tip `9531eb62` on
`127.0.0.1:18080` (swift1). Prod `:8080` was not touched.

G3 asks for a real request per required route plus `/recon/concurrency` counter
deltas proving `native_async_requests_total > 0` while
`legacy_sync_handler_requests_total`, `block_in_place_total`, and
`blocking_network_wait_total` all stay at `0`.

## Result

| Route | Requests | native_async Δ | legacy_sync Δ | block_in_place Δ | blocking_network_wait Δ |
|---|---|---:|---:|---:|---:|
| s3-PUT | 200 | +1 | 0 | 0 | 0 |
| s3-GET | 200 | +1 | 0 | 0 | 0 |
| s3-HEAD | 200 | +1 | 0 | 0 | 0 |
| s3-Range | 206 | +1 | 0 | 0 | 0 |
| s3-COPY | 200 | +1 | 0 | 0 | 0 |
| s3-MPU | initiate 200 / part 200 / complete 200 | +3 | 0 | 0 | 0 |
| swift-PUT | 201 | +1 | 0 | 0 | 0 |
| swift-GET | 200 | +1 | 0 | 0 | 0 |
| swift-HEAD | 200 | +1 | 0 | 0 | 0 |
| swift-Range | 206 | +1 | 0 | 0 | 0 |
| swift-COPY | 201 | +1 | 0 | 0 | 0 |
| swift-SLO | segment 201 / manifest 201 / GET 200 | +4 | 0 | 0 | 0 |
| ec-PUT/GET (policy `ec42`) | container 201 / PUT 201 / GET 200, body verified | +3 | 0 | 0 | 0 |

Every driven route satisfies all four invariants. At rest the proxy also
reports `native_async_requests_total == http_requests_total{engine="hyper"}`
(7259 = 7259) with the three forbidden counters at 0.

## What this does not establish

- **`ssync` is UNCOVERED.** It is object-server to object-server replication
  traffic, not a client-reachable route, so a client probe cannot drive it. It
  needs a replication-triggered measurement on the object servers.
- **This is the tip line, which has no G0 identity.** The lab tip tree
  `/root/work/src-60dd0f6/swift-rust` has no `.git`, so this evidence cannot be
  pinned to an immutable source per G0. Accepting G3 formally requires a
  candidate with a real commit identity, then a rerun.
- The probe only asserts the counter contract. It is not a correctness suite
  and says nothing about response bodies beyond the EC round-trip byte check.

Two probe bugs were found and fixed while producing this, both mine rather than
the engine's, and both worth knowing because either one silently fakes a pass:

1. A rejected request still satisfies the counter invariants. The first run
   scored `s3-MPU` as PASS on a `403` from a mis-signed request. The probe now
   requires a 2xx before a route counts as evidence.
2. SigV4 canonical query strings need valueless keys as `key=`; `?uploads`
   must canonicalize to `uploads=`.

Header lookups are case-insensitive because Swift answers `Etag` where AWS
answers `ETag`; that difference is compliant and is not a defect.

## Reproduce

```bash
scp tools/g3-route-probe.py swift1:/root/work/peregrine-probe-20260918/
ssh swift1 'cd /root/work/peregrine-probe-20260918
  SW=$(sed -n "/\[filter:tempauth\]/,/^\[/p" /etc/g6-rust/proxy-server.conf \
       | awk -F"=" "/^user_test_tester[ ]*=/{print \$2}" | awk "{print \$1}")
  PROBE_SWIFT_USER="test:tester" PROBE_SWIFT_KEY="$SW" \
    PROBE_JSON=g3-routes.json python3 g3-route-probe.py'
```
