# P1c debt clear — SUMMARY

**Verdict: GREEN** · 2026-08-04 · Contabo VIP `http://10.0.0.10:8085`

## What this cycle did

Cleared “partial = unimplemented” debt on already-claimed CORE/L2 path:

1. **SLO** — nested `sub_slo` GET expansion (depth ≤ 10); lazy leaf streaming; ranged GET via per-segment `Range`; HEAD uses `X-Object-Sysmeta-Slo-Etag/Size`; `multipart-manifest=get&format=raw` client-schema conversion.
2. **Copy** — manifest-aware `?multipart-manifest=get` (SLO → `multipart-manifest=put`; DLO → `X-Object-Manifest`).
3. **TempAuth/ACL** — shared memcache info-cache L2 (`account/…`, `container/…`); reads skip process-local L1 when memcache configured; container-server `X-Remove-Container-*` → empty-value clear.

## Gates

| Gate | Result | Evidence |
|------|--------|----------|
| Unit (SLO/copy/info-cache/remove) | PASS | `04b-build.txt` |
| Deploy 4 nodes (proxy+container) | PASS | `05b-deploy.txt` |
| P1c specialty VIP | **28/28** | `20-gates-rerun.txt` |
| CORE-PATH func VIP | **54/54** | `20-gates-rerun.txt` |
| ACL failover smoke | PASS | `21-acl-failover-smoke.txt` |
| Contracts | DONE | ROADMAP / CONTRACTS / blocked / CONFIG-PARITY |

## Residuals (wontfix P1c · listed, not blocking)

- SLO inline `{"data":…}` PUT; heartbeat PUT; `multipart-manifest=delete`
- DLO multi-page listing pagination
- Copy sync-key propagation
- P1b smaller-filter specialty residual (unchanged)
- `bulk_upload` still wontfix

## Deploy note

Contabo proxy binary must be `cargo build --release -p swift-proxy-server --features ec`.  
Proxy md5: `ed1e66aa9bf2c68fb767a61864fe54e3` · Container md5: `d563d9a84b8aa7f44a3d3ff72c9c3421`.  
No wipe of `/srv/node`. P2 **not started**.

Human report: `P1C-REPORT.html`
