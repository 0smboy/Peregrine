# Priority residual wave · Contabo · 2026-08-06

**Claim level:** LAB-HARD-GREEN only. **Not** PRODUCTION-GO-LIVE.

## Priority results

| Pri | Item | Result | Evidence |
|-----|------|--------|----------|
| P0 | Operator TLS PEM | **BLOCKED** — only lab self-signed `haproxyCA.pem` (`O=Contabo-LAB`, subject==issuer). HAProxy `bind *:8085 ssl crt …` live. Operator PEM apply deferred. | `01-tls-lab-status.txt` |
| P0 | VIP HTTPS product path (lab cert) | **LAB OK** with `curl -k`: auth, HEAD count=100, list=100, GET 4KB 200 | `05-vip-https-4kb-sample.txt` |
| P0 | L3b product-style 40×4KB on SHARDED container | **KEEP** (internal `:8080`): put_ok=40, HEAD=LIST=100, NEW=40, GET 5/5 size=4096 | `02-l3b-4kb-product-probe.txt` |
| P1 | Multi-primary root placement | Root DB hash present on multi nodes after prior rep; shrinklab on swift1/3/4, l3bclean on all 4. Full auto shrink-across-primaries **not** re-proven this wave | `04b-targeted-root-replicas.txt`, `04-multi-primary-roots.txt` |
| P1 | Multi-cluster container-sync | **RESIDUAL** — single 4-node LAB, no `container-sync-realms.conf`, `allowed_sync_hosts` local-only. Same-cluster path already KEEP (`sync-smoke-20260806d`) | `03-multi-cluster-sync-status.txt` |

## L3b product 4KB detail

- Container: `shrinklab1786029572` (already SHARDED lab)
- Baseline: 60 objects → after 40×4KB: **100**
- HEAD Object-Count **matches** list line count (**YES**)
- Storage-URL HTTPS VIP without `-k` fails (expected self-signed) — not a data-path bug
- Python对照 / multi-hour soak: **not claimed**

## TLS honesty

| Layer | Status |
|-------|--------|
| HAProxy SSL bind 8085 | LIVE |
| Cert kind | self-signed Contabo-LAB |
| Operator / public CA PEM | **not applied** |
| PRODUCTION-GO-LIVE | **NO** |

## Still residual (next wave)

1. Operator PEM install via `tools/ops/apply-vip-tls-pem.sh` (operator provides PEM)
2. Multi-primary automatic shrink without manual root/donor co-locate
3. Multi-cluster realm soak (needs second cluster)
4. Full Rust vs Python L3b product对照 on identical load
5. Python formal cluster (still ABSENT)

## Git anchor

Code path already on `build/phase1-deploy-rs-lb` @ `09e97bb` (HEAD=list fan-out + multi-device shrink search). This directory is **evidence + docs only**.
