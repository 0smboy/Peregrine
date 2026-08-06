# Handoff verify · 2026-08-06

**Verdict: LAB-READY GREEN (handoff matches live)**  
**PRODUCTION-GO-LIVE: NO**

| Gate | Result | Notes |
|------|--------|-------|
| SSH ×4 | PASS | swift1–4 BatchMode |
| Disk Use% | PASS | all d1/d2/d3 ≈ **2%** |
| VIP HTTPS `/info` | PASS | tempauth + keystoneauth present; policies Policy-0 + ec-2-1 |
| TempAuth CRUD | PASS | PUT 201 / GET 200 body match / DEL 204 |
| Python :8090 ×3 | PASS | 10.0.0.2–4 info JSON (Swift 2.33.0) |
| Tombstone recon | PASS | CLI works; total_count=184 (residual, not blocking lab) |
| Binary align ×4 | PASS | proxy `657e0743…` object `69a7e5eb…` identical |
| **EC feature** | **FAIL (expected)** | PUT ec-2-1 object → **501** `erasure coding not built (compile with --features ec)` |

## Mainline

- Cluster is usable for fairness / integration (LAB-READY).
- Next: **Phase 1** rebuild+deploy EC-enabled binaries (same sha256×4), then re-probe EC PUT/GET/heal.

## Not claimed

- PRODUCTION-GO-LIVE
- EC data path
- soak fail=0, func 54/54 Keystone-native
- operator PEM

## Artifacts

- `01-df.txt` `02-vip-info.txt` `03-tempauth-crud.txt` `04-python-info.txt` `05-recon-ec-bin.txt`
