# Phase 1A layout (2026-08-04)

| Node | Role |
|------|------|
| swift1 | client only — Swift cluster units **stopped+disabled**; CLEAN ports |
| swift2 | Python SAIO `http://10.0.0.2:8090` — thin-viable pipeline (cache required by Python tempauth) |
| swift3 | Rust SAIO `http://10.0.0.3:8081` — release bins with EC |
| swift4 | monitor (prom/loki/console) — Swift cluster units **stopped+disabled**; CLEAN |

## func-suite
| Side | Result |
|------|--------|
| Python | PASS=54 FAIL=0 |
| Rust (after EC release-bin restart) | PASS=54 FAIL=0 |

## Notes
- Cluster VIP/HA left in place but backends empty (stage 2 will re-apply via deploy-rs).
- Python thin pipeline cannot drop `cache` (tempauth raises Memcache required).
