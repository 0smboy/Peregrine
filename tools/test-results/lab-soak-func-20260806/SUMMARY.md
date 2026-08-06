# Lab soak + func · 2026-08-06

## Verdict: **LAB-HARD-GREEN (Phase 2)**

| Gate | Result |
|------|--------|
| func-suite TempAuth HTTPS VIP | **PASS=54 FAIL=0** (`10-func-tempauth-https.log`) |
| Keystone additive CRUD | **PASS** (`11-keystone-crud-smoke.txt`) |
| Soak ≥1h TempAuth reauth/iter | **PASS** `SOAK_END … n=205 ok=205 fail=0` |
| Post-soak VIP + 4× healthcheck | **200** all |

## Soak detail

| Item | Value |
|------|--------|
| Mode | TempAuth, re-auth every iteration |
| Start | 2026-08-06T04:36:59Z |
| End | 2026-08-06T05:37:08Z (~60m) |
| Result | **n=205 ok=205 fail=0** |
| Log | `20-soak-tempauth-1h.log` |

Compared to W2 Keystone soak (185/192 fail=7): this TempAuth soak is clean; no 503 deploy window.

## Gate redefine (locked)

Contabo coexist cluster **primary** func/soak gate:

1. TempAuth VIP HTTPS func-suite **54/54**
2. TempAuth VIP soak ≥1h **fail=0**

Keystone CRUD is **additive** (project `AUTH_<uuid>`), not a replacement for the 54-count TempAuth suite.

## Not claimed

- PRODUCTION-GO-LIVE (still needs operator TLS PEM)
- Keystone-native full 54/54 suite
- L3b multi-node KEEP
