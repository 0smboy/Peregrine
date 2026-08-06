# Keepalived / VIP failover — executed (W2 apply)

Date: 2026-08-05 · Evidence: `apply/06b-failover-complete.txt`

## Result: PASS

| Item | Value |
|------|-------|
| VIP | `https://10.0.0.10:8085` (self-signed; curl `-sk`) |
| Auth during drill | Keystone `tester` / project `test` |
| MASTER before | **swift2** (held `10.0.0.10`) |
| Action | `systemctl stop keepalived` on swift2 |
| MASTER after | **swift1** took VIP |
| VIP healthcheck during FO | **200** |
| PUT during FO | **201** (`during`) |
| GET during FO | **200** body=`during` |
| Pre-FO seed GET | **200** body=`seed` |
| Restore | `systemctl start keepalived` on swift2 |
| Final state | VIP on swift1; keepalived **active** on all four; vip_hc2=200 |

## Notes

- TempAuth coexist remains in proxy pipeline; storage gate for this drill used Keystone only.
- No PRODUCTION-GO-LIVE claim from this drill.
