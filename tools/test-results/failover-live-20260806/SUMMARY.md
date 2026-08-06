# Keepalived failover live · 2026-08-06

**Verdict: PASS**

| Step | Result |
|------|--------|
| VIP before | `10.0.0.1` (swift1) |
| CRUD baseline (from .2) | PASS |
| Stop keepalived on swift1 | VIP → **10.0.0.2** within 2s |
| CRUD while VIP on .2 | PASS |
| Start keepalived on swift1 | keepalived **active** |
| VIP after restore | stayed **10.0.0.2** (nopreempt / non-preemptive master) |
| CRUD recovered | PASS |

Log: `02-failover-v2.log`

## Notes

- Non-preemptive VIP remaining on the new master is expected for this Contabo keepalived config.
- No TLS changes (operator PEM deferred).
