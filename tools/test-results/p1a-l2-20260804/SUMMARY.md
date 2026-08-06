# P1a L2 — SUMMARY

**Date:** 2026-08-04  
**Gate:** **GREEN**

## Results

| Check | Result |
|-------|--------|
| cargo test middleware / proxy P1a wire | PASS (local + Contabo) |
| Contabo VIP `/info` (4 proxies) | `bulk_delete` + `tempurl` + `tempauth.account_acls`; no `bulk_upload` |
| P1a specialty suite VIP | **27/27** (`17-suites-rerun.txt`) |
| P1a specialty suite local | **27/27** |
| CORE-PATH func-suite VIP | **54/54** (`12-func-suite-vip.txt`) |
| TempURL threat negatives | PASS (tamper/expiry/wrong path) — `THREAT-TEMPURL.md` |
| Account ACL validate + enforce | PASS |
| ratelimit | **on-by-config** — sample in `bundle-rust`; not in default pipeline |

## Pipeline (bundle-rust default)

`catch_errors gatekeeper healthcheck proxy-logging cache listing_formats bulk tempurl tempauth copy slo dlo proxy-logging proxy-server`

Lab Contabo peers may already include `ratelimit` (high limits); that is optional, not the template default.

## Honest residual

- `bulk_upload` / `?extract-archive` **not** implemented; not advertised (P1b).
- TempURL `temp_url_ip_range` deferred.
- Account ACL authorize may lag across proxies until info-cache TTL (TempURL keys path is uncached).
- Shared memcache-backed info cache still backlog.
- Pipeline order not identical across all Contabo nodes (swift1 vs 2–4); CORE-PATH still 54/54.

## Evidence

`tools/test-results/p1a-l2-20260804/P1A-REPORT.html`
