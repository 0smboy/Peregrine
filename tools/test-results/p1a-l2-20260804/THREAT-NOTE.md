# P1a TempURL / Account ACL — threat note

**Date:** 2026-08-04  
**Scope:** Contabo VIP `http://10.0.0.10:8085` with P1a pipeline  
(`tempauth tempurl bulk ratelimit copy slo dlo` + P0 front matter).

## TempURL

| Threat | Mitigation in this wave | Negative evidence |
|--------|-------------------------|-------------------|
| Forged signature | HMAC over `METHOD\nexpires\npath`; constant-time compare | tampered sig → 401 |
| Replay after expiry | `temp_url_expires` normalized; expired → invalid | expired → 401 |
| Path confusion | Signature binds full `/v1/account/container/object` | path mismatch → 401 |
| Method confusion | Message includes method; GET ≠ PUT sig | method mismatch → 401 |
| Pointer upload (DLO/symlink) via write TempURL | `X-Object-Manifest` / `X-Symlink-Target` rejected on unsafe methods | Manifest on PUT → 400 |
| Cross-proxy stale keys after POST | TempURL key lookup **bypasses** in-process info cache (live HEAD) | valid GET 200 after key set via VIP |
| Client forging authorize bypass | `X-Backend-Authorize-Override` only set by middleware after valid sig; gatekeeper strips inbound `x-backend*` | covered by gatekeeper + override unit |

**Deferred (documented):** `temp_url_ip_range` (no `REMOTE_ADDR` on `Request`); digest metrics.

## Account ACL (`X-Account-Access-Control`)

| Threat | Mitigation | Negative evidence |
|--------|------------|-------------------|
| Invalid / unknown ACL keys | TempAuth validation → 400 with explanatory body | `{"not-a-key":[]}` → 400 |
| Silent skip of ACL | Enforced in proxy `authorize` via sysmeta `core-access-control` | anonymous GET → 401 with ACL set |
| Client forging sysmeta | gatekeeper strips inbound `x-*-sysmeta-*`; client header rewritten to sysmeta only after validate | — |
| Non-owner reading ACL / Temp-URL keys | `swift_owner` stamp; strip owner headers on response | suite checks owner sees ACL |

**Residual:** Account ACL membership for authorize still uses in-process account info cache (TTL). Cross-proxy lag until TTL is possible for ACL *enforcement* (not TempURL keys). Shared memcache info cache remains P0-follow backlog.

## Rate limit

Default-on in `bundle-rust` with high limits (`account_ratelimit=200`) so CORE-PATH is not tripped. Toggle `enable_ratelimit=false` to remove from pipeline. In-process buckets (not shared memcache) — fairness note for multi-proxy.
