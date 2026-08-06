# TempURL threat note (P1a)

**Date:** 2026-08-04  
**Scope:** Rust `swift-middleware::TempUrl` + proxy `KeyProvider` wiring.

## Assets

- Account/container `Temp-URL-Key[-2]` secrets
- Signed query grants (`temp_url_sig`, `temp_url_expires`, optional prefix)

## Threats & controls

| Threat | Control | Negative evidence |
|--------|---------|-------------------|
| Forged / truncated signature | HMAC verify (sha1/256/512), constant-time compare | suite: tampered sig → 401 |
| Replay after expiry | `normalize_temp_url_expires` coerces past → invalid | suite: expires=1 → 401 |
| Path swap (sig for A used on B) | Message includes full `/v1/a/c/o` path | suite: wrong path → 401 |
| Method confusion (PUT sig on GET) | Method in HMAC message; HEAD allows GET/POST/PUT only | unit tests |
| Upload of DLO/symlink pointer via PUT tempurl | Reject `X-Object-Manifest` / `X-Symlink-Target` on unsafe methods | unit: 400 |
| Client forging authorize bypass | `X-Backend-Authorize-Override` stripped by gatekeeper; only TempURL stamps it after valid sig | gatekeeper inbound exclusions |
| Stale key after rotate (multi-proxy) | `temp_url_keys` uses uncached account/container HEAD | VIP suite across RR |

## Residual

- `temp_url_ip_range` not implemented (no `REMOTE_ADDR` on Request) — document as Deferred.
- Account-vs-container key scope not tracked (flat key list); same as prior crate deferral.
- Shared memcache-backed info cache still backlog (keys path intentionally bypasses in-process cache).
