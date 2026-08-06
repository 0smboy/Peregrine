# P3-auth threat note — Keystone / authtoken (2026-08-04)

**Scope:** Rust proxy `authtoken` + `keystoneauth` path. Contabo VIP remains TempAuth; this note covers the wired code path and unit threat cases.

## Trust boundaries

1. **Gatekeeper** strips inbound `X-Backend-*` and (defense in depth) forged Keystone identity headers before the pipeline.
2. **authtoken** clears client `X-Identity-Status` / `X-Roles` / project headers, validates the token, then stamps identity **and** `X-Backend-Authtoken-Status: Confirmed`.
3. **keystoneauth** trusts client-facing identity headers **only** when that backend marker is present (clients cannot forge the marker past gatekeeper).
4. **Proxy authorize** uses Keystone decision only when `X-Backend-Auth-Plugin: keystone` is stamped; otherwise TempAuth ACL path remains.

## Attack cases covered (unit)

| Threat | Mitigation | Test |
|--------|------------|------|
| Forge `X-Identity-Status: Confirmed` + admin roles | Cleared by authtoken; ignored by keystoneauth without backend marker | `forged_client_identity_cleared_without_token`, gatekeeper strip test |
| Present bogus `X-Auth-Token` | Hard 401 (even with delay) | `invalid_token_is_401` |
| Omit token with `delay_auth_decision=false` | 401 | `no_delay_missing_token_401` |
| Valid token for tenant A accessing `AUTH_<other>` | 403 | `test_authorize_request_deny_cross_tenant` |
| Anonymous GET without referrer ACL | 401 | `test_anonymous_referrer_acl` |
| ResellerAdmin / operator / reader role table | Ported authorize tree | keystoneauth unit suite |

## Residual risks

- Live Keystone TLS, token revocation cache TTL skew, and fernet key rotation are **ops** concerns once an Identity endpoint exists — not exercised on Contabo (absent).
- Pipeline mis-order (`keystoneauth` without `authtoken`) cannot elevate via forged client headers (marker required); operators should still place `authtoken` before `keystoneauth`.
- Enabling Keystone on the shared Contabo VIP without a dual-path cutover plan can break TempAuth clients — explicitly out of scope this wave.
