# P3-auth — Keystone + authtoken (2026-08-04)

**Verdict: partial** — code / wire / unit / threat negatives **GREEN**; Contabo Keystone cluster E2E **ABSENT** (no Keystone/MariaDB on lab; TempAuth VIP left untouched).

VIP: `http://10.0.0.10:8085` (TempAuth still live)

## What shipped

| Item | Status |
|------|--------|
| `authtoken` middleware (`TokenValidator`, `HttpTokenValidator`, `MapTokenValidator` / `static_token_*`) | Done |
| `keystoneauth` Middleware + proxy authorize dispatch | Done |
| Unspoofable `X-Backend-Authtoken-Status` + gatekeeper strip of forged identity | Done |
| `/info` advertises `keystoneauth` only when authtoken+keystoneauth wired | Done |
| TempAuth coexistence (plugin stamp / TempAuth ACL fallback) | Done |
| Contabo Keystone Identity deploy | **NOT done** — infra absent; deploy-rs rust stack still TempAuth-only |

## Gates

| Gate | Result | Evidence |
|------|--------|----------|
| Unit `swift-middleware` | **351/351 PASS** (incl. authtoken + keystoneauth + threat) | `05-cargo-middleware.txt` |
| Unit proxy bin (wiring + `/info`) | **13/13 PASS** incl. `pipeline_p3_auth_wires_*` | `05-cargo-proxy-bin.txt` |
| Unit proxy lib | **13/13 PASS** | `05-cargo-proxy-lib.txt` |
| Contabo Keystone present | **NO** (`/etc/keystone` missing, unit inactive) | `10-contabo-tempauth-smoke.txt` |
| TempAuth VIP CRUD smoke (no wipe / no pipeline change) | **201/201/200/204/204**; bad token **401** | `10-contabo-tempauth-smoke.txt` |
| Live `/info` claims keystoneauth | **False** (honest — not enabled on VIP) | same |
| Contract updates | DONE | ROADMAP / CONTRACTS / blocked |

## Threat negatives (unit)

| Case | Expected | Result |
|------|----------|--------|
| Forged `X-Identity-Status` / roles without valid token | Cleared; no Confirmed stamp | PASS |
| Invalid `X-Auth-Token` | 401 + WWW-Authenticate | PASS |
| Cross-tenant access without ACL | 403 | PASS |
| Anonymous without referrer ACL | 401 | PASS |
| Missing token + `delay_auth_decision=false` | 401 | PASS |
| `static_token_*` stamp → backend authtoken marker | Confirmed | PASS |

## Residuals (do not claim cluster Keystone green)

- Contabo has **no** Keystone/MariaDB; enabling Keystone on the live VIP would require external Identity + pipeline cutover (out of scope; would risk TempAuth).
- `bundle-rust` still rejects rust-stack `auth.method=keystone` node roles (honest: proxy ON-BY-CONFIG, deploy does not provision Identity).
- Project-domain-id sysmeta persistence + container-sync fast-path remain deferred (documented in `keystoneauth.rs`).
- `HttpTokenValidator` supports `http://` Keystone only in this wave (TLS terminator / separate P3-ops).

## Next

- External Keystone (or SAIO Keystone) endpoint → Contabo/SAIO E2E suite before upgrading verdict to GREEN.
- Keep Contabo VIP on TempAuth until then.
