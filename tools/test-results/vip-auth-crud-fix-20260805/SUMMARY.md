# VIP auth CRUD fix — 2026-08-05

**Verdict: GREEN** · TempAuth + Keystone CRUD PASS on `https://10.0.0.10:8085`  
**PRODUCTION-GO-LIVE: not claimed** · No ring migrate · No Python install · No mkfs

## 1) What this cycle did

1. Reproduced wave4 noise from `wave4-python-live-20260805c/02-VIP-HEALTH.txt`.
2. Separated two failures:
   - Keystone **403** on `AUTH_test` = wrong storage account (probe bug).
   - TempAuth **401** on list = `keystoneauth` stole authorize.
3. Fixed Rust `keystoneauth` to stamp `X-Backend-Auth-Plugin: keystone` only when identity is Confirmed.
4. Built + rolled `swift-proxy-server` on swift1–4; payload bin synced.
5. Re-proved TempAuth and Keystone token→list/put/get/delete on VIP HTTPS.

## 2) Optimized / fixed / demoted

| Item | Action |
|------|--------|
| Keystone path | **Confirmed green** with `AUTH_<project_id>` (was never broken) |
| TempAuth coexist | **Fixed** (stamp bug) — not demoted |
| Wave4 AUTH_test Keystone probe | **Documented** as incorrect client path |
| Ring migrate / Python | **Not run** (auth-only scope) |

## 3) Measured effect (before → after)

| Probe | Before | After |
|-------|--------|-------|
| VIP healthcheck | 200 | **200** |
| TempAuth auth/v1.0 | 200 | **200** |
| TempAuth list `AUTH_test` | **401** | **200** |
| TempAuth CRUD | fail | **201/201/200/204/204** |
| Keystone token | 201 | **201** |
| Keystone list `AUTH_<project_id>` | (not probed in wave4) | **200** |
| Keystone list `AUTH_test` | 403 | **403** (expected cross-tenant) |
| Keystone CRUD | N/A in wave4 probe | **201/201/200/204/204** |
| Bogus token | 401 | **401** |

## 4) Gates

| Gate | Result | Evidence |
|------|--------|----------|
| TempAuth CRUD | **PASS** | `after/01-probe-raw.txt` |
| Keystone CRUD | **PASS** | same |
| Cross-tenant deny | **PASS** (403) | same |
| Proxy sha ×4 aligned | **PASS** | `657e07439cde…` |
| Secrets not in git | **PASS** | Contabo `/root/contabo-identity-secrets.yml` only |
| PRODUCTION-GO-LIVE | **NOT claimed** | self-signed LAB TLS |

## 5) Client path (Keystone)

```bash
# token
TOK=$(curl -sk -D - -o /dev/null -X POST https://10.0.0.10:5000/v3/auth/tokens \
  -H 'Content-Type: application/json' \
  -d '{"auth":{"identity":{"methods":["password"],"password":{"user":{"name":"tester","domain":{"name":"Default"},"password":"<from-openrc-or-inventory>"}}},"scope":{"project":{"name":"test","domain":{"name":"Default"}}}}}' \
  | awk -F': ' 'tolower($1)=="x-subject-token"{print $2}' | tr -d '\r')
# project id from token catalog / admin list — NOT the name "test"
curl -sk -H "X-Auth-Token: $TOK" \
  https://10.0.0.10:8085/v1/AUTH_29af7f1e19774999bf700fbef31994d3
```

Do **not** use `AUTH_test` with a Keystone token (403 is correct).

TempAuth (coexist):

```bash
TOK=$(curl -sk -D - -o /dev/null \
  -H 'X-Auth-User: test:tester' -H 'X-Auth-Key: <tempauth-key>' \
  https://10.0.0.10:8085/auth/v1.0 \
  | awk -F': ' 'tolower($1)=="x-auth-token"{print $2}' | tr -d '\r')
curl -sk -H "X-Auth-Token: $TOK" https://10.0.0.10:8085/v1/AUTH_test
```

## 6) Remaining / FROZEN

- W4 ring migrate / Python install still gated on operator window (auth no longer blocks attribution).
- PRODUCTION-GO-LIVE TLS PEM still open.
- Keystone catalog endpoints still advertise `http://10.0.0.10:8085/...` (clients should use HTTPS VIP); optional cleanup, not a CRUD blocker.
