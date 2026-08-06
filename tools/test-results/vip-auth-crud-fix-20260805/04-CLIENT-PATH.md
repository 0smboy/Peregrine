# VIP auth client path (Contabo LAB)

## Keystone (primary for W4+)

1. `POST https://10.0.0.10:5000/v3/auth/tokens` (self-signed LAB) with project-scoped password auth  
   user `tester` / project `test` (secrets: Contabo `/root/contabo-identity-secrets.yml` only).
2. Storage account is **`/v1/AUTH_<project_id>`**, never `/v1/AUTH_test`.  
   Wave4 probes that used `AUTH_test` with a Keystone token correctly got **403** (name ≠ id).
3. CRUD: `PUT/GET/DELETE` container+object with `X-Auth-Token: <Fernet>`.

Project `test` id (LAB, 2026-08-05): `29af7f1e19774999bf700fbef31994d3`  
Role required: `swiftoperator` (or `admin`) on that project.

## TempAuth (coexist, restored)

1. `GET https://10.0.0.10:8085/auth/v1.0` with `X-Auth-User: test:tester` and proxy `user_test_tester` key.
2. Account: `/v1/AUTH_test` (TempAuth account name).
3. Use HTTPS storage URL (`storage_url = https://10.0.0.10:8085` on all proxies after this fix).

## What looked like “auth broken” in wave4c

| Probe | Result | Meaning |
|-------|--------|---------|
| Keystone → `AUTH_test` | 403 | Wrong account path (client); Keystone id path was already 200 |
| TempAuth → list | 401 | Real bug: `keystoneauth` stamped Auth-Plugin for all `AUTH_*` without identity, stealing TempAuth authorize |

## Do not

- Treat Keystone 403 on `AUTH_<project_name>` as Identity misconfig.
- Commit `/root/contabo-identity-secrets.yml`.
- Claim PRODUCTION-GO-LIVE (VIP/Keystone still self-signed LAB).
