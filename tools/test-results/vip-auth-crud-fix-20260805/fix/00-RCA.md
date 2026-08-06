# RCA — VIP auth CRUD noise (wave4 → fix)

## Symptoms (wave4-python-live-20260805c)

- TempAuth `auth/v1.0` → 200, account list → **401**
- Keystone token → 201, Swift `AUTH_test` → **403**
- VIP `/healthcheck` and `/info` still 200 (`tempauth` + `keystoneauth`)

## Cause 1 — Keystone 403 (not a Contabo IdP break)

Wave4 listed `https://…/v1/AUTH_test` with a Keystone token.

Keystone maps storage accounts as `AUTH_<project_id>`. Project `test` is
`29af7f1e19774999bf700fbef31994d3`. Cross-tenant access to `AUTH_test` correctly
returns **403 Forbidden**.

Before any proxy change, Keystone CRUD on `AUTH_29af…` was already
PUT/GET/DELETE green.

## Cause 2 — TempAuth 401 (proxy coexist bug)

Pipeline: `… s3api s3token authtoken keystoneauth tempauth …`

`keystoneauth` middleware claimed every `AUTH_*` path and stamped
`X-Backend-Auth-Plugin: keystone` even when `authtoken` left identity Invalid
(TempAuth token). Proxy authorize then used Keystone anonymous rules → **401
Unauthorized** and never applied TempAuth groups.

## Fix

`swift-middleware` `KeystoneAuth::handle`: stamp Auth-Plugin **only** when
Keystone identity is Confirmed. Unit: `test_coexist_no_stamp_without_identity`.

Deployed release proxy sha256
`657e07439cde3520e83dd1bb47bf0f130120e532d39fda53a2925a0d938c2f77` on
swift1–4; `swift-proxy.service` restarted; payload bin updated.

## After

Both TempAuth and Keystone CRUD PASS on VIP HTTPS. See `after/01-probe-raw.txt`.
