# STRICT VERIFY — item3 IAM multi-tenant

**Date:** 2026-08-08T06:55:45Z  
**Workspace:** `/Users/oboy/Downloads/Peregrine/swift-rust`  
**Source:** `crates/swift-s3api/src/iam.rs`  
**Command:**
```bash
export CARGO_HOME=/Users/oboy/Downloads/Peregrine/.cargo-home
cd /Users/oboy/Downloads/Peregrine/swift-rust
cargo test -p swift-s3api --lib -- iam
```

## VERDICT: KEEP

`IamService::evaluate` Allow/Deny + multi-tenant isolation are unit-proven. Local multi-tenant IAM product surface (not AWS IAM cloud).

## Test counts
| Metric | Count |
|--------|------:|
| passed | 5 |
| failed | 0 |
| ignored | 0 |
| measured | 0 |
| filtered out | 215 |
| duration | 0.00s |

**Artifact:** `iam-cargo-test.txt` (same directory)

## Required claims

| Requirement | Mechanism | Test | Result |
|-------------|-----------|------|--------|
| Allow | `evaluate` → `Some(true)` when matching Allow stmt | `iam::tests::policy_allow_get_deny_delete` | ok |
| Deny (explicit) | Deny stmt short-circuits → `Some(false)` | same | ok |
| Deny (no matching Allow) | Policy present, no Allow match → `Some(false)` (AWS default) | same (`s3:PutObject`) | ok |
| No policy | `evaluate` → `None` (fall through ACL/Swift auth) | `iam::tests::no_policy_returns_none` | ok |
| Tenant isolation | `tenant_of` / `same_tenant` via `iam_tenants` CSV | `iam::tests::multi_tenant_isolation` | ok |
| Identity maps | email + access_key → canonical id | `iam::tests::email_map_and_access_key` | ok |
| S3 helpers | `s3_action` / `s3_resource` | `iam::tests::s3_action_resource_helpers` | ok |

## Evaluation semantics (code)

```text
IamService::evaluate(principal, action, resource) → Option<bool>
  policies attached to principal + "*"
  for each matching statement (principal/action/resource wildcards):
    Effect::Deny  → return Some(false)   // explicit Deny wins
    Effect::Allow → allowed = true
  no policy saw     → None
  allowed           → Some(true)
  else              → Some(false)        // default deny when policy attached
```

Tenant surface:

```text
with_tenants_csv("t1:alice,bob;t2:carol")
tenant_of("alice") == Some("t1")
same_tenant("alice","bob")  == true
same_tenant("alice","carol") == false
```

## Full test list
```
test iam::tests::email_map_and_access_key ... ok
test iam::tests::multi_tenant_isolation ... ok
test iam::tests::no_policy_returns_none ... ok
test iam::tests::policy_allow_get_deny_delete ... ok
test iam::tests::s3_action_resource_helpers ... ok

test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 215 filtered out; finished in 0.00s
```

## Notes
- Package: `swift-s3api` lib filter `iam` (hits only `iam::tests::*`)
- Build: `Finished test profile` after recompile of `swift-s3api` (~1.29s)
- Warnings only in dep `swift-middleware` (unused import / dead code); none failed tests
- Conf surface documented in module: `iam_email_map`, `iam_access_key_map`, `iam_policy_json`/`iam_policy_file`, `iam_tenants`
- Claim boundary: **unit library KEEP** for multi-tenant IAM product in hard residual wave item3. Does **not** re-verify middleware hot-path wiring of `IdentityDirectory` into ACP grant deny (see `hard9-residual-wave-20260808/acp-iam-SUMMARY.md` item 3b GAP if claiming e2e filter integration)

## Paths
| Role | Absolute path |
|------|----------------|
| IAM module | `/Users/oboy/Downloads/Peregrine/swift-rust/crates/swift-s3api/src/iam.rs` |
| This verify | `/Users/oboy/Downloads/Peregrine/tools/test-results/hard-residual-wave-20260808/verify-iam.md` |
| Cargo log | `/Users/oboy/Downloads/Peregrine/tools/test-results/hard-residual-wave-20260808/iam-cargo-test.txt` |
| Wave rollup | `/Users/oboy/Downloads/Peregrine/tools/test-results/hard-residual-wave-20260808/HARD-RESIDUAL-SUMMARY.md` (item 3) |
