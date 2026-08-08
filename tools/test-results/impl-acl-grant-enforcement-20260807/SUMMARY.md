# ACP grant enforcement (GET/HEAD residual) · strict verify · 2026-08-07

## VERDICT: **KEEP**

**Claim level:** unit + code-path. **Not** live Contabo. **Not** PRODUCTION-GO-LIVE.  
**Scope:** LAB-HARD-GREEN (not full IAM). Store/GET ACL already KEEP (`impl-grant-acp-acl-20260807`).

## Worktree / package

| Item | Path |
|------|------|
| Root / worktree | `/Users/oboy/Downloads/Peregrine` |
| Rust workspace | `/Users/oboy/Downloads/Peregrine/swift-rust` |
| Package | `/Users/oboy/Downloads/Peregrine/swift-rust/crates/swift-s3api` |
| Helpers | `src/acl_cors.rs` — `object_grants_allow_read` / `object_acl_denies_read` |
| Wire-up | `src/middleware.rs` — `deny_if_object_acl_blocks_read` / `translate_object_get_head` on object GET/HEAD (+ versioned) |
| Residuals | `src/lib.rs`, `src/middleware.rs`, `src/acl_cors.rs` module docs |
| Evidence | `/Users/oboy/Downloads/Peregrine/tools/test-results/impl-acl-grant-enforcement-20260807/` |
| Git branch | `build/phase1-deploy-rs-lb` (package under `swift-rust/`) |

## Gate (strict verify)

```text
cd /Users/oboy/Downloads/Peregrine/swift-rust && cargo test -p swift-s3api --lib \
  | tee /Users/oboy/Downloads/Peregrine/tools/test-results/impl-acl-grant-enforcement-20260807/cargo-test.txt
```

| Artifact | Result |
|----------|--------|
| `cargo-test.txt` | **200 passed; 0 failed** (lib) |
| `verify-filter.txt` | pure matrix + 5 middleware grant tests **ok** |
| `verify-grep.txt` | symbols + test names present |

### Enforcement tests seen in `cargo-test.txt`

```text
test acl_cors::tests::object_grants_allow_read_enforcement_matrix ... ok
test middleware::tests::get_object_acl_grant_denies_foreign_principal ... ok
test middleware::tests::head_object_acl_grant_denies_foreign_principal ... ok
test middleware::tests::get_object_acl_grant_read_allows_principal ... ok
test middleware::tests::get_object_acl_owner_always_allowed ... ok
test middleware::tests::get_object_without_acl_json_not_denied ... ok
```

## Requirements checklist

| # | Requirement | Status |
|---|-------------|--------|
| 1 | Object GET/HEAD: if `S3_OBJECT_ACL_JSON_META` has grants and principal (access_key / account) is not owner and not granted READ/FULL_CONTROL → AccessDenied | **KEEP** |
| 2 | Owner always allowed; empty/missing grants → existing canned/Swift path (no new denials) | **KEEP** |
| 3 | AllUsers READ still does **not** open anonymous unauthenticated path | **residual documented** |
| 4 | Unit middleware tests: private+foreign denied; grant READ allowed; owner always OK | **KEEP** |
| 5 | Evidence dir | **KEEP** this path |
| 6 | `cargo test -p swift-s3api --lib` pass; residual notes updated | **KEEP** |

## Key symbols (grep-verified)

- `object_grants_allow_read` / `object_acl_denies_read` — pure enforcement
- `deny_if_object_acl_blocks_read` / `translate_object_get_head` — middleware GET/HEAD
- Wired on non-versioned object success + versioned GET/HEAD success paths
- Principal match: owner/grant `ID` vs `cred.access_key` **or** `cred.account`

## Residual (explicit, not KEEP)

- Anonymous unauthenticated GET from object AllUsers grants (no SigV4 → passthrough; container ACL still gates)
- Full IAM / emailAddress → canonical user resolution
- WRITE / READ_ACP / WRITE_ACP enforcement on non-GET/HEAD ops
- Bucket-level ACP grant enforcement on ListObjects etc.

## VERDICT

**KEEP** — object GET/HEAD ACP grant enforcement claimable at unit scope; gate green (200/200); store/GET already KEEP; anonymous AllUsers residual remains explicit.
