# ACP+IAM strict verify · 2026-08-08

**Scope:** `swift-s3api` unit + code-path only. **Not** live Contabo / PRODUCTION-GO-LIVE.  
**Worktree:** `/Users/oboy/Downloads/Peregrine/swift-rust`  
**Evidence dir:** `/Users/oboy/Downloads/Peregrine/tools/test-results/hard9-residual-wave-20260808/`  
**Verifier date:** 2026-08-08T06:23Z (UTC)

---

## Gate command

Cargo accepts a **single** `TESTNAME` filter. The requested multi-token line:

```text
cargo test -p swift-s3api --lib iam object_grants acl grant acp
```

is **invalid as one invocation** (`error: unexpected argument 'object_grants'`).  
Strict verify ran each filter separately with project `CARGO_HOME` + `--offline`:

```bash
export CARGO_HOME=/Users/oboy/Downloads/Peregrine/swift-rust/.cargo-home
cd /Users/oboy/Downloads/Peregrine/swift-rust
for f in iam object_grants acl grant acp; do
  cargo test -p swift-s3api --lib --offline "$f"
done
# full lib sanity:
cargo test -p swift-s3api --lib --offline
```

**Artifact:** `acp-iam-cargo-filters.txt` · code audit: `acp-iam-code-audit.txt` · full lib: `cargo-s3api.txt` (204 ok)

### Filter results

| Filter | Passed | Failed | Filtered out |
|--------|--------|--------|--------------|
| `iam` | **1** | 0 | 203 |
| `object_grants` | **1** | 0 | 203 |
| `acl` | **34** | 0 | 170 |
| `grant` | **10** | 0 | 194 |
| `acp` | **4** | 0 | 200 |
| **full `--lib`** | **204** | **0** | 0 |

**Unique tests hit by the five filters:** 35 (all ok).  
Key hits:

- `iam::tests::email_map_and_access_key`
- `acl_cors::tests::object_grants_allow_read_enforcement_matrix`
- `acl_cors::tests::object_acp_json_store_and_get_xml`
- `acl_cors::tests::acp_xml_roundtrip_structured_grants`
- `middleware::tests::put_object_acl_acp_body_stores_json_and_get_roundtrip`
- `middleware::tests::put_bucket_acl_acp_body_roundtrip`
- `middleware::tests::get_object_acl_grant_denies_foreign_principal` (+ HEAD / allow / owner)

---

## Checklist (strict)

| # | Claim | Verdict | Evidence |
|---|-------|---------|----------|
| 1 | cargo filters green | **PASS** | `acp-iam-cargo-filters.txt`; full lib 204/0 |
| 2 | `object_acl_denies_write` wired on object **PUT/DELETE** | **PASS (non-versioned path)** | `middleware.rs` ~1370–1388 → `acl_write_check_object` → `deny_if_object_acl_blocks_write` → `object_acl_denies_write` |
| 2b | Same WRITE check on **versioned** PUT/DELETE | **GAP** | Versioned plane returns early at `handle_versioned_object` (~1298–1314) **before** `acl_write_check_object`; no write-deny in `handle_versioned_put` / `handle_versioned_delete` |
| 2c | Same WRITE check on **multi-delete** | **GAP** | `handle_multi_delete` runs WORM only (`worm_blocks_key`); no `acl_write_check_object` |
| 2d | Middleware unit test for WRITE deny on PUT/DELETE | **GAP** | READ deny tests exist; **no** `put_*`/`delete_*` grant-deny middleware test |
| 3 | IAM **email map** library | **PASS** | `iam.rs`: `IdentityDirectory::with_email_map_csv` + `resolve_email` (case-insensitive); unit `email_map_and_access_key` ok |
| 3b | IAM email map on **middleware hot path** | **GAP** | `S3Api` has **no** `IdentityDirectory` field; conf key `iam_email_map` is docs-only; `object_acl_denies_{read,write}` call `*_with_iam(..., None)` |
| 4 | store / GET ACP (object + bucket `?acl`) | **PASS** | `handle_acl` PUT → `apply_object_acl_input` / JSON sysmeta; GET → `object_acl_xml_from_headers`; tests above |

---

## Code path detail

### WRITE enforcement (non-versioned)

```text
PUT|DELETE object (versioning not Enabled, no ?versionId)
  → worm_check_object
  → acl_write_check_object
       HEAD existing object
       if 2xx: deny_if_object_acl_blocks_write(cred, headers)
                → object_acl_denies_write
                     → object_grants_allow_write(... iam=None)
                     → Some(false) ⇒ 403 AccessDenied
       if missing/404: no denial (create path)
```

Symbols:

| Symbol | File |
|--------|------|
| `object_acl_denies_write` | `crates/swift-s3api/src/acl_cors.rs:958` |
| `object_grants_allow_write` / `_with_iam` | `acl_cors.rs:865` / `878` |
| `deny_if_object_acl_blocks_write` | `middleware.rs:1027` |
| `acl_write_check_object` | `middleware.rs:1494` |
| call site PUT/DELETE | `middleware.rs:1370–1388` |

Permission matrix for WRITE: `WRITE` \| `FULL_CONTROL` (not READ alone).

### READ enforcement (reference)

GET/HEAD (incl. versioned success path) uses `deny_if_object_acl_blocks_read` / `translate_object_get_head`. Unit matrix + 5 middleware grant tests green.

### IAM email map

```text
crates/swift-s3api/src/iam.rs
  IdentityDirectory { access_key_to_id, email_to_id, id_aliases }
  with_email_map_csv("a@b.com:user1,...")  // lowercases email keys
  resolve_email / principal_matches_id / canonical_id_for_access_key

acl_cors object_grants_allow_{read,write}_with_iam(…, Option<&IdentityDirectory>)
  Email grantee → dir.resolve_email → principal_matches_id
```

**Not present:**

- `S3Api.iam` / `with_identity_directory`
- conf loader for `[filter:s3api] iam_email_map=…`
- production call sites passing `Some(&dir)` into grant evaluation

`lib.rs` residual text still lists “full IAM identity / emailAddress grantee resolution” as **not claimable as implemented** on the full service surface — consistent with middleware gap (library-only is claimable).

### store / GET ACP

| Op | Path | Meta |
|----|------|------|
| PUT object `?acl` (ACP body / grants / canned) | `handle_acl` → POST Swift + `apply_object_acl_input` | `X-Object-Sysmeta-S3-Acl-Json` (and/or canned `…-Acl`) |
| GET object `?acl` | HEAD object → `object_acl_xml_from_headers` | JSON preferred over canned |
| PUT/GET bucket `?acl` | same pattern + container read/write for AllUsers | `X-Container-Meta-S3-Acl-Json` |
| Object PUT body ACL headers | `resolve_acl_put_input` on non-`?acl` PUT | stamps sysmeta on create |

Tests: `put_object_acl_acp_body_stores_json_and_get_roundtrip`, `put_bucket_acl_acp_body_roundtrip`, `object_acp_json_store_and_get_xml`, canned/grant store tests.

---

## Residuals (explicit)

1. **EmailAddress grantees never match** on live GET/PUT/DELETE enforcement until `IdentityDirectory` is attached to `S3Api` and passed into deny helpers (or `object_acl_denies_*` gain an iam parameter used by middleware).
2. **Versioned PUT/DELETE** skip `acl_write_check_object`.
3. **Multi-delete** skips object ACP WRITE check (WORM only).
4. **No middleware unit test** proving foreign principal gets 403 on overwrite PUT / DELETE under private JSON ACL.
5. Not AWS IAM cloud service; local directory only even when wired.

---

## Overall verdict

| Surface | Strict verdict |
|---------|----------------|
| cargo `iam` / `object_grants` / `acl` / `grant` / `acp` | **KEEP** (all green) |
| store/GET ACP | **KEEP** |
| GET/HEAD READ grant enforcement | **KEEP** (prior + reconfirmed) |
| `object_acl_denies_write` on non-versioned PUT/DELETE | **KEEP (code-path)** — unit write-deny test still missing |
| IAM email map as library API | **KEEP (unit)** |
| IAM email map end-to-end on s3api filter | **NOT KEEP** (not wired into `S3Api` / deny path) |
| WRITE on versioned / multi-delete | **NOT KEEP** |

**Composite for hard9-acp-iam item:** **PARTIAL KEEP** — cargo + store/GET ACP + non-versioned WRITE wire-up + IAM directory module pass; do **not** claim full IAM middleware integration or complete WRITE coverage on all delete paths.

Do **not** overwrite parent wave row #6 as unconditional KEEP for “完整 IAM 身份服务” without closing 3b.

---

## Paths

| Role | Absolute path |
|------|----------------|
| Package | `/Users/oboy/Downloads/Peregrine/swift-rust/crates/swift-s3api` |
| IAM | `.../src/iam.rs` |
| Grants/ACP | `.../src/acl_cors.rs` |
| Wire-up | `.../src/middleware.rs` |
| This summary | `.../hard9-residual-wave-20260808/acp-iam-SUMMARY.md` |
| Filter log | `.../hard9-residual-wave-20260808/acp-iam-cargo-filters.txt` |
| Code audit | `.../hard9-residual-wave-20260808/acp-iam-code-audit.txt` |
