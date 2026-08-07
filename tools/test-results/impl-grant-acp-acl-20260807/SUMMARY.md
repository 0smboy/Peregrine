# Grant-header + ACP XML ACL · strict verify · 2026-08-07

## VERDICT: **KEEP**

**Claim level:** unit + code-path. **Not** live Contabo. **Not** PRODUCTION-GO-LIVE.  
**Scope:** LAB-HARD-GREEN (not full IAM identity service).

## Worktree / package

| Item | Path |
|------|------|
| Root | `/Users/oboy/Downloads/Peregrine` |
| Package | `/Users/oboy/Downloads/Peregrine/swift-rust/crates/swift-s3api` |
| Module | `src/acl_cors.rs` + `src/middleware.rs` (`handle_acl`) |
| Evidence | `/Users/oboy/Downloads/Peregrine/tools/test-results/impl-grant-acp-acl-20260807/` |

## Gate

```text
cd /Users/oboy/Downloads/Peregrine/swift-rust && cargo test -p swift-s3api
```

| Artifact | Result |
|----------|--------|
| `cargo-test.txt` | **176 passed; 0 failed** (lib) + **0 doctests** |
| `03-grep-acp-grant.txt` | `parse_acp_xml`, `x-amz-grant-*`, JSON meta, middleware wire-up present |

## Requirements checklist

| # | Requirement | Status |
|---|-------------|--------|
| 1 | Parse PUT `?acl` AccessControlPolicy XML → structured grants (ID/URI + Permission) | **KEEP** `parse_acp_xml` |
| 2 | Store grants JSON sysmeta; bucket AllUsers → container Read/Write + full policy meta | **KEEP** `S3_OBJECT_ACL_JSON_META` / `S3_BUCKET_ACL_JSON_META` |
| 3 | `x-amz-grant-read\|write\|full-control\|read-acp\|write-acp` list form → same store | **KEEP** `parse_grant_headers` |
| 4 | GET `?acl` from grants; canned path if only canned meta | **KEEP** `object_acl_xml_from_headers` / `bucket_acl_xml_from_headers` |
| 5 | Canned `x-amz-acl` precedence if both present | **KEEP** `resolve_acl_put_input` + test |
| 6 | Unit: ACP round-trip; grant-read AllUsers → public-read-like; object JSON + GET Grant/Permission | **KEEP** (tests below) |
| 7 | No anonymous unauthenticated GET authz rewire | **residual documented** |
| 8 | Evidence dir | **KEEP** this path |
| 9 | `cargo test -p swift-s3api` pass; docs/residuals | **KEEP** |

## Key symbols (grep)

- `parse_acp_xml` — ACP body → `AccessControlPolicy`
- `parse_grant_header_value` / `parse_grant_headers` — `x-amz-grant-*`
- `encode_acl_json` / `decode_acl_json`
- `apply_object_acl_policy` / `apply_bucket_acl_policy` / `apply_grants_to_container`
- `resolve_acl_put_input` — canned first
- Middleware: `handle_acl` PUT/GET object+bucket

## Unit tests (P0-3 surface)

**acl_cors:** `acp_xml_roundtrip_structured_grants`, `grant_read_allusers_maps_public_read_container_headers`, `object_acp_json_store_and_get_xml`, `canned_takes_precedence_over_grant_headers`, `parse_grant_header_list_form`, `resolve_grant_headers_to_policy`

**middleware:** `put_bucket_acl_grant_read_allusers_stamps_container_read`, `put_object_acl_acp_body_stores_json_and_get_roundtrip`, `put_bucket_acl_acp_body_roundtrip` + existing canned path

## Residual (not KEEP as implemented)

- Anonymous unauthenticated GET authorization from object grants (container ACL still gates)
- Full IAM / emailAddress → canonical user resolution
- ACP grant enforcement on subsequent ops

## VERDICT

**KEEP** — grant-header + ACP XML store/GET round-trip claimable at unit scope; residual #7 explicit.
