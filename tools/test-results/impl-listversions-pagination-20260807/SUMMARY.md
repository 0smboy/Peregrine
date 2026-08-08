# ListVersions pagination fidelity · strict verify · 2026-08-07

**Task:** P1-2  
**Root:** `/Users/oboy/Downloads/Peregrine/swift-rust`  
**Package:** `swift-s3api`

## VERDICT: **KEEP**

Pagination unit tests **exist and pass**. Full lib gate green.

## Gate (this run)

```bash
cd /Users/oboy/Downloads/Peregrine/swift-rust
cargo test -p swift-s3api --lib | tee tools/test-results/impl-listversions-pagination-20260807/cargo-test.txt
```

Evidence path (requested):  
`/Users/oboy/Downloads/Peregrine/tools/test-results/impl-listversions-pagination-20260807/cargo-test.txt`

| Suite | Result | Counts |
|-------|--------|--------|
| `cargo test -p swift-s3api --lib` | **PASS** | **201 passed; 0 failed** |
| filter `list_versions` | **PASS** | **5/5** |

## Pagination unit tests (exist + pass)

| Test | Module | Status |
|------|--------|--------|
| `list_versions_multi_key_pagination` | `versioning_store::tests` | ok |
| `list_versions_prefix_filter` | `versioning_store::tests` | ok |
| `list_versions_empty_indexes_and_empty_versions` | `versioning_store::tests` | ok |
| `versions_list_returns_empty_list_versions_result` | `middleware::tests` | ok |
| `empty_list_versions_shape` | `bucket_config::tests` | ok |

## Behavior proven

`list_versions_result_xml` (`crates/swift-s3api/src/versioning_store.rs`):

1. Multi-key indexes sorted; markers (`key-marker` / `version-id-marker`) applied across keys
2. `max-keys` mid-list cut → `IsTruncated=true` + `NextKeyMarker` + `NextVersionIdMarker`
3. Prefix filter
4. Empty indexes / empty versions container shape

## Artifacts

- `cargo-test.txt` — full lib gate
- `cargo-test-listversions-filter.txt` — pagination filter
- `01-cargo-test.txt` / `02-*` — earlier wave transcripts (superseded counts may differ; this SUMMARY is authoritative for strict verify)

## Claim boundary

- **KEEP** = unit + code-path only  
- **Not** live Contabo / PRODUCTION-GO-LIVE  
- Residual: invalid version-id-marker soft-start; delimiter/CommonPrefixes; EncodingType=url
