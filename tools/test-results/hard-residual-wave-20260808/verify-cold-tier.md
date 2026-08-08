# STRICT VERIFY — item4 physical cold tier

**Date:** 2026-08-08  
**Workspace:** `/Users/oboy/Downloads/Peregrine/swift-rust`  
**Source:** `crates/swift-s3api/src/cold_tier.rs`  
**Command:**
```bash
export CARGO_HOME=/Users/oboy/Downloads/Peregrine/.cargo-home
cd /Users/oboy/Downloads/Peregrine/swift-rust
cargo test -p swift-s3api --lib -- cold_tier
```

## VERDICT: KEEP

Storage-policy map (`GLACIER:N`), physical stamp (`SYS_COLD_POLICY_INDEX` / backend URI), restore→hot routing, and `MemoryColdBackend` archive/restore are unit-proven.  
`S3Api.cold_map` is product field; operator conf required for live policy indices. Not physical tape hardware GO-LIVE.

## Test counts
| Metric | Count |
|--------|------:|
| passed | 4 |
| failed | 0 |
| ignored | 0 |
| filtered out | 216 |
| duration | 0.00s |

```
test cold_tier::tests::memory_backend_archive_restore ... ok
test cold_tier::tests::csv_map_and_physical_transition ... ok
test cold_tier::tests::unmapped_class_no_physical ... ok
test cold_tier::tests::restore_routes_to_hot ... ok
```

## Claim boundary
LAB-HARD-GREEN unit surface. Live Contabo policy rings + real tape adapter remain operator deploy work.
