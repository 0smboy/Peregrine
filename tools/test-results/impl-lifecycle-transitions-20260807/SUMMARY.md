# impl-lifecycle-transitions · 2026-08-07 — STRICT VERIFY

## Worktree / root

| Item | Path |
|------|------|
| **Repo root** | `/Users/oboy/Downloads/Peregrine` |
| **Crate worktree** | `/Users/oboy/Downloads/Peregrine/swift-rust` |
| **Package** | `swift-s3api` → `crates/swift-s3api` |
| **Primary impl** | `/Users/oboy/Downloads/Peregrine/swift-rust/crates/swift-s3api/src/lifecycle_exec.rs` |
| **Middleware wire** | `/Users/oboy/Downloads/Peregrine/swift-rust/crates/swift-s3api/src/middleware.rs` |
| **Evidence dir** | `/Users/oboy/Downloads/Peregrine/tools/test-results/impl-lifecycle-transitions-20260807/` |

## VERDICT: **KEEP**

Parse + apply unit tests for Transition and AbortIncompleteMultipartUpload **exist and pass**. Expiration KEEP path still passes. No claim of real storage-class tiering backends (LAB-HARD-GREEN metadata stamp only).

## Cargo evidence

```text
cd /Users/oboy/Downloads/Peregrine/swift-rust
# note: host cargo registry cache is root-owned; CARGO_HOME=/tmp/cargo-home-p04 required to compile
CARGO_HOME=/tmp/cargo-home-p04 cargo test -p swift-s3api --lib
```

| Log | Result |
|-----|--------|
| `cargo-test.txt` | **173 passed; 0 failed** (`--lib`) |
| `cargo-test-lifecycle_exec.txt` | **14 passed** (all `lifecycle_exec::tests::*`) |
| `cargo-test-full.txt` | lib ok; **doctests fail** with rustdoc `E0463` (env: can't resolve `sha2`/`swift_http`/`swift_middleware` under isolated `CARGO_HOME`) — **not a P0-4 logic failure** |

Authoritative for KEEP gate: **lib unit tests**.

## Parse + apply unit tests (must-exist gate)

| Test | Role | Status |
|------|------|--------|
| `lifecycle_exec::tests::parse_transition_and_abort_from_sample_xml` | Parse Transition + AbortIncomplete from sample LifecycleConfiguration XML | **ok** |
| `lifecycle_exec::tests::apply_transition_meta_matching_key` | Matching key → `X-Object-Meta-S3-Storage-Class` + `X-Object-Sysmeta-S3-Transition-At` | **ok** |
| `lifecycle_exec::tests::apply_transition_meta_non_matching_prefix_skips` | Non-matching prefix skips | **ok** |
| `lifecycle_exec::tests::expiration_still_works_alongside_transition` | Expiration `X-Delete-At` still works with Transition present | **ok** |
| `lifecycle_exec::tests::abort_incomplete_stamps_delete_at_on_marker` | AbortIncomplete → marker `X-Delete-At` + sysmeta days | **ok** |
| `lifecycle_exec::tests::transition_date_rule` | Transition Date absolute unix | **ok** |
| `middleware::tests::put_object_stamps_transition_meta_from_lifecycle` | PUT path stamps transition + expiration | **ok** |
| `middleware::tests::put_object_transition_skips_non_matching_prefix` | PUT prefix mismatch | **ok** |
| `middleware::tests::mpu_init_stamps_abort_incomplete_x_delete_at` | InitiateMultipartUpload marker stamp | **ok** |
| `middleware::tests::put_object_stamps_x_delete_at_from_lifecycle` | Prior Expiration KEEP | **ok** |

## Behavior claim (KEEP scope)

1. **Transition (LAB-HARD-GREEN):** Enabled `<Transition><Days|Date><StorageClass>` + Prefix/Filter → on object PUT stamp meta only; **no tiering backend**.
2. **AbortIncomplete:** Enabled `<DaysAfterInitiation>` → on MPU init, stamp `X-Delete-At = now+Days*86400` on upload marker (+ `X-Object-Sysmeta-S3-Abort-Mpu-Days`).
3. **Expiration KEEP:** Days/Date → `X-Delete-At` on PUT still intact.

## Residuals (not KEEP)

* Tag / And filters  
* Real Glacier/IA tiering or restore  
* Background lifecycle scan of existing objects  
* Doc-test harness under this agent’s isolated `CARGO_HOME` (infra noise)

## Code anchors

* `parse_transition_rules` / `parse_abort_incomplete_rules` / `apply_lifecycle_transition_meta` / `apply_abort_incomplete_on_marker` — `lifecycle_exec.rs`  
* `maybe_apply_lifecycle_on_put` / `maybe_apply_abort_incomplete_on_marker` — `middleware.rs`  
* Residual list: Transition/Abort removed as residual in `lib.rs` / `bucket_config.rs` (tag filters remain residual)
