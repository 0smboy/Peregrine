# Lifecycle Transition execution — strict verify

**Date:** 2026-08-08  
**Tree:** `/Users/oboy/Downloads/Peregrine/swift-rust`  
**Command intent:** `cargo test -p swift-s3api --lib cold_transition apply_due lifecycle`  
**Note:** Cargo accepts only a single `TESTNAME` filter. Ran three sequential filters with project-local `CARGO_HOME` and `--offline` (global `~/.cargo/registry` is root-owned → permission denied).

```bash
export CARGO_HOME=/Users/oboy/Downloads/Peregrine/swift-rust/.cargo-home
cd /Users/oboy/Downloads/Peregrine/swift-rust
cargo test -p swift-s3api --lib --offline cold_transition
cargo test -p swift-s3api --lib --offline apply_due
cargo test -p swift-s3api --lib --offline lifecycle
```

**Raw log:** `lifecycle-cargo-combined.txt` (same directory)

---

## Verdict: PASS (unit paths confirmed)

| Filter | Result |
|--------|--------|
| `cold_transition` | **1 passed** — `lifecycle_exec::tests::cold_transition_blocks_get_and_restore` |
| `apply_due` | **1 passed** — `lifecycle_exec::tests::apply_due_transition_stamps_transitioned` |
| `lifecycle` | **20 passed** (includes both above + PUT stamp / expiration / abort / middleware lifecycle RT) |

No failures.

---

## Confirmed code paths

### 1. `transition_blocks_get` + `apply_restore_days`

**File:** `crates/swift-s3api/src/lifecycle_exec.rs`

- `transition_blocks_get(headers, now)` → true when:
  - transitioned (`SYS_TRANSITIONED` = 1/true/yes) **or** past `SYS_TRANSITION_AT`, **and**
  - storage class is cold (`GLACIER` / `DEEP_ARCHIVE` / `GLACIER_IR` / `FLEXIBLE_RETRIEVAL` / `DEEP_ARCHIVE_IR`), **and**
  - no active restore (`SYS_RESTORE_UNTIL` missing or `<= now`)
- `apply_restore_days(headers, days, now)` stamps `X-Object-Sysmeta-S3-Restore-Until = now + days*86400`

**Unit test** `cold_transition_blocks_get_and_restore`:
1. GLACIER + TRANSITION_AT=100 + TRANSITIONED=1 @ now=200 → **blocks**
2. `apply_restore_days(..., 1, 200)` → **unblocks** at 200
3. after restore window (`200 + 86400 + 1`) → **blocks again**

### 2. `apply_due_transition_on_headers`

**File:** `lifecycle_exec.rs` L403–418

- If `SYS_TRANSITION_AT` present and `<= now`, stamps `SYS_TRANSITIONED=1` (idempotent if already set)
- Test `apply_due_transition_stamps_transitioned`: TRANSITION_AT=50 @ now=100 → stamped

### 3. GET → `InvalidObjectState`

**File:** `crates/swift-s3api/src/middleware.rs`

```text
GET/HEAD object success
  → translate_object_get_head(...)
      → deny_if_transition_blocks_get(&mut resp.headers, now)
          1. apply_due_transition_on_headers(headers, now)   // stamp due transition
          2. if transition_blocks_get(headers, now):
               return s3_error_response(
                 "InvalidObjectState",
                 Some("The operation is not valid for the object's storage class"),
                 &[],
               )
```

Call sites of `translate_object_get_head`:
- object handler when method is GET|HEAD and Swift status 2xx (~L1442–1444)
- versioned object GET success (~L2183)
- version-id GET success path (~L2257)

**Confirmed:** cold transitioned object on GET/HEAD is denied via S3 error code `InvalidObjectState`.

---

## Residual notes (not test failures)

| Item | Status |
|------|--------|
| `apply_restore_days` HTTP surface | **Lib-only.** Grep shows no RestoreObject / restore API wiring; only used by unit test + available as pure fn. |
| `InvalidObjectState` HTTP status | `error_status_and_message` has **no** arm for `InvalidObjectState` → falls through to `_ => (400, "Bad Request")`. AWS S3 uses **403**. Body still carries `<Code>InvalidObjectState</Code>` with the explicit message from middleware. |
| Middleware integration test for InvalidObjectState on GET | **None** listed. Coverage is pure `lifecycle_exec` unit tests + static wiring in `deny_if_transition_blocks_get` / `translate_object_get_head`. PUT transition stamp **is** covered by `middleware::tests::put_object_stamps_transition_meta_from_lifecycle`. |
| Tiering backend | Doc comment in `lifecycle_exec.rs`: metadata stamp only; data stays in primary Swift store (no fake Glacier tier). |

---

## Key symbols / headers

| Symbol / header | Role |
|-----------------|------|
| `META_STORAGE_CLASS` | `X-Object-Meta-S3-Storage-Class` |
| `SYS_TRANSITION_AT` | `X-Object-Sysmeta-S3-Transition-At` |
| `SYS_TRANSITIONED` | `X-Object-Sysmeta-S3-Transitioned` |
| `SYS_RESTORE_UNTIL` | `X-Object-Sysmeta-S3-Restore-Until` |
| `apply_lifecycle_transition_meta` | PUT-time stamp from Lifecycle XML |
| `apply_due_transition_on_headers` | Lazy stamp before GET deny check |
| `transition_blocks_get` | Cold-archive gate |
| `apply_restore_days` | Temporary restore window stamp |
| `deny_if_transition_blocks_get` | GET/HEAD enforcement → InvalidObjectState |

---

## Bottom line

**Transition execution path is real and unit-tested:** due transition stamps → cold class blocks GET → restore window unblocks → window expiry re-blocks. Middleware GET/HEAD wires that gate to **`InvalidObjectState`**. Cargo filters `cold_transition`, `apply_due`, and `lifecycle` all green (20/20 under `lifecycle`).
