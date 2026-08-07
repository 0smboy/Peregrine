# impl-worm-governance-bypass · 2026-08-07 · STRICT VERIFY

## VERDICT: **KEEP**

Governance bypass is implemented for **GOVERNANCE** only. **COMPLIANCE** and **legal-hold ON** remain hard-blocked with the bypass header present. Full package unit gate green.

---

## Worktree (merge absolute path)

| Item | Absolute path |
|------|----------------|
| **Root / worktree** | `/Users/oboy/Downloads/Peregrine` |
| **Rust workspace** | `/Users/oboy/Downloads/Peregrine/swift-rust` |
| **Crate** | `/Users/oboy/Downloads/Peregrine/swift-rust/crates/swift-s3api` |
| **WORM pure helpers** | `/Users/oboy/Downloads/Peregrine/swift-rust/crates/swift-s3api/src/object_lock_worm.rs` |
| **Middleware wire-up** | `/Users/oboy/Downloads/Peregrine/swift-rust/crates/swift-s3api/src/middleware.rs` |
| **Residual docs** | `/Users/oboy/Downloads/Peregrine/swift-rust/crates/swift-s3api/src/lib.rs` |
| **Evidence dir** | `/Users/oboy/Downloads/Peregrine/tools/test-results/impl-worm-governance-bypass-20260807` |

---

## Command + result

```text
cd /Users/oboy/Downloads/Peregrine/swift-rust && cargo test -p swift-s3api 2>&1 | tee \
  /Users/oboy/Downloads/Peregrine/tools/test-results/impl-worm-governance-bypass-20260807/cargo-test.txt
```

| Suite | Result |
|-------|--------|
| lib unit tests | **182 passed; 0 failed** |
| doc-tests | **0 passed; 0 failed** (none defined) |
| Log | `cargo-test.txt` |

---

## Middleware reads `x-amz-bypass-governance-retention` — CONFIRMED

Capture **before** `req` is moved into `swift_req` (strip would drop `x-amz-*`):

```1193:1198:/Users/oboy/Downloads/Peregrine/swift-rust/crates/swift-s3api/src/middleware.rs
        // Capture bypass before moving req into swift_req.
        let worm_bypass = bypass_governance_requested(
            req.headers
                .get(HDR_BYPASS_GOVERNANCE)
                .or_else(|| req.headers.get("X-Amz-Bypass-Governance-Retention")),
        );
```

Passed into WORM gate on DELETE / overwrite PUT:

```1242:1252:/Users/oboy/Downloads/Peregrine/swift-rust/crates/swift-s3api/src/middleware.rs
        // Object Lock WORM: block DELETE and overwrite PUT (governance bypass).
        if key.is_some() && matches!(method.as_str(), "DELETE" | "PUT") {
            if let Some(blocked) = worm_check_object(
                &cred,
                bucket.as_deref().unwrap(),
                key.as_deref().unwrap(),
                worm_bypass,
                &next,
            ) {
                return blocked;
            }
        }
```

Multi-delete uses the same header:

```1552:1560:/Users/oboy/Downloads/Peregrine/swift-rust/crates/swift-s3api/src/middleware.rs
    let bypass = bypass_governance_requested(
        req.headers
            .get(HDR_BYPASS_GOVERNANCE)
            .or_else(|| req.headers.get("X-Amz-Bypass-Governance-Retention")),
    );
    ...
        if worm_blocks_key(cred, bucket, key, bypass, next) {
```

`HDR_BYPASS_GOVERNANCE` = `"x-amz-bypass-governance-retention"` in `object_lock_worm.rs`.

---

## Safety matrix (KEEP condition)

| Scenario | Expected | Pure unit | Middleware unit | Status in `cargo-test.txt` |
|----------|----------|-----------|-----------------|----------------------------|
| GOVERNANCE + bypass | allow | `governance_bypass_allows_delete` | `governance_bypass_header_allows_delete`, `…_allows_overwrite_put` | ok |
| GOVERNANCE without bypass | deny | `governance_without_bypass_denies` | `retention_future_blocks_delete` | ok |
| **COMPLIANCE + bypass** | **deny** | `compliance_bypass_denied` | `compliance_bypass_header_still_denies_delete` | **ok** |
| **Legal-hold ON + bypass** | **deny** | `legal_hold_ignores_governance_bypass` | `legal_hold_bypass_header_still_denies_delete` | **ok** |
| Expired retain | allow | `expired_retain_allows_even_without_bypass` | `expired_retention_allows_delete` | ok |

Core enforcement (legal-hold first; only GOVERNANCE may bypass active retention):

```73:88:/Users/oboy/Downloads/Peregrine/swift-rust/crates/swift-s3api/src/object_lock_worm.rs
pub fn worm_blocks_delete_with_bypass(
    headers: &HeaderKeyDict,
    now_unix: i64,
    bypass_governance: bool,
) -> bool {
    if legal_hold_on(headers) {
        return true;
    }
    if !retention_active(headers, now_unix) {
        return false;
    }
    let mode = lock_mode(headers).unwrap_or_else(|| "COMPLIANCE".into());
    if mode == "GOVERNANCE" && bypass_governance {
        return false;
    }
    true
}
```

**KEEP gate satisfied:** COMPLIANCE + legal-hold remain blocked under bypass header.

---

## API surface

* `worm_blocks_delete(h, now)` — no bypass
* `worm_blocks_delete_with_bypass(h, now, bypass_governance)`
* `worm_allows_operation(h, now, bypass_governance)`
* `bypass_governance_requested(Option<&str>)` — `true` / `True` / `1` (also `yes`)
* `HDR_BYPASS_GOVERNANCE`

---

## Docs claim

* `lib.rs`: governance bypass **IMPLEMENTED** for GOVERNANCE only
* `middleware.rs` module docs: same; wired DELETE / overwrite PUT / multi-delete

---

## Residuals (not KEEP blockers)

* IAM / policy check for `s3:BypassGovernanceRetention` (header-only gate)
* MFA delete
* Live Contabo e2e (unit claim only)

---

## Logs in this dir

* `cargo-test.txt` — full `cargo test -p swift-s3api` (strict verify)
* `01-cargo-test.txt` / `02-worm-tests.txt` / `03-governance-tests.txt` / `04-bypass-filter.txt` — earlier focused runs
