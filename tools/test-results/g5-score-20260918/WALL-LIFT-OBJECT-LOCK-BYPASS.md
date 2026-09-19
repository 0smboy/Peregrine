# Wall lift: `BypassGovernanceRetention` — what the dig found

Owner lifted the `BypassGovernanceRetention` tip-ask NO wall on 2026-09-18 so
the last genuine Rust-only G5-B identity could be investigated:

```
s3tests_boto3.functional.test_s3:test_object_lock_changing_mode_from_governance_with_bypass
ERROR: AccessDenied when calling the PutObjectRetention operation
```

The dig changes the decision, so it is worth reading before anyone patches
anything: **this is not an oversight. It is a deliberate, documented, unit-tested
security stance that is stricter than AWS, RGW, and Python Swift.**

## What the test asks for

`test_s3.py:13547-13558` — create a bucket with object lock enabled, PUT an
object with `GOVERNANCE` retention, then change the mode to `COMPLIANCE` with
`BypassGovernanceRetention=True`, using the same (owner) client. No IAM policy
is created anywhere in the test.

## Where the engine says no

The retention decision itself is correct and even names this test:

```rust
// rust/crates/swift-s3api/src/object_lock_worm.rs:513-525
ObjectLockMode::Governance => {
    // Any change that is not a pure GOVERNANCE extension (shorten
    // OR mode switch to COMPLIANCE) needs bypass. AWS/Ceph
    // test_object_lock_changing_mode_from_governance_with_bypass.
    let mode_change = requested.mode != ObjectLockMode::Governance;
    let shorten = requested.retain_until_unix < old.retain_until_unix;
    if (mode_change || shorten) && !bypass.effective() {
        RetentionUpdateDecision::Deny(RetentionUpdateDenyReason::GovernanceBypassRequired)
    } else {
        RetentionUpdateDecision::Allow
    }
}
```

The denial comes from `bypass.effective()`, which is `requested && authorized`:

```rust
// rust/crates/swift-s3api/src/middleware.rs:9730-9758
// A bypass header is only effective with an explicit IAM Allow. An
// absent policy must not turn a client-controlled header into a
// governance-retention bypass.
let authorized = match iam.evaluate(&principal, "s3:BypassGovernanceRetention", &resource) {
    Some(true) => true,
    Some(false) => false,
    None => false,          // <- no policy at all also denies
};
```

`IamService::evaluate` returns `None` when **no policy applies at all**
(`middleware.rs:315-370`, `saw_policy == false`). The lab has no IAM policies,
so every bypass attempt lands on `None` and is refused.

## Why this is a policy reversal, not a bug fix

Two unit tests pin the behavior deliberately, as a matched pair:

| Test | Asserts |
|---|---|
| `governance_bypass_header_without_iam_grant_denies_delete` (`middleware.rs:29147`) | header, no grant → **403 AccessDenied**, and the backend DELETE must never be reached (`panic!("header-only bypass must not reach backend DELETE")`) |
| `governance_iam_grant_without_header_denies_delete` (`middleware.rs:29170`) | grant, no header → **403**, "permission alone is never enough" |

So "header AND explicit IAM grant" is an intended invariant with a stated
rationale: a client-controlled header must not by itself defeat governance
retention.

Everyone else disagrees with that choice for the owner case:

| Implementation | Same-owner bypass with no IAM policy |
|---|---|
| AWS S3 | allowed — the resource owner implicitly holds `s3:BypassGovernanceRetention` |
| Ceph RGW | allowed (the suite encodes this expectation) |
| Python Swift 2.33.0 s3api | allowed — it has no IAM subsystem at all, so it authorizes on ordinary write permission. Measured: this identity **passes** on the oracle |
| Rust tip `9531eb62` | denied |

GOVERNANCE mode exists precisely to be bypassable by sufficiently privileged
callers; COMPLIANCE is the mode nobody can bypass, and Rust handles that
correctly (`compliance_bypass_header_still_denies_delete`,
`compliance_bypass_partial_bits_deny_delete`).

## Why no patch was pushed

The obvious one-line change — `None => true` — reverses the invariant those two
tests exist to protect, and it would authorize bypass for *any* principal with
write access, not just the owner. The narrower and correct rule is "the resource
owner is implicitly permitted", but this codebase does not currently expose an
owner predicate at that call site:

- `governance_bypass_context` is synchronous and has only
  `(iam, cred, bucket, key, requested)`; the bucket owner is resolved
  elsewhere by `resolve_bucket_owner_cred` / `resolve_bucket_owner_cred_async`
  (`middleware.rs:4800`, `:4820`).
- `cred.groups` cannot stand in for ownership. The tempauth loader strips
  `.admin` and pushes the storage account into `groups`
  (`middleware.rs:19091-19101`), and the test fixtures give the "foreign" and
  "friend" principals `AUTH_test` in groups as well
  (`middleware.rs:19206-19229`), so group membership does not separate owner
  from co-tenant.

Changing an authorization invariant is an owner decision distinct from "lift the
wall so you can look", so the wall lift was used to diagnose, not to ship.

## The three ways to close this identity

| # | Option | Consequence |
|---|---|---|
| A | **Record it as a deliberate divergence.** Add a `stricter-than-aws` class to the G5 policy holding this one identity, with this document as its basis. | Honest and immediate: G5-B unexpected drops to the remaining transient. Nothing is hidden — the class name says Rust is intentionally stricter, and a reader can see exactly which behavior differs. Does not weaken the engine. |
| B | **Align to the reference: owner-implicit bypass.** Thread the bucket owner into `governance_bypass_context` and authorize on `None` only when the principal is the recorded owner; keep `Some(false)` denying. Replace the two pinned tests with owner/non-owner variants. | Matches AWS, RGW, and Python Swift, and closes the identity for real. Costs an engine change, a rebuild, a new tip, and a re-prove; it is the only option that removes a genuine compatibility gap rather than documenting it. |
| C | **Blanket `None => true`.** | Do not. It grants bypass to co-tenants with write access, which is what the current invariant was written to prevent, and it would still need the two tests rewritten. |

Recommendation: **A now, B as scheduled engine work.** A is accurate today and
unblocks the gate arithmetic; B is the real fix and should be done on a
candidate that has a G0 identity from the start, since the `9531eb62` tip line
can no longer get one (see `../g5b-oracle-diff-20260918/SWIFT-RUST-PR1-REVIEW.md`).

## Decision: A, taken 2026-09-19

The owner chose **A**. The identity is recorded in
`tools/g5-known-failures/g5b-divergences-20260918.tsv` as class
`stricter-than-aws`, pointing at this document.

What that does and does not mean:

- It does **not** change engine behavior. Governance bypass still requires the
  header *and* an explicit IAM Allow, and the two pinned unit tests stand.
- It does **not** hide the difference. The class name states that Rust is
  stricter than AWS, the divergence file is separate from the earned policy, and
  the scorer only counts it when explicitly given `--divergences`, printing the
  identity and this document reference every time.
- **Option B stays open.** Accepting the divergence records today's reality; it
  is not a verdict that owner-implicit bypass is wrong. If parity with AWS, RGW
  and Python Swift on this behavior is wanted later, B is the change, and the
  entry here should be removed in the same commit that lands it.

Whichever is chosen, `test_object_lock_changing_mode_from_governance_without_bypass`
(the companion negative test at `test_s3.py:13565`) must keep passing — it
already does.
