# G5 known-failure policy

Owner decision, 2026-09-18: **option C**. The "raw ~725 all green" override is
replaced by the canonical G5 contract already written in
`docs-site/src/content/docs/validation-gates.mdx`:

> official S3 compatibility | Swift `test/s3api`, pinned Ceph `s3-tests`,
> capability/known-failure policy, exact-name diff | **unexpected test names = 0**

This directory holds the frozen policy that makes that scorable.

## Why the override had to go

The Ceph suite asserts RGW behavior, so a raw Rust failure count cannot say
whether a failure is a Rust regression. The paired run on 2026-09-18
(`../test-results/g5b-oracle-diff-20260918/`) measured it: of the 159 FAIL+ERROR
records at tip `9531eb62`, **156 also fail on Python Swift**, and the reference
implementation fails **388** of the same 725 identities. Requiring all 725 to
pass would have required the Rust engine to deliberately diverge from Python
Swift on 156 identities.

## The rule that keeps this from becoming an alibi

> An identity may be frozen expected-fail **only if** the Python Swift oracle
> fails it too in the paired baseline run, or the harness cannot execute it.

Consequences that matter:

- Anything failing on Rust while the oracle passes is **withheld from the list
  on purpose**, so it scores as unexpected and stays visible.
- A frozen entry that starts passing is reported as a **stale entry and fails
  the gate**, forcing a re-freeze. A list that keeps entries after they pass
  stops describing the system.
- The list is not a blanket excuse, and that is checked: scoring the Python
  baseline itself against this policy yields **231 unexpected failures**.

## Current policy

`g5b-ceph-s3compat-20260918.tsv` — 238 entries over the 725-identity set:

| Class | Count | Meaning |
|---|---:|---|
| expected-skip | 82 | skipped by both sides |
| swift-family-gap | 78 | both Swift implementations lack the behavior (SSE-C, SSE-KMS, bucket logging, object lock, lifecycle counts, header validation, bucket policy) |
| harness-blocked | 40 | the suite never reaches the engine (34 are `test_sts`, aborting because the config has no `[iam]`/`[webidentity]` section) |
| not-applicable-rgw | 38 | RGW-only surface: 31 same-owner `CreateBucket` idempotency, 3 object-append, 3 usage/extended-head, 1 ACL grant-by-email |

## Verdict for tip `9531eb62` under this policy

```
$ tools/g5-score.py rust-census.xml --policy tools/g5-known-failures/g5b-ceph-s3compat-20260918.tsv
passed                : 484
expected failure      : 156
unexpected failure    : 3
unexpected skip       : 0
stale policy entries  : 0
G5 verdict under this policy: FAIL
```

**G5-B is FAIL with exactly three unexpected identities** — not green, but the
gap is now three named things instead of an opaque 159:

| Identity | What it is | Status |
|---|---|---|
| `s3tests.functional.test_headers:test_object_create_bad_contentlength_mismatch_above` | Configuration, not a defect. Both engines answer `400 RequestTimeout`; Python at 60.1s (default), Rust at 600.4s (lab `client_timeout = 600`), longer than the harness waits. | **Closed 2026-09-18.** Owner approved aligning the lab: `client_timeout` 600 → 60 in `/etc/g6-rust/proxy-server.conf`, reloaded through the overseer's `USR1` contract (tip binary and sha unchanged). The probe now answers at 60.2s and the identity **passes** in a scored run. Deliberately never frozen as a known failure — hiding a config mismatch is what G2 exists to prevent. |
| `s3tests_boto3.functional.test_s3:test_buckets_create_then_list` | Transient. Its `NameError` only fires when a just-created bucket is missing from ListBuckets; 10 rounds × 5 buckets showed 0 missing. | **Passed** in the 2026-09-18 scored re-run. The underlying cause — degraded lab replication (G1, `../test-results/g5b-classify-20260918/LAB-FINDINGS.md`) — is still unfixed, so it can recur. |
| `s3tests_boto3.functional.test_s3:test_object_lock_changing_mode_from_governance_with_bypass` | Wall lifted 2026-09-18 and dug. **Not an oversight**: the engine deliberately requires the bypass header *and* an explicit IAM Allow, pinned by two unit tests, and is stricter than AWS, RGW, and Python Swift. | Awaiting an owner choice between recording it as a deliberate divergence and changing the authorization rule. Full analysis: `../test-results/g5-score-20260918/WALL-LIFT-OBJECT-LOCK-BYPASS.md`. |

After the config alignment, the scoped re-run of all 104 `test_headers`
identities plus these two scored **55 passed, 13 expected, 0 unexpected skips,
0 stale, 1 unexpected** — the unexpected being only the object-lock divergence.
No regression appeared from the timeout change.

## Deliberate divergences

`g5b-divergences-20260918.tsv` is a separate, hand-curated list for Rust-only
failures the engine chose on purpose. It is **not loaded unless you pass
`--divergences`**, because accepting one is an owner decision rather than a
measurement, and every entry must name the document that justifies it.

One entry, accepted by the owner on 2026-09-19: the object-lock
governance-bypass identity, class `stricter-than-aws`. Accepting it changed no
engine behavior — bypass still requires the header *and* an explicit IAM Allow,
and both pinned unit tests stand. It records that the engine is deliberately
stricter than AWS, RGW and Python Swift on this one behavior, and leaves the
parity fix (option B in the linked analysis) open as engine work for a candidate
that has a G0 identity from the start.

So the canonical G5-B invocation is now:

```bash
tools/g5-score.py RUN.xml \
  --policy       tools/g5-known-failures/g5b-ceph-s3compat-20260918.tsv \
  --divergences  tools/g5-known-failures/g5b-divergences-20260918.tsv
```

Dropping `--divergences` is still a valid and useful run: it answers "what would
fail if we held ourselves to the suite's expectation exactly", and that number
should be reported alongside, never replaced.

Keeping these out of the generated policy is deliberate: the generated file
earns its entries from the oracle, so mixing in a product decision would
destroy that property. With the object-lock entry accepted the same scoped run
reads `accepted divergence: 1, unexpected: 0 → PASS`; without it, `unexpected:
1 → FAIL`. Both views are committed side by side in
`../test-results/g5-score-20260918/`.

## What option C does not do

It does not make G5 green, and it does not by itself satisfy G5 formally:

- The oracle is Python Swift **2.33.0 as deployed on swift2**, not the upstream
  commit `541a598…` that the G0 manifest pins for the Python oracle. Re-freeze
  against the pinned oracle before any formal G5 acceptance.
- Configuration parity between the two deployments (G2) is unproven, and the
  231 python-only results are the loudest symptom of that.
- The Rust side was measured on a lab whose container replication is broken,
  which the execution directive says to fix before scoring
  (`docs/fairness-lab/PEREGRINE-FOUR-NODE-G0-G8-EXECUTION-DIRECTIVE-20260822.md:259`).
- G5-A (Swift in-tree `test/s3api`) has never been run on this tip.

## Re-freezing

Never hand-edit the policy. Re-run the pair and regenerate, so every entry keeps
a measured basis:

```bash
tools/g5-freeze-known-failures.py RUST.xml PYTHON.xml \
  --fail-error-names fail_error_names.txt \
  --out tools/g5-known-failures/g5b-ceph-s3compat-<date>.tsv
```

Keep old policy files. A diff between two dated policies is the record of what
changed in the capability surface, on either implementation.
