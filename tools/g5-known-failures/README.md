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

| Identity | What it is | Action |
|---|---|---|
| `s3tests.functional.test_headers:test_object_create_bad_contentlength_mismatch_above` | Configuration, not a defect. Both engines answer `400 RequestTimeout`; Python at 60.1s (default), Rust at 600.4s (lab `client_timeout = 600`), longer than the harness waits. | Set `client_timeout = 60` on the lab Rust proxy to match the oracle. Lab-plane config change, needs owner sign-off. Deliberately **not** frozen as a known failure, because hiding a config mismatch is what G2 exists to prevent. |
| `s3tests_boto3.functional.test_s3:test_buckets_create_then_list` | Transient. Its `NameError` only fires when a just-created bucket is missing from ListBuckets; 10 rounds × 5 buckets showed 0 missing. | Fix the degraded lab replication (G1) recorded in `../test-results/g5b-classify-20260918/LAB-FINDINGS.md`, then re-run. |
| `s3tests_boto3.functional.test_s3:test_object_lock_changing_mode_from_governance_with_bypass` | A genuine Rust gap: `AccessDenied` from `PutObjectRetention` with governance bypass, where Python Swift passes. | Inside the owner's `BypassGovernanceRetention` tip-ask NO wall. Needs the wall lifted before anyone digs. |

So closing G5-B needs one config alignment, one environment fix, and one wall
lift — no other engine work on this suite.

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
