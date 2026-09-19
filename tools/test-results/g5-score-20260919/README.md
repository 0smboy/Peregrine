# G5-B full 725 under the new contract — 2026-09-19

First full-suite run since the owner took option C (frozen known-failure policy)
and option A (accepting the object-lock divergence), and the first with the lab
`client_timeout` aligned to the oracle.

## Run

| Field | Value |
|---|---|
| Tip | `9531eb621ee86c15dac050d883b68f097f775c67198947506ffc7dab806794e8` (unchanged; config-only reload) |
| Live worker | pid 621728, exe not `(deleted)` |
| `client_timeout` | **60** (was 600) |
| Identities | 725 |
| Wall | 1719.8 s (~29 min), `EXIT=1` |
| Raw nosetests | SKIP=82, errors=111, failures=47 → F+E **158** (was 159) |
| swift1 root free at start | 9.1 GiB (after stashing 6.3 GiB of dead test residue) |

## Score

```
passed                : 485
expected failure      : 156   (78 swift-family-gap, 40 harness-blocked, 38 not-applicable-rgw)
accepted divergence   :   1   stricter-than-aws (object-lock governance bypass)
unexpected failure    :   1   s3tests_boto3.functional.test_s3:test_buckets_create_then_list
unexpected skip       :   0
stale policy entries  :   0
G5 verdict            : FAIL
```

Strict view without `--divergences` is committed alongside: unexpected 2.

## What moved, and what did not

The `client_timeout` alignment closed one identity for good:
`test_object_create_bad_contentlength_mismatch_above` went from ERROR (`timed
out`) to **pass**, which is the +1 in passed (484 → 485) and the −1 in F+E.

`test_buckets_create_then_list` **failed again**, with the same
`name 'bucket' is not defined` — the test's NameError path, reachable only when a
just-created bucket is missing from ListBuckets. Its history is now informative:

| Run | Outcome |
|---|---|
| 2026-09-15 full 725 | fail |
| 2026-09-18, 10 isolated rounds × 5 buckets | 0 missing, pass |
| 2026-09-18 scoped 106-identity run | pass |
| 2026-09-19 full 725 | fail |

It fails under full-suite load and passes in isolation. That is consistent with
the account/container replication defect in
`../g5b-classify-20260918/LAB-FINDINGS.md` §2: with the `async_pending` backlog
at ≈20 994 entries after this run (≈15 900 before it) and every replicator push
refused, a container creation can be visible
on the container layer before the account listing catches up, so ListBuckets
misses it. Under load the window widens.

**So the last unexpected G5-B identity is an environment defect, not a product
defect.** No engine change can close it; fixing the lab can. Zero unexpected on
this suite is one G1 repair away.

## Standing caveats (unchanged)

A score of 0 unexpected here still would not make G5 green:

- the policy is frozen against Python Swift **2.33.0 as deployed on swift2**,
  not the G0-pinned upstream oracle commit `541a598…`;
- configuration parity between the two deployments (G2) is unproven, and the
  231 python-only results are the symptom;
- the Rust side is measured on a lab whose container replication is broken,
  which the execution directive says to fix *before* scoring
  (`docs/fairness-lab/PEREGRINE-FOUR-NODE-G0-G8-EXECUTION-DIRECTIVE-20260822.md:259`);
- G5-A (Swift in-tree `test/s3api`) has never been run on this tip;
- the `9531eb62` tip line is permanently G0-incapable.

## Reproduce

```bash
tools/g5-score.py full725-clienttimeout60-20260919.xml \
  --policy      ../../g5-known-failures/g5b-ceph-s3compat-20260918.tsv \
  --divergences ../../g5-known-failures/g5b-divergences-20260918.tsv
```

## Disk note

The run needed headroom swift1 did not have (2.8 GiB free against ~3.5 GiB of
run growth). 99 object partitions whose mtime predated 2026-09-16 were moved
from all three lab devices into `/srv/node/d1/reclaim-stash-20260919/`
(6.3 GiB), taking root from 2.8 to 9.1 GiB free; it ended the run at 5.4 GiB.
Moving the same partitions from **all three** replicas is deliberate — removing
one replica only would let the object replicator rebuild it and re-consume the
space. `/srv/node/d{1,2,3}` production data was not touched.
