# G5-B census re-attribution — 2026-09-18

Re-attribution of the 159 FAIL+ERROR records from the 2026-09-15 G5-B census
(Ceph s3compat, 726 identities, lab tip `9531eb62`, PASS=484 F+E=159).

Nothing here changes the census numbers. It answers a different question:
**how many of the 159 are attributable to the Rust engine at all?**

## Result

| Class | Count | Meaning |
|---|---:|---|
| harness | 41 | the test never reached the engine |
| swift-vs-rgw | 38 | Python Swift answers the same way, so not a Rust regression |
| engine | 80 | engine-side gap or defect |

Reproduce:

```bash
tools/g5b-classify.py tools/test-results/g5b-classify-20260918/fail_error_names-9531eb62.txt
tools/g5b-classify.py ... --names swift-vs-rgw   # per-class test names
```

## Why 41 are harness

- **34** `test_sts` records are `Your config file is missing the "iam" section!`
  or `"webidentity" section!`. The suite config
  (`PREFLIGHT-9531eb62.txt` → `ceph-s3.live-13be1dbc.cfg`) has neither section;
  verified on swift1 2026-09-18 (`grep -cE '^\[(iam|webidentity)\]'` → 0).
  These abort in the harness before a single request is signed. The `sts34`
  theme bin, the largest in the census, contains no engine evidence at all.
- **3** `Parameter validation failed` — botocore rejected the bucket name
  locally; no request left the client.
- **1** `'str' object has no attribute 'decode'` — py2-era test body on py3
  (the H90 "soft leftover").
- **1** `name 'bucket' is not defined` — defect in the test body.
- **1** `object has no attribute 'status'` — test reads a boto2 attribute off a
  boto3 exception.
- **1** `Could not connect to the endpoint URL: "http://localhost:8000/..."` —
  the tenant test points at an endpoint this lab does not run.

## Why 38 are swift-vs-rgw

The load-bearing one is **31 × `BucketAlreadyOwnedByYou`**, and it was measured,
not assumed. `tools/s3-probe-sigv4.py` on 2026-09-18 asked three servers to
create a bucket and then create the same bucket again as the same owner:

| Server | create #1 | create #2 (same owner) |
|---|---|---|
| Rust tip `9531eb62` @ `10.0.0.1:18080` | 200 | **409 BucketAlreadyOwnedByYou** |
| Python Swift 2.38.0 s3api @ swift1 `127.0.0.1:8090` | 200 | **409 BucketAlreadyOwnedByYou** |
| Python Swift 2.33.0 s3api @ `10.0.0.2:8090` | 200 | **409 BucketAlreadyOwnedByYou** |

Both Swift implementations agree; the suite expects the RGW/us-east-1 answer of
200. Of those 31, **29 are the entire `select29` theme bin**: every test in
`s3tests_boto3/functional/test_s3select.py` hardcodes `bucket_name = "test"`
and re-creates it in `upload_csv_object()`, so from the second test onward they
all abort in setup and **never reach the S3 Select code path**. The `select29`
bin is therefore not evidence about S3 Select.

The remaining 7: 3 RGW object-append (`501 Not Implemented` for an extension
outside the AWS S3 and Swift surface), 3 RGW usage/extended-head
(`X-RGW-Object-Count`, `subresource 'usage'`), 1 ACL grant-by-email
(`UnresolvableGrantByEmailAddress`, needs an RGW-style account directory).
These 7 are reasoned from the API surface, not probed; the 31 are probed.

## The 80 engine records

Largest groups: header validation 14, object-lock delete/retention 13, SSE-C
12, lifecycle counts 9, SSE-KMS 9 (+2), bucket policy 8, wrong error code
`BucketNotEmpty` on PutObject/UploadPart 4, presign expires range 3.

Two notes on these:

- SSE-KMS (11 total) and bucket logging (2) are honest "unimplemented
  capability" answers from the engine, not defects.
- The 4 `BucketNotEmpty` records answer a PutObject/UploadPart with a
  bucket-delete error code. That is an error-mapping defect, and it may be
  aggravated by the degraded lab container replication recorded in
  `LAB-FINDINGS.md`.

`engine = 80` is an upper bound pending the Python baseline run
(`G5B-pybaseline-20260918` on swift2), which scores the same 725 identities
against Python Swift so that expected-vs-unexpected can be settled by exact
name instead of by signature reasoning.

## Consequence for the acceptance bar

The owner override that ran from 2026-09-15 was "full ~725 all green before
G0–G6 is accepted". 41 of the 159 could not go green without editing the frozen
harness, and 38 could not go green unless the Rust engine deliberately diverged
from Python Swift. That bar could not be met by engine work, and meeting part of
it would have damaged parity.

**Withdrawn 2026-09-18 (option C).** G5 is now scored against the frozen policy
in `tools/g5-known-failures/`; see that README and
`docs-site/src/content/docs/validation-gates.mdx`.

The canonical G5 contract in `docs-site/src/content/docs/validation-gates.mdx`
("capability/known-failure policy, exact-name diff, unexpected test names = 0")
is satisfiable and does not hide anything, because every excluded identity is
named in `names-harness.txt` / `names-swift-vs-rgw.txt` with its reason.
