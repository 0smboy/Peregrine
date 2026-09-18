# G5-B dual-oracle exact-name diff — 2026-09-18

The G0–G8 execution directive requires the Python oracle to run **first**, and
forbids scoring Rust on a bad baseline:

> Python baseline 先跑。若 Python 对 pinned known-failures 仍有 unexpected
> failure/error/skip，先修实验室,禁止用坏 baseline 测 Rust。
> — `docs/fairness-lab/PEREGRINE-FOUR-NODE-G0-G8-EXECUTION-DIRECTIVE-20260822.md:259`

No Python baseline existed for the G5-B identity set, so every census up to
2026-09-15 reported raw Rust PASS counts with nothing to compare them against.
This is that baseline and the resulting diff.

## Runs compared

| Side | Detail |
|---|---|
| Rust | `G5B-live-9531eb62`, tip `9531eb62`, 726 testcases, PASS=484 F+E=159, harvested 2026-09-15T00:58:55Z |
| Python | `G5B-pybaseline-20260918`, Python Swift **2.33.0** s3api @ `10.0.0.2:8090`, same 725 identities, started 2026-09-18T05:40:03Z, ended 06:04:05Z, `EXIT=1`, SKIP=82 errors=258 failures=130 (F+E=388) |

Same suite tree, same identity list (extracted from the Rust census xunit), same
`AWS_DEFAULT_REGION=us-east-1`. Reproduce the diff with:

```bash
tools/g5b-oracle-diff.py rust-census.xml pybaseline.xml
tools/g5b-oracle-diff.py rust-census.xml pybaseline.xml --names rust-only
```

## Result

| Bucket | Count | Meaning |
|---|---:|---|
| both-pass | 253 | clean on both |
| both-fail | **156** | Python Swift fails the same identity → expected, belongs in the frozen known-failure list |
| rust-only | **3** | the real Rust-attributable G5-B gap |
| python-only | 231 | Rust passes where Python Swift fails |
| skipped-either | 82 | skipped on one or both sides |

Arithmetic checks out on both sides: Rust 159 F+E = 156 + 3; Python 388 F+E =
156 + 231 + 1 module-level teardown error (not an identity).

Cross-tabulated against the signature classification in
`../g5b-classify-20260918/`:

| Reason class | both-fail | rust-only |
|---|---:|---:|
| engine | 78 | 2 |
| harness | 40 | 1 |
| swift-vs-rgw | 38 | 0 |

So the 80 records that *looked* engine-attributable by signature are 78 shared
with Python Swift. They are Swift-family capability gaps that the Ceph suite
exercises because RGW has them (SSE-C, SSE-KMS, bucket logging, object lock,
lifecycle counts, header validation, bucket policy) — not Rust regressions.

## The three Rust-only identities

### 1. `s3tests.functional.test_headers:test_object_create_bad_contentlength_mismatch_above`

The test declares `Content-Length` one byte above the body and expects
`400 RequestTimeout` (`test_headers.py:202-216`). Measured 2026-09-18 with a raw
socket that sends the short body and waits:

| Server | Outcome | Configured `client_timeout` |
|---|---|---|
| Python Swift `10.0.0.2:8090` | `400 Bad Request` / `RequestTimeout` at **60.1s** | unset → 60s default |
| Rust tip `127.0.0.1:18080` | `400 Bad Request` / `RequestTimeout` at **600.4s** | **600** (`/etc/g6-rust/proxy-server.conf:17`) |

**Not an engine defect — this is G2 configuration parity.** Both
implementations produce the same status and the same `RequestTimeout` error
code; each does it at its own configured idle-client timeout. The engine
implements the knob (`crates/swift-proxy-server/src/main.rs:541` documents
`client_timeout` as the idle-client socket timeout, default 60) and the lab
raised it 10×, which is longer than the harness is willing to wait, so the test
records `timed out` against Rust and passes against Python.

Setting `client_timeout = 60` on the lab Rust proxy to match the oracle should
close this identity without touching engine code. That is a lab-plane config
change and needs owner sign-off, so it was not made here.

Evidence: `cl600-confirm.txt` in this directory (Rust, 600.4s) and the 60.1s
Python measurement above. An earlier 20s measurement in this session was too
short to distinguish the two and is superseded.

### 2. `s3tests_boto3.functional.test_s3:test_buckets_create_then_list`

Creates 5 buckets, lists, and raises `RuntimeError(..., bucket.name)` when one
is missing — `bucket` is undefined there, so the census recorded
`name 'bucket' is not defined` (`test_s3.py:6140-6158`). The NameError is only
reachable when **a just-created bucket is absent from ListBuckets**.

Re-run directly against the tip on 2026-09-18: **10 rounds × 5 buckets, 0
missing**. It does not reproduce, so the census hit a transient. That is
consistent with the degraded lab account/container replication recorded in
`../g5b-classify-20260918/LAB-FINDINGS.md` (§2: ~15 900 `async_pending`
entries, every replicator push to `10.0.4.2` refused). Ten clean rounds is not
proof of absence; it does rule out a deterministic defect.

### 3. `s3tests_boto3.functional.test_s3:test_object_lock_changing_mode_from_governance_with_bypass`

`AccessDenied` from `PutObjectRetention` with governance bypass, where Python
Swift passes. This is a genuine Rust gap, and it sits inside the owner's
`BypassGovernanceRetention` tip-ask NO wall, so it was characterized but **not
dug into or fixed**.

## What this does and does not license

It does **not** make G5 green:

- The oracle is Python Swift 2.33.0 as deployed on swift2, **not** the upstream
  commit `541a598…` that the G0 manifest pins for the Python oracle, and the
  two deployments are not proven config-equal (G2). The 231 python-only results
  are the loudest symptom of that gap and should not be read as "Rust is
  better" until configuration parity is established.
- The oracle lacks the `test2:tester2` tenant account the Rust lab has, so
  tenant identities are not strictly comparable.
- The Rust side was measured on a lab whose container replication is broken,
  which is a G1 problem the directive says to fix before scoring.
- G5-A (`test/s3api`) was not run on this tip at all.

It does establish that the owner override in force since 2026-09-15 — "full
~725 all green before G0–G6 is accepted" — cannot be satisfied by engine work:
**156 of the 159 failures are shared with the reference implementation**, and
the reference itself fails 388 of the same 725. Meeting the bar literally would
require the Rust engine to diverge from Python Swift on 156 identities.

After characterizing the three, the residue attributable to Rust *product
behavior* on the whole pinned Ceph suite is **one identity**, the object-lock
governance-bypass case, and it sits inside an owner wall. The other two are a
configuration difference (G2) and a transient consistent with the degraded lab
(G1). The remaining distance to G0–G7 is therefore not a pile of product
defects; it is one walled behavior plus the unrun gates (G4, G5-A, G7), the
broken lab replication, and the missing G0 identity for the tip line.

The canonical G5 contract ("capability/known-failure policy, exact-name diff,
unexpected test names = 0") is satisfiable and hides nothing: `names-both-fail.txt`
is the candidate frozen known-failure list, and `names-rust-only.txt` is the
three-identity gap list to work.
