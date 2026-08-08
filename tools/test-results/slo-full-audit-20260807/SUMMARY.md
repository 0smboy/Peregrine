# SLO full-function audit · 2026-08-07

**Claim boundary:** LAB-HARD-GREEN · not PRODUCTION-GO-LIVE  
**Tools:** unit (`cargo`), Contabo live VIP (`curl` TempAuth), `s3cmd` SigV4 MPU

---

## Verdict: **SLO functional surface KEEP / complete for product path**

No missing **client-visible** SLO capability required reimplementation.  
First-pass FAIL rows were either **intentional rejections**, **probe mistakes**, or **fixed by re-probe**.

| Layer | Gate | Result |
|-------|------|--------|
| Unit `slo::` | `cargo test -p swift-middleware --lib slo::` | **27/27 PASS** |
| Integration put validation | `cargo test -p swift-middleware --test slo_put_validation` | **6/6 PASS** |
| Copy manifest-aware | `copy::tests::test_manifest_get_copy_*` | **2/2 PASS** |
| Contabo live Swift SLO | curl matrix | **core + edges PASS** (see below) |
| Contabo s3cmd MPU → SLO | 15 MiB / 5 MiB parts | **round-trip PASS** + `X-Static-Large-Object: True` |

---

## Feature matrix (Swift SLO)

| Feature | Python | Rust unit | Contabo live | Notes |
|---------|:------:|:---------:|:------------:|-------|
| `?multipart-manifest=put` | yes | yes | **PASS** (201) | segment HEAD + etag/size validate |
| GET reassembly | yes | yes | **PASS** body exact | |
| HEAD `X-Static-Large-Object` + logical CL | yes | yes | **PASS** | |
| Range GET (single + cross-segment) | yes | yes | **PASS** 206 | bytes=0-3, 6-9 |
| Nested sub_slo GET | yes | yes | **PASS** | outer→inner reassembly |
| Inline `{"data": base64}` **mixed** with path segments | yes | yes | **PASS** | `SEGDATA1XY` |
| Inline-**only** (no object segment) | reject | reject 400 | **PASS reject** | message: *require at least one object-backed segment* |
| `heartbeat=on` put | yes | yes | **PASS** 202 | |
| `multipart-manifest=get&format=raw` | yes | yes | **PASS** | client JSON shape |
| Sync `multipart-manifest=delete` | yes | yes | **PASS** 200 bulk JSON | Number Deleted / Errors |
| Async `multipart-manifest=delete&async=yes` | yes | yes | **PASS** 204 | expirer hash + ACL probes unit KEEP |
| Expirer day-bucket hash sharding | yes | yes | unit | `impl-slo-expirer-hash` |
| Async ACL HEAD probes | yes | yes | unit | |
| Copy SLO via `X-Copy-From` | yes | yes | **PASS** reassembly | |
| Copy manifest-aware `?multipart-manifest=get` | yes | yes | **PASS** + stays SLO | `X-Static-Large-Object: True` |
| Ranged segment in manifest | yes | yes | unit | put validation |
| Sub-SLO size/etag from sysmeta | yes | yes | unit + live nested | |

### Explicitly **not** missing (first audit false alarms)

| Probe | First result | Root cause |
|-------|--------------|------------|
| pure-inline put | FAIL 400 | **By design** — same as unit `test_inline_data_only_rejected` |
| async delete on non-existent object | FAIL 404 | cascade after pure-inline failed |
| s3cmd MPU 1 MiB parts | FAIL | s3cmd requires **≥ 5 MiB** part size |
| copy with wrong Destination header | FAIL 499 | probe bug; re-probe OK |

---

## S3 / s3cmd (uses SLO under the hood)

| Check | Result |
|-------|--------|
| s3cmd put 15 MiB `--multipart-chunk-size-mb=5` | **PASS** (upload completed) |
| s3cmd get md5 == put | **PASS** `S3_MPU=PASS` |
| Swift HEAD → `x-static-large-object: True` | **PASS** |
| Logical Content-Length 15728640 | **PASS** |
| s3cmd `ls` / delete XML parse noise | **S3 ListObjects residual** (not SLO reassembly) — P1 listobjects unit KEEP; Contabo binary may lag source |

S3 CompleteMultipartUpload builds Swift `?multipart-manifest=put` (`swift-s3api` `slo_manifest_json`).

---

## Deferred vs full Python `slo.py` (non-blocking)

Documented in `slo.rs` module docs; **not** client-visible KEEP blockers for LAB-HARD-GREEN:

1. Concurrent HEAD pile + wall-clock `yield_frequency` (we yield per HEAD; heartbeat still works)
2. Container-listing SLO-etag refetch race dance
3. Bulk-delete **Accept** negotiation beyond JSON default

No code change this wave — product path is complete; above are ops/perf parity polish.

---

## Evidence paths

```
tools/test-results/slo-full-audit-20260807/
  01-cargo-slo-lib.txt
  02-cargo-slo-put-validation.txt
  03-cargo-copy-slo.txt
  live/02-swift-slo.txt
  live/03-s3cmd.txt
  live/fix.txt          # INLINE/COPY/ASYNC re-probe
  live/s3.txt           # s3cmd 15MiB MPU
  SUMMARY.md
```

Prior waves still valid: `residual-slo-edge-20260807`, `impl-slo-expirer-hash-20260807`.

---

## Bottom line

- **Swift SLO: fully implemented for all claimable product features** (put/get/head/range/nested/inline-mixed/heartbeat/raw/delete sync+async/copy/S3 MPU→SLO).  
- **No mandatory code gap** found that requires补全 before LAB-HARD-GREEN.  
- Remaining items are **documented micro-residuals** or **S3 list XML tooling**, not SLO reassembly correctness.
