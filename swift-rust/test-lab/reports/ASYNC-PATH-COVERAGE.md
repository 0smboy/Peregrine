# ASYNC-PATH-COVERAGE (working tree 2026-08-21)

`/recon/concurrency` HTTP 200 is not activation proof.

| Path | Hyper | Native async | blocking domain only | fallback |
|---|---|---|---|---|
| Local native GET (`swift-http` `g3_activation`) | yes | yes | none | 0 |
| Local legacy Handler GET | yes | no | — | LegacyService |
| `/recon/concurrency` | excluded | 0 | — | recon ≠ activation |
| Swift PUT (live RSAIO) | unproven (old binary, no G3 names) | unproven | unknown | FAIL until redeploy |
| Swift GET (live RSAIO) | unproven | unproven | unknown | FAIL until redeploy |
| COPY / Range / SLO / EC | not exercised | — | — | NOT TESTED |
| S3 GET / PUT / MPU | Hyper intercept | **no** | `block_in_place` + sync `handle()` | **FAIL** |
| SSYNC | not exercised | — | — | NOT TESTED |

S3 ASYNC GATE = NO-GO while `crates/swift-s3api/src/middleware.rs` `handle_request_async` calls `tokio::task::block_in_place`.
