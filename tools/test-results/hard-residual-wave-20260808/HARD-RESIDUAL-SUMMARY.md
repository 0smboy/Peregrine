# Hard residual wave 2026-08-08 — LAB-HARD-GREEN

Scope: items **1,2,3,4,6,10** (excluded 5 KMIP, 7 multi-cluster soak, 8 Operator PEM, 9 Ansible twin).

| # | Item | Verdict | Evidence |
|---|------|---------|----------|
| 1 | SigV2 auth | **KEEP** | `swift-s3api` sigv2 module + middleware path; AWS vector + 11 tests; full lib 220/220 |
| 2 | Unlimited third-party Paste plugins | **KEEP** | `PluginRegistry` + default NamedPassthrough; proxy `plugin_default`; pipeline tests 17/17 |
| 3 | Multi-tenant IAM product | **KEEP** | `iam::IamService` tenants + policy Allow/Deny; wired into `S3Api::dispatch_authorized` gate |
| 4 | Physical Glacier/tape tier | **KEEP** | `cold_tier` storage-policy map + MemoryColdBackend; `S3Api.cold_map` field + unit tests |
| 6 | Multi-primary auto-shrink + soak | **KEEP** | multi-device shrink test + `auto_shrink` opt + soak harness |
| 10 | Eventlet greenlet semantics | **KEEP** | `swift_http::eventlet_parity` greenthread pool / yield / concurrency formula |

## Cargo gates (orchestrator)

```
cargo test -p swift-s3api --lib                     # 220 ok
cargo test -p swift-http --lib eventlet_parity      # 5 ok
cargo test -p swift-middleware --lib plugin_registry # 4 ok
cargo test -p swift-container-server --lib sharder  # 24 ok
cargo test -p swift-proxy-server --bin … pipeline   # 17 ok
SOAK_SECONDS=… tools/soak/multi-primary-shrink-soak.sh
```

## Claim boundary

LAB-HARD-GREEN unit + local multi-device. Not PRODUCTION-GO-LIVE for Contabo multi-hour live shrink
or physical tape hardware — soak harness exists; run with SOAK_SECONDS=7200 on LAB when ready.

## Files

- `swift-s3api/src/sigv2.rs`, middleware SigV2 path
- `swift-s3api/src/iam.rs` (IamService)
- `swift-s3api/src/cold_tier.rs`
- `swift-middleware/src/plugin_registry.rs` + proxy wiring
- `swift-http/src/eventlet_parity.rs`
- `swift-container-server/src/sharder.rs` auto_shrink + multi-device test
- `tools/soak/multi-primary-shrink-soak.sh`
