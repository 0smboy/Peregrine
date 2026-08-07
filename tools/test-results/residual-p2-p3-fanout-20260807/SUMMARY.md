# Residual fan-out (screenshot P2/P3 except TLS) · 2026-08-07

Four workflows registered + executed (validate + real runs + local cargo):

| # | Workflow | Item | Verdict |
|---|----------|------|---------|
| 1 | `residual-slo-edge` | SLO inline / heartbeat / multipart-delete | **KEEP unit 24/24** |
| 2 | `residual-s3-surface` | S3 ACL/CORS/SigV2/chunked/versioning | **CORS+canned KEEP**; SigV2/chunked/versioning **WONTFIX 501**; full IAM residual |
| 3 | `residual-pipeline-account` | unknown Paste filter; allow_account_management | **`strict_pipeline` closed residual**; allow_account **KEEP** |
| 4 | `residual-workers-semantics` | eventlet workers equivalence | **tooling KEEP**; process model residual documented |

## Workflow paths
- `~/.grok/workflows/residual-*.rhai`
- `Peregrine/.grok/workflows/residual-*.rhai`
- `swift-master/.grok/workflows/residual-*.rhai`

## Code change
- `swift-proxy-server`: `strict_pipeline` conf (default false) hard-fails unknown/unimplemented filters when true.

## Evidence dirs
- `tools/test-results/residual-slo-edge-20260807/`
- `tools/test-results/residual-s3-surface-20260807/`
- `tools/test-results/residual-pipeline-account-20260807/`
- `tools/test-results/residual-workers-semantics-20260807/`

## Still out of scope (not claimed)
- PRODUCTION-GO-LIVE / operator TLS PEM (excluded by request)
- Full IAM grant-header S3 ACL implementation
- True eventlet multi-process workers clone on proxy
