# Hard residual fan-out · 2026-08-07

Four workflows + parallel agents:

| # | Item | Workflow | Verdict |
|---|------|----------|---------|
| 1 | SLO expirer hash / async ACL | `impl-slo-expirer-hash` | **KEEP unit 27/27** |
| 2 | aws-chunked / STREAMING-* | `impl-aws-chunked` | **IMPLEMENTED** dechunk (unit 117/117 s3api) |
| 3 | versioning/tagging/lifecycle/object-lock | `impl-s3-versioning-surface` | **subresource API KEEP**; multi-version bodies residual |
| 4 | Full ansible v3 surface | `impl-ansible-v3-surface` | **PARTIAL/GREEN** matrix; not full twin |

Evidence dirs: `impl-slo-expirer-hash-20260807/`, `impl-aws-chunked-20260807/`, `impl-s3-versioning-surface-20260807/`, `impl-ansible-v3-surface-20260807/`
