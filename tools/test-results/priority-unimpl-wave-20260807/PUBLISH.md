# Publish record · 2026-08-07 P0 residual wave

## Git

| Item | Value |
|------|--------|
| Repo | https://github.com/0smboy/Peregrine |
| Branch | `build/phase1-deploy-rs-lb` |
| Code | `ed24ebb` — S3 P0 residuals (chunk-sig, WORM bypass, grant/ACP, lifecycle Transition) |
| Docs site content | `bb774ea` — parity.mdx refresh |
| P1 workflows | `56b4011` — four parallel residual workflows |

## Strict gate (pre-publish)

`cargo test -p swift-s3api --lib` → **176 passed / 0 failed**

## Google Drive

`gdrive:Peregrine/2026-08-07-priority-unimpl/`

- priority-unimpl-wave-20260807/
- impl-chunk-sig-enforce-20260807/
- impl-worm-governance-bypass-20260807/
- impl-grant-acp-acl-20260807/
- impl-lifecycle-transitions-20260807/
- docs/RUST-VS-PYTHON-PARITY.md
- docs-site/parity.mdx (+ dist/parity snapshot)
- GDRIVE-INDEX.md

## Docs site (Vercel production)

- **Live alias:** https://peregrine-docs-ochre.vercel.app  
- **Parity page:** https://peregrine-docs-ochre.vercel.app/parity  
- Deploy: `vercel --prod` as `0smboy` (proxy cleared) → Aliased production

## P1 wave (running after publish)

| Workflow | Item |
|----------|------|
| `impl-listobjects-s3cmd-xml` | ListObjects / s3cmd ls XML |
| `impl-listversions-pagination` | ListVersions markers |
| `impl-trailer-chunk-sig` | Trailer signatures |
| `impl-acl-grant-enforcement` | ACP grant enforcement subset |

Backlog: `tools/test-results/priority-p1-wave-20260807/00-P1-BACKLOG.md`
