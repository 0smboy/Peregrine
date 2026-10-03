# Optimize A-E sync manifest — 2026-10-03

| Channel | Location |
|---------|----------|
| Evidence | `tools/test-results/optimize-ae-20261003/` |
| Verdict | `SUMMARY.md` and `verdict.json` (2026-10-03). G7 is NOT ACCEPTED. Console gate stays ACCEPT_WITH_WARN. Apply was not sent. |
| Docs deploy | Vercel production `dpl_8VjUT8H5dyS4hUT3n3roAD9qCeYt`, alias https://docs.myswift.rs |
| Live pages | https://docs.myswift.rs/swift-console/index.md , https://docs.myswift.rs/lab-cluster/index.md , https://docs.myswift.rs/performance/index.md |
| Drive | `gdrive:Peregrine/2026-10-03-optimize-ae/` |

## Excluded on purpose

- Login keys, session cookies, `proxy-server.conf`, and the G7 harness key (it stays only in the existing frozen `swift-rust/tools/test-lab/g7/acceptance.yaml`)
- Nested checkout `peregrine/`
- `/srv/node` and host backups
