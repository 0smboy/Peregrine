# Optimize A-E sync manifest — 2026-10-03

| Channel | Location |
|---------|----------|
| Content commit | `3f5ea6a` on `main` (G7 lab fix and the 17/3 verdict). Prior A-E content was `5644a9d`. |
| Evidence | `tools/test-results/optimize-ae-20261003/` |
| Vercel | `dpl_8VjUT8H5dyS4hUT3n3roAD9qCeYt` aliased to https://docs.myswift.rs |
| Verdict | `SUMMARY.md` and `verdict.json` (2026-10-03). G7 is RED: 17 PASS, 3 FAIL, 0 blocked. NOT ACCEPTED. Console gate stays ACCEPT_WITH_WARN. Apply was not sent. |
| Docs deploy | see Vercel row |
| Live pages | https://docs.myswift.rs/swift-console/index.md , https://docs.myswift.rs/lab-cluster/index.md , https://docs.myswift.rs/performance/index.md |
| Drive | `gdrive:Peregrine/2026-10-03-optimize-ae/` |

## Excluded on purpose

- Login keys, session cookies, `proxy-server.conf`, and the G7 harness key (it stays only in the existing frozen `swift-rust/tools/test-lab/g7/acceptance.yaml`)
- Nested checkout `peregrine/`
- `/srv/node` and host backups
