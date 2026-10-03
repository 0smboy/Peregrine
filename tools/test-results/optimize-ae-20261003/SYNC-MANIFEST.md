# Optimize A-E sync manifest — 2026-10-03

| Channel | Location |
|---------|----------|
| Content commit | Follow-up G7 build is on `main` after `f28caf4`. Prior full matrix was `3f5ea6a` (17 PASS, 3 FAIL on sha `e6ac2931`). |
| Evidence | `tools/test-results/optimize-ae-20261003/` |
| Vercel | `dpl_8VjUT8H5dyS4hUT3n3roAD9qCeYt` aliased to https://docs.myswift.rs |
| Verdict | `SUMMARY.md` and `verdict.json` (2026-10-03). Follow-up is RED: 1 PASS, 3 FAIL, 16 NOT RUN. NOT ACCEPTED. Lab sha `3bac7c9ce904a39476009549eb568f4356dfe4336aa4d39416604c1aaebc3dc5`. Console gate stays ACCEPT_WITH_WARN. Apply was not sent. |
| Docs deploy | see Vercel row |
| Live pages | https://docs.myswift.rs/swift-console/index.md , https://docs.myswift.rs/lab-cluster/index.md , https://docs.myswift.rs/performance/index.md |
| Drive | `gdrive:Peregrine/2026-10-03-optimize-ae/` |

## Excluded on purpose

- Login keys, session cookies, `proxy-server.conf`, and the G7 harness key (it stays only in the existing frozen `swift-rust/tools/test-lab/g7/acceptance.yaml`)
- Nested checkout `peregrine/`
- `/srv/node` and host backups
