# Optimize A-E sync manifest — 2026-10-03

| Channel | Location |
|---------|----------|
| Content commit | `06a78a6` on `main` (2026-10-03 green rerun, lab proxy sha `dc22cca7`). Prior product commit `0a1d590` was the RED follow-up. |
| Evidence | `tools/test-results/optimize-ae-20261003/` |
| Vercel | `dpl_8VjUT8H5dyS4hUT3n3roAD9qCeYt` aliased to https://docs.myswift.rs |
| Verdict | `SUMMARY.md` and `verdict.json` (2026-10-03). Full yaml is GREEN: 20 PASS, 0 FAIL, 0 NOT RUN. Source `swift4:/root/work/g7-optimize-ae-20261003/out-rerun3/verdict.json`. Lab sha `dc22cca7b45e6bbc4a096f99675aeab8855282276fc9f8caaa2d6ed00f402314`. Console gate stays ACCEPT_WITH_WARN. Apply was not sent. Docs-site was not edited. |
| Docs deploy | see Vercel row |
| Live pages | https://docs.myswift.rs/swift-console/index.md , https://docs.myswift.rs/lab-cluster/index.md , https://docs.myswift.rs/performance/index.md |
| Drive | `gdrive:Peregrine/2026-10-03-optimize-ae/` |

## Excluded on purpose

- Login keys, session cookies, `proxy-server.conf`, and the G7 harness key (it stays only in the existing frozen `swift-rust/tools/test-lab/g7/acceptance.yaml`)
- Nested checkout `peregrine/`
- `/srv/node` and host backups
