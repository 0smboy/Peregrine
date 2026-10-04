# Optimize A-E sync manifest — 2026-10-03

| Channel | Location |
|---------|----------|
| Content commit | `ac8a523` on `main` records the docs update and `0F-vip.md`. Product commit `06a78a6` is the green rerun (lab proxy sha `dc22cca7`). Prior product commit `0a1d590` was the RED follow-up. |
| Evidence | `tools/test-results/optimize-ae-20261003/` |
| Vercel | `dpl_DgWw1K3xfpaihYqyo6sLBT33G6dz` aliased to https://docs.myswift.rs (2026-10-03 docs update). Prior alias was `dpl_8VjUT8H5dyS4hUT3n3roAD9qCeYt`. |
| Verdict | `SUMMARY.md` and `verdict.json` (2026-10-03). Full yaml is GREEN: 20 PASS, 0 FAIL, 0 NOT RUN on swift1 `:18080`. Source `swift4:/root/work/g7-optimize-ae-20261003/out-rerun3/verdict.json`. Lab sha `dc22cca7b45e6bbc4a096f99675aeab8855282276fc9f8caaa2d6ed00f402314`. On 2026-10-04 that sha is the production proxy on swift1–4 (`0G-prod-roll.md`). Object, container, and account servers were not rolled. The production G7 suite was not re-run on `:8085`. The production cluster did not pass G7. Production readiness remains NO-GO. Console gate stays ACCEPT_WITH_WARN. Apply was not sent. Refused digest `8195ef0adca513ae7c67c2966ff4aaaa11693bfb19d4efea6bf386d7abe6a9b9`. Live https://docs.myswift.rs/swift-console/index.md should name that production sha and keep NO-GO. VIP `10.0.0.10/22` is on swift1 only (`0F-vip.md`, rechecked 2026-10-04 in `0G-prod-roll.md`). |
| Docs deploy | see Vercel row |
| Live pages | https://docs.myswift.rs/swift-console/index.md , https://docs.myswift.rs/lab-cluster/index.md , https://docs.myswift.rs/performance/index.md |
| Drive | `gdrive:Peregrine/2026-10-03-optimize-ae/` |

## Excluded on purpose

- Login keys, session cookies, `proxy-server.conf`, and the G7 harness key (it stays only in the existing frozen `swift-rust/tools/test-lab/g7/acceptance.yaml`)
- Nested checkout `peregrine/`
- `/srv/node` and host backups
