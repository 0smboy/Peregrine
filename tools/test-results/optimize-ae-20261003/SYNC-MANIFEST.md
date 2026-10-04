# Optimize A-E sync manifest — 2026-10-03

| Channel | Location |
|---------|----------|
| Content commit | `1b02099` on `main` records the production proxy roll, the empty-host identity plan, and `0G-prod-roll.md`. Prior docs commit `ac8a523` recorded `0F-vip.md`. Product commit `06a78a6` is the green lab rerun (lab proxy sha `dc22cca7`). |
| Evidence | `tools/test-results/optimize-ae-20261003/` |
| Vercel | `dpl_AxCU3E2vkoawARKpUxsb4qoyBGak` aliased to https://docs.myswift.rs (2026-10-04). Prior alias was `dpl_144wEYkec6nb5sQ3T3iJd6M4BJWJ`. |
| Verdict | Lab `verdict.json` (2026-10-03) is GREEN: 20 PASS, 0 FAIL, 0 NOT RUN on swift1 `:18080`. Production `verdict-prod.json` (2026-10-04) is RED: 3 PASS, 17 FAIL, 0 NOT RUN on `http://10.0.0.10:8080`. Production readiness remains NO-GO. Console gate stays ACCEPT_WITH_WARN. hkserver joined (`0H-hkserver.md`). Apply digest `9c78c318b439ee077cb5c56953a2d188af2da3af28908cc52eb3c3a73f0ce5b8`. Proxy sha256 `167b6622a6aeb7065eeeb20dc8918f0296f06ec65f73b12322679fcad0f85012` on swift1–4 and hkserver. `16MB_read_8` is ACCEPT (`0J-16mb.md`, 2026-10-04). VIP `10.0.0.10/22` is on swift1 only. |
| Docs deploy | see Vercel row |
| Live pages | https://docs.myswift.rs/swift-console/index.md , https://docs.myswift.rs/lab-cluster/index.md , https://docs.myswift.rs/performance/index.md |
| Drive | `gdrive:Peregrine/2026-10-04-hkserver-g7/` |

## Excluded on purpose

- Login keys, session cookies, `proxy-server.conf`, and the G7 harness key (it stays only in the existing frozen `swift-rust/tools/test-lab/g7/acceptance.yaml`)
- Nested checkout `peregrine/`
- `/srv/node` and host backups
