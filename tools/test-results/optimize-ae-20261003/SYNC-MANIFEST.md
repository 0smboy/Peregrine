# Optimize A-E sync manifest — 2026-10-03

| Channel | Location |
|---------|----------|
| Content commit | The working tree records the 2026-10-04 full production yaml: 20 PASS, 0 FAIL, 0 NOT RUN (`verdict-prod.json`, source `swift4:/root/work/g7-prod-20261004-r21/verdict.json`). |
| Evidence | `tools/test-results/optimize-ae-20261003/` |
| Vercel | https://peregrine-docs-bq9en2w5z-0smboys-projects.vercel.app aliased to https://docs.myswift.rs (2026-10-04). Prior alias was `dpl_8YUDUoba7UjQ9gZi1RLAcNhJJkyF`. |
| Verdict | Lab `verdict.json` (2026-10-03) is GREEN: 20 PASS, 0 FAIL, 0 NOT RUN on swift1 `:18080`. The last full production yaml `verdict-prod.json` (2026-10-04) is GREEN: 20 PASS, 0 FAIL, 0 NOT RUN on `http://10.0.0.10:8080`. A same-day re-run of those four failures records `slow_put_1000` PASS (http_2xx 1000, http_503 0) and passed `sqlite_stall`, `bounded_queue_overload`, and `sigterm_during_durability` (`0I-g7-prod.md`). The full yaml is the 20-case run. Production readiness is GO. Console gate stays ACCEPT_WITH_WARN. hkserver joined (`0H-hkserver.md`). Apply digest `9c78c318b439ee077cb5c56953a2d188af2da3af28908cc52eb3c3a73f0ce5b8`. Proxy sha256 `ce738dc3a7adb01167c16660924e79a1e215a3245d5d90bbe682d36b7cfa5696` on swift1–4 and hkserver. Object sha256 `feae2bc515e1ea2141d4f7cfd96292e0b9166f9b51afc3b9a7031c5cee83a629`. `16MB_read_8` is ACCEPT (`0J-16mb.md`, 2026-10-04). VIP `10.0.0.10/22` is on swift1 only. |
| Docs deploy | see Vercel row |
| Live pages | https://docs.myswift.rs/swift-console/index.md , https://docs.myswift.rs/lab-cluster/index.md , https://docs.myswift.rs/performance/index.md |
| Drive | `gdrive:Peregrine/2026-10-04-hkserver-g7/` |

## Excluded on purpose

- Login keys, session cookies, `proxy-server.conf`, and the G7 harness key (it stays only in the existing frozen `swift-rust/tools/test-lab/g7/acceptance.yaml`)
- Nested checkout `peregrine/`
- `/srv/node` and host backups
