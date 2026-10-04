# Console reaccept sync manifest — 2026-10-04

| Channel | Location |
|---------|----------|
| Evidence | `tools/test-results/console-reaccept-20261004/SUMMARY.md` |
| Verdict | ACCEPT_WITH_WARN. File sha256 matched on the console and on VIP `https://10.0.0.10:8085`. The bucket name is gone. Node status lists four nodes and omits hkserver. Monitor `nodes_up` is 4.0. |
| Production G7 | 20 PASS, 0 FAIL, 0 NOT RUN, GO. `tools/test-results/optimize-ae-20261003/verdict-prod.json` is the copy of `swift4:/root/work/g7-prod-20261004-r21/verdict.json`. Drive object `verdict-prod-r21.json`, id `18v832QtB3_xH5O1BMsVTUSrE6iOE2xL7`. |
| Docs deploy | https://peregrine-docs-5t98nzvgd-0smboys-projects.vercel.app aliased to https://docs.myswift.rs (2026-10-04). Deployment `dpl_FxZdQ89sjjhioaqypB9rudHyPaoD`. |
| Live page | https://docs.myswift.rs/swift-console/ shows the 2026-10-04 ACCEPT_WITH_WARN gate and `tools/test-results/console-reaccept-20261004/SUMMARY.md`. |
| Drive | `gdrive:Peregrine/2026-10-04-console-reaccept/` |
| Stale Drive file | `gdrive:Peregrine/2026-10-04-hkserver-g7/verdict-prod.json` stays. Sibling note `STALE-verdict-prod.md` in that folder. |

## Excluded on purpose

- Login keys, session cookies, `proxy-server.conf`, and auth tokens
- Nested checkout `peregrine/`
- `/srv/node` and host backups
