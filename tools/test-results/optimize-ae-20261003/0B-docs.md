# Phase B — docs only

Date: 2026-10-03. Audit and live pages recorded after `npm run deploy:prod` in `docs-site` (script `docs-site/scripts/deploy-prod.sh`, Vercel production, user `0smboy`). Deployment `peregrine-docs-gox6cikhx-0smboys-projects.vercel.app` ready. Alias: https://docs.myswift.rs

`tools/docs-claim-audit.sh` exit 0 on 2026-10-03.

## Claims updated

- `docs-site/src/content/docs/lab-cluster.mdx`: VIP `10.0.0.10/22` is on swift1. Console listens on swift4 `127.0.0.1:9000`. Evidence `tools/test-results/console-accept-20261002/00-identity.md` (2026-10-02).
- `docs/lab-cluster.md`: same owner, and the 2026-08-04 "VIP may sit on swift2" line is labeled as that day's pointer.
- `docs-site/src/content/docs/incidents.mdx`: `AUTH_test` `status=DELETED` is the state before `tools/test-results/console-accept-20261002/07-fix.md` (2026-10-02). `swift-account-reaper` stays off.
- `HANDOFF.md`: `docs/fairness-lab/HANDOFF-20260816.md` is not the current site. Current lab record is `tools/test-results/console-accept-20261002/SUMMARY.md` (2026-10-02), ACCEPT_WITH_WARN.
- `docs-site/src/content/docs/performance.mdx`: `16MB_read_8` stays ACCEPT_WITH_WARN (`tools/test-results/contabo-deploy-20260801/deep-verify-20260802/PERF-REMEASURE.md`, 2026-08-02). R8 ACCEPT is `16MB_read_4`, object_count=40, runtime=180, 2026-08-04 (`tools/test-results/fairness-lab-R8-20260803/R8-GATE.md` and `SCORECARD.json`).
- `docs-site/src/content/docs/swift-console.mdx` was not edited. G7 NOT ACCEPTED, production NO-GO, and console ACCEPT_WITH_WARN stay.

## Live tokens (2026-10-03)

Fetched with `https_proxy` unset.

| URL | Token |
|---|---|
| https://docs.myswift.rs/swift-console/index.md | `ACCEPT_WITH_WARN`; `G7 is NOT ACCEPTED`; `G7 remains NOT ACCEPTED`; `Production readiness remains NO-GO` |
| https://docs.myswift.rs/lab-cluster/index.md | `Keepalived VIP 10.0.0.10/22 is on **swift1**`; `The console process listens on swift4 at 127.0.0.1:9000`; evidence path `tools/test-results/console-accept-20261002/00-identity.md` (2026-10-02) |
| https://docs.myswift.rs/performance/index.md | `16MB_read_8 remains ACCEPT_WITH_WARN`; `R8 ACCEPT is a different cell: 16MB_read_4, object_count=40, runtime=180, 2026-08-04` |

HTML pages for the same three routes returned 200.
