# Console acceptance sync manifest — 2026-10-02

Strict operator-surface gate on the live contabo-swift-2026 cluster.
Verdict **ACCEPT_WITH_WARN**. Do not upgrade this to ACCEPT. `POST /api/apply`
was not sent.

| Channel | Location |
|---------|----------|
| Content commit | `94871e64144116a06d9f06a7a90d30537c41e9a9` on `main` |
| Vercel | `dpl_EirPBiXE1fHB8iKDPmAPjk4rL3WE` aliased to https://docs.myswift.rs |
| Evidence | `tools/test-results/console-accept-20261002/` |
| Verdict | `SUMMARY.md` (2026-10-02) |
| Docs | `docs-site/src/content/docs/swift-console.mdx` |
| Live page | https://docs.myswift.rs/swift-console/ |
| Drive | `gdrive:Peregrine/2026-10-02-console-accept/` |
| Code | `swift-console/src/proxy.rs` (Content-Length), `swift-console/src/shadow.rs` (peer login) |

## Gate snapshot

| Item | Result |
|------|--------|
| Overall | **ACCEPT_WITH_WARN** (`SUMMARY.md`, `13-apply.md`) |
| File path, chaos, HA, autocos | passed (`09-remaining.md`) |
| Shadow run | passed (`10-shadow.md`) |
| Browser file path | passed (`11-browser-disk.md`) |
| Shadow mutate, warehouse promote | passed (`12-apply-mutate-promote.md`) |
| Deploy apply | not sent. Sealed Contabo plan still names disk-wipe tasks and would change yum, sshd, firewall, MariaDB, and Keystone |
| Nodes left | swift1–4 services active; VIP `10.0.0.10` on swift1 only (`13-apply.md`) |

## Excluded on purpose

- Login keys, session cookies, CSRF values, and `proxy-server.conf` copies
- Nested checkout `peregrine/`
