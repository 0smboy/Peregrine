# P3-ops — TLS / expand / multi-region — 2026-08-04

**Verdict: partial GREEN**

Code + unit + dry-run plan gates pass. Contabo live TLS cutover and live expand
drill were **not applied** (no production PEM; VIP remains `bind *:8085` http;
expand needs a maintenance ticket for partition movement). Dual-guard held:
no wipe of `/srv/node`.

## What this cycle did

1. HAProxy TLS termination in `bundle-rust` when `lb_mode=https` (PEM or self-signed).
2. Workspace allows rust `ingress.http_mode=https` with haproxy/keepalived; rejects https+direct.
3. Expand path: `expand.yml` + `rust_expand_mode` + idempotent ring `add`/`search`/`list`;
   `host_vars.region` / `zone` / `swift_devices` feed `build_rings.sh.j2`.
4. Dual-guard: rust roles never mkfs/wipe; workspace rejects `node.disks`.
5. Docs: `P3-OPS-CONTRACT.md`, `MULTI-REGION.md`, README / DEPLOY-HYBRID / blocked / ROADMAP.

## Gate table

| Gate | Result | Evidence |
|------|--------|----------|
| ring-builder unit | 2/2 PASS | `05-ring-builder-unit.txt` |
| workspace_rust_stack | 11/11 PASS | `05-cargo-workspace.txt` |
| plan expand.yml | PASS (50 tasks, disk_wipe=0) | `plan-expand.json` |
| plan swift.yml + https | PASS (136 tasks, disk_wipe=0, TLS×6) | `plan-swift.json` |
| openssl self-signed dry-run | PASS | `23-tls-openssl-dryrun.txt` |
| Contabo probe | VIP http 200; bind *:8085 (no ssl) | `01-contabo-ssh.txt` |
| Contabo live TLS / expand | NOT APPLIED | honest residual |

## Remaining / next

- **FROZEN this wave:** Contabo live TLS cutover (needs PEM + maintenance).
- **FROZEN this wave:** Contabo live expand drill (needs ticket; partition moves).
- **Backlog:** multi-region live drill; geo-DNS; production cert automation.
