# Contabo = hybrid overlay on swift-deploy-rs

| Layer | What it is | What it is not |
|-------|------------|----------------|
| `swift-deploy-rs/bundle/` | Near-full Python ansible-v3 surface | Contabo’s entire truth today |
| `swift-deploy-rs/bundle-rust/` | Deployable subset of **implemented** Rust Swift + HAProxy + Keepalived VIP | Full plugins / Keystone prod path / full S3 / Paste pipeline |
| Contabo hybrid (transitional) | Was: binaries + manual Keepalived/monitoring/SAIO overlays | Target: pure `bundle-rust apply` for data-plane + LB; monitoring/SAIO remain overlays |

## Honest non-goals (bundle-rust)

S3 `s3api` is ON-BY-CONFIG (not default pipeline; not on Swift `/info`) — enable steps and suite scripts in [S3-ON-BY-CONFIG.md](S3-ON-BY-CONFIG.md). No Keystone/MariaDB *provisioning* in default Contabo path (Identity comes from python `bundle/config_contabo_identity`; rust only 对接 — see [KEYSTONE-LIVE.md](KEYSTONE-LIVE.md)). No block-device wipe/format automation.
**Keepalived VIP is in-scope** via `rust_keepalived` when `ingress.mode=keepalived`.
**P3-ops in-scope:** HAProxy TLS (`lb_mode=https`), `expand.yml` add-disk/add-node
(directory devices + ring rebuild, dual-guard no `/srv/node` wipe), multi-region
host_vars → rings (see [P3-OPS-CONTRACT.md](P3-OPS-CONTRACT.md),
[MULTI-REGION.md](MULTI-REGION.md)).

Monitoring / dual-SAIO mode-switch remain overlays under `tools/fairness-lab/overlays/`.
Stage-2 gate: Contabo data-plane+LB must converge via `swift-deploy apply` — see
[USER-METHOD-PLAN.md](USER-METHOD-PLAN.md).

## Policy

- Prefer `swift-deploy` apply for anything the executor can converge
- Manual `scp`/ssh edits go on an **exceptions list** with owner + expiry
- Never imply public docs that Contabo matches full Python ansible plugin surface
- Missing features → [blocked-by-missing-impl.md](blocked-by-missing-impl.md)
