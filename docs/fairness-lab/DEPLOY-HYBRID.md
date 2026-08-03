# Contabo = hybrid overlay on swift-deploy-rs

| Layer | What it is | What it is not |
|-------|------------|----------------|
| `swift-deploy-rs/bundle/` | Near-full Python ansible-v3 surface | Contabo’s entire truth today |
| `swift-deploy-rs/bundle-rust/` | Deployable subset of **implemented** Rust Swift | Full plugins / Keystone / S3 / Keepalived |
| Contabo hybrid | bundle-rust binaries + Keepalived VIP + monitoring + console + SAIO overlays + fairness-lab mode-switch | “Full ansible-equivalent deploy” |

## Honest non-goals (from bundle-rust README)

No Keepalived/VIP in rust stack alone, no TLS, no S3 API, no Keystone/MariaDB, no add-disk/add-node automation.

Contabo adds Keepalived/monitoring **outside** pure `bundle-rust apply`. Document those as overlays under `tools/fairness-lab/overlays/`.

## Policy

- Prefer `swift-deploy` apply for anything the executor can converge
- Manual `scp`/ssh edits go on an **exceptions list** with owner + expiry
- Never imply public docs that Contabo matches full Python ansible plugin surface
- Missing features → [blocked-by-missing-impl.md](blocked-by-missing-impl.md)
