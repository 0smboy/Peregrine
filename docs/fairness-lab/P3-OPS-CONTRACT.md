# P3-ops contract — TLS · expand · multi-region

Authority for the ops track of [PRODUCTION-GAP-ROADMAP.md](PRODUCTION-GAP-ROADMAP.md).
Implementation: `swift-deploy-rs/bundle-rust` + workspace validation.

## TLS termination

| Item | Contract |
|------|----------|
| Where | HAProxy frontend only (`lb_mode=https`) |
| Proxy | Remains plain HTTP on `proxy_bind_port` |
| Cert | `haproxy_tls_pem_src` (operator PEM) **or** `haproxy_tls_self_signed=true` (lab) |
| Workspace | rust stack allows `ingress.http_mode=https` with haproxy/keepalived; rejects https+direct |
| python-v3 | HTTPS still disabled (Keystone HTTP hardcode) |
| Contabo | Live TLS apply may be **dry-run only** when no production cert / SSH unavailable — document honesty |

## add-disk / add-node

| Item | Contract |
|------|----------|
| Devices | Directory names in `swift_devices` under `/srv/node` (default `d1`) |
| Playbook | `bundle-rust/expand.yml` (`rust_expand_mode` → `ring_expand=true`; disks → rings → LB → verify) |
| Rings | Expand: idempotent `swift-ring-builder add` + rebalance (never `rm` rings). Greenfield: stamp rebuild. Optional `ring_force_rebuild` |
| Data | Ring rebalance ≠ data wipe; replicators heal. Honest: Rust builder has no replica2part2dev persistence |
| Dual-guard | (1) no mkfs/wipe in rust roles; (2) workspace rejects `node.disks`; Contabo wipe needs ticket + `--allow-disk-wipe` elsewhere |

## Multi-region

See [MULTI-REGION.md](MULTI-REGION.md). Template + host_vars region/zone are in
scope; Contabo remains single-region lab.

## Evidence

`tools/test-results/p3-ops-YYYYMMDD/` with HTML report. Contabo live TLS apply
is optional; plan/render/unit gates are mandatory.
