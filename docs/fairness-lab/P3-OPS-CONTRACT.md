# P3-ops contract — TLS · expand · multi-region

Authority for the ops track of [PRODUCTION-GAP-ROADMAP.md](PRODUCTION-GAP-ROADMAP.md).
Implementation: `swift-deploy-rs/bundle-rust` + workspace validation.

## TLS termination

| Item | Contract |
|------|----------|
| Where | HAProxy frontend only (`lb_mode=https`) |
| Proxy | Remains plain HTTP on `proxy_bind_port` |
| Cert | `haproxy_tls_pem_src` (operator PEM) **or** `haproxy_tls_self_signed=true` (lab) |
| Dest path | `haproxy_tls_pem` default `/etc/haproxy/haproxyCA.pem` |
| Workspace | rust stack allows `ingress.http_mode=https` with haproxy/keepalived; rejects https+direct |
| python-v3 | HTTPS still disabled (Keystone HTTP hardcode) |
| Contabo | Live lab may already use **self-signed**; production PEM apply is **operator-driven** (no auto Contabo mutation) |
| Operator script | [`tools/ops/apply-vip-tls-pem.sh`](../../tools/ops/apply-vip-tls-pem.sh) — validate / install / reload; requires explicit `--local` or `--ssh` |
| Contract check | [`tools/ops/check-haproxy-tls-contract.sh`](../../tools/ops/check-haproxy-tls-contract.sh) static dry-run |
| Runbook | [`tools/ops/README.md`](../../tools/ops/README.md) |

### Contabo production PEM (short)

1. Keep fullchain+key PEM **outside git**; export path as `SWIFT_TLS_PEM` if desired.
2. `./tools/ops/apply-vip-tls-pem.sh --pem /secure/vip.pem --check`
3. Dry-run: `--ssh swift1,swift2,swift3,swift4 --reload --dry-run --print-commands`
4. Live apply **only** after confirming SSH targets (same flags without `--dry-run`).
5. Smoke `https://10.0.0.10:8085/healthcheck` with real CA trust (no `curl -k` for PRODUCTION-GO-LIVE).
6. Alternate full path: set `haproxy_tls_pem_src` + `haproxy_tls_self_signed=false` and `swift-deploy plan/apply` (stack=rust).

Offline SAIO (`tools/offline-oneclick`) stays HTTP `:8080`; its `tls` subcommand only stages PEM or delegates to the ops script via `--vip`.

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
