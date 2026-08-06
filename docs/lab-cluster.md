# Lab cluster operations

Reference layout for the four-node Contabo HA lab used to develop and verify
Peregrine. This is the day-to-day cluster described in [`testing.md`](testing.md)
§4 — not a production runbook.

The previous Azure PAYG topology (`10.42.*` + ILB) is **retired**. Cutover
notes: [`tools/CONTABO-CLUSTER.md`](../tools/CONTABO-CLUSTER.md). Azure doc
[`tools/NEW-CLUSTER-CUTOVER.md`](../tools/NEW-CLUSTER-CUTOVER.md) is historical.

**Formal method:** [`docs/fairness-lab/USER-METHOD-PLAN.md`](fairness-lab/USER-METHOD-PLAN.md).
R0–R8 (2026-08-03) = historical baseline only. Contabo target: `swift-deploy apply`
(`stack=rust`, Keepalived VIP + HAProxy roundrobin). Stage-1 SAIO must not run on
swift1/4. See [`docs/fairness-lab/`](fairness-lab/).

**Pointer 2026-08-04:** Stage 2 evidence `tools/test-results/phase-2-20260804/`;
Stage 3 Python path FROZEN (`PYTHON_CLUSTER_ABSENT`) —
`tools/test-results/phase-3-20260804/`. VIP may sit on swift2 (nopreempt).

## Topology

| Plane | Address | Role |
|-------|---------|------|
| Management / SSH | public `169.58.108.{85,86,87,121}` | SSH, Ansible |
| Proxy / client | `10.0.0.1–4` + Keepalived VIP **`10.0.0.10:8085`** | HAProxy → proxy `:8080` |
| Storage | `10.0.4.1–4` | account/container/object data path |
| Replication | `10.0.8.1–4` | replicator / reconstructor |

Nodes: `swift1`–`swift4` (VIP MASTER by keepalived priority; hub/observability on
**swift4**). Prefer VIP `http://10.0.0.10:8085`. Per-node `http://10.0.0.N:8085`
shares the same four-proxy backend pool (roundrobin) after the 2026-08-04 LB fix /
bundle-rust keepalived path.

Devices: `/srv/node/{d1,d2,d3}` XFS per node (12 total). **Never format** them
from deploy tooling.

Storage policies (lab): `default` (replication) and `ec-2-1`
(`liberasurecode_rs_vand`). Rings and `replication_key` must match across all
nodes.

## What must be installed

- Swift daemons + HAProxy on every node; auditor as a **timer**
  (`swift-object-auditor.timer`), not a one-shot you forget to schedule.
- EC plugin libs: `libnullcode`, `liberasurecode_rs_vand` (symlink
  `liberasurecode_rs_vand.so.1.0.1` must resolve).
- Release binaries built with `--features …/ec`. A proxy without EC returns
  **501** “erasure coding not built”.
- Observability + console hub (**swift4**, post-R1 2026-08-03): Prometheus,
  Loki, `swift-console`, deploy-ui. Alloy / statsd_exporter / node_exporter on
  all nodes (Alloy → `10.0.0.4:3100`). Build tree historically on swift1
  (`/root/work`, cargo/rustup); VIP MASTER is **not** the hub host.
- Dual SAIO stopped off VIP MASTER; recreate on a non-hub node (swift3) before
  Compatibility R3 shadow runs.
- SELinux: `haproxy_connect_any=1`; `ip_nonlocal_bind=1` for VIP binds; after
  installing binaries run `restorecon` so labels stay `bin_t`.

## Auth

Harness credentials (unchanged): `test:tester` / `azure-swift-2026.bench`.

## Cutover / migration notes

When replacing a provider or VNet:

1. Copy conf, rings, keys, bins, units, monitoring, SAIO, and lab tools — **not**
   `/srv/node` object bytes unless you explicitly need the dataset.
2. Gate the new cluster with `swift-rust/tools/func-suite.sh`, `ha-test.sh`,
   `ec-heal-test.sh`, and a Prometheus `nodes_up=4` check.
3. Operator checklist and evidence live under [`tools/`](../tools/)
   (`CONTABO-CLUSTER.md`, `test-results/`).

## Build & install (Linux host)

```sh
export PATH=/usr/local/bin:/root/.cargo/bin:$PATH
cd /root/work/swift-rust
cargo build --release \
  --features swift-proxy-server/ec,swift-object-server/ec
# install bins, then:
restorecon -v /usr/local/bin/swift-*
systemctl restart swift-proxy swift-object …
```

Console / autocos follow the same pattern from their crates; see
[`HANDOFF.md`](../HANDOFF.md).

## Related docs

- [`testing.md`](testing.md) — verification levels and harnesses
- [`architecture.md`](architecture.md) — component map
- [`tools/CONTABO-CLUSTER.md`](../tools/CONTABO-CLUSTER.md) — Contabo endpoints
- Docs site: [Operations](https://peregrine-docs-ochre.vercel.app/operations),
  [Testing](https://peregrine-docs-ochre.vercel.app/testing)
