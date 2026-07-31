# Lab cluster operations

Reference layout for the four-node Azure HA lab used to develop and verify
Peregrine. This is the day-to-day cluster described in [`testing.md`](testing.md)
§4 — not a production runbook.

## Topology

| Plane | CIDR / VIP | Role |
|-------|------------|------|
| Management | `10.42.10.1N` | SSH, Prometheus scrape, console loopback |
| Replication | `10.42.20.1N` | Object/account/container sync |
| Proxy / client | `10.42.30.1N` + ILB VIP `10.42.30.10:8085` | HAProxy frontends |

Nodes: `swift1`–`swift4`. Prefer **node HAProxy** `http://10.42.30.1N:8085`
for tests from a backend VM (Azure ILB hairpin from the backends themselves is
unreliable). External clients in the VNet can use the VIP.

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
- On the build/console host (`swift1`): Prometheus, Loki, Alloy, statsd_exporter,
  node_exporter (all nodes), `swift-console`, `cabt` / `autocos`, Rust toolchain
  under `/root/.cargo` + `/root/.rustup`.
- SELinux: `haproxy_connect_any=1`; after installing binaries run `restorecon`
  so labels stay `bin_t`.

## Cutover / migration notes

When replacing a subscription or VNet:

1. Copy conf, rings, keys, bins, units, monitoring, SAIO, and lab tools — **not**
   `/srv/node` object bytes unless you explicitly need the dataset.
2. Gate the new cluster with `swift-rust/tools/func-suite.sh`, `ha-test.sh`,
   `ec-heal-test.sh`, and a Prometheus `nodes_up=4` check.
3. Operator checklist and evidence live under [`tools/`](../tools/)
   (`NEW-CLUSTER-CUTOVER.md`, `test-results/`).

Destroying an old cluster after cutover permanently drops any unmigrated
object data. Confirm with the destroy go/no-go note in `tools/test-results/`
before tearing down VMs.

## Build & install (Linux host)

```sh
export PATH=/usr/local/bin:/root/.cargo/bin:$PATH
cd /root/work/Peregrine/swift-rust   # or the synced engine tree
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
- Docs site: [Operations](https://peregrine-docs-ochre.vercel.app/operations),
  [Testing](https://peregrine-docs-ochre.vercel.app/testing)
