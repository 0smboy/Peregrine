# bundle-monitoring — node observability agents for the Rust Swift stack

Installs the per-node monitoring agents onto every `storage_nodes` host of a
Rust Swift cluster deployed by `bundle-rust`, driven by the swift-deploy-rs
executor (the Ansible-subset engine, not real Ansible). It is applied over
the SAME inventory/config a rust workspace emits; no rust variables are
modified and no swift service is touched.

## What gets deployed

| Agent | Bind | Purpose |
| --- | --- | --- |
| `node_exporter` | web `{{ storage_network_address }}:9100` | host metrics (CPU/mem/disk/net, per WG plane) |
| `statsd_exporter` | UDP+TCP ingest `127.0.0.1:9125`, web `{{ storage_network_address }}:9102` | receives the Swift daemons' statsd and re-exposes labeled Prometheus metrics via `/etc/statsd-mapping.yml` |
| Grafana Alloy | HTTP `127.0.0.1:12345` (loopback only) | journald -> Loki push (`swift-*` units + haproxy), labels `unit` and `host` |

Nothing binds `0.0.0.0`: web listeners bind the WireGuard storage address,
ingest and the Alloy UI bind loopback (one node has public ports open, so
this is load-bearing, not cosmetic).

All three agents run as the unprivileged `monitor` system user (created by
`mon_config`); Alloy reads the journal through the `systemd-journal`
supplementary group. Units are `Restart=on-failure`.

`smartctl_exporter` is deliberately skipped: the target nodes use
virtio/EBS virtual disks, which expose no SMART data.

## Metric namespace (what Prometheus scrapes on :9102)

- `swift_request_total{service,method,status}` — from
  `<service>.<METHOD>.<status>` counters (proxy/object/account/container
  server).
- `swift_request_duration_seconds{service,method}` — histogram, from the
  `.timing` timers. `method="all"` is the proxy's whole-request timer.
  Named `_seconds` (not `_ms`) because statsd_exporter observes statsd `|ms`
  timers in seconds; buckets 1ms..10s with a 2s boundary matching the
  ProxyP99High alert.
- `swift_replicator_total{service,kind}` — replicator/updater/reconstructor
  pass counters (`kind` = successes/failures/suffix_syncs/reverts/unlinks).
- `swift_replicator_duration_seconds{service,kind}` — reserved
  `partition.update.timing` timer.
- Everything else arriving on 9125 is dropped by the catch-all rule.

The Swift side of this contract is wired in bundle-rust's conf templates:
every server/daemon section carries `log_statsd_host = 127.0.0.1`,
`log_statsd_port = 9125` and an EMPTY `log_statsd_metric_prefix` — the Rust
daemons build the metric prefix from their `log_name` (the proxy embeds
`proxy-server` in the metric names it emits), so a non-empty prefix would
double up (`object-server.object-server.GET.200`).

## Variables

Only one host variable is required: `storage_network_address`
(host_vars, present in every rust workspace). Every monitoring knob carries
an in-template `| default(...)`, so the bundle applies cleanly against a
rust workspace config that predates monitoring. Overridable via group_vars
(see `config_sample/group_vars/all`): `monitoring_hub_address` (172.18.1.2),
`loki_push_url`, `node_exporter_port` (9100), `statsd_exporter_web_port`
(9102), `statsd_udp_port` (9125), `alloy_http_port` (12345).

`config_sample/` is a structure example: applying from a `config_sample`
path is permanently refused by the UI/backend.

## How to apply (CLI, against an existing rust workspace)

```sh
# payload first — see roles/mon_payload/PAYLOAD.md
cp /root/monitoring-payload/bin/* bundle-monitoring/roles/mon_payload/files/bin/

swift-deploy audit --bundle bundle-monitoring
swift-deploy plan --bundle bundle-monitoring \
  --inventory <workspace>/swift_hosts \
  --playbook bundle-monitoring/swift.yml \
  --output monitoring-plan.json
swift-deploy apply --bundle bundle-monitoring \
  --inventory <workspace>/swift_hosts \
  --plan monitoring-plan.json --confirm-digest <digest> \
  --allow-host-reconfigure
```

The plan's only risk class is `host_reconfigure` (systemd units + the
`monitor` user), which is expected. If you run `preflight`, point
`--bundle` at the RUST bundle (or omit it): the rust-payload preflight gate
keys off the workspace's `deploy_stack: rust` and would otherwise look for
the swift binaries inside this bundle.

## Idempotency and restarts

Re-applying a converged node reports changed=0: copies/templates compare
content, the user and directories are probe- or changed_when-guarded, units
restart only on drift. Drift restarts are IMMEDIATE (register + `when:
x.changed`, not handlers): a changed mapping or Alloy config restarts that
agent in the same play; a changed binary or unit file restarts the affected
agent likewise.

## Layout

```
swift.yml              one play: storage_nodes -> mon_payload, mon_config, mon_systemd
ansible.cfg
config_sample/         swift_hosts, group_vars/all, host_vars/<ip>.yml
roles/
  mon_payload/         node_exporter, statsd_exporter, alloy -> /usr/local/bin (payload, see PAYLOAD.md)
  mon_config/          monitor user, /etc/statsd-mapping.yml, /etc/alloy/config.alloy
  mon_systemd/         one unit per agent + immediate drift restarts
```
