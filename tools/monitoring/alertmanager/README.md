# Peregrine alerting channel (swift1)

Installed 2026-08-17. These are the deployed artifacts, archived verbatim.

| file | deploy target on swift1 |
|---|---|
| `alertmanager.yml` | `/etc/alertmanager/alertmanager.yml` |
| `alertmanager.service` | `/etc/systemd/system/alertmanager.service` |
| `peregrine-alert-sink.py` | `/usr/local/bin/peregrine-alert-sink.py` (mode 0755) |
| `peregrine-alert-sink.service` | `/etc/systemd/system/peregrine-alert-sink.service` |
| `peregrine-alerts.logrotate` | `/etc/logrotate.d/peregrine-alerts` |

Topology: Prometheus (`127.0.0.1:9090`) -> Alertmanager v0.34.0
(`/usr/local/bin/alertmanager`, `127.0.0.1:9093`, data in
`/var/lib/alertmanager`, clustering disabled) -> webhook receiver
`peregrine-alert-sink` (`127.0.0.1:9094`) -> `/var/log/peregrine-alerts.jsonl`
(mode 0640, rotated weekly x8 compressed). `prometheus.yml` gained an
`alerting:` block pointing at `127.0.0.1:9093`.

Routing: grouped by `alertname`+`severity`, `group_wait 30s`,
`group_interval 5m`, `repeat_interval 4h`, `send_resolved: true`.

Feishu: `alertmanager.yml` carries a commented "Feishu webhook 换装位" block;
once a bot webhook URL exists, fill the receiver, flip `route.receiver`,
`amtool check-config`, then `systemctl reload alertmanager`.

End-to-end proof (2026-08-17): the then-firing `FrozenDaemonStarted`
(swift-object-expirer, x4 nodes) flowed Prometheus -> AM -> sink into the
jsonl (firing 15:58:50Z, resolved x4 16:03:50Z after the 12/13 rule
alignment). Evidence:
`.agent-handoff/workflow-runs/20260817/alerting-offsite/` (operator Mac,
outside the repo).
