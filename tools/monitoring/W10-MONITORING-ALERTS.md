# W10 — Monitoring alerts + gap metrics (Contabo swift1-4)

Date: 2026-08-17. Branch: `codex/monitoring-alerts-20260817`.
Upgrades the stack from "collection only" to "collection + alert rules".
Evidence: `.agent-handoff/workflow-runs/20260817/monitoring/` (Mac, not in repo).

## Stack as found (inventory, 2026-08-17)

- Prometheus 2.54.1 on swift1 (`127.0.0.1:9090`), systemd unit, config
  `/etc/prometheus/prometheus.yml`, `rule_files: /etc/prometheus/rules/*.yml`,
  scrape/eval interval 15s. Jobs: `node` (10.0.0.1-4:9100), `statsd`
  (10.0.0.1-4:9102). All 8 targets up.
- Existing rules: `swift-compat.yml` (statsd→`swift_request_total` recording
  rules), `swift-ops-alerts.yml` (R0: TombstoneGrowth, DbFreelistHigh,
  DeviceUsePctHigh>85 crit, plus 2 W1 stubs). Zero alerts firing pre-W10.
- **No Alertmanager**: `activeAlertmanagers` empty, no unit installed.
- node_exporter 1.8.2 on all four nodes, textfile collector already at
  `/var/lib/node_exporter/textfile_collector` (fed every 2m by
  `swift-recon-textfile.timer` → `swift-recon.prom`). **No systemd collector**
  before W10.
- statsd_exporter exposes flat `proxy_server_<METHOD>_<STATUS>` /
  `object|container|account_server_*` counters and `*_timing_*` summaries;
  5xx counters exist (e.g. `proxy_server_GET_503`). The compat recording rule
  labels them into `swift_request_total{service,method,status}`.

## What W10 adds

| Piece | Source (repo) | Deploy target (all 4 nodes unless noted) |
| --- | --- | --- |
| systemd collector drop-in | `systemd/node_exporter-peregrine-collectors.conf` | `/etc/systemd/system/node_exporter.service.d/10-peregrine-collectors.conf` |
| gap-metrics script | `peregrine-textfile-metrics.sh` | `/usr/local/bin/peregrine-textfile-metrics.sh` (0755) |
| cron entry | `cron.d/peregrine-textfile-metrics` | `/etc/cron.d/peregrine-textfile-metrics` |
| alert rules | `rules/peregrine-alerts.yml` | swift1 `/etc/prometheus/rules/peregrine-alerts.yml` |

New series: `node_systemd_unit_state{name=~"swift-.*"}` (unit liveness),
`peregrine_quarantined_objects`, `peregrine_async_pendings` (both per node via
`instance`; cluster steady state at deploy time: quarantined 12, async 357).

## Deploy procedure (as executed)

1. Per node, back up `/etc/systemd/system/node_exporter.service` (+ no
   pre-existing drop-ins) to `/root/backups/w10-monitoring-20260817/`.
2. Install drop-in, `systemctl daemon-reload && systemctl restart
   node_exporter` (node_exporter is off the data path; restart allowed).
   Verify `:9100/metrics` serves `node_systemd_unit_state`.
3. Install script + cron file; run script once by hand; verify
   `peregrine.prom` contents.
4. On swift1: back up `/etc/prometheus/prometheus.yml` and `rules/` (cp -a,
   dated). `promtool check rules` on the new file **before** installing it
   into `rules/`. prometheus.yml itself is untouched (glob picks the file up).
5. Reload via `kill -HUP <prometheus pid>` (no restart; lifecycle API not
   enabled). Compare `/api/v1/targets` before/after (8/8 up), confirm 3 rule
   files in `/api/v1/rules`, sample `/api/v1/alerts`.

## Alert semantics and design notes

- `RootDiskHigh` has two tiers under one name: warning >88% for 15m, critical
  >93% for 5m. At inventory time swift1 (94%) would have fired both tiers and
  that would have been correct behavior; the parallel disk-governance task
  cleaned all roots to ~74% minutes before the rules went live, so W10
  deployed all-green. The evaluate→fire pipeline was instead proven with a
  temporary always-true self-test rule (fired, observed in `/api/v1/alerts`,
  removed — see evidence `09-selftest-pipeline.txt`).
- `SrvNodeDiskHigh` warns at >80%; the R0 `SwiftDeviceUsePctHigh` critical at
  >85% is left in place as the escalation tier.
- `SwiftDaemonDown` watches the 11 mandatory daemons per node;
  `SwiftDaemonSetIncomplete` (sum of active-state series < 11 per instance)
  additionally catches a unit that systemd unloaded entirely, which the ==0
  match cannot see. `SwiftCoreServiceDown` covers proxy/object/container/
  account servers at critical/3m.
- `FrozenDaemonStarted` (no `for:`): `swift-account-reaper` and
  `swift-object-expirer` are deliberately frozen; these units becoming
  *active* is an incident signal, so the alert fires immediately. While they
  stay stopped/unloaded the expression returns no series, which is the normal
  quiet state.
- `QuarantineGrowth` / `AsyncPendingGrowth` watch growth, not stock
  (`increase(...[1h]) > 0`, `increase(...[2h]) > 50`), per the W10 spec.
  Caveat: `increase()` treats a decrease of these gauges as a counter reset,
  so a manual quarantine cleanup can produce one spurious growth window;
  acceptable, since quarantine cleanups should be noticed anyway.
- `SwiftProxyErrorRateHigh` is the best availability signal the current
  metrics support: statsd-derived 5xx ratio per node (>5% for 10m). Known
  gaps, documented rather than papered over: it cannot see requests that die
  before reaching a proxy worker (HAProxy/VIP layer is unscraped), and with
  zero traffic the expression is NaN → no false fires, but also no signal.
  A blackbox probe of `:8080/healthcheck` via the VIP would close that gap;
  out of W10 scope (needs a blackbox_exporter decision).

## Alertmanager: deliberately not installed

Rules are **evaluated** on swift1 (visible in `/api/v1/alerts` and the UI);
**notification routing is pending the user's channel decision** (mail /
webhook / other). No Alertmanager existed and none was installed, per W10
scope. When the channel is decided: install alertmanager, add an `alerting:`
block to prometheus.yml, and route severity=critical accordingly.

## Rollback

- Rules: `rm /etc/prometheus/rules/peregrine-alerts.yml && kill -HUP <pid>`
  (backups in `/root/backups/w10-monitoring-20260817/` on swift1).
- Collector: remove the drop-in dir, `systemctl daemon-reload && systemctl
  restart node_exporter`.
- Gap metrics: remove `/etc/cron.d/peregrine-textfile-metrics`,
  `/usr/local/bin/peregrine-textfile-metrics.sh`, and
  `/var/lib/node_exporter/textfile_collector/peregrine.prom`.
