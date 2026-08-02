# Wave 1 — Deploy upstream + Monitor wiring

Date: 2026-08-01

## Deploy UI (:8789)

- Built `swift-deploy` from `/root/work/swift-deploy-rs` (release).
- Installed `/usr/local/bin/swift-deploy`, bundle at `/opt/swift-deploy/bundle`.
- systemd `swift-deploy-ui.service`: `swift-deploy ui --bind 127.0.0.1 --port 8789 --auth-token-file /etc/swift-deploy/ui-token --bundle /opt/swift-deploy/bundle`.
- Direct: `curl -u operator:$(cat /etc/swift-deploy/ui-token) http://127.0.0.1:8789/` → **200** HTML.
- Console (session): `GET /deploy` → 200 shell with iframe; `GET /deploy/` → **200** proxied UI (~35KB).
- Scope: audit/validate/read-only only; no format/apply against live disks.

## Monitor / Prometheus

- Added `/etc/prometheus/rules/swift-compat.yml` recording rules mapping statsd flat names → `swift_request_total`, duration sum/count, `swift_replicator_total`.
- Prometheus scrape: `metric_relabel_configs` set `plane` from NIC (`eth1=public`, `eth2=storage`, `eth3=replication`).
- Patched `swift-console` latency panels to use avg(sum/count) (statsd has no histogram buckets); rebuilt + restarted.
- Grafana: **not installed** (Monitor UI uses PromQL/Loki directly; no Grafana iframe).

### Panel smoke (authenticated `/monitor/api/panel`)

| Panel | Result |
|-------|--------|
| nodes_up | value **4.0** |
| reqs | non-zero rate |
| cpu / fs_used | series for 4 nodes |
| net_storage | rx/tx series |
| latency | avg series |
| log_vol | haproxy + swift units |

## Alloy → Loki

- Loki listen changed `127.0.0.1` → `0.0.0.0:3100` (WAN blocked by firewalld public DROP; private eth1 trusted).
- Installed Grafana Alloy v1.8.3 on swift1–4; journal filter `(swift-.*|haproxy).service` → `http://10.0.0.1:3100/loki/api/v1/push`.
- Loki query `{unit=~"swift-.+|haproxy.service"}` returns streams (e.g. `swift-object.service` on host 10.0.0.1).

## Verdict

**ACCEPT** for Wave 1 Deploy + Monitor wiring.
