# R0 metrics → Prometheus / Grafana — SUMMARY

**Date:** 2026-08-05  
**Verdict:** **WIRED (scrape + alerts GREEN)** · Grafana dashboard provisioned; panel *render* PNG stub (no image-renderer) but DS query returns live series after SELinux port fix.

## Before → after

| Surface | Before R0 | After R0 |
|---------|-----------|----------|
| `swift-recon tombstones\|dbspace --prometheus` | CLI-only | unchanged CLI + timer |
| node_exporter textfile | **absent** (no `--collector.textfile.directory`) | `/var/lib/node_exporter/textfile_collector/swift-recon.prom` every 2m |
| Prometheus series | **missing** | four nodes: `swift_object_tombstones*`, `swift_db_*` |
| Alert rules | none for tombstone/freelist/disk | `swift-ops-alerts.yml` loaded (`SwiftTombstoneGrowth`, `SwiftDbFreelistHigh`, `SwiftDeviceUsePctHigh`; Galera/Keystone **stubs**) |
| Grafana | not required / later installed | dashboard uid `swift-r0-tombstone-dbspace` searchable; DS query OK |

## Prom query snapshot (swift4 `127.0.0.1:9090`)

| Query | Result (2026-08-05) |
|-------|---------------------|
| `sum by (node) (swift_object_tombstones)` | early cycle ≈35–41/node; after reclaim→0 the binary omitted empty samples — fixed via wrapper zero-series (`device=none` =0 on all four) |
| `sum by (node,kind) (swift_db_freelist_bytes)` | container ≈0 after W0′ VACUUM; account ≤4KiB |
| `count(up{job="node"}==1)` | 4 |
| Use% `/srv/node/d*` | ~1.4–1.8% (alert inactive) |
| Alert groups | `swift_ops_r0`, `swift_ops_w1_stubs` loaded; all inactive |

## Evidence files

- `00-deploy.log`, `01-prom-queries.txt`, `02-prom-queries-final.txt`
- `swift-ops-alerts.yml` (copy of deployed rules)
- `grafana-swift-tombstone-dbspace.json`
- `05-grafana-import.txt`, `06-grafana-dashboard.txt`
- `R0-REPORT.html` (primary visual)
- `r0-p*.png` — Grafana `/render` returned identical 9KB stubs (renderer not functional); **do not treat as panel proof**. Live proof = Prom API + Grafana `api/ds/query`.

## Honest residuals

- Grafana image renderer not producing real panels (stub PNGs).
- SELinux initially blocked Grafana→`:9090`; fixed with `semanage port -m -t http_port_t -p tcp 9090`.
- W1 Galera/Keystone alerts remain stubs (`vector(0) > 1`).

## Stop-line

R0 stop-line **met** for textfile + scrape + alerts + dashboard JSON/UI presence. Not claiming PRODUCTION alert paging / on-call.
