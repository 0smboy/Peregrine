# monitoring_overlay_path (docs mapping)

Monitoring agents are a **sibling** bundle, not roles inside `bundle-rust/swift.yml`.

| Piece | Path |
|-------|------|
| Playbook | `swift-deploy-rs/bundle-monitoring/swift.yml` |
| Roles | `mon_payload`, `mon_config`, `mon_systemd` |
| Contabo Prom / textfile / Grafana | `tools/monitoring/` |

Apply against the **same** inventory a rust workspace emits (typically
`storage_nodes` covers every Contabo node).

```sh
swift-deploy apply … --bundle bundle-monitoring --playbook swift.yml
```

Data-plane remain on `bundle-rust`. Dual-guard: monitoring roles must not format disks.
