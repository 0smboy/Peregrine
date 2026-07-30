# mon_payload — monitoring agent binary payload

`files/bin/` ships as a `.keep` placeholder in the repository. Before running
`audit`/`apply` for real, populate it on the control machine from the
downloaded agent bundle:

```sh
cp /root/monitoring-payload/bin/* bundle-monitoring/roles/mon_payload/files/bin/
```

Expected contents (3 binaries, linux/amd64, statically linked or glibc >= 2.34):

```
bin/  node_exporter statsd_exporter alloy
```

Version requirements:

- `node_exporter`: any current release (1.x).
- `statsd_exporter`: >= 0.20.0 (`observer_type` / `histogram_options` mapping
  syntax used by mon_config's `/etc/statsd-mapping.yml`).
- `alloy`: any current release (1.x); the config uses the stable
  `loki.source.journal` / `loki.relabel` / `loki.write` components.

The payload is sealed by the bundle fingerprint: changing any file here
invalidates existing plans, which is intended. With only the `.keep`
placeholder present, `audit`, `validate`, and `plan` still succeed (planning
never opens payload files), but `apply` fails at the first copy task.

Note: smartctl_exporter is deliberately NOT part of this payload — the target
nodes use virtio/EBS virtual disks which expose no SMART data.
