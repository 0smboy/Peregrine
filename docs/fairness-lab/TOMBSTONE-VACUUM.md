# Tombstone reclaim + SQLite VACUUM (Wave 0)

Evidence pack: `tools/test-results/wave0-clear-20260805/`.  
Plan authority: production-gap Wave 0 (API clear, not mkfs).

## Object tombstones (`.ts`)

Rust DELETE writes a `.ts` tombstone via `swift-diskfile`;  
`cleanup_ondisk_files` removes reclaimable tombstones when  
`now - tombstone_timestamp > reclaim_age` (default **604800** / 7 days).

### Metrics

#### Gap (pre-R0, honest)

Through Wave 0 clear / A+B (2026-08-05) these gauges existed **CLI-only**:

```bash
swift-recon tombstones /srv/node --prometheus
swift-recon dbspace /srv/node --prometheus
```

They were **not** scraped into Prometheus and **not** on a Grafana dashboard.
Ops could not alert on tombstone growth or freelist from the panel path.
Evidence of the gap: Contabo `node_exporter` lacked
`--collector.textfile.directory` until R0
(`tools/test-results/r0-metrics-prom-20260805/`).

#### After R0 wiring (2026-08-05)

Per-node systemd timer `swift-recon-textfile.timer` writes
`/var/lib/node_exporter/textfile_collector/swift-recon.prom` every 2 minutes
via `swift-recon tombstones|dbspace --prometheus`. Prometheus scrapes all four
`:9100` targets; alert rules live in
`tools/monitoring/rules/swift-ops-alerts.yml` (tombstone growth, freelist,
device Use%>85%; Galera/Keystone stubs until W1). Grafana dashboard JSON:
`tools/monitoring/grafana/swift-tombstone-dbspace.json` (UI import may be
blocked if Grafana is not installed — scrape+alerts still land).

```bash
swift-recon tombstones /srv/node
swift-recon tombstones /srv/node --prometheus
```

| Metric | Labels | Meaning |
|--------|--------|---------|
| `swift_object_tombstones` | `node`, `device`, `policy` | Count of `*.ts` under `objects` / `objects-N` |
| `swift_object_tombstone_bytes` | same | Sum of `.ts` file sizes |

Implementation: `swift-cli` `space_metrics` + `swift-recon` subcommand.  
Unit tests cover policy dir discovery and Prometheus exposition.  
Units: `tools/monitoring/systemd/swift-recon-textfile.{service,timer}`.

### Lab reclaim experiment

1. Backup `/etc/swift/object-server.conf` (and container-server if present).
2. Temporarily set `reclaim_age = 600` on all storage nodes; restart  
   `swift-object-replicator` (and auditor/updater if they cache conf).
3. Delete workload (API) so fresh `.ts` appear; sample counts over ≥10–15 min.
4. Gate: tombstones from the lab wave fall toward 0 (or &lt;1% of peak) within  
   the window **if** replicator/cleanup walks those hash dirs.
5. **Restore** `reclaim_age = 604800`. Never leave 600 in production templates.

Honest residuals to expect:

- Reclaim runs on replicator/auditor hash-dir passes, not instantly at DELETE.
- Orphan `.data` with no container listing path will not become `.ts` via API clear.
- Account/container object counts can stay stale until updaters/reclaim catch up.
- **Wave 0 bug (fixed):** `swift-object-replicator` ignored conf and always used
  `CleanupConfig::default()` (`reclaim_age=604800`). Lab `reclaim_age=600` had no
  effect until the binary was wired to read `[object-replicator]` / `DEFAULT`.
  Also ensure the knob lives under those sections (not only `[object-expirer]`).
- **Wave 0 reclaim residual:** Even after wire-up (logs show `reclaim_age=600s`),
  cluster tombstone counts stayed near-flat for ~21 minutes (~48k/node). Likely
  cause: replicator pass not visiting enough hash dirs under load / rsync stalls;
  not “instant DELETE reclaim”. Gate to ts≈0 in 10–15m: **FAIL** (honest).

## SQLite space + VACUUM

Account/container brokers live in `swift-db`. Row DELETE leaves freelist pages;  
**file size often does not drop** until `VACUUM`.

### Metrics

Same R0 path as tombstones: CLI → textfile → Prometheus (`swift_db_*`).  
Before R0 these were CLI-only and absent from panels/alerts.

```bash
swift-recon dbspace /srv/node
swift-recon dbspace /srv/node --prometheus
```

| Metric | Labels | Meaning |
|--------|--------|---------|
| `swift_db_file_bytes` | `node`, `kind` | Sum of `.db` sizes (`account` / `container`) |
| `swift_db_freelist_count` | same | Sum of `PRAGMA freelist_count` |
| `swift_db_freelist_bytes` | same | Approx freelist × `page_size` |
| `swift_db_files` | same | Number of sampled DBs |

### VACUUM path

```bash
# Single device — off the hot write path; holds a write lock during VACUUM
swift-recon vacuum /srv/node/d1
```

Library API: `swift_db::sample_db_space`, `vacuum_db`, `vacuum_device_dbs`.  
Unit test proves: DELETE → freelist &gt; 0 and size stable; VACUUM → freelist 0 and  
file shrinks.

### Production policy (default)

- Do **not** VACUUM on every delete or on the request path.
- Prefer scheduled / once ops when freelist_bytes is large and load is low.
- Document any `vacuum_age` daemon wiring as opt-in; Contabo lab may run once  
  after API clear for before/after evidence only.

## Contabo notes

- VIP `http://10.0.0.10:8085` TempAuth `test:tester` — often only reachable  
  from inside the lab (laptop may see empty reply / timeout).
- Clear via REST equivalent of `swift delete -a` (`wave0_delete_a.py`); no  
  `mkfs`, no wipe of `/srv/node`.
