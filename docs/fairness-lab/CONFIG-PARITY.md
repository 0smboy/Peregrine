# CONFIG-PARITY — Rust honored knobs vs Python surface

Generated from `main.rs` `get()` scans. Rows=73; unsupported=9 (P2c: `servers_per_port` upgraded).

## Workers semantics (critical)

Rust maps `workers*max_clients` → `worker_threads` clamped to 128; NOT Python eventlet prefork process count. Iso-config must align effective concurrency / CPU quota, not the integer alone.

See [WORKERS-SEMANTICS.md](WORKERS-SEMANTICS.md). Tool: `swift-effective-concurrency`.

**Wave 2:** `servers_per_port` discovers ring ports and supervises **one OS process per (port, worker)** (Python-parity process isolation). Rings use `object_port_per_device` (d1→6200, d2→6201, …). Fairness class: `iso-config`. Contabo live ring rebuild is backlog (no wipe); default Contabo conf remains `servers_per_port=0` until rebuilt.

## Labels required on public claims

- `CORE-PATH-ONLY`
- `ISO-CONFIG`
- `ISO-RESOURCE`
- `HA-PATH`
- `DIRECT-4PROXY`
- `DATA-PATH`
- `PRODUCTION-COMPLETE`
- `NOISY`
- `SUPERSEDED`
- `NON_EQUIVALENT`
- `unsupported`

## Unsupported / not parsed (high signal)

| service | knob | fairness_class |
|---------|------|----------------|
| object | `conn_timeout` | unsupported |
| object | `eventlet_tpool_num_threads` | unsupported |
| object | `node_timeout` | unsupported |
| object | `replication_server` | unsupported |
| object | `use_splice` | unsupported |
| proxy | `pipeline` (full Paste arbitrary filters) | unsupported |
| proxy | `pipeline` (P0+P1a+P1b primary: proxy-logging/cache/listing_formats/tempauth/tempurl/bulk/formpost/staticweb/container_quotas/account_quotas/symlink/versioned_writes/ratelimit/copy/slo/dlo + smaller on-by-config) | iso-config-partial |
| proxy | `memcache_servers` (`[filter:cache]`) | iso-config-partial — parsed; client constructed; **P1c:** account/container info-cache L2 shared when set (L1-only without) |
| account | `databases_per_node` | unsupported |
| container | `allow_versions` | unsupported |

## Parsed knobs

| service | knob | fairness_class |
|---------|------|----------------|
| object | `bind_ip` | iso-config |
| object | `bind_port` | iso-config |
| object | `client_timeout` | iso-config |
| object | `container_update_mode` | iso-config |
| object | `container_update_timeout` | iso-config |
| object | `devices` | iso-config |
| object | `fallocate_reserve` | iso-config |
| object | `fsync_on_close` | iso-config |
| object | `log_level` | iso-config |
| object | `log_name` | iso-config |
| object | `log_statsd_host` | iso-config |
| object | `log_statsd_metric_prefix` | iso-config |
| object | `log_statsd_port` | iso-config |
| object | `max_clients` | iso-config |
| object | `mount_check` | iso-config |
| object | `reuse_port` | iso-config |
| object | `servers_per_port` | iso-config |
| object | `ring_ip` | iso-config |
| object | `workers` | iso-config-with-semantic-mapping |
| proxy | `account_autocreate` | iso-config |
| proxy | `allow_account_management` | iso-config — supported; gates account PUT/DELETE with **405** when false; `/info` advertises the flag; code default **false** when unset; Rust lab templates set `true` |
| proxy | `bind_ip` | iso-config |
| proxy | `bind_port` | iso-config |
| proxy | `client_timeout` | iso-config |
| proxy | `conn_timeout` | iso-config |
| proxy | `error_suppression_interval` | iso-config |
| proxy | `error_suppression_limit` | iso-config |
| proxy | `gold` | iso-config |
| proxy | `log_level` | iso-config |
| proxy | `log_name` | iso-config |
| proxy | `log_statsd_host` | iso-config |
| proxy | `log_statsd_metric_prefix` | iso-config |
| proxy | `log_statsd_port` | iso-config |
| proxy | `max_clients` | iso-config |
| proxy | `node_timeout` | iso-config |
| proxy | `recheck_account_existence` | iso-config |
| proxy | `recheck_container_existence` | iso-config |
| proxy | `storage_url` | iso-config |
| proxy | `trace_endpoint` | iso-config |
| proxy | `trace_sample_ratio` | iso-config |
| proxy | `workers` | iso-config-with-semantic-mapping |
| account | `bind_ip` | iso-config |
| account | `bind_port` | iso-config |
| account | `client_timeout` | iso-config |
| account | `devices` | iso-config |
| account | `log_level` | iso-config |
| account | `log_name` | iso-config |
| account | `log_statsd_host` | iso-config |
| account | `log_statsd_metric_prefix` | iso-config |
| account | `log_statsd_port` | iso-config |
| account | `max_clients` | iso-config |
| account | `mount_check` | iso-config |
| account | `workers` | iso-config-with-semantic-mapping |
| container | `bind_ip` | iso-config |
| container | `bind_port` | iso-config |
| container | `client_timeout` | iso-config |
| container | `devices` | iso-config |
| container | `log_level` | iso-config |
| container | `log_name` | iso-config |
| container | `log_statsd_host` | iso-config |
| container | `log_statsd_metric_prefix` | iso-config |
| container | `log_statsd_port` | iso-config |
| container | `max_clients` | iso-config |
| container | `mount_check` | iso-config |
| container | `workers` | iso-config-with-semantic-mapping |
| object-expirer | `interval` | iso-config |
| object-expirer | `reclaim_age` | iso-config |
| object-expirer | `log_statsd_host` | iso-config |
| object-expirer | `log_statsd_port` | iso-config |
| object-expirer | `log_statsd_metric_prefix` | iso-config |
| account-reaper | `interval` | iso-config |
| account-reaper | `delay_reaping` | iso-config |
| account-reaper | `log_statsd_host` | iso-config |
| account-reaper | `log_statsd_port` | iso-config |
| account-reaper | `log_statsd_metric_prefix` | iso-config |
| container-updater | `interval` | iso-config |
| container-updater | `log_statsd_host` | iso-config |
| container-updater | `log_statsd_port` | iso-config |
| container-updater | `log_statsd_metric_prefix` | iso-config |
| container-reconciler | `interval` | iso-config |
| container-reconciler | `reclaim_age` | iso-config |
| container-reconciler | `log_statsd_host` | iso-config |
| container-reconciler | `log_statsd_port` | iso-config |
| container-reconciler | `log_statsd_metric_prefix` | iso-config |
