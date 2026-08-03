# CONFIG-PARITY — Rust honored knobs vs Python surface

Generated from `main.rs` `get()` scans. Rows=73; unsupported=11.

## Workers semantics (critical)

Rust maps workers*max_clients -> worker_threads clamped to 128; NOT Python eventlet prefork process count. Iso-config must align effective concurrency / CPU quota, not the integer alone.

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
| object | `servers_per_port` | unsupported |
| object | `use_splice` | unsupported |
| proxy | `allow_account_management` | unsupported |
| proxy | `memcache_servers` | unsupported |
| proxy | `pipeline` | unsupported |
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
| object | `workers` | iso-config-with-semantic-mapping |
| proxy | `account_autocreate` | iso-config |
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
