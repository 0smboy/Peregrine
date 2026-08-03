# Blocked by missing Rust implementation

These items explain why Contabo/deploy cannot mirror full Python ansible.  
**This cycle does not implement them** — it only prevents false parity claims.

| Item | Impact on fairness | Priority backlog |
|------|--------------------|------------------|
| Configurable Paste `pipeline` | Middleware surface unequal | High |
| memcache / `[filter:cache]` | Listing/auth cache path differs | High |
| `servers_per_port` / per-disk object listeners | Optimized Python topology unmatched | High |
| TempURL / formpost / bulk | L2 API unsupported | Medium |
| Keystone / MariaDB | Auth model out of scope | Medium (separate cycle) |
| S3 API | Different API contract | Medium |
| Full auditor/expirer/reconciler daemons as conf services | Background I/O profile differs | Medium |
| `workers` prefork semantics | Integer knobs mislead A/B | Doc+mapping first (done in CONFIG-PARITY) |
| Keepalived inside bundle-rust | HA is Contabo overlay | Ops overlay (accepted) |

L3b container sharding stays **after** Formal Performance `ISO-CONFIG` clean baseline.
