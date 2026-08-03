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

L3b container sharding stays **after** Formal Performance `ISO-CONFIG` clean baseline
(R4 Rust DIRECT baseline now exists; 16MB_read remains **WARN** — prepare/seed issue).

| Item (2026-08-03 refresh) | Status |
|---------------------------|--------|
| Full 4-node `openstack-swift` Performance cluster | **Absent** → Python formal **FROZEN** (`PYTHON_CLUSTER_ABSENT`) |
| autocos multi-endpoint true 4-proxy fanout | Pilot uses `ST_ENDPOINT` RR; full fanout backlog |
| 16MB_read formal ACCEPT | Blocked until prepare object_count/runtime retune (R8) |
| 6h soak per impl | 1h smoke done in R6; extend in R8 |
