# SLO async-delete Python parity · expirer hash + ACL · 2026-08-07

## Scope
`crates/swift-middleware/src/slo.rs` (+ `HashPathConfig` from `swift-core`).

## Implemented (Python parity)

### 1. Expirer task container sharding
Python `ExpirerConfig.get_expirer_container` (`swift/obj/expirer.py`):

```
shard_int = int(hash_path(acc, cont, obj), 16) % 100
bucket    = (x_delete_at // 86400) * 86400 - shard_int
return normalize_delete_at_timestamp(bucket)  # 10-digit, clamped ≥ 0
```

Rust: `expirer_task_container` uses `HashPathConfig::hash_path` +
`normalize_delete_at_timestamp(..., false)`.

Shard key = **manifest** a/c/o (Python `get_expirer_account_and_container(ts, account, container, obj)`), not per-segment.

### 2. Write ACL probes
Python: `get_container_info` + `swift.authorize` with `write_acl` on
manifest container, then segment container when different.

Rust: `probe_async_delete_write_acl` — HEAD `/{vrs}/{acc}/{cont}` with
client auth headers; 401/403 short-circuit before expirer `UPDATE`.

### 3. Tests
| Test | Covers |
|------|--------|
| `test_expirer_task_container_hash_sharding` | Known vectors vs CPython `hash_path` (suffix=`changeme`); day-zero clamp |
| `test_async_delete_acl_probe_forbidden` | Manifest HEAD → 403; no enqueue |
| `test_async_delete_acl_probe_segment_container` | Manifest OK, segment HEAD → 401 |
| `test_multipart_delete_async_enqueues_and_deletes_manifest` | HEAD probe + UPDATE path equals `expirer_task_container` (not plain day) |

### 4. Docs
Module + `handle_async_delete` docs state hash sharding + ACL probes as done.
Deferred list no longer includes these items (still deferred: concurrent HEAD
yield_frequency, listing slo_etag refetch, bulk Accept, UPDATE-fail 503).

## Verify
```bash
cargo test -p swift-middleware --lib slo::
# → 27 passed
```

Evidence:
- `01-cargo-test.txt` — full cargo output
- `02-python-vectors.txt` — CPython recompute of pinned vectors

## Residual (not this task)
- Full `swift.authorize` / env-callback path (HEAD approximation only)
- concurrent HEAD pile + wall-clock `yield_frequency`
- SLO-etag container-listing refetch
- bulk Accept negotiation beyond JSON
- Python 503 on expirer UPDATE fail (Rust: best-effort bg segment DELETE)
