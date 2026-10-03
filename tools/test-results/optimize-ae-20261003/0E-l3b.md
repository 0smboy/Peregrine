# Phase E — L3b shrink failure case

Date: 2026-10-03. No VIP 16MB rerun. Production knobs were not changed: `workers = 16`, `container_update_mode = sync`, `container_update_timeout = 1.0`, `fsync_on_close = true`, `reuse_port = false`. L1b, L2, and L4 stay DROP. L3b stays non-production / deferred (`docs-site/src/content/docs/performance.mdx`, lever table: "sharding (L3b) deferred").

## Test

`swift-rust/crates/swift-container-server/src/sharder.rs`

`sharder::tests::test_multi_primary_automatic_shrink_leaves_remote_donor_shrinking`

The root row says a donor is `SHRINKING` with `object_count = 3`. The donor database is not on this host. `process_shrinking_donors` returns 0, the donor stays `SHRINKING` with `deleted = 0`, and no extra `.db` is created. That is the multi-primary automatic-shrink failure case: this process does not invent an empty donor and does not mark a remote donor `SHRUNK`.

## Command and result

```
cd swift-rust
cargo test -p swift-container-server --lib \
  sharder::tests::test_multi_primary_automatic_shrink_leaves_remote_donor_shrinking \
  -- --exact
```

ok. 1 passed, 0 failed (2026-10-03).
