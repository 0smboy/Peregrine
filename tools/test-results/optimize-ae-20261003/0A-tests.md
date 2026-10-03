# Phase A — tests only

Date: 2026-10-03. No SSH. `POST /api/apply` was not sent.

## What changed

- `swift-deploy-rs/tests/planner_safety.rs` seals `bundle/swift.yml` for `config_sample` and `config_contabo_identity`.
- `swift-deploy-rs/src/cli.rs` UI default inventory is `bundle/config_contabo_identity/swift_hosts`. That inventory's `format_disk_servers` group is empty, so mkfs hosts are empty. `config_sample` remains the structure example and is not the UI default.
- `swift-console/src/proxy.rs` keeps the `Content-Length` assignment and sends an unsized body stream, so reqwest does not invent the header.
- `swift-rust` proxy: a backend account 404 that carries `X-Account-Status: Deleted` is not replaced by the autocreate empty listing. Policy 0 without `policy_type` is exercised as replication under `--features ec`.

## Commands and results

Working directories are the package roots. All of these exited 0.

```
cd swift-deploy-rs
cargo test --test planner_safety -- --test-threads=8 sample_swift_plan identity_swift_plan
```

`identity_swift_plan_seals_with_empty_disk_wipe_hosts` ok. `sample_swift_plan_seals_and_mkfs_hosts_are_the_sample_pair` ok. 2 passed, 0 failed (2026-10-03).

```
cd swift-deploy-rs
cargo test --lib ui_default_inventory_does_not_arm_disk_wipe
```

`cli::default_inventory_tests::ui_default_inventory_does_not_arm_disk_wipe` ok. 1 passed (2026-10-03).

```
cd swift-console
cargo test --bin swift-console json_body_through_deploy_proxy
```

`proxy::tests::json_body_through_deploy_proxy_sets_content_length_to_byte_length` ok. 1 passed (2026-10-03).

Removing the `Content-Length` assignment and rerunning the same command failed: upstream request was `transfer-encoding: chunked` and the parsed Content-Length was `None`, expected `Some(17)` for `{"note":"计划"}`. The assignment was put back. The restored test passed, as recorded above.

```
cd swift-rust
LIBERASURECODE_LIB_DIR=/tmp/liberasurecode-prefix/lib \
DYLD_LIBRARY_PATH=/tmp/liberasurecode-prefix/lib \
cargo test -p swift-proxy-server --features ec --test ec_integration -- --test-threads=1
```

`policy0_without_policy_type_replicates_thirty_bytes` ok. `test_ec_object_put_get_round_trip_and_fragment_loss` ok. 2 passed (2026-10-03). Local liberasurecode 1.6.5 was built under `/tmp/liberasurecode-prefix` because the host had no system copy. That tree is not in the repo.

```
cd swift-rust
cargo test -p swift-proxy-server --test integration deleted_account
cargo test -p swift-proxy-server --test integration test_container_put_does_not_mutate_when_account_autocreate_fails
```

`test_deleted_account_head_is_not_a_writable_empty_account` ok. `test_container_put_does_not_mutate_when_account_autocreate_fails` ok. Each 1 passed (2026-10-03).

## Acceptance

Those tests passed. Sample mkfs hosts are `192.168.2.51` and `192.168.2.52`. Identity disk-wipe tasks have empty host lists. Yum Upgrade, Restart sshd, and Installing mariadb packages have non-empty hosts on the identity plan. The UI default is not `config_sample`.
