# python_only_format_disks (docs mapping)

**Do not use this role for Contabo live data disks.**

| Python | Path |
|--------|------|
| Role | `swift-deploy-rs/bundle/roles/format_disks` |
| Play | `bundle/swift.yml` hosts `format_disk_servers` |
| New disks | `bundle/roles/format_new_disks` via `add_new_disks.yml` |

## Rust path (safe)

1. Prepare/mount XFS **out-of-band** at `/srv/node/<name>`.
2. Append basename to host_vars `swift_devices`.
3. Apply `bundle-rust/expand.yml` (mkdir-only + ring expand).

## Dual-guard

- `rust_disks` never mkfs/wipe.
- Workspace rejects `node.disks` for `stack: rust`.
- Wipe requires ticket + `--allow-disk-wipe` on a non-bundle-rust path.

Authority: [ANSIBLE-V3-SURFACE.md](../../../../docs/fairness-lab/ANSIBLE-V3-SURFACE.md) §3.3.
