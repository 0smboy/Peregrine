# Contabo object ring rebuild for servers_per_port (no wipe)

Date: 2026-08-05

## Goal

After Wave 0 clears space, rebuild object rings so each device gets a distinct port:

- d1 → `object_bind_port` (6200)
- d2 → 6201
- d3 → 6202

Account/container rings stay single-port (6202 / 6201).

## Preconditions

- Wave 0 `swift delete -a` + tombstone reclaim + SQLite VACUUM evidence shows usable free space
- No mkfs / destructive-reset
- Maintenance window for ring rebalance + replication heal

## Procedure

1. Confirm `object_port_per_device: true` in project `group_vars/all` (sample default).
2. Deploy updated `build_rings.sh` via bundle-rust rings role.
3. Prefer expand/idempotent add if devices already present with wrong ports — may need `ring_force_rebuild` for port changes (ops decision; still no data wipe).
4. Restart object-server with `servers_per_port ≥ 1` and correct `ring_ip`.
5. Verify: discovery returns `{6200,6201,6202}` on multi-disk nodes; `ss -lntp | grep 620` shows children.
6. Run func-suite VIP 54/54 + short spp smoke.

## Status

**BACKLOG** — not executed this cycle (Wave 0 ownership is another agent; space not verified here).
