# Contabo Wave 2 dry-run plan (no wipe)

## Preconditions

- Wave 0 API clear + tombstone/VACUUM evidence shows usable Avail on swift1–4 `/srv/node/d*`
- Do **not** mkfs / destructive-reset

## Ring rebuild (when safe)

1. Inventory host_vars: swift1/2 `region: 1`, swift3/4 `region: 2`; zones distinct; `swift_devices: [d1,d2,d3]`
2. `object_port_per_device: true` (group_vars default)
3. Set `ring_force_rebuild: true` once (or expand-only if adding devices)
4. Deploy rings role only; verify `object.ring.gz` devices show ports 6200/6201/6202 per node
5. Set `object_servers_per_port: 1` (or 2); restart object-server
6. Journal: `servers_per_port=…: listen_ports=[6200, 6201, 6202]`
7. Smoke PUT/GET; func VIP 54/54; note perf vs pre-rebuild baseline

## Multi-region labels

1. Confirm ring builder specs contain `r1z*` and `r2z*`
2. PUT object; `swift-get-nodes` / ring dump for handoff region diversity
3. Document: same-LAN latency — **not** cross-city DR

## Abort criteria

- Any node `/srv/node` Avail < 10G → stop, return to Wave 0
- Rebuild must not touch data directories
