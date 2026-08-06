# Wave 4 — Python 3-node install plan (exact steps)

**Status:** Contabo live 3-node **DONE (LAB)** in
`wave4-python-live-20260805d/` via `/opt/pyswift-venv` + `/etc/pyswift`
(openstack-swift RPM blocked by missing `python3.9dist(pyxattr)` provide).
Rust isolation migrate completed first. 4-node still optional/FROZEN.

## Preconditions (all must be true)

1. `df` on swift2/3/4: `/srv/node/d1` Use% **&lt; ~70%** (and ideally d2/d3 &lt;70%).
2. Wave 0 evidence pack exists with reclaim/VACUUM proof (or operator accepts residual).
3. No mkfs / no destructive-reset without ticket.
4. Port/disk matrix frozen ([PORT-DISK-MATRIX.md](PORT-DISK-MATRIX.md)).
5. Rust VIP `:8085` health green before touching Python.

## Install sequence (3-node · swift2/3/4)

1. **Space:** confirm `d1` empty enough for Python rings (listing/objects cleared).
2. **Packages:** install openstack-swift (or deploy `bundle/` SAIO→cluster path) on swift2/3/4 only — **not** swift1 data-plane.
3. **Bind:** Python services to ports in the matrix (8090/6102/6101/6100); devices=`/srv/node/d1` only.
4. **Rings:** build Python account/container/object rings with only `10.0.4.2–4` d1 devices; distribute to 2/3/4.
5. **Auth:** TempAuth shared test users for API compare (or Keystone after Wave 1 live).
6. **Entry:** document Python URL (`http://10.0.0.2:8090` or LB `:8086`); keep Rust on VIP `:8085`.
7. **Smoke:** auth + PUT/GET/DELETE on Python; confirm Rust VIP still 54/54 func.
8. **Unfreeze:** set stage-3A status from FROZEN → in progress only after smoke proof.
9. **Evidence:** `tools/test-results/wave4-python-live-YYYYMMDD/` with unit list + df + listener ss.

## Optional 4-node

Only after 3-node API/perf green **and** all devices Use% &lt;70%: add swift1 Python
data-plane with the same port/disk rules. Until then swift1 stays client/monitor.

## Explicit non-claims until proof

- Do **not** claim `PYTHON_CLUSTER` present.
- Do **not** use single-node SAIO as “3-node” results.
- Stage 3B/3D stay FROZEN until Python listeners + rings exist on 2/3/4.
