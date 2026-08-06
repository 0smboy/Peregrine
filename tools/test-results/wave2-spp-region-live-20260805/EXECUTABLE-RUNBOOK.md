# W2 Contabo live runbook (executable when GO)

Date: 2026-08-05  
Status: **BACKLOG** — do not execute until every GO gate in `00-GO-NOGO.md` is green.  
No mkfs. No Galera/Keystone. No TLS cutover.

## Preconditions (re-check at window open)

```bash
for h in swift1 swift2 swift3 swift4; do
  ssh $h 'hostname; df -hP /srv/node/d1 /srv/node/d2 /srv/node/d3; systemctl is-active swift-proxy haproxy keepalived'
done
# META: sample account listing HEADs must not be majority 404
# Code: Contabo /opt/swift-deploy/bundle-rust rings template must include OBJECT_PORT_PER_DEVICE
# Ports: object multi-ports must NOT collide with account:6202 / container:6201
```

### Port collision fix (required before rebuild)

Default `object_bind_port=6200` + `object_port_per_device` → d1:6200, d2:6201, d3:6202 **collides** with live container/account listeners.

Pick **one** ops-approved option and document in the live pack:

1. **Preferred:** raise object base (e.g. `object_bind_port: 6300` → 6300/6301/6302) and keep account 6202 / container 6201.
2. Or move account/container to a non-overlapping pair (larger blast radius).
3. Do **not** enable `object_servers_per_port≥1` until `ss -lntp` can show object children on the chosen ports without fighting account/container.

### Code deploy (before rings)

1. Sync Peregrine `swift-deploy-rs/bundle-rust` wave2 templates to Contabo `/opt/swift-deploy/bundle-rust` (or rebuild via `swift-deploy` project that renders them).
2. Confirm binary has spp supervise (`strings` / unit tests already green in `wave2-spp-region-20260805`).
3. Inventory: `swift_devices: [d1,d2,d3]` on each node; region labels per table below.

## Region / zone labels (affinity lab only — not WAN DR)

| Node | storage IP | region | zone |
|------|------------|--------|------|
| swift1 | 10.0.4.1 | 1 | 1 |
| swift2 | 10.0.4.2 | 1 | 2 |
| swift3 | 10.0.4.3 | 2 | 1 |
| swift4 | 10.0.4.4 | 2 | 2 |

## Ring rebuild (maintenance window)

Today's rings are **d1-only × 4 nodes**, single object port 6200, all region=1. Live needs expand **or** force rebuild to add d2/d3 with distinct object ports.

```bash
# On deploy controller / first proxy — AFTER code sync + port plan frozen
# Prefer expand if builder json present (they are on Contabo today):
#   ring_expand=true  OR  ADD_NODES path
# Use ring_force_rebuild=true only if expand cannot change ports; still NO wipe of /srv/node

# Example shape after success (object policy-0), ports illustrative if base=6300:
#   10.0.4.{1..4}:6300/d1, :6301/d2, :6302/d3  with r1/r2 labels
# Account/container remain single-port; may also gain d2/d3 devices per inventory.
```

Verify:

```bash
python3 - <<'PY'
import json
d=json.load(open('/etc/swift/object.ring.gz.builder.json'))
ports=sorted({x['port'] for x in d['devices'] if x})
devs=sorted({x['device'] for x in d['devices'] if x})
regs=sorted({x['region'] for x in d['devices'] if x})
print('ports', ports, 'devices', devs, 'regions', regs, 'n', len(d['devices']))
PY
# Expect 3 object ports/node worth of devices; regions {1,2}
```

Distribute rings to all nodes; restart object services only after conf update.

## Enable servers_per_port

1. Set `object_servers_per_port: 1` (or 2) in rendered group_vars / object-server.conf.
2. Restart `swift-object.service` on all nodes.
3. Journal must show listen_ports covering the three object ports.
4. `ss -lntp | grep -E ':630[0-2]'` (or chosen base) shows object children; account/container still on 6202/6201.

## Smoke + gates

```bash
# CRUD smoke (as in 05-CRUD-SMOKE.txt)
# spp smoke: PUT with get-nodes showing distinct object ports across devices
bash /root/work/swift-rust/tools/func-suite.sh http://10.0.0.10:8085 test:tester "$PASS" vip-post-w2
# Failover note: keepalived VIP move once; re-CRUD
# Soak ≥1h fail=0 if window allows; else start soak and leave path in SUMMARY
```

## Abort / rollback

- Any `/srv/node` Avail < 10G → abort.
- Object bind fails (EADDRINUSE on 6201/6202) → revert `servers_per_port=0`, restore previous `*.ring.gz` from pre-window backup.
- func < 54/54 → rollback rings + conf; do not claim GREEN.
- Never mkfs; never delete `/srv/node` trees as “cleanup”.

## Pre-window backup commands

```bash
TS=$(date -u +%Y%m%dT%H%M%SZ)
for h in swift1 swift2 swift3 swift4; do
  ssh $h "mkdir -p /root/w2-ring-backup-$TS && cp -a /etc/swift/*.ring.gz /etc/swift/*.builder.json /etc/swift/object-server.conf /root/w2-ring-backup-$TS/"
done
```
