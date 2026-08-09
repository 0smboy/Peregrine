# W2 Contabo live runbook (executable after W0′ clears)

**Status:** READY TO RUN when gates below are green. **Not executed** this cycle.

No mkfs. No wipe of `/srv/node`. Do not run while another agent owns W0′/W1 cutover.

## Gates (all required)

```bash
# 1) Disk
for h in swift1 swift2 swift3 swift4; do ssh $h 'df -hP /srv/node/d1 /srv/node/d2 /srv/node/d3'; done
# need Use% << 70 and Avail >= 10G each

# 2) META — listing must not be a ghost wall (W0′ done or operator waiver)
ssh swift1 'TOKEN=$(curl -sS -D - -o /dev/null -H "X-Auth-User: test:tester" -H "X-Auth-Key: PEREGRINE_LAB_KEY_REQUIRED" http://10.0.0.10:8085/auth/v1.0 | awk -F": " "tolower(\$1)==\"x-auth-token\"{print \$2}" | tr -d "\r"); curl -sS -H "X-Auth-Token: $TOKEN" http://10.0.0.10:8085/v1/AUTH_test | wc -l'
# expect near-zero ghosts, or signed residual

# 3) No conflicting maintainers
ssh swift1 'who; systemctl is-active swift-object swift-proxy haproxy keepalived'
```

## Inventory intent (Contabo)

| Host | storage | replication | region | zone | devices |
|------|---------|-------------|--------|------|---------|
| swift1 | 10.0.4.1 | 10.0.8.1 | 1 | 1 | d1,d2,d3 |
| swift2 | 10.0.4.2 | 10.0.8.2 | 1 | 2 | d1,d2,d3 |
| swift3 | 10.0.4.3 | 10.0.8.3 | 2 | 1 | d1,d2,d3 |
| swift4 | 10.0.4.4 | 10.0.8.4 | 2 | 2 | d1,d2,d3 |

Group vars:

- `object_port_per_device: true`
- `object_servers_per_port: 1` (enable **after** rings distributed)
- `ring_force_rebuild: true` **once** (region + port change; does not touch data dirs)

### Port collision (Contabo-specific hard gate)

Live binds today:

| Service | Port |
|---------|------|
| object | **6200** |
| container | **6201** |
| account | **6202** |

Therefore **do not** assign object d2→6201 / d3→6202 (template default `object_bind_port+index`). That collides with container/account on the same IPs.

Pick one apply path **before** rebuild:

1. **Preferred:** set object base to a free range, e.g. `object_bind_port: 6210` → d1=6210, d2=6211, d3=6212 (leave A/C at 6202/6201), **or**
2. Move account/container to new ports first (heavier; touch all rings + confs), then keep object 6200/6201/6202.

Dry-run artifact `05-dry-run-build.sh` proves builder **shape** (12 devices, r1/r2) only — its 6200–6202 ports are **not** Contabo-apply-safe until collision is resolved.

## Procedure

### A) Backup live rings

```bash
ssh swift1 'ts=$(date -u +%Y%m%dT%H%M%SZ); mkdir -p /root/ring-backup-$ts; cp -a /etc/swift/*.ring.gz /etc/swift/*.builder.json /etc/swift/build_rings.sh /etc/swift/.rings.built /root/ring-backup-$ts/; ls -la /root/ring-backup-$ts'
```

### B) Deploy new `build_rings.sh` from Peregrine wave2 template

Repo template (object_port_per_device):  
`swift-deploy-rs/bundle-rust/roles/rust_rings/templates/build_rings.sh.j2`

Contabo live script today is **stale** (d1-only, all r1, no OBJECT_PORT_PER_DEVICE). Prefer `swift-deploy-rs` rings role / expand with force, **or** copy the proven dry-run builder:

Evidence dry-run (already validated offline):  
`05-dry-run-build.sh` → produced 12 devices, ports `{6200,6201,6202}×4`, regions `{1,2}`.

For full cluster (account/container stay single-port; object gets per-device ports), render via deploy inventory then:

```bash
ssh swift1 'cp /etc/swift/build_rings.sh /etc/swift/build_rings.sh.bak-$(date -u +%Y%m%dT%H%M%SZ)'
# install newly rendered build_rings.sh (FORCE=1 path) with d1/d2/d3 + r1/r2
ssh swift1 'bash /etc/swift/build_rings.sh | tee /tmp/w2-rings-apply.log'
# distribute rings to swift2/3/4
for h in 10.0.4.2 10.0.4.3 10.0.4.4; do
  scp /etc/swift/object*.ring.gz /etc/swift/account.ring.gz /etc/swift/container.ring.gz root@$h:/etc/swift/
done
```

### C) Enable spp and restart object servers

```bash
# on each node: set servers_per_port = 1 in /etc/swift/object-server.conf
# then:
for h in swift1 swift2 swift3 swift4; do
  ssh $h 'systemctl restart swift-object; sleep 2; ss -lntp | grep 620; journalctl -u swift-object -n 40 --no-pager'
done
# expect listeners on 6200,6201,6202 and journal listen_ports=[6200, 6201, 6202]
```

### D) r1/r2 label drill (not WAN DR)

```bash
python3 -m json.tool /etc/swift/object.ring.gz.builder.json | grep -E '"region"|"zone"|"port"|"device"' | head -80
# PUT/GET via VIP; sample handoff diversity — affinity lab only
```

### E) Gates

```bash
scp Peregrine/swift-rust/tools/func-suite.sh swift1:/tmp/func-suite.sh
ssh swift1 'bash /tmp/func-suite.sh http://10.0.0.10:8085 test:tester PEREGRINE_LAB_KEY_REQUIRED vip-w2-spp'
# need PASS=54 FAIL=0

# spp smoke: PUT object, confirm process-per-port children
ssh swift1 'ps -ef | grep swift-object-server | grep -v grep'

# failover note: identify VIP master, systemctl kill -s STOP keepalived briefly on master, confirm VIP moves, CRUD still works, restore
```

### F) Soak

```bash
# ≥1h fail=0 data-plane soak on VIP after spp enable; record under this pack
```

## Rollback

```bash
# restore ring backup + servers_per_port=0 + restart swift-object on all nodes
# re-run func-suite 54/54
```

## Claim boundary

- Live multi-region here = **ring label affinity**, not cross-site DR / async container-sync.
