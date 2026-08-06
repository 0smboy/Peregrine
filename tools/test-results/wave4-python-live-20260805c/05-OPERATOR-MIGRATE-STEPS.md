# Operator steps — Rust leave exclusive `d1` (then unfreeze 3A)

Do **not** run these until: (a) VIP TempAuth **or** Keystone CRUD is green again, (b) a maintenance window is declared, (c) inventory/`build_rings.sh` is synced to match live spp ports.

Target after migrate (matches PORT-DISK-MATRIX):

| Ring | Devices | Ports |
|------|---------|-------|
| account | **d2** only (×4 nodes) | 6202 |
| container | **d2** only (×4 nodes) | 6201 |
| object / object-1 | **d2+d3** (no d1) | 6211, 6212 |
| Python (later) | **d1** exclusive on swift2/3/4 | 8090 / 6102 / 6101 / 6100 |

## 0) Pre-window gates

```bash
for h in swift1 swift2 swift3 swift4; do
  ssh $h 'hostname; df -hP /srv/node/d1 /srv/node/d2 /srv/node/d3; systemctl is-active swift-proxy haproxy keepalived'
done
# Require: Use%<70%; VIP https://10.0.0.10:8085/healthcheck → 200
# Require: one working auth path CRUD (TempAuth OR Keystone) before touching rings
```

## 1) Backup rings + conf (all nodes)

```bash
TS=$(date -u +%Y%m%dT%H%M%SZ)
for h in swift1 swift2 swift3 swift4; do
  ssh $h "mkdir -p /root/w4-ring-backup-$TS && cp -a /etc/swift/*.ring.gz /etc/swift/*.builder.json /etc/swift/build_rings.sh /etc/swift/.rings.built /etc/swift/object-server.conf /etc/swift/account-server.conf /etc/swift/container-server.conf /root/w4-ring-backup-$TS/ && ls -la /root/w4-ring-backup-$TS"
done
echo "BACKUP_TS=$TS"
```

## 2) Sync deploy plan BEFORE any rebalance

On the deploy controller / Peregrine tree:

1. Update Contabo inventory host_vars so Rust `swift_devices` for dual-stack = `[d2, d3]` (or account/container `[d2]`, object `[d2,d3]`).
2. Keep `object_bind_port` / spp base at **6210** (live) — never regenerate a script that uses `6200` while spp is live.
3. Render and **diff** `/etc/swift/build_rings.sh` on Contabo vs live rings; stamp must not greenfield-rm live spp rings.
4. Prefer `ring_expand=true` path from `bundle-rust` (idempotent add) over `ring_force_rebuild`.

## 3) Drain d1 (on swift1, then distribute)

```bash
RB=/usr/local/bin/swift-ring-builder
cd /etc/swift

# --- account: add d2, set d1 weight 0, rebalance ---
for n in 1 2 3 4; do
  ip=10.0.4.$n; rip=10.0.8.$n; z=$n
  $RB account.ring.gz add "r1z${z}-${ip}:6202R${rip}:6202/d2" 100
  $RB account.ring.gz add "r1z${z}-${ip}:6202R${rip}:6202/d1" 0
done
$RB account.ring.gz rebalance

# --- container: same pattern ---
for n in 1 2 3 4; do
  ip=10.0.4.$n; rip=10.0.8.$n; z=$n
  $RB container.ring.gz add "r1z${z}-${ip}:6201R${rip}:6201/d2" 100
  $RB container.ring.gz add "r1z${z}-${ip}:6201R${rip}:6201/d1" 0
done
$RB container.ring.gz rebalance

# --- object + object-1: keep d2@6211 d3@6212; set d1@6210 weight 0 ---
# NOTE: regions on live object ring are r1 (swift1/2) and r2 (swift3/4) — match builder.json exactly
python3 - <<'PY'
import json,subprocess
RB="/usr/local/bin/swift-ring-builder"
for ring in ["object.ring.gz","object-1.ring.gz"]:
  d=json.load(open(ring+".builder.json"))
  for dev in d["devices"]:
    if not dev: continue
    rip = dev.get("replication_ip") or dev["ip"]
    rport = dev.get("replication_port") or dev["port"]
    spec=f"r{dev['region']}z{dev['zone']}-{dev['ip']}:{dev['port']}R{rip}:{rport}/{dev['device']}"
    w = 0 if dev["device"]=="d1" else 100
    print(subprocess.check_output([RB, ring, "add", spec, str(w)], text=True).strip())
  print(subprocess.check_output([RB, ring, "rebalance"], text=True).strip())
PY
```

Distribute:

```bash
for h in swift2 swift3 swift4; do
  scp /etc/swift/account.ring.gz /etc/swift/container.ring.gz \
      /etc/swift/object.ring.gz /etc/swift/object-1.ring.gz \
      /etc/swift/*.builder.json root@$h:/etc/swift/
done
# restart account/container/object (not proxy unless needed)
for h in swift1 swift2 swift3 swift4; do
  ssh $h 'systemctl restart swift-account swift-container swift-object; sleep 2; ss -lntp | grep -E ":620|:621"'
done
```

## 4) Prove isolation + VIP

```bash
# Isolation machine check (expect RUST_USES_D1 False for weight>0 devices)
python3 - <<'PY'
import json
for name in ["account","container","object"]:
  d=json.load(open(f"/etc/swift/{name}.ring.gz.builder.json"))
  live=[x for x in d["devices"] if x and x.get("weight",0)>0]
  print(name, "devices", sorted({x["device"] for x in live}), "ports", sorted({x["port"] for x in live}))
  assert "d1" not in {x["device"] for x in live}, name
print("ISOLATION_OK True")
PY

# VIP regression — use whichever auth path is green in the window
# Prefer: bash /path/to/func-suite.sh https://10.0.0.10:8085 … → 54/54
curl -sk -o /dev/null -w "health=%{http_code}\n" https://10.0.0.10:8085/healthcheck
```

Abort / rollback: restore `/root/w4-ring-backup-$TS` rings to all nodes; restart services; re-check health. **Never mkfs.**

## 5) Only then — Python 3-node

Follow `../wave4-python-prep-20260805/INSTALL-PLAN.md` on **swift2/3/4 only**:

1. Isolation gate PASS + Use% &lt;70%
2. Install openstack-swift; bind matrix ports; rings **d1 only** on 2/3/4
3. Smoke Python entry (`:8090` or LB `:8086`); keep VIP `:8085` Rust
4. Unfreeze 3A/3B in checklist; evidence under new `wave4-python-live-YYYYMMDD/`
5. **4-node:** only if 3-node GREEN **and** Use% &lt;50% on all devices
