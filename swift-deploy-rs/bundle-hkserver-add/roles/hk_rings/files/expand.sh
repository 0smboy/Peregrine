#!/bin/bash
# Add only the hkserver device, then rebalance. Does not remove devices,
# format disks, or rewrite existing device identities.
set -euo pipefail
RB=/root/work/hkserver-add/swift-ring-builder
test -x "$RB"
cd /etc/swift
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p "/root/work/hkserver-add/ring-backup-$STAMP"
cp -a ./*.ring.gz ./*.builder.json "/root/work/hkserver-add/ring-backup-$STAMP/"

add() {
  local ring="$1" spec="$2" weight="$3" out
  out=$("$RB" "$ring" add "$spec" "$weight")
  echo "$ring: $out"
  case "$out" in
    added\ device*|updated\ weight*) return 0 ;;
    already\ present*) return 1 ;;
    *) echo "unexpected add result" >&2; exit 1 ;;
  esac
}

rebalance_if() {
  local ring="$1" changed="$2"
  if [ "$changed" = 1 ]; then
    "$RB" "$ring" rebalance
    echo "EXPAND-REBALANCED $ring"
  else
    echo "EXPAND-CURRENT $ring"
  fi
}

CHANGED=0
if add account.ring.gz 'r1z5-10.0.4.5:6202R10.0.8.5:6202/d2' 80; then CHANGED=1; fi
rebalance_if account.ring.gz "$CHANGED"

CHANGED=0
if add container.ring.gz 'r1z5-10.0.4.5:6201R10.0.8.5:6201/d2' 80; then CHANGED=1; fi
rebalance_if container.ring.gz "$CHANGED"

for ring in object.ring.gz object-1.ring.gz; do
  CHANGED=0
  if add "$ring" 'r3z1-10.0.4.5:6211R10.0.8.5:6211/d2' 80; then CHANGED=1; fi
  rebalance_if "$ring" "$CHANGED"
done

python3 - <<'PY'
import json
expect = {
    "account.ring.gz.builder.json": 5,
    "container.ring.gz.builder.json": 5,
    "object.ring.gz.builder.json": 9,
    "object-1.ring.gz.builder.json": 9,
}
for name, count in expect.items():
    devices = json.load(open("/etc/swift/" + name))["devices"]
    print(name, len(devices))
    if len(devices) != count:
        raise SystemExit("device count mismatch for " + name)
    last = devices[-1]
    if last["ip"] != "10.0.4.5" or last["device"] != "d2" or last["weight"] != 80.0:
        raise SystemExit("hkserver device missing from " + name)
print("RING_DEVICES_OK")
PY
