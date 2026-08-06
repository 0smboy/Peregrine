#!/usr/bin/env bash
# Phase 1A layout (USER-METHOD-PLAN):
#   swift1 = client only (no Swift)
#   swift2 = Python SAIO :8090 (thin pipeline)
#   swift3 = Rust SAIO :8081 (thin)
#   swift4 = monitor only (no Swift data-plane; console/prom/loki OK)
# Does NOT wipe /srv/node. Does NOT touch keepalived/haproxy units.
set -euo pipefail

RUST_UNITS="swift-proxy swift-account swift-container swift-object swift-account-replicator swift-container-replicator swift-container-updater swift-object-replicator swift-object-updater swift-object-reconstructor"
# cache is required by Python tempauth (raises without memcache); listing_formats needed for listings
THIN_PY_PIPELINE="catch_errors gatekeeper healthcheck proxy-logging cache listing_formats tempauth copy slo dlo proxy-server"

remote() { ssh -o BatchMode=yes -o ConnectTimeout=20 "$1" "${@:2}"; }

stop_cluster() {
  local h=$1
  echo "== stop+disable cluster on $h =="
  remote "$h" "bash -s" <<EOF
set +e
for u in $RUST_UNITS; do
  systemctl stop "\$u" 2>/dev/null
  systemctl disable "\$u" 2>/dev/null
  systemctl reset-failed "\$u" 2>/dev/null
done
pkill -f '/etc/(pyswift|rsaio)/' 2>/dev/null
sleep 1
pkill -f '/etc/(pyswift|rsaio)/' 2>/dev/null
true
EOF
}

echo "=== Phase 1A bringup: stop Swift data-plane on all nodes ==="
for h in swift1 swift2 swift3 swift4; do stop_cluster "$h"; done

echo "=== Ensure Python SAIO tree on swift2 (configs only; no data wipe/copy) ==="
remote swift2 'mkdir -p /etc/pyswift /srv/node/d1/pysaio /root/work/pysaio /root/work'
# configs only — never tar /srv/node (large / risk of filling disks)
ssh swift3 'tar -C / -cf - etc/pyswift' | ssh swift2 'tar -C / -xf -'
# editable venv needs swift-master + venv (node-to-node from swift1)
ssh swift1 'rsync -az --delete /root/work/pyswift-venv/ root@10.0.0.2:/root/work/pyswift-venv/'
ssh swift1 'rsync -az --delete /root/work/swift-master/ root@10.0.0.2:/root/work/swift-master/'
# Python tempauth requires memcache
ssh swift2 'dnf install -y memcached >/dev/null && systemctl enable --now memcached'

remote swift2 "bash -s" <<EOF
set -euo pipefail
# rebind proxy to this node's business IP; thin pipeline for 1A
python3 - <<PY
from pathlib import Path
import re
p = Path("/etc/pyswift/proxy-server.conf")
text = p.read_text()
text = text.replace("bind_ip = 10.0.0.3", "bind_ip = 10.0.0.2")
text = text.replace("bind_ip = 127.0.0.1", "bind_ip = 10.0.0.2")
text = re.sub(r"(?m)^pipeline = .*\$", "pipeline = ${THIN_PY_PIPELINE}", text)
text = text.replace("10.0.0.3:8090", "10.0.0.2:8090")
p.write_text(text)
print(p.read_text())
PY
for d in 1 2 3 4; do mkdir -p /srv/node/d1/pysaio/sdb\$d; done
systemctl start memcached 2>/dev/null || true
EOF

echo "=== Ensure Rust SAIO on swift3 binds 10.0.0.3:8081 ==="
remote swift3 "bash -s" <<'EOF'
set -euo pipefail
mkdir -p /srv/node/d1/rsaio /root/work/rsaio /etc/rsaio
for d in 1 2 3 4; do mkdir -p /srv/node/d1/rsaio/sdb$d; done
sed -i 's/^bind_ip = .*/bind_ip = 10.0.0.3/' /etc/rsaio/proxy-server.conf
sed -i 's|storage_url = .*|storage_url = http://10.0.0.3:8081|' /etc/rsaio/proxy-server.conf
grep -E 'bind_|storage_url|tempauth|user_' /etc/rsaio/proxy-server.conf
EOF

echo "=== Start Python SAIO on swift2 ==="
remote swift2 "bash -s" <<'EOF'
set -euo pipefail
ETC=/etc/pyswift
LOG=/root/work/pysaio
BIN=/root/work/pyswift-venv/bin
mkdir -p "$LOG"
pkill -f "$ETC/" 2>/dev/null || true
sleep 1
export SWIFT_DIR=$ETC
nohup "$BIN/swift-account-server"   "$ETC/account-server.conf"   >"$LOG/account.log" 2>&1 &
nohup "$BIN/swift-container-server" "$ETC/container-server.conf" >"$LOG/container.log" 2>&1 &
nohup "$BIN/swift-object-server"    "$ETC/object-server.conf"    >"$LOG/object.log" 2>&1 &
sleep 1
nohup "$BIN/swift-proxy-server"     "$ETC/proxy-server.conf"     >"$LOG/proxy.log" 2>&1 &
sleep 2
ss -lntp | grep -E ':(8090|6310|6311|6312)\b' || { echo FAIL_PY_LISTEN; tail -30 "$LOG"/*.log; exit 1; }
curl -sS -m 5 -o /dev/null -w 'py_health=%{http_code}\n' http://10.0.0.2:8090/healthcheck
EOF

echo "=== Start Rust SAIO on swift3 (prefer EC-enabled release tree) ==="
remote swift3 "bash -s" <<'EOF'
set -euo pipefail
ETC=/etc/rsaio
LOG=/root/work/rsaio
BIN=/root/work/swift-rust/target/release
if [[ ! -x $BIN/swift-proxy-server ]]; then BIN=/usr/local/bin; fi
mkdir -p "$LOG"
pkill -f "$ETC/" 2>/dev/null || true
sleep 1
export SWIFT_DIR=$ETC
nohup "$BIN/swift-account-server"   "$ETC/account-server.conf"   >"$LOG/account.log" 2>&1 &
nohup "$BIN/swift-container-server" "$ETC/container-server.conf" >"$LOG/container.log" 2>&1 &
nohup "$BIN/swift-object-server"    "$ETC/object-server.conf"    >"$LOG/object.log" 2>&1 &
sleep 1
nohup "$BIN/swift-proxy-server"     "$ETC/proxy-server.conf"     >"$LOG/proxy.log" 2>&1 &
sleep 2
ss -lntp | grep -E ':(8081|6320|6321|6322)\b' || { echo FAIL_RS_LISTEN; tail -n 40 "$LOG"/proxy.log; exit 1; }
curl -sS -m 5 -o /dev/null -w 'rs_health=%{http_code}\n' http://10.0.0.3:8081/healthcheck
EOF

echo "=== Gate: swift1/4 must have no Swift listeners ==="
bad=0
for h in swift1 swift4; do
  if remote "$h" "ss -lntp | grep -qE ':(8080|8081|8090|6200|6201|6202|6310|6320)\\b'"; then
    echo "FAIL $h still has Swift ports"
    remote "$h" "ss -lntp | grep -E ':(8080|8081|8090|6200|6201|6202|6310|6320)\\b' || true"
    bad=1
  else
    echo "OK $h no Swift data-plane ports"
  fi
done
[[ $bad -eq 0 ]] || exit 1

echo "=== Endpoints ==="
echo "Python SAIO: http://10.0.0.2:8090"
echo "Rust SAIO:   http://10.0.0.3:8081"
echo "PHASE1A_LAYOUT=READY"
