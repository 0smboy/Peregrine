#!/bin/bash
# Stand up a single-node Rust Swift SAIO on the Azure build host, mirroring the
# Python SAIO topology EXACTLY (1 node, 4 devices, part_power 10, repl=3,
# EC-2-1=3 frags), so Rust-SAIO vs Python-SAIO is a clean same-topology
# implementation A/B. Uses the freshly-built target/release binaries (current
# source, NOT the stale deployed ones) and builds rings with the Python
# ring-builder (ring .gz is byte-compatible) but at the Rust-SAIO ports.
set -u
source "$(dirname "$0")/lib/lab-auth.sh"
peregrine_load_lab_auth || exit $?
RBLD=/root/work/swift-rust/target/release          # current-source binaries
PYBIN=/root/work/pyswift-venv/bin                  # for swift-ring-builder
ETC=/etc/rsaio
DEV=/srv/node/d1/rsaio
LOG=/root/work/rsaio
PREFIX=a7e047fcefe014fbefad296bc6785c84
SUFFIX=7a3cc73587dc333d113e93495a8ec4c4

mkdir -p "$ETC" "$LOG"
for d in 1 2 3 4; do
  mkdir -p "$DEV/sdb$d"
  # Same-FS device dirs: official Swift honours this stub when mount_check=true.
  : > "$DEV/sdb$d/.ismount"
done

cat > "$ETC/swift.conf" <<EOF
[swift-hash]
swift_hash_path_prefix = $PREFIX
swift_hash_path_suffix = $SUFFIX

[storage-policy:0]
name = default
default = yes

[storage-policy:1]
name = ec-2-1
policy_type = erasure_coding
ec_type = liberasurecode_rs_vand
ec_num_data_fragments = 2
ec_num_parity_fragments = 1
ec_object_segment_size = 1048576
EOF

cat > "$ETC/proxy-server.conf" <<EOF
[app:proxy-server]
bind_ip = 127.0.0.1
bind_port = 8081
account_autocreate = true
storage_url = http://127.0.0.1:8081

[filter:tempauth]
user_test_tester = $ST_KEY .admin
user_admin_admin = admin .admin .reseller_admin
EOF

for pair in "account 6322" "container 6321" "object 6320"; do
  set -- $pair; svc=$1; port=$2
  cat > "$ETC/$svc-server.conf" <<EOF
[app:$svc-server]
bind_ip = 127.0.0.1
bind_port = $port
devices = $DEV
mount_check = false
workers = 2
EOF
done

echo "### rings (Python ring-builder; ring .gz is byte-compatible)"
cd "$ETC"
build_ring() { local name=$1 port=$2
  rm -f "$name.builder" "$name.ring.gz"
  "$PYBIN/swift-ring-builder" "$name.builder" create 10 3 1 >/dev/null
  for d in 1 2 3 4; do "$PYBIN/swift-ring-builder" "$name.builder" add r1z${d}-127.0.0.1:${port}/sdb$d 1 >/dev/null; done
  "$PYBIN/swift-ring-builder" "$name.builder" rebalance >/dev/null
}
build_ring account   6322
build_ring container 6321
build_ring object    6320
build_ring object-1  6320

echo "### start (SWIFT_DIR=$ETC, current-source release binaries)"
for c in proxy object container account; do pkill -f "$ETC/$c-server.conf" 2>/dev/null; done
sleep 1
SWIFT_DIR=$ETC nohup "$RBLD/swift-account-server"   "$ETC/account-server.conf"   >"$LOG/account.log" 2>&1 &
SWIFT_DIR=$ETC nohup "$RBLD/swift-container-server" "$ETC/container-server.conf" >"$LOG/container.log" 2>&1 &
SWIFT_DIR=$ETC nohup "$RBLD/swift-object-server"    "$ETC/object-server.conf"    >"$LOG/object.log" 2>&1 &
sleep 2
SWIFT_DIR=$ETC nohup "$RBLD/swift-proxy-server"     "$ETC/proxy-server.conf"     >"$LOG/proxy.log" 2>&1 &
sleep 3

echo "### health"
for p in 6320 6321 6322 8081; do
  printf "  :%s /healthcheck -> %s\n" "$p" "$(curl -s -m5 -o /dev/null -w '%{http_code}' http://127.0.0.1:$p/healthcheck)"
done
echo "### auth smoke"
curl -s -m10 -D - -o /dev/null -H "X-Auth-User: $ST_USER" -H "X-Auth-Key: $ST_KEY" \
  http://127.0.0.1:8081/auth/v1.0 | grep -iE 'x-auth-token|x-storage-url' | sed 's/^/  /'
echo "RUST-SAIO-SETUP-DONE"
