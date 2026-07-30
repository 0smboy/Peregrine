#!/usr/bin/env bash
# Generate the 4-node single-host SAIO configuration and rings.
#
# Node N (1..4): device root /srv/node{N} holding sdb{N} and sdb{N+4}.
# Ports: object 60N0, container 60N1, account 60N2. Proxy :8080.
# Rings: account/container/object(policy-0) = 3 replicas over sdb1-4;
#        object-1 (EC 4+2) = 6 replicas over sdb1-8 (2 devices per node).
#
# Standalone: re-run any time to rebuild confs + rings. Honours $SWIFT_BIN
# (default /usr/local/bin) for the ring-builder location.
set -euo pipefail
SWIFT_DIR=/etc/swift
BINDIR="${SWIFT_BIN:-/usr/local/bin}"

setenforce 0 2>/dev/null || true   # SAIO device dirs are not real mounts

echo "device trees"
for N in 1 2 3 4; do mkdir -p "/srv/node$N/sdb$N" "/srv/node$N/sdb$((N+4))"; done
mkdir -p "$SWIFT_DIR"/{object-server,container-server,account-server} \
         /var/log/swift /var/cache/swift

echo "swift.conf"
cat > "$SWIFT_DIR/swift.conf" <<'EOF'
[swift-hash]
swift_hash_path_prefix = swiftrust0717
swift_hash_path_suffix = saio2026

[storage-policy:0]
name = Policy-0
default = yes

[storage-policy:1]
name = EC-4-2
policy_type = erasure_coding
ec_type = liberasurecode_rs_vand
ec_num_data_fragments = 4
ec_num_parity_fragments = 2
ec_object_segment_size = 1048576
EOF

echo "proxy-server.conf"
cat > "$SWIFT_DIR/proxy-server.conf" <<'EOF'
[app:proxy-server]
bind_ip = 0.0.0.0
bind_port = 8080
account_autocreate = true
storage_url = http://127.0.0.1:8080

[filter:tempauth]
user_admin_admin = admin .admin .reseller_admin
user_test_tester = testing .admin
user_test2_tester2 = testing2 .admin
user_test_tester3 = testing3
EOF

echo "per-node server confs"
PEER_OBJ=""; PEER_CONT=""; PEER_ACCT=""
for N in 1 2 3 4; do
  PEER_OBJ+="60${N}0:/srv/node$N,"; PEER_CONT+="60${N}1:/srv/node$N,"; PEER_ACCT+="60${N}2:/srv/node$N,"
done
for N in 1 2 3 4; do
  cat > "$SWIFT_DIR/object-server/$N.conf" <<EOF
[app:object-server]
bind_ip = 0.0.0.0
bind_port = 60${N}0
devices = /srv/node$N
mount_check = false

[object-replicator]
interval = 30
peer_map = ${PEER_OBJ%,}
EOF
  cat > "$SWIFT_DIR/container-server/$N.conf" <<EOF
[app:container-server]
bind_ip = 0.0.0.0
bind_port = 60${N}1
devices = /srv/node$N
mount_check = false

[container-replicator]
interval = 30
peer_map = ${PEER_CONT%,}
EOF
  cat > "$SWIFT_DIR/account-server/$N.conf" <<EOF
[app:account-server]
bind_ip = 0.0.0.0
bind_port = 60${N}2
devices = /srv/node$N
mount_check = false

[account-replicator]
interval = 30
peer_map = ${PEER_ACCT%,}
EOF
done

echo "rings"
build3() {  # name port-suffix : 3 replicas over sdb1-4
  local name=$1 suffix=$2 ring="$SWIFT_DIR/$1.ring.gz"
  rm -f "$ring" "$ring.builder.json"
  "$BINDIR/swift-ring-builder" "$ring" create 10 3
  for N in 1 2 3 4; do
    "$BINDIR/swift-ring-builder" "$ring" add "r1z$N-127.0.0.1:60${N}${suffix}/sdb$N" 100
  done
  "$BINDIR/swift-ring-builder" "$ring" rebalance
}
build3 object    0
build3 container 1
build3 account   2

ring="$SWIFT_DIR/object-1.ring.gz"; rm -f "$ring" "$ring.builder.json"
"$BINDIR/swift-ring-builder" "$ring" create 10 6
for N in 1 2 3 4; do
  "$BINDIR/swift-ring-builder" "$ring" add "r1z$N-127.0.0.1:60${N}0/sdb$N" 100
  "$BINDIR/swift-ring-builder" "$ring" add "r1z$N-127.0.0.1:60${N}0/sdb$((N+4))" 100
done
"$BINDIR/swift-ring-builder" "$ring" rebalance

ls "$SWIFT_DIR"/*.ring.gz
echo "saio setup complete."
