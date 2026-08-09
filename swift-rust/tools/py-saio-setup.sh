#!/bin/bash
# Stand up a single-node Python OpenStack Swift SAIO on the Azure build host as
# the parity oracle + perf A/B for the Rust cluster. Same hash prefix/suffix,
# same policies (0=3x repl default, 1=ec-2-1), same tempauth creds, on alternate
# ports so it runs alongside the live Rust cluster without collision.
set -u
source "$(dirname "$0")/lib/lab-auth.sh"
peregrine_load_lab_auth || exit $?
VENV=/root/work/pyswift-venv
BIN=$VENV/bin
ETC=/etc/pyswift
DEV=/srv/node/d1/pysaio           # xfs, xattr-capable
RUN=/var/run/pyswift
LOG=/root/work/pysaio
PREFIX=a7e047fcefe014fbefad296bc6785c84
SUFFIX=7a3cc73587dc333d113e93495a8ec4c4
source "$BIN/activate"

mkdir -p "$ETC" "$RUN" "$LOG"
for d in 1 2 3 4; do mkdir -p "$DEV/sdb$d"; done
chown -R root:root "$DEV"

echo "### swift.conf"
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

echo "### proxy-server.conf (:8090)"
cat > "$ETC/proxy-server.conf" <<EOF
[DEFAULT]
bind_ip = 127.0.0.1
bind_port = 8090
workers = 2
swift_dir = $ETC
user = root
log_name = pyproxy

[pipeline:main]
pipeline = catch_errors gatekeeper healthcheck proxy-logging cache listing_formats tempauth copy slo dlo versioned_writes symlink proxy-server

[app:proxy-server]
use = egg:swift#proxy
allow_account_management = true
account_autocreate = true

[filter:tempauth]
use = egg:swift#tempauth
user_test_tester = $ST_KEY .admin
user_admin_admin = admin .admin .reseller_admin

[filter:cache]
use = egg:swift#memcache
memcache_servers = 127.0.0.1:11211

[filter:catch_errors]
use = egg:swift#catch_errors
[filter:gatekeeper]
use = egg:swift#gatekeeper
[filter:healthcheck]
use = egg:swift#healthcheck
[filter:proxy-logging]
use = egg:swift#proxy_logging
[filter:listing_formats]
use = egg:swift#listing_formats
[filter:copy]
use = egg:swift#copy
[filter:slo]
use = egg:swift#slo
[filter:dlo]
use = egg:swift#dlo
[filter:versioned_writes]
use = egg:swift#versioned_writes
allow_versioned_writes = true
[filter:symlink]
use = egg:swift#symlink
EOF

common_dev="[DEFAULT]
devices = $DEV
mount_check = false
swift_dir = $ETC
user = root
workers = 2"

echo "### account-server.conf (:6312)"
cat > "$ETC/account-server.conf" <<EOF
$common_dev
bind_ip = 127.0.0.1
bind_port = 6312
log_name = pyaccount
[pipeline:main]
pipeline = healthcheck account-server
[app:account-server]
use = egg:swift#account
[filter:healthcheck]
use = egg:swift#healthcheck
[account-replicator]
[account-auditor]
[account-reaper]
EOF

echo "### container-server.conf (:6311)"
cat > "$ETC/container-server.conf" <<EOF
$common_dev
bind_ip = 127.0.0.1
bind_port = 6311
log_name = pycontainer
[pipeline:main]
pipeline = healthcheck container-server
[app:container-server]
use = egg:swift#container
[filter:healthcheck]
use = egg:swift#healthcheck
[container-replicator]
[container-updater]
[container-auditor]
EOF

echo "### object-server.conf (:6310, serves both policies)"
cat > "$ETC/object-server.conf" <<EOF
$common_dev
bind_ip = 127.0.0.1
bind_port = 6310
log_name = pyobject
[pipeline:main]
pipeline = healthcheck object-server
[app:object-server]
use = egg:swift#object
[filter:healthcheck]
use = egg:swift#healthcheck
[object-replicator]
[object-reconstructor]
[object-updater]
[object-auditor]
EOF

echo "### building rings (part_power=10; repl=3; EC frags=3 across 4 devices)"
cd "$ETC"
build_ring() { # <name> <port>
  local name=$1 port=$2
  rm -f "$name.builder" "$name.ring.gz"
  "$BIN/swift-ring-builder" "$name.builder" create 10 3 1 >/dev/null
  for d in 1 2 3 4; do
    "$BIN/swift-ring-builder" "$name.builder" add r1z${d}-127.0.0.1:${port}/sdb$d 1 >/dev/null
  done
  "$BIN/swift-ring-builder" "$name.builder" rebalance >/dev/null
}
build_ring account   6312
build_ring container 6311
build_ring object    6310
build_ring object-1  6310

echo "### memcached"
pgrep -x memcached >/dev/null || memcached -d -u root -m 64 -l 127.0.0.1 -p 11211
sleep 1

echo "### starting servers"
pkill -f "$ETC/proxy-server.conf" 2>/dev/null
pkill -f "$ETC/object-server.conf" 2>/dev/null
pkill -f "$ETC/container-server.conf" 2>/dev/null
pkill -f "$ETC/account-server.conf" 2>/dev/null
sleep 1
nohup "$BIN/swift-account-server"   "$ETC/account-server.conf"   -v >"$LOG/account.log" 2>&1 &
nohup "$BIN/swift-container-server" "$ETC/container-server.conf" -v >"$LOG/container.log" 2>&1 &
nohup "$BIN/swift-object-server"    "$ETC/object-server.conf"    -v >"$LOG/object.log" 2>&1 &
sleep 2
nohup "$BIN/swift-proxy-server"     "$ETC/proxy-server.conf"     -v >"$LOG/proxy.log" 2>&1 &
sleep 3

echo "### health"
for p in 6310 6311 6312 8090; do
  printf "  :%s /healthcheck -> %s\n" "$p" "$(curl -s -m5 -o /dev/null -w '%{http_code}' http://127.0.0.1:$p/healthcheck)"
done
echo "### auth smoke"
curl -s -m10 -D - -o /dev/null -H "X-Auth-User: $ST_USER" -H "X-Auth-Key: $ST_KEY" \
  http://127.0.0.1:8090/auth/v1.0 | grep -iE 'x-auth-token|x-storage-url' | sed 's/^/  /'
echo "PY-SAIO-SETUP-DONE"
