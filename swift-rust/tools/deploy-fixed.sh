#!/bin/bash
# Deploy the freshly-built swift-rust server/daemon binaries to one cluster node,
# with a timestamped backup and a post-restart health check. Runs ON swift1.
#   deploy-fixed.sh <last-octet>        e.g. 11 (swift1, local) | 12 | 13 | 14
set -u
N=${1:?node octet}
SRC=/root/work/swift-rust/target/release
TS=$(date +%Y%m%d-%H%M%S)
BINS="swift-proxy-server swift-object-server swift-container-server swift-account-server \
swift-object-replicator swift-object-reconstructor swift-object-updater \
swift-container-updater swift-db-replicator swift-object-auditor"
SVCS="swift-proxy swift-object swift-container swift-account swift-object-replicator \
swift-object-reconstructor swift-object-updater swift-container-updater \
swift-account-replicator swift-container-replicator"
HOST=10.42.10.$N
K="-i /etc/swift/replication_key -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10"

echo "=== deploy to swift.$N ($HOST)  ts=$TS ==="

install_block() {
cat <<EOS
set -u
mkdir -p /usr/local/bin/backup-$TS
for b in $BINS; do [ -f /usr/local/bin/\$b ] && cp -a /usr/local/bin/\$b /usr/local/bin/backup-$TS/; done
for b in $BINS; do install -m755 /root/deploy-stage/\$b /usr/local/bin/\$b; done
systemctl restart $SVCS
sleep 2
echo -n "failed-units: "; systemctl list-units --state=failed --plain --no-legend | grep -cE "swift-|haproxy"
EOS
}

if [ "$N" = 11 ]; then
  mkdir -p /root/deploy-stage
  for b in $BINS; do cp -a "$SRC/$b" /root/deploy-stage/; done
  bash -c "$(install_block)"
else
  ssh $K root@$HOST "mkdir -p /root/deploy-stage"
  for b in $BINS; do scp $K "$SRC/$b" root@$HOST:/root/deploy-stage/ >/dev/null; done
  ssh $K root@$HOST "bash -s" <<< "$(install_block)"
fi

sleep 2
echo -n "  proxy :8080/healthcheck -> "
curl -s -m8 -o /dev/null -w '%{http_code}\n' "http://$HOST:8080/healthcheck"
echo -n "  new object-server mtime: "
if [ "$N" = 11 ]; then stat -c %y /usr/local/bin/swift-object-server | cut -d. -f1
else ssh $K root@$HOST "stat -c %y /usr/local/bin/swift-object-server | cut -d. -f1"; fi
