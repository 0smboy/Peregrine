#!/bin/bash
# Write-concurrency optimization step 1 (immediate, config): raise the object
# server worker-thread pool from the deployed workers=2 to a production value,
# on all four nodes, with a conf backup and a health check. Runs on swift1.
set -u
N=${1:?workers}
K="-i /etc/swift/replication_key -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10"
TS=$(date +%Y%m%d-%H%M%S)
for n in 11 12 13 14; do
  printf "swift.%s: " "$n"
  ssh -n $K root@10.42.10.$n "
    cp -a /etc/swift/object-server.conf /etc/swift/object-server.conf.bak-$TS
    if grep -qE '^\s*workers\s*=' /etc/swift/object-server.conf; then
      sed -i -E 's/^\s*workers\s*=.*/workers = $N/' /etc/swift/object-server.conf
    else
      sed -i -E '/^\[app:object-server\]/a workers = $N' /etc/swift/object-server.conf
    fi
    systemctl restart swift-object
    sleep 2
    printf 'workers=%s  obj-active=%s  hc=' \"\$(grep -E '^workers' /etc/swift/object-server.conf | tr -d ' ')\" \"\$(systemctl is-active swift-object)\"
  " 2>&1
  curl -s -m5 -o /dev/null -w '%{http_code}\n' "http://10.42.30.$n:8080/healthcheck"
done
