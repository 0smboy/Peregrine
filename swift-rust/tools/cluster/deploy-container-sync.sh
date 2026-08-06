#!/bin/bash
# Install swift-container-sync as a daemon on every node. Staging happens
# INSIDE /usr/local/bin so the binary inherits bin_t; a file staged in /tmp gets
# user_tmp_t and systemd refuses to exec it.
set -e
B=swift-container-sync

apply() {
  src=${1:-/root/cs/$B}
  cp "$src" /usr/local/bin/.$B.new
  chmod 755 /usr/local/bin/.$B.new
  restorecon -F /usr/local/bin/.$B.new 2>/dev/null || true
  mv -f /usr/local/bin/.$B.new /usr/local/bin/$B

  grep -q '^\[container-sync\]' /etc/swift/container-server.conf || cat >> /etc/swift/container-server.conf <<'CONF'

[container-sync]
interval = 300
container_time = 60
allowed_sync_hosts = 127.0.0.1
conn_timeout = 5
# Proxy base for local object GET (PUT body). Adjust for VIP if needed.
internal_client_url = http://127.0.0.1:8080/v1
log_statsd_host = 127.0.0.1
log_statsd_port = 9125
log_statsd_metric_prefix =
CONF

  # Realms conf is optional; create a stub so the path exists.
  if [ ! -f /etc/swift/container-sync-realms.conf ]; then
    cat > /etc/swift/container-sync-realms.conf <<'REALMS'
# [DEFAULT]
# mtime_check_interval = 300.0
#
# [realm1]
# key = changeme
# cluster_clustername1 = http://127.0.0.1:8080/v1/
REALMS
    chown swift:swift /etc/swift/container-sync-realms.conf 2>/dev/null || true
  fi

  cat > /etc/systemd/system/swift-container-sync.service <<'UNIT'
[Unit]
Description=Swift container sync (rust)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=SWIFT_DIR=/etc/swift
ExecStart=/usr/local/bin/swift-container-sync /etc/swift/container-server.conf
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT
  restorecon -F /etc/systemd/system/swift-container-sync.service /etc/swift/container-server.conf 2>/dev/null || true
  systemctl daemon-reload
  systemctl enable -q --now swift-container-sync
  sleep 2
  printf "  %-8s sync=%-9s restarts=%s conf=%s\n" \
    "$(hostname)" \
    "$(systemctl is-active swift-container-sync)" \
    "$(systemctl show -p NRestarts --value swift-container-sync)" \
    "$(sha256sum /etc/swift/container-server.conf | cut -c1-12)"
}

if [ "$1" = "--local" ]; then apply "$2"; exit 0; fi

K="-i /etc/swift/replication_key -o BatchMode=yes -o ConnectTimeout=15"
mkdir -p /root/cs
cp /root/work/swift-rust/target/release/$B /root/cs/$B
apply /root/cs/$B
for n in 12 13 14; do
  ssh -n $K root@10.42.10.$n "mkdir -p /root/cs"
  scp -q $K /root/cs/$B root@10.42.10.$n:/root/cs/$B
  scp -q $K "$0" root@10.42.10.$n:/root/deploy-cs.sh
  ssh -n $K root@10.42.10.$n "bash /root/deploy-cs.sh --local"
done
