#!/bin/bash
# Install swift-container-updater as a daemon on every node. Staging happens
# INSIDE /usr/local/bin so the binary inherits bin_t; a file staged in /tmp gets
# user_tmp_t and systemd refuses to exec it.
set -e
B=swift-container-updater

apply() {
  src=${1:-/root/cu/$B}
  cp "$src" /usr/local/bin/.$B.new
  chmod 755 /usr/local/bin/.$B.new
  restorecon -F /usr/local/bin/.$B.new 2>/dev/null || true
  mv -f /usr/local/bin/.$B.new /usr/local/bin/$B

  grep -q '^\[container-updater\]' /etc/swift/container-server.conf || cat >> /etc/swift/container-server.conf <<'CONF'

[container-updater]
interval = 60
log_statsd_host = 127.0.0.1
log_statsd_port = 9125
log_statsd_metric_prefix =
CONF

  cat > /etc/systemd/system/swift-container-updater.service <<'UNIT'
[Unit]
Description=Swift container updater (rust)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=SWIFT_DIR=/etc/swift
ExecStart=/usr/local/bin/swift-container-updater /etc/swift/container-server.conf
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT
  restorecon -F /etc/systemd/system/swift-container-updater.service /etc/swift/container-server.conf 2>/dev/null || true
  systemctl daemon-reload
  systemctl enable -q --now swift-container-updater
  sleep 2
  printf "  %-8s updater=%-9s restarts=%s conf=%s\n" \
    "$(hostname)" \
    "$(systemctl is-active swift-container-updater)" \
    "$(systemctl show -p NRestarts --value swift-container-updater)" \
    "$(sha256sum /etc/swift/container-server.conf | cut -c1-12)"
}

if [ "$1" = "--local" ]; then apply "$2"; exit 0; fi

K="-i /etc/swift/replication_key -o BatchMode=yes -o ConnectTimeout=15"
mkdir -p /root/cu
cp /root/work/swift-rust/target/release/$B /root/cu/$B
apply /root/cu/$B
for n in 12 13 14; do
  ssh -n $K root@10.42.10.$n "mkdir -p /root/cu"
  scp -q $K /root/cu/$B root@10.42.10.$n:/root/cu/$B
  scp -q $K "$0" root@10.42.10.$n:/root/deploy-cu.sh
  ssh -n $K root@10.42.10.$n "bash /root/deploy-cu.sh --local"
done
