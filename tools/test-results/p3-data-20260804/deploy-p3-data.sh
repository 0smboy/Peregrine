#!/bin/bash
# Deploy P3-data partial on one Contabo node (run as root).
# Installs proxy (X-Newest), container-server (sharding-state header),
# container-sharder binary+unit. No wipe. auto_shard stays false.
set -euo pipefail
SRC=${1:-/tmp/p3-data}

install_bin() {
  local bin=$1
  cp "$SRC/$bin" /usr/local/bin/.$bin.new
  chmod 755 /usr/local/bin/.$bin.new
  restorecon -F /usr/local/bin/.$bin.new 2>/dev/null || true
  mv -f /usr/local/bin/.$bin.new /usr/local/bin/$bin
}

for b in swift-proxy-server swift-container-server swift-container-sharder; do
  if [ -f "$SRC/$b" ]; then
    install_bin "$b"
  else
    echo "MISSING $SRC/$b" >&2
    exit 1
  fi
done

grep -q '^\[container-sharder\]' /etc/swift/container-server.conf || cat >> /etc/swift/container-server.conf <<'C'

# P3-data partial: local cleave only; auto_shard ignored
[container-sharder]
interval = 30
cleave_batch_size = 2
auto_shard = false
log_statsd_host = 127.0.0.1
log_statsd_port = 9125
log_statsd_metric_prefix =
C

cat > /etc/systemd/system/swift-container-sharder.service <<'U'
[Unit]
Description=Swift container sharder (rust, local cleave)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=SWIFT_DIR=/etc/swift
ExecStart=/usr/local/bin/swift-container-sharder /etc/swift/container-server.conf
Restart=on-failure
RestartSec=2
TimeoutStopSec=180

[Install]
WantedBy=multi-user.target
U

systemctl daemon-reload
systemctl enable swift-container-sharder
systemctl restart swift-proxy
systemctl restart swift-container
systemctl restart swift-container-sharder
sleep 2
systemctl is-active swift-proxy swift-container swift-container-sharder
echo "P3-data deploy OK on $(hostname)"
