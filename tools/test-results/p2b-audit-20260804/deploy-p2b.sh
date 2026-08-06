#!/bin/bash
# Deploy P2b continuous auditors on one Contabo node (run as root).
set -euo pipefail
SRC=${1:-/tmp/p2b}

install_bin() {
  local bin=$1
  cp "$SRC/$bin" /usr/local/bin/.$bin.new
  chmod 755 /usr/local/bin/.$bin.new
  restorecon -F /usr/local/bin/.$bin.new 2>/dev/null || true
  mv -f /usr/local/bin/.$bin.new /usr/local/bin/$bin
}

install_bin swift-object-auditor
install_bin swift-db-auditor

# conf sections (idempotent)
grep -q '^\[object-auditor\]' /etc/swift/object-server.conf || cat >> /etc/swift/object-server.conf <<'C'

[object-auditor]
interval = 30
devices = /srv/node
mount_check = false
log_statsd_host = 127.0.0.1
log_statsd_port = 9125
log_statsd_metric_prefix =
C

grep -q '^\[account-auditor\]' /etc/swift/account-server.conf || cat >> /etc/swift/account-server.conf <<'C'

[account-auditor]
interval = 1800
devices = /srv/node
mount_check = false
log_statsd_host = 127.0.0.1
log_statsd_port = 9125
log_statsd_metric_prefix =
C

grep -q '^\[container-auditor\]' /etc/swift/container-server.conf || cat >> /etc/swift/container-server.conf <<'C'

[container-auditor]
interval = 1800
devices = /srv/node
mount_check = false
log_statsd_host = 127.0.0.1
log_statsd_port = 9125
log_statsd_metric_prefix =
C

write_unit() {
  local name=$1 desc=$2 bin=$3 args=$4 conf=$5
  cat > /etc/systemd/system/${name}.service <<U
[Unit]
Description=${desc}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=SWIFT_DIR=/etc/swift
ExecStart=/usr/local/bin/${bin}${args:+ ${args}} /etc/swift/${conf}
Restart=on-failure
RestartSec=2
TimeoutStopSec=180

[Install]
WantedBy=multi-user.target
U
}

write_unit swift-object-auditor "Swift object auditor (rust continuous)" swift-object-auditor "" object-server.conf
write_unit swift-account-auditor "Swift account DB auditor (rust continuous)" swift-db-auditor account account-server.conf
write_unit swift-container-auditor "Swift container DB auditor (rust continuous)" swift-db-auditor container container-server.conf

systemctl daemon-reload
systemctl disable --now swift-audit-sweep.timer 2>/dev/null || true
systemctl enable --now swift-object-auditor swift-account-auditor swift-container-auditor
systemctl is-active swift-object-auditor swift-account-auditor swift-container-auditor
echo "P2b deploy OK on $(hostname)"
