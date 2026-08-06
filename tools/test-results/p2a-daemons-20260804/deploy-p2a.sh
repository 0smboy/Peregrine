#!/bin/bash
# Deploy P2a daemons on one Contabo node (run as root).
set -euo pipefail
SRC=${1:-/tmp/p2a}

kill_stray() {
  # kill any non-systemd object-server we may have started during diagnosis
  local main
  main=$(systemctl show -p MainPID --value swift-object 2>/dev/null || echo 0)
  for pid in $(pgrep -x swift-object-se || true); do
    if [ "$pid" != "$main" ] && [ "$pid" != "0" ]; then
      kill "$pid" 2>/dev/null || true
    fi
  done
}

install_bin() {
  local bin=$1
  cp "$SRC/$bin" /usr/local/bin/.$bin.new
  chmod 755 /usr/local/bin/.$bin.new
  restorecon -F /usr/local/bin/.$bin.new 2>/dev/null || true
  mv -f /usr/local/bin/.$bin.new /usr/local/bin/$bin
}

for b in swift-object-expirer swift-account-reaper swift-container-reconciler \
         swift-container-updater swift-object-server; do
  install_bin "$b"
done

# conf sections
grep -q '^\[object-expirer\]' /etc/swift/object-server.conf || cat >> /etc/swift/object-server.conf <<'C'

[object-expirer]
interval = 30
reclaim_age = 604800
log_statsd_host = 127.0.0.1
log_statsd_port = 9125
log_statsd_metric_prefix =
C

grep -q '^\[account-reaper\]' /etc/swift/account-server.conf || cat >> /etc/swift/account-server.conf <<'C'

[account-reaper]
interval = 60
delay_reaping = 0
log_statsd_host = 127.0.0.1
log_statsd_port = 9125
log_statsd_metric_prefix =
C

grep -q '^\[container-updater\]' /etc/swift/container-server.conf || cat >> /etc/swift/container-server.conf <<'C'

[container-updater]
interval = 30
log_statsd_host = 127.0.0.1
log_statsd_port = 9125
log_statsd_metric_prefix =
C

grep -q '^\[container-reconciler\]' /etc/swift/container-server.conf || cat >> /etc/swift/container-server.conf <<'C'

[container-reconciler]
interval = 30
reclaim_age = 604800
log_statsd_host = 127.0.0.1
log_statsd_port = 9125
log_statsd_metric_prefix =
C

write_unit() {
  local name=$1 desc=$2 bin=$3 conf=$4
  cat > /etc/systemd/system/${name}.service <<U
[Unit]
Description=${desc}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=SWIFT_DIR=/etc/swift
ExecStart=/usr/local/bin/${bin} /etc/swift/${conf}
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
U
}

write_unit swift-object-expirer "Swift object expirer (rust)" swift-object-expirer object-server.conf
write_unit swift-account-reaper "Swift account reaper (rust)" swift-account-reaper account-server.conf
write_unit swift-container-updater "Swift container updater (rust)" swift-container-updater container-server.conf
write_unit swift-container-reconciler "Swift container reconciler (rust)" swift-container-reconciler container-server.conf

kill_stray
systemctl daemon-reload
systemctl enable swift-object-expirer swift-account-reaper swift-container-updater swift-container-reconciler
systemctl restart swift-object
systemctl restart swift-object-updater
systemctl restart swift-object-expirer
systemctl restart swift-account-reaper
systemctl restart swift-container-updater
systemctl restart swift-container-reconciler
sleep 2

printf "host=%s\n" "$(hostname)"
for u in swift-object swift-object-updater swift-object-expirer \
         swift-account-reaper swift-container-updater swift-container-reconciler; do
  printf "  %-32s %s\n" "$u" "$(systemctl is-active $u)"
done
