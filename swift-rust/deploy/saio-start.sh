#!/usr/bin/env bash
# The cluster supervisor: launch all 13 SAIO server processes and wait on
# them in the foreground. This is the ExecStart of swift-rust-saio.service,
# so systemd owns every process in one cgroup and reaps them cleanly on
# stop (which is why the SAIO servers do NOT self-daemonise here).
set -u
BINDIR=/usr/local/bin
SWIFT_DIR=/etc/swift
LOG=/var/log/swift
export SWIFT_DIR
mkdir -p "$LOG"

pids=()
start() {  # role conf tag
  "$BINDIR/swift-$1-server" "$2" >>"$LOG/$3.log" 2>&1 &
  pids+=($!)
}

shutdown() {
  trap - TERM INT
  kill "${pids[@]}" 2>/dev/null || true
  wait 2>/dev/null || true
  exit 0
}
trap shutdown TERM INT

for N in 1 2 3 4; do
  start account   "$SWIFT_DIR/account-server/$N.conf"   "account$N"
  start container "$SWIFT_DIR/container-server/$N.conf" "container$N"
  start object    "$SWIFT_DIR/object-server/$N.conf"    "object$N"
done
sleep 1
start proxy "$SWIFT_DIR/proxy-server.conf" proxy

# Reap the whole set: if any server dies, exit non-zero so systemd
# restarts the unit (Restart=on-failure).
wait -n "${pids[@]}"
shutdown
