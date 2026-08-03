#!/usr/bin/env bash
# P2: Contabo mode switch — compat | perf-python | perf-rust | stop | status
# Thin wrapper over systemd units / process checks. Does NOT wipe disks.
# Destructive reset is a separate script with dual guards.
set -euo pipefail

MODE="${1:-status}"
HOSTS=(swift1 swift2 swift3 swift4)

# Contabo today primarily runs Rust cluster units named swift-*.
# Python SAIO on hub uses separate ports; full Python cluster may use
# openstack-swift / swift-* depending on install. These lists are overridable.
RUST_UNITS=${RUST_UNITS:-"swift-proxy swift-account swift-container swift-object swift-account-replicator swift-container-replicator swift-object-replicator swift-object-updater swift-object-reconstructor"}
PYTHON_UNITS=${PYTHON_UNITS:-"openstack-swift-proxy openstack-swift-account openstack-swift-container openstack-swift-object"}

remote() {
  local h=$1; shift
  ssh -o BatchMode=yes -o ConnectTimeout=15 "$h" "$@"
}

stop_list() {
  local h=$1; shift
  local units=("$@")
  remote "$h" "bash -s" <<EOF
set +e
for u in ${units[*]}; do
  systemctl stop "\$u" 2>/dev/null
  systemctl reset-failed "\$u" 2>/dev/null
done
true
EOF
}

start_list() {
  local h=$1; shift
  local units=("$@")
  remote "$h" "bash -s" <<EOF
set +e
for u in ${units[*]}; do
  systemctl start "\$u" 2>/dev/null || true
done
true
EOF
}

residual_check() {
  local h=$1
  local expect=$2 # rust|python|none
  remote "$h" "bash -s" <<EOF
set +e
echo "HOST=\$(hostname) EXPECT=$expect"
ss -lnt | grep -E ':(8081|8090|18080|6200|16200)\\s' || true
# Residual process hints (informational; do not kill blindly)
pgrep -a -f 'swift-object-server|swift-proxy-server|object-server|proxy-server' 2>/dev/null | head -20 || true
EOF
}

install_targets() {
  # Install aggregate target unit files from overlays if present
  local overlay
  overlay="$(cd "$(dirname "$0")/../overlays" && pwd)"
  for h in "${HOSTS[@]}"; do
    if [[ -f "$overlay/swift-rust.target" ]]; then
      scp -q "$overlay/swift-rust.target" "$h:/etc/systemd/system/swift-rust.target" || true
      scp -q "$overlay/swift-python.target" "$h:/etc/systemd/system/swift-python.target" 2>/dev/null || true
      remote "$h" "systemctl daemon-reload"
    fi
  done
}

cmd_status() {
  for h in "${HOSTS[@]}"; do
    echo "======== $h ========"
    residual_check "$h" "?"
  done
}

cmd_stop() {
  for h in "${HOSTS[@]}"; do
    echo "STOP all on $h"
    stop_list "$h" $RUST_UNITS $PYTHON_UNITS
    # Also stop local SAIOs on hub if present
    remote "$h" "pkill -f 'rust-saio|py-saio' 2>/dev/null; true" || true
  done
  cmd_status
}

cmd_perf_rust() {
  echo "MODE=perf-rust: stop python surface, ensure rust cluster up"
  for h in "${HOSTS[@]}"; do
    stop_list "$h" $PYTHON_UNITS
    # Stop SAIO listeners that steal CPU on hub
    remote "$h" "ss -lntp | grep -E ':(8081|8090)\\s' && echo WARN_SAIO_STILL_LISTENING || echo saio_clear"
    start_list "$h" $RUST_UNITS
  done
  sleep 2
  for h in "${HOSTS[@]}"; do residual_check "$h" rust; done
  echo "GATE: verify no python SAIO on VIP MASTER before formal DIRECT-4PROXY runs"
}

cmd_perf_python() {
  echo "MODE=perf-python: stop rust cluster units, start python units if installed"
  for h in "${HOSTS[@]}"; do
    stop_list "$h" $RUST_UNITS
    start_list "$h" $PYTHON_UNITS
  done
  sleep 2
  for h in "${HOSTS[@]}"; do residual_check "$h" python; done
  echo "NOTE: Contabo may not have full 4-node Python cluster; check status carefully"
}

cmd_compat() {
  echo "MODE=compat: both stacks may run on SEPARATE disks/ports (manual conf required)"
  echo "This switch only ensures documentation gate — apply deploy-rs compat vars first."
  echo "See docs/fairness-lab/MODES.md"
  cmd_status
}

case "$MODE" in
  status) cmd_status ;;
  stop) cmd_stop ;;
  perf-rust) cmd_perf_rust ;;
  perf-python) cmd_perf_python ;;
  compat) cmd_compat ;;
  install-targets) install_targets ;;
  *)
    echo "usage: $0 status|stop|perf-rust|perf-python|compat|install-targets"
    exit 2
    ;;
esac
