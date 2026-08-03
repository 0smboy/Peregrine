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
RUST_UNITS=${RUST_UNITS:-"swift-proxy swift-account swift-container swift-object swift-account-replicator swift-container-replicator swift-container-updater swift-object-replicator swift-object-updater swift-object-reconstructor"}
PYTHON_UNITS=${PYTHON_UNITS:-"openstack-swift-proxy openstack-swift-account openstack-swift-container openstack-swift-object"}
# Contabo dual-SAIO configs (loopback) — not systemd units
SAIO_CONF_GLOBS=${SAIO_CONF_GLOBS:-"/etc/pyswift/ /etc/rsaio/"}

remote() {
  local h=$1; shift
  ssh -o BatchMode=yes -o ConnectTimeout=15 "$h" "$@"
}

stop_saio() {
  local h=$1
  remote "$h" "bash -s" <<'EOF'
set +e
pkill -f '/etc/pyswift/' 2>/dev/null
pkill -f '/etc/rsaio/' 2>/dev/null
sleep 1
pkill -f '/etc/pyswift/' 2>/dev/null
pkill -f '/etc/rsaio/' 2>/dev/null
# Never touch /etc/swift/ cluster daemons here
true
EOF
}

python_units_present() {
  local h=$1
  remote "$h" "bash -s" <<EOF
set +e
n=0
for u in ${PYTHON_UNITS}; do
  systemctl cat "\$u" >/dev/null 2>&1 && n=\$((n+1))
done
echo "\$n"
EOF
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
echo "---LISTEN---"
ss -lntp | grep -E ':(8080|8081|8085|8090|6200|6201|6202|6310|6311|6312|6320|6321|6322)\\b' || echo "(no matching listeners)"
echo "---UNITS---"
for u in ${RUST_UNITS} ${PYTHON_UNITS}; do
  st=\$(systemctl is-active "\$u" 2>/dev/null || echo absent)
  [[ "\$st" == "absent" || "\$st" == "inactive" || "\$st" == "dead" || "\$st" == "failed" ]] || echo "unit \$u=\$st"
done
echo "---SAIO_PROCS---"
pgrep -a -f '/etc/(pyswift|rsaio)/' 2>/dev/null | head -20 || echo NONE
echo "---CLUSTER_PROCS---"
pgrep -a -f '/etc/swift/|swift-(proxy|object|container|account)' 2>/dev/null | grep -v -E '/etc/(pyswift|rsaio)/' | head -20 || true
EOF
}

# Gate for perf-rust: SAIO ports/procs must be zero; rust cluster should answer :8080
gate_perf_rust() {
  local bad=0
  for h in "${HOSTS[@]}"; do
    echo "======== GATE perf-rust $h ========"
    if ! remote "$h" "bash -s" <<'EOF'
set +e
fail=0
if ss -lntp | grep -qE ':(8081|8090)\b'; then
  echo FAIL_SAIO_LISTENER
  ss -lntp | grep -E ':(8081|8090)\b' || true
  fail=1
fi
if pgrep -f '/etc/(pyswift|rsaio)/' >/dev/null 2>&1; then
  echo FAIL_SAIO_PROC
  pgrep -a -f '/etc/(pyswift|rsaio)/' | head -10
  fail=1
fi
# openstack-swift must not be active
for u in openstack-swift-proxy openstack-swift-account openstack-swift-container openstack-swift-object; do
  if systemctl is-active "$u" >/dev/null 2>&1; then
    echo FAIL_PYTHON_UNIT=$u
    fail=1
  fi
done
if ! ss -lntp | grep -qE ':8080\b'; then
  echo WARN_NO_PROXY_8080
  fail=1
fi
if ! systemctl is-active swift-proxy >/dev/null 2>&1; then
  echo FAIL_RUST_PROXY_DOWN
  fail=1
fi
exit $fail
EOF
    then
      echo "GATE_FAIL host=$h"
      bad=1
    else
      echo "GATE_OK host=$h"
    fi
  done
  return "$bad"
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
    stop_saio "$h"
  done
  cmd_status
}

cmd_perf_rust() {
  echo "MODE=perf-rust: stop python surface + SAIO, ensure rust cluster up"
  for h in "${HOSTS[@]}"; do
    stop_list "$h" $PYTHON_UNITS
    stop_saio "$h"
    start_list "$h" $RUST_UNITS
  done
  sleep 2
  for h in "${HOSTS[@]}"; do residual_check "$h" rust; done
  if gate_perf_rust; then
    echo "MODE_GATE=PASS expect=perf-rust"
    return 0
  else
    echo "MODE_GATE=FAIL expect=perf-rust"
    return 1
  fi
}

cmd_perf_python() {
  echo "MODE=perf-python: require full 4-node Python cluster units"
  local present=0 total=0
  for h in "${HOSTS[@]}"; do
    n=$(python_units_present "$h" | tr -d '[:space:]')
    total=$((total + n))
    echo "python_unit_files host=$h count=$n"
    present=$((present + n))
  done
  if [[ "$present" -eq 0 ]]; then
    echo "PYTHON_CLUSTER_ABSENT"
    echo "MODE_GATE=SKIP_FREEZE_PY_FORMAL — Contabo has no openstack-swift cluster units"
    echo "Refusing to stop Rust cluster (would destroy live lab with no Python replacement)."
    for h in "${HOSTS[@]}"; do
      residual_check "$h" "python-absent" || echo "WARN residual_check unreachable host=$h"
    done
    return 0
  fi
  echo "MODE=perf-python: stop rust cluster units, start python units"
  for h in "${HOSTS[@]}"; do
    stop_list "$h" $RUST_UNITS
    stop_saio "$h"
    start_list "$h" $PYTHON_UNITS
  done
  sleep 2
  for h in "${HOSTS[@]}"; do residual_check "$h" python; done
  echo "MODE_GATE=CHECK — verify rust listeners=0 and python active"
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
