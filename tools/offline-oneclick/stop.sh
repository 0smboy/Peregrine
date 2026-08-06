#!/usr/bin/env bash
# Stop SAIO stack + console started by offline-oneclick.
# Usage: stop.sh [--prefix DIR] [--wipe]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

PREFIX="${PEREGRINE_PREFIX:-$DEFAULT_PREFIX}"
WIPE=0

usage() {
  cat <<'EOF'
Usage: stop.sh [--prefix DIR] [--wipe]

  --prefix DIR  Install prefix (default: /opt/peregrine)
  --wipe        Also delete SAIO data under DEVICE_ROOT and rings under SWIFT_DIR
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) PREFIX="${2:?}"; shift 2 ;;
    --wipe) WIPE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown arg: $1" ;;
  esac
done

resolve_layout "$PREFIX"
mkdir -p "$RUN_DIR" 2>/dev/null || true

stop_pidfile() {
  local name="$1" f="$2"
  if [ ! -f "$f" ]; then
    return 0
  fi
  local pid
  pid="$(read_pidfile "$f")"
  if pid_alive "$pid"; then
    note "stop $name pid $pid"
    kill "$pid" 2>/dev/null || true
    # graceful then force
    local i
    for i in 1 2 3 4 5; do
      pid_alive "$pid" || break
      sleep 0.3
    done
    if pid_alive "$pid"; then
      kill -9 "$pid" 2>/dev/null || true
    fi
  fi
  rm -f "$f"
}

log "stop Peregrine processes (prefix=$PREFIX)"

# Console
stop_pidfile console "$RUN_DIR/console.pid"

# Optional daemons
for f in "$RUN_DIR"/*.pid; do
  [ -f "$f" ] || continue
  base="$(basename "$f" .pid)"
  case "$base" in
    saio-supervisor|console) continue ;;
  esac
  stop_pidfile "$base" "$f"
done

# SAIO supervisor
stop_pidfile saio-supervisor "$RUN_DIR/saio-supervisor.pid"

# Children listed in saio.pids
if [ -f "$RUN_DIR/saio.pids" ]; then
  while read -r p; do
    if pid_alive "$p"; then
      note "stop saio worker pid $p"
      kill "$p" 2>/dev/null || true
    fi
  done <"$RUN_DIR/saio.pids"
  rm -f "$RUN_DIR/saio.pids"
fi

# Fallback: pack-provided stop.sh / pkill patterns (scoped)
if [ -x "$PREFIX/deploy/stop.sh" ] && is_root; then
  bash "$PREFIX/deploy/stop.sh" 2>/dev/null || true
fi

# Scoped pkill only for binaries under our prefix path when possible
if command -v pgrep >/dev/null 2>&1; then
  # Kill processes whose cmdline includes our prefix bin path
  while read -r p; do
    [ -n "$p" ] || continue
    kill "$p" 2>/dev/null || true
  done < <(pgrep -f "$PREFIX/bin/swift-" 2>/dev/null || true)
fi

# Port-based cleanup for classic SAIO ports if still held
if command -v lsof >/dev/null 2>&1; then
  for port in 8080 6010 6011 6012 6020 6021 6022 6030 6031 6032 6040 6041 6042 9000; do
    pids="$(lsof -tiTCP:"$port" -sTCP:LISTEN 2>/dev/null || true)"
    if [ -n "$pids" ]; then
      # Only kill if process looks like swift
      for p in $pids; do
        cmd="$(ps -p "$p" -o args= 2>/dev/null || true)"
        case "$cmd" in
          *swift-*|*swift_console*|*swift-console*)
            note "free :$port pid $p"
            kill "$p" 2>/dev/null || true
            ;;
        esac
      done
    fi
  done
fi

sleep 0.5
ok "cluster stopped"

if [ "$WIPE" = 1 ]; then
  log "wipe data + rings"
  rm -rf \
    "$DEVICE_ROOT"/node*/sdb*/objects* \
    "$DEVICE_ROOT"/node*/sdb*/accounts \
    "$DEVICE_ROOT"/node*/sdb*/containers \
    "$DEVICE_ROOT"/node*/sdb*/tmp \
    2>/dev/null || true
  # classic paths
  rm -rf /srv/node*/sdb*/objects* /srv/node*/sdb*/accounts \
         /srv/node*/sdb*/containers /srv/node*/sdb*/tmp 2>/dev/null || true
  rm -f "$SWIFT_DIR"/*.ring.gz "$SWIFT_DIR"/*.builder.json 2>/dev/null || true
  ok "data + rings wiped"
fi
