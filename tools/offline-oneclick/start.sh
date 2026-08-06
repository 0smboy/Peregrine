#!/usr/bin/env bash
# Start SAIO stack and/or swift-console from an installed prefix.
# Usage: start.sh [--prefix DIR] [--saio] [--console] [--setup] [--daemons]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

PREFIX="${PEREGRINE_PREFIX:-$DEFAULT_PREFIX}"
DO_SAIO=0
DO_CONSOLE=0
DO_SETUP=0
DO_DAEMONS=0
FOREGROUND=0

usage() {
  cat <<'EOF'
Usage: start.sh [--prefix DIR] [--saio] [--console] [--setup] [--daemons] [--foreground]

  --prefix DIR   Install prefix (default: /opt/peregrine or $PEREGRINE_PREFIX)
  --saio         Start 4-node single-host SAIO (proxy + account/container/object x4)
  --console      Start swift-console (config under prefix or /etc/swift-console)
  --setup        (Re)generate confs + rings before start
  --daemons      Also start optional ops daemons (replicator/updater/expirer/auditor) if present
  --foreground   Run SAIO supervisor in foreground (default: background)

If neither --saio nor --console is given, --saio is assumed.

Env:
  SWIFT_TLS_PEM   Optional PEM staged under prefix/etc/tls on start if set
  ST_AUTH / ST_USER / ST_KEY  TempAuth (defaults: test:tester / testing)
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) PREFIX="${2:?}"; shift 2 ;;
    --saio) DO_SAIO=1; shift ;;
    --console) DO_CONSOLE=1; shift ;;
    --setup) DO_SETUP=1; shift ;;
    --daemons) DO_DAEMONS=1; shift ;;
    --foreground) FOREGROUND=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown arg: $1" ;;
  esac
done

if [ "$DO_SAIO" = 0 ] && [ "$DO_CONSOLE" = 0 ]; then
  DO_SAIO=1
fi

[ -d "$PREFIX/bin" ] || die "not installed at $PREFIX (run install first)"
resolve_layout "$PREFIX"

# shellcheck disable=SC1091
[ -f "$PREFIX/etc/env.sh" ] && . "$PREFIX/etc/env.sh"
export PATH="$PREFIX/bin:$PATH"
export SWIFT_BIN="$PREFIX/bin"
export SWIFT_DIR DEVICE_ROOT LOG_DIR RUN_DIR
export LD_LIBRARY_PATH="${PREFIX}/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

mkdir -p "$LOG_DIR" "$RUN_DIR" "$SWIFT_DIR"

# Prefer PREFIX bins even if system copies exist
export PATH="$PREFIX/bin:$PATH"

apply_tls_pem_if_set "$PREFIX/etc/tls" >/dev/null || true

start_saio() {
  log "start SAIO (SWIFT_DIR=$SWIFT_DIR DEVICE_ROOT=$DEVICE_ROOT)"

  # Stop any previous instance we manage
  if [ -f "$RUN_DIR/saio-supervisor.pid" ]; then
    old="$(read_pidfile "$RUN_DIR/saio-supervisor.pid")"
    if pid_alive "$old"; then
      warn "existing supervisor pid $old — stopping first"
      kill "$old" 2>/dev/null || true
      sleep 1
    fi
  fi
  # Best-effort kill of prior servers bound to SAIO ports
  if [ -f "$RUN_DIR/saio.pids" ]; then
    while read -r p; do
      kill "$p" 2>/dev/null || true
    done <"$RUN_DIR/saio.pids"
  fi

  if [ "$DO_SETUP" = 1 ] || [ ! -f "$SWIFT_DIR/proxy-server.conf" ] || [ ! -f "$SWIFT_DIR/object.ring.gz" ]; then
    log "setup conf + rings"
    if [ -x "$PREFIX/deploy/saio-setup-portable.sh" ]; then
      bash "$PREFIX/deploy/saio-setup-portable.sh"
    elif [ -x "$PREFIX/deploy/saio-setup.sh" ] && is_root; then
      SWIFT_BIN="$PREFIX/bin" bash "$PREFIX/deploy/saio-setup.sh"
    else
      die "cannot setup: missing portable saio-setup or root for classic setup"
    fi
  fi

  # Ensure devices exist
  for N in 1 2 3 4; do
    mkdir -p "$DEVICE_ROOT/node$N/sdb$N" "$DEVICE_ROOT/node$N/sdb$((N+4))"
  done

  START_SH="$PREFIX/deploy/saio-start-portable.sh"
  [ -x "$START_SH" ] || START_SH="$PREFIX/deploy/saio-start.sh"
  [ -x "$START_SH" ] || die "no saio-start script under $PREFIX/deploy"

  # Patch classic saio-start BINDIR via env if portable; classic hardcodes paths —
  # portable is preferred.
  if [ "$FOREGROUND" = 1 ]; then
    log "SAIO supervisor foreground"
    exec env SWIFT_BIN="$PREFIX/bin" SWIFT_DIR="$SWIFT_DIR" LOG_DIR="$LOG_DIR" RUN_DIR="$RUN_DIR" \
      bash "$START_SH"
  fi

  # Background supervisor
  nohup env SWIFT_BIN="$PREFIX/bin" SWIFT_DIR="$SWIFT_DIR" LOG_DIR="$LOG_DIR" RUN_DIR="$RUN_DIR" \
    bash "$START_SH" >>"$LOG_DIR/supervisor.log" 2>&1 &
  echo $! >"$RUN_DIR/saio-supervisor.pid"
  ok "SAIO supervisor pid $(cat "$RUN_DIR/saio-supervisor.pid")"

  log "waiting for proxy :${PROXY_PORT_DEFAULT}"
  if wait_proxy "$ST_AUTH_DEFAULT" 45; then
    ok "proxy up at $ST_URL_DEFAULT (tempauth ${ST_USER_DEFAULT} / ${ST_KEY_DEFAULT})"
  else
    warn "proxy did not respond in time — check $LOG_DIR/*.log"
    return 1
  fi

  if [ "$DO_DAEMONS" = 1 ]; then
    start_optional_daemons
  fi
}

start_optional_daemons() {
  log "optional daemons"
  local conf_obj conf_cont conf_acct
  # Use node-1 confs as representative for single-host lab
  conf_obj="$SWIFT_DIR/object-server/1.conf"
  conf_cont="$SWIFT_DIR/container-server/1.conf"
  conf_acct="$SWIFT_DIR/account-server/1.conf"
  start_bg() {
    local name="$1" bin="$2" conf="$3"
    if [ ! -x "$PREFIX/bin/$bin" ]; then
      note "skip $name (binary missing)"
      return 0
    fi
    if [ ! -f "$conf" ]; then
      note "skip $name (conf missing)"
      return 0
    fi
    nohup env SWIFT_DIR="$SWIFT_DIR" "$PREFIX/bin/$bin" "$conf" \
      >>"$LOG_DIR/${name}.log" 2>&1 &
    echo $! >"$RUN_DIR/${name}.pid"
    note "$name pid $!"
  }
  start_bg object-replicator    swift-object-replicator    "$conf_obj"
  start_bg object-updater       swift-object-updater       "$conf_obj"
  start_bg object-expirer       swift-object-expirer       "$conf_obj"
  start_bg object-auditor       swift-object-auditor       "$conf_obj"
  start_bg object-reconstructor swift-object-reconstructor "$conf_obj"
  start_bg container-updater    swift-container-updater    "$conf_cont"
  start_bg container-reconciler swift-container-reconciler "$conf_cont"
  start_bg account-reaper       swift-account-reaper       "$conf_acct"
}

start_console() {
  log "start swift-console"
  local conf="$CONSOLE_CONF_DIR/config.json"
  if [ ! -f "$conf" ]; then
    conf="$PREFIX/conf/console-config.json"
  fi
  if [ ! -f "$conf" ]; then
    write_console_config "$CONSOLE_CONF_DIR/config.json"
    conf="$CONSOLE_CONF_DIR/config.json"
  fi
  # Refresh auth/base to local SAIO
  write_console_config "$conf" "$ST_AUTH_DEFAULT" "$ST_URL_DEFAULT" "$CONSOLE_BIND_DEFAULT"

  if [ -f "$RUN_DIR/console.pid" ]; then
    old="$(read_pidfile "$RUN_DIR/console.pid")"
    if pid_alive "$old"; then
      warn "console already running pid $old"
      return 0
    fi
  fi

  [ -x "$PREFIX/bin/swift-console" ] || die "swift-console missing under $PREFIX/bin"
  nohup "$PREFIX/bin/swift-console" "$conf" >>"$LOG_DIR/console.log" 2>&1 &
  echo $! >"$RUN_DIR/console.pid"
  sleep 1
  if pid_alive "$(read_pidfile "$RUN_DIR/console.pid")"; then
    ok "console pid $(cat "$RUN_DIR/console.pid")  http://${CONSOLE_BIND_DEFAULT}"
  else
    warn "console exited early — see $LOG_DIR/console.log"
    return 1
  fi
}

rc=0
if [ "$DO_SAIO" = 1 ]; then
  start_saio || rc=1
fi
if [ "$DO_CONSOLE" = 1 ]; then
  start_console || rc=1
fi

if [ "$rc" = 0 ]; then
  ok "start complete"
  note "status: offline-oneclick.sh status --prefix $PREFIX"
  note "stop:   offline-oneclick.sh stop --prefix $PREFIX"
  note "test:   offline-oneclick.sh test --smoke --func"
fi
exit "$rc"
