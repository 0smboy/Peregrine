#!/usr/bin/env bash
# offline-oneclick.sh — air-gapped pack / install / start / test for
# Peregrine swift-rust + swift-console (local SAIO / single-host lab).
#
# Multi-node Contabo production remains via swift-deploy-rs; this tool is the
# offline SAIO + console path and the artifact packer for airgap transfer.
#
# Usage:
#   ./offline-oneclick.sh pack [--out DIR] [--features ec]
#   ./offline-oneclick.sh install [--prefix DIR] [--from PACK]
#   ./offline-oneclick.sh start [--console] [--no-setup]
#   ./offline-oneclick.sh stop
#   ./offline-oneclick.sh status
#   ./offline-oneclick.sh test [--func] [--smoke] [--lab]
#   ./offline-oneclick.sh all-local [--features ec] [--console]
#
# After `pack`, the tarball is self-contained (binaries + scripts + conf).
# Target host needs: bash, tar, gzip, coreutils, and a compatible libc (no
# network required). macOS builds produce Darwin binaries; Linux builds
# produce Linux binaries — pack on the target OS family.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SWIFT_RUST="${REPO_ROOT}/swift-rust"
CONSOLE="${REPO_ROOT}/swift-console"
DEFAULT_PREFIX="${PEREGRINE_PREFIX:-/opt/peregrine}"
DEFAULT_OUT="${PEREGRINE_PACK_OUT:-${REPO_ROOT}/dist/offline-pack}"
AUTH_USER="${ST_USER:-test:tester}"
AUTH_KEY="${ST_KEY:-testing}"
ST_AUTH_DEFAULT="http://127.0.0.1:8080/auth/v1.0"

die() { echo "error: $*" >&2; exit 1; }
log() { echo "[offline-oneclick] $*"; }

need_cmd() { command -v "$1" >/dev/null 2>&1 || die "missing command: $1"; }

cmd_pack() {
  local out="$DEFAULT_OUT" features=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --out) out="$2"; shift 2 ;;
      --features) features="$2"; shift 2 ;;
      *) die "pack: unknown arg $1" ;;
    esac
  done
  need_cmd cargo
  need_cmd tar
  mkdir -p "$out/bin" "$out/scripts" "$out/conf" "$out/docs"
  log "building swift-rust release${features:+ (features=$features)}"
  (
    cd "$SWIFT_RUST"
    if [[ -n "$features" ]]; then
      cargo build --release --workspace --features "swift-object-server/${features},swift-proxy-server/${features}" 2>/dev/null \
        || cargo build --release --workspace
      # Prefer feature-aware builds of object/proxy when available
      cargo build --release -p swift-proxy-server ${features:+--features "$features"} || true
      cargo build --release -p swift-object-server ${features:+--features "$features"} || true
    else
      cargo build --release --workspace
    fi
  )
  log "building swift-console release"
  ( cd "$CONSOLE" && cargo build --release )

  local target="$SWIFT_RUST/target/release"
  local bins=(
    swift-proxy-server swift-object-server swift-container-server swift-account-server
    swift-object-replicator swift-object-reconstructor swift-object-updater swift-object-expirer
    swift-object-auditor swift-db-auditor swift-db-replicator
    swift-container-updater swift-container-reconciler swift-container-sharder
    swift-container-sync
    swift-account-reaper swift-ring-builder swift-ring-info swift-recon
    swift-drive-audit swift-manage-shard-ranges swift-get-nodes
    swift-effective-concurrency
  )
  for b in "${bins[@]}"; do
    if [[ -x "$target/$b" ]]; then
      cp -f "$target/$b" "$out/bin/"
    fi
  done
  if [[ -x "$CONSOLE/target/release/swift-console" ]]; then
    cp -f "$CONSOLE/target/release/swift-console" "$out/bin/"
  else
    die "swift-console binary missing after build"
  fi

  # SAIO + smoke + func
  cp -f "$SWIFT_RUST/deploy/"*.sh "$out/scripts/" 2>/dev/null || true
  chmod +x "$out/scripts/"*.sh 2>/dev/null || true
  cp -f "$REPO_ROOT/tools/func-suite.sh" "$out/scripts/" 2>/dev/null || true
  cp -f "$REPO_ROOT/tools/p1a-l2-suite.sh" "$out/scripts/" 2>/dev/null || true
  # Console sample config
  if [[ -f "$CONSOLE/conf/config.json" ]]; then
    cp -f "$CONSOLE/conf/config.json" "$out/conf/console-config.sample.json"
  fi
  cat > "$out/conf/console-config.json" <<'JSON'
{
  "bind": "127.0.0.1:9090",
  "swift_base": "http://127.0.0.1:8080",
  "auth_url": "http://127.0.0.1:8080/auth/v1.0",
  "tempurl_default_secs": 3600,
  "max_upload_bytes": 5368709120,
  "session_idle_hours": 12,
  "accounts": [
    {"user": "test:tester", "key": "testing", "label": "lab"}
  ],
  "cluster_nodes": [],
  "proxy_nodes": ["127.0.0.1:8080"]
}
JSON
  cat > "$out/README.md" <<EOF
# Peregrine offline pack

Built: $(date -u +%Y-%m-%dT%H:%M:%SZ)
Host: $(uname -s)/$(uname -m)
Features: ${features:-none}

## Install (airgap target)

\`\`\`sh
tar xzf offline-pack-*.tar.gz -C /tmp
cd /tmp/offline-pack-*   # or the extracted dir
sudo ./offline-oneclick.sh install --prefix /opt/peregrine --from .
./offline-oneclick.sh start --console
./offline-oneclick.sh test --smoke --func
\`\`\`

TempAuth (SAIO defaults): test:tester / testing
Proxy: http://127.0.0.1:8080
Console: http://127.0.0.1:9090

Optional TLS PEM for external LB: set SWIFT_TLS_PEM=/path/to/fullchain.pem
EOF
  cp -f "$SCRIPT_DIR/offline-oneclick.sh" "$out/offline-oneclick.sh"
  chmod +x "$out/offline-oneclick.sh"

  local stamp
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  local tarball="${out%/}-peregrine-${stamp}.tar.gz"
  # also write marker inside
  echo "$stamp" > "$out/PACK_VERSION"
  tar -C "$(dirname "$out")" -czf "$tarball" "$(basename "$out")"
  log "pack ready: $tarball"
  log "stage dir: $out"
  echo "$tarball"
}

cmd_install() {
  local prefix="$DEFAULT_PREFIX" from=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --prefix) prefix="$2"; shift 2 ;;
      --from) from="$2"; shift 2 ;;
      *) die "install: unknown arg $1" ;;
    esac
  done
  local src="$from"
  if [[ -z "$src" ]]; then
    src="$DEFAULT_OUT"
  fi
  if [[ -f "$src" && "$src" == *.tar.gz ]]; then
    local tmp
    tmp="$(mktemp -d)"
    tar -xzf "$src" -C "$tmp"
    src="$(find "$tmp" -maxdepth 2 -type d -name 'offline-pack*' | head -1)"
    [[ -n "$src" ]] || die "could not find pack root inside tarball"
  fi
  [[ -d "$src/bin" ]] || die "install: $src/bin missing (run pack first)"
  log "installing to $prefix"
  mkdir -p "$prefix"/{bin,scripts,conf,var/log,var/run}
  cp -f "$src/bin/"* "$prefix/bin/"
  chmod +x "$prefix/bin/"*
  if [[ -d "$src/scripts" ]]; then
    cp -f "$src/scripts/"* "$prefix/scripts/" 2>/dev/null || true
    chmod +x "$prefix/scripts/"*.sh 2>/dev/null || true
  fi
  if [[ -d "$src/conf" ]]; then
    cp -f "$src/conf/"* "$prefix/conf/" 2>/dev/null || true
  fi
  cp -f "$src/offline-oneclick.sh" "$prefix/offline-oneclick.sh" 2>/dev/null || true
  # PATH helper
  cat > "$prefix/env.sh" <<EOF
export PEREGRINE_PREFIX="$prefix"
export PATH="$prefix/bin:\$PATH"
export SWIFT_BIN="$prefix/bin"
export ST_AUTH="${ST_AUTH_DEFAULT}"
export ST_USER="${AUTH_USER}"
export ST_KEY="${AUTH_KEY}"
EOF
  log "installed. source $prefix/env.sh"
}

cmd_start() {
  local console=0 setup=1
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --console) console=1; shift ;;
      --no-setup) setup=0; shift ;;
      *) die "start: unknown arg $1" ;;
    esac
  done
  local prefix="${PEREGRINE_PREFIX:-$DEFAULT_PREFIX}"
  if [[ ! -x "$prefix/bin/swift-proxy-server" ]]; then
    # Fall back to repo tree after local pack
    if [[ -x "$SWIFT_RUST/target/release/swift-proxy-server" ]]; then
      prefix="$SWIFT_RUST/target/release"
      export SWIFT_BIN="$prefix"
      log "using in-tree release bins at $prefix"
    else
      die "no binaries; run pack+install or cargo build --release"
    fi
  else
    export SWIFT_BIN="$prefix/bin"
    # shellcheck disable=SC1090
    [[ -f "${PEREGRINE_PREFIX:-$DEFAULT_PREFIX}/env.sh" ]] && source "${PEREGRINE_PREFIX:-$DEFAULT_PREFIX}/env.sh" || true
  fi
  export PATH="${SWIFT_BIN}:$PATH"

  if [[ "$setup" -eq 1 ]]; then
    local setup_sh="$SWIFT_RUST/deploy/saio-setup.sh"
    [[ -x "${PEREGRINE_PREFIX:-}/scripts/saio-setup.sh" ]] && setup_sh="${PEREGRINE_PREFIX}/scripts/saio-setup.sh"
    if [[ -x "$setup_sh" ]]; then
      log "saio-setup"
      SWIFT_BIN="$SWIFT_BIN" bash "$setup_sh"
    else
      log "warn: saio-setup.sh not found; assuming conf already present"
    fi
  fi

  local start_sh="$SWIFT_RUST/deploy/saio-start.sh"
  [[ -x "${PEREGRINE_PREFIX:-}/scripts/saio-start.sh" ]] && start_sh="${PEREGRINE_PREFIX}/scripts/saio-start.sh"
  if [[ -x "$start_sh" ]]; then
    log "saio-start"
    SWIFT_BIN="$SWIFT_BIN" bash "$start_sh"
  else
    die "saio-start.sh missing"
  fi

  if [[ "$console" -eq 1 ]]; then
    local conf="${PEREGRINE_PREFIX:-$DEFAULT_PREFIX}/conf/console-config.json"
    [[ -f "$conf" ]] || conf="$CONSOLE/conf/config.json"
    local cbin="${PEREGRINE_PREFIX:-$DEFAULT_PREFIX}/bin/swift-console"
    [[ -x "$cbin" ]] || cbin="$CONSOLE/target/release/swift-console"
    [[ -x "$cbin" ]] || die "swift-console binary missing"
    mkdir -p "${PEREGRINE_PREFIX:-$DEFAULT_PREFIX}/var/run" 2>/dev/null || true
    local pidf="${PEREGRINE_PREFIX:-/tmp}/var/run/swift-console.pid"
    mkdir -p "$(dirname "$pidf")"
    if [[ -f "$pidf" ]] && kill -0 "$(cat "$pidf")" 2>/dev/null; then
      log "console already running pid=$(cat "$pidf")"
    else
      log "starting console ($conf)"
      nohup "$cbin" "$conf" >"${PEREGRINE_PREFIX:-/tmp}/var/run/swift-console.log" 2>&1 &
      echo $! >"$pidf"
      log "console pid=$! log=${PEREGRINE_PREFIX:-/tmp}/var/run/swift-console.log"
    fi
  fi

  if [[ -n "${SWIFT_TLS_PEM:-}" ]]; then
    log "SWIFT_TLS_PEM set ($SWIFT_TLS_PEM) — apply via HAProxy/lb outside SAIO; not auto-wired on :8080"
  fi
  log "start complete. ST_AUTH=${ST_AUTH:-$ST_AUTH_DEFAULT}"
}

cmd_stop() {
  local stop_sh="$SWIFT_RUST/deploy/stop.sh"
  [[ -x "${PEREGRINE_PREFIX:-}/scripts/stop.sh" ]] && stop_sh="${PEREGRINE_PREFIX}/scripts/stop.sh"
  if [[ -x "$stop_sh" ]]; then
    bash "$stop_sh" || true
  else
    pkill -f 'swift-proxy-server|swift-object-server|swift-container-server|swift-account-server' 2>/dev/null || true
  fi
  local pidf="${PEREGRINE_PREFIX:-/tmp}/var/run/swift-console.pid"
  if [[ -f "$pidf" ]]; then
    kill "$(cat "$pidf")" 2>/dev/null || true
    rm -f "$pidf"
  fi
  log "stop issued"
}

cmd_status() {
  export ST_AUTH="${ST_AUTH:-$ST_AUTH_DEFAULT}"
  export ST_USER="${ST_USER:-$AUTH_USER}"
  export ST_KEY="${ST_KEY:-$AUTH_KEY}"
  echo "ST_AUTH=$ST_AUTH"
  if command -v curl >/dev/null; then
    curl -sS -m 5 -o /dev/null -w "proxy_info=%{http_code}\n" "$ST_AUTH/../info" 2>/dev/null \
      || curl -sS -m 5 -o /dev/null -w "proxy_root=%{http_code}\n" "http://127.0.0.1:8080/info" || true
    curl -sS -m 3 -D - -o /dev/null -H "X-Auth-User: $ST_USER" -H "X-Auth-Key: $ST_KEY" "$ST_AUTH" 2>/dev/null | head -5 || true
  fi
  pgrep -fl 'swift-proxy-server|swift-object-server|swift-console' 2>/dev/null | head -20 || echo "(no matching processes)"
}

cmd_test() {
  local smoke=0 func=0 lab=0
  if [[ $# -eq 0 ]]; then smoke=1; func=1; fi
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --smoke) smoke=1; shift ;;
      --func) func=1; shift ;;
      --lab) lab=1; shift ;;
      *) die "test: unknown arg $1" ;;
    esac
  done
  export ST_AUTH="${ST_AUTH:-$ST_AUTH_DEFAULT}"
  export ST_USER="${ST_USER:-$AUTH_USER}"
  export ST_KEY="${ST_KEY:-$AUTH_KEY}"
  local rc=0
  if [[ "$smoke" -eq 1 ]]; then
    local smoke_sh="$SWIFT_RUST/deploy/smoke.sh"
    [[ -x "${PEREGRINE_PREFIX:-}/scripts/smoke.sh" ]] && smoke_sh="${PEREGRINE_PREFIX}/scripts/smoke.sh"
    if [[ -x "$smoke_sh" ]]; then
      log "smoke"
      bash "$smoke_sh" || rc=1
    else
      log "smoke: curl auth + put/get"
      local tok
      tok="$(curl -sS -D - -o /dev/null -H "X-Auth-User: $ST_USER" -H "X-Auth-Key: $ST_KEY" "$ST_AUTH" | awk 'tolower($1)=="x-auth-token:"{print $2}' | tr -d '\r')"
      [[ -n "$tok" ]] || { log "auth failed"; rc=1; }
      local url
      url="$(curl -sS -D - -o /dev/null -H "X-Auth-User: $ST_USER" -H "X-Auth-Key: $ST_KEY" "$ST_AUTH" | awk 'tolower($1)=="x-storage-url:"{print $2}' | tr -d '\r')"
      if [[ -n "$tok" && -n "$url" ]]; then
        curl -sS -o /dev/null -w "put=%{http_code}\n" -X PUT -H "X-Auth-Token: $tok" "$url/offline_c" || rc=1
        echo hello | curl -sS -o /dev/null -w "obj=%{http_code}\n" -X PUT -H "X-Auth-Token: $tok" -H "Content-Type: text/plain" --data-binary @- "$url/offline_c/obj1" || rc=1
      fi
    fi
  fi
  if [[ "$func" -eq 1 ]]; then
    local fs="$REPO_ROOT/tools/func-suite.sh"
    [[ -x "${PEREGRINE_PREFIX:-}/scripts/func-suite.sh" ]] && fs="${PEREGRINE_PREFIX}/scripts/func-suite.sh"
    if [[ -x "$fs" ]]; then
      log "func-suite"
      bash "$fs" || rc=1
    else
      log "warn: func-suite.sh missing"
      rc=1
    fi
  fi
  if [[ "$lab" -eq 1 ]]; then
    log "lab: /info + bulk_upload advertise"
    curl -sS -m 10 "http://127.0.0.1:8080/info" | head -c 400; echo
    if curl -sS -m 10 "http://127.0.0.1:8080/info" | grep -q bulk_upload; then
      log "lab: bulk_upload present on /info"
    else
      log "lab: bulk_upload not on /info (pipeline may omit bulk)"
    fi
  fi
  return "$rc"
}

cmd_all_local() {
  local features="" console=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --features) features="$2"; shift 2 ;;
      --console) console=1; shift ;;
      *) die "all-local: unknown arg $1" ;;
    esac
  done
  if [[ -n "$features" ]]; then
    cmd_pack --features "$features"
  else
    cmd_pack
  fi
  local prefix="${HOME}/.local/peregrine"
  cmd_install --prefix "$prefix" --from "$DEFAULT_OUT"
  export PEREGRINE_PREFIX="$prefix"
  # shellcheck disable=SC1090
  source "$prefix/env.sh"
  if [[ "$console" -eq 1 ]]; then
    cmd_start --console
  else
    cmd_start
  fi
  cmd_status || true
  cmd_test --smoke --func --lab
}

usage() {
  sed -n '2,25p' "$0" | sed 's/^# \?//'
}

main() {
  local cmd="${1:-}"
  shift || true
  case "$cmd" in
    pack) cmd_pack "$@" ;;
    install) cmd_install "$@" ;;
    start) cmd_start "$@" ;;
    stop) cmd_stop "$@" ;;
    status) cmd_status "$@" ;;
    test) cmd_test "$@" ;;
    all-local) cmd_all_local "$@" ;;
    -h|--help|help|"") usage ;;
    *) die "unknown command: $cmd (try --help)" ;;
  esac
}

main "$@"
