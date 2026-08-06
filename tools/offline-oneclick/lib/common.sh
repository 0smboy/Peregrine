#!/usr/bin/env bash
# Shared helpers for Peregrine offline-oneclick toolkit.
# shellcheck disable=SC2034

set -euo pipefail

# Resolve toolkit root (tools/offline-oneclick) regardless of how we were invoked.
_offline_common_src="${BASH_SOURCE[0]:-$0}"
TOOLKIT_DIR="$(cd "$(dirname "$_offline_common_src")/.." && pwd)"
# Peregrine monorepo root: tools/offline-oneclick -> tools -> Peregrine
PEREGRINE_ROOT="$(cd "$TOOLKIT_DIR/../.." && pwd)"

# Defaults (overridable by env or CLI)
DEFAULT_PREFIX="/opt/peregrine"
DEFAULT_PACK_OUT="${PEREGRINE_ROOT}/dist"
SWIFT_DIR_DEFAULT="/etc/swift"
DEVICE_ROOT_DEFAULT="/srv"
BINDST_DEFAULT="/usr/local/bin"
CONSOLE_BIND_DEFAULT="127.0.0.1:9000"
PROXY_PORT_DEFAULT="8080"

# SAIO TempAuth (matches deploy/saio-setup.sh)
ST_USER_DEFAULT="test:tester"
ST_KEY_DEFAULT="testing"
ST_AUTH_DEFAULT="http://127.0.0.1:8080/auth/v1.0"
ST_URL_DEFAULT="http://127.0.0.1:8080"

# Runtime state under prefix (non-root / portable mode)
prefix_state_dir() {
  local p="${1:-${PREFIX:-$DEFAULT_PREFIX}}"
  echo "$p/var/run"
}

log()  { printf '\033[1;36m== %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32mOK\033[0m  %s\n' "$*"; }
warn() { printf '\033[1;33mWARN\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mERROR\033[0m %s\n' "$*" >&2; exit 1; }
note() { printf '  %s\n' "$*"; }

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

is_root() { [ "$(id -u)" = 0 ]; }

# Prefer system paths when root (classic SAIO); otherwise PREFIX-local layout.
resolve_layout() {
  local prefix="${1:-${PREFIX:-$DEFAULT_PREFIX}}"
  PREFIX="$prefix"
  if is_root && [ "${FORCE_PREFIX_LAYOUT:-0}" != 1 ]; then
    SWIFT_DIR="${SWIFT_DIR:-$SWIFT_DIR_DEFAULT}"
    DEVICE_ROOT="${DEVICE_ROOT:-$DEVICE_ROOT_DEFAULT}"
    BINDST="${BINDST:-$BINDST_DEFAULT}"
    LOG_DIR="${LOG_DIR:-/var/log/swift}"
    CONSOLE_CONF_DIR="${CONSOLE_CONF_DIR:-/etc/swift-console}"
    RUN_DIR="${RUN_DIR:-/var/run/peregrine}"
  else
    SWIFT_DIR="${SWIFT_DIR:-$prefix/etc/swift}"
    DEVICE_ROOT="${DEVICE_ROOT:-$prefix/var/srv}"
    BINDST="${BINDST:-$prefix/bin}"
    LOG_DIR="${LOG_DIR:-$prefix/var/log/swift}"
    CONSOLE_CONF_DIR="${CONSOLE_CONF_DIR:-$prefix/etc/swift-console}"
    RUN_DIR="${RUN_DIR:-$prefix/var/run}"
  fi
  export PREFIX SWIFT_DIR DEVICE_ROOT BINDST LOG_DIR CONSOLE_CONF_DIR RUN_DIR
}

# Locate most recent offline pack under a directory (tarball or extracted dir).
find_latest_pack() {
  local search="${1:-$DEFAULT_PACK_OUT}"
  local best=""
  if [ -d "$search" ]; then
    # Prefer extracted dirs named offline-pack-*
    best="$(ls -1d "$search"/offline-pack-* 2>/dev/null | grep -v '\.tar\.gz$' | sort | tail -1 || true)"
    if [ -z "$best" ]; then
      best="$(ls -1t "$search"/offline-pack-*.tar.gz 2>/dev/null | head -1 || true)"
    fi
  fi
  if [ -z "$best" ] && [ -e "$search" ]; then
    best="$search"
  fi
  echo "$best"
}

# Expand a pack path (dir or .tar.gz) to a real directory; extracts to TMP if needed.
# Sets global _PACK_DIR and optionally _PACK_EXTRACT_TMP (caller should clean).
expand_pack() {
  local from="$1"
  _PACK_EXTRACT_TMP=""
  if [ -z "$from" ] || [ ! -e "$from" ]; then
    die "pack not found: ${from:-<empty>} (run pack first or pass --from)"
  fi
  if [ -d "$from" ]; then
    _PACK_DIR="$(cd "$from" && pwd)"
    return 0
  fi
  case "$from" in
    *.tar.gz|*.tgz)
      _PACK_EXTRACT_TMP="$(mktemp -d "${TMPDIR:-/tmp}/peregrine-pack.XXXXXX")"
      tar -xzf "$from" -C "$_PACK_EXTRACT_TMP"
      # tarball root may be offline-pack-YYYYMMDD/
      if [ -d "$_PACK_EXTRACT_TMP/bin" ]; then
        _PACK_DIR="$_PACK_EXTRACT_TMP"
      else
        _PACK_DIR="$(find "$_PACK_EXTRACT_TMP" -maxdepth 2 -type d -name 'offline-pack-*' | head -1)"
        [ -n "$_PACK_DIR" ] || _PACK_DIR="$(find "$_PACK_EXTRACT_TMP" -maxdepth 1 -mindepth 1 -type d | head -1)"
      fi
      [ -d "$_PACK_DIR" ] || die "could not find pack root inside $from"
      ;;
    *)
      die "unsupported pack format: $from (want directory or .tar.gz)"
      ;;
  esac
}

cleanup_pack_extract() {
  if [ -n "${_PACK_EXTRACT_TMP:-}" ] && [ -d "$_PACK_EXTRACT_TMP" ]; then
    rm -rf "$_PACK_EXTRACT_TMP"
    _PACK_EXTRACT_TMP=""
  fi
}

# Wait until proxy auth responds 200 (or timeout).
wait_proxy() {
  local auth="${1:-${ST_AUTH:-$ST_AUTH_DEFAULT}}"
  local tries="${2:-40}"
  local code=""
  local i
  for i in $(seq 1 "$tries"); do
    code="$(curl -s -m3 -o /dev/null -w '%{http_code}' \
      -H "X-Auth-User: ${ST_USER:-$ST_USER_DEFAULT}" \
      -H "X-Auth-Key: ${ST_KEY:-$ST_KEY_DEFAULT}" \
      "$auth" 2>/dev/null || true)"
    if [ "$code" = "200" ]; then
      return 0
    fi
    sleep 1
  done
  return 1
}

# Write console config pointing at local proxy.
write_console_config() {
  local dest="$1"
  local auth="${2:-${ST_AUTH:-$ST_AUTH_DEFAULT}}"
  local base="${3:-${ST_URL:-$ST_URL_DEFAULT}}"
  local bind="${4:-${CONSOLE_BIND:-$CONSOLE_BIND_DEFAULT}}"
  mkdir -p "$(dirname "$dest")"
  cat >"$dest" <<EOF
{
  "bind": "$bind",
  "auth_url": "$auth",
  "swift_base": "$base",
  "deploy_upstream": "http://127.0.0.1:8789",
  "deploy_user": "operator",
  "deploy_token_file": "/etc/swift-deploy/ui-token",
  "grafana_upstream": "http://127.0.0.1:3000",
  "grafana_user": "admin",
  "cluster_name": "peregrine-saio-offline",
  "session_idle_hours": 24,
  "max_upload_bytes": 1073741824,
  "tempurl_default_secs": 86400,
  "accounts": [
    { "tenant": "test", "user": "tester", "roles": [".admin"] }
  ]
}
EOF
}

# Optional TLS PEM install (no secrets committed; path from env).
# Proxy does not terminate TLS natively; we stage PEM for reverse-proxy use.
apply_tls_pem_if_set() {
  local dest_dir="$1"
  local pem="${SWIFT_TLS_PEM:-}"
  if [ -z "$pem" ]; then
    return 0
  fi
  if [ ! -f "$pem" ]; then
    die "SWIFT_TLS_PEM set but file missing: $pem"
  fi
  mkdir -p "$dest_dir"
  install -m 0600 "$pem" "$dest_dir/server.pem"
  # Split-style convenience: if PEM has key+cert, leave as combined.
  ok "TLS PEM staged at $dest_dir/server.pem (front with nginx/caddy; proxy stays HTTP)"
  echo "$dest_dir/server.pem"
}

pid_alive() {
  local pid="$1"
  [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null
}

read_pidfile() {
  local f="$1"
  if [ -f "$f" ]; then
    tr -d ' \n' <"$f" || true
  fi
}

# Platform helpers
host_os() { uname -s | tr '[:upper:]' '[:lower:]'; }
host_arch() { uname -m; }

date_stamp() { date +%Y%m%d; }
iso_now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
