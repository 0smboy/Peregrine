#!/usr/bin/env bash
# Install an offline pack onto this host (airgap-safe).
# Usage: install-local-saio.sh [--prefix DIR] [--from PACK] [--setup]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

PREFIX="$DEFAULT_PREFIX"
FROM=""
DO_SETUP=0
LINK_SYSTEM=0

usage() {
  cat <<'EOF'
Usage: install-local-saio.sh [--prefix DIR] [--from PACK] [--setup] [--link-system]

  --prefix DIR     Install root (default: /opt/peregrine)
  --from PACK      offline-pack dir or .tar.gz (default: latest under <repo>/dist)
  --setup          Also run SAIO conf+rings generation after install
  --link-system    As root: also install bins to /usr/local/bin and conf to /etc/swift
                   (matches classic deploy/bootstrap.sh layout)

Env:
  SWIFT_TLS_PEM    Optional path to combined TLS PEM (staged under prefix/etc/tls)
  FORCE_PREFIX_LAYOUT=1  Never use system /etc/swift paths even as root
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) PREFIX="${2:?}"; shift 2 ;;
    --from) FROM="${2:?}"; shift 2 ;;
    --setup) DO_SETUP=1; shift ;;
    --link-system) LINK_SYSTEM=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown arg: $1" ;;
  esac
done

need_cmd install
need_cmd tar

if [ -z "$FROM" ]; then
  FROM="$(find_latest_pack "$DEFAULT_PACK_OUT")"
fi
[ -n "$FROM" ] || die "no pack found; run: offline-oneclick.sh pack"

log "install from: $FROM"
log "prefix:       $PREFIX"

expand_pack "$FROM"
trap cleanup_pack_extract EXIT

[ -d "$_PACK_DIR/bin" ] || die "pack missing bin/: $_PACK_DIR"

resolve_layout "$PREFIX"

# ---- layout ----
mkdir -p \
  "$PREFIX"/{bin,lib,deploy,tools,scripts,conf,docs,etc/tls} \
  "$PREFIX/var"/{log/swift,run,srv} \
  "$LOG_DIR" \
  "$RUN_DIR" \
  "$CONSOLE_CONF_DIR" \
  "$SWIFT_DIR"

log "install binaries -> $PREFIX/bin"
install -m 0755 "$_PACK_DIR"/bin/* "$PREFIX/bin/"

if [ -d "$_PACK_DIR/lib" ] && ls "$_PACK_DIR"/lib/* >/dev/null 2>&1; then
  log "install shared libs -> $PREFIX/lib"
  cp -a "$_PACK_DIR"/lib/. "$PREFIX/lib/" || true
  # Linux: register rpath-less libs via ldconfig conf if root
  if is_root && [ "$(host_os)" = linux ]; then
    conf_d="/etc/ld.so.conf.d/peregrine.conf"
    echo "$PREFIX/lib" >"$conf_d"
    ldconfig 2>/dev/null || true
    # also drop into /usr/lib64 for bootstrap compatibility
    if [ -d /usr/lib64 ]; then
      cp -a "$_PACK_DIR"/lib/*.so* /usr/lib64/ 2>/dev/null || true
      ldconfig 2>/dev/null || true
    fi
  fi
  # macOS: DYLD helper env file
  if [ "$(host_os)" = darwin ]; then
    echo "export DYLD_LIBRARY_PATH=\"$PREFIX/lib\${DYLD_LIBRARY_PATH:+:\$DYLD_LIBRARY_PATH}\"" \
      >"$PREFIX/etc/dyld.env"
  fi
fi

log "install deploy/tools/scripts"
cp -a "$_PACK_DIR"/deploy/. "$PREFIX/deploy/" 2>/dev/null || true
chmod +x "$PREFIX"/deploy/*.sh 2>/dev/null || true
if [ -d "$_PACK_DIR/tools" ]; then
  cp -a "$_PACK_DIR"/tools/. "$PREFIX/tools/"
  chmod +x "$PREFIX"/tools/*.sh 2>/dev/null || true
fi
if [ -d "$_PACK_DIR/scripts" ]; then
  cp -a "$_PACK_DIR"/scripts/. "$PREFIX/scripts/"
  chmod +x "$PREFIX"/scripts/*.sh 2>/dev/null || true
fi
if [ -d "$_PACK_DIR/conf" ]; then
  cp -a "$_PACK_DIR"/conf/. "$PREFIX/conf/"
fi
if [ -d "$_PACK_DIR/docs" ]; then
  cp -a "$_PACK_DIR"/docs/. "$PREFIX/docs/" 2>/dev/null || true
fi
[ -f "$_PACK_DIR/VERSION" ] && cp "$_PACK_DIR/VERSION" "$PREFIX/VERSION"
[ -f "$_PACK_DIR/MANIFEST.txt" ] && cp "$_PACK_DIR/MANIFEST.txt" "$PREFIX/MANIFEST.txt"

# Console config for local SAIO
write_console_config \
  "$CONSOLE_CONF_DIR/config.json" \
  "$ST_AUTH_DEFAULT" \
  "$ST_URL_DEFAULT" \
  "$CONSOLE_BIND_DEFAULT"
# Keep a copy under prefix/conf as well
cp "$CONSOLE_CONF_DIR/config.json" "$PREFIX/conf/console-config.json" 2>/dev/null || true

# Optional TLS PEM
apply_tls_pem_if_set "$PREFIX/etc/tls" >/dev/null || true

# env profile for operators
cat >"$PREFIX/etc/env.sh" <<EOF
# Peregrine offline install profile — source me
export PEREGRINE_PREFIX="$PREFIX"
export PATH="$PREFIX/bin:\$PATH"
export SWIFT_BIN="$PREFIX/bin"
export SWIFT_DIR="$SWIFT_DIR"
export DEVICE_ROOT="$DEVICE_ROOT"
export LOG_DIR="$LOG_DIR"
export RUN_DIR="$RUN_DIR"
export ST_AUTH="${ST_AUTH_DEFAULT}"
export ST_USER="${ST_USER_DEFAULT}"
export ST_KEY="${ST_KEY_DEFAULT}"
if [ -f "$PREFIX/etc/dyld.env" ]; then
  # shellcheck disable=SC1091
  . "$PREFIX/etc/dyld.env"
fi
if [ -d "$PREFIX/lib" ]; then
  export LD_LIBRARY_PATH="$PREFIX/lib\${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}"
fi
EOF

# Optional classic system links
if [ "$LINK_SYSTEM" = 1 ]; then
  is_root || die "--link-system requires root"
  log "link bins -> /usr/local/bin"
  install -d /usr/local/bin
  for b in "$PREFIX"/bin/*; do
    install -m 0755 "$b" "/usr/local/bin/$(basename "$b")"
  done
fi

# Write install stamp
cat >"$PREFIX/INSTALL" <<EOF
prefix=$PREFIX
swift_dir=$SWIFT_DIR
device_root=$DEVICE_ROOT
bindst=$BINDST
installed=$(iso_now)
from=$FROM
user=$(id -un)
host=$(hostname 2>/dev/null || echo unknown)
EOF

if [ "$DO_SETUP" = 1 ]; then
  log "generate SAIO conf + rings"
  export SWIFT_BIN="$PREFIX/bin"
  export SWIFT_DIR DEVICE_ROOT
  if [ -x "$PREFIX/deploy/saio-setup-portable.sh" ]; then
    bash "$PREFIX/deploy/saio-setup-portable.sh"
  elif [ -x "$PREFIX/deploy/saio-setup.sh" ]; then
    # classic script expects /srv/node and /etc/swift
    if is_root; then
      SWIFT_BIN="$PREFIX/bin" bash "$PREFIX/deploy/saio-setup.sh"
    else
      die "classic saio-setup needs root; use portable (should be in pack) or reinstall with newer pack"
    fi
  else
    die "no saio-setup script in $PREFIX/deploy"
  fi
fi

ok "installed Peregrine offline pack at $PREFIX"
note "bins:    $PREFIX/bin"
note "conf:    $SWIFT_DIR (after start/setup)"
note "console: $CONSOLE_CONF_DIR/config.json"
note "profile: source $PREFIX/etc/env.sh"
note "next:    offline-oneclick.sh start --saio [--console]"
