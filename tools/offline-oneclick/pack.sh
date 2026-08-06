#!/usr/bin/env bash
# Build release binaries and stage an offline pack (tarball + extracted dir).
# Usage: pack.sh [--out DIR] [--features ec] [--skip-build]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

OUT_DIR="$DEFAULT_PACK_OUT"
FEATURES_EC=0
SKIP_BUILD=0

usage() {
  cat <<'EOF'
Usage: pack.sh [--out DIR] [--features ec] [--skip-build]

  --out DIR       Stage directory for offline-pack-YYYYMMDD (default: <repo>/dist)
  --features ec   cargo --features swift-proxy-server/ec,swift-object-server/ec
                  (Linux + liberasurecode; also packs shared libs when found)
  --skip-build    Reuse existing target/release binaries (no cargo)
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --out) OUT_DIR="${2:?}"; shift 2 ;;
    --features)
      case "${2:?}" in
        ec) FEATURES_EC=1 ;;
        *) die "unknown feature: $2 (only 'ec' supported)" ;;
      esac
      shift 2
      ;;
    --skip-build) SKIP_BUILD=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown arg: $1" ;;
  esac
done

need_cmd cargo
need_cmd tar
need_cmd install

STAMP="$(date_stamp)"
PACK_NAME="offline-pack-${STAMP}"
STAGE="${OUT_DIR}/${PACK_NAME}"
RUST_DIR="${PEREGRINE_ROOT}/swift-rust"
CONSOLE_DIR="${PEREGRINE_ROOT}/swift-console"
RUST_REL="${RUST_DIR}/target/release"
CONSOLE_REL="${CONSOLE_DIR}/target/release"

log "offline pack -> $STAGE"
rm -rf "$STAGE"
mkdir -p "$STAGE"/{bin,lib,deploy,tools,conf,scripts,docs}

# ---- build ----
FEATURE_ARGS=()
if [ "$FEATURES_EC" = 1 ]; then
  FEATURE_ARGS=(--features "swift-proxy-server/ec,swift-object-server/ec")
  note "EC features enabled (requires liberasurecode on this host)"
fi

if [ "$SKIP_BUILD" != 1 ]; then
  log "cargo build --release (swift-rust)"
  (
    cd "$RUST_DIR"
    # shellcheck disable=SC2086
    cargo build --release --workspace "${FEATURE_ARGS[@]+"${FEATURE_ARGS[@]}"}"
  )
  log "cargo build --release (swift-console)"
  (cd "$CONSOLE_DIR" && cargo build --release)
else
  warn "skip-build: using existing release binaries"
fi

[ -d "$RUST_REL" ] || die "missing $RUST_REL — build failed or --skip-build without prior build"
[ -x "$CONSOLE_REL/swift-console" ] || die "missing swift-console binary at $CONSOLE_REL/swift-console"

# ---- collect binaries ----
log "stage binaries"
# Copy every executable swift-* (and related) from release, skip .d / libs
copied=0
while IFS= read -r -d '' f; do
  base="$(basename "$f")"
  case "$base" in
    *.d|*.rlib|*.rmeta|*.a|*.so|*.dylib) continue ;;
  esac
  if [ -x "$f" ] && [ -f "$f" ]; then
    # skip cargo build-script helpers
    case "$base" in
      build-script-*|*.bin) continue ;;
    esac
    install -m 0755 "$f" "$STAGE/bin/$base"
    copied=$((copied + 1))
  fi
done < <(find "$RUST_REL" -maxdepth 1 -type f -print0 2>/dev/null)

# Ensure core server binaries exist
for must in swift-proxy-server swift-account-server swift-container-server \
            swift-object-server swift-ring-builder; do
  [ -x "$STAGE/bin/$must" ] || die "required binary missing from pack: $must"
done

install -m 0755 "$CONSOLE_REL/swift-console" "$STAGE/bin/swift-console"
copied=$((copied + 1))
ok "staged $copied binaries"

# ---- liberasurecode shared libs (optional, for airgap EC on Linux) ----
if [ "$FEATURES_EC" = 1 ] || [ "$(host_os)" = linux ]; then
  log "collect liberasurecode shared libraries (best-effort)"
  lib_found=0
  search_dirs=(
    /usr/lib64 /usr/lib /usr/lib/x86_64-linux-gnu /lib64 /lib
    /usr/local/lib /opt/homebrew/lib
  )
  for d in "${search_dirs[@]}"; do
    [ -d "$d" ] || continue
    for pattern in liberasurecode libnullcode libXorcode liberasurecode_rs; do
      # shellcheck disable=SC2044
      for so in $(find "$d" -maxdepth 1 \( -name "${pattern}*.so*" -o -name "${pattern}*.dylib*" \) 2>/dev/null); do
        cp -a "$so" "$STAGE/lib/" 2>/dev/null && lib_found=$((lib_found + 1)) || true
      done
    done
  done
  if [ "$lib_found" -gt 0 ]; then
    ok "staged $lib_found EC-related shared libs under lib/"
  else
    warn "no liberasurecode libs found; EC on target needs system packages or rebuild with libs present"
  fi
fi

# ---- deploy scripts (reuse existing SAIO toolkit) ----
log "stage deploy + tools"
for f in saio-setup.sh saio-start.sh smoke.sh stop.sh bootstrap.sh README.md ec-heal-demo.sh; do
  if [ -f "$RUST_DIR/deploy/$f" ]; then
    install -m 0755 "$RUST_DIR/deploy/$f" "$STAGE/deploy/$f" 2>/dev/null \
      || install -m 0644 "$RUST_DIR/deploy/$f" "$STAGE/deploy/$f"
  fi
done
# make scripts executable
chmod +x "$STAGE"/deploy/*.sh 2>/dev/null || true

install -m 0755 "$RUST_DIR/tools/func-suite.sh" "$STAGE/tools/func-suite.sh"
# copy a few useful lab helpers if present
for f in ha-test.sh ec-heal-test.sh; do
  [ -f "$RUST_DIR/tools/$f" ] && install -m 0755 "$RUST_DIR/tools/$f" "$STAGE/tools/$f" || true
done

# ---- console static + conf template ----
if [ -d "$CONSOLE_DIR/static" ]; then
  mkdir -p "$STAGE/console-static"
  cp -a "$CONSOLE_DIR/static/." "$STAGE/console-static/" 2>/dev/null || true
fi
install -m 0644 "$SCRIPT_DIR/conf/console-config.saio.json" "$STAGE/conf/console-config.saio.json"
if [ -f "$CONSOLE_DIR/conf/swift-console.service" ]; then
  install -m 0644 "$CONSOLE_DIR/conf/swift-console.service" "$STAGE/conf/swift-console.service"
fi

# ---- offline-oneclick scripts themselves (so target host can run install/start/test) ----
log "stage offline-oneclick runtime"
install -m 0755 "$SCRIPT_DIR/offline-oneclick.sh" "$STAGE/scripts/offline-oneclick.sh"
for f in pack.sh install-local-saio.sh start.sh stop.sh test.sh; do
  [ -f "$SCRIPT_DIR/$f" ] && install -m 0755 "$SCRIPT_DIR/$f" "$STAGE/scripts/$f"
done
mkdir -p "$STAGE/scripts/lib" "$STAGE/scripts/conf"
install -m 0644 "$SCRIPT_DIR/lib/common.sh" "$STAGE/scripts/lib/common.sh"
install -m 0644 "$SCRIPT_DIR/conf/console-config.saio.json" "$STAGE/scripts/conf/console-config.saio.json"
[ -f "$SCRIPT_DIR/README.md" ] && install -m 0644 "$SCRIPT_DIR/README.md" "$STAGE/docs/OFFLINE-ONECLICK.md"

# Local SAIO setup/start that honour PREFIX / SWIFT_DIR / DEVICE_ROOT
cat >"$STAGE/deploy/saio-setup-portable.sh" <<'PORTABLE_SETUP'
#!/usr/bin/env bash
# Portable SAIO setup: same topology as deploy/saio-setup.sh but paths from env.
# SWIFT_DIR, DEVICE_ROOT, SWIFT_BIN (BINDIR) are honoured.
set -euo pipefail
SWIFT_DIR="${SWIFT_DIR:-/etc/swift}"
DEVICE_ROOT="${DEVICE_ROOT:-/srv}"
BINDIR="${SWIFT_BIN:-/usr/local/bin}"

setenforce 0 2>/dev/null || true

echo "device trees under $DEVICE_ROOT"
for N in 1 2 3 4; do
  mkdir -p "$DEVICE_ROOT/node$N/sdb$N" "$DEVICE_ROOT/node$N/sdb$((N+4))"
done
mkdir -p "$SWIFT_DIR"/{object-server,container-server,account-server}

echo "swift.conf"
cat > "$SWIFT_DIR/swift.conf" <<'EOF'
[swift-hash]
swift_hash_path_prefix = swiftrust0717
swift_hash_path_suffix = saio2026

[storage-policy:0]
name = Policy-0
default = yes

[storage-policy:1]
name = EC-4-2
policy_type = erasure_coding
ec_type = liberasurecode_rs_vand
ec_num_data_fragments = 4
ec_num_parity_fragments = 2
ec_object_segment_size = 1048576
EOF

echo "proxy-server.conf"
cat > "$SWIFT_DIR/proxy-server.conf" <<'EOF'
[app:proxy-server]
bind_ip = 0.0.0.0
bind_port = 8080
account_autocreate = true
storage_url = http://127.0.0.1:8080

[filter:tempauth]
user_admin_admin = admin .admin .reseller_admin
user_test_tester = testing .admin
user_test2_tester2 = testing2 .admin
user_test_tester3 = testing3
EOF

echo "per-node server confs"
PEER_OBJ=""; PEER_CONT=""; PEER_ACCT=""
for N in 1 2 3 4; do
  PEER_OBJ+="60${N}0:$DEVICE_ROOT/node$N,"
  PEER_CONT+="60${N}1:$DEVICE_ROOT/node$N,"
  PEER_ACCT+="60${N}2:$DEVICE_ROOT/node$N,"
done
for N in 1 2 3 4; do
  cat > "$SWIFT_DIR/object-server/$N.conf" <<EOF
[app:object-server]
bind_ip = 0.0.0.0
bind_port = 60${N}0
devices = $DEVICE_ROOT/node$N
mount_check = false

[object-replicator]
interval = 30
peer_map = ${PEER_OBJ%,}
EOF
  cat > "$SWIFT_DIR/container-server/$N.conf" <<EOF
[app:container-server]
bind_ip = 0.0.0.0
bind_port = 60${N}1
devices = $DEVICE_ROOT/node$N
mount_check = false

[container-replicator]
interval = 30
peer_map = ${PEER_CONT%,}
EOF
  cat > "$SWIFT_DIR/account-server/$N.conf" <<EOF
[app:account-server]
bind_ip = 0.0.0.0
bind_port = 60${N}2
devices = $DEVICE_ROOT/node$N
mount_check = false

[account-replicator]
interval = 30
peer_map = ${PEER_ACCT%,}
EOF
done

echo "rings"
RB="$BINDIR/swift-ring-builder"
[ -x "$RB" ] || { echo "ERROR: $RB not found" >&2; exit 1; }

build3() {
  local name=$1 suffix=$2 ring="$SWIFT_DIR/$1.ring.gz"
  rm -f "$ring" "$ring.builder.json"
  "$RB" "$ring" create 10 3
  for N in 1 2 3 4; do
    "$RB" "$ring" add "r1z$N-127.0.0.1:60${N}${suffix}/sdb$N" 100
  done
  "$RB" "$ring" rebalance
}
build3 object    0
build3 container 1
build3 account   2

ring="$SWIFT_DIR/object-1.ring.gz"; rm -f "$ring" "$ring.builder.json"
"$RB" "$ring" create 10 6
for N in 1 2 3 4; do
  "$RB" "$ring" add "r1z$N-127.0.0.1:60${N}0/sdb$N" 100
  "$RB" "$ring" add "r1z$N-127.0.0.1:60${N}0/sdb$((N+4))" 100
done
"$RB" "$ring" rebalance

ls "$SWIFT_DIR"/*.ring.gz
echo "saio portable setup complete (SWIFT_DIR=$SWIFT_DIR)."
PORTABLE_SETUP
chmod +x "$STAGE/deploy/saio-setup-portable.sh"

cat >"$STAGE/deploy/saio-start-portable.sh" <<'PORTABLE_START'
#!/usr/bin/env bash
# Portable SAIO supervisor: same 13 processes as saio-start.sh; paths from env.
set -u
BINDIR="${SWIFT_BIN:-/usr/local/bin}"
SWIFT_DIR="${SWIFT_DIR:-/etc/swift}"
LOG="${LOG_DIR:-/var/log/swift}"
export SWIFT_DIR
mkdir -p "$LOG"

pids=()
start() {
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

# Write combined pid list if RUN_DIR set
if [ -n "${RUN_DIR:-}" ]; then
  mkdir -p "$RUN_DIR"
  printf '%s\n' "${pids[@]}" >"$RUN_DIR/saio.pids"
  echo "$$" >"$RUN_DIR/saio-supervisor.pid"
fi

# Prefer wait -n (bash ≥4, systemd-style reap-on-first-death); else wait all.
if wait -n "${pids[@]}" 2>/dev/null; then
  :
else
  wait 2>/dev/null || true
fi
shutdown
PORTABLE_START
chmod +x "$STAGE/deploy/saio-start-portable.sh"

# ---- VERSION / MANIFEST ----
COMMIT="unknown"
if command -v git >/dev/null 2>&1 && [ -d "$PEREGRINE_ROOT/.git" ]; then
  COMMIT="$(git -C "$PEREGRINE_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
fi
FEATURES_NOTE="default"
[ "$FEATURES_EC" = 1 ] && FEATURES_NOTE="ec"

cat >"$STAGE/VERSION" <<EOF
name=peregrine-offline-pack
version=$STAMP
commit=$COMMIT
built=$(iso_now)
host_os=$(host_os)
host_arch=$(host_arch)
features=$FEATURES_NOTE
source=$PEREGRINE_ROOT
EOF

{
  echo "# offline pack manifest"
  echo "built=$(iso_now)"
  echo
  echo "[bin]"
  ls -1 "$STAGE/bin" | sed 's/^/  /'
  echo
  echo "[lib]"
  ls -1 "$STAGE/lib" 2>/dev/null | sed 's/^/  /' || echo "  (none)"
  echo
  echo "[deploy]"
  ls -1 "$STAGE/deploy" | sed 's/^/  /'
} >"$STAGE/MANIFEST.txt"

# ---- tarball ----
log "create tarball"
mkdir -p "$OUT_DIR"
TARBALL="${OUT_DIR}/${PACK_NAME}.tar.gz"
(
  cd "$OUT_DIR"
  tar -czf "${PACK_NAME}.tar.gz" "$PACK_NAME"
)
SIZE="$(du -h "$TARBALL" | awk '{print $1}')"
ok "pack ready"
note "dir:  $STAGE"
note "tar:  $TARBALL ($SIZE)"
note "bins: $(ls -1 "$STAGE/bin" | wc -l | tr -d ' ')"
note "after airgap copy:  ./offline-oneclick.sh install --from $TARBALL"
echo "$TARBALL"
