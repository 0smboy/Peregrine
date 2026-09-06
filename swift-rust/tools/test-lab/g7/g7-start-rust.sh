#!/bin/bash
# Persistent G6 rust data-plane for G7. Does not touch :8080 / VIP / HAProxy.
set -euo pipefail
export SWIFT_DIR=/etc/g6-rust
export SWIFT_CONF=/etc/g6-rust/swift.conf
export SWIFT_CONF_FILE=/etc/g6-rust/swift.conf
BIN=/root/work/g6-rust-bin
RUN=/var/run/g6-rust
LOG=/var/log/g6-rust
mkdir -p "$RUN" "$LOG"
ulimit -n 500000

is_prod() {
  case "$1" in
    *"/etc/swift/"*|*"/usr/local/bin/"*) return 0 ;;
    *) return 1 ;;
  esac
}

start_one() {
  local name="$1" conf="$2" bin="$3"
  if [[ -f "$RUN/$name.pid" ]] && kill -0 "$(cat "$RUN/$name.pid")" 2>/dev/null; then
    echo "already $name pid=$(cat "$RUN/$name.pid")"
    return 0
  fi
  if is_prod "$conf" || is_prod "$bin"; then
    echo "REFUSE production path $conf $bin" >&2
    exit 2
  fi
  nohup "$bin" "$conf" >>"$LOG/$name.log" 2>&1 &
  echo $! >"$RUN/$name.pid"
  echo "started $name pid=$! conf=$conf"
}

# memcached 11219 is shared with g6-python isolation; start if missing
if ! ss -lntp | grep -q '127.0.0.1:11219'; then
  memcached -d -p 11219 -l 127.0.0.1 -u root -m 64 -P "$RUN/memcached.pid" -c 1024
fi

for i in 1 2 3 4; do
  start_one "account-$i" "$SWIFT_DIR/account-server/${i}.conf" "$BIN/swift-account-server"
  start_one "container-$i" "$SWIFT_DIR/container-server/${i}.conf" "$BIN/swift-container-server"
  start_one "object-$i" "$SWIFT_DIR/object-server/${i}.conf" "$BIN/swift-object-server"
done
start_one "proxy" "$SWIFT_DIR/proxy-server.conf" "$BIN/swift-proxy-server"

sleep 1
ss -lntp | grep -E '18080|16210|16220|16230|16240|16211|16221' || true
# Isolated devices are dirs on a shared root FS. mount_check=true (Rust
# default) 507s REPLICATE/SSYNC/PUT with Drive: <device> / unmounted.
if grep -RqsE '^[[:space:]]*mount_check[[:space:]]*=[[:space:]]*true' \
    "$SWIFT_DIR/object-server" 2>/dev/null; then
  echo "WARN: g6-rust object-server mount_check=true — dir-backed devices 507 REPLICATE/SSYNC" >&2
fi
if ! grep -RqsE '^[[:space:]]*mount_check[[:space:]]*=[[:space:]]*false' \
    "$SWIFT_DIR/object-server" 2>/dev/null; then
  echo "WARN: g6-rust object-server confs do not set mount_check=false (SAIO default)" >&2
fi
echo "G6_RUST_START_OK"
