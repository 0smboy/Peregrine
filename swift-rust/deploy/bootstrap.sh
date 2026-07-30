#!/usr/bin/env bash
# One-click bootstrap for the Swift-in-Rust SAIO cluster.
#
# Run as root on a fresh x86_64 Linux box (Rocky 9 / AlmaLinux 9 / Debian
# with glibc >= 2.34). Installs the erasure-coding shared libraries and the
# prebuilt binaries, generates the cluster configuration and rings, installs
# a systemd service that keeps the 13 server processes alive, and runs an
# end-to-end smoke test. No compiler, no package installs, no downloads.
#
# Idempotent: safe to re-run. Layout expected next to this script:
#   bin/   the release binaries      lib/   liberasurecode .so family
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIBDST=/usr/lib64
BINDST=/usr/local/bin
SVCLIB=/usr/local/lib/swift-rust
SERVICE=swift-rust-saio

log() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
die() { printf '\033[1;31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "must run as root (sudo bash bootstrap.sh)"
[ "$(uname -m)" = x86_64 ] || die "these binaries are x86_64 only (this is $(uname -m))"
[ -d "$HERE/bin" ] && [ -d "$HERE/lib" ] || die "bin/ and lib/ must sit next to bootstrap.sh"

log "erasure-coding libraries -> $LIBDST"
# /usr/lib64 on Debian; fall back to the multiarch dir if it is missing.
[ -d "$LIBDST" ] || LIBDST=/usr/lib/x86_64-linux-gnu
install -d "$LIBDST"
cp -a "$HERE"/lib/*.so* "$LIBDST"/
ldconfig
ldconfig -p | grep -q liberasurecode || die "liberasurecode not visible after ldconfig"

log "binaries -> $BINDST"
install -d "$BINDST"
install -m 0755 "$HERE"/bin/* "$BINDST"/
"$BINDST/swift-proxy-server" --help >/dev/null 2>&1 || true   # link check
ldd "$BINDST/swift-proxy-server" | grep -q 'not found' \
  && die "swift-proxy-server has unresolved shared libraries" || true

log "cluster configuration + rings"
SWIFT_BIN="$BINDST" bash "$HERE/saio-setup.sh"

log "systemd service -> $SERVICE"
install -d "$SVCLIB"
install -m 0755 "$HERE/saio-start.sh" "$SVCLIB/saio-start.sh"
cat > "/etc/systemd/system/$SERVICE.service" <<EOF
[Unit]
Description=Swift-in-Rust SAIO (4-node single-host EC cluster)
After=network.target

[Service]
Type=simple
ExecStart=$SVCLIB/saio-start.sh
Restart=on-failure
RestartSec=2
KillMode=control-group
TimeoutStopSec=15

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable "$SERVICE" >/dev/null 2>&1 || true
systemctl restart "$SERVICE"

log "waiting for the proxy on :8080"
ok=
for _ in $(seq 30); do
  code=$(curl -s -m3 -o /dev/null -w '%{http_code}' \
    -H 'X-Auth-User: test:tester' -H 'X-Auth-Key: testing' \
    http://127.0.0.1:8080/auth/v1.0 || true)
  [ "$code" = 200 ] && { ok=1; break; }
  sleep 1
done
[ -n "$ok" ] || die "proxy did not come up — check: journalctl -u $SERVICE"
echo "proxy is up."

log "smoke test"
bash "$HERE/smoke.sh"

cat <<EOF

$(printf '\033[1;32m')Swift-in-Rust cluster is running.$(printf '\033[0m')
  proxy      http://127.0.0.1:8080  (tempauth: test:tester / testing)
  policies   Policy-0 (3x replication), EC-4-2 (erasure coding)
  service    systemctl {status,stop,restart} $SERVICE
  logs       journalctl -u $SERVICE  +  /var/log/swift/*.log
  re-check   bash $HERE/smoke.sh
  EC heal    bash $HERE/ec-heal-demo.sh
EOF
