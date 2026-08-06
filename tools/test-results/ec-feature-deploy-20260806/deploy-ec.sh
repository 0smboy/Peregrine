#!/bin/bash
# Run ON swift1 after EC build succeeds. Rolling-ish install with brief stop.
set -euo pipefail
export PATH=/root/.cargo/bin:/usr/local/bin:$PATH
SRC=/root/work/swift-rust/target/release
LOGDIR=/root/ec-build-20260806
mkdir -p "$LOGDIR"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)

for bin in swift-proxy-server swift-object-server swift-object-reconstructor; do
  test -x "$SRC/$bin" || { echo "missing $SRC/$bin"; exit 1; }
done

echo "=== new sha256 ==="
sha256sum "$SRC/swift-proxy-server" "$SRC/swift-object-server" "$SRC/swift-object-reconstructor" | tee "$LOGDIR/new-sha256.txt"

# confirm linked to liberasurecode
echo "=== ldd proxy (erasure) ==="
ldd "$SRC/swift-proxy-server" | grep -i erasure || echo "WARN: no liberasurecode in ldd proxy"
ldd "$SRC/swift-object-server" | grep -i erasure || echo "WARN: no liberasurecode in ldd object"
ldd "$SRC/swift-object-reconstructor" | grep -i erasure || echo "WARN: no liberasurecode in ldd reconstructor"

NODES="swift1 swift2 swift3 swift4"
# map hostname aliases from swift1
declare -A IP
IP[swift1]=10.0.0.1
IP[swift2]=10.0.0.2
IP[swift3]=10.0.0.3
IP[swift4]=10.0.0.4

install_one() {
  local host=$1
  local ip=${IP[$host]}
  echo "---- install $host ($ip) ----"
  # stop consumers of bins
  ssh -o BatchMode=yes -o StrictHostKeyChecking=no root@$ip \
    'systemctl stop swift-proxy swift-object 2>/dev/null || true;
     systemctl stop swift-object-reconstructor 2>/dev/null || true;
     sleep 1'
  scp -o BatchMode=yes \
    "$SRC/swift-proxy-server" "$SRC/swift-object-server" "$SRC/swift-object-reconstructor" \
    root@$ip:/usr/local/bin/
  ssh -o BatchMode=yes root@$ip \
    'chmod 755 /usr/local/bin/swift-proxy-server /usr/local/bin/swift-object-server /usr/local/bin/swift-object-reconstructor;
     restorecon /usr/local/bin/swift-proxy-server /usr/local/bin/swift-object-server /usr/local/bin/swift-object-reconstructor 2>/dev/null || true;
     systemctl start swift-object; systemctl start swift-proxy;
     systemctl is-active swift-proxy swift-object;
     sha256sum /usr/local/bin/swift-proxy-server /usr/local/bin/swift-object-server'
}

# local install first (swift1)
echo "---- install local swift1 ----"
systemctl stop swift-proxy swift-object 2>/dev/null || true
systemctl stop swift-object-reconstructor 2>/dev/null || true
sleep 1
install -m755 "$SRC/swift-proxy-server" /usr/local/bin/swift-proxy-server
install -m755 "$SRC/swift-object-server" /usr/local/bin/swift-object-server
install -m755 "$SRC/swift-object-reconstructor" /usr/local/bin/swift-object-reconstructor
restorecon /usr/local/bin/swift-proxy-server /usr/local/bin/swift-object-server /usr/local/bin/swift-object-reconstructor 2>/dev/null || true
systemctl start swift-object
systemctl start swift-proxy
systemctl is-active swift-proxy swift-object
sha256sum /usr/local/bin/swift-proxy-server /usr/local/bin/swift-object-server

for h in swift2 swift3 swift4; do
  install_one $h
done

echo "=== post-hash all ==="
for ip in 10.0.0.1 10.0.0.2 10.0.0.3 10.0.0.4; do
  ssh -o BatchMode=yes root@$ip 'hostname; sha256sum /usr/local/bin/swift-proxy-server /usr/local/bin/swift-object-server'
done | tee "$LOGDIR/post-deploy-sha256.txt"

echo "DEPLOY_OK $STAMP"
