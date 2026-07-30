#!/bin/bash
# Clean A/B of object-server worker count on the Rust SAIO (:8081), no Loki, no
# load-host confound. 4KB writes, conc 64, across 4 containers.
set -u
ETC=/etc/rsaio
RBLD=/root/work/swift-rust/target/release
EP=http://127.0.0.1:8081
source /root/work/pyswift-venv/bin/activate
set_workers(){ sed -i -E "s/^workers = .*/workers = $1/" "$ETC/object-server.conf"; }
restart_obj(){
  pkill -9 -f "$ETC/object-server.conf" 2>/dev/null; sleep 1
  SWIFT_DIR=$ETC nohup "$RBLD/swift-object-server" "$ETC/object-server.conf" >/root/work/rsaio/object.log 2>&1 &
  sleep 2
}
for W in 2 16 64; do
  set_workers "$W"; restart_obj
  printf 'object workers=%-3s: ' "$W"
  python /root/work/wbench.py "$EP" test:tester azure-swift-2026.bench 4 64 6000 4096
done
set_workers 2; restart_obj   # leave SAIO at its baseline
echo SAIO-WORKER-AB-DONE
