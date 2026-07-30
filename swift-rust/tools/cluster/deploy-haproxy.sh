#!/bin/bash
# Put the identical haproxy config on every node and start it there, so the API
# endpoint stops being a property of swift1.
set -e
K="-i /etc/swift/replication_key -o BatchMode=yes -o ConnectTimeout=15"
CFG=/root/haproxy.cfg.new

apply() {  # runs locally on whichever node
  install -m 0644 /root/haproxy.cfg.new /etc/haproxy/haproxy.cfg
  restorecon -F /etc/haproxy/haproxy.cfg 2>/dev/null || true
  setsebool -P haproxy_connect_any 1 2>/dev/null || true
  grep -q ip_nonlocal_bind /etc/sysctl.d/99-haproxy.conf 2>/dev/null || \
    echo 'net.ipv4.ip_nonlocal_bind = 1' > /etc/sysctl.d/99-haproxy.conf
  sysctl -q -p /etc/sysctl.d/99-haproxy.conf 2>/dev/null || true
  haproxy -c -f /etc/haproxy/haproxy.cfg >/dev/null
  systemctl enable -q haproxy 2>/dev/null || true
  systemctl restart haproxy
  sleep 1
  printf "  %-8s haproxy=%s  cfg=%s  nonlocal_bind=%s  sebool=%s\n" \
    "$(hostname)" "$(systemctl is-active haproxy)" \
    "$(sha256sum /etc/haproxy/haproxy.cfg | cut -c1-12)" \
    "$(sysctl -n net.ipv4.ip_nonlocal_bind)" \
    "$(getsebool haproxy_connect_any | awk '{print $3}')"
}

if [ "$1" = "--local" ]; then apply; exit 0; fi

# swift1 first, then push the same file and script everywhere else.
cp /root/haproxy.cfg.new /root/haproxy.cfg.new
apply
for n in 12 13 14; do
  scp -q $K /root/haproxy.cfg.new root@10.42.10.$n:/root/haproxy.cfg.new
  scp -q $K "$0" root@10.42.10.$n:/root/deploy-lb.sh
  ssh -n $K root@10.42.10.$n "bash /root/deploy-lb.sh --local"
done
