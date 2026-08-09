#!/bin/bash
# Diagnose the haproxy -> backend-proxy hang after redeploy.
set -u
source "$(dirname "$0")/lib/lab-auth.sh"
peregrine_load_lab_auth || exit $?
echo "### haproxy per-server: name status check econ eresp qcur wredis"
curl -s -m8 "http://127.0.0.1:8404/;csv" 2>/dev/null \
  | awk -F, '$1=="swift_proxy_back"{printf "  %-8s status=%-6s check=%-8s econ=%s eresp=%s qcur=%s\n",$2,$18,$37,$36,$41,$3}'

echo "### keep-alive reuse (2 requests on ONE connection) to each proxy"
for n in 11 12 13 14; do
  out=$(curl -s -m8 -o /dev/null -w 'r1=%{http_code} ' "http://10.42.30.$n:8080/healthcheck" \
        --next -s -m8 -o /dev/null -w 'r2=%{http_code} ' -H "X-Auth-User: $ST_USER" -H "X-Auth-Key: $ST_KEY" "http://10.42.30.$n:8080/auth/v1.0" \
        --next -s -m8 -o /dev/null -w 'r3=%{http_code}\n' "http://10.42.30.$n:8080/healthcheck")
  printf "  proxy .%s  %s\n" "$n" "$out"
done

echo "### proxy conf (workers / keepalive)"
grep -iE "workers|keep|max_requests|pipeline|bind_port" /etc/swift/proxy-server.conf | head

echo "### haproxy recent termination-state codes"
journalctl -u haproxy --since "-3 min" --no-pager 2>/dev/null | grep -oE " [A-Za-z-]{2}-- " | sort | uniq -c | tail
