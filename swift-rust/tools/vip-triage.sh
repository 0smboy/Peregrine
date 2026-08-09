#!/bin/bash
# Steady-state VIP reliability + capture the haproxy log lines for failures.
set -u
source "$(dirname "$0")/lib/lab-auth.sh"
peregrine_load_lab_auth || exit $?
VIP=${VIP:-http://10.0.0.10:8085}
N=${1:-100}
ok=0; bad=0; badcodes=""
t0=$(date +%s)
for i in $(seq 1 "$N"); do
  c=$(curl -s -m6 -o /dev/null -w '%{http_code}' -H "X-Auth-User: $ST_USER" -H "X-Auth-Key: $ST_KEY" "$VIP/auth/v1.0")
  if [ "$c" = 200 ]; then ok=$((ok+1)); else bad=$((bad+1)); badcodes="$badcodes $c"; fi
done
t1=$(date +%s)
echo "VIP auth over $N: ok=$ok bad=$bad  (elapsed $((t1-t0))s)  badcodes:$badcodes"
echo "### haproxy log: recent non-2xx / timeout terminations on the proxy backend"
journalctl -u haproxy --since "-2 min" --no-pager 2>/dev/null \
  | grep -E "swift_proxy_back|8085" \
  | grep -vE " 200 | 204 | 201 | 304 | 412 " \
  | tail -8
