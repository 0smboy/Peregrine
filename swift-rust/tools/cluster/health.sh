#!/bin/bash
# One screen an operator can trust. Anything this cannot determine is printed
# as UNKNOWN — a check that silently scores a failed probe as "fine" is worse
# than no check, which is the lesson the two scripts beside this one taught.
#
# usage: health.sh [endpoint]     default: a direct node, never the ILB VIP
set -u
EP=${1:-http://10.42.30.11:8085}
K="-i /etc/swift/replication_key -o BatchMode=yes -o ConnectTimeout=10"
on() { # on <lastoctet> <cmd>
  if [ "$1" = 11 ]; then bash -c "$2" 2>/dev/null
  else ssh -n $K root@10.42.10.$1 "$2" 2>/dev/null; fi
}
val() { [ -n "$1" ] && echo "$1" || echo "UNKNOWN"; }

echo "SERVICES"
for n in 11 12 13 14; do
  down=$(on $n 'systemctl list-units --no-legend --plain --state=failed 2>/dev/null | grep -cE "swift-|haproxy"')
  run=$(on $n 'systemctl list-units --no-legend --plain --state=running 2>/dev/null | grep -cE "^(swift-|haproxy)"')
  printf "  swift.%s  running=%-8s failed=%s\n" "$n" "$(val "$run")" "$(val "$down")"
done

echo "LOAD BALANCER"
for n in 11 12 13 14; do
  hp=$(curl -s -m5 -o /dev/null -w '%{http_code}' "http://10.42.30.$n:8085/healthcheck" 2>/dev/null)
  px=$(curl -s -m5 -o /dev/null -w '%{http_code}' "http://10.42.30.$n:8080/healthcheck" 2>/dev/null)
  printf "  10.42.30.%s  haproxy=%-8s proxy=%s\n" "$n" "$(val "$hp")" "$(val "$px")"
done
be=$(curl -s -m8 "http://127.0.0.1:8404/;csv" 2>/dev/null | awk -F, '$1=="swift_proxy_back" && $2!="BACKEND"{printf "%s=%s ", $2, $18}')
printf "  backends   %s\n" "$(val "$be")"

echo "RINGS"
for r in account container object object-1; do
  d=$(python3 -c "import json;print(len(json.load(open('/etc/swift/$r.ring.gz.builder.json'))['devices']))" 2>/dev/null)
  printf "  %-10s %s devices\n" "$r" "$(val "$d")"
done

echo "CAPACITY (used MiB per device)"
for n in 11 12 13 14; do
  u=$(on $n 'for d in d1 d2 d3; do printf "%s:%s " "$d" "$(( $(df -B1 --output=used /srv/node/$d 2>/dev/null | tail -1) / 1048576 ))"; done')
  printf "  swift.%s  %s\n" "$n" "$(val "$u")"
done

echo "REPLICATION DAEMONS (latest pass)"
for n in 11 12 13 14; do
  rp=$(on $n 'journalctl -u swift-object-replicator --since "-10 min" --no-pager 2>/dev/null | grep "pass:" | tail -1 | sed "s/.*pass: //"')
  rc=$(on $n 'journalctl -u swift-object-reconstructor --since "-10 min" --no-pager 2>/dev/null | grep "pass:" | tail -1 | sed "s/.*pass: //"')
  cu=$(on $n 'journalctl -u swift-container-updater --since "-10 min" --no-pager 2>/dev/null | grep "pass:" | tail -1 | sed "s/.*pass: //"')
  printf "  swift.%s\n    repl   %s\n    recon  %s\n    cupd   %s\n" "$n" "$(val "$rp")" "$(val "$rc")" "$(val "$cu")"
done

echo "ACCOUNTING (account rollup vs container truth)"
source "$(dirname "$0")/../lib/lab-auth.sh"
if ! peregrine_load_lab_auth; then
  echo "  UNKNOWN (lab credential unavailable)"
  TOK=""
else
  TOK=$(curl -si -m15 -H "X-Auth-User: $ST_USER" -H "X-Auth-Key: $ST_KEY" "$EP/auth/v1.0" 2>/dev/null | tr -d '\r' | awk 'tolower($1)=="x-auth-token:"{print $2}')
fi
if [ -z "$TOK" ]; then
  echo "  UNKNOWN (auth failed against $EP)"
else
  acct=$(curl -sI -m20 -H "X-Auth-Token: $TOK" "$EP/v1/AUTH_test" 2>/dev/null | tr -d '\r' \
          | awk 'tolower($1)=="x-account-object-count:"{o=$2} tolower($1)=="x-account-bytes-used:"{b=$2} END{print o" objects / "b" bytes"}')
  printf "  account says      %s\n" "$(val "$acct")"
fi

echo "DATA INTEGRITY"
if [ -x /root/expand/readcheck.sh ]; then /root/expand/readcheck.sh "$EP" | sed 's/^/  /'
else echo "  UNKNOWN (readcheck.sh not installed)"; fi
