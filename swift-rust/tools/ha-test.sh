#!/bin/bash
# High-availability drill DRIVEN THROUGH swift-console's node-down feature:
# take swift2 down via /lab/api/node/down, verify reads/writes survive on the
# survivors, then bring it back via /lab/api/node/up. Runs on swift1.
#
# Usage (optional overrides):
#   ha-test.sh [LB_BASE] [user] [key]
# Defaults: Contabo VIP http://10.0.0.10:8085
set -u
source "$(dirname "$0")/lib/lab-auth.sh"
CON=${CON:-http://127.0.0.1:9000}
LB=${1:-http://10.0.0.10:8085}
USR=${2:-test:tester}
if [[ -z "${3:-}" ]]; then peregrine_load_lab_auth || exit $?; fi
KEY=${3:-$ST_KEY}
DOWN_NODE=${DOWN_NODE:-swift2}
J=/tmp/ha.jar; rm -f "$J"

# --- console session ---
curl -s -m15 -c "$J" -o /dev/null -X POST -d "tenant=test&user=tester&key=$KEY" "$CON/login"
capi(){ curl -s -m30 -b "$J" "$@"; }

# --- swift workload helpers (via HAProxy/VIP, tempauth) ---
B="$LB/v1/AUTH_test"
# Fresh token: real clients re-auth on 401, and tempauth tokens cached on a
# downed node's memcached go invalid, so each phase re-authenticates.
auth(){ curl -s -m10 -D - -o /dev/null -H "X-Auth-User: $USR" -H "X-Auth-Key: $KEY" "$LB/auth/v1.0" | awk 'tolower($1)=="x-auth-token:"{print $2}' | tr -d '\r'; }
TOK=$(auth)
if [ -z "$TOK" ]; then echo "FATAL: auth failed against $LB"; exit 3; fi
rep=ha-rep-$RANDOM ; ec=ha-ec-$RANDOM
curl -s -X PUT -H "X-Auth-Token: $TOK" "$B/$rep" >/dev/null
curl -s -X PUT -H "X-Auth-Token: $TOK" -H "X-Storage-Policy: ec-2-1" "$B/$ec" >/dev/null

# write N objects, read them back; re-auth per phase; tally exact HTTP codes.
workload(){ # <label> <container> <n>
  local label=$1 c=$2 n=$3 i body got tok wcodes="" rcodes="" wok=0 rok=0
  tok=$(auth)   # fresh token for this phase (a client that re-auths)
  for i in $(seq 1 "$n"); do
    body="ha-$label-$i-$RANDOM"
    wc=$(curl -s -m15 -o /dev/null -w '%{http_code}' -X PUT -H "X-Auth-Token: $tok" --data-binary "$body" "$B/$c/o$i")
    wcodes="$wcodes $wc"; [ "$wc" = 201 ] && wok=$((wok+1))
    got=$(curl -s -m15 -w '\n%{http_code}' -H "X-Auth-Token: $tok" "$B/$c/o$i")
    rc=$(printf '%s' "$got" | tail -1)
    rcodes="$rcodes $rc"; [ "$(printf '%s' "$got" | head -1)" = "$body" ] && rok=$((rok+1))
  done
  printf '  %-16s writes ok=%s/%s [%s] | reads ok=%s/%s [%s]\n' "$label" "$wok" "$n" \
    "$(echo $wcodes | tr ' ' '\n' | sort | uniq -c | tr '\n' ' ')" "$rok" "$n" \
    "$(echo $rcodes | tr ' ' '\n' | sort | uniq -c | tr '\n' ' ')"
}

echo "===== BASELINE (all nodes up) LB=$LB ====="
capi "$CON/lab/api/node/status" | grep -o '"up":[a-z]*' | sort | uniq -c | sed 's/^/  /'
workload "repl baseline"  "$rep" 10
workload "ec baseline"    "$ec"  10

echo "===== TAKE $DOWN_NODE DOWN via console ====="
capi -X POST -H 'Content-Type: application/json' -d "{\"node\":\"$DOWN_NODE\",\"ttl_secs\":300}" "$CON/lab/api/node/down"
echo
echo "  waiting 20s for HAProxy to detect the dead proxy (fall 3 x 5s)…"; sleep 20
echo "  node status now:"
capi "$CON/lab/api/node/status" | python3 -c "import sys,json;
d=json.load(sys.stdin)
[print('   ',n['node'],'up' if n['up'] else 'DOWN','held_down' if n['held_down'] else '',n['active_services'],'/',n['total_services']) for n in d['nodes']]" 2>/dev/null

echo "===== WORKLOAD WITH $DOWN_NODE DOWN (HA: survivors must serve) ====="
workload "repl degraded"  "$rep" 20
workload "ec degraded"    "$ec"  20

echo "===== BRING $DOWN_NODE BACK UP via console ====="
capi -X POST -H 'Content-Type: application/json' -d "{\"node\":\"$DOWN_NODE\"}" "$CON/lab/api/node/up"
echo
echo "  waiting 15s for services + HAProxy to recover…"; sleep 15
capi "$CON/lab/api/node/status" | grep -o '"up":[a-z]*' | sort | uniq -c | sed 's/^/  /'
workload "repl recovered" "$rep" 10

echo "===== cleanup ====="
TOK=$(auth)
for c in "$rep" "$ec"; do
  for o in $(curl -s -m15 -H "X-Auth-Token: $TOK" "$B/$c"); do curl -s -X DELETE -H "X-Auth-Token: $TOK" "$B/$c/$o" >/dev/null; done
  curl -s -X DELETE -H "X-Auth-Token: $TOK" "$B/$c" >/dev/null
done
echo HA-TEST-DONE
