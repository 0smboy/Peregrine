#!/bin/bash
# Lab/chaos: EC (2+1) fragment loss -> degraded read -> reconstructor heal.
# Runs on swift1; reaches peers via the replication key.
#
# Usage:
#   ec-heal-test.sh [EP] [user] [key]
# Defaults: Contabo VIP http://10.0.0.10:8085 ; nodes 10.0.0.1–4
set -u
EP=${1:-http://10.0.0.10:8085}
USR=${2:-test:tester}
KEY=${3:-azure-swift-2026.bench}
# Contabo storage/proxy plane node addresses (override with NODES="1 2 3 4" + NODE_FMT)
NODE_FMT=${NODE_FMT:-10.0.0.%s}
NODES=${NODES:-1 2 3 4}
K="-i /etc/swift/replication_key -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10"
C=ec-heal-$RANDOM
OBJ=heal-obj

node_host() { printf "$NODE_FMT" "$1"; }

TOK=$(curl -s -m10 -D - -o /dev/null -H "X-Auth-User: $USR" -H "X-Auth-Key: $KEY" "$EP/auth/v1.0" | awk 'tolower($1)=="x-auth-token:"{print $2}' | tr -d '\r')
if [ -z "$TOK" ]; then echo "FATAL: auth failed against $EP"; exit 3; fi
B="$EP/v1/AUTH_test"

echo "### create EC container + 4MB object (EP=$EP)"
curl -s -m10 -X PUT -H "X-Auth-Token: $TOK" -H "X-Storage-Policy: ec-2-1" "$B/$C" >/dev/null
dd if=/dev/urandom of=/tmp/ecsrc bs=1M count=4 status=none
SRC=$(md5sum /tmp/ecsrc | cut -d' ' -f1); echo "  src md5=$SRC"
curl -s -m30 -X PUT -H "X-Auth-Token: $TOK" --data-binary @/tmp/ecsrc "$B/$C/$OBJ" >/dev/null
G0=$(curl -s -m30 -H "X-Auth-Token: $TOK" "$B/$C/$OBJ" | md5sum | cut -d' ' -f1)
echo "  baseline GET md5=$G0  match=$([ "$G0" = "$SRC" ] && echo YES || echo NO)"

echo "### locate fragments (swift-get-nodes)"
NODES_LINE=$(SWIFT_DIR=/etc/swift /usr/local/bin/swift-get-nodes /etc/swift/object-1.ring.gz AUTH_test "$C" "$OBJ" 2>/dev/null | grep -oE "ssh [0-9.]+ .*objects-1/[0-9]+" | head)
PART=$(printf '%s' "$NODES_LINE" | grep -oE "objects-1/[0-9]+" | head -1 | cut -d/ -f2)
echo "  partition=$PART"

frags() { # count fragment .data files for this partition across all nodes
  local total=0 n c
  for n in $NODES; do
    c=$(ssh -n $K "root@$(node_host "$n")" "find /srv/node/*/objects-1/$PART -name '*#*#d.data' 2>/dev/null | wc -l" 2>/dev/null)
    total=$((total + ${c:-0}))
  done
  echo "$total"
}
echo "  fragments present now: $(frags)  (expect 3 for EC 2+1)"

echo "### CHAOS: delete one fragment"
DELDONE=0
for n in $NODES; do
  f=$(ssh -n $K "root@$(node_host "$n")" "find /srv/node/*/objects-1/$PART -name '*#*#d.data' 2>/dev/null | head -1" 2>/dev/null)
  if [ -n "$f" ] && [ "$DELDONE" = 0 ]; then
    ssh -n $K "root@$(node_host "$n")" "rm -f '$f'" 2>/dev/null
    echo "  deleted on $(node_host "$n"): ${f##*/objects-1/}"
    DELDONE=1
  fi
done
echo "  fragments after delete: $(frags)  (expect 2)"

echo "### degraded read (EC 2+1 tolerates losing 1 fragment)"
G1=$(curl -s -m30 -H "X-Auth-Token: $TOK" "$B/$C/$OBJ" | md5sum | cut -d' ' -f1)
echo "  degraded GET md5=$G1  match=$([ "$G1" = "$SRC" ] && echo YES || echo NO)"

echo "### heal: run the reconstructor on all nodes, then re-count"
for n in $NODES; do
  ssh -n $K "root@$(node_host "$n")" "systemctl restart swift-object-reconstructor" 2>/dev/null
done
for w in 1 2 3 4 5 6; do
  sleep 15
  c=$(frags)
  echo "  +$((w*15))s fragments: $c"
  [ "$c" -ge 3 ] && break
done

echo "### post-heal read"
G2=$(curl -s -m30 -H "X-Auth-Token: $TOK" "$B/$C/$OBJ" | md5sum | cut -d' ' -f1)
echo "  post-heal GET md5=$G2  match=$([ "$G2" = "$SRC" ] && echo YES || echo NO)"

echo "### cleanup"
curl -s -X DELETE -H "X-Auth-Token: $TOK" "$B/$C/$OBJ" >/dev/null
curl -s -X DELETE -H "X-Auth-Token: $TOK" "$B/$C" >/dev/null
echo EC-HEAL-DONE match_baseline=$([ "$G0" = "$SRC" ] && echo YES || echo NO) match_degraded=$([ "$G1" = "$SRC" ] && echo YES || echo NO) match_healed=$([ "$G2" = "$SRC" ] && echo YES || echo NO)
