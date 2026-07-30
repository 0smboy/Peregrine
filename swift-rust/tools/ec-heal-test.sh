#!/bin/bash
# Lab/chaos: EC (2+1) fragment loss -> degraded read -> reconstructor heal.
# Runs on swift1; reaches peers via the replication key. Uses a HAProxy address
# (no ILB hairpin).
set -u
EP=http://10.42.30.11:8085
K="-i /etc/swift/replication_key -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10"
C=ec-heal-$RANDOM
OBJ=heal-obj

TOK=$(curl -s -m10 -D - -o /dev/null -H "X-Auth-User: test:tester" -H "X-Auth-Key: azure-swift-2026.bench" "$EP/auth/v1.0" | awk 'tolower($1)=="x-auth-token:"{print $2}' | tr -d '\r')
B="$EP/v1/AUTH_test"

echo "### create EC container + 4MB object"
curl -s -m10 -X PUT -H "X-Auth-Token: $TOK" -H "X-Storage-Policy: ec-2-1" "$B/$C" >/dev/null
dd if=/dev/urandom of=/tmp/ecsrc bs=1M count=4 status=none
SRC=$(md5sum /tmp/ecsrc | cut -d' ' -f1); echo "  src md5=$SRC"
curl -s -m30 -X PUT -H "X-Auth-Token: $TOK" --data-binary @/tmp/ecsrc "$B/$C/$OBJ" >/dev/null
G0=$(curl -s -m30 -H "X-Auth-Token: $TOK" "$B/$C/$OBJ" | md5sum | cut -d' ' -f1)
echo "  baseline GET md5=$G0  match=$([ "$G0" = "$SRC" ] && echo YES || echo NO)"

echo "### locate fragments (swift-get-nodes)"
NODES=$(SWIFT_DIR=/etc/swift /usr/local/bin/swift-get-nodes /etc/swift/object-1.ring.gz AUTH_test "$C" "$OBJ" 2>/dev/null | grep -oE "ssh [0-9.]+ .*objects-1/[0-9]+" | head)
PART=$(printf '%s' "$NODES" | grep -oE "objects-1/[0-9]+" | head -1 | cut -d/ -f2)
echo "  partition=$PART"

frags() { # count fragment .data files for this partition across all nodes
  local total=0
  for n in 11 12 13 14; do
    c=$(ssh -n $K root@10.42.10.$n "find /srv/node/*/objects-1/$PART -name '*#*#d.data' 2>/dev/null | wc -l" 2>/dev/null)
    total=$((total + ${c:-0}))
  done
  echo "$total"
}
echo "  fragments present now: $(frags)  (expect 3 for EC 2+1)"

echo "### CHAOS: delete one fragment"
DELDONE=0
for n in 11 12 13 14; do
  f=$(ssh -n $K root@10.42.10.$n "find /srv/node/*/objects-1/$PART -name '*#*#d.data' 2>/dev/null | head -1" 2>/dev/null)
  if [ -n "$f" ] && [ "$DELDONE" = 0 ]; then
    ssh -n $K root@10.42.10.$n "rm -f '$f'" 2>/dev/null
    echo "  deleted on swift.$n: ${f##*/objects-1/}"
    DELDONE=1
  fi
done
echo "  fragments after delete: $(frags)  (expect 2)"

echo "### degraded read (EC 2+1 tolerates losing 1 fragment)"
G1=$(curl -s -m30 -H "X-Auth-Token: $TOK" "$B/$C/$OBJ" | md5sum | cut -d' ' -f1)
echo "  degraded GET md5=$G1  match=$([ "$G1" = "$SRC" ] && echo YES || echo NO)"

echo "### heal: run the reconstructor on all nodes, then re-count"
for n in 11 12 13 14; do
  ssh -n $K root@10.42.10.$n "systemctl restart swift-object-reconstructor" 2>/dev/null
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
rm -f /tmp/ecsrc
echo "EC-HEAL-TEST-DONE"
