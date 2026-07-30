#!/usr/bin/env bash
# Demonstrate EC self-healing: PUT an erasure-coded object (6 durable
# fragments), delete ONE node's fragment and invalidate its suffix hash,
# then run the reconstructor once on the partner nodes. A partner spots
# the gap via a REPLICATE hash comparison, rebuilds the missing fragment
# from the erasure code, and ssyncs it back — restoring the fragment
# byte-for-byte. Assumes the cluster is running (see bootstrap.sh).
set -u
BINDIR=/usr/local/bin
SWIFT_DIR=/etc/swift
export SWIFT_DIR SWIFT_CONF="$SWIFT_DIR/swift.conf"
AUTH=http://127.0.0.1:8080/auth/v1.0

H=$(curl -s -i -H 'X-Auth-User: test:tester' -H 'X-Auth-Key: testing' "$AUTH")
TOK=$(echo "$H" | grep -i '^X-Auth-Token:'  | tr -d '\r' | awk '{print $2}')
URL=$(echo "$H" | grep -i '^X-Storage-Url:' | tr -d '\r' | awk '{print $2}')
[ -n "$TOK" ] || { echo "auth failed — is the cluster up?"; exit 1; }

echo "== PUT an EC object =="
curl -s -X PUT "$URL/healbox" -H "X-Auth-Token: $TOK" -H 'X-Storage-Policy: EC-4-2' -o /dev/null
head -c 3145728 /dev/urandom > /tmp/heal.obj
MD5=$(md5sum /tmp/heal.obj | awk '{print $1}')
curl -s -X PUT "$URL/healbox/victim.obj" -H "X-Auth-Token: $TOK" -T /tmp/heal.obj \
  -o /dev/null -w 'PUT=%{http_code}\n'

VICTIM=$(find /srv/node* -path '*objects-1*' -name '*#d.data' | sort | head -1)
[ -n "$VICTIM" ] || { echo "no EC fragment found"; exit 1; }
VNAME=$(basename "$VICTIM")
VHASH=$(basename "$(dirname "$VICTIM")")
VPART=$(dirname "$(dirname "$(dirname "$VICTIM")")")
echo "== delete one fragment + invalidate its suffix hash =="
echo "   $VICTIM"
rm -f "$VICTIM"
rm -f "$VPART/hashes.pkl" "$VPART/hashes.invalid"   # the auditor would do this on a real fault
echo "   fragments remaining for this object: $(find /srv/node* -path "*objects-1*/$VHASH/*" -name '*#d.data' | wc -l)/6"

echo "== run the reconstructor once on every node =="
for N in 1 2 3 4; do
  "$BINDIR/swift-object-reconstructor" "$SWIFT_DIR/object-server/$N.conf" once 2>&1 | tail -1
done

echo "== verify =="
BACK=$(find /srv/node* -path '*objects-1*' -name "$VNAME" | head -1)
TOTAL=$(find /srv/node* -path "*objects-1*/$VHASH/*" -name '*#d.data' | wc -l)
echo "   restored fragment: ${BACK:-NONE}  (object durable fragments: $TOTAL/6)"
curl -s "$URL/healbox/victim.obj" -H "X-Auth-Token: $TOK" -o /tmp/heal.down -w 'GET=%{http_code}\n'
MD5D=$(md5sum /tmp/heal.down | awk '{print $1}')
rm -f /tmp/heal.obj /tmp/heal.down
if [ -n "$BACK" ] && [ "$TOTAL" = 6 ] && [ "$MD5" = "$MD5D" ]; then
  printf '\033[1;32mEC-HEAL: PASS\033[0m (fragment rebuilt from the erasure code and pushed back)\n'
else
  printf '\033[1;31mEC-HEAL: FAIL\033[0m (md5 %s)\n' "$([ "$MD5" = "$MD5D" ] && echo match || echo MISMATCH)"
fi
