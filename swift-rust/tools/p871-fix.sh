#!/bin/bash
# Clear the part-871 reconstructor loop: object prodtest-ec-2-1/expiring is
# deleted but left stale EC data fragments alongside newer tombstones on
# different devices. A fresh DELETE places newest-timestamp tombstones on all
# nodes, superseding the stale data everywhere; the reconstructor then stops
# trying to revert a tombstoned partition.
set -u
EP=http://10.42.30.11:8085
K="-i /etc/swift/replication_key -o BatchMode=yes -o ConnectTimeout=8"
TOK=$(curl -s -m10 -D - -o /dev/null -H "X-Auth-User: test:tester" -H "X-Auth-Key: azure-swift-2026.bench" "$EP/auth/v1.0" | awk 'tolower($1)=="x-auth-token:"{print $2}' | tr -d '\r')
B="$EP/v1/AUTH_test"

echo "### container listing (find the deleted/debris object)"
curl -s -m10 -H "X-Auth-Token: $TOK" "$B/prodtest-ec-2-1?format=json" | head -c 800; echo

echo "### fresh DELETE of prodtest-ec-2-1/expiring (places newest tombstones)"
curl -s -m15 -o /dev/null -w "  DELETE code=%{http_code}\n" -X DELETE -H "X-Auth-Token: $TOK" "$B/prodtest-ec-2-1/expiring"

echo "### kick reconstructors on all nodes"
for n in 11 12 13 14; do ssh -n $K root@10.42.10.$n "systemctl restart swift-object-reconstructor swift-object-replicator" 2>/dev/null; done

echo "### wait 2 passes, then check part-871 revert errors + 7e4 fragments"
for w in 1 2 3 4 5; do
  sleep 20
  errs=0
  for n in 11 12 13 14; do
    c=$(ssh -n $K root@10.42.10.$n "journalctl -u swift-object-reconstructor --since '-40 sec' --no-pager 2>/dev/null | grep -c 'revert part 871'" 2>/dev/null)
    errs=$((errs + ${c:-0}))
  done
  frags=0
  for n in 11 12 13 14; do
    c=$(ssh -n $K root@10.42.10.$n "find /srv/node/*/objects-1/871 -name '*7e4*' -prune -o -name '*d9d3b248*' -print 2>/dev/null | wc -l" 2>/dev/null)
    frags=$((frags + ${c:-0}))
  done
  echo "  +$((w*20))s  part-871 revert errors(last 40s)=$errs  stale-7e4-datafiles=$frags"
  [ "$errs" = 0 ] && break
done
echo "P871-FIX-DONE"
