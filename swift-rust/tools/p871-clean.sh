#!/bin/bash
# Reconcile part-871 by hand: object hash d9d3...7e4 has stale EC data fragments
# (ts 1785382956.31524) that are superseded by NEWER tombstones (1785382978.23456)
# on other devices — the object is deleted. Remove only those stale .data
# fragments (keep the .ts tombstones, and never touch the live fb4 object).
set -u
K="-i /etc/swift/replication_key -o BatchMode=yes -o ConnectTimeout=8"
HASHDIR="7e4/d9d3b248bd9194ca70365865437767e4"

echo "### before: 7e4 files across the cluster"
for n in 11 12 13 14; do
  ssh -n $K root@10.42.10.$n "find /srv/node/*/objects-1/871/$HASHDIR -type f 2>/dev/null" 2>/dev/null | sed "s#^#  swift.$n  #"
done

echo "### remove stale 7e4 DATA fragments (keep tombstones)"
for n in 11 12 13 14; do
  ssh -n $K root@10.42.10.$n "find /srv/node/*/objects-1/871/$HASHDIR -name '*#*#d.data' -delete 2>/dev/null; echo removed-on-swift.$n" 2>/dev/null
done

echo "### kick reconstructors, watch part-871 errors clear"
for n in 11 12 13 14; do ssh -n $K root@10.42.10.$n "systemctl restart swift-object-reconstructor" 2>/dev/null; done
for w in 1 2 3 4 5 6; do
  sleep 20
  errs=0
  for n in 11 12 13 14; do
    c=$(ssh -n $K root@10.42.10.$n "journalctl -u swift-object-reconstructor --since '-40 sec' --no-pager 2>/dev/null | grep -c 'revert part 871'" 2>/dev/null)
    errs=$((errs + ${c:-0}))
  done
  echo "  +$((w*20))s  part-871 revert errors(last 40s)=$errs"
  [ "$errs" = 0 ] && { echo "CLEARED"; break; }
done
echo "### after: 7e4 files remaining (should be only tombstones, or none)"
for n in 11 12 13 14; do
  ssh -n $K root@10.42.10.$n "find /srv/node/*/objects-1/871/$HASHDIR -type f 2>/dev/null" 2>/dev/null | sed "s#^#  swift.$n  #"
done
echo P871-CLEAN-DONE
