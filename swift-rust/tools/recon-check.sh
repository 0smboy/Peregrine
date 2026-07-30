#!/bin/bash
# Did the redeploy clear the part-871 reconstructor revert loop?
set -u
K="-i /etc/swift/replication_key -o BatchMode=yes -o ConnectTimeout=8"
echo "### reconstructor last pass per node (since deploy)"
for n in 11 12 13 14; do
  printf "  swift.%s  " "$n"
  ssh -n $K root@10.42.10.$n "journalctl -u swift-object-reconstructor --since '-5 min' --no-pager 2>/dev/null | grep 'pass:' | tail -1 | sed 's/.*pass: //'" 2>&1
done
echo "### part-871 revert errors in the last 5 min (0 == cleared)"
n871=0
for n in 11 12 13 14; do
  c=$(ssh -n $K root@10.42.10.$n "journalctl -u swift-object-reconstructor --since '-5 min' --no-pager 2>/dev/null | grep -c 'revert part 871'" 2>/dev/null)
  echo "  swift.$n: $c"
  n871=$((n871 + ${c:-0}))
done
echo "TOTAL part-871 revert errors (5 min): $n871"
