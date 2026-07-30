#!/bin/bash
# Confirm the exact EC fragment deleted in the heal test came back.
set -u
K="-i /etc/swift/replication_key -o BatchMode=yes -o ConnectTimeout=8"
HASHDIR="55/ad6/0dc9c39a8b4fa2fecff67fdd097a3ad6"
echo "fragments now present for object hash 0dc9c39a... (deleted #2 should be back):"
for n in 11 12 13 14; do
  ssh -n $K root@10.42.10.$n "find /srv/node/*/objects-1/$HASHDIR -name '*d.data' 2>/dev/null" 2>/dev/null \
    | sed "s#^#  swift.$n  #"
done
