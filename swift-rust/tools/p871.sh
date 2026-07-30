#!/bin/bash
# Capture the exact failure for the part-871 reconstructor revert loop.
set -u
K="-i /etc/swift/replication_key -o BatchMode=yes -o ConnectTimeout=8"
echo "### swift4 object-server errors around SSYNC/DELETE on part 871"
ssh -n $K root@10.42.10.14 "journalctl -u swift-object.service --since '-3 min' --no-pager 2>/dev/null | grep -iE '871|ssync|:ERROR:|UPDATES|500' | tail -12" 2>&1
echo "### what fragments actually exist for part 871 policy-1 across nodes"
for n in 11 12 13 14; do
  echo "  swift.$n:"
  ssh -n $K root@10.42.10.$n "find /srv/node/*/objects-1/871 -name '*.data' -o -name '*.ts' 2>/dev/null | sed 's#/srv/node/#    #' | head" 2>&1
done
