#!/bin/bash
# Locate the write bottleneck by resource saturation: run a sustained 4KB write
# load and sample disk %util and per-service CPU on a backend node (swift2) and
# the proxy/load node (swift1).
set -u
source "$(dirname "$0")/lib/lab-auth.sh"
peregrine_load_lab_auth || exit $?
K="-i /etc/swift/replication_key -o BatchMode=yes -o ConnectTimeout=8"
echo "### starting sustained 4KB write load (4 containers, conc 64, 30000 objs)"
source /root/work/pyswift-venv/bin/activate
nohup python /root/work/cbench.py http://10.42.30.11:8085 "$ST_USER" "$ST_KEY" 4 64 30000 >/root/work/sat-load.log 2>&1 &
LOAD=$!
sleep 4

sample(){ # <node-octet> <label>
  local n=$1 lbl=$2
  echo "### $lbl (10.42.10.$n) — disk %util + top swift procs"
  ssh -n $K root@10.42.10.$n "
    command -v iostat >/dev/null 2>&1 && iostat -x 1 2 | awk '/^(nvme|sd)/{print \"  disk \"\$1\" util%=\"\$NF}' | tail -6 || echo '  (no iostat)'
    echo '  --- top swift processes (%CPU) ---'
    top -bn1 | awk 'NR>7 && /swift-/{printf \"  %5s%%  %s\n\", \$9, \$12}' | sort -rn | head -6
    echo -n '  loadavg: '; cat /proc/loadavg | cut -d' ' -f1-3
  " 2>&1
}
sample 12 "BACKEND swift2"
sample 11 "PROXY+LOAD swift1"
wait $LOAD 2>/dev/null
echo "### load result:"; tail -1 /root/work/sat-load.log
echo LOCATE-SAT-DONE
