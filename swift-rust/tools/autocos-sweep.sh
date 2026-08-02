#!/bin/bash
# Bounded autocos automation sweep against the cluster via a HAProxy address
# (ST_ENDPOINT avoids the ILB hairpin). Runs a size x op matrix, then exercises
# autocos list + collect. Progress bars are dropped; stage summaries kept.
#
# Client tuning (required for 128-worker 4KB write→read):
#   - ulimit -n >= 65535 (default 1024 + TIME_WAIT storm → connect fails)
#   - Contabo: prefer Keepalived VIP 10.0.0.10:8085 (override ST_* as needed)
# Host sysctl (persistent on load node): /etc/sysctl.d/99-swift-bench.conf
#   ip_local_port_range=1024 65535, tcp_tw_reuse=1, tcp_fin_timeout=15
set -u
ulimit -n 65535 2>/dev/null || true
export ST_AUTH=${ST_AUTH:-http://10.0.0.10:8085/auth/v1.0}
export ST_USER=${ST_USER:-test:tester}
export ST_KEY=${ST_KEY:-azure-swift-2026.bench}
export ST_ENDPOINT=${ST_ENDPOINT:-http://10.0.0.10:8085/v1/AUTH_test}
AUTOCOS=${AUTOCOS:-/usr/local/bin/autocos}
if [[ ! -x "$AUTOCOS" ]]; then
  AUTOCOS=/root/work/autocos-rs/target/release/autocos
fi
LOG=${LOG:-/root/work/autocos-sweep.log}
: > "$LOG"
echo "CLIENT ulimit -n=$(ulimit -n) ST_ENDPOINT=$ST_ENDPOINT AUTOCOS=$AUTOCOS" | tee -a "$LOG"

run() { # <task> <objcount> <containers> <runtime>
  echo "=== TASK $1 (obj=$2 cont=$3 rt=$4) ===" | tee -a "$LOG"
  "$AUTOCOS" run "$1" --object-count "$2" --container-count "$3" --runtime "$4" 2>&1 \
    | tr '\r' '\n' | grep -E "stage finished|finished! wid|Error|fail=" \
    | grep -vE "^\s*write:|^\s*read:" | tee -a "$LOG"
}

run 4KB_write_128  4000 4 20
run 4KB_read_128   4000 4 20
run 1MB_write_32   500  4 20
run 1MB_read_32    500  4 20
run 16MB_write_8   100  4 20
run 16MB_read_8    100  4 20

echo "=== autocos list ===" | tee -a "$LOG"
"$AUTOCOS" list 2>&1 | tail -20 | tee -a "$LOG"
echo "=== autocos collect ===" | tee -a "$LOG"
"$AUTOCOS" collect 2>&1 | tail -20 | tee -a "$LOG"
echo "AUTOCOS-SWEEP-DONE" | tee -a "$LOG"
