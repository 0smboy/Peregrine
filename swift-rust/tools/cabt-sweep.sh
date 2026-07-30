#!/bin/bash
# Bounded cabt automation sweep against the cluster via a HAProxy address
# (ST_ENDPOINT avoids the ILB hairpin). Runs a size x op matrix, then exercises
# cabt list + collect. Progress bars are dropped; stage summaries kept.
set -u
export ST_AUTH=http://10.42.30.11:8085/auth/v1.0
export ST_USER=test:tester
export ST_KEY=azure-swift-2026.bench
export ST_ENDPOINT=http://10.42.30.11:8085/v1/AUTH_test
CABT=/root/work/cabt-rs/target/release/cabt
LOG=/root/work/cabt-sweep.log
: > "$LOG"

run() { # <task> <objcount> <containers> <runtime>
  echo "=== TASK $1 (obj=$2 cont=$3 rt=$4) ===" | tee -a "$LOG"
  "$CABT" run "$1" --object-count "$2" --container-count "$3" --runtime "$4" 2>&1 \
    | tr '\r' '\n' | grep -E "stage finished|finished! wid|Error|fail=" \
    | grep -vE "^\s*write:|^\s*read:" | tee -a "$LOG"
}

run 4KB_write_128  4000 4 20
run 4KB_read_128   4000 4 20
run 1MB_write_32   500  4 20
run 1MB_read_32    500  4 20
run 16MB_write_8   100  4 20
run 16MB_read_8    100  4 20

echo "=== cabt list ===" | tee -a "$LOG"
"$CABT" list 2>&1 | tail -20 | tee -a "$LOG"
echo "=== cabt collect ===" | tee -a "$LOG"
"$CABT" collect 2>&1 | tail -20 | tee -a "$LOG"
echo "CABT-SWEEP-DONE" | tee -a "$LOG"
