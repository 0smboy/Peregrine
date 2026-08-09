#!/bin/bash
# Re-run the write tasks after raising object workers, to quantify the gain.
set -u
source "$(dirname "$0")/lib/lab-auth.sh"
peregrine_load_lab_auth || exit $?
export ST_AUTH=http://10.42.30.11:8085/auth/v1.0
export ST_ENDPOINT=http://10.42.30.11:8085/v1/AUTH_test
AUTOCOS=/root/work/autocos/target/release/autocos
run() {
  echo "=== $1 ==="
  "$AUTOCOS" run "$1" --object-count "$2" --container-count 4 --runtime 20 2>&1 \
    | tr '\r' '\n' | grep -E "stage=normal" | grep "finished"
}
run 4KB_write_128  4000
run 1MB_write_32   500
run 16MB_write_8   100
echo OPT-VERIFY-DONE
