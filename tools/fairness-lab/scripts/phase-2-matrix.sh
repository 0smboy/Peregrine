#!/usr/bin/env bash
# Phase-2 Rust-only matrix: VIP vs DIRECT (single entry) — separate tables, no win/lose mix.
# Client: swift1. Disk-safe: modest object_count on large sizes (nodes ~90% full).
set -euo pipefail
source "$(dirname "$0")/../../../swift-rust/tools/lib/lab-auth.sh"
peregrine_load_lab_auth

OUT="${OUT:-/tmp/phase2-20260804}"
USR="$ST_USER"
KEY="$ST_KEY"
RUNTIME_SMALL="${RUNTIME_SMALL:-45}"
RUNTIME_1MB="${RUNTIME_1MB:-45}"
RUNTIME_16MB="${RUNTIME_16MB:-90}"
mkdir -p "$OUT/perf/vip" "$OUT/perf/direct" "$OUT/chaos" "$OUT/soak" "$OUT/logs"

auth_ok() {
  local base=$1
  local code
  code=$(curl -sS -m 10 -o /dev/null -w '%{http_code}' \
    -H "X-Auth-User: $USR" -H "X-Auth-Key: $KEY" "$base/auth/v1.0" || echo 000)
  [[ "$code" == "200" ]]
}

run_cell() {
  local entry=$1 base=$2 task=$3 runtime=$4 oc=$5
  local dir="$OUT/perf/$entry"
  local log="$dir/${task}.log"
  export ST_AUTH="$base/auth/v1.0" ST_USER="$USR" ST_KEY="$KEY"
  export ST_ENDPOINT="$base/v1/AUTH_test"
  echo "=== $(date -u +%H:%M:%SZ) entry=$entry task=$task runtime=$runtime oc=$oc ===" | tee -a "$OUT/logs/runner.log"
  set +e
  autocos run "$task" --object-count "$oc" --container-count 1 --runtime "$runtime" --backend swift \
    >"$log" 2>&1
  local rc=$?
  set -e
  # ANSI-safe parse of normal-stage ok/fail
  local ok_n=0 fail_n=0 success_pct="" ops_per_s="n/a"
  local parsed
  parsed=$(python3 - "$log" "$runtime" <<'PY'
import re, sys
from pathlib import Path
ansi = re.compile(r"\x1b\[[0-9;]*m")
text = ansi.sub("", Path(sys.argv[1]).read_text(errors="replace"))
rt = int(sys.argv[2])
pat = re.compile(r"stage finished.*?stage\s*=\s*(\w+).*?ok\s*=\s*(\d+).*?fail\s*=\s*(\d+).*?success\s*=\s*\"?([0-9.]+%?)\"?", re.I)
normal = last = None
for m in pat.finditer(text):
    last = m
    if m.group(1).lower() == "normal":
        normal = m
m = normal or last
if not m:
    print("0\t1\tPARSE_FAIL\tn/a"); raise SystemExit
ok, fail, suc = int(m.group(2)), int(m.group(3)), m.group(4)
ops = f"{ok/rt:.2f}" if rt > 0 and ok > 0 else "n/a"
print(f"{ok}\t{fail}\t{suc}\t{ops}")
PY
)
  ok_n=$(echo "$parsed" | cut -f1)
  fail_n=$(echo "$parsed" | cut -f2)
  success_pct=$(echo "$parsed" | cut -f3)
  ops_per_s=$(echo "$parsed" | cut -f4)
  if [[ $rc -ne 0 && "$fail_n" == "0" && "$ok_n" == "0" ]]; then fail_n=1; fi
  echo -e "${entry}\t${task}\t${runtime}\t${oc}\t${rc}\t${ok_n}\t${fail_n}\t${ops_per_s}\t${success_pct}" | tee -a "$OUT/perf/matrix.tsv"
  tail -20 "$log" >>"$OUT/logs/runner.log"
  return 0
}

echo -e "entry\ttask\truntime\tobject_count\trc\tok\tfail\tops_per_s\tsuccess" >"$OUT/perf/matrix.tsv"

echo "preflight VIP+DIRECT auth..." | tee -a "$OUT/logs/runner.log"
auth_ok "http://10.0.0.10:8085" || { echo "VIP auth FAIL"; exit 2; }
auth_ok "http://10.0.0.2:8080" || { echo "DIRECT s2:8080 auth FAIL"; exit 2; }
echo "preflight OK vip_master=$(ssh -o BatchMode=yes -o StrictHostKeyChecking=no root@10.0.0.2 'ip -4 -br a | grep -c 10.0.0.10 || true')" | tee -a "$OUT/logs/runner.log"

# Size ladder: small → large. Workers chosen for disk headroom.
# VIP table
run_cell vip  "http://10.0.0.10:8085" 1KB_write_32   "$RUNTIME_SMALL" 1500
run_cell vip  "http://10.0.0.10:8085" 1KB_read_32    "$RUNTIME_SMALL" 1500
run_cell vip  "http://10.0.0.10:8085" 4KB_write_64   "$RUNTIME_SMALL" 2000
run_cell vip  "http://10.0.0.10:8085" 4KB_read_64    "$RUNTIME_SMALL" 2000
run_cell vip  "http://10.0.0.10:8085" 64KB_write_32  "$RUNTIME_SMALL" 800
run_cell vip  "http://10.0.0.10:8085" 64KB_read_32   "$RUNTIME_SMALL" 800
run_cell vip  "http://10.0.0.10:8085" 1MB_write_16   "$RUNTIME_1MB"   120
run_cell vip  "http://10.0.0.10:8085" 1MB_read_16    "$RUNTIME_1MB"   120
run_cell vip  "http://10.0.0.10:8085" 16MB_write_4   "$RUNTIME_16MB"  16
run_cell vip  "http://10.0.0.10:8085" 16MB_read_4    "$RUNTIME_16MB"  16

# DIRECT / 单入口 (single proxy business port on swift2)
run_cell direct "http://10.0.0.2:8080" 1KB_write_32   "$RUNTIME_SMALL" 1500
run_cell direct "http://10.0.0.2:8080" 1KB_read_32    "$RUNTIME_SMALL" 1500
run_cell direct "http://10.0.0.2:8080" 4KB_write_64   "$RUNTIME_SMALL" 2000
run_cell direct "http://10.0.0.2:8080" 4KB_read_64    "$RUNTIME_SMALL" 2000
run_cell direct "http://10.0.0.2:8080" 64KB_write_32  "$RUNTIME_SMALL" 800
run_cell direct "http://10.0.0.2:8080" 64KB_read_32   "$RUNTIME_SMALL" 800
run_cell direct "http://10.0.0.2:8080" 1MB_write_16   "$RUNTIME_1MB"   120
run_cell direct "http://10.0.0.2:8080" 1MB_read_16    "$RUNTIME_1MB"   120
run_cell direct "http://10.0.0.2:8080" 16MB_write_4   "$RUNTIME_16MB"  16
run_cell direct "http://10.0.0.2:8080" 16MB_read_4    "$RUNTIME_16MB"  16

echo "MATRIX_DONE $(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "$OUT/logs/runner.log"
cat "$OUT/perf/matrix.tsv"
