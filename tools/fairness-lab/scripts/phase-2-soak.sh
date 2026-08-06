#!/usr/bin/env bash
# Phase-2 soak ≥1h via VIP, chunked 4KB write windows. Disk-aware object_count.
set -euo pipefail
OUT="${OUT:-/tmp/phase2-20260804/soak}"
SOAK_SECONDS="${SOAK_SECONDS:-3600}"
CHUNK="${CHUNK:-600}"
USR="${ST_USER:-test:tester}"
KEY="${ST_KEY:-azure-swift-2026.bench}"
mkdir -p "$OUT"
export ST_AUTH="http://10.0.0.10:8085/auth/v1.0" ST_USER="$USR" ST_KEY="$KEY"
export ST_ENDPOINT="http://10.0.0.10:8085/v1/AUTH_test"

: >"$OUT/summary.tsv"
echo -e "chunk\tok\tfail\truntime\twall_utc" >>"$OUT/summary.tsv"
start=$(date +%s)
i=0
ok_total=0
fail_total=0
while (( $(date +%s) - start < SOAK_SECONDS )); do
  i=$((i+1))
  left=$(( SOAK_SECONDS - ($(date +%s) - start) ))
  rt=$CHUNK
  (( left < rt )) && rt=$left
  (( rt < 30 )) && break
  log="$OUT/chunk-$i.log"
  echo "soak chunk $i runtime=$rt $(date -u +%H:%M:%SZ)" | tee -a "$OUT/runner.log"
  set +e
  autocos run 4KB_write_32 --object-count 1500 --container-count 1 --runtime "$rt" --backend swift >"$log" 2>&1
  set -e
  line=$(grep 'stage finished' "$log" | grep normal | tail -1 || true)
  ok=0; fail=0
  [[ "$line" =~ ok[^0-9]*([0-9]+) ]] && ok="${BASH_REMATCH[1]}"
  [[ "$line" =~ fail[^0-9]*([0-9]+) ]] && fail="${BASH_REMATCH[1]}"
  ok_total=$((ok_total+ok))
  fail_total=$((fail_total+fail))
  echo -e "${i}\t${ok}\t${fail}\t${rt}\t$(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "$OUT/summary.tsv"
done
elapsed=$(( $(date +%s) - start ))
python3 - <<PY | tee "$OUT/SUMMARY.json"
import json
print(json.dumps({
  "soak_seconds_target": $SOAK_SECONDS,
  "soak_seconds_elapsed": $elapsed,
  "chunks": $i,
  "ok_total": $ok_total,
  "fail_total": $fail_total,
  "gate": "PASS" if $fail_total == 0 and $elapsed >= min(3600, $SOAK_SECONDS) * 0.95 else "FAIL",
}, indent=2))
PY
