#!/usr/bin/env bash
# Phase0 SAIO gate: 1KB PUT @ c1 and c32, Rust(:8081) vs Python(:8090), 3× median.
set -euo pipefail
OUT=${OUT:-/root/contabo-deploy-20260801T125749Z/perf-levers/00-phase0-saio}
USR=test:tester
KEY=azure-swift-2026.bench
WB=${WB:-/root/work/wbench.py}
source /root/work/pyswift-venv/bin/activate
mkdir -p "$OUT"
run_side() {
  local side=$1 ep=$2 cont=$3 conc=$4 n=$5
  local log=$OUT/${side}_1kb_c${conc}_cont${cont}.log
  : > "$log"
  echo "SIDE=$side EP=$ep cont=$cont conc=$conc n=$n" | tee -a "$log"
  for i in 1 2 3; do
    echo "=== REP $i ===" | tee -a "$log"
    python "$WB" "$ep" "$USR" "$KEY" "$cont" "$conc" "$n" 1024 2>&1 | tee -a "$log"
  done
  python3 - "$log" "$OUT/${side}_1kb_c${conc}_cont${cont}.json" <<'PY'
import json,re,statistics,sys
from pathlib import Path
text=Path(sys.argv[1]).read_text()
rows=[]
for line in text.splitlines():
    m=re.search(r"([0-9.]+)\s+PUT/s\s+p50=\s*([0-9.]+)ms\s+p95=\s*([0-9.]+)ms\s+p99=\s*([0-9.]+)ms\s+errs=(\d+)", line)
    if m:
        rows.append({"ops":float(m.group(1)),"p50_ms":float(m.group(2)),"p95_ms":float(m.group(3)),"p99_ms":float(m.group(4)),"errs":int(m.group(5))})
def med(k):
    xs=[r[k] for r in rows]
    return statistics.median(xs) if xs else None
summary={"rows":rows,"median":{"ops":med("ops"),"p50_ms":med("p50_ms"),"p99_ms":med("p99_ms"),"errs":med("errs")},
         "gate_fail0": all(r["errs"]==0 for r in rows)}
Path(sys.argv[2]).write_text(json.dumps(summary,indent=2)+"\n")
print(json.dumps(summary["median"]), "gate_fail0=", summary["gate_fail0"])
PY
}
# sanity endpoints
curl -sf -o /dev/null -H "X-Auth-User: $USR" -H "X-Auth-Key: $KEY" http://127.0.0.1:8081/auth/v1.0
curl -sf -o /dev/null -H "X-Auth-User: $USR" -H "X-Auth-Key: $KEY" http://127.0.0.1:8090/auth/v1.0
run_side rust http://127.0.0.1:8081 1 1 2000
run_side rust http://127.0.0.1:8081 1 32 6000
run_side python http://127.0.0.1:8090 1 1 2000
run_side python http://127.0.0.1:8090 1 32 6000
echo SAIO-PHASE0-DONE
