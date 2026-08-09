#!/usr/bin/env bash
# R8: retune 16MB_read (object_count=40, runtime=180) DIRECT+HA ≥8 measured, then 6h soak.
set -euo pipefail
source "$(dirname "$0")/../../../swift-rust/tools/lib/lab-auth.sh"
peregrine_load_lab_auth
OUT=${OUT:-/tmp/fairness-R8}
WARMUP=${WARMUP:-2}
REPS=${REPS:-8}
OC=${OC:-40}
RT=${RT:-180}
AUTH_USER=$ST_USER
KEY=$ST_KEY
mkdir -p "$OUT/runs" "$OUT/logs" "$OUT/soak"
echo "START $(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee "$OUT/logs/runner.log"

parse() {
  RT="$RT" python3 - "$1" <<'PY'
import re, sys, os
t = open(sys.argv[1], errors="replace").read()
t = re.sub(r"\x1b\[[0-9;]*m", "", t)
stages = {}
for m in re.finditer(
    r'stage finished\s+stage=(\w+)\s+ok=(\d+)\s+fail=(\d+)\s+success="?([0-9.]+)%"?',
    t,
):
    stages[m.group(1)] = (int(m.group(2)), int(m.group(3)), float(m.group(4)))
ok, fail, succ = stages.get("normal", (0, 0, 0.0))
pok, pfail, psucc = stages.get("prepare", (0, 0, 0.0))
rt = float(os.environ.get("RT", "180"))
thr = ok / rt if rt else 0.0
print(f"{ok}\t{fail}\t{succ}\t{pok}\t{pfail}\t{psucc}\t{thr}")
PY
}

run_entry() {
  local label=$1
  shift
  local eps=("$@")
  local cell="${label}_16MB_read_4"
  local cell_dir="$OUT/runs/$cell"
  mkdir -p "$cell_dir"
  local epi=0
  echo "=== CELL $cell ===" | tee -a "$OUT/logs/runner.log"
  : >"$cell_dir/samples.tsv"
  local i ep log
  for i in $(seq 1 "$WARMUP"); do
    ep="${eps[$((epi % ${#eps[@]}))]}"
    epi=$((epi + 1))
    export ST_AUTH="${ep}/auth/v1.0" ST_USER="$AUTH_USER" ST_KEY="$KEY" ST_ENDPOINT="${ep}/v1/AUTH_test"
    log="$cell_dir/warmup-${i}.log"
    echo "RUN warmup $i ep=$ep $(date -u +%H:%M:%SZ)" | tee -a "$OUT/logs/runner.log"
    set +e
    autocos run 16MB_read_4 --object-count "$OC" --container-count 1 --runtime "$RT" >"$log" 2>&1
    echo "rc=$?" >>"$log"
    set -e
  done
  for i in $(seq 1 "$REPS"); do
    ep="${eps[$((epi % ${#eps[@]}))]}"
    epi=$((epi + 1))
    export ST_AUTH="${ep}/auth/v1.0" ST_USER="$AUTH_USER" ST_KEY="$KEY" ST_ENDPOINT="${ep}/v1/AUTH_test"
    log="$cell_dir/measured-${i}.log"
    echo "RUN measured $i ep=$ep $(date -u +%H:%M:%SZ)" | tee -a "$OUT/logs/runner.log"
    set +e
    autocos run 16MB_read_4 --object-count "$OC" --container-count 1 --runtime "$RT" >"$log" 2>&1
    echo "rc=$?" >>"$log"
    set -e
    local ok fail succ pok pfail psucc thr
    read -r ok fail succ pok pfail psucc thr < <(parse "$log")
    echo -e "${i}\t${ok}\t${fail}\t${succ}\t${pok}\t${pfail}\t${psucc}\t${thr}\t${ep}" | tee -a "$cell_dir/samples.tsv"
  done
  python3 - "$cell_dir" "$label" "$OC" "$RT" <<'PY'
import json, statistics, pathlib, sys
d = pathlib.Path(sys.argv[1])
label, oc, rt = sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
rows = []
for line in (d / "samples.tsv").read_text().splitlines():
    p = line.split("\t")
    if len(p) < 8:
        continue
    rows.append(
        {
            "i": int(p[0]),
            "ok": int(p[1]),
            "fail": int(p[2]),
            "success_pct": float(p[3]),
            "prepare_ok": int(p[4]),
            "prepare_fail": int(p[5]),
            "prepare_success_pct": float(p[6]),
            "ops_per_s": float(p[7]) if p[7] else None,
            "endpoint": p[8] if len(p) > 8 else "",
        }
    )
ops = [r["ops_per_s"] for r in rows if r["ops_per_s"] is not None]
fails = [
    r["fail"] / (r["ok"] + r["fail"]) if (r["ok"] + r["fail"]) else 1.0 for r in rows
]
prep_ok = all(r["prepare_fail"] == 0 and r["prepare_ok"] > 0 for r in rows)
norm_ok = all(r["fail"] == 0 for r in rows)
validity = "ACCEPT" if prep_ok and norm_ok and len(ops) >= 8 else "WARN"
summary = {
    "entry": label,
    "task": "16MB_read_4",
    "object_count": oc,
    "runtime_s": rt,
    "impl": "rust",
    "profile": "data-path",
    "track": "ISO-CONFIG",
    "n": len(ops),
    "reps_met": len(ops) >= 8,
    "ops_median": statistics.median(ops) if ops else None,
    "ops_samples": ops,
    "fail_rate_median": statistics.median(fails) if fails else None,
    "validity": validity,
    "validity_note": "R8 retune object_count/runtime; ACCEPT iff prepare+normal fail=0",
    "runs": rows,
}
(d / "SUMMARY.json").write_text(json.dumps(summary, indent=2) + "\n")
print(json.dumps({k: summary[k] for k in summary if k != "runs"}, indent=2))
PY
}

run_entry DIRECT-4PROXY \
  http://10.0.0.1:8085 http://10.0.0.2:8085 http://10.0.0.3:8085 http://10.0.0.4:8085

run_entry HA-PATH http://10.0.0.10:8085

echo "=== SOAK 6h DIRECT ===" | tee -a "$OUT/logs/runner.log"
export ST_AUTH=http://10.0.0.2:8085/auth/v1.0 ST_USER="$USER" ST_KEY="$KEY"
export ST_ENDPOINT=http://10.0.0.2:8085/v1/AUTH_test
SOAK_SECONDS=${SOAK_SECONDS:-21600}
CHUNK=1800
end=$(($(date +%s) + SOAK_SECONDS))
i=0
ok_total=0
fails_total=0
: >"$OUT/soak/summary.tsv"
while [[ $(date +%s) -lt $end ]]; do
  i=$((i + 1))
  left=$((end - $(date +%s)))
  rt=$CHUNK
  [[ $left -lt $CHUNK ]] && rt=$left
  [[ $rt -lt 60 ]] && break
  echo "soak chunk $i runtime=$rt $(date -u +%H:%M:%SZ)" | tee -a "$OUT/logs/runner.log"
  log="$OUT/soak/chunk-$i.log"
  set +e
  autocos run 4KB_write_128 --object-count 4000 --container-count 1 --runtime "$rt" >"$log" 2>&1
  set -e
  read -r cok cfail < <(
    python3 - "$log" <<'PY'
import re, sys
t = re.sub(r"\x1b\[[0-9;]*m", "", open(sys.argv[1], errors="replace").read())
m = None
for mm in re.finditer(r"stage finished\s+stage=normal\s+ok=(\d+)\s+fail=(\d+)", t):
    m = mm
print(f"{m.group(1)} {m.group(2)}" if m else "0 1")
PY
  )
  ok_total=$((ok_total + cok))
  fails_total=$((fails_total + cfail))
  echo -e "${i}\t${cok}\t${cfail}\t${rt}" | tee -a "$OUT/soak/summary.tsv"
done
python3 - "$OUT/soak/SUMMARY.json" "$SOAK_SECONDS" "$i" "$ok_total" "$fails_total" <<'PY'
import json, sys
path, soak_s, chunks, ok_total, fails_total = sys.argv[1:6]
summary = {
    "entry": "DIRECT-4PROXY",
    "task": "4KB_write_128",
    "soak_seconds": int(soak_s),
    "chunks": int(chunks),
    "ok_total": int(ok_total),
    "fail_total": int(fails_total),
    "validity": "ACCEPT" if int(fails_total) == 0 else "WARN",
}
open(path, "w").write(json.dumps(summary, indent=2) + "\n")
print(json.dumps(summary, indent=2))
PY
echo "END $(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "$OUT/logs/runner.log"
