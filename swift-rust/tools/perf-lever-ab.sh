#!/usr/bin/env bash
# Controlled A/B harness for write-path levers.
# Runs a task N times, parses autocos stage summaries, writes median JSON.
#
# Usage:
#   ST_ENDPOINT=http://10.0.0.1:8085/v1/AUTH_test \
#   ST_AUTH=http://10.0.0.1:8085/auth/v1.0 \
#   ST_USER=test:tester ST_KEY=azure-swift-2026.bench \
#   OUT=/path/to/dir LABEL=phase0-baseline \
#   bash perf-lever-ab.sh 4KB_write_128 4000 1 60 3
#
# Args: <task> <object_count> <container_count> <runtime_secs> [reps=3]
set -euo pipefail
ulimit -n 65535 2>/dev/null || true

TASK=${1:?task}
OBJ=${2:?object_count}
CONT=${3:?container_count}
RT=${4:?runtime}
REPS=${5:-3}
LABEL=${LABEL:-ab}
OUT=${OUT:-./perf-lever-out}
AUTOCOS=${AUTOCOS:-/usr/local/bin/autocos}
mkdir -p "$OUT"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
RUN_DIR="$OUT/${LABEL}_${TASK}_c${CONT}_${STAMP}"
mkdir -p "$RUN_DIR"

: "${ST_ENDPOINT:?ST_ENDPOINT required}"
: "${ST_AUTH:?ST_AUTH required}"
: "${ST_USER:?ST_USER required}"
: "${ST_KEY:?ST_KEY required}"

echo "CLIENT ulimit=$(ulimit -n) endpoint=$ST_ENDPOINT task=$TASK cont=$CONT rt=$RT reps=$REPS" \
  | tee "$RUN_DIR/meta.txt"

parse_log() {
  python3 - "$1" <<'PY'
import json, re, sys
from pathlib import Path
raw = Path(sys.argv[1]).read_text(errors="replace")
# autocos colors the key=value fields; strip CSI before matching.
text = re.sub(r"\x1b\[[0-9;]*m", "", raw)
pat = re.compile(
    r"stage finished\s+stage=normal\s+ok=(\d+)\s+fail=(\d+).*?p99_us=(\d+)",
    re.I | re.S,
)
m = None
for line in text.splitlines():
    if "stage=normal" in line and "stage finished" in line:
        m = pat.search(line) or m
ok = fail = p99 = None
if m:
    ok, fail, p99 = int(m.group(1)), int(m.group(2)), int(m.group(3))
else:
    for line in reversed(text.splitlines()):
        if "stage=normal" in line and "stage finished" in line:
            mo = re.search(r"ok=(\d+)", line)
            mf = re.search(r"fail=(\d+)", line)
            mp = re.search(r"p99_us=(\d+)", line)
            if mo and mf:
                ok, fail = int(mo.group(1)), int(mf.group(1))
                p99 = int(mp.group(1)) if mp else None
                break
if ok is None:
    print(json.dumps({"error": "no normal stage", "tail": text[-500:]}))
    sys.exit(0)
rt = None
for line in text.splitlines():
    if line.startswith("RUNTIME="):
        rt = float(line.split("=", 1)[1])
ops = (ok / rt) if rt and rt > 0 else None
print(json.dumps({"ok": ok, "fail": fail, "p99_us": p99, "ops_per_s": ops, "runtime_s": rt}))
PY
}

RESULTS=()
for i in $(seq 1 "$REPS"); do
  LOG="$RUN_DIR/run-$i.log"
  echo "=== REP $i/$REPS $TASK ===" | tee -a "$RUN_DIR/console.log"
  START=$(date +%s)
  set +e
  "$AUTOCOS" run "$TASK" --object-count "$OBJ" --container-count "$CONT" --runtime "$RT" \
    >"$LOG" 2>&1
  rc=$?
  set -e
  END=$(date +%s)
  echo "RUNTIME=$((END-START))" >>"$LOG"
  echo "exit=$rc" >>"$LOG"
  tr '\r' '\n' <"$LOG" | grep -E "stage finished|Error|fail=|finished! wid" \
    | grep -vE "^\s*write:|^\s*read:" | tee -a "$RUN_DIR/console.log" || true
  # rewrite log normalized for parser
  tr '\r' '\n' <"$LOG" >"$LOG.norm"
  mv "$LOG.norm" "$LOG"
  echo "RUNTIME=$((END-START))" >>"$LOG"
  parse_log "$LOG" | tee "$RUN_DIR/run-$i.json"
  RESULTS+=("$RUN_DIR/run-$i.json")
done

python3 - "$RUN_DIR" "$TASK" "$CONT" "$LABEL" "${RESULTS[@]}" <<'PY'
import json, statistics, sys
from pathlib import Path
out = Path(sys.argv[1])
task, cont, label = sys.argv[2], int(sys.argv[3]), sys.argv[4]
paths = sys.argv[5:]
rows = []
for p in paths:
    d = json.loads(Path(p).read_text())
    if "error" in d:
        rows.append(d)
        continue
    rows.append(d)

def med(key):
    xs = [r[key] for r in rows if isinstance(r.get(key), (int, float))]
    return statistics.median(xs) if xs else None

summary = {
    "label": label,
    "task": task,
    "container_count": cont,
    "reps": len(rows),
    "rows": rows,
    "median": {
        "ok": med("ok"),
        "fail": med("fail"),
        "p99_us": med("p99_us"),
        "ops_per_s": med("ops_per_s"),
        "runtime_s": med("runtime_s"),
    },
    "gate_fail0": all(r.get("fail", 1) == 0 for r in rows if "fail" in r),
}
Path(out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
m = summary["median"]
print(
    f"SUMMARY label={label} task={task} cont={cont} "
    f"median_ops={m['ops_per_s']} median_p99_us={m['p99_us']} "
    f"median_fail={m['fail']} gate_fail0={summary['gate_fail0']}"
)
print(f"WROTE {out / 'summary.json'}")
PY
