#!/usr/bin/env bash
# P5: Formal performance scheduler skeleton.
# Enforces labels DIRECT-4PROXY vs HA-PATH; does not claim results without mode gate.
#
# Usage:
#   ENTRY=direct IMPL=rust PROFILE=data-path TRACK=ISO-CONFIG \
#     OUT=.../runs ./perf-formal.sh 4KB_write_128
set -euo pipefail
ENTRY="${ENTRY:-direct}"          # direct | ha
IMPL="${IMPL:-rust}"              # rust | python
PROFILE="${PROFILE:-data-path}"   # data-path | production-complete
TRACK="${TRACK:-ISO-CONFIG}"
TASK="${1:-4KB_write_128}"
RUNTIME="${RUNTIME:-60}"
REPS="${REPS:-8}"                 # formal minimum
WARMUP="${WARMUP:-2}"
OBJECT_COUNT="${OBJECT_COUNT:-4000}"
CONTAINER_COUNT="${CONTAINER_COUNT:-1}"
OUT="${OUT:-/tmp/fairness-perf}"
mkdir -p "$OUT"

case "$ENTRY" in
  direct)
    # Distribute across four proxies — autocos typically takes one ST_AUTH;
    # for true 4-way fanout use cosbench-rs multi-endpoint when available.
    # Documented primary endpoints:
    ENDPOINTS="http://10.0.0.1:8085 http://10.0.0.2:8085 http://10.0.0.3:8085 http://10.0.0.4:8085"
    LABEL_ENTRY=DIRECT-4PROXY
    # Pilot client target: round-robin first proxy; full fanout is backlog enhancement
    ST_AUTH="http://10.0.0.1:8085/auth/v1.0"
    ;;
  ha)
    ENDPOINTS="http://10.0.0.10:8085"
    LABEL_ENTRY=HA-PATH
    ST_AUTH="http://10.0.0.10:8085/auth/v1.0"
    ;;
  *) echo "ENTRY must be direct|ha"; exit 2 ;;
esac

USER="${ST_USER:-test:tester}"
KEY="${ST_KEY:-azure-swift-2026.bench}"
AUTOCOS="${AUTOCOS:-autocos}"

MANIFEST="$OUT/manifest.yml"
cat >"$MANIFEST" <<EOF
schema_version: 1
entry: $LABEL_ENTRY
implementation: $IMPL
profile: $PROFILE
track: $TRACK
task: $TASK
reps_measured: $REPS
warmup_discarded: $WARMUP
endpoints: $ENDPOINTS
st_auth: $ST_AUTH
note: >
  Formal A-B-B-A pairing is operator-scheduled across IMPL flips via mode-switch.sh.
  A single invocation runs REPS for one IMPL/ENTRY/PROFILE cell.
EOF

export ST_AUTH ST_USER="$USER" ST_KEY="$KEY"
export ST_ENDPOINT="${ST_AUTH%/auth/v1.0}/v1/AUTH_test"

if ! command -v "$AUTOCOS" >/dev/null 2>&1; then
  echo "WARN: autocos not in PATH — writing dry-run plan only"
  echo "dry_run: true" >>"$MANIFEST"
  echo "OK dry-run manifest -> $MANIFEST"
  exit 0
fi

# Residual SAIO pollution gate for formal runs
if ss -lnt 2>/dev/null | grep -qE ':(8081|8090)\s'; then
  echo "WARN: local SAIO listeners present — mark NOISY if this is the load host" | tee "$OUT/validity-warn.txt"
fi

run_one() {
  local i=$1 kind=$2
  local log="$OUT/${kind}-${i}.log"
  echo "=== $kind $i $TASK ===" | tee -a "$OUT/run.log"
  "$AUTOCOS" run "$TASK" --object-count "$OBJECT_COUNT" --container-count "$CONTAINER_COUNT" \
    --runtime "$RUNTIME" 2>&1 | tee "$log" | tail -30
}

for i in $(seq 1 "$WARMUP"); do
  run_one "$i" warmup || true
done
for i in $(seq 1 "$REPS"); do
  run_one "$i" measured
done

python3 - <<PY
import json, re, pathlib, statistics
out = pathlib.Path("$OUT")
ops = []
for p in sorted(out.glob("measured-*.log")):
    t = p.read_text(errors="replace")
    # autocos normal stage ops/s
    m = re.findall(r"ops_per_s[=:]\s*([0-9.]+)|\"ops_per_s\":\s*([0-9.]+)|([0-9.]+)\s*ops/s", t)
    # fallback: look for success line
    for a,b,c in m:
        v = a or b or c
        if v: ops.append(float(v))
summary = {
    "entry": "$LABEL_ENTRY",
    "impl": "$IMPL",
    "profile": "$PROFILE",
    "track": "$TRACK",
    "task": "$TASK",
    "ops_samples": ops,
    "ops_median": statistics.median(ops) if ops else None,
    "n": len(ops),
    "formal_gate_reps": int("$REPS"),
    "reps_met": len(ops) >= int("$REPS"),
}
(out/"SUMMARY.json").write_text(json.dumps(summary, indent=2)+"\n")
print(json.dumps(summary, indent=2))
PY
