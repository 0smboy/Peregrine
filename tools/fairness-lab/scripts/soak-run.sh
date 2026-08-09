#!/usr/bin/env bash
# P6: Soak at ~saturation-minus-20%. Default 6h; override SOAK_SECONDS.
# Usage: ENTRY=ha SOAK_SECONDS=3600 ./soak-run.sh
set -euo pipefail
source "$(dirname "$0")/../../../swift-rust/tools/lib/lab-auth.sh"
peregrine_load_lab_auth
ENTRY="${ENTRY:-ha}"
SOAK_SECONDS="${SOAK_SECONDS:-21600}"
TASK="${TASK:-4KB_write_128}"
OUT="${OUT:-/tmp/fairness-soak}"
mkdir -p "$OUT"
if [[ "$ENTRY" == "ha" ]]; then
  export ST_AUTH="http://10.0.0.10:8085/auth/v1.0"
  LABEL=HA-PATH
else
  export ST_AUTH="http://10.0.0.1:8085/auth/v1.0"
  LABEL=DIRECT-4PROXY
fi
export ST_ENDPOINT="${ST_AUTH%/auth/v1.0}/v1/AUTH_test"

cat >"$OUT/manifest.yml" <<EOF
entry: $LABEL
task: $TASK
soak_seconds: $SOAK_SECONDS
note: Run at concurrency chosen as saturation-minus-20% from prior formal cell.
EOF

if ! command -v autocos >/dev/null 2>&1; then
  echo "autocos missing — dry soak plan only" | tee "$OUT/DRY_RUN.txt"
  exit 0
fi

# Chunk soak into 30-minute autocos windows for log rotation
CHUNK=1800
end=$(( $(date +%s) + SOAK_SECONDS ))
i=0
while [[ $(date +%s) -lt $end ]]; do
  i=$((i+1))
  left=$(( end - $(date +%s) ))
  rt=$CHUNK
  [[ $left -lt $CHUNK ]] && rt=$left
  [[ $rt -lt 60 ]] && break
  echo "soak chunk $i runtime=$rt" | tee -a "$OUT/run.log"
  autocos run "$TASK" --object-count 4000 --container-count 1 --runtime "$rt" \
    2>&1 | tee "$OUT/chunk-$i.log" | tail -15
done
echo "OK soak chunks=$i -> $OUT"
