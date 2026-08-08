#!/usr/bin/env bash
# Multi-primary auto-shrink soak harness (LAB).
# Runs cargo unit path repeatedly for multi-hour validation.
# Usage:
#   SOAK_SECONDS=7200 ./tools/soak/multi-primary-shrink-soak.sh
# Default: 120s short smoke (set multi-hour via SOAK_SECONDS).

set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT/swift-rust"
export CARGO_HOME="${CARGO_HOME:-$ROOT/.cargo-home}"
mkdir -p "$CARGO_HOME" "$ROOT/tools/test-results/hard-residual-wave-20260808"

SOAK_SECONDS="${SOAK_SECONDS:-120}"
INTERVAL="${INTERVAL:-30}"
OUT="$ROOT/tools/test-results/hard-residual-wave-20260808/multi-primary-shrink-soak.log"
echo "multi-primary auto-shrink soak start $(date -u +%Y-%m-%dT%H:%M:%SZ) soak=${SOAK_SECONDS}s interval=${INTERVAL}s" | tee "$OUT"

END=$(( $(date +%s) + SOAK_SECONDS ))
PASS=0
FAIL=0
ROUND=0
while [ "$(date +%s)" -lt "$END" ]; do
  ROUND=$((ROUND + 1))
  echo "--- round $ROUND $(date -u +%Y-%m-%dT%H:%M:%SZ) ---" | tee -a "$OUT"
  if cargo test -p swift-container-server --lib \
      shrink \
      -- --nocapture 2>&1 | tee -a "$OUT" | tail -8; then
    PASS=$((PASS + 1))
  else
    FAIL=$((FAIL + 1))
    echo "FAIL round $ROUND" | tee -a "$OUT"
  fi
  NOW=$(date +%s)
  if [ "$NOW" -ge "$END" ]; then break; fi
  sleep "$INTERVAL"
done

echo "SOAK_SUMMARY pass=$PASS fail=$FAIL rounds=$ROUND soak_seconds=$SOAK_SECONDS" | tee -a "$OUT"
if [ "$FAIL" -eq 0 ] && [ "$PASS" -gt 0 ]; then
  echo "VERDICT KEEP" | tee -a "$OUT"
  exit 0
fi
echo "VERDICT FAIL" | tee -a "$OUT"
exit 1
