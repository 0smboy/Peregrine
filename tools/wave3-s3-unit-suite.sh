#!/usr/bin/env bash
# Wave 3 PRODUCTION S3 + L3b unit stop-line.
# Usage: from Peregrine repo root
#   ./tools/wave3-s3-unit-suite.sh [EVIDENCE_DIR]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EVID="${1:-$ROOT/tools/test-results/wave3-s3-l3b-prod-$(date -u +%Y%m%d)}"
mkdir -p "$EVID"
cd "$ROOT/swift-rust"

run() {
  local name="$1"; shift
  echo "==> $name" | tee "$EVID/$name.txt"
  if "$@" 2>&1 | tee -a "$EVID/$name.txt"; then
    echo "PASS $name" | tee -a "$EVID/$name.txt"
    return 0
  else
    echo "FAIL $name" | tee -a "$EVID/$name.txt"
    return 1
  fi
}

FAIL=0
run 05-cargo-s3api cargo test -p swift-s3api -- --nocapture || FAIL=1
run 05-cargo-s3token cargo test -p swift-middleware s3token -- --nocapture || FAIL=1
run 05-cargo-sharder cargo test -p swift-container-server sharder -- --nocapture || FAIL=1
run 05-cargo-proxy-fanout cargo test -p swift-proxy-server shard_listing_fanout -- --nocapture || FAIL=1
run 05-cargo-proxy-s3api cargo test -p swift-proxy-server --bin swift-proxy-server pipeline_s3api -- --nocapture || FAIL=1
run 05-cargo-container-sharding cargo test -p swift-container-server --test sharding -- --nocapture || FAIL=1

{
  echo "wave3-s3-unit-suite finished at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "evidence=$EVID"
  if [[ "$FAIL" -eq 0 ]]; then
    echo "VERDICT=PASS"
  else
    echo "VERDICT=FAIL"
  fi
} | tee "$EVID/05-unit-suite-verdict.txt"

exit "$FAIL"
