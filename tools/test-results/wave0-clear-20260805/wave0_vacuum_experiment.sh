#!/usr/bin/env bash
# Wave 0C: sample DB space, VACUUM one device, sample again.
set -euo pipefail
DEV="${1:-/srv/node/d2}"
BIN="${SWIFT_RECON:-/usr/local/bin/swift-recon}"
OUT_DIR="${2:-/tmp/wave0-vacuum}"
mkdir -p "$OUT_DIR"
date -u +%Y-%m-%dT%H:%M:%SZ | tee "$OUT_DIR/00-start.txt"
df -h "$DEV" | tee "$OUT_DIR/01-df-before.txt"
"$BIN" dbspace "$(dirname "$DEV")" | tee "$OUT_DIR/02-dbspace-before-all.txt"
# Per-device before via vacuum dry? sample by running vacuum's before lines only:
# Use vacuum which prints before/after per DB — capture full log
"$BIN" vacuum "$DEV" | tee "$OUT_DIR/03-vacuum-${DEV##*/}.txt"
df -h "$DEV" | tee "$OUT_DIR/04-df-after.txt"
"$BIN" dbspace "$(dirname "$DEV")" | tee "$OUT_DIR/05-dbspace-after-all.txt"
date -u +%Y-%m-%dT%H:%M:%SZ | tee "$OUT_DIR/99-end.txt"
echo "DONE vacuum $DEV"
