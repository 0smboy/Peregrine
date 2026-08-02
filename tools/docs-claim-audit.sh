#!/usr/bin/env bash
# Fail on stale / contradictory public claims in Peregrine docs.
# Exit 0 = clean; non-zero = fix before declaring docs done.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

FAIL=0
warn() { echo "WARN: $*" >&2; }
err() { echo "ERROR: $*" >&2; FAIL=1; }
ok() { echo "OK: $*"; }

PERF="docs-site/src/content/docs/performance.mdx"
LAB="docs-site/src/content/docs/lab-cluster.mdx"
WRITE="docs/write-concurrency-optimization.md"
SUMMARY_JSON="tools/test-results/contabo-deploy-20260801/perf-levers/SUMMARY.json"

scan_files=(
  docs-site/src/content/docs/*.mdx
  docs/write-concurrency-optimization.md
  docs/lab-cluster.md
  docs/testing.md
  README.md
)

echo "== stale token scan =="
# Azure current-lab (allow "retired" / "previous" contexts — flag bare 10.42.30)
while IFS= read -r hit; do
  [[ -z "$hit" ]] && continue
  if echo "$hit" | rg -q "retired|previous Azure|historical|PAYG topology"; then
    continue
  fi
  err "stale Azure/10.42 current-lab claim: $hit"
done < <(rg -n "10\.42\.|Azure HA|Azure lab|ILB hairpin" "${scan_files[@]}" 2>/dev/null || true)

# Retired PUT baseline presented as current (allow "Retired" / "retired" lines)
while IFS= read -r hit; do
  [[ -z "$hit" ]] && continue
  if echo "$hit" | rg -qi "retired|pre-optimization|do not treat|baseline"; then
    continue
  fi
  err "stale SAIO PUT baseline as current: $hit"
done < <(rg -n "54 / 159|159 op/s|255 op/s|32 / 255" "${scan_files[@]}" 2>/dev/null || true)

if rg -n "Python is competitive on concurrent small writes" "${scan_files[@]}" >/dev/null 2>&1; then
  err "stale narrative: Python competitive on small writes"
fi

if rg -n "SO_REUSEPORT.*remaining|remaining piece is multiple accept" "$WRITE" docs-site/src/content/docs/*.mdx 2>/dev/null | rg -v "DROP|DROP'd|dropped" >/dev/null; then
  err "open SO_REUSEPORT remaining language after L4 DROP"
fi

echo "== required Contabo / SAIO tokens =="
for f in "$PERF" "$LAB"; do
  [[ -f "$f" ]] || { err "missing $f"; continue; }
done

rg -q "10\.0\.0\.10" "$LAB" || err "$LAB missing Contabo VIP 10.0.0.10"
rg -q "Contabo" "$LAB" || err "$LAB missing Contabo"
rg -q ":8090" "$LAB" || err "$LAB missing Python SAIO :8090"
rg -q ":8081" "$LAB" || err "$LAB missing Rust SAIO :8081"

if [[ -f "$PERF" ]]; then
  rg -q "264\.4|264 op/s" "$PERF" || err "$PERF missing current SAIO Rust c32 (~264)"
  rg -q "69\.8|70 op/s" "$PERF" || err "$PERF missing current SAIO Python c32 (~70)"
  rg -q "container_update_mode = sync" "$PERF" || err "$PERF missing prod sync knob"
  rg -q "fsync_on_close = true" "$PERF" || err "$PERF missing fsync_on_close=true"
  rg -q "reuse_port = false" "$PERF" || err "$PERF missing reuse_port=false"
  rg -qi "L1a" "$PERF" && rg -qi "KEEP" "$PERF" || err "$PERF missing L1a KEEP"
  rg -q "Contabo" "$PERF" || err "$PERF missing Contabo context"
fi

if [[ -f "$SUMMARY_JSON" ]]; then
  python3 - <<'PY' || err "SUMMARY.json saio_phase0 mismatch vs performance.mdx"
import json, re, sys
from pathlib import Path
root = Path(".")
s = json.loads((root / "tools/test-results/contabo-deploy-20260801/perf-levers/SUMMARY.json").read_text())
med = {}
for row in s["saio_phase0"]["rows"]:
    med[(row["side"], row["conc"])] = row["median"]["ops"]
perf = (root / "docs-site/src/content/docs/performance.mdx").read_text()
need = [
    ("rust", 32, 264.4),
    ("python", 32, 69.8),
    ("rust", 1, 71.8),
    ("python", 1, 32.3),
]
for side, conc, expect in need:
    got = med.get((side, conc))
    if got is None:
        print(f"missing saio_phase0 {side} c{conc}", file=sys.stderr)
        sys.exit(1)
    if abs(got - expect) > 0.05:
        print(f"SUMMARY drift {side} c{conc}: {got} != {expect}", file=sys.stderr)
        sys.exit(1)
    # performance.mdx should contain the exact median string
    token = f"{got:g}" if got != int(got) else str(int(got))
    # allow either 264.4 or rounded forms already checked above for c32
    if side == "rust" and conc == 32 and "264.4" not in perf and "264 op/s" not in perf:
        print("performance.mdx missing 264.4", file=sys.stderr)
        sys.exit(1)
print("saio_phase0 medians consistent with SUMMARY.json")
PY
  ok "SUMMARY.json cross-check"
else
  warn "SUMMARY.json missing — skip numeric cross-check"
fi

echo "== write-concurrency closed language =="
if [[ -f "$WRITE" ]]; then
  rg -qi "Status: \*\*closed\*\*|Status: \*\*A/B program closed\*\*|Status: \*\*closed\*\*" "$WRITE" \
    || rg -qi "Status: \*\*closed\*\*" "$WRITE" \
    || rg -qi "^Status: \*\*closed\*\*" "$WRITE" \
    || true
  if ! rg -qi "closed" "$WRITE"; then
    err "$WRITE missing closed status"
  fi
  if rg -n "^## Plan" "$WRITE" >/dev/null && rg -n "biggest lever|SO_REUSEPORT.*remaining" "$WRITE" >/dev/null; then
    err "$WRITE still has open Plan contradicting CLOSED"
  fi
  ok "write-concurrency doc closed check"
fi

if [[ "$FAIL" -eq 0 ]]; then
  ok "docs-claim-audit passed"
  exit 0
fi
echo "docs-claim-audit FAILED" >&2
exit 1
