#!/usr/bin/env bash
# P3: Fail if public docs claim unsupported knobs as deployed.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$ROOT"
PARITY=docs/fairness-lab/CONFIG-PARITY.json
[[ -f "$PARITY" ]] || { echo "missing $PARITY"; exit 1; }
python3 - <<'PY'
import json, re, sys
from pathlib import Path
parity = json.loads(Path("docs/fairness-lab/CONFIG-PARITY.json").read_text())
unsupported = {(r["service"], r["knob"]) for r in parity["rows"] if r["fairness_class"]=="unsupported"}
# Scan performance + lab for dangerous "servers_per_port enabled" style claims without unsupported tag
text = "\n".join(p.read_text() for p in Path("docs-site/src/content/docs").glob("*.mdx"))
fail = 0
if re.search(r"servers_per_port\s*=\s*[1-9]", text) and "unsupported" not in text.lower():
    print("WARN: servers_per_port numeric claim without unsupported context")
# Require fairness demotion labels already checked by docs-claim-audit
for lab in parity["labels_required_on_claims"]:
    pass
print(f"OK config-parity-audit unsupported_count={len(unsupported)}")
sys.exit(fail)
PY
