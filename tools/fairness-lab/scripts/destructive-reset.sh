#!/usr/bin/env bash
# Performance/Chaos ONLY. Dual guard required.
# NEVER derive devices from /dev/sdX — inventory by-id only.
#
# Usage:
#   ALLOW_DESTRUCTIVE_RESET=YES CONFIRM_TICKET=TICKET-ID \
#     ./destructive-reset.sh inventory/devices.json
set -euo pipefail

: "${ALLOW_DESTRUCTIVE_RESET:?Set ALLOW_DESTRUCTIVE_RESET=YES}"
[[ "$ALLOW_DESTRUCTIVE_RESET" == "YES" ]] || { echo "not authorized"; exit 1; }
: "${CONFIRM_TICKET:?Set CONFIRM_TICKET to ops ticket id}"
INV="${1:?inventory devices.json required}"

python3 - <<'PY' "$INV"
import json, sys, pathlib
inv = json.loads(pathlib.Path(sys.argv[1]).read_text())
for host, mounts in inv["hosts"].items():
    for mp, path in mounts.items():
        assert mp.startswith("/srv/node/"), mp
        # Contabo inventory uses by-uuid; by-id also accepted. Never /dev/sdX.
        ok = path.startswith("/dev/disk/by-id/") or path.startswith("/dev/disk/by-uuid/")
        assert ok and "/dev/sd" not in path, path
print("inventory_ok hosts=", len(inv["hosts"]))
PY

echo "FATAL: destructive reset is intentionally NOT auto-executed from agent runs."
echo "Operator must run the remote wipe sequence after reviewing $INV"
echo "Ticket=$CONFIRM_TICKET"
echo "See docs/fairness-lab/MODES.md §destructive-reset"
exit 3
