#!/bin/bash
# Write swift-recon tombstones + dbspace into node_exporter textfile dir.
set -euo pipefail
TEXTFILE_DIR="${TEXTFILE_DIR:-/var/lib/node_exporter/textfile_collector}"
DEVICES_ROOT="${DEVICES_ROOT:-/srv/node}"
BIN="${SWIFT_RECON_BIN:-/usr/local/bin/swift-recon}"

mkdir -p "$TEXTFILE_DIR"
tmp=$(mktemp "$TEXTFILE_DIR/swift-recon.prom.tmp.XXXXXX")
cleanup() { rm -f "$tmp"; }
trap cleanup EXIT

"$BIN" tombstones "$DEVICES_ROOT" --prometheus >"$tmp"
if ! grep -q '^swift_object_tombstones{' "$tmp"; then
  node=$(hostname -s)
  printf 'swift_object_tombstones{node="%s",device="none",policy="none"} 0\n' "$node" >>"$tmp"
  printf 'swift_object_tombstone_bytes{node="%s",device="none",policy="none"} 0\n' "$node" >>"$tmp"
fi
"$BIN" dbspace "$DEVICES_ROOT" --prometheus >>"$tmp"
chmod 644 "$tmp"
mv -f "$tmp" "$TEXTFILE_DIR/swift-recon.prom"
trap - EXIT
