#!/bin/sh
# Peregrine W10 gap metrics for the node_exporter textfile collector.
# Read-only against /srv/node; writes one atomic .prom file. Idempotent.
# On any error: silent, non-zero exit (cron-safe, no log storms).
# Install: /usr/local/bin/peregrine-textfile-metrics.sh (mode 0755)
# Cron:    /etc/cron.d/peregrine-textfile-metrics (*/5)

set -u

OUT_DIR=/var/lib/node_exporter/textfile_collector
OUT="$OUT_DIR/peregrine.prom"
TMP="$OUT.tmp.$$"

trap 'rm -f "$TMP"' EXIT

[ -d "$OUT_DIR" ] || exit 1
[ -d /srv/node ] || exit 1

# Missing per-device subdirs are legitimate (not every device has a
# quarantined/ or async_pending-*/ dir yet), so find's stderr is dropped;
# the pipeline status is wc's, which is what we want.
quarantined=$(find /srv/node/d*/quarantined -type f 2>/dev/null | wc -l | tr -d '[:space:]') || exit 1
async_pendings=$(find /srv/node/d*/async_pending* -type f 2>/dev/null | wc -l | tr -d '[:space:]') || exit 1

case "$quarantined$async_pendings" in
  *[!0-9]*) exit 1 ;;
esac

{
  printf '# HELP peregrine_quarantined_objects Files under /srv/node/d*/quarantined (recursive, read-only count).\n'
  printf '# TYPE peregrine_quarantined_objects gauge\n'
  printf 'peregrine_quarantined_objects %s\n' "$quarantined"
  printf '# HELP peregrine_async_pendings Files under /srv/node/d*/async_pending* (all policies, read-only count).\n'
  printf '# TYPE peregrine_async_pendings gauge\n'
  printf 'peregrine_async_pendings %s\n' "$async_pendings"
} > "$TMP" 2>/dev/null || exit 1

mv "$TMP" "$OUT" 2>/dev/null || exit 1
trap - EXIT
exit 0
