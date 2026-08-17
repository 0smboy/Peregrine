#!/usr/bin/env bash
#
# dr-backup.sh -- Peregrine config-plane disaster-recovery backup (Wave 10)
#
# Captures the CONFIG PLANE of the node it runs on into one tar.gz bundle:
#
#   /etc/swift/                  rings (.ring.gz), builder JSONs, swift.conf,
#                                service confs, env files  (SECRETS INSIDE)
#   /etc/pyswift/                python-oracle confs + rings (if present)
#   /etc/haproxy/                load-balancer config (if present)
#   /etc/keepalived/             VIP failover config (if present)
#   /etc/systemd/system/swift*   unit files, timers, targets, drop-in dirs
#   /etc/systemd/system/pyswift* (same, python oracle units)
#   root crontab                 captured as meta/crontab-root.txt
#   /usr/local/bin               INVENTORY ONLY (ls -la + per-file sha256).
#                                Binaries are NOT packed; they are rebuildable
#                                from the git repo / release artifacts.
#
# Every bundle carries MANIFEST.txt: node name, UTC generation time, sha256
# of the live /usr/local/bin/swift-proxy-server at backup time, and a
# per-file sha256 of everything packed. A sidecar <bundle>.sha256 is written
# next to the bundle for cross-site verification.
#
# Defensive exclusions: *.so files and anything with an ELF magic header are
# dropped from the stage and logged in meta/excluded-files.txt. The config
# plane should contain none; the filter proves it.
#
# SECRET DISCIPLINE (read this): bundles contain swift_hash_path_prefix/
# suffix and tempauth credentials. Bundles must NEVER be committed to git,
# never uploaded to Google Drive or any cloud storage. Storage locations are
# the lab hosts themselves plus the operator's offline copy. Only this
# script and the documentation belong in the repo.
#
# Usage (run as root on the node itself):
#   dr-backup.sh --outdir /root/dr-backups/20260817 [--stamp 20260817T130000Z]
#
# The optional --stamp lets one collection run share a single timestamp
# across all nodes so the four bundles line up.
#
set -euo pipefail

OUTDIR=""
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"

while [ $# -gt 0 ]; do
  case "$1" in
    --outdir) OUTDIR="$2"; shift 2 ;;
    --stamp)  STAMP="$2";  shift 2 ;;
    -h|--help) sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

[ -n "$OUTDIR" ] || { echo "--outdir is required" >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || { echo "must run as root" >&2; exit 2; }
mkdir -p "$OUTDIR"

NODE="$(hostname -s)"
NAME="dr-config-${NODE}-${STAMP}"
WORK="$(mktemp -d "/tmp/${NAME}.stage.XXXXXX")"
STAGE="${WORK}/${NAME}"
mkdir -p "${STAGE}/meta"
trap 'rm -rf "$WORK"' EXIT

log() { printf '[dr-backup] %s\n' "$*"; }

# ---- 1. copy config-plane trees, preserving /etc/... layout ---------------
copy_tree() {
  local src="$1"
  if [ ! -d "$src" ]; then log "skip (absent): $src"; return 0; fi
  mkdir -p "${STAGE}$(dirname "$src")"
  cp -a "$src" "${STAGE}$(dirname "$src")/"
  log "copied: $src"
}

copy_tree /etc/swift
copy_tree /etc/pyswift
copy_tree /etc/haproxy
copy_tree /etc/keepalived

mkdir -p "${STAGE}/etc/systemd/system"
found_units=0
for u in /etc/systemd/system/swift* /etc/systemd/system/pyswift*; do
  [ -e "$u" ] || continue
  cp -a "$u" "${STAGE}/etc/systemd/system/"
  found_units=$((found_units+1))
done
log "systemd units copied: $found_units"

# ---- 2. metadata captures --------------------------------------------------
crontab -l > "${STAGE}/meta/crontab-root.txt" 2>/dev/null \
  || echo "(no crontab for root)" > "${STAGE}/meta/crontab-root.txt"

ls -la /usr/local/bin > "${STAGE}/meta/usr-local-bin.inventory.txt"
find /usr/local/bin -maxdepth 1 -type f -print0 | sort -z \
  | xargs -0 -r sha256sum > "${STAGE}/meta/usr-local-bin.sha256"

LIVE_PROXY_SHA="(missing)"
if [ -f /usr/local/bin/swift-proxy-server ]; then
  LIVE_PROXY_SHA="$(sha256sum /usr/local/bin/swift-proxy-server | awk '{print $1}')"
fi

# ---- 3. defensive exclusion of ELF / .so / non-regular files --------------
EXCLUDED="${WORK}/excluded.txt"; : > "$EXCLUDED"
while IFS= read -r -d '' f; do
  case "$f" in
    *.so|*.so.*) echo "SO   ${f#"$STAGE"}" >> "$EXCLUDED"; rm -f "$f"; continue ;;
  esac
  if [ "$(head -c4 "$f" 2>/dev/null | od -An -tx1 | tr -d ' \n')" = "7f454c46" ]; then
    echo "ELF  ${f#"$STAGE"}" >> "$EXCLUDED"; rm -f "$f"
  fi
done < <(find "$STAGE" -type f -print0)
# drop sockets/fifos/devices if any slipped in via cp -a
find "$STAGE" ! -type f ! -type d ! -type l -exec rm -f {} + 2>/dev/null || true
if [ -s "$EXCLUDED" ]; then
  cp "$EXCLUDED" "${STAGE}/meta/excluded-files.txt"
  log "excluded $(wc -l < "$EXCLUDED") file(s) (ELF/.so) -- see meta/excluded-files.txt"
else
  log "excluded 0 files (config plane is clean of ELF/.so)"
fi

# ---- 4. MANIFEST -----------------------------------------------------------
{
  echo "bundle:            ${NAME}.tar.gz"
  echo "node:              ${NODE}"
  echo "generated_utc:     $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "live_proxy_sha256: ${LIVE_PROXY_SHA}  (/usr/local/bin/swift-proxy-server)"
  echo "tool:              tools/dr/dr-backup.sh"
  echo ""
  echo "== per-file sha256 =="
  (cd "$STAGE" && find . -type f ! -name MANIFEST.txt -print0 | sort -z | xargs -0 -r sha256sum)
} > "${STAGE}/MANIFEST.txt"

# ---- 5. pack ---------------------------------------------------------------
BUNDLE="${OUTDIR}/${NAME}.tar.gz"
tar -C "$WORK" -czf "$BUNDLE" "$NAME"
( cd "$OUTDIR" && sha256sum "${NAME}.tar.gz" > "${NAME}.tar.gz.sha256" )

log "bundle:  $BUNDLE"
log "sha256:  $(awk '{print $1}' "${BUNDLE}.sha256")"
log "size:    $(du -h "$BUNDLE" | awk '{print $1}')"
