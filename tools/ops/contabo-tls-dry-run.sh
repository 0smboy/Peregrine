#!/usr/bin/env bash
# contabo-tls-dry-run.sh — read-only Contabo VIP TLS inventory.
#
# SSHs to Contabo HAProxy nodes (BatchMode), reports live PEM subject/issuer
# (self-signed vs not), shows haproxy bind ssl lines, and prints the exact
# operator apply command — WITHOUT applying any PEM or restarting services.
#
# Hosts (priority):
#   1) CLI: --hosts H1,H2,...  or positional HOSTS
#   2) env CONTABO_TLS_HOSTS
#   3) parse tools/CONTABO-CLUSTER.md Public SSH column
#   4) fallback: 169.58.108.85,86,87,121 (swift1–4)
#
# Usage:
#   ./tools/ops/contabo-tls-dry-run.sh
#   ./tools/ops/contabo-tls-dry-run.sh --hosts swift1,swift2,swift3,swift4
#   ./tools/ops/contabo-tls-dry-run.sh --out tools/test-results/tls-dry-run-YYYYMMDD
#   PEM_PLACEHOLDER=/secure/vip.pem ./tools/ops/contabo-tls-dry-run.sh
#
# Safety: never scp PEM, never install, never systemctl reload/restart.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CLUSTER_MD="${CONTABO_CLUSTER_MD:-$REPO_ROOT/tools/CONTABO-CLUSTER.md}"
APPLY_SCRIPT="$REPO_ROOT/tools/ops/apply-vip-tls-pem.sh"
DEFAULT_SSH_OPTS="${SSH_OPTS:--o BatchMode=yes -o ConnectTimeout=12 -o StrictHostKeyChecking=accept-new}"
DEST_PEM="${HAPROXY_TLS_PEM:-/etc/haproxy/haproxyCA.pem}"
PEM_PLACEHOLDER="${PEM_PLACEHOLDER:-/secure/vip.fullchain.pem}"
HAPROXY_CFG="${HAPROXY_CFG:-/etc/haproxy/haproxy.cfg}"

OUT_DIR=""
HOSTS_RAW="${CONTABO_TLS_HOSTS:-}"
SSH_HOSTS=()
SSH_OK=0
SSH_FAIL=0
ANY_SELF_SIGNED=0
ANY_OPERATOR_LIKE=0

log()  { printf '\033[1;36m== %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32mOK\033[0m  %s\n' "$*"; }
warn() { printf '\033[1;33mWARN\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mERROR\033[0m %s\n' "$*" >&2; exit 1; }
note() { printf '  %s\n' "$*"; }

usage() {
  cat <<'EOF'
Usage: contabo-tls-dry-run.sh [options] [HOSTS]

Read-only Contabo TLS probe (PEM subject/issuer, haproxy ssl binds).
Prints exact apply-vip-tls-pem.sh command; NEVER applies.

Options:
  --hosts H1,H2,…   Explicit SSH targets (aliases or IPs)
  --out DIR         Write per-host logs + SUMMARY.md under DIR
  --dest PATH       Remote PEM path (default /etc/haproxy/haproxyCA.pem)
  --pem-placeholder PATH  Path shown in printed apply command
  -h, --help        This help

Env:
  CONTABO_TLS_HOSTS   Comma-separated hosts
  CONTABO_CLUSTER_MD  Override path to CONTABO-CLUSTER.md
  SSH_OPTS            Extra ssh options
  PEM_PLACEHOLDER     Path embedded in printed apply command
  HAPROXY_TLS_PEM     Remote dest PEM path

Examples:
  ./tools/ops/contabo-tls-dry-run.sh
  ./tools/ops/contabo-tls-dry-run.sh --hosts 169.58.108.85,169.58.108.86,169.58.108.87,169.58.108.121
  ./tools/ops/contabo-tls-dry-run.sh --out tools/test-results/tls-dry-run-20260806
EOF
}

parse_hosts() {
  local raw="$1"
  local IFS=','
  # shellcheck disable=SC2206
  local parts=($raw)
  local h
  for h in "${parts[@]}"; do
    h="$(echo "$h" | tr -d '[:space:]')"
    [ -n "$h" ] || continue
    SSH_HOSTS+=("$h")
  done
}

# Prefer ssh-config aliases (swift1–4) when Endpoints table is present; else Public SSH IPs only.
hosts_from_cluster_md() {
  local md="$1"
  [ -f "$md" ] || return 1
  local names ips line pub
  names="$(
    grep -E '^\|[[:space:]]*swift[0-9]+' "$md" 2>/dev/null \
      | grep -oE 'swift[0-9]+' \
      | awk '!seen[$0]++' || true
  )"
  if [ -n "$names" ]; then
    local n
    while IFS= read -r n; do
      [ -n "$n" ] || continue
      SSH_HOSTS+=("$n")
    done <<<"$names"
    [ "${#SSH_HOSTS[@]}" -gt 0 ] && return 0
  fi
  # Public SSH column only (3rd pipe-field): | node | `public` | proxy | storage | repl |
  ips=""
  while IFS= read -r line; do
    pub="$(printf '%s\n' "$line" | awk -F'|' '{
      gsub(/[`[:space:]]/, "", $3)
      if ($3 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) print $3
    }')"
    [ -n "$pub" ] || continue
    ips="${ips}${ips:+$'\n'}${pub}"
  done < <(grep -E '^\|[[:space:]]*swift[0-9]+' "$md" 2>/dev/null || true)
  [ -n "$ips" ] || return 1
  local ip
  while IFS= read -r ip; do
    [ -n "$ip" ] || continue
    SSH_HOSTS+=("root@$ip")
  done <<<"$ips"
  [ "${#SSH_HOSTS[@]}" -gt 0 ]
}

while [ $# -gt 0 ]; do
  case "$1" in
    --hosts) HOSTS_RAW="${2:?--hosts requires list}"; shift 2 ;;
    --out) OUT_DIR="${2:?--out requires dir}"; shift 2 ;;
    --dest) DEST_PEM="${2:?--dest requires path}"; shift 2 ;;
    --pem-placeholder) PEM_PLACEHOLDER="${2:?}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    --*) die "unknown arg: $1 (try --help)" ;;
    *)
      if [ -n "$HOSTS_RAW" ]; then
        HOSTS_RAW="$HOSTS_RAW,$1"
      else
        HOSTS_RAW="$1"
      fi
      shift
      ;;
  esac
done

if [ -n "$HOSTS_RAW" ]; then
  parse_hosts "$HOSTS_RAW"
elif hosts_from_cluster_md "$CLUSTER_MD"; then
  note "hosts from $CLUSTER_MD"
else
  # Documented Contabo ssh-config aliases (maps to 169.58.108.85–87,121)
  parse_hosts "swift1,swift2,swift3,swift4"
  note "hosts fallback: swift1–4 (tools/CONTABO-CLUSTER.md not parseable)"
fi

[ "${#SSH_HOSTS[@]}" -gt 0 ] || die "no SSH hosts resolved"

# Bare IPv4 → root@IP (ssh config aliases like swift1 stay as-is)
_normalized=()
for h in "${SSH_HOSTS[@]}"; do
  if [[ "$h" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    _normalized+=("root@$h")
  else
    _normalized+=("$h")
  fi
done
SSH_HOSTS=("${_normalized[@]}")
unset _normalized

if [ -n "$OUT_DIR" ]; then
  mkdir -p "$OUT_DIR"
fi

# ---------- remote probe (read-only) ----------
remote_probe_script() {
  cat <<'REMOTE'
set -euo pipefail
DEST_PEM="${DEST_PEM:-/etc/haproxy/haproxyCA.pem}"
CFG="${HAPROXY_CFG:-/etc/haproxy/haproxy.cfg}"
echo "HOST=$(hostname -f 2>/dev/null || hostname)"
echo "DATE_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "--- PEM_PATH ---"
if [ -f "$DEST_PEM" ]; then
  ls -la "$DEST_PEM"
  echo "PEM_PRESENT=yes"
else
  echo "PEM_PRESENT=no"
  echo "missing: $DEST_PEM"
fi
echo "--- OPENSSL ---"
if [ -f "$DEST_PEM" ] && command -v openssl >/dev/null 2>&1; then
  # First cert only (ignore key block)
  TMP=$(mktemp /tmp/tls-probe.XXXXXX)
  awk '/BEGIN CERTIFICATE/{p=1} p{print} /END CERTIFICATE/{exit}' "$DEST_PEM" >"$TMP"
  SUBJ=$(openssl x509 -in "$TMP" -noout -subject 2>/dev/null | sed 's/^subject=//')
  ISS=$(openssl x509 -in "$TMP" -noout -issuer 2>/dev/null | sed 's/^issuer=//')
  DATES=$(openssl x509 -in "$TMP" -noout -dates 2>/dev/null | tr '\n' ' ')
  echo "subject=$SUBJ"
  echo "issuer=$ISS"
  echo "dates=$DATES"
  if [ -n "$SUBJ" ] && [ "$SUBJ" = "$ISS" ]; then
    echo "kind=self-signed"
  else
    echo "kind=not-self-signed"
  fi
  # Lab fingerprint heuristics (not cryptographic trust)
  if echo "$SUBJ" | grep -qiE 'Contabo-LAB|self.?signed|O=Contabo'; then
    echo "lab_marker=yes"
  else
    echo "lab_marker=no"
  fi
  rm -f "$TMP"
else
  echo "subject="
  echo "issuer="
  echo "dates="
  echo "kind=unknown"
  echo "lab_marker=unknown"
fi
echo "--- HAPROXY_BIND_SSL ---"
if [ -f "$CFG" ]; then
  grep -nE 'bind[[:space:]].*ssl|ssl crt' "$CFG" || echo "(no ssl bind lines)"
else
  echo "missing cfg: $CFG"
fi
echo "--- HAPROXY_UNIT ---"
systemctl is-active haproxy 2>/dev/null || echo "haproxy-state=unknown"
echo "--- TLS_ROTATION ---"
if [ -f /etc/haproxy/TLS-ROTATION.txt ]; then
  tail -n 5 /etc/haproxy/TLS-ROTATION.txt
else
  echo "(no TLS-ROTATION.txt)"
fi
REMOTE
}

ssh_probe() {
  local host="$1"
  # shellcheck disable=SC2086
  remote_probe_script | ssh $DEFAULT_SSH_OPTS "$host" \
    "DEST_PEM=$(printf %q "$DEST_PEM") HAPROXY_CFG=$(printf %q "$HAPROXY_CFG") bash -s"
}

# ---------- main ----------
log "Contabo TLS dry-run (READ-ONLY)"
note "hosts: ${SSH_HOSTS[*]}"
note "dest:  $DEST_PEM"
note "ssh:   $DEFAULT_SSH_OPTS"
note "apply: NEVER — print commands only"
echo

declare -a SUMMARY_ROWS=()
HOSTS_CSV=$(IFS=,; echo "${SSH_HOSTS[*]}")

for host in "${SSH_HOSTS[@]}"; do
  log "probe $host"
  out=""
  rc=0
  set +e
  out="$(ssh_probe "$host" 2>&1)"
  rc=$?
  set -e
  if [ "$rc" -ne 0 ]; then
    warn "SSH failed host=$host rc=$rc"
    SSH_FAIL=$((SSH_FAIL + 1))
    SUMMARY_ROWS+=("| $host | SSH_FAIL | - | - | - |")
    if [ -n "$OUT_DIR" ]; then
      safe="$(echo "$host" | tr '/:@' '___')"
      {
        echo "host=$host"
        echo "status=SSH_FAIL"
        echo "rc=$rc"
        echo "$out"
      } >"$OUT_DIR/host-${safe}.txt"
    fi
    echo "$out"
    echo
    continue
  fi
  SSH_OK=$((SSH_OK + 1))

  subj="$(echo "$out" | sed -n 's/^subject=//p' | head -1)"
  iss="$(echo "$out" | sed -n 's/^issuer=//p' | head -1)"
  kind="$(echo "$out" | sed -n 's/^kind=//p' | head -1)"
  pem_present="$(echo "$out" | sed -n 's/^PEM_PRESENT=//p' | head -1)"
  lab="$(echo "$out" | sed -n 's/^lab_marker=//p' | head -1)"
  binds="$(echo "$out" | sed -n '/^--- HAPROXY_BIND_SSL ---$/,/^--- /p' | grep -E 'bind|ssl crt' || true)"

  if [ "$kind" = "self-signed" ] || [ "$lab" = "yes" ]; then
    ANY_SELF_SIGNED=1
  fi
  if [ "$kind" = "not-self-signed" ] && [ "$lab" = "no" ]; then
    ANY_OPERATOR_LIKE=1
  fi

  note "PEM_PRESENT=$pem_present kind=$kind"
  note "subject: $subj"
  note "issuer:  $iss"
  if [ -n "$binds" ]; then
    note "bind ssl:"
    while IFS= read -r bl; do
      note "  $bl"
    done <<<"$binds"
  fi

  SUMMARY_ROWS+=("| $host | OK | ${pem_present:-?} | ${kind:-?} | \`${subj:--}\` |")

  if [ -n "$OUT_DIR" ]; then
    safe="$(echo "$host" | tr '/:@' '___')"
    printf '%s\n' "$out" >"$OUT_DIR/host-${safe}.txt"
  fi
  echo "$out"
  echo
done

# Exact operator apply command (documentation only — not executed)
APPLY_CMD="./tools/ops/apply-vip-tls-pem.sh --pem $PEM_PLACEHOLDER --ssh $HOSTS_CSV --reload"
APPLY_DRY="./tools/ops/apply-vip-tls-pem.sh --pem $PEM_PLACEHOLDER --ssh $HOSTS_CSV --reload --dry-run --print-commands"

log "exact apply command for operator PEM (NOT executed)"
cat <<EOF

# Validate PEM on operator workstation first:
$APPLY_SCRIPT --pem $PEM_PLACEHOLDER --check

# Dry-run + print remote commands (still no mutation if --dry-run):
$APPLY_DRY

# Live apply ONLY after operator confirms targets + PEM trust:
$APPLY_CMD

# Equivalent one-liner from repo root:
cd $REPO_ROOT && $APPLY_CMD

EOF

# Verdict
VERDICT="UNKNOWN"
if [ "$SSH_OK" -eq 0 ]; then
  VERDICT="SSH_UNAVAILABLE"
elif [ "$ANY_OPERATOR_LIKE" -eq 1 ] && [ "$ANY_SELF_SIGNED" -eq 0 ]; then
  VERDICT="OPERATOR_LIKE_PEM_PRESENT (still verify trust store / no curl -k)"
elif [ "$ANY_SELF_SIGNED" -eq 1 ]; then
  VERDICT="LAB_SELF_SIGNED — PRODUCTION-GO-LIVE BLOCKED until operator PEM"
else
  VERDICT="PROBED — review per-host subject/issuer"
fi

log "verdict: $VERDICT"
ok "probed SSH_OK=$SSH_OK SSH_FAIL=$SSH_FAIL (no PEM applied, no service restart)"

if [ -n "$OUT_DIR" ]; then
  {
    echo "# Contabo TLS dry-run · $(date -u +%Y-%m-%d)"
    echo
    echo "**Mode:** read-only SSH (\`BatchMode\`). **No PEM apply. No service restart.**"
    echo
    echo "**Verdict:** $VERDICT"
    echo
    echo "## Hosts"
    echo
    echo "| Host | SSH | PEM | Kind | Subject |"
    echo "|------|-----|-----|------|---------|"
    for row in "${SUMMARY_ROWS[@]}"; do
      echo "$row"
    done
    echo
    echo "## HAProxy dest"
    echo
    echo "- Path: \`$DEST_PEM\`"
    echo "- Cluster doc: \`$CLUSTER_MD\`"
    echo
    echo "## Exact operator apply (NOT executed this run)"
    echo
    echo '```sh'
    echo "# from repo root"
    echo "$APPLY_DRY"
    echo "# live (operator only):"
    echo "$APPLY_CMD"
    echo '```'
    echo
    echo "Helper: \`$APPLY_SCRIPT\`"
    echo
    echo "## Safety"
    echo
    echo "- \`contabo-tls-dry-run.sh\` never scp/installs PEM and never reloads haproxy."
    echo "- Live path requires explicit operator PEM + \`--ssh\` host confirmation."
    echo
    echo "## Per-host logs"
    echo
    for host in "${SSH_HOSTS[@]}"; do
      safe="$(echo "$host" | tr '/:@' '___')"
      echo "- \`host-${safe}.txt\`"
    done
  } >"$OUT_DIR/SUMMARY.md"
  ok "wrote $OUT_DIR/SUMMARY.md"
fi

# Non-zero only if every host failed SSH (probe unusable)
if [ "$SSH_OK" -eq 0 ]; then
  exit 2
fi
exit 0
