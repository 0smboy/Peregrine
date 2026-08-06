#!/usr/bin/env bash
# apply-vip-tls-pem.sh — production-operator one-shot for HAProxy VIP TLS PEM.
#
# Installs a cert+key concatenated PEM to the path expected by bundle-rust
# rust_haproxy (`haproxy_tls_pem`, default /etc/haproxy/haproxyCA.pem), then
# reloads/restarts haproxy safely.
#
# Does NOT commit secrets. Does NOT auto-touch Contabo: remote apply only when
# you pass explicit --ssh hosts (or print remote commands with --print-commands).
#
# Contract:
#   lb_mode=https
#   haproxy_tls_pem=/etc/haproxy/haproxyCA.pem   (override with --dest)
#   haproxy_tls_pem_src=<controller path>        (for full swift-deploy apply)
#
# Usage:
#   # Validate only
#   ./tools/ops/apply-vip-tls-pem.sh --pem /secure/vip.pem --check
#
#   # Local install + reload
#   sudo SWIFT_TLS_PEM=/secure/vip.pem ./tools/ops/apply-vip-tls-pem.sh --local --reload
#
#   # Remote install on LB hosts (operator must confirm SSH targets)
#   ./tools/ops/apply-vip-tls-pem.sh --pem /secure/vip.pem \
#       --ssh swift1,swift2,swift3,swift4 --reload
#
#   # Dry-run / print exact remote systemctl steps without applying
#   ./tools/ops/apply-vip-tls-pem.sh --pem /secure/vip.pem \
#       --ssh swift1 --print-commands --dry-run
#
#   # Contabo four-node (explicit host list only — no auto-discovery)
#   ./tools/ops/apply-vip-tls-pem.sh --pem /secure/vip.pem \
#       --ssh swift1,swift2,swift3,swift4 --reload --dry-run --print-commands
#   # same with public IPs from tools/CONTABO-CLUSTER.md:
#   #   --ssh 169.58.108.85,169.58.108.86,169.58.108.87,169.58.108.121
#
# Env:
#   SWIFT_TLS_PEM       Default source PEM if --pem omitted
#   HAPROXY_TLS_PEM     Default dest path (default /etc/haproxy/haproxyCA.pem)
#   SSH_OPTS            Extra ssh options (default: BatchMode=yes ConnectTimeout=12)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

DEFAULT_DEST="${HAPROXY_TLS_PEM:-/etc/haproxy/haproxyCA.pem}"
DEFAULT_SSH_OPTS="${SSH_OPTS:--o BatchMode=yes -o ConnectTimeout=12 -o StrictHostKeyChecking=accept-new}"

PEM_SRC="${SWIFT_TLS_PEM:-}"
DEST="$DEFAULT_DEST"
MODE=""                 # local | ssh | print
SSH_HOSTS=()
DO_RELOAD=0
DRY_RUN=0
CHECK_ONLY=0
PRINT_COMMANDS=0
BACKUP=1
WRITE_ROTATION=1

log()  { printf '\033[1;36m== %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32mOK\033[0m  %s\n' "$*"; }
warn() { printf '\033[1;33mWARN\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mERROR\033[0m %s\n' "$*" >&2; exit 1; }
note() { printf '  %s\n' "$*"; }

# mktemp templates must end in XXXXXX (macOS / BSD).
mktemp_path() {
  local prefix="${1:-tls-tmp}"
  mktemp "${TMPDIR:-/tmp}/${prefix}.XXXXXX"
}

usage() {
  cat <<'EOF'
Usage: apply-vip-tls-pem.sh [options]

Install/validate HAProxy VIP TLS PEM (cert+key concatenated).

Options:
  --pem PATH           Source PEM (or env SWIFT_TLS_PEM)
  --dest PATH          Dest on target (default: /etc/haproxy/haproxyCA.pem
                       or env HAPROXY_TLS_PEM)
  --local              Install on this host
  --ssh HOST[,HOST…]   Install via SSH to listed hosts (explicit only;
                       Contabo: swift1,swift2,swift3,swift4 or public IPs
                       from tools/CONTABO-CLUSTER.md — never auto-discovered)
  --reload             Reload/restart haproxy after install
  --check              Validate PEM only; no install
  --dry-run            Print actions; do not write, scp, or restart
  --print-commands     Print exact install/systemctl commands (no mutation;
                       combine with --ssh + --dry-run for Contabo runbooks)
  --no-backup          Skip timestamped backup of existing dest PEM
  --no-rotation-log    Skip /etc/haproxy/TLS-ROTATION.txt stamp
  -h, --help           This help

Env:
  SWIFT_TLS_PEM    Source PEM path
  HAPROXY_TLS_PEM  Dest PEM path
  SSH_OPTS         Extra ssh/scp options

Examples:
  ./tools/ops/apply-vip-tls-pem.sh --pem ./vip.fullchain.pem --check
  sudo SWIFT_TLS_PEM=./vip.fullchain.pem ./tools/ops/apply-vip-tls-pem.sh --local --reload
  ./tools/ops/apply-vip-tls-pem.sh --pem ./vip.fullchain.pem --ssh swift1,swift2 --reload
  ./tools/ops/apply-vip-tls-pem.sh --pem ./vip.fullchain.pem --ssh swift1 --print-commands
  ./tools/ops/apply-vip-tls-pem.sh --pem /secure/vip.pem \
      --ssh swift1,swift2,swift3,swift4 --reload --dry-run --print-commands
  ./tools/ops/apply-vip-tls-pem.sh --pem /secure/vip.pem \
      --ssh 169.58.108.85,169.58.108.86,169.58.108.87,169.58.108.121 \
      --reload --dry-run --print-commands

Safety:
  - No secrets are written into the repo.
  - Contabo is never touched unless you pass --ssh <hosts>.
  - Prefer --check + --dry-run + --print-commands before live apply.
  - --dry-run never scp/ssh-mutates; --print-commands is documentation only.
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

while [ $# -gt 0 ]; do
  case "$1" in
    --pem) PEM_SRC="${2:?--pem requires path}"; shift 2 ;;
    --dest) DEST="${2:?--dest requires path}"; shift 2 ;;
    --local) MODE="local"; shift ;;
    --ssh)
      MODE="ssh"
      parse_hosts "${2:?--ssh requires host list}"
      shift 2
      ;;
    --reload) DO_RELOAD=1; shift ;;
    --check) CHECK_ONLY=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    --print-commands) PRINT_COMMANDS=1; shift ;;
    --no-backup) BACKUP=0; shift ;;
    --no-rotation-log) WRITE_ROTATION=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown arg: $1 (try --help)" ;;
  esac
done

# ---------- PEM validation ----------
validate_pem() {
  local pem="$1"
  [ -n "$pem" ] || die "no PEM path (pass --pem or set SWIFT_TLS_PEM)"
  [ -f "$pem" ] || die "PEM file missing: $pem"
  [ -s "$pem" ] || die "PEM file empty: $pem"

  if ! grep -q 'BEGIN CERTIFICATE' "$pem"; then
    die "PEM missing BEGIN CERTIFICATE block: $pem"
  fi
  if ! grep -qE 'BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY' "$pem"; then
    die "PEM missing PRIVATE KEY block (need cert+key concatenated): $pem"
  fi

  if command -v openssl >/dev/null 2>&1; then
    # Extract first cert for parse check
    local tmp ktmp
    tmp="$(mktemp_path tls-pem-cert)"
    ktmp="$(mktemp_path tls-pem-key)"
    # shellcheck disable=SC2064
    trap "rm -f '$tmp' '$ktmp'" RETURN
    awk '
      /BEGIN CERTIFICATE/ {p=1}
      p {print}
      /END CERTIFICATE/ {exit}
    ' "$pem" >"$tmp"
    openssl x509 -in "$tmp" -noout >/dev/null 2>&1 \
      || die "openssl x509 -noout failed (cert unreadable): $pem"
    # Optional: ensure private key parses (may be RSA/EC/PKCS8)
    if grep -q 'BEGIN.*PRIVATE KEY' "$pem"; then
      awk '
        /BEGIN .*PRIVATE KEY/ {p=1}
        p {print}
        /END .*PRIVATE KEY/ {exit}
      ' "$pem" >"$ktmp"
      if ! openssl pkey -in "$ktmp" -noout 2>/dev/null \
        && ! openssl rsa -in "$ktmp" -check -noout 2>/dev/null \
        && ! openssl ec -in "$ktmp" -check -noout 2>/dev/null; then
        warn "openssl could not fully verify private key format (continuing if PEM markers present)"
      fi
    fi
    rm -f "$tmp" "$ktmp"
    trap - RETURN
    ok "openssl x509 parse OK"
  else
    warn "openssl not found — marker check only (BEGIN CERTIFICATE + PRIVATE KEY)"
  fi

  ok "PEM validated: $pem"
}

print_cert_summary() {
  local pem="$1"
  if ! command -v openssl >/dev/null 2>&1; then
    return 0
  fi
  local tmp subj iss
  tmp="$(mktemp_path tls-pem-cert)"
  awk '
    /BEGIN CERTIFICATE/ {p=1}
    p {print}
    /END CERTIFICATE/ {exit}
  ' "$pem" >"$tmp"
  subj="$(openssl x509 -in "$tmp" -noout -subject 2>/dev/null | sed 's/^subject=//')"
  iss="$(openssl x509 -in "$tmp" -noout -issuer 2>/dev/null | sed 's/^issuer=//')"
  note "subject: $subj"
  note "issuer:  $iss"
  note "dates:   $(openssl x509 -in "$tmp" -noout -dates 2>/dev/null | tr '\n' ' ')"
  if [ -n "$subj" ] && [ "$subj" = "$iss" ]; then
    note "kind:    self-signed (subject == issuer)"
  else
    note "kind:    not self-signed (subject != issuer) or chain leaf"
  fi
  rm -f "$tmp"
}

# ---------- install helpers ----------
remote_install_script() {
  local dest="$1"
  local do_reload="$2"
  local do_backup="$3"
  local do_rotation="$4"
  local dry_run="$5"
  cat <<REMOTE
set -euo pipefail
DEST='$dest'
DO_RELOAD='$do_reload'
DO_BACKUP='$do_backup'
DO_ROTATION='$do_rotation'
DRY_RUN='$dry_run'
STAGED="\${1:?staged pem path}"

if [ ! -f "\$STAGED" ] || [ ! -s "\$STAGED" ]; then
  echo "ERROR staged PEM missing: \$STAGED" >&2
  exit 1
fi
if ! grep -q 'BEGIN CERTIFICATE' "\$STAGED"; then
  echo "ERROR staged PEM has no certificate" >&2
  exit 1
fi
if ! grep -qE 'BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY' "\$STAGED"; then
  echo "ERROR staged PEM has no private key" >&2
  exit 1
fi

mkdir -p "\$(dirname "\$DEST")"
if [ "\$DRY_RUN" = 1 ]; then
  echo "DRY-RUN would install \$STAGED -> \$DEST (mode 0600)"
else
  if [ "\$DO_BACKUP" = 1 ] && [ -f "\$DEST" ]; then
    ts=\$(date -u +%Y%m%dT%H%M%SZ)
    cp -a "\$DEST" "\${DEST}.bak.\${ts}"
    echo "backed up existing PEM to \${DEST}.bak.\${ts}"
  fi
  install -m 0600 "\$STAGED" "\$DEST"
  echo "installed \$DEST"
  if [ "\$DO_ROTATION" = 1 ]; then
    {
      echo "TLS-OPERATOR-PEM \$(date -u +%Y-%m-%dT%H:%M:%SZ) host=\$(hostname -f 2>/dev/null || hostname)"
      echo "dest=\$DEST"
    } >> /etc/haproxy/TLS-ROTATION.txt
    chmod 0644 /etc/haproxy/TLS-ROTATION.txt 2>/dev/null || true
  fi
fi

if [ "\$DO_RELOAD" = 1 ]; then
  if command -v haproxy >/dev/null 2>&1 && [ -f /etc/haproxy/haproxy.cfg ]; then
    if [ "\$DRY_RUN" = 1 ]; then
      echo "DRY-RUN would: haproxy -c -f /etc/haproxy/haproxy.cfg"
    else
      haproxy -c -f /etc/haproxy/haproxy.cfg
    fi
  fi
  if [ "\$DRY_RUN" = 1 ]; then
    echo "DRY-RUN would: systemctl reload haproxy || systemctl restart haproxy"
  else
    if systemctl is-active haproxy >/dev/null 2>&1; then
      systemctl reload haproxy 2>/dev/null || systemctl restart haproxy
    else
      systemctl enable --now haproxy
    fi
    systemctl is-active haproxy
  fi
fi
REMOTE
}

print_operator_commands() {
  local pem="$1"
  local dest="$2"
  local hosts_csv="${3:-<host>}"
  local dest_dir
  dest_dir="$(dirname "$dest")"
  local stamp
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  cat <<EOF

# ---- exact operator commands (no auto-apply) ----
# 1) Validate locally
openssl x509 -in <(awk '/BEGIN CERTIFICATE/{p=1} p; /END CERTIFICATE/{exit}' '$pem') -noout -subject -dates

# 2) Per-host install (repeat for each of: $hosts_csv)
HOST=<one-of:$hosts_csv>
scp $DEFAULT_SSH_OPTS '$pem' "\$HOST:/tmp/haproxyCA.pem.new"
ssh $DEFAULT_SSH_OPTS "\$HOST" bash -s <<'REMOTE'
set -euo pipefail
DEST='$dest'
mkdir -p '$dest_dir'
if [ -f "\$DEST" ]; then cp -a "\$DEST" "\$DEST.bak.$stamp"; fi
install -m 0600 /tmp/haproxyCA.pem.new "\$DEST"
rm -f /tmp/haproxyCA.pem.new
haproxy -c -f /etc/haproxy/haproxy.cfg
systemctl reload haproxy || systemctl restart haproxy
systemctl is-active haproxy
echo "TLS-OPERATOR-PEM $stamp" >> /etc/haproxy/TLS-ROTATION.txt
REMOTE

# 3) Client smoke (VIP example Contabo)
# curl -fsS --cacert <ca-or-fullchain> https://10.0.0.10:8085/healthcheck
# # or temporarily: curl -kfsS https://10.0.0.10:8085/healthcheck

# 4) Full deploy-rs path (optional; after PEM is controller-local)
# set group_vars: lb_mode=https
#                 haproxy_tls_pem_src=/secure/path/to/vip.pem
#                 haproxy_tls_self_signed=false
#                 haproxy_tls_pem=/etc/haproxy/haproxyCA.pem
# then: swift-deploy plan/apply (stack=rust) — prefer plan first
EOF
}

install_local() {
  local pem="$1"
  local dest="$2"
  if [ "$DRY_RUN" = 1 ]; then
    note "DRY-RUN would: install -m 0600 $pem $dest"
    if [ "$DO_RELOAD" = 1 ]; then
      note "DRY-RUN would: haproxy -c -f /etc/haproxy/haproxy.cfg"
      note "DRY-RUN would: systemctl reload haproxy || systemctl restart haproxy"
    fi
    return 0
  fi
  mkdir -p "$(dirname "$dest")"
  if [ "$BACKUP" = 1 ] && [ -f "$dest" ]; then
    local bak="${dest}.bak.$(date -u +%Y%m%dT%H%M%SZ)"
    cp -a "$dest" "$bak"
    ok "backup $bak"
  fi
  install -m 0600 "$pem" "$dest"
  ok "installed $dest"
  if [ "$WRITE_ROTATION" = 1 ]; then
    mkdir -p /etc/haproxy
    {
      echo "TLS-OPERATOR-PEM $(date -u +%Y-%m-%dT%H:%M:%SZ) host=$(hostname -f 2>/dev/null || hostname)"
      echo "dest=$dest"
    } >> /etc/haproxy/TLS-ROTATION.txt
    chmod 0644 /etc/haproxy/TLS-ROTATION.txt 2>/dev/null || true
  fi
  if [ "$DO_RELOAD" = 1 ]; then
    if command -v haproxy >/dev/null 2>&1 && [ -f /etc/haproxy/haproxy.cfg ]; then
      haproxy -c -f /etc/haproxy/haproxy.cfg
      ok "haproxy -c OK"
    else
      warn "haproxy binary or cfg missing — skip config check"
    fi
    if command -v systemctl >/dev/null 2>&1; then
      if systemctl is-active haproxy >/dev/null 2>&1; then
        systemctl reload haproxy 2>/dev/null || systemctl restart haproxy
      else
        systemctl enable --now haproxy
      fi
      systemctl is-active haproxy >/dev/null
      ok "haproxy active"
    else
      warn "systemctl not available — start/reload haproxy manually"
      note "systemctl reload haproxy || systemctl restart haproxy"
    fi
  fi
}

install_ssh() {
  local pem="$1"
  local dest="$2"
  local host remote_sh
  [ "${#SSH_HOSTS[@]}" -gt 0 ] || die "--ssh requires at least one host"

  if [ "$DRY_RUN" = 1 ]; then
    for host in "${SSH_HOSTS[@]}"; do
      log "host $host (DRY-RUN — no scp/ssh mutation)"
      note "would: scp $DEFAULT_SSH_OPTS $pem $host:/tmp/haproxyCA.pem.new"
      note "would: scp $DEFAULT_SSH_OPTS <remote-install.sh> $host:/tmp/apply-vip-tls-pem.remote.sh"
      note "would: ssh $DEFAULT_SSH_OPTS $host 'bash /tmp/apply-vip-tls-pem.remote.sh /tmp/haproxyCA.pem.new; rm -f /tmp/haproxyCA.pem.new /tmp/apply-vip-tls-pem.remote.sh'"
      note "remote intent: dest=$dest reload=$DO_RELOAD backup=$BACKUP rotation=$WRITE_ROTATION"
      if [ "$DO_RELOAD" = 1 ]; then
        note "remote would: haproxy -c -f /etc/haproxy/haproxy.cfg"
        note "remote would: systemctl reload haproxy || systemctl restart haproxy"
      fi
    done
    ok "dry-run complete for ${#SSH_HOSTS[@]} host(s) — nothing applied"
    return 0
  fi

  remote_sh="$(mktemp_path tls-remote)"
  # shellcheck disable=SC2064
  trap "rm -f '$remote_sh'" RETURN
  remote_install_script "$dest" "$DO_RELOAD" "$BACKUP" "$WRITE_ROTATION" "$DRY_RUN" >"$remote_sh"

  for host in "${SSH_HOSTS[@]}"; do
    log "host $host"
    # shellcheck disable=SC2086
    scp $DEFAULT_SSH_OPTS "$pem" "$host:/tmp/haproxyCA.pem.new"
    # shellcheck disable=SC2086
    scp $DEFAULT_SSH_OPTS "$remote_sh" "$host:/tmp/apply-vip-tls-pem.remote.sh"
    # shellcheck disable=SC2086
    ssh $DEFAULT_SSH_OPTS "$host" "bash /tmp/apply-vip-tls-pem.remote.sh /tmp/haproxyCA.pem.new; rm -f /tmp/haproxyCA.pem.new /tmp/apply-vip-tls-pem.remote.sh"
    ok "applied on $host"
  done
}

# ---------- main ----------
validate_pem "$PEM_SRC"
print_cert_summary "$PEM_SRC"

if [ "$CHECK_ONLY" = 1 ]; then
  ok "check-only complete (no install)"
  exit 0
fi

if [ "$PRINT_COMMANDS" = 1 ]; then
  local_hosts="local"
  if [ "${#SSH_HOSTS[@]}" -gt 0 ]; then
    local_hosts=$(IFS=,; echo "${SSH_HOSTS[*]}")
  elif [ "$MODE" = "local" ]; then
    local_hosts="localhost"
  fi
  print_operator_commands "$PEM_SRC" "$DEST" "$local_hosts"
  # print-only path: no --local/--ssh → documentation only
  if [ -z "$MODE" ]; then
    ok "printed commands only (pass --local or --ssh to apply; --dry-run never mutates)"
    exit 0
  fi
fi

if [ -z "$MODE" ]; then
  die "specify --local or --ssh HOSTS (or --check / --print-commands). Refusing implicit Contabo apply."
fi

case "$MODE" in
  local)
    log "local install dest=$DEST dry_run=$DRY_RUN reload=$DO_RELOAD"
    install_local "$PEM_SRC" "$DEST"
    ;;
  ssh)
    log "ssh install hosts=${SSH_HOSTS[*]} dest=$DEST dry_run=$DRY_RUN reload=$DO_RELOAD"
    install_ssh "$PEM_SRC" "$DEST"
    ;;
  *)
    die "internal: unknown mode $MODE"
    ;;
esac

if [ "$DRY_RUN" = 1 ]; then
  ok "done (dry-run — no PEM installed, no service restart)"
else
  ok "done"
fi
note "bundle-rust expects haproxy_tls_pem=$DEST and lb_mode=https"
note "for full deploy-rs apply set haproxy_tls_pem_src on the controller (no secrets in git)"
note "repo helper docs: $REPO_ROOT/tools/ops/README.md"
note "Contabo inventory dry-run (read-only): $REPO_ROOT/tools/ops/contabo-tls-dry-run.sh"
