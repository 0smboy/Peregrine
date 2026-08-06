#!/usr/bin/env bash
# check-haproxy-tls-contract.sh — dry-run / static contract for P3-ops HAProxy TLS.
#
# No secrets, no SSH, no live cluster mutation. Safe for CI / pre-commit.
#
# Usage:
#   ./tools/ops/check-haproxy-tls-contract.sh
#   ./tools/ops/check-haproxy-tls-contract.sh /path/to/Peregrine
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
if [ "${1:-}" != "" ]; then
  ROOT="$(cd "$1" && pwd)"
fi

BUNDLE="$ROOT/swift-deploy-rs/bundle-rust"
HAPROXY_TASKS="$BUNDLE/roles/rust_haproxy/tasks/main.yml"
HAPROXY_CFG="$BUNDLE/roles/rust_haproxy/templates/haproxy.cfg.j2"
SAMPLE_ALL="$BUNDLE/config_sample/group_vars/all"
EXPAND="$BUNDLE/expand.yml"
WORKSPACE_RS="$ROOT/swift-deploy-rs/src/workspace.rs"
APPLY_SCRIPT="$ROOT/tools/ops/apply-vip-tls-pem.sh"

die() { printf 'FAIL %s\n' "$*" >&2; exit 1; }
ok()  { printf 'OK   %s\n' "$*"; }

[ -d "$BUNDLE" ] || die "bundle-rust missing: $BUNDLE"
[ -f "$HAPROXY_TASKS" ] || die "missing $HAPROXY_TASKS"
[ -f "$HAPROXY_CFG" ] || die "missing $HAPROXY_CFG"
[ -f "$SAMPLE_ALL" ] || die "missing $SAMPLE_ALL"
[ -x "$APPLY_SCRIPT" ] || [ -f "$APPLY_SCRIPT" ] || die "missing apply script $APPLY_SCRIPT"

# Template: https bind uses ssl crt + haproxy_tls_pem
grep -q 'lb_mode == "https"' "$HAPROXY_CFG" \
  || die "haproxy.cfg.j2 missing lb_mode==https branch"
grep -q 'ssl crt {{ haproxy_tls_pem' "$HAPROXY_CFG" \
  || die "haproxy.cfg.j2 missing ssl crt {{ haproxy_tls_pem }}"

# Tasks: operator PEM path + self-signed + refuse without material
grep -q 'haproxy_tls_pem_src' "$HAPROXY_TASKS" \
  || die "tasks missing haproxy_tls_pem_src"
grep -q 'install operator-provided HAProxy TLS PEM' "$HAPROXY_TASKS" \
  || die "tasks missing operator PEM install task"
grep -q 'generate self-signed HAProxy TLS material' "$HAPROXY_TASKS" \
  || die "tasks missing self-signed generation"
grep -q 'refuse https without TLS material path' "$HAPROXY_TASKS" \
  || die "tasks missing refuse-without-material guard"
grep -q 'haproxy_tls_self_signed' "$HAPROXY_TASKS" \
  || die "tasks missing haproxy_tls_self_signed"

# Sample vars
grep -q 'haproxy_tls_pem_src:' "$SAMPLE_ALL" \
  || die "config_sample missing haproxy_tls_pem_src"
grep -q 'haproxy_tls_pem:' "$SAMPLE_ALL" \
  || die "config_sample missing haproxy_tls_pem"
grep -q 'lb_mode:' "$SAMPLE_ALL" \
  || die "config_sample missing lb_mode"

# expand.yml still re-runs rust_haproxy (TLS material stays in expand path)
grep -q 'rust_haproxy' "$EXPAND" \
  || die "expand.yml missing rust_haproxy role"

# workspace emits TLS keys
grep -q 'haproxy_tls_pem_src' "$WORKSPACE_RS" \
  || die "workspace.rs missing haproxy_tls_pem_src emit"
grep -q 'haproxy_tls_self_signed' "$WORKSPACE_RS" \
  || die "workspace.rs missing haproxy_tls_self_signed emit"

# Operator script hygiene
grep -q 'set -euo pipefail' "$APPLY_SCRIPT" \
  || die "apply-vip-tls-pem.sh missing set -euo pipefail"
grep -q 'SWIFT_TLS_PEM' "$APPLY_SCRIPT" \
  || die "apply-vip-tls-pem.sh missing SWIFT_TLS_PEM support"
grep -q 'BEGIN CERTIFICATE' "$APPLY_SCRIPT" \
  || die "apply-vip-tls-pem.sh missing cert validation"
grep -q 'PRIVATE KEY' "$APPLY_SCRIPT" \
  || die "apply-vip-tls-pem.sh missing key validation"
# Must not hardcode live Contabo host lists as defaults (examples in comments OK).
# Flag executable lines that call ssh/scp against swift[1-4] without going through $host loop.
if grep -vE '^\s*(#|note |log |cat |printf )' "$APPLY_SCRIPT" \
  | grep -qE '(^|[[:space:]])(ssh|scp)[[:space:]].*swift[1-4]'; then
  die "apply script hardcodes Contabo ssh/scp swiftN outside comments (must require explicit --ssh)"
fi
# Default host array must stay empty / populated only from --ssh
if grep -qE 'SSH_HOSTS=\(swift' "$APPLY_SCRIPT"; then
  die "apply script pre-seeds SSH_HOSTS with Contabo names"
fi

ok "bundle-rust HAProxy TLS contract"
ok "workspace TLS var emit"
ok "operator apply script present + safe defaults"
printf '\nAll TLS contract checks passed (static dry-run).\n'
