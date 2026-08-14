#!/usr/bin/env bash
# Contabo VIP S3 live gate. A zero exit is reserved for a real two-origin
# strict-s3-parity PASS. One-origin probes are recorded as OPS_ONLY and never
# promoted to parity GREEN.
#
# Usage:
#   VIP=https://10.0.0.10:8085 ./tools/wave3-s3-contabo-gate.sh [EVIDENCE_DIR]
#
# Operational-only environment:
#   VIP                 Rust/Peregrine endpoint (default shown above)
#   FORCE_S3_SMOKE=1    run the unsigned one-origin S3 reachability probe
#   SKIP_META_CHECK=1   skip META_DIRTY file probe (not recommended)
#
# Strict parity environment (all required together):
#   PYTHON_S3_ENDPOINT       independent Python Swift S3 endpoint
#   PYTHON_S3_PROVENANCE     verified Python deployment provenance
#   RUST_S3_PROVENANCE       verified Rust deployment provenance
#   PEREGRINE_S3_PY_ACCESS / PEREGRINE_S3_PY_SECRET
#   PEREGRINE_S3_RS_ACCESS / PEREGRINE_S3_RS_SECRET
# Optional parity settings:
#   PYTHON_S3_INSECURE=1, PYTHON_S3_REGION, RUST_S3_REGION,
#   STRICT_S3_PARITY_RUNNER, PYTHON_BIN
#
# Exit contract:
#   0   PARITY_GREEN: strict-s3-parity ran, emitted a valid PASS report, rc=0
#   1   FAIL: operational/parity/cleanup failure
#   2   CONFIG_ERROR: invalid or incomplete configuration/evidence
#   3   BLOCKED: cluster health, metadata, or TempAuth precondition failed
#   4   OPS_ONLY: complete one-origin ops suite (extended matrix only)
#   5   PARTIAL: only a subset/reachability probe ran
#   6   SKIPPED: no live S3 probe or parity oracle ran
#   130 INTERRUPTED
set -euo pipefail

readonly EXIT_GREEN=0
readonly EXIT_FAIL=1
readonly EXIT_CONFIG=2
readonly EXIT_BLOCKED=3
readonly EXIT_OPS_ONLY=4
readonly EXIT_PARTIAL=5
readonly EXIT_SKIPPED=6

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EVID="${1:-$ROOT/tools/test-results/wave3-s3-l3b-prod-$(date -u +%Y%m%d)}"
VIP="${VIP:-https://10.0.0.10:8085}"
mkdir -p "$EVID"
OUT="$EVID/20-contabo-s3-gate.txt"
: >"$OUT"

log() { echo "$@" | tee -a "$OUT"; }

finish() {
  local verdict="$1"
  local claim="$2"
  local reason="$3"
  local rc="$4"
  log "VERDICT=$verdict CLAIM=$claim reason=$reason exit_code=$rc"
  {
    printf 'VERDICT=%s\n' "$verdict"
    printf 'CLAIM=%s\n' "$claim"
    printf 'REASON=%s\n' "$reason"
    printf 'EXIT_CODE=%s\n' "$rc"
  } >"$EVID/20-contabo-verdict.txt"
  exit "$rc"
}

is_bool01() { [[ "$1" == "0" || "$1" == "1" ]]; }

log "Contabo S3 gate @ $(date -u +%Y-%m-%dT%H:%M:%SZ)"
log "VIP=$VIP"
log "ZERO_EXIT_POLICY=strict_two_origin_parity_only"

case "$VIP" in
  http://*|https://*) ;;
  *) finish "CONFIG_ERROR" "OPS_ONLY" "invalid_vip_origin" "$EXIT_CONFIG" ;;
esac
if ! is_bool01 "${FORCE_S3_SMOKE:-0}"; then
  finish "CONFIG_ERROR" "OPS_ONLY" "invalid_FORCE_S3_SMOKE" "$EXIT_CONFIG"
fi
if ! is_bool01 "${SKIP_META_CHECK:-0}"; then
  finish "CONFIG_ERROR" "OPS_ONLY" "invalid_SKIP_META_CHECK" "$EXIT_CONFIG"
fi

# Load lab credentials without allowing set -e to bypass the verdict contract.
# shellcheck source=swift-rust/tools/lib/lab-auth.sh
source "$ROOT/swift-rust/tools/lib/lab-auth.sh"
if ! peregrine_load_lab_auth; then
  finish "CONFIG_ERROR" "OPS_ONLY" "lab_auth_missing" "$EXIT_CONFIG"
fi

# --- health ---
CURL_INSECURE=()
if [[ "$VIP" == https://* ]]; then CURL_INSECURE=(-k); fi
HTTP_CODE=$(curl -sS "${CURL_INSECURE[@]}" -o "$EVID/20-health-body.txt" -w "%{http_code}" --connect-timeout 5 --max-time 15 \
  "$VIP/info" || true)
HTTP_CODE="${HTTP_CODE:-000}"
[[ -z "$HTTP_CODE" || "$HTTP_CODE" == "000000" ]] && HTTP_CODE="000"
log "GET $VIP/info -> HTTP $HTTP_CODE"
if [[ "$HTTP_CODE" != "200" ]]; then
  finish "BLOCKED" "OPS_ONLY" "cluster_unhealthy" "$EXIT_BLOCKED"
fi

# Refuse to claim s3api is advertised (honest /info).
if grep -q '"s3api"' "$EVID/20-health-body.txt" 2>/dev/null; then
  log "WARN: /info unexpectedly contains s3api key (should stay silent)"
else
  log "OK: /info does not advertise s3api (ON-BY-CONFIG honesty)"
fi

# --- meta dirty probe (W0') ---
META_BLOCK=0
if [[ "${SKIP_META_CHECK:-0}" != "1" ]]; then
  for f in \
    "$ROOT/tools/test-results/wave0-meta-repair-"*/SUMMARY.md \
    "$ROOT/tools/test-results/w0-meta-repair-"*/SUMMARY.md \
    "$ROOT/tools/test-results/wave0-ab-"*/SUMMARY.md
  do
    [[ -f "$f" ]] || continue
    if grep -qiE 'META_DIRTY|BLOCKED|ghost|zombie' "$f" 2>/dev/null; then
      if grep -qiE 'META_CLEAN|verdict:.*green|META OK' "$f" 2>/dev/null; then
        continue
      fi
      log "META probe: possible dirty signal in $f"
      META_BLOCK=1
    fi
  done
fi
if [[ "$META_BLOCK" -eq 1 ]]; then
  finish "BLOCKED" "OPS_ONLY" "meta_not_clean" "$EXIT_BLOCKED"
fi

# --- TempAuth smoke (always; proves VIP is alive, not S3 parity) ---
AUTH_USER="${AUTH_USER:-$ST_USER}"
AUTH_KEY="${AUTH_KEY:-$ST_KEY}"
AUTH=$(curl -sS "${CURL_INSECURE[@]}" -D "$EVID/20-auth-headers.txt" -o /dev/null -w "%{http_code}" \
  -H "X-Auth-User: $AUTH_USER" -H "X-Auth-Key: $AUTH_KEY" \
  "$VIP/auth/v1.0" || true)
AUTH="${AUTH:-000}"
[[ -z "$AUTH" || "$AUTH" == "000000" ]] && AUTH="000"
log "TempAuth GET /auth/v1.0 -> HTTP $AUTH"
if [[ "$AUTH" != "200" && "$AUTH" != "204" ]]; then
  finish "BLOCKED" "OPS_ONLY" "tempauth_failed" "$EXIT_BLOCKED"
fi

# A parity request is explicit when any parity selector is present. Partial
# configuration is a hard configuration error, never a skip or GREEN.
PARITY_SELECTORS=(
  "${PYTHON_S3_ENDPOINT:-}"
  "${PYTHON_S3_PROVENANCE:-}"
  "${RUST_S3_PROVENANCE:-}"
  "${PEREGRINE_S3_PY_ACCESS:-}"
  "${PEREGRINE_S3_PY_SECRET:-}"
  "${PEREGRINE_S3_RS_ACCESS:-}"
  "${PEREGRINE_S3_RS_SECRET:-}"
)
PARITY_ANY=0
PARITY_COMPLETE=1
for value in "${PARITY_SELECTORS[@]}"; do
  [[ -n "$value" ]] && PARITY_ANY=1
  [[ -z "$value" ]] && PARITY_COMPLETE=0
done

if [[ "$PARITY_ANY" -eq 1 && "$PARITY_COMPLETE" -ne 1 ]]; then
  finish "CONFIG_ERROR" "OPS_ONLY" "incomplete_python_s3_oracle_config" "$EXIT_CONFIG"
fi

if [[ "$PARITY_COMPLETE" -eq 1 ]]; then
  PYTHON_BIN="${PYTHON_BIN:-python3}"
  PARITY_RUNNER="${STRICT_S3_PARITY_RUNNER:-$ROOT/tools/strict-s3-parity.py}"
  if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    finish "CONFIG_ERROR" "OPS_ONLY" "python_runtime_missing" "$EXIT_CONFIG"
  fi
  if [[ ! -f "$PARITY_RUNNER" ]]; then
    finish "CONFIG_ERROR" "OPS_ONLY" "strict_s3_parity_runner_missing" "$EXIT_CONFIG"
  fi
  if ! is_bool01 "${PYTHON_S3_INSECURE:-0}"; then
    finish "CONFIG_ERROR" "OPS_ONLY" "invalid_PYTHON_S3_INSECURE" "$EXIT_CONFIG"
  fi

  PARITY_REPORT="$EVID/21-strict-s3-parity.json"
  PARITY_LOG="$EVID/21-strict-s3-parity.txt"
  PARITY_ARGS=(
    "$PYTHON_BIN" "$PARITY_RUNNER"
    --python "$PYTHON_S3_ENDPOINT"
    --rust "$VIP"
    --python-provenance "$PYTHON_S3_PROVENANCE"
    --rust-provenance "$RUST_S3_PROVENANCE"
    --python-region "${PYTHON_S3_REGION:-us-east-1}"
    --rust-region "${RUST_S3_REGION:-us-east-1}"
    --json-report "$PARITY_REPORT"
  )
  [[ "${PYTHON_S3_INSECURE:-0}" == "1" ]] && PARITY_ARGS+=(--python-insecure)
  [[ "$VIP" == https://* ]] && PARITY_ARGS+=(--rust-insecure)

  log "PARITY_ORACLE=RUNNING runner=$PARITY_RUNNER"
  set +e
  "${PARITY_ARGS[@]}" >"$PARITY_LOG" 2>&1
  PARITY_RC=$?
  set -e

  if [[ "$PARITY_RC" -eq 130 ]]; then
    finish "INTERRUPTED" "PARITY_ATTEMPTED" "strict_s3_parity_interrupted" 130
  fi
  if [[ "$PARITY_RC" -ne 0 ]]; then
    if [[ "$PARITY_RC" -eq 2 ]]; then
      finish "CONFIG_ERROR" "OPS_ONLY" "strict_s3_parity_runtime_or_config_error" "$EXIT_CONFIG"
    fi
    finish "FAIL" "PARITY_ATTEMPTED" "strict_s3_parity_failed" "$EXIT_FAIL"
  fi

  # A subprocess return code alone is insufficient. Validate the report's
  # schema, complete-case counts, cleanup result and PASS gate before rc=0.
  set +e
  "$PYTHON_BIN" -c '
import json, sys
p = json.load(open(sys.argv[1], encoding="utf-8"))
s = p.get("summary", {})
r = p.get("result", {})
ok = (
    p.get("schema") == "peregrine.strict-s3-parity.v1"
    and r.get("exit_code") == 0 and r.get("gate") == "PASS"
    and s.get("gate") == "PASS"
    and isinstance(s.get("required_cases"), int)
    and s.get("executed_cases") == s.get("required_cases")
    and s.get("failed") == 0 and s.get("missing") == 0
    and s.get("skipped") == 0 and s.get("cleanup_failed") == 0
)
raise SystemExit(0 if ok else 1)
' "$PARITY_REPORT"
  REPORT_RC=$?
  set -e
  if [[ "$REPORT_RC" -ne 0 ]]; then
    finish "CONFIG_ERROR" "OPS_ONLY" "strict_s3_parity_report_invalid" "$EXIT_CONFIG"
  fi

  finish "GREEN" "PARITY" "strict_s3_parity_passed" "$EXIT_GREEN"
fi

# No Python S3 oracle: these paths remain explicitly one-origin OPS_ONLY.
if [[ "${FORCE_S3_SMOKE:-0}" == "1" ]]; then
  log "FORCE_S3_SMOKE=1: unsigned one-origin GET / (reachability only)"
  S3CODE=$(curl -sS "${CURL_INSECURE[@]}" -o "$EVID/20-s3-root-body.txt" -w "%{http_code}" \
    --connect-timeout 5 --max-time 15 "$VIP/" || true)
  S3CODE="${S3CODE:-000}"
  [[ -z "$S3CODE" || "$S3CODE" == "000000" ]] && S3CODE="000"
  log "GET $VIP/ -> HTTP $S3CODE (recorded; never a parity claim)"
  if [[ "$S3CODE" == "000" ]]; then
    finish "FAIL" "OPS_ONLY" "s3_reachability_failed_python_oracle_missing" "$EXIT_FAIL"
  fi
  finish "PARTIAL" "OPS_ONLY" "python_s3_oracle_missing_reachability_only" "$EXIT_PARTIAL"
fi

log "Python S3 oracle is not configured; no parity claim is possible."
log "To run parity, configure the seven strict parity variables documented above."
finish "SKIPPED" "OPS_ONLY" "python_s3_oracle_missing_s3_probe_not_requested" "$EXIT_SKIPPED"
