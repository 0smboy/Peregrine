#!/usr/bin/env bash
# Contabo VIP S3 live gate — only when cluster healthy and meta not blocking.
# Does NOT enable s3api on the VIP; that remains ON-BY-CONFIG (see
# docs/fairness-lab/S3-ON-BY-CONFIG.md).
#
# Usage:
#   VIP=https://10.0.0.10:8085 ./tools/wave3-s3-contabo-gate.sh [EVIDENCE_DIR]
# Env:
#   VIP                 default https://10.0.0.10:8085 (self-signed LAB: uses curl -k)
#   FORCE_S3_SMOKE=1    attempt SigV4 ListBuckets even if s3api not in pipeline
#                       (expects 403/501/404 when filter absent — recorded)
#   SKIP_META_CHECK=1   skip META_DIRTY file probe (not recommended)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EVID="${1:-$ROOT/tools/test-results/wave3-s3-l3b-prod-$(date -u +%Y%m%d)}"
VIP="${VIP:-https://10.0.0.10:8085}"
mkdir -p "$EVID"
OUT="$EVID/20-contabo-s3-gate.txt"
: >"$OUT"

log() { echo "$@" | tee -a "$OUT"; }

log "Contabo S3 gate @ $(date -u +%Y-%m-%dT%H:%M:%SZ)"
log "VIP=$VIP"

# --- health ---
CURL_INSECURE=()
if [[ "$VIP" == https://* ]]; then CURL_INSECURE=(-k); fi
HTTP_CODE=$(curl -sS "${CURL_INSECURE[@]}" -o "$EVID/20-health-body.txt" -w "%{http_code}" --connect-timeout 5 --max-time 15 \
  "$VIP/info" || true)
HTTP_CODE="${HTTP_CODE:-000}"
# curl can print 000 and still exit non-zero; normalize empty.
[[ -z "$HTTP_CODE" || "$HTTP_CODE" == "000000" ]] && HTTP_CODE="000"
log "GET $VIP/info → HTTP $HTTP_CODE"
if [[ "$HTTP_CODE" != "200" ]]; then
  log "VERDICT=BLOCKED reason=cluster_unhealthy (info not 200)"
  echo "BLOCKED" >"$EVID/20-contabo-verdict.txt"
  exit 0
fi

# Refuse to claim s3api is advertised (honest /info).
if grep -q '"s3api"' "$EVID/20-health-body.txt" 2>/dev/null; then
  log "WARN: /info unexpectedly contains s3api key (should stay silent)"
else
  log "OK: /info does not advertise s3api (ON-BY-CONFIG honesty)"
fi

# --- meta dirty probe (W0′) ---
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
  log "VERDICT=BLOCKED reason=meta_not_clean (W0′); S3 live suite not run"
  echo "BLOCKED" >"$EVID/20-contabo-verdict.txt"
  exit 0
fi

# --- TempAuth smoke (always; proves VIP alive) ---
AUTH_USER="${AUTH_USER:-test:tester}"
AUTH_KEY="${AUTH_KEY:-azure-swift-2026.bench}"
AUTH=$(curl -sS "${CURL_INSECURE[@]}" -D "$EVID/20-auth-headers.txt" -o /dev/null -w "%{http_code}" \
  -H "X-Auth-User: $AUTH_USER" -H "X-Auth-Key: $AUTH_KEY" \
  "$VIP/auth/v1.0" || echo "000")
log "TempAuth GET /auth/v1.0 → HTTP $AUTH"
if [[ "$AUTH" != "200" && "$AUTH" != "204" ]]; then
  log "VERDICT=BLOCKED reason=tempauth_failed"
  echo "BLOCKED" >"$EVID/20-contabo-verdict.txt"
  exit 0
fi

# --- Optional S3 smoke (only meaningful after ON-BY-CONFIG enable) ---
if [[ "${FORCE_S3_SMOKE:-0}" == "1" ]]; then
  log "FORCE_S3_SMOKE=1: unsigned GET / (expect non-S3 or 403 without s3api)"
  S3CODE=$(curl -sS "${CURL_INSECURE[@]}" -o "$EVID/20-s3-root-body.txt" -w "%{http_code}" \
    --connect-timeout 5 --max-time 15 "$VIP/" || echo "000")
  log "GET $VIP/ → HTTP $S3CODE (recorded; not a GREEN claim)"
  log "VERDICT=PARTIAL note=s3api_enable_still_operator_action"
  echo "PARTIAL" >"$EVID/20-contabo-verdict.txt"
  exit 0
fi

log "VERDICT=SKIPPED_LIVE_S3 reason=s3api_not_in_default_pipeline (ON-BY-CONFIG)"
log "To enable: see docs/fairness-lab/S3-ON-BY-CONFIG.md then re-run with FORCE_S3_SMOKE=1"
echo "SKIPPED" >"$EVID/20-contabo-verdict.txt"
exit 0
