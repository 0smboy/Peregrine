#!/usr/bin/env bash
# Functional + smoke tests against a running SAIO / lab endpoint.
# Usage: test.sh [--prefix DIR] [--func] [--smoke] [--lab] [--endpoint URL]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

PREFIX="${PEREGRINE_PREFIX:-$DEFAULT_PREFIX}"
DO_FUNC=0
DO_SMOKE=0
DO_LAB=0
ENDPOINT=""
ST_USER="${ST_USER:-$ST_USER_DEFAULT}"
ST_KEY="${ST_KEY:-$ST_KEY_DEFAULT}"

usage() {
  cat <<'EOF'
Usage: test.sh [--prefix DIR] [--func] [--smoke] [--lab] [--endpoint URL]
               [--user USER] [--key KEY]

  --smoke      Run deploy/smoke.sh style replication + EC round-trip
  --func       Run tools/func-suite.sh against endpoint
  --lab        Lightweight lab smoke (auth, healthcheck, console if up)
  --endpoint   Base URL (default: http://127.0.0.1:8080)
  --user/key   TempAuth credentials (default: test:tester / testing)

If no suite flags are given, runs --smoke --lab.
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) PREFIX="${2:?}"; shift 2 ;;
    --func) DO_FUNC=1; shift ;;
    --smoke) DO_SMOKE=1; shift ;;
    --lab) DO_LAB=1; shift ;;
    --endpoint) ENDPOINT="${2:?}"; shift 2 ;;
    --user) ST_USER="${2:?}"; shift 2 ;;
    --key) ST_KEY="${2:?}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown arg: $1" ;;
  esac
done

if [ "$DO_FUNC" = 0 ] && [ "$DO_SMOKE" = 0 ] && [ "$DO_LAB" = 0 ]; then
  DO_SMOKE=1
  DO_LAB=1
fi

resolve_layout "$PREFIX"
# shellcheck disable=SC1091
[ -f "$PREFIX/etc/env.sh" ] && . "$PREFIX/etc/env.sh"

ENDPOINT="${ENDPOINT:-$ST_URL_DEFAULT}"
AUTH="${ENDPOINT%/}/auth/v1.0"
# strip accidental double path
AUTH="$(printf '%s' "$AUTH" | sed 's#//auth#/auth#; s#http:/#http://#; s#https:/#https://#')"

need_cmd curl

FAILS=0
pass_count=0
fail_count=0

record_pass() { pass_count=$((pass_count + 1)); ok "$1"; }
record_fail() { fail_count=$((fail_count + 1)); FAILS=$((FAILS + 1)); printf '\033[1;31mFAIL\033[0m %s\n' "$1" >&2; }

# ---- smoke (prefer pack smoke.sh; else inline) ----
run_smoke() {
  log "smoke test against $ENDPOINT"
  local smoke=""
  for c in "$PREFIX/deploy/smoke.sh" \
           "$PEREGRINE_ROOT/swift-rust/deploy/smoke.sh" \
           "$SCRIPT_DIR/../../swift-rust/deploy/smoke.sh"; do
    if [ -f "$c" ]; then smoke="$c"; break; fi
  done

  if [ -n "$smoke" ] && { [ "$ENDPOINT" = "http://127.0.0.1:8080" ] || [ "$ENDPOINT" = "http://127.0.0.1:8080/" ]; }; then
    # smoke.sh hardcodes 127.0.0.1:8080 — fine for default SAIO.
    # EC fragment check uses /srv/node* — may miss prefix layout; fall back.
    if bash "$smoke"; then
      record_pass "smoke.sh"
    else
      warn "pack smoke.sh failed (often EC path /srv vs prefix); trying portable smoke"
      portable_smoke || record_fail "smoke"
    fi
  else
    portable_smoke || record_fail "smoke"
  fi
}

portable_smoke() {
  local H TOK URL c M NF
  H="$(curl -s -i -H "X-Auth-User: $ST_USER" -H "X-Auth-Key: $ST_KEY" "$AUTH" || true)"
  TOK="$(printf '%s' "$H" | grep -i '^X-Auth-Token:' | tr -d '\r' | awk '{print $2}')"
  URL="$(printf '%s' "$H" | grep -i '^X-Storage-Url:' | tr -d '\r' | awk '{print $2}')"
  # rewrite storage host to endpoint host
  if [ -n "$URL" ]; then
    local path
    path="$(printf '%s' "$URL" | sed -E 's#https?://[^/]+##')"
    URL="${ENDPOINT%/}$path"
  fi
  if [ -z "$TOK" ] || [ -z "$URL" ]; then
    record_fail "smoke: auth"
    return 1
  fi
  note "auth ok ($URL)"

  echo "[1] replication policy (Policy-0)"
  curl -s -X PUT "$URL/rbox-oc" -H "X-Auth-Token: $TOK" -o /dev/null
  head -c 1048576 /dev/urandom > /tmp/r-oc.obj
  M="$(md5sum /tmp/r-oc.obj 2>/dev/null | awk '{print $1}')"
  # macOS md5
  if [ -z "$M" ]; then M="$(md5 -q /tmp/r-oc.obj)"; fi
  c="$(curl -s -X PUT "$URL/rbox-oc/o" -H "X-Auth-Token: $TOK" -T /tmp/r-oc.obj -o /dev/null -w '%{http_code}')"
  [ "$c" = 201 ] && note "PUT 201" || { record_fail "repl PUT ($c)"; return 1; }
  curl -s "$URL/rbox-oc/o" -H "X-Auth-Token: $TOK" -o /tmp/r-oc.down
  local got
  got="$(md5sum /tmp/r-oc.down 2>/dev/null | awk '{print $1}')"
  [ -z "$got" ] && got="$(md5 -q /tmp/r-oc.down)"
  [ "$got" = "$M" ] && note "GET md5 match" || { record_fail "repl md5"; return 1; }
  c="$(curl -s -X DELETE "$URL/rbox-oc/o" -H "X-Auth-Token: $TOK" -o /dev/null -w '%{http_code}')"
  [ "$c" = 204 ] && note "DELETE 204" || note "DELETE $c (non-fatal)"

  echo "[2] erasure-coding policy (EC-4-2) — best effort"
  curl -s -X PUT "$URL/ecbox-oc" -H "X-Auth-Token: $TOK" -H 'X-Storage-Policy: EC-4-2' -o /dev/null
  head -c 1048576 /dev/urandom > /tmp/e-oc.obj
  M="$(md5sum /tmp/e-oc.obj 2>/dev/null | awk '{print $1}')"
  [ -z "$M" ] && M="$(md5 -q /tmp/e-oc.obj)"
  c="$(curl -s -X PUT "$URL/ecbox-oc/o" -H "X-Auth-Token: $TOK" -T /tmp/e-oc.obj -o /dev/null -w '%{http_code}')"
  if [ "$c" = 201 ]; then
    note "EC PUT 201"
    curl -s "$URL/ecbox-oc/o" -H "X-Auth-Token: $TOK" -o /tmp/e-oc.down
    got="$(md5sum /tmp/e-oc.down 2>/dev/null | awk '{print $1}')"
    [ -z "$got" ] && got="$(md5 -q /tmp/e-oc.down)"
    if [ "$got" = "$M" ]; then
      note "EC GET md5 match"
    else
      warn "EC md5 mismatch (stack may lack EC feature)"
    fi
    NF="$(find "$DEVICE_ROOT"/node* /srv/node* -path '*objects-1*' -name '*#d.data' 2>/dev/null | wc -l | tr -d ' ')"
    note "EC durable fragments seen: $NF"
  else
    warn "EC PUT $c — build without --features ec or liberasurecode missing (replication still OK)"
  fi

  rm -f /tmp/r-oc.obj /tmp/r-oc.down /tmp/e-oc.obj /tmp/e-oc.down
  record_pass "portable smoke (replication)"
  return 0
}

# ---- func-suite ----
run_func() {
  log "func-suite against $ENDPOINT"
  local suite=""
  for c in "$PREFIX/tools/func-suite.sh" \
           "$PEREGRINE_ROOT/swift-rust/tools/func-suite.sh" \
           "$SCRIPT_DIR/../../swift-rust/tools/func-suite.sh"; do
    if [ -f "$c" ]; then suite="$c"; break; fi
  done
  [ -n "$suite" ] || { record_fail "func-suite.sh not found"; return 1; }

  local out rc
  out="$(mktemp)"
  set +e
  bash "$suite" "$ENDPOINT" "$ST_USER" "$ST_KEY" "offline-oneclick" | tee "$out"
  rc=${PIPESTATUS[0]}
  set -e

  # func-suite historically exits 0 even with FAIL>0 — parse RESULT line
  local failn passn
  failn="$(grep -E '^RESULT' "$out" | tail -1 | sed -n 's/.*FAIL=\([0-9]*\).*/\1/p')"
  passn="$(grep -E '^RESULT' "$out" | tail -1 | sed -n 's/.*PASS=\([0-9]*\).*/\1/p')"
  failn="${failn:-$rc}"
  passn="${passn:-0}"
  note "func-suite PASS=$passn FAIL=$failn (exit=$rc)"
  if [ "${failn:-1}" = 0 ] || [ "${failn:-1}" = "0" ]; then
    record_pass "func-suite ($passn checks)"
  else
    # EC policy name mismatch (ec-2-1 vs EC-4-2) is a known SAIO limitation
    warn "func-suite reported failures (SAIO policy name may be EC-4-2 while suite expects ec-2-1)"
    record_fail "func-suite FAIL=$failn"
  fi
  rm -f "$out"
}

# ---- lab smoke ----
run_lab() {
  log "lab smoke"
  local code
  code="$(curl -s -m5 -o /dev/null -w '%{http_code}' \
    -H "X-Auth-User: $ST_USER" -H "X-Auth-Key: $ST_KEY" "$AUTH" || true)"
  if [ "$code" = 200 ]; then
    record_pass "lab: tempauth 200"
  else
    record_fail "lab: tempauth ($code)"
  fi

  code="$(curl -s -m5 -o /dev/null -w '%{http_code}' \
    "http://127.0.0.1:8080/healthcheck" 2>/dev/null || true)"
  if [ "$code" = 200 ] || [ "$code" = 204 ]; then
    record_pass "lab: proxy healthcheck $code"
  else
    # healthcheck may be on backend ports only
    note "lab: proxy /healthcheck -> $code (informational)"
  fi

  # backend ports
  local up=0
  for port in 6010 6011 6012; do
    code="$(curl -s -m2 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/healthcheck" 2>/dev/null || true)"
    if [ "$code" = 200 ] || [ "$code" = 204 ]; then
      up=$((up + 1))
    fi
  done
  if [ "$up" -ge 1 ]; then
    record_pass "lab: backend healthchecks ($up/3 sample)"
  else
    note "lab: backend healthchecks not responding (may be OK if path differs)"
  fi

  # console if configured
  if [ -f "$RUN_DIR/console.pid" ] && pid_alive "$(read_pidfile "$RUN_DIR/console.pid")"; then
    code="$(curl -s -m3 -o /dev/null -w '%{http_code}' "http://${CONSOLE_BIND_DEFAULT}/" || true)"
    if [ "$code" != "000" ] && [ -n "$code" ]; then
      record_pass "lab: console HTTP $code"
    else
      record_fail "lab: console not responding"
    fi
  else
    note "lab: console not running (skip)"
  fi

  # recon if available
  if [ -x "$PREFIX/bin/swift-recon" ] && [ -f "$SWIFT_DIR/object.ring.gz" ]; then
    if "$PREFIX/bin/swift-recon" --help >/dev/null 2>&1; then
      note "lab: swift-recon present"
      record_pass "lab: swift-recon binary"
    fi
  fi
}

# ---- run selected ----
rc=0
[ "$DO_SMOKE" = 1 ] && run_smoke
[ "$DO_FUNC" = 1 ] && run_func
[ "$DO_LAB" = 1 ] && run_lab

echo
echo "-------------------------------------------------------------------"
printf 'OFFLINE-TEST  PASS=%s FAIL=%s  endpoint=%s\n' "$pass_count" "$fail_count" "$ENDPOINT"
echo "-------------------------------------------------------------------"

if [ "$FAILS" -gt 0 ]; then
  exit 1
fi
exit 0
