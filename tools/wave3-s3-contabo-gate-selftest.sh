#!/usr/bin/env bash
# Offline exit-contract selftest. All HTTP and parity-runner calls are mocked.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GATE="$ROOT/tools/wave3-s3-contabo-gate.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
MOCK_BIN="$TMP/bin"
mkdir -p "$MOCK_BIN"

cat >"$MOCK_BIN/curl" <<'MOCK_CURL'
#!/usr/bin/env bash
set -euo pipefail
out=""
headers=""
url=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o|-D|-w|-H|--connect-timeout|--max-time)
      key="$1"
      value="${2:-}"
      [[ "$key" == "-o" ]] && out="$value"
      [[ "$key" == "-D" ]] && headers="$value"
      shift 2
      ;;
    -k|-s|-S|-sS) shift ;;
    http://*|https://*) url="$1"; shift ;;
    *) shift ;;
  esac
done
code="${MOCK_ROOT_CODE:-403}"
body='<Error><Code>AccessDenied</Code></Error>'
if [[ "$url" == */info ]]; then
  code="${MOCK_INFO_CODE:-200}"
  body='{"swift":{"version":"selftest"}}'
elif [[ "$url" == */auth/v1.0 ]]; then
  code="${MOCK_AUTH_CODE:-204}"
  body=''
fi
if [[ -n "$out" && "$out" != "/dev/null" ]]; then
  printf '%s' "$body" >"$out"
fi
if [[ -n "$headers" ]]; then
  printf 'HTTP/1.1 %s selftest\r\n\r\n' "$code" >"$headers"
fi
printf '%s' "$code"
MOCK_CURL
chmod +x "$MOCK_BIN/curl"

cat >"$TMP/mock-parity.py" <<'MOCK_PARITY'
#!/usr/bin/env python3
import json
import os
import sys

args = sys.argv[1:]
report = args[args.index("--json-report") + 1]
rc = int(os.environ.get("MOCK_ORACLE_RC", "0"))
if rc:
    raise SystemExit(rc)
cleanup_failed = int(os.environ.get("MOCK_CLEANUP_FAILED", "0"))
valid = os.environ.get("MOCK_REPORT_VALID", "1") == "1"
payload = {
    "schema": "peregrine.strict-s3-parity.v1" if valid else "wrong.schema",
    "summary": {
        "required_cases": 2,
        "executed_cases": 2,
        "failed": 0,
        "missing": 0,
        "skipped": 0,
        "cleanup_failed": cleanup_failed,
        "gate": "PASS",
    },
    "result": {"exit_code": 0, "gate": "PASS"},
}
with open(report, "w", encoding="utf-8") as f:
    json.dump(payload, f)
MOCK_PARITY

unset_vars=(
  PYTHON_S3_ENDPOINT PYTHON_S3_PROVENANCE RUST_S3_PROVENANCE
  PEREGRINE_S3_PY_ACCESS PEREGRINE_S3_PY_SECRET
  PEREGRINE_S3_RS_ACCESS PEREGRINE_S3_RS_SECRET
  STRICT_S3_PARITY_RUNNER PYTHON_S3_INSECURE MOCK_ORACLE_RC
  MOCK_CLEANUP_FAILED MOCK_REPORT_VALID FORCE_S3_SMOKE
)

run_case() {
  local name="$1"
  local expected_rc="$2"
  local expected_verdict="$3"
  local expected_claim="$4"
  shift 4
  local evid="$TMP/$name"
  mkdir -p "$evid"
  local unset_args=()
  local var
  for var in "${unset_vars[@]}"; do unset_args+=(-u "$var"); done
  set +e
  env "${unset_args[@]}" \
    PATH="$MOCK_BIN:$PATH" \
    ST_USER="test:tester" ST_KEY="selftest-key" \
    VIP="https://rust.example.test:8085" SKIP_META_CHECK=1 \
    "$@" "$GATE" "$evid" >"$evid/selftest.stdout" 2>"$evid/selftest.stderr"
  local rc=$?
  set -e
  if [[ "$rc" -ne "$expected_rc" ]]; then
    echo "FAIL $name: expected rc=$expected_rc actual=$rc" >&2
    sed -n '1,160p' "$evid/selftest.stdout" >&2
    sed -n '1,160p' "$evid/selftest.stderr" >&2
    exit 1
  fi
  grep -qx "VERDICT=$expected_verdict" "$evid/20-contabo-verdict.txt"
  grep -qx "CLAIM=$expected_claim" "$evid/20-contabo-verdict.txt"
  grep -qx "EXIT_CODE=$expected_rc" "$evid/20-contabo-verdict.txt"
  echo "PASS $name rc=$rc verdict=$expected_verdict claim=$expected_claim"
}

run_case no_oracle_skipped 6 SKIPPED OPS_ONLY
run_case reachability_partial 5 PARTIAL OPS_ONLY \
  FORCE_S3_SMOKE=1 MOCK_ROOT_CODE=403
run_case health_blocked 3 BLOCKED OPS_ONLY MOCK_INFO_CODE=503
run_case invalid_vip_config 2 CONFIG_ERROR OPS_ONLY VIP=https://
run_case config_incomplete_oracle 2 CONFIG_ERROR OPS_ONLY \
  PYTHON_S3_ENDPOINT=https://python.example.test:8090
run_case parity_failed 1 FAIL PARITY_ATTEMPTED \
  PYTHON_S3_ENDPOINT=https://python.example.test:8090 \
  PYTHON_S3_PROVENANCE=python@selftest RUST_S3_PROVENANCE=rust@selftest \
  PEREGRINE_S3_PY_ACCESS=py PEREGRINE_S3_PY_SECRET=py-secret \
  PEREGRINE_S3_RS_ACCESS=rs PEREGRINE_S3_RS_SECRET=rs-secret \
  STRICT_S3_PARITY_RUNNER="$TMP/mock-parity.py" MOCK_ORACLE_RC=1
run_case parity_report_cleanup_rejected 2 CONFIG_ERROR OPS_ONLY \
  PYTHON_S3_ENDPOINT=https://python.example.test:8090 \
  PYTHON_S3_PROVENANCE=python@selftest RUST_S3_PROVENANCE=rust@selftest \
  PEREGRINE_S3_PY_ACCESS=py PEREGRINE_S3_PY_SECRET=py-secret \
  PEREGRINE_S3_RS_ACCESS=rs PEREGRINE_S3_RS_SECRET=rs-secret \
  STRICT_S3_PARITY_RUNNER="$TMP/mock-parity.py" MOCK_CLEANUP_FAILED=1
run_case parity_green 0 GREEN PARITY \
  PYTHON_S3_ENDPOINT=https://python.example.test:8090 \
  PYTHON_S3_PROVENANCE=python@selftest RUST_S3_PROVENANCE=rust@selftest \
  PEREGRINE_S3_PY_ACCESS=py PEREGRINE_S3_PY_SECRET=py-secret \
  PEREGRINE_S3_RS_ACCESS=rs PEREGRINE_S3_RS_SECRET=rs-secret \
  STRICT_S3_PARITY_RUNNER="$TMP/mock-parity.py"

echo "wave3-s3-contabo-gate exit-contract selftest: PASS"
