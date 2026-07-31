#!/usr/bin/env bash
# Rust Toolchain Canary — compare behaviour across pinned rustc versions.
# Usage:
#   ./canary.sh                  # all toolchains in toolchains.toml
#   ./canary.sh 1.97.1           # one toolchain
# Env:
#   CANARY_WORKSPACE  path to swift-rust workspace (default ../swift-rust)
#   SWIFT_AUTH_URL / SWIFT_USER / SWIFT_KEY for smoke_crud.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
WS="${CANARY_WORKSPACE:-$ROOT/../swift-rust}"
REPORT_DIR="$ROOT/reports"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_JSON="$REPORT_DIR/canary-$STAMP.json"
OUT_MD="$REPORT_DIR/canary-$STAMP.md"
mkdir -p "$REPORT_DIR"

if [[ ! -d "$WS" ]]; then
  echo "workspace not found: $WS" >&2
  exit 2
fi

mapfile -t TOOLCHAINS < <(python3 - <<'PY' "$ROOT/toolchains.toml"
import re,sys
text=open(sys.argv[1]).read()
# naive: collect quoted versions inside toolchains = [ ... ]
m=re.search(r'toolchains\s*=\s*\[(.*?)\]', text, re.S)
if not m:
  sys.exit("no toolchains list")
print("\n".join(re.findall(r'"([^"]+)"', m.group(1))))
PY
)

CRATES=(swift-diskfile swift-object-server swift-proxy-server swift-core)
if [[ $# -gt 0 ]]; then
  TOOLCHAINS=("$@")
fi

echo "workspace=$WS"
echo "toolchains=${TOOLCHAINS[*]}"
echo "crates=${CRATES[*]}"

RESULTS=()
for tc in "${TOOLCHAINS[@]}"; do
  echo "======== toolchain $tc ========"
  if ! rustup run "$tc" rustc --version >/dev/null 2>&1; then
    echo "MISSING toolchain $tc — install with: rustup install $tc" >&2
    RESULTS+=("$tc|BLOCK|missing-toolchain||||")
    continue
  fi
  ver=$(rustup run "$tc" rustc --version)
  pkg_args=()
  for c in "${CRATES[@]}"; do pkg_args+=(-p "$c"); done

  test_ok=0; clippy_ok=0; build_ok=0
  bin_size=""
  test_log=$(mktemp); clippy_log=$(mktemp); build_log=$(mktemp)

  if (cd "$WS" && rustup run "$tc" cargo test --release "${pkg_args[@]}" -- --nocapture) >"$test_log" 2>&1; then
    test_ok=1
  fi
  if (cd "$WS" && rustup run "$tc" cargo clippy --release "${pkg_args[@]}" -- -D warnings) >"$clippy_log" 2>&1; then
    clippy_ok=1
  fi
  if (cd "$WS" && rustup run "$tc" cargo build --release -p swift-object-server) >"$build_log" 2>&1; then
    build_ok=1
    bin=$(find "$WS/target/release" -maxdepth 1 -type f -name 'swift-object*' 2>/dev/null | head -1 || true)
    if [[ -n "${bin:-}" && -f "$bin" ]]; then
      bin_size=$(wc -c <"$bin" | tr -d ' ')
    fi
  fi

  smoke_log=$(mktemp)
  smoke_ok=0
  if bash "$ROOT/scenarios/smoke_crud.sh" >"$smoke_log" 2>&1; then
    smoke_ok=1
  fi

  correctness=PASS
  [[ $test_ok -eq 1 && $clippy_ok -eq 1 && $build_ok -eq 1 ]] || correctness=FAIL
  api=PASS
  [[ $smoke_ok -eq 1 ]] || api=FAIL
  rec=UPGRADE
  [[ $correctness == PASS && $api == PASS ]] || rec=BLOCK

  RESULTS+=("$tc|$rec|$correctness|$api|${bin_size:-0}|$ver")
  mkdir -p "$REPORT_DIR/logs-$STAMP"
  mv "$test_log" "$REPORT_DIR/logs-$STAMP/$tc-test.log"
  mv "$clippy_log" "$REPORT_DIR/logs-$STAMP/$tc-clippy.log"
  mv "$build_log" "$REPORT_DIR/logs-$STAMP/$tc-build.log"
  mv "$smoke_log" "$REPORT_DIR/logs-$STAMP/$tc-smoke.log"
done

# ---- reports ----
{
  echo "{"
  echo "  \"stamp\": \"$STAMP\","
  echo "  \"workspace\": \"$WS\","
  echo "  \"results\": ["
  first=1
  for row in "${RESULTS[@]}"; do
    IFS='|' read -r tc rec corr api size ver <<<"$row"
    [[ $first -eq 1 ]] || echo ","
    first=0
    printf '    {"toolchain":"%s","recommendation":"%s","correctness":"%s","api":"%s","binary_size":%s,"rustc":"%s"}' \
      "$tc" "$rec" "$corr" "$api" "${size:-0}" "$ver"
  done
  echo
  echo "  ]"
  echo "}"
} >"$OUT_JSON"

{
  echo "# Rust Toolchain Canary Report"
  echo
  echo "Stamp: \`$STAMP\`"
  echo "Workspace: \`$WS\`"
  echo
  echo "| Toolchain | Correctness | API | Binary size | Recommendation |"
  echo "|-----------|-------------|-----|-------------|----------------|"
  for row in "${RESULTS[@]}"; do
    IFS='|' read -r tc rec corr api size ver <<<"$row"
    echo "| $tc ($ver) | $corr | $api | ${size:-n/a} | **$rec** |"
  done
  echo
  echo "Logs: \`reports/logs-$STAMP/\`"
  echo
  echo "Recommendation rule: UPGRADE only when correctness (test+clippy+build) and API smoke both PASS."
} >"$OUT_MD"

echo "wrote $OUT_MD"
echo "wrote $OUT_JSON"
# Exit non-zero if any BLOCK
for row in "${RESULTS[@]}"; do
  IFS='|' read -r _ rec _ <<<"$row"
  if [[ "$rec" == "BLOCK" ]]; then
    exit 1
  fi
done
exit 0
