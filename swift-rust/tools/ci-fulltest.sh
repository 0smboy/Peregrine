#!/bin/bash
# Full remote CI on the Azure build host (swift1): release build + workspace
# tests + EC-featured tests + clippy + fmt. Each phase is fenced with a marker
# line so a poller can see exactly where it is and whether it passed.
#
# Run under nohup; all output goes to the log passed as $1 (default below).
set -u
cd /root/work/swift-rust || exit 2
export PATH="/root/.cargo/bin:$PATH"
export CARGO_TERM_COLOR=never
LOG=${1:-/root/work/ci-fulltest.log}
ECF=swift-proxy-server/ec,swift-object-server/ec

say() { echo; echo "########## $* ##########"; }
run() { echo "+ $*"; "$@"; echo "=== exit=$? ($1 ...) ==="; }

{
  say "CI START $(date -u +%FT%TZ)  commit-marker=$(cat /root/work/swift-rust/.sync-marker 2>/dev/null || echo none)"
  say "TOOLCHAIN"; cargo --version; rustc --version; nproc; free -h | head -2

  say "PHASE 1: release build (all crates, EC feature)"
  run cargo build --release --features "$ECF"

  say "PHASE 2: fmt check"
  run cargo fmt --all -- --check

  say "PHASE 3: clippy (workspace, no EC) -D warnings"
  run cargo clippy --workspace --exclude swift-ec --all-targets -- -D warnings

  say "PHASE 4: clippy (EC crates) -D warnings"
  run cargo clippy -p swift-proxy-server -p swift-object-server -p swift-ec \
        --features "$ECF" --all-targets -- -D warnings

  say "PHASE 5: workspace tests (no EC)"
  run cargo test --release --workspace --exclude swift-ec

  say "PHASE 6: EC-featured tests (codec + object + proxy, incl. ec_integration)"
  run cargo test --release -p swift-ec -p swift-object-server -p swift-proxy-server \
        --features "$ECF"

  say "CI DONE $(date -u +%FT%TZ)"
} >"$LOG" 2>&1
echo "CI-FULLTEST-COMPLETE rc-file=$LOG" >>"$LOG"
