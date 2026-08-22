#!/usr/bin/env bash
# Phase 12 CI architecture enforcement (AGENTS.md §24, §32).
# Scans crates/**/*.rs and fails non-zero on hard concurrency-boundary violations.
# Writes nothing to disk (stdout/stderr only). See ci/README.md for the allowlist.
set -euo pipefail
LC_ALL=C
export LC_ALL

usage() {
  cat <<'EOF'
Usage: check-concurrency-boundaries.sh

Scan crates/**/*.rs from the swift-rust workspace (parent of ci/).
Exit 0 if there are no hard failures (WARN/LIST do not fail).
Exit 1 if any hard failure is printed.
Exit 2 if the workspace tree cannot be scanned.
EOF
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  usage
  exit 0
fi
if [ "$#" -ne 0 ]; then
  usage >&2
  exit 2
fi

CI_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$CI_DIR/.." && pwd)
cd "$ROOT"

if [ ! -d crates ]; then
  echo "error: no crates/ under $ROOT" >&2
  exit 2
fi

# spawn_blocking is allowed only in the runtime blocking domain (directory or file).
spawn_blocking_allowed() {
  case "$1" in
    crates/swift-runtime/src/blocking.rs) return 0 ;;
    crates/swift-runtime/src/blocking/*) return 0 ;;
    *) return 1 ;;
  esac
}

is_test_fixture_path() {
  case "$1" in
    */tests/*|*/benches/*|*/examples/*) return 0 ;;
    *) return 1 ;;
  esac
}

in_tokio_fs_forbidden_crate() {
  case "$1" in
    crates/swift-proxy-server/*|crates/swift-http/*|crates/swift-s3api/*) return 0 ;;
    *) return 1 ;;
  esac
}

in_proxy_crate() {
  case "$1" in
    crates/swift-proxy-server/*) return 0 ;;
    *) return 1 ;;
  esac
}

in_http_crate() {
  case "$1" in
    crates/swift-http/*) return 0 ;;
    *) return 1 ;;
  esac
}

in_http_or_proxy_prod() {
  case "$1" in
    crates/swift-http/src/main.rs|crates/swift-proxy-server/src/main.rs) return 1 ;;
    crates/swift-http/src/*|crates/swift-proxy-server/src/*) return 0 ;;
    *) return 1 ;;
  esac
}

is_std_fs_hit() {
  match 'std::fs::' "$1"
}

is_rusqlite_hit() {
  match 'rusqlite::' "$1"
}

# Process-edge listen/bind types. Data-plane sockets are tokio::net.
is_std_net_process_edge() {
  match 'use std::net::' "$1" && return 0
  match 'TcpListener' "$1" && return 0
  match 'SocketAddr' "$1" && return 0
  return 1
}

match() {
  printf '%s\n' "$2" | grep -Eq "$1"
}

# Syntax call / import of spawn_blocking. Metric names such as
# spawn_blocking_total in HELP strings are not calls.
is_spawn_blocking_hit() {
  match 'spawn_blocking_total' "$1" && return 1
  match 'spawn_blocking[[:space:]]*\(' "$1" && return 0
  match 'use [^;]*spawn_blocking' "$1" && return 0
  return 1
}

is_unbounded_hit() {
  local text="$1"
  match '(^|[^[:alnum:]_])unbounded_channel([^[:alnum:]_]|$)' "$text" && return 0
  match 'crossbeam_channel::unbounded' "$text" && return 0
  match '::unbounded\(' "$text" && return 0
  if match 'crossbeam_channel' "$text" && match '(^|[^[:alnum:]_])unbounded([^[:alnum:]_]|$)' "$text"; then
    return 0
  fi
  return 1
}

is_tokio_fs_hit() {
  match 'tokio::fs(::|;|,|\{|[[:space:]]|$)' "$1"
}

is_std_net_hit() {
  match 'std::net::' "$1"
}

snippet() {
  local s="$1"
  s=${s%$'\r'}
  s="${s#"${s%%[![:space:]]*}"}"
  if [ "${#s}" -gt 160 ]; then
    s=$(printf '%s' "$s" | cut -c1-160)
    printf '%s...' "$s"
    return
  fi
  printf '%s' "$s"
}

emit() {
  # kind rule file:line: snippet
  printf '%-5s %-16s %s:%s: %s\n' "$1" "$2" "$3" "$4" "$5"
}

FILES=()
while IFS= read -r f; do
  [ -n "$f" ] || continue
  FILES+=("$f")
done < <(find crates -type f -name '*.rs' ! -path '*/target/*' ! -path '*/tests/fixtures/*' | LC_ALL=C sort)

if [ "${#FILES[@]}" -eq 0 ]; then
  echo "error: no .rs files under crates/" >&2
  exit 2
fi

BROAD='spawn_blocking|unbounded|tokio::fs|std::net::|std::fs::|rusqlite::'

fail_spawn=0
allow_spawn=0
fail_unbounded=0
list_unbounded=0
fail_fs=0
fail_net=0
fail_stdio_fs=0
fail_rusqlite=0
allow_net=0

echo "== check-concurrency-boundaries =="
echo "workspace: $ROOT"
echo "scan: crates/**/*.rs (exclude target/, tests/fixtures/)"
echo "files scanned: ${#FILES[@]}"
echo

for f in "${FILES[@]}"; do
  cfg_test_line=$(grep -n '#\[cfg(test)\]' "$f" 2>/dev/null | head -1 | cut -d: -f1 || true)
  while IFS= read -r hit; do
    [ -n "$hit" ] || continue
    lineno=${hit%%:*}
    text=${hit#*:}
    snip=$(snippet "$text")
    if [ -n "${cfg_test_line:-}" ] && [ "$lineno" -ge "$cfg_test_line" ]; then
      continue
    fi

    if is_spawn_blocking_hit "$text"; then
      if spawn_blocking_allowed "$f"; then
        allow_spawn=$((allow_spawn + 1))
        emit ALLOW spawn_blocking "$f" "$lineno" "$snip"
      else
        fail_spawn=$((fail_spawn + 1))
        emit FAIL spawn_blocking "$f" "$lineno" "$snip"
      fi
    fi

    if is_unbounded_hit "$text"; then
      if is_test_fixture_path "$f"; then
        list_unbounded=$((list_unbounded + 1))
        emit LIST unbounded "$f" "$lineno" "$snip"
      else
        fail_unbounded=$((fail_unbounded + 1))
        emit FAIL unbounded "$f" "$lineno" "$snip"
      fi
    fi

    if in_tokio_fs_forbidden_crate "$f" && is_tokio_fs_hit "$text"; then
      fail_fs=$((fail_fs + 1))
      emit FAIL tokio::fs "$f" "$lineno" "$snip"
    fi

    if in_http_or_proxy_prod "$f" && ! is_test_fixture_path "$f" && is_std_net_hit "$text"; then
      if is_std_net_process_edge "$text"; then
        allow_net=$((allow_net + 1))
        emit ALLOW std::net "$f" "$lineno" "$snip"
      else
        fail_net=$((fail_net + 1))
        emit FAIL std::net "$f" "$lineno" "$snip"
      fi
    fi

    if in_http_or_proxy_prod "$f" && ! is_test_fixture_path "$f" && is_std_fs_hit "$text"; then
      fail_stdio_fs=$((fail_stdio_fs + 1))
      emit FAIL std::fs "$f" "$lineno" "$snip"
    fi

    if in_http_or_proxy_prod "$f" && ! is_test_fixture_path "$f" && is_rusqlite_hit "$text"; then
      fail_rusqlite=$((fail_rusqlite + 1))
      emit FAIL rusqlite "$f" "$lineno" "$snip"
    fi
  done < <(grep -nE "$BROAD" "$f" 2>/dev/null || true)
done

fail_dispatch=0
for f in crates/swift-account-server/src/lib.rs crates/swift-container-server/src/lib.rs; do
  if [ -f "$f" ] && grep -nE 'else \{[[:space:]]*$' "$f" >/dev/null; then
    while IFS= read -r hit; do
      lineno=${hit%%:*}
      # Dual-dispatch: handle_async must not fall through to self.handle(req) on the reactor.
      blk=$(sed -n "${lineno},$((lineno + 3))p" "$f")
      if printf '%s\n' "$blk" | grep -q 'self.handle(req)'; then
        fail_dispatch=$((fail_dispatch + 1))
        emit FAIL handle_fallback "$f" "$lineno" "else { self.handle(req) }"
      fi
    done < <(grep -nE 'else \{[[:space:]]*$' "$f" || true)
  fi
done
if grep -nE 'self\.handle\(Request \{' crates/swift-proxy-server/src/lib.rs >/dev/null 2>&1; then
  while IFS= read -r hit; do
    lineno=${hit%%:*}
    fail_dispatch=$((fail_dispatch + 1))
    emit FAIL handle_fallback "crates/swift-proxy-server/src/lib.rs" "$lineno" "handle_async must not fall back to sync handle()"
  done < <(grep -nE 'self\.handle\(Request \{' crates/swift-proxy-server/src/lib.rs || true)
fi
if grep -nE 'return self\.handle\(req\)' crates/swift-object-server/src/lib.rs >/dev/null 2>&1; then
  while IFS= read -r hit; do
    lineno=${hit%%:*}
    fail_dispatch=$((fail_dispatch + 1))
    emit FAIL handle_fallback "crates/swift-object-server/src/lib.rs" "$lineno" "handle_async must not call handle() on the reactor"
  done < <(grep -nE 'return self\.handle\(req\)' crates/swift-object-server/src/lib.rs || true)
fi
if grep -n 'let mut resp = self.get(' crates/swift-object-server/src/lib.rs >/dev/null 2>&1; then
  while IFS= read -r hit; do
    lineno=${hit%%:*}
    fail_dispatch=$((fail_dispatch + 1))
    emit FAIL get_on_reactor "crates/swift-object-server/src/lib.rs" "$lineno" "get_streaming_async must not call self.get on the caller"
  done < <(grep -n 'let mut resp = self.get(' crates/swift-object-server/src/lib.rs || true)
fi

fail_legacy=0
# Production object/proxy/account/container must not construct LegacyService
# or call the sync handle_connection accept loop. HTTP crate may keep
# LegacyService as the small-handler adapter (occupancy tests) and
# handle_connection as a cfg(test) unit-test path.
for f in \
  crates/swift-object-server/src/lib.rs \
  crates/swift-object-server/src/main.rs \
  crates/swift-proxy-server/src/lib.rs \
  crates/swift-proxy-server/src/main.rs \
  crates/swift-account-server/src/lib.rs \
  crates/swift-account-server/src/main.rs \
  crates/swift-container-server/src/lib.rs \
  crates/swift-container-server/src/main.rs
do
  [ -f "$f" ] || continue
  cfg_test_line=$(grep -n '#\[cfg(test)\]' "$f" 2>/dev/null | head -1 | cut -d: -f1 || true)
  while IFS= read -r hit; do
    [ -n "$hit" ] || continue
    lineno=${hit%%:*}
    text=${hit#*:}
    if [ -n "${cfg_test_line:-}" ] && [ "$lineno" -ge "$cfg_test_line" ]; then
      continue
    fi
    fail_legacy=$((fail_legacy + 1))
    emit FAIL legacy_prod "$f" "$lineno" "$(snippet "$text")"
  done < <(grep -nE 'LegacyService|handle_connection\(' "$f" 2>/dev/null || true)
done
# Dual-mode production switch must not return: only reject_legacy_server_runtime.
if grep -nE 'server_runtime.*=.*legacy|legacy.*handle_connection' \
    crates/swift-http/src/server.rs \
    crates/swift-object-server/src/main.rs \
    crates/swift-proxy-server/src/main.rs \
    crates/swift-account-server/src/main.rs \
    crates/swift-container-server/src/main.rs \
    2>/dev/null | grep -v reject_legacy | grep -v 'removed' | grep -v '#' >/dev/null; then
  while IFS= read -r hit; do
    [ -n "$hit" ] || continue
    file=${hit%%:*}
    rest=${hit#*:}
    lineno=${rest%%:*}
    text=${rest#*:}
    fail_legacy=$((fail_legacy + 1))
    emit FAIL legacy_flag "$file" "$lineno" "$(snippet "$text")"
  done < <(grep -nHE 'server_runtime.*=.*legacy' \
      crates/swift-http/src/server.rs \
      crates/swift-object-server/src/main.rs \
      crates/swift-proxy-server/src/main.rs \
      crates/swift-account-server/src/main.rs \
      crates/swift-container-server/src/main.rs \
      2>/dev/null | grep -v reject_legacy | grep -v 'removed' || true)
fi

hard=$((fail_spawn + fail_unbounded + fail_fs + fail_dispatch + fail_net + fail_stdio_fs + fail_rusqlite + fail_legacy))

echo
echo "== summary =="
echo "files scanned:              ${#FILES[@]}"
echo "spawn_blocking FAIL:        $fail_spawn"
echo "spawn_blocking ALLOW:       $allow_spawn  (crates/swift-runtime/src/blocking)"
echo "unbounded FAIL (prod src):  $fail_unbounded"
echo "unbounded LIST (tests):     $list_unbounded"
echo "tokio::fs FAIL:             $fail_fs  (swift-http / swift-proxy-server / swift-s3api)"
echo "handle_fallback FAIL:       $fail_dispatch"
echo "std::net FAIL (http/proxy): $fail_net"
echo "std::net ALLOW (bind/edge): $allow_net"
echo "std::fs FAIL (http/proxy):  $fail_stdio_fs"
echo "rusqlite FAIL (http/proxy): $fail_rusqlite"
echo "legacy production FAIL:     $fail_legacy"
echo "hard failures:              $hard"

if [ "$hard" -gt 0 ]; then
  echo "FAIL"
  exit 1
fi
echo "PASS"
exit 0
