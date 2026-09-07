#!/usr/bin/env bash
# IsolatedIdentity G6 probe launcher.
#
# Field 988b81b (2026-09-06, /workspace/rebuild-once-988b81b-httpget/):
# official proxy_get via egg:swift#proxy never hit rust :18080. After
# forcing GET onto rust HTTP, test_rebuild_missing_frags
# PASSed (rc=0, 30× G6_DIAG proxy-server: EC GET status=200 reason=ok).
#
# This wrapper is the durable runner: apply that honesty, fail closed if
# GET would still use InternalClient, then exec the probe command.
# Do not reopen gather-bucket chasing, lonely_frag, missing_frags,
# non_durable_newer_data, or sync_expired.
#
# Field `/workspace/rebuild-nondurable-176505e/` (2026-09-06): gatekeeper
# on public :18080 strips X-Backend-* (X-Backend-No-Commit). IC no-commit
# PUT and fragment-preferences GET used rust :18082 for that PASS.
# Field `/workspace/g6-rebuild-176505e/` (2026-09-06): UTF8 names must be
# percent-encoded before http.client (IRI → request-target).
# Field `/workspace/g6-rebuild-6042407-utf8-lonely/`: leftover B PASS
# via make_request HEAD (urllib3 dropped UTF-8 meta). ASCII expire
# IsolatedIdentity proxy_get is rust HTTP (404 → UnexpectedResponse).
# Field `/workspace/g6-rebuild-982e86a-unified/` (2026-09-06): 17/17 PASS.
# Public :18080 gatekeeper strips X-Backend-*. IsolatedIdentity GET and
# no-commit / backend-header hops use rust :18082 (G6_INTERNAL_PROXY_URL).
# Keep rust_http_proxy_get (UnexpectedResponse). Do not raw-replace
# IsolatedIdentity proxy_get with swiftclient.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
export PYTHONPATH="${HERE}${PYTHONPATH:+:$PYTHONPATH}"

if [[ "${PROXY_BASE_URL:-}" == *":18080"* ]]; then
  export G6_INTERNAL_PROXY_URL="${G6_INTERNAL_PROXY_URL:-http://127.0.0.1:18082}"
fi

python3 "$HERE/g6_rust_proxy_get.py" --prepare

if [[ $# -eq 0 ]]; then
  echo "g6_isolated_probe: prepared PYTHONPATH=${PYTHONPATH} PROXY_BASE_URL=${PROXY_BASE_URL:-} G6_INTERNAL_PROXY_URL=${G6_INTERNAL_PROXY_URL:-}" >&2
  echo "usage: $0 pytest|python3 ...   # IsolatedIdentity G6 probe command" >&2
  exit 0
fi

if [[ "$1" == "pytest" ]]; then
  shift
  exec pytest -p g6_rust_proxy_get "$@"
fi
exec "$@"
