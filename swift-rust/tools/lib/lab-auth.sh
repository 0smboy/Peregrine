#!/usr/bin/env bash
# Source-only helper for live lab credentials. The real key must never be
# committed. Install a root-readable env file on the Linux controller or export
# ST_USER/ST_KEY before invoking a tool.

peregrine_load_lab_auth() {
  local auth_file="${PEREGRINE_LAB_AUTH_FILE:-/etc/swift/peregrine-lab.env}"
  if [[ -z "${ST_KEY:-}" && -r "$auth_file" ]]; then
    # shellcheck disable=SC1090
    source "$auth_file"
  fi
  ST_USER="${ST_USER:-test:tester}"
  if [[ -z "${ST_KEY:-}" || "$ST_KEY" == "PEREGRINE_LAB_KEY_REQUIRED" ]]; then
    printf 'FATAL: set ST_KEY or install %s with mode 0600\n' "$auth_file" >&2
    return 2
  fi
  export ST_USER ST_KEY
}
