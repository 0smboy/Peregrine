#!/usr/bin/env bash
# P6: Scripted chaos scenarios (timestamped). Extends ha-test patterns.
# Usage: chaos-run.sh <scenario> [OUTDIR]
# Scenarios: proxy-loss | vip-master-loss | object-loss | node-loss | dry-health
set -euo pipefail
source "$(dirname "$0")/../../../swift-rust/tools/lib/lab-auth.sh"
peregrine_load_lab_auth
SCEN="${1:-dry-health}"
OUT="${2:-/tmp/fairness-chaos}"
mkdir -p "$OUT"
LB="${LB:-http://10.0.0.10:8085}"
CON="${CON:-http://127.0.0.1:9000}"
USR="${USR:-$ST_USER}"
KEY="${KEY:-$ST_KEY}"
TOOLS="${TOOLS:-/root/work/swift-rust/tools}"
# Contabo private IPs (hostnames often missing inside the cluster)
SWIFT1_IP="${SWIFT1_IP:-10.0.0.1}"
SWIFT2_IP="${SWIFT2_IP:-10.0.0.2}"
SWIFT3_IP="${SWIFT3_IP:-10.0.0.3}"
SWIFT4_IP="${SWIFT4_IP:-10.0.0.4}"
ssh_node() { local ip=$1; shift; ssh -o BatchMode=yes -o StrictHostKeyChecking=no "root@$ip" "$@"; }

ts() { date -u +%Y-%m-%dT%H:%M:%S.%NZ; }

emit() {
  python3 - <<PY
import json
print(json.dumps({
  "scenario": "$SCEN",
  "injected_at_utc": "$(ts)",
  "target": "$1",
  "note": """$2""",
}, sort_keys=True))
PY
}

case "$SCEN" in
  dry-health)
    curl -fsS -m 10 "$LB/healthcheck" | tee "$OUT/healthcheck.txt"
    curl -fsS -m 10 -H "X-Auth-User: $USR" -H "X-Auth-Key: $KEY" "$LB/auth/v1.0" -D - -o /dev/null | tee "$OUT/auth.headers"
    emit "cluster" "health+auth ok" | tee "$OUT/events.jsonl"
    ;;
  proxy-loss)
    # Stop proxy on swift2 via systemctl; measure auth+PUT via VIP
    emit "swift2" "stop swift-proxy" | tee -a "$OUT/events.jsonl"
    ssh_node "$SWIFT2_IP" 'systemctl stop swift-proxy'
    sleep 2
    ok=0; fail=0
    TOK=$(curl -sS -m 10 -D - -o /dev/null -H "X-Auth-User: $USR" -H "X-Auth-Key: $KEY" "$LB/auth/v1.0" | awk 'tolower($1)=="x-auth-token:"{print $2}' | tr -d '\r')
    for i in $(seq 1 20); do
      code=$(curl -sS -m 10 -o /dev/null -w '%{http_code}' -H "X-Auth-Token: $TOK" -X PUT "$LB/v1/AUTH_test/chaos-proxy-$RANDOM" || echo 000)
      [[ "$code" =~ ^20 ]] && ok=$((ok+1)) || fail=$((fail+1))
    done
    ssh_node "$SWIFT2_IP" 'systemctl start swift-proxy'
    emit "swift2" "recovered ok=$ok fail=$fail" | tee -a "$OUT/events.jsonl"
    echo "{\"ok\":$ok,\"fail\":$fail}" | tee "$OUT/SUMMARY.json"
    ;;
  vip-master-loss)
    # Prefer console node-down / ha-test if available
    if [[ -x "$TOOLS/ha-test.sh" ]]; then
      bash "$TOOLS/ha-test.sh" "$LB" "$USR" "$KEY" 2>&1 | tee "$OUT/ha-test.log"
      emit "vip" "delegated to ha-test.sh" | tee -a "$OUT/events.jsonl"
    else
      echo "ha-test.sh missing; run from Contabo hub" | tee "$OUT/SKIPPED.txt"
      exit 0
    fi
    ;;
  object-loss)
    emit "swift3" "stop swift-object" | tee -a "$OUT/events.jsonl"
    ssh_node "$SWIFT3_IP" 'systemctl stop swift-object'
    sleep 2
    # reads/writes via VIP should often survive with 3 replicas
    TOK=$(curl -sS -m 10 -D - -o /dev/null -H "X-Auth-User: $USR" -H "X-Auth-Key: $KEY" "$LB/auth/v1.0" | awk 'tolower($1)=="x-auth-token:"{print $2}' | tr -d '\r')
    ctn="chaos-obj-$RANDOM"
    curl -sS -m 15 -X PUT -H "X-Auth-Token: $TOK" "$LB/v1/AUTH_test/$ctn" >/dev/null
    ok=0; fail=0
    for i in $(seq 1 20); do
      code=$(curl -sS -m 15 -o /dev/null -w '%{http_code}' -H "X-Auth-Token: $TOK" -X PUT --data-binary "x$i" "$LB/v1/AUTH_test/$ctn/o$i" || echo 000)
      [[ "$code" =~ ^20 ]] && ok=$((ok+1)) || fail=$((fail+1))
    done
    ssh_node "$SWIFT3_IP" 'systemctl start swift-object'
    echo "{\"ok\":$ok,\"fail\":$fail}" | tee "$OUT/SUMMARY.json"
    emit "swift3" "object-loss ok=$ok fail=$fail" | tee -a "$OUT/events.jsonl"
    ;;
  node-loss)
    echo "node-loss: use console /lab/api/node/down via ha-test — not hard poweroff from agent" | tee "$OUT/SKIPPED.txt"
    emit "manual" "operator-mediated" | tee -a "$OUT/events.jsonl"
    ;;
  *)
    echo "usage: $0 dry-health|proxy-loss|vip-master-loss|object-loss|node-loss [OUT]"
    exit 2
    ;;
esac
echo "OK chaos -> $OUT"
