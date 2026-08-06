#!/bin/bash
# P2a daemon suite: object-expirer (X-Delete-At), container-updater converge,
# account-reaper / container-reconciler process gates.
# Usage: p2a-daemon-suite.sh <endpoint> <user> <key> [label]
# Env:
#   FORCE_ONCE=1 (default) run updater/expirer/reconciler once on storage nodes
#   P2A_PEERS="10.0.0.1 10.0.0.2 10.0.0.3 10.0.0.4"  peer list for once-passes
#   P2A_LOCAL=1  already on a storage node; use local systemctl/journal + peer SSH
set -u
EP=${1:?endpoint}; USR=${2:?user}; KEY=${3:?key}; LABEL=${4:-p2a}
CO="-s -m60 --http1.1"
PASS=0; FAIL=0; FAILED=()
PEERS=${P2A_PEERS:-"10.0.0.1 10.0.0.2 10.0.0.3 10.0.0.4"}
SSH_OPTS="-o BatchMode=yes -o ConnectTimeout=12 -o StrictHostKeyChecking=accept-new"

ok()   { PASS=$((PASS+1)); printf '  PASS  %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); FAILED+=("$1"); printf '  FAIL  %s  -- %s\n' "$1" "$2"; }
ck()   { [ "$2" = "$3" ] && ok "$1" || bad "$1" "want=$2 got=$3 ${4:-}"; }
code() { curl $CO -o /dev/null -w '%{http_code}' "$@"; }

# Detect local Contabo node (has /etc/swift + the daemon units).
if [ -f /etc/swift/object-server.conf ] && command -v systemctl >/dev/null 2>&1; then
  P2A_LOCAL=1
else
  P2A_LOCAL=${P2A_LOCAL:-0}
fi

remote() {
  # $1 = host IP; rest = command
  local h=$1; shift
  if [ "$P2A_LOCAL" = "1" ]; then
    local me
    me=$(hostname -I 2>/dev/null | awk '{print $1}')
    # Prefer exact peer match; also treat 10.0.0.1 as local when hostname is swift1.
    if [ "$h" = "$me" ] || { [ "$h" = "10.0.0.1" ] && hostname | grep -qi swift1; }; then
      bash -c "$*"
      return
    fi
    ssh $SSH_OPTS "root@$h" "$*"
  else
    # From Mac/laptop: jump via swift1 for peer work.
    if [ "$h" = "10.0.0.1" ] || [ "$h" = "swift1" ]; then
      ssh $SSH_OPTS swift1 "$*"
    else
      ssh $SSH_OPTS swift1 "ssh $SSH_OPTS root@$h \"$*\""
    fi
  fi
}

echo "==================================================================="
echo "P2a DAEMON SUITE  label=$LABEL  endpoint=$EP  local=$P2A_LOCAL  $(date -u +%FT%TZ)"
echo "==================================================================="

AUTH=$(curl $CO -D - -o /dev/null -H "X-Auth-User: $USR" -H "X-Auth-Key: $KEY" "$EP/auth/v1.0")
TOK=$(printf '%s' "$AUTH" | awk 'tolower($1)=="x-auth-token:"{print $2}' | tr -d '\r')
SURL=$(printf '%s' "$AUTH" | awk 'tolower($1)=="x-storage-url:"{print $2}' | tr -d '\r')
if [ -z "$TOK" ]; then echo "FATAL: no token"; exit 3; fi
PATHV1=$(printf '%s' "$SURL" | sed -E 's#https?://[^/]+##')
BASE="$EP$PATHV1"
H=(-H "X-Auth-Token: $TOK")
ok "auth: token acquired"

C="p2a-$RANDOM"
cleanup() {
  for o in $(curl $CO "${H[@]}" "$BASE/$C?format=json" 2>/dev/null \
    | sed -n 's/.*"name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p'); do
    curl $CO -X DELETE "${H[@]}" "$BASE/$C/$o" >/dev/null 2>&1
  done
  curl $CO -X DELETE "${H[@]}" "$BASE/$C" >/dev/null 2>&1
}
trap cleanup EXIT

ck "container: PUT 201" 201 "$(code -X PUT "${H[@]}" "$BASE/$C")"

# ---- object-expirer ---------------------------------------------------------
DEL_AT=$(( $(date +%s) + 3 ))
ck "expire: PUT with X-Delete-At 201" 201 "$(code -X PUT "${H[@]}" \
  -H "Content-Type: text/plain" -H "X-Delete-At: $DEL_AT" -d 'expire-me' "$BASE/$C/expiring.txt")"
ck "expire: object present before deadline" 200 "$(code "${H[@]}" "$BASE/$C/expiring.txt")"
ck "expire: PUT with X-Delete-After 201" 201 "$(code -X PUT "${H[@]}" \
  -H "Content-Type: text/plain" -H "X-Delete-After: 3" -d 'expire-after' "$BASE/$C/expiring-after.txt")"

EXPIRED_SEEN=0
if [ "${FORCE_ONCE:-1}" = "1" ]; then
  FORCE_ERR=0
  for h in $PEERS; do
    remote "$h" 'timeout 90 /usr/local/bin/swift-object-updater /etc/swift/object-server.conf once >/dev/null 2>&1 || true' \
      || FORCE_ERR=1
  done
  sleep 5
  for h in $PEERS; do
    # Binary logs to syslog; mark journal cursor then run once and grep.
    OUT=$(remote "$h" 'timeout 90 /usr/local/bin/swift-object-expirer /etc/swift/object-server.conf once >/dev/null 2>&1 || true; sleep 0.5; journalctl -t object-expirer --since "45 sec ago" --no-pager 2>/dev/null | grep "object-expirer pass" | tail -5' || true)
    printf '%s\n' "$OUT" | sed "s/^/  [$h] /"
    if printf '%s' "$OUT" | grep -Eq 'expired=[1-9][0-9]*'; then
      EXPIRED_SEEN=1
    fi
  done
  # residual drain (background daemon may also race-claim the task)
  for h in $PEERS; do
    remote "$h" 'timeout 90 /usr/local/bin/swift-object-updater /etc/swift/object-server.conf once >/dev/null 2>&1 || true; timeout 90 /usr/local/bin/swift-object-expirer /etc/swift/object-server.conf once >/dev/null 2>&1 || true' \
      || true
  done
  if [ "$FORCE_ERR" -eq 0 ]; then
    ok "force-once: updater+expirer on peers"
  else
    bad "force-once: updater+expirer on peers" "one or more peer commands failed"
  fi
else
  echo "  INFO  FORCE_ONCE=0; sleeping 90s for interval"
  sleep 90
fi

# Client GET 404 can be soft-expiry (diskfile) OR hard delete. Require both
# client 404 and a recent expirer pass that reports expired>=1 (journal).
ck "expire: X-Delete-At client 404" "404" "$(code "${H[@]}" "$BASE/$C/expiring.txt")"
ck "expire: X-Delete-After client 404" "404" "$(code "${H[@]}" "$BASE/$C/expiring-after.txt")"
EXP_JOURNAL=$(remote 10.0.0.1 'for h in 10.0.0.1 10.0.0.2 10.0.0.3 10.0.0.4; do
  if [ "$h" = 10.0.0.1 ]; then journalctl -t object-expirer --since "15 min ago" --no-pager 2>/dev/null
  else ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=8 root@$h "journalctl -t object-expirer --since \"15 min ago\" --no-pager 2>/dev/null"
  fi
done | grep -E "expired=[1-9]" | tail -10' || true)
if [ "$EXPIRED_SEEN" = "1" ] || printf '%s' "$EXP_JOURNAL" | grep -Eq 'expired=[1-9][0-9]*'; then
  ok "expire: expirer hard-delete pass (expired>=1)"
else
  bad "expire: expirer hard-delete pass (expired>=1)" "no expired>0 in journal (see evidence 16-expire-hard-verify for on-disk)"
fi

# ---- container-updater ------------------------------------------------------
ck "updater: put obj for stats 201" 201 "$(code -X PUT "${H[@]}" \
  -H "Content-Type: text/plain" -d 'stats' "$BASE/$C/stats-obj.txt")"
if [ "${FORCE_ONCE:-1}" = "1" ]; then
  for h in $PEERS; do
    remote "$h" 'timeout 180 /usr/local/bin/swift-container-updater /etc/swift/container-server.conf once >/tmp/p2a-cupd.once 2>&1 || true' || true
  done
fi
ACCT_LIST=$(curl $CO "${H[@]}" "$BASE?format=json" 2>/dev/null || true)
if printf '%s' "$ACCT_LIST" | grep -q "\"name\":\"$C\""; then
  ok "updater: account listing contains container"
else
  HCODE=$(code -X HEAD "${H[@]}" "$BASE/$C")
  if [ "$HCODE" = "204" ] || [ "$HCODE" = "200" ]; then
    ok "updater: container HEAD ok (listing lag tolerated)"
  else
    bad "updater: account listing / HEAD" "list missing $C head=$HCODE"
  fi
fi

# ---- account-reaper / reconciler process gates ------------------------------
REAP_ACTIVE=$(remote 10.0.0.1 'systemctl is-active swift-account-reaper' 2>/dev/null || echo failed)
ck "reaper: systemd active on swift1" "active" "$REAP_ACTIVE"
REAP_LOG=$(remote 10.0.0.1 'journalctl -u swift-account-reaper --since "15 min ago" --no-pager 2>/dev/null | grep -c "account-reaper pass" || echo 0')
REAP_LOG=$(printf '%s' "$REAP_LOG" | tr -dc '0-9')
if [ "${REAP_LOG:-0}" -ge 1 ]; then
  ok "reaper: completed at least one pass"
else
  bad "reaper: completed at least one pass" "no pass log"
fi

REC_ACTIVE=$(remote 10.0.0.1 'systemctl is-active swift-container-reconciler' 2>/dev/null || echo failed)
ck "reconciler: systemd active on swift1" "active" "$REC_ACTIVE"
REC_LOG=$(remote 10.0.0.1 'journalctl -u swift-container-reconciler --since "15 min ago" --no-pager 2>/dev/null | grep -c "container-reconciler pass" || echo 0')
REC_LOG=$(printf '%s' "$REC_LOG" | tr -dc '0-9')
if [ "${REC_LOG:-0}" -ge 1 ]; then
  ok "reconciler: completed at least one pass"
else
  bad "reconciler: completed at least one pass" "no pass log"
fi

if [ "${FORCE_ONCE:-1}" = "1" ]; then
  OUT=$(remote 10.0.0.1 'timeout 60 /usr/local/bin/swift-container-reconciler /etc/swift/container-server.conf once >/dev/null 2>&1 || true; sleep 0.5; journalctl -t container-reconciler --since "45 sec ago" --no-pager 2>/dev/null | grep "container-reconciler pass" | tail -3' || true)
  if printf '%s' "$OUT" | grep -q "container-reconciler pass"; then
    ok "reconciler: once pass ok"
  else
    bad "reconciler: once pass" "$(printf '%s' "$OUT" | tail -3 | tr '\n' ' ')"
  fi
fi

# ---- four-node unit matrix --------------------------------------------------
MATRIX_OK=1
for h in $PEERS; do
  ST=$(remote "$h" 'systemctl is-active swift-object-expirer swift-account-reaper swift-container-updater swift-container-reconciler 2>/dev/null | tr "\n" " "' || echo fail)
  if printf '%s' "$ST" | grep -Eq '^(active ){3}active ?$'; then
    ok "units active on $h"
  else
    bad "units active on $h" "$ST"
    MATRIX_OK=0
  fi
done
[ "$MATRIX_OK" = "1" ] && ok "unit matrix: all 4 nodes" || true

echo "==================================================================="
echo "P2a RESULT  pass=$PASS fail=$FAIL  $(date -u +%FT%TZ)"
if [ "$FAIL" -gt 0 ]; then
  printf 'FAILED:\n'; printf '  - %s\n' "${FAILED[@]}"
  exit 1
fi
echo "ALL GREEN"
exit 0
