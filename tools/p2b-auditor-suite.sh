#!/bin/bash
# P2b auditor suite: continuous units active + once-pass + SLA notes.
# Usage: p2b-auditor-suite.sh <endpoint> <user> <key> [label]
set -u
EP=${1:?endpoint}; USR=${2:?user}; KEY=${3:?key}; LABEL=${4:-p2b}
CO="-s -m60 --http1.1"
PASS=0; FAIL=0; FAILED=()
PEERS=${P2B_PEERS:-"10.0.0.1 10.0.0.2 10.0.0.3 10.0.0.4"}
SSH_OPTS="-o BatchMode=yes -o ConnectTimeout=12 -o StrictHostKeyChecking=accept-new"

ok()   { PASS=$((PASS+1)); printf '  PASS  %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); FAILED+=("$1"); printf '  FAIL  %s  -- %s\n' "$1" "$2"; }

if [ -f /etc/swift/object-server.conf ] && command -v systemctl >/dev/null 2>&1; then
  P2B_LOCAL=1
else
  P2B_LOCAL=${P2B_LOCAL:-0}
fi

remote() {
  local h=$1; shift
  if [ "$P2B_LOCAL" = "1" ]; then
    local me
    me=$(hostname -I 2>/dev/null | awk '{print $1}')
    if [ "$h" = "$me" ] || { [ "$h" = "10.0.0.1" ] && hostname | grep -qi swift1; }; then
      bash -c "$*"
      return
    fi
    ssh $SSH_OPTS "root@$h" "$*"
  else
    if [ "$h" = "10.0.0.1" ] || [ "$h" = "swift1" ]; then
      ssh $SSH_OPTS swift1 "$*"
    else
      ssh $SSH_OPTS swift1 "ssh $SSH_OPTS root@$h \"$*\""
    fi
  fi
}

echo "==================================================================="
echo "P2b AUDITOR SUITE  label=$LABEL  endpoint=$EP  local=${P2B_LOCAL:-0}  $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "==================================================================="

TOK=$(curl $CO -i -H "X-Auth-User: $USR" -H "X-Auth-Key: $KEY" "$EP/auth/v1.0" \
  | tr -d '\r' | awk -F': ' 'tolower($1)=="x-auth-token"{print $2; exit}')
[ -n "$TOK" ] && ok "auth token" || bad "auth token" "empty"

for h in $PEERS; do
  ST=$(remote "$h" 'systemctl is-active swift-object-auditor swift-account-auditor swift-container-auditor 2>/dev/null | tr "\n" " "')
  echo "  [$h] units: $ST"
  echo "$ST" | grep -q 'active active active' && ok "units active on $h" || bad "units active on $h" "$ST"
done

# DB auditors: once via syslog (daemon logs to syslog, not stdout)
DB=$(remote 10.0.0.1 '
  /usr/local/bin/swift-db-auditor account /etc/swift/account-server.conf once
  /usr/local/bin/swift-db-auditor container /etc/swift/container-server.conf once
  sleep 0.5
  journalctl -t account-auditor --since "45 sec ago" --no-pager 2>/dev/null | grep "account-auditor pass" | tail -2
  journalctl -t container-auditor --since "45 sec ago" --no-pager 2>/dev/null | grep "container-auditor pass" | tail -2
')
echo "$DB" | sed 's/^/  /'
echo "$DB" | grep -q 'account-auditor pass' && ok "account-auditor once pass" || bad "account-auditor once pass" "no journal line"
echo "$DB" | grep -q 'container-auditor pass' && ok "container-auditor once pass" || bad "container-auditor once pass" "no journal line"

# Object auditor: tiny devices root once (fast) + continuous unit mode
TINY=$(remote 10.0.0.1 '
  TD=/tmp/p2b-tiny-dev; rm -rf "$TD"; mkdir -p "$TD/d1"
  cat > /tmp/p2b-tiny-obj.conf <<EOF
[app:object-server]
devices = $TD
mount_check = false
[object-auditor]
interval = 30
devices = $TD
mount_check = false
EOF
  /usr/local/bin/swift-object-auditor /tmp/p2b-tiny-obj.conf once
  sleep 0.3
  journalctl -t object-auditor --since "30 sec ago" --no-pager 2>/dev/null | grep "object-auditor pass" | tail -2
')
echo "$TINY" | sed 's/^/  /'
echo "$TINY" | grep -q 'object-auditor pass' && ok "object-auditor tiny once pass" || bad "object-auditor tiny once pass" "no journal line"

CONT=$(remote 10.0.0.1 'journalctl -t object-auditor --since "30 min ago" --no-pager 2>/dev/null | grep -c "once=false" || echo 0')
CONT=${CONT//[^0-9]/}
[ "${CONT:-0}" -ge 1 ] && ok "object-auditor continuous mode log ($CONT)" || bad "object-auditor continuous mode" "count=$CONT"

# Continuous object process still running (first full /srv/node pass may take minutes)
RUN=$(remote 10.0.0.1 'systemctl is-active swift-object-auditor; pgrep -c -x swift-object-auditor || echo 0')
echo "  continuous object-auditor: $RUN"
echo "$RUN" | grep -q active && ok "object-auditor continuous unit running" || bad "object-auditor continuous unit" "$RUN"

TMR=$(remote 10.0.0.1 'systemctl is-enabled swift-audit-sweep.timer 2>/dev/null || echo disabled; systemctl is-active swift-audit-sweep.timer 2>/dev/null || echo inactive')
echo "  timer state: $TMR"
echo "$TMR" | grep -Eqi 'disabled|not-found|inactive' && ok "nightly timer not active" || bad "nightly timer" "$TMR"

echo "  SLA: object interval=30s (Python ObjectAuditor default); account/container interval=1800s (Python DatabaseAuditor default)"
echo "  SLA: continuous Type=simple + Restart=on-failure — NOT nightly timer equivalence"
echo "  NOTE: first /srv/node object pass can take many minutes on Contabo disk load; tiny-once proves pass path"

echo "-------------------------------------------------------------------"
echo "RESULT $LABEL  pass=$PASS fail=$FAIL"
if [ "$FAIL" -gt 0 ]; then
  printf 'FAILED: %s\n' "${FAILED[*]}"
  exit 1
fi
exit 0
