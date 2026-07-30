#!/bin/bash
# Full swift-console functional test: login, every page, every read API, Files
# CRUD, and the new node-down status. Run on the console host (loopback :9000).
set -u
BASE=http://127.0.0.1:9000
J=/tmp/sc.jar; rm -f "$J"
PASS=0; FAIL=0; FAILED=()
ok(){ PASS=$((PASS+1)); printf '  PASS  %s\n' "$1"; }
bad(){ FAIL=$((FAIL+1)); FAILED+=("$1"); printf '  FAIL  %s -- %s\n' "$1" "$2"; }
code(){ curl -s -m30 -b "$J" -c "$J" -o /dev/null -w '%{http_code}' "$@"; }
ckc(){ local got; got=$(code "${@:3}"); [ "$got" = "$2" ] && ok "$1" || bad "$1" "want $2 got $got"; }
jget(){ curl -s -m30 -b "$J" "$@"; }

echo "===== LOGIN ====="
lc=$(code -X POST -d 'tenant=test&user=tester&key=azure-swift-2026.bench' "$BASE/login")
{ [ "$lc" = 303 ] || [ "$lc" = 302 ] || [ "$lc" = 200 ]; } && ok "login ($lc)" || { bad "login" "code $lc"; exit 1; }

echo "===== PAGES (want 200) ====="
for p in /files /files/trash /files/account /files/users /files/search \
         /deploy /monitor \
         /lab /lab/ring /lab/policy /lab/capsule /lab/tombstone /lab/chaos /lab/shadow /lab/warehouse /lab/nodes /test; do
  ckc "page $p" 200 "$BASE$p"
done

echo "===== READ APIs (want 200) ====="
for a in /files/api/whoami /files/api/buckets \
         /lab/api/chaos/catalogue /lab/api/shadow/corpus /lab/api/warehouse/jobs \
         /lab/api/ring/topology /lab/api/policy/defaults \
         /lab/api/node/status \
         /monitor/api/dash /test/api/runs; do
  ckc "api $a" 200 "$BASE$a"
done
# content sanity
ckin(){ jget "$2" | grep -qiF "$3" && ok "$1" || bad "$1" "missing '$3'"; }
ckin "whoami has account" "/files/api/whoami" "AUTH_test"
ckin "node status lists nodes" "/lab/api/node/status" "swift1"
ckin "chaos catalogue non-empty" "/lab/api/chaos/catalogue" "fault"

echo "===== FILES CRUD ====="
BK="sctest-$RANDOM"
ckc "bucket create" 200 -X POST -H 'Content-Type: application/json' -d "{\"name\":\"$BK\"}" "$BASE/files/api/buckets"
jget "$BASE/files/api/buckets" | grep -qF "$BK" && ok "bucket appears in list" || bad "bucket list" "missing $BK"
ckc "object put" 200 -X PUT --data-binary 'console-test-body' "$BASE/files/api/obj/$BK/hello.txt"
jget "$BASE/files/api/bucket/$BK/objects" | grep -qF "hello.txt" && ok "object appears in listing" || bad "object list" "missing hello.txt"
ckc "object meta get" 200 "$BASE/files/api/objmeta/$BK/hello.txt"
ckc "tempurl make" 200 -X POST -H 'Content-Type: application/json' -d "{\"bucket\":\"$BK\",\"path\":\"hello.txt\",\"expiry_secs\":600}" "$BASE/files/api/tempurl"
ckc "object delete" 200 -X DELETE "$BASE/files/api/obj/$BK/hello.txt"
ckc "bucket delete" 200 -X DELETE "$BASE/files/api/bucket/$BK"

echo "===== MONITOR PANEL (a real metric query) ====="
dash=$(jget "$BASE/monitor/api/dash")
echo "  dash catalog bytes: $(printf '%s' "$dash" | wc -c)"

echo
echo "-------------------------------------------------------------------"
echo "CONSOLE RESULT  PASS=$PASS  FAIL=$FAIL"
[ $FAIL -gt 0 ] && printf '  failed: %s\n' "${FAILED[*]}"
echo "-------------------------------------------------------------------"
