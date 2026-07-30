#!/usr/bin/env bash
# End-to-end smoke test against the running SAIO cluster: authenticate,
# then round-trip an object through the 3x replication policy AND the
# EC-4-2 erasure-coding policy, checking md5 and (for EC) the durable
# fragment count. Exits non-zero on any failure.
set -u
AUTH=http://127.0.0.1:8080/auth/v1.0
pass=1
note() { printf '  %s\n' "$*"; }
fail() { printf '  \033[1;31mFAIL: %s\033[0m\n' "$*"; pass=0; }

H=$(curl -s -i -H 'X-Auth-User: test:tester' -H 'X-Auth-Key: testing' "$AUTH")
TOK=$(echo "$H" | grep -i '^X-Auth-Token:'  | tr -d '\r' | awk '{print $2}')
URL=$(echo "$H" | grep -i '^X-Storage-Url:' | tr -d '\r' | awk '{print $2}')
[ -n "$TOK" ] && [ -n "$URL" ] || { fail "auth"; exit 1; }
note "auth ok  ($URL)"

echo "[1] replication policy (Policy-0)"
curl -s -X PUT "$URL/rbox" -H "X-Auth-Token: $TOK" -o /dev/null
head -c 1048576 /dev/urandom > /tmp/r.obj
M=$(md5sum /tmp/r.obj | awk '{print $1}')
c=$(curl -s -X PUT "$URL/rbox/o" -H "X-Auth-Token: $TOK" -T /tmp/r.obj -o /dev/null -w '%{http_code}')
[ "$c" = 201 ] && note "PUT 201" || fail "repl PUT ($c)"
curl -s "$URL/rbox/o" -H "X-Auth-Token: $TOK" -o /tmp/r.down
[ "$(md5sum /tmp/r.down | awk '{print $1}')" = "$M" ] && note "GET md5 match" || fail "repl md5"
c=$(curl -s -X DELETE "$URL/rbox/o" -H "X-Auth-Token: $TOK" -o /dev/null -w '%{http_code}')
[ "$c" = 204 ] && note "DELETE 204" || fail "repl DELETE ($c)"

echo "[2] erasure-coding policy (EC-4-2)"
curl -s -X PUT "$URL/ecbox" -H "X-Auth-Token: $TOK" -H 'X-Storage-Policy: EC-4-2' -o /dev/null
head -c 5242880 /dev/urandom > /tmp/e.obj
M=$(md5sum /tmp/e.obj | awk '{print $1}')
c=$(curl -s -X PUT "$URL/ecbox/o" -H "X-Auth-Token: $TOK" -T /tmp/e.obj -o /dev/null -w '%{http_code}')
[ "$c" = 201 ] && note "PUT 201" || fail "EC PUT ($c)"
NF=$(find /srv/node* -path '*objects-1*' -name '*#d.data' 2>/dev/null | wc -l)
[ "$NF" = 6 ] && note "6 durable fragments" || fail "EC fragments ($NF, expected 6)"
curl -s "$URL/ecbox/o" -H "X-Auth-Token: $TOK" -o /tmp/e.down
[ "$(md5sum /tmp/e.down | awk '{print $1}')" = "$M" ] && note "GET md5 match" || fail "EC md5"
c=$(curl -s "$URL/ecbox/o" -H "X-Auth-Token: $TOK" -r 1000-2000 -o /tmp/e.rng -w '%{http_code}')
[ "$c" = 206 ] && [ "$(wc -c </tmp/e.rng)" = 1001 ] && note "ranged GET 206" || fail "EC range ($c)"

rm -f /tmp/r.obj /tmp/r.down /tmp/e.obj /tmp/e.down /tmp/e.rng
if [ "$pass" = 1 ]; then
  printf '\033[1;32mSMOKE: PASS\033[0m\n'; exit 0
else
  printf '\033[1;31mSMOKE: FAIL\033[0m\n'; exit 1
fi
