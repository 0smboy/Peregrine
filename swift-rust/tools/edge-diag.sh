#!/bin/bash
# Clean, isolated verification of the functional-suite's "real candidate"
# failures, run with generous timeouts and no concurrent load:
#   1. etag format (is it quoted?)          2. wrong-etag PUT enforcement (422?)
#   3. fast-POST metadata visibility        4. EC PUT/GET/ranged, via proxy AND VIP
# Usage: edge-diag.sh <user> <key>
set -u
USR=${1:?user}; KEY=${2:?key}
PROXY=http://127.0.0.1:8080
VIP=http://10.42.30.10:8085

tok() { curl -s -m20 -D - -o /dev/null -H "X-Auth-User: $USR" -H "X-Auth-Key: $KEY" "$1/auth/v1.0" \
        | awk 'tolower($1)=="x-auth-token:"{print $2}' | tr -d '\r'; }
pathv1() { curl -s -m20 -D - -o /dev/null -H "X-Auth-User: $USR" -H "X-Auth-Key: $KEY" "$1/auth/v1.0" \
        | awk 'tolower($1)=="x-storage-url:"{print $2}' | tr -d '\r' | sed -E 's#https?://[^/]+##'; }

TOK=$(tok $PROXY); PV=$(pathv1 $PROXY)
echo "token=${TOK:0:14}...  path=$PV"

echo
echo "########## 1. ETAG FORMAT (raw object HEAD) ##########"
B=$PROXY$PV; C=diag-$RANDOM
curl -s -X PUT -H "X-Auth-Token: $TOK" "$B/$C" >/dev/null
printf 'hello' | curl -s -X PUT -H "X-Auth-Token: $TOK" -H "Content-Type: text/plain" --data-binary @- "$B/$C/o1" >/dev/null
echo "md5(hello)=$(printf hello | md5sum | cut -d' ' -f1)"
curl -s -D - -o /dev/null -H "X-Auth-Token: $TOK" "$B/$C/o1" | grep -iE 'etag|content-type|content-length'

echo
echo "########## 2. WRONG-ETAG PUT (expect 422) ##########"
printf 'x' | curl -s -o /dev/null -w "  provided-bad-etag PUT code=%{http_code}\n" \
  -X PUT -H "X-Auth-Token: $TOK" -H "ETag: deadbeef00000000deadbeef00000000" --data-binary @- "$B/$C/bad"
printf 'x' | curl -s -o /dev/null -w "  provided-good-etag PUT code=%{http_code}\n" \
  -X PUT -H "X-Auth-Token: $TOK" -H "ETag: 9dd4e461268c8034f5c8564e155c67a6" --data-binary @- "$B/$C/good"

echo
echo "########## 3. FAST-POST METADATA VISIBILITY ##########"
printf 'v1' | curl -s -X PUT -H "X-Auth-Token: $TOK" -H "X-Object-Meta-K: red" --data-binary @- "$B/$C/pm" >/dev/null
echo "  after PUT:  $(curl -s -D - -o /dev/null -H "X-Auth-Token: $TOK" "$B/$C/pm" | grep -i 'x-object-meta-k' | tr -d '\r')"
pc=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "X-Auth-Token: $TOK" -H "X-Object-Meta-K: green" "$B/$C/pm")
echo "  POST code=$pc"
for i in 1 2 3; do
  sleep 1
  echo "  +${i}s HEAD:  $(curl -s -D - -o /dev/null -H "X-Auth-Token: $TOK" "$B/$C/pm" | grep -i 'x-object-meta-k' | tr -d '\r')"
done

echo
echo "########## 4. EC PUT/GET  (proxy :8080 vs VIP :8085) ##########"
dd if=/dev/urandom of=/tmp/ec3.$$ bs=1M count=3 status=none
ECM=$(md5sum /tmp/ec3.$$ | cut -d' ' -f1); echo "  src md5=$ECM (3MB)"
for TAG in PROXY VIP; do
  if [ $TAG = PROXY ]; then E=$PROXY; T=$TOK; P=$PV; else E=$VIP; T=$(tok $VIP); P=$(pathv1 $VIP); fi
  BB=$E$P; EC=diagec-$RANDOM
  echo "  --- via $TAG ($E) ---"
  cc=$(curl -s -m60 -o /dev/null -w '%{http_code}' -X PUT -H "X-Auth-Token: $T" -H "X-Storage-Policy: ec-2-1" "$BB/$EC")
  echo "    ec container create=$cc"
  put=$(curl -s -m60 -o /dev/null -w 'code=%{http_code} time=%{time_total}s' -X PUT -H "X-Auth-Token: $T" --data-binary @/tmp/ec3.$$ "$BB/$EC/obj")
  echo "    PUT  $put"
  g=$(curl -s -m60 "$BB/$EC/obj" -H "X-Auth-Token: $T" | md5sum | cut -d' ' -f1)
  echo "    GET  md5=$g  match=$([ "$g" = "$ECM" ] && echo YES || echo NO)"
  rg=$(curl -s -m60 -o /dev/null -w 'code=%{http_code} time=%{time_total}s' -H "X-Auth-Token: $T" -H 'Range: bytes=0-1023' "$BB/$EC/obj")
  echo "    RANGE $rg"
  curl -s -X DELETE -H "X-Auth-Token: $T" "$BB/$EC/obj" >/dev/null; curl -s -X DELETE -H "X-Auth-Token: $T" "$BB/$EC" >/dev/null
done

echo
echo "########## cleanup ##########"
for o in o1 bad good pm; do curl -s -X DELETE -H "X-Auth-Token: $TOK" "$B/$C/$o" >/dev/null; done
curl -s -X DELETE -H "X-Auth-Token: $TOK" "$B/$C" >/dev/null
rm -f /tmp/ec3.$$
echo done
