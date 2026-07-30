#!/bin/bash
# Verify every object in the corpus manifests against md5 AND size.
#
# Two rules this script exists to enforce, both learned from its predecessor
# reporting data loss that had not happened:
#
#  1. NEVER follow x-storage-url. The proxy advertises the Azure ILB VIP, and a
#     backend node cannot reach its own load balancer's VIP (hairpin), so a
#     script run on a node followed the URL, got a connect timeout, and called
#     it missing data. The endpoint is an argument; the object URL is built
#     from it.
#  2. A transport failure is NOT data loss. UNREACHABLE and CORRUPT are
#     different findings and are counted separately — the first is a statement
#     about the network, only the second is a statement about the bytes.
#
# usage: readcheck.sh [endpoint]        default: a direct node, never the VIP
set -u
EP=${1:-http://10.42.30.11:8085}
ACCOUNT=AUTH_test
RETRIES=2

auth() {
  local r
  r=$(curl -si -m15 -H "X-Auth-User: test:tester" -H "X-Auth-Key: azure-swift-2026.bench" \
        "$EP/auth/v1.0" 2>/dev/null | tr -d '\r')
  awk 'tolower($1)=="x-auth-token:"{print $2}' <<<"$r"
}

TOK=$(auth)
if [ -z "$TOK" ]; then echo "  AUTH FAILED against $EP"; exit 2; fi
echo "  endpoint $EP"

rc=0
for pair in "expand-repl:replication" "expand-ec:erasure-coding"; do
  c=${pair%%:*}; label=${pair##*:}
  man=/root/expand/$c-manifest.txt
  [ -r "$man" ] || { echo "  $label: manifest $man unreadable"; rc=2; continue; }

  ok=0; corrupt=0; unreachable=0; retried=0; detail=""
  while read -r -u 3 name want_md5 want_size; do
    [ -z "$name" ] && continue
    code=""; got_md5=""; got_size=""
    for attempt in $(seq 0 $RETRIES); do
      [ "$attempt" -gt 0 ] && { retried=$((retried+1)); sleep 2; }
      code=$(curl -s -m180 -w '%{http_code}' -H "X-Auth-Token: $TOK" \
               "$EP/v1/$ACCOUNT/$c/$name" -o /tmp/rc.$$ 2>/dev/null)
      [ "$code" = "200" ] && break
    done
    if [ "$code" != "200" ]; then
      unreachable=$((unreachable+1)); detail="$detail $name(http=$code)"
      continue
    fi
    got_md5=$(md5sum /tmp/rc.$$ | cut -d' ' -f1)
    got_size=$(stat -c %s /tmp/rc.$$)
    if [ "$got_md5" = "$want_md5" ] && [ "$got_size" = "$want_size" ]; then
      ok=$((ok+1))
    else
      corrupt=$((corrupt+1)); detail="$detail $name(md5/size mismatch)"; rc=1
    fi
  done 3< "$man"
  total=$((ok+corrupt+unreachable))

  msg="  $(printf '%-16s' "$label") $ok/$total md5+size OK"
  [ "$corrupt" -gt 0 ]     && msg="$msg · $corrupt CORRUPT"
  [ "$unreachable" -gt 0 ] && msg="$msg · $unreachable UNREACHABLE (transport, not data loss)"
  [ "$retried" -gt 0 ]     && msg="$msg · $retried retries consumed"
  echo "$msg"
  [ -n "$detail" ] && echo "     ${detail# }"
done
rm -f /tmp/rc.$$
# Only corrupt data is a failure exit; unreachable is reported, never silent.
exit $rc
